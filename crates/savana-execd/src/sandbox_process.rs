use std::fs;
use std::io::{self, Read as _, Write as _};
use std::os::fd::{AsFd as _, AsRawFd};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::{Duration, Instant};

use nix::fcntl::{fcntl, FcntlArg, OFlag};
use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
use savana_kernel_protocol::v2::Digest32V2;
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use crate::worker_protocol::{
    VerifiedConnectorWorkerJobV2, MAX_CONNECTOR_DESCRIPTOR_BYTES, MAX_CONNECTOR_FRAME_BYTES,
    MAX_CONNECTOR_MATERIAL_BYTES, MAX_CONNECTOR_RESPONSE_BYTES,
};
use crate::worker_supervisor::{
    ConnectorWorkerChildV2, ConnectorWorkerInputV2, ConnectorWorkerSupervisorErrorV2,
    VerifiedConnectorSandboxLauncherV2,
};

const MAX_JOB_FRAME_BYTES: usize =
    MAX_CONNECTOR_DESCRIPTOR_BYTES + MAX_CONNECTOR_RESPONSE_BYTES + 512;

/// A measured sandbox-wrapper/worker/two-profile tuple. There is deliberately
/// no direct-worker fallback.
pub(crate) struct VerifiedConnectorSandboxProgramV2 {
    sandbox_program: PathBuf,
    worker_program: PathBuf,
    no_network_profile: PathBuf,
    credential_absence_profile: PathBuf,
    worker_artifact_digest: Digest32V2,
}

impl std::fmt::Debug for VerifiedConnectorSandboxProgramV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VerifiedConnectorSandboxProgramV2")
            .field("sandbox_program", &self.sandbox_program)
            .field("worker_program", &self.worker_program)
            .field("no_network_profile", &self.no_network_profile)
            .field(
                "credential_absence_profile",
                &self.credential_absence_profile,
            )
            .finish_non_exhaustive()
    }
}

impl VerifiedConnectorSandboxProgramV2 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_verified_manifest(
        sandbox_program: PathBuf,
        sandbox_program_digest: Digest32V2,
        worker_program: PathBuf,
        worker_artifact_digest: Digest32V2,
        no_network_profile: PathBuf,
        no_network_profile_digest: Digest32V2,
        credential_absence_profile: PathBuf,
        credential_absence_profile_digest: Digest32V2,
        owner_uid: u32,
        owner_gid: u32,
    ) -> Result<Self, ConnectorWorkerSupervisorErrorV2> {
        verify_measured_file(
            &sandbox_program,
            sandbox_program_digest,
            owner_uid,
            owner_gid,
            true,
        )?;
        verify_measured_file(
            &worker_program,
            worker_artifact_digest,
            owner_uid,
            owner_gid,
            true,
        )?;
        verify_measured_file(
            &no_network_profile,
            no_network_profile_digest,
            owner_uid,
            owner_gid,
            false,
        )?;
        verify_measured_file(
            &credential_absence_profile,
            credential_absence_profile_digest,
            owner_uid,
            owner_gid,
            false,
        )?;
        Ok(Self {
            sandbox_program,
            worker_program,
            no_network_profile,
            credential_absence_profile,
            worker_artifact_digest,
        })
    }
}

impl VerifiedConnectorSandboxLauncherV2 for VerifiedConnectorSandboxProgramV2 {
    fn launch_one_job(
        &self,
        job: &VerifiedConnectorWorkerJobV2,
        ephemeral_signing_seed: Zeroizing<[u8; 32]>,
        deadline: Instant,
    ) -> Result<Box<dyn ConnectorWorkerChildV2>, ConnectorWorkerSupervisorErrorV2> {
        if Instant::now() >= deadline || job.worker_artifact_digest() != self.worker_artifact_digest
        {
            return Err(ConnectorWorkerSupervisorErrorV2::LaunchFailed);
        }
        let mut child = Command::new(&self.sandbox_program)
            .arg("--no-network-profile")
            .arg(&self.no_network_profile)
            .arg("--credential-absence-profile")
            .arg(&self.credential_absence_profile)
            .arg("--")
            .arg(&self.worker_program)
            .env_clear()
            .current_dir("/")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| ConnectorWorkerSupervisorErrorV2::LaunchFailed)?;
        let stdin = child
            .stdin
            .take()
            .ok_or(ConnectorWorkerSupervisorErrorV2::LaunchFailed)?;
        let stdout = child
            .stdout
            .take()
            .ok_or(ConnectorWorkerSupervisorErrorV2::LaunchFailed)?;
        set_nonblocking(&stdin)?;
        set_nonblocking(&stdout)?;
        Ok(Box::new(ProcessConnectorWorkerChildV2 {
            child,
            stdin: Some(stdin),
            stdout: Some(stdout),
            ephemeral_signing_seed: Some(ephemeral_signing_seed),
            parent_public_key: job.parent_public_key(),
            sent_job: false,
            reaped: false,
        }))
    }
}

struct ProcessConnectorWorkerChildV2 {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: Option<ChildStdout>,
    ephemeral_signing_seed: Option<Zeroizing<[u8; 32]>>,
    parent_public_key: [u8; 32],
    sent_job: bool,
    reaped: bool,
}

impl ConnectorWorkerChildV2 for ProcessConnectorWorkerChildV2 {
    fn send_job(
        &mut self,
        canonical_descriptor: &[u8],
        input: ConnectorWorkerInputV2<'_>,
        deadline: Instant,
    ) -> Result<(), ConnectorWorkerSupervisorErrorV2> {
        if self.sent_job
            || canonical_descriptor.is_empty()
            || canonical_descriptor.len() > MAX_CONNECTOR_DESCRIPTOR_BYTES
        {
            return Err(ConnectorWorkerSupervisorErrorV2::ProtocolViolation);
        }
        let seed = self
            .ephemeral_signing_seed
            .take()
            .ok_or(ConnectorWorkerSupervisorErrorV2::ProtocolViolation)?;
        let (mode, input_bytes, effect_digest) = match input {
            ConnectorWorkerInputV2::Prepare {
                credential_free_material,
            } => {
                if credential_free_material.is_empty()
                    || credential_free_material.len() > MAX_CONNECTOR_MATERIAL_BYTES
                {
                    return Err(ConnectorWorkerSupervisorErrorV2::ProtocolViolation);
                }
                (1_u16, credential_free_material, None)
            }
            ConnectorWorkerInputV2::DecodeRetainedResponse {
                retained_provider_response,
                effect_started_receipt_digest,
            } => {
                if retained_provider_response.is_empty()
                    || retained_provider_response.len() > MAX_CONNECTOR_RESPONSE_BYTES
                    || is_zero(effect_started_receipt_digest.as_bytes())
                {
                    return Err(ConnectorWorkerSupervisorErrorV2::ProtocolViolation);
                }
                (
                    2_u16,
                    retained_provider_response,
                    Some(effect_started_receipt_digest),
                )
            }
        };
        let mut encoder = minicbor::Encoder::new(Vec::new());
        encoder
            .array(7)
            .and_then(|encoder| encoder.u16(2))
            .and_then(|encoder| encoder.bytes(canonical_descriptor))
            .and_then(|encoder| encoder.u16(mode))
            .and_then(|encoder| encoder.bytes(input_bytes))
            .map_err(|_| ConnectorWorkerSupervisorErrorV2::ProtocolViolation)?;
        match effect_digest {
            Some(value) => encoder
                .bytes(value.as_bytes())
                .map_err(|_| ConnectorWorkerSupervisorErrorV2::ProtocolViolation)?,
            None => encoder
                .null()
                .map_err(|_| ConnectorWorkerSupervisorErrorV2::ProtocolViolation)?,
        };
        encoder
            .bytes(seed.as_ref())
            .and_then(|encoder| encoder.bytes(&self.parent_public_key))
            .map_err(|_| ConnectorWorkerSupervisorErrorV2::ProtocolViolation)?;
        let frame = encoder.into_writer();
        if frame.len() > MAX_JOB_FRAME_BYTES {
            return Err(ConnectorWorkerSupervisorErrorV2::ProtocolViolation);
        }
        write_frame(
            self.stdin
                .as_mut()
                .ok_or(ConnectorWorkerSupervisorErrorV2::ProtocolViolation)?,
            &frame,
            deadline,
        )?;
        self.sent_job = true;
        Ok(())
    }

    fn receive_frame(
        &mut self,
        deadline: Instant,
    ) -> Result<Option<Vec<u8>>, ConnectorWorkerSupervisorErrorV2> {
        read_frame(
            self.stdout
                .as_mut()
                .ok_or(ConnectorWorkerSupervisorErrorV2::ProtocolViolation)?,
            MAX_CONNECTOR_FRAME_BYTES,
            deadline,
        )
    }

    fn send_provider_response(
        &mut self,
        canonical_frame: &[u8],
        deadline: Instant,
    ) -> Result<(), ConnectorWorkerSupervisorErrorV2> {
        if !self.sent_job {
            return Err(ConnectorWorkerSupervisorErrorV2::ProtocolViolation);
        }
        write_frame(
            self.stdin
                .as_mut()
                .ok_or(ConnectorWorkerSupervisorErrorV2::ProtocolViolation)?,
            canonical_frame,
            deadline,
        )
    }

    fn finish_after_terminal(
        &mut self,
        deadline: Instant,
    ) -> Result<(), ConnectorWorkerSupervisorErrorV2> {
        if self.receive_frame(deadline)?.is_some() {
            return Err(ConnectorWorkerSupervisorErrorV2::ProtocolViolation);
        }
        self.stdin.take();
        self.stdout.take();
        wait_success(&mut self.child, deadline)?;
        self.reaped = true;
        Ok(())
    }

    fn kill_and_reap(&mut self) {
        self.stdin.take();
        self.stdout.take();
        let _ = self.child.kill();
        let _ = self.child.wait();
        self.reaped = true;
    }
}

impl Drop for ProcessConnectorWorkerChildV2 {
    fn drop(&mut self) {
        if !self.reaped {
            self.kill_and_reap();
        }
    }
}

fn verify_measured_file(
    path: &Path,
    expected_digest: Digest32V2,
    owner_uid: u32,
    owner_gid: u32,
    executable: bool,
) -> Result<(), ConnectorWorkerSupervisorErrorV2> {
    if !path.is_absolute() || is_zero(expected_digest.as_bytes()) {
        return Err(ConnectorWorkerSupervisorErrorV2::SandboxUnavailable);
    }
    verify_parent_chain(
        path.parent()
            .ok_or(ConnectorWorkerSupervisorErrorV2::SandboxUnavailable)?,
    )?;
    let linked = fs::symlink_metadata(path)
        .map_err(|_| ConnectorWorkerSupervisorErrorV2::SandboxUnavailable)?;
    if linked.file_type().is_symlink()
        || !linked.is_file()
        || linked.uid() != owner_uid
        || linked.gid() != owner_gid
        || linked.nlink() != 1
        || linked.mode() & 0o022 != 0
        || (executable && linked.mode() & 0o111 == 0)
    {
        return Err(ConnectorWorkerSupervisorErrorV2::SandboxUnavailable);
    }
    let bytes = fs::read(path).map_err(|_| ConnectorWorkerSupervisorErrorV2::SandboxUnavailable)?;
    if Digest32V2::new(Sha256::digest(&bytes).into()) != expected_digest {
        return Err(ConnectorWorkerSupervisorErrorV2::SandboxUnavailable);
    }
    Ok(())
}

fn verify_parent_chain(path: &Path) -> Result<(), ConnectorWorkerSupervisorErrorV2> {
    for component in path.ancestors() {
        let metadata = fs::symlink_metadata(component)
            .map_err(|_| ConnectorWorkerSupervisorErrorV2::SandboxUnavailable)?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || (metadata.mode() & 0o002 != 0 && metadata.mode() & 0o1000 == 0)
        {
            return Err(ConnectorWorkerSupervisorErrorV2::SandboxUnavailable);
        }
    }
    Ok(())
}

fn set_nonblocking(file: &impl AsRawFd) -> Result<(), ConnectorWorkerSupervisorErrorV2> {
    let raw = file.as_raw_fd();
    let flags = fcntl(raw, FcntlArg::F_GETFL)
        .map(OFlag::from_bits_truncate)
        .map_err(|_| ConnectorWorkerSupervisorErrorV2::LaunchFailed)?;
    fcntl(raw, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK))
        .map(|_| ())
        .map_err(|_| ConnectorWorkerSupervisorErrorV2::LaunchFailed)
}

fn write_frame(
    output: &mut ChildStdin,
    payload: &[u8],
    deadline: Instant,
) -> Result<(), ConnectorWorkerSupervisorErrorV2> {
    if payload.is_empty() || payload.len() > MAX_CONNECTOR_FRAME_BYTES.max(MAX_JOB_FRAME_BYTES) {
        return Err(ConnectorWorkerSupervisorErrorV2::ProtocolViolation);
    }
    let length = u32::try_from(payload.len())
        .map_err(|_| ConnectorWorkerSupervisorErrorV2::ProtocolViolation)?;
    write_all_deadline(output, &length.to_be_bytes(), deadline)?;
    write_all_deadline(output, payload, deadline)
}

fn read_frame(
    input: &mut ChildStdout,
    maximum: usize,
    deadline: Instant,
) -> Result<Option<Vec<u8>>, ConnectorWorkerSupervisorErrorV2> {
    let mut header = [0_u8; 4];
    if !read_exact_or_eof(input, &mut header, deadline)? {
        return Ok(None);
    }
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > maximum {
        return Err(ConnectorWorkerSupervisorErrorV2::ProtocolViolation);
    }
    let mut body = Vec::new();
    body.try_reserve_exact(length)
        .map_err(|_| ConnectorWorkerSupervisorErrorV2::ProtocolViolation)?;
    body.resize(length, 0);
    if !read_exact_or_eof(input, &mut body, deadline)? {
        return Err(ConnectorWorkerSupervisorErrorV2::ProtocolViolation);
    }
    Ok(Some(body))
}

fn write_all_deadline(
    output: &mut ChildStdin,
    mut bytes: &[u8],
    deadline: Instant,
) -> Result<(), ConnectorWorkerSupervisorErrorV2> {
    while !bytes.is_empty() {
        poll_ready(output.as_fd(), PollFlags::POLLOUT, deadline)?;
        match output.write(bytes) {
            Ok(0) => return Err(ConnectorWorkerSupervisorErrorV2::ProtocolViolation),
            Ok(written) => bytes = &bytes[written..],
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(_) => return Err(ConnectorWorkerSupervisorErrorV2::ProtocolViolation),
        }
    }
    Ok(())
}

fn read_exact_or_eof(
    input: &mut ChildStdout,
    bytes: &mut [u8],
    deadline: Instant,
) -> Result<bool, ConnectorWorkerSupervisorErrorV2> {
    let mut offset = 0;
    while offset < bytes.len() {
        poll_ready(input.as_fd(), PollFlags::POLLIN, deadline)?;
        match input.read(&mut bytes[offset..]) {
            Ok(0) if offset == 0 => return Ok(false),
            Ok(0) => return Err(ConnectorWorkerSupervisorErrorV2::ProtocolViolation),
            Ok(read) => offset += read,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(_) => return Err(ConnectorWorkerSupervisorErrorV2::ProtocolViolation),
        }
    }
    Ok(true)
}

fn poll_ready(
    descriptor: std::os::fd::BorrowedFd<'_>,
    interest: PollFlags,
    deadline: Instant,
) -> Result<(), ConnectorWorkerSupervisorErrorV2> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(ConnectorWorkerSupervisorErrorV2::DeadlineExceeded);
    }
    let timeout = PollTimeout::try_from(remaining).unwrap_or(PollTimeout::MAX);
    let mut descriptors = [PollFd::new(descriptor, interest)];
    let ready = poll(&mut descriptors, timeout)
        .map_err(|_| ConnectorWorkerSupervisorErrorV2::ProtocolViolation)?;
    if ready == 0 {
        return Err(ConnectorWorkerSupervisorErrorV2::DeadlineExceeded);
    }
    let flags = descriptors[0]
        .revents()
        .ok_or(ConnectorWorkerSupervisorErrorV2::ProtocolViolation)?;
    if flags.intersects(PollFlags::POLLERR | PollFlags::POLLNVAL) {
        return Err(ConnectorWorkerSupervisorErrorV2::ProtocolViolation);
    }
    Ok(())
}

fn wait_success(
    child: &mut Child,
    deadline: Instant,
) -> Result<(), ConnectorWorkerSupervisorErrorV2> {
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|_| ConnectorWorkerSupervisorErrorV2::ProtocolViolation)?
        {
            return if status.success() {
                Ok(())
            } else {
                Err(ConnectorWorkerSupervisorErrorV2::ProtocolViolation)
            };
        }
        if Instant::now() >= deadline {
            return Err(ConnectorWorkerSupervisorErrorV2::DeadlineExceeded);
        }
        std::thread::park_timeout(Duration::from_millis(1));
    }
}

fn is_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    use savana_kernel_protocol::v2::Digest32V2;
    use sha2::{Digest as _, Sha256};
    use tempfile::tempdir;

    use super::VerifiedConnectorSandboxProgramV2;

    #[test]
    fn both_isolation_profiles_are_measured_and_immutable() {
        let directory = tempdir().unwrap();
        let canonical_directory = directory.path().canonicalize().unwrap();
        let sandbox = canonical_directory.join("sandbox");
        let worker = canonical_directory.join("worker");
        let network = canonical_directory.join("no-network");
        let credentials = canonical_directory.join("no-credentials");
        for (path, bytes, mode) in [
            (&sandbox, b"sandbox".as_slice(), 0o500),
            (&worker, b"worker".as_slice(), 0o500),
            (&network, b"network".as_slice(), 0o400),
            (&credentials, b"credentials".as_slice(), 0o400),
        ] {
            fs::write(path, bytes).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
        }
        let identity = fs::metadata(&sandbox).unwrap();
        let digest = |bytes: &[u8]| Digest32V2::new(Sha256::digest(bytes).into());

        assert!(VerifiedConnectorSandboxProgramV2::from_verified_manifest(
            sandbox.clone(),
            digest(b"sandbox"),
            worker.clone(),
            digest(b"worker"),
            network.clone(),
            digest(b"network"),
            credentials.clone(),
            digest(b"credentials"),
            identity.uid(),
            identity.gid(),
        )
        .is_ok());

        fs::set_permissions(&credentials, fs::Permissions::from_mode(0o602)).unwrap();
        assert!(VerifiedConnectorSandboxProgramV2::from_verified_manifest(
            sandbox,
            digest(b"sandbox"),
            worker,
            digest(b"worker"),
            network,
            digest(b"network"),
            credentials,
            digest(b"credentials"),
            identity.uid(),
            identity.gid(),
        )
        .is_err());
    }
}
