//! Private, root-only administration. Never routed through Agent/Ingress RPCs.
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ed25519_dalek::VerifyingKey;
use savana_kernel_protocol::v2::{
    derive_ed25519_key_id_v2, Digest32V2, Ed25519KeyIdV2, UnixMillisV2,
};
use savana_kernel_protocol::StableCode;
use savana_policy_core::v2::{ManagedAdminReceiptV04, VerifiedManagedAdminCommandV04};
use serde::Serialize;
use zeroize::Zeroizing;

use crate::v2_kernel_owner::KernelRuntimeOwnerV2;

#[cfg(target_os = "linux")]
pub(crate) const FD_NAME: &str = "savana-managed-admin-v04";
#[cfg(target_os = "linux")]
pub(crate) const SOCKET_PATH: &str = "/run/savana/kerneld/admin/managed-v04.sock";
const MAX_COMMAND: usize = 256 * 1024;
const DEADLINE: Duration = Duration::from_secs(5);

#[cfg(target_os = "linux")]
pub(crate) fn verify_listener(listener: &UnixListener) -> Result<(), ()> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let path = std::path::Path::new(SOCKET_PATH);
    if listener.local_addr().map_err(|_| ())?.as_pathname() != Some(path)
        || !nix::sys::socket::getsockopt(listener, nix::sys::socket::sockopt::AcceptConn)
            .map_err(|_| ())?
    {
        return Err(());
    }
    let meta = std::fs::symlink_metadata(path).map_err(|_| ())?;
    let parent = std::fs::symlink_metadata(path.parent().ok_or(())?).map_err(|_| ())?;
    if !meta.file_type().is_socket()
        || meta.uid() != 0
        || meta.gid() != 0
        || meta.mode() & 0o7777 != 0o600
        || !parent.is_dir()
        || parent.file_type().is_symlink()
        || parent.uid() != 0
        || parent.gid() != 0
        || parent.mode() & 0o7777 != 0o711
    {
        return Err(());
    }
    Ok(())
}

// Set remaining time before EVERY read/write, not just once per request. A
// trickling peer must not hold this worker indefinitely by resetting SO_RCVTIMEO.
struct DeadlineStream<'a> {
    stream: &'a mut UnixStream,
    deadline: Instant,
}
impl DeadlineStream<'_> {
    fn remaining(&self) -> std::io::Result<Duration> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::TimedOut))
    }
}
impl Read for DeadlineStream<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        self.stream.set_read_timeout(Some(self.remaining()?))?;
        self.stream.read(bytes)
    }
}
impl Write for DeadlineStream<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.stream.set_write_timeout(Some(self.remaining()?))?;
        self.stream.write(bytes)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }
}

pub(crate) struct AdminTrustV04 {
    key: VerifyingKey,
    installation: Digest32V2,
    store: Digest32V2,
}

impl AdminTrustV04 {
    pub(crate) fn from_deployment(
        expected: Option<(Ed25519KeyIdV2, [u8; 32])>,
        installation: Digest32V2,
        store: Digest32V2,
        other_keys: &[[u8; 32]],
    ) -> Result<Option<Self>, StableCode> {
        let Some((id, public)) = expected else {
            return Ok(None);
        };
        let key = VerifyingKey::from_bytes(&public).map_err(|_| StableCode::KernelUnavailable)?;
        if key.is_weak()
            || public == [0; 32]
            || other_keys.contains(&public)
            || derive_ed25519_key_id_v2(public) != id
            || installation.as_bytes() == &[0; 32]
            || store.as_bytes() == &[0; 32]
        {
            return Err(StableCode::KernelUnavailable);
        }
        Ok(Some(Self {
            key,
            installation,
            store,
        }))
    }

    pub(crate) fn verify(
        &self,
        submission: &AdminSubmissionV04,
    ) -> Result<VerifiedManagedAdminCommandV04, StableCode> {
        VerifiedManagedAdminCommandV04::verify(
            &submission.command,
            &submission.signature,
            &self.key,
            self.installation,
            self.store,
        )
        .map_err(|_| StableCode::PolicyDenied)
    }
}

// No Debug/Serialize: these contain private imported data. The only production
// constructor runs after native peer authentication, before bounded owner admission.
pub(crate) struct AdminSubmissionV04 {
    command: Zeroizing<Vec<u8>>,
    signature: [u8; 64],
}

#[cfg(test)]
impl AdminSubmissionV04 {
    pub(crate) fn for_test(
        command: &savana_policy_core::v2::ManagedAdminCommandV04,
        key: &ed25519_dalek::SigningKey,
    ) -> Self {
        use ed25519_dalek::Signer;
        Self {
            command: Zeroizing::new(command.canonical_bytes().unwrap()),
            signature: key.sign(&command.signing_digest().unwrap()).to_bytes(),
        }
    }
}

fn read_submission(reader: &mut impl Read) -> Result<AdminSubmissionV04, ()> {
    let mut size = [0; 4];
    reader.read_exact(&mut size).map_err(|_| ())?;
    let size = u32::from_be_bytes(size) as usize;
    if size == 0 || size > MAX_COMMAND {
        return Err(());
    }
    let mut command = Zeroizing::new(vec![0; size]);
    reader.read_exact(&mut command).map_err(|_| ())?;
    let mut signature = [0; 64];
    reader.read_exact(&mut signature).map_err(|_| ())?;
    // One command per connection. Require the client's write-half close before
    // any mutation so trailing bytes/second commands cannot be silently ignored.
    let mut extra = [0];
    if reader.read(&mut extra).map_err(|_| ())? != 0 {
        return Err(());
    }
    Ok(AdminSubmissionV04 { command, signature })
}

fn receipt_bytes(receipt: &ManagedAdminReceiptV04) -> Result<Zeroizing<Vec<u8>>, ()> {
    #[derive(Serialize)]
    struct PrivateReply<'a> {
        schema: u16,
        status: &'static str,
        request: [u8; 32],
        command_digest: [u8; 32],
        result: &'a savana_policy_core::v2::ManagedAdminResultV04,
    }
    serde_json::to_vec(&PrivateReply {
        schema: 1,
        status: "committed",
        request: receipt.request(),
        command_digest: receipt.command_digest(),
        result: receipt.result(),
    })
    .map(Zeroizing::new)
    .map_err(|_| ())
}

pub(crate) struct AdminEndpointV04 {
    listener: UnixListener,
    owner: Arc<KernelRuntimeOwnerV2>,
}

impl AdminEndpointV04 {
    pub(crate) fn new(
        listener: UnixListener,
        owner: Arc<KernelRuntimeOwnerV2>,
    ) -> Result<Self, StableCode> {
        listener
            .set_nonblocking(true)
            .map_err(|_| StableCode::KernelUnavailable)?;
        Ok(Self { listener, owner })
    }

    /// One bounded request per poll; caller gives this a separate worker, not the
    /// signal/rollover thread. Bad clients cannot stop the listener.
    pub(crate) fn poll(&self) -> Result<bool, ()> {
        match self.listener.accept() {
            Ok((stream, _)) => {
                let _ = self.serve(stream);
                Ok(true)
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) =>
            {
                Ok(false)
            }
            Err(_) => Err(()),
        }
    }

    fn serve(&self, mut stream: UnixStream) -> Result<(), ()> {
        verify_root_peer(&stream)?;
        let deadline = Instant::now() + DEADLINE;
        stream.set_nonblocking(false).map_err(|_| ())?;
        let mut stream = DeadlineStream {
            stream: &mut stream,
            deadline,
        };
        let submission = read_submission(&mut stream)?;
        let response = match self.owner.submit_managed_admin(submission, deadline) {
            Ok(receipt) => receipt_bytes(&receipt)?,
            // No error details/private data and no claim that an uncertain commit
            // did not happen. Caller must retry the EXACT signed command.
            Err(_) => Zeroizing::new(br#"{"schema":1,"status":"not_confirmed"}"#.to_vec()),
        };
        stream
            .write_all(&(response.len() as u32).to_be_bytes())
            .map_err(|_| ())?;
        stream.write_all(&response).map_err(|_| ())
    }
}

#[cfg(target_os = "linux")]
fn verify_root_peer(stream: &UnixStream) -> Result<(), ()> {
    let peer = nix::sys::socket::getsockopt(stream, nix::sys::socket::sockopt::PeerCredentials)
        .map_err(|_| ())?;
    if peer.uid() == 0 && peer.gid() == 0 && peer.pid() > 0 {
        Ok(())
    } else {
        Err(())
    }
}
#[cfg(not(target_os = "linux"))]
fn verify_root_peer(_: &UnixStream) -> Result<(), ()> {
    Err(())
}

pub(crate) fn now() -> Result<UnixMillisV2, StableCode> {
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| StableCode::KernelUnavailable)?
        .as_millis();
    Ok(UnixMillisV2::new(
        u64::try_from(ms).map_err(|_| StableCode::KernelUnavailable)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use savana_policy_core::v2::{ManagedAdminCommandV04, ManagedAdminOperationV04};

    fn sample() -> (SigningKey, ManagedAdminCommandV04) {
        (
            SigningKey::from_bytes(&[92; 32]),
            ManagedAdminCommandV04 {
                schema: 1,
                installation: [1; 32],
                store: [2; 32],
                request: [3; 32],
                not_before: 1,
                expires_at: 20,
                operation: ManagedAdminOperationV04::CreateResource {
                    source: [4; 32],
                    namespace: [5; 32],
                    label: "private".into(),
                    content: b"secret".to_vec(),
                },
            },
        )
    }
    fn frame(command: &ManagedAdminCommandV04, key: &SigningKey) -> Vec<u8> {
        let bytes = command.canonical_bytes().unwrap();
        let mut out = (bytes.len() as u32).to_be_bytes().to_vec();
        out.extend(bytes);
        out.extend(key.sign(&command.signing_digest().unwrap()).to_bytes());
        out
    }
    #[test]
    fn admin_frame_is_bounded_complete_and_single_command() {
        let (key, cmd) = sample();
        let data = frame(&cmd, &key);
        assert!(read_submission(&mut data.as_slice()).is_ok());
        for len in [0, 3, 4, data.len() - 1] {
            assert!(read_submission(&mut &data[..len]).is_err());
        }
        let mut extra = data;
        extra.push(0);
        assert!(read_submission(&mut extra.as_slice()).is_err());
        for len in [0_u32, MAX_COMMAND as u32 + 1, u32::MAX] {
            assert!(read_submission(&mut len.to_be_bytes().as_slice()).is_err());
        }
    }
    #[test]
    fn admin_trust_is_pinned_distinct_and_checks_namespace_and_signature() {
        let (key, cmd) = sample();
        let public = key.verifying_key().to_bytes();
        let expected = Some((derive_ed25519_key_id_v2(public), public));
        let inst = Digest32V2::new([1; 32]);
        let store = Digest32V2::new([2; 32]);
        assert!(AdminTrustV04::from_deployment(None, inst, store, &[])
            .unwrap()
            .is_none());
        assert!(AdminTrustV04::from_deployment(expected, inst, store, &[public]).is_err());
        assert!(AdminTrustV04::from_deployment(
            Some((Ed25519KeyIdV2::new([0; 32]), public)),
            inst,
            store,
            &[]
        )
        .is_err());
        let trust = AdminTrustV04::from_deployment(expected, inst, store, &[])
            .unwrap()
            .unwrap();
        let mut sub = read_submission(&mut frame(&cmd, &key).as_slice()).unwrap();
        assert!(trust.verify(&sub).is_ok());
        sub.signature[0] ^= 1;
        assert!(trust.verify(&sub).is_err());
        let mut wrong = cmd;
        wrong.store = [3; 32];
        assert!(trust
            .verify(&read_submission(&mut frame(&wrong, &key).as_slice()).unwrap())
            .is_err());
    }

    #[test]
    fn managed_admin_socket_deadline_and_half_close_are_enforced() {
        use std::net::Shutdown;
        let (mut client, mut server) = UnixStream::pair().unwrap();
        let (key, cmd) = sample();
        client.write_all(&frame(&cmd, &key)).unwrap();
        let deadline = Instant::now() + Duration::from_millis(50);
        // Full frame without EOF is not admissible.
        assert!(read_submission(&mut DeadlineStream {
            stream: &mut server,
            deadline
        })
        .is_err());
        assert!(Instant::now() >= deadline);
        let (mut client, mut server) = UnixStream::pair().unwrap();
        client.write_all(&frame(&cmd, &key)).unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        assert!(read_submission(&mut DeadlineStream {
            stream: &mut server,
            deadline: Instant::now() + DEADLINE
        })
        .is_ok());
        // Absolute deadline already elapsed: buffered bytes do not revive it.
        assert!(DeadlineStream {
            stream: &mut server,
            deadline: Instant::now() - Duration::from_millis(1)
        }
        .read(&mut [0])
        .is_err());
    }

    #[test]
    fn managed_admin_native_peer_rejects_non_root_or_unsupported_platform() {
        let (_, stream) = UnixStream::pair().unwrap();
        let expected = cfg!(target_os = "linux")
            && nix::unistd::geteuid().is_root()
            && nix::unistd::getegid().as_raw() == 0;
        assert_eq!(verify_root_peer(&stream).is_ok(), expected);
    }
}
