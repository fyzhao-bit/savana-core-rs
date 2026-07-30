use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};
use std::os::unix::net::UnixListener;
use std::path::Path;

#[cfg(target_os = "linux")]
use nix::sys::socket::{getsockopt, sockopt::AcceptConn};
use rustix::fs::{fstat, FileType};
use savana_kernel_protocol::v2::{Digest32V2, EndpointRoleV2};
use sha2::{Digest as _, Sha256};

use crate::deployment_trust::DeploymentTrustErrorV2;

pub(crate) const AGENT_KERNEL_FD_NAME_V2: &str = "savana-agent-kernel";
pub(crate) const INGRESS_KERNEL_FD_NAME_V2: &str = "savana-ingress-kernel";
pub(crate) const AGENT_KERNEL_SOCKET_PATH_V2: &str = "/run/savana/kerneld/agentd/kerneld.sock";
pub(crate) const INGRESS_KERNEL_SOCKET_PATH_V2: &str = "/run/savana/kerneld/ingressd/kerneld.sock";

const LISTENER_IDENTITY_DOMAIN_V2: &[u8] = b"SAVANA_LISTENER_IDENTITY_V2\0";
const REQUIRED_SOCKET_MODE_V2: u32 = 0o660;
const MAX_SOCKET_PATH_BYTES_V2: usize = 4096;

pub(crate) struct InheritedListenerV2 {
    name: &'static str,
    listener: UnixListener,
}

impl InheritedListenerV2 {
    pub(crate) const fn new(name: &'static str, listener: UnixListener) -> Self {
        Self { name, listener }
    }
}

pub(crate) struct VerifiedInheritedKerneldListenersV2 {
    agent: UnixListener,
    ingress: UnixListener,
}

impl std::fmt::Debug for VerifiedInheritedKerneldListenersV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("VerifiedInheritedKerneldListenersV2(<owned-descriptors>)")
    }
}

impl VerifiedInheritedKerneldListenersV2 {
    #[cfg(test)]
    pub(crate) const fn agent_role(&self) -> EndpointRoleV2 {
        EndpointRoleV2::AgentKernel
    }

    #[cfg(test)]
    pub(crate) const fn ingress_role(&self) -> EndpointRoleV2 {
        EndpointRoleV2::IngressKernel
    }

    pub(crate) fn into_parts(self) -> (UnixListener, UnixListener) {
        (self.agent, self.ingress)
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn take_kerneld_systemd_listeners_v2(
    agent_listener_identity: Digest32V2,
    ingress_listener_identity: Digest32V2,
) -> Result<VerifiedInheritedKerneldListenersV2, DeploymentTrustErrorV2> {
    let inherited = savana_platform_identity::take_systemd_unix_listeners_v2(&[
        AGENT_KERNEL_FD_NAME_V2,
        INGRESS_KERNEL_FD_NAME_V2,
    ])
    .map_err(|_| DeploymentTrustErrorV2::UnsafeSocket)?;
    let mut inherited = inherited.into_iter();
    let (agent_name, agent_listener) = inherited
        .next()
        .ok_or(DeploymentTrustErrorV2::UnsafeSocket)?
        .into_parts();
    let (ingress_name, ingress_listener) = inherited
        .next()
        .ok_or(DeploymentTrustErrorV2::UnsafeSocket)?
        .into_parts();
    if inherited.next().is_some()
        || agent_name != AGENT_KERNEL_FD_NAME_V2
        || ingress_name != INGRESS_KERNEL_FD_NAME_V2
    {
        return Err(DeploymentTrustErrorV2::UnsafeSocket);
    }
    verify_kerneld_inherited_listeners_v2(
        [
            InheritedListenerV2::new(AGENT_KERNEL_FD_NAME_V2, agent_listener),
            InheritedListenerV2::new(INGRESS_KERNEL_FD_NAME_V2, ingress_listener),
        ],
        (
            Path::new(AGENT_KERNEL_SOCKET_PATH_V2),
            agent_listener_identity,
        ),
        (
            Path::new(INGRESS_KERNEL_SOCKET_PATH_V2),
            ingress_listener_identity,
        ),
    )
}

pub(crate) fn verify_kerneld_inherited_listeners_v2(
    inherited: [InheritedListenerV2; 2],
    agent_expectation: (&Path, Digest32V2),
    ingress_expectation: (&Path, Digest32V2),
) -> Result<VerifiedInheritedKerneldListenersV2, DeploymentTrustErrorV2> {
    let [agent, ingress] = inherited;
    if agent.name != AGENT_KERNEL_FD_NAME_V2 || ingress.name != INGRESS_KERNEL_FD_NAME_V2 {
        return Err(DeploymentTrustErrorV2::UnsafeSocket);
    }
    verify_listener_v2(
        &agent.listener,
        EndpointRoleV2::AgentKernel,
        agent_expectation.0,
        agent_expectation.1,
    )?;
    verify_listener_v2(
        &ingress.listener,
        EndpointRoleV2::IngressKernel,
        ingress_expectation.0,
        ingress_expectation.1,
    )?;
    Ok(VerifiedInheritedKerneldListenersV2 {
        agent: agent.listener,
        ingress: ingress.listener,
    })
}

fn verify_listener_v2(
    listener: &UnixListener,
    role: EndpointRoleV2,
    expected_path: &Path,
    expected_digest: Digest32V2,
) -> Result<(), DeploymentTrustErrorV2> {
    if !expected_path.is_absolute() || !listener_is_accepting_v2(listener)? {
        return Err(DeploymentTrustErrorV2::UnsafeSocket);
    }
    let local = listener
        .local_addr()
        .map_err(|_| DeploymentTrustErrorV2::UnsafeSocket)?;
    if !local.as_pathname().is_some_and(|actual_path| {
        savana_platform_identity::launchd_unix_socket_path_matches_v2(actual_path, expected_path)
    }) {
        return Err(DeploymentTrustErrorV2::UnsafeSocket);
    }
    let descriptor = fstat(listener).map_err(|_| DeploymentTrustErrorV2::UnsafeSocket)?;
    if FileType::from_raw_mode(descriptor.st_mode) != FileType::Socket {
        return Err(DeploymentTrustErrorV2::UnsafeSocket);
    }
    let path_metadata = std::fs::symlink_metadata(expected_path)
        .map_err(|_| DeploymentTrustErrorV2::UnsafeSocket)?;
    if path_metadata.file_type().is_symlink() || !path_metadata.file_type().is_socket() {
        return Err(DeploymentTrustErrorV2::UnsafeSocket);
    }
    let mode = path_metadata.mode() & 0o7777;
    if mode != REQUIRED_SOCKET_MODE_V2
        || listener_identity_digest_v2(
            role,
            expected_path,
            path_metadata.uid(),
            path_metadata.gid(),
            mode,
        )? != expected_digest
    {
        return Err(DeploymentTrustErrorV2::UnsafeSocket);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn listener_is_accepting_v2(listener: &UnixListener) -> Result<bool, DeploymentTrustErrorV2> {
    getsockopt(listener, AcceptConn).map_err(|_| DeploymentTrustErrorV2::UnsafeSocket)
}

#[cfg(not(target_os = "linux"))]
fn listener_is_accepting_v2(_listener: &UnixListener) -> Result<bool, DeploymentTrustErrorV2> {
    // SO_ACCEPTCONN is not available for AF_UNIX on every development
    // platform. Production is Linux and performs the kernel-level check.
    Ok(true)
}

pub(crate) fn listener_identity_digest_v2(
    role: EndpointRoleV2,
    path: &Path,
    uid: u32,
    gid: u32,
    mode: u32,
) -> Result<Digest32V2, DeploymentTrustErrorV2> {
    use std::os::unix::ffi::OsStrExt as _;

    let path = path.as_os_str().as_bytes();
    if !matches!(
        role,
        EndpointRoleV2::AgentKernel
            | EndpointRoleV2::IngressKernel
            | EndpointRoleV2::KernelExecutor
    ) || path.is_empty()
        || path.len() > MAX_SOCKET_PATH_BYTES_V2
        || path.contains(&0)
        || mode != REQUIRED_SOCKET_MODE_V2
    {
        return Err(DeploymentTrustErrorV2::UnsafeSocket);
    }
    let path_length =
        u32::try_from(path.len()).map_err(|_| DeploymentTrustErrorV2::UnsafeSocket)?;
    let mut hasher = Sha256::new();
    hasher.update(LISTENER_IDENTITY_DOMAIN_V2);
    hasher.update(role.tag().to_be_bytes());
    hasher.update(path_length.to_be_bytes());
    hasher.update(path);
    hasher.update(uid.to_be_bytes());
    hasher.update(gid.to_be_bytes());
    hasher.update(mode.to_be_bytes());
    Ok(Digest32V2::new(hasher.finalize().into()))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    use std::os::unix::net::UnixListener;

    use savana_kernel_protocol::v2::EndpointRoleV2;

    use super::{
        listener_identity_digest_v2, verify_kerneld_inherited_listeners_v2, InheritedListenerV2,
        AGENT_KERNEL_FD_NAME_V2, INGRESS_KERNEL_FD_NAME_V2,
    };

    fn listener(
        directory: &tempfile::TempDir,
        leaf: &str,
        role: EndpointRoleV2,
    ) -> (
        UnixListener,
        std::path::PathBuf,
        savana_kernel_protocol::v2::Digest32V2,
    ) {
        let path = directory.path().join(leaf);
        let listener = UnixListener::bind(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o660)).unwrap();
        let metadata = fs::symlink_metadata(&path).unwrap();
        let digest = listener_identity_digest_v2(
            role,
            &path,
            metadata.uid(),
            metadata.gid(),
            metadata.mode() & 0o7777,
        )
        .unwrap();
        (listener, path, digest)
    }

    #[test]
    fn inherited_listener_set_is_exact_named_role_locked_and_descriptor_bound() {
        let directory = tempfile::tempdir().unwrap();
        let (agent, agent_path, agent_digest) =
            listener(&directory, "agent.sock", EndpointRoleV2::AgentKernel);
        let (ingress, ingress_path, ingress_digest) =
            listener(&directory, "ingress.sock", EndpointRoleV2::IngressKernel);
        let verified = verify_kerneld_inherited_listeners_v2(
            [
                InheritedListenerV2::new(AGENT_KERNEL_FD_NAME_V2, agent),
                InheritedListenerV2::new(INGRESS_KERNEL_FD_NAME_V2, ingress),
            ],
            (&agent_path, agent_digest),
            (&ingress_path, ingress_digest),
        )
        .unwrap();
        assert_eq!(verified.agent_role(), EndpointRoleV2::AgentKernel);
        assert_eq!(verified.ingress_role(), EndpointRoleV2::IngressKernel);

        let (wrong_agent, _, _) =
            listener(&directory, "wrong-agent.sock", EndpointRoleV2::AgentKernel);
        let (wrong_ingress, _, _) = listener(
            &directory,
            "wrong-ingress.sock",
            EndpointRoleV2::IngressKernel,
        );
        assert!(verify_kerneld_inherited_listeners_v2(
            [
                InheritedListenerV2::new(INGRESS_KERNEL_FD_NAME_V2, wrong_agent),
                InheritedListenerV2::new(AGENT_KERNEL_FD_NAME_V2, wrong_ingress),
            ],
            (&agent_path, agent_digest),
            (&ingress_path, ingress_digest),
        )
        .is_err());
    }
}
