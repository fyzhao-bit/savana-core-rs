use std::os::unix::net::UnixStream;

use savana_kernel_protocol::StableCode;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct PeerIdentity {
    uid: u32,
    gid: u32,
}

impl PeerIdentity {
    const fn from_kernel_credentials(uid: u32, gid: u32) -> Self {
        Self { uid, gid }
    }

    pub(crate) const fn uid(self) -> u32 {
        self.uid
    }

    pub(crate) const fn gid(self) -> u32 {
        self.gid
    }

    #[cfg(test)]
    pub(crate) const fn new_for_test(uid: u32, gid: u32) -> Self {
        Self::from_kernel_credentials(uid, gid)
    }
}

impl std::fmt::Debug for PeerIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PeerIdentity(<kernel-credentials>)")
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn peer_identity(stream: &UnixStream) -> Result<PeerIdentity, StableCode> {
    use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};

    let credentials =
        getsockopt(stream, PeerCredentials).map_err(|_| StableCode::KernelUnavailable)?;
    Ok(PeerIdentity::from_kernel_credentials(
        credentials.uid(),
        credentials.gid(),
    ))
}

#[cfg(target_os = "macos")]
pub(crate) fn peer_identity(stream: &UnixStream) -> Result<PeerIdentity, StableCode> {
    let (uid, gid) = nix::unistd::getpeereid(stream).map_err(|_| StableCode::KernelUnavailable)?;
    Ok(PeerIdentity::from_kernel_credentials(
        uid.as_raw(),
        gid.as_raw(),
    ))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
compile_error!("savana-kerneld supports Unix peer credentials only on Linux and macOS");

#[cfg(test)]
mod tests {
    use nix::unistd::{getegid, geteuid};

    use super::*;

    #[test]
    fn connected_unix_stream_reports_kernel_uid_and_gid() {
        let (left, _right) = UnixStream::pair().unwrap();
        let peer = peer_identity(&left).unwrap();

        assert_eq!(peer.uid(), geteuid().as_raw());
        assert_eq!(peer.gid(), getegid().as_raw());
        assert_eq!(format!("{peer:?}"), "PeerIdentity(<kernel-credentials>)");
    }

    #[test]
    fn disconnected_unix_stream_still_uses_socket_credentials() {
        let (left, right) = UnixStream::pair().unwrap();
        drop(right);

        let peer = peer_identity(&left).unwrap();
        assert_eq!(
            peer,
            PeerIdentity::new_for_test(geteuid().as_raw(), getegid().as_raw())
        );
    }

    #[test]
    fn peer_identity_storage_contains_only_uid_and_gid() {
        assert_eq!(
            std::mem::size_of::<PeerIdentity>(),
            std::mem::size_of::<(u32, u32)>()
        );
    }
}
