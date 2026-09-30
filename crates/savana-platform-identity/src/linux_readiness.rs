//! Notify systemd only after the daemon has constructed its real serving state.
//! No task state, secrets or user authentication claims are sent here.
use std::os::linux::net::SocketAddrExt;
use std::os::unix::net::{SocketAddr, UnixDatagram};

fn address(value: &std::ffi::OsStr) -> std::io::Result<SocketAddr> {
    use std::os::unix::ffi::OsStrExt;
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes.len() > 107 || bytes.contains(&0) {
        return Err(std::io::ErrorKind::InvalidInput.into());
    }
    if let Some(abstract_name) = bytes.strip_prefix(b"@") {
        if abstract_name.is_empty() {
            return Err(std::io::ErrorKind::InvalidInput.into());
        }
        SocketAddr::from_abstract_name(abstract_name)
    } else if bytes[0] == b'/' {
        SocketAddr::from_pathname(std::path::Path::new(value))
    } else {
        Err(std::io::ErrorKind::InvalidInput.into())
    }
}

/// Type=simple/manual invocations have no notify socket and remain supported.
/// When systemd asks for readiness, failure to notify is a startup failure.
pub fn notify_linux_service_ready_v2() -> std::io::Result<()> {
    let Some(value) = std::env::var_os("NOTIFY_SOCKET") else {
        return Ok(());
    };
    let destination = address(&value)?;
    notify(&destination)
}

fn notify(destination: &SocketAddr) -> std::io::Result<()> {
    let socket = UnixDatagram::unbound()?;
    socket.set_write_timeout(Some(std::time::Duration::from_secs(2)))?;
    if socket.send_to_addr(b"READY=1", destination)? != 7 {
        return Err(std::io::ErrorKind::WriteZero.into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn notification_addresses_are_bounded_and_not_relative() {
        for bad in ["", "notify", "@", "a\0b"] {
            assert!(address(std::ffi::OsStr::new(bad)).is_err());
        }
        assert!(address(std::ffi::OsStr::new(&format!("/{}", "a".repeat(107)))).is_err());
        assert!(address(std::ffi::OsStr::new("/run/systemd/notify")).is_ok());
        assert!(address(std::ffi::OsStr::new("@savana-notify-test")).is_ok());
    }
    #[test]
    fn actual_datagram_contains_only_ready_and_missing_listener_fails() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("notify");
        let receiver = UnixDatagram::bind(&path).unwrap();
        receiver
            .set_read_timeout(Some(std::time::Duration::from_secs(1)))
            .unwrap();
        notify(&SocketAddr::from_pathname(&path).unwrap()).unwrap();
        let mut bytes = [0u8; 64];
        let count = receiver.recv(&mut bytes).unwrap();
        assert_eq!(&bytes[..count], b"READY=1");
        assert!(notify(&SocketAddr::from_pathname(dir.path().join("missing")).unwrap()).is_err());
    }
}
