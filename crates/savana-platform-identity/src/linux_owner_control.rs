//! Socket-activated listeners report systemd's SO_PEERCRED. Authenticate the
//! actual daemon over a reverse connection before sending a control envelope.
use crate::{
    measure_linux_peer_v2, NativeIdentityErrorV2 as Error, NativePeerMeasurementV2,
    PinnedLinuxPeerMeasurementV2,
};
use nix::poll::{poll, PollFd, PollFlags};
use std::io::{Read, Write};
use std::os::fd::AsFd;
use std::os::linux::net::SocketAddrExt;
use std::os::unix::net::{SocketAddr, UnixListener, UnixStream};
use std::time::{Duration, Instant};

pub const OWNER_CONTROL_REVERSE_MAGIC_V2: [u8; 4] = *b"SOC2";

fn address(nonce: &[u8; 32]) -> Result<SocketAddr, Error> {
    if *nonce == [0; 32] {
        return Err(Error::InvalidMeasurement);
    }
    let mut name = b"savana.owner.control.v2.".to_vec();
    name.extend_from_slice(nonce);
    SocketAddr::from_abstract_name(name).map_err(|_| Error::Io)
}

fn remaining(deadline: Instant) -> Result<Duration, Error> {
    let value = deadline
        .checked_duration_since(Instant::now())
        .ok_or(Error::Io)?;
    if value.is_zero() || value > Duration::from_secs(10) {
        return Err(Error::Io);
    }
    Ok(value)
}

fn timeouts(stream: &UnixStream, deadline: Instant) -> Result<(), Error> {
    let time = Some(remaining(deadline)?);
    stream
        .set_read_timeout(time)
        .and_then(|()| stream.set_write_timeout(time))
        .map_err(|_| Error::Io)
}

/// Ephemeral abstract listener, with no socket file left after drop.
pub struct OwnerControlRendezvousV2 {
    listener: UnixListener,
    nonce: [u8; 32],
}

impl OwnerControlRendezvousV2 {
    pub fn bind(nonce: [u8; 32]) -> Result<Self, Error> {
        let listener = UnixListener::bind_addr(&address(&nonce)?).map_err(|_| Error::Io)?;
        listener.set_nonblocking(true).map_err(|_| Error::Io)?;
        Ok(Self { listener, nonce })
    }

    /// Send only the rendezvous nonce. Caller MUST compare the returned pinned
    /// measurement against its verified deployment before writing an envelope.
    pub fn connect(
        self,
        initial: &mut UnixStream,
        deadline: Instant,
    ) -> Result<(UnixStream, PinnedLinuxPeerMeasurementV2), Error> {
        timeouts(initial, deadline)?;
        initial
            .write_all(&OWNER_CONTROL_REVERSE_MAGIC_V2)
            .and_then(|()| initial.write_all(&self.nonce))
            .map_err(|_| Error::Io)?;
        let mut fds = [PollFd::new(self.listener.as_fd(), PollFlags::POLLIN)];
        let millis = u16::try_from(remaining(deadline)?.as_millis()).map_err(|_| Error::Io)?;
        if millis == 0
            || poll(&mut fds, millis).map_err(|_| Error::Io)? != 1
            || !fds[0]
                .revents()
                .is_some_and(|f| f.contains(PollFlags::POLLIN))
        {
            return Err(Error::Io);
        }
        let (stream, _) = self.listener.accept().map_err(|_| Error::Io)?;
        timeouts(&stream, deadline)?;
        let pinned = measure_linux_peer_v2(&stream)?;
        remaining(deadline)?;
        Ok((stream, pinned))
    }
}

/// Initial client must already be authenticated and pinned. The reverse
/// listener must belong to that exact PID/start time/UID/GID/executable.
pub fn connect_owner_control_reverse_v2(
    initial: &mut UnixStream,
    expected_client: &NativePeerMeasurementV2,
    deadline: Instant,
) -> Result<(UnixStream, PinnedLinuxPeerMeasurementV2), Error> {
    timeouts(initial, deadline)?;
    let mut nonce = [0; 32];
    initial.read_exact(&mut nonce).map_err(|_| Error::Io)?;
    let address = address(&nonce)?;
    let address = rustix::net::SocketAddrUnix::new_abstract_name(
        address
            .as_abstract_name()
            .ok_or(Error::InvalidMeasurement)?,
    )
    .map_err(|_| Error::Io)?;
    // A full/untrusted listener backlog must not block this worker forever.
    // AF_UNIX connects synchronously when ready; EAGAIN fails without retry.
    let socket = rustix::net::socket_with(
        rustix::net::AddressFamily::UNIX,
        rustix::net::SocketType::STREAM,
        rustix::net::SocketFlags::CLOEXEC | rustix::net::SocketFlags::NONBLOCK,
        None,
    )
    .map_err(|_| Error::Io)?;
    rustix::net::connect(&socket, &address).map_err(|_| Error::Io)?;
    let stream = UnixStream::from(socket);
    stream.set_nonblocking(false).map_err(|_| Error::Io)?;
    timeouts(&stream, deadline)?;
    let pinned = measure_linux_peer_v2(&stream)?;
    if pinned.measurement() != expected_client {
        return Err(Error::IdentityMismatch);
    }
    remaining(deadline)?;
    Ok((stream, pinned))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reverse_control_preserves_initial_process_binding() {
        let mut nonce = [0; 32];
        getrandom::getrandom(&mut nonce).unwrap();
        let rendezvous = OwnerControlRendezvousV2::bind(nonce).unwrap();
        let (mut client, mut server) = UnixStream::pair().unwrap();
        let initial = measure_linux_peer_v2(&server).unwrap();
        let expected = initial.measurement().clone();
        let worker = std::thread::spawn(move || {
            let mut magic = [0; 4];
            server.read_exact(&mut magic).unwrap();
            assert_eq!(magic, OWNER_CONTROL_REVERSE_MAGIC_V2);
            let (mut reverse, _pin) = connect_owner_control_reverse_v2(
                &mut server,
                &expected,
                Instant::now() + Duration::from_secs(5),
            )
            .unwrap();
            let mut request = [0; 4];
            reverse.read_exact(&mut request).unwrap();
            assert_eq!(&request, b"test");
            reverse.write_all(b"okay").unwrap();
        });
        let (mut reverse, pinned) = rendezvous
            .connect(&mut client, Instant::now() + Duration::from_secs(5))
            .unwrap();
        assert!(pinned.measurement() == initial.measurement());
        reverse.write_all(b"test").unwrap();
        let mut reply = [0; 4];
        reverse.read_exact(&mut reply).unwrap();
        assert_eq!(&reply, b"okay");
        worker.join().unwrap();
    }
    #[test]
    fn reverse_listener_rejects_zero_reuse_expiry_and_unbounded_deadline() {
        assert!(OwnerControlRendezvousV2::bind([0; 32]).is_err());
        let mut nonce = [0; 32];
        getrandom::getrandom(&mut nonce).unwrap();
        let listener = OwnerControlRendezvousV2::bind(nonce).unwrap();
        assert!(OwnerControlRendezvousV2::bind(nonce).is_err());
        assert!(remaining(Instant::now() - Duration::from_millis(1)).is_err());
        assert!(remaining(Instant::now() + Duration::from_secs(60)).is_err());
        drop(listener);
        assert!(OwnerControlRendezvousV2::bind(nonce).is_ok());
    }

    #[test]
    fn different_initial_identity_cannot_redirect_to_reverse_listener() {
        let mut nonce = [0; 32];
        getrandom::getrandom(&mut nonce).unwrap();
        let rendezvous = OwnerControlRendezvousV2::bind(nonce).unwrap();
        let (mut client, mut server) = UnixStream::pair().unwrap();
        let initial = measure_linux_peer_v2(&server).unwrap();
        let mut expected = initial.measurement().clone();
        if let NativePeerMeasurementV2::Linux {
            process_start_time, ..
        } = &mut expected
        {
            *process_start_time += 1;
        } else {
            panic!("Linux measurement required");
        }
        let worker = std::thread::spawn(move || {
            let mut magic = [0; 4];
            server.read_exact(&mut magic).unwrap();
            assert!(matches!(
                connect_owner_control_reverse_v2(
                    &mut server,
                    &expected,
                    Instant::now() + Duration::from_secs(5)
                ),
                Err(Error::IdentityMismatch)
            ));
        });
        let (_reverse, _pin) = rendezvous
            .connect(&mut client, Instant::now() + Duration::from_secs(5))
            .unwrap();
        worker.join().unwrap();
    }

    #[test]
    fn absent_reverse_connection_times_out_without_sending_envelope() {
        let mut nonce = [0; 32];
        getrandom::getrandom(&mut nonce).unwrap();
        let rendezvous = OwnerControlRendezvousV2::bind(nonce).unwrap();
        let (mut client, mut server) = UnixStream::pair().unwrap();
        let started = Instant::now();
        assert!(rendezvous
            .connect(&mut client, started + Duration::from_millis(30))
            .is_err());
        assert!(started.elapsed() < Duration::from_secs(2));
        drop(client);
        let mut sent = Vec::new();
        server.read_to_end(&mut sent).unwrap();
        assert_eq!(sent.len(), 36);
        assert_eq!(&sent[..4], &OWNER_CONTROL_REVERSE_MAGIC_V2);
        assert_eq!(&sent[4..], &nonce);
    }

    // Spawned by the following test with the listening socket as stdin. No
    // fork/unsafe code or actual systemd installation is needed for this test.
    #[test]
    fn inherited_listener_child() {
        if std::env::var_os("SAVANA_OWNER_CONTROL_TEST_CHILD").is_none() {
            return;
        }
        let listener = UnixListener::from(rustix::io::dup(std::io::stdin()).unwrap());
        let mut fds = [PollFd::new(listener.as_fd(), PollFlags::POLLIN)];
        assert_eq!(poll(&mut fds, 5000_u16).unwrap(), 1);
        let (mut initial, _) = listener.accept().unwrap();
        let pin = measure_linux_peer_v2(&initial).unwrap();
        let mut magic = [0; 4];
        initial.read_exact(&mut magic).unwrap();
        assert_eq!(magic, OWNER_CONTROL_REVERSE_MAGIC_V2);
        let (mut reverse, _reverse_pin) = connect_owner_control_reverse_v2(
            &mut initial,
            pin.measurement(),
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap();
        let mut request = [0; 4];
        reverse.read_exact(&mut request).unwrap();
        assert_eq!(&request, b"test");
        reverse.write_all(b"okay").unwrap();
        let mut done = [0; 1];
        reverse.read_exact(&mut done).unwrap();
    }

    #[test]
    fn inherited_listener_authenticates_actual_acceptor_not_creator() {
        use std::os::fd::OwnedFd;
        use std::process::{Command, Stdio};
        let mut nonce = [0; 32];
        getrandom::getrandom(&mut nonce).unwrap();
        let initial_address = address(&nonce).unwrap();
        let listener = UnixListener::bind_addr(&initial_address).unwrap();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "linux_owner_control::tests::inherited_listener_child",
                "--nocapture",
            ])
            .env("SAVANA_OWNER_CONTROL_TEST_CHILD", "1")
            .stdin(Stdio::from(OwnedFd::from(listener.try_clone().unwrap())))
            .spawn()
            .unwrap();
        let mut initial = UnixStream::connect_addr(&initial_address).unwrap();
        let creator = measure_linux_peer_v2(&initial).unwrap();
        assert_eq!(creator.measurement().pid(), Some(std::process::id()));
        getrandom::getrandom(&mut nonce).unwrap();
        let rendezvous = OwnerControlRendezvousV2::bind(nonce).unwrap();
        let (mut reverse, acceptor) = rendezvous
            .connect(&mut initial, Instant::now() + Duration::from_secs(5))
            .unwrap();
        assert_eq!(acceptor.measurement().pid(), Some(child.id()));
        assert_ne!(creator.measurement().pid(), acceptor.measurement().pid());
        reverse.write_all(b"test").unwrap();
        let mut response = [0; 4];
        reverse.read_exact(&mut response).unwrap();
        assert_eq!(&response, b"okay");
        reverse.write_all(b"x").unwrap();
        assert!(child.wait().unwrap().success());
    }
}
