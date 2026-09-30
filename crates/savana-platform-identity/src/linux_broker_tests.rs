use super::*;
use std::os::fd::AsRawFd;

fn identity(uid: u32, byte: u8) -> Identity {
    Identity {
        uid,
        gid: uid,
        executable_sha256: [byte; 32],
    }
}

fn measurement(uid: u32, byte: u8) -> NativePeerMeasurementV2 {
    NativePeerMeasurementV2::linux(uid, uid, 100, 1, [byte; 32]).unwrap()
}

#[test]
fn edges_are_directional_and_bind_every_identity_field() {
    let policy = Policy {
        version: 2,
        edges: vec![Edge {
            caller: identity(1001, 1),
            peer: identity(1002, 2),
        }],
    };
    assert!(policy.permits(&measurement(1001, 1), &measurement(1002, 2)));
    assert!(!policy.permits(&measurement(1002, 2), &measurement(1001, 1)));
    assert!(!policy.permits(&measurement(1001, 9), &measurement(1002, 2)));
    assert!(!policy.permits(&measurement(1001, 1), &measurement(1002, 9)));
    let wrong_group = NativePeerMeasurementV2::linux(1002, 55, 100, 1, [2; 32]).unwrap();
    assert!(!policy.permits(&measurement(1001, 1), &wrong_group));
    // Approvald's measured administrator is root, but never an arbitrary root
    // executable. A root peer needs its own explicit edge and pinned digest.
    let admin = Policy {
        version: 2,
        edges: vec![Edge {
            caller: identity(1001, 1),
            peer: identity(0, 3),
        }],
    };
    assert!(admin.permits(&measurement(1001, 1), &measurement(0, 3)));
    assert!(!admin.permits(&measurement(1001, 1), &measurement(0, 4)));
}

#[test]
fn policy_rejects_unknown_empty_zero_duplicate_and_oversized_inputs() {
    let id = |uid| serde_json::json!({"uid": uid, "gid": uid, "executable_sha256": vec![1; 32]});
    let edge = serde_json::json!({"caller": id(1001), "peer": id(1002)});
    let good = serde_json::json!({"version": 2, "edges": [edge.clone()]});
    assert!(Policy::parse(&serde_json::to_vec(&good).unwrap()).is_ok());
    for bad in [
        serde_json::json!({"version": 1, "edges": [edge.clone()]}),
        serde_json::json!({"version": 2, "edges": []}),
        serde_json::json!({"version": 2, "edges": [edge.clone(), edge.clone()]}),
        serde_json::json!({"version": 2, "edges": [edge.clone()], "fallback": true}),
        serde_json::json!({"version": 2, "edges": [{"caller": id(0), "peer": id(1002)}]}),
    ] {
        assert!(Policy::parse(&serde_json::to_vec(&bad).unwrap()).is_err());
    }
    assert!(Policy::parse(&vec![b' '; 65537]).is_err());
    assert!(!identity(1001, 0).valid());
}

#[test]
fn descriptor_roundtrip_is_cloexec_and_pins_the_same_file() {
    let (a, b) = UnixStream::pair().unwrap();
    deadlines(&a).unwrap();
    deadlines(&b).unwrap();
    let mut file = tempfile::tempfile().unwrap();
    file.write_all(b"synthetic descriptor").unwrap();
    send_fd(&a, MAGIC, &file).unwrap();
    let (bytes, fd) = receive_fd::<4>(&b).unwrap();
    assert_eq!(&bytes, MAGIC);
    let flags = nix::fcntl::fcntl(fd.as_raw_fd(), nix::fcntl::FcntlArg::F_GETFD).unwrap();
    assert_ne!(flags & nix::fcntl::FdFlag::FD_CLOEXEC.bits(), 0);
    assert_eq!(
        rustix::fs::fstat(&fd).unwrap().st_ino,
        file.metadata().unwrap().ino()
    );
}

#[test]
fn multiple_or_truncated_descriptors_never_produce_a_measurement() {
    for count in [2, 8] {
        let (a, b) = UnixStream::pair().unwrap();
        deadlines(&b).unwrap();
        let file = tempfile::tempfile().unwrap();
        let fds = vec![file.as_fd(); count];
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(8))];
        let mut control = SendAncillaryBuffer::new(&mut space);
        assert!(control.push(SendAncillaryMessage::ScmRights(&fds)));
        sendmsg(
            &a,
            &[IoSlice::new(MAGIC)],
            &mut control,
            SendFlags::NOSIGNAL,
        )
        .unwrap();
        assert!(receive_fd::<4>(&b).is_err());
    }
}

#[test]
fn missing_descriptor_is_rejected() {
    let (mut a, b) = UnixStream::pair().unwrap();
    a.write_all(MAGIC).unwrap();
    assert!(receive_fd::<4>(&b).is_err());
}

#[test]
fn fragmented_request_has_one_absolute_deadline() {
    let (a, b) = UnixStream::pair().unwrap();
    let file = tempfile::tempfile().unwrap();
    send_fd(&a, &MAGIC[..1], &file).unwrap();
    let start = Instant::now();
    assert!(receive_fd_until::<4>(&b, start + Duration::from_millis(30)).is_err());
    assert!(start.elapsed() < Duration::from_secs(1));
    assert!(remaining(Instant::now() - Duration::from_secs(1)).is_err());
}

#[test]
fn wire_credentials_cannot_substitute_a_different_process() {
    let (a, _) = UnixStream::pair().unwrap();
    let credentials = getsockopt(&a, PeerCredentials).unwrap();
    let wrong = measurement(credentials.uid().wrapping_add(1), 1);
    let bytes = encode(&wrong).unwrap();
    assert!(matches!(
        decode(&bytes, credentials, &mut tempfile::tempfile().unwrap()),
        Err(Error::IdentityMismatch)
    ));
}

#[test]
fn executable_hash_is_bounded_and_rewinds() {
    let mut file = tempfile::tempfile().unwrap();
    assert!(hash_executable(&mut file).is_err());
    file.write_all(b"synthetic executable").unwrap();
    assert_eq!(
        hash_executable(&mut file).unwrap(),
        hash_executable(&mut file).unwrap()
    );
    file.set_len(256 * 1024 * 1024 + 1).unwrap();
    assert!(hash_executable(&mut file).is_err());
}

#[test]
fn unlisted_caller_is_rejected_before_reading_a_request() {
    let (a, _) = UnixStream::pair().unwrap();
    let policy = Policy {
        version: 2,
        edges: vec![],
    };
    assert!(matches!(handle(&a, &policy), Err(Error::IdentityMismatch)));
}

#[test]
fn broker_startup_requires_only_ptrace_and_no_new_privileges() {
    let good = "CapEff:\t00080000\nCapPrm:\t00080000\nCapBnd:\t00080000\nCapInh:\t0\nCapAmb:\t0\nNoNewPrivs:\t1\n";
    assert!(verify_broker_capabilities(good).is_ok());
    for bad in [
        good.replace("00080000", "ffffffff"),
        good.replace("00080000", "0"),
        good.replace("NoNewPrivs:\t1", "NoNewPrivs:\t0"),
        format!("{good}CapEff:\t00080000\n"),
        String::new(),
    ] {
        assert!(verify_broker_capabilities(&bad).is_err());
    }
}

#[test]
fn peer_pidfd_tracks_the_socket_process_after_exit() {
    const KEY: &str = "SAVANA_PEERPIDFD_FIXTURE";
    if let Some(path) = std::env::var_os(KEY) {
        let mut stream = UnixStream::connect(path).unwrap();
        deadlines(&stream).unwrap();
        stream.write_all(&[1]).unwrap();
        let mut release = [0];
        stream.read_exact(&mut release).unwrap();
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("peer.sock");
    let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
    listener.set_nonblocking(true).unwrap();
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "linux_broker::tests::peer_pidfd_tracks_the_socket_process_after_exit",
        ])
        .env_clear()
        .env(KEY, &path)
        .stdout(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut peer = loop {
        match listener.accept() {
            Ok((stream, _)) => break stream,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10))
            }
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("accept fixture: {e}");
            }
        }
    };
    deadlines(&peer).unwrap();
    let mut ready = [0];
    peer.read_exact(&mut ready).unwrap();
    let pidfd = socket_peer_pidfd(&peer).unwrap();
    require_live(&pidfd).unwrap();
    peer.write_all(&[1]).unwrap();
    assert!(child.wait().unwrap().success());
    assert!(matches!(require_live(&pidfd), Err(Error::ProcessExited)));
    assert!(crate::measure_linux_peer_v2(&peer).is_err());
}
