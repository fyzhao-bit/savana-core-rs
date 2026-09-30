//! Diagnostic only: exercise the real peer measurer under a service identity.
//! Run in a disposable, group-restricted directory, never on production sockets.

#[cfg(target_os = "linux")]
fn main() {
    use std::io::{Read, Write};
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::time::{Duration, Instant};

    let args: Vec<_> = std::env::args().collect();
    if args.len() != 3 || !matches!(args[1].as_str(), "server" | "client") {
        eprintln!("usage: linux_peer_probe server|client SOCKET_PATH");
        std::process::exit(64);
    }
    let path = std::path::Path::new(&args[2]);
    if args[1] == "client" {
        let mut stream = UnixStream::connect(path).expect("connect diagnostic socket");
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut result = [0u8];
        stream
            .read_exact(&mut result)
            .expect("bounded diagnostic reply");
        println!("measurement_accepted={}", result[0] == 1);
        return;
    }

    // Do not remove or overwrite a caller's existing socket.
    let listener = UnixListener::bind(path).expect("bind fresh diagnostic socket");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut stream = loop {
        match listener.accept() {
            Ok((stream, _)) => break stream,
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(error) => panic!("bounded diagnostic accept: {error}"),
        }
    };
    let result = savana_platform_identity::measure_linux_peer_v2(&stream);
    let accepted = result.is_ok();
    match &result {
        Ok(_) => println!("native_peer_measurement=accepted"),
        Err(error) => println!("native_peer_measurement=rejected error={error:?}"),
    }
    stream.write_all(&[u8::from(accepted)]).unwrap();
    if !accepted {
        std::process::exit(2);
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("linux_peer_probe requires Linux");
    std::process::exit(64);
}
