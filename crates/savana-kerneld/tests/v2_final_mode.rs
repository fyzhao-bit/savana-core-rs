mod support;

use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;

use support::Installation;

#[test]
fn production_entry_never_publishes_a_valid_v1_installation() {
    let installation = Installation::build();
    let mut child = Command::new(&installation.executable)
        .arg("--config")
        .arg(&installation.config)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if installation.socket.exists() {
            let _ = kill(
                Pid::from_raw(i32::try_from(child.id()).unwrap()),
                Signal::SIGTERM,
            );
            let output = child.wait_with_output().unwrap();
            panic!(
                "the production entry published the V1 socket: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        if child.try_wait().unwrap().is_some() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the production entry neither failed closed nor published a socket"
        );
        thread::sleep(Duration::from_millis(10));
    }

    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(64));
    assert!(output.stdout.is_empty());
    assert!(!installation.socket.exists());
}
