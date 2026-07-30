#![forbid(unsafe_code)]

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use rustix::event::{poll, PollFd, PollFlags, Timespec};
use rustix::fs::{fstat, fsync, open, FileType, Mode, OFlags};
use rustix::io::{read, write, Errno};
use rustix::process::{getegid, geteuid};
use thiserror::Error;

pub const FIFO_PATH: &str =
    "/Library/Application Support/Savana/Development/run/kerneld-audit.fifo";
pub const LOG_PATH: &str = "/Library/Logs/Savana/Development/kerneld-audit.log";

const BUFFER_BYTES: usize = 8192;
const POLL_INTERVAL: Timespec = Timespec {
    tv_sec: 0,
    tv_nsec: 50_000_000,
};

#[derive(Debug, Error)]
pub enum BridgeError {
    #[error("audit bridge input is unavailable")]
    InputUnavailable,
    #[error("audit bridge input is unsafe")]
    UnsafeInput,
    #[error("audit bridge log is unavailable")]
    LogUnavailable,
    #[error("audit bridge log is unsafe")]
    UnsafeLog,
    #[error("audit bridge I/O failed")]
    Io,
}

pub fn run_with_paths(
    fifo_path: &Path,
    log_path: &Path,
    expected_fifo_owner_uid: u32,
    stop: &AtomicBool,
) -> Result<(), BridgeError> {
    let fifo = open(
        fifo_path,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| BridgeError::InputUnavailable)?;
    validate_fifo(&fifo, expected_fifo_owner_uid)?;

    let log = open(
        log_path,
        OFlags::WRONLY | OFlags::APPEND | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| BridgeError::LogUnavailable)?;
    validate_log(&log)?;

    let mut buffer = [0_u8; BUFFER_BYTES];
    while !stop.load(Ordering::Acquire) {
        let mut descriptors = [PollFd::new(&fifo, PollFlags::IN)];
        match poll(&mut descriptors, Some(&POLL_INTERVAL)) {
            Ok(0) => continue,
            Ok(_) => {
                let events = descriptors[0].revents();
                if events.intersects(PollFlags::ERR | PollFlags::NVAL) {
                    return Err(BridgeError::Io);
                }
                if !events.contains(PollFlags::IN) {
                    if events.contains(PollFlags::HUP) {
                        std::thread::sleep(std::time::Duration::from_millis(50));
                    }
                    continue;
                }
            }
            Err(Errno::INTR) => continue,
            Err(_) => return Err(BridgeError::Io),
        }

        let count = match read(&fifo, &mut buffer) {
            Ok(0) => continue,
            Ok(count) => count,
            Err(Errno::INTR | Errno::AGAIN) => continue,
            Err(_) => return Err(BridgeError::Io),
        };
        write_all(&log, &buffer[..count])?;
        fsync(&log).map_err(|_| BridgeError::Io)?;
    }
    Ok(())
}

fn validate_fifo<Fd: std::os::fd::AsFd>(
    fifo: &Fd,
    expected_owner_uid: u32,
) -> Result<(), BridgeError> {
    let metadata = fstat(fifo).map_err(|_| BridgeError::InputUnavailable)?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::Fifo
        || metadata.st_uid != expected_owner_uid
        || metadata.st_gid != getegid().as_raw()
        || metadata.st_mode & 0o777 != 0o640
        || metadata.st_nlink != 1
    {
        return Err(BridgeError::UnsafeInput);
    }
    Ok(())
}

fn validate_log<Fd: std::os::fd::AsFd>(log: &Fd) -> Result<(), BridgeError> {
    let metadata = fstat(log).map_err(|_| BridgeError::LogUnavailable)?;
    if FileType::from_raw_mode(metadata.st_mode) != FileType::RegularFile
        || metadata.st_uid != geteuid().as_raw()
        || metadata.st_gid != getegid().as_raw()
        || metadata.st_mode & 0o777 != 0o600
        || metadata.st_nlink != 1
    {
        return Err(BridgeError::UnsafeLog);
    }
    Ok(())
}

fn write_all<Fd: std::os::fd::AsFd>(log: &Fd, bytes: &[u8]) -> Result<(), BridgeError> {
    let mut offset = 0;
    while offset < bytes.len() {
        match write(log, &bytes[offset..]) {
            Ok(0) => return Err(BridgeError::Io),
            Ok(written) => offset += written,
            Err(Errno::INTR) => {}
            Err(_) => return Err(BridgeError::Io),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs::{self, OpenOptions};
    use std::io::Write as _;
    use std::os::unix::fs::{symlink, PermissionsExt as _};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::thread;
    use std::time::{Duration, Instant};

    use nix::sys::stat::Mode;
    use nix::unistd::mkfifo;

    use super::run_with_paths;

    #[test]
    fn forwards_fifo_bytes_to_private_log() {
        let fixture = tempfile::tempdir().unwrap();
        let fifo = fixture.path().join("audit.fifo");
        let log = fixture.path().join("audit.log");
        mkfifo(&fifo, Mode::from_bits_truncate(0o640)).unwrap();
        fs::write(&log, []).unwrap();
        fs::set_permissions(&log, fs::Permissions::from_mode(0o600)).unwrap();

        let stop = Arc::new(AtomicBool::new(false));
        let bridge_fifo = fifo.clone();
        let bridge_log = log.clone();
        let bridge_stop = Arc::clone(&stop);
        let bridge = thread::spawn(move || {
            run_with_paths(
                &bridge_fifo,
                &bridge_log,
                rustix::process::geteuid().as_raw(),
                bridge_stop.as_ref(),
            )
        });

        let mut writer = open_fifo_writer(&fifo);
        writer
            .write_all(b"{\"event\":\"Started\"}\nsecond-line\n")
            .unwrap();
        writer.flush().unwrap();

        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if fs::read(&log).unwrap() == b"{\"event\":\"Started\"}\nsecond-line\n" {
                break;
            }
            assert!(Instant::now() < deadline, "bridge did not forward bytes");
            thread::sleep(Duration::from_millis(10));
        }
        stop.store(true, Ordering::Release);
        bridge.join().unwrap().unwrap();
    }

    #[test]
    fn rejects_symlinked_fifo() {
        let fixture = tempfile::tempdir().unwrap();
        let fifo = fixture.path().join("real.fifo");
        let link = fixture.path().join("audit.fifo");
        let log = private_log(fixture.path());
        mkfifo(&fifo, Mode::from_bits_truncate(0o640)).unwrap();
        symlink(&fifo, &link).unwrap();

        assert!(run_with_paths(
            &link,
            &log,
            rustix::process::geteuid().as_raw(),
            &AtomicBool::new(true)
        )
        .is_err());
    }

    #[test]
    fn rejects_non_fifo_input() {
        let fixture = tempfile::tempdir().unwrap();
        let input = fixture.path().join("audit.fifo");
        let log = private_log(fixture.path());
        fs::write(&input, b"not a fifo").unwrap();
        fs::set_permissions(&input, fs::Permissions::from_mode(0o600)).unwrap();

        assert!(run_with_paths(
            &input,
            &log,
            rustix::process::geteuid().as_raw(),
            &AtomicBool::new(true)
        )
        .is_err());
    }

    #[test]
    fn rejects_non_private_or_non_regular_log() {
        let fixture = tempfile::tempdir().unwrap();
        let fifo = fixture.path().join("audit.fifo");
        mkfifo(&fifo, Mode::from_bits_truncate(0o640)).unwrap();

        let open_log = fixture.path().join("open.log");
        fs::write(&open_log, []).unwrap();
        fs::set_permissions(&open_log, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(run_with_paths(
            &fifo,
            &open_log,
            rustix::process::geteuid().as_raw(),
            &AtomicBool::new(true)
        )
        .is_err());

        let directory_log = fixture.path().join("directory.log");
        fs::create_dir(&directory_log).unwrap();
        assert!(run_with_paths(
            &fifo,
            &directory_log,
            rustix::process::geteuid().as_raw(),
            &AtomicBool::new(true)
        )
        .is_err());
    }

    #[test]
    fn rejects_fifo_owned_by_an_unexpected_writer() {
        let fixture = tempfile::tempdir().unwrap();
        let fifo = fixture.path().join("audit.fifo");
        let log = private_log(fixture.path());
        mkfifo(&fifo, Mode::from_bits_truncate(0o640)).unwrap();

        let wrong_owner = rustix::process::geteuid().as_raw().saturating_add(1);
        assert!(run_with_paths(&fifo, &log, wrong_owner, &AtomicBool::new(true)).is_err());
    }

    fn private_log(root: &std::path::Path) -> std::path::PathBuf {
        let log = root.join("audit.log");
        fs::write(&log, []).unwrap();
        fs::set_permissions(&log, fs::Permissions::from_mode(0o600)).unwrap();
        log
    }

    fn open_fifo_writer(path: &std::path::Path) -> std::fs::File {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match OpenOptions::new().write(true).open(path) {
                Ok(writer) => return writer,
                Err(error) => {
                    assert!(
                        Instant::now() < deadline,
                        "cannot open FIFO writer: {error}"
                    );
                    thread::sleep(Duration::from_millis(10));
                }
            }
        }
    }
}
