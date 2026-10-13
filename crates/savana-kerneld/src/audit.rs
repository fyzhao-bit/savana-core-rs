use std::fmt::Write as FmtWrite;
use std::fs::File;
use std::io::Write as IoWrite;
use std::os::fd::OwnedFd;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use rustix::event::{poll, PollFd, PollFlags, Timespec};
use rustix::fs::{fcntl_getfl, fcntl_setfl, fstat, FileType, OFlags};
use rustix::io::{fcntl_dupfd_cloexec, fcntl_getfd, fcntl_setfd, write, Errno, FdFlags};
use savana_kernel_protocol::StableCode;

const MAXIMUM_AUDIT_LINE_BYTES: usize = 1024;
const AUDIT_IO_DEADLINE: Duration = Duration::from_secs(5);

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum ShutdownReason {
    Sigterm,
    Sigint,
}

impl ShutdownReason {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Sigterm => "sigterm",
            Self::Sigint => "sigint",
        }
    }
}

pub(crate) enum AuditEvent {
    BootstrapFailed { code: StableCode },
    Fatal { code: StableCode },
    Stopped { reason: ShutdownReason },
}

struct AuditWriter {
    file: File,
    timeout: Duration,
}

pub(crate) struct AuditSink {
    writer: Mutex<AuditWriter>,
}

impl std::fmt::Debug for AuditSink {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("AuditSink(<bounded-stderr>)")
    }
}

impl AuditSink {
    pub(crate) fn establish() -> Result<(Self, OwnedFd), StableCode> {
        let owned = fcntl_dupfd_cloexec(rustix::stdio::stderr(), 3)
            .map_err(|_| StableCode::KernelUnavailable)?;
        let sink = Self::from_owned(owned, AUDIT_IO_DEADLINE)?;
        let panic_descriptor = sink.duplicate_for_panic()?;
        Ok((sink, panic_descriptor))
    }

    #[cfg(test)]
    pub(crate) fn from_owned_for_test(
        owned: OwnedFd,
        timeout: Duration,
    ) -> Result<Self, StableCode> {
        Self::from_owned(owned, timeout)
    }

    fn from_owned(owned: OwnedFd, timeout: Duration) -> Result<Self, StableCode> {
        if timeout.is_zero() || timeout > AUDIT_IO_DEADLINE {
            return Err(StableCode::KernelUnavailable);
        }
        let stat = fstat(&owned).map_err(|_| StableCode::KernelUnavailable)?;
        let file_type = FileType::from_raw_mode(stat.st_mode);
        if !(file_type.is_fifo() || file_type.is_socket() || file_type.is_char_device()) {
            return Err(StableCode::KernelUnavailable);
        }

        let descriptor_flags =
            fcntl_getfd(&owned).map_err(|_| StableCode::KernelUnavailable)? | FdFlags::CLOEXEC;
        fcntl_setfd(&owned, descriptor_flags).map_err(|_| StableCode::KernelUnavailable)?;
        let status =
            fcntl_getfl(&owned).map_err(|_| StableCode::KernelUnavailable)? | OFlags::NONBLOCK;
        fcntl_setfl(&owned, status).map_err(|_| StableCode::KernelUnavailable)?;
        if !fcntl_getfd(&owned)
            .map_err(|_| StableCode::KernelUnavailable)?
            .contains(FdFlags::CLOEXEC)
            || !fcntl_getfl(&owned)
                .map_err(|_| StableCode::KernelUnavailable)?
                .contains(OFlags::NONBLOCK)
        {
            return Err(StableCode::KernelUnavailable);
        }

        let file = File::from(owned);
        if file_type.is_char_device() {
            probe_character_sink(&file)?;
        }
        Ok(Self {
            writer: Mutex::new(AuditWriter { file, timeout }),
        })
    }

    pub(crate) fn emit(&self, event: AuditEvent) -> Result<(), StableCode> {
        let line = encode_event(event)?;
        let mut writer = self
            .writer
            .lock()
            .map_err(|_| StableCode::KernelUnavailable)?;
        writer.write_line(&line)
    }

    pub(crate) fn duplicate_for_panic(&self) -> Result<OwnedFd, StableCode> {
        let writer = self
            .writer
            .lock()
            .map_err(|_| StableCode::KernelUnavailable)?;
        fcntl_dupfd_cloexec(&writer.file, 3).map_err(|_| StableCode::KernelUnavailable)
    }
}

impl AuditWriter {
    fn write_line(&mut self, line: &[u8]) -> Result<(), StableCode> {
        let deadline = Instant::now()
            .checked_add(self.timeout)
            .ok_or(StableCode::KernelUnavailable)?;
        let mut offset = 0;
        while offset < line.len() {
            wait_writable(&self.file, deadline)?;
            match write(&self.file, &line[offset..]) {
                Ok(0) => return Err(StableCode::KernelUnavailable),
                Ok(written) => {
                    offset = offset
                        .checked_add(written)
                        .ok_or(StableCode::KernelUnavailable)?;
                }
                Err(error) if error == Errno::INTR || error == Errno::AGAIN => {}
                Err(_) => return Err(StableCode::KernelUnavailable),
            }
        }
        if Instant::now() >= deadline {
            return Err(StableCode::KernelUnavailable);
        }
        self.file
            .flush()
            .map_err(|_| StableCode::KernelUnavailable)?;
        if Instant::now() > deadline {
            return Err(StableCode::KernelUnavailable);
        }
        Ok(())
    }
}

fn probe_character_sink(file: &File) -> Result<(), StableCode> {
    let mut descriptor = [PollFd::new(file, PollFlags::OUT)];
    let timeout = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let ready = poll(&mut descriptor, Some(&timeout)).map_err(|_| StableCode::KernelUnavailable)?;
    let events = descriptor[0].revents();
    if ready != 1
        || !events.contains(PollFlags::OUT)
        || events.intersects(PollFlags::ERR | PollFlags::HUP | PollFlags::NVAL)
    {
        return Err(StableCode::KernelUnavailable);
    }
    Ok(())
}

fn wait_writable(file: &File, deadline: Instant) -> Result<(), StableCode> {
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or(StableCode::KernelUnavailable)?;
        let timeout = Timespec::try_from(remaining).map_err(|_| StableCode::KernelUnavailable)?;
        let mut descriptor = [PollFd::new(file, PollFlags::OUT)];
        match poll(&mut descriptor, Some(&timeout)) {
            Ok(0) => return Err(StableCode::KernelUnavailable),
            Ok(_) => {
                let events = descriptor[0].revents();
                if events.intersects(PollFlags::ERR | PollFlags::HUP | PollFlags::NVAL)
                    || !events.contains(PollFlags::OUT)
                {
                    return Err(StableCode::KernelUnavailable);
                }
                return Ok(());
            }
            Err(error) if error == Errno::INTR => {}
            Err(_) => return Err(StableCode::KernelUnavailable),
        }
    }
}

fn encode_event(event: AuditEvent) -> Result<Vec<u8>, StableCode> {
    let mut output = String::with_capacity(512);
    match event {
        AuditEvent::BootstrapFailed { code } => {
            write!(
                output,
                r#"{{"event":"BootstrapFailed","code":"{}"}}"#,
                code.as_str()
            )
            .map_err(|_| StableCode::KernelUnavailable)?;
        }
        AuditEvent::Fatal { code } => {
            write!(output, r#"{{"event":"Fatal","code":"{}"}}"#, code.as_str())
                .map_err(|_| StableCode::KernelUnavailable)?;
        }
        AuditEvent::Stopped { reason } => {
            write!(
                output,
                r#"{{"event":"Stopped","reason":"{}"}}"#,
                reason.as_str()
            )
            .map_err(|_| StableCode::KernelUnavailable)?;
        }
    }
    output.push('\n');
    if output.len() > MAXIMUM_AUDIT_LINE_BYTES {
        return Err(StableCode::KernelUnavailable);
    }
    Ok(output.into_bytes())
}

#[cfg(test)]
mod tests {
    use std::io::Read;
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    use savana_kernel_protocol::StableCode;
    #[cfg(target_os = "macos")]
    use std::fs::File;

    use super::*;

    #[test]
    fn closed_events_have_fixed_order_bounded_json_lines() {
        let (writer, mut reader) = UnixStream::pair().unwrap();
        let writer: OwnedFd = writer.into();
        let sink = AuditSink::from_owned_for_test(writer, Duration::from_millis(100)).unwrap();

        sink.emit(AuditEvent::BootstrapFailed {
            code: StableCode::IdentityReleaseMismatch,
        })
        .unwrap();
        sink.emit(AuditEvent::Fatal {
            code: StableCode::KernelUnavailable,
        })
        .unwrap();
        sink.emit(AuditEvent::Stopped {
            reason: ShutdownReason::Sigterm,
        })
        .unwrap();
        drop(sink);

        let mut output = String::new();
        reader.read_to_string(&mut output).unwrap();
        let lines: Vec<_> = output.lines().collect();
        assert_eq!(
            lines,
            [
                r#"{"event":"BootstrapFailed","code":"IDENTITY_RELEASE_MISMATCH"}"#,
                r#"{"event":"Fatal","code":"KERNEL_UNAVAILABLE"}"#,
                r#"{"event":"Stopped","reason":"sigterm"}"#,
            ]
        );
    }

    #[test]
    fn regular_file_sink_is_rejected() {
        let file = tempfile::tempfile().unwrap();
        let owned: OwnedFd = file.into();

        assert_eq!(
            AuditSink::from_owned_for_test(owned, Duration::from_millis(100))
                .err()
                .unwrap(),
            StableCode::KernelUnavailable
        );
    }

    #[test]
    fn a_poisoned_audit_mutex_fails_closed() {
        let _panic_guard = crate::panic_report::PROCESS_PANIC_TEST_LOCK.lock().unwrap();
        let (writer, _reader) = UnixStream::pair().unwrap();
        let writer: OwnedFd = writer.into();
        let sink = AuditSink::from_owned_for_test(writer, Duration::from_millis(100)).unwrap();

        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = sink.writer.lock().unwrap();
            panic!("poison audit mutex");
        }));

        assert_eq!(
            sink.emit(AuditEvent::Fatal {
                code: StableCode::KernelUnavailable,
            }),
            Err(StableCode::KernelUnavailable)
        );
    }

    #[test]
    fn closed_sink_write_failure_is_global() {
        let (writer, reader) = UnixStream::pair().unwrap();
        drop(reader);
        let writer: OwnedFd = writer.into();
        let sink = AuditSink::from_owned_for_test(writer, Duration::from_millis(100)).unwrap();

        assert_eq!(
            sink.emit(AuditEvent::Fatal {
                code: StableCode::KernelUnavailable,
            }),
            Err(StableCode::KernelUnavailable)
        );
    }

    #[test]
    fn one_deadline_bounds_a_full_nonblocking_sink() {
        let (writer, _reader) = UnixStream::pair().unwrap();
        let status = fcntl_getfl(&writer).unwrap() | OFlags::NONBLOCK;
        fcntl_setfl(&writer, status).unwrap();
        let block = [0xa5; 4096];
        loop {
            match write(&writer, &block) {
                Ok(_) => {}
                Err(error) if error == Errno::AGAIN => break,
                Err(error) => panic!("failed to fill audit socket: {error}"),
            }
        }
        let writer: OwnedFd = writer.into();
        let sink = AuditSink::from_owned_for_test(writer, Duration::from_millis(10)).unwrap();
        let started = Instant::now();

        assert_eq!(
            sink.emit(AuditEvent::Fatal {
                code: StableCode::KernelUnavailable,
            }),
            Err(StableCode::KernelUnavailable)
        );
        assert!(started.elapsed() < Duration::from_millis(250));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_dev_null_is_not_accepted_as_an_audit_poll_bypass() {
        let file = File::options().write(true).open("/dev/null").unwrap();
        let owned: OwnedFd = file.into();

        assert_eq!(
            AuditSink::from_owned_for_test(owned, Duration::from_millis(100))
                .err()
                .unwrap(),
            StableCode::KernelUnavailable
        );
    }
}
