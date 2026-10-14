use std::os::fd::OwnedFd;

use rustix::io::write;

/// The only line a kerneld panic writes. The payload may carry protected
/// values, so it is never printed.
const PANIC_LINE: &[u8] = b"savana-kerneld aborted; release=unverified\n";

type PreviousHook = Box<dyn Fn(&std::panic::PanicHookInfo<'_>) + Send + Sync + 'static>;

pub(crate) struct PanicHookGuard {
    previous: Option<PreviousHook>,
}

impl std::fmt::Debug for PanicHookGuard {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PanicHookGuard(<redacted>)")
    }
}

impl PanicHookGuard {
    pub(crate) fn install(descriptor: OwnedFd) -> Self {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |_panic| {
            let _ = write(&descriptor, PANIC_LINE);
        }));
        Self {
            previous: Some(previous),
        }
    }

    pub(crate) fn restore(mut self) {
        self.restore_previous();
    }

    fn restore_previous(&mut self) {
        if let Some(previous) = self.previous.take() {
            std::panic::set_hook(previous);
        }
    }
}

impl Drop for PanicHookGuard {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            self.restore_previous();
        }
    }
}

#[cfg(test)]
pub(crate) static PROCESS_PANIC_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use std::io::Read;
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;

    use super::*;

    #[test]
    fn panic_hook_writes_one_fixed_line_and_never_the_payload() {
        let _guard = PROCESS_PANIC_TEST_LOCK.lock().unwrap();
        let (writer, mut reader) = UnixStream::pair().unwrap();
        writer.set_nonblocking(true).unwrap();
        let writer: OwnedFd = writer.into();
        let hook = PanicHookGuard::install(writer);

        let _ = std::panic::catch_unwind(|| panic!("secret panic payload"));
        hook.restore();

        let mut output = String::new();
        reader.read_to_string(&mut output).unwrap();
        assert_eq!(output, "savana-kerneld aborted; release=unverified\n");
        assert!(!output.contains("secret panic payload"));
    }
}
