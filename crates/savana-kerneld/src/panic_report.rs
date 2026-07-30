use std::os::fd::OwnedFd;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;

use rustix::io::write;
use savana_kernel_protocol::{Digest32, StableCode};

const RELEASE_UNVERIFIED: u8 = 0;
const RELEASE_PUBLISHING: u8 = 1;
const RELEASE_VERIFIED: u8 = 2;
const PANIC_PREFIX: &[u8] = b"savana-kerneld aborted; release=";
const UNVERIFIED_LINE: &[u8] = b"savana-kerneld aborted; release=unverified\n";

type PreviousHook = Box<dyn Fn(&std::panic::PanicHookInfo<'_>) + Send + Sync + 'static>;

struct ReleaseDigestState {
    phase: AtomicU8,
    digest: [AtomicU8; 32],
}

impl ReleaseDigestState {
    fn new() -> Self {
        Self {
            phase: AtomicU8::new(RELEASE_UNVERIFIED),
            digest: std::array::from_fn(|_| AtomicU8::new(0)),
        }
    }

    fn publish(&self, digest: Digest32) -> Result<(), StableCode> {
        self.phase
            .compare_exchange(
                RELEASE_UNVERIFIED,
                RELEASE_PUBLISHING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map_err(|_| StableCode::KernelUnavailable)?;
        for (target, value) in self.digest.iter().zip(digest.as_bytes()) {
            target.store(*value, Ordering::Relaxed);
        }
        self.phase.store(RELEASE_VERIFIED, Ordering::Release);
        Ok(())
    }

    fn verified_digest(&self) -> Option<[u8; 32]> {
        if self.phase.load(Ordering::Acquire) != RELEASE_VERIFIED {
            return None;
        }
        Some(std::array::from_fn(|index| {
            self.digest[index].load(Ordering::Relaxed)
        }))
    }
}

pub(crate) struct PanicHookGuard {
    previous: Option<PreviousHook>,
    release: Arc<ReleaseDigestState>,
}

impl std::fmt::Debug for PanicHookGuard {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PanicHookGuard(<redacted>)")
    }
}

impl PanicHookGuard {
    pub(crate) fn install(descriptor: OwnedFd) -> Self {
        let previous = std::panic::take_hook();
        let release = Arc::new(ReleaseDigestState::new());
        let hook_release = Arc::clone(&release);
        std::panic::set_hook(Box::new(move |_panic| {
            write_panic_line(&descriptor, &hook_release);
        }));
        Self {
            previous: Some(previous),
            release,
        }
    }

    pub(crate) fn publish_release(&self, digest: Digest32) -> Result<(), StableCode> {
        self.release.publish(digest)
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

fn write_panic_line(descriptor: &OwnedFd, release: &ReleaseDigestState) {
    let Some(digest) = release.verified_digest() else {
        let _ = write(descriptor, UNVERIFIED_LINE);
        return;
    };
    let mut line = [0_u8; PANIC_PREFIX.len() + 64 + 1];
    line[..PANIC_PREFIX.len()].copy_from_slice(PANIC_PREFIX);
    let mut offset = PANIC_PREFIX.len();
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in digest {
        line[offset] = HEX[usize::from(byte >> 4)];
        line[offset + 1] = HEX[usize::from(byte & 0x0f)];
        offset += 2;
    }
    line[offset] = b'\n';
    let _ = write(descriptor, &line);
}

#[cfg(test)]
pub(crate) static PROCESS_PANIC_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use std::io::Read;
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;

    use savana_kernel_protocol::{Digest32, StableCode};

    use super::*;

    #[test]
    fn panic_hook_ignores_payload_before_release_verification() {
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

    #[test]
    fn verified_release_digest_is_write_once_and_lowercase() {
        let _guard = PROCESS_PANIC_TEST_LOCK.lock().unwrap();
        let (writer, mut reader) = UnixStream::pair().unwrap();
        writer.set_nonblocking(true).unwrap();
        let writer: OwnedFd = writer.into();
        let hook = PanicHookGuard::install(writer);
        hook.publish_release(Digest32::new([0xab; 32])).unwrap();
        assert_eq!(
            hook.publish_release(Digest32::new([0xcd; 32])),
            Err(StableCode::KernelUnavailable)
        );

        let _ = std::panic::catch_unwind(|| panic!("another secret"));
        hook.restore();

        let mut output = String::new();
        reader.read_to_string(&mut output).unwrap();
        assert_eq!(
            output,
            format!("savana-kerneld aborted; release={}\n", "ab".repeat(32))
        );
        assert!(!output.contains("another secret"));
    }
}
