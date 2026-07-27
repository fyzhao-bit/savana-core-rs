use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use savana_kernel_protocol::{BootId, StableCode, UnixMillis};
use savana_policy_core::{Clock, RandomSource};

pub(crate) struct SystemClock {
    monotonic_origin: Instant,
}

impl SystemClock {
    pub(crate) fn new() -> Self {
        Self {
            monotonic_origin: Instant::now(),
        }
    }
}

impl Clock for SystemClock {
    fn wall_now(&self) -> Result<UnixMillis, StableCode> {
        let elapsed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| StableCode::KernelUnavailable)?;
        let millis =
            u64::try_from(elapsed.as_millis()).map_err(|_| StableCode::KernelUnavailable)?;
        Ok(UnixMillis::new(millis))
    }

    fn monotonic_now_millis(&self) -> Result<u64, StableCode> {
        u64::try_from(self.monotonic_origin.elapsed().as_millis())
            .map_err(|_| StableCode::KernelUnavailable)
    }
}

pub(crate) struct SystemRandom;

impl RandomSource for SystemRandom {
    fn fill(&self, output: &mut [u8]) -> Result<usize, StableCode> {
        getrandom::getrandom(output).map_err(|_| StableCode::KernelUnavailable)?;
        Ok(output.len())
    }
}

pub(crate) fn draw_nonzero_32(random: &dyn RandomSource) -> Result<[u8; 32], StableCode> {
    let mut bytes = [0_u8; 32];
    let written = random
        .fill(&mut bytes)
        .map_err(|_| StableCode::KernelUnavailable)?;
    if written != bytes.len() || bytes == [0; 32] {
        return Err(StableCode::KernelUnavailable);
    }
    Ok(bytes)
}

pub(crate) fn draw_boot_id(random: &dyn RandomSource) -> Result<BootId, StableCode> {
    Ok(BootId::new(draw_nonzero_32(random)?))
}

pub(crate) fn checked_clock(inner: Arc<dyn Clock + Send + Sync>) -> Arc<dyn Clock + Send + Sync> {
    Arc::new(CheckedClock {
        inner,
        last_monotonic: Mutex::new(None),
    })
}

struct CheckedClock {
    inner: Arc<dyn Clock + Send + Sync>,
    last_monotonic: Mutex<Option<u64>>,
}

impl Clock for CheckedClock {
    fn wall_now(&self) -> Result<UnixMillis, StableCode> {
        self.inner
            .wall_now()
            .map_err(|_| StableCode::KernelUnavailable)
    }

    fn monotonic_now_millis(&self) -> Result<u64, StableCode> {
        let now = self
            .inner
            .monotonic_now_millis()
            .map_err(|_| StableCode::KernelUnavailable)?;
        let mut last = self
            .last_monotonic
            .lock()
            .map_err(|_| StableCode::KernelUnavailable)?;
        if last.is_some_and(|previous| now < previous) {
            return Err(StableCode::KernelUnavailable);
        }
        *last = Some(now);
        Ok(now)
    }
}
