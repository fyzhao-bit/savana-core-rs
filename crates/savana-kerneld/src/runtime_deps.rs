use std::time::{Instant, SystemTime, UNIX_EPOCH};

use savana_kernel_protocol::v2::UnixMillisV2;
use savana_kernel_protocol::StableCode;
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
    fn wall_now(&self) -> Result<UnixMillisV2, StableCode> {
        let elapsed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| StableCode::KernelUnavailable)?;
        let millis =
            u64::try_from(elapsed.as_millis()).map_err(|_| StableCode::KernelUnavailable)?;
        Ok(UnixMillisV2::new(millis))
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

/// One full, nonzero 32-byte draw (the process boot identity).
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

#[cfg(test)]
mod tests {
    use super::*;

    enum EntropyStep {
        Fill(u8),
        Error,
        Short(usize),
        Zero,
    }

    struct OneDraw(EntropyStep);

    impl RandomSource for OneDraw {
        fn fill(&self, output: &mut [u8]) -> Result<usize, StableCode> {
            match self.0 {
                EntropyStep::Fill(fill) => {
                    output.fill(fill);
                    Ok(output.len())
                }
                EntropyStep::Error => Err(StableCode::KernelUnavailable),
                EntropyStep::Short(written) => {
                    output.fill(0x5a);
                    Ok(written.min(output.len()))
                }
                EntropyStep::Zero => {
                    output.fill(0);
                    Ok(output.len())
                }
            }
        }
    }

    #[test]
    fn the_boot_identity_is_one_full_nonzero_draw() {
        assert_eq!(
            draw_nonzero_32(&OneDraw(EntropyStep::Fill(0x11))),
            Ok([0x11; 32])
        );
        for fault in [
            EntropyStep::Error,
            EntropyStep::Short(31),
            EntropyStep::Zero,
        ] {
            assert_eq!(
                draw_nonzero_32(&OneDraw(fault)),
                Err(StableCode::KernelUnavailable)
            );
        }
    }
}
