use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use savana_kernel_protocol::{BootId, StableCode, UnixMillis};
use savana_policy_core::{Clock, RandomSource};
use zeroize::Zeroizing;

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

pub(crate) struct AuditSecret(Zeroizing<[u8; 32]>);

impl AuditSecret {
    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    #[cfg(test)]
    pub(crate) fn from_test_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }
}

pub(crate) struct ProcessSecrets {
    pub(crate) boot_id: BootId,
    pub(crate) audit_secret: AuditSecret,
}

impl ProcessSecrets {
    pub(crate) fn draw(random: &dyn RandomSource) -> Result<Self, StableCode> {
        let boot = draw_nonzero_32(random)?;
        let audit = draw_nonzero_32(random)?;
        Ok(Self {
            boot_id: BootId::new(boot),
            audit_secret: AuditSecret(Zeroizing::new(audit)),
        })
    }
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

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use super::*;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum EntropyStep {
        Fill(u8),
        Error,
        Short(usize),
        Zero,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct DrawRecord {
        length: usize,
        fill: u8,
    }

    impl DrawRecord {
        const fn new(length: usize, fill: u8) -> Self {
            Self { length, fill }
        }
    }

    struct ScriptedRandom {
        steps: Mutex<VecDeque<EntropyStep>>,
        completed: Mutex<Vec<DrawRecord>>,
    }

    impl ScriptedRandom {
        fn new(steps: impl IntoIterator<Item = EntropyStep>) -> Self {
            Self {
                steps: Mutex::new(steps.into_iter().collect()),
                completed: Mutex::new(Vec::new()),
            }
        }

        fn completed_draws(&self) -> Vec<DrawRecord> {
            self.completed.lock().unwrap().clone()
        }
    }

    impl RandomSource for ScriptedRandom {
        fn fill(&self, output: &mut [u8]) -> Result<usize, StableCode> {
            let step = self
                .steps
                .lock()
                .unwrap()
                .pop_front()
                .ok_or(StableCode::KernelUnavailable)?;
            match step {
                EntropyStep::Fill(fill) => {
                    output.fill(fill);
                    self.completed
                        .lock()
                        .unwrap()
                        .push(DrawRecord::new(output.len(), fill));
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
    fn boot_audit_and_engine_entropy_are_separate_full_nonzero_draws() {
        let random = Arc::new(ScriptedRandom::new([
            EntropyStep::Fill(0x11),
            EntropyStep::Fill(0x22),
            EntropyStep::Fill(0x33),
        ]));
        let secrets = ProcessSecrets::draw(random.as_ref()).unwrap();
        let installation = crate::startup_identity_tests::MappedInstallation::new();
        let _runtime = installation
            .prepare_with_random_for_entropy_test(secrets.boot_id, random.clone())
            .unwrap();
        assert_eq!(
            random.completed_draws(),
            vec![
                DrawRecord::new(32, 0x11),
                DrawRecord::new(32, 0x22),
                DrawRecord::new(32, 0x33),
            ]
        );
    }

    #[test]
    fn boot_or_audit_entropy_fault_rejects_process_secret_construction() {
        for script in [
            [EntropyStep::Error, EntropyStep::Fill(0x22)],
            [EntropyStep::Short(31), EntropyStep::Fill(0x22)],
            [EntropyStep::Zero, EntropyStep::Fill(0x22)],
            [EntropyStep::Fill(0x11), EntropyStep::Error],
            [EntropyStep::Fill(0x11), EntropyStep::Short(31)],
            [EntropyStep::Fill(0x11), EntropyStep::Zero],
        ] {
            let random = ScriptedRandom::new(script);
            assert!(matches!(
                ProcessSecrets::draw(&random),
                Err(StableCode::KernelUnavailable)
            ));
            assert!(random.completed_draws().len() <= 1);
        }
    }
}
