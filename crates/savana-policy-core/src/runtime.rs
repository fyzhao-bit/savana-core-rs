use savana_kernel_protocol::{StableCode, UnixMillis};

pub trait Clock: Send + Sync {
    fn wall_now(&self) -> Result<UnixMillis, StableCode>;
    fn monotonic_now_millis(&self) -> Result<u64, StableCode>;
}

pub trait RandomSource: Send + Sync {
    fn fill(&self, output: &mut [u8]) -> Result<usize, StableCode>;
}
