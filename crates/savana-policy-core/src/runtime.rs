use savana_kernel_protocol::v2::UnixMillisV2;
use savana_kernel_protocol::StableCode;

pub trait Clock: Send + Sync {
    fn wall_now(&self) -> Result<UnixMillisV2, StableCode>;
    fn monotonic_now_millis(&self) -> Result<u64, StableCode>;
}

pub trait RandomSource: Send + Sync {
    fn fill(&self, output: &mut [u8]) -> Result<usize, StableCode>;
}
