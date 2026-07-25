use savana_kernel_protocol::StableCode;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("{code}")]
pub struct DaemonError {
    code: StableCode,
}

impl DaemonError {
    pub(crate) const fn stable(code: StableCode) -> Self {
        Self { code }
    }

    pub const fn code(self) -> StableCode {
        self.code
    }
}
