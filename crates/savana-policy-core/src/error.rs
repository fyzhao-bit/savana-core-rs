use savana_kernel_protocol::{ProtocolError, StableCode};

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("{code}")]
pub struct PolicyError {
    code: StableCode,
}

impl PolicyError {
    pub(crate) const fn stable(code: StableCode) -> Self {
        Self { code }
    }

    pub const fn code(self) -> StableCode {
        self.code
    }

    pub(crate) fn io<T>(_error: T) -> Self {
        Self::stable(StableCode::ProtocolIo)
    }
}

impl From<ProtocolError> for PolicyError {
    fn from(error: ProtocolError) -> Self {
        Self::stable(error.code())
    }
}
