#![forbid(unsafe_code)]

mod error;
mod limits;
mod primitives;

pub use error::{ProtocolError, StableCode};
pub use limits::{EffectiveLimits, HardLimits};
pub use primitives::ResourceLimitsV1;

pub const PROTOCOL_MAJOR: u16 = 1;
pub const PROTOCOL_MINOR: u16 = 0;
