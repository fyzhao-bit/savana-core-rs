#![forbid(unsafe_code)]

mod error;

pub mod v2;

pub use error::{ProtocolError, StableCode};
