//! Bounded v0.4 verification and private-state primitives for the Rust kernel.
//!
//! This library issues NO production authorization, execution ticket, approval,
//! release grant, or RPC. The trusted host must bind reviewed finite semantics
//! to its actual root, adapter, command classes, renderer and recipient scope.
//! Certificate inputs are untrusted; model definitions are trusted compiler
//! outputs, not candidate-supplied successor lists. Real persistence, full egress
//! mediation, BC/K6 progress, and implementation refinement are separate work.
#![forbid(unsafe_code)]

pub mod finite;
pub mod ledger;
pub mod observation;
pub mod planning;
pub mod planning_observation;
pub mod quotient;
pub mod release;

use serde::Serialize;
use sha2::{Digest as _, Sha256};

pub type Digest = [u8; 32];

fn digest<T: Serialize>(domain: &[u8], value: &T) -> Digest {
    // Only closed internal structs/tuples with integer keys use this encoding.
    // This is versioned serde JSON, NOT arbitrary JSON canonicalization/JCS.
    let bytes = serde_json::to_vec(value).expect("closed verification types serialize");
    let mut h = Sha256::new();
    h.update((domain.len() as u64).to_be_bytes());
    h.update(domain);
    h.update((bytes.len() as u64).to_be_bytes());
    h.update(bytes);
    h.finalize().into()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("invalid closed finite definition")]
    Invalid,
    #[error("binding or identity conflict")]
    Binding,
    #[error("configured verification or state bound exhausted")]
    Limit,
    #[error("certificate does not cover the required behavior")]
    Certificate,
    #[error("operation conflicts with original history")]
    History,
}
