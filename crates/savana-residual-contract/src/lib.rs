//! Bounded model and checkers for the interface-relative residual data
//! contract (framework §5: C1–C6 construction, K1–K6 local replacement
//! checks), together with a reference full checker that does not use the
//! contract.
//!
//! This crate is a research artifact. It issues no authorization and is not
//! linked into the kernel. Its model is a small finite abstraction of the
//! restricted continuation language; results about it are bounded and are
//! not a refinement proof of the Rust kernel.
#![forbid(unsafe_code)]

pub mod check;
pub mod full;
pub mod model;
pub mod residual;
