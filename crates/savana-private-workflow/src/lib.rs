//! Experimental, bounded evidence-grounded private continuations.
//!
//! This is a Rust research runtime, not a new production V2 RPC or bypass of
//! G1–G7. Only [`PlannerPort`] is suitable for an untrusted model boundary.
//! Root/fact issuance, storage, transport and [`Workflow`] belong to the TCB.
//! A derived request reuses the V2 business codec but is NOT a V2 dispatch grant.
mod codec;
mod domain;
mod planner;
mod runtime;
mod store;

pub use codec::invoice_profile;
pub use domain::{
    sign_directory, sign_orders, sign_root, Context, DirectoryFacts, FactBinding, Merchant, Order,
    OrderFacts, RootRule, SignedMessage, TrustPins, MAX_ORDERS,
};
pub use planner::{PlannerCommand, PlannerPort, PlannerReply, PlannerView, SlotStatus, ViewSlot};
pub use runtime::{DiscoveryQuery, DispatchRequest, ProviderTransport, Workflow};
pub use store::{FileStore, StateStore};

pub type Digest = [u8; 32];

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("invalid bounded message")]
    Malformed,
    #[error("authentication or context mismatch")]
    Authentication,
    #[error("authority is unavailable")]
    Unavailable,
    #[error("state or evidence conflict")]
    Conflict,
    #[error("configured bound exhausted")]
    Limit,
    #[error("durable state unavailable; reopen required")]
    Storage,
}

pub(crate) fn hash(domain: &[u8], parts: &[&[u8]]) -> Digest {
    use sha2::{Digest as _, Sha256};
    let mut h = Sha256::new();
    h.update(domain);
    for p in parts {
        h.update((p.len() as u64).to_be_bytes());
        h.update(p);
    }
    h.finalize().into()
}

pub(crate) fn json<T: serde::Serialize>(v: &T) -> Result<Vec<u8>, Error> {
    serde_json::to_vec(v).map_err(|_| Error::Malformed)
}

pub(crate) fn decode<T: serde::de::DeserializeOwned + serde::Serialize>(
    bytes: &[u8],
    limit: usize,
) -> Result<T, Error> {
    if bytes.is_empty() || bytes.len() > limit {
        return Err(Error::Limit);
    }
    let v: T = serde_json::from_slice(bytes).map_err(|_| Error::Malformed)?;
    // Canonical closed JSON, not general JCS. Struct field order is versioned.
    if json(&v)? != bytes {
        return Err(Error::Malformed);
    }
    Ok(v)
}

pub(crate) fn opaque(key: &Digest, kind: &[u8], index: u64) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut h = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("fixed key");
    h.update(b"SAVANA_PRIVATE_CONTINUATION_HANDLE_V1\0");
    h.update(&(kind.len() as u64).to_be_bytes());
    h.update(kind);
    h.update(&index.to_be_bytes());
    hex(&h.finalize().into_bytes())
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(s, "{b:02x}").expect("string write");
    }
    s
}

#[cfg(test)]
mod tests;
