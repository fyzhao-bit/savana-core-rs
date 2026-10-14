use crate::{decode, hash, json, Digest, Error};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

pub const MAX_ORDERS: usize = 32;
pub(crate) const MAX_FACT_BYTES: usize = 256 * 1024;
const ROOT_DOMAIN: &[u8] = b"SAVANA_PRIVATE_CONTINUATION_ROOT_V1\0";
const ORDERS_DOMAIN: &[u8] = b"SAVANA_PRIVATE_CONTINUATION_ORDER_FACTS_V1\0";
const DIRECTORY_DOMAIN: &[u8] = b"SAVANA_PRIVATE_CONTINUATION_DIRECTORY_V1\0";

/// Supplied by the authenticated host, never by a planner command.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Context {
    pub installation: Digest,
    pub task: Digest,
    pub principal: Digest,
    pub deployment: Digest,
}

/// Deployment-selected trust roots; role keys must be distinct.
#[derive(Clone)]
pub struct TrustPins {
    pub issuer: VerifyingKey,
    pub orders: VerifyingKey,
    pub directory: VerifyingKey,
}
impl TrustPins {
    pub(crate) fn validate(&self) -> Result<(), Error> {
        let keys = [
            self.issuer.to_bytes(),
            self.orders.to_bytes(),
            self.directory.to_bytes(),
        ];
        if keys.iter().any(|k| *k == [0; 32])
            || keys[0] == keys[1]
            || keys[0] == keys[2]
            || keys[1] == keys[2]
        {
            return Err(Error::Authentication);
        }
        Ok(())
    }
    pub(crate) fn digest(&self) -> Digest {
        hash(
            b"SAVANA_PRIVATE_CONTINUATION_PINS_V1\0",
            &[
                self.issuer.as_bytes(),
                self.orders.as_bytes(),
                self.directory.as_bytes(),
            ],
        )
    }
}

/// Human-authenticated structured rule. Revision 1 only: no model-authored
/// updates, no wildcard account, recipient, operation, or output template.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootRule {
    pub schema: u8,
    pub context: Context,
    pub revision: u64,
    pub account: String,
    pub year_month: u32,
    pub orders_source: Digest,
    pub directory_source: Digest,
    pub directory_version: u64,
    pub executor_target: Digest,
    pub executor_credential: Digest,
    pub tool_descriptor: Digest,
    pub not_before: u64,
    pub expires_at: u64,
    pub max_fact_age_ms: u64,
    pub max_orders: u16,
    pub max_discoveries: u16,
    pub max_disclosures: u16,
    /// The only supported operation and disclosure policy are versioned here.
    pub program: String,
    pub disclosure: String,
}
impl RootRule {
    pub fn digest(&self) -> Result<Digest, Error> {
        self.validate()?;
        Ok(hash(ROOT_DOMAIN, &[&json(self)?]))
    }
    pub(crate) fn validate(&self) -> Result<(), Error> {
        let ids = [
            self.context.installation,
            self.context.task,
            self.context.principal,
            self.context.deployment,
            self.orders_source,
            self.directory_source,
            self.executor_target,
            self.executor_credential,
            self.tool_descriptor,
        ];
        if self.schema != 1
            || self.revision != 1
            || ids.contains(&[0; 32])
            || !identifier(&self.account)
            || !month(self.year_month)
            || self.directory_version == 0
            || self.not_before >= self.expires_at
            || self.max_fact_age_ms == 0
            || self.max_fact_age_ms > 3_600_000
            || self.max_orders == 0
            || usize::from(self.max_orders) > MAX_ORDERS
            || self.max_discoveries == 0
            || self.max_discoveries > 8
            || self.max_disclosures < 2
            || self.max_disclosures > 128
            || self.program != "request-missing-invoices-v1"
            || self.disclosure != "slot-progress-v1"
        {
            return Err(Error::Malformed);
        }
        Ok(())
    }
    pub(crate) fn live(&self, now: u64) -> Result<(), Error> {
        if now < self.not_before || now >= self.expires_at {
            Err(Error::Unavailable)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedMessage {
    pub canonical: Vec<u8>,
    pub signature: Vec<u8>,
}

fn sign<T: Serialize>(v: &T, domain: &[u8], key: &SigningKey) -> Result<SignedMessage, Error> {
    let canonical = json(v)?;
    if canonical.len() > MAX_FACT_BYTES {
        return Err(Error::Limit);
    }
    let signature = key.sign(&hash(domain, &[&canonical])).to_bytes().to_vec();
    Ok(SignedMessage {
        canonical,
        signature,
    })
}
fn verify<T: serde::de::DeserializeOwned + Serialize>(
    s: &SignedMessage,
    domain: &[u8],
    key: &VerifyingKey,
) -> Result<T, Error> {
    if s.canonical.is_empty() || s.canonical.len() > MAX_FACT_BYTES {
        return Err(Error::Limit);
    }
    let sig = Signature::from_slice(&s.signature).map_err(|_| Error::Authentication)?;
    key.verify_strict(&hash(domain, &[&s.canonical]), &sig)
        .map_err(|_| Error::Authentication)?;
    decode(&s.canonical, MAX_FACT_BYTES)
}

/// Only the authenticated issuer may call this on user-approved structured input.
pub fn sign_root(v: &RootRule, key: &SigningKey) -> Result<SignedMessage, Error> {
    v.validate()?;
    sign(v, ROOT_DOMAIN, key)
}
pub(crate) fn verify_root(
    s: &SignedMessage,
    pins: &TrustPins,
    context: Context,
) -> Result<RootRule, Error> {
    pins.validate()?;
    let root: RootRule = verify(s, ROOT_DOMAIN, &pins.issuer)?;
    root.validate()?;
    if root.context != context {
        return Err(Error::Authentication);
    }
    Ok(root)
}

/// Evidence is bound to a kernel-originated query, not just a task string.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FactBinding {
    pub root: Digest,
    pub query: String,
    pub source: Digest,
    pub observed_at: u64,
    pub expires_at: u64,
}
impl FactBinding {
    pub(crate) fn check(
        &self,
        root: &RootRule,
        query: &str,
        source: Digest,
        now: u64,
    ) -> Result<(), Error> {
        if self.root != root.digest()?
            || self.query != query
            || self.source != source
            || self.observed_at > now
            || now >= self.expires_at
            || self.observed_at >= self.expires_at
            || now.saturating_sub(self.observed_at) > root.max_fact_age_ms
            || self.expires_at > root.expires_at
        {
            return Err(Error::Authentication);
        }
        Ok(())
    }
}

/// Only these closed metadata fields may drive authorization. `untrusted_note`
/// is deliberately present to test that signed text does not acquire authority.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Order {
    pub id: String,
    pub version: u64,
    pub account: String,
    pub year_month: u32,
    pub merchant: String,
    pub invoice_missing: bool,
    pub amount_minor: u64,
    pub untrusted_note: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrderFacts {
    pub binding: FactBinding,
    pub snapshot_version: u64,
    pub orders: Vec<Order>,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Merchant {
    pub id: String,
    /// A reviewed directory identity, not an address extracted from order text.
    pub contact: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryFacts {
    pub binding: FactBinding,
    pub version: u64,
    pub merchants: Vec<Merchant>,
}

pub fn sign_orders(v: &OrderFacts, key: &SigningKey) -> Result<SignedMessage, Error> {
    sign(v, ORDERS_DOMAIN, key)
}
pub fn sign_directory(v: &DirectoryFacts, key: &SigningKey) -> Result<SignedMessage, Error> {
    sign(v, DIRECTORY_DOMAIN, key)
}
pub(crate) fn verify_orders(v: &SignedMessage, pins: &TrustPins) -> Result<OrderFacts, Error> {
    let v: OrderFacts = verify(v, ORDERS_DOMAIN, &pins.orders)?;
    if v.snapshot_version == 0
        || v.orders.len() > MAX_ORDERS
        || v.orders.windows(2).any(|w| w[0].id >= w[1].id)
        || v.orders.iter().any(|o| {
            !identifier(&o.id)
                || o.version == 0
                || !identifier(&o.account)
                || !identifier(&o.merchant)
                || !month(o.year_month)
                || o.untrusted_note.len() > 4096
        })
    {
        return Err(Error::Malformed);
    }
    Ok(v)
}
pub(crate) fn verify_directory(
    v: &SignedMessage,
    pins: &TrustPins,
) -> Result<DirectoryFacts, Error> {
    let v: DirectoryFacts = verify(v, DIRECTORY_DOMAIN, &pins.directory)?;
    if v.version == 0
        || v.merchants.len() > MAX_ORDERS
        || v.merchants.windows(2).any(|w| w[0].id >= w[1].id)
        || v.merchants.iter().any(|m| {
            !identifier(&m.id)
                || m.contact.is_empty()
                || m.contact.len() > 254
                || !m.contact.is_ascii()
                || m.contact
                    .bytes()
                    .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
                || m.contact.bytes().filter(|b| *b == b'@').count() != 1
        })
    {
        return Err(Error::Malformed);
    }
    Ok(v)
}
fn identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}
fn month(m: u32) -> bool {
    (200001..=999912).contains(&m) && (1..=12).contains(&(m % 100))
}
