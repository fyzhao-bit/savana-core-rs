//! Byte-exact port of the resolution primitive of
//! `server/documents/scoped_vault.py` — the authenticated `[[JARVIS-DOC:…]]`
//! token core.
//!
//! A token's authority rests ENTIRELY on its HMAC tag:
//! `tag = HMAC-SHA256(artifact_secret, canonical_claims).hexdigest()[:16]`,
//! where `canonical_claims` is `json.dumps({…}, sort_keys=True,
//! separators=(",", ":"))` over artifact id, counter, generation, kind and
//! mask version. `resolve` re-derives that tag and compares it to the token's
//! in CONSTANT TIME (mirroring `hmac.compare_digest`) before any scope or
//! grant check, so a forged or tampered token is refused with a stable code and
//! never leaks a timing signal or raw value.
//!
//! Byte-exactness rests on: (1) the exact claims JSON byte layout, (2)
//! HMAC-SHA256 (RustCrypto, already used by the encryption core), and (3) the
//! `[[JARVIS-DOC:…]]` grammar. All three are golden-tested against the same
//! CPython in `tests/vault_resolve.rs`.

use crate::masking::canonical_scan_forms;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::{HashMap, HashSet};

type HmacSha256 = Hmac<Sha256>;

/// Stable vault refusal codes (`str(exc)` is the code and nothing else).
pub const VAULT_TOKEN_INVALID: &str = "VAULT_TOKEN_INVALID";
pub const VAULT_TOKEN_UNAUTHORIZED: &str = "VAULT_TOKEN_UNAUTHORIZED";
pub const VAULT_EXPIRED: &str = "VAULT_EXPIRED";

pub const DOC_MASK_VERSION: &str = "doc-mask-v1";
const DOC_TOKEN_TAG_HEX_CHARS: usize = 16;

/// A vault refusal carrying only a stable code — never a raw value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultError {
    pub code: &'static str,
}

impl VaultError {
    fn invalid() -> Self {
        VaultError {
            code: VAULT_TOKEN_INVALID,
        }
    }
    fn unauthorized() -> Self {
        VaultError {
            code: VAULT_TOKEN_UNAUTHORIZED,
        }
    }
}

struct Parsed<'a> {
    artifact_id: &'a str,
    generation: &'a str,
    kind: &'a str,
    counter: &'a str,
    tag: &'a str,
}

/// Parse a token against the `_TOKEN_RE` grammar WITHOUT a regex engine — the
/// grammar is a fixed, anchored shape, so a hand-rolled scanner is both exact
/// and dependency-free:
///   `[[JARVIS-DOC:<hex 8..64>:<digits 1..9>:<KIND>:<digits 1..9>:<hex16>]]`
fn parse_token(token: &str) -> Option<Parsed<'_>> {
    let body = token.strip_prefix("[[JARVIS-DOC:")?.strip_suffix("]]")?;
    let mut it = body.split(':');
    let artifact_id = it.next()?;
    let generation = it.next()?;
    let kind = it.next()?;
    let counter = it.next()?;
    let tag = it.next()?;
    if it.next().is_some() {
        return None; // exactly five fields
    }
    // artifact id: 8..=64 lowercase hex
    if !(8..=64).contains(&artifact_id.len())
        || !artifact_id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    if !is_bounded_digits(generation, 1, 9) || !is_bounded_digits(counter, 1, 9) {
        return None;
    }
    if !is_kind(kind) {
        return None;
    }
    // tag: exactly 16 lowercase hex
    if tag.len() != DOC_TOKEN_TAG_HEX_CHARS
        || !tag
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    Some(Parsed {
        artifact_id,
        generation,
        kind,
        counter,
        tag,
    })
}

/// `\d{lo,hi}` over ASCII digits (Python token fields are always ASCII digits;
/// the grammar uses `\d{1,9}`, which for issued tokens is ASCII).
fn is_bounded_digits(s: &str, lo: usize, hi: usize) -> bool {
    (lo..=hi).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_digit())
}

/// `[A-Z][A-Z0-9_]{0,31}` — `_KIND_RE`.
fn is_kind(s: &str) -> bool {
    let b = s.as_bytes();
    if b.is_empty() || b.len() > 32 {
        return false;
    }
    if !b[0].is_ascii_uppercase() {
        return false;
    }
    b[1..]
        .iter()
        .all(|&c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == b'_')
}

/// Canonical HMAC claims — byte-exact to `json.dumps(sort_keys=True,
/// separators=(",", ":"))`. Keys emit in sorted order: artifact_id, counter,
/// generation, kind, mask_version. All values are constrained to characters
/// that need no JSON escaping (hex ids, ASCII digits, `[A-Z0-9_]` kinds,
/// `doc-mask-v1`), so plain interpolation reproduces CPython exactly.
fn claims_json(
    artifact_id: &str,
    counter: &str,
    generation: &str,
    kind: &str,
    mask_version: &str,
) -> String {
    format!(
        "{{\"artifact_id\":\"{artifact_id}\",\"counter\":{counter},\"generation\":{generation},\"kind\":\"{kind}\",\"mask_version\":\"{mask_version}\"}}"
    )
}

/// Decode the 16-hex-char tag to its 8 raw bytes (the left-truncated HMAC).
fn decode_tag(tag: &str) -> Option<[u8; 8]> {
    let b = tag.as_bytes();
    if b.len() != 16 {
        return None;
    }
    let mut out = [0u8; 8];
    for i in 0..8 {
        let hi = (b[2 * i] as char).to_digit(16)?;
        let lo = (b[2 * i + 1] as char).to_digit(16)?;
        out[i] = ((hi << 4) | lo) as u8;
    }
    Some(out)
}

/// One stored value. The token string is the key; the raw is the payload.
/// `kind`/`chunks` mirror `_VaultEntry` — `kind` feeds the masker's active
/// "mask once → mask everywhere" sweep (`value_entries` → first-seen kind), and
/// `chunks` records which serialized chunks carried the token (`record_chunks`).
struct Entry {
    raw: String,
    kind: String,
    chunks: HashSet<String>,
}

/// The full `ScopedDocumentVault`: the resolution side (`resolve`, byte-exact
/// against CPython in `tests/vault_resolve.rs`) PLUS the MINT side the strict
/// document masker drives — `put` accreting authenticated tokens and the
/// incrementally-maintained folded-value indices (`value_entries`,
/// `folded_length_buckets`, `issued_token_set`) the 2-phase sweep and residual
/// leak scan consume.
pub struct ScopedDocumentVault {
    secret: Vec<u8>,
    artifact_id: String,
    generation: u32,
    mask_version: String,
    entries: HashMap<String, Entry>,
    /// Tokens in first-put order — Python's `dict` insertion order, which
    /// `value_entries`/`entries_in_order` must reproduce so the sweep's
    /// first-seen `(folded → kind)` map and the differential agree.
    order: Vec<String>,
    by_value: HashMap<(String, String), String>,
    counters: HashMap<String, u32>,
    grants: HashMap<String, HashSet<String>>,
    /// Canonical folded raw values, deduplicated (first-seen), grouped by folded
    /// CHAR length — the bucketed residual-scan index maintained at `put` time
    /// (mirrors `_folded_seen`/`_folded_buckets`). Lengths are `char` counts
    /// (Python `len(folded)`), never byte lengths.
    folded_seen: HashSet<String>,
    folded_buckets: HashMap<usize, HashSet<String>>,
}

impl ScopedDocumentVault {
    pub fn new(secret: &[u8], artifact_id: &str, generation: u32, mask_version: &str) -> Self {
        ScopedDocumentVault {
            secret: secret.to_vec(),
            artifact_id: artifact_id.to_string(),
            generation,
            mask_version: mask_version.to_string(),
            entries: HashMap::new(),
            order: Vec::new(),
            by_value: HashMap::new(),
            counters: HashMap::new(),
            grants: HashMap::new(),
            folded_seen: HashSet::new(),
            folded_buckets: HashMap::new(),
        }
    }

    /// Scope getters — the masker re-checks these against the artifact before
    /// masking (fail-closed if the vault is scoped to a different generation).
    pub fn artifact_id(&self) -> &str {
        &self.artifact_id
    }
    pub fn generation(&self) -> u32 {
        self.generation
    }
    pub fn mask_version(&self) -> &str {
        &self.mask_version
    }

    /// `tag = HMAC-SHA256(secret, claims).hexdigest()[:16]`.
    pub fn tag(&self, kind: &str, counter: u32) -> String {
        let claims = claims_json(
            &self.artifact_id,
            &counter.to_string(),
            &self.generation.to_string(),
            kind,
            &self.mask_version,
        );
        let mut mac =
            HmacSha256::new_from_slice(&self.secret).expect("hmac accepts any key length");
        mac.update(claims.as_bytes());
        let full = mac.finalize().into_bytes();
        let mut hex = String::with_capacity(DOC_TOKEN_TAG_HEX_CHARS);
        for &byte in full.iter().take(DOC_TOKEN_TAG_HEX_CHARS / 2) {
            hex.push_str(&format!("{byte:02x}"));
        }
        hex
    }

    /// Port of `put`: dedup by `(kind, raw)`, monotonic per-kind counter, build
    /// the authenticated token. (No JSON escaping needed for the grammars.)
    pub fn put(&mut self, kind: &str, raw: &str, _pages: &[u32]) -> Result<String, VaultError> {
        if !is_kind(kind) || raw.is_empty() {
            return Err(VaultError::invalid());
        }
        if let Some(tok) = self.by_value.get(&(kind.to_string(), raw.to_string())) {
            return Ok(tok.clone());
        }
        let counter = self.counters.get(kind).copied().unwrap_or(0) + 1;
        self.counters.insert(kind.to_string(), counter);
        let tag = self.tag(kind, counter);
        let token = format!(
            "[[JARVIS-DOC:{}:{}:{}:{}:{}]]",
            self.artifact_id, self.generation, kind, counter, tag
        );
        self.entries.insert(
            token.clone(),
            Entry {
                raw: raw.to_string(),
                kind: kind.to_string(),
                chunks: HashSet::new(),
            },
        );
        self.order.push(token.clone());
        self.by_value
            .insert((kind.to_string(), raw.to_string()), token.clone());
        // Fold once at put() time (mirrors `_folded_*` upkeep) so the masker's
        // sweep/scan never re-canonicalizes the whole vault per call. Bucket key
        // is the folded CHAR length.
        let folded = canonical_scan_forms(raw).1;
        if !self.folded_seen.contains(&folded) {
            let len = folded.chars().count();
            self.folded_seen.insert(folded.clone());
            self.folded_buckets.entry(len).or_default().insert(folded);
        }
        Ok(token)
    }

    /// Port of `value_entries`: `(kind, raw)` for every entry in first-put
    /// (insertion) order — the masker builds its first-seen `folded → kind` map
    /// from this, so re-vaulting a recurrence returns the SAME token.
    pub fn value_entries(&self) -> Vec<(String, String)> {
        self.order
            .iter()
            .map(|t| {
                let e = &self.entries[t];
                (e.kind.clone(), e.raw.clone())
            })
            .collect()
    }

    /// `(token, raw)` for every entry in first-put order — the shape the
    /// differential compares against Python's `vault._entries`.
    pub fn entries_in_order(&self) -> Vec<(String, String)> {
        self.order
            .iter()
            .map(|t| (t.clone(), self.entries[t].raw.clone()))
            .collect()
    }

    /// Port of `folded_length_buckets`: folded values grouped by folded CHAR
    /// length for the bucketed residual scan / active sweep. Read-only view.
    pub fn folded_length_buckets(&self) -> &HashMap<usize, HashSet<String>> {
        &self.folded_buckets
    }

    /// Port of `issued_token_set`: the set of vault-issued token strings, used
    /// to strip only genuine tokens (leaving lookalikes for the scan to flag).
    pub fn issued_token_set(&self) -> HashSet<String> {
        self.entries.keys().cloned().collect()
    }

    /// Port of `record_chunks`: record that `chunk_id` carried `token`. Verifies
    /// the token first (fail-closed). Metadata only — never part of masked
    /// output, but kept faithful to the Python entry shape.
    pub fn record_chunks(&mut self, token: &str, chunk_id: &str) -> Result<(), VaultError> {
        // Re-verify via the resolution path, then record on the entry.
        self.verify(token)?;
        if let Some(entry) = self.entries.get_mut(token) {
            entry.chunks.insert(chunk_id.to_string());
        }
        Ok(())
    }

    /// Port of `authorize_evidence`: record the token subset a digest may
    /// rehydrate. Every token must verify; one bad token refuses the whole set.
    pub fn authorize_evidence(&mut self, digest: &str, tokens: &[&str]) -> Result<(), VaultError> {
        if digest.is_empty() {
            return Err(VaultError::unauthorized());
        }
        let mut verified = HashSet::new();
        for &t in tokens {
            self.verify(t)?;
            verified.insert(t.to_string());
        }
        self.grants
            .entry(digest.to_string())
            .or_default()
            .extend(verified);
        Ok(())
    }

    /// Port of `_verify`: parse, CONSTANT-TIME tag check, exact scope re-check,
    /// then entry lookup. Returns the raw value on success.
    fn verify(&self, token: &str) -> Result<&str, VaultError> {
        let parsed = parse_token(token).ok_or_else(VaultError::invalid)?;
        let counter: u32 = parsed.counter.parse().map_err(|_| VaultError::invalid())?;

        // Constant-time tag validation FIRST — the tag binds artifact id,
        // generation, mask version, kind and counter via the HMAC claims.
        let claims = claims_json(
            &self.artifact_id,
            &counter.to_string(),
            &self.generation.to_string(),
            parsed.kind,
            &self.mask_version,
        );
        let tag_bytes = decode_tag(parsed.tag).ok_or_else(VaultError::invalid)?;
        let mut mac =
            HmacSha256::new_from_slice(&self.secret).expect("hmac accepts any key length");
        mac.update(claims.as_bytes());
        // `verify_truncated_left` compares the leading 8 bytes in constant time,
        // exactly the 16 hex chars Python's `compare_digest` compares.
        if mac.verify_truncated_left(&tag_bytes).is_err() {
            return Err(VaultError::invalid());
        }

        // Exact scope re-checks (redundant with the HMAC binding; explicit).
        let gen_ok = parsed
            .generation
            .parse::<u32>()
            .map(|g| g == self.generation)
            .unwrap_or(false);
        if parsed.artifact_id != self.artifact_id || !gen_ok {
            return Err(VaultError::invalid());
        }

        match self.entries.get(token) {
            Some(entry) => Ok(&entry.raw),
            None => Err(VaultError::invalid()),
        }
    }

    /// Port of `resolve`: verify → (liveness) → grant check → raw. Any failure
    /// refuses with a stable code; the raw value is only ever returned to an
    /// authorized digest.
    pub fn resolve(&self, token: &str, evidence_digest: &str) -> Result<String, VaultError> {
        let raw = self.verify(token)?.to_string();
        match self.grants.get(evidence_digest) {
            Some(set) if set.contains(token) => Ok(raw),
            _ => Err(VaultError::unauthorized()),
        }
    }
}
