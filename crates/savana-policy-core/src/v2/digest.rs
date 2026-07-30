use minicbor::Encode as _;
use savana_kernel_protocol::v2::{Digest32V2, ExecutorIdentityV2, ValueInternalIdV2};
use sha2::{Digest as _, Sha256};

use super::{ArgumentNameV2, G3Error, IdentifierV2};

const MAX_ARGUMENTS: usize = 256;
const MAX_EVIDENCE_ITEMS: usize = 256;
const MAX_TOKENS: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArgumentDigestEntryV2 {
    argument_name: ArgumentNameV2,
    value_internal_id: ValueInternalIdV2,
    value_digest: Digest32V2,
    provenance_digest: Digest32V2,
}

impl ArgumentDigestEntryV2 {
    pub const fn new(
        argument_name: ArgumentNameV2,
        value_internal_id: ValueInternalIdV2,
        value_digest: Digest32V2,
        provenance_digest: Digest32V2,
    ) -> Self {
        Self {
            argument_name,
            value_internal_id,
            value_digest,
            provenance_digest,
        }
    }

    pub const fn value_internal_id(&self) -> ValueInternalIdV2 {
        self.value_internal_id
    }

    pub const fn value_digest(&self) -> Digest32V2 {
        self.value_digest
    }

    pub const fn provenance_digest(&self) -> Digest32V2 {
        self.provenance_digest
    }
}

impl<C> minicbor::Encode<C> for ArgumentDigestEntryV2 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        encoder.array(4)?;
        self.argument_name.encode(encoder, context)?;
        self.value_internal_id.encode(encoder, context)?;
        self.value_digest.encode(encoder, context)?;
        self.provenance_digest.encode(encoder, context)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EvidenceDigestEntryV2 {
    value_digest: Digest32V2,
    provenance_digest: Digest32V2,
}

impl EvidenceDigestEntryV2 {
    pub const fn new(value_digest: Digest32V2, provenance_digest: Digest32V2) -> Self {
        Self {
            value_digest,
            provenance_digest,
        }
    }
}

impl<C> minicbor::Encode<C> for EvidenceDigestEntryV2 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        encoder.array(2)?;
        self.value_digest.encode(encoder, context)?;
        self.provenance_digest.encode(encoder, context)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProvenanceSetDigestEntryV2 {
    value_internal_id: ValueInternalIdV2,
    value_digest: Digest32V2,
    provenance_digest: Digest32V2,
}

impl ProvenanceSetDigestEntryV2 {
    pub const fn new(
        value_internal_id: ValueInternalIdV2,
        value_digest: Digest32V2,
        provenance_digest: Digest32V2,
    ) -> Self {
        Self {
            value_internal_id,
            value_digest,
            provenance_digest,
        }
    }
}

impl<C> minicbor::Encode<C> for ProvenanceSetDigestEntryV2 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        encoder.array(3)?;
        self.value_internal_id.encode(encoder, context)?;
        self.value_digest.encode(encoder, context)?;
        self.provenance_digest.encode(encoder, context)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenSetDigestEntryV2 {
    token_slot_id: IdentifierV2,
    vault_segment_internal_id: Digest32V2,
    credential_version_digest: Digest32V2,
    executor_identity_digest: Digest32V2,
}

impl TokenSetDigestEntryV2 {
    pub fn new(
        token_slot_id: IdentifierV2,
        vault_segment_internal_id: Digest32V2,
        credential_version_digest: Digest32V2,
        executor_identity: ExecutorIdentityV2,
    ) -> Self {
        Self {
            token_slot_id,
            vault_segment_internal_id,
            credential_version_digest,
            executor_identity_digest: Digest32V2::new(*executor_identity.as_bytes()),
        }
    }
}

impl<C> minicbor::Encode<C> for TokenSetDigestEntryV2 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        encoder.array(4)?;
        self.token_slot_id.encode(encoder, context)?;
        self.vault_segment_internal_id.encode(encoder, context)?;
        self.credential_version_digest.encode(encoder, context)?;
        self.executor_identity_digest.encode(encoder, context)?;
        Ok(())
    }
}

pub fn argument_digest_v2(entries: &[ArgumentDigestEntryV2]) -> Result<Digest32V2, G3Error> {
    if entries.len() > MAX_ARGUMENTS {
        return Err(G3Error::CollectionLimitExceeded);
    }
    validate_argument_order(entries)?;
    hash_entries(b"SAVANA_ARGUMENTS_V2\0", entries)
}

pub fn evidence_digest_v2(entries: &[EvidenceDigestEntryV2]) -> Result<Digest32V2, G3Error> {
    if entries.len() > MAX_EVIDENCE_ITEMS {
        return Err(G3Error::CollectionLimitExceeded);
    }
    if entries
        .windows(2)
        .any(|pair| evidence_key(&pair[0]) >= evidence_key(&pair[1]))
    {
        return Err(G3Error::NonCanonicalOrder);
    }
    hash_entries(b"SAVANA_EVIDENCE_V2\0", entries)
}

pub fn provenance_set_digest_v2(
    arguments: &[ArgumentDigestEntryV2],
    entries: &[ProvenanceSetDigestEntryV2],
) -> Result<Digest32V2, G3Error> {
    if arguments.len() > MAX_ARGUMENTS || entries.len() > MAX_ARGUMENTS {
        return Err(G3Error::CollectionLimitExceeded);
    }
    validate_argument_order(arguments)?;
    if entries
        .windows(2)
        .any(|pair| pair[0].value_internal_id == pair[1].value_internal_id)
    {
        return Err(G3Error::DuplicateInternalId);
    }
    if entries
        .windows(2)
        .any(|pair| provenance_key(&pair[0]) >= provenance_key(&pair[1]))
    {
        return Err(G3Error::NonCanonicalOrder);
    }

    let mut expected = arguments
        .iter()
        .map(|entry| {
            (
                entry.value_internal_id(),
                entry.value_digest(),
                entry.provenance_digest(),
            )
        })
        .collect::<Vec<_>>();
    expected.sort_unstable_by(provenance_tuple_cmp);
    if expected.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(G3Error::DuplicateInternalId);
    }
    if expected.len() != entries.len()
        || expected.iter().zip(entries).any(|(left, right)| {
            left.0 != right.value_internal_id
                || left.1 != right.value_digest
                || left.2 != right.provenance_digest
        })
    {
        return Err(G3Error::BindingMismatch);
    }

    hash_entries(b"SAVANA_PROVENANCE_SET_V2\0", entries)
}

pub fn token_set_digest_v2(entries: &[TokenSetDigestEntryV2]) -> Result<Digest32V2, G3Error> {
    if entries.len() > MAX_TOKENS {
        return Err(G3Error::CollectionLimitExceeded);
    }
    if entries.windows(2).any(|pair| {
        pair[0].token_slot_id.as_str().as_bytes() >= pair[1].token_slot_id.as_str().as_bytes()
    }) {
        return Err(G3Error::NonCanonicalOrder);
    }

    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(2)
        .and_then(|encoder| encoder.u64(entries.len() as u64))
        .and_then(|encoder| encoder.array(entries.len() as u64))
        .map_err(|_| G3Error::CanonicalEncoding)?;
    for entry in entries {
        entry
            .encode(&mut encoder, &mut ())
            .map_err(|_| G3Error::CanonicalEncoding)?;
    }
    Ok(domain_hash(
        b"SAVANA_TOKEN_SET_V2\0",
        &encoder.into_writer(),
    ))
}

fn evidence_key(entry: &EvidenceDigestEntryV2) -> (&[u8; 32], &[u8; 32]) {
    (
        entry.value_digest.as_bytes(),
        entry.provenance_digest.as_bytes(),
    )
}

fn provenance_key(entry: &ProvenanceSetDigestEntryV2) -> (&[u8; 32], &[u8; 32], &[u8; 32]) {
    (
        entry.value_internal_id.as_bytes(),
        entry.value_digest.as_bytes(),
        entry.provenance_digest.as_bytes(),
    )
}

fn validate_argument_order(entries: &[ArgumentDigestEntryV2]) -> Result<(), G3Error> {
    if entries.windows(2).any(|pair| {
        pair[0].argument_name.as_str().as_bytes() >= pair[1].argument_name.as_str().as_bytes()
    }) {
        return Err(G3Error::NonCanonicalOrder);
    }
    Ok(())
}

fn provenance_tuple_cmp(
    left: &(ValueInternalIdV2, Digest32V2, Digest32V2),
    right: &(ValueInternalIdV2, Digest32V2, Digest32V2),
) -> std::cmp::Ordering {
    left.0
        .as_bytes()
        .cmp(right.0.as_bytes())
        .then_with(|| left.1.as_bytes().cmp(right.1.as_bytes()))
        .then_with(|| left.2.as_bytes().cmp(right.2.as_bytes()))
}

fn hash_entries<C>(domain: &[u8], entries: &[C]) -> Result<Digest32V2, G3Error>
where
    C: minicbor::Encode<()>,
{
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(entries.len() as u64)
        .map_err(|_| G3Error::CanonicalEncoding)?;
    for entry in entries {
        entry
            .encode(&mut encoder, &mut ())
            .map_err(|_| G3Error::CanonicalEncoding)?;
    }
    Ok(domain_hash(domain, &encoder.into_writer()))
}

fn domain_hash(domain: &[u8], canonical: &[u8]) -> Digest32V2 {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(canonical);
    Digest32V2::new(hasher.finalize().into())
}

#[cfg(test)]
#[path = "digest_tests.rs"]
mod tests;
