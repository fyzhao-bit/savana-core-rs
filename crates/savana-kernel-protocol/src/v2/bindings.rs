use super::{Digest32V2, DurableReleaseIdV2};

const FINAL_RELEASE_BINDING_DOMAIN: &[u8] = b"SAVANA_FINAL_RELEASE_SEMANTIC_BINDING_V2\0";

/// The single canonical semantic identity of one final-release authorization.
///
/// Constructing this value does not authorize a release. Authority is carried
/// by the approval, ticket, dispatch, and vault capabilities that bind its
/// digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FinalReleaseSemanticBindingV2 {
    durable_release_id: DurableReleaseIdV2,
    vault_segment_internal_id: Digest32V2,
    vault_segment_digest: Digest32V2,
    release_payload_digest: Digest32V2,
    evidence_digest: Digest32V2,
    token_set_digest: Digest32V2,
    destination_digest: Digest32V2,
    display_projection_digest: Digest32V2,
    display_digest: Digest32V2,
    executor_identity_digest: Digest32V2,
    release_quota_subject_digest: Digest32V2,
}

impl FinalReleaseSemanticBindingV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn from_nonzero_components(
        durable_release_id: DurableReleaseIdV2,
        vault_segment_internal_id: Digest32V2,
        vault_segment_digest: Digest32V2,
        release_payload_digest: Digest32V2,
        evidence_digest: Digest32V2,
        token_set_digest: Digest32V2,
        destination_digest: Digest32V2,
        display_projection_digest: Digest32V2,
        display_digest: Digest32V2,
        executor_identity_digest: Digest32V2,
        release_quota_subject_digest: Digest32V2,
    ) -> Option<Self> {
        if is_zero(durable_release_id.as_bytes())
            || [
                vault_segment_internal_id,
                vault_segment_digest,
                release_payload_digest,
                evidence_digest,
                token_set_digest,
                destination_digest,
                display_projection_digest,
                display_digest,
                executor_identity_digest,
                release_quota_subject_digest,
            ]
            .iter()
            .any(|digest| is_zero(digest.as_bytes()))
        {
            return None;
        }
        Some(Self {
            durable_release_id,
            vault_segment_internal_id,
            vault_segment_digest,
            release_payload_digest,
            evidence_digest,
            token_set_digest,
            destination_digest,
            display_projection_digest,
            display_digest,
            executor_identity_digest,
            release_quota_subject_digest,
        })
    }

    pub const fn durable_release_id(self) -> DurableReleaseIdV2 {
        self.durable_release_id
    }

    pub const fn vault_segment_internal_id(self) -> Digest32V2 {
        self.vault_segment_internal_id
    }

    pub const fn vault_segment_digest(self) -> Digest32V2 {
        self.vault_segment_digest
    }

    pub const fn release_payload_digest(self) -> Digest32V2 {
        self.release_payload_digest
    }

    pub const fn evidence_digest(self) -> Digest32V2 {
        self.evidence_digest
    }

    pub const fn token_set_digest(self) -> Digest32V2 {
        self.token_set_digest
    }

    pub const fn destination_digest(self) -> Digest32V2 {
        self.destination_digest
    }

    pub const fn display_projection_digest(self) -> Digest32V2 {
        self.display_projection_digest
    }

    pub const fn display_digest(self) -> Digest32V2 {
        self.display_digest
    }

    pub const fn executor_identity_digest(self) -> Digest32V2 {
        self.executor_identity_digest
    }

    pub const fn release_quota_subject_digest(self) -> Digest32V2 {
        self.release_quota_subject_digest
    }

    pub fn semantic_digest(self) -> Option<Digest32V2> {
        let canonical = minicbor::to_vec(self).ok()?;
        let mut hasher = sha2::Sha256::new();
        use sha2::Digest as _;
        hasher.update(FINAL_RELEASE_BINDING_DOMAIN);
        hasher.update(canonical);
        Some(Digest32V2::new(hasher.finalize().into()))
    }
}

impl<C> minicbor::Encode<C> for FinalReleaseSemanticBindingV2 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        encoder.array(11)?;
        self.durable_release_id.encode(encoder, context)?;
        self.vault_segment_internal_id.encode(encoder, context)?;
        self.vault_segment_digest.encode(encoder, context)?;
        self.release_payload_digest.encode(encoder, context)?;
        self.evidence_digest.encode(encoder, context)?;
        self.token_set_digest.encode(encoder, context)?;
        self.destination_digest.encode(encoder, context)?;
        self.display_projection_digest.encode(encoder, context)?;
        self.display_digest.encode(encoder, context)?;
        self.executor_identity_digest.encode(encoder, context)?;
        self.release_quota_subject_digest.encode(encoder, context)?;
        Ok(())
    }
}

impl<'bytes> minicbor::Decode<'bytes, super::cbor::V2DecodeContext>
    for FinalReleaseSemanticBindingV2
{
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        context: &mut super::cbor::V2DecodeContext,
    ) -> Result<Self, minicbor::decode::Error> {
        let position = decoder.position();
        if decoder.array()? != Some(11) {
            return Err(minicbor::decode::Error::message(
                crate::StableCode::ProtocolMalformedCbor.as_str(),
            )
            .at(position));
        }
        Self::from_nonzero_components(
            minicbor::Decode::decode(decoder, context)?,
            minicbor::Decode::decode(decoder, context)?,
            minicbor::Decode::decode(decoder, context)?,
            minicbor::Decode::decode(decoder, context)?,
            minicbor::Decode::decode(decoder, context)?,
            minicbor::Decode::decode(decoder, context)?,
            minicbor::Decode::decode(decoder, context)?,
            minicbor::Decode::decode(decoder, context)?,
            minicbor::Decode::decode(decoder, context)?,
            minicbor::Decode::decode(decoder, context)?,
            minicbor::Decode::decode(decoder, context)?,
        )
        .ok_or_else(|| {
            minicbor::decode::Error::message(crate::StableCode::ProtocolMalformedCbor.as_str())
                .at(position)
        })
    }
}

const fn is_zero(bytes: &[u8; 32]) -> bool {
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != 0 {
            return false;
        }
        index += 1;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn final_release_binding_has_the_frozen_shape_and_domain() {
        let binding = FinalReleaseSemanticBindingV2::from_nonzero_components(
            DurableReleaseIdV2::new([1; 32]),
            Digest32V2::new([2; 32]),
            Digest32V2::new([3; 32]),
            Digest32V2::new([4; 32]),
            Digest32V2::new([5; 32]),
            Digest32V2::new([6; 32]),
            Digest32V2::new([7; 32]),
            Digest32V2::new([8; 32]),
            Digest32V2::new([9; 32]),
            Digest32V2::new([10; 32]),
            Digest32V2::new([11; 32]),
        )
        .unwrap();
        let canonical = minicbor::to_vec(binding).unwrap();
        assert_eq!(
            minicbor::Decoder::new(&canonical).array().unwrap(),
            Some(11)
        );

        let mut hasher = sha2::Sha256::new();
        use sha2::Digest as _;
        hasher.update(b"SAVANA_FINAL_RELEASE_SEMANTIC_BINDING_V2\0");
        hasher.update(&canonical);
        assert_eq!(
            binding.semantic_digest().unwrap().as_bytes(),
            &<[u8; 32]>::from(hasher.finalize())
        );
    }

    #[test]
    fn final_release_binding_rejects_every_zero_identity() {
        assert!(FinalReleaseSemanticBindingV2::from_nonzero_components(
            DurableReleaseIdV2::new([0; 32]),
            Digest32V2::new([2; 32]),
            Digest32V2::new([3; 32]),
            Digest32V2::new([4; 32]),
            Digest32V2::new([5; 32]),
            Digest32V2::new([6; 32]),
            Digest32V2::new([7; 32]),
            Digest32V2::new([8; 32]),
            Digest32V2::new([9; 32]),
            Digest32V2::new([10; 32]),
            Digest32V2::new([11; 32]),
        )
        .is_none());
    }
}
