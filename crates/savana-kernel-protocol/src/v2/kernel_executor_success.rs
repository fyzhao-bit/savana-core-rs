use crate::{ProtocolError, StableCode};
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use sha2::Digest as _;

use super::{
    application::PublicStableCodeV2,
    cbor::{scan_single, V2DecodeContext},
    derive_ed25519_key_id_v2,
    kernel_executor::{
        decode_completion_descriptor, encode_completion_descriptor, ExecutorCompletionDescriptorV2,
    },
    Digest32V2, DurableReleaseIdV2, Ed25519KeyIdV2, Ed25519SignatureV2, ExecutorIdentityV2,
    HpkeX25519KeyIdV2, Nonce32V2, UnixMillisV2, ZeroizingBytesV2,
};

const MAX_SIGNED_RECEIPT_PAYLOAD_BYTES_V2: usize = 8 * 1024;
const EFFECT_STARTED_RECEIPT_SIGNATURE_DOMAIN_V2: &[u8] =
    b"SAVANA_EXECD_EFFECT_STARTED_RECEIPT_V2\0";
const EFFECT_STARTED_RECEIPT_DIGEST_DOMAIN_V2: &[u8] =
    b"SAVANA_EXECD_EFFECT_STARTED_SIGNED_RECEIPT_V2\0";
const FINAL_RELEASE_RECEIPT_SIGNATURE_DOMAIN_V2: &[u8] = b"SAVANA_EXECD_FINAL_RELEASE_RECEIPT_V2\0";
const FINAL_RELEASE_RECEIPT_DIGEST_DOMAIN_V2: &[u8] =
    b"SAVANA_EXECD_FINAL_RELEASE_SIGNED_RECEIPT_V2\0";
const FINAL_RELEASE_AUDIT_EVIDENCE_DIGEST_DOMAIN_V2: &[u8] =
    b"SAVANA_EXECD_FINAL_RELEASE_AUDIT_EVIDENCE_V2\0";
const CONNECTOR_PROVIDER_EVIDENCE_DIGEST_DOMAIN_V2: &[u8] =
    b"SAVANA_CONNECTOR_PROVIDER_EVIDENCE_V2\0";
const CONNECTOR_RESULT_DIGEST_DOMAIN_V2: &[u8] = b"SAVANA_CONNECTOR_CODEC_RESULT_V2\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnsignedExecutorEffectStartedReceiptV2 {
    installation_id: Digest32V2,
    active_state_manifest_digest: Digest32V2,
    deployment_generation: u64,
    effect_fence_epoch: u64,
    execution_nonce: Nonce32V2,
    dispatch_core_digest: Digest32V2,
    dispatch_subject_digest: Digest32V2,
    executor_identity: ExecutorIdentityV2,
    connector_identity_digest: Digest32V2,
    external_attempt_ordinal: u16,
    connector_codec_job_descriptor_digest: Digest32V2,
    prepared_provider_request_digest: Digest32V2,
    provider_attempt_prepared_journal_record_digest: Digest32V2,
    started_at: UnixMillisV2,
}

impl UnsignedExecutorEffectStartedReceiptV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        installation_id: Digest32V2,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
        effect_fence_epoch: u64,
        execution_nonce: Nonce32V2,
        dispatch_core_digest: Digest32V2,
        dispatch_subject_digest: Digest32V2,
        executor_identity: ExecutorIdentityV2,
        connector_identity_digest: Digest32V2,
        external_attempt_ordinal: u16,
        connector_codec_job_descriptor_digest: Digest32V2,
        prepared_provider_request_digest: Digest32V2,
        provider_attempt_prepared_journal_record_digest: Digest32V2,
        started_at: UnixMillisV2,
    ) -> Result<Self, ProtocolError> {
        if deployment_generation == 0
            || effect_fence_epoch == 0
            || external_attempt_ordinal == 0
            || started_at.get() == 0
            || [
                installation_id.as_bytes(),
                active_state_manifest_digest.as_bytes(),
                execution_nonce.as_bytes(),
                dispatch_core_digest.as_bytes(),
                dispatch_subject_digest.as_bytes(),
                executor_identity.as_bytes(),
                connector_identity_digest.as_bytes(),
                connector_codec_job_descriptor_digest.as_bytes(),
                prepared_provider_request_digest.as_bytes(),
                provider_attempt_prepared_journal_record_digest.as_bytes(),
            ]
            .iter()
            .any(|bytes| bytes.iter().all(|byte| *byte == 0))
        {
            return Err(malformed());
        }
        Ok(Self {
            installation_id,
            active_state_manifest_digest,
            deployment_generation,
            effect_fence_epoch,
            execution_nonce,
            dispatch_core_digest,
            dispatch_subject_digest,
            executor_identity,
            connector_identity_digest,
            external_attempt_ordinal,
            connector_codec_job_descriptor_digest,
            prepared_provider_request_digest,
            provider_attempt_prepared_journal_record_digest,
            started_at,
        })
    }

    pub const fn installation_id(self) -> Digest32V2 {
        self.installation_id
    }

    pub const fn active_state_manifest_digest(self) -> Digest32V2 {
        self.active_state_manifest_digest
    }

    pub const fn deployment_generation(self) -> u64 {
        self.deployment_generation
    }

    pub const fn effect_fence_epoch(self) -> u64 {
        self.effect_fence_epoch
    }

    pub const fn execution_nonce(self) -> Nonce32V2 {
        self.execution_nonce
    }

    pub const fn dispatch_core_digest(self) -> Digest32V2 {
        self.dispatch_core_digest
    }

    pub const fn dispatch_subject_digest(self) -> Digest32V2 {
        self.dispatch_subject_digest
    }

    pub const fn executor_identity(self) -> ExecutorIdentityV2 {
        self.executor_identity
    }

    pub const fn connector_identity_digest(self) -> Digest32V2 {
        self.connector_identity_digest
    }

    pub const fn external_attempt_ordinal(self) -> u16 {
        self.external_attempt_ordinal
    }

    pub const fn connector_codec_job_descriptor_digest(self) -> Digest32V2 {
        self.connector_codec_job_descriptor_digest
    }

    pub const fn prepared_provider_request_digest(self) -> Digest32V2 {
        self.prepared_provider_request_digest
    }

    pub const fn provider_attempt_prepared_journal_record_digest(self) -> Digest32V2 {
        self.provider_attempt_prepared_journal_record_digest
    }

    pub const fn started_at(self) -> UnixMillisV2 {
        self.started_at
    }
}

impl<C> minicbor::Encode<C> for UnsignedExecutorEffectStartedReceiptV2 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        _context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        encoder
            .array(15)?
            .u16(2)?
            .bytes(self.installation_id.as_bytes())?
            .bytes(self.active_state_manifest_digest.as_bytes())?
            .u64(self.deployment_generation)?
            .u64(self.effect_fence_epoch)?
            .bytes(self.execution_nonce.as_bytes())?
            .bytes(self.dispatch_core_digest.as_bytes())?
            .bytes(self.dispatch_subject_digest.as_bytes())?
            .bytes(self.executor_identity.as_bytes())?
            .bytes(self.connector_identity_digest.as_bytes())?
            .u16(self.external_attempt_ordinal)?
            .bytes(self.connector_codec_job_descriptor_digest.as_bytes())?
            .bytes(self.prepared_provider_request_digest.as_bytes())?
            .bytes(
                self.provider_attempt_prepared_journal_record_digest
                    .as_bytes(),
            )?
            .u64(self.started_at.get())?;
        Ok(())
    }
}

impl<'bytes> minicbor::Decode<'bytes, V2DecodeContext> for UnsignedExecutorEffectStartedReceiptV2 {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        _context: &mut V2DecodeContext,
    ) -> Result<Self, minicbor::decode::Error> {
        let position = decoder.position();
        if decoder.array()? != Some(15) || decoder.u16()? != 2 {
            return Err(decode_error(position));
        }
        Self::new(
            Digest32V2::new(decode_fixed::<32>(decoder).map_err(|_| decode_error(position))?),
            Digest32V2::new(decode_fixed::<32>(decoder).map_err(|_| decode_error(position))?),
            decoder.u64()?,
            decoder.u64()?,
            Nonce32V2::new(decode_fixed::<32>(decoder).map_err(|_| decode_error(position))?),
            Digest32V2::new(decode_fixed::<32>(decoder).map_err(|_| decode_error(position))?),
            Digest32V2::new(decode_fixed::<32>(decoder).map_err(|_| decode_error(position))?),
            ExecutorIdentityV2::new(
                decode_fixed::<32>(decoder).map_err(|_| decode_error(position))?,
            ),
            Digest32V2::new(decode_fixed::<32>(decoder).map_err(|_| decode_error(position))?),
            decoder.u16()?,
            Digest32V2::new(decode_fixed::<32>(decoder).map_err(|_| decode_error(position))?),
            Digest32V2::new(decode_fixed::<32>(decoder).map_err(|_| decode_error(position))?),
            Digest32V2::new(decode_fixed::<32>(decoder).map_err(|_| decode_error(position))?),
            UnixMillisV2::new(decoder.u64()?),
        )
        .map_err(|_| decode_error(position))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnsignedExecutorFinalReleaseReceiptV2 {
    installation_id: Digest32V2,
    active_state_manifest_digest: Digest32V2,
    deployment_generation: u64,
    effect_fence_epoch: u64,
    durable_release_id: DurableReleaseIdV2,
    execution_nonce: Nonce32V2,
    dispatch_core_digest: Digest32V2,
    dispatch_subject_digest: Digest32V2,
    vault_segment_digest: Digest32V2,
    release_payload_digest: Digest32V2,
    destination_digest: Digest32V2,
    executor_identity: ExecutorIdentityV2,
    provider_evidence_digest: Digest32V2,
    release_audit_digest: Digest32V2,
    release_evidence_prepared_journal_record_digest: Digest32V2,
    completed_at: UnixMillisV2,
}

impl UnsignedExecutorFinalReleaseReceiptV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        installation_id: Digest32V2,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
        effect_fence_epoch: u64,
        durable_release_id: DurableReleaseIdV2,
        execution_nonce: Nonce32V2,
        dispatch_core_digest: Digest32V2,
        dispatch_subject_digest: Digest32V2,
        vault_segment_digest: Digest32V2,
        release_payload_digest: Digest32V2,
        destination_digest: Digest32V2,
        executor_identity: ExecutorIdentityV2,
        provider_evidence_digest: Digest32V2,
        release_audit_digest: Digest32V2,
        release_evidence_prepared_journal_record_digest: Digest32V2,
        completed_at: UnixMillisV2,
    ) -> Result<Self, ProtocolError> {
        if deployment_generation == 0
            || effect_fence_epoch == 0
            || completed_at.get() == 0
            || [
                installation_id.as_bytes(),
                active_state_manifest_digest.as_bytes(),
                durable_release_id.as_bytes(),
                execution_nonce.as_bytes(),
                dispatch_core_digest.as_bytes(),
                dispatch_subject_digest.as_bytes(),
                vault_segment_digest.as_bytes(),
                release_payload_digest.as_bytes(),
                destination_digest.as_bytes(),
                executor_identity.as_bytes(),
                provider_evidence_digest.as_bytes(),
                release_audit_digest.as_bytes(),
                release_evidence_prepared_journal_record_digest.as_bytes(),
            ]
            .iter()
            .any(|bytes| bytes.iter().all(|byte| *byte == 0))
        {
            return Err(malformed());
        }
        Ok(Self {
            installation_id,
            active_state_manifest_digest,
            deployment_generation,
            effect_fence_epoch,
            durable_release_id,
            execution_nonce,
            dispatch_core_digest,
            dispatch_subject_digest,
            vault_segment_digest,
            release_payload_digest,
            destination_digest,
            executor_identity,
            provider_evidence_digest,
            release_audit_digest,
            release_evidence_prepared_journal_record_digest,
            completed_at,
        })
    }

    pub const fn durable_release_id(self) -> DurableReleaseIdV2 {
        self.durable_release_id
    }

    pub const fn installation_id(self) -> Digest32V2 {
        self.installation_id
    }

    pub const fn active_state_manifest_digest(self) -> Digest32V2 {
        self.active_state_manifest_digest
    }

    pub const fn deployment_generation(self) -> u64 {
        self.deployment_generation
    }

    pub const fn effect_fence_epoch(self) -> u64 {
        self.effect_fence_epoch
    }

    pub const fn execution_nonce(self) -> Nonce32V2 {
        self.execution_nonce
    }

    pub const fn dispatch_core_digest(self) -> Digest32V2 {
        self.dispatch_core_digest
    }

    pub const fn dispatch_subject_digest(self) -> Digest32V2 {
        self.dispatch_subject_digest
    }

    pub const fn vault_segment_digest(self) -> Digest32V2 {
        self.vault_segment_digest
    }

    pub const fn release_payload_digest(self) -> Digest32V2 {
        self.release_payload_digest
    }

    pub const fn destination_digest(self) -> Digest32V2 {
        self.destination_digest
    }

    pub const fn executor_identity(self) -> ExecutorIdentityV2 {
        self.executor_identity
    }

    pub const fn provider_evidence_digest(self) -> Digest32V2 {
        self.provider_evidence_digest
    }

    pub const fn release_audit_digest(self) -> Digest32V2 {
        self.release_audit_digest
    }

    pub const fn release_evidence_prepared_journal_record_digest(self) -> Digest32V2 {
        self.release_evidence_prepared_journal_record_digest
    }

    pub const fn completed_at(self) -> UnixMillisV2 {
        self.completed_at
    }
}

impl<C> minicbor::Encode<C> for UnsignedExecutorFinalReleaseReceiptV2 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        _context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        encoder
            .array(17)?
            .u16(2)?
            .bytes(self.installation_id.as_bytes())?
            .bytes(self.active_state_manifest_digest.as_bytes())?
            .u64(self.deployment_generation)?
            .u64(self.effect_fence_epoch)?
            .bytes(self.durable_release_id.as_bytes())?
            .bytes(self.execution_nonce.as_bytes())?
            .bytes(self.dispatch_core_digest.as_bytes())?
            .bytes(self.dispatch_subject_digest.as_bytes())?
            .bytes(self.vault_segment_digest.as_bytes())?
            .bytes(self.release_payload_digest.as_bytes())?
            .bytes(self.destination_digest.as_bytes())?
            .bytes(self.executor_identity.as_bytes())?
            .bytes(self.provider_evidence_digest.as_bytes())?
            .bytes(self.release_audit_digest.as_bytes())?
            .bytes(
                self.release_evidence_prepared_journal_record_digest
                    .as_bytes(),
            )?
            .u64(self.completed_at.get())?;
        Ok(())
    }
}

impl<'bytes> minicbor::Decode<'bytes, V2DecodeContext> for UnsignedExecutorFinalReleaseReceiptV2 {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        _context: &mut V2DecodeContext,
    ) -> Result<Self, minicbor::decode::Error> {
        let position = decoder.position();
        if decoder.array()? != Some(17) || decoder.u16()? != 2 {
            return Err(decode_error(position));
        }
        Self::new(
            Digest32V2::new(decode_fixed::<32>(decoder).map_err(|_| decode_error(position))?),
            Digest32V2::new(decode_fixed::<32>(decoder).map_err(|_| decode_error(position))?),
            decoder.u64()?,
            decoder.u64()?,
            DurableReleaseIdV2::new(
                decode_fixed::<32>(decoder).map_err(|_| decode_error(position))?,
            ),
            Nonce32V2::new(decode_fixed::<32>(decoder).map_err(|_| decode_error(position))?),
            Digest32V2::new(decode_fixed::<32>(decoder).map_err(|_| decode_error(position))?),
            Digest32V2::new(decode_fixed::<32>(decoder).map_err(|_| decode_error(position))?),
            Digest32V2::new(decode_fixed::<32>(decoder).map_err(|_| decode_error(position))?),
            Digest32V2::new(decode_fixed::<32>(decoder).map_err(|_| decode_error(position))?),
            Digest32V2::new(decode_fixed::<32>(decoder).map_err(|_| decode_error(position))?),
            ExecutorIdentityV2::new(
                decode_fixed::<32>(decoder).map_err(|_| decode_error(position))?,
            ),
            Digest32V2::new(decode_fixed::<32>(decoder).map_err(|_| decode_error(position))?),
            Digest32V2::new(decode_fixed::<32>(decoder).map_err(|_| decode_error(position))?),
            Digest32V2::new(decode_fixed::<32>(decoder).map_err(|_| decode_error(position))?),
            UnixMillisV2::new(decoder.u64()?),
        )
        .map_err(|_| decode_error(position))
    }
}

macro_rules! signed_executor_receipt_v2 {
    ($name:ident, $unsigned:ident, $signature_domain:ident, $digest_domain:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct $name {
            unsigned: $unsigned,
            canonical_payload: Vec<u8>,
            key_id: Ed25519KeyIdV2,
            signature: Ed25519SignatureV2,
        }

        impl $name {
            pub fn from_canonical_parts(
                canonical_payload: Vec<u8>,
                key_id: Ed25519KeyIdV2,
                signature: Ed25519SignatureV2,
            ) -> Result<Self, ProtocolError> {
                if canonical_payload.is_empty()
                    || canonical_payload.len() > MAX_SIGNED_RECEIPT_PAYLOAD_BYTES_V2
                    || key_id.as_bytes() == &[0; 32]
                    || signature.as_bytes() == &[0; 64]
                {
                    return Err(malformed());
                }
                let unsigned: $unsigned = decode_exact(&canonical_payload)?;
                Ok(Self {
                    unsigned,
                    canonical_payload,
                    key_id,
                    signature,
                })
            }

            pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ProtocolError> {
                decode_exact(bytes)
            }

            pub fn canonical_bytes(&self) -> Result<Vec<u8>, ProtocolError> {
                encode_exact(self)
            }

            pub fn sign(
                unsigned: $unsigned,
                key_id: Ed25519KeyIdV2,
                signing_key: &SigningKey,
            ) -> Result<Self, ProtocolError> {
                if key_id != derive_ed25519_key_id_v2(signing_key.verifying_key().to_bytes()) {
                    return Err(malformed());
                }
                let canonical_payload = encode_exact(&unsigned)?;
                let signature =
                    receipt_signature($signature_domain, &canonical_payload, signing_key);
                Self::from_canonical_parts(canonical_payload, key_id, signature)
            }

            pub fn verify(
                &self,
                expected_key_id: Ed25519KeyIdV2,
                expected_public_key: [u8; 32],
            ) -> Result<(), ProtocolError> {
                if self.key_id != expected_key_id
                    || expected_key_id != derive_ed25519_key_id_v2(expected_public_key)
                {
                    return Err(malformed());
                }
                let key = VerifyingKey::from_bytes(&expected_public_key)
                    .map_err(ProtocolError::malformed)?;
                let input = receipt_signature_input($signature_domain, &self.canonical_payload);
                key.verify_strict(&input, &Signature::from_bytes(self.signature.as_bytes()))
                    .map_err(ProtocolError::malformed)
            }

            pub const fn unsigned(&self) -> &$unsigned {
                &self.unsigned
            }

            pub fn digest(&self) -> Digest32V2 {
                let bytes = self
                    .canonical_bytes()
                    .expect("validated receipt must remain canonically encodable");
                domain_digest($digest_domain, &bytes)
            }

            pub fn canonical_payload(&self) -> &[u8] {
                &self.canonical_payload
            }

            pub const fn key_id(&self) -> Ed25519KeyIdV2 {
                self.key_id
            }

            pub const fn signature(&self) -> Ed25519SignatureV2 {
                self.signature
            }
        }

        impl<C> minicbor::Encode<C> for $name {
            fn encode<W: minicbor::encode::Write>(
                &self,
                encoder: &mut minicbor::Encoder<W>,
                _context: &mut C,
            ) -> Result<(), minicbor::encode::Error<W::Error>> {
                encoder
                    .array(3)?
                    .bytes(&self.canonical_payload)?
                    .bytes(self.key_id.as_bytes())?
                    .bytes(self.signature.as_bytes())?;
                Ok(())
            }
        }

        impl<'bytes> minicbor::Decode<'bytes, V2DecodeContext> for $name {
            fn decode(
                decoder: &mut minicbor::Decoder<'bytes>,
                _context: &mut V2DecodeContext,
            ) -> Result<Self, minicbor::decode::Error> {
                let position = decoder.position();
                if decoder.array()? != Some(3) {
                    return Err(decode_error(position));
                }
                let payload = decoder.bytes()?;
                let key_id = Ed25519KeyIdV2::new(
                    decoder
                        .bytes()?
                        .try_into()
                        .map_err(|_| decode_error(position))?,
                );
                let signature = Ed25519SignatureV2::new(
                    decoder
                        .bytes()?
                        .try_into()
                        .map_err(|_| decode_error(position))?,
                );
                Self::from_canonical_parts(payload.to_vec(), key_id, signature)
                    .map_err(|_| decode_error(position))
            }
        }
    };
}

signed_executor_receipt_v2!(
    SignedExecutorEffectStartedReceiptV2,
    UnsignedExecutorEffectStartedReceiptV2,
    EFFECT_STARTED_RECEIPT_SIGNATURE_DOMAIN_V2,
    EFFECT_STARTED_RECEIPT_DIGEST_DOMAIN_V2
);
signed_executor_receipt_v2!(
    SignedExecutorFinalReleaseReceiptV2,
    UnsignedExecutorFinalReleaseReceiptV2,
    FINAL_RELEASE_RECEIPT_SIGNATURE_DOMAIN_V2,
    FINAL_RELEASE_RECEIPT_DIGEST_DOMAIN_V2
);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutorFailureClassV2 {
    EnvelopeRejectedBeforeEffect,
    FencedBeforeEffect,
    ConnectorUnavailableBeforeEffect,
    ConnectorRejectedBeforeEffect,
    ResourceFailureBeforeEffect,
}

impl ExecutorFailureClassV2 {
    pub const fn tag(self) -> u16 {
        match self {
            Self::EnvelopeRejectedBeforeEffect => 1,
            Self::FencedBeforeEffect => 2,
            Self::ConnectorUnavailableBeforeEffect => 3,
            Self::ConnectorRejectedBeforeEffect => 4,
            Self::ResourceFailureBeforeEffect => 5,
        }
    }

    fn from_tag(tag: u16) -> Result<Self, ProtocolError> {
        Ok(match tag {
            1 => Self::EnvelopeRejectedBeforeEffect,
            2 => Self::FencedBeforeEffect,
            3 => Self::ConnectorUnavailableBeforeEffect,
            4 => Self::ConnectorRejectedBeforeEffect,
            5 => Self::ResourceFailureBeforeEffect,
            _ => return Err(malformed()),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutorStatusV2 {
    Prepared,
    EffectStarted {
        effect_started_receipt: SignedExecutorEffectStartedReceiptV2,
        effect_started_receipt_digest: Digest32V2,
    },
    CompletionAvailable {
        effect_started_receipt: SignedExecutorEffectStartedReceiptV2,
        effect_started_receipt_digest: Digest32V2,
        completion: ExecutorCompletionDescriptorV2,
    },
    FailedNoEffect {
        class: ExecutorFailureClassV2,
    },
    Indeterminate {
        effect_started_receipt: Option<SignedExecutorEffectStartedReceiptV2>,
        effect_started_receipt_digest: Option<Digest32V2>,
    },
    Acknowledged,
}

impl ExecutorStatusV2 {
    pub fn effect_started(
        receipt: SignedExecutorEffectStartedReceiptV2,
        receipt_digest: Digest32V2,
    ) -> Result<Self, ProtocolError> {
        if receipt_digest.as_bytes() == &[0; 32] {
            return Err(malformed());
        }
        Ok(Self::EffectStarted {
            effect_started_receipt: receipt,
            effect_started_receipt_digest: receipt_digest,
        })
    }

    pub fn completion_available(
        receipt: SignedExecutorEffectStartedReceiptV2,
        receipt_digest: Digest32V2,
        completion: ExecutorCompletionDescriptorV2,
    ) -> Result<Self, ProtocolError> {
        if receipt_digest.as_bytes() == &[0; 32] {
            return Err(malformed());
        }
        Ok(Self::CompletionAvailable {
            effect_started_receipt: receipt,
            effect_started_receipt_digest: receipt_digest,
            completion,
        })
    }

    pub fn indeterminate(
        receipt: Option<SignedExecutorEffectStartedReceiptV2>,
        receipt_digest: Option<Digest32V2>,
    ) -> Result<Self, ProtocolError> {
        if receipt.is_some() != receipt_digest.is_some()
            || receipt_digest.is_some_and(|digest| digest.as_bytes() == &[0; 32])
        {
            return Err(malformed());
        }
        Ok(Self::Indeterminate {
            effect_started_receipt: receipt,
            effect_started_receipt_digest: receipt_digest,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutorHealthResponseV2 {
    ready: bool,
    active_state_manifest_digest: Digest32V2,
    deployment_generation: u64,
    effect_fence_epoch: u64,
    executor_identity: ExecutorIdentityV2,
    seal_key_id: HpkeX25519KeyIdV2,
    journal_schema_version: u16,
    journal_key_epoch: u64,
    connector_set_digest: Digest32V2,
    bounded_recovery_backlog: u32,
    last_public_error: Option<PublicStableCodeV2>,
}

impl ExecutorHealthResponseV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        ready: bool,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
        effect_fence_epoch: u64,
        executor_identity: ExecutorIdentityV2,
        seal_key_id: HpkeX25519KeyIdV2,
        journal_schema_version: u16,
        journal_key_epoch: u64,
        connector_set_digest: Digest32V2,
        bounded_recovery_backlog: u32,
        last_public_error: Option<PublicStableCodeV2>,
    ) -> Result<Self, ProtocolError> {
        if active_state_manifest_digest.as_bytes() == &[0; 32]
            || deployment_generation == 0
            || effect_fence_epoch == 0
            || executor_identity.as_bytes() == &[0; 32]
            || seal_key_id.as_bytes() == &[0; 32]
            || journal_schema_version == 0
            || journal_key_epoch == 0
            || connector_set_digest.as_bytes() == &[0; 32]
        {
            return Err(malformed());
        }
        Ok(Self {
            ready,
            active_state_manifest_digest,
            deployment_generation,
            effect_fence_epoch,
            executor_identity,
            seal_key_id,
            journal_schema_version,
            journal_key_epoch,
            connector_set_digest,
            bounded_recovery_backlog,
            last_public_error,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispatchResponseV2 {
    status: ExecutorStatusV2,
}

impl DispatchResponseV2 {
    pub const fn new(status: ExecutorStatusV2) -> Self {
        Self { status }
    }

    pub const fn status(&self) -> &ExecutorStatusV2 {
        &self.status
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryByExecutionNonceResponseV2 {
    status: ExecutorStatusV2,
}

impl QueryByExecutionNonceResponseV2 {
    pub const fn new(status: ExecutorStatusV2) -> Self {
        Self { status }
    }

    pub const fn status(&self) -> &ExecutorStatusV2 {
        &self.status
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcknowledgeCommittedCompletionResponseV2 {
    status: ExecutorStatusV2,
}

impl AcknowledgeCommittedCompletionResponseV2 {
    pub const fn new(status: ExecutorStatusV2) -> Self {
        Self { status }
    }
}

#[derive(Debug)]
pub struct ExecutorFinalReleaseAuditEvidenceV2 {
    evidence: ZeroizingBytesV2,
}

impl ExecutorFinalReleaseAuditEvidenceV2 {
    pub fn new(evidence: Vec<u8>) -> Result<Self, ProtocolError> {
        if evidence.is_empty() {
            return Err(malformed());
        }
        Ok(Self {
            evidence: ZeroizingBytesV2::new(evidence)?,
        })
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.evidence.as_bytes()
    }

    pub fn digest(&self) -> Digest32V2 {
        domain_digest(
            FINAL_RELEASE_AUDIT_EVIDENCE_DIGEST_DOMAIN_V2,
            self.evidence.as_bytes(),
        )
    }
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum ExecutorCompletionPayloadV2 {
    ToolResult {
        result: ZeroizingBytesV2,
    },
    FinalReleaseReceipt {
        receipt: SignedExecutorFinalReleaseReceiptV2,
        provider_evidence: ZeroizingBytesV2,
        audit_evidence: ExecutorFinalReleaseAuditEvidenceV2,
    },
}

impl ExecutorCompletionPayloadV2 {
    pub fn tool_result(result: Vec<u8>) -> Result<Self, ProtocolError> {
        if result.is_empty() {
            return Err(malformed());
        }
        Ok(Self::ToolResult {
            result: ZeroizingBytesV2::new(result)?,
        })
    }

    pub fn final_release(
        receipt: SignedExecutorFinalReleaseReceiptV2,
        provider_evidence: Vec<u8>,
        audit_evidence: ExecutorFinalReleaseAuditEvidenceV2,
    ) -> Result<Self, ProtocolError> {
        if provider_evidence.is_empty()
            || receipt.unsigned().provider_evidence_digest()
                != domain_digest(
                    CONNECTOR_PROVIDER_EVIDENCE_DIGEST_DOMAIN_V2,
                    &provider_evidence,
                )
            || receipt.unsigned().release_audit_digest() != audit_evidence.digest()
        {
            return Err(malformed());
        }
        Ok(Self::FinalReleaseReceipt {
            receipt,
            provider_evidence: ZeroizingBytesV2::new(provider_evidence)?,
            audit_evidence,
        })
    }

    pub fn descriptor(&self) -> Result<ExecutorCompletionDescriptorV2, ProtocolError> {
        match self {
            Self::ToolResult { result } => ExecutorCompletionDescriptorV2::tool_result(
                domain_digest(CONNECTOR_RESULT_DIGEST_DOMAIN_V2, result.as_bytes()),
                u32::try_from(result.as_bytes().len()).map_err(ProtocolError::malformed)?,
            ),
            Self::FinalReleaseReceipt {
                receipt,
                audit_evidence,
                ..
            } => ExecutorCompletionDescriptorV2::final_release_receipt(
                receipt.unsigned().durable_release_id(),
                receipt.digest(),
                audit_evidence.digest(),
                u32::try_from(encode_executor_completion_payload_v2(self)?.len())
                    .map_err(ProtocolError::malformed)?,
            ),
        }
    }
}

pub fn encode_executor_completion_payload_v2(
    value: &ExecutorCompletionPayloadV2,
) -> Result<Vec<u8>, ProtocolError> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encode_completion_payload(&mut encoder, value)?;
    Ok(encoder.into_writer())
}

pub fn decode_executor_completion_payload_v2(
    bytes: &[u8],
) -> Result<ExecutorCompletionPayloadV2, ProtocolError> {
    exact_decode(
        bytes,
        decode_completion_payload,
        encode_executor_completion_payload_v2,
    )
}

#[derive(Debug)]
pub struct FetchCompletionResponseV2 {
    execution_nonce: Nonce32V2,
    dispatch_core_digest: Digest32V2,
    dispatch_subject_digest: Digest32V2,
    effect_started_receipt: SignedExecutorEffectStartedReceiptV2,
    effect_started_receipt_digest: Digest32V2,
    completion: ExecutorCompletionDescriptorV2,
    payload: ExecutorCompletionPayloadV2,
}

impl FetchCompletionResponseV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        execution_nonce: Nonce32V2,
        dispatch_core_digest: Digest32V2,
        dispatch_subject_digest: Digest32V2,
        effect_started_receipt: SignedExecutorEffectStartedReceiptV2,
        effect_started_receipt_digest: Digest32V2,
        completion: ExecutorCompletionDescriptorV2,
        payload: ExecutorCompletionPayloadV2,
    ) -> Result<Self, ProtocolError> {
        if execution_nonce.as_bytes() == &[0; 32]
            || dispatch_core_digest.as_bytes() == &[0; 32]
            || dispatch_subject_digest.as_bytes() == &[0; 32]
            || effect_started_receipt_digest.as_bytes() == &[0; 32]
            || effect_started_receipt.digest() != effect_started_receipt_digest
            || effect_started_receipt.unsigned().execution_nonce() != execution_nonce
            || effect_started_receipt.unsigned().dispatch_core_digest() != dispatch_core_digest
            || effect_started_receipt.unsigned().dispatch_subject_digest()
                != dispatch_subject_digest
            || !payload_matches_descriptor(&payload, completion)
        {
            return Err(malformed());
        }
        Ok(Self {
            execution_nonce,
            dispatch_core_digest,
            dispatch_subject_digest,
            effect_started_receipt,
            effect_started_receipt_digest,
            completion,
            payload,
        })
    }

    pub const fn execution_nonce(&self) -> Nonce32V2 {
        self.execution_nonce
    }

    pub const fn dispatch_core_digest(&self) -> Digest32V2 {
        self.dispatch_core_digest
    }

    pub const fn dispatch_subject_digest(&self) -> Digest32V2 {
        self.dispatch_subject_digest
    }

    pub const fn effect_started_receipt(&self) -> &SignedExecutorEffectStartedReceiptV2 {
        &self.effect_started_receipt
    }

    pub const fn effect_started_receipt_digest(&self) -> Digest32V2 {
        self.effect_started_receipt_digest
    }

    pub const fn completion(&self) -> ExecutorCompletionDescriptorV2 {
        self.completion
    }

    pub const fn payload(&self) -> &ExecutorCompletionPayloadV2 {
        &self.payload
    }
}

pub fn encode_executor_health_response_v2(
    value: &ExecutorHealthResponseV2,
) -> Result<Vec<u8>, ProtocolError> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(11)
        .and_then(|encoder| encoder.bool(value.ready))
        .and_then(|encoder| encoder.bytes(value.active_state_manifest_digest.as_bytes()))
        .and_then(|encoder| encoder.u64(value.deployment_generation))
        .and_then(|encoder| encoder.u64(value.effect_fence_epoch))
        .and_then(|encoder| encoder.bytes(value.executor_identity.as_bytes()))
        .and_then(|encoder| encoder.bytes(value.seal_key_id.as_bytes()))
        .and_then(|encoder| encoder.u16(value.journal_schema_version))
        .and_then(|encoder| encoder.u64(value.journal_key_epoch))
        .and_then(|encoder| encoder.bytes(value.connector_set_digest.as_bytes()))
        .and_then(|encoder| encoder.u32(value.bounded_recovery_backlog))
        .map_err(ProtocolError::malformed)?;
    encode_optional_public_error(&mut encoder, value.last_public_error)?;
    Ok(encoder.into_writer())
}

pub fn decode_executor_health_response_v2(
    bytes: &[u8],
) -> Result<ExecutorHealthResponseV2, ProtocolError> {
    exact_decode(
        bytes,
        |decoder, _context| {
            expect_array(decoder, 11)?;
            ExecutorHealthResponseV2::new(
                decoder.bool().map_err(ProtocolError::malformed)?,
                Digest32V2::new(decode_fixed::<32>(decoder)?),
                decoder.u64().map_err(ProtocolError::malformed)?,
                decoder.u64().map_err(ProtocolError::malformed)?,
                ExecutorIdentityV2::new(decode_fixed::<32>(decoder)?),
                HpkeX25519KeyIdV2::new(decode_fixed::<32>(decoder)?),
                decoder.u16().map_err(ProtocolError::malformed)?,
                decoder.u64().map_err(ProtocolError::malformed)?,
                Digest32V2::new(decode_fixed::<32>(decoder)?),
                decoder.u32().map_err(ProtocolError::malformed)?,
                decode_optional_public_error(decoder)?,
            )
        },
        encode_executor_health_response_v2,
    )
}

macro_rules! status_response_codec {
    ($encode:ident, $decode:ident, $type:ident) => {
        pub fn $encode(value: &$type) -> Result<Vec<u8>, ProtocolError> {
            let mut encoder = minicbor::Encoder::new(Vec::new());
            encoder.array(1).map_err(ProtocolError::malformed)?;
            encode_executor_status(&mut encoder, &value.status)?;
            Ok(encoder.into_writer())
        }

        pub fn $decode(bytes: &[u8]) -> Result<$type, ProtocolError> {
            exact_decode(
                bytes,
                |decoder, context| {
                    expect_array(decoder, 1)?;
                    Ok($type::new(decode_executor_status(decoder, context)?))
                },
                $encode,
            )
        }
    };
}

status_response_codec!(
    encode_dispatch_response_v2,
    decode_dispatch_response_v2,
    DispatchResponseV2
);
status_response_codec!(
    encode_query_by_execution_nonce_response_v2,
    decode_query_by_execution_nonce_response_v2,
    QueryByExecutionNonceResponseV2
);

pub fn encode_acknowledge_committed_completion_response_v2(
    value: &AcknowledgeCommittedCompletionResponseV2,
) -> Result<Vec<u8>, ProtocolError> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder.array(1).map_err(ProtocolError::malformed)?;
    encode_executor_status(&mut encoder, &value.status)?;
    Ok(encoder.into_writer())
}

pub fn decode_acknowledge_committed_completion_response_v2(
    bytes: &[u8],
) -> Result<AcknowledgeCommittedCompletionResponseV2, ProtocolError> {
    exact_decode(
        bytes,
        |decoder, context| {
            expect_array(decoder, 1)?;
            Ok(AcknowledgeCommittedCompletionResponseV2::new(
                decode_executor_status(decoder, context)?,
            ))
        },
        encode_acknowledge_committed_completion_response_v2,
    )
}

pub fn encode_fetch_completion_response_v2(
    value: &FetchCompletionResponseV2,
) -> Result<Vec<u8>, ProtocolError> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(7)
        .and_then(|encoder| encoder.bytes(value.execution_nonce.as_bytes()))
        .and_then(|encoder| encoder.bytes(value.dispatch_core_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(value.dispatch_subject_digest.as_bytes()))
        .map_err(ProtocolError::malformed)?;
    minicbor::Encode::encode(&value.effect_started_receipt, &mut encoder, &mut ())
        .map_err(ProtocolError::malformed)?;
    encoder
        .bytes(value.effect_started_receipt_digest.as_bytes())
        .map_err(ProtocolError::malformed)?;
    encode_completion_descriptor(&mut encoder, value.completion)?;
    encode_completion_payload(&mut encoder, &value.payload)?;
    Ok(encoder.into_writer())
}

pub fn decode_fetch_completion_response_v2(
    bytes: &[u8],
) -> Result<FetchCompletionResponseV2, ProtocolError> {
    exact_decode(
        bytes,
        |decoder, context| {
            expect_array(decoder, 7)?;
            FetchCompletionResponseV2::new(
                Nonce32V2::new(decode_fixed::<32>(decoder)?),
                Digest32V2::new(decode_fixed::<32>(decoder)?),
                Digest32V2::new(decode_fixed::<32>(decoder)?),
                minicbor::Decode::decode(decoder, context)
                    .map_err(ProtocolError::from_typed_decode)?,
                Digest32V2::new(decode_fixed::<32>(decoder)?),
                decode_completion_descriptor(decoder, context)?,
                decode_completion_payload(decoder, context)?,
            )
        },
        encode_fetch_completion_response_v2,
    )
}

fn encode_executor_status(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    value: &ExecutorStatusV2,
) -> Result<(), ProtocolError> {
    match value {
        ExecutorStatusV2::Prepared => {
            encoder
                .array(1)
                .and_then(|encoder| encoder.u16(2))
                .map_err(ProtocolError::malformed)?;
        }
        ExecutorStatusV2::EffectStarted {
            effect_started_receipt,
            effect_started_receipt_digest,
        } => {
            encoder
                .array(3)
                .and_then(|encoder| encoder.u16(3))
                .map_err(ProtocolError::malformed)?;
            minicbor::Encode::encode(effect_started_receipt, encoder, &mut ())
                .map_err(ProtocolError::malformed)?;
            encoder
                .bytes(effect_started_receipt_digest.as_bytes())
                .map_err(ProtocolError::malformed)?;
        }
        ExecutorStatusV2::CompletionAvailable {
            effect_started_receipt,
            effect_started_receipt_digest,
            completion,
        } => {
            encoder
                .array(4)
                .and_then(|encoder| encoder.u16(4))
                .map_err(ProtocolError::malformed)?;
            minicbor::Encode::encode(effect_started_receipt, encoder, &mut ())
                .map_err(ProtocolError::malformed)?;
            encoder
                .bytes(effect_started_receipt_digest.as_bytes())
                .map_err(ProtocolError::malformed)?;
            encode_completion_descriptor(encoder, *completion)?;
        }
        ExecutorStatusV2::FailedNoEffect { class } => {
            encoder
                .array(2)
                .and_then(|encoder| encoder.u16(5))
                .and_then(|encoder| encoder.u16(class.tag()))
                .map_err(ProtocolError::malformed)?;
        }
        ExecutorStatusV2::Indeterminate {
            effect_started_receipt,
            effect_started_receipt_digest,
        } => {
            encoder
                .array(3)
                .and_then(|encoder| encoder.u16(6))
                .map_err(ProtocolError::malformed)?;
            encode_optional_receipt(encoder, effect_started_receipt.as_ref())
                .map_err(ProtocolError::malformed)?;
            encode_optional_digest(encoder, *effect_started_receipt_digest)
                .map_err(ProtocolError::malformed)?;
        }
        ExecutorStatusV2::Acknowledged => {
            encoder
                .array(1)
                .and_then(|encoder| encoder.u16(7))
                .map_err(ProtocolError::malformed)?;
        }
    }
    Ok(())
}

fn decode_executor_status(
    decoder: &mut minicbor::Decoder<'_>,
    context: &mut V2DecodeContext,
) -> Result<ExecutorStatusV2, ProtocolError> {
    let length = decoder
        .array()
        .map_err(ProtocolError::malformed)?
        .ok_or_else(malformed)?;
    let tag = decoder.u16().map_err(ProtocolError::malformed)?;
    match (tag, length) {
        (2, 1) => Ok(ExecutorStatusV2::Prepared),
        (3, 3) => ExecutorStatusV2::effect_started(
            minicbor::Decode::decode(decoder, context).map_err(ProtocolError::from_typed_decode)?,
            Digest32V2::new(decode_fixed::<32>(decoder)?),
        ),
        (4, 4) => ExecutorStatusV2::completion_available(
            minicbor::Decode::decode(decoder, context).map_err(ProtocolError::from_typed_decode)?,
            Digest32V2::new(decode_fixed::<32>(decoder)?),
            decode_completion_descriptor(decoder, context)?,
        ),
        (5, 2) => Ok(ExecutorStatusV2::FailedNoEffect {
            class: ExecutorFailureClassV2::from_tag(
                decoder.u16().map_err(ProtocolError::malformed)?,
            )?,
        }),
        (6, 3) => ExecutorStatusV2::indeterminate(
            decode_optional_receipt(decoder, context)?,
            decode_optional_digest(decoder)?,
        ),
        (7, 1) => Ok(ExecutorStatusV2::Acknowledged),
        _ => Err(malformed()),
    }
}

fn encode_completion_payload(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    value: &ExecutorCompletionPayloadV2,
) -> Result<(), ProtocolError> {
    match value {
        ExecutorCompletionPayloadV2::ToolResult { result } => encoder
            .array(2)
            .and_then(|encoder| encoder.u16(1))
            .and_then(|encoder| encoder.bytes(result.as_bytes()))
            .map(|_| ())
            .map_err(ProtocolError::malformed),
        ExecutorCompletionPayloadV2::FinalReleaseReceipt {
            receipt,
            provider_evidence,
            audit_evidence,
        } => {
            encoder
                .array(4)
                .and_then(|encoder| encoder.u16(2))
                .map_err(ProtocolError::malformed)?;
            minicbor::Encode::encode(receipt, encoder, &mut ())
                .map_err(ProtocolError::malformed)?;
            encoder
                .bytes(provider_evidence.as_bytes())
                .and_then(|encoder| encoder.bytes(audit_evidence.as_bytes()))
                .map(|_| ())
                .map_err(ProtocolError::malformed)
        }
    }
}

fn decode_completion_payload(
    decoder: &mut minicbor::Decoder<'_>,
    context: &mut V2DecodeContext,
) -> Result<ExecutorCompletionPayloadV2, ProtocolError> {
    let length = decoder
        .array()
        .map_err(ProtocolError::malformed)?
        .ok_or_else(malformed)?;
    let tag = decoder.u16().map_err(ProtocolError::malformed)?;
    match (tag, length) {
        (1, 2) => ExecutorCompletionPayloadV2::tool_result(
            decoder.bytes().map_err(ProtocolError::malformed)?.to_vec(),
        ),
        (2, 4) => ExecutorCompletionPayloadV2::final_release(
            minicbor::Decode::decode(decoder, context).map_err(ProtocolError::from_typed_decode)?,
            decoder.bytes().map_err(ProtocolError::malformed)?.to_vec(),
            ExecutorFinalReleaseAuditEvidenceV2::new(
                decoder.bytes().map_err(ProtocolError::malformed)?.to_vec(),
            )?,
        ),
        _ => Err(malformed()),
    }
}

fn payload_matches_descriptor(
    payload: &ExecutorCompletionPayloadV2,
    descriptor: ExecutorCompletionDescriptorV2,
) -> bool {
    match (payload, descriptor) {
        (
            ExecutorCompletionPayloadV2::ToolResult { result },
            ExecutorCompletionDescriptorV2::ToolResult {
                result_digest,
                encoded_length,
            },
        ) => {
            result.as_bytes().len() == encoded_length as usize
                && domain_digest(CONNECTOR_RESULT_DIGEST_DOMAIN_V2, result.as_bytes())
                    == result_digest
        }
        (
            ExecutorCompletionPayloadV2::FinalReleaseReceipt {
                receipt,
                provider_evidence: _,
                audit_evidence,
            },
            ExecutorCompletionDescriptorV2::FinalReleaseReceipt {
                durable_release_id,
                final_release_receipt_digest,
                release_audit_digest,
                encoded_length,
            },
        ) => {
            receipt.unsigned().durable_release_id() == durable_release_id
                && receipt.digest() == final_release_receipt_digest
                && receipt.unsigned().release_audit_digest() == release_audit_digest
                && audit_evidence.digest() == release_audit_digest
                && encode_executor_completion_payload_v2(payload)
                    .ok()
                    .and_then(|bytes| u32::try_from(bytes.len()).ok())
                    == Some(encoded_length)
        }
        _ => false,
    }
}

fn receipt_signature(
    domain: &[u8],
    payload: &[u8],
    signing_key: &SigningKey,
) -> Ed25519SignatureV2 {
    Ed25519SignatureV2::new(
        signing_key
            .sign(&receipt_signature_input(domain, payload))
            .to_bytes(),
    )
}

fn receipt_signature_input(domain: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut input = Vec::with_capacity(domain.len() + 32);
    input.extend_from_slice(domain);
    input.extend_from_slice(sha2::Sha256::digest(payload).as_slice());
    input
}

fn domain_digest(domain: &[u8], value: &[u8]) -> Digest32V2 {
    let mut hasher = sha2::Sha256::new();
    hasher.update(domain);
    hasher.update(value);
    Digest32V2::new(hasher.finalize().into())
}

fn encode_optional_receipt(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    value: Option<&SignedExecutorEffectStartedReceiptV2>,
) -> Result<(), minicbor::encode::Error<std::convert::Infallible>> {
    match value {
        Some(value) => minicbor::Encode::encode(value, encoder, &mut ()),
        None => encoder.null().map(|_| ()),
    }
}

fn decode_optional_receipt(
    decoder: &mut minicbor::Decoder<'_>,
    context: &mut V2DecodeContext,
) -> Result<Option<SignedExecutorEffectStartedReceiptV2>, ProtocolError> {
    if decoder.datatype().map_err(ProtocolError::malformed)? == minicbor::data::Type::Null {
        decoder.null().map_err(ProtocolError::malformed)?;
        Ok(None)
    } else {
        minicbor::Decode::decode(decoder, context)
            .map(Some)
            .map_err(ProtocolError::from_typed_decode)
    }
}

fn encode_optional_digest(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    value: Option<Digest32V2>,
) -> Result<&mut minicbor::Encoder<Vec<u8>>, minicbor::encode::Error<std::convert::Infallible>> {
    match value {
        Some(value) => encoder.bytes(value.as_bytes()),
        None => encoder.null(),
    }
}

fn decode_optional_digest(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<Option<Digest32V2>, ProtocolError> {
    if decoder.datatype().map_err(ProtocolError::malformed)? == minicbor::data::Type::Null {
        decoder.null().map_err(ProtocolError::malformed)?;
        Ok(None)
    } else {
        Ok(Some(Digest32V2::new(decode_fixed::<32>(decoder)?)))
    }
}

fn encode_optional_public_error(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    value: Option<PublicStableCodeV2>,
) -> Result<(), ProtocolError> {
    match value {
        Some(value) => encoder
            .u16(value.tag())
            .map(|_| ())
            .map_err(ProtocolError::malformed),
        None => encoder.null().map(|_| ()).map_err(ProtocolError::malformed),
    }
}

fn decode_optional_public_error(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<Option<PublicStableCodeV2>, ProtocolError> {
    if decoder.datatype().map_err(ProtocolError::malformed)? == minicbor::data::Type::Null {
        decoder.null().map_err(ProtocolError::malformed)?;
        Ok(None)
    } else {
        PublicStableCodeV2::from_tag(decoder.u16().map_err(ProtocolError::malformed)?).map(Some)
    }
}

fn exact_decode<T>(
    bytes: &[u8],
    decode: impl FnOnce(&mut minicbor::Decoder<'_>, &mut V2DecodeContext) -> Result<T, ProtocolError>,
    encode: impl FnOnce(&T) -> Result<Vec<u8>, ProtocolError>,
) -> Result<T, ProtocolError> {
    scan_single(bytes)?;
    let mut decoder = minicbor::Decoder::new(bytes);
    let mut context = V2DecodeContext;
    let value = decode(&mut decoder, &mut context)?;
    if decoder.position() != bytes.len() || encode(&value)? != bytes {
        return Err(malformed());
    }
    Ok(value)
}

fn encode_exact<T: minicbor::Encode<()>>(value: &T) -> Result<Vec<u8>, ProtocolError> {
    minicbor::to_vec(value).map_err(ProtocolError::malformed)
}

fn decode_exact<T>(bytes: &[u8]) -> Result<T, ProtocolError>
where
    for<'bytes> T: minicbor::Decode<'bytes, V2DecodeContext> + minicbor::Encode<()>,
{
    scan_single(bytes)?;
    let mut decoder = minicbor::Decoder::new(bytes);
    let mut context = V2DecodeContext;
    let value = T::decode(&mut decoder, &mut context).map_err(ProtocolError::from_typed_decode)?;
    if decoder.position() != bytes.len() || encode_exact(&value)? != bytes {
        return Err(malformed());
    }
    Ok(value)
}

fn expect_array(decoder: &mut minicbor::Decoder<'_>, expected: u64) -> Result<(), ProtocolError> {
    if decoder.array().map_err(ProtocolError::malformed)? != Some(expected) {
        return Err(malformed());
    }
    Ok(())
}

fn decode_fixed<const N: usize>(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<[u8; N], ProtocolError> {
    decoder
        .bytes()
        .map_err(ProtocolError::malformed)?
        .try_into()
        .map_err(ProtocolError::malformed)
}

fn malformed() -> ProtocolError {
    ProtocolError::stable(StableCode::ProtocolMalformedCbor)
}

fn decode_error(position: usize) -> minicbor::decode::Error {
    minicbor::decode::Error::message(StableCode::ProtocolMalformedCbor.as_str()).at(position)
}
