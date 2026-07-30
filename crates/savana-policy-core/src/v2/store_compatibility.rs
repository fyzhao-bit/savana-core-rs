use savana_kernel_protocol::v2::{Digest32V2, Ed25519KeyIdV2, Ed25519SignatureV2};
use savana_platform_identity::{
    NativeDeploymentSignatureDomainV2, NativeDeploymentSignatureRequestV2,
    NativeDeploymentSigningAuthorityV2,
};
use sha2::{Digest as _, Sha256};

use super::{DeploymentActivationVerifierV2, DeploymentControlErrorV2};

const STORE_COMPATIBILITY_SCHEMA_VERSION_V2: u16 = 2;
const COMPLETE_FIELDS_V2: u64 = 15;
const PAYLOAD_FIELDS_V2: u64 = 14;
const SIGNATURE_FIELDS_V2: u64 = 4;
const STORE_COMPATIBILITY_SIGNATURE_TAG_V2: u16 = 8;
const STORE_COMPATIBILITY_PAYLOAD_DOMAIN_V2: &[u8] = b"savana.store-compatibility.v2.payload\0";
const STORE_COMPATIBILITY_SIGNATURE_DOMAIN_V2: &[u8] = b"savana.store-compatibility.v2.signature\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryValidationResultV2 {
    NormalRollbackManifest {
        rollback_copy_validation_result_digest: Digest32V2,
    },
    BootstrapBridgeRestore {
        unchanged_store_and_journal_integrity_result_digest: Digest32V2,
        native_effect_fence_measurement_digest: Digest32V2,
    },
}

impl RecoveryValidationResultV2 {
    const fn tag(self) -> u16 {
        match self {
            Self::NormalRollbackManifest { .. } => 1,
            Self::BootstrapBridgeRestore { .. } => 2,
        }
    }

    fn validate(self) -> Result<(), DeploymentControlErrorV2> {
        let invalid = match self {
            Self::NormalRollbackManifest {
                rollback_copy_validation_result_digest,
            } => is_zero(rollback_copy_validation_result_digest.as_bytes()),
            Self::BootstrapBridgeRestore {
                unchanged_store_and_journal_integrity_result_digest,
                native_effect_fence_measurement_digest,
            } => {
                is_zero(unchanged_store_and_journal_integrity_result_digest.as_bytes())
                    || is_zero(native_effect_fence_measurement_digest.as_bytes())
            }
        };
        if invalid {
            Err(DeploymentControlErrorV2::InvalidStoreCompatibilityAttestation)
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StoreCompatibilitySignatureV2 {
    domain_tag: u16,
    signer_key_id: Ed25519KeyIdV2,
    signer_key_epoch: u64,
    signature: Ed25519SignatureV2,
}

#[derive(Clone, PartialEq, Eq)]
pub struct StoreCompatibilityAttestationV2 {
    canonical_bytes: Vec<u8>,
    transaction_intent_digest: Digest32V2,
    installation_id: Digest32V2,
    installation_epoch: u64,
    ledger_generation: u64,
    manifest_digest: Digest32V2,
    logical_data_origin_manifest_digest: Digest32V2,
    recovery_target_digest: Digest32V2,
    actual_store_state_set_digest: Digest32V2,
    desired_copy_validation_result_digest: Digest32V2,
    recovery_validation_result: RecoveryValidationResultV2,
    migration_simulation_result_digest: Digest32V2,
    validator_set_digest: Digest32V2,
    completed_at_unix_ms: u64,
    activation_key_id: Ed25519KeyIdV2,
    payload_digest: Digest32V2,
}

impl std::fmt::Debug for StoreCompatibilityAttestationV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StoreCompatibilityAttestationV2")
            .field("ledger_generation", &self.ledger_generation)
            .field("completed_at_unix_ms", &self.completed_at_unix_ms)
            .field("payload_digest", &self.payload_digest)
            .finish_non_exhaustive()
    }
}

impl StoreCompatibilityAttestationV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn new_signed_with_authority(
        transaction_intent_digest: Digest32V2,
        installation_id: Digest32V2,
        ledger_generation: u64,
        manifest_digest: Digest32V2,
        logical_data_origin_manifest_digest: Digest32V2,
        recovery_target_digest: Digest32V2,
        actual_store_state_set_digest: Digest32V2,
        desired_copy_validation_result_digest: Digest32V2,
        recovery_validation_result: RecoveryValidationResultV2,
        migration_simulation_result_digest: Digest32V2,
        validator_set_digest: Digest32V2,
        completed_at_unix_ms: u64,
        authority: &mut dyn NativeDeploymentSigningAuthorityV2,
        verifier: &DeploymentActivationVerifierV2,
    ) -> Result<Self, DeploymentControlErrorV2> {
        let activation_key_id = Ed25519KeyIdV2::new(authority.key_id());
        if authority.installation_id() != *installation_id.as_bytes()
            || authority.key_epoch() != verifier.key_epoch()
            || verifier.installation_id() != installation_id
            || verifier.key_id() != activation_key_id
        {
            return Err(DeploymentControlErrorV2::ActivationKeyMismatch);
        }
        let mut decoded = DecodedStoreCompatibilityAttestationV2 {
            schema_version: STORE_COMPATIBILITY_SCHEMA_VERSION_V2,
            transaction_intent_digest,
            installation_id,
            ledger_generation,
            manifest_digest,
            logical_data_origin_manifest_digest,
            recovery_target_digest,
            actual_store_state_set_digest,
            desired_copy_validation_result_digest,
            recovery_validation_result,
            migration_simulation_result_digest,
            validator_set_digest,
            completed_at_unix_ms,
            activation_key_id,
            signature: StoreCompatibilitySignatureV2 {
                domain_tag: STORE_COMPATIBILITY_SIGNATURE_TAG_V2,
                signer_key_id: activation_key_id,
                signer_key_epoch: authority.key_epoch(),
                signature: Ed25519SignatureV2::new([1; 64]),
            },
        };
        decoded.validate_shape(verifier)?;
        let payload_digest = hash_domain(
            STORE_COMPATIBILITY_PAYLOAD_DOMAIN_V2,
            &encode_payload(&decoded)?,
        );
        let request = NativeDeploymentSignatureRequestV2::new(
            NativeDeploymentSignatureDomainV2::StoreCompatibility,
            *installation_id.as_bytes(),
            authority.key_epoch(),
            *payload_digest.as_bytes(),
        )
        .map_err(|_| DeploymentControlErrorV2::NativeSigningAuthorityUnavailable)?;
        decoded.signature.signature = Ed25519SignatureV2::new(
            authority
                .sign(request)
                .map_err(|_| DeploymentControlErrorV2::NativeSigningAuthorityUnavailable)?,
        );
        Self::from_canonical_bytes(&encode_complete(&decoded)?, verifier)
    }

    pub fn from_canonical_bytes(
        bytes: &[u8],
        verifier: &DeploymentActivationVerifierV2,
    ) -> Result<Self, DeploymentControlErrorV2> {
        if bytes.is_empty() || bytes.len() > 4096 {
            return Err(DeploymentControlErrorV2::InvalidStoreCompatibilityAttestation);
        }
        let decoded = decode_complete(bytes)?;
        decoded.validate_shape(verifier)?;
        if encode_complete(&decoded)? != bytes {
            return Err(DeploymentControlErrorV2::NonCanonicalLedgerEncoding);
        }
        let payload_digest = hash_domain(
            STORE_COMPATIBILITY_PAYLOAD_DOMAIN_V2,
            &encode_payload(&decoded)?,
        );
        verifier.verify_domain_signature_parts(
            decoded.signature.domain_tag,
            decoded.signature.signer_key_id,
            decoded.signature.signer_key_epoch,
            decoded.signature.signature,
            STORE_COMPATIBILITY_SIGNATURE_TAG_V2,
            STORE_COMPATIBILITY_SIGNATURE_DOMAIN_V2,
            payload_digest,
        )?;
        Ok(Self {
            canonical_bytes: bytes.to_vec(),
            transaction_intent_digest: decoded.transaction_intent_digest,
            installation_id: decoded.installation_id,
            installation_epoch: decoded.signature.signer_key_epoch,
            ledger_generation: decoded.ledger_generation,
            manifest_digest: decoded.manifest_digest,
            logical_data_origin_manifest_digest: decoded.logical_data_origin_manifest_digest,
            recovery_target_digest: decoded.recovery_target_digest,
            actual_store_state_set_digest: decoded.actual_store_state_set_digest,
            desired_copy_validation_result_digest: decoded.desired_copy_validation_result_digest,
            recovery_validation_result: decoded.recovery_validation_result,
            migration_simulation_result_digest: decoded.migration_simulation_result_digest,
            validator_set_digest: decoded.validator_set_digest,
            completed_at_unix_ms: decoded.completed_at_unix_ms,
            activation_key_id: decoded.activation_key_id,
            payload_digest,
        })
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub const fn transaction_intent_digest(&self) -> Digest32V2 {
        self.transaction_intent_digest
    }

    pub const fn installation_id(&self) -> Digest32V2 {
        self.installation_id
    }

    pub const fn installation_epoch(&self) -> u64 {
        self.installation_epoch
    }

    pub const fn ledger_generation(&self) -> u64 {
        self.ledger_generation
    }

    pub const fn manifest_digest(&self) -> Digest32V2 {
        self.manifest_digest
    }

    pub const fn logical_data_origin_manifest_digest(&self) -> Digest32V2 {
        self.logical_data_origin_manifest_digest
    }

    pub const fn recovery_target_digest(&self) -> Digest32V2 {
        self.recovery_target_digest
    }

    pub const fn actual_store_state_set_digest(&self) -> Digest32V2 {
        self.actual_store_state_set_digest
    }

    pub const fn desired_copy_validation_result_digest(&self) -> Digest32V2 {
        self.desired_copy_validation_result_digest
    }

    pub const fn recovery_validation_result(&self) -> RecoveryValidationResultV2 {
        self.recovery_validation_result
    }

    pub const fn migration_simulation_result_digest(&self) -> Digest32V2 {
        self.migration_simulation_result_digest
    }

    pub const fn validator_set_digest(&self) -> Digest32V2 {
        self.validator_set_digest
    }

    pub const fn completed_at_unix_ms(&self) -> u64 {
        self.completed_at_unix_ms
    }

    pub const fn activation_key_id(&self) -> Ed25519KeyIdV2 {
        self.activation_key_id
    }

    pub const fn payload_digest(&self) -> Digest32V2 {
        self.payload_digest
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DecodedStoreCompatibilityAttestationV2 {
    schema_version: u16,
    transaction_intent_digest: Digest32V2,
    installation_id: Digest32V2,
    ledger_generation: u64,
    manifest_digest: Digest32V2,
    logical_data_origin_manifest_digest: Digest32V2,
    recovery_target_digest: Digest32V2,
    actual_store_state_set_digest: Digest32V2,
    desired_copy_validation_result_digest: Digest32V2,
    recovery_validation_result: RecoveryValidationResultV2,
    migration_simulation_result_digest: Digest32V2,
    validator_set_digest: Digest32V2,
    completed_at_unix_ms: u64,
    activation_key_id: Ed25519KeyIdV2,
    signature: StoreCompatibilitySignatureV2,
}

impl DecodedStoreCompatibilityAttestationV2 {
    fn validate_shape(
        &self,
        verifier: &DeploymentActivationVerifierV2,
    ) -> Result<(), DeploymentControlErrorV2> {
        if self.schema_version != STORE_COMPATIBILITY_SCHEMA_VERSION_V2
            || self.installation_id != verifier.installation_id()
            || self.activation_key_id != verifier.key_id()
            || self.signature.domain_tag != STORE_COMPATIBILITY_SIGNATURE_TAG_V2
            || self.signature.signer_key_id != self.activation_key_id
            || self.signature.signer_key_epoch != verifier.key_epoch()
            || self.ledger_generation == 0
            || self.completed_at_unix_ms == 0
            || [
                self.transaction_intent_digest.as_bytes(),
                self.installation_id.as_bytes(),
                self.manifest_digest.as_bytes(),
                self.logical_data_origin_manifest_digest.as_bytes(),
                self.recovery_target_digest.as_bytes(),
                self.actual_store_state_set_digest.as_bytes(),
                self.desired_copy_validation_result_digest.as_bytes(),
                self.migration_simulation_result_digest.as_bytes(),
                self.validator_set_digest.as_bytes(),
            ]
            .iter()
            .any(|value| is_zero(*value))
            || is_zero(self.signature.signature.as_bytes())
        {
            return Err(DeploymentControlErrorV2::InvalidStoreCompatibilityAttestation);
        }
        self.recovery_validation_result.validate()
    }
}

fn encode_payload(
    value: &DecodedStoreCompatibilityAttestationV2,
) -> Result<Vec<u8>, DeploymentControlErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encode_fields(&mut encoder, value, PAYLOAD_FIELDS_V2)?;
    Ok(encoder.into_writer())
}

fn encode_complete(
    value: &DecodedStoreCompatibilityAttestationV2,
) -> Result<Vec<u8>, DeploymentControlErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encode_fields(&mut encoder, value, COMPLETE_FIELDS_V2)?;
    encode_signature(&mut encoder, value.signature)?;
    Ok(encoder.into_writer())
}

fn encode_fields(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    value: &DecodedStoreCompatibilityAttestationV2,
    count: u64,
) -> Result<(), DeploymentControlErrorV2> {
    encoder
        .array(count)
        .and_then(|encoder| encoder.u16(value.schema_version))
        .and_then(|encoder| encoder.bytes(value.transaction_intent_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(value.installation_id.as_bytes()))
        .and_then(|encoder| encoder.u64(value.ledger_generation))
        .and_then(|encoder| encoder.bytes(value.manifest_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(value.logical_data_origin_manifest_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(value.recovery_target_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(value.actual_store_state_set_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(value.desired_copy_validation_result_digest.as_bytes()))
        .map_err(|_| DeploymentControlErrorV2::InvalidStoreCompatibilityAttestation)?;
    encode_recovery_result(encoder, value.recovery_validation_result)?;
    encoder
        .bytes(value.migration_simulation_result_digest.as_bytes())
        .and_then(|encoder| encoder.bytes(value.validator_set_digest.as_bytes()))
        .and_then(|encoder| encoder.u64(value.completed_at_unix_ms))
        .and_then(|encoder| encoder.bytes(value.activation_key_id.as_bytes()))
        .map_err(|_| DeploymentControlErrorV2::InvalidStoreCompatibilityAttestation)?;
    Ok(())
}

fn encode_recovery_result(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    value: RecoveryValidationResultV2,
) -> Result<(), DeploymentControlErrorV2> {
    match value {
        RecoveryValidationResultV2::NormalRollbackManifest {
            rollback_copy_validation_result_digest,
        } => encoder
            .array(2)
            .and_then(|encoder| encoder.u16(value.tag()))
            .and_then(|encoder| encoder.bytes(rollback_copy_validation_result_digest.as_bytes())),
        RecoveryValidationResultV2::BootstrapBridgeRestore {
            unchanged_store_and_journal_integrity_result_digest,
            native_effect_fence_measurement_digest,
        } => encoder
            .array(3)
            .and_then(|encoder| encoder.u16(value.tag()))
            .and_then(|encoder| {
                encoder.bytes(unchanged_store_and_journal_integrity_result_digest.as_bytes())
            })
            .and_then(|encoder| encoder.bytes(native_effect_fence_measurement_digest.as_bytes())),
    }
    .map_err(|_| DeploymentControlErrorV2::InvalidStoreCompatibilityAttestation)?;
    Ok(())
}

fn encode_signature(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    value: StoreCompatibilitySignatureV2,
) -> Result<(), DeploymentControlErrorV2> {
    encoder
        .array(SIGNATURE_FIELDS_V2)
        .and_then(|encoder| encoder.u16(value.domain_tag))
        .and_then(|encoder| encoder.bytes(value.signer_key_id.as_bytes()))
        .and_then(|encoder| encoder.u64(value.signer_key_epoch))
        .and_then(|encoder| encoder.bytes(value.signature.as_bytes()))
        .map_err(|_| DeploymentControlErrorV2::InvalidStoreCompatibilityAttestation)?;
    Ok(())
}

fn decode_complete(
    bytes: &[u8],
) -> Result<DecodedStoreCompatibilityAttestationV2, DeploymentControlErrorV2> {
    let mut decoder = minicbor::Decoder::new(bytes);
    expect_array(&mut decoder, COMPLETE_FIELDS_V2)?;
    let value = DecodedStoreCompatibilityAttestationV2 {
        schema_version: decode_u16(&mut decoder)?,
        transaction_intent_digest: decode_digest(&mut decoder)?,
        installation_id: decode_digest(&mut decoder)?,
        ledger_generation: decode_u64(&mut decoder)?,
        manifest_digest: decode_digest(&mut decoder)?,
        logical_data_origin_manifest_digest: decode_digest(&mut decoder)?,
        recovery_target_digest: decode_digest(&mut decoder)?,
        actual_store_state_set_digest: decode_digest(&mut decoder)?,
        desired_copy_validation_result_digest: decode_digest(&mut decoder)?,
        recovery_validation_result: decode_recovery_result(&mut decoder)?,
        migration_simulation_result_digest: decode_digest(&mut decoder)?,
        validator_set_digest: decode_digest(&mut decoder)?,
        completed_at_unix_ms: decode_u64(&mut decoder)?,
        activation_key_id: decode_key_id(&mut decoder)?,
        signature: decode_signature(&mut decoder)?,
    };
    if decoder.position() != bytes.len() {
        return Err(DeploymentControlErrorV2::InvalidStoreCompatibilityAttestation);
    }
    Ok(value)
}

fn decode_recovery_result(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<RecoveryValidationResultV2, DeploymentControlErrorV2> {
    let length = decoder
        .array()
        .map_err(|_| DeploymentControlErrorV2::InvalidStoreCompatibilityAttestation)?
        .ok_or(DeploymentControlErrorV2::InvalidStoreCompatibilityAttestation)?;
    let tag = decode_u16(decoder)?;
    match (tag, length) {
        (1, 2) => Ok(RecoveryValidationResultV2::NormalRollbackManifest {
            rollback_copy_validation_result_digest: decode_digest(decoder)?,
        }),
        (2, 3) => Ok(RecoveryValidationResultV2::BootstrapBridgeRestore {
            unchanged_store_and_journal_integrity_result_digest: decode_digest(decoder)?,
            native_effect_fence_measurement_digest: decode_digest(decoder)?,
        }),
        _ => Err(DeploymentControlErrorV2::InvalidStoreCompatibilityAttestation),
    }
}

fn decode_signature(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<StoreCompatibilitySignatureV2, DeploymentControlErrorV2> {
    expect_array(decoder, SIGNATURE_FIELDS_V2)?;
    Ok(StoreCompatibilitySignatureV2 {
        domain_tag: decode_u16(decoder)?,
        signer_key_id: decode_key_id(decoder)?,
        signer_key_epoch: decode_u64(decoder)?,
        signature: Ed25519SignatureV2::new(decode_fixed::<64>(decoder)?),
    })
}

fn expect_array(
    decoder: &mut minicbor::Decoder<'_>,
    expected: u64,
) -> Result<(), DeploymentControlErrorV2> {
    if decoder
        .array()
        .map_err(|_| DeploymentControlErrorV2::InvalidStoreCompatibilityAttestation)?
        != Some(expected)
    {
        return Err(DeploymentControlErrorV2::InvalidStoreCompatibilityAttestation);
    }
    Ok(())
}

fn decode_u16(decoder: &mut minicbor::Decoder<'_>) -> Result<u16, DeploymentControlErrorV2> {
    decoder
        .u16()
        .map_err(|_| DeploymentControlErrorV2::InvalidStoreCompatibilityAttestation)
}

fn decode_u64(decoder: &mut minicbor::Decoder<'_>) -> Result<u64, DeploymentControlErrorV2> {
    decoder
        .u64()
        .map_err(|_| DeploymentControlErrorV2::InvalidStoreCompatibilityAttestation)
}

fn decode_digest(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<Digest32V2, DeploymentControlErrorV2> {
    Ok(Digest32V2::new(decode_fixed::<32>(decoder)?))
}

fn decode_key_id(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<Ed25519KeyIdV2, DeploymentControlErrorV2> {
    Ok(Ed25519KeyIdV2::new(decode_fixed::<32>(decoder)?))
}

fn decode_fixed<const N: usize>(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<[u8; N], DeploymentControlErrorV2> {
    let bytes = decoder
        .bytes()
        .map_err(|_| DeploymentControlErrorV2::InvalidStoreCompatibilityAttestation)?;
    bytes
        .try_into()
        .map_err(|_| DeploymentControlErrorV2::InvalidStoreCompatibilityAttestation)
}

fn hash_domain(domain: &[u8], bytes: &[u8]) -> Digest32V2 {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(bytes);
    Digest32V2::new(hasher.finalize().into())
}

fn is_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}
