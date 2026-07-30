use savana_kernel_protocol::v2::{Digest32V2, Ed25519KeyIdV2, Ed25519SignatureV2, Nonce32V2};
use savana_platform_identity::{
    NativeDeploymentSignatureDomainV2, NativeDeploymentSignatureRequestV2,
    NativeDeploymentSigningAuthorityV2,
};
use sha2::{Digest as _, Sha256};

use super::{
    ArtifactIdentityV2, ClosedArtifactTypeV2, DeploymentActivationVerifierV2,
    DeploymentControlErrorV2, PlatformLockV2, RollbackOriginPhaseV2,
};

const SCHEMA_VERSION: u16 = 2;
const COMPLETE_FIELDS: u64 = 32;
const PAYLOAD_FIELDS: u64 = 31;
const SIGNATURE_FIELDS: u64 = 4;
const SIGNATURE_TAG: u16 = 27;
const PAYLOAD_DOMAIN: &[u8] = b"savana.recovery-rollback-readiness.v2.payload\0";
const SIGNATURE_DOMAIN: &[u8] = b"savana.recovery-rollback-readiness.v2.signature\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u16)]
pub enum ClosedRecoveryRollbackDigestFieldV2 {
    EvidenceTrustPolicy = 1,
    EvidenceLayerLimits = 2,
    SourceEvidence = 3,
    ArtifactEvidence = 4,
    InstallationId = 5,
    TransactionIntent = 6,
    TransactionPayload = 7,
    AttemptedManifest = 8,
    RollbackManifest = 9,
    HighestEver = 10,
    RollbackGrant = 11,
    RollbackStoreCompatibilityAttestation = 12,
    RollbackNativeControlMeasurementSet = 13,
    RollbackEffectFenceResult = 14,
    RollbackServiceReadinessResult = 15,
    RollbackRecoveryResult = 16,
    RollbackLegacyAbsenceResult = 17,
    RoleJournalReconciliation = 18,
}

impl ClosedRecoveryRollbackDigestFieldV2 {
    pub const ALL: [Self; 18] = [
        Self::EvidenceTrustPolicy,
        Self::EvidenceLayerLimits,
        Self::SourceEvidence,
        Self::ArtifactEvidence,
        Self::InstallationId,
        Self::TransactionIntent,
        Self::TransactionPayload,
        Self::AttemptedManifest,
        Self::RollbackManifest,
        Self::HighestEver,
        Self::RollbackGrant,
        Self::RollbackStoreCompatibilityAttestation,
        Self::RollbackNativeControlMeasurementSet,
        Self::RollbackEffectFenceResult,
        Self::RollbackServiceReadinessResult,
        Self::RollbackRecoveryResult,
        Self::RollbackLegacyAbsenceResult,
        Self::RoleJournalReconciliation,
    ];

    const fn index(self) -> usize {
        self as usize - 1
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryRollbackOriginMeasurementsV2 {
    Armed {
        armed_ledger_record_digest: Digest32V2,
        frozen_effect_work_set_digest: Digest32V2,
        os_effect_deny_measurement_digest: Digest32V2,
    },
    Quiesced {
        quiesced_ledger_record_digest: Digest32V2,
        frozen_effect_work_set_digest: Digest32V2,
        role_journal_reconciliation_digest: Digest32V2,
    },
    Installed {
        installed_ledger_record_digest: Digest32V2,
        attempted_file_tree_root: Digest32V2,
        attempted_store_migration_result_digest: Digest32V2,
        role_journal_reconciliation_digest: Digest32V2,
    },
}

impl RecoveryRollbackOriginMeasurementsV2 {
    pub const fn origin_phase(self) -> RollbackOriginPhaseV2 {
        match self {
            Self::Armed { .. } => RollbackOriginPhaseV2::Armed,
            Self::Quiesced { .. } => RollbackOriginPhaseV2::Quiesced,
            Self::Installed { .. } => RollbackOriginPhaseV2::Installed,
        }
    }

    fn validate(
        self,
        outer_role_journal_digest: Digest32V2,
    ) -> Result<(), DeploymentControlErrorV2> {
        let valid = match self {
            Self::Armed {
                armed_ledger_record_digest,
                frozen_effect_work_set_digest,
                os_effect_deny_measurement_digest,
            } => [
                armed_ledger_record_digest,
                frozen_effect_work_set_digest,
                os_effect_deny_measurement_digest,
            ]
            .iter()
            .all(|value| !is_zero(value.as_bytes())),
            Self::Quiesced {
                quiesced_ledger_record_digest,
                frozen_effect_work_set_digest,
                role_journal_reconciliation_digest,
            } => {
                role_journal_reconciliation_digest == outer_role_journal_digest
                    && [
                        quiesced_ledger_record_digest,
                        frozen_effect_work_set_digest,
                        role_journal_reconciliation_digest,
                    ]
                    .iter()
                    .all(|value| !is_zero(value.as_bytes()))
            }
            Self::Installed {
                installed_ledger_record_digest,
                attempted_file_tree_root,
                attempted_store_migration_result_digest,
                role_journal_reconciliation_digest,
            } => {
                role_journal_reconciliation_digest == outer_role_journal_digest
                    && [
                        installed_ledger_record_digest,
                        attempted_file_tree_root,
                        attempted_store_migration_result_digest,
                        role_journal_reconciliation_digest,
                    ]
                    .iter()
                    .all(|value| !is_zero(value.as_bytes()))
            }
        };
        if !valid {
            return Err(DeploymentControlErrorV2::InvalidRecoveryRollbackReadinessEvidence);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EvidenceSignature {
    domain_tag: u16,
    key_id: Ed25519KeyIdV2,
    key_epoch: u64,
    signature: Ed25519SignatureV2,
}

#[derive(Clone, PartialEq, Eq)]
pub struct RecoveryRollbackReadinessEvidenceV2 {
    canonical_bytes: Vec<u8>,
    digests: [Digest32V2; 18],
    installation_epoch: u64,
    platform: PlatformLockV2,
    transaction_id: Nonce32V2,
    origin_measurements: RecoveryRollbackOriginMeasurementsV2,
    rollback_installed_ledger_generation: u64,
    rollback_installed_effect_fence_epoch: u64,
    verified_at_unix_ms: u64,
    helper_identity: ArtifactIdentityV2,
    watchdog_identity: ArtifactIdentityV2,
    activation_key_id: Ed25519KeyIdV2,
    payload_digest: Digest32V2,
}

impl std::fmt::Debug for RecoveryRollbackReadinessEvidenceV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RecoveryRollbackReadinessEvidenceV2")
            .field("rollback_origin_phase", &self.rollback_origin_phase())
            .field(
                "rollback_installed_ledger_generation",
                &self.rollback_installed_ledger_generation,
            )
            .field("verified_at_unix_ms", &self.verified_at_unix_ms)
            .field("payload_digest", &self.payload_digest)
            .finish_non_exhaustive()
    }
}

impl RecoveryRollbackReadinessEvidenceV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn new_signed_with_authority(
        digests: [Digest32V2; 18],
        installation_epoch: u64,
        platform: PlatformLockV2,
        transaction_id: Nonce32V2,
        origin_measurements: RecoveryRollbackOriginMeasurementsV2,
        rollback_installed_ledger_generation: u64,
        rollback_installed_effect_fence_epoch: u64,
        verified_at_unix_ms: u64,
        helper_identity: ArtifactIdentityV2,
        watchdog_identity: ArtifactIdentityV2,
        authority: &mut dyn NativeDeploymentSigningAuthorityV2,
        verifier: &DeploymentActivationVerifierV2,
    ) -> Result<Self, DeploymentControlErrorV2> {
        let installation_id = digests[ClosedRecoveryRollbackDigestFieldV2::InstallationId.index()];
        let activation_key_id = Ed25519KeyIdV2::new(authority.key_id());
        if authority.installation_id() != *installation_id.as_bytes()
            || authority.key_epoch() != installation_epoch
            || verifier.installation_id() != installation_id
            || verifier.key_epoch() != installation_epoch
            || verifier.key_id() != activation_key_id
        {
            return Err(DeploymentControlErrorV2::ActivationKeyMismatch);
        }
        let mut decoded = Decoded {
            schema_version: SCHEMA_VERSION,
            digests,
            installation_epoch,
            platform,
            transaction_id,
            origin_measurements,
            rollback_installed_ledger_generation,
            rollback_installed_effect_fence_epoch,
            verified_at_unix_ms,
            helper_identity,
            watchdog_identity,
            activation_key_id,
            signature: EvidenceSignature {
                domain_tag: SIGNATURE_TAG,
                key_id: activation_key_id,
                key_epoch: installation_epoch,
                signature: Ed25519SignatureV2::new([1; 64]),
            },
        };
        decoded.validate(verifier)?;
        let payload_digest = hash_domain(PAYLOAD_DOMAIN, &encode_payload(&decoded)?);
        let request = NativeDeploymentSignatureRequestV2::new(
            NativeDeploymentSignatureDomainV2::RecoveryRollbackReadinessEvidence,
            *installation_id.as_bytes(),
            installation_epoch,
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
        if bytes.is_empty() || bytes.len() > 16 * 1024 {
            return Err(DeploymentControlErrorV2::InvalidRecoveryRollbackReadinessEvidence);
        }
        let decoded = decode_complete(bytes)?;
        decoded.validate(verifier)?;
        if encode_complete(&decoded)? != bytes {
            return Err(DeploymentControlErrorV2::NonCanonicalLedgerEncoding);
        }
        let payload_digest = hash_domain(PAYLOAD_DOMAIN, &encode_payload(&decoded)?);
        verifier.verify_domain_signature_parts(
            decoded.signature.domain_tag,
            decoded.signature.key_id,
            decoded.signature.key_epoch,
            decoded.signature.signature,
            SIGNATURE_TAG,
            SIGNATURE_DOMAIN,
            payload_digest,
        )?;
        Ok(Self {
            canonical_bytes: bytes.to_vec(),
            digests: decoded.digests,
            installation_epoch: decoded.installation_epoch,
            platform: decoded.platform,
            transaction_id: decoded.transaction_id,
            origin_measurements: decoded.origin_measurements,
            rollback_installed_ledger_generation: decoded.rollback_installed_ledger_generation,
            rollback_installed_effect_fence_epoch: decoded.rollback_installed_effect_fence_epoch,
            verified_at_unix_ms: decoded.verified_at_unix_ms,
            helper_identity: decoded.helper_identity,
            watchdog_identity: decoded.watchdog_identity,
            activation_key_id: decoded.activation_key_id,
            payload_digest,
        })
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub const fn digest_field(&self, field: ClosedRecoveryRollbackDigestFieldV2) -> Digest32V2 {
        self.digests[field.index()]
    }

    pub const fn installation_id(&self) -> Digest32V2 {
        self.digest_field(ClosedRecoveryRollbackDigestFieldV2::InstallationId)
    }

    pub const fn installation_epoch(&self) -> u64 {
        self.installation_epoch
    }

    pub const fn platform(&self) -> &PlatformLockV2 {
        &self.platform
    }

    pub const fn transaction_id(&self) -> Nonce32V2 {
        self.transaction_id
    }

    pub const fn rollback_origin_phase(&self) -> RollbackOriginPhaseV2 {
        self.origin_measurements.origin_phase()
    }

    pub const fn origin_measurements(&self) -> RecoveryRollbackOriginMeasurementsV2 {
        self.origin_measurements
    }

    pub const fn rollback_installed_ledger_generation(&self) -> u64 {
        self.rollback_installed_ledger_generation
    }

    pub const fn rollback_installed_effect_fence_epoch(&self) -> u64 {
        self.rollback_installed_effect_fence_epoch
    }

    pub const fn verified_at_unix_ms(&self) -> u64 {
        self.verified_at_unix_ms
    }

    pub const fn helper_identity(&self) -> &ArtifactIdentityV2 {
        &self.helper_identity
    }

    pub const fn watchdog_identity(&self) -> &ArtifactIdentityV2 {
        &self.watchdog_identity
    }

    pub const fn activation_key_id(&self) -> Ed25519KeyIdV2 {
        self.activation_key_id
    }

    pub const fn payload_digest(&self) -> Digest32V2 {
        self.payload_digest
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Decoded {
    schema_version: u16,
    digests: [Digest32V2; 18],
    installation_epoch: u64,
    platform: PlatformLockV2,
    transaction_id: Nonce32V2,
    origin_measurements: RecoveryRollbackOriginMeasurementsV2,
    rollback_installed_ledger_generation: u64,
    rollback_installed_effect_fence_epoch: u64,
    verified_at_unix_ms: u64,
    helper_identity: ArtifactIdentityV2,
    watchdog_identity: ArtifactIdentityV2,
    activation_key_id: Ed25519KeyIdV2,
    signature: EvidenceSignature,
}

impl Decoded {
    fn validate(
        &self,
        verifier: &DeploymentActivationVerifierV2,
    ) -> Result<(), DeploymentControlErrorV2> {
        self.origin_measurements.validate(
            self.digests[ClosedRecoveryRollbackDigestFieldV2::RoleJournalReconciliation.index()],
        )?;
        if self.schema_version != SCHEMA_VERSION
            || self.installation_epoch == 0
            || self.rollback_installed_ledger_generation == 0
            || self.rollback_installed_effect_fence_epoch == 0
            || self.verified_at_unix_ms == 0
            || self.digests.iter().any(|value| is_zero(value.as_bytes()))
            || is_zero(self.transaction_id.as_bytes())
            || self.digests[ClosedRecoveryRollbackDigestFieldV2::InstallationId.index()]
                != verifier.installation_id()
            || self.installation_epoch != verifier.key_epoch()
            || self.activation_key_id != verifier.key_id()
            || self.signature.domain_tag != SIGNATURE_TAG
            || self.signature.key_id != self.activation_key_id
            || self.signature.key_epoch != self.installation_epoch
            || is_zero(self.signature.signature.as_bytes())
            || self.helper_identity.artifact_type() != ClosedArtifactTypeV2::RootHelper
            || self.watchdog_identity.artifact_type() != ClosedArtifactTypeV2::Watchdog
            || self.helper_identity.target_os() != self.platform.target_os()
            || self.watchdog_identity.target_os() != self.platform.target_os()
            || self.helper_identity.target_architecture() != self.platform.target_architecture()
            || self.watchdog_identity.target_architecture() != self.platform.target_architecture()
        {
            return Err(DeploymentControlErrorV2::InvalidRecoveryRollbackReadinessEvidence);
        }
        Ok(())
    }
}

fn encode_payload(value: &Decoded) -> Result<Vec<u8>, DeploymentControlErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encode_fields(&mut encoder, value, PAYLOAD_FIELDS)?;
    Ok(encoder.into_writer())
}

fn encode_complete(value: &Decoded) -> Result<Vec<u8>, DeploymentControlErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encode_fields(&mut encoder, value, COMPLETE_FIELDS)?;
    encode_signature(&mut encoder, value.signature)?;
    Ok(encoder.into_writer())
}

fn encode_fields(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    value: &Decoded,
    count: u64,
) -> Result<(), DeploymentControlErrorV2> {
    encoder
        .array(count)
        .and_then(|encoder| encoder.u16(value.schema_version))
        .map_err(|_| DeploymentControlErrorV2::InvalidRecoveryRollbackReadinessEvidence)?;
    for field in &ClosedRecoveryRollbackDigestFieldV2::ALL[..5] {
        put_digest(encoder, value.digests[field.index()])?;
    }
    encoder
        .u64(value.installation_epoch)
        .map_err(|_| DeploymentControlErrorV2::InvalidRecoveryRollbackReadinessEvidence)?;
    encoder
        .writer_mut()
        .extend_from_slice(value.platform.canonical_bytes());
    encoder
        .bytes(value.transaction_id.as_bytes())
        .map_err(|_| DeploymentControlErrorV2::InvalidRecoveryRollbackReadinessEvidence)?;
    for field in &ClosedRecoveryRollbackDigestFieldV2::ALL[5..7] {
        put_digest(encoder, value.digests[field.index()])?;
    }
    encoder
        .u16(value.origin_measurements.origin_phase() as u16)
        .map_err(|_| DeploymentControlErrorV2::InvalidRecoveryRollbackReadinessEvidence)?;
    encode_origin_measurements(encoder, value.origin_measurements)?;
    encoder
        .u64(value.rollback_installed_ledger_generation)
        .and_then(|encoder| encoder.u64(value.rollback_installed_effect_fence_epoch))
        .and_then(|encoder| encoder.bool(true))
        .map_err(|_| DeploymentControlErrorV2::InvalidRecoveryRollbackReadinessEvidence)?;
    for field in &ClosedRecoveryRollbackDigestFieldV2::ALL[7..] {
        put_digest(encoder, value.digests[field.index()])?;
    }
    encoder
        .u64(value.verified_at_unix_ms)
        .map_err(|_| DeploymentControlErrorV2::InvalidRecoveryRollbackReadinessEvidence)?;
    encoder
        .writer_mut()
        .extend_from_slice(value.helper_identity.canonical_bytes());
    encoder
        .writer_mut()
        .extend_from_slice(value.watchdog_identity.canonical_bytes());
    encoder
        .bytes(value.activation_key_id.as_bytes())
        .map_err(|_| DeploymentControlErrorV2::InvalidRecoveryRollbackReadinessEvidence)?;
    Ok(())
}

fn decode_complete(bytes: &[u8]) -> Result<Decoded, DeploymentControlErrorV2> {
    let mut decoder = minicbor::Decoder::new(bytes);
    expect_array(&mut decoder, COMPLETE_FIELDS)?;
    let schema_version = get_u16(&mut decoder)?;
    let mut digests = [Digest32V2::new([0; 32]); 18];
    for field in &ClosedRecoveryRollbackDigestFieldV2::ALL[..5] {
        digests[field.index()] = get_digest(&mut decoder)?;
    }
    let installation_epoch = get_u64(&mut decoder)?;
    let platform = nested(&mut decoder, PlatformLockV2::from_canonical_bytes)?;
    let transaction_id = Nonce32V2::new(get_fixed::<32>(&mut decoder)?);
    for field in &ClosedRecoveryRollbackDigestFieldV2::ALL[5..7] {
        digests[field.index()] = get_digest(&mut decoder)?;
    }
    let origin_phase_tag = get_u16(&mut decoder)?;
    let origin_measurements = decode_origin_measurements(&mut decoder)?;
    if origin_phase_tag != origin_measurements.origin_phase() as u16 {
        return Err(DeploymentControlErrorV2::InvalidRecoveryRollbackReadinessEvidence);
    }
    let rollback_installed_ledger_generation = get_u64(&mut decoder)?;
    let rollback_installed_effect_fence_epoch = get_u64(&mut decoder)?;
    if !decoder
        .bool()
        .map_err(|_| DeploymentControlErrorV2::InvalidRecoveryRollbackReadinessEvidence)?
    {
        return Err(DeploymentControlErrorV2::InvalidRecoveryRollbackReadinessEvidence);
    }
    for field in &ClosedRecoveryRollbackDigestFieldV2::ALL[7..] {
        digests[field.index()] = get_digest(&mut decoder)?;
    }
    let verified_at_unix_ms = get_u64(&mut decoder)?;
    let helper_identity = nested(&mut decoder, ArtifactIdentityV2::from_canonical_bytes)?;
    let watchdog_identity = nested(&mut decoder, ArtifactIdentityV2::from_canonical_bytes)?;
    let activation_key_id = Ed25519KeyIdV2::new(get_fixed::<32>(&mut decoder)?);
    let signature = decode_signature(&mut decoder)?;
    if decoder.position() != bytes.len() {
        return Err(DeploymentControlErrorV2::InvalidRecoveryRollbackReadinessEvidence);
    }
    Ok(Decoded {
        schema_version,
        digests,
        installation_epoch,
        platform,
        transaction_id,
        origin_measurements,
        rollback_installed_ledger_generation,
        rollback_installed_effect_fence_epoch,
        verified_at_unix_ms,
        helper_identity,
        watchdog_identity,
        activation_key_id,
        signature,
    })
}

fn encode_origin_measurements(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    value: RecoveryRollbackOriginMeasurementsV2,
) -> Result<(), DeploymentControlErrorV2> {
    match value {
        RecoveryRollbackOriginMeasurementsV2::Armed {
            armed_ledger_record_digest,
            frozen_effect_work_set_digest,
            os_effect_deny_measurement_digest,
        } => {
            encoder
                .array(4)
                .and_then(|encoder| encoder.u16(1))
                .map_err(|_| DeploymentControlErrorV2::InvalidRecoveryRollbackReadinessEvidence)?;
            put_digest(encoder, armed_ledger_record_digest)?;
            put_digest(encoder, frozen_effect_work_set_digest)?;
            put_digest(encoder, os_effect_deny_measurement_digest)?;
        }
        RecoveryRollbackOriginMeasurementsV2::Quiesced {
            quiesced_ledger_record_digest,
            frozen_effect_work_set_digest,
            role_journal_reconciliation_digest,
        } => {
            encoder
                .array(4)
                .and_then(|encoder| encoder.u16(2))
                .map_err(|_| DeploymentControlErrorV2::InvalidRecoveryRollbackReadinessEvidence)?;
            put_digest(encoder, quiesced_ledger_record_digest)?;
            put_digest(encoder, frozen_effect_work_set_digest)?;
            put_digest(encoder, role_journal_reconciliation_digest)?;
        }
        RecoveryRollbackOriginMeasurementsV2::Installed {
            installed_ledger_record_digest,
            attempted_file_tree_root,
            attempted_store_migration_result_digest,
            role_journal_reconciliation_digest,
        } => {
            encoder
                .array(5)
                .and_then(|encoder| encoder.u16(3))
                .map_err(|_| DeploymentControlErrorV2::InvalidRecoveryRollbackReadinessEvidence)?;
            put_digest(encoder, installed_ledger_record_digest)?;
            put_digest(encoder, attempted_file_tree_root)?;
            put_digest(encoder, attempted_store_migration_result_digest)?;
            put_digest(encoder, role_journal_reconciliation_digest)?;
        }
    }
    Ok(())
}

fn decode_origin_measurements(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<RecoveryRollbackOriginMeasurementsV2, DeploymentControlErrorV2> {
    let length = decoder
        .array()
        .map_err(|_| DeploymentControlErrorV2::InvalidRecoveryRollbackReadinessEvidence)?
        .ok_or(DeploymentControlErrorV2::InvalidRecoveryRollbackReadinessEvidence)?;
    let tag = get_u16(decoder)?;
    match (tag, length) {
        (1, 4) => Ok(RecoveryRollbackOriginMeasurementsV2::Armed {
            armed_ledger_record_digest: get_digest(decoder)?,
            frozen_effect_work_set_digest: get_digest(decoder)?,
            os_effect_deny_measurement_digest: get_digest(decoder)?,
        }),
        (2, 4) => Ok(RecoveryRollbackOriginMeasurementsV2::Quiesced {
            quiesced_ledger_record_digest: get_digest(decoder)?,
            frozen_effect_work_set_digest: get_digest(decoder)?,
            role_journal_reconciliation_digest: get_digest(decoder)?,
        }),
        (3, 5) => Ok(RecoveryRollbackOriginMeasurementsV2::Installed {
            installed_ledger_record_digest: get_digest(decoder)?,
            attempted_file_tree_root: get_digest(decoder)?,
            attempted_store_migration_result_digest: get_digest(decoder)?,
            role_journal_reconciliation_digest: get_digest(decoder)?,
        }),
        _ => Err(DeploymentControlErrorV2::InvalidRecoveryRollbackReadinessEvidence),
    }
}

fn put_digest(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    value: Digest32V2,
) -> Result<(), DeploymentControlErrorV2> {
    encoder
        .bytes(value.as_bytes())
        .map_err(|_| DeploymentControlErrorV2::InvalidRecoveryRollbackReadinessEvidence)?;
    Ok(())
}

fn encode_signature(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    value: EvidenceSignature,
) -> Result<(), DeploymentControlErrorV2> {
    encoder
        .array(SIGNATURE_FIELDS)
        .and_then(|encoder| encoder.u16(value.domain_tag))
        .and_then(|encoder| encoder.bytes(value.key_id.as_bytes()))
        .and_then(|encoder| encoder.u64(value.key_epoch))
        .and_then(|encoder| encoder.bytes(value.signature.as_bytes()))
        .map_err(|_| DeploymentControlErrorV2::InvalidRecoveryRollbackReadinessEvidence)?;
    Ok(())
}

fn decode_signature(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<EvidenceSignature, DeploymentControlErrorV2> {
    expect_array(decoder, SIGNATURE_FIELDS)?;
    Ok(EvidenceSignature {
        domain_tag: get_u16(decoder)?,
        key_id: Ed25519KeyIdV2::new(get_fixed::<32>(decoder)?),
        key_epoch: get_u64(decoder)?,
        signature: Ed25519SignatureV2::new(get_fixed::<64>(decoder)?),
    })
}

fn nested<T>(
    decoder: &mut minicbor::Decoder<'_>,
    decode: impl FnOnce(&[u8]) -> Result<T, DeploymentControlErrorV2>,
) -> Result<T, DeploymentControlErrorV2> {
    let start = decoder.position();
    decoder
        .skip()
        .map_err(|_| DeploymentControlErrorV2::InvalidRecoveryRollbackReadinessEvidence)?;
    decode(
        decoder
            .input()
            .get(start..decoder.position())
            .ok_or(DeploymentControlErrorV2::InvalidRecoveryRollbackReadinessEvidence)?,
    )
}

fn expect_array(
    decoder: &mut minicbor::Decoder<'_>,
    expected: u64,
) -> Result<(), DeploymentControlErrorV2> {
    if decoder
        .array()
        .map_err(|_| DeploymentControlErrorV2::InvalidRecoveryRollbackReadinessEvidence)?
        != Some(expected)
    {
        return Err(DeploymentControlErrorV2::InvalidRecoveryRollbackReadinessEvidence);
    }
    Ok(())
}

fn get_u16(decoder: &mut minicbor::Decoder<'_>) -> Result<u16, DeploymentControlErrorV2> {
    decoder
        .u16()
        .map_err(|_| DeploymentControlErrorV2::InvalidRecoveryRollbackReadinessEvidence)
}

fn get_u64(decoder: &mut minicbor::Decoder<'_>) -> Result<u64, DeploymentControlErrorV2> {
    decoder
        .u64()
        .map_err(|_| DeploymentControlErrorV2::InvalidRecoveryRollbackReadinessEvidence)
}

fn get_digest(decoder: &mut minicbor::Decoder<'_>) -> Result<Digest32V2, DeploymentControlErrorV2> {
    Ok(Digest32V2::new(get_fixed::<32>(decoder)?))
}

fn get_fixed<const N: usize>(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<[u8; N], DeploymentControlErrorV2> {
    decoder
        .bytes()
        .map_err(|_| DeploymentControlErrorV2::InvalidRecoveryRollbackReadinessEvidence)?
        .try_into()
        .map_err(|_| DeploymentControlErrorV2::InvalidRecoveryRollbackReadinessEvidence)
}

fn hash_domain(domain: &[u8], bytes: &[u8]) -> Digest32V2 {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(bytes);
    Digest32V2::new(hash.finalize().into())
}

fn is_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|value| *value == 0)
}
