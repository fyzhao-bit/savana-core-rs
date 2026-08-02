use savana_kernel_protocol::v2::{Digest32V2, Nonce32V2};
use sha2::{Digest as _, Sha256};

use super::{
    ActiveActivationV2, ArtifactIdentityV2, ClosedArtifactTypeV2, DeploymentControlErrorV2,
    DeploymentHardLimitsV2, DeploymentPhaseV2, PlatformLockV2,
};

const INTENT_SCHEMA_VERSION_V2: u16 = 2;
const INTENT_DOMAIN_TAG_V2: u16 = 2;
const INTENT_FIELDS_V2: u64 = 26;
const EXPECTED_PRE_STATE_FIELDS_V2: u64 = 17;
const INTENT_DIGEST_DOMAIN_V2: &[u8] = b"savana.deployment-transaction.v2.intent\0";
const RECOVERY_TARGET_DIGEST_DOMAIN_V2: &[u8] = b"savana.deployment-recovery-target.v2\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedPreStateV2 {
    canonical_bytes: Vec<u8>,
    ledger_generation: u64,
    ledger_record_payload_digest: Digest32V2,
    phase: DeploymentPhaseV2,
    active_activation: ActiveActivationV2,
    effects_fenced: bool,
    active_manifest_digest: Digest32V2,
    highest_ever_digest: Digest32V2,
    install_identity_profile_signed_digest: Digest32V2,
    deploy_helper_identity: ArtifactIdentityV2,
    deploy_watchdog_identity: ArtifactIdentityV2,
    deployment_trust_root_set_digest: Digest32V2,
    activation_trust_root_set_digest: Digest32V2,
    release_trust_root_set_digest: Digest32V2,
    declassification_trust_root_set_digest: Digest32V2,
    bootstrap_slot_closure_digest: Digest32V2,
    installation_epoch: u64,
    effect_fence_epoch: u64,
}

impl ExpectedPreStateV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        ledger_generation: u64,
        ledger_record_payload_digest: Digest32V2,
        phase: DeploymentPhaseV2,
        active_activation: ActiveActivationV2,
        effects_fenced: bool,
        active_manifest_digest: Digest32V2,
        highest_ever_digest: Digest32V2,
        install_identity_profile_signed_digest: Digest32V2,
        deploy_helper_identity: ArtifactIdentityV2,
        deploy_watchdog_identity: ArtifactIdentityV2,
        deployment_trust_root_set_digest: Digest32V2,
        activation_trust_root_set_digest: Digest32V2,
        release_trust_root_set_digest: Digest32V2,
        declassification_trust_root_set_digest: Digest32V2,
        bootstrap_slot_closure_digest: Digest32V2,
        installation_epoch: u64,
        effect_fence_epoch: u64,
    ) -> Result<Self, DeploymentControlErrorV2> {
        let canonical_bytes = encode_expected_pre_state(&ExpectedPreStateFieldsV2 {
            ledger_generation,
            ledger_record_payload_digest,
            phase,
            active_activation,
            effects_fenced,
            active_manifest_digest,
            highest_ever_digest,
            install_identity_profile_signed_digest,
            deploy_helper_identity,
            deploy_watchdog_identity,
            deployment_trust_root_set_digest,
            activation_trust_root_set_digest,
            release_trust_root_set_digest,
            declassification_trust_root_set_digest,
            bootstrap_slot_closure_digest,
            installation_epoch,
            effect_fence_epoch,
        })?;
        Self::from_canonical_bytes(&canonical_bytes)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, DeploymentControlErrorV2> {
        if bytes.is_empty()
            || u64::try_from(bytes.len())
                .ok()
                .is_none_or(|length| length > DeploymentHardLimitsV2::compiled().max_plan_bytes())
        {
            return Err(DeploymentControlErrorV2::InvalidDeploymentTransaction);
        }
        let mut decoder = minicbor::Decoder::new(bytes);
        expect_array(&mut decoder, EXPECTED_PRE_STATE_FIELDS_V2)?;
        let fields = ExpectedPreStateFieldsV2 {
            ledger_generation: decode_u64(&mut decoder)?,
            ledger_record_payload_digest: decode_digest(&mut decoder)?,
            phase: decode_phase(&mut decoder)?,
            active_activation: decode_nested(
                &mut decoder,
                ActiveActivationV2::from_canonical_bytes,
            )?,
            effects_fenced: decoder
                .bool()
                .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentTransaction)?,
            active_manifest_digest: decode_digest(&mut decoder)?,
            highest_ever_digest: decode_digest(&mut decoder)?,
            install_identity_profile_signed_digest: decode_digest(&mut decoder)?,
            deploy_helper_identity: decode_nested(
                &mut decoder,
                ArtifactIdentityV2::from_canonical_bytes,
            )?,
            deploy_watchdog_identity: decode_nested(
                &mut decoder,
                ArtifactIdentityV2::from_canonical_bytes,
            )?,
            deployment_trust_root_set_digest: decode_digest(&mut decoder)?,
            activation_trust_root_set_digest: decode_digest(&mut decoder)?,
            release_trust_root_set_digest: decode_digest(&mut decoder)?,
            declassification_trust_root_set_digest: decode_digest(&mut decoder)?,
            bootstrap_slot_closure_digest: decode_digest(&mut decoder)?,
            installation_epoch: decode_u64(&mut decoder)?,
            effect_fence_epoch: decode_u64(&mut decoder)?,
        };
        if decoder.position() != bytes.len() {
            return Err(DeploymentControlErrorV2::InvalidDeploymentTransaction);
        }
        validate_expected_pre_state(&fields)?;
        let canonical_bytes = encode_expected_pre_state(&fields)?;
        if canonical_bytes != bytes {
            return Err(DeploymentControlErrorV2::NonCanonicalLedgerEncoding);
        }
        Ok(Self {
            canonical_bytes,
            ledger_generation: fields.ledger_generation,
            ledger_record_payload_digest: fields.ledger_record_payload_digest,
            phase: fields.phase,
            active_activation: fields.active_activation,
            effects_fenced: fields.effects_fenced,
            active_manifest_digest: fields.active_manifest_digest,
            highest_ever_digest: fields.highest_ever_digest,
            install_identity_profile_signed_digest: fields.install_identity_profile_signed_digest,
            deploy_helper_identity: fields.deploy_helper_identity,
            deploy_watchdog_identity: fields.deploy_watchdog_identity,
            deployment_trust_root_set_digest: fields.deployment_trust_root_set_digest,
            activation_trust_root_set_digest: fields.activation_trust_root_set_digest,
            release_trust_root_set_digest: fields.release_trust_root_set_digest,
            declassification_trust_root_set_digest: fields.declassification_trust_root_set_digest,
            bootstrap_slot_closure_digest: fields.bootstrap_slot_closure_digest,
            installation_epoch: fields.installation_epoch,
            effect_fence_epoch: fields.effect_fence_epoch,
        })
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub const fn ledger_generation(&self) -> u64 {
        self.ledger_generation
    }

    pub const fn ledger_record_payload_digest(&self) -> Digest32V2 {
        self.ledger_record_payload_digest
    }

    pub const fn phase(&self) -> DeploymentPhaseV2 {
        self.phase
    }

    pub const fn active_activation(&self) -> &ActiveActivationV2 {
        &self.active_activation
    }

    pub const fn effects_fenced(&self) -> bool {
        self.effects_fenced
    }

    pub const fn active_manifest_digest(&self) -> Digest32V2 {
        self.active_manifest_digest
    }

    pub const fn highest_ever_digest(&self) -> Digest32V2 {
        self.highest_ever_digest
    }

    pub const fn install_identity_profile_signed_digest(&self) -> Digest32V2 {
        self.install_identity_profile_signed_digest
    }

    pub const fn deploy_helper_identity(&self) -> &ArtifactIdentityV2 {
        &self.deploy_helper_identity
    }

    pub const fn deploy_watchdog_identity(&self) -> &ArtifactIdentityV2 {
        &self.deploy_watchdog_identity
    }

    pub const fn deployment_trust_root_set_digest(&self) -> Digest32V2 {
        self.deployment_trust_root_set_digest
    }

    pub const fn activation_trust_root_set_digest(&self) -> Digest32V2 {
        self.activation_trust_root_set_digest
    }

    pub const fn release_trust_root_set_digest(&self) -> Digest32V2 {
        self.release_trust_root_set_digest
    }

    pub const fn declassification_trust_root_set_digest(&self) -> Digest32V2 {
        self.declassification_trust_root_set_digest
    }

    pub const fn bootstrap_slot_closure_digest(&self) -> Digest32V2 {
        self.bootstrap_slot_closure_digest
    }

    pub const fn installation_epoch(&self) -> u64 {
        self.installation_epoch
    }

    pub const fn effect_fence_epoch(&self) -> u64 {
        self.effect_fence_epoch
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ExpectedPreStateFieldsV2 {
    ledger_generation: u64,
    ledger_record_payload_digest: Digest32V2,
    phase: DeploymentPhaseV2,
    active_activation: ActiveActivationV2,
    effects_fenced: bool,
    active_manifest_digest: Digest32V2,
    highest_ever_digest: Digest32V2,
    install_identity_profile_signed_digest: Digest32V2,
    deploy_helper_identity: ArtifactIdentityV2,
    deploy_watchdog_identity: ArtifactIdentityV2,
    deployment_trust_root_set_digest: Digest32V2,
    activation_trust_root_set_digest: Digest32V2,
    release_trust_root_set_digest: Digest32V2,
    declassification_trust_root_set_digest: Digest32V2,
    bootstrap_slot_closure_digest: Digest32V2,
    installation_epoch: u64,
    effect_fence_epoch: u64,
}

fn validate_expected_pre_state(
    value: &ExpectedPreStateFieldsV2,
) -> Result<(), DeploymentControlErrorV2> {
    let phase_shape = match value.phase {
        DeploymentPhaseV2::Idle | DeploymentPhaseV2::Committed | DeploymentPhaseV2::RolledBack => {
            !value.effects_fenced
        }
        DeploymentPhaseV2::BootstrapBridge => value.effects_fenced,
        _ => false,
    };
    let activation_shape = matches!(
        (&value.active_activation, value.phase),
        (
            ActiveActivationV2::Normal,
            DeploymentPhaseV2::Idle | DeploymentPhaseV2::Committed
        ) | (
            ActiveActivationV2::ConsumedRollback { .. },
            DeploymentPhaseV2::RolledBack
        ) | (
            ActiveActivationV2::BootstrapBridge(_),
            DeploymentPhaseV2::BootstrapBridge
        )
    );
    if value.ledger_generation == 0
        || value.installation_epoch == 0
        || value.effect_fence_epoch == 0
        || !phase_shape
        || !activation_shape
        || value.deploy_helper_identity.artifact_type() != ClosedArtifactTypeV2::RootHelper
        || value.deploy_watchdog_identity.artifact_type() != ClosedArtifactTypeV2::Watchdog
        || [
            value.ledger_record_payload_digest.as_bytes(),
            value.active_manifest_digest.as_bytes(),
            value.highest_ever_digest.as_bytes(),
            value.install_identity_profile_signed_digest.as_bytes(),
            value.deployment_trust_root_set_digest.as_bytes(),
            value.activation_trust_root_set_digest.as_bytes(),
            value.release_trust_root_set_digest.as_bytes(),
            value.declassification_trust_root_set_digest.as_bytes(),
            value.bootstrap_slot_closure_digest.as_bytes(),
        ]
        .iter()
        .any(|digest| is_zero(*digest))
    {
        return Err(DeploymentControlErrorV2::InvalidDeploymentTransaction);
    }
    Ok(())
}

fn encode_expected_pre_state(
    value: &ExpectedPreStateFieldsV2,
) -> Result<Vec<u8>, DeploymentControlErrorV2> {
    validate_expected_pre_state(value)?;
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(EXPECTED_PRE_STATE_FIELDS_V2)
        .and_then(|encoder| encoder.u64(value.ledger_generation))
        .and_then(|encoder| encoder.bytes(value.ledger_record_payload_digest.as_bytes()))
        .and_then(|encoder| encoder.u16(value.phase as u16))
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentTransaction)?;
    encoder
        .writer_mut()
        .extend_from_slice(&value.active_activation.canonical_bytes()?);
    encoder
        .bool(value.effects_fenced)
        .and_then(|encoder| encoder.bytes(value.active_manifest_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(value.highest_ever_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(value.install_identity_profile_signed_digest.as_bytes()))
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentTransaction)?;
    encoder
        .writer_mut()
        .extend_from_slice(value.deploy_helper_identity.canonical_bytes());
    encoder
        .writer_mut()
        .extend_from_slice(value.deploy_watchdog_identity.canonical_bytes());
    encoder
        .bytes(value.deployment_trust_root_set_digest.as_bytes())
        .and_then(|encoder| encoder.bytes(value.activation_trust_root_set_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(value.release_trust_root_set_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(value.declassification_trust_root_set_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(value.bootstrap_slot_closure_digest.as_bytes()))
        .and_then(|encoder| encoder.u64(value.installation_epoch))
        .and_then(|encoder| encoder.u64(value.effect_fence_epoch))
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentTransaction)?;
    Ok(encoder.into_writer())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeploymentRecoveryTargetV2 {
    NormalRollbackManifest {
        rollback_manifest_digest: Digest32V2,
        canonical_bytes: Vec<u8>,
        digest: Digest32V2,
    },
    BootstrapBridgeRestore {
        bridge_manifest_digest: Digest32V2,
        maintenance_intent_signed_digest: Digest32V2,
        bridge_genesis_ledger_record_signed_digest: Digest32V2,
        bootstrap_slot_closure_digest: Digest32V2,
        premaintenance_runtime_manifest_digest: Digest32V2,
        canonical_bytes: Vec<u8>,
        digest: Digest32V2,
    },
}

impl DeploymentRecoveryTargetV2 {
    pub fn normal(rollback_manifest_digest: Digest32V2) -> Result<Self, DeploymentControlErrorV2> {
        let mut encoder = minicbor::Encoder::new(Vec::new());
        encoder
            .array(2)
            .and_then(|encoder| encoder.u16(1))
            .and_then(|encoder| encoder.bytes(rollback_manifest_digest.as_bytes()))
            .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentTransaction)?;
        Self::from_canonical_bytes(&encoder.into_writer())
    }

    pub fn bootstrap_bridge_restore(
        bridge_manifest_digest: Digest32V2,
        maintenance_intent_signed_digest: Digest32V2,
        bridge_genesis_ledger_record_signed_digest: Digest32V2,
        bootstrap_slot_closure_digest: Digest32V2,
        premaintenance_runtime_manifest_digest: Digest32V2,
    ) -> Result<Self, DeploymentControlErrorV2> {
        let mut encoder = minicbor::Encoder::new(Vec::new());
        encoder
            .array(6)
            .and_then(|encoder| encoder.u16(2))
            .and_then(|encoder| encoder.bytes(bridge_manifest_digest.as_bytes()))
            .and_then(|encoder| encoder.bytes(maintenance_intent_signed_digest.as_bytes()))
            .and_then(|encoder| {
                encoder.bytes(bridge_genesis_ledger_record_signed_digest.as_bytes())
            })
            .and_then(|encoder| encoder.bytes(bootstrap_slot_closure_digest.as_bytes()))
            .and_then(|encoder| encoder.bytes(premaintenance_runtime_manifest_digest.as_bytes()))
            .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentTransaction)?;
        Self::from_canonical_bytes(&encoder.into_writer())
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, DeploymentControlErrorV2> {
        let mut decoder = minicbor::Decoder::new(bytes);
        let length = decoder
            .array()
            .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentTransaction)?
            .ok_or(DeploymentControlErrorV2::InvalidDeploymentTransaction)?;
        let tag = decode_u16(&mut decoder)?;
        let value = match (tag, length) {
            (1, 2) => {
                let rollback_manifest_digest = decode_digest(&mut decoder)?;
                if is_zero(rollback_manifest_digest.as_bytes()) {
                    return Err(DeploymentControlErrorV2::InvalidDeploymentTransaction);
                }
                Self::NormalRollbackManifest {
                    rollback_manifest_digest,
                    canonical_bytes: bytes.to_vec(),
                    digest: hash_domain(RECOVERY_TARGET_DIGEST_DOMAIN_V2, bytes),
                }
            }
            (2, 6) => {
                let bridge_manifest_digest = decode_digest(&mut decoder)?;
                let maintenance_intent_signed_digest = decode_digest(&mut decoder)?;
                let bridge_genesis_ledger_record_signed_digest = decode_digest(&mut decoder)?;
                let bootstrap_slot_closure_digest = decode_digest(&mut decoder)?;
                let premaintenance_runtime_manifest_digest = decode_digest(&mut decoder)?;
                if [
                    bridge_manifest_digest.as_bytes(),
                    maintenance_intent_signed_digest.as_bytes(),
                    bridge_genesis_ledger_record_signed_digest.as_bytes(),
                    bootstrap_slot_closure_digest.as_bytes(),
                    premaintenance_runtime_manifest_digest.as_bytes(),
                ]
                .iter()
                .any(|digest| is_zero(*digest))
                {
                    return Err(DeploymentControlErrorV2::InvalidDeploymentTransaction);
                }
                Self::BootstrapBridgeRestore {
                    bridge_manifest_digest,
                    maintenance_intent_signed_digest,
                    bridge_genesis_ledger_record_signed_digest,
                    bootstrap_slot_closure_digest,
                    premaintenance_runtime_manifest_digest,
                    canonical_bytes: bytes.to_vec(),
                    digest: hash_domain(RECOVERY_TARGET_DIGEST_DOMAIN_V2, bytes),
                }
            }
            _ => return Err(DeploymentControlErrorV2::InvalidDeploymentTransaction),
        };
        if decoder.position() != bytes.len() {
            return Err(DeploymentControlErrorV2::InvalidDeploymentTransaction);
        }
        Ok(value)
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        match self {
            Self::NormalRollbackManifest {
                canonical_bytes, ..
            }
            | Self::BootstrapBridgeRestore {
                canonical_bytes, ..
            } => canonical_bytes,
        }
    }

    pub const fn digest(&self) -> Digest32V2 {
        match self {
            Self::NormalRollbackManifest { digest, .. }
            | Self::BootstrapBridgeRestore { digest, .. } => *digest,
        }
    }

    pub const fn tag(&self) -> u16 {
        match self {
            Self::NormalRollbackManifest { .. } => 1,
            Self::BootstrapBridgeRestore { .. } => 2,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeploymentTransactionIntentMaterialV2 {
    pub transaction_id: Nonce32V2,
    pub installation_id: Digest32V2,
    pub target_platform: PlatformLockV2,
    pub evidence_trust_policy_digest: Digest32V2,
    pub evidence_layer_limits_digest: Digest32V2,
    pub source_evidence_digest: Digest32V2,
    pub artifact_evidence_digest: Digest32V2,
    pub created_at_unix_ms: u64,
    pub not_before_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub maximum_prepare_duration_ns: u64,
    pub maximum_cutover_duration_ns: u64,
    pub maximum_boot_recovery_duration_ns: u64,
    pub maximum_clock_skew_ns: u64,
    pub expected_pre_state: ExpectedPreStateV2,
    pub staging_tree_digest: Digest32V2,
    pub desired_manifest_digest: Digest32V2,
    pub recovery_target: DeploymentRecoveryTargetV2,
    pub migration_plan_digest: Digest32V2,
    pub artifact_install_plan_digest: Digest32V2,
    pub service_transition_plan_digest: Digest32V2,
    pub isolated_e2e_plan_digest: Digest32V2,
    pub evidence_contract_digest: Digest32V2,
    pub protected_acceptance_plan_digest: Digest32V2,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeploymentTransactionIntentV2 {
    canonical_bytes: Vec<u8>,
    material: DeploymentTransactionIntentMaterialV2,
    intent_digest: Digest32V2,
}

impl DeploymentTransactionIntentV2 {
    pub fn new(
        material: DeploymentTransactionIntentMaterialV2,
    ) -> Result<Self, DeploymentControlErrorV2> {
        validate_intent(&material)?;
        let canonical_bytes = encode_intent(&material)?;
        let intent_digest = hash_domain(INTENT_DIGEST_DOMAIN_V2, &canonical_bytes);
        Ok(Self {
            canonical_bytes,
            material,
            intent_digest,
        })
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, DeploymentControlErrorV2> {
        if bytes.is_empty()
            || u64::try_from(bytes.len()).ok().is_none_or(|length| {
                length > DeploymentHardLimitsV2::compiled().max_transaction_bytes()
            })
        {
            return Err(DeploymentControlErrorV2::InvalidDeploymentTransaction);
        }
        let mut decoder = minicbor::Decoder::new(bytes);
        expect_array(&mut decoder, INTENT_FIELDS_V2)?;
        if decode_u16(&mut decoder)? != INTENT_SCHEMA_VERSION_V2
            || decode_u16(&mut decoder)? != INTENT_DOMAIN_TAG_V2
        {
            return Err(DeploymentControlErrorV2::InvalidDeploymentTransaction);
        }
        let material = DeploymentTransactionIntentMaterialV2 {
            transaction_id: decode_nonce(&mut decoder)?,
            installation_id: decode_digest(&mut decoder)?,
            target_platform: decode_nested(&mut decoder, PlatformLockV2::from_canonical_bytes)?,
            evidence_trust_policy_digest: decode_digest(&mut decoder)?,
            evidence_layer_limits_digest: decode_digest(&mut decoder)?,
            source_evidence_digest: decode_digest(&mut decoder)?,
            artifact_evidence_digest: decode_digest(&mut decoder)?,
            created_at_unix_ms: decode_u64(&mut decoder)?,
            not_before_unix_ms: decode_u64(&mut decoder)?,
            expires_at_unix_ms: decode_u64(&mut decoder)?,
            maximum_prepare_duration_ns: decode_u64(&mut decoder)?,
            maximum_cutover_duration_ns: decode_u64(&mut decoder)?,
            maximum_boot_recovery_duration_ns: decode_u64(&mut decoder)?,
            maximum_clock_skew_ns: decode_u64(&mut decoder)?,
            expected_pre_state: decode_nested(
                &mut decoder,
                ExpectedPreStateV2::from_canonical_bytes,
            )?,
            staging_tree_digest: decode_digest(&mut decoder)?,
            desired_manifest_digest: decode_digest(&mut decoder)?,
            recovery_target: decode_nested(
                &mut decoder,
                DeploymentRecoveryTargetV2::from_canonical_bytes,
            )?,
            migration_plan_digest: decode_digest(&mut decoder)?,
            artifact_install_plan_digest: decode_digest(&mut decoder)?,
            service_transition_plan_digest: decode_digest(&mut decoder)?,
            isolated_e2e_plan_digest: decode_digest(&mut decoder)?,
            evidence_contract_digest: decode_digest(&mut decoder)?,
            protected_acceptance_plan_digest: decode_digest(&mut decoder)?,
        };
        if decoder.position() != bytes.len() {
            return Err(DeploymentControlErrorV2::InvalidDeploymentTransaction);
        }
        let value = Self::new(material)?;
        if value.canonical_bytes != bytes {
            return Err(DeploymentControlErrorV2::NonCanonicalLedgerEncoding);
        }
        Ok(value)
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub const fn material(&self) -> &DeploymentTransactionIntentMaterialV2 {
        &self.material
    }

    pub const fn transaction_id(&self) -> Nonce32V2 {
        self.material.transaction_id
    }

    pub const fn installation_id(&self) -> Digest32V2 {
        self.material.installation_id
    }

    pub const fn expected_pre_state(&self) -> &ExpectedPreStateV2 {
        &self.material.expected_pre_state
    }

    pub const fn recovery_target(&self) -> &DeploymentRecoveryTargetV2 {
        &self.material.recovery_target
    }

    pub const fn intent_digest(&self) -> Digest32V2 {
        self.intent_digest
    }
}

fn validate_intent(
    value: &DeploymentTransactionIntentMaterialV2,
) -> Result<(), DeploymentControlErrorV2> {
    let limits = DeploymentHardLimitsV2::compiled();
    let authenticated_recovery_target =
        DeploymentRecoveryTargetV2::from_canonical_bytes(value.recovery_target.canonical_bytes())?;
    if value.created_at_unix_ms == 0
        || value.not_before_unix_ms < value.created_at_unix_ms
        || value.expires_at_unix_ms <= value.not_before_unix_ms
        || value.maximum_prepare_duration_ns == 0
        || value.maximum_prepare_duration_ns > limits.max_prepare_duration_ns()
        || value.maximum_cutover_duration_ns == 0
        || value.maximum_cutover_duration_ns > limits.max_cutover_duration_ns()
        || value.maximum_boot_recovery_duration_ns == 0
        || value.maximum_boot_recovery_duration_ns > limits.max_boot_recovery_duration_ns()
        || value.maximum_clock_skew_ns == 0
        || value.maximum_clock_skew_ns > limits.max_clock_skew_ns()
        || value.expected_pre_state.installation_epoch() == 0
        || value.target_platform.target_os()
            != value
                .expected_pre_state
                .deploy_helper_identity()
                .target_os()
        || value.target_platform.target_architecture()
            != value
                .expected_pre_state
                .deploy_helper_identity()
                .target_architecture()
        || value.target_platform.target_os()
            != value
                .expected_pre_state
                .deploy_watchdog_identity()
                .target_os()
        || value.target_platform.target_architecture()
            != value
                .expected_pre_state
                .deploy_watchdog_identity()
                .target_architecture()
        || [
            value.transaction_id.as_bytes(),
            value.installation_id.as_bytes(),
            value.evidence_trust_policy_digest.as_bytes(),
            value.evidence_layer_limits_digest.as_bytes(),
            value.source_evidence_digest.as_bytes(),
            value.artifact_evidence_digest.as_bytes(),
            value.staging_tree_digest.as_bytes(),
            value.desired_manifest_digest.as_bytes(),
            value.migration_plan_digest.as_bytes(),
            value.artifact_install_plan_digest.as_bytes(),
            value.service_transition_plan_digest.as_bytes(),
            value.isolated_e2e_plan_digest.as_bytes(),
            value.evidence_contract_digest.as_bytes(),
            value.protected_acceptance_plan_digest.as_bytes(),
        ]
        .iter()
        .any(|digest| is_zero(*digest))
        || authenticated_recovery_target != value.recovery_target
    {
        return Err(DeploymentControlErrorV2::InvalidDeploymentTransaction);
    }
    match (&value.material_phase(), &value.recovery_target) {
        (
            DeploymentPhaseV2::BootstrapBridge,
            DeploymentRecoveryTargetV2::BootstrapBridgeRestore {
                bridge_manifest_digest,
                bootstrap_slot_closure_digest,
                ..
            },
        ) if *bridge_manifest_digest == value.expected_pre_state.active_manifest_digest()
            && *bootstrap_slot_closure_digest
                == value.expected_pre_state.bootstrap_slot_closure_digest() => {}
        (
            DeploymentPhaseV2::Idle | DeploymentPhaseV2::Committed | DeploymentPhaseV2::RolledBack,
            DeploymentRecoveryTargetV2::NormalRollbackManifest { .. },
        ) => {}
        _ => return Err(DeploymentControlErrorV2::InvalidDeploymentTransaction),
    }
    Ok(())
}

impl DeploymentTransactionIntentMaterialV2 {
    const fn material_phase(&self) -> DeploymentPhaseV2 {
        self.expected_pre_state.phase()
    }
}

fn encode_intent(
    value: &DeploymentTransactionIntentMaterialV2,
) -> Result<Vec<u8>, DeploymentControlErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(INTENT_FIELDS_V2)
        .and_then(|encoder| encoder.u16(INTENT_SCHEMA_VERSION_V2))
        .and_then(|encoder| encoder.u16(INTENT_DOMAIN_TAG_V2))
        .and_then(|encoder| encoder.bytes(value.transaction_id.as_bytes()))
        .and_then(|encoder| encoder.bytes(value.installation_id.as_bytes()))
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentTransaction)?;
    encoder
        .writer_mut()
        .extend_from_slice(value.target_platform.canonical_bytes());
    encoder
        .bytes(value.evidence_trust_policy_digest.as_bytes())
        .and_then(|encoder| encoder.bytes(value.evidence_layer_limits_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(value.source_evidence_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(value.artifact_evidence_digest.as_bytes()))
        .and_then(|encoder| encoder.u64(value.created_at_unix_ms))
        .and_then(|encoder| encoder.u64(value.not_before_unix_ms))
        .and_then(|encoder| encoder.u64(value.expires_at_unix_ms))
        .and_then(|encoder| encoder.u64(value.maximum_prepare_duration_ns))
        .and_then(|encoder| encoder.u64(value.maximum_cutover_duration_ns))
        .and_then(|encoder| encoder.u64(value.maximum_boot_recovery_duration_ns))
        .and_then(|encoder| encoder.u64(value.maximum_clock_skew_ns))
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentTransaction)?;
    encoder
        .writer_mut()
        .extend_from_slice(value.expected_pre_state.canonical_bytes());
    encoder
        .bytes(value.staging_tree_digest.as_bytes())
        .and_then(|encoder| encoder.bytes(value.desired_manifest_digest.as_bytes()))
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentTransaction)?;
    encoder
        .writer_mut()
        .extend_from_slice(value.recovery_target.canonical_bytes());
    encoder
        .bytes(value.migration_plan_digest.as_bytes())
        .and_then(|encoder| encoder.bytes(value.artifact_install_plan_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(value.service_transition_plan_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(value.isolated_e2e_plan_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(value.evidence_contract_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(value.protected_acceptance_plan_digest.as_bytes()))
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentTransaction)?;
    Ok(encoder.into_writer())
}

fn decode_nested<T>(
    decoder: &mut minicbor::Decoder<'_>,
    decode: impl FnOnce(&[u8]) -> Result<T, DeploymentControlErrorV2>,
) -> Result<T, DeploymentControlErrorV2> {
    let start = decoder.position();
    decoder
        .skip()
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentTransaction)?;
    decode(
        decoder
            .input()
            .get(start..decoder.position())
            .ok_or(DeploymentControlErrorV2::InvalidDeploymentTransaction)?,
    )
}

fn expect_array(
    decoder: &mut minicbor::Decoder<'_>,
    expected: u64,
) -> Result<(), DeploymentControlErrorV2> {
    if decoder
        .array()
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentTransaction)?
        != Some(expected)
    {
        return Err(DeploymentControlErrorV2::InvalidDeploymentTransaction);
    }
    Ok(())
}

fn decode_u16(decoder: &mut minicbor::Decoder<'_>) -> Result<u16, DeploymentControlErrorV2> {
    decoder
        .u16()
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentTransaction)
}

fn decode_u64(decoder: &mut minicbor::Decoder<'_>) -> Result<u64, DeploymentControlErrorV2> {
    decoder
        .u64()
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentTransaction)
}

fn decode_digest(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<Digest32V2, DeploymentControlErrorV2> {
    Ok(Digest32V2::new(decode_fixed::<32>(decoder)?))
}

fn decode_nonce(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<Nonce32V2, DeploymentControlErrorV2> {
    Ok(Nonce32V2::new(decode_fixed::<32>(decoder)?))
}

fn decode_fixed<const N: usize>(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<[u8; N], DeploymentControlErrorV2> {
    decoder
        .bytes()
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentTransaction)?
        .try_into()
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentTransaction)
}

fn decode_phase(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<DeploymentPhaseV2, DeploymentControlErrorV2> {
    match decode_u16(decoder)? {
        1 => Ok(DeploymentPhaseV2::Idle),
        7 => Ok(DeploymentPhaseV2::Committed),
        12 => Ok(DeploymentPhaseV2::RolledBack),
        14 => Ok(DeploymentPhaseV2::BootstrapBridge),
        _ => Err(DeploymentControlErrorV2::InvalidDeploymentTransaction),
    }
}

fn hash_domain(domain: &[u8], bytes: &[u8]) -> Digest32V2 {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(bytes);
    Digest32V2::new(hash.finalize().into())
}

fn is_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}
