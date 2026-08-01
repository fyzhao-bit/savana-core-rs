use savana_kernel_protocol::v2::{Digest32V2, Ed25519KeyIdV2, Ed25519SignatureV2, Nonce32V2};
use savana_platform_identity::{
    NativeDeploymentSignatureDomainV2, NativeDeploymentSignatureRequestV2,
    NativeDeploymentSigningAuthorityV2,
};
use sha2::{Digest as _, Sha256};

use super::deployment_manifest_primitives::{hash_domain, is_zero};
use super::{
    ArtifactInstallPlanV2, DeploymentActivationVerifierV2, DeploymentAuthorizationKeyRefsV2,
    DeploymentAuthorizationVerifierV2, DeploymentControlErrorV2, DeploymentLedgerRecordV2,
    DeploymentOwnerClaimV2, DeploymentOwnerRoleV2, DeploymentRecoveryTargetV2,
    DeploymentTransactionV2, EvidenceContractV2, ExpectedPreStateV2, IsolatedE2EPlanV2,
    MigrationPlanV2, OperationalTrustRootPurposeV2, OperationalTrustRootSetBindingV2,
    OperationalTrustRootSetV2, ProtectedAcceptancePlanV2, ReleaseTrustRootSetV2,
    SecurityStateManifestV2, ServiceTransitionPlanV2,
};

const CORE_SCHEMA_VERSION_V2: u16 = 2;
const CORE_OBJECT_DOMAIN_TAG_V2: u16 = 6;
const CORE_PAYLOAD_FIELDS_V2: u64 = 22;
const CORE_COMPLETE_FIELDS_V2: u64 = 3;
const CORE_SIGNATURE_FIELDS_V2: u64 = 4;
const CORE_SIGNATURE_TAG_V2: u16 = 25;
const CORE_PAYLOAD_DOMAIN_V2: &[u8] = b"savana.durable-deployment-core.v2.payload\0";
const CORE_SIGNED_DOMAIN_V2: &[u8] = b"savana.durable-deployment-core.v2.signed\0";
const CORE_SIGNATURE_DOMAIN_V2: &[u8] = b"savana.durable-deployment-core.v2.signature\0";
const STAGING_SELECTOR_DOMAIN_V2: &[u8] = b"savana.staging-selector.v2\0";
const MAX_CORE_BYTES_V2: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DurableDeploymentRecoveryTargetV2 {
    NormalRollbackManifest {
        rollback_manifest: Box<SecurityStateManifestV2>,
    },
    BootstrapBridgeRestore {
        bridge_manifest: Box<SecurityStateManifestV2>,
        maintenance_intent_signed_digest: Digest32V2,
        bridge_genesis_ledger_record_signed_digest: Digest32V2,
        bootstrap_slot_closure_digest: Digest32V2,
        premaintenance_runtime_manifest_digest: Digest32V2,
    },
}

impl DurableDeploymentRecoveryTargetV2 {
    pub fn normal(
        rollback_manifest: SecurityStateManifestV2,
    ) -> Result<Self, DeploymentControlErrorV2> {
        rollback_manifest.validate_for_normal_transaction()?;
        Ok(Self::NormalRollbackManifest {
            rollback_manifest: Box::new(rollback_manifest),
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn bootstrap_bridge_restore(
        bridge_manifest: SecurityStateManifestV2,
        maintenance_intent_signed_digest: Digest32V2,
        bridge_genesis_ledger_record_signed_digest: Digest32V2,
        bootstrap_slot_closure_digest: Digest32V2,
        premaintenance_runtime_manifest_digest: Digest32V2,
    ) -> Result<Self, DeploymentControlErrorV2> {
        if bridge_manifest.material().installation_class
            != super::InstallationClassV2::BootstrapEpochBridge
            || [
                maintenance_intent_signed_digest,
                bridge_genesis_ledger_record_signed_digest,
                bootstrap_slot_closure_digest,
                premaintenance_runtime_manifest_digest,
            ]
            .iter()
            .any(|digest| is_zero(digest.as_bytes()))
        {
            return Err(DeploymentControlErrorV2::InvalidDeploymentTransaction);
        }
        Ok(Self::BootstrapBridgeRestore {
            bridge_manifest: Box::new(bridge_manifest),
            maintenance_intent_signed_digest,
            bridge_genesis_ledger_record_signed_digest,
            bootstrap_slot_closure_digest,
            premaintenance_runtime_manifest_digest,
        })
    }

    pub fn intent_projection(
        &self,
    ) -> Result<DeploymentRecoveryTargetV2, DeploymentControlErrorV2> {
        match self {
            Self::NormalRollbackManifest { rollback_manifest } => {
                DeploymentRecoveryTargetV2::normal(rollback_manifest.signed_digest())
            }
            Self::BootstrapBridgeRestore {
                bridge_manifest,
                maintenance_intent_signed_digest,
                bridge_genesis_ledger_record_signed_digest,
                bootstrap_slot_closure_digest,
                premaintenance_runtime_manifest_digest,
            } => DeploymentRecoveryTargetV2::bootstrap_bridge_restore(
                bridge_manifest.signed_digest(),
                *maintenance_intent_signed_digest,
                *bridge_genesis_ledger_record_signed_digest,
                *bootstrap_slot_closure_digest,
                *premaintenance_runtime_manifest_digest,
            ),
        }
    }

    pub const fn manifest(&self) -> &SecurityStateManifestV2 {
        match self {
            Self::NormalRollbackManifest { rollback_manifest } => rollback_manifest,
            Self::BootstrapBridgeRestore {
                bridge_manifest, ..
            } => bridge_manifest,
        }
    }

    pub const fn is_normal(&self) -> bool {
        matches!(self, Self::NormalRollbackManifest { .. })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableDeploymentTransactionCoreMaterialV2 {
    pub installation_id: Digest32V2,
    pub installation_epoch: u64,
    pub signed_transaction: DeploymentTransactionV2,
    pub desired_manifest: SecurityStateManifestV2,
    pub recovery_target: DurableDeploymentRecoveryTargetV2,
    pub migration_plan: MigrationPlanV2,
    pub artifact_install_plan: ArtifactInstallPlanV2,
    pub service_transition_plan: ServiceTransitionPlanV2,
    pub isolated_e2e_plan: IsolatedE2EPlanV2,
    pub evidence_contract: EvidenceContractV2,
    pub protected_acceptance_plan: ProtectedAcceptancePlanV2,
    pub initial_owner: DeploymentOwnerClaimV2,
    pub watchdog_boot_id: Digest32V2,
    pub watchdog_process_identity_digest: Digest32V2,
    pub watchdog_deadline_monotonic_ns: u64,
    pub created_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableDeploymentTransactionCoreV2 {
    canonical_bytes: Vec<u8>,
    payload_digest: Digest32V2,
    signed_digest: Digest32V2,
    material: DurableDeploymentTransactionCoreMaterialV2,
}

impl DurableDeploymentTransactionCoreV2 {
    /// Authenticates the immutable core envelope with the installation
    /// activation key before exposing the embedded transaction key
    /// references needed to select the two operational-root verifiers.
    ///
    /// This is key discovery only. Callers must subsequently perform the full
    /// canonical core decode with the selected verifiers before using any
    /// other core field or causing a side effect.
    pub fn authenticated_authorization_key_refs(
        bytes: &[u8],
        activation_verifier: &DeploymentActivationVerifierV2,
    ) -> Result<DeploymentAuthorizationKeyRefsV2, DeploymentControlErrorV2> {
        if bytes.is_empty() || bytes.len() > MAX_CORE_BYTES_V2 {
            return Err(DeploymentControlErrorV2::InvalidDeploymentTransaction);
        }
        let mut decoder = minicbor::Decoder::new(bytes);
        expect_array(&mut decoder, CORE_COMPLETE_FIELDS_V2)?;
        let payload_start = decoder.position();
        decoder
            .skip()
            .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentTransaction)?;
        let payload_end = decoder.position();
        let payload = bytes
            .get(payload_start..payload_end)
            .ok_or(DeploymentControlErrorV2::InvalidDeploymentTransaction)?;
        let payload_digest = decode_digest(&mut decoder)?;
        let signature = decode_core_signature(&mut decoder)?;
        require_eof(&decoder, bytes)?;
        if hash_domain(CORE_PAYLOAD_DOMAIN_V2, payload) != payload_digest {
            return Err(DeploymentControlErrorV2::InvalidDeploymentTransaction);
        }
        activation_verifier.verify_domain_signature_parts(
            signature.domain_tag,
            signature.signer_key_id,
            signature.signer_key_epoch,
            signature.signature,
            CORE_SIGNATURE_TAG_V2,
            CORE_SIGNATURE_DOMAIN_V2,
            payload_digest,
        )?;

        let mut payload_decoder = minicbor::Decoder::new(payload);
        expect_array(&mut payload_decoder, CORE_PAYLOAD_FIELDS_V2)?;
        if decode_u16(&mut payload_decoder)? != CORE_SCHEMA_VERSION_V2
            || decode_u16(&mut payload_decoder)? != CORE_OBJECT_DOMAIN_TAG_V2
            || decode_digest(&mut payload_decoder)? != activation_verifier.installation_id()
            || decode_u64(&mut payload_decoder)? != activation_verifier.key_epoch()
        {
            return Err(DeploymentControlErrorV2::InstallationTupleMismatch);
        }
        let _transaction_id = decode_nonce(&mut payload_decoder)?;
        let transaction_start = payload_decoder.position();
        payload_decoder
            .skip()
            .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentTransaction)?;
        let transaction_end = payload_decoder.position();
        for _ in 0..(CORE_PAYLOAD_FIELDS_V2 - 6) {
            payload_decoder
                .skip()
                .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentTransaction)?;
        }
        require_eof(&payload_decoder, payload)?;
        DeploymentAuthorizationKeyRefsV2::peek(
            payload
                .get(transaction_start..transaction_end)
                .ok_or(DeploymentControlErrorV2::InvalidDeploymentTransaction)?,
        )
    }

    pub fn authenticated_authorization_key_refs_for_signed_digest(
        bytes: &[u8],
        expected_signed_digest: Digest32V2,
        activation_verifier: &DeploymentActivationVerifierV2,
    ) -> Result<DeploymentAuthorizationKeyRefsV2, DeploymentControlErrorV2> {
        if expected_signed_digest
            .as_bytes()
            .iter()
            .all(|byte| *byte == 0)
            || hash_domain(CORE_SIGNED_DOMAIN_V2, bytes) != expected_signed_digest
        {
            return Err(DeploymentControlErrorV2::InvalidDeploymentTransaction);
        }
        Self::authenticated_authorization_key_refs(bytes, activation_verifier)
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn new_signed_with_authority(
        material: DurableDeploymentTransactionCoreMaterialV2,
        authority: &mut dyn NativeDeploymentSigningAuthorityV2,
        verifier: &DeploymentActivationVerifierV2,
        release_trust_root_set: &ReleaseTrustRootSetV2,
    ) -> Result<Self, DeploymentControlErrorV2> {
        Self::new_signed_internal(material, authority, verifier, release_trust_root_set)
    }

    pub fn new_signed_with_complete_trust(
        material: DurableDeploymentTransactionCoreMaterialV2,
        authority: &mut dyn NativeDeploymentSigningAuthorityV2,
        verifier: &DeploymentActivationVerifierV2,
        deployment_trust_root_set: &OperationalTrustRootSetV2,
        activation_trust_root_set: &OperationalTrustRootSetV2,
        declassification_trust_root_set: &OperationalTrustRootSetV2,
        release_trust_root_set: &ReleaseTrustRootSetV2,
    ) -> Result<Self, DeploymentControlErrorV2> {
        validate_operational_trust_binding(
            &material,
            verifier,
            deployment_trust_root_set,
            activation_trust_root_set,
            declassification_trust_root_set,
        )?;
        Self::new_signed_internal(material, authority, verifier, release_trust_root_set)
    }

    fn new_signed_internal(
        material: DurableDeploymentTransactionCoreMaterialV2,
        authority: &mut dyn NativeDeploymentSigningAuthorityV2,
        verifier: &DeploymentActivationVerifierV2,
        release_trust_root_set: &ReleaseTrustRootSetV2,
    ) -> Result<Self, DeploymentControlErrorV2> {
        validate_core_material(&material, release_trust_root_set)?;
        validate_signing_authority(&material, authority, verifier)?;
        let payload = encode_core_payload(&material)?;
        let payload_digest = hash_domain(CORE_PAYLOAD_DOMAIN_V2, &payload);
        let request = NativeDeploymentSignatureRequestV2::new(
            NativeDeploymentSignatureDomainV2::DurableDeploymentTransactionCore,
            *material.installation_id.as_bytes(),
            material.installation_epoch,
            *payload_digest.as_bytes(),
        )
        .map_err(|_| DeploymentControlErrorV2::NativeSigningAuthorityUnavailable)?;
        let signature = CoreSignatureV2 {
            domain_tag: CORE_SIGNATURE_TAG_V2,
            signer_key_id: Ed25519KeyIdV2::new(authority.key_id()),
            signer_key_epoch: material.installation_epoch,
            signature: Ed25519SignatureV2::new(
                authority
                    .sign(request)
                    .map_err(|_| DeploymentControlErrorV2::NativeSigningAuthorityUnavailable)?,
            ),
        };
        build_authenticated_core(material, payload_digest, signature, verifier, None)
    }

    #[cfg(any(test, feature = "test-support"))]
    #[allow(clippy::too_many_arguments)]
    pub fn from_canonical_bytes(
        bytes: &[u8],
        activation_verifier: &DeploymentActivationVerifierV2,
        rollback_grant_verifier: &DeploymentAuthorizationVerifierV2,
        transaction_authorization_verifier: &DeploymentAuthorizationVerifierV2,
        release_trust_root_set: &ReleaseTrustRootSetV2,
    ) -> Result<Self, DeploymentControlErrorV2> {
        Self::from_canonical_bytes_internal(
            bytes,
            activation_verifier,
            rollback_grant_verifier,
            transaction_authorization_verifier,
            release_trust_root_set,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_canonical_bytes_with_complete_trust(
        bytes: &[u8],
        activation_verifier: &DeploymentActivationVerifierV2,
        rollback_grant_verifier: &DeploymentAuthorizationVerifierV2,
        transaction_authorization_verifier: &DeploymentAuthorizationVerifierV2,
        deployment_trust_root_set: &OperationalTrustRootSetV2,
        activation_trust_root_set: &OperationalTrustRootSetV2,
        declassification_trust_root_set: &OperationalTrustRootSetV2,
        release_trust_root_set: &ReleaseTrustRootSetV2,
    ) -> Result<Self, DeploymentControlErrorV2> {
        let value = Self::from_canonical_bytes_internal(
            bytes,
            activation_verifier,
            rollback_grant_verifier,
            transaction_authorization_verifier,
            release_trust_root_set,
        )?;
        validate_operational_trust_binding(
            value.material(),
            activation_verifier,
            deployment_trust_root_set,
            activation_trust_root_set,
            declassification_trust_root_set,
        )?;
        Ok(value)
    }

    #[allow(clippy::too_many_arguments)]
    fn from_canonical_bytes_internal(
        bytes: &[u8],
        activation_verifier: &DeploymentActivationVerifierV2,
        rollback_grant_verifier: &DeploymentAuthorizationVerifierV2,
        transaction_authorization_verifier: &DeploymentAuthorizationVerifierV2,
        release_trust_root_set: &ReleaseTrustRootSetV2,
    ) -> Result<Self, DeploymentControlErrorV2> {
        if bytes.is_empty() || bytes.len() > MAX_CORE_BYTES_V2 {
            return Err(DeploymentControlErrorV2::InvalidDeploymentTransaction);
        }
        let manifest_verification_time_unix_ms = peek_core_created_at(bytes)?;
        let mut decoder = minicbor::Decoder::new(bytes);
        expect_array(&mut decoder, CORE_COMPLETE_FIELDS_V2)?;
        let material = decode_nested(&mut decoder, |payload| {
            decode_core_payload(
                payload,
                rollback_grant_verifier,
                transaction_authorization_verifier,
                release_trust_root_set,
                manifest_verification_time_unix_ms,
            )
        })?;
        let payload_digest = decode_digest(&mut decoder)?;
        let signature = decode_core_signature(&mut decoder)?;
        require_eof(&decoder, bytes)?;
        validate_core_material(&material, release_trust_root_set)?;
        let computed = hash_domain(CORE_PAYLOAD_DOMAIN_V2, &encode_core_payload(&material)?);
        if computed != payload_digest {
            return Err(DeploymentControlErrorV2::InvalidDeploymentTransaction);
        }
        build_authenticated_core(
            material,
            payload_digest,
            signature,
            activation_verifier,
            Some(bytes),
        )
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub const fn payload_digest(&self) -> Digest32V2 {
        self.payload_digest
    }

    pub const fn signed_digest(&self) -> Digest32V2 {
        self.signed_digest
    }

    pub const fn material(&self) -> &DurableDeploymentTransactionCoreMaterialV2 {
        &self.material
    }

    pub const fn transaction_id(&self) -> Nonce32V2 {
        self.material.signed_transaction.intent().transaction_id()
    }

    pub fn validate_selected_ledger_pre_state(
        &self,
        selected: &DeploymentLedgerRecordV2,
    ) -> Result<(), DeploymentControlErrorV2> {
        let expected = self
            .material
            .signed_transaction
            .intent()
            .expected_pre_state();
        self.material
            .signed_transaction
            .validate_authenticated_pre_state(
                selected,
                expected.deployment_trust_root_set_digest(),
                expected.activation_trust_root_set_digest(),
                expected.release_trust_root_set_digest(),
            )?;
        if selected.bootstrap_tcb_lock_digest()
            != self
                .material
                .desired_manifest
                .material()
                .bootstrap_tcb_lock
                .digest()
        {
            return Err(DeploymentControlErrorV2::TransactionBindingMismatch);
        }
        Ok(())
    }
}

fn validate_operational_trust_binding(
    material: &DurableDeploymentTransactionCoreMaterialV2,
    activation_verifier: &DeploymentActivationVerifierV2,
    deployment_trust_root_set: &OperationalTrustRootSetV2,
    activation_trust_root_set: &OperationalTrustRootSetV2,
    declassification_trust_root_set: &OperationalTrustRootSetV2,
) -> Result<(), DeploymentControlErrorV2> {
    let expected = material.signed_transaction.intent().expected_pre_state();
    let bootstrap = &material.desired_manifest.material().bootstrap_tcb_lock;
    if !matches!(
        deployment_trust_root_set.binding(),
        OperationalTrustRootSetBindingV2::Deployment { .. }
    ) || !matches!(
        activation_trust_root_set.binding(),
        OperationalTrustRootSetBindingV2::Activation { .. }
    ) || !matches!(
        declassification_trust_root_set.binding(),
        OperationalTrustRootSetBindingV2::Declassification { .. }
    ) || deployment_trust_root_set.product_family_digest()
        != activation_trust_root_set.product_family_digest()
        || deployment_trust_root_set.product_family_digest()
            != declassification_trust_root_set.product_family_digest()
        || deployment_trust_root_set.binding().member_set_digest()
            != expected.deployment_trust_root_set_digest()
        || activation_trust_root_set.binding().member_set_digest()
            != expected.activation_trust_root_set_digest()
        || declassification_trust_root_set
            .binding()
            .member_set_digest()
            != expected.declassification_trust_root_set_digest()
        || deployment_trust_root_set
            .matches_versioned_identity(bootstrap.deployment_trust_root_set())
            .is_err()
        || activation_trust_root_set
            .matches_versioned_identity(bootstrap.activation_trust_root_set())
            .is_err()
        || declassification_trust_root_set
            .matches_versioned_identity(bootstrap.declassification_trust_root_set())
            .is_err()
        || !deployment_trust_root_set.authorizes(
            OperationalTrustRootPurposeV2::DeploymentAuthorization,
            material.signed_transaction.authorization_key_id(),
            material.signed_transaction.authorization_key_epoch(),
            material.created_at_unix_ms,
        )
        || !deployment_trust_root_set.authorizes(
            OperationalTrustRootPurposeV2::RollbackAuthorization,
            material.signed_transaction.rollback_grant().signer_key_id(),
            material
                .signed_transaction
                .rollback_grant()
                .signer_key_epoch(),
            material.created_at_unix_ms,
        )
        || !activation_trust_root_set.authorizes(
            OperationalTrustRootPurposeV2::InstallationActivation,
            activation_verifier.key_id(),
            activation_verifier.key_epoch(),
            material.created_at_unix_ms,
        )
    {
        return Err(DeploymentControlErrorV2::InvalidDeploymentTransaction);
    }
    Ok(())
}

fn peek_core_created_at(bytes: &[u8]) -> Result<u64, DeploymentControlErrorV2> {
    let mut decoder = minicbor::Decoder::new(bytes);
    expect_array(&mut decoder, CORE_COMPLETE_FIELDS_V2)?;
    expect_array(&mut decoder, CORE_PAYLOAD_FIELDS_V2)?;
    for _ in 0..(CORE_PAYLOAD_FIELDS_V2 - 1) {
        decoder
            .skip()
            .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentTransaction)?;
    }
    decode_u64(&mut decoder)
}

#[derive(Debug, Clone, Copy)]
struct CoreSignatureV2 {
    domain_tag: u16,
    signer_key_id: Ed25519KeyIdV2,
    signer_key_epoch: u64,
    signature: Ed25519SignatureV2,
}

fn build_authenticated_core(
    material: DurableDeploymentTransactionCoreMaterialV2,
    payload_digest: Digest32V2,
    signature: CoreSignatureV2,
    verifier: &DeploymentActivationVerifierV2,
    original: Option<&[u8]>,
) -> Result<DurableDeploymentTransactionCoreV2, DeploymentControlErrorV2> {
    if material.installation_id != verifier.installation_id()
        || material.installation_epoch != verifier.key_epoch()
        || signature.domain_tag != CORE_SIGNATURE_TAG_V2
        || signature.signer_key_id != verifier.key_id()
        || signature.signer_key_epoch != material.installation_epoch
    {
        return Err(DeploymentControlErrorV2::ActivationKeyMismatch);
    }
    verifier.verify_domain_signature_parts(
        signature.domain_tag,
        signature.signer_key_id,
        signature.signer_key_epoch,
        signature.signature,
        CORE_SIGNATURE_TAG_V2,
        CORE_SIGNATURE_DOMAIN_V2,
        payload_digest,
    )?;
    let canonical_bytes = encode_core_complete(&material, payload_digest, signature)?;
    if original.is_some_and(|bytes| bytes != canonical_bytes) {
        return Err(DeploymentControlErrorV2::NonCanonicalLedgerEncoding);
    }
    let signed_digest = hash_domain(CORE_SIGNED_DOMAIN_V2, &canonical_bytes);
    Ok(DurableDeploymentTransactionCoreV2 {
        canonical_bytes,
        payload_digest,
        signed_digest,
        material,
    })
}

fn validate_signing_authority(
    material: &DurableDeploymentTransactionCoreMaterialV2,
    authority: &dyn NativeDeploymentSigningAuthorityV2,
    verifier: &DeploymentActivationVerifierV2,
) -> Result<(), DeploymentControlErrorV2> {
    if authority.installation_id() != *material.installation_id.as_bytes()
        || authority.key_epoch() != material.installation_epoch
        || Ed25519KeyIdV2::new(authority.key_id()) != verifier.key_id()
        || verifier.installation_id() != material.installation_id
        || verifier.key_epoch() != material.installation_epoch
    {
        return Err(DeploymentControlErrorV2::ActivationKeyMismatch);
    }
    Ok(())
}

fn validate_core_material(
    value: &DurableDeploymentTransactionCoreMaterialV2,
    release_trust_root_set: &ReleaseTrustRootSetV2,
) -> Result<(), DeploymentControlErrorV2> {
    let transaction = &value.signed_transaction;
    let intent = transaction.intent();
    let intent_material = intent.material();
    let transaction_id = intent.transaction_id();
    let expected_pre_state = intent.expected_pre_state();
    let recovery_projection = value.recovery_target.intent_projection()?;
    let desired = value.desired_manifest.material();
    value.desired_manifest.validate_for_normal_transaction()?;
    if is_zero(value.installation_id.as_bytes())
        || value.installation_epoch == 0
        || value.created_at_unix_ms == 0
        || value.watchdog_deadline_monotonic_ns == 0
        || is_zero(value.watchdog_boot_id.as_bytes())
        || is_zero(value.watchdog_process_identity_digest.as_bytes())
        || value.installation_id != intent.installation_id()
        || value.installation_epoch != expected_pre_state.installation_epoch()
        || value.installation_epoch != desired.bootstrap_tcb_lock.installation_epoch()
        || transaction_id != value.initial_owner.transaction_id()
        || value.initial_owner.owner_role() != DeploymentOwnerRoleV2::Helper
        || value.initial_owner.identity().executable_identity_digest()
            != desired
                .bootstrap_tcb_lock
                .deploy_helper_identity()
                .identity_digest()
        || value.watchdog_process_identity_digest
            != desired
                .bootstrap_tcb_lock
                .deploy_watchdog_identity()
                .identity_digest()
        || value.watchdog_deadline_monotonic_ns
            < value.initial_owner.heartbeat_deadline_monotonic_ns()
        || value.created_at_unix_ms < intent_material.not_before_unix_ms
        || value.created_at_unix_ms > intent_material.expires_at_unix_ms
        || value.desired_manifest.signed_digest() != intent_material.desired_manifest_digest
        || recovery_projection.digest() != intent_material.recovery_target.digest()
        || value.migration_plan.digest() != intent_material.migration_plan_digest
        || value.artifact_install_plan.digest() != intent_material.artifact_install_plan_digest
        || value.service_transition_plan.digest() != intent_material.service_transition_plan_digest
        || value.isolated_e2e_plan.digest() != intent_material.isolated_e2e_plan_digest
        || value.evidence_contract.digest() != intent_material.evidence_contract_digest
        || value.protected_acceptance_plan.digest()
            != intent_material.protected_acceptance_plan_digest
        || value.desired_manifest.material().target_platform != intent_material.target_platform
        || value.recovery_target.manifest().material().target_platform
            != intent_material.target_platform
        || value.initial_owner.identity().boot_id() == value.watchdog_boot_id
        || value
            .initial_owner
            .operation_nonce()
            .as_bytes()
            .iter()
            .all(|byte| *byte == 0)
    {
        return Err(DeploymentControlErrorV2::InvalidDeploymentTransaction);
    }
    validate_expected_pre_state_binding(expected_pre_state, value, release_trust_root_set)?;
    Ok(())
}

fn validate_expected_pre_state_binding(
    expected: &ExpectedPreStateV2,
    core: &DurableDeploymentTransactionCoreMaterialV2,
    release_trust_root_set: &ReleaseTrustRootSetV2,
) -> Result<(), DeploymentControlErrorV2> {
    let desired = core.desired_manifest.material();
    if expected.deploy_helper_identity() != desired.bootstrap_tcb_lock.deploy_helper_identity()
        || expected.deploy_watchdog_identity()
            != desired.bootstrap_tcb_lock.deploy_watchdog_identity()
        || expected.release_trust_root_set_digest()
            != release_trust_root_set.release_trust_root_set_digest()
    {
        return Err(DeploymentControlErrorV2::InvalidDeploymentTransaction);
    }
    Ok(())
}

pub fn staging_selector_v2(
    transaction_id: Nonce32V2,
    staging_tree_digest: Digest32V2,
) -> Digest32V2 {
    let mut hash = Sha256::new();
    hash.update(STAGING_SELECTOR_DOMAIN_V2);
    hash.update(transaction_id.as_bytes());
    hash.update(staging_tree_digest.as_bytes());
    Digest32V2::new(hash.finalize().into())
}

fn encode_core_payload(
    value: &DurableDeploymentTransactionCoreMaterialV2,
) -> Result<Vec<u8>, DeploymentControlErrorV2> {
    let transaction_id = value.signed_transaction.intent().transaction_id();
    let staging_tree_digest = value
        .signed_transaction
        .intent()
        .material()
        .staging_tree_digest;
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(CORE_PAYLOAD_FIELDS_V2)
        .and_then(|encoder| encoder.u16(CORE_SCHEMA_VERSION_V2))
        .and_then(|encoder| encoder.u16(CORE_OBJECT_DOMAIN_TAG_V2))
        .and_then(|encoder| encoder.bytes(value.installation_id.as_bytes()))
        .and_then(|encoder| encoder.u64(value.installation_epoch))
        .and_then(|encoder| encoder.bytes(transaction_id.as_bytes()))
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentTransaction)?;
    encoder
        .writer_mut()
        .extend_from_slice(value.signed_transaction.canonical_bytes());
    encoder
        .bytes(staging_selector_v2(transaction_id, staging_tree_digest).as_bytes())
        .and_then(|encoder| encoder.bytes(staging_tree_digest.as_bytes()))
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentTransaction)?;
    encoder
        .writer_mut()
        .extend_from_slice(value.desired_manifest.canonical_bytes());
    encode_recovery_target(&mut encoder, &value.recovery_target)?;
    for nested in [
        value.migration_plan.canonical_bytes(),
        value.artifact_install_plan.canonical_bytes(),
        value.service_transition_plan.canonical_bytes(),
        value.isolated_e2e_plan.canonical_bytes(),
        value.evidence_contract.canonical_bytes(),
        value.protected_acceptance_plan.canonical_bytes(),
        value
            .signed_transaction
            .intent()
            .expected_pre_state()
            .canonical_bytes(),
    ] {
        encoder.writer_mut().extend_from_slice(nested);
    }
    encode_owner(&mut encoder, value.initial_owner)?;
    encoder
        .bytes(value.watchdog_boot_id.as_bytes())
        .and_then(|encoder| encoder.bytes(value.watchdog_process_identity_digest.as_bytes()))
        .and_then(|encoder| encoder.u64(value.watchdog_deadline_monotonic_ns))
        .and_then(|encoder| encoder.u64(value.created_at_unix_ms))
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentTransaction)?;
    Ok(encoder.into_writer())
}

#[allow(clippy::too_many_arguments)]
fn decode_core_payload(
    bytes: &[u8],
    rollback_grant_verifier: &DeploymentAuthorizationVerifierV2,
    transaction_authorization_verifier: &DeploymentAuthorizationVerifierV2,
    release_trust_root_set: &ReleaseTrustRootSetV2,
    manifest_verification_time_unix_ms: u64,
) -> Result<DurableDeploymentTransactionCoreMaterialV2, DeploymentControlErrorV2> {
    let mut decoder = minicbor::Decoder::new(bytes);
    expect_array(&mut decoder, CORE_PAYLOAD_FIELDS_V2)?;
    if decode_u16(&mut decoder)? != CORE_SCHEMA_VERSION_V2
        || decode_u16(&mut decoder)? != CORE_OBJECT_DOMAIN_TAG_V2
    {
        return Err(DeploymentControlErrorV2::InvalidDeploymentTransaction);
    }
    let installation_id = decode_digest(&mut decoder)?;
    let installation_epoch = decode_u64(&mut decoder)?;
    let transaction_id = decode_nonce(&mut decoder)?;
    let signed_transaction = decode_nested(&mut decoder, |bytes| {
        DeploymentTransactionV2::from_canonical_bytes(
            bytes,
            rollback_grant_verifier,
            transaction_authorization_verifier,
        )
    })?;
    let encoded_staging_selector = decode_digest(&mut decoder)?;
    let staging_tree_digest = decode_digest(&mut decoder)?;
    if transaction_id != signed_transaction.intent().transaction_id()
        || staging_tree_digest != signed_transaction.intent().material().staging_tree_digest
        || encoded_staging_selector != staging_selector_v2(transaction_id, staging_tree_digest)
    {
        return Err(DeploymentControlErrorV2::InvalidDeploymentTransaction);
    }
    let desired_manifest = decode_nested(&mut decoder, |bytes| {
        SecurityStateManifestV2::from_canonical_bytes(
            bytes,
            release_trust_root_set,
            manifest_verification_time_unix_ms,
        )
    })?;
    let recovery_target = decode_recovery_target(
        &mut decoder,
        release_trust_root_set,
        manifest_verification_time_unix_ms,
    )?;
    let migration_plan = decode_nested(&mut decoder, MigrationPlanV2::from_canonical_bytes)?;
    let artifact_install_plan =
        decode_nested(&mut decoder, ArtifactInstallPlanV2::from_canonical_bytes)?;
    let service_transition_plan =
        decode_nested(&mut decoder, ServiceTransitionPlanV2::from_canonical_bytes)?;
    let isolated_e2e_plan = decode_nested(&mut decoder, IsolatedE2EPlanV2::from_canonical_bytes)?;
    let evidence_contract = decode_nested(&mut decoder, EvidenceContractV2::from_canonical_bytes)?;
    let protected_acceptance_plan = decode_nested(
        &mut decoder,
        ProtectedAcceptancePlanV2::from_canonical_bytes,
    )?;
    let expected_pre_state = decode_nested(&mut decoder, ExpectedPreStateV2::from_canonical_bytes)?;
    if expected_pre_state != *signed_transaction.intent().expected_pre_state() {
        return Err(DeploymentControlErrorV2::InvalidDeploymentTransaction);
    }
    let initial_owner = decode_owner(&mut decoder)?;
    let watchdog_boot_id = decode_digest(&mut decoder)?;
    let watchdog_process_identity_digest = decode_digest(&mut decoder)?;
    let watchdog_deadline_monotonic_ns = decode_u64(&mut decoder)?;
    let created_at_unix_ms = decode_u64(&mut decoder)?;
    require_eof(&decoder, bytes)?;
    Ok(DurableDeploymentTransactionCoreMaterialV2 {
        installation_id,
        installation_epoch,
        signed_transaction,
        desired_manifest,
        recovery_target,
        migration_plan,
        artifact_install_plan,
        service_transition_plan,
        isolated_e2e_plan,
        evidence_contract,
        protected_acceptance_plan,
        initial_owner,
        watchdog_boot_id,
        watchdog_process_identity_digest,
        watchdog_deadline_monotonic_ns,
        created_at_unix_ms,
    })
}

fn encode_recovery_target(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    target: &DurableDeploymentRecoveryTargetV2,
) -> Result<(), DeploymentControlErrorV2> {
    match target {
        DurableDeploymentRecoveryTargetV2::NormalRollbackManifest { rollback_manifest } => {
            encoder
                .array(2)
                .and_then(|encoder| encoder.u16(1))
                .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentTransaction)?;
            encoder
                .writer_mut()
                .extend_from_slice(rollback_manifest.canonical_bytes());
        }
        DurableDeploymentRecoveryTargetV2::BootstrapBridgeRestore {
            bridge_manifest,
            maintenance_intent_signed_digest,
            bridge_genesis_ledger_record_signed_digest,
            bootstrap_slot_closure_digest,
            premaintenance_runtime_manifest_digest,
        } => {
            encoder
                .array(6)
                .and_then(|encoder| encoder.u16(2))
                .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentTransaction)?;
            encoder
                .writer_mut()
                .extend_from_slice(bridge_manifest.canonical_bytes());
            encoder
                .bytes(maintenance_intent_signed_digest.as_bytes())
                .and_then(|encoder| {
                    encoder.bytes(bridge_genesis_ledger_record_signed_digest.as_bytes())
                })
                .and_then(|encoder| encoder.bytes(bootstrap_slot_closure_digest.as_bytes()))
                .and_then(|encoder| {
                    encoder.bytes(premaintenance_runtime_manifest_digest.as_bytes())
                })
                .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentTransaction)?;
        }
    }
    Ok(())
}

fn decode_recovery_target(
    decoder: &mut minicbor::Decoder<'_>,
    release_trust_root_set: &ReleaseTrustRootSetV2,
    verification_time_unix_ms: u64,
) -> Result<DurableDeploymentRecoveryTargetV2, DeploymentControlErrorV2> {
    let length = decoder
        .array()
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentTransaction)?
        .ok_or(DeploymentControlErrorV2::InvalidDeploymentTransaction)?;
    match (decode_u16(decoder)?, length) {
        (1, 2) => DurableDeploymentRecoveryTargetV2::normal(decode_nested(decoder, |bytes| {
            SecurityStateManifestV2::from_canonical_bytes(
                bytes,
                release_trust_root_set,
                verification_time_unix_ms,
            )
        })?),
        (2, 6) => DurableDeploymentRecoveryTargetV2::bootstrap_bridge_restore(
            decode_nested(decoder, |bytes| {
                SecurityStateManifestV2::from_canonical_bytes(
                    bytes,
                    release_trust_root_set,
                    verification_time_unix_ms,
                )
            })?,
            decode_digest(decoder)?,
            decode_digest(decoder)?,
            decode_digest(decoder)?,
            decode_digest(decoder)?,
        ),
        _ => Err(DeploymentControlErrorV2::InvalidDeploymentTransaction),
    }
}

fn encode_owner(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    owner: DeploymentOwnerClaimV2,
) -> Result<(), DeploymentControlErrorV2> {
    let identity = owner.identity();
    encoder
        .array(9)
        .and_then(|encoder| encoder.bytes(owner.transaction_id().as_bytes()))
        .and_then(|encoder| encoder.u16(owner.owner_role() as u16))
        .and_then(|encoder| encoder.bytes(identity.boot_id().as_bytes()))
        .and_then(|encoder| encoder.u64(identity.pid()))
        .and_then(|encoder| encoder.u64(identity.process_start_identity()))
        .and_then(|encoder| encoder.bytes(identity.executable_identity_digest().as_bytes()))
        .and_then(|encoder| encoder.bytes(owner.operation_nonce().as_bytes()))
        .and_then(|encoder| encoder.u64(owner.heartbeat_generation()))
        .and_then(|encoder| encoder.u64(owner.heartbeat_deadline_monotonic_ns()))
        .map(|_| ())
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentTransaction)
}

fn decode_owner(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<DeploymentOwnerClaimV2, DeploymentControlErrorV2> {
    expect_array(decoder, 9)?;
    let transaction_id = decode_nonce(decoder)?;
    let owner_role = match decode_u16(decoder)? {
        1 => DeploymentOwnerRoleV2::Helper,
        2 => DeploymentOwnerRoleV2::Watchdog,
        _ => return Err(DeploymentControlErrorV2::InvalidDeploymentTransaction),
    };
    DeploymentOwnerClaimV2::new(
        transaction_id,
        owner_role,
        decode_digest(decoder)?,
        decode_u64(decoder)?,
        decode_u64(decoder)?,
        decode_digest(decoder)?,
        decode_nonce(decoder)?,
        decode_u64(decoder)?,
        decode_u64(decoder)?,
    )
    .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentTransaction)
}

fn encode_core_complete(
    material: &DurableDeploymentTransactionCoreMaterialV2,
    payload_digest: Digest32V2,
    signature: CoreSignatureV2,
) -> Result<Vec<u8>, DeploymentControlErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(CORE_COMPLETE_FIELDS_V2)
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentTransaction)?;
    encoder
        .writer_mut()
        .extend_from_slice(&encode_core_payload(material)?);
    encoder
        .bytes(payload_digest.as_bytes())
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentTransaction)?;
    encode_core_signature(&mut encoder, signature)?;
    Ok(encoder.into_writer())
}

fn encode_core_signature(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    signature: CoreSignatureV2,
) -> Result<(), DeploymentControlErrorV2> {
    encoder
        .array(CORE_SIGNATURE_FIELDS_V2)
        .and_then(|encoder| encoder.u16(signature.domain_tag))
        .and_then(|encoder| encoder.bytes(signature.signer_key_id.as_bytes()))
        .and_then(|encoder| encoder.u64(signature.signer_key_epoch))
        .and_then(|encoder| encoder.bytes(signature.signature.as_bytes()))
        .map(|_| ())
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentTransaction)
}

fn decode_core_signature(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<CoreSignatureV2, DeploymentControlErrorV2> {
    expect_array(decoder, CORE_SIGNATURE_FIELDS_V2)?;
    Ok(CoreSignatureV2 {
        domain_tag: decode_u16(decoder)?,
        signer_key_id: decode_key_id(decoder)?,
        signer_key_epoch: decode_u64(decoder)?,
        signature: decode_signature(decoder)?,
    })
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

fn require_eof(
    decoder: &minicbor::Decoder<'_>,
    bytes: &[u8],
) -> Result<(), DeploymentControlErrorV2> {
    if decoder.position() != bytes.len() {
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
    let bytes: [u8; 32] = decoder
        .bytes()
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentTransaction)?
        .try_into()
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentTransaction)?;
    Ok(Digest32V2::new(bytes))
}

fn decode_nonce(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<Nonce32V2, DeploymentControlErrorV2> {
    let bytes: [u8; 32] = decoder
        .bytes()
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentTransaction)?
        .try_into()
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentTransaction)?;
    Ok(Nonce32V2::new(bytes))
}

fn decode_key_id(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<Ed25519KeyIdV2, DeploymentControlErrorV2> {
    let bytes: [u8; 32] = decoder
        .bytes()
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentTransaction)?
        .try_into()
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentTransaction)?;
    Ok(Ed25519KeyIdV2::new(bytes))
}

fn decode_signature(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<Ed25519SignatureV2, DeploymentControlErrorV2> {
    let bytes: [u8; 64] = decoder
        .bytes()
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentTransaction)?
        .try_into()
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentTransaction)?;
    Ok(Ed25519SignatureV2::new(bytes))
}
