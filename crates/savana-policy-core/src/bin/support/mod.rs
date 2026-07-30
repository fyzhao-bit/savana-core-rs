use std::ffi::OsString;

use savana_platform_identity::{
    harden_root_deployment_process_v2, open_native_deployment_authority_handles_v2,
    open_native_deployment_bootstrap_trust_material_v2, DeploymentApplySelectorV2,
    FixedDeploymentSpoolV2, NativeIdentityErrorV2,
};
use savana_policy_core::v2::{
    staging_selector_v2, AuthenticatedNativeDeploymentLedgerV2,
    AuthenticatedNativeDeploymentTrustV2, DeploymentControlErrorV2, DeploymentRecoveryActionV2,
    DeploymentTransactionV2, DurableDeploymentAuxiliaryEvidenceStoreV2,
    DurableDeploymentCoreKeyDiscoveryStoreV2, DurableDeploymentTransactionCoreStoreV2,
    DurableDeploymentTransactionStoreV2, DurableDeploymentTransitionStoreV2,
    DurableEvidenceGcCheckpointStoreV2, DurableInstallationEvidenceStoreV2,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeploymentEntrypointErrorV2 {
    Usage,
    Permission,
    PlatformUnavailable,
    UnsafeState,
}

impl DeploymentEntrypointErrorV2 {
    pub const fn exit_code(self) -> i32 {
        match self {
            Self::Usage => 64,
            Self::PlatformUnavailable => 69,
            Self::UnsafeState => 74,
            Self::Permission => 77,
        }
    }
}

// This module is compiled once per binary; each entry point intentionally uses
// only its own half.
#[allow(dead_code)]
pub fn run_apply(
    arguments: impl Iterator<Item = OsString>,
) -> Result<(), DeploymentEntrypointErrorV2> {
    let selector = DeploymentApplySelectorV2::parse_arguments(arguments)
        .map_err(|_| DeploymentEntrypointErrorV2::Usage)?;
    harden_root_deployment_process_v2().map_err(map_hardening_error)?;
    let spool = FixedDeploymentSpoolV2::open_fixed_platform().map_err(map_native_state_error)?;
    let staged = spool
        .open_transaction(selector)
        .map_err(map_native_state_error)?;
    if staged.staging_id() != selector || staged.descriptor_bytes().is_empty() {
        return Err(DeploymentEntrypointErrorV2::UnsafeState);
    }
    let mut authorities =
        open_native_deployment_authority_handles_v2().map_err(map_native_state_error)?;
    let ledger = AuthenticatedNativeDeploymentLedgerV2::open_fixed_platform(&mut authorities)
        .map_err(map_deployment_control_error)?;
    let trust_material =
        open_native_deployment_bootstrap_trust_material_v2().map_err(map_native_state_error)?;
    let trust = AuthenticatedNativeDeploymentTrustV2::verify(&trust_material)
        .map_err(map_deployment_control_error)?;
    let (rollback_verifier, transaction_verifier) = trust
        .transaction_authorization_verifiers(staged.descriptor_bytes())
        .map_err(map_deployment_control_error)?;
    let transaction = DeploymentTransactionV2::from_canonical_bytes(
        staged.descriptor_bytes(),
        &rollback_verifier,
        &transaction_verifier,
    )
    .map_err(map_deployment_control_error)?;
    transaction
        .validate_authenticated_pre_state(
            ledger.snapshot().selected_record(),
            trust
                .deployment_trust_root_set()
                .binding()
                .member_set_digest(),
            trust
                .activation_trust_root_set()
                .binding()
                .member_set_digest(),
            trust
                .release_trust_root_set()
                .release_trust_root_set_digest(),
        )
        .map_err(map_deployment_control_error)?;
    let expected_selector = staging_selector_v2(
        transaction.intent().transaction_id(),
        transaction.intent().material().staging_tree_digest,
    );
    if selector.as_bytes() != expected_selector.as_bytes() {
        return Err(DeploymentEntrypointErrorV2::UnsafeState);
    }
    let activation_verifier = ledger.activation_verifier().clone();
    let transaction_cores = DurableDeploymentTransactionCoreStoreV2::open_fixed_platform(
        activation_verifier.clone(),
        rollback_verifier,
        transaction_verifier,
        trust.deployment_trust_root_set().clone(),
        trust.activation_trust_root_set().clone(),
        trust.release_trust_root_set().clone(),
    )
    .map_err(map_deployment_control_error)?;
    let transaction_heads =
        DurableDeploymentTransactionStoreV2::open_fixed_platform(activation_verifier.clone())
            .map_err(map_deployment_control_error)?;
    let gc_checkpoints =
        DurableEvidenceGcCheckpointStoreV2::open_fixed_platform(activation_verifier.clone())
            .map_err(map_deployment_control_error)?;
    let installation_evidence =
        DurableInstallationEvidenceStoreV2::open_fixed_platform(activation_verifier)
            .map_err(map_deployment_control_error)?;
    let auxiliary_evidence = DurableDeploymentAuxiliaryEvidenceStoreV2::open_fixed_platform()
        .map_err(map_deployment_control_error)?;
    let _transition_store = DurableDeploymentTransitionStoreV2::new_with_core_and_evidence_stores(
        ledger.into_ledger_store(),
        transaction_heads,
        transaction_cores,
        gc_checkpoints,
        installation_evidence,
        auxiliary_evidence,
    );
    Err(DeploymentEntrypointErrorV2::PlatformUnavailable)
}

#[allow(dead_code)]
pub fn run_watchdog(
    mut arguments: impl Iterator<Item = OsString>,
) -> Result<(), DeploymentEntrypointErrorV2> {
    if arguments.next().is_none() || arguments.next().is_some() {
        return Err(DeploymentEntrypointErrorV2::Usage);
    }
    harden_root_deployment_process_v2().map_err(map_hardening_error)?;
    let mut authorities =
        open_native_deployment_authority_handles_v2().map_err(map_native_state_error)?;
    let ledger = AuthenticatedNativeDeploymentLedgerV2::open_fixed_platform(&mut authorities)
        .map_err(map_deployment_control_error)?;
    let trust_material =
        open_native_deployment_bootstrap_trust_material_v2().map_err(map_native_state_error)?;
    let trust = AuthenticatedNativeDeploymentTrustV2::verify(&trust_material)
        .map_err(map_deployment_control_error)?;
    let transaction_binding = {
        let projection = ledger.snapshot().selected_record().projection();
        (
            projection.transaction_id(),
            projection.transaction_head_digest(),
        )
    };
    let recovery_plan = match transaction_binding {
        (None, None) => ledger
            .recovery_plan_without_transaction()
            .map_err(map_deployment_control_error)?,
        (Some(transaction_id), Some(head_digest)) => {
            let activation_verifier = ledger.activation_verifier().clone();
            let transaction_heads = DurableDeploymentTransactionStoreV2::open_fixed_platform(
                activation_verifier.clone(),
            )
            .map_err(map_deployment_control_error)?;
            let selected_head = transaction_heads
                .load_head(head_digest)
                .map_err(map_deployment_control_error)?;
            if selected_head.transaction_id() != transaction_id {
                return Err(DeploymentEntrypointErrorV2::UnsafeState);
            }
            let key_discovery = DurableDeploymentCoreKeyDiscoveryStoreV2::open_fixed_platform(
                activation_verifier.clone(),
            )
            .map_err(map_deployment_control_error)?;
            let key_refs = key_discovery
                .load_authorization_key_refs(selected_head.core_signed_digest())
                .map_err(map_deployment_control_error)?;
            let (rollback_verifier, transaction_verifier) = trust
                .transaction_authorization_verifiers_for_key_refs(&key_refs)
                .map_err(map_deployment_control_error)?;
            let transaction_cores = DurableDeploymentTransactionCoreStoreV2::open_fixed_platform(
                activation_verifier.clone(),
                rollback_verifier,
                transaction_verifier,
                trust.deployment_trust_root_set().clone(),
                trust.activation_trust_root_set().clone(),
                trust.release_trust_root_set().clone(),
            )
            .map_err(map_deployment_control_error)?;
            let gc_checkpoints = DurableEvidenceGcCheckpointStoreV2::open_fixed_platform(
                activation_verifier.clone(),
            )
            .map_err(map_deployment_control_error)?;
            let installation_evidence =
                DurableInstallationEvidenceStoreV2::open_fixed_platform(activation_verifier)
                    .map_err(map_deployment_control_error)?;
            let auxiliary_evidence =
                DurableDeploymentAuxiliaryEvidenceStoreV2::open_fixed_platform()
                    .map_err(map_deployment_control_error)?;
            let transition_store =
                DurableDeploymentTransitionStoreV2::new_with_core_and_evidence_stores(
                    ledger.into_ledger_store(),
                    transaction_heads,
                    transaction_cores,
                    gc_checkpoints,
                    installation_evidence,
                    auxiliary_evidence,
                );
            let (_, rollback_authority) = authorities.split();
            transition_store
                .load_recovery_plan(rollback_authority)
                .map_err(map_deployment_control_error)?
        }
        _ => return Err(DeploymentEntrypointErrorV2::UnsafeState),
    };
    match recovery_plan.action() {
        DeploymentRecoveryActionV2::PublishRuntimeReadiness => Ok(()),
        DeploymentRecoveryActionV2::HoldBootstrapFence
        | DeploymentRecoveryActionV2::HoldFailedSafe => {
            Err(DeploymentEntrypointErrorV2::UnsafeState)
        }
        _ => Err(DeploymentEntrypointErrorV2::PlatformUnavailable),
    }
}

fn map_hardening_error(error: NativeIdentityErrorV2) -> DeploymentEntrypointErrorV2 {
    match error {
        NativeIdentityErrorV2::InvalidDeploymentInvocation => {
            DeploymentEntrypointErrorV2::Permission
        }
        _ => DeploymentEntrypointErrorV2::UnsafeState,
    }
}

fn map_native_state_error(error: NativeIdentityErrorV2) -> DeploymentEntrypointErrorV2 {
    match error {
        NativeIdentityErrorV2::NativePlatformAuthorityUnavailable => {
            DeploymentEntrypointErrorV2::PlatformUnavailable
        }
        NativeIdentityErrorV2::InvalidDeploymentInvocation => {
            DeploymentEntrypointErrorV2::Permission
        }
        _ => DeploymentEntrypointErrorV2::UnsafeState,
    }
}

fn map_deployment_control_error(error: DeploymentControlErrorV2) -> DeploymentEntrypointErrorV2 {
    match error {
        DeploymentControlErrorV2::NativeSigningAuthorityUnavailable
        | DeploymentControlErrorV2::NativeRollbackAuthorityUnavailable => {
            DeploymentEntrypointErrorV2::PlatformUnavailable
        }
        _ => DeploymentEntrypointErrorV2::UnsafeState,
    }
}
