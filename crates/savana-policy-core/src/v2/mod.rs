mod authenticated_anchor;
#[allow(dead_code)] // Stored binding resolution is consumed by the G4 intent adapter.
mod binding;
mod commit_attestation;
mod connector_registry;
mod connector_store;
mod continuation_dispatch;
mod continuation_state;
mod fused_execution_recovery;
mod fused_final_result;
pub use fused_final_result::FusedFinalResultCandidateV04;
mod fused_input_document;
mod fused_inputs;
pub use fused_execution_recovery::{FusedResultScopeV04, RecoveredFusedExecutionV04};
pub use fused_input_document::{FusedInputDocumentV04, FusedInputTextV04};
mod fused_model_exchange;
mod fused_plan_adapter;
mod fused_planning;
mod fused_recipe;
mod fused_task_compiler;
pub use fused_inputs::{
    FusedOwnedInputV04, FusedOwnedResultV04, RecoveredFusedInputV04, RecoveredFusedInputsV04,
};
pub use fused_task_compiler::{
    check_fused_owner_views_v04, check_result_operation_rule_v04, compile_fused_task_v04,
    fused_operation_derived_rules_v04, fused_owner_view_v04, FusedTaskDraftV04,
    FusedTaskOperationV04,
};
mod fused_recipe_approval;
pub use fused_model_exchange::{
    exchange_fused_model_v04, exchange_scheduled_fused_model_v04, DisabledFusedModelTransportV04,
    FusedModelExchangeOutcomeV04, FusedModelReleaseContextV04, FusedModelTransportErrorV04,
    FusedModelTransportV04, MAX_FUSED_MODEL_EXCHANGE_MS_V04, MAX_FUSED_MODEL_REPLY_BYTES_V04,
};
pub use fused_plan_adapter::{lower_fused_plan_v04, lower_fused_plan_with_tools_v04};
pub use fused_planning::{
    fused_execution_commitment_v04, ActiveFusedPlanV04, FusedDeliverySlotV04,
    FusedExecutionBindingV04, FusedFinalReleaseV04, FusedOperationRefV04, FusedPlanningProfileV04,
    FusedPlanningResultV04, FusedPlanningStatusV04, FusedPlanningUpdateV04, FusedScheduledWorkV04,
    VerifiedFusedPlanningProfileV04,
};
pub use fused_recipe::FusedExecutionRecipeV04;
pub use fused_recipe_approval::{FusedRecipeApprovalV04, FusedRecipeBindingV04};
mod managed_admin;
mod managed_execution;
pub use managed_admin::{
    ManagedAdminCommandV04, ManagedAdminOperationV04, ManagedAdminReceiptV04,
    ManagedAdminResultV04, ManagedAdminValueV04, VerifiedManagedAdminCommandV04,
};
mod managed_resource;
pub use continuation_dispatch::{
    ContinuationChargeBasisV04, ContinuationChargeRuleV04, ContinuationDispatchPolicyV04,
    ContinuationMagnitudeV04, ContinuationResourceEvidenceV04, ContinuationResourceFactV04,
    VerifiedContinuationDispatchPolicyV04,
};
pub use continuation_state::{
    ContinuationStorageProfileV04, ContinuationStorageUpdateV04, ContinuationStorageViewV04,
    VerifiedContinuationStorageV04,
};
pub use managed_execution::ManagedExecutionSnapshotV04;
pub use managed_resource::{
    managed_resource_locator_v04, managed_resource_selector_digest_v04, ManagedInputProjectionV04,
    ManagedResourceViewV04, ManagedSourcePolicyV04, VerifiedManagedSourceV04,
};
mod declassification;
mod deployment_authorization;
mod deployment_control;
mod deployment_failure;
mod deployment_ledger;
mod deployment_ledger_v3;
#[cfg(target_os = "linux")]
mod deployment_staging_v3;
#[cfg(target_os = "linux")]
pub use deployment_staging_v3::{
    VerifiedDeploymentStagingV3, VerifiedNativeDeploymentPreparationV3,
};
#[cfg(test)]
mod deployment_v3_test_support;
pub use deployment_ledger_v3::{
    DeploymentLedgerHistoryV3, DeploymentLedgerMaterialV3, DeploymentLedgerStateV3,
    VerifiedDeploymentLedgerRecordV3,
};
mod deployment_evidence_v3;
pub use deployment_evidence_v3::{
    CommitClaimsV3, VerificationClaimsV3, VerifiedCommitAttestationV3,
    VerifiedVerificationEvidenceV3,
};
mod deployment_limits;
mod deployment_manifest;
mod deployment_manifest_claim;
mod deployment_manifest_closure;
mod deployment_manifest_compatibility;
mod deployment_manifest_primitives;
#[allow(dead_code)] // Consumed by the closed staging/install tree verifier.
mod deployment_merkle;
mod deployment_native_bootstrap;
mod deployment_network;
mod deployment_operational_trust;
mod deployment_plan;
mod deployment_recovery;
mod deployment_release_trust;
mod deployment_runtime_evidence;
mod deployment_runtime_evidence_store;
mod deployment_schema;
mod deployment_store;
mod deployment_transaction;
mod deployment_transaction_core;
mod deployment_transaction_core_store;
mod deployment_transaction_intent;
mod deployment_transaction_store;
mod deployment_transition_store;
mod deployment_trust;
#[allow(dead_code)] // Descriptor activation remains private until registry verification is wired.
mod descriptor;
#[allow(dead_code)] // Closed until the G4 verified-state adapter consumes these primitives.
mod digest;
#[allow(dead_code)] // Consumed by the durable G7 transaction adapter.
mod dispatch;
#[allow(dead_code)] // Wired by the V2 kerneld transaction adapter.
mod durable;
mod evidence_gc_checkpoint;
mod evidence_gc_checkpoint_store;
mod filesystem_startup;
mod installation_evidence;
mod installation_evidence_store;
#[allow(dead_code)] // Intent construction is consumed by the kerneld transaction adapter.
mod intent;
mod labels;
mod leak_gate;

mod control_selection;
#[allow(dead_code)] // Closed AST is activated only through the G4 verified-state adapter.
mod ontology;
mod production;
#[allow(dead_code)] // Source minting remains private until verified G4/G6/G7 capabilities exist.
mod provenance;
#[allow(dead_code)] // Durable quota ledger is wired by the G7 transaction adapter.
mod quota;
mod recovery_rollback_readiness;
mod rollback_verification_attestation;
mod rollback_verification_evidence;
mod store_compatibility;
mod task_authorization;
mod task_issuance;
mod task_state;
pub use task_issuance::PendingTaskAuthorizationV2;
pub use task_state::{
    TaskAuthorizationStateV2, TaskDispatchAuthorizationV2, TaskDispatchBindingV2,
    VerifiedTaskOutcomeV2,
};
mod transition_audit;
#[allow(dead_code)] // Activated by the G5 evaluation transaction.
mod validator;
mod value;
mod verification_evidence;
pub use control_selection::{
    authorization_digest_v2, checked_control_endorsements_v2, AuthorizationDigestV2,
    ControlEndorsementV2, ControlEvidenceV2, ControlFacetV2, ControlSelectionV2,
};
pub use task_authorization::{
    task_effect_set_v2, CompleteContractDomainV2, TaskAuthorizationErrorV2, TaskMatchContextV2,
    VerifiedTaskAuthorizationV2, VerifiedTaskMatchV2,
};
#[cfg(test)]
mod task_authorization_tests;

pub use authenticated_anchor::{AuthenticatedFileAnchorErrorV2, AuthenticatedFileAnchorV2};
pub use binding::{
    ClosedCardinalityV2, PlannerSlotConfidentialityV2, ResolvedSlotRelationSemanticV2,
    ResolvedStoredArgumentV2, ResolvedStoredTokenV2, StoredBindingResolverV2, StoredValueRecordV2,
    StoredVaultCredentialV2, VerifiedInternalSlotMaterialV2, VerifiedPlanArgumentV2,
    VerifiedRequiredTokenV2, VerifiedResolvedRelationSetV2, VerifiedStoredBindingsV2,
};
pub use commit_attestation::{ClosedCommitDigestFieldV2, CommitAttestationV2};
pub use connector_registry::{
    connector_host_allowlist_digest_v2, user_tier_host_allowed_v2, BoundedConnectorHostV2,
    BoundedConnectorNameV2, BoundedConnectorUrlV2, ConnectorDescriptorV2, ConnectorRegistryDeltaV2,
    ConnectorRegistryStateV2, ConnectorStructuralRoleV2, ConnectorTierV2, ConnectorTransportV2,
    PreparedConnectorRegistryDeltaV2,
};
#[cfg(any(test, feature = "test-support"))]
pub use connector_store::TestConnectorStoreCrashPointV2;
pub use connector_store::{
    ConnectorStoreRevisionV2, DurableConnectorRegistryStoreV2,
    MAX_CONNECTOR_AUTHORITY_STATE_BYTES_V2,
};
pub use declassification::{
    declassification_implementation_digest_v2, ClosedDeclassificationPurposeV2,
    DeclassificationRuleSetV2, DeclassificationRuleV2,
};
pub use deployment_authorization::{
    DeploymentAuthorizationKeyRefsV2, DeploymentAuthorizationVerifierV2, DeploymentTransactionV2,
    RecoveryPhaseHighWaterV2, RollbackGrantV2,
};
pub use deployment_control::{
    select_authenticated_ledger_slot_v2, DeploymentBranchV2, DeploymentControlErrorV2,
    DeploymentLedgerProjectionV2, DeploymentOwnerClaimV2, DeploymentOwnerIdentityV2,
    DeploymentOwnerRoleV2, DeploymentPhaseV2, DeploymentTransitionV2, LedgerSlotIdV2,
    RollbackGrantStateV2, VerifiedLedgerSlotV2,
};
pub use deployment_failure::{ClosedDeploymentFailureClassV2, DeploymentFailureEvidenceV2};
pub use deployment_ledger::{
    ActiveActivationV2, BootstrapBridgeActivationV2, BootstrapBridgeRestoreProvenanceV2,
    ClosedSecurityDomainV2, DeploymentActivationUpdateV2, DeploymentActivationVerifierV2,
    DeploymentLedgerRecordV2, HighWaterEntryV2, HighestEverV2, RollbackOriginPhaseV2,
    SignedLedgerSlotV2,
};
pub use deployment_limits::DeploymentHardLimitsV2;
pub use deployment_manifest::{
    InstallationClassV2, ManifestComponentSignatureV2, SecurityStateManifestMaterialV2,
    SecurityStateManifestV2,
};
pub use deployment_manifest_claim::{
    AgentClaimCompatibilityDirectionV2, AgentClaimCompatibilityMaterialV2,
    AgentClaimCompatibilitySetV2, AgentClaimCompatibilityV2, AgentViewProjectionSetItemV2,
    VaultKeyReadSetItemV2,
};
pub use deployment_manifest_closure::{
    BinaryClosureV2, BootstrapTcbLockV2, PlatformClosureV2, SecurityStateClosureV2,
};
pub use deployment_manifest_compatibility::{
    PersistentStoreCompatibilitySetV2, PersistentStoreCompatibilityV2,
};
pub use deployment_manifest_primitives::{
    ArtifactSetIdentityV2, ClosedDigestRuleV2, InclusiveEpochRangeV2, SourceLockV2,
    VersionedIdentityV2,
};
pub use deployment_native_bootstrap::{
    AuthenticatedNativeDeploymentLedgerV2, AuthenticatedNativeDeploymentTrustV2,
};
pub use deployment_network::{
    measured_model_destination_ips_v2, parse_measured_model_connect_addresses_v2,
    validate_measured_model_connect_addresses_v2, MeasuredModelNetworkErrorV2,
    MAX_MODEL_CONNECT_ADDRESSES_V2,
};
pub use deployment_operational_trust::{
    OperationalTrustRootPurposeV2, OperationalTrustRootSetBindingV2, OperationalTrustRootSetItemV2,
    OperationalTrustRootSetV2,
};
pub use deployment_plan::{
    ArtifactInstallOperationV2, ArtifactInstallPlanV2, ClosedDeploymentServiceIdV2,
    ClosedE2ECaseV2, ClosedEvidenceRetentionClassV2, ClosedProtectedAcceptanceCaseV2,
    EvidenceContractV2, IsolatedE2EPlanV2, MigrationPlanV2, MigrationStepV2, PlatformTupleV2,
    ProtectedAcceptancePlanV2, ServiceTransitionPlanV2,
};
pub use deployment_recovery::{AuthenticatedDeploymentRecoveryPlanV2, DeploymentRecoveryActionV2};
pub use deployment_release_trust::{
    ComponentSignerAuthorizationV2, InstallerOrMdmVerifierV2, ManifestComponentKindV2,
    ManifestComponentRefV2, ManifestDomainSignatureV2, ReleaseRootKeyV2, ReleaseSigningRoleV2,
    ReleaseTrustRootSetV2,
};
pub use deployment_runtime_evidence::{
    BootstrapBridgeRestoreIntegrityV2, FrozenEffectWorkItemV2, FrozenEffectWorkKindV2,
    FrozenEffectWorkSetV2, NativeControlMeasurementSetItemV2, NativeControlMeasurementSetV2,
    RoleJournalReconciliationItemV2, RoleJournalReconciliationV2,
};
pub use deployment_runtime_evidence_store::DurableDeploymentAuxiliaryEvidenceStoreV2;
pub use deployment_schema::{
    ArtifactIdentityV2, ClosedArtifactTypeV2, ClosedLogicalPathIdV2, ClosedStagingPathIdV2,
    ClosedStoreIdV2, ClosedTargetArchitectureV2, ClosedTargetOsV2, FileTreeEntryV2, FileTreeV2,
    PlatformLockV2, StagingEntryV2, StagingTreeV2,
};
#[cfg(any(test, feature = "test-support"))]
pub use deployment_store::TestNativeRollbackAuthorityV2;
pub use deployment_store::{
    AuthenticatedDeploymentLedgerSnapshotV2, DeploymentLedgerStoreV2, NativeRollbackAuthorityV2,
};
pub use deployment_transaction::{
    ClosedDurableDeploymentStepV2, DurableDeploymentEvidenceRefV2,
    DurableDeploymentTransactionRecordV2,
};
pub use deployment_transaction_core::{
    staging_selector_v2, DurableDeploymentRecoveryTargetV2,
    DurableDeploymentTransactionCoreMaterialV2, DurableDeploymentTransactionCoreV2,
};
pub use deployment_transaction_core_store::{
    DurableDeploymentCoreKeyDiscoveryStoreV2, DurableDeploymentTransactionCoreStoreV2,
};
pub use deployment_transaction_intent::{
    DeploymentRecoveryTargetV2, DeploymentTransactionIntentMaterialV2,
    DeploymentTransactionIntentV2, ExpectedPreStateV2,
};
pub use deployment_transaction_store::DurableDeploymentTransactionStoreV2;
pub use deployment_transition_store::DurableDeploymentTransitionStoreV2;
#[cfg(any(test, feature = "test-support"))]
pub use deployment_transition_store::{
    TestAbortedCompactionCrashPointV2, TestDeploymentCrashPointV2, TestDeploymentGcCrashPointV2,
};
pub use deployment_trust::{
    listener_identity_digest_v2, ClosedServiceEdgeIdV2, ClosedServiceIdV2, DeploymentTrustErrorV2,
    PlatformDeploymentTrustV2, PlatformServiceObservationV2, ServiceAuthorityHandlesV2,
    ServiceDeploymentLockV2, ServiceEdgeLockV2, VerifiedDaemonStartupV2,
    VerifiedDeploymentManifestV2,
};
pub use descriptor::{
    descriptor_digest_v2, ActiveToolRecordV2, ActiveToolRegistryV2, BoundedConnectorRetryPolicyV2,
    ExecutorIdempotencyContractV2, InternalValidatorDeclarationV2, SignedToolDescriptorV2,
    UnsignedToolDescriptorV2, VerifiedManifestToolConstraintSetV2,
    VerifiedManifestToolConstraintV2, VerifiedPolicyToolActivationV2, VerifiedPolicyToolSetV2,
    VerifiedRegistryPublisherV2, VerifiedToolDescriptorV2, VerifiedToolRegistryV2,
};
pub use digest::{
    evidence_digest_v2, token_set_digest_v2, EvidenceDigestEntryV2, TokenSetDigestEntryV2,
};
pub use dispatch::{
    DispatchCoreV2, DispatchPreparationKindV2, DispatchPreparationV2,
    DispatchRecoverySubjectKindV2, DispatchSubjectV2, KernelDispatchRecoveryProjectionV2,
    KernelDispatchStateV2, SignedExecutorDispositionReceiptV2,
};
pub use durable::{
    DurableG4StateV2, DurableStateNamespaceV2, RollbackProtectedStateAnchorV2,
    RollbackProtectedStateHeadV2,
};
pub use evidence_gc_checkpoint::{
    CompactedTransactionProvenanceV2, EvidenceGcCheckpointV2, EvidenceGcWindowV2,
};
pub use evidence_gc_checkpoint_store::DurableEvidenceGcCheckpointStoreV2;
pub use filesystem_startup::{
    decode_hex_32_v2, load_verified_filesystem_startup_v2, read_verified_regular_file_v2,
    FilesystemServiceEndpointConfigV2, FilesystemServiceObservationConfigV2,
};
pub use installation_evidence::{ClosedInstallationEvidenceKindV2, InstallationEvidenceEnvelopeV2};
pub use installation_evidence_store::DurableInstallationEvidenceStoreV2;
#[cfg(any(test, feature = "test-support"))]
pub use installation_evidence_store::TestInstallationEvidenceCrashPointV2;
pub use intent::{
    action_intent_id_v2, tool_approval_binding_digest_v2,
    tool_execution_semantic_binding_digest_v2, ActionIntentRecordV2, ActionIntentResolutionKindV2,
    ActionIntentResolutionV2, ActionIntentStateV2, PendingCallStateRecordV2, PendingCallStateV2,
    PublicTaskStateRecordV2, PublicTaskStateV2, StableActionArgumentBindingV2,
    ToolExecutionSemanticBindingV2, VerifiedActionIntentMaterialV2, VerifiedProjectionOutputsV2,
};
pub use labels::{
    ConfidentialityV2, EffectSetV2, G3Error, IntegrityV2, ReaderSetV2, SecurityLabelV2,
    UNTRUSTED_EFFECT_CEILING_V2,
};
pub use leak_gate::LeakGateDutyV2;
pub use ontology::{
    AttemptKindV2, ContextFieldV2, FieldPathV2, G4Error, OntologyExprV2, OntologyOperandV2,
    OntologyScalarV2, VerifiedOntologySetV2,
};
pub use production::{
    activate_internal_validator_registry, InternalValidatorBuildV2, KernelPreparedDispatchV2,
    ResolvedExecutionTicketV2, ResolvedFinalReleaseTicketV2, SharedVerifiedConnectorRegistryV2,
    VerifiedEffectGateLeaseV2, VerifiedFinalReleaseRecordV2, VerifiedFinalReleaseSettlementV2,
    VerifiedOntologyEvaluationV2, VerifiedPolicyDispositionV2, VerifiedToolApprovalSettlementV2,
};
pub use provenance::{
    decode_provenance_record_v2, encode_provenance_record_v2, provenance_digest_v2,
    DeclassificationTransitionV2, DeriveOperationV2, HandoffJudgmentV2, PolicyConstantIdV2,
    ProvenanceContextV2, ProvenanceRecordV2, RootEvidenceV2, SourceKindV2,
    VerifiedIngressProvenanceEvidenceSourceV2,
};
pub use quota::{
    AuthenticatedEffectDispositionV2, DispatchQuotaCounterV2, DispatchQuotaMutationKindV2,
    DispatchQuotaMutationV2, DispatchQuotaReservationStateV2, DispatchQuotaReservationV2,
    DispatchQuotaSubjectV2, VerifiedQuotaLimitV2,
};
pub use recovery_rollback_readiness::{
    ClosedRecoveryRollbackDigestFieldV2, RecoveryRollbackOriginMeasurementsV2,
    RecoveryRollbackReadinessEvidenceV2,
};
pub use rollback_verification_attestation::{
    ClosedRollbackAttestationDigestFieldV2, RollbackTerminalReadinessRefV2,
    RollbackVerificationAttestationV2,
};
pub use rollback_verification_evidence::{
    ClosedRollbackVerificationDigestFieldV2, RollbackVerificationEvidenceV2,
};
pub use savana_kernel_protocol::v2::FinalReleaseSemanticBindingV2;
#[cfg(any(test, feature = "test-support"))]
pub use savana_platform_identity::TestNativeDeploymentSigningAuthorityV2;
pub use savana_platform_identity::{
    NativeDeploymentAuthorityHandlesV2, NativeDeploymentBootstrapTrustMaterialV2,
    NativeDeploymentSignatureDomainV2, NativeDeploymentSignatureRequestV2,
    NativeDeploymentSigningAuthorityV2,
};
pub use store_compatibility::{RecoveryValidationResultV2, StoreCompatibilityAttestationV2};
pub use transition_audit::TransitionAuditV2;
pub use validator::{
    deployment_requires_intent_flow_confinement, G5DecisionBranchV2, G5DecisionIndexV2,
    G5DecisionResolutionKindV2, G5DecisionResolutionV2, G5Error, G5PolicyDispositionV2,
    InternalValidatorImplementationKindV2, PublicDecisionTraceV2, ValidatorBuildManifestIdentityV2,
    VerifiedG5EvaluationInputV2, VerifiedInternalValidatorImplementationV2,
    VerifiedInternalValidatorRegistryV2, VerifiedInternalValidatorSetV2, EFFECT_AUTHORIZING_V2,
    EFFECT_STATE_CHANGING_V2,
};
pub use value::{value_digest_v2, ArgumentNameV2, FieldNameV2, IdentifierV2, KernelValueV2};
pub use verification_evidence::{ClosedVerificationDigestFieldV2, VerificationEvidenceV2};

#[cfg(test)]
#[path = "durable_tests.rs"]
mod durable_tests;

#[cfg(test)]
#[path = "deployment_merkle_tests.rs"]
mod deployment_merkle_tests;

#[cfg(test)]
#[path = "dispatch_tests.rs"]
mod dispatch_tests;

#[cfg(test)]
#[path = "validator_tests.rs"]
mod validator_tests;
