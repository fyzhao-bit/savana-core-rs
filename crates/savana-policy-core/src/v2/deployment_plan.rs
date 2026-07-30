use savana_kernel_protocol::v2::Digest32V2;
use sha2::{Digest as _, Sha256};

use super::{
    ClosedLogicalPathIdV2, ClosedStoreIdV2, DeploymentBranchV2, DeploymentControlErrorV2,
    DeploymentHardLimitsV2,
};

const MIGRATION_PLAN_DOMAIN_V2: &[u8] = b"savana.migration-plan.v2\0";
const ARTIFACT_INSTALL_PLAN_DOMAIN_V2: &[u8] = b"savana.artifact-install-plan.v2\0";
const SERVICE_PLAN_DOMAIN_V2: &[u8] = b"savana.service-transition-plan.v2\0";
const E2E_PLAN_DOMAIN_V2: &[u8] = b"savana.isolated-e2e-plan.v2\0";
const EVIDENCE_CONTRACT_DOMAIN_V2: &[u8] = b"savana.evidence-contract.v2\0";
const ACCEPTANCE_PLAN_DOMAIN_V2: &[u8] = b"savana.protected-acceptance-plan.v2\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrationStepV2 {
    AssertStoreEpoch {
        store_id: ClosedStoreIdV2,
        expected_epoch: u64,
    },
    ExpandSchema {
        store_id: ClosedStoreIdV2,
        from_epoch: u64,
        to_epoch: u64,
        migration_artifact_digest: Digest32V2,
    },
    ProvisionKeySlot {
        store_id: ClosedStoreIdV2,
        closed_slot_id: Digest32V2,
    },
}

impl MigrationStepV2 {
    const fn tag(self) -> u16 {
        match self {
            Self::AssertStoreEpoch { .. } => 1,
            Self::ExpandSchema { .. } => 2,
            Self::ProvisionKeySlot { .. } => 3,
        }
    }

    fn validate(self) -> Result<(), DeploymentControlErrorV2> {
        match self {
            Self::AssertStoreEpoch { expected_epoch, .. } if expected_epoch != 0 => Ok(()),
            Self::ExpandSchema {
                from_epoch,
                to_epoch,
                migration_artifact_digest,
                ..
            } if from_epoch != 0
                && to_epoch > from_epoch
                && !is_zero(migration_artifact_digest.as_bytes()) =>
            {
                Ok(())
            }
            Self::ProvisionKeySlot { closed_slot_id, .. }
                if !is_zero(closed_slot_id.as_bytes()) =>
            {
                Ok(())
            }
            _ => Err(DeploymentControlErrorV2::InvalidDeploymentPlan),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationPlanV2 {
    canonical_bytes: Vec<u8>,
    digest: Digest32V2,
    steps: Vec<MigrationStepV2>,
}

impl MigrationPlanV2 {
    pub fn new(steps: Vec<MigrationStepV2>) -> Result<Self, DeploymentControlErrorV2> {
        validate_migration_steps(&steps)?;
        let canonical_bytes = encode_migration_plan(&steps)?;
        Ok(Self {
            digest: hash_domain(MIGRATION_PLAN_DOMAIN_V2, &canonical_bytes),
            canonical_bytes,
            steps,
        })
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, DeploymentControlErrorV2> {
        check_plan_size(bytes)?;
        let mut decoder = minicbor::Decoder::new(bytes);
        let count = decode_array_length(&mut decoder)?;
        let mut steps = Vec::new();
        steps
            .try_reserve_exact(count)
            .map_err(|_| DeploymentControlErrorV2::DeploymentPlanLimitExceeded)?;
        for _ in 0..count {
            steps.push(decode_migration_step(&mut decoder)?);
        }
        require_eof(&decoder, bytes)?;
        let value = Self::new(steps)?;
        require_canonical(value.canonical_bytes(), bytes)?;
        Ok(value)
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub const fn digest(&self) -> Digest32V2 {
        self.digest
    }

    pub fn steps(&self) -> &[MigrationStepV2] {
        &self.steps
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactInstallOperationV2 {
    MaterializeFile(ClosedLogicalPathIdV2),
    MaterializeDirectory(ClosedLogicalPathIdV2),
    VerifyNativeIdentity(ClosedLogicalPathIdV2),
}

impl ArtifactInstallOperationV2 {
    const fn tag(self) -> u16 {
        match self {
            Self::MaterializeFile(_) => 1,
            Self::MaterializeDirectory(_) => 2,
            Self::VerifyNativeIdentity(_) => 3,
        }
    }

    pub const fn logical_path_id(self) -> ClosedLogicalPathIdV2 {
        match self {
            Self::MaterializeFile(path)
            | Self::MaterializeDirectory(path)
            | Self::VerifyNativeIdentity(path) => path,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactInstallPlanV2 {
    canonical_bytes: Vec<u8>,
    digest: Digest32V2,
    operations: Vec<ArtifactInstallOperationV2>,
}

impl ArtifactInstallPlanV2 {
    pub fn complete_operations() -> Vec<ArtifactInstallOperationV2> {
        let mut operations = Vec::with_capacity(75);
        for path in ClosedLogicalPathIdV2::ALL.iter().copied().take(40) {
            if path.is_directory() {
                operations.push(ArtifactInstallOperationV2::MaterializeDirectory(path));
            } else {
                operations.push(ArtifactInstallOperationV2::MaterializeFile(path));
                operations.push(ArtifactInstallOperationV2::VerifyNativeIdentity(path));
            }
        }
        operations
    }

    pub fn new(
        operations: Vec<ArtifactInstallOperationV2>,
    ) -> Result<Self, DeploymentControlErrorV2> {
        validate_artifact_install_operations(&operations)?;
        let canonical_bytes = encode_artifact_install_plan(&operations)?;
        Ok(Self {
            digest: hash_domain(ARTIFACT_INSTALL_PLAN_DOMAIN_V2, &canonical_bytes),
            canonical_bytes,
            operations,
        })
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, DeploymentControlErrorV2> {
        check_plan_size(bytes)?;
        let mut decoder = minicbor::Decoder::new(bytes);
        let count = decode_array_length(&mut decoder)?;
        let mut operations = Vec::new();
        operations
            .try_reserve_exact(count)
            .map_err(|_| DeploymentControlErrorV2::DeploymentPlanLimitExceeded)?;
        for _ in 0..count {
            operations.push(decode_artifact_install_operation(&mut decoder)?);
        }
        require_eof(&decoder, bytes)?;
        let value = Self::new(operations)?;
        require_canonical(value.canonical_bytes(), bytes)?;
        Ok(value)
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub const fn digest(&self) -> Digest32V2 {
        self.digest
    }

    pub fn operations(&self) -> &[ArtifactInstallOperationV2] {
        &self.operations
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u16)]
pub enum ClosedDeploymentServiceIdV2 {
    Jarvis = 1,
    Agentd = 2,
    Ingressd = 3,
    Kerneld = 4,
    Approvald = 5,
    Execd = 6,
    ParserWorkerTemplate = 7,
    ConnectorWorkerTemplate = 8,
}

impl ClosedDeploymentServiceIdV2 {
    const fn from_tag(tag: u16) -> Option<Self> {
        match tag {
            1 => Some(Self::Jarvis),
            2 => Some(Self::Agentd),
            3 => Some(Self::Ingressd),
            4 => Some(Self::Kerneld),
            5 => Some(Self::Approvald),
            6 => Some(Self::Execd),
            7 => Some(Self::ParserWorkerTemplate),
            8 => Some(Self::ConnectorWorkerTemplate),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceTransitionPlanV2 {
    canonical_bytes: Vec<u8>,
    digest: Digest32V2,
    stop_order: Vec<ClosedDeploymentServiceIdV2>,
    candidate_start_order: Vec<ClosedDeploymentServiceIdV2>,
    rollback_start_order: Vec<ClosedDeploymentServiceIdV2>,
    readiness_order: Vec<ClosedDeploymentServiceIdV2>,
}

impl ServiceTransitionPlanV2 {
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, DeploymentControlErrorV2> {
        check_plan_size(bytes)?;
        let mut decoder = minicbor::Decoder::new(bytes);
        expect_array(&mut decoder, 4)?;
        let stop_order = decode_unique_services(&mut decoder)?;
        let candidate_start_order = decode_unique_services(&mut decoder)?;
        let rollback_start_order = decode_unique_services(&mut decoder)?;
        let readiness_order = decode_unique_services(&mut decoder)?;
        require_eof(&decoder, bytes)?;
        let canonical = encode_service_plan(
            &stop_order,
            &candidate_start_order,
            &rollback_start_order,
            &readiness_order,
        )?;
        require_canonical(&canonical, bytes)?;
        Ok(Self {
            canonical_bytes: canonical,
            digest: hash_domain(SERVICE_PLAN_DOMAIN_V2, bytes),
            stop_order,
            candidate_start_order,
            rollback_start_order,
            readiness_order,
        })
    }

    pub fn validate_branch_shape(
        &self,
        branch: DeploymentBranchV2,
    ) -> Result<(), DeploymentControlErrorV2> {
        if branch == DeploymentBranchV2::BootstrapBridgeRestore
            && (!self.stop_order.is_empty() || !self.rollback_start_order.is_empty())
        {
            return Err(DeploymentControlErrorV2::InvalidDeploymentPlan);
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub const fn digest(&self) -> Digest32V2 {
        self.digest
    }

    pub fn stop_order(&self) -> &[ClosedDeploymentServiceIdV2] {
        &self.stop_order
    }

    pub fn candidate_start_order(&self) -> &[ClosedDeploymentServiceIdV2] {
        &self.candidate_start_order
    }

    pub fn rollback_start_order(&self) -> &[ClosedDeploymentServiceIdV2] {
        &self.rollback_start_order
    }

    pub fn readiness_order(&self) -> &[ClosedDeploymentServiceIdV2] {
        &self.readiness_order
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ClosedE2ECaseV2 {
    CanonicalHandshake = 1,
    SensitiveTransport = 2,
    InputProjection = 3,
    PlannerProjection = 4,
    ApprovalApprove = 5,
    ApprovalDeny = 6,
    WebAuthnUvCounterReplay = 7,
    GatesG1ThroughG7 = 8,
    ExactOnceIntent = 9,
    ExecutorNonce = 10,
    RawResultContainment = 11,
    ResultAcknowledgement = 12,
    CrashRecoveryNoReplay = 13,
    CrossRoleRejection = 14,
    V1Rejection = 15,
    NativeControlMeasurement = 16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsolatedE2EPlanV2 {
    canonical_bytes: Vec<u8>,
    digest: Digest32V2,
    planner_fixture_digest: Digest32V2,
    connector_fixture_digest: Digest32V2,
    isolation_profile_digest: Digest32V2,
}

impl IsolatedE2EPlanV2 {
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, DeploymentControlErrorV2> {
        check_plan_size(bytes)?;
        let mut decoder = minicbor::Decoder::new(bytes);
        expect_array(&mut decoder, 4)?;
        decode_exact_tags(&mut decoder, 16)?;
        let planner_fixture_digest = decode_nonzero_digest(&mut decoder)?;
        let connector_fixture_digest = decode_nonzero_digest(&mut decoder)?;
        let isolation_profile_digest = decode_nonzero_digest(&mut decoder)?;
        require_eof(&decoder, bytes)?;
        let canonical = encode_e2e_plan(
            planner_fixture_digest,
            connector_fixture_digest,
            isolation_profile_digest,
        )?;
        require_canonical(&canonical, bytes)?;
        Ok(Self {
            canonical_bytes: canonical,
            digest: hash_domain(E2E_PLAN_DOMAIN_V2, bytes),
            planner_fixture_digest,
            connector_fixture_digest,
            isolation_profile_digest,
        })
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub const fn digest(&self) -> Digest32V2 {
        self.digest
    }

    pub const fn planner_fixture_digest(&self) -> Digest32V2 {
        self.planner_fixture_digest
    }

    pub const fn connector_fixture_digest(&self) -> Digest32V2 {
        self.connector_fixture_digest
    }

    pub const fn isolation_profile_digest(&self) -> Digest32V2 {
        self.isolation_profile_digest
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct PlatformTupleV2 {
    os_tag: u16,
    architecture_tag: u16,
}

impl PlatformTupleV2 {
    pub const fn os_tag(self) -> u16 {
        self.os_tag
    }

    pub const fn architecture_tag(self) -> u16 {
        self.architecture_tag
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ClosedEvidenceRetentionClassV2 {
    NormalBounded = 1,
    SignedLegalHoldMetadataOnly = 2,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceContractV2 {
    canonical_bytes: Vec<u8>,
    digest: Digest32V2,
    required_review_count: u16,
    required_execution_platforms: Vec<PlatformTupleV2>,
    retention_class: ClosedEvidenceRetentionClassV2,
}

impl EvidenceContractV2 {
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, DeploymentControlErrorV2> {
        check_plan_size(bytes)?;
        let mut decoder = minicbor::Decoder::new(bytes);
        expect_array(&mut decoder, 5)?;
        decode_exact_tags(&mut decoder, 9)?;
        decode_exact_tags(&mut decoder, 7)?;
        let required_review_count = decode_u16(&mut decoder)?;
        if required_review_count == 0 {
            return Err(DeploymentControlErrorV2::InvalidDeploymentPlan);
        }
        let required_execution_platforms = decode_platforms(&mut decoder)?;
        let retention_class = match decode_u16(&mut decoder)? {
            1 => ClosedEvidenceRetentionClassV2::NormalBounded,
            2 => ClosedEvidenceRetentionClassV2::SignedLegalHoldMetadataOnly,
            _ => return Err(DeploymentControlErrorV2::InvalidDeploymentPlan),
        };
        require_eof(&decoder, bytes)?;
        let canonical = encode_evidence_contract(
            required_review_count,
            &required_execution_platforms,
            retention_class,
        )?;
        require_canonical(&canonical, bytes)?;
        Ok(Self {
            canonical_bytes: canonical,
            digest: hash_domain(EVIDENCE_CONTRACT_DOMAIN_V2, bytes),
            required_review_count,
            required_execution_platforms,
            retention_class,
        })
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub const fn digest(&self) -> Digest32V2 {
        self.digest
    }

    pub const fn required_review_count(&self) -> u16 {
        self.required_review_count
    }

    pub fn required_execution_platforms(&self) -> &[PlatformTupleV2] {
        &self.required_execution_platforms
    }

    pub const fn retention_class(&self) -> ClosedEvidenceRetentionClassV2 {
        self.retention_class
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ClosedProtectedAcceptanceCaseV2 {
    RealKeystoreAcl = 1,
    NonEmptyStoreOpen = 2,
    ExistingStateRecovery = 3,
    CanaryApproval = 4,
    CanaryDispatch = 5,
    CanaryExecutorNonce = 6,
    ControlledSinkReceipt = 7,
    ResultGateAndAcknowledgement = 8,
    RestartNoReplay = 9,
    SourceStoreUnchanged = 10,
    CloneDestroyed = 11,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectedAcceptancePlanV2 {
    canonical_bytes: Vec<u8>,
    digest: Digest32V2,
    isolation_profile_digest: Digest32V2,
    controlled_sink_identity_digest: Digest32V2,
}

impl ProtectedAcceptancePlanV2 {
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, DeploymentControlErrorV2> {
        check_plan_size(bytes)?;
        let mut decoder = minicbor::Decoder::new(bytes);
        expect_array(&mut decoder, 3)?;
        decode_exact_tags(&mut decoder, 11)?;
        let isolation_profile_digest = decode_nonzero_digest(&mut decoder)?;
        let controlled_sink_identity_digest = decode_nonzero_digest(&mut decoder)?;
        require_eof(&decoder, bytes)?;
        let canonical =
            encode_acceptance_plan(isolation_profile_digest, controlled_sink_identity_digest)?;
        require_canonical(&canonical, bytes)?;
        Ok(Self {
            canonical_bytes: canonical,
            digest: hash_domain(ACCEPTANCE_PLAN_DOMAIN_V2, bytes),
            isolation_profile_digest,
            controlled_sink_identity_digest,
        })
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub const fn digest(&self) -> Digest32V2 {
        self.digest
    }

    pub const fn isolation_profile_digest(&self) -> Digest32V2 {
        self.isolation_profile_digest
    }

    pub const fn controlled_sink_identity_digest(&self) -> Digest32V2 {
        self.controlled_sink_identity_digest
    }
}

fn validate_migration_steps(steps: &[MigrationStepV2]) -> Result<(), DeploymentControlErrorV2> {
    if steps.len() as u64 > DeploymentHardLimitsV2::compiled().max_plan_steps() {
        return Err(DeploymentControlErrorV2::DeploymentPlanLimitExceeded);
    }
    let mut previous = None;
    for step in steps {
        step.validate()?;
        let key = migration_step_sort_key(*step);
        if previous.as_ref().is_some_and(|value| value >= &key) {
            return Err(DeploymentControlErrorV2::InvalidDeploymentPlan);
        }
        previous = Some(key);
    }
    Ok(())
}

fn validate_artifact_install_operations(
    operations: &[ArtifactInstallOperationV2],
) -> Result<(), DeploymentControlErrorV2> {
    if operations.len() as u64 > DeploymentHardLimitsV2::compiled().max_plan_steps()
        || operations != ArtifactInstallPlanV2::complete_operations()
    {
        return Err(DeploymentControlErrorV2::InvalidDeploymentPlan);
    }
    Ok(())
}

fn encode_migration_plan(steps: &[MigrationStepV2]) -> Result<Vec<u8>, DeploymentControlErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(steps.len() as u64)
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentPlan)?;
    for step in steps {
        encode_migration_step(&mut encoder, *step)?;
    }
    Ok(encoder.into_writer())
}

fn encode_migration_step(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    step: MigrationStepV2,
) -> Result<(), DeploymentControlErrorV2> {
    match step {
        MigrationStepV2::AssertStoreEpoch {
            store_id,
            expected_epoch,
        } => encoder
            .array(3)
            .and_then(|encoder| encoder.u16(step.tag()))
            .and_then(|encoder| encoder.u16(store_id.tag()))
            .and_then(|encoder| encoder.u64(expected_epoch)),
        MigrationStepV2::ExpandSchema {
            store_id,
            from_epoch,
            to_epoch,
            migration_artifact_digest,
        } => encoder
            .array(5)
            .and_then(|encoder| encoder.u16(step.tag()))
            .and_then(|encoder| encoder.u16(store_id.tag()))
            .and_then(|encoder| encoder.u64(from_epoch))
            .and_then(|encoder| encoder.u64(to_epoch))
            .and_then(|encoder| encoder.bytes(migration_artifact_digest.as_bytes())),
        MigrationStepV2::ProvisionKeySlot {
            store_id,
            closed_slot_id,
        } => encoder
            .array(3)
            .and_then(|encoder| encoder.u16(step.tag()))
            .and_then(|encoder| encoder.u16(store_id.tag()))
            .and_then(|encoder| encoder.bytes(closed_slot_id.as_bytes())),
    }
    .map(|_| ())
    .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentPlan)
}

fn migration_step_sort_key(step: MigrationStepV2) -> Vec<u8> {
    let (store_id, trailing) = match step {
        MigrationStepV2::AssertStoreEpoch {
            store_id,
            expected_epoch,
        } => (store_id, expected_epoch.to_be_bytes().to_vec()),
        MigrationStepV2::ExpandSchema {
            store_id,
            from_epoch,
            to_epoch,
            migration_artifact_digest,
        } => {
            let mut trailing = Vec::with_capacity(48);
            trailing.extend_from_slice(&from_epoch.to_be_bytes());
            trailing.extend_from_slice(&to_epoch.to_be_bytes());
            trailing.extend_from_slice(migration_artifact_digest.as_bytes());
            (store_id, trailing)
        }
        MigrationStepV2::ProvisionKeySlot {
            store_id,
            closed_slot_id,
        } => (store_id, closed_slot_id.as_bytes().to_vec()),
    };
    let mut key = Vec::with_capacity(4 + trailing.len());
    key.extend_from_slice(&store_id.tag().to_be_bytes());
    key.extend_from_slice(&step.tag().to_be_bytes());
    key.extend_from_slice(&trailing);
    key
}

fn decode_migration_step(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<MigrationStepV2, DeploymentControlErrorV2> {
    let length = decoder
        .array()
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentPlan)?;
    let tag = decode_u16(decoder)?;
    let store_id = ClosedStoreIdV2::from_tag(decode_u16(decoder)?)
        .ok_or(DeploymentControlErrorV2::InvalidDeploymentPlan)?;
    let step = match (tag, length) {
        (1, Some(3)) => MigrationStepV2::AssertStoreEpoch {
            store_id,
            expected_epoch: decoder
                .u64()
                .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentPlan)?,
        },
        (2, Some(5)) => MigrationStepV2::ExpandSchema {
            store_id,
            from_epoch: decoder
                .u64()
                .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentPlan)?,
            to_epoch: decoder
                .u64()
                .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentPlan)?,
            migration_artifact_digest: decode_nonzero_digest(decoder)?,
        },
        (3, Some(3)) => MigrationStepV2::ProvisionKeySlot {
            store_id,
            closed_slot_id: decode_nonzero_digest(decoder)?,
        },
        _ => return Err(DeploymentControlErrorV2::InvalidDeploymentPlan),
    };
    step.validate()?;
    Ok(step)
}

fn encode_artifact_install_plan(
    operations: &[ArtifactInstallOperationV2],
) -> Result<Vec<u8>, DeploymentControlErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(operations.len() as u64)
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentPlan)?;
    for operation in operations {
        encoder
            .array(2)
            .and_then(|encoder| encoder.u16(operation.tag()))
            .and_then(|encoder| encoder.u16(operation.logical_path_id().tag()))
            .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentPlan)?;
    }
    Ok(encoder.into_writer())
}

fn decode_artifact_install_operation(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<ArtifactInstallOperationV2, DeploymentControlErrorV2> {
    expect_array(decoder, 2)?;
    let tag = decode_u16(decoder)?;
    let path = ClosedLogicalPathIdV2::from_tag(decode_u16(decoder)?)
        .ok_or(DeploymentControlErrorV2::InvalidDeploymentPlan)?;
    if path.is_bootstrap_owned() {
        return Err(DeploymentControlErrorV2::InvalidDeploymentPlan);
    }
    match tag {
        1 if !path.is_directory() => Ok(ArtifactInstallOperationV2::MaterializeFile(path)),
        2 if path.is_directory() => Ok(ArtifactInstallOperationV2::MaterializeDirectory(path)),
        3 if !path.is_directory() => Ok(ArtifactInstallOperationV2::VerifyNativeIdentity(path)),
        _ => Err(DeploymentControlErrorV2::InvalidDeploymentPlan),
    }
}

fn check_plan_size(bytes: &[u8]) -> Result<(), DeploymentControlErrorV2> {
    let limits = DeploymentHardLimitsV2::compiled();
    if bytes.len() as u64 > limits.max_plan_bytes() {
        Err(DeploymentControlErrorV2::DeploymentPlanLimitExceeded)
    } else if bytes.is_empty() {
        Err(DeploymentControlErrorV2::InvalidDeploymentPlan)
    } else {
        Ok(())
    }
}

fn expect_array(
    decoder: &mut minicbor::Decoder<'_>,
    expected: u64,
) -> Result<(), DeploymentControlErrorV2> {
    if decoder
        .array()
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentPlan)?
        != Some(expected)
    {
        return Err(DeploymentControlErrorV2::InvalidDeploymentPlan);
    }
    Ok(())
}

fn decode_array_length(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<usize, DeploymentControlErrorV2> {
    let count = decoder
        .array()
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentPlan)?
        .ok_or(DeploymentControlErrorV2::InvalidDeploymentPlan)?;
    if count > DeploymentHardLimitsV2::compiled().max_plan_steps() {
        return Err(DeploymentControlErrorV2::DeploymentPlanLimitExceeded);
    }
    usize::try_from(count).map_err(|_| DeploymentControlErrorV2::DeploymentPlanLimitExceeded)
}

fn decode_u16(decoder: &mut minicbor::Decoder<'_>) -> Result<u16, DeploymentControlErrorV2> {
    decoder
        .u16()
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentPlan)
}

fn decode_unique_services(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<Vec<ClosedDeploymentServiceIdV2>, DeploymentControlErrorV2> {
    let count = decode_array_length(decoder)?;
    if count > 8 {
        return Err(DeploymentControlErrorV2::InvalidDeploymentPlan);
    }
    let mut seen = [false; 9];
    let mut services = Vec::new();
    services
        .try_reserve_exact(count)
        .map_err(|_| DeploymentControlErrorV2::DeploymentPlanLimitExceeded)?;
    for _ in 0..count {
        let service = ClosedDeploymentServiceIdV2::from_tag(decode_u16(decoder)?)
            .ok_or(DeploymentControlErrorV2::InvalidDeploymentPlan)?;
        let index = service as usize;
        if seen[index] {
            return Err(DeploymentControlErrorV2::InvalidDeploymentPlan);
        }
        seen[index] = true;
        services.push(service);
    }
    Ok(services)
}

fn decode_exact_tags(
    decoder: &mut minicbor::Decoder<'_>,
    expected_count: u16,
) -> Result<(), DeploymentControlErrorV2> {
    if decode_array_length(decoder)? != usize::from(expected_count) {
        return Err(DeploymentControlErrorV2::InvalidDeploymentPlan);
    }
    for expected in 1..=expected_count {
        if decode_u16(decoder)? != expected {
            return Err(DeploymentControlErrorV2::InvalidDeploymentPlan);
        }
    }
    Ok(())
}

fn decode_nonzero_digest(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<Digest32V2, DeploymentControlErrorV2> {
    let bytes = decoder
        .bytes()
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentPlan)?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentPlan)?;
    if bytes == [0; 32] {
        return Err(DeploymentControlErrorV2::InvalidDeploymentPlan);
    }
    Ok(Digest32V2::new(bytes))
}

fn decode_platforms(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<Vec<PlatformTupleV2>, DeploymentControlErrorV2> {
    let count = decode_array_length(decoder)?;
    if count == 0 || count > 4 {
        return Err(DeploymentControlErrorV2::InvalidDeploymentPlan);
    }
    let mut platforms = Vec::new();
    platforms
        .try_reserve_exact(count)
        .map_err(|_| DeploymentControlErrorV2::DeploymentPlanLimitExceeded)?;
    let mut previous = None;
    for _ in 0..count {
        expect_array(decoder, 2)?;
        let os_tag = decode_u16(decoder)?;
        let architecture_tag = decode_u16(decoder)?;
        if !matches!(os_tag, 1 | 2) || !matches!(architecture_tag, 1 | 2) {
            return Err(DeploymentControlErrorV2::InvalidDeploymentPlan);
        }
        let platform = PlatformTupleV2 {
            os_tag,
            architecture_tag,
        };
        if previous.is_some_and(|value| value >= platform) {
            return Err(DeploymentControlErrorV2::InvalidDeploymentPlan);
        }
        previous = Some(platform);
        platforms.push(platform);
    }
    Ok(platforms)
}

fn require_eof(
    decoder: &minicbor::Decoder<'_>,
    bytes: &[u8],
) -> Result<(), DeploymentControlErrorV2> {
    if decoder.position() != bytes.len() {
        return Err(DeploymentControlErrorV2::InvalidDeploymentPlan);
    }
    Ok(())
}

fn require_canonical(canonical: &[u8], original: &[u8]) -> Result<(), DeploymentControlErrorV2> {
    if canonical != original {
        return Err(DeploymentControlErrorV2::InvalidDeploymentPlan);
    }
    Ok(())
}

fn encode_services(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    services: &[ClosedDeploymentServiceIdV2],
) -> Result<(), DeploymentControlErrorV2> {
    encoder
        .array(services.len() as u64)
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentPlan)?;
    for service in services {
        encoder
            .u16(*service as u16)
            .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentPlan)?;
    }
    Ok(())
}

fn encode_exact_tags(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    count: u16,
) -> Result<(), DeploymentControlErrorV2> {
    encoder
        .array(u64::from(count))
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentPlan)?;
    for tag in 1..=count {
        encoder
            .u16(tag)
            .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentPlan)?;
    }
    Ok(())
}

fn encode_service_plan(
    stop: &[ClosedDeploymentServiceIdV2],
    candidate: &[ClosedDeploymentServiceIdV2],
    rollback: &[ClosedDeploymentServiceIdV2],
    readiness: &[ClosedDeploymentServiceIdV2],
) -> Result<Vec<u8>, DeploymentControlErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(4)
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentPlan)?;
    encode_services(&mut encoder, stop)?;
    encode_services(&mut encoder, candidate)?;
    encode_services(&mut encoder, rollback)?;
    encode_services(&mut encoder, readiness)?;
    Ok(encoder.into_writer())
}

fn encode_e2e_plan(
    planner: Digest32V2,
    connector: Digest32V2,
    isolation: Digest32V2,
) -> Result<Vec<u8>, DeploymentControlErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(4)
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentPlan)?;
    encode_exact_tags(&mut encoder, 16)?;
    encoder
        .bytes(planner.as_bytes())
        .and_then(|value| value.bytes(connector.as_bytes()))
        .and_then(|value| value.bytes(isolation.as_bytes()))
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentPlan)?;
    Ok(encoder.into_writer())
}

fn encode_evidence_contract(
    review_count: u16,
    platforms: &[PlatformTupleV2],
    retention: ClosedEvidenceRetentionClassV2,
) -> Result<Vec<u8>, DeploymentControlErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(5)
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentPlan)?;
    encode_exact_tags(&mut encoder, 9)?;
    encode_exact_tags(&mut encoder, 7)?;
    encoder
        .u16(review_count)
        .and_then(|value| value.array(platforms.len() as u64))
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentPlan)?;
    for platform in platforms {
        encoder
            .array(2)
            .and_then(|value| value.u16(platform.os_tag))
            .and_then(|value| value.u16(platform.architecture_tag))
            .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentPlan)?;
    }
    encoder
        .u16(retention as u16)
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentPlan)?;
    Ok(encoder.into_writer())
}

fn encode_acceptance_plan(
    isolation: Digest32V2,
    sink: Digest32V2,
) -> Result<Vec<u8>, DeploymentControlErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(3)
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentPlan)?;
    encode_exact_tags(&mut encoder, 11)?;
    encoder
        .bytes(isolation.as_bytes())
        .and_then(|value| value.bytes(sink.as_bytes()))
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentPlan)?;
    Ok(encoder.into_writer())
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
