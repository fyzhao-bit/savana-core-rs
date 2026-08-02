use savana_kernel_protocol::v2::{Digest32V2, Nonce32V2};

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DeploymentControlErrorV2 {
    #[error("the deployment phase transition is not in the closed graph")]
    IllegalPhaseTransition,
    #[error("the deployment ledger link is malformed")]
    InvalidLedgerRecord,
    #[error("the deployment ledger slots conflict")]
    LedgerConflict,
    #[error("the deployment ledger slots equivocate at one generation")]
    LedgerEquivocation,
    #[error("the deployment fence transition is invalid")]
    FenceTransitionMismatch,
    #[error("the rollback grant transition is invalid")]
    RollbackGrantMismatch,
    #[error("the deployment transaction binding changed")]
    TransactionBindingMismatch,
    #[error("the current deployment owner heartbeat is still live")]
    HeartbeatLive,
    #[error("the current deployment owner heartbeat has expired")]
    HeartbeatExpired,
    #[error("the observed deployment owner identity does not match")]
    OwnerIdentityMismatch,
    #[error("the deployment owner generation overflowed")]
    OwnerGenerationOverflow,
    #[error("the deployment ledger CBOR is not canonical")]
    NonCanonicalLedgerEncoding,
    #[error("the deployment activation key does not match")]
    ActivationKeyMismatch,
    #[error("the deployment installation identity or epoch does not match")]
    InstallationTupleMismatch,
    #[error("the deployment activation signature is invalid")]
    InvalidActivationSignature,
    #[error("the deployment ledger payload digest does not match")]
    LedgerPayloadDigestMismatch,
    #[error("the deployment ledger slot is invalid")]
    InvalidLedgerSlot,
    #[error("the deployment ledger slot checksum does not match")]
    LedgerSlotChecksumMismatch,
    #[error("the native rollback authority is unavailable")]
    NativeRollbackAuthorityUnavailable,
    #[error("the native rollback authority generation conflicts with the signed ledger")]
    NativeRollbackGenerationMismatch,
    #[error("the deployment ledger durable filesystem is unsafe or unavailable")]
    DeploymentLedgerIo,
    #[error("the fixed deployment mutex is busy, replaced, or unavailable")]
    DeploymentMutexUnavailable,
    #[error("the deployment highest-ever vector regressed or equivocated")]
    HighestEverMismatch,
    #[error("the durable deployment transaction head is malformed")]
    InvalidDurableDeploymentHead,
    #[error(
        "the durable deployment transaction head does not extend the exact completed-step prefix"
    )]
    DurableHeadPrefixMismatch,
    #[error("the durable deployment transaction head drops or conflicts with durable evidence")]
    DurableHeadEvidenceMismatch,
    #[error("the durable deployment transaction owner progression is invalid")]
    DurableHeadOwnerMismatch,
    #[error("the durable deployment transaction store is unsafe or unavailable")]
    DeploymentTransactionIo,
    #[error("the evidence GC checkpoint is malformed or unauthenticated")]
    InvalidEvidenceGcCheckpoint,
    #[error("the compacted transaction provenance does not bind the exact aborted chain")]
    InvalidCompactedTransactionProvenance,
    #[error("the evidence GC checkpoint store is unsafe or unavailable")]
    EvidenceGcCheckpointIo,
    #[error("the installation evidence envelope is malformed or unauthenticated")]
    InvalidInstallationEvidenceEnvelope,
    #[error("the installation evidence store is unsafe, discontinuous, or unavailable")]
    InstallationEvidenceIo,
    #[error("the deployment failure evidence is malformed or does not prove a fenced failure")]
    InvalidDeploymentFailureEvidence,
    #[error("the store compatibility attestation is malformed or unauthenticated")]
    InvalidStoreCompatibilityAttestation,
    #[error("the deployment transaction intent or authorization is malformed")]
    InvalidDeploymentTransaction,
    #[error("the deployment verification evidence is malformed or unauthenticated")]
    InvalidVerificationEvidence,
    #[error("the deployment commit attestation is malformed or unauthenticated")]
    InvalidCommitAttestation,
    #[error("the deployment rollback verification evidence is malformed or unauthenticated")]
    InvalidRollbackVerificationEvidence,
    #[error("the deployment recovery rollback readiness evidence is malformed or unauthenticated")]
    InvalidRecoveryRollbackReadinessEvidence,
    #[error("the deployment rollback terminal attestation is malformed or unauthenticated")]
    InvalidRollbackVerificationAttestation,
    #[error("the deployment transition audit is malformed or does not bind one exact transition")]
    InvalidTransitionAudit,
    #[error("the deployment runtime evidence is malformed, incomplete, or ambiguous")]
    InvalidDeploymentRuntimeEvidence,
    #[error("the deployment auxiliary evidence store is unsafe or unavailable")]
    DeploymentAuxiliaryEvidenceIo,
    #[error("the operational trust-root set is malformed or unauthenticated")]
    InvalidOperationalTrustRootSet,
    #[error("the declassification rule set is malformed or unauthenticated")]
    InvalidDeclassificationRuleSet,
    #[error("the deployment plan is malformed, incomplete, or outside the closed vocabulary")]
    InvalidDeploymentPlan,
    #[error("the deployment plan exceeds the compiled hard limits")]
    DeploymentPlanLimitExceeded,
    #[error("the deployment file tree is empty or malformed")]
    InvalidDeploymentTree,
    #[error("the deployment file tree exceeds the compiled hard limits")]
    DeploymentTreeLimitExceeded,
    #[error("the deployment artifact identity is malformed or outside the closed vocabulary")]
    InvalidArtifactIdentity,
    #[error("the security-state manifest is malformed, ambiguous, or unauthenticated")]
    InvalidSecurityStateManifest,
    #[error("the native non-exportable deployment signing authority is unavailable")]
    NativeSigningAuthorityUnavailable,
    #[error("the deployment active state changed outside its exact terminal transition")]
    ActiveStateMismatch,
    #[error("the rollback origin does not match the exact recovery source phase")]
    RollbackOriginMismatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum DeploymentPhaseV2 {
    Idle = 1,
    Prepared = 2,
    Armed = 3,
    Quiesced = 4,
    Installed = 5,
    Verified = 6,
    Committed = 7,
    Aborted = 8,
    RollbackPrepared = 9,
    RollbackInstalled = 10,
    RollbackVerified = 11,
    RolledBack = 12,
    FailedSafe = 13,
    BootstrapBridge = 14,
    BridgeRestorePrepared = 15,
    BridgeRestoreInstalled = 16,
    BridgeRestoreVerified = 17,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum RollbackGrantStateV2 {
    None = 0,
    Prearmed = 1,
    Consuming = 2,
    Consumed = 3,
    Burned = 4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum DeploymentBranchV2 {
    Normal = 1,
    BootstrapBridgeRestore = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeploymentTransitionV2 {
    branch: DeploymentBranchV2,
    from: DeploymentPhaseV2,
    to: DeploymentPhaseV2,
}

impl DeploymentTransitionV2 {
    pub fn new(
        branch: DeploymentBranchV2,
        from: DeploymentPhaseV2,
        to: DeploymentPhaseV2,
    ) -> Result<Self, DeploymentControlErrorV2> {
        if !legal_transition(branch, from, to) {
            return Err(DeploymentControlErrorV2::IllegalPhaseTransition);
        }
        Ok(Self { branch, from, to })
    }

    pub const fn branch(self) -> DeploymentBranchV2 {
        self.branch
    }

    pub const fn from(self) -> DeploymentPhaseV2 {
        self.from
    }

    pub const fn to(self) -> DeploymentPhaseV2 {
        self.to
    }
}

fn legal_transition(
    branch: DeploymentBranchV2,
    from: DeploymentPhaseV2,
    to: DeploymentPhaseV2,
) -> bool {
    use DeploymentPhaseV2 as Phase;
    if to == Phase::FailedSafe {
        return matches!(
            from,
            Phase::Prepared
                | Phase::Armed
                | Phase::Quiesced
                | Phase::Installed
                | Phase::Verified
                | Phase::RollbackPrepared
                | Phase::RollbackInstalled
                | Phase::RollbackVerified
                | Phase::BridgeRestorePrepared
                | Phase::BridgeRestoreInstalled
                | Phase::BridgeRestoreVerified
        );
    }
    match branch {
        DeploymentBranchV2::Normal => matches!(
            (from, to),
            (Phase::Idle, Phase::Prepared)
                | (Phase::Committed, Phase::Prepared)
                | (Phase::RolledBack, Phase::Prepared)
                | (Phase::Prepared, Phase::Armed)
                | (Phase::Prepared, Phase::Aborted)
                | (Phase::Aborted, Phase::Idle)
                | (Phase::Armed, Phase::Quiesced)
                | (Phase::Quiesced, Phase::Installed)
                | (Phase::Installed, Phase::Verified)
                | (Phase::Verified, Phase::Committed)
                | (Phase::Armed, Phase::RollbackPrepared)
                | (Phase::Quiesced, Phase::RollbackPrepared)
                | (Phase::Installed, Phase::RollbackPrepared)
                | (Phase::Verified, Phase::RollbackPrepared)
                | (Phase::RollbackPrepared, Phase::RollbackInstalled)
                | (Phase::RollbackInstalled, Phase::RollbackVerified)
                | (Phase::RollbackVerified, Phase::RolledBack)
        ),
        DeploymentBranchV2::BootstrapBridgeRestore => matches!(
            (from, to),
            (Phase::BootstrapBridge, Phase::Prepared)
                | (Phase::Prepared, Phase::Armed)
                | (Phase::Prepared, Phase::Aborted)
                | (Phase::Aborted, Phase::BootstrapBridge)
                | (Phase::Armed, Phase::Quiesced)
                | (Phase::Quiesced, Phase::Installed)
                | (Phase::Installed, Phase::Verified)
                | (Phase::Verified, Phase::Committed)
                | (Phase::Armed, Phase::BridgeRestorePrepared)
                | (Phase::Quiesced, Phase::BridgeRestorePrepared)
                | (Phase::Installed, Phase::BridgeRestorePrepared)
                | (Phase::Verified, Phase::BridgeRestorePrepared)
                | (Phase::BridgeRestorePrepared, Phase::BridgeRestoreInstalled)
                | (Phase::BridgeRestoreInstalled, Phase::BridgeRestoreVerified)
                | (Phase::BridgeRestoreVerified, Phase::BootstrapBridge)
        ),
    }
}

/// The security-relevant projection used only after the complete signed
/// deployment record has been authenticated. It deliberately carries no
/// signing or ledger-write capability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeploymentLedgerProjectionV2 {
    installation_id: Digest32V2,
    installation_epoch: u64,
    generation: u64,
    previous_record_digest: Digest32V2,
    record_payload_digest: Digest32V2,
    phase: DeploymentPhaseV2,
    transaction_id: Option<Nonce32V2>,
    effects_fenced: bool,
    effect_fence_epoch: u64,
    rollback_grant_state: RollbackGrantStateV2,
    transaction_head_digest: Option<Digest32V2>,
}

impl DeploymentLedgerProjectionV2 {
    #[cfg(any(test, feature = "test-support"))]
    #[allow(clippy::too_many_arguments)]
    pub fn new_for_test(
        installation_id: Digest32V2,
        installation_epoch: u64,
        generation: u64,
        previous_record_digest: Digest32V2,
        record_payload_digest: Digest32V2,
        phase: DeploymentPhaseV2,
        transaction_id: Option<Nonce32V2>,
        effects_fenced: bool,
        effect_fence_epoch: u64,
        rollback_grant_state: RollbackGrantStateV2,
        transaction_head_digest: Option<Digest32V2>,
    ) -> Result<Self, DeploymentControlErrorV2> {
        Self::from_authenticated_record(
            installation_id,
            installation_epoch,
            generation,
            previous_record_digest,
            record_payload_digest,
            phase,
            transaction_id,
            effects_fenced,
            effect_fence_epoch,
            rollback_grant_state,
            transaction_head_digest,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn from_authenticated_record(
        installation_id: Digest32V2,
        installation_epoch: u64,
        generation: u64,
        previous_record_digest: Digest32V2,
        record_payload_digest: Digest32V2,
        phase: DeploymentPhaseV2,
        transaction_id: Option<Nonce32V2>,
        effects_fenced: bool,
        effect_fence_epoch: u64,
        rollback_grant_state: RollbackGrantStateV2,
        transaction_head_digest: Option<Digest32V2>,
    ) -> Result<Self, DeploymentControlErrorV2> {
        let value = Self {
            installation_id,
            installation_epoch,
            generation,
            previous_record_digest,
            record_payload_digest,
            phase,
            transaction_id,
            effects_fenced,
            effect_fence_epoch,
            rollback_grant_state,
            transaction_head_digest,
        };
        value.validate_shape()?;
        Ok(value)
    }

    fn validate_shape(&self) -> Result<(), DeploymentControlErrorV2> {
        if is_zero(self.installation_id.as_bytes())
            || self.installation_epoch == 0
            || self.generation == 0
            || is_zero(self.record_payload_digest.as_bytes())
            || self.effect_fence_epoch == 0
            || self
                .transaction_id
                .is_some_and(|value| is_zero(value.as_bytes()))
            || self
                .transaction_head_digest
                .is_some_and(|value| is_zero(value.as_bytes()))
            || self.transaction_id.is_some() != self.transaction_head_digest.is_some()
        {
            return Err(DeploymentControlErrorV2::InvalidLedgerRecord);
        }
        use DeploymentPhaseV2 as Phase;
        use RollbackGrantStateV2 as Grant;
        let transaction_bearing =
            self.transaction_id.is_some() && self.transaction_head_digest.is_some();
        let valid = match self.phase {
            Phase::Idle => {
                !transaction_bearing
                    && !self.effects_fenced
                    && self.rollback_grant_state == Grant::None
            }
            Phase::Prepared => transaction_bearing && self.rollback_grant_state == Grant::Prearmed,
            Phase::Armed | Phase::Quiesced | Phase::Installed | Phase::Verified => {
                transaction_bearing
                    && self.effects_fenced
                    && self.rollback_grant_state == Grant::Prearmed
            }
            Phase::Committed => {
                transaction_bearing
                    && !self.effects_fenced
                    && self.rollback_grant_state == Grant::Burned
            }
            Phase::Aborted => transaction_bearing && self.rollback_grant_state == Grant::Burned,
            Phase::RollbackPrepared
            | Phase::RollbackInstalled
            | Phase::RollbackVerified
            | Phase::BridgeRestorePrepared
            | Phase::BridgeRestoreInstalled
            | Phase::BridgeRestoreVerified => {
                transaction_bearing
                    && self.effects_fenced
                    && self.rollback_grant_state == Grant::Consuming
            }
            Phase::RolledBack => {
                transaction_bearing
                    && !self.effects_fenced
                    && self.rollback_grant_state == Grant::Consumed
            }
            Phase::FailedSafe => {
                transaction_bearing
                    && self.effects_fenced
                    && self.rollback_grant_state == Grant::Burned
            }
            Phase::BootstrapBridge => {
                self.effects_fenced
                    && matches!(self.rollback_grant_state, Grant::Burned | Grant::Consumed)
                    && (transaction_bearing
                        || (self.transaction_id.is_none()
                            && self.transaction_head_digest.is_none()))
            }
        };
        if !valid {
            return Err(DeploymentControlErrorV2::InvalidLedgerRecord);
        }
        Ok(())
    }

    pub fn validate_successor(
        &self,
        successor: &Self,
        branch: DeploymentBranchV2,
    ) -> Result<DeploymentTransitionV2, DeploymentControlErrorV2> {
        let transition = DeploymentTransitionV2::new(branch, self.phase, successor.phase)?;
        if successor.installation_id != self.installation_id
            || successor.installation_epoch != self.installation_epoch
            || successor.generation
                != self
                    .generation
                    .checked_add(1)
                    .ok_or(DeploymentControlErrorV2::InvalidLedgerRecord)?
            || successor.previous_record_digest != self.record_payload_digest
        {
            return Err(DeploymentControlErrorV2::LedgerConflict);
        }
        validate_transaction_binding(self, successor, transition)?;
        validate_fence_transition(self, successor, transition)?;
        validate_grant_transition(self, successor, transition)?;
        Ok(transition)
    }

    pub const fn installation_id(&self) -> Digest32V2 {
        self.installation_id
    }

    pub const fn installation_epoch(&self) -> u64 {
        self.installation_epoch
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub const fn previous_record_digest(&self) -> Digest32V2 {
        self.previous_record_digest
    }

    pub const fn record_payload_digest(&self) -> Digest32V2 {
        self.record_payload_digest
    }

    pub const fn phase(&self) -> DeploymentPhaseV2 {
        self.phase
    }

    pub const fn transaction_id(&self) -> Option<Nonce32V2> {
        self.transaction_id
    }

    pub const fn transaction_head_digest(&self) -> Option<Digest32V2> {
        self.transaction_head_digest
    }

    pub const fn effects_fenced(&self) -> bool {
        self.effects_fenced
    }

    pub const fn effect_fence_epoch(&self) -> u64 {
        self.effect_fence_epoch
    }
}

fn validate_transaction_binding(
    current: &DeploymentLedgerProjectionV2,
    successor: &DeploymentLedgerProjectionV2,
    transition: DeploymentTransitionV2,
) -> Result<(), DeploymentControlErrorV2> {
    use DeploymentPhaseV2 as Phase;
    match (transition.from, transition.to) {
        (
            Phase::Idle | Phase::Committed | Phase::RolledBack | Phase::BootstrapBridge,
            Phase::Prepared,
        ) => {
            if successor.transaction_id.is_none() {
                return Err(DeploymentControlErrorV2::TransactionBindingMismatch);
            }
        }
        (Phase::Aborted, Phase::Idle) => {
            if successor.transaction_id.is_some() {
                return Err(DeploymentControlErrorV2::TransactionBindingMismatch);
            }
        }
        (Phase::Aborted, Phase::BootstrapBridge) => {
            if successor.transaction_id != current.transaction_id {
                return Err(DeploymentControlErrorV2::TransactionBindingMismatch);
            }
        }
        _ if successor.transaction_id != current.transaction_id => {
            return Err(DeploymentControlErrorV2::TransactionBindingMismatch);
        }
        _ => {}
    }
    Ok(())
}

fn validate_fence_transition(
    current: &DeploymentLedgerProjectionV2,
    successor: &DeploymentLedgerProjectionV2,
    transition: DeploymentTransitionV2,
) -> Result<(), DeploymentControlErrorV2> {
    use DeploymentPhaseV2 as Phase;
    let expected = match transition.to {
        Phase::Armed
        | Phase::RollbackPrepared
        | Phase::BridgeRestorePrepared
        | Phase::FailedSafe => (
            true,
            current
                .effect_fence_epoch
                .checked_add(1)
                .ok_or(DeploymentControlErrorV2::FenceTransitionMismatch)?,
        ),
        Phase::Committed | Phase::RolledBack => (
            false,
            current
                .effect_fence_epoch
                .checked_add(1)
                .ok_or(DeploymentControlErrorV2::FenceTransitionMismatch)?,
        ),
        Phase::Idle => (false, current.effect_fence_epoch),
        Phase::Prepared => (current.effects_fenced, current.effect_fence_epoch),
        Phase::Aborted => (current.effects_fenced, current.effect_fence_epoch),
        _ => (true, current.effect_fence_epoch),
    };
    if (successor.effects_fenced, successor.effect_fence_epoch) != expected {
        return Err(DeploymentControlErrorV2::FenceTransitionMismatch);
    }
    Ok(())
}

fn validate_grant_transition(
    current: &DeploymentLedgerProjectionV2,
    successor: &DeploymentLedgerProjectionV2,
    transition: DeploymentTransitionV2,
) -> Result<(), DeploymentControlErrorV2> {
    use DeploymentPhaseV2 as Phase;
    use RollbackGrantStateV2 as Grant;
    let valid = match transition.to {
        Phase::Prepared => successor.rollback_grant_state == Grant::Prearmed,
        Phase::Armed | Phase::Quiesced | Phase::Installed | Phase::Verified => {
            successor.rollback_grant_state == Grant::Prearmed
        }
        Phase::RollbackPrepared | Phase::BridgeRestorePrepared => {
            current.rollback_grant_state == Grant::Prearmed
                && successor.rollback_grant_state == Grant::Consuming
        }
        Phase::RollbackInstalled
        | Phase::RollbackVerified
        | Phase::BridgeRestoreInstalled
        | Phase::BridgeRestoreVerified => {
            current.rollback_grant_state == Grant::Consuming
                && successor.rollback_grant_state == Grant::Consuming
        }
        Phase::RolledBack => {
            current.rollback_grant_state == Grant::Consuming
                && successor.rollback_grant_state == Grant::Consumed
        }
        Phase::BootstrapBridge if transition.from == Phase::BridgeRestoreVerified => {
            current.rollback_grant_state == Grant::Consuming
                && successor.rollback_grant_state == Grant::Consumed
        }
        Phase::Committed | Phase::Aborted | Phase::FailedSafe => {
            successor.rollback_grant_state == Grant::Burned
        }
        Phase::Idle => successor.rollback_grant_state == Grant::None,
        Phase::BootstrapBridge => successor.rollback_grant_state == Grant::Burned,
    };
    if !valid {
        return Err(DeploymentControlErrorV2::RollbackGrantMismatch);
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum LedgerSlotIdV2 {
    A = 1,
    B = 2,
}

/// A slot produced by the canonical slot decoder after checksum, activation
/// signature, installation tuple, and duplicated header verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedLedgerSlotV2 {
    slot_id: LedgerSlotIdV2,
    record: DeploymentLedgerProjectionV2,
    record_bytes: Vec<u8>,
    authenticated_record: Option<super::deployment_ledger::DeploymentLedgerRecordV2>,
}

impl VerifiedLedgerSlotV2 {
    #[cfg(any(test, feature = "test-support"))]
    pub fn new_for_test(
        slot_id: LedgerSlotIdV2,
        record: DeploymentLedgerProjectionV2,
    ) -> Result<Self, DeploymentControlErrorV2> {
        record.validate_shape()?;
        let record_bytes = test_projection_bytes(&record);
        Ok(Self {
            slot_id,
            record,
            record_bytes,
            authenticated_record: None,
        })
    }

    pub(super) fn from_authenticated_slot(
        slot_id: LedgerSlotIdV2,
        authenticated_record: super::deployment_ledger::DeploymentLedgerRecordV2,
    ) -> Result<Self, DeploymentControlErrorV2> {
        let record = authenticated_record.projection().clone();
        let record_bytes = authenticated_record.canonical_bytes().to_vec();
        if record_bytes.is_empty() {
            return Err(DeploymentControlErrorV2::InvalidLedgerSlot);
        }
        record.validate_shape()?;
        Ok(Self {
            slot_id,
            record,
            record_bytes,
            authenticated_record: Some(authenticated_record),
        })
    }

    pub const fn slot_id(&self) -> LedgerSlotIdV2 {
        self.slot_id
    }

    pub const fn record(&self) -> &DeploymentLedgerProjectionV2 {
        &self.record
    }

    pub(super) fn authenticated_record(
        &self,
    ) -> Result<&super::deployment_ledger::DeploymentLedgerRecordV2, DeploymentControlErrorV2> {
        self.authenticated_record
            .as_ref()
            .ok_or(DeploymentControlErrorV2::InvalidLedgerSlot)
    }
}

pub fn select_authenticated_ledger_slot_v2(
    first: Option<VerifiedLedgerSlotV2>,
    second: Option<VerifiedLedgerSlotV2>,
) -> Result<DeploymentLedgerProjectionV2, DeploymentControlErrorV2> {
    match (first, second) {
        (None, None) => Err(DeploymentControlErrorV2::LedgerConflict),
        (Some(slot), None) | (None, Some(slot)) => Ok(slot.record),
        (Some(first), Some(second)) => {
            if first.slot_id == second.slot_id
                || first.record.installation_id != second.record.installation_id
                || first.record.installation_epoch != second.record.installation_epoch
            {
                return Err(DeploymentControlErrorV2::LedgerConflict);
            }
            if first.record.generation == second.record.generation {
                return if first.record.record_payload_digest == second.record.record_payload_digest
                    && first.record_bytes == second.record_bytes
                {
                    Ok(first.record)
                } else {
                    Err(DeploymentControlErrorV2::LedgerEquivocation)
                };
            }
            let (older, newer) = if first.record.generation < second.record.generation {
                (first.record, second.record)
            } else {
                (second.record, first.record)
            };
            if older.generation.checked_add(1) != Some(newer.generation)
                || newer.previous_record_digest != older.record_payload_digest
            {
                return Err(DeploymentControlErrorV2::LedgerConflict);
            }
            Ok(newer)
        }
    }
}

#[cfg(any(test, feature = "test-support"))]
fn test_projection_bytes(record: &DeploymentLedgerProjectionV2) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(32 * 5 + 64);
    bytes.extend_from_slice(record.installation_id.as_bytes());
    bytes.extend_from_slice(&record.installation_epoch.to_be_bytes());
    bytes.extend_from_slice(&record.generation.to_be_bytes());
    bytes.extend_from_slice(record.previous_record_digest.as_bytes());
    bytes.extend_from_slice(record.record_payload_digest.as_bytes());
    bytes.extend_from_slice(&(record.phase as u16).to_be_bytes());
    match record.transaction_id {
        Some(value) => bytes.extend_from_slice(value.as_bytes()),
        None => bytes.extend_from_slice(&[0; 32]),
    }
    bytes.push(u8::from(record.effects_fenced));
    bytes.extend_from_slice(&record.effect_fence_epoch.to_be_bytes());
    bytes.extend_from_slice(&(record.rollback_grant_state as u16).to_be_bytes());
    match record.transaction_head_digest {
        Some(value) => bytes.extend_from_slice(value.as_bytes()),
        None => bytes.extend_from_slice(&[0; 32]),
    }
    bytes
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeploymentOwnerIdentityV2 {
    boot_id: Digest32V2,
    pid: u64,
    process_start_identity: u64,
    executable_identity_digest: Digest32V2,
}

impl DeploymentOwnerIdentityV2 {
    pub fn new(
        boot_id: Digest32V2,
        pid: u64,
        process_start_identity: u64,
        executable_identity_digest: Digest32V2,
    ) -> Result<Self, DeploymentControlErrorV2> {
        if is_zero(boot_id.as_bytes())
            || pid == 0
            || process_start_identity == 0
            || is_zero(executable_identity_digest.as_bytes())
        {
            return Err(DeploymentControlErrorV2::OwnerIdentityMismatch);
        }
        Ok(Self {
            boot_id,
            pid,
            process_start_identity,
            executable_identity_digest,
        })
    }

    pub const fn boot_id(self) -> Digest32V2 {
        self.boot_id
    }

    pub const fn pid(self) -> u64 {
        self.pid
    }

    pub const fn process_start_identity(self) -> u64 {
        self.process_start_identity
    }

    pub const fn executable_identity_digest(self) -> Digest32V2 {
        self.executable_identity_digest
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum DeploymentOwnerRoleV2 {
    Helper = 1,
    Watchdog = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeploymentOwnerClaimV2 {
    transaction_id: Nonce32V2,
    owner_role: DeploymentOwnerRoleV2,
    identity: DeploymentOwnerIdentityV2,
    operation_nonce: Nonce32V2,
    heartbeat_generation: u64,
    heartbeat_deadline_monotonic_ns: u64,
}

impl DeploymentOwnerClaimV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        transaction_id: Nonce32V2,
        owner_role: DeploymentOwnerRoleV2,
        boot_id: Digest32V2,
        pid: u64,
        process_start_identity: u64,
        executable_identity_digest: Digest32V2,
        operation_nonce: Nonce32V2,
        heartbeat_generation: u64,
        heartbeat_deadline_monotonic_ns: u64,
    ) -> Result<Self, DeploymentControlErrorV2> {
        if is_zero(transaction_id.as_bytes())
            || is_zero(operation_nonce.as_bytes())
            || heartbeat_generation == 0
            || heartbeat_deadline_monotonic_ns == 0
        {
            return Err(DeploymentControlErrorV2::OwnerIdentityMismatch);
        }
        Ok(Self {
            transaction_id,
            owner_role,
            identity: DeploymentOwnerIdentityV2::new(
                boot_id,
                pid,
                process_start_identity,
                executable_identity_digest,
            )?,
            operation_nonce,
            heartbeat_generation,
            heartbeat_deadline_monotonic_ns,
        })
    }

    pub fn watchdog_takeover(
        self,
        observed_current_owner: &DeploymentOwnerIdentityV2,
        watchdog_identity: DeploymentOwnerIdentityV2,
        now_monotonic_ns: u64,
        watchdog_operation_nonce: Nonce32V2,
        next_heartbeat_deadline_monotonic_ns: u64,
    ) -> Result<Self, DeploymentControlErrorV2> {
        if *observed_current_owner != self.identity {
            return Err(DeploymentControlErrorV2::OwnerIdentityMismatch);
        }
        if now_monotonic_ns < self.heartbeat_deadline_monotonic_ns {
            return Err(DeploymentControlErrorV2::HeartbeatLive);
        }
        if is_zero(watchdog_operation_nonce.as_bytes())
            || next_heartbeat_deadline_monotonic_ns <= now_monotonic_ns
        {
            return Err(DeploymentControlErrorV2::OwnerIdentityMismatch);
        }
        Ok(Self {
            transaction_id: self.transaction_id,
            owner_role: DeploymentOwnerRoleV2::Watchdog,
            identity: watchdog_identity,
            operation_nonce: watchdog_operation_nonce,
            heartbeat_generation: self
                .heartbeat_generation
                .checked_add(1)
                .ok_or(DeploymentControlErrorV2::OwnerGenerationOverflow)?,
            heartbeat_deadline_monotonic_ns: next_heartbeat_deadline_monotonic_ns,
        })
    }

    pub fn renew_heartbeat(
        self,
        observed_current_owner: &DeploymentOwnerIdentityV2,
        now_monotonic_ns: u64,
        next_heartbeat_deadline_monotonic_ns: u64,
    ) -> Result<Self, DeploymentControlErrorV2> {
        if *observed_current_owner != self.identity {
            return Err(DeploymentControlErrorV2::OwnerIdentityMismatch);
        }
        if now_monotonic_ns >= self.heartbeat_deadline_monotonic_ns {
            return Err(DeploymentControlErrorV2::HeartbeatExpired);
        }
        if next_heartbeat_deadline_monotonic_ns <= now_monotonic_ns
            || next_heartbeat_deadline_monotonic_ns <= self.heartbeat_deadline_monotonic_ns
        {
            return Err(DeploymentControlErrorV2::OwnerIdentityMismatch);
        }
        Ok(Self {
            heartbeat_generation: self
                .heartbeat_generation
                .checked_add(1)
                .ok_or(DeploymentControlErrorV2::OwnerGenerationOverflow)?,
            heartbeat_deadline_monotonic_ns: next_heartbeat_deadline_monotonic_ns,
            ..self
        })
    }

    pub const fn owner_role(self) -> DeploymentOwnerRoleV2 {
        self.owner_role
    }

    pub const fn transaction_id(self) -> Nonce32V2 {
        self.transaction_id
    }

    pub const fn identity(self) -> DeploymentOwnerIdentityV2 {
        self.identity
    }

    pub const fn operation_nonce(self) -> Nonce32V2 {
        self.operation_nonce
    }

    pub const fn heartbeat_generation(self) -> u64 {
        self.heartbeat_generation
    }

    pub const fn heartbeat_deadline_monotonic_ns(self) -> u64 {
        self.heartbeat_deadline_monotonic_ns
    }
}

fn is_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}
