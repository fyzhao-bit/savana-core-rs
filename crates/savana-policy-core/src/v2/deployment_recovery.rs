use savana_kernel_protocol::v2::{Digest32V2, Nonce32V2};

use super::{
    DeploymentBranchV2, DeploymentControlErrorV2, DeploymentPhaseV2,
    DurableDeploymentTransactionCoreV2, DurableDeploymentTransactionRecordV2,
};

/// The one closed operation that boot recovery may perform after the current
/// ledger, transaction head chain, and immutable transaction core have all
/// authenticated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeploymentRecoveryActionV2 {
    PublishRuntimeReadiness,
    HoldBootstrapFence,
    HoldFailedSafe,
    ResumeArm,
    ResumeQuiesce,
    ResumeCandidateInstall,
    ResumeCandidateVerification,
    ResumeCommit,
    ResumeAbortedCompaction,
    ResumeRollbackInstall,
    ResumeRollbackVerification,
    ResumeRollbackCommit,
    ResumeBridgeRestoreInstall,
    ResumeBridgeRestoreVerification,
    ResumeBridgeRestoreCommit,
}

/// Authenticated, bounded recovery input. It contains no path, command,
/// service name, or caller-controlled operation selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthenticatedDeploymentRecoveryPlanV2 {
    phase: DeploymentPhaseV2,
    branch: Option<DeploymentBranchV2>,
    action: DeploymentRecoveryActionV2,
    transaction_id: Option<Nonce32V2>,
    core_signed_digest: Option<Digest32V2>,
    transaction_head_signed_digest: Option<Digest32V2>,
}

impl AuthenticatedDeploymentRecoveryPlanV2 {
    pub(super) fn without_transaction(
        phase: DeploymentPhaseV2,
    ) -> Result<Self, DeploymentControlErrorV2> {
        let action = recovery_action(phase, None)?;
        Ok(Self {
            phase,
            branch: None,
            action,
            transaction_id: None,
            core_signed_digest: None,
            transaction_head_signed_digest: None,
        })
    }

    pub(super) fn with_transaction(
        phase: DeploymentPhaseV2,
        branch: DeploymentBranchV2,
        head: &DurableDeploymentTransactionRecordV2,
        core: &DurableDeploymentTransactionCoreV2,
    ) -> Result<Self, DeploymentControlErrorV2> {
        if head.target_phase() != phase
            || head.transaction_id() != core.transaction_id()
            || head.core_signed_digest() != core.signed_digest()
            || head.installation_id() != core.material().installation_id
            || head.installation_epoch() != core.material().installation_epoch
        {
            return Err(DeploymentControlErrorV2::TransactionBindingMismatch);
        }
        let action = recovery_action(phase, Some(branch))?;
        Ok(Self {
            phase,
            branch: Some(branch),
            action,
            transaction_id: Some(head.transaction_id()),
            core_signed_digest: Some(core.signed_digest()),
            transaction_head_signed_digest: Some(head.signed_digest()),
        })
    }

    pub const fn phase(self) -> DeploymentPhaseV2 {
        self.phase
    }

    pub const fn branch(self) -> Option<DeploymentBranchV2> {
        self.branch
    }

    pub const fn action(self) -> DeploymentRecoveryActionV2 {
        self.action
    }

    pub const fn transaction_id(self) -> Option<Nonce32V2> {
        self.transaction_id
    }

    pub const fn core_signed_digest(self) -> Option<Digest32V2> {
        self.core_signed_digest
    }

    pub const fn transaction_head_signed_digest(self) -> Option<Digest32V2> {
        self.transaction_head_signed_digest
    }
}

fn recovery_action(
    phase: DeploymentPhaseV2,
    branch: Option<DeploymentBranchV2>,
) -> Result<DeploymentRecoveryActionV2, DeploymentControlErrorV2> {
    use DeploymentPhaseV2 as Phase;
    use DeploymentRecoveryActionV2 as Action;

    match (phase, branch) {
        (Phase::Idle, None) => Ok(Action::PublishRuntimeReadiness),
        (Phase::BootstrapBridge, None | Some(DeploymentBranchV2::BootstrapBridgeRestore)) => {
            Ok(Action::HoldBootstrapFence)
        }
        (Phase::Prepared, Some(_)) => Ok(Action::ResumeArm),
        (Phase::Armed, Some(_)) => Ok(Action::ResumeQuiesce),
        (Phase::Quiesced, Some(_)) => Ok(Action::ResumeCandidateInstall),
        (Phase::Installed, Some(_)) => Ok(Action::ResumeCandidateVerification),
        (Phase::Verified, Some(_)) => Ok(Action::ResumeCommit),
        (Phase::Committed, Some(_)) => Ok(Action::PublishRuntimeReadiness),
        (Phase::Aborted, Some(_)) => Ok(Action::ResumeAbortedCompaction),
        (Phase::RollbackPrepared, Some(DeploymentBranchV2::Normal)) => {
            Ok(Action::ResumeRollbackInstall)
        }
        (Phase::RollbackInstalled, Some(DeploymentBranchV2::Normal)) => {
            Ok(Action::ResumeRollbackVerification)
        }
        (Phase::RollbackVerified, Some(DeploymentBranchV2::Normal)) => {
            Ok(Action::ResumeRollbackCommit)
        }
        (Phase::RolledBack, Some(DeploymentBranchV2::Normal)) => {
            Ok(Action::PublishRuntimeReadiness)
        }
        (Phase::FailedSafe, Some(_)) => Ok(Action::HoldFailedSafe),
        (Phase::BridgeRestorePrepared, Some(DeploymentBranchV2::BootstrapBridgeRestore)) => {
            Ok(Action::ResumeBridgeRestoreInstall)
        }
        (Phase::BridgeRestoreInstalled, Some(DeploymentBranchV2::BootstrapBridgeRestore)) => {
            Ok(Action::ResumeBridgeRestoreVerification)
        }
        (Phase::BridgeRestoreVerified, Some(DeploymentBranchV2::BootstrapBridgeRestore)) => {
            Ok(Action::ResumeBridgeRestoreCommit)
        }
        _ => Err(DeploymentControlErrorV2::TransactionBindingMismatch),
    }
}

#[cfg(test)]
mod tests {
    use super::{recovery_action, DeploymentRecoveryActionV2 as Action};
    use crate::v2::{DeploymentBranchV2 as Branch, DeploymentPhaseV2 as Phase};

    #[test]
    fn recovery_action_rejects_cross_branch_and_transactionless_nonterminal_states() {
        assert!(recovery_action(Phase::Armed, None).is_err());
        assert!(recovery_action(
            Phase::RollbackPrepared,
            Some(Branch::BootstrapBridgeRestore)
        )
        .is_err());
        assert!(recovery_action(Phase::BridgeRestorePrepared, Some(Branch::Normal)).is_err());
        assert!(recovery_action(Phase::Idle, Some(Branch::Normal)).is_err());
    }

    #[test]
    fn recovery_action_covers_every_legal_phase_family() {
        assert_eq!(
            recovery_action(Phase::Idle, None).unwrap(),
            Action::PublishRuntimeReadiness
        );
        assert_eq!(
            recovery_action(Phase::Prepared, Some(Branch::Normal)).unwrap(),
            Action::ResumeArm
        );
        assert_eq!(
            recovery_action(Phase::RollbackVerified, Some(Branch::Normal)).unwrap(),
            Action::ResumeRollbackCommit
        );
        assert_eq!(
            recovery_action(
                Phase::BridgeRestoreInstalled,
                Some(Branch::BootstrapBridgeRestore)
            )
            .unwrap(),
            Action::ResumeBridgeRestoreVerification
        );
        assert_eq!(
            recovery_action(Phase::FailedSafe, Some(Branch::Normal)).unwrap(),
            Action::HoldFailedSafe
        );
    }
}
