//! Actual Linux staging bytes -> closed canonical tree and six typed plans.
//! This is a read-only preparation prerequisite, NOT permission to install,
//! sign an activation, unfence effects or start a daemon.
use super::{
    ArtifactInstallPlanV2, ClosedStagingPathIdV2, DeploymentControlErrorV2 as Error,
    DeploymentTransactionV2, EvidenceContractV2, IsolatedE2EPlanV2, MigrationPlanV2,
    ProtectedAcceptancePlanV2, ServiceTransitionPlanV2, StagingEntryV2, StagingTreeV2,
};
use savana_kernel_protocol::v2::Digest32V2;
use savana_platform_identity::{
    DeploymentApplySelectorV2, FixedDeploymentSpoolV2, LinuxDeploymentJournalV3,
    LinuxMeasuredStagingTreeV3, TpmStateHeadV3,
};

/// Read-only prepare result. It cannot sign, reserve a rollback grant, remove a
/// fence or activate a service. Native TCB/manifest/plan closure checks and the
/// privileged install state machine must still precede those effects.
pub struct VerifiedNativeDeploymentPreparationV3<'a> {
    staging: VerifiedDeploymentStagingV3<'a>,
    transaction: DeploymentTransactionV2,
    manifest: super::SecurityStateManifestV2,
    release_trust: super::ReleaseTrustRootSetV2,
    next_highest_ever: super::HighestEverV2,
    checked_head: TpmStateHeadV3,
    checked_at_ms: u64,
    poisoned: bool,
}
impl<'a> VerifiedNativeDeploymentPreparationV3<'a> {
    /// The journal retains the deployment mutex. Trust, platform and genesis
    /// must come from reviewed native installation material, not the request.
    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        spool: &'a FixedDeploymentSpoolV2,
        selector: DeploymentApplySelectorV2,
        journal: &mut LinuxDeploymentJournalV3,
        trust: &super::AuthenticatedNativeDeploymentTrustV2,
        canonical_manifest: &[u8],
        platform: &super::PlatformLockV2,
        expected_genesis: Digest32V2,
        completed: Option<(
            &super::VerifiedVerificationEvidenceV3,
            &super::VerifiedCommitAttestationV3,
        )>,
        clock: &mut impl FnMut() -> u64,
    ) -> Result<Self, Error> {
        let descriptor = spool
            .open_transaction(selector)
            .map_err(|_| Error::InvalidDeploymentTree)?;
        let history = super::DeploymentLedgerHistoryV3::load_native(journal, expected_genesis)?;
        let checked_at_ms = clock();
        let transaction = trust.verify_transaction_for_v3_preparation(
            descriptor.descriptor_bytes(),
            &history,
            platform,
            checked_at_ms,
            completed,
        )?;
        let mut staging = VerifiedDeploymentStagingV3::open(spool, selector, &transaction)?;
        let manifest = staging.verify_manifest(
            &transaction,
            canonical_manifest,
            trust.release_trust_root_set(),
            checked_at_ms,
        )?;
        // A normal update cannot smuggle a bootstrap TCB replacement through
        // the release manifest. That requires a separate recovery protocol.
        if manifest.material().bootstrap_tcb_lock.digest()
            != history
                .latest_ledger()
                .state()
                .material()
                .bootstrap_tcb_lock
        {
            return Err(Error::TransactionBindingMismatch);
        }
        let next_highest_ever = manifest
            .normal_update_highwater(&history.latest_ledger().state().material().highest_ever)?;
        let mut prepared = Self {
            staging,
            transaction,
            manifest,
            release_trust: trust.release_trust_root_set().clone(),
            next_highest_ever,
            checked_head: history.head(),
            checked_at_ms,
            poisoned: false,
        };
        prepared.revalidate(journal, clock)?;
        Ok(prepared)
    }
    pub fn transaction(&self) -> &DeploymentTransactionV2 {
        &self.transaction
    }
    pub fn staging(&self) -> &VerifiedDeploymentStagingV3<'a> {
        &self.staging
    }
    pub fn manifest(&self) -> &super::SecurityStateManifestV2 {
        &self.manifest
    }
    /// Proposed values only. The effect-fenced durable transition must still
    /// retain these maxima at the appropriate irreversible phase.
    pub fn next_highest_ever(&self) -> &super::HighestEverV2 {
        &self.next_highest_ever
    }
    pub fn checked_head(&self) -> TpmStateHeadV3 {
        self.checked_head
    }
    pub fn revalidate(
        &mut self,
        journal: &mut LinuxDeploymentJournalV3,
        clock: &mut impl FnMut() -> u64,
    ) -> Result<(), Error> {
        if self.poisoned {
            return Err(Error::TransactionBindingMismatch);
        }
        self.poisoned = true;
        self.staging.revalidate()?;
        let history = journal
            .history()
            .map_err(|_| Error::NativeSigningAuthorityUnavailable)?;
        if history.last().map(|record| record.head()) != Some(self.checked_head) {
            return Err(Error::TransactionBindingMismatch);
        }
        let current = journal
            .snapshot()
            .map_err(|_| Error::NativeSigningAuthorityUnavailable)?
            .head();
        let now = clock();
        if current != self.checked_head
            || now < self.checked_at_ms
            || now >= self.transaction.intent().material().expires_at_unix_ms
        {
            return Err(Error::TransactionBindingMismatch);
        }
        self.checked_at_ms = now;
        // The retained verified object alone is not evidence that its signing
        // keys and component validity windows are still current.
        // Do not perform another potentially multi-gigabyte file rehash after
        // sampling the clock. The retained staging was rehashed above and its
        // immutable content binding was established during construction.
        super::SecurityStateManifestV2::from_canonical_bytes(
            self.manifest.canonical_bytes(),
            &self.release_trust,
            now,
        )?;
        self.poisoned = false;
        Ok(())
    }
}

pub struct VerifiedDeploymentStagingV3<'a> {
    measured: LinuxMeasuredStagingTreeV3<'a>,
    tree: StagingTreeV2,
    migration: MigrationPlanV2,
    artifacts: ArtifactInstallPlanV2,
    services: ServiceTransitionPlanV2,
    isolated: IsolatedE2EPlanV2,
    evidence: EvidenceContractV2,
    acceptance: ProtectedAcceptancePlanV2,
}
impl<'a> VerifiedDeploymentStagingV3<'a> {
    /// Caller must first authenticate the transaction against current native
    /// trust and V3 ledger history. Only the compiled spool is measured here.
    pub fn open(
        spool: &'a FixedDeploymentSpoolV2,
        selector: DeploymentApplySelectorV2,
        transaction: &DeploymentTransactionV2,
    ) -> Result<Self, Error> {
        let intent = transaction.intent().material();
        if selector.as_bytes()
            != super::staging_selector_v2(intent.transaction_id, intent.staging_tree_digest)
                .as_bytes()
        {
            return Err(Error::TransactionBindingMismatch);
        }
        let mut measured = spool
            .measure_staging_v3(selector)
            .map_err(|_| Error::InvalidDeploymentTree)?;
        if measured.descriptor_bytes() != transaction.canonical_bytes() {
            return Err(Error::TransactionBindingMismatch);
        }
        let entries = measured
            .entries()
            .iter()
            .map(|e| {
                let tag =
                    ClosedStagingPathIdV2::from_tag(e.tag()).ok_or(Error::InvalidDeploymentTree)?;
                if tag == ClosedStagingPathIdV2::ArtifactPayloadRoot {
                    StagingEntryV2::new_directory(
                        tag,
                        e.mode(),
                        Digest32V2::new(e.acl_digest()),
                        Digest32V2::new(e.xattr_digest()),
                    )
                } else {
                    StagingEntryV2::new_regular(
                        tag,
                        e.size(),
                        Digest32V2::new(e.sha256()),
                        e.mode(),
                        Digest32V2::new(e.acl_digest()),
                        Digest32V2::new(e.xattr_digest()),
                    )
                }
            })
            .collect::<Result<Vec<_>, Error>>()?;
        let tree = StagingTreeV2::new(entries)?;
        if tree.merkle_root() != intent.staging_tree_digest {
            return Err(Error::TransactionBindingMismatch);
        }
        let plan = |tag| {
            measured
                .plan_bytes(tag)
                .map_err(|_| Error::InvalidDeploymentTree)
        };
        let migration = MigrationPlanV2::from_canonical_bytes(plan(1)?)?;
        let artifacts = ArtifactInstallPlanV2::from_canonical_bytes(plan(2)?)?;
        let services = ServiceTransitionPlanV2::from_canonical_bytes(plan(3)?)?;
        let isolated = IsolatedE2EPlanV2::from_canonical_bytes(plan(4)?)?;
        let evidence = EvidenceContractV2::from_canonical_bytes(plan(5)?)?;
        let acceptance = ProtectedAcceptancePlanV2::from_canonical_bytes(plan(6)?)?;
        if migration.digest() != intent.migration_plan_digest
            || artifacts.digest() != intent.artifact_install_plan_digest
            || services.digest() != intent.service_transition_plan_digest
            || isolated.digest() != intent.isolated_e2e_plan_digest
            || evidence.digest() != intent.evidence_contract_digest
            || acceptance.digest() != intent.protected_acceptance_plan_digest
        {
            return Err(Error::TransactionBindingMismatch);
        }
        services.validate_branch_shape(if intent.recovery_target.tag() == 2 {
            super::DeploymentBranchV2::BootstrapBridgeRestore
        } else {
            super::DeploymentBranchV2::Normal
        })?;
        measured
            .revalidate()
            .map_err(|_| Error::InvalidDeploymentTree)?;
        Ok(Self {
            measured,
            tree,
            migration,
            artifacts,
            services,
            isolated,
            evidence,
            acceptance,
        })
    }
    pub fn tree(&self) -> &StagingTreeV2 {
        &self.tree
    }
    /// Verify canonical release signatures using the caller's authenticated
    /// release roots, then bind every retained payload to that exact release.
    /// The transaction must be the same one whose bytes were measured here.
    pub fn verify_manifest(
        &mut self,
        transaction: &DeploymentTransactionV2,
        canonical_manifest: &[u8],
        release_trust: &super::ReleaseTrustRootSetV2,
        now_ms: u64,
    ) -> Result<super::SecurityStateManifestV2, Error> {
        self.revalidate()?;
        if transaction.canonical_bytes() != self.measured.descriptor_bytes()
            || now_ms < transaction.intent().material().not_before_unix_ms
            || now_ms >= transaction.intent().material().expires_at_unix_ms
        {
            return Err(Error::TransactionBindingMismatch);
        }
        let manifest = super::SecurityStateManifestV2::from_canonical_bytes(
            canonical_manifest,
            release_trust,
            now_ms,
        )?;
        manifest.validate_transaction_binding(transaction)?;
        manifest.validate_staged_payloads(&self.tree)?;
        self.revalidate()?;
        Ok(manifest)
    }
    pub fn migration(&self) -> &MigrationPlanV2 {
        &self.migration
    }
    pub fn artifacts(&self) -> &ArtifactInstallPlanV2 {
        &self.artifacts
    }
    pub fn services(&self) -> &ServiceTransitionPlanV2 {
        &self.services
    }
    pub fn isolated(&self) -> &IsolatedE2EPlanV2 {
        &self.isolated
    }
    pub fn evidence(&self) -> &EvidenceContractV2 {
        &self.evidence
    }
    pub fn acceptance(&self) -> &ProtectedAcceptancePlanV2 {
        &self.acceptance
    }
    pub fn revalidate(&mut self) -> Result<(), Error> {
        self.measured
            .revalidate()
            .map_err(|_| Error::InvalidDeploymentTree)
    }
}

#[cfg(test)]
#[path = "deployment_staging_v3_tests.rs"]
mod tests;
