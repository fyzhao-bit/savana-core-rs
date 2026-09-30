#![forbid(unsafe_code)]

use std::fmt;

use hmac::{Hmac, Mac as _};
use minicbor::Encode as _;
use savana_approvald::{ApprovalPurposeV2, ConsumedApprovalSettlementV2};
pub use savana_kernel_protocol::v2::MaskedDocumentHandleV2;
use savana_kernel_protocol::v2::{
    AuthorityHandleKeyV2, BootIdV2, Digest32V2, DurableReleaseIdV2, DurableRunIdV2,
    DurableTaskIdV2, FinalReleaseSemanticBindingV2, Nonce32V2, PrincipalIdV2, ServiceIdentityV2,
    UnixMillisV2,
};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

mod durable;
pub use durable::{
    DurableVaultNamespaceV2, DurableVaultServiceV2, VaultRollbackAnchorV2, VaultStateHeadV2,
};

const VAULT_SEGMENT_DOMAIN: &[u8] = b"SAVANA_VAULT_SEGMENT_V2\0";
const VAULT_INTERNAL_ID_DOMAIN: &[u8] = b"SAVANA_VAULT_SEGMENT_INTERNAL_ID_V2\0";
const TOOL_RESULT_INTERNAL_ID_DOMAIN: &[u8] = b"SAVANA_VAULT_TOOL_RESULT_INTERNAL_ID_V2\0";
const CAPABILITY_HASH_DOMAIN: &[u8] = b"SAVANA_VAULT_CAPABILITY_HASH_V2\0";
const CAPABILITY_DERIVATION_DOMAIN: &[u8] = b"SAVANA_VAULT_CAPABILITY_DERIVATION_V2\0";
const DISPATCH_SUBJECT_DOMAIN: &[u8] = b"SAVANA_DISPATCH_SUBJECT_V2\0";
const MAX_SEGMENT_BYTES: usize = 8 * 1024 * 1024;
const MAX_DOCUMENT_CAPABILITIES: usize = 65_536;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum VaultErrorV2 {
    #[error("vault input is invalid")]
    InvalidInput,
    #[error("vault capability is invalid, stale, or bound to another context")]
    InvalidCapability,
    #[error("vault object expired")]
    Expired,
    #[error("vault state conflicts with the requested transition")]
    StateConflict,
    #[error("vault object is terminal")]
    TerminalState,
    #[error("vault approval is invalid")]
    InvalidApproval,
    #[error("vault allocation or entropy failed")]
    AllocationFailure,
    #[error("vault clock moved below its accepted floor")]
    ClockRollback,
    #[error("durable vault state I/O or invariant failure")]
    DurableState,
    #[error("durable vault state authentication failed")]
    DurableAuthentication,
    #[error("durable vault state rollback was detected")]
    RollbackDetected,
    #[error("durable vault commit outcome is uncertain")]
    CommitUncertain,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VaultPublicStateV2 {
    Pending,
    Live,
    ReleaseAuthorized,
    Dispatching,
    Released,
    FailedNoEffect,
    Revoked,
    Expired,
    Indeterminate,
    RestartInvalidated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultReleaseRecoveryStateV2 {
    PendingApproval,
    Authorized,
    DispatchPrepared,
    Dispatching,
    Released,
    FailedNoEffect,
    Revoked,
    Expired,
    Indeterminate,
    RestartInvalidated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VaultReleaseRecoveryProjectionV2 {
    durable_release_id: DurableReleaseIdV2,
    binding_digest: Digest32V2,
    execution_nonce: Option<Nonce32V2>,
    dispatch_core_digest: Option<Digest32V2>,
    dispatch_subject_digest: Option<Digest32V2>,
    state: VaultReleaseRecoveryStateV2,
}

impl VaultReleaseRecoveryProjectionV2 {
    pub const fn durable_release_id(self) -> DurableReleaseIdV2 {
        self.durable_release_id
    }

    pub const fn binding_digest(self) -> Digest32V2 {
        self.binding_digest
    }

    pub const fn execution_nonce(self) -> Option<Nonce32V2> {
        self.execution_nonce
    }

    pub const fn dispatch_core_digest(self) -> Option<Digest32V2> {
        self.dispatch_core_digest
    }

    pub const fn dispatch_subject_digest(self) -> Option<Digest32V2> {
        self.dispatch_subject_digest
    }

    pub const fn state(self) -> VaultReleaseRecoveryStateV2 {
        self.state
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VaultStateV2 {
    PendingIngress,
    Live,
    ReleaseAuthorized,
    DispatchPrepared,
    Dispatching,
    Released,
    FailedNoEffect,
    Revoked,
    Expired,
    Indeterminate,
    RestartInvalidated,
}

impl VaultStateV2 {
    const fn public(self) -> VaultPublicStateV2 {
        match self {
            Self::PendingIngress => VaultPublicStateV2::Pending,
            Self::Live => VaultPublicStateV2::Live,
            Self::ReleaseAuthorized => VaultPublicStateV2::ReleaseAuthorized,
            Self::DispatchPrepared | Self::Dispatching => VaultPublicStateV2::Dispatching,
            Self::Released => VaultPublicStateV2::Released,
            Self::FailedNoEffect => VaultPublicStateV2::FailedNoEffect,
            Self::Revoked => VaultPublicStateV2::Revoked,
            Self::Expired => VaultPublicStateV2::Expired,
            Self::Indeterminate => VaultPublicStateV2::Indeterminate,
            Self::RestartInvalidated => VaultPublicStateV2::RestartInvalidated,
        }
    }

    const fn terminal(self) -> bool {
        matches!(
            self,
            Self::Released
                | Self::FailedNoEffect
                | Self::Revoked
                | Self::Expired
                | Self::Indeterminate
                | Self::RestartInvalidated
        )
    }
}

#[derive(Clone)]
pub struct VaultIngressMaterialV2 {
    durable_task_id: DurableTaskIdV2,
    durable_run_id: DurableRunIdV2,
    authenticated_principal: PrincipalIdV2,
    provenance_digest: Digest32V2,
    input_commit_digest: Digest32V2,
    expires_at: UnixMillisV2,
    sensitive_bytes: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for VaultIngressMaterialV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VaultIngressMaterialV2")
            .field("durable_task_id", &self.durable_task_id)
            .field("durable_run_id", &self.durable_run_id)
            .field("expires_at", &self.expires_at)
            .field("encoded_len", &self.sensitive_bytes.len())
            .finish_non_exhaustive()
    }
}

impl VaultIngressMaterialV2 {
    pub fn from_verified_gated_input(
        durable_task_id: DurableTaskIdV2,
        durable_run_id: DurableRunIdV2,
        authenticated_principal: PrincipalIdV2,
        provenance_digest: Digest32V2,
        input_commit_digest: Digest32V2,
        expires_at: UnixMillisV2,
        sensitive_bytes: Vec<u8>,
    ) -> Result<Self, VaultErrorV2> {
        if [
            durable_task_id.as_bytes(),
            durable_run_id.as_bytes(),
            authenticated_principal.as_bytes(),
            provenance_digest.as_bytes(),
            input_commit_digest.as_bytes(),
        ]
        .iter()
        .any(|value| is_zero(value))
            || expires_at.get() == 0
            || sensitive_bytes.is_empty()
            || sensitive_bytes.len() > MAX_SEGMENT_BYTES
        {
            return Err(VaultErrorV2::InvalidInput);
        }
        Ok(Self {
            durable_task_id,
            durable_run_id,
            authenticated_principal,
            provenance_digest,
            input_commit_digest,
            expires_at,
            sensitive_bytes: Zeroizing::new(sensitive_bytes),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VaultAccessContextV2 {
    boot_id: BootIdV2,
    service_identity: ServiceIdentityV2,
    peer_identity_digest: Digest32V2,
    durable_run_id: DurableRunIdV2,
    expires_at: UnixMillisV2,
}

impl VaultAccessContextV2 {
    pub fn from_authenticated_agent(
        boot_id: BootIdV2,
        service_identity: ServiceIdentityV2,
        peer_identity_digest: Digest32V2,
        durable_run_id: DurableRunIdV2,
        expires_at: UnixMillisV2,
    ) -> Result<Self, VaultErrorV2> {
        if [
            boot_id.as_bytes(),
            service_identity.as_bytes(),
            peer_identity_digest.as_bytes(),
            durable_run_id.as_bytes(),
        ]
        .iter()
        .any(|value| is_zero(value))
            || expires_at.get() == 0
        {
            return Err(VaultErrorV2::InvalidInput);
        }
        Ok(Self {
            boot_id,
            service_identity,
            peer_identity_digest,
            durable_run_id,
            expires_at,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VaultReleaseMaterialV2 {
    release_payload_digest: Digest32V2,
    evidence_digest: Digest32V2,
    token_set_digest: Digest32V2,
    destination_digest: Digest32V2,
    display_projection_digest: Digest32V2,
    display_digest: Digest32V2,
    executor_identity_digest: Digest32V2,
    release_quota_subject_digest: Digest32V2,
}

impl VaultReleaseMaterialV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn from_verified_projection(
        release_payload_digest: Digest32V2,
        evidence_digest: Digest32V2,
        token_set_digest: Digest32V2,
        destination_digest: Digest32V2,
        display_projection_digest: Digest32V2,
        display_digest: Digest32V2,
        executor_identity_digest: Digest32V2,
        release_quota_subject_digest: Digest32V2,
    ) -> Result<Self, VaultErrorV2> {
        if [
            release_payload_digest,
            evidence_digest,
            token_set_digest,
            destination_digest,
            display_projection_digest,
            display_digest,
            executor_identity_digest,
            release_quota_subject_digest,
        ]
        .iter()
        .any(|digest| is_zero(digest.as_bytes()))
        {
            return Err(VaultErrorV2::InvalidInput);
        }
        Ok(Self {
            release_payload_digest,
            evidence_digest,
            token_set_digest,
            destination_digest,
            display_projection_digest,
            display_digest,
            executor_identity_digest,
            release_quota_subject_digest,
        })
    }
}

macro_rules! opaque_capability {
    ($name:ident, $label:literal) => {
        #[derive(Clone, Copy, PartialEq, Eq)]
        pub struct $name {
            token: [u8; 32],
            internal_id: Digest32V2,
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!($label, "(<opaque>)"))
            }
        }
    };
}

opaque_capability!(PendingVaultSegmentV2, "PendingVaultSegmentV2");
opaque_capability!(LiveVaultSegmentV2, "LiveVaultSegmentV2");

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PendingVaultReleaseV2 {
    token: [u8; 32],
    binding: FinalReleaseSemanticBindingV2,
    binding_digest: Digest32V2,
}

impl fmt::Debug for PendingVaultReleaseV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PendingVaultReleaseV2(<opaque>)")
    }
}

impl PendingVaultReleaseV2 {
    pub const fn durable_release_id(self) -> DurableReleaseIdV2 {
        self.binding.durable_release_id()
    }

    pub const fn binding(self) -> FinalReleaseSemanticBindingV2 {
        self.binding
    }

    pub const fn binding_digest(self) -> Digest32V2 {
        self.binding_digest
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct AuthorizedVaultReleaseV2 {
    token: [u8; 32],
    binding: FinalReleaseSemanticBindingV2,
    binding_digest: Digest32V2,
    approval_settlement_digest: Digest32V2,
}

impl fmt::Debug for AuthorizedVaultReleaseV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthorizedVaultReleaseV2(<opaque>)")
    }
}

impl AuthorizedVaultReleaseV2 {
    pub const fn binding(self) -> FinalReleaseSemanticBindingV2 {
        self.binding
    }

    pub const fn binding_digest(self) -> Digest32V2 {
        self.binding_digest
    }

    pub const fn approval_settlement_digest(self) -> Digest32V2 {
        self.approval_settlement_digest
    }

    pub fn dispatch_subject_digest(self) -> Result<Digest32V2, VaultErrorV2> {
        final_release_subject_digest(self.binding, self.approval_settlement_digest)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct VaultDispatchPreparedV2 {
    token: [u8; 32],
    binding: FinalReleaseSemanticBindingV2,
    execution_nonce: Nonce32V2,
    dispatch_core_digest: Digest32V2,
    dispatch_subject_digest: Digest32V2,
}

impl fmt::Debug for VaultDispatchPreparedV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VaultDispatchPreparedV2(<opaque>)")
    }
}

impl VaultDispatchPreparedV2 {
    pub const fn execution_nonce(self) -> Nonce32V2 {
        self.execution_nonce
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedFinalReleaseApprovalV2 {
    binding_digest: Digest32V2,
    authenticated_principal: PrincipalIdV2,
    settlement_digest: Digest32V2,
    expires_at: UnixMillisV2,
}

impl VerifiedFinalReleaseApprovalV2 {
    pub fn from_verified_protocol_settlement(
        settlement: savana_kernel_protocol::v2::VerifiedApprovalSettlementV2,
        expected_binding_digest: Digest32V2,
        now: UnixMillisV2,
    ) -> Result<Self, VaultErrorV2> {
        if settlement.decision() != savana_kernel_protocol::v2::ApprovalDecisionV2::Approve
            || is_zero(expected_binding_digest.as_bytes())
            || is_zero(settlement.authenticated_principal().as_bytes())
            || is_zero(settlement.settlement_digest().as_bytes())
            || now.get() == 0
            || now.get() >= settlement.expires_at().get()
        {
            return Err(VaultErrorV2::InvalidApproval);
        }
        Ok(Self {
            binding_digest: expected_binding_digest,
            authenticated_principal: settlement.authenticated_principal(),
            settlement_digest: settlement.settlement_digest(),
            expires_at: settlement.expires_at(),
        })
    }

    pub fn from_consumed_settlement(
        settlement: ConsumedApprovalSettlementV2,
        expected_binding_digest: Digest32V2,
        now: UnixMillisV2,
    ) -> Result<Self, VaultErrorV2> {
        if settlement.purpose() != ApprovalPurposeV2::FinalRelease
            || settlement.binding_digest() != expected_binding_digest
            || is_zero(expected_binding_digest.as_bytes())
            || is_zero(settlement.authenticated_principal().as_bytes())
            || is_zero(settlement.settlement_digest().as_bytes())
            || now.get() == 0
            || now.get() >= settlement.expires_at().get()
        {
            return Err(VaultErrorV2::InvalidApproval);
        }
        Ok(Self {
            binding_digest: expected_binding_digest,
            authenticated_principal: settlement.authenticated_principal(),
            settlement_digest: settlement.settlement_digest(),
            expires_at: settlement.expires_at(),
        })
    }

    #[cfg(test)]
    fn new_for_test(
        binding_digest: Digest32V2,
        authenticated_principal: PrincipalIdV2,
        settlement_digest: Digest32V2,
        expires_at: UnixMillisV2,
    ) -> Self {
        Self {
            binding_digest,
            authenticated_principal,
            settlement_digest,
            expires_at,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KernelPreparedReleaseDispatchV2 {
    binding: FinalReleaseSemanticBindingV2,
    consumed_ticket_digest: Digest32V2,
    execution_nonce: Nonce32V2,
    dispatch_core_digest: Digest32V2,
    dispatch_subject_digest: Digest32V2,
}

impl KernelPreparedReleaseDispatchV2 {
    pub fn from_verified_kernel_commit(
        binding: FinalReleaseSemanticBindingV2,
        consumed_ticket_digest: Digest32V2,
        execution_nonce: Nonce32V2,
        dispatch_core_digest: Digest32V2,
        dispatch_subject_digest: Digest32V2,
    ) -> Result<Self, VaultErrorV2> {
        if [
            consumed_ticket_digest.as_bytes(),
            execution_nonce.as_bytes(),
            dispatch_core_digest.as_bytes(),
            dispatch_subject_digest.as_bytes(),
        ]
        .iter()
        .any(|value| is_zero(value))
            || binding.semantic_digest().is_none()
        {
            return Err(VaultErrorV2::InvalidInput);
        }
        Ok(Self {
            binding,
            consumed_ticket_digest,
            execution_nonce,
            dispatch_core_digest,
            dispatch_subject_digest,
        })
    }

    #[cfg(test)]
    fn new_for_test(
        binding: FinalReleaseSemanticBindingV2,
        consumed_ticket_digest: Digest32V2,
        execution_nonce: Nonce32V2,
        dispatch_core_digest: Digest32V2,
        dispatch_subject_digest: Digest32V2,
    ) -> Self {
        Self::from_verified_kernel_commit(
            binding,
            consumed_ticket_digest,
            execution_nonce,
            dispatch_core_digest,
            dispatch_subject_digest,
        )
        .unwrap()
    }
}

#[derive(Clone)]
struct DocumentCapabilityRecordV2 {
    token_digest: Digest32V2,
    internal_id: Digest32V2,
    context: VaultAccessContextV2,
}

#[derive(Clone)]
struct VaultReleaseRecordV2 {
    capability_digest: Digest32V2,
    binding: FinalReleaseSemanticBindingV2,
    binding_digest: Digest32V2,
    approval_principal: Option<PrincipalIdV2>,
    approval_settlement_digest: Option<Digest32V2>,
    consumed_ticket_digest: Option<Digest32V2>,
    execution_nonce: Option<Nonce32V2>,
    dispatch_core_digest: Option<Digest32V2>,
    dispatch_subject_digest: Option<Digest32V2>,
    final_release_receipt_digest: Option<Digest32V2>,
    release_audit_digest: Option<Digest32V2>,
}

#[derive(Clone)]
struct VaultSegmentRecordV2 {
    internal_id: Digest32V2,
    authority_digest: Digest32V2,
    durable_task_id: DurableTaskIdV2,
    durable_run_id: DurableRunIdV2,
    authenticated_principal: PrincipalIdV2,
    provenance_digest: Digest32V2,
    input_commit_digest: Digest32V2,
    segment_digest: Digest32V2,
    expires_at: UnixMillisV2,
    state_revision: u64,
    state: VaultStateV2,
    sensitive_bytes: Zeroizing<Vec<u8>>,
    release: Option<VaultReleaseRecordV2>,
}

#[derive(Clone)]
pub struct VaultServiceV2 {
    installation_id: Digest32V2,
    active_state_manifest_digest: Digest32V2,
    boot_id: BootIdV2,
    maximum_segments: usize,
    accepted_time_floor_ms: u64,
    capability_key: Zeroizing<[u8; 32]>,
    segments: Vec<VaultSegmentRecordV2>,
    documents: Vec<DocumentCapabilityRecordV2>,
}

impl fmt::Debug for VaultServiceV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VaultServiceV2")
            .field("segment_count", &self.segments.len())
            .field("document_capability_count", &self.documents.len())
            .field("accepted_time_floor_ms", &self.accepted_time_floor_ms)
            .finish_non_exhaustive()
    }
}

impl VaultServiceV2 {
    pub fn from_verified_deployment(
        installation_id: Digest32V2,
        active_state_manifest_digest: Digest32V2,
        boot_id: BootIdV2,
        maximum_segments: usize,
    ) -> Result<Self, VaultErrorV2> {
        if is_zero(installation_id.as_bytes())
            || is_zero(active_state_manifest_digest.as_bytes())
            || is_zero(boot_id.as_bytes())
            || maximum_segments == 0
            || maximum_segments > 65_536
        {
            return Err(VaultErrorV2::InvalidInput);
        }
        let mut capability_key = [0_u8; 32];
        getrandom::getrandom(&mut capability_key).map_err(|_| VaultErrorV2::AllocationFailure)?;
        if capability_key == [0; 32] {
            return Err(VaultErrorV2::AllocationFailure);
        }
        Ok(Self {
            installation_id,
            active_state_manifest_digest,
            boot_id,
            maximum_segments,
            accepted_time_floor_ms: 0,
            capability_key: Zeroizing::new(capability_key),
            segments: Vec::new(),
            documents: Vec::new(),
        })
    }

    pub fn recovery_projection(
        &self,
    ) -> Result<Vec<VaultReleaseRecoveryProjectionV2>, VaultErrorV2> {
        let release_count = self
            .segments
            .iter()
            .filter(|segment| segment.release.is_some())
            .count();
        let mut projection = Vec::new();
        projection
            .try_reserve(release_count)
            .map_err(|_| VaultErrorV2::AllocationFailure)?;
        for segment in &self.segments {
            let Some(release) = segment.release.as_ref() else {
                continue;
            };
            let state = match segment.state {
                VaultStateV2::PendingIngress => return Err(VaultErrorV2::StateConflict),
                VaultStateV2::Live => VaultReleaseRecoveryStateV2::PendingApproval,
                VaultStateV2::ReleaseAuthorized => VaultReleaseRecoveryStateV2::Authorized,
                VaultStateV2::DispatchPrepared => VaultReleaseRecoveryStateV2::DispatchPrepared,
                VaultStateV2::Dispatching => VaultReleaseRecoveryStateV2::Dispatching,
                VaultStateV2::Released => VaultReleaseRecoveryStateV2::Released,
                VaultStateV2::FailedNoEffect => VaultReleaseRecoveryStateV2::FailedNoEffect,
                VaultStateV2::Revoked => VaultReleaseRecoveryStateV2::Revoked,
                VaultStateV2::Expired => VaultReleaseRecoveryStateV2::Expired,
                VaultStateV2::Indeterminate => VaultReleaseRecoveryStateV2::Indeterminate,
                VaultStateV2::RestartInvalidated => VaultReleaseRecoveryStateV2::RestartInvalidated,
            };
            projection.push(VaultReleaseRecoveryProjectionV2 {
                durable_release_id: release.binding.durable_release_id(),
                binding_digest: release.binding_digest,
                execution_nonce: release.execution_nonce,
                dispatch_core_digest: release.dispatch_core_digest,
                dispatch_subject_digest: release.dispatch_subject_digest,
                state,
            });
        }
        projection.sort_unstable_by(|left, right| {
            left.durable_release_id
                .as_bytes()
                .cmp(right.durable_release_id.as_bytes())
        });
        Ok(projection)
    }

    pub fn create_pending_ingress(
        &mut self,
        material: VaultIngressMaterialV2,
        now: UnixMillisV2,
    ) -> Result<PendingVaultSegmentV2, VaultErrorV2> {
        self.create_pending_material(material, now, false)
    }

    /// Kernel-internal result insertion, after exact executor completion proof
    /// verification. Each commit has a separate domain-separated segment; it
    /// never replaces the task's immutable original ingress. Not an agent API.
    pub fn create_pending_tool_result(
        &mut self,
        material: VaultIngressMaterialV2,
        now: UnixMillisV2,
    ) -> Result<PendingVaultSegmentV2, VaultErrorV2> {
        self.create_pending_material(material, now, true)
    }

    fn create_pending_material(
        &mut self,
        material: VaultIngressMaterialV2,
        now: UnixMillisV2,
        tool_result: bool,
    ) -> Result<PendingVaultSegmentV2, VaultErrorV2> {
        self.accept_time(now)?;
        if now.get() >= material.expires_at.get() {
            return Err(VaultErrorV2::Expired);
        }
        // The ingress identity is deterministic so that a response loss after
        // the durable vault commit can be retried without creating a second
        // segment. The capability remains secret because it is derived with
        // the persisted, installation-scoped capability key.
        let internal_id = domain_hash_many(
            if tool_result {
                TOOL_RESULT_INTERNAL_ID_DOMAIN
            } else {
                VAULT_INTERNAL_ID_DOMAIN
            },
            &[
                self.installation_id.as_bytes(),
                self.active_state_manifest_digest.as_bytes(),
                material.durable_task_id.as_bytes(),
                material.durable_run_id.as_bytes(),
                material.input_commit_digest.as_bytes(),
            ],
        );
        if is_zero(internal_id.as_bytes()) {
            return Err(VaultErrorV2::AllocationFailure);
        }
        let token = self.derive_capability(
            b"pending-segment",
            internal_id.as_bytes(),
            material.input_commit_digest.as_bytes(),
        )?;
        let authority_digest = capability_digest(self.installation_id, &token);
        let segment_digest = vault_segment_digest(
            self.installation_id,
            self.active_state_manifest_digest,
            internal_id,
            &material,
        );
        if let Some(existing) = self.segments.iter_mut().find(|segment| {
            if tool_result {
                segment.internal_id == internal_id
            } else {
                // Result records are recognized by their separate, bound
                // identity domain, without changing historical ingress IDs
                // or rewriting the encrypted snapshot format.
                segment.durable_task_id == material.durable_task_id
                    && segment.internal_id
                        != domain_hash_many(
                            TOOL_RESULT_INTERNAL_ID_DOMAIN,
                            &[
                                self.installation_id.as_bytes(),
                                self.active_state_manifest_digest.as_bytes(),
                                segment.durable_task_id.as_bytes(),
                                segment.durable_run_id.as_bytes(),
                                segment.input_commit_digest.as_bytes(),
                            ],
                        )
            }
        }) {
            if existing.internal_id != internal_id
                || existing.durable_run_id != material.durable_run_id
                || existing.authenticated_principal != material.authenticated_principal
                || existing.provenance_digest != material.provenance_digest
                || existing.input_commit_digest != material.input_commit_digest
                || existing.segment_digest != segment_digest
                || (!tool_result && existing.authority_digest != authority_digest)
                || existing.expires_at != material.expires_at
            {
                return Err(VaultErrorV2::StateConflict);
            }
            return match existing.state {
                VaultStateV2::PendingIngress | VaultStateV2::Live => {
                    // A verified replay of the *same result material* may run
                    // under a new service boot. Rotate only its local capability,
                    // never content, provenance, expiry or result identity.
                    if tool_result && existing.authority_digest != authority_digest {
                        advance_revision(existing)?;
                        existing.authority_digest = authority_digest;
                    }
                    Ok(PendingVaultSegmentV2 { token, internal_id })
                }
                VaultStateV2::Expired => Err(VaultErrorV2::Expired),
                _ => Err(VaultErrorV2::TerminalState),
            };
        }
        if self.segments.len() >= self.maximum_segments {
            return Err(VaultErrorV2::AllocationFailure);
        }
        self.segments
            .try_reserve(1)
            .map_err(|_| VaultErrorV2::AllocationFailure)?;
        self.segments.push(VaultSegmentRecordV2 {
            internal_id,
            authority_digest,
            durable_task_id: material.durable_task_id,
            durable_run_id: material.durable_run_id,
            authenticated_principal: material.authenticated_principal,
            provenance_digest: material.provenance_digest,
            input_commit_digest: material.input_commit_digest,
            segment_digest,
            expires_at: material.expires_at,
            state_revision: 1,
            state: VaultStateV2::PendingIngress,
            sensitive_bytes: material.sensitive_bytes,
            release: None,
        });
        Ok(PendingVaultSegmentV2 { token, internal_id })
    }

    pub fn ingest_verified(
        &mut self,
        material: VaultIngressMaterialV2,
        now: UnixMillisV2,
    ) -> Result<LiveVaultSegmentV2, VaultErrorV2> {
        let pending = self.create_pending_ingress(material, now)?;
        self.commit_ingress(pending, now)
    }

    /// Kernel-only restoration of a result already durably committed as Live.
    /// The caller must resolve the commit reference from its authenticated G7
    /// owner. This is not a browser/Agent lookup and never promotes Pending data.
    pub fn recover_committed_tool_result(
        &mut self,
        task: DurableTaskIdV2,
        run: DurableRunIdV2,
        principal: PrincipalIdV2,
        commit: Digest32V2,
        expires_at: UnixMillisV2,
        now: UnixMillisV2,
    ) -> Result<LiveVaultSegmentV2, VaultErrorV2> {
        self.accept_time(now)?;
        if now.get() >= expires_at.get() {
            return Err(VaultErrorV2::Expired);
        }
        let internal_id = domain_hash_many(
            TOOL_RESULT_INTERNAL_ID_DOMAIN,
            &[
                self.installation_id.as_bytes(),
                self.active_state_manifest_digest.as_bytes(),
                task.as_bytes(),
                run.as_bytes(),
                commit.as_bytes(),
            ],
        );
        let token = self.derive_capability(
            b"pending-segment",
            internal_id.as_bytes(),
            commit.as_bytes(),
        )?;
        let segment = self
            .segments
            .iter_mut()
            .find(|s| s.internal_id == internal_id)
            .ok_or(VaultErrorV2::InvalidCapability)?;
        if segment.state != VaultStateV2::Live
            || segment.durable_task_id != task
            || segment.durable_run_id != run
            || segment.authenticated_principal != principal
            || segment.input_commit_digest != commit
            || segment.expires_at != expires_at
        {
            return Err(VaultErrorV2::StateConflict);
        }
        let authority = capability_digest(self.installation_id, &token);
        if segment.authority_digest != authority {
            advance_revision(segment)?;
            segment.authority_digest = authority;
        }
        Ok(LiveVaultSegmentV2 { token, internal_id })
    }

    /// Kernel-only lookup of a committed tool result. Does not mint an Agent
    /// document or accept replacement plaintext. An exact authorized retry
    /// recovers the original release binding, never resets its state.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_committed_tool_result_release(
        &mut self,
        task: DurableTaskIdV2,
        run: DurableRunIdV2,
        principal: PrincipalIdV2,
        commit: Digest32V2,
        expires_at: UnixMillisV2,
        material: VaultReleaseMaterialV2,
        now: UnixMillisV2,
    ) -> Result<PendingVaultReleaseV2, VaultErrorV2> {
        self.accept_time(now)?;
        if now.get() >= expires_at.get() {
            return Err(VaultErrorV2::Expired);
        }
        let internal_id = domain_hash_many(
            TOOL_RESULT_INTERNAL_ID_DOMAIN,
            &[
                self.installation_id.as_bytes(),
                self.active_state_manifest_digest.as_bytes(),
                task.as_bytes(),
                run.as_bytes(),
                commit.as_bytes(),
            ],
        );
        let index = self
            .segments
            .iter()
            .position(|s| s.internal_id == internal_id)
            .ok_or(VaultErrorV2::InvalidCapability)?;
        let segment = &self.segments[index];
        if segment.durable_task_id != task
            || segment.durable_run_id != run
            || segment.authenticated_principal != principal
            || segment.input_commit_digest != commit
            || segment.expires_at != expires_at
            || !matches!(
                segment.state,
                VaultStateV2::Live | VaultStateV2::ReleaseAuthorized
            )
            || domain_hash_many(
                b"SAVANA_FINAL_RELEASE_PAYLOAD_V2\0",
                &[
                    &(segment.sensitive_bytes.len() as u64).to_be_bytes(),
                    &segment.sensitive_bytes,
                ],
            ) != material.release_payload_digest
        {
            return Err(VaultErrorV2::StateConflict);
        }
        if segment.state == VaultStateV2::ReleaseAuthorized {
            let r = segment
                .release
                .as_ref()
                .ok_or(VaultErrorV2::StateConflict)?;
            if !release_material_matches(r.binding, material) {
                return Err(VaultErrorV2::StateConflict);
            }
            return Ok(PendingVaultReleaseV2 {
                token: self.release_capability(r.binding, r.binding_digest)?,
                binding: r.binding,
                binding_digest: r.binding_digest,
            });
        }
        self.prepare_release_at_index(index, material, now)
    }

    pub fn commit_ingress(
        &mut self,
        pending: PendingVaultSegmentV2,
        now: UnixMillisV2,
    ) -> Result<LiveVaultSegmentV2, VaultErrorV2> {
        self.accept_time(now)?;
        let installation_id = self.installation_id;
        let segment = self.segment_by_authority(pending.token, pending.internal_id)?;
        expire_segment_if_needed(segment, now);
        match segment.state {
            VaultStateV2::PendingIngress => {
                segment.state = VaultStateV2::Live;
                advance_revision(segment)?;
            }
            VaultStateV2::Live => {}
            VaultStateV2::Expired => return Err(VaultErrorV2::Expired),
            _ => return Err(VaultErrorV2::StateConflict),
        }
        if segment.authority_digest != capability_digest(installation_id, &pending.token) {
            return Err(VaultErrorV2::InvalidCapability);
        }
        Ok(LiveVaultSegmentV2 {
            token: pending.token,
            internal_id: pending.internal_id,
        })
    }

    pub fn issue_masked_document(
        &mut self,
        live: &LiveVaultSegmentV2,
        context: VaultAccessContextV2,
        now: UnixMillisV2,
    ) -> Result<MaskedDocumentHandleV2, VaultErrorV2> {
        self.accept_time(now)?;
        self.validate_context(context, now)?;
        if self.documents.len() >= MAX_DOCUMENT_CAPABILITIES {
            return Err(VaultErrorV2::AllocationFailure);
        }
        let segment = self.segment_by_authority(live.token, live.internal_id)?;
        expire_segment_if_needed(segment, now);
        if segment.state != VaultStateV2::Live || segment.durable_run_id != context.durable_run_id {
            return Err(if segment.state.terminal() {
                VaultErrorV2::TerminalState
            } else {
                VaultErrorV2::StateConflict
            });
        }
        let mut token = [0_u8; 32];
        getrandom::getrandom(&mut token).map_err(|_| VaultErrorV2::AllocationFailure)?;
        if token == [0; 32] {
            return Err(VaultErrorV2::AllocationFailure);
        }
        let document = MaskedDocumentHandleV2::from_authority_entropy(token)
            .ok_or(VaultErrorV2::AllocationFailure)?;
        let token_digest = self.document_commitment(document)?;
        if self
            .documents
            .iter()
            .any(|record| record.token_digest == token_digest)
        {
            return Err(VaultErrorV2::AllocationFailure);
        }
        self.documents
            .try_reserve(1)
            .map_err(|_| VaultErrorV2::AllocationFailure)?;
        self.documents.push(DocumentCapabilityRecordV2 {
            token_digest,
            internal_id: live.internal_id,
            context,
        });
        Ok(document)
    }

    pub fn read_agent_bytes(
        &mut self,
        document: &MaskedDocumentHandleV2,
        context: VaultAccessContextV2,
        now: UnixMillisV2,
    ) -> Result<Zeroizing<Vec<u8>>, VaultErrorV2> {
        self.accept_time(now)?;
        let index = self.resolve_document(document, context, now)?;
        let segment = &mut self.segments[index];
        expire_segment_if_needed(segment, now);
        match segment.state {
            VaultStateV2::Live | VaultStateV2::ReleaseAuthorized => {
                Ok(Zeroizing::new(segment.sensitive_bytes.to_vec()))
            }
            VaultStateV2::Expired => Err(VaultErrorV2::Expired),
            VaultStateV2::Released
            | VaultStateV2::FailedNoEffect
            | VaultStateV2::Revoked
            | VaultStateV2::Indeterminate
            | VaultStateV2::RestartInvalidated => Err(VaultErrorV2::TerminalState),
            _ => Err(VaultErrorV2::StateConflict),
        }
    }

    pub fn read_agent_bytes_for_authenticated_agent(
        &mut self,
        document: &MaskedDocumentHandleV2,
        boot_id: BootIdV2,
        service_identity: ServiceIdentityV2,
        peer_identity_digest: Digest32V2,
        now: UnixMillisV2,
    ) -> Result<Zeroizing<Vec<u8>>, VaultErrorV2> {
        self.accept_time(now)?;
        let index = self.resolve_document_for_authenticated_agent(
            document,
            boot_id,
            service_identity,
            peer_identity_digest,
            now,
        )?;
        let segment = &mut self.segments[index];
        expire_segment_if_needed(segment, now);
        match segment.state {
            VaultStateV2::Live | VaultStateV2::ReleaseAuthorized => {
                Ok(Zeroizing::new(segment.sensitive_bytes.to_vec()))
            }
            VaultStateV2::Expired => Err(VaultErrorV2::Expired),
            VaultStateV2::Released
            | VaultStateV2::FailedNoEffect
            | VaultStateV2::Revoked
            | VaultStateV2::Indeterminate
            | VaultStateV2::RestartInvalidated => Err(VaultErrorV2::TerminalState),
            _ => Err(VaultErrorV2::StateConflict),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn read_release_bytes_for_authenticated_agent(
        &mut self,
        document: &MaskedDocumentHandleV2,
        boot_id: BootIdV2,
        service_identity: ServiceIdentityV2,
        peer_identity_digest: Digest32V2,
        durable_run_id: DurableRunIdV2,
        now: UnixMillisV2,
    ) -> Result<Zeroizing<Vec<u8>>, VaultErrorV2> {
        self.accept_time(now)?;
        let index = self.resolve_document_for_authenticated_agent(
            document,
            boot_id,
            service_identity,
            peer_identity_digest,
            now,
        )?;
        let segment = &mut self.segments[index];
        expire_segment_if_needed(segment, now);
        if segment.durable_run_id != durable_run_id {
            return Err(VaultErrorV2::InvalidCapability);
        }
        match segment.state {
            VaultStateV2::Live | VaultStateV2::ReleaseAuthorized => {
                Ok(Zeroizing::new(segment.sensitive_bytes.to_vec()))
            }
            VaultStateV2::Expired => Err(VaultErrorV2::Expired),
            VaultStateV2::Released
            | VaultStateV2::FailedNoEffect
            | VaultStateV2::Revoked
            | VaultStateV2::Indeterminate
            | VaultStateV2::RestartInvalidated => Err(VaultErrorV2::TerminalState),
            _ => Err(VaultErrorV2::StateConflict),
        }
    }

    pub fn prepare_release(
        &mut self,
        document: &MaskedDocumentHandleV2,
        context: VaultAccessContextV2,
        material: VaultReleaseMaterialV2,
        now: UnixMillisV2,
    ) -> Result<PendingVaultReleaseV2, VaultErrorV2> {
        self.accept_time(now)?;
        let index = self.resolve_document(document, context, now)?;
        self.prepare_release_at_index(index, material, now)
    }

    fn prepare_release_at_index(
        &mut self,
        index: usize,
        material: VaultReleaseMaterialV2,
        now: UnixMillisV2,
    ) -> Result<PendingVaultReleaseV2, VaultErrorV2> {
        expire_segment_if_needed(&mut self.segments[index], now);
        let segment = &self.segments[index];
        if segment.state == VaultStateV2::Expired {
            return Err(VaultErrorV2::Expired);
        }
        if segment.state != VaultStateV2::Live {
            return Err(if segment.state.terminal() {
                VaultErrorV2::TerminalState
            } else {
                VaultErrorV2::StateConflict
            });
        }
        if let Some(existing) = segment.release.as_ref() {
            if release_material_matches(existing.binding, material) {
                let token = self.release_capability(existing.binding, existing.binding_digest)?;
                return Ok(PendingVaultReleaseV2 {
                    token,
                    binding: existing.binding,
                    binding_digest: existing.binding_digest,
                });
            }
            return Err(VaultErrorV2::StateConflict);
        }

        let mut release_entropy = [0_u8; 32];
        getrandom::getrandom(&mut release_entropy).map_err(|_| VaultErrorV2::AllocationFailure)?;
        if release_entropy == [0; 32] {
            return Err(VaultErrorV2::AllocationFailure);
        }
        let durable_release_id = DurableReleaseIdV2::new(
            *domain_hash_many(
                b"SAVANA_DURABLE_RELEASE_ID_V2\0",
                &[
                    self.installation_id.as_bytes(),
                    segment.internal_id.as_bytes(),
                    &release_entropy,
                ],
            )
            .as_bytes(),
        );
        let binding = FinalReleaseSemanticBindingV2::from_nonzero_components(
            durable_release_id,
            segment.internal_id,
            segment.segment_digest,
            material.release_payload_digest,
            material.evidence_digest,
            material.token_set_digest,
            material.destination_digest,
            material.display_projection_digest,
            material.display_digest,
            material.executor_identity_digest,
            material.release_quota_subject_digest,
        )
        .ok_or(VaultErrorV2::InvalidInput)?;
        let binding_digest = binding
            .semantic_digest()
            .ok_or(VaultErrorV2::AllocationFailure)?;
        let token = self.release_capability(binding, binding_digest)?;
        let capability_digest = capability_digest(self.installation_id, &token);
        self.segments[index].release = Some(VaultReleaseRecordV2 {
            capability_digest,
            binding,
            binding_digest,
            approval_principal: None,
            approval_settlement_digest: None,
            consumed_ticket_digest: None,
            execution_nonce: None,
            dispatch_core_digest: None,
            dispatch_subject_digest: None,
            final_release_receipt_digest: None,
            release_audit_digest: None,
        });
        Ok(PendingVaultReleaseV2 {
            token,
            binding,
            binding_digest,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn prepare_release_for_authenticated_agent(
        &mut self,
        document: &MaskedDocumentHandleV2,
        boot_id: BootIdV2,
        service_identity: ServiceIdentityV2,
        peer_identity_digest: Digest32V2,
        durable_run_id: DurableRunIdV2,
        material: VaultReleaseMaterialV2,
        now: UnixMillisV2,
    ) -> Result<PendingVaultReleaseV2, VaultErrorV2> {
        self.accept_time(now)?;
        let index = self.resolve_document_for_authenticated_agent(
            document,
            boot_id,
            service_identity,
            peer_identity_digest,
            now,
        )?;
        if self.segments[index].durable_run_id != durable_run_id {
            return Err(VaultErrorV2::InvalidCapability);
        }
        self.prepare_release_at_index(index, material, now)
    }

    pub fn authorize_release(
        &mut self,
        pending: PendingVaultReleaseV2,
        approval: VerifiedFinalReleaseApprovalV2,
        now: UnixMillisV2,
    ) -> Result<AuthorizedVaultReleaseV2, VaultErrorV2> {
        self.accept_time(now)?;
        let index = self.release_segment_index(pending.token, pending.binding)?;
        expire_segment_if_needed(&mut self.segments[index], now);
        let segment = &mut self.segments[index];
        if now.get() >= approval.expires_at.get()
            || approval.binding_digest != pending.binding_digest
            || approval.authenticated_principal != segment.authenticated_principal
        {
            return Err(VaultErrorV2::InvalidApproval);
        }
        match segment.state {
            VaultStateV2::Live => {
                let release = segment
                    .release
                    .as_mut()
                    .ok_or(VaultErrorV2::StateConflict)?;
                release.approval_principal = Some(approval.authenticated_principal);
                release.approval_settlement_digest = Some(approval.settlement_digest);
                segment.state = VaultStateV2::ReleaseAuthorized;
                advance_revision(segment)?;
            }
            VaultStateV2::ReleaseAuthorized => {
                let release = segment
                    .release
                    .as_ref()
                    .ok_or(VaultErrorV2::StateConflict)?;
                if release.approval_principal != Some(approval.authenticated_principal)
                    || release.approval_settlement_digest != Some(approval.settlement_digest)
                {
                    return Err(VaultErrorV2::StateConflict);
                }
            }
            VaultStateV2::Expired => return Err(VaultErrorV2::Expired),
            state if state.terminal() => return Err(VaultErrorV2::TerminalState),
            _ => return Err(VaultErrorV2::StateConflict),
        }
        Ok(AuthorizedVaultReleaseV2 {
            token: pending.token,
            binding: pending.binding,
            binding_digest: pending.binding_digest,
            approval_settlement_digest: approval.settlement_digest,
        })
    }

    pub fn mark_dispatch_prepared(
        &mut self,
        authorized: AuthorizedVaultReleaseV2,
        commit: KernelPreparedReleaseDispatchV2,
        now: UnixMillisV2,
    ) -> Result<VaultDispatchPreparedV2, VaultErrorV2> {
        self.accept_time(now)?;
        let index = self.release_segment_index(authorized.token, authorized.binding)?;
        expire_segment_if_needed(&mut self.segments[index], now);
        let expected_subject = final_release_subject_digest(
            authorized.binding,
            authorized.approval_settlement_digest,
        )?;
        if commit.binding != authorized.binding
            || commit.dispatch_subject_digest != expected_subject
            || authorized.binding_digest
                != authorized
                    .binding
                    .semantic_digest()
                    .ok_or(VaultErrorV2::StateConflict)?
        {
            return Err(VaultErrorV2::StateConflict);
        }
        let segment = &mut self.segments[index];
        match segment.state {
            VaultStateV2::ReleaseAuthorized => {
                let release = segment
                    .release
                    .as_mut()
                    .ok_or(VaultErrorV2::StateConflict)?;
                release.consumed_ticket_digest = Some(commit.consumed_ticket_digest);
                release.execution_nonce = Some(commit.execution_nonce);
                release.dispatch_core_digest = Some(commit.dispatch_core_digest);
                release.dispatch_subject_digest = Some(commit.dispatch_subject_digest);
                segment.state = VaultStateV2::DispatchPrepared;
                advance_revision(segment)?;
            }
            VaultStateV2::DispatchPrepared | VaultStateV2::Dispatching => {
                let release = segment
                    .release
                    .as_ref()
                    .ok_or(VaultErrorV2::StateConflict)?;
                if release.consumed_ticket_digest != Some(commit.consumed_ticket_digest)
                    || release.execution_nonce != Some(commit.execution_nonce)
                    || release.dispatch_core_digest != Some(commit.dispatch_core_digest)
                    || release.dispatch_subject_digest != Some(commit.dispatch_subject_digest)
                {
                    return Err(VaultErrorV2::StateConflict);
                }
            }
            VaultStateV2::Expired => return Err(VaultErrorV2::Expired),
            state if state.terminal() => return Err(VaultErrorV2::TerminalState),
            _ => return Err(VaultErrorV2::StateConflict),
        }
        Ok(VaultDispatchPreparedV2 {
            token: authorized.token,
            binding: authorized.binding,
            execution_nonce: commit.execution_nonce,
            dispatch_core_digest: commit.dispatch_core_digest,
            dispatch_subject_digest: commit.dispatch_subject_digest,
        })
    }

    pub fn mark_dispatching(
        &mut self,
        prepared: VaultDispatchPreparedV2,
        now: UnixMillisV2,
    ) -> Result<(), VaultErrorV2> {
        self.accept_time(now)?;
        let index = self.release_segment_index(prepared.token, prepared.binding)?;
        let segment = &mut self.segments[index];
        exact_dispatch_matches(segment, prepared)?;
        match segment.state {
            VaultStateV2::DispatchPrepared => {
                segment.state = VaultStateV2::Dispatching;
                advance_revision(segment)
            }
            VaultStateV2::Dispatching => Ok(()),
            state if state.terminal() => Err(VaultErrorV2::TerminalState),
            _ => Err(VaultErrorV2::StateConflict),
        }
    }

    pub fn commit_known_release(
        &mut self,
        prepared: VaultDispatchPreparedV2,
        final_release_receipt_digest: Digest32V2,
        release_audit_digest: Digest32V2,
        now: UnixMillisV2,
    ) -> Result<(), VaultErrorV2> {
        self.accept_time(now)?;
        if is_zero(final_release_receipt_digest.as_bytes())
            || is_zero(release_audit_digest.as_bytes())
        {
            return Err(VaultErrorV2::InvalidInput);
        }
        let index = self.release_segment_index(prepared.token, prepared.binding)?;
        let segment = &mut self.segments[index];
        exact_dispatch_matches(segment, prepared)?;
        match segment.state {
            VaultStateV2::DispatchPrepared | VaultStateV2::Dispatching => {
                let release = segment
                    .release
                    .as_mut()
                    .ok_or(VaultErrorV2::StateConflict)?;
                release.final_release_receipt_digest = Some(final_release_receipt_digest);
                release.release_audit_digest = Some(release_audit_digest);
                segment.state = VaultStateV2::Released;
                clear_sensitive(segment);
                advance_revision(segment)
            }
            VaultStateV2::Released => {
                let release = segment
                    .release
                    .as_ref()
                    .ok_or(VaultErrorV2::StateConflict)?;
                if release.final_release_receipt_digest == Some(final_release_receipt_digest)
                    && release.release_audit_digest == Some(release_audit_digest)
                {
                    Ok(())
                } else {
                    Err(VaultErrorV2::StateConflict)
                }
            }
            state if state.terminal() => Err(VaultErrorV2::TerminalState),
            _ => Err(VaultErrorV2::StateConflict),
        }
    }

    pub fn mark_indeterminate(
        &mut self,
        prepared: VaultDispatchPreparedV2,
        now: UnixMillisV2,
    ) -> Result<(), VaultErrorV2> {
        self.accept_time(now)?;
        let index = self.release_segment_index(prepared.token, prepared.binding)?;
        let segment = &mut self.segments[index];
        exact_dispatch_matches(segment, prepared)?;
        match segment.state {
            VaultStateV2::DispatchPrepared | VaultStateV2::Dispatching => {
                segment.state = VaultStateV2::Indeterminate;
                clear_sensitive(segment);
                advance_revision(segment)
            }
            VaultStateV2::Indeterminate => Ok(()),
            state if state.terminal() => Err(VaultErrorV2::TerminalState),
            _ => Err(VaultErrorV2::StateConflict),
        }
    }

    pub fn mark_failed_no_effect_by_identity(
        &mut self,
        durable_release_id: DurableReleaseIdV2,
        execution_nonce: Nonce32V2,
        dispatch_core_digest: Digest32V2,
        dispatch_subject_digest: Digest32V2,
        now: UnixMillisV2,
    ) -> Result<(), VaultErrorV2> {
        self.accept_time(now)?;
        validate_recovery_identity(
            durable_release_id,
            execution_nonce,
            dispatch_core_digest,
            dispatch_subject_digest,
        )?;
        let index = self.release_segment_index_by_id(durable_release_id)?;
        let segment = &mut self.segments[index];
        let release = segment
            .release
            .as_mut()
            .ok_or(VaultErrorV2::StateConflict)?;
        let expected_subject = release
            .approval_settlement_digest
            .and_then(|approval| final_release_subject_digest(release.binding, approval).ok())
            .ok_or(VaultErrorV2::StateConflict)?;
        if expected_subject != dispatch_subject_digest {
            return Err(VaultErrorV2::StateConflict);
        }
        match segment.state {
            VaultStateV2::ReleaseAuthorized => {
                if release.execution_nonce.is_some()
                    || release.dispatch_core_digest.is_some()
                    || release.dispatch_subject_digest.is_some()
                {
                    return Err(VaultErrorV2::StateConflict);
                }
                release.execution_nonce = Some(execution_nonce);
                release.dispatch_core_digest = Some(dispatch_core_digest);
                release.dispatch_subject_digest = Some(dispatch_subject_digest);
            }
            VaultStateV2::DispatchPrepared | VaultStateV2::Dispatching => {
                require_release_identity(
                    release,
                    execution_nonce,
                    dispatch_core_digest,
                    dispatch_subject_digest,
                )?;
            }
            VaultStateV2::FailedNoEffect => {
                return require_release_identity(
                    release,
                    execution_nonce,
                    dispatch_core_digest,
                    dispatch_subject_digest,
                );
            }
            state if state.terminal() => return Err(VaultErrorV2::TerminalState),
            _ => return Err(VaultErrorV2::StateConflict),
        }
        segment.state = VaultStateV2::FailedNoEffect;
        clear_sensitive(segment);
        advance_revision(segment)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn commit_known_release_by_identity(
        &mut self,
        durable_release_id: DurableReleaseIdV2,
        execution_nonce: Nonce32V2,
        dispatch_core_digest: Digest32V2,
        dispatch_subject_digest: Digest32V2,
        final_release_receipt_digest: Digest32V2,
        release_audit_digest: Digest32V2,
        now: UnixMillisV2,
    ) -> Result<(), VaultErrorV2> {
        self.accept_time(now)?;
        validate_recovery_identity(
            durable_release_id,
            execution_nonce,
            dispatch_core_digest,
            dispatch_subject_digest,
        )?;
        if is_zero(final_release_receipt_digest.as_bytes())
            || is_zero(release_audit_digest.as_bytes())
        {
            return Err(VaultErrorV2::InvalidInput);
        }
        let index = self.release_segment_index_by_id(durable_release_id)?;
        let segment = &mut self.segments[index];
        let release = segment
            .release
            .as_mut()
            .ok_or(VaultErrorV2::StateConflict)?;
        require_release_identity(
            release,
            execution_nonce,
            dispatch_core_digest,
            dispatch_subject_digest,
        )?;
        match segment.state {
            VaultStateV2::DispatchPrepared | VaultStateV2::Dispatching => {
                release.final_release_receipt_digest = Some(final_release_receipt_digest);
                release.release_audit_digest = Some(release_audit_digest);
                segment.state = VaultStateV2::Released;
                clear_sensitive(segment);
                advance_revision(segment)
            }
            VaultStateV2::Released
                if release.final_release_receipt_digest == Some(final_release_receipt_digest)
                    && release.release_audit_digest == Some(release_audit_digest) =>
            {
                Ok(())
            }
            state if state.terminal() => Err(VaultErrorV2::TerminalState),
            _ => Err(VaultErrorV2::StateConflict),
        }
    }

    pub fn mark_indeterminate_by_identity(
        &mut self,
        durable_release_id: DurableReleaseIdV2,
        execution_nonce: Nonce32V2,
        dispatch_core_digest: Digest32V2,
        dispatch_subject_digest: Digest32V2,
        now: UnixMillisV2,
    ) -> Result<(), VaultErrorV2> {
        self.accept_time(now)?;
        validate_recovery_identity(
            durable_release_id,
            execution_nonce,
            dispatch_core_digest,
            dispatch_subject_digest,
        )?;
        let index = self.release_segment_index_by_id(durable_release_id)?;
        let segment = &mut self.segments[index];
        let release = segment
            .release
            .as_ref()
            .ok_or(VaultErrorV2::StateConflict)?;
        require_release_identity(
            release,
            execution_nonce,
            dispatch_core_digest,
            dispatch_subject_digest,
        )?;
        match segment.state {
            VaultStateV2::DispatchPrepared | VaultStateV2::Dispatching => {
                segment.state = VaultStateV2::Indeterminate;
                clear_sensitive(segment);
                advance_revision(segment)
            }
            VaultStateV2::Indeterminate => Ok(()),
            state if state.terminal() => Err(VaultErrorV2::TerminalState),
            _ => Err(VaultErrorV2::StateConflict),
        }
    }

    pub fn revoke(
        &mut self,
        document: &MaskedDocumentHandleV2,
        context: VaultAccessContextV2,
        now: UnixMillisV2,
    ) -> Result<VaultPublicStateV2, VaultErrorV2> {
        self.accept_time(now)?;
        let index = self.resolve_document(document, context, now)?;
        let segment = &mut self.segments[index];
        expire_segment_if_needed(segment, now);
        match segment.state {
            VaultStateV2::PendingIngress | VaultStateV2::Live | VaultStateV2::ReleaseAuthorized => {
                segment.state = VaultStateV2::Revoked;
                clear_sensitive(segment);
                advance_revision(segment)?;
                Ok(VaultPublicStateV2::Revoked)
            }
            VaultStateV2::Revoked => Ok(VaultPublicStateV2::Revoked),
            VaultStateV2::Expired => Err(VaultErrorV2::Expired),
            VaultStateV2::Released
            | VaultStateV2::FailedNoEffect
            | VaultStateV2::Indeterminate
            | VaultStateV2::RestartInvalidated => Err(VaultErrorV2::TerminalState),
            VaultStateV2::DispatchPrepared | VaultStateV2::Dispatching => {
                Err(VaultErrorV2::StateConflict)
            }
        }
    }

    pub fn revoke_for_authenticated_agent(
        &mut self,
        document: &MaskedDocumentHandleV2,
        boot_id: BootIdV2,
        service_identity: ServiceIdentityV2,
        peer_identity_digest: Digest32V2,
        now: UnixMillisV2,
    ) -> Result<VaultPublicStateV2, VaultErrorV2> {
        self.accept_time(now)?;
        let index = self.resolve_document_for_authenticated_agent(
            document,
            boot_id,
            service_identity,
            peer_identity_digest,
            now,
        )?;
        let segment = &mut self.segments[index];
        expire_segment_if_needed(segment, now);
        match segment.state {
            VaultStateV2::PendingIngress | VaultStateV2::Live | VaultStateV2::ReleaseAuthorized => {
                segment.state = VaultStateV2::Revoked;
                clear_sensitive(segment);
                advance_revision(segment)?;
                Ok(VaultPublicStateV2::Revoked)
            }
            VaultStateV2::Revoked => Ok(VaultPublicStateV2::Revoked),
            VaultStateV2::Expired => Err(VaultErrorV2::Expired),
            VaultStateV2::Released
            | VaultStateV2::FailedNoEffect
            | VaultStateV2::Indeterminate
            | VaultStateV2::RestartInvalidated => Err(VaultErrorV2::TerminalState),
            VaultStateV2::DispatchPrepared | VaultStateV2::Dispatching => {
                Err(VaultErrorV2::StateConflict)
            }
        }
    }

    pub fn public_state(
        &mut self,
        document: &MaskedDocumentHandleV2,
        context: VaultAccessContextV2,
        now: UnixMillisV2,
    ) -> Result<VaultPublicStateV2, VaultErrorV2> {
        self.accept_time(now)?;
        let index = self.resolve_document(document, context, now)?;
        expire_segment_if_needed(&mut self.segments[index], now);
        Ok(self.segments[index].state.public())
    }

    pub fn state_record_digest(
        &mut self,
        document: &MaskedDocumentHandleV2,
        context: VaultAccessContextV2,
        now: UnixMillisV2,
    ) -> Result<Digest32V2, VaultErrorV2> {
        self.accept_time(now)?;
        let index = self.resolve_document(document, context, now)?;
        expire_segment_if_needed(&mut self.segments[index], now);
        let segment = &self.segments[index];
        Ok(domain_hash_many(
            b"SAVANA_VAULT_STATE_RECORD_V2\0",
            &[
                self.installation_id.as_bytes(),
                self.active_state_manifest_digest.as_bytes(),
                segment.durable_task_id.as_bytes(),
                segment.durable_run_id.as_bytes(),
                segment.internal_id.as_bytes(),
                segment.provenance_digest.as_bytes(),
                segment.input_commit_digest.as_bytes(),
                segment.segment_digest.as_bytes(),
                &segment.state_revision.to_be_bytes(),
                &vault_state_tag(segment.state).to_be_bytes(),
                segment.expires_at.get().to_be_bytes().as_slice(),
            ],
        ))
    }

    pub fn invalidate_for_restart(
        &mut self,
        live: &LiveVaultSegmentV2,
        now: UnixMillisV2,
    ) -> Result<VaultPublicStateV2, VaultErrorV2> {
        self.accept_time(now)?;
        let segment = self.segment_by_authority(live.token, live.internal_id)?;
        match segment.state {
            VaultStateV2::PendingIngress | VaultStateV2::Live | VaultStateV2::ReleaseAuthorized => {
                segment.state = VaultStateV2::RestartInvalidated;
                clear_sensitive(segment);
                advance_revision(segment)?;
                Ok(VaultPublicStateV2::RestartInvalidated)
            }
            VaultStateV2::RestartInvalidated => Ok(VaultPublicStateV2::RestartInvalidated),
            VaultStateV2::Expired => Err(VaultErrorV2::Expired),
            VaultStateV2::DispatchPrepared | VaultStateV2::Dispatching => {
                Err(VaultErrorV2::StateConflict)
            }
            VaultStateV2::Released
            | VaultStateV2::FailedNoEffect
            | VaultStateV2::Revoked
            | VaultStateV2::Indeterminate => Err(VaultErrorV2::TerminalState),
        }
    }

    fn accept_time(&mut self, now: UnixMillisV2) -> Result<(), VaultErrorV2> {
        if now.get() == 0 || now.get() < self.accepted_time_floor_ms {
            return Err(VaultErrorV2::ClockRollback);
        }
        self.accepted_time_floor_ms = now.get();
        Ok(())
    }

    fn validate_context(
        &self,
        context: VaultAccessContextV2,
        now: UnixMillisV2,
    ) -> Result<(), VaultErrorV2> {
        if context.boot_id != self.boot_id || now.get() >= context.expires_at.get() {
            return Err(VaultErrorV2::InvalidCapability);
        }
        Ok(())
    }

    fn segment_by_authority(
        &mut self,
        token: [u8; 32],
        internal_id: Digest32V2,
    ) -> Result<&mut VaultSegmentRecordV2, VaultErrorV2> {
        let expected = capability_digest(self.installation_id, &token);
        self.segments
            .iter_mut()
            .find(|segment| {
                segment.internal_id == internal_id && segment.authority_digest == expected
            })
            .ok_or(VaultErrorV2::InvalidCapability)
    }

    fn resolve_document(
        &self,
        document: &MaskedDocumentHandleV2,
        context: VaultAccessContextV2,
        now: UnixMillisV2,
    ) -> Result<usize, VaultErrorV2> {
        self.validate_context(context, now)?;
        let token_digest = self.document_commitment(*document)?;
        let record = self
            .documents
            .iter()
            .find(|record| record.token_digest == token_digest)
            .ok_or(VaultErrorV2::InvalidCapability)?;
        if record.context != context {
            return Err(VaultErrorV2::InvalidCapability);
        }
        self.segments
            .iter()
            .position(|segment| segment.internal_id == record.internal_id)
            .ok_or(VaultErrorV2::InvalidCapability)
    }

    fn resolve_document_for_authenticated_agent(
        &self,
        document: &MaskedDocumentHandleV2,
        boot_id: BootIdV2,
        service_identity: ServiceIdentityV2,
        peer_identity_digest: Digest32V2,
        now: UnixMillisV2,
    ) -> Result<usize, VaultErrorV2> {
        if [
            boot_id.as_bytes(),
            service_identity.as_bytes(),
            peer_identity_digest.as_bytes(),
        ]
        .iter()
        .any(|value| is_zero(value))
        {
            return Err(VaultErrorV2::InvalidCapability);
        }
        let token_digest = self.document_commitment(*document)?;
        let record = self
            .documents
            .iter()
            .find(|record| record.token_digest == token_digest)
            .ok_or(VaultErrorV2::InvalidCapability)?;
        if record.context.boot_id != boot_id
            || record.context.service_identity != service_identity
            || record.context.peer_identity_digest != peer_identity_digest
            || now.get() >= record.context.expires_at.get()
        {
            return Err(VaultErrorV2::InvalidCapability);
        }
        self.segments
            .iter()
            .position(|segment| segment.internal_id == record.internal_id)
            .ok_or(VaultErrorV2::InvalidCapability)
    }

    fn document_commitment(
        &self,
        document: MaskedDocumentHandleV2,
    ) -> Result<Digest32V2, VaultErrorV2> {
        let key = AuthorityHandleKeyV2::from_entropy(*self.capability_key)
            .ok_or(VaultErrorV2::DurableState)?;
        Ok(document.authority_commitment(&key))
    }

    fn release_segment_index(
        &self,
        token: [u8; 32],
        binding: FinalReleaseSemanticBindingV2,
    ) -> Result<usize, VaultErrorV2> {
        let token_digest = capability_digest(self.installation_id, &token);
        self.segments
            .iter()
            .position(|segment| {
                segment.internal_id == binding.vault_segment_internal_id()
                    && segment.release.as_ref().is_some_and(|release| {
                        release.binding == binding
                            && release.capability_digest == token_digest
                            && release.binding_digest
                                == binding
                                    .semantic_digest()
                                    .unwrap_or(Digest32V2::new([0; 32]))
                    })
            })
            .ok_or(VaultErrorV2::InvalidCapability)
    }

    fn release_segment_index_by_id(
        &self,
        durable_release_id: DurableReleaseIdV2,
    ) -> Result<usize, VaultErrorV2> {
        self.segments
            .iter()
            .position(|segment| {
                segment.release.as_ref().is_some_and(|release| {
                    release.binding.durable_release_id() == durable_release_id
                })
            })
            .ok_or(VaultErrorV2::StateConflict)
    }

    fn derive_capability(
        &self,
        kind: &[u8],
        stable_id: &[u8; 32],
        context: &[u8],
    ) -> Result<[u8; 32], VaultErrorV2> {
        let mut mac = <Hmac<Sha256>>::new_from_slice(self.capability_key.as_ref())
            .map_err(|_| VaultErrorV2::AllocationFailure)?;
        mac.update(CAPABILITY_DERIVATION_DOMAIN);
        mac.update(kind);
        mac.update(self.installation_id.as_bytes());
        mac.update(self.boot_id.as_bytes());
        mac.update(stable_id);
        mac.update(context);
        let token: [u8; 32] = mac.finalize().into_bytes().into();
        if token == [0; 32] {
            return Err(VaultErrorV2::AllocationFailure);
        }
        Ok(token)
    }

    fn release_capability(
        &self,
        binding: FinalReleaseSemanticBindingV2,
        binding_digest: Digest32V2,
    ) -> Result<[u8; 32], VaultErrorV2> {
        self.derive_capability(
            b"pending-release",
            binding.durable_release_id().as_bytes(),
            binding_digest.as_bytes(),
        )
    }
}

fn vault_segment_digest(
    installation_id: Digest32V2,
    manifest_digest: Digest32V2,
    internal_id: Digest32V2,
    material: &VaultIngressMaterialV2,
) -> Digest32V2 {
    domain_hash_many(
        VAULT_SEGMENT_DOMAIN,
        &[
            installation_id.as_bytes(),
            manifest_digest.as_bytes(),
            internal_id.as_bytes(),
            material.durable_task_id.as_bytes(),
            material.durable_run_id.as_bytes(),
            material.authenticated_principal.as_bytes(),
            material.provenance_digest.as_bytes(),
            material.input_commit_digest.as_bytes(),
            &material.expires_at.get().to_be_bytes(),
            &(material.sensitive_bytes.len() as u64).to_be_bytes(),
            material.sensitive_bytes.as_slice(),
        ],
    )
}

fn capability_digest(installation_id: Digest32V2, token: &[u8; 32]) -> Digest32V2 {
    domain_hash_many(CAPABILITY_HASH_DOMAIN, &[installation_id.as_bytes(), token])
}

fn domain_hash_many(domain: &[u8], fields: &[&[u8]]) -> Digest32V2 {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    for field in fields {
        hasher.update(field);
    }
    Digest32V2::new(hasher.finalize().into())
}

fn final_release_subject_digest(
    binding: FinalReleaseSemanticBindingV2,
    approval_settlement_digest: Digest32V2,
) -> Result<Digest32V2, VaultErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(3)
        .and_then(|encoder| encoder.u16(2))
        .map_err(|_| VaultErrorV2::AllocationFailure)?;
    binding
        .encode(&mut encoder, &mut ())
        .map_err(|_| VaultErrorV2::AllocationFailure)?;
    approval_settlement_digest
        .encode(&mut encoder, &mut ())
        .map_err(|_| VaultErrorV2::AllocationFailure)?;
    Ok(domain_hash_many(
        DISPATCH_SUBJECT_DOMAIN,
        &[&encoder.into_writer()],
    ))
}

fn release_material_matches(
    binding: FinalReleaseSemanticBindingV2,
    material: VaultReleaseMaterialV2,
) -> bool {
    binding.release_payload_digest() == material.release_payload_digest
        && binding.evidence_digest() == material.evidence_digest
        && binding.token_set_digest() == material.token_set_digest
        && binding.destination_digest() == material.destination_digest
        && binding.display_projection_digest() == material.display_projection_digest
        && binding.display_digest() == material.display_digest
        && binding.executor_identity_digest() == material.executor_identity_digest
        && binding.release_quota_subject_digest() == material.release_quota_subject_digest
}

fn exact_dispatch_matches(
    segment: &VaultSegmentRecordV2,
    prepared: VaultDispatchPreparedV2,
) -> Result<(), VaultErrorV2> {
    let release = segment
        .release
        .as_ref()
        .ok_or(VaultErrorV2::StateConflict)?;
    if release.binding != prepared.binding
        || release.execution_nonce != Some(prepared.execution_nonce)
        || release.dispatch_core_digest != Some(prepared.dispatch_core_digest)
        || release.dispatch_subject_digest != Some(prepared.dispatch_subject_digest)
    {
        return Err(VaultErrorV2::StateConflict);
    }
    Ok(())
}

fn validate_recovery_identity(
    durable_release_id: DurableReleaseIdV2,
    execution_nonce: Nonce32V2,
    dispatch_core_digest: Digest32V2,
    dispatch_subject_digest: Digest32V2,
) -> Result<(), VaultErrorV2> {
    if is_zero(durable_release_id.as_bytes())
        || is_zero(execution_nonce.as_bytes())
        || is_zero(dispatch_core_digest.as_bytes())
        || is_zero(dispatch_subject_digest.as_bytes())
    {
        Err(VaultErrorV2::InvalidInput)
    } else {
        Ok(())
    }
}

fn require_release_identity(
    release: &VaultReleaseRecordV2,
    execution_nonce: Nonce32V2,
    dispatch_core_digest: Digest32V2,
    dispatch_subject_digest: Digest32V2,
) -> Result<(), VaultErrorV2> {
    if release.execution_nonce == Some(execution_nonce)
        && release.dispatch_core_digest == Some(dispatch_core_digest)
        && release.dispatch_subject_digest == Some(dispatch_subject_digest)
    {
        Ok(())
    } else {
        Err(VaultErrorV2::StateConflict)
    }
}

fn expire_segment_if_needed(segment: &mut VaultSegmentRecordV2, now: UnixMillisV2) {
    if now.get() >= segment.expires_at.get() && !segment.state.terminal() {
        segment.state = VaultStateV2::Expired;
        clear_sensitive(segment);
        segment.state_revision = segment.state_revision.saturating_add(1);
    }
}

fn clear_sensitive(segment: &mut VaultSegmentRecordV2) {
    segment.sensitive_bytes = Zeroizing::new(Vec::new());
}

fn advance_revision(segment: &mut VaultSegmentRecordV2) -> Result<(), VaultErrorV2> {
    segment.state_revision = segment
        .state_revision
        .checked_add(1)
        .ok_or(VaultErrorV2::StateConflict)?;
    Ok(())
}

const fn vault_state_tag(state: VaultStateV2) -> u16 {
    match state {
        VaultStateV2::PendingIngress => 1,
        VaultStateV2::Live => 2,
        VaultStateV2::ReleaseAuthorized => 3,
        VaultStateV2::DispatchPrepared => 4,
        VaultStateV2::Dispatching => 5,
        VaultStateV2::Released => 6,
        VaultStateV2::FailedNoEffect => 11,
        VaultStateV2::Revoked => 7,
        VaultStateV2::Expired => 8,
        VaultStateV2::Indeterminate => 9,
        VaultStateV2::RestartInvalidated => 10,
    }
}

const fn decode_vault_state_tag(tag: u16) -> Option<VaultStateV2> {
    match tag {
        1 => Some(VaultStateV2::PendingIngress),
        2 => Some(VaultStateV2::Live),
        3 => Some(VaultStateV2::ReleaseAuthorized),
        4 => Some(VaultStateV2::DispatchPrepared),
        5 => Some(VaultStateV2::Dispatching),
        6 => Some(VaultStateV2::Released),
        7 => Some(VaultStateV2::Revoked),
        8 => Some(VaultStateV2::Expired),
        9 => Some(VaultStateV2::Indeterminate),
        10 => Some(VaultStateV2::RestartInvalidated),
        11 => Some(VaultStateV2::FailedNoEffect),
        _ => None,
    }
}

fn is_zero(bytes: &[u8; 32]) -> bool {
    bytes == &[0; 32]
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;
    use std::sync::{Arc, Mutex};

    use savana_kernel_protocol::v2::{
        BootIdV2, Digest32V2, DurableRunIdV2, DurableTaskIdV2, Nonce32V2, PrincipalIdV2,
        ServiceIdentityV2, UnixMillisV2,
    };

    use super::*;

    fn service() -> VaultServiceV2 {
        VaultServiceV2::from_verified_deployment(
            Digest32V2::new([1; 32]),
            Digest32V2::new([2; 32]),
            BootIdV2::new([3; 32]),
            128,
        )
        .unwrap()
    }

    fn ingress(bytes: &[u8]) -> VaultIngressMaterialV2 {
        ingress_for_task(4, bytes)
    }

    fn ingress_for_task(task_seed: u8, bytes: &[u8]) -> VaultIngressMaterialV2 {
        VaultIngressMaterialV2::from_verified_gated_input(
            DurableTaskIdV2::new([task_seed; 32]),
            DurableRunIdV2::new([5; 32]),
            PrincipalIdV2::new([0x40; 32]),
            Digest32V2::new([6; 32]),
            Digest32V2::new([7; 32]),
            UnixMillisV2::new(10_000),
            bytes.to_vec(),
        )
        .unwrap()
    }

    fn access(peer: u8) -> VaultAccessContextV2 {
        VaultAccessContextV2::from_authenticated_agent(
            BootIdV2::new([3; 32]),
            ServiceIdentityV2::new([8; 32]),
            Digest32V2::new([peer; 32]),
            DurableRunIdV2::new([5; 32]),
            UnixMillisV2::new(20_000),
        )
        .unwrap()
    }

    #[test]
    fn durable_tool_results_are_distinct_replayable_and_cannot_replace_original_input() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.path().join("vault-state-v2.cbor");
        let namespace = DurableVaultNamespaceV2::from_verified_installation(
            Digest32V2::new([1; 32]),
            Digest32V2::new([0x70; 32]),
        )
        .unwrap();
        let anchor = TestRollbackAnchor::default();
        let mut owner = DurableVaultServiceV2::open(
            &path,
            [0x71; 32],
            namespace,
            Box::new(anchor.clone()),
            service(),
        )
        .unwrap();
        let original = owner
            .create_pending_ingress(ingress(b"original"), UnixMillisV2::new(100))
            .unwrap();
        owner
            .commit_ingress(original, UnixMillisV2::new(100))
            .unwrap();
        let mut documents = Vec::new();
        for seed in [7, 8] {
            let mut result = ingress(&[seed]);
            result.input_commit_digest = Digest32V2::new([seed; 32]);
            let pending = owner
                .create_pending_tool_result(result.clone(), UnixMillisV2::new(101))
                .unwrap();
            let live = owner
                .commit_ingress(pending, UnixMillisV2::new(101))
                .unwrap();
            documents.push(
                owner
                    .issue_masked_document(&live, access(9), UnixMillisV2::new(101))
                    .unwrap(),
            );
            let replay = owner
                .create_pending_tool_result(result.clone(), UnixMillisV2::new(101))
                .unwrap();
            assert_eq!(replay.internal_id, pending.internal_id);
            result.sensitive_bytes = Zeroizing::new(b"substituted".to_vec());
            assert!(matches!(
                owner.create_pending_tool_result(result, UnixMillisV2::new(101)),
                Err(VaultErrorV2::StateConflict)
            ));
        }
        assert_eq!(owner.segment_count(), 3);
        assert!(matches!(
            owner.create_pending_ingress(ingress(b"replacement"), UnixMillisV2::new(103)),
            Err(VaultErrorV2::StateConflict)
        ));
        drop(owner);
        let mut owner =
            DurableVaultServiceV2::open(&path, [0x71; 32], namespace, Box::new(anchor), service())
                .unwrap();
        assert_eq!(owner.segment_count(), 3);
        for (document, seed) in documents.iter().zip([7, 8]) {
            assert_eq!(
                owner
                    .read_agent_bytes_for_authenticated_agent(
                        document,
                        BootIdV2::new([3; 32]),
                        ServiceIdentityV2::new([8; 32]),
                        Digest32V2::new([9; 32]),
                        UnixMillisV2::new(104),
                    )
                    .unwrap()
                    .as_slice(),
                &[seed]
            );
        }
        let replay = owner
            .create_pending_ingress(ingress(b"original"), UnixMillisV2::new(104))
            .unwrap();
        assert_eq!(replay.internal_id, original.internal_id);
    }

    #[test]
    fn committed_tool_result_recovery_reopens_without_plaintext_or_old_document_handle() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.path().join("vault-state-v2.cbor");
        let namespace = DurableVaultNamespaceV2::from_verified_installation(
            Digest32V2::new([1; 32]),
            Digest32V2::new([0x70; 32]),
        )
        .unwrap();
        let anchor = TestRollbackAnchor::default();
        let mut owner = DurableVaultServiceV2::open(
            &path,
            [0x71; 32],
            namespace,
            Box::new(anchor.clone()),
            service(),
        )
        .unwrap();
        let material = ingress(b"private recovered result");
        let pending = owner
            .create_pending_tool_result(material.clone(), UnixMillisV2::new(100))
            .unwrap();
        assert!(owner
            .recover_committed_tool_result(
                material.durable_task_id,
                material.durable_run_id,
                material.authenticated_principal,
                material.input_commit_digest,
                material.expires_at,
                UnixMillisV2::new(100)
            )
            .is_err());
        owner
            .commit_ingress(pending, UnixMillisV2::new(101))
            .unwrap();
        drop(owner);
        let deployment = VaultServiceV2::from_verified_deployment(
            Digest32V2::new([1; 32]),
            Digest32V2::new([2; 32]),
            BootIdV2::new([43; 32]),
            128,
        )
        .unwrap();
        let mut owner =
            DurableVaultServiceV2::open(&path, [0x71; 32], namespace, Box::new(anchor), deployment)
                .unwrap();
        for mode in 0..5 {
            assert!(owner
                .recover_committed_tool_result(
                    if mode == 0 {
                        DurableTaskIdV2::new([55; 32])
                    } else {
                        material.durable_task_id
                    },
                    if mode == 1 {
                        DurableRunIdV2::new([55; 32])
                    } else {
                        material.durable_run_id
                    },
                    if mode == 2 {
                        PrincipalIdV2::new([55; 32])
                    } else {
                        material.authenticated_principal
                    },
                    if mode == 3 {
                        Digest32V2::new([55; 32])
                    } else {
                        material.input_commit_digest
                    },
                    if mode == 4 {
                        UnixMillisV2::new(material.expires_at.get() + 1)
                    } else {
                        material.expires_at
                    },
                    UnixMillisV2::new(102)
                )
                .is_err());
        }
        let live = owner
            .recover_committed_tool_result(
                material.durable_task_id,
                material.durable_run_id,
                material.authenticated_principal,
                material.input_commit_digest,
                material.expires_at,
                UnixMillisV2::new(103),
            )
            .unwrap();
        let context = VaultAccessContextV2::from_authenticated_agent(
            BootIdV2::new([43; 32]),
            ServiceIdentityV2::new([8; 32]),
            Digest32V2::new([9; 32]),
            material.durable_run_id,
            material.expires_at,
        )
        .unwrap();
        let document = owner
            .issue_masked_document(&live, context, UnixMillisV2::new(103))
            .unwrap();
        assert_eq!(
            owner
                .read_agent_bytes_for_authenticated_agent(
                    &document,
                    BootIdV2::new([43; 32]),
                    ServiceIdentityV2::new([8; 32]),
                    Digest32V2::new([9; 32]),
                    UnixMillisV2::new(104)
                )
                .unwrap()
                .as_slice(),
            b"private recovered result"
        );
        assert_eq!(owner.segment_count(), 1);
        assert!(owner
            .recover_committed_tool_result(
                material.durable_task_id,
                material.durable_run_id,
                material.authenticated_principal,
                material.input_commit_digest,
                material.expires_at,
                material.expires_at
            )
            .is_err());
    }

    #[test]
    fn exact_tool_result_replay_rotates_boot_capability_without_replacing_material() {
        let mut owner = service();
        let material = ingress(b"same result across boots");
        let pending = owner
            .create_pending_tool_result(material.clone(), UnixMillisV2::new(100))
            .unwrap();
        let old_live = owner
            .commit_ingress(pending, UnixMillisV2::new(100))
            .unwrap();
        owner.boot_id = BootIdV2::new([43; 32]);
        let context = VaultAccessContextV2::from_authenticated_agent(
            owner.boot_id,
            ServiceIdentityV2::new([8; 32]),
            Digest32V2::new([9; 32]),
            material.durable_run_id,
            material.expires_at,
        )
        .unwrap();
        for mode in 0..3 {
            let mut changed = material.clone();
            match mode {
                0 => changed.sensitive_bytes = Zeroizing::new(b"substituted".to_vec()),
                1 => changed.provenance_digest = Digest32V2::new([88; 32]),
                _ => changed.expires_at = UnixMillisV2::new(material.expires_at.get() + 1),
            }
            assert!(owner
                .create_pending_tool_result(changed, UnixMillisV2::new(101))
                .is_err());
        }
        let replay = owner
            .create_pending_tool_result(material, UnixMillisV2::new(101))
            .unwrap();
        assert_eq!(replay.internal_id, pending.internal_id);
        assert_ne!(replay.token, pending.token);
        assert!(owner
            .issue_masked_document(&old_live, context, UnixMillisV2::new(101))
            .is_err());
        let live = owner
            .commit_ingress(replay, UnixMillisV2::new(101))
            .unwrap();
        assert!(owner
            .issue_masked_document(&live, context, UnixMillisV2::new(101))
            .is_ok());
        assert_eq!(owner.segments.len(), 1);
    }

    fn release_material(seed: u8) -> VaultReleaseMaterialV2 {
        VaultReleaseMaterialV2::from_verified_projection(
            Digest32V2::new([seed; 32]),
            Digest32V2::new([seed.wrapping_add(1); 32]),
            Digest32V2::new([seed.wrapping_add(2); 32]),
            Digest32V2::new([seed.wrapping_add(3); 32]),
            Digest32V2::new([seed.wrapping_add(4); 32]),
            Digest32V2::new([seed.wrapping_add(5); 32]),
            Digest32V2::new([seed.wrapping_add(6); 32]),
            Digest32V2::new([seed.wrapping_add(7); 32]),
        )
        .unwrap()
    }

    fn live_document(service: &mut VaultServiceV2) -> (LiveVaultSegmentV2, MaskedDocumentHandleV2) {
        let pending = service
            .create_pending_ingress(
                ingress(b"masked: account <TOKEN_1>"),
                UnixMillisV2::new(100),
            )
            .unwrap();
        let live = service
            .commit_ingress(pending, UnixMillisV2::new(101))
            .unwrap();
        let document = service
            .issue_masked_document(&live, access(9), UnixMillisV2::new(102))
            .unwrap();
        (live, document)
    }

    #[test]
    fn exact_ingress_retry_is_idempotent_and_task_rebinding_is_rejected() {
        let mut service = service();
        let first = service
            .ingest_verified(ingress(b"same committed input"), UnixMillisV2::new(100))
            .unwrap();
        let replay = service
            .ingest_verified(ingress(b"same committed input"), UnixMillisV2::new(101))
            .unwrap();
        assert_eq!(first, replay);
        assert_eq!(service.segments.len(), 1);
        assert_eq!(
            service.ingest_verified(ingress(b"changed input"), UnixMillisV2::new(102)),
            Err(VaultErrorV2::StateConflict)
        );
        assert_eq!(service.segments.len(), 1);
    }

    #[test]
    fn opaque_document_is_exact_context_bound_and_content_stays_in_rust() {
        let mut service = service();
        let (_live, document) = live_document(&mut service);

        assert_eq!(
            service
                .read_agent_bytes(&document, access(9), UnixMillisV2::new(103))
                .unwrap()
                .as_slice(),
            b"masked: account <TOKEN_1>"
        );
        assert_eq!(
            service.read_agent_bytes(&document, access(10), UnixMillisV2::new(103)),
            Err(VaultErrorV2::InvalidCapability)
        );
        assert_eq!(
            format!("{document:?}"),
            "MaskedDocumentHandleV2(<redacted>)"
        );
        assert!(!format!("{service:?}").contains("TOKEN_1"));
    }

    #[test]
    fn final_release_binding_nonce_and_terminal_transition_are_one_shot() {
        let mut service = service();
        let (_live, document) = live_document(&mut service);
        let material = release_material(0x20);
        let first = service
            .prepare_release(&document, access(9), material, UnixMillisV2::new(110))
            .unwrap();
        let replay = service
            .prepare_release(&document, access(9), material, UnixMillisV2::new(111))
            .unwrap();
        assert_eq!(first.durable_release_id(), replay.durable_release_id());
        assert_eq!(first.binding(), replay.binding());
        assert_eq!(first.binding_digest(), replay.binding_digest());
        assert_eq!(
            service.prepare_release(
                &document,
                access(9),
                release_material(0x30),
                UnixMillisV2::new(111),
            ),
            Err(VaultErrorV2::StateConflict)
        );

        let principal = PrincipalIdV2::new([0x40; 32]);
        let approval = VerifiedFinalReleaseApprovalV2::new_for_test(
            first.binding_digest(),
            principal,
            Digest32V2::new([0x41; 32]),
            UnixMillisV2::new(1_000),
        );
        let authorized = service
            .authorize_release(first, approval, UnixMillisV2::new(112))
            .unwrap();
        let commit = KernelPreparedReleaseDispatchV2::new_for_test(
            authorized.binding(),
            Digest32V2::new([0x42; 32]),
            Nonce32V2::new([0x43; 32]),
            Digest32V2::new([0x44; 32]),
            authorized.dispatch_subject_digest().unwrap(),
        );
        let prepared = service
            .mark_dispatch_prepared(authorized, commit, UnixMillisV2::new(113))
            .unwrap();
        let replay = service
            .mark_dispatch_prepared(authorized, commit, UnixMillisV2::new(114))
            .unwrap();
        assert_eq!(prepared.execution_nonce(), replay.execution_nonce());

        let rebound = KernelPreparedReleaseDispatchV2::new_for_test(
            authorized.binding(),
            Digest32V2::new([0x42; 32]),
            Nonce32V2::new([0x46; 32]),
            Digest32V2::new([0x44; 32]),
            authorized.dispatch_subject_digest().unwrap(),
        );
        assert_eq!(
            service.mark_dispatch_prepared(authorized, rebound, UnixMillisV2::new(114)),
            Err(VaultErrorV2::StateConflict)
        );

        service
            .mark_dispatching(prepared, UnixMillisV2::new(115))
            .unwrap();
        service
            .commit_known_release(
                prepared,
                Digest32V2::new([0x47; 32]),
                Digest32V2::new([0x48; 32]),
                UnixMillisV2::new(116),
            )
            .unwrap();
        assert_eq!(
            service.public_state(&document, access(9), UnixMillisV2::new(117)),
            Ok(VaultPublicStateV2::Released)
        );
        assert_eq!(
            service.read_agent_bytes(&document, access(9), UnixMillisV2::new(117)),
            Err(VaultErrorV2::TerminalState)
        );
    }

    #[test]
    fn recovery_projection_contains_no_release_capability_or_sensitive_bytes() {
        let mut service = service();
        let (_live, document) = live_document(&mut service);
        let pending = service
            .prepare_release(
                &document,
                access(9),
                release_material(0x60),
                UnixMillisV2::new(140),
            )
            .unwrap();
        let approval = VerifiedFinalReleaseApprovalV2::new_for_test(
            pending.binding_digest(),
            PrincipalIdV2::new([0x40; 32]),
            Digest32V2::new([0x61; 32]),
            UnixMillisV2::new(1_000),
        );
        let authorized = service
            .authorize_release(pending, approval, UnixMillisV2::new(141))
            .unwrap();
        let commit = KernelPreparedReleaseDispatchV2::new_for_test(
            authorized.binding(),
            Digest32V2::new([0x62; 32]),
            Nonce32V2::new([0x63; 32]),
            Digest32V2::new([0x64; 32]),
            authorized.dispatch_subject_digest().unwrap(),
        );
        service
            .mark_dispatch_prepared(authorized, commit, UnixMillisV2::new(142))
            .unwrap();

        let projection = service.recovery_projection().unwrap();

        assert_eq!(projection.len(), 1);
        assert_eq!(
            projection[0].durable_release_id(),
            authorized.binding().durable_release_id()
        );
        assert_eq!(
            projection[0].execution_nonce(),
            Some(Nonce32V2::new([0x63; 32]))
        );
        assert_eq!(
            projection[0].state(),
            VaultReleaseRecoveryStateV2::DispatchPrepared
        );
        assert!(!format!("{projection:?}").contains("TOKEN_1"));
    }

    #[test]
    fn recovery_can_terminally_record_exact_failed_no_effect_without_a_capability() {
        let mut service = service();
        let (_live, document) = live_document(&mut service);
        let pending = service
            .prepare_release(
                &document,
                access(9),
                release_material(0x70),
                UnixMillisV2::new(150),
            )
            .unwrap();
        let approval = VerifiedFinalReleaseApprovalV2::new_for_test(
            pending.binding_digest(),
            PrincipalIdV2::new([0x40; 32]),
            Digest32V2::new([0x71; 32]),
            UnixMillisV2::new(1_000),
        );
        let authorized = service
            .authorize_release(pending, approval, UnixMillisV2::new(151))
            .unwrap();
        let release_id = authorized.binding().durable_release_id();
        let nonce = Nonce32V2::new([0x72; 32]);
        let core = Digest32V2::new([0x73; 32]);
        let subject = authorized.dispatch_subject_digest().unwrap();
        let commit = KernelPreparedReleaseDispatchV2::new_for_test(
            authorized.binding(),
            Digest32V2::new([0x74; 32]),
            nonce,
            core,
            subject,
        );
        service
            .mark_dispatch_prepared(authorized, commit, UnixMillisV2::new(152))
            .unwrap();

        assert_eq!(
            service.mark_failed_no_effect_by_identity(
                release_id,
                Nonce32V2::new([0x75; 32]),
                core,
                subject,
                UnixMillisV2::new(153),
            ),
            Err(VaultErrorV2::StateConflict)
        );
        service
            .mark_failed_no_effect_by_identity(
                release_id,
                nonce,
                core,
                subject,
                UnixMillisV2::new(153),
            )
            .unwrap();
        service
            .mark_failed_no_effect_by_identity(
                release_id,
                nonce,
                core,
                subject,
                UnixMillisV2::new(154),
            )
            .unwrap();

        let projection = service.recovery_projection().unwrap();
        assert_eq!(
            projection[0].state(),
            VaultReleaseRecoveryStateV2::FailedNoEffect
        );
        assert_eq!(
            service.public_state(&document, access(9), UnixMillisV2::new(155)),
            Ok(VaultPublicStateV2::FailedNoEffect)
        );
        assert_eq!(
            service.read_agent_bytes(&document, access(9), UnixMillisV2::new(155)),
            Err(VaultErrorV2::TerminalState)
        );
    }

    #[test]
    fn revoke_expiry_and_indeterminate_are_fail_closed() {
        let mut revoked = service();
        let (_live, document) = live_document(&mut revoked);
        assert_eq!(
            revoked
                .revoke(&document, access(9), UnixMillisV2::new(120))
                .unwrap(),
            VaultPublicStateV2::Revoked
        );
        assert_eq!(
            revoked.read_agent_bytes(&document, access(9), UnixMillisV2::new(121)),
            Err(VaultErrorV2::TerminalState)
        );

        let mut expired = service();
        let (_live, document) = live_document(&mut expired);
        assert_eq!(
            expired.public_state(&document, access(9), UnixMillisV2::new(10_000)),
            Ok(VaultPublicStateV2::Expired)
        );
        assert_eq!(
            expired.read_agent_bytes(&document, access(9), UnixMillisV2::new(10_000)),
            Err(VaultErrorV2::Expired)
        );

        let mut uncertain = service();
        let (_live, document) = live_document(&mut uncertain);
        let pending = uncertain
            .prepare_release(
                &document,
                access(9),
                release_material(0x50),
                UnixMillisV2::new(130),
            )
            .unwrap();
        let approval = VerifiedFinalReleaseApprovalV2::new_for_test(
            pending.binding_digest(),
            PrincipalIdV2::new([0x40; 32]),
            Digest32V2::new([0x52; 32]),
            UnixMillisV2::new(1_000),
        );
        let authorized = uncertain
            .authorize_release(pending, approval, UnixMillisV2::new(131))
            .unwrap();
        let commit = KernelPreparedReleaseDispatchV2::new_for_test(
            authorized.binding(),
            Digest32V2::new([0x53; 32]),
            Nonce32V2::new([0x54; 32]),
            Digest32V2::new([0x55; 32]),
            authorized.dispatch_subject_digest().unwrap(),
        );
        let prepared = uncertain
            .mark_dispatch_prepared(authorized, commit, UnixMillisV2::new(132))
            .unwrap();
        uncertain
            .mark_indeterminate(prepared, UnixMillisV2::new(133))
            .unwrap();
        assert_eq!(
            uncertain.public_state(&document, access(9), UnixMillisV2::new(134)),
            Ok(VaultPublicStateV2::Indeterminate)
        );
        assert_eq!(
            uncertain.revoke(&document, access(9), UnixMillisV2::new(134)),
            Err(VaultErrorV2::TerminalState)
        );
    }

    #[derive(Clone, Default)]
    struct TestRollbackAnchor {
        head: Arc<Mutex<VaultStateHeadV2>>,
    }

    impl VaultRollbackAnchorV2 for TestRollbackAnchor {
        fn current_head(&self) -> Result<VaultStateHeadV2, VaultErrorV2> {
            Ok(*self.head.lock().unwrap())
        }

        fn compare_and_advance(
            &mut self,
            expected: VaultStateHeadV2,
            next: VaultStateHeadV2,
        ) -> Result<(), VaultErrorV2> {
            let mut head = self.head.lock().unwrap();
            if *head != expected {
                return Err(VaultErrorV2::RollbackDetected);
            }
            *head = next;
            Ok(())
        }
    }

    #[test]
    fn durable_vault_encrypts_content_restores_document_capabilities_and_rejects_rollback() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.path().join("vault-state-v2.cbor");
        let namespace = DurableVaultNamespaceV2::from_verified_installation(
            Digest32V2::new([1; 32]),
            Digest32V2::new([0x70; 32]),
        )
        .unwrap();
        let key = [0x71; 32];
        let anchor = TestRollbackAnchor::default();
        let mut durable =
            DurableVaultServiceV2::open(&path, key, namespace, Box::new(anchor.clone()), service())
                .unwrap();
        let pending = durable
            .create_pending_ingress(
                ingress(b"masked durable secret <TOKEN_9>"),
                UnixMillisV2::new(200),
            )
            .unwrap();
        let live = durable
            .commit_ingress(pending, UnixMillisV2::new(201))
            .unwrap();
        let old_snapshot = std::fs::read(&path).unwrap();
        let document = durable
            .issue_masked_document(&live, access(9), UnixMillisV2::new(202))
            .unwrap();
        assert!(!std::fs::read(&path)
            .unwrap()
            .windows(b"durable secret".len())
            .any(|window| window == b"durable secret"));
        drop(durable);

        let mut reopened =
            DurableVaultServiceV2::open(&path, key, namespace, Box::new(anchor.clone()), service())
                .unwrap();
        assert_eq!(reopened.segment_count(), 1);
        assert_eq!(
            reopened
                .read_agent_bytes_for_authenticated_agent(
                    &document,
                    BootIdV2::new([3; 32]),
                    ServiceIdentityV2::new([8; 32]),
                    Digest32V2::new([9; 32]),
                    UnixMillisV2::new(203),
                )
                .unwrap()
                .as_slice(),
            b"masked durable secret <TOKEN_9>"
        );
        assert_eq!(
            reopened.read_agent_bytes_for_authenticated_agent(
                &document,
                BootIdV2::new([3; 32]),
                ServiceIdentityV2::new([8; 32]),
                Digest32V2::new([10; 32]),
                UnixMillisV2::new(203),
            ),
            Err(VaultErrorV2::InvalidCapability)
        );
        let pending = reopened
            .create_pending_ingress(
                ingress_for_task(0x44, b"second segment"),
                UnixMillisV2::new(204),
            )
            .unwrap();
        reopened
            .commit_ingress(pending, UnixMillisV2::new(205))
            .unwrap();
        drop(reopened);

        std::fs::write(&path, old_snapshot).unwrap();
        assert!(matches!(
            DurableVaultServiceV2::open(&path, key, namespace, Box::new(anchor), service(),),
            Err(VaultErrorV2::RollbackDetected)
        ));
    }
}
