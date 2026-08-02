use std::collections::BTreeSet;

use minicbor::data::Type;
use savana_kernel_protocol::v2::{
    connector_registration_descriptor_digest_v2, decode_signed_approval_envelope_v2,
    decode_signed_approval_settlement_v2, decode_signed_ui_authentication_envelope_v2,
    encode_signed_approval_envelope_v2, encode_signed_approval_settlement_v2,
    encode_signed_ui_authentication_envelope_v2, AgentSessionHandleV2, ApprovalBindingV2,
    ApprovalDecisionV2, ApprovalPurposeV2, ApprovedConnectorRegistrationHandleV2,
    AuthorityHandleKeyV2, BootIdV2, ConnectorRemovalAuthorizationHandleV2, Digest32V2,
    FixedOriginV2, PendingConnectorRegistrationHandleV2, ProposeConnectorRegistrationRequestV2,
    ProposeConnectorRegistrationResponseV2, ServiceIdentityV2, SignedApprovalEnvelopeV2,
    SignedApprovalSettlementV2, SignedUiAuthenticationEnvelopeV2, UiAuthenticationBindingV2,
    UiAuthenticationPurposeV2, UnixMillisV2, V2DecodeContext,
};
use savana_kernel_protocol::{ProtocolError, StableCode};
#[cfg(test)]
use savana_policy_core::v2::TestConnectorStoreCrashPointV2;
use savana_policy_core::v2::{
    ConnectorDescriptorV2, ConnectorRegistryStateV2, ConnectorStoreRevisionV2, ConnectorTierV2,
    DurableConnectorRegistryStoreV2, G4Error, SharedVerifiedConnectorRegistryV2,
    MAX_CONNECTOR_AUTHORITY_STATE_BYTES_V2,
};
use sha2::{Digest as _, Sha256};

use crate::v2_agent_authority::{
    ConnectorSecurityVerifiersV2, ConnectorUiSessionContextV2, KernelAgentAuthorityErrorV2,
    KernelAgentAuthorityV2, PreparedConnectorRegistrationProposalV2,
};
use crate::v2_value_owner::KernelValueOwnerV2;

const AUTHORITY_STATE_SCHEMA_V2: u16 = 1;
const MAX_AUTHORITY_RECORDS_V2: usize = 65_536;
const ADD_RECORD_FIELDS_V2: u64 = 9;
const ADD_DETAILS_FIELDS_V2: u64 = 10;
const REMOVE_RECORD_FIELDS_V2: u64 = 8;
const REMOVE_DETAILS_FIELDS_V2: u64 = 3;
const SESSION_FIELDS_V2: u64 = 9;
const MUTATION_SUMMARY_FIELDS_V2: u64 = 4;
const PROPOSAL_IDENTITY_DOMAIN_V2: &[u8] = b"SAVANA_CONNECTOR_PROPOSAL_IDENTITY_V2\0";

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TestConnectorCommitCrashPointV2 {
    BeforeWrite,
    FileFlushed,
    RenamedBeforeDirectoryFlush,
    DirectoryFlushed,
    Reopened,
    HighWaterAdvanced,
}

#[cfg(test)]
impl TestConnectorCommitCrashPointV2 {
    pub(crate) const ALL: [Self; 6] = [
        Self::BeforeWrite,
        Self::FileFlushed,
        Self::RenamedBeforeDirectoryFlush,
        Self::DirectoryFlushed,
        Self::Reopened,
        Self::HighWaterAdvanced,
    ];

    pub(crate) const fn is_after_durable_reopen(self) -> bool {
        matches!(self, Self::Reopened | Self::HighWaterAdvanced)
    }

    const fn store_point(self) -> TestConnectorStoreCrashPointV2 {
        match self {
            Self::BeforeWrite => TestConnectorStoreCrashPointV2::BeforeWrite,
            Self::FileFlushed => TestConnectorStoreCrashPointV2::FileFlushed,
            Self::RenamedBeforeDirectoryFlush => {
                TestConnectorStoreCrashPointV2::RenamedBeforeDirectoryFlush
            }
            Self::DirectoryFlushed => TestConnectorStoreCrashPointV2::DirectoryFlushed,
            Self::Reopened => TestConnectorStoreCrashPointV2::Reopened,
            Self::HighWaterAdvanced => TestConnectorStoreCrashPointV2::HighWaterAdvanced,
        }
    }
}

enum ConnectorCommitModeV2 {
    Normal,
    #[cfg(test)]
    Crash(TestConnectorCommitCrashPointV2),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KernelConnectorAuthorityErrorV2 {
    InvalidReference,
    AlreadyConsumed,
    BindingMismatch,
    Denied,
    Expired,
    StateConflict,
    LimitExceeded,
    Durable,
    Unavailable,
}

impl KernelConnectorAuthorityErrorV2 {
    #[cfg(test)]
    pub(crate) const fn stable_code(self) -> StableCode {
        match self {
            Self::InvalidReference => StableCode::HandleUnknown,
            Self::AlreadyConsumed => StableCode::HandleAlreadyConsumed,
            Self::BindingMismatch | Self::Denied => StableCode::ApprovalBindingMismatch,
            Self::Expired => StableCode::ApprovalReplayed,
            Self::StateConflict => StableCode::RegistryEquivocation,
            Self::LimitExceeded => StableCode::PolicyLimitExceeded,
            Self::Durable | Self::Unavailable => StableCode::KernelUnavailable,
        }
    }
}

impl From<KernelAgentAuthorityErrorV2> for KernelConnectorAuthorityErrorV2 {
    fn from(value: KernelAgentAuthorityErrorV2) -> Self {
        match value {
            KernelAgentAuthorityErrorV2::InvalidReference => Self::InvalidReference,
            KernelAgentAuthorityErrorV2::AlreadyConsumed => Self::AlreadyConsumed,
            KernelAgentAuthorityErrorV2::BindingMismatch => Self::BindingMismatch,
            KernelAgentAuthorityErrorV2::Expired => Self::Expired,
            KernelAgentAuthorityErrorV2::StateConflict => Self::StateConflict,
            KernelAgentAuthorityErrorV2::LimitExceeded => Self::LimitExceeded,
            KernelAgentAuthorityErrorV2::Unavailable => Self::Unavailable,
        }
    }
}

impl From<G4Error> for KernelConnectorAuthorityErrorV2 {
    fn from(value: G4Error) -> Self {
        match value {
            G4Error::DescriptorLimitExceeded | G4Error::IntentLimitExceeded => Self::LimitExceeded,
            G4Error::DurableStateIo
            | G4Error::DurableStateAuthentication
            | G4Error::DurableStateRollback
            | G4Error::DurableStateCorrupt
            | G4Error::DurableCommitUncertain => Self::Durable,
            G4Error::StateConflict | G4Error::IdempotencyConflict => Self::StateConflict,
            _ => Self::BindingMismatch,
        }
    }
}

impl From<ProtocolError> for KernelConnectorAuthorityErrorV2 {
    fn from(error: ProtocolError) -> Self {
        match error.code() {
            StableCode::ApprovalReplayed => Self::Expired,
            StableCode::ApprovalBindingMismatch
            | StableCode::ApprovalInvalidSignature
            | StableCode::ProtocolMalformedCbor
            | StableCode::ProtocolNonCanonicalCbor => Self::BindingMismatch,
            _ => Self::Unavailable,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConnectorRegistryMutationV2 {
    canonical_delta: Vec<u8>,
    signed_delta_digest: Digest32V2,
    head_digest: Digest32V2,
    sequence: u64,
    connector_id: Digest32V2,
    add: bool,
}

impl ConnectorRegistryMutationV2 {
    pub(crate) fn canonical_delta(&self) -> &[u8] {
        &self.canonical_delta
    }

    pub(crate) const fn signed_delta_digest(&self) -> Digest32V2 {
        self.signed_delta_digest
    }

    pub(crate) const fn head_digest(&self) -> Digest32V2 {
        self.head_digest
    }

    pub(crate) const fn sequence(&self) -> u64 {
        self.sequence
    }

    pub(crate) const fn connector_id(&self) -> Digest32V2 {
        self.connector_id
    }

    pub(crate) const fn is_add(&self) -> bool {
        self.add
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PreparedConnectorRemovalV2 {
    authorization: ConnectorRemovalAuthorizationHandleV2,
    previous_head_digest: Digest32V2,
    expires_at: UnixMillisV2,
}

impl PreparedConnectorRemovalV2 {
    pub(crate) const fn authorization(&self) -> ConnectorRemovalAuthorizationHandleV2 {
        self.authorization
    }

    pub(crate) const fn previous_head_digest(&self) -> Digest32V2 {
        self.previous_head_digest
    }

    pub(crate) const fn expires_at(&self) -> UnixMillisV2 {
        self.expires_at
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConnectorRegistrySnapshotV2 {
    canonical_bytes: Vec<u8>,
    head_digest: Digest32V2,
    sequence: u64,
}

impl ConnectorRegistrySnapshotV2 {
    pub(crate) fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub(crate) const fn head_digest(&self) -> Digest32V2 {
        self.head_digest
    }

    pub(crate) const fn sequence(&self) -> u64 {
        self.sequence
    }
}

#[derive(Debug, Clone)]
struct ConnectorAddRecordV2 {
    pending: PendingConnectorRegistrationHandleV2,
    pending_commitment: Digest32V2,
    source_authorization_commitment: Digest32V2,
    proposal_identity_digest: Digest32V2,
    active_state_manifest_digest: Digest32V2,
    deployment_generation: u64,
    details: Option<ConnectorAddDetailsV2>,
    status: ConnectorAddStatusV2,
}

#[derive(Debug, Clone)]
struct ConnectorAddDetailsV2 {
    session: ConnectorUiSessionContextV2,
    caller_identity: ServiceIdentityV2,
    canonical_descriptor: Vec<u8>,
    descriptor_digest: Digest32V2,
    previous_head_digest: Digest32V2,
    envelope: SignedApprovalEnvelopeV2,
    display_authentication: SignedUiAuthenticationEnvelopeV2,
    envelope_digest: Digest32V2,
    decision_challenge: savana_kernel_protocol::v2::Nonce32V2,
}

#[derive(Debug, Clone)]
enum ConnectorAddStatusV2 {
    Pending,
    Approved {
        approved: ApprovedConnectorRegistrationHandleV2,
        approved_commitment: Digest32V2,
        settlement_bytes: Vec<u8>,
        settlement_digest: Digest32V2,
        settlement_issued_at: UnixMillisV2,
    },
    Denied {
        settlement_digest: Digest32V2,
    },
    Committed {
        approved: ApprovedConnectorRegistrationHandleV2,
        approved_commitment: Digest32V2,
        settlement_digest: Digest32V2,
        result: ConnectorRegistryMutationSummaryV2,
    },
    Expired,
}

#[derive(Debug, Clone)]
struct ConnectorRemoveRecordV2 {
    authorization: ConnectorRemovalAuthorizationHandleV2,
    authorization_commitment: Digest32V2,
    session: AgentSessionHandleV2,
    connector_id: Digest32V2,
    active_state_manifest_digest: Digest32V2,
    deployment_generation: u64,
    details: Option<ConnectorRemoveDetailsV2>,
    status: ConnectorRemoveStatusV2,
}

#[derive(Debug, Clone)]
struct ConnectorRemoveDetailsV2 {
    session: ConnectorUiSessionContextV2,
    previous_head_digest: Digest32V2,
    issued_at: UnixMillisV2,
}

#[derive(Debug, Clone)]
enum ConnectorRemoveStatusV2 {
    Pending,
    Committed(ConnectorRegistryMutationSummaryV2),
    Expired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ConnectorRegistryMutationSummaryV2 {
    sequence: u64,
    connector_id: Digest32V2,
    add: bool,
}

#[derive(Debug, Clone, Default)]
struct ConnectorAuthorityStateV2 {
    adds: Vec<ConnectorAddRecordV2>,
    removes: Vec<ConnectorRemoveRecordV2>,
    sign_count: u64,
}

pub(crate) struct KernelConnectorAuthorityV2 {
    enabled: bool,
    handle_key: AuthorityHandleKeyV2,
    store: Option<DurableConnectorRegistryStoreV2>,
    store_revision: Option<ConnectorStoreRevisionV2>,
    shared_registry: SharedVerifiedConnectorRegistryV2,
    state: ConnectorAuthorityStateV2,
    poisoned: bool,
    #[cfg(test)]
    published_after_durable_reopen: bool,
}

impl std::fmt::Debug for KernelConnectorAuthorityV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("KernelConnectorAuthorityV2")
            .field("enabled", &self.enabled)
            .field("poisoned", &self.poisoned)
            .finish_non_exhaustive()
    }
}

impl KernelConnectorAuthorityV2 {
    pub(crate) fn from_durable_store(
        store: DurableConnectorRegistryStoreV2,
        shared_registry: SharedVerifiedConnectorRegistryV2,
        handle_key: [u8; 32],
    ) -> Result<Self, KernelConnectorAuthorityErrorV2> {
        let handle_key = AuthorityHandleKeyV2::from_entropy(handle_key)
            .ok_or(KernelConnectorAuthorityErrorV2::Unavailable)?;
        let registry = store.snapshot()?;
        let store_revision = store.revision()?;
        let shared = shared_registry.snapshot()?;
        if registry.head_digest() != shared.head_digest()
            || registry.genesis_digest() != shared.genesis_digest()
            || registry.connector_authority_public_key() != shared.connector_authority_public_key()
            || registry.connector_authority_public_key() == [0; 32]
        {
            return Err(KernelConnectorAuthorityErrorV2::BindingMismatch);
        }
        let state = decode_authority_state(store.authority_state()?)?;
        validate_recovered_authority_state(&state, &registry, &handle_key)?;
        Ok(Self {
            enabled: true,
            handle_key,
            store: Some(store),
            store_revision: Some(store_revision),
            shared_registry,
            state,
            poisoned: false,
            #[cfg(test)]
            published_after_durable_reopen: false,
        })
    }

    pub(crate) fn disabled(
        shared_registry: SharedVerifiedConnectorRegistryV2,
        handle_key: [u8; 32],
    ) -> Result<Self, KernelConnectorAuthorityErrorV2> {
        let snapshot = shared_registry.snapshot()?;
        if snapshot.connector_authority_public_key() != [0; 32] || snapshot.sequence() != 0 {
            return Err(KernelConnectorAuthorityErrorV2::BindingMismatch);
        }
        Ok(Self {
            enabled: false,
            handle_key: AuthorityHandleKeyV2::from_entropy(handle_key)
                .ok_or(KernelConnectorAuthorityErrorV2::Unavailable)?,
            store: None,
            store_revision: None,
            shared_registry,
            state: ConnectorAuthorityStateV2::default(),
            poisoned: false,
            #[cfg(test)]
            published_after_durable_reopen: false,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn propose_add(
        &mut self,
        request: &ProposeConnectorRegistrationRequestV2,
        agent_authority: &mut KernelAgentAuthorityV2,
        values: &KernelValueOwnerV2,
        caller_boot_id: BootIdV2,
        caller_identity: ServiceIdentityV2,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
        now: UnixMillisV2,
    ) -> Result<ProposeConnectorRegistrationResponseV2, KernelConnectorAuthorityErrorV2> {
        self.ensure_available()?;
        self.compact_stale_records(active_state_manifest_digest, deployment_generation, now)?;
        let source_commitment =
            agent_authority.connector_authorization_commitment(request.authorization())?;
        if let Some(existing) = self
            .state
            .adds
            .iter()
            .find(|record| record.source_authorization_commitment == source_commitment)
        {
            let details = existing
                .details
                .as_ref()
                .ok_or(KernelConnectorAuthorityErrorV2::AlreadyConsumed)?;
            if details.canonical_descriptor != request.canonical_descriptor()
                || details.session.caller_boot_id() != caller_boot_id
                || details.caller_identity != caller_identity
                || existing.active_state_manifest_digest != active_state_manifest_digest
                || existing.deployment_generation != deployment_generation
            {
                return Err(KernelConnectorAuthorityErrorV2::StateConflict);
            }
            return proposal_response(existing);
        }
        let prepared = agent_authority.prepare_connector_registration_proposal(
            request,
            values,
            caller_boot_id,
            caller_identity,
            active_state_manifest_digest,
            deployment_generation,
            now,
        )?;
        if prepared.authorization_commitment() != source_commitment {
            return Err(KernelConnectorAuthorityErrorV2::BindingMismatch);
        }
        if let Some(existing) = self.state.adds.iter().find(|record| {
            matches!(
                &record.status,
                ConnectorAddStatusV2::Pending | ConnectorAddStatusV2::Approved { .. }
            ) && same_proposal_identity(record, &prepared, &self.handle_key)
                && record
                    .details
                    .as_ref()
                    .is_some_and(|details| now.get() < details.session.expires_at().get())
        }) {
            let response = proposal_response(existing)?;
            agent_authority.consume_connector_registration_proposal(&prepared)?;
            return Ok(response);
        }
        self.ensure_record_capacity()?;
        let current = self.store_snapshot()?;
        if prepared.previous_head_digest() != current.head_digest()
            || self.shared_registry.current_head_digest()? != current.head_digest()
        {
            return Err(KernelConnectorAuthorityErrorV2::BindingMismatch);
        }
        let pending = mint_handle(PendingConnectorRegistrationHandleV2::from_authority_entropy)?;
        let record = add_record_from_prepared(pending, prepared.clone(), &self.handle_key);
        let mut candidate = self.state.clone();
        candidate.adds.push(record);
        self.persist_state(&candidate, current.head_digest(), None)?;
        self.state = candidate;
        if let Err(error) = agent_authority.consume_connector_registration_proposal(&prepared) {
            // The reservation is already durable. A retry resolves it from the
            // record without asking Task8 state to produce or consume again.
            if error != KernelAgentAuthorityErrorV2::AlreadyConsumed {
                return Err(error.into());
            }
        }
        let stored = self
            .state
            .adds
            .last()
            .ok_or(KernelConnectorAuthorityErrorV2::Unavailable)?;
        proposal_response(stored)
    }

    pub(crate) fn authorize_add(
        &mut self,
        pending: PendingConnectorRegistrationHandleV2,
        settlement: &SignedApprovalSettlementV2,
        agent_authority: &KernelAgentAuthorityV2,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
        now: UnixMillisV2,
    ) -> Result<ApprovedConnectorRegistrationHandleV2, KernelConnectorAuthorityErrorV2> {
        self.ensure_available()?;
        self.compact_stale_records(active_state_manifest_digest, deployment_generation, now)?;
        let pending_commitment = pending.authority_commitment(&self.handle_key);
        let index = self
            .state
            .adds
            .iter()
            .position(|record| record.pending_commitment == pending_commitment)
            .ok_or(KernelConnectorAuthorityErrorV2::InvalidReference)?;
        let record = &self.state.adds[index];
        if record.active_state_manifest_digest != active_state_manifest_digest
            || record.deployment_generation != deployment_generation
        {
            return Err(KernelConnectorAuthorityErrorV2::BindingMismatch);
        }
        let settlement_bytes = encode_signed_approval_settlement_v2(settlement)?;
        let settlement_digest = settlement.settlement_digest()?;
        match &self.state.adds[index].status {
            ConnectorAddStatusV2::Approved {
                approved,
                settlement_bytes: existing,
                settlement_digest: existing_digest,
                ..
            } => {
                return if *existing_digest == settlement_digest && *existing == settlement_bytes {
                    Ok(*approved)
                } else {
                    Err(KernelConnectorAuthorityErrorV2::StateConflict)
                };
            }
            ConnectorAddStatusV2::Committed {
                approved,
                settlement_digest: existing_digest,
                ..
            } => {
                return if *existing_digest == settlement_digest {
                    Ok(*approved)
                } else {
                    Err(KernelConnectorAuthorityErrorV2::StateConflict)
                };
            }
            ConnectorAddStatusV2::Denied {
                settlement_digest: existing_digest,
            } => {
                return if *existing_digest == settlement_digest {
                    Err(KernelConnectorAuthorityErrorV2::Denied)
                } else {
                    Err(KernelConnectorAuthorityErrorV2::StateConflict)
                };
            }
            ConnectorAddStatusV2::Expired => {
                return Err(KernelConnectorAuthorityErrorV2::Expired);
            }
            ConnectorAddStatusV2::Pending => {}
        }

        let record = &self.state.adds[index];
        let details = record
            .details
            .as_ref()
            .ok_or(KernelConnectorAuthorityErrorV2::StateConflict)?;
        let current = self.store_snapshot()?;
        if current.head_digest() != details.previous_head_digest
            || self.shared_registry.current_head_digest()? != details.previous_head_digest
        {
            return Err(KernelConnectorAuthorityErrorV2::BindingMismatch);
        }
        let ConnectorSecurityVerifiersV2 {
            installation_id,
            settlement_key_id,
            settlement_public_key,
            envelope_key_id,
            envelope_public_key,
        } = agent_authority.connector_security_verifiers()?;
        let unsigned_envelope = details.envelope.verify(
            envelope_key_id,
            envelope_public_key,
            installation_id,
            details.session.active_state_manifest_digest(),
            details.session.deployment_generation(),
            ApprovalPurposeV2::ConnectorRegistration,
            details.session.principal(),
            now,
        )?;
        if details.envelope.envelope_digest()? != details.envelope_digest
            || unsigned_envelope.decision_challenge() != details.decision_challenge
            || unsigned_envelope.binding()
                != (ApprovalBindingV2::ConnectorRegistration {
                    descriptor_digest: details.descriptor_digest,
                    previous_head_digest: details.previous_head_digest,
                })
        {
            return Err(KernelConnectorAuthorityErrorV2::BindingMismatch);
        }
        let verified = settlement.verify_connector_registration(
            settlement_key_id,
            settlement_public_key,
            installation_id,
            details.session.active_state_manifest_digest(),
            details.session.deployment_generation(),
            details.envelope_digest,
            details.session.principal(),
            details.decision_challenge,
            now,
        )?;

        let mut candidate = self.state.clone();
        if verified.decision() != ApprovalDecisionV2::Approve {
            candidate.adds[index].status = ConnectorAddStatusV2::Denied { settlement_digest };
            candidate.adds[index].details = None;
            self.persist_state(&candidate, current.head_digest(), None)?;
            self.state = candidate;
            return Err(KernelConnectorAuthorityErrorV2::Denied);
        }
        let approved = mint_handle(ApprovedConnectorRegistrationHandleV2::from_authority_entropy)?;
        candidate.adds[index].status = ConnectorAddStatusV2::Approved {
            approved,
            approved_commitment: approved.authority_commitment(&self.handle_key),
            settlement_bytes,
            settlement_digest,
            settlement_issued_at: verified.issued_at(),
        };
        self.persist_state(&candidate, current.head_digest(), None)?;
        self.state = candidate;
        Ok(approved)
    }

    pub(crate) fn apply_approved_add(
        &mut self,
        approved: ApprovedConnectorRegistrationHandleV2,
        agent_authority: &mut KernelAgentAuthorityV2,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
    ) -> Result<ConnectorRegistryMutationV2, KernelConnectorAuthorityErrorV2> {
        self.apply_approved_add_with_mode(
            approved,
            agent_authority,
            active_state_manifest_digest,
            deployment_generation,
            ConnectorCommitModeV2::Normal,
        )
    }

    #[cfg(test)]
    pub(crate) fn apply_approved_add_with_crash_for_test(
        &mut self,
        approved: ApprovedConnectorRegistrationHandleV2,
        agent_authority: &mut KernelAgentAuthorityV2,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
        crash_at: TestConnectorCommitCrashPointV2,
    ) -> Result<ConnectorRegistryMutationV2, KernelConnectorAuthorityErrorV2> {
        self.apply_approved_add_with_mode(
            approved,
            agent_authority,
            active_state_manifest_digest,
            deployment_generation,
            ConnectorCommitModeV2::Crash(crash_at),
        )
    }

    fn apply_approved_add_with_mode(
        &mut self,
        approved: ApprovedConnectorRegistrationHandleV2,
        agent_authority: &mut KernelAgentAuthorityV2,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
        commit_mode: ConnectorCommitModeV2,
    ) -> Result<ConnectorRegistryMutationV2, KernelConnectorAuthorityErrorV2> {
        self.ensure_available()?;
        #[cfg(test)]
        {
            self.published_after_durable_reopen = false;
        }
        let approved_commitment = approved.authority_commitment(&self.handle_key);
        let index = self
            .state
            .adds
            .iter()
            .position(|record| match &record.status {
                ConnectorAddStatusV2::Approved {
                    approved_commitment: value,
                    ..
                }
                | ConnectorAddStatusV2::Committed {
                    approved_commitment: value,
                    ..
                } => *value == approved_commitment,
                _ => false,
            })
            .ok_or(KernelConnectorAuthorityErrorV2::InvalidReference)?;
        let record = &self.state.adds[index];
        if record.active_state_manifest_digest != active_state_manifest_digest
            || record.deployment_generation != deployment_generation
        {
            return Err(KernelConnectorAuthorityErrorV2::BindingMismatch);
        }
        if let ConnectorAddStatusV2::Committed { result, .. } = &self.state.adds[index].status {
            return materialize_mutation(*result, &self.store_snapshot()?);
        }
        let current = self.store_snapshot()?;
        let record = &self.state.adds[index];
        let (settlement_digest, settlement_issued_at) = verify_approved_add_before_signing(
            record,
            &current,
            agent_authority,
            &self.handle_key,
        )?;
        let details = record
            .details
            .as_ref()
            .ok_or(KernelConnectorAuthorityErrorV2::StateConflict)?;
        if current.head_digest() != details.previous_head_digest
            || self.shared_registry.current_head_digest()? != details.previous_head_digest
        {
            return Err(KernelConnectorAuthorityErrorV2::BindingMismatch);
        }
        let prepared = current.prepare_add_delta(
            &details.canonical_descriptor,
            settlement_digest,
            settlement_issued_at.get(),
        )?;
        let delta = agent_authority.sign_prepared_connector_delta(prepared)?;
        let mut candidate_registry = current.clone();
        candidate_registry.apply_canonical_delta(delta.canonical_bytes())?;
        let result = ConnectorRegistryMutationV2 {
            canonical_delta: delta.canonical_bytes().to_vec(),
            signed_delta_digest: delta.signed_digest(),
            head_digest: candidate_registry.head_digest(),
            sequence: candidate_registry.sequence(),
            connector_id: delta.connector_id(),
            add: true,
        };
        let mut candidate = self.state.clone();
        candidate.sign_count = candidate
            .sign_count
            .checked_add(1)
            .ok_or(KernelConnectorAuthorityErrorV2::LimitExceeded)?;
        candidate.adds[index].status = ConnectorAddStatusV2::Committed {
            approved,
            approved_commitment,
            settlement_digest,
            result: ConnectorRegistryMutationSummaryV2 {
                sequence: result.sequence,
                connector_id: result.connector_id,
                add: true,
            },
        };
        candidate.adds[index].details = None;
        self.persist_state_with_mode(
            &candidate,
            current.head_digest(),
            Some(delta.canonical_bytes()),
            commit_mode,
        )?;
        if let Err(error) = self
            .shared_registry
            .verify_and_apply_canonical_delta(delta.canonical_bytes())
        {
            self.poisoned = true;
            return Err(error.into());
        }
        if self.shared_registry.current_head_digest()? != result.head_digest {
            self.poisoned = true;
            return Err(KernelConnectorAuthorityErrorV2::StateConflict);
        }
        #[cfg(test)]
        {
            self.published_after_durable_reopen = true;
        }
        self.state = candidate;
        Ok(result)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prepare_remove(
        &mut self,
        session: AgentSessionHandleV2,
        connector_id: Digest32V2,
        agent_authority: &KernelAgentAuthorityV2,
        caller_boot_id: BootIdV2,
        caller_identity: ServiceIdentityV2,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
        now: UnixMillisV2,
    ) -> Result<PreparedConnectorRemovalV2, KernelConnectorAuthorityErrorV2> {
        self.ensure_available()?;
        self.compact_stale_records(active_state_manifest_digest, deployment_generation, now)?;
        let context = agent_authority.connector_ui_session_context(
            session,
            caller_boot_id,
            caller_identity,
            active_state_manifest_digest,
            deployment_generation,
            now,
        )?;
        let current = self.store_snapshot()?;
        if !current.contains_registered_connector(connector_id)
            || current.head_digest() != self.shared_registry.current_head_digest()?
        {
            return Err(KernelConnectorAuthorityErrorV2::InvalidReference);
        }
        if let Some(existing) = self.state.removes.iter().find(|record| {
            matches!(&record.status, ConnectorRemoveStatusV2::Pending)
                && record.session == session
                && record.connector_id == connector_id
                && record.active_state_manifest_digest == active_state_manifest_digest
                && record.deployment_generation == deployment_generation
                && record.details.as_ref().is_some_and(|details| {
                    details.previous_head_digest == current.head_digest()
                        && same_removal_session_identity(&details.session, &context)
                        && now.get() < details.session.expires_at().get()
                })
        }) {
            let details = existing
                .details
                .as_ref()
                .ok_or(KernelConnectorAuthorityErrorV2::StateConflict)?;
            return Ok(PreparedConnectorRemovalV2 {
                authorization: existing.authorization,
                previous_head_digest: details.previous_head_digest,
                expires_at: details.session.expires_at(),
            });
        }
        self.ensure_record_capacity()?;
        let authorization =
            mint_handle(ConnectorRemovalAuthorizationHandleV2::from_authority_entropy)?;
        let record = ConnectorRemoveRecordV2 {
            authorization,
            authorization_commitment: authorization.authority_commitment(&self.handle_key),
            session,
            connector_id,
            active_state_manifest_digest,
            deployment_generation,
            details: Some(ConnectorRemoveDetailsV2 {
                session: context.clone(),
                previous_head_digest: current.head_digest(),
                issued_at: now,
            }),
            status: ConnectorRemoveStatusV2::Pending,
        };
        let mut candidate = self.state.clone();
        candidate.removes.push(record);
        self.persist_state(&candidate, current.head_digest(), None)?;
        self.state = candidate;
        Ok(PreparedConnectorRemovalV2 {
            authorization,
            previous_head_digest: current.head_digest(),
            expires_at: context.expires_at(),
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn remove(
        &mut self,
        session: AgentSessionHandleV2,
        authorization: ConnectorRemovalAuthorizationHandleV2,
        connector_id: Digest32V2,
        agent_authority: &mut KernelAgentAuthorityV2,
        caller_boot_id: BootIdV2,
        caller_identity: ServiceIdentityV2,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
        now: UnixMillisV2,
    ) -> Result<ConnectorRegistryMutationV2, KernelConnectorAuthorityErrorV2> {
        self.ensure_available()?;
        self.compact_stale_records(active_state_manifest_digest, deployment_generation, now)?;
        let authorization_commitment = authorization.authority_commitment(&self.handle_key);
        let index = self
            .state
            .removes
            .iter()
            .position(|record| record.authorization_commitment == authorization_commitment)
            .ok_or(KernelConnectorAuthorityErrorV2::InvalidReference)?;
        let record = &self.state.removes[index];
        if record.connector_id != connector_id
            || record.session != session
            || record.active_state_manifest_digest != active_state_manifest_digest
            || record.deployment_generation != deployment_generation
        {
            return Err(KernelConnectorAuthorityErrorV2::BindingMismatch);
        }
        if let ConnectorRemoveStatusV2::Committed(result) = &record.status {
            return materialize_mutation(*result, &self.store_snapshot()?);
        }
        if matches!(&record.status, ConnectorRemoveStatusV2::Expired) {
            return Err(KernelConnectorAuthorityErrorV2::Expired);
        }
        let details = record
            .details
            .as_ref()
            .ok_or(KernelConnectorAuthorityErrorV2::StateConflict)?;
        let live = agent_authority.connector_ui_session_context(
            session,
            caller_boot_id,
            caller_identity,
            active_state_manifest_digest,
            deployment_generation,
            now,
        )?;
        if !same_session_identity(&details.session, &live) {
            return Err(KernelConnectorAuthorityErrorV2::BindingMismatch);
        }
        let current = self.store_snapshot()?;
        if current.head_digest() != details.previous_head_digest
            || self.shared_registry.current_head_digest()? != details.previous_head_digest
            || !current.contains_registered_connector(connector_id)
        {
            return Err(KernelConnectorAuthorityErrorV2::BindingMismatch);
        }
        let prepared = current.prepare_remove_delta(connector_id, details.issued_at.get())?;
        let delta = agent_authority.sign_prepared_connector_delta(prepared)?;
        let mut candidate_registry = current.clone();
        candidate_registry.apply_canonical_delta(delta.canonical_bytes())?;
        let result = ConnectorRegistryMutationV2 {
            canonical_delta: delta.canonical_bytes().to_vec(),
            signed_delta_digest: delta.signed_digest(),
            head_digest: candidate_registry.head_digest(),
            sequence: candidate_registry.sequence(),
            connector_id,
            add: false,
        };
        let mut candidate = self.state.clone();
        candidate.sign_count = candidate
            .sign_count
            .checked_add(1)
            .ok_or(KernelConnectorAuthorityErrorV2::LimitExceeded)?;
        candidate.removes[index].status =
            ConnectorRemoveStatusV2::Committed(ConnectorRegistryMutationSummaryV2 {
                sequence: result.sequence,
                connector_id: result.connector_id,
                add: false,
            });
        candidate.removes[index].details = None;
        self.persist_state(
            &candidate,
            current.head_digest(),
            Some(delta.canonical_bytes()),
        )?;
        if let Err(error) = self
            .shared_registry
            .verify_and_apply_canonical_delta(delta.canonical_bytes())
        {
            self.poisoned = true;
            return Err(error.into());
        }
        self.state = candidate;
        Ok(result)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn snapshot(
        &self,
        session: AgentSessionHandleV2,
        agent_authority: &KernelAgentAuthorityV2,
        caller_boot_id: BootIdV2,
        caller_identity: ServiceIdentityV2,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
        now: UnixMillisV2,
    ) -> Result<ConnectorRegistrySnapshotV2, KernelConnectorAuthorityErrorV2> {
        self.ensure_available()?;
        agent_authority.connector_ui_session_context(
            session,
            caller_boot_id,
            caller_identity,
            active_state_manifest_digest,
            deployment_generation,
            now,
        )?;
        let state = self.store_snapshot()?;
        if self.shared_registry.current_head_digest()? != state.head_digest() {
            return Err(KernelConnectorAuthorityErrorV2::StateConflict);
        }
        Ok(ConnectorRegistrySnapshotV2 {
            canonical_bytes: encode_registry_snapshot(&state)?,
            head_digest: state.head_digest(),
            sequence: state.sequence(),
        })
    }

    fn ensure_available(&self) -> Result<(), KernelConnectorAuthorityErrorV2> {
        if !self.enabled || self.poisoned || self.store.is_none() {
            Err(KernelConnectorAuthorityErrorV2::Unavailable)
        } else {
            Ok(())
        }
    }

    fn ensure_record_capacity(&self) -> Result<(), KernelConnectorAuthorityErrorV2> {
        if self
            .state
            .adds
            .len()
            .saturating_add(self.state.removes.len())
            >= MAX_AUTHORITY_RECORDS_V2
        {
            Err(KernelConnectorAuthorityErrorV2::LimitExceeded)
        } else {
            Ok(())
        }
    }

    fn compact_stale_records(
        &mut self,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
        now: UnixMillisV2,
    ) -> Result<(), KernelConnectorAuthorityErrorV2> {
        let mut candidate = self.state.clone();
        let mut changed = false;
        for record in &mut candidate.adds {
            let stale = record.details.as_ref().is_some_and(|details| {
                now.get() >= details.session.expires_at().get()
                    || record.active_state_manifest_digest != active_state_manifest_digest
                    || record.deployment_generation != deployment_generation
            });
            if stale && matches!(&record.status, ConnectorAddStatusV2::Pending) {
                record.details = None;
                record.status = ConnectorAddStatusV2::Expired;
                changed = true;
            }
        }
        for record in &mut candidate.removes {
            let stale = record.details.as_ref().is_some_and(|details| {
                now.get() >= details.session.expires_at().get()
                    || record.active_state_manifest_digest != active_state_manifest_digest
                    || record.deployment_generation != deployment_generation
            });
            if stale && matches!(&record.status, ConnectorRemoveStatusV2::Pending) {
                record.details = None;
                record.status = ConnectorRemoveStatusV2::Expired;
                changed = true;
            }
        }
        if changed {
            let current = self.store_snapshot()?;
            self.persist_state(&candidate, current.head_digest(), None)?;
            self.state = candidate;
        }
        Ok(())
    }

    fn store_snapshot(&self) -> Result<ConnectorRegistryStateV2, KernelConnectorAuthorityErrorV2> {
        let store = self
            .store
            .as_ref()
            .ok_or(KernelConnectorAuthorityErrorV2::Unavailable)?;
        if Some(store.revision()?) != self.store_revision {
            return Err(KernelConnectorAuthorityErrorV2::StateConflict);
        }
        store.snapshot().map_err(Into::into)
    }

    fn persist_state(
        &mut self,
        candidate: &ConnectorAuthorityStateV2,
        expected_head: Digest32V2,
        delta: Option<&[u8]>,
    ) -> Result<ConnectorRegistryStateV2, KernelConnectorAuthorityErrorV2> {
        self.persist_state_with_mode(
            candidate,
            expected_head,
            delta,
            ConnectorCommitModeV2::Normal,
        )
    }

    fn persist_state_with_mode(
        &mut self,
        candidate: &ConnectorAuthorityStateV2,
        expected_head: Digest32V2,
        delta: Option<&[u8]>,
        mode: ConnectorCommitModeV2,
    ) -> Result<ConnectorRegistryStateV2, KernelConnectorAuthorityErrorV2> {
        let bytes = encode_authority_state(candidate)?;
        let expected_revision = self
            .store_revision
            .ok_or(KernelConnectorAuthorityErrorV2::Unavailable)?;
        let result = {
            let store = self
                .store
                .as_mut()
                .ok_or(KernelConnectorAuthorityErrorV2::Unavailable)?;
            match mode {
                ConnectorCommitModeV2::Normal => store
                    .commit(expected_head, expected_revision, delta, &bytes)
                    .map_err(Into::into),
                #[cfg(test)]
                ConnectorCommitModeV2::Crash(point) => store
                    .commit_with_crash_for_test(
                        expected_head,
                        expected_revision,
                        delta,
                        &bytes,
                        point.store_point(),
                    )
                    .map_err(Into::into),
            }
        };
        if result.is_ok() {
            self.store_revision = Some(
                self.store
                    .as_ref()
                    .ok_or(KernelConnectorAuthorityErrorV2::Unavailable)?
                    .revision()?,
            );
        }
        result
    }

    #[cfg(test)]
    pub(crate) const fn sign_count(&self) -> u64 {
        self.state.sign_count
    }

    #[cfg(test)]
    pub(crate) fn add_record_count_for_test(&self) -> usize {
        self.state.adds.len()
    }

    #[cfg(test)]
    pub(crate) fn heavy_record_count_for_test(&self) -> usize {
        self.state
            .adds
            .iter()
            .filter(|record| record.details.is_some())
            .count()
            .saturating_add(
                self.state
                    .removes
                    .iter()
                    .filter(|record| record.details.is_some())
                    .count(),
            )
    }

    #[cfg(test)]
    pub(crate) fn encoded_state_len_for_test(
        &self,
    ) -> Result<usize, KernelConnectorAuthorityErrorV2> {
        encode_authority_state(&self.state).map(|bytes| bytes.len())
    }

    #[cfg(test)]
    pub(crate) fn replace_approved_settlement_for_test(
        &mut self,
        approved: ApprovedConnectorRegistrationHandleV2,
        settlement: &SignedApprovalSettlementV2,
    ) -> Result<(), KernelConnectorAuthorityErrorV2> {
        let approved_commitment = approved.authority_commitment(&self.handle_key);
        let mut candidate = self.state.clone();
        let record = candidate
            .adds
            .iter_mut()
            .find(|record| {
                matches!(
                    &record.status,
                    ConnectorAddStatusV2::Approved {
                        approved_commitment: value,
                        ..
                    } if *value == approved_commitment
                )
            })
            .ok_or(KernelConnectorAuthorityErrorV2::InvalidReference)?;
        let ConnectorAddStatusV2::Approved {
            settlement_bytes,
            settlement_digest,
            settlement_issued_at,
            ..
        } = &mut record.status
        else {
            return Err(KernelConnectorAuthorityErrorV2::InvalidReference);
        };
        *settlement_bytes = encode_signed_approval_settlement_v2(settlement)?;
        *settlement_digest = settlement.settlement_digest()?;
        *settlement_issued_at = settlement.unsigned().issued_at();
        let current = self.store_snapshot()?;
        self.persist_state(&candidate, current.head_digest(), None)?;
        self.state = candidate;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn duplicate_committed_add_summary_for_test(
        &mut self,
    ) -> Result<(), KernelConnectorAuthorityErrorV2> {
        let mut candidate = self.state.clone();
        let summaries = candidate
            .adds
            .iter()
            .filter_map(|record| match record.status {
                ConnectorAddStatusV2::Committed { result, .. } => Some(result),
                _ => None,
            })
            .collect::<Vec<_>>();
        if summaries.len() < 2 {
            return Err(KernelConnectorAuthorityErrorV2::InvalidReference);
        }
        let mut seen = false;
        for record in &mut candidate.adds {
            if let ConnectorAddStatusV2::Committed { result, .. } = &mut record.status {
                if seen {
                    *result = summaries[0];
                    break;
                }
                seen = true;
            }
        }
        let current = self.store_snapshot()?;
        self.persist_state(&candidate, current.head_digest(), None)?;
        self.state = candidate;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn corrupt_committed_add_settlement_digest_for_test(
        &mut self,
    ) -> Result<(), KernelConnectorAuthorityErrorV2> {
        let mut candidate = self.state.clone();
        let record = candidate
            .adds
            .iter_mut()
            .find(|record| matches!(record.status, ConnectorAddStatusV2::Committed { .. }))
            .ok_or(KernelConnectorAuthorityErrorV2::InvalidReference)?;
        let ConnectorAddStatusV2::Committed {
            settlement_digest, ..
        } = &mut record.status
        else {
            return Err(KernelConnectorAuthorityErrorV2::InvalidReference);
        };
        let mut bytes = *settlement_digest.as_bytes();
        bytes[0] ^= 1;
        *settlement_digest = Digest32V2::new(bytes);
        let current = self.store_snapshot()?;
        self.persist_state(&candidate, current.head_digest(), None)?;
        self.state = candidate;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn shared_registry_for_test(&self) -> SharedVerifiedConnectorRegistryV2 {
        self.shared_registry.clone()
    }

    #[cfg(test)]
    pub(crate) fn replace_shared_registry_for_test(
        &mut self,
        shared_registry: SharedVerifiedConnectorRegistryV2,
    ) {
        self.shared_registry = shared_registry;
    }

    #[cfg(test)]
    pub(crate) const fn published_after_durable_reopen_for_test(&self) -> bool {
        self.published_after_durable_reopen
    }

    #[cfg(test)]
    pub(crate) fn replace_removal_head_for_test(
        &mut self,
        authorization: ConnectorRemovalAuthorizationHandleV2,
        replacement: Digest32V2,
    ) -> Result<Digest32V2, KernelConnectorAuthorityErrorV2> {
        let commitment = authorization.authority_commitment(&self.handle_key);
        let record = self
            .state
            .removes
            .iter_mut()
            .find(|record| record.authorization_commitment == commitment)
            .ok_or(KernelConnectorAuthorityErrorV2::InvalidReference)?;
        let details = record
            .details
            .as_mut()
            .ok_or(KernelConnectorAuthorityErrorV2::AlreadyConsumed)?;
        Ok(std::mem::replace(
            &mut details.previous_head_digest,
            replacement,
        ))
    }
}

fn add_record_from_prepared(
    pending: PendingConnectorRegistrationHandleV2,
    prepared: PreparedConnectorRegistrationProposalV2,
    handle_key: &AuthorityHandleKeyV2,
) -> ConnectorAddRecordV2 {
    let proposal_identity_digest = proposal_identity_digest(
        prepared.session(),
        prepared.caller_identity(),
        prepared.descriptor_digest(),
        prepared.previous_head_digest(),
        handle_key,
    );
    let active_state_manifest_digest = prepared.session().active_state_manifest_digest();
    let deployment_generation = prepared.session().deployment_generation();
    ConnectorAddRecordV2 {
        pending,
        pending_commitment: pending.authority_commitment(handle_key),
        source_authorization_commitment: prepared.authorization_commitment(),
        proposal_identity_digest,
        active_state_manifest_digest,
        deployment_generation,
        details: Some(ConnectorAddDetailsV2 {
            session: prepared.session().clone(),
            caller_identity: prepared.caller_identity(),
            canonical_descriptor: prepared.canonical_descriptor().to_vec(),
            descriptor_digest: prepared.descriptor_digest(),
            previous_head_digest: prepared.previous_head_digest(),
            envelope: prepared.envelope().clone(),
            display_authentication: prepared.display_authentication().clone(),
            envelope_digest: prepared.envelope_digest(),
            decision_challenge: prepared.decision_challenge(),
        }),
        status: ConnectorAddStatusV2::Pending,
    }
}

fn proposal_identity_digest(
    session: &ConnectorUiSessionContextV2,
    caller_identity: ServiceIdentityV2,
    descriptor_digest: Digest32V2,
    previous_head_digest: Digest32V2,
    handle_key: &AuthorityHandleKeyV2,
) -> Digest32V2 {
    let mut hasher = Sha256::new();
    hasher.update(PROPOSAL_IDENTITY_DOMAIN_V2);
    hasher.update(descriptor_digest.as_bytes());
    hasher.update(previous_head_digest.as_bytes());
    hasher.update(
        session
            .session()
            .authority_commitment(handle_key)
            .as_bytes(),
    );
    hasher.update(session.principal().as_bytes());
    hasher.update(session.durable_task_id().as_bytes());
    hasher.update(session.durable_run_id().as_bytes());
    hasher.update(session.caller_boot_id().as_bytes());
    hasher.update(caller_identity.as_bytes());
    hasher.update(session.active_state_manifest_digest().as_bytes());
    hasher.update(session.deployment_generation().to_be_bytes());
    Digest32V2::new(hasher.finalize().into())
}

fn proposal_response(
    record: &ConnectorAddRecordV2,
) -> Result<ProposeConnectorRegistrationResponseV2, KernelConnectorAuthorityErrorV2> {
    let details = record
        .details
        .as_ref()
        .ok_or(KernelConnectorAuthorityErrorV2::AlreadyConsumed)?;
    Ok(ProposeConnectorRegistrationResponseV2::new(
        record.pending,
        details.envelope.clone(),
        details.display_authentication.clone(),
    ))
}

fn materialize_mutation(
    summary: ConnectorRegistryMutationSummaryV2,
    registry: &ConnectorRegistryStateV2,
) -> Result<ConnectorRegistryMutationV2, KernelConnectorAuthorityErrorV2> {
    let index = usize::try_from(
        summary
            .sequence
            .checked_sub(1)
            .ok_or(KernelConnectorAuthorityErrorV2::StateConflict)?,
    )
    .map_err(|_| KernelConnectorAuthorityErrorV2::StateConflict)?;
    let journal = registry.deltas();
    let delta = journal
        .get(index)
        .ok_or(KernelConnectorAuthorityErrorV2::StateConflict)?;
    if delta.sequence() != summary.sequence
        || delta.connector_id() != summary.connector_id
        || delta.is_add() != summary.add
    {
        return Err(KernelConnectorAuthorityErrorV2::StateConflict);
    }
    let head_digest = journal
        .get(index + 1)
        .map_or(registry.head_digest(), |next| next.previous_head_digest());
    Ok(ConnectorRegistryMutationV2 {
        canonical_delta: delta.canonical_bytes().to_vec(),
        signed_delta_digest: delta.signed_digest(),
        head_digest,
        sequence: summary.sequence,
        connector_id: summary.connector_id,
        add: summary.add,
    })
}

fn same_session_identity(
    expected: &ConnectorUiSessionContextV2,
    actual: &ConnectorUiSessionContextV2,
) -> bool {
    expected.session() == actual.session()
        && expected.principal() == actual.principal()
        && expected.durable_task_id() == actual.durable_task_id()
        && expected.durable_run_id() == actual.durable_run_id()
        && expected.caller_boot_id() == actual.caller_boot_id()
        && expected.active_state_manifest_digest() == actual.active_state_manifest_digest()
        && expected.deployment_generation() == actual.deployment_generation()
        && expected.expires_at() == actual.expires_at()
}

fn same_removal_session_identity(
    expected: &ConnectorUiSessionContextV2,
    actual: &ConnectorUiSessionContextV2,
) -> bool {
    expected.session() == actual.session()
        && expected.principal() == actual.principal()
        && expected.durable_task_id() == actual.durable_task_id()
        && expected.durable_run_id() == actual.durable_run_id()
        && expected.caller_boot_id() == actual.caller_boot_id()
        && expected.active_state_manifest_digest() == actual.active_state_manifest_digest()
        && expected.deployment_generation() == actual.deployment_generation()
        && expected.expires_at() == actual.expires_at()
}

fn same_proposal_identity(
    existing: &ConnectorAddRecordV2,
    prepared: &PreparedConnectorRegistrationProposalV2,
    handle_key: &AuthorityHandleKeyV2,
) -> bool {
    existing.proposal_identity_digest
        == proposal_identity_digest(
            prepared.session(),
            prepared.caller_identity(),
            prepared.descriptor_digest(),
            prepared.previous_head_digest(),
            handle_key,
        )
        && existing.details.as_ref().is_some_and(|details| {
            details.canonical_descriptor == prepared.canonical_descriptor()
                && details.descriptor_digest == prepared.descriptor_digest()
                && details.previous_head_digest == prepared.previous_head_digest()
        })
}

fn verify_approved_add_before_signing(
    record: &ConnectorAddRecordV2,
    registry: &ConnectorRegistryStateV2,
    agent_authority: &KernelAgentAuthorityV2,
    handle_key: &AuthorityHandleKeyV2,
) -> Result<(Digest32V2, UnixMillisV2), KernelConnectorAuthorityErrorV2> {
    let details = record
        .details
        .as_ref()
        .ok_or(KernelConnectorAuthorityErrorV2::BindingMismatch)?;
    let ConnectorAddStatusV2::Approved {
        settlement_bytes,
        settlement_digest,
        settlement_issued_at,
        ..
    } = &record.status
    else {
        return Err(KernelConnectorAuthorityErrorV2::AlreadyConsumed);
    };
    if details.session.active_state_manifest_digest() != record.active_state_manifest_digest
        || details.session.deployment_generation() != record.deployment_generation
        || record.proposal_identity_digest
            != proposal_identity_digest(
                &details.session,
                details.caller_identity,
                details.descriptor_digest,
                details.previous_head_digest,
                handle_key,
            )
        || connector_registration_descriptor_digest_v2(&details.canonical_descriptor)?
            != details.descriptor_digest
    {
        return Err(KernelConnectorAuthorityErrorV2::BindingMismatch);
    }
    let descriptor = ConnectorDescriptorV2::from_canonical_bytes(
        &details.canonical_descriptor,
        registry.user_host_allowlist(),
    )?;
    if descriptor.tier() != ConnectorTierV2::UserRegistered {
        return Err(KernelConnectorAuthorityErrorV2::BindingMismatch);
    }

    let ConnectorSecurityVerifiersV2 {
        installation_id,
        settlement_key_id,
        settlement_public_key,
        envelope_key_id,
        envelope_public_key,
    } = agent_authority.connector_security_verifiers()?;
    let unsigned_envelope = details.envelope.verify(
        envelope_key_id,
        envelope_public_key,
        installation_id,
        record.active_state_manifest_digest,
        record.deployment_generation,
        ApprovalPurposeV2::ConnectorRegistration,
        details.session.principal(),
        *settlement_issued_at,
    )?;
    if details.envelope.envelope_digest()? != details.envelope_digest
        || unsigned_envelope.decision_challenge() != details.decision_challenge
        || unsigned_envelope.binding()
            != (ApprovalBindingV2::ConnectorRegistration {
                descriptor_digest: details.descriptor_digest,
                previous_head_digest: details.previous_head_digest,
            })
    {
        return Err(KernelConnectorAuthorityErrorV2::BindingMismatch);
    }
    let unsigned_display = details.display_authentication.verify(
        envelope_key_id,
        envelope_public_key,
        installation_id,
        record.active_state_manifest_digest,
        record.deployment_generation,
        *settlement_issued_at,
    )?;
    if unsigned_display.purpose() != UiAuthenticationPurposeV2::ApprovalDisplay
        || unsigned_display.expected_principal() != Some(details.session.principal())
        || unsigned_display.authentication_origin() != FixedOriginV2::Approval8766
        || unsigned_display.return_origin() != FixedOriginV2::Approval8766
        || unsigned_display.binding()
            != (UiAuthenticationBindingV2::ApprovalDisplay {
                durable_task_id: details.session.durable_task_id(),
                approval_envelope_digest: details.envelope_digest,
                approval_purpose: ApprovalPurposeV2::ConnectorRegistration,
                display_digest: unsigned_envelope.display_digest(),
            })
    {
        return Err(KernelConnectorAuthorityErrorV2::BindingMismatch);
    }

    let settlement = decode_signed_approval_settlement_v2(settlement_bytes)?;
    if settlement.settlement_digest()? != *settlement_digest {
        return Err(KernelConnectorAuthorityErrorV2::BindingMismatch);
    }
    let verified = settlement.verify_connector_registration(
        settlement_key_id,
        settlement_public_key,
        installation_id,
        record.active_state_manifest_digest,
        record.deployment_generation,
        details.envelope_digest,
        details.session.principal(),
        details.decision_challenge,
        *settlement_issued_at,
    )?;
    if verified.decision() != ApprovalDecisionV2::Approve
        || verified.settlement_digest() != *settlement_digest
        || verified.issued_at() != *settlement_issued_at
    {
        return Err(KernelConnectorAuthorityErrorV2::BindingMismatch);
    }
    Ok((*settlement_digest, *settlement_issued_at))
}

fn validate_recovered_authority_state(
    state: &ConnectorAuthorityStateV2,
    registry: &ConnectorRegistryStateV2,
    handle_key: &AuthorityHandleKeyV2,
) -> Result<(), KernelConnectorAuthorityErrorV2> {
    if state.adds.len().saturating_add(state.removes.len()) > MAX_AUTHORITY_RECORDS_V2 {
        return Err(KernelConnectorAuthorityErrorV2::LimitExceeded);
    }
    if state.sign_count != registry.sequence() {
        return Err(KernelConnectorAuthorityErrorV2::BindingMismatch);
    }
    let mut pending_handles = BTreeSet::new();
    let mut approved_handles = BTreeSet::new();
    let mut removal_handles = BTreeSet::new();
    let mut committed_sequences = BTreeSet::new();
    for record in &state.adds {
        if !pending_handles.insert(handle_bytes(&record.pending_commitment)?)
            || record.pending.authority_commitment(handle_key) != record.pending_commitment
        {
            return Err(KernelConnectorAuthorityErrorV2::BindingMismatch);
        }
        match (&record.status, &record.details) {
            (ConnectorAddStatusV2::Pending | ConnectorAddStatusV2::Approved { .. }, Some(_))
            | (
                ConnectorAddStatusV2::Denied { .. }
                | ConnectorAddStatusV2::Committed { .. }
                | ConnectorAddStatusV2::Expired,
                None,
            ) => {}
            _ => return Err(KernelConnectorAuthorityErrorV2::BindingMismatch),
        }
        if let Some(details) = &record.details {
            if details.envelope_digest != details.envelope.envelope_digest()?
                || encode_signed_approval_envelope_v2(&details.envelope)?.is_empty()
                || details.session.active_state_manifest_digest()
                    != record.active_state_manifest_digest
                || details.session.deployment_generation() != record.deployment_generation
                || record.proposal_identity_digest
                    != proposal_identity_digest(
                        &details.session,
                        details.caller_identity,
                        details.descriptor_digest,
                        details.previous_head_digest,
                        handle_key,
                    )
                || connector_registration_descriptor_digest_v2(&details.canonical_descriptor)?
                    != details.descriptor_digest
            {
                return Err(KernelConnectorAuthorityErrorV2::BindingMismatch);
            }
        }
        if let ConnectorAddStatusV2::Approved {
            approved,
            approved_commitment,
            ..
        }
        | ConnectorAddStatusV2::Committed {
            approved,
            approved_commitment,
            ..
        } = &record.status
        {
            if approved.authority_commitment(handle_key) != *approved_commitment
                || !approved_handles.insert(handle_bytes(approved_commitment)?)
            {
                return Err(KernelConnectorAuthorityErrorV2::BindingMismatch);
            }
        }
        if let ConnectorAddStatusV2::Approved {
            settlement_bytes,
            settlement_digest,
            settlement_issued_at,
            ..
        } = &record.status
        {
            let settlement = decode_signed_approval_settlement_v2(settlement_bytes)?;
            if settlement.purpose() != ApprovalPurposeV2::ConnectorRegistration
                || settlement.unsigned().decision() != ApprovalDecisionV2::Approve
                || settlement.settlement_digest()? != *settlement_digest
                || settlement.unsigned().issued_at() != *settlement_issued_at
            {
                return Err(KernelConnectorAuthorityErrorV2::BindingMismatch);
            }
        }
        if let ConnectorAddStatusV2::Committed {
            settlement_digest,
            result,
            ..
        } = &record.status
        {
            let mutation = materialize_mutation(*result, registry)
                .map_err(|_| KernelConnectorAuthorityErrorV2::BindingMismatch)?;
            let delta = registry
                .deltas()
                .get(
                    usize::try_from(result.sequence.saturating_sub(1))
                        .map_err(|_| KernelConnectorAuthorityErrorV2::BindingMismatch)?,
                )
                .ok_or(KernelConnectorAuthorityErrorV2::BindingMismatch)?;
            if !result.add
                || !mutation.add
                || delta.settlement_digest() != *settlement_digest
                || !committed_sequences.insert(result.sequence)
            {
                return Err(KernelConnectorAuthorityErrorV2::BindingMismatch);
            }
        }
    }
    for record in &state.removes {
        if record.authorization.authority_commitment(handle_key) != record.authorization_commitment
            || !removal_handles.insert(handle_bytes(&record.authorization_commitment)?)
        {
            return Err(KernelConnectorAuthorityErrorV2::BindingMismatch);
        }
        match (&record.status, &record.details) {
            (ConnectorRemoveStatusV2::Pending, Some(_))
            | (ConnectorRemoveStatusV2::Committed(_) | ConnectorRemoveStatusV2::Expired, None) => {}
            _ => return Err(KernelConnectorAuthorityErrorV2::BindingMismatch),
        }
        if let ConnectorRemoveStatusV2::Committed(result) = &record.status {
            let mutation = materialize_mutation(*result, registry)
                .map_err(|_| KernelConnectorAuthorityErrorV2::BindingMismatch)?;
            let delta = registry
                .deltas()
                .get(
                    usize::try_from(result.sequence.saturating_sub(1))
                        .map_err(|_| KernelConnectorAuthorityErrorV2::BindingMismatch)?,
                )
                .ok_or(KernelConnectorAuthorityErrorV2::BindingMismatch)?;
            if result.add
                || mutation.add
                || delta.settlement_digest() != Digest32V2::new([0; 32])
                || !committed_sequences.insert(result.sequence)
            {
                return Err(KernelConnectorAuthorityErrorV2::BindingMismatch);
            }
        }
    }
    if committed_sequences.len() != registry.deltas().len()
        || !(1..=registry.sequence()).all(|sequence| committed_sequences.contains(&sequence))
    {
        return Err(KernelConnectorAuthorityErrorV2::BindingMismatch);
    }
    Ok(())
}

fn encode_registry_snapshot(
    state: &ConnectorRegistryStateV2,
) -> Result<Vec<u8>, KernelConnectorAuthorityErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(6)
        .and_then(|encoder| encoder.u16(1))
        .and_then(|encoder| encoder.bytes(state.genesis_digest().as_bytes()))
        .and_then(|encoder| encoder.bytes(state.head_digest().as_bytes()))
        .and_then(|encoder| encoder.u64(state.sequence()))
        .and_then(|encoder| encoder.bytes(&state.connector_authority_public_key()))
        .and_then(|encoder| encoder.array(state.registered_connector_count() as u64))
        .map_err(|_| KernelConnectorAuthorityErrorV2::Unavailable)?;
    for descriptor in state.registered_connectors() {
        encoder
            .array(2)
            .and_then(|encoder| encoder.bytes(descriptor.connector_id().as_bytes()))
            .and_then(|encoder| encoder.bool(state.contains_connector(descriptor.connector_id())))
            .map_err(|_| KernelConnectorAuthorityErrorV2::Unavailable)?;
    }
    let bytes = encoder.into_writer();
    if bytes.is_empty() || bytes.len() > MAX_CONNECTOR_AUTHORITY_STATE_BYTES_V2 {
        return Err(KernelConnectorAuthorityErrorV2::LimitExceeded);
    }
    Ok(bytes)
}

fn encode_authority_state(
    state: &ConnectorAuthorityStateV2,
) -> Result<Vec<u8>, KernelConnectorAuthorityErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(4)
        .and_then(|encoder| encoder.u16(AUTHORITY_STATE_SCHEMA_V2))
        .and_then(|encoder| encoder.u64(state.sign_count))
        .and_then(|encoder| encoder.array(state.adds.len() as u64))
        .map_err(|_| KernelConnectorAuthorityErrorV2::Unavailable)?;
    for record in &state.adds {
        encode_add_record(&mut encoder, record)?;
    }
    encoder
        .array(state.removes.len() as u64)
        .map_err(|_| KernelConnectorAuthorityErrorV2::Unavailable)?;
    for record in &state.removes {
        encode_remove_record(&mut encoder, record)?;
    }
    let bytes = encoder.into_writer();
    if bytes.len() > MAX_CONNECTOR_AUTHORITY_STATE_BYTES_V2 {
        return Err(KernelConnectorAuthorityErrorV2::LimitExceeded);
    }
    Ok(bytes)
}

fn encode_add_record(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    record: &ConnectorAddRecordV2,
) -> Result<(), KernelConnectorAuthorityErrorV2> {
    encoder
        .array(ADD_RECORD_FIELDS_V2)
        .map_err(|_| KernelConnectorAuthorityErrorV2::Unavailable)?;
    encode_typed(encoder, &record.pending)?;
    encode_typed(encoder, &record.pending_commitment)?;
    encode_typed(encoder, &record.source_authorization_commitment)?;
    encode_typed(encoder, &record.proposal_identity_digest)?;
    encode_typed(encoder, &record.active_state_manifest_digest)?;
    encoder
        .u64(record.deployment_generation)
        .map_err(|_| KernelConnectorAuthorityErrorV2::Unavailable)?;
    match &record.details {
        Some(details) => encode_add_details(encoder, details)?,
        None => {
            encoder
                .null()
                .map_err(|_| KernelConnectorAuthorityErrorV2::Unavailable)?;
        }
    }
    encode_add_status(encoder, &record.status)?;
    encoder
        .null()
        .map_err(|_| KernelConnectorAuthorityErrorV2::Unavailable)?;
    Ok(())
}

fn encode_add_details(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    details: &ConnectorAddDetailsV2,
) -> Result<(), KernelConnectorAuthorityErrorV2> {
    encoder
        .array(ADD_DETAILS_FIELDS_V2)
        .map_err(|_| KernelConnectorAuthorityErrorV2::Unavailable)?;
    encode_session(encoder, &details.session)?;
    encode_typed(encoder, &details.caller_identity)?;
    encoder
        .bytes(&details.canonical_descriptor)
        .map_err(|_| KernelConnectorAuthorityErrorV2::Unavailable)?;
    encode_typed(encoder, &details.descriptor_digest)?;
    encode_typed(encoder, &details.previous_head_digest)?;
    let envelope_bytes = encode_signed_approval_envelope_v2(&details.envelope)?;
    let display_bytes =
        encode_signed_ui_authentication_envelope_v2(&details.display_authentication)?;
    encoder
        .bytes(&envelope_bytes)
        .and_then(|encoder| encoder.bytes(&display_bytes))
        .map_err(|_| KernelConnectorAuthorityErrorV2::Unavailable)?;
    encode_typed(encoder, &details.envelope_digest)?;
    encode_typed(encoder, &details.decision_challenge)?;
    encoder
        .null()
        .map_err(|_| KernelConnectorAuthorityErrorV2::Unavailable)?;
    Ok(())
}

fn encode_add_status(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    status: &ConnectorAddStatusV2,
) -> Result<(), KernelConnectorAuthorityErrorV2> {
    match status {
        ConnectorAddStatusV2::Pending => {
            encoder
                .array(1)
                .and_then(|encoder| encoder.u16(0))
                .map_err(|_| KernelConnectorAuthorityErrorV2::Unavailable)?;
        }
        ConnectorAddStatusV2::Approved {
            approved,
            approved_commitment,
            settlement_bytes,
            settlement_digest,
            settlement_issued_at,
        } => {
            encoder
                .array(6)
                .and_then(|encoder| encoder.u16(1))
                .map_err(|_| KernelConnectorAuthorityErrorV2::Unavailable)?;
            encode_typed(encoder, approved)?;
            encode_typed(encoder, approved_commitment)?;
            encoder
                .bytes(settlement_bytes)
                .map_err(|_| KernelConnectorAuthorityErrorV2::Unavailable)?;
            encode_typed(encoder, settlement_digest)?;
            encode_typed(encoder, settlement_issued_at)?;
        }
        ConnectorAddStatusV2::Denied { settlement_digest } => {
            encoder
                .array(2)
                .and_then(|encoder| encoder.u16(2))
                .map_err(|_| KernelConnectorAuthorityErrorV2::Unavailable)?;
            encode_typed(encoder, settlement_digest)?;
        }
        ConnectorAddStatusV2::Committed {
            approved,
            approved_commitment,
            settlement_digest,
            result,
        } => {
            encoder
                .array(5)
                .and_then(|encoder| encoder.u16(3))
                .map_err(|_| KernelConnectorAuthorityErrorV2::Unavailable)?;
            encode_typed(encoder, approved)?;
            encode_typed(encoder, approved_commitment)?;
            encode_typed(encoder, settlement_digest)?;
            encode_mutation_summary(encoder, result)?;
        }
        ConnectorAddStatusV2::Expired => {
            encoder
                .array(1)
                .and_then(|encoder| encoder.u16(4))
                .map_err(|_| KernelConnectorAuthorityErrorV2::Unavailable)?;
        }
    }
    Ok(())
}

fn encode_remove_record(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    record: &ConnectorRemoveRecordV2,
) -> Result<(), KernelConnectorAuthorityErrorV2> {
    encoder
        .array(REMOVE_RECORD_FIELDS_V2)
        .map_err(|_| KernelConnectorAuthorityErrorV2::Unavailable)?;
    encode_typed(encoder, &record.authorization)?;
    encode_typed(encoder, &record.authorization_commitment)?;
    encode_typed(encoder, &record.session)?;
    encode_typed(encoder, &record.connector_id)?;
    encode_typed(encoder, &record.active_state_manifest_digest)?;
    encoder
        .u64(record.deployment_generation)
        .map_err(|_| KernelConnectorAuthorityErrorV2::Unavailable)?;
    match &record.details {
        Some(details) => {
            encoder
                .array(REMOVE_DETAILS_FIELDS_V2)
                .map_err(|_| KernelConnectorAuthorityErrorV2::Unavailable)?;
            encode_session(encoder, &details.session)?;
            encode_typed(encoder, &details.previous_head_digest)?;
            encode_typed(encoder, &details.issued_at)?;
        }
        None => {
            encoder
                .null()
                .map_err(|_| KernelConnectorAuthorityErrorV2::Unavailable)?;
        }
    }
    match &record.status {
        ConnectorRemoveStatusV2::Pending => {
            encoder
                .array(1)
                .and_then(|encoder| encoder.u16(0))
                .map_err(|_| KernelConnectorAuthorityErrorV2::Unavailable)?;
        }
        ConnectorRemoveStatusV2::Committed(result) => {
            encoder
                .array(2)
                .and_then(|encoder| encoder.u16(1))
                .map_err(|_| KernelConnectorAuthorityErrorV2::Unavailable)?;
            encode_mutation_summary(encoder, result)?;
        }
        ConnectorRemoveStatusV2::Expired => {
            encoder
                .array(1)
                .and_then(|encoder| encoder.u16(2))
                .map_err(|_| KernelConnectorAuthorityErrorV2::Unavailable)?;
        }
    }
    Ok(())
}

fn encode_session(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    session: &ConnectorUiSessionContextV2,
) -> Result<(), KernelConnectorAuthorityErrorV2> {
    encoder
        .array(SESSION_FIELDS_V2)
        .map_err(|_| KernelConnectorAuthorityErrorV2::Unavailable)?;
    encode_typed(encoder, &session.session())?;
    encode_typed(encoder, &session.principal())?;
    encode_typed(encoder, &session.durable_task_id())?;
    encode_typed(encoder, &session.durable_run_id())?;
    encode_typed(encoder, &session.caller_boot_id())?;
    encode_typed(encoder, &session.active_state_manifest_digest())?;
    encoder
        .u64(session.deployment_generation())
        .map_err(|_| KernelConnectorAuthorityErrorV2::Unavailable)?;
    encode_typed(encoder, &session.issued_at())?;
    encode_typed(encoder, &session.expires_at())?;
    Ok(())
}

fn encode_mutation_summary(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    result: &ConnectorRegistryMutationSummaryV2,
) -> Result<(), KernelConnectorAuthorityErrorV2> {
    encoder
        .array(MUTATION_SUMMARY_FIELDS_V2)
        .and_then(|encoder| encoder.u64(result.sequence))
        .map_err(|_| KernelConnectorAuthorityErrorV2::Unavailable)?;
    encode_typed(encoder, &result.connector_id)?;
    encoder
        .bool(result.add)
        .and_then(|encoder| encoder.null())
        .map_err(|_| KernelConnectorAuthorityErrorV2::Unavailable)?;
    Ok(())
}

fn decode_authority_state(
    bytes: &[u8],
) -> Result<ConnectorAuthorityStateV2, KernelConnectorAuthorityErrorV2> {
    if bytes.is_empty() {
        return Ok(ConnectorAuthorityStateV2::default());
    }
    if bytes.len() > MAX_CONNECTOR_AUTHORITY_STATE_BYTES_V2 {
        return Err(KernelConnectorAuthorityErrorV2::LimitExceeded);
    }
    let mut decoder = minicbor::Decoder::new(bytes);
    require_array(&mut decoder, 4)?;
    if decoder
        .u16()
        .map_err(|_| KernelConnectorAuthorityErrorV2::BindingMismatch)?
        != AUTHORITY_STATE_SCHEMA_V2
    {
        return Err(KernelConnectorAuthorityErrorV2::BindingMismatch);
    }
    let sign_count = decoder
        .u64()
        .map_err(|_| KernelConnectorAuthorityErrorV2::BindingMismatch)?;
    let add_count = bounded_array(&mut decoder)?;
    let mut adds = Vec::new();
    adds.try_reserve_exact(add_count)
        .map_err(|_| KernelConnectorAuthorityErrorV2::Unavailable)?;
    for _ in 0..add_count {
        adds.push(decode_add_record(&mut decoder)?);
    }
    let remove_count = bounded_array(&mut decoder)?;
    if add_count.saturating_add(remove_count) > MAX_AUTHORITY_RECORDS_V2 {
        return Err(KernelConnectorAuthorityErrorV2::LimitExceeded);
    }
    let mut removes = Vec::new();
    removes
        .try_reserve_exact(remove_count)
        .map_err(|_| KernelConnectorAuthorityErrorV2::Unavailable)?;
    for _ in 0..remove_count {
        removes.push(decode_remove_record(&mut decoder)?);
    }
    let state = ConnectorAuthorityStateV2 {
        adds,
        removes,
        sign_count,
    };
    if decoder.position() != bytes.len() || encode_authority_state(&state)? != bytes {
        return Err(KernelConnectorAuthorityErrorV2::BindingMismatch);
    }
    Ok(state)
}

fn decode_add_record(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<ConnectorAddRecordV2, KernelConnectorAuthorityErrorV2> {
    require_array(decoder, ADD_RECORD_FIELDS_V2)?;
    let pending = decode_typed(decoder)?;
    let pending_commitment = decode_typed(decoder)?;
    let source_authorization_commitment = decode_typed(decoder)?;
    let proposal_identity_digest = decode_typed(decoder)?;
    let active_state_manifest_digest = decode_typed(decoder)?;
    let deployment_generation = decoder
        .u64()
        .map_err(|_| KernelConnectorAuthorityErrorV2::BindingMismatch)?;
    let details = if decoder
        .datatype()
        .map_err(|_| KernelConnectorAuthorityErrorV2::BindingMismatch)?
        == Type::Null
    {
        decoder
            .null()
            .map_err(|_| KernelConnectorAuthorityErrorV2::BindingMismatch)?;
        None
    } else {
        Some(decode_add_details(decoder)?)
    };
    let status = decode_add_status(decoder)?;
    decoder
        .null()
        .map_err(|_| KernelConnectorAuthorityErrorV2::BindingMismatch)?;
    Ok(ConnectorAddRecordV2 {
        pending,
        pending_commitment,
        source_authorization_commitment,
        proposal_identity_digest,
        active_state_manifest_digest,
        deployment_generation,
        details,
        status,
    })
}

fn decode_add_details(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<ConnectorAddDetailsV2, KernelConnectorAuthorityErrorV2> {
    require_array(decoder, ADD_DETAILS_FIELDS_V2)?;
    let session = decode_session(decoder)?;
    let caller_identity = decode_typed(decoder)?;
    let canonical_descriptor = decoder
        .bytes()
        .map_err(|_| KernelConnectorAuthorityErrorV2::BindingMismatch)?
        .to_vec();
    let descriptor_digest = decode_typed(decoder)?;
    let previous_head_digest = decode_typed(decoder)?;
    let envelope = decode_signed_approval_envelope_v2(
        decoder
            .bytes()
            .map_err(|_| KernelConnectorAuthorityErrorV2::BindingMismatch)?,
    )?;
    let display_authentication = decode_signed_ui_authentication_envelope_v2(
        decoder
            .bytes()
            .map_err(|_| KernelConnectorAuthorityErrorV2::BindingMismatch)?,
    )?;
    let envelope_digest = decode_typed(decoder)?;
    let decision_challenge = decode_typed(decoder)?;
    decoder
        .null()
        .map_err(|_| KernelConnectorAuthorityErrorV2::BindingMismatch)?;
    Ok(ConnectorAddDetailsV2 {
        session,
        caller_identity,
        canonical_descriptor,
        descriptor_digest,
        previous_head_digest,
        envelope,
        display_authentication,
        envelope_digest,
        decision_challenge,
    })
}

fn decode_add_status(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<ConnectorAddStatusV2, KernelConnectorAuthorityErrorV2> {
    let length = decoder
        .array()
        .map_err(|_| KernelConnectorAuthorityErrorV2::BindingMismatch)?
        .ok_or(KernelConnectorAuthorityErrorV2::BindingMismatch)?;
    let tag = decoder
        .u16()
        .map_err(|_| KernelConnectorAuthorityErrorV2::BindingMismatch)?;
    match (tag, length) {
        (0, 1) => Ok(ConnectorAddStatusV2::Pending),
        (1, 6) => {
            let approved = decode_typed(decoder)?;
            let approved_commitment = decode_typed(decoder)?;
            let settlement_bytes = decode_settlement_bytes(decoder)?;
            let settlement_digest = decode_typed(decoder)?;
            let settlement_issued_at = decode_typed(decoder)?;
            Ok(ConnectorAddStatusV2::Approved {
                approved,
                approved_commitment,
                settlement_bytes,
                settlement_digest,
                settlement_issued_at,
            })
        }
        (2, 2) => {
            let settlement_digest = decode_typed(decoder)?;
            Ok(ConnectorAddStatusV2::Denied { settlement_digest })
        }
        (3, 5) => {
            let approved = decode_typed(decoder)?;
            let approved_commitment = decode_typed(decoder)?;
            let settlement_digest = decode_typed(decoder)?;
            let result = decode_mutation_summary(decoder)?;
            Ok(ConnectorAddStatusV2::Committed {
                approved,
                approved_commitment,
                settlement_digest,
                result,
            })
        }
        (4, 1) => Ok(ConnectorAddStatusV2::Expired),
        _ => Err(KernelConnectorAuthorityErrorV2::BindingMismatch),
    }
}

fn decode_remove_record(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<ConnectorRemoveRecordV2, KernelConnectorAuthorityErrorV2> {
    require_array(decoder, REMOVE_RECORD_FIELDS_V2)?;
    let authorization = decode_typed(decoder)?;
    let authorization_commitment = decode_typed(decoder)?;
    let session = decode_typed(decoder)?;
    let connector_id = decode_typed(decoder)?;
    let active_state_manifest_digest = decode_typed(decoder)?;
    let deployment_generation = decoder
        .u64()
        .map_err(|_| KernelConnectorAuthorityErrorV2::BindingMismatch)?;
    let details = if decoder
        .datatype()
        .map_err(|_| KernelConnectorAuthorityErrorV2::BindingMismatch)?
        == Type::Null
    {
        decoder
            .null()
            .map_err(|_| KernelConnectorAuthorityErrorV2::BindingMismatch)?;
        None
    } else {
        require_array(decoder, REMOVE_DETAILS_FIELDS_V2)?;
        Some(ConnectorRemoveDetailsV2 {
            session: decode_session(decoder)?,
            previous_head_digest: decode_typed(decoder)?,
            issued_at: decode_typed(decoder)?,
        })
    };
    let status_length = decoder
        .array()
        .map_err(|_| KernelConnectorAuthorityErrorV2::BindingMismatch)?
        .ok_or(KernelConnectorAuthorityErrorV2::BindingMismatch)?;
    let status_tag = decoder
        .u16()
        .map_err(|_| KernelConnectorAuthorityErrorV2::BindingMismatch)?;
    let status = match (status_tag, status_length) {
        (0, 1) => ConnectorRemoveStatusV2::Pending,
        (1, 2) => ConnectorRemoveStatusV2::Committed(decode_mutation_summary(decoder)?),
        (2, 1) => ConnectorRemoveStatusV2::Expired,
        _ => return Err(KernelConnectorAuthorityErrorV2::BindingMismatch),
    };
    Ok(ConnectorRemoveRecordV2 {
        authorization,
        authorization_commitment,
        session,
        connector_id,
        active_state_manifest_digest,
        deployment_generation,
        details,
        status,
    })
}

fn decode_session(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<ConnectorUiSessionContextV2, KernelConnectorAuthorityErrorV2> {
    require_array(decoder, SESSION_FIELDS_V2)?;
    ConnectorUiSessionContextV2::from_durable_connector_state(
        decode_typed(decoder)?,
        decode_typed(decoder)?,
        decode_typed(decoder)?,
        decode_typed(decoder)?,
        decode_typed(decoder)?,
        decode_typed(decoder)?,
        decoder
            .u64()
            .map_err(|_| KernelConnectorAuthorityErrorV2::BindingMismatch)?,
        decode_typed(decoder)?,
        decode_typed(decoder)?,
    )
    .map_err(Into::into)
}

fn decode_mutation_summary(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<ConnectorRegistryMutationSummaryV2, KernelConnectorAuthorityErrorV2> {
    require_array(decoder, MUTATION_SUMMARY_FIELDS_V2)?;
    let sequence = decoder
        .u64()
        .map_err(|_| KernelConnectorAuthorityErrorV2::BindingMismatch)?;
    let connector_id = decode_typed(decoder)?;
    let add = decoder
        .bool()
        .map_err(|_| KernelConnectorAuthorityErrorV2::BindingMismatch)?;
    decoder
        .null()
        .map_err(|_| KernelConnectorAuthorityErrorV2::BindingMismatch)?;
    if sequence == 0 || connector_id == Digest32V2::new([0; 32]) {
        return Err(KernelConnectorAuthorityErrorV2::BindingMismatch);
    }
    Ok(ConnectorRegistryMutationSummaryV2 {
        sequence,
        connector_id,
        add,
    })
}

fn decode_settlement_bytes(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<Vec<u8>, KernelConnectorAuthorityErrorV2> {
    let bytes = decoder
        .bytes()
        .map_err(|_| KernelConnectorAuthorityErrorV2::BindingMismatch)?;
    let settlement = decode_signed_approval_settlement_v2(bytes)?;
    if encode_signed_approval_settlement_v2(&settlement)? != bytes {
        return Err(KernelConnectorAuthorityErrorV2::BindingMismatch);
    }
    Ok(bytes.to_vec())
}

fn encode_typed<T: minicbor::Encode<()>>(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    value: &T,
) -> Result<(), KernelConnectorAuthorityErrorV2> {
    minicbor::Encode::encode(value, encoder, &mut ())
        .map_err(|_| KernelConnectorAuthorityErrorV2::Unavailable)
}

fn handle_bytes<T: minicbor::Encode<()>>(
    value: &T,
) -> Result<Vec<u8>, KernelConnectorAuthorityErrorV2> {
    minicbor::to_vec(value).map_err(|_| KernelConnectorAuthorityErrorV2::BindingMismatch)
}

fn decode_typed<'bytes, T>(
    decoder: &mut minicbor::Decoder<'bytes>,
) -> Result<T, KernelConnectorAuthorityErrorV2>
where
    T: minicbor::Decode<'bytes, V2DecodeContext>,
{
    minicbor::Decode::decode(decoder, &mut V2DecodeContext)
        .map_err(|_| KernelConnectorAuthorityErrorV2::BindingMismatch)
}

fn require_array(
    decoder: &mut minicbor::Decoder<'_>,
    expected: u64,
) -> Result<(), KernelConnectorAuthorityErrorV2> {
    if decoder
        .array()
        .map_err(|_| KernelConnectorAuthorityErrorV2::BindingMismatch)?
        != Some(expected)
    {
        return Err(KernelConnectorAuthorityErrorV2::BindingMismatch);
    }
    Ok(())
}

fn bounded_array(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<usize, KernelConnectorAuthorityErrorV2> {
    let value = decoder
        .array()
        .map_err(|_| KernelConnectorAuthorityErrorV2::BindingMismatch)?
        .ok_or(KernelConnectorAuthorityErrorV2::BindingMismatch)?;
    let value =
        usize::try_from(value).map_err(|_| KernelConnectorAuthorityErrorV2::LimitExceeded)?;
    if value > MAX_AUTHORITY_RECORDS_V2 {
        return Err(KernelConnectorAuthorityErrorV2::LimitExceeded);
    }
    Ok(value)
}

fn mint_handle<T>(
    constructor: impl Fn([u8; 32]) -> Option<T>,
) -> Result<T, KernelConnectorAuthorityErrorV2> {
    for _ in 0..8 {
        let mut bytes = [0_u8; 32];
        getrandom::getrandom(&mut bytes)
            .map_err(|_| KernelConnectorAuthorityErrorV2::Unavailable)?;
        if let Some(handle) = constructor(bytes) {
            return Ok(handle);
        }
    }
    Err(KernelConnectorAuthorityErrorV2::Unavailable)
}
