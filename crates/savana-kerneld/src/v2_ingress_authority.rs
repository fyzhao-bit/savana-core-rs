use ed25519_dalek::SigningKey;
use getrandom::getrandom;
use savana_kernel_protocol::v2::{
    approval_display_digest_v2, derive_ed25519_key_id_v2, ApprovalBindingV2, ApprovalDecisionV2,
    ApprovalPurposeV2, AuthorityHandleKeyV2, BoundedApprovalDisplayTextV2, Digest32V2,
    DurableTaskIdV2, Ed25519KeyIdV2, IngressKernelApprovalHandleV2,
    IngressUiAuthenticationPreparationHandleV2, IngressUiAuthorizationHandleV2,
    KernelIngressBootstrapTransferCapabilityV2, Nonce32V2, PendingIngressHandleV2, PrincipalIdV2,
    ServiceIdentityV2, SignedApprovalEnvelopeV2, SignedApprovalSettlementV2,
    SignedUiAuthenticationEnvelopeV2, SignedUiAuthenticationSettlementV2,
    UiAuthenticationBindingV2, UiAuthenticationPurposeV2, UnixMillisV2, UnsignedApprovalEnvelopeV2,
    UnsignedUiAuthenticationEnvelopeV2,
};
use sha2::{Digest as _, Sha256};

use crate::v2_input_owner::{
    FinalizedKernelInputV2, KernelInputErrorV2, KernelVerifiedUiAuthorizationV2,
};

const UI_AUTH_TTL_MS: u64 = 5 * 60 * 1_000;
const APPROVAL_TTL_MS: u64 = 5 * 60 * 1_000;
const PENDING_TASK_DOMAIN: &[u8] = b"SAVANA_PENDING_TASK_DIGEST_V2\0";
const INGRESS_SUBJECT_DOMAIN: &[u8] = b"SAVANA_INGRESS_SUBJECT_V2\0";
const CHANNEL_COMMITMENTS_DOMAIN: &[u8] = b"SAVANA_INPUT_CHANNEL_COMMITMENTS_V2\0";
const DISPLAY_PROJECTION_DOMAIN: &[u8] = b"SAVANA_INGRESS_DISPLAY_PROJECTION_V2\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KernelIngressAuthorityErrorV2 {
    InvalidReference,
    AlreadyConsumed,
    BindingMismatch,
    Expired,
    LimitExceeded,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KernelPendingIngressStateV2 {
    AwaitingApproval,
    Approved,
    Denied,
}

pub(crate) struct KernelIngressSecurityConfigV2 {
    installation_id: Digest32V2,
    ingressd_identity: ServiceIdentityV2,
    approvald_identity: ServiceIdentityV2,
    envelope_signing_key: SigningKey,
    ui_settlement_key_id: Ed25519KeyIdV2,
    ui_settlement_public_key: [u8; 32],
    ingress_settlement_key_id: Ed25519KeyIdV2,
    ingress_settlement_public_key: [u8; 32],
}

impl std::fmt::Debug for KernelIngressSecurityConfigV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("KernelIngressSecurityConfigV2(<redacted>)")
    }
}

impl KernelIngressSecurityConfigV2 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        installation_id: Digest32V2,
        ingressd_identity: ServiceIdentityV2,
        approvald_identity: ServiceIdentityV2,
        envelope_signing_key: SigningKey,
        ui_settlement_key_id: Ed25519KeyIdV2,
        ui_settlement_public_key: [u8; 32],
        ingress_settlement_key_id: Ed25519KeyIdV2,
        ingress_settlement_public_key: [u8; 32],
    ) -> Result<Self, KernelIngressAuthorityErrorV2> {
        if is_zero(installation_id.as_bytes())
            || is_zero(ingressd_identity.as_bytes())
            || is_zero(approvald_identity.as_bytes())
            || derive_ed25519_key_id_v2(ui_settlement_public_key) != ui_settlement_key_id
            || derive_ed25519_key_id_v2(ingress_settlement_public_key) != ingress_settlement_key_id
        {
            return Err(KernelIngressAuthorityErrorV2::BindingMismatch);
        }
        Ok(Self {
            installation_id,
            ingressd_identity,
            approvald_identity,
            envelope_signing_key,
            ui_settlement_key_id,
            ui_settlement_public_key,
            ingress_settlement_key_id,
            ingress_settlement_public_key,
        })
    }
}

struct BootstrapRecordV2 {
    transfer_commitment: Digest32V2,
    durable_task_id: DurableTaskIdV2,
    pending_task_digest: Digest32V2,
    expected_principal: Option<PrincipalIdV2>,
    expires_at: UnixMillisV2,
    consumed: bool,
}

struct UiPreparationRecordV2 {
    preparation_commitment: Digest32V2,
    durable_task_id: DurableTaskIdV2,
    envelope_digest: Digest32V2,
    binding_digest: Digest32V2,
    challenge: Nonce32V2,
    expected_principal: Option<PrincipalIdV2>,
    expires_at: UnixMillisV2,
    consumed: bool,
}

struct PendingIngressRecordV2 {
    pending_commitment: Digest32V2,
    approval_commitment: Digest32V2,
    durable_task_id: DurableTaskIdV2,
    expected_principal: PrincipalIdV2,
    approval_envelope_digest: Digest32V2,
    decision_challenge: Nonce32V2,
    expires_at: UnixMillisV2,
    state: KernelPendingIngressStateV2,
    finalized: Option<FinalizedKernelInputV2>,
}

pub(crate) struct PreparedIngressUiAuthenticationV2 {
    pub(crate) preparation: IngressUiAuthenticationPreparationHandleV2,
    pub(crate) envelope: SignedUiAuthenticationEnvelopeV2,
}

pub(crate) struct AuthenticatedIngressUiV2 {
    pub(crate) authorization: IngressUiAuthorizationHandleV2,
    pub(crate) evidence: KernelVerifiedUiAuthorizationV2,
}

pub(crate) struct PreparedPendingIngressV2 {
    pub(crate) pending: PendingIngressHandleV2,
    pub(crate) approval: IngressKernelApprovalHandleV2,
    pub(crate) envelope: SignedApprovalEnvelopeV2,
    pub(crate) display_authentication: SignedUiAuthenticationEnvelopeV2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VerifiedIngressSettlementDecisionV2 {
    Denied,
    Approved {
        record_index: usize,
        durable_task_id: DurableTaskIdV2,
        principal: PrincipalIdV2,
    },
}

pub(crate) struct KernelIngressAuthorityV2 {
    config: KernelIngressSecurityConfigV2,
    handle_key: AuthorityHandleKeyV2,
    maximum_records: usize,
    bootstraps: Vec<BootstrapRecordV2>,
    preparations: Vec<UiPreparationRecordV2>,
    pending: Vec<PendingIngressRecordV2>,
}

impl std::fmt::Debug for KernelIngressAuthorityV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("KernelIngressAuthorityV2")
            .field("bootstrap_count", &self.bootstraps.len())
            .field("preparation_count", &self.preparations.len())
            .field("pending_count", &self.pending.len())
            .finish_non_exhaustive()
    }
}

impl KernelIngressAuthorityV2 {
    pub(crate) fn new(
        config: KernelIngressSecurityConfigV2,
        maximum_records: usize,
    ) -> Result<Self, KernelIngressAuthorityErrorV2> {
        if maximum_records == 0 || maximum_records > 65_536 {
            return Err(KernelIngressAuthorityErrorV2::LimitExceeded);
        }
        let handle_key = AuthorityHandleKeyV2::from_entropy(random_bytes()?)
            .ok_or(KernelIngressAuthorityErrorV2::Unavailable)?;
        Ok(Self {
            config,
            handle_key,
            maximum_records,
            bootstraps: Vec::new(),
            preparations: Vec::new(),
            pending: Vec::new(),
        })
    }

    pub(crate) fn mint_new_task_bootstrap(
        &mut self,
        agent_task_nonce: Nonce32V2,
        expected_principal: Option<PrincipalIdV2>,
        now: UnixMillisV2,
        expires_at: UnixMillisV2,
    ) -> Result<
        (DurableTaskIdV2, KernelIngressBootstrapTransferCapabilityV2),
        KernelIngressAuthorityErrorV2,
    > {
        if self.bootstraps.len() >= self.maximum_records
            || is_zero(agent_task_nonce.as_bytes())
            || expected_principal.is_some_and(|principal| is_zero(principal.as_bytes()))
            || now.get() == 0
            || now.get() >= expires_at.get()
        {
            return Err(KernelIngressAuthorityErrorV2::LimitExceeded);
        }
        let durable_task_id = DurableTaskIdV2::new(random_bytes()?);
        let transfer = mint_handle(
            &self.handle_key,
            &self.bootstraps,
            |record| record.transfer_commitment,
            KernelIngressBootstrapTransferCapabilityV2::from_authority_entropy,
        )?;
        let transfer_commitment = transfer.authority_commitment(&self.handle_key);
        let pending_task_digest = hash_many(
            PENDING_TASK_DOMAIN,
            &[
                durable_task_id.as_bytes(),
                agent_task_nonce.as_bytes(),
                transfer_commitment.as_bytes(),
            ],
        );
        self.bootstraps
            .try_reserve(1)
            .map_err(|_| KernelIngressAuthorityErrorV2::Unavailable)?;
        self.bootstraps.push(BootstrapRecordV2 {
            transfer_commitment,
            durable_task_id,
            pending_task_digest,
            expected_principal,
            expires_at,
            consumed: false,
        });
        Ok((durable_task_id, transfer))
    }

    pub(crate) fn prepare_ui_authentication(
        &mut self,
        transfer: KernelIngressBootstrapTransferCapabilityV2,
        caller_identity: ServiceIdentityV2,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
        now: UnixMillisV2,
    ) -> Result<PreparedIngressUiAuthenticationV2, KernelIngressAuthorityErrorV2> {
        if caller_identity != self.config.ingressd_identity {
            return Err(KernelIngressAuthorityErrorV2::BindingMismatch);
        }
        let transfer_commitment = transfer.authority_commitment(&self.handle_key);
        let bootstrap_index = self
            .bootstraps
            .iter()
            .position(|record| record.transfer_commitment == transfer_commitment)
            .ok_or(KernelIngressAuthorityErrorV2::InvalidReference)?;
        let bootstrap = &self.bootstraps[bootstrap_index];
        if bootstrap.consumed {
            return Err(KernelIngressAuthorityErrorV2::AlreadyConsumed);
        }
        if now.get() >= bootstrap.expires_at.get() {
            return Err(KernelIngressAuthorityErrorV2::Expired);
        }
        let binding = UiAuthenticationBindingV2::IngressNewTask {
            durable_task_id: bootstrap.durable_task_id,
            pending_task_digest: bootstrap.pending_task_digest,
            ingressd_identity: self.config.ingressd_identity,
        };
        let expires_at = bounded_expiry(now, UI_AUTH_TTL_MS, bootstrap.expires_at)?;
        let unsigned = UnsignedUiAuthenticationEnvelopeV2::new(
            self.config.installation_id,
            active_state_manifest_digest,
            deployment_generation,
            UiAuthenticationPurposeV2::IngressInput,
            binding,
            bootstrap.expected_principal,
            savana_kernel_protocol::v2::FixedOriginV2::Approval8766,
            savana_kernel_protocol::v2::FixedOriginV2::Ingress8767,
            Nonce32V2::new(random_bytes()?),
            now,
            expires_at,
        )
        .map_err(|_| KernelIngressAuthorityErrorV2::BindingMismatch)?;
        let binding_digest = unsigned
            .binding_digest()
            .map_err(|_| KernelIngressAuthorityErrorV2::BindingMismatch)?;
        let envelope =
            SignedUiAuthenticationEnvelopeV2::sign(unsigned, &self.config.envelope_signing_key)
                .map_err(|_| KernelIngressAuthorityErrorV2::Unavailable)?;
        let envelope_digest = envelope
            .envelope_digest()
            .map_err(|_| KernelIngressAuthorityErrorV2::Unavailable)?;
        let preparation = mint_handle(
            &self.handle_key,
            &self.preparations,
            |record| record.preparation_commitment,
            IngressUiAuthenticationPreparationHandleV2::from_authority_entropy,
        )?;
        let preparation_commitment = preparation.authority_commitment(&self.handle_key);
        self.preparations
            .try_reserve(1)
            .map_err(|_| KernelIngressAuthorityErrorV2::Unavailable)?;
        self.preparations.push(UiPreparationRecordV2 {
            preparation_commitment,
            durable_task_id: bootstrap.durable_task_id,
            envelope_digest,
            binding_digest,
            challenge: unsigned.envelope_nonce(),
            expected_principal: bootstrap.expected_principal,
            expires_at,
            consumed: false,
        });
        self.bootstraps[bootstrap_index].consumed = true;
        Ok(PreparedIngressUiAuthenticationV2 {
            preparation,
            envelope,
        })
    }

    pub(crate) fn authenticate_ui(
        &mut self,
        preparation: IngressUiAuthenticationPreparationHandleV2,
        settlement: &SignedUiAuthenticationSettlementV2,
        caller_identity: ServiceIdentityV2,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
        now: UnixMillisV2,
    ) -> Result<AuthenticatedIngressUiV2, KernelIngressAuthorityErrorV2> {
        if caller_identity != self.config.ingressd_identity {
            return Err(KernelIngressAuthorityErrorV2::BindingMismatch);
        }
        let commitment = preparation.authority_commitment(&self.handle_key);
        let index = self
            .preparations
            .iter()
            .position(|record| record.preparation_commitment == commitment)
            .ok_or(KernelIngressAuthorityErrorV2::InvalidReference)?;
        let record = &self.preparations[index];
        if record.consumed {
            return Err(KernelIngressAuthorityErrorV2::AlreadyConsumed);
        }
        if now.get() >= record.expires_at.get() {
            return Err(KernelIngressAuthorityErrorV2::Expired);
        }
        let verified = settlement
            .verify_ingress_input(
                self.config.ui_settlement_key_id,
                self.config.ui_settlement_public_key,
                self.config.installation_id,
                active_state_manifest_digest,
                deployment_generation,
                now,
            )
            .map_err(|_| KernelIngressAuthorityErrorV2::BindingMismatch)?;
        if verified.envelope_digest() != record.envelope_digest
            || verified.binding_digest() != record.binding_digest
            || verified.challenge() != record.challenge
            || record
                .expected_principal
                .is_some_and(|principal| principal != verified.authenticated_principal())
        {
            return Err(KernelIngressAuthorityErrorV2::BindingMismatch);
        }
        let authorization =
            mint_untracked_handle(IngressUiAuthorizationHandleV2::from_authority_entropy)?;
        let evidence = KernelVerifiedUiAuthorizationV2::from_bound_verified_settlement(
            record.durable_task_id,
            verified,
        )
        .map_err(map_input_error)?;
        self.preparations[index].consumed = true;
        Ok(AuthenticatedIngressUiV2 {
            authorization,
            evidence,
        })
    }

    pub(crate) fn prepare_pending_approval(
        &mut self,
        finalized: FinalizedKernelInputV2,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
        now: UnixMillisV2,
    ) -> Result<PreparedPendingIngressV2, KernelIngressAuthorityErrorV2> {
        if self.pending.len() >= self.maximum_records {
            return Err(KernelIngressAuthorityErrorV2::LimitExceeded);
        }
        let authorization = finalized.authorization();
        let durable_task_id = authorization
            .durable_task_id()
            .ok_or(KernelIngressAuthorityErrorV2::BindingMismatch)?;
        if authorization.installation_id() != self.config.installation_id
            || authorization.active_state_manifest_digest() != active_state_manifest_digest
            || authorization.deployment_generation() != deployment_generation
            || now.get() >= authorization.expires_at().get()
        {
            return Err(KernelIngressAuthorityErrorV2::BindingMismatch);
        }
        let pending = mint_handle(
            &self.handle_key,
            &self.pending,
            |record| record.pending_commitment,
            PendingIngressHandleV2::from_authority_entropy,
        )?;
        let approval = mint_handle(
            &self.handle_key,
            &self.pending,
            |record| record.approval_commitment,
            IngressKernelApprovalHandleV2::from_authority_entropy,
        )?;
        let pending_commitment = pending.authority_commitment(&self.handle_key);
        let approval_commitment = approval.authority_commitment(&self.handle_key);
        let principal = authorization.authenticated_principal();
        let ingress_subject_digest = hash_many(
            INGRESS_SUBJECT_DOMAIN,
            &[
                durable_task_id.as_bytes(),
                finalized.input_commitment().as_bytes(),
                principal.as_bytes(),
            ],
        );
        let channel_commitments_digest = finalized_channel_commitments_digest(&finalized);
        let binding = ApprovalBindingV2::Ingress {
            pending_ingress_id: pending_commitment,
            ingress_subject_digest,
            channel_commitments_digest,
            source_provenance_digest: finalized.source_provenance_digest(),
        };
        let display_projection_digest = hash_many(
            DISPLAY_PROJECTION_DOMAIN,
            &[
                ingress_subject_digest.as_bytes(),
                channel_commitments_digest.as_bytes(),
                finalized.source_provenance_digest().as_bytes(),
            ],
        );
        let mut display_encoder = minicbor::Encoder::new(Vec::new());
        display_encoder
            .array(3)
            .and_then(|encoder| encoder.bytes(display_projection_digest.as_bytes()))
            .and_then(|encoder| encoder.bytes(principal.as_bytes()))
            .and_then(|encoder| encoder.bytes(durable_task_id.as_bytes()))
            .map_err(|_| KernelIngressAuthorityErrorV2::Unavailable)?;
        let display_text =
            BoundedApprovalDisplayTextV2::from_binary(&display_encoder.into_writer())
                .map_err(|_| KernelIngressAuthorityErrorV2::BindingMismatch)?;
        let display_digest = approval_display_digest_v2(display_text.as_bytes());
        let decision_challenge = Nonce32V2::new(random_bytes()?);
        let expires_at = bounded_expiry(now, APPROVAL_TTL_MS, authorization.expires_at())?;
        let approval_unsigned = UnsignedApprovalEnvelopeV2::new(
            self.config.installation_id,
            active_state_manifest_digest,
            deployment_generation,
            ApprovalPurposeV2::Ingress,
            Nonce32V2::new(random_bytes()?),
            decision_challenge,
            binding,
            principal,
            display_projection_digest,
            display_digest,
            display_text,
            None,
            self.config.approvald_identity,
            now,
            expires_at,
        )
        .map_err(|_| KernelIngressAuthorityErrorV2::BindingMismatch)?;
        let envelope =
            SignedApprovalEnvelopeV2::sign(approval_unsigned, &self.config.envelope_signing_key)
                .map_err(|_| KernelIngressAuthorityErrorV2::Unavailable)?;
        let approval_envelope_digest = envelope
            .envelope_digest()
            .map_err(|_| KernelIngressAuthorityErrorV2::Unavailable)?;
        let display_unsigned = UnsignedUiAuthenticationEnvelopeV2::new(
            self.config.installation_id,
            active_state_manifest_digest,
            deployment_generation,
            UiAuthenticationPurposeV2::ApprovalDisplay,
            UiAuthenticationBindingV2::ApprovalDisplay {
                durable_task_id,
                approval_envelope_digest,
                approval_purpose: ApprovalPurposeV2::Ingress,
                display_digest,
            },
            Some(principal),
            savana_kernel_protocol::v2::FixedOriginV2::Approval8766,
            savana_kernel_protocol::v2::FixedOriginV2::Approval8766,
            Nonce32V2::new(random_bytes()?),
            now,
            expires_at,
        )
        .map_err(|_| KernelIngressAuthorityErrorV2::BindingMismatch)?;
        let display_authentication = SignedUiAuthenticationEnvelopeV2::sign(
            display_unsigned,
            &self.config.envelope_signing_key,
        )
        .map_err(|_| KernelIngressAuthorityErrorV2::Unavailable)?;
        self.pending
            .try_reserve(1)
            .map_err(|_| KernelIngressAuthorityErrorV2::Unavailable)?;
        self.pending.push(PendingIngressRecordV2 {
            pending_commitment,
            approval_commitment,
            durable_task_id,
            expected_principal: principal,
            approval_envelope_digest,
            decision_challenge,
            expires_at,
            state: KernelPendingIngressStateV2::AwaitingApproval,
            finalized: Some(finalized),
        });
        Ok(PreparedPendingIngressV2 {
            pending,
            approval,
            envelope,
            display_authentication,
        })
    }

    pub(crate) fn verify_settlement(
        &self,
        pending: PendingIngressHandleV2,
        approval: IngressKernelApprovalHandleV2,
        settlement: &SignedApprovalSettlementV2,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
        now: UnixMillisV2,
    ) -> Result<VerifiedIngressSettlementDecisionV2, KernelIngressAuthorityErrorV2> {
        let pending_commitment = pending.authority_commitment(&self.handle_key);
        let approval_commitment = approval.authority_commitment(&self.handle_key);
        let index = self
            .pending
            .iter()
            .position(|record| {
                record.pending_commitment == pending_commitment
                    && record.approval_commitment == approval_commitment
            })
            .ok_or(KernelIngressAuthorityErrorV2::InvalidReference)?;
        let record = &self.pending[index];
        if record.state != KernelPendingIngressStateV2::AwaitingApproval {
            return Err(KernelIngressAuthorityErrorV2::AlreadyConsumed);
        }
        if now.get() >= record.expires_at.get() {
            return Err(KernelIngressAuthorityErrorV2::Expired);
        }
        let verified = settlement
            .verify_ingress(
                self.config.ingress_settlement_key_id,
                self.config.ingress_settlement_public_key,
                self.config.installation_id,
                active_state_manifest_digest,
                deployment_generation,
                record.approval_envelope_digest,
                record.expected_principal,
                record.decision_challenge,
                now,
            )
            .map_err(|_| KernelIngressAuthorityErrorV2::BindingMismatch)?;
        let durable_task_id = record.durable_task_id;
        let expected_principal = record.expected_principal;
        match verified.decision() {
            ApprovalDecisionV2::Deny => Ok(VerifiedIngressSettlementDecisionV2::Denied),
            ApprovalDecisionV2::Approve => Ok(VerifiedIngressSettlementDecisionV2::Approved {
                record_index: index,
                durable_task_id,
                principal: expected_principal,
            }),
        }
    }

    pub(crate) fn finalized_for_verified_approval(
        &self,
        record_index: usize,
    ) -> Result<&FinalizedKernelInputV2, KernelIngressAuthorityErrorV2> {
        let record = self
            .pending
            .get(record_index)
            .ok_or(KernelIngressAuthorityErrorV2::InvalidReference)?;
        if record.state != KernelPendingIngressStateV2::AwaitingApproval {
            return Err(KernelIngressAuthorityErrorV2::AlreadyConsumed);
        }
        record
            .finalized
            .as_ref()
            .ok_or(KernelIngressAuthorityErrorV2::AlreadyConsumed)
    }

    pub(crate) fn finish_verified_settlement(
        &mut self,
        decision: VerifiedIngressSettlementDecisionV2,
    ) -> Result<KernelPendingIngressStateV2, KernelIngressAuthorityErrorV2> {
        match decision {
            VerifiedIngressSettlementDecisionV2::Denied => {
                // A denial is completed by the caller through
                // `finish_verified_denial`, which also proves the exact
                // pending handle again. This branch is intentionally not
                // sufficient to select a record.
                Err(KernelIngressAuthorityErrorV2::InvalidReference)
            }
            VerifiedIngressSettlementDecisionV2::Approved { record_index, .. } => {
                let record = self
                    .pending
                    .get_mut(record_index)
                    .ok_or(KernelIngressAuthorityErrorV2::InvalidReference)?;
                if record.state != KernelPendingIngressStateV2::AwaitingApproval
                    || record.finalized.take().is_none()
                {
                    return Err(KernelIngressAuthorityErrorV2::AlreadyConsumed);
                }
                record.state = KernelPendingIngressStateV2::Approved;
                Ok(record.state)
            }
        }
    }

    pub(crate) fn finish_verified_denial(
        &mut self,
        pending: PendingIngressHandleV2,
        approval: IngressKernelApprovalHandleV2,
    ) -> Result<KernelPendingIngressStateV2, KernelIngressAuthorityErrorV2> {
        let pending_commitment = pending.authority_commitment(&self.handle_key);
        let approval_commitment = approval.authority_commitment(&self.handle_key);
        let record = self
            .pending
            .iter_mut()
            .find(|record| {
                record.pending_commitment == pending_commitment
                    && record.approval_commitment == approval_commitment
            })
            .ok_or(KernelIngressAuthorityErrorV2::InvalidReference)?;
        if record.state != KernelPendingIngressStateV2::AwaitingApproval {
            return Err(KernelIngressAuthorityErrorV2::AlreadyConsumed);
        }
        record.finalized = None;
        record.state = KernelPendingIngressStateV2::Denied;
        Ok(record.state)
    }

    pub(crate) fn pending_status(
        &self,
        pending: PendingIngressHandleV2,
    ) -> Result<KernelPendingIngressStateV2, KernelIngressAuthorityErrorV2> {
        let commitment = pending.authority_commitment(&self.handle_key);
        self.pending
            .iter()
            .find(|record| record.pending_commitment == commitment)
            .map(|record| record.state)
            .ok_or(KernelIngressAuthorityErrorV2::InvalidReference)
    }
}

fn finalized_channel_commitments_digest(finalized: &FinalizedKernelInputV2) -> Digest32V2 {
    let mut hasher = Sha256::new();
    hasher.update(CHANNEL_COMMITMENTS_DOMAIN);
    for channel in finalized.channels() {
        hasher.update(channel.channel().tag().to_be_bytes());
        hasher.update((channel.bytes().len() as u64).to_be_bytes());
        hasher.update(Sha256::digest(channel.bytes()));
    }
    Digest32V2::new(hasher.finalize().into())
}

fn bounded_expiry(
    now: UnixMillisV2,
    ttl: u64,
    outer: UnixMillisV2,
) -> Result<UnixMillisV2, KernelIngressAuthorityErrorV2> {
    let expiry = now
        .get()
        .checked_add(ttl)
        .ok_or(KernelIngressAuthorityErrorV2::Unavailable)?
        .min(outer.get());
    if now.get() == 0 || expiry <= now.get() {
        return Err(KernelIngressAuthorityErrorV2::Expired);
    }
    Ok(UnixMillisV2::new(expiry))
}

fn mint_untracked_handle<T>(
    constructor: impl Fn([u8; 32]) -> Option<T>,
) -> Result<T, KernelIngressAuthorityErrorV2> {
    for _ in 0..8 {
        if let Some(handle) = constructor(random_bytes()?) {
            return Ok(handle);
        }
    }
    Err(KernelIngressAuthorityErrorV2::Unavailable)
}

fn mint_handle<T, R>(
    key: &AuthorityHandleKeyV2,
    records: &[R],
    commitment: impl Fn(&R) -> Digest32V2,
    constructor: impl Fn([u8; 32]) -> Option<T>,
) -> Result<T, KernelIngressAuthorityErrorV2>
where
    T: Copy + HandleCommitmentV2,
{
    for _ in 0..8 {
        let handle =
            constructor(random_bytes()?).ok_or(KernelIngressAuthorityErrorV2::Unavailable)?;
        let candidate = handle.commitment(key);
        if records.iter().all(|record| commitment(record) != candidate) {
            return Ok(handle);
        }
    }
    Err(KernelIngressAuthorityErrorV2::Unavailable)
}

trait HandleCommitmentV2 {
    fn commitment(self, key: &AuthorityHandleKeyV2) -> Digest32V2;
}

macro_rules! handle_commitment_v2 {
    ($($type:ty),+ $(,)?) => {
        $(
            impl HandleCommitmentV2 for $type {
                fn commitment(self, key: &AuthorityHandleKeyV2) -> Digest32V2 {
                    self.authority_commitment(key)
                }
            }
        )+
    };
}

handle_commitment_v2!(
    KernelIngressBootstrapTransferCapabilityV2,
    IngressUiAuthenticationPreparationHandleV2,
    PendingIngressHandleV2,
    IngressKernelApprovalHandleV2,
);

fn random_bytes() -> Result<[u8; 32], KernelIngressAuthorityErrorV2> {
    let mut bytes = [0_u8; 32];
    getrandom(&mut bytes).map_err(|_| KernelIngressAuthorityErrorV2::Unavailable)?;
    if bytes == [0; 32] {
        return Err(KernelIngressAuthorityErrorV2::Unavailable);
    }
    Ok(bytes)
}

fn hash_many(domain: &[u8], parts: &[&[u8]]) -> Digest32V2 {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    for part in parts {
        hasher.update(part);
    }
    Digest32V2::new(hasher.finalize().into())
}

const fn map_input_error(error: KernelInputErrorV2) -> KernelIngressAuthorityErrorV2 {
    match error {
        KernelInputErrorV2::InvalidReference => KernelIngressAuthorityErrorV2::InvalidReference,
        KernelInputErrorV2::AlreadyConsumed => KernelIngressAuthorityErrorV2::AlreadyConsumed,
        KernelInputErrorV2::LimitExceeded => KernelIngressAuthorityErrorV2::LimitExceeded,
        KernelInputErrorV2::StateConflict
        | KernelInputErrorV2::InvalidSequence
        | KernelInputErrorV2::DigestMismatch
        | KernelInputErrorV2::ProvenanceMismatch => KernelIngressAuthorityErrorV2::BindingMismatch,
        KernelInputErrorV2::Unavailable => KernelIngressAuthorityErrorV2::Unavailable,
    }
}

fn is_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer as _, SigningKey};
    use savana_kernel_protocol::v2::{
        derive_ed25519_key_id_v2, input_channel_step_digest_v2, input_chunk_digest_v2,
        ApprovalDecisionV2, ApprovalPurposeV2, BeginInputRequestV2, ContentKindV2, Digest32V2,
        DirectInputChannelV2, Ed25519SignatureV2, FinalizeInputRequestV2, FixedOriginV2,
        InputChannelCommitmentV2, InputChannelV2, InputSourceKindV2, InputSourceProvenanceV2,
        Nonce32V2, PrincipalIdV2, ServiceIdentityV2, SignedApprovalSettlementV2,
        SignedUiAuthenticationSettlementV2, UiAuthenticationPurposeV2, UnixMillisV2,
        UnsignedApprovalSettlementV2, UnsignedUiAuthenticationSettlementV2, VersionV2,
        ZeroizingBytesV2,
    };
    use sha2::{Digest as _, Sha256};

    use super::{
        KernelIngressAuthorityErrorV2, KernelIngressAuthorityV2, KernelIngressSecurityConfigV2,
        KernelPendingIngressStateV2, VerifiedIngressSettlementDecisionV2,
    };
    use crate::v2_input_owner::KernelInputOwnerV2;

    const UI_SETTLEMENT_DOMAIN: &[u8] = b"SAVANA_UI_AUTH_INGRESS_SETTLEMENT_V2\0";
    const APPROVAL_SETTLEMENT_DOMAIN: &[u8] = b"SAVANA_INGRESS_APPROVAL_SETTLEMENT_V2\0";

    #[test]
    fn ingress_authority_consumes_each_capability_and_binds_both_settlements() {
        let installation = Digest32V2::new([0x11; 32]);
        let manifest = Digest32V2::new([0x12; 32]);
        let ingress_identity = ServiceIdentityV2::new([0x13; 32]);
        let approval_identity = ServiceIdentityV2::new([0x14; 32]);
        let envelope_key = SigningKey::from_bytes(&[0x15; 32]);
        let ui_key = SigningKey::from_bytes(&[0x16; 32]);
        let approval_key = SigningKey::from_bytes(&[0x17; 32]);
        let config = KernelIngressSecurityConfigV2::new(
            installation,
            ingress_identity,
            approval_identity,
            envelope_key.clone(),
            derive_ed25519_key_id_v2(ui_key.verifying_key().to_bytes()),
            ui_key.verifying_key().to_bytes(),
            derive_ed25519_key_id_v2(approval_key.verifying_key().to_bytes()),
            approval_key.verifying_key().to_bytes(),
        )
        .unwrap();
        let mut authority = KernelIngressAuthorityV2::new(config, 8).unwrap();
        let (_, transfer) = authority
            .mint_new_task_bootstrap(
                Nonce32V2::new([0x18; 32]),
                None,
                UnixMillisV2::new(100),
                UnixMillisV2::new(1_000),
            )
            .unwrap();
        let prepared = authority
            .prepare_ui_authentication(
                transfer,
                ingress_identity,
                manifest,
                7,
                UnixMillisV2::new(110),
            )
            .unwrap();
        assert!(matches!(
            authority.prepare_ui_authentication(
                transfer,
                ingress_identity,
                manifest,
                7,
                UnixMillisV2::new(111),
            ),
            Err(KernelIngressAuthorityErrorV2::AlreadyConsumed)
        ));
        let ui_unsigned = prepared
            .envelope
            .verify(
                derive_ed25519_key_id_v2(envelope_key.verifying_key().to_bytes()),
                envelope_key.verifying_key().to_bytes(),
                installation,
                manifest,
                7,
                UnixMillisV2::new(120),
            )
            .unwrap();
        let principal = PrincipalIdV2::new([0x19; 32]);
        let ui_settlement_unsigned = UnsignedUiAuthenticationSettlementV2::new(
            installation,
            manifest,
            7,
            UiAuthenticationPurposeV2::IngressInput,
            prepared.envelope.envelope_digest().unwrap(),
            ui_unsigned.binding_digest().unwrap(),
            FixedOriginV2::Approval8766,
            FixedOriginV2::Ingress8767,
            principal,
            Digest32V2::new([0x20; 32]),
            Digest32V2::new([0x21; 32]),
            true,
            true,
            false,
            false,
            1,
            ui_unsigned.envelope_nonce(),
            Nonce32V2::new([0x22; 32]),
            UnixMillisV2::new(120),
            UnixMillisV2::new(300),
        )
        .unwrap();
        let ui_settlement = sign_ui_settlement(ui_settlement_unsigned, &ui_key);
        let authenticated = authority
            .authenticate_ui(
                prepared.preparation,
                &ui_settlement,
                ingress_identity,
                manifest,
                7,
                UnixMillisV2::new(130),
            )
            .unwrap();

        let content = b"send a short note";
        let mut input = KernelInputOwnerV2::new(4, 4096).unwrap();
        input
            .register_verified_ui_authorization(authenticated.authorization, authenticated.evidence)
            .unwrap();
        let begun = input
            .begin(
                BeginInputRequestV2::new(
                    authenticated.authorization,
                    ContentKindV2::ChatText,
                    content.len() as u64,
                    Some(Digest32V2::new(Sha256::digest(content).into())),
                )
                .unwrap(),
                manifest,
                7,
                UnixMillisV2::new(140),
            )
            .unwrap();
        let prior = begun.channels()[0].cumulative_digest();
        let chunk_digest =
            input_chunk_digest_v2(begun.session(), InputChannelV2::ChatText, 0, content).unwrap();
        let resulting = input_channel_step_digest_v2(prior, 0, chunk_digest).unwrap();
        let ack = input
            .append(
                savana_kernel_protocol::v2::AppendInputChunkRequestV2::new(
                    begun.writer(),
                    DirectInputChannelV2::ChatText,
                    0,
                    prior,
                    ZeroizingBytesV2::new(content.to_vec()).unwrap(),
                    chunk_digest,
                    resulting,
                )
                .unwrap(),
            )
            .unwrap();
        let finalized = input
            .finalize(
                FinalizeInputRequestV2::new(
                    begun.session(),
                    vec![InputChannelCommitmentV2::new(
                        InputChannelV2::ChatText,
                        1,
                        0,
                        content.len() as u64,
                        ack.cumulative_digest(),
                    )
                    .unwrap()],
                    InputSourceProvenanceV2::direct(
                        InputSourceKindV2::Chat,
                        content.len() as u64,
                        Digest32V2::new(Sha256::digest(content).into()),
                        VersionV2::new(1, 0, 0),
                    )
                    .unwrap(),
                )
                .unwrap(),
            )
            .unwrap();
        let pending = authority
            .prepare_pending_approval(finalized, manifest, 7, UnixMillisV2::new(150))
            .unwrap();
        let approval_unsigned = pending
            .envelope
            .verify(
                derive_ed25519_key_id_v2(envelope_key.verifying_key().to_bytes()),
                envelope_key.verifying_key().to_bytes(),
                installation,
                manifest,
                7,
                ApprovalPurposeV2::Ingress,
                principal,
                UnixMillisV2::new(160),
            )
            .unwrap();
        let approval_settlement_unsigned = UnsignedApprovalSettlementV2::new(
            installation,
            manifest,
            7,
            ApprovalPurposeV2::Ingress,
            pending.envelope.envelope_digest().unwrap(),
            ApprovalDecisionV2::Approve,
            principal,
            Digest32V2::new([0x23; 32]),
            Digest32V2::new([0x24; 32]),
            true,
            true,
            false,
            false,
            1,
            approval_unsigned.decision_challenge(),
            Nonce32V2::new([0x25; 32]),
            UnixMillisV2::new(160),
            UnixMillisV2::new(250),
        )
        .unwrap();
        let approval_settlement =
            sign_approval_settlement(approval_settlement_unsigned, &approval_key);
        let decision = authority
            .verify_settlement(
                pending.pending,
                pending.approval,
                &approval_settlement,
                manifest,
                7,
                UnixMillisV2::new(170),
            )
            .unwrap();
        assert!(matches!(
            decision,
            VerifiedIngressSettlementDecisionV2::Approved { principal: p, .. } if p == principal
        ));
        let record_index = match decision {
            VerifiedIngressSettlementDecisionV2::Approved { record_index, .. } => record_index,
            VerifiedIngressSettlementDecisionV2::Denied => unreachable!(),
        };
        assert!(authority
            .finalized_for_verified_approval(record_index)
            .is_ok());
        authority.finish_verified_settlement(decision).unwrap();
        assert_eq!(
            authority.pending_status(pending.pending).unwrap(),
            KernelPendingIngressStateV2::Approved,
        );
        assert!(matches!(
            authority.verify_settlement(
                pending.pending,
                pending.approval,
                &approval_settlement,
                manifest,
                7,
                UnixMillisV2::new(171),
            ),
            Err(KernelIngressAuthorityErrorV2::AlreadyConsumed)
        ));
    }

    fn sign_ui_settlement(
        unsigned: UnsignedUiAuthenticationSettlementV2,
        key: &SigningKey,
    ) -> SignedUiAuthenticationSettlementV2 {
        let key_id = derive_ed25519_key_id_v2(key.verifying_key().to_bytes());
        let placeholder = SignedUiAuthenticationSettlementV2::from_parts(
            unsigned,
            key_id,
            Ed25519SignatureV2::new([1; 64]),
        )
        .unwrap();
        let encoded = minicbor::to_vec(placeholder).unwrap();
        let payload = signed_payload(&encoded);
        let signature = sign_payload_domain(key, UI_SETTLEMENT_DOMAIN, payload);
        SignedUiAuthenticationSettlementV2::from_parts(unsigned, key_id, signature).unwrap()
    }

    fn sign_approval_settlement(
        unsigned: UnsignedApprovalSettlementV2,
        key: &SigningKey,
    ) -> SignedApprovalSettlementV2 {
        let key_id = derive_ed25519_key_id_v2(key.verifying_key().to_bytes());
        let placeholder = SignedApprovalSettlementV2::from_parts(
            unsigned,
            key_id,
            Ed25519SignatureV2::new([1; 64]),
        )
        .unwrap();
        let encoded = minicbor::to_vec(placeholder).unwrap();
        let payload = signed_payload(&encoded);
        let signature = sign_payload_domain(key, APPROVAL_SETTLEMENT_DOMAIN, payload);
        SignedApprovalSettlementV2::from_parts(unsigned, key_id, signature).unwrap()
    }

    fn signed_payload(bytes: &[u8]) -> &[u8] {
        let mut decoder = minicbor::Decoder::new(bytes);
        assert_eq!(decoder.array().unwrap(), Some(3));
        decoder.bytes().unwrap()
    }

    fn sign_payload_domain(key: &SigningKey, domain: &[u8], payload: &[u8]) -> Ed25519SignatureV2 {
        let mut hasher = Sha256::new();
        hasher.update(domain);
        hasher.update(payload);
        let digest: [u8; 32] = hasher.finalize().into();
        let mut input = Vec::from(domain);
        input.extend_from_slice(&digest);
        Ed25519SignatureV2::new(key.sign(&input).to_bytes())
    }
}
