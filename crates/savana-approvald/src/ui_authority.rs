use std::sync::Mutex;
use std::time::Instant;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use savana_kernel_protocol::v2::{
    AgentApprovalRecordTargetV2, AgentUiAuthenticationBrowserCeremonyCapabilityV2,
    AgentUiAuthenticationSettlementTransferCapabilityV2, AgentUiAuthenticationTransferCapabilityV2,
    AgentUiPreAuthenticationTabCapabilityV2, ApprovalDecisionBrowserBeginRequestV2,
    ApprovalDecisionBrowserBeginResponseV2, ApprovalDecisionBrowserFinishRequestV2,
    ApprovalDecisionBrowserFinishResponseV2, ApprovalDecisionCeremonyCapabilityV2,
    ApprovalDecisionV2, ApprovalDisplayAuthenticationTransferCapabilityV2,
    ApprovalDisplayUiAuthenticationBrowserCeremonyCapabilityV2,
    ApprovalDisplayUiPreAuthenticationTabCapabilityV2, ApprovalDisplayViewV2, ApprovalPurposeV2,
    ApprovalSettlementViewV2, ApprovalTabSessionCapabilityV2, ApprovalUiRecordHandleV2,
    BeginEnrollmentBrowserRequestV2, BeginEnrollmentBrowserResponseV2, BrowserWebAuthnAssertionV2,
    ClosedCredentialRevocationReasonV2, ConnectorApprovalRecordHandleV2,
    CreateEnrollmentCodeResponseV2, CredentialPublicStateV2, Digest32V2, EndpointRoleV2,
    EnrollmentCeremonyCapabilityV2, EnrollmentProfileIdV2, FinishEnrollmentBrowserRequestV2,
    FinishEnrollmentBrowserResponseV2, FixedOriginV2, IngressApprovalRecordHandleV2,
    IngressUiAuthenticationBrowserCeremonyCapabilityV2,
    IngressUiAuthenticationSettlementTransferCapabilityV2,
    IngressUiAuthenticationTransferCapabilityV2, IngressUiPreAuthenticationTabCapabilityV2,
    RegisteredApprovalV2, RegisteredUiAuthenticationV2, ReleaseApprovalRecordHandleV2,
    ServiceIdentityV2, SignedAgentAuthenticationAttemptClosureProofV2,
    SignedAgentAuthenticationClosureDescriptorV2, SignedApprovalEnvelopeV2,
    SignedUiAuthenticationEnvelopeV2, SignedUiAuthenticationSettlementV2,
    ToolApprovalRecordHandleV2, UiAuthenticationBrowserBeginRequestV2,
    UiAuthenticationBrowserBeginResponseV2, UiAuthenticationBrowserFinishRequestV2,
    UiAuthenticationBrowserFinishResponseV2, UiAuthenticationPurposeV2, UnixMillisV2,
};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use crate::{
    verify_enrollment_attestation_v2, ConsumedEnrollmentCodeV2, HardwareAttestationRootV2,
    ProtocolApprovalStateOwnerErrorV2, ProtocolApprovalStateOwnerV2,
    UiAuthenticationChallengeProjectionV2, WebAuthnAssertionV2,
};

const CREDENTIAL_ID_DIGEST_DOMAIN_V2: &[u8] = b"SAVANA_WEBAUTHN_CREDENTIAL_ID_V2\0";
const MAX_UI_RECORDS_V2: usize = 65_536;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ApprovalUiAuthorityErrorV2 {
    #[error("approval UI reference is invalid")]
    InvalidReference,
    #[error("approval UI reference was already consumed")]
    AlreadyConsumed,
    #[error("approval UI authority is busy")]
    Busy,
    #[error("approval UI deadline was exceeded")]
    DeadlineExceeded,
    #[error("approval UI authority is unavailable")]
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcceptedUiAuthenticationV2 {
    Ingress {
        pre_authentication: IngressUiPreAuthenticationTabCapabilityV2,
    },
    Agent {
        pre_authentication: AgentUiPreAuthenticationTabCapabilityV2,
    },
    ApprovalDisplay {
        pre_authentication: ApprovalDisplayUiPreAuthenticationTabCapabilityV2,
    },
}

#[derive(Debug, Clone)]
enum InitialTransferV2 {
    Ingress(IngressUiAuthenticationTransferCapabilityV2),
    Agent(AgentUiAuthenticationTransferCapabilityV2),
    ApprovalDisplay(ApprovalDisplayAuthenticationTransferCapabilityV2),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PreAuthenticationV2 {
    Ingress(IngressUiPreAuthenticationTabCapabilityV2),
    Agent(AgentUiPreAuthenticationTabCapabilityV2),
    ApprovalDisplay(ApprovalDisplayUiPreAuthenticationTabCapabilityV2),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CeremonyV2 {
    Ingress(IngressUiAuthenticationBrowserCeremonyCapabilityV2),
    Agent(AgentUiAuthenticationBrowserCeremonyCapabilityV2),
    ApprovalDisplay(ApprovalDisplayUiAuthenticationBrowserCeremonyCapabilityV2),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SettlementTransferV2 {
    Ingress(IngressUiAuthenticationSettlementTransferCapabilityV2),
    Agent(AgentUiAuthenticationSettlementTransferCapabilityV2),
}

#[derive(Debug)]
struct UiRecordV2 {
    role: EndpointRoleV2,
    record: ApprovalUiRecordHandleV2,
    envelope_digest: Digest32V2,
    initial_transfer: InitialTransferV2,
    pre_authentication: Option<PreAuthenticationV2>,
    begin_request_nonce: Option<savana_kernel_protocol::v2::Nonce32V2>,
    ceremony: Option<CeremonyV2>,
    options_json: Option<Vec<u8>>,
    finish_request_digest: Option<Digest32V2>,
    settlement: Option<SignedUiAuthenticationSettlementV2>,
    settlement_transfer: Option<SettlementTransferV2>,
    approval_tab: Option<ApprovalTabSessionCapabilityV2>,
    decision_begin_nonce: Option<savana_kernel_protocol::v2::Nonce32V2>,
    decision: Option<ApprovalDecisionV2>,
    decision_ceremony: Option<ApprovalDecisionCeremonyCapabilityV2>,
    decision_options_json: Option<Vec<u8>>,
    decision_finish_digest: Option<Digest32V2>,
    settlement_delivered: bool,
    approval_envelope_digest: Option<Digest32V2>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ApprovalRecordHandleV2 {
    Ingress(IngressApprovalRecordHandleV2),
    Tool(ToolApprovalRecordHandleV2),
    Release(ReleaseApprovalRecordHandleV2),
    Connector(ConnectorApprovalRecordHandleV2),
}

#[derive(Debug)]
struct ApprovalRecordV2 {
    role: EndpointRoleV2,
    handle: ApprovalRecordHandleV2,
    envelope_digest: Digest32V2,
    display_transfer: ApprovalDisplayAuthenticationTransferCapabilityV2,
}

#[derive(Debug)]
struct EnrollmentCeremonyRecordV2 {
    ceremony: EnrollmentCeremonyCapabilityV2,
    grant: ConsumedEnrollmentCodeV2,
    challenge: savana_kernel_protocol::v2::Nonce32V2,
    begin_nonce: savana_kernel_protocol::v2::Nonce32V2,
    options_json: Vec<u8>,
    consumed: bool,
    finish_request_digest: Option<Digest32V2>,
    response: Option<FinishEnrollmentBrowserResponseV2>,
}

pub struct ApprovalUiAuthorityV2 {
    state: ProtocolApprovalStateOwnerV2,
    records: Mutex<Vec<UiRecordV2>>,
    approvals: Mutex<Vec<ApprovalRecordV2>>,
    enrollments: Mutex<Vec<EnrollmentCeremonyRecordV2>>,
    attestation_roots: Vec<HardwareAttestationRootV2>,
    maximum_records: usize,
}

impl core::fmt::Debug for ApprovalUiAuthorityV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ApprovalUiAuthorityV2")
            .field("maximum_records", &self.maximum_records)
            .finish_non_exhaustive()
    }
}

impl ApprovalUiAuthorityV2 {
    pub fn new(
        state: ProtocolApprovalStateOwnerV2,
        maximum_records: usize,
        attestation_roots: Vec<HardwareAttestationRootV2>,
    ) -> Result<Self, ApprovalUiAuthorityErrorV2> {
        if maximum_records == 0
            || maximum_records > MAX_UI_RECORDS_V2
            || attestation_roots.is_empty()
            || attestation_roots.len() > 256
        {
            return Err(ApprovalUiAuthorityErrorV2::Unavailable);
        }
        Ok(Self {
            state,
            records: Mutex::new(Vec::new()),
            approvals: Mutex::new(Vec::new()),
            enrollments: Mutex::new(Vec::new()),
            attestation_roots,
            maximum_records,
        })
    }

    pub fn create_enrollment_code(
        &self,
        profile: EnrollmentProfileIdV2,
        client_request_nonce: savana_kernel_protocol::v2::Nonce32V2,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<CreateEnrollmentCodeResponseV2, ApprovalUiAuthorityErrorV2> {
        self.state
            .create_enrollment_code(profile, client_request_nonce, now, deadline)
            .map_err(map_owner)
    }

    pub fn revoke_credential(
        &self,
        credential_digest: Digest32V2,
        reason: ClosedCredentialRevocationReasonV2,
        deadline: Instant,
    ) -> Result<CredentialPublicStateV2, ApprovalUiAuthorityErrorV2> {
        self.state
            .revoke_credential(credential_digest, reason, deadline)
            .map_err(map_owner)
    }

    pub fn begin_enrollment(
        &self,
        request: BeginEnrollmentBrowserRequestV2,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<BeginEnrollmentBrowserResponseV2, ApprovalUiAuthorityErrorV2> {
        let (handle, begin_nonce, code) = request.into_parts();
        let mut enrollments = self
            .enrollments
            .lock()
            .map_err(|_| ApprovalUiAuthorityErrorV2::Unavailable)?;
        if let Some(existing) = enrollments
            .iter()
            .find(|record| record.grant.handle() == handle && record.begin_nonce == begin_nonce)
        {
            return BeginEnrollmentBrowserResponseV2::new(
                existing.ceremony,
                existing.options_json.clone(),
            )
            .map_err(|_| ApprovalUiAuthorityErrorV2::Unavailable);
        }
        if enrollments.len() >= self.maximum_records {
            return Err(ApprovalUiAuthorityErrorV2::Busy);
        }
        enrollments
            .try_reserve(1)
            .map_err(|_| ApprovalUiAuthorityErrorV2::Unavailable)?;
        let grant = self
            .state
            .consume_enrollment_code(handle, code, now, deadline)
            .map_err(map_owner)?;
        let challenge = savana_kernel_protocol::v2::Nonce32V2::new(draw_nonzero()?);
        let ceremony = EnrollmentCeremonyCapabilityV2::from_authority_entropy(draw_nonzero()?)
            .ok_or(ApprovalUiAuthorityErrorV2::Unavailable)?;
        let options_json = enrollment_creation_options_json(grant, challenge, now)?;
        enrollments.push(EnrollmentCeremonyRecordV2 {
            ceremony,
            grant,
            challenge,
            begin_nonce,
            options_json: options_json.clone(),
            consumed: false,
            finish_request_digest: None,
            response: None,
        });
        BeginEnrollmentBrowserResponseV2::new(ceremony, options_json)
            .map_err(|_| ApprovalUiAuthorityErrorV2::Unavailable)
    }

    pub fn finish_enrollment(
        &self,
        request: FinishEnrollmentBrowserRequestV2,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<FinishEnrollmentBrowserResponseV2, ApprovalUiAuthorityErrorV2> {
        let (ceremony, nonce, credential_id, client_data_json, attestation_object) =
            request.into_parts();
        let digest = enrollment_finish_digest(
            ceremony,
            nonce,
            &credential_id,
            &client_data_json,
            &attestation_object,
        )?;
        let mut enrollments = self
            .enrollments
            .lock()
            .map_err(|_| ApprovalUiAuthorityErrorV2::Unavailable)?;
        let record = enrollments
            .iter_mut()
            .find(|record| record.ceremony == ceremony)
            .ok_or(ApprovalUiAuthorityErrorV2::InvalidReference)?;
        if record.consumed {
            return if record.finish_request_digest == Some(digest) {
                record
                    .response
                    .ok_or(ApprovalUiAuthorityErrorV2::AlreadyConsumed)
            } else {
                Err(ApprovalUiAuthorityErrorV2::AlreadyConsumed)
            };
        }
        record.consumed = true;
        record.finish_request_digest = Some(digest);
        if now.get() >= record.grant.ceremony_expires_at().get() {
            return Err(ApprovalUiAuthorityErrorV2::AlreadyConsumed);
        }
        let verified = verify_enrollment_attestation_v2(
            &credential_id,
            &client_data_json,
            &attestation_object,
            record.challenge,
            &self.attestation_roots,
            now,
        )
        .map_err(|_| ApprovalUiAuthorityErrorV2::InvalidReference)?;
        let credential_digest = webauthn_credential_digest_v2(&credential_id)
            .ok_or(ApprovalUiAuthorityErrorV2::InvalidReference)?;
        let state = self
            .state
            .register_enrolled_hardware_credential(
                record.grant.handle(),
                credential_digest,
                verified.aaguid,
                verified.p256_sec1_public_key,
                verified.signature_counter,
                deadline,
            )
            .map_err(map_owner)?;
        let response = FinishEnrollmentBrowserResponseV2::new(credential_digest, state)
            .map_err(|_| ApprovalUiAuthorityErrorV2::Unavailable)?;
        record.response = Some(response);
        Ok(response)
    }

    pub fn register(
        &self,
        role: EndpointRoleV2,
        envelope: SignedUiAuthenticationEnvelopeV2,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<RegisteredUiAuthenticationV2, ApprovalUiAuthorityErrorV2> {
        if !matches!(
            role,
            EndpointRoleV2::AgentApproval | EndpointRoleV2::IngressApproval
        ) {
            return Err(ApprovalUiAuthorityErrorV2::InvalidReference);
        }
        let envelope_digest = envelope
            .envelope_digest()
            .map_err(|_| ApprovalUiAuthorityErrorV2::InvalidReference)?;
        let record = ApprovalUiRecordHandleV2::from_authority_entropy(draw_nonzero()?)
            .ok_or(ApprovalUiAuthorityErrorV2::Unavailable)?;
        let initial_transfer = match role {
            EndpointRoleV2::IngressApproval => {
                InitialTransferV2::Ingress(
                    IngressUiAuthenticationTransferCapabilityV2::from_authority_entropy(
                        draw_nonzero()?,
                    )
                    .ok_or(ApprovalUiAuthorityErrorV2::Unavailable)?,
                )
            }
            EndpointRoleV2::AgentApproval => InitialTransferV2::Agent(
                AgentUiAuthenticationTransferCapabilityV2::from_authority_entropy(draw_nonzero()?)
                    .ok_or(ApprovalUiAuthorityErrorV2::Unavailable)?,
            ),
            _ => return Err(ApprovalUiAuthorityErrorV2::InvalidReference),
        };
        let mut records = self
            .records
            .lock()
            .map_err(|_| ApprovalUiAuthorityErrorV2::Unavailable)?;
        if let Some(existing) = records
            .iter()
            .find(|candidate| candidate.envelope_digest == envelope_digest)
        {
            return registered(existing);
        }
        if records.len() >= self.maximum_records {
            return Err(ApprovalUiAuthorityErrorV2::Busy);
        }
        records
            .try_reserve(1)
            .map_err(|_| ApprovalUiAuthorityErrorV2::Unavailable)?;
        let registered_digest = self
            .state
            .register_ui_authentication_envelope(envelope, now, deadline)
            .map_err(map_owner)?;
        if registered_digest != envelope_digest {
            return Err(ApprovalUiAuthorityErrorV2::Unavailable);
        }
        records.push(UiRecordV2 {
            role,
            record,
            envelope_digest,
            initial_transfer,
            pre_authentication: None,
            begin_request_nonce: None,
            ceremony: None,
            options_json: None,
            finish_request_digest: None,
            settlement: None,
            settlement_transfer: None,
            approval_tab: None,
            decision_begin_nonce: None,
            decision: None,
            decision_ceremony: None,
            decision_options_json: None,
            decision_finish_digest: None,
            settlement_delivered: false,
            approval_envelope_digest: None,
        });
        registered(
            records
                .last()
                .ok_or(ApprovalUiAuthorityErrorV2::Unavailable)?,
        )
    }

    pub fn close_agent_authentication_attempt(
        &self,
        descriptor: SignedAgentAuthenticationClosureDescriptorV2,
        caller_identity: ServiceIdentityV2,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<SignedAgentAuthenticationAttemptClosureProofV2, ApprovalUiAuthorityErrorV2> {
        self.state
            .close_agent_authentication_attempt(descriptor, caller_identity, now, deadline)
            .map_err(map_owner)
    }

    pub fn register_approval(
        &self,
        role: EndpointRoleV2,
        envelope: SignedApprovalEnvelopeV2,
        display_authentication: SignedUiAuthenticationEnvelopeV2,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<RegisteredApprovalV2, ApprovalUiAuthorityErrorV2> {
        if !matches!(
            role,
            EndpointRoleV2::AgentApproval | EndpointRoleV2::IngressApproval
        ) {
            return Err(ApprovalUiAuthorityErrorV2::InvalidReference);
        }
        let envelope_digest = envelope
            .envelope_digest()
            .map_err(|_| ApprovalUiAuthorityErrorV2::InvalidReference)?;
        let mut approvals = self
            .approvals
            .lock()
            .map_err(|_| ApprovalUiAuthorityErrorV2::Unavailable)?;
        if let Some(existing) = approvals
            .iter()
            .find(|record| record.envelope_digest == envelope_digest)
        {
            if existing.role != role {
                return Err(ApprovalUiAuthorityErrorV2::InvalidReference);
            }
            return registered_approval(existing);
        }
        let mut records = self
            .records
            .lock()
            .map_err(|_| ApprovalUiAuthorityErrorV2::Unavailable)?;
        if approvals.len() >= self.maximum_records || records.len() >= self.maximum_records {
            return Err(ApprovalUiAuthorityErrorV2::Busy);
        }
        approvals
            .try_reserve(1)
            .map_err(|_| ApprovalUiAuthorityErrorV2::Unavailable)?;
        records
            .try_reserve(1)
            .map_err(|_| ApprovalUiAuthorityErrorV2::Unavailable)?;
        let handle_entropy = draw_nonzero()?;
        let display_transfer =
            ApprovalDisplayAuthenticationTransferCapabilityV2::from_authority_entropy(
                draw_nonzero()?,
            )
            .ok_or(ApprovalUiAuthorityErrorV2::Unavailable)?;
        let ui_record_handle = ApprovalUiRecordHandleV2::from_authority_entropy(draw_nonzero()?)
            .ok_or(ApprovalUiAuthorityErrorV2::Unavailable)?;
        let (registered_digest, display_envelope_digest, purpose) = self
            .state
            .register_approval_pair(role, envelope, display_authentication, now, deadline)
            .map_err(map_owner)?;
        if registered_digest != envelope_digest {
            return Err(ApprovalUiAuthorityErrorV2::Unavailable);
        }
        let handle = match (role, purpose) {
            (EndpointRoleV2::IngressApproval, ApprovalPurposeV2::Ingress) => {
                ApprovalRecordHandleV2::Ingress(
                    IngressApprovalRecordHandleV2::from_authority_entropy(handle_entropy)
                        .ok_or(ApprovalUiAuthorityErrorV2::Unavailable)?,
                )
            }
            (EndpointRoleV2::AgentApproval, ApprovalPurposeV2::ToolExecution) => {
                ApprovalRecordHandleV2::Tool(
                    ToolApprovalRecordHandleV2::from_authority_entropy(handle_entropy)
                        .ok_or(ApprovalUiAuthorityErrorV2::Unavailable)?,
                )
            }
            (EndpointRoleV2::AgentApproval, ApprovalPurposeV2::FinalRelease) => {
                ApprovalRecordHandleV2::Release(
                    ReleaseApprovalRecordHandleV2::from_authority_entropy(handle_entropy)
                        .ok_or(ApprovalUiAuthorityErrorV2::Unavailable)?,
                )
            }
            (EndpointRoleV2::AgentApproval, ApprovalPurposeV2::ConnectorRegistration) => {
                ApprovalRecordHandleV2::Connector(
                    ConnectorApprovalRecordHandleV2::from_authority_entropy(handle_entropy)
                        .ok_or(ApprovalUiAuthorityErrorV2::Unavailable)?,
                )
            }
            _ => return Err(ApprovalUiAuthorityErrorV2::InvalidReference),
        };
        approvals.push(ApprovalRecordV2 {
            role,
            handle,
            envelope_digest,
            display_transfer,
        });
        records.push(UiRecordV2 {
            role,
            record: ui_record_handle,
            envelope_digest: display_envelope_digest,
            initial_transfer: InitialTransferV2::ApprovalDisplay(display_transfer),
            pre_authentication: None,
            begin_request_nonce: None,
            ceremony: None,
            options_json: None,
            finish_request_digest: None,
            settlement: None,
            settlement_transfer: None,
            approval_tab: None,
            decision_begin_nonce: None,
            decision: None,
            decision_ceremony: None,
            decision_options_json: None,
            decision_finish_digest: None,
            settlement_delivered: false,
            approval_envelope_digest: Some(envelope_digest),
        });
        registered_approval(
            approvals
                .last()
                .ok_or(ApprovalUiAuthorityErrorV2::Unavailable)?,
        )
    }

    pub fn get_ingress_approval_settlement(
        &self,
        approval: IngressApprovalRecordHandleV2,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<ApprovalSettlementViewV2, ApprovalUiAuthorityErrorV2> {
        self.get_approval_settlement(
            ApprovalRecordHandleV2::Ingress(approval),
            EndpointRoleV2::IngressApproval,
            now,
            deadline,
        )
    }

    pub fn get_agent_approval_settlement(
        &self,
        approval: AgentApprovalRecordTargetV2,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<ApprovalSettlementViewV2, ApprovalUiAuthorityErrorV2> {
        let handle = match approval {
            AgentApprovalRecordTargetV2::Tool(handle) => ApprovalRecordHandleV2::Tool(handle),
            AgentApprovalRecordTargetV2::Release(handle) => ApprovalRecordHandleV2::Release(handle),
            AgentApprovalRecordTargetV2::Connector(handle) => {
                ApprovalRecordHandleV2::Connector(handle)
            }
        };
        self.get_approval_settlement(handle, EndpointRoleV2::AgentApproval, now, deadline)
    }

    fn get_approval_settlement(
        &self,
        handle: ApprovalRecordHandleV2,
        role: EndpointRoleV2,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<ApprovalSettlementViewV2, ApprovalUiAuthorityErrorV2> {
        let envelope_digest = self
            .approvals
            .lock()
            .map_err(|_| ApprovalUiAuthorityErrorV2::Unavailable)?
            .iter()
            .find(|record| record.handle == handle && record.role == role)
            .map(|record| record.envelope_digest)
            .ok_or(ApprovalUiAuthorityErrorV2::InvalidReference)?;
        self.state
            .approval_settlement_view(envelope_digest, now, deadline)
            .map_err(map_owner)
    }

    pub fn accept_ingress_transfer(
        &self,
        transfer: IngressUiAuthenticationTransferCapabilityV2,
    ) -> Result<AcceptedUiAuthenticationV2, ApprovalUiAuthorityErrorV2> {
        let mut records = self
            .records
            .lock()
            .map_err(|_| ApprovalUiAuthorityErrorV2::Unavailable)?;
        let record = records
            .iter_mut()
            .find(|record| {
                matches!(
                    record.initial_transfer,
                    InitialTransferV2::Ingress(candidate) if candidate == transfer
                )
            })
            .ok_or(ApprovalUiAuthorityErrorV2::InvalidReference)?;
        let pre_authentication = match record.pre_authentication {
            Some(PreAuthenticationV2::Ingress(value)) => value,
            Some(PreAuthenticationV2::Agent(_) | PreAuthenticationV2::ApprovalDisplay(_)) => {
                return Err(ApprovalUiAuthorityErrorV2::InvalidReference)
            }
            None => {
                let value = IngressUiPreAuthenticationTabCapabilityV2::from_authority_entropy(
                    draw_nonzero()?,
                )
                .ok_or(ApprovalUiAuthorityErrorV2::Unavailable)?;
                record.pre_authentication = Some(PreAuthenticationV2::Ingress(value));
                value
            }
        };
        Ok(AcceptedUiAuthenticationV2::Ingress { pre_authentication })
    }

    pub fn accept_agent_transfer(
        &self,
        transfer: AgentUiAuthenticationTransferCapabilityV2,
    ) -> Result<AcceptedUiAuthenticationV2, ApprovalUiAuthorityErrorV2> {
        let mut records = self
            .records
            .lock()
            .map_err(|_| ApprovalUiAuthorityErrorV2::Unavailable)?;
        let record = records
            .iter_mut()
            .find(|record| {
                matches!(
                    record.initial_transfer,
                    InitialTransferV2::Agent(candidate) if candidate == transfer
                )
            })
            .ok_or(ApprovalUiAuthorityErrorV2::InvalidReference)?;
        let pre_authentication = match record.pre_authentication {
            Some(PreAuthenticationV2::Agent(value)) => value,
            Some(PreAuthenticationV2::Ingress(_) | PreAuthenticationV2::ApprovalDisplay(_)) => {
                return Err(ApprovalUiAuthorityErrorV2::InvalidReference)
            }
            None => {
                let value = AgentUiPreAuthenticationTabCapabilityV2::from_authority_entropy(
                    draw_nonzero()?,
                )
                .ok_or(ApprovalUiAuthorityErrorV2::Unavailable)?;
                record.pre_authentication = Some(PreAuthenticationV2::Agent(value));
                value
            }
        };
        Ok(AcceptedUiAuthenticationV2::Agent { pre_authentication })
    }

    pub fn accept_approval_display_transfer(
        &self,
        transfer: ApprovalDisplayAuthenticationTransferCapabilityV2,
    ) -> Result<AcceptedUiAuthenticationV2, ApprovalUiAuthorityErrorV2> {
        let mut records = self
            .records
            .lock()
            .map_err(|_| ApprovalUiAuthorityErrorV2::Unavailable)?;
        let record = records
            .iter_mut()
            .find(|record| {
                matches!(
                    record.initial_transfer,
                    InitialTransferV2::ApprovalDisplay(candidate) if candidate == transfer
                )
            })
            .ok_or(ApprovalUiAuthorityErrorV2::InvalidReference)?;
        let pre_authentication = match record.pre_authentication {
            Some(PreAuthenticationV2::ApprovalDisplay(value)) => value,
            Some(_) => return Err(ApprovalUiAuthorityErrorV2::InvalidReference),
            None => {
                let value =
                    ApprovalDisplayUiPreAuthenticationTabCapabilityV2::from_authority_entropy(
                        draw_nonzero()?,
                    )
                    .ok_or(ApprovalUiAuthorityErrorV2::Unavailable)?;
                record.pre_authentication = Some(PreAuthenticationV2::ApprovalDisplay(value));
                value
            }
        };
        Ok(AcceptedUiAuthenticationV2::ApprovalDisplay { pre_authentication })
    }

    pub fn begin(
        &self,
        request: UiAuthenticationBrowserBeginRequestV2,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<UiAuthenticationBrowserBeginResponseV2, ApprovalUiAuthorityErrorV2> {
        let (pre_authentication, request_nonce) = match request {
            UiAuthenticationBrowserBeginRequestV2::Ingress {
                pre_authentication,
                client_request_nonce,
            } => (
                PreAuthenticationV2::Ingress(pre_authentication),
                client_request_nonce,
            ),
            UiAuthenticationBrowserBeginRequestV2::Agent {
                pre_authentication,
                client_request_nonce,
            } => (
                PreAuthenticationV2::Agent(pre_authentication),
                client_request_nonce,
            ),
            UiAuthenticationBrowserBeginRequestV2::ApprovalDisplay {
                pre_authentication,
                client_request_nonce,
            } => (
                PreAuthenticationV2::ApprovalDisplay(pre_authentication),
                client_request_nonce,
            ),
        };
        let mut records = self
            .records
            .lock()
            .map_err(|_| ApprovalUiAuthorityErrorV2::Unavailable)?;
        let record = records
            .iter_mut()
            .find(|record| record.pre_authentication == Some(pre_authentication))
            .ok_or(ApprovalUiAuthorityErrorV2::InvalidReference)?;
        if let Some(existing_nonce) = record.begin_request_nonce {
            if existing_nonce != request_nonce {
                return Err(ApprovalUiAuthorityErrorV2::AlreadyConsumed);
            }
            return begin_response(record);
        }
        let challenge = self
            .state
            .ui_authentication_challenge(record.envelope_digest, now, deadline)
            .map_err(map_owner)?;
        validate_challenge_role(record.role, challenge)?;
        let ceremony = match pre_authentication {
            PreAuthenticationV2::Ingress(_) => CeremonyV2::Ingress(
                IngressUiAuthenticationBrowserCeremonyCapabilityV2::from_authority_entropy(
                    draw_nonzero()?,
                )
                .ok_or(ApprovalUiAuthorityErrorV2::Unavailable)?,
            ),
            PreAuthenticationV2::Agent(_) => CeremonyV2::Agent(
                AgentUiAuthenticationBrowserCeremonyCapabilityV2::from_authority_entropy(
                    draw_nonzero()?,
                )
                .ok_or(ApprovalUiAuthorityErrorV2::Unavailable)?,
            ),
            PreAuthenticationV2::ApprovalDisplay(_) => CeremonyV2::ApprovalDisplay(
                ApprovalDisplayUiAuthenticationBrowserCeremonyCapabilityV2::from_authority_entropy(
                    draw_nonzero()?,
                )
                .ok_or(ApprovalUiAuthorityErrorV2::Unavailable)?,
            ),
        };
        record.begin_request_nonce = Some(request_nonce);
        record.ceremony = Some(ceremony);
        record.options_json = Some(public_key_options_json(challenge, now)?);
        begin_response(record)
    }

    pub fn finish(
        &self,
        request: UiAuthenticationBrowserFinishRequestV2,
        exact_request_digest: Digest32V2,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<UiAuthenticationBrowserFinishResponseV2, ApprovalUiAuthorityErrorV2> {
        let (ceremony, assertion) = match request {
            UiAuthenticationBrowserFinishRequestV2::Ingress {
                ceremony,
                assertion,
                ..
            } => (CeremonyV2::Ingress(ceremony), assertion),
            UiAuthenticationBrowserFinishRequestV2::Agent {
                ceremony,
                assertion,
                ..
            } => (CeremonyV2::Agent(ceremony), assertion),
            UiAuthenticationBrowserFinishRequestV2::ApprovalDisplay {
                ceremony,
                assertion,
                ..
            } => (CeremonyV2::ApprovalDisplay(ceremony), assertion),
        };
        let mut records = self
            .records
            .lock()
            .map_err(|_| ApprovalUiAuthorityErrorV2::Unavailable)?;
        let record = records
            .iter_mut()
            .find(|record| record.ceremony == Some(ceremony))
            .ok_or(ApprovalUiAuthorityErrorV2::InvalidReference)?;
        if let Some(existing_digest) = record.finish_request_digest {
            if existing_digest != exact_request_digest {
                return Err(ApprovalUiAuthorityErrorV2::AlreadyConsumed);
            }
            return finish_response(record);
        }
        let assertion = convert_assertion(assertion)?;
        let settlement = self
            .state
            .settle_ui_authentication(record.envelope_digest, assertion, now, deadline)
            .map_err(map_owner)?;
        let settlement_transfer = match ceremony {
            CeremonyV2::Ingress(_) => SettlementTransferV2::Ingress(
                IngressUiAuthenticationSettlementTransferCapabilityV2::from_authority_entropy(
                    draw_nonzero()?,
                )
                .ok_or(ApprovalUiAuthorityErrorV2::Unavailable)?,
            ),
            CeremonyV2::Agent(_) => SettlementTransferV2::Agent(
                AgentUiAuthenticationSettlementTransferCapabilityV2::from_authority_entropy(
                    draw_nonzero()?,
                )
                .ok_or(ApprovalUiAuthorityErrorV2::Unavailable)?,
            ),
            CeremonyV2::ApprovalDisplay(_) => {
                record.approval_tab = Some(
                    ApprovalTabSessionCapabilityV2::from_authority_entropy(draw_nonzero()?)
                        .ok_or(ApprovalUiAuthorityErrorV2::Unavailable)?,
                );
                record.finish_request_digest = Some(exact_request_digest);
                record.settlement = Some(settlement);
                return finish_response(record);
            }
        };
        record.finish_request_digest = Some(exact_request_digest);
        record.settlement = Some(settlement);
        record.settlement_transfer = Some(settlement_transfer);
        finish_response(record)
    }

    pub fn approval_display(
        &self,
        tab: ApprovalTabSessionCapabilityV2,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<ApprovalDisplayViewV2, ApprovalUiAuthorityErrorV2> {
        let envelope_digest = self
            .records
            .lock()
            .map_err(|_| ApprovalUiAuthorityErrorV2::Unavailable)?
            .iter()
            .find(|record| record.approval_tab == Some(tab))
            .and_then(|record| record.approval_envelope_digest)
            .ok_or(ApprovalUiAuthorityErrorV2::InvalidReference)?;
        let challenge = self
            .state
            .approval_challenge(envelope_digest, now, deadline)
            .map_err(map_owner)?;
        let display_declassification_provenance_digest = challenge
            .display_declassification_provenance_digest()
            .ok_or(ApprovalUiAuthorityErrorV2::Unavailable)?;
        ApprovalDisplayViewV2::new(
            challenge.purpose(),
            challenge.display_projection_digest(),
            challenge.display_digest(),
            challenge.display_text().clone(),
            display_declassification_provenance_digest,
        )
        .map_err(|_| ApprovalUiAuthorityErrorV2::Unavailable)
    }

    pub fn begin_approval_decision(
        &self,
        request: ApprovalDecisionBrowserBeginRequestV2,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<ApprovalDecisionBrowserBeginResponseV2, ApprovalUiAuthorityErrorV2> {
        let mut records = self
            .records
            .lock()
            .map_err(|_| ApprovalUiAuthorityErrorV2::Unavailable)?;
        let record = records
            .iter_mut()
            .find(|record| record.approval_tab == Some(request.tab()))
            .ok_or(ApprovalUiAuthorityErrorV2::InvalidReference)?;
        if let Some(existing_nonce) = record.decision_begin_nonce {
            if existing_nonce != request.client_request_nonce()
                || record.decision != Some(request.decision())
            {
                return Err(ApprovalUiAuthorityErrorV2::AlreadyConsumed);
            }
            return decision_begin_response(record);
        }
        let envelope_digest = record
            .approval_envelope_digest
            .ok_or(ApprovalUiAuthorityErrorV2::InvalidReference)?;
        let challenge = self
            .state
            .approval_challenge(envelope_digest, now, deadline)
            .map_err(map_owner)?;
        let ceremony =
            ApprovalDecisionCeremonyCapabilityV2::from_authority_entropy(draw_nonzero()?)
                .ok_or(ApprovalUiAuthorityErrorV2::Unavailable)?;
        record.decision_begin_nonce = Some(request.client_request_nonce());
        record.decision = Some(request.decision());
        record.decision_ceremony = Some(ceremony);
        record.decision_options_json = Some(public_key_options(
            challenge.challenge(),
            challenge.expires_at(),
            now,
        )?);
        decision_begin_response(record)
    }

    pub fn finish_approval_decision(
        &self,
        request: ApprovalDecisionBrowserFinishRequestV2,
        exact_request_digest: Digest32V2,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<ApprovalDecisionBrowserFinishResponseV2, ApprovalUiAuthorityErrorV2> {
        let (ceremony, _request_nonce, assertion) = request.into_parts();
        let mut records = self
            .records
            .lock()
            .map_err(|_| ApprovalUiAuthorityErrorV2::Unavailable)?;
        let record = records
            .iter_mut()
            .find(|record| record.decision_ceremony == Some(ceremony))
            .ok_or(ApprovalUiAuthorityErrorV2::InvalidReference)?;
        if let Some(existing_digest) = record.decision_finish_digest {
            if existing_digest != exact_request_digest {
                return Err(ApprovalUiAuthorityErrorV2::AlreadyConsumed);
            }
            return decision_finish_response(record);
        }
        let envelope_digest = record
            .approval_envelope_digest
            .ok_or(ApprovalUiAuthorityErrorV2::InvalidReference)?;
        let decision = record
            .decision
            .ok_or(ApprovalUiAuthorityErrorV2::InvalidReference)?;
        let assertion = convert_assertion(assertion)?;
        self.state
            .settle_approval(envelope_digest, decision, assertion, now, deadline)
            .map_err(map_owner)?;
        record.decision_finish_digest = Some(exact_request_digest);
        decision_finish_response(record)
    }

    pub fn consume_ingress_settlement(
        &self,
        record_handle: ApprovalUiRecordHandleV2,
        transfer: IngressUiAuthenticationSettlementTransferCapabilityV2,
    ) -> Result<SignedUiAuthenticationSettlementV2, ApprovalUiAuthorityErrorV2> {
        self.consume_settlement(
            record_handle,
            SettlementTransferV2::Ingress(transfer),
            EndpointRoleV2::IngressApproval,
        )
    }

    pub fn consume_agent_settlement(
        &self,
        record_handle: ApprovalUiRecordHandleV2,
        transfer: AgentUiAuthenticationSettlementTransferCapabilityV2,
    ) -> Result<SignedUiAuthenticationSettlementV2, ApprovalUiAuthorityErrorV2> {
        self.consume_settlement(
            record_handle,
            SettlementTransferV2::Agent(transfer),
            EndpointRoleV2::AgentApproval,
        )
    }

    fn consume_settlement(
        &self,
        record_handle: ApprovalUiRecordHandleV2,
        transfer: SettlementTransferV2,
        role: EndpointRoleV2,
    ) -> Result<SignedUiAuthenticationSettlementV2, ApprovalUiAuthorityErrorV2> {
        let mut records = self
            .records
            .lock()
            .map_err(|_| ApprovalUiAuthorityErrorV2::Unavailable)?;
        let record = records
            .iter_mut()
            .find(|record| record.record == record_handle && record.role == role)
            .ok_or(ApprovalUiAuthorityErrorV2::InvalidReference)?;
        if record.settlement_transfer != Some(transfer) {
            return Err(ApprovalUiAuthorityErrorV2::InvalidReference);
        }
        let settlement = record
            .settlement
            .clone()
            .ok_or(ApprovalUiAuthorityErrorV2::InvalidReference)?;
        record.settlement_delivered = true;
        Ok(settlement)
    }
}

pub fn webauthn_credential_digest_v2(credential_id: &[u8]) -> Option<Digest32V2> {
    if credential_id.is_empty() || credential_id.len() > 4096 {
        return None;
    }
    let mut hasher = Sha256::new();
    hasher.update(CREDENTIAL_ID_DIGEST_DOMAIN_V2);
    hasher.update(credential_id);
    Some(Digest32V2::new(hasher.finalize().into()))
}

fn registered(
    record: &UiRecordV2,
) -> Result<RegisteredUiAuthenticationV2, ApprovalUiAuthorityErrorV2> {
    match record.initial_transfer {
        InitialTransferV2::Ingress(transfer) => Ok(RegisteredUiAuthenticationV2::Ingress {
            record: record.record,
            transfer,
        }),
        InitialTransferV2::Agent(transfer) => Ok(RegisteredUiAuthenticationV2::Agent {
            record: record.record,
            transfer,
        }),
        InitialTransferV2::ApprovalDisplay(_) => Err(ApprovalUiAuthorityErrorV2::InvalidReference),
    }
}

fn registered_approval(
    record: &ApprovalRecordV2,
) -> Result<RegisteredApprovalV2, ApprovalUiAuthorityErrorV2> {
    match record.handle {
        ApprovalRecordHandleV2::Ingress(approval) => Ok(RegisteredApprovalV2::Ingress {
            approval,
            display_authentication: record.display_transfer,
        }),
        ApprovalRecordHandleV2::Tool(approval) => Ok(RegisteredApprovalV2::Tool {
            approval,
            display_authentication: record.display_transfer,
        }),
        ApprovalRecordHandleV2::Release(approval) => Ok(RegisteredApprovalV2::Release {
            approval,
            display_authentication: record.display_transfer,
        }),
        ApprovalRecordHandleV2::Connector(approval) => Ok(RegisteredApprovalV2::Connector {
            approval,
            display_authentication: record.display_transfer,
        }),
    }
}

fn validate_challenge_role(
    role: EndpointRoleV2,
    challenge: UiAuthenticationChallengeProjectionV2,
) -> Result<(), ApprovalUiAuthorityErrorV2> {
    let valid = matches!(
        (role, challenge.purpose()),
        (
            EndpointRoleV2::IngressApproval,
            UiAuthenticationPurposeV2::IngressInput
        ) | (
            EndpointRoleV2::AgentApproval,
            UiAuthenticationPurposeV2::AgentContent
        ) | (
            EndpointRoleV2::IngressApproval,
            UiAuthenticationPurposeV2::ApprovalDisplay
        ) | (
            EndpointRoleV2::AgentApproval,
            UiAuthenticationPurposeV2::ApprovalDisplay
        )
    );
    if valid {
        Ok(())
    } else {
        Err(ApprovalUiAuthorityErrorV2::InvalidReference)
    }
}

fn begin_response(
    record: &UiRecordV2,
) -> Result<UiAuthenticationBrowserBeginResponseV2, ApprovalUiAuthorityErrorV2> {
    let options = record
        .options_json
        .as_ref()
        .ok_or(ApprovalUiAuthorityErrorV2::Unavailable)?
        .clone();
    match record.ceremony {
        Some(CeremonyV2::Ingress(ceremony)) => {
            Ok(UiAuthenticationBrowserBeginResponseV2::Ingress {
                ceremony,
                public_key_options_json: Zeroizing::new(options),
            })
        }
        Some(CeremonyV2::Agent(ceremony)) => Ok(UiAuthenticationBrowserBeginResponseV2::Agent {
            ceremony,
            public_key_options_json: Zeroizing::new(options),
        }),
        Some(CeremonyV2::ApprovalDisplay(ceremony)) => {
            Ok(UiAuthenticationBrowserBeginResponseV2::ApprovalDisplay {
                ceremony,
                public_key_options_json: Zeroizing::new(options),
            })
        }
        None => Err(ApprovalUiAuthorityErrorV2::Unavailable),
    }
}

fn finish_response(
    record: &UiRecordV2,
) -> Result<UiAuthenticationBrowserFinishResponseV2, ApprovalUiAuthorityErrorV2> {
    if let Some(tab) = record.approval_tab {
        return Ok(UiAuthenticationBrowserFinishResponseV2::ApprovalDisplayReady { tab });
    }
    match record.settlement_transfer {
        Some(SettlementTransferV2::Ingress(transfer)) => {
            Ok(UiAuthenticationBrowserFinishResponseV2::TransferToIngress {
                return_origin: FixedOriginV2::Ingress8767,
                transfer,
            })
        }
        Some(SettlementTransferV2::Agent(transfer)) => {
            Ok(UiAuthenticationBrowserFinishResponseV2::TransferToAgent {
                return_origin: FixedOriginV2::Agent8768,
                transfer,
            })
        }
        None => Err(ApprovalUiAuthorityErrorV2::Unavailable),
    }
}

fn public_key_options_json(
    challenge: UiAuthenticationChallengeProjectionV2,
    now: UnixMillisV2,
) -> Result<Vec<u8>, ApprovalUiAuthorityErrorV2> {
    public_key_options(challenge.challenge(), challenge.expires_at(), now)
}

fn public_key_options(
    challenge: savana_kernel_protocol::v2::Nonce32V2,
    expires_at: UnixMillisV2,
    now: UnixMillisV2,
) -> Result<Vec<u8>, ApprovalUiAuthorityErrorV2> {
    let timeout = expires_at.get().saturating_sub(now.get()).min(300_000);
    if timeout == 0 {
        return Err(ApprovalUiAuthorityErrorV2::AlreadyConsumed);
    }
    let encoded = URL_SAFE_NO_PAD.encode(challenge.as_bytes());
    let json = format!(
        "{{\"challenge\":\"{encoded}\",\"rpId\":\"localhost\",\"timeout\":{timeout},\"userVerification\":\"required\"}}"
    )
    .into_bytes();
    if json.len() > 8192 {
        Err(ApprovalUiAuthorityErrorV2::Unavailable)
    } else {
        Ok(json)
    }
}

fn decision_begin_response(
    record: &UiRecordV2,
) -> Result<ApprovalDecisionBrowserBeginResponseV2, ApprovalUiAuthorityErrorV2> {
    ApprovalDecisionBrowserBeginResponseV2::new(
        record
            .decision_ceremony
            .ok_or(ApprovalUiAuthorityErrorV2::Unavailable)?,
        record
            .decision_options_json
            .clone()
            .ok_or(ApprovalUiAuthorityErrorV2::Unavailable)?,
    )
    .map_err(|_| ApprovalUiAuthorityErrorV2::Unavailable)
}

fn decision_finish_response(
    record: &UiRecordV2,
) -> Result<ApprovalDecisionBrowserFinishResponseV2, ApprovalUiAuthorityErrorV2> {
    match record.decision {
        Some(ApprovalDecisionV2::Deny) => Ok(ApprovalDecisionBrowserFinishResponseV2::Denied),
        Some(ApprovalDecisionV2::Approve) => Ok(ApprovalDecisionBrowserFinishResponseV2::Approved),
        None => Err(ApprovalUiAuthorityErrorV2::Unavailable),
    }
}

fn convert_assertion(
    assertion: BrowserWebAuthnAssertionV2,
) -> Result<WebAuthnAssertionV2, ApprovalUiAuthorityErrorV2> {
    let (credential_id, authenticator_data, client_data_json, signature, user_handle) =
        assertion.into_parts();
    let credential_digest = webauthn_credential_digest_v2(&credential_id)
        .ok_or(ApprovalUiAuthorityErrorV2::InvalidReference)?;
    let user_handle: [u8; 32] = user_handle
        .as_slice()
        .try_into()
        .map_err(|_| ApprovalUiAuthorityErrorV2::InvalidReference)?;
    WebAuthnAssertionV2::from_wire(
        credential_digest,
        savana_kernel_protocol::v2::PrincipalIdV2::new(user_handle),
        client_data_json.to_vec(),
        authenticator_data.to_vec(),
        signature.to_vec(),
    )
    .map_err(|_| ApprovalUiAuthorityErrorV2::InvalidReference)
}

fn enrollment_creation_options_json(
    grant: ConsumedEnrollmentCodeV2,
    challenge: savana_kernel_protocol::v2::Nonce32V2,
    now: UnixMillisV2,
) -> Result<Vec<u8>, ApprovalUiAuthorityErrorV2> {
    let timeout = grant
        .ceremony_expires_at()
        .get()
        .saturating_sub(now.get())
        .min(300_000);
    if timeout == 0 {
        return Err(ApprovalUiAuthorityErrorV2::AlreadyConsumed);
    }
    let challenge = URL_SAFE_NO_PAD.encode(challenge.as_bytes());
    let principal = URL_SAFE_NO_PAD.encode(grant.principal().as_bytes());
    let json = format!(
        "{{\"challenge\":\"{challenge}\",\"rp\":{{\"id\":\"localhost\",\"name\":\"Savana\"}},\"user\":{{\"id\":\"{principal}\",\"name\":\"Savana principal\",\"displayName\":\"Savana security principal\"}},\"pubKeyCredParams\":[{{\"type\":\"public-key\",\"alg\":-7}}],\"timeout\":{timeout},\"attestation\":\"direct\",\"authenticatorSelection\":{{\"authenticatorAttachment\":\"cross-platform\",\"residentKey\":\"discouraged\",\"requireResidentKey\":false,\"userVerification\":\"required\"}},\"excludeCredentials\":[]}}"
    )
    .into_bytes();
    if json.len() > 64 * 1024 {
        Err(ApprovalUiAuthorityErrorV2::Unavailable)
    } else {
        Ok(json)
    }
}

fn enrollment_finish_digest(
    ceremony: EnrollmentCeremonyCapabilityV2,
    nonce: savana_kernel_protocol::v2::Nonce32V2,
    credential_id: &[u8],
    client_data_json: &[u8],
    attestation_object: &[u8],
) -> Result<Digest32V2, ApprovalUiAuthorityErrorV2> {
    let ceremony =
        minicbor::to_vec(ceremony).map_err(|_| ApprovalUiAuthorityErrorV2::Unavailable)?;
    let mut hasher = Sha256::new();
    hasher.update(b"SAVANA_ENROLLMENT_FINISH_REQUEST_V2\0");
    for value in [
        ceremony.as_slice(),
        nonce.as_bytes().as_slice(),
        credential_id,
        client_data_json,
        attestation_object,
    ] {
        hasher.update(
            u64::try_from(value.len())
                .map_err(|_| ApprovalUiAuthorityErrorV2::Unavailable)?
                .to_be_bytes(),
        );
        hasher.update(value);
    }
    Ok(Digest32V2::new(hasher.finalize().into()))
}

fn draw_nonzero() -> Result<[u8; 32], ApprovalUiAuthorityErrorV2> {
    for _ in 0..4 {
        let mut bytes = [0_u8; 32];
        getrandom::getrandom(&mut bytes).map_err(|_| ApprovalUiAuthorityErrorV2::Unavailable)?;
        if bytes != [0; 32] {
            return Ok(bytes);
        }
    }
    Err(ApprovalUiAuthorityErrorV2::Unavailable)
}

fn map_owner(error: ProtocolApprovalStateOwnerErrorV2) -> ApprovalUiAuthorityErrorV2 {
    match error {
        ProtocolApprovalStateOwnerErrorV2::Busy => ApprovalUiAuthorityErrorV2::Busy,
        ProtocolApprovalStateOwnerErrorV2::DeadlineExceeded => {
            ApprovalUiAuthorityErrorV2::DeadlineExceeded
        }
        ProtocolApprovalStateOwnerErrorV2::Unavailable => ApprovalUiAuthorityErrorV2::Unavailable,
        ProtocolApprovalStateOwnerErrorV2::Approval(_) => {
            ApprovalUiAuthorityErrorV2::InvalidReference
        }
    }
}
