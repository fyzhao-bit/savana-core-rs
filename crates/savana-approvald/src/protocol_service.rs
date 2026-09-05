use base64::Engine as _;
use ed25519_dalek::SigningKey;
use minicbor::{Decode as _, Encode as _};
use savana_kernel_protocol::v2::{
    decode_signed_agent_authentication_attempt_closure_proof_v2,
    decode_signed_approval_envelope_v2, decode_signed_approval_settlement_v2,
    decode_signed_ui_authentication_envelope_v2, decode_signed_ui_authentication_settlement_v2,
    derive_ed25519_key_id_v2, encode_signed_agent_authentication_attempt_closure_proof_v2,
    encode_signed_approval_envelope_v2, encode_signed_approval_settlement_v2,
    encode_signed_ui_authentication_envelope_v2, encode_signed_ui_authentication_settlement_v2,
    AgentAuthenticationClosureEvidenceV2, AgentAuthenticationInitialTransferTerminalStateV2,
    AgentAuthenticationSettlementTerminalStateV2,
    AgentAuthenticationSettlementTransferTerminalStateV2,
    AgentAuthenticationTransferTerminalStateV2, ApprovalDecisionV2 as ProtocolApprovalDecisionV2,
    ApprovalPurposeV2 as ProtocolApprovalPurposeV2, ApprovalSettlementViewV2, BootIdV2,
    BoundedApprovalDisplayTextV2, ClosedCredentialRevocationReasonV2,
    CreateEnrollmentCodeResponseV2, CredentialPublicStateV2, Digest32V2, Ed25519KeyIdV2,
    EndpointRoleV2, EnrollmentHandleV2, EnrollmentProfileIdV2, FixedOriginV2, PrincipalIdV2,
    ServiceIdentityV2, SignedAgentAuthenticationAttemptClosureProofV2,
    SignedAgentAuthenticationClosureDescriptorV2,
    SignedApprovalEnvelopeV2 as ProtocolSignedApprovalEnvelopeV2,
    SignedApprovalSettlementV2 as ProtocolSignedApprovalSettlementV2,
    SignedUiAuthenticationEnvelopeV2 as ProtocolSignedUiAuthenticationEnvelopeV2,
    SignedUiAuthenticationSettlementV2 as ProtocolSignedUiAuthenticationSettlementV2,
    UiAuthenticationBindingV2, UiAuthenticationPurposeV2, UnixMillisV2,
    UnsignedAgentAuthenticationAttemptClosureProofV2, UnsignedApprovalEnvelopeV2,
    UnsignedApprovalSettlementV2, UnsignedUiAuthenticationEnvelopeV2,
    UnsignedUiAuthenticationSettlementV2, ZeroizingTextV2,
};
use sha2::{Digest as _, Sha256};

use crate::{
    verify_approval_decision_assertion, verify_ui_authentication_assertion,
    ActiveHardwareCredentialV2, ApprovalDecisionChallengeV2, ApprovalErrorV2, ApprovalPurposeV2,
    WebAuthnAssertionV2,
};

#[derive(Debug, Clone)]
struct ProtocolApprovalRecordV2 {
    unsigned: UnsignedApprovalEnvelopeV2,
    envelope_digest: Digest32V2,
    canonical_envelope: Vec<u8>,
    settlement: Option<ProtocolSignedApprovalSettlementV2>,
}

#[derive(Debug, Clone)]
struct ProtocolUiAuthenticationRecordV2 {
    unsigned: UnsignedUiAuthenticationEnvelopeV2,
    envelope_digest: Digest32V2,
    canonical_envelope: Vec<u8>,
    settlement: Option<ProtocolSignedUiAuthenticationSettlementV2>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UiAuthenticationChallengeProjectionV2 {
    purpose: UiAuthenticationPurposeV2,
    envelope_digest: Digest32V2,
    binding: UiAuthenticationBindingV2,
    expected_principal: Option<PrincipalIdV2>,
    challenge: savana_kernel_protocol::v2::Nonce32V2,
    expires_at: UnixMillisV2,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalChallengeProjectionV2 {
    purpose: ProtocolApprovalPurposeV2,
    envelope_digest: Digest32V2,
    expected_principal: PrincipalIdV2,
    challenge: savana_kernel_protocol::v2::Nonce32V2,
    display_projection_digest: Digest32V2,
    display_digest: Digest32V2,
    display_text: BoundedApprovalDisplayTextV2,
    display_declassification_provenance_digest: Option<Digest32V2>,
    expires_at: UnixMillisV2,
}

impl ApprovalChallengeProjectionV2 {
    pub const fn purpose(&self) -> ProtocolApprovalPurposeV2 {
        self.purpose
    }

    pub const fn envelope_digest(&self) -> Digest32V2 {
        self.envelope_digest
    }

    pub const fn expected_principal(&self) -> PrincipalIdV2 {
        self.expected_principal
    }

    pub const fn challenge(&self) -> savana_kernel_protocol::v2::Nonce32V2 {
        self.challenge
    }

    pub const fn display_projection_digest(&self) -> Digest32V2 {
        self.display_projection_digest
    }

    pub const fn display_digest(&self) -> Digest32V2 {
        self.display_digest
    }

    pub fn display_text(&self) -> &BoundedApprovalDisplayTextV2 {
        &self.display_text
    }

    pub const fn display_declassification_provenance_digest(&self) -> Option<Digest32V2> {
        self.display_declassification_provenance_digest
    }

    pub const fn expires_at(&self) -> UnixMillisV2 {
        self.expires_at
    }
}

impl UiAuthenticationChallengeProjectionV2 {
    pub const fn purpose(self) -> UiAuthenticationPurposeV2 {
        self.purpose
    }

    pub const fn envelope_digest(self) -> Digest32V2 {
        self.envelope_digest
    }

    pub const fn binding(self) -> UiAuthenticationBindingV2 {
        self.binding
    }

    pub const fn expected_principal(self) -> Option<PrincipalIdV2> {
        self.expected_principal
    }

    pub const fn challenge(self) -> savana_kernel_protocol::v2::Nonce32V2 {
        self.challenge
    }

    pub const fn expires_at(self) -> UnixMillisV2 {
        self.expires_at
    }
}

#[derive(Debug, Clone)]
struct AgentAuthenticationDenylistRecordV2 {
    envelope_digest: Digest32V2,
    auth_attempt_nonce: savana_kernel_protocol::v2::Nonce32V2,
    tombstone_sequence: u64,
    tombstone_digest: Digest32V2,
    denylisted: bool,
    proof: SignedAgentAuthenticationAttemptClosureProofV2,
}

#[derive(Debug, Clone, Copy)]
struct EnrollmentProfilePolicyV2 {
    profile: EnrollmentProfileIdV2,
    code_lifetime_ms: u64,
    ceremony_lifetime_ms: u64,
}

#[derive(Debug, Clone)]
struct EnrollmentCodeRecordV2 {
    handle: EnrollmentHandleV2,
    profile: EnrollmentProfileIdV2,
    principal: PrincipalIdV2,
    client_request_nonce: savana_kernel_protocol::v2::Nonce32V2,
    code_digest: Digest32V2,
    expires_at: UnixMillisV2,
    consumed: bool,
    credential_digest: Option<Digest32V2>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConsumedEnrollmentCodeV2 {
    handle: EnrollmentHandleV2,
    profile: EnrollmentProfileIdV2,
    principal: PrincipalIdV2,
    ceremony_expires_at: UnixMillisV2,
}

impl ConsumedEnrollmentCodeV2 {
    pub const fn handle(self) -> EnrollmentHandleV2 {
        self.handle
    }

    pub const fn profile(self) -> EnrollmentProfileIdV2 {
        self.profile
    }

    pub const fn principal(self) -> PrincipalIdV2 {
        self.principal
    }

    pub const fn ceremony_expires_at(self) -> UnixMillisV2 {
        self.ceremony_expires_at
    }
}

const AGENT_AUTH_INITIAL_TRANSFER_DOMAIN_V2: &[u8] =
    b"SAVANA_AGENT_AUTH_INITIAL_TRANSFER_RECORD_V2\0";
const AGENT_AUTH_CEREMONY_DOMAIN_V2: &[u8] = b"SAVANA_AGENT_AUTH_CEREMONY_RECORD_V2\0";
const AGENT_AUTH_TERMINAL_TRANSACTION_DOMAIN_V2: &[u8] =
    b"SAVANA_AGENT_AUTH_TERMINAL_TRANSACTION_V2\0";
const AGENT_AUTH_DENYLIST_TOMBSTONE_DOMAIN_V2: &[u8] = b"SAVANA_AGENT_AUTH_DENYLIST_TOMBSTONE_V2\0";
const AGENT_AUTH_JOURNAL_HEAD_DOMAIN_V2: &[u8] = b"SAVANA_AGENT_AUTH_APPROVALD_JOURNAL_HEAD_V2\0";
const AGENT_AUTH_CLOSURE_PROOF_TTL_MS_V2: u64 = 5 * 60 * 1_000;
const ENROLLMENT_CODE_DIGEST_DOMAIN_V2: &[u8] = b"SAVANA_ENROLLMENT_CODE_DIGEST_V2\0";

/// Protocol-owned approval and UI-authentication authority.
///
/// This service accepts only the signed envelope types defined by
/// `savana-kernel-protocol`; it never reparses them into a weaker local wire
/// shape. Every successful WebAuthn ceremony advances the credential counter
/// before the signed settlement can be returned.
#[derive(Clone)]
pub struct ProtocolApprovalServiceV2 {
    installation_id: Digest32V2,
    active_state_manifest_digest: Digest32V2,
    deployment_generation: u64,
    approvald_boot_id: BootIdV2,
    settlement_key_epoch: u64,
    approvald_endpoint_identity: ServiceIdentityV2,
    kernel_envelope_key_id: Ed25519KeyIdV2,
    kernel_envelope_public_key: [u8; 32],
    kernel_correlation_key_id: Ed25519KeyIdV2,
    kernel_correlation_public_key: [u8; 32],
    settlement_key_id: Ed25519KeyIdV2,
    settlement_signing_key: SigningKey,
    enrollment_profiles: Vec<EnrollmentProfilePolicyV2>,
    credentials: Vec<ActiveHardwareCredentialV2>,
    enrollment_codes: Vec<EnrollmentCodeRecordV2>,
    approval_envelopes: Vec<ProtocolApprovalRecordV2>,
    ui_authentication_envelopes: Vec<ProtocolUiAuthenticationRecordV2>,
    agent_authentication_denylist: Vec<AgentAuthenticationDenylistRecordV2>,
    complete_index_generation: u64,
    journal_head_digest: Digest32V2,
    maximum_records: usize,
}

impl std::fmt::Debug for ProtocolApprovalServiceV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProtocolApprovalServiceV2")
            .field("deployment_generation", &self.deployment_generation)
            .field("credentials", &self.credentials.len())
            .field("approval_envelopes", &self.approval_envelopes.len())
            .field(
                "ui_authentication_envelopes",
                &self.ui_authentication_envelopes.len(),
            )
            .field(
                "agent_authentication_denylist",
                &self.agent_authentication_denylist.len(),
            )
            .finish_non_exhaustive()
    }
}

impl ProtocolApprovalServiceV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn from_verified_deployment(
        installation_id: Digest32V2,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
        approvald_boot_id: BootIdV2,
        settlement_key_epoch: u64,
        approvald_endpoint_identity: ServiceIdentityV2,
        kernel_envelope_key_id: Ed25519KeyIdV2,
        kernel_envelope_public_key: [u8; 32],
        kernel_correlation_key_id: Ed25519KeyIdV2,
        kernel_correlation_public_key: [u8; 32],
        settlement_key_id: Ed25519KeyIdV2,
        settlement_signing_seed: [u8; 32],
        maximum_records: usize,
    ) -> Result<Self, ApprovalErrorV2> {
        let settlement_signing_key = SigningKey::from_bytes(&settlement_signing_seed);
        if installation_id.as_bytes() == &[0; 32]
            || active_state_manifest_digest.as_bytes() == &[0; 32]
            || deployment_generation == 0
            || approvald_boot_id.as_bytes() == &[0; 32]
            || settlement_key_epoch == 0
            || approvald_endpoint_identity.as_bytes() == &[0; 32]
            || kernel_envelope_public_key == [0; 32]
            || kernel_correlation_public_key == [0; 32]
            || settlement_signing_seed == [0; 32]
            || derive_ed25519_key_id_v2(kernel_envelope_public_key) != kernel_envelope_key_id
            || derive_ed25519_key_id_v2(kernel_correlation_public_key) != kernel_correlation_key_id
            || kernel_correlation_key_id == kernel_envelope_key_id
            || derive_ed25519_key_id_v2(settlement_signing_key.verifying_key().to_bytes())
                != settlement_key_id
            || maximum_records == 0
        {
            return Err(ApprovalErrorV2::InvalidCredential);
        }
        Ok(Self {
            installation_id,
            active_state_manifest_digest,
            deployment_generation,
            approvald_boot_id,
            settlement_key_epoch,
            approvald_endpoint_identity,
            kernel_envelope_key_id,
            kernel_envelope_public_key,
            kernel_correlation_key_id,
            kernel_correlation_public_key,
            settlement_key_id,
            settlement_signing_key,
            enrollment_profiles: Vec::new(),
            credentials: Vec::new(),
            enrollment_codes: Vec::new(),
            approval_envelopes: Vec::new(),
            ui_authentication_envelopes: Vec::new(),
            agent_authentication_denylist: Vec::new(),
            complete_index_generation: 0,
            journal_head_digest: Digest32V2::new([0; 32]),
            maximum_records,
        })
    }

    pub fn load_verified_enrollment_profile(
        &mut self,
        profile: EnrollmentProfileIdV2,
        code_lifetime_ms: u64,
        ceremony_lifetime_ms: u64,
    ) -> Result<(), ApprovalErrorV2> {
        if profile.get() == 0
            || code_lifetime_ms == 0
            || ceremony_lifetime_ms == 0
            || self.enrollment_profiles.len() >= 64
            || self
                .enrollment_profiles
                .iter()
                .any(|candidate| candidate.profile == profile)
        {
            return Err(ApprovalErrorV2::InvalidCredential);
        }
        self.enrollment_profiles
            .try_reserve(1)
            .map_err(|_| ApprovalErrorV2::AllocationFailure)?;
        self.enrollment_profiles.push(EnrollmentProfilePolicyV2 {
            profile,
            code_lifetime_ms,
            ceremony_lifetime_ms,
        });
        Ok(())
    }

    pub fn create_enrollment_code(
        &mut self,
        profile: EnrollmentProfileIdV2,
        client_request_nonce: savana_kernel_protocol::v2::Nonce32V2,
        now: UnixMillisV2,
    ) -> Result<CreateEnrollmentCodeResponseV2, ApprovalErrorV2> {
        if client_request_nonce.as_bytes() == &[0; 32]
            || self
                .enrollment_codes
                .iter()
                .any(|record| record.client_request_nonce == client_request_nonce)
        {
            return Err(ApprovalErrorV2::AlreadyConsumed);
        }
        let policy = self
            .enrollment_profiles
            .iter()
            .find(|candidate| candidate.profile == profile)
            .copied()
            .ok_or(ApprovalErrorV2::InvalidCredential)?;
        if self.credentials.len() + self.enrollment_codes.len() >= self.maximum_records {
            return Err(ApprovalErrorV2::AllocationFailure);
        }
        let expires_at = UnixMillisV2::new(
            now.get()
                .checked_add(policy.code_lifetime_ms)
                .ok_or(ApprovalErrorV2::InvalidChallenge)?,
        );
        let handle = EnrollmentHandleV2::from_authority_entropy(random_nonzero_bytes()?)
            .ok_or(ApprovalErrorV2::AllocationFailure)?;
        let principal = PrincipalIdV2::new(random_nonzero_bytes()?);
        let code = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random_nonzero_bytes()?);
        let code = ZeroizingTextV2::new(code).map_err(|_| ApprovalErrorV2::AllocationFailure)?;
        let code_digest = enrollment_code_digest(handle, code.as_str())?;
        self.enrollment_codes
            .try_reserve(1)
            .map_err(|_| ApprovalErrorV2::AllocationFailure)?;
        self.enrollment_codes.push(EnrollmentCodeRecordV2 {
            handle,
            profile,
            principal,
            client_request_nonce,
            code_digest,
            expires_at,
            consumed: false,
            credential_digest: None,
        });
        CreateEnrollmentCodeResponseV2::new(handle, code, expires_at)
            .map_err(|_| ApprovalErrorV2::AllocationFailure)
    }

    pub fn consume_enrollment_code(
        &mut self,
        handle: EnrollmentHandleV2,
        code: &ZeroizingTextV2,
        now: UnixMillisV2,
    ) -> Result<ConsumedEnrollmentCodeV2, ApprovalErrorV2> {
        let index = self
            .enrollment_codes
            .iter()
            .position(|record| record.handle == handle)
            .ok_or(ApprovalErrorV2::InvalidChallenge)?;
        let record = &self.enrollment_codes[index];
        if record.consumed
            || now.get() >= record.expires_at.get()
            || enrollment_code_digest(handle, code.as_str())? != record.code_digest
        {
            return Err(ApprovalErrorV2::AlreadyConsumed);
        }
        let policy = self
            .enrollment_profiles
            .iter()
            .find(|candidate| candidate.profile == record.profile)
            .copied()
            .ok_or(ApprovalErrorV2::InvalidCredential)?;
        let ceremony_expires_at = UnixMillisV2::new(
            now.get()
                .checked_add(policy.ceremony_lifetime_ms)
                .ok_or(ApprovalErrorV2::InvalidChallenge)?,
        );
        let record = &mut self.enrollment_codes[index];
        record.consumed = true;
        Ok(ConsumedEnrollmentCodeV2 {
            handle,
            profile: record.profile,
            principal: record.principal,
            ceremony_expires_at,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn register_enrolled_hardware_credential(
        &mut self,
        enrollment: EnrollmentHandleV2,
        credential_digest: Digest32V2,
        aaguid: [u8; 16],
        p256_sec1_public_key: [u8; 65],
        signature_counter: u32,
    ) -> Result<CredentialPublicStateV2, ApprovalErrorV2> {
        let index = self
            .enrollment_codes
            .iter()
            .position(|record| record.handle == enrollment)
            .ok_or(ApprovalErrorV2::InvalidChallenge)?;
        if !self.enrollment_codes[index].consumed
            || self.enrollment_codes[index].credential_digest.is_some()
        {
            return Err(ApprovalErrorV2::AlreadyConsumed);
        }
        let principal = self.enrollment_codes[index].principal;
        self.load_verified_hardware_credential(
            credential_digest,
            principal,
            aaguid,
            p256_sec1_public_key,
            signature_counter,
        )?;
        self.enrollment_codes[index].credential_digest = Some(credential_digest);
        Ok(CredentialPublicStateV2::Active)
    }

    pub fn revoke_credential(
        &mut self,
        credential_digest: Digest32V2,
        _reason: ClosedCredentialRevocationReasonV2,
    ) -> Result<CredentialPublicStateV2, ApprovalErrorV2> {
        let credential = self
            .credentials
            .iter_mut()
            .find(|credential| credential.credential_digest == credential_digest)
            .ok_or(ApprovalErrorV2::InvalidCredential)?;
        credential.revoke();
        Ok(CredentialPublicStateV2::Revoked)
    }

    pub fn load_verified_hardware_credential(
        &mut self,
        credential_digest: Digest32V2,
        principal: PrincipalIdV2,
        aaguid: [u8; 16],
        p256_sec1_public_key: [u8; 65],
        signature_counter: u32,
    ) -> Result<(), ApprovalErrorV2> {
        if self
            .credentials
            .iter()
            .any(|credential| credential.credential_digest == credential_digest)
        {
            return Err(ApprovalErrorV2::InvalidCredential);
        }
        if self.credentials.len() >= self.maximum_records {
            return Err(ApprovalErrorV2::AllocationFailure);
        }
        let credential = ActiveHardwareCredentialV2::from_verified_enrollment(
            credential_digest,
            principal,
            aaguid,
            p256_sec1_public_key,
            signature_counter,
        )?;
        self.credentials
            .try_reserve(1)
            .map_err(|_| ApprovalErrorV2::AllocationFailure)?;
        self.credentials.push(credential);
        Ok(())
    }

    pub fn register_approval_envelope(
        &mut self,
        envelope: &ProtocolSignedApprovalEnvelopeV2,
        now: UnixMillisV2,
    ) -> Result<Digest32V2, ApprovalErrorV2> {
        let unsigned = envelope
            .verify_for_approval_service(
                self.kernel_envelope_key_id,
                self.kernel_envelope_public_key,
                self.installation_id,
                self.active_state_manifest_digest,
                self.deployment_generation,
                self.approvald_endpoint_identity,
                now,
            )
            .map_err(|_| ApprovalErrorV2::InvalidEnvelopeSignature)?;
        let envelope_digest = envelope
            .envelope_digest()
            .map_err(|_| ApprovalErrorV2::NonCanonicalEnvelope)?;
        let canonical_envelope = encode_signed_approval_envelope_v2(envelope)
            .map_err(|_| ApprovalErrorV2::NonCanonicalEnvelope)?;
        if let Some(existing) = self
            .approval_envelopes
            .iter()
            .find(|record| record.envelope_digest == envelope_digest)
        {
            if existing.canonical_envelope != canonical_envelope {
                return Err(ApprovalErrorV2::InvalidChallenge);
            }
            return Ok(envelope_digest);
        }
        if self.total_envelope_count() >= self.maximum_records
            || self.envelope_nonce_is_registered(unsigned.envelope_nonce())
        {
            return Err(ApprovalErrorV2::InvalidChallenge);
        }
        self.approval_envelopes
            .try_reserve(1)
            .map_err(|_| ApprovalErrorV2::AllocationFailure)?;
        self.approval_envelopes.push(ProtocolApprovalRecordV2 {
            unsigned,
            envelope_digest,
            canonical_envelope,
            settlement: None,
        });
        Ok(envelope_digest)
    }

    pub fn settle_approval(
        &mut self,
        envelope_digest: Digest32V2,
        decision: ProtocolApprovalDecisionV2,
        assertion: &WebAuthnAssertionV2,
        now: UnixMillisV2,
    ) -> Result<ProtocolSignedApprovalSettlementV2, ApprovalErrorV2> {
        let record_index = self
            .approval_envelopes
            .iter()
            .position(|record| record.envelope_digest == envelope_digest)
            .ok_or(ApprovalErrorV2::InvalidChallenge)?;
        if self.approval_envelopes[record_index].settlement.is_some() {
            return Err(ApprovalErrorV2::AlreadyConsumed);
        }
        let unsigned = &self.approval_envelopes[record_index].unsigned;
        if unsigned
            .display_declassification_provenance_digest()
            .is_none()
        {
            return Err(ApprovalErrorV2::InvalidChallenge);
        }
        let credential_index = self.credential_index(assertion)?;
        let legacy_purpose = match unsigned.purpose() {
            ProtocolApprovalPurposeV2::TaskAuthorization => ApprovalPurposeV2::TaskAuthorization,
            savana_kernel_protocol::v2::ApprovalPurposeV2::Ingress => ApprovalPurposeV2::Ingress,
            savana_kernel_protocol::v2::ApprovalPurposeV2::ToolExecution => {
                ApprovalPurposeV2::ToolExecution
            }
            savana_kernel_protocol::v2::ApprovalPurposeV2::FinalRelease => {
                ApprovalPurposeV2::FinalRelease
            }
            savana_kernel_protocol::v2::ApprovalPurposeV2::ConnectorRegistration => {
                ApprovalPurposeV2::ConnectorRegistration
            }
        };
        let challenge = ApprovalDecisionChallengeV2::from_verified_envelope(
            legacy_purpose,
            envelope_digest,
            unsigned.expected_principal(),
            unsigned.decision_challenge(),
            unsigned.issued_at(),
            unsigned.expires_at(),
        )?;
        let verified = verify_approval_decision_assertion(
            challenge,
            &self.credentials[credential_index],
            assertion,
            now,
        )?;
        let settlement_nonce = random_nonce()?;
        let expires_at = bounded_settlement_expiry(now, unsigned.expires_at())?;
        let settlement = ProtocolSignedApprovalSettlementV2::sign(
            UnsignedApprovalSettlementV2::new(
                self.installation_id,
                self.active_state_manifest_digest,
                self.deployment_generation,
                unsigned.purpose(),
                envelope_digest,
                decision,
                verified.authenticated_principal(),
                verified.authentication_context_digest(),
                verified.credential_digest(),
                true,
                true,
                false,
                false,
                verified.signature_counter(),
                unsigned.decision_challenge(),
                settlement_nonce,
                now,
                expires_at,
            )
            .map_err(|_| ApprovalErrorV2::NonCanonicalEnvelope)?,
            &self.settlement_signing_key,
        )
        .map_err(|_| ApprovalErrorV2::InvalidEnvelopeSignature)?;
        self.credentials[credential_index].signature_counter = verified.signature_counter();
        self.approval_envelopes[record_index].settlement = Some(settlement.clone());
        Ok(settlement)
    }

    pub fn approval_challenge(
        &self,
        envelope_digest: Digest32V2,
        now: UnixMillisV2,
    ) -> Result<ApprovalChallengeProjectionV2, ApprovalErrorV2> {
        let record = self
            .approval_envelopes
            .iter()
            .find(|record| record.envelope_digest == envelope_digest)
            .ok_or(ApprovalErrorV2::InvalidChallenge)?;
        if record.settlement.is_some() {
            return Err(ApprovalErrorV2::AlreadyConsumed);
        }
        if now.get() < record.unsigned.issued_at().get()
            || now.get() >= record.unsigned.expires_at().get()
        {
            return Err(ApprovalErrorV2::InvalidChallenge);
        }
        Ok(ApprovalChallengeProjectionV2 {
            purpose: record.unsigned.purpose(),
            envelope_digest,
            expected_principal: record.unsigned.expected_principal(),
            challenge: record.unsigned.decision_challenge(),
            display_projection_digest: record.unsigned.display_projection_digest(),
            display_digest: record.unsigned.display_digest(),
            display_text: record.unsigned.display_text().clone(),
            display_declassification_provenance_digest: record
                .unsigned
                .display_declassification_provenance_digest(),
            expires_at: record.unsigned.expires_at(),
        })
    }

    pub fn approval_settlement_view(
        &self,
        envelope_digest: Digest32V2,
        now: UnixMillisV2,
    ) -> Result<ApprovalSettlementViewV2, ApprovalErrorV2> {
        let record = self
            .approval_envelopes
            .iter()
            .find(|record| record.envelope_digest == envelope_digest)
            .ok_or(ApprovalErrorV2::InvalidChallenge)?;
        match &record.settlement {
            Some(settlement)
                if settlement.unsigned().decision() == ProtocolApprovalDecisionV2::Approve =>
            {
                Ok(ApprovalSettlementViewV2::Approved {
                    settlement: settlement.clone(),
                })
            }
            Some(settlement) => Ok(ApprovalSettlementViewV2::Denied {
                settlement: settlement.clone(),
            }),
            None if now.get() >= record.unsigned.expires_at().get() => {
                Ok(ApprovalSettlementViewV2::Expired)
            }
            None => Ok(ApprovalSettlementViewV2::Pending),
        }
    }

    pub fn register_ui_authentication_envelope(
        &mut self,
        envelope: &ProtocolSignedUiAuthenticationEnvelopeV2,
        now: UnixMillisV2,
    ) -> Result<Digest32V2, ApprovalErrorV2> {
        let unsigned = envelope
            .verify(
                self.kernel_envelope_key_id,
                self.kernel_envelope_public_key,
                self.installation_id,
                self.active_state_manifest_digest,
                self.deployment_generation,
                now,
            )
            .map_err(|_| ApprovalErrorV2::InvalidEnvelopeSignature)?;
        let envelope_digest = envelope
            .envelope_digest()
            .map_err(|_| ApprovalErrorV2::NonCanonicalEnvelope)?;
        let canonical_envelope = encode_signed_ui_authentication_envelope_v2(envelope)
            .map_err(|_| ApprovalErrorV2::NonCanonicalEnvelope)?;
        if self.agent_authentication_denylist.iter().any(|record| {
            record.denylisted
                && (record.envelope_digest == envelope_digest
                    || record.auth_attempt_nonce == unsigned.envelope_nonce())
        }) {
            return Err(ApprovalErrorV2::AlreadyConsumed);
        }
        if let Some(existing) = self
            .ui_authentication_envelopes
            .iter()
            .find(|record| record.envelope_digest == envelope_digest)
        {
            if existing.canonical_envelope != canonical_envelope {
                return Err(ApprovalErrorV2::InvalidChallenge);
            }
            return Ok(envelope_digest);
        }
        if self.total_envelope_count() >= self.maximum_records
            || self.envelope_nonce_is_registered(unsigned.envelope_nonce())
        {
            return Err(ApprovalErrorV2::InvalidChallenge);
        }
        self.ui_authentication_envelopes
            .try_reserve(1)
            .map_err(|_| ApprovalErrorV2::AllocationFailure)?;
        self.ui_authentication_envelopes
            .push(ProtocolUiAuthenticationRecordV2 {
                unsigned,
                envelope_digest,
                canonical_envelope,
                settlement: None,
            });
        Ok(envelope_digest)
    }

    pub(crate) fn register_approval_pair(
        &mut self,
        role: EndpointRoleV2,
        envelope: &ProtocolSignedApprovalEnvelopeV2,
        display_authentication: &ProtocolSignedUiAuthenticationEnvelopeV2,
        now: UnixMillisV2,
    ) -> Result<(Digest32V2, Digest32V2, ProtocolApprovalPurposeV2), ApprovalErrorV2> {
        // Validate both signed purposes and their complete pairing before adding
        // any record. The state owner additionally commits the pair atomically.
        let approval = envelope
            .verify_for_approval_service(
                self.kernel_envelope_key_id,
                self.kernel_envelope_public_key,
                self.installation_id,
                self.active_state_manifest_digest,
                self.deployment_generation,
                self.approvald_endpoint_identity,
                now,
            )
            .map_err(|_| ApprovalErrorV2::InvalidEnvelopeSignature)?;
        let display = display_authentication
            .verify(
                self.kernel_envelope_key_id,
                self.kernel_envelope_public_key,
                self.installation_id,
                self.active_state_manifest_digest,
                self.deployment_generation,
                now,
            )
            .map_err(|_| ApprovalErrorV2::InvalidEnvelopeSignature)?;
        let approval_digest = envelope
            .envelope_digest()
            .map_err(|_| ApprovalErrorV2::NonCanonicalEnvelope)?;
        let role_matches = matches!(
            (role, approval.purpose()),
            (
                EndpointRoleV2::IngressApproval,
                ProtocolApprovalPurposeV2::Ingress | ProtocolApprovalPurposeV2::TaskAuthorization
            ) | (
                EndpointRoleV2::AgentApproval,
                ProtocolApprovalPurposeV2::ToolExecution
                    | ProtocolApprovalPurposeV2::FinalRelease
                    | ProtocolApprovalPurposeV2::ConnectorRegistration
            )
        );
        let binding_matches = matches!(
            display.binding(),
            UiAuthenticationBindingV2::ApprovalDisplay {
                durable_task_id,
                approval_envelope_digest,
                approval_purpose,
                display_digest,
            } if approval_envelope_digest == approval_digest
                && approval_purpose == approval.purpose()
                && display_digest == approval.display_digest()
                && match approval.binding() {
                    savana_kernel_protocol::v2::ApprovalBindingV2::TaskAuthorization { task, .. } => task == durable_task_id,
                    _ => true,
                }
        );
        if display.purpose() != UiAuthenticationPurposeV2::ApprovalDisplay
            || display.expected_principal() != Some(approval.expected_principal())
            || !role_matches
            || !binding_matches
        {
            return Err(ApprovalErrorV2::InvalidChallenge);
        }
        self.register_approval_envelope(envelope, now)?;
        let display_digest =
            self.register_ui_authentication_envelope(display_authentication, now)?;
        Ok((approval_digest, display_digest, approval.purpose()))
    }

    pub fn settle_ui_authentication(
        &mut self,
        envelope_digest: Digest32V2,
        assertion: &WebAuthnAssertionV2,
        now: UnixMillisV2,
    ) -> Result<ProtocolSignedUiAuthenticationSettlementV2, ApprovalErrorV2> {
        let record_index = self
            .ui_authentication_envelopes
            .iter()
            .position(|record| record.envelope_digest == envelope_digest)
            .ok_or(ApprovalErrorV2::InvalidChallenge)?;
        if self.ui_authentication_envelopes[record_index]
            .settlement
            .is_some()
        {
            return Err(ApprovalErrorV2::AlreadyConsumed);
        }
        let unsigned = self.ui_authentication_envelopes[record_index].unsigned;
        let credential_index = self.credential_index(assertion)?;
        let expected_principal = unsigned
            .expected_principal()
            .unwrap_or(self.credentials[credential_index].principal);
        let verified = verify_ui_authentication_assertion(
            unsigned.purpose(),
            envelope_digest,
            expected_principal,
            unsigned.envelope_nonce(),
            unsigned.issued_at(),
            unsigned.expires_at(),
            &self.credentials[credential_index],
            assertion,
            now,
        )?;
        let settlement_nonce = random_nonce()?;
        let expires_at = bounded_settlement_expiry(now, unsigned.expires_at())?;
        let settlement = ProtocolSignedUiAuthenticationSettlementV2::sign(
            UnsignedUiAuthenticationSettlementV2::new(
                self.installation_id,
                self.active_state_manifest_digest,
                self.deployment_generation,
                unsigned.purpose(),
                envelope_digest,
                unsigned
                    .binding_digest()
                    .map_err(|_| ApprovalErrorV2::NonCanonicalEnvelope)?,
                FixedOriginV2::Approval8766,
                unsigned.return_origin(),
                verified.authenticated_principal,
                verified.authentication_context_digest,
                verified.credential_digest,
                true,
                true,
                false,
                false,
                verified.signature_counter,
                unsigned.envelope_nonce(),
                settlement_nonce,
                now,
                expires_at,
            )
            .map_err(|_| ApprovalErrorV2::NonCanonicalEnvelope)?,
            &self.settlement_signing_key,
        )
        .map_err(|_| ApprovalErrorV2::InvalidEnvelopeSignature)?;
        self.credentials[credential_index].signature_counter = verified.signature_counter;
        self.ui_authentication_envelopes[record_index].settlement = Some(settlement.clone());
        Ok(settlement)
    }

    pub fn ui_authentication_challenge(
        &self,
        envelope_digest: Digest32V2,
        now: UnixMillisV2,
    ) -> Result<UiAuthenticationChallengeProjectionV2, ApprovalErrorV2> {
        let record = self
            .ui_authentication_envelopes
            .iter()
            .find(|record| record.envelope_digest == envelope_digest)
            .ok_or(ApprovalErrorV2::InvalidChallenge)?;
        if record.settlement.is_some() {
            return Err(ApprovalErrorV2::AlreadyConsumed);
        }
        if now.get() < record.unsigned.issued_at().get()
            || now.get() >= record.unsigned.expires_at().get()
        {
            return Err(ApprovalErrorV2::InvalidChallenge);
        }
        Ok(UiAuthenticationChallengeProjectionV2 {
            purpose: record.unsigned.purpose(),
            envelope_digest,
            binding: record.unsigned.binding(),
            expected_principal: record.unsigned.expected_principal(),
            challenge: record.unsigned.envelope_nonce(),
            expires_at: record.unsigned.expires_at(),
        })
    }

    pub fn close_agent_authentication_attempt(
        &mut self,
        descriptor: &SignedAgentAuthenticationClosureDescriptorV2,
        caller_identity: ServiceIdentityV2,
        now: UnixMillisV2,
    ) -> Result<SignedAgentAuthenticationAttemptClosureProofV2, ApprovalErrorV2> {
        let unsigned = descriptor
            .verify(
                self.kernel_correlation_key_id,
                self.kernel_correlation_public_key,
                now,
            )
            .map_err(|_| ApprovalErrorV2::InvalidEnvelopeSignature)?;
        if unsigned.installation_id() != self.installation_id
            || unsigned.closure_issuing_manifest_digest() != self.active_state_manifest_digest
            || unsigned.closure_issuing_deployment_generation() != self.deployment_generation
            || unsigned.approvald_identity() != self.approvald_endpoint_identity
            || unsigned.agentd_identity() != caller_identity
        {
            return Err(ApprovalErrorV2::InvalidChallenge);
        }
        let descriptor_digest = descriptor
            .descriptor_digest()
            .map_err(|_| ApprovalErrorV2::NonCanonicalEnvelope)?;
        if let Some(existing) = self.agent_authentication_denylist.iter().find(|record| {
            record.envelope_digest == unsigned.authentication_envelope_digest()
                && record.auth_attempt_nonce == unsigned.auth_attempt_nonce()
        }) {
            if existing.proof.unsigned().closure_descriptor_digest() != descriptor_digest {
                return Err(ApprovalErrorV2::InvalidChallenge);
            }
            return Ok(existing.proof.clone());
        }
        if self.total_envelope_count() + self.agent_authentication_denylist.len()
            >= self.maximum_records
        {
            return Err(ApprovalErrorV2::AllocationFailure);
        }

        let registered = self
            .ui_authentication_envelopes
            .iter()
            .find(|record| record.envelope_digest == unsigned.authentication_envelope_digest());
        if let Some(record) = registered {
            if record.unsigned.purpose() != UiAuthenticationPurposeV2::AgentContent
                || record.unsigned.active_state_manifest_digest()
                    != unsigned.attempt_manifest_digest()
                || record.unsigned.deployment_generation()
                    != unsigned.attempt_deployment_generation()
                || record.unsigned.envelope_nonce() != unsigned.auth_attempt_nonce()
                || record.unsigned.expected_principal() != Some(unsigned.authenticated_principal())
                || record.unsigned.binding()
                    != (UiAuthenticationBindingV2::AgentContent {
                        durable_task_id: unsigned.durable_task_id(),
                        ingress_claim_digest: unsigned.claim_commitment_digest(),
                        agentd_identity: unsigned.agentd_identity(),
                        agentd_boot_id: unsigned.originating_agentd_boot_id(),
                    })
            {
                return Err(ApprovalErrorV2::InvalidChallenge);
            }
        }

        let next_generation = self
            .complete_index_generation
            .checked_add(1)
            .ok_or(ApprovalErrorV2::DurableState)?;
        let initial_transfer_digest = closure_record_digest(
            AGENT_AUTH_INITIAL_TRANSFER_DOMAIN_V2,
            &[
                unsigned.authentication_envelope_digest().as_bytes(),
                unsigned.auth_attempt_nonce().as_bytes(),
            ],
        );
        let ceremony_digest = closure_record_digest(
            AGENT_AUTH_CEREMONY_DOMAIN_V2,
            &[
                unsigned.authentication_envelope_digest().as_bytes(),
                unsigned.authentication_recovery_record_digest().as_bytes(),
            ],
        );
        let terminal_transaction_digest = closure_record_digest(
            AGENT_AUTH_TERMINAL_TRANSACTION_DOMAIN_V2,
            &[descriptor_digest.as_bytes(), &next_generation.to_be_bytes()],
        );
        let denylisted = registered.is_none_or(|record| record.settlement.is_none());
        let tombstone_sequence = if denylisted { next_generation } else { 0 };
        let tombstone_digest = if denylisted {
            closure_record_digest(
                AGENT_AUTH_DENYLIST_TOMBSTONE_DOMAIN_V2,
                &[
                    unsigned.authentication_envelope_digest().as_bytes(),
                    unsigned.auth_attempt_nonce().as_bytes(),
                    descriptor_digest.as_bytes(),
                    &tombstone_sequence.to_be_bytes(),
                ],
            )
        } else {
            Digest32V2::new([0; 32])
        };
        let next_journal_head = closure_record_digest(
            AGENT_AUTH_JOURNAL_HEAD_DOMAIN_V2,
            &[
                self.journal_head_digest.as_bytes(),
                descriptor_digest.as_bytes(),
                terminal_transaction_digest.as_bytes(),
                &next_generation.to_be_bytes(),
            ],
        );
        let evidence = match registered {
            None => AgentAuthenticationClosureEvidenceV2::NeverRegisteredDenylisted {
                complete_index_generation: next_generation,
                current_journal_head_digest: next_journal_head,
                denylist_tombstone_sequence: tombstone_sequence,
                denylist_tombstone_digest: tombstone_digest,
                approvald_key_epoch: self.settlement_key_epoch,
            },
            Some(record) if record.settlement.is_none() => {
                let transfer_state = AgentAuthenticationTransferTerminalStateV2::new(
                    initial_transfer_digest,
                    AgentAuthenticationInitialTransferTerminalStateV2::ConsumedIntoTerminalizedCeremony,
                    Some(ceremony_digest),
                    None,
                    AgentAuthenticationSettlementTerminalStateV2::NotCreated,
                    None,
                    AgentAuthenticationSettlementTransferTerminalStateV2::NotCreated,
                )
                .map_err(|_| ApprovalErrorV2::DurableState)?;
                AgentAuthenticationClosureEvidenceV2::RegisteredInvalidatedUnredeemed {
                    approval_record_digest: unsigned.authentication_envelope_digest(),
                    ceremony_record_digest: ceremony_digest,
                    transfer_state,
                    approvald_terminal_transaction_digest: terminal_transaction_digest,
                    complete_index_generation: next_generation,
                    current_journal_head_digest: next_journal_head,
                    denylist_tombstone_sequence: tombstone_sequence,
                    denylist_tombstone_digest: tombstone_digest,
                    approvald_key_epoch: self.settlement_key_epoch,
                }
            }
            Some(record) => {
                let settlement = record
                    .settlement
                    .as_ref()
                    .ok_or(ApprovalErrorV2::DurableState)?;
                let settlement_digest = settlement
                    .settlement_digest()
                    .map_err(|_| ApprovalErrorV2::DurableAuthentication)?;
                let transfer_state = AgentAuthenticationTransferTerminalStateV2::new(
                    initial_transfer_digest,
                    AgentAuthenticationInitialTransferTerminalStateV2::ConsumedIntoTerminalizedCeremony,
                    Some(ceremony_digest),
                    Some(settlement_digest),
                    AgentAuthenticationSettlementTerminalStateV2::ExportedOrTransferRedeemed,
                    None,
                    AgentAuthenticationSettlementTransferTerminalStateV2::Indeterminate,
                )
                .map_err(|_| ApprovalErrorV2::DurableState)?;
                AgentAuthenticationClosureEvidenceV2::SettlementOrTransferObserved {
                    approval_record_digest: unsigned.authentication_envelope_digest(),
                    ceremony_record_digest: ceremony_digest,
                    transfer_state,
                    settlement_digest,
                    complete_index_generation: next_generation,
                    current_journal_head_digest: next_journal_head,
                    approvald_key_epoch: self.settlement_key_epoch,
                }
            }
        };
        let expires_at = UnixMillisV2::new(
            now.get()
                .checked_add(AGENT_AUTH_CLOSURE_PROOF_TTL_MS_V2)
                .ok_or(ApprovalErrorV2::DurableState)?
                .min(unsigned.expires_at().get()),
        );
        if expires_at.get() <= now.get() {
            return Err(ApprovalErrorV2::InvalidChallenge);
        }
        let proof = SignedAgentAuthenticationAttemptClosureProofV2::sign(
            UnsignedAgentAuthenticationAttemptClosureProofV2::new(
                unsigned.installation_id(),
                unsigned.attempt_manifest_digest(),
                unsigned.attempt_deployment_generation(),
                unsigned.closure_issuing_manifest_digest(),
                unsigned.closure_issuing_deployment_generation(),
                unsigned.agent_claim_compatibility_edge_identity_digest(),
                unsigned.durable_task_id(),
                unsigned.durable_run_id(),
                unsigned.signed_correlation_digest(),
                unsigned.claim_commitment_digest(),
                unsigned.authenticated_principal(),
                unsigned.agentd_identity(),
                unsigned.originating_agentd_boot_id(),
                unsigned.kerneld_identity(),
                unsigned.originating_kerneld_boot_id(),
                self.approvald_endpoint_identity,
                self.approvald_boot_id,
                unsigned.authentication_recovery_record_digest(),
                unsigned.authentication_envelope_digest(),
                unsigned.auth_attempt_nonce(),
                descriptor_digest,
                evidence,
                now,
                expires_at,
            )
            .map_err(|_| ApprovalErrorV2::NonCanonicalEnvelope)?,
            &self.settlement_signing_key,
        )
        .map_err(|_| ApprovalErrorV2::InvalidEnvelopeSignature)?;
        self.agent_authentication_denylist
            .try_reserve(1)
            .map_err(|_| ApprovalErrorV2::AllocationFailure)?;
        self.complete_index_generation = next_generation;
        self.journal_head_digest = next_journal_head;
        self.agent_authentication_denylist
            .push(AgentAuthenticationDenylistRecordV2 {
                envelope_digest: unsigned.authentication_envelope_digest(),
                auth_attempt_nonce: unsigned.auth_attempt_nonce(),
                tombstone_sequence,
                tombstone_digest,
                denylisted,
                proof: proof.clone(),
            });
        Ok(proof)
    }

    pub const fn settlement_key_id(&self) -> Ed25519KeyIdV2 {
        self.settlement_key_id
    }

    pub fn settlement_public_key(&self) -> [u8; 32] {
        self.settlement_signing_key.verifying_key().to_bytes()
    }

    pub(crate) const fn installation_id(&self) -> Digest32V2 {
        self.installation_id
    }

    pub(crate) fn is_pristine(&self) -> bool {
        self.credentials.is_empty()
            && self.enrollment_codes.is_empty()
            && self.approval_envelopes.is_empty()
            && self.ui_authentication_envelopes.is_empty()
            && self.agent_authentication_denylist.is_empty()
            && self.complete_index_generation == 0
            && self.journal_head_digest == Digest32V2::new([0; 32])
    }

    pub(crate) fn encode_mutable_state(&self) -> Result<Vec<u8>, ApprovalErrorV2> {
        let mut encoder = minicbor::Encoder::new(Vec::new());
        encoder
            .array(8)
            .and_then(|encoder| encoder.u16(4))
            .and_then(|encoder| encoder.array(self.credentials.len() as u64))
            .map_err(|_| ApprovalErrorV2::AllocationFailure)?;
        for credential in &self.credentials {
            encoder
                .array(6)
                .and_then(|encoder| encoder.bytes(credential.credential_digest.as_bytes()))
                .and_then(|encoder| encoder.bytes(credential.principal.as_bytes()))
                .and_then(|encoder| encoder.bytes(&credential.aaguid))
                .and_then(|encoder| encoder.bytes(&credential.p256_sec1_public_key))
                .and_then(|encoder| encoder.u32(credential.signature_counter))
                .and_then(|encoder| encoder.bool(credential.revoked))
                .map_err(|_| ApprovalErrorV2::AllocationFailure)?;
        }
        encoder
            .array(self.approval_envelopes.len() as u64)
            .map_err(|_| ApprovalErrorV2::AllocationFailure)?;
        for record in &self.approval_envelopes {
            encoder
                .array(2)
                .and_then(|encoder| encoder.bytes(&record.canonical_envelope))
                .map_err(|_| ApprovalErrorV2::AllocationFailure)?;
            encode_optional_bytes(
                &mut encoder,
                record
                    .settlement
                    .as_ref()
                    .map(encode_signed_approval_settlement_v2)
                    .transpose()
                    .map_err(|_| ApprovalErrorV2::NonCanonicalEnvelope)?
                    .as_deref(),
            )?;
        }
        encoder
            .array(self.ui_authentication_envelopes.len() as u64)
            .map_err(|_| ApprovalErrorV2::AllocationFailure)?;
        for record in &self.ui_authentication_envelopes {
            encoder
                .array(2)
                .and_then(|encoder| encoder.bytes(&record.canonical_envelope))
                .map_err(|_| ApprovalErrorV2::AllocationFailure)?;
            encode_optional_bytes(
                &mut encoder,
                record
                    .settlement
                    .as_ref()
                    .map(encode_signed_ui_authentication_settlement_v2)
                    .transpose()
                    .map_err(|_| ApprovalErrorV2::NonCanonicalEnvelope)?
                    .as_deref(),
            )?;
        }
        encoder
            .u64(self.complete_index_generation)
            .and_then(|encoder| encoder.bytes(self.journal_head_digest.as_bytes()))
            .and_then(|encoder| encoder.array(self.agent_authentication_denylist.len() as u64))
            .map_err(|_| ApprovalErrorV2::AllocationFailure)?;
        for record in &self.agent_authentication_denylist {
            let proof = encode_signed_agent_authentication_attempt_closure_proof_v2(&record.proof)
                .map_err(|_| ApprovalErrorV2::NonCanonicalEnvelope)?;
            encoder
                .array(6)
                .and_then(|encoder| encoder.bytes(record.envelope_digest.as_bytes()))
                .and_then(|encoder| encoder.bytes(record.auth_attempt_nonce.as_bytes()))
                .and_then(|encoder| encoder.u64(record.tombstone_sequence))
                .and_then(|encoder| encoder.bytes(record.tombstone_digest.as_bytes()))
                .and_then(|encoder| encoder.bool(record.denylisted))
                .and_then(|encoder| encoder.bytes(&proof))
                .map_err(|_| ApprovalErrorV2::AllocationFailure)?;
        }
        encoder
            .array(self.enrollment_codes.len() as u64)
            .map_err(|_| ApprovalErrorV2::AllocationFailure)?;
        for record in &self.enrollment_codes {
            encoder
                .array(8)
                .map_err(|_| ApprovalErrorV2::AllocationFailure)?;
            record
                .handle
                .encode(&mut encoder, &mut ())
                .and_then(|()| record.profile.encode(&mut encoder, &mut ()))
                .and_then(|()| record.principal.encode(&mut encoder, &mut ()))
                .and_then(|()| record.client_request_nonce.encode(&mut encoder, &mut ()))
                .and_then(|()| record.code_digest.encode(&mut encoder, &mut ()))
                .and_then(|()| record.expires_at.encode(&mut encoder, &mut ()))
                .and_then(|()| encoder.bool(record.consumed))
                .map_err(|_| ApprovalErrorV2::AllocationFailure)?;
            encode_optional_bytes(
                &mut encoder,
                record
                    .credential_digest
                    .as_ref()
                    .map(|digest| digest.as_bytes().as_slice()),
            )?;
        }
        Ok(encoder.into_writer())
    }

    pub(crate) fn restore_mutable_state(
        mut deployment: Self,
        bytes: &[u8],
    ) -> Result<Self, ApprovalErrorV2> {
        if !deployment.is_pristine() || bytes.is_empty() || bytes.len() > 64 * 1024 * 1024 {
            return Err(ApprovalErrorV2::DurableState);
        }
        let mut decoder = minicbor::Decoder::new(bytes);
        let top_level = decoder
            .array()
            .map_err(|_| ApprovalErrorV2::DurableState)?
            .ok_or(ApprovalErrorV2::DurableState)?;
        let schema = decoder.u16().map_err(|_| ApprovalErrorV2::DurableState)?;
        if (schema, top_level) != (4, 8) {
            return Err(ApprovalErrorV2::DurableState);
        }
        let credential_count = decode_bounded_count(&mut decoder, deployment.maximum_records)?;
        for _ in 0..credential_count {
            require_array(&mut decoder, 6)?;
            deployment.load_verified_hardware_credential(
                Digest32V2::new(decode_fixed::<32>(&mut decoder)?),
                PrincipalIdV2::new(decode_fixed::<32>(&mut decoder)?),
                decode_fixed::<16>(&mut decoder)?,
                decode_fixed::<65>(&mut decoder)?,
                decoder.u32().map_err(|_| ApprovalErrorV2::DurableState)?,
            )?;
            if decoder.bool().map_err(|_| ApprovalErrorV2::DurableState)? {
                deployment
                    .credentials
                    .last_mut()
                    .ok_or(ApprovalErrorV2::DurableState)?
                    .revoke();
            }
        }
        let approval_count = decode_bounded_count(&mut decoder, deployment.maximum_records)?;
        for _ in 0..approval_count {
            require_array(&mut decoder, 2)?;
            let envelope_bytes = decode_bounded_bytes(&mut decoder)?;
            let envelope = decode_signed_approval_envelope_v2(envelope_bytes)
                .map_err(|_| ApprovalErrorV2::DurableState)?;
            let unsigned = envelope
                .verify_approval_service_deployment(
                    deployment.kernel_envelope_key_id,
                    deployment.kernel_envelope_public_key,
                    deployment.installation_id,
                    deployment.active_state_manifest_digest,
                    deployment.deployment_generation,
                    deployment.approvald_endpoint_identity,
                )
                .map_err(|_| ApprovalErrorV2::DurableState)?;
            let digest = deployment.register_approval_envelope(&envelope, unsigned.issued_at())?;
            let settlement_bytes = decode_optional_bounded_bytes(&mut decoder)?;
            if let Some(settlement_bytes) = settlement_bytes {
                let settlement = decode_signed_approval_settlement_v2(settlement_bytes)
                    .map_err(|_| ApprovalErrorV2::DurableState)?;
                validate_restored_approval_settlement(&deployment, unsigned, digest, &settlement)?;
                deployment
                    .approval_envelopes
                    .last_mut()
                    .ok_or(ApprovalErrorV2::DurableState)?
                    .settlement = Some(settlement);
            }
        }
        let ui_count = decode_bounded_count(&mut decoder, deployment.maximum_records)?;
        if approval_count
            .checked_add(ui_count)
            .is_none_or(|count| count > deployment.maximum_records)
        {
            return Err(ApprovalErrorV2::DurableState);
        }
        for _ in 0..ui_count {
            require_array(&mut decoder, 2)?;
            let envelope_bytes = decode_bounded_bytes(&mut decoder)?;
            let envelope = decode_signed_ui_authentication_envelope_v2(envelope_bytes)
                .map_err(|_| ApprovalErrorV2::DurableState)?;
            let unsigned = envelope
                .verify_deployment(
                    deployment.kernel_envelope_key_id,
                    deployment.kernel_envelope_public_key,
                    deployment.installation_id,
                    deployment.active_state_manifest_digest,
                    deployment.deployment_generation,
                )
                .map_err(|_| ApprovalErrorV2::DurableState)?;
            let digest =
                deployment.register_ui_authentication_envelope(&envelope, unsigned.issued_at())?;
            let settlement_bytes = decode_optional_bounded_bytes(&mut decoder)?;
            if let Some(settlement_bytes) = settlement_bytes {
                let settlement = decode_signed_ui_authentication_settlement_v2(settlement_bytes)
                    .map_err(|_| ApprovalErrorV2::DurableState)?;
                validate_restored_ui_settlement(&deployment, unsigned, digest, &settlement)?;
                deployment
                    .ui_authentication_envelopes
                    .last_mut()
                    .ok_or(ApprovalErrorV2::DurableState)?
                    .settlement = Some(settlement);
            }
        }
        deployment.complete_index_generation =
            decoder.u64().map_err(|_| ApprovalErrorV2::DurableState)?;
        deployment.journal_head_digest = Digest32V2::new(decode_fixed::<32>(&mut decoder)?);
        let closure_count = decode_bounded_count(&mut decoder, deployment.maximum_records)?;
        if approval_count
            .checked_add(ui_count)
            .and_then(|count| count.checked_add(closure_count))
            .is_none_or(|count| count > deployment.maximum_records)
            || (closure_count == 0
                && (deployment.complete_index_generation != 0
                    || deployment.journal_head_digest != Digest32V2::new([0; 32])))
            || (closure_count > 0
                && (deployment.complete_index_generation == 0
                    || deployment.journal_head_digest == Digest32V2::new([0; 32])))
        {
            return Err(ApprovalErrorV2::DurableState);
        }
        deployment
            .agent_authentication_denylist
            .try_reserve_exact(closure_count)
            .map_err(|_| ApprovalErrorV2::AllocationFailure)?;
        for _ in 0..closure_count {
            require_array(&mut decoder, 6)?;
            let envelope_digest = Digest32V2::new(decode_fixed::<32>(&mut decoder)?);
            let auth_attempt_nonce =
                savana_kernel_protocol::v2::Nonce32V2::new(decode_fixed::<32>(&mut decoder)?);
            let tombstone_sequence = decoder.u64().map_err(|_| ApprovalErrorV2::DurableState)?;
            let tombstone_digest = Digest32V2::new(decode_fixed::<32>(&mut decoder)?);
            let denylisted = decoder.bool().map_err(|_| ApprovalErrorV2::DurableState)?;
            let proof = decode_signed_agent_authentication_attempt_closure_proof_v2(
                decode_bounded_bytes(&mut decoder)?,
            )
            .map_err(|_| ApprovalErrorV2::DurableAuthentication)?;
            let proof_unsigned = proof
                .verify(
                    deployment.settlement_key_id,
                    deployment.settlement_public_key(),
                    proof.unsigned().issued_at(),
                )
                .map_err(|_| ApprovalErrorV2::DurableAuthentication)?;
            if proof_unsigned.installation_id() != deployment.installation_id
                || proof_unsigned.closure_issuing_manifest_digest()
                    != deployment.active_state_manifest_digest
                || proof_unsigned.closure_issuing_deployment_generation()
                    != deployment.deployment_generation
                || proof_unsigned.approvald_identity() != deployment.approvald_endpoint_identity
                || proof_unsigned.approvald_boot_id() != deployment.approvald_boot_id
                || proof_unsigned.authentication_envelope_digest() != envelope_digest
                || proof_unsigned.auth_attempt_nonce() != auth_attempt_nonce
                || (denylisted
                    && (tombstone_sequence == 0 || tombstone_digest == Digest32V2::new([0; 32])))
                || (!denylisted
                    && (tombstone_sequence != 0 || tombstone_digest != Digest32V2::new([0; 32])))
            {
                return Err(ApprovalErrorV2::DurableState);
            }
            deployment
                .agent_authentication_denylist
                .push(AgentAuthenticationDenylistRecordV2 {
                    envelope_digest,
                    auth_attempt_nonce,
                    tombstone_sequence,
                    tombstone_digest,
                    denylisted,
                    proof,
                });
        }
        let enrollment_count = decode_bounded_count(&mut decoder, deployment.maximum_records)?;
        if enrollment_count
            .checked_add(deployment.credentials.len())
            .is_none_or(|count| count > deployment.maximum_records)
        {
            return Err(ApprovalErrorV2::DurableState);
        }
        deployment
            .enrollment_codes
            .try_reserve_exact(enrollment_count)
            .map_err(|_| ApprovalErrorV2::AllocationFailure)?;
        for _ in 0..enrollment_count {
            require_array(&mut decoder, 8)?;
            let mut context = savana_kernel_protocol::v2::V2DecodeContext;
            let handle = EnrollmentHandleV2::decode(&mut decoder, &mut context)
                .map_err(|_| ApprovalErrorV2::DurableState)?;
            let profile = EnrollmentProfileIdV2::decode(&mut decoder, &mut context)
                .map_err(|_| ApprovalErrorV2::DurableState)?;
            let principal = PrincipalIdV2::decode(&mut decoder, &mut context)
                .map_err(|_| ApprovalErrorV2::DurableState)?;
            let client_request_nonce =
                savana_kernel_protocol::v2::Nonce32V2::decode(&mut decoder, &mut context)
                    .map_err(|_| ApprovalErrorV2::DurableState)?;
            let code_digest = Digest32V2::decode(&mut decoder, &mut context)
                .map_err(|_| ApprovalErrorV2::DurableState)?;
            let expires_at = UnixMillisV2::decode(&mut decoder, &mut context)
                .map_err(|_| ApprovalErrorV2::DurableState)?;
            let consumed = decoder.bool().map_err(|_| ApprovalErrorV2::DurableState)?;
            let credential_digest = decode_optional_bounded_bytes(&mut decoder)?
                .map(|bytes| {
                    <[u8; 32]>::try_from(bytes)
                        .map(Digest32V2::new)
                        .map_err(|_| ApprovalErrorV2::DurableState)
                })
                .transpose()?;
            if profile.get() == 0
                || principal.as_bytes() == &[0; 32]
                || client_request_nonce.as_bytes() == &[0; 32]
                || code_digest.as_bytes() == &[0; 32]
                || expires_at.get() == 0
                || !deployment
                    .enrollment_profiles
                    .iter()
                    .any(|candidate| candidate.profile == profile)
                || (!consumed && credential_digest.is_some())
                || deployment.enrollment_codes.iter().any(|candidate| {
                    candidate.handle == handle
                        || candidate.client_request_nonce == client_request_nonce
                })
            {
                return Err(ApprovalErrorV2::DurableState);
            }
            deployment.enrollment_codes.push(EnrollmentCodeRecordV2 {
                handle,
                profile,
                principal,
                client_request_nonce,
                code_digest,
                expires_at,
                consumed,
                credential_digest,
            });
        }
        if decoder.position() != bytes.len() || deployment.encode_mutable_state()? != bytes {
            return Err(ApprovalErrorV2::DurableState);
        }
        Ok(deployment)
    }

    fn credential_index(&self, assertion: &WebAuthnAssertionV2) -> Result<usize, ApprovalErrorV2> {
        self.credentials
            .iter()
            .position(|credential| {
                !credential.is_revoked()
                    && credential.credential_digest == assertion.credential_digest
            })
            .ok_or(ApprovalErrorV2::InvalidCredential)
    }

    fn total_envelope_count(&self) -> usize {
        self.approval_envelopes.len() + self.ui_authentication_envelopes.len()
    }

    fn envelope_nonce_is_registered(&self, nonce: savana_kernel_protocol::v2::Nonce32V2) -> bool {
        self.approval_envelopes
            .iter()
            .any(|record| record.unsigned.envelope_nonce() == nonce)
            || self
                .ui_authentication_envelopes
                .iter()
                .any(|record| record.unsigned.envelope_nonce() == nonce)
    }
}

fn validate_restored_approval_settlement(
    deployment: &ProtocolApprovalServiceV2,
    envelope: UnsignedApprovalEnvelopeV2,
    envelope_digest: Digest32V2,
    settlement: &ProtocolSignedApprovalSettlementV2,
) -> Result<(), ApprovalErrorV2> {
    let settlement_unsigned = settlement.unsigned();
    let verified = match envelope.purpose() {
        ProtocolApprovalPurposeV2::TaskAuthorization => settlement.verify_task_authorization(
            deployment.settlement_key_id,
            deployment.settlement_public_key(),
            deployment.installation_id,
            deployment.active_state_manifest_digest,
            deployment.deployment_generation,
            envelope_digest,
            envelope.expected_principal(),
            envelope.decision_challenge(),
            settlement_unsigned.issued_at(),
        ),
        ProtocolApprovalPurposeV2::Ingress => settlement.verify_ingress(
            deployment.settlement_key_id,
            deployment.settlement_public_key(),
            deployment.installation_id,
            deployment.active_state_manifest_digest,
            deployment.deployment_generation,
            envelope_digest,
            envelope.expected_principal(),
            envelope.decision_challenge(),
            settlement_unsigned.issued_at(),
        ),
        ProtocolApprovalPurposeV2::ToolExecution => settlement.verify_tool_execution(
            deployment.settlement_key_id,
            deployment.settlement_public_key(),
            deployment.installation_id,
            deployment.active_state_manifest_digest,
            deployment.deployment_generation,
            envelope_digest,
            envelope.expected_principal(),
            envelope.decision_challenge(),
            settlement_unsigned.issued_at(),
        ),
        ProtocolApprovalPurposeV2::FinalRelease => settlement.verify_final_release(
            deployment.settlement_key_id,
            deployment.settlement_public_key(),
            deployment.installation_id,
            deployment.active_state_manifest_digest,
            deployment.deployment_generation,
            envelope_digest,
            envelope.expected_principal(),
            envelope.decision_challenge(),
            settlement_unsigned.issued_at(),
        ),
        ProtocolApprovalPurposeV2::ConnectorRegistration => settlement
            .verify_connector_registration(
                deployment.settlement_key_id,
                deployment.settlement_public_key(),
                deployment.installation_id,
                deployment.active_state_manifest_digest,
                deployment.deployment_generation,
                envelope_digest,
                envelope.expected_principal(),
                envelope.decision_challenge(),
                settlement_unsigned.issued_at(),
            ),
    }
    .map_err(|_| ApprovalErrorV2::DurableAuthentication)?;
    let credential = deployment
        .credentials
        .iter()
        .find(|credential| {
            credential.credential_digest == verified.credential_digest()
                && credential.principal == verified.authenticated_principal()
        })
        .ok_or(ApprovalErrorV2::InvalidCredential)?;
    if credential.signature_counter < settlement_unsigned.signature_counter() {
        return Err(ApprovalErrorV2::CounterReplay);
    }
    Ok(())
}

fn closure_record_digest(domain: &[u8], fields: &[&[u8]]) -> Digest32V2 {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    for field in fields {
        hasher.update(u64::try_from(field.len()).unwrap_or(u64::MAX).to_be_bytes());
        hasher.update(field);
    }
    Digest32V2::new(hasher.finalize().into())
}

fn validate_restored_ui_settlement(
    deployment: &ProtocolApprovalServiceV2,
    envelope: UnsignedUiAuthenticationEnvelopeV2,
    envelope_digest: Digest32V2,
    settlement: &ProtocolSignedUiAuthenticationSettlementV2,
) -> Result<(), ApprovalErrorV2> {
    let settlement_unsigned = settlement.unsigned();
    let verified = match envelope.purpose() {
        savana_kernel_protocol::v2::UiAuthenticationPurposeV2::IngressInput => settlement
            .verify_ingress_input(
                deployment.settlement_key_id,
                deployment.settlement_public_key(),
                deployment.installation_id,
                deployment.active_state_manifest_digest,
                deployment.deployment_generation,
                settlement_unsigned.issued_at(),
            ),
        savana_kernel_protocol::v2::UiAuthenticationPurposeV2::ApprovalDisplay => settlement
            .verify_approval_display(
                deployment.settlement_key_id,
                deployment.settlement_public_key(),
                deployment.installation_id,
                deployment.active_state_manifest_digest,
                deployment.deployment_generation,
                settlement_unsigned.issued_at(),
            ),
        savana_kernel_protocol::v2::UiAuthenticationPurposeV2::AgentContent => settlement
            .verify_agent_content(
                deployment.settlement_key_id,
                deployment.settlement_public_key(),
                deployment.installation_id,
                deployment.active_state_manifest_digest,
                deployment.deployment_generation,
                settlement_unsigned.issued_at(),
            ),
    }
    .map_err(|_| ApprovalErrorV2::DurableAuthentication)?;
    if verified.envelope_digest() != envelope_digest
        || verified.binding_digest()
            != envelope
                .binding_digest()
                .map_err(|_| ApprovalErrorV2::DurableState)?
        || verified.challenge() != envelope.envelope_nonce()
        || envelope
            .expected_principal()
            .is_some_and(|principal| principal != verified.authenticated_principal())
    {
        return Err(ApprovalErrorV2::DurableState);
    }
    let credential = deployment
        .credentials
        .iter()
        .find(|credential| {
            credential.credential_digest == verified.credential_digest()
                && credential.principal == verified.authenticated_principal()
        })
        .ok_or(ApprovalErrorV2::InvalidCredential)?;
    if credential.signature_counter < settlement_unsigned.signature_counter() {
        return Err(ApprovalErrorV2::CounterReplay);
    }
    Ok(())
}

fn encode_optional_bytes(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    bytes: Option<&[u8]>,
) -> Result<(), ApprovalErrorV2> {
    match bytes {
        Some(bytes) => encoder
            .bytes(bytes)
            .map(|_| ())
            .map_err(|_| ApprovalErrorV2::AllocationFailure),
        None => encoder
            .null()
            .map(|_| ())
            .map_err(|_| ApprovalErrorV2::AllocationFailure),
    }
}

fn decode_optional_bounded_bytes<'bytes>(
    decoder: &mut minicbor::Decoder<'bytes>,
) -> Result<Option<&'bytes [u8]>, ApprovalErrorV2> {
    match decoder
        .datatype()
        .map_err(|_| ApprovalErrorV2::DurableState)?
    {
        minicbor::data::Type::Null => {
            decoder.null().map_err(|_| ApprovalErrorV2::DurableState)?;
            Ok(None)
        }
        minicbor::data::Type::Bytes => decode_bounded_bytes(decoder).map(Some),
        _ => Err(ApprovalErrorV2::DurableState),
    }
}

fn decode_bounded_bytes<'bytes>(
    decoder: &mut minicbor::Decoder<'bytes>,
) -> Result<&'bytes [u8], ApprovalErrorV2> {
    let bytes = decoder.bytes().map_err(|_| ApprovalErrorV2::DurableState)?;
    if bytes.is_empty() || bytes.len() > 8 * 1024 * 1024 {
        return Err(ApprovalErrorV2::DurableState);
    }
    Ok(bytes)
}

fn decode_bounded_count(
    decoder: &mut minicbor::Decoder<'_>,
    maximum: usize,
) -> Result<usize, ApprovalErrorV2> {
    let count = decoder
        .array()
        .map_err(|_| ApprovalErrorV2::DurableState)?
        .ok_or(ApprovalErrorV2::DurableState)?;
    let count = usize::try_from(count).map_err(|_| ApprovalErrorV2::DurableState)?;
    if count > maximum {
        return Err(ApprovalErrorV2::DurableState);
    }
    Ok(count)
}

fn require_array(
    decoder: &mut minicbor::Decoder<'_>,
    expected: u64,
) -> Result<(), ApprovalErrorV2> {
    if decoder.array().map_err(|_| ApprovalErrorV2::DurableState)? != Some(expected) {
        return Err(ApprovalErrorV2::DurableState);
    }
    Ok(())
}

fn decode_fixed<const N: usize>(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<[u8; N], ApprovalErrorV2> {
    decoder
        .bytes()
        .map_err(|_| ApprovalErrorV2::DurableState)?
        .try_into()
        .map_err(|_| ApprovalErrorV2::DurableState)
}

fn random_nonce() -> Result<savana_kernel_protocol::v2::Nonce32V2, ApprovalErrorV2> {
    Ok(savana_kernel_protocol::v2::Nonce32V2::new(
        random_nonzero_bytes()?,
    ))
}

fn random_nonzero_bytes() -> Result<[u8; 32], ApprovalErrorV2> {
    for _ in 0..4 {
        let mut bytes = [0_u8; 32];
        getrandom::getrandom(&mut bytes).map_err(|_| ApprovalErrorV2::AllocationFailure)?;
        if bytes != [0; 32] {
            return Ok(bytes);
        }
    }
    Err(ApprovalErrorV2::AllocationFailure)
}

fn enrollment_code_digest(
    handle: EnrollmentHandleV2,
    code: &str,
) -> Result<Digest32V2, ApprovalErrorV2> {
    let canonical_handle =
        minicbor::to_vec(handle).map_err(|_| ApprovalErrorV2::AllocationFailure)?;
    let mut hasher = Sha256::new();
    hasher.update(ENROLLMENT_CODE_DIGEST_DOMAIN_V2);
    hasher.update(
        u64::try_from(canonical_handle.len())
            .map_err(|_| ApprovalErrorV2::AllocationFailure)?
            .to_be_bytes(),
    );
    hasher.update(canonical_handle);
    hasher.update(
        u64::try_from(code.len())
            .map_err(|_| ApprovalErrorV2::AllocationFailure)?
            .to_be_bytes(),
    );
    hasher.update(code.as_bytes());
    Ok(Digest32V2::new(hasher.finalize().into()))
}

fn bounded_settlement_expiry(
    now: UnixMillisV2,
    envelope_expiry: UnixMillisV2,
) -> Result<UnixMillisV2, ApprovalErrorV2> {
    let expires_at = now
        .get()
        .checked_add(60_000)
        .map(|expiry| expiry.min(envelope_expiry.get()))
        .ok_or(ApprovalErrorV2::InvalidChallenge)?;
    if expires_at <= now.get() {
        return Err(ApprovalErrorV2::InvalidChallenge);
    }
    Ok(UnixMillisV2::new(expires_at))
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use ed25519_dalek::SigningKey;
    use p256::ecdsa::signature::Signer as _;
    use p256::ecdsa::{Signature, SigningKey as P256SigningKey};
    use savana_kernel_protocol::v2::{
        derive_ed25519_key_id_v2, ApprovalBindingV2, ApprovalPurposeV2, BootIdV2,
        BoundedApprovalDisplayTextV2, ClosedCredentialRevocationReasonV2, Digest32V2,
        DurableRunIdV2, DurableTaskIdV2, EnrollmentProfileIdV2, FixedOriginV2, Nonce32V2,
        PrincipalIdV2, ServiceIdentityV2, SignedAgentAuthenticationClosureDescriptorV2,
        SignedApprovalEnvelopeV2, SignedUiAuthenticationEnvelopeV2, UiAuthenticationBindingV2,
        UiAuthenticationPurposeV2, UnixMillisV2, UnsignedAgentAuthenticationClosureDescriptorV2,
        UnsignedApprovalEnvelopeV2, UnsignedUiAuthenticationEnvelopeV2,
    };
    use sha2::{Digest as _, Sha256};

    use super::ProtocolApprovalServiceV2;
    use crate::{ApprovalErrorV2, WebAuthnAssertionV2};

    fn assertion(
        signing_key: &P256SigningKey,
        credential_digest: Digest32V2,
        principal: PrincipalIdV2,
        challenge: Nonce32V2,
        counter: u32,
    ) -> WebAuthnAssertionV2 {
        let challenge =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge.as_bytes());
        let client_data = format!(
            r#"{{"type":"webauthn.get","challenge":"{challenge}","origin":"http://localhost:8766","crossOrigin":false}}"#
        )
        .into_bytes();
        let mut authenticator_data = Vec::from(Sha256::digest(b"localhost").as_slice());
        authenticator_data.push(0x01 | 0x04);
        authenticator_data.extend_from_slice(&counter.to_be_bytes());
        let mut signed = authenticator_data.clone();
        signed.extend_from_slice(&Sha256::digest(&client_data));
        let signature: Signature = signing_key.sign(&signed);
        let signature = signature.normalize_s().unwrap_or(signature);
        WebAuthnAssertionV2::from_wire(
            credential_digest,
            principal,
            client_data,
            authenticator_data,
            signature.to_der().as_bytes().to_vec(),
        )
        .unwrap()
    }

    fn enrollment_service() -> ProtocolApprovalServiceV2 {
        let kernel = SigningKey::from_bytes(&[0x71; 32]);
        let correlation = SigningKey::from_bytes(&[0x72; 32]);
        let settlement = SigningKey::from_bytes(&[0x73; 32]);
        let mut service = ProtocolApprovalServiceV2::from_verified_deployment(
            Digest32V2::new([0x74; 32]),
            Digest32V2::new([0x75; 32]),
            9,
            BootIdV2::new([0x76; 32]),
            2,
            ServiceIdentityV2::new([0x77; 32]),
            derive_ed25519_key_id_v2(kernel.verifying_key().to_bytes()),
            kernel.verifying_key().to_bytes(),
            derive_ed25519_key_id_v2(correlation.verifying_key().to_bytes()),
            correlation.verifying_key().to_bytes(),
            derive_ed25519_key_id_v2(settlement.verifying_key().to_bytes()),
            settlement.to_bytes(),
            128,
        )
        .unwrap();
        service
            .load_verified_enrollment_profile(EnrollmentProfileIdV2::new(1), 10_000, 5_000)
            .unwrap();
        service
    }

    #[test]
    fn enrollment_code_is_hash_only_durable_once_and_revocation_is_persistent() {
        let mut service = enrollment_service();
        let response = service
            .create_enrollment_code(
                EnrollmentProfileIdV2::new(1),
                Nonce32V2::new([0x78; 32]),
                UnixMillisV2::new(100),
            )
            .unwrap();
        let (handle, code, _) = response.into_parts();
        let snapshot = service.encode_mutable_state().unwrap();
        assert!(!snapshot
            .windows(code.as_str().len())
            .any(|window| window == code.as_str().as_bytes()));

        let mut restored =
            ProtocolApprovalServiceV2::restore_mutable_state(enrollment_service(), &snapshot)
                .unwrap();
        let consumed = restored
            .consume_enrollment_code(handle, &code, UnixMillisV2::new(101))
            .unwrap();
        assert_eq!(consumed.profile(), EnrollmentProfileIdV2::new(1));
        assert_eq!(
            restored
                .consume_enrollment_code(handle, &code, UnixMillisV2::new(102))
                .unwrap_err(),
            crate::ApprovalErrorV2::AlreadyConsumed
        );

        let signing = P256SigningKey::from_slice(&[0x79; 32]).unwrap();
        let point = signing.verifying_key().to_encoded_point(false);
        let credential_digest = Digest32V2::new([0x7a; 32]);
        restored
            .register_enrolled_hardware_credential(
                handle,
                credential_digest,
                [0x7b; 16],
                point.as_bytes().try_into().unwrap(),
                1,
            )
            .unwrap();
        assert_eq!(
            restored
                .revoke_credential(
                    credential_digest,
                    ClosedCredentialRevocationReasonV2::Compromised,
                )
                .unwrap(),
            savana_kernel_protocol::v2::CredentialPublicStateV2::Revoked
        );
        let assertion = assertion(
            &signing,
            credential_digest,
            consumed.principal(),
            Nonce32V2::new([0x7c; 32]),
            2,
        );
        assert_eq!(
            restored.credential_index(&assertion).unwrap_err(),
            crate::ApprovalErrorV2::InvalidCredential
        );
        let restored_again = ProtocolApprovalServiceV2::restore_mutable_state(
            enrollment_service(),
            &restored.encode_mutable_state().unwrap(),
        )
        .unwrap();
        assert!(restored_again.credentials[0].is_revoked());
    }

    #[test]
    fn protocol_owned_approval_and_ui_envelopes_produce_exact_settlements() {
        let kernel_key = SigningKey::from_bytes(&[0x11; 32]);
        let correlation_key = SigningKey::from_bytes(&[0x1a; 32]);
        let settlement_key = SigningKey::from_bytes(&[0x12; 32]);
        let installation = Digest32V2::new([0x13; 32]);
        let manifest = Digest32V2::new([0x14; 32]);
        let approvald_identity = ServiceIdentityV2::new([0x15; 32]);
        let principal = PrincipalIdV2::new([0x16; 32]);
        let credential_digest = Digest32V2::new([0x17; 32]);
        let p256_key = P256SigningKey::from_slice(&[0x18; 32]).unwrap();
        let public = p256_key.verifying_key().to_encoded_point(false);
        let mut service = ProtocolApprovalServiceV2::from_verified_deployment(
            installation,
            manifest,
            7,
            BootIdV2::new([0x1b; 32]),
            4,
            approvald_identity,
            derive_ed25519_key_id_v2(kernel_key.verifying_key().to_bytes()),
            kernel_key.verifying_key().to_bytes(),
            derive_ed25519_key_id_v2(correlation_key.verifying_key().to_bytes()),
            correlation_key.verifying_key().to_bytes(),
            derive_ed25519_key_id_v2(settlement_key.verifying_key().to_bytes()),
            settlement_key.to_bytes(),
            16,
        )
        .unwrap();
        service
            .load_verified_hardware_credential(
                credential_digest,
                principal,
                [0x19; 16],
                public.as_bytes().try_into().unwrap(),
                1,
            )
            .unwrap();

        let approval_challenge = Nonce32V2::new([0x21; 32]);
        let display = BoundedApprovalDisplayTextV2::new(
            "批准：exact persisted approval artifact — ".repeat(4),
        )
        .unwrap();
        let display_node = Digest32V2::new([0x27; 32]);
        let approval = SignedApprovalEnvelopeV2::sign(
            UnsignedApprovalEnvelopeV2::new(
                installation,
                manifest,
                7,
                ApprovalPurposeV2::Ingress,
                Nonce32V2::new([0x20; 32]),
                approval_challenge,
                ApprovalBindingV2::Ingress {
                    pending_ingress_id: Digest32V2::new([0x22; 32]),
                    ingress_subject_digest: Digest32V2::new([0x23; 32]),
                    channel_commitments_digest: Digest32V2::new([0x24; 32]),
                    source_provenance_digest: Digest32V2::new([0x25; 32]),
                },
                principal,
                Digest32V2::new([0x26; 32]),
                savana_kernel_protocol::v2::approval_display_digest_v2(display.as_bytes()),
                display.clone(),
                Some(display_node),
                approvald_identity,
                UnixMillisV2::new(100),
                UnixMillisV2::new(10_000),
            )
            .unwrap(),
            &kernel_key,
        )
        .unwrap();
        let mut tampered_payload = approval.canonical_payload().to_vec();
        let display_offset = tampered_payload
            .windows(display.as_bytes().len())
            .rposition(|window| window == display.as_bytes())
            .unwrap();
        tampered_payload[display_offset + display.as_bytes().len() - 1] ^= 1;
        let tampered = SignedApprovalEnvelopeV2::from_canonical_parts(
            tampered_payload,
            approval.key_id(),
            approval.signature(),
        )
        .unwrap();
        assert_eq!(
            service
                .register_approval_envelope(&tampered, UnixMillisV2::new(200))
                .unwrap_err(),
            ApprovalErrorV2::InvalidEnvelopeSignature
        );
        let approval_digest = service
            .register_approval_envelope(&approval, UnixMillisV2::new(200))
            .unwrap();
        let durable = service.encode_mutable_state().unwrap();
        assert!(durable
            .windows(display.as_bytes().len())
            .any(|window| window == display.as_bytes()));
        let projected = service
            .approval_challenge(approval_digest, UnixMillisV2::new(200))
            .unwrap();
        assert_eq!(projected.display_text(), &display);
        assert_eq!(
            projected.display_digest(),
            savana_kernel_protocol::v2::approval_display_digest_v2(
                projected.display_text().as_bytes()
            )
        );
        assert_eq!(
            projected.display_declassification_provenance_digest(),
            Some(display_node)
        );
        let approval_settlement = service
            .settle_approval(
                approval_digest,
                savana_kernel_protocol::v2::ApprovalDecisionV2::Approve,
                &assertion(
                    &p256_key,
                    credential_digest,
                    principal,
                    approval_challenge,
                    2,
                ),
                UnixMillisV2::new(300),
            )
            .unwrap();
        approval_settlement
            .verify_ingress(
                service.settlement_key_id(),
                service.settlement_public_key(),
                installation,
                manifest,
                7,
                approval_digest,
                principal,
                approval_challenge,
                UnixMillisV2::new(301),
            )
            .unwrap();

        let ungated_challenge = Nonce32V2::new([0x28; 32]);
        let ungated = SignedApprovalEnvelopeV2::sign(
            UnsignedApprovalEnvelopeV2::new(
                installation,
                manifest,
                7,
                ApprovalPurposeV2::Ingress,
                Nonce32V2::new([0x29; 32]),
                ungated_challenge,
                ApprovalBindingV2::Ingress {
                    pending_ingress_id: Digest32V2::new([0x2a; 32]),
                    ingress_subject_digest: Digest32V2::new([0x2b; 32]),
                    channel_commitments_digest: Digest32V2::new([0x2c; 32]),
                    source_provenance_digest: Digest32V2::new([0x2d; 32]),
                },
                principal,
                Digest32V2::new([0x2e; 32]),
                savana_kernel_protocol::v2::approval_display_digest_v2(display.as_bytes()),
                display.clone(),
                None,
                approvald_identity,
                UnixMillisV2::new(100),
                UnixMillisV2::new(10_000),
            )
            .unwrap(),
            &kernel_key,
        )
        .unwrap();
        let ungated_digest = service
            .register_approval_envelope(&ungated, UnixMillisV2::new(302))
            .unwrap();
        assert_eq!(
            service
                .settle_approval(
                    ungated_digest,
                    savana_kernel_protocol::v2::ApprovalDecisionV2::Approve,
                    &assertion(
                        &p256_key,
                        credential_digest,
                        principal,
                        ungated_challenge,
                        3,
                    ),
                    UnixMillisV2::new(303),
                )
                .unwrap_err(),
            ApprovalErrorV2::InvalidChallenge
        );

        let ui_challenge = Nonce32V2::new([0x31; 32]);
        let ui = SignedUiAuthenticationEnvelopeV2::sign(
            UnsignedUiAuthenticationEnvelopeV2::new(
                installation,
                manifest,
                7,
                UiAuthenticationPurposeV2::AgentContent,
                UiAuthenticationBindingV2::AgentContent {
                    durable_task_id: savana_kernel_protocol::v2::DurableTaskIdV2::new([0x32; 32]),
                    ingress_claim_digest: Digest32V2::new([0x33; 32]),
                    agentd_identity: ServiceIdentityV2::new([0x34; 32]),
                    agentd_boot_id: savana_kernel_protocol::v2::BootIdV2::new([0x35; 32]),
                },
                Some(principal),
                FixedOriginV2::Approval8766,
                FixedOriginV2::Agent8768,
                ui_challenge,
                UnixMillisV2::new(400),
                UnixMillisV2::new(10_000),
            )
            .unwrap(),
            &kernel_key,
        )
        .unwrap();
        let ui_digest = service
            .register_ui_authentication_envelope(&ui, UnixMillisV2::new(500))
            .unwrap();
        let ui_settlement = service
            .settle_ui_authentication(
                ui_digest,
                &assertion(&p256_key, credential_digest, principal, ui_challenge, 3),
                UnixMillisV2::new(600),
            )
            .unwrap();
        let verified = ui_settlement
            .verify_agent_content(
                service.settlement_key_id(),
                service.settlement_public_key(),
                installation,
                manifest,
                7,
                UnixMillisV2::new(601),
            )
            .unwrap();
        assert_eq!(verified.envelope_digest(), ui_digest);
        assert_eq!(verified.authenticated_principal(), principal);
    }

    #[test]
    fn connector_registration_uses_its_own_approval_settlement_purpose() {
        let kernel_key = SigningKey::from_bytes(&[0x41; 32]);
        let correlation_key = SigningKey::from_bytes(&[0x42; 32]);
        let settlement_key = SigningKey::from_bytes(&[0x43; 32]);
        let installation = Digest32V2::new([0x44; 32]);
        let manifest = Digest32V2::new([0x45; 32]);
        let approvald_identity = ServiceIdentityV2::new([0x46; 32]);
        let principal = PrincipalIdV2::new([0x47; 32]);
        let credential_digest = Digest32V2::new([0x48; 32]);
        let p256_key = P256SigningKey::from_slice(&[0x49; 32]).unwrap();
        let public = p256_key.verifying_key().to_encoded_point(false);
        let mut service = ProtocolApprovalServiceV2::from_verified_deployment(
            installation,
            manifest,
            8,
            BootIdV2::new([0x4a; 32]),
            1,
            approvald_identity,
            derive_ed25519_key_id_v2(kernel_key.verifying_key().to_bytes()),
            kernel_key.verifying_key().to_bytes(),
            derive_ed25519_key_id_v2(correlation_key.verifying_key().to_bytes()),
            correlation_key.verifying_key().to_bytes(),
            derive_ed25519_key_id_v2(settlement_key.verifying_key().to_bytes()),
            settlement_key.to_bytes(),
            8,
        )
        .unwrap();
        service
            .load_verified_hardware_credential(
                credential_digest,
                principal,
                [0x4b; 16],
                public.as_bytes().try_into().unwrap(),
                1,
            )
            .unwrap();

        let challenge = Nonce32V2::new([0x4c; 32]);
        let display = BoundedApprovalDisplayTextV2::new(
            "Connector registration; name: mail-connector; url: https://api.example.com/mcp"
                .to_owned(),
        )
        .unwrap();
        let envelope = SignedApprovalEnvelopeV2::sign(
            UnsignedApprovalEnvelopeV2::new(
                installation,
                manifest,
                8,
                ApprovalPurposeV2::ConnectorRegistration,
                Nonce32V2::new([0x4d; 32]),
                challenge,
                ApprovalBindingV2::ConnectorRegistration {
                    descriptor_digest: Digest32V2::new([0x4e; 32]),
                    previous_head_digest: Digest32V2::new([0x4f; 32]),
                },
                principal,
                Digest32V2::new([0x50; 32]),
                savana_kernel_protocol::v2::approval_display_digest_v2(display.as_bytes()),
                display,
                Some(Digest32V2::new([0x51; 32])),
                approvald_identity,
                UnixMillisV2::new(100),
                UnixMillisV2::new(10_000),
            )
            .unwrap(),
            &kernel_key,
        )
        .unwrap();
        let envelope_digest = service
            .register_approval_envelope(&envelope, UnixMillisV2::new(200))
            .unwrap();
        let settlement = service
            .settle_approval(
                envelope_digest,
                savana_kernel_protocol::v2::ApprovalDecisionV2::Approve,
                &assertion(&p256_key, credential_digest, principal, challenge, 2),
                UnixMillisV2::new(300),
            )
            .unwrap();
        assert_eq!(
            settlement.purpose(),
            ApprovalPurposeV2::ConnectorRegistration
        );
        settlement
            .verify_connector_registration(
                service.settlement_key_id(),
                service.settlement_public_key(),
                installation,
                manifest,
                8,
                envelope_digest,
                principal,
                challenge,
                UnixMillisV2::new(301),
            )
            .unwrap();
        assert!(settlement
            .verify_tool_execution(
                service.settlement_key_id(),
                service.settlement_public_key(),
                installation,
                manifest,
                8,
                envelope_digest,
                principal,
                challenge,
                UnixMillisV2::new(301),
            )
            .is_err());
    }

    #[test]
    fn task_root_approval_requires_ingress_role_exact_ceremony_and_survives_recovery() {
        use savana_kernel_protocol::v2::{
            ApprovalDecisionV2 as ProtocolApprovalDecisionV2, DurableTaskIdV2, EndpointRoleV2,
            TaskAuthorizationChangeV2,
        };
        let kernel_key = SigningKey::from_bytes(&[0x71; 32]);
        let principal = PrincipalIdV2::new([0x81; 32]);
        let credential = Digest32V2::new([0x82; 32]);
        let p256 = P256SigningKey::from_slice(&[0x83; 32]).unwrap();
        let mut initial = enrollment_service();
        initial
            .load_verified_hardware_credential(
                credential,
                principal,
                [0x84; 16],
                p256.verifying_key()
                    .to_encoded_point(false)
                    .as_bytes()
                    .try_into()
                    .unwrap(),
                1,
            )
            .unwrap();
        for (change, revision) in [
            (TaskAuthorizationChangeV2::Create, 1),
            (TaskAuthorizationChangeV2::Amend, 2),
            (TaskAuthorizationChangeV2::Revoke, 2),
        ] {
            let mut service = initial.clone();
            let challenge = Nonce32V2::new([0x85; 32]);
            let display = BoundedApprovalDisplayTextV2::new(
                "Exact task authorization: A -> Alice; B -> Bob; limit 2".into(),
            )
            .unwrap();
            let display_digest =
                savana_kernel_protocol::v2::approval_display_digest_v2(display.as_bytes());
            let unsigned = UnsignedApprovalEnvelopeV2::new(
                service.installation_id,
                service.active_state_manifest_digest,
                9,
                ApprovalPurposeV2::TaskAuthorization,
                Nonce32V2::new([0x86; 32]),
                challenge,
                ApprovalBindingV2::TaskAuthorization {
                    authorization_id: Digest32V2::new([0x87; 32]),
                    task: DurableTaskIdV2::new([0x88; 32]),
                    revision,
                    change,
                    draft_digest: Digest32V2::new([0x89; 32]),
                },
                principal,
                Digest32V2::new([0x89; 32]),
                display_digest,
                display,
                Some(Digest32V2::new([0x8a; 32])),
                service.approvald_endpoint_identity,
                UnixMillisV2::new(100),
                UnixMillisV2::new(1000),
            )
            .unwrap();
            let approval = SignedApprovalEnvelopeV2::sign(unsigned.clone(), &kernel_key).unwrap();
            let digest = approval.envelope_digest().unwrap();
            let ui = SignedUiAuthenticationEnvelopeV2::sign(
                UnsignedUiAuthenticationEnvelopeV2::new(
                    service.installation_id,
                    service.active_state_manifest_digest,
                    9,
                    UiAuthenticationPurposeV2::ApprovalDisplay,
                    UiAuthenticationBindingV2::ApprovalDisplay {
                        durable_task_id: DurableTaskIdV2::new([0x88; 32]),
                        approval_envelope_digest: digest,
                        approval_purpose: ApprovalPurposeV2::TaskAuthorization,
                        display_digest,
                    },
                    Some(principal),
                    FixedOriginV2::Approval8766,
                    FixedOriginV2::Approval8766,
                    Nonce32V2::new([0x8b; 32]),
                    UnixMillisV2::new(100),
                    UnixMillisV2::new(1000),
                )
                .unwrap(),
                &kernel_key,
            )
            .unwrap();
            let before = service.encode_mutable_state().unwrap();
            let agent_signed = SignedApprovalEnvelopeV2::sign(
                unsigned.clone(),
                &SigningKey::from_bytes(&[0xff; 32]),
            )
            .unwrap();
            assert!(service
                .register_approval_pair(
                    EndpointRoleV2::IngressApproval,
                    &agent_signed,
                    &ui,
                    UnixMillisV2::new(200)
                )
                .is_err());
            assert!(service
                .register_approval_pair(
                    EndpointRoleV2::AgentApproval,
                    &approval,
                    &ui,
                    UnixMillisV2::new(200)
                )
                .is_err());
            // Even correctly kernel-signed display authentication cannot switch
            // the task, principal, approval purpose, or the displayed bytes.
            for field in 0..4 {
                let bad_ui = SignedUiAuthenticationEnvelopeV2::sign(
                    UnsignedUiAuthenticationEnvelopeV2::new(
                        service.installation_id,
                        service.active_state_manifest_digest,
                        9,
                        UiAuthenticationPurposeV2::ApprovalDisplay,
                        UiAuthenticationBindingV2::ApprovalDisplay {
                            durable_task_id: DurableTaskIdV2::new(
                                [if field == 0 { 0xee } else { 0x88 }; 32],
                            ),
                            approval_envelope_digest: digest,
                            approval_purpose: if field == 1 {
                                ApprovalPurposeV2::Ingress
                            } else {
                                ApprovalPurposeV2::TaskAuthorization
                            },
                            display_digest: if field == 2 {
                                Digest32V2::new([0xee; 32])
                            } else {
                                display_digest
                            },
                        },
                        Some(if field == 3 {
                            PrincipalIdV2::new([0xee; 32])
                        } else {
                            principal
                        }),
                        FixedOriginV2::Approval8766,
                        FixedOriginV2::Approval8766,
                        Nonce32V2::new([0x8c; 32]),
                        UnixMillisV2::new(100),
                        UnixMillisV2::new(1000),
                    )
                    .unwrap(),
                    &kernel_key,
                )
                .unwrap();
                assert!(service
                    .register_approval_pair(
                        EndpointRoleV2::IngressApproval,
                        &approval,
                        &bad_ui,
                        UnixMillisV2::new(200)
                    )
                    .is_err());
            }
            assert_eq!(
                before,
                service.encode_mutable_state().unwrap(),
                "a rejected role must not register a task-root envelope"
            );
            service
                .register_approval_pair(
                    EndpointRoleV2::IngressApproval,
                    &approval,
                    &ui,
                    UnixMillisV2::new(200),
                )
                .unwrap();
            let encoded = service.encode_mutable_state().unwrap();
            let mut service =
                ProtocolApprovalServiceV2::restore_mutable_state(enrollment_service(), &encoded)
                    .unwrap();
            assert_eq!(
                service
                    .approval_challenge(digest, UnixMillisV2::new(200))
                    .unwrap()
                    .display_text(),
                unsigned.display_text()
            );
            assert!(service
                .settle_approval(
                    digest,
                    ProtocolApprovalDecisionV2::Approve,
                    &assertion(&p256, credential, principal, Nonce32V2::new([0xee; 32]), 2),
                    UnixMillisV2::new(300)
                )
                .is_err());
            let settlement = service
                .settle_approval(
                    digest,
                    ProtocolApprovalDecisionV2::Approve,
                    &assertion(&p256, credential, principal, challenge, 2),
                    UnixMillisV2::new(300),
                )
                .unwrap();
            settlement
                .verify_task_authorization(
                    service.settlement_key_id(),
                    service.settlement_public_key(),
                    service.installation_id,
                    service.active_state_manifest_digest,
                    9,
                    digest,
                    principal,
                    challenge,
                    UnixMillisV2::new(301),
                )
                .unwrap();
            assert!(settlement
                .verify_ingress(
                    service.settlement_key_id(),
                    service.settlement_public_key(),
                    service.installation_id,
                    service.active_state_manifest_digest,
                    9,
                    digest,
                    principal,
                    challenge,
                    UnixMillisV2::new(301)
                )
                .is_err());
            assert!(settlement
                .verify_tool_execution(
                    service.settlement_key_id(),
                    service.settlement_public_key(),
                    service.installation_id,
                    service.active_state_manifest_digest,
                    9,
                    digest,
                    principal,
                    challenge,
                    UnixMillisV2::new(301)
                )
                .is_err());
            assert!(settlement
                .verify_task_authorization(
                    service.settlement_key_id(),
                    service.settlement_public_key(),
                    service.installation_id,
                    service.active_state_manifest_digest,
                    9,
                    Digest32V2::new([0xee; 32]),
                    principal,
                    challenge,
                    UnixMillisV2::new(301)
                )
                .is_err());
            let mut restored = ProtocolApprovalServiceV2::restore_mutable_state(
                enrollment_service(),
                &service.encode_mutable_state().unwrap(),
            )
            .unwrap();
            assert!(restored
                .settle_approval(
                    digest,
                    ProtocolApprovalDecisionV2::Approve,
                    &assertion(&p256, credential, principal, challenge, 3),
                    UnixMillisV2::new(400)
                )
                .is_err());
            assert_eq!(
                restored.approval_envelopes[0].settlement.as_ref(),
                Some(&settlement)
            );
        }
    }

    #[test]
    fn closure_terminalizes_unregistered_agent_attempt_and_denylist_survives_replay() {
        let installation = Digest32V2::new([0x31; 32]);
        let manifest = Digest32V2::new([0x32; 32]);
        let kernel_envelope_key = SigningKey::from_bytes(&[0x33; 32]);
        let correlation_key = SigningKey::from_bytes(&[0x34; 32]);
        let settlement_key = SigningKey::from_bytes(&[0x35; 32]);
        let approvald = ServiceIdentityV2::new([0x36; 32]);
        let agentd = ServiceIdentityV2::new([0x37; 32]);
        let kerneld = ServiceIdentityV2::new([0x38; 32]);
        let approvald_boot = BootIdV2::new([0x39; 32]);
        let agentd_boot = BootIdV2::new([0x3a; 32]);
        let kerneld_boot = BootIdV2::new([0x3b; 32]);
        let principal = PrincipalIdV2::new([0x3c; 32]);
        let task = DurableTaskIdV2::new([0x3d; 32]);
        let run = DurableRunIdV2::new([0x3e; 32]);
        let claim = Digest32V2::new([0x3f; 32]);
        let attempt_nonce = Nonce32V2::new([0x40; 32]);
        let envelope = SignedUiAuthenticationEnvelopeV2::sign(
            UnsignedUiAuthenticationEnvelopeV2::new(
                installation,
                manifest,
                9,
                UiAuthenticationPurposeV2::AgentContent,
                UiAuthenticationBindingV2::AgentContent {
                    durable_task_id: task,
                    ingress_claim_digest: claim,
                    agentd_identity: agentd,
                    agentd_boot_id: agentd_boot,
                },
                Some(principal),
                FixedOriginV2::Approval8766,
                FixedOriginV2::Agent8768,
                attempt_nonce,
                UnixMillisV2::new(1_000),
                UnixMillisV2::new(20_000),
            )
            .unwrap(),
            &kernel_envelope_key,
        )
        .unwrap();
        let envelope_digest = envelope.envelope_digest().unwrap();
        let descriptor = SignedAgentAuthenticationClosureDescriptorV2::sign(
            UnsignedAgentAuthenticationClosureDescriptorV2::new(
                installation,
                manifest,
                9,
                manifest,
                9,
                None,
                task,
                run,
                Digest32V2::new([0x41; 32]),
                claim,
                principal,
                agentd,
                agentd_boot,
                kerneld,
                kerneld_boot,
                approvald,
                attempt_nonce,
                Digest32V2::new([0x42; 32]),
                Digest32V2::new([0x43; 32]),
                envelope_digest,
                Nonce32V2::new([0x44; 32]),
                UnixMillisV2::new(1_100),
                UnixMillisV2::new(19_000),
            )
            .unwrap(),
            &correlation_key,
        )
        .unwrap();
        let mut service = ProtocolApprovalServiceV2::from_verified_deployment(
            installation,
            manifest,
            9,
            approvald_boot,
            4,
            approvald,
            derive_ed25519_key_id_v2(kernel_envelope_key.verifying_key().to_bytes()),
            kernel_envelope_key.verifying_key().to_bytes(),
            derive_ed25519_key_id_v2(correlation_key.verifying_key().to_bytes()),
            correlation_key.verifying_key().to_bytes(),
            derive_ed25519_key_id_v2(settlement_key.verifying_key().to_bytes()),
            settlement_key.to_bytes(),
            16,
        )
        .unwrap();
        let proof = service
            .close_agent_authentication_attempt(&descriptor, agentd, UnixMillisV2::new(1_200))
            .unwrap();
        assert!(matches!(
            proof.unsigned().evidence(),
            super::AgentAuthenticationClosureEvidenceV2::NeverRegisteredDenylisted { .. }
        ));
        assert_eq!(
            service
                .close_agent_authentication_attempt(&descriptor, agentd, UnixMillisV2::new(1_300),)
                .unwrap(),
            proof
        );
        assert_eq!(
            service.register_ui_authentication_envelope(&envelope, UnixMillisV2::new(1_400)),
            Err(crate::ApprovalErrorV2::AlreadyConsumed)
        );
    }
}
