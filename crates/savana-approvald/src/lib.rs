#![forbid(unsafe_code)]

#[cfg(all(feature = "macos-development-authority", not(debug_assertions)))]
compile_error!("macos-development-authority is forbidden in release builds");

#[cfg(all(feature = "test-support", not(debug_assertions)))]
compile_error!("test-support is forbidden in release builds");

use base64::Engine as _;
use ed25519_dalek::{
    Signature as Ed25519Signature, Signer as _, SigningKey, VerifyingKey as Ed25519VerifyingKey,
};
use minicbor::Encode as _;
use p256::ecdsa::signature::Verifier as _;
use p256::ecdsa::{Signature, VerifyingKey};
use savana_kernel_protocol::v2::{Digest32V2, Nonce32V2, PrincipalIdV2, UnixMillisV2};
use serde::de::{self, MapAccess, Visitor};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

mod client;
mod daemon;
mod durable;
mod protocol_durable;
mod protocol_service;
mod protocol_state_owner;
mod state_owner;
mod suite_one;
mod ui_authority;
mod webauthn_attestation;
pub use client::{ApprovalSuiteOneClientErrorV2, ApprovalSuiteOneClientV2};
pub use daemon::{run, ApprovaldDaemonErrorV2};
use durable::DurableApprovalServiceV2;
pub use durable::{ApprovalRollbackAnchorV2, ApprovalStateHeadV2, DurableApprovalNamespaceV2};
pub use protocol_durable::DurableProtocolApprovalServiceV2;
pub use protocol_service::{
    ApprovalChallengeProjectionV2, ConsumedEnrollmentCodeV2, ProtocolApprovalServiceV2,
    UiAuthenticationChallengeProjectionV2,
};
pub use protocol_state_owner::{ProtocolApprovalStateOwnerErrorV2, ProtocolApprovalStateOwnerV2};
pub use state_owner::{ApprovalStateOwnerErrorV2, ApprovalStateOwnerV2};
pub use suite_one::{ApprovalSuiteOneServerV2, ApprovalSuiteOneServiceErrorV2};
pub use ui_authority::{
    webauthn_credential_digest_v2, AcceptedUiAuthenticationV2, ApprovalUiAuthorityErrorV2,
    ApprovalUiAuthorityV2,
};
pub use webauthn_attestation::{
    verify_enrollment_attestation_v2, HardwareAttestationRootV2, VerifiedEnrollmentAttestationV2,
};

const RP_ID: &[u8] = b"localhost";
const APPROVAL_ORIGIN: &str = "http://localhost:8766";
const CLIENT_DATA_TYPE: &str = "webauthn.get";
const MAX_CLIENT_DATA_BYTES: usize = 8 * 1024;
const MAX_SIGNATURE_BYTES: usize = 128;
const AUTHENTICATOR_DATA_BYTES: usize = 37;
const FLAG_USER_PRESENT: u8 = 0x01;
const FLAG_USER_VERIFIED: u8 = 0x04;
const FLAG_BACKUP_ELIGIBLE: u8 = 0x08;
const FLAG_BACKUP_STATE: u8 = 0x10;
const WEBAUTHN_CONTEXT_DOMAIN: &[u8] = b"SAVANA_WEBAUTHN_CONTEXT_V2\0";
const UI_WEBAUTHN_CONTEXT_DOMAIN: &[u8] = b"SAVANA_UI_WEBAUTHN_CONTEXT_V2\0";
const MAX_ENVELOPE_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ApprovalErrorV2 {
    #[error("approval challenge is invalid or expired")]
    InvalidChallenge,
    #[error("approval credential binding is invalid")]
    InvalidCredential,
    #[error("WebAuthn client data is malformed or not exact")]
    InvalidClientData,
    #[error("WebAuthn authenticator data is malformed or violates policy")]
    InvalidAuthenticatorData,
    #[error("WebAuthn assertion signature is invalid")]
    InvalidSignature,
    #[error("WebAuthn signature counter did not strictly increase")]
    CounterReplay,
    #[error("approval allocation failed")]
    AllocationFailure,
    #[error("approval envelope or settlement signature is invalid")]
    InvalidEnvelopeSignature,
    #[error("approval envelope is noncanonical")]
    NonCanonicalEnvelope,
    #[error("approval envelope was already consumed")]
    AlreadyConsumed,
    #[error("durable approval state I/O or invariant failure")]
    DurableState,
    #[error("durable approval state authentication failed")]
    DurableAuthentication,
    #[error("durable approval state rollback was detected")]
    RollbackDetected,
    #[error("durable approval commit outcome is uncertain")]
    CommitUncertain,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ApprovalPurposeV2 {
    Ingress,
    ToolExecution,
    FinalRelease,
    ConnectorRegistration,
    TaskAuthorization,
}

impl ApprovalPurposeV2 {
    const fn tag(self) -> u16 {
        match self {
            Self::Ingress => 1,
            Self::ToolExecution => 2,
            Self::FinalRelease => 3,
            Self::ConnectorRegistration => 4,
            Self::TaskAuthorization => 5,
        }
    }

    const fn envelope_domain(self) -> &'static [u8] {
        match self {
            Self::Ingress => b"SAVANA_INGRESS_APPROVAL_ENVELOPE_V2\0",
            Self::ToolExecution => b"SAVANA_TOOL_APPROVAL_ENVELOPE_V2\0",
            Self::FinalRelease => b"SAVANA_RELEASE_APPROVAL_ENVELOPE_V2\0",
            Self::ConnectorRegistration => b"SAVANA_CONNECTOR_REGISTRATION_APPROVAL_ENVELOPE_V2\0",
            Self::TaskAuthorization => b"SAVANA_TASK_AUTHORIZATION_APPROVAL_ENVELOPE_V2_SCHEMA1\0",
        }
    }

    const fn settlement_domain(self) -> &'static [u8] {
        match self {
            Self::Ingress => b"SAVANA_INGRESS_APPROVAL_SETTLEMENT_V2\0",
            Self::ToolExecution => b"SAVANA_TOOL_APPROVAL_SETTLEMENT_V2\0",
            Self::FinalRelease => b"SAVANA_RELEASE_APPROVAL_SETTLEMENT_V2\0",
            Self::ConnectorRegistration => {
                b"SAVANA_CONNECTOR_REGISTRATION_APPROVAL_SETTLEMENT_V2\0"
            }
            Self::TaskAuthorization => {
                b"SAVANA_TASK_AUTHORIZATION_APPROVAL_SETTLEMENT_V2_SCHEMA1\0"
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ApprovalDecisionV2 {
    Deny,
    Approve,
}

impl ApprovalDecisionV2 {
    const fn tag(self) -> u16 {
        match self {
            Self::Deny => 1,
            Self::Approve => 2,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct ApprovalEnvelopePayloadV2 {
    installation_id: Digest32V2,
    active_state_manifest_digest: Digest32V2,
    deployment_generation: u64,
    purpose: ApprovalPurposeV2,
    envelope_nonce: Nonce32V2,
    decision_challenge: Nonce32V2,
    binding_digest: Digest32V2,
    expected_principal: PrincipalIdV2,
    issued_at: UnixMillisV2,
    expires_at: UnixMillisV2,
}

#[derive(Debug, Clone, Copy)]
struct ApprovalSettlementPayloadV2 {
    installation_id: Digest32V2,
    active_state_manifest_digest: Digest32V2,
    deployment_generation: u64,
    purpose: ApprovalPurposeV2,
    envelope_digest: Digest32V2,
    decision: ApprovalDecisionV2,
    authenticated_principal: PrincipalIdV2,
    credential_digest: Digest32V2,
    signature_counter: u32,
    decision_challenge: Nonce32V2,
    issued_at: UnixMillisV2,
    expires_at: UnixMillisV2,
}

#[derive(Debug, Clone)]
pub struct SignedApprovalEnvelopeV2 {
    canonical_payload: Vec<u8>,
    key_id: Digest32V2,
    signature: [u8; 64],
}

impl SignedApprovalEnvelopeV2 {
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ApprovalErrorV2> {
        if bytes.is_empty() || bytes.len() > MAX_ENVELOPE_BYTES {
            return Err(ApprovalErrorV2::NonCanonicalEnvelope);
        }
        let mut decoder = minicbor::Decoder::new(bytes);
        require_array(&mut decoder, 3)?;
        let canonical_payload = decoder
            .bytes()
            .map_err(|_| ApprovalErrorV2::NonCanonicalEnvelope)?
            .to_vec();
        let key_id = Digest32V2::new(decode_fixed::<32>(&mut decoder)?);
        let signature = decode_fixed::<64>(&mut decoder)?;
        if decoder.position() != bytes.len() {
            return Err(ApprovalErrorV2::NonCanonicalEnvelope);
        }
        let envelope = Self {
            canonical_payload,
            key_id,
            signature,
        };
        if encode_signed_envelope(&envelope)? != bytes {
            return Err(ApprovalErrorV2::NonCanonicalEnvelope);
        }
        decode_envelope_payload(&envelope.canonical_payload)?;
        Ok(envelope)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ApprovalErrorV2> {
        encode_signed_envelope(self)
    }
}

#[derive(Debug, Clone)]
pub struct SignedApprovalSettlementV2 {
    canonical_payload: Vec<u8>,
    key_id: Digest32V2,
    signature: [u8; 64],
    settlement_digest: Digest32V2,
}

impl SignedApprovalSettlementV2 {
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ApprovalErrorV2> {
        if bytes.is_empty() || bytes.len() > MAX_ENVELOPE_BYTES {
            return Err(ApprovalErrorV2::NonCanonicalEnvelope);
        }
        let mut decoder = minicbor::Decoder::new(bytes);
        require_array(&mut decoder, 3)?;
        let canonical_payload = decoder
            .bytes()
            .map_err(|_| ApprovalErrorV2::NonCanonicalEnvelope)?
            .to_vec();
        let key_id = Digest32V2::new(decode_fixed::<32>(&mut decoder)?);
        let signature = decode_fixed::<64>(&mut decoder)?;
        if decoder.position() != bytes.len() {
            return Err(ApprovalErrorV2::NonCanonicalEnvelope);
        }
        let payload = decode_settlement_payload(&canonical_payload)?;
        let settlement_digest =
            domain_hash(payload.purpose.settlement_domain(), &canonical_payload);
        let settlement = Self {
            canonical_payload,
            key_id,
            signature,
            settlement_digest,
        };
        if encode_signed_settlement(&settlement)? != bytes {
            return Err(ApprovalErrorV2::NonCanonicalEnvelope);
        }
        Ok(settlement)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ApprovalErrorV2> {
        encode_signed_settlement(self)
    }

    pub fn canonical_payload(&self) -> &[u8] {
        &self.canonical_payload
    }

    pub const fn key_id(&self) -> Digest32V2 {
        self.key_id
    }

    pub const fn signature(&self) -> &[u8; 64] {
        &self.signature
    }

    pub const fn settlement_digest(&self) -> Digest32V2 {
        self.settlement_digest
    }
}

#[derive(Debug, Clone)]
struct RegisteredEnvelopeV2 {
    payload: ApprovalEnvelopePayloadV2,
    envelope_digest: Digest32V2,
    signed_envelope: Vec<u8>,
    consumed: bool,
    settlement: Option<SignedApprovalSettlementV2>,
    settlement_consumed: bool,
}

#[derive(Clone)]
pub struct ApprovalServiceV2 {
    installation_id: Digest32V2,
    active_state_manifest_digest: Digest32V2,
    deployment_generation: u64,
    kernel_envelope_key_id: Digest32V2,
    kernel_envelope_verifying_key: Ed25519VerifyingKey,
    settlement_key_id: Digest32V2,
    settlement_signing_key: SigningKey,
    credentials: Vec<ActiveHardwareCredentialV2>,
    envelopes: Vec<RegisteredEnvelopeV2>,
}

impl std::fmt::Debug for ApprovalServiceV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ApprovalServiceV2")
            .field("deployment_generation", &self.deployment_generation)
            .field("credentials", &self.credentials.len())
            .field("envelopes", &self.envelopes.len())
            .finish_non_exhaustive()
    }
}

impl ApprovalServiceV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn from_verified_deployment(
        installation_id: Digest32V2,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
        kernel_envelope_key_id: Digest32V2,
        kernel_envelope_public_key: [u8; 32],
        settlement_key_id: Digest32V2,
        settlement_signing_seed: [u8; 32],
    ) -> Result<Self, ApprovalErrorV2> {
        if is_zero(installation_id.as_bytes())
            || is_zero(active_state_manifest_digest.as_bytes())
            || deployment_generation == 0
            || is_zero(kernel_envelope_key_id.as_bytes())
            || is_zero(settlement_key_id.as_bytes())
            || settlement_signing_seed == [0; 32]
        {
            return Err(ApprovalErrorV2::InvalidCredential);
        }
        let kernel_envelope_verifying_key =
            Ed25519VerifyingKey::from_bytes(&kernel_envelope_public_key)
                .map_err(|_| ApprovalErrorV2::InvalidCredential)?;
        Ok(Self {
            installation_id,
            active_state_manifest_digest,
            deployment_generation,
            kernel_envelope_key_id,
            kernel_envelope_verifying_key,
            settlement_key_id,
            settlement_signing_key: SigningKey::from_bytes(&settlement_signing_seed),
            credentials: Vec::new(),
            envelopes: Vec::new(),
        })
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

    pub fn register_envelope(
        &mut self,
        envelope: &SignedApprovalEnvelopeV2,
        now: UnixMillisV2,
    ) -> Result<Digest32V2, ApprovalErrorV2> {
        if envelope.key_id != self.kernel_envelope_key_id {
            return Err(ApprovalErrorV2::InvalidEnvelopeSignature);
        }
        let payload = decode_envelope_payload(&envelope.canonical_payload)?;
        if payload.installation_id != self.installation_id
            || payload.active_state_manifest_digest != self.active_state_manifest_digest
            || payload.deployment_generation != self.deployment_generation
            || now.get() < payload.issued_at.get()
            || now.get() >= payload.expires_at.get()
        {
            return Err(ApprovalErrorV2::InvalidChallenge);
        }
        let envelope_digest = domain_hash(
            payload.purpose.envelope_domain(),
            &envelope.canonical_payload,
        );
        let mut signature_input = Vec::new();
        signature_input.extend_from_slice(payload.purpose.envelope_domain());
        signature_input.extend_from_slice(envelope_digest.as_bytes());
        self.kernel_envelope_verifying_key
            .verify_strict(
                &signature_input,
                &Ed25519Signature::from_bytes(&envelope.signature),
            )
            .map_err(|_| ApprovalErrorV2::InvalidEnvelopeSignature)?;
        let signed_envelope = encode_signed_envelope(envelope)?;
        if let Some(existing) = self
            .envelopes
            .iter()
            .find(|entry| entry.envelope_digest == envelope_digest)
        {
            if existing.payload.binding_digest != payload.binding_digest
                || existing.signed_envelope != signed_envelope
            {
                return Err(ApprovalErrorV2::InvalidChallenge);
            }
            return Ok(envelope_digest);
        }
        if self.envelopes.iter().any(|entry| {
            entry.payload.envelope_nonce == payload.envelope_nonce
                || entry.payload.decision_challenge == payload.decision_challenge
        }) {
            return Err(ApprovalErrorV2::InvalidChallenge);
        }
        self.envelopes
            .try_reserve(1)
            .map_err(|_| ApprovalErrorV2::AllocationFailure)?;
        self.envelopes.push(RegisteredEnvelopeV2 {
            payload,
            envelope_digest,
            signed_envelope,
            consumed: false,
            settlement: None,
            settlement_consumed: false,
        });
        Ok(envelope_digest)
    }

    pub fn settle(
        &mut self,
        envelope_digest: Digest32V2,
        decision: ApprovalDecisionV2,
        assertion: &WebAuthnAssertionV2,
        now: UnixMillisV2,
    ) -> Result<SignedApprovalSettlementV2, ApprovalErrorV2> {
        let envelope_index = self
            .envelopes
            .iter()
            .position(|entry| entry.envelope_digest == envelope_digest)
            .ok_or(ApprovalErrorV2::InvalidChallenge)?;
        if self.envelopes[envelope_index].consumed {
            return Err(ApprovalErrorV2::AlreadyConsumed);
        }
        let payload = self.envelopes[envelope_index].payload;
        let credential_index = self
            .credentials
            .iter()
            .position(|credential| credential.credential_digest == assertion.credential_digest)
            .ok_or(ApprovalErrorV2::InvalidCredential)?;
        let challenge = ApprovalDecisionChallengeV2::from_verified_envelope(
            payload.purpose,
            envelope_digest,
            payload.expected_principal,
            payload.decision_challenge,
            payload.issued_at,
            payload.expires_at,
        )?;
        let verified = verify_approval_decision_assertion(
            challenge,
            &self.credentials[credential_index],
            assertion,
            now,
        )?;
        let mut settlement_nonce = [0_u8; 32];
        getrandom::getrandom(&mut settlement_nonce)
            .map_err(|_| ApprovalErrorV2::AllocationFailure)?;
        if settlement_nonce == [0; 32] {
            return Err(ApprovalErrorV2::AllocationFailure);
        }
        let expires_at = now
            .get()
            .checked_add(60_000)
            .map(|expiry| expiry.min(payload.expires_at.get()))
            .ok_or(ApprovalErrorV2::InvalidChallenge)?;
        let canonical_payload = encode_settlement_payload(
            self.installation_id,
            self.active_state_manifest_digest,
            self.deployment_generation,
            payload.purpose,
            envelope_digest,
            decision,
            verified,
            Nonce32V2::new(settlement_nonce),
            now,
            UnixMillisV2::new(expires_at),
        )?;
        let settlement_digest =
            domain_hash(payload.purpose.settlement_domain(), &canonical_payload);
        let mut signature_input = Vec::new();
        signature_input.extend_from_slice(payload.purpose.settlement_domain());
        signature_input.extend_from_slice(settlement_digest.as_bytes());
        let signature = self
            .settlement_signing_key
            .sign(&signature_input)
            .to_bytes();

        let settlement = SignedApprovalSettlementV2 {
            canonical_payload,
            key_id: self.settlement_key_id,
            signature,
            settlement_digest,
        };
        self.credentials[credential_index].signature_counter = verified.signature_counter;
        self.envelopes[envelope_index].consumed = true;
        self.envelopes[envelope_index].settlement = Some(settlement.clone());
        Ok(settlement)
    }

    pub fn consume_settlement(
        &mut self,
        envelope_digest: Digest32V2,
        settlement_digest: Digest32V2,
        now: UnixMillisV2,
    ) -> Result<ConsumedApprovalSettlementV2, ApprovalErrorV2> {
        let envelope = self
            .envelopes
            .iter_mut()
            .find(|entry| entry.envelope_digest == envelope_digest)
            .ok_or(ApprovalErrorV2::InvalidChallenge)?;
        if envelope.settlement_consumed {
            return Err(ApprovalErrorV2::AlreadyConsumed);
        }
        let settlement = envelope
            .settlement
            .as_ref()
            .ok_or(ApprovalErrorV2::InvalidChallenge)?;
        if settlement.settlement_digest != settlement_digest
            || settlement.key_id != self.settlement_key_id
        {
            return Err(ApprovalErrorV2::InvalidEnvelopeSignature);
        }
        let payload = decode_settlement_payload(&settlement.canonical_payload)?;
        if payload.installation_id != self.installation_id
            || payload.active_state_manifest_digest != self.active_state_manifest_digest
            || payload.deployment_generation != self.deployment_generation
            || payload.purpose != envelope.payload.purpose
            || payload.envelope_digest != envelope.envelope_digest
            || payload.authenticated_principal != envelope.payload.expected_principal
            || payload.decision_challenge != envelope.payload.decision_challenge
            || payload.decision != ApprovalDecisionV2::Approve
            || now.get() < payload.issued_at.get()
            || now.get() >= payload.expires_at.get()
        {
            return Err(ApprovalErrorV2::InvalidChallenge);
        }
        let credential = self
            .credentials
            .iter()
            .find(|credential| {
                credential.credential_digest == payload.credential_digest
                    && credential.principal == payload.authenticated_principal
            })
            .ok_or(ApprovalErrorV2::InvalidCredential)?;
        if credential.signature_counter < payload.signature_counter {
            return Err(ApprovalErrorV2::CounterReplay);
        }
        let digest = domain_hash(
            payload.purpose.settlement_domain(),
            &settlement.canonical_payload,
        );
        let mut signature_input = Vec::from(payload.purpose.settlement_domain());
        signature_input.extend_from_slice(digest.as_bytes());
        self.settlement_signing_key
            .verifying_key()
            .verify_strict(
                &signature_input,
                &Ed25519Signature::from_bytes(&settlement.signature),
            )
            .map_err(|_| ApprovalErrorV2::InvalidEnvelopeSignature)?;
        envelope.settlement_consumed = true;
        Ok(ConsumedApprovalSettlementV2 {
            purpose: payload.purpose,
            envelope_digest,
            settlement_digest,
            binding_digest: envelope.payload.binding_digest,
            authenticated_principal: payload.authenticated_principal,
            issued_at: payload.issued_at,
            expires_at: payload.expires_at,
        })
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ConsumedApprovalSettlementV2 {
    purpose: ApprovalPurposeV2,
    envelope_digest: Digest32V2,
    settlement_digest: Digest32V2,
    binding_digest: Digest32V2,
    authenticated_principal: PrincipalIdV2,
    issued_at: UnixMillisV2,
    expires_at: UnixMillisV2,
}

impl ConsumedApprovalSettlementV2 {
    pub const fn purpose(self) -> ApprovalPurposeV2 {
        self.purpose
    }

    pub const fn envelope_digest(self) -> Digest32V2 {
        self.envelope_digest
    }

    pub const fn settlement_digest(self) -> Digest32V2 {
        self.settlement_digest
    }

    pub const fn binding_digest(self) -> Digest32V2 {
        self.binding_digest
    }

    pub const fn authenticated_principal(self) -> PrincipalIdV2 {
        self.authenticated_principal
    }

    pub const fn issued_at(self) -> UnixMillisV2 {
        self.issued_at
    }

    pub const fn expires_at(self) -> UnixMillisV2 {
        self.expires_at
    }
}

#[derive(Debug, Clone)]
pub struct ActiveHardwareCredentialV2 {
    credential_digest: Digest32V2,
    principal: PrincipalIdV2,
    aaguid: [u8; 16],
    p256_sec1_public_key: [u8; 65],
    signature_counter: u32,
    revoked: bool,
}

impl ActiveHardwareCredentialV2 {
    pub(crate) fn from_verified_enrollment(
        credential_digest: Digest32V2,
        principal: PrincipalIdV2,
        aaguid: [u8; 16],
        p256_sec1_public_key: [u8; 65],
        signature_counter: u32,
    ) -> Result<Self, ApprovalErrorV2> {
        if is_zero(credential_digest.as_bytes())
            || is_zero(principal.as_bytes())
            || aaguid == [0; 16]
            || signature_counter == 0
            || VerifyingKey::from_sec1_bytes(&p256_sec1_public_key).is_err()
        {
            return Err(ApprovalErrorV2::InvalidCredential);
        }
        Ok(Self {
            credential_digest,
            principal,
            aaguid,
            p256_sec1_public_key,
            signature_counter,
            revoked: false,
        })
    }

    pub const fn signature_counter(&self) -> u32 {
        self.signature_counter
    }

    pub(crate) const fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub(crate) fn revoke(&mut self) {
        self.revoked = true;
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ApprovalDecisionChallengeV2 {
    purpose: ApprovalPurposeV2,
    envelope_digest: Digest32V2,
    expected_principal: PrincipalIdV2,
    challenge: Nonce32V2,
    issued_at: UnixMillisV2,
    expires_at: UnixMillisV2,
}

impl ApprovalDecisionChallengeV2 {
    pub(crate) fn from_verified_envelope(
        purpose: ApprovalPurposeV2,
        envelope_digest: Digest32V2,
        expected_principal: PrincipalIdV2,
        challenge: Nonce32V2,
        issued_at: UnixMillisV2,
        expires_at: UnixMillisV2,
    ) -> Result<Self, ApprovalErrorV2> {
        if is_zero(envelope_digest.as_bytes())
            || is_zero(expected_principal.as_bytes())
            || is_zero(challenge.as_bytes())
            || issued_at.get() >= expires_at.get()
        {
            return Err(ApprovalErrorV2::InvalidChallenge);
        }
        Ok(Self {
            purpose,
            envelope_digest,
            expected_principal,
            challenge,
            issued_at,
            expires_at,
        })
    }
}

#[derive(Debug)]
pub struct WebAuthnAssertionV2 {
    credential_digest: Digest32V2,
    user_handle: PrincipalIdV2,
    client_data_json: Zeroizing<Vec<u8>>,
    authenticator_data: Vec<u8>,
    der_signature: Vec<u8>,
}

impl WebAuthnAssertionV2 {
    pub fn from_wire(
        credential_digest: Digest32V2,
        user_handle: PrincipalIdV2,
        client_data_json: Vec<u8>,
        authenticator_data: Vec<u8>,
        der_signature: Vec<u8>,
    ) -> Result<Self, ApprovalErrorV2> {
        if is_zero(credential_digest.as_bytes())
            || is_zero(user_handle.as_bytes())
            || client_data_json.is_empty()
            || client_data_json.len() > MAX_CLIENT_DATA_BYTES
            || authenticator_data.len() != AUTHENTICATOR_DATA_BYTES
            || der_signature.is_empty()
            || der_signature.len() > MAX_SIGNATURE_BYTES
        {
            return Err(ApprovalErrorV2::InvalidCredential);
        }
        Ok(Self {
            credential_digest,
            user_handle,
            client_data_json: Zeroizing::new(client_data_json),
            authenticator_data,
            der_signature,
        })
    }
}

#[derive(Debug, Clone, Copy)]
pub struct VerifiedApprovalDecisionV2 {
    purpose: ApprovalPurposeV2,
    envelope_digest: Digest32V2,
    authenticated_principal: PrincipalIdV2,
    credential_digest: Digest32V2,
    authentication_context_digest: Digest32V2,
    signature_counter: u32,
    challenge: Nonce32V2,
}

impl VerifiedApprovalDecisionV2 {
    pub const fn purpose(self) -> ApprovalPurposeV2 {
        self.purpose
    }

    pub const fn envelope_digest(self) -> Digest32V2 {
        self.envelope_digest
    }

    pub const fn authenticated_principal(self) -> PrincipalIdV2 {
        self.authenticated_principal
    }

    pub const fn credential_digest(self) -> Digest32V2 {
        self.credential_digest
    }

    pub const fn authentication_context_digest(self) -> Digest32V2 {
        self.authentication_context_digest
    }

    pub const fn signature_counter(self) -> u32 {
        self.signature_counter
    }
}

#[derive(Deserialize)]
#[serde(field_identifier, rename_all = "camelCase")]
enum CollectedClientDataFieldV2 {
    #[serde(rename = "type")]
    Type,
    Challenge,
    Origin,
    CrossOrigin,
    TopOrigin,
    #[serde(other)]
    Other,
}

#[derive(Debug)]
struct CollectedClientDataV2 {
    ceremony_type: String,
    challenge: String,
    origin: String,
    cross_origin: bool,
    top_origin_seen: bool,
}

impl<'de> Deserialize<'de> for CollectedClientDataV2 {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct CollectedClientDataVisitorV2;

        impl<'de> Visitor<'de> for CollectedClientDataVisitorV2 {
            type Value = CollectedClientDataV2;

            fn expecting(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                formatter.write_str("WebAuthn CollectedClientData object")
            }

            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
                let mut ceremony_type = None;
                let mut challenge = None;
                let mut origin = None;
                let mut cross_origin = None;
                let mut top_origin_seen = false;
                while let Some(field) = map.next_key::<CollectedClientDataFieldV2>()? {
                    match field {
                        CollectedClientDataFieldV2::Type => {
                            if ceremony_type.is_some() {
                                return Err(de::Error::duplicate_field("type"));
                            }
                            ceremony_type = Some(map.next_value()?);
                        }
                        CollectedClientDataFieldV2::Challenge => {
                            if challenge.is_some() {
                                return Err(de::Error::duplicate_field("challenge"));
                            }
                            challenge = Some(map.next_value()?);
                        }
                        CollectedClientDataFieldV2::Origin => {
                            if origin.is_some() {
                                return Err(de::Error::duplicate_field("origin"));
                            }
                            origin = Some(map.next_value()?);
                        }
                        CollectedClientDataFieldV2::CrossOrigin => {
                            if cross_origin.is_some() {
                                return Err(de::Error::duplicate_field("crossOrigin"));
                            }
                            cross_origin = Some(map.next_value()?);
                        }
                        CollectedClientDataFieldV2::TopOrigin => {
                            if top_origin_seen {
                                return Err(de::Error::duplicate_field("topOrigin"));
                            }
                            top_origin_seen = true;
                            let _: serde_json::Value = map.next_value()?;
                        }
                        CollectedClientDataFieldV2::Other => {
                            let _: serde_json::Value = map.next_value()?;
                        }
                    }
                }
                Ok(CollectedClientDataV2 {
                    ceremony_type: ceremony_type.ok_or_else(|| de::Error::missing_field("type"))?,
                    challenge: challenge.ok_or_else(|| de::Error::missing_field("challenge"))?,
                    origin: origin.ok_or_else(|| de::Error::missing_field("origin"))?,
                    cross_origin: cross_origin.unwrap_or(false),
                    top_origin_seen,
                })
            }
        }

        deserializer.deserialize_map(CollectedClientDataVisitorV2)
    }
}

pub fn verify_approval_decision_assertion(
    challenge: ApprovalDecisionChallengeV2,
    credential: &ActiveHardwareCredentialV2,
    assertion: &WebAuthnAssertionV2,
    now: UnixMillisV2,
) -> Result<VerifiedApprovalDecisionV2, ApprovalErrorV2> {
    let verified = verify_webauthn_assertion(
        WEBAUTHN_CONTEXT_DOMAIN,
        challenge.purpose.tag(),
        challenge.envelope_digest,
        challenge.expected_principal,
        challenge.challenge,
        challenge.issued_at,
        challenge.expires_at,
        credential,
        assertion,
        now,
    )?;
    Ok(VerifiedApprovalDecisionV2 {
        purpose: challenge.purpose,
        envelope_digest: challenge.envelope_digest,
        authenticated_principal: verified.authenticated_principal,
        credential_digest: verified.credential_digest,
        authentication_context_digest: verified.authentication_context_digest,
        signature_counter: verified.signature_counter,
        challenge: challenge.challenge,
    })
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct VerifiedWebAuthnAssertionV2 {
    pub(crate) authenticated_principal: PrincipalIdV2,
    pub(crate) credential_digest: Digest32V2,
    pub(crate) authentication_context_digest: Digest32V2,
    pub(crate) signature_counter: u32,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_ui_authentication_assertion(
    purpose: savana_kernel_protocol::v2::UiAuthenticationPurposeV2,
    envelope_digest: Digest32V2,
    expected_principal: PrincipalIdV2,
    challenge: Nonce32V2,
    issued_at: UnixMillisV2,
    expires_at: UnixMillisV2,
    credential: &ActiveHardwareCredentialV2,
    assertion: &WebAuthnAssertionV2,
    now: UnixMillisV2,
) -> Result<VerifiedWebAuthnAssertionV2, ApprovalErrorV2> {
    verify_webauthn_assertion(
        UI_WEBAUTHN_CONTEXT_DOMAIN,
        purpose.tag(),
        envelope_digest,
        expected_principal,
        challenge,
        issued_at,
        expires_at,
        credential,
        assertion,
        now,
    )
}

#[allow(clippy::too_many_arguments)]
fn verify_webauthn_assertion(
    context_domain: &[u8],
    purpose_tag: u16,
    envelope_digest: Digest32V2,
    expected_principal: PrincipalIdV2,
    challenge: Nonce32V2,
    issued_at: UnixMillisV2,
    expires_at: UnixMillisV2,
    credential: &ActiveHardwareCredentialV2,
    assertion: &WebAuthnAssertionV2,
    now: UnixMillisV2,
) -> Result<VerifiedWebAuthnAssertionV2, ApprovalErrorV2> {
    if now.get() < issued_at.get() || now.get() >= expires_at.get() {
        return Err(ApprovalErrorV2::InvalidChallenge);
    }
    if assertion.credential_digest != credential.credential_digest
        || assertion.user_handle != credential.principal
        || expected_principal != credential.principal
    {
        return Err(ApprovalErrorV2::InvalidCredential);
    }

    let client: CollectedClientDataV2 = serde_json::from_slice(&assertion.client_data_json)
        .map_err(|_| ApprovalErrorV2::InvalidClientData)?;
    let expected_challenge =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge.as_bytes());
    if client.ceremony_type != CLIENT_DATA_TYPE
        || client.challenge != expected_challenge
        || client.origin != APPROVAL_ORIGIN
        || client.cross_origin
        || client.top_origin_seen
    {
        return Err(ApprovalErrorV2::InvalidClientData);
    }

    let expected_rp_hash: [u8; 32] = Sha256::digest(RP_ID).into();
    if assertion.authenticator_data[..32] != expected_rp_hash {
        return Err(ApprovalErrorV2::InvalidAuthenticatorData);
    }
    let flags = assertion.authenticator_data[32];
    if flags & FLAG_USER_PRESENT == 0
        || flags & FLAG_USER_VERIFIED == 0
        || flags & FLAG_BACKUP_ELIGIBLE != 0
        || flags & FLAG_BACKUP_STATE != 0
    {
        return Err(ApprovalErrorV2::InvalidAuthenticatorData);
    }
    let next_counter = u32::from_be_bytes(
        assertion.authenticator_data[33..37]
            .try_into()
            .map_err(|_| ApprovalErrorV2::InvalidAuthenticatorData)?,
    );
    if next_counter == 0 || next_counter <= credential.signature_counter {
        return Err(ApprovalErrorV2::CounterReplay);
    }

    let client_hash: [u8; 32] = Sha256::digest(assertion.client_data_json.as_slice()).into();
    let mut signed_bytes = Vec::new();
    signed_bytes
        .try_reserve_exact(assertion.authenticator_data.len() + client_hash.len())
        .map_err(|_| ApprovalErrorV2::AllocationFailure)?;
    signed_bytes.extend_from_slice(&assertion.authenticator_data);
    signed_bytes.extend_from_slice(&client_hash);
    let signature = Signature::from_der(&assertion.der_signature)
        .map_err(|_| ApprovalErrorV2::InvalidSignature)?;
    if signature.normalize_s().is_some() {
        return Err(ApprovalErrorV2::InvalidSignature);
    }
    let verifying_key = VerifyingKey::from_sec1_bytes(&credential.p256_sec1_public_key)
        .map_err(|_| ApprovalErrorV2::InvalidCredential)?;
    verifying_key
        .verify(&signed_bytes, &signature)
        .map_err(|_| ApprovalErrorV2::InvalidSignature)?;

    let authentication_context_digest = webauthn_context_digest(
        context_domain,
        purpose_tag,
        envelope_digest,
        credential,
        &assertion.client_data_json,
        &assertion.authenticator_data,
        next_counter,
    );
    Ok(VerifiedWebAuthnAssertionV2 {
        authenticated_principal: credential.principal,
        credential_digest: credential.credential_digest,
        authentication_context_digest,
        signature_counter: next_counter,
    })
}

#[allow(clippy::too_many_arguments)]
fn webauthn_context_digest(
    context_domain: &[u8],
    purpose_tag: u16,
    envelope_digest: Digest32V2,
    credential: &ActiveHardwareCredentialV2,
    client_data_json: &[u8],
    authenticator_data: &[u8],
    signature_counter: u32,
) -> Digest32V2 {
    let mut hasher = Sha256::new();
    hasher.update(context_domain);
    hasher.update(purpose_tag.to_be_bytes());
    hasher.update(1_u16.to_be_bytes());
    hasher.update(1_u16.to_be_bytes());
    hasher.update(envelope_digest.as_bytes());
    hasher.update(Sha256::digest(client_data_json));
    hasher.update(Sha256::digest(authenticator_data));
    hasher.update(credential.credential_digest.as_bytes());
    hasher.update(signature_counter.to_be_bytes());
    hasher.update(credential.aaguid);
    Digest32V2::new(hasher.finalize().into())
}

fn decode_envelope_payload(
    canonical_payload: &[u8],
) -> Result<ApprovalEnvelopePayloadV2, ApprovalErrorV2> {
    if canonical_payload.is_empty() || canonical_payload.len() > MAX_ENVELOPE_BYTES {
        return Err(ApprovalErrorV2::NonCanonicalEnvelope);
    }
    let mut decoder = minicbor::Decoder::new(canonical_payload);
    require_array(&mut decoder, 11)?;
    if decoder
        .u16()
        .map_err(|_| ApprovalErrorV2::NonCanonicalEnvelope)?
        != 2
    {
        return Err(ApprovalErrorV2::NonCanonicalEnvelope);
    }
    let payload = ApprovalEnvelopePayloadV2 {
        installation_id: Digest32V2::new(decode_fixed::<32>(&mut decoder)?),
        active_state_manifest_digest: Digest32V2::new(decode_fixed::<32>(&mut decoder)?),
        deployment_generation: decoder
            .u64()
            .map_err(|_| ApprovalErrorV2::NonCanonicalEnvelope)?,
        purpose: decode_purpose(
            decoder
                .u16()
                .map_err(|_| ApprovalErrorV2::NonCanonicalEnvelope)?,
        )?,
        envelope_nonce: Nonce32V2::new(decode_fixed::<32>(&mut decoder)?),
        decision_challenge: Nonce32V2::new(decode_fixed::<32>(&mut decoder)?),
        binding_digest: Digest32V2::new(decode_fixed::<32>(&mut decoder)?),
        expected_principal: PrincipalIdV2::new(decode_fixed::<32>(&mut decoder)?),
        issued_at: UnixMillisV2::new(
            decoder
                .u64()
                .map_err(|_| ApprovalErrorV2::NonCanonicalEnvelope)?,
        ),
        expires_at: UnixMillisV2::new(
            decoder
                .u64()
                .map_err(|_| ApprovalErrorV2::NonCanonicalEnvelope)?,
        ),
    };
    if decoder.position() != canonical_payload.len()
        || encode_envelope_payload(payload)? != canonical_payload
        || payload.deployment_generation == 0
        || is_zero(payload.installation_id.as_bytes())
        || is_zero(payload.active_state_manifest_digest.as_bytes())
        || is_zero(payload.envelope_nonce.as_bytes())
        || is_zero(payload.decision_challenge.as_bytes())
        || is_zero(payload.binding_digest.as_bytes())
        || is_zero(payload.expected_principal.as_bytes())
        || payload.issued_at.get() >= payload.expires_at.get()
    {
        return Err(ApprovalErrorV2::NonCanonicalEnvelope);
    }
    Ok(payload)
}

fn encode_envelope_payload(payload: ApprovalEnvelopePayloadV2) -> Result<Vec<u8>, ApprovalErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(11)
        .and_then(|encoder| encoder.u16(2))
        .map_err(|_| ApprovalErrorV2::NonCanonicalEnvelope)?;
    payload
        .installation_id
        .encode(&mut encoder, &mut ())
        .map_err(|_| ApprovalErrorV2::NonCanonicalEnvelope)?;
    payload
        .active_state_manifest_digest
        .encode(&mut encoder, &mut ())
        .map_err(|_| ApprovalErrorV2::NonCanonicalEnvelope)?;
    encoder
        .u64(payload.deployment_generation)
        .and_then(|encoder| encoder.u16(payload.purpose.tag()))
        .map_err(|_| ApprovalErrorV2::NonCanonicalEnvelope)?;
    payload
        .envelope_nonce
        .encode(&mut encoder, &mut ())
        .map_err(|_| ApprovalErrorV2::NonCanonicalEnvelope)?;
    payload
        .decision_challenge
        .encode(&mut encoder, &mut ())
        .map_err(|_| ApprovalErrorV2::NonCanonicalEnvelope)?;
    payload
        .binding_digest
        .encode(&mut encoder, &mut ())
        .map_err(|_| ApprovalErrorV2::NonCanonicalEnvelope)?;
    payload
        .expected_principal
        .encode(&mut encoder, &mut ())
        .map_err(|_| ApprovalErrorV2::NonCanonicalEnvelope)?;
    encoder
        .u64(payload.issued_at.get())
        .and_then(|encoder| encoder.u64(payload.expires_at.get()))
        .map_err(|_| ApprovalErrorV2::NonCanonicalEnvelope)?;
    Ok(encoder.into_writer())
}

fn encode_signed_envelope(envelope: &SignedApprovalEnvelopeV2) -> Result<Vec<u8>, ApprovalErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(3)
        .and_then(|encoder| encoder.bytes(&envelope.canonical_payload))
        .map_err(|_| ApprovalErrorV2::NonCanonicalEnvelope)?;
    envelope
        .key_id
        .encode(&mut encoder, &mut ())
        .map_err(|_| ApprovalErrorV2::NonCanonicalEnvelope)?;
    encoder
        .bytes(&envelope.signature)
        .map_err(|_| ApprovalErrorV2::NonCanonicalEnvelope)?;
    Ok(encoder.into_writer())
}

fn encode_signed_settlement(
    settlement: &SignedApprovalSettlementV2,
) -> Result<Vec<u8>, ApprovalErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(3)
        .and_then(|encoder| encoder.bytes(&settlement.canonical_payload))
        .map_err(|_| ApprovalErrorV2::NonCanonicalEnvelope)?;
    settlement
        .key_id
        .encode(&mut encoder, &mut ())
        .map_err(|_| ApprovalErrorV2::NonCanonicalEnvelope)?;
    encoder
        .bytes(&settlement.signature)
        .map_err(|_| ApprovalErrorV2::NonCanonicalEnvelope)?;
    Ok(encoder.into_writer())
}

#[allow(clippy::too_many_arguments)]
fn encode_settlement_payload(
    installation_id: Digest32V2,
    active_state_manifest_digest: Digest32V2,
    deployment_generation: u64,
    purpose: ApprovalPurposeV2,
    envelope_digest: Digest32V2,
    decision: ApprovalDecisionV2,
    verified: VerifiedApprovalDecisionV2,
    settlement_nonce: Nonce32V2,
    issued_at: UnixMillisV2,
    expires_at: UnixMillisV2,
) -> Result<Vec<u8>, ApprovalErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(19)
        .and_then(|encoder| encoder.u16(2))
        .map_err(|_| ApprovalErrorV2::NonCanonicalEnvelope)?;
    installation_id
        .encode(&mut encoder, &mut ())
        .map_err(|_| ApprovalErrorV2::NonCanonicalEnvelope)?;
    active_state_manifest_digest
        .encode(&mut encoder, &mut ())
        .map_err(|_| ApprovalErrorV2::NonCanonicalEnvelope)?;
    encoder
        .u64(deployment_generation)
        .and_then(|encoder| encoder.u16(purpose.tag()))
        .map_err(|_| ApprovalErrorV2::NonCanonicalEnvelope)?;
    envelope_digest
        .encode(&mut encoder, &mut ())
        .map_err(|_| ApprovalErrorV2::NonCanonicalEnvelope)?;
    encoder
        .u16(decision.tag())
        .map_err(|_| ApprovalErrorV2::NonCanonicalEnvelope)?;
    verified
        .authenticated_principal
        .encode(&mut encoder, &mut ())
        .map_err(|_| ApprovalErrorV2::NonCanonicalEnvelope)?;
    verified
        .authentication_context_digest
        .encode(&mut encoder, &mut ())
        .map_err(|_| ApprovalErrorV2::NonCanonicalEnvelope)?;
    verified
        .credential_digest
        .encode(&mut encoder, &mut ())
        .map_err(|_| ApprovalErrorV2::NonCanonicalEnvelope)?;
    encoder
        .bool(true)
        .and_then(|encoder| encoder.bool(true))
        .and_then(|encoder| encoder.bool(false))
        .and_then(|encoder| encoder.bool(false))
        .and_then(|encoder| encoder.u32(verified.signature_counter))
        .map_err(|_| ApprovalErrorV2::NonCanonicalEnvelope)?;
    verified
        .challenge
        .encode(&mut encoder, &mut ())
        .map_err(|_| ApprovalErrorV2::NonCanonicalEnvelope)?;
    settlement_nonce
        .encode(&mut encoder, &mut ())
        .map_err(|_| ApprovalErrorV2::NonCanonicalEnvelope)?;
    encoder
        .u64(issued_at.get())
        .and_then(|encoder| encoder.u64(expires_at.get()))
        .map_err(|_| ApprovalErrorV2::NonCanonicalEnvelope)?;
    Ok(encoder.into_writer())
}

fn decode_settlement_payload(
    canonical_payload: &[u8],
) -> Result<ApprovalSettlementPayloadV2, ApprovalErrorV2> {
    if canonical_payload.is_empty() || canonical_payload.len() > MAX_ENVELOPE_BYTES {
        return Err(ApprovalErrorV2::NonCanonicalEnvelope);
    }
    let mut decoder = minicbor::Decoder::new(canonical_payload);
    require_array(&mut decoder, 19)?;
    if decoder
        .u16()
        .map_err(|_| ApprovalErrorV2::NonCanonicalEnvelope)?
        != 2
    {
        return Err(ApprovalErrorV2::NonCanonicalEnvelope);
    }
    let installation_id = Digest32V2::new(decode_fixed::<32>(&mut decoder)?);
    let active_state_manifest_digest = Digest32V2::new(decode_fixed::<32>(&mut decoder)?);
    let deployment_generation = decoder
        .u64()
        .map_err(|_| ApprovalErrorV2::NonCanonicalEnvelope)?;
    let purpose = decode_purpose(
        decoder
            .u16()
            .map_err(|_| ApprovalErrorV2::NonCanonicalEnvelope)?,
    )?;
    let envelope_digest = Digest32V2::new(decode_fixed::<32>(&mut decoder)?);
    let decision = match decoder
        .u16()
        .map_err(|_| ApprovalErrorV2::NonCanonicalEnvelope)?
    {
        1 => ApprovalDecisionV2::Deny,
        2 => ApprovalDecisionV2::Approve,
        _ => return Err(ApprovalErrorV2::NonCanonicalEnvelope),
    };
    let authenticated_principal = PrincipalIdV2::new(decode_fixed::<32>(&mut decoder)?);
    let authentication_context_digest = Digest32V2::new(decode_fixed::<32>(&mut decoder)?);
    let credential_digest = Digest32V2::new(decode_fixed::<32>(&mut decoder)?);
    let user_present = decoder
        .bool()
        .map_err(|_| ApprovalErrorV2::NonCanonicalEnvelope)?;
    let user_verified = decoder
        .bool()
        .map_err(|_| ApprovalErrorV2::NonCanonicalEnvelope)?;
    let backup_eligible = decoder
        .bool()
        .map_err(|_| ApprovalErrorV2::NonCanonicalEnvelope)?;
    let backup_state = decoder
        .bool()
        .map_err(|_| ApprovalErrorV2::NonCanonicalEnvelope)?;
    let signature_counter = decoder
        .u32()
        .map_err(|_| ApprovalErrorV2::NonCanonicalEnvelope)?;
    let decision_challenge = Nonce32V2::new(decode_fixed::<32>(&mut decoder)?);
    let settlement_nonce = Nonce32V2::new(decode_fixed::<32>(&mut decoder)?);
    let issued_at = UnixMillisV2::new(
        decoder
            .u64()
            .map_err(|_| ApprovalErrorV2::NonCanonicalEnvelope)?,
    );
    let expires_at = UnixMillisV2::new(
        decoder
            .u64()
            .map_err(|_| ApprovalErrorV2::NonCanonicalEnvelope)?,
    );
    let payload = ApprovalSettlementPayloadV2 {
        installation_id,
        active_state_manifest_digest,
        deployment_generation,
        purpose,
        envelope_digest,
        decision,
        authenticated_principal,
        credential_digest,
        signature_counter,
        decision_challenge,
        issued_at,
        expires_at,
    };
    let verified = VerifiedApprovalDecisionV2 {
        purpose,
        envelope_digest,
        authenticated_principal,
        credential_digest,
        authentication_context_digest,
        signature_counter,
        challenge: decision_challenge,
    };
    if decoder.position() != canonical_payload.len()
        || encode_settlement_payload(
            installation_id,
            active_state_manifest_digest,
            deployment_generation,
            purpose,
            envelope_digest,
            decision,
            verified,
            settlement_nonce,
            issued_at,
            expires_at,
        )? != canonical_payload
        || !user_present
        || !user_verified
        || backup_eligible
        || backup_state
        || deployment_generation == 0
        || signature_counter == 0
        || issued_at.get() >= expires_at.get()
        || [
            installation_id.as_bytes(),
            active_state_manifest_digest.as_bytes(),
            envelope_digest.as_bytes(),
            authenticated_principal.as_bytes(),
            authentication_context_digest.as_bytes(),
            credential_digest.as_bytes(),
            decision_challenge.as_bytes(),
            settlement_nonce.as_bytes(),
        ]
        .iter()
        .any(|bytes| is_zero(bytes))
    {
        return Err(ApprovalErrorV2::NonCanonicalEnvelope);
    }
    Ok(payload)
}

fn decode_purpose(tag: u16) -> Result<ApprovalPurposeV2, ApprovalErrorV2> {
    match tag {
        1 => Ok(ApprovalPurposeV2::Ingress),
        2 => Ok(ApprovalPurposeV2::ToolExecution),
        3 => Ok(ApprovalPurposeV2::FinalRelease),
        4 => Ok(ApprovalPurposeV2::ConnectorRegistration),
        5 => Ok(ApprovalPurposeV2::TaskAuthorization),
        _ => Err(ApprovalErrorV2::NonCanonicalEnvelope),
    }
}

fn require_array(
    decoder: &mut minicbor::Decoder<'_>,
    expected: u64,
) -> Result<(), ApprovalErrorV2> {
    if decoder
        .array()
        .map_err(|_| ApprovalErrorV2::NonCanonicalEnvelope)?
        != Some(expected)
    {
        return Err(ApprovalErrorV2::NonCanonicalEnvelope);
    }
    Ok(())
}

fn decode_fixed<const N: usize>(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<[u8; N], ApprovalErrorV2> {
    decoder
        .bytes()
        .map_err(|_| ApprovalErrorV2::NonCanonicalEnvelope)?
        .try_into()
        .map_err(|_| ApprovalErrorV2::NonCanonicalEnvelope)
}

fn domain_hash(domain: &[u8], payload: &[u8]) -> Digest32V2 {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(payload);
    Digest32V2::new(hasher.finalize().into())
}

fn is_zero<const N: usize>(bytes: &[u8; N]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;
    use std::sync::{Arc, Mutex};

    use p256::ecdsa::signature::Signer as _;
    use p256::ecdsa::SigningKey as P256SigningKey;

    use super::*;

    #[test]
    fn release_build_has_a_hard_test_support_compile_gate() {
        let source = include_str!("lib.rs");
        assert!(source.contains(
            "#[cfg(all(feature = \"test-support\", not(debug_assertions)))]\n\
             compile_error!(\"test-support is forbidden in release builds\");"
        ));
    }

    #[test]
    fn assertion_client_data_rejects_duplicate_security_fields() {
        for bytes in [
            br#"{"type":"webauthn.get","type":"webauthn.get","challenge":"x","origin":"http://localhost:8766"}"#.as_slice(),
            br#"{"type":"webauthn.get","challenge":"x","challenge":"x","origin":"http://localhost:8766"}"#.as_slice(),
            br#"{"type":"webauthn.get","challenge":"x","origin":"http://localhost:8766","origin":"http://localhost:8766"}"#.as_slice(),
            br#"{"type":"webauthn.get","challenge":"x","origin":"http://localhost:8766","crossOrigin":false,"crossOrigin":false}"#.as_slice(),
            br#"{"type":"webauthn.get","challenge":"x","origin":"http://localhost:8766","topOrigin":null,"topOrigin":null}"#.as_slice(),
        ] {
            assert!(serde_json::from_slice::<CollectedClientDataV2>(bytes).is_err());
        }
    }

    #[derive(Clone, Default)]
    struct TestApprovalAnchor(Arc<Mutex<ApprovalStateHeadV2>>);

    impl ApprovalRollbackAnchorV2 for TestApprovalAnchor {
        fn current_head(&self) -> Result<ApprovalStateHeadV2, ApprovalErrorV2> {
            self.0
                .lock()
                .map(|head| *head)
                .map_err(|_| ApprovalErrorV2::DurableState)
        }

        fn compare_and_advance(
            &mut self,
            expected: ApprovalStateHeadV2,
            next: ApprovalStateHeadV2,
        ) -> Result<(), ApprovalErrorV2> {
            let mut head = self.0.lock().map_err(|_| ApprovalErrorV2::DurableState)?;
            if *head != expected {
                return Err(ApprovalErrorV2::RollbackDetected);
            }
            *head = next;
            Ok(())
        }
    }

    fn fixture(
        challenge_bytes: [u8; 32],
        counter: u32,
    ) -> (
        ApprovalDecisionChallengeV2,
        ActiveHardwareCredentialV2,
        WebAuthnAssertionV2,
    ) {
        let signing_key = P256SigningKey::from_bytes((&[0x41; 32]).into()).unwrap();
        let encoded = signing_key.verifying_key().to_encoded_point(false);
        let public_key: [u8; 65] = encoded.as_bytes().try_into().unwrap();
        let principal = PrincipalIdV2::new([0x42; 32]);
        let credential_digest = Digest32V2::new([0x43; 32]);
        let credential = ActiveHardwareCredentialV2::from_verified_enrollment(
            credential_digest,
            principal,
            [0x44; 16],
            public_key,
            7,
        )
        .unwrap();
        let challenge = ApprovalDecisionChallengeV2::from_verified_envelope(
            ApprovalPurposeV2::ToolExecution,
            Digest32V2::new([0x45; 32]),
            principal,
            Nonce32V2::new(challenge_bytes),
            UnixMillisV2::new(100),
            UnixMillisV2::new(200),
        )
        .unwrap();
        let challenge_text =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge_bytes);
        let client_data = format!(
            r#"{{"type":"webauthn.get","challenge":"{challenge_text}","origin":"http://localhost:8766","crossOrigin":false}}"#
        )
        .into_bytes();
        let mut authenticator_data = Vec::from(Sha256::digest(RP_ID).as_slice());
        authenticator_data.push(FLAG_USER_PRESENT | FLAG_USER_VERIFIED);
        authenticator_data.extend_from_slice(&counter.to_be_bytes());
        let client_hash = Sha256::digest(&client_data);
        let mut signed = authenticator_data.clone();
        signed.extend_from_slice(&client_hash);
        let signature: Signature = signing_key.sign(&signed);
        let signature = signature.normalize_s().unwrap_or(signature);
        let assertion = WebAuthnAssertionV2::from_wire(
            credential_digest,
            principal,
            client_data,
            authenticator_data,
            signature.to_der().as_bytes().to_vec(),
        )
        .unwrap();
        (challenge, credential, assertion)
    }

    #[test]
    fn exact_hardware_assertion_is_verified_and_counter_bound() {
        let (challenge, credential, assertion) = fixture([0x46; 32], 8);
        let verified = verify_approval_decision_assertion(
            challenge,
            &credential,
            &assertion,
            UnixMillisV2::new(150),
        )
        .unwrap();
        assert_eq!(verified.purpose(), ApprovalPurposeV2::ToolExecution);
        assert_eq!(verified.signature_counter(), 8);
        assert_ne!(
            verified.authentication_context_digest().as_bytes(),
            &[0; 32]
        );
    }

    #[test]
    fn challenge_counter_flags_origin_and_signature_fail_closed() {
        let (challenge, credential, assertion) = fixture([0x51; 32], 7);
        assert_eq!(
            verify_approval_decision_assertion(
                challenge,
                &credential,
                &assertion,
                UnixMillisV2::new(150),
            )
            .unwrap_err(),
            ApprovalErrorV2::CounterReplay
        );

        let (challenge, credential, mut assertion) = fixture([0x52; 32], 8);
        assertion.authenticator_data[32] |= FLAG_BACKUP_ELIGIBLE;
        assert_eq!(
            verify_approval_decision_assertion(
                challenge,
                &credential,
                &assertion,
                UnixMillisV2::new(150),
            )
            .unwrap_err(),
            ApprovalErrorV2::InvalidAuthenticatorData
        );

        let (challenge, credential, mut assertion) = fixture([0x53; 32], 8);
        assertion.der_signature[4] ^= 1;
        assert_eq!(
            verify_approval_decision_assertion(
                challenge,
                &credential,
                &assertion,
                UnixMillisV2::new(150),
            )
            .unwrap_err(),
            ApprovalErrorV2::InvalidSignature
        );
    }

    #[test]
    fn signed_envelope_settlement_advances_counter_and_is_one_use() {
        let kernel_signing = ed25519_dalek::SigningKey::from_bytes(&[0x61; 32]);
        let kernel_key_id = Digest32V2::new([0x62; 32]);
        let installation = Digest32V2::new([0x63; 32]);
        let manifest = Digest32V2::new([0x64; 32]);
        let principal = PrincipalIdV2::new([0x42; 32]);
        let payload = ApprovalEnvelopePayloadV2 {
            installation_id: installation,
            active_state_manifest_digest: manifest,
            deployment_generation: 9,
            purpose: ApprovalPurposeV2::ToolExecution,
            envelope_nonce: Nonce32V2::new([0x65; 32]),
            decision_challenge: Nonce32V2::new([0x66; 32]),
            binding_digest: Digest32V2::new([0x67; 32]),
            expected_principal: principal,
            issued_at: UnixMillisV2::new(100),
            expires_at: UnixMillisV2::new(200),
        };
        let canonical_payload = encode_envelope_payload(payload).unwrap();
        let envelope_digest = domain_hash(payload.purpose.envelope_domain(), &canonical_payload);
        let mut signature_input = Vec::from(payload.purpose.envelope_domain());
        signature_input.extend_from_slice(envelope_digest.as_bytes());
        let envelope = SignedApprovalEnvelopeV2 {
            canonical_payload,
            key_id: kernel_key_id,
            signature: kernel_signing.sign(&signature_input).to_bytes(),
        };
        let envelope = SignedApprovalEnvelopeV2::from_canonical_bytes(
            &encode_signed_envelope(&envelope).unwrap(),
        )
        .unwrap();

        let deployment = ApprovalServiceV2::from_verified_deployment(
            installation,
            manifest,
            9,
            kernel_key_id,
            kernel_signing.verifying_key().to_bytes(),
            Digest32V2::new([0x68; 32]),
            [0x69; 32],
        )
        .unwrap();
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.path().join("approval-state-v2.cbor");
        let namespace = DurableApprovalNamespaceV2::from_verified_installation(
            installation,
            Digest32V2::new([0x6a; 32]),
        )
        .unwrap();
        let anchor = TestApprovalAnchor::default();
        let mut service = DurableApprovalServiceV2::open(
            &path,
            [0x6b; 32],
            namespace,
            Box::new(anchor.clone()),
            deployment,
        )
        .unwrap();
        let (_, fixture_credential, assertion) = fixture([0x66; 32], 8);
        service
            .load_verified_hardware_credential(
                fixture_credential.credential_digest,
                fixture_credential.principal,
                fixture_credential.aaguid,
                fixture_credential.p256_sec1_public_key,
                fixture_credential.signature_counter,
            )
            .unwrap();
        let registered = service
            .register_envelope(&envelope, UnixMillisV2::new(120))
            .unwrap();
        assert_eq!(registered, envelope_digest);
        let settlement = service
            .settle(
                envelope_digest,
                ApprovalDecisionV2::Approve,
                &assertion,
                UnixMillisV2::new(150),
            )
            .unwrap();
        assert_ne!(settlement.settlement_digest().as_bytes(), &[0; 32]);
        assert_eq!(
            service
                .settle(
                    envelope_digest,
                    ApprovalDecisionV2::Approve,
                    &assertion,
                    UnixMillisV2::new(150),
                )
                .unwrap_err(),
            ApprovalErrorV2::AlreadyConsumed
        );
        drop(service);
        let deployment = ApprovalServiceV2::from_verified_deployment(
            installation,
            manifest,
            9,
            kernel_key_id,
            kernel_signing.verifying_key().to_bytes(),
            Digest32V2::new([0x68; 32]),
            [0x69; 32],
        )
        .unwrap();
        let mut service = DurableApprovalServiceV2::open(
            &path,
            [0x6b; 32],
            namespace,
            Box::new(anchor),
            deployment,
        )
        .unwrap();
        let consumed = service
            .consume_settlement(
                envelope_digest,
                settlement.settlement_digest(),
                UnixMillisV2::new(151),
            )
            .unwrap();
        assert_eq!(consumed.purpose(), ApprovalPurposeV2::ToolExecution);
        assert_eq!(consumed.binding_digest(), Digest32V2::new([0x67; 32]));
        assert_eq!(
            service
                .consume_settlement(
                    envelope_digest,
                    settlement.settlement_digest(),
                    UnixMillisV2::new(152),
                )
                .unwrap_err(),
            ApprovalErrorV2::AlreadyConsumed
        );
        let persisted = fs::read(path).unwrap();
        assert!(!persisted
            .windows(payload.decision_challenge.as_bytes().len())
            .any(|window| window == payload.decision_challenge.as_bytes()));
    }

    #[test]
    fn durable_approval_state_rejects_rollback_and_namespace_substitution() {
        let kernel_signing = ed25519_dalek::SigningKey::from_bytes(&[0x71; 32]);
        let installation = Digest32V2::new([0x72; 32]);
        let manifest = Digest32V2::new([0x73; 32]);
        let kernel_key_id = Digest32V2::new([0x74; 32]);
        let settlement_key_id = Digest32V2::new([0x75; 32]);
        let namespace = DurableApprovalNamespaceV2::from_verified_installation(
            installation,
            Digest32V2::new([0x76; 32]),
        )
        .unwrap();
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.path().join("approval-state-v2.cbor");
        let anchor = TestApprovalAnchor::default();
        let credential_key = P256SigningKey::from_bytes((&[0x77; 32]).into()).unwrap();
        let public_key: [u8; 65] = credential_key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .try_into()
            .unwrap();
        let deployment = ApprovalServiceV2::from_verified_deployment(
            installation,
            manifest,
            3,
            kernel_key_id,
            kernel_signing.verifying_key().to_bytes(),
            settlement_key_id,
            [0x78; 32],
        )
        .unwrap();
        let old_bytes;
        {
            let mut durable = DurableApprovalServiceV2::open(
                &path,
                [0x79; 32],
                namespace,
                Box::new(anchor.clone()),
                deployment,
            )
            .unwrap();
            durable
                .load_verified_hardware_credential(
                    Digest32V2::new([0x7a; 32]),
                    PrincipalIdV2::new([0x7b; 32]),
                    [0x7c; 16],
                    public_key,
                    1,
                )
                .unwrap();
            old_bytes = fs::read(&path).unwrap();
            durable
                .load_verified_hardware_credential(
                    Digest32V2::new([0x7d; 32]),
                    PrincipalIdV2::new([0x7e; 32]),
                    [0x7f; 16],
                    public_key,
                    2,
                )
                .unwrap();
        }
        fs::write(&path, old_bytes).unwrap();
        let deployment = ApprovalServiceV2::from_verified_deployment(
            installation,
            manifest,
            3,
            kernel_key_id,
            kernel_signing.verifying_key().to_bytes(),
            settlement_key_id,
            [0x78; 32],
        )
        .unwrap();
        assert_eq!(
            DurableApprovalServiceV2::open(
                &path,
                [0x79; 32],
                namespace,
                Box::new(anchor),
                deployment,
            )
            .unwrap_err(),
            ApprovalErrorV2::RollbackDetected
        );

        let deployment = ApprovalServiceV2::from_verified_deployment(
            installation,
            manifest,
            3,
            kernel_key_id,
            kernel_signing.verifying_key().to_bytes(),
            settlement_key_id,
            [0x78; 32],
        )
        .unwrap();
        let wrong_namespace = DurableApprovalNamespaceV2::from_verified_installation(
            installation,
            Digest32V2::new([0x80; 32]),
        )
        .unwrap();
        assert!(matches!(
            DurableApprovalServiceV2::open(
                &path,
                [0x79; 32],
                wrong_namespace,
                Box::new(TestApprovalAnchor::default()),
                deployment,
            ),
            Err(ApprovalErrorV2::DurableAuthentication | ApprovalErrorV2::RollbackDetected)
        ));
    }
}
