#![forbid(unsafe_code)]

#[cfg(all(feature = "macos-development-authority", not(debug_assertions)))]
compile_error!("macos-development-authority is forbidden in release builds");

#[cfg(all(feature = "test-support", not(debug_assertions)))]
compile_error!("test-support is forbidden in release builds");

use base64::Engine as _;
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
mod suite_one;
mod ui_authority;
mod webauthn_attestation;
pub use client::{ApprovalSuiteOneClientErrorV2, ApprovalSuiteOneClientV2};
pub use daemon::{run, ApprovaldDaemonErrorV2};
pub use durable::{ApprovalRollbackAnchorV2, ApprovalStateHeadV2, DurableApprovalNamespaceV2};
pub use protocol_durable::DurableProtocolApprovalServiceV2;
pub use protocol_service::{
    ApprovalChallengeProjectionV2, ConsumedEnrollmentCodeV2, ProtocolApprovalServiceV2,
    UiAuthenticationChallengeProjectionV2,
};
pub use protocol_state_owner::{ProtocolApprovalStateOwnerErrorV2, ProtocolApprovalStateOwnerV2};
pub use suite_one::{ApprovalSuiteOneServerV2, ApprovalSuiteOneServiceErrorV2};
pub use ui_authority::{
    webauthn_credential_digest_v2, AcceptedUiAuthenticationV2, ApprovalUiAuthorityErrorV2,
    ApprovalUiAuthorityV2,
};
pub use webauthn_attestation::{
    verify_enrollment_attestation_v2, verify_passkey_registration_v04, HardwareAttestationRootV2,
    VerifiedEnrollmentAttestationV2, VerifiedPasskeyRegistrationV04,
};

const RP_ID: &[u8] = b"localhost";
#[cfg(test)]
mod passkey_tests_v04;
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

}

#[derive(Debug, Clone)]
pub struct ActiveHardwareCredentialV2 {
    assurance: savana_kernel_protocol::v2::AuthenticationAssuranceV04,
    backup_eligible: bool,
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
            assurance: savana_kernel_protocol::v2::AuthenticationAssuranceV04::AttestedHardware,
            backup_eligible: false,
        })
    }

    pub(crate) fn from_verified_passkey(
        credential_digest: Digest32V2,
        principal: PrincipalIdV2,
        aaguid: [u8; 16],
        p256_sec1_public_key: [u8; 65],
        signature_counter: u32,
        backup_eligible: bool,
    ) -> Result<Self, ApprovalErrorV2> {
        if is_zero(credential_digest.as_bytes())
            || is_zero(principal.as_bytes())
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
            backup_eligible,
            assurance: savana_kernel_protocol::v2::AuthenticationAssuranceV04::UserVerifiedPasskey,
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
    assurance: savana_kernel_protocol::v2::AuthenticationAssuranceV04,
    backup_eligible: bool,
    backup_state: bool,
    purpose: ApprovalPurposeV2,
    envelope_digest: Digest32V2,
    authenticated_principal: PrincipalIdV2,
    credential_digest: Digest32V2,
    authentication_context_digest: Digest32V2,
    signature_counter: u32,
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
        assurance: verified.assurance,
        backup_eligible: verified.backup_eligible,
        backup_state: verified.backup_state,
        purpose: challenge.purpose,
        envelope_digest: challenge.envelope_digest,
        authenticated_principal: verified.authenticated_principal,
        credential_digest: verified.credential_digest,
        authentication_context_digest: verified.authentication_context_digest,
        signature_counter: verified.signature_counter,
    })
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct VerifiedWebAuthnAssertionV2 {
    pub(crate) assurance: savana_kernel_protocol::v2::AuthenticationAssuranceV04,
    pub(crate) backup_eligible: bool,
    pub(crate) backup_state: bool,
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
    if credential.revoked
        || assertion.credential_digest != credential.credential_digest
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
    let backup_eligible = flags & FLAG_BACKUP_ELIGIBLE != 0;
    let backup_state = flags & FLAG_BACKUP_STATE != 0;
    if flags & !(FLAG_USER_PRESENT | FLAG_USER_VERIFIED | FLAG_BACKUP_ELIGIBLE | FLAG_BACKUP_STATE)
        != 0
        || backup_eligible != credential.backup_eligible
    {
        return Err(ApprovalErrorV2::InvalidAuthenticatorData);
    }
    let next_counter = u32::from_be_bytes(
        assertion.authenticator_data[33..37]
            .try_into()
            .map_err(|_| ApprovalErrorV2::InvalidAuthenticatorData)?,
    );
    if !credential.assurance.accepts_evidence(
        flags & FLAG_USER_PRESENT != 0,
        flags & FLAG_USER_VERIFIED != 0,
        backup_eligible,
        backup_state,
        next_counter,
    ) {
        return Err(ApprovalErrorV2::InvalidAuthenticatorData);
    }
    if credential.assurance
        == savana_kernel_protocol::v2::AuthenticationAssuranceV04::AttestedHardware
        && (next_counter == 0 || next_counter <= credential.signature_counter)
    {
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
    if credential.assurance
        == savana_kernel_protocol::v2::AuthenticationAssuranceV04::AttestedHardware
        && signature.normalize_s().is_some()
    {
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
        assurance: credential.assurance,
        backup_eligible,
        backup_state,
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
    if credential.assurance
        == savana_kernel_protocol::v2::AuthenticationAssuranceV04::UserVerifiedPasskey
    {
        hasher.update(b"SAVANA_USER_VERIFIED_PASSKEY_V04\0");
    }
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

fn is_zero<const N: usize>(bytes: &[u8; N]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

#[cfg(test)]
mod tests {
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

}
