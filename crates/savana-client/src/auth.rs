use std::path::Path;
use std::sync::Arc;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use minicbor::Decode as _;
use savana_kernel_protocol::v2::{
    decode_begin_enrollment_browser_response_v2, decode_finish_enrollment_browser_response_v2,
    decode_ui_authentication_browser_begin_response_v2,
    decode_ui_authentication_browser_finish_response_v2,
    encode_begin_enrollment_browser_request_v2, encode_finish_enrollment_browser_request_v2,
    encode_finish_enrollment_browser_response_v2,
    encode_ui_authentication_browser_begin_request_v2,
    encode_ui_authentication_browser_finish_request_v2, AgentMaskedDocumentRefV2,
    AgentTabSessionCapabilityV2, AgentUiPreAuthenticationTabCapabilityV2,
    BeginEnrollmentBrowserRequestV2, BrowserWebAuthnAssertionV2, CredentialPublicStateV2,
    Digest32V2, EnrollmentHandleV2, FinishEnrollmentBrowserRequestV2, FixedOriginV2,
    UiAuthenticationBrowserBeginRequestV2, UiAuthenticationBrowserBeginResponseV2,
    UiAuthenticationBrowserFinishRequestV2, UiAuthenticationBrowserFinishResponseV2,
    V2DecodeContext, ZeroizingTextV2,
};
use zeroize::Zeroizing;

use crate::handle::SessionBinding;
use crate::identity::PublicCredentialState;
use crate::{
    ApprovalCallback, AuthError, BrowserContentType, BrowserOrigin, BrowserRequest,
    BrowserResponse, BrowserRoute, BrowserService, Client, Identity, Session, SessionBootstrap,
};

const MAX_AUTHENTICATION_HTML_BYTES: usize = 64 * 1024;
const MAX_MAIN_TAG_BYTES: usize = 8 * 1024;
const MAX_PURPOSE_BYTES: usize = 32;
const MAX_CAPABILITY_ATTRIBUTE_BYTES: usize = 128;
const MAX_CREDENTIAL_ID_BYTES: usize = 4096;
const MAX_CLIENT_DATA_BYTES: usize = 64 * 1024;
const MAX_ATTESTATION_OBJECT_BYTES: usize = 512 * 1024;

pub trait WebAuthnProvider: Send + Sync {
    fn assert_credential(&self, options_json: &[u8]) -> Result<WebAuthnAssertion, AuthError>;
    fn create_credential(&self, options_json: &[u8]) -> Result<WebAuthnAttestation, AuthError>;
}

pub struct WebAuthnAssertion {
    inner: BrowserWebAuthnAssertionV2,
}

impl WebAuthnAssertion {
    pub fn new(
        credential_id: Vec<u8>,
        authenticator_data: Vec<u8>,
        client_data_json: Vec<u8>,
        signature: Vec<u8>,
        user_handle: Vec<u8>,
    ) -> Result<Self, AuthError> {
        BrowserWebAuthnAssertionV2::new(
            credential_id,
            authenticator_data,
            client_data_json,
            signature,
            user_handle,
        )
        .map(|inner| Self { inner })
        .map_err(|_| AuthError::AuthenticationFailed)
    }

    pub(crate) fn credential_id(&self) -> &[u8] {
        self.inner.credential_id()
    }

    pub(crate) fn into_protocol(self) -> BrowserWebAuthnAssertionV2 {
        self.inner
    }
}

impl core::fmt::Debug for WebAuthnAssertion {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("WebAuthnAssertion(<redacted>)")
    }
}

pub struct WebAuthnAttestation {
    credential_id: Zeroizing<Vec<u8>>,
    client_data_json: Zeroizing<Vec<u8>>,
    attestation_object: Zeroizing<Vec<u8>>,
}

type WebAuthnAttestationParts = (Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>);

impl WebAuthnAttestation {
    pub fn new(
        credential_id: Vec<u8>,
        client_data_json: Vec<u8>,
        attestation_object: Vec<u8>,
    ) -> Result<Self, AuthError> {
        if credential_id.is_empty()
            || credential_id.len() > MAX_CREDENTIAL_ID_BYTES
            || client_data_json.is_empty()
            || client_data_json.len() > MAX_CLIENT_DATA_BYTES
            || attestation_object.is_empty()
            || attestation_object.len() > MAX_ATTESTATION_OBJECT_BYTES
        {
            return Err(AuthError::EnrollmentFailed);
        }
        Ok(Self {
            credential_id: Zeroizing::new(credential_id),
            client_data_json: Zeroizing::new(client_data_json),
            attestation_object: Zeroizing::new(attestation_object),
        })
    }

    fn into_parts(self) -> WebAuthnAttestationParts {
        (
            self.credential_id,
            self.client_data_json,
            self.attestation_object,
        )
    }
}

impl core::fmt::Debug for WebAuthnAttestation {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("WebAuthnAttestation(<redacted>)")
    }
}

impl Client {
    pub fn session(
        &self,
        identity: &Identity,
        bootstrap: &mut SessionBootstrap,
        webauthn: Arc<dyn WebAuthnProvider>,
        approval: Arc<dyn ApprovalCallback>,
    ) -> Result<Session, AuthError> {
        let transfer = bootstrap.take_transfer()?;
        if !identity.is_active() {
            return Err(AuthError::AuthenticationFailed);
        }
        let accept = self.send_authentication(
            BrowserRoute::ApprovalUiAuthenticationAccept,
            BrowserService::Approval,
            BrowserOrigin::Jarvis,
            BrowserContentType::FormUrlEncoded,
            form_transfer(transfer)?,
            BrowserContentType::Html,
        )?;
        let attributes = extract_main_data_attributes(
            accept.body(),
            &[
                ("data-purpose", MAX_PURPOSE_BYTES),
                ("data-pre-authentication", MAX_CAPABILITY_ATTRIBUTE_BYTES),
            ],
        )?;
        if attributes[0] != "agent" {
            return Err(AuthError::AuthenticationFailed);
        }
        let pre_authentication: AgentUiPreAuthenticationTabCapabilityV2 =
            decode_capability_attribute(&attributes[1], 32)?;
        let nonce = self
            .next_nonce()
            .map_err(|_| AuthError::AuthenticationFailed)?;
        let begin_body = encode_ui_authentication_browser_begin_request_v2(
            UiAuthenticationBrowserBeginRequestV2::Agent {
                pre_authentication,
                client_request_nonce: nonce,
            },
        )
        .map_err(|_| AuthError::AuthenticationFailed)?;
        let begun = self.send_authentication(
            BrowserRoute::ApprovalUiAuthenticationBegin,
            BrowserService::Approval,
            BrowserOrigin::Approval,
            BrowserContentType::CanonicalCbor,
            begin_body,
            BrowserContentType::CanonicalCbor,
        )?;
        let (ceremony, options_json) =
            match decode_ui_authentication_browser_begin_response_v2(begun.body())
                .map_err(|_| AuthError::AuthenticationFailed)?
            {
                UiAuthenticationBrowserBeginResponseV2::Agent {
                    ceremony,
                    public_key_options_json,
                } => (ceremony, public_key_options_json),
                _ => return Err(AuthError::AuthenticationFailed),
            };
        let assertion = webauthn.assert_credential(&options_json)?;
        if assertion.credential_id() != identity.credential_id() {
            return Err(AuthError::AuthenticationFailed);
        }
        let finish = UiAuthenticationBrowserFinishRequestV2::Agent {
            ceremony,
            client_request_nonce: nonce,
            assertion: assertion.into_protocol(),
        };
        let finish_body = encode_ui_authentication_browser_finish_request_v2(&finish)
            .map_err(|_| AuthError::AuthenticationFailed)?;
        let finished = self.send_authentication(
            BrowserRoute::ApprovalUiAuthenticationFinish,
            BrowserService::Approval,
            BrowserOrigin::Approval,
            BrowserContentType::CanonicalCbor,
            finish_body,
            BrowserContentType::CanonicalCbor,
        )?;
        let settlement = match decode_ui_authentication_browser_finish_response_v2(finished.body())
            .map_err(|_| AuthError::AuthenticationFailed)?
        {
            UiAuthenticationBrowserFinishResponseV2::TransferToAgent {
                return_origin: FixedOriginV2::Agent8768,
                transfer,
            } => {
                require_nonzero_capability(transfer, 32)?;
                transfer
            }
            _ => return Err(AuthError::AuthenticationFailed),
        };
        let completed = self.send_authentication(
            BrowserRoute::AgentUiAuthenticationComplete,
            BrowserService::Agent,
            BrowserOrigin::Approval,
            BrowserContentType::FormUrlEncoded,
            form_transfer(settlement)?,
            BrowserContentType::Html,
        )?;
        let attributes = extract_main_data_attributes(
            completed.body(),
            &[
                ("data-agent-tab", MAX_CAPABILITY_ATTRIBUTE_BYTES),
                ("data-agent-document", MAX_CAPABILITY_ATTRIBUTE_BYTES),
            ],
        )?;
        let tab: AgentTabSessionCapabilityV2 = decode_capability_attribute(&attributes[0], 32)?;
        let document: AgentMaskedDocumentRefV2 = decode_capability_attribute(&attributes[1], 16)?;
        let binding = SessionBinding::random().map_err(|_| AuthError::AuthenticationFailed)?;
        Ok(Session::authenticated_agent(
            self.transport.clone(),
            self.nonces.clone(),
            binding,
            tab,
            document,
            webauthn,
            approval,
        ))
    }

    pub fn enroll(
        &self,
        enrollment_token: &str,
        code: &str,
        webauthn: &dyn WebAuthnProvider,
        identity_path: &Path,
    ) -> Result<Identity, AuthError> {
        if code.is_empty() || code.len() > 256 {
            return Err(AuthError::EnrollmentFailed);
        }
        let enrollment: EnrollmentHandleV2 = decode_capability_attribute(enrollment_token, 32)
            .map_err(|_| AuthError::EnrollmentFailed)?;
        let nonce = self.next_nonce().map_err(|_| AuthError::EnrollmentFailed)?;
        let code =
            ZeroizingTextV2::new(code.to_owned()).map_err(|_| AuthError::EnrollmentFailed)?;
        let request = BeginEnrollmentBrowserRequestV2::new(enrollment, nonce, code)
            .map_err(|_| AuthError::EnrollmentFailed)?;
        let body = encode_begin_enrollment_browser_request_v2(&request)
            .map_err(|_| AuthError::EnrollmentFailed)?;
        let begun = self.send_enrollment(
            BrowserRoute::ApprovalEnrollmentBegin,
            body,
            BrowserContentType::CanonicalCbor,
        )?;
        let (ceremony, options_json) = decode_begin_enrollment_browser_response_v2(begun.body())
            .map_err(|_| AuthError::EnrollmentFailed)?
            .into_parts();
        let attestation = webauthn.create_credential(&options_json)?;
        let (credential_id, client_data_json, attestation_object) = attestation.into_parts();
        let persisted_credential_id = credential_id.to_vec();
        let finish_nonce = self.next_nonce().map_err(|_| AuthError::EnrollmentFailed)?;
        let request = FinishEnrollmentBrowserRequestV2::new(
            ceremony,
            finish_nonce,
            credential_id.to_vec(),
            client_data_json.to_vec(),
            attestation_object.to_vec(),
        )
        .map_err(|_| AuthError::EnrollmentFailed)?;
        let body = encode_finish_enrollment_browser_request_v2(&request)
            .map_err(|_| AuthError::EnrollmentFailed)?;
        let finished = self.send_enrollment(
            BrowserRoute::ApprovalEnrollmentFinish,
            body,
            BrowserContentType::CanonicalCbor,
        )?;
        let decoded = decode_finish_enrollment_browser_response_v2(finished.body())
            .map_err(|_| AuthError::EnrollmentFailed)?;
        let (digest, state) = enrollment_response_parts(decoded)?;
        Identity::persist(identity_path, digest, persisted_credential_id, state)
    }

    fn send_authentication(
        &self,
        route: BrowserRoute,
        service: BrowserService,
        origin: BrowserOrigin,
        content_type: BrowserContentType,
        body: Vec<u8>,
        expected_content_type: BrowserContentType,
    ) -> Result<BrowserResponse, AuthError> {
        send(
            self,
            BrowserRequest {
                service,
                route,
                origin,
                content_type,
                body,
            },
            expected_content_type,
            AuthError::AuthenticationFailed,
        )
    }

    fn send_enrollment(
        &self,
        route: BrowserRoute,
        body: Vec<u8>,
        expected_content_type: BrowserContentType,
    ) -> Result<BrowserResponse, AuthError> {
        send(
            self,
            BrowserRequest {
                service: BrowserService::Approval,
                route,
                origin: BrowserOrigin::Approval,
                content_type: BrowserContentType::CanonicalCbor,
                body,
            },
            expected_content_type,
            AuthError::EnrollmentFailed,
        )
    }
}

fn send(
    client: &Client,
    request: BrowserRequest,
    expected_content_type: BrowserContentType,
    error: AuthError,
) -> Result<BrowserResponse, AuthError> {
    request.validate().map_err(|_| error)?;
    let response = client.transport().send(request).map_err(|_| error)?;
    if response.content_type() != expected_content_type {
        return Err(error);
    }
    Ok(response)
}

pub(crate) fn form_transfer<T: minicbor::Encode<()>>(transfer: T) -> Result<Vec<u8>, AuthError> {
    let encoded = minicbor::to_vec(transfer).map_err(|_| AuthError::AuthenticationFailed)?;
    let raw = decode_single_bytes(&encoded, 32)?;
    Ok(format!("transfer={}", URL_SAFE_NO_PAD.encode(raw)).into_bytes())
}

pub(crate) fn decode_capability_attribute<T>(
    value: &str,
    expected_length: usize,
) -> Result<T, AuthError>
where
    for<'bytes> T: minicbor::Decode<'bytes, V2DecodeContext> + minicbor::Encode<()>,
{
    let encoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| AuthError::AuthenticationFailed)?;
    if URL_SAFE_NO_PAD.encode(&encoded) != value {
        return Err(AuthError::AuthenticationFailed);
    }
    decode_single_bytes(&encoded, expected_length)?;
    let mut decoder = minicbor::Decoder::new(&encoded);
    let mut context = V2DecodeContext;
    let capability =
        T::decode(&mut decoder, &mut context).map_err(|_| AuthError::AuthenticationFailed)?;
    if decoder.position() != encoded.len()
        || minicbor::to_vec(&capability).map_err(|_| AuthError::AuthenticationFailed)? != encoded
    {
        return Err(AuthError::AuthenticationFailed);
    }
    Ok(capability)
}

fn require_nonzero_capability<T: minicbor::Encode<()>>(
    capability: T,
    expected_length: usize,
) -> Result<(), AuthError> {
    let encoded = minicbor::to_vec(capability).map_err(|_| AuthError::AuthenticationFailed)?;
    decode_single_bytes(&encoded, expected_length).map(|_| ())
}

fn decode_single_bytes(encoded: &[u8], expected_length: usize) -> Result<&[u8], AuthError> {
    let mut decoder = minicbor::Decoder::new(encoded);
    let bytes = decoder
        .bytes()
        .map_err(|_| AuthError::AuthenticationFailed)?;
    if bytes.len() != expected_length
        || bytes.iter().all(|byte| *byte == 0)
        || decoder.position() != encoded.len()
    {
        return Err(AuthError::AuthenticationFailed);
    }
    Ok(bytes)
}

fn enrollment_response_parts(
    value: savana_kernel_protocol::v2::FinishEnrollmentBrowserResponseV2,
) -> Result<([u8; 32], PublicCredentialState), AuthError> {
    let encoded = encode_finish_enrollment_browser_response_v2(value)
        .map_err(|_| AuthError::EnrollmentFailed)?;
    let mut decoder = minicbor::Decoder::new(&encoded);
    if decoder.array().map_err(|_| AuthError::EnrollmentFailed)? != Some(2) {
        return Err(AuthError::EnrollmentFailed);
    }
    let mut context = V2DecodeContext;
    let digest =
        Digest32V2::decode(&mut decoder, &mut context).map_err(|_| AuthError::EnrollmentFailed)?;
    let state = CredentialPublicStateV2::decode(&mut decoder, &mut context)
        .map_err(|_| AuthError::EnrollmentFailed)?;
    if decoder.position() != encoded.len() || digest.as_bytes() == &[0; 32] {
        return Err(AuthError::EnrollmentFailed);
    }
    let state = match state {
        CredentialPublicStateV2::Active => PublicCredentialState::Active,
        CredentialPublicStateV2::Revoked => PublicCredentialState::Revoked,
    };
    Ok((*digest.as_bytes(), state))
}

pub(crate) fn extract_main_data_attributes(
    html: &[u8],
    required: &[(&str, usize)],
) -> Result<Vec<String>, AuthError> {
    if html.is_empty() || html.len() > MAX_AUTHENTICATION_HTML_BYTES {
        return Err(AuthError::AuthenticationFailed);
    }
    let html = core::str::from_utf8(html).map_err(|_| AuthError::AuthenticationFailed)?;
    const DOCUMENT_PREFIX: &str = "<!doctype html><html><head>";
    const HEAD_END: &str = "</head><body>";
    const MAIN_PREFIX: &str = "<main ";
    const DOCUMENT_SUFFIX: &str =
        "</main><script src=\"/v2/savana-ui.js\" defer></script></body></html>";
    const AUTHENTICATION_HEAD: &str =
        "<meta charset=\"utf-8\"><title>Savana authentication</title>";
    const AUTHENTICATION_CONTENT: &str = "<h1>Hardware authentication required</h1><button id=\"savana-authenticate\" type=\"button\">Use security key</button><p id=\"savana-status\">The opaque capability is held only in this page.</p>";
    const AGENT_HEAD: &str = "<meta charset=\"utf-8\"><title>Savana agent</title>";
    const PASSKEY_AUTHENTICATION_CONTENT: &str = "<h1>User verification required</h1><button id=\"savana-authenticate\" type=\"button\">Use passkey or security key</button><p id=\"savana-status\">The opaque capability is held only in this page.</p>";
    const AGENT_CONTENT: &str = "<h1>Authenticated Savana agent</h1><pre id=\"savana-agent-view\"></pre><section id=\"savana-agent-actions\"></section><pre id=\"savana-agent-result\"></pre><p id=\"savana-status\">Loading kernel view…</p>";
    let (expected_head, expected_content) = match required {
        [("data-purpose", _), ("data-pre-authentication", _)] => {
            (AUTHENTICATION_HEAD, AUTHENTICATION_CONTENT)
        }
        [("data-agent-tab", _), ("data-agent-document", _)] => (AGENT_HEAD, AGENT_CONTENT),
        _ => return Err(AuthError::AuthenticationFailed),
    };
    if !html.starts_with(DOCUMENT_PREFIX)
        || html.contains("<!--")
        || html.contains("-->")
        || html.matches(HEAD_END).count() != 1
        || !html.ends_with(DOCUMENT_SUFFIX)
    {
        return Err(AuthError::AuthenticationFailed);
    }
    let after_prefix = &html[DOCUMENT_PREFIX.len()..];
    let head_end = after_prefix
        .find(HEAD_END)
        .ok_or(AuthError::AuthenticationFailed)?;
    let head = &after_prefix[..head_end];
    if head != expected_head {
        return Err(AuthError::AuthenticationFailed);
    }
    let body = &after_prefix[head_end + HEAD_END.len()..];
    if !body.starts_with(MAIN_PREFIX) || body.matches("<main").count() != 1 {
        return Err(AuthError::AuthenticationFailed);
    }
    let after_main = &body[MAIN_PREFIX.len()..];
    let relative_end = after_main
        .find('>')
        .ok_or(AuthError::AuthenticationFailed)?;
    if relative_end > MAX_MAIN_TAG_BYTES {
        return Err(AuthError::AuthenticationFailed);
    }
    let attributes = &after_main[..relative_end];
    let values = parse_exact_attributes(attributes, required)?;
    let main_content_and_suffix = &after_main[relative_end + 1..];
    let content_length = main_content_and_suffix
        .len()
        .checked_sub(DOCUMENT_SUFFIX.len())
        .ok_or(AuthError::AuthenticationFailed)?;
    let content = &main_content_and_suffix[..content_length];
    // Both are exact pinned templates, never arbitrary browser-provided HTML.
    if content != expected_content
        && !(expected_head == AUTHENTICATION_HEAD && content == PASSKEY_AUTHENTICATION_CONTENT)
    {
        return Err(AuthError::AuthenticationFailed);
    }
    Ok(values)
}

fn parse_exact_attributes(
    attributes: &str,
    required: &[(&str, usize)],
) -> Result<Vec<String>, AuthError> {
    let bytes = attributes.as_bytes();
    let mut offset = 0;
    let mut values = Vec::with_capacity(required.len());
    for (index, (required_name, maximum)) in required.iter().enumerate() {
        if index > 0 {
            let separator_start = offset;
            while offset < bytes.len() && bytes[offset].is_ascii_whitespace() {
                offset += 1;
            }
            if separator_start == offset {
                return Err(AuthError::AuthenticationFailed);
            }
        }
        if !attributes[offset..].starts_with(required_name) {
            return Err(AuthError::AuthenticationFailed);
        }
        offset += required_name.len();
        while offset < bytes.len() && bytes[offset].is_ascii_whitespace() {
            offset += 1;
        }
        if bytes.get(offset) != Some(&b'=') {
            return Err(AuthError::AuthenticationFailed);
        }
        offset += 1;
        while offset < bytes.len() && bytes[offset].is_ascii_whitespace() {
            offset += 1;
        }
        if bytes.get(offset) != Some(&b'"') {
            return Err(AuthError::AuthenticationFailed);
        }
        offset += 1;
        let value_start = offset;
        while offset < bytes.len() && bytes[offset] != b'"' {
            if !bytes[offset].is_ascii() || bytes[offset] == b'&' || bytes[offset] == b'<' {
                return Err(AuthError::AuthenticationFailed);
            }
            offset += 1;
        }
        if bytes.get(offset) != Some(&b'"') {
            return Err(AuthError::AuthenticationFailed);
        }
        let value = &attributes[value_start..offset];
        offset += 1;
        if value.is_empty() || value.len() > *maximum {
            return Err(AuthError::AuthenticationFailed);
        }
        values.push(value.to_owned());
    }
    while offset < bytes.len() && bytes[offset].is_ascii_whitespace() {
        offset += 1;
    }
    if offset != bytes.len() {
        return Err(AuthError::AuthenticationFailed);
    }
    Ok(values)
}
