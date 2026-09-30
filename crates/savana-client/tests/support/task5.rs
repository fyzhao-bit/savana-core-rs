use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use savana_client::{
    ApprovalCallback, ApprovalRequest, AuthError, BrowserContentType, BrowserResponse, Client,
    ClientEndpoints, Identity, NonceSource, SavanaError, Session, SessionBootstrap,
    WebAuthnAssertion, WebAuthnAttestation, WebAuthnProvider,
};
use savana_kernel_protocol::v2::{
    approval_display_digest_v2, encode_approval_decision_browser_begin_response_v2,
    encode_approval_decision_browser_finish_response_v2, encode_approval_display_view_v2,
    encode_ui_authentication_browser_begin_response_v2,
    encode_ui_authentication_browser_finish_response_v2, render_agent_workspace_v2,
    AgentMaskedDocumentRefV2, AgentTabSessionCapabilityV2,
    AgentUiAuthenticationBrowserCeremonyCapabilityV2,
    AgentUiAuthenticationSettlementTransferCapabilityV2, AgentUiPreAuthenticationTabCapabilityV2,
    ApprovalDecisionBrowserBeginResponseV2, ApprovalDecisionBrowserFinishResponseV2,
    ApprovalDecisionCeremonyCapabilityV2,
    ApprovalDisplayUiAuthenticationBrowserCeremonyCapabilityV2,
    ApprovalDisplayUiPreAuthenticationTabCapabilityV2, ApprovalDisplayViewV2, ApprovalPurposeV2,
    ApprovalTabSessionCapabilityV2, BoundedApprovalDisplayTextV2, Digest32V2, FixedOriginV2,
    Nonce32V2, UiAuthenticationBrowserBeginResponseV2, UiAuthenticationBrowserFinishResponseV2,
};
use zeroize::Zeroizing;

use super::ScriptedTransport;

pub struct FixedNonces(Mutex<u8>);

impl FixedNonces {
    pub fn new() -> Self {
        Self(Mutex::new(1))
    }
}

impl NonceSource for FixedNonces {
    fn nonce(&self) -> Result<Nonce32V2, SavanaError> {
        let mut next = self.0.lock().map_err(|_| SavanaError::transport())?;
        let nonce = Nonce32V2::new([*next; 32]);
        *next = next.checked_add(1).ok_or(SavanaError::InvalidState)?;
        Ok(nonce)
    }
}

#[derive(Default)]
pub struct RecordingWebAuthn {
    pub options: Mutex<Vec<Vec<u8>>>,
}

impl WebAuthnProvider for RecordingWebAuthn {
    fn assert_credential(&self, options_json: &[u8]) -> Result<WebAuthnAssertion, AuthError> {
        self.options
            .lock()
            .map_err(|_| AuthError::AuthenticationFailed)?
            .push(options_json.to_vec());
        WebAuthnAssertion::new(
            vec![0x61; 16],
            vec![0x62; 32],
            br#"{"type":"webauthn.get"}"#.to_vec(),
            vec![0x63; 64],
            vec![0x64; 32],
        )
    }

    fn create_credential(&self, _options_json: &[u8]) -> Result<WebAuthnAttestation, AuthError> {
        Err(AuthError::EnrollmentFailed)
    }
}

#[derive(Default)]
pub struct RecordingDecision {
    decision: bool,
    pub requests: Mutex<Vec<(String, savana_client::ApprovalPurpose)>>,
}

impl RecordingDecision {
    pub fn new(decision: bool) -> Self {
        Self {
            decision,
            ..Self::default()
        }
    }
}

impl ApprovalCallback for RecordingDecision {
    fn decide(&self, request: &ApprovalRequest) -> Result<bool, SavanaError> {
        self.requests
            .lock()
            .map_err(|_| SavanaError::InvalidState)?
            .push((request.display().to_owned(), request.purpose()));
        Ok(self.decision)
    }
}

pub fn endpoints() -> ClientEndpoints {
    ClientEndpoints::new(
        "http://localhost:8768",
        "http://localhost:8767",
        "http://localhost:8766",
    )
    .unwrap()
}

pub fn response(content_type: BrowserContentType, body: Vec<u8>) -> BrowserResponse {
    BrowserResponse::from_scripted(content_type, body).unwrap()
}

pub fn cbor_response(body: Vec<u8>) -> Result<BrowserResponse, SavanaError> {
    Ok(response(BrowserContentType::CanonicalCbor, body))
}

pub fn html_response(body: Vec<u8>) -> Result<BrowserResponse, SavanaError> {
    Ok(response(BrowserContentType::Html, body))
}

pub fn authentication_html<T: minicbor::Encode<()>>(purpose: &str, capability: T) -> Vec<u8> {
    let capability = URL_SAFE_NO_PAD.encode(minicbor::to_vec(capability).unwrap());
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>Savana authentication</title></head><body><main data-purpose=\"{purpose}\" data-pre-authentication=\"{capability}\"><h1>User verification required</h1><button id=\"savana-authenticate\" type=\"button\">Use passkey or security key</button><p id=\"savana-status\">The opaque capability is held only in this page.</p></main><script src=\"/v2/savana-ui.js\" defer></script></body></html>"
    )
    .into_bytes()
}

fn temporary_directory(label: &str) -> PathBuf {
    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "savana-client-task5-{label}-{}-{stamp}-{}",
        std::process::id(),
        NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed),
    ));
    fs::create_dir(&path).unwrap();
    path
}

fn identity_file(root: &Path) -> PathBuf {
    let path = root.join("identity.json");
    fs::write(
        &path,
        b"{\"version\":2,\"credential_digest\":\"d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3c\",\"credential_id\":\"YWFhYWFhYWFhYWFhYWFhYQ\",\"public_credential_state\":\"active\"}",
    )
    .unwrap();
    #[cfg(unix)]
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    path
}

fn initial_authentication_responses() -> Vec<Result<BrowserResponse, SavanaError>> {
    let pre_authentication =
        AgentUiPreAuthenticationTabCapabilityV2::from_authority_entropy([0x31; 32]).unwrap();
    let ceremony =
        AgentUiAuthenticationBrowserCeremonyCapabilityV2::from_authority_entropy([0x32; 32])
            .unwrap();
    let settlement =
        AgentUiAuthenticationSettlementTransferCapabilityV2::from_authority_entropy([0x33; 32])
            .unwrap();
    let tab = AgentTabSessionCapabilityV2::from_authority_entropy([0x34; 32]).unwrap();
    let document = AgentMaskedDocumentRefV2::from_authority_entropy([0x35; 16]).unwrap();
    vec![
        html_response(authentication_html("agent", pre_authentication)),
        cbor_response(
            encode_ui_authentication_browser_begin_response_v2(
                &UiAuthenticationBrowserBeginResponseV2::Agent {
                    ceremony,
                    public_key_options_json: Zeroizing::new(b"agent-options".to_vec()),
                },
            )
            .unwrap(),
        ),
        cbor_response(
            encode_ui_authentication_browser_finish_response_v2(
                UiAuthenticationBrowserFinishResponseV2::TransferToAgent {
                    return_origin: FixedOriginV2::Agent8768,
                    transfer: settlement,
                },
            )
            .unwrap(),
        ),
        html_response(render_agent_workspace_v2(tab, document)),
    ]
}

pub fn authenticated_session(
    mut responses: Vec<Result<BrowserResponse, SavanaError>>,
) -> (Session, Arc<ScriptedTransport>, Arc<RecordingWebAuthn>) {
    let mut scripted = initial_authentication_responses();
    scripted.append(&mut responses);
    let transport = Arc::new(ScriptedTransport::new(scripted));
    let provider = Arc::new(RecordingWebAuthn::default());
    let client = Client::with_transport_and_nonce_source(
        endpoints(),
        transport.clone(),
        Arc::new(FixedNonces::new()),
    );
    let root = temporary_directory("identity");
    let identity = Identity::load(&identity_file(&root)).unwrap();
    let mut bootstrap =
        SessionBootstrap::from_control_plane_token(&URL_SAFE_NO_PAD.encode([0x21; 32])).unwrap();
    let session = client
        .session(
            &identity,
            &mut bootstrap,
            provider.clone(),
            Arc::new(RecordingDecision::new(true)),
        )
        .unwrap();
    (session, transport, provider)
}

pub fn approval_responses(
    purpose: ApprovalPurposeV2,
    finish: ApprovalDecisionBrowserFinishResponseV2,
) -> Vec<Result<BrowserResponse, SavanaError>> {
    let pre_authentication =
        ApprovalDisplayUiPreAuthenticationTabCapabilityV2::from_authority_entropy([0x71; 32])
            .unwrap();
    let auth_ceremony =
        ApprovalDisplayUiAuthenticationBrowserCeremonyCapabilityV2::from_authority_entropy(
            [0x72; 32],
        )
        .unwrap();
    let tab = ApprovalTabSessionCapabilityV2::from_authority_entropy([0x73; 32]).unwrap();
    let decision_ceremony =
        ApprovalDecisionCeremonyCapabilityV2::from_authority_entropy([0x74; 32]).unwrap();
    let display_text =
        BoundedApprovalDisplayTextV2::new("Approve exact operation".to_owned()).unwrap();
    let display = ApprovalDisplayViewV2::new(
        purpose,
        Digest32V2::new([0x75; 32]),
        approval_display_digest_v2(display_text.as_bytes()),
        display_text,
        Digest32V2::new([0x76; 32]),
    )
    .unwrap();
    vec![
        html_response(authentication_html("approval-display", pre_authentication)),
        cbor_response(
            encode_ui_authentication_browser_begin_response_v2(
                &UiAuthenticationBrowserBeginResponseV2::ApprovalDisplay {
                    ceremony: auth_ceremony,
                    public_key_options_json: Zeroizing::new(b"approval-auth-options".to_vec()),
                },
            )
            .unwrap(),
        ),
        cbor_response(
            encode_ui_authentication_browser_finish_response_v2(
                UiAuthenticationBrowserFinishResponseV2::ApprovalDisplayReady { tab },
            )
            .unwrap(),
        ),
        cbor_response(encode_approval_display_view_v2(&display).unwrap()),
        cbor_response(
            encode_approval_decision_browser_begin_response_v2(
                &ApprovalDecisionBrowserBeginResponseV2::new(
                    decision_ceremony,
                    b"approval-decision-options".to_vec(),
                )
                .unwrap(),
            )
            .unwrap(),
        ),
        cbor_response(encode_approval_decision_browser_finish_response_v2(finish).unwrap()),
    ]
}
pub fn task_authorization_draft() -> savana_kernel_protocol::v2::TaskAuthorizationDraftV2 {
    use savana_kernel_protocol::v2::*;
    let d = |n| Digest32V2::new([n; 32]);
    let profile = BusinessProfileV2::new(
        ActionCodecProfileV2::McpToolsCallJsonV1,
        "mail.send",
        d(1),
        d(2),
        TaskEffectV2::Send,
        BusinessMagnitudeV2::FixedCount(1),
        vec![
            BusinessFieldV2::new(
                "body",
                BusinessFieldRoleV2::Payload,
                BusinessFieldTypeV2::Text,
            )
            .unwrap(),
            BusinessFieldV2::new(
                "file",
                BusinessFieldRoleV2::Resource,
                BusinessFieldTypeV2::Text,
            )
            .unwrap(),
            BusinessFieldV2::new(
                "to",
                BusinessFieldRoleV2::Destination,
                BusinessFieldTypeV2::Text,
            )
            .unwrap(),
        ],
    )
    .unwrap();
    let controls = BusinessControlsV2::from_fields(
        &profile,
        vec![
            ("file".into(), BusinessValueV2::Text("A".into())),
            ("to".into(), BusinessValueV2::Text("Alice".into())),
        ],
    )
    .unwrap();
    TaskAuthorizationDraftV2::new(
        d(3),
        PrincipalIdV2::new([4; 32]),
        DurableTaskIdV2::new([5; 32]),
        1,
        d(6),
        d(7),
        1,
        UnixMillisV2::new(1),
        UnixMillisV2::new(100),
        d(8),
        vec![TaskAuthorizationDraftClauseV2::new(
            1,
            vec![TaskAuthorizationDraftAlternativeV2::new(d(9), controls).unwrap()],
            1,
            1,
            1,
            vec![],
            false,
        )
        .unwrap()],
    )
    .unwrap()
}
