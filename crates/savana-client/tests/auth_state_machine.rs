mod support;

use std::fs;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use minicbor::Encode as _;
use savana_client::{
    AuthError, BrowserContentType, BrowserOrigin, BrowserResponse, BrowserRoute, Client,
    ClientEndpoints, HandleKind, Identity, NonceSource, SavanaError, SessionBootstrap,
    WebAuthnAssertion, WebAuthnAttestation, WebAuthnProvider,
};
use savana_kernel_protocol::v2::{
    decode_begin_enrollment_browser_request_v2, decode_finish_enrollment_browser_request_v2,
    decode_ui_authentication_browser_begin_request_v2,
    decode_ui_authentication_browser_finish_request_v2,
    encode_begin_enrollment_browser_response_v2, encode_finish_enrollment_browser_response_v2,
    encode_ui_authentication_browser_begin_response_v2,
    encode_ui_authentication_browser_finish_response_v2, render_agent_workspace_v2,
    AgentMaskedDocumentRefV2, AgentTabSessionCapabilityV2,
    AgentUiAuthenticationBrowserCeremonyCapabilityV2,
    AgentUiAuthenticationSettlementTransferCapabilityV2, AgentUiPreAuthenticationTabCapabilityV2,
    BeginEnrollmentBrowserResponseV2, CredentialPublicStateV2, Digest32V2,
    EnrollmentCeremonyCapabilityV2, FinishEnrollmentBrowserResponseV2, FixedOriginV2,
    IngressUiAuthenticationSettlementTransferCapabilityV2, Nonce32V2,
    UiAuthenticationBrowserBeginRequestV2, UiAuthenticationBrowserBeginResponseV2,
    UiAuthenticationBrowserFinishRequestV2, UiAuthenticationBrowserFinishResponseV2,
};
use support::ScriptedTransport;
use zeroize::Zeroizing;

struct FixedNonces(Mutex<u8>);

impl FixedNonces {
    fn new() -> Self {
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
struct RecordingWebAuthn {
    assertion_options: Mutex<Vec<Vec<u8>>>,
    creation_options: Mutex<Vec<Vec<u8>>>,
    reject_assertion: bool,
}

impl RecordingWebAuthn {
    fn rejecting_assertion() -> Self {
        Self {
            reject_assertion: true,
            ..Self::default()
        }
    }
}

impl WebAuthnProvider for RecordingWebAuthn {
    fn assert_credential(&self, options_json: &[u8]) -> Result<WebAuthnAssertion, AuthError> {
        self.assertion_options
            .lock()
            .map_err(|_| AuthError::AuthenticationFailed)?
            .push(options_json.to_vec());
        if self.reject_assertion {
            return Err(AuthError::AuthenticationFailed);
        }
        WebAuthnAssertion::new(
            vec![0x61; 16],
            vec![0x62; 32],
            br#"{"type":"webauthn.get"}"#.to_vec(),
            vec![0x63; 64],
            vec![0x64; 32],
        )
    }

    fn create_credential(&self, options_json: &[u8]) -> Result<WebAuthnAttestation, AuthError> {
        self.creation_options
            .lock()
            .map_err(|_| AuthError::EnrollmentFailed)?
            .push(options_json.to_vec());
        WebAuthnAttestation::new(
            vec![0x61; 16],
            br#"{"type":"webauthn.create"}"#.to_vec(),
            vec![0x65; 128],
        )
    }
}

fn endpoints() -> ClientEndpoints {
    ClientEndpoints::new(
        "http://localhost:8768",
        "http://localhost:8767",
        "http://localhost:8766",
    )
    .unwrap()
}

fn scripted_client(
    responses: Vec<Result<BrowserResponse, SavanaError>>,
) -> (Client, Arc<ScriptedTransport>) {
    let transport = Arc::new(ScriptedTransport::new(responses));
    let client = Client::with_transport_and_nonce_source(
        endpoints(),
        transport.clone(),
        Arc::new(FixedNonces::new()),
    );
    (client, transport)
}

fn response(content_type: BrowserContentType, body: Vec<u8>) -> BrowserResponse {
    BrowserResponse::from_scripted(content_type, body).unwrap()
}

fn encoded_capability<T: minicbor::Encode<()>>(capability: T) -> String {
    URL_SAFE_NO_PAD.encode(minicbor::to_vec(capability).unwrap())
}

fn authentication_html(purpose: &str, pre_authentication: &str) -> Vec<u8> {
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>Savana authentication</title></head><body><main data-purpose=\"{purpose}\" data-pre-authentication=\"{pre_authentication}\"><h1>Hardware authentication required</h1><button id=\"savana-authenticate\" type=\"button\">Use security key</button><p id=\"savana-status\">The opaque capability is held only in this page.</p></main><script src=\"/v2/savana-ui.js\" defer></script></body></html>"
    )
    .into_bytes()
}

fn agent_html(tab: AgentTabSessionCapabilityV2, document: AgentMaskedDocumentRefV2) -> Vec<u8> {
    render_agent_workspace_v2(tab, document)
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

fn bootstrap() -> SessionBootstrap {
    SessionBootstrap::from_control_plane_token(&URL_SAFE_NO_PAD.encode([0x21; 32])).unwrap()
}

fn successful_auth_responses() -> Vec<Result<BrowserResponse, SavanaError>> {
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
        Ok(response(
            BrowserContentType::Html,
            authentication_html("agent", &encoded_capability(pre_authentication)),
        )),
        Ok(response(
            BrowserContentType::CanonicalCbor,
            encode_ui_authentication_browser_begin_response_v2(
                &UiAuthenticationBrowserBeginResponseV2::Agent {
                    ceremony,
                    public_key_options_json: Zeroizing::new(br#"{"challenge":"AQID"}"#.to_vec()),
                },
            )
            .unwrap(),
        )),
        Ok(response(
            BrowserContentType::CanonicalCbor,
            encode_ui_authentication_browser_finish_response_v2(
                UiAuthenticationBrowserFinishResponseV2::TransferToAgent {
                    return_origin: FixedOriginV2::Agent8768,
                    transfer: settlement,
                },
            )
            .unwrap(),
        )),
        Ok(response(
            BrowserContentType::Html,
            agent_html(tab, document),
        )),
    ]
}

#[test]
fn session_uses_the_exact_agent_authentication_sequence_and_keeps_capabilities_opaque() {
    let root = temporary_directory("session-success");
    let identity = Identity::load(&identity_file(&root)).unwrap();
    let provider = Arc::new(RecordingWebAuthn::default());
    let (client, transport) = scripted_client(successful_auth_responses());
    let mut bootstrap = bootstrap();

    let session = client
        .session(&identity, &mut bootstrap, provider.clone())
        .unwrap();

    assert_eq!(session.initial_document().kind(), HandleKind::Document);
    assert_eq!(format!("{session:?}"), "Session(<authenticated>)");
    assert_eq!(
        provider.assertion_options.lock().unwrap().as_slice(),
        [br#"{"challenge":"AQID"}"#.as_slice()]
    );

    let requests = transport.take_requests();
    assert_eq!(requests.len(), 4);
    assert_eq!(
        requests
            .iter()
            .map(|request| request.service)
            .collect::<Vec<_>>(),
        vec![
            savana_client::BrowserService::Approval,
            savana_client::BrowserService::Approval,
            savana_client::BrowserService::Approval,
            savana_client::BrowserService::Agent,
        ]
    );
    assert_eq!(
        requests
            .iter()
            .map(|request| (request.route, request.origin, request.content_type))
            .collect::<Vec<_>>(),
        vec![
            (
                BrowserRoute::ApprovalUiAuthenticationAccept,
                BrowserOrigin::Jarvis,
                BrowserContentType::FormUrlEncoded,
            ),
            (
                BrowserRoute::ApprovalUiAuthenticationBegin,
                BrowserOrigin::Approval,
                BrowserContentType::CanonicalCbor,
            ),
            (
                BrowserRoute::ApprovalUiAuthenticationFinish,
                BrowserOrigin::Approval,
                BrowserContentType::CanonicalCbor,
            ),
            (
                BrowserRoute::AgentUiAuthenticationComplete,
                BrowserOrigin::Approval,
                BrowserContentType::FormUrlEncoded,
            ),
        ]
    );
    assert_eq!(decode_form_transfer(&requests[0].body), [0x21; 32]);
    match decode_ui_authentication_browser_begin_request_v2(&requests[1].body).unwrap() {
        UiAuthenticationBrowserBeginRequestV2::Agent {
            pre_authentication,
            client_request_nonce,
        } => {
            assert_eq!(
                pre_authentication,
                AgentUiPreAuthenticationTabCapabilityV2::from_authority_entropy([0x31; 32])
                    .unwrap()
            );
            assert_eq!(client_request_nonce, Nonce32V2::new([1; 32]));
        }
        _ => panic!("wrong begin request variant"),
    }
    match decode_ui_authentication_browser_finish_request_v2(&requests[2].body).unwrap() {
        UiAuthenticationBrowserFinishRequestV2::Agent {
            ceremony,
            client_request_nonce,
            assertion,
        } => {
            assert_eq!(
                ceremony,
                AgentUiAuthenticationBrowserCeremonyCapabilityV2::from_authority_entropy(
                    [0x32; 32]
                )
                .unwrap()
            );
            assert_eq!(client_request_nonce, Nonce32V2::new([1; 32]));
            assert_eq!(assertion.credential_id(), &[0x61; 16]);
            assert_eq!(assertion.authenticator_data(), &[0x62; 32]);
            assert_eq!(assertion.signature(), &[0x63; 64]);
        }
        _ => panic!("wrong finish request variant"),
    }
    assert_eq!(decode_form_transfer(&requests[3].body), [0x33; 32]);
}

#[test]
fn authentication_html_rejects_comment_wrapped_or_truncated_main_carriers() {
    let root = temporary_directory("ambiguous-auth-html");
    let identity = Identity::load(&identity_file(&root)).unwrap();
    let pre_authentication = encoded_capability(
        AgentUiPreAuthenticationTabCapabilityV2::from_authority_entropy([0x31; 32]).unwrap(),
    );
    let fake_main = format!(
        "<!doctype html><html><head><title>Savana</title></head><body><!--<main data-purpose=\"agent\" data-pre-authentication=\"{pre_authentication}\"></main>--><script src=\"/v2/savana-ui.js\" defer></script></body></html>"
    )
    .into_bytes();
    let truncated = format!(
        "<!doctype html><html><head><title>Savana</title></head><body><main data-purpose=\"agent\" data-pre-authentication=\"{pre_authentication}\">"
    )
    .into_bytes();

    for html in [fake_main, truncated] {
        let (client, transport) =
            scripted_client(vec![Ok(response(BrowserContentType::Html, html))]);
        assert!(client
            .session(
                &identity,
                &mut bootstrap(),
                Arc::new(RecordingWebAuthn::default()),
            )
            .is_err());
        assert_eq!(transport.take_requests().len(), 1);
    }
}

#[test]
fn authentication_html_rejects_duplicate_unbounded_or_unexpected_data_attributes() {
    let root = temporary_directory("invalid-auth-attributes");
    let identity = Identity::load(&identity_file(&root)).unwrap();
    let capability = encoded_capability(
        AgentUiPreAuthenticationTabCapabilityV2::from_authority_entropy([0x31; 32]).unwrap(),
    );
    let invalid_openings = [
        format!(
            "data-purpose=\"agent\" data-purpose=\"agent\" data-pre-authentication=\"{capability}\""
        ),
        format!(
            "data-purpose=\"agent\" data-pre-authentication=\"{}\"",
            "A".repeat(129)
        ),
        format!(
            "data-purpose=\"agent\" data-pre-authentication=\"{capability}\" data-extra=\"no\""
        ),
    ];
    for opening in invalid_openings {
        let html = format!(
            "<!doctype html><html><head><title>Savana</title></head><body><main {opening}></main><script src=\"/v2/savana-ui.js\" defer></script></body></html>"
        )
        .into_bytes();
        let (client, transport) =
            scripted_client(vec![Ok(response(BrowserContentType::Html, html))]);
        assert!(client
            .session(
                &identity,
                &mut bootstrap(),
                Arc::new(RecordingWebAuthn::default()),
            )
            .is_err());
        assert_eq!(transport.take_requests().len(), 1);
    }
}

#[test]
fn completion_html_rejects_malformed_envelopes_and_zero_capabilities() {
    let root = temporary_directory("invalid-completion-html");
    let identity = Identity::load(&identity_file(&root)).unwrap();
    let tab = AgentTabSessionCapabilityV2::from_authority_entropy([0x34; 32]).unwrap();
    let document = AgentMaskedDocumentRefV2::from_authority_entropy([0x35; 16]).unwrap();
    let malformed = format!(
        "<!doctype html><html><head><title>Savana</title></head><body><!--<main data-agent-tab=\"{}\" data-agent-document=\"{}\"></main>--><script src=\"/v2/savana-ui.js\" defer></script></body></html>",
        encoded_capability(tab),
        encoded_capability(document),
    )
    .into_bytes();
    let zero_tab = format!(
        "<!doctype html><html><head><title>Savana</title></head><body><main data-agent-tab=\"{}\" data-agent-document=\"{}\"></main><script src=\"/v2/savana-ui.js\" defer></script></body></html>",
        encoded_raw_capability(&[0; 32]),
        encoded_capability(document),
    )
    .into_bytes();
    let zero_document = format!(
        "<!doctype html><html><head><title>Savana</title></head><body><main data-agent-tab=\"{}\" data-agent-document=\"{}\"></main><script src=\"/v2/savana-ui.js\" defer></script></body></html>",
        encoded_capability(tab),
        encoded_raw_capability(&[0; 16]),
    )
    .into_bytes();
    let extra_markup = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>Savana agent</title></head><body><main data-agent-tab=\"{}\" data-agent-document=\"{}\"><aside>ambiguous</aside></main><script src=\"/v2/savana-ui.js\" defer></script></body></html>",
        encoded_capability(tab),
        encoded_capability(document),
    )
    .into_bytes();

    for completion in [malformed, zero_tab, zero_document, extra_markup] {
        let mut responses = successful_auth_responses();
        responses[3] = Ok(response(BrowserContentType::Html, completion));
        let (client, transport) = scripted_client(responses);
        assert!(client
            .session(
                &identity,
                &mut bootstrap(),
                Arc::new(RecordingWebAuthn::default()),
            )
            .is_err());
        assert_eq!(transport.take_requests().len(), 4);
    }
}

#[test]
fn session_fails_closed_on_wrong_variant_malformed_carrier_and_callback_rejection() {
    let root = temporary_directory("session-failures");
    let identity = Identity::load(&identity_file(&root)).unwrap();

    let ingress_ceremony = savana_kernel_protocol::v2::IngressUiAuthenticationBrowserCeremonyCapabilityV2::from_authority_entropy([0x41; 32]).unwrap();
    let mut wrong_variant_responses = successful_auth_responses();
    wrong_variant_responses[1] = Ok(response(
        BrowserContentType::CanonicalCbor,
        encode_ui_authentication_browser_begin_response_v2(
            &UiAuthenticationBrowserBeginResponseV2::Ingress {
                ceremony: ingress_ceremony,
                public_key_options_json: Zeroizing::new(br#"{"challenge":"AQID"}"#.to_vec()),
            },
        )
        .unwrap(),
    ));
    let (client, transport) = scripted_client(wrong_variant_responses);
    assert!(client
        .session(
            &identity,
            &mut bootstrap(),
            Arc::new(RecordingWebAuthn::default()),
        )
        .is_err());
    assert_eq!(transport.take_requests().len(), 2);

    let (client, transport) = scripted_client(vec![Ok(response(
        BrowserContentType::Html,
        authentication_html("agent", "AA%00"),
    ))]);
    assert!(client
        .session(
            &identity,
            &mut bootstrap(),
            Arc::new(RecordingWebAuthn::default()),
        )
        .is_err());
    assert_eq!(transport.take_requests().len(), 1);

    let (client, transport) = scripted_client(successful_auth_responses());
    let mut one_shot = bootstrap();
    assert!(client
        .session(
            &identity,
            &mut one_shot,
            Arc::new(RecordingWebAuthn::rejecting_assertion()),
        )
        .is_err());
    assert!(matches!(
        client.session(
            &identity,
            &mut one_shot,
            Arc::new(RecordingWebAuthn::default()),
        ),
        Err(AuthError::InvalidBootstrap)
    ));
    assert_eq!(transport.take_requests().len(), 2);
}

#[test]
fn session_rejects_zero_transfer_and_a_mismatched_return_origin() {
    let root = temporary_directory("session-transfer-failures");
    let identity = Identity::load(&identity_file(&root)).unwrap();

    let mut zero_transfer = successful_auth_responses();
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder.array(3).unwrap().u16(3).unwrap();
    FixedOriginV2::Agent8768
        .encode(&mut encoder, &mut ())
        .unwrap();
    encoder.bytes(&[0; 32]).unwrap();
    zero_transfer[2] = Ok(response(
        BrowserContentType::CanonicalCbor,
        encoder.into_writer(),
    ));
    let (client, transport) = scripted_client(zero_transfer);
    assert!(client
        .session(
            &identity,
            &mut bootstrap(),
            Arc::new(RecordingWebAuthn::default()),
        )
        .is_err());
    assert_eq!(transport.take_requests().len(), 3);

    let mut wrong_origin = successful_auth_responses();
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder.array(3).unwrap().u16(3).unwrap();
    FixedOriginV2::Ingress8767
        .encode(&mut encoder, &mut ())
        .unwrap();
    encoder.bytes(&[0x52; 32]).unwrap();
    wrong_origin[2] = Ok(response(
        BrowserContentType::CanonicalCbor,
        encoder.into_writer(),
    ));
    let (client, transport) = scripted_client(wrong_origin);
    assert!(client
        .session(
            &identity,
            &mut bootstrap(),
            Arc::new(RecordingWebAuthn::default()),
        )
        .is_err());
    assert_eq!(transport.take_requests().len(), 3);
}

#[test]
fn session_rejects_a_wrong_finish_response_variant() {
    let root = temporary_directory("wrong-finish-variant");
    let identity = Identity::load(&identity_file(&root)).unwrap();
    let mut responses = successful_auth_responses();
    responses[2] = Ok(response(
        BrowserContentType::CanonicalCbor,
        encode_ui_authentication_browser_finish_response_v2(
            UiAuthenticationBrowserFinishResponseV2::TransferToIngress {
                return_origin: FixedOriginV2::Ingress8767,
                transfer:
                    IngressUiAuthenticationSettlementTransferCapabilityV2::from_authority_entropy(
                        [0x53; 32],
                    )
                    .unwrap(),
            },
        )
        .unwrap(),
    ));
    let (client, transport) = scripted_client(responses);

    assert!(client
        .session(
            &identity,
            &mut bootstrap(),
            Arc::new(RecordingWebAuthn::default()),
        )
        .is_err());
    assert_eq!(transport.take_requests().len(), 3);
}

#[test]
fn enrollment_persists_only_canonical_public_identity_with_private_mode() {
    let root = temporary_directory("enrollment");
    let path = root.join("enrolled.json");
    let enrollment = encoded_capability(
        savana_kernel_protocol::v2::EnrollmentHandleV2::from_authority_entropy([0x71; 32]).unwrap(),
    );
    let ceremony = EnrollmentCeremonyCapabilityV2::from_authority_entropy([0x72; 32]).unwrap();
    let digest = Digest32V2::new([0x77; 32]);
    let provider = RecordingWebAuthn::default();
    let (client, transport) = scripted_client(vec![
        Ok(response(
            BrowserContentType::CanonicalCbor,
            encode_begin_enrollment_browser_response_v2(
                &BeginEnrollmentBrowserResponseV2::new(
                    ceremony,
                    br#"{"challenge":"BAUG"}"#.to_vec(),
                )
                .unwrap(),
            )
            .unwrap(),
        )),
        Ok(response(
            BrowserContentType::CanonicalCbor,
            encode_finish_enrollment_browser_response_v2(
                FinishEnrollmentBrowserResponseV2::new(digest, CredentialPublicStateV2::Active)
                    .unwrap(),
            )
            .unwrap(),
        )),
    ]);

    let identity = client
        .enroll(&enrollment, "one-time-code", &provider, &path)
        .unwrap();

    assert_eq!(format!("{identity:?}"), "Identity(<public-credential>)");
    assert_eq!(Identity::load(&path).unwrap(), identity);
    let bytes = fs::read(&path).unwrap();
    assert_eq!(
        bytes,
        b"{\"version\":2,\"credential_digest\":\"d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3c\",\"credential_id\":\"YWFhYWFhYWFhYWFhYWFhYQ\",\"public_credential_state\":\"active\"}"
    );
    assert!(!String::from_utf8_lossy(&bytes).contains("private"));
    #[cfg(unix)]
    assert_eq!(fs::metadata(&path).unwrap().mode() & 0o7777, 0o600);

    let requests = transport.take_requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].route, BrowserRoute::ApprovalEnrollmentBegin);
    assert_eq!(requests[1].route, BrowserRoute::ApprovalEnrollmentFinish);
    assert_eq!(requests[0].origin, BrowserOrigin::Approval);
    assert_eq!(requests[1].origin, BrowserOrigin::Approval);
    decode_begin_enrollment_browser_request_v2(&requests[0].body).unwrap();
    decode_finish_enrollment_browser_request_v2(&requests[1].body).unwrap();
    assert_eq!(
        provider.creation_options.lock().unwrap().as_slice(),
        [br#"{"challenge":"BAUG"}"#.as_slice()]
    );
}

#[test]
fn identity_load_rejects_partial_noncanonical_or_permissive_files() {
    let root = temporary_directory("identity-rejections");
    for (name, bytes) in [
        ("partial.json", br#"{"version":2}"#.as_slice()),
        (
            "whitespace.json",
            b" {\"version\":2,\"credential_digest\":\"d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3c\",\"credential_id\":\"YWFhYWFhYWFhYWFhYWFhYQ\",\"public_credential_state\":\"active\"}",
        ),
        (
            "unknown.json",
            b"{\"version\":2,\"credential_digest\":\"d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3c\",\"credential_id\":\"YWFhYWFhYWFhYWFhYWFhYQ\",\"public_credential_state\":\"active\",\"private_key\":\"forbidden\"}",
        ),
    ] {
        let path = root.join(name);
        fs::write(&path, bytes).unwrap();
        #[cfg(unix)]
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(Identity::load(&path).is_err());
    }

    #[cfg(unix)]
    {
        let path = identity_file(&root);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(Identity::load(&path).is_err());
    }

    let oversized = root.join("oversized.json");
    fs::write(&oversized, vec![b'a'; 32 * 1024 + 1]).unwrap();
    #[cfg(unix)]
    fs::set_permissions(&oversized, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(Identity::load(&oversized).is_err());
}

#[test]
fn a_revoked_identity_is_loaded_for_inspection_but_cannot_start_a_session() {
    let root = temporary_directory("revoked-identity");
    let path = identity_file(&root);
    let active = fs::read_to_string(&path).unwrap();
    fs::write(&path, active.replace("\"active\"", "\"revoked\"")).unwrap();
    #[cfg(unix)]
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let identity = Identity::load(&path).unwrap();
    let (client, transport) = scripted_client(successful_auth_responses());
    let mut one_shot = bootstrap();

    assert!(matches!(
        client.session(
            &identity,
            &mut one_shot,
            Arc::new(RecordingWebAuthn::default()),
        ),
        Err(AuthError::AuthenticationFailed)
    ));
    assert!(matches!(
        client.session(
            &identity,
            &mut one_shot,
            Arc::new(RecordingWebAuthn::default()),
        ),
        Err(AuthError::InvalidBootstrap)
    ));
    assert!(transport.take_requests().is_empty());
}

#[test]
fn webauthn_carriers_redact_all_credential_material() {
    let assertion = WebAuthnAssertion::new(
        b"credential-marker".to_vec(),
        b"authenticator-marker".to_vec(),
        b"client-data-marker".to_vec(),
        b"signature-marker".to_vec(),
        vec![0x44; 32],
    )
    .unwrap();
    let attestation = WebAuthnAttestation::new(
        b"credential-marker".to_vec(),
        b"client-data-marker".to_vec(),
        b"attestation-marker".to_vec(),
    )
    .unwrap();
    assert_eq!(format!("{assertion:?}"), "WebAuthnAssertion(<redacted>)");
    assert_eq!(
        format!("{attestation:?}"),
        "WebAuthnAttestation(<redacted>)"
    );
}

fn temporary_directory(label: &str) -> PathBuf {
    let mut random = [0_u8; 8];
    getrandom::getrandom(&mut random).unwrap();
    let path = std::env::temp_dir().join(format!(
        "savana-client-auth-{label}-{}-{}",
        std::process::id(),
        u64::from_le_bytes(random)
    ));
    fs::create_dir(&path).unwrap();
    path
}

fn decode_form_transfer(body: &[u8]) -> [u8; 32] {
    let token = body.strip_prefix(b"transfer=").unwrap();
    URL_SAFE_NO_PAD.decode(token).unwrap().try_into().unwrap()
}

fn encoded_raw_capability(bytes: &[u8]) -> String {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder.bytes(bytes).unwrap();
    URL_SAFE_NO_PAD.encode(encoder.into_writer())
}
