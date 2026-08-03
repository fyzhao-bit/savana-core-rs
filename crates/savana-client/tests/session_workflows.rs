mod support;

use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use savana_client::{
    AuthError, BrowserContentType, BrowserResponse, BrowserRoute, Client, ClientEndpoints,
    ContentKind, HandleKind, Identity, IntentPrivacy, NonceSource, SavanaError, Session,
    SessionBootstrap, WebAuthnAssertion, WebAuthnAttestation, WebAuthnProvider,
};
use savana_kernel_protocol::v2::{
    approval_display_digest_v2, decode_agent_browser_request_v2,
    decode_approval_decision_browser_begin_request_v2, decode_ingress_browser_request_v2,
    encode_agent_browser_mutation_response_v2, encode_agent_browser_read_view_response_v2,
    encode_approval_decision_browser_begin_response_v2,
    encode_approval_decision_browser_finish_response_v2, encode_approval_display_view_v2,
    encode_ingress_browser_mutation_response_v2,
    encode_ui_authentication_browser_begin_response_v2,
    encode_ui_authentication_browser_finish_response_v2, render_agent_workspace_v2,
    render_ingress_ui_authentication_form_v2, render_ingress_workspace_v2, AgentBrowserActionV2,
    AgentBrowserMutationResponseV2, AgentBrowserReadViewResponseV2, AgentBrowserRequestV2,
    AgentContentStateV2, AgentMaskedDocumentRefV2, AgentPlanStepRefV2, AgentSessionStatusV2,
    AgentTabSessionCapabilityV2, AgentViewV2, ApprovalDecisionBrowserBeginResponseV2,
    ApprovalDecisionBrowserFinishResponseV2, ApprovalDecisionCeremonyCapabilityV2,
    ApprovalDecisionV2, ApprovalDisplayAuthenticationTransferCapabilityV2,
    ApprovalDisplayUiAuthenticationBrowserCeremonyCapabilityV2,
    ApprovalDisplayUiPreAuthenticationTabCapabilityV2, ApprovalDisplayViewV2, ApprovalPurposeV2,
    ApprovalTabSessionCapabilityV2, BoundedAgentTextV2, BoundedApprovalDisplayTextV2,
    ContentKindV2, Digest32V2, FixedBrowserFormPostCarrierV2, FixedOriginV2,
    IngressBrowserMutationResponseV2, IngressBrowserRequestV2, IngressTabSessionCapabilityV2,
    IngressUiAuthenticationBrowserCeremonyCapabilityV2,
    IngressUiAuthenticationSettlementTransferCapabilityV2,
    IngressUiAuthenticationTransferCapabilityV2, IngressUiPreAuthenticationTabCapabilityV2,
    InputPublicStateV2, KernelIngressBootstrapTransferCapabilityV2, Nonce32V2, StaticTemplateIdV2,
    UiAuthenticationBrowserBeginResponseV2, UiAuthenticationBrowserFinishResponseV2,
    VaultPublicStateV2,
};
use sha2::{Digest as _, Sha256};
use support::ScriptedTransport;
use zeroize::Zeroizing;

const CHUNK_BYTES: usize = 256 * 1024;

struct FixedNonces(Mutex<u8>);

impl FixedNonces {
    fn new() -> Self {
        Self(Mutex::new(1))
    }
}

struct FailOnceNonces {
    next: Mutex<u8>,
    fail_on_call: u8,
}

impl FailOnceNonces {
    fn new(fail_on_call: u8) -> Self {
        Self {
            next: Mutex::new(1),
            fail_on_call,
        }
    }
}

impl NonceSource for FailOnceNonces {
    fn nonce(&self) -> Result<Nonce32V2, SavanaError> {
        let mut next = self.next.lock().map_err(|_| SavanaError::transport())?;
        let call = *next;
        *next = next.checked_add(1).ok_or(SavanaError::InvalidState)?;
        if call == self.fail_on_call {
            return Err(SavanaError::transport());
        }
        Ok(Nonce32V2::new([call; 32]))
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
    options: Mutex<Vec<Vec<u8>>>,
    reject_on_call: Option<usize>,
}

impl RecordingWebAuthn {
    fn rejecting_call(call: usize) -> Self {
        Self {
            reject_on_call: Some(call),
            ..Self::default()
        }
    }
}

impl WebAuthnProvider for RecordingWebAuthn {
    fn assert_credential(&self, options_json: &[u8]) -> Result<WebAuthnAssertion, AuthError> {
        let mut options = self
            .options
            .lock()
            .map_err(|_| AuthError::AuthenticationFailed)?;
        options.push(options_json.to_vec());
        if self.reject_on_call == Some(options.len()) {
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

    fn create_credential(&self, _options_json: &[u8]) -> Result<WebAuthnAttestation, AuthError> {
        Err(AuthError::EnrollmentFailed)
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

fn response(content_type: BrowserContentType, body: Vec<u8>) -> BrowserResponse {
    BrowserResponse::from_scripted(content_type, body).unwrap()
}

fn cbor_response(body: Vec<u8>) -> Result<BrowserResponse, SavanaError> {
    Ok(response(BrowserContentType::CanonicalCbor, body))
}

fn html_response(body: Vec<u8>) -> Result<BrowserResponse, SavanaError> {
    Ok(response(BrowserContentType::Html, body))
}

fn authentication_html<T: minicbor::Encode<()>>(purpose: &str, capability: T) -> Vec<u8> {
    let capability = URL_SAFE_NO_PAD.encode(minicbor::to_vec(capability).unwrap());
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>Savana authentication</title></head><body><main data-purpose=\"{purpose}\" data-pre-authentication=\"{capability}\"><h1>Hardware authentication required</h1><button id=\"savana-authenticate\" type=\"button\">Use security key</button><p id=\"savana-status\">The opaque capability is held only in this page.</p></main><script src=\"/v2/savana-ui.js\" defer></script></body></html>"
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
        "savana-client-task4-{label}-{}-{stamp}-{}",
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
        savana_kernel_protocol::v2::AgentUiPreAuthenticationTabCapabilityV2::from_authority_entropy(
            [0x31; 32],
        )
        .unwrap();
    let ceremony = savana_kernel_protocol::v2::AgentUiAuthenticationBrowserCeremonyCapabilityV2::from_authority_entropy([0x32; 32]).unwrap();
    let settlement = savana_kernel_protocol::v2::AgentUiAuthenticationSettlementTransferCapabilityV2::from_authority_entropy([0x33; 32]).unwrap();
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

fn authenticated_session(
    responses: Vec<Result<BrowserResponse, SavanaError>>,
) -> (Session, Arc<ScriptedTransport>, Arc<RecordingWebAuthn>) {
    authenticated_session_with_provider(responses, Arc::new(RecordingWebAuthn::default()))
}

fn authenticated_session_with_provider(
    responses: Vec<Result<BrowserResponse, SavanaError>>,
    webauthn: Arc<RecordingWebAuthn>,
) -> (Session, Arc<ScriptedTransport>, Arc<RecordingWebAuthn>) {
    authenticated_session_with_dependencies(responses, webauthn, Arc::new(FixedNonces::new()))
}

fn authenticated_session_with_dependencies(
    mut responses: Vec<Result<BrowserResponse, SavanaError>>,
    webauthn: Arc<RecordingWebAuthn>,
    nonces: Arc<dyn NonceSource>,
) -> (Session, Arc<ScriptedTransport>, Arc<RecordingWebAuthn>) {
    let mut scripted = initial_authentication_responses();
    scripted.append(&mut responses);
    let transport = Arc::new(ScriptedTransport::new(scripted));
    let client = Client::with_transport_and_nonce_source(endpoints(), transport.clone(), nonces);
    let root = temporary_directory("identity");
    let identity = Identity::load(&identity_file(&root)).unwrap();
    let mut bootstrap =
        SessionBootstrap::from_control_plane_token(&URL_SAFE_NO_PAD.encode([0x21; 32])).unwrap();
    let session = client
        .session(&identity, &mut bootstrap, webauthn.clone())
        .unwrap();
    (session, transport, webauthn)
}

fn approval_display() -> ApprovalDisplayViewV2 {
    let display_text =
        BoundedApprovalDisplayTextV2::new("Commit masked ingress".to_owned()).unwrap();
    ApprovalDisplayViewV2::new(
        ApprovalPurposeV2::Ingress,
        Digest32V2::new([0x91; 32]),
        approval_display_digest_v2(display_text.as_bytes()),
        display_text,
        Digest32V2::new([0x92; 32]),
    )
    .unwrap()
}

fn successful_ingress_responses(chunks: usize) -> Vec<Result<BrowserResponse, SavanaError>> {
    let bootstrap =
        KernelIngressBootstrapTransferCapabilityV2::from_authority_entropy([0x41; 32]).unwrap();
    let ingress_transfer =
        IngressUiAuthenticationTransferCapabilityV2::from_authority_entropy([0x42; 32]).unwrap();
    let ingress_pre_authentication =
        IngressUiPreAuthenticationTabCapabilityV2::from_authority_entropy([0x43; 32]).unwrap();
    let ingress_ceremony =
        IngressUiAuthenticationBrowserCeremonyCapabilityV2::from_authority_entropy([0x44; 32])
            .unwrap();
    let ingress_settlement =
        IngressUiAuthenticationSettlementTransferCapabilityV2::from_authority_entropy([0x45; 32])
            .unwrap();
    let ingress_tab = IngressTabSessionCapabilityV2::from_authority_entropy([0x46; 32]).unwrap();
    let approval_transfer =
        ApprovalDisplayAuthenticationTransferCapabilityV2::from_authority_entropy([0x47; 32])
            .unwrap();
    let approval_pre_authentication =
        ApprovalDisplayUiPreAuthenticationTabCapabilityV2::from_authority_entropy([0x48; 32])
            .unwrap();
    let approval_auth_ceremony =
        ApprovalDisplayUiAuthenticationBrowserCeremonyCapabilityV2::from_authority_entropy(
            [0x49; 32],
        )
        .unwrap();
    let approval_tab = ApprovalTabSessionCapabilityV2::from_authority_entropy([0x4a; 32]).unwrap();
    let decision_ceremony =
        ApprovalDecisionCeremonyCapabilityV2::from_authority_entropy([0x4b; 32]).unwrap();

    let mut responses = vec![
        cbor_response(
            encode_agent_browser_mutation_response_v2(
                &AgentBrowserMutationResponseV2::FollowupOpenIngress {
                    post: FixedBrowserFormPostCarrierV2::AgentFollowupIngress(bootstrap),
                },
            )
            .unwrap(),
        ),
        html_response(render_ingress_ui_authentication_form_v2(ingress_transfer)),
        html_response(authentication_html("ingress", ingress_pre_authentication)),
        cbor_response(
            encode_ui_authentication_browser_begin_response_v2(
                &UiAuthenticationBrowserBeginResponseV2::Ingress {
                    ceremony: ingress_ceremony,
                    public_key_options_json: Zeroizing::new(b"ingress-options".to_vec()),
                },
            )
            .unwrap(),
        ),
        cbor_response(
            encode_ui_authentication_browser_finish_response_v2(
                UiAuthenticationBrowserFinishResponseV2::TransferToIngress {
                    return_origin: FixedOriginV2::Ingress8767,
                    transfer: ingress_settlement,
                },
            )
            .unwrap(),
        ),
        html_response(render_ingress_workspace_v2(ingress_tab)),
        cbor_response(
            encode_ingress_browser_mutation_response_v2(IngressBrowserMutationResponseV2::Begun {
                next_sequence: 0,
            })
            .unwrap(),
        ),
    ];
    for sequence in 0..chunks {
        responses.push(cbor_response(
            encode_ingress_browser_mutation_response_v2(
                IngressBrowserMutationResponseV2::ChunkAccepted {
                    acknowledged_sequence: sequence as u32,
                    cumulative_digest: Digest32V2::new([0x60 + sequence as u8; 32]),
                },
            )
            .unwrap(),
        ));
    }
    responses.extend([
        cbor_response(
            encode_ingress_browser_mutation_response_v2(
                IngressBrowserMutationResponseV2::FinalizeOpenApproval {
                    transfer: approval_transfer,
                },
            )
            .unwrap(),
        ),
        html_response(authentication_html(
            "approval-display",
            approval_pre_authentication,
        )),
        cbor_response(
            encode_ui_authentication_browser_begin_response_v2(
                &UiAuthenticationBrowserBeginResponseV2::ApprovalDisplay {
                    ceremony: approval_auth_ceremony,
                    public_key_options_json: Zeroizing::new(b"approval-auth-options".to_vec()),
                },
            )
            .unwrap(),
        ),
        cbor_response(
            encode_ui_authentication_browser_finish_response_v2(
                UiAuthenticationBrowserFinishResponseV2::ApprovalDisplayReady { tab: approval_tab },
            )
            .unwrap(),
        ),
        cbor_response(encode_approval_display_view_v2(&approval_display()).unwrap()),
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
        cbor_response(
            encode_approval_decision_browser_finish_response_v2(
                ApprovalDecisionBrowserFinishResponseV2::Approved,
            )
            .unwrap(),
        ),
        cbor_response(
            encode_ingress_browser_mutation_response_v2(
                IngressBrowserMutationResponseV2::FinalizeCommitted {
                    state: InputPublicStateV2::AgentClaimed,
                },
            )
            .unwrap(),
        ),
    ]);
    responses
}

#[test]
fn ingest_text_drives_exact_chunk_digest_authentication_and_approval_sequence() {
    let mut text = "x".repeat(CHUNK_BYTES * 2);
    text.push_str("end");
    let expected_digest = Digest32V2::new(Sha256::digest(text.as_bytes()).into());
    let (mut session, transport, webauthn) = authenticated_session(successful_ingress_responses(3));

    session.ingest_text(&text, ContentKind::ChatText).unwrap();

    assert_eq!(
        webauthn.options.lock().unwrap().as_slice(),
        [
            b"agent-options".as_slice(),
            b"ingress-options".as_slice(),
            b"approval-auth-options".as_slice(),
            b"approval-decision-options".as_slice(),
        ]
    );
    let requests = transport.take_requests();
    let workflow = &requests[4..];
    assert_eq!(
        workflow
            .iter()
            .map(|request| request.route)
            .collect::<Vec<_>>(),
        vec![
            BrowserRoute::AgentAction,
            BrowserRoute::IngressBootstrapAccept,
            BrowserRoute::ApprovalUiAuthenticationAccept,
            BrowserRoute::ApprovalUiAuthenticationBegin,
            BrowserRoute::ApprovalUiAuthenticationFinish,
            BrowserRoute::IngressUiAuthenticationComplete,
            BrowserRoute::IngressInputBegin,
            BrowserRoute::IngressInputChunk,
            BrowserRoute::IngressInputChunk,
            BrowserRoute::IngressInputChunk,
            BrowserRoute::IngressInputFinalize,
            BrowserRoute::ApprovalUiAuthenticationAccept,
            BrowserRoute::ApprovalUiAuthenticationBegin,
            BrowserRoute::ApprovalUiAuthenticationFinish,
            BrowserRoute::ApprovalDisplay,
            BrowserRoute::ApprovalDecisionBegin,
            BrowserRoute::ApprovalDecisionFinish,
            BrowserRoute::IngressInputFinalize,
        ]
    );
    match decode_agent_browser_request_v2(&workflow[0].body).unwrap() {
        AgentBrowserRequestV2::Act { action, .. } => {
            assert_eq!(action, AgentBrowserActionV2::PrepareFollowupIngress)
        }
        _ => panic!("prepare ingress must be an action"),
    }
    match decode_ingress_browser_request_v2(&workflow[6].body).unwrap() {
        IngressBrowserRequestV2::Begin {
            content_kind,
            declared_total_bytes,
            declared_content_digest,
            ..
        } => {
            assert_eq!(content_kind, ContentKindV2::ChatText);
            assert_eq!(declared_total_bytes, text.len() as u64);
            assert_eq!(declared_content_digest, Some(expected_digest));
        }
        _ => panic!("first ingress mutation must begin"),
    }
    for (index, request) in workflow[7..10].iter().enumerate() {
        match decode_ingress_browser_request_v2(&request.body).unwrap() {
            IngressBrowserRequestV2::Append {
                sequence, chunk, ..
            } => {
                assert_eq!(sequence, index as u32);
                let expected_len = if index == 2 { 3 } else { CHUNK_BYTES };
                assert_eq!(chunk.as_bytes().len(), expected_len);
            }
            _ => panic!("expected append"),
        }
    }
    for index in [10, 17] {
        match decode_ingress_browser_request_v2(&workflow[index].body).unwrap() {
            IngressBrowserRequestV2::Finalize {
                declared_content_digest,
                ..
            } => assert_eq!(declared_content_digest, expected_digest),
            _ => panic!("expected finalize"),
        }
    }
    assert_eq!(
        decode_approval_decision_browser_begin_request_v2(&workflow[15].body)
            .unwrap()
            .decision(),
        ApprovalDecisionV2::Approve
    );
}

#[test]
fn read_view_preserves_each_protocol_variant_without_flattening() {
    let views = vec![
        AgentViewV2::masked_text(BoundedAgentTextV2::new("masked").unwrap(), vec![]).unwrap(),
        AgentViewV2::Structured {
            template: StaticTemplateIdV2::new(7),
            fields: vec![],
        },
        AgentViewV2::DocumentPage {
            page_index: 3,
            text: BoundedAgentTextV2::new("page").unwrap(),
            placeholders: vec![],
        },
        AgentViewV2::ContentState(AgentContentStateV2::Ready),
    ];
    let responses = views
        .into_iter()
        .map(|view| {
            cbor_response(
                encode_agent_browser_read_view_response_v2(
                    &AgentBrowserReadViewResponseV2::new(view, vec![], None).unwrap(),
                )
                .unwrap(),
            )
        })
        .collect();
    let (mut session, transport, _) = authenticated_session(responses);
    let document = session.initial_document().clone();

    let first = session.read_view(&document).unwrap();
    assert_eq!(first.masked_text().unwrap().0, "masked");
    let second = session.read_view(&document).unwrap();
    assert_eq!(second.structured().unwrap().0, StaticTemplateIdV2::new(7));
    let third = session.read_view(&document).unwrap();
    assert_eq!(third.document_page().unwrap().0, 3);
    let fourth = session.read_view(&document).unwrap();
    assert_eq!(fourth.content_state(), Some(AgentContentStateV2::Ready));

    for request in &transport.take_requests()[4..] {
        assert_eq!(request.route, BrowserRoute::AgentView);
    }
}

#[test]
fn planner_privacy_selects_exact_actions_and_accepts_only_planner_committed() {
    let first_step = AgentPlanStepRefV2::from_authority_entropy([0x71; 16]).unwrap();
    let second_step = AgentPlanStepRefV2::from_authority_entropy([0x72; 16]).unwrap();
    let responses = vec![
        cbor_response(
            encode_agent_browser_mutation_response_v2(
                &AgentBrowserMutationResponseV2::PlannerCommitted {
                    steps: vec![first_step],
                },
            )
            .unwrap(),
        ),
        cbor_response(
            encode_agent_browser_mutation_response_v2(
                &AgentBrowserMutationResponseV2::PlannerCommitted {
                    steps: vec![second_step],
                },
            )
            .unwrap(),
        ),
        cbor_response(
            encode_agent_browser_mutation_response_v2(
                &AgentBrowserMutationResponseV2::SessionClosed {
                    state: AgentSessionStatusV2::Closed,
                },
            )
            .unwrap(),
        ),
    ];
    let (mut session, transport, _) = authenticated_session(responses);

    let private = session.run_planner(IntentPrivacy::Private).unwrap();
    let third_party = session.run_planner(IntentPrivacy::ThirdParty).unwrap();
    assert_eq!(private.steps().len(), 1);
    assert_eq!(private.steps()[0].handle().kind(), HandleKind::PlanStep);
    assert_eq!(third_party.steps().len(), 1);
    assert!(matches!(
        session.run_planner(IntentPrivacy::Private),
        Err(SavanaError::InvalidResponse)
    ));
    assert!(matches!(
        session.run_planner(IntentPrivacy::Private),
        Err(SavanaError::InvalidState)
    ));

    let actions = transport.take_requests()[4..]
        .iter()
        .map(
            |request| match decode_agent_browser_request_v2(&request.body).unwrap() {
                AgentBrowserRequestV2::Act { action, .. } => action,
                _ => panic!("planner must use agent action"),
            },
        )
        .collect::<Vec<_>>();
    assert_eq!(
        actions,
        vec![
            AgentBrowserActionV2::RunPlanner,
            AgentBrowserActionV2::RunPlannerWithThirdPartyMapper,
            AgentBrowserActionV2::RunPlanner,
        ]
    );
}

#[test]
fn revoke_and_close_require_exact_terminal_states_and_close_locally() {
    let responses = vec![
        cbor_response(
            encode_agent_browser_mutation_response_v2(
                &AgentBrowserMutationResponseV2::VaultRevoked {
                    state: VaultPublicStateV2::Revoked,
                },
            )
            .unwrap(),
        ),
        cbor_response(
            encode_agent_browser_mutation_response_v2(
                &AgentBrowserMutationResponseV2::PlannerCommitted { steps: vec![] },
            )
            .unwrap(),
        ),
        cbor_response(
            encode_agent_browser_mutation_response_v2(
                &AgentBrowserMutationResponseV2::SessionClosed {
                    state: AgentSessionStatusV2::Closed,
                },
            )
            .unwrap(),
        ),
    ];
    let (mut session, transport, _) = authenticated_session(responses);
    let document = session.initial_document().clone();

    session.revoke(&document).unwrap();
    assert!(matches!(
        session.read_view(&document),
        Err(SavanaError::InvalidState)
    ));
    assert!(session
        .run_planner(IntentPrivacy::Private)
        .unwrap()
        .steps()
        .is_empty());
    session.close().unwrap();
    assert!(matches!(
        session.run_planner(IntentPrivacy::Private),
        Err(SavanaError::InvalidState)
    ));
    session.close().unwrap();

    let requests = transport.take_requests();
    assert_eq!(
        requests.len(),
        7,
        "second close must be local and idempotent"
    );
    assert!(matches!(
        decode_agent_browser_request_v2(&requests[4].body).unwrap(),
        AgentBrowserRequestV2::Act {
            action: AgentBrowserActionV2::RevokeVault(_),
            ..
        }
    ));
    assert!(matches!(
        decode_agent_browser_request_v2(&requests[5].body).unwrap(),
        AgentBrowserRequestV2::Act {
            action: AgentBrowserActionV2::RunPlanner,
            ..
        }
    ));
    assert!(matches!(
        decode_agent_browser_request_v2(&requests[6].body).unwrap(),
        AgentBrowserRequestV2::Act {
            action: AgentBrowserActionV2::CloseSession,
            ..
        }
    ));
}

#[test]
fn revoke_and_close_reject_nonterminal_states_and_remain_locally_fail_closed() {
    let (mut revoke_session, revoke_transport, _) = authenticated_session(vec![cbor_response(
        encode_agent_browser_mutation_response_v2(&AgentBrowserMutationResponseV2::VaultRevoked {
            state: VaultPublicStateV2::Live,
        })
        .unwrap(),
    )]);
    let document = revoke_session.initial_document().clone();
    assert!(matches!(
        revoke_session.revoke(&document),
        Err(SavanaError::InvalidResponse)
    ));
    assert!(matches!(
        revoke_session.read_view(&document),
        Err(SavanaError::InvalidState)
    ));
    assert!(matches!(
        revoke_session.run_planner(IntentPrivacy::Private),
        Err(SavanaError::InvalidState)
    ));
    assert_eq!(revoke_transport.take_requests().len(), 5);

    let (mut close_session, close_transport, _) = authenticated_session(vec![cbor_response(
        encode_agent_browser_mutation_response_v2(&AgentBrowserMutationResponseV2::SessionClosed {
            state: AgentSessionStatusV2::Ready,
        })
        .unwrap(),
    )]);
    assert!(matches!(
        close_session.close(),
        Err(SavanaError::InvalidResponse)
    ));
    assert!(matches!(
        close_session.run_planner(IntentPrivacy::Private),
        Err(SavanaError::InvalidState)
    ));
    assert_eq!(close_transport.take_requests().len(), 5);
}

fn assert_revoke_failure_closes_locally(
    revoke_response: Result<BrowserResponse, SavanaError>,
) -> SavanaError {
    let (mut session, transport, _) = authenticated_session(vec![revoke_response]);
    let document = session.initial_document().clone();

    let error = session.revoke(&document).unwrap_err();
    assert!(matches!(
        session.run_planner(IntentPrivacy::Private),
        Err(SavanaError::InvalidState)
    ));
    let requests = transport.take_requests();
    assert_eq!(requests.len(), 5);
    assert!(matches!(
        decode_agent_browser_request_v2(&requests[4].body).unwrap(),
        AgentBrowserRequestV2::Act {
            action: AgentBrowserActionV2::RevokeVault(_),
            ..
        }
    ));
    error
}

#[test]
fn lost_revoke_response_closes_locally_without_later_transport() {
    assert!(matches!(
        assert_revoke_failure_closes_locally(Err(SavanaError::Transport)),
        SavanaError::Transport
    ));
}

#[test]
fn malformed_revoke_response_closes_locally_without_later_transport() {
    assert!(matches!(
        assert_revoke_failure_closes_locally(cbor_response(vec![0xff])),
        SavanaError::InvalidResponse
    ));
}

#[test]
fn wrong_content_type_revoke_response_closes_locally_without_later_transport() {
    assert!(matches!(
        assert_revoke_failure_closes_locally(html_response(b"wrong type".to_vec())),
        SavanaError::InvalidResponse
    ));
}

#[test]
fn append_acknowledgement_error_issues_real_abort_before_returning() {
    let mut responses = successful_ingress_responses(1);
    responses.truncate(8);
    responses[7] = cbor_response(
        encode_ingress_browser_mutation_response_v2(
            IngressBrowserMutationResponseV2::ChunkAccepted {
                acknowledged_sequence: 9,
                cumulative_digest: Digest32V2::new([0x61; 32]),
            },
        )
        .unwrap(),
    );
    responses.push(cbor_response(
        encode_ingress_browser_mutation_response_v2(IngressBrowserMutationResponseV2::Aborted)
            .unwrap(),
    ));
    let (mut session, transport, _) = authenticated_session(responses);

    assert!(matches!(
        session.ingest_text("abort me", ContentKind::PlainText),
        Err(SavanaError::InvalidResponse)
    ));
    let requests = transport.take_requests();
    assert_eq!(
        requests.last().unwrap().route,
        BrowserRoute::IngressInputAbort
    );
    assert!(matches!(
        decode_ingress_browser_request_v2(&requests.last().unwrap().body).unwrap(),
        IngressBrowserRequestV2::Abort { .. }
    ));
}

#[test]
fn unexpected_prepare_ingress_response_closes_locally_before_any_input() {
    let (mut session, transport, _) = authenticated_session(vec![cbor_response(
        encode_agent_browser_mutation_response_v2(
            &AgentBrowserMutationResponseV2::PlannerCommitted { steps: vec![] },
        )
        .unwrap(),
    )]);

    assert!(matches!(
        session.ingest_text("wrong prepare", ContentKind::PlainText),
        Err(SavanaError::InvalidResponse)
    ));
    assert!(matches!(
        session.run_planner(IntentPrivacy::Private),
        Err(SavanaError::InvalidState)
    ));
    assert_eq!(transport.take_requests().len(), 5);
}

#[test]
fn failed_ingress_authentication_closes_locally_before_begin() {
    let mut responses = successful_ingress_responses(1);
    responses.truncate(2);
    responses[1] = html_response(b"malformed ingress transfer form".to_vec());
    let (mut session, transport, _) = authenticated_session(responses);

    assert!(matches!(
        session.ingest_text("auth failure", ContentKind::PlainText),
        Err(SavanaError::InvalidResponse)
    ));
    assert!(matches!(
        session.run_planner(IntentPrivacy::Private),
        Err(SavanaError::InvalidState)
    ));
    assert_eq!(transport.take_requests().len(), 6);
}

#[test]
fn nonce_failure_after_begin_uses_the_next_nonce_for_abort() {
    let mut responses = successful_ingress_responses(1);
    responses.truncate(7);
    responses.push(cbor_response(
        encode_ingress_browser_mutation_response_v2(IngressBrowserMutationResponseV2::Aborted)
            .unwrap(),
    ));
    let provider = Arc::new(RecordingWebAuthn::default());
    let (mut session, transport, _) = authenticated_session_with_dependencies(
        responses,
        provider,
        Arc::new(FailOnceNonces::new(5)),
    );

    assert!(matches!(
        session.ingest_text("nonce failure", ContentKind::PlainText),
        Err(SavanaError::Transport)
    ));
    assert_eq!(
        transport.take_requests().last().unwrap().route,
        BrowserRoute::IngressInputAbort
    );
}

#[test]
fn ingest_file_streams_one_open_regular_file_in_bounded_chunks() {
    let root = temporary_directory("file-ingress");
    let path = root.join("input.bin");
    let bytes = vec![0x7a; CHUNK_BYTES * 2 + 17];
    fs::write(&path, &bytes).unwrap();
    let expected_digest = Digest32V2::new(Sha256::digest(&bytes).into());
    let (mut session, transport, _) = authenticated_session(successful_ingress_responses(3));

    session
        .ingest_file(&path, ContentKind::ParsedDocument)
        .unwrap();

    let requests = transport.take_requests();
    let workflow = &requests[4..];
    match decode_ingress_browser_request_v2(&workflow[6].body).unwrap() {
        IngressBrowserRequestV2::Begin {
            content_kind,
            declared_total_bytes,
            declared_content_digest,
            ..
        } => {
            assert_eq!(content_kind, ContentKindV2::ParsedDocument);
            assert_eq!(declared_total_bytes, bytes.len() as u64);
            assert_eq!(declared_content_digest, Some(expected_digest));
        }
        _ => panic!("expected begin"),
    }
    let lengths = workflow[7..10]
        .iter()
        .map(
            |request| match decode_ingress_browser_request_v2(&request.body).unwrap() {
                IngressBrowserRequestV2::Append { chunk, .. } => chunk.as_bytes().len(),
                _ => panic!("expected append"),
            },
        )
        .collect::<Vec<_>>();
    assert_eq!(lengths, vec![CHUNK_BYTES, CHUNK_BYTES, 17]);
}

#[cfg(unix)]
#[test]
fn ingest_file_rejects_symlink_replacement_paths_before_transport() {
    use std::os::unix::fs::symlink;

    let root = temporary_directory("symlink-ingress");
    let target = root.join("target.txt");
    let link = root.join("link.txt");
    fs::write(&target, b"do not follow").unwrap();
    symlink(&target, &link).unwrap();
    let (mut session, transport, _) = authenticated_session(vec![]);

    assert!(matches!(
        session.ingest_file(&link, ContentKind::PlainText),
        Err(SavanaError::InvalidRequest)
    ));
    assert_eq!(transport.take_requests().len(), 4);
}

#[test]
fn approval_denial_is_settled_by_second_finalize_and_returns_typed_error() {
    let mut responses = successful_ingress_responses(1);
    responses[14] = cbor_response(
        encode_approval_decision_browser_finish_response_v2(
            ApprovalDecisionBrowserFinishResponseV2::Denied,
        )
        .unwrap(),
    );
    responses[15] = cbor_response(
        encode_ingress_browser_mutation_response_v2(
            IngressBrowserMutationResponseV2::FinalizeRejected {
                state: InputPublicStateV2::Denied,
            },
        )
        .unwrap(),
    );
    let (mut session, transport, _) = authenticated_session(responses);

    assert!(matches!(
        session.ingest_text("deny me", ContentKind::PlainText),
        Err(SavanaError::ApprovalDenied(_))
    ));
    assert_eq!(
        transport.take_requests().last().unwrap().route,
        BrowserRoute::IngressInputFinalize
    );
}

#[test]
fn handles_are_rejected_by_kind_session_revocation_and_closed_state_without_transport() {
    let step = AgentPlanStepRefV2::from_authority_entropy([0x81; 16]).unwrap();
    let first_responses = vec![
        cbor_response(
            encode_agent_browser_mutation_response_v2(
                &AgentBrowserMutationResponseV2::PlannerCommitted { steps: vec![step] },
            )
            .unwrap(),
        ),
        cbor_response(
            encode_agent_browser_mutation_response_v2(
                &AgentBrowserMutationResponseV2::SessionClosed {
                    state: AgentSessionStatusV2::Closed,
                },
            )
            .unwrap(),
        ),
    ];
    let (mut first, first_transport, _) = authenticated_session(first_responses);
    let (second, second_transport, _) = authenticated_session(vec![]);
    let own_document = first.initial_document().clone();
    let foreign_document = second.initial_document().clone();
    let plan = first.run_planner(IntentPrivacy::Private).unwrap();

    assert!(matches!(
        first.read_view(plan.steps()[0].handle()),
        Err(SavanaError::WrongHandleKind { .. })
    ));
    assert!(matches!(
        first.read_view(&foreign_document),
        Err(SavanaError::WrongSession)
    ));
    first.close().unwrap();
    assert!(matches!(
        first.read_view(&own_document),
        Err(SavanaError::InvalidState)
    ));
    assert_eq!(first_transport.take_requests().len(), 6);
    assert_eq!(second_transport.take_requests().len(), 4);
}

#[test]
fn begin_response_error_aborts_the_active_input_before_returning() {
    let mut responses = successful_ingress_responses(1);
    responses.truncate(7);
    responses[6] = cbor_response(
        encode_ingress_browser_mutation_response_v2(
            IngressBrowserMutationResponseV2::ChunkAccepted {
                acknowledged_sequence: 0,
                cumulative_digest: Digest32V2::new([0x82; 32]),
            },
        )
        .unwrap(),
    );
    responses.push(cbor_response(
        encode_ingress_browser_mutation_response_v2(IngressBrowserMutationResponseV2::Aborted)
            .unwrap(),
    ));
    let (mut session, transport, _) = authenticated_session(responses);

    assert!(matches!(
        session.ingest_text("begin error", ContentKind::PlainText),
        Err(SavanaError::InvalidResponse)
    ));
    assert_eq!(
        transport.take_requests().last().unwrap().route,
        BrowserRoute::IngressInputAbort
    );
}

#[test]
fn unconfirmed_abort_closes_the_session_locally() {
    let mut responses = successful_ingress_responses(1);
    responses.truncate(7);
    responses[6] = cbor_response(
        encode_ingress_browser_mutation_response_v2(
            IngressBrowserMutationResponseV2::ChunkAccepted {
                acknowledged_sequence: 0,
                cumulative_digest: Digest32V2::new([0x83; 32]),
            },
        )
        .unwrap(),
    );
    responses.push(cbor_response(
        encode_ingress_browser_mutation_response_v2(IngressBrowserMutationResponseV2::Begun {
            next_sequence: 0,
        })
        .unwrap(),
    ));
    let (mut session, transport, _) = authenticated_session(responses);

    assert!(matches!(
        session.ingest_text("abort indeterminate", ContentKind::PlainText),
        Err(SavanaError::InvalidResponse)
    ));
    assert!(matches!(
        session.run_planner(IntentPrivacy::Private),
        Err(SavanaError::InvalidState)
    ));
    assert_eq!(transport.take_requests().len(), 12);
}

#[test]
fn approval_failure_after_finalize_closes_locally_without_illegal_abort() {
    let provider = Arc::new(RecordingWebAuthn::rejecting_call(3));
    let (mut session, transport, _) =
        authenticated_session_with_provider(successful_ingress_responses(1), provider);

    assert!(matches!(
        session.ingest_text("approval failure", ContentKind::PlainText),
        Err(SavanaError::Auth(AuthError::AuthenticationFailed))
    ));
    assert!(matches!(
        session.run_planner(IntentPrivacy::Private),
        Err(SavanaError::InvalidState)
    ));
    let requests = transport.take_requests();
    assert_eq!(
        requests.last().unwrap().route,
        BrowserRoute::ApprovalUiAuthenticationBegin
    );
    assert!(!requests
        .iter()
        .any(|request| request.route == BrowserRoute::IngressInputAbort));
}

fn assert_first_finalize_failure_closes_without_abort(
    first_finalize_response: Result<BrowserResponse, SavanaError>,
) -> SavanaError {
    let mut responses = successful_ingress_responses(1);
    responses.truncate(9);
    responses[8] = first_finalize_response;
    let (mut session, transport, _) = authenticated_session(responses);

    let error = session
        .ingest_text("ambiguous first finalize", ContentKind::PlainText)
        .unwrap_err();
    assert!(matches!(
        session.run_planner(IntentPrivacy::Private),
        Err(SavanaError::InvalidState)
    ));
    let requests = transport.take_requests();
    assert_eq!(
        requests.last().unwrap().route,
        BrowserRoute::IngressInputFinalize
    );
    assert!(!requests
        .iter()
        .any(|request| request.route == BrowserRoute::IngressInputAbort));
    error
}

#[test]
fn lost_first_finalize_response_closes_locally_without_abort() {
    assert!(matches!(
        assert_first_finalize_failure_closes_without_abort(Err(SavanaError::Transport)),
        SavanaError::Transport
    ));
}

#[test]
fn malformed_first_finalize_response_closes_locally_without_abort() {
    assert!(matches!(
        assert_first_finalize_failure_closes_without_abort(cbor_response(vec![0xff])),
        SavanaError::InvalidResponse
    ));
}

#[test]
fn wrong_content_type_for_first_finalize_closes_locally_without_abort() {
    assert!(matches!(
        assert_first_finalize_failure_closes_without_abort(html_response(b"wrong type".to_vec())),
        SavanaError::InvalidResponse
    ));
}

#[test]
fn unexpected_first_finalize_response_closes_locally_without_abort() {
    assert!(matches!(
        assert_first_finalize_failure_closes_without_abort(cbor_response(
            encode_ingress_browser_mutation_response_v2(IngressBrowserMutationResponseV2::Begun {
                next_sequence: 0
            },)
            .unwrap(),
        )),
        SavanaError::InvalidResponse
    ));
}
