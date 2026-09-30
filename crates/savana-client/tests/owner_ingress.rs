mod support;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use savana_client::owner_ingress::{OwnerIngress, MAX_OWNER_TEXT_BYTES};
use savana_client::*;
use savana_kernel_protocol::v2::*;
use sha2::{Digest as _, Sha256};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use support::{task5::*, ScriptedTransport};
use zeroize::Zeroizing;

fn login() -> Vec<Result<BrowserResponse, SavanaError>> {
    vec![
        html_response(render_ingress_ui_authentication_form_v2(
            IngressUiAuthenticationTransferCapabilityV2::from_authority_entropy([1; 32]).unwrap())),
        html_response(authentication_html("ingress",
            IngressUiPreAuthenticationTabCapabilityV2::from_authority_entropy([2; 32]).unwrap())),
        cbor_response(encode_ui_authentication_browser_begin_response_v2(
            &UiAuthenticationBrowserBeginResponseV2::Ingress {
                ceremony: IngressUiAuthenticationBrowserCeremonyCapabilityV2::from_authority_entropy([3; 32]).unwrap(),
                public_key_options_json: Zeroizing::new(b"{}".to_vec()),
            }).unwrap()),
        cbor_response(encode_ui_authentication_browser_finish_response_v2(
            UiAuthenticationBrowserFinishResponseV2::TransferToIngress {
                return_origin: FixedOriginV2::Ingress8767,
                transfer: IngressUiAuthenticationSettlementTransferCapabilityV2::from_authority_entropy([4; 32]).unwrap(),
            }).unwrap()),
        html_response(render_ingress_workspace_v2(IngressTabSessionCapabilityV2::from_authority_entropy([5; 32]).unwrap())),
    ]
}

fn mutation(value: IngressBrowserMutationResponseV2) -> Result<BrowserResponse, SavanaError> {
    cbor_response(encode_ingress_browser_mutation_response_v2(value).unwrap())
}

fn session_commitment(text: &str) -> Digest32V2 {
    // Match Ingressd's actual chain, not the unframed SHA-256 of the text.
    // This synthetic session belongs to the server fixture; it is never
    // disclosed by the browser Begin response or known to the SDK client.
    let session = InputSessionHandleV2::from_authority_entropy([0x71; 32]).unwrap();
    let channel = InputChannelV2::ChatText;
    input_channel_step_digest_v2(
        input_channel_begin_digest_v2(session, channel),
        0,
        input_chunk_digest_v2(session, channel, 0, text.as_bytes()).unwrap(),
    )
    .unwrap()
}

fn input(text: &str, allowed: bool) -> Vec<Result<BrowserResponse, SavanaError>> {
    let mut result = vec![
        mutation(IngressBrowserMutationResponseV2::Begun { next_sequence: 0 }),
        mutation(IngressBrowserMutationResponseV2::ChunkAccepted {
            acknowledged_sequence: 0,
            cumulative_digest: session_commitment(text),
        }),
        mutation(IngressBrowserMutationResponseV2::FinalizeOpenApproval {
            transfer: ApprovalDisplayAuthenticationTransferCapabilityV2::from_authority_entropy(
                [6; 32],
            )
            .unwrap(),
        }),
    ];
    result.extend(approval_responses(
        ApprovalPurposeV2::Ingress,
        if allowed {
            ApprovalDecisionBrowserFinishResponseV2::Approved
        } else {
            ApprovalDecisionBrowserFinishResponseV2::Denied
        },
    ));
    result.push(mutation(if allowed {
        IngressBrowserMutationResponseV2::FinalizeCommitted {
            state: InputPublicStateV2::CommittedUnclaimed,
        }
    } else {
        IngressBrowserMutationResponseV2::FinalizeRejected {
            state: InputPublicStateV2::Denied,
        }
    }));
    result
}

fn connected(
    extra: Vec<Result<BrowserResponse, SavanaError>>,
) -> (OwnerIngress, Arc<ScriptedTransport>) {
    let mut responses = login();
    responses.extend(extra);
    let transport = Arc::new(ScriptedTransport::new(responses));
    let client = Client::with_transport_and_nonce_source(
        endpoints(),
        transport.clone(),
        Arc::new(FixedNonces::new()),
    );
    let owner = client
        .owner_ingress(
            &URL_SAFE_NO_PAD.encode([9; 32]),
            Arc::new(RecordingWebAuthn::default()),
        )
        .unwrap();
    (owner, transport)
}

#[test]
fn owner_login_uses_ingress_only_without_sdk_identity_file() {
    let (mut owner, transport) = connected(vec![]);
    assert_eq!(format!("{owner:?}"), "OwnerIngress(<private-owner>)");
    let requests = transport.take_requests();
    assert_eq!(
        requests.iter().map(|r| r.route).collect::<Vec<_>>(),
        vec![
            BrowserRoute::IngressBootstrapAccept,
            BrowserRoute::ApprovalUiAuthenticationAccept,
            BrowserRoute::ApprovalUiAuthenticationBegin,
            BrowserRoute::ApprovalUiAuthenticationFinish,
            BrowserRoute::IngressUiAuthenticationComplete,
        ]
    );
    assert_eq!(requests[0].origin, BrowserOrigin::Jarvis);
    for r in requests {
        r.validate().unwrap();
        assert_ne!(r.service, BrowserService::Agent);
    }
    assert!(owner.into_private_session().is_err());
    owner.close();
    assert!(owner.task_authorization_context().is_err());
    assert!(transport.take_requests().is_empty());
}

#[test]
fn invalid_bootstraps_and_wrong_login_purpose_fail_closed() {
    for token in [
        String::new(),
        URL_SAFE_NO_PAD.encode([0; 32]),
        "a".repeat(44),
        "http://localhost/secret".into(),
    ] {
        let t = Arc::new(ScriptedTransport::default());
        assert!(Client::with_transport(endpoints(), t.clone())
            .owner_ingress(&token, Arc::new(RecordingWebAuthn::default()))
            .is_err());
        assert!(t.take_requests().is_empty());
    }
    let mut responses = login();
    responses[1] = html_response(authentication_html(
        "agent",
        AgentUiPreAuthenticationTabCapabilityV2::from_authority_entropy([2; 32]).unwrap(),
    ));
    let t = Arc::new(ScriptedTransport::new(responses));
    let provider = Arc::new(RecordingWebAuthn::default());
    assert!(Client::with_transport(endpoints(), t.clone())
        .owner_ingress(&URL_SAFE_NO_PAD.encode([9; 32]), provider.clone())
        .is_err());
    assert_eq!(t.take_requests().len(), 2);
    assert!(provider.options.lock().unwrap().is_empty());
}

#[test]
fn login_transport_failure_at_every_stage_stops_without_retry() {
    for failed in 0..5 {
        let mut responses = login();
        responses[failed] = Err(SavanaError::transport());
        let t = Arc::new(ScriptedTransport::new(responses));
        assert!(Client::with_transport(endpoints(), t.clone())
            .owner_ingress(
                &URL_SAFE_NO_PAD.encode([9; 32]),
                Arc::new(RecordingWebAuthn::default())
            )
            .is_err());
        assert_eq!(t.take_requests().len(), failed + 1);
    }
}

#[test]
fn commit_is_bounded_signed_once_and_not_task_authority() {
    let text = "Synthetic 测试 only";
    let content_digest = Digest32V2::new(Sha256::digest(text.as_bytes()).into());
    assert_ne!(session_commitment(text), content_digest);
    let (mut owner, t) = connected(input(text, true));
    t.take_requests();
    let decision = RecordingDecision::new(true);
    for invalid in [String::new(), "x".repeat(MAX_OWNER_TEXT_BYTES + 1)] {
        assert!(owner.commit_text(&invalid, &decision).is_err());
        assert!(t.take_requests().is_empty());
    }
    owner.commit_text(text, &decision).unwrap();
    assert_eq!(
        decision.requests.lock().unwrap()[0].1,
        ApprovalPurpose::Ingress
    );
    let requests = t.take_requests();
    assert_eq!(requests.len(), 10);
    for r in &requests {
        assert_ne!(r.service, BrowserService::Agent);
        r.validate().unwrap();
    }
    match decode_ingress_browser_request_v2(&requests[1].body).unwrap() {
        IngressBrowserRequestV2::Append { chunk, .. } => {
            assert_eq!(chunk.as_bytes(), text.as_bytes())
        }
        _ => panic!("not an input chunk"),
    }
    assert!(matches!(
        decode_ingress_browser_request_v2(&requests[0].body).unwrap(),
        IngressBrowserRequestV2::Begin {
            declared_total_bytes,
            declared_content_digest: Some(digest),
            ..
        } if declared_total_bytes == text.len() as u64 && digest == content_digest
    ));
    // Both preparation and settlement retain the plain content digest;
    // neither substitutes the opaque, session-bound transport commitment.
    for index in [2, 9] {
        assert!(matches!(
            decode_ingress_browser_request_v2(&requests[index].body).unwrap(),
            IngressBrowserRequestV2::Finalize { declared_content_digest, .. }
                if declared_content_digest == content_digest
        ));
    }
    assert!(owner.into_private_session().is_err());
    assert!(owner.commit_text(text, &decision).is_err());
    assert!(t.take_requests().is_empty());
}

#[test]
fn every_uncertain_commit_stage_closes_without_replay() {
    for failed in 0..10 {
        let mut responses = input("synthetic", true);
        responses[failed] = Err(SavanaError::transport());
        let (mut owner, t) = connected(responses);
        t.take_requests();
        let decision = RecordingDecision::new(true);
        assert!(owner.commit_text("synthetic", &decision).is_err());
        assert_eq!(t.take_requests().len(), failed + 1);
        assert!(owner.commit_text("synthetic", &decision).is_err());
        assert!(owner.into_private_session().is_err());
        assert!(t.take_requests().is_empty());
    }
}

#[test]
fn denial_and_wrong_chunk_sequence_do_not_commit() {
    let (mut owner, t) = connected(input("synthetic", false));
    t.take_requests();
    assert!(matches!(
        owner.commit_text("synthetic", &RecordingDecision::new(false)),
        Err(SavanaError::ApprovalDenied(_))
    ));
    assert_eq!(t.take_requests().len(), 10);
    let mut responses = input("synthetic", true);
    responses[1] = mutation(IngressBrowserMutationResponseV2::ChunkAccepted {
        acknowledged_sequence: 1,
        cumulative_digest: session_commitment("synthetic"),
    });
    let (mut owner, t) = connected(responses);
    t.take_requests();
    let decision = RecordingDecision::new(true);
    assert!(owner
        .commit_text("synthetic", &decision)
        .is_err());
    assert_eq!(t.take_requests().len(), 2);
    assert!(decision.requests.lock().unwrap().is_empty());
}

#[test]
fn finalize_without_separate_approval_never_commits() {
    for response in [
        IngressBrowserMutationResponseV2::FinalizeRejected {
            state: InputPublicStateV2::Denied,
        },
        IngressBrowserMutationResponseV2::FinalizeCommitted {
            state: InputPublicStateV2::CommittedUnclaimed,
        },
    ] {
        let mut responses = input("synthetic", true);
        responses[2] = mutation(response);
        let (mut owner, t) = connected(responses);
        t.take_requests();
        let decision = RecordingDecision::new(true);
        assert!(owner.commit_text("synthetic", &decision).is_err());
        assert_eq!(t.take_requests().len(), 3);
        assert!(decision.requests.lock().unwrap().is_empty());
        assert!(owner.into_private_session().is_err());
        assert!(owner.commit_text("synthetic", &decision).is_err());
        assert!(t.take_requests().is_empty());
    }
}

struct SwitchingCredential(AtomicUsize);
impl WebAuthnProvider for SwitchingCredential {
    fn assert_credential(&self, _: &[u8]) -> Result<WebAuthnAssertion, AuthError> {
        let id = if self.0.fetch_add(1, Ordering::SeqCst) == 0 {
            0x61
        } else {
            0x62
        };
        WebAuthnAssertion::new(
            vec![id; 16],
            vec![2; 32],
            b"{}".to_vec(),
            vec![3; 64],
            vec![4; 32],
        )
    }
    fn create_credential(&self, _: &[u8]) -> Result<WebAuthnAttestation, AuthError> {
        panic!("must not enroll")
    }
}

#[test]
fn switched_credential_never_reaches_approval_finish_or_decision() {
    let mut responses = login();
    responses.extend(input("synthetic", true));
    let t = Arc::new(ScriptedTransport::new(responses));
    let mut owner = Client::with_transport(endpoints(), t.clone())
        .owner_ingress(
            &URL_SAFE_NO_PAD.encode([9; 32]),
            Arc::new(SwitchingCredential(AtomicUsize::new(0))),
        )
        .unwrap();
    t.take_requests();
    let decision = RecordingDecision::new(true);
    assert!(owner.commit_text("synthetic", &decision).is_err());
    let requests = t.take_requests();
    assert_eq!(requests.len(), 5);
    assert_eq!(
        requests.last().unwrap().route,
        BrowserRoute::ApprovalUiAuthenticationBegin
    );
    assert!(decision.requests.lock().unwrap().is_empty());
}

#[test]
fn wrong_approval_purpose_is_rejected_before_user_decision() {
    let mut responses = input("synthetic", true);
    let wrong = approval_responses(
        ApprovalPurposeV2::TaskAuthorization,
        ApprovalDecisionBrowserFinishResponseV2::Approved,
    );
    responses.splice(3..9, wrong);
    let (mut owner, t) = connected(responses);
    t.take_requests();
    let decision = RecordingDecision::new(true);
    assert!(owner.commit_text("synthetic", &decision).is_err());
    assert!(decision.requests.lock().unwrap().is_empty());
    assert_eq!(t.take_requests().len(), 7);
    assert!(owner.task_authorization_context().is_err());
    assert!(t.take_requests().is_empty());
}

#[test]
fn unrelated_root_receipt_does_not_open_approval_or_private_session() {
    let draft = TaskAuthorizationDraft::from_canonical_bytes(
        &encode_task_authorization_draft_v2(&task_authorization_draft()).unwrap(),
    )
    .unwrap();
    let mut responses = input("synthetic", true);
    responses.push(mutation(
        IngressBrowserMutationResponseV2::TaskAuthorizationOpenApproval {
            request_digest: Digest32V2::new([99; 32]),
            transfer: ApprovalDisplayAuthenticationTransferCapabilityV2::from_authority_entropy(
                [11; 32],
            )
            .unwrap(),
        },
    ));
    let (mut owner, t) = connected(responses);
    let decision = RecordingDecision::new(true);
    assert!(owner.approve_task_authorization(&draft, &decision).is_err());
    assert_eq!(t.take_requests().len(), 5); // only the initial login
    owner.commit_text("synthetic", &decision).unwrap();
    t.take_requests();
    assert!(owner.approve_task_authorization(&draft, &decision).is_err());
    assert_eq!(t.take_requests().len(), 1);
    assert_eq!(decision.requests.lock().unwrap().len(), 1); // input only
    assert!(owner.into_private_session().is_err());
    assert!(t.take_requests().is_empty());
}

#[test]
fn authorized_input_hands_off_directly_to_private_session_once() {
    let material = task_authorization_draft();
    // Nonces 1..7 are consumed by login and signed input commit.
    let mut h = Sha256::new();
    h.update(b"SAVANA_TASK_ISSUANCE_REQUEST_V2_SCHEMA1\0");
    for bytes in [
        material.installation_digest().as_bytes(),
        material.task().as_bytes(),
        material.principal().as_bytes(),
        &[8; 32],
    ] {
        h.update((bytes.len() as u64).to_be_bytes());
        h.update(bytes);
    }
    let expected = Digest32V2::new(h.finalize().into());
    let draft = TaskAuthorizationDraft::from_canonical_bytes(
        &encode_task_authorization_draft_v2(&material).unwrap(),
    )
    .unwrap();
    let mut responses = input("synthetic", true);
    responses.push(mutation(
        IngressBrowserMutationResponseV2::TaskAuthorizationOpenApproval {
            request_digest: expected,
            transfer: ApprovalDisplayAuthenticationTransferCapabilityV2::from_authority_entropy(
                [11; 32],
            )
            .unwrap(),
        },
    ));
    responses.extend(approval_responses(
        ApprovalPurposeV2::TaskAuthorization,
        ApprovalDecisionBrowserFinishResponseV2::Approved,
    ));
    responses.push(mutation(
        IngressBrowserMutationResponseV2::TaskAuthorizationEstablished {
            request_digest: expected,
            authorization_digest: Digest32V2::new([12; 32]),
        },
    ));
    responses.extend([
        cbor_response(
            encode_private_session_begin_v04(
                PrivateSessionTransferV04::from_authority_entropy([13; 32]).unwrap(),
            )
            .unwrap(),
        ),
        cbor_response(encode_private_session_options_v04(b"{}").unwrap()),
        cbor_response(
            encode_private_session_browser_v04(
                PrivateSessionBrowserCapabilityV04::from_authority_entropy([14; 32]).unwrap(),
            )
            .unwrap(),
        ),
    ]);
    let (mut owner, t) = connected(responses);
    let decision = RecordingDecision::new(true);
    owner.commit_text("synthetic", &decision).unwrap();
    let receipt = owner.approve_task_authorization(&draft, &decision).unwrap();
    assert_eq!(receipt.authorization_digest(), &[12; 32]);
    let mut private = owner.into_private_session().unwrap();
    assert_eq!(decision.requests.lock().unwrap().len(), 2);
    for r in t.take_requests() {
        assert_ne!(r.service, BrowserService::Agent);
    }
    assert!(owner.into_private_session().is_err());
    private.close();
    assert!(t.take_requests().is_empty());
}
