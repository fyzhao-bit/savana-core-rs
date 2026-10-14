mod support;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use savana_client::*;
use savana_kernel_protocol::v2::*;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use support::task5::*;
use support::ScriptedTransport;

fn identity() -> Identity {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let path = std::env::temp_dir().join(format!(
        "savana-private-sdk-{}-{}.json",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::SeqCst)
    ));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    use std::io::Write as _;
    let mut file = options.open(&path).unwrap();
    file.write_all(b"{\"version\":2,\"credential_digest\":\"d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3c\",\"credential_id\":\"YWFhYWFhYWFhYWFhYWFhYQ\",\"public_credential_state\":\"active\"}").unwrap();
    drop(file);
    let identity = Identity::load(&path).unwrap();
    std::fs::remove_file(&path).unwrap();
    identity
}

#[test]
fn private_v04_ingress_exchange_stays_in_rust_and_never_uses_agent() {
    let transfer = PrivateSessionTransferV04::from_authority_entropy([7; 32]).unwrap();
    let mut responses = vec![cbor_response(
        encode_private_session_begin_v04(transfer).unwrap(),
    )];
    responses.extend(login_responses());
    let transport = Arc::new(ScriptedTransport::new(responses));
    let provider = Arc::new(RecordingWebAuthn::default());
    let client = Client::with_transport(endpoints(), transport.clone());
    let mut session = client
        .private_session_from_ingress_v04(
            &identity(),
            &URL_SAFE_NO_PAD.encode([6; 32]),
            provider.clone(),
        )
        .unwrap();
    let requests = transport.take_requests();
    assert_eq!(requests.len(), 3);
    assert_eq!(requests[0].route, BrowserRoute::IngressPrivateSessionV04);
    assert_eq!(requests[0].service, BrowserService::Ingress);
    assert_eq!(requests[0].origin, BrowserOrigin::Ingress);
    assert!(matches!(
        decode_ingress_browser_request_v2(&requests[0].body).unwrap(),
        IngressBrowserRequestV2::OpenPrivateSessionV04 { .. }
    ));
    assert_eq!(
        decode_private_session_begin_v04(&requests[1].body).unwrap(),
        transfer
    );
    assert_eq!(provider.options.lock().unwrap().len(), 1);
    for request in &requests {
        request.validate().unwrap();
    }
    for origin in [
        BrowserOrigin::Agent,
        BrowserOrigin::Jarvis,
        BrowserOrigin::Approval,
        BrowserOrigin::None,
    ] {
        assert!(BrowserRequest {
            service: BrowserService::Ingress,
            route: BrowserRoute::IngressPrivateSessionV04,
            origin,
            content_type: BrowserContentType::CanonicalCbor,
            body: requests[0].body.clone(),
        }
        .validate()
        .is_err());
    }
    session.close();
    assert!(transport.take_requests().is_empty());
}

#[test]
fn private_v04_ingress_exchange_refuses_invalid_capabilities_before_io() {
    for token in [
        String::new(),
        URL_SAFE_NO_PAD.encode([0; 32]),
        "a".repeat(42),
        format!("{}=", URL_SAFE_NO_PAD.encode([6; 32])),
        "http://localhost/token".into(),
    ] {
        let transport = Arc::new(ScriptedTransport::new(vec![]));
        let client = Client::with_transport(endpoints(), transport.clone());
        assert!(client
            .private_session_from_ingress_v04(
                &identity(),
                &token,
                Arc::new(RecordingWebAuthn::default())
            )
            .is_err());
        assert!(transport.take_requests().is_empty());
    }
}

#[test]
fn private_v04_ingress_bad_response_never_authenticates_or_retries() {
    let valid = encode_private_session_begin_v04(
        PrivateSessionTransferV04::from_authority_entropy([7; 32]).unwrap(),
    )
    .unwrap();
    let mut trailing = valid.clone();
    trailing.push(0);
    for response in [
        Err(SavanaError::transport()),
        cbor_response(trailing),
        cbor_response(encode_private_session_handoff_v04(None).unwrap()),
        cbor_response(encode_private_session_options_v04(b"{}").unwrap()),
    ] {
        let transport = Arc::new(ScriptedTransport::new(vec![response]));
        let client = Client::with_transport(endpoints(), transport.clone());
        let provider = Arc::new(RecordingWebAuthn::default());
        assert!(client
            .private_session_from_ingress_v04(
                &identity(),
                &URL_SAFE_NO_PAD.encode([6; 32]),
                provider.clone()
            )
            .is_err());
        assert_eq!(transport.take_requests().len(), 1);
        assert!(provider.options.lock().unwrap().is_empty());
    }
}

fn login_responses() -> Vec<Result<BrowserResponse, SavanaError>> {
    vec![
        cbor_response(encode_private_session_options_v04(b"private-login-options").unwrap()),
        cbor_response(
            encode_private_session_browser_v04(
                PrivateSessionBrowserCapabilityV04::from_authority_entropy([8; 32]).unwrap(),
            )
            .unwrap(),
        ),
    ]
}

fn handoff(present: bool) -> Result<BrowserResponse, SavanaError> {
    cbor_response(
        encode_private_session_handoff_v04(if present {
            Some(
                ApprovalDisplayAuthenticationTransferCapabilityV2::from_authority_entropy([9; 32])
                    .unwrap(),
            )
        } else {
            None
        })
        .unwrap(),
    )
}

fn connect(
    responses: Vec<Result<BrowserResponse, SavanaError>>,
) -> (
    private_v04::PrivateSession,
    Arc<ScriptedTransport>,
    Arc<RecordingWebAuthn>,
) {
    let mut all = login_responses();
    all.extend(responses);
    let transport = Arc::new(ScriptedTransport::new(all));
    let provider = Arc::new(RecordingWebAuthn::default());
    let client = Client::with_transport(endpoints(), transport.clone());
    let session = client
        .private_session_v04(
            &identity(),
            &URL_SAFE_NO_PAD.encode([7; 32]),
            provider.clone(),
        )
        .unwrap();
    (session, transport, provider)
}

fn publication(commit: u8) -> PrivatePublicationV04 {
    PrivatePublicationV04::new(
        DurableTaskIdV2::new([1; 32]),
        DurableRunIdV2::new([2; 32]),
        Digest32V2::new([3; 32]),
        BootIdV2::new([4; 32]),
        DurableReleaseIdV2::new([5; 32]),
        Digest32V2::new([6; 32]),
        Digest32V2::new([7; 32]),
        Digest32V2::new([8; 32]),
        Digest32V2::new([9; 32]),
        Digest32V2::new([10; 32]),
        Digest32V2::new([commit; 32]),
    )
    .unwrap()
}

#[test]
fn private_v04_publication_is_explicit_immutable_and_owner_only() {
    let p = publication(11);
    let (mut session, transport, provider) = connect(vec![
        cbor_response(encode_private_publication_status_v04(None).unwrap()),
        cbor_response(encode_private_publication_status_v04(Some(p)).unwrap()),
        cbor_response(encode_private_publication_status_v04(Some(p)).unwrap()),
    ]);
    assert!(session.poll_publication().unwrap().is_none());
    let receipt = session.poll_publication().unwrap().unwrap();
    assert_eq!(receipt.metadata(), p);
    assert!(!receipt.matches_payload(b"invented model result"));
    assert_eq!(session.poll_publication().unwrap().unwrap().metadata(), p);
    assert_eq!(
        provider.options.lock().unwrap().len(),
        1,
        "read-only observation is not another vote"
    );
    let requests = transport.take_requests();
    for r in &requests[2..] {
        assert_eq!(r.route, BrowserRoute::PrivateSessionPublicationV04);
        assert_eq!(r.origin, BrowserOrigin::Approval);
    }
}

#[test]
fn private_v04_publication_rebind_regression_and_corruption_close_capability() {
    for next in [
        encode_private_publication_status_v04(None).unwrap(),
        encode_private_publication_status_v04(Some(publication(12))).unwrap(),
        vec![0x82, 3, 0xf6],
        vec![0; 1025],
    ] {
        let (mut session, transport, _) = connect(vec![
            cbor_response(encode_private_publication_status_v04(Some(publication(11))).unwrap()),
            cbor_response(next),
        ]);
        assert!(session.poll_publication().unwrap().is_some());
        assert!(session.poll_publication().is_err());
        assert!(session.poll_publication().is_err());
        assert!(session.poll_approval().is_err());
        assert_eq!(transport.take_requests().len(), 4);
    }
}

#[test]
fn private_v04_authentication_is_not_an_action_or_agent_session() {
    let (mut session, transport, provider) = connect(vec![handoff(false)]);
    assert!(!session.poll_approval().unwrap());
    assert!(session
        .review_pending(&RecordingDecision::new(true))
        .is_err());
    assert_eq!(provider.options.lock().unwrap().len(), 1);
    let requests = transport.take_requests();
    assert_eq!(
        requests.iter().map(|r| r.route).collect::<Vec<_>>(),
        vec![
            BrowserRoute::PrivateSessionBeginV04,
            BrowserRoute::PrivateSessionFinishV04,
            BrowserRoute::PrivateSessionPollV04
        ]
    );
    for r in &requests {
        r.validate().unwrap();
        assert_eq!(r.service, BrowserService::Approval);
        assert_eq!(r.origin, BrowserOrigin::Approval);
    }
    assert!(decode_private_session_finish_v04(&requests[1].body).is_ok());
    session.close();
    session.close();
    assert!(session.poll_approval().is_err());
    assert!(transport.take_requests().is_empty());
    assert!(!format!("{session:?}").contains(&URL_SAFE_NO_PAD.encode([8; 32])));
}

#[test]
fn private_v04_approval_and_denial_require_separate_ceremonies() {
    for (wire_purpose, sdk_purpose) in [
        (
            ApprovalPurposeV2::ToolExecution,
            ApprovalPurpose::ToolExecution,
        ),
        (
            ApprovalPurposeV2::FinalRelease,
            ApprovalPurpose::FinalRelease,
        ),
    ] {
        for decision in [true, false] {
            let mut responses = vec![handoff(true)];
            responses.extend(approval_responses(
                wire_purpose,
                if decision {
                    ApprovalDecisionBrowserFinishResponseV2::Approved
                } else {
                    ApprovalDecisionBrowserFinishResponseV2::Denied
                },
            ));
            let (mut session, transport, provider) = connect(responses);
            let callback = RecordingDecision::new(decision);
            assert!(session.poll_approval().unwrap());
            assert_eq!(session.review_pending(&callback).unwrap(), decision);
            assert!(session.review_pending(&callback).is_err());
            assert_eq!(callback.requests.lock().unwrap().len(), 1);
            assert_eq!(callback.requests.lock().unwrap()[0].1, sdk_purpose);
            assert_eq!(provider.options.lock().unwrap().len(), 3);
            let requests = transport.take_requests();
            assert_eq!(requests[3].route, BrowserRoute::PrivateApprovalAcceptV04);
            assert_eq!(
                requests.last().unwrap().route,
                BrowserRoute::ApprovalDecisionFinish
            );
            for r in &requests {
                r.validate().unwrap();
                assert_eq!(r.service, BrowserService::Approval);
            }
            let decoded =
                decode_approval_decision_browser_begin_request_v2(&requests[7].body).unwrap();
            assert_eq!(
                decoded.decision(),
                if decision {
                    ApprovalDecisionV2::Approve
                } else {
                    ApprovalDecisionV2::Deny
                }
            );
        }
    }
}

#[test]
fn private_v04_wrong_purpose_is_rejected_before_user_choice() {
    for purpose in [
        ApprovalPurposeV2::Ingress,
        ApprovalPurposeV2::ConnectorRegistration,
        ApprovalPurposeV2::TaskAuthorization,
    ] {
        let mut responses = vec![handoff(true)];
        responses.extend(approval_responses(
            purpose,
            ApprovalDecisionBrowserFinishResponseV2::Approved,
        ));
        let (mut session, transport, _) = connect(responses);
        let callback = RecordingDecision::new(true);
        assert!(session.poll_approval().unwrap());
        assert!(session.review_pending(&callback).is_err());
        assert!(callback.requests.lock().unwrap().is_empty());
        assert!(session.poll_approval().is_err());
        assert_eq!(
            transport.take_requests().last().unwrap().route,
            BrowserRoute::ApprovalDisplay
        );
    }
}

#[test]
fn private_v04_malformed_poll_closes_and_uncertain_decision_never_retries() {
    let (mut session, transport, _) =
        connect(vec![handoff(true), cbor_response(vec![0x82, 4, 0xf6, 0])]);
    assert!(session.poll_approval().unwrap());
    assert!(session.poll_approval().is_err());
    assert!(session
        .review_pending(&RecordingDecision::new(true))
        .is_err());
    assert_eq!(transport.take_requests().len(), 4);

    let mut responses = vec![handoff(true)];
    responses.extend(approval_responses(
        ApprovalPurposeV2::ToolExecution,
        ApprovalDecisionBrowserFinishResponseV2::Approved,
    ));
    *responses.last_mut().unwrap() = Err(SavanaError::transport());
    let (mut session, transport, _) = connect(responses);
    assert!(session.poll_approval().unwrap());
    assert!(session
        .review_pending(&RecordingDecision::new(true))
        .is_err());
    assert!(session.poll_approval().is_err());
    assert_eq!(transport.take_requests().len(), 9);
}

#[test]
fn private_v04_routes_reject_wrong_role_and_content_type() {
    for route in [
        BrowserRoute::PrivateSessionBeginV04,
        BrowserRoute::PrivateSessionFinishV04,
        BrowserRoute::PrivateSessionPollV04,
        BrowserRoute::PrivateSessionPublicationV04,
        BrowserRoute::PrivateApprovalAcceptV04,
    ] {
        let content_type = if route == BrowserRoute::PrivateApprovalAcceptV04 {
            BrowserContentType::FormUrlEncoded
        } else {
            BrowserContentType::CanonicalCbor
        };
        for origin in [
            BrowserOrigin::Agent,
            BrowserOrigin::Jarvis,
            BrowserOrigin::Ingress,
            BrowserOrigin::None,
        ] {
            assert!(BrowserRequest {
                service: BrowserService::Approval,
                route,
                origin,
                content_type,
                body: vec![1]
            }
            .validate()
            .is_err());
        }
    }
}

struct WrongCredential;
impl WebAuthnProvider for WrongCredential {
    fn assert_credential(&self, _: &[u8]) -> Result<WebAuthnAssertion, AuthError> {
        WebAuthnAssertion::new(
            vec![0x99; 16],
            vec![1; 32],
            b"{}".to_vec(),
            vec![2; 64],
            vec![3; 32],
        )
    }
    fn create_credential(&self, _: &[u8]) -> Result<WebAuthnAttestation, AuthError> {
        Err(AuthError::EnrollmentFailed)
    }
}

#[test]
fn private_v04_wrong_credential_and_invalid_login_do_not_finish() {
    let transport = Arc::new(ScriptedTransport::new(login_responses()));
    let client = Client::with_transport(endpoints(), transport.clone());
    assert!(client
        .private_session_v04(
            &identity(),
            &URL_SAFE_NO_PAD.encode([7; 32]),
            Arc::new(WrongCredential)
        )
        .is_err());
    assert_eq!(transport.take_requests().len(), 1);
    for token in [
        "",
        "http://localhost:8765/v2/bootstrap/ingress/secret",
        "not-a-transfer",
    ] {
        assert!(client
            .private_session_v04(&identity(), token, Arc::new(WrongCredential))
            .is_err());
        assert!(transport.take_requests().is_empty());
    }
    let transport = Arc::new(ScriptedTransport::new(vec![html_response(
        b"wrong response".to_vec(),
    )]));
    let provider = Arc::new(RecordingWebAuthn::default());
    let client = Client::with_transport(endpoints(), transport.clone());
    assert!(client
        .private_session_v04(
            &identity(),
            &URL_SAFE_NO_PAD.encode([7; 32]),
            provider.clone()
        )
        .is_err());
    assert!(provider.options.lock().unwrap().is_empty());
    assert_eq!(transport.take_requests().len(), 1);
}
