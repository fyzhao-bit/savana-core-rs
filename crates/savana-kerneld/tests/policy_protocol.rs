#![cfg(feature = "test-support")]

mod support;

use savana_kernel_protocol::{BeginRunResponse, KernelValue, ResponsePayloadV1, StableCode};
use support::{AuthenticatedConnection, Installation, RunningDaemon, WireClient};

#[test]
fn begin_and_ingest_dispatch_through_authenticated_context() {
    let installation = Installation::build();
    let mut daemon = RunningDaemon::start(&installation);
    let begin = expect_begin(&installation, WireClient::A, 0x91, 0xa1);
    let ingest = AuthenticatedConnection::connect(&installation, WireClient::A, 0x92);
    let request = ingest.ingest_request(
        begin.run,
        KernelValue::Text("ingest".try_into().expect("input")),
        0xa2,
    );
    match ingest.submit(request).expect("IngestUserInput") {
        ResponsePayloadV1::IngestUserInput(value) => {
            assert_ne!(value, begin.initial_value);
        }
        other => panic!("expected IngestUserInput success, got {other:?}"),
    }
    daemon.stop();
}

#[test]
fn policy_handles_follow_authenticated_client_not_original_connection() {
    let installation = Installation::build();
    let mut daemon = RunningDaemon::start(&installation);
    let begin = expect_begin(&installation, WireClient::A, 0x92, 0xa2);

    let same_client = AuthenticatedConnection::connect(&installation, WireClient::A, 0x93);
    let accepted = same_client.ingest_request(
        begin.run,
        KernelValue::Text("ingest".try_into().expect("input")),
        0xa3,
    );
    assert!(matches!(
        same_client.submit(accepted),
        Ok(ResponsePayloadV1::IngestUserInput(_))
    ));

    let other_client = AuthenticatedConnection::connect(&installation, WireClient::B, 0x94);
    let rejected = other_client.ingest_request(
        begin.run,
        KernelValue::Text("ingest".try_into().expect("input")),
        0xa4,
    );
    assert_eq!(
        other_client.submit(rejected).unwrap_err(),
        StableCode::HandleWrongClient
    );

    let audit = daemon.stop_and_collect_audit();
    let failed_ingest = audit
        .lines()
        .find(|line| {
            line.contains(r#""operation_tag":"ingest_user_input""#)
                && line.contains(r#""code":"HANDLE_WRONG_CLIENT""#)
        })
        .expect("failed IngestUserInput completion audit");
    assert!(
        failed_ingest.contains(r#""connection_audit_id":""#),
        "{failed_ingest}"
    );
    assert!(
        failed_ingest.contains(r#""run_audit_id":""#),
        "{failed_ingest}"
    );
}

#[test]
fn every_policy_connection_still_has_exactly_one_request_and_response() {
    let installation = Installation::build();
    let mut daemon = RunningDaemon::start(&installation);
    let begin = expect_begin(&installation, WireClient::A, 0x95, 0xa4);
    let ingest = AuthenticatedConnection::connect(&installation, WireClient::A, 0x96);
    let request = ingest.ingest_request(
        begin.run,
        KernelValue::Text("ingest".try_into().expect("input")),
        0xa5,
    );
    assert!(matches!(
        ingest.submit(request),
        Ok(ResponsePayloadV1::IngestUserInput(_))
    ));
    daemon.stop();
}

#[test]
fn request_audit_never_emits_raw_sensitive_ingress_identity() {
    let installation = Installation::build();
    let mut daemon = RunningDaemon::start(&installation);
    let begin = expect_begin(&installation, WireClient::A, 0xa7, 0xa8);
    let ingest = AuthenticatedConnection::connect(&installation, WireClient::A, 0xa9);
    let request = ingest.ingest_request(
        begin.run,
        KernelValue::Text("ingest".try_into().expect("input")),
        0xaa,
    );
    assert!(matches!(
        ingest.submit(request),
        Ok(ResponsePayloadV1::IngestUserInput(_))
    ));

    let audit = daemon.stop_and_collect_audit();
    for forbidden in [
        "principal-1",
        "conversation-1",
        "operator",
        &"44".repeat(32),
        &"55".repeat(32),
    ] {
        assert!(!audit.contains(forbidden), "{forbidden}: {audit}");
    }
    assert!(audit.contains(r#""connection_audit_id":""#), "{audit}");
    assert!(audit.contains(r#""run_audit_id":""#), "{audit}");
}

fn expect_begin(
    installation: &Installation,
    client: WireClient,
    connection_nonce: u64,
    ingress_nonce: u64,
) -> BeginRunResponse {
    let connection = AuthenticatedConnection::connect(installation, client, connection_nonce);
    let request = connection.begin_request(
        installation.signed_registry(),
        KernelValue::Text("begin".try_into().expect("input")),
        ingress_nonce,
    );
    match connection.submit(request).expect("BeginRun") {
        ResponsePayloadV1::BeginRun(response) => {
            assert_eq!(response.active_tools.len(), 1);
            assert_eq!(
                response.active_tools[0].identity.name.as_str(),
                "operator-tool"
            );
            response
        }
        other => panic!("expected BeginRun success, got {other:?}"),
    }
}
