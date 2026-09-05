#![cfg(feature = "test-support")]

mod support;

use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use savana_kernel_protocol::{
    decode_client_message, Digest32, KernelValue, Nonce32, OperationV1, RequestEnvelopeV1,
    ResponsePayloadV1, Signature64, SignedRegistrySnapshotV1, StableCode, UnixMillis,
};
use support::{
    resign_ingress, resign_registry, AuthenticatedConnection, ControlOpcode, ControlStatus,
    Installation, RunningDaemon, WireClient,
};

#[test]
fn pre_restart_ingress_fails_under_new_boot_with_same_policy_and_key() {
    let installation = Installation::build();
    let mut first = RunningDaemon::start(&installation);
    let first_connection = AuthenticatedConnection::connect(&installation, WireClient::A, 0x1001);
    let signed =
        first_connection.begin_request(installation.signed_registry(), KernelValue::Null, 0x2001);
    drop(first_connection);
    first.stop();

    let mut second = RunningDaemon::start(&installation);
    let second_connection = AuthenticatedConnection::connect(&installation, WireClient::A, 0x1002);
    assert_eq!(
        second_connection.submit(signed).unwrap_err(),
        StableCode::AttestationBindingMismatch
    );
    second.stop();
}

#[test]
fn one_signed_ingress_sent_on_two_connections_has_one_binding_winner() {
    let installation = Arc::new(Installation::build());
    let mut daemon = RunningDaemon::start(&installation);
    let client_a = AuthenticatedConnection::connect(&installation, WireClient::A, 0x1101);
    let client_b = AuthenticatedConnection::connect(&installation, WireClient::B, 0x1102);
    let signed = client_a.begin_request(installation.signed_registry(), KernelValue::Null, 0x2101);
    let barrier = Arc::new(Barrier::new(3));
    let joins = [(client_a, signed.clone()), (client_b, signed)].map(|(client, request)| {
        let barrier = Arc::clone(&barrier);
        thread::spawn(move || {
            barrier.wait();
            client.submit(request)
        })
    });
    barrier.wait();
    let outcomes = joins.map(|join| join.join().expect("request thread"));
    assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| {
                outcome
                    .as_ref()
                    .is_err_and(|code| *code == StableCode::AttestationBindingMismatch)
            })
            .count(),
        1
    );
    daemon.stop();
}

#[test]
fn exact_replay_boundary_never_evicts_live_security_state() {
    let installation = Installation::build();
    let mut daemon = installation.spawn_lifecycle_daemon();
    daemon.continue_startup();
    let registry = installation.signed_registry();

    let begin_connection = AuthenticatedConnection::connect(&installation, WireClient::A, 0x1200);
    let begin_request = begin_connection.begin_request(registry, KernelValue::Null, 0x2200);
    let initial_expiry = match &begin_request.operation {
        OperationV1::BeginRun(request) => request.ingress.unsigned.expires_at.get(),
        _ => unreachable!(),
    };
    let begin = begin_connection
        .submit(begin_request)
        .expect("initial BeginRun");
    let run = match begin {
        ResponsePayloadV1::BeginRun(begin) => begin.run,
        other => panic!("expected BeginRun response, got {other:?}"),
    };

    let before_bad_signature = daemon.security_state_snapshot();
    let bad_signature_connection =
        AuthenticatedConnection::connect(&installation, WireClient::A, 0x1201);
    let mut bad_signature = bad_signature_connection.ingest_request(run, KernelValue::Null, 0x2201);
    ingress_mut(&mut bad_signature).signature = Signature64::new([0; 64]);
    assert_eq!(
        bad_signature_connection.submit(bad_signature).unwrap_err(),
        StableCode::AttestationInvalidSignature
    );
    assert_eq!(daemon.security_state_snapshot(), before_bad_signature);

    let corrected_connection =
        AuthenticatedConnection::connect(&installation, WireClient::A, 0x8201);
    let corrected = corrected_connection.ingest_request(run, KernelValue::Null, 0x2201);
    assert!(corrected_connection.submit(corrected).is_ok());

    let mut connections_since_expiry = 3_u64;
    for sequence in 2..4_096_u64 {
        if connections_since_expiry == 120 {
            thread::sleep(Duration::from_millis(5_100));
            connections_since_expiry = 0;
        }
        let connection =
            AuthenticatedConnection::connect(&installation, WireClient::A, 0x1200 + sequence);
        connections_since_expiry += 1;
        let request = connection.ingest_request(run, KernelValue::Null, 0x2200 + sequence);
        let window = match &request.operation {
            OperationV1::IngestUserInput(request) => (
                request.envelope.unsigned.issued_at.get(),
                request.envelope.unsigned.expires_at.get(),
            ),
            _ => unreachable!(),
        };
        let response = connection.submit(request);
        assert!(
            matches!(response, Ok(ResponsePayloadV1::IngestUserInput(_))),
            "sequence {sequence}: {response:?}; run expiry {initial_expiry}; ingress {window:?}; client wall {:?}", SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis()
        );
    }
    let before = daemon.security_state_snapshot();
    let overflow = AuthenticatedConnection::connect(&installation, WireClient::A, 0x3200);
    let overflow_request = overflow.ingest_request(run, KernelValue::Null, 0x4200);
    assert_eq!(
        overflow.submit(overflow_request).unwrap_err(),
        StableCode::KernelOverloaded
    );
    assert_eq!(daemon.security_state_snapshot(), before);
    assert_eq!(before.replay_entries, 4_096);

    let replay = AuthenticatedConnection::connect(&installation, WireClient::A, 0x4300);
    let replay_request = replay.ingest_request(run, KernelValue::Null, 0x2201);
    assert_eq!(
        replay.submit(replay_request).unwrap_err(),
        StableCode::AttestationBindingMismatch
    );
    assert_eq!(daemon.security_state_snapshot(), before);
    daemon.shutdown();
}

#[test]
fn exact_handle_boundary_rolls_to_stale_without_eviction() {
    let installation = Installation::build_with_matching_tools(256);
    let mut daemon = installation.spawn_lifecycle_daemon();
    daemon.continue_startup();
    let registry = installation.signed_registry();
    let mut oldest_run = None;
    let mut client_runs = [None, None, None];

    for sequence in 0..254_u64 {
        let (client, client_index) = match sequence % 3 {
            0 => (WireClient::A, 0),
            1 => (WireClient::B, 1),
            _ => (WireClient::C, 2),
        };
        let connection = AuthenticatedConnection::connect(&installation, client, 0x5000 + sequence);
        let request =
            connection.begin_request(registry.clone(), KernelValue::Null, 0x6000 + sequence);
        let response = connection.submit(request).expect("capacity BeginRun");
        let begin = match response {
            ResponsePayloadV1::BeginRun(begin) => begin,
            other => panic!("expected BeginRun response, got {other:?}"),
        };
        oldest_run.get_or_insert(begin.run);
        client_runs[client_index].get_or_insert(begin.run);
    }
    let oldest_run = oldest_run.expect("at least one run");
    for sequence in 0..4_u64 {
        let (client, client_index) = match sequence % 3 {
            0 => (WireClient::A, 0),
            1 => (WireClient::B, 1),
            _ => (WireClient::C, 2),
        };
        let connection = AuthenticatedConnection::connect(&installation, client, 0x7000 + sequence);
        let request = connection.ingest_request(
            client_runs[client_index].expect("client run"),
            KernelValue::Null,
            0x7100 + sequence,
        );
        assert!(connection.submit(request).is_ok());
    }
    let exact = daemon.security_state_snapshot();
    assert_eq!(exact.live_handles(), 65_536);

    let overflow = AuthenticatedConnection::connect(&installation, WireClient::A, 0x7200);
    let overflow_request = overflow.ingest_request(oldest_run, KernelValue::Null, 0x7201);
    assert_eq!(
        overflow.submit(overflow_request).unwrap_err(),
        StableCode::KernelOverloaded
    );
    assert_eq!(daemon.security_state_snapshot(), exact);

    installation
        .install_next_candidate_strictly()
        .expect("strict policy update");
    daemon.command_expect(ControlOpcode::Refresh, ControlStatus::Published);
    let rolled = daemon.security_state_snapshot();
    assert_eq!(rolled.stale_handles, 65_536);
    assert_eq!(rolled.live_handles(), 0);
    assert_eq!(rolled.registry_digest, Digest32::new([0; 32]));
    let ledger = installation.ledger_bytes().expect("accepted ledger");

    let stale = AuthenticatedConnection::connect(&installation, WireClient::A, 0x7300);
    let stale_request = stale.ingest_request(oldest_run, KernelValue::Null, 0x7301);
    assert_eq!(
        stale.submit(stale_request).unwrap_err(),
        StableCode::HandleStalePolicy
    );
    let new_begin = AuthenticatedConnection::connect(&installation, WireClient::A, 0x7400);
    let new_begin_request = new_begin.begin_request(
        installation.signed_empty_registry(),
        KernelValue::Null,
        0x7401,
    );
    assert_eq!(
        new_begin.submit(new_begin_request).unwrap_err(),
        StableCode::KernelOverloaded
    );
    assert_eq!(
        installation.ledger_bytes().as_deref(),
        Some(ledger.as_slice())
    );
    assert_eq!(daemon.security_state_snapshot(), rolled);
    daemon.shutdown();
}

#[test]
fn malformed_cbor_precedes_expired_policy_over_real_transport() {
    let installation = Installation::build_with_lifetime_ms(20_000);
    let mut daemon = installation.spawn_lifecycle_daemon();
    daemon.continue_startup();
    installation.wait_until_policy_remaining(3_000);
    let connection = AuthenticatedConnection::connect(&installation, WireClient::A, 0x8001);
    installation.wait_until_policy_expired();
    let before = daemon.security_state_snapshot();
    let malformed = [0xff];
    assert_eq!(
        decode_client_message(&malformed, &installation.effective_limits())
            .unwrap_err()
            .code(),
        StableCode::ProtocolMalformedCbor
    );
    connection.send_payload_expect_silent_close(&malformed);
    assert_eq!(daemon.security_state_snapshot(), before);
    let audit = daemon.shutdown_and_collect_audit();
    assert!(!audit.contains(r#""event":"RequestCompleted""#), "{audit}");
}

#[test]
fn expired_policy_precedes_bad_ingress_signature_over_real_transport() {
    let installation = Installation::build_with_lifetime_ms(20_000);
    let mut daemon = installation.spawn_lifecycle_daemon();
    daemon.continue_startup();
    installation.wait_until_policy_remaining(3_000);
    let connection = AuthenticatedConnection::connect(&installation, WireClient::A, 0x8101);
    let mut request =
        connection.begin_request(installation.signed_registry(), KernelValue::Null, 0x8102);
    ingress_mut(&mut request).signature = Signature64::new([0; 64]);
    installation.wait_until_policy_expired();
    let before = daemon.security_state_snapshot();
    assert_eq!(
        connection.submit(request).unwrap_err(),
        StableCode::PolicyExpired
    );
    assert_eq!(daemon.security_state_snapshot(), before);
    let audit = daemon.shutdown_and_collect_audit();
    assert!(
        audit.contains(
            r#""event":"RequestCompleted","operation_tag":"begin_run","code":"POLICY_EXPIRED""#
        ),
        "{audit}"
    );
}

#[test]
fn pairwise_ingress_and_registry_precedence_is_stable_over_real_transport() {
    assert_stateless_begin_failure(
        0x9000,
        |request| {
            let ingress = ingress_mut(request);
            ingress.unsigned.expires_at = UnixMillis::new(system_now_ms().saturating_sub(1));
            ingress.signature = Signature64::new([0; 64]);
        },
        StableCode::AttestationInvalidSignature,
    );
    assert_stateless_begin_failure(
        0x9100,
        |request| {
            let ingress = ingress_mut(request);
            let expired = system_now_ms().saturating_sub(1);
            ingress.unsigned.issued_at = UnixMillis::new(expired.saturating_sub(1_000));
            ingress.unsigned.expires_at = UnixMillis::new(expired);
            ingress.unsigned.connection_binding_digest = Digest32::new([0x91; 32]);
            resign_ingress(ingress);
        },
        StableCode::AttestationExpired,
    );
    assert_stateless_begin_failure(
        0x9200,
        |request| {
            let ingress = ingress_mut(request);
            let expired = system_now_ms().saturating_sub(1);
            ingress.unsigned.issued_at = UnixMillis::new(expired.saturating_sub(1_000));
            ingress.unsigned.expires_at = UnixMillis::new(expired);
            ingress.unsigned.nonce = Nonce32::new([0; 32]);
            resign_ingress(ingress);
        },
        StableCode::AttestationExpired,
    );
    assert_stateless_begin_failure(
        0x9300,
        |request| {
            let ingress = ingress_mut(request);
            ingress.unsigned.connection_binding_digest = Digest32::new([0x93; 32]);
            resign_ingress(ingress);
            registry_mut(request).signature = Signature64::new([0; 64]);
        },
        StableCode::AttestationBindingMismatch,
    );
    assert_stateless_begin_failure(
        0x9400,
        |request| {
            let registry = registry_mut(request);
            registry.unsigned.expires_at = UnixMillis::new(system_now_ms().saturating_sub(1));
            registry.signature = Signature64::new([0; 64]);
        },
        StableCode::RegistryInvalidSignature,
    );

    assert_replay_pair_precedence(
        0x9500,
        |request| {
            let ingress = ingress_mut(request);
            ingress.unsigned.connection_binding_digest = Digest32::new([0x95; 32]);
            resign_ingress(ingress);
        },
        StableCode::AttestationBindingMismatch,
    );
    assert_replay_pair_precedence(
        0x9600,
        |request| registry_mut(request).signature = Signature64::new([0; 64]),
        StableCode::RegistryInvalidSignature,
    );
    assert_replay_pair_precedence(
        0x9700,
        |request| {
            let registry = registry_mut(request);
            registry.unsigned.expires_at = UnixMillis::new(system_now_ms().saturating_sub(1));
            resign_registry(registry);
        },
        StableCode::AttestationExpired,
    );
    assert_replay_pair_precedence(
        0x9800,
        |request| {
            let registry = registry_mut(request);
            registry.unsigned.expires_at =
                UnixMillis::new(registry.unsigned.expires_at.get().saturating_sub(1));
            resign_registry(registry);
        },
        StableCode::RegistryEquivocation,
    );

    // RegistrySnapshotV1 has no policy-provenance field on the V1 wire.
    // A wrong typed-wrapper provenance therefore cannot be manufactured by a
    // client. The authoritative proof is the policy-core provenance test;
    // the real-daemon rollover test above separately proves registry state is
    // cleared rather than carried into the next policy generation.
}

#[test]
fn signed_begin_input_substitution_fails_before_state_or_nonce_consumption() {
    let installation = Installation::build();
    let mut daemon = installation.spawn_lifecycle_daemon();
    daemon.continue_startup();
    let connection = AuthenticatedConnection::connect(&installation, WireClient::A, 0x9900);
    let mut substituted =
        connection.begin_request(installation.signed_registry(), KernelValue::Null, 0x9901);
    let OperationV1::BeginRun(begin) = &mut substituted.operation else {
        panic!("expected BeginRun");
    };
    begin.input = KernelValue::Bool(true);
    let before = daemon.security_state_snapshot();
    assert_eq!(
        connection.submit(substituted).unwrap_err(),
        StableCode::AttestationBindingMismatch
    );
    assert_eq!(daemon.security_state_snapshot(), before);

    let corrected = AuthenticatedConnection::connect(&installation, WireClient::A, 0x9902);
    let corrected_request =
        corrected.begin_request(installation.signed_registry(), KernelValue::Null, 0x9901);
    assert!(matches!(
        corrected.submit(corrected_request),
        Ok(ResponsePayloadV1::BeginRun(_))
    ));
    daemon.shutdown();
}

#[test]
fn pre_rollover_signed_ingress_fails_on_the_new_real_connection() {
    let installation = Installation::build();
    let mut daemon = installation.spawn_lifecycle_daemon();
    daemon.continue_startup();
    let old_connection = AuthenticatedConnection::connect(&installation, WireClient::A, 0x9a00);
    let old_request =
        old_connection.begin_request(installation.signed_registry(), KernelValue::Null, 0x9a01);
    drop(old_connection);

    installation
        .install_next_candidate_strictly()
        .expect("strict policy update");
    daemon.command_expect(ControlOpcode::Refresh, ControlStatus::Published);
    let before = daemon.security_state_snapshot();
    let new_connection = AuthenticatedConnection::connect(&installation, WireClient::A, 0x9a02);
    assert_eq!(
        new_connection.submit(old_request).unwrap_err(),
        StableCode::AttestationBindingMismatch
    );
    assert_eq!(daemon.security_state_snapshot(), before);
    daemon.shutdown();
}

#[test]
fn cross_run_role_session_auth_context_and_zero_bindings_leave_no_state() {
    let installation = Installation::build();
    let mut daemon = installation.spawn_lifecycle_daemon();
    daemon.continue_startup();
    let registry = installation.signed_registry();
    let first = begin_run(
        &installation,
        WireClient::A,
        registry.clone(),
        0xa001,
        0xa101,
    );
    let second = begin_run(&installation, WireClient::A, registry, 0xa002, 0xa102);

    for (index, mutation) in [
        IngestMutation::CrossRun(second),
        IngestMutation::WrongRole,
        IngestMutation::WrongAuthoritySession,
        IngestMutation::WrongAuthenticationContext,
        IngestMutation::WrongPrincipal,
        IngestMutation::WrongConversation,
        IngestMutation::ZeroAuthoritySession,
        IngestMutation::ZeroNonce,
    ]
    .into_iter()
    .enumerate()
    {
        let sequence = 0xa200 + u64::try_from(index).expect("mutation index");
        let connection = AuthenticatedConnection::connect(&installation, WireClient::A, sequence);
        let mut request = connection.ingest_request(first, KernelValue::Null, sequence + 0x100);
        apply_ingest_mutation(&mut request, mutation);
        let before = daemon.security_state_snapshot();
        assert_eq!(
            connection.submit(request).unwrap_err(),
            StableCode::AttestationBindingMismatch
        );
        assert_eq!(daemon.security_state_snapshot(), before);
    }
    daemon.shutdown();
}

#[test]
fn invalid_expired_equivocated_and_wrong_previous_registry_leave_no_state() {
    assert_stateless_begin_failure(
        0xb000,
        |request| registry_mut(request).signature = Signature64::new([0; 64]),
        StableCode::RegistryInvalidSignature,
    );
    assert_stateless_begin_failure(
        0xb100,
        |request| {
            let registry = registry_mut(request);
            registry.unsigned.expires_at = UnixMillis::new(system_now_ms().saturating_sub(1));
            resign_registry(registry);
        },
        StableCode::AttestationExpired,
    );

    for (index, transition) in [
        RegistryTransition::SameVersionEquivocation,
        RegistryTransition::WrongPreviousDigest,
    ]
    .into_iter()
    .enumerate()
    {
        let installation = Installation::build();
        let mut daemon = installation.spawn_lifecycle_daemon();
        daemon.continue_startup();
        let registry = installation.signed_registry();
        let _run = begin_run(
            &installation,
            WireClient::A,
            registry.clone(),
            0xb200,
            0xb300,
        );
        let connection = AuthenticatedConnection::connect(
            &installation,
            WireClient::A,
            0xb400 + u64::try_from(index).expect("transition index"),
        );
        let mut request = connection.begin_request(
            registry,
            KernelValue::Null,
            0xb500 + u64::try_from(index).expect("transition index"),
        );
        let registry = registry_mut(&mut request);
        match transition {
            RegistryTransition::SameVersionEquivocation => {
                registry.unsigned.expires_at =
                    UnixMillis::new(registry.unsigned.expires_at.get().saturating_sub(1));
            }
            RegistryTransition::WrongPreviousDigest => {
                registry.unsigned.version = 2;
                registry.unsigned.previous_digest = Some(Digest32::new([0xee; 32]));
                for tool in &mut registry.unsigned.tools {
                    tool.identity.registry_version = 2;
                }
            }
        }
        resign_registry(registry);
        let before = daemon.security_state_snapshot();
        assert_eq!(
            connection.submit(request).unwrap_err(),
            StableCode::RegistryEquivocation
        );
        assert_eq!(daemon.security_state_snapshot(), before);
        daemon.shutdown();
    }
}

fn ingress_mut(
    request: &mut RequestEnvelopeV1,
) -> &mut savana_kernel_protocol::SignedIngressEnvelopeV1 {
    match &mut request.operation {
        OperationV1::BeginRun(request) => &mut request.ingress,
        OperationV1::IngestUserInput(request) => &mut request.envelope,
        other => panic!("expected ingress-bearing request, got {other:?}"),
    }
}

fn registry_mut(request: &mut RequestEnvelopeV1) -> &mut SignedRegistrySnapshotV1 {
    match &mut request.operation {
        OperationV1::BeginRun(request) => &mut request.registry,
        other => panic!("expected BeginRun request, got {other:?}"),
    }
}

fn assert_stateless_begin_failure(
    sequence: u64,
    mutate: impl FnOnce(&mut RequestEnvelopeV1),
    expected: StableCode,
) {
    let installation = Installation::build();
    let mut daemon = installation.spawn_lifecycle_daemon();
    daemon.continue_startup();
    let connection = AuthenticatedConnection::connect(&installation, WireClient::A, sequence);
    let mut request = connection.begin_request(
        installation.signed_registry(),
        KernelValue::Null,
        sequence + 1,
    );
    mutate(&mut request);
    let before = daemon.security_state_snapshot();
    assert_eq!(
        connection.submit(request).unwrap_err(),
        expected,
        "stateless case {sequence:#x}"
    );
    assert_eq!(daemon.security_state_snapshot(), before);
    daemon.shutdown();
}

fn assert_replay_pair_precedence(
    sequence: u64,
    mutate: impl FnOnce(&mut RequestEnvelopeV1),
    expected: StableCode,
) {
    let installation = Installation::build();
    let mut daemon = installation.spawn_lifecycle_daemon();
    daemon.continue_startup();
    let registry = installation.signed_registry();
    let first = AuthenticatedConnection::connect(&installation, WireClient::A, sequence);
    let first_request = first.begin_request(registry.clone(), KernelValue::Null, sequence + 2);
    assert!(first.submit(first_request).is_ok());

    let replay = AuthenticatedConnection::connect(&installation, WireClient::A, sequence + 1);
    let mut request = replay.begin_request(registry, KernelValue::Null, sequence + 2);
    mutate(&mut request);
    let before = daemon.security_state_snapshot();
    assert_eq!(
        replay.submit(request).unwrap_err(),
        expected,
        "replay case {sequence:#x}"
    );
    assert_eq!(daemon.security_state_snapshot(), before);
    daemon.shutdown();
}

fn begin_run(
    installation: &Installation,
    client: WireClient,
    registry: SignedRegistrySnapshotV1,
    connection_nonce: u64,
    ingress_nonce: u64,
) -> savana_kernel_protocol::RunHandle {
    let connection = AuthenticatedConnection::connect(installation, client, connection_nonce);
    let request = connection.begin_request(registry, KernelValue::Null, ingress_nonce);
    match connection.submit(request).expect("BeginRun") {
        ResponsePayloadV1::BeginRun(response) => response.run,
        other => panic!("expected BeginRun response, got {other:?}"),
    }
}

#[derive(Clone, Copy)]
enum IngestMutation {
    CrossRun(savana_kernel_protocol::RunHandle),
    WrongRole,
    WrongAuthoritySession,
    WrongAuthenticationContext,
    WrongPrincipal,
    WrongConversation,
    ZeroAuthoritySession,
    ZeroNonce,
}

fn apply_ingest_mutation(request: &mut RequestEnvelopeV1, mutation: IngestMutation) {
    let OperationV1::IngestUserInput(ingest) = &mut request.operation else {
        panic!("expected IngestUserInput request");
    };
    match mutation {
        IngestMutation::CrossRun(run) => ingest.run = run,
        IngestMutation::WrongRole => {
            ingest.envelope.unsigned.role = "other-role".try_into().expect("role")
        }
        IngestMutation::WrongAuthoritySession => {
            ingest.envelope.unsigned.authority_session_id = Nonce32::new([0x91; 32])
        }
        IngestMutation::WrongAuthenticationContext => {
            ingest.envelope.unsigned.authentication_context_digest = Digest32::new([0x92; 32])
        }
        IngestMutation::WrongPrincipal => {
            ingest.envelope.unsigned.principal = "other-principal".try_into().expect("principal")
        }
        IngestMutation::WrongConversation => {
            ingest.envelope.unsigned.conversation_id =
                "other-conversation".try_into().expect("conversation")
        }
        IngestMutation::ZeroAuthoritySession => {
            ingest.envelope.unsigned.authority_session_id = Nonce32::new([0; 32])
        }
        IngestMutation::ZeroNonce => ingest.envelope.unsigned.nonce = Nonce32::new([0; 32]),
    }
    resign_ingress(&mut ingest.envelope);
}

#[derive(Clone, Copy)]
enum RegistryTransition {
    SameVersionEquivocation,
    WrongPreviousDigest,
}

fn system_now_ms() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_millis(),
    )
    .expect("millisecond clock")
}
