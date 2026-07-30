mod support;

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Barrier};

use ed25519_dalek::{Signer, SigningKey};
use savana_kernel_protocol::{
    ingress_request_digest, ActiveToolView, AttemptKindV1, BeginRunRequest, BootId, BoundedText,
    ClientId, ConversationId, Digest32, IngestUserInputRequest, IngressEnvelopeV1,
    IngressRequestCommitmentV1, KernelValue, KeyId, Nonce32, PrincipalId, RegistrySnapshotV1,
    RoleId, Signature64, SignedIngressEnvelopeV1, SignedRegistrySnapshotV1, StableCode,
    ToolDescriptorV1, ToolExecutionIdentity, ToolName, UnixMillis,
};
use savana_policy_core::{
    AuthenticatedCallContext, Clock, PolicyEngine, PolicyIdentity, RandomSource,
};

const INGRESS_DOMAIN: &[u8] = b"SAVANA_INGRESS_V1\0";
const REGISTRY_DOMAIN: &[u8] = b"SAVANA_REGISTRY_V1\0";

struct SequenceRandom {
    next: AtomicU8,
}

impl RandomSource for SequenceRandom {
    fn fill(&self, output: &mut [u8]) -> Result<usize, StableCode> {
        let byte = self.next.fetch_add(1, Ordering::SeqCst);
        output.fill(byte);
        Ok(output.len())
    }
}

struct Fixture {
    engine: PolicyEngine,
    context: Arc<AuthenticatedCallContext>,
    identity: PolicyIdentity,
    boot_id: BootId,
    connection_binding: Digest32,
    next_nonce: AtomicU8,
}

impl Fixture {
    fn new() -> Self {
        let (current, identity) = support::current_policy_and_identity();
        let clock = support::clock();
        let boot_id = BootId::new([0x41; 32]);
        let random: Arc<dyn RandomSource + Send + Sync> = Arc::new(SequenceRandom {
            next: AtomicU8::new(1),
        });
        let (engine, issuer) = PolicyEngine::new(
            current,
            boot_id,
            Arc::clone(&clock) as Arc<dyn Clock + Send + Sync>,
            random,
        )
        .unwrap();
        let connection_binding = Digest32::new([0x44; 32]);
        let context = issuer
            .bind(
                ClientId::new("jarvis-client").unwrap(),
                Nonce32::new([0x33; 32]),
                connection_binding,
                identity,
                boot_id,
                1_001,
                UnixMillis::new(3_000),
            )
            .unwrap();
        Self {
            engine,
            context: Arc::new(context),
            identity,
            boot_id,
            connection_binding,
            next_nonce: AtomicU8::new(0x80),
        }
    }

    fn begin_request(&self, role: &str, input: KernelValue) -> BeginRunRequest {
        let commitment = IngressRequestCommitmentV1::BeginRun {
            input: input.clone(),
        };
        BeginRunRequest {
            ingress: self.ingress(
                role,
                ingress_request_digest(&commitment).unwrap(),
                self.next_nonce(),
            ),
            input,
            registry: signed_registry(),
        }
    }

    fn ingest_request(
        &self,
        run: savana_kernel_protocol::RunHandle,
        input: KernelValue,
    ) -> IngestUserInputRequest {
        let commitment = IngressRequestCommitmentV1::IngestUserInput {
            run,
            input: input.clone(),
        };
        IngestUserInputRequest {
            run,
            envelope: self.ingress(
                "operator",
                ingress_request_digest(&commitment).unwrap(),
                self.next_nonce(),
            ),
            input,
        }
    }

    fn ingress(
        &self,
        role: &str,
        request_digest: Digest32,
        nonce: Nonce32,
    ) -> SignedIngressEnvelopeV1 {
        let unsigned = IngressEnvelopeV1 {
            principal: PrincipalId::new("principal-1").unwrap(),
            conversation_id: ConversationId::new("conversation-1").unwrap(),
            request_digest,
            issued_at: UnixMillis::new(1_900),
            expires_at: UnixMillis::new(3_000),
            nonce,
            authority_session_id: Nonce32::new([0x66; 32]),
            authentication_context_digest: Digest32::new([0x55; 32]),
            role: RoleId::new(role).unwrap(),
            policy_digest: self.identity.digest,
            boot_id: self.boot_id,
            connection_binding_digest: self.connection_binding,
        };
        SignedIngressEnvelopeV1 {
            signature: sign(
                INGRESS_DOMAIN,
                &unsigned,
                &SigningKey::from_bytes(&[0x70; 32]),
            ),
            unsigned,
            key_id: KeyId::new("role-00").unwrap(),
        }
    }

    fn next_nonce(&self) -> Nonce32 {
        Nonce32::new([self.next_nonce.fetch_add(1, Ordering::SeqCst); 32])
    }
}

#[test]
fn begin_run_derives_exact_signed_role_and_policy_intersection() {
    let fixture = Fixture::new();
    let response = fixture
        .engine
        .begin_run(
            fixture.context.as_ref(),
            fixture.begin_request("operator", KernelValue::Null),
        )
        .unwrap();
    assert_eq!(tool_names(&response.active_tools), vec!["tool-00"]);

    let empty = fixture
        .engine
        .begin_run(
            fixture.context.as_ref(),
            fixture.begin_request("role-with-no-tools", KernelValue::Null),
        )
        .unwrap();
    assert!(empty.active_tools.is_empty());
}

#[test]
fn changed_begin_or_ingest_input_fails_before_state_transition() {
    let fixture = Fixture::new();
    let mut begin = fixture.begin_request("operator", KernelValue::Bool(true));
    begin.input = KernelValue::Bool(false);
    assert_eq!(
        fixture
            .engine
            .begin_run(fixture.context.as_ref(), begin)
            .unwrap_err()
            .code(),
        StableCode::AttestationBindingMismatch
    );

    let run = fixture
        .engine
        .begin_run(
            fixture.context.as_ref(),
            fixture.begin_request("operator", KernelValue::Null),
        )
        .unwrap()
        .run;
    let mut ingest = fixture.ingest_request(run, KernelValue::Bool(true));
    ingest.input = KernelValue::Bool(false);
    assert_eq!(
        fixture
            .engine
            .ingest_user_input(fixture.context.as_ref(), ingest)
            .unwrap_err()
            .code(),
        StableCode::AttestationBindingMismatch
    );
    assert!(fixture
        .engine
        .ingest_user_input(
            fixture.context.as_ref(),
            fixture.ingest_request(run, KernelValue::Bool(true)),
        )
        .is_ok());
}

#[test]
fn one_signed_ingress_has_one_atomic_winner() {
    let fixture = Arc::new(Fixture::new());
    let request = fixture.begin_request("operator", KernelValue::Null);
    let barrier = Arc::new(Barrier::new(3));
    let joins = [(), ()].map(|()| {
        let fixture = Arc::clone(&fixture);
        let request = request.clone();
        let barrier = Arc::clone(&barrier);
        std::thread::spawn(move || {
            barrier.wait();
            fixture.engine.begin_run(fixture.context.as_ref(), request)
        })
    });
    barrier.wait();
    let outcomes = joins.map(|join| join.join().unwrap());
    assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| outcome
                .as_ref()
                .is_err_and(|error| { error.code() == StableCode::AttestationBindingMismatch }))
            .count(),
        1
    );
}

#[test]
fn policy_boot_request_and_connection_binding_mutations_do_not_consume_nonce() {
    for mutation in 0..4 {
        let fixture = support::IngressFixture::new();
        let mut request = fixture.begin_request("operator", KernelValue::Null);
        match mutation {
            0 => request.ingress.unsigned.request_digest = Digest32::new([0xe1; 32]),
            1 => request.ingress.unsigned.policy_digest = Digest32::new([0xe2; 32]),
            2 => request.ingress.unsigned.boot_id = BootId::new([0xe3; 32]),
            3 => request.ingress.unsigned.connection_binding_digest = Digest32::new([0xe4; 32]),
            _ => unreachable!(),
        }
        support::resign_ingress(&mut request.ingress);
        let replay = request.clone();
        assert_eq!(
            fixture
                .engine
                .begin_run(&fixture.context, request)
                .unwrap_err()
                .code(),
            StableCode::AttestationBindingMismatch
        );
        let mut corrected = replay;
        corrected.ingress.unsigned.request_digest =
            ingress_request_digest(&IngressRequestCommitmentV1::BeginRun {
                input: corrected.input.clone(),
            })
            .unwrap();
        corrected.ingress.unsigned.policy_digest = fixture.identity.digest;
        corrected.ingress.unsigned.boot_id = fixture.boot_id;
        corrected.ingress.unsigned.connection_binding_digest = fixture.connection_binding;
        support::resign_ingress(&mut corrected.ingress);
        assert!(fixture
            .engine
            .begin_run(&fixture.context, corrected)
            .is_ok());
    }
}

#[test]
fn replay_key_is_global_across_clients_and_connection_bindings() {
    let fixture = Arc::new(support::IngressFixture::new());
    let (other_context, other_binding) = fixture.bind("other-client", 0x35, 0x46);
    let input = KernelValue::Null;
    let digest = ingress_request_digest(&IngressRequestCommitmentV1::BeginRun {
        input: input.clone(),
    })
    .unwrap();
    let nonce = Nonce32::new([0xa5; 32]);
    let request_a = BeginRunRequest {
        ingress: fixture.ingress("operator", digest, nonce, fixture.connection_binding),
        input: input.clone(),
        registry: support::signed_registry(),
    };
    let request_b = BeginRunRequest {
        ingress: fixture.ingress("operator", digest, nonce, other_binding),
        input,
        registry: support::signed_registry(),
    };
    assert_ne!(request_a.ingress.signature, request_b.ingress.signature);
    let other_context = Arc::new(other_context);
    let barrier = Arc::new(Barrier::new(3));
    let joins = [
        (request_a, None),
        (request_b, Some(Arc::clone(&other_context))),
    ]
    .map(|(request, other)| {
        let fixture = Arc::clone(&fixture);
        let barrier = Arc::clone(&barrier);
        std::thread::spawn(move || {
            barrier.wait();
            match other {
                Some(context) => fixture.engine.begin_run(context.as_ref(), request),
                None => fixture.engine.begin_run(&fixture.context, request),
            }
        })
    });
    barrier.wait();
    let outcomes = joins.map(|join| join.join().unwrap());
    assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| outcome
                .as_ref()
                .is_err_and(|error| { error.code() == StableCode::AttestationBindingMismatch }))
            .count(),
        1
    );
}

#[test]
fn same_client_new_connection_continues_run_but_other_client_cannot() {
    let fixture = support::IngressFixture::new();
    let run = fixture
        .engine
        .begin_run(
            &fixture.context,
            fixture.begin_request("operator", KernelValue::Null),
        )
        .unwrap()
        .run;
    let (fresh, fresh_binding) = fixture.bind("jarvis-client", 0x36, 0x47);
    assert!(fixture
        .engine
        .ingest_user_input(
            &fresh,
            fixture.ingest_request_for(run, KernelValue::Bool(true), fresh_binding),
        )
        .is_ok());
    let (other, other_binding) = fixture.bind("other-client", 0x37, 0x48);
    assert_eq!(
        fixture
            .engine
            .ingest_user_input(
                &other,
                fixture.ingest_request_for(run, KernelValue::Bool(false), other_binding),
            )
            .unwrap_err()
            .code(),
        StableCode::HandleWrongClient
    );
}

fn signed_registry() -> SignedRegistrySnapshotV1 {
    let unsigned = RegistrySnapshotV1 {
        version: 1,
        previous_digest: None,
        tools: vec![ToolDescriptorV1 {
            identity: ToolExecutionIdentity {
                name: ToolName::new("tool-00").unwrap(),
                descriptor_digest: Digest32::new([0x21; 32]),
                registry_version: 1,
            },
            provider_id: BoundedText::try_from("provider-1").unwrap(),
            roles: vec![RoleId::new("operator").unwrap()],
            input_schema_digest: Digest32::new([0x31; 32]),
            output_schema_digest: Digest32::new([0x32; 32]),
            attempt: AttemptKindV1::Read,
            constraint_ids: Vec::new(),
            validator_ids: Vec::new(),
            projection_digest: Digest32::new([0x33; 32]),
        }],
        issued_at: UnixMillis::new(1_900),
        expires_at: UnixMillis::new(3_000),
    };
    SignedRegistrySnapshotV1 {
        signature: sign(
            REGISTRY_DOMAIN,
            &unsigned,
            &SigningKey::from_bytes(&[0x72; 32]),
        ),
        unsigned,
        key_id: KeyId::new("role-02").unwrap(),
    }
}

fn sign<T: minicbor::Encode<()>>(domain: &[u8], value: &T, key: &SigningKey) -> Signature64 {
    let payload = minicbor::to_vec(value).unwrap();
    let mut message = Vec::with_capacity(domain.len() + payload.len());
    message.extend_from_slice(domain);
    message.extend_from_slice(&payload);
    Signature64::new(key.sign(&message).to_bytes())
}

fn tool_names(tools: &[ActiveToolView]) -> Vec<&str> {
    tools
        .iter()
        .map(|tool| tool.identity.name.as_str())
        .collect()
}
