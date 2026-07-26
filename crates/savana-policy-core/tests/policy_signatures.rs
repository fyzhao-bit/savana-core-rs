#[path = "support/mod.rs"]
mod policy_support;
#[path = "../vector_support.rs"]
mod vector_support;

use policy_support as support;

use ed25519_dalek::SigningKey;
use savana_kernel_protocol::{
    ApprovalAuthMethod, ApprovalChallengeV1, ApprovalDecision, ApprovalPurposeV1,
    ApprovalReceiptV1, ApprovalSubjectV1, BootId, BoundedText, ConversationId, Digest32,
    IngressEnvelopeV1, KeyId, Nonce32, OntologyEffectV1, OntologyEntryV1, OntologyEventV1,
    OntologySnapshotV1, PendingToolCallHandle, PlannerId, PrincipalId, RegistrySnapshotV1, RunId,
    Signature64, SignedIngressEnvelopeV1, SignedOntologyEventV1, SignedOntologySnapshotV1,
    SignedPlannerAttestationV1, SignedRegistrySnapshotV1, SignedValidatorAttestationV1, StableCode,
    TaskId, ToolExecutionIdentity, ToolName, UnixMillis, UnsignedApprovalReceiptV1, ValidatorId,
    ValidatorVerdictV1,
};
use savana_policy_core::{AuthorityRoleV1, PolicyTrustRootV1, PolicyVerifier, VerifiedPolicyV1};
use sha2::{Digest as _, Sha256};

#[test]
fn committed_policy_vector_and_signature_match_the_v1_fixture() {
    let fixture = vector_support::release_bound_vector_fixture();
    let (bundle, signature) = support::signed(&fixture.policy);
    assert_eq!(
        bundle.as_slice(),
        include_bytes!("../../../vectors/kerneld/policy-bundle-v1.cbor")
    );
    assert_eq!(
        signature.as_bytes(),
        include_bytes!("../../../vectors/kerneld/policy-bundle-v1.sig")
    );
}

#[test]
fn release_bound_vector_fixture_uses_independent_domain_hashes() {
    let fixture = vector_support::release_bound_vector_fixture();

    let canonical_resources = minicbor::to_vec(fixture.policy.resources).unwrap();
    let mut resource_hash = Sha256::new();
    resource_hash.update(b"SAVANA_RESOURCE_PROFILE_V1\0");
    resource_hash.update(canonical_resources);
    assert_eq!(
        <[u8; 32]>::from(resource_hash.finalize()),
        fixture.resource_profile_digest
    );

    let mut target_tuple = minicbor::Encoder::new(Vec::new());
    target_tuple
        .array(7)
        .unwrap()
        .u16(1)
        .unwrap()
        .u16(0)
        .unwrap()
        .u16(0)
        .unwrap()
        .array(1)
        .unwrap()
        .u16(1)
        .unwrap()
        .bytes(&fixture.roots_digest)
        .unwrap()
        .bytes(&fixture.resource_profile_digest)
        .unwrap()
        .bytes(&fixture.installation_profile_digest)
        .unwrap();
    let mut target_hash = Sha256::new();
    target_hash.update(b"SAVANA_RELEASE_TARGET_V1\0");
    target_hash.update(target_tuple.into_writer());
    assert_eq!(
        <[u8; 32]>::from(target_hash.finalize()),
        fixture.release_target_id
    );
    assert_eq!(
        fixture.policy.release.compatible_release_target_ids,
        vec![fixture.release_target_id]
    );
    assert_eq!(
        <[u8; 32]>::from(Sha256::digest(&fixture.roots_bytes)),
        fixture.roots_digest
    );
    assert_eq!(
        <[u8; 32]>::from(Sha256::digest(&fixture.profile_bytes)),
        fixture.installation_profile_digest
    );
}

#[test]
fn valid_policy_signature_is_accepted() {
    let policy = support::valid_policy(7, 3);
    let (bundle, signature) = support::signed(&policy);
    let verified = support::verifier()
        .verify(&bundle, &signature, support::unix_now())
        .unwrap();
    assert_eq!(verified.identity().policy_version, 7);
    assert_eq!(verified.identity().key_epoch, 3);
    assert_eq!(
        verified.effective_limits().frame_bytes(),
        savana_kernel_protocol::HardLimits::COMPILED.frame_bytes()
    );
    let validator_id = KeyId::try_from("role-04").unwrap();
    let validator = verified
        .authority(&validator_id, AuthorityRoleV1::Validator)
        .unwrap();
    assert_eq!(validator.key_id(), &validator_id);
    assert_eq!(validator.role(), AuthorityRoleV1::Validator);
    assert_eq!(
        validator.public_key(),
        &producer_key(AuthorityRoleV1::Validator.tag())
            .verifying_key()
            .to_bytes()
    );
    assert_eq!(validator.epoch(), 1);
    assert!(verified
        .authority(&validator_id, AuthorityRoleV1::Ontology)
        .is_none());
}

#[test]
fn authority_view_excludes_revoked_and_partial_window_keys() {
    let mut policy = support::valid_policy(7, 3);
    policy.authorities.push(support::Authority {
        key_id: "role-04-window".to_owned(),
        role: 4,
        public_key: SigningKey::from_bytes(&[0x52; 32])
            .verifying_key()
            .to_bytes(),
        epoch: 2,
        not_before: 1_001,
        not_after: 4_100,
        revoked: false,
    });
    policy.authorities.push(support::Authority {
        key_id: "role-04-revoked".to_owned(),
        role: 4,
        public_key: SigningKey::from_bytes(&[0x51; 32])
            .verifying_key()
            .to_bytes(),
        epoch: 2,
        not_before: 900,
        not_after: 4_100,
        revoked: true,
    });
    let (bundle, signature) = support::signed(&policy);
    let verified = support::verifier()
        .verify(&bundle, &signature, support::unix_now())
        .unwrap();

    for key_id in ["role-04-revoked", "role-04-window"] {
        assert!(verified
            .authority(
                &KeyId::try_from(key_id).unwrap(),
                AuthorityRoleV1::Validator
            )
            .is_none());
    }
}

#[test]
fn modified_bundle_and_wrong_domain_are_rejected() {
    let policy = support::valid_policy(7, 3);
    let (bundle, signature) = support::signed(&policy);
    let verifier = support::verifier();

    let mut modified = bundle.clone();
    let digest_offset = modified
        .windows(32)
        .position(|window| window == [0x21; 32])
        .expect("fixture descriptor digest is encoded");
    modified[digest_offset] ^= 1;
    assert_eq!(
        verifier
            .verify(&modified, &signature, support::unix_now())
            .unwrap_err()
            .code(),
        StableCode::PolicyInvalidSignature
    );

    let (_, wrong_domain_signature) =
        support::signed_with_domain(&policy, support::RELEASE_DOMAIN, &support::signing_key());
    assert_eq!(
        verifier
            .verify(&bundle, &wrong_domain_signature, support::unix_now())
            .unwrap_err()
            .code(),
        StableCode::PolicyInvalidSignature
    );
}

#[test]
fn unknown_revoked_epoch_mismatched_and_wrong_keys_are_rejected() {
    let key = support::signing_key();
    let policy = support::valid_policy(7, 3);
    let (bundle, signature) = support::signed(&policy);

    let unknown =
        support::verifier_with_roots(vec![support::trust_root("other-root", &key, 3, false)]);
    assert_eq!(
        unknown
            .verify(&bundle, &signature, support::unix_now())
            .unwrap_err()
            .code(),
        StableCode::PolicyInvalidSignature
    );

    let revoked =
        support::verifier_with_roots(vec![support::trust_root("policy-root", &key, 3, true)]);
    assert_eq!(
        revoked
            .verify(&bundle, &signature, support::unix_now())
            .unwrap_err()
            .code(),
        StableCode::PolicyInvalidSignature
    );

    let wrong_epoch =
        support::verifier_with_roots(vec![support::trust_root("policy-root", &key, 4, false)]);
    assert_eq!(
        wrong_epoch
            .verify(&bundle, &signature, support::unix_now())
            .unwrap_err()
            .code(),
        StableCode::PolicyInvalidSignature
    );

    let (_, wrong_key_signature) =
        support::signed_with_key(&policy, &support::alternate_signing_key());
    assert_eq!(
        support::verifier()
            .verify(&bundle, &wrong_key_signature, support::unix_now())
            .unwrap_err()
            .code(),
        StableCode::PolicyInvalidSignature
    );
}

#[test]
fn embedded_authority_never_creates_policy_trust() {
    let mut policy = support::valid_policy(7, 3);
    policy.signing_key_id = "role-00".to_owned();
    let (bundle, signature) = support::signed(&policy);
    assert_eq!(
        support::verifier()
            .verify(&bundle, &signature, support::unix_now())
            .unwrap_err()
            .code(),
        StableCode::PolicyInvalidSignature
    );
}

#[test]
fn verifier_constructor_rejects_invalid_root_sets() {
    let key = support::signing_key();
    assert_eq!(
        PolicyVerifier::new(Vec::new(), support::active_target())
            .unwrap_err()
            .code(),
        StableCode::ProtocolMalformedCbor
    );

    let too_many = (0..17)
        .map(|index| support::trust_root(&format!("root-{index:02}"), &key, 3, false))
        .collect();
    assert_eq!(
        PolicyVerifier::new(too_many, support::active_target())
            .unwrap_err()
            .code(),
        StableCode::PolicyLimitExceeded
    );

    let duplicate = support::trust_root("policy-root", &key, 3, false);
    assert_eq!(
        PolicyVerifier::new(vec![duplicate.clone(), duplicate], support::active_target())
            .unwrap_err()
            .code(),
        StableCode::ProtocolMalformedCbor
    );

    let unsorted = vec![
        support::trust_root("root-bb", &key, 3, false),
        support::trust_root("root-aa", &key, 3, false),
    ];
    assert_eq!(
        PolicyVerifier::new(unsorted, support::active_target())
            .unwrap_err()
            .code(),
        StableCode::ProtocolMalformedCbor
    );

    for invalid in [
        PolicyTrustRootV1 {
            key_id: KeyId::try_from("zero-epoch").unwrap(),
            public_key: key.verifying_key().to_bytes(),
            epoch: 0,
            revoked: false,
        },
        PolicyTrustRootV1 {
            key_id: KeyId::try_from("zero-key").unwrap(),
            public_key: [0; 32],
            epoch: 3,
            revoked: false,
        },
    ] {
        assert_eq!(
            PolicyVerifier::new(vec![invalid], Digest32::new([0xa0; 32]))
                .unwrap_err()
                .code(),
            StableCode::PolicyInvalidSignature
        );
    }
}

#[test]
fn noncanonical_indefinite_and_trailing_policy_bytes_are_rejected() {
    let policy = support::valid_policy(7, 3);
    let canonical = support::encode_policy(&policy);
    let verifier = support::verifier();

    let mut non_shortest = canonical.clone();
    let mut decoder = minicbor::Decoder::new(&canonical);
    assert_eq!(decoder.array().unwrap(), Some(17));
    assert_eq!(decoder.u16().unwrap(), 1);
    assert_eq!(decoder.array().unwrap(), Some(3));
    assert_eq!(decoder.u16().unwrap(), 1);
    assert_eq!(decoder.u16().unwrap(), 0);
    assert_eq!(decoder.u16().unwrap(), 0);
    let policy_version_position = decoder.position();
    assert_eq!(decoder.u64().unwrap(), 7);
    non_shortest.splice(
        policy_version_position..policy_version_position + 1,
        [0x18, 0x07],
    );

    let mut indefinite = canonical.clone();
    assert_eq!(indefinite[0], 0x91);
    indefinite[0] = 0x9f;
    indefinite.push(0xff);

    let mut trailing = canonical;
    trailing.push(0);

    for bytes in [non_shortest, indefinite, trailing] {
        let signature =
            support::detached_signature(support::POLICY_DOMAIN, &bytes, &support::signing_key());
        assert_eq!(
            verifier
                .verify(&bytes, &signature, support::unix_now())
                .unwrap_err()
                .code(),
            StableCode::ProtocolMalformedCbor
        );
    }
}

const INGRESS_DOMAIN: &[u8] = b"SAVANA_INGRESS_V1\0";
const PLANNER_DOMAIN: &[u8] = b"SAVANA_PLANNER_V1\0";
const REGISTRY_DOMAIN: &[u8] = b"SAVANA_REGISTRY_V1\0";
const ONTOLOGY_SNAPSHOT_DOMAIN: &[u8] = b"SAVANA_ONTOLOGY_SNAPSHOT_V1\0";
const ONTOLOGY_EVENT_DOMAIN: &[u8] = b"SAVANA_ONTOLOGY_EVENT_V1\0";
const VALIDATOR_DOMAIN: &[u8] = b"SAVANA_VALIDATOR_V1\0";
const APPROVAL_ENVELOPE_DOMAIN: &[u8] = b"SAVANA_APPROVAL_ENVELOPE_V1\0";
const APPROVAL_RECEIPT_DOMAIN: &[u8] = b"SAVANA_APPROVAL_RECEIPT_V1\0";

fn producer_key(role: u8) -> SigningKey {
    SigningKey::from_bytes(&[0x70 + role; 32])
}

fn producer_policy() -> VerifiedPolicyV1 {
    producer_policy_with_ttls(60, 60)
}

fn producer_policy_with_ttls(
    challenge_ttl_seconds: u32,
    receipt_ttl_seconds: u32,
) -> VerifiedPolicyV1 {
    let mut policy = support::valid_policy(7, 3);
    policy.release.challenge_ttl_seconds = challenge_ttl_seconds;
    policy.release.receipt_ttl_seconds = receipt_ttl_seconds;
    for authority in &mut policy.authorities {
        authority.public_key = producer_key(authority.role).verifying_key().to_bytes();
    }
    let (bundle, signature) = support::signed(&policy);
    support::verifier()
        .verify(&bundle, &signature, support::unix_now())
        .unwrap()
}

fn producer_policy_with_snapshot_limit(max_snapshot_entries: u32) -> VerifiedPolicyV1 {
    let mut policy = support::valid_policy(7, 3);
    policy.ontology.max_snapshot_entries = max_snapshot_entries;
    for authority in &mut policy.authorities {
        authority.public_key = producer_key(authority.role).verifying_key().to_bytes();
    }
    let (bundle, signature) = support::signed(&policy);
    support::verifier()
        .verify(&bundle, &signature, support::unix_now())
        .unwrap()
}

fn signature(domain: &[u8], payload: &[u8], role: u8) -> Signature64 {
    support::detached_signature(domain, payload, &producer_key(role))
}

fn encoded_ingress(domain: &[u8]) -> Vec<u8> {
    let unsigned = IngressEnvelopeV1 {
        principal: PrincipalId::try_from("principal-1").unwrap(),
        conversation_id: ConversationId::try_from("conversation-1").unwrap(),
        request_digest: Digest32::new([0x21; 32]),
        issued_at: UnixMillis::new(1_000),
        expires_at: UnixMillis::new(3_000),
        nonce: Nonce32::new([0x22; 32]),
        authority_session_id: Nonce32::new([0x23; 32]),
        authentication_context_digest: Digest32::new([0x24; 32]),
        role: savana_kernel_protocol::RoleId::try_from("operator").unwrap(),
        policy_digest: Digest32::new([0x25; 32]),
        boot_id: BootId::new([0x26; 32]),
        connection_binding_digest: Digest32::new([0x27; 32]),
    };
    let payload = minicbor::to_vec(&unsigned).unwrap();
    minicbor::to_vec(SignedIngressEnvelopeV1 {
        unsigned,
        key_id: KeyId::try_from("role-00").unwrap(),
        signature: signature(domain, &payload, 0),
    })
    .unwrap()
}

fn encoded_planner(domain: &[u8]) -> Vec<u8> {
    let mut value = SignedPlannerAttestationV1 {
        run_id: RunId::new([0x31; 32]),
        planner_id: PlannerId::try_from("role-01").unwrap(),
        planner_version: BoundedText::try_from("planner-1").unwrap(),
        prompt_digest: Digest32::new([0x32; 32]),
        output_digest: Digest32::new([0x33; 32]),
        issued_at: UnixMillis::new(1_000),
        expires_at: UnixMillis::new(3_000),
        nonce: Nonce32::new([0x34; 32]),
        key_id: KeyId::try_from("role-01").unwrap(),
        signature: Signature64::new([0; 64]),
    };
    let payload = planner_payload(&value);
    value.signature = signature(domain, &payload, 1);
    minicbor::to_vec(value).unwrap()
}

fn planner_payload(value: &SignedPlannerAttestationV1) -> Vec<u8> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(9)
        .unwrap()
        .encode(value.run_id)
        .unwrap()
        .encode(&value.planner_id)
        .unwrap()
        .encode(&value.planner_version)
        .unwrap()
        .encode(value.prompt_digest)
        .unwrap()
        .encode(value.output_digest)
        .unwrap()
        .encode(value.issued_at)
        .unwrap()
        .encode(value.expires_at)
        .unwrap()
        .encode(value.nonce)
        .unwrap()
        .encode(&value.key_id)
        .unwrap();
    encoder.into_writer()
}

fn encoded_registry(domain: &[u8]) -> Vec<u8> {
    let unsigned = RegistrySnapshotV1 {
        version: 1,
        previous_digest: None,
        tools: Vec::new(),
        issued_at: UnixMillis::new(1_000),
        expires_at: UnixMillis::new(3_000),
    };
    let payload = minicbor::to_vec(&unsigned).unwrap();
    minicbor::to_vec(SignedRegistrySnapshotV1 {
        unsigned,
        key_id: KeyId::try_from("role-02").unwrap(),
        signature: signature(domain, &payload, 2),
    })
    .unwrap()
}

fn ontology_entry() -> OntologyEntryV1 {
    OntologyEntryV1 {
        constraint_id: "constraint-00".try_into().unwrap(),
        tool: ToolName::try_from("tool-00").unwrap(),
        effect: OntologyEffectV1::Allow,
        validator_id: None,
    }
}

fn encoded_ontology_snapshot(domain: &[u8]) -> Vec<u8> {
    let unsigned = OntologySnapshotV1 {
        version: 1,
        previous_digest: None,
        entries: vec![ontology_entry()],
        issued_at: UnixMillis::new(1_000),
        expires_at: UnixMillis::new(3_000),
    };
    let payload = minicbor::to_vec(&unsigned).unwrap();
    minicbor::to_vec(SignedOntologySnapshotV1 {
        unsigned,
        key_id: KeyId::try_from("role-03").unwrap(),
        signature: signature(domain, &payload, 3),
    })
    .unwrap()
}

fn encoded_ontology_event(domain: &[u8]) -> Vec<u8> {
    let unsigned = OntologyEventV1 {
        version: 2,
        previous_digest: Digest32::new([0x41; 32]),
        sequence: 1,
        replacement: ontology_entry(),
        issued_at: UnixMillis::new(1_000),
        expires_at: UnixMillis::new(3_000),
    };
    let payload = minicbor::to_vec(&unsigned).unwrap();
    minicbor::to_vec(SignedOntologyEventV1 {
        unsigned,
        key_id: KeyId::try_from("role-03").unwrap(),
        signature: signature(domain, &payload, 3),
    })
    .unwrap()
}

fn pending_handle() -> PendingToolCallHandle {
    let mut encoded = vec![0x58, 0x20];
    encoded.extend_from_slice(&[0x51; 32]);
    minicbor::decode(&encoded).unwrap()
}

fn encoded_validator(domain: &[u8]) -> Vec<u8> {
    let mut value = SignedValidatorAttestationV1 {
        validator_id: ValidatorId::try_from("role-04").unwrap(),
        validator_version: BoundedText::try_from("validator-1").unwrap(),
        run_id: RunId::new([0x52; 32]),
        pending: pending_handle(),
        argument_digest: Digest32::new([0x53; 32]),
        verdict: ValidatorVerdictV1::Pass,
        public_reason: StableCode::PolicyDenied,
        issued_at: UnixMillis::new(1_000),
        expires_at: UnixMillis::new(3_000),
        nonce: Nonce32::new([0x54; 32]),
        key_id: KeyId::try_from("role-04").unwrap(),
        signature: Signature64::new([0; 64]),
    };
    let payload = validator_payload(&value);
    value.signature = signature(domain, &payload, 4);
    minicbor::to_vec(value).unwrap()
}

fn validator_payload(value: &SignedValidatorAttestationV1) -> Vec<u8> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(11)
        .unwrap()
        .encode(&value.validator_id)
        .unwrap()
        .encode(&value.validator_version)
        .unwrap()
        .encode(value.run_id)
        .unwrap()
        .encode(value.pending)
        .unwrap()
        .encode(value.argument_digest)
        .unwrap()
        .encode(value.verdict)
        .unwrap()
        .encode(value.public_reason)
        .unwrap()
        .encode(value.issued_at)
        .unwrap()
        .encode(value.expires_at)
        .unwrap()
        .encode(value.nonce)
        .unwrap()
        .encode(&value.key_id)
        .unwrap();
    encoder.into_writer()
}

fn approval_challenge() -> ApprovalChallengeV1 {
    ApprovalChallengeV1 {
        challenge_id: Nonce32::new([0x61; 32]),
        purpose: ApprovalPurposeV1::ToolMaterialization,
        subject: ApprovalSubjectV1::ToolCall {
            pending: pending_handle(),
            argument_digest: Digest32::new([0x62; 32]),
            provenance_digest: Digest32::new([0x63; 32]),
        },
        boot_id: BootId::new([0x64; 32]),
        run_id: RunId::new([0x65; 32]),
        principal: PrincipalId::try_from("principal-1").unwrap(),
        conversation_id: ConversationId::try_from("conversation-1").unwrap(),
        task_id: TaskId::try_from("task-1").unwrap(),
        tool: ToolExecutionIdentity {
            name: ToolName::try_from("tool-00").unwrap(),
            descriptor_digest: Digest32::new([0x66; 32]),
            registry_version: 1,
        },
        destination_digest: Digest32::new([0x67; 32]),
        policy_version: 7,
        issued_at: UnixMillis::new(1_000),
        expires_at: UnixMillis::new(3_000),
        nonce: Nonce32::new([0x68; 32]),
    }
}

fn encoded_approval_receipt(domain: &[u8]) -> Vec<u8> {
    let unsigned = UnsignedApprovalReceiptV1 {
        envelope_digest: Digest32::new([0x69; 32]),
        challenge: approval_challenge(),
        decision: ApprovalDecision::Approve,
        approval_principal: PrincipalId::try_from("approver-1").unwrap(),
        auth_method: ApprovalAuthMethod::WebAuthnUv,
        approval_key_id: KeyId::try_from("role-05").unwrap(),
        issued_at: UnixMillis::new(1_100),
        expires_at: UnixMillis::new(2_900),
        receipt_nonce: Nonce32::new([0x6a; 32]),
    };
    let payload = minicbor::to_vec(&unsigned).unwrap();
    minicbor::to_vec(ApprovalReceiptV1 {
        unsigned,
        signature: signature(domain, &payload, 5),
    })
    .unwrap()
}

#[test]
fn ingress_signature_binds_principal_request_and_nonce() {
    let policy = producer_policy();
    let encoded = encoded_ingress(INGRESS_DOMAIN);
    let verified = policy
        .verify_ingress(&encoded, support::unix_now())
        .unwrap();
    assert_eq!(verified.principal().as_str(), "principal-1");
    assert_eq!(verified.request_digest(), Digest32::new([0x21; 32]));
    assert_eq!(verified.nonce(), Nonce32::new([0x22; 32]));

    let mut mutated: SignedIngressEnvelopeV1 = minicbor::decode(&encoded).unwrap();
    mutated.unsigned.request_digest = Digest32::new([0xff; 32]);
    assert_eq!(
        policy
            .verify_ingress(&minicbor::to_vec(mutated).unwrap(), support::unix_now())
            .unwrap_err()
            .code(),
        StableCode::AttestationInvalidSignature
    );
}

#[test]
fn producer_verifiers_select_all_domains_and_authority_roles_internally() {
    let policy = producer_policy();
    let now = support::unix_now();

    assert!(policy
        .verify_ingress(&encoded_ingress(INGRESS_DOMAIN), now)
        .is_ok());
    assert!(policy
        .verify_planner_attestation(&encoded_planner(PLANNER_DOMAIN), now)
        .is_ok());
    assert!(policy
        .verify_registry_snapshot(&encoded_registry(REGISTRY_DOMAIN), now)
        .is_ok());
    assert!(policy
        .verify_ontology_snapshot(&encoded_ontology_snapshot(ONTOLOGY_SNAPSHOT_DOMAIN), now,)
        .is_ok());
    assert!(policy
        .verify_ontology_event(&encoded_ontology_event(ONTOLOGY_EVENT_DOMAIN), now)
        .is_ok());
    assert!(policy
        .verify_validator_attestation(&encoded_validator(VALIDATOR_DOMAIN), now)
        .is_ok());
    assert!(policy
        .verify_approval_receipt(&encoded_approval_receipt(APPROVAL_RECEIPT_DOMAIN), now)
        .is_ok());

    assert_eq!(
        policy
            .verify_ingress(&encoded_ingress(PLANNER_DOMAIN), now)
            .unwrap_err()
            .code(),
        StableCode::AttestationInvalidSignature
    );
    assert_eq!(
        policy
            .verify_planner_attestation(&encoded_planner(INGRESS_DOMAIN), now)
            .unwrap_err()
            .code(),
        StableCode::AttestationInvalidSignature
    );
    assert_eq!(
        policy
            .verify_registry_snapshot(&encoded_registry(ONTOLOGY_SNAPSHOT_DOMAIN), now)
            .unwrap_err()
            .code(),
        StableCode::RegistryInvalidSignature
    );
    assert_eq!(
        policy
            .verify_ontology_snapshot(&encoded_ontology_snapshot(ONTOLOGY_EVENT_DOMAIN), now)
            .unwrap_err()
            .code(),
        StableCode::OntologyInvalidSignature
    );
    assert_eq!(
        policy
            .verify_ontology_event(&encoded_ontology_event(ONTOLOGY_SNAPSHOT_DOMAIN), now)
            .unwrap_err()
            .code(),
        StableCode::OntologyInvalidSignature
    );
    assert_eq!(
        policy
            .verify_validator_attestation(&encoded_validator(REGISTRY_DOMAIN), now)
            .unwrap_err()
            .code(),
        StableCode::AttestationInvalidSignature
    );
    assert_eq!(
        policy
            .verify_approval_receipt(&encoded_approval_receipt(APPROVAL_ENVELOPE_DOMAIN), now,)
            .unwrap_err()
            .code(),
        StableCode::ApprovalInvalidSignature
    );
}

#[test]
fn producer_artifacts_enforce_time_binding_and_canonical_bytes() {
    let policy = producer_policy();
    let encoded = encoded_ingress(INGRESS_DOMAIN);

    for now in [999, 3_000] {
        assert_eq!(
            policy
                .verify_ingress(&encoded, UnixMillis::new(now))
                .unwrap_err()
                .code(),
            StableCode::AttestationExpired
        );
    }

    let mut trailing = encoded;
    trailing.push(0);
    assert_eq!(
        policy
            .verify_ingress(&trailing, support::unix_now())
            .unwrap_err()
            .code(),
        StableCode::ProtocolMalformedCbor
    );
}

#[test]
fn validator_attestation_is_not_a_bare_verdict() {
    let policy = producer_policy();
    let verified = policy
        .verify_validator_attestation(&encoded_validator(VALIDATOR_DOMAIN), support::unix_now())
        .unwrap();
    assert_eq!(verified.pending(), pending_handle());
    assert_eq!(verified.argument_digest(), Digest32::new([0x53; 32]));
    assert_eq!(verified.validator_version().as_str(), "validator-1");
    assert_eq!(verified.verdict(), ValidatorVerdictV1::Pass);
    assert_eq!(verified.public_reason(), StableCode::PolicyDenied);
    assert!(verified.expires_at().get() > verified.issued_at().get());
}

#[test]
fn producer_role_mismatch_never_falls_back_to_a_caller_key() {
    let policy = producer_policy();
    let mut ingress: SignedIngressEnvelopeV1 =
        minicbor::decode(&encoded_ingress(INGRESS_DOMAIN)).unwrap();
    ingress.key_id = KeyId::try_from("role-01").unwrap();
    let payload = minicbor::to_vec(&ingress.unsigned).unwrap();
    ingress.signature = signature(INGRESS_DOMAIN, &payload, 1);

    assert_eq!(
        policy
            .verify_ingress(&minicbor::to_vec(ingress).unwrap(), support::unix_now())
            .unwrap_err()
            .code(),
        StableCode::AttestationInvalidSignature
    );
}

fn with_trailing_byte(mut bytes: Vec<u8>) -> Vec<u8> {
    bytes.push(0);
    bytes
}

#[test]
fn every_producer_entry_point_requires_whole_artifact_canonical_bytes() {
    let policy = producer_policy();
    let now = support::unix_now();
    assert_eq!(
        policy
            .verify_planner_attestation(&with_trailing_byte(encoded_planner(PLANNER_DOMAIN)), now,)
            .unwrap_err()
            .code(),
        StableCode::ProtocolMalformedCbor
    );
    assert_eq!(
        policy
            .verify_registry_snapshot(&with_trailing_byte(encoded_registry(REGISTRY_DOMAIN)), now,)
            .unwrap_err()
            .code(),
        StableCode::ProtocolMalformedCbor
    );
    assert_eq!(
        policy
            .verify_ontology_snapshot(
                &with_trailing_byte(encoded_ontology_snapshot(ONTOLOGY_SNAPSHOT_DOMAIN)),
                now,
            )
            .unwrap_err()
            .code(),
        StableCode::ProtocolMalformedCbor
    );
    assert_eq!(
        policy
            .verify_ontology_event(
                &with_trailing_byte(encoded_ontology_event(ONTOLOGY_EVENT_DOMAIN)),
                now,
            )
            .unwrap_err()
            .code(),
        StableCode::ProtocolMalformedCbor
    );
    assert_eq!(
        policy
            .verify_validator_attestation(
                &with_trailing_byte(encoded_validator(VALIDATOR_DOMAIN)),
                now,
            )
            .unwrap_err()
            .code(),
        StableCode::ProtocolMalformedCbor
    );
    assert_eq!(
        policy
            .verify_approval_receipt(
                &with_trailing_byte(encoded_approval_receipt(APPROVAL_RECEIPT_DOMAIN)),
                now,
            )
            .unwrap_err()
            .code(),
        StableCode::ProtocolMalformedCbor
    );
}

#[test]
fn planner_validator_and_receipt_identity_fields_are_signed_and_bound() {
    let policy = producer_policy();
    let now = support::unix_now();

    let mut planner: SignedPlannerAttestationV1 =
        minicbor::decode(&encoded_planner(PLANNER_DOMAIN)).unwrap();
    planner.planner_id = PlannerId::try_from("other-planner").unwrap();
    planner.signature = signature(PLANNER_DOMAIN, &planner_payload(&planner), 1);
    assert_eq!(
        policy
            .verify_planner_attestation(&minicbor::to_vec(planner).unwrap(), now)
            .unwrap_err()
            .code(),
        StableCode::AttestationBindingMismatch
    );

    let mut validator: SignedValidatorAttestationV1 =
        minicbor::decode(&encoded_validator(VALIDATOR_DOMAIN)).unwrap();
    validator.validator_id = ValidatorId::try_from("other-validator").unwrap();
    validator.signature = signature(VALIDATOR_DOMAIN, &validator_payload(&validator), 4);
    assert_eq!(
        policy
            .verify_validator_attestation(&minicbor::to_vec(validator).unwrap(), now)
            .unwrap_err()
            .code(),
        StableCode::AttestationBindingMismatch
    );

    let mut receipt: ApprovalReceiptV1 =
        minicbor::decode(&encoded_approval_receipt(APPROVAL_RECEIPT_DOMAIN)).unwrap();
    receipt.unsigned.challenge.policy_version = 8;
    let payload = minicbor::to_vec(&receipt.unsigned).unwrap();
    receipt.signature = signature(APPROVAL_RECEIPT_DOMAIN, &payload, 5);
    assert_eq!(
        policy
            .verify_approval_receipt(&minicbor::to_vec(receipt).unwrap(), now)
            .unwrap_err()
            .code(),
        StableCode::ApprovalBindingMismatch
    );
}

#[test]
fn every_producer_time_window_is_half_open() {
    let policy = producer_policy();
    for now in [UnixMillis::new(999), UnixMillis::new(3_000)] {
        assert_eq!(
            policy
                .verify_planner_attestation(&encoded_planner(PLANNER_DOMAIN), now)
                .unwrap_err()
                .code(),
            StableCode::AttestationExpired
        );
        assert_eq!(
            policy
                .verify_registry_snapshot(&encoded_registry(REGISTRY_DOMAIN), now)
                .unwrap_err()
                .code(),
            StableCode::AttestationExpired
        );
        assert_eq!(
            policy
                .verify_ontology_snapshot(
                    &encoded_ontology_snapshot(ONTOLOGY_SNAPSHOT_DOMAIN),
                    now,
                )
                .unwrap_err()
                .code(),
            StableCode::AttestationExpired
        );
        assert_eq!(
            policy
                .verify_ontology_event(&encoded_ontology_event(ONTOLOGY_EVENT_DOMAIN), now)
                .unwrap_err()
                .code(),
            StableCode::AttestationExpired
        );
        assert_eq!(
            policy
                .verify_validator_attestation(&encoded_validator(VALIDATOR_DOMAIN), now)
                .unwrap_err()
                .code(),
            StableCode::AttestationExpired
        );
        assert_eq!(
            policy
                .verify_approval_receipt(&encoded_approval_receipt(APPROVAL_RECEIPT_DOMAIN), now,)
                .unwrap_err()
                .code(),
            StableCode::AttestationExpired
        );
    }
}

#[test]
fn approval_challenge_and_receipt_obey_the_verified_policy_ttls() {
    let policy = producer_policy_with_ttls(1, 1);
    assert_eq!(
        policy
            .verify_approval_receipt(
                &encoded_approval_receipt(APPROVAL_RECEIPT_DOMAIN),
                support::unix_now(),
            )
            .unwrap_err()
            .code(),
        StableCode::ApprovalBindingMismatch
    );
}

#[test]
fn producer_nonce_and_session_bindings_reject_all_zero_values() {
    let policy = producer_policy();
    let now = support::unix_now();

    for mutate in [
        |value: &mut SignedIngressEnvelopeV1| value.unsigned.nonce = Nonce32::new([0; 32]),
        |value: &mut SignedIngressEnvelopeV1| {
            value.unsigned.authority_session_id = Nonce32::new([0; 32])
        },
    ] {
        let mut value: SignedIngressEnvelopeV1 =
            minicbor::decode(&encoded_ingress(INGRESS_DOMAIN)).unwrap();
        mutate(&mut value);
        let payload = minicbor::to_vec(&value.unsigned).unwrap();
        value.signature = signature(INGRESS_DOMAIN, &payload, 0);
        assert_eq!(
            policy
                .verify_ingress(&minicbor::to_vec(value).unwrap(), now)
                .unwrap_err()
                .code(),
            StableCode::AttestationBindingMismatch
        );
    }

    let mut planner: SignedPlannerAttestationV1 =
        minicbor::decode(&encoded_planner(PLANNER_DOMAIN)).unwrap();
    planner.nonce = Nonce32::new([0; 32]);
    planner.signature = signature(PLANNER_DOMAIN, &planner_payload(&planner), 1);
    assert_eq!(
        policy
            .verify_planner_attestation(&minicbor::to_vec(planner).unwrap(), now)
            .unwrap_err()
            .code(),
        StableCode::AttestationBindingMismatch
    );

    let mut validator: SignedValidatorAttestationV1 =
        minicbor::decode(&encoded_validator(VALIDATOR_DOMAIN)).unwrap();
    validator.nonce = Nonce32::new([0; 32]);
    validator.signature = signature(VALIDATOR_DOMAIN, &validator_payload(&validator), 4);
    assert_eq!(
        policy
            .verify_validator_attestation(&minicbor::to_vec(validator).unwrap(), now)
            .unwrap_err()
            .code(),
        StableCode::AttestationBindingMismatch
    );

    for mutate in [
        |value: &mut ApprovalReceiptV1| {
            value.unsigned.challenge.challenge_id = Nonce32::new([0; 32])
        },
        |value: &mut ApprovalReceiptV1| value.unsigned.challenge.nonce = Nonce32::new([0; 32]),
        |value: &mut ApprovalReceiptV1| value.unsigned.receipt_nonce = Nonce32::new([0; 32]),
    ] {
        let mut value: ApprovalReceiptV1 =
            minicbor::decode(&encoded_approval_receipt(APPROVAL_RECEIPT_DOMAIN)).unwrap();
        mutate(&mut value);
        let payload = minicbor::to_vec(&value.unsigned).unwrap();
        value.signature = signature(APPROVAL_RECEIPT_DOMAIN, &payload, 5);
        assert_eq!(
            policy
                .verify_approval_receipt(&minicbor::to_vec(value).unwrap(), now)
                .unwrap_err()
                .code(),
            StableCode::ApprovalBindingMismatch
        );
    }
}

#[test]
fn ontology_snapshot_obeys_the_verified_policy_entry_limit() {
    let policy = producer_policy_with_snapshot_limit(1);
    let mut artifact: SignedOntologySnapshotV1 =
        minicbor::decode(&encoded_ontology_snapshot(ONTOLOGY_SNAPSHOT_DOMAIN)).unwrap();
    artifact.unsigned.entries.push(OntologyEntryV1 {
        constraint_id: "constraint-01".try_into().unwrap(),
        tool: ToolName::try_from("tool-01").unwrap(),
        effect: OntologyEffectV1::Allow,
        validator_id: None,
    });
    let payload = minicbor::to_vec(&artifact.unsigned).unwrap();
    artifact.signature = signature(ONTOLOGY_SNAPSHOT_DOMAIN, &payload, 3);
    assert_eq!(
        policy
            .verify_ontology_snapshot(&minicbor::to_vec(artifact).unwrap(), support::unix_now())
            .unwrap_err()
            .code(),
        StableCode::PolicyLimitExceeded
    );
}
