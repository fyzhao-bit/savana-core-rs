mod support;

use savana_kernel_protocol::{HardLimits, StableCode, UnixMillis};

type Mutation = Box<dyn Fn(&mut support::TestPolicy)>;
type MutationCase = (&'static str, Mutation);
type CodedMutationCase = (&'static str, StableCode, Mutation);

fn assert_rejected(policy: &support::TestPolicy, now: u64, expected: StableCode, label: &str) {
    let (bundle, signature) = support::signed(policy);
    let error = support::verifier()
        .verify(&bundle, &signature, UnixMillis::new(now))
        .expect_err(label);
    assert_eq!(error.code(), expected, "{label}");
}

#[test]
fn policy_identity_and_time_boundaries_are_exact() {
    let policy = support::valid_policy(7, 3);
    for now in [policy.issued_at, policy.expires_at - 1] {
        let (bundle, signature) = support::signed(&policy);
        support::verifier()
            .verify(&bundle, &signature, UnixMillis::new(now))
            .unwrap();
    }

    assert_rejected(
        &policy,
        policy.issued_at - 1,
        StableCode::PolicyNotYetValid,
        "future policy",
    );
    assert_rejected(
        &policy,
        policy.expires_at,
        StableCode::PolicyExpired,
        "expired policy",
    );
}

#[test]
fn schema_protocol_and_scalar_rules_are_enforced() {
    let base = support::valid_policy(7, 3);
    let cases: Vec<CodedMutationCase> = vec![
        (
            "schema",
            StableCode::ProtocolUnsupportedVersion,
            Box::new(|p| p.schema_version = 2),
        ),
        (
            "protocol major",
            StableCode::ProtocolUnsupportedVersion,
            Box::new(|p| p.protocol.major = 2),
        ),
        (
            "protocol minimum",
            StableCode::ProtocolUnsupportedVersion,
            Box::new(|p| p.protocol.minimum_minor = 1),
        ),
        (
            "zero policy version",
            StableCode::ProtocolMalformedCbor,
            Box::new(|p| p.policy_version = 0),
        ),
        (
            "zero key epoch",
            StableCode::PolicyInvalidSignature,
            Box::new(|p| p.key_epoch = 0),
        ),
        (
            "inverted lifetime",
            StableCode::ProtocolMalformedCbor,
            Box::new(|p| p.expires_at = p.issued_at),
        ),
        (
            "challenge ttl zero",
            StableCode::ProtocolMalformedCbor,
            Box::new(|p| p.release.challenge_ttl_seconds = 0),
        ),
        (
            "challenge ttl high",
            StableCode::PolicyLimitExceeded,
            Box::new(|p| p.release.challenge_ttl_seconds = 121),
        ),
        (
            "receipt ttl zero",
            StableCode::ProtocolMalformedCbor,
            Box::new(|p| p.release.receipt_ttl_seconds = 0),
        ),
        (
            "receipt ttl high",
            StableCode::PolicyLimitExceeded,
            Box::new(|p| p.release.receipt_ttl_seconds = 121),
        ),
        (
            "unauthenticated release",
            StableCode::ProtocolMalformedCbor,
            Box::new(|p| p.release.require_authenticated_user_assertion = false),
        ),
        (
            "nonconsuming release",
            StableCode::ProtocolMalformedCbor,
            Box::new(|p| p.release.consume_vault_on_success = false),
        ),
        (
            "missing attestation allowed",
            StableCode::ProtocolMalformedCbor,
            Box::new(|p| p.sink.deny_on_missing_attestation = false),
        ),
        (
            "snapshot entries zero",
            StableCode::ProtocolMalformedCbor,
            Box::new(|p| p.ontology.max_snapshot_entries = 0),
        ),
        (
            "snapshot entries high",
            StableCode::PolicyLimitExceeded,
            Box::new(|p| p.ontology.max_snapshot_entries = 100_001),
        ),
        (
            "constraints scalar zero",
            StableCode::ProtocolMalformedCbor,
            Box::new(|p| p.ontology.max_constraints_per_tool = 0),
        ),
        (
            "constraints scalar high",
            StableCode::PolicyLimitExceeded,
            Box::new(|p| p.ontology.max_constraints_per_tool = 65),
        ),
        (
            "attempt maximum zero",
            StableCode::ProtocolMalformedCbor,
            Box::new(|p| p.attempts.limits[0].maximum_per_run = 0),
        ),
        (
            "attempt maximum high",
            StableCode::PolicyLimitExceeded,
            Box::new(|p| p.attempts.limits[0].maximum_per_run = 65_537),
        ),
    ];

    for (label, expected, mutate) in cases {
        let mut policy = base.clone();
        mutate(&mut policy);
        assert_rejected(&policy, support::NOW, expected, label);
    }
}

#[test]
fn resource_limits_cannot_exceed_compiled_ceilings() {
    let mut policy = support::valid_policy(7, 3);
    policy.resources.frame_bytes = HardLimits::COMPILED.frame_bytes() + 1;
    assert_rejected(
        &policy,
        support::NOW,
        StableCode::PolicyLimitExceeded,
        "resource ceiling",
    );
}

#[test]
fn authority_integrity_and_all_eight_roles_are_required() {
    let base = support::valid_policy(7, 3);

    for role in 0_u8..8 {
        let mut policy = base.clone();
        policy.authorities[usize::from(role)].revoked = true;
        assert_rejected(
            &policy,
            support::NOW,
            StableCode::ProtocolMalformedCbor,
            "missing valid role",
        );
    }

    let mutations: Vec<MutationCase> = vec![
        (
            "zero authority epoch",
            Box::new(|p| p.authorities[0].epoch = 0),
        ),
        (
            "zero authority key",
            Box::new(|p| p.authorities[0].public_key = [0; 32]),
        ),
        (
            "authority inverted lifetime",
            Box::new(|p| p.authorities[0].not_after = p.authorities[0].not_before),
        ),
        (
            "authority starts too late",
            Box::new(|p| p.authorities[0].not_before = p.issued_at + 1),
        ),
        (
            "authority expires too early",
            Box::new(|p| p.authorities[0].not_after = p.expires_at - 1),
        ),
        (
            "duplicate authority",
            Box::new(|p| p.authorities[1].key_id = p.authorities[0].key_id.clone()),
        ),
        ("unsorted authority", Box::new(|p| p.authorities.swap(0, 1))),
    ];
    for (label, mutate) in mutations {
        let mut policy = base.clone();
        mutate(&mut policy);
        assert_rejected(
            &policy,
            support::NOW,
            StableCode::ProtocolMalformedCbor,
            label,
        );
    }
}

#[test]
fn dataflow_and_attempt_references_are_closed_and_canonical() {
    let base = support::valid_policy(7, 3);
    let mutations: Vec<MutationCase> = vec![
        (
            "absent dataflow tool",
            Box::new(|p| p.dataflow.high_risk_tools[0] = "missing".to_owned()),
        ),
        (
            "duplicate dataflow tool",
            Box::new(|p| p.dataflow.no_side_effect_tools.push("tool-00".to_owned())),
        ),
        (
            "unsorted dataflow tools",
            Box::new(|p| {
                p.dataflow.no_side_effect_tools = vec!["tool-01".to_owned(), "tool-00".to_owned()]
            }),
        ),
        (
            "missing declared pair",
            Box::new(|p| {
                p.attempts.valid_pairs.pop();
            }),
        ),
        (
            "pair references absent tool",
            Box::new(|p| p.attempts.valid_pairs[1].tool = "missing".to_owned()),
        ),
        (
            "duplicate valid pair",
            Box::new(|p| {
                let pair = p.attempts.valid_pairs[0].clone();
                p.attempts.valid_pairs.insert(1, pair);
            }),
        ),
        (
            "unsorted valid pairs",
            Box::new(|p| p.attempts.valid_pairs.swap(0, 1)),
        ),
        (
            "duplicate attempt limit",
            Box::new(|p| p.attempts.limits[1].attempt = p.attempts.limits[0].attempt),
        ),
        (
            "unsorted attempt limits",
            Box::new(|p| p.attempts.limits.swap(0, 1)),
        ),
        (
            "duplicate cloud blocked",
            Box::new(|p| p.attempts.cloud_blocked = vec![3, 3]),
        ),
        (
            "unsorted cloud blocked",
            Box::new(|p| p.attempts.cloud_blocked = vec![4, 3]),
        ),
        (
            "unknown attempt tag",
            Box::new(|p| p.attempts.cloud_blocked[0] = 6),
        ),
        (
            "duplicate tool",
            Box::new(|p| p.tools[1].name = p.tools[0].name.clone()),
        ),
        ("unsorted tools", Box::new(|p| p.tools.swap(0, 1))),
    ];
    for (label, mutate) in mutations {
        let mut policy = base.clone();
        mutate(&mut policy);
        assert_rejected(
            &policy,
            support::NOW,
            StableCode::ProtocolMalformedCbor,
            label,
        );
    }
}

#[test]
fn ontology_validator_and_sink_references_are_strict() {
    let base = support::valid_policy(7, 3);
    let mutations: Vec<MutationCase> = vec![
        (
            "snapshot absent",
            Box::new(|p| p.ontology.snapshot_authority_key_ids[0] = "missing".to_owned()),
        ),
        (
            "snapshot wrong role",
            Box::new(|p| p.ontology.snapshot_authority_key_ids[0] = "role-02".to_owned()),
        ),
        (
            "duplicate snapshot",
            Box::new(|p| {
                p.ontology
                    .snapshot_authority_key_ids
                    .push("role-03".to_owned())
            }),
        ),
        (
            "unsorted snapshot",
            Box::new(|p| {
                let mut second = p.authorities[3].clone();
                second.key_id = "role-03b".to_owned();
                p.authorities.push(second);
                p.ontology.snapshot_authority_key_ids =
                    vec!["role-03b".to_owned(), "role-03".to_owned()];
            }),
        ),
        (
            "duplicate constraint",
            Box::new(|p| p.tools[0].constraint_ids.push("constraint-00".to_owned())),
        ),
        (
            "unsorted constraints",
            Box::new(|p| {
                p.tools[0].constraint_ids =
                    vec!["constraint-01".to_owned(), "constraint-00".to_owned()]
            }),
        ),
        (
            "validator absent",
            Box::new(|p| p.tools[1].validator_ids[0] = "missing".to_owned()),
        ),
        (
            "validator wrong role",
            Box::new(|p| p.tools[1].validator_ids[0] = "role-03".to_owned()),
        ),
        (
            "duplicate tool validator",
            Box::new(|p| p.tools[1].validator_ids.push("role-04".to_owned())),
        ),
        (
            "unsorted tool validators",
            Box::new(|p| {
                let mut second = p.authorities[4].clone();
                second.key_id = "role-04b".to_owned();
                p.authorities.push(second);
                p.tools[1].validator_ids = vec!["role-04b".to_owned(), "role-04".to_owned()];
            }),
        ),
        (
            "sink absent tool",
            Box::new(|p| p.sink.validator_requirements[0].tool = "missing".to_owned()),
        ),
        (
            "sink validators empty",
            Box::new(|p| p.sink.validator_requirements[0].validator_ids.clear()),
        ),
        (
            "sink validator not on tool",
            Box::new(|p| p.sink.validator_requirements[0].validator_ids[0] = "role-04x".to_owned()),
        ),
        (
            "duplicate sink requirement",
            Box::new(|p| {
                let requirement = p.sink.validator_requirements[0].clone();
                p.sink.validator_requirements.push(requirement);
            }),
        ),
        (
            "unsorted sink requirements",
            Box::new(|p| {
                p.tools[0].validator_ids = vec!["role-04".to_owned()];
                p.sink
                    .validator_requirements
                    .push(support::ValidatorRequirement {
                        tool: "tool-00".to_owned(),
                        validator_ids: vec!["role-04".to_owned()],
                    });
            }),
        ),
    ];
    for (label, mutate) in mutations {
        let mut policy = base.clone();
        mutate(&mut policy);
        assert_rejected(
            &policy,
            support::NOW,
            StableCode::ProtocolMalformedCbor,
            label,
        );
    }
}

#[test]
fn digest_sets_error_map_and_active_target_are_strict() {
    let base = support::valid_policy(7, 3);
    let cases: Vec<CodedMutationCase> = vec![
        (
            "empty release targets",
            StableCode::ProtocolMalformedCbor,
            Box::new(|p| p.release.compatible_release_target_ids.clear()),
        ),
        (
            "duplicate release target",
            StableCode::ProtocolMalformedCbor,
            Box::new(|p| p.release.compatible_release_target_ids.push([0xa0; 32])),
        ),
        (
            "unsorted release targets",
            StableCode::ProtocolMalformedCbor,
            Box::new(|p| p.release.compatible_release_target_ids = vec![[0xb0; 32], [0xa0; 32]]),
        ),
        (
            "active target missing",
            StableCode::PolicyReleaseIncompatible,
            Box::new(|p| p.release.compatible_release_target_ids = vec![[0xa1; 32]]),
        ),
        (
            "empty model digests",
            StableCode::ProtocolMalformedCbor,
            Box::new(|p| p.accepted_model_manifest_digests.clear()),
        ),
        (
            "duplicate model digest",
            StableCode::ProtocolMalformedCbor,
            Box::new(|p| p.accepted_model_manifest_digests.push([0xb0; 32])),
        ),
        (
            "unsorted model digests",
            StableCode::ProtocolMalformedCbor,
            Box::new(|p| p.accepted_model_manifest_digests = vec![[0xc0; 32], [0xb0; 32]]),
        ),
        (
            "duplicate error tag",
            StableCode::ProtocolMalformedCbor,
            Box::new(|p| p.error_map[1].policy_reason_tag = 1),
        ),
        (
            "unsorted error tags",
            StableCode::ProtocolMalformedCbor,
            Box::new(|p| p.error_map.swap(0, 1)),
        ),
    ];
    for (label, expected, mutate) in cases {
        let mut policy = base.clone();
        mutate(&mut policy);
        assert_rejected(&policy, support::NOW, expected, label);
    }
}

#[test]
fn every_structural_ceiling_is_enforced() {
    let base = support::valid_policy(7, 3);
    let cases: Vec<MutationCase> = vec![
        (
            "tools",
            Box::new(|p| p.tools = vec![p.tools[0].clone(); 257]),
        ),
        (
            "authorities",
            Box::new(|p| p.authorities = vec![p.authorities[0].clone(); 65]),
        ),
        (
            "error mappings",
            Box::new(|p| p.error_map = vec![p.error_map[0].clone(); 257]),
        ),
        (
            "model digests",
            Box::new(|p| p.accepted_model_manifest_digests = vec![[0xb0; 32]; 33]),
        ),
        (
            "tool-name set",
            Box::new(|p| p.dataflow.high_risk_tools = vec!["tool-00".to_owned(); 257]),
        ),
        (
            "valid pairs",
            Box::new(|p| p.attempts.valid_pairs = vec![p.attempts.valid_pairs[0].clone(); 1537]),
        ),
        (
            "attempt limits",
            Box::new(|p| p.attempts.limits = vec![p.attempts.limits[0].clone(); 7]),
        ),
        (
            "snapshot authorities",
            Box::new(|p| p.ontology.snapshot_authority_key_ids = vec!["role-03".to_owned(); 17]),
        ),
        (
            "validator requirements",
            Box::new(|p| {
                p.sink.validator_requirements = vec![p.sink.validator_requirements[0].clone(); 257]
            }),
        ),
        (
            "validators per tool",
            Box::new(|p| p.tools[1].validator_ids = vec!["role-04".to_owned(); 33]),
        ),
        (
            "constraints per tool",
            Box::new(|p| p.tools[0].constraint_ids = vec!["constraint-00".to_owned(); 65]),
        ),
        (
            "release targets",
            Box::new(|p| p.release.compatible_release_target_ids = vec![[0xa0; 32]; 17]),
        ),
    ];

    for (label, mutate) in cases {
        let mut policy = base.clone();
        mutate(&mut policy);
        assert_rejected(
            &policy,
            support::NOW,
            StableCode::PolicyLimitExceeded,
            label,
        );
    }
}

#[test]
fn malformed_identifiers_and_fixed_fields_are_rejected() {
    let base = support::valid_policy(7, 3);
    let mutations: Vec<MutationCase> = vec![
        (
            "control in tool",
            Box::new(|p| p.tools[0].name = "bad\0tool".to_owned()),
        ),
        (
            "overlong validator",
            Box::new(|p| p.tools[1].validator_ids[0] = "v".repeat(129)),
        ),
        (
            "unknown authority role",
            Box::new(|p| p.authorities[0].role = 8),
        ),
        ("unknown tool attempt", Box::new(|p| p.tools[0].attempt = 6)),
    ];
    for (label, mutate) in mutations {
        let mut policy = base.clone();
        mutate(&mut policy);
        assert_rejected(
            &policy,
            support::NOW,
            StableCode::ProtocolMalformedCbor,
            label,
        );
    }
}
