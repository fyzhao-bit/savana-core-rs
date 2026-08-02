use ed25519_dalek::SigningKey;
use savana_kernel_protocol::v2::Digest32V2;
use savana_policy_core::v2::{
    ClosedDeclassificationPurposeV2, DeclassificationRuleSetV2, DeclassificationRuleV2,
    DeclassificationTransitionV2, DeploymentControlErrorV2, DeploymentHardLimitsV2, LeakGateDutyV2,
    OperationalTrustRootPurposeV2, OperationalTrustRootSetItemV2, OperationalTrustRootSetV2,
};
use sha2::{Digest as _, Sha256};

fn digest(byte: u8) -> Digest32V2 {
    Digest32V2::new([byte; 32])
}

fn root_and_authority() -> (OperationalTrustRootSetV2, SigningKey) {
    let installer = SigningKey::from_bytes(&[0x11; 32]);
    let authority = SigningKey::from_bytes(&[0x12; 32]);
    let member = OperationalTrustRootSetItemV2::new(
        OperationalTrustRootPurposeV2::DeclassificationAuthority,
        authority.verifying_key().to_bytes(),
        7,
        10,
        90,
    )
    .unwrap();
    let roots = OperationalTrustRootSetV2::new_declassification_signed_for_test(
        digest(0x13),
        1,
        None,
        vec![member],
        5,
        100,
        &installer,
        3,
    )
    .unwrap();
    (roots, authority)
}

fn rule(
    transition_tag: u16,
    purpose: ClosedDeclassificationPurposeV2,
    readers: Option<Vec<Digest32V2>>,
    consent_max_age_ms: Option<u64>,
) -> DeclassificationRuleV2 {
    DeclassificationRuleV2::new_for_test(
        transition_tag,
        purpose,
        digest(0x21 + transition_tag as u8),
        LeakGateDutyV2::BlocklistOnly,
        readers,
        consent_max_age_ms,
        20,
        80,
    )
    .unwrap()
}

fn replace_rule_array_with_distinct_overflow(set: &DeclassificationRuleSetV2) -> Vec<u8> {
    // The current closed vocabulary has only five valid sort keys. The decoder
    // checks the declared cardinality before decoding any rule, so this raw
    // fixture uses 65 distinct, canonically encoded, key-sorted nested rules;
    // their future-vocabulary purpose digests are deliberately never reached.
    let encoded_rules = (1_u8..=65)
        .map(|ordinal| {
            let purpose_digest = digest(ordinal);
            let mut encoder = minicbor::Encoder::new(Vec::new());
            encoder
                .array(8)
                .unwrap()
                .u16(1)
                .unwrap()
                .bytes(purpose_digest.as_bytes())
                .unwrap()
                .bytes(digest(0x80_u8.wrapping_add(ordinal)).as_bytes())
                .unwrap()
                .u16(LeakGateDutyV2::BlocklistOnly.tag())
                .unwrap()
                .array(1)
                .unwrap()
                .u16(0)
                .unwrap()
                .array(1)
                .unwrap()
                .u16(0)
                .unwrap()
                .u64(20)
                .unwrap()
                .u64(80)
                .unwrap();
            (purpose_digest, encoder.into_writer())
        })
        .collect::<Vec<_>>();
    assert_eq!(encoded_rules.len(), 65);
    assert!(encoded_rules
        .windows(2)
        .all(|pair| { pair[0].0.as_bytes() < pair[1].0.as_bytes() && pair[0].1 < pair[1].1 }));

    let mut decoder = minicbor::Decoder::new(set.canonical_bytes());
    assert_eq!(decoder.array().unwrap(), Some(3));
    assert_eq!(decoder.array().unwrap(), Some(8));
    decoder.u16().unwrap();
    decoder.bytes().unwrap();
    decoder.u64().unwrap();
    decoder.skip().unwrap();
    let rules_start = decoder.position();
    let original_count = decoder.array().unwrap().unwrap();
    for _ in 0..original_count {
        decoder.skip().unwrap();
    }
    let rules_end = decoder.position();

    let mut replacement = minicbor::Encoder::new(Vec::new());
    replacement.array(65).unwrap();
    for (_, rule) in encoded_rules {
        replacement.writer_mut().extend_from_slice(&rule);
    }
    let mut bytes = set.canonical_bytes().to_vec();
    bytes.splice(rules_start..rules_end, replacement.into_writer());
    bytes
}

fn nested_noncanonical_rule_mutations(set: &DeclassificationRuleSetV2) -> [Vec<u8>; 3] {
    let mut decoder = minicbor::Decoder::new(set.canonical_bytes());
    assert_eq!(decoder.array().unwrap(), Some(3));
    assert_eq!(decoder.array().unwrap(), Some(8));
    decoder.u16().unwrap();
    decoder.bytes().unwrap();
    decoder.u64().unwrap();
    decoder.skip().unwrap();
    assert_eq!(decoder.array().unwrap(), Some(1));
    assert_eq!(decoder.array().unwrap(), Some(8));
    let transition_tag = decoder.position();
    assert_eq!(decoder.u16().unwrap(), 1);
    decoder.bytes().unwrap();
    decoder.bytes().unwrap();
    decoder.u16().unwrap();
    assert_eq!(decoder.array().unwrap(), Some(1));
    let reader_option_tag = decoder.position();
    assert_eq!(decoder.u16().unwrap(), 0);
    assert_eq!(decoder.array().unwrap(), Some(1));
    let consent_option_tag = decoder.position();
    assert_eq!(decoder.u16().unwrap(), 0);

    [
        nonminimal_u8(set.canonical_bytes(), transition_tag, 1),
        nonminimal_u8(set.canonical_bytes(), reader_option_tag, 0),
        nonminimal_u8(set.canonical_bytes(), consent_option_tag, 0),
    ]
}

fn nonminimal_u8(canonical: &[u8], offset: usize, value: u8) -> Vec<u8> {
    assert_eq!(canonical[offset], value);
    let mut mutated = canonical.to_vec();
    mutated.splice(offset..=offset, [0x18, value]);
    mutated
}

#[test]
fn signed_rule_set_round_trips_and_binds_closed_rules_to_root_generation() {
    let (roots, authority) = root_and_authority();
    let rules = vec![
        rule(
            1,
            ClosedDeclassificationPurposeV2::AgentIngressMasking,
            None,
            None,
        ),
        rule(
            5,
            ClosedDeclassificationPurposeV2::FinalRelease,
            Some(vec![digest(0x41), digest(0x42)]),
            Some(300_000),
        ),
    ];
    let set = DeclassificationRuleSetV2::new_signed_for_test(
        digest(0x13),
        1,
        None,
        rules,
        15,
        85,
        &roots,
        &authority,
        7,
        50,
    )
    .unwrap();
    let decoded =
        DeclassificationRuleSetV2::from_canonical_bytes(set.canonical_bytes(), &roots, 50).unwrap();

    assert_eq!(decoded.rule_set_sequence(), 1);
    assert_eq!(decoded.trust_root_set_digest(), roots.signed_digest());
    assert_eq!(decoded.authority_signature().domain_tag(), 29);
    let purpose = ClosedDeclassificationPurposeV2::FinalRelease;
    let found = decoded
        .authorizing_rule(5, purpose.purpose_digest())
        .unwrap();
    assert_eq!(found.transition_tag(), 5);
    assert_eq!(found.reader_identities(), &[digest(0x41), digest(0x42)]);
    assert_eq!(found.consent_max_age_ms(), Some(300_000));
    assert_ne!(found.rule_digest(), digest(0));

    let mut mutated = decoded.canonical_bytes().to_vec();
    *mutated.last_mut().unwrap() ^= 1;
    assert_eq!(
        DeclassificationRuleSetV2::from_canonical_bytes(&mutated, &roots, 50).unwrap_err(),
        DeploymentControlErrorV2::InvalidDeclassificationRuleSet
    );
}

#[test]
fn rules_reject_owner_reader_consent_and_window_violations() {
    assert_eq!(
        DeclassificationRuleV2::new_for_test(
            2,
            ClosedDeclassificationPurposeV2::AgentIngressMasking,
            digest(1),
            LeakGateDutyV2::BlocklistOnly,
            None,
            None,
            20,
            80,
        )
        .unwrap_err(),
        DeploymentControlErrorV2::InvalidDeclassificationRuleSet
    );
    for invalid_rule in [
        DeclassificationRuleV2::new_for_test(
            1,
            ClosedDeclassificationPurposeV2::AgentIngressMasking,
            digest(1),
            LeakGateDutyV2::BlocklistOnly,
            Some(vec![digest(2)]),
            None,
            20,
            80,
        ),
        DeclassificationRuleV2::new_for_test(
            5,
            ClosedDeclassificationPurposeV2::FinalRelease,
            digest(1),
            LeakGateDutyV2::BlocklistOnly,
            Some(Vec::new()),
            Some(300_000),
            20,
            80,
        ),
        DeclassificationRuleV2::new_for_test(
            4,
            ClosedDeclassificationPurposeV2::ExecutionHandoff,
            digest(1),
            LeakGateDutyV2::BlocklistOnly,
            Some(vec![digest(2)]),
            Some(1),
            20,
            80,
        ),
        DeclassificationRuleV2::new_for_test(
            5,
            ClosedDeclassificationPurposeV2::FinalRelease,
            digest(1),
            LeakGateDutyV2::BlocklistOnly,
            Some(vec![digest(2)]),
            Some(300_001),
            20,
            80,
        ),
    ] {
        assert_eq!(
            invalid_rule.unwrap_err(),
            DeploymentControlErrorV2::InvalidDeclassificationRuleSet
        );
    }
}

#[test]
fn rule_set_rejects_wrong_root_time_order_and_predecessor() {
    let (roots, authority) = root_and_authority();
    let rule = rule(
        1,
        ClosedDeclassificationPurposeV2::AgentIngressMasking,
        None,
        None,
    );
    let first = DeclassificationRuleSetV2::new_signed_for_test(
        digest(0x13),
        1,
        None,
        vec![rule.clone()],
        15,
        85,
        &roots,
        &authority,
        7,
        50,
    )
    .unwrap();
    assert_eq!(
        DeclassificationRuleSetV2::from_canonical_bytes(first.canonical_bytes(), &roots, 9)
            .unwrap_err(),
        DeploymentControlErrorV2::InvalidDeclassificationRuleSet
    );
    let second = DeclassificationRuleSetV2::new_signed_for_test(
        digest(0x13),
        2,
        Some(first.signed_digest()),
        vec![rule],
        15,
        85,
        &roots,
        &authority,
        7,
        50,
    )
    .unwrap();
    second.validate_predecessor(Some(&first)).unwrap();
    assert_eq!(
        second.validate_predecessor(None).unwrap_err(),
        DeploymentControlErrorV2::InvalidDeclassificationRuleSet
    );

    let transition = DeclassificationTransitionV2::BuildFinalRelease {
        sink_identity_digest: digest(0x41),
    };
    assert_eq!(transition.tag(), 5);
}

#[test]
fn canonical_shape_payload_signed_digest_and_signature_domain_are_exact() {
    let (roots, authority) = root_and_authority();
    let set = DeclassificationRuleSetV2::new_signed_for_test(
        digest(0x13),
        1,
        None,
        vec![rule(
            1,
            ClosedDeclassificationPurposeV2::AgentIngressMasking,
            None,
            None,
        )],
        15,
        85,
        &roots,
        &authority,
        7,
        50,
    )
    .unwrap();
    let canonical = set.canonical_bytes();
    let mut decoder = minicbor::Decoder::new(canonical);
    assert_eq!(decoder.array().unwrap(), Some(3));
    let payload_start = decoder.position();
    decoder.skip().unwrap();
    let payload_end = decoder.position();
    let payload_digest = domain_hash(
        b"savana.declassification-rule-set.v2.payload\0",
        &canonical[payload_start..payload_end],
    );
    assert_eq!(set.payload_digest(), payload_digest);
    assert_eq!(
        set.signed_digest(),
        domain_hash(b"savana.declassification-rule-set.v2.signed\0", canonical)
    );
    assert_eq!(set.authority_signature().domain_tag(), 29);

    let mut wrong_shape = canonical.to_vec();
    wrong_shape[0] = 0x82;
    assert_eq!(
        DeclassificationRuleSetV2::from_canonical_bytes(&wrong_shape, &roots, 50).unwrap_err(),
        DeploymentControlErrorV2::InvalidDeclassificationRuleSet
    );
    let mut trailing = canonical.to_vec();
    trailing.push(0);
    assert_eq!(
        DeclassificationRuleSetV2::from_canonical_bytes(&trailing, &roots, 50).unwrap_err(),
        DeploymentControlErrorV2::InvalidDeclassificationRuleSet
    );

    let mut wrong_payload_digest = canonical.to_vec();
    let offset = wrong_payload_digest
        .windows(32)
        .position(|window| window == set.payload_digest().as_bytes())
        .unwrap();
    wrong_payload_digest[offset] ^= 1;
    assert_eq!(
        DeclassificationRuleSetV2::from_canonical_bytes(&wrong_payload_digest, &roots, 50)
            .unwrap_err(),
        DeploymentControlErrorV2::InvalidDeclassificationRuleSet
    );

    let mut wrong_signature_domain = canonical.to_vec();
    let domain_offset = wrong_signature_domain
        .windows(2)
        .rposition(|window| window == [0x18, 0x1d])
        .unwrap();
    wrong_signature_domain[domain_offset + 1] = 0x1e;
    assert_eq!(
        DeclassificationRuleSetV2::from_canonical_bytes(&wrong_signature_domain, &roots, 50)
            .unwrap_err(),
        DeploymentControlErrorV2::InvalidDeclassificationRuleSet
    );

    for nested_noncanonical in nested_noncanonical_rule_mutations(&set) {
        assert_eq!(
            DeclassificationRuleSetV2::from_canonical_bytes(&nested_noncanonical, &roots, 50)
                .unwrap_err(),
            DeploymentControlErrorV2::InvalidDeclassificationRuleSet
        );
    }

    let unauthorized = SigningKey::from_bytes(&[0x44; 32]);
    assert_eq!(
        DeclassificationRuleSetV2::new_signed_for_test(
            digest(0x13),
            1,
            None,
            vec![rule(
                1,
                ClosedDeclassificationPurposeV2::AgentIngressMasking,
                None,
                None,
            )],
            15,
            85,
            &roots,
            &unauthorized,
            7,
            50,
        )
        .unwrap_err(),
        DeploymentControlErrorV2::InvalidDeclassificationRuleSet
    );
}

#[test]
fn zero_duplicate_unsorted_and_closed_shape_inputs_are_refused() {
    assert_eq!(
        DeclassificationRuleV2::new_for_test(
            1,
            ClosedDeclassificationPurposeV2::AgentIngressMasking,
            Digest32V2::new([0; 32]),
            LeakGateDutyV2::BlocklistOnly,
            None,
            None,
            20,
            80,
        )
        .unwrap_err(),
        DeploymentControlErrorV2::InvalidDeclassificationRuleSet
    );
    for readers in [
        vec![digest(0x42), digest(0x41)],
        vec![digest(0x41), digest(0x41)],
        vec![Digest32V2::new([0; 32])],
    ] {
        assert_eq!(
            DeclassificationRuleV2::new_for_test(
                5,
                ClosedDeclassificationPurposeV2::FinalRelease,
                digest(1),
                LeakGateDutyV2::BlocklistOnly,
                Some(readers),
                Some(1),
                20,
                80,
            )
            .unwrap_err(),
            DeploymentControlErrorV2::InvalidDeclassificationRuleSet
        );
    }
    assert_eq!(
        DeclassificationRuleV2::new_for_test(
            1,
            ClosedDeclassificationPurposeV2::FinalRelease,
            digest(1),
            LeakGateDutyV2::BlocklistOnly,
            Some(vec![digest(2)]),
            Some(1),
            20,
            80,
        )
        .unwrap_err(),
        DeploymentControlErrorV2::InvalidDeclassificationRuleSet
    );

    let (roots, authority) = root_and_authority();
    let first = rule(
        1,
        ClosedDeclassificationPurposeV2::AgentIngressMasking,
        None,
        None,
    );
    let last = rule(
        5,
        ClosedDeclassificationPurposeV2::FinalRelease,
        Some(vec![digest(0x41)]),
        Some(1),
    );
    for invalid_rules in [
        vec![first.clone(), first.clone()],
        vec![last, first.clone()],
    ] {
        assert_eq!(
            DeclassificationRuleSetV2::new_signed_for_test(
                digest(0x13),
                1,
                None,
                invalid_rules,
                15,
                85,
                &roots,
                &authority,
                7,
                50,
            )
            .unwrap_err(),
            DeploymentControlErrorV2::InvalidDeclassificationRuleSet
        );
    }
    assert_eq!(
        DeclassificationRuleSetV2::new_signed_for_test(
            digest(0x13),
            0,
            None,
            vec![first.clone()],
            15,
            85,
            &roots,
            &authority,
            7,
            50,
        )
        .unwrap_err(),
        DeploymentControlErrorV2::InvalidDeclassificationRuleSet
    );
    assert_eq!(
        DeclassificationRuleSetV2::new_signed_for_test(
            digest(0x13),
            2,
            Some(Digest32V2::new([0; 32])),
            vec![first],
            15,
            85,
            &roots,
            &authority,
            7,
            50,
        )
        .unwrap_err(),
        DeploymentControlErrorV2::InvalidDeclassificationRuleSet
    );
}

#[test]
fn set_rule_windows_and_compiled_rule_reader_limits_are_enforced() {
    let (roots, authority) = root_and_authority();
    let base = rule(
        1,
        ClosedDeclassificationPurposeV2::AgentIngressMasking,
        None,
        None,
    );
    assert_eq!(
        DeclassificationRuleSetV2::new_signed_for_test(
            digest(0x13),
            1,
            None,
            vec![base.clone()],
            85,
            85,
            &roots,
            &authority,
            7,
            50,
        )
        .unwrap_err(),
        DeploymentControlErrorV2::InvalidDeclassificationRuleSet
    );
    assert_eq!(
        DeclassificationRuleSetV2::new_signed_for_test(
            digest(0x13),
            1,
            None,
            vec![base.clone()],
            25,
            75,
            &roots,
            &authority,
            7,
            50,
        )
        .unwrap_err(),
        DeploymentControlErrorV2::InvalidDeclassificationRuleSet
    );
    assert_eq!(
        DeclassificationRuleV2::new_for_test(
            1,
            ClosedDeclassificationPurposeV2::AgentIngressMasking,
            digest(1),
            LeakGateDutyV2::BlocklistOnly,
            None,
            None,
            20,
            20,
        )
        .unwrap_err(),
        DeploymentControlErrorV2::InvalidDeclassificationRuleSet
    );

    let too_many_readers = (1..=DeploymentHardLimitsV2::compiled().max_declassification_readers()
        + 1)
        .map(|value| digest(u8::try_from(value).unwrap()))
        .collect();
    assert_eq!(
        DeclassificationRuleV2::new_for_test(
            5,
            ClosedDeclassificationPurposeV2::FinalRelease,
            digest(1),
            LeakGateDutyV2::BlocklistOnly,
            Some(too_many_readers),
            Some(1),
            20,
            80,
        )
        .unwrap_err(),
        DeploymentControlErrorV2::InvalidDeclassificationRuleSet
    );
}

#[test]
fn rule_count_overflow_uses_sixty_five_distinct_sorted_nested_rules() {
    let (roots, authority) = root_and_authority();
    assert_eq!(
        DeploymentHardLimitsV2::compiled().max_declassification_rules(),
        64,
        "this vector isolates the first out-of-bounds cardinality at 65"
    );
    let valid = DeclassificationRuleSetV2::new_signed_for_test(
        digest(0x13),
        1,
        None,
        vec![rule(
            1,
            ClosedDeclassificationPurposeV2::AgentIngressMasking,
            None,
            None,
        )],
        15,
        85,
        &roots,
        &authority,
        7,
        50,
    )
    .unwrap();
    let too_many_distinct_sorted_rules = replace_rule_array_with_distinct_overflow(&valid);
    assert_eq!(
        DeclassificationRuleSetV2::from_canonical_bytes(
            &too_many_distinct_sorted_rules,
            &roots,
            50
        )
        .unwrap_err(),
        DeploymentControlErrorV2::InvalidDeclassificationRuleSet
    );
}

#[test]
fn predecessor_chain_and_wrong_trust_root_purpose_are_refused() {
    let (roots, authority) = root_and_authority();
    let base = rule(
        1,
        ClosedDeclassificationPurposeV2::AgentIngressMasking,
        None,
        None,
    );
    let first = DeclassificationRuleSetV2::new_signed_for_test(
        digest(0x13),
        1,
        None,
        vec![base.clone()],
        15,
        85,
        &roots,
        &authority,
        7,
        50,
    )
    .unwrap();
    let fork = DeclassificationRuleSetV2::new_signed_for_test(
        digest(0x13),
        2,
        Some(digest(0x66)),
        vec![base],
        15,
        85,
        &roots,
        &authority,
        7,
        50,
    )
    .unwrap();
    assert_eq!(
        fork.validate_predecessor(Some(&first)).unwrap_err(),
        DeploymentControlErrorV2::InvalidDeclassificationRuleSet
    );

    let installer = SigningKey::from_bytes(&[0x70; 32]);
    let deployment_authority = SigningKey::from_bytes(&[0x71; 32]);
    let rollback_authority = SigningKey::from_bytes(&[0x72; 32]);
    let wrong_purpose_root = OperationalTrustRootSetV2::new_deployment_signed_for_test(
        digest(0x13),
        1,
        None,
        vec![
            OperationalTrustRootSetItemV2::new(
                OperationalTrustRootPurposeV2::DeploymentAuthorization,
                deployment_authority.verifying_key().to_bytes(),
                7,
                10,
                90,
            )
            .unwrap(),
            OperationalTrustRootSetItemV2::new(
                OperationalTrustRootPurposeV2::RollbackAuthorization,
                rollback_authority.verifying_key().to_bytes(),
                7,
                10,
                90,
            )
            .unwrap(),
        ],
        5,
        100,
        &installer,
        3,
    )
    .unwrap();
    assert_eq!(
        DeclassificationRuleSetV2::from_canonical_bytes(
            first.canonical_bytes(),
            &wrong_purpose_root,
            50
        )
        .unwrap_err(),
        DeploymentControlErrorV2::InvalidDeclassificationRuleSet
    );
}

#[test]
fn explicit_lower_sequence_rule_set_is_rejected_as_rollback() {
    let (roots, authority) = root_and_authority();
    let first = DeclassificationRuleSetV2::new_signed_for_test(
        digest(0x13),
        1,
        None,
        vec![rule(
            1,
            ClosedDeclassificationPurposeV2::AgentIngressMasking,
            None,
            None,
        )],
        15,
        85,
        &roots,
        &authority,
        7,
        50,
    )
    .unwrap();
    let lower_sequence = DeclassificationRuleSetV2::new_signed_for_test(
        digest(0x13),
        2,
        Some(first.signed_digest()),
        vec![rule(
            1,
            ClosedDeclassificationPurposeV2::AgentIngressMasking,
            None,
            None,
        )],
        15,
        85,
        &roots,
        &authority,
        7,
        50,
    )
    .unwrap();
    let active_higher_sequence = DeclassificationRuleSetV2::new_signed_for_test(
        digest(0x13),
        3,
        Some(lower_sequence.signed_digest()),
        vec![rule(
            1,
            ClosedDeclassificationPurposeV2::AgentIngressMasking,
            None,
            None,
        )],
        15,
        85,
        &roots,
        &authority,
        7,
        50,
    )
    .unwrap();
    assert_eq!(
        lower_sequence
            .validate_predecessor(Some(&active_higher_sequence))
            .unwrap_err(),
        DeploymentControlErrorV2::InvalidDeclassificationRuleSet,
        "an explicit lower-sequence set must not roll back a newer predecessor"
    );
}

fn domain_hash(domain: &[u8], bytes: &[u8]) -> Digest32V2 {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(bytes);
    Digest32V2::new(hasher.finalize().into())
}
