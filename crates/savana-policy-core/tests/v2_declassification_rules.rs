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
    assert!(DeclassificationRuleV2::new_for_test(
        1,
        ClosedDeclassificationPurposeV2::AgentIngressMasking,
        digest(1),
        LeakGateDutyV2::BlocklistOnly,
        Some(vec![digest(2)]),
        None,
        20,
        80,
    )
    .is_err());
    assert!(DeclassificationRuleV2::new_for_test(
        5,
        ClosedDeclassificationPurposeV2::FinalRelease,
        digest(1),
        LeakGateDutyV2::BlocklistOnly,
        Some(Vec::new()),
        Some(300_000),
        20,
        80,
    )
    .is_err());
    assert!(DeclassificationRuleV2::new_for_test(
        4,
        ClosedDeclassificationPurposeV2::ExecutionHandoff,
        digest(1),
        LeakGateDutyV2::BlocklistOnly,
        Some(vec![digest(2)]),
        Some(1),
        20,
        80,
    )
    .is_err());
    assert!(DeclassificationRuleV2::new_for_test(
        5,
        ClosedDeclassificationPurposeV2::FinalRelease,
        digest(1),
        LeakGateDutyV2::BlocklistOnly,
        Some(vec![digest(2)]),
        Some(300_001),
        20,
        80,
    )
    .is_err());
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
    assert!(second.validate_predecessor(None).is_err());

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
    assert!(DeclassificationRuleSetV2::from_canonical_bytes(&wrong_shape, &roots, 50).is_err());
    let mut trailing = canonical.to_vec();
    trailing.push(0);
    assert!(DeclassificationRuleSetV2::from_canonical_bytes(&trailing, &roots, 50).is_err());

    let mut wrong_payload_digest = canonical.to_vec();
    let offset = wrong_payload_digest
        .windows(32)
        .position(|window| window == set.payload_digest().as_bytes())
        .unwrap();
    wrong_payload_digest[offset] ^= 1;
    assert!(
        DeclassificationRuleSetV2::from_canonical_bytes(&wrong_payload_digest, &roots, 50).is_err()
    );

    let mut wrong_signature_domain = canonical.to_vec();
    let domain_offset = wrong_signature_domain
        .windows(2)
        .rposition(|window| window == [0x18, 0x1d])
        .unwrap();
    wrong_signature_domain[domain_offset + 1] = 0x1e;
    assert!(
        DeclassificationRuleSetV2::from_canonical_bytes(&wrong_signature_domain, &roots, 50)
            .is_err()
    );

    let unauthorized = SigningKey::from_bytes(&[0x44; 32]);
    assert!(DeclassificationRuleSetV2::new_signed_for_test(
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
    .is_err());
}

#[test]
fn zero_duplicate_unsorted_and_closed_shape_inputs_are_refused() {
    assert!(DeclassificationRuleV2::new_for_test(
        1,
        ClosedDeclassificationPurposeV2::AgentIngressMasking,
        Digest32V2::new([0; 32]),
        LeakGateDutyV2::BlocklistOnly,
        None,
        None,
        20,
        80,
    )
    .is_err());
    for readers in [
        vec![digest(0x42), digest(0x41)],
        vec![digest(0x41), digest(0x41)],
        vec![Digest32V2::new([0; 32])],
    ] {
        assert!(DeclassificationRuleV2::new_for_test(
            5,
            ClosedDeclassificationPurposeV2::FinalRelease,
            digest(1),
            LeakGateDutyV2::BlocklistOnly,
            Some(readers),
            Some(1),
            20,
            80,
        )
        .is_err());
    }
    assert!(DeclassificationRuleV2::new_for_test(
        1,
        ClosedDeclassificationPurposeV2::FinalRelease,
        digest(1),
        LeakGateDutyV2::BlocklistOnly,
        Some(vec![digest(2)]),
        Some(1),
        20,
        80,
    )
    .is_err());

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
        assert!(DeclassificationRuleSetV2::new_signed_for_test(
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
        .is_err());
    }
    assert!(DeclassificationRuleSetV2::new_signed_for_test(
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
    .is_err());
    assert!(DeclassificationRuleSetV2::new_signed_for_test(
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
    .is_err());
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
    assert!(DeclassificationRuleSetV2::new_signed_for_test(
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
    .is_err());
    assert!(DeclassificationRuleSetV2::new_signed_for_test(
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
    .is_err());
    assert!(DeclassificationRuleV2::new_for_test(
        1,
        ClosedDeclassificationPurposeV2::AgentIngressMasking,
        digest(1),
        LeakGateDutyV2::BlocklistOnly,
        None,
        None,
        20,
        20,
    )
    .is_err());

    let too_many_rules =
        vec![
            base;
            usize::try_from(DeploymentHardLimitsV2::compiled().max_declassification_rules() + 1)
                .unwrap()
        ];
    assert!(DeclassificationRuleSetV2::new_signed_for_test(
        digest(0x13),
        1,
        None,
        too_many_rules,
        15,
        85,
        &roots,
        &authority,
        7,
        50,
    )
    .is_err());
    let too_many_readers = (1..=DeploymentHardLimitsV2::compiled().max_declassification_readers()
        + 1)
        .map(|value| digest(u8::try_from(value).unwrap()))
        .collect();
    assert!(DeclassificationRuleV2::new_for_test(
        5,
        ClosedDeclassificationPurposeV2::FinalRelease,
        digest(1),
        LeakGateDutyV2::BlocklistOnly,
        Some(too_many_readers),
        Some(1),
        20,
        80,
    )
    .is_err());
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
    assert!(fork.validate_predecessor(Some(&first)).is_err());

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
    assert!(DeclassificationRuleSetV2::from_canonical_bytes(
        first.canonical_bytes(),
        &wrong_purpose_root,
        50
    )
    .is_err());
}

fn domain_hash(domain: &[u8], bytes: &[u8]) -> Digest32V2 {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(bytes);
    Digest32V2::new(hasher.finalize().into())
}
