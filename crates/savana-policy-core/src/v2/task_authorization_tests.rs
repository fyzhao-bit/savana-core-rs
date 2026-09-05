use super::*;
use ed25519_dalek::SigningKey;
use savana_kernel_protocol::v2::*;
fn d(n: u8) -> Digest32V2 {
    Digest32V2::new([n; 32])
}
fn alt(resource: u8, destination: u8, effect: TaskEffectV2) -> ActionAlternativeV2 {
    ActionAlternativeV2::new(
        d(10),
        ActionCodecProfileV2::FixedJsonPostV1,
        effect,
        d(resource),
        d(destination),
        d(11),
        MagnitudeUnitV2::Count,
    )
    .unwrap()
}
fn contract(alts: Vec<ActionAlternativeV2>, revision: u64) -> TaskAuthorizationV2 {
    contract_with_limit(alts, revision, 5)
}
fn contract_with_limit(
    alts: Vec<ActionAlternativeV2>,
    revision: u64,
    maximum_single_magnitude: u64,
) -> TaskAuthorizationV2 {
    TaskAuthorizationV2::new(
        d(1),
        PrincipalIdV2::new([2; 32]),
        DurableTaskIdV2::new([3; 32]),
        revision,
        d(4),
        d(5),
        UnixMillisV2::new(100),
        UnixMillisV2::new(200),
        TaskEvidenceKindV2::AuthenticatedStructuredInput,
        d(6),
        d(7),
        vec![TaskAuthorizationClauseV2::new(
            1,
            alts,
            maximum_single_magnitude,
            20,
            4,
            vec![],
            false,
        )
        .unwrap()],
    )
    .unwrap()
}
fn verified(m: TaskAuthorizationV2) -> VerifiedTaskAuthorizationV2 {
    let key = SigningKey::from_bytes(&[31; 32]);
    let s = sign_task_authorization_v2(m, &key).unwrap();
    VerifiedTaskAuthorizationV2::verify(
        &s,
        &key.verifying_key(),
        PrincipalIdV2::new([2; 32]),
        DurableTaskIdV2::new([3; 32]),
        d(4),
        d(5),
        UnixMillisV2::new(100),
    )
    .unwrap()
}
fn current(v: &VerifiedTaskAuthorizationV2) -> TaskMatchContextV2<'_> {
    TaskMatchContextV2 {
        current_authorization: Some(v),
        pre_state_digest: d(16),
        pre_state_revision: 0,
        deployment_generation: 1,
        now: UnixMillisV2::new(100),
    }
}
fn content(
    v: &VerifiedTaskAuthorizationV2,
    index: u64,
    action: ActionAlternativeV2,
) -> ActionContentV2 {
    content_with_magnitude(v, index, action, 2)
}
fn content_with_magnitude(
    v: &VerifiedTaskAuthorizationV2,
    index: u64,
    action: ActionAlternativeV2,
    magnitude: u64,
) -> ActionContentV2 {
    ActionContentV2::new(
        d(1),
        v.material().revision(),
        1,
        index,
        action,
        magnitude,
        d(12),
        d(13),
        d(14),
        v.candidate_domain(1, UnixMillisV2::new(100))
            .unwrap()
            .digest(),
        d(16),
        0,
    )
    .unwrap()
}
fn pair() -> VerifiedTaskAuthorizationV2 {
    verified(contract(
        vec![
            alt(20, 30, TaskEffectV2::Send),
            alt(21, 31, TaskEffectV2::Send),
        ],
        1,
    ))
}
fn mutate_content(c: &ActionContentV2, n: usize) -> ActionContentV2 {
    let a = c.action();
    let action = ActionAlternativeV2::new(
        if n == 12 {
            d(99)
        } else {
            a.tool_descriptor_digest()
        },
        if n == 13 {
            ActionCodecProfileV2::McpToolsCallJsonV1
        } else {
            a.codec_profile()
        },
        if n == 14 {
            TaskEffectV2::Delete
        } else {
            a.effect()
        },
        if n == 15 { d(99) } else { a.resource_digest() },
        if n == 16 {
            d(99)
        } else {
            a.destination_digest()
        },
        if n == 17 {
            d(99)
        } else {
            a.parameters_digest()
        },
        if n == 18 {
            MagnitudeUnitV2::Bytes
        } else {
            a.magnitude_unit()
        },
    )
    .unwrap();
    ActionContentV2::new(
        if n == 0 { d(99) } else { c.authorization_id() },
        if n == 1 {
            2
        } else {
            c.authorization_revision()
        },
        if n == 2 { 2 } else { c.clause_id() },
        if n == 3 { 1 } else { c.alternative_index() },
        action,
        if n == 4 { 6 } else { c.magnitude() },
        if n == 5 { d(99) } else { c.payload_digest() },
        if n == 6 { d(99) } else { c.provenance_digest() },
        if n == 7 {
            d(99)
        } else {
            c.plan_revision_digest()
        },
        if n == 8 {
            d(99)
        } else {
            c.candidate_domain_digest()
        },
        if n == 9 { d(99) } else { c.pre_state_digest() },
        if n == 10 { 1 } else { c.pre_state_revision() },
    )
    .unwrap()
}
// Dropping whole-tuple matching allows cross-pair and summary->send escalation.
#[test]
fn task_authorization_matches_whole_alternatives_not_cartesian_products() {
    let v = pair();
    for (i, r, dest, want) in [
        (0, 20, 30, true),
        (1, 21, 31, true),
        (0, 20, 31, false),
        (1, 21, 30, false),
        (0, 21, 31, false),
    ] {
        let c = content(&v, i, alt(r, dest, TaskEffectV2::Send));
        assert_eq!(v.match_action(&c, &current(&v)).is_ok(), want);
    }
    let v = verified(contract(vec![alt(20, 30, TaskEffectV2::Read)], 1));
    assert!(v
        .match_action(
            &content(&v, 0, alt(20, 30, TaskEffectV2::Send)),
            &current(&v)
        )
        .is_err());
}
// Dropping any identity/member/unit/magnitude/currentness check breaks a row.
#[test]
fn task_authorization_rejects_malformed_current_and_candidate_bindings() {
    let v = pair();
    let c = content(&v, 0, alt(20, 30, TaskEffectV2::Send));
    for n in [0, 1, 2, 3, 4, 8, 9, 10, 12, 13, 14, 15, 16, 17, 18] {
        assert!(
            v.match_action(&mutate_content(&c, n), &current(&v))
                .is_err(),
            "field {n}"
        );
    }
    for now in [99, 200] {
        let mut ctx = current(&v);
        ctx.now = UnixMillisV2::new(now);
        assert!(v.match_action(&c, &ctx).is_err());
    }
    let mut ctx = current(&v);
    ctx.current_authorization = None;
    assert!(v.match_action(&c, &ctx).is_err());
    let changed = verified(contract(vec![alt(20, 30, TaskEffectV2::Send)], 1)); // same epoch, altered full domain
    ctx.current_authorization = Some(&changed);
    assert!(v.match_action(&c, &ctx).is_err());
    let revised = verified(contract(vec![alt(20, 30, TaskEffectV2::Send)], 2));
    ctx.current_authorization = Some(&revised);
    assert!(v.match_action(&c, &ctx).is_err());
    let partial = content(&changed, 0, alt(20, 30, TaskEffectV2::Send));
    assert!(v.match_action(&partial, &current(&v)).is_err());
}
// A singleton, even pinned by the user, never promotes planner control labels.
#[test]
fn task_authorization_all_seven_selections_remain_untrusted_read() {
    let v = verified(contract_with_limit(
        vec![alt(20, 30, TaskEffectV2::Send)],
        1,
        1,
    ));
    let c = content_with_magnitude(&v, 0, alt(20, 30, TaskEffectV2::Send), 1);
    let m = v.match_action(&c, &current(&v)).unwrap();
    assert!(ControlSelectionV2::from_match(&m, d(0)).is_err());
    let s = ControlSelectionV2::from_match(&m, d(40)).unwrap();
    assert_eq!(s.len(), 7);
    for (i, s) in s.iter().enumerate() {
        assert_eq!(usize::from(s.facet().tag()), i + 1);
        assert_eq!(s.integrity(), IntegrityV2::ExternalUntrusted);
        assert_eq!(s.allowed_effects(), EffectSetV2::READ);
        assert_eq!(s.proposer_parent(), d(40));
    }
    assert!(checked_control_endorsements_v2(
        &m,
        &s,
        ControlEvidenceV2::CompleteContractSingleton,
        &current(&v)
    )
    .is_ok());
    let v = pair();
    let c = content(&v, 0, alt(20, 30, TaskEffectV2::Send));
    let m = v.match_action(&c, &current(&v)).unwrap();
    let s = ControlSelectionV2::from_match(&m, d(40)).unwrap();
    assert!(checked_control_endorsements_v2(
        &m,
        &s,
        ControlEvidenceV2::CompleteContractSingleton,
        &current(&v)
    )
    .is_err());
    assert!(checked_control_endorsements_v2(
        &m,
        &s,
        ControlEvidenceV2::ExplicitAlternative,
        &current(&v)
    )
    .is_ok());
}
// A dropped, reordered, duplicated, or reused endorsement is not a full proof.
#[test]
fn task_authorization_rechecks_endorsements_and_final_digest() {
    let v = pair();
    let c = content(&v, 0, alt(20, 30, TaskEffectV2::Send));
    let m = v.match_action(&c, &current(&v)).unwrap();
    let s = ControlSelectionV2::from_match(&m, d(40)).unwrap();
    let endorse = |s: &[ControlSelectionV2]| {
        checked_control_endorsements_v2(&m, s, ControlEvidenceV2::ExplicitAlternative, &current(&v))
    };
    assert!(endorse(&s[..6]).is_err());
    let mut bad = s.clone();
    bad.swap(0, 1);
    assert!(endorse(&bad).is_err());
    bad = s.clone();
    bad[1] = s[0].clone();
    assert!(endorse(&bad).is_err());
    let e = endorse(&s).unwrap();
    let digest = authorization_digest_v2(&m, &e, d(50), d(51), &current(&v)).unwrap();
    assert!(authorization_digest_v2(&m, &e, d(0), d(51), &current(&v)).is_err());
    assert!(authorization_digest_v2(&m, &e, d(50), d(0), &current(&v)).is_err());
    assert_ne!(
        authorization_digest_v2(&m, &e, d(52), d(51), &current(&v)).unwrap(),
        digest
    );
    assert_ne!(
        authorization_digest_v2(&m, &e, d(50), d(52), &current(&v)).unwrap(),
        digest
    );
    assert!(authorization_digest_v2(&m, &e[..6], d(50), d(51), &current(&v)).is_err());
    let mut bad = e.clone();
    bad.swap(0, 1);
    assert!(authorization_digest_v2(&m, &bad, d(50), d(51), &current(&v)).is_err());
    bad = e.clone();
    bad[1] = e[0].clone();
    assert!(authorization_digest_v2(&m, &bad, d(50), d(51), &current(&v)).is_err());
    for n in [5, 6, 7] {
        let other = v
            .match_action(&mutate_content(&c, n), &current(&v))
            .unwrap();
        assert!(checked_control_endorsements_v2(
            &other,
            &s,
            ControlEvidenceV2::ExplicitAlternative,
            &current(&v)
        )
        .is_err());
        assert!(authorization_digest_v2(&other, &e, d(50), d(51), &current(&v)).is_err());
    }
    let mut expired = current(&v);
    expired.now = UnixMillisV2::new(200);
    assert!(checked_control_endorsements_v2(
        &m,
        &s,
        ControlEvidenceV2::ExplicitAlternative,
        &expired
    )
    .is_err());
    assert!(authorization_digest_v2(&m, &e, d(50), d(51), &expired).is_err());
    expired = current(&v);
    expired.current_authorization = None;
    assert!(authorization_digest_v2(&m, &e, d(50), d(51), &expired).is_err());
}
fn approval_context(c: &ActionContentV2) -> TaskActionApprovalContextV2 {
    TaskActionApprovalContextV2 {
        content_digest: action_content_digest_v2(c).unwrap(),
        authorization_id: c.authorization_id(),
        authorization_revision: c.authorization_revision(),
        principal: PrincipalIdV2::new([2; 32]),
        task: DurableTaskIdV2::new([3; 32]),
        installation_digest: d(4),
        manifest_digest: d(5),
        deployment_generation: 1,
        challenge_nonce: d(60),
        settlement_nonce: d(61),
        authentication_context_digest: d(62),
        display_digest: d(63),
    }
}
fn approval(ctx: &TaskActionApprovalContextV2) -> VerifiedTaskActionApprovalV2 {
    let key = SigningKey::from_bytes(&[32; 32]);
    let a = TaskActionApprovalV2::new(
        ctx.clone(),
        TaskActionApprovalDecisionV2::Approve,
        UnixMillisV2::new(100),
        UnixMillisV2::new(150),
    )
    .unwrap();
    verify_task_action_approval_v2(
        &sign_task_action_approval_v2(a, &key).unwrap(),
        &key.verifying_key(),
        ctx,
        UnixMillisV2::new(100),
    )
    .unwrap()
}
// Approval is additional content-bound evidence; it cannot create a contract match.
#[test]
fn task_authorization_approval_is_content_bound_and_cannot_expand_contract() {
    let v = pair();
    let c = content(&v, 0, alt(20, 30, TaskEffectV2::Send));
    let ctx = approval_context(&c);
    let a = approval(&ctx);
    let m = v.match_action(&c, &current(&v)).unwrap();
    let s = ControlSelectionV2::from_match(&m, d(40)).unwrap();
    let evidence = || ControlEvidenceV2::ActionApproval {
        approval: &a,
        expected_context: &ctx,
    };
    let e = checked_control_endorsements_v2(&m, &s, evidence(), &current(&v)).unwrap();
    assert!(authorization_digest_v2(&m, &e, d(50), d(51), &current(&v)).is_ok());
    let mut expired = current(&v);
    expired.now = UnixMillisV2::new(150);
    assert!(checked_control_endorsements_v2(&m, &s, evidence(), &expired).is_err());
    assert!(authorization_digest_v2(&m, &e, d(50), d(51), &expired).is_err());
    let other = content(&v, 1, alt(21, 31, TaskEffectV2::Send));
    let other_m = v.match_action(&other, &current(&v)).unwrap();
    let other_s = ControlSelectionV2::from_match(&other_m, d(40)).unwrap();
    assert!(checked_control_endorsements_v2(&other_m, &other_s, evidence(), &current(&v)).is_err());
    let v = verified(contract(vec![alt(20, 30, TaskEffectV2::Read)], 1));
    let forbidden = content(&v, 0, alt(20, 30, TaskEffectV2::Send));
    let _valid_signed_approval = approval(&approval_context(&forbidden));
    assert!(v.match_action(&forbidden, &current(&v)).is_err());
    let mut mixed = e.clone();
    let explicit = checked_control_endorsements_v2(
        &m,
        &s,
        ControlEvidenceV2::ExplicitAlternative,
        &current(&m.authorization()),
    )
    .unwrap();
    mixed[0] = explicit[0].clone();
    assert!(
        authorization_digest_v2(&m, &mixed, d(50), d(51), &current(&m.authorization())).is_err()
    );
}
#[test]
fn task_authorization_effect_mapping_uses_bits_not_sequential_tags() {
    for (effect, want) in [
        (TaskEffectV2::Read, 1),
        (TaskEffectV2::Create, 2),
        (TaskEffectV2::Update, 4),
        (TaskEffectV2::Delete, 8),
        (TaskEffectV2::Send, 16),
        (TaskEffectV2::Execute, 32),
        (TaskEffectV2::FinalRelease, 64),
    ] {
        assert_eq!(task_effect_set_v2(effect).bits(), want);
    }
}

// Reusing a proof after deployment changes must fail even if its contract is unchanged.
#[test]
fn task_authorization_generation_change_invalidates_existing_match_and_approval() {
    let v = pair();
    let c = content(&v, 0, alt(20, 30, TaskEffectV2::Send));
    let m = v.match_action(&c, &current(&v)).unwrap();
    let s = ControlSelectionV2::from_match(&m, d(40)).unwrap();
    let e = checked_control_endorsements_v2(
        &m,
        &s,
        ControlEvidenceV2::ExplicitAlternative,
        &current(&v),
    )
    .unwrap();
    for generation in [0, 2] {
        let mut changed = current(&v);
        changed.deployment_generation = generation;
        assert!(m.recheck(&changed).is_err());
        assert!(authorization_digest_v2(&m, &e, d(50), d(51), &changed).is_err());
    }
    let mut zero = current(&v);
    zero.deployment_generation = 0;
    assert!(v.match_action(&c, &zero).is_err());
    let mut ctx = approval_context(&c);
    ctx.deployment_generation = 2;
    let a = approval(&ctx);
    assert!(checked_control_endorsements_v2(
        &m,
        &s,
        ControlEvidenceV2::ActionApproval {
            approval: &a,
            expected_context: &ctx
        },
        &current(&v)
    )
    .is_err());
}

fn hex(d: Digest32V2) -> String {
    d.as_bytes().iter().map(|b| format!("{b:02x}")).collect()
}
// Independent Python hashlib + hand-encoded CBOR/framing vectors, not production helpers.
#[test]
fn task_authorization_digest_has_independent_golden_vectors() {
    let v = pair();
    let c = content(&v, 0, alt(20, 30, TaskEffectV2::Send));
    let m = v.match_action(&c, &current(&v)).unwrap();
    let s = ControlSelectionV2::from_match(&m, d(40)).unwrap();
    let e = checked_control_endorsements_v2(
        &m,
        &s,
        ControlEvidenceV2::ExplicitAlternative,
        &current(&v),
    )
    .unwrap();
    assert_eq!(
        hex(v.digest()),
        "68179adf29aaaf859ae739ed6026660deb02a55a5a7db112a5728635bfd03200"
    );
    assert_eq!(
        hex(m.candidates().digest()),
        "dfb9c9ad3c2f55adb0873f9a45d8d0f074c3cd1aaaa3c7c576003598302b9ae4"
    );
    assert_eq!(
        hex(m.content_digest()),
        "3396237a15079fd35e15f9b5e9d76b3f0f03a7ea25236e139897066333813f03"
    );
    for (e, want) in e.iter().zip([
        "9a3e823e12c0023a43698baa1102164522896f3fe357e160c6a3d12d12e5bb2d",
        "2314ec0aff4405333ff6bb45b77daab86cbd2efba573b9197822cfb82913b318",
        "e3aff9df70c313f913911470678c7bb7834977f6e49ad6351bdacd9dd3fb56fa",
        "ba21e1b43c7c82a78b1f2f518ade7ff863b10a352910afa35d54be2ffd11f63b",
        "66de1c9be24880ac6f425e146745e69cf22dbe23c677020c7adfe59b74df4f85",
        "78816e2b120fef6fb1a3129ac418d8679d6eaa8de6a4598000c6510ef7f36585",
        "6d512dac8883357352b12b4d4029b5ef4c80591674d4ca57ba8e01e30aec5ab1",
    ]) {
        assert_eq!(hex(e.digest()), want);
    }
    for (policy, transition, want) in [
        (
            50,
            51,
            "56c141250c93985acfad2ed4eab6f094f90a4aa177ff3cb5a57cebfaceabb8d2",
        ),
        (
            52,
            51,
            "492cc959deca3e1b05efe574e31c200ca1e0d961874374c66c3d8c10b74b631a",
        ),
        (
            50,
            52,
            "6114b8a08dbe2d882e2877ad1fcb6ff1a9f9000b50269a8a824e54aa7e162694",
        ),
    ] {
        assert_eq!(
            hex(
                authorization_digest_v2(&m, &e, d(policy), d(transition), &current(&v))
                    .unwrap()
                    .digest()
            ),
            want
        );
    }
}

// Removing a facet projection field must not be hidden by the outer content hash.
#[test]
fn task_authorization_control_projection_mutations_bind_all_planes() {
    let base = verified(contract(vec![alt(20, 30, TaskEffectV2::Send)], 1));
    let c = content(&base, 0, alt(20, 30, TaskEffectV2::Send));
    let m = base.match_action(&c, &current(&base)).unwrap();
    let s = ControlSelectionV2::from_match(&m, d(40)).unwrap();
    for (n, facet) in [
        (12, 0),
        (13, 0),
        (14, 1),
        (15, 2),
        (16, 5),
        (17, 4),
        (18, 3),
    ] {
        let changed = mutate_content(&c, n).action().clone();
        let v = verified(contract(vec![changed.clone()], 1));
        let c = content(&v, 0, changed);
        let m = v.match_action(&c, &current(&v)).unwrap();
        let other = ControlSelectionV2::from_match(&m, d(40)).unwrap();
        for i in 0..7 {
            assert_eq!(
                s[i].selected_digest() != other[i].selected_digest(),
                i == facet,
                "mutation {n} facet {i}"
            );
        }
    }
    for n in [4, 9, 10] {
        let changed = ActionContentV2::new(
            c.authorization_id(),
            1,
            1,
            0,
            c.action().clone(),
            if n == 4 { 3 } else { 2 },
            d(12),
            d(13),
            d(14),
            c.candidate_domain_digest(),
            if n == 9 { d(17) } else { d(16) },
            u64::from(n == 10),
        )
        .unwrap();
        let mut ctx = current(&base);
        ctx.pre_state_digest = changed.pre_state_digest();
        ctx.pre_state_revision = changed.pre_state_revision();
        let m = base.match_action(&changed, &ctx).unwrap();
        let other = ControlSelectionV2::from_match(&m, d(40)).unwrap();
        for i in 0..7 {
            assert_eq!(
                s[i].selected_digest() != other[i].selected_digest(),
                i == if n == 4 { 3 } else { 6 }
            );
        }
    }
    let mut digest = None;
    for predecessors in [vec![], vec![2]] {
        let original = base.material();
        let v = verified(
            TaskAuthorizationV2::new(
                original.authorization_id(),
                original.principal(),
                original.task(),
                1,
                d(4),
                d(5),
                UnixMillisV2::new(100),
                UnixMillisV2::new(200),
                TaskEvidenceKindV2::AuthenticatedStructuredInput,
                d(6),
                d(7),
                vec![
                    TaskAuthorizationClauseV2::new(
                        1,
                        vec![alt(20, 30, TaskEffectV2::Send)],
                        5,
                        20,
                        4,
                        predecessors,
                        false,
                    )
                    .unwrap(),
                    TaskAuthorizationClauseV2::new(
                        2,
                        vec![alt(21, 31, TaskEffectV2::Read)],
                        5,
                        20,
                        4,
                        vec![],
                        false,
                    )
                    .unwrap(),
                ],
            )
            .unwrap(),
        );
        let c = content(&v, 0, alt(20, 30, TaskEffectV2::Send));
        let m = v.match_action(&c, &current(&v)).unwrap();
        let trigger = ControlSelectionV2::from_match(&m, d(40)).unwrap()[6].selected_digest();
        if let Some(previous) = digest {
            assert_ne!(previous, trigger);
        }
        digest = Some(trigger);
    }
}

// A valid signature for a different identity/session must still fail policy use.
#[test]
fn task_authorization_approval_context_and_settlement_mutations() {
    let v = pair();
    let c = content(&v, 0, alt(20, 30, TaskEffectV2::Send));
    let m = v.match_action(&c, &current(&v)).unwrap();
    let s = ControlSelectionV2::from_match(&m, d(40)).unwrap();
    let ctx = approval_context(&c);
    let a = approval(&ctx);
    let original = checked_control_endorsements_v2(
        &m,
        &s,
        ControlEvidenceV2::ActionApproval {
            approval: &a,
            expected_context: &ctx,
        },
        &current(&v),
    )
    .unwrap();
    let digest = authorization_digest_v2(&m, &original, d(50), d(51), &current(&v)).unwrap();
    for n in 0..12 {
        let mut other = ctx.clone();
        match n {
            0 => other.content_digest = d(99),
            1 => other.authorization_id = d(99),
            2 => other.authorization_revision = 2,
            3 => other.principal = PrincipalIdV2::new([99; 32]),
            4 => other.task = DurableTaskIdV2::new([99; 32]),
            5 => other.installation_digest = d(99),
            6 => other.manifest_digest = d(99),
            7 => other.deployment_generation = 2,
            8 => other.challenge_nonce = d(99),
            9 => other.settlement_nonce = d(99),
            10 => other.authentication_context_digest = d(99),
            _ => other.display_digest = d(99),
        };
        assert!(checked_control_endorsements_v2(
            &m,
            &s,
            ControlEvidenceV2::ActionApproval {
                approval: &a,
                expected_context: &other
            },
            &current(&v)
        )
        .is_err());
        let signed_other = approval(&other);
        let result = checked_control_endorsements_v2(
            &m,
            &s,
            ControlEvidenceV2::ActionApproval {
                approval: &signed_other,
                expected_context: &other,
            },
            &current(&v),
        );
        if n < 8 {
            assert!(result.is_err(), "context {n}");
        } else {
            let e = result.unwrap();
            assert_ne!(
                authorization_digest_v2(&m, &e, d(50), d(51), &current(&v)).unwrap(),
                digest
            );
            let mut mixed = original.clone();
            mixed[3] = e[3].clone();
            assert!(authorization_digest_v2(&m, &mixed, d(50), d(51), &current(&v)).is_err());
        }
    }
    let other_s = ControlSelectionV2::from_match(&m, d(41)).unwrap();
    let other_e = checked_control_endorsements_v2(
        &m,
        &other_s,
        ControlEvidenceV2::ActionApproval {
            approval: &a,
            expected_context: &ctx,
        },
        &current(&v),
    )
    .unwrap();
    assert_ne!(
        authorization_digest_v2(&m, &other_e, d(50), d(51), &current(&v)).unwrap(),
        digest
    );
}

// The wrapper must not accept decoded material, an arbitrary key, or wrong context.
#[test]
fn task_authorization_verified_wrapper_checks_trust_context() {
    let key = SigningKey::from_bytes(&[31; 32]);
    let signed =
        sign_task_authorization_v2(contract(vec![alt(20, 30, TaskEffectV2::Send)], 1), &key)
            .unwrap();
    for n in 0..7 {
        let other = SigningKey::from_bytes(&[32; 32]);
        let result = VerifiedTaskAuthorizationV2::verify(
            &signed,
            &if n == 0 {
                other.verifying_key()
            } else {
                key.verifying_key()
            },
            PrincipalIdV2::new([if n == 1 { 99 } else { 2 }; 32]),
            DurableTaskIdV2::new([if n == 2 { 99 } else { 3 }; 32]),
            d(if n == 3 { 99 } else { 4 }),
            d(if n == 4 { 99 } else { 5 }),
            UnixMillisV2::new(if n == 5 {
                99
            } else if n == 6 {
                200
            } else {
                100
            }),
        );
        assert!(result.is_err(), "context {n}");
    }
}

#[test]
fn task_authorization_endorsement_preserves_only_verified_settlement_identity() {
    let v = verified(contract_with_limit(
        vec![alt(20, 30, TaskEffectV2::Send)],
        1,
        1,
    ));
    let c = content_with_magnitude(&v, 0, alt(20, 30, TaskEffectV2::Send), 1);
    let m = v.match_action(&c, &current(&v)).unwrap();
    let s = ControlSelectionV2::from_match(&m, d(40)).unwrap();
    let ctx = approval_context(&c);
    let a = approval(&ctx);
    for choice in [
        ControlEvidenceV2::ExplicitAlternative,
        ControlEvidenceV2::CompleteContractSingleton,
        ControlEvidenceV2::ActionApproval {
            approval: &a,
            expected_context: &ctx,
        },
    ] {
        let expected = if matches!(choice, ControlEvidenceV2::ActionApproval { .. }) {
            Some((a.digest(), d(61)))
        } else {
            None
        };
        for e in checked_control_endorsements_v2(&m, &s, choice, &current(&v)).unwrap() {
            assert_eq!(e.settlement_digest().zip(e.settlement_nonce()), expected);
            assert_eq!(e.settlement_nonce().is_some(), expected.is_some());
            assert_eq!(e.settlement_digest().is_some(), expected.is_some());
        }
    }
}

// One tuple still permits two whole actions when positive magnitude may be 1 or 2.
#[test]
fn task_authorization_singleton_requires_a_unique_positive_magnitude() {
    for maximum in [1, 2] {
        let v = verified(contract_with_limit(
            vec![alt(20, 30, TaskEffectV2::Send)],
            1,
            maximum,
        ));
        for magnitude in 1..=maximum {
            let c = content_with_magnitude(&v, 0, alt(20, 30, TaskEffectV2::Send), magnitude);
            let m = v.match_action(&c, &current(&v)).unwrap();
            let s = ControlSelectionV2::from_match(&m, d(40)).unwrap();
            let singleton = checked_control_endorsements_v2(
                &m,
                &s,
                ControlEvidenceV2::CompleteContractSingleton,
                &current(&v),
            );
            assert_eq!(
                singleton.is_ok(),
                maximum == 1,
                "maximum={maximum}, magnitude={magnitude}"
            );
            if let Ok(e) = singleton {
                assert!(authorization_digest_v2(&m, &e, d(50), d(51), &current(&v)).is_ok());
            }
            let ctx = approval_context(&c);
            let a = approval(&ctx);
            for evidence in [
                ControlEvidenceV2::ExplicitAlternative,
                ControlEvidenceV2::ActionApproval {
                    approval: &a,
                    expected_context: &ctx,
                },
            ] {
                let e = checked_control_endorsements_v2(&m, &s, evidence, &current(&v)).unwrap();
                assert!(authorization_digest_v2(&m, &e, d(50), d(51), &current(&v)).is_ok());
            }
        }
    }
}
