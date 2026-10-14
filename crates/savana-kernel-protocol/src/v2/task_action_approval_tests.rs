use super::*;
use ed25519_dalek::SigningKey;

fn d(n: u8) -> Digest32V2 {
    Digest32V2::new([n; 32])
}
fn context() -> TaskActionApprovalContextV2 {
    TaskActionApprovalContextV2 {
        content_digest: d(1),
        authorization_id: d(2),
        authorization_revision: 3,
        principal: PrincipalIdV2::new([4; 32]),
        task: DurableTaskIdV2::new([5; 32]),
        installation_digest: d(6),
        manifest_digest: d(7),
        deployment_generation: 8,
        challenge_nonce: d(9),
        settlement_nonce: d(10),
        authentication_context_digest: d(11),
        display_digest: d(12),
    }
}
fn material(c: TaskActionApprovalContextV2) -> TaskActionApprovalV2 {
    TaskActionApprovalV2::new(
        c,
        TaskActionApprovalDecisionV2::Approve,
        UnixMillisV2::new(100),
        UnixMillisV2::new(200),
    )
    .unwrap()
}

// Removing any expected binding/key/time/decision check must break this test.
#[test]
fn task_action_approval_checks_every_expected_binding() {
    let key = SigningKey::from_bytes(&[41; 32]);
    let c = context();
    let signed = sign_task_action_approval_v2(material(c.clone()), &key).unwrap();
    let check = |c: &TaskActionApprovalContextV2, time| {
        verify_task_action_approval_v2(&signed, &key.verifying_key(), c, UnixMillisV2::new(time))
    };
    assert!(check(&c, 100).is_ok());
    assert!(check(&c, 199).is_ok());
    assert!(check(&c, 99).is_err());
    assert!(check(&c, 200).is_err());
    assert!(verify_task_action_approval_v2(
        &signed,
        &SigningKey::from_bytes(&[42; 32]).verifying_key(),
        &c,
        UnixMillisV2::new(100)
    )
    .is_err());
    for n in 0..12 {
        let mut bad = c.clone();
        match n {
            0 => bad.content_digest = d(20),
            1 => bad.authorization_id = d(20),
            2 => bad.authorization_revision = 4,
            3 => bad.principal = PrincipalIdV2::new([20; 32]),
            4 => bad.task = DurableTaskIdV2::new([20; 32]),
            5 => bad.installation_digest = d(20),
            6 => bad.manifest_digest = d(20),
            7 => bad.deployment_generation = 9,
            8 => bad.challenge_nonce = d(20),
            9 => bad.settlement_nonce = d(20),
            10 => bad.authentication_context_digest = d(20),
            _ => bad.display_digest = d(20),
        };
        assert!(check(&bad, 100).is_err(), "binding {n}");
        let altered = SignedTaskActionApprovalV2::from_canonical_parts(
            encode_task_action_approval_v2(&material(bad)).unwrap(),
            signed.signature(),
        )
        .unwrap();
        assert!(verify_task_action_approval_v2(
            &altered,
            &key.verifying_key(),
            &c,
            UnixMillisV2::new(100)
        )
        .is_err());
    }
    let deny = TaskActionApprovalV2::new(
        c.clone(),
        TaskActionApprovalDecisionV2::Deny,
        UnixMillisV2::new(100),
        UnixMillisV2::new(200),
    )
    .unwrap();
    let deny = sign_task_action_approval_v2(deny, &key).unwrap();
    assert!(verify_task_action_approval_v2(
        &deny,
        &key.verifying_key(),
        &c,
        UnixMillisV2::new(100)
    )
    .is_err());
}

// Relaxing canonical/bounded parsing or losing signed-envelope binding breaks this.
#[test]
fn task_action_approval_wire_is_bounded_canonical_and_signed() {
    let key = SigningKey::from_bytes(&[41; 32]);
    let m = material(context());
    let bytes = encode_task_action_approval_v2(&m).unwrap();
    assert_eq!(decode_task_action_approval_v2(&bytes).unwrap(), m);
    assert_eq!(bytes[0], 0x90); // sixteen fields, fixed schema 1
    let mut wide = bytes.clone();
    wide.splice(1..2, [0x18, 1]);
    assert!(decode_task_action_approval_v2(&wide).is_err());
    for bad in [
        vec![],
        vec![0; MAX_TASK_ACTION_APPROVAL_BYTES_V2 + 1],
        bytes[..bytes.len() - 1].to_vec(),
        [bytes.clone(), vec![0]].concat(),
    ] {
        assert!(decode_task_action_approval_v2(&bad).is_err());
    }
    let signed = sign_task_action_approval_v2(m, &key).unwrap();
    let wire = encode_signed_task_action_approval_v2(&signed).unwrap();
    assert_eq!(
        decode_signed_task_action_approval_v2(&wire).unwrap(),
        signed
    );
    let mut bad = wire;
    let i = bad.len() - 1;
    bad[i] ^= 1;
    let altered = decode_signed_task_action_approval_v2(&bad).unwrap();
    assert!(verify_task_action_approval_v2(
        &altered,
        &key.verifying_key(),
        &context(),
        UnixMillisV2::new(100)
    )
    .is_err());
    for n in 0..12 {
        let mut c = context();
        match n {
            0 => c.content_digest = d(0),
            1 => c.authorization_id = d(0),
            2 => c.authorization_revision = 0,
            3 => c.principal = PrincipalIdV2::new([0; 32]),
            4 => c.task = DurableTaskIdV2::new([0; 32]),
            5 => c.installation_digest = d(0),
            6 => c.manifest_digest = d(0),
            7 => c.deployment_generation = 0,
            8 => c.challenge_nonce = d(0),
            9 => c.settlement_nonce = d(0),
            10 => c.authentication_context_digest = d(0),
            _ => c.display_digest = d(0),
        };
        assert!(TaskActionApprovalV2::new(
            c,
            TaskActionApprovalDecisionV2::Approve,
            UnixMillisV2::new(100),
            UnixMillisV2::new(200)
        )
        .is_err());
    }
}

// Signed timestamps/decision must not be replaceable, and verified digests bind
// the entire signed envelope, not merely the action content.
#[test]
fn task_action_approval_signed_times_and_settlement_digest_are_bound() {
    let key = SigningKey::from_bytes(&[41; 32]);
    let c = context();
    let baseline = sign_task_action_approval_v2(material(c.clone()), &key).unwrap();
    let verified =
        verify_task_action_approval_v2(&baseline, &key.verifying_key(), &c, UnixMillisV2::new(110))
            .unwrap();
    for (decision, issued, expires) in [
        (TaskActionApprovalDecisionV2::Deny, 100, 200),
        (TaskActionApprovalDecisionV2::Approve, 101, 200),
        (TaskActionApprovalDecisionV2::Approve, 100, 199),
    ] {
        let m = TaskActionApprovalV2::new(
            c.clone(),
            decision,
            UnixMillisV2::new(issued),
            UnixMillisV2::new(expires),
        )
        .unwrap();
        let altered = SignedTaskActionApprovalV2::from_canonical_parts(
            encode_task_action_approval_v2(&m).unwrap(),
            baseline.signature(),
        )
        .unwrap();
        assert!(verify_task_action_approval_v2(
            &altered,
            &key.verifying_key(),
            &c,
            UnixMillisV2::new(110)
        )
        .is_err());
        if decision == TaskActionApprovalDecisionV2::Approve {
            let signed = sign_task_action_approval_v2(m, &key).unwrap();
            assert_ne!(
                verify_task_action_approval_v2(
                    &signed,
                    &key.verifying_key(),
                    &c,
                    UnixMillisV2::new(110)
                )
                .unwrap()
                .digest(),
                verified.digest()
            );
        }
    }
    assert!(verified.recheck(&c, UnixMillisV2::new(200)).is_err());
    for (start, end) in [(200, 200), (201, 200)] {
        assert!(TaskActionApprovalV2::new(
            c.clone(),
            TaskActionApprovalDecisionV2::Approve,
            UnixMillisV2::new(start),
            UnixMillisV2::new(end)
        )
        .is_err());
    }
    let mut bytes = encode_task_action_approval_v2(&material(c.clone())).unwrap();
    bytes[1] = 2;
    assert!(decode_task_action_approval_v2(&bytes).is_err());
    let good = encode_task_action_approval_v2(&material(c)).unwrap();
    for end in 0..good.len() {
        assert!(decode_task_action_approval_v2(&good[..end]).is_err());
    }
    let mut indefinite = good.clone();
    indefinite[0] = 0x9f;
    indefinite.push(0xff);
    assert!(decode_task_action_approval_v2(&indefinite).is_err());
    let mut unknown_decision = good;
    let mut decoder = minicbor::Decoder::new(&unknown_decision);
    decoder.array().unwrap();
    for _ in 0..9 {
        decoder.skip().unwrap();
    }
    let position = decoder.position();
    unknown_decision[position] = 3;
    assert!(decode_task_action_approval_v2(&unknown_decision).is_err());
}
