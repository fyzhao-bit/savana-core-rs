use super::*;
use ed25519_dalek::{Signer as _, SigningKey};

// Fixtures describe the wire contract independently of production constructors.
#[derive(Clone)]
enum V {
    U(u64),
    B(u8),
    A(Vec<V>),
    Bool(bool),
}
fn a(v: Vec<V>) -> V {
    V::A(v)
}
fn u(n: u64) -> V {
    V::U(n)
}
fn b(n: u8) -> V {
    V::B(n)
}
fn fields(v: &mut V) -> &mut Vec<V> {
    if let V::A(v) = v {
        v
    } else {
        panic!("array")
    }
}
fn wire(v: &V) -> Vec<u8> {
    fn put(v: &V, e: &mut minicbor::Encoder<Vec<u8>>) {
        match v {
            V::U(n) => {
                e.u64(*n).unwrap();
            }
            V::B(n) => {
                e.bytes(&[*n; 32]).unwrap();
            }
            V::Bool(n) => {
                e.bool(*n).unwrap();
            }
            V::A(v) => {
                e.array(v.len() as u64).unwrap();
                for x in v {
                    put(x, e);
                }
            }
        }
    }
    let mut e = minicbor::Encoder::new(Vec::new());
    put(v, &mut e);
    e.into_writer()
}
fn alternative(resource: u8, destination: u8) -> V {
    a(vec![
        b(7),
        u(1),
        u(5),
        b(resource),
        b(destination),
        b(10),
        u(1),
    ])
}
fn clause(id: u64, predecessors: Vec<V>) -> V {
    a(vec![
        u(id),
        a(vec![alternative(8, 9), alternative(18, 19)]),
        u(5),
        u(10),
        u(2),
        a(predecessors),
        V::Bool(false),
    ])
}
fn contract() -> V {
    a(vec![
        u(1),
        b(1),
        b(2),
        b(3),
        u(1),
        b(4),
        b(5),
        u(100),
        u(200),
        u(1),
        b(6),
        b(11),
        a(vec![clause(1, vec![])]),
    ])
}
fn content() -> V {
    a(vec![
        u(1),
        b(1),
        u(1),
        u(1),
        u(0),
        alternative(8, 9),
        u(3),
        b(12),
        b(13),
        b(14),
        b(15),
        b(16),
        u(0),
    ])
}
fn key() -> SigningKey {
    SigningKey::from_bytes(&[42; 32])
}
fn verify(s: &SignedTaskAuthorizationV2) -> Result<TaskAuthorizationV2, crate::ProtocolError> {
    verify_task_authorization_v2(
        s,
        &key().verifying_key(),
        PrincipalIdV2::new([2; 32]),
        DurableTaskIdV2::new([3; 32]),
        Digest32V2::new([4; 32]),
        Digest32V2::new([5; 32]),
        UnixMillisV2::new(100),
    )
}

#[test]
fn task_authorization_canonical_round_trip_and_trusted_expectations() {
    let raw = wire(&contract());
    let value = decode_task_authorization_v2(&raw).unwrap();
    assert_eq!(encode_task_authorization_v2(&value).unwrap(), raw);
    let s = sign_task_authorization_v2(value.clone(), &key()).unwrap();
    let signed_wire = encode_signed_task_authorization_v2(&s).unwrap();
    assert_eq!(
        decode_signed_task_authorization_v2(&signed_wire).unwrap(),
        s
    );
    assert_eq!(verify(&s).unwrap(), value);
    for bad in 0..7 {
        let wrong = SigningKey::from_bytes(&[43; 32]);
        assert!(
            verify_task_authorization_v2(
                &s,
                &if bad == 0 {
                    wrong.verifying_key()
                } else {
                    key().verifying_key()
                },
                PrincipalIdV2::new([if bad == 1 { 22 } else { 2 }; 32]),
                DurableTaskIdV2::new([if bad == 2 { 33 } else { 3 }; 32]),
                Digest32V2::new([if bad == 3 { 44 } else { 4 }; 32]),
                Digest32V2::new([if bad == 4 { 55 } else { 5 }; 32]),
                UnixMillisV2::new(if bad == 5 {
                    99
                } else if bad == 6 {
                    200
                } else {
                    100
                })
            )
            .is_err(),
            "binding {bad}"
        );
    }
    let wrong_purpose = key().sign(&raw);
    let s = SignedTaskAuthorizationV2::from_canonical_parts(
        raw,
        Ed25519SignatureV2::new(wrong_purpose.to_bytes()),
    )
    .unwrap();
    assert!(verify(&s).is_err());
}

// Omitting any field from the signature must break this test.
#[test]
fn task_authorization_signature_binds_every_contract_field() {
    let value = decode_task_authorization_v2(&wire(&contract())).unwrap();
    let signed = sign_task_authorization_v2(value, &key()).unwrap();
    fn mutations(v: &V) -> Vec<V> {
        match v {
            V::U(n) => vec![u(n + 1)],
            V::B(n) => vec![b(n + 1)],
            V::Bool(n) => vec![V::Bool(!n)],
            V::A(xs) => xs
                .iter()
                .enumerate()
                .flat_map(|(i, x)| {
                    mutations(x).into_iter().map(move |m| {
                        let mut next = xs.clone();
                        next[i] = m;
                        a(next)
                    })
                })
                .collect(),
        }
    }
    for changed in mutations(&contract()) {
        let raw = wire(&changed);
        if let Ok(s) = SignedTaskAuthorizationV2::from_canonical_parts(raw, signed.signature()) {
            assert!(verify(&s).is_err());
        }
    }
}

#[test]
fn task_authorization_rejects_malformed_and_noncanonical_wire() {
    let raw = wire(&contract());
    for cut in 0..raw.len() {
        assert!(decode_task_authorization_v2(&raw[..cut]).is_err());
    }
    let mut trailing = raw.clone();
    trailing.push(0);
    assert!(decode_task_authorization_v2(&trailing).is_err());
    let mut noncanonical = raw.clone();
    noncanonical.splice(1..2, [0x18, 1]);
    assert!(decode_task_authorization_v2(&noncanonical).is_err());
    let mut indefinite = raw.clone();
    indefinite[0] = 0x9f;
    indefinite.push(0xff);
    assert!(decode_task_authorization_v2(&indefinite).is_err());
    assert!(decode_task_authorization_v2(&[0x9b, 255, 255, 255, 255, 255, 255, 255, 255]).is_err());
    assert!(decode_task_authorization_v2(&vec![0; 1024 * 1024 + 1]).is_err());
    for (i, v) in [
        (0, u(2)),
        (1, b(0)),
        (2, b(0)),
        (3, b(0)),
        (4, u(0)),
        (5, b(0)),
        (6, b(0)),
        (8, u(100)),
        (9, u(3)),
        (10, b(0)),
        (11, b(0)),
        (12, a(vec![])),
        (12, a(vec![clause(1, vec![]); 65])),
    ] {
        let mut bad = contract();
        fields(&mut bad)[i] = v;
        assert!(
            decode_task_authorization_v2(&wire(&bad)).is_err(),
            "field {i}"
        );
    }
}

#[test]
fn task_authorization_rejects_invalid_clause_limits_members_and_graphs() {
    for (i, v) in [
        (0, u(0)),
        (1, a(vec![])),
        (1, a(vec![alternative(8, 9); 2])),
        (1, a((1..=65).map(|n| alternative(n, 9)).collect())),
        (2, u(0)),
        (2, u(11)),
        (3, u(0)),
        (4, u(0)),
        (5, a(vec![u(1)])),
        (5, a(vec![u(2); 33])),
        (5, a(vec![u(2), u(2)])),
    ] {
        let mut c = clause(1, vec![]);
        fields(&mut c)[i] = v;
        let mut bad = contract();
        fields(&mut bad)[12] = a(vec![c]);
        assert!(
            decode_task_authorization_v2(&wire(&bad)).is_err(),
            "clause field {i}"
        );
    }
    for clauses in [
        vec![clause(2, vec![]), clause(1, vec![])],
        vec![clause(1, vec![]), clause(1, vec![])],
        vec![clause(1, vec![u(2)])],
        vec![clause(1, vec![u(2)]), clause(2, vec![u(1)])],
    ] {
        let mut bad = contract();
        fields(&mut bad)[12] = a(clauses);
        assert!(decode_task_authorization_v2(&wire(&bad)).is_err());
    }
    let mut valid = contract();
    fields(&mut valid)[12] = a(vec![clause(1, vec![u(2)]), clause(2, vec![])]);
    assert!(
        decode_task_authorization_v2(&wire(&valid)).is_ok(),
        "IDs need not be topological"
    );
}

#[test]
fn task_authorization_alternatives_are_whole_pairs() {
    let t = decode_task_authorization_v2(&wire(&contract())).unwrap();
    let member = decode_action_content_v2(&wire(&content())).unwrap();
    assert!(t.clauses()[0].alternatives().contains(member.action()));
    let mut cross = content();
    fields(&mut cross)[5] = alternative(8, 19);
    let cross = decode_action_content_v2(&wire(&cross)).unwrap();
    assert!(!t.clauses()[0].alternatives().contains(cross.action()));
}

#[test]
fn task_authorization_action_content_validates_and_binds_all_fields() {
    let raw = wire(&content());
    let value = decode_action_content_v2(&raw).unwrap();
    assert_eq!(encode_action_content_v2(&value).unwrap(), raw);
    for (i, v) in [
        (0, u(2)),
        (1, b(0)),
        (2, u(0)),
        (3, u(0)),
        (4, u(64)),
        (6, u(0)),
        (7, b(0)),
        (8, b(0)),
        (9, b(0)),
        (10, b(0)),
        (11, b(0)),
    ] {
        let mut bad = content();
        fields(&mut bad)[i] = v;
        assert!(decode_action_content_v2(&wire(&bad)).is_err());
    }
    for (i, v) in [
        (0, b(0)),
        (1, u(3)),
        (2, u(8)),
        (3, b(0)),
        (4, b(0)),
        (5, b(0)),
        (6, u(3)),
    ] {
        let mut bad = content();
        fields(fields(&mut bad).get_mut(5).unwrap())[i] = v;
        assert!(decode_action_content_v2(&wire(&bad)).is_err());
    }
    let baseline = action_content_digest_v2(&value).unwrap();
    for i in 1..13 {
        let mut changed = content();
        let f = &mut fields(&mut changed)[i];
        *f = match f {
            V::U(n) => u(*n + 1),
            V::B(n) => b(*n + 1),
            V::A(_) => alternative(18, 19),
            _ => unreachable!(),
        };
        let changed = decode_action_content_v2(&wire(&changed)).unwrap();
        assert_ne!(
            action_content_digest_v2(&changed).unwrap(),
            baseline,
            "action field {i}"
        );
    }
}

#[test]
fn task_authorization_rejects_mixed_units_in_one_budget() {
    let mut mixed = contract();
    let clauses = fields(&mut fields(&mut mixed)[12]);
    let alts = fields(&mut fields(&mut clauses[0])[1]);
    fields(&mut alts[1])[6] = u(2);
    assert!(decode_task_authorization_v2(&wire(&mixed)).is_err());

    let mut separate = contract();
    let mut bytes_clause = clause(2, vec![]);
    for alt in fields(&mut fields(&mut bytes_clause)[1]) {
        fields(alt)[6] = u(2);
    }
    fields(&mut separate)[12] = a(vec![clause(1, vec![]), bytes_clause]);
    assert!(decode_task_authorization_v2(&wire(&separate)).is_ok());
}

#[test]
fn task_authorization_signature_binds_dependencies_membership_and_budget_units() {
    let mut original = contract();
    fields(&mut original)[12] = a(vec![clause(1, vec![]), clause(2, vec![u(1)])]);
    let signed = sign_task_authorization_v2(
        decode_task_authorization_v2(&wire(&original)).unwrap(),
        &key(),
    )
    .unwrap();
    for mutation in 0..4 {
        let mut changed = original.clone();
        let clauses = fields(&mut fields(&mut changed)[12]);
        match mutation {
            0 => {
                fields(&mut clauses[1])[5] = a(vec![]);
            }
            1 => {
                clauses.pop();
            }
            2 => {
                fields(&mut fields(&mut clauses[0])[1]).pop();
            }
            3 => {
                for alt in fields(&mut fields(&mut clauses[0])[1]) {
                    fields(alt)[6] = u(2);
                }
            }
            _ => unreachable!(),
        }
        let value =
            SignedTaskAuthorizationV2::from_canonical_parts(wire(&changed), signed.signature())
                .unwrap();
        assert!(verify(&value).is_err(), "mutation {mutation}");
    }
}

#[test]
fn task_authorization_maximum_collections_round_trip_with_maximum_integers() {
    let mut maximum = contract();
    fields(&mut maximum)[4] = u(u64::MAX);
    fields(&mut maximum)[12] = a((1..=64)
        .map(|id| {
            let mut c = clause(id, (1..id).rev().take(32).map(u).collect());
            fields(&mut c)[1] = a((1..=64).map(|resource| alternative(resource, 9)).collect());
            for i in 2..=4 {
                fields(&mut c)[i] = u(u64::MAX);
            }
            c
        })
        .collect());
    let raw = wire(&maximum);
    assert!(raw.len() < 1024 * 1024);
    let material = decode_task_authorization_v2(&raw).unwrap();
    assert_eq!(material.clauses().len(), 64);
    assert_eq!(encode_task_authorization_v2(&material).unwrap(), raw);
    let signed = sign_task_authorization_v2(material, &key()).unwrap();
    assert!(verify(&signed).is_ok());
    let raw = encode_signed_task_authorization_v2(&signed).unwrap();
    assert!(decode_signed_task_authorization_v2(&raw).is_ok());
}

#[test]
fn task_authorization_public_constructors_preserve_validation() {
    let t = decode_task_authorization_v2(&wire(&contract())).unwrap();
    let alt = &t.clauses()[0].alternatives()[0];
    let make_alt = |resource| {
        ActionAlternativeV2::new(
            alt.tool_descriptor_digest(),
            alt.codec_profile(),
            alt.effect(),
            resource,
            alt.destination_digest(),
            alt.parameters_digest(),
            alt.magnitude_unit(),
        )
    };
    assert_eq!(make_alt(alt.resource_digest()).unwrap(), *alt);
    assert!(make_alt(Digest32V2::new([0; 32])).is_err());
    let make_clause = |id| {
        TaskAuthorizationClauseV2::new(
            id,
            t.clauses()[0].alternatives().to_vec(),
            5,
            10,
            2,
            vec![],
            false,
        )
    };
    assert_eq!(make_clause(1).unwrap(), t.clauses()[0]);
    assert!(make_clause(0).is_err());
    let make_task = |revision| {
        TaskAuthorizationV2::new(
            t.authorization_id(),
            t.principal(),
            t.task(),
            revision,
            t.installation_digest(),
            t.manifest_digest(),
            t.not_before(),
            t.expires_at(),
            t.evidence_kind(),
            t.user_evidence_digest(),
            t.rendering_digest(),
            t.clauses().to_vec(),
        )
    };
    assert_eq!(make_task(1).unwrap(), t);
    assert!(make_task(0).is_err());
    let c = decode_action_content_v2(&wire(&content())).unwrap();
    let make_content = |index| {
        ActionContentV2::new(
            c.authorization_id(),
            c.authorization_revision(),
            c.clause_id(),
            index,
            c.action().clone(),
            c.magnitude(),
            c.payload_digest(),
            c.provenance_digest(),
            c.plan_revision_digest(),
            c.candidate_domain_digest(),
            c.pre_state_digest(),
            c.pre_state_revision(),
        )
    };
    assert_eq!(make_content(0).unwrap(), c);
    assert!(make_content(64).is_err());
}

#[test]
fn task_authorization_signed_and_content_wire_reject_noncanonical_inputs() {
    let signed = sign_task_authorization_v2(
        decode_task_authorization_v2(&wire(&contract())).unwrap(),
        &key(),
    )
    .unwrap();
    let encoded = encode_signed_task_authorization_v2(&signed).unwrap();
    for cut in 0..encoded.len() {
        assert!(decode_signed_task_authorization_v2(&encoded[..cut]).is_err());
    }
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert!(decode_signed_task_authorization_v2(&trailing).is_err());
    let mut noncanonical = encoded.clone();
    noncanonical.splice(1..2, [0x18, 1]);
    assert!(decode_signed_task_authorization_v2(&noncanonical).is_err());
    let mut bad_schema = encoded.clone();
    bad_schema[1] = 2;
    assert!(decode_signed_task_authorization_v2(&bad_schema).is_err());
    let mut indefinite = encoded;
    indefinite[0] = 0x9f;
    indefinite.push(0xff);
    assert!(decode_signed_task_authorization_v2(&indefinite).is_err());
    let raw = wire(&content());
    for cut in 0..raw.len() {
        assert!(decode_action_content_v2(&raw[..cut]).is_err());
    }
    let mut trailing = raw.clone();
    trailing.push(0);
    assert!(decode_action_content_v2(&trailing).is_err());
    let mut noncanonical = raw.clone();
    noncanonical.splice(1..2, [0x18, 1]);
    assert!(decode_action_content_v2(&noncanonical).is_err());
    let mut indefinite = raw;
    indefinite[0] = 0x9f;
    indefinite.push(0xff);
    assert!(decode_action_content_v2(&indefinite).is_err());
    assert!(SignedTaskAuthorizationV2::from_canonical_parts(
        wire(&contract()),
        Ed25519SignatureV2::new([0; 64])
    )
    .is_err());
    assert!(verify_task_authorization_v2(
        &signed,
        &key().verifying_key(),
        PrincipalIdV2::new([2; 32]),
        DurableTaskIdV2::new([3; 32]),
        Digest32V2::new([4; 32]),
        Digest32V2::new([5; 32]),
        UnixMillisV2::new(199)
    )
    .is_ok());
}

// Literal vectors were calculated once with independent Python hashlib plus a
// small manual CBOR encoder (no production code or Rust encoding helpers).
#[test]
fn task_authorization_digest_literal_mutation_vectors() {
    fn hex(d: Digest32V2) -> String {
        d.as_bytes().iter().map(|b| format!("{b:02x}")).collect()
    }
    let t = decode_task_authorization_v2(&wire(&contract())).unwrap();
    assert_eq!(
        hex(task_authorization_digest_v2(&t).unwrap()),
        "2f491b762467503c8797aa8a5b557d081d655dc95910f8a77d3f7eb50765d210"
    );
    let c = decode_action_content_v2(&wire(&content())).unwrap();
    assert_eq!(
        hex(action_content_digest_v2(&c).unwrap()),
        "95c4112278af0468d57aac98d93092c30e9da99bc1b1525786000cac2a9b73ba"
    );
    let expected = [
        "8013c32ce48e81ee1ccce5b5030f512d62dc0c775bc2895c8d6eedf91eb2ebba",
        "0c595e3bd12c08a4732f320d5c2b752fdee545ef365ebb4e7f5efc546baccb1b",
        "b95670fa34e5bd94ccb74690de17c693a6658aa10df63bf64e804a0efd798d68",
        "c40f81a31d2ee09ae57fe672fac7d88527f22f685952578be93014e8ccd67e37",
        "02364b7fcb2037a1f1f8eeb75819c844f82401332c995042e86de89e993eeb9d",
        "d223205b3f33483d23fc50dbcfde65f5d41999add5a9a14c5c4129d8f64ac124",
        "5f810ab3a4bf4dbc7eab588aea3e221b26631d533485762b6147cf342f90544a",
        "edb8a1cc63ac58f2dc93ce403f085b12592daf3ce4fc815d7df4a9e02a22a4c1",
        "df1a254657048f58097368cf89ee2823f173b6b5bbb87786c9a1648dc502a295",
        "163e023d2d0225c95df08bb7825460e4eb458f5b698ef5344a7a323efe95a56f",
        "16b4a149f896330510eaedc95583d04e4acd2cc786acf6d60206b569bfd16921",
        "3d0439421b9fc64ec45ecdcfafce974e5a8860244a863d1b5f6d81866daa7f9a",
    ];
    for (i, want) in expected.iter().enumerate() {
        let mut changed = content();
        let f = &mut fields(&mut changed)[i + 1];
        *f = match f {
            V::U(n) => u(*n + 1),
            V::B(n) => b(*n + 1),
            V::A(_) => alternative(18, 19),
            _ => unreachable!(),
        };
        let changed = decode_action_content_v2(&wire(&changed)).unwrap();
        assert_eq!(
            hex(action_content_digest_v2(&changed).unwrap()),
            *want,
            "field {}",
            i + 1
        );
    }
    let expected = [
        "b001a34f1efe342bbb78d83b0e35e452ed70f7c87349334cd42c8f4937cb9b5f",
        "02bbed50415afa8799708afd84b05baa8d2e99f958fafd48382d559813115033",
        "0d86b3b527ca470b64ab84b6dd66931b0bc767f674b967f551e1124766618bd3",
        "282755ffc5042030def38d77a922912b9676dda0d26f7d563d55e7b7c1b62f07",
        "937bf5dfa4a22d7636b311a2fdc583c93b3218ee99e98fee2b9012f63309156f",
        "0d283bc511bd3eedd1f74b4ec090451f0c0318c0fa861c9d652da09779d1a70f",
        "a70499014ad428396a5118d7e272318ee87c4308e8e2789930938883cbcda713",
    ];
    for (i, want) in expected.iter().enumerate() {
        let mut changed = content();
        let f = &mut fields(&mut fields(&mut changed)[5])[i];
        *f = match f {
            V::U(n) => u(*n + 1),
            V::B(n) => b(*n + 1),
            _ => unreachable!(),
        };
        let changed = decode_action_content_v2(&wire(&changed)).unwrap();
        assert_eq!(
            hex(action_content_digest_v2(&changed).unwrap()),
            *want,
            "alternative field {i}"
        );
    }
}
