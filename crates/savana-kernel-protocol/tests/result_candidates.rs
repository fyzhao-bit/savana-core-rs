//! A trusted-set origin (U7): the owner signs a closed candidate set into a
//! result-derived control. The set is part of the rule's canonical bytes, so
//! every digest that commits to the rule commits to it, and a rule without one
//! keeps its bytes.
use savana_kernel_protocol::v2::*;
use std::collections::BTreeMap;

fn d(n: u8) -> Digest32V2 {
    Digest32V2::new([n; 32])
}

fn profile() -> BusinessProfileV2 {
    let mut fields = vec![
        BusinessFieldV2::new(
            "body",
            BusinessFieldRoleV2::Payload,
            BusinessFieldTypeV2::Text,
        )
        .unwrap(),
        BusinessFieldV2::new(
            "file",
            BusinessFieldRoleV2::Resource,
            BusinessFieldTypeV2::Text,
        )
        .unwrap(),
        BusinessFieldV2::new(
            "subject",
            BusinessFieldRoleV2::Parameter,
            BusinessFieldTypeV2::Text,
        )
        .unwrap(),
        BusinessFieldV2::new(
            "to",
            BusinessFieldRoleV2::Destination,
            BusinessFieldTypeV2::Text,
        )
        .unwrap(),
        BusinessFieldV2::new(
            "quantity",
            BusinessFieldRoleV2::Magnitude,
            BusinessFieldTypeV2::Unsigned,
        )
        .unwrap(),
    ];
    fields.sort_by(|a, b| a.name().cmp(b.name()));
    BusinessProfileV2::new(
        ActionCodecProfileV2::McpToolsCallJsonV1,
        "mail.send",
        d(1),
        d(2),
        TaskEffectV2::Send,
        BusinessMagnitudeV2::CountField,
        fields,
    )
    .unwrap()
}

fn members(items: &[&str]) -> ResultCandidatesV2 {
    ResultCandidatesV2::new(items.iter().map(|s| s.to_string()).collect()).unwrap()
}

fn rule(set: Option<ResultCandidatesV2>) -> ResultDerivedControlV2 {
    let plain = ResultDerivedControlV2::new(
        1,
        vec!["participants".into(), "0".into()],
        BusinessFieldTypeV2::Text,
        256,
    )
    .unwrap();
    match set {
        Some(set) => plain.with_candidates(set).unwrap(),
        None => plain,
    }
}

fn controls(set: Option<ResultCandidatesV2>) -> BusinessControlsV2 {
    let mut derived = BTreeMap::new();
    derived.insert("to".to_string(), rule(set));
    BusinessControlsV2::from_fields_with_derived(
        &profile(),
        vec![
            ("file".into(), BusinessValueV2::Text("A".into())),
            ("subject".into(), BusinessValueV2::Text("report".into())),
        ],
        derived,
    )
    .unwrap()
}

#[test]
fn a_set_is_canonical_bounded_and_exact() {
    let set = members(&["Alice", "Bob", "alice@x.com"]);
    assert!(set.contains("Bob"));
    // Exact bytes: no case folding, no trimming.
    assert!(!set.contains("bob"));
    assert!(!set.contains(" Bob"));
    for bad in [
        vec![],
        vec!["Bob".to_string(), "Alice".to_string()],
        vec!["Alice".to_string(), "Alice".to_string()],
        vec!["".to_string()],
        vec![" Alice".to_string()],
        vec!["line\nbreak".to_string()],
        (0..=MAX_RESULT_CANDIDATES_V2)
            .map(|n| format!("m{n:03}"))
            .collect(),
        (0..2)
            .map(|n| format!("{n}{}", "x".repeat(MAX_RESULT_CANDIDATE_BYTES_V2 / 2)))
            .collect(),
    ] {
        assert!(ResultCandidatesV2::new(bad.clone()).is_err(), "{bad:?}");
    }
}

#[test]
fn a_set_rides_only_on_an_uncomputed_text_or_list_edge_within_its_bound() {
    let set = members(&["Alice", "Bob"]);
    let text = |kind| ResultDerivedControlV2::new(1, vec!["x".into()], kind, 8).unwrap();
    assert!(text(BusinessFieldTypeV2::Text)
        .with_candidates(set.clone())
        .is_ok());
    assert!(text(BusinessFieldTypeV2::TextList)
        .with_candidates(set.clone())
        .is_ok());
    assert!(text(BusinessFieldTypeV2::Unsigned)
        .with_candidates(set.clone())
        .is_err());
    assert!(text(BusinessFieldTypeV2::Boolean)
        .with_candidates(set.clone())
        .is_err());
    let computed = text(BusinessFieldTypeV2::Text)
        .with_compute(ResultComputeV2::new(ResultComputeOpV2::AddDays, 1).unwrap())
        .unwrap();
    assert!(computed.with_candidates(set.clone()).is_err());
    assert!(text(BusinessFieldTypeV2::Text)
        .with_candidates(set.clone())
        .unwrap()
        .with_compute(ResultComputeV2::new(ResultComputeOpV2::AddDays, 1).unwrap())
        .is_err());
    // A member longer than the edge's byte bound could never be derived.
    let narrow =
        ResultDerivedControlV2::new(1, vec!["x".into()], BusinessFieldTypeV2::Text, 4).unwrap();
    assert!(narrow.with_candidates(members(&["Alice"])).is_err());
}

#[test]
fn the_set_is_signed_and_a_plain_rule_keeps_its_bytes() {
    let plain = controls(None);
    let signed = controls(Some(members(&["Alice", "Bob"])));
    // Round trips, and the plain rule's encoding is untouched by the feature.
    for c in [&plain, &signed] {
        let bytes = encode_business_controls_v2(c).unwrap();
        assert_eq!(&decode_business_controls_v2(&bytes).unwrap(), c);
    }
    let rules = |c: &BusinessControlsV2| encode_result_derived_controls_v2(c.derived()).unwrap();
    assert_eq!(
        decode_result_derived_controls_v2(&rules(&signed)).unwrap(),
        *signed.derived()
    );
    let plain_rule = rules(&plain);
    // [["to", [1, ["participants", "0"], 1, 256]]]
    assert_eq!(&plain_rule[..2], &[0x81, 0x82]);
    assert!(plain_rule.windows(2).any(|w| w == [0x84, 0x01]));
    // Adding, removing or changing a member changes what the owner signs.
    let alternatives: Vec<_> = [
        controls(None),
        controls(Some(members(&["Alice", "Bob"]))),
        controls(Some(members(&["Alice"]))),
        controls(Some(members(&["Alice", "Bob", "Mallory"]))),
        controls(Some(members(&["Alice", "Bobby"]))),
    ]
    .iter()
    .map(|c| c.action_alternative(d(90)).unwrap())
    .collect();
    for (i, a) in alternatives.iter().enumerate() {
        for b in &alternatives[i + 1..] {
            assert_ne!(a, b);
        }
    }
}

#[test]
fn a_request_matches_the_signed_alternative_only_under_the_same_set() {
    let signed = controls(Some(members(&["Alice", "Bob"])));
    let root = signed.action_alternative(d(90)).unwrap();
    let request = BusinessRequestV2::parse(
        &profile(),
        "request-1",
        br#"{"jsonrpc":"2.0","id":"request-1","method":"tools/call","params":{"name":"mail.send","arguments":{"body":"hi","file":"A","quantity":1,"subject":"report","to":"Bob"}}}"#,
    )
    .unwrap();
    assert_eq!(
        request
            .action_alternative_with_derived(d(90), signed.derived())
            .unwrap(),
        root
    );
    // A binding that widens or drops the set never matches what was signed.
    for other in [None, Some(members(&["Alice", "Bob", "Mallory"]))] {
        let mut derived = BTreeMap::new();
        derived.insert("to".to_string(), rule(other));
        assert_ne!(
            request
                .action_alternative_with_derived(d(90), &derived)
                .unwrap(),
            root
        );
    }
}

#[test]
fn a_rule_with_a_set_cannot_be_decoded_out_of_order_or_with_a_computation() {
    let signed = controls(Some(members(&["Alice", "Bob"])));
    let bytes = encode_result_derived_controls_v2(signed.derived()).unwrap();
    // Swap the two members: no longer canonical.
    let (a, b) = (b"eAlice".as_slice(), b"cBob".as_slice());
    let position = bytes.windows(a.len()).position(|w| w == a).unwrap();
    let mut swapped = bytes[..position].to_vec();
    swapped.extend_from_slice(b);
    swapped.extend_from_slice(a);
    swapped.extend_from_slice(&bytes[position + a.len() + b.len()..]);
    assert!(decode_result_derived_controls_v2(&swapped).is_err());
    // The fifth element must be null (no computation) when a set follows.
    let null = bytes.iter().position(|byte| *byte == 0xf6).unwrap();
    let mut computed = bytes[..null].to_vec();
    computed.extend_from_slice(&[0x82, 0x02, 0x01]);
    computed.extend_from_slice(&bytes[null + 1..]);
    assert!(decode_result_derived_controls_v2(&computed).is_err());
}
