use savana_kernel_protocol::v2::*;

fn d(n: u8) -> Digest32V2 {
    Digest32V2::new([n; 32])
}
fn profile(codec: ActionCodecProfileV2, magnitude: BusinessMagnitudeV2) -> BusinessProfileV2 {
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
    ];
    if magnitude == BusinessMagnitudeV2::CountField {
        fields.push(
            BusinessFieldV2::new(
                "quantity",
                BusinessFieldRoleV2::Magnitude,
                BusinessFieldTypeV2::Unsigned,
            )
            .unwrap(),
        );
    }
    fields.sort_by(|a, b| a.name().cmp(b.name()));
    BusinessProfileV2::new(
        codec,
        if codec == ActionCodecProfileV2::McpToolsCallJsonV1 {
            "mail.send"
        } else {
            "/v1/send"
        },
        d(1),
        d(2),
        TaskEffectV2::Send,
        magnitude,
        fields,
    )
    .unwrap()
}
fn input(quantity: u64) -> Vec<u8> {
    format!(r#"{{"jsonrpc":"2.0","id":"request-1","method":"tools/call","params":{{"name":"mail.send","arguments":{{"body":"hello","file":"A","quantity":{quantity},"subject":"report","to":"Alice"}}}}}}"#).into_bytes()
}

#[test]
fn business_request_roundtrip_and_independent_controls() {
    let p = profile(
        ActionCodecProfileV2::McpToolsCallJsonV1,
        BusinessMagnitudeV2::CountField,
    );
    let a = BusinessRequestV2::parse(&p, "request-1", &input(1)).unwrap();
    let b = BusinessRequestV2::parse(&p, "request-1", &input(2)).unwrap();
    assert_eq!(a.magnitude(), 1);
    assert_eq!(b.magnitude(), 2);
    assert_eq!(
        a.parameters_digest(),
        b.parameters_digest(),
        "quantity is separately bounded, not a static parameter"
    );
    assert_eq!(a.resource(), "A");
    assert_eq!(a.destination(), "Alice");
    assert_ne!(a.digest(), b.digest());
    assert_eq!(
        a,
        BusinessRequestV2::parse(&p, "request-1", &a.canonical_json()).unwrap()
    );
    let bytes = encode_business_profile_v2(&p).unwrap();
    assert_eq!(p, decode_business_profile_v2(&bytes).unwrap());
    let debug = format!("{a:?}");
    for sensitive in ["Alice", "hello", "report", "request-1"] {
        assert!(!debug.contains(sensitive));
    }
}

#[test]
fn business_request_rejects_duplicate_unknown_malformed_or_rebound_envelopes() {
    let p = profile(
        ActionCodecProfileV2::McpToolsCallJsonV1,
        BusinessMagnitudeV2::CountField,
    );
    let source = String::from_utf8(input(1)).unwrap();
    for bad in [
        source.replace("\"to\":\"Alice\"", "\"to\":\"Alice\",\"to\":\"Bob\""),
        source.replace("\"to\":\"Alice\"", "\"to\":\"Alice\",\"t\\u006f\":\"Bob\""),
        source.replace("\"to\":\"Alice\"", "\"to\":\"Alice\",\"hidden\":true"),
        source.replace("\"quantity\":1", "\"quantity\":1.0"),
        source.replace("\"quantity\":1", "\"quantity\":-1"),
        source.replace("\"quantity\":1", "\"quantity\":0"),
        source.replace("\"quantity\":1", "\"quantity\":18446744073709551616"),
        source.replace("tools/call", "tools/list"),
        source.replace("mail.send", "shell.execute"),
        source.replace("request-1", "request-2"),
        source.replace("\"to\":\"Alice\"", "\"to\":{\"name\":\"Alice\"}"),
        source.replace("\"to\":\"Alice\"", "\"to\":\"Alice\\u202e\""),
        format!("{source} {{}}"),
    ] {
        assert!(
            BusinessRequestV2::parse(&p, "request-1", bad.as_bytes()).is_err(),
            "accepted malformed request"
        );
    }
}

#[test]
fn business_request_changed_values_change_exact_binding() {
    let p = profile(
        ActionCodecProfileV2::McpToolsCallJsonV1,
        BusinessMagnitudeV2::CountField,
    );
    let original = String::from_utf8(input(1)).unwrap();
    let a = BusinessRequestV2::parse(&p, "request-1", original.as_bytes()).unwrap();
    for (old, new) in [
        ("Alice", "Bob"),
        ("\"A\"", "\"B\""),
        ("hello", "other"),
        ("report", "different"),
    ] {
        let b = BusinessRequestV2::parse(&p, "request-1", original.replace(old, new).as_bytes())
            .unwrap();
        assert_ne!(a.digest(), b.digest());
        assert!(a.verify_equivalent(&b.canonical_json()).is_err());
    }
    let mut object: serde_json::Value = serde_json::from_slice(&input(1)).unwrap();
    object["params"]["arguments"]["quantity"] = 2.into();
    assert!(a
        .verify_equivalent(&serde_json::to_vec(&object).unwrap())
        .is_err());
}

#[test]
fn business_request_fixed_post_and_utf8_bytes_are_closed() {
    let p = profile(
        ActionCodecProfileV2::FixedJsonPostV1,
        BusinessMagnitudeV2::Utf8PayloadBytes,
    );
    let source = r#"{"request_id":"request-1","method":"POST","path":"/v1/send","body":{"body":"你好","file":"A","subject":"report","to":"Alice"}}"#;
    let a = BusinessRequestV2::parse(&p, "request-1", source.as_bytes()).unwrap();
    assert_eq!(a.magnitude(), 6);
    assert_eq!(a.unit(), MagnitudeUnitV2::Bytes);
    for bad in [
        source.replace("POST", "GET"),
        source.replace("/v1/send", "/v1/delete"),
    ] {
        assert!(BusinessRequestV2::parse(&p, "request-1", bad.as_bytes()).is_err());
    }
}

#[test]
fn business_request_response_is_not_success_merely_because_result_exists() {
    let p = profile(
        ActionCodecProfileV2::McpToolsCallJsonV1,
        BusinessMagnitudeV2::CountField,
    );
    let a = BusinessRequestV2::parse(&p, "request-1", &input(1)).unwrap();
    let ok = br#"{"jsonrpc":"2.0","id":"request-1","result":{"isError":false,"content":[],"structuredContent":{"savana_status":"succeeded"}}}"#;
    assert_eq!(
        a.classify_response(ok).unwrap(),
        BusinessResponseDispositionV2::Succeeded
    );
    for bad in [
        r#"{"jsonrpc":"2.0","id":"request-1","result":{}}"#,
        r#"{"jsonrpc":"2.0","id":"other","result":{"isError":false,"content":[],"structuredContent":{"savana_status":"succeeded"}}}"#,
        r#"{"jsonrpc":"2.0","id":"request-1","result":{"isError":false,"content":[],"structuredContent":{"savana_status":"succeeded"},"inputRequired":true}}"#,
        r#"{"jsonrpc":"2.0","id":"request-1","result":{"isError":false,"isError":true,"content":[],"structuredContent":{"savana_status":"succeeded"}}}"#,
    ] {
        assert!(a.classify_response(bad.as_bytes()).is_err());
    }
    let failure = String::from_utf8(ok.to_vec())
        .unwrap()
        .replace("false", "true");
    assert_eq!(
        a.classify_response(failure.as_bytes()).unwrap(),
        BusinessResponseDispositionV2::Failed
    );
    assert_eq!(
        a.classify_response(
            br#"{"jsonrpc":"2.0","id":"request-1","error":{"code":-32603,"message":"internal"}}"#
        )
        .unwrap(),
        BusinessResponseDispositionV2::Failed
    );
}

#[test]
fn business_request_trusted_builder_uses_the_same_exact_mapping() {
    let p = profile(
        ActionCodecProfileV2::McpToolsCallJsonV1,
        BusinessMagnitudeV2::CountField,
    );
    let fields = vec![
        ("to".into(), BusinessValueV2::Text("Alice".into())),
        ("file".into(), BusinessValueV2::Text("A".into())),
        ("body".into(), BusinessValueV2::Text("hello".into())),
        ("subject".into(), BusinessValueV2::Text("report".into())),
        ("quantity".into(), BusinessValueV2::Unsigned(1)),
    ];
    let a = BusinessRequestV2::from_fields(&p, "request-1", fields.clone()).unwrap();
    assert_eq!(
        a,
        BusinessRequestV2::parse(&p, "request-1", &input(1)).unwrap()
    );
    let mut duplicate = fields.clone();
    duplicate.push(fields[0].clone());
    assert!(BusinessRequestV2::from_fields(&p, "request-1", duplicate).is_err());
    let alternative = a.action_alternative(d(90)).unwrap();
    assert_eq!(alternative.resource_digest(), a.resource_digest());
    assert_eq!(alternative.destination_digest(), a.destination_digest());
    assert_eq!(alternative.parameters_digest(), a.parameters_digest());
    assert_eq!(alternative.magnitude_unit(), MagnitudeUnitV2::Count);
    assert!(!format!("{:?}", fields[0].1).contains("Alice"));
}

#[test]
fn business_request_profile_rejects_ambiguous_roles_and_paths() {
    let p = profile(
        ActionCodecProfileV2::FixedJsonPostV1,
        BusinessMagnitudeV2::FixedCount(1),
    );
    for path in [
        "/../send",
        "/./send",
        "/v1//send",
        "/v1/send?x=1",
        "/v1/%73end",
        "https://evil/send",
    ] {
        assert!(
            BusinessProfileV2::new(
                p.codec(),
                path,
                p.target_identity(),
                p.credential_identity(),
                p.effect(),
                p.magnitude_rule(),
                p.fields().to_vec()
            )
            .is_err(),
            "accepted ambiguous path"
        );
    }
    let mut duplicate_role = p.fields().to_vec();
    duplicate_role.push(
        BusinessFieldV2::new(
            "z",
            BusinessFieldRoleV2::Destination,
            BusinessFieldTypeV2::Text,
        )
        .unwrap(),
    );
    assert!(BusinessProfileV2::new(
        p.codec(),
        p.operation(),
        p.target_identity(),
        p.credential_identity(),
        p.effect(),
        p.magnitude_rule(),
        duplicate_role
    )
    .is_err());
    assert!(BusinessFieldV2::new(
        "to",
        BusinessFieldRoleV2::Destination,
        BusinessFieldTypeV2::Boolean
    )
    .is_err());
    assert!(BusinessFieldV2::new(
        "to.alias",
        BusinessFieldRoleV2::Magnitude,
        BusinessFieldTypeV2::Text
    )
    .is_err());
}

#[test]
fn business_request_size_and_unknown_profile_are_refused() {
    let p = profile(
        ActionCodecProfileV2::McpToolsCallJsonV1,
        BusinessMagnitudeV2::CountField,
    );
    assert!(
        BusinessRequestV2::parse(&p, "request-1", &vec![b' '; MAX_BUSINESS_JSON_BYTES_V2 + 1])
            .is_err()
    );
    let mut encoded = encode_business_profile_v2(&p).unwrap();
    encoded[1] = 2;
    assert!(decode_business_profile_v2(&encoded).is_err());
    let encoded = encode_business_profile_v2(&p).unwrap();
    for end in 0..encoded.len() {
        assert!(decode_business_profile_v2(&encoded[..end]).is_err());
    }
    let mut noncanonical = encoded.clone();
    noncanonical.splice(0..1, [0x98, 0x08]);
    assert!(decode_business_profile_v2(&noncanonical).is_err());
    let mut trailing = encoded;
    trailing.push(0);
    assert!(decode_business_profile_v2(&trailing).is_err());
}

#[test]
fn business_request_golden_commitments_are_independent_literal_vectors() {
    // Independently derived with Python hashlib, manual canonical CBOR, and
    // json.dumps(sort_keys=True, separators=(",", ":")); not copied from Rust.
    let p = profile(
        ActionCodecProfileV2::McpToolsCallJsonV1,
        BusinessMagnitudeV2::CountField,
    );
    let a = BusinessRequestV2::parse(&p, "request-1", &input(1)).unwrap();
    fn hex(d: Digest32V2) -> String {
        d.as_bytes().iter().map(|b| format!("{b:02x}")).collect()
    }
    assert_eq!(
        hex(p.digest()),
        "23f8ebcf7201b70df1a5769e8f437038cd37e0180d55610170f591e0205ec471"
    );
    assert_eq!(
        hex(a.digest()),
        "437e8e87c532ced6d5c9338bbf614bca6327a2e0848d5bf58758397f074bdd78"
    );
    assert_eq!(
        hex(a.resource_digest()),
        "762ae48357f5a890a55fcbcf7eed493a7875d533a8d6f90325a6f967be1d19ec"
    );
    assert_eq!(
        hex(a.destination_digest()),
        "2477ccebcd3f7874b5be987140aae6b32512fd42f468cbf5342df544612daab8"
    );
    assert_eq!(
        hex(a.payload_digest()),
        "d888a2474cc4c595af7d129751d57e6563c6a82d6ccab51e39c6acd420af6b6d"
    );
    assert_eq!(
        hex(a.parameters_digest()),
        "64d180a3297b86968c5599e0839c041e4f9a582f4ee8196ddd846c41b71a3dcd"
    );
    assert_eq!(a.canonical_json(), br#"{"id":"request-1","jsonrpc":"2.0","method":"tools/call","params":{"arguments":{"body":"hello","file":"A","quantity":1,"subject":"report","to":"Alice"},"name":"mail.send"}}"#);
}

#[test]
fn business_request_profile_target_credential_effect_and_mapping_are_bound() {
    let p = profile(
        ActionCodecProfileV2::McpToolsCallJsonV1,
        BusinessMagnitudeV2::CountField,
    );
    let a = BusinessRequestV2::parse(&p, "request-1", &input(1)).unwrap();
    for (target, credential, effect) in [
        (d(10), d(2), TaskEffectV2::Send),
        (d(1), d(20), TaskEffectV2::Send),
        (d(1), d(2), TaskEffectV2::Read),
    ] {
        let other = BusinessProfileV2::new(
            p.codec(),
            p.operation(),
            target,
            credential,
            effect,
            p.magnitude_rule(),
            p.fields().to_vec(),
        )
        .unwrap();
        assert_ne!(p.digest(), other.digest());
        assert_ne!(
            a.digest(),
            BusinessRequestV2::parse(&other, "request-1", &input(1))
                .unwrap()
                .digest()
        );
    }
    let fields = p
        .fields()
        .iter()
        .map(|f| {
            BusinessFieldV2::new(
                f.name(),
                match f.role() {
                    BusinessFieldRoleV2::Resource => BusinessFieldRoleV2::Destination,
                    BusinessFieldRoleV2::Destination => BusinessFieldRoleV2::Resource,
                    other => other,
                },
                f.kind(),
            )
            .unwrap()
        })
        .collect();
    let other = BusinessProfileV2::new(
        p.codec(),
        p.operation(),
        p.target_identity(),
        p.credential_identity(),
        p.effect(),
        p.magnitude_rule(),
        fields,
    )
    .unwrap();
    assert_ne!(p.digest(), other.digest());
    let swapped = BusinessRequestV2::parse(&other, "request-1", &input(1)).unwrap();
    assert_ne!(a.digest(), swapped.digest());
    assert_ne!(a.resource_digest(), swapped.resource_digest());
}

#[test]
fn business_request_response_profiles_reject_pending_and_distinguish_unknown() {
    let p = profile(
        ActionCodecProfileV2::FixedJsonPostV1,
        BusinessMagnitudeV2::FixedCount(1),
    );
    let body = br#"{"request_id":"request-1","method":"POST","path":"/v1/send","body":{"body":"hello","file":"A","subject":"report","to":"Alice"}}"#;
    let a = BusinessRequestV2::parse(&p, "request-1", body).unwrap();
    for (status, expected) in [
        ("succeeded", BusinessResponseDispositionV2::Succeeded),
        ("failed", BusinessResponseDispositionV2::Failed),
        (
            "indeterminate",
            BusinessResponseDispositionV2::Indeterminate,
        ),
    ] {
        let response = format!(r#"{{"request_id":"request-1","status":"{status}"}}"#);
        assert_eq!(a.classify_response(response.as_bytes()).unwrap(), expected);
    }
    for bad in [
        r#"{"request_id":"request-1","status":"pending"}"#,
        r#"{"request_id":"request-1","status":"succeeded","redirect":"evil"}"#,
        r#"{"request_id":"other","status":"succeeded"}"#,
        r#"{"request_id":"request-1","status":true}"#,
    ] {
        assert!(a.classify_response(bad.as_bytes()).is_err());
    }
    let p = profile(
        ActionCodecProfileV2::McpToolsCallJsonV1,
        BusinessMagnitudeV2::CountField,
    );
    let a = BusinessRequestV2::parse(&p, "request-1", &input(1)).unwrap();
    let response = br#"{"jsonrpc":"2.0","id":"request-1","result":{"isError":false,"content":[{"type":"text","text":"untrusted response"}],"structuredContent":{"savana_status":"indeterminate"}}}"#;
    assert_eq!(
        a.classify_response(response).unwrap(),
        BusinessResponseDispositionV2::Indeterminate
    );
}
