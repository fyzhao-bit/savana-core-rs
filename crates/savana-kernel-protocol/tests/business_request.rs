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
fn action_review_is_exact_readable_bounded_and_not_model_prose() {
    let p = profile(
        ActionCodecProfileV2::McpToolsCallJsonV1,
        BusinessMagnitudeV2::CountField,
    );
    let review = |request: &BusinessRequestV2, used, charged| {
        let action = request.action_alternative(d(21)).unwrap();
        let root = TaskAuthorizationV2::new(
            d(20),
            PrincipalIdV2::new([30; 32]),
            DurableTaskIdV2::new([31; 32]),
            1,
            d(32),
            d(33),
            UnixMillisV2::new(1),
            UnixMillisV2::new(1000),
            TaskEvidenceKindV2::AuthenticatedStructuredInput,
            d(34),
            d(35),
            vec![
                TaskAuthorizationClauseV2::new(1, vec![action.clone()], 1, 1, 1, vec![], false)
                    .unwrap(),
                TaskAuthorizationClauseV2::new(2, vec![action.clone()], 3, 5, 3, vec![1], true)
                    .unwrap(),
            ],
        )
        .unwrap();
        let content = ActionContentV2::new(
            d(20),
            1,
            2,
            0,
            action,
            request.magnitude(),
            request.payload_digest(),
            d(22),
            d(23),
            d(24),
            d(25),
            1,
        )
        .unwrap();
        render_task_action_display_v2(
            &content,
            &root,
            request,
            &std::collections::BTreeMap::new(),
            used,
            charged,
        )
    };
    let source = String::from_utf8(input(2))
        .unwrap()
        .replace("hello", "<script>&\\n\\u202eevil\\u200b");
    let request = BusinessRequestV2::parse(&p, "request-1", source.as_bytes()).unwrap();
    let display = review(&request, 1, 2).unwrap();
    let text = display.as_str();
    assert!(!text.contains('<') && !text.contains('&'));
    assert!(!text.contains('\u{202e}') && !text.contains('\u{200b}'));
    assert!(text.contains("\\u202e") && text.contains("\\u200b"));
    let decoded: serde_json::Value = serde_json::from_str(text).unwrap();
    assert_eq!(decoded["resource"], "A");
    assert_eq!(decoded["destination"], "Alice");
    assert_eq!(decoded["magnitude"], 2);
    assert_eq!(decoded["attempts_after_prepare"], 2);
    assert_eq!(decoded["magnitude_after_prepare"], 4);
    assert_eq!(
        decoded["requires_verified_success_of_clauses"],
        serde_json::json!([1])
    );
    assert_eq!(
        decoded["approval_kind"],
        "One action; does not amend task authorization"
    );
    assert_eq!(
        decoded["exact_business_request"],
        serde_json::from_slice::<serde_json::Value>(&request.canonical_json()).unwrap()
    );
    for (used, charged) in [(3, 0), (0, 4), (u64::MAX, 0), (0, u64::MAX)] {
        assert!(review(&request, used, charged).is_err());
    }
    // Escaping expansion must reject the whole review, not hide/truncate the tail.
    let oversized = String::from_utf8(input(1))
        .unwrap()
        .replace("hello", &"<".repeat(25_000));
    let oversized = BusinessRequestV2::parse(&p, "request-1", oversized.as_bytes()).unwrap();
    assert!(review(&oversized, 0, 0).is_err());
}

#[test]
fn task_execution_payload_is_closed_content_bound_and_redacts_debug() {
    let profile = profile(
        ActionCodecProfileV2::McpToolsCallJsonV1,
        BusinessMagnitudeV2::CountField,
    );
    let request = BusinessRequestV2::parse(&profile, "request-1", &input(1)).unwrap();
    let content = ActionContentV2::new(
        d(20),
        1,
        1,
        0,
        request.action_alternative(d(21)).unwrap(),
        1,
        request.payload_digest(),
        d(22),
        d(23),
        d(24),
        d(25),
        1,
    )
    .unwrap();
    let payload = TaskExecutionPayloadV2::new(content.clone(), request.clone()).unwrap();
    let bytes = encode_task_execution_payload_v2(&payload).unwrap();
    assert_eq!(decode_task_execution_payload_v2(&bytes).unwrap(), payload);
    assert!(!format!("{payload:?}").contains("hello"));
    assert!(!format!("{payload:?}").contains("Alice"));
    for end in 0..bytes.len() {
        assert!(decode_task_execution_payload_v2(&bytes[..end]).is_err());
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(decode_task_execution_payload_v2(&trailing).is_err());
    let mut unknown = bytes.clone();
    unknown[1] = 2;
    assert!(decode_task_execution_payload_v2(&unknown).is_err());
    let altered = String::from_utf8(input(1)).unwrap().replace("Alice", "Bob");
    assert!(TaskExecutionPayloadV2::new(
        content.clone(),
        BusinessRequestV2::parse(&profile, "request-1", altered.as_bytes()).unwrap()
    )
    .is_err());
    assert!(TaskExecutionPayloadV2::new(
        content.clone(),
        BusinessRequestV2::parse(&profile, "request-1", &input(2)).unwrap()
    )
    .is_err());
    let altered_payload = String::from_utf8(input(1))
        .unwrap()
        .replace("hello", "secret");
    assert!(TaskExecutionPayloadV2::new(
        content.clone(),
        BusinessRequestV2::parse(&profile, "request-1", altered_payload.as_bytes()).unwrap()
    )
    .is_err());
    let subject = DispatchSubjectV2::tool_execution(
        ActionIntentIdV2::new([30; 32]),
        ToolExecutionSemanticBindingV2::new(
            PlanRevisionDigestV2::new([23; 32]),
            InternalStepIdV2::new([31; 32]),
            d(21),
            d(32),
            d(22),
            d(33),
            d(34),
            d(35),
            d(36),
            d(37),
            AttemptKindV2::new(2),
        )
        .unwrap(),
        None,
    )
    .unwrap();
    let core = DispatchCoreV2::new(
        d(38),
        d(39),
        1,
        1,
        DurableTaskIdV2::new([40; 32]),
        DurableRunIdV2::new([41; 32]),
        Nonce32V2::new([42; 32]),
        subject,
        ExecutorIdentityV2::new([43; 32]),
        HpkeX25519KeyIdV2::new([44; 32]),
        d(45),
        UnixMillisV2::new(100),
    )
    .unwrap();
    assert!(payload.check_core(&core).is_err());
    let bound = core.clone().with_task_binding(
        DispatchTaskBindingV2::new(action_content_digest_v2(&content).unwrap(), d(46), d(47))
            .unwrap(),
    );
    assert!(payload.check_core(&bound).is_ok());
    assert!(payload
        .check_core(
            &core.with_task_binding(DispatchTaskBindingV2::new(d(99), d(46), d(47)).unwrap())
        )
        .is_err());
    assert_ne!(
        business_target_identity_v2("https://provider.example/one", d(1)).unwrap(),
        business_target_identity_v2("https://provider.example/two", d(1)).unwrap()
    );
    assert!(business_target_identity_v2("http://provider.example", d(1)).is_err());
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

#[test]
fn business_request_format_and_default_ignorable_controls_never_enter_identity_fields() {
    let p = profile(
        ActionCodecProfileV2::McpToolsCallJsonV1,
        BusinessMagnitudeV2::CountField,
    );
    let source = String::from_utf8(input(1)).unwrap();
    // Unicode 16 Cf and Default_Ignorable representatives missing from the
    // original hand-written filter, including a supplementary-plane character.
    for cp in [
        0x180e, 0xfff9, 0xfffa, 0xfffb, 0x034f, 0x115f, 0x0600, 0x110bd, 0xe0100,
    ] {
        let ch = char::from_u32(cp).unwrap();
        let escaped = if cp <= 0xffff {
            format!("\\u{cp:04x}")
        } else {
            let n = cp - 0x10000;
            format!(
                "\\u{:04x}\\u{:04x}",
                0xd800 + (n >> 10),
                0xdc00 + (n & 0x3ff)
            )
        };
        for value in [format!("x{ch}y"), format!("x{escaped}y")] {
            for original in ["Alice", "report", "A"] {
                let request = source.replace(&format!("\"{original}\""), &format!("\"{value}\""));
                assert!(
                    BusinessRequestV2::parse(&p, "request-1", request.as_bytes()).is_err(),
                    "control U+{cp:04X} admitted"
                );
            }
            let payload = source.replace("hello", &value);
            assert_eq!(
                BusinessRequestV2::parse(&p, "request-1", payload.as_bytes())
                    .unwrap()
                    .payload(),
                format!("x{ch}y")
            );
        }
    }
}

#[test]
fn task_draft_controls_match_real_requests_without_dummy_payload_or_quantity() {
    let p = profile(
        ActionCodecProfileV2::McpToolsCallJsonV1,
        BusinessMagnitudeV2::CountField,
    );
    let fields = vec![
        ("file".into(), BusinessValueV2::Text("A".into())),
        ("to".into(), BusinessValueV2::Text("Alice".into())),
        ("subject".into(), BusinessValueV2::Text("report".into())),
    ];
    let controls = BusinessControlsV2::from_fields(&p, fields.clone()).unwrap();
    assert_eq!(controls.resource(), "A");
    assert_eq!(controls.destination(), "Alice");
    for quantity in [1, 2, u64::MAX] {
        let request = BusinessRequestV2::parse(&p, "request-1", &input(quantity)).unwrap();
        assert_eq!(
            controls.action_alternative(d(90)).unwrap(),
            request.action_alternative(d(90)).unwrap()
        );
    }
    let encoded = encode_business_controls_v2(&controls).unwrap();
    assert_eq!(decode_business_controls_v2(&encoded).unwrap(), controls);
    for extra in [
        ("body", BusinessValueV2::Text("dummy".into())),
        ("quantity", BusinessValueV2::Unsigned(1)),
    ] {
        let mut wrong = fields.clone();
        wrong.push((extra.0.into(), extra.1));
        assert!(BusinessControlsV2::from_fields(&p, wrong).is_err());
    }
    let mut missing = fields.clone();
    missing.pop();
    assert!(BusinessControlsV2::from_fields(&p, missing).is_err());
    let mut invisible = fields;
    invisible[1].1 = BusinessValueV2::Text("Ali\u{180e}ce".into());
    assert!(BusinessControlsV2::from_fields(&p, invisible).is_err());
    assert!(!format!("{controls:?}").contains("Alice"));
}

#[test]
fn task_draft_controls_enforce_encoded_bounds_and_canonical_wire() {
    let p = profile(
        ActionCodecProfileV2::McpToolsCallJsonV1,
        BusinessMagnitudeV2::FixedCount(1),
    );
    let fields = |subject: String| {
        vec![
            ("file".into(), BusinessValueV2::Text("A".into())),
            ("to".into(), BusinessValueV2::Text("Alice".into())),
            ("subject".into(), BusinessValueV2::Text(subject)),
        ]
    };
    // Quotes are valid visible text, but escaping doubles their encoded size.
    assert!(BusinessControlsV2::from_fields(&p, fields("\"".repeat(33 * 1024))).is_err());
    let controls = BusinessControlsV2::from_fields(&p, fields("report".into())).unwrap();
    let wire = encode_business_controls_v2(&controls).unwrap();
    let mut trailing = wire.clone();
    trailing.push(0);
    assert!(decode_business_controls_v2(&trailing).is_err());
    let mut noncanonical = wire.clone();
    noncanonical.splice(1..2, [0x18, 1]);
    assert!(decode_business_controls_v2(&noncanonical).is_err());
    for values in [
        br#"{"file":"A","to":"Alice","subject":"report","s\u0075bject":"other"}"#.as_slice(),
        br#"{ "file":"A","subject":"report","to":"Alice"}"#.as_slice(),
        br#"{"file":"A","subject":1,"to":"Alice"}"#.as_slice(),
    ] {
        let mut e = minicbor::Encoder::new(Vec::new());
        e.array(3)
            .unwrap()
            .u8(1)
            .unwrap()
            .bytes(&encode_business_profile_v2(&p).unwrap())
            .unwrap()
            .bytes(values)
            .unwrap();
        assert!(decode_business_controls_v2(&e.into_writer()).is_err());
    }
}

#[test]
fn task_draft_controls_bound_total_escaped_fields_not_only_individual_text() {
    let mut fields = vec![BusinessFieldV2::new(
        "body",
        BusinessFieldRoleV2::Payload,
        BusinessFieldTypeV2::Text,
    )
    .unwrap()];
    let mut values = Vec::new();
    for i in 0..31 {
        let name = format!("f{i:02}{}", "x".repeat(61));
        fields.push(
            BusinessFieldV2::new(
                &name,
                match i {
                    0 => BusinessFieldRoleV2::Resource,
                    1 => BusinessFieldRoleV2::Destination,
                    _ => BusinessFieldRoleV2::Parameter,
                },
                BusinessFieldTypeV2::Text,
            )
            .unwrap(),
        );
        values.push((name, BusinessValueV2::Text("\"".repeat(1024))));
    }
    let p = BusinessProfileV2::new(
        ActionCodecProfileV2::McpToolsCallJsonV1,
        "mail.send",
        d(1),
        d(2),
        TaskEffectV2::Send,
        BusinessMagnitudeV2::FixedCount(1),
        fields,
    )
    .unwrap();
    assert!(
        BusinessControlsV2::from_fields(&p, values).is_err(),
        "builder must not create a controls value that its own decoder rejects"
    );
}

#[test]
fn exact_only_controls_stay_byte_identical_with_derived_support() {
    // A control set with no derived fields must encode exactly as before, so
    // every previously signed root stays valid.
    let p = profile(
        ActionCodecProfileV2::McpToolsCallJsonV1,
        BusinessMagnitudeV2::CountField,
    );
    let fields = vec![
        ("file".into(), BusinessValueV2::Text("A".into())),
        ("to".into(), BusinessValueV2::Text("Alice".into())),
        ("subject".into(), BusinessValueV2::Text("report".into())),
    ];
    let controls = BusinessControlsV2::from_fields(&p, fields).unwrap();
    let encoded = encode_business_controls_v2(&controls).unwrap();
    // Discriminant 1, array of 3: the unchanged v1 layout.
    assert_eq!(encoded[0], 0x83);
    assert_eq!(encoded[1], 1);
    assert_eq!(decode_business_controls_v2(&encoded).unwrap(), controls);
}

#[test]
fn derived_destination_never_collides_with_a_literal_request() {
    let p = profile(
        ActionCodecProfileV2::McpToolsCallJsonV1,
        BusinessMagnitudeV2::CountField,
    );
    // "to" (Destination) is the value at result[0].participants of clause 1.
    let mut derived = std::collections::BTreeMap::new();
    derived.insert(
        "to".to_string(),
        ResultDerivedControlV2::new(
            1,
            vec!["participants".into(), "0".into()],
            BusinessFieldTypeV2::Text,
            256,
        )
        .unwrap(),
    );
    let controls = BusinessControlsV2::from_fields_with_derived(
        &p,
        vec![
            ("file".into(), BusinessValueV2::Text("A".into())),
            ("subject".into(), BusinessValueV2::Text("report".into())),
        ],
        derived,
    )
    .unwrap();
    // The derived alternative round-trips (discriminant 2).
    let encoded = encode_business_controls_v2(&controls).unwrap();
    assert_eq!(encoded[1], 2);
    assert_eq!(decode_business_controls_v2(&encoded).unwrap(), controls);

    let derived_alt = controls.action_alternative(d(90)).unwrap();
    // No literal "to" value can produce this alternative: the destination digest
    // lives under the derived domain, so every concrete request differs.
    for recipient in ["a@x.com", "attacker@evil.com", "Alice"] {
        let literal = BusinessControlsV2::from_fields(
            &p,
            vec![
                ("file".into(), BusinessValueV2::Text("A".into())),
                ("subject".into(), BusinessValueV2::Text("report".into())),
                ("to".into(), BusinessValueV2::Text(recipient.into())),
            ],
        )
        .unwrap();
        assert_ne!(literal.action_alternative(d(90)).unwrap(), derived_alt);
    }
    // The non-derived fields still bind exactly: a different resource still differs.
    let mut same_rule = std::collections::BTreeMap::new();
    same_rule.insert(
        "to".to_string(),
        ResultDerivedControlV2::new(
            1,
            vec!["participants".into(), "0".into()],
            BusinessFieldTypeV2::Text,
            256,
        )
        .unwrap(),
    );
    let other_resource = BusinessControlsV2::from_fields_with_derived(
        &p,
        vec![
            ("file".into(), BusinessValueV2::Text("B".into())),
            ("subject".into(), BusinessValueV2::Text("report".into())),
        ],
        same_rule,
    )
    .unwrap();
    assert_ne!(
        other_resource.action_alternative(d(90)).unwrap(),
        derived_alt
    );
}

#[test]
fn derived_controls_validate_coverage_disjointness_and_kind() {
    let p = profile(
        ActionCodecProfileV2::McpToolsCallJsonV1,
        BusinessMagnitudeV2::CountField,
    );
    let rule = |kind| ResultDerivedControlV2::new(1, vec!["x".into()], kind, 32).unwrap();

    // A field both exact and derived is rejected.
    let mut both = std::collections::BTreeMap::new();
    both.insert("to".to_string(), rule(BusinessFieldTypeV2::Text));
    assert!(BusinessControlsV2::from_fields_with_derived(
        &p,
        vec![
            ("file".into(), BusinessValueV2::Text("A".into())),
            ("subject".into(), BusinessValueV2::Text("report".into())),
            ("to".into(), BusinessValueV2::Text("Alice".into())),
        ],
        both,
    )
    .is_err());

    // A missing controlled field (neither exact nor derived) is rejected.
    let mut only_to = std::collections::BTreeMap::new();
    only_to.insert("to".to_string(), rule(BusinessFieldTypeV2::Text));
    assert!(BusinessControlsV2::from_fields_with_derived(
        &p,
        vec![("file".into(), BusinessValueV2::Text("A".into()))],
        only_to,
    )
    .is_err());

    // A derived rule whose kind mismatches the field kind is rejected
    // ("to" is Text, rule says Unsigned).
    let mut wrong_kind = std::collections::BTreeMap::new();
    wrong_kind.insert("to".to_string(), rule(BusinessFieldTypeV2::Unsigned));
    assert!(BusinessControlsV2::from_fields_with_derived(
        &p,
        vec![
            ("file".into(), BusinessValueV2::Text("A".into())),
            ("subject".into(), BusinessValueV2::Text("report".into())),
        ],
        wrong_kind,
    )
    .is_err());

    // Rule bounds: clause 0, empty/over-long path, zero max_bytes.
    assert!(
        ResultDerivedControlV2::new(0, vec!["x".into()], BusinessFieldTypeV2::Text, 8).is_err()
    );
    assert!(ResultDerivedControlV2::new(1, vec!["".into()], BusinessFieldTypeV2::Text, 8).is_err());
    assert!(
        ResultDerivedControlV2::new(1, vec!["x".into()], BusinessFieldTypeV2::Text, 0).is_err()
    );
}

#[test]
fn a_request_matches_the_owner_signed_derived_alternative_iff_the_rule_matches() {
    // This is the property G4 relies on: the kernel materializes a concrete
    // value into the derived field, then builds the request alternative with the
    // SAME rule the owner signed. It must equal the signed derived alternative,
    // regardless of the concrete value, and differ if the rule differs.
    let p = profile(
        ActionCodecProfileV2::McpToolsCallJsonV1,
        BusinessMagnitudeV2::CountField,
    );
    let rule = ResultDerivedControlV2::new(
        1,
        vec!["participants".into(), "0".into()],
        BusinessFieldTypeV2::Text,
        256,
    )
    .unwrap();
    let mut signed = std::collections::BTreeMap::new();
    signed.insert("to".to_string(), rule.clone());
    let root_alt = BusinessControlsV2::from_fields_with_derived(
        &p,
        vec![
            ("file".into(), BusinessValueV2::Text("A".into())),
            ("subject".into(), BusinessValueV2::Text("report".into())),
        ],
        signed.clone(),
    )
    .unwrap()
    .action_alternative(d(90))
    .unwrap();

    // The kernel's request carries whatever scalar it extracted into "to".
    for extracted in ["a@x.com", "attacker@evil.com", "anything"] {
        let request = BusinessRequestV2::parse(
            &p,
            "request-1",
            format!(
                r#"{{"jsonrpc":"2.0","id":"request-1","method":"tools/call","params":{{"name":"mail.send","arguments":{{"body":"hi","file":"A","quantity":1,"subject":"report","to":{extracted:?}}}}}}}"#
            )
            .as_bytes(),
        )
        .unwrap();
        // With the signed rule: equal (the concrete "to" value is ignored).
        assert_eq!(
            request
                .action_alternative_with_derived(d(90), &signed)
                .unwrap(),
            root_alt
        );
        // Without the rule (treating "to" as a literal): never equal.
        assert_ne!(request.action_alternative(d(90)).unwrap(), root_alt);
    }
    // A different rule (other path) produces a different alternative: a planner
    // that changes the edge cannot match the owner-signed one.
    let mut other = std::collections::BTreeMap::new();
    other.insert(
        "to".to_string(),
        ResultDerivedControlV2::new(1, vec!["organizer".into()], BusinessFieldTypeV2::Text, 256)
            .unwrap(),
    );
    let request = BusinessRequestV2::parse(
        &p,
        "request-1",
        br#"{"jsonrpc":"2.0","id":"request-1","method":"tools/call","params":{"name":"mail.send","arguments":{"body":"hi","file":"A","quantity":1,"subject":"report","to":"a@x.com"}}}"#,
    )
    .unwrap();
    assert_ne!(
        request
            .action_alternative_with_derived(d(90), &other)
            .unwrap(),
        root_alt
    );
}

#[test]
fn action_review_of_a_result_derived_field_renders_under_the_signed_rule() {
    // The owner signed: resource `file` = the value the kernel extracts from
    // clause 1's verified result at this path. G4 matched the action under that
    // rule, so the review must rebuild the alternative with it; the plain
    // (literal-domain) alternative differs and must not be accepted.
    let p = profile(
        ActionCodecProfileV2::McpToolsCallJsonV1,
        BusinessMagnitudeV2::FixedCount(1),
    );
    let rule = ResultDerivedControlV2::new(
        1,
        vec![
            "result".into(),
            "content".into(),
            "0".into(),
            "text".into(),
            "$json".into(),
            "0".into(),
            "id_".into(),
        ],
        BusinessFieldTypeV2::Text,
        64,
    )
    .unwrap();
    let derived: std::collections::BTreeMap<String, ResultDerivedControlV2> =
        [("file".to_string(), rule)].into_iter().collect();
    let source = br#"{"jsonrpc":"2.0","id":"request-1","method":"tools/call","params":{"name":"mail.send","arguments":{"body":"hello","file":"3","subject":"report","to":"Alice"}}}"#;
    let request = BusinessRequestV2::parse(&p, "request-1", source).unwrap();
    let action = request
        .action_alternative_with_derived(d(21), &derived)
        .unwrap();
    assert_ne!(action, request.action_alternative(d(21)).unwrap());
    let root = TaskAuthorizationV2::new(
        d(20),
        PrincipalIdV2::new([30; 32]),
        DurableTaskIdV2::new([31; 32]),
        1,
        d(32),
        d(33),
        UnixMillisV2::new(1),
        UnixMillisV2::new(1000),
        TaskEvidenceKindV2::AuthenticatedStructuredInput,
        d(34),
        d(35),
        vec![
            TaskAuthorizationClauseV2::new(
                1,
                vec![request.action_alternative(d(40)).unwrap()],
                1,
                1,
                1,
                vec![],
                false,
            )
            .unwrap(),
            TaskAuthorizationClauseV2::new(2, vec![action.clone()], 1, 1, 1, vec![1], false)
                .unwrap(),
        ],
    )
    .unwrap();
    let content = ActionContentV2::new(
        d(20),
        1,
        2,
        0,
        action,
        request.magnitude(),
        request.payload_digest(),
        d(22),
        d(23),
        d(24),
        d(25),
        1,
    )
    .unwrap();
    let display = render_task_action_display_v2(&content, &root, &request, &derived, 0, 0).unwrap();
    let decoded: serde_json::Value = serde_json::from_str(display.as_str()).unwrap();
    assert_eq!(decoded["rendering_schema"], 2);
    assert_eq!(decoded["resource"], "3");
    assert_eq!(decoded["derived_fields"]["file"]["source_clause"], 1);
    assert_eq!(decoded["derived_fields"]["file"]["path"][4], "$json");
    // Without the rule the matched action cannot be re-derived: refused.
    assert!(render_task_action_display_v2(
        &content,
        &root,
        &request,
        &std::collections::BTreeMap::new(),
        0,
        0
    )
    .is_err());
}

#[test]
fn task_execution_payload_carries_the_signed_derived_rules() {
    let p = profile(
        ActionCodecProfileV2::McpToolsCallJsonV1,
        BusinessMagnitudeV2::FixedCount(1),
    );
    let rule =
        ResultDerivedControlV2::new(1, vec!["id_".into()], BusinessFieldTypeV2::Text, 64).unwrap();
    let derived: std::collections::BTreeMap<String, ResultDerivedControlV2> =
        [("file".to_string(), rule)].into_iter().collect();
    let source = br#"{"jsonrpc":"2.0","id":"request-1","method":"tools/call","params":{"name":"mail.send","arguments":{"body":"hello","file":"3","subject":"report","to":"Alice"}}}"#;
    let request = BusinessRequestV2::parse(&p, "request-1", source).unwrap();
    let content_for = |action| {
        ActionContentV2::new(
            d(20),
            1,
            2,
            0,
            action,
            request.magnitude(),
            request.payload_digest(),
            d(22),
            d(23),
            d(24),
            d(25),
            1,
        )
        .unwrap()
    };
    let derived_content = content_for(
        request
            .action_alternative_with_derived(d(21), &derived)
            .unwrap(),
    );
    // Without the rules the matched derived action cannot be re-verified.
    assert!(TaskExecutionPayloadV2::new(derived_content.clone(), request.clone()).is_err());
    let payload =
        TaskExecutionPayloadV2::new_with_derived(derived_content, request.clone(), derived.clone())
            .unwrap();
    let bytes = encode_task_execution_payload_v2(&payload).unwrap();
    assert_eq!(&bytes[..2], &[0x86, 0x02]); // array(6), version 2
    let decoded = decode_task_execution_payload_v2(&bytes).unwrap();
    assert_eq!(decoded.derived(), &derived);
    assert_eq!(decoded, payload);
    // An exact-only payload keeps the version 1 encoding and carries no rules.
    let exact = TaskExecutionPayloadV2::new(
        content_for(request.action_alternative(d(21)).unwrap()),
        request.clone(),
    )
    .unwrap();
    let exact_bytes = encode_task_execution_payload_v2(&exact).unwrap();
    assert_eq!(&exact_bytes[..2], &[0x85, 0x01]);
    assert!(decode_task_execution_payload_v2(&exact_bytes)
        .unwrap()
        .derived()
        .is_empty());
    // Rules cannot be stripped (v2 relabeled as v1) or swapped for other rules.
    let mut relabeled = bytes.clone();
    relabeled[0] = 0x85;
    relabeled[1] = 0x01;
    assert!(decode_task_execution_payload_v2(&relabeled).is_err());
    let other = ResultDerivedControlV2::new(1, vec!["other".into()], BusinessFieldTypeV2::Text, 64)
        .unwrap();
    let swapped: std::collections::BTreeMap<String, ResultDerivedControlV2> =
        [("file".to_string(), other)].into_iter().collect();
    assert!(
        TaskExecutionPayloadV2::new_with_derived(decoded.content().clone(), request, swapped)
            .is_err()
    );
    // Canonical rule-set codec round-trips and refuses an empty v2 rule set.
    let rules = encode_result_derived_controls_v2(&derived).unwrap();
    assert_eq!(decode_result_derived_controls_v2(&rules).unwrap(), derived);
    assert!(decode_result_derived_controls_v2(&[0x80, 0x00]).is_err());
}

fn list_profile() -> BusinessProfileV2 {
    let mut fields = vec![
        BusinessFieldV2::new(
            "body",
            BusinessFieldRoleV2::Payload,
            BusinessFieldTypeV2::Text,
        )
        .unwrap(),
        BusinessFieldV2::new(
            "cc",
            BusinessFieldRoleV2::Parameter,
            BusinessFieldTypeV2::TextList,
        )
        .unwrap(),
        BusinessFieldV2::new(
            "end",
            BusinessFieldRoleV2::Parameter,
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
            "to",
            BusinessFieldRoleV2::Destination,
            BusinessFieldTypeV2::TextList,
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
        BusinessMagnitudeV2::FixedCount(1),
        fields,
    )
    .unwrap()
}

#[test]
fn text_lists_are_typed_controls_with_their_own_destination_domain() {
    // Only a destination or a parameter may be a list; the profile codec keeps it.
    for role in [
        BusinessFieldRoleV2::Resource,
        BusinessFieldRoleV2::Payload,
        BusinessFieldRoleV2::Magnitude,
    ] {
        assert!(BusinessFieldV2::new("x", role, BusinessFieldTypeV2::TextList).is_err());
    }
    let p = list_profile();
    let encoded = encode_business_profile_v2(&p).unwrap();
    assert_eq!(decode_business_profile_v2(&encoded).unwrap(), p);

    let request = |args: &str| {
        BusinessRequestV2::parse(&p, "r1", format!(
            r#"{{"jsonrpc":"2.0","id":"r1","method":"tools/call","params":{{"name":"mail.send","arguments":{args}}}}}"#
        ).as_bytes())
    };
    let two =
        request(r#"{"body":"hi","cc":[],"end":"","file":"A","to":["alice@x.com","bob@y.com"]}"#)
            .unwrap();
    assert_eq!(two.destination_items(), vec!["alice@x.com", "bob@y.com"]);
    assert!(two.destination_is_list());
    // The order and the membership of the list are both bound.
    let swapped =
        request(r#"{"body":"hi","cc":[],"end":"","file":"A","to":["bob@y.com","alice@x.com"]}"#)
            .unwrap();
    let one = request(r#"{"body":"hi","cc":[],"end":"","file":"A","to":["alice@x.com"]}"#).unwrap();
    assert_ne!(two.destination_digest(), swapped.destination_digest());
    assert_ne!(two.destination_digest(), one.destination_digest());
    // A one-item list never collides with the same single text destination.
    let text_profile = profile(
        ActionCodecProfileV2::McpToolsCallJsonV1,
        BusinessMagnitudeV2::FixedCount(1),
    );
    let text = BusinessRequestV2::parse(&text_profile, "r1", br#"{"jsonrpc":"2.0","id":"r1","method":"tools/call","params":{"name":"mail.send","arguments":{"body":"hi","file":"A","subject":"s","to":"alice@x.com"}}}"#).unwrap();
    assert_ne!(one.destination_digest(), text.destination_digest());
    // Controls built from typed values give the same alternative as the request.
    let controls = BusinessControlsV2::from_fields(
        &p,
        vec![
            ("cc".into(), BusinessValueV2::TextList(vec![])),
            ("end".into(), BusinessValueV2::Text(String::new())),
            ("file".into(), BusinessValueV2::Text("A".into())),
            (
                "to".into(),
                BusinessValueV2::TextList(vec!["alice@x.com".into(), "bob@y.com".into()]),
            ),
        ],
    )
    .unwrap();
    assert_eq!(
        controls.action_alternative(d(9)).unwrap(),
        two.action_alternative(d(9)).unwrap()
    );

    // An empty destination list is "no one", under its own digest.
    let nobody = request(r#"{"body":"hi","cc":[],"end":"","file":"A","to":[]}"#).unwrap();
    assert!(nobody.destination_items().is_empty());
    assert_ne!(nobody.destination_digest(), one.destination_digest());
    // Refused: a non-text item, an empty or padded item, a control character,
    // too many items, a list where text belongs, and an empty resource (only a
    // parameter text may be empty).
    let many = (0..33)
        .map(|i| format!("\"u{i}@x.com\""))
        .collect::<Vec<_>>()
        .join(",");
    for args in [
        r#"{"body":"hi","cc":[],"end":"","file":"A","to":["a@x.com",1]}"#.to_owned(),
        r#"{"body":"hi","cc":[""],"end":"","file":"A","to":["a@x.com"]}"#.to_owned(),
        r#"{"body":"hi","cc":[" a"],"end":"","file":"A","to":["a@x.com"]}"#.to_owned(),
        r#"{"body":"hi","cc":["a\nb"],"end":"","file":"A","to":["a@x.com"]}"#.to_owned(),
        format!(r#"{{"body":"hi","cc":[],"end":"","file":"A","to":[{many}]}}"#),
        r#"{"body":"hi","cc":"a@x.com","end":"","file":"A","to":["a@x.com"]}"#.to_owned(),
        r#"{"body":"hi","cc":[],"end":["x"],"file":"A","to":["a@x.com"]}"#.to_owned(),
        r#"{"body":"hi","cc":[],"end":"","file":"","to":["a@x.com"]}"#.to_owned(),
    ] {
        assert!(request(&args).is_err(), "{args}");
    }
}

#[test]
fn computed_rules_are_signed_bounded_and_plain_rules_keep_their_bytes() {
    let plain = ResultDerivedControlV2::new(1, vec!["start".into()], BusinessFieldTypeV2::Text, 32)
        .unwrap();
    let computed = plain
        .clone()
        .with_compute(ResultComputeV2::new(ResultComputeOpV2::AddMinutes, 60).unwrap())
        .unwrap();
    let rules = |r: &ResultDerivedControlV2| {
        let map: std::collections::BTreeMap<String, ResultDerivedControlV2> =
            [("end".to_string(), r.clone())].into_iter().collect();
        encode_result_derived_controls_v2(&map).unwrap()
    };
    let plain_bytes = rules(&plain);
    // [[ "end", [1, ["start"], 1, 32] ]]: the original four-element rule.
    assert_eq!(
        plain_bytes,
        vec![
            0x81, 0x82, 0x63, b'e', b'n', b'd', 0x84, 0x01, 0x81, 0x65, b's', b't', b'a', b'r',
            b't', 0x01, 0x18, 0x20
        ]
    );
    let computed_bytes = rules(&computed);
    assert_ne!(computed_bytes, plain_bytes);
    let decoded = decode_result_derived_controls_v2(&computed_bytes).unwrap();
    assert_eq!(decoded["end"], computed);
    assert_eq!(decoded["end"].compute().unwrap().amount(), 60);
    // A computed rule and a plain one (or another amount) sign different alternatives.
    let p = list_profile();
    let alternative = |rule: &ResultDerivedControlV2| {
        BusinessControlsV2::from_fields_with_derived(
            &p,
            vec![
                ("cc".into(), BusinessValueV2::TextList(vec![])),
                ("file".into(), BusinessValueV2::Text("A".into())),
                (
                    "to".into(),
                    BusinessValueV2::TextList(vec!["a@x.com".into()]),
                ),
            ],
            [("end".to_string(), rule.clone())].into_iter().collect(),
        )
        .unwrap()
        .action_alternative(d(9))
        .unwrap()
    };
    let other = plain
        .clone()
        .with_compute(ResultComputeV2::new(ResultComputeOpV2::AddMinutes, 30).unwrap())
        .unwrap();
    assert_ne!(alternative(&plain), alternative(&computed));
    assert_ne!(alternative(&other), alternative(&computed));
    // Bounds: amounts within range, and only a text field can be computed.
    assert!(ResultComputeV2::new(ResultComputeOpV2::AddDays, 3_661).is_err());
    assert!(ResultComputeV2::new(ResultComputeOpV2::AddMinutes, -527_041).is_err());
    assert!(
        ResultDerivedControlV2::new(1, vec!["x".into()], BusinessFieldTypeV2::TextList, 32)
            .unwrap()
            .with_compute(ResultComputeV2::new(ResultComputeOpV2::AddDays, 1).unwrap())
            .is_err()
    );
    // Unknown computation codes are refused.
    let mut unknown = computed_bytes.clone();
    let at = unknown.len() - 2; // [op, amount] = 0x82, op, 0x18 0x3c
    assert_eq!(&unknown[at - 2..], &[0x82, 0x01, 0x18, 0x3c][..2 + 2]);
    unknown[at - 1] = 0x09;
    assert!(decode_result_derived_controls_v2(&unknown).is_err());
}

#[test]
fn a_parameter_may_carry_more_text_than_a_resource_under_the_same_rules() {
    let p = list_profile();
    let request = |end: &str, file: &str| {
        let args = serde_json::json!({"body": "hi", "cc": [], "end": end, "file": file, "to": ["a@x.com"]});
        let call = serde_json::json!({"jsonrpc": "2.0", "id": "r1", "method": "tools/call",
            "params": {"name": "mail.send", "arguments": args}});
        BusinessRequestV2::parse(&p, "r1", call.to_string().as_bytes())
    };
    let long = "word ".repeat(400).trim_end().to_owned(); // about 2 KB
    assert!(request(&long, "A").is_ok());
    assert!(request("x".repeat(MAX_PARAMETER_TEXT_BYTES_V2).as_str(), "A").is_ok());
    // A resource keeps its 1 KB bound; a parameter its own; neither takes a
    // line break, padding or more than its bound.
    assert!(request("short", &long).is_err());
    assert!(request(&"x".repeat(MAX_PARAMETER_TEXT_BYTES_V2 + 1), "A").is_err());
    assert!(request(&format!("{long}\nmore"), "A").is_err());
    assert!(request(&format!(" {long}"), "A").is_err());
}
