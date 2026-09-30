use savana_kernel_protocol::v2::*;

fn d(n: u8) -> Digest32V2 {
    Digest32V2::new([n; 32])
}
fn context() -> TaskAuthorizationContextV2 {
    let profile = final_release_business_profile_v2(d(8), d(9)).unwrap();
    TaskAuthorizationContextV2::new(
        PrincipalIdV2::new([1; 32]),
        DurableTaskIdV2::new([2; 32]),
        d(3),
        d(4),
        7,
        d(5),
        UnixMillisV2::new(100),
        UnixMillisV2::new(500),
        Some((d(6), 2)),
        vec![TaskAuthorizationToolContextV2::new(d(7), "release.allowed".into(), profile).unwrap()],
        vec![d(10)],
    )
    .unwrap()
}

#[test]
fn private_context_binding_contains_only_verified_operator_metadata() {
    let context = context();
    let before = encode_task_authorization_context_v2(&context).unwrap();
    let binding: serde_json::Value =
        serde_json::from_str(&context.private_binding_json().unwrap()).unwrap();
    assert_eq!(binding, serde_json::json!({
        "schema": 1, "task": "02".repeat(32), "installation": "03".repeat(32),
        "manifest": "04".repeat(32), "generation": 7, "source": "05".repeat(32),
        "not_before": 100, "expires_at": 500
    }));
    assert_eq!(before, encode_task_authorization_context_v2(&context).unwrap());
    assert_eq!(context.final_result_resource(1, d(7)).unwrap(),
        fused_final_result_resource_v04(context.task(), 1, d(7)).unwrap());
    assert_ne!(context.final_result_resource(1, d(7)).unwrap(),
        context.final_result_resource(2, d(7)).unwrap());
    assert!(context.final_result_resource(0, d(7)).is_err());
    assert!(context.final_result_resource(1, d(8)).is_err());
}

#[test]
fn task_context_is_bounded_data_and_preserves_kernel_identity_when_building_draft() {
    let context = context();
    let encoded = encode_task_authorization_context_v2(&context).unwrap();
    assert_eq!(
        decode_task_authorization_context_v2(&encoded).unwrap(),
        context
    );
    for length in 0..encoded.len() {
        assert!(decode_task_authorization_context_v2(&encoded[..length]).is_err());
    }
    let mut trailing = encoded;
    trailing.push(0);
    assert!(decode_task_authorization_context_v2(&trailing).is_err());
    assert_eq!(context.authorization_identity(), Some((d(6), 2)));
    assert_eq!(context.pending_requests(), &[d(10)]);
    let tool = &context.tools()[0];
    let controls = BusinessControlsV2::from_fields(
        tool.profile(),
        vec![
            (
                "resource".into(),
                BusinessValueV2::Text(format!("input:{}", "05".repeat(32))),
            ),
            (
                "destination".into(),
                BusinessValueV2::Text(format!("application-turn:{}", "0b".repeat(32))),
            ),
        ],
    )
    .unwrap();
    let clause = TaskAuthorizationDraftClauseV2::new(
        1,
        vec![TaskAuthorizationDraftAlternativeV2::new(tool.descriptor_digest(), controls).unwrap()],
        1,
        1,
        1,
        vec![],
        false,
    )
    .unwrap();
    let draft = context.draft(d(6), vec![clause.clone()]).unwrap();
    assert_eq!(draft.source_input_digest(), d(5));
    assert_eq!(draft.task(), context.task());
    assert_eq!(draft.principal(), context.principal());
    assert_eq!(draft.revision(), 2);
    assert!(context.draft(d(12), vec![clause]).is_err());
    let json = serde_json::json!([{"clause_id":1,"alternatives":[{"descriptor_digest":"07".repeat(32),"controls":[["resource",format!("input:{}","05".repeat(32))],["destination",format!("application-turn:{}","0b".repeat(32))]]}],"maximum_single_magnitude":1,"total_magnitude_budget":1,"maximum_attempts":1,"predecessor_clause_ids":[],"retry_after_proven_no_effect":false}]).to_string();
    assert_eq!(
        context.draft_from_json(d(6), json.as_bytes()).unwrap(),
        draft
    );
    assert!(context.tools_json().unwrap().contains("release.allowed"));
    for bad in [
        json.replace("\"clause_id\":1", "\"clause_id\":1,\"clause_id\":2"),
        json.replace("\"clause_id\":1", "\"clause_id\":1,\"source\":\"forged\""),
        json.replace("\"maximum_attempts\":1", "\"maximum_attempts\":1.5"),
        json.replace(&"07".repeat(32), &"08".repeat(32)),
    ] {
        assert!(context.draft_from_json(d(6), bad.as_bytes()).is_err());
    }
    assert!(!format!("{context:?}").contains("release.allowed"));
    assert!(TaskAuthorizationContextV2::new(
        context.principal(),
        context.task(),
        d(3),
        d(4),
        0,
        d(5),
        UnixMillisV2::new(100),
        UnixMillisV2::new(500),
        None,
        vec![],
        vec![]
    )
    .is_err());
    assert!(TaskAuthorizationContextV2::new(
        context.principal(),
        context.task(),
        d(3),
        d(4),
        7,
        d(5),
        UnixMillisV2::new(500),
        UnixMillisV2::new(500),
        None,
        vec![],
        vec![]
    )
    .is_err());
    assert!(TaskAuthorizationContextV2::new(
        context.principal(),
        context.task(),
        d(3),
        d(4),
        7,
        d(5),
        UnixMillisV2::new(100),
        UnixMillisV2::new(500),
        None,
        vec![tool.clone(), tool.clone()],
        vec![]
    )
    .is_err());
    assert!(TaskAuthorizationContextV2::new(
        context.principal(),
        context.task(),
        d(3),
        d(4),
        7,
        d(5),
        UnixMillisV2::new(100),
        UnixMillisV2::new(500),
        None,
        vec![],
        vec![d(10), d(10)]
    )
    .is_err());
}

#[test]
fn draft_from_json_admits_a_result_derived_edge() {
    // The owner-side SDK can express a result-derived control (the kernel fills
    // it from a prior clause's verified result) alongside exact controls, and it
    // round-trips to the same draft as building it natively.
    let context = context();
    let tool = &context.tools()[0];
    let derived: std::collections::BTreeMap<String, ResultDerivedControlV2> = [(
        "destination".to_string(),
        ResultDerivedControlV2::new(1, vec!["recipient".to_string()], BusinessFieldTypeV2::Text, 64)
            .unwrap(),
    )]
    .into_iter()
    .collect();
    let controls = BusinessControlsV2::from_fields_with_derived(
        tool.profile(),
        vec![(
            "resource".into(),
            BusinessValueV2::Text(format!("input:{}", "05".repeat(32))),
        )],
        derived,
    )
    .unwrap();
    let clause = TaskAuthorizationDraftClauseV2::new(
        1,
        vec![TaskAuthorizationDraftAlternativeV2::new(tool.descriptor_digest(), controls).unwrap()],
        1,
        1,
        1,
        vec![],
        false,
    )
    .unwrap();
    let expected = context.draft(d(6), vec![clause]).unwrap();

    let json = serde_json::json!([{
        "clause_id": 1,
        "alternatives": [{
            "descriptor_digest": "07".repeat(32),
            "controls": [["resource", format!("input:{}", "05".repeat(32))]],
            "derived_controls": [["destination", {
                "source_clause": 1, "path": ["recipient"], "kind": 1, "max_bytes": 64
            }]]
        }],
        "maximum_single_magnitude": 1, "total_magnitude_budget": 1, "maximum_attempts": 1,
        "predecessor_clause_ids": [], "retry_after_proven_no_effect": false
    }])
    .to_string();
    assert_eq!(context.draft_from_json(d(6), json.as_bytes()).unwrap(), expected);

    // A derived edge that overlaps an exact control (both name the same field),
    // an unknown field type, or a zero source clause is refused.
    for bad in [
        json.replace("[\"resource\"", "[\"destination\""),
        json.replace("\"kind\":1", "\"kind\":9"),
        json.replace("\"source_clause\":1", "\"source_clause\":0"),
    ] {
        assert!(context.draft_from_json(d(6), bad.as_bytes()).is_err());
    }
}

#[test]
fn context_ingress_wire_has_no_caller_supplied_identity_or_profile() {
    let auth = IngressUiAuthorizationHandleV2::from_authority_entropy([1; 32]).unwrap();
    for session in [
        None,
        Some(InputSessionHandleV2::from_authority_entropy([2; 32]).unwrap()),
    ] {
        let op = KernelIngressOperationV2::GetTaskAuthorizationContext(
            GetTaskAuthorizationContextRequestV2::new(auth, session),
        );
        let bytes = encode_kernel_ingress_operation_v2(&op).unwrap();
        assert_eq!(
            decode_kernel_ingress_operation_v2(&bytes).unwrap().tag(),
            56
        );
        for len in 0..bytes.len() {
            assert!(decode_kernel_ingress_operation_v2(&bytes[..len]).is_err());
        }
        let mut trailing = bytes;
        trailing.push(0);
        assert!(decode_kernel_ingress_operation_v2(&trailing).is_err());
    }
    let request = IngressBrowserRequestV2::GetTaskAuthorizationContext {
        tab: IngressTabSessionCapabilityV2::from_authority_entropy([1; 32]).unwrap(),
        client_request_nonce: Nonce32V2::new([2; 32]),
    };
    let bytes = encode_ingress_browser_request_v2(&request).unwrap();
    assert!(matches!(
        decode_ingress_browser_request_v2(&bytes).unwrap(),
        IngressBrowserRequestV2::GetTaskAuthorizationContext { .. }
    ));
}
