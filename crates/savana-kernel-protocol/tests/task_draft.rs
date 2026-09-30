use savana_kernel_protocol::v2::*;

#[test]
fn task_browser_submission_is_typed_tab_bound_and_canonical() {
    let tab = IngressTabSessionCapabilityV2::from_authority_entropy([91; 32]).unwrap();
    let nonce = Nonce32V2::new([92; 32]);
    for request in [
        IngressBrowserRequestV2::EstablishTaskAuthorization {
            tab,
            client_request_nonce: nonce,
            draft: draft(vec![clause(1, vec![])], 1).unwrap(),
        },
        IngressBrowserRequestV2::PrepareTaskAuthorizationApproval {
            tab,
            client_request_nonce: nonce,
            draft: draft(vec![clause(1, vec![])], 1).unwrap(),
        },
        IngressBrowserRequestV2::CommitTaskAuthorizationApproval {
            tab,
            client_request_nonce: nonce,
            request_digest: d(93),
        },
        IngressBrowserRequestV2::RevokeTaskAuthorization {
            tab,
            client_request_nonce: nonce,
            draft: draft(vec![clause(1, vec![])], 1).unwrap(),
        },
    ] {
        let encoded = encode_ingress_browser_request_v2(&request).unwrap();
        let decoded = decode_ingress_browser_request_v2(&encoded).unwrap();
        assert_eq!(decoded.tab(), tab);
        assert_eq!(decoded.client_request_nonce(), nonce);
        assert_eq!(
            encode_ingress_browser_request_v2(&decoded).unwrap(),
            encoded
        );
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(decode_ingress_browser_request_v2(&trailing).is_err());
        let mut unknown = encoded.clone();
        unknown[1] = 23;
        assert!(decode_ingress_browser_request_v2(&unknown).is_err());
    }
}

fn d(n: u8) -> Digest32V2 {
    Digest32V2::new([n; 32])
}
fn controls(
    resource: &str,
    destination: &str,
    magnitude: BusinessMagnitudeV2,
) -> BusinessControlsV2 {
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
        fields.sort_by(|a, b| a.name().cmp(b.name()));
    }
    let p = BusinessProfileV2::new(
        ActionCodecProfileV2::McpToolsCallJsonV1,
        "mail.send",
        d(1),
        d(2),
        TaskEffectV2::Send,
        magnitude,
        fields,
    )
    .unwrap();
    BusinessControlsV2::from_fields(
        &p,
        vec![
            ("file".into(), BusinessValueV2::Text(resource.into())),
            ("to".into(), BusinessValueV2::Text(destination.into())),
            (
                "subject".into(),
                BusinessValueV2::Text("A \"report\" <script>".into()),
            ),
        ],
    )
    .unwrap()
}
fn clause(id: u64, predecessors: Vec<u64>) -> TaskAuthorizationDraftClauseV2 {
    TaskAuthorizationDraftClauseV2::new(
        id,
        vec![
            TaskAuthorizationDraftAlternativeV2::new(
                d(3),
                controls("A", "Alice", BusinessMagnitudeV2::CountField),
            )
            .unwrap(),
            TaskAuthorizationDraftAlternativeV2::new(
                d(3),
                controls("B", "Bob", BusinessMagnitudeV2::CountField),
            )
            .unwrap(),
        ],
        2,
        4,
        3,
        predecessors,
        true,
    )
    .unwrap()
}
fn draft(
    clauses: Vec<TaskAuthorizationDraftClauseV2>,
    revision: u64,
) -> Result<TaskAuthorizationDraftV2, savana_kernel_protocol::ProtocolError> {
    TaskAuthorizationDraftV2::new(
        d(4),
        PrincipalIdV2::new([5; 32]),
        DurableTaskIdV2::new([6; 32]),
        revision,
        d(7),
        d(8),
        9,
        UnixMillisV2::new(10),
        UnixMillisV2::new(100),
        d(11),
        clauses,
    )
}

#[test]
fn task_draft_roundtrip_preserves_joint_relations_and_displays_actual_limits() {
    let value = draft(vec![clause(1, vec![]), clause(2, vec![1])], 1).unwrap();
    let encoded = encode_task_authorization_draft_v2(&value).unwrap();
    assert_eq!(value, decode_task_authorization_draft_v2(&encoded).unwrap());
    let text = value.render_approval_text().unwrap();
    for expected in [
        "Alice",
        "Bob",
        "CountField",
        "Payload is chosen later",
        "maximum_attempts",
        "predecessor_clause_ids",
    ] {
        assert!(text.as_str().contains(expected), "missing {expected}");
    }
    let projection: serde_json::Value = serde_json::from_str(text.as_str()).unwrap();
    assert_eq!(
        projection["clauses"][0]["alternatives"][0]["fields"]["file"],
        "A"
    );
    assert_eq!(
        projection["clauses"][0]["alternatives"][0]["fields"]["to"],
        "Alice"
    );
    assert_eq!(
        projection["clauses"][0]["alternatives"][1]["fields"]["file"],
        "B"
    );
    assert_eq!(
        projection["clauses"][0]["alternatives"][1]["fields"]["to"],
        "Bob"
    );
    let a = value
        .to_unsigned_authorization(TaskEvidenceKindV2::ApprovedDraft, d(12))
        .unwrap();
    let b = value
        .to_unsigned_authorization(TaskEvidenceKindV2::ApprovedDraft, d(13))
        .unwrap();
    assert_ne!(
        task_authorization_digest_v2(&a).unwrap(),
        task_authorization_digest_v2(&b).unwrap()
    );
    assert_eq!(
        a.rendering_digest(),
        approval_display_digest_v2(text.as_bytes())
    );
    assert_eq!(
        a.clauses()[0].alternatives()[0],
        controls("A", "Alice", BusinessMagnitudeV2::CountField)
            .action_alternative(d(3))
            .unwrap()
    );
    // Neither parsing a draft nor converting it yields a signature/verified permit.
    for secret in ["Alice", "report", "Bob"] {
        assert!(!format!("{value:?}").contains(secret));
    }
}

#[test]
fn structured_task_submission_is_a_separate_canonical_ingress_operation() {
    let request = EstablishTaskAuthorizationRequestV2::new(
        InputSessionHandleV2::from_authority_entropy([0x70; 32]).unwrap(),
        draft(vec![clause(1, vec![])], 1).unwrap(),
        Nonce32V2::new([0x71; 32]),
    )
    .unwrap();
    let op = KernelIngressOperationV2::EstablishTaskAuthorization(request);
    assert_eq!(op.tag(), 51);
    let bytes = encode_kernel_ingress_operation_v2(&op).unwrap();
    assert_eq!(
        encode_kernel_ingress_operation_v2(&decode_kernel_ingress_operation_v2(&bytes).unwrap())
            .unwrap(),
        bytes
    );
    assert!(decode_kernel_agent_operation_v2(&bytes).is_err());
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(decode_kernel_ingress_operation_v2(&trailing).is_err());
    let response = EstablishTaskAuthorizationResponseV2::new(d(10), d(11)).unwrap();
    let bytes = encode_establish_task_authorization_response_v2(&response).unwrap();
    assert_eq!(
        decode_establish_task_authorization_response_v2(&bytes).unwrap(),
        response
    );
}

#[test]
fn task_draft_rejects_invalid_graph_units_limits_and_wire() {
    assert!(draft(vec![], 1).is_err());
    assert!(draft(vec![clause(1, vec![2]), clause(2, vec![1])], 1).is_err());
    assert!(draft(vec![clause(1, vec![2])], 1).is_err());
    assert!(draft(vec![clause(2, vec![]), clause(1, vec![])], 1).is_err());
    assert!(draft(vec![clause(1, vec![])], 0).is_err());
    let alt = |rule| {
        TaskAuthorizationDraftAlternativeV2::new(d(3), controls("A", "Alice", rule)).unwrap()
    };
    assert!(TaskAuthorizationDraftClauseV2::new(
        1,
        vec![alt(BusinessMagnitudeV2::FixedCount(3))],
        2,
        4,
        3,
        vec![],
        false
    )
    .is_err());
    assert!(TaskAuthorizationDraftClauseV2::new(
        1,
        vec![
            alt(BusinessMagnitudeV2::FixedCount(1)),
            alt(BusinessMagnitudeV2::Utf8PayloadBytes)
        ],
        2,
        4,
        3,
        vec![],
        false
    )
    .is_err());
    let value = draft(vec![clause(1, vec![])], 1).unwrap();
    let bytes = encode_task_authorization_draft_v2(&value).unwrap();
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(decode_task_authorization_draft_v2(&trailing).is_err());
    let mut noncanonical = bytes.clone();
    noncanonical.splice(1..2, [0x18, 1]);
    assert!(decode_task_authorization_draft_v2(&noncanonical).is_err());
    for i in 0..bytes.len() {
        assert!(decode_task_authorization_draft_v2(&bytes[..i]).is_err());
    }
    assert!(decode_task_authorization_draft_v2(&vec![
        0;
        MAX_TASK_AUTHORIZATION_DRAFT_BYTES_V2 + 1
    ])
    .is_err());
    assert_ne!(
        task_authorization_draft_digest_v2(&value).unwrap(),
        task_authorization_draft_digest_v2(&draft(vec![clause(1, vec![])], 2).unwrap()).unwrap()
    );
}

#[test]
fn task_root_approval_is_separate_from_ingress_and_action_approval() {
    let value = draft(vec![clause(1, vec![])], 1).unwrap();
    let text = value.render_approval_text().unwrap();
    let key = ed25519_dalek::SigningKey::from_bytes(&[31; 32]);
    let binding = ApprovalBindingV2::TaskAuthorization {
        authorization_id: value.authorization_id(),
        task: value.task(),
        revision: value.revision(),
        change: TaskAuthorizationChangeV2::Create,
        draft_digest: task_authorization_draft_digest_v2(&value).unwrap(),
    };
    let envelope = SignedApprovalEnvelopeV2::sign(
        UnsignedApprovalEnvelopeV2::new(
            d(7),
            d(8),
            9,
            ApprovalPurposeV2::TaskAuthorization,
            Nonce32V2::new([32; 32]),
            Nonce32V2::new([33; 32]),
            binding,
            value.principal(),
            task_authorization_draft_digest_v2(&value).unwrap(),
            approval_display_digest_v2(text.as_bytes()),
            text,
            Some(d(34)),
            ServiceIdentityV2::new([35; 32]),
            UnixMillisV2::new(10),
            UnixMillisV2::new(90),
        )
        .unwrap(),
        &key,
    )
    .unwrap();
    let encoded = encode_signed_approval_envelope_v2(&envelope).unwrap();
    assert_eq!(
        envelope,
        decode_signed_approval_envelope_v2(&encoded).unwrap()
    );
    let key_id = derive_ed25519_key_id_v2(key.verifying_key().to_bytes());
    let verify = |purpose| {
        envelope.verify(
            key_id,
            key.verifying_key().to_bytes(),
            d(7),
            d(8),
            9,
            purpose,
            value.principal(),
            UnixMillisV2::new(50),
        )
    };
    assert_eq!(
        verify(ApprovalPurposeV2::TaskAuthorization)
            .unwrap()
            .binding(),
        binding
    );
    for purpose in [
        ApprovalPurposeV2::Ingress,
        ApprovalPurposeV2::ToolExecution,
        ApprovalPurposeV2::FinalRelease,
        ApprovalPurposeV2::ConnectorRegistration,
    ] {
        assert!(verify(purpose).is_err());
    }
}

#[test]
fn task_root_approval_handle_and_query_are_ingress_only() {
    let handle = TaskAuthorizationApprovalRecordHandleV2::from_authority_entropy([41; 32]).unwrap();
    let registered = RegisteredApprovalV2::TaskAuthorization {
        approval: handle,
        display_authentication:
            ApprovalDisplayAuthenticationTransferCapabilityV2::from_authority_entropy([42; 32])
                .unwrap(),
    };
    let bytes = encode_registered_approval_v2(registered).unwrap();
    assert_eq!(
        registered,
        decode_registered_approval_v2(&bytes, EndpointRoleV2::IngressApproval).unwrap()
    );
    assert!(decode_registered_approval_v2(&bytes, EndpointRoleV2::AgentApproval).is_err());
    let operation =
        ApprovalServiceOperationV2::GetTaskAuthorizationApprovalSettlement { approval: handle };
    assert_eq!(operation.role(), EndpointRoleV2::IngressApproval);
    assert_eq!(operation.tag(), 25);
    let request = ApprovalServiceRequestV2::new(
        RequestIdV2::new([44; 16]),
        UnixMillisV2::new(100),
        operation,
    )
    .unwrap();
    let request_bytes = encode_approval_service_request_v2(&request).unwrap();
    assert_eq!(
        request,
        decode_approval_service_request_v2(&request_bytes, EndpointRoleV2::IngressApproval, 25)
            .unwrap()
    );
    assert!(
        decode_approval_service_request_v2(&request_bytes, EndpointRoleV2::AgentApproval, 25)
            .is_err()
    );
    assert!(decode_approval_service_request_v2(
        &request_bytes,
        EndpointRoleV2::IngressApproval,
        21
    )
    .is_err());
    assert!(kernel_service_operation_has_error_contract_v2(
        EndpointRoleV2::IngressApproval,
        25
    ));
    assert!(!kernel_service_operation_has_error_contract_v2(
        EndpointRoleV2::AgentApproval,
        25
    ));
    let key = AuthorityHandleKeyV2::from_entropy([43; 32]).unwrap();
    let old = IngressApprovalRecordHandleV2::from_authority_entropy([41; 32]).unwrap();
    assert_ne!(
        handle.authority_commitment(&key),
        old.authority_commitment(&key)
    );
}

#[test]
fn task_draft_every_root_context_field_changes_the_draft_and_display() {
    let base = draft(vec![clause(1, vec![])], 1).unwrap();
    let build = |n| {
        TaskAuthorizationDraftV2::new(
            if n == 0 {
                d(90)
            } else {
                base.authorization_id()
            },
            if n == 1 {
                PrincipalIdV2::new([90; 32])
            } else {
                base.principal()
            },
            if n == 2 {
                DurableTaskIdV2::new([90; 32])
            } else {
                base.task()
            },
            if n == 3 { 2 } else { base.revision() },
            if n == 4 {
                d(90)
            } else {
                base.installation_digest()
            },
            if n == 5 {
                d(90)
            } else {
                base.manifest_digest()
            },
            if n == 6 {
                90
            } else {
                base.deployment_generation()
            },
            if n == 7 {
                UnixMillisV2::new(11)
            } else {
                base.not_before()
            },
            if n == 8 {
                UnixMillisV2::new(101)
            } else {
                base.expires_at()
            },
            if n == 9 {
                d(90)
            } else {
                base.source_input_digest()
            },
            if n == 10 {
                vec![clause(2, vec![])]
            } else {
                base.clauses().to_vec()
            },
        )
        .unwrap()
    };
    for n in 0..11 {
        let changed = build(n);
        assert_ne!(
            task_authorization_draft_digest_v2(&base).unwrap(),
            task_authorization_draft_digest_v2(&changed).unwrap(),
            "context field {n}"
        );
        assert_ne!(
            base.render_approval_text().unwrap(),
            changed.render_approval_text().unwrap(),
            "display context {n}"
        );
    }
    let decomposed = TaskAuthorizationDraftAlternativeV2::new(
        d(3),
        controls("e\u{301}", "Alice", BusinessMagnitudeV2::FixedCount(1)),
    )
    .unwrap();
    let clause =
        TaskAuthorizationDraftClauseV2::new(1, vec![decomposed], 1, 1, 1, vec![], false).unwrap();
    assert!(
        draft(vec![clause], 1).is_err(),
        "never normalize the displayed resource into a different identity"
    );
}

#[test]
fn task_draft_aggregate_limits_refuse_instead_of_truncating() {
    let alternatives: Vec<_> = (0..64)
        .map(|i| {
            TaskAuthorizationDraftAlternativeV2::new(
                d(3),
                controls(
                    &format!("A{i:02}{}", "x".repeat(1021)),
                    "Alice",
                    BusinessMagnitudeV2::FixedCount(1),
                ),
            )
            .unwrap()
        })
        .collect();
    let clauses = (1..=16)
        .map(|id| {
            TaskAuthorizationDraftClauseV2::new(id, alternatives.clone(), 1, 1, 1, vec![], false)
                .unwrap()
        })
        .collect();
    assert!(draft(clauses, 1).is_err());
}

fn cbor_bytes(content: &[u8]) -> Vec<u8> {
    let mut out = match content.len() {
        n if n < 24 => vec![0x40 | n as u8],
        n if n < 256 => vec![0x58, n as u8],
        n => vec![0x59, (n >> 8) as u8, n as u8],
    };
    out.extend_from_slice(content);
    out
}

fn splice(bytes: &[u8], old: &[u8], new: &[u8]) -> Vec<u8> {
    let at = bytes
        .windows(old.len())
        .position(|w| w == old)
        .expect("controls embedded in draft");
    let mut out = bytes[..at].to_vec();
    out.extend_from_slice(new);
    out.extend_from_slice(&bytes[at + old.len()..]);
    out
}

#[test]
fn a_result_derived_edge_is_admitted_and_shown_to_the_owner() {
    // A derived control is admitted into a root draft; the approval text shows
    // the owner the EDGE (which clause's result, which path), not a value it
    // cannot see, and marks the rendering schema as derived (2).
    let exact = controls("A", "Alice", BusinessMagnitudeV2::CountField);
    let mut rules = std::collections::BTreeMap::new();
    rules.insert(
        "to".to_string(),
        ResultDerivedControlV2::new(
            1,
            vec!["participants".into(), "0".into()],
            BusinessFieldTypeV2::Text,
            256,
        )
        .unwrap(),
    );
    let edge = BusinessControlsV2::from_fields_with_derived(
        exact.profile(),
        vec![
            ("file".into(), BusinessValueV2::Text("A".into())),
            (
                "subject".into(),
                BusinessValueV2::Text("A \"report\" <script>".into()),
            ),
        ],
        rules,
    )
    .unwrap();
    let edge_alt = TaskAuthorizationDraftAlternativeV2::new(d(3), edge.clone()).unwrap();
    // Clause 1 is the prior read; clause 2 sends using its result.
    let read = TaskAuthorizationDraftClauseV2::new(
        1,
        vec![TaskAuthorizationDraftAlternativeV2::new(
            d(3),
            controls("A", "Alice", BusinessMagnitudeV2::CountField),
        )
        .unwrap()],
        1,
        1,
        1,
        vec![],
        false,
    )
    .unwrap();
    let send = TaskAuthorizationDraftClauseV2::new(2, vec![edge_alt], 1, 1, 1, vec![1], false).unwrap();
    let draft = TaskAuthorizationDraftV2::new(
        d(4),
        PrincipalIdV2::new([5; 32]),
        DurableTaskIdV2::new([6; 32]),
        1,
        d(7),
        d(8),
        9,
        UnixMillisV2::new(10),
        UnixMillisV2::new(100),
        d(9),
        vec![read, send],
    )
    .unwrap();
    // Round-trips on the wire (discriminant 2 controls carried through).
    let bytes = encode_task_authorization_draft_v2(&draft).unwrap();
    assert_eq!(decode_task_authorization_draft_v2(&bytes).unwrap(), draft);
    // The owner sees the derived edge and the derived rendering schema.
    let text = draft.render_approval_text().unwrap();
    let projection: serde_json::Value = serde_json::from_str(text.as_str()).unwrap();
    assert_eq!(projection["rendering_schema"], 2);
    let derived = &projection["clauses"][1]["alternatives"][0]["derived_fields"]["to"];
    assert_eq!(derived["source_clause"], 1);
    assert_eq!(derived["path"][0], "participants");
    assert_eq!(derived["path"][1], "0");
    assert_eq!(derived["type"], "Text");
    // The signed root's alternative carries the derived (rule) digest.
    let signed = draft
        .to_unsigned_authorization(TaskEvidenceKindV2::ApprovedDraft, d(12))
        .unwrap();
    assert_eq!(
        signed.clauses()[1].alternatives()[0],
        edge.action_alternative(d(3)).unwrap()
    );
}
