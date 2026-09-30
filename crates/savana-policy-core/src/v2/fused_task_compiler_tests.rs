use super::*;
use crate::v2::durable::TestRollbackProtectedStateAnchorV2;
use crate::v2::*;
use ed25519_dalek::{Signer, SigningKey};
use savana_continuation_core::planning::{Mode, Role};
use savana_kernel_protocol::v2::*;

fn d(n: u8) -> Digest32V2 {
    Digest32V2::new([n; 32])
}
fn at(n: u64) -> UnixMillisV2 {
    UnixMillisV2::new(n)
}

fn fixture() -> (
    FusedTaskDraftV04,
    VerifiedTaskAuthorizationV2,
    ActiveToolRegistryV2,
) {
    let key = SigningKey::from_bytes(&[71; 32]);
    let key_id = Ed25519KeyIdV2::new([72; 32]);
    let version = VersionV2::new(1, 0, 0);
    let unsigned = UnsignedToolDescriptorV2::new_for_test(
        version,
        vec![RoleIdV2::new(1)],
        vec![],
        ProjectionIdV2::new(1),
        d(50),
    )
    .unwrap()
    .with_business_profile(
        BusinessProfileV2::new(
            ActionCodecProfileV2::McpToolsCallJsonV1,
            "mail.send",
            d(30),
            d(31),
            TaskEffectV2::Send,
            BusinessMagnitudeV2::FixedCount(1),
            vec![
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
                    "to",
                    BusinessFieldRoleV2::Destination,
                    BusinessFieldTypeV2::Text,
                )
                .unwrap(),
            ],
        )
        .unwrap(),
    )
    .unwrap();
    let digest = descriptor_digest_v2(&unsigned).unwrap();
    let mut message = b"SAVANA_TOOL_DESCRIPTOR_SIGNATURE_V2\0".to_vec();
    message.extend_from_slice(digest.as_bytes());
    let signed = SignedToolDescriptorV2::new_for_test(
        minicbor::to_vec(&unsigned).unwrap(),
        key_id,
        key.sign(&message).to_bytes(),
    );
    let publisher = VerifiedRegistryPublisherV2::from_verified_manifest(
        key_id,
        key.verifying_key().to_bytes(),
        at(100),
        at(1000),
    )
    .unwrap();
    let tool = signed.verify(&publisher, version, at(100)).unwrap();
    let registry = ActiveToolRegistryV2::intersect(
        &VerifiedToolRegistryV2::from_verified_descriptors(version, vec![tool]).unwrap(),
        &VerifiedPolicyToolSetV2::from_verified_policy(vec![
            VerifiedPolicyToolActivationV2::from_verified_policy(digest, 0, d(60)),
        ])
        .unwrap(),
        &VerifiedManifestToolConstraintSetV2::from_manifest(vec![
            VerifiedManifestToolConstraintV2::from_manifest(
                digest,
                unsigned.connector_retry_policy().maximum_attempts(),
                unsigned.connector_retry_policy().maximum_elapsed_ns(),
                vec![],
            )
            .unwrap(),
        ])
        .unwrap(),
    )
    .unwrap();
    let root = TaskAuthorizationV2::new(
        d(1),
        PrincipalIdV2::new([2; 32]),
        DurableTaskIdV2::new([4; 32]),
        1,
        d(2),
        d(3),
        at(100),
        at(1000),
        TaskEvidenceKindV2::AuthenticatedStructuredInput,
        d(6),
        d(7),
        (1..=2)
            .map(|id| {
                TaskAuthorizationClauseV2::new(
                    id,
                    vec![ActionAlternativeV2::new(
                        digest,
                        ActionCodecProfileV2::McpToolsCallJsonV1,
                        TaskEffectV2::Send,
                        d(id as u8 + 10),
                        d(12),
                        d(13),
                        MagnitudeUnitV2::Count,
                    )
                    .unwrap()],
                    1,
                    1,
                    1,
                    if id == 2 { vec![1] } else { vec![] },
                    false,
                )
                .unwrap()
            })
            .collect(),
    )
    .unwrap();
    let auth = VerifiedTaskAuthorizationV2::verify(
        &sign_task_authorization_v2(root, &key).unwrap(),
        &key.verifying_key(),
        PrincipalIdV2::new([2; 32]),
        DurableTaskIdV2::new([4; 32]),
        d(2),
        d(3),
        at(100),
    )
    .unwrap();
    let draft = FusedTaskDraftV04 {
        final_release: None,
        final_result_source: None,
        schema: 1,
        root: *auth.digest().as_bytes(),
        observer_scope: [80; 32],
        not_before: 100,
        expires_at: 900,
        operations: (1..=2)
            .map(|id| FusedTaskOperationV04 {
                id,
                clause: u64::from(id),
                descriptor: *digest.as_bytes(),
                tool: "mail.send".into(),
                bindings: ["body", "file", "to"]
                    .iter()
                    .enumerate()
                    .map(|(n, arg)| SlotBinding {
                        argument: (*arg).into(),
                        slot: [id as u8 * 10 + n as u8; 16],
                        result_of: None,
                        result_path: None,
                        result_max_bytes: None,
                        result_source_clause: None,
                    })
                    .collect(),
                after: vec![],
            })
            .collect(),
        templates: vec![Template {
            id: 1,
            order: vec![1, 2],
        }],
        rounds: vec![Round {
            observations: vec![],
            id: 1,
            opens_at: 110,
            advice_cut: 110,
            closes_at: 900,
            advisor: None,
            planner: [21; 32],
            model_profile: 1,
            mode: Mode::RegisteredTemplateV04,
            public_view: b"Choose registered continuation".to_vec(),
            template_ids: vec![1],
            question_codes: vec![],
            max_deliveries: 1,
        }],
        delivery_schedule: vec![FusedDeliverySlotV04 {
            id: 1,
            round: 1,
            role: Role::Planner,
            opens_at: 110,
            closes_at: 900,
        }],
        release_model_views: true,
        max_replacements: 0,
    };
    (draft, auth, registry)
}

#[test]
fn fused_task_compiler_final_source_is_explicit_signed_and_terminal() {
    let (mut draft, auth, registry) = fixture();
    let old = draft.signing_digest().unwrap();
    assert!(!serde_json::to_string(&draft)
        .unwrap()
        .contains("final_result_source"));
    draft.final_result_source = Some(2);
    assert!(draft.signing_digest().is_err()); // old schemas gain no new meaning
    draft.schema = 2;
    let signed = draft.signing_digest().unwrap();
    assert_ne!(old, signed);
    let p = compile_fused_task_v04(&draft, &auth, &registry, RoleIdV2::new(1), at(100)).unwrap();
    assert_eq!(p.schema, 3);
    assert_eq!(p.final_result_source, Some(2));
    assert!(!p.policy.rounds.iter().any(|r| !r.observations.is_empty()));
    assert!(p.execution_bindings.is_empty()); // retention is not execution approval
    for source in [0, 1, 3] {
        draft.final_result_source = Some(source);
        assert!(draft.signing_digest().is_err());
        assert!(
            compile_fused_task_v04(&draft, &auth, &registry, RoleIdV2::new(1), at(100)).is_err()
        );
    }
    draft.final_result_source = None;
    assert_ne!(signed, draft.signing_digest().unwrap());
    draft.final_result_source = Some(2);
    draft.templates.push(Template {
        id: 2,
        order: vec![2, 1],
    });
    assert!(draft.signing_digest().is_err());
}

#[test]
fn fused_task_compiler_uses_signed_tools_and_inherits_root_dependencies() {
    let (draft, auth, registry) = fixture();
    let p = compile_fused_task_v04(&draft, &auth, &registry, RoleIdV2::new(1), at(100)).unwrap();
    assert_eq!(p.policy.operations[1].after, vec![1]);
    assert_eq!(p.policy.operations[0].tool_class, 2);
    assert_eq!(p.policy.operations[0].action_template, 1);
    assert!(p.execution_bindings.is_empty()); // compilation is NOT execution consent
    assert_eq!(p.task, [4; 32]);
    assert_eq!(p.installation, [2; 32]);
    assert_eq!(p.policy.root, *auth.digest().as_bytes());
    assert_eq!(
        p.signing_digest().unwrap(),
        compile_fused_task_v04(&draft, &auth, &registry, RoleIdV2::new(1), at(100))
            .unwrap()
            .signing_digest()
            .unwrap()
    );
}

#[test]
fn fused_task_compiler_rejects_authority_schema_and_dependency_changes() {
    let (original, auth, registry) = fixture();
    for case in 0..13 {
        let mut draft = original.clone();
        match case {
            0 => draft.root = [99; 32],
            1 => draft.expires_at += 1,
            2 => draft.not_before -= 1,
            3 => draft.operations[0].descriptor = [99; 32],
            4 => draft.operations[0].tool = "delete_all_emails".into(),
            5 => {
                draft.operations[0].bindings.pop();
            }
            6 => draft.operations[0].bindings[2].argument = "cc".into(),
            7 => draft.operations[1].clause = 1,
            8 => {
                draft.operations.pop();
            }
            9 => draft.templates[0].order = vec![2, 1],
            10 => draft.operations[0].after = vec![2], // cycle with inherited edge
            11 => draft.operations[1].bindings[2].result_of = Some(1),
            _ => draft.operations[1].after = vec![1, 1],
        }
        assert!(
            compile_fused_task_v04(&draft, &auth, &registry, RoleIdV2::new(1), at(100)).is_err(),
            "case {case}"
        );
    }
    assert!(
        compile_fused_task_v04(&original, &auth, &registry, RoleIdV2::new(2), at(100)).is_err()
    );
    assert!(
        compile_fused_task_v04(&original, &auth, &registry, RoleIdV2::new(1), at(1000)).is_err()
    );
    assert!(compile_fused_task_v04(
        &original,
        &auth,
        &ActiveToolRegistryV2::intersect(
            &VerifiedToolRegistryV2::from_verified_descriptors(VersionV2::new(1, 0, 0), vec![])
                .unwrap(),
            &VerifiedPolicyToolSetV2::from_verified_policy(vec![]).unwrap(),
            &VerifiedManifestToolConstraintSetV2::from_manifest(vec![]).unwrap()
        )
        .unwrap(),
        RoleIdV2::new(1),
        at(100)
    )
    .is_err());
}

#[test]
fn fused_task_compiler_accepts_only_signed_payload_result_edges() {
    let (mut draft, auth, registry) = fixture();
    draft.operations[1].bindings[0].result_of = Some(1);
    let p = compile_fused_task_v04(&draft, &auth, &registry, RoleIdV2::new(1), at(100)).unwrap();
    assert_eq!(p.policy.schema, 2);
    assert_eq!(p.policy.operations[1].bindings[0].result_of, Some(1));
}

#[test]
fn fused_task_compiler_draft_rejects_unknown_and_duplicate_fields() {
    let (draft, _, _) = fixture();
    let raw = serde_json::to_vec(&draft).unwrap();
    let mut extra = raw.clone();
    extra.pop();
    extra.extend_from_slice(b",\"secret_override\":true}");
    assert!(serde_json::from_slice::<FusedTaskDraftV04>(&extra).is_err());
    let mut duplicate = raw;
    duplicate.pop();
    duplicate.extend_from_slice(b",\"schema\":1}");
    assert!(serde_json::from_slice::<FusedTaskDraftV04>(&duplicate).is_err());
}

#[test]
fn fused_task_compiler_signed_administration_is_atomic_replayable_and_requires_live_tools() {
    use crate::v2::durable_tests::task_store;
    let (draft, auth, registry) = fixture();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("kernel-g4-state-v2.cbor");
    let anchor = TestRollbackProtectedStateAnchorV2::default();
    let mut store = task_store(&path, [81; 32], anchor.clone());
    store
        .install_verified_task_authorization(auth.clone())
        .unwrap();
    let root_before = store
        .task_authorization_state(auth.material().task())
        .unwrap()
        .digest();
    let key = SigningKey::from_bytes(&[82; 32]);
    let mut command = ManagedAdminCommandV04 {
        schema: 1,
        installation: [2; 32],
        store: [0x54; 32],
        request: [83; 32],
        not_before: 100,
        expires_at: 900,
        operation: ManagedAdminOperationV04::CompilePlanning {
            task: [4; 32],
            draft: Box::new(draft.clone()),
        },
    };
    let proof = |c: &ManagedAdminCommandV04| {
        VerifiedManagedAdminCommandV04::verify(
            &c.canonical_bytes().unwrap(),
            &key.sign(&c.signing_digest().unwrap()).to_bytes(),
            &key.verifying_key(),
            d(2),
            d(0x54),
        )
        .unwrap()
    };
    let signed = proof(&command);
    assert!(store.apply_managed_admin_v04(&signed, at(100)).is_err());
    assert!(store
        .apply_managed_admin_with_tools_v04(&signed, &registry, RoleIdV2::new(2), at(100))
        .is_err());
    assert!(!store
        .fused_planning_enrolled_v04(auth.material().task())
        .unwrap());
    let receipt = store
        .apply_managed_admin_with_tools_v04(&signed, &registry, RoleIdV2::new(1), at(100))
        .unwrap();
    let compiled =
        compile_fused_task_v04(&draft, &auth, &registry, RoleIdV2::new(1), at(100)).unwrap();
    assert!(
        receipt.result()
            == &ManagedAdminResultV04::PlanningEnrolled {
                task: [4; 32],
                profile: compiled.signing_digest().unwrap()
            }
    );
    assert_eq!(
        store
            .task_authorization_state(auth.material().task())
            .unwrap()
            .digest(),
        root_before
    );
    drop(store);
    let mut store = task_store(&path, [81; 32], anchor);
    // Exact historical receipt replay works after expiry, without re-enrollment.
    assert_eq!(
        store.apply_managed_admin_v04(&signed, at(1001)).unwrap(),
        receipt
    );
    // Same request ID with changed content is not a new authorization.
    if let ManagedAdminOperationV04::CompilePlanning { draft, .. } = &mut command.operation {
        draft.rounds[0].public_view = b"changed".to_vec();
    }
    assert!(store
        .apply_managed_admin_with_tools_v04(&proof(&command), &registry, RoleIdV2::new(1), at(100))
        .is_err());
    assert_eq!(
        store.apply_managed_admin_v04(&signed, at(1001)).unwrap(),
        receipt
    );
}

#[test]
fn fused_task_compiler_bounds_model_budget_by_owner_attempts() {
    // Fixture root: two operation clauses, one signed attempt each.
    let (original, auth, registry) = fixture();
    let compile = |draft: &FusedTaskDraftV04| {
        compile_fused_task_v04(draft, &auth, &registry, RoleIdV2::new(1), at(100))
    };
    assert!(compile(&original).is_ok());
    let mut two = original.clone();
    two.rounds[0].max_deliveries = 2;
    assert!(compile(&two).is_ok());
    // A well-formed advised round: one advisor + one planner delivery = 2.
    let mut advised = original.clone();
    advised.rounds[0].advisor = Some([22; 32]);
    advised.rounds[0].advice_cut = 500;
    advised.delivery_schedule[0].opens_at = 500;
    assert!(compile(&advised).is_ok());
    for case in 0..4 {
        let mut draft = original.clone();
        match case {
            0 => draft.rounds[0].max_deliveries = 3,
            1 => draft.rounds[0].max_deliveries = 8,
            // An advisor delivery is a model call too.
            2 => {
                draft = advised.clone();
                draft.rounds[0].max_deliveries = 2;
            }
            // A replacement needs a later round.
            _ => draft.max_replacements = 1,
        }
        assert!(compile(&draft).is_err(), "case {case}");
    }
}

#[test]
fn fused_owner_view_is_fixed_canonical_json_of_the_owner_request() {
    assert_eq!(
        fused_owner_view_v04("Who is invited?", &[1]).unwrap(),
        br#"{"permitted_template_ids":[1],"request":"Who is invited?"}"#.to_vec()
    );
    // Same bytes as the experiment's canonical JSON (sorted keys, raw UTF-8).
    assert_eq!(
        fused_owner_view_v04("日历 \"x\"\n", &[1, 2]).unwrap(),
        "{\"permitted_template_ids\":[1,2],\"request\":\"日历 \\\"x\\\"\\n\"}".as_bytes()
    );
    let (mut draft, _, _) = fixture();
    draft.rounds[0].public_view = fused_owner_view_v04("Who is invited?", &[1]).unwrap();
    assert!(check_fused_owner_views_v04(&draft, Some("Who is invited?")).is_ok());
    assert!(check_fused_owner_views_v04(&draft, Some("Who else is invited?")).is_err());
    assert!(check_fused_owner_views_v04(&draft, None).is_err());
    draft.rounds[0].template_ids = vec![2];
    assert!(check_fused_owner_views_v04(&draft, Some("Who is invited?")).is_err());
    draft.rounds[0].public_view.clear();
    assert!(check_fused_owner_views_v04(&draft, None).is_ok());
}

#[test]
fn compiler_allows_a_result_edge_into_a_nonpayload_field_structurally() {
    // A path-extracted edge into the Destination ("to") is structurally valid;
    // whether the owner signed THIS path is checked at G4, not here.
    let (base, auth, registry) = fixture();
    let mut draft = base.clone();
    draft.operations[1].after = vec![1];
    let to = draft.operations[1]
        .bindings
        .iter_mut()
        .find(|b| b.argument == "to")
        .unwrap();
    to.result_of = Some(1);
    to.result_path = Some(vec!["participants".into(), "0".into()]);
    to.result_max_bytes = Some(256);
    assert!(compile_fused_task_v04(&draft, &auth, &registry, RoleIdV2::new(1), at(100)).is_ok());

    // The same edge onto the payload ("body") is rejected: the payload takes the
    // whole result, never a path extraction.
    let mut on_payload = base.clone();
    on_payload.operations[1].after = vec![1];
    let body = on_payload.operations[1]
        .bindings
        .iter_mut()
        .find(|b| b.argument == "body")
        .unwrap();
    body.result_of = Some(1);
    body.result_path = Some(vec!["participants".into()]);
    body.result_max_bytes = Some(256);
    assert!(compile_fused_task_v04(&on_payload, &auth, &registry, RoleIdV2::new(1), at(100)).is_err());

    // A whole-result edge (no path) onto a non-payload field is rejected.
    let mut whole_to = base.clone();
    whole_to.operations[1].after = vec![1];
    let to = whole_to.operations[1]
        .bindings
        .iter_mut()
        .find(|b| b.argument == "to")
        .unwrap();
    to.result_of = Some(1);
    assert!(compile_fused_task_v04(&whole_to, &auth, &registry, RoleIdV2::new(1), at(100)).is_err());
}
