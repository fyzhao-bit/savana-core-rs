mod fused_compiler_tests {
    include!("v04_fused_input_admission_tests.rs");
    include!("v04_fused_actions_tests.rs");
    include!("v04_fused_approval_recovery_tests.rs");
    include!("v04_fused_approval_delivery_tests.rs");
    include!("v04_fused_dispatch_tests.rs");
    include!("v04_private_session_tests.rs");
    use super::super::fused_compiler::{FusedLocalValueBindingV04, FusedPreparedCandidateV04};
    use super::*;
    use savana_continuation_core::planning::{PlanChoice, PlanProposal, Role};
    use savana_kernel_protocol::v2::ValueHandleV2;
    use savana_policy_core::v2::{
        FusedPlanningProfileV04, FusedPlanningUpdateV04 as U, VerifiedFusedPlanningProfileV04,
        VerifiedResolvedRelationSetV2,
    };

    #[test]
    fn fused_task_compiler_binds_separate_final_release_clause_before_execution() {
        use savana_policy_core::v2::{compile_fused_task_v04, FusedTaskDraftV04};
        let (f, _) = business_proposal_fixture_with_result_release("A", "Alice", true, false, true);
        let s = &f.authority.sessions[0];
        let p = f.authority.policy.as_ref().unwrap();
        let root = p
            .durable
            .task_authorization_state(s.durable_task_id)
            .unwrap();
        let tool = p
            .active_tools
            .resolve_class(ToolClassIdV2::new(31), s.role, UnixMillisV2::new(202))
            .unwrap();
        let release = p
            .active_tools
            .resolve_class(ToolClassIdV2::new(34), s.role, UnixMillisV2::new(202))
            .unwrap();
        let draft: FusedTaskDraftV04 = serde_json::from_value(serde_json::json!({
            "schema":3, "root":root.authorization().digest().as_bytes(), "observer_scope":vec![1u8;32],
            "not_before":100, "expires_at":900,
            "operations":(1..=2).map(|id| serde_json::json!({
                "id":id,"clause":id,"descriptor":tool.descriptor().descriptor_digest().as_bytes(),
                "tool":"mail.allowed","after":[], "bindings":(["body","file","to"].iter().enumerate()
                    .map(|(i,arg)| serde_json::json!({"argument":arg,"slot":vec![id as u8*10+i as u8;16]})).collect::<Vec<_>>())
            })).collect::<Vec<_>>(),
            "templates":[{"id":1,"order":[1,2]}],
            "rounds":[{"id":1,"opens_at":200,"advice_cut":200,"closes_at":300,
                "advisor":null,"planner":vec![2u8;32],"model_profile":1,"mode":"registered_template_v04",
                "public_view":[],"template_ids":[1],"question_codes":[],"max_deliveries":1}],
            "delivery_schedule":[],"release_model_views":false,"max_replacements":0,
            "final_result_source":2,"final_release":{"clause":3,
                "descriptor":release.descriptor().descriptor_digest().as_bytes(),"turn":vec![4u8;32]}
        })).unwrap();
        let compile = |d: &FusedTaskDraftV04| {
            compile_fused_task_v04(
                d,
                root.authorization(),
                &p.active_tools,
                s.role,
                UnixMillisV2::new(202),
            )
        };
        let compiled = compile(&draft).unwrap();
        assert_eq!(compiled.schema, 4);
        assert!(compiled.final_release == draft.final_release);
        assert_eq!(
            compiled.policy.operations.len(),
            2,
            "publication is never a model-selectable operation"
        );
        let original = draft.signing_digest().unwrap();
        for case in 0..5 {
            let mut changed = draft.clone();
            match case {
                0 => changed.final_release.as_mut().unwrap().turn = [5; 32],
                1 => {
                    changed.final_release.as_mut().unwrap().descriptor =
                        *tool.descriptor().descriptor_digest().as_bytes()
                }
                2 => changed.final_release.as_mut().unwrap().clause = 2,
                3 => changed.final_release = None,
                _ => changed.schema = 2,
            }
            assert!(compile(&changed).is_err());
            assert_ne!(changed.signing_digest().ok(), Some(original));
        }
    }

    fn bindings(request: &ProposeToolCallRequestV2) -> Vec<FusedLocalValueBindingV04> {
        request
            .arguments()
            .iter()
            .enumerate()
            .map(|(i, a)| FusedLocalValueBindingV04 {
                slot: [i as u8 + 1; 16],
                value: a.value(),
            })
            .collect()
    }
    fn install(f: &mut PlannerAuthorityFixtureV2, request: &ProposeToolCallRequestV2, count: u16) {
        let operations = (1..=count).map(|id| serde_json::json!({
            "id":id,"tool_class":31,"action_template":21,"after":[],
            "bindings":request.arguments().iter().enumerate().map(|(i,a)| serde_json::json!({
                "argument":a.name().as_str(),"slot":vec![i as u8+1;16]
            })).collect::<Vec<_>>()
        })).collect::<Vec<_>>();
        install_operations(f, operations);
    }
    fn install_operations(f: &mut PlannerAuthorityFixtureV2, operations: Vec<serde_json::Value>) {
        install_operations_until(f, operations, 1000);
    }
    fn install_operations_until(
        f: &mut PlannerAuthorityFixtureV2,
        operations: Vec<serde_json::Value>,
        expires_at: u64,
    ) {
        install_operations_with_observation(f, operations, expires_at, false, false);
    }
    fn install_operations_with_observation(
        f: &mut PlannerAuthorityFixtureV2,
        operations: Vec<serde_json::Value>,
        expires_at: u64,
        observe: bool,
        final_result: bool,
    ) {
        let count = u16::try_from(operations.len()).unwrap();
        let result_edges = operations.iter().any(|op| {
            op["bindings"]
                .as_array()
                .unwrap()
                .iter()
                .any(|b| b.get("result_of").is_some())
        });
        let s = &f.authority.sessions[0];
        let release_descriptor = f
            .authority
            .policy
            .as_ref()
            .unwrap()
            .active_tools
            .resolve_class(ToolClassIdV2::new(34), s.role, UnixMillisV2::new(202))
            .map(|r| *r.descriptor().descriptor_digest().as_bytes());
        let owner = &mut f.authority.policy.as_mut().unwrap().durable;
        let root = owner.task_authorization_state(s.durable_task_id).unwrap();
        let mut profile: FusedPlanningProfileV04 = serde_json::from_value(serde_json::json!({
            "schema":1,"installation":f.authority.config.installation_id.as_bytes(),
            "task":s.durable_task_id.as_bytes(),"not_before":1,"expires_at":expires_at,
            "policy":{"schema":if result_edges {2} else {1},"root":root.authorization().digest().as_bytes(),"observer_scope":vec![1u8;32],
                "operations":operations,"max_replacements":1,
                "templates":[{"id":1,"order":(1..=count).collect::<Vec<_>>()},
                    {"id":2,"order":if result_edges {(1..=count).collect::<Vec<_>>()} else {(1..=count).rev().collect::<Vec<_>>()} }],
                "rounds":(1..=2).map(|id| serde_json::json!({"id":id,
                    "opens_at":200+(id-1)*100,"advice_cut":200+(id-1)*100,"closes_at":300+(id-1)*100,
                    "advisor":null,"planner":vec![2u8;32],"model_profile":1,"mode":"registered_template_v04",
                    "public_view":[],"template_ids":[1,2],"question_codes":[],"max_deliveries":1
                })).collect::<Vec<_>>()}
        })).unwrap();
        if observe {
            profile.schema = 2;
            profile.policy.schema = 3;
            profile.release_model_views = true;
            let r = &mut profile.policy.rounds[1];
            r.opens_at = 1300;
            r.advice_cut = 1300;
            r.closes_at = 1400;
            r.observations = vec![
                savana_continuation_core::planning_observation::ResultObservation {
                    source: 1,
                    path: vec![
                        "result".into(),
                        "structuredContent".into(),
                        "savana_status".into(),
                    ],
                },
            ];
            profile.delivery_schedule = profile
                .policy
                .rounds
                .iter()
                .map(|r| savana_policy_core::v2::FusedDeliverySlotV04 {
                    id: r.id,
                    round: r.id,
                    role: Role::Planner,
                    opens_at: r.opens_at,
                    closes_at: r.closes_at,
                })
                .collect();
        }
        if final_result {
            profile.schema = 3;
            profile.final_result_source = Some(count);
            profile.policy.templates[1].order = (1..=count).collect();
            if let Some(descriptor) = release_descriptor {
                profile.schema = 4;
                profile.final_release = Some(savana_policy_core::v2::FusedFinalReleaseV04 {
                    clause: 3,
                    descriptor,
                    turn: [4; 32],
                });
            }
        }
        let key = SigningKey::from_bytes(&[0x21; 32]);
        let proof = VerifiedFusedPlanningProfileV04::verify(
            &serde_json::to_vec(&profile).unwrap(),
            &key.sign(&profile.signing_digest().unwrap()).to_bytes(),
            &key.verifying_key(),
            root.authorization(),
            UnixMillisV2::new(202),
        )
        .unwrap();
        owner
            .install_fused_planning_v04(proof, UnixMillisV2::new(202))
            .unwrap();
        // Bind the existing signed fixture rules to the actual local deployment;
        // the compiler must not trust a generation supplied by its caller alone.
        let roots = OperationalTrustRootSetV2::new_declassification_signed_for_test(
            Digest32V2::new([0xa0; 32]),
            1,
            None,
            vec![OperationalTrustRootSetItemV2::new(
                OperationalTrustRootPurposeV2::DeclassificationAuthority,
                SigningKey::from_bytes(&[0x9f; 32])
                    .verifying_key()
                    .to_bytes(),
                1,
                1,
                10_000,
            )
            .unwrap()],
            1,
            10_000,
            &SigningKey::from_bytes(&[0x9e; 32]),
            1,
        )
        .unwrap();
        let p = f.authority.policy.as_mut().unwrap();
        let rules = p.declassification_rules.snapshot().unwrap();
        p.declassification_rules =
            crate::v2_declassification_policy::ActiveDeclassificationRuleSetV2::new_for_binding(
                (*rules).clone(),
                std::sync::Arc::new(roots),
                f.authority.config.installation_id,
                s.active_state_manifest_digest,
                7,
            )
            .unwrap();
    }
    fn choose(
        f: &mut PlannerAuthorityFixtureV2,
        round: u16,
        template: u16,
        activate: bool,
        at: u64,
    ) {
        choose_with_schedule(f, round, template, activate, at, false);
    }
    fn choose_with_schedule(
        f: &mut PlannerAuthorityFixtureV2,
        round: u16,
        template: u16,
        activate: bool,
        at: u64,
        scheduled: bool,
    ) {
        let task = f.authority.sessions[0].durable_task_id;
        let owner = &mut f.authority.policy.as_mut().unwrap().durable;
        let now = UnixMillisV2::new(at);
        let mut update = |u| {
            let rev = owner.fused_planning_status_v04(task, now).unwrap().revision;
            owner.update_fused_planning_v04(task, rev, u, now).unwrap()
        };
        let result = if scheduled {
            update(U::ClaimScheduledDelivery { recipient: [2; 32] })
        } else {
            update(U::FreezeEnvelope { round });
            update(U::ReserveDelivery {
                round,
                role: Role::Planner,
                recipient: [2; 32],
            })
        };
        let view = result.view_for_release_check().unwrap();
        update(U::AcceptPlan {
            round,
            sender: [2; 32],
            bytes: serde_json::to_vec(&PlanProposal {
                schema: 1,
                job: view.job,
                view: view.commitment(),
                choice: PlanChoice::RegisteredTemplate { template },
            })
            .unwrap(),
        });
        if activate {
            let status = owner.fused_planning_status_v04(task, now).unwrap();
            owner
                .update_fused_planning_v04(
                    task,
                    status.revision,
                    U::Activate {
                        round,
                        expected_plan_revision: status.active_plan_revision,
                    },
                    now,
                )
                .unwrap();
        }
    }
    fn compile(
        f: &PlannerAuthorityFixtureV2,
        b: &[FusedLocalValueBindingV04],
        at: u64,
    ) -> Result<FusedPreparedCandidateV04, KernelAgentAuthorityErrorV2> {
        f.authority.prepare_active_fused_actions_v04(
            f.run,
            b,
            &f.values,
            f.authority.sessions[0].active_state_manifest_digest,
            7,
            UnixMillisV2::new(at),
        )
    }
    fn disk(f: &PlannerAuthorityFixtureV2) -> Vec<u8> {
        std::fs::read(f._directory.path().join("kernel-g4-state-v2.cbor")).unwrap()
    }

    fn approve_recipes(f: &mut PlannerAuthorityFixtureV2, candidate: &FusedPreparedCandidateV04) {
        approve_recipes_until(f, candidate, 350);
    }
    fn approve_recipes_until(
        f: &mut PlannerAuthorityFixtureV2,
        candidate: &FusedPreparedCandidateV04,
        expires_at: u64,
    ) {
        use savana_policy_core::v2::{
            FusedRecipeApprovalV04, FusedRecipeBindingV04, ManagedAdminCommandV04,
            ManagedAdminOperationV04, VerifiedManagedAdminCommandV04,
        };
        let s = &f.authority.sessions[0];
        let owner = &mut f.authority.policy.as_mut().unwrap().durable;
        let root = owner.task_authorization_state(s.durable_task_id).unwrap();
        let mut bindings = candidate
            .actions
            .iter()
            .map(|a| FusedRecipeBindingV04 {
                operation: a.reference.operation,
                recipe: a.recipe.commitment(),
            })
            .collect::<Vec<_>>();
        let active = owner
            .active_fused_plan_v04(s.durable_task_id, UnixMillisV2::new(202))
            .unwrap();
        let result_edges = active
            .compiled()
            .operations()
            .iter()
            .any(|o| o.bindings.iter().any(|b| b.result_of.is_some()));
        if result_edges {
            for op in active.compiled().operations() {
                if op.bindings.iter().any(|b| b.result_of.is_some()) {
                    bindings.retain(|b| b.operation != op.id);
                    bindings.push(FusedRecipeBindingV04 {
                        operation: op.id,
                        recipe: FusedRecipeApprovalV04::result_recipe(
                            candidate.profile_digest,
                            active.input_commitment().unwrap(),
                            op,
                        )
                        .unwrap(),
                    });
                }
            }
        }
        bindings.sort_by_key(|b| b.operation);
        let a = FusedRecipeApprovalV04 {
            inputs_digest: if result_edges {
                active.input_commitment()
            } else {
                None
            },
            schema: 1,
            recipe_schema: if result_edges { 2 } else { 1 },
            installation: *f.authority.config.installation_id.as_bytes(),
            manifest: *s.active_state_manifest_digest.as_bytes(),
            task: *s.durable_task_id.as_bytes(),
            root: *root.authorization().digest().as_bytes(),
            profile: candidate.profile_digest,
            deployment_generation: 7,
            not_before: 202,
            expires_at,
            bindings,
        };
        let key = SigningKey::from_bytes(&[0x21; 32]);
        let command = ManagedAdminCommandV04 {
            schema: 1,
            installation: a.installation,
            store: [0x9b; 32],
            request: [90; 32],
            not_before: 202,
            expires_at,
            operation: ManagedAdminOperationV04::ApprovePlanningRecipes {
                approval_signature: key.sign(&a.signing_digest().unwrap()).to_bytes().to_vec(),
                approval: Box::new(a),
            },
        };
        let proof = VerifiedManagedAdminCommandV04::verify(
            &command.canonical_bytes().unwrap(),
            &key.sign(&command.signing_digest().unwrap()).to_bytes(),
            &key.verifying_key(),
            f.authority.config.installation_id,
            Digest32V2::new([0x9b; 32]),
        )
        .unwrap();
        owner
            .apply_managed_admin_v04(&proof, UnixMillisV2::new(202))
            .unwrap();
    }

    fn pin_inputs(
        f: &mut PlannerAuthorityFixtureV2,
        b: &[FusedLocalValueBindingV04],
        time: u64,
    ) -> Result<(), KernelAgentAuthorityErrorV2> {
        f.authority.pin_active_fused_inputs_v04(
            f.run,
            b,
            &f.values,
            f.authority.sessions[0].active_state_manifest_digest,
            7,
            UnixMillisV2::new(time),
        )
    }

    #[test]
    fn fused_inputs_new_process_handles_keep_real_g4_recipe_and_identity() {
        let (mut f, request) = business_proposal_fixture("A", "Alice");
        install(&mut f, &request, 2);
        choose(&mut f, 1, 1, true, 202);
        let b = bindings(&request);
        let before = compile(&f, &b, 202).unwrap();
        pin_inputs(&mut f, &b, 202).unwrap();
        let original_disk = disk(&f);
        pin_inputs(&mut f, &b, 202).unwrap();
        assert_eq!(disk(&f), original_disk);
        approve_recipes(&mut f, &before);
        let s = &f.authority.sessions[0];
        let manifest = s.active_state_manifest_digest;
        // Recreate only the value owner; authenticated session recovery is a
        // separate prerequisite, supplied here by the private test fixture.
        let mut fresh = KernelValueOwnerV2::new(4, 32).unwrap();
        let run = fresh
            .open_verified_run(
                s.producer_identity,
                s.durable_run_id,
                manifest,
                UnixMillisV2::new(202),
                s.expires_at,
                s.policy_allowed_effects,
            )
            .unwrap();
        assert!(fresh
            .resolve_g4_value(run, b[0].value, UnixMillisV2::new(202))
            .is_err());
        f.run = run;
        f.authority.sessions[0].run = run;
        f.values = fresh;
        let restored = f
            .authority
            .restore_active_fused_inputs_v04(
                run,
                &mut f.values,
                manifest,
                7,
                UnixMillisV2::new(202),
            )
            .unwrap();
        assert_ne!(restored[0].value, b[0].value);
        let again = f
            .authority
            .restore_active_fused_inputs_v04(
                run,
                &mut f.values,
                manifest,
                7,
                UnixMillisV2::new(202),
            )
            .unwrap();
        for (a, b) in restored.iter().zip(&again) {
            assert_eq!(a.slot, b.slot);
            assert_eq!(a.value, b.value);
        }
        let after = compile(&f, &restored, 202).unwrap();
        for (a, b) in before.actions.iter().zip(&after.actions) {
            assert_eq!(a.recipe.commitment(), b.recipe.commitment());
            assert!(b.matches_recipe_approval);
        }
        choose(&mut f, 2, 2, true, 302);
        assert!(compile(&f, &restored, 302)
            .unwrap()
            .actions
            .iter()
            .all(|a| a.matches_recipe_approval));
    }

    #[test]
    fn fused_inputs_pin_refuses_substitution_and_late_registration() {
        let (mut f, request) = business_proposal_fixture("A", "Alice");
        install(&mut f, &request, 1);
        choose(&mut f, 1, 1, true, 202);
        let mut b = bindings(&request);
        pin_inputs(&mut f, &b, 202).unwrap();
        let raw = f
            .values
            .resolve_g4_value(f.run, b[0].value, UnixMillisV2::new(202))
            .unwrap();
        let snapshot = f
            .authority
            .policy
            .as_ref()
            .unwrap()
            .durable
            .recover_fused_inputs_v04(
                f.authority.sessions[0].durable_task_id,
                7,
                UnixMillisV2::new(202),
            )
            .unwrap();
        let old = snapshot
            .inputs()
            .iter()
            .find(|i| i.identity() == raw.value_internal_id())
            .unwrap();
        // Same bytes and provenance, but independently minted identity.
        b[0].value = f
            .values
            .register_verified_value(f.run, old.copy_value().unwrap(), old.provenance().clone())
            .unwrap()
            .handle();
        let original = disk(&f);
        assert!(compile(&f, &b, 202).is_err());
        assert!(pin_inputs(&mut f, &b, 202).is_err());
        assert_eq!(disk(&f), original);
        let (mut f, request) = business_proposal_fixture("A", "Alice");
        install(&mut f, &request, 1);
        choose(&mut f, 1, 1, true, 202);
        let b = bindings(&request);
        let candidate = compile(&f, &b, 202).unwrap();
        approve_recipes(&mut f, &candidate);
        let original = disk(&f);
        assert!(pin_inputs(&mut f, &b, 202).is_err());
        assert_eq!(disk(&f), original);
    }

    #[test]
    fn fused_inputs_restore_rechecks_generation_root_and_capacity_without_partial_writes() {
        let (mut f, request) = business_proposal_fixture("A", "Alice");
        install(&mut f, &request, 1);
        choose(&mut f, 1, 1, true, 202);
        pin_inputs(&mut f, &bindings(&request), 202).unwrap();
        let s = &f.authority.sessions[0];
        let manifest = s.active_state_manifest_digest;
        let mut fresh = KernelValueOwnerV2::new(4, 1).unwrap();
        let run = fresh
            .open_verified_run(
                s.producer_identity,
                s.durable_run_id,
                manifest,
                UnixMillisV2::new(202),
                s.expires_at,
                s.policy_allowed_effects,
            )
            .unwrap();
        f.run = run;
        f.authority.sessions[0].run = run;
        f.values = fresh;
        assert!(f
            .authority
            .restore_active_fused_inputs_v04(
                run,
                &mut f.values,
                manifest,
                7,
                UnixMillisV2::new(202)
            )
            .is_err());
        assert!(format!("{:?}", f.values).contains("value_count: 0"));
        assert!(f
            .authority
            .restore_active_fused_inputs_v04(
                run,
                &mut f.values,
                manifest,
                8,
                UnixMillisV2::new(202)
            )
            .is_err());
        f.authority
            .policy
            .as_mut()
            .unwrap()
            .durable
            .revoke_task_authorization(f.authority.sessions[0].durable_task_id)
            .unwrap();
        assert!(f
            .authority
            .restore_active_fused_inputs_v04(
                run,
                &mut f.values,
                manifest,
                7,
                UnixMillisV2::new(202)
            )
            .is_err());
    }

    #[test]
    fn fused_compiler_signed_recipe_approval_survives_reorder_but_never_grants_execution() {
        let (mut f, request) = business_proposal_fixture("A", "Alice");
        install(&mut f, &request, 2);
        choose(&mut f, 1, 1, true, 202);
        let b = bindings(&request);
        let initial = compile(&f, &b, 202).unwrap();
        assert!(initial.actions.iter().all(|a| !a.matches_recipe_approval));
        approve_recipes(&mut f, &initial);
        let approved = compile(&f, &b, 202).unwrap();
        assert!(approved
            .actions
            .iter()
            .all(|a| a.matches_recipe_approval && !a.matches_profile_approval));
        choose(&mut f, 2, 2, true, 302);
        let reordered = compile(&f, &b, 302).unwrap();
        assert_eq!(reordered.actions[0].reference.operation, 2);
        assert!(reordered
            .actions
            .iter()
            .all(|a| a.matches_recipe_approval && !a.matches_profile_approval));
        assert!(compile(&f, &b, 350)
            .unwrap()
            .actions
            .iter()
            .all(|a| !a.matches_recipe_approval));
        let owner = &f.authority.policy.as_ref().unwrap().durable;
        let active = owner
            .active_fused_plan_v04(initial.task, UnixMillisV2::new(302))
            .unwrap();
        assert!(!active.recipe_approved(1, &initial.actions[0].recipe, 8, UnixMillisV2::new(302)));
        assert!(f.authority.intents.is_empty());
        assert!(f.authority.executions.is_empty());
        assert!(f
            .authority
            .propose_tool_call(
                RequestIdV2::new([99; 16]),
                b"legacy cannot use recipe approval",
                &request,
                &f.values,
                f.caller_identity,
                f.authority.sessions[0].active_state_manifest_digest,
                7,
                UnixMillisV2::new(302),
            )
            .is_err());
    }

    #[test]
    fn fused_compiler_builds_real_g4_request_without_write_handle_or_authority() {
        let (mut f, request) = business_proposal_fixture("A", "Alice");
        let b = bindings(&request);
        install(&mut f, &request, 1);
        choose(&mut f, 1, 1, false, 202);
        assert!(compile(&f, &b, 202).is_err());
        let task = f.authority.sessions[0].durable_task_id;
        let owner = &mut f.authority.policy.as_mut().unwrap().durable;
        let status = owner
            .fused_planning_status_v04(task, UnixMillisV2::new(202))
            .unwrap();
        owner
            .update_fused_planning_v04(
                task,
                status.revision,
                U::Activate {
                    round: 1,
                    expected_plan_revision: 0,
                },
                UnixMillisV2::new(202),
            )
            .unwrap();
        let before = disk(&f);
        let handles = f.authority.plan_steps.len();
        let candidate = compile(&f, &b, 202).unwrap();
        assert_eq!(candidate.task, task);
        assert_eq!(candidate.activation_revision, 1);
        assert_eq!(candidate.actions.len(), 1);
        let a = &candidate.actions[0];
        assert_eq!(a.reference.operation, 1);
        assert!(!a.matches_profile_approval); // protocol-only enrollment grants no effect
        let actual = a.prepared.business_request.canonical_json();
        let json: serde_json::Value = serde_json::from_slice(&actual).unwrap();
        assert_eq!(json["params"]["arguments"]["file"], "A");
        assert_eq!(json["params"]["arguments"]["to"], "Alice");
        assert_eq!(json["params"]["arguments"]["body"], "private payload");
        let payload = savana_kernel_protocol::v2::decode_task_execution_payload_v2(
            &a.prepared.dispatch_plaintext,
        )
        .unwrap();
        assert_eq!(payload.request().canonical_json(), actual);
        assert_eq!(
            candidate.provenance.run_internal_id(),
            f.authority.sessions[0].durable_run_id
        );
        assert_eq!(
            compile(&f, &b, 202).unwrap().actions[0].execution_commitment,
            a.execution_commitment
        );
        assert_eq!(disk(&f), before);
        assert_eq!(f.authority.plan_steps.len(), handles);
        assert!(f.authority.intents.is_empty());
        assert!(f.authority.executions.is_empty());
        assert!(f
            .authority
            .propose_tool_call(
                RequestIdV2::new([1; 16]),
                b"cached legacy",
                &request,
                &f.values,
                f.caller_identity,
                f.authority.sessions[0].active_state_manifest_digest,
                7,
                UnixMillisV2::new(202)
            )
            .is_err());
    }

    #[test]
    fn fused_compiler_rejects_missing_extra_duplicate_alias_and_foreign_values() {
        let (mut f, request) = business_proposal_fixture("A", "Alice");
        install(&mut f, &request, 1);
        choose(&mut f, 1, 1, true, 202);
        let b = bindings(&request);
        let before = disk(&f);
        assert!(compile(&f, &b[..2], 202).is_err());
        for mutation in 0..5 {
            let mut b = bindings(&request);
            match mutation {
                0 => b.push(FusedLocalValueBindingV04 {
                    slot: [9; 16],
                    value: f.prompt,
                }),
                1 => b[1].slot = b[0].slot,
                2 => b[1].value = b[0].value,
                3 => b[0].value = ValueHandleV2::from_authority_entropy([0xfa; 32]).unwrap(),
                _ => b[0].slot = [0; 16],
            }
            assert!(compile(&f, &b, 202).is_err());
        }
        assert_eq!(disk(&f), before);
    }

    #[test]
    fn fused_compiler_uses_g4_root_tuple_checks_not_model_field_names() {
        let (mut f, request) = business_proposal_fixture("A", "Bob"); // individually valid fields, forbidden pair
        install(&mut f, &request, 1);
        choose(&mut f, 1, 1, true, 202);
        let before = disk(&f);
        assert!(compile(&f, &bindings(&request), 202).is_err());
        assert_eq!(disk(&f), before);
        assert!(f.authority.intents.is_empty());
    }

    #[test]
    fn fused_compiler_rechecks_root_manifest_generation_limits_and_owned_value_lifetime() {
        let (mut f, request) = business_proposal_fixture("A", "Alice");
        install(&mut f, &request, 1);
        choose(&mut f, 1, 1, true, 202);
        let b = bindings(&request);
        assert!(compile(&f, &b, 201).is_err()); // durable clock floor
        assert!(compile(&f, &b, 1000).is_err()); // profile expired
        for (manifest, generation) in [
            (Digest32V2::new([9; 32]), 7),
            (f.authority.sessions[0].active_state_manifest_digest, 8),
        ] {
            assert!(f
                .authority
                .prepare_active_fused_actions_v04(
                    f.run,
                    &b,
                    &f.values,
                    manifest,
                    generation,
                    UnixMillisV2::new(202)
                )
                .is_err());
        }
        let limits = f.authority.sessions[0].signed_planner_policy.limits;
        f.authority.sessions[0].signed_planner_policy.limits =
            PlannerLimitsV2::new(1, 1, 1, 4096).unwrap();
        assert!(compile(&f, &b, 202).is_err());
        f.authority.sessions[0].signed_planner_policy.limits = limits;
        let principal = f.authority.sessions[0].principal;
        f.authority.sessions[0].principal = PrincipalIdV2::new([9; 32]);
        assert!(compile(&f, &b, 202).is_err());
        f.authority.sessions[0].principal = principal;
        f.authority
            .policy
            .as_mut()
            .unwrap()
            .durable
            .revoke_task_authorization(f.authority.sessions[0].durable_task_id)
            .unwrap();
        assert!(compile(&f, &b, 202).is_err());
    }

    #[test]
    fn fused_compiler_rejects_expired_input_even_while_root_and_session_are_live() {
        let (mut f, request) = business_proposal_fixture("A", "Alice");
        install(&mut f, &request, 1);
        choose(&mut f, 1, 1, true, 202);
        let mut b = bindings(&request);
        let s = &f.authority.sessions[0];
        let value = KernelValueV2::text("private payload").unwrap();
        let provenance = ProvenanceRecordV2::planner_output(
            &value,
            ProvenanceContextV2::from_authenticated_runtime(
                s.producer_identity,
                s.durable_run_id,
                s.active_state_manifest_digest,
                UnixMillisV2::new(200),
                UnixMillisV2::new(203),
            )
            .unwrap(),
            Digest32V2::new([1; 32]),
            Digest32V2::new([2; 32]),
            Digest32V2::new([3; 32]),
            &[],
            EffectSetV2::SEND,
        )
        .unwrap();
        b[0].value = f
            .values
            .register_verified_value(f.run, value, provenance)
            .unwrap()
            .handle();
        assert!(compile(&f, &b, 202).is_ok());
        assert!(compile(&f, &b, 204).is_err());
        let s = &f.authority.sessions[0];
        let value = KernelValueV2::text("private payload").unwrap();
        let future = ProvenanceRecordV2::planner_output(
            &value,
            ProvenanceContextV2::from_authenticated_runtime(
                s.producer_identity,
                s.durable_run_id,
                s.active_state_manifest_digest,
                UnixMillisV2::new(250),
                UnixMillisV2::new(800),
            )
            .unwrap(),
            Digest32V2::new([1; 32]),
            Digest32V2::new([2; 32]),
            Digest32V2::new([3; 32]),
            &[],
            EffectSetV2::SEND,
        )
        .unwrap();
        b[0].value = f
            .values
            .register_verified_value(f.run, value, future)
            .unwrap()
            .handle();
        assert!(compile(&f, &b, 249).is_err());
        assert!(compile(&f, &b, 250).is_ok());
    }

    #[test]
    fn fused_compiler_preserves_logical_request_identity_but_never_reuses_changed_g4_approval() {
        let (mut f, request) = business_proposal_fixture("A", "Alice");
        install(&mut f, &request, 2);
        choose(&mut f, 1, 1, true, 202);
        let b = bindings(&request);
        let before = compile(&f, &b, 202).unwrap();
        choose(&mut f, 2, 2, false, 302);
        let pending = compile(&f, &b, 302).unwrap();
        assert_eq!(pending.activation_revision, 1); // ignores newer unactivated candidate
        assert_eq!(pending.actions[0].reference.operation, 1);
        let task = f.authority.sessions[0].durable_task_id;
        let owner = &mut f.authority.policy.as_mut().unwrap().durable;
        let status = owner
            .fused_planning_status_v04(task, UnixMillisV2::new(302))
            .unwrap();
        owner
            .update_fused_planning_v04(
                task,
                status.revision,
                U::Activate {
                    round: 2,
                    expected_plan_revision: 1,
                },
                UnixMillisV2::new(302),
            )
            .unwrap();
        let after = compile(&f, &b, 302).unwrap();
        assert_eq!(after.activation_revision, 2);
        assert_eq!(after.actions[0].reference.operation, 2);
        for old in &before.actions {
            let new = after
                .actions
                .iter()
                .find(|a| a.reference.operation == old.reference.operation)
                .unwrap();
            assert_eq!(old.internal_step_id, new.internal_step_id);
            assert_eq!(
                old.prepared.business_request.request_id(),
                new.prepared.business_request.request_id()
            );
            // Real G4 binds the matched relation/display as well. Don't weaken
            // those fields merely to make a recompiled action look approved.
            assert_ne!(old.execution_commitment, new.execution_commitment);
            assert_eq!(old.recipe.commitment(), new.recipe.commitment());
            assert_ne!(new.recipe.commitment(), new.execution_commitment);
            assert!(new
                .recipe
                .matches_exact_draft(&new.prepared.material, new.prepared.task_match.content())
                .unwrap());
            assert!(!old
                .recipe
                .matches_exact_draft(&new.prepared.material, new.prepared.task_match.content())
                .unwrap());
            assert!(
                savana_policy_core::v2::FusedExecutionRecipeV04::from_verified_g4(
                    &old.prepared.material,
                    &new.prepared.task_match,
                    &old.prepared.recipe_slots
                )
                .is_err()
            );
            assert!(!new.matches_profile_approval);
        }
    }

    #[test]
    fn fused_compiler_recipe_rejects_bad_witnesses_and_pins_operation_identity() {
        use savana_policy_core::v2::FusedExecutionRecipeV04 as Recipe;
        let (mut f, request) = business_proposal_fixture("A", "Alice");
        install(&mut f, &request, 2);
        choose(&mut f, 1, 1, true, 202);
        let before = disk(&f);
        let c = compile(&f, &bindings(&request), 202).unwrap();
        let a = &c.actions[0].prepared;
        assert!(Recipe::from_verified_g4(&a.material, &a.task_match, &[]).is_err());
        assert!(
            Recipe::from_verified_g4(&a.material, &a.task_match, &a.recipe_slots[..2]).is_err()
        );
        let mut swapped = a.recipe_slots.clone();
        swapped.swap(0, 1);
        assert!(Recipe::from_verified_g4(&a.material, &a.task_match, &swapped).is_err());
        let relation = VerifiedResolvedRelationSetV2::from_task_match(3, &a.task_match).unwrap();
        let already_bound = a
            .recipe_slots
            .iter()
            .cloned()
            .map(|s| s.with_task_relation(&relation).unwrap())
            .collect::<Vec<_>>();
        assert!(Recipe::from_verified_g4(&a.material, &a.task_match, &already_bound).is_err());
        // Identical business actions may have the same whole-task match. The
        // separate logical step AND projected request ID distinguish operations.
        assert_eq!(
            a.task_match.content(),
            c.actions[1].prepared.task_match.content()
        );
        assert_ne!(
            c.actions[0].recipe.commitment(),
            c.actions[1].recipe.commitment()
        );
        assert!(!c.actions[0]
            .recipe
            .matches_exact_draft(
                &c.actions[1].prepared.material,
                c.actions[1].prepared.task_match.content()
            )
            .unwrap());
        assert_eq!(disk(&f), before);
    }

    #[test]
    fn fused_compiler_recipe_pins_owned_source_even_when_plaintext_is_identical() {
        use savana_policy_core::v2::FusedExecutionRecipeV04 as Recipe;
        let (mut f, request) = business_proposal_fixture("A", "Alice");
        install(&mut f, &request, 1);
        choose(&mut f, 1, 1, true, 202);
        let mut b = bindings(&request);
        let old = compile(&f, &b, 202).unwrap();
        approve_recipes(&mut f, &old);
        assert!(compile(&f, &b, 202).unwrap().actions[0].matches_recipe_approval);
        let before = disk(&f);
        let s = &f.authority.sessions[0];
        let value = KernelValueV2::text("private payload").unwrap();
        let provenance = ProvenanceRecordV2::planner_output(
            &value,
            ProvenanceContextV2::from_authenticated_runtime(
                s.producer_identity,
                s.durable_run_id,
                s.active_state_manifest_digest,
                UnixMillisV2::new(200),
                UnixMillisV2::new(800),
            )
            .unwrap(),
            Digest32V2::new([1; 32]),
            Digest32V2::new([2; 32]),
            Digest32V2::new([3; 32]),
            &[],
            EffectSetV2::SEND,
        )
        .unwrap();
        b[0].value = f
            .values
            .register_verified_value(f.run, value, provenance)
            .unwrap()
            .handle();
        let new = compile(&f, &b, 202).unwrap();
        let a = &old.actions[0];
        let z = &new.actions[0];
        assert_eq!(
            a.prepared.business_request.canonical_json(),
            z.prepared.business_request.canonical_json()
        );
        assert_ne!(a.recipe.commitment(), z.recipe.commitment());
        assert!(Recipe::from_verified_g4(
            &z.prepared.material,
            &z.prepared.task_match,
            &a.prepared.recipe_slots
        )
        .is_err());
        assert!(!a
            .recipe
            .matches_exact_draft(&z.prepared.material, z.prepared.task_match.content())
            .unwrap());
        assert!(!z.matches_profile_approval);
        assert!(!z.matches_recipe_approval);
        assert_eq!(disk(&f), before);
    }
}
