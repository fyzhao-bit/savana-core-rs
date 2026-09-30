// Real G4/G5/G7, authenticated local IPC, sealed envelope, execd journal and
// result vault; the only provider is the isolated test-support connector.
#[test]
fn fused_private_g7_handoff_refusal_leaves_no_charge_or_execution() {
    let mut f = private_action_fixture(1);
    f.authority
        .policy
        .as_ref()
        .unwrap()
        .declassification_rules
        .set_recovery_fence_for_test(8);
    let manifest = f.authority.sessions[0].active_state_manifest_digest;
    f.authority
        .policy
        .as_mut()
        .unwrap()
        .install_g7(test_g7_runtime(
            f.authority.config.installation_id,
            manifest,
            7,
            8,
        ))
        .unwrap();
    let action = prepare_private(&mut f, 202).unwrap();
    f.authority
        .evaluate_fused_action_v04(&action, &f.values, manifest, 7, UnixMillisV2::new(203))
        .unwrap();
    let before = disk(&f);
    assert!(matches!(
        f.authority.dispatch_fused_action_v04(
            &action,
            RequestIdV2::new([29; 16]),
            manifest,
            7,
            8,
            UnixMillisV2::new(204)
        ),
        Err(KernelAgentAuthorityErrorV2::BindingMismatch)
    ));
    assert_eq!(f.authority.execution_declassification_gate_test_observation,
        Some(super::super::ExecutionDeclassificationGateTestObservationV2::ProvenanceDeclassificationRefused));
    assert!(f.authority.executions.is_empty());
    assert!(f
        .authority
        .policy
        .as_ref()
        .unwrap()
        .durable
        .recovery_projection()
        .unwrap()
        .is_empty());
    assert_eq!(disk(&f), before);
}

#[test]
fn fused_private_g7_rejects_old_pending_revision_and_expired_recipe() {
    for replace in [false, true] {
        let mut f = private_action_fixture(2);
        let manifest = f.authority.sessions[0].active_state_manifest_digest;
        let action = prepare_private(&mut f, 202).unwrap();
        f.authority
            .evaluate_fused_action_v04(&action, &f.values, manifest, 7, UnixMillisV2::new(203))
            .unwrap();
        if replace {
            choose(&mut f, 2, 2, true, 302);
        }
        let before = disk(&f);
        assert!(matches!(
            f.authority.dispatch_fused_action_v04(
                &action,
                RequestIdV2::new([30; 16]),
                manifest,
                7,
                8,
                UnixMillisV2::new(if replace { 302 } else { 350 })
            ),
            Err(KernelAgentAuthorityErrorV2::StateConflict)
        ));
        assert_eq!(disk(&f), before);
        assert!(f.authority.executions.is_empty());
    }
}

#[cfg(feature = "test-support")]
fn private_dispatch_fixture(case: u8) {
    private_dispatch_fixture_with_provider(case, None, None);
}

#[cfg(feature = "test-support")]
fn private_dispatch_fixture_with_provider(
    case: u8,
    exchange: Option<savana_execd::intent_bound_test_support::ProviderExchange>,
    replies: Option<std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>>>,
) {
    use savana_execd::intent_bound_test_support::{
        deployment_connector, service_with_provider, ProviderReply,
    };
    use savana_kernel_protocol::v2::{
        ExecutionStatusTargetV2, ExecutorStatusV2, GetExecutionStatusRequestV2,
        KernelServiceApplicationResponseV2, KernelServiceOperationV2, PublicExecutionStatusV2,
        PublicStableCodeV2,
    };
    let (mut f, proposal) = business_proposal_fixture_with_result_release(
        "A",
        "Alice",
        case >= 26,
        case == 36,
        matches!(case, 41 | 42),
    );
    f.authority.policy.as_mut().unwrap().declassification_rules =
        planner_declassification_rules_with_model(
            matches!(case, 24 | 25 | 30 | 31 | 34 | 41 | 42),
            Some(Digest32V2::new([0xa7; 32])),
            None,
            if case == 38 {
                Some(Digest32V2::new([2; 32]))
            } else {
                None
            },
        );
    let b = if case >= 26 {
        let second = replan_business_proposal(&mut f, "B", "Bob", 201);
        let third = if case == 36 {
            Some(replan_business_proposal(&mut f, "C", "Carol", 201))
        } else {
            None
        };
        let mut requests = vec![&proposal, &second];
        if let Some(third) = &third {
            requests.push(third);
        }
        let mut local = Vec::new();
        let operations = requests
            .iter()
            .enumerate()
            .map(|(index, request)| {
                let args = request
                    .arguments()
                    .iter()
                    .enumerate()
                    .map(|(i, a)| {
                        let slot = [u8::try_from(index * 3 + i + 1).unwrap(); 16];
                        let from_result = case >= 32 && index > 0 && a.name().as_str() == "body";
                        if !from_result { local.push(FusedLocalValueBindingV04 {
                            slot,
                            value: a.value(),
                        }); }
                        if from_result { serde_json::json!({"argument":a.name().as_str(),"slot":slot,"result_of":index}) }
                        else { serde_json::json!({"argument":a.name().as_str(),"slot":slot}) }
                    })
                    .collect::<Vec<_>>();
                serde_json::json!({"id":index+1,"tool_class":31,"action_template":21,
                "after":if case >= 32 && index > 0 {vec![index]} else {vec![]},"bindings":args})
            })
            .collect();
        // Clause 2 has a signed success dependency on clause 1. The planner
        // does not acquire authority by merely putting this operation second.
        install_operations_with_observation(
            &mut f,
            operations,
            if case == 36 { 7000 } else { 4000 },
            matches!(case, 38 | 39),
            case >= 40,
        );
        local
    } else {
        install(&mut f, &proposal, 2);
        bindings(&proposal)
    };
    choose_with_schedule(
        &mut f,
        1,
        if case == 28 { 2 } else { 1 },
        true,
        202,
        matches!(case, 38 | 39),
    );
    pin_inputs(&mut f, &b, 202).unwrap();
    let candidate = compile(&f, &b, 202).unwrap();
    approve_recipes_until(
        &mut f,
        &candidate,
        if case == 36 {
            6500
        } else if case >= 26 {
            3500
        } else {
            350
        },
    );
    let installation = f.authority.config.installation_id;
    let manifest = f.authority.sessions[0].active_state_manifest_digest;
    let task = f.authority.sessions[0].durable_task_id;
    let active = f
        .authority
        .policy
        .as_ref()
        .unwrap()
        .active_tools
        .resolve_class(
            ToolClassIdV2::new(31),
            RoleIdV2::new(1),
            UnixMillisV2::new(202),
        )
        .unwrap();
    let mut tools = vec![active.descriptor().unsigned().clone()];
    if matches!(case, 41 | 42) {
        tools.push(
            f.authority
                .policy
                .as_ref()
                .unwrap()
                .active_tools
                .resolve_class(
                    ToolClassIdV2::new(34),
                    RoleIdV2::new(1),
                    UnixMillisV2::new(202),
                )
                .unwrap()
                .descriptor()
                .unsigned()
                .clone(),
        );
    }
    let connectors = vec![deployment_connector(tools)];
    let mut g7 = test_g7_runtime(installation, manifest, 7, 8);
    // This fixture explicitly authorizes three attempts; production quotas
    // remain unchanged. The old two-attempt fixture correctly refused step 3.
    if case == 36 {
        g7.quota_limit = 3;
    }
    g7.connector_registry = SharedVerifiedConnectorRegistryV2::from_verified_state(
        ConnectorRegistryStateV2::from_verified_genesis(
            Digest32V2::new([0xbf; 32]),
            [0; 32],
            vec![],
            connectors.clone(),
        )
        .unwrap(),
    )
    .unwrap();
    g7.executor = g7
        .executor
        .with_socket_path_for_test(f._directory.path().join("executor.sock"));
    f.authority.policy.as_mut().unwrap().install_g7(g7).unwrap();
    f.authority
        .policy
        .as_ref()
        .unwrap()
        .declassification_rules
        .set_recovery_fence_for_test(8);
    let root = f._directory.path().join("executor");
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let (service, observed) = service_with_provider(
        &root,
        installation,
        manifest,
        7,
        8,
        case == 2,
        if case == 37 {
            ProviderReply::Unknown
        } else {
            ProviderReply::Success
        },
        connectors,
        exchange,
    );
    let messages = if case == 42 {
        16
    } else if case == 41 {
        15
    } else if case == 37 {
        3
    } else if case == 36 {
        17
    } else if matches!(case, 26 | 27 | 31 | 32 | 33 | 34 | 38 | 39 | 40) {
        10
    } else if matches!(case, 23 | 25 | 28) {
        0
    } else if case == 21 {
        1
    } else if matches!(case, 13 | 15) {
        6
    } else if matches!(case, 14 | 18 | 19) {
        7
    } else if matches!(case, 16 | 17) {
        8
    } else if case == 9 {
        1
    } else if matches!(case, 10 | 11) {
        7
    } else if case == 12 {
        4
    } else if case == 2 || (5..=7).contains(&case) {
        3
    } else if case == 3 {
        6
    } else {
        5
    };
    let delayed = std::cell::Cell::new(false);
    let queries = std::cell::Cell::new(0);
    let service_clock = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(205));
    let server_clock = service_clock.clone();
    let server = f
        .authority
        .policy
        .as_ref()
        .unwrap()
        .g7
        .as_ref()
        .unwrap()
        .executor
        .fixture_server(
            SigningKey::from_bytes(&[0xb0; 32]),
            messages,
            move |request| {
                let KernelServiceOperationV2::Executor(operation) = request.operation() else {
                    panic!("executor")
                };
                let mut bytes = service
                    .execute(
                        operation.clone(),
                        UnixMillisV2::new(server_clock.load(std::sync::atomic::Ordering::SeqCst)),
                        std::time::Instant::now() + std::time::Duration::from_secs(5),
                    )
                    .unwrap();
                if request.operation().tag() == 61 {
                    queries.set(queries.get() + 1);
                }
                if case == 18 && queries.get() == 1 && request.operation().tag() == 61 {
                    return KernelServiceApplicationResponseV2::error(
                        EndpointRoleV2::KernelExecutor,
                        request.request_id(),
                        61,
                        PublicStableCodeV2::ServiceUnavailable,
                    )
                    .unwrap();
                }
                if matches!(case, 16 | 17) && queries.get() == 2 && request.operation().tag() == 61
                {
                    use savana_kernel_protocol::v2::{
                        decode_query_by_execution_nonce_response_v2,
                        encode_query_by_execution_nonce_response_v2,
                        ExecutorCompletionDescriptorV2, QueryByExecutionNonceResponseV2,
                    };
                    let original = decode_query_by_execution_nonce_response_v2(&bytes).unwrap();
                    let ExecutorStatusV2::CompletionAvailable {
                        effect_started_receipt,
                        effect_started_receipt_digest,
                        completion,
                    } = original.status()
                    else {
                        panic!("completion")
                    };
                    bytes = encode_query_by_execution_nonce_response_v2(
                        &QueryByExecutionNonceResponseV2::new(
                            ExecutorStatusV2::completion_available(
                                effect_started_receipt.clone(),
                                if case == 17 {
                                    Digest32V2::new([77; 32])
                                } else {
                                    *effect_started_receipt_digest
                                },
                                if case == 16 {
                                    ExecutorCompletionDescriptorV2::tool_result(
                                        Digest32V2::new([78; 32]),
                                        1,
                                    )
                                    .unwrap()
                                } else {
                                    *completion
                                },
                            )
                            .unwrap(),
                        ),
                    )
                    .unwrap();
                }
                if case == 3 && request.operation().tag() == 61 && !delayed.replace(true) {
                    bytes =
                        savana_kernel_protocol::v2::encode_query_by_execution_nonce_response_v2(
                            &savana_kernel_protocol::v2::QueryByExecutionNonceResponseV2::new(
                                ExecutorStatusV2::indeterminate(None, None).unwrap(),
                            ),
                        )
                        .unwrap();
                }
                if (5..=7).contains(&case) && request.operation().tag() == 61 {
                    use savana_kernel_protocol::v2::{
                        decode_query_by_execution_nonce_response_v2,
                        encode_query_by_execution_nonce_response_v2,
                        QueryByExecutionNonceResponseV2, SignedExecutorEffectStartedReceiptV2,
                        UnsignedExecutorEffectStartedReceiptV2,
                    };
                    let original = decode_query_by_execution_nonce_response_v2(&bytes).unwrap();
                    let ExecutorStatusV2::CompletionAvailable {
                        effect_started_receipt,
                        completion,
                        ..
                    } = original.status()
                    else {
                        panic!("completed")
                    };
                    let u = effect_started_receipt.unsigned();
                    let material = if case == 5 {
                        UnsignedExecutorEffectStartedReceiptV2::new(
                            u.installation_id(),
                            u.active_state_manifest_digest(),
                            u.deployment_generation(),
                            u.effect_fence_epoch(),
                            Nonce32V2::new([45; 32]),
                            u.dispatch_core_digest(),
                            u.dispatch_subject_digest(),
                            u.executor_identity(),
                            u.connector_identity_digest(),
                            u.external_attempt_ordinal(),
                            u.connector_codec_job_descriptor_digest(),
                            u.prepared_provider_request_digest(),
                            u.provider_attempt_prepared_journal_record_digest(),
                            u.started_at(),
                        )
                        .unwrap()
                    } else {
                        *u
                    };
                    let signing_key =
                        SigningKey::from_bytes(&[if case == 6 { 0x11 } else { 0xbd }; 32]);
                    let receipt = SignedExecutorEffectStartedReceiptV2::sign(
                        material,
                        derive_ed25519_key_id_v2(signing_key.verifying_key().to_bytes()),
                        &signing_key,
                    )
                    .unwrap();
                    let digest = if case == 7 {
                        Digest32V2::new([46; 32])
                    } else {
                        receipt.digest()
                    };
                    bytes = encode_query_by_execution_nonce_response_v2(
                        &QueryByExecutionNonceResponseV2::new(
                            ExecutorStatusV2::completion_available(receipt, digest, *completion)
                                .unwrap(),
                        ),
                    )
                    .unwrap();
                }
                if (matches!(case, 1 | 8 | 13 | 22) && request.operation().tag() == 60)
                    || (matches!(case, 4 | 15) && request.operation().tag() == 62)
                {
                    service.restart();
                    return KernelServiceApplicationResponseV2::error(
                        EndpointRoleV2::KernelExecutor,
                        request.request_id(),
                        request.operation().tag(),
                        PublicStableCodeV2::ServiceUnavailable,
                    )
                    .unwrap();
                }
                KernelServiceApplicationResponseV2::success(
                    EndpointRoleV2::KernelExecutor,
                    request.request_id(),
                    request.operation().tag(),
                    bytes,
                )
                .unwrap()
            },
        );
    if (20..=42).contains(&case) {
        let mut vault = tool_result_data_fixture(&f);
        if matches!(case, 24 | 25) {
            f.authority.policy.as_mut().unwrap().disposition =
                VerifiedPolicyDispositionV2::require_approval_from_verified_policy();
        }
        if case == 21 {
            f.authority.fused_recovery_fault =
                Some(super::super::fused_actions::FusedRecoveryFaultV04::G7Prepared);
        }
        f.authority.policy.as_mut().unwrap().fused_workflow_phase = 2;
        let active_policy = f
            .authority
            .policy
            .as_ref()
            .unwrap()
            .declassification_rules
            .clone();
        let mut times = [202, 203, 204].into_iter();
        f.authority
            .tick_private_workflows_v04(&mut f.values, Some(&mut vault), || {
                let at = times.next().unwrap();
                if case == 23 && at == 204 {
                    active_policy.set_recovery_fence_for_test(9);
                }
                UnixMillisV2::new(at)
            })
            .unwrap();
        assert_eq!(f.authority.intents.len(), 1);
        if case == 28 {
            // A signed ordering choice is still not proof that the task's
            // predecessor succeeded. G7 must reject the reversed execution.
            let owner = &f.authority.policy.as_ref().unwrap().durable;
            let state = owner.task_authorization_state(task).unwrap();
            assert_eq!(state.clause_consumption(1), Some((0, 0)));
            assert_eq!(state.clause_consumption(2), Some((0, 0)));
            assert!(owner.recovery_projection().unwrap().is_empty());
            assert!(f.authority.executions.is_empty());
            assert!(observed.requests().is_empty());
            assert!(server.join().unwrap().is_empty());
            return;
        }
        if matches!(case, 24 | 25) {
            use savana_kernel_protocol::v2::{
                sign_task_action_approval_v2, ApprovalDecisionV2, SignedApprovalSettlementV2,
                TaskActionApprovalDecisionV2, TaskActionApprovalV2, UnsignedApprovalSettlementV2,
            };
            assert!(f.authority.execution_tickets.is_empty());
            assert!(f.authority.executions.is_empty());
            assert!(observed.requests().is_empty());
            let envelope = &f.authority.tool_approvals[0].envelope;
            let material = envelope.unverified_material().unwrap();
            let unsigned = UnsignedApprovalSettlementV2::new(
                installation,
                manifest,
                7,
                ApprovalPurposeV2::ToolExecution,
                envelope.envelope_digest().unwrap(),
                ApprovalDecisionV2::Approve,
                material.expected_principal(),
                Digest32V2::new([0xd1; 32]),
                Digest32V2::new([0xd2; 32]),
                true,
                true,
                false,
                false,
                2,
                material.decision_challenge(),
                Nonce32V2::new([0xd3; 32]),
                UnixMillisV2::new(203),
                UnixMillisV2::new(if case == 25 { 205 } else { 340 }),
            )
            .unwrap();
            let key = SigningKey::from_bytes(&[0x9c; 32]);
            let exact = sign_task_action_approval_v2(
                TaskActionApprovalV2::new(
                    material.task_action_context(&unsigned).unwrap(),
                    TaskActionApprovalDecisionV2::Approve,
                    unsigned.issued_at(),
                    unsigned.expires_at(),
                )
                .unwrap(),
                &key,
            )
            .unwrap();
            let receipt = SignedApprovalSettlementV2::sign(unsigned, &key)
                .unwrap()
                .with_task_action_approval(exact)
                .unwrap();
            let action = super::super::fused_actions::FusedPrivateActionV04 {
                intent: f.authority.intents[0].intent,
            };
            f.authority
                .authorize_fused_action_v04(&action, receipt, manifest, 7, UnixMillisV2::new(204))
                .unwrap();
            f.authority.policy.as_mut().unwrap().fused_action_not_before = 0;
            f.authority
                .tick_fused_actions_v04(&mut f.values, &mut || {
                    UnixMillisV2::new(if case == 25 { 206 } else { 204 })
                })
                .unwrap();
            assert_eq!(f.authority.intents.len(), 1);
            assert_eq!(f.authority.execution_tickets.len(), 1);
            if case == 25 {
                assert!(f.authority.executions.is_empty());
                assert!(f
                    .authority
                    .policy
                    .as_ref()
                    .unwrap()
                    .durable
                    .recovery_projection()
                    .unwrap()
                    .is_empty());
                assert!(observed.requests().is_empty());
                assert!(server.join().unwrap().is_empty());
                return;
            }
            assert_eq!(f.authority.executions.len(), 1);
        }
        if case == 23 {
            assert!(f.authority.executions.is_empty());
            assert!(f
                .authority
                .policy
                .as_ref()
                .unwrap()
                .durable
                .recovery_projection()
                .unwrap()
                .is_empty());
            assert!(observed.requests().is_empty());
            assert!(server.join().unwrap().is_empty());
            return;
        }
        let head = disk(&f);
        // Bypass only the test pacing interval to exercise the durable in-flight
        // guard, not just the rate limiter. Operation 2 must not be prepared.
        if case < 26 {
            f.authority.policy.as_mut().unwrap().fused_action_not_before = 0;
        }
        f.authority
            .tick_fused_actions_v04(&mut f.values, &mut || {
                UnixMillisV2::new(if case >= 26 { 1202 } else { 206 })
            })
            .unwrap();
        assert_eq!(f.authority.intents.len(), 1);
        assert_eq!(disk(&f), head);
        assert_eq!(
            f.authority
                .policy
                .as_ref()
                .unwrap()
                .durable
                .task_authorization_state(task)
                .unwrap()
                .clause_consumption(1),
            Some((1, 1))
        );
        if case == 21 {
            assert!(f.authority.executions.is_empty());
            assert!(observed.requests().is_empty());
        } else {
            service_clock.store(
                if case >= 26 { 1203 } else { 207 },
                std::sync::atomic::Ordering::SeqCst,
            );
            f.authority
                .tick_fused_recovery_v04(
                    &mut vault,
                    manifest,
                    7,
                    8,
                    UnixMillisV2::new(if case >= 26 { 1203 } else { 207 }),
                )
                .unwrap();
            if case == 37 {
                let owner = &f.authority.policy.as_ref().unwrap().durable;
                let records = owner.recover_fused_executions_v04(task).unwrap();
                assert_eq!(records.len(), 1);
                assert!(records[0].result_commit().is_none());
                let inputs = owner
                    .recover_fused_inputs_v04(task, 7, UnixMillisV2::new(1203))
                    .unwrap();
                assert!(
                    inputs.inputs().iter().all(|i| i.slot() != [4; 16]),
                    "unknown cannot fabricate result slot"
                );
                f.authority
                    .tick_fused_actions_v04(&mut f.values, &mut || UnixMillisV2::new(2204))
                    .unwrap();
                let state = f
                    .authority
                    .policy
                    .as_ref()
                    .unwrap()
                    .durable
                    .task_authorization_state(task)
                    .unwrap();
                assert_eq!(state.clause_consumption(1), Some((1, 1)));
                assert_eq!(state.clause_consumption(2), Some((0, 0)));
                assert_eq!(observed.requests().len(), 1);
                assert_eq!(server.join().unwrap().len(), messages);
                return;
            }
            assert!(f
                .authority
                .policy
                .as_ref()
                .unwrap()
                .durable
                .recover_fused_executions_v04(task)
                .unwrap()[0]
                .result_commit()
                .is_some());
            assert_eq!(observed.requests().len(), 1);
        }
        if case >= 26 {
            if matches!(case, 38 | 39) {
                use savana_policy_core::v2::{FusedModelTransportErrorV04, FusedModelTransportV04};
                struct ObservationWorker(std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>>);
                impl FusedModelTransportV04 for ObservationWorker {
                    fn recipient_identity(&self) -> [u8; 32] {
                        [2; 32]
                    }
                    fn exchange(
                        &mut self,
                        request: &[u8],
                        _: UnixMillisV2,
                        _: usize,
                    ) -> Result<Vec<u8>, FusedModelTransportErrorV04> {
                        self.0.lock().unwrap().push(request.to_vec());
                        let view: savana_continuation_core::planning::ModelView =
                            serde_json::from_slice(request).unwrap();
                        Ok(serde_json::to_vec(&PlanProposal {
                            schema: 1,
                            job: view.job,
                            view: view.commitment(),
                            choice: PlanChoice::RegisteredTemplate { template: 1 },
                        })
                        .unwrap())
                    }
                }
                let sent = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
                f.authority
                    .policy
                    .as_mut()
                    .unwrap()
                    .fused_workers
                    .push(Box::new(ObservationWorker(sent.clone())));
                f.authority
                    .tick_fused_planning(&f.values, || UnixMillisV2::new(1300))
                    .unwrap();
                let requests = sent.lock().unwrap();
                assert_eq!(
                    requests.len(),
                    usize::from(case == 38),
                    "a signed observation cannot bypass current G3"
                );
                if case == 38 {
                    let view: savana_continuation_core::planning::ModelView =
                        serde_json::from_slice(&requests[0]).unwrap();
                    let projection: serde_json::Value =
                        serde_json::from_slice(&view.public_view).unwrap();
                    assert_eq!(projection["observations"][0]["value"], "succeeded");
                    assert_eq!(projection["observations"][0]["status"], "available");
                    assert!(!String::from_utf8(view.public_view)
                        .unwrap()
                        .contains("jsonrpc"));
                }
                drop(requests);
                f.authority
                    .tick_fused_planning(&f.values, || UnixMillisV2::new(1301))
                    .unwrap();
                assert_eq!(
                    sent.lock().unwrap().len(),
                    usize::from(case == 38),
                    "neither success nor refusal retries a spent slot"
                );
            }
            if case == 36 {
                // Confirm executor cleanup in a separate paced owner turn.
                // Otherwise the fair recovery queue may select this older job.
                service_clock.store(2203, std::sync::atomic::Ordering::SeqCst);
                f.authority
                    .tick_fused_recovery_v04(&mut vault, manifest, 7, 8, UnixMillisV2::new(2203))
                    .unwrap();
            }
            // The original all-plan compiler cannot prepare exhausted clause 1.
            // That must not prevent execution of clause 2 with its own budget.
            assert!(compile(&f, &b, 2204).is_err());
            assert_eq!(
                f.authority
                    .policy
                    .as_ref()
                    .unwrap()
                    .durable
                    .task_authorization_state(task)
                    .unwrap()
                    .clause_consumption(2),
                Some((0, 0))
            );
            if matches!(case, 29 | 35) {
                f.authority
                    .policy
                    .as_mut()
                    .unwrap()
                    .durable
                    .revoke_task_authorization(task)
                    .unwrap();
            }
            if matches!(case, 30 | 31 | 34) {
                f.authority.policy.as_mut().unwrap().disposition =
                    VerifiedPolicyDispositionV2::require_approval_from_verified_policy();
            }
            if matches!(case, 33 | 38 | 39 | 40) {
                let head = f
                    .authority
                    .policy
                    .as_ref()
                    .unwrap()
                    .durable
                    .authenticated_state_head()
                    .unwrap();
                let mut policy = f.authority.policy.take().unwrap();
                drop(policy.durable);
                let reopened = DurableG4StateV2::open(
                    &f._directory.path().join("kernel-g4-state-v2.cbor"),
                    [0x99; 32],
                    DurableStateNamespaceV2::from_verified_installation(
                        Digest32V2::new([0x89; 32]),
                        Digest32V2::new([0x9b; 32]),
                    )
                    .unwrap(),
                    Box::new(TestG4StateAnchorV2(std::sync::Arc::new(
                        std::sync::Mutex::new(head),
                    ))),
                )
                .unwrap();
                policy.durable = reopened;
                f.authority.policy = Some(policy);
            }
            if matches!(case, 27 | 33) {
                // Drop volatile execution handles, but keep the authenticated
                // user session: this is execution recovery, not login recovery.
                f.authority.executions.clear();
                f.authority.execution_tickets.clear();
                f.authority.intents.clear();
            }
            // Respect the production pacing intervals. Only the supplied clock
            // advances; no private scheduling cursor is reset in these cases.
            service_clock.store(2204, std::sync::atomic::Ordering::SeqCst);
            f.authority
                .tick_fused_actions_v04(&mut f.values, &mut || UnixMillisV2::new(2204))
                .unwrap();
            if matches!(case, 29 | 30 | 35) {
                assert_eq!(observed.requests().len(), 1);
                assert_eq!(
                    f.authority
                        .policy
                        .as_ref()
                        .unwrap()
                        .durable
                        .task_authorization_state(task)
                        .unwrap()
                        .clause_consumption(2),
                    Some((0, 0))
                );
                assert_eq!(f.authority.tool_approvals.len(), usize::from(case == 30));
                assert_eq!(server.join().unwrap().len(), messages);
                return;
            }
            if matches!(case, 31 | 34) {
                assert_eq!(observed.requests().len(), 1);
                assert_eq!(f.authority.tool_approvals.len(), 1);
                let receipt = private_loop_signed_approval(&f, 2205, 3400);
                let action = super::super::fused_actions::FusedPrivateActionV04 {
                    intent: f.authority.intents.last().unwrap().intent,
                };
                f.authority
                    .authorize_fused_action_v04(
                        &action,
                        receipt,
                        manifest,
                        7,
                        UnixMillisV2::new(2205),
                    )
                    .unwrap();
                assert_eq!(
                    observed.requests().len(),
                    1,
                    "G6 settlement alone cannot dispatch"
                );
                service_clock.store(3204, std::sync::atomic::Ordering::SeqCst);
                f.authority
                    .tick_fused_actions_v04(&mut f.values, &mut || UnixMillisV2::new(3204))
                    .unwrap();
            }
            assert_eq!(
                observed.requests().len(),
                2,
                "the second distinct effect must actually execute"
            );
            let requests = observed.requests();
            if case >= 32 {
                let decode = |bytes: &[u8]| -> serde_json::Value {
                    let mut d = minicbor::Decoder::new(bytes);
                    assert_eq!(d.array().unwrap(), Some(11));
                    for _ in 0..10 {
                        d.skip().unwrap();
                    }
                    serde_json::from_slice(d.bytes().unwrap()).unwrap()
                };
                let first = decode(&requests[0]);
                let second = decode(&requests[1]);
                let expected = if let Some(replies) = &replies {
                    serde_json::from_slice(&replies.lock().unwrap()[0]).unwrap()
                } else {
                    serde_json::json!({"jsonrpc":"2.0","id":first["id"],"result":{
                    "isError":false,"content":[],"structuredContent":{"savana_status":"succeeded"}}})
                };
                let actual: serde_json::Value =
                    serde_json::from_str(second["params"]["arguments"]["body"].as_str().unwrap())
                        .unwrap();
                assert_eq!(actual, expected, "second effect must carry the first real provider response, not its preconfigured body");
                assert_eq!(second["params"]["arguments"]["to"], "Bob");
                assert_eq!(second["params"]["arguments"]["file"], "B");
            }
            assert_ne!(
                requests[0], requests[1],
                "the two authorized destinations are distinct"
            );
            let settled_at = if case == 36 {
                3204
            } else if matches!(case, 31 | 34) {
                3205
            } else {
                2205
            };
            service_clock.store(settled_at, std::sync::atomic::Ordering::SeqCst);
            f.authority
                .tick_fused_recovery_v04(&mut vault, manifest, 7, 8, UnixMillisV2::new(settled_at))
                .unwrap();
            let settled_at = if case == 36 {
                service_clock.store(4204, std::sync::atomic::Ordering::SeqCst);
                f.authority
                    .tick_fused_recovery_v04(&mut vault, manifest, 7, 8, UnixMillisV2::new(4204))
                    .unwrap();
                service_clock.store(4205, std::sync::atomic::Ordering::SeqCst);
                f.authority
                    .tick_fused_actions_v04(&mut f.values, &mut || UnixMillisV2::new(4205))
                    .unwrap();
                let requests = observed.requests();
                assert_eq!(requests.len(), 3);
                let request = |i: usize| -> serde_json::Value {
                    let mut d = minicbor::Decoder::new(&requests[i]);
                    assert_eq!(d.array().unwrap(), Some(11));
                    for _ in 0..10 {
                        d.skip().unwrap();
                    }
                    serde_json::from_slice(d.bytes().unwrap()).unwrap()
                };
                let second = request(1);
                let third = request(2);
                let body: serde_json::Value =
                    serde_json::from_str(third["params"]["arguments"]["body"].as_str().unwrap())
                        .unwrap();
                assert_eq!(
                    body["id"], second["id"],
                    "third step consumes second, not first result"
                );
                assert_eq!(
                    body["result"]["structuredContent"]["savana_status"],
                    "succeeded"
                );
                assert_eq!(third["params"]["arguments"]["to"], "Carol");
                service_clock.store(5205, std::sync::atomic::Ordering::SeqCst);
                f.authority
                    .tick_fused_recovery_v04(&mut vault, manifest, 7, 8, UnixMillisV2::new(5205))
                    .unwrap();
                5205
            } else {
                settled_at
            };
            let owner = &f.authority.policy.as_ref().unwrap().durable;
            let records = owner.recover_fused_executions_v04(task).unwrap();
            assert_eq!(records.len(), if case == 36 { 3 } else { 2 });
            assert!(records.iter().all(|r| r.result_commit().is_some()));
            assert!(owner
                .active_fused_plan_v04(task, UnixMillisV2::new(settled_at))
                .unwrap()
                .next_operation()
                .is_none());
            let state = owner.task_authorization_state(task).unwrap();
            assert_eq!(state.clause_consumption(1), Some((1, 1)));
            assert_eq!(state.clause_consumption(2), Some((1, 1)));
            if case == 36 {
                assert_eq!(state.clause_consumption(3), Some((1, 1)));
            }
            if case == 40 {
                assert_fused_final_result(&mut f, manifest, settled_at);
            }
            if matches!(case, 41 | 42) {
                assert_fused_final_release(
                    &mut f,
                    &mut vault,
                    manifest,
                    settled_at,
                    &service_clock,
                    case == 42,
                );
            }
            let complete = disk(&f);
            for now in [settled_at + 1000, settled_at + 2000, settled_at + 3000] {
                f.authority
                    .tick_fused_actions_v04(&mut f.values, &mut || UnixMillisV2::new(now))
                    .unwrap();
            }
            assert_eq!(disk(&f), complete, "completion must not restart the loop");
            assert_eq!(
                observed.requests().len(),
                if matches!(case, 36 | 41 | 42) { 3 } else { 2 }
            );
        }
        assert_eq!(server.join().unwrap().len(), messages);
        return;
    }
    let action = prepare_private(&mut f, 202).unwrap();
    let evaluation = f
        .authority
        .evaluate_fused_action_v04(&action, &f.values, manifest, 7, UnixMillisV2::new(203))
        .unwrap();
    let EvaluateToolCallResponseV2::Allowed { ticket, .. } = evaluation.0 else {
        panic!("permit")
    };
    let before = disk(&f);
    for (m, g, fence) in [
        (Digest32V2::new([42; 32]), 7, 8),
        (manifest, 8, 8),
        (manifest, 7, 9),
    ] {
        assert!(f
            .authority
            .dispatch_fused_action_v04(
                &action,
                RequestIdV2::new([20; 16]),
                m,
                g,
                fence,
                UnixMillisV2::new(204)
            )
            .is_err());
        assert_eq!(disk(&f), before);
    }
    use super::super::fused_actions::FusedRecoveryFaultV04;
    f.authority.fused_recovery_fault = match case {
        9 => Some(FusedRecoveryFaultV04::G7Prepared),
        10 => Some(FusedRecoveryFaultV04::VaultCommitted),
        11 => Some(FusedRecoveryFaultV04::OutcomeCommitted),
        12 | 14 | 16 | 17 | 19 => Some(FusedRecoveryFaultV04::ResultCheckpointed),
        _ => None,
    };
    let sent = f.authority.dispatch_fused_action_v04(
        &action,
        RequestIdV2::new([21; 16]),
        manifest,
        7,
        8,
        UnixMillisV2::new(205),
    );
    assert_eq!(sent.is_err(), matches!(case, 1 | 8 | 9 | 13));
    let after = disk(&f);
    if case == 9 {
        assert!(f.authority.executions.is_empty());
        forget_private_execution_memory(&mut f);
        let restored = f
            .authority
            .restore_fused_execution_queries_v04(task, manifest, 7, 8)
            .unwrap();
        assert_eq!(restored.len(), 1);
        assert_eq!(disk(&f), after);
        assert!(f.authority.execution_tickets.is_empty());
        assert_eq!(
            f.authority
                .policy
                .as_ref()
                .unwrap()
                .durable
                .task_authorization_state(task)
                .unwrap()
                .clause_consumption(1),
            Some((1, 1))
        );
        assert_eq!(
            server.join().unwrap().len(),
            1,
            "registry sync only, no send"
        );
        assert!(observed.requests().is_empty());
        return;
    }
    if case >= 13 {
        let mut vault = tool_result_data_fixture(&f);
        if case == 13 {
            for (m, g, fence) in [
                (Digest32V2::new([42; 32]), 7, 8),
                (manifest, 8, 8),
                (manifest, 7, 9),
            ] {
                forget_private_execution_memory(&mut f);
                f.authority
                    .tick_fused_recovery_v04(&mut vault, m, g, fence, UnixMillisV2::new(206))
                    .unwrap();
                assert!(f.authority.executions.is_empty());
                assert_eq!(
                    disk(&f),
                    after,
                    "no restoration or IPC across deployment context"
                );
            }
            forget_private_execution_memory(&mut f);
            f.authority
                .tick_private_workflows_v04(&mut f.values, None, || UnixMillisV2::new(206))
                .unwrap();
            assert!(f.authority.executions.is_empty());
        }
        forget_private_execution_memory(&mut f);
        // Use the production owner-clock entry: it discovers the task from the
        // durable owner, not a caller-provided task or execution handle.
        f.authority
            .tick_private_workflows_v04(&mut f.values, Some(&mut vault), || UnixMillisV2::new(207))
            .unwrap();
        if case == 18 {
            assert_eq!(
                disk(&f),
                after,
                "transient unavailability keeps reservation"
            );
            forget_private_execution_memory(&mut f);
            f.authority
                .tick_private_workflows_v04(&mut f.values, Some(&mut vault), || {
                    UnixMillisV2::new(208)
                })
                .unwrap();
        }
        let checkpoint = f
            .authority
            .policy
            .as_ref()
            .unwrap()
            .durable
            .recover_fused_executions_v04(task)
            .unwrap()
            .remove(0);
        assert!(checkpoint.result_commit().is_some());
        let checkpoint_head = disk(&f);
        if case == 19 {
            let original = super::super::fused_actions::FusedPrivateExecutionV04(
                f.authority.executions[0].execution,
            );
            for now in [208, 209] {
                // Advance the test-only pacing cursor without discarding the
                // surviving handle; real time progression is covered above.
                f.authority
                    .policy
                    .as_mut()
                    .unwrap()
                    .fused_recovery_not_before = 0;
                f.authority
                    .tick_fused_recovery_v04(&mut vault, manifest, 7, 8, UnixMillisV2::new(now))
                    .unwrap();
            }
            let recovered = f
                .authority
                .reconcile_fused_execution_v04(
                    &original,
                    RequestIdV2::new([79; 16]),
                    &mut vault,
                    manifest,
                    7,
                    8,
                    UnixMillisV2::new(210),
                )
                .unwrap();
            assert!(matches!(
                recovered.0.status(),
                PublicExecutionStatusV2::Succeeded { .. }
            ));
            assert_eq!(disk(&f), checkpoint_head);
            assert_eq!(server.join().unwrap().len(), messages);
            assert_eq!(observed.requests().len(), 1);
            return;
        }
        f.authority
            .tick_fused_recovery_v04(&mut vault, manifest, 7, 8, UnixMillisV2::new(209))
            .unwrap();
        assert_eq!(
            disk(&f),
            checkpoint_head,
            "rate-limited tick does not repeat reconciliation"
        );
        forget_private_execution_memory(&mut f);
        // Cleanup remains legal after the original result lifetime: no plaintext
        // fetch, new document, lifetime extension or new task authorization.
        f.authority
            .tick_private_workflows_v04(&mut f.values, Some(&mut vault), || UnixMillisV2::new(1208))
            .unwrap();
        assert!(
            f.authority.executions.is_empty(),
            "cleanup needs no process handles"
        );
        assert_eq!(disk(&f), checkpoint_head);
        if matches!(case, 16 | 17) {
            assert!(f
                .authority
                .policy
                .as_ref()
                .unwrap()
                .fused_cleanup_confirmed
                .is_empty());
            // Bad cleanup evidence cannot cause acknowledgement; a later exact
            // response is still accepted without redoing the effect.
            f.authority
                .tick_fused_recovery_v04(&mut vault, manifest, 7, 8, UnixMillisV2::new(2208))
                .unwrap();
        }
        if matches!(case, 14 | 16 | 17) {
            f.authority
                .tick_fused_recovery_v04(&mut vault, manifest, 7, 8, UnixMillisV2::new(3208))
                .unwrap();
        }
        assert_eq!(
            f.authority
                .policy
                .as_ref()
                .unwrap()
                .fused_cleanup_confirmed
                .len(),
            1
        );
        // Cache suppresses further IPC, while durable checkpoint remains exact.
        f.authority
            .tick_fused_recovery_v04(&mut vault, manifest, 7, 8, UnixMillisV2::new(4208))
            .unwrap();
        assert_eq!(disk(&f), checkpoint_head);
        assert!(f.authority.sessions.is_empty());
        assert!(f.authority.intents.is_empty());
        assert!(f.authority.execution_tickets.is_empty());
        assert_eq!(
            f.authority
                .policy
                .as_ref()
                .unwrap()
                .durable
                .task_authorization_state(task)
                .unwrap()
                .clause_consumption(1),
            Some((1, 1))
        );
        let seen = server.join().unwrap();
        assert_eq!(seen.len(), messages);
        assert_eq!(
            observed.requests().len(),
            1,
            "never repeats provider effect"
        );
        f.authority.durable_poisoned = true;
        assert_eq!(
            f.authority.tick_fused_recovery_v04(
                &mut vault,
                manifest,
                7,
                8,
                UnixMillisV2::new(5208)
            ),
            Err(savana_kernel_protocol::StableCode::KernelUnavailable)
        );
        return;
    }
    let mut retry = f
        .authority
        .dispatch_fused_action_v04(
            &action,
            RequestIdV2::new([22; 16]),
            manifest,
            7,
            8,
            UnixMillisV2::new(206),
        )
        .unwrap();
    if let Ok(sent) = sent {
        assert_eq!(sent.0, retry.0);
    }
    assert_eq!(disk(&f), after, "retry is query-only, no new G7 charge");
    assert_eq!(f.authority.executions.len(), 1);
    assert_eq!(
        f.authority
            .policy
            .as_ref()
            .unwrap()
            .durable
            .task_authorization_state(task)
            .unwrap()
            .clause_consumption(1),
        Some((1, 1))
    );
    // Isolation must precede the dispatch cache and each status selector.
    assert!(f
        .authority
        .dispatch_execution(
            RequestIdV2::new([23; 16]),
            savana_kernel_protocol::v2::DispatchExecutionRequestV2::new(ticket),
            f.caller_identity,
            manifest,
            7,
            8,
            UnixMillisV2::new(206)
        )
        .is_err());
    let mut vault = tool_result_data_fixture(&f);
    for target in [
        ExecutionStatusTargetV2::Intent(action.intent),
        ExecutionStatusTargetV2::Ticket(ticket),
        ExecutionStatusTargetV2::Execution(retry.0),
    ] {
        assert!(f
            .authority
            .execution_status(
                RequestIdV2::new([24; 16]),
                GetExecutionStatusRequestV2::new(target),
                &mut vault,
                f.caller_identity,
                manifest,
                7,
                8,
                UnixMillisV2::new(206)
            )
            .is_err());
    }
    assert!(f
        .authority
        .reconcile_fused_execution_v04(
            &retry,
            RequestIdV2::new([25; 16]),
            &mut vault,
            manifest,
            8,
            8,
            UnixMillisV2::new(207)
        )
        .is_err());
    assert_eq!(disk(&f), after);
    if case == 8 {
        let old_handle = retry.0;
        // No login/session, G4 intent, approval or ticket survives this restart
        // simulation. Durable owner reopen is separately tested in policy core.
        f.authority.sessions.clear();
        f.authority.intents.clear();
        f.authority.execution_tickets.clear();
        f.authority.tool_approvals.clear();
        f.authority.executions.clear();
        f.authority.handle_key =
            savana_kernel_protocol::v2::AuthorityHandleKeyV2::from_entropy([0x48; 32]).unwrap();
        assert!(f
            .authority
            .restore_fused_execution_queries_v04(task, manifest, 8, 8)
            .is_err());
        assert!(f.authority.executions.is_empty());
        let maximum = f.authority.maximum_records;
        f.authority.maximum_records = 0;
        assert!(f
            .authority
            .restore_fused_execution_queries_v04(task, manifest, 7, 8)
            .is_err());
        assert!(f.authority.executions.is_empty());
        f.authority.maximum_records = maximum;
        retry = f
            .authority
            .restore_fused_execution_queries_v04(task, manifest, 7, 8)
            .unwrap()
            .remove(0);
        assert_ne!(retry.0, old_handle);
        let again = f
            .authority
            .restore_fused_execution_queries_v04(task, manifest, 7, 8)
            .unwrap();
        assert_eq!(again[0].0, retry.0);
        assert!(f.authority.sessions.is_empty());
        assert!(f.authority.intents.is_empty());
        assert!(f.authority.execution_tickets.is_empty());
        assert!(f
            .authority
            .execution_status(
                RequestIdV2::new([49; 16]),
                GetExecutionStatusRequestV2::new(ExecutionStatusTargetV2::Execution(retry.0)),
                &mut vault,
                f.caller_identity,
                manifest,
                7,
                8,
                UnixMillisV2::new(207)
            )
            .is_err());
        assert_eq!(disk(&f), after, "restoring query handles is read-only");
    }
    let mut result = f.authority.reconcile_fused_execution_v04(
        &retry,
        RequestIdV2::new([26; 16]),
        &mut vault,
        manifest,
        7,
        8,
        UnixMillisV2::new(207),
    );
    if (10..=12).contains(&case) {
        assert!(result.is_err(), "injected recovery cut");
        forget_private_execution_memory(&mut f);
        retry = f
            .authority
            .restore_fused_execution_queries_v04(task, manifest, 7, 8)
            .unwrap()
            .remove(0);
        result = f.authority.reconcile_fused_execution_v04(
            &retry,
            RequestIdV2::new([51; 16]),
            &mut vault,
            manifest,
            7,
            8,
            UnixMillisV2::new(208),
        );
    }
    if (5..=7).contains(&case) {
        assert!(matches!(
            result,
            Err(KernelAgentAuthorityErrorV2::BindingMismatch)
        ));
        assert_eq!(
            disk(&f),
            after,
            "foreign/invalid receipt never settles or fetches"
        );
        assert_eq!(server.join().unwrap().len(), messages);
        assert_eq!(observed.requests().len(), 1);
        return;
    }
    if case == 3 {
        assert_eq!(
            result.unwrap().0.status(),
            PublicExecutionStatusV2::Indeterminate
        );
        assert_eq!(
            f.authority
                .policy
                .as_ref()
                .unwrap()
                .durable
                .task_authorization_state(task)
                .unwrap()
                .clause_consumption(1),
            Some((1, 1))
        );
        // Root revocation/approval expiry forbid new effects, but may not erase
        // the original reservation or prevent accounting for its late success.
        f.authority
            .policy
            .as_mut()
            .unwrap()
            .durable
            .revoke_task_authorization(task)
            .unwrap();
        result = f.authority.reconcile_fused_execution_v04(
            &retry,
            RequestIdV2::new([27; 16]),
            &mut vault,
            manifest,
            7,
            8,
            UnixMillisV2::new(351),
        );
    } else if case == 4 {
        assert!(result.is_err(), "lost cleanup ack");
        result = f.authority.reconcile_fused_execution_v04(
            &retry,
            RequestIdV2::new([28; 16]),
            &mut vault,
            manifest,
            7,
            8,
            UnixMillisV2::new(208),
        );
    }
    let result = result.unwrap();
    if case == 8 {
        // Cleanup has completed: execd no longer needs to serve the payload.
        // Another volatile reset restores the document from the vault checkpoint
        // without any executor request or provider attempt.
        let head = disk(&f);
        f.authority.executions.clear();
        f.authority.handle_key =
            savana_kernel_protocol::v2::AuthorityHandleKeyV2::from_entropy([0x49; 32]).unwrap();
        let restored = f
            .authority
            .restore_fused_execution_queries_v04(task, manifest, 7, 8)
            .unwrap()
            .remove(0);
        let recovered = f
            .authority
            .reconcile_fused_execution_v04(
                &restored,
                RequestIdV2::new([50; 16]),
                &mut vault,
                manifest,
                7,
                8,
                UnixMillisV2::new(208),
            )
            .unwrap();
        assert!(matches!(
            recovered.0.status(),
            PublicExecutionStatusV2::Succeeded { .. }
        ));
        let again = f
            .authority
            .reconcile_fused_execution_v04(
                &restored,
                RequestIdV2::new([52; 16]),
                &mut vault,
                manifest,
                7,
                8,
                UnixMillisV2::new(209),
            )
            .unwrap();
        assert_eq!(
            recovered.0, again.0,
            "same-process restore does not mint unlimited document handles"
        );
        assert_eq!(disk(&f), head);
    }
    if case == 2 {
        assert!(matches!(
            result.0.status(),
            PublicExecutionStatusV2::FailedNoEffect { .. }
        ));
    } else {
        assert!(matches!(
            result.0.status(),
            PublicExecutionStatusV2::Succeeded { .. }
        ));
    }
    assert_eq!(
        f.authority
            .policy
            .as_ref()
            .unwrap()
            .durable
            .task_authorization_state(task)
            .unwrap()
            .clause_consumption(1),
        // This root forbids retry-after-no-effect, so even an authenticated
        // no-effect receipt cannot restore its magnitude budget.
        Some((1, 1))
    );
    assert_eq!(server.join().unwrap().len(), messages);
    assert_eq!(observed.requests().len(), if case == 2 { 0 } else { 1 });
}

#[cfg(feature = "test-support")]
#[test]
fn fused_private_loop_completes_two_dependent_clauses_without_repreparing_consumed_work() {
    private_dispatch_fixture(26);
}

#[cfg(feature = "test-support")]
#[test]
fn fused_result_loop_passes_verified_predecessor_result_to_next_effect() {
    private_dispatch_fixture(32);
}

#[test]
#[cfg(feature = "test-support")]
fn fused_result_loop_reopens_encrypted_owner_without_resending_predecessor() {
    private_dispatch_fixture(33);
}

#[test]
#[cfg(feature = "test-support")]
fn fused_result_loop_waits_for_exact_second_step_approval() {
    private_dispatch_fixture(34);
}

#[test]
#[cfg(feature = "test-support")]
fn fused_result_loop_revocation_stops_downstream_without_resetting_consumption() {
    private_dispatch_fixture(35);
}

#[test]
#[cfg(feature = "test-support")]
fn fused_result_loop_three_steps_consume_immediate_predecessor_once() {
    private_dispatch_fixture(36);
}

#[test]
#[cfg(feature = "test-support")]
fn fused_result_loop_unknown_blocks_without_fabricating_result_or_refunding() {
    private_dispatch_fixture(37);
}

#[test]
#[cfg(feature = "test-support")]
fn fused_dynamic_observation_from_real_execution_through_g3_survives_reopen() {
    private_dispatch_fixture(38);
}

#[test]
#[cfg(feature = "test-support")]
fn fused_dynamic_observation_without_g3_never_reaches_model_or_retries() {
    private_dispatch_fixture(39);
}

#[test]
#[cfg(feature = "test-support")]
fn fused_final_result_native_pipeline_retains_terminal_bytes_without_publication() {
    private_dispatch_fixture(40);
}

#[test]
#[cfg(feature = "test-support")]
fn fused_final_release_native_pipeline_publishes_only_approved_terminal_result() {
    private_dispatch_fixture(41);
}

#[test]
#[cfg(feature = "test-support")]
fn fused_final_release_encrypted_reopen_reconciles_original_dispatch_without_session_or_resend() {
    private_dispatch_fixture(42);
}

#[cfg(feature = "test-support")]
fn assert_fused_final_release(
    f: &mut PlannerAuthorityFixtureV2,
    vault: &mut dyn crate::v2_core_services::KernelIngressCommitSinkV2,
    manifest: Digest32V2,
    at: u64,
    clock: &std::sync::atomic::AtomicU64,
    reopen: bool,
) {
    use crate::v2_agent_durable::DurableKernelAgentAuthorityStateV2;
    use savana_kernel_protocol::v2::*;
    let path = f
        ._directory
        .path()
        .join("kernel-agent-authority-state-v2.cbor");
    let anchor = TestAgentStateAnchorV2::default();
    if reopen {
        f.authority.durable_state = Some(
            DurableKernelAgentAuthorityStateV2::open(
                &path,
                [0xe1; 32],
                f.authority.config.installation_id,
                Digest32V2::new([0xe2; 32]),
                Box::new(anchor.clone()),
            )
            .unwrap()
            .0,
        );
    }
    let run = f.authority.sessions[0].run;
    let task = f.authority.sessions[0].durable_task_id;
    assert!(f.authority.fused_publication_v04(task).unwrap().is_none());
    let prepare = f
        .authority
        .prepare_fused_release_v04(run, vault, manifest, 7, 8, UnixMillisV2::new(at))
        .unwrap();
    let again = f
        .authority
        .prepare_fused_release_v04(run, vault, manifest, 7, 8, UnixMillisV2::new(at))
        .unwrap();
    assert_eq!(prepare.envelope(), again.envelope());
    let envelope = prepare.envelope().unverified_material().unwrap();
    let candidate = f
        .authority
        .prepare_fused_final_result_v04(run, manifest, 7, 8, UnixMillisV2::new(at))
        .unwrap();
    let delivery = decode_final_result_release_delivery_v04(
        &f.authority.pending_releases[0]
            .business_request
            .canonical_json(),
    )
    .unwrap();
    assert_eq!(delivery.payload(), candidate.private_payload());
    assert_eq!(delivery.turn_binding(), Digest32V2::new([4; 32]));
    assert!(decode_final_release_delivery_v2(
        &f.authority.pending_releases[0]
            .business_request
            .canonical_json()
    )
    .is_err());
    let key = SigningKey::from_bytes(&[0x9c; 32]);
    let generic = UnsignedApprovalSettlementV2::new(
        f.authority.config.installation_id,
        manifest,
        7,
        ApprovalPurposeV2::FinalRelease,
        prepare.envelope().envelope_digest().unwrap(),
        ApprovalDecisionV2::Approve,
        envelope.expected_principal(),
        Digest32V2::new([0xd1; 32]),
        Digest32V2::new([0xd2; 32]),
        true,
        true,
        false,
        false,
        2,
        envelope.decision_challenge(),
        Nonce32V2::new([0xd3; 32]),
        UnixMillisV2::new(at),
        envelope.expires_at(),
    )
    .unwrap();
    let receipt = SignedApprovalSettlementV2::sign(generic, &key)
        .unwrap()
        .with_task_action_approval(
            sign_task_action_approval_v2(
                TaskActionApprovalV2::new(
                    envelope.task_action_context(&generic).unwrap(),
                    TaskActionApprovalDecisionV2::Approve,
                    generic.issued_at(),
                    generic.expires_at(),
                )
                .unwrap(),
                &key,
            )
            .unwrap(),
        )
        .unwrap();
    let request =
        AuthorizeReleaseRequestV2::new(prepare.pending(), prepare.approval(), receipt).unwrap();
    assert!(f
        .authority
        .authorize_release(
            &request,
            vault,
            f.caller_identity,
            manifest,
            7,
            UnixMillisV2::new(at)
        )
        .is_err());
    let authorized = f
        .authority
        .authorize_release_for(&request, vault, true, manifest, 7, UnixMillisV2::new(at))
        .unwrap();
    let dispatch = DispatchReleaseRequestV2::new(authorized.ticket());
    assert!(
        f.authority.fused_publication_v04(task).unwrap().is_none(),
        "approval is not publication"
    );
    assert!(f
        .authority
        .dispatch_release(
            RequestIdV2::new([90; 16]),
            dispatch.clone(),
            vault,
            f.caller_identity,
            manifest,
            7,
            8,
            UnixMillisV2::new(at + 1)
        )
        .is_err());
    // No signed final-output declassification rule yet: approval alone is not enough.
    assert!(f
        .authority
        .dispatch_release_for(
            RequestIdV2::new([91; 16]),
            dispatch.clone(),
            vault,
            true,
            manifest,
            7,
            8,
            UnixMillisV2::new(at + 1)
        )
        .is_err());
    assert_eq!(
        f.authority
            .policy
            .as_ref()
            .unwrap()
            .durable
            .task_authorization_state(task)
            .unwrap()
            .clause_consumption(3),
        Some((0, 0))
    );
    let destination = f.authority.pending_releases[0]
        .task_match
        .content()
        .action()
        .destination_digest();
    f.authority.policy.as_mut().unwrap().declassification_rules =
        planner_declassification_rules_with_handoffs(true, None, Some(destination));
    clock.store(at + 2, std::sync::atomic::Ordering::SeqCst);
    let dispatched = f
        .authority
        .dispatch_release_for(
            RequestIdV2::new([92; 16]),
            dispatch.clone(),
            vault,
            true,
            manifest,
            7,
            8,
            UnixMillisV2::new(at + 2),
        )
        .unwrap();
    let retry = f
        .authority
        .dispatch_release_for(
            RequestIdV2::new([93; 16]),
            dispatch,
            vault,
            true,
            manifest,
            7,
            8,
            UnixMillisV2::new(at + 2),
        )
        .unwrap();
    assert_eq!(retry.release(), dispatched.release());
    let status_request =
        GetReleaseStatusRequestV2::new(ReleaseStatusTargetV2::Release(dispatched.release()));
    assert!(f
        .authority
        .release_status(
            RequestIdV2::new([94; 16]),
            status_request.clone(),
            vault,
            f.caller_identity,
            UnixMillisV2::new(at + 3)
        )
        .is_err());
    clock.store(at + 3, std::sync::atomic::Ordering::SeqCst);
    if reopen {
        let core = f.authority.fused_release_recovery[0].dispatch.unwrap();
        // Reproduce the cross-journal crash window: G7 is durable but the
        // publication archive has not recorded its original dispatch yet.
        f.authority.fused_release_recovery[0].dispatch = None;
        f.authority.persist_fused_release_archive_v04().unwrap();
        let reopen_owner = |f: &mut PlannerAuthorityFixtureV2| {
            drop(f.authority.durable_state.take());
            let (store, snapshot) = DurableKernelAgentAuthorityStateV2::open(
                &path,
                [0xe1; 32],
                f.authority.config.installation_id,
                Digest32V2::new([0xe2; 32]),
                Box::new(anchor.clone()),
            )
            .unwrap();
            f.authority.sessions.clear();
            f.authority.tasks.clear();
            f.authority.authentication_preparations.clear();
            f.authority.intents.clear();
            f.authority.executions.clear();
            f.authority.pending_releases.clear();
            f.authority.release_tickets.clear();
            f.authority.releases.clear();
            f.authority.fused_approval_recovery.clear();
            f.authority.fused_release_recovery.clear();
            f.authority
                .restore_recovery_snapshot(&snapshot.unwrap(), UnixMillisV2::new(at + 3))
                .unwrap();
            f.authority.durable_state = Some(store);
            assert!(f.authority.sessions.is_empty());
            assert!(f.authority.pending_releases.is_empty());
        };
        reopen_owner(f);
        assert!(f.authority.fused_release_recovery[0].dispatch.is_none());
        f.authority.restore_fused_release_dispatches_v04().unwrap();
        assert_eq!(f.authority.fused_release_recovery[0].dispatch, Some(core));
        f.authority
            .reconcile_fused_release_v04(0, vault, UnixMillisV2::new(at + 3))
            .unwrap();
        let committed = f.authority.fused_release_recovery[0].commit.unwrap();
        reopen_owner(f);
        assert_eq!(
            f.authority.fused_release_recovery[0].commit,
            Some(committed)
        );
        f.authority
            .reconcile_fused_release_v04(0, vault, UnixMillisV2::new(at + 3))
            .unwrap();
        assert_eq!(f.authority.fused_release_recovery[0].dispatch, Some(core));
        assert_eq!(
            f.authority.fused_release_recovery[0].commit,
            Some(committed)
        );
    } else {
        let status = f
            .authority
            .release_status_for(
                RequestIdV2::new([95; 16]),
                status_request,
                vault,
                true,
                UnixMillisV2::new(at + 3),
            )
            .unwrap();
        assert!(
            matches!(status.status(), PublicExecutionStatusV2::Succeeded { .. }),
            "{status:?}"
        );
    }
    let publication = f.authority.fused_publication_v04(task).unwrap().unwrap();
    assert_eq!(publication.task(), task);
    assert_eq!(
        publication.approval_digest(),
        prepare.envelope().envelope_digest().unwrap()
    );
    assert!(publication.matches_payload(delivery.payload()));
    assert!(!publication.matches_payload(b"invented result"));
    assert_eq!(
        publication.commit_digest(),
        f.authority.fused_release_recovery[0].commit.unwrap()
    );
    let state = f
        .authority
        .policy
        .as_ref()
        .unwrap()
        .durable
        .task_authorization_state(task)
        .unwrap();
    assert_eq!(state.clause_consumption(1), Some((1, 1)));
    assert_eq!(state.clause_consumption(2), Some((1, 1)));
    assert_eq!(state.clause_consumption(3), Some((1, 1)));
}

#[cfg(feature = "test-support")]
fn assert_fused_final_result(f: &mut PlannerAuthorityFixtureV2, manifest: Digest32V2, time: u64) {
    let run = f.authority.sessions[0].run;
    let before = disk(f);
    let c = f
        .authority
        .prepare_fused_final_result_v04(run, manifest, 7, 8, UnixMillisV2::new(time))
        .unwrap();
    assert_eq!(c.source(), 2);
    let bytes: serde_json::Value = serde_json::from_slice(c.private_payload()).unwrap();
    assert_eq!(
        bytes["result"]["structuredContent"]["savana_status"],
        "succeeded"
    );
    let digest = c.digest();
    let task = c.task();
    let jobs = f
        .authority
        .policy
        .as_ref()
        .unwrap()
        .durable
        .recover_fused_executions_v04(task)
        .unwrap();
    assert_eq!(c.core().execution_nonce(), jobs[1].core().execution_nonce());
    assert_ne!(c.core().execution_nonce(), jobs[0].core().execution_nonce());
    for (m, generation, fence) in [
        (Digest32V2::new([42; 32]), 7, 8),
        (manifest, 8, 8),
        (manifest, 7, 9),
    ] {
        assert!(f
            .authority
            .prepare_fused_final_result_v04(run, m, generation, fence, UnixMillisV2::new(time))
            .is_err());
    }
    let original = f.authority.sessions[0].durable_run_id;
    f.authority.sessions[0].durable_run_id = DurableRunIdV2::new([42; 32]);
    assert!(f
        .authority
        .prepare_fused_final_result_v04(run, manifest, 7, 8, UnixMillisV2::new(time))
        .is_err());
    f.authority.sessions[0].durable_run_id = original;
    let principal = f.authority.sessions[0].principal;
    f.authority.sessions[0].principal = PrincipalIdV2::new([42; 32]);
    assert!(f
        .authority
        .prepare_fused_final_result_v04(run, manifest, 7, 8, UnixMillisV2::new(time))
        .is_err());
    f.authority.sessions[0].principal = principal;
    assert_eq!(
        f.authority
            .prepare_fused_final_result_v04(run, manifest, 7, 8, UnixMillisV2::new(time))
            .unwrap()
            .digest(),
        digest
    );
    assert_eq!(
        disk(f),
        before,
        "private preparation cannot reserve or publish an output"
    );
}

/// Explicit opt-in conformance probe; synthetic keys and local AgentDojo data.
/// No provider URL, credentials or test authority enters a release build.
#[test]
#[cfg(all(feature = "test-support", unix))]
#[ignore = "run with savana_bench agentdojo-native-probe (local synthetic provider)"]
fn fused_agentdojo_provider_roundtrip_v04() {
    use std::io::{Read as _, Write as _};
    use std::os::unix::net::UnixStream;
    let socket = std::env::var_os("SAVANA_AGENTDOJO_TEST_SOCKET").expect("explicit test socket");
    let case: u8 = std::env::var("SAVANA_AGENTDOJO_TEST_CASE")
        .unwrap()
        .parse()
        .unwrap();
    assert!(matches!(case, 32 | 33 | 34 | 35 | 36 | 41 | 42));
    let replies = std::sync::Arc::new(std::sync::Mutex::new(Vec::<Vec<u8>>::new()));
    let captured = replies.clone();
    let exchange = std::sync::Arc::new(
        move |request: &[u8], maximum: u32, deadline: std::time::Instant| {
            let timeout = deadline
                .checked_duration_since(std::time::Instant::now())
                .ok_or(())?;
            let mut stream = UnixStream::connect(&socket).map_err(|_| ())?;
            stream.set_read_timeout(Some(timeout)).map_err(|_| ())?;
            stream.set_write_timeout(Some(timeout)).map_err(|_| ())?;
            let length = u32::try_from(request.len()).map_err(|_| ())?;
            stream.write_all(&length.to_be_bytes()).map_err(|_| ())?;
            stream.write_all(request).map_err(|_| ())?;
            let mut length = [0; 4];
            stream.read_exact(&mut length).map_err(|_| ())?;
            let length = u32::from_be_bytes(length);
            if length == 0 || length > maximum || length > 32 * 1024 {
                return Err(());
            }
            let mut reply = vec![0; length as usize];
            stream.read_exact(&mut reply).map_err(|_| ())?;
            captured.lock().map_err(|_| ())?.push(reply.clone());
            Ok(reply)
        },
    );
    private_dispatch_fixture_with_provider(case, Some(exchange), Some(replies));
}

#[cfg(feature = "test-support")]
#[test]
fn fused_private_loop_resumes_after_execution_memory_loss_without_resetting_consumption() {
    private_dispatch_fixture(27);
}

#[cfg(feature = "test-support")]
#[test]
fn fused_private_loop_rejects_planner_order_that_skips_signed_success_dependency() {
    private_dispatch_fixture(28);
}

#[cfg(feature = "test-support")]
#[test]
fn fused_private_loop_stops_when_root_is_revoked_between_steps() {
    private_dispatch_fixture(29);
}

#[cfg(feature = "test-support")]
#[test]
fn fused_private_loop_waits_for_new_action_approval_between_steps() {
    private_dispatch_fixture(30);
}

#[cfg(feature = "test-support")]
#[test]
fn fused_private_loop_completes_after_second_step_exact_approval_and_next_owner_tick() {
    private_dispatch_fixture(31);
}

// Cryptographically valid synthetic approvald settlement, not browser/hardware
// evidence. No production G6 signature or action binding is bypassed.
#[cfg(feature = "test-support")]
fn private_loop_signed_approval(
    f: &PlannerAuthorityFixtureV2,
    issued: u64,
    expires: u64,
) -> savana_kernel_protocol::v2::SignedApprovalSettlementV2 {
    use savana_kernel_protocol::v2::{
        sign_task_action_approval_v2, ApprovalDecisionV2, SignedApprovalSettlementV2,
        TaskActionApprovalDecisionV2, TaskActionApprovalV2, UnsignedApprovalSettlementV2,
    };
    let envelope = &f.authority.tool_approvals.last().unwrap().envelope;
    let material = envelope.unverified_material().unwrap();
    let unsigned = UnsignedApprovalSettlementV2::new(
        f.authority.config.installation_id,
        f.authority.sessions[0].active_state_manifest_digest,
        7,
        ApprovalPurposeV2::ToolExecution,
        envelope.envelope_digest().unwrap(),
        ApprovalDecisionV2::Approve,
        material.expected_principal(),
        Digest32V2::new([0xd1; 32]),
        Digest32V2::new([0xd2; 32]),
        true,
        true,
        false,
        false,
        2,
        material.decision_challenge(),
        Nonce32V2::new([0xd3; 32]),
        UnixMillisV2::new(issued),
        UnixMillisV2::new(expires),
    )
    .unwrap();
    let key = SigningKey::from_bytes(&[0x9c; 32]);
    let exact = sign_task_action_approval_v2(
        TaskActionApprovalV2::new(
            material.task_action_context(&unsigned).unwrap(),
            TaskActionApprovalDecisionV2::Approve,
            unsigned.issued_at(),
            unsigned.expires_at(),
        )
        .unwrap(),
        &key,
    )
    .unwrap();
    SignedApprovalSettlementV2::sign(unsigned, &key)
        .unwrap()
        .with_task_action_approval(exact)
        .unwrap()
}

#[test]
#[cfg(feature = "test-support")]
fn fused_private_g7_success_and_legacy_cache_isolation() {
    private_dispatch_fixture(0);
}
#[test]
#[cfg(feature = "test-support")]
fn fused_private_g7_lost_dispatch_response_queries_original_execution() {
    private_dispatch_fixture(1);
}
#[test]
#[cfg(feature = "test-support")]
fn fused_private_g7_signed_no_effect_preserves_root_retry_policy() {
    private_dispatch_fixture(2);
}
#[test]
#[cfg(feature = "test-support")]
fn fused_private_g7_unknown_late_success_survives_revocation_and_expiry() {
    private_dispatch_fixture(3);
}
#[test]
#[cfg(feature = "test-support")]
fn fused_private_g7_lost_ack_keeps_committed_result() {
    private_dispatch_fixture(4);
}

#[test]
#[cfg(feature = "test-support")]
fn fused_private_g7_rejects_foreign_nonce_key_and_receipt_digest() {
    for case in 5..=7 {
        private_dispatch_fixture(case);
    }
}

#[test]
#[cfg(feature = "test-support")]
fn fused_private_g7_recovers_queries_and_results_without_session_intent_or_ticket() {
    private_dispatch_fixture(8);
}

#[cfg(feature = "test-support")]
fn forget_private_execution_memory(f: &mut PlannerAuthorityFixtureV2) {
    f.authority.sessions.clear();
    f.authority.intents.clear();
    f.authority.execution_tickets.clear();
    f.authority.tool_approvals.clear();
    f.authority.executions.clear();
    let policy = f.authority.policy.as_mut().unwrap();
    policy.fused_workflow_phase = 0;
    policy.fused_action_last_task = None;
    policy.fused_action_not_before = 0;
    policy.fused_recovery_not_before = 0;
    policy.fused_recovery_last_nonce = None;
    policy.fused_cleanup_confirmed.clear();
    f.authority.handle_key =
        savana_kernel_protocol::v2::AuthorityHandleKeyV2::from_entropy([0x50; 32]).unwrap();
}

#[test]
#[cfg(feature = "test-support")]
fn fused_private_g7_recovers_prepare_without_minting_a_new_send_ticket() {
    private_dispatch_fixture(9);
}

#[test]
#[cfg(feature = "test-support")]
fn fused_private_g7_recovers_vault_outcome_and_checkpoint_crash_boundaries() {
    for case in 10..=12 {
        private_dispatch_fixture(case);
    }
}

#[test]
#[cfg(feature = "test-support")]
fn fused_recovery_driver_discovers_original_execution_without_session_or_ticket() {
    private_dispatch_fixture(13);
}

#[test]
#[cfg(feature = "test-support")]
fn fused_recovery_driver_retries_cleanup_after_checkpoint_crash_and_lost_ack() {
    private_dispatch_fixture(14);
    private_dispatch_fixture(15);
}

#[test]
#[cfg(feature = "test-support")]
fn fused_recovery_driver_rejects_changed_completion_and_receipt_before_cleanup() {
    private_dispatch_fixture(16);
    private_dispatch_fixture(17);
}

#[test]
#[cfg(feature = "test-support")]
fn fused_recovery_driver_retains_reservation_on_executor_unavailability() {
    private_dispatch_fixture(18);
}

#[test]
#[cfg(feature = "test-support")]
fn fused_recovery_driver_cleanup_preserves_existing_private_result_handle() {
    private_dispatch_fixture(19);
}

#[test]
#[cfg(feature = "test-support")]
fn fused_action_driver_runs_real_g4_through_g7_and_serializes_unsettled_work() {
    private_dispatch_fixture(20);
}

#[test]
#[cfg(feature = "test-support")]
fn fused_action_driver_never_resends_after_g7_prepare_or_lost_dispatch_response() {
    private_dispatch_fixture(21);
    private_dispatch_fixture(22);
}

#[test]
#[cfg(feature = "test-support")]
fn fused_action_driver_refuses_fence_change_between_evaluation_and_dispatch() {
    private_dispatch_fixture(23);
}

#[test]
#[cfg(feature = "test-support")]
fn fused_action_driver_resumes_only_after_exact_signed_approval() {
    private_dispatch_fixture(24);
}

#[test]
#[cfg(feature = "test-support")]
fn fused_action_driver_does_not_execute_an_expired_signed_approval() {
    private_dispatch_fixture(25);
}
