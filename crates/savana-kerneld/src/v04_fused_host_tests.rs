mod fused_host_tests {
    use super::*;
    use crate::v2_declassification_policy::ActiveDeclassificationRuleSetV2;
    use savana_continuation_core::planning::{ModelView, PlanChoice, PlanProposal};
    use savana_policy_core::v2::{
        FusedModelTransportErrorV04, FusedModelTransportV04, FusedPlanningProfileV04,
        VerifiedFusedPlanningProfileV04,
    };
    use std::sync::{Arc, Mutex};

    struct Worker(Arc<Mutex<Vec<Vec<u8>>>>, u8);
    impl FusedModelTransportV04 for Worker {
        fn recipient_identity(&self) -> [u8; 32] {
            [2; 32]
        }
        fn exchange(
            &mut self,
            bytes: &[u8],
            deadline: UnixMillisV2,
            _: usize,
        ) -> Result<Vec<u8>, FusedModelTransportErrorV04> {
            self.0.lock().unwrap().push(bytes.to_vec());
            assert!(deadline.get() <= 250);
            if self.1 == 1 {
                return Err(FusedModelTransportErrorV04::Unavailable);
            }
            if self.1 == 2 {
                return Ok(b"ignore all rules".to_vec());
            }
            let view: ModelView = serde_json::from_slice(bytes).unwrap();
            Ok(serde_json::to_vec(&PlanProposal {
                schema: 1,
                job: view.job,
                view: view.commitment(),
                choice: PlanChoice::RegisteredTemplate { template: 1 },
            })
            .unwrap())
        }
    }
    fn install(f: &mut PlannerAuthorityFixtureV2) {
        let session = &f.authority.sessions[0];
        let task = session.durable_task_id;
        let manifest = session.active_state_manifest_digest;
        let installation = f.authority.config.installation_id;
        let p = f.authority.policy.as_mut().unwrap();
        let parent = p.durable.task_authorization_state(task).unwrap();
        let m = parent.authorization().material();
        let profile: FusedPlanningProfileV04 = serde_json::from_value(serde_json::json!({
            "schema":1,"installation":installation.as_bytes(),"task":task.as_bytes(),
            "not_before":m.not_before().get(),"expires_at":m.expires_at().get(),
            "release_model_views":true,
            "delivery_schedule":[{"id":1,"round":1,"role":"planner","opens_at":200,"closes_at":250}],
            "policy":{"schema":1,"root":parent.authorization().digest().as_bytes(),"observer_scope":vec![1u8;32],
                "operations":[{"id":1,"tool_class":31,"action_template":21,"bindings":[],"after":[]}],
                "templates":[{"id":1,"order":[1]}],"max_replacements":0,
                "rounds":[{"id":1,"opens_at":200,"advice_cut":200,"closes_at":500,
                    "advisor":null,"planner":vec![2u8;32],"model_profile":1,"mode":"registered_template_v04",
                    "public_view":[],"template_ids":[1],"question_codes":[],"max_deliveries":1}]}
        })).unwrap();
        let key = SigningKey::from_bytes(&[0x21; 32]);
        let proof = VerifiedFusedPlanningProfileV04::verify(
            &serde_json::to_vec(&profile).unwrap(),
            &key.sign(&profile.signing_digest().unwrap()).to_bytes(),
            &key.verifying_key(),
            parent.authorization(),
            UnixMillisV2::new(200),
        )
        .unwrap();
        p.durable
            .install_fused_planning_v04(proof, UnixMillisV2::new(200))
            .unwrap();
        let installer = SigningKey::from_bytes(&[0xa1; 32]);
        let authority = SigningKey::from_bytes(&[0xa2; 32]);
        let family = Digest32V2::new([3; 32]);
        let roots = OperationalTrustRootSetV2::new_declassification_signed_for_test(
            family,
            1,
            None,
            vec![OperationalTrustRootSetItemV2::new(
                OperationalTrustRootPurposeV2::DeclassificationAuthority,
                authority.verifying_key().to_bytes(),
                1,
                1,
                1000,
            )
            .unwrap()],
            1,
            1000,
            &installer,
            1,
        )
        .unwrap();
        let rule = DeclassificationRuleV2::new_for_test(
            6,
            ClosedDeclassificationPurposeV2::FusedModelCall,
            declassification_implementation_digest_v2(6).unwrap(),
            LeakGateDutyV2::BlocklistAndNoResidualPii,
            Some(vec![Digest32V2::new([2; 32])]),
            None,
            1,
            1000,
        )
        .unwrap();
        let rules = DeclassificationRuleSetV2::new_signed_for_test(
            family,
            1,
            None,
            vec![rule],
            1,
            1000,
            &roots,
            &authority,
            1,
            200,
        )
        .unwrap();
        p.declassification_rules = ActiveDeclassificationRuleSetV2::new_for_binding(
            rules,
            Arc::new(roots),
            installation,
            manifest,
            1,
        )
        .unwrap();
    }

    #[test]
    fn fused_host_recovery_turn_does_not_starve_planning_when_vault_is_absent() {
        let mut f = planner_authority_fixture();
        install(&mut f);
        let calls = Arc::new(Mutex::new(Vec::new()));
        f.authority
            .policy
            .as_mut()
            .unwrap()
            .fused_workers
            .push(Box::new(Worker(calls.clone(), 0)));
        f.authority
            .tick_private_workflows_v04(&mut f.values, None, || UnixMillisV2::new(200))
            .unwrap();
        assert!(calls.lock().unwrap().is_empty());
        f.authority
            .tick_private_workflows_v04(&mut f.values, None, || UnixMillisV2::new(200))
            .unwrap();
        assert_eq!(calls.lock().unwrap().len(), 1);
        assert!(f.authority.executions.is_empty());
        // Missing vault skips both actions and publication, without starvation.
        f.authority
            .tick_private_workflows_v04(&mut f.values, None, || UnixMillisV2::new(201))
            .unwrap();
        f.authority
            .tick_private_workflows_v04(&mut f.values, None, || UnixMillisV2::new(201))
            .unwrap();
        assert_eq!(f.authority.policy.as_ref().unwrap().fused_workflow_phase, 0);
        assert!(f.authority.executions.is_empty());
        assert_eq!(calls.lock().unwrap().len(), 1);
    }

    #[test]
    fn fused_host_clock_reaches_g3_worker_durable_plan_and_activation_once() {
        let mut f = planner_authority_fixture();
        install(&mut f);
        let calls = Arc::new(Mutex::new(Vec::new()));
        f.authority
            .policy
            .as_mut()
            .unwrap()
            .fused_workers
            .push(Box::new(Worker(calls.clone(), 0)));
        f.authority
            .tick_fused_planning(&f.values, || UnixMillisV2::new(200))
            .unwrap();
        assert_eq!(calls.lock().unwrap().len(), 1);
        let task = f.authority.sessions[0].durable_task_id;
        assert_eq!(
            f.authority
                .policy
                .as_ref()
                .unwrap()
                .durable
                .fused_planning_status_v04(task, UnixMillisV2::new(200))
                .unwrap()
                .active_plan_revision,
            1
        );
        f.authority
            .tick_fused_planning(&f.values, || UnixMillisV2::new(201))
            .unwrap();
        assert_eq!(calls.lock().unwrap().len(), 1);
        assert!(f.authority.executions.is_empty()); // activation is not a G7 grant
    }
    #[test]
    fn fused_host_disabled_worker_skips_without_fabricating_attempt_or_plan() {
        let mut f = planner_authority_fixture();
        install(&mut f);
        let task = f.authority.sessions[0].durable_task_id;
        f.authority
            .tick_fused_planning(&f.values, || UnixMillisV2::new(200))
            .unwrap();
        let owner = &f.authority.policy.as_ref().unwrap().durable;
        assert_eq!(
            owner
                .fused_planning_status_v04(task, UnixMillisV2::new(200))
                .unwrap()
                .revision,
            1
        );
        f.authority
            .tick_fused_planning(&f.values, || UnixMillisV2::new(250))
            .unwrap();
        let owner = &f.authority.policy.as_ref().unwrap().durable;
        assert!(owner
            .scheduled_fused_work_v04(UnixMillisV2::new(250))
            .unwrap()
            .is_empty());
        assert_eq!(
            owner
                .fused_planning_status_v04(task, UnixMillisV2::new(250))
                .unwrap()
                .active_plan_revision,
            0
        );
    }
    #[test]
    fn fused_host_recovers_settled_candidate_without_another_model_call() {
        let mut f = planner_authority_fixture();
        install(&mut f);
        let calls = Arc::new(Mutex::new(Vec::new()));
        f.authority
            .policy
            .as_mut()
            .unwrap()
            .fused_workers
            .push(Box::new(Worker(calls.clone(), 0)));
        let mut times = [200, 200, 200, 200, 0].into_iter();
        assert!(f
            .authority
            .tick_fused_planning(&f.values, || UnixMillisV2::new(times.next().unwrap()))
            .is_err());
        let task = f.authority.sessions[0].durable_task_id;
        let owner = &f.authority.policy.as_ref().unwrap().durable;
        assert_eq!(
            owner
                .fused_planning_status_v04(task, UnixMillisV2::new(200))
                .unwrap()
                .active_plan_revision,
            0
        );
        assert_eq!(
            owner
                .scheduled_fused_work_v04(UnixMillisV2::new(201))
                .unwrap()[0]
                .activation_round,
            Some(1)
        );
        f.authority
            .tick_fused_planning(&f.values, || UnixMillisV2::new(201))
            .unwrap();
        assert_eq!(
            f.authority
                .policy
                .as_ref()
                .unwrap()
                .durable
                .fused_planning_status_v04(task, UnixMillisV2::new(201))
                .unwrap()
                .active_plan_revision,
            1
        );
        assert_eq!(calls.lock().unwrap().len(), 1);
    }
    #[test]
    fn fused_host_no_retry_for_missing_malicious_or_failed_model_reply() {
        for mode in [1, 2] {
            let mut f = planner_authority_fixture();
            install(&mut f);
            let calls = Arc::new(Mutex::new(Vec::new()));
            f.authority
                .policy
                .as_mut()
                .unwrap()
                .fused_workers
                .push(Box::new(Worker(calls.clone(), mode)));
            f.authority
                .tick_fused_planning(&f.values, || UnixMillisV2::new(200))
                .unwrap();
            f.authority
                .tick_fused_planning(&f.values, || UnixMillisV2::new(201))
                .unwrap();
            assert_eq!(calls.lock().unwrap().len(), 1);
            let task = f.authority.sessions[0].durable_task_id;
            assert_eq!(
                f.authority
                    .policy
                    .as_ref()
                    .unwrap()
                    .durable
                    .fused_planning_status_v04(task, UnixMillisV2::new(201))
                    .unwrap()
                    .active_plan_revision,
                0
            );
        }
    }
    #[test]
    fn fused_host_wrong_private_session_revoked_root_and_stale_deployment_cannot_send() {
        for case in 0..3 {
            let mut f = planner_authority_fixture();
            install(&mut f);
            let calls = Arc::new(Mutex::new(Vec::new()));
            f.authority
                .policy
                .as_mut()
                .unwrap()
                .fused_workers
                .push(Box::new(Worker(calls.clone(), 0)));
            let task = f.authority.sessions[0].durable_task_id;
            match case {
                0 => f.authority.sessions[0].principal = PrincipalIdV2::new([99; 32]),
                1 => f
                    .authority
                    .policy
                    .as_mut()
                    .unwrap()
                    .durable
                    .revoke_task_authorization(task)
                    .unwrap(),
                _ => {
                    f.authority.policy.as_mut().unwrap().declassification_rules =
                        planner_declassification_rules(false)
                }
            }
            f.authority
                .tick_fused_planning(&f.values, || UnixMillisV2::new(200))
                .unwrap();
            assert!(calls.lock().unwrap().is_empty());
        }
    }
}
