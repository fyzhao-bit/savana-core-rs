// Synthetic signer/owner fixture, not passkey or installed-system acceptance.
fn owner_document_fixture(extra: bool, wrong_control: bool, untrusted: bool)
    -> PlannerAuthorityFixtureV2 {
    let (mut f, request) = business_proposal_fixture("A","Alice");
    install(&mut f,&request,1);
    choose(&mut f,1,1,true,202);
    let mut inputs=vec![
        serde_json::json!({"slot":vec![1;16],"text":"private payload"}),
        serde_json::json!({"slot":vec![2;16],"text":if wrong_control {"B"}else{"A"}}),
        serde_json::json!({"slot":vec![3;16],"text":"Alice"})];
    if extra { inputs.push(serde_json::json!({"slot":vec![4;16],"text":"extra"})); }
    let value=KernelValueV2::text(serde_json::json!({"schema":1,"prompt":"send the reports","inputs":inputs}).to_string()).unwrap();
    let s=&f.authority.sessions[0];
    let context=ProvenanceContextV2::from_authenticated_runtime(s.producer_identity,s.durable_run_id,
        s.active_state_manifest_digest,UnixMillisV2::new(200),UnixMillisV2::new(1000)).unwrap();
    let d=Digest32V2::new([71;32]);
    let provenance=if untrusted {
        ProvenanceRecordV2::planner_output(&value,context,d,Digest32V2::new([172;32]),Digest32V2::new([173;32]),&[],EffectSetV2::SEND).unwrap()
    } else { ProvenanceRecordV2::from_verified_kernel_input(&value,context,d,Digest32V2::new([172;32]),Digest32V2::new([173;32]),Digest32V2::new([174;32]),EffectSetV2::SEND).unwrap() };
    f.authority.sessions[0].initial_value=f.values.register_verified_value(f.run,value,provenance).unwrap().handle();
    f
}

fn review_proof(f:&PlannerAuthorityFixtureV2, marker:u8)
    -> savana_policy_core::v2::VerifiedManagedAdminCommandV04 {
    use savana_policy_core::v2::{ManagedAdminCommandV04,ManagedAdminOperationV04,VerifiedManagedAdminCommandV04};
    let s=&f.authority.sessions[0];let key=SigningKey::from_bytes(&[73;32]);
    let command=ManagedAdminCommandV04 { schema:1,installation:*f.authority.config.installation_id.as_bytes(),
        store:[0x9b;32],request:[marker;32],not_before:202,expires_at:800,
        operation:ManagedAdminOperationV04::PreparePlanningExecution { task:*s.durable_task_id.as_bytes(),
            root:*s.task_authorization_digest.unwrap().as_bytes() }};
    VerifiedManagedAdminCommandV04::verify(&command.canonical_bytes().unwrap(),
        &key.sign(&command.signing_digest().unwrap()).to_bytes(),&key.verifying_key(),
        f.authority.config.installation_id,Digest32V2::new([0x9b;32])).unwrap()
}

#[test]
fn fused_owner_inputs_reach_real_pin_and_unsigned_recipe_without_execution_grant() {
    use savana_policy_core::v2::ManagedAdminResultV04;
    let mut f=owner_document_fixture(false,false,false);
    let task=f.authority.sessions[0].durable_task_id;
    let root=f.authority.sessions[0].task_authorization_digest.unwrap();
    let proof=review_proof(&f,74);
    let before=disk(&f);
    let receipt=f.authority.prepare_owner_execution_review_v04(&proof,*task.as_bytes(),*root.as_bytes(),
        &mut f.values,UnixMillisV2::new(203)).unwrap();
    assert_ne!(disk(&f),before);
    let ManagedAdminResultV04::PlanningExecutionPrepared { run,approval,.. }=receipt.result() else {panic!("review receipt")};
    assert_eq!(run,f.authority.sessions[0].durable_run_id.as_bytes());
    assert_eq!(approval.bindings.len(),1);
    assert_eq!(approval.recipe_schema,2);
    let p=f.authority.policy.as_ref().unwrap();
    assert!(p.durable.fused_inputs_pinned_v04(task).unwrap());
    assert!(p.durable.active_fused_plan_v04(task,UnixMillisV2::new(204)).unwrap().recipe_deadline().is_none());
    assert!(p.durable.recover_fused_executions_v04(task).unwrap().is_empty());
    let frozen=disk(&f);
    assert!(p.durable.managed_admin_receipt_v04(&proof).unwrap().is_some());
    assert_eq!(disk(&f),frozen);
    // A new review request resolves original durable values, never re-pins.
    let proof2=review_proof(&f,75);
    let again=f.authority.prepare_owner_execution_review_v04(&proof2,*task.as_bytes(),*root.as_bytes(),
        &mut f.values,UnixMillisV2::new(204)).unwrap();
    let ManagedAdminResultV04::PlanningExecutionPrepared { approval:a,.. }=again.result() else {panic!("review")};
    assert_eq!(approval.inputs_digest,a.inputs_digest);
    assert_eq!(approval.bindings[0].recipe,a.bindings[0].recipe);
}

#[test]
fn fused_owner_input_intake_rejects_unsigned_source_extra_slots_and_wrong_root_controls() {
    for case in 0..3 {
        let mut f=owner_document_fixture(case==0,case==1,case==2);
        let proof=review_proof(&f,74);
        let task=f.authority.sessions[0].durable_task_id;
        let root=f.authority.sessions[0].task_authorization_digest.unwrap();
        let before=disk(&f);
        assert!(f.authority.prepare_owner_execution_review_v04(&proof,*task.as_bytes(),*root.as_bytes(),
            &mut f.values,UnixMillisV2::new(203)).is_err(),"case {case}");
        assert_eq!(disk(&f),before);
        assert!(!f.authority.policy.as_ref().unwrap().durable.fused_inputs_pinned_v04(task).unwrap());
    }
}
