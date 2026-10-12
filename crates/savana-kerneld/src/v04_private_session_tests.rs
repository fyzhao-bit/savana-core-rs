// Real signature/binding and value-admission checks; fixture credential signing
// is synthetic, not a claim of browser or installed-hardware acceptance.
/// A private task whose committed input is Ready for its first login, and
/// the synthetic key standing in for approvald's settlement signer.
struct PrivateTaskFixtureV04 {
    f: PlannerAuthorityFixtureV2,
    task: DurableTaskIdV2,
    run: DurableRunIdV2,
    root: Digest32V2,
    manifest: Digest32V2,
    principal: PrincipalIdV2,
    settlement_key: SigningKey,
}

impl PrivateTaskFixtureV04 {
    fn target(&self) -> PrivateLoginTargetV04 {
        PrivateLoginTargetV04 {
            task: self.task,
            run: self.run,
            root: self.root,
            manifest: self.manifest,
            principal: self.principal,
        }
    }
}

/// Who a private login is for: the task, its durable run and root, the owner.
#[derive(Clone, Copy)]
struct PrivateLoginTargetV04 {
    task: DurableTaskIdV2,
    run: DurableRunIdV2,
    root: Digest32V2,
    manifest: Digest32V2,
    principal: PrincipalIdV2,
}

fn private_task_fixture_v04() -> PrivateTaskFixtureV04 {
    use super::super::*;
    let mut f = planner_authority_fixture();
    install_operations(
        &mut f,
        vec![
            serde_json::json!({"id":1,"tool_class":31,"action_template":21,"after":[],"bindings":[]}),
        ],
    );
    let session = f.authority.sessions.remove(0);
    let task = session.durable_task_id;
    let manifest = session.active_state_manifest_digest;
    let state = f
        .authority
        .policy
        .as_ref()
        .unwrap()
        .durable
        .task_authorization_state(task)
        .unwrap();
    let root = state.authorization().digest();
    // Committed input and its provenance share one lifetime, as from ingress.
    let initial = KernelValueV2::text("private planner prompt").unwrap();
    let provenance = ProvenanceRecordV2::planner_output(
        &initial,
        ProvenanceContextV2::from_authenticated_runtime(
            session.producer_identity,
            session.durable_run_id,
            manifest,
            UnixMillisV2::new(100),
            UnixMillisV2::new(1000),
        )
        .unwrap(),
        Digest32V2::new([0x86; 32]),
        Digest32V2::new([0x87; 32]),
        Digest32V2::new([0x88; 32]),
        &[],
        EffectSetV2::SEND,
    )
    .unwrap();
    let material = PreparedAgentClaimMaterialV2::from_verified_ingress(
        session.durable_run_id,
        session.producer_identity,
        initial,
        provenance,
        session.initial_document,
        session.policy_allowed_effects,
        session.signed_planner_policy,
        UnixMillisV2::new(1000),
        None,
    )
    .unwrap();
    let correlation = SignedDurableTaskCorrelationV2::sign(
        UnsignedDurableTaskCorrelationV2::new(
            f.authority.config.installation_id,
            manifest,
            7,
            task,
            f.authority.config.agentd_identity,
            f.authority.config.agentd_kernel_client_boot_id,
            f.authority.config.kerneld_server_boot_id,
            f.authority.config.machine_boot_id,
            UnixMillisV2::new(1),
            UnixMillisV2::new(9000),
            UnixMillisV2::new(10000),
        )
        .unwrap(),
        &f.authority.config.correlation_signing_key,
    )
    .unwrap();
    f.authority.tasks.push(TaskRecordV2 {
        preparation: NewTaskPreparationHandleV2::from_authority_entropy([71; 32]).unwrap(),
        agent_task_nonce: Nonce32V2::new([72; 32]),
        client_request_nonce: Nonce32V2::new([73; 32]),
        durable_task_id: task,
        active_state_manifest_digest: manifest,
        correlation: correlation.clone(),
        ingress_transfer: KernelIngressBootstrapTransferCapabilityV2::from_authority_entropy(
            [74; 32],
        )
        .unwrap(),
        status: PublicTaskStatusV2::Ready { bootstrap: None },
        expected_principal: Some(session.principal),
        claim_digest: Some(Digest32V2::new([75; 32])),
        durable_run_id: Some(session.durable_run_id),
        material: Some(material),
        reconnect_material: None,
        current_authentication_preparation: None,
        source_input_digest: Some(Digest32V2::new([76; 32])),
        task_authorization_digest: Some(root),
    });
    let settlement_key = SigningKey::from_bytes(&[0x5d; 32]);
    f.authority.config.ui_settlement_public_key = settlement_key.verifying_key().to_bytes();
    f.authority.config.ui_settlement_key_id =
        derive_ed25519_key_id_v2(settlement_key.verifying_key().to_bytes());
    PrivateTaskFixtureV04 {
        f,
        task,
        run: session.durable_run_id,
        root,
        manifest,
        principal: session.principal,
        settlement_key,
    }
}

fn private_session_accept_case(case: u8) {
    use super::super::private_session::PrivateSessionAuthenticationV04;
    use super::super::*;
    use savana_kernel_protocol::v2::{
        ApprovalUiRecordHandleV2, PrivateSessionTransferV04, RegisteredPrivateSessionV04,
        UnsignedUiAuthenticationSettlementV2,
    };
    let PrivateTaskFixtureV04 {
        mut f,
        task,
        run,
        root,
        manifest,
        principal,
        settlement_key,
    } = private_task_fixture_v04();
    let binding = UiAuthenticationBindingV2::PrivateSessionV04 {
        durable_task_id: task,
        durable_run_id: run,
        task_authorization_digest: root,
        kerneld_boot_id: f.authority.config.kerneld_server_boot_id,
    };
    let e = UnsignedUiAuthenticationEnvelopeV2::new(
        f.authority.config.installation_id,
        manifest,
        7,
        UiAuthenticationPurposeV2::PrivateSessionV04,
        binding,
        Some(principal),
        FixedOriginV2::Approval8766,
        FixedOriginV2::Approval8766,
        Nonce32V2::new([77; 32]),
        UnixMillisV2::new(200),
        UnixMillisV2::new(900),
    )
    .unwrap();
    let envelope =
        SignedUiAuthenticationEnvelopeV2::sign(e, &f.authority.config.envelope_signing_key)
            .unwrap();
    let purpose = if case == 1 {
        UiAuthenticationPurposeV2::AgentContent
    } else {
        UiAuthenticationPurposeV2::PrivateSessionV04
    };
    let proof = SignedUiAuthenticationSettlementV2::sign(
        UnsignedUiAuthenticationSettlementV2::new(
            f.authority.config.installation_id,
            manifest,
            7,
            purpose,
            if case == 2 {
                Digest32V2::new([99; 32])
            } else {
                envelope.envelope_digest().unwrap()
            },
            if case == 3 {
                Digest32V2::new([99; 32])
            } else {
                e.binding_digest().unwrap()
            },
            FixedOriginV2::Approval8766,
            if case == 1 {
                FixedOriginV2::Agent8768
            } else {
                FixedOriginV2::Approval8766
            },
            if case == 4 {
                PrincipalIdV2::new([99; 32])
            } else {
                principal
            },
            Digest32V2::new([78; 32]),
            Digest32V2::new([79; 32]),
            true,
            true,
            false,
            false,
            2,
            if case == 5 {
                Nonce32V2::new([99; 32])
            } else {
                e.envelope_nonce()
            },
            Nonce32V2::new([80; 32]),
            UnixMillisV2::new(204),
            UnixMillisV2::new(800),
        )
        .unwrap(),
        &settlement_key,
    )
    .unwrap();
    f.authority
        .private_session_authentications
        .push(PrivateSessionAuthenticationV04 {
            task,
            root,
            envelope,
            registered: RegisteredPrivateSessionV04 {
                record: ApprovalUiRecordHandleV2::from_authority_entropy([81; 32]).unwrap(),
                transfer: PrivateSessionTransferV04::from_authority_entropy([82; 32]).unwrap(),
            },
            consumed: false,
            next_poll: 0,
        });
    if case == 6 {
        f.authority.config.kerneld_server_boot_id = BootIdV2::new([99; 32]);
    }
    if case == 7 {
        f.authority.config.ui_settlement_public_key =
            SigningKey::from_bytes(&[99; 32]).verifying_key().to_bytes();
    }
    let tools_before = f.authority.tools.len();
    assert!(f.authority.require_public_task_v04(task).is_err());
    if case == 0 {
        let ui_key = SigningKey::from_bytes(&[0x13; 32]);
        let settlement_key = SigningKey::from_bytes(&[0x14; 32]);
        let mut ingress = KernelIngressAuthorityV2::new(
            KernelIngressSecurityConfigV2::new(
                f.authority.config.installation_id,
                f.authority.config.kerneld_identity,
                f.authority.config.approvald_identity,
                SigningKey::from_bytes(&[0x18; 32]),
                derive_ed25519_key_id_v2(ui_key.verifying_key().to_bytes()),
                ui_key.verifying_key().to_bytes(),
                derive_ed25519_key_id_v2(settlement_key.verifying_key().to_bytes()),
                settlement_key.verifying_key().to_bytes(),
                planner_declassification_rules(true),
                EffectSetV2::SEND,
            )
            .unwrap(),
            8,
        )
        .unwrap();
        let request = PrepareNewIngressRequestV2::new(
            f.authority.tasks[0].agent_task_nonce,
            f.authority.tasks[0].client_request_nonce,
        )
        .unwrap();
        // Retrying the public creation request must not reveal a private
        // task's current phase or give out its old ingress transfer.
        assert!(f
            .authority
            .prepare_new_ingress(
                request,
                &mut ingress,
                f.authority.config.agentd_identity,
                manifest,
                7,
                UnixMillisV2::new(205),
            )
            .is_err());
    }
    let result = f.authority.accept_private_session_v04(
        0,
        proof.clone(),
        &mut f.values,
        UnixMillisV2::new(if case == 8 { 800 } else { 205 }),
    );
    if case == 0 {
        result.unwrap();
        assert_eq!(f.authority.sessions.len(), 1);
        let s = &f.authority.sessions[0];
        assert_eq!(s.durable_run_id, run);
        assert_eq!(s.task_authorization_digest, Some(root));
        assert_eq!(s.expires_at, UnixMillisV2::new(800));
        assert_eq!(f.authority.tools.len(), tools_before);
        assert!(f.authority.private_session_authentications[0].consumed);
        assert!(f
            .authority
            .accept_private_session_v04(0, proof, &mut f.values, UnixMillisV2::new(206))
            .is_err());
        assert_eq!(f.authority.sessions.len(), 1);
        // The first login moves the committed input into the run and keeps
        // one copy, encrypted with the snapshot, for a later login to it.
        assert!(f.authority.tasks[0].material.is_none());
        assert!(f.authority.tasks[0].reconnect_material.is_some());
        let running = f.authority.encode_recovery_snapshot().unwrap();
        f.authority.tasks[0].status = PublicTaskStatusV2::Ready { bootstrap: None };
        let invalid_ready = f.authority.encode_recovery_snapshot().unwrap();
        f.authority.tasks[0].status = PublicTaskStatusV2::Indeterminate;
        let invalid_lost = f.authority.encode_recovery_snapshot().unwrap();
        let mut restored = KernelAgentAuthorityV2::new(f.authority.config, 128).unwrap();
        for invalid in [&invalid_ready, &invalid_lost] {
            assert!(restored
                .restore_recovery_snapshot(invalid, UnixMillisV2::new(207))
                .is_err());
            restored.tasks.clear();
        }
        restored
            .restore_recovery_snapshot(&running, UnixMillisV2::new(207))
            .unwrap();
        // Restart keeps the task running in durable state, waiting for a
        // fresh login. No session, login, tool or input admission survives.
        assert_eq!(restored.tasks[0].status, PublicTaskStatusV2::Running);
        assert_eq!(restored.tasks[0].durable_task_id, task);
        assert_eq!(restored.tasks[0].task_authorization_digest, Some(root));
        assert!(restored.tasks[0].material.is_none());
        assert!(restored.tasks[0].reconnect_material.is_some());
        assert!(restored.sessions.is_empty());
        assert!(restored.tools.is_empty());
        assert!(restored.private_session_authentications.is_empty());
        assert_eq!(restored.encode_recovery_snapshot().unwrap(), running);
        // After the run's input lifetime, restart keeps only the fail-closed
        // tombstone: no old session, and no permission to repeat admission.
        restored.tasks.clear();
        restored
            .restore_recovery_snapshot(&running, UnixMillisV2::new(1000))
            .unwrap();
        assert_eq!(restored.tasks[0].status, PublicTaskStatusV2::Indeterminate);
        assert!(restored.tasks[0].reconnect_material.is_none());
        let tombstone = restored.encode_recovery_snapshot().unwrap();
        restored.tasks.clear();
        restored
            .restore_recovery_snapshot(&tombstone, UnixMillisV2::new(1001))
            .unwrap();
        assert_eq!(restored.encode_recovery_snapshot().unwrap(), tombstone);
    } else {
        assert!(result.is_err(), "mutation {case} admitted");
        assert!(f.authority.sessions.is_empty());
        assert!(f.authority.tasks[0].material.is_some());
        assert!(!f.authority.private_session_authentications[0].consumed);
    }
}

#[test]
fn fused_private_session_consumes_exact_proof_without_agent_handles() {
    private_session_accept_case(0);
}

#[test]
fn fused_private_session_rejects_wrong_purpose_binding_principal_boot_key_and_expiry() {
    for case in 1..=8 {
        private_session_accept_case(case);
    }
}

/// A signed login bound to the kernel's current boot, as approvald returns it
/// after the owner's WebAuthn ceremony.
fn signed_private_login_v04(
    authority: &KernelAgentAuthorityV2,
    p: PrivateLoginTargetV04,
    settlement_key: &SigningKey,
    seed: u8,
    issued: u64,
    envelope_expires: u64,
    settlement_expires: u64,
) -> (
    super::super::private_session::PrivateSessionAuthenticationV04,
    savana_kernel_protocol::v2::SignedUiAuthenticationSettlementV2,
) {
    use super::super::private_session::PrivateSessionAuthenticationV04;
    use super::super::*;
    use savana_kernel_protocol::v2::{
        ApprovalUiRecordHandleV2, PrivateSessionTransferV04, RegisteredPrivateSessionV04,
        UnsignedUiAuthenticationSettlementV2,
    };
    let c = &authority.config;
    let e = UnsignedUiAuthenticationEnvelopeV2::new(
        c.installation_id,
        p.manifest,
        7,
        UiAuthenticationPurposeV2::PrivateSessionV04,
        UiAuthenticationBindingV2::PrivateSessionV04 {
            durable_task_id: p.task,
            durable_run_id: p.run,
            task_authorization_digest: p.root,
            kerneld_boot_id: c.kerneld_server_boot_id,
        },
        Some(p.principal),
        FixedOriginV2::Approval8766,
        FixedOriginV2::Approval8766,
        Nonce32V2::new([seed; 32]),
        UnixMillisV2::new(issued),
        UnixMillisV2::new(envelope_expires),
    )
    .unwrap();
    let envelope = SignedUiAuthenticationEnvelopeV2::sign(e, &c.envelope_signing_key).unwrap();
    let proof = SignedUiAuthenticationSettlementV2::sign(
        UnsignedUiAuthenticationSettlementV2::new(
            c.installation_id,
            p.manifest,
            7,
            UiAuthenticationPurposeV2::PrivateSessionV04,
            envelope.envelope_digest().unwrap(),
            e.binding_digest().unwrap(),
            FixedOriginV2::Approval8766,
            FixedOriginV2::Approval8766,
            p.principal,
            Digest32V2::new([78; 32]),
            Digest32V2::new([79; 32]),
            true,
            true,
            false,
            false,
            2,
            e.envelope_nonce(),
            Nonce32V2::new([seed.wrapping_add(1); 32]),
            UnixMillisV2::new(issued + 1),
            UnixMillisV2::new(settlement_expires),
        )
        .unwrap(),
        settlement_key,
    )
    .unwrap();
    let login = PrivateSessionAuthenticationV04 {
        task: p.task,
        root: p.root,
        envelope,
        registered: RegisteredPrivateSessionV04 {
            record: ApprovalUiRecordHandleV2::from_authority_entropy([seed; 32]).unwrap(),
            transfer: PrivateSessionTransferV04::from_authority_entropy([seed.wrapping_add(2); 32])
                .unwrap(),
        },
        consumed: false,
        next_poll: 0,
    };
    (login, proof)
}

/// Case 0: kerneld restarts. Case 1: the session expires in the same process;
/// a second login continues the same session and run. Case 2: the root is
/// revoked. Case 3: the run's input lifetime is over.
fn private_session_reconnect_case(case: u8) {
    use super::super::*;
    let mut p = private_task_fixture_v04();
    let accept = |p: &mut PrivateTaskFixtureV04,
                  login: super::super::private_session::PrivateSessionAuthenticationV04,
                  proof: SignedUiAuthenticationSettlementV2,
                  at: u64| {
        p.f.authority.private_session_authentications.push(login);
        let index = p.f.authority.private_session_authentications.len() - 1;
        let result = p.f.authority.accept_private_session_v04(
            index,
            proof,
            &mut p.f.values,
            UnixMillisV2::new(at),
        );
        (result, index)
    };
    let (login, proof) = signed_private_login_v04(
        &p.f.authority,
        p.target(),
        &p.settlement_key,
        77,
        200,
        900,
        800,
    );
    accept(&mut p, login, proof, 205).0.unwrap();
    let first = &p.f.authority.sessions[0];
    let (first_run, first_value) = (first.run, first.initial_value);
    let original =
        p.f.values
            .resolve_g4_value(first_run, first_value, UnixMillisV2::new(206))
            .unwrap()
            .provenance()
            .clone();
    // A live session admits no second login to the task.
    let (login, proof) = signed_private_login_v04(
        &p.f.authority,
        p.target(),
        &p.settlement_key,
        83,
        206,
        900,
        800,
    );
    let (result, index) = accept(&mut p, login, proof, 207);
    assert!(matches!(
        result,
        Err(KernelAgentAuthorityErrorV2::StateConflict)
    ));
    assert!(!p.f.authority.private_session_authentications[index].consumed);
    assert_eq!(p.f.authority.sessions.len(), 1);
    match case {
        0 => {
            // Only the encrypted snapshot and the durable G4 owner survive.
            let snapshot = p.f.authority.encode_recovery_snapshot().unwrap();
            let (old_login, old_proof) = signed_private_login_v04(
                &p.f.authority,
                p.target(),
                &p.settlement_key,
                84,
                801,
                990,
                980,
            );
            let c = &p.f.authority.config;
            let config = KernelAgentSecurityConfigV2 {
                installation_id: c.installation_id,
                kerneld_identity: c.kerneld_identity,
                agentd_identity: c.agentd_identity,
                approvald_identity: c.approvald_identity,
                agentd_kernel_client_boot_id: c.agentd_kernel_client_boot_id,
                kerneld_server_boot_id: BootIdV2::new([0x7e; 32]),
                approvald_boot_id: c.approvald_boot_id,
                machine_boot_id: c.machine_boot_id,
                correlation_signing_key: c.correlation_signing_key.clone(),
                envelope_signing_key: c.envelope_signing_key.clone(),
                ui_settlement_key_id: c.ui_settlement_key_id,
                ui_settlement_public_key: c.ui_settlement_public_key,
            };
            let mut restarted = KernelAgentAuthorityV2::new(config, 128).unwrap();
            restarted
                .restore_recovery_snapshot(&snapshot, UnixMillisV2::new(801))
                .unwrap();
            restarted
                .install_g4_g5_runtime(p.f.authority.policy.take().unwrap())
                .unwrap();
            p.f.authority = restarted;
            p.f.values = KernelValueOwnerV2::new(4, 32).unwrap();
            assert_eq!(p.f.authority.tasks[0].status, PublicTaskStatusV2::Running);
            // A proof the old boot would have accepted is not a login here.
            let (result, _) = accept(&mut p, old_login, old_proof, 802);
            assert!(result.is_err());
            assert!(p.f.authority.sessions.is_empty());
        }
        1 => (),
        2 => {
            p.f.authority
                .policy
                .as_mut()
                .unwrap()
                .durable
                .revoke_task_authorization(p.task)
                .unwrap();
        }
        3 => {
            let (login, proof) = signed_private_login_v04(
                &p.f.authority,
                p.target(),
                &p.settlement_key,
                86,
                990,
                1500,
                1400,
            );
            let (result, index) = accept(&mut p, login, proof, 1000);
            assert!(matches!(
                result,
                Err(KernelAgentAuthorityErrorV2::StateConflict)
            ));
            assert!(!p.f.authority.private_session_authentications[index].consumed);
            assert_eq!(p.f.authority.sessions.len(), 1);
            return;
        }
        _ => unreachable!(),
    }
    let (login, proof) = signed_private_login_v04(
        &p.f.authority,
        p.target(),
        &p.settlement_key,
        85,
        801,
        990,
        980,
    );
    let (result, index) = accept(&mut p, login, proof.clone(), 803);
    if case == 2 {
        assert!(matches!(
            result,
            Err(KernelAgentAuthorityErrorV2::StateConflict)
        ));
        assert!(!p.f.authority.private_session_authentications[index].consumed);
        assert_eq!(p.f.authority.sessions.len(), 1);
        assert!(p.f.authority.tasks[0].reconnect_material.is_some());
        return;
    }
    result.unwrap();
    // One session: the same durable run, root and input, bounded by the
    // input's original lifetime. Nothing is renewed or derived again. After
    // a restart the input enters a new run; in the same process the same
    // run continues.
    assert_eq!(p.f.authority.sessions.len(), 1);
    let s = &p.f.authority.sessions[0];
    assert_eq!(s.durable_run_id, p.run);
    assert_eq!(s.task_authorization_digest, Some(p.root));
    assert_eq!(s.expires_at, UnixMillisV2::new(980));
    assert_eq!(s.status, AgentSessionStatusV2::Running);
    assert_eq!(s.run == first_run, case == 1);
    assert_eq!(s.initial_value == first_value, case == 1);
    let again =
        p.f.values
            .resolve_g4_value(s.run, s.initial_value, UnixMillisV2::new(804))
            .unwrap();
    assert_eq!(again.provenance(), &original);
    let t = &p.f.authority.tasks[0];
    assert_eq!(t.status, PublicTaskStatusV2::Running);
    assert!(t.material.is_none());
    assert!(t.reconnect_material.is_some());
    // Only the newest login of the task is kept to receive its handoffs.
    let logins = &p.f.authority.private_session_authentications;
    assert_eq!(
        logins
            .iter()
            .filter(|l| l.task == p.task && l.consumed)
            .count(),
        1
    );
    let current = logins
        .iter()
        .position(|l| l.task == p.task && l.consumed)
        .unwrap();
    assert!(current <= index);
    // The proof is spent.
    let spent = p.f.authority.accept_private_session_v04(
        current,
        proof,
        &mut p.f.values,
        UnixMillisV2::new(805),
    );
    assert!(spent.is_err());
    assert_eq!(p.f.authority.sessions.len(), 1);
}

#[test]
fn fused_private_session_reconnects_after_restart_to_the_same_run_with_a_fresh_login() {
    private_session_reconnect_case(0);
}

#[test]
fn fused_private_session_continues_the_same_run_after_its_login_expires_in_process() {
    private_session_reconnect_case(1);
}

#[test]
fn fused_private_session_refuses_a_later_login_after_revocation_or_input_expiry() {
    for case in 2..=3 {
        private_session_reconnect_case(case);
    }
}

#[test]
fn fused_private_login_gate_admits_first_input_or_kept_copy_never_both() {
    use super::super::private_session::private_login_material_v04;
    use super::super::*;
    let mut p = private_task_fixture_v04();
    let now = UnixMillisV2::new(205);
    let gate = |p: &PrivateTaskFixtureV04| {
        private_login_material_v04(&p.f.authority.tasks[0], &p.f.authority.sessions, now)
            .map(|(_, login)| login != super::super::private_session::PrivateLoginV04::First)
    };
    assert!(matches!(gate(&p), Ok(false)));
    let copy = p.f.authority.tasks[0]
        .material
        .as_ref()
        .unwrap()
        .duplicate()
        .unwrap();
    // A Ready task never also carries a kept copy.
    p.f.authority.tasks[0].reconnect_material = Some(copy);
    assert!(gate(&p).is_err());
    let copy = p.f.authority.tasks[0].material.take().unwrap();
    // A Ready task without its committed input admits nothing.
    assert!(gate(&p).is_err());
    p.f.authority.tasks[0].status = PublicTaskStatusV2::Running;
    assert!(matches!(gate(&p), Ok(true)));
    // Neither beside the unconsumed input, nor for a different run.
    p.f.authority.tasks[0].material = Some(copy);
    assert!(gate(&p).is_err());
    p.f.authority.tasks[0].material = None;
    p.f.authority.tasks[0].durable_run_id = Some(DurableRunIdV2::new([0x55; 32]));
    assert!(gate(&p).is_err());
    p.f.authority.tasks[0].durable_run_id = Some(p.run);
    // Any other phase admits no login.
    for status in [
        PublicTaskStatusV2::Indeterminate,
        PublicTaskStatusV2::Dispatching,
        PublicTaskStatusV2::Cancelled,
        PublicTaskStatusV2::Expired,
    ] {
        p.f.authority.tasks[0].status = status;
        assert!(gate(&p).is_err());
    }
    p.f.authority.tasks[0].status = PublicTaskStatusV2::Running;
    assert!(matches!(gate(&p), Ok(true)));
    // At the end of the input's lifetime the kept copy admits nothing.
    assert!(private_login_material_v04(
        &p.f.authority.tasks[0],
        &p.f.authority.sessions,
        UnixMillisV2::new(1000)
    )
    .is_err());
    // With a session: refused while it is live, continued once it expired.
    let mut q = private_task_fixture_v04();
    let (login, proof) = signed_private_login_v04(
        &q.f.authority,
        q.target(),
        &q.settlement_key,
        77,
        200,
        900,
        800,
    );
    q.f.authority.private_session_authentications.push(login);
    q.f.authority
        .accept_private_session_v04(0, proof, &mut q.f.values, UnixMillisV2::new(205))
        .unwrap();
    let at = |q: &PrivateTaskFixtureV04, now: u64| {
        private_login_material_v04(
            &q.f.authority.tasks[0],
            &q.f.authority.sessions,
            UnixMillisV2::new(now),
        )
        .map(|(_, login)| login)
    };
    assert!(at(&q, 799).is_err());
    assert_eq!(
        at(&q, 800).unwrap(),
        super::super::private_session::PrivateLoginV04::Continue(0)
    );
}
