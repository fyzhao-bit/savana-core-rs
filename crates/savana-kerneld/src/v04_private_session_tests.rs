// Real signature/binding and value-admission checks; fixture credential signing
// is synthetic, not a claim of browser or installed-hardware acceptance.
fn private_session_accept_case(case: u8) {
    use super::super::private_session::PrivateSessionAuthenticationV04;
    use super::super::*;
    use savana_kernel_protocol::v2::{
        ApprovalUiRecordHandleV2, PrivateSessionTransferV04, RegisteredPrivateSessionV04,
        UnsignedUiAuthenticationSettlementV2,
    };
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
    let provenance = f
        .values
        .resolve_g4_value(f.run, f.prompt, UnixMillisV2::new(203))
        .unwrap()
        .provenance()
        .clone();
    let material = PreparedAgentClaimMaterialV2::from_verified_ingress(
        session.durable_run_id,
        session.producer_identity,
        KernelValueV2::text("private planner prompt").unwrap(),
        provenance,
        session.initial_document,
        session.policy_allowed_effects,
        session.signed_planner_policy,
        UnixMillisV2::new(1000),
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
        current_authentication_preparation: None,
        source_input_digest: Some(Digest32V2::new([76; 32])),
        task_authorization_digest: Some(root),
    });
    let binding = UiAuthenticationBindingV2::PrivateSessionV04 {
        durable_task_id: task,
        durable_run_id: session.durable_run_id,
        task_authorization_digest: root,
        kerneld_boot_id: f.authority.config.kerneld_server_boot_id,
    };
    let e = UnsignedUiAuthenticationEnvelopeV2::new(
        f.authority.config.installation_id,
        manifest,
        7,
        UiAuthenticationPurposeV2::PrivateSessionV04,
        binding,
        Some(session.principal),
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
    let settlement_key = SigningKey::from_bytes(&[0x5d; 32]);
    f.authority.config.ui_settlement_public_key = settlement_key.verifying_key().to_bytes();
    f.authority.config.ui_settlement_key_id =
        derive_ed25519_key_id_v2(settlement_key.verifying_key().to_bytes());
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
                session.principal
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
        assert_eq!(s.durable_run_id, session.durable_run_id);
        assert_eq!(s.task_authorization_digest, Some(root));
        assert_eq!(s.expires_at, UnixMillisV2::new(800));
        assert_eq!(f.authority.tools.len(), tools_before);
        assert!(f.authority.private_session_authentications[0].consumed);
        assert!(f
            .authority
            .accept_private_session_v04(0, proof, &mut f.values, UnixMillisV2::new(206))
            .is_err());
        assert_eq!(f.authority.sessions.len(), 1);
        // A consumed input is absent by design, not corrupt owner storage.
        // Restart retains a fail-closed tombstone, never the old session or
        // permission to repeat the initial admission/provider effect.
        let running = f.authority.encode_recovery_snapshot().unwrap();
        f.authority.tasks[0].status = PublicTaskStatusV2::Ready { bootstrap: None };
        let invalid_ready = f.authority.encode_recovery_snapshot().unwrap();
        let mut restored = KernelAgentAuthorityV2::new(f.authority.config, 128).unwrap();
        assert!(restored
            .restore_recovery_snapshot(&invalid_ready, UnixMillisV2::new(207))
            .is_err());
        restored
            .restore_recovery_snapshot(&running, UnixMillisV2::new(207))
            .unwrap();
        assert_eq!(restored.tasks[0].status, PublicTaskStatusV2::Indeterminate);
        assert_eq!(restored.tasks[0].durable_task_id, task);
        assert_eq!(restored.tasks[0].task_authorization_digest, Some(root));
        assert!(restored.tasks[0].material.is_none());
        assert!(restored.sessions.is_empty());
        assert!(restored.tools.is_empty());
        assert!(restored.private_session_authentications.is_empty());
        let tombstone = restored.encode_recovery_snapshot().unwrap();
        restored.tasks.clear();
        restored
            .restore_recovery_snapshot(&tombstone, UnixMillisV2::new(208))
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
