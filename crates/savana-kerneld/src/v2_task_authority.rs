//! Native task issuer. Neither planner output nor a caller-selected signing key
//! can establish task authority. Pending material and grants use the G4 owner.
use crate::v2_input_owner::AuthenticatedTaskDraftSubmissionV2;
use ed25519_dalek::SigningKey;
use savana_kernel_protocol::v2::{
    derive_ed25519_key_id_v2, sign_task_authorization_v2, task_authorization_draft_digest_v2,
    ApprovalDecisionV2, ApprovalPurposeV2, Digest32V2, Ed25519KeyIdV2, RoleIdV2,
    SignedApprovalEnvelopeV2, SignedApprovalSettlementV2, TaskAuthorizationDraftV2,
    TaskEvidenceKindV2, UnixMillisV2,
};
use savana_policy_core::v2::{
    ActiveToolRegistryV2, DurableG4StateV2, PendingTaskAuthorizationV2, VerifiedTaskAuthorizationV2,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TaskAuthorityErrorV2 {
    Binding,
    State,
    Unavailable,
}

pub(crate) struct KernelTaskAuthorizationIssuerV2 {
    installation: Digest32V2,
    key: SigningKey,
    envelope_key: [u8; 32],
    settlement_key: [u8; 32],
}
impl KernelTaskAuthorizationIssuerV2 {
    /// Revocation only removes authority. It is a separate authenticated typed
    /// operation, never a side effect of a planner request or ordinary chat.
    pub(crate) fn revoke(
        &self,
        owner: &mut DurableG4StateV2,
        proof: &AuthenticatedTaskDraftSubmissionV2,
        draft: &TaskAuthorizationDraftV2,
        now: UnixMillisV2,
    ) -> Result<Digest32V2, TaskAuthorityErrorV2> {
        let auth = proof.authorization();
        if proof.draft_digest() != task_authorization_draft_digest_v2(draft).map_err(binding)?
            || auth.installation_id() != self.installation
            || draft.installation_digest() != self.installation
            || auth.durable_task_id() != Some(draft.task())
            || auth.authenticated_principal() != draft.principal()
            || auth.active_state_manifest_digest() != draft.manifest_digest()
            || auth.deployment_generation() != draft.deployment_generation()
            || now.get() >= auth.expires_at().get()
            || now.get() < draft.not_before().get()
            || now.get() >= draft.expires_at().get()
        {
            return Err(TaskAuthorityErrorV2::Binding);
        }
        let current = owner
            .task_authorization_state(draft.task())
            .map_err(state)?;
        let digest = current.authorization().digest();
        if owner
            .installed_task_authorization_draft(digest)
            .map_err(state)?
            != Some(draft)
        {
            return Err(TaskAuthorityErrorV2::Binding);
        }
        owner
            .revoke_task_authorization(draft.task())
            .map_err(state)?;
        Ok(digest)
    }
    /// All key expectations are deployment-selected, never supplied by an RPC.
    /// The caller must include every other daemon key in `other_key_material`.
    pub(crate) fn new(
        installation: Digest32V2,
        key: SigningKey,
        expected_key_id: Ed25519KeyIdV2,
        expected_public_key: [u8; 32],
        envelope_key: [u8; 32],
        settlement_key: [u8; 32],
        other_key_material: &[[u8; 32]],
    ) -> Result<Self, TaskAuthorityErrorV2> {
        if installation.as_bytes() == &[0; 32]
            || key.to_bytes() == [0; 32]
            || expected_public_key == [0; 32]
            || key.verifying_key().to_bytes() != expected_public_key
            || derive_ed25519_key_id_v2(expected_public_key) != expected_key_id
            || envelope_key == [0; 32]
            || settlement_key == [0; 32]
            || [envelope_key, settlement_key]
                .iter()
                .chain(other_key_material)
                .any(|k| k == &key.to_bytes() || k == &expected_public_key)
        {
            return Err(TaskAuthorityErrorV2::Binding);
        }
        Ok(Self {
            installation,
            key,
            envelope_key,
            settlement_key,
        })
    }

    pub(crate) fn prepare(
        &self,
        owner: &mut DurableG4StateV2,
        registry: &ActiveToolRegistryV2,
        role: RoleIdV2,
        proof: &AuthenticatedTaskDraftSubmissionV2,
        draft: TaskAuthorizationDraftV2,
        request: Digest32V2,
        now: UnixMillisV2,
    ) -> Result<PendingTaskAuthorizationV2, TaskAuthorityErrorV2> {
        let auth = proof.authorization();
        if proof.draft_digest() != task_authorization_draft_digest_v2(&draft).map_err(binding)?
            || self.installation != draft.installation_digest()
            || auth.installation_id() != self.installation
            || auth.durable_task_id() != Some(draft.task())
            || auth.authenticated_principal() != draft.principal()
            || auth.active_state_manifest_digest() != draft.manifest_digest()
            || auth.deployment_generation() != draft.deployment_generation()
            || now.get() >= auth.expires_at().get()
            || now.get() < draft.not_before().get()
            || now.get() >= draft.expires_at().get()
        {
            return Err(TaskAuthorityErrorV2::Binding);
        }
        registry
            .validate_task_draft_profiles(&draft, role, now)
            .map_err(binding)?;
        owner
            .record_pending_task_authorization(draft, request)
            .map_err(state)
    }

    pub(crate) fn issue_structured(
        &self,
        owner: &mut DurableG4StateV2,
        registry: &ActiveToolRegistryV2,
        role: RoleIdV2,
        proof: &AuthenticatedTaskDraftSubmissionV2,
        request: Digest32V2,
        now: UnixMillisV2,
    ) -> Result<Digest32V2, TaskAuthorityErrorV2> {
        let pending = owner
            .pending_task_authorization(request)
            .map_err(state)?
            .cloned()
            .ok_or(TaskAuthorityErrorV2::State)?;
        // Re-run all proof/profile checks after any intervening owner operation.
        self.prepare(
            owner,
            registry,
            role,
            proof,
            pending.draft().clone(),
            request,
            now,
        )?;
        if pending.draft().revision() != 1 || pending.envelope().is_some() {
            return Err(TaskAuthorityErrorV2::Binding);
        }
        self.install(
            owner,
            request,
            pending.draft(),
            TaskEvidenceKindV2::AuthenticatedStructuredInput,
            proof.evidence_digest(),
            now,
        )
    }

    pub(crate) fn attach_approval(
        &self,
        owner: &mut DurableG4StateV2,
        request: Digest32V2,
        envelope: SignedApprovalEnvelopeV2,
        display_authentication: savana_kernel_protocol::v2::SignedUiAuthenticationEnvelopeV2,
        manifest: Digest32V2,
        generation: u64,
        now: UnixMillisV2,
    ) -> Result<(), TaskAuthorityErrorV2> {
        let p = owner
            .pending_task_authorization(request)
            .map_err(state)?
            .ok_or(TaskAuthorityErrorV2::State)?;
        envelope
            .verify(
                derive_ed25519_key_id_v2(self.envelope_key),
                self.envelope_key,
                self.installation,
                manifest,
                generation,
                ApprovalPurposeV2::TaskAuthorization,
                p.draft().principal(),
                now,
            )
            .map_err(binding)?;
        display_authentication
            .verify(
                derive_ed25519_key_id_v2(self.envelope_key),
                self.envelope_key,
                self.installation,
                manifest,
                generation,
                now,
            )
            .map_err(binding)?;
        owner
            .attach_task_authorization_approval(request, envelope, display_authentication)
            .map_err(state)
    }

    pub(crate) fn settle_approved(
        &self,
        owner: &mut DurableG4StateV2,
        registry: &ActiveToolRegistryV2,
        role: RoleIdV2,
        request: Digest32V2,
        settlement: &SignedApprovalSettlementV2,
        manifest: Digest32V2,
        generation: u64,
        now: UnixMillisV2,
    ) -> Result<Digest32V2, TaskAuthorityErrorV2> {
        let p = owner
            .pending_task_authorization(request)
            .map_err(state)?
            .cloned()
            .ok_or(TaskAuthorityErrorV2::State)?;
        let draft = p.draft();
        if draft.installation_digest() != self.installation
            || draft.manifest_digest() != manifest
            || draft.deployment_generation() != generation
            || now.get() < draft.not_before().get()
            || now.get() >= draft.expires_at().get()
        {
            return Err(TaskAuthorityErrorV2::Binding);
        }
        registry
            .validate_task_draft_profiles(draft, role, now)
            .map_err(binding)?;
        let envelope = p.envelope().ok_or(TaskAuthorityErrorV2::State)?;
        let e = envelope
            .verify(
                derive_ed25519_key_id_v2(self.envelope_key),
                self.envelope_key,
                self.installation,
                manifest,
                generation,
                ApprovalPurposeV2::TaskAuthorization,
                draft.principal(),
                now,
            )
            .map_err(binding)?;
        let verified = settlement
            .verify_task_authorization(
                derive_ed25519_key_id_v2(self.settlement_key),
                self.settlement_key,
                self.installation,
                manifest,
                generation,
                envelope.envelope_digest().map_err(binding)?,
                draft.principal(),
                e.decision_challenge(),
                now,
            )
            .map_err(binding)?;
        if verified.decision() != ApprovalDecisionV2::Approve {
            return Err(TaskAuthorityErrorV2::Binding);
        }
        self.install(
            owner,
            request,
            draft,
            TaskEvidenceKindV2::ApprovedDraft,
            verified.settlement_digest(),
            now,
        )
    }

    fn install(
        &self,
        owner: &mut DurableG4StateV2,
        request: Digest32V2,
        draft: &TaskAuthorizationDraftV2,
        kind: TaskEvidenceKindV2,
        evidence: Digest32V2,
        now: UnixMillisV2,
    ) -> Result<Digest32V2, TaskAuthorityErrorV2> {
        let material = draft
            .to_unsigned_authorization(kind, evidence)
            .map_err(binding)?;
        let signed = sign_task_authorization_v2(material, &self.key).map_err(binding)?;
        let verified = VerifiedTaskAuthorizationV2::verify(
            &signed,
            &self.key.verifying_key(),
            draft.principal(),
            draft.task(),
            self.installation,
            draft.manifest_digest(),
            now,
        )
        .map_err(binding)?;
        let digest = verified.digest();
        owner
            .install_pending_task_authorization(request, verified)
            .map_err(state)?;
        Ok(digest)
    }
}
fn binding<T>(_: T) -> TaskAuthorityErrorV2 {
    TaskAuthorityErrorV2::Binding
}
fn state<T>(_: T) -> TaskAuthorityErrorV2 {
    TaskAuthorityErrorV2::State
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::v2_agent_authority::tests::{planner_active_tools, TestG4StateAnchorV2};
    use crate::v2_input_owner::tests::finalized_task_input_fixture;
    use savana_kernel_protocol::v2::*;
    use savana_policy_core::v2::DurableStateNamespaceV2;
    fn d(n: u8) -> Digest32V2 {
        Digest32V2::new([n; 32])
    }
    fn key(n: u8) -> SigningKey {
        SigningKey::from_bytes(&[n; 32])
    }
    pub(crate) fn issuer() -> KernelTaskAuthorizationIssuerV2 {
        KernelTaskAuthorizationIssuerV2::new(
            d(0x30),
            key(61),
            derive_ed25519_key_id_v2(key(61).verifying_key().to_bytes()),
            key(61).verifying_key().to_bytes(),
            key(62).verifying_key().to_bytes(),
            key(63).verifying_key().to_bytes(),
            &[],
        )
        .unwrap()
    }
    pub(crate) fn draft(
        registry: &ActiveToolRegistryV2,
        input: Digest32V2,
        revision: u64,
        to: &str,
    ) -> TaskAuthorizationDraftV2 {
        let descriptor = registry.records()[0].descriptor();
        let controls = BusinessControlsV2::from_fields(
            descriptor.unsigned().require_business_profile().unwrap(),
            vec![
                ("file".into(), BusinessValueV2::Text("report".into())),
                ("to".into(), BusinessValueV2::Text(to.into())),
            ],
        )
        .unwrap();
        TaskAuthorizationDraftV2::new(
            d(60),
            PrincipalIdV2::new([0x31; 32]),
            DurableTaskIdV2::new([0x2f; 32]),
            revision,
            d(0x30),
            d(0x35),
            7,
            UnixMillisV2::new(100),
            UnixMillisV2::new(400),
            input,
            vec![TaskAuthorizationDraftClauseV2::new(
                1,
                vec![TaskAuthorizationDraftAlternativeV2::new(
                    descriptor.descriptor_digest(),
                    controls,
                )
                .unwrap()],
                1,
                10,
                10,
                vec![],
                false,
            )
            .unwrap()],
        )
        .unwrap()
    }
    fn envelope(draft: &TaskAuthorizationDraftV2, signer: u8) -> SignedApprovalEnvelopeV2 {
        let text = draft.render_approval_text().unwrap();
        SignedApprovalEnvelopeV2::sign(
            UnsignedApprovalEnvelopeV2::new(
                draft.installation_digest(),
                draft.manifest_digest(),
                7,
                ApprovalPurposeV2::TaskAuthorization,
                Nonce32V2::new([64; 32]),
                Nonce32V2::new([65; 32]),
                ApprovalBindingV2::TaskAuthorization {
                    authorization_id: draft.authorization_id(),
                    task: draft.task(),
                    revision: draft.revision(),
                    change: if draft.revision() == 1 {
                        TaskAuthorizationChangeV2::Create
                    } else {
                        TaskAuthorizationChangeV2::Amend
                    },
                    draft_digest: task_authorization_draft_digest_v2(draft).unwrap(),
                },
                draft.principal(),
                d(66),
                approval_display_digest_v2(text.as_bytes()),
                text,
                Some(d(67)),
                ServiceIdentityV2::new([68; 32]),
                UnixMillisV2::new(200),
                UnixMillisV2::new(400),
            )
            .unwrap(),
            &key(signer),
        )
        .unwrap()
    }
    fn settlement(
        envelope: &SignedApprovalEnvelopeV2,
        purpose: ApprovalPurposeV2,
        signer: u8,
        decision: ApprovalDecisionV2,
    ) -> SignedApprovalSettlementV2 {
        let e = envelope.unverified_material().unwrap();
        SignedApprovalSettlementV2::sign(
            UnsignedApprovalSettlementV2::new(
                e.installation_id(),
                e.active_state_manifest_digest(),
                e.deployment_generation(),
                purpose,
                envelope.envelope_digest().unwrap(),
                decision,
                e.expected_principal(),
                d(69),
                d(70),
                true,
                true,
                false,
                false,
                1,
                e.decision_challenge(),
                Nonce32V2::new([71; 32]),
                UnixMillisV2::new(201),
                UnixMillisV2::new(400),
            )
            .unwrap(),
            &key(signer),
        )
        .unwrap()
    }
    fn display(envelope: &SignedApprovalEnvelopeV2) -> SignedUiAuthenticationEnvelopeV2 {
        let e = envelope.unverified_material().unwrap();
        let task = match e.binding() {
            ApprovalBindingV2::TaskAuthorization { task, .. } => task,
            _ => unreachable!(),
        };
        SignedUiAuthenticationEnvelopeV2::sign(
            UnsignedUiAuthenticationEnvelopeV2::new(
                e.installation_id(),
                e.active_state_manifest_digest(),
                e.deployment_generation(),
                UiAuthenticationPurposeV2::ApprovalDisplay,
                UiAuthenticationBindingV2::ApprovalDisplay {
                    durable_task_id: task,
                    approval_envelope_digest: envelope.envelope_digest().unwrap(),
                    approval_purpose: ApprovalPurposeV2::TaskAuthorization,
                    display_digest: e.display_digest(),
                },
                Some(e.expected_principal()),
                FixedOriginV2::Approval8766,
                FixedOriginV2::Approval8766,
                Nonce32V2::new([79; 32]),
                e.issued_at(),
                e.expires_at(),
            )
            .unwrap(),
            &key(62),
        )
        .unwrap()
    }
    pub(crate) fn owner(dir: &std::path::Path) -> DurableG4StateV2 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        DurableG4StateV2::open(
            &dir.join("kernel-g4-state-v2.cbor"),
            [72; 32],
            DurableStateNamespaceV2::from_verified_installation(d(0x30), d(73)).unwrap(),
            Box::new(TestG4StateAnchorV2::default()),
        )
        .unwrap()
    }

    #[test]
    fn task_issuer_requires_expected_distinct_native_key() {
        let good = key(61).verifying_key().to_bytes();
        for (private, id, public, others) in [
            (key(60), derive_ed25519_key_id_v2(good), good, vec![]),
            (key(61), derive_ed25519_key_id_v2([0; 32]), good, vec![]),
            (key(61), derive_ed25519_key_id_v2(good), good, vec![good]),
            (
                key(61),
                derive_ed25519_key_id_v2(good),
                good,
                vec![key(61).to_bytes()],
            ),
        ] {
            assert!(KernelTaskAuthorizationIssuerV2::new(
                d(0x30),
                private,
                id,
                public,
                key(62).verifying_key().to_bytes(),
                key(63).verifying_key().to_bytes(),
                &others
            )
            .is_err());
        }
        issuer();
    }

    pub(crate) fn ingress(
        with_display: bool,
    ) -> crate::v2_ingress_authority::KernelIngressAuthorityV2 {
        use crate::v2_ingress_authority::{
            KernelIngressAuthorityV2, KernelIngressSecurityConfigV2,
        };
        let public = key(63).verifying_key().to_bytes();
        KernelIngressAuthorityV2::new(
            KernelIngressSecurityConfigV2::new(
                d(0x30),
                ServiceIdentityV2::new([67; 32]),
                ServiceIdentityV2::new([68; 32]),
                key(62),
                derive_ed25519_key_id_v2(public),
                public,
                derive_ed25519_key_id_v2(public),
                public,
                crate::v2_agent_authority::tests::planner_declassification_rules(with_display),
                savana_policy_core::v2::EffectSetV2::SEND,
            )
            .unwrap(),
            32,
        )
        .unwrap()
    }

    #[test]
    fn task_approval_display_requires_the_real_declassification_gate() {
        let (input, session, commitment) = finalized_task_input_fixture();
        let registry = planner_active_tools();
        let draft = draft(&registry, commitment, 1, "Alice");
        let proof = input
            .authenticate_task_draft_submission(session, &draft, d(0x35), 7, UnixMillisV2::new(200))
            .unwrap();
        assert!(ingress(false)
            .prepare_task_authorization_display(&draft, &proof, UnixMillisV2::new(200))
            .is_err());
        let (envelope, ui) = ingress(true)
            .prepare_task_authorization_display(&draft, &proof, UnixMillisV2::new(200))
            .unwrap();
        let e = envelope
            .verify(
                derive_ed25519_key_id_v2(key(62).verifying_key().to_bytes()),
                key(62).verifying_key().to_bytes(),
                d(0x30),
                d(0x35),
                7,
                ApprovalPurposeV2::TaskAuthorization,
                draft.principal(),
                UnixMillisV2::new(201),
            )
            .unwrap();
        assert_eq!(e.display_text(), &draft.render_approval_text().unwrap());
        assert!(e.display_declassification_provenance_digest().is_some());
        let dir = tempfile::tempdir().unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let anchor = TestG4StateAnchorV2::default();
        let open = || {
            DurableG4StateV2::open(
                &dir.path().join("kernel-g4-state-v2.cbor"),
                [72; 32],
                DurableStateNamespaceV2::from_verified_installation(d(0x30), d(73)).unwrap(),
                Box::new(anchor.clone()),
            )
            .unwrap()
        };
        let mut owner = open();
        let issuer = issuer();
        issuer
            .prepare(
                &mut owner,
                &registry,
                RoleIdV2::new(1),
                &proof,
                draft.clone(),
                d(74),
                UnixMillisV2::new(200),
            )
            .unwrap();
        issuer
            .attach_approval(
                &mut owner,
                d(74),
                envelope.clone(),
                ui.clone(),
                d(0x35),
                7,
                UnixMillisV2::new(201),
            )
            .unwrap();
        drop(owner);
        let mut reopened = open();
        let pending = reopened.pending_task_authorization(d(74)).unwrap().unwrap();
        assert_eq!(pending.envelope(), Some(&envelope));
        assert_eq!(pending.display_authentication(), Some(&ui));
        assert!(reopened.task_authorization_state(draft.task()).is_err());
        let receipt = settlement(
            &envelope,
            ApprovalPurposeV2::TaskAuthorization,
            63,
            ApprovalDecisionV2::Approve,
        );
        let digest = issuer
            .settle_approved(
                &mut reopened,
                &registry,
                RoleIdV2::new(1),
                d(74),
                &receipt,
                d(0x35),
                7,
                UnixMillisV2::new(202),
            )
            .unwrap();
        assert_eq!(
            reopened
                .task_authorization_state(draft.task())
                .unwrap()
                .authorization()
                .digest(),
            digest
        );
    }

    #[test]
    fn task_revocation_requires_the_exact_authenticated_current_draft_and_never_regrants() {
        let (input, session, commitment) = finalized_task_input_fixture();
        let registry = planner_active_tools();
        let original = draft(&registry, commitment, 1, "Alice");
        let proof = input
            .authenticate_task_draft_submission(
                session,
                &original,
                d(0x35),
                7,
                UnixMillisV2::new(200),
            )
            .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let mut owner = owner(dir.path());
        let issuer = issuer();
        issuer
            .prepare(
                &mut owner,
                &registry,
                RoleIdV2::new(1),
                &proof,
                original.clone(),
                d(74),
                UnixMillisV2::new(200),
            )
            .unwrap();
        let digest = issuer
            .issue_structured(
                &mut owner,
                &registry,
                RoleIdV2::new(1),
                &proof,
                d(74),
                UnixMillisV2::new(200),
            )
            .unwrap();
        let changed = draft(&registry, commitment, 1, "Bob");
        let changed_proof = input
            .authenticate_task_draft_submission(
                session,
                &changed,
                d(0x35),
                7,
                UnixMillisV2::new(200),
            )
            .unwrap();
        assert!(issuer
            .revoke(&mut owner, &changed_proof, &changed, UnixMillisV2::new(201))
            .is_err());
        assert!(!owner
            .task_authorization_state(original.task())
            .unwrap()
            .revoked());
        assert_eq!(
            issuer
                .revoke(&mut owner, &proof, &original, UnixMillisV2::new(201))
                .unwrap(),
            digest
        );
        assert_eq!(
            issuer
                .revoke(&mut owner, &proof, &original, UnixMillisV2::new(202))
                .unwrap(),
            digest
        );
        assert!(owner
            .task_authorization_state(original.task())
            .unwrap()
            .revoked());
        // An old successful issuance replay returns a historical receipt only.
        issuer
            .issue_structured(
                &mut owner,
                &registry,
                RoleIdV2::new(1),
                &proof,
                d(74),
                UnixMillisV2::new(203),
            )
            .unwrap();
        assert!(owner
            .task_authorization_state(original.task())
            .unwrap()
            .revoked());
    }

    #[test]
    fn task_issuer_structured_path_uses_finalized_authenticated_input_and_exact_profile() {
        let (input, session, commitment) = finalized_task_input_fixture();
        let registry = planner_active_tools();
        let draft = draft(&registry, commitment, 1, "Alice");
        let proof = input
            .authenticate_task_draft_submission(session, &draft, d(0x35), 7, UnixMillisV2::new(200))
            .unwrap();
        assert!(input
            .authenticate_task_draft_submission(
                InputSessionHandleV2::from_authority_entropy([78; 32]).unwrap(),
                &draft,
                d(0x35),
                7,
                UnixMillisV2::new(200)
            )
            .is_err());
        assert!(input
            .authenticate_task_draft_submission(session, &draft, d(0x35), 8, UnixMillisV2::new(200))
            .is_err());
        assert!(input
            .authenticate_task_draft_submission(session, &draft, d(0x35), 7, UnixMillisV2::new(500))
            .is_err());
        let wrong = self::draft(&registry, d(79), 1, "Alice");
        assert!(input
            .authenticate_task_draft_submission(session, &wrong, d(0x35), 7, UnixMillisV2::new(200))
            .is_err());
        let dir = tempfile::tempdir().unwrap();
        let mut owner = owner(dir.path());
        let issuer = issuer();
        assert!(issuer
            .prepare(
                &mut owner,
                &registry,
                RoleIdV2::new(1),
                &proof,
                wrong,
                d(74),
                UnixMillisV2::new(200)
            )
            .is_err());
        issuer
            .prepare(
                &mut owner,
                &registry,
                RoleIdV2::new(1),
                &proof,
                draft.clone(),
                d(74),
                UnixMillisV2::new(200),
            )
            .unwrap();
        assert!(owner.task_authorization_state(draft.task()).is_err());
        let digest = issuer
            .issue_structured(
                &mut owner,
                &registry,
                RoleIdV2::new(1),
                &proof,
                d(74),
                UnixMillisV2::new(200),
            )
            .unwrap();
        let state = owner.task_authorization_state(draft.task()).unwrap();
        assert_eq!(state.authorization().digest(), digest);
        assert_eq!(
            state.authorization().material().evidence_kind(),
            TaskEvidenceKindV2::AuthenticatedStructuredInput
        );
        assert_eq!(
            state.authorization().material().user_evidence_digest(),
            proof.evidence_digest()
        );
        assert_eq!(state.clause_consumption(1), Some((0, 0)));
        assert_eq!(
            issuer
                .issue_structured(
                    &mut owner,
                    &registry,
                    RoleIdV2::new(1),
                    &proof,
                    d(74),
                    UnixMillisV2::new(201)
                )
                .unwrap(),
            digest
        );
    }

    #[test]
    fn task_amendment_needs_exact_expected_key_task_purpose_approval() {
        let (input, session, commitment) = finalized_task_input_fixture();
        let registry = planner_active_tools();
        let dir = tempfile::tempdir().unwrap();
        let mut owner = owner(dir.path());
        let issuer = issuer();
        let first = draft(&registry, commitment, 1, "Alice");
        let proof = input
            .authenticate_task_draft_submission(session, &first, d(0x35), 7, UnixMillisV2::new(200))
            .unwrap();
        issuer
            .prepare(
                &mut owner,
                &registry,
                RoleIdV2::new(1),
                &proof,
                first.clone(),
                d(74),
                UnixMillisV2::new(200),
            )
            .unwrap();
        issuer
            .issue_structured(
                &mut owner,
                &registry,
                RoleIdV2::new(1),
                &proof,
                d(74),
                UnixMillisV2::new(200),
            )
            .unwrap();
        let amendment = draft(&registry, commitment, 2, "Bob");
        let proof = input
            .authenticate_task_draft_submission(
                session,
                &amendment,
                d(0x35),
                7,
                UnixMillisV2::new(200),
            )
            .unwrap();
        issuer
            .prepare(
                &mut owner,
                &registry,
                RoleIdV2::new(1),
                &proof,
                amendment.clone(),
                d(75),
                UnixMillisV2::new(200),
            )
            .unwrap();
        assert!(issuer
            .issue_structured(
                &mut owner,
                &registry,
                RoleIdV2::new(1),
                &proof,
                d(75),
                UnixMillisV2::new(200)
            )
            .is_err());
        assert!(issuer
            .attach_approval(
                &mut owner,
                d(75),
                envelope(&amendment, 80),
                display(&envelope(&amendment, 80)),
                d(0x35),
                7,
                UnixMillisV2::new(200)
            )
            .is_err());
        assert!(issuer
            .attach_approval(
                &mut owner,
                d(75),
                envelope(&first, 62),
                display(&envelope(&first, 62)),
                d(0x35),
                7,
                UnixMillisV2::new(200)
            )
            .is_err());
        let approved = envelope(&amendment, 62);
        issuer
            .attach_approval(
                &mut owner,
                d(75),
                approved.clone(),
                display(&approved),
                d(0x35),
                7,
                UnixMillisV2::new(200),
            )
            .unwrap();
        for bad in [
            settlement(
                &approved,
                ApprovalPurposeV2::Ingress,
                63,
                ApprovalDecisionV2::Approve,
            ),
            settlement(
                &approved,
                ApprovalPurposeV2::TaskAuthorization,
                80,
                ApprovalDecisionV2::Approve,
            ),
            settlement(
                &approved,
                ApprovalPurposeV2::TaskAuthorization,
                63,
                ApprovalDecisionV2::Deny,
            ),
            settlement(
                &envelope(&first, 62),
                ApprovalPurposeV2::TaskAuthorization,
                63,
                ApprovalDecisionV2::Approve,
            ),
        ] {
            assert!(issuer
                .settle_approved(
                    &mut owner,
                    &registry,
                    RoleIdV2::new(1),
                    d(75),
                    &bad,
                    d(0x35),
                    7,
                    UnixMillisV2::new(202)
                )
                .is_err());
            assert_eq!(
                owner
                    .task_authorization_state(first.task())
                    .unwrap()
                    .authorization()
                    .material()
                    .revision(),
                1
            );
        }
        let consent = settlement(
            &approved,
            ApprovalPurposeV2::TaskAuthorization,
            63,
            ApprovalDecisionV2::Approve,
        );
        assert!(issuer
            .settle_approved(
                &mut owner,
                &registry,
                RoleIdV2::new(1),
                d(75),
                &consent,
                d(0x35),
                8,
                UnixMillisV2::new(202)
            )
            .is_err());
        issuer
            .settle_approved(
                &mut owner,
                &registry,
                RoleIdV2::new(1),
                d(75),
                &consent,
                d(0x35),
                7,
                UnixMillisV2::new(202),
            )
            .unwrap();
        let state = owner.task_authorization_state(first.task()).unwrap();
        assert_eq!(state.authorization().material().revision(), 2);
        assert_eq!(
            state.authorization().material().user_evidence_digest(),
            consent.settlement_digest().unwrap()
        );
    }
}
