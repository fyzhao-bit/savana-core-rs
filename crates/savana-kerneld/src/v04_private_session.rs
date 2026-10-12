//! Task-scoped consumer login, separate from AgentContent and tool approvals.
use super::*;
use savana_kernel_protocol::v2::{PrivateSessionTransferV04, RegisteredPrivateSessionV04};

pub(super) struct PrivateSessionAuthenticationV04 {
    pub(super) task: DurableTaskIdV2,
    pub(super) root: Digest32V2,
    pub(super) envelope: SignedUiAuthenticationEnvelopeV2,
    pub(super) registered: RegisteredPrivateSessionV04,
    pub(super) consumed: bool,
    pub(super) next_poll: u64,
}

/// What a private login of a task does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PrivateLoginV04 {
    /// Admits the Ready task's committed input into a new run.
    First,
    /// After a kerneld restart: admits the kept copy into a new run with the
    /// same durable run id.
    AfterRestart,
    /// The task's session (at this index) expired in this process: the same
    /// session and run continue under the new login.
    Continue(usize),
}

/// The input a private login of `task` may use at `now`, and what the login
/// does. A later login never brings a new run, root, lifetime or reset
/// charge: it uses only the copy kept for the same durable run, while no
/// session of the task is live. A task never has two sessions.
pub(super) fn private_login_material_v04<'a>(
    task: &'a TaskRecordV2,
    sessions: &[SessionRecordV2],
    now: UnixMillisV2,
) -> Result<(&'a PreparedAgentClaimMaterialV2, PrivateLoginV04), KernelAgentAuthorityErrorV2> {
    let mut same_task = sessions
        .iter()
        .enumerate()
        .filter(|(_, s)| s.durable_task_id == task.durable_task_id);
    let existing = same_task.next();
    if same_task.next().is_some() {
        return Err(KernelAgentAuthorityErrorV2::StateConflict);
    }
    let kept = |material: &PreparedAgentClaimMaterialV2| {
        task.durable_run_id == Some(material.durable_run_id)
            && now.get() < material.expires_at.get()
    };
    match (
        &task.status,
        task.material.as_ref(),
        task.reconnect_material.as_ref(),
        existing,
    ) {
        (PublicTaskStatusV2::Ready { .. }, Some(material), None, None) => {
            Ok((material, PrivateLoginV04::First))
        }
        (PublicTaskStatusV2::Running, None, Some(material), None) if kept(material) => {
            Ok((material, PrivateLoginV04::AfterRestart))
        }
        (PublicTaskStatusV2::Running, None, Some(material), Some((index, session)))
            if kept(material)
                && session.durable_run_id == material.durable_run_id
                && matches!(
                    session.status,
                    AgentSessionStatusV2::Ready | AgentSessionStatusV2::Running
                )
                && now.get() >= session.expires_at.get() =>
        {
            Ok((material, PrivateLoginV04::Continue(index)))
        }
        _ => Err(KernelAgentAuthorityErrorV2::StateConflict),
    }
}

impl KernelAgentAuthorityV2 {
    /// Legacy polling/claiming cannot expose a private task's execution phase or
    /// receive its plaintext admission handles.
    pub(super) fn require_public_task_v04(
        &self,
        task: DurableTaskIdV2,
    ) -> Result<(), KernelAgentAuthorityErrorV2> {
        if let Some(policy) = self.policy.as_ref() {
            if policy
                .durable
                .fused_planning_enrolled_v04(task)
                .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?
            {
                return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
            }
        }
        Ok(())
    }
    pub(crate) fn open_private_session_v04(
        &mut self,
        subject: &crate::v2_input_owner::AuthenticatedTaskContextSubjectV2,
        now: UnixMillisV2,
    ) -> Result<PrivateSessionTransferV04, KernelAgentAuthorityErrorV2> {
        self.ensure_durable_available()?;
        let auth = subject.authorization();
        let task_id = auth
            .durable_task_id()
            .ok_or(KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let policy = self
            .policy
            .as_ref()
            .ok_or(KernelAgentAuthorityErrorV2::Unavailable)?;
        let state = policy
            .durable
            .task_authorization_state(task_id)
            .map_err(|_| KernelAgentAuthorityErrorV2::StateConflict)?;
        let root = state.authorization().digest();
        let m = state.authorization().material();
        if state.revoked()
            || m.principal() != auth.authenticated_principal()
            || m.installation_digest() != auth.installation_id()
            || m.manifest_digest() != auth.active_state_manifest_digest()
            || auth.installation_id() != self.config.installation_id
            || now.get() < m.not_before().get()
            || now.get() >= m.expires_at().get()
            || !policy
                .durable
                .fused_planning_enrolled_v04(task_id)
                .map_err(|_| KernelAgentAuthorityErrorV2::StateConflict)?
        {
            return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
        }
        if let Some(existing) = self.private_session_authentications.iter().find(|p| {
            p.task == task_id
                && !p.consumed
                && p.envelope
                    .unverified_material()
                    .is_ok_and(|e| now.get() < e.expires_at().get())
        }) {
            let e = existing
                .envelope
                .unverified_material()
                .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
            if existing.root == root
                && now.get() >= e.issued_at().get()
                && now.get() < e.expires_at().get()
                && e.deployment_generation() == auth.deployment_generation()
                && e.active_state_manifest_digest() == auth.active_state_manifest_digest()
            {
                return Ok(existing.registered.transfer);
            }
            return Err(KernelAgentAuthorityErrorV2::Expired);
        }
        let index = self
            .tasks
            .iter()
            .position(|t| t.durable_task_id == task_id)
            .ok_or(KernelAgentAuthorityErrorV2::InvalidReference)?;
        if self.tasks[index]
            .reconnect_material
            .as_ref()
            .is_some_and(|kept| now.get() >= kept.expires_at.get())
        {
            // The run's input lifetime is over: no later login, no copy kept.
            self.tasks[index].reconnect_material = None;
            self.persist_recovery_snapshot()?;
            return Err(KernelAgentAuthorityErrorV2::Expired);
        }
        let task = &self.tasks[index];
        let (material, _) = private_login_material_v04(task, &self.sessions, now)?;
        if task.expected_principal != Some(m.principal())
            || task.active_state_manifest_digest != m.manifest_digest()
            || self.private_session_authentications.len() >= self.maximum_records
        {
            return Err(KernelAgentAuthorityErrorV2::StateConflict);
        }
        let expires = now
            .get()
            .checked_add(300_000)
            .ok_or(KernelAgentAuthorityErrorV2::Expired)?
            .min(m.expires_at().get())
            .min(material.expires_at.get());
        let unsigned = UnsignedUiAuthenticationEnvelopeV2::new(
            self.config.installation_id,
            m.manifest_digest(),
            auth.deployment_generation(),
            UiAuthenticationPurposeV2::PrivateSessionV04,
            UiAuthenticationBindingV2::PrivateSessionV04 {
                durable_task_id: task_id,
                durable_run_id: material.durable_run_id,
                task_authorization_digest: root,
                kerneld_boot_id: self.config.kerneld_server_boot_id,
            },
            Some(m.principal()),
            FixedOriginV2::Approval8766,
            FixedOriginV2::Approval8766,
            Nonce32V2::new(random_bytes()?),
            now,
            UnixMillisV2::new(expires),
        )
        .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let envelope =
            SignedUiAuthenticationEnvelopeV2::sign(unsigned, &self.config.envelope_signing_key)
                .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
        self.private_session_authentications
            .try_reserve(1)
            .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
        let client = policy
            .fused_approval_client
            .as_ref()
            .ok_or(KernelAgentAuthorityErrorV2::Unavailable)?;
        self.verify_private_approval_edge_v04(
            client,
            m.manifest_digest(),
            auth.deployment_generation(),
        )?;
        let registered = client
            .register_private_session_v04(
                envelope.clone(),
                UnixMillisV2::new(now.get().saturating_add(5000).min(expires)),
            )
            .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
        self.private_session_authentications
            .push(PrivateSessionAuthenticationV04 {
                task: task_id,
                root,
                envelope,
                registered,
                consumed: false,
                next_poll: now.get(),
            });
        Ok(registered.transfer)
    }

    pub(super) fn tick_private_sessions_v04(
        &mut self,
        values: &mut KernelValueOwnerV2,
        clock: &mut impl FnMut() -> UnixMillisV2,
    ) -> Result<(), StableCode> {
        let now = clock();
        let Some(index) = self
            .private_session_authentications
            .iter()
            .enumerate()
            .filter(|(_, p)| {
                !p.consumed
                    && now.get() >= p.next_poll
                    && p.envelope.unverified_material().is_ok_and(|e| {
                        now.get() >= e.issued_at().get() && now.get() < e.expires_at().get()
                    })
            })
            .min_by_key(|(_, p)| p.next_poll)
            .map(|(i, _)| i)
        else {
            return Ok(());
        };
        self.private_session_authentications[index].next_poll = now.get().saturating_add(1000);
        let Some(client) = self
            .policy
            .as_ref()
            .and_then(|p| p.fused_approval_client.as_ref())
        else {
            return Ok(());
        };
        let pending = &self.private_session_authentications[index];
        let envelope = pending
            .envelope
            .unverified_material()
            .map_err(|_| StableCode::KernelUnavailable)?;
        self.verify_private_approval_edge_v04(
            client,
            envelope.active_state_manifest_digest(),
            envelope.deployment_generation(),
        )
        .map_err(|_| StableCode::KernelUnavailable)?;
        let deadline = UnixMillisV2::new(
            now.get()
                .saturating_add(5000)
                .min(envelope.expires_at().get()),
        );
        let Ok(Some(settlement)) =
            client.private_session_authentication_v04(pending.registered.record, deadline)
        else {
            return Ok(());
        };
        let received = clock();
        if received.get() < now.get() || received.get() >= deadline.get() {
            return Ok(());
        }
        let _ = self.accept_private_session_v04(index, settlement, values, received);
        self.ensure_durable_available()
            .map_err(|_| StableCode::KernelUnavailable)
    }

    pub(super) fn accept_private_session_v04(
        &mut self,
        index: usize,
        settlement: SignedUiAuthenticationSettlementV2,
        values: &mut KernelValueOwnerV2,
        now: UnixMillisV2,
    ) -> Result<(), KernelAgentAuthorityErrorV2> {
        self.ensure_durable_available()?;
        let pending = self
            .private_session_authentications
            .get(index)
            .ok_or(KernelAgentAuthorityErrorV2::InvalidReference)?;
        if pending.consumed || self.sessions.len() >= self.maximum_records {
            return Err(KernelAgentAuthorityErrorV2::AlreadyConsumed);
        }
        let e = pending
            .envelope
            .unverified_material()
            .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        let p = self
            .policy
            .as_ref()
            .ok_or(KernelAgentAuthorityErrorV2::Unavailable)?;
        let generation = p
            .declassification_rules
            .generation_snapshot()
            .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
        if generation.active_state_manifest_digest() != e.active_state_manifest_digest()
            || generation.deployment_generation() != e.deployment_generation()
        {
            return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
        }
        let verified = settlement
            .verify_private_session_v04(
                self.config.ui_settlement_key_id,
                self.config.ui_settlement_public_key,
                self.config.installation_id,
                e.active_state_manifest_digest(),
                e.deployment_generation(),
                now,
            )
            .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?;
        if verified.envelope_digest()
            != pending
                .envelope
                .envelope_digest()
                .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?
            || verified.binding_digest()
                != e.binding_digest()
                    .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?
            || verified.challenge() != e.envelope_nonce()
            || Some(verified.authenticated_principal()) != e.expected_principal()
            || now.get() >= e.expires_at().get()
        {
            return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
        }
        let state = p
            .durable
            .task_authorization_state(pending.task)
            .map_err(|_| KernelAgentAuthorityErrorV2::StateConflict)?;
        let m = state.authorization().material();
        if state.revoked()
            || state.authorization().digest() != pending.root
            || now.get() < m.not_before().get()
            || now.get() >= m.expires_at().get()
            || m.principal() != verified.authenticated_principal()
        {
            return Err(KernelAgentAuthorityErrorV2::StateConflict);
        }
        if !p
            .durable
            .fused_planning_enrolled_v04(pending.task)
            .map_err(|_| KernelAgentAuthorityErrorV2::StateConflict)?
        {
            return Err(KernelAgentAuthorityErrorV2::StateConflict);
        }
        let task_index = self
            .tasks
            .iter()
            .position(|t| t.durable_task_id == pending.task)
            .ok_or(KernelAgentAuthorityErrorV2::InvalidReference)?;
        let task = &self.tasks[task_index];
        let (material, login) = private_login_material_v04(task, &self.sessions, now)?;
        if e.binding()
            != (UiAuthenticationBindingV2::PrivateSessionV04 {
                durable_task_id: pending.task,
                durable_run_id: material.durable_run_id,
                task_authorization_digest: pending.root,
                kerneld_boot_id: self.config.kerneld_server_boot_id,
            })
            || task.expected_principal != e.expected_principal()
            || task.active_state_manifest_digest != e.active_state_manifest_digest()
        {
            return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
        }
        let expires = UnixMillisV2::new(
            material
                .expires_at
                .get()
                .min(m.expires_at().get())
                .min(e.expires_at().get())
                .min(verified.expires_at().get()),
        );
        let task_id = pending.task;
        if let PrivateLoginV04::Continue(session_index) = login {
            // The same session and run continue under the new login: no new
            // run, input or value, and every value keeps its own lifetime.
            let session = &self.sessions[session_index];
            if session.principal != verified.authenticated_principal()
                || session.active_state_manifest_digest != e.active_state_manifest_digest()
            {
                return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
            }
            values
                .extend_private_run_v04(session.run, material.durable_run_id, now, expires)
                .map_err(map_value_error)?;
            let session = &mut self.sessions[session_index];
            session.expires_at = expires;
            session.status = AgentSessionStatusV2::Running;
            session.task_authorization_digest = Some(pending.root);
        } else {
            let mut admission = values
                .prepare_verified_run_admission(
                    material.producer_identity,
                    material.durable_run_id,
                    e.active_state_manifest_digest(),
                    now,
                    expires,
                    material.policy_allowed_effects,
                    &material.initial_value,
                    &material.provenance,
                )
                .map_err(map_value_error)?;
            // The masked value stays the session input; the consented owner
            // document is reserved beside it for kernel-only fused derivation.
            if let Some((owner_value, owner_provenance)) = material.owner_input.as_ref() {
                values
                    .prepare_owner_input_v04(&mut admission, owner_value, owner_provenance)
                    .map_err(map_value_error)?;
            }
            let run = admission.run_handle();
            let initial = admission.initial_value();
            let revision = RunRevisionObservationV2::new(
                material.durable_run_id,
                1,
                run_revision_digest(
                    material.durable_run_id,
                    e.active_state_manifest_digest(),
                    initial.value_digest(),
                ),
            )
            .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
            let session = mint_handle(AgentSessionHandleV2::from_authority_entropy)?;
            self.sessions
                .try_reserve(1)
                .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
            // Copy before any commit. The first login moves the committed input
            // into the run and keeps the copy; a later login admits the copy and
            // leaves the kept input in place for the next one.
            let copy = material.duplicate()?;
            let task = &mut self.tasks[task_index];
            let material = if login == PrivateLoginV04::AfterRestart {
                copy
            } else {
                let admitted = task
                    .material
                    .take()
                    .ok_or(KernelAgentAuthorityErrorV2::StateConflict)?;
                task.reconnect_material = Some(copy);
                admitted
            };
            // Commit is infallible after reservation; a missing owner handle only
            // makes later fused preparation fail closed.
            let (_, _, owner_input_value) = values
                .commit_verified_run_admission_with_owner_input_v04(
                    admission,
                    material.initial_value,
                    material.provenance,
                    material.owner_input,
                );
            self.sessions.push(SessionRecordV2 {
                session,
                run,
                durable_run_id: material.durable_run_id,
                durable_task_id: pending.task,
                active_state_manifest_digest: e.active_state_manifest_digest(),
                principal: verified.authenticated_principal(),
                producer_identity: material.producer_identity,
                role: p.role,
                policy_allowed_effects: material.policy_allowed_effects,
                signed_planner_policy: material.signed_planner_policy,
                expires_at: expires,
                revision,
                initial_document: material.initial_document,
                initial_value: initial.handle(),
                owner_input_value,
                status: AgentSessionStatusV2::Running,
                task_authorization_digest: Some(pending.root),
            });
        }
        // No session/run/value/tool handle is returned to Agent or the browser.
        self.tasks[task_index].status = PublicTaskStatusV2::Running;
        self.private_session_authentications[index].consumed = true;
        // Only the newest login of a task receives its approval and
        // publication handoffs; an earlier, spent login cannot reach the owner.
        let current = self.private_session_authentications[index]
            .registered
            .record;
        self.private_session_authentications
            .retain(|p| p.task != task_id || !p.consumed || p.registered.record == current);
        self.persist_recovery_snapshot()?;
        Ok(())
    }

    pub(super) fn verify_private_approval_edge_v04(
        &self,
        client: &savana_approvald::ApprovalSuiteOneClientV2,
        manifest: Digest32V2,
        generation: u64,
    ) -> Result<(), KernelAgentAuthorityErrorV2> {
        let edge = client.deployment_edge();
        if edge.role() != savana_kernel_protocol::v2::EndpointRoleV2::KernelApproval
            || edge.installation_id() != self.config.installation_id
            || edge.active_state_manifest_digest() != manifest
            || edge.deployment_generation() != generation
            || edge.client_identity() != self.config.kerneld_identity
            || edge.server_identity() != self.config.approvald_identity
            || edge.server_boot_id() != self.config.approvald_boot_id
        {
            return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
        }
        Ok(())
    }
}
