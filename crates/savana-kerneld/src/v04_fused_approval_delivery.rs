//! Private kernel-to-approvald delivery. No Agent forwarding or synthetic vote.
use super::*;
use savana_kernel_protocol::v2::{ApprovalSettlementViewV2, EndpointRoleV2, RegisteredApprovalV2};

impl KernelG4G5RuntimeV2 {
    /// Startup-only installation; a caller cannot substitute an Agent edge.
    pub(crate) fn install_fused_approval_client_v04(
        &mut self,
        client: savana_approvald::ApprovalSuiteOneClientV2,
        expected: savana_kernel_protocol::v2::KernelServiceHandshakeEdgeV2,
    ) -> Result<(), StableCode> {
        if self.fused_approval_client.is_some()
            || expected.role() != EndpointRoleV2::KernelApproval
            || client.deployment_edge() != expected
        {
            return Err(StableCode::KernelUnavailable);
        }
        self.fused_approval_client = Some(client);
        Ok(())
    }
}

impl KernelAgentAuthorityV2 {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn deliver_fused_approval_v04(
        &mut self,
        action: &fused_actions::FusedPrivateActionV04,
        envelope: SignedApprovalEnvelopeV2,
        display: SignedUiAuthenticationEnvelopeV2,
        manifest: Digest32V2,
        generation: u64,
        evaluated_at: UnixMillisV2,
        clock: &mut impl FnMut() -> UnixMillisV2,
    ) -> Result<(), KernelAgentAuthorityErrorV2> {
        self.ensure_durable_available()?;
        let Some(client) = self
            .policy
            .as_ref()
            .and_then(|p| p.fused_approval_client.as_ref())
        else {
            // Unconfigured is a safe pause, not a route to the Agent fallback.
            return Ok(());
        };
        let edge = client.deployment_edge();
        if edge.role() != EndpointRoleV2::KernelApproval
            || edge.installation_id() != self.config.installation_id
            || edge.active_state_manifest_digest() != manifest
            || edge.deployment_generation() != generation
            || edge.client_identity() != self.config.kerneld_identity
            || edge.server_identity() != self.config.approvald_identity
            || edge.server_boot_id() != self.config.approvald_boot_id
        {
            return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
        }
        // The material came from the just-completed private G5 evaluation and
        // was durably archived before NeedsApproval. Re-register exact bytes on
        // every attempt, so loss of a volatile approvald handle is recoverable.
        let expires = envelope
            .unverified_material()
            .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?
            .expires_at()
            .get();
        let start = clock();
        if start.get() < evaluated_at.get() || start.get() >= expires {
            return Err(KernelAgentAuthorityErrorV2::Expired);
        }
        let deadline = UnixMillisV2::new(start.get().saturating_add(5_000).min(expires));
        let task = envelope
            .unverified_material()
            .map_err(|_| KernelAgentAuthorityErrorV2::BindingMismatch)?
            .task_action_binding()
            .ok_or(KernelAgentAuthorityErrorV2::BindingMismatch)?
            .task();
        let registered = client
            .register_approval(envelope, display, deadline)
            .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
        let RegisteredApprovalV2::Tool { approval, .. } = registered else {
            return Err(KernelAgentAuthorityErrorV2::BindingMismatch);
        };
        if let Some(session) = self
            .private_session_authentications
            .iter()
            .find(|s| s.task == task && s.consumed)
        {
            client
                .attach_private_approval_v04(
                    session.registered.record,
                    approval,
                    session.root,
                    deadline,
                )
                .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
        }
        let query_at = clock();
        if query_at.get() < start.get() || query_at.get() >= deadline.get() {
            return Err(KernelAgentAuthorityErrorV2::Expired);
        }
        let view = client
            .get_kernel_approval_settlement(approval, deadline)
            .map_err(|_| KernelAgentAuthorityErrorV2::Unavailable)?;
        let received_at = clock();
        if received_at.get() < query_at.get() || received_at.get() >= deadline.get() {
            return Err(KernelAgentAuthorityErrorV2::Expired);
        }
        match view {
            ApprovalSettlementViewV2::Approved { settlement }
            | ApprovalSettlementViewV2::Denied { settlement } => {
                // Both outcomes pass through G6: signatures, exact task/action,
                // current root/content and expiry. A transport status is not an
                // authorization. Verified denial is durably retained by G6 too.
                self.authorize_fused_action_v04(
                    action,
                    settlement,
                    manifest,
                    generation,
                    received_at,
                )?;
            }
            ApprovalSettlementViewV2::Pending | ApprovalSettlementViewV2::Expired => (),
        }
        // No immediate dispatch: the next owner turn re-evaluates then runs G7.
        Ok(())
    }
}
