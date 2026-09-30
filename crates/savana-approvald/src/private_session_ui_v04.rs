//! Private consumer authentication lives on the trusted approval origin. A
//! session receipt is never a tool vote, and no legacy Agent transfer is accepted.
use super::*;
use savana_kernel_protocol::v2::{
    PrivateSessionBrowserCapabilityV04, PrivateSessionTransferV04, RegisteredPrivateSessionV04,
    UiAuthenticationBindingV2,
};

#[cfg(test)]
#[path = "private_session_tests_v04.rs"]
mod tests;

pub(super) struct PrivateSessionRecordV04 {
    registered: RegisteredPrivateSessionV04,
    envelope: savana_kernel_protocol::v2::UnsignedUiAuthenticationEnvelopeV2,
    digest: Digest32V2,
    begun: bool,
    finish_digest: Option<Digest32V2>,
    settlement: Option<SignedUiAuthenticationSettlementV2>,
    browser: Option<PrivateSessionBrowserCapabilityV04>,
    pending_approval: Option<ApprovalRecordHandleV2>,
    publication: Option<savana_kernel_protocol::v2::PrivatePublicationV04>,
}

impl ApprovalUiAuthorityV2 {
    /// Only the authenticated KernelApproval IPC edge calls this method. This
    /// caches a completion observation; it cannot create an approval or effect.
    pub fn attach_private_publication_v04(
        &self,
        session: ApprovalUiRecordHandleV2,
        publication: savana_kernel_protocol::v2::PrivatePublicationV04,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<(), ApprovalUiAuthorityErrorV2> {
        let mut sessions = self
            .private_sessions
            .lock()
            .map_err(|_| ApprovalUiAuthorityErrorV2::Unavailable)?;
        let s = sessions
            .iter_mut()
            .find(|s| s.registered.record == session)
            .ok_or(ApprovalUiAuthorityErrorV2::InvalidReference)?;
        if s.browser.is_none()
            || s.envelope.binding()
                != (UiAuthenticationBindingV2::PrivateSessionV04 {
                    durable_task_id: publication.task(),
                    durable_run_id: publication.run(),
                    task_authorization_digest: publication.root(),
                    kerneld_boot_id: publication.boot(),
                })
            || self
                .state
                .private_session_authentication_v04(s.digest, now, deadline)
                .map_err(map_owner)?
                .is_none()
        {
            return Err(ApprovalUiAuthorityErrorV2::InvalidReference);
        }
        let Some(ApprovalRecordHandleV2::Release(handle)) = s.pending_approval else {
            return Err(ApprovalUiAuthorityErrorV2::InvalidReference);
        };
        let approvals = self
            .approvals
            .lock()
            .map_err(|_| ApprovalUiAuthorityErrorV2::Unavailable)?;
        let a = approvals
            .iter()
            .find(|a| {
                a.role == EndpointRoleV2::KernelApproval
                    && a.handle == ApprovalRecordHandleV2::Release(handle)
            })
            .ok_or(ApprovalUiAuthorityErrorV2::InvalidReference)?;
        if a.envelope_digest != publication.approval_digest()
            || a.private_scope
                != s.envelope
                    .expected_principal()
                    .map(|p| (publication.task(), p))
        {
            return Err(ApprovalUiAuthorityErrorV2::InvalidReference);
        }
        let ApprovalSettlementViewV2::Approved { settlement } = self
            .state
            .approval_settlement_view(a.envelope_digest, now, deadline)
            .map_err(map_owner)?
        else {
            return Err(ApprovalUiAuthorityErrorV2::InvalidReference);
        };
        if settlement.unsigned().purpose()
            != savana_kernel_protocol::v2::ApprovalPurposeV2::FinalRelease
            || Some(settlement.unsigned().authenticated_principal())
                != s.envelope.expected_principal()
            || s.publication.is_some_and(|old| old != publication)
        {
            return Err(ApprovalUiAuthorityErrorV2::InvalidReference);
        }
        s.publication = Some(publication);
        Ok(())
    }

    pub fn private_session_publication_v04(
        &self,
        browser: PrivateSessionBrowserCapabilityV04,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<Option<savana_kernel_protocol::v2::PrivatePublicationV04>, ApprovalUiAuthorityErrorV2>
    {
        let sessions = self
            .private_sessions
            .lock()
            .map_err(|_| ApprovalUiAuthorityErrorV2::Unavailable)?;
        let s = sessions
            .iter()
            .find(|s| s.browser == Some(browser))
            .ok_or(ApprovalUiAuthorityErrorV2::InvalidReference)?;
        if self
            .state
            .private_session_authentication_v04(s.digest, now, deadline)
            .map_err(map_owner)?
            .is_none()
        {
            return Err(ApprovalUiAuthorityErrorV2::InvalidReference);
        }
        // None is unknown/not-yet-observed, NOT success, refusal or safety.
        Ok(s.publication)
    }

    pub fn register_private_session_v04(
        &self,
        envelope: SignedUiAuthenticationEnvelopeV2,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<RegisteredPrivateSessionV04, ApprovalUiAuthorityErrorV2> {
        let unsigned = envelope
            .unverified_material()
            .map_err(|_| ApprovalUiAuthorityErrorV2::InvalidReference)?;
        if unsigned.purpose() != UiAuthenticationPurposeV2::PrivateSessionV04
            || !matches!(
                unsigned.binding(),
                UiAuthenticationBindingV2::PrivateSessionV04 { .. }
            )
        {
            return Err(ApprovalUiAuthorityErrorV2::InvalidReference);
        }
        let digest = envelope
            .envelope_digest()
            .map_err(|_| ApprovalUiAuthorityErrorV2::InvalidReference)?;
        let mut records = self
            .private_sessions
            .lock()
            .map_err(|_| ApprovalUiAuthorityErrorV2::Unavailable)?;
        if let Some(existing) = records.iter().find(|r| r.digest == digest) {
            self.state
                .register_ui_authentication_envelope(envelope, now, deadline)
                .map_err(map_owner)?;
            return Ok(existing.registered);
        }
        if records.len() >= self.maximum_records {
            return Err(ApprovalUiAuthorityErrorV2::Busy);
        }
        records
            .try_reserve(1)
            .map_err(|_| ApprovalUiAuthorityErrorV2::Unavailable)?;
        let registered = RegisteredPrivateSessionV04 {
            record: ApprovalUiRecordHandleV2::from_authority_entropy(draw_nonzero()?)
                .ok_or(ApprovalUiAuthorityErrorV2::Unavailable)?,
            transfer: PrivateSessionTransferV04::from_authority_entropy(draw_nonzero()?)
                .ok_or(ApprovalUiAuthorityErrorV2::Unavailable)?,
        };
        // The durable owner verifies the kernel signature, deployment, principal
        // and time before any browser capability is made reachable.
        if self
            .state
            .register_ui_authentication_envelope(envelope, now, deadline)
            .map_err(map_owner)?
            != digest
        {
            return Err(ApprovalUiAuthorityErrorV2::Unavailable);
        }
        records.push(PrivateSessionRecordV04 {
            registered,
            envelope: unsigned,
            digest,
            begun: false,
            finish_digest: None,
            settlement: None,
            browser: None,
            pending_approval: None,
            publication: None,
        });
        Ok(registered)
    }

    pub fn begin_private_session_v04(
        &self,
        transfer: PrivateSessionTransferV04,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<Vec<u8>, ApprovalUiAuthorityErrorV2> {
        let mut records = self
            .private_sessions
            .lock()
            .map_err(|_| ApprovalUiAuthorityErrorV2::Unavailable)?;
        let r = records
            .iter_mut()
            .find(|r| r.registered.transfer == transfer)
            .ok_or(ApprovalUiAuthorityErrorV2::InvalidReference)?;
        if r.settlement.is_some() {
            return Err(ApprovalUiAuthorityErrorV2::AlreadyConsumed);
        }
        let challenge = self
            .state
            .ui_authentication_challenge(r.digest, now, deadline)
            .map_err(map_owner)?;
        if challenge.purpose() != UiAuthenticationPurposeV2::PrivateSessionV04 {
            return Err(ApprovalUiAuthorityErrorV2::InvalidReference);
        }
        let options = public_key_options_json(challenge, now)?;
        r.begun = true;
        Ok(options)
    }

    pub fn finish_private_session_v04(
        &self,
        transfer: PrivateSessionTransferV04,
        assertion: BrowserWebAuthnAssertionV2,
        exact_request_digest: Digest32V2,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<PrivateSessionBrowserCapabilityV04, ApprovalUiAuthorityErrorV2> {
        let mut records = self
            .private_sessions
            .lock()
            .map_err(|_| ApprovalUiAuthorityErrorV2::Unavailable)?;
        let r = records
            .iter_mut()
            .find(|r| r.registered.transfer == transfer)
            .ok_or(ApprovalUiAuthorityErrorV2::InvalidReference)?;
        if !r.begun
            || now.get() < r.envelope.issued_at().get()
            || now.get() >= r.envelope.expires_at().get()
        {
            return Err(ApprovalUiAuthorityErrorV2::InvalidReference);
        }
        if let Some(existing) = r.finish_digest {
            if existing != exact_request_digest {
                return Err(ApprovalUiAuthorityErrorV2::AlreadyConsumed);
            }
            if self
                .state
                .private_session_authentication_v04(r.digest, now, deadline)
                .map_err(map_owner)?
                .is_none()
            {
                return Err(ApprovalUiAuthorityErrorV2::InvalidReference);
            }
            return r.browser.ok_or(ApprovalUiAuthorityErrorV2::Unavailable);
        }
        let browser = PrivateSessionBrowserCapabilityV04::from_authority_entropy(draw_nonzero()?)
            .ok_or(ApprovalUiAuthorityErrorV2::Unavailable)?;
        let settlement = self
            .state
            .settle_ui_authentication(r.digest, convert_assertion(assertion)?, now, deadline)
            .map_err(map_owner)?;
        let u = settlement.unsigned();
        if u.purpose() != UiAuthenticationPurposeV2::PrivateSessionV04
            || u.envelope_digest() != r.digest
            || Some(u.authenticated_principal()) != r.envelope.expected_principal()
        {
            return Err(ApprovalUiAuthorityErrorV2::Unavailable);
        }
        r.finish_digest = Some(exact_request_digest);
        r.browser = Some(browser);
        r.settlement = Some(settlement);
        Ok(browser)
    }

    /// Called only on the authenticated KernelApproval edge. A lost response
    /// returns the same signed proof; kerneld consumes its original challenge.
    pub fn private_session_authentication_v04(
        &self,
        record: ApprovalUiRecordHandleV2,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<Option<SignedUiAuthenticationSettlementV2>, ApprovalUiAuthorityErrorV2> {
        let records = self
            .private_sessions
            .lock()
            .map_err(|_| ApprovalUiAuthorityErrorV2::Unavailable)?;
        let r = records
            .iter()
            .find(|r| r.registered.record == record)
            .ok_or(ApprovalUiAuthorityErrorV2::InvalidReference)?;
        if now.get() < r.envelope.issued_at().get()
            || now.get() >= r.envelope.expires_at().get()
            || r.settlement
                .as_ref()
                .is_some_and(|s| now.get() >= s.unsigned().expires_at().get())
        {
            return Err(ApprovalUiAuthorityErrorV2::InvalidReference);
        }
        self.state
            .private_session_authentication_v04(r.digest, now, deadline)
            .map_err(map_owner)
    }

    pub fn attach_private_approval_v04(
        &self,
        session: ApprovalUiRecordHandleV2,
        approval: ToolApprovalRecordHandleV2,
        root: Digest32V2,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<(), ApprovalUiAuthorityErrorV2> {
        self.attach_private_action_approval_v04(
            session,
            ApprovalRecordHandleV2::Tool(approval),
            root,
            now,
            deadline,
        )
    }

    pub fn attach_private_release_approval_v04(
        &self,
        session: ApprovalUiRecordHandleV2,
        approval: ReleaseApprovalRecordHandleV2,
        root: Digest32V2,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<(), ApprovalUiAuthorityErrorV2> {
        self.attach_private_action_approval_v04(
            session,
            ApprovalRecordHandleV2::Release(approval),
            root,
            now,
            deadline,
        )
    }

    fn attach_private_action_approval_v04(
        &self,
        session: ApprovalUiRecordHandleV2,
        approval: ApprovalRecordHandleV2,
        root: Digest32V2,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<(), ApprovalUiAuthorityErrorV2> {
        if !matches!(
            approval,
            ApprovalRecordHandleV2::Tool(_) | ApprovalRecordHandleV2::Release(_)
        ) {
            return Err(ApprovalUiAuthorityErrorV2::InvalidReference);
        }
        let mut sessions = self
            .private_sessions
            .lock()
            .map_err(|_| ApprovalUiAuthorityErrorV2::Unavailable)?;
        let s = sessions
            .iter_mut()
            .find(|s| s.registered.record == session)
            .ok_or(ApprovalUiAuthorityErrorV2::InvalidReference)?;
        let UiAuthenticationBindingV2::PrivateSessionV04 {
            durable_task_id,
            task_authorization_digest,
            ..
        } = s.envelope.binding()
        else {
            return Err(ApprovalUiAuthorityErrorV2::InvalidReference);
        };
        if root != task_authorization_digest
            || s.browser.is_none()
            || self
                .state
                .private_session_authentication_v04(s.digest, now, deadline)
                .map_err(map_owner)?
                .is_none()
        {
            return Err(ApprovalUiAuthorityErrorV2::InvalidReference);
        }
        let approvals = self
            .approvals
            .lock()
            .map_err(|_| ApprovalUiAuthorityErrorV2::Unavailable)?;
        let a = approvals
            .iter()
            .find(|a| a.role == EndpointRoleV2::KernelApproval && a.handle == approval)
            .ok_or(ApprovalUiAuthorityErrorV2::InvalidReference)?;
        if a.private_scope
            != s.envelope
                .expected_principal()
                .map(|p| (durable_task_id, p))
        {
            return Err(ApprovalUiAuthorityErrorV2::InvalidReference);
        }
        if let Some(prior) = s.pending_approval.filter(|old| *old != approval) {
            let old = approvals
                .iter()
                .find(|a| a.role == EndpointRoleV2::KernelApproval && a.handle == prior)
                .ok_or(ApprovalUiAuthorityErrorV2::InvalidReference)?;
            if matches!(
                self.state
                    .approval_settlement_view(old.envelope_digest, now, deadline)
                    .map_err(map_owner)?,
                ApprovalSettlementViewV2::Pending
            ) {
                return Err(ApprovalUiAuthorityErrorV2::Busy);
            }
        }
        self.state
            .approval_settlement_view(a.envelope_digest, now, deadline)
            .map_err(map_owner)?;
        s.pending_approval = Some(approval);
        Ok(())
    }

    pub fn private_session_handoff_v04(
        &self,
        browser: PrivateSessionBrowserCapabilityV04,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<Option<ApprovalDisplayAuthenticationTransferCapabilityV2>, ApprovalUiAuthorityErrorV2>
    {
        let sessions = self
            .private_sessions
            .lock()
            .map_err(|_| ApprovalUiAuthorityErrorV2::Unavailable)?;
        let s = sessions
            .iter()
            .find(|s| s.browser == Some(browser))
            .ok_or(ApprovalUiAuthorityErrorV2::InvalidReference)?;
        if self
            .state
            .private_session_authentication_v04(s.digest, now, deadline)
            .map_err(map_owner)?
            .is_none()
        {
            return Err(ApprovalUiAuthorityErrorV2::InvalidReference);
        }
        let Some(pending) = s.pending_approval else {
            return Ok(None);
        };
        let approvals = self
            .approvals
            .lock()
            .map_err(|_| ApprovalUiAuthorityErrorV2::Unavailable)?;
        let a = approvals
            .iter()
            .find(|a| a.role == EndpointRoleV2::KernelApproval && a.handle == pending)
            .ok_or(ApprovalUiAuthorityErrorV2::InvalidReference)?;
        match self
            .state
            .approval_settlement_view(a.envelope_digest, now, deadline)
            .map_err(map_owner)?
        {
            ApprovalSettlementViewV2::Pending => Ok(Some(a.display_transfer)),
            _ => Ok(None),
        }
    }
}
