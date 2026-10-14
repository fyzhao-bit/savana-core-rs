use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

use savana_kernel_protocol::v2::{
    AgentMaskedDocumentRefV2, AgentReleaseTicketRefV2, AgentTabSessionCapabilityV2, Digest32V2,
    IngressTabSessionCapabilityV2,
};

use crate::handle::SessionBinding;
use crate::{
    ApprovalCallback, BrowserTransport, Handle, NonceSource, SavanaError, WebAuthnProvider,
};

pub(crate) struct AuthenticatedAgentTab {
    pub(crate) tab: AgentTabSessionCapabilityV2,
}

pub(crate) struct AuthenticatedIngressTab {
    pub(crate) tab: IngressTabSessionCapabilityV2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LocalSessionState {
    Open,
    Closed,
}

pub(crate) struct AgentRunGuard {
    deadline: Instant,
    cancelled: Arc<AtomicBool>,
}

impl AgentRunGuard {
    pub(crate) const fn new(deadline: Instant, cancelled: Arc<AtomicBool>) -> Self {
        Self {
            deadline,
            cancelled,
        }
    }

    pub(crate) fn check(&self) -> Result<(), SavanaError> {
        if self.cancelled.load(Ordering::SeqCst) {
            return Err(SavanaError::Cancelled);
        }
        if Instant::now() >= self.deadline {
            return Err(SavanaError::DeadlineExceeded);
        }
        Ok(())
    }
}

pub struct Session {
    pub(crate) transport: Arc<dyn BrowserTransport>,
    pub(crate) nonces: Arc<dyn NonceSource>,
    pub(crate) binding: SessionBinding,
    pub(crate) agent: AuthenticatedAgentTab,
    pub(crate) ingress: Option<AuthenticatedIngressTab>,
    pub(crate) webauthn: Arc<dyn WebAuthnProvider>,
    pub(crate) ingress_approval: Arc<dyn ApprovalCallback>,
    pub(crate) state: LocalSessionState,
    pub(crate) revoked_documents: Vec<AgentMaskedDocumentRefV2>,
    pub(crate) observed_release_tickets: Vec<AgentReleaseTicketRefV2>,
    pub(crate) removed_connectors: Vec<Digest32V2>,
    pub(crate) agent_run_guard: Option<AgentRunGuard>,
    request_guard_rejected: AtomicBool,
    initial_document: Handle,
}

impl Session {
    pub(crate) fn authenticated_agent(
        transport: Arc<dyn BrowserTransport>,
        nonces: Arc<dyn NonceSource>,
        binding: SessionBinding,
        tab: AgentTabSessionCapabilityV2,
        document: AgentMaskedDocumentRefV2,
        webauthn: Arc<dyn WebAuthnProvider>,
        ingress_approval: Arc<dyn ApprovalCallback>,
    ) -> Self {
        let initial_document = Handle::document(&binding, document);
        Self {
            transport,
            nonces,
            binding,
            agent: AuthenticatedAgentTab { tab },
            ingress: None,
            webauthn,
            ingress_approval,
            state: LocalSessionState::Open,
            revoked_documents: Vec::new(),
            observed_release_tickets: Vec::new(),
            removed_connectors: Vec::new(),
            agent_run_guard: None,
            request_guard_rejected: AtomicBool::new(false),
            initial_document,
        }
    }

    pub const fn initial_document(&self) -> &Handle {
        &self.initial_document
    }

    pub(crate) fn require_open(&self) -> Result<(), SavanaError> {
        if self.state == LocalSessionState::Open {
            Ok(())
        } else {
            Err(SavanaError::InvalidState)
        }
    }

    pub(crate) fn take_request_guard_rejection(&self) -> bool {
        self.request_guard_rejected.swap(false, Ordering::SeqCst)
    }

    pub(crate) fn clear_request_guard_rejection(&self) {
        self.request_guard_rejected.store(false, Ordering::SeqCst);
    }

    pub(crate) fn check_request_guard(&self) -> Result<(), SavanaError> {
        self.clear_request_guard_rejection();
        if let Some(guard) = &self.agent_run_guard {
            if let Err(error) = guard.check() {
                self.request_guard_rejected.store(true, Ordering::SeqCst);
                return Err(error);
            }
        }
        Ok(())
    }
}

impl core::fmt::Debug for Session {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("Session(<authenticated>)")
    }
}

impl core::fmt::Debug for AuthenticatedAgentTab {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("AuthenticatedAgentTab(<opaque>)")
    }
}

impl core::fmt::Debug for AuthenticatedIngressTab {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("AuthenticatedIngressTab(<opaque>)")
    }
}
