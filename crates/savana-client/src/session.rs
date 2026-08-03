use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

use savana_kernel_protocol::v2::{
    AgentMaskedDocumentRefV2, AgentReleaseTicketRefV2, AgentTabSessionCapabilityV2,
    ApprovalTabSessionCapabilityV2, Digest32V2, IngressTabSessionCapabilityV2,
};

use crate::handle::SessionBinding;
use crate::{BrowserTransport, Handle, NonceSource, SavanaError, WebAuthnProvider};

#[allow(dead_code)] // Read by authenticated Agent workflows added in Task 4.
pub(crate) struct AuthenticatedAgentTab {
    pub(crate) tab: AgentTabSessionCapabilityV2,
}

#[allow(dead_code)] // Populated and read by authenticated ingress workflows added in Task 4.
pub(crate) struct AuthenticatedIngressTab {
    pub(crate) tab: IngressTabSessionCapabilityV2,
}

#[allow(dead_code)] // Populated and read by authenticated approval workflows added in Task 4.
pub(crate) struct AuthenticatedApprovalTab {
    pub(crate) tab: ApprovalTabSessionCapabilityV2,
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
    #[allow(dead_code)] // Shared transport for workflows added in Task 4.
    pub(crate) transport: Arc<dyn BrowserTransport>,
    #[allow(dead_code)] // Shared nonce source for workflows added in Task 4.
    pub(crate) nonces: Arc<dyn NonceSource>,
    #[allow(dead_code)] // Enforces private capability binding in subsequent workflows.
    pub(crate) binding: SessionBinding,
    #[allow(dead_code)] // Read by authenticated Agent workflows added in Task 4.
    pub(crate) agent: AuthenticatedAgentTab,
    #[allow(dead_code)] // Populated by authenticated ingress workflows added in Task 4.
    pub(crate) ingress: Option<AuthenticatedIngressTab>,
    #[allow(dead_code)] // Populated by authenticated approval workflows added in Task 4.
    pub(crate) approval: Option<AuthenticatedApprovalTab>,
    pub(crate) webauthn: Arc<dyn WebAuthnProvider>,
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
    ) -> Self {
        let initial_document = Handle::document(&binding, document);
        Self {
            transport,
            nonces,
            binding,
            agent: AuthenticatedAgentTab { tab },
            ingress: None,
            approval: None,
            webauthn,
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

impl core::fmt::Debug for AuthenticatedApprovalTab {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("AuthenticatedApprovalTab(<opaque>)")
    }
}
