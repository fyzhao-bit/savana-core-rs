use std::sync::Arc;

use savana_kernel_protocol::v2::{
    AgentMaskedDocumentRefV2, AgentTabSessionCapabilityV2, ApprovalTabSessionCapabilityV2,
    IngressTabSessionCapabilityV2,
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
