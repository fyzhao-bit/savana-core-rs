#[cfg(test)]
mod tests {
    use savana_kernel_protocol::v2::{AgentMaskedDocumentRefV2, AgentPlanStepRefV2};

    use super::{Handle, HandleKind, SessionBinding};

    #[test]
    fn handle_debug_is_redacted_and_kind_mismatch_fails_closed() {
        let binding = SessionBinding::from_test_bytes([0x31; 32]).unwrap();
        let document = AgentMaskedDocumentRefV2::from_authority_entropy([0x42; 16]).unwrap();
        let document_handle = Handle::document(&binding, document);

        assert_eq!(document_handle.kind(), HandleKind::Document);
        assert_eq!(format!("{document_handle:?}"), "Handle(<opaque:document>)");
        assert!(document_handle.expect_plan_step(&binding).is_err());
    }

    #[test]
    fn a_handle_from_another_session_fails_closed() {
        let owner = SessionBinding::from_test_bytes([0x31; 32]).unwrap();
        let other = SessionBinding::from_test_bytes([0x32; 32]).unwrap();
        let step = AgentPlanStepRefV2::from_authority_entropy([0x43; 16]).unwrap();
        let step_handle = Handle::plan_step(&owner, step);

        assert!(step_handle.expect_plan_step(&other).is_err());
    }
}
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use savana_kernel_protocol::v2::{
    AgentExecutionRefV2, AgentExecutionTicketRefV2, AgentMaskedDocumentRefV2,
    AgentPendingConnectorRegistrationRefV2, AgentPendingToolCallRefV2, AgentPlanStepRefV2,
    AgentReleaseRefV2, AgentReleaseTicketRefV2, AgentUiAuthenticationTransferCapabilityV2,
    Digest32V2, Nonce32V2,
};
use zeroize::Zeroize as _;

use crate::{AuthError, SavanaError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandleKind {
    Document,
    PlanStep,
    PendingToolCall,
    ExecutionTicket,
    ReleaseTicket,
    Execution,
    Release,
    PendingConnectorRegistration,
    Connector,
}

impl HandleKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Document => "document",
            Self::PlanStep => "plan-step",
            Self::PendingToolCall => "pending-tool-call",
            Self::ExecutionTicket => "execution-ticket",
            Self::ReleaseTicket => "release-ticket",
            Self::Execution => "execution",
            Self::Release => "release",
            Self::PendingConnectorRegistration => "pending-connector-registration",
            Self::Connector => "connector",
        }
    }
}

impl core::fmt::Display for HandleKind {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone)]
pub(crate) struct SessionBinding(Nonce32V2);

impl SessionBinding {
    #[allow(dead_code)] // Session creation is implemented in Task 3.
    pub(crate) fn random() -> Result<Self, SavanaError> {
        for _ in 0..8 {
            let mut bytes = [0_u8; 32];
            getrandom::getrandom(&mut bytes).map_err(|_| SavanaError::transport())?;
            if bytes != [0; 32] {
                return Ok(Self(Nonce32V2::new(bytes)));
            }
        }
        Err(SavanaError::transport())
    }

    #[cfg(test)]
    fn from_test_bytes(bytes: [u8; 32]) -> Option<Self> {
        (bytes != [0; 32]).then(|| Self(Nonce32V2::new(bytes)))
    }
}

impl PartialEq for SessionBinding {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

#[allow(dead_code)] // Variants are consumed by the workflow modules added after Task 2.
enum Capability {
    Document(AgentMaskedDocumentRefV2),
    PlanStep(AgentPlanStepRefV2),
    PendingToolCall(AgentPendingToolCallRefV2),
    ExecutionTicket(AgentExecutionTicketRefV2),
    ReleaseTicket(AgentReleaseTicketRefV2),
    Execution(AgentExecutionRefV2),
    Release(AgentReleaseRefV2),
    PendingConnectorRegistration(AgentPendingConnectorRegistrationRefV2),
    Connector(Digest32V2),
}

impl Capability {
    const fn kind(&self) -> HandleKind {
        match self {
            Self::Document(_) => HandleKind::Document,
            Self::PlanStep(_) => HandleKind::PlanStep,
            Self::PendingToolCall(_) => HandleKind::PendingToolCall,
            Self::ExecutionTicket(_) => HandleKind::ExecutionTicket,
            Self::ReleaseTicket(_) => HandleKind::ReleaseTicket,
            Self::Execution(_) => HandleKind::Execution,
            Self::Release(_) => HandleKind::Release,
            Self::PendingConnectorRegistration(_) => HandleKind::PendingConnectorRegistration,
            Self::Connector(_) => HandleKind::Connector,
        }
    }
}

pub struct Handle {
    #[allow(dead_code)] // Read by kind-specific consumers added after Task 2.
    session: SessionBinding,
    capability: Capability,
}

impl Handle {
    pub const fn kind(&self) -> HandleKind {
        self.capability.kind()
    }

    #[allow(dead_code)] // Constructed from decoded Agent responses after Task 2.
    pub(crate) fn document(session: &SessionBinding, capability: AgentMaskedDocumentRefV2) -> Self {
        Self {
            session: session.clone(),
            capability: Capability::Document(capability),
        }
    }

    #[allow(dead_code)] // Constructed from decoded Agent responses after Task 2.
    pub(crate) fn plan_step(session: &SessionBinding, capability: AgentPlanStepRefV2) -> Self {
        Self {
            session: session.clone(),
            capability: Capability::PlanStep(capability),
        }
    }

    #[allow(dead_code)] // Consumed by planner execution after Task 2.
    pub(crate) fn expect_plan_step(
        &self,
        session: &SessionBinding,
    ) -> Result<AgentPlanStepRefV2, SavanaError> {
        self.require_session(session)?;
        match &self.capability {
            Capability::PlanStep(capability) => Ok(*capability),
            _ => Err(SavanaError::WrongHandleKind {
                expected: HandleKind::PlanStep,
                actual: self.kind(),
            }),
        }
    }

    #[allow(dead_code)] // Shared by kind-specific consumers added after Task 2.
    fn require_session(&self, session: &SessionBinding) -> Result<(), SavanaError> {
        if &self.session == session {
            Ok(())
        } else {
            Err(SavanaError::WrongSession)
        }
    }
}

impl core::fmt::Debug for Handle {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "Handle(<opaque:{}>)", self.kind())
    }
}

pub struct SessionBootstrap {
    transfer: Option<AgentUiAuthenticationTransferCapabilityV2>,
}

impl SessionBootstrap {
    pub fn from_control_plane_token(token: &str) -> Result<Self, AuthError> {
        let decoded_len = base64::decoded_len_estimate(token.len());
        if !(32..=34).contains(&decoded_len) {
            return Err(AuthError::InvalidBootstrap);
        }
        let mut bytes = [0_u8; 32];
        let length = match URL_SAFE_NO_PAD.decode_slice(token, &mut bytes) {
            Ok(length) => length,
            Err(_) => {
                bytes.zeroize();
                return Err(AuthError::InvalidBootstrap);
            }
        };
        if length != bytes.len() || URL_SAFE_NO_PAD.encode(bytes) != token {
            bytes.zeroize();
            return Err(AuthError::InvalidBootstrap);
        }
        let transfer = AgentUiAuthenticationTransferCapabilityV2::from_authority_entropy(bytes)
            .ok_or(AuthError::InvalidBootstrap);
        bytes.zeroize();
        transfer.map(|transfer| Self {
            transfer: Some(transfer),
        })
    }

    pub(crate) fn take_transfer(
        &mut self,
    ) -> Result<AgentUiAuthenticationTransferCapabilityV2, AuthError> {
        self.transfer.take().ok_or(AuthError::InvalidBootstrap)
    }
}

impl core::fmt::Debug for SessionBootstrap {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("SessionBootstrap(<opaque>)")
    }
}
