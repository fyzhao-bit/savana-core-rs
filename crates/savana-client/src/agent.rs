use savana_kernel_protocol::v2::{
    decode_agent_browser_mutation_response_v2, decode_agent_browser_read_view_response_v2,
    encode_agent_browser_request_v2, AgentBrowserActionV2, AgentBrowserMutationResponseV2,
    AgentBrowserRequestV2, AgentSessionStatusV2, VaultPublicStateV2,
};

use crate::session::LocalSessionState;
use crate::{
    BrowserContentType, BrowserOrigin, BrowserRequest, BrowserRoute, BrowserService, Handle,
    IntentPrivacy, MaskedView, Plan, PlanStep, SavanaError, Session,
};

const MAXIMUM_VIEW_BYTES: u32 = 8 * 1024 * 1024 - 512;

impl Session {
    pub fn read_view(&mut self, document: &Handle) -> Result<MaskedView, SavanaError> {
        self.require_open()?;
        let document = document.expect_document(&self.binding)?;
        if self.revoked_documents.contains(&document) {
            return Err(SavanaError::InvalidState);
        }
        let request = AgentBrowserRequestV2::ReadView {
            tab: self.agent.tab,
            client_request_nonce: self.nonces.nonce()?,
            document,
            cursor: None,
            maximum_encoded_bytes: MAXIMUM_VIEW_BYTES,
        };
        let response = self.send_browser_request(BrowserRequest {
            service: BrowserService::Agent,
            route: BrowserRoute::AgentView,
            origin: BrowserOrigin::Agent,
            content_type: BrowserContentType::CanonicalCbor,
            body: encode_agent_browser_request_v2(request)
                .map_err(|_| SavanaError::InvalidRequest)?,
        })?;
        let decoded = decode_agent_browser_read_view_response_v2(response.body())
            .map_err(|_| SavanaError::InvalidResponse)?;
        Ok(MaskedView::from_protocol(decoded.view().clone()))
    }

    pub fn run_planner(&mut self, privacy: IntentPrivacy) -> Result<Plan, SavanaError> {
        let action = match privacy {
            IntentPrivacy::Private => AgentBrowserActionV2::RunPlanner,
            IntentPrivacy::ThirdParty => AgentBrowserActionV2::RunPlannerWithThirdPartyMapper,
        };
        let response = match self.agent_action(action) {
            Ok(response) => response,
            Err(error) if error.is_local_run_stop() => return Err(error),
            Err(error) => {
                self.state = LocalSessionState::Closed;
                return Err(error);
            }
        };
        match response {
            AgentBrowserMutationResponseV2::PlannerCommitted { steps } => Ok(Plan {
                steps: steps
                    .into_iter()
                    .map(|step| PlanStep {
                        handle: Handle::plan_step(&self.binding, step),
                    })
                    .collect(),
            }),
            _ => {
                self.state = LocalSessionState::Closed;
                Err(SavanaError::InvalidResponse)
            }
        }
    }

    pub fn revoke(&mut self, document: &Handle) -> Result<(), SavanaError> {
        self.require_open()?;
        let document = document.expect_document(&self.binding)?;
        if self.revoked_documents.contains(&document) {
            return Err(SavanaError::InvalidState);
        }
        self.revoked_documents.push(document);
        let response =
            match self.agent_action_unchecked(AgentBrowserActionV2::RevokeVault(document)) {
                Ok(response) => response,
                Err(error) => {
                    self.state = LocalSessionState::Closed;
                    return Err(error);
                }
            };
        match response {
            AgentBrowserMutationResponseV2::VaultRevoked {
                state: VaultPublicStateV2::Revoked,
            } => Ok(()),
            _ => {
                self.state = LocalSessionState::Closed;
                Err(SavanaError::InvalidResponse)
            }
        }
    }

    pub fn close(&mut self) -> Result<(), SavanaError> {
        if self.state == LocalSessionState::Closed {
            return Ok(());
        }
        self.state = LocalSessionState::Closed;
        match self.agent_action_unchecked(AgentBrowserActionV2::CloseSession)? {
            AgentBrowserMutationResponseV2::SessionClosed {
                state: AgentSessionStatusV2::Closed,
            } => Ok(()),
            _ => Err(SavanaError::InvalidResponse),
        }
    }

    pub(crate) fn agent_action(
        &self,
        action: AgentBrowserActionV2,
    ) -> Result<AgentBrowserMutationResponseV2, SavanaError> {
        self.require_open()?;
        self.agent_action_unchecked(action)
    }

    fn agent_action_unchecked(
        &self,
        action: AgentBrowserActionV2,
    ) -> Result<AgentBrowserMutationResponseV2, SavanaError> {
        let request = AgentBrowserRequestV2::Act {
            tab: self.agent.tab,
            client_request_nonce: self.nonces.nonce()?,
            action,
        };
        let response = self.send_browser_request(BrowserRequest {
            service: BrowserService::Agent,
            route: BrowserRoute::AgentAction,
            origin: BrowserOrigin::Agent,
            content_type: BrowserContentType::CanonicalCbor,
            body: encode_agent_browser_request_v2(request)
                .map_err(|_| SavanaError::InvalidRequest)?,
        })?;
        decode_agent_browser_mutation_response_v2(response.body())
            .map_err(|_| SavanaError::InvalidResponse)
    }

    pub(crate) fn send_browser_request(
        &self,
        request: BrowserRequest,
    ) -> Result<crate::BrowserResponse, SavanaError> {
        if let Some(guard) = &self.agent_run_guard {
            guard.check()?;
        }
        request.validate()?;
        let expected = request.route.response_content_type();
        let response = self.transport.send(request)?;
        if response.content_type() != expected {
            return Err(SavanaError::InvalidResponse);
        }
        Ok(response)
    }
}
