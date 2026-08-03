mod agent;
mod agent_loop;
mod approval;
mod auth;
mod connectors;
mod error;
mod execution;
mod handle;
mod http;
mod identity;
mod ingress;
mod session;
mod types;

use std::sync::Arc;

use savana_kernel_protocol::v2::Nonce32V2;

pub use agent_loop::EventCallback;
pub use approval::ApprovalCallback;
pub use auth::{WebAuthnAssertion, WebAuthnAttestation, WebAuthnProvider};
pub use error::{ApprovalDenied, AuthError, PolicyRefused, SavanaError};
pub use handle::{Handle, HandleKind, SessionBootstrap};
pub use http::{
    parse_fixed_http_response, BrowserContentType, BrowserOrigin, BrowserRequest, BrowserResponse,
    BrowserRoute, BrowserService, BrowserTransport, ClientEndpoints, LocalFixedHttpTransport,
};
pub use identity::Identity;
pub use session::Session;
pub use types::{
    AgentEvent, ApprovalPurpose, ApprovalRequest, ConnectorDescriptor, ContentKind,
    ExecutionResult, ExecutionStatus, IntentPrivacy, MaskedView, Plan, PlanStep, RunLimits,
};

pub trait NonceSource: Send + Sync {
    fn nonce(&self) -> Result<Nonce32V2, SavanaError>;
}

struct SystemNonceSource;

impl NonceSource for SystemNonceSource {
    fn nonce(&self) -> Result<Nonce32V2, SavanaError> {
        for _ in 0..8 {
            let mut bytes = [0_u8; 32];
            getrandom::getrandom(&mut bytes).map_err(|_| SavanaError::transport())?;
            if bytes != [0; 32] {
                return Ok(Nonce32V2::new(bytes));
            }
        }
        Err(SavanaError::transport())
    }
}

pub struct Client {
    endpoints: ClientEndpoints,
    #[allow(dead_code)] // Consumed by the authenticated workflow modules added after Task 2.
    transport: Arc<dyn BrowserTransport>,
    #[allow(dead_code)] // Consumed by the authenticated workflow modules added after Task 2.
    nonces: Arc<dyn NonceSource>,
}

impl Client {
    pub fn new(endpoints: ClientEndpoints) -> Self {
        Self::with_transport(endpoints, Arc::new(LocalFixedHttpTransport::new()))
    }

    pub fn with_transport(
        endpoints: ClientEndpoints,
        transport: Arc<dyn BrowserTransport>,
    ) -> Self {
        Self::with_transport_and_nonce_source(endpoints, transport, Arc::new(SystemNonceSource))
    }

    pub fn with_transport_and_nonce_source(
        endpoints: ClientEndpoints,
        transport: Arc<dyn BrowserTransport>,
        nonces: Arc<dyn NonceSource>,
    ) -> Self {
        Self {
            endpoints,
            transport,
            nonces,
        }
    }

    pub const fn endpoints(&self) -> &ClientEndpoints {
        &self.endpoints
    }

    #[allow(dead_code)] // Foundation seam for the subsequent workflow tasks.
    pub(crate) fn transport(&self) -> &dyn BrowserTransport {
        self.transport.as_ref()
    }

    #[allow(dead_code)] // Foundation seam for the subsequent workflow tasks.
    pub(crate) fn next_nonce(&self) -> Result<Nonce32V2, SavanaError> {
        self.nonces.nonce()
    }
}

impl core::fmt::Debug for Client {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("Client(<configured>)")
    }
}
