use savana_kernel_protocol::v2::{
    decode_planner_plan_v2, Digest32V2, PlannerEnvelopeV2, PlannerPlanV2, UnixMillisV2,
};
use zeroize::Zeroizing;

use crate::private_model_transport::{
    PinnedMtlsCborEndpointV2, PrivateModelTransportErrorV2, VerifiedMtlsClientCredentialsV2,
};

const PLANNER_PATH_V2: &str = "/savana.planner.v2/plan";
const MAX_PLANNER_BODY_BYTES_V2: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AgentPlannerClientErrorV2 {
    #[error("planner deadline was exceeded")]
    DeadlineExceeded,
    #[error("planner deployment binding is invalid")]
    InvalidDeployment,
    #[error("planner transport or response is unavailable")]
    Unavailable,
    #[error("planner returned a non-canonical or invalid plan")]
    InvalidPlan,
}

pub struct PinnedMtlsAgentPlannerClientV2 {
    endpoint: PinnedMtlsCborEndpointV2,
}

impl core::fmt::Debug for PinnedMtlsAgentPlannerClientV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("PinnedMtlsAgentPlannerClientV2(<deployment-redacted>)")
    }
}

impl PinnedMtlsAgentPlannerClientV2 {
    pub fn from_verified_deployment(
        host: String,
        port: u16,
        server_spki_sha256: Digest32V2,
        root_certificate_der: Vec<u8>,
        client_certificate_der: Vec<u8>,
        client_private_key_pkcs8_der: Zeroizing<Vec<u8>>,
    ) -> Result<Self, AgentPlannerClientErrorV2> {
        let credentials = VerifiedMtlsClientCredentialsV2::from_verified_deployment(
            root_certificate_der,
            client_certificate_der,
            client_private_key_pkcs8_der,
        )
        .map_err(map_transport)?;
        let endpoint = PinnedMtlsCborEndpointV2::from_verified_deployment(
            host,
            port,
            server_spki_sha256,
            credentials,
        )
        .map_err(map_transport)?;
        Ok(Self { endpoint })
    }

    pub fn plan(
        &self,
        envelope: &PlannerEnvelopeV2,
        deadline: UnixMillisV2,
    ) -> Result<PlannerPlanV2, AgentPlannerClientErrorV2> {
        let body =
            minicbor::to_vec(envelope).map_err(|_| AgentPlannerClientErrorV2::InvalidPlan)?;
        if body.is_empty() || body.len() > MAX_PLANNER_BODY_BYTES_V2 {
            return Err(AgentPlannerClientErrorV2::InvalidPlan);
        }
        let response = self
            .endpoint
            .post_canonical_cbor(PLANNER_PATH_V2, &body, MAX_PLANNER_BODY_BYTES_V2, deadline)
            .map_err(map_transport)?;
        decode_planner_plan_v2(&response).map_err(|_| AgentPlannerClientErrorV2::InvalidPlan)
    }
}

fn map_transport(error: PrivateModelTransportErrorV2) -> AgentPlannerClientErrorV2 {
    match error {
        PrivateModelTransportErrorV2::DeadlineExceeded => {
            AgentPlannerClientErrorV2::DeadlineExceeded
        }
        PrivateModelTransportErrorV2::InvalidDeployment => {
            AgentPlannerClientErrorV2::InvalidDeployment
        }
        PrivateModelTransportErrorV2::Unavailable => AgentPlannerClientErrorV2::Unavailable,
        PrivateModelTransportErrorV2::InvalidResponse => AgentPlannerClientErrorV2::InvalidPlan,
    }
}

#[cfg(test)]
mod tests {
    use crate::private_model_transport::validate_response_header;

    #[test]
    fn planner_http_surface_is_exact_and_rejects_ambient_features() {
        assert_eq!(
            validate_response_header(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/cbor\r\nContent-Length: 42\r\nConnection: close\r\n\r\n",
                1024,
            )
            .unwrap(),
            42
        );
        assert!(validate_response_header(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/cbor\r\nContent-Length: 42\r\nContent-Encoding: gzip\r\nConnection: close\r\n\r\n",
            1024,
        )
        .is_err());
    }
}
