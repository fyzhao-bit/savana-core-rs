use std::io::{Read as _, Write as _};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, SocketAddrV4, TcpStream};
use std::time::Duration;

use url::Url;

use crate::SavanaError;

const MAX_HTTP_HEADER_BYTES: usize = 32 * 1024;
const MAX_RESPONSE_BODY_BYTES: usize = 8 * 1024 * 1024;
const MAX_REQUEST_BODY_BYTES: usize = savana_kernel_protocol::v2::MAX_HTTP_BODY_BYTES_V2;
const IO_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserService {
    Agent,
    Ingress,
    Approval,
}

impl BrowserService {
    const fn port(self) -> u16 {
        match self {
            Self::Agent => 8768,
            Self::Ingress => 8767,
            Self::Approval => 8766,
        }
    }

    const fn authority(self) -> &'static str {
        match self {
            Self::Agent => "localhost:8768",
            Self::Ingress => "localhost:8767",
            Self::Approval => "localhost:8766",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserOrigin {
    None,
    Jarvis,
    Approval,
    Ingress,
    Agent,
}

impl BrowserOrigin {
    const fn header_value(self) -> Option<&'static str> {
        match self {
            Self::None => None,
            Self::Jarvis => Some("http://localhost:8765"),
            Self::Approval => Some("http://localhost:8766"),
            Self::Ingress => Some("http://localhost:8767"),
            Self::Agent => Some("http://localhost:8768"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserContentType {
    None,
    FormUrlEncoded,
    CanonicalCbor,
    Html,
}

impl BrowserContentType {
    const fn header_value(self) -> Option<&'static str> {
        match self {
            Self::None => None,
            Self::FormUrlEncoded => Some("application/x-www-form-urlencoded"),
            Self::CanonicalCbor => Some("application/cbor"),
            Self::Html => Some("text/html; charset=utf-8"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserRoute {
    ApprovalEnrollmentBootstrap,
    ApprovalUiAuthenticationAccept,
    ApprovalUiAuthenticationBegin,
    ApprovalUiAuthenticationFinish,
    ApprovalDisplay,
    ApprovalDecisionBegin,
    ApprovalDecisionFinish,
    ApprovalEnrollmentBegin,
    ApprovalEnrollmentFinish,
    IngressBootstrapAccept,
    IngressUiAuthenticationComplete,
    IngressInputBegin,
    IngressInputChunk,
    IngressInputFinalize,
    IngressInputAbort,
    AgentUiAuthenticationComplete,
    AgentView,
    AgentAction,
}

impl BrowserRoute {
    const fn method(self) -> &'static str {
        match self {
            Self::ApprovalEnrollmentBootstrap => "GET",
            _ => "POST",
        }
    }

    const fn path(self) -> &'static str {
        match self {
            Self::ApprovalEnrollmentBootstrap => "/v2/enrollment/bootstrap",
            Self::ApprovalUiAuthenticationAccept => "/v2/ui-auth/accept",
            Self::ApprovalUiAuthenticationBegin => "/v2/ui-auth/begin",
            Self::ApprovalUiAuthenticationFinish => "/v2/ui-auth/finish",
            Self::ApprovalDisplay => "/v2/approval/display",
            Self::ApprovalDecisionBegin => "/v2/approval/decision/begin",
            Self::ApprovalDecisionFinish => "/v2/approval/decision/finish",
            Self::ApprovalEnrollmentBegin => "/v2/webauthn/enroll/begin",
            Self::ApprovalEnrollmentFinish => "/v2/webauthn/enroll/finish",
            Self::IngressBootstrapAccept => "/v2/bootstrap/accept",
            Self::IngressUiAuthenticationComplete => "/v2/ui-auth/complete",
            Self::IngressInputBegin => "/v2/input/begin",
            Self::IngressInputChunk => "/v2/input/chunk",
            Self::IngressInputFinalize => "/v2/input/finalize",
            Self::IngressInputAbort => "/v2/input/abort",
            Self::AgentUiAuthenticationComplete => "/v2/ui-auth/complete",
            Self::AgentView => "/v2/agent/view",
            Self::AgentAction => "/v2/agent/action",
        }
    }

    const fn service(self) -> BrowserService {
        match self {
            Self::ApprovalEnrollmentBootstrap
            | Self::ApprovalUiAuthenticationAccept
            | Self::ApprovalUiAuthenticationBegin
            | Self::ApprovalUiAuthenticationFinish
            | Self::ApprovalDisplay
            | Self::ApprovalDecisionBegin
            | Self::ApprovalDecisionFinish
            | Self::ApprovalEnrollmentBegin
            | Self::ApprovalEnrollmentFinish => BrowserService::Approval,
            Self::IngressBootstrapAccept
            | Self::IngressUiAuthenticationComplete
            | Self::IngressInputBegin
            | Self::IngressInputChunk
            | Self::IngressInputFinalize
            | Self::IngressInputAbort => BrowserService::Ingress,
            Self::AgentUiAuthenticationComplete | Self::AgentView | Self::AgentAction => {
                BrowserService::Agent
            }
        }
    }

    const fn request_content_type(self) -> BrowserContentType {
        match self {
            Self::ApprovalEnrollmentBootstrap => BrowserContentType::None,
            Self::ApprovalUiAuthenticationAccept
            | Self::IngressBootstrapAccept
            | Self::IngressUiAuthenticationComplete
            | Self::AgentUiAuthenticationComplete => BrowserContentType::FormUrlEncoded,
            _ => BrowserContentType::CanonicalCbor,
        }
    }

    const fn response_content_type(self) -> BrowserContentType {
        match self {
            Self::ApprovalEnrollmentBootstrap
            | Self::ApprovalUiAuthenticationAccept
            | Self::IngressBootstrapAccept
            | Self::IngressUiAuthenticationComplete
            | Self::AgentUiAuthenticationComplete => BrowserContentType::Html,
            _ => BrowserContentType::CanonicalCbor,
        }
    }

    const fn permits_origin(self, origin: BrowserOrigin) -> bool {
        match self {
            Self::ApprovalEnrollmentBootstrap => matches!(origin, BrowserOrigin::None),
            Self::ApprovalUiAuthenticationAccept => matches!(
                origin,
                BrowserOrigin::Jarvis | BrowserOrigin::Ingress | BrowserOrigin::Agent
            ),
            Self::IngressBootstrapAccept => {
                matches!(origin, BrowserOrigin::Jarvis | BrowserOrigin::Agent)
            }
            Self::IngressUiAuthenticationComplete | Self::AgentUiAuthenticationComplete => {
                matches!(origin, BrowserOrigin::Approval)
            }
            Self::ApprovalUiAuthenticationBegin
            | Self::ApprovalUiAuthenticationFinish
            | Self::ApprovalDisplay
            | Self::ApprovalDecisionBegin
            | Self::ApprovalDecisionFinish
            | Self::ApprovalEnrollmentBegin
            | Self::ApprovalEnrollmentFinish => matches!(origin, BrowserOrigin::Approval),
            Self::IngressInputBegin
            | Self::IngressInputChunk
            | Self::IngressInputFinalize
            | Self::IngressInputAbort => matches!(origin, BrowserOrigin::Ingress),
            Self::AgentView | Self::AgentAction => matches!(origin, BrowserOrigin::Agent),
        }
    }
}

pub struct BrowserRequest {
    pub service: BrowserService,
    pub route: BrowserRoute,
    pub origin: BrowserOrigin,
    pub content_type: BrowserContentType,
    pub body: Vec<u8>,
}

impl BrowserRequest {
    pub fn validate(&self) -> Result<(), SavanaError> {
        let body_shape_is_valid = if self.route.method() == "GET" {
            self.body.is_empty()
        } else {
            !self.body.is_empty() && self.body.len() <= MAX_REQUEST_BODY_BYTES
        };
        if self.service != self.route.service()
            || self.content_type != self.route.request_content_type()
            || !self.route.permits_origin(self.origin)
            || !body_shape_is_valid
        {
            return Err(SavanaError::InvalidRequest);
        }
        Ok(())
    }
}

impl core::fmt::Debug for BrowserRequest {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("BrowserRequest")
            .field("service", &self.service)
            .field("route", &self.route)
            .field("origin", &self.origin)
            .field("content_type", &self.content_type)
            .field("body", &"<redacted>")
            .finish()
    }
}

pub struct BrowserResponse {
    content_type: BrowserContentType,
    body: Vec<u8>,
}

impl BrowserResponse {
    pub fn from_scripted(
        content_type: BrowserContentType,
        body: Vec<u8>,
    ) -> Result<Self, SavanaError> {
        if !matches!(
            content_type,
            BrowserContentType::CanonicalCbor | BrowserContentType::Html
        ) || body.is_empty()
            || body.len() > MAX_RESPONSE_BODY_BYTES
        {
            return Err(SavanaError::InvalidResponse);
        }
        Ok(Self { content_type, body })
    }

    pub const fn content_type(&self) -> BrowserContentType {
        self.content_type
    }

    pub fn body(&self) -> &[u8] {
        &self.body
    }

    pub fn into_body(self) -> Vec<u8> {
        self.body
    }
}

impl core::fmt::Debug for BrowserResponse {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("BrowserResponse")
            .field("content_type", &self.content_type)
            .field("body", &"<redacted>")
            .finish()
    }
}

pub trait BrowserTransport: Send + Sync {
    fn send(&self, request: BrowserRequest) -> Result<BrowserResponse, SavanaError>;
}

#[derive(Clone)]
pub struct ClientEndpoints {
    agent: Url,
    ingress: Url,
    approval: Url,
}

impl ClientEndpoints {
    pub fn new(agent: &str, ingress: &str, approval: &str) -> Result<Self, SavanaError> {
        Ok(Self {
            agent: validate_endpoint(agent, BrowserService::Agent)?,
            ingress: validate_endpoint(ingress, BrowserService::Ingress)?,
            approval: validate_endpoint(approval, BrowserService::Approval)?,
        })
    }

    pub fn endpoint(&self, service: BrowserService) -> &str {
        match service {
            BrowserService::Agent => self.agent.as_str(),
            BrowserService::Ingress => self.ingress.as_str(),
            BrowserService::Approval => self.approval.as_str(),
        }
    }
}

impl core::fmt::Debug for ClientEndpoints {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ClientEndpoints(<fixed-loopback>)")
    }
}

fn validate_endpoint(value: &str, service: BrowserService) -> Result<Url, SavanaError> {
    let lexically_allowed = match service {
        BrowserService::Agent => matches!(value, "http://localhost:8768" | "http://127.0.0.1:8768"),
        BrowserService::Ingress => {
            matches!(value, "http://localhost:8767" | "http://127.0.0.1:8767")
        }
        BrowserService::Approval => {
            matches!(value, "http://localhost:8766" | "http://127.0.0.1:8766")
        }
    };
    if !lexically_allowed {
        return Err(SavanaError::InvalidEndpoint);
    }
    let endpoint = Url::parse(value).map_err(|_| SavanaError::InvalidEndpoint)?;
    if endpoint.scheme() != "http"
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || !matches!(endpoint.host_str(), Some("localhost" | "127.0.0.1"))
        || endpoint.port() != Some(service.port())
        || endpoint.path() != "/"
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
    {
        return Err(SavanaError::InvalidEndpoint);
    }
    Ok(endpoint)
}

#[derive(Debug, Default)]
pub struct LocalFixedHttpTransport;

impl LocalFixedHttpTransport {
    pub const fn new() -> Self {
        Self
    }
}

impl BrowserTransport for LocalFixedHttpTransport {
    fn send(&self, request: BrowserRequest) -> Result<BrowserResponse, SavanaError> {
        request.validate()?;
        let expected_content_type = request.route.response_content_type();
        let address = SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::LOCALHOST,
            request.service.port(),
        ));
        let mut stream =
            TcpStream::connect_timeout(&address, IO_TIMEOUT).map_err(|_| SavanaError::Transport)?;
        stream
            .set_read_timeout(Some(IO_TIMEOUT))
            .and_then(|()| stream.set_write_timeout(Some(IO_TIMEOUT)))
            .map_err(|_| SavanaError::Transport)?;
        let peer = stream.peer_addr().map_err(|_| SavanaError::Transport)?;
        if !peer.ip().is_loopback() || peer.port() != request.service.port() {
            let _ = stream.shutdown(Shutdown::Both);
            return Err(SavanaError::Transport);
        }

        let header = render_request_header(&request, expected_content_type);
        stream
            .write_all(header.as_bytes())
            .and_then(|()| stream.write_all(&request.body))
            .and_then(|()| stream.flush())
            .map_err(|_| SavanaError::Transport)?;

        let maximum_wire_bytes = MAX_HTTP_HEADER_BYTES
            .checked_add(MAX_RESPONSE_BODY_BYTES)
            .and_then(|value| value.checked_add(1))
            .ok_or(SavanaError::InvalidResponse)?;
        let mut wire = Vec::new();
        (&mut stream)
            .take(u64::try_from(maximum_wire_bytes).map_err(|_| SavanaError::InvalidResponse)?)
            .read_to_end(&mut wire)
            .map_err(|_| SavanaError::Transport)?;
        let _ = stream.shutdown(Shutdown::Both);
        parse_fixed_http_response(peer, expected_content_type, &wire)
    }
}

fn render_request_header(
    request: &BrowserRequest,
    response_content_type: BrowserContentType,
) -> String {
    let mut header = format!(
        "{} {} HTTP/1.1\r\nHost: {}\r\nAccept: {}\r\n",
        request.route.method(),
        request.route.path(),
        request.service.authority(),
        response_content_type
            .header_value()
            .expect("routes always have a response content type")
    );
    if let Some(origin) = request.origin.header_value() {
        header.push_str("Origin: ");
        header.push_str(origin);
        header.push_str("\r\n");
    }
    if let Some(content_type) = request.content_type.header_value() {
        header.push_str("Content-Type: ");
        header.push_str(content_type);
        header.push_str("\r\nContent-Length: ");
        header.push_str(&request.body.len().to_string());
        header.push_str("\r\n");
    }
    header.push_str("Connection: close\r\n\r\n");
    header
}

pub fn parse_fixed_http_response(
    peer: SocketAddr,
    expected_content_type: BrowserContentType,
    wire: &[u8],
) -> Result<BrowserResponse, SavanaError> {
    if !peer.ip().is_loopback()
        || !matches!(
            expected_content_type,
            BrowserContentType::CanonicalCbor | BrowserContentType::Html
        )
    {
        return Err(SavanaError::InvalidResponse);
    }
    let separator = wire
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or(SavanaError::InvalidResponse)?;
    let header_end = separator
        .checked_add(4)
        .ok_or(SavanaError::InvalidResponse)?;
    if header_end > MAX_HTTP_HEADER_BYTES {
        return Err(SavanaError::InvalidResponse);
    }
    let header = wire.get(..header_end).ok_or(SavanaError::InvalidResponse)?;
    if header.iter().any(|byte| !byte.is_ascii() || *byte == 0) {
        return Err(SavanaError::InvalidResponse);
    }
    let text = core::str::from_utf8(header).map_err(|_| SavanaError::InvalidResponse)?;
    let mut lines = text
        .strip_suffix("\r\n\r\n")
        .ok_or(SavanaError::InvalidResponse)?
        .split("\r\n");
    if lines.next() != Some("HTTP/1.1 200 OK") {
        return Err(SavanaError::InvalidResponse);
    }

    let mut content_type = None;
    let mut content_length = None;
    let mut connection = None;
    for line in lines {
        if line.is_empty() || line.starts_with([' ', '\t']) {
            return Err(SavanaError::InvalidResponse);
        }
        let (name, value) = line.split_once(':').ok_or(SavanaError::InvalidResponse)?;
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(SavanaError::InvalidResponse);
        }
        let value = value.trim_matches([' ', '\t']);
        if value.bytes().any(|byte| byte.is_ascii_control()) {
            return Err(SavanaError::InvalidResponse);
        }
        match name.to_ascii_lowercase().as_str() {
            "content-type" => set_once(&mut content_type, value)?,
            "content-length" => {
                if value.is_empty()
                    || !value.bytes().all(|byte| byte.is_ascii_digit())
                    || (value.len() > 1 && value.starts_with('0'))
                {
                    return Err(SavanaError::InvalidResponse);
                }
                let length = value
                    .parse::<usize>()
                    .map_err(|_| SavanaError::InvalidResponse)?;
                set_once(&mut content_length, length)?;
            }
            "connection" => set_once(&mut connection, value)?,
            "content-encoding" | "transfer-encoding" | "set-cookie" | "location" | "trailer"
            | "upgrade" | "proxy-authenticate" | "proxy-connection" => {
                return Err(SavanaError::InvalidResponse)
            }
            _ => {}
        }
    }
    if content_type != expected_content_type.header_value()
        || !connection.is_some_and(|value| value.eq_ignore_ascii_case("close"))
    {
        return Err(SavanaError::InvalidResponse);
    }
    let length = content_length.ok_or(SavanaError::InvalidResponse)?;
    if length == 0 || length > MAX_RESPONSE_BODY_BYTES {
        return Err(SavanaError::InvalidResponse);
    }
    let body_end = header_end
        .checked_add(length)
        .ok_or(SavanaError::InvalidResponse)?;
    if body_end != wire.len() {
        return Err(SavanaError::InvalidResponse);
    }
    BrowserResponse::from_scripted(expected_content_type, wire[header_end..body_end].to_vec())
}

fn set_once<T>(slot: &mut Option<T>, value: T) -> Result<(), SavanaError> {
    if slot.is_some() {
        Err(SavanaError::InvalidResponse)
    } else {
        *slot = Some(value);
        Ok(())
    }
}
