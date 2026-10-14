use std::io::{Read, Write};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

use super::{
    cbor::V2DecodeContext, AgentMaskedDocumentRefV2, AgentTabSessionCapabilityV2,
    AgentUiAuthenticationTransferCapabilityV2, ApprovalDisplayAuthenticationTransferCapabilityV2,
    BootstrapKindV2, FixedOriginV2, IngressTabSessionCapabilityV2,
    IngressUiAuthenticationTransferCapabilityV2, JarvisBootstrapSelectorV2,
    KernelIngressBootstrapTransferCapabilityV2, Nonce32V2,
};

const MAX_HTTP_HEADER_BYTES_V2: usize = 32 * 1024;
pub const MAX_HTTP_BODY_BYTES_V2: usize = 1024 * 1024;
const CSP_V2: &str = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; form-action 'self' http://localhost:8766 http://localhost:8767 http://localhost:8768; frame-ancestors 'none'; base-uri 'none'";

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FixedHttpErrorV2 {
    #[error("HTTP request is malformed or exceeds a fixed bound")]
    Malformed,
    #[error("HTTP authority or origin is not authorized for this route")]
    UnauthorizedOrigin,
    #[error("HTTP method or path is not in the closed surface")]
    NotFound,
    #[error("HTTP transport failed")]
    Transport,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FixedHttpServiceV2 {
    Jarvis,
    Approval,
    Ingress,
    Agent,
}

impl FixedHttpServiceV2 {
    pub const fn origin(self) -> FixedOriginV2 {
        match self {
            Self::Jarvis => FixedOriginV2::Jarvis8765,
            Self::Approval => FixedOriginV2::Approval8766,
            Self::Ingress => FixedOriginV2::Ingress8767,
            Self::Agent => FixedOriginV2::Agent8768,
        }
    }

    const fn host(self) -> &'static str {
        match self {
            Self::Jarvis => "localhost:8765",
            Self::Approval => "localhost:8766",
            Self::Ingress => "localhost:8767",
            Self::Agent => "localhost:8768",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FixedHttpRouteV2 {
    BrowserScript,
    JarvisShell,
    JarvisBootstrap {
        kind: BootstrapKindV2,
        selector: JarvisBootstrapSelectorV2,
    },
    JarvisBootstrapContinue,
    ApprovalEnrollmentBootstrap,
    PrivateApprovalLandingV04,
    PrivateSessionLandingV04,
    PrivateSessionAcceptV04,
    PrivateSessionBeginV04,
    PrivateSessionFinishV04,
    PrivateSessionPollV04,
    PrivateSessionPublicationV04,
    PrivateApprovalAcceptV04,
    ApprovalUiAuthenticationAccept,
    ApprovalUiAuthenticationBegin,
    ApprovalUiAuthenticationFinish,
    ApprovalUiAuthenticationPlatformBegin,
    ApprovalUiAuthenticationPlatformStatus,
    ApprovalDisplay,
    ApprovalDecisionBegin,
    ApprovalDecisionFinish,
    ApprovalDecisionPlatformBegin,
    ApprovalDecisionPlatformStatus,
    ApprovalEnrollmentBegin,
    ApprovalEnrollmentFinish,
    IngressBootstrapAccept,
    IngressUiAuthenticationComplete,
    IngressInputBegin,
    IngressInputChunk,
    IngressInputFinalize,
    IngressInputAbort,
    IngressTaskEstablish,
    IngressTaskApprovalPrepare,
    IngressTaskApprovalCommit,
    IngressTaskRevoke,
    IngressTaskRecover,
    IngressTaskContext,
    IngressPrivateSessionV04,
    AgentUiAuthenticationComplete,
    AgentView,
    AgentAction,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixedHttpRequestV2 {
    route: FixedHttpRouteV2,
    origin: Option<FixedOriginV2>,
    body: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContinueJarvisBootstrapRequestV2 {
    selector: JarvisBootstrapSelectorV2,
    client_request_nonce: Nonce32V2,
}

impl ContinueJarvisBootstrapRequestV2 {
    pub fn new(
        selector: JarvisBootstrapSelectorV2,
        client_request_nonce: Nonce32V2,
    ) -> Result<Self, FixedHttpErrorV2> {
        if selector.as_bytes() == &[0; 32] || client_request_nonce.as_bytes() == &[0; 32] {
            return Err(FixedHttpErrorV2::Malformed);
        }
        Ok(Self {
            selector,
            client_request_nonce,
        })
    }

    pub const fn selector(self) -> JarvisBootstrapSelectorV2 {
        self.selector
    }

    pub const fn client_request_nonce(self) -> Nonce32V2 {
        self.client_request_nonce
    }
}

pub fn decode_continue_jarvis_bootstrap_request_v2(
    bytes: &[u8],
) -> Result<ContinueJarvisBootstrapRequestV2, FixedHttpErrorV2> {
    if bytes.is_empty() || bytes.len() > MAX_HTTP_BODY_BYTES_V2 {
        return Err(FixedHttpErrorV2::Malformed);
    }
    let mut decoder = minicbor::Decoder::new(bytes);
    if decoder.array().map_err(|_| FixedHttpErrorV2::Malformed)? != Some(2) {
        return Err(FixedHttpErrorV2::Malformed);
    }
    let mut context = V2DecodeContext;
    let selector = minicbor::Decode::decode(&mut decoder, &mut context)
        .map_err(|_| FixedHttpErrorV2::Malformed)?;
    let client_request_nonce = minicbor::Decode::decode(&mut decoder, &mut context)
        .map_err(|_| FixedHttpErrorV2::Malformed)?;
    let value = ContinueJarvisBootstrapRequestV2::new(selector, client_request_nonce)?;
    if decoder.position() != bytes.len()
        || encode_continue_jarvis_bootstrap_request_v2(value)? != bytes
    {
        return Err(FixedHttpErrorV2::Malformed);
    }
    Ok(value)
}

pub fn encode_continue_jarvis_bootstrap_request_v2(
    value: ContinueJarvisBootstrapRequestV2,
) -> Result<Vec<u8>, FixedHttpErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder.array(2).map_err(|_| FixedHttpErrorV2::Malformed)?;
    minicbor::Encode::encode(&value.selector, &mut encoder, &mut ())
        .map_err(|_| FixedHttpErrorV2::Malformed)?;
    minicbor::Encode::encode(&value.client_request_nonce, &mut encoder, &mut ())
        .map_err(|_| FixedHttpErrorV2::Malformed)?;
    Ok(encoder.into_writer())
}

pub fn render_ingress_bootstrap_form_v2(
    transfer: KernelIngressBootstrapTransferCapabilityV2,
) -> Vec<u8> {
    let token = URL_SAFE_NO_PAD.encode(transfer.transfer_bytes());
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>Savana ingress</title></head><body><main><h1>Continue securely</h1><form method=\"post\" action=\"http://localhost:8767/v2/bootstrap/accept\"><input type=\"hidden\" name=\"transfer\" value=\"{token}\"><button type=\"submit\">Continue</button></form><p id=\"savana-status\"></p></main><script src=\"/v2/savana-ui.js\" defer></script></body></html>"
    )
    .into_bytes()
}

pub fn render_ingress_ui_authentication_form_v2(
    transfer: IngressUiAuthenticationTransferCapabilityV2,
) -> Vec<u8> {
    render_transfer_form(
        "Savana authentication",
        "http://localhost:8766/v2/ui-auth/accept",
        transfer.transfer_bytes(),
    )
}

pub fn render_agent_ui_authentication_form_v2(
    transfer: AgentUiAuthenticationTransferCapabilityV2,
) -> Vec<u8> {
    render_transfer_form(
        "Authenticate agent content",
        "http://localhost:8766/v2/ui-auth/accept",
        transfer.transfer_bytes(),
    )
}

pub fn render_approval_display_authentication_form_v2(
    transfer: ApprovalDisplayAuthenticationTransferCapabilityV2,
) -> Vec<u8> {
    render_transfer_form(
        "Savana approval",
        "http://localhost:8766/v2/ui-auth/accept",
        transfer.transfer_bytes(),
    )
}

/// Static entry, never a list of private tasks or approval status. The transfer
/// is supplied by the trusted local host/user, not a planner or Agent response.
pub fn render_private_approval_landing_v04() -> Vec<u8> {
    br#"<!doctype html><html><head><meta charset="utf-8"><title>Savana private approval</title></head><body><main><h1>Private kernel approval</h1><p>Enter the private handoff from your trusted Savana session. Hardware authentication is still required before any approval details are shown.</p><form method="post" action="/v04/private-approval/accept" autocomplete="off"><label for="transfer">Private handoff</label><input id="transfer" name="transfer" type="password" minlength="43" maxlength="43" pattern="[A-Za-z0-9_-]{43}" autocomplete="off" required><button type="submit">Authenticate privately</button></form></main></body></html>"#.to_vec()
}

fn render_transfer_form(title: &str, action: &str, transfer: &[u8; 32]) -> Vec<u8> {
    let token = URL_SAFE_NO_PAD.encode(transfer);
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>{title}</title></head><body><main><h1>{title}</h1><form method=\"post\" action=\"{action}\"><input type=\"hidden\" name=\"transfer\" value=\"{token}\"><button type=\"submit\">Continue</button></form><p id=\"savana-status\"></p></main><script src=\"/v2/savana-ui.js\" defer></script></body></html>"
    )
    .into_bytes()
}

pub fn render_ingress_workspace_v2(tab: IngressTabSessionCapabilityV2) -> Vec<u8> {
    let tab = URL_SAFE_NO_PAD
        .encode(minicbor::to_vec(tab).expect("encoding an opaque handle into Vec cannot fail"));
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>Savana secure input</title></head><body><main data-ingress-tab=\"{tab}\"><h1>Send input to the Rust kernel</h1><label for=\"savana-ingress-input\">Input</label><textarea id=\"savana-ingress-input\" rows=\"16\" cols=\"80\"></textarea><button id=\"savana-ingress-submit\" type=\"button\">Authenticate and commit</button><p id=\"savana-status\">Ready.</p></main><script src=\"/v2/savana-ui.js\" defer></script></body></html>"
    )
    .into_bytes()
}

pub fn render_agent_workspace_v2(
    tab: AgentTabSessionCapabilityV2,
    document: AgentMaskedDocumentRefV2,
) -> Vec<u8> {
    let tab = URL_SAFE_NO_PAD
        .encode(minicbor::to_vec(tab).expect("encoding an opaque handle into Vec cannot fail"));
    let document = URL_SAFE_NO_PAD.encode(
        minicbor::to_vec(document).expect("encoding an opaque handle into Vec cannot fail"),
    );
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>Savana agent</title></head><body><main data-agent-tab=\"{tab}\" data-agent-document=\"{document}\"><h1>Authenticated Savana agent</h1><pre id=\"savana-agent-view\"></pre><section id=\"savana-agent-actions\"></section><pre id=\"savana-agent-result\"></pre><p id=\"savana-status\">Loading kernel view…</p></main><script src=\"/v2/savana-ui.js\" defer></script></body></html>"
    )
    .into_bytes()
}

impl FixedHttpRequestV2 {
    pub const fn route(&self) -> FixedHttpRouteV2 {
        self.route
    }

    pub const fn origin(&self) -> Option<FixedOriginV2> {
        self.origin
    }

    pub fn body(&self) -> &[u8] {
        &self.body
    }

    pub fn into_body(self) -> Vec<u8> {
        self.body
    }
}

pub fn read_fixed_http_request_v2(
    reader: &mut impl Read,
    service: FixedHttpServiceV2,
) -> Result<FixedHttpRequestV2, FixedHttpErrorV2> {
    let mut header = Vec::new();
    header
        .try_reserve(1024)
        .map_err(|_| FixedHttpErrorV2::Malformed)?;
    let mut byte = [0_u8; 1];
    while header.len() < MAX_HTTP_HEADER_BYTES_V2 {
        reader
            .read_exact(&mut byte)
            .map_err(|_| FixedHttpErrorV2::Transport)?;
        header.push(byte[0]);
        if header.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    if !header.ends_with(b"\r\n\r\n")
        || header.iter().any(|byte| !byte.is_ascii())
        || header.iter().any(|byte| *byte == 0)
    {
        return Err(FixedHttpErrorV2::Malformed);
    }
    let text = std::str::from_utf8(&header).map_err(|_| FixedHttpErrorV2::Malformed)?;
    let mut lines = text[..text.len() - 4].split("\r\n");
    let request_line = lines.next().ok_or(FixedHttpErrorV2::Malformed)?;
    let mut request_parts = request_line.split(' ');
    let method = request_parts.next().ok_or(FixedHttpErrorV2::Malformed)?;
    let path = request_parts.next().ok_or(FixedHttpErrorV2::Malformed)?;
    let version = request_parts.next().ok_or(FixedHttpErrorV2::Malformed)?;
    if request_parts.next().is_some()
        || !matches!(version, "HTTP/1.0" | "HTTP/1.1")
        || !path.starts_with('/')
        || path.contains('?')
        || path.contains('#')
        || path.contains("//")
    {
        return Err(FixedHttpErrorV2::Malformed);
    }

    let route = route(method, path, service)?;
    let mut host = None;
    let mut origin = None;
    let mut content_length = None;
    let mut content_type = None;
    for line in lines {
        if line.is_empty() || line.starts_with([' ', '\t']) {
            return Err(FixedHttpErrorV2::Malformed);
        }
        let (name, value) = line.split_once(':').ok_or(FixedHttpErrorV2::Malformed)?;
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(FixedHttpErrorV2::Malformed);
        }
        let value = value.trim_matches([' ', '\t']);
        if value.bytes().any(|byte| byte.is_ascii_control()) {
            return Err(FixedHttpErrorV2::Malformed);
        }
        match name.to_ascii_lowercase().as_str() {
            "host" => set_once(&mut host, value.to_owned())?,
            "origin" => set_once(&mut origin, parse_origin(value)?)?,
            "content-length" => {
                if value.is_empty()
                    || !value.bytes().all(|byte| byte.is_ascii_digit())
                    || (value.len() > 1 && value.starts_with('0'))
                {
                    return Err(FixedHttpErrorV2::Malformed);
                }
                let length = value
                    .parse::<usize>()
                    .map_err(|_| FixedHttpErrorV2::Malformed)?;
                set_once(&mut content_length, length)?;
            }
            "content-type" => set_once(&mut content_type, value.to_ascii_lowercase())?,
            "cookie"
            | "authorization"
            | "proxy-authorization"
            | "transfer-encoding"
            | "upgrade"
            | "expect" => return Err(FixedHttpErrorV2::UnauthorizedOrigin),
            "sec-websocket-protocol" if !value.is_empty() => {
                return Err(FixedHttpErrorV2::UnauthorizedOrigin);
            }
            _ => {}
        }
    }
    if host.as_deref() != Some(service.host()) {
        return Err(FixedHttpErrorV2::UnauthorizedOrigin);
    }
    validate_origin(route, origin)?;
    let expected_content_type = route_content_type(route);
    let length = content_length.unwrap_or(0);
    if length > MAX_HTTP_BODY_BYTES_V2
        || (method == "GET" && (length != 0 || content_type.is_some()))
        || (method == "POST" && (length == 0 || content_type.as_deref() != expected_content_type))
    {
        return Err(FixedHttpErrorV2::Malformed);
    }
    let mut body = vec![0_u8; length];
    reader
        .read_exact(&mut body)
        .map_err(|_| FixedHttpErrorV2::Transport)?;
    Ok(FixedHttpRequestV2 {
        route,
        origin,
        body,
    })
}

pub fn write_fixed_http_response_v2(
    writer: &mut impl Write,
    status: u16,
    content_type: &str,
    body: &[u8],
) -> Result<(), FixedHttpErrorV2> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        409 => "Conflict",
        410 => "Gone",
        503 => "Service Unavailable",
        _ => return Err(FixedHttpErrorV2::Malformed),
    };
    if body.len() > MAX_HTTP_BODY_BYTES_V2
        || !matches!(
            content_type,
            "application/cbor"
                | "application/javascript; charset=utf-8"
                | "text/html; charset=utf-8"
                | "text/plain; charset=utf-8"
        )
    {
        return Err(FixedHttpErrorV2::Malformed);
    }
    let header = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nPragma: no-cache\r\nReferrer-Policy: no-referrer\r\nX-Content-Type-Options: nosniff\r\nContent-Security-Policy: {CSP_V2}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    writer
        .write_all(header.as_bytes())
        .and_then(|()| writer.write_all(body))
        .and_then(|()| writer.flush())
        .map_err(|_| FixedHttpErrorV2::Transport)
}

fn route(
    method: &str,
    path: &str,
    service: FixedHttpServiceV2,
) -> Result<FixedHttpRouteV2, FixedHttpErrorV2> {
    let route = match (service, method, path) {
        (FixedHttpServiceV2::Approval, "GET", "/v04/session") => {
            FixedHttpRouteV2::PrivateSessionLandingV04
        }
        (FixedHttpServiceV2::Approval, "POST", "/v04/session/begin") => {
            FixedHttpRouteV2::PrivateSessionBeginV04
        }
        (FixedHttpServiceV2::Approval, "POST", "/v04/session/finish") => {
            FixedHttpRouteV2::PrivateSessionFinishV04
        }
        (_, "GET", "/v2/savana-ui.js") => FixedHttpRouteV2::BrowserScript,
        (FixedHttpServiceV2::Jarvis, "GET", "/v2/shell") => FixedHttpRouteV2::JarvisShell,
        (FixedHttpServiceV2::Jarvis, "POST", "/v2/bootstrap/continue") => {
            FixedHttpRouteV2::JarvisBootstrapContinue
        }
        (FixedHttpServiceV2::Approval, "GET", "/v2/enrollment/bootstrap") => {
            FixedHttpRouteV2::ApprovalEnrollmentBootstrap
        }
        (FixedHttpServiceV2::Approval, "GET", "/v04/private-approval") => {
            FixedHttpRouteV2::PrivateApprovalLandingV04
        }
        (FixedHttpServiceV2::Approval, "POST", "/v04/private-approval/accept") => {
            FixedHttpRouteV2::PrivateApprovalAcceptV04
        }
        (FixedHttpServiceV2::Approval, "POST", "/v2/ui-auth/accept") => {
            FixedHttpRouteV2::ApprovalUiAuthenticationAccept
        }
        (FixedHttpServiceV2::Approval, "POST", "/v2/ui-auth/begin") => {
            FixedHttpRouteV2::ApprovalUiAuthenticationBegin
        }
        (FixedHttpServiceV2::Approval, "POST", "/v2/ui-auth/finish") => {
            FixedHttpRouteV2::ApprovalUiAuthenticationFinish
        }
        (FixedHttpServiceV2::Approval, "POST", "/v2/ui-auth/platform/begin") => {
            FixedHttpRouteV2::ApprovalUiAuthenticationPlatformBegin
        }
        (FixedHttpServiceV2::Approval, "POST", "/v2/ui-auth/platform/status") => {
            FixedHttpRouteV2::ApprovalUiAuthenticationPlatformStatus
        }
        (FixedHttpServiceV2::Approval, "POST", "/v2/approval/display") => {
            FixedHttpRouteV2::ApprovalDisplay
        }
        (FixedHttpServiceV2::Approval, "POST", "/v2/approval/decision/begin") => {
            FixedHttpRouteV2::ApprovalDecisionBegin
        }
        (FixedHttpServiceV2::Approval, "POST", "/v2/approval/decision/finish") => {
            FixedHttpRouteV2::ApprovalDecisionFinish
        }
        (FixedHttpServiceV2::Approval, "POST", "/v2/approval/decision/platform/begin") => {
            FixedHttpRouteV2::ApprovalDecisionPlatformBegin
        }
        (FixedHttpServiceV2::Approval, "POST", "/v2/approval/decision/platform/status") => {
            FixedHttpRouteV2::ApprovalDecisionPlatformStatus
        }
        (FixedHttpServiceV2::Approval, "POST", "/v2/webauthn/enroll/begin") => {
            FixedHttpRouteV2::ApprovalEnrollmentBegin
        }
        (FixedHttpServiceV2::Approval, "POST", "/v2/webauthn/enroll/finish") => {
            FixedHttpRouteV2::ApprovalEnrollmentFinish
        }
        (FixedHttpServiceV2::Ingress, "POST", "/v2/bootstrap/accept") => {
            FixedHttpRouteV2::IngressBootstrapAccept
        }
        (FixedHttpServiceV2::Ingress, "POST", "/v2/ui-auth/complete") => {
            FixedHttpRouteV2::IngressUiAuthenticationComplete
        }
        (FixedHttpServiceV2::Ingress, "POST", "/v2/input/begin") => {
            FixedHttpRouteV2::IngressInputBegin
        }
        (FixedHttpServiceV2::Ingress, "POST", "/v2/input/chunk") => {
            FixedHttpRouteV2::IngressInputChunk
        }
        (FixedHttpServiceV2::Ingress, "POST", "/v2/input/finalize") => {
            FixedHttpRouteV2::IngressInputFinalize
        }
        (FixedHttpServiceV2::Ingress, "POST", "/v2/input/abort") => {
            FixedHttpRouteV2::IngressInputAbort
        }
        (FixedHttpServiceV2::Ingress, "POST", "/v2/task/establish") => {
            FixedHttpRouteV2::IngressTaskEstablish
        }
        (FixedHttpServiceV2::Ingress, "POST", "/v2/task/revoke") => {
            FixedHttpRouteV2::IngressTaskRevoke
        }
        (FixedHttpServiceV2::Ingress, "POST", "/v2/task/recover") => {
            FixedHttpRouteV2::IngressTaskRecover
        }
        (FixedHttpServiceV2::Ingress, "POST", "/v04/session/open") => {
            FixedHttpRouteV2::IngressPrivateSessionV04
        }
        (FixedHttpServiceV2::Approval, "POST", "/v04/session/accept") => {
            FixedHttpRouteV2::PrivateSessionAcceptV04
        }
        (FixedHttpServiceV2::Approval, "POST", "/v04/session/poll") => {
            FixedHttpRouteV2::PrivateSessionPollV04
        }
        (FixedHttpServiceV2::Approval, "POST", "/v04/session/publication") => {
            FixedHttpRouteV2::PrivateSessionPublicationV04
        }
        (FixedHttpServiceV2::Ingress, "POST", "/v2/task/context") => {
            FixedHttpRouteV2::IngressTaskContext
        }
        (FixedHttpServiceV2::Ingress, "POST", "/v2/task/approval/prepare") => {
            FixedHttpRouteV2::IngressTaskApprovalPrepare
        }
        (FixedHttpServiceV2::Ingress, "POST", "/v2/task/approval/commit") => {
            FixedHttpRouteV2::IngressTaskApprovalCommit
        }
        (FixedHttpServiceV2::Agent, "POST", "/v2/ui-auth/complete") => {
            FixedHttpRouteV2::AgentUiAuthenticationComplete
        }
        (FixedHttpServiceV2::Agent, "POST", "/v2/agent/view") => FixedHttpRouteV2::AgentView,
        (FixedHttpServiceV2::Agent, "POST", "/v2/agent/action") => FixedHttpRouteV2::AgentAction,
        (FixedHttpServiceV2::Jarvis, "GET", path) => return parse_bootstrap_path(path),
        _ => return Err(FixedHttpErrorV2::NotFound),
    };
    Ok(route)
}

fn parse_bootstrap_path(path: &str) -> Result<FixedHttpRouteV2, FixedHttpErrorV2> {
    let tail = path
        .strip_prefix("/v2/bootstrap/")
        .ok_or(FixedHttpErrorV2::NotFound)?;
    let (kind, selector) = tail.split_once('/').ok_or(FixedHttpErrorV2::NotFound)?;
    if selector.contains('/') {
        return Err(FixedHttpErrorV2::NotFound);
    }
    let kind = match kind {
        "ingress" => BootstrapKindV2::Ingress,
        "approval" => BootstrapKindV2::Approval,
        "agent" => BootstrapKindV2::Agent,
        _ => return Err(FixedHttpErrorV2::NotFound),
    };
    let selector: [u8; 32] = URL_SAFE_NO_PAD
        .decode(selector)
        .map_err(|_| FixedHttpErrorV2::NotFound)?
        .try_into()
        .map_err(|_| FixedHttpErrorV2::NotFound)?;
    let selector = JarvisBootstrapSelectorV2::from_authority_entropy(selector)
        .ok_or(FixedHttpErrorV2::NotFound)?;
    Ok(FixedHttpRouteV2::JarvisBootstrap { kind, selector })
}

fn route_content_type(route: FixedHttpRouteV2) -> Option<&'static str> {
    match route {
        FixedHttpRouteV2::BrowserScript => None,
        FixedHttpRouteV2::IngressBootstrapAccept
        | FixedHttpRouteV2::PrivateSessionAcceptV04
        | FixedHttpRouteV2::PrivateApprovalAcceptV04
        | FixedHttpRouteV2::ApprovalUiAuthenticationAccept
        | FixedHttpRouteV2::IngressUiAuthenticationComplete
        | FixedHttpRouteV2::AgentUiAuthenticationComplete => {
            Some("application/x-www-form-urlencoded")
        }
        FixedHttpRouteV2::JarvisShell
        | FixedHttpRouteV2::PrivateSessionLandingV04
        | FixedHttpRouteV2::PrivateApprovalLandingV04
        | FixedHttpRouteV2::JarvisBootstrap { .. }
        | FixedHttpRouteV2::ApprovalEnrollmentBootstrap => None,
        _ => Some("application/cbor"),
    }
}

fn validate_origin(
    route: FixedHttpRouteV2,
    origin: Option<FixedOriginV2>,
) -> Result<(), FixedHttpErrorV2> {
    let valid = match route {
        FixedHttpRouteV2::BrowserScript
        | FixedHttpRouteV2::PrivateSessionLandingV04
        | FixedHttpRouteV2::PrivateApprovalLandingV04
        | FixedHttpRouteV2::JarvisShell
        | FixedHttpRouteV2::JarvisBootstrap { .. }
        | FixedHttpRouteV2::ApprovalEnrollmentBootstrap => origin.is_none(),
        FixedHttpRouteV2::JarvisBootstrapContinue => origin == Some(FixedOriginV2::Jarvis8765),
        FixedHttpRouteV2::PrivateSessionAcceptV04 => origin == Some(FixedOriginV2::Ingress8767),
        FixedHttpRouteV2::ApprovalUiAuthenticationAccept => matches!(
            origin,
            Some(FixedOriginV2::Jarvis8765 | FixedOriginV2::Ingress8767 | FixedOriginV2::Agent8768)
        ),
        FixedHttpRouteV2::IngressBootstrapAccept => matches!(
            origin,
            Some(FixedOriginV2::Jarvis8765 | FixedOriginV2::Agent8768)
        ),
        FixedHttpRouteV2::IngressUiAuthenticationComplete
        | FixedHttpRouteV2::AgentUiAuthenticationComplete => {
            origin == Some(FixedOriginV2::Approval8766)
        }
        FixedHttpRouteV2::ApprovalUiAuthenticationBegin
        | FixedHttpRouteV2::PrivateSessionBeginV04
        | FixedHttpRouteV2::PrivateSessionFinishV04
        | FixedHttpRouteV2::PrivateSessionPollV04
        | FixedHttpRouteV2::PrivateSessionPublicationV04
        | FixedHttpRouteV2::PrivateApprovalAcceptV04
        | FixedHttpRouteV2::ApprovalUiAuthenticationFinish
        | FixedHttpRouteV2::ApprovalUiAuthenticationPlatformBegin
        | FixedHttpRouteV2::ApprovalUiAuthenticationPlatformStatus
        | FixedHttpRouteV2::ApprovalDisplay
        | FixedHttpRouteV2::ApprovalDecisionBegin
        | FixedHttpRouteV2::ApprovalDecisionFinish
        | FixedHttpRouteV2::ApprovalDecisionPlatformBegin
        | FixedHttpRouteV2::ApprovalDecisionPlatformStatus
        | FixedHttpRouteV2::ApprovalEnrollmentBegin
        | FixedHttpRouteV2::ApprovalEnrollmentFinish => origin == Some(FixedOriginV2::Approval8766),
        FixedHttpRouteV2::IngressInputBegin
        | FixedHttpRouteV2::IngressPrivateSessionV04
        | FixedHttpRouteV2::IngressInputChunk
        | FixedHttpRouteV2::IngressInputFinalize
        | FixedHttpRouteV2::IngressTaskEstablish
        | FixedHttpRouteV2::IngressTaskRevoke
        | FixedHttpRouteV2::IngressTaskRecover
        | FixedHttpRouteV2::IngressTaskContext
        | FixedHttpRouteV2::IngressTaskApprovalPrepare
        | FixedHttpRouteV2::IngressTaskApprovalCommit
        | FixedHttpRouteV2::IngressInputAbort => origin == Some(FixedOriginV2::Ingress8767),
        FixedHttpRouteV2::AgentView | FixedHttpRouteV2::AgentAction => {
            origin == Some(FixedOriginV2::Agent8768)
        }
    };
    if valid {
        Ok(())
    } else {
        Err(FixedHttpErrorV2::UnauthorizedOrigin)
    }
}

fn parse_origin(value: &str) -> Result<FixedOriginV2, FixedHttpErrorV2> {
    match value {
        "http://localhost:8765" => Ok(FixedOriginV2::Jarvis8765),
        "http://localhost:8766" => Ok(FixedOriginV2::Approval8766),
        "http://localhost:8767" => Ok(FixedOriginV2::Ingress8767),
        "http://localhost:8768" => Ok(FixedOriginV2::Agent8768),
        _ => Err(FixedHttpErrorV2::UnauthorizedOrigin),
    }
}

fn set_once<T>(slot: &mut Option<T>, value: T) -> Result<(), FixedHttpErrorV2> {
    if slot.is_some() {
        Err(FixedHttpErrorV2::Malformed)
    } else {
        *slot = Some(value);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn private_publication_http_is_owner_post_only() {
        use super::*;
        let request = |origin: &str, path: &str, method: &str| {
            format!(
            "{method} {path} HTTP/1.1\r\nHost: localhost:8766\r\nOrigin: {origin}\r\nContent-Type: application/cbor\r\nContent-Length: 1\r\n\r\nx")
        };
        let path = "/v04/session/publication";
        let parsed = read_fixed_http_request_v2(
            &mut request("http://localhost:8766", path, "POST").as_bytes(),
            FixedHttpServiceV2::Approval,
        )
        .unwrap();
        assert_eq!(
            parsed.route(),
            FixedHttpRouteV2::PrivateSessionPublicationV04
        );
        for origin in [
            "http://localhost:8765",
            "http://localhost:8767",
            "http://localhost:8768",
            "null",
            "https://example.invalid",
        ] {
            assert!(read_fixed_http_request_v2(
                &mut request(origin, path, "POST").as_bytes(),
                FixedHttpServiceV2::Approval
            )
            .is_err());
        }
        for invalid_path in [
            "/v04/session/publication?cap=x",
            "/v04/session/publication#x",
        ] {
            assert!(read_fixed_http_request_v2(
                &mut request("http://localhost:8766", invalid_path, "POST").as_bytes(),
                FixedHttpServiceV2::Approval
            )
            .is_err());
        }
        for service in [
            FixedHttpServiceV2::Agent,
            FixedHttpServiceV2::Ingress,
            FixedHttpServiceV2::Jarvis,
        ] {
            assert!(read_fixed_http_request_v2(
                &mut request("http://localhost:8766", path, "POST").as_bytes(),
                service
            )
            .is_err());
        }
        assert!(read_fixed_http_request_v2(
            &mut request("http://localhost:8766", path, "GET").as_bytes(),
            FixedHttpServiceV2::Approval
        )
        .is_err());
    }

    #[test]
    fn private_approval_http_is_same_origin_post_without_query_tokens() {
        use super::*;
        let request = |origin: &str, path: &str| {
            format!(
            "POST {path} HTTP/1.1\r\nHost: localhost:8766\r\nOrigin: {origin}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 10\r\n\r\ntransfer=x"
        )
        };
        let path = "/v04/private-approval/accept";
        let parsed = read_fixed_http_request_v2(
            &mut request("http://localhost:8766", path).as_bytes(),
            FixedHttpServiceV2::Approval,
        )
        .unwrap();
        assert_eq!(parsed.route(), FixedHttpRouteV2::PrivateApprovalAcceptV04);
        for origin in [
            "http://localhost:8765",
            "http://localhost:8767",
            "http://localhost:8768",
            "null",
            "https://example.invalid",
        ] {
            assert!(read_fixed_http_request_v2(
                &mut request(origin, path).as_bytes(),
                FixedHttpServiceV2::Approval,
            )
            .is_err());
        }
        for path in [
            "/v04/private-approval/accept?transfer=x",
            "/v04/private-approval/accept#x",
        ] {
            assert!(read_fixed_http_request_v2(
                &mut request("http://localhost:8766", path).as_bytes(),
                FixedHttpServiceV2::Approval,
            )
            .is_err());
        }
        for service in [
            FixedHttpServiceV2::Agent,
            FixedHttpServiceV2::Ingress,
            FixedHttpServiceV2::Jarvis,
        ] {
            assert!(read_fixed_http_request_v2(
                &mut request("http://localhost:8766", path).as_bytes(),
                service,
            )
            .is_err());
        }
        assert!(read_fixed_http_request_v2(
            &mut b"GET /v04/private-approval/accept HTTP/1.1\r\nHost: localhost:8766\r\n\r\n"
                .as_slice(),
            FixedHttpServiceV2::Approval,
        )
        .is_err());
        let landing = read_fixed_http_request_v2(
            &mut b"GET /v04/private-approval HTTP/1.1\r\nHost: localhost:8766\r\n\r\n".as_slice(),
            FixedHttpServiceV2::Approval,
        )
        .unwrap();
        assert_eq!(landing.route(), FixedHttpRouteV2::PrivateApprovalLandingV04);
        let html = String::from_utf8(render_private_approval_landing_v04()).unwrap();
        assert!(html.contains("method=\"post\""));
        assert!(html.contains("type=\"password\""));
        assert!(!html.contains("<script"));
        assert!(!html.contains("8765"));
        assert!(!html.contains("8768"));
    }

    use super::*;

    #[test]
    fn fixed_http_platform_routes_are_approval_post_same_origin_only() {
        let routes = [
            (
                "/v2/ui-auth/platform/begin",
                FixedHttpRouteV2::ApprovalUiAuthenticationPlatformBegin,
            ),
            (
                "/v2/ui-auth/platform/status",
                FixedHttpRouteV2::ApprovalUiAuthenticationPlatformStatus,
            ),
            (
                "/v2/approval/decision/platform/begin",
                FixedHttpRouteV2::ApprovalDecisionPlatformBegin,
            ),
            (
                "/v2/approval/decision/platform/status",
                FixedHttpRouteV2::ApprovalDecisionPlatformStatus,
            ),
        ];
        for (path, expected) in routes {
            let request = |method: &str, host: &str, origin: &str| {
                let mut bytes = format!(
                    "{method} {path} HTTP/1.1\r\nHost: {host}\r\nOrigin: {origin}\r\nContent-Type: application/cbor\r\nContent-Length: 1\r\n\r\n"
                )
                .into_bytes();
                bytes.push(0x80);
                bytes
            };
            let decoded = read_fixed_http_request_v2(
                &mut request("POST", "localhost:8766", "http://localhost:8766").as_slice(),
                FixedHttpServiceV2::Approval,
            )
            .unwrap();
            assert_eq!(decoded.route(), expected);

            assert_eq!(
                read_fixed_http_request_v2(
                    &mut request("GET", "localhost:8766", "http://localhost:8766").as_slice(),
                    FixedHttpServiceV2::Approval,
                ),
                Err(FixedHttpErrorV2::NotFound)
            );
            assert_eq!(
                read_fixed_http_request_v2(
                    &mut request("POST", "localhost:8766", "http://localhost:8765").as_slice(),
                    FixedHttpServiceV2::Approval,
                ),
                Err(FixedHttpErrorV2::UnauthorizedOrigin)
            );
            assert!(read_fixed_http_request_v2(
                &mut request("POST", "localhost:8765", "http://localhost:8765").as_slice(),
                FixedHttpServiceV2::Jarvis,
            )
            .is_err());
            assert!(read_fixed_http_request_v2(
                &mut request("POST", "localhost:8766", "http://127.0.0.1:8766").as_slice(),
                FixedHttpServiceV2::Approval,
            )
            .is_err());
            let query = format!("{path}?retry=1");
            let mut request = format!(
                "POST {query} HTTP/1.1\r\nHost: localhost:8766\r\nOrigin: http://localhost:8766\r\nContent-Type: application/cbor\r\nContent-Length: 1\r\n\r\n"
            )
            .into_bytes();
            request.push(0x80);
            assert!(read_fixed_http_request_v2(
                &mut request.as_slice(),
                FixedHttpServiceV2::Approval,
            )
            .is_err());
        }
    }

    #[test]
    fn closed_surface_accepts_exact_ingress_mutation() {
        let body = [0x81, 0x01];
        let request = format!(
            "POST /v2/input/begin HTTP/1.1\r\nHost: localhost:8767\r\nOrigin: http://localhost:8767\r\nContent-Type: application/cbor\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        let mut bytes = request.into_bytes();
        bytes.extend_from_slice(&body);
        let decoded =
            read_fixed_http_request_v2(&mut bytes.as_slice(), FixedHttpServiceV2::Ingress).unwrap();
        assert_eq!(decoded.route(), FixedHttpRouteV2::IngressInputBegin);
        assert_eq!(decoded.body(), body);
    }

    #[test]
    fn task_mutations_require_exact_ingress_origin() {
        for path in [
            "/v2/task/establish",
            "/v2/task/revoke",
            "/v2/task/recover",
            "/v2/task/context",
            "/v2/task/approval/prepare",
            "/v2/task/approval/commit",
        ] {
            for origin in [
                "http://localhost:8767",
                "http://localhost:8768",
                "http://localhost:8765",
                "https://attacker.example",
                "null",
            ] {
                let mut bytes = format!("POST {path} HTTP/1.1\r\nHost: localhost:8767\r\nOrigin: {origin}\r\nContent-Type: application/cbor\r\nContent-Length: 1\r\n\r\n").into_bytes();
                bytes.push(0x80);
                assert_eq!(
                    read_fixed_http_request_v2(&mut bytes.as_slice(), FixedHttpServiceV2::Ingress)
                        .is_ok(),
                    origin == "http://localhost:8767"
                );
            }
        }
    }

    #[test]
    fn privileged_headers_and_cross_origin_requests_fail_closed() {
        for forbidden in [
            "Cookie: a=b\r\n",
            "Authorization: Basic x\r\n",
            "Proxy-Authorization: Basic x\r\n",
            "Sec-WebSocket-Protocol: x\r\n",
            "Transfer-Encoding: chunked\r\n",
        ] {
            let mut request = format!(
                "POST /v2/agent/action HTTP/1.1\r\nHost: localhost:8768\r\nOrigin: http://localhost:8768\r\nContent-Type: application/cbor\r\nContent-Length: 1\r\n{forbidden}\r\n"
            )
            .into_bytes();
            request.push(0x80);
            assert!(
                read_fixed_http_request_v2(&mut request.as_slice(), FixedHttpServiceV2::Agent)
                    .is_err()
            );
        }
        let request = b"POST /v2/input/abort HTTP/1.1\r\nHost: localhost:8767\r\nOrigin: http://localhost:8768\r\nContent-Type: application/cbor\r\nContent-Length: 1\r\n\r\n\x80";
        assert_eq!(
            read_fixed_http_request_v2(&mut request.as_slice(), FixedHttpServiceV2::Ingress),
            Err(FixedHttpErrorV2::UnauthorizedOrigin)
        );
    }

    #[test]
    fn response_has_all_fixed_security_headers_and_no_cors_or_cookie() {
        let mut bytes = Vec::new();
        write_fixed_http_response_v2(&mut bytes, 200, "text/html; charset=utf-8", b"ok").unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("Cache-Control: no-store\r\n"));
        assert!(text.contains("Content-Security-Policy: "));
        assert!(!text.contains("Access-Control-Allow"));
        assert!(!text.contains("Set-Cookie"));
    }

    #[test]
    fn browser_script_is_a_same_origin_get_only_route() {
        for service in [
            FixedHttpServiceV2::Jarvis,
            FixedHttpServiceV2::Approval,
            FixedHttpServiceV2::Ingress,
            FixedHttpServiceV2::Agent,
        ] {
            let request = format!(
                "GET /v2/savana-ui.js HTTP/1.1\r\nHost: {}\r\n\r\n",
                service.host()
            );
            let decoded = read_fixed_http_request_v2(&mut request.as_bytes(), service).unwrap();
            assert_eq!(decoded.route(), FixedHttpRouteV2::BrowserScript);
            assert_eq!(decoded.origin(), None);
            assert!(decoded.body().is_empty());
        }

        let request = b"POST /v2/savana-ui.js HTTP/1.1\r\nHost: localhost:8768\r\nOrigin: http://localhost:8768\r\nContent-Type: application/cbor\r\nContent-Length: 1\r\n\r\n\x80";
        assert_eq!(
            read_fixed_http_request_v2(&mut request.as_slice(), FixedHttpServiceV2::Agent),
            Err(FixedHttpErrorV2::NotFound)
        );
    }
}
