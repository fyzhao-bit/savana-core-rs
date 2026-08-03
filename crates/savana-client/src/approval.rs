use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use savana_kernel_protocol::v2::{
    decode_approval_decision_browser_begin_response_v2,
    decode_approval_decision_browser_finish_response_v2, decode_approval_display_view_v2,
    decode_ui_authentication_browser_begin_response_v2,
    decode_ui_authentication_browser_finish_response_v2,
    encode_approval_decision_browser_begin_request_v2,
    encode_approval_decision_browser_finish_request_v2, encode_approval_display_browser_request_v2,
    encode_ui_authentication_browser_begin_request_v2,
    encode_ui_authentication_browser_finish_request_v2, render_ingress_ui_authentication_form_v2,
    render_ingress_workspace_v2, ApprovalDecisionBrowserBeginRequestV2,
    ApprovalDecisionBrowserFinishRequestV2, ApprovalDecisionBrowserFinishResponseV2,
    ApprovalDecisionV2, ApprovalDisplayAuthenticationTransferCapabilityV2,
    ApprovalDisplayBrowserRequestV2, ApprovalPurposeV2, FixedOriginV2,
    IngressTabSessionCapabilityV2, IngressUiAuthenticationTransferCapabilityV2,
    IngressUiPreAuthenticationTabCapabilityV2, KernelIngressBootstrapTransferCapabilityV2,
    UiAuthenticationBrowserBeginRequestV2, UiAuthenticationBrowserBeginResponseV2,
    UiAuthenticationBrowserFinishRequestV2, UiAuthenticationBrowserFinishResponseV2,
};

use crate::auth::{decode_capability_attribute, extract_main_data_attributes, form_transfer};
use crate::session::{AuthenticatedApprovalTab, AuthenticatedIngressTab};
use crate::{
    BrowserContentType, BrowserOrigin, BrowserRequest, BrowserRoute, BrowserService, SavanaError,
    Session,
};

const MAX_CAPABILITY_ATTRIBUTE_BYTES: usize = 128;
const MAX_PURPOSE_BYTES: usize = 32;
const MAX_TRANSFER_FORM_BYTES: usize = 4096;
const MAX_WORKSPACE_BYTES: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ApprovalOutcome {
    Approved,
    Denied,
}

impl Session {
    pub(crate) fn authenticate_followup_ingress(
        &mut self,
        bootstrap: KernelIngressBootstrapTransferCapabilityV2,
    ) -> Result<IngressTabSessionCapabilityV2, SavanaError> {
        let prepared = self.send_browser_request(BrowserRequest {
            service: BrowserService::Ingress,
            route: BrowserRoute::IngressBootstrapAccept,
            origin: BrowserOrigin::Agent,
            content_type: BrowserContentType::FormUrlEncoded,
            body: form_transfer(bootstrap)?,
        })?;
        let transfer = parse_ingress_authentication_form(prepared.body())?;
        let accepted = self.send_browser_request(BrowserRequest {
            service: BrowserService::Approval,
            route: BrowserRoute::ApprovalUiAuthenticationAccept,
            origin: BrowserOrigin::Ingress,
            content_type: BrowserContentType::FormUrlEncoded,
            body: form_transfer(transfer)?,
        })?;
        let attributes = extract_main_data_attributes(
            accepted.body(),
            &[
                ("data-purpose", MAX_PURPOSE_BYTES),
                ("data-pre-authentication", MAX_CAPABILITY_ATTRIBUTE_BYTES),
            ],
        )?;
        if attributes[0] != "ingress" {
            return Err(SavanaError::InvalidResponse);
        }
        let pre_authentication: IngressUiPreAuthenticationTabCapabilityV2 =
            decode_capability_attribute(&attributes[1], 32)?;
        let nonce = self.nonces.nonce()?;
        let begun = self.send_browser_request(BrowserRequest {
            service: BrowserService::Approval,
            route: BrowserRoute::ApprovalUiAuthenticationBegin,
            origin: BrowserOrigin::Approval,
            content_type: BrowserContentType::CanonicalCbor,
            body: encode_ui_authentication_browser_begin_request_v2(
                UiAuthenticationBrowserBeginRequestV2::Ingress {
                    pre_authentication,
                    client_request_nonce: nonce,
                },
            )
            .map_err(|_| SavanaError::InvalidRequest)?,
        })?;
        let (ceremony, options) =
            match decode_ui_authentication_browser_begin_response_v2(begun.body())
                .map_err(|_| SavanaError::InvalidResponse)?
            {
                UiAuthenticationBrowserBeginResponseV2::Ingress {
                    ceremony,
                    public_key_options_json,
                } => (ceremony, public_key_options_json),
                _ => return Err(SavanaError::InvalidResponse),
            };
        let assertion = self.webauthn.assert_credential(&options)?;
        let finished = self.send_browser_request(BrowserRequest {
            service: BrowserService::Approval,
            route: BrowserRoute::ApprovalUiAuthenticationFinish,
            origin: BrowserOrigin::Approval,
            content_type: BrowserContentType::CanonicalCbor,
            body: encode_ui_authentication_browser_finish_request_v2(
                &UiAuthenticationBrowserFinishRequestV2::Ingress {
                    ceremony,
                    client_request_nonce: nonce,
                    assertion: assertion.into_protocol(),
                },
            )
            .map_err(|_| SavanaError::InvalidRequest)?,
        })?;
        let settlement = match decode_ui_authentication_browser_finish_response_v2(finished.body())
            .map_err(|_| SavanaError::InvalidResponse)?
        {
            UiAuthenticationBrowserFinishResponseV2::TransferToIngress {
                return_origin: FixedOriginV2::Ingress8767,
                transfer,
            } => transfer,
            _ => return Err(SavanaError::InvalidResponse),
        };
        let completed = self.send_browser_request(BrowserRequest {
            service: BrowserService::Ingress,
            route: BrowserRoute::IngressUiAuthenticationComplete,
            origin: BrowserOrigin::Approval,
            content_type: BrowserContentType::FormUrlEncoded,
            body: form_transfer(settlement)?,
        })?;
        let tab = parse_ingress_workspace(completed.body())?;
        self.ingress = Some(AuthenticatedIngressTab { tab });
        Ok(tab)
    }

    pub(crate) fn approve_ingress(
        &mut self,
        transfer: ApprovalDisplayAuthenticationTransferCapabilityV2,
    ) -> Result<ApprovalOutcome, SavanaError> {
        let accepted = self.send_browser_request(BrowserRequest {
            service: BrowserService::Approval,
            route: BrowserRoute::ApprovalUiAuthenticationAccept,
            origin: BrowserOrigin::Ingress,
            content_type: BrowserContentType::FormUrlEncoded,
            body: form_transfer(transfer)?,
        })?;
        let attributes = extract_main_data_attributes(
            accepted.body(),
            &[
                ("data-purpose", MAX_PURPOSE_BYTES),
                ("data-pre-authentication", MAX_CAPABILITY_ATTRIBUTE_BYTES),
            ],
        )?;
        if attributes[0] != "approval-display" {
            return Err(SavanaError::InvalidResponse);
        }
        let pre_authentication = decode_capability_attribute(&attributes[1], 32)?;
        let nonce = self.nonces.nonce()?;
        let begun = self.send_browser_request(BrowserRequest {
            service: BrowserService::Approval,
            route: BrowserRoute::ApprovalUiAuthenticationBegin,
            origin: BrowserOrigin::Approval,
            content_type: BrowserContentType::CanonicalCbor,
            body: encode_ui_authentication_browser_begin_request_v2(
                UiAuthenticationBrowserBeginRequestV2::ApprovalDisplay {
                    pre_authentication,
                    client_request_nonce: nonce,
                },
            )
            .map_err(|_| SavanaError::InvalidRequest)?,
        })?;
        let (ceremony, options) =
            match decode_ui_authentication_browser_begin_response_v2(begun.body())
                .map_err(|_| SavanaError::InvalidResponse)?
            {
                UiAuthenticationBrowserBeginResponseV2::ApprovalDisplay {
                    ceremony,
                    public_key_options_json,
                } => (ceremony, public_key_options_json),
                _ => return Err(SavanaError::InvalidResponse),
            };
        let assertion = self.webauthn.assert_credential(&options)?;
        let finished = self.send_browser_request(BrowserRequest {
            service: BrowserService::Approval,
            route: BrowserRoute::ApprovalUiAuthenticationFinish,
            origin: BrowserOrigin::Approval,
            content_type: BrowserContentType::CanonicalCbor,
            body: encode_ui_authentication_browser_finish_request_v2(
                &UiAuthenticationBrowserFinishRequestV2::ApprovalDisplay {
                    ceremony,
                    client_request_nonce: nonce,
                    assertion: assertion.into_protocol(),
                },
            )
            .map_err(|_| SavanaError::InvalidRequest)?,
        })?;
        let tab = match decode_ui_authentication_browser_finish_response_v2(finished.body())
            .map_err(|_| SavanaError::InvalidResponse)?
        {
            UiAuthenticationBrowserFinishResponseV2::ApprovalDisplayReady { tab } => tab,
            _ => return Err(SavanaError::InvalidResponse),
        };
        self.approval = Some(AuthenticatedApprovalTab { tab });

        let displayed = self.send_browser_request(BrowserRequest {
            service: BrowserService::Approval,
            route: BrowserRoute::ApprovalDisplay,
            origin: BrowserOrigin::Approval,
            content_type: BrowserContentType::CanonicalCbor,
            body: encode_approval_display_browser_request_v2(ApprovalDisplayBrowserRequestV2::new(
                tab,
            ))
            .map_err(|_| SavanaError::InvalidRequest)?,
        })?;
        let view = decode_approval_display_view_v2(displayed.body())
            .map_err(|_| SavanaError::InvalidResponse)?;
        if view.purpose() != ApprovalPurposeV2::Ingress {
            return Err(SavanaError::InvalidResponse);
        }

        let decision_nonce = self.nonces.nonce()?;
        let decision = ApprovalDecisionBrowserBeginRequestV2::new(
            tab,
            decision_nonce,
            ApprovalDecisionV2::Approve,
        )
        .map_err(|_| SavanaError::InvalidRequest)?;
        let begun = self.send_browser_request(BrowserRequest {
            service: BrowserService::Approval,
            route: BrowserRoute::ApprovalDecisionBegin,
            origin: BrowserOrigin::Approval,
            content_type: BrowserContentType::CanonicalCbor,
            body: encode_approval_decision_browser_begin_request_v2(decision)
                .map_err(|_| SavanaError::InvalidRequest)?,
        })?;
        let (ceremony, options) = decode_approval_decision_browser_begin_response_v2(begun.body())
            .map_err(|_| SavanaError::InvalidResponse)?
            .into_parts();
        let assertion = self.webauthn.assert_credential(&options)?;
        let finish = ApprovalDecisionBrowserFinishRequestV2::new(
            ceremony,
            decision_nonce,
            assertion.into_protocol(),
        )
        .map_err(|_| SavanaError::InvalidRequest)?;
        let finished = self.send_browser_request(BrowserRequest {
            service: BrowserService::Approval,
            route: BrowserRoute::ApprovalDecisionFinish,
            origin: BrowserOrigin::Approval,
            content_type: BrowserContentType::CanonicalCbor,
            body: encode_approval_decision_browser_finish_request_v2(&finish)
                .map_err(|_| SavanaError::InvalidRequest)?,
        })?;
        match decode_approval_decision_browser_finish_response_v2(finished.body())
            .map_err(|_| SavanaError::InvalidResponse)?
        {
            ApprovalDecisionBrowserFinishResponseV2::Approved => Ok(ApprovalOutcome::Approved),
            ApprovalDecisionBrowserFinishResponseV2::Denied => Ok(ApprovalOutcome::Denied),
        }
    }
}

fn parse_ingress_authentication_form(
    html: &[u8],
) -> Result<IngressUiAuthenticationTransferCapabilityV2, SavanaError> {
    if html.is_empty() || html.len() > MAX_TRANSFER_FORM_BYTES {
        return Err(SavanaError::InvalidResponse);
    }
    let html_text = core::str::from_utf8(html).map_err(|_| SavanaError::InvalidResponse)?;
    const PREFIX: &str = "<!doctype html><html><head><meta charset=\"utf-8\"><title>Savana authentication</title></head><body><main><h1>Savana authentication</h1><form method=\"post\" action=\"http://localhost:8766/v2/ui-auth/accept\"><input type=\"hidden\" name=\"transfer\" value=\"";
    const SUFFIX: &str = "\"><button type=\"submit\">Continue</button></form><p id=\"savana-status\"></p></main><script src=\"/v2/savana-ui.js\" defer></script></body></html>";
    let token = html_text
        .strip_prefix(PREFIX)
        .and_then(|value| value.strip_suffix(SUFFIX))
        .ok_or(SavanaError::InvalidResponse)?;
    let bytes = URL_SAFE_NO_PAD
        .decode(token)
        .map_err(|_| SavanaError::InvalidResponse)?;
    if bytes.len() != 32 || URL_SAFE_NO_PAD.encode(&bytes) != token {
        return Err(SavanaError::InvalidResponse);
    }
    let transfer = IngressUiAuthenticationTransferCapabilityV2::from_authority_entropy(
        bytes.try_into().map_err(|_| SavanaError::InvalidResponse)?,
    )
    .ok_or(SavanaError::InvalidResponse)?;
    if render_ingress_ui_authentication_form_v2(transfer) != html {
        return Err(SavanaError::InvalidResponse);
    }
    Ok(transfer)
}

fn parse_ingress_workspace(html: &[u8]) -> Result<IngressTabSessionCapabilityV2, SavanaError> {
    if html.is_empty() || html.len() > MAX_WORKSPACE_BYTES {
        return Err(SavanaError::InvalidResponse);
    }
    let text = core::str::from_utf8(html).map_err(|_| SavanaError::InvalidResponse)?;
    const PREFIX: &str = "<!doctype html><html><head><meta charset=\"utf-8\"><title>Savana secure input</title></head><body><main data-ingress-tab=\"";
    const SUFFIX: &str = "\"><h1>Send input to the Rust kernel</h1><label for=\"savana-ingress-input\">Input</label><textarea id=\"savana-ingress-input\" rows=\"16\" cols=\"80\"></textarea><button id=\"savana-ingress-submit\" type=\"button\">Authenticate and commit</button><p id=\"savana-status\">Ready.</p></main><script src=\"/v2/savana-ui.js\" defer></script></body></html>";
    let token = text
        .strip_prefix(PREFIX)
        .and_then(|value| value.strip_suffix(SUFFIX))
        .ok_or(SavanaError::InvalidResponse)?;
    let tab: IngressTabSessionCapabilityV2 = decode_capability_attribute(token, 32)?;
    if render_ingress_workspace_v2(tab) != html {
        return Err(SavanaError::InvalidResponse);
    }
    Ok(tab)
}
