//! Trusted owner-side v0.4 authentication/approval client. NOT an Agent API.
//! No task enrollment, planner proposal, raw result, execution ticket or run
//! handles are exposed. Publication metadata is only for the authenticated
//! owner. Login is not admission confirmation or action consent.
use std::sync::Arc;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use minicbor::{Decode as _, Encode as _};
use savana_kernel_protocol::v2::*;

use crate::auth::{decode_capability_attribute, extract_main_data_attributes, form_transfer};
use crate::{
    ApprovalCallback, ApprovalPurpose, ApprovalRequest, AuthError, BrowserContentType,
    BrowserOrigin, BrowserRequest, BrowserResponse, BrowserRoute, BrowserService, BrowserTransport,
    Client, Identity, NonceSource, SavanaError, WebAuthnProvider,
};

/// A private owner capability; never give this object to an untrusted planner.
pub struct PrivateSession {
    transport: Arc<dyn BrowserTransport>,
    nonces: Arc<dyn NonceSource>,
    webauthn: Arc<dyn WebAuthnProvider>,
    credential_id: zeroize::Zeroizing<Vec<u8>>,
    browser: Option<PrivateSessionBrowserCapabilityV04>,
    pending: Option<ApprovalDisplayAuthenticationTransferCapabilityV2>,
    publication: Option<PrivatePublicationV04>,
}

impl core::fmt::Debug for PrivateSession {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("PrivateSessionV04(<private-owner>)")
    }
}

/// Returned only by the authenticated client exchange. Not a new execution or
/// release capability and not standalone signed attestation. No raw bytes.
#[derive(Clone)]
pub struct PublicationReceipt {
    inner: PrivatePublicationV04,
}
impl PublicationReceipt {
    pub fn metadata(&self) -> PrivatePublicationV04 {
        self.inner
    }
    pub fn matches_payload(&self, payload: &[u8]) -> bool {
        self.inner.matches_payload(payload)
    }
}
impl core::fmt::Debug for PublicationReceipt {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("PrivatePublicationReceipt(<owner-only metadata>)")
    }
}

impl Client {
    /// Exchange an EXISTING authenticated, committed Ingress tab for a private
    /// session, without exporting the intermediate transfer to Python/HTTP.
    /// This does not bootstrap Ingress, install a root, or enroll a plan.
    pub fn private_session_from_ingress_v04(
        &self,
        identity: &Identity,
        ingress_tab: &str,
        webauthn: Arc<dyn WebAuthnProvider>,
    ) -> Result<PrivateSession, SavanaError> {
        if !identity.is_active() || ingress_tab.len() != 43 {
            return Err(SavanaError::InvalidRequest);
        }
        let raw = URL_SAFE_NO_PAD
            .decode(ingress_tab)
            .map_err(invalid_request)?;
        if URL_SAFE_NO_PAD.encode(&raw) != ingress_tab {
            return Err(SavanaError::InvalidRequest);
        }
        let tab = IngressTabSessionCapabilityV2::from_authority_entropy(
            raw.try_into().map_err(invalid_request)?,
        )
        .ok_or(SavanaError::InvalidRequest)?;
        self.private_session_for_owner_tab(tab, identity.credential_id(), webauthn)
    }

    pub(crate) fn private_session_for_owner_tab(
        &self,
        tab: IngressTabSessionCapabilityV2,
        credential_id: &[u8],
        webauthn: Arc<dyn WebAuthnProvider>,
    ) -> Result<PrivateSession, SavanaError> {
        let request = BrowserRequest {
            service: BrowserService::Ingress,
            route: BrowserRoute::IngressPrivateSessionV04,
            origin: BrowserOrigin::Ingress,
            content_type: BrowserContentType::CanonicalCbor,
            body: encode_ingress_browser_request_v2(
                &IngressBrowserRequestV2::OpenPrivateSessionV04 {
                    tab,
                    client_request_nonce: self.nonces.nonce()?,
                },
            )
            .map_err(invalid_request)?,
        };
        request.validate()?;
        let response = self.transport.send(request)?;
        if response.content_type() != BrowserContentType::CanonicalCbor {
            return Err(SavanaError::InvalidResponse);
        }
        let transfer = decode_private_session_begin_v04(response.body())
            .map_err(|_| SavanaError::InvalidResponse)?;
        self.authenticate_private_transfer_credential(credential_id, transfer, webauthn)
    }

    /// Authenticate an already issued Ingress private-session transfer. It is
    /// raw canonical base64url (43 chars), not a URL, V2 bootstrap or task ID.
    /// The server enforces principal/root/boot/expiry and verifies the assertion.
    pub fn private_session_v04(
        &self,
        identity: &Identity,
        transfer: &str,
        webauthn: Arc<dyn WebAuthnProvider>,
    ) -> Result<PrivateSession, SavanaError> {
        if !identity.is_active() {
            return Err(AuthError::AuthenticationFailed.into());
        }
        let transfer = parse_transfer(transfer)?;
        self.authenticate_private_transfer(identity, transfer, webauthn)
    }

    fn authenticate_private_transfer(
        &self,
        identity: &Identity,
        transfer: PrivateSessionTransferV04,
        webauthn: Arc<dyn WebAuthnProvider>,
    ) -> Result<PrivateSession, SavanaError> {
        self.authenticate_private_transfer_credential(identity.credential_id(), transfer, webauthn)
    }

    fn authenticate_private_transfer_credential(
        &self,
        credential_id: &[u8],
        transfer: PrivateSessionTransferV04,
        webauthn: Arc<dyn WebAuthnProvider>,
    ) -> Result<PrivateSession, SavanaError> {
        let begun = send(
            self.transport.as_ref(),
            BrowserRoute::PrivateSessionBeginV04,
            encode_private_session_begin_v04(transfer).map_err(invalid_request)?,
        )?;
        let options = decode_options(begun.body())?;
        let assertion = webauthn.assert_credential(&options)?;
        if assertion.credential_id() != credential_id {
            return Err(AuthError::AuthenticationFailed.into());
        }
        let assertion = assertion.into_protocol();
        let finished = send(
            self.transport.as_ref(),
            BrowserRoute::PrivateSessionFinishV04,
            encode_finish(transfer, &assertion)?,
        )?;
        let browser = decode_private_session_browser_v04(finished.body())
            .map_err(|_| SavanaError::InvalidResponse)?;
        Ok(PrivateSession {
            transport: self.transport.clone(),
            nonces: self.nonces.clone(),
            webauthn,
            credential_id: zeroize::Zeroizing::new(credential_id.to_vec()),
            browser: Some(browser),
            pending: None,
            publication: None,
        })
    }
}

impl PrivateSession {
    /// Kernel-confirmed, committed publication, not a model's claim of success.
    /// None means no completion has been observed. It MUST NOT be scored safe.
    pub fn poll_publication(&mut self) -> Result<Option<PublicationReceipt>, SavanaError> {
        let browser = self.browser.ok_or(SavanaError::InvalidState)?;
        let result = (|| {
            let response = send(
                self.transport.as_ref(),
                BrowserRoute::PrivateSessionPublicationV04,
                encode_private_session_browser_v04(browser).map_err(invalid_request)?,
            )?;
            let value = decode_private_publication_status_v04(response.body())
                .map_err(|_| SavanaError::InvalidResponse)?;
            if self.publication.is_some() && self.publication != value {
                return Err(SavanaError::InvalidResponse);
            }
            self.publication = value;
            Ok(value.map(|inner| PublicationReceipt { inner }))
        })();
        if result.is_err() {
            self.close();
        }
        result
    }

    /// Private owner observation only. False means no approval handoff NOW,
    /// never task completion, denial, safety or a publication decision.
    pub fn poll_approval(&mut self) -> Result<bool, SavanaError> {
        let browser = self.browser.ok_or(SavanaError::InvalidState)?;
        self.pending = None;
        let result = (|| {
            let response = send(
                self.transport.as_ref(),
                BrowserRoute::PrivateSessionPollV04,
                encode_private_session_browser_v04(browser).map_err(invalid_request)?,
            )?;
            decode_handoff(response.body())
        })();
        match result {
            Ok(pending) => {
                self.pending = pending;
                Ok(pending.is_some())
            }
            Err(error) => {
                self.close();
                Err(error)
            }
        }
    }

    /// Separate display authentication, explicit user choice, then separate
    /// hardware-signed exact action decision. Never execute a tool from Python.
    pub fn review_pending(&mut self, approval: &dyn ApprovalCallback) -> Result<bool, SavanaError> {
        self.browser.ok_or(SavanaError::InvalidState)?;
        let transfer = self.pending.take().ok_or(SavanaError::InvalidState)?;
        let result = self.review(transfer, approval);
        if result.is_err() {
            // An uncertain decision is NOT rollback. No automatic retry or
            // reauthentication that could silently create another ceremony.
            self.close();
        }
        result
    }

    /// Forget only local capabilities. This does NOT revoke root authority,
    /// cancel the kernel run, refund budget, or revoke a signed decision.
    pub fn close(&mut self) {
        self.browser = None;
        self.pending = None;
        self.publication = None;
    }

    fn assert(&self, options: &[u8]) -> Result<BrowserWebAuthnAssertionV2, SavanaError> {
        let assertion = self.webauthn.assert_credential(options)?;
        if assertion.credential_id() != self.credential_id.as_slice() {
            return Err(AuthError::AuthenticationFailed.into());
        }
        Ok(assertion.into_protocol())
    }

    fn send(&self, route: BrowserRoute, body: Vec<u8>) -> Result<BrowserResponse, SavanaError> {
        send(self.transport.as_ref(), route, body)
    }

    fn review(
        &self,
        transfer: ApprovalDisplayAuthenticationTransferCapabilityV2,
        approval: &dyn ApprovalCallback,
    ) -> Result<bool, SavanaError> {
        let accepted = self.send(
            BrowserRoute::PrivateApprovalAcceptV04,
            form_transfer(transfer)?,
        )?;
        let attributes = extract_main_data_attributes(
            accepted.body(),
            &[("data-purpose", 32), ("data-pre-authentication", 128)],
        )?;
        if attributes[0] != "approval-display" {
            return Err(SavanaError::InvalidResponse);
        }
        let pre_authentication = decode_capability_attribute(&attributes[1], 32)?;
        let nonce = self.nonces.nonce()?;
        let begun = self.send(
            BrowserRoute::ApprovalUiAuthenticationBegin,
            encode_ui_authentication_browser_begin_request_v2(
                UiAuthenticationBrowserBeginRequestV2::ApprovalDisplay {
                    pre_authentication,
                    client_request_nonce: nonce,
                },
            )
            .map_err(invalid_request)?,
        )?;
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
        let finished = self.send(
            BrowserRoute::ApprovalUiAuthenticationFinish,
            encode_ui_authentication_browser_finish_request_v2(
                &UiAuthenticationBrowserFinishRequestV2::ApprovalDisplay {
                    ceremony,
                    client_request_nonce: nonce,
                    assertion: self.assert(&options)?,
                },
            )
            .map_err(invalid_request)?,
        )?;
        let tab = match decode_ui_authentication_browser_finish_response_v2(finished.body())
            .map_err(|_| SavanaError::InvalidResponse)?
        {
            UiAuthenticationBrowserFinishResponseV2::ApprovalDisplayReady { tab } => tab,
            _ => return Err(SavanaError::InvalidResponse),
        };
        let displayed = self.send(
            BrowserRoute::ApprovalDisplay,
            encode_approval_display_browser_request_v2(ApprovalDisplayBrowserRequestV2::new(tab))
                .map_err(invalid_request)?,
        )?;
        let view = decode_approval_display_view_v2(displayed.body())
            .map_err(|_| SavanaError::InvalidResponse)?;
        let purpose = match view.purpose() {
            ApprovalPurposeV2::ToolExecution => ApprovalPurpose::ToolExecution,
            ApprovalPurposeV2::FinalRelease => ApprovalPurpose::FinalRelease,
            _ => return Err(SavanaError::InvalidResponse),
        };
        let approve = approval.decide(&ApprovalRequest {
            display: view.display_text().as_str().to_owned(),
            purpose,
        })?;
        let nonce = self.nonces.nonce()?;
        let begun = self.send(
            BrowserRoute::ApprovalDecisionBegin,
            encode_approval_decision_browser_begin_request_v2(
                ApprovalDecisionBrowserBeginRequestV2::new(
                    tab,
                    nonce,
                    if approve {
                        ApprovalDecisionV2::Approve
                    } else {
                        ApprovalDecisionV2::Deny
                    },
                )
                .map_err(invalid_request)?,
            )
            .map_err(invalid_request)?,
        )?;
        let (ceremony, options) = decode_approval_decision_browser_begin_response_v2(begun.body())
            .map_err(|_| SavanaError::InvalidResponse)?
            .into_parts();
        let finished = self.send(
            BrowserRoute::ApprovalDecisionFinish,
            encode_approval_decision_browser_finish_request_v2(
                &ApprovalDecisionBrowserFinishRequestV2::new(
                    ceremony,
                    nonce,
                    self.assert(&options)?,
                )
                .map_err(invalid_request)?,
            )
            .map_err(invalid_request)?,
        )?;
        match decode_approval_decision_browser_finish_response_v2(finished.body())
            .map_err(|_| SavanaError::InvalidResponse)?
        {
            ApprovalDecisionBrowserFinishResponseV2::Approved if approve => Ok(true),
            ApprovalDecisionBrowserFinishResponseV2::Denied => Ok(false),
            _ => Err(SavanaError::InvalidResponse),
        }
    }
}

fn invalid_request(_: impl core::fmt::Debug) -> SavanaError {
    SavanaError::InvalidRequest
}

fn send(
    transport: &dyn BrowserTransport,
    route: BrowserRoute,
    body: Vec<u8>,
) -> Result<BrowserResponse, SavanaError> {
    let request = BrowserRequest {
        service: BrowserService::Approval,
        route,
        origin: BrowserOrigin::Approval,
        content_type: if route == BrowserRoute::PrivateApprovalAcceptV04 {
            BrowserContentType::FormUrlEncoded
        } else {
            BrowserContentType::CanonicalCbor
        },
        body,
    };
    request.validate()?;
    let response = transport.send(request)?;
    if response.content_type() != route.response_content_type() {
        return Err(SavanaError::InvalidResponse);
    }
    Ok(response)
}

fn parse_transfer(token: &str) -> Result<PrivateSessionTransferV04, SavanaError> {
    if token.len() != 43 {
        return Err(SavanaError::InvalidRequest);
    }
    let bytes = URL_SAFE_NO_PAD.decode(token).map_err(invalid_request)?;
    if URL_SAFE_NO_PAD.encode(&bytes) != token {
        return Err(SavanaError::InvalidRequest);
    }
    PrivateSessionTransferV04::from_authority_entropy(bytes.try_into().map_err(invalid_request)?)
        .ok_or(SavanaError::InvalidRequest)
}

fn decode_options(bytes: &[u8]) -> Result<Vec<u8>, SavanaError> {
    if bytes.len() > 8200 {
        return Err(SavanaError::InvalidResponse);
    }
    let mut d = minicbor::Decoder::new(bytes);
    let invalid = |_| SavanaError::InvalidResponse;
    if d.array().map_err(invalid)? != Some(2) || d.u16().map_err(invalid)? != 4 {
        return Err(SavanaError::InvalidResponse);
    }
    let options = d.bytes().map_err(invalid)?.to_vec();
    if encode_private_session_options_v04(&options).map_err(|_| SavanaError::InvalidResponse)?
        != bytes
    {
        return Err(SavanaError::InvalidResponse);
    }
    Ok(options)
}

fn encode_finish(
    transfer: PrivateSessionTransferV04,
    a: &BrowserWebAuthnAssertionV2,
) -> Result<Vec<u8>, SavanaError> {
    let mut e = minicbor::Encoder::new(Vec::new());
    e.array(3).and_then(|e| e.u16(4)).map_err(invalid_request)?;
    transfer.encode(&mut e, &mut ()).map_err(invalid_request)?;
    e.array(5).map_err(invalid_request)?;
    for field in [
        a.credential_id(),
        a.authenticator_data(),
        a.client_data_json(),
        a.signature(),
        a.user_handle(),
    ] {
        e.bytes(field).map_err(invalid_request)?;
    }
    let bytes = e.into_writer();
    decode_private_session_finish_v04(&bytes).map_err(invalid_request)?;
    Ok(bytes)
}

fn decode_handoff(
    bytes: &[u8],
) -> Result<Option<ApprovalDisplayAuthenticationTransferCapabilityV2>, SavanaError> {
    if bytes.len() > 128 {
        return Err(SavanaError::InvalidResponse);
    }
    let mut d = minicbor::Decoder::new(bytes);
    let invalid = |_| SavanaError::InvalidResponse;
    if d.array().map_err(invalid)? != Some(2) || d.u16().map_err(invalid)? != 4 {
        return Err(SavanaError::InvalidResponse);
    }
    let handoff = if d.datatype().map_err(invalid)? == minicbor::data::Type::Null {
        d.null().map_err(invalid)?;
        None
    } else {
        Some(
            ApprovalDisplayAuthenticationTransferCapabilityV2::decode(&mut d, &mut ())
                .map_err(invalid)?,
        )
    };
    if encode_private_session_handoff_v04(handoff).map_err(|_| SavanaError::InvalidResponse)?
        != bytes
    {
        return Err(SavanaError::InvalidResponse);
    }
    Ok(handoff)
}

#[cfg(test)]
#[path = "private_v04_tests.rs"]
mod tests;
