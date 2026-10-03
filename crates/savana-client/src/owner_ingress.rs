//! Trusted owner intake, with no Agent session, file API or model/tool API.
//! The caller supplies a kernel-issued bootstrap and an interactive WebAuthn
//! provider. Browser enrollment is sufficient: no invented SDK Identity file.
use std::sync::Arc;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use savana_kernel_protocol::v2::*;
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use crate::approval::{
    parse_ingress_authentication_form, parse_ingress_workspace, ApprovalFlow, ApprovalOutcome,
};
use crate::auth::{decode_capability_attribute, extract_main_data_attributes, form_transfer};
use crate::task_authorization::issuance_request_digest;
use crate::{
    ApprovalCallback, ApprovalDenied, ApprovalPurpose, AuthError, BrowserContentType,
    BrowserOrigin, BrowserRequest, BrowserResponse, BrowserRoute, BrowserService, Client,
    SavanaError, TaskAuthorizationDraft, TaskAuthorizationReceipt, WebAuthnAssertion,
    WebAuthnAttestation, WebAuthnProvider,
};

/// Deliberately limited to one small user-entered text, not file ingestion.
pub const MAX_OWNER_TEXT_BYTES: usize = 64 * 1024;

pub struct OwnerIngress {
    client: Client,
    webauthn: Arc<PinnedCredential>,
    tab: Option<IngressTabSessionCapabilityV2>,
    committed: bool,
    authorized: bool,
}

impl core::fmt::Debug for OwnerIngress {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("OwnerIngress(<private-owner>)")
    }
}

struct PinnedCredential {
    provider: Arc<dyn WebAuthnProvider>,
    credential_id: Zeroizing<Vec<u8>>,
}
impl WebAuthnProvider for PinnedCredential {
    fn assert_credential(&self, options: &[u8]) -> Result<WebAuthnAssertion, AuthError> {
        let assertion = self.provider.assert_credential(options)?;
        if assertion.credential_id() != self.credential_id.as_slice() {
            return Err(AuthError::AuthenticationFailed);
        }
        Ok(assertion)
    }
    fn create_credential(&self, _: &[u8]) -> Result<WebAuthnAttestation, AuthError> {
        Err(AuthError::EnrollmentFailed)
    }
}

fn send(client: &Client, request: BrowserRequest) -> Result<BrowserResponse, SavanaError> {
    request.validate()?;
    let expected = request.route.response_content_type();
    let response = client.transport.send(request)?;
    if response.content_type() != expected {
        return Err(SavanaError::InvalidResponse);
    }
    Ok(response)
}

impl Client {
    /// Consume a raw canonical base64url kernel Ingress bootstrap, NOT a URL,
    /// enrollment code, Agent transfer, or browser-scraped tab. The server
    /// verifies the discoverable credential against the task's expected owner.
    /// This authenticates only; it never creates a root or approves an action.
    pub fn owner_ingress(
        &self,
        bootstrap: &str,
        webauthn: Arc<dyn WebAuthnProvider>,
    ) -> Result<OwnerIngress, SavanaError> {
        if bootstrap.len() != 43 {
            return Err(SavanaError::InvalidRequest);
        }
        let raw = URL_SAFE_NO_PAD
            .decode(bootstrap)
            .map_err(|_| SavanaError::InvalidRequest)?;
        if URL_SAFE_NO_PAD.encode(&raw) != bootstrap {
            return Err(SavanaError::InvalidRequest);
        }
        let bootstrap = KernelIngressBootstrapTransferCapabilityV2::from_authority_entropy(
            raw.try_into().map_err(|_| SavanaError::InvalidRequest)?,
        )
        .ok_or(SavanaError::InvalidRequest)?;
        let prepared = send(
            self,
            BrowserRequest {
                service: BrowserService::Ingress,
                route: BrowserRoute::IngressBootstrapAccept,
                origin: BrowserOrigin::Jarvis,
                content_type: BrowserContentType::FormUrlEncoded,
                body: form_transfer(bootstrap)?,
            },
        )?;
        let transfer = parse_ingress_authentication_form(prepared.body())?;
        let accepted = send(
            self,
            BrowserRequest {
                service: BrowserService::Approval,
                route: BrowserRoute::ApprovalUiAuthenticationAccept,
                origin: BrowserOrigin::Ingress,
                content_type: BrowserContentType::FormUrlEncoded,
                body: form_transfer(transfer)?,
            },
        )?;
        let attrs = extract_main_data_attributes(
            accepted.body(),
            &[("data-purpose", 32), ("data-pre-authentication", 128)],
        )?;
        if attrs[0] != "ingress" {
            return Err(SavanaError::InvalidResponse);
        }
        let pre_authentication = decode_capability_attribute(&attrs[1], 32)?;
        let nonce = self.next_nonce()?;
        let begun = send(
            self,
            BrowserRequest {
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
            },
        )?;
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
        let assertion = webauthn.assert_credential(&options)?;
        let credential_id = Zeroizing::new(assertion.credential_id().to_vec());
        let finished = send(
            self,
            BrowserRequest {
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
            },
        )?;
        let settlement = match decode_ui_authentication_browser_finish_response_v2(finished.body())
            .map_err(|_| SavanaError::InvalidResponse)?
        {
            UiAuthenticationBrowserFinishResponseV2::TransferToIngress {
                return_origin: FixedOriginV2::Ingress8767,
                transfer,
            } => transfer,
            _ => return Err(SavanaError::InvalidResponse),
        };
        let completed = send(
            self,
            BrowserRequest {
                service: BrowserService::Ingress,
                route: BrowserRoute::IngressUiAuthenticationComplete,
                origin: BrowserOrigin::Approval,
                content_type: BrowserContentType::FormUrlEncoded,
                body: form_transfer(settlement)?,
            },
        )?;
        Ok(OwnerIngress {
            client: Client::with_transport_and_nonce_source(
                self.endpoints.clone(),
                self.transport.clone(),
                self.nonces.clone(),
            ),
            webauthn: Arc::new(PinnedCredential {
                provider: webauthn,
                credential_id,
            }),
            tab: Some(parse_ingress_workspace(completed.body())?),
            committed: false,
            authorized: false,
        })
    }
}

impl OwnerIngress {
    fn tab(&self) -> Result<IngressTabSessionCapabilityV2, SavanaError> {
        self.tab.ok_or(SavanaError::InvalidState)
    }

    fn request(
        &self,
        route: BrowserRoute,
        request: IngressBrowserRequestV2,
    ) -> Result<BrowserResponse, SavanaError> {
        send(
            &self.client,
            BrowserRequest {
                service: BrowserService::Ingress,
                route,
                origin: BrowserOrigin::Ingress,
                content_type: BrowserContentType::CanonicalCbor,
                body: encode_ingress_browser_request_v2(&request)
                    .map_err(|_| SavanaError::InvalidRequest)?,
            },
        )
    }

    fn mutate(
        &self,
        route: BrowserRoute,
        request: IngressBrowserRequestV2,
    ) -> Result<IngressBrowserMutationResponseV2, SavanaError> {
        decode_ingress_browser_mutation_response_v2(self.request(route, request)?.body())
            .map_err(|_| SavanaError::InvalidResponse)
    }

    fn approve(
        &self,
        transfer: ApprovalDisplayAuthenticationTransferCapabilityV2,
        purpose: ApprovalPurposeV2,
        public: ApprovalPurpose,
        callback: &dyn ApprovalCallback,
    ) -> Result<ApprovalOutcome, SavanaError> {
        ApprovalFlow {
            send: &mut |request| send(&self.client, request),
            nonces: self.client.nonces.as_ref(),
            webauthn: self.webauthn.as_ref(),
            tab: &mut None,
        }
        .run(transfer, BrowserOrigin::Ingress, purpose, public, callback)
    }

    fn settle<T>(&mut self, result: Result<T, SavanaError>) -> Result<T, SavanaError> {
        if result.is_err() {
            self.close();
        }
        result
    }

    /// Owner-only context. It is not a grant and must not be exposed to a model.
    pub fn task_authorization_context(
        &mut self,
    ) -> Result<TaskAuthorizationContextV2, SavanaError> {
        let tab = self.tab()?;
        let result = (|| {
            let response = self.request(
                BrowserRoute::IngressTaskContext,
                IngressBrowserRequestV2::GetTaskAuthorizationContext {
                    tab,
                    client_request_nonce: self.client.next_nonce()?,
                },
            )?;
            decode_task_authorization_context_v2(response.body())
                .map_err(|_| SavanaError::InvalidResponse)
        })();
        self.settle(result)
    }

    /// Submit one user-entered text with a separate signed input approval.
    /// Success means input committed, NOT task authorized or executed.
    pub fn commit_text(
        &mut self,
        text: &str,
        approval: &dyn ApprovalCallback,
    ) -> Result<(), SavanaError> {
        let tab = self.tab()?;
        if self.committed || text.is_empty() || text.len() > MAX_OWNER_TEXT_BYTES {
            return Err(SavanaError::InvalidRequest);
        }
        let digest = Digest32V2::new(Sha256::digest(text.as_bytes()).into());
        let result = (|| {
            let begun = self.mutate(
                BrowserRoute::IngressInputBegin,
                IngressBrowserRequestV2::Begin {
                    tab,
                    client_request_nonce: self.client.next_nonce()?,
                    content_kind: ContentKindV2::ChatText,
                    declared_total_bytes: text.len() as u64,
                    declared_content_digest: Some(digest),
                },
            )?;
            if !matches!(
                begun,
                IngressBrowserMutationResponseV2::Begun { next_sequence: 0 }
            ) {
                return Err(SavanaError::InvalidResponse);
            }
            let appended = self.mutate(
                BrowserRoute::IngressInputChunk,
                IngressBrowserRequestV2::Append {
                    tab,
                    client_request_nonce: self.client.next_nonce()?,
                    sequence: 0,
                    chunk: ZeroizingBytesV2::new(text.as_bytes().to_vec())
                        .map_err(|_| SavanaError::InvalidRequest)?,
                },
            )?;
            // The cumulative digest commits to the private input session, channel,
            // sequence and chunk chain. Only ingress/kernel have that session;
            // it is NOT the SHA-256 of the plaintext. They verify the chain, while
            // Begin/Finalize bind our plaintext digest and separate signed approval.
            if !matches!(
                appended,
                IngressBrowserMutationResponseV2::ChunkAccepted {
                    acknowledged_sequence: 0,
                    ..
                }
            ) {
                return Err(SavanaError::InvalidResponse);
            }
            let finalize = || {
                self.mutate(
                    BrowserRoute::IngressInputFinalize,
                    IngressBrowserRequestV2::Finalize {
                        tab,
                        client_request_nonce: self.client.next_nonce()?,
                        declared_content_digest: digest,
                    },
                )
            };
            let transfer = match finalize()? {
                IngressBrowserMutationResponseV2::FinalizeOpenApproval { transfer } => transfer,
                _ => return Err(SavanaError::InvalidResponse),
            };
            let outcome = self.approve(
                transfer,
                ApprovalPurposeV2::Ingress,
                ApprovalPurpose::Ingress,
                approval,
            )?;
            match (outcome, finalize()?) {
                (
                    ApprovalOutcome::Approved,
                    IngressBrowserMutationResponseV2::FinalizeCommitted {
                        state: InputPublicStateV2::CommittedUnclaimed,
                    },
                ) => Ok(()),
                (
                    ApprovalOutcome::Denied,
                    IngressBrowserMutationResponseV2::FinalizeRejected {
                        state: InputPublicStateV2::Denied,
                    },
                ) => Err(ApprovalDenied.into()),
                _ => Err(SavanaError::InvalidResponse),
            }
        })();
        self.settle(result)?;
        self.committed = true;
        Ok(())
    }

    /// A typed draft is untrusted. Only the kernel's exact, hardware-signed
    /// task approval and matching commit receipt establish authorization.
    pub fn approve_task_authorization(
        &mut self,
        draft: &TaskAuthorizationDraft,
        approval: &dyn ApprovalCallback,
    ) -> Result<TaskAuthorizationReceipt, SavanaError> {
        let tab = self.tab()?;
        if !self.committed || self.authorized {
            return Err(SavanaError::InvalidState);
        }
        let result = (|| {
            let nonce = self.client.next_nonce()?;
            let expected = issuance_request_digest(&draft.material, nonce);
            let response = self.mutate(
                BrowserRoute::IngressTaskApprovalPrepare,
                IngressBrowserRequestV2::PrepareTaskAuthorizationApproval {
                    tab,
                    client_request_nonce: nonce,
                    draft: draft.material.clone(),
                },
            )?;
            let transfer = match response {
                IngressBrowserMutationResponseV2::TaskAuthorizationOpenApproval {
                    request_digest,
                    transfer,
                } if request_digest == expected => transfer,
                _ => return Err(SavanaError::InvalidResponse),
            };
            if self.approve(
                transfer,
                ApprovalPurposeV2::TaskAuthorization,
                ApprovalPurpose::TaskAuthorization,
                approval,
            )? != ApprovalOutcome::Approved
            {
                return Err(ApprovalDenied.into());
            }
            match self.mutate(
                BrowserRoute::IngressTaskApprovalCommit,
                IngressBrowserRequestV2::CommitTaskAuthorizationApproval {
                    tab,
                    client_request_nonce: self.client.next_nonce()?,
                    request_digest: expected,
                },
            )? {
                IngressBrowserMutationResponseV2::TaskAuthorizationEstablished {
                    request_digest,
                    authorization_digest,
                } if request_digest == expected => Ok(TaskAuthorizationReceipt {
                    request: *request_digest.as_bytes(),
                    authorization: *authorization_digest.as_bytes(),
                }),
                IngressBrowserMutationResponseV2::TaskAuthorizationRejected => {
                    Err(ApprovalDenied.into())
                }
                _ => Err(SavanaError::InvalidResponse),
            }
        })();
        let receipt = self.settle(result)?;
        self.authorized = true;
        Ok(receipt)
    }

    /// One-way handoff. An installed signed private plan is still required by
    /// the kernel. No fallback to Agent, automatic retry or capability export.
    pub fn into_private_session(
        &mut self,
    ) -> Result<crate::private_v04::PrivateSession, SavanaError> {
        let tab = self.tab()?;
        if !self.committed || !self.authorized {
            return Err(SavanaError::InvalidState);
        }
        self.tab = None;
        self.client.private_session_for_owner_tab(
            tab,
            &self.webauthn.credential_id,
            self.webauthn.clone(),
        )
    }

    /// Local cleanup only. Does not undo input, revoke a root or refund budget.
    pub fn close(&mut self) {
        self.tab = None;
    }
}
