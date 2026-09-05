//! Data-only task-contract transport. This module has no signing key, verified
//! evidence constructor, or ability to upgrade a planner draft into authority.
use savana_kernel_protocol::v2::*;
use sha2::{Digest as _, Sha256};

use crate::approval::ApprovalOutcome;
use crate::session::LocalSessionState;
use crate::{
    ApprovalCallback, ApprovalDenied, ApprovalPurpose, BrowserOrigin, BrowserRoute, SavanaError,
    Session,
};

#[derive(Clone)]
pub struct TaskAuthorizationDraft {
    material: TaskAuthorizationDraftV2,
    canonical: Vec<u8>,
}
impl TaskAuthorizationDraft {
    /// Parses an untrusted proposal, not a signed authorization. Unknown schemas,
    /// extra bytes and unsupported control grammars are refused before transport.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, SavanaError> {
        let material =
            decode_task_authorization_draft_v2(bytes).map_err(|_| SavanaError::InvalidRequest)?;
        Ok(Self {
            material,
            canonical: bytes.to_vec(),
        })
    }
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical
    }
}
impl std::fmt::Debug for TaskAuthorizationDraft {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TaskAuthorizationDraft(<untrusted, redacted>)")
    }
}

/// An observation of a kernel receipt, never a portable grant or execution ticket.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TaskAuthorizationReceipt {
    request: [u8; 32],
    authorization: [u8; 32],
}
impl TaskAuthorizationReceipt {
    pub fn request_digest(&self) -> &[u8; 32] {
        &self.request
    }
    pub fn authorization_digest(&self) -> &[u8; 32] {
        &self.authorization
    }
}
impl std::fmt::Debug for TaskAuthorizationReceipt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TaskAuthorizationReceipt(<observation>)")
    }
}

impl Session {
    /// Explicit structured-input submission on the current authenticated ingress
    /// tab. The native input owner authenticates the exact finalized input; the
    /// SDK does not infer a contract from ordinary chat or planner output.
    pub fn establish_task_authorization(
        &mut self,
        draft: &TaskAuthorizationDraft,
    ) -> Result<TaskAuthorizationReceipt, SavanaError> {
        let tab = self.task_ingress_tab()?;
        let nonce = self.nonces.nonce()?;
        let expected = issuance_request_digest(&draft.material, nonce);
        let response = self.task_mutation(
            BrowserRoute::IngressTaskEstablish,
            IngressBrowserRequestV2::EstablishTaskAuthorization {
                tab,
                client_request_nonce: nonce,
                draft: draft.material.clone(),
            },
        )?;
        self.task_receipt(response, expected)
    }

    /// Independent task-level consent, distinct from consent to one tool action.
    /// Returning true from a callback is insufficient: the existing authenticated
    /// UI/credential ceremony and the kernel's exact settlement checks still run.
    pub fn approve_task_authorization(
        &mut self,
        draft: &TaskAuthorizationDraft,
        approval: &dyn ApprovalCallback,
    ) -> Result<TaskAuthorizationReceipt, SavanaError> {
        let tab = self.task_ingress_tab()?;
        let nonce = self.nonces.nonce()?;
        let expected = issuance_request_digest(&draft.material, nonce);
        let opened = self.task_mutation(
            BrowserRoute::IngressTaskApprovalPrepare,
            IngressBrowserRequestV2::PrepareTaskAuthorizationApproval {
                tab,
                client_request_nonce: nonce,
                draft: draft.material.clone(),
            },
        )?;
        let transfer = match opened {
            IngressBrowserMutationResponseV2::TaskAuthorizationOpenApproval {
                request_digest,
                transfer,
            } if request_digest == expected => transfer,
            _ => return self.invalid_task_response(),
        };
        let outcome = match self.run_approval(
            transfer,
            BrowserOrigin::Ingress,
            ApprovalPurposeV2::TaskAuthorization,
            ApprovalPurpose::TaskAuthorization,
            approval,
        ) {
            Ok(outcome) => outcome,
            Err(e) => {
                self.state = LocalSessionState::Closed;
                return Err(e);
            }
        };
        if outcome == ApprovalOutcome::Denied {
            return Err(ApprovalDenied.into());
        }
        let committed = self.task_mutation(
            BrowserRoute::IngressTaskApprovalCommit,
            IngressBrowserRequestV2::CommitTaskAuthorizationApproval {
                tab,
                client_request_nonce: self.nonces.nonce()?,
                request_digest: expected,
            },
        )?;
        self.task_receipt(committed, expected)
    }

    /// Removes the exact current task authorization. It cannot mint a replacement
    /// or reset consumption. The return value is only the revoked root's digest.
    pub fn revoke_task_authorization(
        &mut self,
        draft: &TaskAuthorizationDraft,
    ) -> Result<[u8; 32], SavanaError> {
        let tab = self.task_ingress_tab()?;
        let response = self.task_mutation(
            BrowserRoute::IngressTaskRevoke,
            IngressBrowserRequestV2::RevokeTaskAuthorization {
                tab,
                client_request_nonce: self.nonces.nonce()?,
                draft: draft.material.clone(),
            },
        )?;
        match response {
            IngressBrowserMutationResponseV2::TaskAuthorizationRevoked {
                authorization_digest,
            } => Ok(*authorization_digest.as_bytes()),
            _ => self.invalid_task_response(),
        }
    }

    fn task_ingress_tab(&self) -> Result<IngressTabSessionCapabilityV2, SavanaError> {
        self.require_open()?;
        self.ingress
            .as_ref()
            .map(|t| t.tab)
            .ok_or(SavanaError::InvalidState)
    }
    fn task_mutation(
        &mut self,
        route: BrowserRoute,
        request: IngressBrowserRequestV2,
    ) -> Result<IngressBrowserMutationResponseV2, SavanaError> {
        match self.ingress_mutation(route, request) {
            Ok(r) => Ok(r),
            Err(e) => {
                self.state = LocalSessionState::Closed;
                Err(e)
            }
        }
    }
    fn task_receipt(
        &mut self,
        response: IngressBrowserMutationResponseV2,
        expected: Digest32V2,
    ) -> Result<TaskAuthorizationReceipt, SavanaError> {
        match response {
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
            _ => self.invalid_task_response(),
        }
    }
    fn invalid_task_response<T>(&mut self) -> Result<T, SavanaError> {
        self.state = LocalSessionState::Closed;
        Err(SavanaError::InvalidResponse)
    }
}

fn issuance_request_digest(d: &TaskAuthorizationDraftV2, nonce: Nonce32V2) -> Digest32V2 {
    let mut h = Sha256::new();
    h.update(b"SAVANA_TASK_ISSUANCE_REQUEST_V2_SCHEMA1\0");
    for b in [
        d.installation_digest().as_bytes(),
        d.task().as_bytes(),
        d.principal().as_bytes(),
        nonce.as_bytes(),
    ] {
        h.update((b.len() as u64).to_be_bytes());
        h.update(b);
    }
    Digest32V2::new(h.finalize().into())
}
