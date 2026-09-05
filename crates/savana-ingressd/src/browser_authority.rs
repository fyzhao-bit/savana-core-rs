use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use savana_approvald::{ApprovalSuiteOneClientErrorV2, ApprovalSuiteOneClientV2};
use savana_kernel_protocol::v2::{
    input_channel_begin_digest_v2, input_channel_step_digest_v2, input_chunk_digest_v2,
    AbortInputRequestV2, AppendInputChunkRequestV2, AppendParserWorkerPageFrameRequestV2,
    ApprovalDisplayAuthenticationTransferCapabilityV2, ApprovalSettlementViewV2,
    AuthenticateIngressUiRequestV2, BeginInputRequestV2, CommitInputSettlementRequestV2,
    CommitParserWorkerResultRequestV2, ContentKindV2, Digest32V2, DirectInputChannelV2,
    FinalizeInputRequestV2, IngressApprovalRecordHandleV2, IngressBrowserMutationResponseV2,
    IngressBrowserRequestV2, IngressKernelApprovalHandleV2, IngressTabSessionCapabilityV2,
    IngressUiAuthenticationPreparationHandleV2,
    IngressUiAuthenticationSettlementTransferCapabilityV2,
    IngressUiAuthenticationTransferCapabilityV2, IngressWriteCapabilityV2,
    InputChannelCommitmentV2, InputChannelV2, InputPublicStateV2, InputSessionHandleV2,
    InputSourceKindV2, InputSourceProvenanceV2, KernelIngressBootstrapTransferCapabilityV2,
    PendingIngressHandleV2, PrepareIngressUiAuthenticationRequestV2,
    RegisterParserWorkerJobRequestV2, RegisteredApprovalV2, RegisteredUiAuthenticationV2,
    UnixMillisV2, VersionV2, ZeroizingBytesV2,
};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use crate::protocol_parser::{ProtocolParserErrorV2, ProtocolParserRuntimeV2};
use crate::{IngressKernelClientErrorV2, SuiteOneIngressKernelClientV2};

const MAX_PENDING_AUTHENTICATIONS_V2: usize = 128;
const MAX_TABS_V2: usize = 128;
const MAX_REPLAYS_PER_TAB_V2: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum IngressBrowserAuthorityErrorV2 {
    #[error("ingress browser reference is invalid")]
    InvalidReference,
    #[error("ingress browser request conflicts with prior state")]
    StateConflict,
    #[error("ingress browser request deadline was exceeded")]
    DeadlineExceeded,
    #[error("ingress browser service is busy")]
    Busy,
    #[error("ingress browser service is unavailable")]
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PreparedBrowserAuthenticationV2 {
    transfer: IngressUiAuthenticationTransferCapabilityV2,
}

impl PreparedBrowserAuthenticationV2 {
    pub const fn transfer(self) -> IngressUiAuthenticationTransferCapabilityV2 {
        self.transfer
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PendingAuthenticationV2 {
    bootstrap_transfer: KernelIngressBootstrapTransferCapabilityV2,
    preparation: IngressUiAuthenticationPreparationHandleV2,
    approval_record: savana_kernel_protocol::v2::ApprovalUiRecordHandleV2,
    browser_transfer: IngressUiAuthenticationTransferCapabilityV2,
    completed_transfer: Option<IngressUiAuthenticationSettlementTransferCapabilityV2>,
    tab: Option<IngressTabSessionCapabilityV2>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ReplayV2 {
    nonce: savana_kernel_protocol::v2::Nonce32V2,
    request_digest: Digest32V2,
    response: IngressBrowserMutationResponseV2,
}

#[derive(Clone)]
struct ActiveInputV2 {
    session: InputSessionHandleV2,
    writer: IngressWriteCapabilityV2,
    content_kind: ContentKindV2,
    direct_channel: DirectInputChannelV2,
    commitment_channel: InputChannelV2,
    declared_total_bytes: u64,
    declared_content_digest: Option<Digest32V2>,
    next_sequence: u32,
    cumulative_digest: Digest32V2,
    total_length: u64,
    content_hasher: Sha256,
    parser_job_session_binding_digest: Digest32V2,
    original_bytes: Zeroizing<Vec<u8>>,
    approval: Option<PendingInputApprovalV2>,
}

#[derive(Debug, Clone, Copy)]
struct PendingInputApprovalV2 {
    pending: PendingIngressHandleV2,
    kernel_approval: IngressKernelApprovalHandleV2,
    approval_record: IngressApprovalRecordHandleV2,
    display_transfer: ApprovalDisplayAuthenticationTransferCapabilityV2,
}

impl core::fmt::Debug for ActiveInputV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ActiveInputV2")
            .field("session", &self.session)
            .field("content_kind", &self.content_kind)
            .field("next_sequence", &self.next_sequence)
            .field("total_length", &self.total_length)
            .field("approval_pending", &self.approval.is_some())
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
struct TabV2 {
    tab: IngressTabSessionCapabilityV2,
    authorization: savana_kernel_protocol::v2::IngressUiAuthorizationHandleV2,
    input: Option<ActiveInputV2>,
    replays: Vec<ReplayV2>,
    mutation_in_flight: bool,
    finalized_session: Option<InputSessionHandleV2>,
    task_approvals: Vec<PendingTaskApprovalV2>,
}

#[derive(Debug, Clone, Copy)]
struct PendingTaskApprovalV2 {
    request_digest: Digest32V2,
    approval: savana_kernel_protocol::v2::TaskAuthorizationApprovalRecordHandleV2,
    transfer: ApprovalDisplayAuthenticationTransferCapabilityV2,
}

pub struct IngressBrowserAuthorityV2 {
    kernel: SuiteOneIngressKernelClientV2,
    approval: ApprovalSuiteOneClientV2,
    parser: Option<Arc<ProtocolParserRuntimeV2>>,
    pending: Mutex<Vec<PendingAuthenticationV2>>,
    tabs: Mutex<Vec<TabV2>>,
}

impl core::fmt::Debug for IngressBrowserAuthorityV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("IngressBrowserAuthorityV2")
            .finish_non_exhaustive()
    }
}

impl IngressBrowserAuthorityV2 {
    pub fn new(kernel: SuiteOneIngressKernelClientV2, approval: ApprovalSuiteOneClientV2) -> Self {
        Self {
            kernel,
            approval,
            parser: None,
            pending: Mutex::new(Vec::new()),
            tabs: Mutex::new(Vec::new()),
        }
    }

    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn with_verified_parser(mut self, parser: ProtocolParserRuntimeV2) -> Self {
        self.parser = Some(Arc::new(parser));
        self
    }

    pub fn prepare_authentication(
        &self,
        transfer: KernelIngressBootstrapTransferCapabilityV2,
        deadline: UnixMillisV2,
    ) -> Result<PreparedBrowserAuthenticationV2, IngressBrowserAuthorityErrorV2> {
        {
            let pending = self
                .pending
                .lock()
                .map_err(|_| IngressBrowserAuthorityErrorV2::Unavailable)?;
            if let Some(existing) = pending
                .iter()
                .find(|record| record.bootstrap_transfer == transfer)
            {
                return Ok(PreparedBrowserAuthenticationV2 {
                    transfer: existing.browser_transfer,
                });
            }
        }
        let prepared = self
            .kernel
            .prepare_ui_authentication(
                PrepareIngressUiAuthenticationRequestV2::new(transfer),
                deadline,
            )
            .map_err(map_kernel)?;
        let registered = self
            .approval
            .register_ui_authentication(prepared.envelope().clone(), deadline)
            .map_err(map_approval)?;
        let (approval_record, browser_transfer) = match registered {
            RegisteredUiAuthenticationV2::Ingress { record, transfer } => (record, transfer),
            RegisteredUiAuthenticationV2::Agent { .. } => {
                return Err(IngressBrowserAuthorityErrorV2::Unavailable)
            }
        };
        let mut pending = self
            .pending
            .lock()
            .map_err(|_| IngressBrowserAuthorityErrorV2::Unavailable)?;
        if pending.len() >= MAX_PENDING_AUTHENTICATIONS_V2 {
            return Err(IngressBrowserAuthorityErrorV2::Busy);
        }
        pending
            .try_reserve(1)
            .map_err(|_| IngressBrowserAuthorityErrorV2::Unavailable)?;
        pending.push(PendingAuthenticationV2 {
            bootstrap_transfer: transfer,
            preparation: prepared.authentication_preparation(),
            approval_record,
            browser_transfer,
            completed_transfer: None,
            tab: None,
        });
        Ok(PreparedBrowserAuthenticationV2 {
            transfer: browser_transfer,
        })
    }

    pub fn complete_authentication(
        &self,
        transfer: IngressUiAuthenticationSettlementTransferCapabilityV2,
        deadline: UnixMillisV2,
    ) -> Result<IngressTabSessionCapabilityV2, IngressBrowserAuthorityErrorV2> {
        {
            let pending = self
                .pending
                .lock()
                .map_err(|_| IngressBrowserAuthorityErrorV2::Unavailable)?;
            if let Some(existing) = pending
                .iter()
                .find(|record| record.completed_transfer == Some(transfer))
            {
                return existing
                    .tab
                    .ok_or(IngressBrowserAuthorityErrorV2::Unavailable);
            }
        }
        let candidates: Vec<_> = self
            .pending
            .lock()
            .map_err(|_| IngressBrowserAuthorityErrorV2::Unavailable)?
            .iter()
            .filter(|record| record.tab.is_none())
            .map(|record| (record.approval_record, record.preparation))
            .collect();
        for (approval_record, preparation) in candidates {
            let consumed = match self.approval.consume_ingress_ui_authentication(
                approval_record,
                transfer,
                deadline,
            ) {
                Ok(value) => value,
                Err(ApprovalSuiteOneClientErrorV2::Rejected(_)) => continue,
                Err(error) => return Err(map_approval(error)),
            };
            let authenticated = self
                .kernel
                .authenticate_ui(
                    AuthenticateIngressUiRequestV2::new(preparation, consumed.settlement().clone())
                        .map_err(|_| IngressBrowserAuthorityErrorV2::Unavailable)?,
                    deadline,
                )
                .map_err(map_kernel)?;
            let tab = IngressTabSessionCapabilityV2::from_authority_entropy(draw_nonzero()?)
                .ok_or(IngressBrowserAuthorityErrorV2::Unavailable)?;
            {
                let mut pending = self
                    .pending
                    .lock()
                    .map_err(|_| IngressBrowserAuthorityErrorV2::Unavailable)?;
                let record = pending
                    .iter_mut()
                    .find(|record| record.approval_record == approval_record)
                    .ok_or(IngressBrowserAuthorityErrorV2::Unavailable)?;
                record.completed_transfer = Some(transfer);
                record.tab = Some(tab);
            }
            let mut tabs = self
                .tabs
                .lock()
                .map_err(|_| IngressBrowserAuthorityErrorV2::Unavailable)?;
            if tabs.len() >= MAX_TABS_V2 {
                return Err(IngressBrowserAuthorityErrorV2::Busy);
            }
            tabs.try_reserve(1)
                .map_err(|_| IngressBrowserAuthorityErrorV2::Unavailable)?;
            tabs.push(TabV2 {
                tab,
                authorization: authenticated.authorization(),
                input: None,
                replays: Vec::new(),
                mutation_in_flight: false,
                finalized_session: None,
                task_approvals: Vec::new(),
            });
            return Ok(tab);
        }
        Err(IngressBrowserAuthorityErrorV2::InvalidReference)
    }

    pub fn mutate(
        &self,
        request: IngressBrowserRequestV2,
        request_digest: Digest32V2,
        deadline: UnixMillisV2,
    ) -> Result<IngressBrowserMutationResponseV2, IngressBrowserAuthorityErrorV2> {
        let tab_handle = request.tab();
        let nonce = request.client_request_nonce();
        {
            let mut tabs = self
                .tabs
                .lock()
                .map_err(|_| IngressBrowserAuthorityErrorV2::Unavailable)?;
            let tab = tabs
                .iter_mut()
                .find(|tab| tab.tab == tab_handle)
                .ok_or(IngressBrowserAuthorityErrorV2::InvalidReference)?;
            if let Some(replay) = tab.replays.iter().find(|replay| replay.nonce == nonce) {
                return if replay.request_digest == request_digest {
                    Ok(replay.response)
                } else {
                    Err(IngressBrowserAuthorityErrorV2::StateConflict)
                };
            }
            if tab.mutation_in_flight {
                return Err(IngressBrowserAuthorityErrorV2::Busy);
            }
            // Reserve replay capacity before any external mutation; never
            // execute and then discover we cannot remember the receipt.
            if tab.replays.len() >= MAX_REPLAYS_PER_TAB_V2 {
                return Err(IngressBrowserAuthorityErrorV2::Busy);
            }
            tab.replays
                .try_reserve(1)
                .map_err(|_| IngressBrowserAuthorityErrorV2::Unavailable)?;
            tab.mutation_in_flight = true;
        }
        let mutation = (|| {
            Ok(match request {
                IngressBrowserRequestV2::GetTaskAuthorizationContext { .. } => {
                    return Err(IngressBrowserAuthorityErrorV2::InvalidReference)
                }
                IngressBrowserRequestV2::Begin {
                    content_kind,
                    declared_total_bytes,
                    declared_content_digest,
                    ..
                } => self.begin_input(
                    tab_handle,
                    content_kind,
                    declared_total_bytes,
                    declared_content_digest,
                    deadline,
                )?,
                IngressBrowserRequestV2::Append {
                    sequence, chunk, ..
                } => self.append_input(tab_handle, sequence, chunk, deadline)?,
                IngressBrowserRequestV2::Finalize {
                    declared_content_digest,
                    ..
                } => self.finalize_input(tab_handle, declared_content_digest, deadline)?,
                IngressBrowserRequestV2::Abort { .. } => self.abort_input(tab_handle, deadline)?,
                IngressBrowserRequestV2::EstablishTaskAuthorization {
                    draft,
                    client_request_nonce,
                    ..
                } => self.submit_task(tab_handle, draft, client_request_nonce, false, deadline)?,
                IngressBrowserRequestV2::PrepareTaskAuthorizationApproval {
                    draft,
                    client_request_nonce,
                    ..
                } => self.submit_task(tab_handle, draft, client_request_nonce, true, deadline)?,
                IngressBrowserRequestV2::CommitTaskAuthorizationApproval {
                    request_digest, ..
                } => self.commit_task(tab_handle, request_digest, deadline)?,
                IngressBrowserRequestV2::RecoverTaskAuthorization { request_digest, .. } => {
                    self.recover_task(tab_handle, request_digest, deadline)?
                }
                IngressBrowserRequestV2::RevokeTaskAuthorization {
                    draft,
                    client_request_nonce,
                    ..
                } => {
                    let session = self
                        .tabs
                        .lock()
                        .map_err(|_| IngressBrowserAuthorityErrorV2::Unavailable)?
                        .iter()
                        .find(|t| t.tab == tab_handle)
                        .and_then(|t| t.finalized_session)
                        .ok_or(IngressBrowserAuthorityErrorV2::StateConflict)?;
                    let request =
                        savana_kernel_protocol::v2::RevokeTaskAuthorizationRequestV2::new(
                            session,
                            draft,
                            client_request_nonce,
                        )
                        .map_err(|_| IngressBrowserAuthorityErrorV2::StateConflict)?;
                    let response = self
                        .kernel
                        .revoke_task_authorization(request, deadline)
                        .map_err(map_kernel)?;
                    IngressBrowserMutationResponseV2::TaskAuthorizationRevoked {
                        authorization_digest: response.authorization_digest(),
                    }
                }
            })
        })();
        let response = match mutation {
            Ok(response) => response,
            Err(error) => {
                self.clear_mutation_in_flight(tab_handle);
                return Err(error);
            }
        };
        let mut tabs = self
            .tabs
            .lock()
            .map_err(|_| IngressBrowserAuthorityErrorV2::Unavailable)?;
        let tab = tabs
            .iter_mut()
            .find(|tab| tab.tab == tab_handle)
            .ok_or(IngressBrowserAuthorityErrorV2::Unavailable)?;
        if tab.replays.len() >= MAX_REPLAYS_PER_TAB_V2 {
            tab.mutation_in_flight = false;
            return Err(IngressBrowserAuthorityErrorV2::Busy);
        }
        if tab.replays.try_reserve(1).is_err() {
            tab.mutation_in_flight = false;
            return Err(IngressBrowserAuthorityErrorV2::Unavailable);
        }
        tab.replays.push(ReplayV2 {
            nonce,
            request_digest,
            response,
        });
        tab.mutation_in_flight = false;
        Ok(response)
    }

    pub fn task_authorization_context(
        &self,
        tab_handle: IngressTabSessionCapabilityV2,
        deadline: UnixMillisV2,
    ) -> Result<
        savana_kernel_protocol::v2::TaskAuthorizationContextV2,
        IngressBrowserAuthorityErrorV2,
    > {
        let request = {
            let tabs = self
                .tabs
                .lock()
                .map_err(|_| IngressBrowserAuthorityErrorV2::Unavailable)?;
            let tab = tabs
                .iter()
                .find(|t| t.tab == tab_handle)
                .ok_or(IngressBrowserAuthorityErrorV2::InvalidReference)?;
            if tab.mutation_in_flight {
                return Err(IngressBrowserAuthorityErrorV2::Busy);
            }
            savana_kernel_protocol::v2::GetTaskAuthorizationContextRequestV2::new(
                tab.authorization,
                tab.finalized_session,
            )
        };
        // Native input owner rechecks current UI authentication. Never return a
        // cached context after expiry, restart, amendment or revocation.
        self.kernel
            .task_authorization_context(request, deadline)
            .map_err(map_kernel)
    }

    fn recover_task(
        &self,
        tab_handle: IngressTabSessionCapabilityV2,
        request_digest: Digest32V2,
        deadline: UnixMillisV2,
    ) -> Result<IngressBrowserMutationResponseV2, IngressBrowserAuthorityErrorV2> {
        let authorization = self
            .tabs
            .lock()
            .map_err(|_| IngressBrowserAuthorityErrorV2::Unavailable)?
            .iter()
            .find(|t| t.tab == tab_handle)
            .ok_or(IngressBrowserAuthorityErrorV2::InvalidReference)?
            .authorization;
        let request = savana_kernel_protocol::v2::RecoverTaskAuthorizationRequestV2::new(
            authorization,
            request_digest,
        )
        .map_err(|_| IngressBrowserAuthorityErrorV2::InvalidReference)?;
        match self
            .kernel
            .recover_task_authorization(request, deadline)
            .map_err(map_kernel)?
        {
            savana_kernel_protocol::v2::RecoverTaskAuthorizationResponseV2::Installed(receipt) => {
                if receipt.request_digest() != request_digest {
                    return Err(IngressBrowserAuthorityErrorV2::Unavailable);
                }
                Ok(
                    IngressBrowserMutationResponseV2::TaskAuthorizationEstablished {
                        request_digest,
                        authorization_digest: receipt.authorization_digest(),
                    },
                )
            }
            savana_kernel_protocol::v2::RecoverTaskAuthorizationResponseV2::Approval(prepared) => {
                if prepared.request_digest() != request_digest {
                    return Err(IngressBrowserAuthorityErrorV2::Unavailable);
                }
                self.register_task_display(tab_handle, prepared, deadline)
            }
        }
    }

    fn submit_task(
        &self,
        tab_handle: IngressTabSessionCapabilityV2,
        draft: savana_kernel_protocol::v2::TaskAuthorizationDraftV2,
        nonce: savana_kernel_protocol::v2::Nonce32V2,
        independent_approval: bool,
        deadline: UnixMillisV2,
    ) -> Result<IngressBrowserMutationResponseV2, IngressBrowserAuthorityErrorV2> {
        let session = {
            let mut tabs = self
                .tabs
                .lock()
                .map_err(|_| IngressBrowserAuthorityErrorV2::Unavailable)?;
            let tab = tabs
                .iter_mut()
                .find(|t| t.tab == tab_handle)
                .ok_or(IngressBrowserAuthorityErrorV2::InvalidReference)?;
            if independent_approval {
                if tab.task_approvals.len() >= MAX_PENDING_AUTHENTICATIONS_V2 {
                    return Err(IngressBrowserAuthorityErrorV2::Busy);
                }
                tab.task_approvals
                    .try_reserve(1)
                    .map_err(|_| IngressBrowserAuthorityErrorV2::Unavailable)?;
            }
            tab.finalized_session
                .ok_or(IngressBrowserAuthorityErrorV2::StateConflict)?
        };
        let request = savana_kernel_protocol::v2::EstablishTaskAuthorizationRequestV2::new(
            session, draft, nonce,
        )
        .map_err(|_| IngressBrowserAuthorityErrorV2::StateConflict)?;
        if !independent_approval {
            let receipt = self
                .kernel
                .establish_task_authorization(request, deadline)
                .map_err(map_kernel)?;
            return Ok(
                IngressBrowserMutationResponseV2::TaskAuthorizationEstablished {
                    request_digest: receipt.request_digest(),
                    authorization_digest: receipt.authorization_digest(),
                },
            );
        }
        let prepared = self
            .kernel
            .prepare_task_authorization_approval(request, deadline)
            .map_err(map_kernel)?;
        self.register_task_display(tab_handle, prepared, deadline)
    }

    fn register_task_display(
        &self,
        tab_handle: IngressTabSessionCapabilityV2,
        prepared: savana_kernel_protocol::v2::PrepareTaskAuthorizationApprovalResponseV2,
        deadline: UnixMillisV2,
    ) -> Result<IngressBrowserMutationResponseV2, IngressBrowserAuthorityErrorV2> {
        {
            let mut tabs = self
                .tabs
                .lock()
                .map_err(|_| IngressBrowserAuthorityErrorV2::Unavailable)?;
            let tab = tabs
                .iter_mut()
                .find(|t| t.tab == tab_handle)
                .ok_or(IngressBrowserAuthorityErrorV2::InvalidReference)?;
            if !tab
                .task_approvals
                .iter()
                .any(|p| p.request_digest == prepared.request_digest())
            {
                if tab.task_approvals.len() >= MAX_PENDING_AUTHENTICATIONS_V2 {
                    return Err(IngressBrowserAuthorityErrorV2::Busy);
                }
                tab.task_approvals
                    .try_reserve(1)
                    .map_err(|_| IngressBrowserAuthorityErrorV2::Unavailable)?;
            }
        }
        let registered = self
            .approval
            .register_approval(
                prepared.envelope().clone(),
                prepared.display_authentication().clone(),
                deadline,
            )
            .map_err(map_approval)?;
        let RegisteredApprovalV2::TaskAuthorization {
            approval,
            display_authentication: transfer,
        } = registered
        else {
            return Err(IngressBrowserAuthorityErrorV2::Unavailable);
        };
        let mut tabs = self
            .tabs
            .lock()
            .map_err(|_| IngressBrowserAuthorityErrorV2::Unavailable)?;
        let tab = tabs
            .iter_mut()
            .find(|t| t.tab == tab_handle)
            .ok_or(IngressBrowserAuthorityErrorV2::InvalidReference)?;
        if let Some(old) = tab
            .task_approvals
            .iter()
            .find(|p| p.request_digest == prepared.request_digest())
        {
            if old.approval != approval || old.transfer != transfer {
                return Err(IngressBrowserAuthorityErrorV2::StateConflict);
            }
        } else {
            tab.task_approvals.push(PendingTaskApprovalV2 {
                request_digest: prepared.request_digest(),
                approval,
                transfer,
            });
        }
        Ok(
            IngressBrowserMutationResponseV2::TaskAuthorizationOpenApproval {
                request_digest: prepared.request_digest(),
                transfer,
            },
        )
    }

    fn commit_task(
        &self,
        tab_handle: IngressTabSessionCapabilityV2,
        request_digest: Digest32V2,
        deadline: UnixMillisV2,
    ) -> Result<IngressBrowserMutationResponseV2, IngressBrowserAuthorityErrorV2> {
        let pending = self
            .tabs
            .lock()
            .map_err(|_| IngressBrowserAuthorityErrorV2::Unavailable)?
            .iter()
            .find(|t| t.tab == tab_handle)
            .and_then(|t| {
                t.task_approvals
                    .iter()
                    .find(|p| p.request_digest == request_digest)
            })
            .copied()
            .ok_or(IngressBrowserAuthorityErrorV2::InvalidReference)?;
        match self
            .approval
            .get_task_authorization_approval_settlement(pending.approval, deadline)
            .map_err(map_approval)?
        {
            ApprovalSettlementViewV2::Pending => Ok(
                IngressBrowserMutationResponseV2::TaskAuthorizationOpenApproval {
                    request_digest,
                    transfer: pending.transfer,
                },
            ),
            ApprovalSettlementViewV2::Denied { .. } | ApprovalSettlementViewV2::Expired => {
                Ok(IngressBrowserMutationResponseV2::TaskAuthorizationRejected)
            }
            ApprovalSettlementViewV2::Approved { settlement } => {
                let request =
                    savana_kernel_protocol::v2::CommitTaskAuthorizationApprovalRequestV2::new(
                        request_digest,
                        settlement,
                    )
                    .map_err(|_| IngressBrowserAuthorityErrorV2::StateConflict)?;
                let receipt = self
                    .kernel
                    .commit_task_authorization_approval(request, deadline)
                    .map_err(map_kernel)?;
                Ok(
                    IngressBrowserMutationResponseV2::TaskAuthorizationEstablished {
                        request_digest: receipt.request_digest(),
                        authorization_digest: receipt.authorization_digest(),
                    },
                )
            }
        }
    }

    fn begin_input(
        &self,
        tab_handle: IngressTabSessionCapabilityV2,
        content_kind: ContentKindV2,
        declared_total_bytes: u64,
        declared_content_digest: Option<Digest32V2>,
        deadline: UnixMillisV2,
    ) -> Result<IngressBrowserMutationResponseV2, IngressBrowserAuthorityErrorV2> {
        let (authorization, direct_channel, commitment_channel) = {
            let tabs = self
                .tabs
                .lock()
                .map_err(|_| IngressBrowserAuthorityErrorV2::Unavailable)?;
            let tab = tabs
                .iter()
                .find(|tab| tab.tab == tab_handle)
                .ok_or(IngressBrowserAuthorityErrorV2::InvalidReference)?;
            if tab.input.is_some() {
                return Err(IngressBrowserAuthorityErrorV2::StateConflict);
            }
            let (direct, commitment) = match content_kind {
                ContentKindV2::ChatText => {
                    (DirectInputChannelV2::ChatText, InputChannelV2::ChatText)
                }
                ContentKindV2::PlainText => (
                    DirectInputChannelV2::OriginalSource,
                    InputChannelV2::OriginalSource,
                ),
                ContentKindV2::ParsedDocument => (
                    DirectInputChannelV2::OriginalSource,
                    InputChannelV2::OriginalSource,
                ),
            };
            (tab.authorization, direct, commitment)
        };
        let begun = self
            .kernel
            .begin_input(
                BeginInputRequestV2::new(
                    authorization,
                    content_kind,
                    declared_total_bytes,
                    declared_content_digest,
                )
                .map_err(|_| IngressBrowserAuthorityErrorV2::InvalidReference)?,
                deadline,
            )
            .map_err(map_kernel)?;
        let next_sequence = begun
            .next_sequences()
            .iter()
            .find(|entry| entry.channel() == commitment_channel)
            .map(|entry| entry.next_sequence())
            .ok_or(IngressBrowserAuthorityErrorV2::Unavailable)?;
        if next_sequence != 0 {
            return Err(IngressBrowserAuthorityErrorV2::Unavailable);
        }
        let mut tabs = self
            .tabs
            .lock()
            .map_err(|_| IngressBrowserAuthorityErrorV2::Unavailable)?;
        let tab = tabs
            .iter_mut()
            .find(|tab| tab.tab == tab_handle)
            .ok_or(IngressBrowserAuthorityErrorV2::Unavailable)?;
        tab.input = Some(ActiveInputV2 {
            session: begun.session(),
            writer: begun.writer(),
            content_kind,
            direct_channel,
            commitment_channel,
            declared_total_bytes,
            declared_content_digest,
            next_sequence: 0,
            cumulative_digest: input_channel_begin_digest_v2(begun.session(), commitment_channel),
            total_length: 0,
            content_hasher: Sha256::new(),
            parser_job_session_binding_digest: begun.parser_job_session_binding_digest(),
            original_bytes: Zeroizing::new(Vec::new()),
            approval: None,
        });
        Ok(IngressBrowserMutationResponseV2::Begun { next_sequence: 0 })
    }

    fn append_input(
        &self,
        tab_handle: IngressTabSessionCapabilityV2,
        sequence: u32,
        chunk: ZeroizingBytesV2,
        deadline: UnixMillisV2,
    ) -> Result<IngressBrowserMutationResponseV2, IngressBrowserAuthorityErrorV2> {
        let input = self.input_snapshot(tab_handle)?;
        if input.approval.is_some() || sequence != input.next_sequence {
            return Err(IngressBrowserAuthorityErrorV2::StateConflict);
        }
        let chunk_digest = input_chunk_digest_v2(
            input.session,
            input.commitment_channel,
            sequence,
            chunk.as_bytes(),
        )
        .map_err(|_| IngressBrowserAuthorityErrorV2::InvalidReference)?;
        let chunk_length = u64::try_from(chunk.as_bytes().len())
            .map_err(|_| IngressBrowserAuthorityErrorV2::InvalidReference)?;
        let next_total_length = input
            .total_length
            .checked_add(chunk_length)
            .filter(|length| *length <= input.declared_total_bytes)
            .ok_or(IngressBrowserAuthorityErrorV2::StateConflict)?;
        let mut next_hasher = input.content_hasher.clone();
        next_hasher.update(chunk.as_bytes());
        let mut next_original = input.original_bytes.clone();
        if input.content_kind == ContentKindV2::ParsedDocument {
            next_original
                .try_reserve(chunk.as_bytes().len())
                .map_err(|_| IngressBrowserAuthorityErrorV2::Unavailable)?;
            next_original.extend_from_slice(chunk.as_bytes());
        }
        let resulting =
            input_channel_step_digest_v2(input.cumulative_digest, sequence, chunk_digest)
                .map_err(|_| IngressBrowserAuthorityErrorV2::InvalidReference)?;
        let accepted = self
            .kernel
            .append_input_chunk(
                AppendInputChunkRequestV2::new(
                    input.writer,
                    input.direct_channel,
                    sequence,
                    input.cumulative_digest,
                    chunk,
                    chunk_digest,
                    resulting,
                )
                .map_err(|_| IngressBrowserAuthorityErrorV2::InvalidReference)?,
                deadline,
            )
            .map_err(map_kernel)?;
        if accepted.acknowledged_sequence() != sequence || accepted.cumulative_digest() != resulting
        {
            return Err(IngressBrowserAuthorityErrorV2::Unavailable);
        }
        let mut tabs = self
            .tabs
            .lock()
            .map_err(|_| IngressBrowserAuthorityErrorV2::Unavailable)?;
        let input = tabs
            .iter_mut()
            .find(|tab| tab.tab == tab_handle)
            .and_then(|tab| tab.input.as_mut())
            .ok_or(IngressBrowserAuthorityErrorV2::Unavailable)?;
        input.next_sequence = input
            .next_sequence
            .checked_add(1)
            .ok_or(IngressBrowserAuthorityErrorV2::StateConflict)?;
        input.cumulative_digest = resulting;
        input.total_length = next_total_length;
        input.content_hasher = next_hasher;
        input.original_bytes = next_original;
        Ok(IngressBrowserMutationResponseV2::ChunkAccepted {
            acknowledged_sequence: sequence,
            cumulative_digest: resulting,
        })
    }

    fn finalize_input(
        &self,
        tab_handle: IngressTabSessionCapabilityV2,
        declared_content_digest: Digest32V2,
        deadline: UnixMillisV2,
    ) -> Result<IngressBrowserMutationResponseV2, IngressBrowserAuthorityErrorV2> {
        let input = self.input_snapshot(tab_handle)?;
        if input.next_sequence == 0
            || input.total_length != input.declared_total_bytes
            || input
                .declared_content_digest
                .is_some_and(|digest| digest != declared_content_digest)
            || Digest32V2::new(input.content_hasher.clone().finalize().into())
                != declared_content_digest
        {
            return Err(IngressBrowserAuthorityErrorV2::StateConflict);
        }
        if let Some(approval) = input.approval {
            return self.finish_pending_approval(tab_handle, approval, deadline);
        }
        let original_commitment = InputChannelCommitmentV2::new(
            input.commitment_channel,
            input.next_sequence,
            input.next_sequence - 1,
            input.declared_total_bytes,
            input.cumulative_digest,
        )
        .map_err(|_| IngressBrowserAuthorityErrorV2::StateConflict)?;
        let (commitments, provenance) = match input.content_kind {
            ContentKindV2::ChatText | ContentKindV2::PlainText => {
                let source_kind = if input.content_kind == ContentKindV2::ChatText {
                    InputSourceKindV2::Chat
                } else {
                    InputSourceKindV2::Paste
                };
                (
                    vec![original_commitment],
                    InputSourceProvenanceV2::direct(
                        source_kind,
                        input.declared_total_bytes,
                        declared_content_digest,
                        VersionV2::new(1, 0, 0),
                    )
                    .map_err(|_| IngressBrowserAuthorityErrorV2::StateConflict)?,
                )
            }
            ContentKindV2::ParsedDocument => self.parse_document(
                &input,
                original_commitment,
                declared_content_digest,
                deadline,
            )?,
        };
        let finalized = self
            .kernel
            .finalize_input(
                FinalizeInputRequestV2::new(input.session, commitments, provenance)
                    .map_err(|_| IngressBrowserAuthorityErrorV2::StateConflict)?,
                deadline,
            )
            .map_err(map_kernel)?;
        let registered = self
            .approval
            .register_approval(
                finalized.envelope().clone(),
                finalized.display_authentication().clone(),
                deadline,
            )
            .map_err(map_approval)?;
        let (approval, transfer) = match registered {
            RegisteredApprovalV2::Ingress {
                approval,
                display_authentication,
            } => (approval, display_authentication),
            _ => return Err(IngressBrowserAuthorityErrorV2::Unavailable),
        };
        let mut tabs = self
            .tabs
            .lock()
            .map_err(|_| IngressBrowserAuthorityErrorV2::Unavailable)?;
        let input = tabs
            .iter_mut()
            .find(|tab| tab.tab == tab_handle)
            .and_then(|tab| tab.input.as_mut())
            .ok_or(IngressBrowserAuthorityErrorV2::Unavailable)?;
        input.approval = Some(PendingInputApprovalV2 {
            pending: finalized.pending(),
            kernel_approval: finalized.approval(),
            approval_record: approval,
            display_transfer: transfer,
        });
        Ok(IngressBrowserMutationResponseV2::FinalizeOpenApproval { transfer })
    }

    fn abort_input(
        &self,
        tab_handle: IngressTabSessionCapabilityV2,
        deadline: UnixMillisV2,
    ) -> Result<IngressBrowserMutationResponseV2, IngressBrowserAuthorityErrorV2> {
        let input = self.input_snapshot(tab_handle)?;
        if input.approval.is_some() {
            return Err(IngressBrowserAuthorityErrorV2::StateConflict);
        }
        self.kernel
            .abort_input(AbortInputRequestV2::new(input.session), deadline)
            .map_err(map_kernel)?;
        let mut tabs = self
            .tabs
            .lock()
            .map_err(|_| IngressBrowserAuthorityErrorV2::Unavailable)?;
        let tab = tabs
            .iter_mut()
            .find(|tab| tab.tab == tab_handle)
            .ok_or(IngressBrowserAuthorityErrorV2::Unavailable)?;
        tab.input = None;
        Ok(IngressBrowserMutationResponseV2::Aborted)
    }

    fn input_snapshot(
        &self,
        tab_handle: IngressTabSessionCapabilityV2,
    ) -> Result<ActiveInputV2, IngressBrowserAuthorityErrorV2> {
        self.tabs
            .lock()
            .map_err(|_| IngressBrowserAuthorityErrorV2::Unavailable)?
            .iter()
            .find(|tab| tab.tab == tab_handle)
            .and_then(|tab| tab.input.clone())
            .ok_or(IngressBrowserAuthorityErrorV2::InvalidReference)
    }

    fn finish_pending_approval(
        &self,
        tab_handle: IngressTabSessionCapabilityV2,
        approval: PendingInputApprovalV2,
        deadline: UnixMillisV2,
    ) -> Result<IngressBrowserMutationResponseV2, IngressBrowserAuthorityErrorV2> {
        let settlement = self
            .approval
            .get_ingress_approval_settlement(approval.approval_record, deadline)
            .map_err(map_approval)?;
        let response = match settlement {
            ApprovalSettlementViewV2::Pending => {
                return Ok(IngressBrowserMutationResponseV2::FinalizeOpenApproval {
                    transfer: approval.display_transfer,
                })
            }
            ApprovalSettlementViewV2::Approved { settlement } => {
                let committed = self
                    .kernel
                    .commit_input_settlement(
                        CommitInputSettlementRequestV2::new(
                            approval.pending,
                            approval.kernel_approval,
                            settlement,
                        )
                        .map_err(|_| IngressBrowserAuthorityErrorV2::Unavailable)?,
                        deadline,
                    )
                    .map_err(map_kernel)?;
                if !matches!(
                    committed.state(),
                    InputPublicStateV2::CommittedUnclaimed | InputPublicStateV2::AgentClaimed
                ) {
                    return Err(IngressBrowserAuthorityErrorV2::Unavailable);
                }
                IngressBrowserMutationResponseV2::FinalizeCommitted {
                    state: committed.state(),
                }
            }
            ApprovalSettlementViewV2::Denied { settlement } => {
                let rejected = self
                    .kernel
                    .commit_input_settlement(
                        CommitInputSettlementRequestV2::new(
                            approval.pending,
                            approval.kernel_approval,
                            settlement,
                        )
                        .map_err(|_| IngressBrowserAuthorityErrorV2::Unavailable)?,
                        deadline,
                    )
                    .map_err(map_kernel)?;
                if rejected.state() != InputPublicStateV2::Denied {
                    return Err(IngressBrowserAuthorityErrorV2::Unavailable);
                }
                IngressBrowserMutationResponseV2::FinalizeRejected {
                    state: rejected.state(),
                }
            }
            ApprovalSettlementViewV2::Expired => {
                let aborted = self
                    .kernel
                    .abort_input(
                        AbortInputRequestV2::new(self.input_snapshot(tab_handle)?.session),
                        deadline,
                    )
                    .map_err(map_kernel)?;
                if !matches!(
                    aborted.state(),
                    InputPublicStateV2::Expired
                        | InputPublicStateV2::Aborted
                        | InputPublicStateV2::FailedClosed
                ) {
                    return Err(IngressBrowserAuthorityErrorV2::Unavailable);
                }
                IngressBrowserMutationResponseV2::FinalizeRejected {
                    state: aborted.state(),
                }
            }
        };
        let mut tabs = self
            .tabs
            .lock()
            .map_err(|_| IngressBrowserAuthorityErrorV2::Unavailable)?;
        let tab = tabs
            .iter_mut()
            .find(|tab| tab.tab == tab_handle)
            .ok_or(IngressBrowserAuthorityErrorV2::Unavailable)?;
        if matches!(
            response,
            IngressBrowserMutationResponseV2::FinalizeCommitted { .. }
        ) {
            tab.finalized_session = tab.input.as_ref().map(|input| input.session);
        }
        tab.input = None;
        Ok(response)
    }

    fn parse_document(
        &self,
        input: &ActiveInputV2,
        original_commitment: InputChannelCommitmentV2,
        original_digest: Digest32V2,
        deadline: UnixMillisV2,
    ) -> Result<
        (Vec<InputChannelCommitmentV2>, InputSourceProvenanceV2),
        IngressBrowserAuthorityErrorV2,
    > {
        let parser = self
            .parser
            .as_ref()
            .ok_or(IngressBrowserAuthorityErrorV2::Unavailable)?;
        if input.original_bytes.len() as u64 != input.declared_total_bytes {
            return Err(IngressBrowserAuthorityErrorV2::StateConflict);
        }
        let process_deadline = instant_deadline(deadline)?;
        let prepared = parser.prepare(process_deadline).map_err(map_parser)?;
        let output = match parser.execute(
            prepared,
            input.parser_job_session_binding_digest,
            input.original_bytes.clone(),
            original_digest,
            current_unix_millis()?,
            deadline,
            process_deadline,
        ) {
            Ok(output) => output,
            Err(error) => {
                let _ = self
                    .kernel
                    .abort_input(AbortInputRequestV2::new(input.session), deadline);
                return Err(map_parser(error));
            }
        };
        let registered = self
            .kernel
            .register_parser_worker_job(
                RegisterParserWorkerJobRequestV2::new(input.session, output.descriptor),
                deadline,
            )
            .map_err(map_kernel)?;
        for frame in output.frames {
            let expected_page = frame.page_index();
            let expected_chunk = frame.page_chunk_index();
            let expected_transcript = frame.transcript_step_digest();
            let acknowledged = self
                .kernel
                .append_parser_worker_page_frame(
                    AppendParserWorkerPageFrameRequestV2::new(registered.extraction(), frame),
                    deadline,
                )
                .map_err(map_kernel)?;
            if acknowledged.page_index() != expected_page
                || acknowledged.page_chunk_index() != expected_chunk
                || acknowledged.ordered_page_frame_transcript_digest() != expected_transcript
            {
                return Err(IngressBrowserAuthorityErrorV2::Unavailable);
            }
        }
        let verified_attestation = output
            .attestation
            .verify_for_job(output.verified_job, current_unix_millis()?)
            .map_err(|_| IngressBrowserAuthorityErrorV2::Unavailable)?;
        let committed = self
            .kernel
            .commit_parser_worker_result(
                CommitParserWorkerResultRequestV2::new(registered.extraction(), output.attestation),
                deadline,
            )
            .map_err(map_kernel)?;
        let profile = parser.profile();
        let provenance = InputSourceProvenanceV2::parsed_document(
            InputSourceKindV2::FileUpload,
            input.declared_total_bytes,
            original_digest,
            output.verified_job.declared_media_type(),
            output.verified_job.detected_media_type(),
            profile.extension_class,
            output.verified_job.parser_implementation_id(),
            profile.semantic_version,
            output.verified_job.parser_code_digest(),
            output.verified_job.renderer_code_digest(),
            output.verified_job.ocr_model_set_digest(),
            output.verified_job.normalization_version(),
            verified_attestation.page_records().to_vec(),
            verified_attestation.extracted_output_digest(),
        )
        .map_err(|_| IngressBrowserAuthorityErrorV2::Unavailable)?;
        Ok((
            vec![
                original_commitment,
                committed.extracted_channel_commitment(),
            ],
            provenance,
        ))
    }

    fn clear_mutation_in_flight(&self, tab_handle: IngressTabSessionCapabilityV2) {
        if let Ok(mut tabs) = self.tabs.lock() {
            if let Some(tab) = tabs.iter_mut().find(|tab| tab.tab == tab_handle) {
                tab.mutation_in_flight = false;
            }
        }
    }
}

fn draw_nonzero() -> Result<[u8; 32], IngressBrowserAuthorityErrorV2> {
    let mut bytes = [0_u8; 32];
    getrandom::getrandom(&mut bytes).map_err(|_| IngressBrowserAuthorityErrorV2::Unavailable)?;
    if bytes == [0; 32] {
        Err(IngressBrowserAuthorityErrorV2::Unavailable)
    } else {
        Ok(bytes)
    }
}

fn map_kernel(error: IngressKernelClientErrorV2) -> IngressBrowserAuthorityErrorV2 {
    match error {
        IngressKernelClientErrorV2::DeadlineExceeded => {
            IngressBrowserAuthorityErrorV2::DeadlineExceeded
        }
        IngressKernelClientErrorV2::Unavailable => IngressBrowserAuthorityErrorV2::Unavailable,
    }
}

fn map_approval(error: ApprovalSuiteOneClientErrorV2) -> IngressBrowserAuthorityErrorV2 {
    match error {
        ApprovalSuiteOneClientErrorV2::DeadlineExceeded => {
            IngressBrowserAuthorityErrorV2::DeadlineExceeded
        }
        ApprovalSuiteOneClientErrorV2::Rejected(_) => {
            IngressBrowserAuthorityErrorV2::InvalidReference
        }
        ApprovalSuiteOneClientErrorV2::Unavailable => IngressBrowserAuthorityErrorV2::Unavailable,
    }
}

fn map_parser(error: ProtocolParserErrorV2) -> IngressBrowserAuthorityErrorV2 {
    match error {
        ProtocolParserErrorV2::Deadline => IngressBrowserAuthorityErrorV2::DeadlineExceeded,
        ProtocolParserErrorV2::Rejected => IngressBrowserAuthorityErrorV2::InvalidReference,
        ProtocolParserErrorV2::Deployment
        | ProtocolParserErrorV2::Launch
        | ProtocolParserErrorV2::Protocol => IngressBrowserAuthorityErrorV2::Unavailable,
    }
}

fn current_unix_millis() -> Result<UnixMillisV2, IngressBrowserAuthorityErrorV2> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| IngressBrowserAuthorityErrorV2::Unavailable)?
        .as_millis();
    let millis = u64::try_from(millis).map_err(|_| IngressBrowserAuthorityErrorV2::Unavailable)?;
    if millis == 0 {
        Err(IngressBrowserAuthorityErrorV2::Unavailable)
    } else {
        Ok(UnixMillisV2::new(millis))
    }
}

fn instant_deadline(deadline: UnixMillisV2) -> Result<Instant, IngressBrowserAuthorityErrorV2> {
    let now = current_unix_millis()?;
    let remaining = deadline
        .get()
        .checked_sub(now.get())
        .filter(|value| *value > 0)
        .ok_or(IngressBrowserAuthorityErrorV2::DeadlineExceeded)?;
    Instant::now()
        .checked_add(Duration::from_millis(remaining.min(30_000)))
        .ok_or(IngressBrowserAuthorityErrorV2::Unavailable)
}
