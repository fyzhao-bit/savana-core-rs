use std::time::Instant;

use savana_kernel_protocol::v2::{
    EndpointRoleV2, KernelAgentOperationV2, KernelConnectorControlOperationV2,
    KernelIngressOperationV2, KernelServiceOperationV2, RequestIdV2, UnixMillisV2,
};
use savana_kernel_protocol::StableCode;

use crate::policy_runtime::V2GenerationLease;
#[cfg(any(test, feature = "test-support"))]
use crate::v2_dispatch::KernelServiceResponseBodyV2;
use crate::v2_dispatch::{
    KernelRuntimeResponseBuilderV2, KernelRuntimeResponsePreparationErrorV2,
    PreparedKernelServiceResponseV2, VerifiedKernelServicePeerV2,
};
use crate::v2_state_owner::{StateOwnerCommitV2, StateOwnerErrorV2, StateOwnerV2};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KernelRuntimeHandlerV2 {
    AgentHealth,
    ClaimAgentSession,
    PrepareFollowupIngress,
    GetAgentSessionStatus,
    PreparePlannerCall,
    CommitPlannerValue,
    DeriveValue,
    ProposeToolCall,
    EvaluateToolCall,
    AuthorizeToolCall,
    DispatchExecution,
    GetExecutionStatus,
    ReadAgentView,
    PrepareRelease,
    AuthorizeRelease,
    DispatchRelease,
    GetReleaseStatus,
    RevokeVault,
    CloseAgentSession,
    PrepareNewIngress,
    PrepareAgentUiAuthentication,
    AuthenticateAgentUi,
    GetKernelTaskStatus,
    CancelKernelTask,
    ResumeCommittedAgentAuthentication,
    PrepareConnectorRegistration,
    ProposeConnectorRegistration,
    AuthorizeConnectorRegistration,
    ApplyApprovedConnectorRegistration,
    PrepareConnectorRemoval,
    RemoveConnector,
    SnapshotConnectorRegistry,
    IngressHealth,
    BeginInput,
    AppendInputChunk,
    FinalizeInput,
    CommitInputSettlement,
    AbortInput,
    GetInputStatus,
    PrepareIngressUiAuthentication,
    AuthenticateIngressUi,
    RegisterParserWorkerJob,
    AppendParserWorkerPageFrame,
    CommitParserWorkerResult,
    EstablishTaskAuthorization,
    PrepareTaskAuthorizationApproval,
    CommitTaskAuthorizationApproval,
    RevokeTaskAuthorization,
    RecoverTaskAuthorization,
}

impl KernelRuntimeHandlerV2 {
    pub(crate) const fn role(self) -> EndpointRoleV2 {
        match self {
            Self::AgentHealth
            | Self::ClaimAgentSession
            | Self::PrepareFollowupIngress
            | Self::GetAgentSessionStatus
            | Self::PreparePlannerCall
            | Self::CommitPlannerValue
            | Self::DeriveValue
            | Self::ProposeToolCall
            | Self::EvaluateToolCall
            | Self::AuthorizeToolCall
            | Self::DispatchExecution
            | Self::GetExecutionStatus
            | Self::ReadAgentView
            | Self::PrepareRelease
            | Self::AuthorizeRelease
            | Self::DispatchRelease
            | Self::GetReleaseStatus
            | Self::RevokeVault
            | Self::CloseAgentSession
            | Self::PrepareNewIngress
            | Self::PrepareAgentUiAuthentication
            | Self::AuthenticateAgentUi
            | Self::GetKernelTaskStatus
            | Self::CancelKernelTask
            | Self::ResumeCommittedAgentAuthentication => EndpointRoleV2::AgentKernel,
            Self::PrepareConnectorRegistration
            | Self::ProposeConnectorRegistration
            | Self::AuthorizeConnectorRegistration
            | Self::ApplyApprovedConnectorRegistration
            | Self::PrepareConnectorRemoval
            | Self::RemoveConnector
            | Self::SnapshotConnectorRegistry => EndpointRoleV2::AgentKernel,
            Self::IngressHealth
            | Self::BeginInput
            | Self::AppendInputChunk
            | Self::FinalizeInput
            | Self::CommitInputSettlement
            | Self::AbortInput
            | Self::GetInputStatus
            | Self::PrepareIngressUiAuthentication
            | Self::AuthenticateIngressUi
            | Self::RegisterParserWorkerJob
            | Self::AppendParserWorkerPageFrame
            | Self::CommitParserWorkerResult
            | Self::EstablishTaskAuthorization
            | Self::PrepareTaskAuthorizationApproval
            | Self::CommitTaskAuthorizationApproval
            | Self::RevokeTaskAuthorization
            | Self::RecoverTaskAuthorization => EndpointRoleV2::IngressKernel,
        }
    }

    pub(crate) const fn tag(self) -> u16 {
        match self {
            Self::AgentHealth | Self::IngressHealth => 0,
            Self::ClaimAgentSession => 20,
            Self::PrepareFollowupIngress => 21,
            Self::GetAgentSessionStatus => 22,
            Self::PreparePlannerCall => 23,
            Self::CommitPlannerValue => 24,
            Self::DeriveValue => 25,
            Self::ProposeToolCall => 26,
            Self::EvaluateToolCall => 27,
            Self::AuthorizeToolCall => 28,
            Self::DispatchExecution => 29,
            Self::GetExecutionStatus => 30,
            Self::ReadAgentView => 31,
            Self::PrepareRelease => 32,
            Self::AuthorizeRelease => 33,
            Self::DispatchRelease => 34,
            Self::GetReleaseStatus => 35,
            Self::RevokeVault => 36,
            Self::CloseAgentSession => 37,
            Self::PrepareNewIngress => 38,
            Self::PrepareAgentUiAuthentication => 39,
            Self::AuthenticateAgentUi | Self::BeginInput => 40,
            Self::GetKernelTaskStatus | Self::AppendInputChunk => 41,
            Self::CancelKernelTask | Self::FinalizeInput => 42,
            Self::ResumeCommittedAgentAuthentication | Self::CommitInputSettlement => 43,
            Self::PrepareConnectorRegistration => 70,
            Self::ProposeConnectorRegistration => 71,
            Self::AuthorizeConnectorRegistration => 72,
            Self::ApplyApprovedConnectorRegistration => 73,
            Self::PrepareConnectorRemoval => 74,
            Self::RemoveConnector => 75,
            Self::SnapshotConnectorRegistry => 76,
            Self::AbortInput => 44,
            Self::GetInputStatus => 45,
            Self::PrepareIngressUiAuthentication => 46,
            Self::AuthenticateIngressUi => 47,
            Self::RegisterParserWorkerJob => 48,
            Self::AppendParserWorkerPageFrame => 49,
            Self::CommitParserWorkerResult => 50,
            Self::EstablishTaskAuthorization => 51,
            Self::PrepareTaskAuthorizationApproval => 52,
            Self::CommitTaskAuthorizationApproval => 53,
            Self::RevokeTaskAuthorization => 54,
            Self::RecoverTaskAuthorization => 55,
        }
    }
}

#[cfg(test)]
pub(crate) const ALL_KERNEL_RUNTIME_HANDLERS_V2: [KernelRuntimeHandlerV2; 49] = [
    KernelRuntimeHandlerV2::AgentHealth,
    KernelRuntimeHandlerV2::ClaimAgentSession,
    KernelRuntimeHandlerV2::PrepareFollowupIngress,
    KernelRuntimeHandlerV2::GetAgentSessionStatus,
    KernelRuntimeHandlerV2::PreparePlannerCall,
    KernelRuntimeHandlerV2::CommitPlannerValue,
    KernelRuntimeHandlerV2::DeriveValue,
    KernelRuntimeHandlerV2::ProposeToolCall,
    KernelRuntimeHandlerV2::EvaluateToolCall,
    KernelRuntimeHandlerV2::AuthorizeToolCall,
    KernelRuntimeHandlerV2::DispatchExecution,
    KernelRuntimeHandlerV2::GetExecutionStatus,
    KernelRuntimeHandlerV2::ReadAgentView,
    KernelRuntimeHandlerV2::PrepareRelease,
    KernelRuntimeHandlerV2::AuthorizeRelease,
    KernelRuntimeHandlerV2::DispatchRelease,
    KernelRuntimeHandlerV2::GetReleaseStatus,
    KernelRuntimeHandlerV2::RevokeVault,
    KernelRuntimeHandlerV2::CloseAgentSession,
    KernelRuntimeHandlerV2::PrepareNewIngress,
    KernelRuntimeHandlerV2::PrepareAgentUiAuthentication,
    KernelRuntimeHandlerV2::AuthenticateAgentUi,
    KernelRuntimeHandlerV2::GetKernelTaskStatus,
    KernelRuntimeHandlerV2::CancelKernelTask,
    KernelRuntimeHandlerV2::ResumeCommittedAgentAuthentication,
    KernelRuntimeHandlerV2::PrepareConnectorRegistration,
    KernelRuntimeHandlerV2::ProposeConnectorRegistration,
    KernelRuntimeHandlerV2::AuthorizeConnectorRegistration,
    KernelRuntimeHandlerV2::ApplyApprovedConnectorRegistration,
    KernelRuntimeHandlerV2::PrepareConnectorRemoval,
    KernelRuntimeHandlerV2::RemoveConnector,
    KernelRuntimeHandlerV2::SnapshotConnectorRegistry,
    KernelRuntimeHandlerV2::IngressHealth,
    KernelRuntimeHandlerV2::BeginInput,
    KernelRuntimeHandlerV2::AppendInputChunk,
    KernelRuntimeHandlerV2::FinalizeInput,
    KernelRuntimeHandlerV2::CommitInputSettlement,
    KernelRuntimeHandlerV2::AbortInput,
    KernelRuntimeHandlerV2::GetInputStatus,
    KernelRuntimeHandlerV2::PrepareIngressUiAuthentication,
    KernelRuntimeHandlerV2::AuthenticateIngressUi,
    KernelRuntimeHandlerV2::RegisterParserWorkerJob,
    KernelRuntimeHandlerV2::AppendParserWorkerPageFrame,
    KernelRuntimeHandlerV2::CommitParserWorkerResult,
    KernelRuntimeHandlerV2::EstablishTaskAuthorization,
    KernelRuntimeHandlerV2::PrepareTaskAuthorizationApproval,
    KernelRuntimeHandlerV2::CommitTaskAuthorizationApproval,
    KernelRuntimeHandlerV2::RevokeTaskAuthorization,
    KernelRuntimeHandlerV2::RecoverTaskAuthorization,
];

pub(crate) fn handler_for_operation_v2(
    operation: &KernelServiceOperationV2,
) -> Result<KernelRuntimeHandlerV2, StableCode> {
    match operation {
        KernelServiceOperationV2::Agent(operation) => Ok(match operation {
            KernelAgentOperationV2::Health(_) => KernelRuntimeHandlerV2::AgentHealth,
            KernelAgentOperationV2::ClaimAgentSession(_) => {
                KernelRuntimeHandlerV2::ClaimAgentSession
            }
            KernelAgentOperationV2::PrepareFollowupIngress(_) => {
                KernelRuntimeHandlerV2::PrepareFollowupIngress
            }
            KernelAgentOperationV2::GetAgentSessionStatus(_) => {
                KernelRuntimeHandlerV2::GetAgentSessionStatus
            }
            KernelAgentOperationV2::PreparePlannerCall(_) => {
                KernelRuntimeHandlerV2::PreparePlannerCall
            }
            KernelAgentOperationV2::CommitPlannerValue(_) => {
                KernelRuntimeHandlerV2::CommitPlannerValue
            }
            KernelAgentOperationV2::DeriveValue(_) => KernelRuntimeHandlerV2::DeriveValue,
            KernelAgentOperationV2::ProposeToolCall(_) => KernelRuntimeHandlerV2::ProposeToolCall,
            KernelAgentOperationV2::EvaluateToolCall(_) => KernelRuntimeHandlerV2::EvaluateToolCall,
            KernelAgentOperationV2::AuthorizeToolCall(_) => {
                KernelRuntimeHandlerV2::AuthorizeToolCall
            }
            KernelAgentOperationV2::DispatchExecution(_) => {
                KernelRuntimeHandlerV2::DispatchExecution
            }
            KernelAgentOperationV2::GetExecutionStatus(_) => {
                KernelRuntimeHandlerV2::GetExecutionStatus
            }
            KernelAgentOperationV2::ReadAgentView(_) => KernelRuntimeHandlerV2::ReadAgentView,
            KernelAgentOperationV2::PrepareRelease(_) => KernelRuntimeHandlerV2::PrepareRelease,
            KernelAgentOperationV2::AuthorizeRelease(_) => KernelRuntimeHandlerV2::AuthorizeRelease,
            KernelAgentOperationV2::DispatchRelease(_) => KernelRuntimeHandlerV2::DispatchRelease,
            KernelAgentOperationV2::GetReleaseStatus(_) => KernelRuntimeHandlerV2::GetReleaseStatus,
            KernelAgentOperationV2::RevokeVault(_) => KernelRuntimeHandlerV2::RevokeVault,
            KernelAgentOperationV2::CloseAgentSession(_) => {
                KernelRuntimeHandlerV2::CloseAgentSession
            }
            KernelAgentOperationV2::PrepareNewIngress(_) => {
                KernelRuntimeHandlerV2::PrepareNewIngress
            }
            KernelAgentOperationV2::PrepareAgentUiAuthentication(_) => {
                KernelRuntimeHandlerV2::PrepareAgentUiAuthentication
            }
            KernelAgentOperationV2::AuthenticateAgentUi(_) => {
                KernelRuntimeHandlerV2::AuthenticateAgentUi
            }
            KernelAgentOperationV2::GetKernelTaskStatus(_) => {
                KernelRuntimeHandlerV2::GetKernelTaskStatus
            }
            KernelAgentOperationV2::CancelKernelTask(_) => KernelRuntimeHandlerV2::CancelKernelTask,
            KernelAgentOperationV2::ResumeCommittedAgentAuthentication(_) => {
                KernelRuntimeHandlerV2::ResumeCommittedAgentAuthentication
            }
        }),
        KernelServiceOperationV2::Ingress(operation) => Ok(match operation {
            KernelIngressOperationV2::Health(_) => KernelRuntimeHandlerV2::IngressHealth,
            KernelIngressOperationV2::BeginInput(_) => KernelRuntimeHandlerV2::BeginInput,
            KernelIngressOperationV2::AppendInputChunk(_) => {
                KernelRuntimeHandlerV2::AppendInputChunk
            }
            KernelIngressOperationV2::FinalizeInput(_) => KernelRuntimeHandlerV2::FinalizeInput,
            KernelIngressOperationV2::CommitInputSettlement(_) => {
                KernelRuntimeHandlerV2::CommitInputSettlement
            }
            KernelIngressOperationV2::AbortInput(_) => KernelRuntimeHandlerV2::AbortInput,
            KernelIngressOperationV2::GetInputStatus(_) => KernelRuntimeHandlerV2::GetInputStatus,
            KernelIngressOperationV2::PrepareIngressUiAuthentication(_) => {
                KernelRuntimeHandlerV2::PrepareIngressUiAuthentication
            }
            KernelIngressOperationV2::AuthenticateIngressUi(_) => {
                KernelRuntimeHandlerV2::AuthenticateIngressUi
            }
            KernelIngressOperationV2::RegisterParserWorkerJob(_) => {
                KernelRuntimeHandlerV2::RegisterParserWorkerJob
            }
            KernelIngressOperationV2::AppendParserWorkerPageFrame(_) => {
                KernelRuntimeHandlerV2::AppendParserWorkerPageFrame
            }
            KernelIngressOperationV2::CommitParserWorkerResult(_) => {
                KernelRuntimeHandlerV2::CommitParserWorkerResult
            }
            KernelIngressOperationV2::EstablishTaskAuthorization(_) => {
                KernelRuntimeHandlerV2::EstablishTaskAuthorization
            }
            KernelIngressOperationV2::PrepareTaskAuthorizationApproval(_) => {
                KernelRuntimeHandlerV2::PrepareTaskAuthorizationApproval
            }
            KernelIngressOperationV2::CommitTaskAuthorizationApproval(_) => {
                KernelRuntimeHandlerV2::CommitTaskAuthorizationApproval
            }
            KernelIngressOperationV2::RevokeTaskAuthorization(_) => {
                KernelRuntimeHandlerV2::RevokeTaskAuthorization
            }
            KernelIngressOperationV2::RecoverTaskAuthorization(_) => {
                KernelRuntimeHandlerV2::RecoverTaskAuthorization
            }
        }),
        KernelServiceOperationV2::Connector(operation) => Ok(match operation {
            KernelConnectorControlOperationV2::PrepareRegistration(_) => {
                KernelRuntimeHandlerV2::PrepareConnectorRegistration
            }
            KernelConnectorControlOperationV2::ProposeRegistration(_) => {
                KernelRuntimeHandlerV2::ProposeConnectorRegistration
            }
            KernelConnectorControlOperationV2::AuthorizeRegistration(_) => {
                KernelRuntimeHandlerV2::AuthorizeConnectorRegistration
            }
            KernelConnectorControlOperationV2::ApplyApprovedRegistration(_) => {
                KernelRuntimeHandlerV2::ApplyApprovedConnectorRegistration
            }
            KernelConnectorControlOperationV2::PrepareRemoval(_) => {
                KernelRuntimeHandlerV2::PrepareConnectorRemoval
            }
            KernelConnectorControlOperationV2::Remove(_) => KernelRuntimeHandlerV2::RemoveConnector,
            KernelConnectorControlOperationV2::Snapshot(_) => {
                KernelRuntimeHandlerV2::SnapshotConnectorRegistry
            }
        }),
        KernelServiceOperationV2::Executor(_) => Err(StableCode::IdentityPeerRejected),
    }
}

pub(crate) struct KernelRuntimeRequestV2 {
    context: KernelRuntimeRequestContextV2,
    response_builder: KernelRuntimeResponseBuilderV2,
}

pub(crate) struct KernelRuntimeRequestContextV2 {
    peer: VerifiedKernelServicePeerV2,
    lease: V2GenerationLease,
    request_id: RequestIdV2,
    logical_deadline: UnixMillisV2,
    now: UnixMillisV2,
    handler: KernelRuntimeHandlerV2,
    operation: KernelServiceOperationV2,
}

impl KernelRuntimeRequestV2 {
    pub(crate) fn into_parts(
        self,
    ) -> (
        KernelRuntimeRequestContextV2,
        KernelRuntimeResponseBuilderV2,
    ) {
        (self.context, self.response_builder)
    }

    fn validate(&self) -> Result<(), StableCode> {
        self.context.validate()
    }

    fn prepares_finalize_before_commit(&self) -> bool {
        matches!(
            self.context.operation,
            KernelServiceOperationV2::Ingress(KernelIngressOperationV2::FinalizeInput(_))
        )
    }
}

impl KernelRuntimeRequestContextV2 {
    #[cfg(test)]
    pub(crate) const fn peer(&self) -> &VerifiedKernelServicePeerV2 {
        &self.peer
    }

    #[cfg(test)]
    pub(crate) const fn handler(&self) -> KernelRuntimeHandlerV2 {
        self.handler
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) const fn operation(&self) -> &KernelServiceOperationV2 {
        &self.operation
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        VerifiedKernelServicePeerV2,
        V2GenerationLease,
        RequestIdV2,
        UnixMillisV2,
        UnixMillisV2,
        KernelRuntimeHandlerV2,
        KernelServiceOperationV2,
    ) {
        (
            self.peer,
            self.lease,
            self.request_id,
            self.logical_deadline,
            self.now,
            self.handler,
            self.operation,
        )
    }

    fn validate(&self) -> Result<(), StableCode> {
        if self.request_id.as_bytes().iter().all(|byte| *byte == 0)
            || self.logical_deadline.get() == 0
            || self.now.get() == 0
            || self.lease.deployment_generation() == 0
            || self.lease.effect_fence_epoch() == 0
            || self
                .lease
                .protocol_abi_digest()
                .as_bytes()
                .iter()
                .all(|byte| *byte == 0)
            || self.handler.role() != self.peer.role()
            || self.handler.tag() != self.operation.tag()
        {
            return Err(StableCode::IdentityPeerRejected);
        }
        Ok(())
    }
}

pub(crate) trait KernelRuntimeServicesV2: Send + 'static {
    fn execute(
        &mut self,
        request: KernelRuntimeRequestV2,
        commit: Option<StateOwnerCommitV2>,
    ) -> Result<PreparedKernelServiceResponseV2, KernelRuntimeResponsePreparationErrorV2>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KernelRuntimeOwnerErrorV2 {
    Busy,
    DeadlineExceeded,
    Unavailable,
    Operation(StableCode),
}

pub(crate) struct KernelRuntimeOwnerV2 {
    owner: StateOwnerV2<
        KernelRuntimeRequestV2,
        Result<PreparedKernelServiceResponseV2, KernelRuntimeResponsePreparationErrorV2>,
    >,
}

impl std::fmt::Debug for KernelRuntimeOwnerV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("KernelRuntimeOwnerV2(<private-state>)")
    }
}

impl KernelRuntimeOwnerV2 {
    pub(crate) fn spawn(
        capacity: usize,
        mut services: impl KernelRuntimeServicesV2,
    ) -> Result<Self, KernelRuntimeOwnerErrorV2> {
        let owner = StateOwnerV2::spawn_transactional(
            "savana-kerneld-runtime-v2",
            capacity,
            move |request: KernelRuntimeRequestV2, commit| {
                Ok(match request.validate() {
                    Ok(()) => {
                        let commit = request.prepares_finalize_before_commit().then_some(commit);
                        services.execute(request, commit)
                    }
                    Err(error) => {
                        let (_, builder) = request.into_parts();
                        builder.prepare(Err(error))
                    }
                })
            },
        )
        .map_err(map_owner_error)?;
        Ok(Self { owner })
    }

    #[cfg(test)]
    pub(crate) fn spawn_for_test(
        capacity: usize,
        handler: impl FnMut(KernelRuntimeRequestContextV2) -> Result<KernelServiceResponseBodyV2, StableCode>
            + Send
            + 'static,
    ) -> Result<Self, KernelRuntimeOwnerErrorV2> {
        struct TestServicesV2<Handler>(Handler);

        impl<Handler> KernelRuntimeServicesV2 for TestServicesV2<Handler>
        where
            Handler: FnMut(
                    KernelRuntimeRequestContextV2,
                ) -> Result<KernelServiceResponseBodyV2, StableCode>
                + Send
                + 'static,
        {
            fn execute(
                &mut self,
                request: KernelRuntimeRequestV2,
                commit: Option<StateOwnerCommitV2>,
            ) -> Result<PreparedKernelServiceResponseV2, KernelRuntimeResponsePreparationErrorV2>
            {
                let (context, builder) = request.into_parts();
                if matches!(
                    context.operation(),
                    KernelServiceOperationV2::Ingress(KernelIngressOperationV2::FinalizeInput(_))
                ) {
                    commit
                        .ok_or(KernelRuntimeResponsePreparationErrorV2::Unavailable)?
                        .claim()
                        .map_err(map_commit_preparation_error)?;
                }
                builder.prepare((self.0)(context))
            }
        }

        Self::spawn(capacity, TestServicesV2(handler))
    }

    #[cfg(feature = "test-support")]
    pub(crate) fn spawn_for_test_support(
        capacity: usize,
        handler: impl FnMut(KernelRuntimeRequestContextV2) -> Result<KernelServiceResponseBodyV2, StableCode>
            + Send
            + 'static,
    ) -> Result<Self, KernelRuntimeOwnerErrorV2> {
        struct TestSupportServicesV2<Handler>(Handler);

        impl<Handler> KernelRuntimeServicesV2 for TestSupportServicesV2<Handler>
        where
            Handler: FnMut(
                    KernelRuntimeRequestContextV2,
                ) -> Result<KernelServiceResponseBodyV2, StableCode>
                + Send
                + 'static,
        {
            fn execute(
                &mut self,
                request: KernelRuntimeRequestV2,
                commit: Option<StateOwnerCommitV2>,
            ) -> Result<PreparedKernelServiceResponseV2, KernelRuntimeResponsePreparationErrorV2>
            {
                let (context, builder) = request.into_parts();
                if matches!(
                    context.operation(),
                    KernelServiceOperationV2::Ingress(KernelIngressOperationV2::FinalizeInput(_))
                ) {
                    commit
                        .ok_or(KernelRuntimeResponsePreparationErrorV2::Unavailable)?
                        .claim()
                        .map_err(map_commit_preparation_error)?;
                }
                builder.prepare((self.0)(context))
            }
        }

        Self::spawn(capacity, TestSupportServicesV2(handler))
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn dispatch(
        &self,
        peer: VerifiedKernelServicePeerV2,
        lease: V2GenerationLease,
        request_id: RequestIdV2,
        operation: KernelServiceOperationV2,
        logical_deadline: UnixMillisV2,
        now: UnixMillisV2,
        deadline: Instant,
        response_builder: KernelRuntimeResponseBuilderV2,
    ) -> Result<PreparedKernelServiceResponseV2, KernelRuntimeOwnerErrorV2> {
        if Instant::now() >= deadline {
            return Err(KernelRuntimeOwnerErrorV2::DeadlineExceeded);
        }
        let handler =
            handler_for_operation_v2(&operation).map_err(KernelRuntimeOwnerErrorV2::Operation)?;
        if handler.role() != peer.role()
            || handler.tag() != operation.tag()
            || now.get() == 0
            || lease
                .active_state_manifest_digest()
                .as_bytes()
                .iter()
                .all(|byte| *byte == 0)
        {
            return Err(KernelRuntimeOwnerErrorV2::Operation(
                StableCode::IdentityPeerRejected,
            ));
        }
        self.owner
            .request(
                KernelRuntimeRequestV2 {
                    context: KernelRuntimeRequestContextV2 {
                        peer,
                        lease,
                        request_id,
                        logical_deadline,
                        now,
                        handler,
                        operation,
                    },
                    response_builder,
                },
                deadline,
            )
            .map_err(map_owner_error)?
            .map_err(|error| match error {
                KernelRuntimeResponsePreparationErrorV2::DeadlineExceeded => {
                    KernelRuntimeOwnerErrorV2::DeadlineExceeded
                }
                KernelRuntimeResponsePreparationErrorV2::Unavailable => {
                    KernelRuntimeOwnerErrorV2::Unavailable
                }
            })
    }

    #[cfg(test)]
    pub(crate) fn queued_for_test(&self) -> usize {
        self.owner.queued_for_test()
    }
}

const fn map_commit_preparation_error(
    error: StateOwnerErrorV2,
) -> KernelRuntimeResponsePreparationErrorV2 {
    match error {
        StateOwnerErrorV2::DeadlineExceeded => {
            KernelRuntimeResponsePreparationErrorV2::DeadlineExceeded
        }
        StateOwnerErrorV2::RuntimeBusy | StateOwnerErrorV2::RuntimeUnavailable => {
            KernelRuntimeResponsePreparationErrorV2::Unavailable
        }
    }
}

const fn map_owner_error(error: StateOwnerErrorV2) -> KernelRuntimeOwnerErrorV2 {
    match error {
        StateOwnerErrorV2::RuntimeBusy => KernelRuntimeOwnerErrorV2::Busy,
        StateOwnerErrorV2::DeadlineExceeded => KernelRuntimeOwnerErrorV2::DeadlineExceeded,
        StateOwnerErrorV2::RuntimeUnavailable => KernelRuntimeOwnerErrorV2::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use savana_kernel_protocol::v2::{
        kernel_agent_operation_tags_v2, kernel_connector_control_operation_tags_v2,
        kernel_ingress_operation_tags_v2, EndpointRoleV2, ExecutorHealthRequestV2,
        KernelExecutorOperationV2, KernelServiceOperationV2,
    };
    use savana_kernel_protocol::StableCode;

    use super::{handler_for_operation_v2, ALL_KERNEL_RUNTIME_HANDLERS_V2};

    #[test]
    fn exhaustive_handler_table_covers_all_49_kerneld_operations_once() {
        assert_eq!(ALL_KERNEL_RUNTIME_HANDLERS_V2.len(), 49);
        let actual = ALL_KERNEL_RUNTIME_HANDLERS_V2
            .into_iter()
            .map(|handler| (role_tag(handler.role()), handler.tag()))
            .collect::<BTreeSet<_>>();
        assert_eq!(actual.len(), 49);

        let expected = kernel_agent_operation_tags_v2()
            .iter()
            .map(|tag| (role_tag(EndpointRoleV2::AgentKernel), *tag))
            .chain(
                kernel_connector_control_operation_tags_v2()
                    .iter()
                    .map(|tag| (role_tag(EndpointRoleV2::AgentKernel), *tag)),
            )
            .chain(
                kernel_ingress_operation_tags_v2()
                    .iter()
                    .map(|tag| (role_tag(EndpointRoleV2::IngressKernel), *tag)),
            )
            .collect::<BTreeSet<_>>();
        assert_eq!(actual, expected);
    }

    const fn role_tag(role: EndpointRoleV2) -> u8 {
        match role {
            EndpointRoleV2::AgentKernel => 1,
            EndpointRoleV2::IngressKernel => 2,
            _ => 0,
        }
    }

    #[test]
    fn kernel_executor_has_no_kerneld_handler() {
        let operation = KernelServiceOperationV2::executor(KernelExecutorOperationV2::Health(
            ExecutorHealthRequestV2,
        ));
        assert_eq!(
            handler_for_operation_v2(&operation),
            Err(StableCode::IdentityPeerRejected)
        );
    }
}
