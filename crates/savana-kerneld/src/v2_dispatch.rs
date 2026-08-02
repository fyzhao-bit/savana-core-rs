use std::sync::{Arc, Mutex};
use std::time::Instant;

use ed25519_dalek::SigningKey;
use savana_kernel_protocol::v2::{
    decode_kernel_service_request_envelope_v2, encode_kernel_service_application_response_v2,
    sign_kernel_service_response_envelope_v2, BootIdV2, Digest32V2, Ed25519KeyIdV2, EndpointRoleV2,
    KernelServiceApplicationRequestV2, KernelServiceApplicationResponseV2,
    KernelServiceRequestEnvelopeV2, KernelServiceResponseEnvelopeV2, KernelServiceResponseV2,
    PublicStableCodeV2, RequestIdV2, ServiceIdentityV2, UnixMillisV2, V2ServerTransportSession,
};
use savana_kernel_protocol::StableCode;

use crate::policy_runtime::V2GenerationLease;
use crate::v2_kernel_owner::{KernelRuntimeOwnerErrorV2, KernelRuntimeOwnerV2};

const MAX_RESPONSE_BODY_BYTES: usize = 8 * 1024 * 1024;

#[cfg(test)]
type KernelResponseFailureV2 = Option<KernelResponseFailurePointV2>;
#[cfg(not(test))]
type KernelResponseFailureV2 = Option<()>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct KernelServiceDeploymentV2 {
    kernel_boot_id: BootIdV2,
    kernel_identity: ServiceIdentityV2,
    active_state_manifest_digest: Digest32V2,
    deployment_generation: u64,
}

impl KernelServiceDeploymentV2 {
    pub(crate) fn from_verified_startup(
        kernel_boot_id: BootIdV2,
        kernel_identity: ServiceIdentityV2,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
    ) -> Result<Self, KernelServiceDispatchErrorV2> {
        if is_zero(kernel_boot_id.as_bytes())
            || is_zero(kernel_identity.as_bytes())
            || is_zero(active_state_manifest_digest.as_bytes())
            || deployment_generation == 0
        {
            return Err(KernelServiceDispatchErrorV2::Unavailable);
        }
        Ok(Self {
            kernel_boot_id,
            kernel_identity,
            active_state_manifest_digest,
            deployment_generation,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct VerifiedKernelServicePeerV2 {
    role: EndpointRoleV2,
    caller_boot_id: BootIdV2,
    caller_identity: ServiceIdentityV2,
}

impl VerifiedKernelServicePeerV2 {
    pub(crate) fn from_mutual_authentication(
        role: EndpointRoleV2,
        caller_boot_id: BootIdV2,
        caller_identity: ServiceIdentityV2,
    ) -> Result<Self, KernelServiceDispatchErrorV2> {
        if !matches!(
            role,
            EndpointRoleV2::AgentKernel
                | EndpointRoleV2::IngressKernel
                | EndpointRoleV2::KernelExecutor
        ) || is_zero(caller_boot_id.as_bytes())
            || is_zero(caller_identity.as_bytes())
        {
            return Err(KernelServiceDispatchErrorV2::IdentityRejected);
        }
        Ok(Self {
            role,
            caller_boot_id,
            caller_identity,
        })
    }

    pub(crate) const fn role(self) -> EndpointRoleV2 {
        self.role
    }

    pub(crate) const fn caller_identity(self) -> ServiceIdentityV2 {
        self.caller_identity
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KernelServiceResponseBodyV2(Vec<u8>);

impl KernelServiceResponseBodyV2 {
    pub(crate) fn from_typed_handler(
        canonical_body: Vec<u8>,
    ) -> Result<Self, KernelServiceDispatchErrorV2> {
        if canonical_body.is_empty() || canonical_body.len() > MAX_RESPONSE_BODY_BYTES {
            return Err(KernelServiceDispatchErrorV2::Unavailable);
        }
        KernelServiceResponseV2::success(canonical_body.clone())
            .map_err(|_| KernelServiceDispatchErrorV2::Unavailable)?;
        Ok(Self(canonical_body))
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

pub(crate) enum PreparedKernelServiceResponseV2 {
    Body(Result<KernelServiceResponseBodyV2, StableCode>),
    Application(KernelServiceApplicationResponseV2),
    Signed(Vec<u8>),
    SuiteOne(Vec<u8>),
}

pub(crate) enum KernelRuntimeResponseBuilderV2 {
    Body,
    Application {
        role: EndpointRoleV2,
        request_id: RequestIdV2,
        operation_tag: u16,
    },
    Signed {
        role: EndpointRoleV2,
        request_id: RequestIdV2,
        operation_tag: u16,
        deployment: KernelServiceDeploymentV2,
        signing_key_id: Ed25519KeyIdV2,
        signing_key: Arc<SigningKey>,
    },
    SuiteOne {
        role: EndpointRoleV2,
        request_id: RequestIdV2,
        operation_tag: u16,
        session: SuiteOneResponseSessionSlotV2,
    },
    #[cfg(test)]
    InjectedFailure {
        point: KernelResponseFailurePointV2,
        inner: Box<KernelRuntimeResponseBuilderV2>,
    },
}

impl KernelRuntimeResponseBuilderV2 {
    pub(crate) fn prepare_canonical_success(
        self,
        canonical_body: Vec<u8>,
    ) -> Result<PreparedKernelServiceResponseV2, KernelRuntimeResponsePreparationErrorV2> {
        #[cfg(test)]
        if matches!(
            &self,
            Self::InjectedFailure {
                point: KernelResponseFailurePointV2::TypedWrapper,
                ..
            }
        ) {
            return Err(KernelRuntimeResponsePreparationErrorV2::Unavailable);
        }
        let body = KernelServiceResponseBodyV2::from_typed_handler(canonical_body)
            .map_err(|_| KernelRuntimeResponsePreparationErrorV2::Unavailable)?;
        self.prepare(Ok(body))
    }

    pub(crate) fn prepare(
        self,
        outcome: Result<KernelServiceResponseBodyV2, StableCode>,
    ) -> Result<PreparedKernelServiceResponseV2, KernelRuntimeResponsePreparationErrorV2> {
        match self {
            #[cfg(test)]
            Self::InjectedFailure { point, inner } => match (point, *inner) {
                (KernelResponseFailurePointV2::TypedWrapper, _) => {
                    Err(KernelRuntimeResponsePreparationErrorV2::Unavailable)
                }
                (
                    KernelResponseFailurePointV2::ApplicationWrapper,
                    KernelRuntimeResponseBuilderV2::Application { .. },
                )
                | (
                    KernelResponseFailurePointV2::SignedEnvelope,
                    KernelRuntimeResponseBuilderV2::Signed { .. },
                )
                | (
                    KernelResponseFailurePointV2::SuiteOneSeal,
                    KernelRuntimeResponseBuilderV2::SuiteOne { .. },
                ) => Err(KernelRuntimeResponsePreparationErrorV2::Unavailable),
                (_, inner) => inner.prepare(outcome),
            },
            Self::Body => Ok(PreparedKernelServiceResponseV2::Body(outcome)),
            Self::Application {
                role,
                request_id,
                operation_tag,
            } => build_application_response(role, request_id, operation_tag, outcome)
                .map(PreparedKernelServiceResponseV2::Application),
            Self::Signed {
                role,
                request_id,
                operation_tag,
                deployment,
                signing_key_id,
                signing_key,
            } => {
                let response = match outcome {
                    Ok(body) => KernelServiceResponseV2::success(body.0)
                        .map_err(|_| KernelRuntimeResponsePreparationErrorV2::Unavailable)?,
                    Err(error) => KernelServiceResponseV2::error(error),
                };
                let envelope = KernelServiceResponseEnvelopeV2::from_authenticated_connection(
                    role,
                    request_id,
                    deployment.kernel_boot_id,
                    deployment.kernel_identity,
                    deployment.active_state_manifest_digest,
                    deployment.deployment_generation,
                    operation_tag,
                    response,
                )
                .map_err(|_| KernelRuntimeResponsePreparationErrorV2::Unavailable)?;
                sign_kernel_service_response_envelope_v2(
                    &envelope,
                    signing_key_id,
                    signing_key.as_ref(),
                )
                .map(PreparedKernelServiceResponseV2::Signed)
                .map_err(|_| KernelRuntimeResponsePreparationErrorV2::Unavailable)
            }
            Self::SuiteOne {
                role,
                request_id,
                operation_tag,
                session,
            } => {
                let response =
                    build_application_response(role, request_id, operation_tag, outcome)?;
                let plaintext = encode_kernel_service_application_response_v2(&response)
                    .map_err(|_| KernelRuntimeResponsePreparationErrorV2::Unavailable)?;
                session
                    .seal(request_id, operation_tag, &plaintext)
                    .map(PreparedKernelServiceResponseV2::SuiteOne)
            }
        }
    }
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KernelResponseFailurePointV2 {
    TypedWrapper,
    ApplicationWrapper,
    SignedEnvelope,
    SuiteOneSeal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KernelRuntimeResponsePreparationErrorV2 {
    Unavailable,
}

#[derive(Clone)]
pub(crate) struct SuiteOneResponseSessionSlotV2 {
    session: Arc<Mutex<Option<V2ServerTransportSession>>>,
}

impl SuiteOneResponseSessionSlotV2 {
    pub(crate) fn new(session: V2ServerTransportSession) -> Self {
        Self {
            session: Arc::new(Mutex::new(Some(session))),
        }
    }

    fn seal(
        &self,
        request_id: RequestIdV2,
        operation_tag: u16,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, KernelRuntimeResponsePreparationErrorV2> {
        let mut guard = self
            .session
            .lock()
            .map_err(|_| KernelRuntimeResponsePreparationErrorV2::Unavailable)?;
        let mut session = guard
            .take()
            .ok_or(KernelRuntimeResponsePreparationErrorV2::Unavailable)?;
        match session.seal_application_response(request_id, operation_tag, plaintext) {
            Ok(record) => Ok(record),
            Err(_) => {
                *guard = Some(session);
                Err(KernelRuntimeResponsePreparationErrorV2::Unavailable)
            }
        }
    }

    pub(crate) fn seal_public_error(
        &self,
        role: EndpointRoleV2,
        request_id: RequestIdV2,
        operation_tag: u16,
        error: PublicStableCodeV2,
    ) -> Result<Vec<u8>, KernelServiceDispatchErrorV2> {
        let response =
            KernelServiceApplicationResponseV2::error(role, request_id, operation_tag, error)
                .map_err(|_| KernelServiceDispatchErrorV2::Unavailable)?;
        let plaintext = encode_kernel_service_application_response_v2(&response)
            .map_err(|_| KernelServiceDispatchErrorV2::Unavailable)?;
        self.seal(request_id, operation_tag, &plaintext)
            .map_err(|_| KernelServiceDispatchErrorV2::Unavailable)
    }
}

fn build_application_response(
    role: EndpointRoleV2,
    request_id: RequestIdV2,
    operation_tag: u16,
    outcome: Result<KernelServiceResponseBodyV2, StableCode>,
) -> Result<KernelServiceApplicationResponseV2, KernelRuntimeResponsePreparationErrorV2> {
    match outcome {
        Ok(body) => {
            KernelServiceApplicationResponseV2::success(role, request_id, operation_tag, body.0)
        }
        Err(error) => KernelServiceApplicationResponseV2::error(
            role,
            request_id,
            operation_tag,
            public_error_code(error),
        ),
    }
    .map_err(|_| KernelRuntimeResponsePreparationErrorV2::Unavailable)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KernelServiceDispatchErrorV2 {
    Malformed,
    IdentityRejected,
    DeadlineExceeded,
    Busy,
    Unavailable,
    Operation(StableCode),
}

pub(crate) struct KernelServiceDispatcherV2 {
    deployment: KernelServiceDeploymentV2,
    signing_key_id: Ed25519KeyIdV2,
    signing_key: Arc<SigningKey>,
    owner: Arc<KernelRuntimeOwnerV2>,
}

impl std::fmt::Debug for KernelServiceDispatcherV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("KernelServiceDispatcherV2")
            .field(
                "deployment_generation",
                &self.deployment.deployment_generation,
            )
            .finish_non_exhaustive()
    }
}

impl KernelServiceDispatcherV2 {
    pub(crate) fn spawn(
        deployment: KernelServiceDeploymentV2,
        signing_key_id: Ed25519KeyIdV2,
        signing_key: SigningKey,
        owner: impl Into<Arc<KernelRuntimeOwnerV2>>,
    ) -> Result<Self, KernelServiceDispatchErrorV2> {
        if is_zero(signing_key_id.as_bytes()) {
            return Err(KernelServiceDispatchErrorV2::Unavailable);
        }
        Ok(Self {
            deployment,
            signing_key_id,
            signing_key: Arc::new(signing_key),
            owner: owner.into(),
        })
    }

    pub(crate) fn matches_generation(
        &self,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
    ) -> bool {
        self.deployment.active_state_manifest_digest == active_state_manifest_digest
            && self.deployment.deployment_generation == deployment_generation
    }

    pub(crate) fn dispatch_one(
        &self,
        peer: VerifiedKernelServicePeerV2,
        lease: V2GenerationLease,
        canonical_request: &[u8],
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<KernelServiceResponseBodyV2, KernelServiceDispatchErrorV2> {
        if Instant::now() >= deadline {
            return Err(KernelServiceDispatchErrorV2::DeadlineExceeded);
        }
        let request = decode_kernel_service_request_envelope_v2(canonical_request)
            .map_err(|_| KernelServiceDispatchErrorV2::Malformed)?;
        self.validate_connection_binding(peer, &request, now)?;
        self.validate_generation_lease(&lease)?;
        let request_id = request.request_id();
        match self
            .owner
            .dispatch(
                peer,
                lease,
                request_id,
                request.into_operation(),
                now,
                deadline,
                KernelRuntimeResponseBuilderV2::Body,
            )
            .map_err(map_runtime_owner_error)?
        {
            PreparedKernelServiceResponseV2::Body(outcome) => {
                outcome.map_err(KernelServiceDispatchErrorV2::Operation)
            }
            _ => unreachable!("closed body response builder returned another variant"),
        }
    }

    pub(crate) fn dispatch_one_application(
        &self,
        peer: VerifiedKernelServicePeerV2,
        lease: V2GenerationLease,
        request: KernelServiceApplicationRequestV2,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<KernelServiceApplicationResponseV2, KernelServiceDispatchErrorV2> {
        self.dispatch_one_application_inner(peer, lease, request, now, deadline, None)
    }

    #[cfg(test)]
    pub(crate) fn dispatch_one_application_with_failure_for_test(
        &self,
        peer: VerifiedKernelServicePeerV2,
        lease: V2GenerationLease,
        request: KernelServiceApplicationRequestV2,
        now: UnixMillisV2,
        deadline: Instant,
        point: KernelResponseFailurePointV2,
    ) -> Result<KernelServiceApplicationResponseV2, KernelServiceDispatchErrorV2> {
        self.dispatch_one_application_inner(peer, lease, request, now, deadline, Some(point))
    }

    fn dispatch_one_application_inner(
        &self,
        peer: VerifiedKernelServicePeerV2,
        lease: V2GenerationLease,
        request: KernelServiceApplicationRequestV2,
        now: UnixMillisV2,
        deadline: Instant,
        failure: KernelResponseFailureV2,
    ) -> Result<KernelServiceApplicationResponseV2, KernelServiceDispatchErrorV2> {
        #[cfg(not(test))]
        let _ = failure;
        if Instant::now() >= deadline || now.get() == 0 || now.get() >= request.deadline().get() {
            return Err(KernelServiceDispatchErrorV2::DeadlineExceeded);
        }
        if request.role() != peer.role {
            return Err(KernelServiceDispatchErrorV2::IdentityRejected);
        }
        self.validate_generation_lease(&lease)?;
        let (role, request_id, _, operation) = request.into_parts();
        let operation_tag = operation.tag();
        let builder = KernelRuntimeResponseBuilderV2::Application {
            role,
            request_id,
            operation_tag,
        };
        #[cfg(test)]
        let builder = match failure {
            Some(point) => KernelRuntimeResponseBuilderV2::InjectedFailure {
                point,
                inner: Box::new(builder),
            },
            None => builder,
        };
        let prepared = self
            .owner
            .dispatch(peer, lease, request_id, operation, now, deadline, builder)
            .map_err(map_runtime_owner_error)?;
        match prepared {
            PreparedKernelServiceResponseV2::Application(response) => Ok(response),
            _ => unreachable!("closed application response builder returned another variant"),
        }
    }

    pub(crate) fn dispatch_one_suite_one(
        &self,
        peer: VerifiedKernelServicePeerV2,
        lease: V2GenerationLease,
        request: KernelServiceApplicationRequestV2,
        session: SuiteOneResponseSessionSlotV2,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<Vec<u8>, KernelServiceDispatchErrorV2> {
        self.dispatch_one_suite_one_inner(peer, lease, request, session, now, deadline, None)
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn dispatch_one_suite_one_with_failure_for_test(
        &self,
        peer: VerifiedKernelServicePeerV2,
        lease: V2GenerationLease,
        request: KernelServiceApplicationRequestV2,
        session: SuiteOneResponseSessionSlotV2,
        now: UnixMillisV2,
        deadline: Instant,
        point: KernelResponseFailurePointV2,
    ) -> Result<Vec<u8>, KernelServiceDispatchErrorV2> {
        self.dispatch_one_suite_one_inner(peer, lease, request, session, now, deadline, Some(point))
    }

    #[allow(clippy::too_many_arguments)]
    fn dispatch_one_suite_one_inner(
        &self,
        peer: VerifiedKernelServicePeerV2,
        lease: V2GenerationLease,
        request: KernelServiceApplicationRequestV2,
        session: SuiteOneResponseSessionSlotV2,
        now: UnixMillisV2,
        deadline: Instant,
        failure: KernelResponseFailureV2,
    ) -> Result<Vec<u8>, KernelServiceDispatchErrorV2> {
        #[cfg(not(test))]
        let _ = failure;
        if Instant::now() >= deadline || now.get() == 0 || now.get() >= request.deadline().get() {
            return Err(KernelServiceDispatchErrorV2::DeadlineExceeded);
        }
        if request.role() != peer.role {
            return Err(KernelServiceDispatchErrorV2::IdentityRejected);
        }
        self.validate_generation_lease(&lease)?;
        let (role, request_id, _, operation) = request.into_parts();
        let operation_tag = operation.tag();
        let builder = KernelRuntimeResponseBuilderV2::SuiteOne {
            role,
            request_id,
            operation_tag,
            session,
        };
        #[cfg(test)]
        let builder = match failure {
            Some(point) => KernelRuntimeResponseBuilderV2::InjectedFailure {
                point,
                inner: Box::new(builder),
            },
            None => builder,
        };
        let prepared = self
            .owner
            .dispatch(peer, lease, request_id, operation, now, deadline, builder)
            .map_err(map_runtime_owner_error)?;
        match prepared {
            PreparedKernelServiceResponseV2::SuiteOne(record) => Ok(record),
            _ => unreachable!("closed Suite-1 response builder returned another variant"),
        }
    }

    pub(crate) fn dispatch_one_signed(
        &self,
        peer: VerifiedKernelServicePeerV2,
        lease: V2GenerationLease,
        canonical_request: &[u8],
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<Vec<u8>, KernelServiceDispatchErrorV2> {
        self.dispatch_one_signed_inner(peer, lease, canonical_request, now, deadline, None)
    }

    #[cfg(test)]
    pub(crate) fn dispatch_one_signed_with_failure_for_test(
        &self,
        peer: VerifiedKernelServicePeerV2,
        lease: V2GenerationLease,
        canonical_request: &[u8],
        now: UnixMillisV2,
        deadline: Instant,
        point: KernelResponseFailurePointV2,
    ) -> Result<Vec<u8>, KernelServiceDispatchErrorV2> {
        self.dispatch_one_signed_inner(peer, lease, canonical_request, now, deadline, Some(point))
    }

    fn dispatch_one_signed_inner(
        &self,
        peer: VerifiedKernelServicePeerV2,
        lease: V2GenerationLease,
        canonical_request: &[u8],
        now: UnixMillisV2,
        deadline: Instant,
        failure: KernelResponseFailureV2,
    ) -> Result<Vec<u8>, KernelServiceDispatchErrorV2> {
        if Instant::now() >= deadline {
            return Err(KernelServiceDispatchErrorV2::DeadlineExceeded);
        }
        let request = decode_kernel_service_request_envelope_v2(canonical_request)
            .map_err(|_| KernelServiceDispatchErrorV2::Malformed)?;
        self.validate_connection_binding(peer, &request, now)?;
        self.validate_generation_lease(&lease)?;
        self.dispatch_verified_request(peer, lease, request, now, deadline, failure)
    }

    fn dispatch_verified_request(
        &self,
        peer: VerifiedKernelServicePeerV2,
        lease: V2GenerationLease,
        request: KernelServiceRequestEnvelopeV2,
        now: UnixMillisV2,
        deadline: Instant,
        failure: KernelResponseFailureV2,
    ) -> Result<Vec<u8>, KernelServiceDispatchErrorV2> {
        #[cfg(not(test))]
        let _ = failure;
        let role = request.role();
        let request_id = request.request_id();
        let operation_tag = request.operation().tag();
        let builder = KernelRuntimeResponseBuilderV2::Signed {
            role,
            request_id,
            operation_tag,
            deployment: self.deployment,
            signing_key_id: self.signing_key_id,
            signing_key: Arc::clone(&self.signing_key),
        };
        #[cfg(test)]
        let builder = match failure {
            Some(point) => KernelRuntimeResponseBuilderV2::InjectedFailure {
                point,
                inner: Box::new(builder),
            },
            None => builder,
        };
        let prepared = self
            .owner
            .dispatch(
                peer,
                lease,
                request_id,
                request.into_operation(),
                now,
                deadline,
                builder,
            )
            .map_err(map_runtime_owner_error)?;
        match prepared {
            PreparedKernelServiceResponseV2::Signed(response) => Ok(response),
            _ => unreachable!("closed signed response builder returned another variant"),
        }
    }

    fn validate_generation_lease(
        &self,
        lease: &V2GenerationLease,
    ) -> Result<(), KernelServiceDispatchErrorV2> {
        if lease.active_state_manifest_digest() != self.deployment.active_state_manifest_digest
            || lease.deployment_generation() != self.deployment.deployment_generation
        {
            return Err(KernelServiceDispatchErrorV2::IdentityRejected);
        }
        Ok(())
    }

    fn validate_connection_binding(
        &self,
        peer: VerifiedKernelServicePeerV2,
        request: &KernelServiceRequestEnvelopeV2,
        now: UnixMillisV2,
    ) -> Result<(), KernelServiceDispatchErrorV2> {
        if now.get() == 0 || now.get() >= request.deadline().get() {
            return Err(KernelServiceDispatchErrorV2::DeadlineExceeded);
        }
        if request.role() != peer.role
            || request.caller_boot_id() != peer.caller_boot_id
            || request.caller_identity() != peer.caller_identity
            || request.service_boot_id() != self.deployment.kernel_boot_id
            || request.service_identity() != self.deployment.kernel_identity
            || request.active_state_manifest_digest()
                != self.deployment.active_state_manifest_digest
            || request.deployment_generation() != self.deployment.deployment_generation
        {
            return Err(KernelServiceDispatchErrorV2::IdentityRejected);
        }
        Ok(())
    }
}

const fn public_error_code(error: StableCode) -> PublicStableCodeV2 {
    match error {
        StableCode::DeadlineExceeded => PublicStableCodeV2::DeadlineExceeded,
        StableCode::KernelOverloaded => PublicStableCodeV2::Overloaded,
        StableCode::KernelUnavailable => PublicStableCodeV2::ServiceUnavailable,
        StableCode::PolicyLimitExceeded | StableCode::ApprovalLedgerFull => {
            PublicStableCodeV2::LimitExceeded
        }
        StableCode::PolicyDenied => PublicStableCodeV2::PolicyDenied,
        StableCode::PolicyExpired => PublicStableCodeV2::PolicyExpired,
        StableCode::CancellationTooLate => PublicStableCodeV2::CancellationTooLate,
        StableCode::ApprovalBindingMismatch => PublicStableCodeV2::ApprovalBindingMismatch,
        StableCode::ApprovalReplayed => PublicStableCodeV2::ApprovalReplay,
        StableCode::HandleUnknown
        | StableCode::HandleWrongClient
        | StableCode::HandleWrongConnection
        | StableCode::HandleWrongRun
        | StableCode::HandleWrongType
        | StableCode::HandleStalePolicy
        | StableCode::HandleStaleRegistry
        | StableCode::HandleAlreadyConsumed
        | StableCode::HandleInvalidatedBoot => PublicStableCodeV2::InvalidReference,
        _ => PublicStableCodeV2::InternalFatal,
    }
}

const fn map_runtime_owner_error(error: KernelRuntimeOwnerErrorV2) -> KernelServiceDispatchErrorV2 {
    match error {
        KernelRuntimeOwnerErrorV2::Busy => KernelServiceDispatchErrorV2::Busy,
        KernelRuntimeOwnerErrorV2::DeadlineExceeded => {
            KernelServiceDispatchErrorV2::DeadlineExceeded
        }
        KernelRuntimeOwnerErrorV2::Unavailable => KernelServiceDispatchErrorV2::Unavailable,
        KernelRuntimeOwnerErrorV2::Operation(code) => KernelServiceDispatchErrorV2::Operation(code),
    }
}

fn is_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use ed25519_dalek::SigningKey;
    use savana_kernel_protocol::v2::{
        encode_kernel_service_request_envelope_v2, verify_kernel_service_response_envelope_v2,
        BootIdV2, Digest32V2, DispatchExecutionRequestV2, Ed25519KeyIdV2, EndpointRoleV2,
        ExecutionTicketHandleV2, KernelAgentOperationV2, KernelExecutorOperationV2,
        KernelServiceApplicationRequestV2, KernelServiceApplicationResponseBodyV2,
        KernelServiceOperationV2, KernelServiceRequestEnvelopeV2, Nonce32V2,
        QueryByExecutionNonceRequestV2, RequestIdV2, ServiceIdentityV2, UnixMillisV2,
    };

    use super::{
        KernelServiceDeploymentV2, KernelServiceDispatchErrorV2, KernelServiceDispatcherV2,
        KernelServiceResponseBodyV2, VerifiedKernelServicePeerV2,
    };
    use crate::policy_runtime::V2GenerationLease;
    use crate::v2_kernel_owner::{KernelRuntimeHandlerV2, KernelRuntimeOwnerV2};

    fn deployment() -> KernelServiceDeploymentV2 {
        KernelServiceDeploymentV2::from_verified_startup(
            BootIdV2::new([1; 32]),
            ServiceIdentityV2::new([2; 32]),
            Digest32V2::new([3; 32]),
            4,
        )
        .unwrap()
    }

    fn peer(role: EndpointRoleV2) -> VerifiedKernelServicePeerV2 {
        VerifiedKernelServicePeerV2::from_mutual_authentication(
            role,
            BootIdV2::new([5; 32]),
            ServiceIdentityV2::new([6; 32]),
        )
        .unwrap()
    }

    fn request(role: EndpointRoleV2, tag: u16) -> Vec<u8> {
        encode_kernel_service_request_envelope_v2(
            &KernelServiceRequestEnvelopeV2::from_authenticated_connection(
                role,
                RequestIdV2::new([7; 16]),
                BootIdV2::new([5; 32]),
                BootIdV2::new([1; 32]),
                ServiceIdentityV2::new([6; 32]),
                ServiceIdentityV2::new([2; 32]),
                Digest32V2::new([3; 32]),
                4,
                UnixMillisV2::new(1_000),
                operation(role, tag),
            )
            .unwrap(),
        )
        .unwrap()
    }

    fn operation(role: EndpointRoleV2, tag: u16) -> KernelServiceOperationV2 {
        match (role, tag) {
            (EndpointRoleV2::AgentKernel, 29) => KernelServiceOperationV2::agent(
                KernelAgentOperationV2::DispatchExecution(DispatchExecutionRequestV2::new(
                    ExecutionTicketHandleV2::from_authority_entropy([29; 32]).unwrap(),
                )),
            ),
            (EndpointRoleV2::KernelExecutor, 61) => KernelServiceOperationV2::executor(
                KernelExecutorOperationV2::QueryByExecutionNonce(
                    QueryByExecutionNonceRequestV2::new(
                        Nonce32V2::new([61; 32]),
                        Digest32V2::new([62; 32]),
                        Digest32V2::new([63; 32]),
                    )
                    .unwrap(),
                ),
            ),
            _ => panic!("unsupported test operation"),
        }
    }

    fn signing() -> (Ed25519KeyIdV2, SigningKey) {
        (
            Ed25519KeyIdV2::new([8; 32]),
            SigningKey::from_bytes(&[9; 32]),
        )
    }

    fn lease() -> V2GenerationLease {
        V2GenerationLease::for_dispatch_test(Digest32V2::new([3; 32]), 4)
    }

    #[test]
    fn authenticated_role_binding_is_checked_before_state_owner_invocation() {
        let calls = Arc::new(AtomicUsize::new(0));
        let handled = Arc::clone(&calls);
        let (key_id, key) = signing();
        let owner = KernelRuntimeOwnerV2::spawn_for_test(4, move |request| {
            handled.fetch_add(1, Ordering::SeqCst);
            assert_eq!(request.peer().role(), EndpointRoleV2::AgentKernel);
            assert_eq!(request.handler(), KernelRuntimeHandlerV2::DispatchExecution);
            assert_eq!(request.operation().tag(), 29);
            KernelServiceResponseBodyV2::from_typed_handler(vec![0x80])
                .map_err(|_| savana_kernel_protocol::StableCode::KernelUnavailable)
        })
        .unwrap();
        let dispatcher =
            KernelServiceDispatcherV2::spawn(deployment(), key_id, key, owner).unwrap();

        assert_eq!(
            dispatcher.dispatch_one(
                peer(EndpointRoleV2::IngressKernel),
                lease(),
                &request(EndpointRoleV2::AgentKernel, 29),
                UnixMillisV2::new(100),
                Instant::now() + Duration::from_secs(1),
            ),
            Err(KernelServiceDispatchErrorV2::IdentityRejected)
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);

        assert_eq!(
            dispatcher
                .dispatch_one(
                    peer(EndpointRoleV2::AgentKernel),
                    lease(),
                    &request(EndpointRoleV2::AgentKernel, 29),
                    UnixMillisV2::new(100),
                    Instant::now() + Duration::from_secs(1),
                )
                .unwrap()
                .as_bytes(),
            &[0x80]
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn handler_panic_permanently_fails_the_dispatch_owner() {
        let (key_id, key) = signing();
        let owner = KernelRuntimeOwnerV2::spawn_for_test(1, |_| {
            panic!("state invariant");
        })
        .unwrap();
        let dispatcher =
            KernelServiceDispatcherV2::spawn(deployment(), key_id, key, owner).unwrap();
        let first = dispatcher.dispatch_one(
            peer(EndpointRoleV2::AgentKernel),
            lease(),
            &request(EndpointRoleV2::AgentKernel, 29),
            UnixMillisV2::new(100),
            Instant::now() + Duration::from_secs(1),
        );
        assert_eq!(first, Err(KernelServiceDispatchErrorV2::Unavailable));
        assert_eq!(
            dispatcher.dispatch_one(
                peer(EndpointRoleV2::AgentKernel),
                lease(),
                &request(EndpointRoleV2::AgentKernel, 29),
                UnixMillisV2::new(100),
                Instant::now() + Duration::from_secs(1),
            ),
            Err(KernelServiceDispatchErrorV2::Unavailable)
        );
    }

    #[test]
    fn signed_dispatch_binds_response_to_request_role_operation_and_deployment() {
        let (key_id, key) = signing();
        let public_key = key.verifying_key().to_bytes();
        let owner = KernelRuntimeOwnerV2::spawn_for_test(2, |_| {
            Ok(KernelServiceResponseBodyV2::from_typed_handler(vec![0x80]).unwrap())
        })
        .unwrap();
        let dispatcher =
            KernelServiceDispatcherV2::spawn(deployment(), key_id, key, owner).unwrap();

        let signed = dispatcher
            .dispatch_one_signed(
                peer(EndpointRoleV2::AgentKernel),
                lease(),
                &request(EndpointRoleV2::AgentKernel, 29),
                UnixMillisV2::new(100),
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap();
        let response =
            verify_kernel_service_response_envelope_v2(&signed, key_id, public_key).unwrap();
        assert_eq!(response.role(), EndpointRoleV2::AgentKernel);
        assert_eq!(response.operation_tag(), 29);
        assert_eq!(response.request_id(), RequestIdV2::new([7; 16]));
        assert_eq!(
            response.response().canonical_body(),
            Some([0x80].as_slice())
        );
    }

    #[test]
    fn suite_one_dispatch_uses_authenticated_role_and_closed_public_response() {
        let (key_id, key) = signing();
        let owner = KernelRuntimeOwnerV2::spawn_for_test(2, |_| {
            Ok(KernelServiceResponseBodyV2::from_typed_handler(vec![0x80]).unwrap())
        })
        .unwrap();
        let dispatcher =
            KernelServiceDispatcherV2::spawn(deployment(), key_id, key, owner).unwrap();
        let wrong_request = KernelServiceApplicationRequestV2::new(
            EndpointRoleV2::AgentKernel,
            RequestIdV2::new([0x51; 16]),
            UnixMillisV2::new(1_000),
            operation(EndpointRoleV2::AgentKernel, 29),
        )
        .unwrap();

        assert!(dispatcher
            .dispatch_one_application(
                peer(EndpointRoleV2::IngressKernel),
                lease(),
                wrong_request,
                UnixMillisV2::new(100),
                Instant::now() + Duration::from_secs(1),
            )
            .is_err());
        let request = KernelServiceApplicationRequestV2::new(
            EndpointRoleV2::AgentKernel,
            RequestIdV2::new([0x51; 16]),
            UnixMillisV2::new(1_000),
            operation(EndpointRoleV2::AgentKernel, 29),
        )
        .unwrap();
        let response = dispatcher
            .dispatch_one_application(
                peer(EndpointRoleV2::AgentKernel),
                lease(),
                request,
                UnixMillisV2::new(100),
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap();
        assert_eq!(response.request_id(), RequestIdV2::new([0x51; 16]));
        assert_eq!(response.operation_tag(), 29);
        assert!(matches!(
            response.body(),
            KernelServiceApplicationResponseBodyV2::Success(body) if body == &[0x80]
        ));
    }
}
