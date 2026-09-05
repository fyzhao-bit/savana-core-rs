use crate::{ProtocolError, StableCode};

use super::{
    cbor::{scan_single, V2DecodeContext},
    kernel_service::validate_canonical_body,
    EndpointRoleV2, KernelServiceOperationV2, RequestIdV2, UnixMillisV2, PROTOCOL_MAJOR,
    PROTOCOL_MINOR,
};

const REQUEST_FIELDS: u64 = 3;
const REQUEST_HEADER_FIELDS: u64 = 5;
const RESPONSE_FIELDS: u64 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PublicStableCodeV2 {
    InvalidReference,
    StateConflict,
    IdempotencyConflict,
    CancellationTooLate,
    LimitExceeded,
    Overloaded,
    DeadlineExceeded,
    Cancelled,
    PolicyDenied,
    PolicyExpired,
    ArtifactRollback,
    RegistryMismatch,
    OntologyMismatch,
    ProjectionMismatch,
    ModelUnavailable,
    ModelContract,
    InputDenied,
    InputMalformed,
    ApprovalDenied,
    ApprovalExpired,
    ApprovalReplay,
    ApprovalBindingMismatch,
    ValidatorMissing,
    ValidatorRejected,
    ValidatorBindingMismatch,
    ExecutionFailedNoEffect,
    ExecutionIndeterminate,
    ResultUnavailable,
    StorageUnavailable,
    AuditUnavailable,
    EntropyUnavailable,
    ServiceUnavailable,
    InternalFatal,
}

impl PublicStableCodeV2 {
    pub const fn tag(self) -> u16 {
        match self {
            Self::InvalidReference => 20,
            Self::StateConflict => 23,
            Self::IdempotencyConflict => 24,
            Self::CancellationTooLate => 25,
            Self::LimitExceeded => 30,
            Self::Overloaded => 31,
            Self::DeadlineExceeded => 32,
            Self::Cancelled => 33,
            Self::PolicyDenied => 40,
            Self::PolicyExpired => 41,
            Self::ArtifactRollback => 42,
            Self::RegistryMismatch => 43,
            Self::OntologyMismatch => 44,
            Self::ProjectionMismatch => 45,
            Self::ModelUnavailable => 50,
            Self::ModelContract => 51,
            Self::InputDenied => 52,
            Self::InputMalformed => 53,
            Self::ApprovalDenied => 60,
            Self::ApprovalExpired => 61,
            Self::ApprovalReplay => 62,
            Self::ApprovalBindingMismatch => 63,
            Self::ValidatorMissing => 70,
            Self::ValidatorRejected => 71,
            Self::ValidatorBindingMismatch => 72,
            Self::ExecutionFailedNoEffect => 80,
            Self::ExecutionIndeterminate => 81,
            Self::ResultUnavailable => 82,
            Self::StorageUnavailable => 90,
            Self::AuditUnavailable => 91,
            Self::EntropyUnavailable => 92,
            Self::ServiceUnavailable => 93,
            Self::InternalFatal => 255,
        }
    }

    pub(super) fn from_tag(tag: u16) -> Result<Self, ProtocolError> {
        Ok(match tag {
            20 => Self::InvalidReference,
            23 => Self::StateConflict,
            24 => Self::IdempotencyConflict,
            25 => Self::CancellationTooLate,
            30 => Self::LimitExceeded,
            31 => Self::Overloaded,
            32 => Self::DeadlineExceeded,
            33 => Self::Cancelled,
            40 => Self::PolicyDenied,
            41 => Self::PolicyExpired,
            42 => Self::ArtifactRollback,
            43 => Self::RegistryMismatch,
            44 => Self::OntologyMismatch,
            45 => Self::ProjectionMismatch,
            50 => Self::ModelUnavailable,
            51 => Self::ModelContract,
            52 => Self::InputDenied,
            53 => Self::InputMalformed,
            60 => Self::ApprovalDenied,
            61 => Self::ApprovalExpired,
            62 => Self::ApprovalReplay,
            63 => Self::ApprovalBindingMismatch,
            70 => Self::ValidatorMissing,
            71 => Self::ValidatorRejected,
            72 => Self::ValidatorBindingMismatch,
            80 => Self::ExecutionFailedNoEffect,
            81 => Self::ExecutionIndeterminate,
            82 => Self::ResultUnavailable,
            90 => Self::StorageUnavailable,
            91 => Self::AuditUnavailable,
            92 => Self::EntropyUnavailable,
            93 => Self::ServiceUnavailable,
            255 => Self::InternalFatal,
            _ => return Err(malformed()),
        })
    }
}

#[derive(Debug)]
pub struct KernelServiceApplicationRequestV2 {
    role: EndpointRoleV2,
    request_id: RequestIdV2,
    deadline: UnixMillisV2,
    operation: KernelServiceOperationV2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KernelServiceApplicationRoutingV2 {
    role: EndpointRoleV2,
    request_id: RequestIdV2,
    deadline: UnixMillisV2,
    operation_tag: u16,
}

impl KernelServiceApplicationRoutingV2 {
    pub const fn role(self) -> EndpointRoleV2 {
        self.role
    }

    pub const fn request_id(self) -> RequestIdV2 {
        self.request_id
    }

    pub const fn deadline(self) -> UnixMillisV2 {
        self.deadline
    }

    pub const fn operation_tag(self) -> u16 {
        self.operation_tag
    }
}

impl KernelServiceApplicationRequestV2 {
    pub fn new(
        role: EndpointRoleV2,
        request_id: RequestIdV2,
        deadline: UnixMillisV2,
        operation: KernelServiceOperationV2,
    ) -> Result<Self, ProtocolError> {
        if operation.role() != role
            || is_zero(request_id.as_bytes())
            || deadline.get() == 0
            || error_set_for(role, operation.tag()).is_none()
        {
            return Err(malformed());
        }
        Ok(Self {
            role,
            request_id,
            deadline,
            operation,
        })
    }

    fn validate(&self) -> Result<(), ProtocolError> {
        if self.operation.role() != self.role
            || is_zero(self.request_id.as_bytes())
            || self.deadline.get() == 0
            || error_set_for(self.role, self.operation.tag()).is_none()
        {
            return Err(malformed());
        }
        Ok(())
    }

    pub const fn role(&self) -> EndpointRoleV2 {
        self.role
    }

    pub const fn request_id(&self) -> RequestIdV2 {
        self.request_id
    }

    pub const fn deadline(&self) -> UnixMillisV2 {
        self.deadline
    }

    pub const fn operation(&self) -> &KernelServiceOperationV2 {
        &self.operation
    }

    pub fn into_parts(
        self,
    ) -> (
        EndpointRoleV2,
        RequestIdV2,
        UnixMillisV2,
        KernelServiceOperationV2,
    ) {
        (self.role, self.request_id, self.deadline, self.operation)
    }
}

pub fn encode_kernel_service_application_request_v2(
    value: &KernelServiceApplicationRequestV2,
) -> Result<Vec<u8>, ProtocolError> {
    value.validate()?;
    let operation_body = value.operation.encode_canonical_body()?;
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(REQUEST_FIELDS)
        .and_then(|encoder| encoder.array(REQUEST_HEADER_FIELDS))
        .and_then(|encoder| encoder.u16(PROTOCOL_MAJOR))
        .and_then(|encoder| encoder.u16(PROTOCOL_MINOR))
        .map_err(ProtocolError::malformed)?;
    minicbor::Encode::encode(&value.role, &mut encoder, &mut ())
        .map_err(ProtocolError::malformed)?;
    encoder
        .bytes(value.request_id.as_bytes())
        .and_then(|encoder| encoder.u64(value.deadline.get()))
        .and_then(|encoder| encoder.u16(value.operation.tag()))
        .map_err(ProtocolError::malformed)?;
    let mut bytes = encoder.into_writer();
    bytes.extend_from_slice(&operation_body);
    scan_single(&bytes)?;
    Ok(bytes)
}

pub fn decode_kernel_service_application_request_v2(
    bytes: &[u8],
) -> Result<KernelServiceApplicationRequestV2, ProtocolError> {
    let routing = peek_kernel_service_application_request_v2(bytes)?;
    scan_single(bytes)?;
    let mut decoder = minicbor::Decoder::new(bytes);
    if decoder.array().map_err(ProtocolError::malformed)? != Some(REQUEST_FIELDS)
        || decoder.array().map_err(ProtocolError::malformed)? != Some(REQUEST_HEADER_FIELDS)
        || decoder.u16().map_err(ProtocolError::malformed)? != PROTOCOL_MAJOR
        || decoder.u16().map_err(ProtocolError::malformed)? != PROTOCOL_MINOR
    {
        return Err(malformed());
    }
    let mut context = V2DecodeContext;
    let role =
        <EndpointRoleV2 as minicbor::Decode<V2DecodeContext>>::decode(&mut decoder, &mut context)
            .map_err(ProtocolError::from_typed_decode)?;
    let request_id = RequestIdV2::new(decode_fixed::<16>(&mut decoder)?);
    let deadline = UnixMillisV2::new(decoder.u64().map_err(ProtocolError::malformed)?);
    let tag = decoder.u16().map_err(ProtocolError::malformed)?;
    if role != routing.role
        || request_id != routing.request_id
        || deadline != routing.deadline
        || tag != routing.operation_tag
    {
        return Err(malformed());
    }
    let body_start = decoder.position();
    decoder.skip().map_err(ProtocolError::malformed)?;
    if decoder.position() != bytes.len() {
        return Err(malformed());
    }
    let operation =
        KernelServiceOperationV2::from_canonical_body(role, tag, bytes[body_start..].to_vec())?;
    let value = KernelServiceApplicationRequestV2::new(role, request_id, deadline, operation)?;
    if encode_kernel_service_application_request_v2(&value)? != bytes {
        return Err(noncanonical());
    }
    Ok(value)
}

/// Reads only the duplicated routing fields from decrypted request bytes.
///
/// This deliberately does not scan or interpret the operation body. A
/// transport must compare the returned role, request ID, and operation tag
/// with the authenticated clear record header before calling the full
/// decoder.
pub fn peek_kernel_service_application_request_v2(
    bytes: &[u8],
) -> Result<KernelServiceApplicationRoutingV2, ProtocolError> {
    if bytes.is_empty() || bytes.len() > 8 * 1024 * 1024 {
        return Err(malformed());
    }
    let mut decoder = minicbor::Decoder::new(bytes);
    if decoder.array().map_err(ProtocolError::malformed)? != Some(REQUEST_FIELDS)
        || decoder.array().map_err(ProtocolError::malformed)? != Some(REQUEST_HEADER_FIELDS)
        || decoder.u16().map_err(ProtocolError::malformed)? != PROTOCOL_MAJOR
        || decoder.u16().map_err(ProtocolError::malformed)? != PROTOCOL_MINOR
    {
        return Err(malformed());
    }
    let mut context = V2DecodeContext;
    let role =
        <EndpointRoleV2 as minicbor::Decode<V2DecodeContext>>::decode(&mut decoder, &mut context)
            .map_err(ProtocolError::from_typed_decode)?;
    let request_id = RequestIdV2::new(decode_fixed::<16>(&mut decoder)?);
    let deadline = UnixMillisV2::new(decoder.u64().map_err(ProtocolError::malformed)?);
    let operation_tag = decoder.u16().map_err(ProtocolError::malformed)?;
    if decoder.position() >= bytes.len() {
        return Err(malformed());
    }
    Ok(KernelServiceApplicationRoutingV2 {
        role,
        request_id,
        deadline,
        operation_tag,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KernelServiceApplicationResponseBodyV2 {
    Success(Vec<u8>),
    Error(PublicStableCodeV2),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelServiceApplicationResponseV2 {
    role: EndpointRoleV2,
    request_id: RequestIdV2,
    operation_tag: u16,
    body: KernelServiceApplicationResponseBodyV2,
}

impl KernelServiceApplicationResponseV2 {
    pub fn success(
        role: EndpointRoleV2,
        request_id: RequestIdV2,
        operation_tag: u16,
        canonical_body: Vec<u8>,
    ) -> Result<Self, ProtocolError> {
        validate_response_identity(role, request_id, operation_tag)?;
        validate_canonical_body(&canonical_body)?;
        Ok(Self {
            role,
            request_id,
            operation_tag,
            body: KernelServiceApplicationResponseBodyV2::Success(canonical_body),
        })
    }

    pub fn error(
        role: EndpointRoleV2,
        request_id: RequestIdV2,
        operation_tag: u16,
        code: PublicStableCodeV2,
    ) -> Result<Self, ProtocolError> {
        validate_response_identity(role, request_id, operation_tag)?;
        let error_set = error_set_for(role, operation_tag).ok_or_else(malformed)?;
        if !error_set.allows(code) {
            return Err(ProtocolError::stable(StableCode::ProtocolUnknownField));
        }
        Ok(Self {
            role,
            request_id,
            operation_tag,
            body: KernelServiceApplicationResponseBodyV2::Error(code),
        })
    }

    pub const fn request_id(&self) -> RequestIdV2 {
        self.request_id
    }

    pub const fn operation_tag(&self) -> u16 {
        self.operation_tag
    }

    pub const fn body(&self) -> &KernelServiceApplicationResponseBodyV2 {
        &self.body
    }
}

pub fn encode_kernel_service_application_response_v2(
    value: &KernelServiceApplicationResponseV2,
) -> Result<Vec<u8>, ProtocolError> {
    validate_response_identity(value.role, value.request_id, value.operation_tag)?;
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(RESPONSE_FIELDS)
        .and_then(|encoder| encoder.bytes(value.request_id.as_bytes()))
        .map_err(ProtocolError::malformed)?;
    match &value.body {
        KernelServiceApplicationResponseBodyV2::Success(body) => {
            validate_canonical_body(body)?;
            encoder.u8(0).map_err(ProtocolError::malformed)?;
            let mut bytes = encoder.into_writer();
            bytes.extend_from_slice(body);
            scan_single(&bytes)?;
            Ok(bytes)
        }
        KernelServiceApplicationResponseBodyV2::Error(code) => {
            if !error_set_for(value.role, value.operation_tag).is_some_and(|set| set.allows(*code))
            {
                return Err(ProtocolError::stable(StableCode::ProtocolUnknownField));
            }
            encoder
                .u8(1)
                .and_then(|encoder| encoder.array(1))
                .and_then(|encoder| encoder.u16(code.tag()))
                .map_err(ProtocolError::malformed)?;
            Ok(encoder.into_writer())
        }
    }
}

pub fn decode_kernel_service_application_response_v2(
    bytes: &[u8],
    role: EndpointRoleV2,
    operation_tag: u16,
) -> Result<KernelServiceApplicationResponseV2, ProtocolError> {
    scan_single(bytes)?;
    let mut decoder = minicbor::Decoder::new(bytes);
    if decoder.array().map_err(ProtocolError::malformed)? != Some(RESPONSE_FIELDS) {
        return Err(malformed());
    }
    let request_id = RequestIdV2::new(decode_fixed::<16>(&mut decoder)?);
    let status = decoder.u8().map_err(ProtocolError::malformed)?;
    let value = match status {
        0 => {
            let body_start = decoder.position();
            decoder.skip().map_err(ProtocolError::malformed)?;
            KernelServiceApplicationResponseV2::success(
                role,
                request_id,
                operation_tag,
                bytes[body_start..].to_vec(),
            )?
        }
        1 => {
            if decoder.array().map_err(ProtocolError::malformed)? != Some(1) {
                return Err(malformed());
            }
            KernelServiceApplicationResponseV2::error(
                role,
                request_id,
                operation_tag,
                PublicStableCodeV2::from_tag(decoder.u16().map_err(ProtocolError::malformed)?)?,
            )?
        }
        _ => return Err(malformed()),
    };
    if decoder.position() != bytes.len()
        || encode_kernel_service_application_response_v2(&value)? != bytes
    {
        return Err(noncanonical());
    }
    Ok(value)
}

#[derive(Debug, Clone, Copy)]
enum ErrorSetV2 {
    Health,
    Query,
    ControlMutation,
    Input,
    Policy,
    Approval,
    Execution,
}

impl ErrorSetV2 {
    const fn allows(self, code: PublicStableCodeV2) -> bool {
        match self {
            Self::Health => matches!(
                code,
                PublicStableCodeV2::ServiceUnavailable | PublicStableCodeV2::InternalFatal
            ),
            Self::Query => matches!(
                code,
                PublicStableCodeV2::InvalidReference
                    | PublicStableCodeV2::DeadlineExceeded
                    | PublicStableCodeV2::ServiceUnavailable
                    | PublicStableCodeV2::InternalFatal
            ),
            Self::ControlMutation => control_mutation_code(code),
            Self::Input => {
                control_mutation_code(code)
                    || matches!(
                        code,
                        PublicStableCodeV2::InputDenied
                            | PublicStableCodeV2::InputMalformed
                            | PublicStableCodeV2::ModelUnavailable
                            | PublicStableCodeV2::ModelContract
                            | PublicStableCodeV2::PolicyDenied
                            | PublicStableCodeV2::PolicyExpired
                    )
            }
            Self::Policy => {
                control_mutation_code(code)
                    || matches!(
                        code,
                        PublicStableCodeV2::PolicyDenied
                            | PublicStableCodeV2::PolicyExpired
                            | PublicStableCodeV2::RegistryMismatch
                            | PublicStableCodeV2::OntologyMismatch
                            | PublicStableCodeV2::ProjectionMismatch
                            | PublicStableCodeV2::ValidatorMissing
                            | PublicStableCodeV2::ValidatorRejected
                            | PublicStableCodeV2::ValidatorBindingMismatch
                    )
            }
            Self::Approval => {
                control_mutation_code(code)
                    || matches!(
                        code,
                        PublicStableCodeV2::ApprovalDenied
                            | PublicStableCodeV2::ApprovalExpired
                            | PublicStableCodeV2::ApprovalReplay
                            | PublicStableCodeV2::ApprovalBindingMismatch
                    )
            }
            Self::Execution => {
                ErrorSetV2::Policy.allows(code)
                    || ErrorSetV2::Approval.allows(code)
                    || matches!(
                        code,
                        PublicStableCodeV2::ExecutionFailedNoEffect
                            | PublicStableCodeV2::ExecutionIndeterminate
                            | PublicStableCodeV2::ResultUnavailable
                    )
            }
        }
    }
}

const fn control_mutation_code(code: PublicStableCodeV2) -> bool {
    matches!(
        code,
        PublicStableCodeV2::InvalidReference
            | PublicStableCodeV2::StateConflict
            | PublicStableCodeV2::IdempotencyConflict
            | PublicStableCodeV2::CancellationTooLate
            | PublicStableCodeV2::LimitExceeded
            | PublicStableCodeV2::Overloaded
            | PublicStableCodeV2::DeadlineExceeded
            | PublicStableCodeV2::Cancelled
            | PublicStableCodeV2::StorageUnavailable
            | PublicStableCodeV2::AuditUnavailable
            | PublicStableCodeV2::EntropyUnavailable
            | PublicStableCodeV2::ServiceUnavailable
            | PublicStableCodeV2::InternalFatal
    )
}

const fn error_set_for(role: EndpointRoleV2, tag: u16) -> Option<ErrorSetV2> {
    match (role, tag) {
        (
            EndpointRoleV2::AgentKernel
            | EndpointRoleV2::IngressKernel
            | EndpointRoleV2::KernelExecutor
            | EndpointRoleV2::AgentApproval
            | EndpointRoleV2::IngressApproval
            | EndpointRoleV2::ApprovalAdmin,
            0,
        ) => Some(ErrorSetV2::Health),
        (EndpointRoleV2::AgentKernel, 22 | 30 | 35 | 41 | 76)
        | (EndpointRoleV2::IngressKernel, 45)
        | (EndpointRoleV2::KernelExecutor, 61) => Some(ErrorSetV2::Query),
        (EndpointRoleV2::AgentKernel, 31 | 36 | 37 | 42 | 73..=75) => {
            Some(ErrorSetV2::ControlMutation)
        }
        (EndpointRoleV2::AgentKernel, 21 | 38)
        | (EndpointRoleV2::IngressKernel, 40..=42 | 44 | 48..=56) => Some(ErrorSetV2::Input),
        (EndpointRoleV2::AgentKernel, 23..=27 | 32) => Some(ErrorSetV2::Policy),
        (EndpointRoleV2::AgentKernel, 20 | 28 | 33 | 39 | 40 | 43 | 70..=72)
        | (EndpointRoleV2::IngressKernel, 43 | 46 | 47) => Some(ErrorSetV2::Approval),
        (EndpointRoleV2::AgentApproval, 20 | 22..=24)
        | (EndpointRoleV2::IngressApproval, 20 | 22..=23) => Some(ErrorSetV2::Approval),
        (EndpointRoleV2::AgentApproval | EndpointRoleV2::IngressApproval, 21)
        | (EndpointRoleV2::IngressApproval, 25) => Some(ErrorSetV2::Query),
        (EndpointRoleV2::ApprovalAdmin, 100 | 101) => Some(ErrorSetV2::ControlMutation),
        (EndpointRoleV2::AgentKernel, 29 | 34) | (EndpointRoleV2::KernelExecutor, 60 | 62..=64) => {
            Some(ErrorSetV2::Execution)
        }
        _ => None,
    }
}

/// Reports whether an authenticated role/tag pair has a frozen public error
/// contract. A pair without a contract is never dispatchable.
pub const fn kernel_service_operation_has_error_contract_v2(
    role: EndpointRoleV2,
    tag: u16,
) -> bool {
    error_set_for(role, tag).is_some()
}

/// Checks one public error against the frozen contract for an authenticated
/// role/tag pair. This exposes contract metadata only; it does not create a
/// response or grant dispatch authority.
pub const fn kernel_service_public_error_is_allowed_v2(
    role: EndpointRoleV2,
    tag: u16,
    code: PublicStableCodeV2,
) -> bool {
    match error_set_for(role, tag) {
        Some(error_set) => error_set.allows(code),
        None => false,
    }
}

fn validate_response_identity(
    role: EndpointRoleV2,
    request_id: RequestIdV2,
    operation_tag: u16,
) -> Result<(), ProtocolError> {
    if is_zero(request_id.as_bytes()) || error_set_for(role, operation_tag).is_none() {
        return Err(malformed());
    }
    Ok(())
}

fn decode_fixed<const N: usize>(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<[u8; N], ProtocolError> {
    decoder
        .bytes()
        .map_err(ProtocolError::malformed)?
        .try_into()
        .map_err(|_| malformed())
}

fn is_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

fn malformed() -> ProtocolError {
    ProtocolError::stable(StableCode::ProtocolMalformedCbor)
}

fn noncanonical() -> ProtocolError {
    ProtocolError::stable(StableCode::ProtocolNonCanonicalCbor)
}
