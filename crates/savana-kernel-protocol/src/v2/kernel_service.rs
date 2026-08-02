use ed25519_dalek::{
    Signature as Ed25519Signature, Signer as _, SigningKey, VerifyingKey as Ed25519VerifyingKey,
};
use sha2::{Digest as _, Sha256};

use crate::{ProtocolError, StableCode};

use super::{
    cbor::{scan_single, V2DecodeContext},
    decode_kernel_agent_operation_v2, decode_kernel_connector_control_operation_v2,
    decode_kernel_executor_operation_v2, decode_kernel_ingress_operation_v2,
    encode_kernel_agent_operation_v2, encode_kernel_connector_control_operation_v2,
    encode_kernel_executor_operation_v2, encode_kernel_ingress_operation_v2, BootIdV2, Digest32V2,
    Ed25519KeyIdV2, EndpointRoleV2, KernelAgentOperationV2, KernelConnectorControlOperationV2,
    KernelExecutorOperationV2, KernelIngressOperationV2, RequestIdV2, ServiceIdentityV2,
    UnixMillisV2, PROTOCOL_MAJOR, PROTOCOL_MINOR,
};

const REQUEST_FIELDS: u64 = 12;
const RESPONSE_PAYLOAD_FIELDS: u64 = 10;
const RESPONSE_SIGNATURE_DOMAIN: &[u8] = b"SAVANA_KERNEL_SERVICE_RESPONSE_SIGNATURE_V2\0";
const MAX_BODY_BYTES: usize = 8 * 1024 * 1024;
const MAX_SIGNED_RESPONSE_BYTES: usize = MAX_BODY_BYTES + 4 * 1024;
const MAX_BODY_DEPTH: usize = 32;
const MAX_BODY_ITEMS: u64 = 65_536;

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum KernelServiceOperationV2 {
    Agent(KernelAgentOperationV2),
    Connector(KernelConnectorControlOperationV2),
    Ingress(KernelIngressOperationV2),
    Executor(KernelExecutorOperationV2),
}

impl KernelServiceOperationV2 {
    pub const fn agent(operation: KernelAgentOperationV2) -> Self {
        Self::Agent(operation)
    }

    pub const fn ingress(operation: KernelIngressOperationV2) -> Self {
        Self::Ingress(operation)
    }

    pub const fn connector(operation: KernelConnectorControlOperationV2) -> Self {
        Self::Connector(operation)
    }

    pub const fn executor(operation: KernelExecutorOperationV2) -> Self {
        Self::Executor(operation)
    }

    pub(super) fn from_canonical_body(
        role: EndpointRoleV2,
        tag: u16,
        canonical_body: Vec<u8>,
    ) -> Result<Self, ProtocolError> {
        validate_canonical_body(&canonical_body)?;
        let full = operation_with_tag(tag, &canonical_body)?;
        let value = match role {
            EndpointRoleV2::AgentKernel
                if super::kernel_connector_control_operation_tags_v2().contains(&tag) =>
            {
                Self::Connector(decode_kernel_connector_control_operation_v2(&full)?)
            }
            EndpointRoleV2::AgentKernel => Self::Agent(decode_kernel_agent_operation_v2(&full)?),
            EndpointRoleV2::IngressKernel => {
                Self::Ingress(decode_kernel_ingress_operation_v2(&full)?)
            }
            EndpointRoleV2::KernelExecutor => {
                Self::Executor(decode_kernel_executor_operation_v2(&full)?)
            }
            _ => return Err(ProtocolError::stable(StableCode::ProtocolUnknownOperation)),
        };
        if value.tag() != tag {
            return Err(ProtocolError::stable(StableCode::ProtocolUnknownOperation));
        }
        Ok(value)
    }

    pub const fn role(&self) -> EndpointRoleV2 {
        match self {
            Self::Agent(_) => EndpointRoleV2::AgentKernel,
            Self::Connector(_) => EndpointRoleV2::AgentKernel,
            Self::Ingress(_) => EndpointRoleV2::IngressKernel,
            Self::Executor(_) => EndpointRoleV2::KernelExecutor,
        }
    }

    pub const fn tag(&self) -> u16 {
        match self {
            Self::Agent(operation) => operation.tag(),
            Self::Connector(operation) => operation.tag(),
            Self::Ingress(operation) => operation.tag(),
            Self::Executor(operation) => operation.tag(),
        }
    }

    pub fn encode_canonical_body(&self) -> Result<Vec<u8>, ProtocolError> {
        let full = match self {
            Self::Agent(operation) => encode_kernel_agent_operation_v2(operation)?,
            Self::Connector(operation) => encode_kernel_connector_control_operation_v2(operation)?,
            Self::Ingress(operation) => encode_kernel_ingress_operation_v2(operation)?,
            Self::Executor(operation) => encode_kernel_executor_operation_v2(operation)?,
        };
        operation_body(&full, self.tag())
    }
}

#[derive(Debug)]
pub struct KernelServiceRequestEnvelopeV2 {
    role: EndpointRoleV2,
    request_id: RequestIdV2,
    caller_boot_id: BootIdV2,
    service_boot_id: BootIdV2,
    caller_identity: ServiceIdentityV2,
    service_identity: ServiceIdentityV2,
    active_state_manifest_digest: Digest32V2,
    deployment_generation: u64,
    deadline: UnixMillisV2,
    operation: KernelServiceOperationV2,
}

impl KernelServiceRequestEnvelopeV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn from_authenticated_connection(
        role: EndpointRoleV2,
        request_id: RequestIdV2,
        caller_boot_id: BootIdV2,
        service_boot_id: BootIdV2,
        caller_identity: ServiceIdentityV2,
        service_identity: ServiceIdentityV2,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
        deadline: UnixMillisV2,
        operation: KernelServiceOperationV2,
    ) -> Result<Self, ProtocolError> {
        let value = Self {
            role,
            request_id,
            caller_boot_id,
            service_boot_id,
            caller_identity,
            service_identity,
            active_state_manifest_digest,
            deployment_generation,
            deadline,
            operation,
        };
        value.validate()?;
        Ok(value)
    }

    pub const fn role(&self) -> EndpointRoleV2 {
        self.role
    }

    pub const fn request_id(&self) -> RequestIdV2 {
        self.request_id
    }

    pub const fn caller_boot_id(&self) -> BootIdV2 {
        self.caller_boot_id
    }

    pub const fn service_boot_id(&self) -> BootIdV2 {
        self.service_boot_id
    }

    pub const fn caller_identity(&self) -> ServiceIdentityV2 {
        self.caller_identity
    }

    pub const fn service_identity(&self) -> ServiceIdentityV2 {
        self.service_identity
    }

    pub const fn active_state_manifest_digest(&self) -> Digest32V2 {
        self.active_state_manifest_digest
    }

    pub const fn deployment_generation(&self) -> u64 {
        self.deployment_generation
    }

    pub const fn deadline(&self) -> UnixMillisV2 {
        self.deadline
    }

    pub const fn operation(&self) -> &KernelServiceOperationV2 {
        &self.operation
    }

    pub fn into_operation(self) -> KernelServiceOperationV2 {
        self.operation
    }

    fn validate(&self) -> Result<(), ProtocolError> {
        if !matches!(
            self.role,
            EndpointRoleV2::AgentKernel
                | EndpointRoleV2::IngressKernel
                | EndpointRoleV2::KernelExecutor
        ) || self.operation.role() != self.role
            || !tag_allowed(self.role, self.operation.tag())
            || is_zero(self.request_id.as_bytes())
            || is_zero(self.caller_boot_id.as_bytes())
            || is_zero(self.service_boot_id.as_bytes())
            || is_zero(self.caller_identity.as_bytes())
            || is_zero(self.service_identity.as_bytes())
            || is_zero(self.active_state_manifest_digest.as_bytes())
            || self.deployment_generation == 0
            || self.deadline.get() == 0
        {
            return Err(ProtocolError::stable(StableCode::ProtocolMalformedCbor));
        }
        validate_canonical_body(&self.operation.encode_canonical_body()?)
    }
}

pub fn encode_kernel_service_request_envelope_v2(
    value: &KernelServiceRequestEnvelopeV2,
) -> Result<Vec<u8>, ProtocolError> {
    value.validate()?;
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(REQUEST_FIELDS)
        .and_then(|encoder| encoder.u16(PROTOCOL_MAJOR))
        .and_then(|encoder| encoder.u16(PROTOCOL_MINOR))
        .map_err(ProtocolError::malformed)?;
    minicbor::Encode::encode(&value.role, &mut encoder, &mut ())
        .map_err(ProtocolError::malformed)?;
    encode_fixed(&mut encoder, value.request_id.as_bytes())?;
    encode_fixed(&mut encoder, value.caller_boot_id.as_bytes())?;
    encode_fixed(&mut encoder, value.service_boot_id.as_bytes())?;
    encode_fixed(&mut encoder, value.caller_identity.as_bytes())?;
    encode_fixed(&mut encoder, value.service_identity.as_bytes())?;
    encode_fixed(&mut encoder, value.active_state_manifest_digest.as_bytes())?;
    let operation_body = value.operation.encode_canonical_body()?;
    encoder
        .u64(value.deployment_generation)
        .and_then(|encoder| encoder.u64(value.deadline.get()))
        .and_then(|encoder| encoder.array(2))
        .and_then(|encoder| encoder.u16(value.operation.tag()))
        .and_then(|encoder| encoder.bytes(&operation_body))
        .map_err(ProtocolError::malformed)?;
    Ok(encoder.into_writer())
}

pub fn decode_kernel_service_request_envelope_v2(
    bytes: &[u8],
) -> Result<KernelServiceRequestEnvelopeV2, ProtocolError> {
    scan_single(bytes)?;
    let mut decoder = minicbor::Decoder::new(bytes);
    if decoder.array().map_err(ProtocolError::malformed)? != Some(REQUEST_FIELDS)
        || decoder.u16().map_err(ProtocolError::malformed)? != PROTOCOL_MAJOR
        || decoder.u16().map_err(ProtocolError::malformed)? != PROTOCOL_MINOR
    {
        return Err(ProtocolError::stable(StableCode::ProtocolMalformedCbor));
    }
    let mut context = V2DecodeContext;
    let role =
        <EndpointRoleV2 as minicbor::Decode<V2DecodeContext>>::decode(&mut decoder, &mut context)
            .map_err(ProtocolError::from_typed_decode)?;
    let request_id = RequestIdV2::new(decode_fixed::<16>(&mut decoder)?);
    let caller_boot_id = BootIdV2::new(decode_fixed::<32>(&mut decoder)?);
    let service_boot_id = BootIdV2::new(decode_fixed::<32>(&mut decoder)?);
    let caller_identity = ServiceIdentityV2::new(decode_fixed::<32>(&mut decoder)?);
    let service_identity = ServiceIdentityV2::new(decode_fixed::<32>(&mut decoder)?);
    let active_state_manifest_digest = Digest32V2::new(decode_fixed::<32>(&mut decoder)?);
    let deployment_generation = decoder.u64().map_err(ProtocolError::malformed)?;
    let deadline = UnixMillisV2::new(decoder.u64().map_err(ProtocolError::malformed)?);
    if decoder.array().map_err(ProtocolError::malformed)? != Some(2) {
        return Err(ProtocolError::stable(StableCode::ProtocolMalformedCbor));
    }
    let tag = decoder.u16().map_err(ProtocolError::malformed)?;
    let body = decoder.bytes().map_err(ProtocolError::malformed)?.to_vec();
    if decoder.position() != bytes.len() {
        return Err(ProtocolError::stable(StableCode::ProtocolMalformedCbor));
    }
    let operation = KernelServiceOperationV2::from_canonical_body(role, tag, body)?;
    let value = KernelServiceRequestEnvelopeV2::from_authenticated_connection(
        role,
        request_id,
        caller_boot_id,
        service_boot_id,
        caller_identity,
        service_identity,
        active_state_manifest_digest,
        deployment_generation,
        deadline,
        operation,
    )?;
    if encode_kernel_service_request_envelope_v2(&value)? != bytes {
        return Err(ProtocolError::stable(StableCode::ProtocolNonCanonicalCbor));
    }
    Ok(value)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KernelServiceResponseV2 {
    Success(Vec<u8>),
    Error(StableCode),
}

impl KernelServiceResponseV2 {
    pub fn success(canonical_body: Vec<u8>) -> Result<Self, ProtocolError> {
        validate_canonical_body(&canonical_body)?;
        Ok(Self::Success(canonical_body))
    }

    pub const fn error(code: StableCode) -> Self {
        Self::Error(code)
    }

    pub fn canonical_body(&self) -> Option<&[u8]> {
        match self {
            Self::Success(body) => Some(body),
            Self::Error(_) => None,
        }
    }

    pub const fn error_code(&self) -> Option<StableCode> {
        match self {
            Self::Success(_) => None,
            Self::Error(code) => Some(*code),
        }
    }

    fn validate(&self) -> Result<(), ProtocolError> {
        match self {
            Self::Success(body) => validate_canonical_body(body),
            Self::Error(_) => Ok(()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelServiceResponseEnvelopeV2 {
    role: EndpointRoleV2,
    request_id: RequestIdV2,
    service_boot_id: BootIdV2,
    service_identity: ServiceIdentityV2,
    active_state_manifest_digest: Digest32V2,
    deployment_generation: u64,
    operation_tag: u16,
    response: KernelServiceResponseV2,
}

impl KernelServiceResponseEnvelopeV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn from_authenticated_connection(
        role: EndpointRoleV2,
        request_id: RequestIdV2,
        service_boot_id: BootIdV2,
        service_identity: ServiceIdentityV2,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
        operation_tag: u16,
        response: KernelServiceResponseV2,
    ) -> Result<Self, ProtocolError> {
        let value = Self {
            role,
            request_id,
            service_boot_id,
            service_identity,
            active_state_manifest_digest,
            deployment_generation,
            operation_tag,
            response,
        };
        value.validate()?;
        Ok(value)
    }

    pub const fn role(&self) -> EndpointRoleV2 {
        self.role
    }

    pub const fn request_id(&self) -> RequestIdV2 {
        self.request_id
    }

    pub const fn service_boot_id(&self) -> BootIdV2 {
        self.service_boot_id
    }

    pub const fn service_identity(&self) -> ServiceIdentityV2 {
        self.service_identity
    }

    pub const fn active_state_manifest_digest(&self) -> Digest32V2 {
        self.active_state_manifest_digest
    }

    pub const fn deployment_generation(&self) -> u64 {
        self.deployment_generation
    }

    pub const fn operation_tag(&self) -> u16 {
        self.operation_tag
    }

    pub const fn response(&self) -> &KernelServiceResponseV2 {
        &self.response
    }

    fn validate(&self) -> Result<(), ProtocolError> {
        if !matches!(
            self.role,
            EndpointRoleV2::AgentKernel
                | EndpointRoleV2::IngressKernel
                | EndpointRoleV2::KernelExecutor
        ) || !tag_allowed(self.role, self.operation_tag)
            || is_zero(self.request_id.as_bytes())
            || is_zero(self.service_boot_id.as_bytes())
            || is_zero(self.service_identity.as_bytes())
            || is_zero(self.active_state_manifest_digest.as_bytes())
            || self.deployment_generation == 0
        {
            return Err(ProtocolError::stable(StableCode::ProtocolMalformedCbor));
        }
        self.response.validate()
    }
}

pub fn sign_kernel_service_response_envelope_v2(
    value: &KernelServiceResponseEnvelopeV2,
    signing_key_id: Ed25519KeyIdV2,
    signing_key: &SigningKey,
) -> Result<Vec<u8>, ProtocolError> {
    value.validate()?;
    if is_zero(signing_key_id.as_bytes()) {
        return Err(ProtocolError::stable(StableCode::IdentityInvalidSignature));
    }
    let payload = encode_response_payload(value)?;
    let payload_digest: [u8; 32] = Sha256::digest(&payload).into();
    let mut signature_input =
        Vec::with_capacity(RESPONSE_SIGNATURE_DOMAIN.len() + payload_digest.len());
    signature_input.extend_from_slice(RESPONSE_SIGNATURE_DOMAIN);
    signature_input.extend_from_slice(&payload_digest);
    let signature = signing_key.sign(&signature_input).to_bytes();
    encode_signed_response(&payload, signing_key_id, &signature)
}

pub fn verify_kernel_service_response_envelope_v2(
    canonical_signed_response: &[u8],
    expected_signing_key_id: Ed25519KeyIdV2,
    signing_public_key: [u8; 32],
) -> Result<KernelServiceResponseEnvelopeV2, ProtocolError> {
    if canonical_signed_response.is_empty()
        || canonical_signed_response.len() > MAX_SIGNED_RESPONSE_BYTES
    {
        return Err(ProtocolError::stable(StableCode::ProtocolFrameTooLarge));
    }
    scan_single(canonical_signed_response)?;
    let mut decoder = minicbor::Decoder::new(canonical_signed_response);
    if decoder.array().map_err(ProtocolError::malformed)? != Some(3) {
        return Err(ProtocolError::stable(StableCode::ProtocolMalformedCbor));
    }
    let payload = decoder.bytes().map_err(ProtocolError::malformed)?.to_vec();
    let signing_key_id = Ed25519KeyIdV2::new(decode_fixed::<32>(&mut decoder)?);
    let signature = decode_fixed::<64>(&mut decoder)?;
    if decoder.position() != canonical_signed_response.len() {
        return Err(ProtocolError::stable(StableCode::ProtocolMalformedCbor));
    }
    if encode_signed_response(&payload, signing_key_id, &signature)? != canonical_signed_response {
        return Err(ProtocolError::stable(StableCode::ProtocolNonCanonicalCbor));
    }
    if signing_key_id != expected_signing_key_id || is_zero(expected_signing_key_id.as_bytes()) {
        return Err(ProtocolError::stable(StableCode::IdentityInvalidSignature));
    }
    let verifying_key = Ed25519VerifyingKey::from_bytes(&signing_public_key)
        .map_err(|_| ProtocolError::stable(StableCode::IdentityInvalidSignature))?;
    let payload_digest: [u8; 32] = Sha256::digest(&payload).into();
    let mut signature_input =
        Vec::with_capacity(RESPONSE_SIGNATURE_DOMAIN.len() + payload_digest.len());
    signature_input.extend_from_slice(RESPONSE_SIGNATURE_DOMAIN);
    signature_input.extend_from_slice(&payload_digest);
    verifying_key
        .verify_strict(&signature_input, &Ed25519Signature::from_bytes(&signature))
        .map_err(|_| ProtocolError::stable(StableCode::IdentityInvalidSignature))?;
    let value = decode_response_payload(&payload)?;
    if encode_response_payload(&value)? != payload {
        return Err(ProtocolError::stable(StableCode::ProtocolNonCanonicalCbor));
    }
    Ok(value)
}

fn encode_response_payload(
    value: &KernelServiceResponseEnvelopeV2,
) -> Result<Vec<u8>, ProtocolError> {
    value.validate()?;
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(RESPONSE_PAYLOAD_FIELDS)
        .and_then(|encoder| encoder.u16(PROTOCOL_MAJOR))
        .and_then(|encoder| encoder.u16(PROTOCOL_MINOR))
        .map_err(ProtocolError::malformed)?;
    minicbor::Encode::encode(&value.role, &mut encoder, &mut ())
        .map_err(ProtocolError::malformed)?;
    encode_fixed(&mut encoder, value.request_id.as_bytes())?;
    encode_fixed(&mut encoder, value.service_boot_id.as_bytes())?;
    encode_fixed(&mut encoder, value.service_identity.as_bytes())?;
    encode_fixed(&mut encoder, value.active_state_manifest_digest.as_bytes())?;
    encoder
        .u64(value.deployment_generation)
        .and_then(|encoder| encoder.u16(value.operation_tag))
        .map_err(ProtocolError::malformed)?;
    match &value.response {
        KernelServiceResponseV2::Success(body) => {
            encoder
                .array(2)
                .and_then(|encoder| encoder.u16(0))
                .and_then(|encoder| encoder.bytes(body))
                .map_err(ProtocolError::malformed)?;
        }
        KernelServiceResponseV2::Error(code) => {
            encoder
                .array(2)
                .and_then(|encoder| encoder.u16(1))
                .map_err(ProtocolError::malformed)?;
            minicbor::Encode::encode(code, &mut encoder, &mut ())
                .map_err(ProtocolError::malformed)?;
        }
    }
    Ok(encoder.into_writer())
}

fn decode_response_payload(bytes: &[u8]) -> Result<KernelServiceResponseEnvelopeV2, ProtocolError> {
    let mut decoder = minicbor::Decoder::new(bytes);
    if decoder.array().map_err(ProtocolError::malformed)? != Some(RESPONSE_PAYLOAD_FIELDS)
        || decoder.u16().map_err(ProtocolError::malformed)? != PROTOCOL_MAJOR
        || decoder.u16().map_err(ProtocolError::malformed)? != PROTOCOL_MINOR
    {
        return Err(ProtocolError::stable(StableCode::ProtocolMalformedCbor));
    }
    let mut context = V2DecodeContext;
    let role =
        <EndpointRoleV2 as minicbor::Decode<V2DecodeContext>>::decode(&mut decoder, &mut context)
            .map_err(ProtocolError::from_typed_decode)?;
    let request_id = RequestIdV2::new(decode_fixed::<16>(&mut decoder)?);
    let service_boot_id = BootIdV2::new(decode_fixed::<32>(&mut decoder)?);
    let service_identity = ServiceIdentityV2::new(decode_fixed::<32>(&mut decoder)?);
    let active_state_manifest_digest = Digest32V2::new(decode_fixed::<32>(&mut decoder)?);
    let deployment_generation = decoder.u64().map_err(ProtocolError::malformed)?;
    let operation_tag = decoder.u16().map_err(ProtocolError::malformed)?;
    if decoder.array().map_err(ProtocolError::malformed)? != Some(2) {
        return Err(ProtocolError::stable(StableCode::ProtocolMalformedCbor));
    }
    let response = match decoder.u16().map_err(ProtocolError::malformed)? {
        0 => KernelServiceResponseV2::success(
            decoder.bytes().map_err(ProtocolError::malformed)?.to_vec(),
        )?,
        1 => KernelServiceResponseV2::error(
            <StableCode as minicbor::Decode<V2DecodeContext>>::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?,
        ),
        _ => return Err(ProtocolError::stable(StableCode::ProtocolMalformedCbor)),
    };
    if decoder.position() != bytes.len() {
        return Err(ProtocolError::stable(StableCode::ProtocolMalformedCbor));
    }
    KernelServiceResponseEnvelopeV2::from_authenticated_connection(
        role,
        request_id,
        service_boot_id,
        service_identity,
        active_state_manifest_digest,
        deployment_generation,
        operation_tag,
        response,
    )
}

fn encode_signed_response(
    payload: &[u8],
    signing_key_id: Ed25519KeyIdV2,
    signature: &[u8; 64],
) -> Result<Vec<u8>, ProtocolError> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(3)
        .and_then(|encoder| encoder.bytes(payload))
        .and_then(|encoder| encoder.bytes(signing_key_id.as_bytes()))
        .and_then(|encoder| encoder.bytes(signature))
        .map_err(ProtocolError::malformed)?;
    Ok(encoder.into_writer())
}

fn operation_with_tag(tag: u16, body: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(2)
        .and_then(|encoder| encoder.u16(tag))
        .map_err(ProtocolError::malformed)?;
    let mut full = encoder.into_writer();
    full.extend_from_slice(body);
    scan_single(&full)?;
    Ok(full)
}

fn operation_body(full: &[u8], expected_tag: u16) -> Result<Vec<u8>, ProtocolError> {
    scan_single(full)?;
    let mut decoder = minicbor::Decoder::new(full);
    if decoder.array().map_err(ProtocolError::malformed)? != Some(2)
        || decoder.u16().map_err(ProtocolError::malformed)? != expected_tag
    {
        return Err(ProtocolError::stable(StableCode::ProtocolMalformedCbor));
    }
    let body_start = decoder.position();
    decoder.skip().map_err(ProtocolError::malformed)?;
    if decoder.position() != full.len() {
        return Err(ProtocolError::stable(StableCode::ProtocolMalformedCbor));
    }
    let body = full[body_start..].to_vec();
    validate_canonical_body(&body)?;
    Ok(body)
}

const fn tag_allowed(role: EndpointRoleV2, tag: u16) -> bool {
    match role {
        EndpointRoleV2::AgentKernel => {
            tag == 0 || (tag >= 20 && tag <= 43) || tag == 70 || tag == 71
        }
        EndpointRoleV2::IngressKernel => tag == 0 || (tag >= 40 && tag <= 50),
        EndpointRoleV2::KernelExecutor => tag == 0 || (tag >= 60 && tag <= 63),
        _ => false,
    }
}

/// Returns the complete, closed operation-tag registry for one authenticated
/// kernel-service role. Roles outside the three kernel service edges have no
/// entry in this registry.
pub const fn kernel_service_operation_tags_for_role_v2(
    role: EndpointRoleV2,
) -> Option<&'static [u16]> {
    match role {
        EndpointRoleV2::AgentKernel => Some(&[
            0, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
            41, 42, 43, 70, 71,
        ]),
        EndpointRoleV2::IngressKernel => Some(super::kernel_ingress_operation_tags_v2()),
        EndpointRoleV2::KernelExecutor => Some(super::kernel_executor_operation_tags_v2()),
        _ => None,
    }
}

pub(super) fn validate_canonical_body(bytes: &[u8]) -> Result<(), ProtocolError> {
    if bytes.is_empty() || bytes.len() > MAX_BODY_BYTES {
        return Err(ProtocolError::stable(StableCode::ProtocolNonCanonicalCbor));
    }
    let mut decoder = minicbor::Decoder::new(bytes);
    let mut items = MAX_BODY_ITEMS;
    validate_item(bytes, &mut decoder, 0, &mut items)?;
    if decoder.position() != bytes.len() {
        return Err(ProtocolError::stable(StableCode::ProtocolNonCanonicalCbor));
    }
    Ok(())
}

fn validate_item(
    bytes: &[u8],
    decoder: &mut minicbor::Decoder<'_>,
    depth: usize,
    items: &mut u64,
) -> Result<(), ProtocolError> {
    if depth > MAX_BODY_DEPTH {
        return Err(ProtocolError::stable(StableCode::ProtocolNestingTooDeep));
    }
    *items = items
        .checked_sub(1)
        .ok_or_else(|| ProtocolError::stable(StableCode::ProtocolAllocationRefused))?;
    let position = decoder.position();
    let first = *bytes
        .get(position)
        .ok_or_else(|| ProtocolError::stable(StableCode::ProtocolNonCanonicalCbor))?;
    let additional = first & 0x1f;
    match decoder.datatype().map_err(ProtocolError::malformed)? {
        minicbor::data::Type::Array => {
            let length = decoder
                .array()
                .map_err(ProtocolError::malformed)?
                .ok_or_else(|| ProtocolError::stable(StableCode::ProtocolNonCanonicalCbor))?;
            require_shortest_head(additional, length)?;
            if length > MAX_BODY_ITEMS {
                return Err(ProtocolError::stable(StableCode::ProtocolAllocationRefused));
            }
            for _ in 0..length {
                validate_item(bytes, decoder, depth + 1, items)?;
            }
        }
        minicbor::data::Type::Bytes => {
            let value = decoder.bytes().map_err(ProtocolError::malformed)?;
            require_shortest_head(additional, value.len() as u64)?;
        }
        minicbor::data::Type::String => {
            let value = decoder.str().map_err(ProtocolError::malformed)?;
            require_shortest_head(additional, value.len() as u64)?;
        }
        minicbor::data::Type::Bool => {
            decoder.bool().map_err(ProtocolError::malformed)?;
        }
        minicbor::data::Type::Null => {
            decoder.null().map_err(ProtocolError::malformed)?;
        }
        minicbor::data::Type::U8
        | minicbor::data::Type::U16
        | minicbor::data::Type::U32
        | minicbor::data::Type::U64 => {
            let value = decoder.u64().map_err(ProtocolError::malformed)?;
            require_shortest_head(additional, value)?;
        }
        minicbor::data::Type::I8
        | minicbor::data::Type::I16
        | minicbor::data::Type::I32
        | minicbor::data::Type::I64
        | minicbor::data::Type::Int => {
            let value = decoder.i64().map_err(ProtocolError::malformed)?;
            let argument = u64::try_from(-1_i128 - i128::from(value))
                .map_err(|_| ProtocolError::stable(StableCode::ProtocolNonCanonicalCbor))?;
            require_shortest_head(additional, argument)?;
        }
        minicbor::data::Type::ArrayIndef
        | minicbor::data::Type::BytesIndef
        | minicbor::data::Type::StringIndef
        | minicbor::data::Type::MapIndef => {
            return Err(ProtocolError::stable(StableCode::ProtocolNonCanonicalCbor));
        }
        _ => {
            return Err(ProtocolError::stable(StableCode::ProtocolMalformedCbor));
        }
    }
    Ok(())
}

fn require_shortest_head(additional: u8, value: u64) -> Result<(), ProtocolError> {
    let expected = match value {
        0..=23 => value as u8,
        24..=0xff => 24,
        0x100..=0xffff => 25,
        0x1_0000..=0xffff_ffff => 26,
        _ => 27,
    };
    if additional == expected {
        Ok(())
    } else {
        Err(ProtocolError::stable(StableCode::ProtocolNonCanonicalCbor))
    }
}

fn encode_fixed<const N: usize>(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    bytes: &[u8; N],
) -> Result<(), ProtocolError> {
    encoder.bytes(bytes).map_err(ProtocolError::malformed)?;
    Ok(())
}

fn decode_fixed<const N: usize>(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<[u8; N], ProtocolError> {
    decoder
        .bytes()
        .map_err(ProtocolError::malformed)?
        .try_into()
        .map_err(ProtocolError::malformed)
}

fn is_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}
