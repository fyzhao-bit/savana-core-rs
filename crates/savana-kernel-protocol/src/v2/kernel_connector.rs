use sha2::{Digest as _, Sha256};

use crate::{ProtocolError, StableCode};

use super::{
    cbor::{scan_single, V2DecodeContext},
    AgentSessionHandleV2, ConnectorUiAuthorizationHandleV2, Digest32V2, SignedApprovalEnvelopeV2,
    SignedUiAuthenticationEnvelopeV2, UnixMillisV2,
};

const PREPARE_CONNECTOR_REGISTRATION_TAG_V2: u16 = 70;
const PROPOSE_CONNECTOR_REGISTRATION_TAG_V2: u16 = 71;
const MAX_CONNECTOR_DESCRIPTOR_BYTES_V2: usize = 8 * 1024 * 1024;
const CONNECTOR_DESCRIPTOR_DIGEST_DOMAIN_V2: &[u8] =
    b"SAVANA_CONNECTOR_REGISTRATION_DESCRIPTOR_V2\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrepareConnectorRegistrationRequestV2 {
    session: AgentSessionHandleV2,
    canonical_descriptor: Vec<u8>,
}

impl PrepareConnectorRegistrationRequestV2 {
    pub fn new(
        session: AgentSessionHandleV2,
        canonical_descriptor: Vec<u8>,
    ) -> Result<Self, ProtocolError> {
        validate_descriptor_bytes(&canonical_descriptor)?;
        Ok(Self {
            session,
            canonical_descriptor,
        })
    }

    pub const fn session(&self) -> AgentSessionHandleV2 {
        self.session
    }

    pub fn canonical_descriptor(&self) -> &[u8] {
        &self.canonical_descriptor
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProposeConnectorRegistrationRequestV2 {
    authorization: ConnectorUiAuthorizationHandleV2,
    canonical_descriptor: Vec<u8>,
}

impl ProposeConnectorRegistrationRequestV2 {
    pub fn new(
        authorization: ConnectorUiAuthorizationHandleV2,
        canonical_descriptor: Vec<u8>,
    ) -> Result<Self, ProtocolError> {
        validate_descriptor_bytes(&canonical_descriptor)?;
        Ok(Self {
            authorization,
            canonical_descriptor,
        })
    }

    pub const fn authorization(&self) -> ConnectorUiAuthorizationHandleV2 {
        self.authorization
    }

    pub fn canonical_descriptor(&self) -> &[u8] {
        &self.canonical_descriptor
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KernelConnectorControlOperationV2 {
    PrepareRegistration(PrepareConnectorRegistrationRequestV2),
    ProposeRegistration(ProposeConnectorRegistrationRequestV2),
}

impl KernelConnectorControlOperationV2 {
    pub const fn tag(&self) -> u16 {
        match self {
            Self::PrepareRegistration(_) => PREPARE_CONNECTOR_REGISTRATION_TAG_V2,
            Self::ProposeRegistration(_) => PROPOSE_CONNECTOR_REGISTRATION_TAG_V2,
        }
    }
}

pub const fn kernel_connector_control_operation_tags_v2() -> &'static [u16; 2] {
    &[
        PREPARE_CONNECTOR_REGISTRATION_TAG_V2,
        PROPOSE_CONNECTOR_REGISTRATION_TAG_V2,
    ]
}

pub fn connector_registration_descriptor_digest_v2(
    bytes: &[u8],
) -> Result<Digest32V2, ProtocolError> {
    validate_descriptor_bytes(bytes)?;
    let mut hasher = Sha256::new();
    hasher.update(CONNECTOR_DESCRIPTOR_DIGEST_DOMAIN_V2);
    hasher.update(bytes);
    Ok(Digest32V2::new(hasher.finalize().into()))
}

pub fn encode_kernel_connector_control_operation_v2(
    value: &KernelConnectorControlOperationV2,
) -> Result<Vec<u8>, ProtocolError> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(2)
        .and_then(|encoder| encoder.u16(value.tag()))
        .and_then(|encoder| encoder.array(2))
        .map_err(ProtocolError::malformed)?;
    match value {
        KernelConnectorControlOperationV2::PrepareRegistration(request) => {
            minicbor::Encode::encode(&request.session, &mut encoder, &mut ())
                .map_err(ProtocolError::malformed)?;
            encoder
                .bytes(&request.canonical_descriptor)
                .map_err(ProtocolError::malformed)?;
        }
        KernelConnectorControlOperationV2::ProposeRegistration(request) => {
            minicbor::Encode::encode(&request.authorization, &mut encoder, &mut ())
                .map_err(ProtocolError::malformed)?;
            encoder
                .bytes(&request.canonical_descriptor)
                .map_err(ProtocolError::malformed)?;
        }
    }
    Ok(encoder.into_writer())
}

pub fn decode_kernel_connector_control_operation_v2(
    bytes: &[u8],
) -> Result<KernelConnectorControlOperationV2, ProtocolError> {
    scan_single(bytes)?;
    let mut decoder = minicbor::Decoder::new(bytes);
    if decoder.array().map_err(ProtocolError::malformed)? != Some(2) {
        return Err(malformed());
    }
    let tag = decoder.u16().map_err(ProtocolError::malformed)?;
    if decoder.array().map_err(ProtocolError::malformed)? != Some(2) {
        return Err(malformed());
    }
    let mut context = V2DecodeContext;
    let value = match tag {
        PREPARE_CONNECTOR_REGISTRATION_TAG_V2 => {
            KernelConnectorControlOperationV2::PrepareRegistration(
                PrepareConnectorRegistrationRequestV2::new(
                    minicbor::Decode::decode(&mut decoder, &mut context)
                        .map_err(ProtocolError::from_typed_decode)?,
                    decode_descriptor_bytes(&mut decoder)?,
                )?,
            )
        }
        PROPOSE_CONNECTOR_REGISTRATION_TAG_V2 => {
            KernelConnectorControlOperationV2::ProposeRegistration(
                ProposeConnectorRegistrationRequestV2::new(
                    minicbor::Decode::decode(&mut decoder, &mut context)
                        .map_err(ProtocolError::from_typed_decode)?,
                    decode_descriptor_bytes(&mut decoder)?,
                )?,
            )
        }
        _ => return Err(ProtocolError::stable(StableCode::ProtocolUnknownOperation)),
    };
    if decoder.position() != bytes.len()
        || encode_kernel_connector_control_operation_v2(&value)? != bytes
    {
        return Err(ProtocolError::stable(StableCode::ProtocolNonCanonicalCbor));
    }
    Ok(value)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrepareConnectorRegistrationResponseV2 {
    authorization: ConnectorUiAuthorizationHandleV2,
    descriptor_digest: Digest32V2,
    previous_head_digest: Digest32V2,
    expires_at: UnixMillisV2,
}

impl PrepareConnectorRegistrationResponseV2 {
    pub fn new(
        authorization: ConnectorUiAuthorizationHandleV2,
        descriptor_digest: Digest32V2,
        previous_head_digest: Digest32V2,
        expires_at: UnixMillisV2,
    ) -> Result<Self, ProtocolError> {
        if is_zero(descriptor_digest.as_bytes())
            || is_zero(previous_head_digest.as_bytes())
            || expires_at.get() == 0
        {
            return Err(malformed());
        }
        Ok(Self {
            authorization,
            descriptor_digest,
            previous_head_digest,
            expires_at,
        })
    }

    pub const fn authorization(self) -> ConnectorUiAuthorizationHandleV2 {
        self.authorization
    }

    pub const fn descriptor_digest(self) -> Digest32V2 {
        self.descriptor_digest
    }

    pub const fn previous_head_digest(self) -> Digest32V2 {
        self.previous_head_digest
    }

    pub const fn expires_at(self) -> UnixMillisV2 {
        self.expires_at
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProposeConnectorRegistrationResponseV2 {
    envelope: SignedApprovalEnvelopeV2,
    display_authentication: SignedUiAuthenticationEnvelopeV2,
}

impl ProposeConnectorRegistrationResponseV2 {
    pub fn new(
        envelope: SignedApprovalEnvelopeV2,
        display_authentication: SignedUiAuthenticationEnvelopeV2,
    ) -> Self {
        Self {
            envelope,
            display_authentication,
        }
    }

    pub const fn envelope(&self) -> &SignedApprovalEnvelopeV2 {
        &self.envelope
    }

    pub const fn display_authentication(&self) -> &SignedUiAuthenticationEnvelopeV2 {
        &self.display_authentication
    }
}

pub fn encode_prepare_connector_registration_response_v2(
    value: PrepareConnectorRegistrationResponseV2,
) -> Result<Vec<u8>, ProtocolError> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder.array(4).map_err(ProtocolError::malformed)?;
    minicbor::Encode::encode(&value.authorization, &mut encoder, &mut ())
        .and_then(|()| minicbor::Encode::encode(&value.descriptor_digest, &mut encoder, &mut ()))
        .and_then(|()| minicbor::Encode::encode(&value.previous_head_digest, &mut encoder, &mut ()))
        .and_then(|()| minicbor::Encode::encode(&value.expires_at, &mut encoder, &mut ()))
        .map_err(ProtocolError::malformed)?;
    Ok(encoder.into_writer())
}

pub fn decode_prepare_connector_registration_response_v2(
    bytes: &[u8],
) -> Result<PrepareConnectorRegistrationResponseV2, ProtocolError> {
    scan_single(bytes)?;
    let mut decoder = minicbor::Decoder::new(bytes);
    if decoder.array().map_err(ProtocolError::malformed)? != Some(4) {
        return Err(malformed());
    }
    let mut context = V2DecodeContext;
    let value = PrepareConnectorRegistrationResponseV2::new(
        minicbor::Decode::decode(&mut decoder, &mut context)
            .map_err(ProtocolError::from_typed_decode)?,
        minicbor::Decode::decode(&mut decoder, &mut context)
            .map_err(ProtocolError::from_typed_decode)?,
        minicbor::Decode::decode(&mut decoder, &mut context)
            .map_err(ProtocolError::from_typed_decode)?,
        minicbor::Decode::decode(&mut decoder, &mut context)
            .map_err(ProtocolError::from_typed_decode)?,
    )?;
    if decoder.position() != bytes.len()
        || encode_prepare_connector_registration_response_v2(value)? != bytes
    {
        return Err(ProtocolError::stable(StableCode::ProtocolNonCanonicalCbor));
    }
    Ok(value)
}

pub fn encode_propose_connector_registration_response_v2(
    value: &ProposeConnectorRegistrationResponseV2,
) -> Result<Vec<u8>, ProtocolError> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder.array(2).map_err(ProtocolError::malformed)?;
    minicbor::Encode::encode(&value.envelope, &mut encoder, &mut ())
        .and_then(|()| {
            minicbor::Encode::encode(&value.display_authentication, &mut encoder, &mut ())
        })
        .map_err(ProtocolError::malformed)?;
    Ok(encoder.into_writer())
}

pub fn decode_propose_connector_registration_response_v2(
    bytes: &[u8],
) -> Result<ProposeConnectorRegistrationResponseV2, ProtocolError> {
    scan_single(bytes)?;
    let mut decoder = minicbor::Decoder::new(bytes);
    if decoder.array().map_err(ProtocolError::malformed)? != Some(2) {
        return Err(malformed());
    }
    let mut context = V2DecodeContext;
    let value = ProposeConnectorRegistrationResponseV2::new(
        minicbor::Decode::decode(&mut decoder, &mut context)
            .map_err(ProtocolError::from_typed_decode)?,
        minicbor::Decode::decode(&mut decoder, &mut context)
            .map_err(ProtocolError::from_typed_decode)?,
    );
    if decoder.position() != bytes.len()
        || encode_propose_connector_registration_response_v2(&value)? != bytes
    {
        return Err(ProtocolError::stable(StableCode::ProtocolNonCanonicalCbor));
    }
    Ok(value)
}

fn decode_descriptor_bytes(decoder: &mut minicbor::Decoder<'_>) -> Result<Vec<u8>, ProtocolError> {
    let value = decoder.bytes().map_err(ProtocolError::malformed)?;
    validate_descriptor_bytes(value)?;
    Ok(value.to_vec())
}

fn validate_descriptor_bytes(bytes: &[u8]) -> Result<(), ProtocolError> {
    if bytes.is_empty() || bytes.len() > MAX_CONNECTOR_DESCRIPTOR_BYTES_V2 {
        return Err(malformed());
    }
    Ok(())
}

const fn is_zero(bytes: &[u8]) -> bool {
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != 0 {
            return false;
        }
        index += 1;
    }
    true
}

fn malformed() -> ProtocolError {
    ProtocolError::stable(StableCode::ProtocolMalformedCbor)
}
