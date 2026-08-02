use sha2::{Digest as _, Sha256};

use crate::{ProtocolError, StableCode};

use super::{
    cbor::{scan_single, V2DecodeContext},
    AgentSessionHandleV2, ApprovalPurposeV2, ApprovedConnectorRegistrationHandleV2,
    ConnectorRemovalAuthorizationHandleV2, ConnectorUiAuthorizationHandleV2, Digest32V2,
    PendingConnectorRegistrationHandleV2, SignedApprovalEnvelopeV2, SignedApprovalSettlementV2,
    SignedUiAuthenticationEnvelopeV2, UnixMillisV2,
};

const PREPARE_CONNECTOR_REGISTRATION_TAG_V2: u16 = 70;
const PROPOSE_CONNECTOR_REGISTRATION_TAG_V2: u16 = 71;
const AUTHORIZE_CONNECTOR_REGISTRATION_TAG_V2: u16 = 72;
const APPLY_APPROVED_CONNECTOR_REGISTRATION_TAG_V2: u16 = 73;
const PREPARE_CONNECTOR_REMOVAL_TAG_V2: u16 = 74;
const REMOVE_CONNECTOR_TAG_V2: u16 = 75;
const CONNECTOR_REGISTRY_SNAPSHOT_TAG_V2: u16 = 76;
const MAX_CONNECTOR_DESCRIPTOR_BYTES_V2: usize = 8 * 1024 * 1024;
pub const MAX_CONNECTOR_REGISTRY_DELTA_BYTES_V2: usize = 8 * 1024 * 1024 - 512;
pub const MAX_CONNECTOR_REGISTRY_SNAPSHOT_BYTES_V2: usize = 64 * 1024;
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
pub struct AuthorizeConnectorRegistrationRequestV2 {
    pending: PendingConnectorRegistrationHandleV2,
    settlement: SignedApprovalSettlementV2,
}

impl AuthorizeConnectorRegistrationRequestV2 {
    pub fn new(
        pending: PendingConnectorRegistrationHandleV2,
        settlement: SignedApprovalSettlementV2,
    ) -> Result<Self, ProtocolError> {
        if settlement.purpose() != ApprovalPurposeV2::ConnectorRegistration {
            return Err(malformed());
        }
        Ok(Self {
            pending,
            settlement,
        })
    }

    pub const fn pending(&self) -> PendingConnectorRegistrationHandleV2 {
        self.pending
    }

    pub const fn settlement(&self) -> &SignedApprovalSettlementV2 {
        &self.settlement
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApplyApprovedConnectorRegistrationRequestV2 {
    approved: ApprovedConnectorRegistrationHandleV2,
}

impl ApplyApprovedConnectorRegistrationRequestV2 {
    pub const fn new(approved: ApprovedConnectorRegistrationHandleV2) -> Self {
        Self { approved }
    }

    pub const fn approved(self) -> ApprovedConnectorRegistrationHandleV2 {
        self.approved
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrepareConnectorRemovalRequestV2 {
    session: AgentSessionHandleV2,
    connector_id: Digest32V2,
}

impl PrepareConnectorRemovalRequestV2 {
    pub fn new(
        session: AgentSessionHandleV2,
        connector_id: Digest32V2,
    ) -> Result<Self, ProtocolError> {
        validate_connector_id(connector_id)?;
        Ok(Self {
            session,
            connector_id,
        })
    }

    pub const fn session(self) -> AgentSessionHandleV2 {
        self.session
    }

    pub const fn connector_id(self) -> Digest32V2 {
        self.connector_id
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RemoveConnectorRequestV2 {
    session: AgentSessionHandleV2,
    authorization: ConnectorRemovalAuthorizationHandleV2,
    connector_id: Digest32V2,
}

impl RemoveConnectorRequestV2 {
    pub fn new(
        session: AgentSessionHandleV2,
        authorization: ConnectorRemovalAuthorizationHandleV2,
        connector_id: Digest32V2,
    ) -> Result<Self, ProtocolError> {
        validate_connector_id(connector_id)?;
        Ok(Self {
            session,
            authorization,
            connector_id,
        })
    }

    pub const fn session(self) -> AgentSessionHandleV2 {
        self.session
    }

    pub const fn authorization(self) -> ConnectorRemovalAuthorizationHandleV2 {
        self.authorization
    }

    pub const fn connector_id(self) -> Digest32V2 {
        self.connector_id
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectorRegistrySnapshotRequestV2 {
    session: AgentSessionHandleV2,
}

impl ConnectorRegistrySnapshotRequestV2 {
    pub const fn new(session: AgentSessionHandleV2) -> Self {
        Self { session }
    }

    pub const fn session(self) -> AgentSessionHandleV2 {
        self.session
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum KernelConnectorControlOperationV2 {
    PrepareRegistration(PrepareConnectorRegistrationRequestV2),
    ProposeRegistration(ProposeConnectorRegistrationRequestV2),
    AuthorizeRegistration(AuthorizeConnectorRegistrationRequestV2),
    ApplyApprovedRegistration(ApplyApprovedConnectorRegistrationRequestV2),
    PrepareRemoval(PrepareConnectorRemovalRequestV2),
    Remove(RemoveConnectorRequestV2),
    Snapshot(ConnectorRegistrySnapshotRequestV2),
}

impl KernelConnectorControlOperationV2 {
    pub const fn tag(&self) -> u16 {
        match self {
            Self::PrepareRegistration(_) => PREPARE_CONNECTOR_REGISTRATION_TAG_V2,
            Self::ProposeRegistration(_) => PROPOSE_CONNECTOR_REGISTRATION_TAG_V2,
            Self::AuthorizeRegistration(_) => AUTHORIZE_CONNECTOR_REGISTRATION_TAG_V2,
            Self::ApplyApprovedRegistration(_) => APPLY_APPROVED_CONNECTOR_REGISTRATION_TAG_V2,
            Self::PrepareRemoval(_) => PREPARE_CONNECTOR_REMOVAL_TAG_V2,
            Self::Remove(_) => REMOVE_CONNECTOR_TAG_V2,
            Self::Snapshot(_) => CONNECTOR_REGISTRY_SNAPSHOT_TAG_V2,
        }
    }
}

pub const fn kernel_connector_control_operation_tags_v2() -> &'static [u16; 7] {
    &[
        PREPARE_CONNECTOR_REGISTRATION_TAG_V2,
        PROPOSE_CONNECTOR_REGISTRATION_TAG_V2,
        AUTHORIZE_CONNECTOR_REGISTRATION_TAG_V2,
        APPLY_APPROVED_CONNECTOR_REGISTRATION_TAG_V2,
        PREPARE_CONNECTOR_REMOVAL_TAG_V2,
        REMOVE_CONNECTOR_TAG_V2,
        CONNECTOR_REGISTRY_SNAPSHOT_TAG_V2,
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
        .map_err(ProtocolError::malformed)?;
    match value {
        KernelConnectorControlOperationV2::PrepareRegistration(request) => {
            encoder.array(2).map_err(ProtocolError::malformed)?;
            minicbor::Encode::encode(&request.session, &mut encoder, &mut ())
                .map_err(ProtocolError::malformed)?;
            encoder
                .bytes(&request.canonical_descriptor)
                .map_err(ProtocolError::malformed)?;
        }
        KernelConnectorControlOperationV2::ProposeRegistration(request) => {
            encoder.array(2).map_err(ProtocolError::malformed)?;
            minicbor::Encode::encode(&request.authorization, &mut encoder, &mut ())
                .map_err(ProtocolError::malformed)?;
            encoder
                .bytes(&request.canonical_descriptor)
                .map_err(ProtocolError::malformed)?;
        }
        KernelConnectorControlOperationV2::AuthorizeRegistration(request) => {
            encoder.array(2).map_err(ProtocolError::malformed)?;
            minicbor::Encode::encode(&request.pending, &mut encoder, &mut ())
                .and_then(|()| minicbor::Encode::encode(&request.settlement, &mut encoder, &mut ()))
                .map_err(ProtocolError::malformed)?;
        }
        KernelConnectorControlOperationV2::ApplyApprovedRegistration(request) => {
            encoder.array(1).map_err(ProtocolError::malformed)?;
            minicbor::Encode::encode(&request.approved, &mut encoder, &mut ())
                .map_err(ProtocolError::malformed)?;
        }
        KernelConnectorControlOperationV2::PrepareRemoval(request) => {
            encoder.array(2).map_err(ProtocolError::malformed)?;
            minicbor::Encode::encode(&request.session, &mut encoder, &mut ())
                .and_then(|()| {
                    minicbor::Encode::encode(&request.connector_id, &mut encoder, &mut ())
                })
                .map_err(ProtocolError::malformed)?;
        }
        KernelConnectorControlOperationV2::Remove(request) => {
            encoder.array(3).map_err(ProtocolError::malformed)?;
            minicbor::Encode::encode(&request.session, &mut encoder, &mut ())
                .and_then(|()| {
                    minicbor::Encode::encode(&request.authorization, &mut encoder, &mut ())
                })
                .and_then(|()| {
                    minicbor::Encode::encode(&request.connector_id, &mut encoder, &mut ())
                })
                .map_err(ProtocolError::malformed)?;
        }
        KernelConnectorControlOperationV2::Snapshot(request) => {
            encoder.array(1).map_err(ProtocolError::malformed)?;
            minicbor::Encode::encode(&request.session, &mut encoder, &mut ())
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
    let mut context = V2DecodeContext;
    let value = match tag {
        PREPARE_CONNECTOR_REGISTRATION_TAG_V2 => {
            expect_array(&mut decoder, 2)?;
            KernelConnectorControlOperationV2::PrepareRegistration(
                PrepareConnectorRegistrationRequestV2::new(
                    minicbor::Decode::decode(&mut decoder, &mut context)
                        .map_err(ProtocolError::from_typed_decode)?,
                    decode_descriptor_bytes(&mut decoder)?,
                )?,
            )
        }
        PROPOSE_CONNECTOR_REGISTRATION_TAG_V2 => {
            expect_array(&mut decoder, 2)?;
            KernelConnectorControlOperationV2::ProposeRegistration(
                ProposeConnectorRegistrationRequestV2::new(
                    minicbor::Decode::decode(&mut decoder, &mut context)
                        .map_err(ProtocolError::from_typed_decode)?,
                    decode_descriptor_bytes(&mut decoder)?,
                )?,
            )
        }
        AUTHORIZE_CONNECTOR_REGISTRATION_TAG_V2 => {
            expect_array(&mut decoder, 2)?;
            KernelConnectorControlOperationV2::AuthorizeRegistration(
                AuthorizeConnectorRegistrationRequestV2::new(
                    minicbor::Decode::decode(&mut decoder, &mut context)
                        .map_err(ProtocolError::from_typed_decode)?,
                    minicbor::Decode::decode(&mut decoder, &mut context)
                        .map_err(ProtocolError::from_typed_decode)?,
                )?,
            )
        }
        APPLY_APPROVED_CONNECTOR_REGISTRATION_TAG_V2 => {
            expect_array(&mut decoder, 1)?;
            KernelConnectorControlOperationV2::ApplyApprovedRegistration(
                ApplyApprovedConnectorRegistrationRequestV2::new(
                    minicbor::Decode::decode(&mut decoder, &mut context)
                        .map_err(ProtocolError::from_typed_decode)?,
                ),
            )
        }
        PREPARE_CONNECTOR_REMOVAL_TAG_V2 => {
            expect_array(&mut decoder, 2)?;
            KernelConnectorControlOperationV2::PrepareRemoval(
                PrepareConnectorRemovalRequestV2::new(
                    minicbor::Decode::decode(&mut decoder, &mut context)
                        .map_err(ProtocolError::from_typed_decode)?,
                    minicbor::Decode::decode(&mut decoder, &mut context)
                        .map_err(ProtocolError::from_typed_decode)?,
                )?,
            )
        }
        REMOVE_CONNECTOR_TAG_V2 => {
            expect_array(&mut decoder, 3)?;
            KernelConnectorControlOperationV2::Remove(RemoveConnectorRequestV2::new(
                minicbor::Decode::decode(&mut decoder, &mut context)
                    .map_err(ProtocolError::from_typed_decode)?,
                minicbor::Decode::decode(&mut decoder, &mut context)
                    .map_err(ProtocolError::from_typed_decode)?,
                minicbor::Decode::decode(&mut decoder, &mut context)
                    .map_err(ProtocolError::from_typed_decode)?,
            )?)
        }
        CONNECTOR_REGISTRY_SNAPSHOT_TAG_V2 => {
            expect_array(&mut decoder, 1)?;
            KernelConnectorControlOperationV2::Snapshot(ConnectorRegistrySnapshotRequestV2::new(
                minicbor::Decode::decode(&mut decoder, &mut context)
                    .map_err(ProtocolError::from_typed_decode)?,
            ))
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundedConnectorRegistryDeltaV2(Vec<u8>);

impl BoundedConnectorRegistryDeltaV2 {
    pub fn new(bytes: Vec<u8>) -> Result<Self, ProtocolError> {
        validate_connector_registry_payload(&bytes, MAX_CONNECTOR_REGISTRY_DELTA_BYTES_V2)?;
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundedConnectorRegistrySnapshotV2(Vec<u8>);

impl BoundedConnectorRegistrySnapshotV2 {
    pub fn new(bytes: Vec<u8>) -> Result<Self, ProtocolError> {
        validate_connector_registry_payload(&bytes, MAX_CONNECTOR_REGISTRY_SNAPSHOT_BYTES_V2)?;
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
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
    pending: PendingConnectorRegistrationHandleV2,
    envelope: SignedApprovalEnvelopeV2,
    display_authentication: SignedUiAuthenticationEnvelopeV2,
}

impl ProposeConnectorRegistrationResponseV2 {
    pub fn new(
        pending: PendingConnectorRegistrationHandleV2,
        envelope: SignedApprovalEnvelopeV2,
        display_authentication: SignedUiAuthenticationEnvelopeV2,
    ) -> Self {
        Self {
            pending,
            envelope,
            display_authentication,
        }
    }

    pub const fn pending(&self) -> PendingConnectorRegistrationHandleV2 {
        self.pending
    }

    pub const fn envelope(&self) -> &SignedApprovalEnvelopeV2 {
        &self.envelope
    }

    pub const fn display_authentication(&self) -> &SignedUiAuthenticationEnvelopeV2 {
        &self.display_authentication
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthorizeConnectorRegistrationResponseV2 {
    approved: ApprovedConnectorRegistrationHandleV2,
}

impl AuthorizeConnectorRegistrationResponseV2 {
    pub const fn new(approved: ApprovedConnectorRegistrationHandleV2) -> Self {
        Self { approved }
    }

    pub const fn approved(self) -> ApprovedConnectorRegistrationHandleV2 {
        self.approved
    }
}

macro_rules! connector_registry_mutation_response_v2 {
    ($name:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct $name {
            signed_delta_digest: Digest32V2,
            head_digest: Digest32V2,
            sequence: u64,
            connector_id: Digest32V2,
        }

        impl $name {
            pub fn new(
                signed_delta_digest: Digest32V2,
                head_digest: Digest32V2,
                sequence: u64,
                connector_id: Digest32V2,
            ) -> Result<Self, ProtocolError> {
                validate_connector_registry_mutation(
                    signed_delta_digest,
                    head_digest,
                    sequence,
                    connector_id,
                )?;
                Ok(Self {
                    signed_delta_digest,
                    head_digest,
                    sequence,
                    connector_id,
                })
            }

            pub const fn signed_delta_digest(&self) -> Digest32V2 {
                self.signed_delta_digest
            }

            pub const fn head_digest(&self) -> Digest32V2 {
                self.head_digest
            }

            pub const fn sequence(&self) -> u64 {
                self.sequence
            }

            pub const fn connector_id(&self) -> Digest32V2 {
                self.connector_id
            }
        }
    };
}

connector_registry_mutation_response_v2!(ApplyApprovedConnectorRegistrationResponseV2);
connector_registry_mutation_response_v2!(RemoveConnectorResponseV2);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrepareConnectorRemovalResponseV2 {
    authorization: ConnectorRemovalAuthorizationHandleV2,
    previous_head_digest: Digest32V2,
    expires_at: UnixMillisV2,
}

impl PrepareConnectorRemovalResponseV2 {
    pub fn new(
        authorization: ConnectorRemovalAuthorizationHandleV2,
        previous_head_digest: Digest32V2,
        expires_at: UnixMillisV2,
    ) -> Result<Self, ProtocolError> {
        if is_zero(previous_head_digest.as_bytes()) || expires_at.get() == 0 {
            return Err(malformed());
        }
        Ok(Self {
            authorization,
            previous_head_digest,
            expires_at,
        })
    }

    pub const fn authorization(self) -> ConnectorRemovalAuthorizationHandleV2 {
        self.authorization
    }

    pub const fn previous_head_digest(self) -> Digest32V2 {
        self.previous_head_digest
    }

    pub const fn expires_at(self) -> UnixMillisV2 {
        self.expires_at
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectorRegistrySnapshotResponseV2 {
    canonical_snapshot: BoundedConnectorRegistrySnapshotV2,
}

impl ConnectorRegistrySnapshotResponseV2 {
    pub const fn new(canonical_snapshot: BoundedConnectorRegistrySnapshotV2) -> Self {
        Self { canonical_snapshot }
    }

    pub const fn canonical_snapshot(&self) -> &BoundedConnectorRegistrySnapshotV2 {
        &self.canonical_snapshot
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
    encoder.array(3).map_err(ProtocolError::malformed)?;
    minicbor::Encode::encode(&value.pending, &mut encoder, &mut ())
        .and_then(|()| minicbor::Encode::encode(&value.envelope, &mut encoder, &mut ()))
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
    if decoder.array().map_err(ProtocolError::malformed)? != Some(3) {
        return Err(malformed());
    }
    let mut context = V2DecodeContext;
    let value = ProposeConnectorRegistrationResponseV2::new(
        minicbor::Decode::decode(&mut decoder, &mut context)
            .map_err(ProtocolError::from_typed_decode)?,
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

pub fn encode_authorize_connector_registration_response_v2(
    value: AuthorizeConnectorRegistrationResponseV2,
) -> Result<Vec<u8>, ProtocolError> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder.array(1).map_err(ProtocolError::malformed)?;
    minicbor::Encode::encode(&value.approved, &mut encoder, &mut ())
        .map_err(ProtocolError::malformed)?;
    Ok(encoder.into_writer())
}

pub fn decode_authorize_connector_registration_response_v2(
    bytes: &[u8],
) -> Result<AuthorizeConnectorRegistrationResponseV2, ProtocolError> {
    scan_single(bytes)?;
    let mut decoder = minicbor::Decoder::new(bytes);
    expect_array(&mut decoder, 1)?;
    let mut context = V2DecodeContext;
    let value = AuthorizeConnectorRegistrationResponseV2::new(
        minicbor::Decode::decode(&mut decoder, &mut context)
            .map_err(ProtocolError::from_typed_decode)?,
    );
    if decoder.position() != bytes.len()
        || encode_authorize_connector_registration_response_v2(value)? != bytes
    {
        return Err(noncanonical());
    }
    Ok(value)
}

pub fn encode_apply_approved_connector_registration_response_v2(
    value: &ApplyApprovedConnectorRegistrationResponseV2,
) -> Result<Vec<u8>, ProtocolError> {
    encode_connector_registry_mutation_response_fields(
        value.signed_delta_digest,
        value.head_digest,
        value.sequence,
        value.connector_id,
    )
}

pub fn decode_apply_approved_connector_registration_response_v2(
    bytes: &[u8],
) -> Result<ApplyApprovedConnectorRegistrationResponseV2, ProtocolError> {
    let (signed_delta_digest, head_digest, sequence, connector_id) =
        decode_connector_registry_mutation_response_fields(bytes)?;
    let value = ApplyApprovedConnectorRegistrationResponseV2::new(
        signed_delta_digest,
        head_digest,
        sequence,
        connector_id,
    )?;
    if encode_apply_approved_connector_registration_response_v2(&value)? != bytes {
        return Err(noncanonical());
    }
    Ok(value)
}

pub fn encode_prepare_connector_removal_response_v2(
    value: PrepareConnectorRemovalResponseV2,
) -> Result<Vec<u8>, ProtocolError> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder.array(3).map_err(ProtocolError::malformed)?;
    minicbor::Encode::encode(&value.authorization, &mut encoder, &mut ())
        .and_then(|()| minicbor::Encode::encode(&value.previous_head_digest, &mut encoder, &mut ()))
        .and_then(|()| minicbor::Encode::encode(&value.expires_at, &mut encoder, &mut ()))
        .map_err(ProtocolError::malformed)?;
    Ok(encoder.into_writer())
}

pub fn decode_prepare_connector_removal_response_v2(
    bytes: &[u8],
) -> Result<PrepareConnectorRemovalResponseV2, ProtocolError> {
    scan_single(bytes)?;
    let mut decoder = minicbor::Decoder::new(bytes);
    expect_array(&mut decoder, 3)?;
    let mut context = V2DecodeContext;
    let value = PrepareConnectorRemovalResponseV2::new(
        minicbor::Decode::decode(&mut decoder, &mut context)
            .map_err(ProtocolError::from_typed_decode)?,
        minicbor::Decode::decode(&mut decoder, &mut context)
            .map_err(ProtocolError::from_typed_decode)?,
        minicbor::Decode::decode(&mut decoder, &mut context)
            .map_err(ProtocolError::from_typed_decode)?,
    )?;
    if decoder.position() != bytes.len()
        || encode_prepare_connector_removal_response_v2(value)? != bytes
    {
        return Err(noncanonical());
    }
    Ok(value)
}

pub fn encode_remove_connector_response_v2(
    value: &RemoveConnectorResponseV2,
) -> Result<Vec<u8>, ProtocolError> {
    encode_connector_registry_mutation_response_fields(
        value.signed_delta_digest,
        value.head_digest,
        value.sequence,
        value.connector_id,
    )
}

pub fn decode_remove_connector_response_v2(
    bytes: &[u8],
) -> Result<RemoveConnectorResponseV2, ProtocolError> {
    let (signed_delta_digest, head_digest, sequence, connector_id) =
        decode_connector_registry_mutation_response_fields(bytes)?;
    let value =
        RemoveConnectorResponseV2::new(signed_delta_digest, head_digest, sequence, connector_id)?;
    if encode_remove_connector_response_v2(&value)? != bytes {
        return Err(noncanonical());
    }
    Ok(value)
}

pub fn encode_connector_registry_snapshot_response_v2(
    value: &ConnectorRegistrySnapshotResponseV2,
) -> Result<Vec<u8>, ProtocolError> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(1)
        .and_then(|encoder| encoder.bytes(value.canonical_snapshot.as_bytes()))
        .map_err(ProtocolError::malformed)?;
    let bytes = encoder.into_writer();
    validate_connector_wire_size(&bytes)?;
    Ok(bytes)
}

pub fn decode_connector_registry_snapshot_response_v2(
    bytes: &[u8],
) -> Result<ConnectorRegistrySnapshotResponseV2, ProtocolError> {
    scan_single(bytes)?;
    let mut decoder = minicbor::Decoder::new(bytes);
    expect_array(&mut decoder, 1)?;
    let value = ConnectorRegistrySnapshotResponseV2::new(BoundedConnectorRegistrySnapshotV2::new(
        decoder.bytes().map_err(ProtocolError::malformed)?.to_vec(),
    )?);
    if decoder.position() != bytes.len()
        || encode_connector_registry_snapshot_response_v2(&value)? != bytes
    {
        return Err(noncanonical());
    }
    Ok(value)
}

fn encode_connector_registry_mutation_response_fields(
    signed_delta_digest: Digest32V2,
    head_digest: Digest32V2,
    sequence: u64,
    connector_id: Digest32V2,
) -> Result<Vec<u8>, ProtocolError> {
    validate_connector_registry_mutation(signed_delta_digest, head_digest, sequence, connector_id)?;
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder.array(4).map_err(ProtocolError::malformed)?;
    minicbor::Encode::encode(&signed_delta_digest, &mut encoder, &mut ())
        .map_err(ProtocolError::malformed)?;
    minicbor::Encode::encode(&head_digest, &mut encoder, &mut ())
        .map_err(ProtocolError::malformed)?;
    encoder.u64(sequence).map_err(ProtocolError::malformed)?;
    minicbor::Encode::encode(&connector_id, &mut encoder, &mut ())
        .map_err(ProtocolError::malformed)?;
    let bytes = encoder.into_writer();
    validate_connector_wire_size(&bytes)?;
    Ok(bytes)
}

fn decode_connector_registry_mutation_response_fields(
    bytes: &[u8],
) -> Result<(Digest32V2, Digest32V2, u64, Digest32V2), ProtocolError> {
    scan_single(bytes)?;
    let mut decoder = minicbor::Decoder::new(bytes);
    expect_array(&mut decoder, 4)?;
    let mut context = V2DecodeContext;
    let signed_delta_digest = minicbor::Decode::decode(&mut decoder, &mut context)
        .map_err(ProtocolError::from_typed_decode)?;
    let head_digest = minicbor::Decode::decode(&mut decoder, &mut context)
        .map_err(ProtocolError::from_typed_decode)?;
    let sequence = decoder.u64().map_err(ProtocolError::malformed)?;
    let connector_id = minicbor::Decode::decode(&mut decoder, &mut context)
        .map_err(ProtocolError::from_typed_decode)?;
    validate_connector_registry_mutation(signed_delta_digest, head_digest, sequence, connector_id)?;
    if decoder.position() != bytes.len() {
        return Err(malformed());
    }
    Ok((signed_delta_digest, head_digest, sequence, connector_id))
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

fn validate_connector_registry_payload(
    bytes: &[u8],
    maximum_bytes: usize,
) -> Result<(), ProtocolError> {
    if bytes.is_empty() || bytes.len() > maximum_bytes {
        return Err(malformed());
    }
    super::kernel_service::validate_canonical_body(bytes)
}

fn validate_connector_registry_mutation(
    signed_delta_digest: Digest32V2,
    head_digest: Digest32V2,
    sequence: u64,
    connector_id: Digest32V2,
) -> Result<(), ProtocolError> {
    if is_zero(signed_delta_digest.as_bytes()) || is_zero(head_digest.as_bytes()) || sequence == 0 {
        return Err(malformed());
    }
    validate_connector_id(connector_id)
}

fn validate_connector_id(connector_id: Digest32V2) -> Result<(), ProtocolError> {
    if is_zero(connector_id.as_bytes()) {
        return Err(malformed());
    }
    Ok(())
}

fn validate_connector_wire_size(bytes: &[u8]) -> Result<(), ProtocolError> {
    if bytes.is_empty() || bytes.len() > 8 * 1024 * 1024 {
        return Err(malformed());
    }
    Ok(())
}

fn expect_array(decoder: &mut minicbor::Decoder<'_>, count: u64) -> Result<(), ProtocolError> {
    if decoder.array().map_err(ProtocolError::malformed)? != Some(count) {
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

fn noncanonical() -> ProtocolError {
    ProtocolError::stable(StableCode::ProtocolNonCanonicalCbor)
}
