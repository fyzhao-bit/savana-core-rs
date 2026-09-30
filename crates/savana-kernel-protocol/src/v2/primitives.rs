use core::fmt;

use zeroize::Zeroizing;

use crate::{ProtocolError, StableCode};

use super::cbor::V2DecodeContext;

macro_rules! fixed_bytes_v2 {
    ($name:ident, $length:literal) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name([u8; $length]);

        impl $name {
            pub const fn new(bytes: [u8; $length]) -> Self {
                Self(bytes)
            }

            pub const fn as_bytes(&self) -> &[u8; $length] {
                &self.0
            }
        }

        impl<C> minicbor::Encode<C> for $name {
            fn encode<W: minicbor::encode::Write>(
                &self,
                encoder: &mut minicbor::Encoder<W>,
                _context: &mut C,
            ) -> Result<(), minicbor::encode::Error<W::Error>> {
                encoder.bytes(&self.0)?;
                Ok(())
            }
        }

        impl<'bytes> minicbor::Decode<'bytes, V2DecodeContext> for $name {
            fn decode(
                decoder: &mut minicbor::Decoder<'bytes>,
                _context: &mut V2DecodeContext,
            ) -> Result<Self, minicbor::decode::Error> {
                let position = decoder.position();
                let bytes = <[u8; $length]>::try_from(decoder.bytes()?).map_err(|_| {
                    minicbor::decode::Error::message(StableCode::ProtocolMalformedCbor.as_str())
                        .at(position)
                })?;
                Ok(Self::new(bytes))
            }
        }
    };
}

fixed_bytes_v2!(RequestIdV2, 16);
fixed_bytes_v2!(Digest32V2, 32);
fixed_bytes_v2!(Nonce32V2, 32);
fixed_bytes_v2!(BootIdV2, 32);
fixed_bytes_v2!(Ed25519KeyIdV2, 32);
fixed_bytes_v2!(HpkeX25519KeyIdV2, 32);
fixed_bytes_v2!(ReplayAeadKeyIdV2, 32);
fixed_bytes_v2!(VaultKeyIdV2, 32);
fixed_bytes_v2!(Ed25519SignatureV2, 64);
fixed_bytes_v2!(DurableRunIdV2, 32);
fixed_bytes_v2!(ValueInternalIdV2, 32);
fixed_bytes_v2!(InternalSlotDigestV2, 32);
fixed_bytes_v2!(ActionIntentIdV2, 32);
fixed_bytes_v2!(ProducerIdentityV2, 32);
fixed_bytes_v2!(ExecutorIdentityV2, 32);
fixed_bytes_v2!(PrincipalIdV2, 32);
fixed_bytes_v2!(ServiceIdentityV2, 32);
fixed_bytes_v2!(DurableTaskIdV2, 32);
fixed_bytes_v2!(DurableReleaseIdV2, 32);
fixed_bytes_v2!(InternalStepIdV2, 32);
fixed_bytes_v2!(RunRevisionDigestV2, 32);
fixed_bytes_v2!(PlanRevisionDigestV2, 32);
fixed_bytes_v2!(PlannerSlotRefV2, 16);
fixed_bytes_v2!(FixedBytes32V2, 32);

const MAX_ARGUMENT_NAME_BYTES_V2: usize = 128;
const MAX_IDENTITY_STRING_BYTES_V2: usize = 255;
const MAX_SENSITIVE_WIRE_BYTES_V2: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ArgumentNameV2(String);

impl ArgumentNameV2 {
    pub fn new(value: String) -> Result<Self, ProtocolError> {
        if value.is_empty()
            || value.len() > MAX_ARGUMENT_NAME_BYTES_V2
            || value.chars().any(char::is_control)
        {
            return Err(malformed_protocol());
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BoundedIdentityStringV2(String);

impl BoundedIdentityStringV2 {
    pub fn new(value: String) -> Result<Self, ProtocolError> {
        if value.is_empty()
            || value.len() > MAX_IDENTITY_STRING_BYTES_V2
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return Err(malformed_protocol());
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

pub struct ZeroizingBytesV2(Zeroizing<Vec<u8>>);

impl ZeroizingBytesV2 {
    pub fn new(value: Vec<u8>) -> Result<Self, ProtocolError> {
        if value.len() > MAX_SENSITIVE_WIRE_BYTES_V2 {
            return Err(malformed_protocol());
        }
        Ok(Self(Zeroizing::new(value)))
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl fmt::Debug for ZeroizingBytesV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ZeroizingBytesV2(<redacted>)")
    }
}

pub struct ZeroizingTextV2(Zeroizing<String>);

impl ZeroizingTextV2 {
    pub fn new(value: String) -> Result<Self, ProtocolError> {
        if value.is_empty()
            || value.len() > MAX_SENSITIVE_WIRE_BYTES_V2
            || value.chars().any(char::is_control)
        {
            return Err(malformed_protocol());
        }
        Ok(Self(Zeroizing::new(value)))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for ZeroizingTextV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ZeroizingTextV2(<redacted>)")
    }
}

macro_rules! bounded_string_v2 {
    ($name:ident) => {
        impl<C> minicbor::Encode<C> for $name {
            fn encode<W: minicbor::encode::Write>(
                &self,
                encoder: &mut minicbor::Encoder<W>,
                _context: &mut C,
            ) -> Result<(), minicbor::encode::Error<W::Error>> {
                encoder.str(self.as_str())?;
                Ok(())
            }
        }

        impl<'bytes, C> minicbor::Decode<'bytes, C> for $name {
            fn decode(
                decoder: &mut minicbor::Decoder<'bytes>,
                _context: &mut C,
            ) -> Result<Self, minicbor::decode::Error> {
                let position = decoder.position();
                Self::new(decoder.str()?.to_owned()).map_err(|_| malformed(position))
            }
        }
    };
}

bounded_string_v2!(ArgumentNameV2);
bounded_string_v2!(BoundedIdentityStringV2);

impl<C> minicbor::Encode<C> for ZeroizingBytesV2 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        _context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        encoder.bytes(self.as_bytes())?;
        Ok(())
    }
}

impl<'bytes, C> minicbor::Decode<'bytes, C> for ZeroizingBytesV2 {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        _context: &mut C,
    ) -> Result<Self, minicbor::decode::Error> {
        let position = decoder.position();
        let bytes = decoder.bytes()?;
        if bytes.len() > MAX_SENSITIVE_WIRE_BYTES_V2 {
            return Err(malformed(position));
        }
        Self::new(bytes.to_vec()).map_err(|_| malformed(position))
    }
}

impl<C> minicbor::Encode<C> for ZeroizingTextV2 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        _context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        encoder.str(self.as_str())?;
        Ok(())
    }
}

impl<'bytes, C> minicbor::Decode<'bytes, C> for ZeroizingTextV2 {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        _context: &mut C,
    ) -> Result<Self, minicbor::decode::Error> {
        let position = decoder.position();
        let value = decoder.str()?;
        if value.len() > MAX_SENSITIVE_WIRE_BYTES_V2 {
            return Err(malformed(position));
        }
        Self::new(value.to_owned()).map_err(|_| malformed(position))
    }
}

macro_rules! unsigned_u32_v2 {
    ($($name:ident),+ $(,)?) => {
        $(
            #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
            pub struct $name(u32);

            impl $name {
                pub const fn new(value: u32) -> Self {
                    Self(value)
                }

                pub const fn get(self) -> u32 {
                    self.0
                }
            }

            impl<C> minicbor::Encode<C> for $name {
                fn encode<W: minicbor::encode::Write>(
                    &self,
                    encoder: &mut minicbor::Encoder<W>,
                    _context: &mut C,
                ) -> Result<(), minicbor::encode::Error<W::Error>> {
                    encoder.u32(self.0)?;
                    Ok(())
                }
            }

            impl<'bytes> minicbor::Decode<'bytes, V2DecodeContext> for $name {
                fn decode(
                    decoder: &mut minicbor::Decoder<'bytes>,
                    _context: &mut V2DecodeContext,
                ) -> Result<Self, minicbor::decode::Error> {
                    Ok(Self::new(decoder.u32()?))
                }
            }
        )+
    };
}

unsigned_u32_v2!(
    RoleIdV2,
    ActionTemplateIdV2,
    ToolClassIdV2,
    PlannerRouteIdV2,
    NamespaceIdV2,
    EntityIdV2,
    OntologySetIdV2,
    ProjectionIdV2,
    DisplayProjectionIdV2,
    ImplementationIdV2,
    PolicyConstantIdV2,
    ClosedMediaTypeV2,
    ClosedExtensionClassV2,
    ClosedConfidenceClassV2,
    AttemptKindV2,
    SlotKindV2,
    RelationIdV2,
    StaticTemplateIdV2,
    EnrollmentProfileIdV2,
);

macro_rules! unsigned_u64_v2 {
    ($name:ident) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name(u64);

        impl $name {
            pub const fn new(value: u64) -> Self {
                Self(value)
            }

            pub const fn get(self) -> u64 {
                self.0
            }
        }

        impl<C> minicbor::Encode<C> for $name {
            fn encode<W: minicbor::encode::Write>(
                &self,
                encoder: &mut minicbor::Encoder<W>,
                _context: &mut C,
            ) -> Result<(), minicbor::encode::Error<W::Error>> {
                encoder.u64(self.0)?;
                Ok(())
            }
        }

        impl<'bytes> minicbor::Decode<'bytes, V2DecodeContext> for $name {
            fn decode(
                decoder: &mut minicbor::Decoder<'bytes>,
                _context: &mut V2DecodeContext,
            ) -> Result<Self, minicbor::decode::Error> {
                Ok(Self::new(decoder.u64()?))
            }
        }
    };
}

unsigned_u64_v2!(UnixMillisV2);
unsigned_u64_v2!(MonotonicNanosV2);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VersionV2 {
    major: u16,
    minor: u16,
    patch: u16,
}

impl VersionV2 {
    pub const fn new(major: u16, minor: u16, patch: u16) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    pub const fn major(self) -> u16 {
        self.major
    }

    pub const fn minor(self) -> u16 {
        self.minor
    }

    pub const fn patch(self) -> u16 {
        self.patch
    }
}

impl<C> minicbor::Encode<C> for VersionV2 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        _context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        encoder
            .array(3)?
            .u16(self.major)?
            .u16(self.minor)?
            .u16(self.patch)?;
        Ok(())
    }
}

impl<'bytes> minicbor::Decode<'bytes, V2DecodeContext> for VersionV2 {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        _context: &mut V2DecodeContext,
    ) -> Result<Self, minicbor::decode::Error> {
        let position = decoder.position();
        if decoder.array()? != Some(3) {
            return Err(malformed(position));
        }
        Ok(Self::new(decoder.u16()?, decoder.u16()?, decoder.u16()?))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EndpointRoleV2 {
    JarvisAgentControl,
    AgentKernel,
    IngressKernel,
    KernelExecutor,
    AgentApproval,
    IngressApproval,
    ApprovalAdmin,
    KernelApproval,
}

impl EndpointRoleV2 {
    pub const fn tag(self) -> u16 {
        match self {
            Self::JarvisAgentControl => 1,
            Self::AgentKernel => 2,
            Self::IngressKernel => 3,
            Self::KernelExecutor => 4,
            Self::AgentApproval => 5,
            Self::IngressApproval => 6,
            Self::ApprovalAdmin => 7,
            Self::KernelApproval => 8,
        }
    }
}

impl<C> minicbor::Encode<C> for EndpointRoleV2 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        _context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        encoder.array(1)?.u16(self.tag())?;
        Ok(())
    }
}

impl<'bytes> minicbor::Decode<'bytes, V2DecodeContext> for EndpointRoleV2 {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        _context: &mut V2DecodeContext,
    ) -> Result<Self, minicbor::decode::Error> {
        let position = decoder.position();
        if decoder.array()? != Some(1) {
            return Err(malformed(position));
        }
        match decoder.u16()? {
            1 => Ok(Self::JarvisAgentControl),
            2 => Ok(Self::AgentKernel),
            3 => Ok(Self::IngressKernel),
            4 => Ok(Self::KernelExecutor),
            5 => Ok(Self::AgentApproval),
            6 => Ok(Self::IngressApproval),
            7 => Ok(Self::ApprovalAdmin),
            8 => Ok(Self::KernelApproval),
            _ => Err(malformed(position)),
        }
    }
}

fn malformed(position: usize) -> minicbor::decode::Error {
    minicbor::decode::Error::message(StableCode::ProtocolMalformedCbor.as_str()).at(position)
}

fn malformed_protocol() -> ProtocolError {
    ProtocolError::stable(StableCode::ProtocolMalformedCbor)
}
