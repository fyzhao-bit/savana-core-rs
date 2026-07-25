use crate::{ProtocolError, StableCode};

macro_rules! fixed_bytes {
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

        impl TryFrom<&[u8]> for $name {
            type Error = ProtocolError;

            fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
                let bytes = <[u8; $length]>::try_from(bytes)
                    .map_err(|_| ProtocolError::stable(StableCode::ProtocolMalformedCbor))?;
                Ok(Self::new(bytes))
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

        impl<'bytes, C> minicbor::Decode<'bytes, C> for $name {
            fn decode(
                decoder: &mut minicbor::Decoder<'bytes>,
                _context: &mut C,
            ) -> Result<Self, minicbor::decode::Error> {
                let position = decoder.position();
                Self::try_from(decoder.bytes()?).map_err(|_| {
                    minicbor::decode::Error::message(StableCode::ProtocolMalformedCbor.as_str())
                        .at(position)
                })
            }
        }
    };
}

fixed_bytes!(Digest32, 32);
fixed_bytes!(Nonce32, 32);
fixed_bytes!(BootId, 32);
fixed_bytes!(Signature64, 64);
fixed_bytes!(RequestId, 16);

macro_rules! bounded_id {
    ($name:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ProtocolError> {
                let value = value.into();
                if !valid_bounded_text(&value) {
                    return Err(ProtocolError::stable(StableCode::ProtocolMalformedCbor));
                }
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<&str> for $name {
            type Error = ProtocolError;

            fn try_from(value: &str) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }

        impl TryFrom<String> for $name {
            type Error = ProtocolError;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }

        impl<C> minicbor::Encode<C> for $name {
            fn encode<W: minicbor::encode::Write>(
                &self,
                encoder: &mut minicbor::Encoder<W>,
                _context: &mut C,
            ) -> Result<(), minicbor::encode::Error<W::Error>> {
                encoder.str(&self.0)?;
                Ok(())
            }
        }

        impl<'bytes, C> minicbor::Decode<'bytes, C> for $name {
            fn decode(
                decoder: &mut minicbor::Decoder<'bytes>,
                _context: &mut C,
            ) -> Result<Self, minicbor::decode::Error> {
                let position = decoder.position();
                let value = decoder.str()?;
                if !valid_bounded_text(value) {
                    return Err(minicbor::decode::Error::message(
                        StableCode::ProtocolMalformedCbor.as_str(),
                    )
                    .at(position));
                }
                Ok(Self(value.to_owned()))
            }
        }
    };
}

fn valid_bounded_text(value: &str) -> bool {
    (1..=128).contains(&value.len()) && !value.chars().any(char::is_control)
}

bounded_id!(KeyId);
bounded_id!(ClientId);
bounded_id!(ToolName);
bounded_id!(ValidatorId);
bounded_id!(ConstraintId);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AttemptKindV1 {
    Read,
    Create,
    Update,
    Delete,
    Send,
    Execute,
}

impl AttemptKindV1 {
    pub const fn tag(self) -> u8 {
        match self {
            Self::Read => 0,
            Self::Create => 1,
            Self::Update => 2,
            Self::Delete => 3,
            Self::Send => 4,
            Self::Execute => 5,
        }
    }
}

impl<C> minicbor::Encode<C> for AttemptKindV1 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        _context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        encoder.u8(self.tag())?;
        Ok(())
    }
}

impl<'bytes, C> minicbor::Decode<'bytes, C> for AttemptKindV1 {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        _context: &mut C,
    ) -> Result<Self, minicbor::decode::Error> {
        let position = decoder.position();
        match decoder.u8()? {
            0 => Ok(Self::Read),
            1 => Ok(Self::Create),
            2 => Ok(Self::Update),
            3 => Ok(Self::Delete),
            4 => Ok(Self::Send),
            5 => Ok(Self::Execute),
            _ => Err(
                minicbor::decode::Error::message(StableCode::ProtocolMalformedCbor.as_str())
                    .at(position),
            ),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, minicbor::Encode, minicbor::Decode)]
#[cbor(array)]
pub struct ProtocolVersion {
    #[n(0)]
    pub major: u16,
    #[n(1)]
    pub minor: u16,
}

impl ProtocolVersion {
    pub const fn new(major: u16, minor: u16) -> Self {
        Self { major, minor }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UnixMillis(u64);

impl UnixMillis {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

impl<C> minicbor::Encode<C> for UnixMillis {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        _context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        encoder.u64(self.0)?;
        Ok(())
    }
}

impl<'bytes, C> minicbor::Decode<'bytes, C> for UnixMillis {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        _context: &mut C,
    ) -> Result<Self, minicbor::decode::Error> {
        Ok(Self::new(decoder.u64()?))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RequestedMode {
    Required,
    Shadow,
}

impl<C> minicbor::Encode<C> for RequestedMode {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        _context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        encoder.u8(match self {
            Self::Required => 0,
            Self::Shadow => 1,
        })?;
        Ok(())
    }
}

impl<'bytes, C> minicbor::Decode<'bytes, C> for RequestedMode {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        _context: &mut C,
    ) -> Result<Self, minicbor::decode::Error> {
        let position = decoder.position();
        match decoder.u64()? {
            0 => Ok(Self::Required),
            1 => Ok(Self::Shadow),
            _ => Err(minicbor::decode::Error::message(
                StableCode::ProtocolUnknownOperation.as_str(),
            )
            .at(position)),
        }
    }
}

const RESOURCE_LIMIT_FIELD_COUNT: usize = 24;

#[derive(Debug, Clone, Copy, PartialEq, Eq, minicbor::Encode)]
#[cbor(map)]
pub struct ResourceLimitsV1 {
    #[n(0)]
    pub frame_bytes: u64,
    #[n(1)]
    pub cbor_depth: u64,
    #[n(2)]
    pub pages: u64,
    #[n(3)]
    pub chars_per_page: u64,
    #[n(4)]
    pub chars_per_document: u64,
    #[n(5)]
    pub observations: u64,
    #[n(6)]
    pub vault_entries: u64,
    #[n(7)]
    pub vault_raw_bytes: u64,
    #[n(8)]
    pub runs_per_client: u64,
    #[n(9)]
    pub vaults_per_client: u64,
    #[n(10)]
    pub approval_ledger_entries: u64,
    #[n(11)]
    pub model_manifest_bytes: u64,
    #[n(12)]
    pub model_assets: u64,
    #[n(13)]
    pub model_tensor_contracts: u64,
    #[n(14)]
    pub model_tensor_rank: u64,
    #[n(15)]
    pub single_model_asset_bytes: u64,
    #[n(16)]
    pub total_model_asset_bytes: u64,
    #[n(17)]
    pub ner_workers: u64,
    #[n(18)]
    pub ner_queue: u64,
    #[n(19)]
    pub ner_text_bytes: u64,
    #[n(20)]
    pub model_probes: u64,
    #[n(21)]
    pub model_probe_spans: u64,
    #[n(22)]
    pub ner_failure_threshold: u64,
    #[n(23)]
    pub request_deadline_ms: u64,
}

impl<'b, C> minicbor::Decode<'b, C> for ResourceLimitsV1 {
    fn decode(
        decoder: &mut minicbor::Decoder<'b>,
        _context: &mut C,
    ) -> Result<Self, minicbor::decode::Error> {
        let map_position = decoder.position();
        let entries = match decoder.map() {
            Ok(Some(entries)) => entries,
            Ok(None) | Err(_) => return Err(malformed_cbor(map_position)),
        };
        let mut fields = [None; RESOURCE_LIMIT_FIELD_COUNT];

        for _ in 0..entries {
            let field_position = decoder.position();
            let field = match decoder.u64() {
                Ok(field) => field,
                Err(_) => return Err(malformed_cbor(field_position)),
            };
            let index = match usize::try_from(field) {
                Ok(index) if index < RESOURCE_LIMIT_FIELD_COUNT => index,
                _ => return Err(unknown_field(field_position)),
            };
            if fields[index].is_some() {
                return Err(malformed_cbor(field_position));
            }

            let value_position = decoder.position();
            fields[index] = Some(match decoder.u64() {
                Ok(value) => value,
                Err(_) => return Err(malformed_cbor(value_position)),
            });
        }

        Ok(Self {
            frame_bytes: required(&fields, 0)?,
            cbor_depth: required(&fields, 1)?,
            pages: required(&fields, 2)?,
            chars_per_page: required(&fields, 3)?,
            chars_per_document: required(&fields, 4)?,
            observations: required(&fields, 5)?,
            vault_entries: required(&fields, 6)?,
            vault_raw_bytes: required(&fields, 7)?,
            runs_per_client: required(&fields, 8)?,
            vaults_per_client: required(&fields, 9)?,
            approval_ledger_entries: required(&fields, 10)?,
            model_manifest_bytes: required(&fields, 11)?,
            model_assets: required(&fields, 12)?,
            model_tensor_contracts: required(&fields, 13)?,
            model_tensor_rank: required(&fields, 14)?,
            single_model_asset_bytes: required(&fields, 15)?,
            total_model_asset_bytes: required(&fields, 16)?,
            ner_workers: required(&fields, 17)?,
            ner_queue: required(&fields, 18)?,
            ner_text_bytes: required(&fields, 19)?,
            model_probes: required(&fields, 20)?,
            model_probe_spans: required(&fields, 21)?,
            ner_failure_threshold: required(&fields, 22)?,
            request_deadline_ms: required(&fields, 23)?,
        })
    }
}

fn required(
    fields: &[Option<u64>; RESOURCE_LIMIT_FIELD_COUNT],
    index: usize,
) -> Result<u64, minicbor::decode::Error> {
    fields[index].ok_or_else(|| malformed_cbor(0))
}

fn malformed_cbor(position: usize) -> minicbor::decode::Error {
    minicbor::decode::Error::message(StableCode::ProtocolMalformedCbor.as_str()).at(position)
}

fn unknown_field(position: usize) -> minicbor::decode::Error {
    minicbor::decode::Error::message(StableCode::ProtocolUnknownField.as_str()).at(position)
}
