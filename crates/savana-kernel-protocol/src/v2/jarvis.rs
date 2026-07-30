use core::fmt;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use minicbor::{Decode as _, Encode as _};

use crate::{ProtocolError, StableCode};

use super::{cbor::V2DecodeContext, JarvisBootstrapSelectorV2, Nonce32V2, TaskHandleV2};

fn malformed(position: usize) -> minicbor::decode::Error {
    minicbor::decode::Error::message(StableCode::ProtocolMalformedCbor.as_str()).at(position)
}

fn encode_error<E>() -> minicbor::encode::Error<E> {
    minicbor::encode::Error::message(StableCode::ProtocolMalformedCbor.as_str())
}

fn expect_array(
    decoder: &mut minicbor::Decoder<'_>,
    position: usize,
    expected: u64,
) -> Result<(), minicbor::decode::Error> {
    if decoder.array()? == Some(expected) {
        Ok(())
    } else {
        Err(malformed(position))
    }
}

macro_rules! closed_unit_enum_v2 {
    (
        $name:ident {
            $($variant:ident = $tag:literal),+ $(,)?
        }
    ) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum $name {
            $($variant),+
        }

        impl $name {
            pub const fn tag(self) -> u16 {
                match self {
                    $(Self::$variant => $tag),+
                }
            }
        }

        impl<C> minicbor::Encode<C> for $name {
            fn encode<W: minicbor::encode::Write>(
                &self,
                encoder: &mut minicbor::Encoder<W>,
                _context: &mut C,
            ) -> Result<(), minicbor::encode::Error<W::Error>> {
                encoder.array(1)?.u16(self.tag())?;
                Ok(())
            }
        }

        impl<'bytes> minicbor::Decode<'bytes, V2DecodeContext> for $name {
            fn decode(
                decoder: &mut minicbor::Decoder<'bytes>,
                _context: &mut V2DecodeContext,
            ) -> Result<Self, minicbor::decode::Error> {
                let position = decoder.position();
                expect_array(decoder, position, 1)?;
                match decoder.u16()? {
                    $($tag => Ok(Self::$variant)),+,
                    _ => Err(malformed(position)),
                }
            }
        }
    };
}

closed_unit_enum_v2! {
    FixedOriginV2 {
        Jarvis8765 = 1,
        Approval8766 = 2,
        Ingress8767 = 3,
        Agent8768 = 4,
    }
}

closed_unit_enum_v2! {
    BootstrapKindV2 {
        Ingress = 1,
        Approval = 2,
        Agent = 3,
    }
}

impl BootstrapKindV2 {
    const fn path_component(self) -> &'static str {
        match self {
            Self::Ingress => "ingress",
            Self::Approval => "approval",
            Self::Agent => "agent",
        }
    }
}

closed_unit_enum_v2! {
    PublicServiceStateV2 {
        Starting = 1,
        Ready = 2,
        DegradedFailClosed = 3,
        Fenced = 4,
    }
}

closed_unit_enum_v2! {
    PublicFailureClassV2 {
        Policy = 1,
        Input = 2,
        Approval = 3,
        Connector = 4,
        Infrastructure = 5,
        ResultGate = 6,
        Audit = 7,
        ReleaseEvidence = 8,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct JarvisBootstrapUrlV2 {
    origin: FixedOriginV2,
    kind: BootstrapKindV2,
    selector: JarvisBootstrapSelectorV2,
}

impl JarvisBootstrapUrlV2 {
    pub const fn from_agentd_selector(
        kind: BootstrapKindV2,
        selector: JarvisBootstrapSelectorV2,
    ) -> Self {
        Self {
            origin: FixedOriginV2::Jarvis8765,
            kind,
            selector,
        }
    }

    pub const fn origin(&self) -> FixedOriginV2 {
        self.origin
    }

    pub const fn kind(&self) -> BootstrapKindV2 {
        self.kind
    }

    pub const fn selector(&self) -> JarvisBootstrapSelectorV2 {
        self.selector
    }
}

impl fmt::Display for JarvisBootstrapUrlV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "http://localhost:8765/v2/bootstrap/{}/{}",
            self.kind.path_component(),
            URL_SAFE_NO_PAD.encode(self.selector.as_bytes())
        )
    }
}

impl<C> minicbor::Encode<C> for JarvisBootstrapUrlV2 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        if self.origin != FixedOriginV2::Jarvis8765 {
            return Err(encode_error());
        }
        encoder.array(3)?;
        self.origin.encode(encoder, context)?;
        self.kind.encode(encoder, context)?;
        self.selector.encode(encoder, context)?;
        Ok(())
    }
}

impl<'bytes> minicbor::Decode<'bytes, V2DecodeContext> for JarvisBootstrapUrlV2 {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        context: &mut V2DecodeContext,
    ) -> Result<Self, minicbor::decode::Error> {
        let position = decoder.position();
        expect_array(decoder, position, 3)?;
        let origin = FixedOriginV2::decode(decoder, context)?;
        let kind = BootstrapKindV2::decode(decoder, context)?;
        let selector = JarvisBootstrapSelectorV2::decode(decoder, context)?;
        if origin != FixedOriginV2::Jarvis8765 {
            return Err(malformed(position));
        }
        Ok(Self {
            origin,
            kind,
            selector,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JarvisBootstrapActionV2 {
    None,
    OpenIngress { url: JarvisBootstrapUrlV2 },
    OpenApproval { url: JarvisBootstrapUrlV2 },
    OpenAgent { url: JarvisBootstrapUrlV2 },
}

impl JarvisBootstrapActionV2 {
    pub const fn tag(self) -> u16 {
        match self {
            Self::None => 0,
            Self::OpenIngress { .. } => 1,
            Self::OpenApproval { .. } => 2,
            Self::OpenAgent { .. } => 3,
        }
    }

    fn validate(self) -> Result<(), ProtocolError> {
        let valid = match self {
            Self::None => true,
            Self::OpenIngress { url } => url.kind == BootstrapKindV2::Ingress,
            Self::OpenApproval { url } => url.kind == BootstrapKindV2::Approval,
            Self::OpenAgent { url } => url.kind == BootstrapKindV2::Agent,
        };
        if valid {
            Ok(())
        } else {
            Err(ProtocolError::stable(StableCode::ProtocolMalformedCbor))
        }
    }
}

impl<C> minicbor::Encode<C> for JarvisBootstrapActionV2 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        self.validate().map_err(|_| encode_error())?;
        match self {
            Self::None => {
                encoder.array(1)?.u16(0)?;
            }
            Self::OpenIngress { url } => {
                encoder.array(2)?.u16(1)?;
                url.encode(encoder, context)?;
            }
            Self::OpenApproval { url } => {
                encoder.array(2)?.u16(2)?;
                url.encode(encoder, context)?;
            }
            Self::OpenAgent { url } => {
                encoder.array(2)?.u16(3)?;
                url.encode(encoder, context)?;
            }
        }
        Ok(())
    }
}

impl<'bytes> minicbor::Decode<'bytes, V2DecodeContext> for JarvisBootstrapActionV2 {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        context: &mut V2DecodeContext,
    ) -> Result<Self, minicbor::decode::Error> {
        let position = decoder.position();
        let len = decoder.array()?;
        let tag = decoder.u16()?;
        let value = match (tag, len) {
            (0, Some(1)) => Self::None,
            (1, Some(2)) => Self::OpenIngress {
                url: JarvisBootstrapUrlV2::decode(decoder, context)?,
            },
            (2, Some(2)) => Self::OpenApproval {
                url: JarvisBootstrapUrlV2::decode(decoder, context)?,
            },
            (3, Some(2)) => Self::OpenAgent {
                url: JarvisBootstrapUrlV2::decode(decoder, context)?,
            },
            _ => return Err(malformed(position)),
        };
        value.validate().map_err(|_| malformed(position))?;
        Ok(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PublicTaskStatusV2 {
    AwaitingUiAuthentication {
        bootstrap: Option<JarvisBootstrapActionV2>,
    },
    AwaitingInput,
    Processing,
    AwaitingIngressApproval,
    Ready {
        bootstrap: Option<JarvisBootstrapActionV2>,
    },
    Running,
    Dispatching,
    Succeeded,
    EffectSucceededOutputQuarantined {
        class: PublicFailureClassV2,
    },
    PolicyDenied {
        class: PublicFailureClassV2,
    },
    FailedNoEffect {
        class: PublicFailureClassV2,
    },
    Indeterminate,
    Cancelled,
    Expired,
}

impl PublicTaskStatusV2 {
    pub const fn tag(self) -> u16 {
        match self {
            Self::AwaitingUiAuthentication { .. } => 1,
            Self::AwaitingInput => 2,
            Self::Processing => 3,
            Self::AwaitingIngressApproval => 4,
            Self::Ready { .. } => 5,
            Self::Running => 6,
            Self::Dispatching => 7,
            Self::Succeeded => 8,
            Self::EffectSucceededOutputQuarantined { .. } => 9,
            Self::PolicyDenied { .. } => 10,
            Self::FailedNoEffect { .. } => 11,
            Self::Indeterminate => 12,
            Self::Cancelled => 13,
            Self::Expired => 14,
        }
    }

    pub(crate) fn validate(self) -> Result<(), ProtocolError> {
        let valid = match self {
            Self::AwaitingUiAuthentication { bootstrap } | Self::Ready { bootstrap } => {
                !matches!(bootstrap, Some(JarvisBootstrapActionV2::None))
            }
            Self::EffectSucceededOutputQuarantined { class } => matches!(
                class,
                PublicFailureClassV2::ResultGate
                    | PublicFailureClassV2::Audit
                    | PublicFailureClassV2::ReleaseEvidence
            ),
            Self::PolicyDenied { class } => class == PublicFailureClassV2::Policy,
            Self::FailedNoEffect { class } => matches!(
                class,
                PublicFailureClassV2::Input
                    | PublicFailureClassV2::Approval
                    | PublicFailureClassV2::Connector
                    | PublicFailureClassV2::Infrastructure
            ),
            _ => true,
        };
        if valid {
            Ok(())
        } else {
            Err(ProtocolError::stable(StableCode::ProtocolMalformedCbor))
        }
    }
}

impl<C> minicbor::Encode<C> for PublicTaskStatusV2 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        self.validate().map_err(|_| encode_error())?;
        match self {
            Self::AwaitingUiAuthentication { bootstrap } => {
                encoder.array(2)?.u16(1)?;
                encode_optional_action(bootstrap, encoder, context)?;
            }
            Self::Ready { bootstrap } => {
                encoder.array(2)?.u16(5)?;
                encode_optional_action(bootstrap, encoder, context)?;
            }
            Self::EffectSucceededOutputQuarantined { class } => {
                encoder.array(2)?.u16(9)?;
                class.encode(encoder, context)?;
            }
            Self::PolicyDenied { class } => {
                encoder.array(2)?.u16(10)?;
                class.encode(encoder, context)?;
            }
            Self::FailedNoEffect { class } => {
                encoder.array(2)?.u16(11)?;
                class.encode(encoder, context)?;
            }
            unit => {
                encoder.array(1)?.u16(unit.tag())?;
            }
        }
        Ok(())
    }
}

impl<'bytes> minicbor::Decode<'bytes, V2DecodeContext> for PublicTaskStatusV2 {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        context: &mut V2DecodeContext,
    ) -> Result<Self, minicbor::decode::Error> {
        let position = decoder.position();
        let len = decoder.array()?;
        let tag = decoder.u16()?;
        let value = match (tag, len) {
            (1, Some(2)) => Self::AwaitingUiAuthentication {
                bootstrap: decode_optional_action(decoder, context)?,
            },
            (2, Some(1)) => Self::AwaitingInput,
            (3, Some(1)) => Self::Processing,
            (4, Some(1)) => Self::AwaitingIngressApproval,
            (5, Some(2)) => Self::Ready {
                bootstrap: decode_optional_action(decoder, context)?,
            },
            (6, Some(1)) => Self::Running,
            (7, Some(1)) => Self::Dispatching,
            (8, Some(1)) => Self::Succeeded,
            (9, Some(2)) => Self::EffectSucceededOutputQuarantined {
                class: PublicFailureClassV2::decode(decoder, context)?,
            },
            (10, Some(2)) => Self::PolicyDenied {
                class: PublicFailureClassV2::decode(decoder, context)?,
            },
            (11, Some(2)) => Self::FailedNoEffect {
                class: PublicFailureClassV2::decode(decoder, context)?,
            },
            (12, Some(1)) => Self::Indeterminate,
            (13, Some(1)) => Self::Cancelled,
            (14, Some(1)) => Self::Expired,
            _ => return Err(malformed(position)),
        };
        value.validate().map_err(|_| malformed(position))?;
        Ok(value)
    }
}

fn encode_optional_action<C, W: minicbor::encode::Write>(
    value: &Option<JarvisBootstrapActionV2>,
    encoder: &mut minicbor::Encoder<W>,
    context: &mut C,
) -> Result<(), minicbor::encode::Error<W::Error>> {
    match value {
        Some(value) => value.encode(encoder, context),
        None => {
            encoder.null()?;
            Ok(())
        }
    }
}

fn decode_optional_action(
    decoder: &mut minicbor::Decoder<'_>,
    context: &mut V2DecodeContext,
) -> Result<Option<JarvisBootstrapActionV2>, minicbor::decode::Error> {
    if decoder.datatype()? == minicbor::data::Type::Null {
        decoder.null()?;
        Ok(None)
    } else {
        Ok(Some(JarvisBootstrapActionV2::decode(decoder, context)?))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AgentControlHealthResponseV2 {
    state: PublicServiceStateV2,
}

impl AgentControlHealthResponseV2 {
    pub const fn new(state: PublicServiceStateV2) -> Self {
        Self { state }
    }

    pub const fn state(self) -> PublicServiceStateV2 {
        self.state
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PrepareIngressRequestV2 {
    client_request_nonce: Nonce32V2,
}

impl PrepareIngressRequestV2 {
    pub const fn new(client_request_nonce: Nonce32V2) -> Self {
        Self {
            client_request_nonce,
        }
    }

    pub const fn client_request_nonce(&self) -> &Nonce32V2 {
        &self.client_request_nonce
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PrepareIngressResponseV2 {
    task: TaskHandleV2,
    bootstrap: JarvisBootstrapActionV2,
}

impl PrepareIngressResponseV2 {
    pub const fn new(task: TaskHandleV2, bootstrap: JarvisBootstrapActionV2) -> Self {
        Self { task, bootstrap }
    }

    pub const fn task(self) -> TaskHandleV2 {
        self.task
    }

    pub const fn bootstrap(self) -> JarvisBootstrapActionV2 {
        self.bootstrap
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GetTaskStatusRequestV2 {
    task: TaskHandleV2,
}

impl GetTaskStatusRequestV2 {
    pub const fn new(task: TaskHandleV2) -> Self {
        Self { task }
    }

    pub const fn task(self) -> TaskHandleV2 {
        self.task
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GetTaskStatusResponseV2 {
    status: PublicTaskStatusV2,
}

impl GetTaskStatusResponseV2 {
    pub const fn new(status: PublicTaskStatusV2) -> Self {
        Self { status }
    }

    pub const fn status(self) -> PublicTaskStatusV2 {
        self.status
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CancelTaskRequestV2 {
    task: TaskHandleV2,
}

impl CancelTaskRequestV2 {
    pub const fn new(task: TaskHandleV2) -> Self {
        Self { task }
    }

    pub const fn task(self) -> TaskHandleV2 {
        self.task
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CancelTaskResponseV2 {
    status: PublicTaskStatusV2,
}

impl CancelTaskResponseV2 {
    pub const fn new(status: PublicTaskStatusV2) -> Self {
        Self { status }
    }

    pub const fn status(self) -> PublicTaskStatusV2 {
        self.status
    }
}

macro_rules! array_struct_one_v2 {
    ($name:ident, $field:ident: $field_ty:ty) => {
        impl<C> minicbor::Encode<C> for $name {
            fn encode<W: minicbor::encode::Write>(
                &self,
                encoder: &mut minicbor::Encoder<W>,
                context: &mut C,
            ) -> Result<(), minicbor::encode::Error<W::Error>> {
                encoder.array(1)?;
                self.$field.encode(encoder, context)?;
                Ok(())
            }
        }

        impl<'bytes> minicbor::Decode<'bytes, V2DecodeContext> for $name {
            fn decode(
                decoder: &mut minicbor::Decoder<'bytes>,
                context: &mut V2DecodeContext,
            ) -> Result<Self, minicbor::decode::Error> {
                let position = decoder.position();
                expect_array(decoder, position, 1)?;
                Ok(Self {
                    $field: <$field_ty>::decode(decoder, context)?,
                })
            }
        }
    };
}

array_struct_one_v2!(AgentControlHealthResponseV2, state: PublicServiceStateV2);
array_struct_one_v2!(PrepareIngressRequestV2, client_request_nonce: Nonce32V2);
array_struct_one_v2!(GetTaskStatusRequestV2, task: TaskHandleV2);
array_struct_one_v2!(GetTaskStatusResponseV2, status: PublicTaskStatusV2);
array_struct_one_v2!(CancelTaskRequestV2, task: TaskHandleV2);
array_struct_one_v2!(CancelTaskResponseV2, status: PublicTaskStatusV2);

impl<C> minicbor::Encode<C> for PrepareIngressResponseV2 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        self.bootstrap.validate().map_err(|_| encode_error())?;
        encoder.array(2)?;
        self.task.encode(encoder, context)?;
        self.bootstrap.encode(encoder, context)?;
        Ok(())
    }
}

impl<'bytes> minicbor::Decode<'bytes, V2DecodeContext> for PrepareIngressResponseV2 {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        context: &mut V2DecodeContext,
    ) -> Result<Self, minicbor::decode::Error> {
        let position = decoder.position();
        expect_array(decoder, position, 2)?;
        let value = Self {
            task: TaskHandleV2::decode(decoder, context)?,
            bootstrap: JarvisBootstrapActionV2::decode(decoder, context)?,
        };
        value
            .bootstrap
            .validate()
            .map_err(|_| malformed(position))?;
        Ok(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AgentControlOperationV2 {
    Health,
    PrepareIngress(PrepareIngressRequestV2),
    GetTaskStatus(GetTaskStatusRequestV2),
    CancelTask(CancelTaskRequestV2),
}

impl AgentControlOperationV2 {
    pub const fn tag(self) -> u16 {
        match self {
            Self::Health => 0,
            Self::PrepareIngress(_) => 10,
            Self::GetTaskStatus(_) => 11,
            Self::CancelTask(_) => 12,
        }
    }

    pub(crate) fn validate(self) -> Result<(), ProtocolError> {
        Ok(())
    }
}

impl<C> minicbor::Encode<C> for AgentControlOperationV2 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        encoder.array(2)?.u16(self.tag())?;
        match self {
            Self::Health => {
                encoder.array(0)?;
            }
            Self::PrepareIngress(body) => body.encode(encoder, context)?,
            Self::GetTaskStatus(body) => body.encode(encoder, context)?,
            Self::CancelTask(body) => body.encode(encoder, context)?,
        }
        Ok(())
    }
}

impl<'bytes> minicbor::Decode<'bytes, V2DecodeContext> for AgentControlOperationV2 {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        context: &mut V2DecodeContext,
    ) -> Result<Self, minicbor::decode::Error> {
        let position = decoder.position();
        expect_array(decoder, position, 2)?;
        match decoder.u16()? {
            0 => {
                expect_array(decoder, position, 0)?;
                Ok(Self::Health)
            }
            10 => Ok(Self::PrepareIngress(PrepareIngressRequestV2::decode(
                decoder, context,
            )?)),
            11 => Ok(Self::GetTaskStatus(GetTaskStatusRequestV2::decode(
                decoder, context,
            )?)),
            12 => Ok(Self::CancelTask(CancelTaskRequestV2::decode(
                decoder, context,
            )?)),
            _ => Err(minicbor::decode::Error::message(
                StableCode::ProtocolUnknownOperation.as_str(),
            )
            .at(position)),
        }
    }
}
