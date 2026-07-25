#![forbid(unsafe_code)]

mod cbor;
mod error;
mod frame;
mod limits;
mod messages;
mod primitives;

pub use cbor::{
    decode_client_message, decode_server_message, encode_client_message, encode_server_message,
};
pub use error::{ProtocolError, StableCode};
pub use frame::{read_frame, write_frame};
pub use limits::{EffectiveLimits, HardLimits};
pub use messages::{
    ClientFinishV1, ClientHelloV1, ClientMessageV1, HandshakeAcceptedV1, HandshakeTranscriptV1,
    HealthSnapshotV1, OperationV1, RequestEnvelopeV1, ResponseBodyV1, ResponseEnvelopeV1,
    ResponsePayloadV1, ServerIdentityV1, ServerMessageV1, SignedServerHelloV1,
};
pub use primitives::{
    AttemptKindV1, BootId, ClientId, ConstraintId, Digest32, KeyId, Nonce32, ProtocolVersion,
    RequestId, RequestedMode, ResourceLimitsV1, Signature64, ToolName, UnixMillis, ValidatorId,
};

pub const PROTOCOL_MAJOR: u16 = 1;
pub const PROTOCOL_MINOR: u16 = 0;
