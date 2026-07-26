#![forbid(unsafe_code)]

mod approval;
mod attestation;
mod cbor;
mod error;
mod frame;
mod handles;
mod limits;
mod messages;
mod ontology;
mod operations;
mod policy;
mod primitives;
mod registry;
mod value;

pub use approval::{
    approval_display_digest, ApprovalAuthMethod, ApprovalChallengeV1, ApprovalDecision,
    ApprovalPurposeV1, ApprovalReceiptV1, ApprovalSubjectV1, MaskedDisplayBundleV1,
    SignedApprovalEnvelopeV1, UnsignedApprovalEnvelopeV1, UnsignedApprovalReceiptV1,
};
pub use attestation::{SignedValidatorAttestationV1, ValidatorVerdictV1};
pub use cbor::{
    decode_client_message, decode_server_message, encode_client_message, encode_server_message,
};
pub use error::{ProtocolError, StableCode};
pub use frame::{read_frame, write_frame};
pub use handles::{
    ExecutionTicketHandle, PendingToolCallHandle, PlannerTicketHandle, RunHandle, ToolHandle,
    ValueHandle,
};
pub use limits::{EffectiveLimits, HardLimits};
pub use messages::{
    connection_binding_digest, ClientFinishV1, ClientHelloV1, ClientMessageV1, HandshakeAcceptedV1,
    HandshakeTranscriptV1, HealthSnapshotV1, RequestEnvelopeV1, ResponseBodyV1, ResponseEnvelopeV1,
    ResponsePayloadV1, ServerIdentityV1, ServerMessageV1, SignedServerHelloV1,
};
pub use ontology::{
    OntologyEffectV1, OntologyEntryV1, OntologyEventV1, OntologySnapshotV1, SignedOntologyEventV1,
    SignedOntologySnapshotV1,
};
pub use operations::{
    AuthorizeToolCallRequest, BeginRunRequest, BeginRunResponse, CommitPlannerValueRequest,
    CommitToolResultRequest, DeriveValueRequest, EvaluateToolCallRequest,
    EvaluateToolCallResponseV1, ExecutionEnvelope, IngestUserInputRequest,
    MaterializeExecutionRequest, NamedArgumentHandle, OperationV1, PreparePlannerCallRequest,
    ProposeToolCallRequest,
};
pub use policy::{
    ingress_request_digest, ActiveToolView, DecisionTrace, IngressEnvelopeV1,
    IngressRequestCommitmentV1, PlannerCommitProofV1, SignedIngressEnvelopeV1,
    SignedPlannerAttestationV1, ToolExecutionIdentity,
};
pub use primitives::{
    AttemptKindV1, BootId, ClientId, ConstraintId, Digest32, KeyId, Nonce32, ProtocolVersion,
    RequestId, RequestedMode, ResourceLimitsV1, Signature64, ToolName, UnixMillis, ValidatorId,
};
pub use registry::{RegistrySnapshotV1, SignedRegistrySnapshotV1, ToolDescriptorV1};
pub use value::{
    ArgumentName, ArtifactId, BoundedArgumentNames, BoundedBytes, BoundedList, BoundedObject,
    BoundedText, ConversationId, DeriveOperation, KernelValue, PlannerId, PrincipalId, RoleId,
    RunId, TaskId,
};

pub const PROTOCOL_MAJOR: u16 = 1;
pub const PROTOCOL_MINOR: u16 = 0;
