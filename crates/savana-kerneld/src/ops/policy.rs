use savana_kernel_protocol::{OperationV1, ResponseBodyV1, ResponsePayloadV1, StableCode};
use savana_policy_core::{AuthenticatedCallContext, PolicyEngine};

pub(crate) fn dispatch(
    engine: &PolicyEngine,
    context: &AuthenticatedCallContext,
    operation: OperationV1,
) -> ResponseBodyV1 {
    match operation {
        OperationV1::BeginRun(request) => engine
            .begin_run(context, request)
            .map(ResponsePayloadV1::BeginRun)
            .map(ResponseBodyV1::Ok)
            .unwrap_or_else(|error| ResponseBodyV1::Err(error.code())),
        OperationV1::IngestUserInput(request) => engine
            .ingest_user_input(context, request)
            .map(ResponsePayloadV1::IngestUserInput)
            .map(ResponseBodyV1::Ok)
            .unwrap_or_else(|error| ResponseBodyV1::Err(error.code())),
        OperationV1::Health
        | OperationV1::PreparePlannerCall(_)
        | OperationV1::CommitPlannerValue(_)
        | OperationV1::DeriveValue(_)
        | OperationV1::ProposeToolCall(_)
        | OperationV1::EvaluateToolCall(_)
        | OperationV1::AuthorizeToolCall(_)
        | OperationV1::MaterializeExecution(_)
        | OperationV1::CommitToolResult(_) => ResponseBodyV1::Err(StableCode::KernelUnavailable),
    }
}
