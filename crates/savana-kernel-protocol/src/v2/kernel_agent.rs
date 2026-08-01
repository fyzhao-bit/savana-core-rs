use crate::{ProtocolError, StableCode};
use ed25519_dalek::{Signature as Ed25519Signature, Signer as _, SigningKey, VerifyingKey};
use sha2::{Digest as _, Sha256};

use super::{
    cbor::{scan_single, V2DecodeContext},
    ActionIntentHandleV2, ActionTemplateIdV2, AgentSessionHandleV2,
    AgentUiAuthenticationPreparationHandleV2, AgentUiAuthorizationHandleV2, ApprovalPurposeV2,
    ArgumentNameV2, BootIdV2, Digest32V2, DisplayProjectionIdV2, DurableTaskIdV2, Ed25519KeyIdV2,
    Ed25519SignatureV2, ExecutionHandleV2, ExecutionTicketHandleV2, ExecutorIdentityV2,
    KernelAgentViewCursorV2, MaskedDocumentHandleV2, NewTaskPreparationHandleV2, Nonce32V2,
    PendingReleaseHandleV2, PendingToolCallHandleV2, PlanStepHandleV2, PlannerIntentKindV2,
    PlannerLimitsV2, PlannerPurposeV2, PlannerRouteIdV2, PlannerSlotRefV2, PlannerTicketHandleV2,
    PolicyConstantIdV2, ProjectionIdV2, ReleaseHandleV2, ReleaseKernelApprovalHandleV2,
    ReleaseTicketHandleV2, RunHandleV2, ServiceIdentityV2,
    SignedAgentAuthenticationAttemptClosureProofV2, SignedApprovalSettlementV2,
    SignedUiAuthenticationSettlementV2, StaticTemplateIdV2, ToolClassIdV2, ToolHandleV2,
    ToolKernelApprovalHandleV2, UiAuthenticationPurposeV2, UnixMillisV2, ValueHandleV2,
};

const MAX_AGENT_VIEW_RESPONSE_BYTES_V2: u32 = 8 * 1024 * 1024;
const MAX_PROMPT_VALUES_V2: usize = 256;
const MAX_DURABLE_TASK_CORRELATION_PAYLOAD_BYTES_V2: usize = 4 * 1024;
const DURABLE_TASK_CORRELATION_SIGNATURE_DOMAIN_V2: &[u8] = b"SAVANA_DURABLE_TASK_CORRELATION_V2\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KernelAgentHealthRequestV2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnsignedDurableTaskCorrelationV2 {
    installation_id: Digest32V2,
    active_state_manifest_digest: Digest32V2,
    deployment_generation: u64,
    durable_task_id: DurableTaskIdV2,
    agentd_identity: ServiceIdentityV2,
    agentd_kernel_client_boot_id: BootIdV2,
    kerneld_server_boot_id: BootIdV2,
    machine_boot_id: BootIdV2,
    issued_at: UnixMillisV2,
    task_logical_expires_at: UnixMillisV2,
    status_retain_until: UnixMillisV2,
}

impl UnsignedDurableTaskCorrelationV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        installation_id: Digest32V2,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
        durable_task_id: DurableTaskIdV2,
        agentd_identity: ServiceIdentityV2,
        agentd_kernel_client_boot_id: BootIdV2,
        kerneld_server_boot_id: BootIdV2,
        machine_boot_id: BootIdV2,
        issued_at: UnixMillisV2,
        task_logical_expires_at: UnixMillisV2,
        status_retain_until: UnixMillisV2,
    ) -> Result<Self, ProtocolError> {
        if is_zero(installation_id.as_bytes())
            || is_zero(active_state_manifest_digest.as_bytes())
            || deployment_generation == 0
            || is_zero(durable_task_id.as_bytes())
            || is_zero(agentd_identity.as_bytes())
            || is_zero(agentd_kernel_client_boot_id.as_bytes())
            || is_zero(kerneld_server_boot_id.as_bytes())
            || is_zero(machine_boot_id.as_bytes())
            || issued_at.get() >= task_logical_expires_at.get()
            || task_logical_expires_at.get() > status_retain_until.get()
        {
            return Err(malformed());
        }
        Ok(Self {
            installation_id,
            active_state_manifest_digest,
            deployment_generation,
            durable_task_id,
            agentd_identity,
            agentd_kernel_client_boot_id,
            kerneld_server_boot_id,
            machine_boot_id,
            issued_at,
            task_logical_expires_at,
            status_retain_until,
        })
    }

    pub const fn installation_id(self) -> Digest32V2 {
        self.installation_id
    }

    pub const fn active_state_manifest_digest(self) -> Digest32V2 {
        self.active_state_manifest_digest
    }

    pub const fn deployment_generation(self) -> u64 {
        self.deployment_generation
    }

    pub const fn durable_task_id(self) -> DurableTaskIdV2 {
        self.durable_task_id
    }

    pub const fn agentd_identity(self) -> ServiceIdentityV2 {
        self.agentd_identity
    }

    pub const fn agentd_kernel_client_boot_id(self) -> BootIdV2 {
        self.agentd_kernel_client_boot_id
    }

    pub const fn kerneld_server_boot_id(self) -> BootIdV2 {
        self.kerneld_server_boot_id
    }

    pub const fn machine_boot_id(self) -> BootIdV2 {
        self.machine_boot_id
    }

    pub const fn issued_at(self) -> UnixMillisV2 {
        self.issued_at
    }

    pub const fn task_logical_expires_at(self) -> UnixMillisV2 {
        self.task_logical_expires_at
    }

    pub const fn status_retain_until(self) -> UnixMillisV2 {
        self.status_retain_until
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedDurableTaskCorrelationV2 {
    unsigned: UnsignedDurableTaskCorrelationV2,
    key_id: Ed25519KeyIdV2,
    signature: Ed25519SignatureV2,
}

impl SignedDurableTaskCorrelationV2 {
    pub fn sign(
        unsigned: UnsignedDurableTaskCorrelationV2,
        signing_key: &SigningKey,
    ) -> Result<Self, ProtocolError> {
        let payload = encode_unsigned_durable_task_correlation_v2(&unsigned)?;
        let signature_input = correlation_signature_input(&payload);
        let public_key = signing_key.verifying_key().to_bytes();
        Self::from_parts(
            unsigned,
            super::derive_ed25519_key_id_v2(public_key),
            Ed25519SignatureV2::new(signing_key.sign(&signature_input).to_bytes()),
        )
    }

    pub fn from_parts(
        unsigned: UnsignedDurableTaskCorrelationV2,
        key_id: Ed25519KeyIdV2,
        signature: Ed25519SignatureV2,
    ) -> Result<Self, ProtocolError> {
        if is_zero(key_id.as_bytes()) || is_zero(signature.as_bytes()) {
            return Err(malformed());
        }
        Ok(Self {
            unsigned,
            key_id,
            signature,
        })
    }

    pub const fn unsigned(&self) -> UnsignedDurableTaskCorrelationV2 {
        self.unsigned
    }

    pub const fn key_id(&self) -> Ed25519KeyIdV2 {
        self.key_id
    }

    pub const fn signature(&self) -> Ed25519SignatureV2 {
        self.signature
    }

    pub fn payload_bytes(&self) -> Result<Vec<u8>, ProtocolError> {
        encode_unsigned_durable_task_correlation_v2(&self.unsigned)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        &self,
        expected_key_id: Ed25519KeyIdV2,
        expected_public_key: [u8; 32],
        expected_installation_id: Digest32V2,
        expected_active_state_manifest_digest: Digest32V2,
        expected_agentd_identity: ServiceIdentityV2,
        now: UnixMillisV2,
    ) -> Result<UnsignedDurableTaskCorrelationV2, ProtocolError> {
        if self.key_id != expected_key_id
            || super::derive_ed25519_key_id_v2(expected_public_key) != expected_key_id
            || self.unsigned.installation_id != expected_installation_id
            || self.unsigned.active_state_manifest_digest != expected_active_state_manifest_digest
            || self.unsigned.agentd_identity != expected_agentd_identity
            || now.get() < self.unsigned.issued_at.get()
            || now.get() >= self.unsigned.status_retain_until.get()
        {
            return Err(malformed());
        }
        let payload = self.payload_bytes()?;
        let verifying_key =
            VerifyingKey::from_bytes(&expected_public_key).map_err(ProtocolError::malformed)?;
        verifying_key
            .verify_strict(
                &correlation_signature_input(&payload),
                &Ed25519Signature::from_bytes(self.signature.as_bytes()),
            )
            .map_err(ProtocolError::malformed)?;
        Ok(self.unsigned)
    }

    pub fn correlation_digest(&self) -> Result<Digest32V2, ProtocolError> {
        let canonical = minicbor::to_vec(self).map_err(ProtocolError::malformed)?;
        Ok(Digest32V2::new(Sha256::digest(canonical).into()))
    }
}

fn correlation_signature_input(payload: &[u8]) -> Vec<u8> {
    let mut input = Vec::with_capacity(DURABLE_TASK_CORRELATION_SIGNATURE_DOMAIN_V2.len() + 32);
    input.extend_from_slice(DURABLE_TASK_CORRELATION_SIGNATURE_DOMAIN_V2);
    input.extend_from_slice(&Sha256::digest(payload));
    input
}

impl<C> minicbor::Encode<C> for SignedDurableTaskCorrelationV2 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        _context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        let payload = self
            .payload_bytes()
            .map_err(|_| minicbor::encode::Error::message("invalid durable task correlation"))?;
        encoder.array(3)?.bytes(&payload)?;
        minicbor::Encode::encode(&self.key_id, encoder, &mut ())?;
        minicbor::Encode::encode(&self.signature, encoder, &mut ())?;
        Ok(())
    }
}

impl<'bytes> minicbor::Decode<'bytes, V2DecodeContext> for SignedDurableTaskCorrelationV2 {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        context: &mut V2DecodeContext,
    ) -> Result<Self, minicbor::decode::Error> {
        let position = decoder.position();
        if decoder.array()? != Some(3) {
            return Err(minicbor::decode::Error::message(
                StableCode::ProtocolMalformedCbor.as_str(),
            )
            .at(position));
        }
        let payload = decoder.bytes()?;
        if payload.len() > MAX_DURABLE_TASK_CORRELATION_PAYLOAD_BYTES_V2 {
            return Err(minicbor::decode::Error::message(
                StableCode::ProtocolMalformedCbor.as_str(),
            )
            .at(position));
        }
        let unsigned = decode_unsigned_durable_task_correlation_v2(payload).map_err(|_| {
            minicbor::decode::Error::message(StableCode::ProtocolMalformedCbor.as_str())
                .at(position)
        })?;
        let key_id = minicbor::Decode::decode(decoder, context)?;
        let signature = minicbor::Decode::decode(decoder, context)?;
        Self::from_parts(unsigned, key_id, signature).map_err(|_| {
            minicbor::decode::Error::message(StableCode::ProtocolMalformedCbor.as_str())
                .at(position)
        })
    }
}

pub fn encode_signed_durable_task_correlation_v2(
    value: &SignedDurableTaskCorrelationV2,
) -> Result<Vec<u8>, ProtocolError> {
    minicbor::to_vec(value).map_err(ProtocolError::malformed)
}

pub fn decode_signed_durable_task_correlation_v2(
    bytes: &[u8],
) -> Result<SignedDurableTaskCorrelationV2, ProtocolError> {
    scan_single(bytes)?;
    let mut decoder = minicbor::Decoder::new(bytes);
    let mut context = V2DecodeContext;
    let value = <SignedDurableTaskCorrelationV2 as minicbor::Decode<V2DecodeContext>>::decode(
        &mut decoder,
        &mut context,
    )
    .map_err(ProtocolError::from_typed_decode)?;
    if decoder.position() != bytes.len() {
        return Err(ProtocolError::stable(StableCode::ProtocolMalformedCbor));
    }
    if encode_signed_durable_task_correlation_v2(&value)? != bytes {
        return Err(ProtocolError::stable(StableCode::ProtocolNonCanonicalCbor));
    }
    Ok(value)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetKernelTaskStatusRequestV2 {
    correlation: SignedDurableTaskCorrelationV2,
}

impl GetKernelTaskStatusRequestV2 {
    pub const fn new(correlation: SignedDurableTaskCorrelationV2) -> Self {
        Self { correlation }
    }

    pub const fn correlation(&self) -> &SignedDurableTaskCorrelationV2 {
        &self.correlation
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CancelKernelTaskRequestV2 {
    preparation: NewTaskPreparationHandleV2,
    correlation: SignedDurableTaskCorrelationV2,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResumeCommittedAgentAuthenticationRequestV2 {
    correlation: SignedDurableTaskCorrelationV2,
    client_request_nonce: Nonce32V2,
    prior_attempt_closure_proof: Option<SignedAgentAuthenticationAttemptClosureProofV2>,
}

impl ResumeCommittedAgentAuthenticationRequestV2 {
    pub fn new(
        correlation: SignedDurableTaskCorrelationV2,
        client_request_nonce: Nonce32V2,
        prior_attempt_closure_proof: Option<SignedAgentAuthenticationAttemptClosureProofV2>,
    ) -> Result<Self, ProtocolError> {
        if is_zero(client_request_nonce.as_bytes()) {
            return Err(malformed());
        }
        Ok(Self {
            correlation,
            client_request_nonce,
            prior_attempt_closure_proof,
        })
    }

    pub const fn correlation(&self) -> &SignedDurableTaskCorrelationV2 {
        &self.correlation
    }

    pub const fn client_request_nonce(&self) -> Nonce32V2 {
        self.client_request_nonce
    }

    pub const fn prior_attempt_closure_proof(
        &self,
    ) -> Option<&SignedAgentAuthenticationAttemptClosureProofV2> {
        self.prior_attempt_closure_proof.as_ref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannerStepV2 {
    ordinal: u16,
    action_template: ActionTemplateIdV2,
    tool_class: ToolClassIdV2,
    slot_bindings: Vec<(ArgumentNameV2, PlannerSlotRefV2)>,
    dependencies: Vec<u16>,
}

impl PlannerStepV2 {
    pub fn new(
        ordinal: u16,
        action_template: ActionTemplateIdV2,
        tool_class: ToolClassIdV2,
        slot_bindings: Vec<(ArgumentNameV2, PlannerSlotRefV2)>,
        dependencies: Vec<u16>,
    ) -> Result<Self, ProtocolError> {
        if ordinal == 0
            || action_template.get() == 0
            || tool_class.get() == 0
            || slot_bindings.len() > MAX_PROMPT_VALUES_V2
            || dependencies.len() > MAX_PROMPT_VALUES_V2
            || slot_bindings
                .iter()
                .any(|(_, reference)| is_zero(reference.as_bytes()))
            || slot_bindings.windows(2).any(|pair| pair[0].0 >= pair[1].0)
            || dependencies.windows(2).any(|pair| pair[0] >= pair[1])
            || dependencies
                .iter()
                .any(|dependency| *dependency == 0 || *dependency >= ordinal)
        {
            return Err(malformed());
        }
        Ok(Self {
            ordinal,
            action_template,
            tool_class,
            slot_bindings,
            dependencies,
        })
    }

    pub const fn ordinal(&self) -> u16 {
        self.ordinal
    }

    pub const fn action_template(&self) -> ActionTemplateIdV2 {
        self.action_template
    }

    pub const fn tool_class(&self) -> ToolClassIdV2 {
        self.tool_class
    }

    pub fn slot_bindings(&self) -> &[(ArgumentNameV2, PlannerSlotRefV2)] {
        &self.slot_bindings
    }

    pub fn dependencies(&self) -> &[u16] {
        &self.dependencies
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannerPlanV2 {
    envelope_nonce: Nonce32V2,
    steps: Vec<PlannerStepV2>,
}

pub fn encode_planner_plan_v2(value: &PlannerPlanV2) -> Result<Vec<u8>, ProtocolError> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encode_planner_plan(&mut encoder, value)?;
    Ok(encoder.into_writer())
}

pub fn decode_planner_plan_v2(bytes: &[u8]) -> Result<PlannerPlanV2, ProtocolError> {
    if bytes.is_empty() || bytes.len() > MAX_AGENT_VIEW_RESPONSE_BYTES_V2 as usize {
        return Err(malformed());
    }
    let mut decoder = minicbor::Decoder::new(bytes);
    let mut context = V2DecodeContext;
    let value = decode_planner_plan(&mut decoder, &mut context)?;
    if decoder.position() != bytes.len() || encode_planner_plan_v2(&value)? != bytes {
        return Err(ProtocolError::stable(StableCode::ProtocolNonCanonicalCbor));
    }
    Ok(value)
}

impl PlannerPlanV2 {
    pub fn new(
        envelope_nonce: Nonce32V2,
        steps: Vec<PlannerStepV2>,
    ) -> Result<Self, ProtocolError> {
        if is_zero(envelope_nonce.as_bytes())
            || steps.len() > MAX_PROMPT_VALUES_V2
            || steps
                .iter()
                .enumerate()
                .any(|(index, step)| usize::from(step.ordinal) != index + 1)
        {
            return Err(malformed());
        }
        Ok(Self {
            envelope_nonce,
            steps,
        })
    }

    pub const fn envelope_nonce(&self) -> Nonce32V2 {
        self.envelope_nonce
    }

    pub fn steps(&self) -> &[PlannerStepV2] {
        &self.steps
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitPlannerValueRequestV2 {
    run: RunHandleV2,
    ticket: PlannerTicketHandleV2,
    plan: PlannerPlanV2,
}

impl CommitPlannerValueRequestV2 {
    pub const fn new(run: RunHandleV2, ticket: PlannerTicketHandleV2, plan: PlannerPlanV2) -> Self {
        Self { run, ticket, plan }
    }

    pub const fn run(&self) -> RunHandleV2 {
        self.run
    }

    pub const fn ticket(&self) -> PlannerTicketHandleV2 {
        self.ticket
    }

    pub const fn plan(&self) -> &PlannerPlanV2 {
        &self.plan
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeriveOperationV2 {
    ConcatenateText,
    NormalizeNfc,
    SelectObjectField(ArgumentNameV2),
    AssembleList,
    AssembleObject(Vec<ArgumentNameV2>),
    PolicyConstant(PolicyConstantIdV2),
}

impl DeriveOperationV2 {
    pub const fn concatenate_text() -> Self {
        Self::ConcatenateText
    }

    pub const fn normalize_nfc() -> Self {
        Self::NormalizeNfc
    }

    pub const fn select_object_field(name: ArgumentNameV2) -> Self {
        Self::SelectObjectField(name)
    }

    pub const fn assemble_list() -> Self {
        Self::AssembleList
    }

    pub fn assemble_object(fields: Vec<ArgumentNameV2>) -> Result<Self, ProtocolError> {
        if fields.len() > MAX_PROMPT_VALUES_V2 || fields.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(malformed());
        }
        Ok(Self::AssembleObject(fields))
    }

    pub fn policy_constant(constant_id: PolicyConstantIdV2) -> Result<Self, ProtocolError> {
        if constant_id.get() == 0 {
            return Err(malformed());
        }
        Ok(Self::PolicyConstant(constant_id))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeriveValueRequestV2 {
    run: RunHandleV2,
    operation: DeriveOperationV2,
    inputs: Vec<ValueHandleV2>,
}

impl DeriveValueRequestV2 {
    pub fn new(
        run: RunHandleV2,
        operation: DeriveOperationV2,
        inputs: Vec<ValueHandleV2>,
    ) -> Result<Self, ProtocolError> {
        if inputs.len() > MAX_PROMPT_VALUES_V2 {
            return Err(malformed());
        }
        Ok(Self {
            run,
            operation,
            inputs,
        })
    }

    pub const fn run(&self) -> RunHandleV2 {
        self.run
    }

    pub const fn operation(&self) -> &DeriveOperationV2 {
        &self.operation
    }

    pub fn inputs(&self) -> &[ValueHandleV2] {
        &self.inputs
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamedArgumentValueBindingV2 {
    name: ArgumentNameV2,
    value: ValueHandleV2,
}

impl NamedArgumentValueBindingV2 {
    pub const fn new(name: ArgumentNameV2, value: ValueHandleV2) -> Self {
        Self { name, value }
    }

    pub const fn name(&self) -> &ArgumentNameV2 {
        &self.name
    }

    pub const fn value(&self) -> ValueHandleV2 {
        self.value
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProposeToolCallRequestV2 {
    step: PlanStepHandleV2,
    tool: ToolHandleV2,
    arguments: Vec<NamedArgumentValueBindingV2>,
}

impl ProposeToolCallRequestV2 {
    pub fn new(
        step: PlanStepHandleV2,
        tool: ToolHandleV2,
        arguments: Vec<NamedArgumentValueBindingV2>,
    ) -> Result<Self, ProtocolError> {
        if arguments.len() > MAX_PROMPT_VALUES_V2
            || arguments
                .windows(2)
                .any(|pair| pair[0].name >= pair[1].name)
        {
            return Err(malformed());
        }
        Ok(Self {
            step,
            tool,
            arguments,
        })
    }

    pub const fn step(&self) -> PlanStepHandleV2 {
        self.step
    }

    pub const fn tool(&self) -> ToolHandleV2 {
        self.tool
    }

    pub fn arguments(&self) -> &[NamedArgumentValueBindingV2] {
        &self.arguments
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EvaluateToolCallRequestV2 {
    pending: PendingToolCallHandleV2,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizeToolCallRequestV2 {
    pending: PendingToolCallHandleV2,
    approval: ToolKernelApprovalHandleV2,
    receipt: SignedApprovalSettlementV2,
}

impl AuthorizeToolCallRequestV2 {
    pub fn new(
        pending: PendingToolCallHandleV2,
        approval: ToolKernelApprovalHandleV2,
        receipt: SignedApprovalSettlementV2,
    ) -> Result<Self, ProtocolError> {
        if receipt.purpose() != ApprovalPurposeV2::ToolExecution {
            return Err(malformed());
        }
        Ok(Self {
            pending,
            approval,
            receipt,
        })
    }

    pub const fn pending(&self) -> PendingToolCallHandleV2 {
        self.pending
    }

    pub const fn approval(&self) -> ToolKernelApprovalHandleV2 {
        self.approval
    }

    pub const fn receipt(&self) -> &SignedApprovalSettlementV2 {
        &self.receipt
    }
}

impl EvaluateToolCallRequestV2 {
    pub const fn new(pending: PendingToolCallHandleV2) -> Self {
        Self { pending }
    }

    pub const fn pending(self) -> PendingToolCallHandleV2 {
        self.pending
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrepareReleaseRequestV2 {
    document: MaskedDocumentHandleV2,
    evidence: Vec<ValueHandleV2>,
    executor: ExecutorIdentityV2,
    destination_projection: ProjectionIdV2,
    display_projection: DisplayProjectionIdV2,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizeReleaseRequestV2 {
    pending: PendingReleaseHandleV2,
    approval: ReleaseKernelApprovalHandleV2,
    settlement: SignedApprovalSettlementV2,
}

impl AuthorizeReleaseRequestV2 {
    pub fn new(
        pending: PendingReleaseHandleV2,
        approval: ReleaseKernelApprovalHandleV2,
        settlement: SignedApprovalSettlementV2,
    ) -> Result<Self, ProtocolError> {
        if settlement.purpose() != ApprovalPurposeV2::FinalRelease {
            return Err(malformed());
        }
        Ok(Self {
            pending,
            approval,
            settlement,
        })
    }

    pub const fn pending(&self) -> PendingReleaseHandleV2 {
        self.pending
    }

    pub const fn approval(&self) -> ReleaseKernelApprovalHandleV2 {
        self.approval
    }

    pub const fn settlement(&self) -> &SignedApprovalSettlementV2 {
        &self.settlement
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticateAgentUiRequestV2 {
    authentication_preparation: AgentUiAuthenticationPreparationHandleV2,
    settlement: SignedUiAuthenticationSettlementV2,
}

impl AuthenticateAgentUiRequestV2 {
    pub fn new(
        authentication_preparation: AgentUiAuthenticationPreparationHandleV2,
        settlement: SignedUiAuthenticationSettlementV2,
    ) -> Result<Self, ProtocolError> {
        if settlement.purpose() != UiAuthenticationPurposeV2::AgentContent {
            return Err(malformed());
        }
        Ok(Self {
            authentication_preparation,
            settlement,
        })
    }

    pub const fn authentication_preparation(&self) -> AgentUiAuthenticationPreparationHandleV2 {
        self.authentication_preparation
    }

    pub const fn settlement(&self) -> &SignedUiAuthenticationSettlementV2 {
        &self.settlement
    }
}

impl PrepareReleaseRequestV2 {
    pub fn new(
        document: MaskedDocumentHandleV2,
        evidence: Vec<ValueHandleV2>,
        executor: ExecutorIdentityV2,
        destination_projection: ProjectionIdV2,
        display_projection: DisplayProjectionIdV2,
    ) -> Result<Self, ProtocolError> {
        if evidence.len() > MAX_PROMPT_VALUES_V2
            || is_zero(executor.as_bytes())
            || destination_projection.get() == 0
            || display_projection.get() == 0
        {
            return Err(malformed());
        }
        Ok(Self {
            document,
            evidence,
            executor,
            destination_projection,
            display_projection,
        })
    }

    pub const fn document(&self) -> MaskedDocumentHandleV2 {
        self.document
    }

    pub fn evidence(&self) -> &[ValueHandleV2] {
        &self.evidence
    }

    pub const fn executor(&self) -> ExecutorIdentityV2 {
        self.executor
    }

    pub const fn destination_projection(&self) -> ProjectionIdV2 {
        self.destination_projection
    }

    pub const fn display_projection(&self) -> DisplayProjectionIdV2 {
        self.display_projection
    }
}

impl CancelKernelTaskRequestV2 {
    pub const fn new(
        preparation: NewTaskPreparationHandleV2,
        correlation: SignedDurableTaskCorrelationV2,
    ) -> Self {
        Self {
            preparation,
            correlation,
        }
    }

    pub const fn preparation(&self) -> NewTaskPreparationHandleV2 {
        self.preparation
    }

    pub const fn correlation(&self) -> &SignedDurableTaskCorrelationV2 {
        &self.correlation
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClaimAgentSessionRequestV2 {
    authorization: AgentUiAuthorizationHandleV2,
}

impl ClaimAgentSessionRequestV2 {
    pub const fn new(authorization: AgentUiAuthorizationHandleV2) -> Self {
        Self { authorization }
    }

    pub const fn authorization(self) -> AgentUiAuthorizationHandleV2 {
        self.authorization
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrepareFollowupIngressRequestV2 {
    session: AgentSessionHandleV2,
    run: RunHandleV2,
    client_request_nonce: Nonce32V2,
}

impl PrepareFollowupIngressRequestV2 {
    pub fn new(
        session: AgentSessionHandleV2,
        run: RunHandleV2,
        client_request_nonce: Nonce32V2,
    ) -> Result<Self, ProtocolError> {
        if is_zero(client_request_nonce.as_bytes()) {
            return Err(malformed());
        }
        Ok(Self {
            session,
            run,
            client_request_nonce,
        })
    }

    pub const fn session(self) -> AgentSessionHandleV2 {
        self.session
    }

    pub const fn run(self) -> RunHandleV2 {
        self.run
    }

    pub const fn client_request_nonce(self) -> Nonce32V2 {
        self.client_request_nonce
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GetAgentSessionStatusRequestV2 {
    session: AgentSessionHandleV2,
}

impl GetAgentSessionStatusRequestV2 {
    pub const fn new(session: AgentSessionHandleV2) -> Self {
        Self { session }
    }

    pub const fn session(self) -> AgentSessionHandleV2 {
        self.session
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparePlannerCallRequestV2 {
    run: RunHandleV2,
    planner_route: PlannerRouteIdV2,
    task_template: StaticTemplateIdV2,
    intent: PlannerIntentKindV2,
    purpose: PlannerPurposeV2,
    limits: PlannerLimitsV2,
    prompt_values: Vec<ValueHandleV2>,
}

impl PreparePlannerCallRequestV2 {
    pub fn new(
        run: RunHandleV2,
        planner_route: PlannerRouteIdV2,
        task_template: StaticTemplateIdV2,
        intent: PlannerIntentKindV2,
        purpose: PlannerPurposeV2,
        limits: PlannerLimitsV2,
        prompt_values: Vec<ValueHandleV2>,
    ) -> Result<Self, ProtocolError> {
        if planner_route.get() == 0
            || task_template.get() == 0
            || prompt_values.len() > MAX_PROMPT_VALUES_V2
        {
            return Err(malformed());
        }
        Ok(Self {
            run,
            planner_route,
            task_template,
            intent,
            purpose,
            limits,
            prompt_values,
        })
    }

    pub const fn run(&self) -> RunHandleV2 {
        self.run
    }

    pub const fn planner_route(&self) -> PlannerRouteIdV2 {
        self.planner_route
    }

    pub const fn task_template(&self) -> StaticTemplateIdV2 {
        self.task_template
    }

    pub const fn intent(&self) -> PlannerIntentKindV2 {
        self.intent
    }

    pub const fn purpose(&self) -> PlannerPurposeV2 {
        self.purpose
    }

    pub const fn limits(&self) -> PlannerLimitsV2 {
        self.limits
    }

    pub fn prompt_values(&self) -> &[ValueHandleV2] {
        &self.prompt_values
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RevokeVaultRequestV2 {
    document: MaskedDocumentHandleV2,
}

impl RevokeVaultRequestV2 {
    pub const fn new(document: MaskedDocumentHandleV2) -> Self {
        Self { document }
    }

    pub const fn document(self) -> MaskedDocumentHandleV2 {
        self.document
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CloseAgentSessionRequestV2 {
    session: AgentSessionHandleV2,
}

impl CloseAgentSessionRequestV2 {
    pub const fn new(session: AgentSessionHandleV2) -> Self {
        Self { session }
    }

    pub const fn session(self) -> AgentSessionHandleV2 {
        self.session
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrepareNewIngressRequestV2 {
    agent_task_nonce: Nonce32V2,
    client_request_nonce: Nonce32V2,
}

impl PrepareNewIngressRequestV2 {
    pub fn new(
        agent_task_nonce: Nonce32V2,
        client_request_nonce: Nonce32V2,
    ) -> Result<Self, ProtocolError> {
        if is_zero(agent_task_nonce.as_bytes()) || is_zero(client_request_nonce.as_bytes()) {
            return Err(malformed());
        }
        Ok(Self {
            agent_task_nonce,
            client_request_nonce,
        })
    }

    pub const fn agent_task_nonce(self) -> Nonce32V2 {
        self.agent_task_nonce
    }

    pub const fn client_request_nonce(self) -> Nonce32V2 {
        self.client_request_nonce
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrepareAgentUiAuthenticationRequestV2 {
    preparation: NewTaskPreparationHandleV2,
}

impl PrepareAgentUiAuthenticationRequestV2 {
    pub const fn new(preparation: NewTaskPreparationHandleV2) -> Self {
        Self { preparation }
    }

    pub const fn preparation(self) -> NewTaskPreparationHandleV2 {
        self.preparation
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DispatchExecutionRequestV2 {
    ticket: ExecutionTicketHandleV2,
}

impl DispatchExecutionRequestV2 {
    pub const fn new(ticket: ExecutionTicketHandleV2) -> Self {
        Self { ticket }
    }

    pub const fn ticket(self) -> ExecutionTicketHandleV2 {
        self.ticket
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionStatusTargetV2 {
    Intent(ActionIntentHandleV2),
    Ticket(ExecutionTicketHandleV2),
    Execution(ExecutionHandleV2),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GetExecutionStatusRequestV2 {
    target: ExecutionStatusTargetV2,
}

impl GetExecutionStatusRequestV2 {
    pub const fn new(target: ExecutionStatusTargetV2) -> Self {
        Self { target }
    }

    pub const fn target(self) -> ExecutionStatusTargetV2 {
        self.target
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DispatchReleaseRequestV2 {
    ticket: ReleaseTicketHandleV2,
}

impl DispatchReleaseRequestV2 {
    pub const fn new(ticket: ReleaseTicketHandleV2) -> Self {
        Self { ticket }
    }

    pub const fn ticket(self) -> ReleaseTicketHandleV2 {
        self.ticket
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseStatusTargetV2 {
    Pending(PendingReleaseHandleV2),
    Ticket(ReleaseTicketHandleV2),
    Release(ReleaseHandleV2),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GetReleaseStatusRequestV2 {
    target: ReleaseStatusTargetV2,
}

impl GetReleaseStatusRequestV2 {
    pub const fn new(target: ReleaseStatusTargetV2) -> Self {
        Self { target }
    }

    pub const fn target(self) -> ReleaseStatusTargetV2 {
        self.target
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadAgentViewRequestV2 {
    document: MaskedDocumentHandleV2,
    cursor: Option<KernelAgentViewCursorV2>,
    maximum_encoded_bytes: u32,
    client_request_nonce: Nonce32V2,
}

impl ReadAgentViewRequestV2 {
    pub fn new(
        document: MaskedDocumentHandleV2,
        cursor: Option<KernelAgentViewCursorV2>,
        maximum_encoded_bytes: u32,
        client_request_nonce: Nonce32V2,
    ) -> Result<Self, ProtocolError> {
        if maximum_encoded_bytes == 0
            || maximum_encoded_bytes > MAX_AGENT_VIEW_RESPONSE_BYTES_V2
            || is_zero(client_request_nonce.as_bytes())
        {
            return Err(malformed());
        }
        Ok(Self {
            document,
            cursor,
            maximum_encoded_bytes,
            client_request_nonce,
        })
    }

    pub const fn document(self) -> MaskedDocumentHandleV2 {
        self.document
    }

    pub const fn cursor(self) -> Option<KernelAgentViewCursorV2> {
        self.cursor
    }

    pub const fn maximum_encoded_bytes(self) -> u32 {
        self.maximum_encoded_bytes
    }

    pub const fn client_request_nonce(self) -> Nonce32V2 {
        self.client_request_nonce
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum KernelAgentOperationV2 {
    Health(KernelAgentHealthRequestV2),
    ClaimAgentSession(ClaimAgentSessionRequestV2),
    PrepareFollowupIngress(PrepareFollowupIngressRequestV2),
    GetAgentSessionStatus(GetAgentSessionStatusRequestV2),
    PreparePlannerCall(PreparePlannerCallRequestV2),
    CommitPlannerValue(CommitPlannerValueRequestV2),
    DeriveValue(DeriveValueRequestV2),
    ProposeToolCall(ProposeToolCallRequestV2),
    EvaluateToolCall(EvaluateToolCallRequestV2),
    AuthorizeToolCall(AuthorizeToolCallRequestV2),
    DispatchExecution(DispatchExecutionRequestV2),
    GetExecutionStatus(GetExecutionStatusRequestV2),
    ReadAgentView(ReadAgentViewRequestV2),
    PrepareRelease(PrepareReleaseRequestV2),
    AuthorizeRelease(AuthorizeReleaseRequestV2),
    DispatchRelease(DispatchReleaseRequestV2),
    GetReleaseStatus(GetReleaseStatusRequestV2),
    RevokeVault(RevokeVaultRequestV2),
    CloseAgentSession(CloseAgentSessionRequestV2),
    PrepareNewIngress(PrepareNewIngressRequestV2),
    PrepareAgentUiAuthentication(PrepareAgentUiAuthenticationRequestV2),
    AuthenticateAgentUi(AuthenticateAgentUiRequestV2),
    GetKernelTaskStatus(GetKernelTaskStatusRequestV2),
    CancelKernelTask(CancelKernelTaskRequestV2),
    ResumeCommittedAgentAuthentication(ResumeCommittedAgentAuthenticationRequestV2),
}

impl KernelAgentOperationV2 {
    pub const fn tag(&self) -> u16 {
        match self {
            Self::Health(_) => 0,
            Self::ClaimAgentSession(_) => 20,
            Self::PrepareFollowupIngress(_) => 21,
            Self::GetAgentSessionStatus(_) => 22,
            Self::PreparePlannerCall(_) => 23,
            Self::CommitPlannerValue(_) => 24,
            Self::DeriveValue(_) => 25,
            Self::ProposeToolCall(_) => 26,
            Self::EvaluateToolCall(_) => 27,
            Self::AuthorizeToolCall(_) => 28,
            Self::DispatchExecution(_) => 29,
            Self::GetExecutionStatus(_) => 30,
            Self::ReadAgentView(_) => 31,
            Self::PrepareRelease(_) => 32,
            Self::AuthorizeRelease(_) => 33,
            Self::DispatchRelease(_) => 34,
            Self::GetReleaseStatus(_) => 35,
            Self::RevokeVault(_) => 36,
            Self::CloseAgentSession(_) => 37,
            Self::PrepareNewIngress(_) => 38,
            Self::PrepareAgentUiAuthentication(_) => 39,
            Self::AuthenticateAgentUi(_) => 40,
            Self::GetKernelTaskStatus(_) => 41,
            Self::CancelKernelTask(_) => 42,
            Self::ResumeCommittedAgentAuthentication(_) => 43,
        }
    }
}

pub const fn kernel_agent_operation_tags_v2() -> &'static [u16; 25] {
    &[
        0, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41,
        42, 43,
    ]
}

pub fn encode_kernel_agent_operation_v2(
    value: &KernelAgentOperationV2,
) -> Result<Vec<u8>, ProtocolError> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    match value {
        KernelAgentOperationV2::Health(_) => {
            encoder
                .array(2)
                .and_then(|encoder| encoder.u16(0))
                .and_then(|encoder| encoder.array(0))
                .map_err(ProtocolError::malformed)?;
        }
        KernelAgentOperationV2::ClaimAgentSession(request) => {
            encoder
                .array(2)
                .and_then(|encoder| encoder.u16(20))
                .and_then(|encoder| encoder.array(1))
                .map_err(ProtocolError::malformed)?;
            minicbor::Encode::encode(&request.authorization, &mut encoder, &mut ())
                .map_err(ProtocolError::malformed)?;
        }
        KernelAgentOperationV2::PrepareFollowupIngress(request) => {
            encoder
                .array(2)
                .and_then(|encoder| encoder.u16(21))
                .and_then(|encoder| encoder.array(3))
                .map_err(ProtocolError::malformed)?;
            minicbor::Encode::encode(&request.session, &mut encoder, &mut ())
                .and_then(|_| minicbor::Encode::encode(&request.run, &mut encoder, &mut ()))
                .and_then(|_| {
                    minicbor::Encode::encode(&request.client_request_nonce, &mut encoder, &mut ())
                })
                .map_err(ProtocolError::malformed)?;
        }
        KernelAgentOperationV2::GetAgentSessionStatus(request) => {
            encoder
                .array(2)
                .and_then(|encoder| encoder.u16(22))
                .and_then(|encoder| encoder.array(1))
                .map_err(ProtocolError::malformed)?;
            minicbor::Encode::encode(&request.session, &mut encoder, &mut ())
                .map_err(ProtocolError::malformed)?;
        }
        KernelAgentOperationV2::PreparePlannerCall(request) => {
            encoder
                .array(2)
                .and_then(|encoder| encoder.u16(23))
                .and_then(|encoder| encoder.array(7))
                .map_err(ProtocolError::malformed)?;
            minicbor::Encode::encode(&request.run, &mut encoder, &mut ())
                .map_err(ProtocolError::malformed)?;
            minicbor::Encode::encode(&request.planner_route, &mut encoder, &mut ())
                .map_err(ProtocolError::malformed)?;
            minicbor::Encode::encode(&request.task_template, &mut encoder, &mut ())
                .map_err(ProtocolError::malformed)?;
            minicbor::Encode::encode(&request.intent, &mut encoder, &mut ())
                .map_err(ProtocolError::malformed)?;
            minicbor::Encode::encode(&request.purpose, &mut encoder, &mut ())
                .map_err(ProtocolError::malformed)?;
            minicbor::Encode::encode(&request.limits, &mut encoder, &mut ())
                .map_err(ProtocolError::malformed)?;
            encoder
                .array(u64::try_from(request.prompt_values.len()).map_err(|_| malformed())?)
                .map_err(ProtocolError::malformed)?;
            for value in &request.prompt_values {
                minicbor::Encode::encode(value, &mut encoder, &mut ())
                    .map_err(ProtocolError::malformed)?;
            }
        }
        KernelAgentOperationV2::CommitPlannerValue(request) => {
            encoder
                .array(2)
                .and_then(|encoder| encoder.u16(24))
                .and_then(|encoder| encoder.array(3))
                .map_err(ProtocolError::malformed)?;
            minicbor::Encode::encode(&request.run, &mut encoder, &mut ())
                .and_then(|_| minicbor::Encode::encode(&request.ticket, &mut encoder, &mut ()))
                .map_err(ProtocolError::malformed)?;
            encode_planner_plan(&mut encoder, &request.plan)?;
        }
        KernelAgentOperationV2::DeriveValue(request) => {
            encoder
                .array(2)
                .and_then(|encoder| encoder.u16(25))
                .and_then(|encoder| encoder.array(3))
                .map_err(ProtocolError::malformed)?;
            minicbor::Encode::encode(&request.run, &mut encoder, &mut ())
                .map_err(ProtocolError::malformed)?;
            encode_derive_operation(&mut encoder, &request.operation)?;
            encode_value_handles(&mut encoder, &request.inputs)?;
        }
        KernelAgentOperationV2::ProposeToolCall(request) => {
            encoder
                .array(2)
                .and_then(|encoder| encoder.u16(26))
                .and_then(|encoder| encoder.array(3))
                .map_err(ProtocolError::malformed)?;
            minicbor::Encode::encode(&request.step, &mut encoder, &mut ())
                .and_then(|_| minicbor::Encode::encode(&request.tool, &mut encoder, &mut ()))
                .map_err(ProtocolError::malformed)?;
            encode_named_arguments(&mut encoder, &request.arguments)?;
        }
        KernelAgentOperationV2::EvaluateToolCall(request) => {
            encode_one_field(&mut encoder, 27, &request.pending)?;
        }
        KernelAgentOperationV2::AuthorizeToolCall(request) => {
            encoder
                .array(2)
                .and_then(|encoder| encoder.u16(28))
                .and_then(|encoder| encoder.array(3))
                .map_err(ProtocolError::malformed)?;
            minicbor::Encode::encode(&request.pending, &mut encoder, &mut ())
                .and_then(|_| minicbor::Encode::encode(&request.approval, &mut encoder, &mut ()))
                .and_then(|_| minicbor::Encode::encode(&request.receipt, &mut encoder, &mut ()))
                .map_err(ProtocolError::malformed)?;
        }
        KernelAgentOperationV2::DispatchExecution(request) => {
            encode_one_field(&mut encoder, 29, &request.ticket)?;
        }
        KernelAgentOperationV2::GetExecutionStatus(request) => {
            encoder
                .array(2)
                .and_then(|encoder| encoder.u16(30))
                .and_then(|encoder| encoder.array(1))
                .map_err(ProtocolError::malformed)?;
            encode_execution_target(&mut encoder, request.target)?;
        }
        KernelAgentOperationV2::ReadAgentView(request) => {
            encoder
                .array(2)
                .and_then(|encoder| encoder.u16(31))
                .and_then(|encoder| encoder.array(4))
                .map_err(ProtocolError::malformed)?;
            minicbor::Encode::encode(&request.document, &mut encoder, &mut ())
                .map_err(ProtocolError::malformed)?;
            match request.cursor {
                Some(cursor) => minicbor::Encode::encode(&cursor, &mut encoder, &mut ())
                    .map_err(ProtocolError::malformed)?,
                None => {
                    encoder.null().map_err(ProtocolError::malformed)?;
                }
            }
            encoder
                .u32(request.maximum_encoded_bytes)
                .map_err(ProtocolError::malformed)?;
            minicbor::Encode::encode(&request.client_request_nonce, &mut encoder, &mut ())
                .map_err(ProtocolError::malformed)?;
        }
        KernelAgentOperationV2::PrepareRelease(request) => {
            encoder
                .array(2)
                .and_then(|encoder| encoder.u16(32))
                .and_then(|encoder| encoder.array(5))
                .map_err(ProtocolError::malformed)?;
            minicbor::Encode::encode(&request.document, &mut encoder, &mut ())
                .map_err(ProtocolError::malformed)?;
            encode_value_handles(&mut encoder, &request.evidence)?;
            minicbor::Encode::encode(&request.executor, &mut encoder, &mut ())
                .and_then(|_| {
                    minicbor::Encode::encode(&request.destination_projection, &mut encoder, &mut ())
                })
                .and_then(|_| {
                    minicbor::Encode::encode(&request.display_projection, &mut encoder, &mut ())
                })
                .map_err(ProtocolError::malformed)?;
        }
        KernelAgentOperationV2::AuthorizeRelease(request) => {
            encoder
                .array(2)
                .and_then(|encoder| encoder.u16(33))
                .and_then(|encoder| encoder.array(3))
                .map_err(ProtocolError::malformed)?;
            minicbor::Encode::encode(&request.pending, &mut encoder, &mut ())
                .and_then(|_| minicbor::Encode::encode(&request.approval, &mut encoder, &mut ()))
                .and_then(|_| minicbor::Encode::encode(&request.settlement, &mut encoder, &mut ()))
                .map_err(ProtocolError::malformed)?;
        }
        KernelAgentOperationV2::DispatchRelease(request) => {
            encode_one_field(&mut encoder, 34, &request.ticket)?;
        }
        KernelAgentOperationV2::GetReleaseStatus(request) => {
            encoder
                .array(2)
                .and_then(|encoder| encoder.u16(35))
                .and_then(|encoder| encoder.array(1))
                .map_err(ProtocolError::malformed)?;
            encode_release_target(&mut encoder, request.target)?;
        }
        KernelAgentOperationV2::RevokeVault(request) => {
            encode_one_field(&mut encoder, 36, &request.document)?;
        }
        KernelAgentOperationV2::CloseAgentSession(request) => {
            encode_one_field(&mut encoder, 37, &request.session)?;
        }
        KernelAgentOperationV2::PrepareNewIngress(request) => {
            encoder
                .array(2)
                .and_then(|encoder| encoder.u16(38))
                .and_then(|encoder| encoder.array(2))
                .map_err(ProtocolError::malformed)?;
            minicbor::Encode::encode(&request.agent_task_nonce, &mut encoder, &mut ())
                .and_then(|_| {
                    minicbor::Encode::encode(&request.client_request_nonce, &mut encoder, &mut ())
                })
                .map_err(ProtocolError::malformed)?;
        }
        KernelAgentOperationV2::PrepareAgentUiAuthentication(request) => {
            encode_one_field(&mut encoder, 39, &request.preparation)?;
        }
        KernelAgentOperationV2::AuthenticateAgentUi(request) => {
            encoder
                .array(2)
                .and_then(|encoder| encoder.u16(40))
                .and_then(|encoder| encoder.array(2))
                .map_err(ProtocolError::malformed)?;
            minicbor::Encode::encode(&request.authentication_preparation, &mut encoder, &mut ())
                .and_then(|_| minicbor::Encode::encode(&request.settlement, &mut encoder, &mut ()))
                .map_err(ProtocolError::malformed)?;
        }
        KernelAgentOperationV2::GetKernelTaskStatus(request) => {
            encode_one_field(&mut encoder, 41, &request.correlation)?;
        }
        KernelAgentOperationV2::CancelKernelTask(request) => {
            encoder
                .array(2)
                .and_then(|encoder| encoder.u16(42))
                .and_then(|encoder| encoder.array(2))
                .map_err(ProtocolError::malformed)?;
            minicbor::Encode::encode(&request.preparation, &mut encoder, &mut ())
                .and_then(|_| minicbor::Encode::encode(&request.correlation, &mut encoder, &mut ()))
                .map_err(ProtocolError::malformed)?;
        }
        KernelAgentOperationV2::ResumeCommittedAgentAuthentication(request) => {
            encoder
                .array(2)
                .and_then(|encoder| encoder.u16(43))
                .and_then(|encoder| encoder.array(3))
                .map_err(ProtocolError::malformed)?;
            minicbor::Encode::encode(&request.correlation, &mut encoder, &mut ())
                .and_then(|_| {
                    minicbor::Encode::encode(&request.client_request_nonce, &mut encoder, &mut ())
                })
                .map_err(ProtocolError::malformed)?;
            match &request.prior_attempt_closure_proof {
                Some(proof) => minicbor::Encode::encode(proof, &mut encoder, &mut ())
                    .map_err(ProtocolError::malformed)?,
                None => {
                    encoder.null().map_err(ProtocolError::malformed)?;
                }
            }
        }
    }
    Ok(encoder.into_writer())
}

pub fn decode_kernel_agent_operation_v2(
    bytes: &[u8],
) -> Result<KernelAgentOperationV2, ProtocolError> {
    scan_single(bytes)?;
    let mut decoder = minicbor::Decoder::new(bytes);
    if decoder.array().map_err(ProtocolError::malformed)? != Some(2) {
        return Err(malformed());
    }
    let tag = decoder.u16().map_err(ProtocolError::malformed)?;
    let mut context = V2DecodeContext;
    let value = match tag {
        0 => {
            if decoder.array().map_err(ProtocolError::malformed)? != Some(0) {
                return Err(malformed());
            }
            KernelAgentOperationV2::Health(KernelAgentHealthRequestV2)
        }
        20 => {
            expect_array(&mut decoder, 1)?;
            let authorization = minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?;
            KernelAgentOperationV2::ClaimAgentSession(ClaimAgentSessionRequestV2::new(
                authorization,
            ))
        }
        21 => {
            expect_array(&mut decoder, 3)?;
            let session = minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?;
            let run = minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?;
            let nonce = minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?;
            KernelAgentOperationV2::PrepareFollowupIngress(PrepareFollowupIngressRequestV2::new(
                session, run, nonce,
            )?)
        }
        22 => {
            expect_array(&mut decoder, 1)?;
            let session = minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?;
            KernelAgentOperationV2::GetAgentSessionStatus(GetAgentSessionStatusRequestV2::new(
                session,
            ))
        }
        23 => {
            expect_array(&mut decoder, 7)?;
            let run = minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?;
            let planner_route = minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?;
            let task_template = minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?;
            let intent = minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?;
            let purpose = minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?;
            let limits = minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?;
            let prompt_values = decode_value_handles(&mut decoder, &mut context)?;
            KernelAgentOperationV2::PreparePlannerCall(PreparePlannerCallRequestV2::new(
                run,
                planner_route,
                task_template,
                intent,
                purpose,
                limits,
                prompt_values,
            )?)
        }
        24 => {
            expect_array(&mut decoder, 3)?;
            let run = minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?;
            let ticket = minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?;
            let plan = decode_planner_plan(&mut decoder, &mut context)?;
            KernelAgentOperationV2::CommitPlannerValue(CommitPlannerValueRequestV2::new(
                run, ticket, plan,
            ))
        }
        25 => {
            expect_array(&mut decoder, 3)?;
            let run = minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?;
            let operation = decode_derive_operation(&mut decoder, &mut context)?;
            let inputs = decode_value_handles(&mut decoder, &mut context)?;
            KernelAgentOperationV2::DeriveValue(DeriveValueRequestV2::new(run, operation, inputs)?)
        }
        26 => {
            expect_array(&mut decoder, 3)?;
            let step = minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?;
            let tool = minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?;
            let arguments = decode_named_arguments(&mut decoder, &mut context)?;
            KernelAgentOperationV2::ProposeToolCall(ProposeToolCallRequestV2::new(
                step, tool, arguments,
            )?)
        }
        27 => {
            expect_array(&mut decoder, 1)?;
            let pending = minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?;
            KernelAgentOperationV2::EvaluateToolCall(EvaluateToolCallRequestV2::new(pending))
        }
        28 => {
            expect_array(&mut decoder, 3)?;
            let pending = minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?;
            let approval = minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?;
            let receipt = minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?;
            KernelAgentOperationV2::AuthorizeToolCall(AuthorizeToolCallRequestV2::new(
                pending, approval, receipt,
            )?)
        }
        29 => {
            expect_array(&mut decoder, 1)?;
            let ticket = minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?;
            KernelAgentOperationV2::DispatchExecution(DispatchExecutionRequestV2::new(ticket))
        }
        30 => {
            expect_array(&mut decoder, 1)?;
            KernelAgentOperationV2::GetExecutionStatus(GetExecutionStatusRequestV2::new(
                decode_execution_target(&mut decoder, &mut context)?,
            ))
        }
        31 => {
            expect_array(&mut decoder, 4)?;
            let document = minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?;
            let cursor = if decoder.datatype().map_err(ProtocolError::malformed)?
                == minicbor::data::Type::Null
            {
                decoder.null().map_err(ProtocolError::malformed)?;
                None
            } else {
                Some(
                    minicbor::Decode::decode(&mut decoder, &mut context)
                        .map_err(ProtocolError::from_typed_decode)?,
                )
            };
            let maximum_encoded_bytes = decoder.u32().map_err(ProtocolError::malformed)?;
            let client_request_nonce = minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?;
            KernelAgentOperationV2::ReadAgentView(ReadAgentViewRequestV2::new(
                document,
                cursor,
                maximum_encoded_bytes,
                client_request_nonce,
            )?)
        }
        32 => {
            expect_array(&mut decoder, 5)?;
            let document = minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?;
            let evidence = decode_value_handles(&mut decoder, &mut context)?;
            let executor = minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?;
            let destination_projection = minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?;
            let display_projection = minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?;
            KernelAgentOperationV2::PrepareRelease(PrepareReleaseRequestV2::new(
                document,
                evidence,
                executor,
                destination_projection,
                display_projection,
            )?)
        }
        33 => {
            expect_array(&mut decoder, 3)?;
            let pending = minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?;
            let approval = minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?;
            let settlement = minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?;
            KernelAgentOperationV2::AuthorizeRelease(AuthorizeReleaseRequestV2::new(
                pending, approval, settlement,
            )?)
        }
        34 => {
            expect_array(&mut decoder, 1)?;
            let ticket = minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?;
            KernelAgentOperationV2::DispatchRelease(DispatchReleaseRequestV2::new(ticket))
        }
        35 => {
            expect_array(&mut decoder, 1)?;
            KernelAgentOperationV2::GetReleaseStatus(GetReleaseStatusRequestV2::new(
                decode_release_target(&mut decoder, &mut context)?,
            ))
        }
        36 => {
            expect_array(&mut decoder, 1)?;
            let document = minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?;
            KernelAgentOperationV2::RevokeVault(RevokeVaultRequestV2::new(document))
        }
        37 => {
            expect_array(&mut decoder, 1)?;
            let session = minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?;
            KernelAgentOperationV2::CloseAgentSession(CloseAgentSessionRequestV2::new(session))
        }
        38 => {
            expect_array(&mut decoder, 2)?;
            let agent_task_nonce = minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?;
            let client_request_nonce = minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?;
            KernelAgentOperationV2::PrepareNewIngress(PrepareNewIngressRequestV2::new(
                agent_task_nonce,
                client_request_nonce,
            )?)
        }
        39 => {
            expect_array(&mut decoder, 1)?;
            let preparation = minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?;
            KernelAgentOperationV2::PrepareAgentUiAuthentication(
                PrepareAgentUiAuthenticationRequestV2::new(preparation),
            )
        }
        40 => {
            expect_array(&mut decoder, 2)?;
            let authentication_preparation = minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?;
            let settlement = minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?;
            KernelAgentOperationV2::AuthenticateAgentUi(AuthenticateAgentUiRequestV2::new(
                authentication_preparation,
                settlement,
            )?)
        }
        41 => {
            expect_array(&mut decoder, 1)?;
            let correlation = minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?;
            KernelAgentOperationV2::GetKernelTaskStatus(GetKernelTaskStatusRequestV2::new(
                correlation,
            ))
        }
        42 => {
            expect_array(&mut decoder, 2)?;
            let preparation = minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?;
            let correlation = minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?;
            KernelAgentOperationV2::CancelKernelTask(CancelKernelTaskRequestV2::new(
                preparation,
                correlation,
            ))
        }
        43 => {
            expect_array(&mut decoder, 3)?;
            let correlation = minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?;
            let client_request_nonce = minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?;
            let prior_attempt_closure_proof =
                if decoder.datatype().map_err(ProtocolError::malformed)?
                    == minicbor::data::Type::Null
                {
                    decoder.null().map_err(ProtocolError::malformed)?;
                    None
                } else {
                    Some(
                        minicbor::Decode::decode(&mut decoder, &mut context)
                            .map_err(ProtocolError::from_typed_decode)?,
                    )
                };
            KernelAgentOperationV2::ResumeCommittedAgentAuthentication(
                ResumeCommittedAgentAuthenticationRequestV2::new(
                    correlation,
                    client_request_nonce,
                    prior_attempt_closure_proof,
                )?,
            )
        }
        _ => {
            return Err(ProtocolError::stable(StableCode::ProtocolUnknownOperation));
        }
    };
    if decoder.position() != bytes.len() || encode_kernel_agent_operation_v2(&value)? != bytes {
        return Err(malformed());
    }
    Ok(value)
}

fn decode_value_handles(
    decoder: &mut minicbor::Decoder<'_>,
    context: &mut V2DecodeContext,
) -> Result<Vec<ValueHandleV2>, ProtocolError> {
    let length = decoder
        .array()
        .map_err(ProtocolError::malformed)?
        .ok_or_else(malformed)?;
    let length = usize::try_from(length).map_err(|_| malformed())?;
    if length > MAX_PROMPT_VALUES_V2 {
        return Err(malformed());
    }
    let mut values = Vec::new();
    values.try_reserve_exact(length).map_err(|_| malformed())?;
    for _ in 0..length {
        values.push(
            minicbor::Decode::decode(decoder, context).map_err(ProtocolError::from_typed_decode)?,
        );
    }
    Ok(values)
}

fn encode_value_handles(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    values: &[ValueHandleV2],
) -> Result<(), ProtocolError> {
    encoder
        .array(u64::try_from(values.len()).map_err(|_| malformed())?)
        .map_err(ProtocolError::malformed)?;
    for value in values {
        minicbor::Encode::encode(value, encoder, &mut ()).map_err(ProtocolError::malformed)?;
    }
    Ok(())
}

fn encode_planner_plan(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    plan: &PlannerPlanV2,
) -> Result<(), ProtocolError> {
    encoder
        .array(3)
        .and_then(|encoder| encoder.u16(2))
        .map_err(ProtocolError::malformed)?;
    minicbor::Encode::encode(&plan.envelope_nonce, encoder, &mut ())
        .map_err(ProtocolError::malformed)?;
    encoder
        .array(u64::try_from(plan.steps.len()).map_err(|_| malformed())?)
        .map_err(ProtocolError::malformed)?;
    for step in &plan.steps {
        encoder
            .array(5)
            .and_then(|encoder| encoder.u16(step.ordinal))
            .map_err(ProtocolError::malformed)?;
        minicbor::Encode::encode(&step.action_template, encoder, &mut ())
            .and_then(|_| minicbor::Encode::encode(&step.tool_class, encoder, &mut ()))
            .map_err(ProtocolError::malformed)?;
        encoder
            .array(u64::try_from(step.slot_bindings.len()).map_err(|_| malformed())?)
            .map_err(ProtocolError::malformed)?;
        for (name, reference) in &step.slot_bindings {
            encoder.array(2).map_err(ProtocolError::malformed)?;
            minicbor::Encode::encode(name, encoder, &mut ())
                .and_then(|_| minicbor::Encode::encode(reference, encoder, &mut ()))
                .map_err(ProtocolError::malformed)?;
        }
        encoder
            .array(u64::try_from(step.dependencies.len()).map_err(|_| malformed())?)
            .map_err(ProtocolError::malformed)?;
        for dependency in &step.dependencies {
            encoder.u16(*dependency).map_err(ProtocolError::malformed)?;
        }
    }
    Ok(())
}

fn decode_planner_plan(
    decoder: &mut minicbor::Decoder<'_>,
    context: &mut V2DecodeContext,
) -> Result<PlannerPlanV2, ProtocolError> {
    expect_array(decoder, 3)?;
    if decoder.u16().map_err(ProtocolError::malformed)? != 2 {
        return Err(malformed());
    }
    let envelope_nonce =
        minicbor::Decode::decode(decoder, context).map_err(ProtocolError::from_typed_decode)?;
    let step_count = decode_bounded_array_length(decoder, MAX_PROMPT_VALUES_V2)?;
    let mut steps = Vec::new();
    steps
        .try_reserve_exact(step_count)
        .map_err(|_| malformed())?;
    for _ in 0..step_count {
        expect_array(decoder, 5)?;
        let ordinal = decoder.u16().map_err(ProtocolError::malformed)?;
        let action_template =
            minicbor::Decode::decode(decoder, context).map_err(ProtocolError::from_typed_decode)?;
        let tool_class =
            minicbor::Decode::decode(decoder, context).map_err(ProtocolError::from_typed_decode)?;
        let binding_count = decode_bounded_array_length(decoder, MAX_PROMPT_VALUES_V2)?;
        let mut slot_bindings = Vec::new();
        slot_bindings
            .try_reserve_exact(binding_count)
            .map_err(|_| malformed())?;
        for _ in 0..binding_count {
            expect_array(decoder, 2)?;
            let name = minicbor::Decode::decode(decoder, context)
                .map_err(ProtocolError::from_typed_decode)?;
            let reference = minicbor::Decode::decode(decoder, context)
                .map_err(ProtocolError::from_typed_decode)?;
            slot_bindings.push((name, reference));
        }
        let dependency_count = decode_bounded_array_length(decoder, MAX_PROMPT_VALUES_V2)?;
        let mut dependencies = Vec::new();
        dependencies
            .try_reserve_exact(dependency_count)
            .map_err(|_| malformed())?;
        for _ in 0..dependency_count {
            dependencies.push(decoder.u16().map_err(ProtocolError::malformed)?);
        }
        steps.push(PlannerStepV2::new(
            ordinal,
            action_template,
            tool_class,
            slot_bindings,
            dependencies,
        )?);
    }
    PlannerPlanV2::new(envelope_nonce, steps)
}

fn encode_derive_operation(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    operation: &DeriveOperationV2,
) -> Result<(), ProtocolError> {
    match operation {
        DeriveOperationV2::ConcatenateText => {
            encoder
                .array(1)
                .and_then(|encoder| encoder.u16(1))
                .map_err(ProtocolError::malformed)?;
        }
        DeriveOperationV2::NormalizeNfc => {
            encoder
                .array(1)
                .and_then(|encoder| encoder.u16(2))
                .map_err(ProtocolError::malformed)?;
        }
        DeriveOperationV2::SelectObjectField(name) => {
            encoder
                .array(2)
                .and_then(|encoder| encoder.u16(3))
                .map_err(ProtocolError::malformed)?;
            minicbor::Encode::encode(name, encoder, &mut ()).map_err(ProtocolError::malformed)?;
        }
        DeriveOperationV2::AssembleList => {
            encoder
                .array(1)
                .and_then(|encoder| encoder.u16(4))
                .map_err(ProtocolError::malformed)?;
        }
        DeriveOperationV2::AssembleObject(fields) => {
            encoder
                .array(2)
                .and_then(|encoder| encoder.u16(5))
                .and_then(|encoder| {
                    encoder.array(u64::try_from(fields.len()).map_err(|_| {
                        minicbor::encode::Error::<core::convert::Infallible>::message(
                            "too many fields",
                        )
                    })?)
                })
                .map_err(ProtocolError::malformed)?;
            for field in fields {
                minicbor::Encode::encode(field, encoder, &mut ())
                    .map_err(ProtocolError::malformed)?;
            }
        }
        DeriveOperationV2::PolicyConstant(constant_id) => {
            encoder
                .array(2)
                .and_then(|encoder| encoder.u16(6))
                .map_err(ProtocolError::malformed)?;
            minicbor::Encode::encode(constant_id, encoder, &mut ())
                .map_err(ProtocolError::malformed)?;
        }
    }
    Ok(())
}

fn decode_derive_operation(
    decoder: &mut minicbor::Decoder<'_>,
    context: &mut V2DecodeContext,
) -> Result<DeriveOperationV2, ProtocolError> {
    let length = decoder
        .array()
        .map_err(ProtocolError::malformed)?
        .ok_or_else(malformed)?;
    let tag = decoder.u16().map_err(ProtocolError::malformed)?;
    match (tag, length) {
        (1, 1) => Ok(DeriveOperationV2::concatenate_text()),
        (2, 1) => Ok(DeriveOperationV2::normalize_nfc()),
        (3, 2) => {
            let name = minicbor::Decode::decode(decoder, context)
                .map_err(ProtocolError::from_typed_decode)?;
            Ok(DeriveOperationV2::select_object_field(name))
        }
        (4, 1) => Ok(DeriveOperationV2::assemble_list()),
        (5, 2) => {
            let field_count = decode_bounded_array_length(decoder, MAX_PROMPT_VALUES_V2)?;
            let mut fields = Vec::new();
            fields
                .try_reserve_exact(field_count)
                .map_err(|_| malformed())?;
            for _ in 0..field_count {
                fields.push(
                    minicbor::Decode::decode(decoder, context)
                        .map_err(ProtocolError::from_typed_decode)?,
                );
            }
            DeriveOperationV2::assemble_object(fields)
        }
        (6, 2) => {
            let constant_id = minicbor::Decode::decode(decoder, context)
                .map_err(ProtocolError::from_typed_decode)?;
            DeriveOperationV2::policy_constant(constant_id)
        }
        _ => Err(malformed()),
    }
}

fn encode_named_arguments(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    arguments: &[NamedArgumentValueBindingV2],
) -> Result<(), ProtocolError> {
    encoder
        .array(u64::try_from(arguments.len()).map_err(|_| malformed())?)
        .map_err(ProtocolError::malformed)?;
    for argument in arguments {
        encoder.array(2).map_err(ProtocolError::malformed)?;
        minicbor::Encode::encode(&argument.name, encoder, &mut ())
            .and_then(|_| minicbor::Encode::encode(&argument.value, encoder, &mut ()))
            .map_err(ProtocolError::malformed)?;
    }
    Ok(())
}

fn decode_named_arguments(
    decoder: &mut minicbor::Decoder<'_>,
    context: &mut V2DecodeContext,
) -> Result<Vec<NamedArgumentValueBindingV2>, ProtocolError> {
    let length = decode_bounded_array_length(decoder, MAX_PROMPT_VALUES_V2)?;
    let mut arguments = Vec::new();
    arguments
        .try_reserve_exact(length)
        .map_err(|_| malformed())?;
    for _ in 0..length {
        expect_array(decoder, 2)?;
        let name =
            minicbor::Decode::decode(decoder, context).map_err(ProtocolError::from_typed_decode)?;
        let value =
            minicbor::Decode::decode(decoder, context).map_err(ProtocolError::from_typed_decode)?;
        arguments.push(NamedArgumentValueBindingV2::new(name, value));
    }
    if arguments
        .windows(2)
        .any(|pair| pair[0].name >= pair[1].name)
    {
        return Err(malformed());
    }
    Ok(arguments)
}

fn decode_bounded_array_length(
    decoder: &mut minicbor::Decoder<'_>,
    maximum: usize,
) -> Result<usize, ProtocolError> {
    let length = decoder
        .array()
        .map_err(ProtocolError::malformed)?
        .ok_or_else(malformed)?;
    let length = usize::try_from(length).map_err(|_| malformed())?;
    if length > maximum {
        return Err(malformed());
    }
    Ok(length)
}

fn encode_unsigned_durable_task_correlation_v2(
    value: &UnsignedDurableTaskCorrelationV2,
) -> Result<Vec<u8>, ProtocolError> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(12)
        .and_then(|encoder| encoder.u16(2))
        .map_err(ProtocolError::malformed)?;
    minicbor::Encode::encode(&value.installation_id, &mut encoder, &mut ())
        .and_then(|_| {
            minicbor::Encode::encode(&value.active_state_manifest_digest, &mut encoder, &mut ())
        })
        .map_err(ProtocolError::malformed)?;
    encoder
        .u64(value.deployment_generation)
        .map_err(ProtocolError::malformed)?;
    minicbor::Encode::encode(&value.durable_task_id, &mut encoder, &mut ())
        .and_then(|_| minicbor::Encode::encode(&value.agentd_identity, &mut encoder, &mut ()))
        .and_then(|_| {
            minicbor::Encode::encode(&value.agentd_kernel_client_boot_id, &mut encoder, &mut ())
        })
        .and_then(|_| {
            minicbor::Encode::encode(&value.kerneld_server_boot_id, &mut encoder, &mut ())
        })
        .and_then(|_| minicbor::Encode::encode(&value.machine_boot_id, &mut encoder, &mut ()))
        .and_then(|_| minicbor::Encode::encode(&value.issued_at, &mut encoder, &mut ()))
        .and_then(|_| {
            minicbor::Encode::encode(&value.task_logical_expires_at, &mut encoder, &mut ())
        })
        .and_then(|_| minicbor::Encode::encode(&value.status_retain_until, &mut encoder, &mut ()))
        .map_err(ProtocolError::malformed)?;
    Ok(encoder.into_writer())
}

fn decode_unsigned_durable_task_correlation_v2(
    bytes: &[u8],
) -> Result<UnsignedDurableTaskCorrelationV2, ProtocolError> {
    scan_single(bytes)?;
    let mut decoder = minicbor::Decoder::new(bytes);
    expect_array(&mut decoder, 12)?;
    if decoder.u16().map_err(ProtocolError::malformed)? != 2 {
        return Err(malformed());
    }
    let mut context = V2DecodeContext;
    let installation_id = minicbor::Decode::decode(&mut decoder, &mut context)
        .map_err(ProtocolError::from_typed_decode)?;
    let active_state_manifest_digest = minicbor::Decode::decode(&mut decoder, &mut context)
        .map_err(ProtocolError::from_typed_decode)?;
    let deployment_generation = decoder.u64().map_err(ProtocolError::malformed)?;
    let durable_task_id = minicbor::Decode::decode(&mut decoder, &mut context)
        .map_err(ProtocolError::from_typed_decode)?;
    let agentd_identity = minicbor::Decode::decode(&mut decoder, &mut context)
        .map_err(ProtocolError::from_typed_decode)?;
    let agentd_kernel_client_boot_id = minicbor::Decode::decode(&mut decoder, &mut context)
        .map_err(ProtocolError::from_typed_decode)?;
    let kerneld_server_boot_id = minicbor::Decode::decode(&mut decoder, &mut context)
        .map_err(ProtocolError::from_typed_decode)?;
    let machine_boot_id = minicbor::Decode::decode(&mut decoder, &mut context)
        .map_err(ProtocolError::from_typed_decode)?;
    let issued_at = minicbor::Decode::decode(&mut decoder, &mut context)
        .map_err(ProtocolError::from_typed_decode)?;
    let task_logical_expires_at = minicbor::Decode::decode(&mut decoder, &mut context)
        .map_err(ProtocolError::from_typed_decode)?;
    let status_retain_until = minicbor::Decode::decode(&mut decoder, &mut context)
        .map_err(ProtocolError::from_typed_decode)?;
    let value = UnsignedDurableTaskCorrelationV2::new(
        installation_id,
        active_state_manifest_digest,
        deployment_generation,
        durable_task_id,
        agentd_identity,
        agentd_kernel_client_boot_id,
        kerneld_server_boot_id,
        machine_boot_id,
        issued_at,
        task_logical_expires_at,
        status_retain_until,
    )?;
    if decoder.position() != bytes.len()
        || encode_unsigned_durable_task_correlation_v2(&value)? != bytes
    {
        return Err(malformed());
    }
    Ok(value)
}

fn encode_execution_target(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    value: ExecutionStatusTargetV2,
) -> Result<(), ProtocolError> {
    encoder.array(2).map_err(ProtocolError::malformed)?;
    match value {
        ExecutionStatusTargetV2::Intent(handle) => {
            encoder.u16(1).map_err(ProtocolError::malformed)?;
            minicbor::Encode::encode(&handle, encoder, &mut ())
        }
        ExecutionStatusTargetV2::Ticket(handle) => {
            encoder.u16(2).map_err(ProtocolError::malformed)?;
            minicbor::Encode::encode(&handle, encoder, &mut ())
        }
        ExecutionStatusTargetV2::Execution(handle) => {
            encoder.u16(3).map_err(ProtocolError::malformed)?;
            minicbor::Encode::encode(&handle, encoder, &mut ())
        }
    }
    .map_err(ProtocolError::malformed)
}

fn decode_execution_target(
    decoder: &mut minicbor::Decoder<'_>,
    context: &mut V2DecodeContext,
) -> Result<ExecutionStatusTargetV2, ProtocolError> {
    expect_array(decoder, 2)?;
    match decoder.u16().map_err(ProtocolError::malformed)? {
        1 => minicbor::Decode::decode(decoder, context)
            .map(ExecutionStatusTargetV2::Intent)
            .map_err(ProtocolError::from_typed_decode),
        2 => minicbor::Decode::decode(decoder, context)
            .map(ExecutionStatusTargetV2::Ticket)
            .map_err(ProtocolError::from_typed_decode),
        3 => minicbor::Decode::decode(decoder, context)
            .map(ExecutionStatusTargetV2::Execution)
            .map_err(ProtocolError::from_typed_decode),
        _ => Err(malformed()),
    }
}

fn encode_release_target(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    value: ReleaseStatusTargetV2,
) -> Result<(), ProtocolError> {
    encoder.array(2).map_err(ProtocolError::malformed)?;
    match value {
        ReleaseStatusTargetV2::Pending(handle) => {
            encoder.u16(1).map_err(ProtocolError::malformed)?;
            minicbor::Encode::encode(&handle, encoder, &mut ())
        }
        ReleaseStatusTargetV2::Ticket(handle) => {
            encoder.u16(2).map_err(ProtocolError::malformed)?;
            minicbor::Encode::encode(&handle, encoder, &mut ())
        }
        ReleaseStatusTargetV2::Release(handle) => {
            encoder.u16(3).map_err(ProtocolError::malformed)?;
            minicbor::Encode::encode(&handle, encoder, &mut ())
        }
    }
    .map_err(ProtocolError::malformed)
}

fn decode_release_target(
    decoder: &mut minicbor::Decoder<'_>,
    context: &mut V2DecodeContext,
) -> Result<ReleaseStatusTargetV2, ProtocolError> {
    expect_array(decoder, 2)?;
    match decoder.u16().map_err(ProtocolError::malformed)? {
        1 => minicbor::Decode::decode(decoder, context)
            .map(ReleaseStatusTargetV2::Pending)
            .map_err(ProtocolError::from_typed_decode),
        2 => minicbor::Decode::decode(decoder, context)
            .map(ReleaseStatusTargetV2::Ticket)
            .map_err(ProtocolError::from_typed_decode),
        3 => minicbor::Decode::decode(decoder, context)
            .map(ReleaseStatusTargetV2::Release)
            .map_err(ProtocolError::from_typed_decode),
        _ => Err(malformed()),
    }
}

fn encode_one_field<T: minicbor::Encode<()>>(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    tag: u16,
    value: &T,
) -> Result<(), ProtocolError> {
    encoder
        .array(2)
        .and_then(|encoder| encoder.u16(tag))
        .and_then(|encoder| encoder.array(1))
        .map_err(ProtocolError::malformed)?;
    minicbor::Encode::encode(value, encoder, &mut ()).map_err(ProtocolError::malformed)
}

fn expect_array(decoder: &mut minicbor::Decoder<'_>, length: u64) -> Result<(), ProtocolError> {
    if decoder.array().map_err(ProtocolError::malformed)? != Some(length) {
        return Err(malformed());
    }
    Ok(())
}

fn is_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

fn malformed() -> ProtocolError {
    ProtocolError::stable(StableCode::ProtocolMalformedCbor)
}
