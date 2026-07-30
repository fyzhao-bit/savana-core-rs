use minicbor::Encode as _;
use savana_kernel_protocol::v2::{
    ActionIntentIdV2, Digest32V2, DisplayProjectionIdV2, DurableRunIdV2, DurableTaskIdV2,
    Ed25519KeyIdV2, ExecutorIdentityV2, InternalSlotDigestV2, InternalStepIdV2,
    PlanRevisionDigestV2, ProjectionIdV2, RequestIdV2, ValueInternalIdV2,
};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use super::{
    ActiveToolRecordV2, ArgumentNameV2, AttemptKindV2, BoundedConnectorRetryPolicyV2, G4Error,
    KernelValueV2, ResolvedStoredTokenV2, VerifiedStoredBindingsV2,
};

const MAX_ACTION_INTENTS: usize = 4_096;
const MAX_REPLAY_RECORDS: usize = 65_536;
const MAX_CANONICAL_REQUEST_BYTES: usize = 8 * 1024 * 1024;
const SEMANTIC_BINDING_DOMAIN: &[u8] = b"SAVANA_TOOL_EXECUTION_SEMANTIC_BINDING_V2\0";
const ACTION_INTENT_DOMAIN: &[u8] = b"SAVANA_ACTION_INTENT_V2\0";
const REQUEST_DIGEST_DOMAIN: &[u8] = b"SAVANA_REQUEST_V2\0";
const ACTION_MATERIAL_DOMAIN: &[u8] = b"SAVANA_ACTION_INTENT_MATERIAL_V2\0";
const TOOL_APPROVAL_BINDING_DOMAIN: &[u8] = b"SAVANA_TOOL_APPROVAL_BINDING_V2\0";
const DESTINATION_DIGEST_DOMAIN: &[u8] = b"SAVANA_DESTINATION_V2\0";
const DISPLAY_DIGEST_DOMAIN: &[u8] = b"SAVANA_DISPLAY_V2\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct VerifiedProposalRequestDigestV2(Digest32V2);

impl VerifiedProposalRequestDigestV2 {
    pub(crate) fn from_authenticated_canonical_request(
        exact_canonical_request_bytes: &[u8],
    ) -> Result<Self, G4Error> {
        if exact_canonical_request_bytes.is_empty()
            || exact_canonical_request_bytes.len() > MAX_CANONICAL_REQUEST_BYTES
        {
            return Err(G4Error::InvalidIntentBinding);
        }
        Ok(Self(domain_hash(
            REQUEST_DIGEST_DOMAIN,
            exact_canonical_request_bytes,
        )))
    }

    const fn digest(self) -> Digest32V2 {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct VerifiedToolProposalV2 {
    pub(crate) request_id: RequestIdV2,
    pub(crate) proposal_request_digest: VerifiedProposalRequestDigestV2,
    pub(crate) installation_id: Digest32V2,
    pub(crate) active_state_manifest_digest: Digest32V2,
    pub(crate) durable_run_id: DurableRunIdV2,
    pub(crate) durable_task_id: DurableTaskIdV2,
    pub(crate) action_material_digest: Digest32V2,
}

impl VerifiedToolProposalV2 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_authenticated_decoded_request(
        request_id: RequestIdV2,
        authenticated_canonical_request: &[u8],
        installation_id: Digest32V2,
        active_state_manifest_digest: Digest32V2,
        durable_run_id: DurableRunIdV2,
        durable_task_id: DurableTaskIdV2,
        material: &VerifiedActionIntentMaterialV2,
    ) -> Result<Self, G4Error> {
        if is_zero(request_id.as_bytes())
            || is_zero(installation_id.as_bytes())
            || is_zero(active_state_manifest_digest.as_bytes())
            || is_zero(durable_run_id.as_bytes())
            || is_zero(durable_task_id.as_bytes())
        {
            return Err(G4Error::InvalidIntentBinding);
        }
        Ok(Self {
            request_id,
            proposal_request_digest:
                VerifiedProposalRequestDigestV2::from_authenticated_canonical_request(
                    authenticated_canonical_request,
                )?,
            installation_id,
            active_state_manifest_digest,
            durable_run_id,
            durable_task_id,
            action_material_digest: action_intent_material_digest_v2(material)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolExecutionSemanticBindingV2 {
    pub(crate) plan_revision_digest: PlanRevisionDigestV2,
    pub(crate) internal_step_id: InternalStepIdV2,
    pub(crate) tool_descriptor_digest: Digest32V2,
    pub(crate) argument_digest: Digest32V2,
    pub(crate) provenance_set_digest: Digest32V2,
    pub(crate) token_set_digest: Digest32V2,
    pub(crate) destination_digest: Digest32V2,
    pub(crate) display_projection_digest: Digest32V2,
    pub(crate) display_digest: Digest32V2,
    pub(crate) executor_identity_digest: Digest32V2,
    pub(crate) attempt_kind: AttemptKindV2,
}

impl ToolExecutionSemanticBindingV2 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_verified_authorization(
        plan_revision_digest: PlanRevisionDigestV2,
        internal_step_id: InternalStepIdV2,
        tool_descriptor_digest: Digest32V2,
        argument_digest: Digest32V2,
        provenance_set_digest: Digest32V2,
        token_set_digest: Digest32V2,
        destination_digest: Digest32V2,
        display_projection_digest: Digest32V2,
        display_digest: Digest32V2,
        executor_identity: ExecutorIdentityV2,
        attempt_kind: AttemptKindV2,
    ) -> Result<Self, G4Error> {
        let executor_identity_digest = Digest32V2::new(*executor_identity.as_bytes());
        if is_zero(plan_revision_digest.as_bytes())
            || is_zero(internal_step_id.as_bytes())
            || [
                tool_descriptor_digest,
                argument_digest,
                provenance_set_digest,
                token_set_digest,
                destination_digest,
                display_projection_digest,
                display_digest,
                executor_identity_digest,
            ]
            .iter()
            .any(|digest| is_zero(digest.as_bytes()))
        {
            return Err(G4Error::InvalidIntentBinding);
        }
        Ok(Self {
            plan_revision_digest,
            internal_step_id,
            tool_descriptor_digest,
            argument_digest,
            provenance_set_digest,
            token_set_digest,
            destination_digest,
            display_projection_digest,
            display_digest,
            executor_identity_digest,
            attempt_kind,
        })
    }

    pub const fn plan_revision_digest(&self) -> PlanRevisionDigestV2 {
        self.plan_revision_digest
    }

    pub const fn internal_step_id(&self) -> InternalStepIdV2 {
        self.internal_step_id
    }

    pub const fn tool_descriptor_digest(&self) -> Digest32V2 {
        self.tool_descriptor_digest
    }

    pub const fn argument_digest(&self) -> Digest32V2 {
        self.argument_digest
    }

    pub const fn provenance_set_digest(&self) -> Digest32V2 {
        self.provenance_set_digest
    }

    pub const fn token_set_digest(&self) -> Digest32V2 {
        self.token_set_digest
    }

    pub const fn destination_digest(&self) -> Digest32V2 {
        self.destination_digest
    }

    pub const fn display_projection_digest(&self) -> Digest32V2 {
        self.display_projection_digest
    }

    pub const fn display_digest(&self) -> Digest32V2 {
        self.display_digest
    }

    pub const fn executor_identity_digest(&self) -> Digest32V2 {
        self.executor_identity_digest
    }

    pub const fn attempt_kind(&self) -> AttemptKindV2 {
        self.attempt_kind
    }
}

impl<C> minicbor::Encode<C> for ToolExecutionSemanticBindingV2 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        encoder.array(11)?;
        self.plan_revision_digest.encode(encoder, context)?;
        self.internal_step_id.encode(encoder, context)?;
        self.tool_descriptor_digest.encode(encoder, context)?;
        self.argument_digest.encode(encoder, context)?;
        self.provenance_set_digest.encode(encoder, context)?;
        self.token_set_digest.encode(encoder, context)?;
        self.destination_digest.encode(encoder, context)?;
        self.display_projection_digest.encode(encoder, context)?;
        self.display_digest.encode(encoder, context)?;
        self.executor_identity_digest.encode(encoder, context)?;
        self.attempt_kind.encode(encoder, context)?;
        Ok(())
    }
}

pub fn tool_execution_semantic_binding_digest_v2(
    binding: &ToolExecutionSemanticBindingV2,
) -> Result<Digest32V2, G4Error> {
    let canonical = minicbor::to_vec(binding).map_err(|_| G4Error::BindingDigestFailure)?;
    Ok(domain_hash(SEMANTIC_BINDING_DOMAIN, &canonical))
}

pub fn action_intent_id_v2(
    installation_id: Digest32V2,
    active_state_manifest_digest: Digest32V2,
    durable_run_id: DurableRunIdV2,
    durable_task_id: DurableTaskIdV2,
    binding: &ToolExecutionSemanticBindingV2,
) -> Result<ActionIntentIdV2, G4Error> {
    if [
        installation_id,
        active_state_manifest_digest,
        Digest32V2::new(*durable_run_id.as_bytes()),
        Digest32V2::new(*durable_task_id.as_bytes()),
    ]
    .iter()
    .any(|digest| is_zero(digest.as_bytes()))
    {
        return Err(G4Error::InvalidIntentBinding);
    }
    let binding_digest = tool_execution_semantic_binding_digest_v2(binding)?;
    let mut hasher = Sha256::new();
    hasher.update(ACTION_INTENT_DOMAIN);
    hasher.update(installation_id.as_bytes());
    hasher.update(active_state_manifest_digest.as_bytes());
    hasher.update(durable_run_id.as_bytes());
    hasher.update(durable_task_id.as_bytes());
    hasher.update(binding_digest.as_bytes());
    Ok(ActionIntentIdV2::new(hasher.finalize().into()))
}

pub fn tool_approval_binding_digest_v2(
    action_intent_id: ActionIntentIdV2,
    semantic_binding_digest: Digest32V2,
    active_state_manifest_digest: Digest32V2,
) -> Result<Digest32V2, G4Error> {
    if is_zero(action_intent_id.as_bytes())
        || is_zero(semantic_binding_digest.as_bytes())
        || is_zero(active_state_manifest_digest.as_bytes())
    {
        return Err(G4Error::InvalidIntentBinding);
    }
    let mut hasher = Sha256::new();
    hasher.update(TOOL_APPROVAL_BINDING_DOMAIN);
    hasher.update(action_intent_id.as_bytes());
    hasher.update(semantic_binding_digest.as_bytes());
    hasher.update(active_state_manifest_digest.as_bytes());
    Ok(Digest32V2::new(hasher.finalize().into()))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StableActionArgumentBindingV2 {
    pub(crate) argument_name: ArgumentNameV2,
    pub(crate) internal_slot_digest: InternalSlotDigestV2,
    pub(crate) value_internal_id: ValueInternalIdV2,
    pub(crate) value_digest: Digest32V2,
    pub(crate) provenance_digest: Digest32V2,
}

impl StableActionArgumentBindingV2 {
    pub const fn argument_name(&self) -> &ArgumentNameV2 {
        &self.argument_name
    }

    pub const fn internal_slot_digest(&self) -> InternalSlotDigestV2 {
        self.internal_slot_digest
    }

    pub const fn value_internal_id(&self) -> ValueInternalIdV2 {
        self.value_internal_id
    }

    pub const fn value_digest(&self) -> Digest32V2 {
        self.value_digest
    }

    pub const fn provenance_digest(&self) -> Digest32V2 {
        self.provenance_digest
    }

    #[cfg(test)]
    pub(super) const fn new_for_test(
        argument_name: ArgumentNameV2,
        internal_slot_digest: InternalSlotDigestV2,
        value_internal_id: ValueInternalIdV2,
        value_digest: Digest32V2,
        provenance_digest: Digest32V2,
    ) -> Self {
        Self {
            argument_name,
            internal_slot_digest,
            value_internal_id,
            value_digest,
            provenance_digest,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedProjectionOutputsV2 {
    pub(crate) tool_descriptor_digest: Digest32V2,
    pub(crate) destination_projection: ProjectionIdV2,
    pub(crate) destination_projection_digest: Digest32V2,
    pub(crate) destination_canonical: Zeroizing<Vec<u8>>,
    pub(crate) destination_digest: Digest32V2,
    pub(crate) display_projection: DisplayProjectionIdV2,
    pub(crate) display_projection_digest: Digest32V2,
    pub(crate) display_canonical: Zeroizing<Vec<u8>>,
    pub(crate) display_digest: Digest32V2,
}

impl VerifiedProjectionOutputsV2 {
    pub fn from_verified_projection(
        active_tool: &ActiveToolRecordV2,
        projected_destination: &KernelValueV2,
        projected_display: &KernelValueV2,
    ) -> Result<Self, G4Error> {
        let descriptor = active_tool.descriptor();
        Self::from_descriptor_projection(
            descriptor.descriptor_digest(),
            descriptor.unsigned().destination_projection(),
            descriptor.unsigned().destination_projection_digest(),
            descriptor.unsigned().display_projection(),
            descriptor.unsigned().display_projection_digest(),
            projected_destination,
            projected_display,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn from_descriptor_projection(
        tool_descriptor_digest: Digest32V2,
        destination_projection: ProjectionIdV2,
        destination_projection_digest: Digest32V2,
        display_projection: DisplayProjectionIdV2,
        display_projection_digest: Digest32V2,
        projected_destination: &KernelValueV2,
        projected_display: &KernelValueV2,
    ) -> Result<Self, G4Error> {
        if is_zero(tool_descriptor_digest.as_bytes())
            || destination_projection.get() == 0
            || display_projection.get() == 0
            || is_zero(destination_projection_digest.as_bytes())
            || is_zero(display_projection_digest.as_bytes())
            || projected_destination.contains_internal_slot()
            || projected_display.contains_internal_slot()
        {
            return Err(G4Error::InvalidProjectionBinding);
        }
        let destination_canonical =
            minicbor::to_vec(projected_destination).map_err(|_| G4Error::BindingDigestFailure)?;
        let display_canonical =
            minicbor::to_vec(projected_display).map_err(|_| G4Error::BindingDigestFailure)?;
        let destination_digest = projection_output_digest(
            DESTINATION_DIGEST_DOMAIN,
            destination_projection_digest,
            &destination_canonical,
        );
        let display_digest = projection_output_digest(
            DISPLAY_DIGEST_DOMAIN,
            display_projection_digest,
            &display_canonical,
        );
        Ok(Self {
            tool_descriptor_digest,
            destination_projection,
            destination_projection_digest,
            destination_canonical: Zeroizing::new(destination_canonical),
            destination_digest,
            display_projection,
            display_projection_digest,
            display_canonical: Zeroizing::new(display_canonical),
            display_digest,
        })
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new_for_test(
        tool_descriptor_digest: Digest32V2,
        destination_projection: ProjectionIdV2,
        destination_projection_digest: Digest32V2,
        display_projection: DisplayProjectionIdV2,
        display_projection_digest: Digest32V2,
        projected_destination: &KernelValueV2,
        projected_display: &KernelValueV2,
    ) -> Result<Self, G4Error> {
        Self::from_descriptor_projection(
            tool_descriptor_digest,
            destination_projection,
            destination_projection_digest,
            display_projection,
            display_projection_digest,
            projected_destination,
            projected_display,
        )
    }

    pub const fn destination_projection(&self) -> ProjectionIdV2 {
        self.destination_projection
    }

    pub const fn destination_projection_digest(&self) -> Digest32V2 {
        self.destination_projection_digest
    }

    pub const fn destination_digest(&self) -> Digest32V2 {
        self.destination_digest
    }

    pub(crate) fn destination_canonical(&self) -> &[u8] {
        &self.destination_canonical
    }

    pub const fn display_projection(&self) -> DisplayProjectionIdV2 {
        self.display_projection
    }

    pub const fn display_projection_digest(&self) -> Digest32V2 {
        self.display_projection_digest
    }

    pub const fn display_digest(&self) -> Digest32V2 {
        self.display_digest
    }

    pub(crate) fn display_canonical(&self) -> &[u8] {
        &self.display_canonical
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedActionIntentMaterialV2 {
    pub(crate) binding: ToolExecutionSemanticBindingV2,
    pub(crate) selected_descriptor_canonical: Vec<u8>,
    pub(crate) descriptor_publisher_key_id: Ed25519KeyIdV2,
    pub(crate) registry_ordinal: u32,
    pub(crate) policy_activation_digest: Digest32V2,
    pub(crate) effective_retry_policy: BoundedConnectorRetryPolicyV2,
    pub(crate) normalized_arguments: Vec<StableActionArgumentBindingV2>,
    pub(crate) token_bindings: Vec<ResolvedStoredTokenV2>,
    pub(crate) projection_outputs: VerifiedProjectionOutputsV2,
}

impl VerifiedActionIntentMaterialV2 {
    pub fn from_verified_g4(
        plan_revision_digest: PlanRevisionDigestV2,
        internal_step_id: InternalStepIdV2,
        active_tool: &ActiveToolRecordV2,
        stored_bindings: &VerifiedStoredBindingsV2<'_>,
        projection_outputs: VerifiedProjectionOutputsV2,
    ) -> Result<Self, G4Error> {
        let descriptor = active_tool.descriptor();
        let unsigned = descriptor.unsigned();
        let executor_identity_digest = Digest32V2::new(*unsigned.executor_identity().as_bytes());
        if projection_outputs.tool_descriptor_digest != descriptor.descriptor_digest()
            || projection_outputs.destination_projection != unsigned.destination_projection()
            || projection_outputs.destination_projection_digest
                != unsigned.destination_projection_digest()
            || projection_outputs.display_projection != unsigned.display_projection()
            || projection_outputs.display_projection_digest != unsigned.display_projection_digest()
            || stored_bindings.executor_identity_digest() != executor_identity_digest
        {
            return Err(G4Error::InvalidIntentBinding);
        }

        let mut normalized_arguments = Vec::new();
        normalized_arguments
            .try_reserve_exact(stored_bindings.arguments().len())
            .map_err(|_| G4Error::AllocationFailure)?;
        for argument in stored_bindings.arguments() {
            normalized_arguments.push(StableActionArgumentBindingV2 {
                argument_name: argument.argument_name().clone(),
                internal_slot_digest: argument.internal_slot_digest(),
                value_internal_id: argument.value_internal_id(),
                value_digest: argument.value_digest(),
                provenance_digest: argument.provenance_digest(),
            });
        }

        let selected_descriptor_canonical =
            minicbor::to_vec(unsigned).map_err(|_| G4Error::NonCanonicalDescriptor)?;
        let binding = ToolExecutionSemanticBindingV2::from_verified_authorization(
            plan_revision_digest,
            internal_step_id,
            descriptor.descriptor_digest(),
            stored_bindings.argument_digest(),
            stored_bindings.provenance_set_digest(),
            stored_bindings.token_set_digest(),
            projection_outputs.destination_digest,
            projection_outputs.display_projection_digest,
            projection_outputs.display_digest,
            unsigned.executor_identity(),
            unsigned.attempt_kind(),
        )?;
        Ok(Self {
            binding,
            selected_descriptor_canonical,
            descriptor_publisher_key_id: descriptor.publisher_key_id(),
            registry_ordinal: active_tool.registry_ordinal(),
            policy_activation_digest: active_tool.policy_activation_digest(),
            effective_retry_policy: active_tool.effective_retry_policy(),
            normalized_arguments,
            token_bindings: stored_bindings.tokens().to_vec(),
            projection_outputs,
        })
    }

    #[cfg(test)]
    pub(crate) fn new_for_test(
        binding: ToolExecutionSemanticBindingV2,
        normalized_arguments: Vec<StableActionArgumentBindingV2>,
        seed: u8,
    ) -> Self {
        Self::new_for_test_with_validators(binding, normalized_arguments, seed, Vec::new())
    }

    #[cfg(test)]
    pub(crate) fn new_for_test_with_validators(
        mut binding: ToolExecutionSemanticBindingV2,
        normalized_arguments: Vec<StableActionArgumentBindingV2>,
        seed: u8,
        internal_validators: Vec<super::InternalValidatorDeclarationV2>,
    ) -> Self {
        use savana_kernel_protocol::v2::{
            ActionTemplateIdV2, DisplayProjectionIdV2, ProjectionIdV2, RoleIdV2, ToolClassIdV2,
            UnixMillisV2, VersionV2,
        };

        use super::digest::{
            argument_digest_v2, provenance_set_digest_v2, token_set_digest_v2,
            ArgumentDigestEntryV2, ProvenanceSetDigestEntryV2,
        };

        let argument_entries = normalized_arguments
            .iter()
            .map(|argument| {
                ArgumentDigestEntryV2::new(
                    argument.argument_name.clone(),
                    argument.value_internal_id,
                    argument.value_digest,
                    argument.provenance_digest,
                )
            })
            .collect::<Vec<_>>();
        let mut provenance_entries = normalized_arguments
            .iter()
            .map(|argument| {
                ProvenanceSetDigestEntryV2::new(
                    argument.value_internal_id,
                    argument.value_digest,
                    argument.provenance_digest,
                )
            })
            .collect::<Vec<_>>();
        provenance_entries.sort_unstable_by(|left, right| {
            minicbor::to_vec(left)
                .unwrap()
                .cmp(&minicbor::to_vec(right).unwrap())
        });
        binding.argument_digest = argument_digest_v2(&argument_entries).unwrap();
        binding.provenance_set_digest =
            provenance_set_digest_v2(&argument_entries, &provenance_entries).unwrap();
        binding.token_set_digest = token_set_digest_v2(&[]).unwrap();

        let destination_projection_digest = Digest32V2::new([0x21; 32]);
        let unsigned = super::UnsignedToolDescriptorV2::from_verified_manifest(
            2,
            VersionV2::new(1, 0, 0),
            Digest32V2::new([0x22; 32]),
            super::IdentifierV2::new("test.tool").unwrap(),
            ActionTemplateIdV2::new(1),
            ToolClassIdV2::new(1),
            Digest32V2::new([0x23; 32]),
            Digest32V2::new([0x24; 32]),
            vec![RoleIdV2::new(1)],
            super::EffectSetV2::SEND,
            binding.attempt_kind,
            BoundedConnectorRetryPolicyV2::new(
                super::ExecutorIdempotencyContractV2::ConnectorNonIdempotentSingleAttempt,
                1,
                0,
            )
            .unwrap(),
            internal_validators,
            ExecutorIdentityV2::new(*binding.executor_identity_digest.as_bytes()),
            ProjectionIdV2::new(1),
            destination_projection_digest,
            DisplayProjectionIdV2::new(1),
            binding.display_projection_digest,
            super::ExecutorIdempotencyContractV2::ConnectorNonIdempotentSingleAttempt,
            UnixMillisV2::new(1),
            UnixMillisV2::new(1_000),
        )
        .unwrap();
        let selected_descriptor_canonical = minicbor::to_vec(&unsigned).unwrap();
        binding.tool_descriptor_digest = super::descriptor_digest_v2(&unsigned).unwrap();
        let destination = KernelValueV2::text(format!("destination-{seed}")).unwrap();
        let display = KernelValueV2::text(format!("display-{seed}")).unwrap();
        let projection_outputs = VerifiedProjectionOutputsV2::from_descriptor_projection(
            binding.tool_descriptor_digest,
            ProjectionIdV2::new(1),
            destination_projection_digest,
            DisplayProjectionIdV2::new(1),
            binding.display_projection_digest,
            &destination,
            &display,
        )
        .unwrap();
        binding.destination_digest = projection_outputs.destination_digest;
        binding.display_digest = projection_outputs.display_digest;
        Self {
            projection_outputs,
            selected_descriptor_canonical,
            descriptor_publisher_key_id: Ed25519KeyIdV2::new([seed; 32]),
            registry_ordinal: u32::from(seed),
            policy_activation_digest: Digest32V2::new([seed.wrapping_add(1); 32]),
            effective_retry_policy: BoundedConnectorRetryPolicyV2::new(
                super::ExecutorIdempotencyContractV2::ConnectorNonIdempotentSingleAttempt,
                1,
                0,
            )
            .unwrap(),
            token_bindings: Vec::new(),
            normalized_arguments,
            binding,
        }
    }

    pub const fn binding(&self) -> &ToolExecutionSemanticBindingV2 {
        &self.binding
    }

    pub fn selected_descriptor_canonical(&self) -> &[u8] {
        &self.selected_descriptor_canonical
    }

    pub fn normalized_arguments(&self) -> &[StableActionArgumentBindingV2] {
        &self.normalized_arguments
    }

    pub fn token_bindings(&self) -> &[ResolvedStoredTokenV2] {
        &self.token_bindings
    }

    pub const fn projection_outputs(&self) -> &VerifiedProjectionOutputsV2 {
        &self.projection_outputs
    }
}

pub(crate) fn action_intent_material_digest_v2(
    material: &VerifiedActionIntentMaterialV2,
) -> Result<Digest32V2, G4Error> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(9)
        .map_err(|_| G4Error::BindingDigestFailure)?;
    material
        .binding
        .encode(&mut encoder, &mut ())
        .map_err(|_| G4Error::BindingDigestFailure)?;
    encoder
        .bytes(&material.selected_descriptor_canonical)
        .map_err(|_| G4Error::BindingDigestFailure)?;
    material
        .descriptor_publisher_key_id
        .encode(&mut encoder, &mut ())
        .map_err(|_| G4Error::BindingDigestFailure)?;
    encoder
        .u32(material.registry_ordinal)
        .map_err(|_| G4Error::BindingDigestFailure)?;
    material
        .policy_activation_digest
        .encode(&mut encoder, &mut ())
        .map_err(|_| G4Error::BindingDigestFailure)?;
    material
        .effective_retry_policy
        .encode(&mut encoder, &mut ())
        .map_err(|_| G4Error::BindingDigestFailure)?;
    encoder
        .array(material.normalized_arguments.len() as u64)
        .map_err(|_| G4Error::BindingDigestFailure)?;
    for argument in &material.normalized_arguments {
        encoder
            .array(5)
            .map_err(|_| G4Error::BindingDigestFailure)?;
        argument
            .argument_name
            .encode(&mut encoder, &mut ())
            .map_err(|_| G4Error::BindingDigestFailure)?;
        argument
            .internal_slot_digest
            .encode(&mut encoder, &mut ())
            .map_err(|_| G4Error::BindingDigestFailure)?;
        argument
            .value_internal_id
            .encode(&mut encoder, &mut ())
            .map_err(|_| G4Error::BindingDigestFailure)?;
        argument
            .value_digest
            .encode(&mut encoder, &mut ())
            .map_err(|_| G4Error::BindingDigestFailure)?;
        argument
            .provenance_digest
            .encode(&mut encoder, &mut ())
            .map_err(|_| G4Error::BindingDigestFailure)?;
    }
    encoder
        .array(material.token_bindings.len() as u64)
        .map_err(|_| G4Error::BindingDigestFailure)?;
    for token in &material.token_bindings {
        encoder
            .array(4)
            .map_err(|_| G4Error::BindingDigestFailure)?;
        token
            .token_slot_id
            .encode(&mut encoder, &mut ())
            .map_err(|_| G4Error::BindingDigestFailure)?;
        token
            .vault_segment_internal_id
            .encode(&mut encoder, &mut ())
            .map_err(|_| G4Error::BindingDigestFailure)?;
        token
            .credential_version_digest
            .encode(&mut encoder, &mut ())
            .map_err(|_| G4Error::BindingDigestFailure)?;
        token
            .executor_identity_digest
            .encode(&mut encoder, &mut ())
            .map_err(|_| G4Error::BindingDigestFailure)?;
    }
    let projection = &material.projection_outputs;
    encoder
        .array(9)
        .map_err(|_| G4Error::BindingDigestFailure)?;
    projection
        .tool_descriptor_digest
        .encode(&mut encoder, &mut ())
        .map_err(|_| G4Error::BindingDigestFailure)?;
    projection
        .destination_projection
        .encode(&mut encoder, &mut ())
        .map_err(|_| G4Error::BindingDigestFailure)?;
    projection
        .destination_projection_digest
        .encode(&mut encoder, &mut ())
        .map_err(|_| G4Error::BindingDigestFailure)?;
    encoder
        .bytes(projection.destination_canonical())
        .map_err(|_| G4Error::BindingDigestFailure)?;
    projection
        .destination_digest
        .encode(&mut encoder, &mut ())
        .map_err(|_| G4Error::BindingDigestFailure)?;
    projection
        .display_projection
        .encode(&mut encoder, &mut ())
        .map_err(|_| G4Error::BindingDigestFailure)?;
    projection
        .display_projection_digest
        .encode(&mut encoder, &mut ())
        .map_err(|_| G4Error::BindingDigestFailure)?;
    encoder
        .bytes(projection.display_canonical())
        .map_err(|_| G4Error::BindingDigestFailure)?;
    projection
        .display_digest
        .encode(&mut encoder, &mut ())
        .map_err(|_| G4Error::BindingDigestFailure)?;
    let canonical = Zeroizing::new(encoder.into_writer());
    Ok(domain_hash(ACTION_MATERIAL_DOMAIN, canonical.as_slice()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ActionIntentStateV2 {
    Proposed,
    Evaluating,
    Denied,
    NeedsApproval,
    AuthorizedApproval,
    AuthorizedPolicy,
    DispatchPrepared,
    Dispatching,
    FailedNoEffect,
    Indeterminate,
    ResultGatePending,
    Succeeded,
    EffectSucceededOutputQuarantined,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PendingCallStateV2 {
    Evaluating,
    AwaitingApproval,
    Authorized,
    DispatchPrepared,
    Dispatching,
    ResultGatePending,
    TerminalDenied,
    TerminalFailedNoEffect,
    TerminalIndeterminate,
    TerminalSucceeded,
    TerminalOutputQuarantined,
}

impl PendingCallStateV2 {
    pub const fn tag(self) -> u16 {
        match self {
            Self::Evaluating => 1,
            Self::AwaitingApproval => 2,
            Self::Authorized => 3,
            Self::DispatchPrepared => 4,
            Self::Dispatching => 5,
            Self::ResultGatePending => 6,
            Self::TerminalDenied => 7,
            Self::TerminalFailedNoEffect => 8,
            Self::TerminalIndeterminate => 9,
            Self::TerminalSucceeded => 10,
            Self::TerminalOutputQuarantined => 11,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PublicTaskStateV2 {
    Evaluating,
    AwaitingApproval,
    Authorized,
    Executing,
    Failed,
    Indeterminate,
    Succeeded,
    OutputQuarantined,
}

impl PublicTaskStateV2 {
    pub const fn tag(self) -> u16 {
        match self {
            Self::Evaluating => 1,
            Self::AwaitingApproval => 2,
            Self::Authorized => 3,
            Self::Executing => 4,
            Self::Failed => 5,
            Self::Indeterminate => 6,
            Self::Succeeded => 7,
            Self::OutputQuarantined => 8,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingCallStateRecordV2 {
    pub(crate) action_intent_id: ActionIntentIdV2,
    pub(crate) state: PendingCallStateV2,
}

impl PendingCallStateRecordV2 {
    pub const fn action_intent_id(self) -> ActionIntentIdV2 {
        self.action_intent_id
    }

    pub const fn state(self) -> PendingCallStateV2 {
        self.state
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicTaskStateRecordV2 {
    pub(crate) durable_task_id: DurableTaskIdV2,
    pub(crate) action_intent_id: ActionIntentIdV2,
    pub(crate) state: PublicTaskStateV2,
}

impl PublicTaskStateRecordV2 {
    pub const fn durable_task_id(self) -> DurableTaskIdV2 {
        self.durable_task_id
    }

    pub const fn action_intent_id(self) -> ActionIntentIdV2 {
        self.action_intent_id
    }

    pub const fn state(self) -> PublicTaskStateV2 {
        self.state
    }
}

impl ActionIntentStateV2 {
    pub const fn tag(self) -> u16 {
        match self {
            Self::Proposed => 1,
            Self::Evaluating => 2,
            Self::Denied => 3,
            Self::NeedsApproval => 4,
            Self::AuthorizedApproval => 5,
            Self::AuthorizedPolicy => 6,
            Self::DispatchPrepared => 7,
            Self::Dispatching => 8,
            Self::FailedNoEffect => 9,
            Self::Indeterminate => 10,
            Self::ResultGatePending => 11,
            Self::Succeeded => 12,
            Self::EffectSucceededOutputQuarantined => 13,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionIntentRecordV2 {
    pub(crate) action_intent_id: ActionIntentIdV2,
    pub(crate) installation_id: Digest32V2,
    pub(crate) active_state_manifest_digest: Digest32V2,
    pub(crate) durable_run_id: DurableRunIdV2,
    pub(crate) durable_task_id: DurableTaskIdV2,
    pub(crate) stable_proposal_digest: Digest32V2,
    pub(crate) semantic_binding_digest: Digest32V2,
    pub(crate) material: VerifiedActionIntentMaterialV2,
    pub(crate) pending_call_state: PendingCallStateRecordV2,
    pub(crate) public_task_state: PublicTaskStateRecordV2,
}

impl ActionIntentRecordV2 {
    pub const fn action_intent_id(&self) -> ActionIntentIdV2 {
        self.action_intent_id
    }

    pub const fn binding(&self) -> &ToolExecutionSemanticBindingV2 {
        self.material.binding()
    }

    pub const fn material(&self) -> &VerifiedActionIntentMaterialV2 {
        &self.material
    }

    pub const fn pending_call_state(&self) -> PendingCallStateRecordV2 {
        self.pending_call_state
    }

    pub const fn public_task_state(&self) -> PublicTaskStateRecordV2 {
        self.public_task_state
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionIntentResolutionKindV2 {
    Created,
    Replay,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActionIntentResolutionV2 {
    action_intent_id: ActionIntentIdV2,
    current_state: ActionIntentStateV2,
    kind: ActionIntentResolutionKindV2,
}

impl ActionIntentResolutionV2 {
    pub const fn action_intent_id(self) -> ActionIntentIdV2 {
        self.action_intent_id
    }

    pub const fn current_state(self) -> ActionIntentStateV2 {
        self.current_state
    }

    pub const fn kind(self) -> ActionIntentResolutionKindV2 {
        self.kind
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ActionIntentEntryV2 {
    pub(crate) record: ActionIntentRecordV2,
    pub(crate) current_state: ActionIntentStateV2,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct IntentReplayEntryV2 {
    pub(crate) request_id: RequestIdV2,
    pub(crate) stable_proposal_digest: Digest32V2,
    pub(crate) action_intent_id: ActionIntentIdV2,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct ActionIntentIndexV2 {
    pub(crate) intents: Vec<ActionIntentEntryV2>,
    pub(crate) replay: Vec<IntentReplayEntryV2>,
}

impl ActionIntentIndexV2 {
    pub const fn new() -> Self {
        Self {
            intents: Vec::new(),
            replay: Vec::new(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn create_or_replay(
        &mut self,
        request_id: RequestIdV2,
        proposal_request_digest: VerifiedProposalRequestDigestV2,
        installation_id: Digest32V2,
        active_state_manifest_digest: Digest32V2,
        durable_run_id: DurableRunIdV2,
        durable_task_id: DurableTaskIdV2,
        material: VerifiedActionIntentMaterialV2,
    ) -> Result<ActionIntentResolutionV2, G4Error> {
        let binding = material.binding();
        let semantic_binding_digest = tool_execution_semantic_binding_digest_v2(binding)?;
        let action_intent_id = action_intent_id_v2(
            installation_id,
            active_state_manifest_digest,
            durable_run_id,
            durable_task_id,
            binding,
        )?;
        let stable_proposal_digest = proposal_request_digest.digest();

        if let Some(replay) = self
            .replay
            .iter()
            .find(|entry| entry.request_id == request_id)
        {
            let entry = self
                .intents
                .iter()
                .find(|entry| entry.record.action_intent_id == replay.action_intent_id)
                .ok_or(G4Error::IntentNotFound)?;
            if replay.stable_proposal_digest != stable_proposal_digest
                || entry.record.installation_id != installation_id
                || entry.record.active_state_manifest_digest != active_state_manifest_digest
                || entry.record.durable_run_id != durable_run_id
                || entry.record.durable_task_id != durable_task_id
                || entry.record.semantic_binding_digest != semantic_binding_digest
                || entry.record.material != material
                || entry.record.action_intent_id != action_intent_id
            {
                return Err(G4Error::IdempotencyConflict);
            }
            return Ok(resolution(entry, ActionIntentResolutionKindV2::Replay));
        }

        if let Some(entry) = self.intents.iter().find(|entry| {
            entry.record.durable_run_id == durable_run_id
                && entry.record.material.binding.plan_revision_digest
                    == binding.plan_revision_digest
                && entry.record.material.binding.internal_step_id == binding.internal_step_id
        }) {
            if entry.record.installation_id != installation_id
                || entry.record.active_state_manifest_digest != active_state_manifest_digest
                || entry.record.durable_task_id != durable_task_id
                || entry.record.stable_proposal_digest != stable_proposal_digest
                || entry.record.semantic_binding_digest != semantic_binding_digest
                || entry.record.material != material
                || entry.record.action_intent_id != action_intent_id
            {
                return Err(G4Error::StateConflict);
            }
            if self.replay.len() >= MAX_REPLAY_RECORDS {
                return Err(G4Error::IntentLimitExceeded);
            }
            self.replay
                .try_reserve(1)
                .map_err(|_| G4Error::AllocationFailure)?;
            let result = resolution(entry, ActionIntentResolutionKindV2::Replay);
            self.replay.push(IntentReplayEntryV2 {
                request_id,
                stable_proposal_digest,
                action_intent_id,
            });
            return Ok(result);
        }

        if self.intents.len() >= MAX_ACTION_INTENTS || self.replay.len() >= MAX_REPLAY_RECORDS {
            return Err(G4Error::IntentLimitExceeded);
        }
        self.intents
            .try_reserve(1)
            .map_err(|_| G4Error::AllocationFailure)?;
        self.replay
            .try_reserve(1)
            .map_err(|_| G4Error::AllocationFailure)?;
        let record = ActionIntentRecordV2 {
            action_intent_id,
            installation_id,
            active_state_manifest_digest,
            durable_run_id,
            durable_task_id,
            stable_proposal_digest,
            semantic_binding_digest,
            material,
            pending_call_state: PendingCallStateRecordV2 {
                action_intent_id,
                state: PendingCallStateV2::Evaluating,
            },
            public_task_state: PublicTaskStateRecordV2 {
                durable_task_id,
                action_intent_id,
                state: PublicTaskStateV2::Evaluating,
            },
        };
        self.intents.push(ActionIntentEntryV2 {
            record,
            current_state: ActionIntentStateV2::Proposed,
        });
        self.replay.push(IntentReplayEntryV2 {
            request_id,
            stable_proposal_digest,
            action_intent_id,
        });
        Ok(ActionIntentResolutionV2 {
            action_intent_id,
            current_state: ActionIntentStateV2::Proposed,
            kind: ActionIntentResolutionKindV2::Created,
        })
    }

    #[cfg(test)]
    pub(super) fn advance_for_test(
        &mut self,
        action_intent_id: ActionIntentIdV2,
        state: ActionIntentStateV2,
    ) -> Result<(), G4Error> {
        let entry = self
            .intents
            .iter_mut()
            .find(|entry| entry.record.action_intent_id == action_intent_id)
            .ok_or(G4Error::IntentNotFound)?;
        entry.current_state = state;
        entry.record.pending_call_state = PendingCallStateRecordV2 {
            action_intent_id,
            state: pending_call_state_for_action(state),
        };
        entry.record.public_task_state = PublicTaskStateRecordV2 {
            durable_task_id: entry.record.durable_task_id,
            action_intent_id,
            state: public_task_state_for_action(state),
        };
        Ok(())
    }

    pub(crate) fn advance_verified(
        &mut self,
        action_intent_id: ActionIntentIdV2,
        next_state: ActionIntentStateV2,
    ) -> Result<(), G4Error> {
        let entry = self
            .intents
            .iter_mut()
            .find(|entry| entry.record.action_intent_id == action_intent_id)
            .ok_or(G4Error::IntentNotFound)?;
        if !valid_verified_transition(entry.current_state, next_state) {
            return Err(G4Error::StateConflict);
        }
        entry.current_state = next_state;
        entry.record.pending_call_state = PendingCallStateRecordV2 {
            action_intent_id,
            state: pending_call_state_for_action(next_state),
        };
        entry.record.public_task_state = PublicTaskStateRecordV2 {
            durable_task_id: entry.record.durable_task_id,
            action_intent_id,
            state: public_task_state_for_action(next_state),
        };
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn record_for_test(
        &self,
        action_intent_id: ActionIntentIdV2,
    ) -> Option<&ActionIntentRecordV2> {
        self.intents
            .iter()
            .find(|entry| entry.record.action_intent_id == action_intent_id)
            .map(|entry| &entry.record)
    }

    pub fn intent_count(&self) -> usize {
        self.intents.len()
    }

    pub fn replay_count(&self) -> usize {
        self.replay.len()
    }
}

const fn valid_verified_transition(
    current: ActionIntentStateV2,
    next: ActionIntentStateV2,
) -> bool {
    matches!(
        (current, next),
        (
            ActionIntentStateV2::Proposed,
            ActionIntentStateV2::Evaluating
        ) | (
            ActionIntentStateV2::Evaluating,
            ActionIntentStateV2::Denied
                | ActionIntentStateV2::NeedsApproval
                | ActionIntentStateV2::AuthorizedPolicy
        ) | (
            ActionIntentStateV2::NeedsApproval,
            ActionIntentStateV2::Denied | ActionIntentStateV2::AuthorizedApproval
        ) | (
            ActionIntentStateV2::AuthorizedApproval | ActionIntentStateV2::AuthorizedPolicy,
            ActionIntentStateV2::DispatchPrepared
        ) | (
            ActionIntentStateV2::DispatchPrepared,
            ActionIntentStateV2::Dispatching
                | ActionIntentStateV2::FailedNoEffect
                | ActionIntentStateV2::Indeterminate
        ) | (
            ActionIntentStateV2::Dispatching,
            ActionIntentStateV2::FailedNoEffect
                | ActionIntentStateV2::Indeterminate
                | ActionIntentStateV2::ResultGatePending
                | ActionIntentStateV2::Succeeded
                | ActionIntentStateV2::EffectSucceededOutputQuarantined
        ) | (
            ActionIntentStateV2::ResultGatePending,
            ActionIntentStateV2::Indeterminate
                | ActionIntentStateV2::Succeeded
                | ActionIntentStateV2::EffectSucceededOutputQuarantined
        )
    )
}

const fn pending_call_state_for_action(state: ActionIntentStateV2) -> PendingCallStateV2 {
    match state {
        ActionIntentStateV2::Proposed | ActionIntentStateV2::Evaluating => {
            PendingCallStateV2::Evaluating
        }
        ActionIntentStateV2::Denied => PendingCallStateV2::TerminalDenied,
        ActionIntentStateV2::NeedsApproval => PendingCallStateV2::AwaitingApproval,
        ActionIntentStateV2::AuthorizedApproval | ActionIntentStateV2::AuthorizedPolicy => {
            PendingCallStateV2::Authorized
        }
        ActionIntentStateV2::DispatchPrepared => PendingCallStateV2::DispatchPrepared,
        ActionIntentStateV2::Dispatching => PendingCallStateV2::Dispatching,
        ActionIntentStateV2::FailedNoEffect => PendingCallStateV2::TerminalFailedNoEffect,
        ActionIntentStateV2::Indeterminate => PendingCallStateV2::TerminalIndeterminate,
        ActionIntentStateV2::ResultGatePending => PendingCallStateV2::ResultGatePending,
        ActionIntentStateV2::Succeeded => PendingCallStateV2::TerminalSucceeded,
        ActionIntentStateV2::EffectSucceededOutputQuarantined => {
            PendingCallStateV2::TerminalOutputQuarantined
        }
    }
}

const fn public_task_state_for_action(state: ActionIntentStateV2) -> PublicTaskStateV2 {
    match state {
        ActionIntentStateV2::Proposed | ActionIntentStateV2::Evaluating => {
            PublicTaskStateV2::Evaluating
        }
        ActionIntentStateV2::Denied | ActionIntentStateV2::FailedNoEffect => {
            PublicTaskStateV2::Failed
        }
        ActionIntentStateV2::NeedsApproval => PublicTaskStateV2::AwaitingApproval,
        ActionIntentStateV2::AuthorizedApproval | ActionIntentStateV2::AuthorizedPolicy => {
            PublicTaskStateV2::Authorized
        }
        ActionIntentStateV2::DispatchPrepared
        | ActionIntentStateV2::Dispatching
        | ActionIntentStateV2::ResultGatePending => PublicTaskStateV2::Executing,
        ActionIntentStateV2::Indeterminate => PublicTaskStateV2::Indeterminate,
        ActionIntentStateV2::Succeeded => PublicTaskStateV2::Succeeded,
        ActionIntentStateV2::EffectSucceededOutputQuarantined => {
            PublicTaskStateV2::OutputQuarantined
        }
    }
}

fn resolution(
    entry: &ActionIntentEntryV2,
    kind: ActionIntentResolutionKindV2,
) -> ActionIntentResolutionV2 {
    ActionIntentResolutionV2 {
        action_intent_id: entry.record.action_intent_id,
        current_state: entry.current_state,
        kind,
    }
}

fn domain_hash(domain: &[u8], canonical: &[u8]) -> Digest32V2 {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(canonical);
    Digest32V2::new(hasher.finalize().into())
}

fn is_zero<const N: usize>(bytes: &[u8; N]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

pub(crate) fn projection_output_digest(
    domain: &[u8],
    projection_digest: Digest32V2,
    canonical_output: &[u8],
) -> Digest32V2 {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(projection_digest.as_bytes());
    hasher.update(canonical_output);
    Digest32V2::new(hasher.finalize().into())
}

#[cfg(test)]
#[path = "intent_tests.rs"]
mod tests;
