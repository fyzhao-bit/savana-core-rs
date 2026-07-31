use minicbor::Encode as _;
use savana_kernel_protocol::v2::{
    ActionIntentIdV2, Digest32V2, DurableRunIdV2, ProducerIdentityV2, UnixMillisV2, V2DecodeContext,
};
use sha2::{Digest as _, Sha256};
use unicode_normalization::UnicodeNormalization as _;

use super::leak_gate::{enforce_for_declassification, LeakGateDutyV2};
use super::{
    value_digest_v2, ArgumentNameV2, ConfidentialityV2, EffectSetV2, G3Error, IntegrityV2,
    KernelValueV2, ReaderSetV2, SecurityLabelV2,
};

const MAX_ROOT_EVIDENCE: usize = 64;
const MAX_PROVENANCE_PARENTS: usize = 256;
const MAX_DERIVE_OBJECT_FIELDS: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PolicyConstantIdV2(u32);

impl PolicyConstantIdV2 {
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u32 {
        self.0
    }
}

impl<C> minicbor::Encode<C> for PolicyConstantIdV2 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        _context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        encoder.u32(self.0)?;
        Ok(())
    }
}

impl<'bytes, C> minicbor::Decode<'bytes, C> for PolicyConstantIdV2 {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        _context: &mut C,
    ) -> Result<Self, minicbor::decode::Error> {
        Ok(Self(decoder.u32()?))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DeriveOperationV2(DeriveOperationKindV2);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum DeriveOperationKindV2 {
    ConcatenateText,
    NormalizeNfc,
    SelectObjectField(ArgumentNameV2),
    AssembleList,
    AssembleObject(Vec<ArgumentNameV2>),
    PolicyConstant(PolicyConstantIdV2),
}

impl DeriveOperationV2 {
    pub const fn concatenate_text() -> Self {
        Self(DeriveOperationKindV2::ConcatenateText)
    }

    pub const fn normalize_nfc() -> Self {
        Self(DeriveOperationKindV2::NormalizeNfc)
    }

    pub const fn select_object_field(name: ArgumentNameV2) -> Self {
        Self(DeriveOperationKindV2::SelectObjectField(name))
    }

    pub const fn assemble_list() -> Self {
        Self(DeriveOperationKindV2::AssembleList)
    }

    pub fn assemble_object(fields: Vec<ArgumentNameV2>) -> Result<Self, G3Error> {
        if fields.len() > MAX_DERIVE_OBJECT_FIELDS {
            return Err(G3Error::CollectionLimitExceeded);
        }
        if fields.windows(2).any(|pair| {
            canonical_text_order(pair[0].as_str(), pair[1].as_str()) != std::cmp::Ordering::Less
        }) {
            return Err(G3Error::NonCanonicalOrder);
        }
        Ok(Self(DeriveOperationKindV2::AssembleObject(fields)))
    }

    pub const fn policy_constant(constant_id: PolicyConstantIdV2) -> Self {
        Self(DeriveOperationKindV2::PolicyConstant(constant_id))
    }

    pub const fn tag(&self) -> u16 {
        match &self.0 {
            DeriveOperationKindV2::ConcatenateText => 1,
            DeriveOperationKindV2::NormalizeNfc => 2,
            DeriveOperationKindV2::SelectObjectField(_) => 3,
            DeriveOperationKindV2::AssembleList => 4,
            DeriveOperationKindV2::AssembleObject(_) => 5,
            DeriveOperationKindV2::PolicyConstant(_) => 6,
        }
    }

    fn execute(
        &self,
        parents: &[(&KernelValueV2, &ProvenanceRecordV2)],
    ) -> Result<KernelValueV2, G3Error> {
        match &self.0 {
            DeriveOperationKindV2::ConcatenateText => {
                require_nonempty(parents)?;
                let total_length = parents.iter().try_fold(0_usize, |length, (value, _)| {
                    let text = value.as_text().ok_or(G3Error::DeriveTypeMismatch)?;
                    length
                        .checked_add(text.len())
                        .ok_or(G3Error::ValueEncodedBytesExceeded)
                })?;
                KernelValueV2::validate_text_output_size(total_length)?;
                let mut output = String::new();
                output
                    .try_reserve_exact(total_length)
                    .map_err(|_| G3Error::AllocationFailure)?;
                for (value, _) in parents {
                    output.push_str(value.as_text().ok_or(G3Error::DeriveTypeMismatch)?);
                }
                KernelValueV2::text(output)
            }
            DeriveOperationKindV2::NormalizeNfc => {
                let [(value, _)] = parents else {
                    return Err(G3Error::DeriveArityMismatch);
                };
                let text = value.as_text().ok_or(G3Error::DeriveTypeMismatch)?;
                let normalized_length = text.nfc().try_fold(0_usize, |length, character| {
                    length
                        .checked_add(character.len_utf8())
                        .ok_or(G3Error::ValueEncodedBytesExceeded)
                })?;
                KernelValueV2::validate_text_output_size(normalized_length)?;
                let mut output = String::new();
                output
                    .try_reserve_exact(normalized_length)
                    .map_err(|_| G3Error::AllocationFailure)?;
                output.extend(text.nfc());
                KernelValueV2::text(output)
            }
            DeriveOperationKindV2::SelectObjectField(name) => {
                let [(value, _)] = parents else {
                    return Err(G3Error::DeriveArityMismatch);
                };
                let selected = value
                    .object_field(name.as_str())
                    .ok_or(G3Error::DeriveFieldMissing)?;
                selected.try_clone_internal()
            }
            DeriveOperationKindV2::AssembleList => {
                require_nonempty(parents)?;
                let values = parent_value_refs(parents)?;
                KernelValueV2::list_from_refs(&values)
            }
            DeriveOperationKindV2::AssembleObject(fields) => {
                require_nonempty(parents)?;
                if fields.len() != parents.len() {
                    return Err(G3Error::DeriveArityMismatch);
                }
                let values = parent_value_refs(parents)?;
                KernelValueV2::object_from_refs(fields, &values)
            }
            DeriveOperationKindV2::PolicyConstant(constant_id) => {
                let [(value, provenance)] = parents else {
                    return Err(G3Error::DeriveArityMismatch);
                };
                if !matches!(
                    provenance.source_kind(),
                    SourceKindV2::PolicyConstant {
                        constant_id: parent_id
                    } if parent_id == constant_id
                ) {
                    return Err(G3Error::DeriveTypeMismatch);
                }
                value.try_clone_internal()
            }
        }
    }
}

impl<C> minicbor::Encode<C> for DeriveOperationV2 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        match &self.0 {
            DeriveOperationKindV2::ConcatenateText => {
                encoder.array(1)?.u16(1)?;
            }
            DeriveOperationKindV2::NormalizeNfc => {
                encoder.array(1)?.u16(2)?;
            }
            DeriveOperationKindV2::SelectObjectField(name) => {
                encoder.array(2)?.u16(3)?;
                name.encode(encoder, context)?;
            }
            DeriveOperationKindV2::AssembleList => {
                encoder.array(1)?.u16(4)?;
            }
            DeriveOperationKindV2::AssembleObject(fields) => {
                encoder.array(2)?.u16(5)?.array(fields.len() as u64)?;
                for field in fields {
                    field.encode(encoder, context)?;
                }
            }
            DeriveOperationKindV2::PolicyConstant(constant_id) => {
                encoder.array(2)?.u16(6)?;
                constant_id.encode(encoder, context)?;
            }
        }
        Ok(())
    }
}

impl<'bytes, C> minicbor::Decode<'bytes, C> for DeriveOperationV2 {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        context: &mut C,
    ) -> Result<Self, minicbor::decode::Error> {
        let position = decoder.position();
        let length = decoder.array()?.ok_or_else(|| {
            minicbor::decode::Error::message("indefinite derive operation").at(position)
        })?;
        let tag = decoder.u16()?;
        match (length, tag) {
            (1, 1) => Ok(Self::concatenate_text()),
            (1, 2) => Ok(Self::normalize_nfc()),
            (2, 3) => Ok(Self::select_object_field(minicbor::Decode::decode(
                decoder, context,
            )?)),
            (1, 4) => Ok(Self::assemble_list()),
            (2, 5) => {
                let count = decode_bounded_array(decoder, MAX_DERIVE_OBJECT_FIELDS, position)?;
                let mut fields = Vec::new();
                fields.try_reserve_exact(count).map_err(|_| {
                    minicbor::decode::Error::message("derive allocation failed").at(position)
                })?;
                for _ in 0..count {
                    fields.push(minicbor::Decode::decode(decoder, context)?);
                }
                Self::assemble_object(fields).map_err(|_| {
                    minicbor::decode::Error::message("invalid derive object").at(position)
                })
            }
            (2, 6) => Ok(Self::policy_constant(minicbor::Decode::decode(
                decoder, context,
            )?)),
            _ => Err(minicbor::decode::Error::message("unknown derive operation").at(position)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DeclassificationTransitionV2 {
    MaskTokenizeAndLeakCheck,
    BuildPlannerEnvelope,
    BuildApprovalDisplay,
    /// Hands the value to ONE exact executor, named by its identity digest.
    ///
    /// The identity rides in the variant rather than alongside it so the
    /// transition cannot be named without naming its reader. `ReaderSetV2` can
    /// only say "an executor may read this"; the design requires "this executor
    /// may read this", and a class bit cannot express the difference.
    BuildExecutionEnvelope {
        executor_identity_digest: Digest32V2,
    },
    /// Hands the value to ONE exact external sink, named by its identity digest.
    ///
    /// This is the egress boundary — the transition after which the value has
    /// left. Binding the exact sink is what distinguishes a release the user
    /// asked for from a release to somewhere else entirely; the reader class
    /// alone treats both as "an external sink".
    BuildFinalRelease {
        sink_identity_digest: Digest32V2,
    },
}

impl DeclassificationTransitionV2 {
    pub const fn tag(self) -> u16 {
        match self {
            Self::MaskTokenizeAndLeakCheck => 1,
            Self::BuildPlannerEnvelope => 2,
            Self::BuildApprovalDisplay => 3,
            Self::BuildExecutionEnvelope { .. } => 4,
            Self::BuildFinalRelease { .. } => 5,
        }
    }

    /// What the leak gate must prove before this transition may run.
    ///
    /// The split follows who reads the result, not how far confidentiality
    /// drops. A language model is the one recipient that cannot be trusted to
    /// hold personal data without it becoming training input, prompt context,
    /// or an outbound request, so those two transitions must be free of
    /// residual PII. The human approving the action, and the executor carrying
    /// it out, both need the real values to do their job at all — masking
    /// those would not be a stricter gate, it would be a broken one.
    ///
    /// The blocklist applies everywhere: injected instructions are not data any
    /// recipient is entitled to, under any transition.
    const fn leak_gate_duty(self) -> LeakGateDutyV2 {
        match self {
            Self::MaskTokenizeAndLeakCheck | Self::BuildPlannerEnvelope => {
                LeakGateDutyV2::BlocklistAndNoResidualPii
            }
            Self::BuildApprovalDisplay
            | Self::BuildExecutionEnvelope { .. }
            | Self::BuildFinalRelease { .. } => LeakGateDutyV2::BlocklistOnly,
        }
    }

    const fn target(self) -> (ConfidentialityV2, ReaderSetV2) {
        match self {
            Self::MaskTokenizeAndLeakCheck => (ConfidentialityV2::AgentMasked, ReaderSetV2::AGENT),
            Self::BuildPlannerEnvelope => (
                ConfidentialityV2::PlannerAbstract,
                ReaderSetV2::EXTERNAL_PLANNER,
            ),
            Self::BuildApprovalDisplay => (
                ConfidentialityV2::AgentMasked,
                ReaderSetV2::APPROVAL_DISPLAY,
            ),
            Self::BuildExecutionEnvelope { .. } => {
                (ConfidentialityV2::VaultBound, ReaderSetV2::EXECUTOR)
            }
            Self::BuildFinalRelease { .. } => {
                (ConfidentialityV2::VaultBound, ReaderSetV2::EXTERNAL_SINK)
            }
        }
    }

    /// The exact reader this transition names, for the two that name one.
    ///
    /// Bound into the declassification's provenance node so the record says
    /// which executor or sink the value was released to, not merely that it was
    /// released to some member of a class.
    const fn exact_reader_identity(self) -> Option<Digest32V2> {
        match self {
            Self::BuildExecutionEnvelope {
                executor_identity_digest: identity,
            }
            | Self::BuildFinalRelease {
                sink_identity_digest: identity,
            } => Some(identity),
            Self::MaskTokenizeAndLeakCheck
            | Self::BuildPlannerEnvelope
            | Self::BuildApprovalDisplay => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SourceKindV2 {
    GatedIngress {
        settlement_digest: Digest32V2,
    },
    KernelExtraction {
        model_digest: Digest32V2,
        schema_digest: Digest32V2,
    },
    PolicyConstant {
        constant_id: PolicyConstantIdV2,
    },
    PlannerOutput {
        planner_route_digest: Digest32V2,
    },
    ToolResult {
        action_intent: ActionIntentIdV2,
        execution_nonce_digest: Digest32V2,
    },
    Derived {
        operation: DeriveOperationV2,
    },
    KernelDeclassification {
        rule_digest: Digest32V2,
    },
    RecoveredExecution {
        dispatch_record_digest: Digest32V2,
    },
}

impl SourceKindV2 {
    pub const fn tag(&self) -> u16 {
        match self {
            Self::GatedIngress { .. } => 1,
            Self::KernelExtraction { .. } => 2,
            Self::PolicyConstant { .. } => 3,
            Self::PlannerOutput { .. } => 4,
            Self::ToolResult { .. } => 5,
            Self::Derived { .. } => 6,
            Self::KernelDeclassification { .. } => 7,
            Self::RecoveredExecution { .. } => 8,
        }
    }
}

impl<C> minicbor::Encode<C> for SourceKindV2 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        match self {
            Self::GatedIngress { settlement_digest } => {
                encoder.array(2)?.u16(1)?;
                settlement_digest.encode(encoder, context)?;
            }
            Self::KernelExtraction {
                model_digest,
                schema_digest,
            } => {
                encoder.array(3)?.u16(2)?;
                model_digest.encode(encoder, context)?;
                schema_digest.encode(encoder, context)?;
            }
            Self::PolicyConstant { constant_id } => {
                encoder.array(2)?.u16(3)?;
                constant_id.encode(encoder, context)?;
            }
            Self::PlannerOutput {
                planner_route_digest,
            } => {
                encoder.array(2)?.u16(4)?;
                planner_route_digest.encode(encoder, context)?;
            }
            Self::ToolResult {
                action_intent,
                execution_nonce_digest,
            } => {
                encoder.array(3)?.u16(5)?;
                action_intent.encode(encoder, context)?;
                execution_nonce_digest.encode(encoder, context)?;
            }
            Self::Derived { operation } => {
                encoder.array(2)?.u16(6)?;
                operation.encode(encoder, context)?;
            }
            Self::KernelDeclassification { rule_digest } => {
                encoder.array(2)?.u16(7)?;
                rule_digest.encode(encoder, context)?;
            }
            Self::RecoveredExecution {
                dispatch_record_digest,
            } => {
                encoder.array(2)?.u16(8)?;
                dispatch_record_digest.encode(encoder, context)?;
            }
        }
        Ok(())
    }
}

impl<'bytes> minicbor::Decode<'bytes, V2DecodeContext> for SourceKindV2 {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        context: &mut V2DecodeContext,
    ) -> Result<Self, minicbor::decode::Error> {
        let position = decoder.position();
        let length = decoder.array()?.ok_or_else(|| {
            minicbor::decode::Error::message("indefinite provenance source").at(position)
        })?;
        let tag = decoder.u16()?;
        match (length, tag) {
            (2, 1) => Ok(Self::GatedIngress {
                settlement_digest: minicbor::Decode::decode(decoder, context)?,
            }),
            (3, 2) => Ok(Self::KernelExtraction {
                model_digest: minicbor::Decode::decode(decoder, context)?,
                schema_digest: minicbor::Decode::decode(decoder, context)?,
            }),
            (2, 3) => Ok(Self::PolicyConstant {
                constant_id: minicbor::Decode::decode(decoder, context)?,
            }),
            (2, 4) => Ok(Self::PlannerOutput {
                planner_route_digest: minicbor::Decode::decode(decoder, context)?,
            }),
            (3, 5) => Ok(Self::ToolResult {
                action_intent: minicbor::Decode::decode(decoder, context)?,
                execution_nonce_digest: minicbor::Decode::decode(decoder, context)?,
            }),
            (2, 6) => Ok(Self::Derived {
                operation: minicbor::Decode::decode(decoder, context)?,
            }),
            (2, 7) => Ok(Self::KernelDeclassification {
                rule_digest: minicbor::Decode::decode(decoder, context)?,
            }),
            (2, 8) => Ok(Self::RecoveredExecution {
                dispatch_record_digest: minicbor::Decode::decode(decoder, context)?,
            }),
            _ => Err(minicbor::decode::Error::message("unknown provenance source").at(position)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootEvidenceV2(Vec<Digest32V2>);

impl RootEvidenceV2 {
    pub fn new(mut roots: Vec<Digest32V2>) -> Result<Self, G3Error> {
        if roots.len() > MAX_ROOT_EVIDENCE {
            return Err(G3Error::RootEvidenceOverflow);
        }
        roots.sort_unstable_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
        if roots
            .windows(2)
            .any(|pair| pair[0].as_bytes() == pair[1].as_bytes())
        {
            return Err(G3Error::DuplicateRootEvidence);
        }
        Ok(Self(roots))
    }

    pub fn as_slice(&self) -> &[Digest32V2] {
        &self.0
    }
}

impl<C> minicbor::Encode<C> for RootEvidenceV2 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        encoder.array(self.0.len() as u64)?;
        for root in &self.0 {
            root.encode(encoder, context)?;
        }
        Ok(())
    }
}

impl<'bytes> minicbor::Decode<'bytes, V2DecodeContext> for RootEvidenceV2 {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        context: &mut V2DecodeContext,
    ) -> Result<Self, minicbor::decode::Error> {
        let position = decoder.position();
        let count = decode_bounded_array(decoder, MAX_ROOT_EVIDENCE, position)?;
        let mut roots = Vec::new();
        roots.try_reserve_exact(count).map_err(|_| {
            minicbor::decode::Error::message("root evidence allocation failed").at(position)
        })?;
        for _ in 0..count {
            roots.push(minicbor::Decode::decode(decoder, context)?);
        }
        let candidate = Self::new(roots)
            .map_err(|_| minicbor::decode::Error::message("invalid root evidence").at(position))?;
        Ok(candidate)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProvenanceContextV2 {
    producer_identity: ProducerIdentityV2,
    run_internal_id: DurableRunIdV2,
    active_state_manifest_digest: Digest32V2,
    created_at: UnixMillisV2,
    expires_at: UnixMillisV2,
}

impl ProvenanceContextV2 {
    pub fn from_authenticated_runtime(
        producer_identity: ProducerIdentityV2,
        run_internal_id: DurableRunIdV2,
        active_state_manifest_digest: Digest32V2,
        created_at: UnixMillisV2,
        expires_at: UnixMillisV2,
    ) -> Result<Self, G3Error> {
        if expires_at.get() <= created_at.get() {
            return Err(G3Error::InvalidTimeRange);
        }
        Ok(Self {
            producer_identity,
            run_internal_id,
            active_state_manifest_digest,
            created_at,
            expires_at,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvenanceRecordV2 {
    source_kind: SourceKindV2,
    producer_identity: ProducerIdentityV2,
    value_digest: Digest32V2,
    ordered_parent_value_digests: Vec<Digest32V2>,
    ordered_parent_provenance_digests: Vec<Digest32V2>,
    root_evidence: RootEvidenceV2,
    label: SecurityLabelV2,
    run_internal_id: DurableRunIdV2,
    active_state_manifest_digest: Digest32V2,
    created_at: UnixMillisV2,
    expires_at: UnixMillisV2,
    provenance_digest: Digest32V2,
}

impl ProvenanceRecordV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn from_verified_executor_tool_result(
        value: &KernelValueV2,
        context: ProvenanceContextV2,
        action_intent: ActionIntentIdV2,
        execution_nonce_digest: Digest32V2,
        action_intent_record_digest: Digest32V2,
        descriptor_digest: Digest32V2,
        executor_receipt_digest: Digest32V2,
        policy_allowed_effects: EffectSetV2,
    ) -> Result<Self, G3Error> {
        Self::tool_result(
            value,
            context,
            action_intent,
            execution_nonce_digest,
            action_intent_record_digest,
            descriptor_digest,
            executor_receipt_digest,
            policy_allowed_effects,
        )
    }

    pub(crate) fn gated_ingress(
        value: &KernelValueV2,
        context: ProvenanceContextV2,
        settlement_digest: Digest32V2,
        source_digest: Digest32V2,
        approval_digest: Digest32V2,
        policy_allowed_effects: EffectSetV2,
    ) -> Result<Self, G3Error> {
        let value_digest = value_digest_v2(value)?;
        let source = SourceKindV2::GatedIngress { settlement_digest };
        let label = SecurityLabelV2::from_verified_source(
            IntegrityV2::UserAuthorized,
            ConfidentialityV2::VaultBound,
            ReaderSetV2::KERNEL,
            policy_allowed_effects,
        );
        Self::build(
            source,
            value_digest,
            context,
            &[],
            vec![settlement_digest, source_digest, approval_digest],
            label,
        )
    }

    pub fn from_verified_ingress_evidence<E: VerifiedIngressProvenanceEvidenceSourceV2>(
        value: &KernelValueV2,
        context: ProvenanceContextV2,
        evidence: E,
        policy_allowed_effects: EffectSetV2,
    ) -> Result<Self, G3Error> {
        if evidence.active_state_manifest_digest_v2() != context.active_state_manifest_digest {
            return Err(G3Error::CrossManifestParent);
        }
        Self::gated_ingress(
            value,
            context,
            evidence.authentication_context_digest_v2(),
            evidence.declared_content_digest_v2(),
            evidence.tab_binding_digest_v2(),
            policy_allowed_effects,
        )
    }

    pub fn from_verified_kernel_input(
        value: &KernelValueV2,
        context: ProvenanceContextV2,
        settlement_digest: Digest32V2,
        source_provenance_digest: Digest32V2,
        authentication_context_digest: Digest32V2,
        authentication_binding_digest: Digest32V2,
        policy_allowed_effects: EffectSetV2,
    ) -> Result<Self, G3Error> {
        if [
            settlement_digest.as_bytes(),
            source_provenance_digest.as_bytes(),
            authentication_context_digest.as_bytes(),
            authentication_binding_digest.as_bytes(),
        ]
        .iter()
        .any(|digest| digest.iter().all(|byte| *byte == 0))
        {
            return Err(G3Error::BindingMismatch);
        }
        let value_digest = value_digest_v2(value)?;
        let label = SecurityLabelV2::from_verified_source(
            IntegrityV2::UserAuthorized,
            ConfidentialityV2::VaultBound,
            ReaderSetV2::KERNEL,
            policy_allowed_effects,
        );
        Self::build(
            SourceKindV2::GatedIngress { settlement_digest },
            value_digest,
            context,
            &[],
            vec![
                settlement_digest,
                source_provenance_digest,
                authentication_context_digest,
                authentication_binding_digest,
            ],
            label,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn policy_constant(
        value: &KernelValueV2,
        context: ProvenanceContextV2,
        constant_id: PolicyConstantIdV2,
        signed_constant_digest: Digest32V2,
        declared_confidentiality: ConfidentialityV2,
        declared_readers: ReaderSetV2,
        policy_allowed_readers: ReaderSetV2,
        policy_allowed_effects: EffectSetV2,
    ) -> Result<Self, G3Error> {
        let value_digest = value_digest_v2(value)?;
        let label = SecurityLabelV2::from_verified_source(
            IntegrityV2::KernelTrusted,
            declared_confidentiality,
            declared_readers.intersection(policy_allowed_readers),
            policy_allowed_effects,
        );
        Self::build(
            SourceKindV2::PolicyConstant { constant_id },
            value_digest,
            context,
            &[],
            vec![signed_constant_digest],
            label,
        )
    }

    pub fn derived(
        context: ProvenanceContextV2,
        operation: DeriveOperationV2,
        parents: &[(&KernelValueV2, &Self)],
        policy_allowed_effects: EffectSetV2,
    ) -> Result<(KernelValueV2, Self), G3Error> {
        require_nonempty(parents)?;
        if parents.len() > MAX_PROVENANCE_PARENTS {
            return Err(G3Error::ParentLimitExceeded);
        }
        validate_parent_contexts(parents, &context)?;
        validate_parent_values(parents)?;
        let value = operation.execute(parents)?;
        let value_digest = value_digest_v2(&value)?;
        let mut provenance_parents = Vec::new();
        provenance_parents
            .try_reserve_exact(parents.len())
            .map_err(|_| G3Error::AllocationFailure)?;
        provenance_parents.extend(parents.iter().map(|(_, provenance)| *provenance));
        let label = derived_label(&provenance_parents, policy_allowed_effects)?;
        let provenance = Self::build(
            SourceKindV2::Derived { operation },
            value_digest,
            context,
            &provenance_parents,
            vec![],
            label,
        )?;
        Ok((value, provenance))
    }

    pub fn kernel_extraction(
        value: &KernelValueV2,
        context: ProvenanceContextV2,
        model_digest: Digest32V2,
        schema_digest: Digest32V2,
        parents: &[&Self],
        policy_allowed_effects: EffectSetV2,
    ) -> Result<Self, G3Error> {
        let value_digest = value_digest_v2(value)?;
        if !parents
            .iter()
            .any(|parent| matches!(parent.source_kind, SourceKindV2::GatedIngress { .. }))
        {
            return Err(G3Error::MissingGatedIngressParent);
        }
        let label = derived_label(parents, policy_allowed_effects)?;
        Self::build(
            SourceKindV2::KernelExtraction {
                model_digest,
                schema_digest,
            },
            value_digest,
            context,
            parents,
            vec![model_digest, schema_digest],
            label,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn planner_output(
        value: &KernelValueV2,
        context: ProvenanceContextV2,
        planner_route_digest: Digest32V2,
        planner_envelope_digest: Digest32V2,
        planner_output_digest: Digest32V2,
        parents: &[&Self],
        policy_allowed_effects: EffectSetV2,
    ) -> Result<Self, G3Error> {
        let value_digest = value_digest_v2(value)?;
        let parent_label = if parents.is_empty() {
            SecurityLabelV2::from_verified_source(
                IntegrityV2::ExternalUntrusted,
                ConfidentialityV2::PlannerAbstract,
                ReaderSetV2::KERNEL,
                policy_allowed_effects,
            )
        } else {
            derived_label(parents, policy_allowed_effects)?
        };
        let label = SecurityLabelV2::from_verified_source(
            IntegrityV2::ExternalUntrusted,
            ConfidentialityV2::PlannerAbstract.join(parent_label.confidentiality()),
            ReaderSetV2::KERNEL,
            parent_label.effects(),
        );
        Self::build(
            SourceKindV2::PlannerOutput {
                planner_route_digest,
            },
            value_digest,
            context,
            parents,
            vec![
                planner_route_digest,
                planner_envelope_digest,
                planner_output_digest,
            ],
            label,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn tool_result(
        value: &KernelValueV2,
        context: ProvenanceContextV2,
        action_intent: ActionIntentIdV2,
        execution_nonce_digest: Digest32V2,
        action_intent_record_digest: Digest32V2,
        descriptor_digest: Digest32V2,
        executor_receipt_digest: Digest32V2,
        policy_allowed_effects: EffectSetV2,
    ) -> Result<Self, G3Error> {
        let value_digest = value_digest_v2(value)?;
        let label = SecurityLabelV2::from_verified_source(
            IntegrityV2::ExternalUntrusted,
            ConfidentialityV2::VaultBound,
            ReaderSetV2::KERNEL,
            policy_allowed_effects,
        );
        Self::build(
            SourceKindV2::ToolResult {
                action_intent,
                execution_nonce_digest,
            },
            value_digest,
            context,
            &[],
            vec![
                action_intent_record_digest,
                execution_nonce_digest,
                descriptor_digest,
                executor_receipt_digest,
                value_digest,
            ],
            label,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn kernel_declassification(
        value: &KernelValueV2,
        context: ProvenanceContextV2,
        transition: DeclassificationTransitionV2,
        rule_digest: Digest32V2,
        implementation_digest: Digest32V2,
        token_set_digest: Digest32V2,
        purpose_digest: Digest32V2,
        parents: &[&Self],
        policy_allowed_effects: EffectSetV2,
    ) -> Result<Self, G3Error> {
        // The gate runs here, and its digest is derived from what it actually
        // saw. Taking `leak_gate_digest` as a parameter would let the caller
        // assert a check the kernel cannot verify happened, at the one point
        // where the kernel gives up a confidentiality guarantee.
        // A declassification is only legitimate after a signed rule authorized
        // it, so a node whose rule, implementation, token set, or purpose is
        // all zeroes binds nothing and must not be built: it would claim
        // authority from a rule that names nothing. `from_verified_kernel_input`
        // already refuses null bindings; there is no reason for the path that
        // gives up confidentiality to be the laxer of the two.
        if [
            rule_digest.as_bytes(),
            implementation_digest.as_bytes(),
            token_set_digest.as_bytes(),
            purpose_digest.as_bytes(),
        ]
        .iter()
        .any(|digest| digest.iter().all(|byte| *byte == 0))
        {
            return Err(G3Error::BindingMismatch);
        }
        let leak_gate_digest = enforce_for_declassification(value, transition.leak_gate_duty())?;
        let mut evidence = vec![
            rule_digest,
            implementation_digest,
            leak_gate_digest,
            token_set_digest,
            purpose_digest,
        ];
        // The two transitions that hand the value to one exact reader bind that
        // reader's identity into the node, so the record says WHERE the value
        // went and not merely that it left. An all-zero digest names nobody, and
        // accepting it would collapse "one exact sink" back into the class bit.
        if let Some(identity) = transition.exact_reader_identity() {
            if identity.as_bytes().iter().all(|byte| *byte == 0) {
                return Err(G3Error::BindingMismatch);
            }
            evidence.push(identity);
        }
        let value_digest = value_digest_v2(value)?;
        let parent_label = derived_label(parents, policy_allowed_effects)?;
        let (confidentiality, readers) = transition.target();
        let label = SecurityLabelV2::from_verified_source(
            parent_label.integrity(),
            confidentiality,
            readers,
            parent_label.effects(),
        );
        Self::build(
            SourceKindV2::KernelDeclassification { rule_digest },
            value_digest,
            context,
            parents,
            evidence,
            label,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn recovered_execution(
        value: &KernelValueV2,
        context: ProvenanceContextV2,
        dispatch_record_digest: Digest32V2,
        execd_journal_head_digest: Digest32V2,
        executor_receipt_digest: Digest32V2,
        policy_allowed_effects: EffectSetV2,
    ) -> Result<Self, G3Error> {
        let value_digest = value_digest_v2(value)?;
        let label = SecurityLabelV2::from_verified_source(
            IntegrityV2::ExternalUntrusted,
            ConfidentialityV2::VaultBound,
            ReaderSetV2::KERNEL,
            policy_allowed_effects,
        );
        Self::build(
            SourceKindV2::RecoveredExecution {
                dispatch_record_digest,
            },
            value_digest,
            context,
            &[],
            vec![
                dispatch_record_digest,
                execd_journal_head_digest,
                executor_receipt_digest,
                value_digest,
            ],
            label,
        )
    }

    fn build(
        source_kind: SourceKindV2,
        value_digest: Digest32V2,
        context: ProvenanceContextV2,
        parents: &[&Self],
        source_roots: Vec<Digest32V2>,
        label: SecurityLabelV2,
    ) -> Result<Self, G3Error> {
        if parents.len() > MAX_PROVENANCE_PARENTS {
            return Err(G3Error::ParentLimitExceeded);
        }
        for parent in parents {
            if parent.run_internal_id != context.run_internal_id {
                return Err(G3Error::CrossRunParent);
            }
            if parent.active_state_manifest_digest != context.active_state_manifest_digest {
                return Err(G3Error::CrossManifestParent);
            }
        }

        let source_roots = RootEvidenceV2::new(source_roots)?;
        let root_evidence = union_roots(parents, &source_roots)?;
        let ordered_parent_value_digests =
            parents.iter().map(|parent| parent.value_digest).collect();
        let ordered_parent_provenance_digests = parents
            .iter()
            .map(|parent| parent.provenance_digest)
            .collect();
        let mut value = Self {
            source_kind,
            producer_identity: context.producer_identity,
            value_digest,
            ordered_parent_value_digests,
            ordered_parent_provenance_digests,
            root_evidence,
            label,
            run_internal_id: context.run_internal_id,
            active_state_manifest_digest: context.active_state_manifest_digest,
            created_at: context.created_at,
            expires_at: context.expires_at,
            provenance_digest: Digest32V2::new([0; 32]),
        };
        value.provenance_digest = compute_provenance_digest(&value)?;
        Ok(value)
    }

    pub const fn source_kind(&self) -> &SourceKindV2 {
        &self.source_kind
    }

    pub const fn producer_identity(&self) -> ProducerIdentityV2 {
        self.producer_identity
    }

    pub const fn label(&self) -> SecurityLabelV2 {
        self.label
    }

    pub fn root_evidence(&self) -> &RootEvidenceV2 {
        &self.root_evidence
    }

    pub const fn value_digest(&self) -> Digest32V2 {
        self.value_digest
    }

    pub const fn provenance_digest(&self) -> Digest32V2 {
        self.provenance_digest
    }

    pub const fn run_internal_id(&self) -> DurableRunIdV2 {
        self.run_internal_id
    }

    pub const fn active_state_manifest_digest(&self) -> Digest32V2 {
        self.active_state_manifest_digest
    }

    pub const fn created_at(&self) -> UnixMillisV2 {
        self.created_at
    }

    pub const fn expires_at(&self) -> UnixMillisV2 {
        self.expires_at
    }
}

/// Narrow evidence projection accepted by G3 after ingressd has authenticated
/// and finalized an input. Implementations expose digests only; content,
/// capabilities, and ingress mutable state cannot cross this boundary.
pub trait VerifiedIngressProvenanceEvidenceSourceV2 {
    fn active_state_manifest_digest_v2(&self) -> Digest32V2;
    fn authentication_context_digest_v2(&self) -> Digest32V2;
    fn declared_content_digest_v2(&self) -> Digest32V2;
    fn tab_binding_digest_v2(&self) -> Digest32V2;
}

fn canonical_text_order(left: &str, right: &str) -> std::cmp::Ordering {
    left.len()
        .cmp(&right.len())
        .then_with(|| left.as_bytes().cmp(right.as_bytes()))
}

pub fn provenance_digest_v2(record: &ProvenanceRecordV2) -> Result<Digest32V2, G3Error> {
    compute_provenance_digest(record)
}

pub fn encode_provenance_record_v2(record: &ProvenanceRecordV2) -> Result<Vec<u8>, G3Error> {
    if compute_provenance_digest(record)? != record.provenance_digest {
        return Err(G3Error::BindingMismatch);
    }
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(16)
        .and_then(|encoder| encoder.u16(2))
        .map_err(|_| G3Error::CanonicalEncoding)?;
    record
        .source_kind
        .encode(&mut encoder, &mut ())
        .map_err(|_| G3Error::CanonicalEncoding)?;
    record
        .producer_identity
        .encode(&mut encoder, &mut ())
        .map_err(|_| G3Error::CanonicalEncoding)?;
    record
        .value_digest
        .encode(&mut encoder, &mut ())
        .map_err(|_| G3Error::CanonicalEncoding)?;
    encode_digests(&record.ordered_parent_value_digests, &mut encoder, &mut ())
        .map_err(|_| G3Error::CanonicalEncoding)?;
    encode_digests(
        &record.ordered_parent_provenance_digests,
        &mut encoder,
        &mut (),
    )
    .map_err(|_| G3Error::CanonicalEncoding)?;
    record
        .root_evidence
        .encode(&mut encoder, &mut ())
        .map_err(|_| G3Error::CanonicalEncoding)?;
    record
        .label
        .integrity()
        .encode(&mut encoder, &mut ())
        .map_err(|_| G3Error::CanonicalEncoding)?;
    record
        .label
        .confidentiality()
        .encode(&mut encoder, &mut ())
        .map_err(|_| G3Error::CanonicalEncoding)?;
    record
        .label
        .readers()
        .encode(&mut encoder, &mut ())
        .map_err(|_| G3Error::CanonicalEncoding)?;
    record
        .label
        .effects()
        .encode(&mut encoder, &mut ())
        .map_err(|_| G3Error::CanonicalEncoding)?;
    record
        .run_internal_id
        .encode(&mut encoder, &mut ())
        .map_err(|_| G3Error::CanonicalEncoding)?;
    record
        .active_state_manifest_digest
        .encode(&mut encoder, &mut ())
        .map_err(|_| G3Error::CanonicalEncoding)?;
    record
        .created_at
        .encode(&mut encoder, &mut ())
        .map_err(|_| G3Error::CanonicalEncoding)?;
    record
        .expires_at
        .encode(&mut encoder, &mut ())
        .map_err(|_| G3Error::CanonicalEncoding)?;
    record
        .provenance_digest
        .encode(&mut encoder, &mut ())
        .map_err(|_| G3Error::CanonicalEncoding)?;
    Ok(encoder.into_writer())
}

pub fn decode_provenance_record_v2(bytes: &[u8]) -> Result<ProvenanceRecordV2, G3Error> {
    if bytes.is_empty() || bytes.len() > 8 * 1024 * 1024 {
        return Err(G3Error::CanonicalEncoding);
    }
    let mut decoder = minicbor::Decoder::new(bytes);
    if decoder.array().map_err(|_| G3Error::CanonicalEncoding)? != Some(16)
        || decoder.u16().map_err(|_| G3Error::CanonicalEncoding)? != 2
    {
        return Err(G3Error::CanonicalEncoding);
    }
    let mut context = V2DecodeContext;
    let source_kind: SourceKindV2 = minicbor::Decode::decode(&mut decoder, &mut context)
        .map_err(|_| G3Error::CanonicalEncoding)?;
    let producer_identity: ProducerIdentityV2 =
        minicbor::Decode::decode(&mut decoder, &mut context)
            .map_err(|_| G3Error::CanonicalEncoding)?;
    let value_digest: Digest32V2 = minicbor::Decode::decode(&mut decoder, &mut context)
        .map_err(|_| G3Error::CanonicalEncoding)?;
    let ordered_parent_value_digests =
        decode_digest_vec(&mut decoder, &mut context, MAX_PROVENANCE_PARENTS)?;
    let ordered_parent_provenance_digests =
        decode_digest_vec(&mut decoder, &mut context, MAX_PROVENANCE_PARENTS)?;
    if ordered_parent_value_digests.len() != ordered_parent_provenance_digests.len() {
        return Err(G3Error::BindingMismatch);
    }
    let root_evidence: RootEvidenceV2 = minicbor::Decode::decode(&mut decoder, &mut context)
        .map_err(|_| G3Error::CanonicalEncoding)?;
    let integrity: IntegrityV2 = minicbor::Decode::decode(&mut decoder, &mut context)
        .map_err(|_| G3Error::CanonicalEncoding)?;
    let confidentiality: ConfidentialityV2 = minicbor::Decode::decode(&mut decoder, &mut context)
        .map_err(|_| G3Error::CanonicalEncoding)?;
    let readers: ReaderSetV2 = minicbor::Decode::decode(&mut decoder, &mut context)
        .map_err(|_| G3Error::CanonicalEncoding)?;
    let effects: EffectSetV2 = minicbor::Decode::decode(&mut decoder, &mut context)
        .map_err(|_| G3Error::CanonicalEncoding)?;
    let run_internal_id: DurableRunIdV2 = minicbor::Decode::decode(&mut decoder, &mut context)
        .map_err(|_| G3Error::CanonicalEncoding)?;
    let active_state_manifest_digest: Digest32V2 =
        minicbor::Decode::decode(&mut decoder, &mut context)
            .map_err(|_| G3Error::CanonicalEncoding)?;
    let created_at: UnixMillisV2 = minicbor::Decode::decode(&mut decoder, &mut context)
        .map_err(|_| G3Error::CanonicalEncoding)?;
    let expires_at: UnixMillisV2 = minicbor::Decode::decode(&mut decoder, &mut context)
        .map_err(|_| G3Error::CanonicalEncoding)?;
    let provenance_digest: Digest32V2 = minicbor::Decode::decode(&mut decoder, &mut context)
        .map_err(|_| G3Error::CanonicalEncoding)?;
    if decoder.position() != bytes.len()
        || created_at.get() == 0
        || created_at.get() >= expires_at.get()
        || producer_identity.as_bytes().iter().all(|byte| *byte == 0)
        || value_digest.as_bytes().iter().all(|byte| *byte == 0)
        || run_internal_id.as_bytes().iter().all(|byte| *byte == 0)
        || active_state_manifest_digest
            .as_bytes()
            .iter()
            .all(|byte| *byte == 0)
    {
        return Err(G3Error::BindingMismatch);
    }
    let record = ProvenanceRecordV2 {
        source_kind,
        producer_identity,
        value_digest,
        ordered_parent_value_digests,
        ordered_parent_provenance_digests,
        root_evidence,
        label: SecurityLabelV2::from_verified_source(integrity, confidentiality, readers, effects),
        run_internal_id,
        active_state_manifest_digest,
        created_at,
        expires_at,
        provenance_digest,
    };
    if compute_provenance_digest(&record)? != provenance_digest
        || encode_provenance_record_v2(&record)? != bytes
    {
        return Err(G3Error::BindingMismatch);
    }
    Ok(record)
}

fn derived_label(
    parents: &[&ProvenanceRecordV2],
    policy_allowed_effects: EffectSetV2,
) -> Result<SecurityLabelV2, G3Error> {
    let labels = parents
        .iter()
        .map(|parent| parent.label)
        .collect::<Vec<_>>();
    SecurityLabelV2::derive_normal(&labels, policy_allowed_effects)
}

fn require_nonempty<T>(values: &[T]) -> Result<(), G3Error> {
    if values.is_empty() {
        Err(G3Error::EmptyParents)
    } else {
        Ok(())
    }
}

fn validate_parent_values(
    parents: &[(&KernelValueV2, &ProvenanceRecordV2)],
) -> Result<(), G3Error> {
    for (value, provenance) in parents {
        if value_digest_v2(value)? != provenance.value_digest {
            return Err(G3Error::ParentValueMismatch);
        }
    }
    Ok(())
}

fn validate_parent_contexts(
    parents: &[(&KernelValueV2, &ProvenanceRecordV2)],
    context: &ProvenanceContextV2,
) -> Result<(), G3Error> {
    for (_, provenance) in parents {
        if provenance.run_internal_id != context.run_internal_id {
            return Err(G3Error::CrossRunParent);
        }
        if provenance.active_state_manifest_digest != context.active_state_manifest_digest {
            return Err(G3Error::CrossManifestParent);
        }
    }
    Ok(())
}

fn parent_value_refs<'value>(
    parents: &[(&'value KernelValueV2, &ProvenanceRecordV2)],
) -> Result<Vec<&'value KernelValueV2>, G3Error> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(parents.len())
        .map_err(|_| G3Error::AllocationFailure)?;
    values.extend(parents.iter().map(|(value, _)| *value));
    Ok(values)
}

fn union_roots(
    parents: &[&ProvenanceRecordV2],
    source_roots: &RootEvidenceV2,
) -> Result<RootEvidenceV2, G3Error> {
    let mut roots = source_roots.0.clone();
    for parent in parents {
        roots.extend_from_slice(parent.root_evidence.as_slice());
    }
    roots.sort_unstable_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    roots.dedup_by(|left, right| left.as_bytes() == right.as_bytes());
    if roots.len() > MAX_ROOT_EVIDENCE {
        return Err(G3Error::RootEvidenceOverflow);
    }
    Ok(RootEvidenceV2(roots))
}

fn compute_provenance_digest(value: &ProvenanceRecordV2) -> Result<Digest32V2, G3Error> {
    let canonical =
        minicbor::to_vec(ProvenanceDigestPayload(value)).map_err(|_| G3Error::CanonicalEncoding)?;
    let mut hasher = Sha256::new();
    hasher.update(b"SAVANA_PROVENANCE_V2\0");
    hasher.update(canonical);
    Ok(Digest32V2::new(hasher.finalize().into()))
}

struct ProvenanceDigestPayload<'record>(&'record ProvenanceRecordV2);

impl<C> minicbor::Encode<C> for ProvenanceDigestPayload<'_> {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        let value = self.0;
        encoder.array(14)?;
        value.source_kind.encode(encoder, context)?;
        value.producer_identity.encode(encoder, context)?;
        value.value_digest.encode(encoder, context)?;
        encode_digests(&value.ordered_parent_value_digests, encoder, context)?;
        encode_digests(&value.ordered_parent_provenance_digests, encoder, context)?;
        value.root_evidence.encode(encoder, context)?;
        value.label.integrity().encode(encoder, context)?;
        value.label.confidentiality().encode(encoder, context)?;
        value.label.readers().encode(encoder, context)?;
        value.label.effects().encode(encoder, context)?;
        value.run_internal_id.encode(encoder, context)?;
        value
            .active_state_manifest_digest
            .encode(encoder, context)?;
        value.created_at.encode(encoder, context)?;
        value.expires_at.encode(encoder, context)?;
        Ok(())
    }
}

fn encode_digests<C, W: minicbor::encode::Write>(
    values: &[Digest32V2],
    encoder: &mut minicbor::Encoder<W>,
    context: &mut C,
) -> Result<(), minicbor::encode::Error<W::Error>> {
    encoder.array(values.len() as u64)?;
    for value in values {
        value.encode(encoder, context)?;
    }
    Ok(())
}

fn decode_digest_vec(
    decoder: &mut minicbor::Decoder<'_>,
    context: &mut V2DecodeContext,
    maximum: usize,
) -> Result<Vec<Digest32V2>, G3Error> {
    let count = decoder
        .array()
        .map_err(|_| G3Error::CanonicalEncoding)?
        .ok_or(G3Error::CanonicalEncoding)?;
    let count = usize::try_from(count).map_err(|_| G3Error::CollectionLimitExceeded)?;
    if count > maximum {
        return Err(G3Error::ParentLimitExceeded);
    }
    let mut values = Vec::new();
    values
        .try_reserve_exact(count)
        .map_err(|_| G3Error::AllocationFailure)?;
    for _ in 0..count {
        let value: Digest32V2 =
            minicbor::Decode::decode(decoder, context).map_err(|_| G3Error::CanonicalEncoding)?;
        if value.as_bytes().iter().all(|byte| *byte == 0) {
            return Err(G3Error::BindingMismatch);
        }
        values.push(value);
    }
    Ok(values)
}

fn decode_bounded_array(
    decoder: &mut minicbor::Decoder<'_>,
    maximum: usize,
    position: usize,
) -> Result<usize, minicbor::decode::Error> {
    let count = decoder
        .array()?
        .ok_or_else(|| minicbor::decode::Error::message("indefinite collection").at(position))?;
    let count = usize::try_from(count)
        .map_err(|_| minicbor::decode::Error::message("collection too large").at(position))?;
    if count > maximum {
        return Err(minicbor::decode::Error::message("collection too large").at(position));
    }
    Ok(count)
}

#[cfg(test)]
#[path = "provenance_tests.rs"]
mod tests;
