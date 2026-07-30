use crate::{ProtocolError, StableCode};
use sha2::Digest as _;

use super::{
    cbor::{scan_single, V2DecodeContext},
    ActionIntentHandleV2, ActionTemplateIdV2, AgentUiAuthenticationPreparationHandleV2,
    ArgumentNameV2, Digest32V2, ExecutionHandleV2, ExecutionTicketHandleV2,
    KernelAgentViewCursorV2, MaskedDocumentHandleV2, Nonce32V2, PendingReleaseHandleV2,
    PendingToolCallHandleV2, PlanRevisionDigestV2, PlanStepHandleV2, PlannerRouteIdV2,
    PlannerSlotRefV2, PlannerTicketHandleV2, PublicFailureClassV2, PublicStableCodeV2,
    RelationIdV2, ReleaseHandleV2, ReleaseKernelApprovalHandleV2, ReleaseTicketHandleV2,
    SignedAgentAuthenticationClosureDescriptorV2, SignedApprovalEnvelopeV2,
    SignedUiAuthenticationEnvelopeV2, SlotKindV2, StaticTemplateIdV2, ToolKernelApprovalHandleV2,
    UnixMillisV2, ValueHandleV2,
};

const MAX_PLANNER_ITEMS_V2: usize = 256;
const MAX_RELATIONS_V2: usize = 512;
const MAX_AGENT_VIEW_FIELDS_V2: usize = 256;
const MAX_AGENT_VIEW_PLACEHOLDERS_V2: usize = 20_000;
const MAX_AGENT_VIEW_TEXT_BYTES_V2: usize = 8 * 1024 * 1024;

macro_rules! impl_struct_codec {
    ($name:ident, $count:literal, { $($field:ident),+ $(,)? }) => {
        impl<C> minicbor::Encode<C> for $name {
            fn encode<W: minicbor::encode::Write>(
                &self,
                encoder: &mut minicbor::Encoder<W>,
                context: &mut C,
            ) -> Result<(), minicbor::encode::Error<W::Error>> {
                encoder.array($count)?;
                $(self.$field.encode(encoder, context)?;)+
                Ok(())
            }
        }

        impl<'bytes> minicbor::Decode<'bytes, V2DecodeContext> for $name {
            fn decode(
                decoder: &mut minicbor::Decoder<'bytes>,
                context: &mut V2DecodeContext,
            ) -> Result<Self, minicbor::decode::Error> {
                let position = decoder.position();
                if decoder.array()? != Some($count) {
                    return Err(decode_error(position));
                }
                Ok(Self {
                    $($field: minicbor::Decode::decode(decoder, context)?),+
                })
            }
        }
    };
    ($name:ident, $count:literal, {
        $first:ident => u32,
        $($field:ident),+ $(,)?
    }) => {
        impl<C> minicbor::Encode<C> for $name {
            fn encode<W: minicbor::encode::Write>(
                &self,
                encoder: &mut minicbor::Encoder<W>,
                context: &mut C,
            ) -> Result<(), minicbor::encode::Error<W::Error>> {
                encoder.array($count)?.u32(self.$first)?;
                $(self.$field.encode(encoder, context)?;)+
                Ok(())
            }
        }

        impl<'bytes> minicbor::Decode<'bytes, V2DecodeContext> for $name {
            fn decode(
                decoder: &mut minicbor::Decoder<'bytes>,
                context: &mut V2DecodeContext,
            ) -> Result<Self, minicbor::decode::Error> {
                let position = decoder.position();
                if decoder.array()? != Some($count) {
                    return Err(decode_error(position));
                }
                Ok(Self {
                    $first: decoder.u32()?,
                    $($field: minicbor::Decode::decode(decoder, context)?),+
                })
            }
        }
    };
}

macro_rules! simple_handle_response {
    ($name:ident, $field:ident, $handle:ty) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub struct $name {
            $field: $handle,
        }

        impl $name {
            pub const fn new($field: $handle) -> Self {
                Self { $field }
            }

            pub const fn $field(self) -> $handle {
                self.$field
            }
        }

        impl_struct_codec!($name, 1, { $field });
    };
}

macro_rules! closed_enum_v2 {
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

            fn from_tag(tag: u16) -> Result<Self, ProtocolError> {
                match tag {
                    $($tag => Ok(Self::$variant)),+,
                    _ => Err(malformed()),
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
                if decoder.array()? != Some(1) {
                    return Err(decode_error(position));
                }
                Self::from_tag(decoder.u16()?).map_err(|_| decode_error(position))
            }
        }
    };
}

closed_enum_v2! {
    PlannerIntentKindV2 {
        SendMessage = 1,
        Search = 2,
        SummarizeDocument = 3,
        StoreRecord = 4,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
// The closure proof is a bounded signed protocol object. Keeping it inline
// avoids an extra attacker-triggerable allocation during authenticated decode.
#[allow(clippy::large_enum_variant)]
pub enum ResumeCommittedAgentAuthenticationResponseV2 {
    Prepared {
        authentication_preparation: AgentUiAuthenticationPreparationHandleV2,
        envelope: SignedUiAuthenticationEnvelopeV2,
    },
    ClosureRequired {
        closure: SignedAgentAuthenticationClosureDescriptorV2,
    },
}

impl<C> minicbor::Encode<C> for ResumeCommittedAgentAuthenticationResponseV2 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        match self {
            Self::Prepared {
                authentication_preparation,
                envelope,
            } => {
                encoder.array(3)?.u16(1)?;
                authentication_preparation.encode(encoder, context)?;
                envelope.encode(encoder, context)?;
            }
            Self::ClosureRequired { closure } => {
                encoder.array(2)?.u16(2)?;
                closure.encode(encoder, context)?;
            }
        }
        Ok(())
    }
}

impl<'bytes> minicbor::Decode<'bytes, V2DecodeContext>
    for ResumeCommittedAgentAuthenticationResponseV2
{
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        context: &mut V2DecodeContext,
    ) -> Result<Self, minicbor::decode::Error> {
        let position = decoder.position();
        match (
            decoder.array()?.ok_or_else(|| decode_error(position))?,
            decoder.u16()?,
        ) {
            (3, 1) => Ok(Self::Prepared {
                authentication_preparation: minicbor::Decode::decode(decoder, context)?,
                envelope: minicbor::Decode::decode(decoder, context)?,
            }),
            (2, 2) => Ok(Self::ClosureRequired {
                closure: minicbor::Decode::decode(decoder, context)?,
            }),
            _ => Err(decode_error(position)),
        }
    }
}

closed_enum_v2! {
    PlannerSlotCardinalityV2 {
        ExactlyOne = 1,
        ZeroOrOne = 2,
        OneOrMore = 3,
        ZeroOrMore = 4,
    }
}

closed_enum_v2! {
    PlannerSlotConfidentialityV2 {
        PublicStructural = 1,
        ConfidentialAbstract = 2,
    }
}

closed_enum_v2! {
    PublicDispatchAcceptedStateV2 {
        Prepared = 1,
        Dispatching = 2,
    }
}

closed_enum_v2! {
    ActionIntentDispatchPhaseV2 {
        Prepared = 1,
        Dispatching = 2,
        CompletionCommitPending = 3,
    }
}

closed_enum_v2! {
    AgentContentStateV2 {
        Ready = 1,
        Running = 2,
        AwaitingApproval = 3,
        Closed = 4,
        Failed = 5,
        Indeterminate = 6,
    }
}

closed_enum_v2! {
    VaultPublicStateV2 {
        Pending = 1,
        Live = 2,
        ReleaseAuthorized = 3,
        Dispatching = 4,
        Released = 5,
        FailedNoEffect = 6,
        Revoked = 7,
        Expired = 8,
        Indeterminate = 9,
        RestartInvalidated = 10,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlannerLimitsV2 {
    maximum_steps: u16,
    maximum_dependencies_per_step: u16,
    maximum_arguments_per_step: u16,
    maximum_encoded_plan_bytes: u32,
}

impl PlannerLimitsV2 {
    pub fn new(
        maximum_steps: u16,
        maximum_dependencies_per_step: u16,
        maximum_arguments_per_step: u16,
        maximum_encoded_plan_bytes: u32,
    ) -> Result<Self, ProtocolError> {
        if maximum_steps == 0
            || maximum_steps as usize > MAX_PLANNER_ITEMS_V2
            || maximum_dependencies_per_step == 0
            || maximum_arguments_per_step == 0
            || maximum_encoded_plan_bytes == 0
            || maximum_encoded_plan_bytes as usize > MAX_AGENT_VIEW_TEXT_BYTES_V2
        {
            return Err(malformed());
        }
        Ok(Self {
            maximum_steps,
            maximum_dependencies_per_step,
            maximum_arguments_per_step,
            maximum_encoded_plan_bytes,
        })
    }
}

impl<C> minicbor::Encode<C> for PlannerLimitsV2 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        _context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        encoder
            .array(4)?
            .u16(self.maximum_steps)?
            .u16(self.maximum_dependencies_per_step)?
            .u16(self.maximum_arguments_per_step)?
            .u32(self.maximum_encoded_plan_bytes)?;
        Ok(())
    }
}

impl<'bytes> minicbor::Decode<'bytes, V2DecodeContext> for PlannerLimitsV2 {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        _context: &mut V2DecodeContext,
    ) -> Result<Self, minicbor::decode::Error> {
        let position = decoder.position();
        if decoder.array()? != Some(4) {
            return Err(decode_error(position));
        }
        Self::new(
            decoder.u16()?,
            decoder.u16()?,
            decoder.u16()?,
            decoder.u32()?,
        )
        .map_err(|_| decode_error(position))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlannerAbstractSlotV2 {
    reference: PlannerSlotRefV2,
    kind: SlotKindV2,
    cardinality: PlannerSlotCardinalityV2,
    confidentiality: PlannerSlotConfidentialityV2,
}

impl PlannerAbstractSlotV2 {
    pub fn new(
        reference: PlannerSlotRefV2,
        kind: SlotKindV2,
        cardinality: PlannerSlotCardinalityV2,
        confidentiality: PlannerSlotConfidentialityV2,
    ) -> Result<Self, ProtocolError> {
        if is_zero(reference.as_bytes()) || kind.get() == 0 {
            return Err(malformed());
        }
        Ok(Self {
            reference,
            kind,
            cardinality,
            confidentiality,
        })
    }

    pub const fn reference(self) -> PlannerSlotRefV2 {
        self.reference
    }

    pub const fn kind(self) -> SlotKindV2 {
        self.kind
    }

    pub const fn cardinality(self) -> PlannerSlotCardinalityV2 {
        self.cardinality
    }

    pub const fn confidentiality(self) -> PlannerSlotConfidentialityV2 {
        self.confidentiality
    }
}

impl<C> minicbor::Encode<C> for PlannerAbstractSlotV2 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        encoder.array(4)?;
        self.reference.encode(encoder, context)?;
        self.kind.encode(encoder, context)?;
        self.cardinality.encode(encoder, context)?;
        self.confidentiality.encode(encoder, context)?;
        Ok(())
    }
}

impl<'bytes> minicbor::Decode<'bytes, V2DecodeContext> for PlannerAbstractSlotV2 {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        context: &mut V2DecodeContext,
    ) -> Result<Self, minicbor::decode::Error> {
        let position = decoder.position();
        if decoder.array()? != Some(4) {
            return Err(decode_error(position));
        }
        Self::new(
            minicbor::Decode::decode(decoder, context)?,
            minicbor::Decode::decode(decoder, context)?,
            minicbor::Decode::decode(decoder, context)?,
            minicbor::Decode::decode(decoder, context)?,
        )
        .map_err(|_| decode_error(position))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlannerAbstractRelationV2 {
    relation: RelationIdV2,
    left: PlannerSlotRefV2,
    right: PlannerSlotRefV2,
}

impl PlannerAbstractRelationV2 {
    pub fn new(
        relation: RelationIdV2,
        left: PlannerSlotRefV2,
        right: PlannerSlotRefV2,
    ) -> Result<Self, ProtocolError> {
        if relation.get() == 0 || is_zero(left.as_bytes()) || is_zero(right.as_bytes()) {
            return Err(malformed());
        }
        Ok(Self {
            relation,
            left,
            right,
        })
    }
}

impl<C> minicbor::Encode<C> for PlannerAbstractRelationV2 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        encoder.array(3)?;
        self.relation.encode(encoder, context)?;
        self.left.encode(encoder, context)?;
        self.right.encode(encoder, context)?;
        Ok(())
    }
}

impl<'bytes> minicbor::Decode<'bytes, V2DecodeContext> for PlannerAbstractRelationV2 {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        context: &mut V2DecodeContext,
    ) -> Result<Self, minicbor::decode::Error> {
        let position = decoder.position();
        if decoder.array()? != Some(3) {
            return Err(decode_error(position));
        }
        Self::new(
            minicbor::Decode::decode(decoder, context)?,
            minicbor::Decode::decode(decoder, context)?,
            minicbor::Decode::decode(decoder, context)?,
        )
        .map_err(|_| decode_error(position))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannerEnvelopeV2 {
    planner_route: PlannerRouteIdV2,
    task_template: StaticTemplateIdV2,
    intent: PlannerIntentKindV2,
    allowed_action_templates: Vec<ActionTemplateIdV2>,
    slots: Vec<PlannerAbstractSlotV2>,
    relations: Vec<PlannerAbstractRelationV2>,
    effective_limits: PlannerLimitsV2,
    envelope_nonce: Nonce32V2,
    expires_at: UnixMillisV2,
}

impl PlannerEnvelopeV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        planner_route: PlannerRouteIdV2,
        task_template: StaticTemplateIdV2,
        intent: PlannerIntentKindV2,
        allowed_action_templates: Vec<ActionTemplateIdV2>,
        slots: Vec<PlannerAbstractSlotV2>,
        relations: Vec<PlannerAbstractRelationV2>,
        effective_limits: PlannerLimitsV2,
        envelope_nonce: Nonce32V2,
        expires_at: UnixMillisV2,
    ) -> Result<Self, ProtocolError> {
        if planner_route.get() == 0
            || task_template.get() == 0
            || allowed_action_templates.len() > MAX_PLANNER_ITEMS_V2
            || allowed_action_templates
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            || slots.len() > MAX_PLANNER_ITEMS_V2
            || slots
                .windows(2)
                .any(|pair| pair[0].reference.as_bytes() >= pair[1].reference.as_bytes())
            || relations.len() > MAX_RELATIONS_V2
            || relations.windows(2).any(|pair| {
                (
                    pair[0].relation.get(),
                    pair[0].left.as_bytes(),
                    pair[0].right.as_bytes(),
                ) >= (
                    pair[1].relation.get(),
                    pair[1].left.as_bytes(),
                    pair[1].right.as_bytes(),
                )
            })
            || is_zero(envelope_nonce.as_bytes())
            || expires_at.get() == 0
        {
            return Err(malformed());
        }
        Ok(Self {
            planner_route,
            task_template,
            intent,
            allowed_action_templates,
            slots,
            relations,
            effective_limits,
            envelope_nonce,
            expires_at,
        })
    }

    pub const fn envelope_nonce(&self) -> Nonce32V2 {
        self.envelope_nonce
    }

    pub const fn expires_at(&self) -> UnixMillisV2 {
        self.expires_at
    }
}

impl<C> minicbor::Encode<C> for PlannerEnvelopeV2 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        encoder.array(10)?.u16(2)?;
        self.planner_route.encode(encoder, context)?;
        self.task_template.encode(encoder, context)?;
        self.intent.encode(encoder, context)?;
        encode_vec(encoder, context, &self.allowed_action_templates)?;
        encode_vec(encoder, context, &self.slots)?;
        encode_vec(encoder, context, &self.relations)?;
        self.effective_limits.encode(encoder, context)?;
        self.envelope_nonce.encode(encoder, context)?;
        self.expires_at.encode(encoder, context)?;
        Ok(())
    }
}

impl<'bytes> minicbor::Decode<'bytes, V2DecodeContext> for PlannerEnvelopeV2 {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        context: &mut V2DecodeContext,
    ) -> Result<Self, minicbor::decode::Error> {
        let position = decoder.position();
        if decoder.array()? != Some(10) || decoder.u16()? != 2 {
            return Err(decode_error(position));
        }
        Self::new(
            minicbor::Decode::decode(decoder, context)?,
            minicbor::Decode::decode(decoder, context)?,
            minicbor::Decode::decode(decoder, context)?,
            decode_vec(decoder, context, MAX_PLANNER_ITEMS_V2, position)?,
            decode_vec(decoder, context, MAX_PLANNER_ITEMS_V2, position)?,
            decode_vec(decoder, context, MAX_RELATIONS_V2, position)?,
            minicbor::Decode::decode(decoder, context)?,
            minicbor::Decode::decode(decoder, context)?,
            minicbor::Decode::decode(decoder, context)?,
        )
        .map_err(|_| decode_error(position))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparePlannerCallResponseV2 {
    ticket: PlannerTicketHandleV2,
    envelope: PlannerEnvelopeV2,
    envelope_digest: Digest32V2,
    expires_at: UnixMillisV2,
}

impl PreparePlannerCallResponseV2 {
    pub fn new(
        ticket: PlannerTicketHandleV2,
        envelope: PlannerEnvelopeV2,
        envelope_digest: Digest32V2,
        expires_at: UnixMillisV2,
    ) -> Result<Self, ProtocolError> {
        let canonical = minicbor::to_vec(&envelope).map_err(ProtocolError::malformed)?;
        let expected = Digest32V2::new(sha2::Sha256::digest(&canonical).into());
        if envelope_digest != expected || expires_at != envelope.expires_at || expires_at.get() == 0
        {
            return Err(malformed());
        }
        Ok(Self {
            ticket,
            envelope,
            envelope_digest,
            expires_at,
        })
    }

    pub const fn ticket(&self) -> PlannerTicketHandleV2 {
        self.ticket
    }

    pub const fn envelope(&self) -> &PlannerEnvelopeV2 {
        &self.envelope
    }
}

impl_struct_codec!(PreparePlannerCallResponseV2, 4, {
    ticket,
    envelope,
    envelope_digest,
    expires_at
});

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitPlannerValueResponseV2 {
    value: ValueHandleV2,
    value_digest: Digest32V2,
    plan_revision_digest: PlanRevisionDigestV2,
    steps: Vec<PlanStepHandleV2>,
}

impl CommitPlannerValueResponseV2 {
    pub fn new(
        value: ValueHandleV2,
        value_digest: Digest32V2,
        plan_revision_digest: PlanRevisionDigestV2,
        steps: Vec<PlanStepHandleV2>,
    ) -> Result<Self, ProtocolError> {
        if is_zero(value_digest.as_bytes())
            || is_zero(plan_revision_digest.as_bytes())
            || steps.len() > MAX_PLANNER_ITEMS_V2
        {
            return Err(malformed());
        }
        Ok(Self {
            value,
            value_digest,
            plan_revision_digest,
            steps,
        })
    }

    pub const fn value(&self) -> ValueHandleV2 {
        self.value
    }

    pub fn steps(&self) -> &[PlanStepHandleV2] {
        &self.steps
    }
}

impl<C> minicbor::Encode<C> for CommitPlannerValueResponseV2 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        encoder.array(4)?;
        self.value.encode(encoder, context)?;
        self.value_digest.encode(encoder, context)?;
        self.plan_revision_digest.encode(encoder, context)?;
        encode_vec(encoder, context, &self.steps)
    }
}

impl<'bytes> minicbor::Decode<'bytes, V2DecodeContext> for CommitPlannerValueResponseV2 {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        context: &mut V2DecodeContext,
    ) -> Result<Self, minicbor::decode::Error> {
        let position = decoder.position();
        if decoder.array()? != Some(4) {
            return Err(decode_error(position));
        }
        Self::new(
            minicbor::Decode::decode(decoder, context)?,
            minicbor::Decode::decode(decoder, context)?,
            minicbor::Decode::decode(decoder, context)?,
            decode_vec(decoder, context, MAX_PLANNER_ITEMS_V2, position)?,
        )
        .map_err(|_| decode_error(position))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicDecisionTraceV2 {
    decision_record_digest: Digest32V2,
}

impl PublicDecisionTraceV2 {
    pub fn new(decision_record_digest: Digest32V2) -> Result<Self, ProtocolError> {
        if is_zero(decision_record_digest.as_bytes()) {
            return Err(malformed());
        }
        Ok(Self {
            decision_record_digest,
        })
    }

    pub const fn decision_record_digest(self) -> Digest32V2 {
        self.decision_record_digest
    }
}

impl<C> minicbor::Encode<C> for PublicDecisionTraceV2 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        encoder.array(1)?;
        self.decision_record_digest.encode(encoder, context)
    }
}

impl<'bytes> minicbor::Decode<'bytes, V2DecodeContext> for PublicDecisionTraceV2 {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        context: &mut V2DecodeContext,
    ) -> Result<Self, minicbor::decode::Error> {
        let position = decoder.position();
        if decoder.array()? != Some(1) {
            return Err(decode_error(position));
        }
        Self::new(minicbor::Decode::decode(decoder, context)?).map_err(|_| decode_error(position))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionIntentTerminalSummaryV2 {
    Succeeded,
    EffectSucceededOutputQuarantined { class: PublicFailureClassV2 },
    FailedNoEffect { class: PublicFailureClassV2 },
    Indeterminate,
}

impl<C> minicbor::Encode<C> for ActionIntentTerminalSummaryV2 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        match self {
            Self::Succeeded => {
                encoder.array(1)?.u16(1)?;
            }
            Self::EffectSucceededOutputQuarantined { class } => {
                encoder.array(2)?.u16(2)?;
                class.encode(encoder, context)?;
            }
            Self::FailedNoEffect { class } => {
                encoder.array(2)?.u16(3)?;
                class.encode(encoder, context)?;
            }
            Self::Indeterminate => {
                encoder.array(1)?.u16(4)?;
            }
        }
        Ok(())
    }
}

impl<'bytes> minicbor::Decode<'bytes, V2DecodeContext> for ActionIntentTerminalSummaryV2 {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        context: &mut V2DecodeContext,
    ) -> Result<Self, minicbor::decode::Error> {
        let position = decoder.position();
        let count = decoder.array()?.ok_or_else(|| decode_error(position))?;
        match (count, decoder.u16()?) {
            (1, 1) => Ok(Self::Succeeded),
            (2, 2) => Ok(Self::EffectSucceededOutputQuarantined {
                class: minicbor::Decode::decode(decoder, context)?,
            }),
            (2, 3) => Ok(Self::FailedNoEffect {
                class: minicbor::Decode::decode(decoder, context)?,
            }),
            (1, 4) => Ok(Self::Indeterminate),
            _ => Err(decode_error(position)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionIntentCurrentStateV2 {
    Proposed {
        pending: PendingToolCallHandleV2,
    },
    Evaluating {
        pending: PendingToolCallHandleV2,
    },
    Denied {
        code: PublicStableCodeV2,
        trace: PublicDecisionTraceV2,
    },
    AwaitingApproval {
        pending: PendingToolCallHandleV2,
    },
    Authorized {
        ticket: ExecutionTicketHandleV2,
    },
    Dispatched {
        execution: ExecutionHandleV2,
        phase: ActionIntentDispatchPhaseV2,
    },
    Terminal {
        execution: ExecutionHandleV2,
        summary: ActionIntentTerminalSummaryV2,
    },
}

impl<C> minicbor::Encode<C> for ActionIntentCurrentStateV2 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        match self {
            Self::Proposed { pending } => {
                encoder.array(2)?.u16(1)?;
                pending.encode(encoder, context)?;
            }
            Self::Evaluating { pending } => {
                encoder.array(2)?.u16(2)?;
                pending.encode(encoder, context)?;
            }
            Self::Denied { code, trace } => {
                encoder.array(3)?.u16(3)?.u16(code.tag())?;
                trace.encode(encoder, context)?;
            }
            Self::AwaitingApproval { pending } => {
                encoder.array(2)?.u16(4)?;
                pending.encode(encoder, context)?;
            }
            Self::Authorized { ticket } => {
                encoder.array(2)?.u16(5)?;
                ticket.encode(encoder, context)?;
            }
            Self::Dispatched { execution, phase } => {
                encoder.array(3)?.u16(6)?;
                execution.encode(encoder, context)?;
                phase.encode(encoder, context)?;
            }
            Self::Terminal { execution, summary } => {
                encoder.array(3)?.u16(7)?;
                execution.encode(encoder, context)?;
                summary.encode(encoder, context)?;
            }
        }
        Ok(())
    }
}

impl<'bytes> minicbor::Decode<'bytes, V2DecodeContext> for ActionIntentCurrentStateV2 {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        context: &mut V2DecodeContext,
    ) -> Result<Self, minicbor::decode::Error> {
        let position = decoder.position();
        let count = decoder.array()?.ok_or_else(|| decode_error(position))?;
        match (count, decoder.u16()?) {
            (2, 1) => Ok(Self::Proposed {
                pending: minicbor::Decode::decode(decoder, context)?,
            }),
            (2, 2) => Ok(Self::Evaluating {
                pending: minicbor::Decode::decode(decoder, context)?,
            }),
            (3, 3) => Ok(Self::Denied {
                code: PublicStableCodeV2::from_tag(decoder.u16()?)
                    .map_err(|_| decode_error(position))?,
                trace: minicbor::Decode::decode(decoder, context)?,
            }),
            (2, 4) => Ok(Self::AwaitingApproval {
                pending: minicbor::Decode::decode(decoder, context)?,
            }),
            (2, 5) => Ok(Self::Authorized {
                ticket: minicbor::Decode::decode(decoder, context)?,
            }),
            (3, 6) => Ok(Self::Dispatched {
                execution: minicbor::Decode::decode(decoder, context)?,
                phase: minicbor::Decode::decode(decoder, context)?,
            }),
            (3, 7) => Ok(Self::Terminal {
                execution: minicbor::Decode::decode(decoder, context)?,
                summary: minicbor::Decode::decode(decoder, context)?,
            }),
            _ => Err(decode_error(position)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProposeToolCallResponseV2 {
    intent: ActionIntentHandleV2,
    current: ActionIntentCurrentStateV2,
}

impl ProposeToolCallResponseV2 {
    pub const fn new(intent: ActionIntentHandleV2, current: ActionIntentCurrentStateV2) -> Self {
        Self { intent, current }
    }

    pub const fn intent(self) -> ActionIntentHandleV2 {
        self.intent
    }

    pub const fn current(self) -> ActionIntentCurrentStateV2 {
        self.current
    }
}

impl_struct_codec!(ProposeToolCallResponseV2, 2, { intent, current });

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum EvaluateToolCallResponseV2 {
    Denied {
        code: PublicStableCodeV2,
        trace: PublicDecisionTraceV2,
    },
    NeedsApproval {
        approval: ToolKernelApprovalHandleV2,
        envelope: SignedApprovalEnvelopeV2,
        display_authentication: SignedUiAuthenticationEnvelopeV2,
        trace: PublicDecisionTraceV2,
    },
    Allowed {
        ticket: ExecutionTicketHandleV2,
        trace: PublicDecisionTraceV2,
    },
}

impl<C> minicbor::Encode<C> for EvaluateToolCallResponseV2 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        match self {
            Self::Denied { code, trace } => {
                encoder.array(3)?.u16(1)?.u16(code.tag())?;
                trace.encode(encoder, context)?;
            }
            Self::NeedsApproval {
                approval,
                envelope,
                display_authentication,
                trace,
            } => {
                encoder.array(5)?.u16(2)?;
                approval.encode(encoder, context)?;
                envelope.encode(encoder, context)?;
                display_authentication.encode(encoder, context)?;
                trace.encode(encoder, context)?;
            }
            Self::Allowed { ticket, trace } => {
                encoder.array(3)?.u16(3)?;
                ticket.encode(encoder, context)?;
                trace.encode(encoder, context)?;
            }
        }
        Ok(())
    }
}

impl<'bytes> minicbor::Decode<'bytes, V2DecodeContext> for EvaluateToolCallResponseV2 {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        context: &mut V2DecodeContext,
    ) -> Result<Self, minicbor::decode::Error> {
        let position = decoder.position();
        let count = decoder.array()?.ok_or_else(|| decode_error(position))?;
        match (count, decoder.u16()?) {
            (3, 1) => Ok(Self::Denied {
                code: PublicStableCodeV2::from_tag(decoder.u16()?)
                    .map_err(|_| decode_error(position))?,
                trace: minicbor::Decode::decode(decoder, context)?,
            }),
            (5, 2) => Ok(Self::NeedsApproval {
                approval: minicbor::Decode::decode(decoder, context)?,
                envelope: minicbor::Decode::decode(decoder, context)?,
                display_authentication: minicbor::Decode::decode(decoder, context)?,
                trace: minicbor::Decode::decode(decoder, context)?,
            }),
            (3, 3) => Ok(Self::Allowed {
                ticket: minicbor::Decode::decode(decoder, context)?,
                trace: minicbor::Decode::decode(decoder, context)?,
            }),
            _ => Err(decode_error(position)),
        }
    }
}

simple_handle_response!(AuthorizeToolCallResponseV2, ticket, ExecutionTicketHandleV2);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DispatchExecutionResponseV2 {
    execution: ExecutionHandleV2,
    status: PublicDispatchAcceptedStateV2,
}

impl DispatchExecutionResponseV2 {
    pub const fn new(execution: ExecutionHandleV2, status: PublicDispatchAcceptedStateV2) -> Self {
        Self { execution, status }
    }

    pub const fn execution(self) -> ExecutionHandleV2 {
        self.execution
    }

    pub const fn status(self) -> PublicDispatchAcceptedStateV2 {
        self.status
    }
}

impl_struct_codec!(DispatchExecutionResponseV2, 2, { execution, status });

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicDispatchCompletionV2 {
    ToolExecution { document: MaskedDocumentHandleV2 },
    FinalRelease,
}

impl<C> minicbor::Encode<C> for PublicDispatchCompletionV2 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        match self {
            Self::ToolExecution { document } => {
                encoder.array(2)?.u16(1)?;
                document.encode(encoder, context)?;
            }
            Self::FinalRelease => {
                encoder.array(1)?.u16(2)?;
            }
        }
        Ok(())
    }
}

impl<'bytes> minicbor::Decode<'bytes, V2DecodeContext> for PublicDispatchCompletionV2 {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        context: &mut V2DecodeContext,
    ) -> Result<Self, minicbor::decode::Error> {
        let position = decoder.position();
        match (
            decoder.array()?.ok_or_else(|| decode_error(position))?,
            decoder.u16()?,
        ) {
            (2, 1) => Ok(Self::ToolExecution {
                document: minicbor::Decode::decode(decoder, context)?,
            }),
            (1, 2) => Ok(Self::FinalRelease),
            _ => Err(decode_error(position)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicExecutionStatusV2 {
    Prepared,
    Dispatching,
    ResultGatePending,
    Succeeded {
        completion: PublicDispatchCompletionV2,
    },
    EffectSucceededOutputQuarantined {
        class: PublicFailureClassV2,
    },
    FailedNoEffect {
        class: PublicFailureClassV2,
    },
    Indeterminate,
}

impl<C> minicbor::Encode<C> for PublicExecutionStatusV2 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        match self {
            Self::Prepared => {
                encoder.array(1)?.u16(1)?;
            }
            Self::Dispatching => {
                encoder.array(1)?.u16(2)?;
            }
            Self::ResultGatePending => {
                encoder.array(1)?.u16(3)?;
            }
            Self::Succeeded { completion } => {
                encoder.array(2)?.u16(4)?;
                completion.encode(encoder, context)?;
            }
            Self::EffectSucceededOutputQuarantined { class } => {
                encoder.array(2)?.u16(5)?;
                class.encode(encoder, context)?;
            }
            Self::FailedNoEffect { class } => {
                encoder.array(2)?.u16(6)?;
                class.encode(encoder, context)?;
            }
            Self::Indeterminate => {
                encoder.array(1)?.u16(7)?;
            }
        }
        Ok(())
    }
}

impl<'bytes> minicbor::Decode<'bytes, V2DecodeContext> for PublicExecutionStatusV2 {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        context: &mut V2DecodeContext,
    ) -> Result<Self, minicbor::decode::Error> {
        let position = decoder.position();
        match (
            decoder.array()?.ok_or_else(|| decode_error(position))?,
            decoder.u16()?,
        ) {
            (1, 1) => Ok(Self::Prepared),
            (1, 2) => Ok(Self::Dispatching),
            (1, 3) => Ok(Self::ResultGatePending),
            (2, 4) => Ok(Self::Succeeded {
                completion: minicbor::Decode::decode(decoder, context)?,
            }),
            (2, 5) => Ok(Self::EffectSucceededOutputQuarantined {
                class: minicbor::Decode::decode(decoder, context)?,
            }),
            (2, 6) => Ok(Self::FailedNoEffect {
                class: minicbor::Decode::decode(decoder, context)?,
            }),
            (1, 7) => Ok(Self::Indeterminate),
            _ => Err(decode_error(position)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GetExecutionStatusResponseV2 {
    status: PublicExecutionStatusV2,
}

impl GetExecutionStatusResponseV2 {
    pub const fn new(status: PublicExecutionStatusV2) -> Self {
        Self { status }
    }

    pub const fn status(self) -> PublicExecutionStatusV2 {
        self.status
    }
}

impl_struct_codec!(GetExecutionStatusResponseV2, 1, { status });

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundedAgentTextV2(String);

impl BoundedAgentTextV2 {
    pub fn new(value: impl Into<String>) -> Result<Self, ProtocolError> {
        let value = value.into();
        if value.len() > MAX_AGENT_VIEW_TEXT_BYTES_V2
            || value.chars().any(|character| {
                character == '\0'
                    || matches!(character, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
            })
        {
            return Err(malformed());
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<C> minicbor::Encode<C> for BoundedAgentTextV2 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        _context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        encoder.str(&self.0)?;
        Ok(())
    }
}

impl<'bytes> minicbor::Decode<'bytes, V2DecodeContext> for BoundedAgentTextV2 {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        _context: &mut V2DecodeContext,
    ) -> Result<Self, minicbor::decode::Error> {
        let position = decoder.position();
        let text = decoder.str()?;
        if text.len() > MAX_AGENT_VIEW_TEXT_BYTES_V2 {
            return Err(decode_error(position));
        }
        Self::new(text).map_err(|_| decode_error(position))
    }
}

closed_enum_v2! {
    ClosedRedactionClassV2 {
        Confidential = 1,
        Credential = 2,
        PersonalData = 3,
        PolicyProtected = 4,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlaceholderViewV2 {
    ordinal: u32,
    token: BoundedAgentTextV2,
    redaction_class: ClosedRedactionClassV2,
}

impl PlaceholderViewV2 {
    pub fn new(
        ordinal: u32,
        token: BoundedAgentTextV2,
        redaction_class: ClosedRedactionClassV2,
    ) -> Result<Self, ProtocolError> {
        if token.as_str().is_empty() || token.as_str().len() > 1024 {
            return Err(malformed());
        }
        Ok(Self {
            ordinal,
            token,
            redaction_class,
        })
    }

    pub const fn ordinal(&self) -> u32 {
        self.ordinal
    }

    pub const fn token(&self) -> &BoundedAgentTextV2 {
        &self.token
    }

    pub const fn redaction_class(&self) -> ClosedRedactionClassV2 {
        self.redaction_class
    }
}

impl<C> minicbor::Encode<C> for PlaceholderViewV2 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        encoder.array(3)?.u32(self.ordinal)?;
        self.token.encode(encoder, context)?;
        self.redaction_class.encode(encoder, context)?;
        Ok(())
    }
}

impl<'bytes> minicbor::Decode<'bytes, V2DecodeContext> for PlaceholderViewV2 {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        context: &mut V2DecodeContext,
    ) -> Result<Self, minicbor::decode::Error> {
        let position = decoder.position();
        if decoder.array()? != Some(3) {
            return Err(decode_error(position));
        }
        Self::new(
            decoder.u32()?,
            minicbor::Decode::decode(decoder, context)?,
            minicbor::Decode::decode(decoder, context)?,
        )
        .map_err(|_| decode_error(position))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentViewFieldV2 {
    name: ArgumentNameV2,
    text: BoundedAgentTextV2,
    placeholders: Vec<PlaceholderViewV2>,
}

impl AgentViewFieldV2 {
    pub fn new(
        name: ArgumentNameV2,
        text: BoundedAgentTextV2,
        placeholders: Vec<PlaceholderViewV2>,
    ) -> Result<Self, ProtocolError> {
        validate_placeholders(&text, &placeholders)?;
        Ok(Self {
            name,
            text,
            placeholders,
        })
    }
}

impl<C> minicbor::Encode<C> for AgentViewFieldV2 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        encoder.array(3)?;
        self.name.encode(encoder, context)?;
        self.text.encode(encoder, context)?;
        encode_vec(encoder, context, &self.placeholders)
    }
}

impl<'bytes> minicbor::Decode<'bytes, V2DecodeContext> for AgentViewFieldV2 {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        context: &mut V2DecodeContext,
    ) -> Result<Self, minicbor::decode::Error> {
        let position = decoder.position();
        if decoder.array()? != Some(3) {
            return Err(decode_error(position));
        }
        Self::new(
            minicbor::Decode::decode(decoder, context)?,
            minicbor::Decode::decode(decoder, context)?,
            decode_vec(decoder, context, MAX_AGENT_VIEW_PLACEHOLDERS_V2, position)?,
        )
        .map_err(|_| decode_error(position))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentViewV2 {
    MaskedText {
        text: BoundedAgentTextV2,
        placeholders: Vec<PlaceholderViewV2>,
    },
    Structured {
        template: StaticTemplateIdV2,
        fields: Vec<AgentViewFieldV2>,
    },
    DocumentPage {
        page_index: u32,
        text: BoundedAgentTextV2,
        placeholders: Vec<PlaceholderViewV2>,
    },
    ContentState(AgentContentStateV2),
}

impl AgentViewV2 {
    pub fn masked_text(
        text: BoundedAgentTextV2,
        placeholders: Vec<PlaceholderViewV2>,
    ) -> Result<Self, ProtocolError> {
        validate_placeholders(&text, &placeholders)?;
        Ok(Self::MaskedText { text, placeholders })
    }
}

impl<C> minicbor::Encode<C> for AgentViewV2 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        match self {
            Self::MaskedText { text, placeholders } => {
                encoder.array(3)?.u16(1)?;
                text.encode(encoder, context)?;
                encode_vec(encoder, context, placeholders)?;
            }
            Self::Structured { template, fields } => {
                encoder.array(3)?.u16(2)?;
                template.encode(encoder, context)?;
                encode_vec(encoder, context, fields)?;
            }
            Self::DocumentPage {
                page_index,
                text,
                placeholders,
            } => {
                encoder.array(4)?.u16(3)?.u32(*page_index)?;
                text.encode(encoder, context)?;
                encode_vec(encoder, context, placeholders)?;
            }
            Self::ContentState(state) => {
                encoder.array(2)?.u16(4)?;
                state.encode(encoder, context)?;
            }
        }
        Ok(())
    }
}

impl<'bytes> minicbor::Decode<'bytes, V2DecodeContext> for AgentViewV2 {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        context: &mut V2DecodeContext,
    ) -> Result<Self, minicbor::decode::Error> {
        let position = decoder.position();
        let count = decoder.array()?.ok_or_else(|| decode_error(position))?;
        let value = match (count, decoder.u16()?) {
            (3, 1) => Self::masked_text(
                minicbor::Decode::decode(decoder, context)?,
                decode_vec(decoder, context, MAX_AGENT_VIEW_PLACEHOLDERS_V2, position)?,
            )
            .map_err(|_| decode_error(position))?,
            (3, 2) => {
                let template: StaticTemplateIdV2 = minicbor::Decode::decode(decoder, context)?;
                let fields = decode_vec(decoder, context, MAX_AGENT_VIEW_FIELDS_V2, position)?;
                if template.get() == 0 {
                    return Err(decode_error(position));
                }
                Self::Structured { template, fields }
            }
            (4, 3) => {
                let page_index = decoder.u32()?;
                let text = minicbor::Decode::decode(decoder, context)?;
                let placeholders =
                    decode_vec(decoder, context, MAX_AGENT_VIEW_PLACEHOLDERS_V2, position)?;
                validate_placeholders(&text, &placeholders).map_err(|_| decode_error(position))?;
                Self::DocumentPage {
                    page_index,
                    text,
                    placeholders,
                }
            }
            (2, 4) => Self::ContentState(minicbor::Decode::decode(decoder, context)?),
            _ => return Err(decode_error(position)),
        };
        Ok(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadAgentViewResponseV2 {
    view: AgentViewV2,
    next: Option<KernelAgentViewCursorV2>,
}

impl ReadAgentViewResponseV2 {
    pub const fn new(view: AgentViewV2, next: Option<KernelAgentViewCursorV2>) -> Self {
        Self { view, next }
    }

    pub const fn view(&self) -> &AgentViewV2 {
        &self.view
    }

    pub const fn next(&self) -> Option<KernelAgentViewCursorV2> {
        self.next
    }
}

impl<C> minicbor::Encode<C> for ReadAgentViewResponseV2 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        encoder.array(2)?;
        self.view.encode(encoder, context)?;
        encode_option(encoder, context, self.next.as_ref())
    }
}

impl<'bytes> minicbor::Decode<'bytes, V2DecodeContext> for ReadAgentViewResponseV2 {
    fn decode(
        decoder: &mut minicbor::Decoder<'bytes>,
        context: &mut V2DecodeContext,
    ) -> Result<Self, minicbor::decode::Error> {
        let position = decoder.position();
        if decoder.array()? != Some(2) {
            return Err(decode_error(position));
        }
        Ok(Self::new(
            minicbor::Decode::decode(decoder, context)?,
            decode_option(decoder, context)?,
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrepareReleaseResponseV2 {
    pending: PendingReleaseHandleV2,
    approval: ReleaseKernelApprovalHandleV2,
    envelope: SignedApprovalEnvelopeV2,
    display_authentication: SignedUiAuthenticationEnvelopeV2,
}

impl PrepareReleaseResponseV2 {
    pub const fn new(
        pending: PendingReleaseHandleV2,
        approval: ReleaseKernelApprovalHandleV2,
        envelope: SignedApprovalEnvelopeV2,
        display_authentication: SignedUiAuthenticationEnvelopeV2,
    ) -> Self {
        Self {
            pending,
            approval,
            envelope,
            display_authentication,
        }
    }

    pub const fn pending(&self) -> PendingReleaseHandleV2 {
        self.pending
    }

    pub const fn approval(&self) -> ReleaseKernelApprovalHandleV2 {
        self.approval
    }

    pub const fn envelope(&self) -> &SignedApprovalEnvelopeV2 {
        &self.envelope
    }

    pub const fn display_authentication(&self) -> &SignedUiAuthenticationEnvelopeV2 {
        &self.display_authentication
    }
}

impl_struct_codec!(PrepareReleaseResponseV2, 4, {
    pending,
    approval,
    envelope,
    display_authentication
});

simple_handle_response!(AuthorizeReleaseResponseV2, ticket, ReleaseTicketHandleV2);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DispatchReleaseResponseV2 {
    release: ReleaseHandleV2,
    status: PublicDispatchAcceptedStateV2,
}

impl DispatchReleaseResponseV2 {
    pub const fn new(release: ReleaseHandleV2, status: PublicDispatchAcceptedStateV2) -> Self {
        Self { release, status }
    }

    pub const fn release(self) -> ReleaseHandleV2 {
        self.release
    }

    pub const fn status(self) -> PublicDispatchAcceptedStateV2 {
        self.status
    }
}

impl_struct_codec!(DispatchReleaseResponseV2, 2, { release, status });

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GetReleaseStatusResponseV2 {
    status: PublicExecutionStatusV2,
}

impl GetReleaseStatusResponseV2 {
    pub const fn new(status: PublicExecutionStatusV2) -> Self {
        Self { status }
    }

    pub const fn status(self) -> PublicExecutionStatusV2 {
        self.status
    }
}

impl_struct_codec!(GetReleaseStatusResponseV2, 1, { status });

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RevokeVaultResponseV2 {
    state: VaultPublicStateV2,
}

impl RevokeVaultResponseV2 {
    pub const fn new(state: VaultPublicStateV2) -> Self {
        Self { state }
    }

    pub const fn state(self) -> VaultPublicStateV2 {
        self.state
    }
}

impl_struct_codec!(RevokeVaultResponseV2, 1, { state });

macro_rules! response_codec {
    ($encode:ident, $decode:ident, $type:ty) => {
        pub fn $encode(value: &$type) -> Result<Vec<u8>, ProtocolError> {
            minicbor::to_vec(value).map_err(ProtocolError::malformed)
        }

        pub fn $decode(bytes: &[u8]) -> Result<$type, ProtocolError> {
            scan_single(bytes)?;
            let mut decoder = minicbor::Decoder::new(bytes);
            let mut context = V2DecodeContext;
            let value: $type = minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?;
            let canonical = $encode(&value)?;
            if decoder.position() != bytes.len() || canonical != bytes {
                return Err(malformed());
            }
            Ok(value)
        }
    };
}

response_codec!(
    encode_resume_committed_agent_authentication_response_v2,
    decode_resume_committed_agent_authentication_response_v2,
    ResumeCommittedAgentAuthenticationResponseV2
);
response_codec!(
    encode_prepare_planner_call_response_v2,
    decode_prepare_planner_call_response_v2,
    PreparePlannerCallResponseV2
);
response_codec!(
    encode_commit_planner_value_response_v2,
    decode_commit_planner_value_response_v2,
    CommitPlannerValueResponseV2
);
response_codec!(
    encode_propose_tool_call_response_v2,
    decode_propose_tool_call_response_v2,
    ProposeToolCallResponseV2
);
response_codec!(
    encode_evaluate_tool_call_response_v2,
    decode_evaluate_tool_call_response_v2,
    EvaluateToolCallResponseV2
);
response_codec!(
    encode_authorize_tool_call_response_v2,
    decode_authorize_tool_call_response_v2,
    AuthorizeToolCallResponseV2
);
response_codec!(
    encode_dispatch_execution_response_v2,
    decode_dispatch_execution_response_v2,
    DispatchExecutionResponseV2
);
response_codec!(
    encode_get_execution_status_response_v2,
    decode_get_execution_status_response_v2,
    GetExecutionStatusResponseV2
);
response_codec!(
    encode_read_agent_view_response_v2,
    decode_read_agent_view_response_v2,
    ReadAgentViewResponseV2
);
response_codec!(
    encode_prepare_release_response_v2,
    decode_prepare_release_response_v2,
    PrepareReleaseResponseV2
);
response_codec!(
    encode_authorize_release_response_v2,
    decode_authorize_release_response_v2,
    AuthorizeReleaseResponseV2
);
response_codec!(
    encode_dispatch_release_response_v2,
    decode_dispatch_release_response_v2,
    DispatchReleaseResponseV2
);
response_codec!(
    encode_get_release_status_response_v2,
    decode_get_release_status_response_v2,
    GetReleaseStatusResponseV2
);
response_codec!(
    encode_revoke_vault_response_v2,
    decode_revoke_vault_response_v2,
    RevokeVaultResponseV2
);

fn validate_placeholders(
    text: &BoundedAgentTextV2,
    placeholders: &[PlaceholderViewV2],
) -> Result<(), ProtocolError> {
    if placeholders.len() > MAX_AGENT_VIEW_PLACEHOLDERS_V2
        || placeholders.iter().enumerate().any(|(index, placeholder)| {
            placeholder.ordinal != index as u32
                || !text.as_str().contains(placeholder.token.as_str())
        })
    {
        return Err(malformed());
    }
    Ok(())
}

fn encode_vec<C, W, T>(
    encoder: &mut minicbor::Encoder<W>,
    context: &mut C,
    values: &[T],
) -> Result<(), minicbor::encode::Error<W::Error>>
where
    W: minicbor::encode::Write,
    T: minicbor::Encode<C>,
{
    encoder.array(values.len() as u64)?;
    for value in values {
        value.encode(encoder, context)?;
    }
    Ok(())
}

fn decode_vec<'bytes, T>(
    decoder: &mut minicbor::Decoder<'bytes>,
    context: &mut V2DecodeContext,
    maximum: usize,
    position: usize,
) -> Result<Vec<T>, minicbor::decode::Error>
where
    T: minicbor::Decode<'bytes, V2DecodeContext>,
{
    let count = decoder
        .array()?
        .and_then(|count| usize::try_from(count).ok())
        .ok_or_else(|| decode_error(position))?;
    if count > maximum {
        return Err(decode_error(position));
    }
    let mut values = Vec::new();
    values
        .try_reserve_exact(count)
        .map_err(|_| decode_error(position))?;
    for _ in 0..count {
        values.push(minicbor::Decode::decode(decoder, context)?);
    }
    Ok(values)
}

fn encode_option<C, W, T>(
    encoder: &mut minicbor::Encoder<W>,
    context: &mut C,
    value: Option<&T>,
) -> Result<(), minicbor::encode::Error<W::Error>>
where
    W: minicbor::encode::Write,
    T: minicbor::Encode<C>,
{
    match value {
        Some(value) => value.encode(encoder, context),
        None => {
            encoder.null()?;
            Ok(())
        }
    }
}

fn decode_option<'bytes, T>(
    decoder: &mut minicbor::Decoder<'bytes>,
    context: &mut V2DecodeContext,
) -> Result<Option<T>, minicbor::decode::Error>
where
    T: minicbor::Decode<'bytes, V2DecodeContext>,
{
    if decoder.datatype()? == minicbor::data::Type::Null {
        decoder.null()?;
        Ok(None)
    } else {
        minicbor::Decode::decode(decoder, context).map(Some)
    }
}

fn malformed() -> ProtocolError {
    ProtocolError::stable(StableCode::ProtocolMalformedCbor)
}

fn decode_error(position: usize) -> minicbor::decode::Error {
    minicbor::decode::Error::message(StableCode::ProtocolMalformedCbor.as_str()).at(position)
}

fn is_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}
