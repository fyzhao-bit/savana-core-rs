use std::collections::{HashMap, HashSet, VecDeque};

use savana_kernel_protocol::v2::{
    encode_planner_plan_v2, ActionTemplateIdV2, ActiveToolViewV2, ArgumentNameV2,
    PlannerAbstractRelationV2, PlannerAbstractSlotV2, PlannerEnvelopeV2, PlannerIntentKindV2,
    PlannerLimitsV2, PlannerPlanV2, PlannerSlotRefV2, PlannerStepV2, StaticTemplateIdV2,
    ToolClassIdV2, V2DecodeContext,
};
use savana_policy_core::v2::EffectSetV2;
use sha2::{Digest as _, Sha256};

use crate::planner_catalog::{BoundedPlannerSemanticTextV2, PlannerCatalogEntryV2};

pub const MAX_STRUCTURAL_NODES_V2: usize = 256;
pub const MAX_STRUCTURAL_EDGES_V2: usize = 4096;
const MAX_MODEL_BODY_BYTES_V2: usize = 8 * 1024 * 1024;
const MAX_MAPPER_CATALOG_TOOLS_V2: usize = 4096;
const MAX_MAPPER_RELATIONS_V2: usize = 512;
const MAX_MAPPER_SEMANTIC_TEXT_BYTES_V2: usize = 1024;
const MAX_FRESH_ID_ATTEMPTS_V2: usize = 32;
const STRUCTURAL_NODE_ID_DOMAIN_V2: &[u8] = b"SAVANA_STRUCTURAL_NODE_ID_V2\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PlannerPrivacyErrorV2 {
    #[error("planner privacy object is invalid")]
    Invalid,
    #[error("planner privacy object is non-canonical")]
    NonCanonical,
    #[error("planner privacy entropy is unavailable")]
    EntropyUnavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum IntentTrustDeploymentCeilingV2 {
    PrivateOnly = 1,
    UserMayUseThirdParty = 2,
}

impl IntentTrustDeploymentCeilingV2 {
    pub const fn from_tag(tag: u16) -> Result<Self, PlannerPrivacyErrorV2> {
        match tag {
            1 => Ok(Self::PrivateOnly),
            2 => Ok(Self::UserMayUseThirdParty),
            _ => Err(PlannerPrivacyErrorV2::Invalid),
        }
    }

    pub const fn permits(self, boundary: IntentTrustBoundaryV2) -> bool {
        matches!(boundary, IntentTrustBoundaryV2::Private)
            || matches!(self, Self::UserMayUseThirdParty)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntentTrustBoundaryV2 {
    Private,
    ThirdParty,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum StructuralRoleV2 {
    Source = 1,
    Transform = 2,
    Sink = 3,
}

impl StructuralRoleV2 {
    const fn tag(self) -> u16 {
        self as u16
    }

    fn from_tag(tag: u16) -> Result<Self, PlannerPrivacyErrorV2> {
        match tag {
            1 => Ok(Self::Source),
            2 => Ok(Self::Transform),
            3 => Ok(Self::Sink),
            _ => Err(PlannerPrivacyErrorV2::Invalid),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StructuralNodeIdV2([u8; 16]);

impl StructuralNodeIdV2 {
    pub fn new(bytes: [u8; 16]) -> Result<Self, PlannerPrivacyErrorV2> {
        if bytes == [0; 16] {
            return Err(PlannerPrivacyErrorV2::Invalid);
        }
        Ok(Self(bytes))
    }

    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StructuralNodeV2 {
    id: StructuralNodeIdV2,
    role: StructuralRoleV2,
    effect_class: EffectSetV2,
    in_arity: u8,
    out_arity: u8,
}

impl StructuralNodeV2 {
    pub fn new(
        id: StructuralNodeIdV2,
        role: StructuralRoleV2,
        effect_class: EffectSetV2,
        in_arity: u8,
        out_arity: u8,
    ) -> Result<Self, PlannerPrivacyErrorV2> {
        validate_role_effect(role, effect_class)?;
        Ok(Self {
            id,
            role,
            effect_class,
            in_arity,
            out_arity,
        })
    }

    pub const fn id(&self) -> StructuralNodeIdV2 {
        self.id
    }

    pub const fn role(&self) -> StructuralRoleV2 {
        self.role
    }

    pub const fn effect_class(&self) -> EffectSetV2 {
        self.effect_class
    }

    pub const fn in_arity(&self) -> u8 {
        self.in_arity
    }

    pub const fn out_arity(&self) -> u8 {
        self.out_arity
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StructuralEdgeV2 {
    from: StructuralNodeIdV2,
    to: StructuralNodeIdV2,
}

impl StructuralEdgeV2 {
    pub fn new(
        from: StructuralNodeIdV2,
        to: StructuralNodeIdV2,
    ) -> Result<Self, PlannerPrivacyErrorV2> {
        if from == to {
            return Err(PlannerPrivacyErrorV2::Invalid);
        }
        Ok(Self { from, to })
    }

    pub const fn from(&self) -> StructuralNodeIdV2 {
        self.from
    }

    pub const fn to(&self) -> StructuralNodeIdV2 {
        self.to
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructuralGraphV2 {
    nodes: Vec<StructuralNodeV2>,
    edges: Vec<StructuralEdgeV2>,
}

impl StructuralGraphV2 {
    pub fn new(
        nodes: Vec<StructuralNodeV2>,
        edges: Vec<StructuralEdgeV2>,
    ) -> Result<Self, PlannerPrivacyErrorV2> {
        if nodes.is_empty()
            || nodes.len() > MAX_STRUCTURAL_NODES_V2
            || edges.len() > MAX_STRUCTURAL_EDGES_V2
        {
            return Err(PlannerPrivacyErrorV2::Invalid);
        }
        let indices = unique_structural_indices(&nodes)?;
        let mut seen_edges = HashSet::with_capacity(edges.len());
        let mut incoming = vec![0_usize; nodes.len()];
        let mut outgoing = vec![0_usize; nodes.len()];
        let mut adjacency = vec![Vec::new(); nodes.len()];
        for edge in &edges {
            let Some(&from) = indices.get(&edge.from) else {
                return Err(PlannerPrivacyErrorV2::Invalid);
            };
            let Some(&to) = indices.get(&edge.to) else {
                return Err(PlannerPrivacyErrorV2::Invalid);
            };
            if from == to || !seen_edges.insert(*edge) {
                return Err(PlannerPrivacyErrorV2::Invalid);
            }
            outgoing[from] += 1;
            incoming[to] += 1;
            adjacency[from].push(to);
        }
        if incoming.iter().any(|value| *value > usize::from(u8::MAX))
            || outgoing.iter().any(|value| *value > usize::from(u8::MAX))
            || nodes.iter().enumerate().any(|(index, node)| {
                usize::from(node.in_arity) != incoming[index]
                    || usize::from(node.out_arity) != outgoing[index]
            })
            || !is_acyclic(&adjacency, &incoming)
        {
            return Err(PlannerPrivacyErrorV2::Invalid);
        }
        Ok(Self { nodes, edges })
    }

    pub fn nodes(&self) -> &[StructuralNodeV2] {
        &self.nodes
    }

    pub fn edges(&self) -> &[StructuralEdgeV2] {
        &self.edges
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum StructuralGoalV2 {
    OrderValidDataflow = 1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructuralPlannerRequestV2 {
    graph: StructuralGraphV2,
    goal: StructuralGoalV2,
}

impl StructuralPlannerRequestV2 {
    pub const fn new(graph: StructuralGraphV2, goal: StructuralGoalV2) -> Self {
        Self { graph, goal }
    }

    pub const fn graph(&self) -> &StructuralGraphV2 {
        &self.graph
    }

    pub const fn goal(&self) -> StructuralGoalV2 {
        self.goal
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrderedStructuralPlanV2 {
    ordered_nodes: Vec<StructuralNodeIdV2>,
}

impl OrderedStructuralPlanV2 {
    pub fn new(ordered_nodes: Vec<StructuralNodeIdV2>) -> Result<Self, PlannerPrivacyErrorV2> {
        if ordered_nodes.len() > MAX_STRUCTURAL_NODES_V2 {
            return Err(PlannerPrivacyErrorV2::Invalid);
        }
        Ok(Self { ordered_nodes })
    }

    pub fn ordered_nodes(&self) -> &[StructuralNodeIdV2] {
        &self.ordered_nodes
    }
}

pub fn encode_structural_planner_request_v2(
    request: &StructuralPlannerRequestV2,
) -> Result<Vec<u8>, PlannerPrivacyErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(4)
        .and_then(|encoder| encoder.u16(2))
        .map_err(|_| PlannerPrivacyErrorV2::Invalid)?;
    encode_structural_nodes(&mut encoder, &request.graph.nodes)?;
    encode_structural_edges(&mut encoder, &request.graph.edges)?;
    encoder
        .u16(request.goal as u16)
        .map_err(|_| PlannerPrivacyErrorV2::Invalid)?;
    let bytes = encoder.into_writer();
    if bytes.len() > MAX_MODEL_BODY_BYTES_V2 {
        return Err(PlannerPrivacyErrorV2::Invalid);
    }
    Ok(bytes)
}

pub fn decode_structural_planner_request_v2(
    bytes: &[u8],
) -> Result<StructuralPlannerRequestV2, PlannerPrivacyErrorV2> {
    if bytes.is_empty() || bytes.len() > MAX_MODEL_BODY_BYTES_V2 {
        return Err(PlannerPrivacyErrorV2::Invalid);
    }
    let mut decoder = minicbor::Decoder::new(bytes);
    if decoder.array().map_err(decode_failure)? != Some(4)
        || decoder.u16().map_err(decode_failure)? != 2
    {
        return Err(PlannerPrivacyErrorV2::Invalid);
    }
    let node_count = definite_length(&mut decoder, MAX_STRUCTURAL_NODES_V2)?;
    if node_count == 0 {
        return Err(PlannerPrivacyErrorV2::Invalid);
    }
    let mut nodes = Vec::with_capacity(node_count);
    for _ in 0..node_count {
        if decoder.array().map_err(decode_failure)? != Some(5) {
            return Err(PlannerPrivacyErrorV2::Invalid);
        }
        let id = decode_structural_id(&mut decoder)?;
        let role = StructuralRoleV2::from_tag(decoder.u16().map_err(decode_failure)?)?;
        let effects = EffectSetV2::from_bits(decoder.u16().map_err(decode_failure)?)
            .ok_or(PlannerPrivacyErrorV2::Invalid)?;
        let in_arity = decoder.u8().map_err(decode_failure)?;
        let out_arity = decoder.u8().map_err(decode_failure)?;
        nodes.push(StructuralNodeV2::new(
            id, role, effects, in_arity, out_arity,
        )?);
    }
    let edge_count = definite_length(&mut decoder, MAX_STRUCTURAL_EDGES_V2)?;
    let mut edges = Vec::with_capacity(edge_count);
    for _ in 0..edge_count {
        if decoder.array().map_err(decode_failure)? != Some(2) {
            return Err(PlannerPrivacyErrorV2::Invalid);
        }
        edges.push(StructuralEdgeV2::new(
            decode_structural_id(&mut decoder)?,
            decode_structural_id(&mut decoder)?,
        )?);
    }
    if decoder.u16().map_err(decode_failure)? != StructuralGoalV2::OrderValidDataflow as u16
        || decoder.position() != bytes.len()
    {
        return Err(PlannerPrivacyErrorV2::Invalid);
    }
    let value = StructuralPlannerRequestV2::new(
        StructuralGraphV2::new(nodes, edges)?,
        StructuralGoalV2::OrderValidDataflow,
    );
    if encode_structural_planner_request_v2(&value)? != bytes {
        return Err(PlannerPrivacyErrorV2::NonCanonical);
    }
    Ok(value)
}

pub fn encode_ordered_structural_plan_v2(
    plan: &OrderedStructuralPlanV2,
) -> Result<Vec<u8>, PlannerPrivacyErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(2)
        .and_then(|encoder| encoder.u16(2))
        .and_then(|encoder| encoder.array(plan.ordered_nodes.len() as u64))
        .map_err(|_| PlannerPrivacyErrorV2::Invalid)?;
    for id in &plan.ordered_nodes {
        encoder
            .bytes(id.as_bytes())
            .map_err(|_| PlannerPrivacyErrorV2::Invalid)?;
    }
    Ok(encoder.into_writer())
}

pub fn decode_ordered_structural_plan_v2(
    bytes: &[u8],
) -> Result<OrderedStructuralPlanV2, PlannerPrivacyErrorV2> {
    if bytes.is_empty() || bytes.len() > MAX_MODEL_BODY_BYTES_V2 {
        return Err(PlannerPrivacyErrorV2::Invalid);
    }
    let mut decoder = minicbor::Decoder::new(bytes);
    if decoder.array().map_err(decode_failure)? != Some(2)
        || decoder.u16().map_err(decode_failure)? != 2
    {
        return Err(PlannerPrivacyErrorV2::Invalid);
    }
    let count = definite_length(&mut decoder, MAX_STRUCTURAL_NODES_V2)?;
    let mut ordered_nodes = Vec::with_capacity(count);
    for _ in 0..count {
        ordered_nodes.push(decode_structural_id(&mut decoder)?);
    }
    if decoder.position() != bytes.len() {
        return Err(PlannerPrivacyErrorV2::Invalid);
    }
    let value = OrderedStructuralPlanV2::new(ordered_nodes)?;
    if encode_ordered_structural_plan_v2(&value)? != bytes {
        return Err(PlannerPrivacyErrorV2::NonCanonical);
    }
    Ok(value)
}

/// Decode a planner response and bind it to the exact request graph.
///
/// A syntactically valid ordering is not sufficient: it must be a complete,
/// duplicate-free permutation of the request node identifiers and preserve
/// every dataflow edge. Keeping this check at the remote-response boundary
/// prevents an untrusted planner from substituting or omitting nodes.
pub fn decode_ordered_structural_plan_for_request_v2(
    bytes: &[u8],
    request: &StructuralPlannerRequestV2,
) -> Result<OrderedStructuralPlanV2, PlannerPrivacyErrorV2> {
    let plan = decode_ordered_structural_plan_v2(bytes)?;
    validate_ordered_structural_plan_v2(request, &plan)?;
    Ok(plan)
}

pub fn validate_ordered_structural_plan_v2(
    request: &StructuralPlannerRequestV2,
    plan: &OrderedStructuralPlanV2,
) -> Result<(), PlannerPrivacyErrorV2> {
    if plan.ordered_nodes.len() != request.graph.nodes.len() {
        return Err(PlannerPrivacyErrorV2::Invalid);
    }
    let request_ids = request
        .graph
        .nodes
        .iter()
        .map(StructuralNodeV2::id)
        .collect::<HashSet<_>>();
    let mut positions = HashMap::with_capacity(plan.ordered_nodes.len());
    for (position, id) in plan.ordered_nodes.iter().copied().enumerate() {
        if !request_ids.contains(&id) || positions.insert(id, position).is_some() {
            return Err(PlannerPrivacyErrorV2::Invalid);
        }
    }
    for edge in &request.graph.edges {
        let from = positions
            .get(&edge.from)
            .ok_or(PlannerPrivacyErrorV2::Invalid)?;
        let to = positions
            .get(&edge.to)
            .ok_or(PlannerPrivacyErrorV2::Invalid)?;
        if from >= to {
            return Err(PlannerPrivacyErrorV2::Invalid);
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapperCatalogToolV2 {
    tool_class: ToolClassIdV2,
    action_template: ActionTemplateIdV2,
    structural_role: StructuralRoleV2,
    effect_class: EffectSetV2,
    semantic_name: BoundedPlannerSemanticTextV2,
    semantic_description: BoundedPlannerSemanticTextV2,
}

impl MapperCatalogToolV2 {
    pub fn new(
        tool_class: ToolClassIdV2,
        action_template: ActionTemplateIdV2,
        structural_role: StructuralRoleV2,
        effect_class: EffectSetV2,
        semantic_name: BoundedPlannerSemanticTextV2,
        semantic_description: BoundedPlannerSemanticTextV2,
    ) -> Result<Self, PlannerPrivacyErrorV2> {
        if tool_class.get() == 0 || action_template.get() == 0 {
            return Err(PlannerPrivacyErrorV2::Invalid);
        }
        validate_role_effect(structural_role, effect_class)?;
        Ok(Self {
            tool_class,
            action_template,
            structural_role,
            effect_class,
            semantic_name,
            semantic_description,
        })
    }

    pub fn from_catalog_entry(
        entry: &PlannerCatalogEntryV2,
    ) -> Result<Self, PlannerPrivacyErrorV2> {
        let structural_role = match entry.structural_role() {
            savana_policy_core::v2::ConnectorStructuralRoleV2::Source => StructuralRoleV2::Source,
            savana_policy_core::v2::ConnectorStructuralRoleV2::Transform => {
                StructuralRoleV2::Transform
            }
            savana_policy_core::v2::ConnectorStructuralRoleV2::Sink => StructuralRoleV2::Sink,
        };
        Self::new(
            entry.tool_class(),
            entry.action_template(),
            structural_role,
            entry.effects(),
            entry.semantic_name().clone(),
            entry.semantic_description().clone(),
        )
    }

    pub const fn tool_class(&self) -> ToolClassIdV2 {
        self.tool_class
    }

    pub const fn action_template(&self) -> ActionTemplateIdV2 {
        self.action_template
    }

    pub const fn structural_role(&self) -> StructuralRoleV2 {
        self.structural_role
    }

    pub const fn effect_class(&self) -> EffectSetV2 {
        self.effect_class
    }

    pub fn semantic_name(&self) -> &str {
        self.semantic_name.as_str()
    }

    pub fn semantic_description(&self) -> &str {
        self.semantic_description.as_str()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapperIntentRequestV2 {
    task_template: StaticTemplateIdV2,
    intent: PlannerIntentKindV2,
    allowed_action_templates: Vec<ActionTemplateIdV2>,
    slots: Vec<PlannerAbstractSlotV2>,
    relations: Vec<PlannerAbstractRelationV2>,
    effective_limits: PlannerLimitsV2,
    available_tools: Vec<MapperCatalogToolV2>,
}

impl MapperIntentRequestV2 {
    pub fn new(
        envelope: &PlannerEnvelopeV2,
        active_tools: &[ActiveToolViewV2],
        catalog_tools: Vec<MapperCatalogToolV2>,
    ) -> Result<Self, PlannerPrivacyErrorV2> {
        let active_pairs = active_tools
            .iter()
            .map(|tool| (tool.tool_class().get(), tool.action_template().get()))
            .collect::<HashSet<_>>();
        let allowed_actions = envelope
            .allowed_action_templates()
            .iter()
            .map(|action| action.get())
            .collect::<HashSet<_>>();
        let mut available_tools = catalog_tools
            .into_iter()
            .filter(|tool| {
                active_pairs.contains(&(tool.tool_class.get(), tool.action_template.get()))
                    && allowed_actions.contains(&tool.action_template.get())
            })
            .collect::<Vec<_>>();
        available_tools.sort_by_key(|tool| (tool.tool_class.get(), tool.action_template.get()));
        if available_tools.windows(2).any(|pair| {
            (pair[0].tool_class, pair[0].action_template)
                == (pair[1].tool_class, pair[1].action_template)
        }) {
            return Err(PlannerPrivacyErrorV2::Invalid);
        }
        Ok(Self {
            task_template: envelope.task_template(),
            intent: envelope.intent(),
            allowed_action_templates: envelope.allowed_action_templates().to_vec(),
            slots: envelope.slots().to_vec(),
            relations: envelope.relations().to_vec(),
            effective_limits: envelope.effective_limits(),
            available_tools,
        })
    }

    pub const fn task_template(&self) -> StaticTemplateIdV2 {
        self.task_template
    }

    pub const fn intent(&self) -> PlannerIntentKindV2 {
        self.intent
    }

    pub fn allowed_action_templates(&self) -> &[ActionTemplateIdV2] {
        &self.allowed_action_templates
    }

    pub fn slots(&self) -> &[PlannerAbstractSlotV2] {
        &self.slots
    }

    pub fn relations(&self) -> &[PlannerAbstractRelationV2] {
        &self.relations
    }

    pub const fn effective_limits(&self) -> PlannerLimitsV2 {
        self.effective_limits
    }

    pub fn available_tools(&self) -> &[MapperCatalogToolV2] {
        &self.available_tools
    }
}

pub fn encode_mapper_intent_request_v2(
    request: &MapperIntentRequestV2,
) -> Result<Vec<u8>, PlannerPrivacyErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(8)
        .and_then(|encoder| encoder.u16(2))
        .and_then(|encoder| encoder.u32(request.task_template.get()))
        .and_then(|encoder| encoder.u16(request.intent.tag()))
        .map_err(|_| PlannerPrivacyErrorV2::Invalid)?;
    encode_u32_values(
        &mut encoder,
        request
            .allowed_action_templates
            .iter()
            .map(|action| action.get()),
    )?;
    encode_minicbor_values(&mut encoder, &request.slots)?;
    encode_minicbor_values(&mut encoder, &request.relations)?;
    minicbor::Encode::encode(&request.effective_limits, &mut encoder, &mut ())
        .map_err(|_| PlannerPrivacyErrorV2::Invalid)?;
    encoder
        .array(request.available_tools.len() as u64)
        .map_err(|_| PlannerPrivacyErrorV2::Invalid)?;
    for tool in &request.available_tools {
        encoder
            .array(6)
            .and_then(|encoder| encoder.u32(tool.tool_class.get()))
            .and_then(|encoder| encoder.u32(tool.action_template.get()))
            .and_then(|encoder| encoder.u16(tool.structural_role.tag()))
            .and_then(|encoder| encoder.u16(tool.effect_class.bits()))
            .and_then(|encoder| encoder.str(tool.semantic_name.as_str()))
            .and_then(|encoder| encoder.str(tool.semantic_description.as_str()))
            .map_err(|_| PlannerPrivacyErrorV2::Invalid)?;
    }
    let bytes = encoder.into_writer();
    if bytes.len() > MAX_MODEL_BODY_BYTES_V2 {
        return Err(PlannerPrivacyErrorV2::Invalid);
    }
    Ok(bytes)
}

/// Decode the mapper-only intent projection at the private model boundary.
///
/// This deliberately does not decode a `PlannerEnvelopeV2`: route, nonce, and
/// expiry are not members of this schema and cannot be smuggled through it.
/// Every attacker-controlled collection is bounded before allocation and the
/// final re-encode check rejects alternate CBOR spellings.
pub fn decode_mapper_intent_request_v2(
    bytes: &[u8],
) -> Result<MapperIntentRequestV2, PlannerPrivacyErrorV2> {
    if bytes.is_empty() || bytes.len() > MAX_MODEL_BODY_BYTES_V2 {
        return Err(PlannerPrivacyErrorV2::Invalid);
    }
    let mut decoder = minicbor::Decoder::new(bytes);
    if decoder.array().map_err(decode_failure)? != Some(8)
        || decoder.u16().map_err(decode_failure)? != 2
    {
        return Err(PlannerPrivacyErrorV2::Invalid);
    }

    let task_template = StaticTemplateIdV2::new(decoder.u32().map_err(decode_failure)?);
    if task_template.get() == 0 {
        return Err(PlannerPrivacyErrorV2::Invalid);
    }
    let intent = match decoder.u16().map_err(decode_failure)? {
        1 => PlannerIntentKindV2::SendMessage,
        2 => PlannerIntentKindV2::Search,
        3 => PlannerIntentKindV2::SummarizeDocument,
        4 => PlannerIntentKindV2::StoreRecord,
        _ => return Err(PlannerPrivacyErrorV2::Invalid),
    };

    let action_count = definite_length(&mut decoder, MAX_STRUCTURAL_NODES_V2)?;
    let mut allowed_action_templates = Vec::with_capacity(action_count);
    for _ in 0..action_count {
        let action = ActionTemplateIdV2::new(decoder.u32().map_err(decode_failure)?);
        if action.get() == 0
            || allowed_action_templates
                .last()
                .is_some_and(|previous| previous >= &action)
        {
            return Err(PlannerPrivacyErrorV2::Invalid);
        }
        allowed_action_templates.push(action);
    }

    let slot_count = definite_length(&mut decoder, MAX_STRUCTURAL_NODES_V2)?;
    let mut slots = Vec::with_capacity(slot_count);
    let mut previous_slot_wire: Option<&[u8]> = None;
    let mut context = V2DecodeContext;
    for _ in 0..slot_count {
        let start = decoder.position();
        let slot = minicbor::Decode::decode(&mut decoder, &mut context).map_err(decode_failure)?;
        let wire = &bytes[start..decoder.position()];
        if previous_slot_wire.is_some_and(|previous| previous >= wire) {
            return Err(PlannerPrivacyErrorV2::Invalid);
        }
        previous_slot_wire = Some(wire);
        slots.push(slot);
    }

    let relation_count = definite_length(&mut decoder, MAX_MAPPER_RELATIONS_V2)?;
    let mut relations = Vec::with_capacity(relation_count);
    let mut previous_relation_wire: Option<&[u8]> = None;
    for _ in 0..relation_count {
        let start = decoder.position();
        let relation =
            minicbor::Decode::decode(&mut decoder, &mut context).map_err(decode_failure)?;
        let wire = &bytes[start..decoder.position()];
        if previous_relation_wire.is_some_and(|previous| previous >= wire) {
            return Err(PlannerPrivacyErrorV2::Invalid);
        }
        previous_relation_wire = Some(wire);
        relations.push(relation);
    }

    let effective_limits =
        minicbor::Decode::decode(&mut decoder, &mut context).map_err(decode_failure)?;
    let tool_count = definite_length(&mut decoder, MAX_MAPPER_CATALOG_TOOLS_V2)?;
    let mut available_tools = Vec::with_capacity(tool_count);
    for _ in 0..tool_count {
        if decoder.array().map_err(decode_failure)? != Some(6) {
            return Err(PlannerPrivacyErrorV2::Invalid);
        }
        let tool_class = ToolClassIdV2::new(decoder.u32().map_err(decode_failure)?);
        let action_template = ActionTemplateIdV2::new(decoder.u32().map_err(decode_failure)?);
        let structural_role = StructuralRoleV2::from_tag(decoder.u16().map_err(decode_failure)?)?;
        let effect_class = EffectSetV2::from_bits(decoder.u16().map_err(decode_failure)?)
            .ok_or(PlannerPrivacyErrorV2::Invalid)?;
        let semantic_name = decoder.str().map_err(decode_failure)?;
        if semantic_name.is_empty() || semantic_name.len() > MAX_MAPPER_SEMANTIC_TEXT_BYTES_V2 {
            return Err(PlannerPrivacyErrorV2::Invalid);
        }
        let semantic_name = BoundedPlannerSemanticTextV2::new(semantic_name.to_owned())
            .map_err(|_| PlannerPrivacyErrorV2::Invalid)?;
        let semantic_description = decoder.str().map_err(decode_failure)?;
        if semantic_description.is_empty()
            || semantic_description.len() > MAX_MAPPER_SEMANTIC_TEXT_BYTES_V2
        {
            return Err(PlannerPrivacyErrorV2::Invalid);
        }
        let semantic_description =
            BoundedPlannerSemanticTextV2::new(semantic_description.to_owned())
                .map_err(|_| PlannerPrivacyErrorV2::Invalid)?;
        let tool = MapperCatalogToolV2::new(
            tool_class,
            action_template,
            structural_role,
            effect_class,
            semantic_name,
            semantic_description,
        )?;
        if available_tools
            .last()
            .is_some_and(|previous: &MapperCatalogToolV2| {
                (previous.tool_class, previous.action_template)
                    >= (tool.tool_class, tool.action_template)
            })
        {
            return Err(PlannerPrivacyErrorV2::Invalid);
        }
        available_tools.push(tool);
    }
    if decoder.position() != bytes.len() {
        return Err(PlannerPrivacyErrorV2::Invalid);
    }

    let request = MapperIntentRequestV2 {
        task_template,
        intent,
        allowed_action_templates,
        slots,
        relations,
        effective_limits,
        available_tools,
    };
    if encode_mapper_intent_request_v2(&request)? != bytes {
        return Err(PlannerPrivacyErrorV2::NonCanonical);
    }
    Ok(request)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MappedNodeV2 {
    local_ordinal: u16,
    tool_class: ToolClassIdV2,
    action_template: ActionTemplateIdV2,
    slot_bindings: Vec<(ArgumentNameV2, PlannerSlotRefV2)>,
    structural_role: StructuralRoleV2,
    effect_class: EffectSetV2,
}

impl MappedNodeV2 {
    pub fn new(
        local_ordinal: u16,
        tool_class: ToolClassIdV2,
        action_template: ActionTemplateIdV2,
        slot_bindings: Vec<(ArgumentNameV2, PlannerSlotRefV2)>,
        structural_role: StructuralRoleV2,
        effect_class: EffectSetV2,
    ) -> Result<Self, PlannerPrivacyErrorV2> {
        if local_ordinal == 0
            || tool_class.get() == 0
            || action_template.get() == 0
            || slot_bindings.len() > MAX_STRUCTURAL_NODES_V2
            || slot_bindings.windows(2).any(|pair| pair[0].0 >= pair[1].0)
            || slot_bindings
                .iter()
                .any(|(_, reference)| reference.as_bytes() == &[0; 16])
        {
            return Err(PlannerPrivacyErrorV2::Invalid);
        }
        validate_role_effect(structural_role, effect_class)?;
        Ok(Self {
            local_ordinal,
            tool_class,
            action_template,
            slot_bindings,
            structural_role,
            effect_class,
        })
    }

    pub const fn local_ordinal(&self) -> u16 {
        self.local_ordinal
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MappedEdgeV2 {
    from: u16,
    to: u16,
}

impl MappedEdgeV2 {
    pub fn new(from: u16, to: u16) -> Result<Self, PlannerPrivacyErrorV2> {
        if from == 0 || to == 0 || from == to {
            return Err(PlannerPrivacyErrorV2::Invalid);
        }
        Ok(Self { from, to })
    }

    pub const fn from(&self) -> u16 {
        self.from
    }

    pub const fn to(&self) -> u16 {
        self.to
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MappedWorkflowV2 {
    nodes: Vec<MappedNodeV2>,
    edges: Vec<MappedEdgeV2>,
    effective_limits: PlannerLimitsV2,
}

/// Process-lifetime issuer for planner-visible node IDs.
///
/// One long-lived instance must be reused for every planner call. It is
/// deliberately neither `Clone` nor stateless: the monotonically increasing
/// call sequence is the cross-call uniqueness boundary.
pub struct StructuralNodeIdIssuerV2 {
    permutation_key: [u8; 32],
    call_sequence: u64,
    #[cfg(any(test, all(feature = "test-support", debug_assertions)))]
    fixed_test_call_salt: Option<[u8; 16]>,
}

impl StructuralNodeIdIssuerV2 {
    pub fn new() -> Result<Self, PlannerPrivacyErrorV2> {
        let mut permutation_key = [0_u8; 32];
        for _ in 0..MAX_FRESH_ID_ATTEMPTS_V2 {
            getrandom::getrandom(&mut permutation_key)
                .map_err(|_| PlannerPrivacyErrorV2::EntropyUnavailable)?;
            if permutation_key != [0; 32] {
                return Ok(Self {
                    permutation_key,
                    call_sequence: 0,
                    #[cfg(any(test, all(feature = "test-support", debug_assertions)))]
                    fixed_test_call_salt: None,
                });
            }
        }
        Err(PlannerPrivacyErrorV2::EntropyUnavailable)
    }

    #[cfg(test)]
    fn with_test_key(permutation_key: [u8; 32]) -> Self {
        assert_ne!(permutation_key, [0; 32]);
        Self {
            permutation_key,
            call_sequence: 0,
            fixed_test_call_salt: None,
        }
    }

    #[cfg(all(feature = "test-support", debug_assertions))]
    #[doc(hidden)]
    pub fn for_test(
        permutation_key: [u8; 32],
        fixed_call_salt: [u8; 16],
    ) -> Result<Self, PlannerPrivacyErrorV2> {
        if permutation_key == [0; 32] {
            return Err(PlannerPrivacyErrorV2::Invalid);
        }
        Ok(Self {
            permutation_key,
            call_sequence: 0,
            fixed_test_call_salt: Some(fixed_call_salt),
        })
    }

    fn issue_for_call<F>(
        &mut self,
        count: usize,
        mut draw_call_salt: F,
    ) -> Result<Vec<StructuralNodeIdV2>, PlannerPrivacyErrorV2>
    where
        F: FnMut() -> Result<[u8; 16], PlannerPrivacyErrorV2>,
    {
        let call_sequence = self
            .call_sequence
            .checked_add(1)
            .ok_or(PlannerPrivacyErrorV2::EntropyUnavailable)?;
        let call_salt = draw_call_salt()?;
        let salt_mask = u64::from_be_bytes(
            call_salt[..8]
                .try_into()
                .map_err(|_| PlannerPrivacyErrorV2::Invalid)?,
        );
        self.call_sequence = call_sequence;

        (0..count)
            .map(|index| {
                let node_index =
                    u64::try_from(index).map_err(|_| PlannerPrivacyErrorV2::Invalid)?;
                let mut unique_input = [0_u8; 16];
                // The upper half is unique across calls and the lower half is
                // unique within a call. The fixed-key Feistel permutation is a
                // bijection, so distinct issuer inputs cannot produce the same
                // planner-visible ID even when call salts repeat.
                unique_input[..8].copy_from_slice(&call_sequence.to_be_bytes());
                unique_input[8..].copy_from_slice(&(node_index ^ salt_mask).to_be_bytes());
                Ok(StructuralNodeIdV2(self.permute_nonzero(unique_input)))
            })
            .collect()
    }

    fn permute_nonzero(&self, mut block: [u8; 16]) -> [u8; 16] {
        // Cycle-walking restricts the permutation to the nonzero domain while
        // preserving its one-to-one property.
        loop {
            block = self.permute(block);
            if block != [0; 16] {
                return block;
            }
        }
    }

    fn permute(&self, block: [u8; 16]) -> [u8; 16] {
        let mut left_bytes = [0_u8; 8];
        left_bytes.copy_from_slice(&block[..8]);
        let mut right_bytes = [0_u8; 8];
        right_bytes.copy_from_slice(&block[8..]);
        let mut left = u64::from_be_bytes(left_bytes);
        let mut right = u64::from_be_bytes(right_bytes);
        for round in 0_u8..6 {
            let mut hasher = Sha256::new();
            hasher.update(STRUCTURAL_NODE_ID_DOMAIN_V2);
            hasher.update(self.permutation_key);
            hasher.update([round]);
            hasher.update(right.to_be_bytes());
            let digest = hasher.finalize();
            let mut round_bytes = [0_u8; 8];
            round_bytes.copy_from_slice(&digest[..8]);
            let round_output = u64::from_be_bytes(round_bytes);
            (left, right) = (right, left ^ round_output);
        }
        let mut output = [0_u8; 16];
        output[..8].copy_from_slice(&left.to_be_bytes());
        output[8..].copy_from_slice(&right.to_be_bytes());
        output
    }
}

impl std::fmt::Debug for StructuralNodeIdIssuerV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StructuralNodeIdIssuerV2")
            .field("call_sequence", &self.call_sequence)
            .finish_non_exhaustive()
    }
}

impl MappedWorkflowV2 {
    pub fn new(
        request: &MapperIntentRequestV2,
        mut nodes: Vec<MappedNodeV2>,
        mut edges: Vec<MappedEdgeV2>,
    ) -> Result<Self, PlannerPrivacyErrorV2> {
        let limits = request.effective_limits;
        if nodes.is_empty()
            || nodes.len() > MAX_STRUCTURAL_NODES_V2
            || nodes.len() > usize::from(limits.maximum_steps())
            || edges.len() > MAX_STRUCTURAL_EDGES_V2
        {
            return Err(PlannerPrivacyErrorV2::Invalid);
        }
        // Mapper-local ordinals remain opaque labels, never execution order.
        // Sorting only removes response-array enumeration as a downstream
        // planner side channel and fixes one canonical serialization.
        nodes.sort_by_key(|node| node.local_ordinal);
        edges.sort_by_key(|edge| (edge.from, edge.to));
        let allowed_actions = request
            .allowed_action_templates
            .iter()
            .copied()
            .collect::<HashSet<_>>();
        let allowed_slots = request
            .slots
            .iter()
            .map(|slot| slot.reference())
            .collect::<HashSet<_>>();
        let available = request
            .available_tools
            .iter()
            .map(|tool| {
                (
                    tool.tool_class,
                    tool.action_template,
                    tool.structural_role,
                    tool.effect_class,
                )
            })
            .collect::<HashSet<_>>();
        let mut indices = HashMap::with_capacity(nodes.len());
        for (index, node) in nodes.iter().enumerate() {
            if indices.insert(node.local_ordinal, index).is_some()
                || !allowed_actions.contains(&node.action_template)
                || !available.contains(&(
                    node.tool_class,
                    node.action_template,
                    node.structural_role,
                    node.effect_class,
                ))
                || node.slot_bindings.len() > usize::from(limits.maximum_arguments_per_step())
                || node
                    .slot_bindings
                    .iter()
                    .any(|(_, reference)| !allowed_slots.contains(reference))
            {
                return Err(PlannerPrivacyErrorV2::Invalid);
            }
        }
        let mut incoming = vec![0_usize; nodes.len()];
        let mut outgoing = vec![0_usize; nodes.len()];
        let mut adjacency = vec![Vec::new(); nodes.len()];
        let mut seen_edges = HashSet::with_capacity(edges.len());
        for edge in &edges {
            let Some(&from) = indices.get(&edge.from) else {
                return Err(PlannerPrivacyErrorV2::Invalid);
            };
            let Some(&to) = indices.get(&edge.to) else {
                return Err(PlannerPrivacyErrorV2::Invalid);
            };
            if !seen_edges.insert(*edge) {
                return Err(PlannerPrivacyErrorV2::Invalid);
            }
            outgoing[from] += 1;
            incoming[to] += 1;
            adjacency[from].push(to);
        }
        if incoming.iter().any(|count| {
            *count > usize::from(u8::MAX)
                || *count > usize::from(limits.maximum_dependencies_per_step())
        }) || outgoing.iter().any(|count| *count > usize::from(u8::MAX))
            || !is_acyclic(&adjacency, &incoming)
        {
            return Err(PlannerPrivacyErrorV2::Invalid);
        }
        Ok(Self {
            nodes,
            edges,
            effective_limits: limits,
        })
    }

    pub fn relabel(
        self,
        issuer: &mut StructuralNodeIdIssuerV2,
    ) -> Result<(StructuralPlannerRequestV2, PlannerDecodeTableV2), PlannerPrivacyErrorV2> {
        #[cfg(any(test, all(feature = "test-support", debug_assertions)))]
        if let Some(call_salt) = issuer.fixed_test_call_salt {
            return self.relabel_from(issuer, || Ok(call_salt));
        }
        self.relabel_from(issuer, || {
            let mut bytes = [0_u8; 16];
            getrandom::getrandom(&mut bytes)
                .map_err(|_| PlannerPrivacyErrorV2::EntropyUnavailable)?;
            Ok(bytes)
        })
    }

    #[cfg(test)]
    fn relabel_with<F>(
        self,
        issuer: &mut StructuralNodeIdIssuerV2,
        draw: F,
    ) -> Result<(StructuralPlannerRequestV2, PlannerDecodeTableV2), PlannerPrivacyErrorV2>
    where
        F: FnMut() -> Result<[u8; 16], PlannerPrivacyErrorV2>,
    {
        self.relabel_from(issuer, draw)
    }

    fn relabel_from<F>(
        self,
        issuer: &mut StructuralNodeIdIssuerV2,
        draw_call_salt: F,
    ) -> Result<(StructuralPlannerRequestV2, PlannerDecodeTableV2), PlannerPrivacyErrorV2>
    where
        F: FnMut() -> Result<[u8; 16], PlannerPrivacyErrorV2>,
    {
        let issued_ids = issuer.issue_for_call(self.nodes.len(), draw_call_salt)?;
        let mut labels = HashMap::with_capacity(self.nodes.len());
        for (node, id) in self.nodes.iter().zip(issued_ids) {
            labels.insert(node.local_ordinal, id);
        }
        let mut incoming = HashMap::<u16, usize>::new();
        let mut outgoing = HashMap::<u16, usize>::new();
        for edge in &self.edges {
            *outgoing.entry(edge.from).or_default() += 1;
            *incoming.entry(edge.to).or_default() += 1;
        }
        let mut structural_nodes = self
            .nodes
            .iter()
            .map(|node| {
                StructuralNodeV2::new(
                    labels[&node.local_ordinal],
                    node.structural_role,
                    node.effect_class,
                    incoming.get(&node.local_ordinal).copied().unwrap_or(0) as u8,
                    outgoing.get(&node.local_ordinal).copied().unwrap_or(0) as u8,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        structural_nodes.sort_by_key(StructuralNodeV2::id);
        let mut structural_edges = self
            .edges
            .iter()
            .map(|edge| StructuralEdgeV2::new(labels[&edge.from], labels[&edge.to]))
            .collect::<Result<Vec<_>, _>>()?;
        structural_edges.sort_by_key(|edge| (edge.from(), edge.to()));
        let graph = StructuralGraphV2::new(structural_nodes, structural_edges)?;
        let entries = self
            .nodes
            .into_iter()
            .map(|node| {
                (
                    labels[&node.local_ordinal],
                    DecodeNodeV2 {
                        tool_class: node.tool_class,
                        action_template: node.action_template,
                        slot_bindings: node.slot_bindings,
                    },
                )
            })
            .collect();
        let edges = self
            .edges
            .into_iter()
            .map(|edge| (labels[&edge.from], labels[&edge.to]))
            .collect();
        let table = PlannerDecodeTableV2 {
            entries,
            edges,
            effective_limits: self.effective_limits,
        };
        Ok((
            StructuralPlannerRequestV2::new(graph, StructuralGoalV2::OrderValidDataflow),
            table,
        ))
    }
}

pub fn encode_mapped_workflow_v2(
    workflow: &MappedWorkflowV2,
) -> Result<Vec<u8>, PlannerPrivacyErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(3)
        .and_then(|encoder| encoder.u16(2))
        .and_then(|encoder| encoder.array(workflow.nodes.len() as u64))
        .map_err(|_| PlannerPrivacyErrorV2::Invalid)?;
    for node in &workflow.nodes {
        encoder
            .array(6)
            .and_then(|encoder| encoder.u16(node.local_ordinal))
            .and_then(|encoder| encoder.u32(node.tool_class.get()))
            .and_then(|encoder| encoder.u32(node.action_template.get()))
            .and_then(|encoder| encoder.array(node.slot_bindings.len() as u64))
            .map_err(|_| PlannerPrivacyErrorV2::Invalid)?;
        for (name, reference) in &node.slot_bindings {
            encoder
                .array(2)
                .and_then(|encoder| encoder.str(name.as_str()))
                .and_then(|encoder| encoder.bytes(reference.as_bytes()))
                .map_err(|_| PlannerPrivacyErrorV2::Invalid)?;
        }
        encoder
            .u16(node.structural_role.tag())
            .and_then(|encoder| encoder.u16(node.effect_class.bits()))
            .map_err(|_| PlannerPrivacyErrorV2::Invalid)?;
    }
    encoder
        .array(workflow.edges.len() as u64)
        .map_err(|_| PlannerPrivacyErrorV2::Invalid)?;
    for edge in &workflow.edges {
        encoder
            .array(2)
            .and_then(|encoder| encoder.u16(edge.from))
            .and_then(|encoder| encoder.u16(edge.to))
            .map_err(|_| PlannerPrivacyErrorV2::Invalid)?;
    }
    let bytes = encoder.into_writer();
    if bytes.len() > MAX_MODEL_BODY_BYTES_V2 {
        return Err(PlannerPrivacyErrorV2::Invalid);
    }
    Ok(bytes)
}

pub fn decode_mapped_workflow_v2(
    bytes: &[u8],
    request: &MapperIntentRequestV2,
) -> Result<MappedWorkflowV2, PlannerPrivacyErrorV2> {
    if bytes.is_empty() || bytes.len() > MAX_MODEL_BODY_BYTES_V2 {
        return Err(PlannerPrivacyErrorV2::Invalid);
    }
    let mut decoder = minicbor::Decoder::new(bytes);
    if decoder.array().map_err(decode_failure)? != Some(3)
        || decoder.u16().map_err(decode_failure)? != 2
    {
        return Err(PlannerPrivacyErrorV2::Invalid);
    }
    let node_count = definite_length(
        &mut decoder,
        MAX_STRUCTURAL_NODES_V2.min(usize::from(request.effective_limits.maximum_steps())),
    )?;
    if node_count == 0 {
        return Err(PlannerPrivacyErrorV2::Invalid);
    }
    let mut nodes = Vec::with_capacity(node_count);
    for _ in 0..node_count {
        if decoder.array().map_err(decode_failure)? != Some(6) {
            return Err(PlannerPrivacyErrorV2::Invalid);
        }
        let local_ordinal = decoder.u16().map_err(decode_failure)?;
        let tool_class = ToolClassIdV2::new(decoder.u32().map_err(decode_failure)?);
        let action_template = ActionTemplateIdV2::new(decoder.u32().map_err(decode_failure)?);
        let binding_count = definite_length(
            &mut decoder,
            MAX_STRUCTURAL_NODES_V2.min(usize::from(
                request.effective_limits.maximum_arguments_per_step(),
            )),
        )?;
        let mut slot_bindings = Vec::with_capacity(binding_count);
        for _ in 0..binding_count {
            if decoder.array().map_err(decode_failure)? != Some(2) {
                return Err(PlannerPrivacyErrorV2::Invalid);
            }
            let name = ArgumentNameV2::new(decoder.str().map_err(decode_failure)?.to_owned())
                .map_err(|_| PlannerPrivacyErrorV2::Invalid)?;
            let reference = <[u8; 16]>::try_from(decoder.bytes().map_err(decode_failure)?)
                .map(PlannerSlotRefV2::new)
                .map_err(|_| PlannerPrivacyErrorV2::Invalid)?;
            slot_bindings.push((name, reference));
        }
        let structural_role = StructuralRoleV2::from_tag(decoder.u16().map_err(decode_failure)?)?;
        let effect_class = EffectSetV2::from_bits(decoder.u16().map_err(decode_failure)?)
            .ok_or(PlannerPrivacyErrorV2::Invalid)?;
        nodes.push(MappedNodeV2::new(
            local_ordinal,
            tool_class,
            action_template,
            slot_bindings,
            structural_role,
            effect_class,
        )?);
    }
    let edge_count = definite_length(&mut decoder, MAX_STRUCTURAL_EDGES_V2)?;
    let mut edges = Vec::with_capacity(edge_count);
    for _ in 0..edge_count {
        if decoder.array().map_err(decode_failure)? != Some(2) {
            return Err(PlannerPrivacyErrorV2::Invalid);
        }
        edges.push(MappedEdgeV2::new(
            decoder.u16().map_err(decode_failure)?,
            decoder.u16().map_err(decode_failure)?,
        )?);
    }
    if decoder.position() != bytes.len() {
        return Err(PlannerPrivacyErrorV2::Invalid);
    }
    let workflow = MappedWorkflowV2::new(request, nodes, edges)?;
    if encode_mapped_workflow_v2(&workflow)? != bytes {
        return Err(PlannerPrivacyErrorV2::NonCanonical);
    }
    Ok(workflow)
}

struct DecodeNodeV2 {
    tool_class: ToolClassIdV2,
    action_template: ActionTemplateIdV2,
    slot_bindings: Vec<(ArgumentNameV2, PlannerSlotRefV2)>,
}

pub struct PlannerDecodeTableV2 {
    entries: HashMap<StructuralNodeIdV2, DecodeNodeV2>,
    edges: Vec<(StructuralNodeIdV2, StructuralNodeIdV2)>,
    effective_limits: PlannerLimitsV2,
}

impl std::fmt::Debug for PlannerDecodeTableV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PlannerDecodeTableV2")
            .field("entry_count", &self.entries.len())
            .field("edge_count", &self.edges.len())
            .finish_non_exhaustive()
    }
}

pub fn decode_ordered_plan_v2(
    envelope: &PlannerEnvelopeV2,
    table: &PlannerDecodeTableV2,
    ordered: &OrderedStructuralPlanV2,
) -> Result<PlannerPlanV2, PlannerPrivacyErrorV2> {
    if ordered.ordered_nodes.len() != table.entries.len()
        || ordered.ordered_nodes.len() > usize::from(table.effective_limits.maximum_steps())
    {
        return Err(PlannerPrivacyErrorV2::Invalid);
    }
    let mut positions = HashMap::with_capacity(ordered.ordered_nodes.len());
    for (index, id) in ordered.ordered_nodes.iter().copied().enumerate() {
        if !table.entries.contains_key(&id) || positions.insert(id, index + 1).is_some() {
            return Err(PlannerPrivacyErrorV2::Invalid);
        }
    }
    let mut dependencies = HashMap::<StructuralNodeIdV2, Vec<u16>>::new();
    for (from, to) in &table.edges {
        let from_position = *positions.get(from).ok_or(PlannerPrivacyErrorV2::Invalid)?;
        let to_position = *positions.get(to).ok_or(PlannerPrivacyErrorV2::Invalid)?;
        if from_position >= to_position {
            return Err(PlannerPrivacyErrorV2::Invalid);
        }
        dependencies
            .entry(*to)
            .or_default()
            .push(from_position as u16);
    }
    let steps = ordered
        .ordered_nodes
        .iter()
        .enumerate()
        .map(|(index, id)| {
            let entry = table
                .entries
                .get(id)
                .ok_or(PlannerPrivacyErrorV2::Invalid)?;
            let mut node_dependencies = dependencies.remove(id).unwrap_or_default();
            node_dependencies.sort_unstable();
            PlannerStepV2::new(
                (index + 1) as u16,
                entry.action_template,
                entry.tool_class,
                entry.slot_bindings.clone(),
                node_dependencies,
            )
            .map_err(|_| PlannerPrivacyErrorV2::Invalid)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let plan = PlannerPlanV2::new(envelope.envelope_nonce(), steps)
        .map_err(|_| PlannerPrivacyErrorV2::Invalid)?;
    if encode_planner_plan_v2(&plan)
        .map_err(|_| PlannerPrivacyErrorV2::Invalid)?
        .len()
        > table.effective_limits.maximum_encoded_plan_bytes() as usize
    {
        return Err(PlannerPrivacyErrorV2::Invalid);
    }
    Ok(plan)
}

fn validate_role_effect(
    role: StructuralRoleV2,
    effects: EffectSetV2,
) -> Result<(), PlannerPrivacyErrorV2> {
    if effects == EffectSetV2::EMPTY
        || (effects.contains(EffectSetV2::FINAL_RELEASE) && role != StructuralRoleV2::Sink)
    {
        return Err(PlannerPrivacyErrorV2::Invalid);
    }
    Ok(())
}

fn unique_structural_indices(
    nodes: &[StructuralNodeV2],
) -> Result<HashMap<StructuralNodeIdV2, usize>, PlannerPrivacyErrorV2> {
    let mut indices = HashMap::with_capacity(nodes.len());
    for (index, node) in nodes.iter().enumerate() {
        if indices.insert(node.id, index).is_some() {
            return Err(PlannerPrivacyErrorV2::Invalid);
        }
    }
    Ok(indices)
}

fn is_acyclic(adjacency: &[Vec<usize>], incoming: &[usize]) -> bool {
    let mut remaining = incoming.to_vec();
    let mut ready = remaining
        .iter()
        .enumerate()
        .filter_map(|(index, count)| (*count == 0).then_some(index))
        .collect::<VecDeque<_>>();
    let mut visited = 0;
    while let Some(index) = ready.pop_front() {
        visited += 1;
        for target in &adjacency[index] {
            remaining[*target] -= 1;
            if remaining[*target] == 0 {
                ready.push_back(*target);
            }
        }
    }
    visited == adjacency.len()
}

fn encode_structural_nodes(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    nodes: &[StructuralNodeV2],
) -> Result<(), PlannerPrivacyErrorV2> {
    encoder
        .array(nodes.len() as u64)
        .map_err(|_| PlannerPrivacyErrorV2::Invalid)?;
    for node in nodes {
        encoder
            .array(5)
            .and_then(|encoder| encoder.bytes(node.id.as_bytes()))
            .and_then(|encoder| encoder.u16(node.role.tag()))
            .and_then(|encoder| encoder.u16(node.effect_class.bits()))
            .and_then(|encoder| encoder.u8(node.in_arity))
            .and_then(|encoder| encoder.u8(node.out_arity))
            .map_err(|_| PlannerPrivacyErrorV2::Invalid)?;
    }
    Ok(())
}

fn encode_structural_edges(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    edges: &[StructuralEdgeV2],
) -> Result<(), PlannerPrivacyErrorV2> {
    encoder
        .array(edges.len() as u64)
        .map_err(|_| PlannerPrivacyErrorV2::Invalid)?;
    for edge in edges {
        encoder
            .array(2)
            .and_then(|encoder| encoder.bytes(edge.from.as_bytes()))
            .and_then(|encoder| encoder.bytes(edge.to.as_bytes()))
            .map_err(|_| PlannerPrivacyErrorV2::Invalid)?;
    }
    Ok(())
}

fn definite_length(
    decoder: &mut minicbor::Decoder<'_>,
    maximum: usize,
) -> Result<usize, PlannerPrivacyErrorV2> {
    let length = decoder
        .array()
        .map_err(decode_failure)?
        .ok_or(PlannerPrivacyErrorV2::Invalid)?;
    let length = usize::try_from(length).map_err(|_| PlannerPrivacyErrorV2::Invalid)?;
    if length > maximum {
        return Err(PlannerPrivacyErrorV2::Invalid);
    }
    Ok(length)
}

fn decode_structural_id(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<StructuralNodeIdV2, PlannerPrivacyErrorV2> {
    let bytes = decoder.bytes().map_err(decode_failure)?;
    let bytes = <[u8; 16]>::try_from(bytes).map_err(|_| PlannerPrivacyErrorV2::Invalid)?;
    StructuralNodeIdV2::new(bytes)
}

fn decode_failure(_: minicbor::decode::Error) -> PlannerPrivacyErrorV2 {
    PlannerPrivacyErrorV2::Invalid
}

fn encode_u32_values(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    values: impl ExactSizeIterator<Item = u32>,
) -> Result<(), PlannerPrivacyErrorV2> {
    encoder
        .array(values.len() as u64)
        .map_err(|_| PlannerPrivacyErrorV2::Invalid)?;
    for value in values {
        encoder
            .u32(value)
            .map_err(|_| PlannerPrivacyErrorV2::Invalid)?;
    }
    Ok(())
}

fn encode_minicbor_values<T: minicbor::Encode<()>>(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    values: &[T],
) -> Result<(), PlannerPrivacyErrorV2> {
    encoder
        .array(values.len() as u64)
        .map_err(|_| PlannerPrivacyErrorV2::Invalid)?;
    for value in values {
        minicbor::Encode::encode(value, encoder, &mut ())
            .map_err(|_| PlannerPrivacyErrorV2::Invalid)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BoundedPlannerSemanticTextV2, PlannerCatalogEntryV2};
    use savana_kernel_protocol::v2::{
        ActionTemplateIdV2, ActiveToolViewV2, ArgumentNameV2, Nonce32V2, PlannerAbstractRelationV2,
        PlannerAbstractSlotV2, PlannerEnvelopeV2, PlannerIntentKindV2, PlannerLimitsV2,
        PlannerRouteIdV2, PlannerSlotCardinalityV2, PlannerSlotConfidentialityV2, PlannerSlotRefV2,
        RelationIdV2, SlotKindV2, StaticTemplateIdV2, ToolClassIdV2, ToolHandleV2, UnixMillisV2,
    };
    use savana_policy_core::v2::EffectSetV2;

    fn id(byte: u8) -> StructuralNodeIdV2 {
        StructuralNodeIdV2::new([byte; 16]).unwrap()
    }

    fn node(
        byte: u8,
        role: StructuralRoleV2,
        effects: EffectSetV2,
        in_arity: u8,
        out_arity: u8,
    ) -> StructuralNodeV2 {
        StructuralNodeV2::new(id(byte), role, effects, in_arity, out_arity).unwrap()
    }

    fn edge(from: u8, to: u8) -> StructuralEdgeV2 {
        StructuralEdgeV2::new(id(from), id(to)).unwrap()
    }

    fn request(
        nodes: Vec<StructuralNodeV2>,
        edges: Vec<StructuralEdgeV2>,
    ) -> StructuralPlannerRequestV2 {
        StructuralPlannerRequestV2::new(
            StructuralGraphV2::new(nodes, edges).unwrap(),
            StructuralGoalV2::OrderValidDataflow,
        )
    }

    #[test]
    fn canonical_request_bytes_are_the_closed_literal_wire_shape() {
        let request = request(
            vec![node(1, StructuralRoleV2::Source, EffectSetV2::READ, 0, 0)],
            vec![],
        );

        let mut expected = vec![0x84, 0x02, 0x81, 0x85, 0x50];
        expected.extend_from_slice(&[1; 16]);
        expected.extend_from_slice(&[0x01, 0x01, 0x00, 0x00, 0x80, 0x01]);

        assert_eq!(
            encode_structural_planner_request_v2(&request).unwrap(),
            expected
        );
        assert_eq!(
            decode_structural_planner_request_v2(&expected).unwrap(),
            request
        );
        assert!(!expected.windows(6).any(|bytes| bytes == b"secret"));
    }

    #[test]
    fn structural_decoder_rejects_unknown_tags_zero_ids_and_noncanonical_integers() {
        let canonical = encode_structural_planner_request_v2(&request(
            vec![node(1, StructuralRoleV2::Source, EffectSetV2::READ, 0, 0)],
            vec![],
        ))
        .unwrap();

        let cases = [("unknown role tag", 21, 4), ("zero node ID", 5, 0)];
        for (name, index, replacement) in cases {
            let mut malformed = canonical.clone();
            if name == "zero node ID" {
                malformed[5..21].fill(replacement);
            } else {
                malformed[index] = replacement;
            }
            assert!(
                decode_structural_planner_request_v2(&malformed).is_err(),
                "{name}"
            );
        }

        let mut unknown_effect = canonical.clone();
        unknown_effect.splice(22..23, [0x18, 0x80]);
        assert!(decode_structural_planner_request_v2(&unknown_effect).is_err());

        let mut noncanonical = canonical.clone();
        noncanonical.splice(21..22, [0x18, 0x01]);
        assert!(decode_structural_planner_request_v2(&noncanonical).is_err());
    }

    #[test]
    fn structural_constructors_reject_zero_effects_and_final_release_on_non_sink() {
        assert!(StructuralNodeIdV2::new([0; 16]).is_err());
        assert!(
            StructuralNodeV2::new(id(1), StructuralRoleV2::Source, EffectSetV2::EMPTY, 0, 0,)
                .is_err()
        );
        assert!(StructuralNodeV2::new(
            id(1),
            StructuralRoleV2::Transform,
            EffectSetV2::FINAL_RELEASE,
            0,
            0,
        )
        .is_err());
    }

    #[test]
    fn graph_validation_rejects_reused_ids_bad_edges_cycles_and_wrong_arities() {
        let source = node(1, StructuralRoleV2::Source, EffectSetV2::READ, 0, 1);
        let sink = node(2, StructuralRoleV2::Sink, EffectSetV2::SEND, 1, 0);
        let unknown = edge(1, 3);
        let forward = edge(1, 2);
        let backward = edge(2, 1);

        assert!(StructuralEdgeV2::new(id(1), id(1)).is_err());

        let cases = [
            (
                "reused node ID",
                vec![
                    node(1, StructuralRoleV2::Source, EffectSetV2::READ, 0, 0),
                    node(1, StructuralRoleV2::Sink, EffectSetV2::SEND, 0, 0),
                ],
                vec![],
            ),
            ("unknown edge endpoint", vec![source, sink], vec![unknown]),
            (
                "duplicate edge",
                vec![
                    node(1, StructuralRoleV2::Source, EffectSetV2::READ, 0, 2),
                    node(2, StructuralRoleV2::Sink, EffectSetV2::SEND, 2, 0),
                ],
                vec![forward, forward],
            ),
            (
                "cycle",
                vec![
                    node(1, StructuralRoleV2::Source, EffectSetV2::READ, 1, 1),
                    node(2, StructuralRoleV2::Sink, EffectSetV2::SEND, 1, 1),
                ],
                vec![forward, backward],
            ),
            (
                "declared arity mismatch",
                vec![
                    node(1, StructuralRoleV2::Source, EffectSetV2::READ, 0, 0),
                    sink,
                ],
                vec![forward],
            ),
        ];
        for (name, nodes, edges) in cases {
            assert!(StructuralGraphV2::new(nodes, edges).is_err(), "{name}");
        }
    }

    #[test]
    fn graph_validation_rejects_more_than_256_nodes_or_4096_edges() {
        let nodes = (1..=257)
            .map(|value| {
                let mut bytes = [0_u8; 16];
                bytes[..2].copy_from_slice(&(value as u16).to_be_bytes());
                StructuralNodeV2::new(
                    StructuralNodeIdV2::new(bytes).unwrap(),
                    StructuralRoleV2::Transform,
                    EffectSetV2::READ,
                    0,
                    0,
                )
                .unwrap()
            })
            .collect();
        assert!(StructuralGraphV2::new(nodes, vec![]).is_err());

        let unique_edges = (1_u16..=256)
            .flat_map(|from| ((from + 1)..=256).map(move |to| (from, to)))
            .take(4097)
            .map(|(from, to)| {
                let mut from_bytes = [0_u8; 16];
                from_bytes[..2].copy_from_slice(&from.to_be_bytes());
                let mut to_bytes = [0_u8; 16];
                to_bytes[..2].copy_from_slice(&to.to_be_bytes());
                StructuralEdgeV2::new(
                    StructuralNodeIdV2::new(from_bytes).unwrap(),
                    StructuralNodeIdV2::new(to_bytes).unwrap(),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let mut incoming = [0_u8; 256];
        let mut outgoing = [0_u8; 256];
        for edge in &unique_edges {
            outgoing[usize::from(u16::from_be_bytes([
                edge.from().as_bytes()[0],
                edge.from().as_bytes()[1],
            ])) - 1] += 1;
            incoming[usize::from(u16::from_be_bytes([
                edge.to().as_bytes()[0],
                edge.to().as_bytes()[1],
            ])) - 1] += 1;
        }
        let graph_nodes = (1_u16..=256)
            .map(|value| {
                let mut bytes = [0_u8; 16];
                bytes[..2].copy_from_slice(&value.to_be_bytes());
                StructuralNodeV2::new(
                    StructuralNodeIdV2::new(bytes).unwrap(),
                    StructuralRoleV2::Transform,
                    EffectSetV2::READ,
                    incoming[usize::from(value) - 1],
                    outgoing[usize::from(value) - 1],
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        assert!(StructuralGraphV2::new(graph_nodes, unique_edges).is_err());
    }

    #[test]
    fn ordered_response_bytes_are_exact_and_noncanonical_lengths_are_rejected() {
        let plan = OrderedStructuralPlanV2::new(vec![id(1), id(2)]).unwrap();
        let mut expected = vec![0x82, 0x02, 0x82, 0x50];
        expected.extend_from_slice(&[1; 16]);
        expected.push(0x50);
        expected.extend_from_slice(&[2; 16]);

        assert_eq!(encode_ordered_structural_plan_v2(&plan).unwrap(), expected);
        assert_eq!(decode_ordered_structural_plan_v2(&expected).unwrap(), plan);

        let mut noncanonical = expected;
        noncanonical.splice(2..3, [0x98, 0x02]);
        assert!(decode_ordered_structural_plan_v2(&noncanonical).is_err());
    }

    fn envelope_with_limits(limits: PlannerLimitsV2) -> PlannerEnvelopeV2 {
        let slot_a = PlannerAbstractSlotV2::new(
            PlannerSlotRefV2::new([0xa1; 16]),
            SlotKindV2::new(1),
            PlannerSlotCardinalityV2::ExactlyOne,
            PlannerSlotConfidentialityV2::ConfidentialAbstract,
        )
        .unwrap();
        let slot_b = PlannerAbstractSlotV2::new(
            PlannerSlotRefV2::new([0xb2; 16]),
            SlotKindV2::new(2),
            PlannerSlotCardinalityV2::ZeroOrOne,
            PlannerSlotConfidentialityV2::PublicStructural,
        )
        .unwrap();
        PlannerEnvelopeV2::new(
            PlannerRouteIdV2::new(99),
            StaticTemplateIdV2::new(7),
            PlannerIntentKindV2::Search,
            vec![ActionTemplateIdV2::new(10), ActionTemplateIdV2::new(20)],
            vec![slot_a, slot_b],
            vec![PlannerAbstractRelationV2::new(
                RelationIdV2::new(1),
                PlannerSlotRefV2::new([0xa1; 16]),
                PlannerSlotRefV2::new([0xb2; 16]),
            )
            .unwrap()],
            limits,
            Nonce32V2::new([0xcc; 32]),
            UnixMillisV2::new(123_456),
        )
        .unwrap()
    }

    fn envelope() -> PlannerEnvelopeV2 {
        envelope_with_limits(PlannerLimitsV2::new(4, 3, 2, 4096).unwrap())
    }

    fn active(tool_byte: u8, action: u32, class: u32) -> ActiveToolViewV2 {
        ActiveToolViewV2::new(
            ToolHandleV2::from_authority_entropy([tool_byte; 32]).unwrap(),
            ActionTemplateIdV2::new(action),
            ToolClassIdV2::new(class),
            StaticTemplateIdV2::new(action + class),
        )
        .unwrap()
    }

    fn mapper_request() -> MapperIntentRequestV2 {
        let envelope = envelope();
        MapperIntentRequestV2::new(
            &envelope,
            &[active(1, 10, 100), active(2, 20, 200)],
            vec![
                MapperCatalogToolV2::new(
                    ToolClassIdV2::new(100),
                    ActionTemplateIdV2::new(10),
                    StructuralRoleV2::Source,
                    EffectSetV2::READ,
                    BoundedPlannerSemanticTextV2::new("source_tool").unwrap(),
                    BoundedPlannerSemanticTextV2::new("read source records").unwrap(),
                )
                .unwrap(),
                MapperCatalogToolV2::new(
                    ToolClassIdV2::new(200),
                    ActionTemplateIdV2::new(20),
                    StructuralRoleV2::Sink,
                    EffectSetV2::SEND,
                    BoundedPlannerSemanticTextV2::new("sink_tool").unwrap(),
                    BoundedPlannerSemanticTextV2::new("send transformed records").unwrap(),
                )
                .unwrap(),
            ],
        )
        .unwrap()
    }

    fn test_issuer() -> StructuralNodeIdIssuerV2 {
        StructuralNodeIdIssuerV2::with_test_key([0x5a; 32])
    }

    fn mapped_node(
        ordinal: u16,
        action: u32,
        class: u32,
        binding: (&str, u8),
        role: StructuralRoleV2,
        effects: EffectSetV2,
    ) -> MappedNodeV2 {
        MappedNodeV2::new(
            ordinal,
            ToolClassIdV2::new(class),
            ActionTemplateIdV2::new(action),
            vec![(
                ArgumentNameV2::new(binding.0.to_owned()).unwrap(),
                PlannerSlotRefV2::new([binding.1; 16]),
            )],
            role,
            effects,
        )
        .unwrap()
    }

    #[test]
    fn mapper_projection_omits_route_nonce_and_expiry() {
        let request = mapper_request();
        let encoded = encode_mapper_intent_request_v2(&request).unwrap();

        assert_eq!(request.task_template(), StaticTemplateIdV2::new(7));
        assert_eq!(request.intent(), PlannerIntentKindV2::Search);
        assert!(!encoded.windows(32).any(|bytes| bytes == [0xcc; 32]));
        assert!(!encoded
            .windows(5)
            .any(|bytes| bytes == [0x1a, 0, 1, 0xe2, 0x40]));
        assert!(!encoded.windows(2).any(|bytes| bytes == [0x18, 99]));
    }

    #[test]
    fn mapper_request_decoder_accepts_only_the_canonical_six_field_schema() {
        let request = mapper_request();
        let encoded = encode_mapper_intent_request_v2(&request).unwrap();
        assert_eq!(decode_mapper_intent_request_v2(&encoded).unwrap(), request);

        let mut old_four_field_tool = encoded.clone();
        let row = old_four_field_tool
            .windows(3)
            .position(|window| window == [0x86, 0x18, 0x64])
            .expect("canonical six-field tool row");
        old_four_field_tool[row] = 0x84;
        assert_eq!(
            decode_mapper_intent_request_v2(&old_four_field_tool),
            Err(PlannerPrivacyErrorV2::Invalid)
        );

        let mut wrong_field_type = encoded.clone();
        wrong_field_type[2] = 0x60;
        assert_eq!(
            decode_mapper_intent_request_v2(&wrong_field_type),
            Err(PlannerPrivacyErrorV2::Invalid)
        );

        let mut unknown_intent = encoded.clone();
        unknown_intent[3] = 5;
        assert_eq!(
            decode_mapper_intent_request_v2(&unknown_intent),
            Err(PlannerPrivacyErrorV2::Invalid)
        );

        let mut noncanonical_version = encoded.clone();
        noncanonical_version.splice(1..2, [0x18, 0x02]);
        assert_eq!(
            decode_mapper_intent_request_v2(&noncanonical_version),
            Err(PlannerPrivacyErrorV2::NonCanonical)
        );

        let mut unsafe_semantic = encoded.clone();
        let semantic = unsafe_semantic
            .windows(b"source_tool".len())
            .position(|window| window == b"source_tool")
            .unwrap();
        unsafe_semantic[semantic] = b'\n';
        assert_eq!(
            decode_mapper_intent_request_v2(&unsafe_semantic),
            Err(PlannerPrivacyErrorV2::Invalid)
        );

        let mut oversize_semantic = encoded.clone();
        let semantic = oversize_semantic
            .windows(b"source_tool".len())
            .position(|window| window == b"source_tool")
            .unwrap();
        let mut encoded_text = minicbor::Encoder::new(Vec::new());
        encoded_text
            .str(&"a".repeat(MAX_MAPPER_SEMANTIC_TEXT_BYTES_V2 + 1))
            .unwrap();
        oversize_semantic.splice(
            semantic - 1..semantic + b"source_tool".len(),
            encoded_text.into_writer(),
        );
        assert_eq!(
            decode_mapper_intent_request_v2(&oversize_semantic),
            Err(PlannerPrivacyErrorV2::Invalid)
        );

        let mut trailing = encoded;
        trailing.push(0);
        assert_eq!(
            decode_mapper_intent_request_v2(&trailing),
            Err(PlannerPrivacyErrorV2::Invalid)
        );
    }

    #[test]
    fn mapper_request_decoder_rejects_unsorted_duplicate_and_oversize_collections() {
        let mut unsorted_actions = mapper_request();
        unsorted_actions.allowed_action_templates.swap(0, 1);
        assert_eq!(
            decode_mapper_intent_request_v2(
                &encode_mapper_intent_request_v2(&unsorted_actions).unwrap()
            ),
            Err(PlannerPrivacyErrorV2::Invalid)
        );

        let mut duplicate_tools = mapper_request();
        duplicate_tools.available_tools[1] = duplicate_tools.available_tools[0].clone();
        assert_eq!(
            decode_mapper_intent_request_v2(
                &encode_mapper_intent_request_v2(&duplicate_tools).unwrap()
            ),
            Err(PlannerPrivacyErrorV2::Invalid)
        );

        let seed = mapper_request().available_tools[0].clone();
        let mut oversize = mapper_request();
        oversize.available_tools = (1..=MAX_MAPPER_CATALOG_TOOLS_V2 + 1)
            .map(|class| {
                MapperCatalogToolV2::new(
                    ToolClassIdV2::new(u32::try_from(class).unwrap()),
                    seed.action_template,
                    seed.structural_role,
                    seed.effect_class,
                    seed.semantic_name.clone(),
                    seed.semantic_description.clone(),
                )
                .unwrap()
            })
            .collect();
        assert_eq!(
            decode_mapper_intent_request_v2(&encode_mapper_intent_request_v2(&oversize).unwrap()),
            Err(PlannerPrivacyErrorV2::Invalid)
        );

        assert_eq!(
            decode_mapper_intent_request_v2(&vec![0; MAX_MODEL_BODY_BYTES_V2 + 1]),
            Err(PlannerPrivacyErrorV2::Invalid)
        );
    }

    #[test]
    fn mapper_projection_carries_bounded_rich_semantics_only_to_mapper_wire() {
        let entry = PlannerCatalogEntryV2::new(
            ToolClassIdV2::new(100),
            ActionTemplateIdV2::new(10),
            savana_policy_core::v2::ConnectorStructuralRoleV2::Source,
            EffectSetV2::READ,
            BoundedPlannerSemanticTextV2::new("customer_lookup").unwrap(),
            BoundedPlannerSemanticTextV2::new("query the private customer database").unwrap(),
        )
        .unwrap();
        let tool = MapperCatalogToolV2::from_catalog_entry(&entry).unwrap();
        let request =
            MapperIntentRequestV2::new(&envelope(), &[active(1, 10, 100)], vec![tool]).unwrap();

        let bytes = encode_mapper_intent_request_v2(&request).unwrap();

        assert!(bytes
            .windows(b"customer_lookup".len())
            .any(|window| window == b"customer_lookup"));
        assert!(bytes
            .windows(b"query the private customer database".len())
            .any(|window| window == b"query the private customer database"));
        assert_eq!(
            request.available_tools()[0].semantic_name(),
            "customer_lookup"
        );
        assert_eq!(
            request.available_tools()[0].semantic_description(),
            "query the private customer database"
        );
        let debug = format!("{request:?}");
        assert!(!debug.contains("customer_lookup"));
        assert!(!debug.contains("private customer database"));
    }

    #[test]
    fn mapper_validation_rejects_unauthorized_tool_action_slot_role_and_effect() {
        let request = mapper_request();
        let valid_source = mapped_node(
            7,
            10,
            100,
            ("input", 0xa1),
            StructuralRoleV2::Source,
            EffectSetV2::READ,
        );
        let invalid_nodes = [
            (
                "action outside envelope allowlist",
                mapped_node(
                    7,
                    30,
                    100,
                    ("input", 0xa1),
                    StructuralRoleV2::Source,
                    EffectSetV2::READ,
                ),
            ),
            (
                "tool pair not active and catalog-backed",
                mapped_node(
                    7,
                    10,
                    999,
                    ("input", 0xa1),
                    StructuralRoleV2::Source,
                    EffectSetV2::READ,
                ),
            ),
            (
                "slot outside envelope",
                mapped_node(
                    7,
                    10,
                    100,
                    ("input", 0xdd),
                    StructuralRoleV2::Source,
                    EffectSetV2::READ,
                ),
            ),
            (
                "role differs from signed catalog",
                mapped_node(
                    7,
                    10,
                    100,
                    ("input", 0xa1),
                    StructuralRoleV2::Transform,
                    EffectSetV2::READ,
                ),
            ),
            (
                "effect differs from signed catalog",
                mapped_node(
                    7,
                    10,
                    100,
                    ("input", 0xa1),
                    StructuralRoleV2::Source,
                    EffectSetV2::EXECUTE,
                ),
            ),
        ];

        for (name, invalid) in invalid_nodes {
            assert!(
                MappedWorkflowV2::new(&request, vec![invalid], vec![]).is_err(),
                "{name}"
            );
        }
        assert!(MappedWorkflowV2::new(&request, vec![valid_source], vec![]).is_ok());
    }

    #[test]
    fn mapper_local_ordinals_are_labels_not_an_order() {
        let request = mapper_request();
        let source = mapped_node(
            90,
            10,
            100,
            ("z", 0xa1),
            StructuralRoleV2::Source,
            EffectSetV2::READ,
        );
        let sink = mapped_node(
            4,
            20,
            200,
            ("a", 0xb2),
            StructuralRoleV2::Sink,
            EffectSetV2::SEND,
        );

        assert!(MappedWorkflowV2::new(
            &request,
            vec![sink, source],
            vec![MappedEdgeV2::new(90, 4).unwrap()],
        )
        .is_ok());
    }

    #[test]
    fn mapper_workflow_rejects_duplicate_ordinals_bad_edges_cycles_and_limits() {
        let request = mapper_request();
        let source = mapped_node(
            7,
            10,
            100,
            ("input", 0xa1),
            StructuralRoleV2::Source,
            EffectSetV2::READ,
        );
        let sink = mapped_node(
            2,
            20,
            200,
            ("output", 0xb2),
            StructuralRoleV2::Sink,
            EffectSetV2::SEND,
        );
        assert!(
            MappedWorkflowV2::new(&request, vec![source.clone(), source.clone()], vec![]).is_err()
        );
        assert!(MappedWorkflowV2::new(
            &request,
            vec![source.clone(), sink.clone()],
            vec![MappedEdgeV2::new(7, 99).unwrap()],
        )
        .is_err());
        assert!(MappedWorkflowV2::new(
            &request,
            vec![source.clone(), sink.clone()],
            vec![
                MappedEdgeV2::new(7, 2).unwrap(),
                MappedEdgeV2::new(7, 2).unwrap(),
            ],
        )
        .is_err());
        assert!(MappedWorkflowV2::new(
            &request,
            vec![source, sink],
            vec![
                MappedEdgeV2::new(7, 2).unwrap(),
                MappedEdgeV2::new(2, 7).unwrap()
            ],
        )
        .is_err());
    }

    #[test]
    fn mapped_workflow_codec_is_canonical_and_request_bound() {
        let request = mapper_request();
        let source = mapped_node(
            9,
            10,
            100,
            ("a", 0xa1),
            StructuralRoleV2::Source,
            EffectSetV2::READ,
        );
        let sink = mapped_node(
            2,
            20,
            200,
            ("b", 0xb2),
            StructuralRoleV2::Sink,
            EffectSetV2::SEND,
        );
        let workflow = MappedWorkflowV2::new(
            &request,
            vec![sink, source],
            vec![MappedEdgeV2::new(9, 2).unwrap()],
        )
        .unwrap();

        let encoded = encode_mapped_workflow_v2(&workflow).unwrap();
        assert_eq!(
            decode_mapped_workflow_v2(&encoded, &request).unwrap(),
            workflow
        );

        let mut noncanonical_version = encoded;
        noncanonical_version.splice(1..2, [0x18, 0x02]);
        assert!(decode_mapped_workflow_v2(&noncanonical_version, &request).is_err());
    }

    #[test]
    fn mapped_workflow_enforces_step_argument_dependency_and_encoded_byte_limits() {
        let limited_envelope = envelope_with_limits(PlannerLimitsV2::new(2, 1, 1, 4096).unwrap());
        let limited_request = MapperIntentRequestV2::new(
            &limited_envelope,
            &[active(1, 10, 100), active(2, 20, 200)],
            vec![
                MapperCatalogToolV2::new(
                    ToolClassIdV2::new(100),
                    ActionTemplateIdV2::new(10),
                    StructuralRoleV2::Source,
                    EffectSetV2::READ,
                    BoundedPlannerSemanticTextV2::new("source_tool").unwrap(),
                    BoundedPlannerSemanticTextV2::new("read source records").unwrap(),
                )
                .unwrap(),
                MapperCatalogToolV2::new(
                    ToolClassIdV2::new(200),
                    ActionTemplateIdV2::new(20),
                    StructuralRoleV2::Sink,
                    EffectSetV2::SEND,
                    BoundedPlannerSemanticTextV2::new("sink_tool").unwrap(),
                    BoundedPlannerSemanticTextV2::new("send transformed records").unwrap(),
                )
                .unwrap(),
            ],
        )
        .unwrap();
        let source = mapped_node(
            1,
            10,
            100,
            ("a", 0xa1),
            StructuralRoleV2::Source,
            EffectSetV2::READ,
        );
        let second_source = mapped_node(
            2,
            10,
            100,
            ("b", 0xa1),
            StructuralRoleV2::Source,
            EffectSetV2::READ,
        );
        let sink = mapped_node(
            3,
            20,
            200,
            ("c", 0xb2),
            StructuralRoleV2::Sink,
            EffectSetV2::SEND,
        );
        assert!(MappedWorkflowV2::new(
            &limited_request,
            vec![source.clone(), second_source.clone(), sink.clone()],
            vec![],
        )
        .is_err());

        let too_many_arguments = MappedNodeV2::new(
            1,
            ToolClassIdV2::new(100),
            ActionTemplateIdV2::new(10),
            vec![
                (
                    ArgumentNameV2::new("a".to_owned()).unwrap(),
                    PlannerSlotRefV2::new([0xa1; 16]),
                ),
                (
                    ArgumentNameV2::new("b".to_owned()).unwrap(),
                    PlannerSlotRefV2::new([0xb2; 16]),
                ),
            ],
            StructuralRoleV2::Source,
            EffectSetV2::READ,
        )
        .unwrap();
        assert!(MappedWorkflowV2::new(&limited_request, vec![too_many_arguments], vec![]).is_err());

        let dependency_envelope =
            envelope_with_limits(PlannerLimitsV2::new(3, 1, 2, 4096).unwrap());
        let dependency_request = MapperIntentRequestV2::new(
            &dependency_envelope,
            &[active(1, 10, 100), active(2, 20, 200)],
            limited_request.available_tools().to_vec(),
        )
        .unwrap();
        assert!(MappedWorkflowV2::new(
            &dependency_request,
            vec![source.clone(), second_source, sink],
            vec![
                MappedEdgeV2::new(1, 3).unwrap(),
                MappedEdgeV2::new(2, 3).unwrap(),
            ],
        )
        .is_err());

        let tiny_envelope = envelope_with_limits(PlannerLimitsV2::new(2, 1, 1, 1).unwrap());
        let tiny_request = MapperIntentRequestV2::new(
            &tiny_envelope,
            &[active(1, 10, 100)],
            vec![limited_request.available_tools()[0].clone()],
        )
        .unwrap();
        let workflow = MappedWorkflowV2::new(&tiny_request, vec![source], vec![]).unwrap();
        let mut issuer = test_issuer();
        let (structural, table) = workflow
            .relabel_with(&mut issuer, || Ok([0x31; 16]))
            .unwrap();
        let ordered =
            OrderedStructuralPlanV2::new(vec![structural.graph().nodes()[0].id()]).unwrap();
        assert!(decode_ordered_plan_v2(&tiny_envelope, &table, &ordered).is_err());
    }

    fn relabeled_fixture() -> (
        PlannerEnvelopeV2,
        StructuralPlannerRequestV2,
        PlannerDecodeTableV2,
    ) {
        let envelope = envelope();
        let request = mapper_request();
        let source = mapped_node(
            90,
            10,
            100,
            ("z", 0xa1),
            StructuralRoleV2::Source,
            EffectSetV2::READ,
        );
        let sink = mapped_node(
            4,
            20,
            200,
            ("a", 0xb2),
            StructuralRoleV2::Sink,
            EffectSetV2::SEND,
        );
        let workflow = MappedWorkflowV2::new(
            &request,
            vec![sink, source],
            vec![MappedEdgeV2::new(90, 4).unwrap()],
        )
        .unwrap();
        let mut issuer = test_issuer();
        let (structural, table) = workflow
            .relabel_with(&mut issuer, || Ok([0x22; 16]))
            .unwrap();
        (envelope, structural, table)
    }

    #[test]
    fn fresh_issuer_makes_nonzero_unique_ids_from_zero_random_bytes() {
        let request = mapper_request();
        let first = mapped_node(
            1,
            10,
            100,
            ("a", 0xa1),
            StructuralRoleV2::Source,
            EffectSetV2::READ,
        );
        let second = mapped_node(
            2,
            20,
            200,
            ("b", 0xb2),
            StructuralRoleV2::Sink,
            EffectSetV2::SEND,
        );
        let workflow = MappedWorkflowV2::new(&request, vec![first, second], vec![]).unwrap();
        let mut issuer = test_issuer();

        let (structural, _) = workflow.relabel_with(&mut issuer, || Ok([0; 16])).unwrap();

        let ids = structural
            .graph()
            .nodes()
            .iter()
            .map(StructuralNodeV2::id)
            .collect::<HashSet<_>>();
        assert_eq!(ids.len(), 2);
        assert!(ids.iter().all(|id| id.as_bytes() != &[0; 16]));
    }

    #[test]
    fn repeated_random_bytes_cannot_reuse_ids_across_planner_calls() {
        let request = mapper_request();
        let workflow = || {
            MappedWorkflowV2::new(
                &request,
                vec![
                    mapped_node(
                        1,
                        10,
                        100,
                        ("a", 0xa1),
                        StructuralRoleV2::Source,
                        EffectSetV2::READ,
                    ),
                    mapped_node(
                        2,
                        20,
                        200,
                        ("b", 0xb2),
                        StructuralRoleV2::Sink,
                        EffectSetV2::SEND,
                    ),
                ],
                vec![],
            )
            .unwrap()
        };

        let mut issuer = test_issuer();
        let (first, _) = workflow()
            .relabel_with(&mut issuer, || Ok([0x77; 16]))
            .unwrap();
        let (second, _) = workflow()
            .relabel_with(&mut issuer, || Ok([0x77; 16]))
            .unwrap();
        let first_ids = first
            .graph()
            .nodes()
            .iter()
            .map(StructuralNodeV2::id)
            .collect::<HashSet<_>>();
        let second_ids = second
            .graph()
            .nodes()
            .iter()
            .map(StructuralNodeV2::id)
            .collect::<HashSet<_>>();

        assert!(first_ids.is_disjoint(&second_ids));
    }

    #[test]
    fn mapper_array_order_cannot_change_the_canonical_structural_request() {
        let request = mapper_request();
        let nodes = vec![
            mapped_node(
                10,
                10,
                100,
                ("a", 0xa1),
                StructuralRoleV2::Source,
                EffectSetV2::READ,
            ),
            mapped_node(
                20,
                10,
                100,
                ("a", 0xa1),
                StructuralRoleV2::Source,
                EffectSetV2::READ,
            ),
            mapped_node(
                30,
                20,
                200,
                ("b", 0xb2),
                StructuralRoleV2::Sink,
                EffectSetV2::SEND,
            ),
            mapped_node(
                40,
                20,
                200,
                ("b", 0xb2),
                StructuralRoleV2::Sink,
                EffectSetV2::SEND,
            ),
        ];
        let edges = vec![
            MappedEdgeV2::new(10, 30).unwrap(),
            MappedEdgeV2::new(20, 30).unwrap(),
            MappedEdgeV2::new(30, 40).unwrap(),
        ];
        let first = MappedWorkflowV2::new(&request, nodes.clone(), edges.clone()).unwrap();
        let second = MappedWorkflowV2::new(
            &request,
            vec![
                nodes[3].clone(),
                nodes[1].clone(),
                nodes[0].clone(),
                nodes[2].clone(),
            ],
            vec![edges[2], edges[1], edges[0]],
        )
        .unwrap();
        let mut first_issuer = StructuralNodeIdIssuerV2::with_test_key([0x91; 32]);
        let mut second_issuer = StructuralNodeIdIssuerV2::with_test_key([0x91; 32]);

        let (first_request, _) = first
            .relabel_with(&mut first_issuer, || Ok([0xa2; 16]))
            .unwrap();
        let (second_request, _) = second
            .relabel_with(&mut second_issuer, || Ok([0xa2; 16]))
            .unwrap();

        assert_eq!(
            encode_structural_planner_request_v2(&first_request).unwrap(),
            encode_structural_planner_request_v2(&second_request).unwrap()
        );
    }

    #[test]
    fn id_issuer_fails_closed_on_entropy_error_or_call_sequence_overflow() {
        let request = mapper_request();
        let workflow = || {
            MappedWorkflowV2::new(
                &request,
                vec![mapped_node(
                    1,
                    10,
                    100,
                    ("a", 0xa1),
                    StructuralRoleV2::Source,
                    EffectSetV2::READ,
                )],
                vec![],
            )
            .unwrap()
        };
        let mut issuer = test_issuer();
        assert!(workflow()
            .relabel_with(&mut issuer, || Err(
                PlannerPrivacyErrorV2::EntropyUnavailable
            ))
            .is_err());

        issuer.call_sequence = u64::MAX;
        assert!(workflow()
            .relabel_with(&mut issuer, || Ok([0x44; 16]))
            .is_err());
    }

    #[test]
    fn deterministic_decode_uses_remote_permutation_and_local_concrete_bindings() {
        let (envelope, structural, table) = relabeled_fixture();
        let edge = structural.graph().edges()[0];
        let ordered = OrderedStructuralPlanV2::new(vec![edge.from(), edge.to()]).unwrap();

        let decoded = decode_ordered_plan_v2(&envelope, &table, &ordered).unwrap();

        assert_eq!(decoded.envelope_nonce(), envelope.envelope_nonce());
        assert_eq!(decoded.steps().len(), 2);
        assert_eq!(decoded.steps()[0].ordinal(), 1);
        assert_eq!(decoded.steps()[0].tool_class(), ToolClassIdV2::new(100));
        assert_eq!(
            decoded.steps()[0].action_template(),
            ActionTemplateIdV2::new(10)
        );
        assert_eq!(decoded.steps()[0].slot_bindings()[0].0.as_str(), "z");
        assert!(decoded.steps()[0].dependencies().is_empty());
        assert_eq!(decoded.steps()[1].ordinal(), 2);
        assert_eq!(decoded.steps()[1].tool_class(), ToolClassIdV2::new(200));
        assert_eq!(
            decoded.steps()[1].action_template(),
            ActionTemplateIdV2::new(20)
        );
        assert_eq!(decoded.steps()[1].slot_bindings()[0].0.as_str(), "a");
        assert_eq!(decoded.steps()[1].dependencies(), &[1]);
    }

    #[test]
    fn deterministic_decode_rejects_missing_duplicate_unknown_and_non_topological_orders() {
        let (envelope, structural, table) = relabeled_fixture();
        let edge = structural.graph().edges()[0];
        let unknown = StructuralNodeIdV2::new([0xee; 16]).unwrap();
        let cases = [
            ("missing", vec![edge.from()]),
            ("duplicate", vec![edge.from(), edge.from()]),
            ("unknown", vec![edge.from(), unknown]),
            ("violates edge", vec![edge.to(), edge.from()]),
        ];
        for (name, order) in cases {
            let ordered = OrderedStructuralPlanV2::new(order).unwrap();
            assert!(
                decode_ordered_plan_v2(&envelope, &table, &ordered).is_err(),
                "{name}"
            );
        }
    }
}
