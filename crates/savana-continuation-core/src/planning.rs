//! Closed fused-planning protocol. Pure transitions, NOT effect or egress grants.
//!
//! The durable host must authenticate the policy, bind it to current authority,
//! commit/anchor every mutation and perform current release checks before send.
//! No live transport, model callbacks, secret-dependent rendering or clock exists
//! here. The first profile supports constant public views and registered plans.
use crate::planning_observation::{ObservationSource, ResultObservation};
use crate::{digest, Digest, Error};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const MAX_WIRE_BYTES: usize = 16 * 1024;
const MAX_ROUNDS: usize = 16;
const MAX_OPERATIONS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Advisor,
    Planner,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    StructuralOrderV04,
    RegisteredTemplateV04,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SlotBinding {
    pub argument: String,
    pub slot: [u8; 16],
    /// Signed private data edge, not a model-supplied value. Schema 2 or 3.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_of: Option<u16>,
    /// For a result edge into a non-payload field: the fixed JSON path the
    /// kernel extracts a scalar from, and the byte bound on a text scalar.
    /// Absent means the whole-result edge into the payload field (`body`). The
    /// owner-signed control authorizes which field, path and bound; the compiler
    /// and G4 enforce that match, so a planner cannot widen this edge.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_path: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_max_bytes: Option<u16>,
}

/// Private compiler input. Never serialize this registry to a model implicitly.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Operation {
    pub id: u16,
    pub tool_class: u16,
    pub action_template: u16,
    pub bindings: Vec<SlotBinding>,
    pub after: Vec<u16>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Template {
    pub id: u16,
    pub order: Vec<u16>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Round {
    /// Schema 3 only. Administrator approval includes the availability bit and
    /// selected value at this fixed slot, not just the final transcript.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub observations: Vec<ResultObservation>,
    pub id: u16,
    pub opens_at: u64,
    /// Public cut at which advice is settled and the planner envelope is frozen.
    pub advice_cut: u64,
    pub closes_at: u64,
    pub advisor: Option<Digest>,
    pub planner: Digest,
    pub model_profile: u16,
    pub mode: Mode,
    /// Already approved complete semantic view; NOT a redaction-model output.
    pub public_view: Vec<u8>,
    pub template_ids: Vec<u16>,
    pub question_codes: Vec<u16>,
    pub max_deliveries: u16,
}

/// Trusted local configuration; contains private bindings, so no Debug derive.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub schema: u16,
    pub root: Digest,
    pub observer_scope: Digest,
    pub operations: Vec<Operation>,
    pub templates: Vec<Template>,
    pub rounds: Vec<Round>,
    /// Zero disables replacement. Installing a new policy cannot reset this.
    pub max_replacements: u16,
}

fn ordered(values: &[u16]) -> bool {
    values.iter().all(|v| *v != 0) && values.windows(2).all(|w| w[0] < w[1])
}

impl Policy {
    pub fn validate(&self) -> Result<(), Error> {
        if !matches!(self.schema, 1 | 2 | 3)
            || [self.root, self.observer_scope].contains(&[0; 32])
            || self.operations.is_empty()
            || self.operations.len() > MAX_OPERATIONS
            || self.templates.is_empty()
            || self.templates.len() > 32
            || self.rounds.is_empty()
            || self.rounds.len() > MAX_ROUNDS
            || usize::from(self.max_replacements) >= MAX_ROUNDS
            || !ordered(&self.operations.iter().map(|x| x.id).collect::<Vec<_>>())
            || !ordered(&self.templates.iter().map(|x| x.id).collect::<Vec<_>>())
            || !ordered(&self.rounds.iter().map(|x| x.id).collect::<Vec<_>>())
        {
            return Err(Error::Invalid);
        }
        for operation in &self.operations {
            if operation.tool_class == 0
                || operation.action_template == 0
                || operation.bindings.len() > 16
                || !ordered(&operation.after)
                || operation
                    .after
                    .iter()
                    .any(|id| *id == operation.id || !self.operations.iter().any(|o| o.id == *id))
                || operation.bindings.iter().any(|b| b.slot == [0; 16]
                        // Structural edge checks only: a result edge needs
                        // schema >= 2 and a declared predecessor source. Which
                        // FIELD (payload vs a non-payload role) and which PATH
                        // are authorized is the compiler's and G4's job, against
                        // the owner-signed control; this crate sees no roles.
                        || b.result_of.is_some_and(|source| {
                            self.schema < 2 || !operation.after.contains(&source)
                        })
                        // A path/bound may appear only together, on a result
                        // edge, with a well-formed path and a non-zero bound: a
                        // whole-result (payload) edge carries neither.
                        || (b.result_path.is_some() != b.result_max_bytes.is_some())
                        || (b.result_path.is_some() && b.result_of.is_none())
                        || b.result_max_bytes == Some(0)
                        || b.result_path.as_ref().is_some_and(|path| {
                            path.len() > 16
                                || path.iter().any(|s| {
                                    s.is_empty()
                                        || s.len() > 128
                                        || s.chars().any(char::is_control)
                                })
                        })
                        || b.argument.is_empty()
                        || b.argument.len() > 64
                        || !b
                            .argument
                            .bytes()
                            .all(|c| c.is_ascii_alphanumeric() || c == b'_'))
                || !operation
                    .bindings
                    .windows(2)
                    .all(|w| w[0].argument < w[1].argument)
            {
                return Err(Error::Invalid);
            }
        }
        // A slot has exactly one signed origin across the entire workflow.
        let mut origins = std::collections::BTreeMap::new();
        for b in self.operations.iter().flat_map(|o| &o.bindings) {
            if let Some(old) = origins.insert(b.slot, b.result_of) {
                if old != b.result_of {
                    return Err(Error::Invalid);
                }
            }
        }
        for template in &self.templates {
            self.check_order(&template.order)?;
        }
        for (i, round) in self.rounds.iter().enumerate() {
            if round.observations.len() > 4
                || (!round.observations.is_empty() && self.schema != 3)
                || round.observations.iter().any(|s| {
                    s.validate().is_err() || !self.operations.iter().any(|o| o.id == s.source)
                })
                || round
                    .observations
                    .windows(2)
                    .any(|w| (&w[0].source, &w[0].path) >= (&w[1].source, &w[1].path))
            {
                return Err(Error::Invalid);
            }
            if round.opens_at > round.advice_cut
                || round.advice_cut >= round.closes_at
                || (round.advisor.is_some() && round.opens_at == round.advice_cut)
                || (round.advisor.is_none() && round.opens_at != round.advice_cut)
                || round.advisor == Some([0; 32])
                || round.planner == [0; 32]
                || round.model_profile == 0
                || round.public_view.len() > 4096
                || round.template_ids.is_empty()
                || !ordered(&round.template_ids)
                || !ordered(&round.question_codes)
                || round.question_codes.len() > 32
                || round
                    .template_ids
                    .iter()
                    .any(|id| !self.templates.iter().any(|t| t.id == *id))
                || round.max_deliveries == 0
                || round.max_deliveries > 8
                || (i > 0 && self.rounds[i - 1].closes_at > round.opens_at)
            {
                return Err(Error::Invalid);
            }
        }
        Ok(())
    }

    fn check_order(&self, order: &[u16]) -> Result<(), Error> {
        if order.len() != self.operations.len()
            || order.iter().copied().collect::<BTreeSet<_>>()
                != self.operations.iter().map(|o| o.id).collect()
        {
            return Err(Error::Binding);
        }
        for (position, id) in order.iter().enumerate() {
            let op = self
                .operations
                .iter()
                .find(|o| o.id == *id)
                .ok_or(Error::Binding)?;
            if !op.after.iter().all(|dep| order[..position].contains(dep)) {
                return Err(Error::Binding);
            }
        }
        Ok(())
    }

    pub fn commitment(&self) -> Result<Digest, Error> {
        self.validate()?;
        Ok(digest(b"SAVANA_FUSED_PLANNING_POLICY_V04\0", self))
    }
}

/// Complete model-facing object. No root/task/store/ledger digest or real handle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelView {
    pub schema: u16,
    pub job: [u8; 16],
    pub role: Role,
    pub model_profile: u16,
    /// Unix milliseconds, sent as 8 big-endian bytes (see `wire_deadline`).
    #[serde(with = "wire_deadline")]
    pub deadline: u64,
    pub mode: Mode,
    pub public_view: Vec<u8>,
    pub template_ids: Vec<u16>,
    pub question_codes: Vec<u16>,
    pub suggested_templates: Vec<u16>,
    pub suggested_questions: Vec<u16>,
}
impl ModelView {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, Error> {
        wire(self)
    }
    pub fn commitment(&self) -> Digest {
        digest(b"SAVANA_FUSED_MODEL_VIEW_V04\0", self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewAdvice {
    pub schema: u16,
    pub job: [u8; 16],
    pub view: Digest,
    pub templates: Vec<u16>,
    pub questions: Vec<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PlanChoice {
    RegisteredTemplate { template: u16 },
    StructuralOrder { order: Vec<u16> },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanProposal {
    pub schema: u16,
    pub job: [u8; 16],
    pub view: Digest,
    pub choice: PlanChoice,
}

/// The G3 leak gate scans the released JSON wire. A 13-digit Unix-ms decimal
/// matches its card/phone PII patterns, so a decimal deadline would withhold
/// every view. Fixed-width bytes carry the same value without digit runs.
mod wire_deadline {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(value: &u64, serializer: S) -> Result<S::Ok, S::Error> {
        value.to_be_bytes().serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
        <[u8; 8]>::deserialize(deserializer).map(u64::from_be_bytes)
    }
}

fn wire<T: Serialize>(value: &T) -> Result<Vec<u8>, Error> {
    let bytes = serde_json::to_vec(value).map_err(|_| Error::Invalid)?;
    if bytes.len() > MAX_WIRE_BYTES {
        return Err(Error::Limit);
    }
    Ok(bytes)
}
fn decode<T: serde::de::DeserializeOwned + Serialize>(bytes: &[u8]) -> Result<T, Error> {
    if bytes.len() > MAX_WIRE_BYTES {
        return Err(Error::Limit);
    }
    let value = serde_json::from_slice(bytes).map_err(|_| Error::Invalid)?;
    if wire(&value)? != bytes {
        return Err(Error::Invalid);
    }
    Ok(value)
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RoundState {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    observation: Option<FrozenObservation>,
    review_job: Option<[u8; 16]>,
    planner_job: [u8; 16],
    review_deliveries: u16,
    planner_deliveries: u16,
    advice: Option<ReviewAdvice>,
    envelope: Option<ModelView>,
    proposal: Option<PlanProposal>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FrozenObservation {
    at: u64,
    inputs: Vec<ObservationSource>,
}

/// Compiled local plan; cannot be constructed by deserializing model output.
#[derive(Clone)]
pub struct CompiledPlan {
    policy: Digest,
    operations: Vec<Operation>,
}
impl CompiledPlan {
    pub fn operations(&self) -> &[Operation] {
        &self.operations
    }
    pub fn policy(&self) -> Digest {
        self.policy
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActivePlan {
    round: u16,
    revision: u64,
    replacements: u16,
    order: Vec<u16>,
    /// Original execution IDs in exact started prefix. No outcome-based removal.
    started: Vec<Digest>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanningState {
    policy: Policy,
    rounds: Vec<RoundState>,
    active: Option<ActivePlan>,
}

impl PlanningState {
    /// IDs must be freshly sampled by the trusted host, not derived from secrets.
    /// All rounds are allocated once, not in response to private failure.
    pub fn new(policy: Policy, jobs: Vec<(Option<[u8; 16]>, [u8; 16])>) -> Result<Self, Error> {
        policy.validate()?;
        if jobs.len() != policy.rounds.len() {
            return Err(Error::Binding);
        }
        let mut ids = BTreeSet::new();
        let mut rounds = Vec::new();
        for (round, (review, planner)) in policy.rounds.iter().zip(jobs) {
            if review.is_some() != round.advisor.is_some() {
                return Err(Error::Binding);
            }
            for id in review.iter().chain(std::iter::once(&planner)) {
                if *id == [0; 16] || !ids.insert(*id) {
                    return Err(Error::Binding);
                }
            }
            rounds.push(RoundState {
                observation: None,
                review_job: review,
                planner_job: planner,
                review_deliveries: 0,
                planner_deliveries: 0,
                advice: None,
                envelope: None,
                proposal: None,
            });
        }
        Ok(Self {
            policy,
            rounds,
            active: None,
        })
    }
    pub fn policy(&self) -> &Policy {
        &self.policy
    }
    pub fn active_round(&self) -> Option<u16> {
        self.active.as_ref().map(|a| a.round)
    }
    /// Private-owner recovery invariant, never model-visible feedback.
    pub fn delivery_attempts(&self, round: u16, role: Role) -> Result<u16, Error> {
        let r = &self.rounds[self.index(round)?];
        Ok(match role {
            Role::Advisor => r.review_deliveries,
            Role::Planner => r.planner_deliveries,
        })
    }
    fn index(&self, id: u16) -> Result<usize, Error> {
        self.policy
            .rounds
            .iter()
            .position(|r| r.id == id)
            .ok_or(Error::Binding)
    }
    fn view(&self, i: usize, role: Role) -> Result<ModelView, Error> {
        let r = &self.policy.rounds[i];
        let s = &self.rounds[i];
        let advice = if role == Role::Planner {
            s.advice.as_ref()
        } else {
            None
        };
        Ok(ModelView {
            schema: 1,
            job: if role == Role::Advisor {
                s.review_job.ok_or(Error::Binding)?
            } else {
                s.planner_job
            },
            role,
            model_profile: r.model_profile,
            deadline: if role == Role::Advisor {
                r.advice_cut
            } else {
                r.closes_at
            },
            mode: r.mode,
            public_view: if r.observations.is_empty() {
                r.public_view.clone()
            } else {
                crate::planning_observation::render(
                    &r.public_view,
                    &r.observations,
                    &s.observation.as_ref().ok_or(Error::History)?.inputs,
                )?
            },
            template_ids: r.template_ids.clone(),
            question_codes: r.question_codes.clone(),
            suggested_templates: advice.map(|a| a.templates.clone()).unwrap_or_default(),
            suggested_questions: advice.map(|a| a.questions.clone()).unwrap_or_default(),
        })
    }

    /// Called only by the trusted host at a signed public slot, using original
    /// committed results. Freeze once before advice or planner delivery. Missing
    /// data stays missing in this round even when a late response arrives.
    pub fn freeze_observations(
        &mut self,
        round: u16,
        inputs: Vec<ObservationSource>,
        now: u64,
    ) -> Result<bool, Error> {
        let i = self.index(round)?;
        let r = &self.policy.rounds[i];
        if now < r.opens_at || now >= r.closes_at {
            return Err(Error::Binding);
        }
        if let Some(old) = &self.rounds[i].observation {
            return if old.inputs == inputs {
                Ok(false)
            } else {
                Err(Error::History)
            };
        }
        if self.rounds[i].envelope.is_some()
            || self.rounds[i].review_deliveries != 0
            || self.rounds[i].planner_deliveries != 0
        {
            return Err(Error::History);
        }
        crate::planning_observation::render(&r.public_view, &r.observations, &inputs)?;
        self.rounds[i].observation = Some(FrozenObservation { at: now, inputs });
        Ok(true)
    }
    pub fn observations_frozen(&self, round: u16) -> Result<bool, Error> {
        Ok(self.rounds[self.index(round)?].observation.is_some())
    }
    /// Private recovery evidence, never a model or user output.
    pub fn frozen_observations(&self) -> Vec<(u16, u64, &[ObservationSource])> {
        self.policy
            .rounds
            .iter()
            .zip(&self.rounds)
            .filter_map(|(r, s)| {
                s.observation
                    .as_ref()
                    .map(|o| (r.id, o.at, o.inputs.as_slice()))
            })
            .collect()
    }

    /// Freeze at a public cut, independently of private work or advice arrival.
    /// No advice means the already admitted empty-suggestions fallback.
    pub fn freeze_envelope(&mut self, round: u16, now: u64) -> Result<bool, Error> {
        let i = self.index(round)?;
        let r = &self.policy.rounds[i];
        if now < r.advice_cut || now >= r.closes_at {
            return Err(Error::Binding);
        }
        if self.rounds[i].envelope.is_some() {
            return Ok(false);
        }
        self.rounds[i].envelope = Some(self.view(i, Role::Planner)?);
        Ok(true)
    }

    /// Reserve a transmission attempt. Host must COMMIT before releasing bytes,
    /// and still enforce current G3/disclosure/recipient checks. No hidden retry.
    pub fn reserve_delivery(
        &mut self,
        round: u16,
        role: Role,
        recipient: Digest,
        now: u64,
    ) -> Result<ModelView, Error> {
        let i = self.index(round)?;
        let r = &self.policy.rounds[i];
        let expected = if role == Role::Advisor {
            r.advisor.ok_or(Error::Binding)?
        } else {
            r.planner
        };
        let (start, end) = if role == Role::Advisor {
            (r.opens_at, r.advice_cut)
        } else {
            (r.advice_cut, r.closes_at)
        };
        if recipient != expected || now < start || now >= end {
            return Err(Error::Binding);
        }
        let view = if role == Role::Advisor {
            self.view(i, role)?
        } else {
            self.rounds[i].envelope.clone().ok_or(Error::History)?
        };
        let counter = if role == Role::Advisor {
            &mut self.rounds[i].review_deliveries
        } else {
            &mut self.rounds[i].planner_deliveries
        };
        if *counter >= r.max_deliveries {
            return Err(Error::Limit);
        }
        *counter += 1;
        Ok(view)
    }

    pub fn accept_advice(
        &mut self,
        round: u16,
        sender: Digest,
        bytes: &[u8],
        now: u64,
    ) -> Result<bool, Error> {
        let i = self.index(round)?;
        let r = &self.policy.rounds[i];
        let advice: ReviewAdvice = decode(bytes)?;
        if r.advisor != Some(sender)
            || advice.schema != 1
            || Some(advice.job) != self.rounds[i].review_job
            || advice.view != self.view(i, Role::Advisor)?.commitment()
            || !ordered(&advice.templates)
            || !ordered(&advice.questions)
            || !advice
                .templates
                .iter()
                .all(|id| r.template_ids.contains(id))
            || !advice
                .questions
                .iter()
                .all(|id| r.question_codes.contains(id))
            || self.rounds[i].review_deliveries == 0
        {
            return Err(Error::Binding);
        }
        if let Some(old) = &self.rounds[i].advice {
            return if old == &advice {
                Ok(false)
            } else {
                Err(Error::History)
            };
        }
        if now < r.opens_at || now >= r.advice_cut || self.rounds[i].envelope.is_some() {
            return Err(Error::History);
        }
        self.rounds[i].advice = Some(advice);
        Ok(true)
    }

    fn compile(&self, i: usize, proposal: &PlanProposal) -> Result<CompiledPlan, Error> {
        let r = &self.policy.rounds[i];
        let envelope = self.rounds[i].envelope.as_ref().ok_or(Error::History)?;
        if proposal.schema != 1
            || proposal.job != envelope.job
            || proposal.view != envelope.commitment()
        {
            return Err(Error::Binding);
        }
        let order = match (&r.mode, &proposal.choice) {
            (Mode::RegisteredTemplateV04, PlanChoice::RegisteredTemplate { template })
                if r.template_ids.contains(template) =>
            {
                &self
                    .policy
                    .templates
                    .iter()
                    .find(|t| t.id == *template)
                    .ok_or(Error::Binding)?
                    .order
            }
            (Mode::StructuralOrderV04, PlanChoice::StructuralOrder { order }) => order,
            _ => return Err(Error::Binding),
        };
        self.policy.check_order(order)?;
        Ok(CompiledPlan {
            policy: self.policy.commitment()?,
            operations: order
                .iter()
                .map(|id| {
                    self.policy
                        .operations
                        .iter()
                        .find(|o| o.id == *id)
                        .unwrap()
                        .clone()
                })
                .collect(),
        })
    }

    pub fn accept_plan(
        &mut self,
        round: u16,
        sender: Digest,
        bytes: &[u8],
        now: u64,
    ) -> Result<bool, Error> {
        let i = self.index(round)?;
        let r = &self.policy.rounds[i];
        if sender != r.planner || self.rounds[i].planner_deliveries == 0 {
            return Err(Error::Binding);
        }
        let proposal: PlanProposal = decode(bytes)?;
        self.compile(i, &proposal)?;
        if let Some(old) = &self.rounds[i].proposal {
            return if old == &proposal {
                Ok(false)
            } else {
                Err(Error::History)
            };
        }
        if now < r.advice_cut || now >= r.closes_at {
            return Err(Error::Binding);
        }
        self.rounds[i].proposal = Some(proposal);
        Ok(true)
    }

    /// No execution permission. Returns only validated, locally bound operations.
    pub fn compiled(&self, round: u16) -> Result<CompiledPlan, Error> {
        let i = self.index(round)?;
        self.compile(i, self.rounds[i].proposal.as_ref().ok_or(Error::History)?)
    }

    /// Restricted residual rule: retain all operations and dependency edges and
    /// preserve the exact started prefix. No arbitrary interface-equivalence claim.
    pub fn activate(&mut self, round: u16, expected_revision: u64) -> Result<bool, Error> {
        let order: Vec<_> = self
            .compiled(round)?
            .operations
            .iter()
            .map(|o| o.id)
            .collect();
        let next = match &self.active {
            None if expected_revision == 0 => ActivePlan {
                round,
                revision: 1,
                replacements: 0,
                order,
                started: vec![],
            },
            Some(old) if old.revision == expected_revision => {
                if old.round == round {
                    return Ok(false);
                }
                if round <= old.round
                    || old.replacements >= self.policy.max_replacements
                    || old.started.len() == old.order.len()
                    || order[..old.started.len()] != old.order[..old.started.len()]
                {
                    return Err(Error::History);
                }
                ActivePlan {
                    round,
                    revision: old.revision.checked_add(1).ok_or(Error::Limit)?,
                    replacements: old.replacements + 1,
                    order,
                    started: old.started.clone(),
                }
            }
            _ => return Err(Error::Binding),
        };
        self.active = Some(next);
        Ok(true)
    }

    /// Host-only: couple this to the original G7 reservation, never model status.
    pub fn retain_started(
        &mut self,
        revision: u64,
        operation: u16,
        execution: Digest,
    ) -> Result<bool, Error> {
        let a = self.active.as_mut().ok_or(Error::History)?;
        if a.revision != revision || execution == [0; 32] {
            return Err(Error::Binding);
        }
        if let Some(index) = a.order[..a.started.len()]
            .iter()
            .position(|id| *id == operation)
        {
            return if a.started[index] == execution {
                Ok(false)
            } else {
                Err(Error::History)
            };
        }
        if a.order.get(a.started.len()) != Some(&operation) || a.started.contains(&execution) {
            return Err(Error::History);
        }
        a.started.push(execution);
        Ok(true)
    }
    pub fn active_revision(&self) -> u64 {
        self.active.as_ref().map(|a| a.revision).unwrap_or(0)
    }
    pub fn started_executions(&self) -> &[Digest] {
        self.active
            .as_ref()
            .map(|a| a.started.as_slice())
            .unwrap_or(&[])
    }

    /// Private owner projection used to cross-check the actual execution journal.
    pub fn started_operations(&self) -> Vec<(u16, Digest)> {
        self.active
            .as_ref()
            .map(|a| {
                a.order
                    .iter()
                    .copied()
                    .zip(a.started.iter().copied())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Revalidate authenticated stored state. Does not establish freshness itself.
    pub fn validate(&self) -> Result<(), Error> {
        let jobs = self
            .rounds
            .iter()
            .map(|s| (s.review_job, s.planner_job))
            .collect();
        let mut rebuilt = Self::new(self.policy.clone(), jobs)?;
        for (i, stored) in self.rounds.iter().enumerate() {
            let r = &self.policy.rounds[i];
            if let Some(frozen) = &stored.observation {
                rebuilt.freeze_observations(r.id, frozen.inputs.clone(), frozen.at)?;
            }
            if stored.review_deliveries > r.max_deliveries
                || stored.planner_deliveries > r.max_deliveries
                || (r.advisor.is_none() && stored.review_deliveries != 0)
            {
                return Err(Error::History);
            }
            rebuilt.rounds[i].review_deliveries = stored.review_deliveries;
            if let Some(advice) = &stored.advice {
                rebuilt.accept_advice(
                    r.id,
                    r.advisor.ok_or(Error::Binding)?,
                    &wire(advice)?,
                    r.opens_at,
                )?;
            }
            if let Some(envelope) = &stored.envelope {
                rebuilt.freeze_envelope(r.id, r.advice_cut)?;
                if rebuilt.rounds[i].envelope.as_ref() != Some(envelope) {
                    return Err(Error::History);
                }
            } else if stored.planner_deliveries != 0 || stored.proposal.is_some() {
                return Err(Error::History);
            }
            rebuilt.rounds[i].planner_deliveries = stored.planner_deliveries;
            if let Some(proposal) = &stored.proposal {
                rebuilt.accept_plan(r.id, r.planner, &wire(proposal)?, r.advice_cut)?;
            }
        }
        if let Some(active) = &self.active {
            let compiled = rebuilt.compiled(active.round)?;
            if active.revision != u64::from(active.replacements) + 1
                || active.replacements > self.policy.max_replacements
                || active.order != compiled.operations.iter().map(|o| o.id).collect::<Vec<_>>()
                || active.started.len() > active.order.len()
                || active.started.contains(&[0; 32])
                || active.started.iter().collect::<BTreeSet<_>>().len() != active.started.len()
            {
                return Err(Error::History);
            }
        }
        Ok(())
    }
}
