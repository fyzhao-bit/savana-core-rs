//! Explicit, total finite semantics. Construct only from a trusted host compiler.
use crate::{digest, Digest, Error};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub type StateId = u32;
pub type CommandId = u16;

pub const MAX_STATES: usize = 4096;
pub const MAX_COMMANDS: usize = 64;
pub const MAX_EDGES: usize = 262_144;
pub const MAX_BYTES: usize = 4096;

/// Exact complete logical output bytes (including types, errors and metadata),
/// not an individual value plucked out of a larger unexamined prompt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicStep {
    pub next: StateId,
    pub output: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateStep {
    pub event: u16,
    pub next: StateId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    /// Required safety/goal predicates for behavioral quotienting, not release.
    pub color: u64,
    /// One exact deterministic step for EVERY command, in declared order.
    pub public: Vec<PublicStep>,
    /// All allowed private successors, including denial/recovery if in scope.
    pub private: Vec<PrivateStep>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InitialState {
    pub state: StateId,
    /// Already-approved initial public baseline, not actual private subject.
    pub baseline: u32,
}

/// Root/semantics/observer/renderer bindings prevent accidental cross-context
/// certificate reuse. They are supplied by the trusted host, not a model RPC.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Context {
    pub root: Digest,
    pub semantics: Digest,
    pub observer_scope: Digest,
    pub renderer: Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Definition {
    pub context: Context,
    pub commands: Vec<CommandId>,
    pub initial: Vec<InitialState>,
    pub states: Vec<State>,
}

/// Validated total finite definition. No Deserialize impl can bypass validation.
#[derive(Debug, Clone)]
pub struct Model {
    definition: Definition,
    digest: Digest,
}

impl Model {
    pub fn new(definition: Definition) -> Result<Self, Error> {
        let n = definition.states.len();
        let m = definition.commands.len();
        if n == 0 || m == 0 || definition.initial.is_empty() {
            return Err(Error::Invalid);
        }
        if n > MAX_STATES || m > MAX_COMMANDS || definition.initial.len() > n {
            return Err(Error::Limit);
        }
        if [
            definition.context.root,
            definition.context.semantics,
            definition.context.observer_scope,
            definition.context.renderer,
        ]
        .contains(&[0; 32])
            || !strict_order(&definition.commands)
        {
            return Err(Error::Invalid);
        }
        let mut initial_ids = BTreeSet::new();
        for initial in &definition.initial {
            if initial.state as usize >= n || !initial_ids.insert(initial.state) {
                return Err(Error::Invalid);
            }
        }
        let mut edges = 0usize;
        let mut total_bytes = 0usize;
        for state in &definition.states {
            if state.public.len() != m || !strict_order(&state.private) {
                return Err(Error::Invalid);
            }
            edges = edges
                .checked_add(m)
                .and_then(|v| v.checked_add(state.private.len()))
                .ok_or(Error::Limit)?;
            if edges > MAX_EDGES {
                return Err(Error::Limit);
            }
            for step in &state.public {
                if step.next as usize >= n {
                    return Err(Error::Invalid);
                }
                if step.output.len() > MAX_BYTES {
                    return Err(Error::Limit);
                }
                total_bytes = total_bytes
                    .checked_add(step.output.len())
                    .ok_or(Error::Limit)?;
                if total_bytes > 16 * 1024 * 1024 {
                    return Err(Error::Limit);
                }
            }
            if state.private.iter().any(|step| step.next as usize >= n) {
                return Err(Error::Invalid);
            }
        }
        let digest = digest(b"SAVANA_FINITE_SEMANTICS_V04\0", &definition);
        Ok(Self { definition, digest })
    }

    pub fn binding(&self) -> Digest {
        self.digest
    }
    pub fn definition(&self) -> &Definition {
        &self.definition
    }
    pub fn states(&self) -> &[State] {
        &self.definition.states
    }
    pub fn commands(&self) -> &[CommandId] {
        &self.definition.commands
    }

    pub(crate) fn initial_pairs(&self) -> impl Iterator<Item = (StateId, StateId)> + '_ {
        self.definition.initial.iter().flat_map(move |left| {
            self.definition
                .initial
                .iter()
                .filter(move |right| left.baseline == right.baseline)
                .map(move |right| (left.state, right.state))
        })
    }
}

pub(crate) fn strict_order<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|w| w[0] < w[1])
}

/// Separate resource budget. Hitting it is UNKNOWN, never a proof of safety or
/// of no solution. The bound applies separately to exploration and independent
/// rechecking; the host must also budget aggregate search/admission work.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub pairs: usize,
    pub transitions: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            pairs: 1_000_000,
            transitions: 10_000_000,
        }
    }
}

pub(crate) struct Budget {
    pub limits: Limits,
    used: usize,
}
impl Budget {
    pub fn new(limits: Limits) -> Result<Self, Error> {
        if limits.pairs == 0
            || limits.transitions == 0
            || limits.pairs > 1_000_000
            || limits.transitions > 10_000_000
        {
            return Err(Error::Limit);
        }
        Ok(Self { limits, used: 0 })
    }
    pub fn tick(&mut self) -> Result<(), Error> {
        self.used = self.used.checked_add(1).ok_or(Error::Limit)?;
        if self.used > self.limits.transitions {
            Err(Error::Limit)
        } else {
            Ok(())
        }
    }
}
