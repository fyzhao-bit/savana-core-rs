//! Strict whole-interaction checking and finite, publicly ranked release search.
//!
//! No probabilistic mode, task-progress claim, or release authorization is issued.
use crate::finite::{strict_order, Budget, CommandId, Limits, Model, StateId, MAX_BYTES};
use crate::{Digest, Error};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

pub type Pair = (StateId, StateId);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Certificate {
    pub binding: Digest,
    /// Sorted, unique inductive relation. These are private abstract states.
    pub pairs: Vec<Pair>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Event {
    Public(CommandId),
    LeftPrivate { event: u16, next: StateId },
    RightPrivate { event: u16, next: StateId },
}

/// Diagnostic for authenticated local administration, NEVER a model receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Counterexample {
    pub initial: Pair,
    pub prefix: Vec<Event>,
    pub command: CommandId,
    pub left_output: Vec<u8>,
    pub right_output: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Check {
    Safe(Certificate),
    Unsafe(Counterexample),
    Unknown,
}

type Parents = BTreeMap<Pair, Option<(Pair, Event)>>;

fn enqueue(
    pair: Pair,
    parent: Option<(Pair, Event)>,
    budget: &mut Budget,
    parents: &mut Parents,
    queue: &mut VecDeque<Pair>,
) -> Result<(), Error> {
    budget.tick()?;
    if !parents.contains_key(&pair) {
        if parents.len() >= budget.limits.pairs {
            return Err(Error::Limit);
        }
        parents.insert(pair, parent);
        queue.push_back(pair);
    }
    Ok(())
}

fn witness(
    mut pair: Pair,
    command: CommandId,
    left: &[u8],
    right: &[u8],
    parents: &Parents,
) -> Counterexample {
    let mut prefix = Vec::new();
    while let Some((previous, event)) = parents[&pair].as_ref() {
        prefix.push(event.clone());
        pair = *previous;
    }
    prefix.reverse();
    Counterexample {
        initial: pair,
        prefix,
        command,
        left_output: left.to_vec(),
        right_output: right.to_vec(),
    }
}

fn explore(model: &Model, limits: Limits) -> Result<Check, Error> {
    let mut budget = Budget::new(limits)?;
    let mut parents = Parents::new();
    let mut queue = VecDeque::new();
    for pair in model.initial_pairs() {
        enqueue(pair, None, &mut budget, &mut parents, &mut queue)?;
    }
    while let Some(pair @ (l, r)) = queue.pop_front() {
        let left = &model.states()[l as usize];
        let right = &model.states()[r as usize];
        for (index, command) in model.commands().iter().enumerate() {
            let a = &left.public[index];
            let b = &right.public[index];
            budget.tick()?;
            if a.output != b.output {
                return Ok(Check::Unsafe(witness(
                    pair, *command, &a.output, &b.output, &parents,
                )));
            }
            enqueue(
                (a.next, b.next),
                Some((pair, Event::Public(*command))),
                &mut budget,
                &mut parents,
                &mut queue,
            )?;
        }
        // Independent private moves, not just lockstep events. Repeated closure
        // includes every interleaving and every pair of nondeterministic choices.
        for step in &left.private {
            enqueue(
                (step.next, r),
                Some((
                    pair,
                    Event::LeftPrivate {
                        event: step.event,
                        next: step.next,
                    },
                )),
                &mut budget,
                &mut parents,
                &mut queue,
            )?;
        }
        for step in &right.private {
            enqueue(
                (l, step.next),
                Some((
                    pair,
                    Event::RightPrivate {
                        event: step.event,
                        next: step.next,
                    },
                )),
                &mut budget,
                &mut parents,
                &mut queue,
            )?;
        }
    }
    Ok(Check::Safe(Certificate {
        binding: model.binding(),
        pairs: parents.into_keys().collect(),
    }))
}

/// BFS reaches a fixed point, not an arbitrary number of interaction rounds.
pub fn check_strict(model: &Model, limits: Limits) -> Check {
    match explore(model, limits) {
        Ok(Check::Safe(certificate)) => match verify_certificate(model, &certificate, limits) {
            Ok(()) => Check::Safe(certificate),
            Err(_) => Check::Unknown,
        },
        Ok(result) => result,
        Err(_) => Check::Unknown,
    }
}

/// Independent checker regenerates every edge from the trusted model. A digest
/// match or a prover-supplied list of "visited edges" is not sufficient.
pub fn verify_certificate(
    model: &Model,
    certificate: &Certificate,
    limits: Limits,
) -> Result<(), Error> {
    let mut budget = Budget::new(limits)?;
    if certificate.binding != model.binding() {
        return Err(Error::Binding);
    }
    if certificate.pairs.len() > limits.pairs {
        return Err(Error::Limit);
    }
    if certificate.pairs.is_empty()
        || !strict_order(&certificate.pairs)
        || certificate.pairs.iter().any(|(l, r)| {
            *l as usize >= model.states().len() || *r as usize >= model.states().len()
        })
    {
        return Err(Error::Certificate);
    }
    let pairs: BTreeSet<_> = certificate.pairs.iter().copied().collect();
    let mut contains = |pair: Pair| -> Result<(), Error> {
        budget.tick()?;
        if pairs.contains(&pair) {
            Ok(())
        } else {
            Err(Error::Certificate)
        }
    };
    for pair in model.initial_pairs() {
        contains(pair)?;
    }
    for &(l, r) in &certificate.pairs {
        let a = &model.states()[l as usize];
        let b = &model.states()[r as usize];
        for (x, y) in a.public.iter().zip(&b.public) {
            if x.output != y.output {
                return Err(Error::Certificate);
            }
            contains((x.next, y.next))?;
        }
        for step in &a.private {
            contains((step.next, r))?;
        }
        for step in &b.private {
            contains((l, step.next))?;
        }
    }
    Ok(())
}

/// Replays the concrete trace under a NEW candidate. Old counterexamples may
/// eliminate that candidate only when a real distinguishable trace still exists.
pub fn replay_counterexample(model: &Model, counterexample: &Counterexample) -> bool {
    if !model.initial_pairs().any(|p| p == counterexample.initial) {
        return false;
    }
    let (mut l, mut r) = counterexample.initial;
    for event in &counterexample.prefix {
        match event {
            Event::Public(command) => {
                let Ok(i) = model.commands().binary_search(command) else {
                    return false;
                };
                let a = &model.states()[l as usize].public[i];
                let b = &model.states()[r as usize].public[i];
                if a.output != b.output {
                    return true;
                }
                (l, r) = (a.next, b.next);
            }
            Event::LeftPrivate { event, next } => {
                if !model.states()[l as usize]
                    .private
                    .iter()
                    .any(|s| s.event == *event && s.next == *next)
                {
                    return false;
                }
                l = *next;
            }
            Event::RightPrivate { event, next } => {
                if !model.states()[r as usize]
                    .private
                    .iter()
                    .any(|s| s.event == *event && s.next == *next)
                {
                    return false;
                }
                r = *next;
            }
        }
    }
    let Ok(i) = model.commands().binary_search(&counterexample.command) else {
        return false;
    };
    model.states()[l as usize].public[i].output != model.states()[r as usize].public[i].output
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rewrite {
    pub from: Vec<u8>,
    pub to: Vec<u8>,
}

/// First finite candidate language: static total postprocessing of COMPLETE
/// messages. It cannot generate private-state-dependent schemas or change work.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleasePolicy {
    pub model_binding: Digest,
    pub rewrites: Vec<Rewrite>,
}

impl ReleasePolicy {
    pub fn apply(&self, model: &Model) -> Result<Model, Error> {
        if self.model_binding != model.binding() {
            return Err(Error::Binding);
        }
        let alphabet: BTreeSet<_> = model
            .states()
            .iter()
            .flat_map(|s| s.public.iter().map(|p| &p.output))
            .collect();
        if self.rewrites.len() != alphabet.len()
            || self
                .rewrites
                .iter()
                .any(|r| r.to.len() > MAX_BYTES || r.from.len() > MAX_BYTES)
            || !self.rewrites.windows(2).all(|w| w[0].from < w[1].from)
        {
            return Err(Error::Invalid);
        }
        let map: BTreeMap<_, _> = self.rewrites.iter().map(|r| (&r.from, &r.to)).collect();
        // Check aggregate expansion BEFORE allocating rewritten messages.
        // A short repeated input must not expand to gigabytes before Model::new
        // eventually rejects the candidate. Candidate renderers are untrusted.
        let mut output_bytes = 0usize;
        for state in model.states() {
            for step in &state.public {
                let output = map.get(&step.output).ok_or(Error::Invalid)?;
                output_bytes = output_bytes.checked_add(output.len()).ok_or(Error::Limit)?;
                if output_bytes > 16 * 1024 * 1024 {
                    return Err(Error::Limit);
                }
            }
        }
        let mut definition = model.definition().clone();
        for state in &mut definition.states {
            for step in &mut state.public {
                step.output = (*map.get(&step.output).ok_or(Error::Invalid)?).clone();
            }
        }
        // Bind the actual renderer as well as the root's original renderer.
        definition.context.renderer = crate::digest(
            b"SAVANA_RELEASE_RENDERER_V04\0",
            &(definition.context.renderer, self),
        );
        Model::new(definition)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Synthesis {
    Safe {
        index: usize,
        certificate: Certificate,
        full_checks: usize,
        counterexamples: Vec<Counterexample>,
    },
    NoSolutionInLibrary,
    Unknown,
}

/// Public order supplies utility ranking. There is no actual production subject
/// argument. Every SAFE result receives an independent closure check.
pub fn synthesize_release(
    model: &Model,
    library: &[ReleasePolicy],
    limits: Limits,
) -> Result<Synthesis, Error> {
    if library.len() > 64 {
        return Ok(Synthesis::Unknown);
    }
    let mut counterexamples = Vec::new();
    let mut full_checks = 0;
    for (index, policy) in library.iter().enumerate() {
        let candidate = match policy.apply(model) {
            Ok(candidate) => candidate,
            Err(Error::Limit) => return Ok(Synthesis::Unknown),
            Err(error) => return Err(error),
        };
        if counterexamples
            .iter()
            .any(|c| replay_counterexample(&candidate, c))
        {
            continue;
        }
        full_checks += 1;
        match check_strict(&candidate, limits) {
            Check::Safe(certificate) => {
                return Ok(Synthesis::Safe {
                    index,
                    certificate,
                    full_checks,
                    counterexamples,
                })
            }
            Check::Unsafe(counterexample) => counterexamples.push(counterexample),
            Check::Unknown => return Ok(Synthesis::Unknown),
        }
    }
    Ok(Synthesis::NoSolutionInLibrary)
}
