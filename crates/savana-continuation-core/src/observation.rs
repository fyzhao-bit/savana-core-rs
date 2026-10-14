//! Pure pin/freeze transitions. Integration must commit and anchor before egress.
//! Reading bytes here is NOT a declassification or current-reader permission.
use crate::finite::MAX_BYTES;
use crate::{digest, Digest, Error};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    pub root: Digest,
    pub policy: Digest,
    pub observer_scope: Digest,
    pub renderer: Digest,
}

/// Closed deterministic projectors. A Boolean is declared feedback, NOT strict
/// inference. Root admission must check compatibility with InferenceSpec.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Projection {
    PublicConstant(Vec<u8>),
    DeclaredBoolean,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Slot {
    pub id: u16,
    pub logical_round: u32,
    pub projection: Projection,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PinnedInput {
    Public,
    /// The authenticated host must establish the exact goal predicate at cut.
    Boolean {
        cut: Digest,
        value: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    input: PinnedInput,
    frozen: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    schema: u16,
    scope: Scope,
    slots: Vec<Slot>,
    records: BTreeMap<u16, Record>,
}

/// No Deserialize or mutation of an original record. Copies of encoded state
/// do not provide lifecycle ownership or anti-rollback evidence on their own.
#[derive(Debug, Clone)]
pub struct Observations {
    state: Snapshot,
}

impl Observations {
    pub fn new(scope: Scope, slots: Vec<Slot>) -> Result<Self, Error> {
        if [
            scope.root,
            scope.policy,
            scope.observer_scope,
            scope.renderer,
        ]
        .contains(&[0; 32])
            || slots.is_empty()
            || slots.len() > 128
            || !slots.windows(2).all(|s| s[0].id < s[1].id)
            || slots.iter().any(|s| {
                matches!(&s.projection,
                Projection::PublicConstant(b) if b.len() > MAX_BYTES)
            })
        {
            return Err(Error::Invalid);
        }
        Ok(Self {
            state: Snapshot {
                schema: 1,
                scope,
                slots,
                records: BTreeMap::new(),
            },
        })
    }

    fn slot(&self, id: u16) -> Result<&Slot, Error> {
        self.state
            .slots
            .iter()
            .find(|s| s.id == id)
            .ok_or(Error::Binding)
    }

    fn project(slot: &Slot, input: &PinnedInput) -> Result<Vec<u8>, Error> {
        match (&slot.projection, input) {
            (Projection::PublicConstant(bytes), PinnedInput::Public) => Ok(bytes.clone()),
            (Projection::DeclaredBoolean, PinnedInput::Boolean { cut, value })
                if *cut != [0; 32] =>
            {
                Ok(if *value {
                    b"true".to_vec()
                } else {
                    b"false".to_vec()
                })
            }
            _ => Err(Error::Binding),
        }
    }

    /// Called by the private fixed publisher, NEVER by the model-facing observe.
    /// Same exact pin is idempotent; new input at an old slot is rejected.
    pub fn pin(&mut self, slot: u16, logical_round: u32, input: PinnedInput) -> Result<(), Error> {
        let definition = self.slot(slot)?;
        if definition.logical_round != logical_round {
            return Err(Error::Binding);
        }
        Self::project(definition, &input)?;
        if let Some(original) = self.state.records.get(&slot) {
            return if original.input == input {
                Ok(())
            } else {
                Err(Error::History)
            };
        }
        self.state.records.insert(
            slot,
            Record {
                input,
                frozen: None,
            },
        );
        Ok(())
    }

    /// Takes no current facts, clock or model callback: evaluates original input.
    pub fn freeze(&mut self, slot: u16) -> Result<(), Error> {
        let definition = self.slot(slot)?;
        let record = self.state.records.get(&slot).ok_or(Error::History)?;
        let bytes = Self::project(definition, &record.input)?;
        self.state
            .records
            .get_mut(&slot)
            .ok_or(Error::History)?
            .frozen = Some(bytes);
        Ok(())
    }

    /// For the host's CURRENT reader/release checks, not directly for an Agent.
    /// No allocation of a slot, private work, or recomputation on reread.
    pub fn frozen_bytes_for_release_check(&self, slot: u16) -> Option<&[u8]> {
        self.state
            .records
            .get(&slot)
            .and_then(|r| r.frozen.as_deref())
    }

    pub fn charged_slots(&self) -> usize {
        self.state.records.len()
    }

    pub fn snapshot(&self) -> Result<Vec<u8>, Error> {
        serde_json::to_vec(&self.state).map_err(|_| Error::Invalid)
    }

    /// Digest to bind into the owner commit. It is NOT an independent anchor.
    pub fn state_commitment(&self) -> Digest {
        digest(b"SAVANA_OBSERVATION_STATE_V04\0", &self.state)
    }

    /// expected_commitment must come from authenticated committed owner state,
    /// never from the same untrusted snapshot. This checks content, not freshness.
    pub fn restore(
        bytes: &[u8],
        scope: &Scope,
        slots: &[Slot],
        expected_commitment: Digest,
    ) -> Result<Self, Error> {
        if bytes.len() > 4 * 1024 * 1024 {
            return Err(Error::Limit);
        }
        let state: Snapshot = serde_json::from_slice(bytes).map_err(|_| Error::Invalid)?;
        if serde_json::to_vec(&state).map_err(|_| Error::Invalid)? != bytes
            || state.schema != 1
            || &state.scope != scope
            || state.slots != slots
            || digest(b"SAVANA_OBSERVATION_STATE_V04\0", &state) != expected_commitment
        {
            return Err(Error::Binding);
        }
        let mut result = Self::new(scope.clone(), slots.to_vec())?;
        for (id, record) in state.records {
            let slot = result.slot(id)?;
            let exact = Self::project(slot, &record.input)?;
            if record.frozen.as_ref().is_some_and(|bytes| *bytes != exact) {
                return Err(Error::History);
            }
            result.state.records.insert(id, record);
        }
        Ok(result)
    }
}
