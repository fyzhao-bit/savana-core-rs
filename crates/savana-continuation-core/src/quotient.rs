//! Exact finite behavioral quotient, independent from protected-world privacy.
//! This preserves finite labeled behavior and colors, not BC5 fair progress.
use crate::finite::{Budget, Limits, Model};
use crate::{Digest, Error};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Quotient {
    pub binding: Digest,
    /// Private classifier, one class for each concrete state. Not constant-size.
    pub classes: Vec<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Signature {
    previous: u32,
    public: Vec<(u16, Vec<u8>, u32)>,
    private: BTreeSet<(u16, u32)>,
}

fn signature(
    model: &Model,
    state: usize,
    classes: &[u32],
    budget: &mut Budget,
) -> Result<Signature, Error> {
    budget.tick()?;
    let mut public = Vec::new();
    let mut private = BTreeSet::new();
    for (command, step) in model.commands().iter().zip(&model.states()[state].public) {
        budget.tick()?;
        public.push((*command, step.output.clone(), classes[step.next as usize]));
    }
    for step in &model.states()[state].private {
        budget.tick()?;
        private.insert((step.event, classes[step.next as usize]));
    }
    Ok(Signature {
        previous: classes[state],
        public,
        private,
    })
}

pub fn build_quotient(model: &Model, limits: Limits) -> Result<Quotient, Error> {
    let mut budget = Budget::new(limits)?;
    if model.states().len() > limits.pairs {
        return Err(Error::Limit);
    }
    let mut colors = BTreeMap::new();
    let mut classes = Vec::new();
    for state in model.states() {
        let next = colors.len() as u32;
        classes.push(*colors.entry(state.color).or_insert(next));
    }
    loop {
        let mut signatures = BTreeMap::new();
        let mut refined = Vec::new();
        for i in 0..model.states().len() {
            let s = signature(model, i, &classes, &mut budget)?;
            let next = signatures.len() as u32;
            refined.push(*signatures.entry(s).or_insert(next));
        }
        if refined == classes {
            break;
        }
        classes = refined;
    }
    let quotient = Quotient {
        binding: model.binding(),
        classes,
    };
    verify_quotient(model, &quotient, limits)?;
    Ok(quotient)
}

/// Checks colors and complete labeled successors, not invariant equality alone.
/// Accepts any stable refinement; only build_quotient claims relative coarseness.
pub fn verify_quotient(model: &Model, quotient: &Quotient, limits: Limits) -> Result<(), Error> {
    let mut budget = Budget::new(limits)?;
    if quotient.binding != model.binding() {
        return Err(Error::Binding);
    }
    let n = model.states().len();
    if n > limits.pairs {
        return Err(Error::Limit);
    }
    if quotient.classes.len() != n || quotient.classes.iter().any(|c| *c as usize >= n) {
        return Err(Error::Certificate);
    }
    let mut representatives = BTreeMap::new();
    for (i, class) in quotient.classes.iter().enumerate() {
        let value = (
            model.states()[i].color,
            signature(model, i, &quotient.classes, &mut budget)?,
        );
        if let Some(expected) = representatives.get(class) {
            if expected != &value {
                return Err(Error::Certificate);
            }
        } else {
            representatives.insert(*class, value);
        }
    }
    if representatives
        .keys()
        .copied()
        .ne(0..representatives.len() as u32)
    {
        return Err(Error::Certificate);
    }
    Ok(())
}
