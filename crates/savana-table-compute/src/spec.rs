//! The spec grammar: `_spec_text`, `_ref`, `parse_filter`, `parse_order`
//! and `parse_output` of the reference.
//!
//! ```text
//! filter  "<ref> <op> <operand>"   op: contains lacks startswith is isnt = > >= < <=
//! order   "max <ref>" | "min <ref>"
//! output  "key" | "keys" | "keys <1..32>" | "count" | "sum <ref>" | "value <ref>"
//!         | "values <ref>" | "pairs <ref>" | "mode <ref>" | "mode *.<field>"
//!         | "calc <expression>"   (only where calc is allowed)
//! ref     "key" | "1".."4" | "<n>.<field>" | "<field>" (= "1.<field>")
//! field   [A-Za-z_][A-Za-z0-9_]{0,31}
//! ```

use crate::calc::{self, Node};
use crate::table;
use crate::ComputeSpecError;

const MAX_SPEC_BYTES: usize = 128;
const MAX_OPERAND_BYTES: usize = 96;

/// What a ref names in a row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Ref {
    Key,
    /// An input's whole value (0-based input).
    Input(usize),
    /// A field of an input's record (0-based input).
    Field(usize, String),
}

impl Ref {
    pub(crate) fn input(&self) -> Option<usize> {
        match self {
            Ref::Key => None,
            Ref::Input(input) | Ref::Field(input, _) => Some(*input),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Op {
    Contains,
    Lacks,
    StartsWith,
    Is,
    Isnt,
    Eq,
    Gt,
    Ge,
    Lt,
    Le,
}

impl Op {
    fn parse(text: &str) -> Option<Op> {
        Some(match text {
            "contains" => Op::Contains,
            "lacks" => Op::Lacks,
            "startswith" => Op::StartsWith,
            "is" => Op::Is,
            "isnt" => Op::Isnt,
            "=" => Op::Eq,
            ">" => Op::Gt,
            ">=" => Op::Ge,
            "<" => Op::Lt,
            "<=" => Op::Le,
            _ => return None,
        })
    }

    fn is_numeric(self) -> bool {
        matches!(self, Op::Eq | Op::Gt | Op::Ge | Op::Lt | Op::Le)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Filter {
    pub(crate) reference: Ref,
    pub(crate) op: Op,
    /// The operand's number, for a numeric op.
    pub(crate) bound: f64,
    /// The operand folded (`_fold`), for a text op.
    pub(crate) needle: String,
}

#[derive(Debug, Clone)]
pub(crate) struct Order {
    pub(crate) max: bool,
    pub(crate) reference: Ref,
}

#[derive(Debug, Clone)]
pub(crate) enum Output {
    Key,
    Keys(Option<usize>),
    Count,
    Sum(Ref),
    Value(Ref),
    Values(Ref),
    Pairs(Ref),
    Mode(Ref),
    /// `mode *.<field>`: the field over every input's records.
    ModeAll(String),
    Calc(Node),
}

/// `_spec_text`: nonempty, no surrounding whitespace, at most 128 bytes,
/// no control character below U+0020.
fn spec_text(text: &str) -> Result<&str, ComputeSpecError> {
    if text.is_empty()
        || table::strip(text) != text
        || text.len() > MAX_SPEC_BYTES
        || text.chars().any(|c| (c as u32) < 32)
    {
        return Err(ComputeSpecError::Spec);
    }
    Ok(text)
}

/// `_FIELD`.
fn is_field(text: &str) -> bool {
    let bytes = text.as_bytes();
    (1..=32).contains(&bytes.len())
        && (bytes[0].is_ascii_alphabetic() || bytes[0] == b'_')
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'_')
}

/// `_ref`: a bare field is a field of input1; an input beyond `inputs` is
/// an input error.
fn parse_ref(text: &str, inputs: usize) -> Result<Ref, ComputeSpecError> {
    if text == "key" {
        return Ok(Ref::Key);
    }
    let (input, field) = if is_field(text) {
        (1, Some(text))
    } else {
        let bytes = text.as_bytes();
        let input = match bytes.first() {
            Some(digit @ b'1'..=b'4') => usize::from(digit - b'0'),
            _ => return Err(ComputeSpecError::Spec),
        };
        match text.get(1..) {
            Some("") => (input, None),
            Some(rest) => match rest.strip_prefix('.') {
                Some(field) if is_field(field) => (input, Some(field)),
                _ => return Err(ComputeSpecError::Spec),
            },
            None => return Err(ComputeSpecError::Spec),
        }
    };
    if input > inputs {
        return Err(ComputeSpecError::Input);
    }
    Ok(match field {
        Some(field) => Ref::Field(input - 1, field.to_string()),
        None => Ref::Input(input - 1),
    })
}

/// `parse_filter`.
pub(crate) fn parse_filter(text: &str, inputs: usize) -> Result<Filter, ComputeSpecError> {
    let parts: Vec<&str> = spec_text(text)?.splitn(3, ' ').collect();
    let op = match parts.as_slice() {
        [_, op, operand] if !table::strip(operand).is_empty() => Op::parse(op),
        _ => None,
    }
    .ok_or(ComputeSpecError::Spec)?;
    let operand = table::strip(parts[2]);
    if operand.len() > MAX_OPERAND_BYTES {
        return Err(ComputeSpecError::Spec);
    }
    let bound = table::text_number(operand);
    if op.is_numeric() && bound.is_none() {
        return Err(ComputeSpecError::Spec);
    }
    let reference = parse_ref(parts[0], inputs)?;
    Ok(Filter {
        reference,
        op,
        bound: bound.unwrap_or(0.0),
        needle: table::fold(operand),
    })
}

/// `parse_order`.
pub(crate) fn parse_order(text: &str, inputs: usize) -> Result<Order, ComputeSpecError> {
    let parts: Vec<&str> = spec_text(text)?.split(' ').collect();
    match parts.as_slice() {
        [direction @ ("max" | "min"), reference] => Ok(Order {
            max: *direction == "max",
            reference: parse_ref(reference, inputs)?,
        }),
        _ => Err(ComputeSpecError::Spec),
    }
}

/// `parse_output`.
pub(crate) fn parse_output(
    text: &str,
    inputs: usize,
    calc: bool,
) -> Result<Output, ComputeSpecError> {
    let text = spec_text(text)?;
    let parts: Vec<&str> = text.split(' ').collect();
    let kind = parts[0];
    if kind == "calc" && calc {
        if parts.len() < 2 {
            return Err(ComputeSpecError::Spec);
        }
        return calc::parse(&text["calc ".len()..], inputs).map(Output::Calc);
    }
    match kind {
        "key" | "count" => {
            if parts.len() != 1 {
                return Err(ComputeSpecError::Spec);
            }
            return Ok(if kind == "key" {
                Output::Key
            } else {
                Output::Count
            });
        }
        "keys" => {
            if parts.len() == 1 {
                return Ok(Output::Keys(None));
            }
            return match parts.as_slice() {
                [_, count] => match keys_count(count) {
                    Some(count) => Ok(Output::Keys(Some(count))),
                    None => Err(ComputeSpecError::Spec),
                },
                _ => Err(ComputeSpecError::Spec),
            };
        }
        "sum" | "value" | "values" | "pairs" | "mode" => {}
        _ => return Err(ComputeSpecError::Spec),
    }
    let [_, argument] = parts.as_slice() else {
        return Err(ComputeSpecError::Spec);
    };
    if kind == "mode" {
        if let Some(field) = argument.strip_prefix("*.") {
            if !is_field(field) {
                return Err(ComputeSpecError::Spec);
            }
            return Ok(Output::ModeAll(field.to_string()));
        }
    }
    let reference = parse_ref(argument, inputs)?;
    Ok(match kind {
        "sum" => Output::Sum(reference),
        "value" => Output::Value(reference),
        "values" => Output::Values(reference),
        "pairs" => Output::Pairs(reference),
        _ => Output::Mode(reference),
    })
}

/// "keys N": ASCII digits whose value is 1..=32.
fn keys_count(text: &str) -> Option<usize> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let significant = text.trim_start_matches('0');
    if significant.len() > 2 {
        return None;
    }
    let count: usize = if significant.is_empty() {
        0
    } else {
        significant.parse().ok()?
    };
    (1..=table::MAX_ITEMS).contains(&count).then_some(count)
}
