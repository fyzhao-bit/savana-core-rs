//! `dojo.compute.table`: the deterministic computation over earlier results
//! that a drafted program's compute step asks for, evaluated by the trusted
//! executor rather than by a connector.
//!
//! This is a byte-exact port of `experiments/savana_bench/dojo_compute.py`
//! (`compute`, `validate_spec`, `calc_constants` and every helper they use):
//! for the same inputs, [`compute`] returns the same output (compare
//! [`ComputeOutput::canonical_json`] with the reference's
//! `canonical({"text": ..., "items": [...]})`) or the same error.
//! `experiments/tests/test_compute_rust_parity.py` checks that on the
//! reference's own test cases, on real AgentDojo tool results and on
//! seeded random fuzz, through `examples/compute_diff.rs`.
//!
//! ## The function
//!
//! ```text
//! inputs   input1..input4: earlier results (a tool result's JSON text, or an
//!          extracted/computed value); "" = absent, and the given ones come first
//! filters  "<ref> <op> <operand>", every one must hold
//! orders   "max <ref>" | "min <ref>" (numeric; ties fall through to the next
//!          order, then to the key in code point order; missing numbers last)
//! output   "key" | "keys [n]" | "count" | "sum <ref>" | "value <ref>"
//!          | "values <ref>" | "pairs <ref>" | "mode <ref>" | "mode *.<field>"
//!          | "calc <expression>" (where the run allows it)
//! ```
//!
//! input1 gives the rows (an object's entries, a list's records keyed by
//! `id`/`id_`/`name`/`title`/`filename` or position, a list of texts, or a
//! text's lines); every other input is joined to them by key (exactly, then
//! NFKC-lowercased). "calc" evaluates exact decimal arithmetic (34 digits,
//! half-even) on the first number of each input, rounded to cents.
//! The output is at most 32 items of at most 160 bytes, 480 bytes joined.
//!
//! ## Rules made explicit in both implementations
//!
//! Where Python's behavior rested on interpreter internals, the reference
//! states a rule and this crate implements the same one: JSON nested more
//! than 128 deep, the constants `NaN`/`Infinity`, a lone surrogate escape or
//! an integer literal over 4300 digits make a text plain text; a number
//! beyond the float range is infinite and an infinite number has no text;
//! case folding is `NFKC` then `str.lower()` (not `casefold`); "keys N"
//! takes ASCII digits; the decimal context has unbounded exponents; and
//! `calc_constants` of an output that is not "calc" is empty. Python's
//! whitespace (`isspace`: Unicode `White_Space` plus U+001C..U+001F) and
//! line boundaries (`splitlines`) are fixed sets here.
//!
//! ## Totality
//!
//! Every function is total: it returns a value or a [`ComputeSpecError`] and
//! never panics. Work is bounded by the input sizes: parsing is linear;
//! rows are at most 256 per input, and each spec text reads each row once,
//! so a row's value is read at most once per filter, order and output (as
//! in the reference); exact products are Karatsuba. Recursion is bounded by
//! the JSON depth limit (128), the calc grammar's limits (64 tokens, depth
//! 8) and Karatsuba's halving (capped at 48 levels); all exponent
//! arithmetic is checked.

#![forbid(unsafe_code)]

mod calc;
mod decimal;
mod json;
mod pyfloat;
mod spec;
mod table;

#[cfg(test)]
mod tests;

use std::cmp::Ordering;

use json::Value;
use spec::{Filter, Op, Order, Output, Ref};

/// Why a compute step cannot run: the reference's `ComputeSpecError` codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ComputeSpecError {
    /// "compute_spec": a filter, order or output text outside the grammar.
    #[error("compute_spec")]
    Spec,
    /// "compute_input": the inputs are not contiguous from input1, or a ref
    /// names an input that was not given.
    #[error("compute_input")]
    Input,
}

/// A computed value: data exactly like an extraction's.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ComputeOutput {
    /// The items joined by "; ".
    pub text: String,
    pub items: Vec<String>,
}

impl ComputeOutput {
    /// The reference's `canonical({"text": ..., "items": [...]})`: sorted
    /// keys, no spaces, non-ASCII as is, `json.dumps` escapes.
    pub fn canonical_json(&self) -> String {
        let mut out = String::from("{\"items\":[");
        for (at, item) in self.items.iter().enumerate() {
            if at > 0 {
                out.push(',');
            }
            json::escape_into(item, &mut out);
        }
        out.push_str("],\"text\":");
        json::escape_into(&self.text, &mut out);
        out.push('}');
        out
    }
}

/// A step's parsed spec texts for a number of inputs: what the owner's
/// review accepts ([`ComputeSpec::parse`]) and the executor evaluates
/// ([`ComputeSpec::evaluate`]).
#[derive(Debug, Clone)]
pub struct ComputeSpec {
    filter_texts: Vec<String>,
    order_texts: Vec<String>,
    output_text: String,
    calc: bool,
    inputs: usize,
    filters: Vec<Filter>,
    orders: Vec<Order>,
    output: Output,
}

impl ComputeSpec {
    /// Parses spec texts for `inputs` inputs, as the reference's
    /// `validate_spec` reviews them: each filter, then each order, then the
    /// output, then "mode *." and "calc" outputs refuse filters and orders.
    /// An empty filter or order text is absent. `calc` admits a "calc"
    /// output.
    pub fn parse(
        filters: &[&str],
        orders: &[&str],
        output: &str,
        inputs: usize,
        calc: bool,
    ) -> Result<ComputeSpec, ComputeSpecError> {
        let filter_texts: Vec<String> = filters
            .iter()
            .filter(|t| !t.is_empty())
            .map(|t| t.to_string())
            .collect();
        let order_texts: Vec<String> = orders
            .iter()
            .filter(|t| !t.is_empty())
            .map(|t| t.to_string())
            .collect();
        let parsed_filters = filter_texts
            .iter()
            .map(|text| spec::parse_filter(text, inputs))
            .collect::<Result<Vec<_>, _>>()?;
        let parsed_orders = order_texts
            .iter()
            .map(|text| spec::parse_order(text, inputs))
            .collect::<Result<Vec<_>, _>>()?;
        let parsed_output = spec::parse_output(output, inputs, calc)?;
        let exclusive = matches!(parsed_output, Output::Calc(_) | Output::ModeAll(_));
        if exclusive && !(parsed_filters.is_empty() && parsed_orders.is_empty()) {
            return Err(ComputeSpecError::Spec);
        }
        Ok(ComputeSpec {
            filter_texts,
            order_texts,
            output_text: output.to_string(),
            calc,
            inputs,
            filters: parsed_filters,
            orders: parsed_orders,
            output: parsed_output,
        })
    }

    /// The reference's `compute` of these spec texts over `inputs` (input1
    /// first, "" = absent). When the number of inputs present differs from
    /// the number the spec was parsed for, the spec is read again for the
    /// inputs given, as the reference reads it.
    pub fn evaluate(&self, inputs: &[&str]) -> Result<ComputeOutput, ComputeSpecError> {
        let present = present_inputs(inputs)?;
        if present.len() == self.inputs {
            return Ok(self.run(&present));
        }
        let filters: Vec<&str> = self.filter_texts.iter().map(String::as_str).collect();
        let orders: Vec<&str> = self.order_texts.iter().map(String::as_str).collect();
        let spec = ComputeSpec::parse(
            &filters,
            &orders,
            &self.output_text,
            present.len(),
            self.calc,
        )?;
        Ok(spec.run(&present))
    }

    fn run(&self, present: &[&str]) -> ComputeOutput {
        match &self.output {
            Output::Calc(tree) => {
                // Only #1..#4 can be named.
                let values: Vec<Option<decimal::Dec>> = present
                    .iter()
                    .take(4)
                    .map(|text| calc::input_value(text))
                    .collect();
                calc::evaluate(tree, &values)
                    .and_then(|result| result.format_cents())
                    .map(|text| table::bounded([text]))
                    .unwrap_or_default()
            }
            Output::ModeAll(field) => table::mode(present.iter().flat_map(|text| {
                table::table(text)
                    .into_iter()
                    .filter(|(_, value)| matches!(value, Value::Object(_)))
                    .map(|(_, value)| value.get(field).and_then(table::value_text))
            })),
            _ => self.run_table(present),
        }
    }

    fn run_table(&self, present: &[&str]) -> ComputeOutput {
        let base = table::table(present.first().copied().unwrap_or(""));
        // Only the joined inputs that a ref names are ever read.
        let mut named = [false; 4];
        let refs = self
            .filters
            .iter()
            .map(|f| &f.reference)
            .chain(self.orders.iter().map(|o| &o.reference))
            .chain(output_ref(&self.output));
        for input in refs.filter_map(Ref::input) {
            if let Some(slot) = named.get_mut(input) {
                *slot = true;
            }
        }
        let joined: Vec<Option<Vec<(String, Value)>>> = (1..present.len().min(4))
            .map(|input| named[input].then(|| table::table(present[input])))
            .collect();
        let lookups: Vec<Option<table::Lookup>> = joined
            .iter()
            .map(|rows| rows.as_deref().map(table::Lookup::new))
            .collect();
        let mut rows: Vec<Row> = base
            .iter()
            .map(|(key, value)| {
                let mut folded = None;
                let mut columns = vec![Some(value)];
                columns.extend(lookups.iter().map(|lookup| {
                    lookup
                        .as_ref()
                        .and_then(|lookup| lookup.get(key, &mut folded))
                }));
                Row { key, columns }
            })
            .collect();
        rows.retain(|row| self.filters.iter().all(|filter| holds(row, filter)));
        rows.sort_by(|a, b| a.key.cmp(b.key));
        for order in self.orders.iter().rev() {
            rows = sorted(rows, order);
        }
        match &self.output {
            Output::Count => table::bounded([rows.len().to_string()]),
            Output::Sum(reference) => {
                let total = pyfloat::sum(rows.iter().filter_map(|row| row.number(reference)));
                table::bounded([pyfloat::format_number(total)])
            }
            _ if rows.is_empty() => ComputeOutput::default(),
            Output::Key => table::bounded([rows[0].key.to_string()]),
            Output::Keys(limit) => table::bounded(
                rows.iter()
                    .take(limit.unwrap_or(usize::MAX))
                    .map(|row| row.key.to_string()),
            ),
            Output::Value(reference) => {
                table::bounded([rows[0].text(reference).unwrap_or_default()])
            }
            Output::Values(reference) => table::bounded(
                rows.iter()
                    .filter_map(|row| row.text(reference))
                    .filter(|text| !text.is_empty()),
            ),
            Output::Mode(reference) => table::mode(rows.iter().map(|row| row.text(reference))),
            Output::Pairs(reference) => table::bounded(
                rows.iter()
                    .map(|row| format!("{}: {}", row.key, row.text(reference).unwrap_or_default())),
            ),
            Output::Calc(_) | Output::ModeAll(_) => ComputeOutput::default(),
        }
    }
}

fn output_ref(output: &Output) -> Option<&Ref> {
    match output {
        Output::Sum(r)
        | Output::Value(r)
        | Output::Values(r)
        | Output::Pairs(r)
        | Output::Mode(r) => Some(r),
        _ => None,
    }
}

/// One base row: its key and each input's value for it (input1's own
/// value, then each joined input's value for the same key, if any).
struct Row<'a> {
    key: &'a str,
    columns: Vec<Option<&'a Value>>,
}

/// What a ref resolves to in a row (`_resolve`).
enum Resolved<'a> {
    Key(&'a str),
    Value(Option<&'a Value>),
}

impl<'a> Row<'a> {
    fn resolve(&self, reference: &Ref) -> Resolved<'a> {
        match reference {
            Ref::Key => Resolved::Key(self.key),
            Ref::Input(input) => Resolved::Value(self.columns.get(*input).copied().flatten()),
            Ref::Field(input, field) => Resolved::Value(
                self.columns
                    .get(*input)
                    .copied()
                    .flatten()
                    .and_then(|column| column.get(field)),
            ),
        }
    }

    /// `_text(_resolve(...))`.
    fn text(&self, reference: &Ref) -> Option<String> {
        match self.resolve(reference) {
            Resolved::Key(key) => Some(key.to_string()),
            Resolved::Value(value) => value.and_then(table::value_text),
        }
    }

    /// `_number(_resolve(...))`.
    fn number(&self, reference: &Ref) -> Option<f64> {
        match self.resolve(reference) {
            Resolved::Key(key) => table::text_number(key),
            Resolved::Value(value) => value.and_then(table::value_number),
        }
    }
}

/// `_holds`: a missing value never passes.
fn holds(row: &Row, filter: &Filter) -> bool {
    let bound = filter.bound;
    match filter.op {
        Op::Eq | Op::Gt | Op::Ge | Op::Lt | Op::Le => match row.number(&filter.reference) {
            None => false,
            Some(number) => match filter.op {
                Op::Eq => number == bound,
                Op::Gt => number > bound,
                Op::Ge => number >= bound,
                Op::Lt => number < bound,
                _ => number <= bound,
            },
        },
        Op::Contains | Op::Lacks | Op::StartsWith | Op::Is | Op::Isnt => {
            match row.text(&filter.reference) {
                None => false,
                Some(text) => {
                    let text = table::fold(&text);
                    let needle = filter.needle.as_str();
                    match filter.op {
                        Op::Contains => text.contains(needle),
                        Op::Lacks => !text.contains(needle),
                        Op::StartsWith => text.starts_with(needle),
                        Op::Is => text == needle,
                        _ => text != needle,
                    }
                }
            }
        }
    }
}

/// One order: rows with a number first, sorted stably by it (descending
/// for "max"), then the rows without one in their order.
fn sorted<'a>(rows: Vec<Row<'a>>, order: &Order) -> Vec<Row<'a>> {
    let mut with: Vec<(f64, Row)> = Vec::new();
    let mut without: Vec<Row> = Vec::new();
    for row in rows {
        match row.number(&order.reference) {
            Some(number) => with.push((number, row)),
            None => without.push(row),
        }
    }
    // `_number` is never NaN (JSON refuses it and no text spells it), so
    // this is a total order; equal numbers (-0.0 and 0.0 among them) keep
    // their order, as Python's stable sort keeps them, `reverse` or not.
    with.sort_by(|a, b| {
        let ascending = a.0.partial_cmp(&b.0).unwrap_or(Ordering::Equal);
        if order.max {
            ascending.reverse()
        } else {
            ascending
        }
    });
    with.into_iter()
        .map(|(_, row)| row)
        .chain(without)
        .collect()
}

/// The inputs before the first empty one; an empty first input or a given
/// input after an empty one is an input error.
fn present_inputs<'a>(inputs: &[&'a str]) -> Result<Vec<&'a str>, ComputeSpecError> {
    let count = inputs
        .iter()
        .position(|text| text.is_empty())
        .unwrap_or(inputs.len());
    if count == 0 || inputs[count..].iter().any(|text| !text.is_empty()) {
        return Err(ComputeSpecError::Input);
    }
    Ok(inputs[..count].to_vec())
}

/// The step's whole function (the reference's `compute`): input texts
/// (input1 first; "" = absent) and spec texts (an empty filter or order is
/// absent) give the output, or the error the reference raises first.
/// `calc` admits a "calc" output.
pub fn compute(
    inputs: &[&str],
    filters: &[&str],
    orders: &[&str],
    output: &str,
    calc: bool,
) -> Result<ComputeOutput, ComputeSpecError> {
    let present = present_inputs(inputs)?;
    let spec = ComputeSpec::parse(filters, orders, output, present.len(), calc)?;
    Ok(spec.run(&present))
}

/// The owner's review of one step's spec texts for `inputs` given inputs
/// (the reference's `validate_spec`; an empty filter or order is absent, an
/// empty output is an error).
pub fn validate_spec(
    filters: &[&str],
    orders: &[&str],
    output: &str,
    inputs: usize,
    calc: bool,
) -> Result<(), ComputeSpecError> {
    ComputeSpec::parse(filters, orders, output, inputs, calc).map(drop)
}

/// The numbers a "calc" output writes itself, for the owner's review (the
/// reference's `calc_constants`): each distinct value once, in ascending
/// order, as plain decimal text without redundant zeros ("2.5", "100",
/// "0.05"). Any other valid output writes none.
pub fn calc_constants(output: &str, inputs: usize) -> Result<Vec<String>, ComputeSpecError> {
    let Output::Calc(tree) = spec::parse_output(output, inputs, true)? else {
        return Ok(Vec::new());
    };
    let mut found = Vec::new();
    calc::constants(&tree, &mut found);
    found.sort_by(|a, b| decimal::compare(a, b).unwrap_or(Ordering::Equal));
    found.dedup_by(|a, b| decimal::compare(a, b) == Some(Ordering::Equal));
    Ok(found.into_iter().map(decimal::Dec::plain).collect())
}
