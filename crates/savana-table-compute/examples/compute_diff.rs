//! Differential driver for `experiments/tests/test_compute_rust_parity.py`.
//!
//! Reads one JSON object per line from stdin and writes one JSON object per
//! line to stdout:
//!
//! ```text
//! {"inputs":[...],"filters":[...],"orders":[...],"output":"...","calc":bool}
//!     -> {"ok":"<canonical output JSON>"} | {"error":"compute_spec"|"compute_input"}
//! {"op":"validate","filters":[...],"orders":[...],"output":"...","count":N,"calc":bool}
//!     -> {"ok":""} | {"error":...}
//! {"op":"constants","output":"...","count":N}
//!     -> {"ok":["<decimal>",...]} | {"error":...}
//! ```
//!
//! A line that is not such an object gives `{"bad":"<reason>"}`.

use std::io::{BufRead, BufWriter, Write};

use serde_json::{json, Value};

fn strings(case: &Value, name: &str) -> Result<Vec<String>, String> {
    match case.get(name) {
        None => Ok(Vec::new()),
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| {
                item.as_str()
                    .map(str::to_string)
                    .ok_or_else(|| format!("{name}: not a string"))
            })
            .collect(),
        Some(_) => Err(format!("{name}: not a list")),
    }
}

fn answer(case: &Value) -> Result<Value, String> {
    let output = case
        .get("output")
        .and_then(Value::as_str)
        .ok_or("output: not a string")?;
    let calc = case.get("calc").and_then(Value::as_bool).unwrap_or(false);
    let filters = strings(case, "filters")?;
    let orders = strings(case, "orders")?;
    let filters: Vec<&str> = filters.iter().map(String::as_str).collect();
    let orders: Vec<&str> = orders.iter().map(String::as_str).collect();
    let count = || -> Result<usize, String> {
        let count = case
            .get("count")
            .and_then(Value::as_u64)
            .ok_or("count: not a number")?;
        usize::try_from(count).map_err(|_| "count: too large".to_string())
    };
    let op = case.get("op").and_then(Value::as_str).unwrap_or("compute");
    let result = match op {
        "compute" => {
            let inputs = strings(case, "inputs")?;
            let inputs: Vec<&str> = inputs.iter().map(String::as_str).collect();
            savana_table_compute::compute(&inputs, &filters, &orders, output, calc)
                .map(|computed| json!(computed.canonical_json()))
        }
        "validate" => {
            savana_table_compute::validate_spec(&filters, &orders, output, count()?, calc)
                .map(|()| json!(""))
        }
        "constants" => {
            savana_table_compute::calc_constants(output, count()?).map(|found| json!(found))
        }
        other => return Err(format!("op: unknown {other}")),
    };
    Ok(match result {
        Ok(value) => json!({ "ok": value }),
        Err(error) => json!({ "error": error.to_string() }),
    })
}

fn main() -> std::io::Result<()> {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut out = BufWriter::new(stdout.lock());
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let reply = match serde_json::from_str::<Value>(&line) {
            Ok(case) => answer(&case).unwrap_or_else(|reason| json!({ "bad": reason })),
            Err(error) => json!({ "bad": error.to_string() }),
        };
        writeln!(out, "{reply}")?;
    }
    out.flush()
}
