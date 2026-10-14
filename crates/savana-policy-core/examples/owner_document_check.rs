//! Checks owner documents the way the kernel admits a fused plan's inputs
//! (`FusedInputDocumentV04::check_owner_text_origin`), for the experiment
//! harness's cross-check (`experiments/tests/test_owner_document_parity.py`).
//!
//! Reads JSON lines `{"document": <owner document text>, "uses": [{"slot":
//! [16 bytes], "operation": <name>, "name": <field>, "role": <catalog role>,
//! "type": "text"|"text_list", "fixed": <text, optional>}]}` and writes one
//! line per case: `ok`, or the refusal.
use std::io::{BufRead, Write};

use savana_kernel_protocol::v2::{
    BusinessFieldRoleV2 as Role, BusinessFieldTypeV2 as Kind, BusinessFieldV2,
};
use savana_policy_core::v2::{FusedInputDocumentV04, OwnerInputUseV04};
use serde_json::Value;

fn role(name: &str) -> Role {
    match name {
        "payload" => Role::Payload,
        "resource" => Role::Resource,
        "destination" => Role::Destination,
        "parameter" => Role::Parameter,
        "condition" => Role::Condition,
        "copy_destination" => Role::CopyDestination,
        other => panic!("unknown role {other}"),
    }
}

fn check(case: &Value) -> Result<(), String> {
    let document = FusedInputDocumentV04::parse(case["document"].as_str().ok_or("document")?)
        .map_err(|error| format!("parse: {error:?}"))?;
    let mut fields = Vec::new();
    for item in case["uses"].as_array().ok_or("uses")? {
        let kind = match item["type"].as_str() {
            Some("text") => Kind::Text,
            Some("text_list") => Kind::TextList,
            _ => return Err("type".into()),
        };
        let mut field = BusinessFieldV2::new(
            item["name"].as_str().ok_or("name")?,
            role(item["role"].as_str().ok_or("role")?),
            kind,
        )
        .map_err(|error| format!("field: {error:?}"))?;
        if let Some(fixed) = item.get("fixed").and_then(Value::as_str) {
            field = field
                .with_fixed(fixed)
                .map_err(|error| format!("fixed: {error:?}"))?;
        }
        let slot: Vec<u8> = item["slot"]
            .as_array()
            .ok_or("slot")?
            .iter()
            .map(|b| {
                b.as_u64()
                    .and_then(|b| u8::try_from(b).ok())
                    .ok_or("slot byte")
            })
            .collect::<Result<_, _>>()?;
        let slot: [u8; 16] = slot.try_into().map_err(|_| "slot length")?;
        fields.push((
            slot,
            item["operation"].as_str().ok_or("operation")?.to_owned(),
            field,
        ));
    }
    let uses: Vec<OwnerInputUseV04<'_>> = fields
        .iter()
        .map(|(slot, operation, field)| OwnerInputUseV04 {
            slot: *slot,
            operation,
            field,
        })
        .collect();
    document
        .check_owner_text_origin(&uses)
        .map_err(|error| format!("refused: {error:?}"))
}

fn main() {
    let stdin = std::io::stdin();
    let mut out = std::io::stdout().lock();
    for line in stdin.lock().lines() {
        let line = line.expect("stdin");
        let verdict = match serde_json::from_str::<Value>(&line) {
            Ok(case) => check(&case).err().unwrap_or_else(|| "ok".into()),
            Err(_) => "bad json".into(),
        };
        writeln!(out, "{verdict}").expect("stdout");
    }
}
