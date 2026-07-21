//! Host-side tokenization of extracted financial amounts — port of the pure
//! transforms in `server/documents/amount_tokens.py`.
//!
//! The vault-less Document MCP emits every amount as a canonical DECIMAL STRING
//! (`canonical::json_amount`); the trusted host then swaps each string for a
//! vault-scoped `AMOUNT` token BEFORE the evidence digest is (re)computed and
//! BEFORE anything egresses. The swap itself is a pure structural transform
//! over already-serialized rows — the authority lives entirely in
//! [`crate::scoped_vault::ScopedDocumentVault::put`] (dedup by `(kind, raw)`,
//! monotonic counter, HMAC tag), which is byte-exact vs Python on its own. This
//! module reproduces the field-selection and right-to-left splice policy.
//!
//! Rows (`facts` / `reconciliation` entries and `chunks`) are modeled as
//! [`serde_json::Value`] objects — the same canonical-dict shape
//! [`crate::canonical`] serializes — so amounts are JSON strings (post
//! `json_amount`) or `null`, and every non-amount field is passed through
//! untouched.

use serde_json::Value;

use crate::canonical::{json_amount, Amount};
use crate::facts::amount_number_spans;
use crate::scoped_vault::{ScopedDocumentVault, VaultError};

// The pre-tokenization wire form the vault-less Document MCP self-validates:
// a plain signed fixed-point decimal string (never a JSON number, never a
// token). `AMOUNT_DECIMAL_STR_MAX_LEN` bounds magnitude on the schema.
pub const AMOUNT_DECIMAL_STR_PATTERN: &str = r"^-?\d+(\.\d+)?$";
pub const AMOUNT_DECIMAL_STR_MAX_LEN: usize = 40;

// The tokenized form every cloud-bound / digest-covered amount takes.
pub const AMOUNT_KIND: &str = "AMOUNT";
pub const AMOUNT_TOKEN_PATTERN: &str =
    r"^\[\[JARVIS-DOC:[0-9a-f]{8,64}:\d{1,9}:AMOUNT:\d{1,9}:[0-9a-f]{16}\]\]$";

const AMOUNT_FACT_FIELD: &str = "value";
const AMOUNT_RECON_FIELDS: [&str; 3] = ["stated_amount", "computed_amount", "variance"];

/// Extract `row["pages"]` as `Vec<u32>` (defaults to empty when absent, exactly
/// `row.get("pages", ())`). The Rust vault does not accrete pages, so these are
/// threaded only for parity of the call shape.
fn row_pages(row: &Value) -> Vec<u32> {
    row.get("pages")
        .and_then(|p| p.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_u64().map(|n| n as u32))
                .collect()
        })
        .unwrap_or_default()
}

/// Replace one decimal-string amount with its vault `AMOUNT` token
/// (amount_tokens.py:40-51). `null` (a genuinely absent amount) stays `null`.
/// A non-null value MUST already be the canonical decimal string.
fn tokenize(
    vault: &mut ScopedDocumentVault,
    value: &Value,
    pages: &[u32],
) -> Result<Value, VaultError> {
    match value {
        Value::Null => Ok(Value::Null),
        Value::String(s) => Ok(Value::String(vault.put(AMOUNT_KIND, s, pages)?)),
        // Amounts arrive already stringified by `json_amount`; anything else is
        // a caller contract violation (kept explicit, never silently passed).
        _ => Err(VaultError {
            code: crate::scoped_vault::VAULT_TOKEN_INVALID,
        }),
    }
}

/// `tokenize_evidence_amounts` (amount_tokens.py:54-84). Returns copies of the
/// `facts` / `reconciliation` rows with amounts tokenized in exactly the amount
/// fields; every other field passes through unchanged.
pub fn tokenize_evidence_amounts(
    vault: &mut ScopedDocumentVault,
    facts: &[Value],
    reconciliation: &[Value],
) -> Result<(Vec<Value>, Vec<Value>), VaultError> {
    let mut tokenized_facts = Vec::with_capacity(facts.len());
    for fact in facts {
        let mut row = fact.clone();
        let pages = row_pages(&row);
        let current = row.get(AMOUNT_FACT_FIELD).cloned().unwrap_or(Value::Null);
        let swapped = tokenize(vault, &current, &pages)?;
        set_field(&mut row, AMOUNT_FACT_FIELD, swapped);
        tokenized_facts.push(row);
    }

    let mut tokenized_recon = Vec::with_capacity(reconciliation.len());
    for entry in reconciliation {
        let mut row = entry.clone();
        let pages = row_pages(&row);
        for field in AMOUNT_RECON_FIELDS {
            let current = row.get(field).cloned().unwrap_or(Value::Null);
            let swapped = tokenize(vault, &current, &pages)?;
            set_field(&mut row, field, swapped);
        }
        tokenized_recon.push(row);
    }
    Ok((tokenized_facts, tokenized_recon))
}

/// Set (or insert) `row[field] = value`, mirroring Python's `row[field] = ...`
/// on a `dict(fact)` copy. Requires the row to be a JSON object.
fn set_field(row: &mut Value, field: &str, value: Value) {
    if let Value::Object(map) = row {
        map.insert(field.to_string(), value);
    }
}

/// `mask_chunk_amounts` (amount_tokens.py:87-120). Returns copies of `chunks`
/// with every currency-associated amount NUMBER in the chunk text replaced by
/// its vault `AMOUNT` token — the SAME decimal string
/// `tokenize_evidence_amounts` uses, so an amount that is also a fact shares one
/// token (dedup by `(kind, raw)`). Replacement is right-to-left so earlier
/// offsets stay valid; the currency marker is left in place. Spans are CHARACTER
/// offsets (as Python `re`), so the splice is char-indexed.
pub fn mask_chunk_amounts(
    vault: &mut ScopedDocumentVault,
    chunks: &[Value],
) -> Result<Vec<Value>, VaultError> {
    let mut masked = Vec::with_capacity(chunks.len());
    for chunk in chunks {
        let mut row = chunk.clone();
        let text = row
            .get("text")
            .and_then(|t| t.as_str())
            .map(|s| s.to_string());
        if let Some(text) = text {
            let mut spans = amount_number_spans(&text);
            if !spans.is_empty() {
                let pages = row_pages(&row);
                // Sort by (start, end, value) then apply in reverse — matches
                // Python `sorted(spans, reverse=True)` (tuple order), so
                // earlier char offsets are spliced last.
                spans.sort_by(|a, b| {
                    a.0.cmp(&b.0)
                        .then(a.1.cmp(&b.1))
                        .then_with(|| a.2.cmp_num(&b.2))
                });
                let chars: Vec<char> = text.chars().collect();
                let mut out = chars;
                for (start, end, value) in spans.into_iter().rev() {
                    let token = vault.put(
                        AMOUNT_KIND,
                        &json_amount(&Amount::Dec(value))
                            .expect("finite amount")
                            .expect("non-null"),
                        &pages,
                    )?;
                    out.splice(start..end, token.chars());
                }
                let new_text: String = out.into_iter().collect();
                set_field(&mut row, "text", Value::String(new_text));
            }
        }
        masked.push(row);
    }
    Ok(masked)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};
    use std::fs;

    const SECRET: &[u8] = b"amount-tokens-differential-secret-key";
    const ARTIFACT: &str = "a1b2c3d4";
    const GENERATION: u32 = 1;
    const MASK_VERSION: &str = "doc-mask-v1";

    fn new_vault() -> ScopedDocumentVault {
        ScopedDocumentVault::new(SECRET, ARTIFACT, GENERATION, MASK_VERSION)
    }

    #[test]
    fn none_stays_none_and_string_tokenizes() {
        let mut v = new_vault();
        assert_eq!(tokenize(&mut v, &Value::Null, &[]).unwrap(), Value::Null);
        let tok = tokenize(&mut v, &Value::String("12.50".into()), &[1]).unwrap();
        let s = tok.as_str().unwrap();
        assert!(s.starts_with("[[JARVIS-DOC:a1b2c3d4:1:AMOUNT:1:"));
    }

    #[test]
    fn dedup_shares_one_token() {
        let mut v = new_vault();
        let a = tokenize(&mut v, &Value::String("100.00".into()), &[1]).unwrap();
        let b = tokenize(&mut v, &Value::String("100.00".into()), &[2]).unwrap();
        assert_eq!(a, b, "equal amounts share one token (dedup by (kind,raw))");
    }

    #[test]
    fn evidence_transform_passes_through_non_amount_fields() {
        let mut v = new_vault();
        let facts = vec![json!({
            "fact_id": "f1", "kind": "amount", "value": "12.50",
            "currency": "USD", "date": Value::Null, "pages": [1]
        })];
        let recon = vec![json!({
            "metric": "documented_total", "stated_amount": "1000",
            "computed_amount": "1000", "variance": Value::Null,
            "currency": "USD", "pages": [1]
        })];
        let (tf, tr) = tokenize_evidence_amounts(&mut v, &facts, &recon).unwrap();
        assert_eq!(tf[0]["fact_id"], "f1");
        assert_eq!(tf[0]["currency"], "USD");
        assert!(tf[0]["value"].as_str().unwrap().contains(":AMOUNT:"));
        assert_eq!(tr[0]["variance"], Value::Null);
        assert!(tr[0]["stated_amount"]
            .as_str()
            .unwrap()
            .contains(":AMOUNT:"));
    }

    // Live differential: Python built the same vault (byte-exact port) and
    // recorded the tokenized rows / masked chunk text; Rust must reproduce them.
    #[test]
    fn amount_tokens_live_differential() {
        let path = format!(
            "{}/../../vectors/differential/amount_tokens.json",
            env!("CARGO_MANIFEST_DIR")
        );
        let raw = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
        let fixture: Value = serde_json::from_str(&raw).unwrap();

        // Config must match the generator so tokens line up.
        let secret = fixture["secret"].as_str().unwrap().as_bytes();
        let artifact = fixture["artifact_id"].as_str().unwrap();
        let generation = fixture["generation"].as_u64().unwrap() as u32;
        let mask_version = fixture["mask_version"].as_str().unwrap();

        // evidence tokenization
        {
            let mut v = ScopedDocumentVault::new(secret, artifact, generation, mask_version);
            let facts: Vec<Value> = fixture["facts"].as_array().unwrap().clone();
            let recon: Vec<Value> = fixture["reconciliation"].as_array().unwrap().clone();
            let (tf, tr) = tokenize_evidence_amounts(&mut v, &facts, &recon).unwrap();
            assert_eq!(
                Value::Array(tf),
                fixture["expect_facts"],
                "facts tokenization diverged"
            );
            assert_eq!(
                Value::Array(tr),
                fixture["expect_reconciliation"],
                "recon tokenization diverged"
            );
        }
        // chunk masking (fresh vault, mirrors generator ordering)
        {
            let mut v = ScopedDocumentVault::new(secret, artifact, generation, mask_version);
            let chunks: Vec<Value> = fixture["chunks"].as_array().unwrap().clone();
            let masked = mask_chunk_amounts(&mut v, &chunks).unwrap();
            assert_eq!(
                Value::Array(masked),
                fixture["expect_chunks"],
                "chunk masking diverged"
            );
        }
    }
}
