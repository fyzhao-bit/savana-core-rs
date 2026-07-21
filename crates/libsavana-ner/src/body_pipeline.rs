//! Byte-exact port of the **deterministic** data-plane leak gate in
//! `server/security/body_pipeline.py` (G2 redesign §6/§7).
//!
//! ## Scope contract — what crosses to Rust vs stays Python
//! `body_pipeline()` itself STAYS Python: it is orchestration over two INJECTED
//! callbacks — `masker` (default = NER `mask_content`, already ported in
//! `masking.rs`) and `compress` (a stella socket). Only the two pure,
//! model-free, deterministic functions cross here:
//!
//!   - [`leak_gate`] — the fail-closed residue detector (§7). This is the second,
//!     independent gate that runs after masking (and again after compression);
//!     a MISS is a data-plane bypass, so every ambiguity resolves to "unsafe".
//!   - [`should_compress`] — the length/units heuristic (`_should_compress`) that
//!     decides whether the injected compressor is even invoked. Pure and
//!     deterministic, but it only gates an injected call and its output is
//!     re-checked by [`leak_gate`], so it is a helper, not a security boundary.
//!
//! ## Regex: reuse the ONE pinned-Unicode source (no re-vendoring)
//! Both regexes need CPython-15.0.0-exact `\b`/`\s`/`\d`/`\w`, which the `regex`
//! crate does NOT provide (different Unicode version + `\w`/`\d`/`\s`
//! definitions). They are therefore compiled through the SAME
//! `l2_filter::build_fancy` machinery the L2 filter uses — `\b`→vendored word
//! boundary, `\s`→`WS_SET`, `\d`→`Nd`, `\w`→`PY_WORD_RANGES` — over fancy-regex.
//!
//!   - `_RESIDUAL_PII_RE` is a `re.VERBOSE` pattern; its de-sugared form (verbose
//!     whitespace + `#` comments stripped, char classes preserved) is vendored as
//!     [`RESIDUAL_PII`] and asserted byte-equivalent to the live pattern in the
//!     differential. No lookaround/backref, so fancy-regex is a strict superset.
//!   - The per-value vault regex `(?<![\w<])<re.escape(raw)>(?![\w>])` uses BOTH a
//!     negative lookbehind and lookahead → fancy-regex is required; `re.escape`
//!     is `l2_filter::py_re_escape`.
//!
//! Any fancy-regex runtime error FAILS CLOSED — counted as a leak (gate returns
//! `false`) — so the gate can only ever over-drop, never egress on error.

use crate::l2_filter::{build_fancy, py_re_escape};
use fancy_regex::Regex as Fancy;
use std::collections::BTreeSet;
use std::sync::OnceLock;

// Compression thresholds (`L2_COMPRESSION_POLICY` rule 1): skip on short text.
const MIN_OTOK: usize = 150; // approx output tokens
const MIN_UNITS: usize = 6; // approx clause/field units

/// De-verbosed `_RESIDUAL_PII_RE` (body_pipeline.py:27-39). Structured-PII
/// residue: email / phone / IBAN / SSN / EIN / long-digit / payment card.
/// Verbatim from the live `re.VERBOSE` pattern with insignificant whitespace and
/// `#` comments removed (char-class contents — incl. the literal space in
/// `[ \-]` — preserved); the differential re-asserts equivalence to the source.
const RESIDUAL_PII: &str = concat!(
    r"([A-Za-z0-9._%+\-]+@[A-Za-z0-9]",
    r"|\b(?:\+?\d[\s\-]?){10,}\b",
    r"|\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b",
    r"|\b\d{3}-\d{2}-\d{4}\b",
    r"|\b\d{2}-\d{7}\b",
    r"|\b\d{10,}\b",
    r"|\b(?:\d[ \-]?){13,19}\b)",
);

fn residual_pii_re() -> &'static Fancy {
    static R: OnceLock<Fancy> = OnceLock::new();
    R.get_or_init(|| build_fancy(RESIDUAL_PII, false))
}

/// `_should_compress`'s unit pattern (body_pipeline.py:62): clause/field markers.
fn unit_re() -> &'static Fancy {
    static R: OnceLock<Fancy> = OnceLock::new();
    R.get_or_init(|| build_fancy(r"[.,;\n]|\b[A-Z][A-Z_]+:", false))
}

/// Fail-closed residue check — byte-exact port of `leak_gate`
/// (body_pipeline.py:46-57). Returns `true` iff `body` is safe to egress:
/// no structured-PII pattern AND no raw vault value (char-len ≥ 4) surviving at
/// a non-word / non-`<>` boundary ("mask once → mask everywhere", §7).
///
/// `body == None` → `false` (Python `if body is None: return False`). Any doubt
/// (incl. a fancy-regex runtime error) → `false`.
///
/// `vault` is the on-host placeholder→real map as ordered `(key, value)` pairs;
/// only the values are inspected. Python filters them through a `set`
/// comprehension (`{v for v in vault.values() if v and len(v) >= 4}`) and returns
/// `False` on the first match — so the check is order-independent (any hit ⇒
/// unsafe), and we dedup the same way. `len(v)` is a code-point count.
pub fn leak_gate(body: Option<&str>, vault: &[(String, String)]) -> bool {
    let body = match body {
        None => return false,
        Some(b) => b,
    };
    // Structured-PII residue anywhere → unsafe. Fail closed on engine error.
    if residual_pii_re().is_match(body).unwrap_or(true) {
        return false;
    }
    // Surviving raw vault value (≥4 code points) at a word boundary → unsafe.
    // `BTreeSet` dedups exactly like Python's set-comprehension; iteration order
    // does not affect the boolean result.
    let mut values: BTreeSet<&str> = BTreeSet::new();
    for (_k, v) in vault {
        if v.chars().count() >= 4 {
            values.insert(v.as_str());
        }
    }
    for raw in values {
        let pat = format!(r"(?<![\w<]){}(?![\w>])", py_re_escape(raw));
        // `re.escape` output is a literal, so this always compiles; a runtime
        // match error still fails closed (counts as a leak).
        if build_fancy(&pat, false).is_match(body).unwrap_or(true) {
            return false;
        }
    }
    true
}

/// Byte-exact port of `_should_compress` (body_pipeline.py:60-63). Pure length /
/// unit heuristic gating the (injected) extractive compressor. `otok` is a
/// ~4-chars/token estimate over the code-point length; `units` counts
/// clause/field markers (non-overlapping, no capture groups → whole matches)
/// plus one. Not a security boundary — its output is re-gated by [`leak_gate`].
pub fn should_compress(masked: &str) -> bool {
    let otok = masked.chars().count() / 4;
    // `re.findall` count == number of non-overlapping matches. Filter to Ok
    // matches (a fancy-regex error, which cannot occur for this ASCII-anchored
    // pattern on real text, would otherwise be counted as an item).
    let units = unit_re().find_iter(masked).filter(|m| m.is_ok()).count() + 1;
    otok >= MIN_OTOK && units >= MIN_UNITS
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::fs;

    fn vault_pairs(v: &Value) -> Vec<(String, String)> {
        // preserve_order is on → object iteration is insertion order.
        v.as_object()
            .map(|o| {
                o.iter()
                    .map(|(k, val)| (k.clone(), val.as_str().unwrap().to_string()))
                    .collect()
            })
            .unwrap_or_default()
    }

    fn fixture(name: &str) -> Value {
        let path = format!(
            "{}/../../vectors/differential/{name}",
            env!("CARGO_MANIFEST_DIR")
        );
        let raw = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
        serde_json::from_str(&raw).unwrap()
    }

    // Live differential vs CPython `body_pipeline.leak_gate`
    // (`/tmp/civenv/bin/python`, PYTHONPATH=jarvis). Fixture generated by
    // `vectors/gen/gen_body_pipeline_vectors.py`.
    #[test]
    fn leak_gate_live_differential() {
        let rows = fixture("body_leak_gate.json");
        let mut fails = 0;
        let mut n = 0;
        for row in rows.as_array().unwrap() {
            n += 1;
            let body = match &row["body"] {
                Value::Null => None,
                Value::String(s) => Some(s.as_str()),
                other => panic!("bad body {other}"),
            };
            let vault = vault_pairs(&row["vault"]);
            let got = leak_gate(body, &vault);
            let want = row["expect"].as_bool().unwrap();
            if got != want {
                fails += 1;
                eprintln!(
                    "leak_gate FAIL body={:?} vault={} got={got} want={want}",
                    row["body"], row["vault"]
                );
            }
        }
        assert!(n > 0, "no leak_gate rows");
        assert_eq!(fails, 0, "{fails}/{n} leak_gate rows diverged");
    }

    // Live differential vs CPython `body_pipeline._should_compress`.
    #[test]
    fn should_compress_live_differential() {
        let rows = fixture("body_should_compress.json");
        let mut fails = 0;
        let mut n = 0;
        for row in rows.as_array().unwrap() {
            n += 1;
            let masked = row["masked"].as_str().unwrap();
            let got = should_compress(masked);
            let want = row["expect"].as_bool().unwrap();
            if got != want {
                fails += 1;
                eprintln!("should_compress FAIL masked={masked:?} got={got} want={want}");
            }
        }
        assert!(n > 0, "no should_compress rows");
        assert_eq!(fails, 0, "{fails}/{n} should_compress rows diverged");
    }

    // Spot anchors (independent of the fixture) documenting the contract.
    #[test]
    fn leak_gate_spot_anchors() {
        assert!(!leak_gate(None, &[]));
        assert!(leak_gate(Some("hello world"), &[]));
        assert!(!leak_gate(Some("reach bob@corp.com"), &[]));
        assert!(!leak_gate(Some("call +1 415 555 2671"), &[]));
        // vault value < 4 code points is not checked.
        assert!(leak_gate(Some("abc here"), &[("p".into(), "abc".into())]));
        // vault value >= 4 at a boundary → leak.
        assert!(!leak_gate(
            Some("。欧阳娜娜。"),
            &[("p".into(), "欧阳娜娜".into())]
        ));
        // adjacent CJK word char defeats the lookbehind (faithful to Python).
        assert!(leak_gate(
            Some("给欧阳娜娜打电话"),
            &[("p".into(), "欧阳娜娜".into())]
        ));
    }
}
