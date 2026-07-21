//! Byte-exact port of the **deterministic** core of CaMeL's PEP/enforcement loop
//! in `server/runtime/camel_interpreter.py`.
//!
//! ## Honest scope: the portable core is THIN, but genuinely new
//! Almost all of `camel_interpreter.py` STAYS Python — the `run_plan` loop is
//! orchestration over injected/model/side-effecting collaborators that have no
//! deterministic content to port: `execute_tool` (MCP dispatch), `qllm`
//! (quarantined model), `consent_cb` (human consent), `unified_sink_check` (the
//! PDP — already ported in `sink_policy.rs`/`pdp_tool.rs`), audit/flywheel
//! logging, and the `on_milestone`/`on_blocked`/summary side effects.
//!
//! The taint ALGEBRA (`Capability`, `combine_caps`, `is_trusted`/`is_public`) is
//! already ported in `capabilities.rs` and is REUSED here, not duplicated. What
//! `camel_interpreter` adds on top — and what this module ports — is the pure
//! **arg → value resolution + on-host rehydration decision** that
//! `capabilities.rs` deliberately left out (it declined to pick a concrete
//! `CaMeLValue.raw` payload type; this interpreter slice makes that decision:
//! `serde_json::Value`). Concretely:
//!
//!   - [`resolve_one`] / [`resolve_args`] (`_resolve_one`/`_resolve_args`) — turn
//!     a plan arg into a capability-tagged value, propagating taint via `$from`
//!     refs (env/field lookup) and rehydrating vault/page-vault placeholders
//!     on-host at execution time. This is the genuinely-new deterministic core.
//!   - [`rehydrate`] (`slm_gate.rehydrate`) — the ordered placeholder→real
//!     substitution the resolve step depends on (not previously ported;
//!     `redact_pii` already lives in `l2_filter`).
//!   - [`constant`] / [`rehydrated_value`] — the two `CaMeLValue` constructors
//!     the resolve step emits (the rest of the constructor family stays Python).
//!   - [`safe_policy_detail`] (`_safe_policy_detail`) — a deterministic trace
//!     formatter (NOT a security decision); ported for completeness.
//!
//! Everything here is model-free and byte-exact vs live CPython (see the inline
//! live differential, fixture `vectors/differential/camel_resolve.json`).

use crate::capabilities::{Capability, Source};
use regex::Regex;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

/// Minimal `CaMeLValue` — `raw` payload + its [`Capability`]. The Python class
/// also carries a `deps` dependency tree, which the resolve core never reads
/// (`constant`/`rehydrated_value` set `deps=()`, and env/field hits are returned
/// unchanged), so it is intentionally omitted from this slice. `raw` is
/// `serde_json::Value` — the interpreter-level payload choice `capabilities.rs`
/// deferred. No `Eq` (a `Value` may hold a float); `PartialEq` suffices.
#[derive(Debug, Clone, PartialEq)]
pub struct CaMeLValue {
    pub raw: Value,
    pub cap: Capability,
}

/// `constant(raw)` (capabilities.py:87-89): a literal from the trusted P-LLM
/// plan — trusted (`{CONSTANT}`), public (`readers = None`).
pub fn constant(raw: Value) -> CaMeLValue {
    let mut sources = BTreeSet::new();
    sources.insert(Source::Constant);
    CaMeLValue {
        raw,
        cap: Capability::new(sources, None),
    }
}

/// `rehydrated_value(raw)` (capabilities.py:96-111): a vaulted secret restored
/// on-host — trusted for control flow (`{USER}`) but PRIVATE (`readers =
/// {"user"}`), so the data-flow policy forces consent before it egresses.
pub fn rehydrated_value(raw: Value) -> CaMeLValue {
    let mut sources = BTreeSet::new();
    sources.insert(Source::User);
    let mut readers = BTreeSet::new();
    readers.insert("user".to_string());
    CaMeLValue {
        raw,
        cap: Capability::new(sources, Some(readers)),
    }
}

/// A reference the resolver could not satisfy — mirrors the frozen
/// `UnresolvedRef` dataclass (camel_interpreter.py:66-69).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnresolvedRef {
    pub path: String,
    pub reason: String,
}

/// Result of resolving one plan arg: either a capability-tagged value or an
/// unresolved reference (Python returns `CaMeLValue | UnresolvedRef`).
#[derive(Debug, Clone, PartialEq)]
pub enum Resolved {
    Value(CaMeLValue),
    Unresolved(UnresolvedRef),
}

/// `_REF_PATH_RE` (camel_interpreter.py:35-38) applied with `.fullmatch`. Pure
/// ASCII, no lookaround/`\b`/`\s`/`\d`, so the linear `regex` crate expresses it
/// exactly; `\A…\z` gives `re.fullmatch` semantics (whole string, no trailing
/// `\n` exception — unlike `$`). One identifier is 1 + up to 63 = ≤64 chars,
/// with at most one dotted segment.
fn ref_path_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r"\A(?:[A-Za-z_][A-Za-z0-9_]{0,63}(?:\.[A-Za-z_][A-Za-z0-9_]{0,63})?)\z")
            .expect("ref path regex compiles")
    })
}

/// `slm_gate.rehydrate` (slm_gate.py:129-138): substitute any `<TYPE_n>`
/// placeholder in `text` back to its real value, iterating `vault` in order and
/// mutating sequentially (so a real value that itself contains a later
/// placeholder is expanded on the later iteration — order is load-bearing and
/// preserved). Short-circuits when the vault is empty or `text` has no `<`.
pub fn rehydrate(text: &str, vault: &[(String, String)]) -> String {
    if vault.is_empty() || !text.contains('<') {
        return text.to_string();
    }
    let mut text = text.to_string();
    for (placeholder, real) in vault {
        if text.contains(placeholder.as_str()) {
            text = text.replace(placeholder.as_str(), real);
        }
    }
    text
}

/// Python dict merge `{**page, **vault}`: `page`'s entries in order, then
/// `vault`'s; a key in both keeps `page`'s POSITION but takes `vault`'s VALUE.
/// (L2 vault wins on a key clash, per the resolve docstring.)
fn merge_vaults(page: &[(String, String)], vault: &[(String, String)]) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = page.to_vec();
    for (k, v) in vault {
        if let Some(e) = out.iter_mut().find(|(kk, _)| kk == k) {
            e.1 = v.clone();
        } else {
            out.push((k.clone(), v.clone()));
        }
    }
    out
}

/// `_resolve_one` (camel_interpreter.py:79-115): turn a plan arg into a
/// capability-tagged value, propagating taint via `$from` refs.
///
/// - `{"$from": ref}` (a dict carrying `$from`): validate `ref` is a string
///   matching `_REF_PATH_RE`; a dotted `sid.fname` resolves against `fields`, a
///   bare `sid` against `env`. Misses become an [`UnresolvedRef`] with the exact
///   Python reason string.
/// - Otherwise a literal from the trusted plan: if the merged page+L2 vault is
///   non-empty and the literal is a `str` containing `<`, rehydrate on-host; a
///   changed value becomes [`rehydrated_value`] (trusted-but-private), else
///   [`constant`] (trusted+public).
pub fn resolve_one(
    v: &Value,
    env: &BTreeMap<String, CaMeLValue>,
    fields: &BTreeMap<String, BTreeMap<String, CaMeLValue>>,
    vault: &[(String, String)],
    page_vault: Option<&[(String, String)]>,
) -> Resolved {
    if let Some(obj) = v.as_object() {
        if let Some(raw_ref) = obj.get("$from") {
            // `isinstance(raw_ref, str) and _REF_PATH_RE.fullmatch(raw_ref)`.
            let ref_str = match raw_ref.as_str() {
                Some(s) if ref_path_re().is_match(s) => s,
                _ => {
                    return Resolved::Unresolved(UnresolvedRef {
                        path: String::new(),
                        reason: "invalid_reference".to_string(),
                    })
                }
            };
            if ref_str.contains('.') {
                // `ref.split(".", 1)` — the regex guarantees exactly one dot, so
                // `split_once` yields the same `(sid, fname)` split.
                let (sid, fname) = ref_str.split_once('.').unwrap();
                return match fields.get(sid).and_then(|m| m.get(fname)) {
                    Some(fv) => Resolved::Value(fv.clone()),
                    None => Resolved::Unresolved(UnresolvedRef {
                        path: ref_str.to_string(),
                        reason: "field is unavailable".to_string(),
                    }),
                };
            }
            return match env.get(ref_str) {
                Some(val) => Resolved::Value(val.clone()),
                None => Resolved::Unresolved(UnresolvedRef {
                    path: ref_str.to_string(),
                    reason: "step is unavailable".to_string(),
                }),
            };
        }
    }
    // Literal from the trusted plan: rehydrate a vault placeholder on-host.
    let combined = merge_vaults(page_vault.unwrap_or(&[]), vault);
    if !combined.is_empty() {
        if let Some(s) = v.as_str() {
            if s.contains('<') {
                let hydrated = rehydrate(s, &combined);
                if hydrated != s {
                    return Resolved::Value(rehydrated_value(Value::String(hydrated)));
                }
            }
        }
    }
    Resolved::Value(constant(v.clone()))
}

/// `_resolve_args` (camel_interpreter.py:118-133): resolve every arg, collecting
/// successes into an insertion-ordered `(key, value)` list (Python dict) and
/// misses into an ordered `unresolved` list (Python returns it as a tuple).
pub fn resolve_args(
    args: &serde_json::Map<String, Value>,
    env: &BTreeMap<String, CaMeLValue>,
    fields: &BTreeMap<String, BTreeMap<String, CaMeLValue>>,
    vault: &[(String, String)],
    page_vault: Option<&[(String, String)]>,
) -> (Vec<(String, CaMeLValue)>, Vec<UnresolvedRef>) {
    let mut resolved: Vec<(String, CaMeLValue)> = Vec::new();
    let mut unresolved: Vec<UnresolvedRef> = Vec::new();
    for (key, value) in args {
        match resolve_one(value, env, fields, vault, page_vault) {
            Resolved::Value(cv) => resolved.push((key.clone(), cv)),
            Resolved::Unresolved(u) => unresolved.push(u),
        }
    }
    (resolved, unresolved)
}

/// `_safe_policy_detail` (camel_interpreter.py:72-76): format a verdict into the
/// trace `detail` string. Deterministic FORMATTER, not a security decision —
/// ported for completeness. Argument mapping mirrors the Python getattr/`or`
/// fallbacks exactly:
///   - `source_layer`: Python `verdict.source_layer or "unknown"` — `None` OR an
///     empty string is falsy → `"unknown"`.
///   - `reason` / `verdict`: Python `getattr(x, "value", "unknown")` — a missing
///     attribute (modeled as `None`) → `"unknown"`; a present value (even the
///     empty string) is used verbatim.
pub fn safe_policy_detail(
    source_layer: Option<&str>,
    reason_value: Option<&str>,
    verdict_value: Option<&str>,
) -> String {
    let source = match source_layer {
        Some(s) if !s.is_empty() => s,
        _ => "unknown",
    };
    let reason = reason_value.unwrap_or("unknown");
    let status = verdict_value.unwrap_or("unknown");
    format!("source={source}; reason={reason}; verdict={status}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::fs;

    // ── fixture reconstruction helpers ──
    fn parse_pairs(v: &Value) -> Vec<(String, String)> {
        v.as_object()
            .map(|o| {
                o.iter()
                    .map(|(k, val)| (k.clone(), val.as_str().unwrap().to_string()))
                    .collect()
            })
            .unwrap_or_default()
    }

    fn parse_cap(spec: &Value) -> Capability {
        let sources: BTreeSet<Source> = spec["sources"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| Source::from_wire(s.as_str().unwrap()).unwrap())
            .collect();
        let readers = match &spec["readers"] {
            Value::Null => None,
            Value::Array(a) => Some(
                a.iter()
                    .map(|s| s.as_str().unwrap().to_string())
                    .collect::<BTreeSet<String>>(),
            ),
            other => panic!("bad readers {other}"),
        };
        Capability::new(sources, readers)
    }

    fn parse_val(spec: &Value) -> CaMeLValue {
        CaMeLValue {
            raw: spec["raw"].clone(),
            cap: parse_cap(spec),
        }
    }

    fn parse_env(v: &Value) -> BTreeMap<String, CaMeLValue> {
        v.as_object()
            .map(|o| o.iter().map(|(k, s)| (k.clone(), parse_val(s))).collect())
            .unwrap_or_default()
    }

    fn parse_fields(v: &Value) -> BTreeMap<String, BTreeMap<String, CaMeLValue>> {
        v.as_object()
            .map(|o| {
                o.iter()
                    .map(|(k, inner)| {
                        let m = inner
                            .as_object()
                            .unwrap()
                            .iter()
                            .map(|(fk, s)| (fk.clone(), parse_val(s)))
                            .collect();
                        (k.clone(), m)
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    // ── canonical serialization matching the Python generator ──
    fn ser_cap(cap: &Capability) -> (Value, Value) {
        let mut sources: Vec<&str> = cap.sources.iter().map(|s| s.as_str()).collect();
        sources.sort_unstable();
        let readers = match &cap.readers {
            None => Value::Null,
            Some(set) => {
                let mut v: Vec<&str> = set.iter().map(|s| s.as_str()).collect();
                v.sort_unstable();
                json!(v)
            }
        };
        (json!(sources), readers)
    }

    fn ser_val(cv: &CaMeLValue) -> Value {
        let (sources, readers) = ser_cap(&cv.cap);
        json!({"kind": "value", "raw": cv.raw, "sources": sources, "readers": readers})
    }

    fn ser_res(r: &Resolved) -> Value {
        match r {
            Resolved::Value(cv) => ser_val(cv),
            Resolved::Unresolved(u) => {
                json!({"kind": "unresolved", "path": u.path, "reason": u.reason})
            }
        }
    }

    fn fixture() -> Value {
        let path = format!(
            "{}/../../vectors/differential/camel_resolve.json",
            env!("CARGO_MANIFEST_DIR")
        );
        let raw = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
        serde_json::from_str(&raw).unwrap()
    }

    fn page_vault_opt(row: &Value) -> Option<Vec<(String, String)>> {
        match &row["page_vault"] {
            Value::Null => None,
            other => Some(parse_pairs(other)),
        }
    }

    // Live differential vs CPython `_resolve_one` (`/tmp/civenv/bin/python`,
    // PYTHONPATH=jarvis). Fixture: `vectors/gen/gen_camel_vectors.py`.
    #[test]
    fn resolve_one_live_differential() {
        let fx = fixture();
        let rows = fx["resolve_one"].as_array().unwrap();
        let mut fails = 0;
        for row in rows {
            let env = parse_env(&row["env"]);
            let fields = parse_fields(&row["fields"]);
            let vault = parse_pairs(&row["vault"]);
            let pv = page_vault_opt(row);
            let got = resolve_one(&row["v"], &env, &fields, &vault, pv.as_deref());
            let got_j = ser_res(&got);
            if got_j != row["expect"] {
                fails += 1;
                eprintln!(
                    "resolve_one FAIL name={} v={}\n got={got_j}\nwant={}",
                    row["name"], row["v"], row["expect"]
                );
            }
        }
        assert!(!rows.is_empty(), "no resolve_one rows");
        assert_eq!(fails, 0, "{fails}/{} resolve_one rows diverged", rows.len());
    }

    #[test]
    fn resolve_args_live_differential() {
        let fx = fixture();
        let rows = fx["resolve_args"].as_array().unwrap();
        let mut fails = 0;
        for row in rows {
            let env = parse_env(&row["env"]);
            let fields = parse_fields(&row["fields"]);
            let vault = parse_pairs(&row["vault"]);
            let pv = page_vault_opt(row);
            let args = row["args"].as_object().cloned().unwrap_or_default();
            let (resolved, unresolved) = resolve_args(&args, &env, &fields, &vault, pv.as_deref());
            let got = json!({
                "resolved": resolved.iter()
                    .map(|(k, cv)| (k.clone(), ser_val(cv)))
                    .collect::<serde_json::Map<String, Value>>(),
                "unresolved": unresolved.iter()
                    .map(|u| json!({"path": u.path, "reason": u.reason}))
                    .collect::<Vec<Value>>(),
            });
            if got != row["expect"] {
                fails += 1;
                eprintln!(
                    "resolve_args FAIL name={}\n got={got}\nwant={}",
                    row["name"], row["expect"]
                );
            }
        }
        assert!(!rows.is_empty(), "no resolve_args rows");
        assert_eq!(
            fails,
            0,
            "{fails}/{} resolve_args rows diverged",
            rows.len()
        );
    }

    #[test]
    fn safe_policy_detail_live_differential() {
        let fx = fixture();
        let rows = fx["safe_policy_detail"].as_array().unwrap();
        let opt = |v: &Value| -> Option<String> {
            match v {
                Value::Null => None,
                Value::String(s) => Some(s.clone()),
                other => panic!("bad {other}"),
            }
        };
        let mut fails = 0;
        for row in rows {
            let s = opt(&row["source"]);
            let r = opt(&row["reason"]);
            let v = opt(&row["verdict"]);
            let got = safe_policy_detail(s.as_deref(), r.as_deref(), v.as_deref());
            let want = row["expect"].as_str().unwrap();
            if got != want {
                fails += 1;
                eprintln!("safe_policy_detail FAIL got={got:?} want={want:?}");
            }
        }
        assert!(!rows.is_empty(), "no safe_policy_detail rows");
        assert_eq!(fails, 0, "{fails} safe_policy_detail rows diverged");
    }

    // Independent contract anchors.
    #[test]
    fn resolve_one_spot_anchors() {
        let env = BTreeMap::new();
        let fields = BTreeMap::new();
        // literal int → constant (trusted+public).
        let r = resolve_one(&json!(42), &env, &fields, &[], None);
        assert_eq!(r, Resolved::Value(constant(json!(42))));
        // placeholder + vault → rehydrated_value (trusted+private).
        let vault = vec![("<E_1>".to_string(), "bob@corp.com".to_string())];
        let r = resolve_one(&json!("mail <E_1>"), &env, &fields, &vault, None);
        assert_eq!(
            r,
            Resolved::Value(rehydrated_value(json!("mail bob@corp.com")))
        );
        // invalid ref.
        let r = resolve_one(&json!({"$from": "1bad"}), &env, &fields, &[], None);
        assert_eq!(
            r,
            Resolved::Unresolved(UnresolvedRef {
                path: String::new(),
                reason: "invalid_reference".to_string()
            })
        );
    }

    #[test]
    fn rehydrate_is_order_sensitive() {
        // <A_1> expands to a string that itself contains <B_1>, expanded next.
        let vault = vec![
            ("<A_1>".to_string(), "<B_1>".to_string()),
            ("<B_1>".to_string(), "real".to_string()),
        ];
        assert_eq!(rehydrate("<A_1>", &vault), "real");
    }
}
