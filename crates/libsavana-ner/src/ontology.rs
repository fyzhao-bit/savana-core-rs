//! On-device ontology + constraint engine — Rust port of the PURE
//! constraint-evaluation core of `server/security/ontology.py`:
//! `_eval_one` (ontology.py:62-84), `evaluate_constraints`
//! (ontology.py:87-98), and the read path of `OntologyStore.resolve`
//! (ontology.py:44-59).
//!
//! Deliberately NOT ported: the `OntologyStore` class itself — a mutable
//! `dict`-of-dicts assembled via repeated `.set()` calls. That's data
//! assembly, not decision logic (the same rationale `dataflow_policy.rs`/
//! `attempt_classifier.rs` use for `rules.yaml`): callers resolve the
//! store's contents to a plain nested map ([`Store`]) and pass it in.
//!
//! A key simplification this port leans on: `evaluate_constraints`'s two
//! failure-reason templates (ontology.py:94 and :97) only ever embed the
//! ORIGINAL constraint string — never the inner exception text (that text
//! only reaches a `logger.warning` call, never the returned `reason`). So
//! this port models constraint evaluation as a tri-state
//! `Result<bool, ()>` (pass / clean-fail / fail-closed-error) rather than
//! threading Python's exact exception messages through — the observable
//! `(ok, reason)` contract doesn't depend on them.

use std::collections::BTreeMap;

/// A resolved ontology field value: either a scalar string (e.g.
/// `status: "active"`) or a collection of strings (e.g.
/// `contacts: {"a@x.com", "b@x.com"}`) — the two shapes real callers store
/// (see `evals/full_e2e_report.py` and `tests/test_g2_redesign.py`:
/// `s.set("matter", "M-123", contacts={...}, status="active")`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Str(String),
    Collection(Vec<String>),
}

impl Value {
    /// Mirrors Python's `str(x)` for the two shapes above (used by the
    /// `==`/`!=` comparison branch of `_eval_one`): a scalar is unquoted;
    /// a collection formats like `list.__repr__` (`str(list)` delegates to
    /// `repr`) — `['a', 'b']`.
    ///
    /// NOTE: real ontology collections are Python `set`s, and `str(set)`
    /// iteration order is hash-randomized per process — i.e. already
    /// nondeterministic in the Python original if a `set`-valued field were
    /// ever compared with `==`/`!=` (no real caller does this: sets are
    /// only ever used for `in`/`not in` in this codebase). This port's
    /// `Collection` therefore renders in a fixed (insertion) order, which is
    /// A valid Python `str(some_list)` but intentionally not an attempt to
    /// replicate `str(some_set)`'s hash-dependent order.
    fn py_str(&self) -> String {
        match self {
            Value::Str(s) => s.clone(),
            Value::Collection(items) => py_list_repr(items),
        }
    }
}

/// `repr()` of a Python `str` — see `dataflow_policy.rs`'s copy of this
/// helper for the exact rules; duplicated here (rather than shared) so each
/// ported module file stays self-contained.
fn py_str_repr(s: &str) -> String {
    let quote = if s.contains('\'') && !s.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::with_capacity(s.len() + 2);
    out.push(quote);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 || (c as u32) == 0x7f => {
                out.push_str(&format!("\\x{:02x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}

fn py_list_repr(items: &[String]) -> String {
    let parts: Vec<String> = items.iter().map(|s| py_str_repr(s)).collect();
    format!("[{}]", parts.join(", "))
}

/// `_KEY_BY_NS` (ontology.py:25-30) — a code constant (no YAML override),
/// so it's baked in rather than injected.
fn key_arg_for_ns(ns: &str) -> Option<&'static str> {
    match ns {
        "matter" => Some("matter_id"),
        "advisor" => Some("advisor_id"),
        "patient" => Some("patient_id"),
        "account" => Some("account_id"),
        _ => None,
    }
}

/// The store's resolved contents: `namespace -> entity_key -> field -> value`.
pub type Store = BTreeMap<String, BTreeMap<String, BTreeMap<String, Value>>>;

/// `OntologyStore.resolve`'s read path (ontology.py:44-59). `args` is the
/// tool call's (already rehydrated) argument map. `Err(())` on ANY missing
/// piece — not-a-path, unknown namespace, missing/empty key arg, unknown
/// entity, or unrecorded field — all fail closed identically (see module
/// docs on why the exact exception text isn't threaded through).
fn resolve<'a>(
    path: &str,
    args: &BTreeMap<String, String>,
    store: &'a Store,
) -> Result<&'a Value, ()> {
    let (ns, field) = path.split_once('.').ok_or(())?; // "not an ontology path"
    if field.is_empty() {
        return Err(());
    }
    let key_arg = key_arg_for_ns(ns).ok_or(())?; // "unknown ontology namespace"
                                                 // `if not key:` — Python falsiness, so an empty-string arg counts as absent.
    let key = args.get(key_arg).filter(|k| !k.is_empty()).ok_or(())?;
    let entity = store.get(ns).and_then(|by_key| by_key.get(key)).ok_or(())?; // entity absent
    entity.get(field).ok_or(()) // field not recorded
}

/// `_eval_one` (ontology.py:62-84). `constraint` is stripped internally for
/// PARSING only — callers needing the original string for messages (as
/// `evaluate_constraints` does) must keep their own copy; see module docs.
fn eval_one(constraint: &str, args: &BTreeMap<String, String>, store: &Store) -> Result<bool, ()> {
    let c = constraint.trim();

    // Membership: "<arg> [not] in <ns.collection>".
    if c.contains(" in ") {
        let neg = c.contains(" not in ");
        let sep = if neg { " not in " } else { " in " };
        let (lhs, rhs) = c.split_once(sep).ok_or(())?;
        let lhs = lhs.trim();
        let rhs = rhs.trim();

        // `value = args.get(lhs); if value is None: raise` — presence-only
        // check (unlike `resolve`'s key lookup, an empty string is fine here).
        let value = args.get(lhs).ok_or(())?;

        let collection = resolve(rhs, args, store)?;
        let items = match collection {
            Value::Collection(items) => items,
            Value::Str(_) => return Err(()), // "{rhs} is not a collection"
        };
        let member = items.iter().any(|it| it == value);
        return Ok(if neg { !member } else { member });
    }

    // Comparison: "<ns.field> == literal" / "!= literal". "==" checked first,
    // matching Python's `for op in ("==", "!="):` iteration order.
    for op in ["==", "!="] {
        if let Some((lhs, rhs)) = c.split_once(op) {
            let actual = resolve(lhs.trim(), args, store)?;
            let literal = rhs.trim().trim_matches(|ch| ch == '\'' || ch == '"');
            let actual_str = actual.py_str();
            return Ok(if op == "==" {
                actual_str == literal
            } else {
                actual_str != literal
            });
        }
    }

    Err(()) // "unparseable constraint"
}

/// `evaluate_constraints` (ontology.py:87-98). Evaluates each constraint in
/// order; ALL must pass, short-circuiting on the first failure (clean-`False`
/// or fail-closed error). Returns `(ok, reason)`; `reason` is `""` iff `ok`.
pub fn evaluate_constraints(
    constraints: &[String],
    args: &BTreeMap<String, String>,
    store: &Store,
) -> (bool, String) {
    for c in constraints {
        match eval_one(c, args, store) {
            Ok(true) => continue,
            Ok(false) => return (false, format!("ontology constraint failed: {c}")),
            Err(()) => return (false, format!("ontology constraint unresolved (deny): {c}")),
        }
    }
    (true, String::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(items: &[(&str, &str)]) -> BTreeMap<String, String> {
        items
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn constraints(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    /// Mirrors `TestOntology._store()` (tests/test_g2_redesign.py:446-452).
    fn matter_store() -> Store {
        let mut store: Store = BTreeMap::new();
        let mut matter: BTreeMap<String, BTreeMap<String, Value>> = BTreeMap::new();
        let mut m123: BTreeMap<String, Value> = BTreeMap::new();
        m123.insert(
            "contacts".to_string(),
            Value::Collection(vec![
                "sarah@client.com".to_string(),
                "li@client.com".to_string(),
            ]),
        );
        m123.insert("status".to_string(), Value::Str("active".to_string()));
        matter.insert("M-123".to_string(), m123);

        let mut sealed: BTreeMap<String, Value> = BTreeMap::new();
        sealed.insert(
            "contacts".to_string(),
            Value::Collection(vec!["x@client.com".to_string()]),
        );
        sealed.insert("status".to_string(), Value::Str("sealed".to_string()));
        matter.insert("M-SEALED".to_string(), sealed);

        store.insert("matter".to_string(), matter);
        store
    }

    #[test]
    fn allows_when_all_constraints_satisfied() {
        let (ok, reason) = evaluate_constraints(
            &constraints(&["to in matter.contacts", "matter.status != sealed"]),
            &args(&[("to", "sarah@client.com"), ("matter_id", "M-123")]),
            &matter_store(),
        );
        assert!(ok, "{reason}");
    }

    #[test]
    fn denies_recipient_not_on_matter() {
        let (ok, reason) = evaluate_constraints(
            &constraints(&["to in matter.contacts"]),
            &args(&[("to", "attacker@evil.com"), ("matter_id", "M-123")]),
            &matter_store(),
        );
        assert!(!ok);
        assert!(reason.contains("matter.contacts"));
    }

    #[test]
    fn denies_sealed_matter() {
        let (ok, _) = evaluate_constraints(
            &constraints(&["matter.status != sealed"]),
            &args(&[("to", "x@client.com"), ("matter_id", "M-SEALED")]),
            &matter_store(),
        );
        assert!(!ok);
    }

    #[test]
    fn fail_closed_on_missing_data() {
        let (ok, _) = evaluate_constraints(
            &constraints(&["to in matter.contacts"]),
            &args(&[("to", "sarah@client.com"), ("matter_id", "M-UNKNOWN")]),
            &matter_store(),
        );
        assert!(!ok);
    }

    #[test]
    fn fail_closed_on_malformed_constraint() {
        let (ok, _) = evaluate_constraints(
            &constraints(&["definitely not a predicate"]),
            &args(&[("matter_id", "M-123")]),
            &matter_store(),
        );
        assert!(!ok);
    }

    #[test]
    fn empty_constraints_allow() {
        let (ok, reason) = evaluate_constraints(&[], &BTreeMap::new(), &Store::new());
        assert!(ok);
        assert_eq!(reason, "");
    }

    #[test]
    fn membership_not_in_negates() {
        let (ok, _) = evaluate_constraints(
            &constraints(&["to not in matter.contacts"]),
            &args(&[("to", "attacker@evil.com"), ("matter_id", "M-123")]),
            &matter_store(),
        );
        assert!(ok);

        let (ok2, _) = evaluate_constraints(
            &constraints(&["to not in matter.contacts"]),
            &args(&[("to", "sarah@client.com"), ("matter_id", "M-123")]),
            &matter_store(),
        );
        assert!(!ok2);
    }

    #[test]
    fn equality_constraint_passes_on_match() {
        let (ok, _) = evaluate_constraints(
            &constraints(&["matter.status == active"]),
            &args(&[("matter_id", "M-123")]),
            &matter_store(),
        );
        assert!(ok);
    }

    #[test]
    fn equality_literal_quotes_are_stripped() {
        let (ok, _) = evaluate_constraints(
            &constraints(&["matter.status == 'active'"]),
            &args(&[("matter_id", "M-123")]),
            &matter_store(),
        );
        assert!(ok);

        let (ok2, _) = evaluate_constraints(
            &constraints(&["matter.status == \"active\""]),
            &args(&[("matter_id", "M-123")]),
            &matter_store(),
        );
        assert!(ok2);
    }

    #[test]
    fn membership_rhs_resolving_to_scalar_is_not_a_collection_fail_closed() {
        let (ok, _) = evaluate_constraints(
            &constraints(&["to in matter.status"]),
            &args(&[("to", "active"), ("matter_id", "M-123")]),
            &matter_store(),
        );
        assert!(!ok);
    }

    #[test]
    fn unknown_namespace_fails_closed() {
        let (ok, _) = evaluate_constraints(
            &constraints(&["to in patient.contacts"]),
            &args(&[("to", "x"), ("patient_id", "P-1")]),
            &Store::new(),
        );
        assert!(!ok);
    }

    #[test]
    fn empty_key_arg_value_is_treated_as_missing() {
        let (ok, _) = evaluate_constraints(
            &constraints(&["to in matter.contacts"]),
            &args(&[("to", "sarah@client.com"), ("matter_id", "")]),
            &matter_store(),
        );
        assert!(!ok);
    }

    #[test]
    fn membership_arg_present_as_empty_string_is_not_missing() {
        // `args.get(lhs) is None` check — empty string IS present, so this
        // should evaluate the membership test (and fail it, since "" isn't
        // a contact), NOT fail closed on a "missing arg" error.
        let mut a = args(&[("matter_id", "M-123")]);
        a.insert("to".to_string(), "".to_string());
        let (ok, reason) = evaluate_constraints(
            &constraints(&["to in matter.contacts"]),
            &a,
            &matter_store(),
        );
        assert!(!ok);
        assert!(reason.starts_with("ontology constraint failed:")); // clean False, not "unresolved"
    }

    #[test]
    fn reason_uses_original_unstripped_constraint_string() {
        let (ok, reason) = evaluate_constraints(
            &constraints(&["  matter.status != sealed  "]),
            &args(&[("matter_id", "M-SEALED")]),
            &matter_store(),
        );
        assert!(!ok);
        assert_eq!(
            reason,
            "ontology constraint failed:   matter.status != sealed  "
        );
    }

    #[test]
    fn first_failing_constraint_short_circuits() {
        let (ok, reason) = evaluate_constraints(
            &constraints(&["matter.status == sealed", "to in matter.contacts"]),
            &args(&[("to", "attacker@evil.com"), ("matter_id", "M-123")]),
            &matter_store(),
        );
        assert!(!ok);
        assert!(reason.contains("matter.status == sealed"));
        assert!(!reason.contains("matter.contacts"));
    }

    #[test]
    fn unparseable_constraint_with_no_operator_fails_closed() {
        let (ok, reason) = evaluate_constraints(
            &constraints(&["gibberish"]),
            &BTreeMap::new(),
            &Store::new(),
        );
        assert!(!ok);
        assert_eq!(reason, "ontology constraint unresolved (deny): gibberish");
    }
}
