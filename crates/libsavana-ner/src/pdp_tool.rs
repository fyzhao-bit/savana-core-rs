//! PDP control-plane tool-call adjudication — Rust port of the PURE decision
//! core of `server/security/pdp_tool.py`'s `adjudicate_tool_call`
//! (pdp_tool.py:29-60): the G4 "三连" (triple), all deterministic —
//!   ① whitelist   : the tool is in this role's ACTIVE set (and has a policy);
//!   ② ontology    : every `x-policy.constraint` holds (reuses the ported
//!                   [`crate::ontology::evaluate_constraints`]);
//!   ③ limit       : `count[attempt] < spec.limits[attempt]`.
//!
//! Deliberately NOT ported (kept in Python — same seams as the sibling ports):
//!   - `active_tools(role, packs)` (the `active is None` branch,
//!     pdp_tool.py:39) — pack loading + live MCP discovery, all I/O. The
//!     Python function already lets the caller INJECT the resolved active set
//!     via `active=`; this port takes that resolved set (as [`ToolSpecLite`]s)
//!     directly, exactly as `dataflow_policy.rs`/`attempt_classifier.rs` take a
//!     resolved profile. The `role` string is still threaded through because it
//!     is interpolated verbatim into the not-whitelisted denial reason.
//!   - the full `ToolSpec` (tool_registry.py:33-66) — only the four fields the
//!     decision reads (`name`/`attempt`/`constraints`/`limits`) are modeled;
//!     `input_schema`/`roles`/`projections`/… are registry-shape metadata the
//!     verdict never inspects. Role filtering happened upstream in
//!     `resolve_active_tools`, so the injected `active` set is already
//!     role-scoped (mirroring how Python passes a pre-filtered `active`).
//!   - the `OntologyStore` object — resolved to a plain [`crate::ontology::Store`]
//!     and passed in (see `ontology.rs` module docs). `Option<&Store>` models
//!     Python's `ontology is not None` distinction: `None` == unavailable
//!     (the `elif spec.constraints` fail-closed branch), `Some(store)` ==
//!     available (even if empty).

use std::collections::BTreeMap;

use crate::ontology::{self, Store};

/// The four `ToolSpec` fields (tool_registry.py:34-42) the G4 triple reads: the
/// tool `name`, its resolved `attempt` type, the ontology `constraints`, and
/// the per-attempt `limits`. The caller resolves the active set (packs + MCP
/// discovery, role-filtered) and passes these in — see module docs.
#[derive(Debug, Clone, Default)]
pub struct ToolSpecLite {
    pub name: String,
    pub attempt: String,
    pub constraints: Vec<String>,
    pub limits: BTreeMap<String, i64>,
}

/// Mirrors `@dataclass ToolVerdict` (pdp_tool.py:22-26): `reason`/`attempt`
/// default to `""` (the not-whitelisted / no-policy paths return an empty
/// `attempt`; every later path carries `spec.attempt`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolVerdict {
    pub allowed: bool,
    pub reason: String,
    pub attempt: String,
}

impl ToolVerdict {
    fn deny(reason: String, attempt: &str) -> Self {
        ToolVerdict {
            allowed: false,
            reason,
            attempt: attempt.to_string(),
        }
    }
}

/// `adjudicate_tool_call` (pdp_tool.py:29-60). Fail-closed throughout; the
/// first failing check short-circuits. `real_args` must be the on-host
/// rehydrated argument values (so ontology constraints compare true
/// identities), reduced to the `name -> str(value)` map
/// `evaluate_constraints` reads — same reduction the `ontology` differential
/// uses.
///
/// Order (exactly Python's):
///   ① whitelist — `active.find(name)`; absent → deny (empty attempt); present
///      but attempt-less (no local policy) → deny (empty attempt).
///   ② ontology  — `Some(store)` → `evaluate_constraints`, deny with its reason
///      on failure; `None` but the spec HAS constraints → deny
///      "ontology unavailable but constraints required (deny)".
///   ③ limit     — `spec.limits[attempt]` present AND
///      `counts[attempt] (default 0) >= that limit` → deny "over limit".
///   otherwise → allow, carrying `spec.attempt`.
pub fn adjudicate_tool_call(
    tool_name: &str,
    real_args: &BTreeMap<String, String>,
    role: &str,
    active: &[ToolSpecLite],
    ontology: Option<&Store>,
    attempt_counts: &BTreeMap<String, i64>,
) -> ToolVerdict {
    // ① whitelist — first spec whose name matches (Python `next(...)`).
    let spec = match active.iter().find(|s| s.name == tool_name) {
        None => {
            return ToolVerdict::deny(
                format!("tool '{tool_name}' not in active set for role '{role}'"),
                "",
            )
        }
        Some(s) => s,
    };
    if spec.attempt.is_empty() {
        return ToolVerdict::deny(format!("tool '{tool_name}' has no local policy (deny)"), "");
    }

    // ② ontology constraints — deterministic, fail-closed.
    match ontology {
        Some(store) => {
            let (ok, reason) = ontology::evaluate_constraints(&spec.constraints, real_args, store);
            if !ok {
                return ToolVerdict::deny(reason, &spec.attempt);
            }
        }
        None => {
            if !spec.constraints.is_empty() {
                return ToolVerdict::deny(
                    "ontology unavailable but constraints required (deny)".to_string(),
                    &spec.attempt,
                );
            }
        }
    }

    // ③ limit — count[attempt] < hard limit (a missing limit entry = no cap).
    if let Some(&hard) = spec.limits.get(&spec.attempt) {
        if attempt_counts.get(&spec.attempt).copied().unwrap_or(0) >= hard {
            return ToolVerdict::deny(
                format!("attempt '{}' over limit ({hard})", spec.attempt),
                &spec.attempt,
            );
        }
    }

    ToolVerdict {
        allowed: true,
        reason: String::new(),
        attempt: spec.attempt.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ontology::Value;

    fn args(items: &[(&str, &str)]) -> BTreeMap<String, String> {
        items
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn counts(items: &[(&str, i64)]) -> BTreeMap<String, i64> {
        items.iter().map(|(k, v)| (k.to_string(), *v)).collect()
    }

    fn spec(
        name: &str,
        attempt: &str,
        constraints: &[&str],
        limits: &[(&str, i64)],
    ) -> ToolSpecLite {
        ToolSpecLite {
            name: name.to_string(),
            attempt: attempt.to_string(),
            constraints: constraints.iter().map(|s| s.to_string()).collect(),
            limits: counts(limits),
        }
    }

    /// A store with `matter M-123` (contacts + active status).
    fn matter_store() -> Store {
        let mut store: Store = BTreeMap::new();
        let mut matter: BTreeMap<String, BTreeMap<String, Value>> = BTreeMap::new();
        let mut m123: BTreeMap<String, Value> = BTreeMap::new();
        m123.insert(
            "contacts".to_string(),
            Value::Collection(vec!["sarah@client.com".to_string()]),
        );
        m123.insert("status".to_string(), Value::Str("active".to_string()));
        matter.insert("M-123".to_string(), m123);
        store.insert("matter".to_string(), matter);
        store
    }

    #[test]
    fn tool_not_in_active_set_is_denied_with_role_in_reason() {
        let v = adjudicate_tool_call(
            "unknown_tool",
            &BTreeMap::new(),
            "partner",
            &[spec("other", "document_read", &[], &[])],
            None,
            &BTreeMap::new(),
        );
        assert!(!v.allowed);
        assert_eq!(
            v.reason,
            "tool 'unknown_tool' not in active set for role 'partner'"
        );
        assert_eq!(v.attempt, "");
    }

    #[test]
    fn tool_without_policy_attempt_is_denied() {
        let v = adjudicate_tool_call(
            "no_policy",
            &BTreeMap::new(),
            "user",
            &[spec("no_policy", "", &[], &[])],
            None,
            &BTreeMap::new(),
        );
        assert!(!v.allowed);
        assert_eq!(v.reason, "tool 'no_policy' has no local policy (deny)");
        assert_eq!(v.attempt, "");
    }

    #[test]
    fn constraints_required_but_ontology_unavailable_denies() {
        let v = adjudicate_tool_call(
            "send_email",
            &args(&[("to", "sarah@client.com"), ("matter_id", "M-123")]),
            "user",
            &[spec(
                "send_email",
                "outbound_message",
                &["to in matter.contacts"],
                &[],
            )],
            None, // ontology unavailable
            &BTreeMap::new(),
        );
        assert!(!v.allowed);
        assert_eq!(
            v.reason,
            "ontology unavailable but constraints required (deny)"
        );
        assert_eq!(v.attempt, "outbound_message");
    }

    #[test]
    fn no_constraints_and_no_ontology_passes_to_limit_check() {
        // No constraints → the ontology-unavailable branch is skipped even
        // with ontology=None.
        let v = adjudicate_tool_call(
            "reader",
            &BTreeMap::new(),
            "user",
            &[spec(
                "reader",
                "document_read",
                &[],
                &[("document_read", 1)],
            )],
            None,
            &BTreeMap::new(),
        );
        assert!(v.allowed);
        assert_eq!(v.attempt, "document_read");
    }

    #[test]
    fn constraint_satisfied_allows() {
        let v = adjudicate_tool_call(
            "send_email",
            &args(&[("to", "sarah@client.com"), ("matter_id", "M-123")]),
            "user",
            &[spec(
                "send_email",
                "outbound_message",
                &["to in matter.contacts"],
                &[],
            )],
            Some(&matter_store()),
            &BTreeMap::new(),
        );
        assert!(v.allowed, "{}", v.reason);
        assert_eq!(v.attempt, "outbound_message");
    }

    #[test]
    fn constraint_violated_denies_with_ontology_reason_and_attempt() {
        let v = adjudicate_tool_call(
            "send_email",
            &args(&[("to", "attacker@evil.com"), ("matter_id", "M-123")]),
            "user",
            &[spec(
                "send_email",
                "outbound_message",
                &["to in matter.contacts"],
                &[],
            )],
            Some(&matter_store()),
            &BTreeMap::new(),
        );
        assert!(!v.allowed);
        assert!(v.reason.contains("matter.contacts"));
        assert_eq!(v.attempt, "outbound_message");
    }

    #[test]
    fn limit_exactly_reached_denies() {
        let v = adjudicate_tool_call(
            "reader",
            &BTreeMap::new(),
            "user",
            &[spec(
                "reader",
                "document_read",
                &[],
                &[("document_read", 1)],
            )],
            Some(&Store::new()),
            &counts(&[("document_read", 1)]),
        );
        assert!(!v.allowed);
        assert_eq!(v.reason, "attempt 'document_read' over limit (1)");
        assert_eq!(v.attempt, "document_read");
    }

    #[test]
    fn limit_one_under_allows() {
        let v = adjudicate_tool_call(
            "reader",
            &BTreeMap::new(),
            "user",
            &[spec(
                "reader",
                "document_read",
                &[],
                &[("document_read", 2)],
            )],
            Some(&Store::new()),
            &counts(&[("document_read", 1)]),
        );
        assert!(v.allowed);
    }

    #[test]
    fn missing_limit_entry_means_no_cap() {
        // spec.limits has no entry for the attempt → `hard is None` → no limit.
        let v = adjudicate_tool_call(
            "reader",
            &BTreeMap::new(),
            "user",
            &[spec("reader", "document_read", &[], &[("other", 1)])],
            Some(&Store::new()),
            &counts(&[("document_read", 999)]),
        );
        assert!(v.allowed);
    }

    #[test]
    fn first_matching_spec_wins() {
        let v = adjudicate_tool_call(
            "dup",
            &BTreeMap::new(),
            "user",
            &[
                spec("dup", "document_read", &[], &[]),
                spec("dup", "outbound_message", &[], &[]),
            ],
            Some(&Store::new()),
            &BTreeMap::new(),
        );
        assert!(v.allowed);
        assert_eq!(v.attempt, "document_read"); // the first entry
    }
}
