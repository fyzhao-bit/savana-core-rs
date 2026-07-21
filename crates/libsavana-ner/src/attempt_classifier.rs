//! G4 attempt-type classification + per-run limits — Rust port of the PURE
//! decision core of `server/policy/attempt_classifier.py`'s `validate`
//! (attempt_classifier.py:121-152), plus the hardcoded `get_consent_required`
//! predicate (attempt_classifier.py:187-188).
//!
//! Ported: the three-check `validate` decision (tool×attempt pair is
//! registered, attempt type isn't cloud-blocked, running count is under
//! limit).
//!
//! Deliberately NOT ported:
//!   - `infer_attempt` (attempt_classifier.py:163-180) — its
//!     `profile is None` fast path hardcodes `"open_app" -> "system_action"`,
//!     but the GENERIC priority-sorted lookup it falls back to whenever an
//!     EXPLICIT profile is passed deterministically returns `"navigation"`
//!     for `open_app` instead (`"navigation"` sorts strictly before
//!     `"system_action"` in `_ATTEMPT_PRIORITY`, so this isn't a tie the
//!     pre-sort order could swing — the two paths genuinely disagree). That
//!     means `infer_attempt`'s observable output depends on Python object
//!     identity (`profile is None`) rather than resolved rule *content*,
//!     which doesn't fit the "inject the resolved profile" shape this port
//!     (and the whole differential-testing setup, which always calls Rust
//!     with an explicit resolved profile) uses. Left un-ported rather than
//!     forced to pick one behavior and silently diverge from the other.
//!   - `get_limits()` — a plain accessor over already-resolved data (no
//!     decision logic); callers just resolve limits in Python and pass them
//!     straight into `validate`.
//!   - `_limits()` / the `rules.yaml` `attempt_limits` override and its
//!     process-wide cache — YAML I/O stays Python; the caller resolves an
//!     [`AttemptPolicyProfile`] (explicit, or from `rules.yaml`/code
//!     defaults) and passes it in.

use std::collections::{BTreeMap, BTreeSet};

/// Mirrors `@dataclass(frozen=True) AttemptPolicyProfile`
/// (attempt_classifier.py:18-25). The caller resolves all three fields
/// (explicit profile, or `rules.yaml` / code defaults) and passes them in —
/// see module docs. `limits` uses `i64` to mirror Python's arbitrary-size
/// `int` without needing to reason about unsigned underflow in the caller.
#[derive(Debug, Clone, Default)]
pub struct AttemptPolicyProfile {
    pub valid_pairs: BTreeSet<(String, String)>,
    pub limits: BTreeMap<String, i64>,
    pub cloud_blocked: BTreeSet<String>,
}

/// The limit `validate` falls back to for an attempt type with no entry in
/// `profile.limits` (attempt_classifier.py:147: `limits.get(attempt_type, 50)`).
const DEFAULT_LIMIT: i64 = 50;

/// `validate` (attempt_classifier.py:121-152). Returns `(allowed,
/// reason_if_blocked)`; `reason` is `""` iff `allowed`. Checks, in order:
///   1. `(tool_name, attempt_type)` must be a registered pair.
///   2. If `provider == "cloud"`, `attempt_type` must not be cloud-blocked.
///   3. `attempt_counts[attempt_type]` (default 0) must be under
///      `profile.limits[attempt_type]` (default [`DEFAULT_LIMIT`]).
pub fn validate(
    tool_name: &str,
    attempt_type: &str,
    attempt_counts: &BTreeMap<String, i64>,
    provider: &str,
    profile: &AttemptPolicyProfile,
) -> (bool, String) {
    if !profile
        .valid_pairs
        .contains(&(tool_name.to_string(), attempt_type.to_string()))
    {
        return (
            false,
            format!("attempt '{attempt_type}' 与工具 '{tool_name}' 不匹配"),
        );
    }

    if provider == "cloud" && profile.cloud_blocked.contains(attempt_type) {
        return (false, format!("'{attempt_type}' 不允许云端执行，请转本地"));
    }

    let limit = profile
        .limits
        .get(attempt_type)
        .copied()
        .unwrap_or(DEFAULT_LIMIT);
    let count = attempt_counts.get(attempt_type).copied().unwrap_or(0);
    if count >= limit {
        return (false, format!("'{attempt_type}' 已达上限 ({limit}次)"));
    }

    (true, String::new())
}

/// `get_consent_required` (attempt_classifier.py:187-188): a hardcoded set
/// with no YAML override, so it needs no profile injection.
pub fn consent_required(attempt_type: &str) -> bool {
    matches!(attempt_type, "payment" | "shell_exec" | "vision_analysis")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairs(items: &[(&str, &str)]) -> BTreeSet<(String, String)> {
        items
            .iter()
            .map(|(a, b)| (a.to_string(), b.to_string()))
            .collect()
    }

    fn limits(items: &[(&str, i64)]) -> BTreeMap<String, i64> {
        items.iter().map(|(k, v)| (k.to_string(), *v)).collect()
    }

    fn strset(items: &[&str]) -> BTreeSet<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    fn counts(items: &[(&str, i64)]) -> BTreeMap<String, i64> {
        items.iter().map(|(k, v)| (k.to_string(), *v)).collect()
    }

    fn full_profile() -> AttemptPolicyProfile {
        AttemptPolicyProfile {
            valid_pairs: pairs(&[
                ("browser_navigate", "navigation"),
                ("browser_read", "page_read"),
                ("browser_read", "document_read"),
                ("run_shell", "shell_exec"),
            ]),
            limits: limits(&[
                ("navigation", 3),
                ("page_read", 20),
                ("document_read", 20),
                ("shell_exec", 10),
            ]),
            cloud_blocked: strset(&["credential_fill", "payment", "vision_analysis"]),
        }
    }

    #[test]
    fn unregistered_pair_is_rejected() {
        let p = full_profile();
        let (ok, reason) = validate("run_shell", "navigation", &BTreeMap::new(), "local", &p);
        assert!(!ok);
        assert!(reason.contains("不匹配"));
        assert!(reason.contains("navigation"));
        assert!(reason.contains("run_shell"));
    }

    #[test]
    fn registered_pair_within_limit_on_local_is_allowed() {
        let p = full_profile();
        let (ok, reason) = validate(
            "browser_navigate",
            "navigation",
            &BTreeMap::new(),
            "local",
            &p,
        );
        assert!(ok);
        assert_eq!(reason, "");
    }

    #[test]
    fn cloud_blocked_attempt_rejected_on_cloud_but_allowed_on_local() {
        let mut p = full_profile();
        p.valid_pairs
            .insert(("browser_login".to_string(), "credential_fill".to_string()));
        p.limits.insert("credential_fill".to_string(), 5);

        let (ok_cloud, reason) = validate(
            "browser_login",
            "credential_fill",
            &BTreeMap::new(),
            "cloud",
            &p,
        );
        assert!(!ok_cloud);
        assert!(reason.contains("不允许云端执行"));

        let (ok_local, _) = validate(
            "browser_login",
            "credential_fill",
            &BTreeMap::new(),
            "local",
            &p,
        );
        assert!(ok_local);
    }

    #[test]
    fn limit_boundary_at_exactly_the_limit_is_rejected() {
        let p = full_profile();
        let c = counts(&[("navigation", 3)]); // limit is 3 -> 3rd already used, 4th denied
        let (ok, reason) = validate("browser_navigate", "navigation", &c, "local", &p);
        assert!(!ok);
        assert!(reason.contains("上限"));
        assert!(reason.contains("(3次)"));
    }

    #[test]
    fn limit_boundary_one_under_the_limit_is_allowed() {
        let p = full_profile();
        let c = counts(&[("navigation", 2)]);
        let (ok, _) = validate("browser_navigate", "navigation", &c, "local", &p);
        assert!(ok);
    }

    #[test]
    fn missing_limit_entry_falls_back_to_default_50() {
        let mut p = full_profile();
        p.valid_pairs
            .insert(("get_time".to_string(), "data_access".to_string()));
        // no "data_access" entry in limits
        let c = counts(&[("data_access", 49)]);
        let (ok, _) = validate("get_time", "data_access", &c, "local", &p);
        assert!(ok);
        let c2 = counts(&[("data_access", 50)]);
        let (ok2, reason) = validate("get_time", "data_access", &c2, "local", &p);
        assert!(!ok2);
        assert!(reason.contains("(50次)"));
    }

    #[test]
    fn missing_count_entry_defaults_to_zero() {
        let p = full_profile();
        let (ok, _) = validate(
            "browser_navigate",
            "navigation",
            &BTreeMap::new(),
            "local",
            &p,
        );
        assert!(ok);
    }

    #[test]
    fn empty_profile_rejects_everything() {
        let p = AttemptPolicyProfile::default();
        let (ok, reason) = validate(
            "browser_navigate",
            "navigation",
            &BTreeMap::new(),
            "local",
            &p,
        );
        assert!(!ok);
        assert!(reason.contains("不匹配"));
    }

    #[test]
    fn consent_required_matches_hardcoded_set() {
        assert!(consent_required("payment"));
        assert!(consent_required("shell_exec"));
        assert!(consent_required("vision_analysis"));
        assert!(!consent_required("navigation"));
        assert!(!consent_required("page_read"));
        assert!(!consent_required(""));
    }
}
