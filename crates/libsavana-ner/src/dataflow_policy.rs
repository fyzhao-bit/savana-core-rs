//! Data-flow security policy — Rust port of the PURE decision core of
//! `server/security/dataflow_policy.py`'s `check_policy` (dataflow_policy.py:121-173),
//! plus its two small helpers `_untrusted_args`/`_private_trusted_args`
//! (dataflow_policy.py:108-118).
//!
//! Ported: the three-way classification of a tool call's arguments
//! (untrusted / private-trusted / public-trusted) against a
//! [`DataflowPolicyProfile`], and the ALLOW/DENY/CONSENT decision table.
//!
//! Deliberately NOT ported:
//!   - `CaMeLValue`/`kwargs: dict[str, CaMeLValue]` — `check_policy` only
//!     ever reads `is_trusted(v)`/`is_public(v)` off each argument value
//!     (never `.raw`/`.deps`), so this port takes that two-bool reduction
//!     directly (see [`ArgTaint`]) rather than modeling `CaMeLValue` itself —
//!     same scoping rationale as `capabilities.rs`'s module docs.
//!   - `_rules()`/`no_side_effect_tools()`/`consent_overridable_tools()`/
//!     `high_risk_tools()`/`_toolset` — the `rules.yaml` load and its
//!     process-wide cache. The caller resolves a [`DataflowPolicyProfile`]
//!     in Python (from an explicit profile, or from `rules.yaml`/code
//!     defaults) and passes the resolved three tool sets in.

use std::collections::BTreeSet;

/// Mirrors `class Verdict(str, Enum)` (dataflow_policy.py:23-26).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Verdict {
    Allow,
    Deny,
    Consent,
}

impl Verdict {
    /// The exact string value of the corresponding Python `Verdict` member.
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Allow => "allow",
            Verdict::Deny => "deny",
            Verdict::Consent => "consent",
        }
    }
}

/// Mirrors `@dataclass PolicyResult` (dataflow_policy.py:29-32); `reason` is
/// `""` for the default (ALLOW-with-no-reason) case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyResult {
    pub verdict: Verdict,
    pub reason: String,
}

impl PolicyResult {
    fn allow() -> Self {
        PolicyResult {
            verdict: Verdict::Allow,
            reason: String::new(),
        }
    }
}

/// Mirrors `@dataclass(frozen=True) DataflowPolicyProfile`
/// (dataflow_policy.py:35-39). The caller resolves these three sets
/// (explicit profile, or `rules.yaml` / code defaults) and passes them in —
/// see module docs.
#[derive(Debug, Clone, Default)]
pub struct DataflowPolicyProfile {
    pub no_side_effect_tools: BTreeSet<String>,
    pub consent_overridable_tools: BTreeSet<String>,
    pub high_risk_tools: BTreeSet<String>,
}

/// One `kwargs` entry, reduced to exactly what `check_policy` reads off a
/// `CaMeLValue`: its name (dict key) and its `is_trusted`/`is_public`
/// predicates (`Capability.is_trusted`/`is_public` — see `capabilities.rs`).
/// Order matters: Python dict iteration is insertion order, and that order
/// flows into the `{untrusted}`/`{private}` list embedded in a denial
/// reason, so callers must supply args in the original kwargs order (not
/// sorted).
#[derive(Debug, Clone)]
pub struct ArgTaint {
    pub name: String,
    pub is_trusted: bool,
    pub is_public: bool,
}

/// `repr()` of a Python `str`: picks the outer quote (single, unless the
/// string contains a `'` and no `"`, in which case double) and escapes
/// backslashes, the chosen quote, and the common control characters.
/// Printable non-ASCII passes through unescaped. Faithful for the realistic
/// inputs here (argument/tool names); does not replicate CPython's
/// `unicodedata`-category escaping for exotic non-printable Unicode.
///
/// Intentionally duplicated in `ontology.rs` (which needs the same
/// formatting for its `Value::Collection`'s `str()`) rather than factored
/// into a shared module, so each ported file stays self-contained per the
/// one-file-per-module porting convention.
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

/// `str()`/f-string formatting of a Python `list[str]`, e.g. `['a', 'b']` —
/// `str(list)` delegates to `list.__repr__`, which reprs each element.
fn py_list_repr(items: &[String]) -> String {
    let parts: Vec<String> = items.iter().map(|s| py_str_repr(s)).collect();
    format!("[{}]", parts.join(", "))
}

/// `_untrusted_args` (dataflow_policy.py:108-110): names of args that came
/// from the world (TOOL/QLLM) — not trusted. Preserves input order.
fn untrusted_args(args: &[ArgTaint]) -> Vec<String> {
    args.iter()
        .filter(|a| !a.is_trusted)
        .map(|a| a.name.clone())
        .collect()
}

/// `_private_trusted_args` (dataflow_policy.py:113-118): names of args that
/// are the user's own private data (trusted but non-public). Preserves
/// input order.
fn private_trusted_args(args: &[ArgTaint]) -> Vec<String> {
    args.iter()
        .filter(|a| a.is_trusted && !a.is_public)
        .map(|a| a.name.clone())
        .collect()
}

/// `check_policy` (dataflow_policy.py:121-173). Three-way classification of
/// each argument (untrusted / private+trusted / public+trusted) against
/// `profile`, in the same order Python checks them:
///   1. `tool_name` is a no-side-effect tool → ALLOW outright.
///   2. Any untrusted arg → CONSENT (if `tool_name` is consent-overridable)
///      else DENY.
///   3. No untrusted args, but some private-trusted (rehydrated PII) arg →
///      CONSENT.
///   4. All args public+trusted, but `tool_name` is high-risk → CONSENT.
///   5. Otherwise → ALLOW.
pub fn check_policy(
    tool_name: &str,
    args: &[ArgTaint],
    profile: &DataflowPolicyProfile,
) -> PolicyResult {
    if profile.no_side_effect_tools.contains(tool_name) {
        return PolicyResult::allow();
    }

    let untrusted = untrusted_args(args);
    if !untrusted.is_empty() {
        if profile.consent_overridable_tools.contains(tool_name) {
            return PolicyResult {
                verdict: Verdict::Consent,
                reason: format!(
                    "{tool_name} 的参数 {} 源自不可信数据(网页/邮件等),需你确认",
                    py_list_repr(&untrusted)
                ),
            };
        }
        return PolicyResult {
            verdict: Verdict::Deny,
            reason: format!(
                "{tool_name} 是状态变更操作,但参数 {} 源自不可信数据 — 已按数据流策略拦截",
                py_list_repr(&untrusted)
            ),
        };
    }

    let private = private_trusted_args(args);
    if !private.is_empty() {
        return PolicyResult {
            verdict: Verdict::Consent,
            reason: format!(
                "{tool_name} 的参数 {} 含你的隐私数据(已本地还原),外发前需你确认",
                py_list_repr(&private)
            ),
        };
    }

    if profile.high_risk_tools.contains(tool_name) {
        return PolicyResult {
            verdict: Verdict::Consent,
            reason: format!("{tool_name} 为高风险操作,需你确认"),
        };
    }

    PolicyResult::allow()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(items: &[&str]) -> BTreeSet<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    fn arg(name: &str, is_trusted: bool, is_public: bool) -> ArgTaint {
        ArgTaint {
            name: name.to_string(),
            is_trusted,
            is_public,
        }
    }

    fn profile(no_se: &[&str], consent_ov: &[&str], high_risk: &[&str]) -> DataflowPolicyProfile {
        DataflowPolicyProfile {
            no_side_effect_tools: set(no_se),
            consent_overridable_tools: set(consent_ov),
            high_risk_tools: set(high_risk),
        }
    }

    #[test]
    fn py_str_repr_matches_python_quoting_rules() {
        assert_eq!(py_str_repr("plain"), "'plain'");
        assert_eq!(py_str_repr("it's"), "\"it's\"");
        assert_eq!(py_str_repr("a\"b"), "'a\"b'");
        assert_eq!(py_str_repr("c\\d"), "'c\\\\d'");
        assert_eq!(py_str_repr("line\nbreak"), "'line\\nbreak'");
        assert_eq!(py_str_repr("tab\ttab"), "'tab\\ttab'");
    }

    #[test]
    fn py_list_repr_matches_python_list_str() {
        assert_eq!(py_list_repr(&["a".into(), "b".into()]), "['a', 'b']");
        assert_eq!(py_list_repr(&[]), "[]");
        assert_eq!(py_list_repr(&["only".into()]), "['only']");
    }

    #[test]
    fn no_side_effect_tool_always_allowed_even_with_untrusted_args() {
        let p = profile(&["browser_read"], &[], &[]);
        let r = check_policy("browser_read", &[arg("x", false, false)], &p);
        assert_eq!(r.verdict, Verdict::Allow);
        assert_eq!(r.reason, "");
    }

    #[test]
    fn untrusted_arg_denies_by_default() {
        let p = profile(&[], &[], &[]);
        let r = check_policy("run_shell", &[arg("command", false, false)], &p);
        assert_eq!(r.verdict, Verdict::Deny);
        assert!(r.reason.contains("run_shell"));
        assert!(r.reason.contains("['command']"));
    }

    #[test]
    fn untrusted_arg_on_consent_overridable_tool_yields_consent() {
        let p = profile(&[], &["browser_navigate"], &[]);
        let r = check_policy("browser_navigate", &[arg("url", false, false)], &p);
        assert_eq!(r.verdict, Verdict::Consent);
        assert!(r.reason.contains("['url']"));
    }

    #[test]
    fn trusted_public_arg_on_high_risk_tool_yields_consent() {
        let p = profile(&[], &[], &["run_shell"]);
        let r = check_policy("run_shell", &[arg("command", true, true)], &p);
        assert_eq!(r.verdict, Verdict::Consent);
        assert_eq!(r.reason, "run_shell 为高风险操作,需你确认");
    }

    #[test]
    fn trusted_private_arg_yields_consent_even_on_low_risk_tool() {
        let p = profile(&[], &[], &[]);
        let r = check_policy("search_emails", &[arg("query", true, false)], &p);
        assert_eq!(r.verdict, Verdict::Consent);
        assert!(r.reason.contains("['query']"));
    }

    #[test]
    fn all_trusted_public_non_high_risk_allows() {
        let p = profile(&[], &[], &[]);
        let r = check_policy("browser_click", &[arg("selector", true, true)], &p);
        assert_eq!(r.verdict, Verdict::Allow);
        assert_eq!(r.reason, "");
    }

    #[test]
    fn no_args_at_all_allows_unless_high_risk() {
        let p = profile(&[], &[], &[]);
        let r = check_policy("browser_click", &[], &p);
        assert_eq!(r.verdict, Verdict::Allow);
    }

    #[test]
    fn untrusted_check_takes_priority_over_private_and_high_risk() {
        // A tool that's both consent-overridable AND high-risk, with a mix
        // of untrusted + private args: untrusted must win (checked first).
        let p = profile(&[], &["send_email"], &["send_email"]);
        let r = check_policy(
            "send_email",
            &[arg("body", true, false), arg("to", false, false)],
            &p,
        );
        assert_eq!(r.verdict, Verdict::Consent);
        assert!(r.reason.contains("源自不可信数据"));
        assert!(r.reason.contains("['to']"));
    }

    #[test]
    fn multiple_untrusted_args_preserve_input_order_in_message() {
        let p = profile(&[], &[], &[]);
        let r = check_policy(
            "run_shell",
            &[arg("b", false, false), arg("a", false, false)],
            &p,
        );
        assert!(r.reason.contains("['b', 'a']"));
    }
}
