//! Unified PDP sink verdict — Rust port of the PURE verdict adjudication of
//! `server/security/sink_policy.py`'s `unified_sink_check`
//! (sink_policy.py:127-314), together with the two decision-mapping bridges it
//! depends on from `jarvis/security_bridge.py`: `bridge_dataflow`
//! (security_bridge.py:181-211) and `bridge_attempt_validation`
//! (security_bridge.py:133-178).
//!
//! This is the E2E-critical G3→G4→G5→G6 gate decision. It maps
//! `(tool, attempt, per-arg taint, running counts, provider, profile)` to a
//! terminal `(verdict, reason, resolved_attempt)` plus an ordered decision
//! trace. It REUSES the already-ported pure cores it composes:
//!   - G3 dataflow taint: [`crate::dataflow_policy::check_policy`]
//!   - G4 attempt/limit:  [`crate::attempt_classifier::validate`]
//!
//! Deliberately NOT ported (kept in Python — audit/flywheel I/O and the
//! external validator fan-out, matching the task's seam):
//!   - `_capture`/`_audit`/`_trace_gate` — audit-log + de-identified flywheel
//!     capture + `log_security_gate` emission. All side effects / callbacks.
//!     This port returns the ordered decision trace as pure DATA (see
//!     [`SinkVerdict::trace`]); the caller feeds it to the logger. The Python
//!     logger's per-row detail strings and its `source_layer`→gate remapping
//!     (sink_policy.py:198-215) are logging concerns, not verdict logic, and
//!     are not reproduced.
//!   - The G5 external validators — `validate_shell_command` (shell),
//!     `validate_vision` (vision), `cloud_validator.validate_tool` (browser_*).
//!     These do real work (command parsing, URL/domain rules, selector rules)
//!     and stay Python. Their already-bridged results are INJECTED in order via
//!     `g5_results` (empty for the sealed DOCUMENT pack, whose three tools trip
//!     none of the G5 branches). The pure merge/short-circuit/consent logic
//!     over those injected results IS ported here.
//!   - `_fail_closed` — a Python try/except wrapper around each validator that
//!     converts an exception into a REJECT. The ported cores are total (they
//!     cannot raise), so on the Rust side a fail-closed reject only arises from
//!     a G5 validator, and the caller injects it as a `Rejected` `g5_results`
//!     entry.
//!   - `_resolve_attempt`'s `infer_attempt` fallback (sink_policy.py:111-124)
//!     for an OMITTED attempt — `infer_attempt` is itself un-ported (see
//!     `attempt_classifier.rs` module docs). When `attempt` is declared
//!     (non-empty) `_resolve_attempt` returns it verbatim, which is the only
//!     path the differential/conformance vectors exercise; this port takes the
//!     declared attempt and treats it as resolved. Resolving an omitted attempt
//!     stays Python.

use std::collections::BTreeMap;

use crate::attempt_classifier::{self, AttemptPolicyProfile};
use crate::dataflow_policy::{self, ArgTaint, DataflowPolicyProfile, Verdict as DfVerdict};

/// Mirrors `class SecurityVerdict(Enum)` (security_bridge.py:16-19). `as_str`
/// round-trips the exact `.value` wire strings the differential compares on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityVerdict {
    Allowed,
    Rejected,
    Blocked,
}

impl SecurityVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            SecurityVerdict::Allowed => "allowed",
            SecurityVerdict::Rejected => "rejected",
            SecurityVerdict::Blocked => "blocked",
        }
    }

    /// Inverse of [`SecurityVerdict::as_str`] — used to parse injected G5
    /// sub-verdicts. `None` for anything the Python `SecurityVerdict(str)`
    /// would reject.
    pub fn from_wire(s: &str) -> Option<SecurityVerdict> {
        match s {
            "allowed" => Some(SecurityVerdict::Allowed),
            "rejected" => Some(SecurityVerdict::Rejected),
            "blocked" => Some(SecurityVerdict::Blocked),
            _ => None,
        }
    }

    /// Compact word for the decision trace.
    fn trace_word(self) -> &'static str {
        match self {
            SecurityVerdict::Allowed => "allow",
            SecurityVerdict::Rejected => "reject",
            SecurityVerdict::Blocked => "block",
        }
    }
}

/// The `RejectReason.value` strings this pure sink path can emit
/// (security_bridge.py:22-71). Only the reachable subset is modeled; injected
/// G5 results carry their own already-computed reason value string, so those
/// are passed through verbatim rather than re-enumerated here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectReason {
    Unknown,
    ConsentRequired,
    DestructiveOperation,
    InvalidAttempt,
    CloudBlockedType,
    LimitExceeded,
}

impl RejectReason {
    pub fn as_str(self) -> &'static str {
        match self {
            RejectReason::Unknown => "unknown",
            RejectReason::ConsentRequired => "consent_required",
            RejectReason::DestructiveOperation => "destructive_operation",
            RejectReason::InvalidAttempt => "invalid_attempt",
            RejectReason::CloudBlockedType => "cloud_blocked_type",
            RejectReason::LimitExceeded => "limit_exceeded",
        }
    }
}

/// A gate's bridged verdict: the [`SecurityVerdict`] plus its reason as a
/// `RejectReason.value` string (so injected G5 reasons — which can be any of
/// the ~30 `RejectReason` members — pass through uniformly alongside the
/// handful this module emits itself).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BridgedVerdict {
    pub verdict: SecurityVerdict,
    pub reason: String,
}

impl BridgedVerdict {
    fn new(verdict: SecurityVerdict, reason: RejectReason) -> Self {
        BridgedVerdict {
            verdict,
            reason: reason.as_str().to_string(),
        }
    }
}

/// Mirrors `@dataclass(frozen=True) SinkPolicyProfile` (sink_policy.py:42-55):
/// the sealed dataflow (G3) + attempts (G4) sub-profiles. The caller resolves
/// both (explicit profile, or `rules.yaml`/code defaults) and passes them in,
/// exactly as `dataflow_policy.rs`/`attempt_classifier.rs` already require.
#[derive(Debug, Clone, Default)]
pub struct SinkPolicyProfile {
    pub dataflow: DataflowPolicyProfile,
    pub attempts: AttemptPolicyProfile,
}

/// One ordered decision-trace event: `(gate, outcome)` where `gate` is
/// `"G3"`/`"G4"`/`"G5"`/`"G6"` and `outcome` is `"allow"`/`"block"`/
/// `"reject"`/`"skip"`. This is the pure "which gates fired, in what order,
/// with what local verdict" path — the data the Python `_trace_gate` calls
/// would carry. Detail/source-layer strings are a logging concern and stay
/// Python (see module docs).
pub type TraceEvent = (String, String);

/// Terminal output of [`unified_sink_check`]: the byte-exact verdict tuple the
/// differential and the `pdp_verdict_matrix` conformance vector assert on
/// (`(verdict.value, reason.value, resolved_attempt)`), plus the ordered
/// decision trace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SinkVerdict {
    pub verdict: SecurityVerdict,
    pub reason: String,
    pub attempt: String,
    pub trace: Vec<TraceEvent>,
}

/// `bridge_dataflow` (security_bridge.py:181-211): maps a G3 `PolicyResult`
/// verdict to a `SecurityResponse` verdict+reason. Purely on the `Verdict`
/// enum — no substring inspection:
///   - ALLOW   → (ALLOWED,  UNKNOWN)
///   - CONSENT → (BLOCKED,  CONSENT_REQUIRED)
///   - DENY    → (REJECTED, DESTRUCTIVE_OPERATION)
fn bridge_dataflow(result: &dataflow_policy::PolicyResult) -> BridgedVerdict {
    match result.verdict {
        DfVerdict::Allow => BridgedVerdict::new(SecurityVerdict::Allowed, RejectReason::Unknown),
        DfVerdict::Consent => {
            BridgedVerdict::new(SecurityVerdict::Blocked, RejectReason::ConsentRequired)
        }
        DfVerdict::Deny => BridgedVerdict::new(
            SecurityVerdict::Rejected,
            RejectReason::DestructiveOperation,
        ),
    }
}

/// `bridge_attempt_validation` (security_bridge.py:133-178): maps a G4
/// `validate` result `(allowed, reason)` to a `SecurityResponse` verdict+reason.
///
/// The reason classification is by SUBSTRING of the (byte-exact, Chinese +
/// interpolated) `validate` reason, in this exact order — order is
/// load-bearing:
///   1. `"不允许云端执行" in reason` OR `"cloud" in reason.lower()` → CLOUD_BLOCKED_TYPE
///   2. `"不匹配" in reason`                                         → INVALID_ATTEMPT
///   3. `"上限" in reason`                                           → LIMIT_EXCEEDED
///   4. otherwise                                                    → UNKNOWN
///
/// The `"cloud" in reason.lower()` clause is why a LIMIT rejection of an
/// attempt whose NAME contains "cloud" (e.g. `document_cloud_analysis`, which
/// `validate` interpolates into `"'document_cloud_analysis' 已达上限 (1次)"`)
/// is reported as CLOUD_BLOCKED_TYPE, not LIMIT_EXCEEDED — a quirk the frozen
/// `pdp_verdict_matrix` rows 20-21 depend on. Reusing the byte-exact ported
/// `validate` reproduces it exactly.
fn bridge_attempt_validation(allowed: bool, reason: &str) -> BridgedVerdict {
    if allowed {
        return BridgedVerdict::new(SecurityVerdict::Allowed, RejectReason::Unknown);
    }
    // `str::to_lowercase()` mirrors Python `str.lower()`; the only case-varying
    // content that matters here is the ASCII attempt name (already snake_case),
    // so the two agree for every realistic reason.
    let reason_lower = reason.to_lowercase();
    let mapped = if reason.contains("不允许云端执行") || reason_lower.contains("cloud") {
        RejectReason::CloudBlockedType
    } else if reason.contains("不匹配") {
        RejectReason::InvalidAttempt
    } else if reason.contains("上限") {
        RejectReason::LimitExceeded
    } else {
        RejectReason::Unknown
    };
    BridgedVerdict::new(SecurityVerdict::Rejected, mapped)
}

/// `unified_sink_check` (sink_policy.py:127-314) — the pure verdict path.
///
/// Inputs:
///   - `tool_name`, `attempt` (DECLARED; see the `_resolve_attempt` seam in the
///     module docs — resolved == declared for every vector),
///   - `args`: each `kwargs` entry reduced to `(name, is_trusted, is_public)`
///     in original insertion order (what `check_policy` reads off a
///     `CaMeLValue`; same reduction as `dataflow_policy.rs`'s [`ArgTaint`]),
///   - `attempt_counts`, `provider`, the resolved `profile`,
///   - `g5_results`: the Python-side G5 validator outputs, already bridged to
///     `(verdict, reason)`, in evaluation order (shell, then vision, then cloud
///     — whichever applied). Empty for the DOCUMENT pack.
///
/// Composition (short-circuit order preserved from Python):
///   G3 dataflow → reject returns; consent is remembered.
///   G4 attempt  → reject returns; (never yields consent — its bridge only
///                 returns ALLOWED/REJECTED).
///   G5 injected → each reject returns; each block remembered (first wins).
///   G6          → a remembered consent returns BLOCKED; else ALLOWED.
pub fn unified_sink_check(
    tool_name: &str,
    attempt: &str,
    args: &[ArgTaint],
    attempt_counts: &BTreeMap<String, i64>,
    provider: &str,
    profile: &SinkPolicyProfile,
    g5_results: &[BridgedVerdict],
) -> SinkVerdict {
    // `_resolve_attempt` declared-branch: a non-empty declared attempt is used
    // verbatim (the infer fallback for an empty attempt stays Python).
    let resolved_attempt = attempt.to_string();
    let mut trace: Vec<TraceEvent> = Vec::new();
    let mut consent: Option<BridgedVerdict> = None;

    let terminal = |verdict: SecurityVerdict, reason: String, trace: Vec<TraceEvent>| SinkVerdict {
        verdict,
        reason,
        attempt: resolved_attempt.clone(),
        trace,
    };

    // ── G3: dataflow / taint (CaMeL structural) ──
    let g3 = bridge_dataflow(&dataflow_policy::check_policy(
        tool_name,
        args,
        &profile.dataflow,
    ));
    trace.push(("G3".to_string(), g3.verdict.trace_word().to_string()));
    match g3.verdict {
        SecurityVerdict::Rejected => return terminal(g3.verdict, g3.reason, trace),
        SecurityVerdict::Blocked => consent = Some(g3),
        SecurityVerdict::Allowed => {}
    }

    // ── G4: attempt classifier (tool×intent, per-type limits) ──
    let (ok, reason) = attempt_classifier::validate(
        tool_name,
        &resolved_attempt,
        attempt_counts,
        provider,
        &profile.attempts,
    );
    let g4 = bridge_attempt_validation(ok, &reason);
    trace.push(("G4".to_string(), g4.verdict.trace_word().to_string()));
    match g4.verdict {
        SecurityVerdict::Rejected => return terminal(g4.verdict, g4.reason, trace),
        // `bridge_attempt_validation` never returns BLOCKED, but mirror the
        // Python `consent = consent or r2` (first remembered consent wins).
        SecurityVerdict::Blocked => consent = consent.or(Some(g4)),
        SecurityVerdict::Allowed => {}
    }

    // ── G5: injected external-validator sub-verdicts (shell/vision/cloud) ──
    // Empty for the DOCUMENT pack → recorded as a single SKIP, matching the
    // Python `g5_checked=False → _trace_gate("G5","SKIP",...)`.
    if g5_results.is_empty() {
        trace.push(("G5".to_string(), "skip".to_string()));
    } else {
        for g5 in g5_results {
            trace.push(("G5".to_string(), g5.verdict.trace_word().to_string()));
            match g5.verdict {
                SecurityVerdict::Rejected => return terminal(g5.verdict, g5.reason.clone(), trace),
                SecurityVerdict::Blocked => consent = consent.or_else(|| Some(g5.clone())),
                SecurityVerdict::Allowed => {}
            }
        }
    }

    // ── G6: human consent ──
    if let Some(c) = consent {
        trace.push(("G6".to_string(), "block".to_string()));
        return terminal(c.verdict, c.reason, trace);
    }
    trace.push(("G6".to_string(), "skip".to_string()));
    terminal(
        SecurityVerdict::Allowed,
        RejectReason::Unknown.as_str().to_string(),
        trace,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(items: &[&str]) -> std::collections::BTreeSet<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    fn pairs(items: &[(&str, &str)]) -> std::collections::BTreeSet<(String, String)> {
        items
            .iter()
            .map(|(a, b)| (a.to_string(), b.to_string()))
            .collect()
    }

    fn kv(items: &[(&str, i64)]) -> BTreeMap<String, i64> {
        items.iter().map(|(k, v)| (k.to_string(), *v)).collect()
    }

    fn arg(name: &str, is_trusted: bool, is_public: bool) -> ArgTaint {
        ArgTaint {
            name: name.to_string(),
            is_trusted,
            is_public,
        }
    }

    /// The sealed DOCUMENT_SINK_POLICY_PROFILE (sink_policy.py:61-76).
    fn document_profile() -> SinkPolicyProfile {
        SinkPolicyProfile {
            dataflow: DataflowPolicyProfile {
                no_side_effect_tools: set(&["retrieve_pdf_evidence"]),
                consent_overridable_tools: set(&["draft_due_diligence_report", "send_email"]),
                high_risk_tools: set(&["draft_due_diligence_report", "send_email"]),
            },
            attempts: AttemptPolicyProfile {
                valid_pairs: pairs(&[
                    ("retrieve_pdf_evidence", "document_read"),
                    ("draft_due_diligence_report", "document_cloud_analysis"),
                    ("send_email", "outbound_message"),
                ]),
                limits: kv(&[
                    ("document_read", 1),
                    ("document_cloud_analysis", 1),
                    ("outbound_message", 1),
                ]),
                cloud_blocked: set(&[]),
            },
        }
    }

    fn check(tool: &str, attempt: &str, args: &[ArgTaint], counts: &[(&str, i64)]) -> SinkVerdict {
        unified_sink_check(
            tool,
            attempt,
            args,
            &kv(counts),
            "local",
            &document_profile(),
            &[],
        )
    }

    // Public/trusted arg (constant/user) reduce to (true, true); tainted
    // world data (tool/qllm) reduce to (false, false).
    const PUBLIC_TRUSTED: (bool, bool) = (true, true);
    const UNTRUSTED: (bool, bool) = (false, false);

    fn body(t: (bool, bool)) -> Vec<ArgTaint> {
        vec![arg("body", t.0, t.1)]
    }

    #[test]
    fn document_read_no_side_effect_always_allowed_regardless_of_taint() {
        for t in [PUBLIC_TRUSTED, UNTRUSTED] {
            let v = check("retrieve_pdf_evidence", "document_read", &body(t), &[]);
            assert_eq!(v.verdict, SecurityVerdict::Allowed);
            assert_eq!(v.reason, "unknown");
            assert_eq!(v.attempt, "document_read");
        }
    }

    #[test]
    fn draft_cloud_analysis_consent_regardless_of_taint() {
        // G3: public-trusted → high_risk consent; untrusted → consent-overridable
        // consent. Both remembered, G4 passes at count 0 → BLOCKED/consent.
        for t in [PUBLIC_TRUSTED, UNTRUSTED] {
            let v = check(
                "draft_due_diligence_report",
                "document_cloud_analysis",
                &body(t),
                &[],
            );
            assert_eq!(v.verdict, SecurityVerdict::Blocked);
            assert_eq!(v.reason, "consent_required");
            assert_eq!(v.attempt, "document_cloud_analysis");
        }
    }

    #[test]
    fn send_email_outbound_consent_at_zero_count() {
        let v = check("send_email", "outbound_message", &body(PUBLIC_TRUSTED), &[]);
        assert_eq!(v.verdict, SecurityVerdict::Blocked);
        assert_eq!(v.reason, "consent_required");
    }

    #[test]
    fn wrong_pair_rejected_invalid_attempt() {
        let v = check(
            "retrieve_pdf_evidence",
            "outbound_message",
            &body(PUBLIC_TRUSTED),
            &[],
        );
        assert_eq!(v.verdict, SecurityVerdict::Rejected);
        assert_eq!(v.reason, "invalid_attempt");
        assert_eq!(v.attempt, "outbound_message");
    }

    #[test]
    fn document_read_over_limit_rejected_limit_exceeded() {
        let v = check(
            "retrieve_pdf_evidence",
            "document_read",
            &body(PUBLIC_TRUSTED),
            &[("document_read", 1)],
        );
        assert_eq!(v.verdict, SecurityVerdict::Rejected);
        assert_eq!(v.reason, "limit_exceeded");
    }

    #[test]
    fn cloud_in_attempt_name_reclassifies_limit_as_cloud_blocked_type() {
        // The frozen-matrix rows 20-21 quirk: a LIMIT rejection of
        // "document_cloud_analysis" reports cloud_blocked_type because the
        // interpolated attempt name contains the substring "cloud".
        let v = check(
            "draft_due_diligence_report",
            "document_cloud_analysis",
            &body(PUBLIC_TRUSTED),
            &[("document_cloud_analysis", 1)],
        );
        assert_eq!(v.verdict, SecurityVerdict::Rejected);
        assert_eq!(v.reason, "cloud_blocked_type");
    }

    #[test]
    fn outbound_over_limit_is_plain_limit_exceeded() {
        let v = check(
            "send_email",
            "outbound_message",
            &body(PUBLIC_TRUSTED),
            &[("outbound_message", 1)],
        );
        assert_eq!(v.verdict, SecurityVerdict::Rejected);
        assert_eq!(v.reason, "limit_exceeded");
    }

    #[test]
    fn allow_path_trace_is_g3_g4_g5skip_g6skip_in_order() {
        let v = check(
            "retrieve_pdf_evidence",
            "document_read",
            &body(PUBLIC_TRUSTED),
            &[],
        );
        assert_eq!(
            v.trace,
            vec![
                ("G3".to_string(), "allow".to_string()),
                ("G4".to_string(), "allow".to_string()),
                ("G5".to_string(), "skip".to_string()),
                ("G6".to_string(), "skip".to_string()),
            ]
        );
    }

    #[test]
    fn consent_path_trace_ends_in_g6_block() {
        let v = check("send_email", "outbound_message", &body(PUBLIC_TRUSTED), &[]);
        assert_eq!(
            v.trace,
            vec![
                ("G3".to_string(), "block".to_string()),
                ("G4".to_string(), "allow".to_string()),
                ("G5".to_string(), "skip".to_string()),
                ("G6".to_string(), "block".to_string()),
            ]
        );
    }

    #[test]
    fn g4_reject_short_circuits_before_g5_and_g6_even_with_pending_consent() {
        // draft at limit: G3 consent remembered, G4 rejects → returns at G4,
        // trace has no G5/G6.
        let v = check(
            "draft_due_diligence_report",
            "document_cloud_analysis",
            &body(PUBLIC_TRUSTED),
            &[("document_cloud_analysis", 1)],
        );
        assert_eq!(
            v.trace,
            vec![
                ("G3".to_string(), "block".to_string()),
                ("G4".to_string(), "reject".to_string()),
            ]
        );
    }

    // ── bridge unit coverage (branches the DOCUMENT pack can't reach) ──

    #[test]
    fn bridge_dataflow_deny_is_rejected_destructive_operation() {
        let r = dataflow_policy::PolicyResult {
            verdict: DfVerdict::Deny,
            reason: "x".to_string(),
        };
        let b = bridge_dataflow(&r);
        assert_eq!(b.verdict, SecurityVerdict::Rejected);
        assert_eq!(b.reason, "destructive_operation");
    }

    #[test]
    fn dataflow_deny_propagates_as_terminal_reject() {
        // A high-risk-but-NOT-consent-overridable tool with an untrusted arg →
        // G3 DENY (not reachable in the DOCUMENT pack; drive it with a custom
        // profile).
        let profile = SinkPolicyProfile {
            dataflow: DataflowPolicyProfile {
                no_side_effect_tools: set(&[]),
                consent_overridable_tools: set(&[]),
                high_risk_tools: set(&["danger"]),
            },
            attempts: AttemptPolicyProfile {
                valid_pairs: pairs(&[("danger", "system_action")]),
                limits: kv(&[("system_action", 10)]),
                cloud_blocked: set(&[]),
            },
        };
        let v = unified_sink_check(
            "danger",
            "system_action",
            &[arg("payload", false, false)],
            &BTreeMap::new(),
            "local",
            &profile,
            &[],
        );
        assert_eq!(v.verdict, SecurityVerdict::Rejected);
        assert_eq!(v.reason, "destructive_operation");
        assert_eq!(v.trace, vec![("G3".to_string(), "reject".to_string())]);
    }

    #[test]
    fn bridge_attempt_validation_branches() {
        assert_eq!(bridge_attempt_validation(true, "").reason, "unknown");
        assert_eq!(
            bridge_attempt_validation(false, "'x' 不允许云端执行，请转本地").reason,
            "cloud_blocked_type"
        );
        assert_eq!(
            bridge_attempt_validation(false, "attempt 'a' 与工具 'b' 不匹配").reason,
            "invalid_attempt"
        );
        assert_eq!(
            bridge_attempt_validation(false, "'outbound_message' 已达上限 (1次)").reason,
            "limit_exceeded"
        );
        // ASCII "cloud" anywhere wins over the 上限 clause (order-sensitive).
        assert_eq!(
            bridge_attempt_validation(false, "'document_cloud_analysis' 已达上限 (1次)").reason,
            "cloud_blocked_type"
        );
        // Unrecognized reason → UNKNOWN.
        assert_eq!(bridge_attempt_validation(false, "???").reason, "unknown");
    }

    #[test]
    fn injected_g5_reject_short_circuits_and_returns_its_reason() {
        // A browser-like tool whose G3/G4 pass, but an injected G5 (cloud)
        // rejection terminates with the injected reason value.
        let profile = SinkPolicyProfile {
            dataflow: DataflowPolicyProfile {
                no_side_effect_tools: set(&["browser_x"]),
                ..Default::default()
            },
            attempts: AttemptPolicyProfile {
                valid_pairs: pairs(&[("browser_x", "page_read")]),
                limits: kv(&[("page_read", 20)]),
                cloud_blocked: set(&[]),
            },
        };
        let g5 = vec![BridgedVerdict {
            verdict: SecurityVerdict::Rejected,
            reason: "css_selector_blocked".to_string(),
        }];
        let v = unified_sink_check(
            "browser_x",
            "page_read",
            &[],
            &BTreeMap::new(),
            "local",
            &profile,
            &g5,
        );
        assert_eq!(v.verdict, SecurityVerdict::Rejected);
        assert_eq!(v.reason, "css_selector_blocked");
        assert_eq!(
            v.trace,
            vec![
                ("G3".to_string(), "allow".to_string()),
                ("G4".to_string(), "allow".to_string()),
                ("G5".to_string(), "reject".to_string()),
            ]
        );
    }

    #[test]
    fn injected_g5_block_becomes_consent_at_g6() {
        let profile = SinkPolicyProfile {
            dataflow: DataflowPolicyProfile {
                no_side_effect_tools: set(&["browser_x"]),
                ..Default::default()
            },
            attempts: AttemptPolicyProfile {
                valid_pairs: pairs(&[("browser_x", "page_read")]),
                limits: kv(&[("page_read", 20)]),
                cloud_blocked: set(&[]),
            },
        };
        let g5 = vec![BridgedVerdict {
            verdict: SecurityVerdict::Blocked,
            reason: "network_consent".to_string(),
        }];
        let v = unified_sink_check(
            "browser_x",
            "page_read",
            &[],
            &BTreeMap::new(),
            "local",
            &profile,
            &g5,
        );
        assert_eq!(v.verdict, SecurityVerdict::Blocked);
        assert_eq!(v.reason, "network_consent");
        assert_eq!(v.trace.last().unwrap().0, "G6");
        assert_eq!(v.trace.last().unwrap().1, "block");
    }

    #[test]
    fn g3_consent_wins_over_later_g5_block_first_remembered() {
        // Mirror `consent = consent or r`: G3's consent must survive a later
        // G5 block (first remembered wins).
        let profile = SinkPolicyProfile {
            dataflow: DataflowPolicyProfile {
                no_side_effect_tools: set(&[]),
                consent_overridable_tools: set(&["browser_x"]),
                high_risk_tools: set(&[]),
            },
            attempts: AttemptPolicyProfile {
                valid_pairs: pairs(&[("browser_x", "page_read")]),
                limits: kv(&[("page_read", 20)]),
                cloud_blocked: set(&[]),
            },
        };
        let g5 = vec![BridgedVerdict {
            verdict: SecurityVerdict::Blocked,
            reason: "network_consent".to_string(),
        }];
        let v = unified_sink_check(
            "browser_x",
            "page_read",
            &[arg("url", false, false)], // untrusted → G3 consent (consent_required)
            &BTreeMap::new(),
            "local",
            &profile,
            &g5,
        );
        assert_eq!(v.verdict, SecurityVerdict::Blocked);
        assert_eq!(v.reason, "consent_required"); // G3's, not G5's
    }

    #[test]
    fn security_verdict_wire_round_trip() {
        for v in [
            SecurityVerdict::Allowed,
            SecurityVerdict::Rejected,
            SecurityVerdict::Blocked,
        ] {
            assert_eq!(SecurityVerdict::from_wire(v.as_str()), Some(v));
        }
        assert_eq!(SecurityVerdict::from_wire("bogus"), None);
    }
}
