"""Differential test: Rust `dataflow_policy` decision core vs. the live
Python `server.security.dataflow_policy` module (Python is the oracle).

Covers `check_policy` (dataflow_policy.py:121-173) ported to
`crates/libsavana-ner/src/dataflow_policy.rs` and exposed via PyO3 as
`savana_core.dataflow_check_policy`, over:
  - every CaMeLValue provenance shape (constant/user/planner = public+trusted,
    tool/qllm = untrusted, rehydrated = private+trusted) singly and mixed,
  - argument-order sensitivity (the untrusted/private arg list embedded in a
    denial/consent reason follows kwargs insertion order),
  - every branch of the decision table (no-side-effect / untrusted-deny /
    untrusted-consent-overridable / private-consent / high-risk-consent /
    plain-allow), including a tool that is BOTH consent-overridable AND
    high-risk (checking the untrusted-arg check wins, since it's checked
    first),
  - the `profile=None` path against the REAL on-disk `rules.yaml`/code
    defaults (via `no_side_effect_tools()`/`consent_overridable_tools()`/
    `high_risk_tools()`), and an explicit custom profile, and the sealed
    `DOCUMENT_DATAFLOW_POLICY_PROFILE`.
"""
import sys

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
from server.security.dataflow_policy import (  # noqa: E402
    DOCUMENT_DATAFLOW_POLICY_PROFILE,
    DataflowPolicyProfile,
    Verdict,
    check_policy,
    consent_overridable_tools,
    high_risk_tools,
    no_side_effect_tools,
)


def _kwargs_to_ffi(kwargs):
    """dict[str, CaMeLValue] -> [(name, is_trusted, is_public), ...],
    preserving dict (insertion) order — the same order `check_policy`'s own
    `[k for k, v in kwargs.items() if ...]` comprehensions use, which flows
    into the `{untrusted}`/`{private}` list embedded in the reason string."""
    return [(k, v.is_trusted, v.is_public) for k, v in kwargs.items()]


def _profile_to_ffi(profile: DataflowPolicyProfile):
    return (
        sorted(profile.no_side_effect_tools),
        sorted(profile.consent_overridable_tools),
        sorted(profile.high_risk_tools),
    )


def _resolved_default_ffi():
    """What `check_policy(profile=None)` actually resolves against right
    now: the real on-disk `rules.yaml` merged with code defaults."""
    return (
        sorted(no_side_effect_tools()),
        sorted(consent_overridable_tools()),
        sorted(high_risk_tools()),
    )


def _run(tool_name, kwargs, profile):
    py_result = check_policy(tool_name, kwargs, profile)
    no_se, consent_ov, high_risk = (
        _profile_to_ffi(profile) if profile is not None else _resolved_default_ffi()
    )
    rust_verdict, rust_reason = savana_core.dataflow_check_policy(
        tool_name, _kwargs_to_ffi(kwargs), no_se, consent_ov, high_risk
    )
    return (py_result.verdict.value, py_result.reason), (rust_verdict, rust_reason)


KWARGS_CASES = {
    "empty": {},
    "single_constant": {"cmd": constant("ls")},
    "single_user": {"query": user_value("hello")},
    "single_planner": {"x": planner_value("derived")},
    "single_tool_untrusted": {"url": tool_value("http://evil.com", "browser_read")},
    "single_qllm_untrusted": {
        "cmd": qllm_value("rm -rf /", parents=[tool_value("page", "browser_read")])
    },
    "single_rehydrated_private_trusted": {"phone": rehydrated_value("13812345678")},
    "mixed_untrusted_and_private": {
        "body": rehydrated_value("secret-address"),
        "to": tool_value("evil@x.com", "browser_read"),
    },
    "mixed_public_and_private": {"a": constant("x"), "b": rehydrated_value("y")},
    "multi_untrusted_order_z_then_a": {
        "z": tool_value("1", "t1"),
        "a": tool_value("2", "t2"),
    },
    "multi_untrusted_order_a_then_z": {
        "a": tool_value("2", "t2"),
        "z": tool_value("1", "t1"),
    },
    "all_public_trusted_multi": {
        "a": constant("1"),
        "b": user_value("2"),
        "c": planner_value("3"),
    },
    "multi_private_trusted": {"a": rehydrated_value("1"), "b": rehydrated_value("2")},
    "tool_value_default_readers_no_name": {"x": tool_value("raw")},
    "tool_value_empty_reader_set": {
        "x": tool_value("raw", "t", readers=frozenset())
    },
}


CUSTOM_PROFILE = DataflowPolicyProfile(
    no_side_effect_tools=frozenset({"custom_reader"}),
    consent_overridable_tools=frozenset({"custom_writer", "custom_both"}),
    high_risk_tools=frozenset({"custom_danger", "custom_both"}),
)

TOOL_PROFILE_CASES = [
    ("browser_read", None),
    ("browser_navigate", None),
    ("run_shell", None),
    ("browser_click", None),
    ("some_totally_unclassified_tool_xyz", None),
    ("custom_reader", CUSTOM_PROFILE),
    ("custom_writer", CUSTOM_PROFILE),
    ("custom_danger", CUSTOM_PROFILE),
    ("custom_both", CUSTOM_PROFILE),  # consent-overridable AND high-risk: priority check
    ("retrieve_pdf_evidence", DOCUMENT_DATAFLOW_POLICY_PROFILE),
    ("draft_due_diligence_report", DOCUMENT_DATAFLOW_POLICY_PROFILE),
    ("send_email", DOCUMENT_DATAFLOW_POLICY_PROFILE),
    ("send_email", None),  # NOT classified by defaults (sealed pack is opt-in only)
]


@pytest.mark.parametrize("kwargs_name", list(KWARGS_CASES))
@pytest.mark.parametrize(
    "tool_name,profile",
    TOOL_PROFILE_CASES,
    ids=[f"{t}{'+custom' if p is CUSTOM_PROFILE else '+doc' if p is DOCUMENT_DATAFLOW_POLICY_PROFILE else '+default'}" for t, p in TOOL_PROFILE_CASES],
)
def test_check_policy_matches(tool_name, profile, kwargs_name):
    kwargs = KWARGS_CASES[kwargs_name]
    py, rust = _run(tool_name, kwargs, profile)
    assert py == rust


def test_verdict_wire_strings_match_python_enum_values():
    assert Verdict.ALLOW.value == "allow"
    assert Verdict.DENY.value == "deny"
    assert Verdict.CONSENT.value == "consent"


def test_document_profile_tools_are_unclassified_under_real_defaults():
    # Mirrors test_no_global_default_rule_classifies_a_document_tool in
    # tests/test_policy_profiles.py: none of the sealed pack's tools may be
    # accidentally classified by the global rules.yaml/code defaults.
    for name in ("retrieve_pdf_evidence", "draft_due_diligence_report", "send_email"):
        py, rust = _run(name, {"x": constant("v")}, None)
        assert py == rust
        assert py[0] == "allow"  # plain, unclassified, all-public-trusted args
