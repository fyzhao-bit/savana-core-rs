"""Differential test: Rust `attempt_classifier` decision core vs. the live
Python `server.policy.attempt_classifier` module (Python is the oracle).

Covers `validate` (attempt_classifier.py:121-152) ported to
`crates/libsavana-ner/src/attempt_classifier.rs` and exposed via PyO3 as
`savana_core.attempt_validate`, plus `get_consent_required` as
`savana_core.attempt_consent_required`, over:
  - every registered `(tool, attempt_type)` pair in `_VALID_PAIRS`,
  - unregistered pairs (garbage tool/attempt names, and real names crossed
    the wrong way),
  - both providers ("cloud"/"local") for every cloud-blocked attempt type,
    plus a non-"cloud" provider string to confirm only the literal "cloud"
    trips the block,
  - limit boundaries (limit-1 / exactly-at-limit / over-limit) computed
    relative to whatever the REAL resolved limits are (not hardcoded), so
    the test stays correct if `rules.yaml` changes,
  - the `profile=None` path against real `_VALID_PAIRS`/`_CLOUD_BLOCKED`/
    `get_limits()`, an explicit custom profile (mirroring
    tests/test_policy_profiles.py), and the sealed
    `DOCUMENT_SINK_POLICY_PROFILE.attempts`.

NOT covered (by design — see attempt_classifier.rs's module docs):
`infer_attempt`, whose `profile is None` fast path for `open_app` disagrees
with what its own generic priority-sorted lookup would return given the
exact same rules explicitly, so it isn't ported.
"""
import sys

import pytest

savana_core = pytest.importorskip("savana_core")

sys.path.insert(0, "/Users/fz/Documents/jarvis")

from server.policy.attempt_classifier import (  # noqa: E402
    _CLOUD_BLOCKED,
    _VALID_PAIRS,
    ATTEMPT_ENUM,
    AttemptPolicyProfile,
    get_consent_required,
    get_limits,
    validate,
)
from server.security.sink_policy import DOCUMENT_SINK_POLICY_PROFILE  # noqa: E402


def _profile_to_ffi(profile: AttemptPolicyProfile):
    return (
        sorted(profile.valid_pairs),
        sorted(profile.limits.items()),
        sorted(profile.cloud_blocked),
    )


def _resolved_default_ffi():
    return (sorted(_VALID_PAIRS), sorted(get_limits().items()), sorted(_CLOUD_BLOCKED))


def _run(tool_name, attempt_type, attempt_counts, provider, profile):
    py_ok, py_reason = validate(
        tool_name, attempt_type, attempt_counts, provider=provider, profile=profile
    )
    valid_pairs, limits, cloud_blocked = (
        _profile_to_ffi(profile) if profile is not None else _resolved_default_ffi()
    )
    rust_ok, rust_reason = savana_core.attempt_validate(
        tool_name,
        attempt_type,
        sorted(attempt_counts.items()),
        provider,
        valid_pairs,
        limits,
        cloud_blocked,
    )
    return (py_ok, py_reason), (rust_ok, rust_reason)


# ── Every registered pair, both providers, empty counts (baseline sweep) ──


@pytest.mark.parametrize("tool_name,attempt_type", sorted(_VALID_PAIRS))
def test_registered_pair_matches_on_local(tool_name, attempt_type):
    py, rust = _run(tool_name, attempt_type, {}, "local", None)
    assert py == rust


@pytest.mark.parametrize("tool_name,attempt_type", sorted(_VALID_PAIRS))
def test_registered_pair_matches_on_cloud(tool_name, attempt_type):
    py, rust = _run(tool_name, attempt_type, {}, "cloud", None)
    assert py == rust


@pytest.mark.parametrize("tool_name,attempt_type", sorted(_VALID_PAIRS))
def test_registered_pair_matches_on_unrecognized_provider(tool_name, attempt_type):
    # Only the literal string "cloud" trips the cloud-blocked check; any
    # other provider string (even garbage) behaves like "local".
    py, rust = _run(tool_name, attempt_type, {}, "some_other_provider", None)
    assert py == rust


# ── Unregistered / malformed pairs ──


@pytest.mark.parametrize(
    "tool_name,attempt_type",
    [
        ("run_shell", "navigation"),  # real tool, wrong attempt
        ("browser_navigate", "shell_exec"),  # real tool, wrong attempt
        ("nonexistent_tool", "page_read"),  # bogus tool
        ("browser_read", "nonexistent_attempt"),  # bogus attempt
        ("", ""),
        ("", "page_read"),
        ("browser_read", ""),
    ],
)
def test_unregistered_pair_matches(tool_name, attempt_type):
    py, rust = _run(tool_name, attempt_type, {}, "local", None)
    assert py == rust
    assert py[0] is False


# ── Limit boundaries, relative to the REAL resolved limits ──


@pytest.mark.parametrize("attempt_type", sorted(get_limits().keys()))
def test_limit_boundaries_relative_to_real_limits(attempt_type):
    tool_name = next(t for (t, a) in _VALID_PAIRS if a == attempt_type)
    limit = get_limits()[attempt_type]
    below = max(limit - 1, 0)

    for count in (below, limit, limit + 1):
        py, rust = _run(tool_name, attempt_type, {attempt_type: count}, "local", None)
        assert py == rust

    # Sanity anchor so the parametrized case can't be vacuously true: at/over
    # the limit is always blocked, and (for any real, positive limit) one
    # under it is allowed.
    py_at, _ = _run(tool_name, attempt_type, {attempt_type: limit}, "local", None)
    assert py_at[0] is False
    if limit > 0:
        py_below, _ = _run(tool_name, attempt_type, {attempt_type: below}, "local", None)
        assert py_below[0] is True


def test_missing_attempt_type_in_limits_falls_back_to_50():
    # Craft a profile whose valid_pairs include an attempt type absent from
    # its own limits map, to hit the `limits.get(attempt_type, 50)` fallback.
    profile = AttemptPolicyProfile(
        valid_pairs=frozenset({("custom_tool", "custom_attempt")}),
        limits={},
        cloud_blocked=frozenset(),
    )
    for count in (49, 50, 51):
        py, rust = _run("custom_tool", "custom_attempt", {"custom_attempt": count}, "local", profile)
        assert py == rust


# ── Explicit custom profiles (mirrors tests/test_policy_profiles.py) ──


def test_custom_profile_unknown_pair_rejected():
    profile = AttemptPolicyProfile(
        valid_pairs=frozenset({("send_test_email", "outbound_message")}),
        limits={"outbound_message": 1},
        cloud_blocked=frozenset(),
    )
    py, rust = _run("run_shell", "outbound_message", {}, "local", profile)
    assert py == rust
    assert py[0] is False


@pytest.mark.parametrize("count", [0, 1, 2])
def test_custom_profile_limit_boundary(count):
    profile = AttemptPolicyProfile(
        valid_pairs=frozenset({("read_test_document", "document_read")}),
        limits={"document_read": 1},
        cloud_blocked=frozenset(),
    )
    py, rust = _run("read_test_document", "document_read", {"document_read": count}, "local", profile)
    assert py == rust


def test_custom_profile_cloud_blocked():
    profile = AttemptPolicyProfile(
        valid_pairs=frozenset({("browser_login", "credential_fill")}),
        limits={"credential_fill": 5},
        cloud_blocked=frozenset({"credential_fill"}),
    )
    py_cloud, rust_cloud = _run("browser_login", "credential_fill", {}, "cloud", profile)
    assert py_cloud == rust_cloud
    assert py_cloud[0] is False

    py_local, rust_local = _run("browser_login", "credential_fill", {}, "local", profile)
    assert py_local == rust_local
    assert py_local[0] is True


# ── The sealed document-chain profile (real production fixture) ──


@pytest.mark.parametrize(
    "tool_name,attempt_type",
    sorted(DOCUMENT_SINK_POLICY_PROFILE.attempts.valid_pairs),
)
@pytest.mark.parametrize("count", [0, 1, 2])
def test_document_profile_matches(tool_name, attempt_type, count):
    py, rust = _run(
        tool_name, attempt_type, {attempt_type: count}, "local", DOCUMENT_SINK_POLICY_PROFILE.attempts
    )
    assert py == rust


def test_document_pairs_do_not_validate_under_real_defaults():
    for tool_name, attempt_type in sorted(DOCUMENT_SINK_POLICY_PROFILE.attempts.valid_pairs):
        py, rust = _run(tool_name, attempt_type, {}, "local", None)
        assert py == rust
        assert py[0] is False


# ── get_consent_required / attempt_consent_required ──


@pytest.mark.parametrize("attempt_type", ATTEMPT_ENUM + ["", "bogus_attempt_type"])
def test_consent_required_matches(attempt_type):
    py = get_consent_required(attempt_type)
    rust = savana_core.attempt_consent_required(attempt_type)
    assert py == rust
