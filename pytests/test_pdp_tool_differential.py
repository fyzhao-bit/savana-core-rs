"""Differential test: Rust `pdp_tool` adjudication vs. the live Python
`server.security.pdp_tool.adjudicate_tool_call` (Python is the oracle).

Covers the G4 "triple" (whitelist / ontology-constraint / limit) ported to
`crates/libsavana-ner/src/pdp_tool.rs` and exposed via PyO3 as
`savana_core.pdp_adjudicate_tool_call`, over every branch of the decision:

  - whitelist: tool absent from the active set (reason interpolates the role),
    tool present but attempt-less (no local policy);
  - ontology: constraint satisfied (allow), constraint violated (deny with the
    ontology reason + spec attempt), ontology UNAVAILABLE with constraints
    (fail-closed deny) vs. without constraints (skip to limit);
  - limit: count under / exactly at / a missing limit entry (no cap);
  - first-matching-spec-wins when the injected active list has a duplicate name.

The injected active set (ToolSpecs) and the ontology store are marshalled to
the same flat FFI shapes the ports take. Assertion is byte-exact on
`(allowed, reason, attempt)`.
"""
import sys

import pytest

savana_core = pytest.importorskip("savana_core")

sys.path.insert(0, "/Users/fz/Documents/jarvis")

from server.runtime.tool_registry import ToolSpec  # noqa: E402
from server.security.ontology import OntologyStore  # noqa: E402
from server.security.pdp_tool import adjudicate_tool_call  # noqa: E402


def _spec(name, attempt, constraints=(), limits=None):
    """A minimal ToolSpec carrying only the four fields the G4 triple reads."""
    return ToolSpec(
        name=name,
        description="",
        input_schema={},
        roles=frozenset(),
        attempt=attempt,
        constraints=tuple(constraints),
        limits=dict(limits or {}),
    )


def _specs_to_ffi(specs):
    return [
        (s.name, s.attempt, list(s.constraints), sorted(s.limits.items()))
        for s in specs
    ]


def _store_to_ffi(store):
    """Flatten OntologyStore._data into (scalars, collections) — same shape the
    ontology differential uses."""
    scalars, collections = [], []
    for ns, by_key in store._data.items():
        for key, fields in by_key.items():
            for field, value in fields.items():
                if isinstance(value, (set, frozenset, list, tuple)):
                    collections.append((ns, key, field, list(value)))
                else:
                    scalars.append((ns, key, field, str(value)))
    return scalars, collections


def _build_store():
    s = OntologyStore()
    s.set("matter", "M-123", contacts={"sarah@client.com", "li@client.com"}, status="active")
    s.set("matter", "M-SEALED", contacts={"x@client.com"}, status="sealed")
    return s


STORE = _build_store()


def _run(tool, real_args, role, specs, ontology, counts):
    py = adjudicate_tool_call(
        tool, dict(real_args), role=role, ontology=ontology,
        attempt_counts=dict(counts), active=list(specs),
    )
    py_t = (py.allowed, py.reason, py.attempt)

    if ontology is None:
        available, scalars, collections = False, [], []
    else:
        available = True
        scalars, collections = _store_to_ffi(ontology)

    rust = savana_core.pdp_adjudicate_tool_call(
        tool,
        list(real_args.items()),
        role,
        _specs_to_ffi(specs),
        available,
        scalars,
        collections,
        sorted(counts.items()),
    )
    return py_t, rust


SEND = _spec("send_email", "outbound_message", constraints=("to in matter.contacts",))
SEND_STATUS = _spec(
    "send_email", "outbound_message",
    constraints=("to in matter.contacts", "matter.status != sealed"),
)
READER = _spec("reader", "document_read", limits={"document_read": 1})
READER_NOLIMIT = _spec("reader", "document_read")
NOPOLICY = _spec("no_policy", "")  # attempt-less → no local policy

# (id, tool, real_args, role, specs, ontology, counts)
CASES = [
    ("allow_no_constraints_ontology_present",
     "reader", {}, "user", [READER], STORE, {}),
    ("allow_no_constraints_ontology_none",
     "reader", {}, "user", [READER], None, {}),
    ("deny_not_in_active_user",
     "ghost", {}, "user", [READER], STORE, {}),
    ("deny_not_in_active_partner_role_in_reason",
     "ghost", {}, "partner", [READER], STORE, {}),
    ("deny_no_local_policy",
     "no_policy", {}, "user", [NOPOLICY], STORE, {}),
    ("allow_constraint_satisfied",
     "send_email", {"to": "sarah@client.com", "matter_id": "M-123"}, "user",
     [SEND], STORE, {}),
    ("deny_constraint_violated_recipient",
     "send_email", {"to": "attacker@evil.com", "matter_id": "M-123"}, "user",
     [SEND], STORE, {}),
    ("deny_constraint_sealed_matter",
     "send_email", {"to": "x@client.com", "matter_id": "M-SEALED"}, "user",
     [SEND_STATUS], STORE, {}),
    ("deny_ontology_unavailable_but_constraints_required",
     "send_email", {"to": "sarah@client.com", "matter_id": "M-123"}, "user",
     [SEND], None, {}),
    ("deny_limit_exactly_reached",
     "reader", {}, "user", [READER], STORE, {"document_read": 1}),
    ("allow_limit_one_under",
     "reader", {}, "user", [_spec("reader", "document_read", limits={"document_read": 2})],
     STORE, {"document_read": 1}),
    ("allow_no_limit_entry_no_cap",
     "reader", {}, "user", [READER_NOLIMIT], STORE, {"document_read": 999}),
    ("first_matching_spec_wins",
     "reader", {}, "user",
     [READER, _spec("reader", "outbound_message")], STORE, {}),
    ("fail_closed_missing_matter_id_arg",
     "send_email", {"to": "sarah@client.com"}, "user", [SEND], STORE, {}),
]


@pytest.mark.parametrize(
    "tool,real_args,role,specs,ontology,counts",
    [c[1:] for c in CASES],
    ids=[c[0] for c in CASES],
)
def test_adjudicate_tool_call_matches_python(tool, real_args, role, specs, ontology, counts):
    py, rust = _run(tool, real_args, role, specs, ontology, counts)
    assert py == rust


def test_deny_reasons_are_byte_exact():
    """Spot-check the exact denial reason strings (English, interpolated)."""
    py, rust = _run("ghost", {}, "partner", [READER], STORE, {})
    assert py == rust == (False, "tool 'ghost' not in active set for role 'partner'", "")

    py, rust = _run("no_policy", {}, "user", [NOPOLICY], STORE, {})
    assert py == rust == (False, "tool 'no_policy' has no local policy (deny)", "")

    py, rust = _run("reader", {}, "user", [READER], STORE, {"document_read": 1})
    assert py == rust == (False, "attempt 'document_read' over limit (1)", "document_read")

    py, rust = _run(
        "send_email", {"to": "sarah@client.com", "matter_id": "M-123"}, "user",
        [SEND], None, {},
    )
    assert py == rust == (
        False, "ontology unavailable but constraints required (deny)", "outbound_message",
    )
