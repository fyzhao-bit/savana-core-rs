"""Differential test: Rust `ontology` constraint engine vs. the live Python
`server.security.ontology` module (Python is the oracle).

Covers `evaluate_constraints`/`_eval_one`/`OntologyStore.resolve`
(ontology.py:44-98) ported to `crates/libsavana-ner/src/ontology.rs` and
exposed via PyO3 as `savana_core.ontology_evaluate_constraints`, over:
  - every namespace in `_KEY_BY_NS` (matter/advisor/patient/account),
  - membership (`in`/`not in`) and comparison (`==`/`!=`) predicates,
  - multi-constraint lists (all-pass, short-circuit-on-first-failure with
    the reason naming the RIGHT constraint),
  - fail-closed paths: unknown namespace, missing/empty key arg, unknown
    entity, unrecorded field, non-collection membership target, unparseable
    constraint, missing membership arg,
  - the `is None` (presence-only) vs. falsy (`not key`) asymmetry between
    `_eval_one`'s arg lookup and `resolve`'s key lookup — an empty-string
    arg is "present" for the former but "missing" for the latter,
  - the reason string using the ORIGINAL (unstripped) constraint text,
  - a non-string scalar field (stringified, like Python's own `str()` would
    do) and a list-valued (not set-valued) field compared via `==` — the
    one shape where `str()` of a collection is deterministic enough to
    differential-test (see NOTE below).

NOTE on scope: real ontology collection fields are Python `set`s (see
evals/full_e2e_report.py, tests/test_g2_redesign.py), used only for
`in`/`not in` — `str(a_set)`'s hash-randomized iteration order means
comparing a `set`-valued field with `==`/`!=` is already nondeterministic in
the Python ORIGINAL. This test therefore never does that (it uses a `list`
field for the one `==`-against-a-collection case, which IS deterministic).
"""
import sys

import pytest

savana_core = pytest.importorskip("savana_core")

sys.path.insert(0, "/Users/fz/Documents/jarvis")

from server.security.ontology import OntologyStore, evaluate_constraints  # noqa: E402


def _store_to_ffi(store: OntologyStore):
    """Flatten `OntologyStore._data` (ns -> key -> field -> value) into the
    two FFI lists `ontology_evaluate_constraints` takes. `list(value)`
    (NOT `sorted`) preserves each field's original iteration order — for a
    Python `list`/`tuple` that's insertion order (which is what `str()`
    renders), and for a `set` order doesn't matter since this test only
    ever uses `in`/`not in` against set-valued fields (see module docstring)."""
    scalars = []
    collections = []
    for ns, by_key in store._data.items():
        for key, fields in by_key.items():
            for field, value in fields.items():
                if isinstance(value, (set, frozenset, list, tuple)):
                    collections.append((ns, key, field, list(value)))
                else:
                    scalars.append((ns, key, field, str(value)))
    return scalars, collections


def _run(constraints, args, store):
    py_ok, py_reason = evaluate_constraints(constraints, args, store)
    scalars, collections = _store_to_ffi(store)
    rust_ok, rust_reason = savana_core.ontology_evaluate_constraints(
        list(constraints or []), list(args.items()), scalars, collections
    )
    return (py_ok, py_reason), (rust_ok, rust_reason)


def _build_store():
    s = OntologyStore()
    s.set("matter", "M-123", contacts={"sarah@client.com", "li@client.com"}, status="active")
    s.set("matter", "M-SEALED", contacts={"x@client.com"}, status="sealed")
    s.set("matter", "M-LIST", tags=["a", "b"], status="active")
    s.set("matter", "M-INT", status=42)
    s.set("advisor", "A-1", clients={"M-123"}, region="us")
    s.set("patient", "P-1", providers={"dr.x"}, status="active")
    s.set("account", "AC-1", owners={"u1", "u2"}, tier="gold")
    return s


STORE = _build_store()

# (id, constraints, args)
CASES = [
    ("all_pass", ["to in matter.contacts", "matter.status != sealed"],
     {"to": "sarah@client.com", "matter_id": "M-123"}),
    ("membership_fail_not_a_contact", ["to in matter.contacts"],
     {"to": "attacker@evil.com", "matter_id": "M-123"}),
    ("negated_equality_fail_on_sealed", ["matter.status != sealed"],
     {"to": "x@client.com", "matter_id": "M-SEALED"}),
    ("equality_pass", ["matter.status == sealed"], {"matter_id": "M-SEALED"}),
    ("fail_closed_unknown_entity", ["to in matter.contacts"],
     {"to": "sarah@client.com", "matter_id": "M-UNKNOWN"}),
    ("fail_closed_malformed_no_operator", ["definitely not a predicate"], {"matter_id": "M-123"}),
    ("empty_constraints_allow", [], {}),
    ("none_constraints_allow", None, {}),
    ("negation_pass", ["to not in matter.contacts"],
     {"to": "attacker@evil.com", "matter_id": "M-123"}),
    ("negation_fail", ["to not in matter.contacts"],
     {"to": "sarah@client.com", "matter_id": "M-123"}),
    ("membership_rhs_not_a_collection", ["to in matter.status"],
     {"to": "active", "matter_id": "M-123"}),
    ("field_not_recorded_on_entity", ["to in patient.contacts"],
     {"to": "x", "patient_id": "P-1"}),
    ("advisor_namespace_pass", ["client in advisor.clients"],
     {"client": "M-123", "advisor_id": "A-1"}),
    ("whitespace_preserved_in_reason", ["  matter.status != sealed  "], {"matter_id": "M-SEALED"}),
    ("short_circuit_first_constraint_fails", ["matter.status == sealed", "to in matter.contacts"],
     {"to": "attacker@evil.com", "matter_id": "M-123"}),
    ("short_circuit_second_constraint_fails", ["to in matter.contacts", "matter.status == sealed"],
     {"to": "sarah@client.com", "matter_id": "M-123"}),
    ("list_field_equality_edge_case", ["matter.tags == ['a', 'b']"], {"matter_id": "M-LIST"}),
    ("int_scalar_stringified", ["matter.status == '42'"], {"matter_id": "M-INT"}),
    ("unknown_namespace_in_comparison", ["nonexistent_ns.field == x"], {}),
    ("field_not_recorded_in_comparison", ["matter.nonexistent_field == x"], {"matter_id": "M-123"}),
    ("missing_membership_arg_entirely", ["to in matter.contacts"], {"matter_id": "M-123"}),
    ("membership_arg_present_but_empty", ["to in matter.contacts"], {"to": "", "matter_id": "M-123"}),
    ("key_arg_present_but_empty", ["to in matter.contacts"],
     {"to": "sarah@client.com", "matter_id": ""}),
    ("account_namespace_pass", ["owner in account.owners"], {"owner": "u1", "account_id": "AC-1"}),
    ("both_sides_unresolvable", ["x == y"], {}),
    ("no_operator_at_all", ["matter.status"], {"matter_id": "M-123"}),
    ("empty_string_constraint", [""], {}),
    ("missing_key_arg_entirely", ["matter.status == active"], {}),
]


@pytest.mark.parametrize("case_id,constraints,args", CASES, ids=[c[0] for c in CASES])
def test_evaluate_constraints_matches(case_id, constraints, args):
    py, rust = _run(constraints, args, STORE)
    assert py == rust


def test_reason_uses_original_unstripped_constraint_string():
    py, rust = _run(["  matter.status != sealed  "], {"matter_id": "M-SEALED"}, STORE)
    assert py == rust
    assert py[1] == "ontology constraint failed:   matter.status != sealed  "


def test_empty_store_fails_closed():
    py, rust = _run(["to in matter.contacts"], {"to": "x", "matter_id": "M-1"}, OntologyStore())
    assert py == rust
    assert py[0] is False
