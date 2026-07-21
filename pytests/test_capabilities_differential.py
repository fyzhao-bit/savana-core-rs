"""Differential test: Rust `capabilities` algebra vs. the live Python
`server.security.capabilities` module (Python is the oracle).

Covers the pure taint algebra ported to `crates/libsavana-ner/src/capabilities.rs`
and exposed via PyO3 in `crates/savana-core-py/src/lib.rs`:
  - `Capability.is_trusted` / `capability_is_trusted`
  - `Capability.is_public`  / `capability_is_public`
  - `combine_caps`          / `capabilities_combine`
over empty / disjoint / overlapping / public-sentinel / self-merge /
associativity / order-independence inputs, plus the invalid-source error path.
"""
import itertools
import random
import sys

import pytest

savana_core = pytest.importorskip("savana_core")

sys.path.insert(0, "/Users/fz/Documents/jarvis")

from server.security.capabilities import Capability, Source, combine_caps  # noqa: E402

ALL_SOURCES = list(Source)


def _all_subsets(items):
    for r in range(len(items) + 1):
        yield from itertools.combinations(items, r)


def _py_cap_to_ffi(cap: Capability):
    """Normalize a Python `Capability` to the `(sources, readers)` shape the
    Rust PyO3 functions take: sorted source-value strings, and `None` for
    public / sorted list for private readers."""
    sources = sorted(s.value for s in cap.sources)
    readers = None if cap.readers is None else sorted(cap.readers)
    return sources, readers


def _rust_normalized(sources, readers):
    sources = sorted(sources)
    readers = None if readers is None else sorted(readers)
    return sources, readers


# A representative spread: public/private, overlapping/disjoint/empty
# readers, empty/single/all source sets — the categories the port must get
# right (especially the public-sentinel and union/intersect asymmetry).
REPRESENTATIVE_CAPS = [
    Capability(frozenset({Source.USER}), None),                          # 0: public, trusted
    Capability(frozenset({Source.CONSTANT}), None),                      # 1: public, trusted
    Capability(frozenset({Source.USER, Source.PLANNER}), None),          # 2: public, trusted, multi-source
    Capability(frozenset({Source.TOOL}), frozenset({"a"})),              # 3: private, untrusted
    Capability(frozenset({Source.TOOL}), frozenset({"b"})),              # 4: private, disjoint readers vs #3
    Capability(frozenset({Source.TOOL}), frozenset({"a", "b"})),         # 5: private, overlaps #3 and #4
    Capability(frozenset({Source.QLLM}), frozenset({"b", "c"})),         # 6: private, partial overlap w/ #5
    Capability(frozenset({Source.USER}), frozenset({"user"})),           # 7: rehydrated_value shape
    Capability(frozenset({Source.TOOL}), frozenset()),                   # 8: private w/ EMPTY reader set
    Capability(frozenset(), None),                                       # 9: empty sources, public
    Capability(frozenset(ALL_SOURCES), None),                            # 10: all sources, public
    Capability(frozenset(ALL_SOURCES), frozenset({"x"})),                # 11: all sources, private
]


def test_source_enum_values_round_trip_through_rust():
    for s in ALL_SOURCES:
        sources_out, _ = savana_core.capabilities_combine([([s.value], None)])
        assert sources_out == [s.value]


@pytest.mark.parametrize(
    "subset",
    list(_all_subsets(ALL_SOURCES)),
    ids=lambda ss: "+".join(s.value for s in ss) or "empty",
)
def test_is_trusted_matches_over_all_source_subsets(subset):
    cap = Capability(frozenset(subset), None)
    expected = cap.is_trusted
    actual = savana_core.capability_is_trusted([s.value for s in subset])
    assert actual == expected


@pytest.mark.parametrize(
    "readers",
    [None, [], ["a"], ["a", "b"], ["user"], ["tool:x"]],
    ids=lambda r: "public" if r is None else ("empty" if not r else "+".join(r)),
)
def test_is_public_matches(readers):
    cap = Capability(frozenset({Source.TOOL}), None if readers is None else frozenset(readers))
    expected = cap.is_public
    actual = savana_core.capability_is_public(readers)
    assert actual == expected


def test_combine_caps_empty_matches():
    py_result = _py_cap_to_ffi(combine_caps([]))
    rust_result = _rust_normalized(*savana_core.capabilities_combine([]))
    assert py_result == rust_result


@pytest.mark.parametrize("cap", REPRESENTATIVE_CAPS, ids=lambda c: repr(_py_cap_to_ffi(c)))
def test_combine_caps_singleton_matches(cap):
    py_result = _py_cap_to_ffi(combine_caps([cap]))
    rust_result = _rust_normalized(*savana_core.capabilities_combine([_py_cap_to_ffi(cap)]))
    assert py_result == rust_result


@pytest.mark.parametrize("cap", REPRESENTATIVE_CAPS, ids=lambda c: repr(_py_cap_to_ffi(c)))
def test_combine_caps_self_merge_matches(cap):
    py_result = _py_cap_to_ffi(combine_caps([cap, cap]))
    ffi_cap = _py_cap_to_ffi(cap)
    rust_result = _rust_normalized(*savana_core.capabilities_combine([ffi_cap, ffi_cap]))
    assert py_result == rust_result


@pytest.mark.parametrize("a,b", list(itertools.product(REPRESENTATIVE_CAPS, repeat=2)))
def test_combine_caps_pairwise_matches(a, b):
    py_result = _py_cap_to_ffi(combine_caps([a, b]))
    rust_result = _rust_normalized(
        *savana_core.capabilities_combine([_py_cap_to_ffi(a), _py_cap_to_ffi(b)])
    )
    assert py_result == rust_result


def test_combine_caps_full_list_matches():
    py_result = _py_cap_to_ffi(combine_caps(REPRESENTATIVE_CAPS))
    ffi_caps = [_py_cap_to_ffi(c) for c in REPRESENTATIVE_CAPS]
    rust_result = _rust_normalized(*savana_core.capabilities_combine(ffi_caps))
    assert py_result == rust_result


def test_combine_caps_order_independent_both_languages():
    shuffled = REPRESENTATIVE_CAPS[:]
    random.Random(1234).shuffle(shuffled)

    py_forward = _py_cap_to_ffi(combine_caps(REPRESENTATIVE_CAPS))
    py_shuffled = _py_cap_to_ffi(combine_caps(shuffled))
    assert py_forward == py_shuffled  # Python-side invariant sanity check

    ffi_forward = [_py_cap_to_ffi(c) for c in REPRESENTATIVE_CAPS]
    ffi_shuffled = [_py_cap_to_ffi(c) for c in shuffled]
    rust_forward = _rust_normalized(*savana_core.capabilities_combine(ffi_forward))
    rust_shuffled = _rust_normalized(*savana_core.capabilities_combine(ffi_shuffled))
    assert rust_forward == rust_shuffled
    assert py_forward == rust_forward


@pytest.mark.parametrize(
    "a,b,c",
    [
        (REPRESENTATIVE_CAPS[3], REPRESENTATIVE_CAPS[4], REPRESENTATIVE_CAPS[5]),  # priv/priv/priv overlapping
        (REPRESENTATIVE_CAPS[0], REPRESENTATIVE_CAPS[3], REPRESENTATIVE_CAPS[6]),  # pub/priv/priv
        (REPRESENTATIVE_CAPS[8], REPRESENTATIVE_CAPS[3], REPRESENTATIVE_CAPS[9]),  # empty-readers/priv/empty-sources
    ],
)
def test_combine_caps_associativity_matches(a, b, c):
    # Python-side sanity: the algebra really is associative.
    flat = _py_cap_to_ffi(combine_caps([a, b, c]))
    left = _py_cap_to_ffi(combine_caps([combine_caps([a, b]), c]))
    right = _py_cap_to_ffi(combine_caps([a, combine_caps([b, c])]))
    assert flat == left == right

    # Rust-side, grouped differently, cross-checked against Python's flat result.
    fa, fb, fc = _py_cap_to_ffi(a), _py_cap_to_ffi(b), _py_cap_to_ffi(c)
    rust_flat = _rust_normalized(*savana_core.capabilities_combine([fa, fb, fc]))
    rust_ab = savana_core.capabilities_combine([fa, fb])
    rust_left = _rust_normalized(*savana_core.capabilities_combine([rust_ab, fc]))
    rust_bc = savana_core.capabilities_combine([fb, fc])
    rust_right = _rust_normalized(*savana_core.capabilities_combine([fa, rust_bc]))

    assert flat == rust_flat == rust_left == rust_right


def test_invalid_source_raises_valueerror_both_languages():
    with pytest.raises(ValueError):
        Source("bogus")
    with pytest.raises(ValueError):
        savana_core.capability_is_trusted(["bogus"])
