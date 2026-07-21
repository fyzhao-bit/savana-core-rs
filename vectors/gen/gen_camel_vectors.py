"""Regenerate the camel_interpreter resolve-core differential corpus, frozen from
the SAME reference CPython the kernel vectors use.

    PYTHONPATH=/path/to/jarvis python vectors/gen/gen_camel_vectors.py

Emits (byte-stable):
  vectors/differential/camel_resolve.json
    { "resolve_one": [...], "resolve_args": [...], "safe_policy_detail": [...] }

Each resolve_* row is SELF-CONTAINED: it embeds the env/fields/vault/page_vault
spec so the Rust side can reconstruct identical `CaMeLValue`s, run the ported
function, and assert byte-exact against the `expect` computed here by the LIVE
reference functions. MUST NOT touch any vectors/conformance/*.json oracle.
"""

from __future__ import annotations

import json
import os
import types

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
OUT = os.path.join(REPO, "vectors", "differential")

from server.security.capabilities import (  # noqa: E402
    CaMeLValue,
    Capability,
    Source,
)
from server.runtime.camel_interpreter import (  # noqa: E402
    _resolve_one,
    _resolve_args,
    _safe_policy_detail,
    UnresolvedRef,
)

# ── shared env / fields specs (embedded per row for a self-contained fixture) ──
ENV_SPEC = {
    "s1": {"raw": "OUT", "sources": ["tool"], "readers": ["tool:browser_read"]},
    "s2": {"raw": 123, "sources": ["user"], "readers": None},
    "s3": {"raw": {"nested": [1, 2]}, "sources": ["qllm", "tool"], "readers": ["tool"]},
    "a" * 64: {"raw": "MAXID", "sources": ["planner"], "readers": None},
}
FIELDS_SPEC = {
    "s1": {
        "name": {"raw": "Bob", "sources": ["qllm"], "readers": ["tool"]},
        "amount": {"raw": "42", "sources": ["constant"], "readers": None},
    }
}


def mkval(spec):
    sources = frozenset(Source(s) for s in spec["sources"])
    readers = None if spec["readers"] is None else frozenset(spec["readers"])
    return CaMeLValue(spec["raw"], Capability(sources, readers))


def build_env(spec):
    return {k: mkval(v) for k, v in spec.items()}


def build_fields(spec):
    return {k: {fk: mkval(fv) for fk, fv in inner.items()} for k, inner in spec.items()}


def ser_val(cv):
    return {
        "kind": "value",
        "raw": cv.raw,
        "sources": sorted(s.value for s in cv.cap.sources),
        "readers": None if cv.cap.readers is None else sorted(cv.cap.readers),
    }


def ser_res(r):
    if isinstance(r, UnresolvedRef):
        return {"kind": "unresolved", "path": r.path, "reason": r.reason}
    return ser_val(r)


def resolve_one_rows():
    rows = []

    def add(name, v, vault=None, page_vault=None, env_spec=None, fields_spec=None):
        es = ENV_SPEC if env_spec is None else env_spec
        fs = FIELDS_SPEC if fields_spec is None else fields_spec
        vault = vault or {}
        env = build_env(es)
        fields = build_fields(fs)
        res = _resolve_one(v, env, fields, vault, page_vault)
        rows.append(
            {
                "name": name,
                "v": v,
                "env": es,
                "fields": fs,
                "vault": vault,
                "page_vault": page_vault,
                "expect": ser_res(res),
            }
        )

    # ── $from ref resolution ──
    add("env_hit", {"$from": "s1"})
    add("env_hit_scalar", {"$from": "s2"})
    add("env_hit_nested", {"$from": "s3"})
    add("env_hit_maxid", {"$from": "a" * 64})
    add("env_miss", {"$from": "sX"})
    add("field_hit", {"$from": "s1.name"})
    add("field_hit2", {"$from": "s1.amount"})
    add("field_miss_fname", {"$from": "s1.zzz"})
    add("field_miss_sid", {"$from": "sZ.name"})
    add("field_miss_empty_sid_fields", {"$from": "nope.x"})
    add("dollarfrom_plus_junk", {"$from": "s1", "junk": 1})  # still $from branch
    # ── invalid refs ──
    add("bad_ref_leading_digit", {"$from": "1abc"})
    add("bad_ref_hyphen", {"$from": "a-b"})
    add("bad_ref_two_dots", {"$from": "a.b.c"})
    add("bad_ref_empty", {"$from": ""})
    add("bad_ref_space", {"$from": "a b"})
    add("bad_ref_nonstr_int", {"$from": 123})
    add("bad_ref_nonstr_null", {"$from": None})
    add("bad_ref_nonstr_list", {"$from": ["s1"]})
    add("bad_ref_too_long_ident", {"$from": "a" * 65})
    add("valid_ref_maxlen_env_miss", {"$from": "b" * 64})  # valid, not in env
    add("valid_ref_trailing_newline", {"$from": "s1\n"})  # fullmatch rejects \n
    # ── literal rehydration ──
    add("lit_hydrate", "mail <EMAIL_1> now", vault={"<EMAIL_1>": "bob@corp.com"})
    add(
        "lit_hydrate_pv_and_vault",
        "hi <NAME_1> and <EMAIL_1>",
        vault={"<EMAIL_1>": "bob@corp.com"},
        page_vault={"<NAME_1>": "Alice"},
    )
    add(
        "lit_vault_precedence_clash",
        "val <X_1> end",
        vault={"<X_1>": "L2VAL"},
        page_vault={"<X_1>": "PAGEVAL"},
    )
    add(
        "lit_rehydrate_chained_order",
        "<A_1>",
        vault={"<A_1>": "<B_1>", "<B_1>": "real"},
    )
    add(
        "lit_pv_only",
        "hey <NAME_1>",
        vault={},
        page_vault={"<NAME_1>": "Alice"},
    )
    add("lit_placeholder_no_match", "x <NAME_1> y", vault={"<EMAIL_1>": "bob@corp.com"})
    add("lit_lt_but_empty_vault", "x <NAME_1> y", vault={})
    add("lit_lt_but_no_placeholder_key", "has < angle", vault={"<EMAIL_1>": "z"})
    # ── literal non-str / no-'<' → constant ──
    add("lit_int", 42, vault={"<E_1>": "z"})
    add("lit_bool", True, vault={"<E_1>": "z"})
    add("lit_null", None, vault={"<E_1>": "z"})
    add("lit_float", 3.5, vault={"<E_1>": "z"})
    add("lit_list", [1, 2, "<E_1>"], vault={"<E_1>": "z"})  # list not str → constant
    add("lit_dict_no_from", {"a": 1, "b": "<E_1>"}, vault={"<E_1>": "z"})
    add("lit_plain_str", "plain text", vault={"<E_1>": "z"})
    add("lit_empty_str", "", vault={"<E_1>": "z"})
    add("lit_cjk_hydrate", "打给 <NAME_1>", vault={"<NAME_1>": "王小明"})
    return rows


def resolve_args_rows():
    rows = []

    def add(name, args, vault=None, page_vault=None):
        vault = vault or {}
        env = build_env(ENV_SPEC)
        fields = build_fields(FIELDS_SPEC)
        resolved, unresolved = _resolve_args(args, env, fields, vault, page_vault)
        rows.append(
            {
                "name": name,
                "args": args,
                "env": ENV_SPEC,
                "fields": FIELDS_SPEC,
                "vault": vault,
                "page_vault": page_vault,
                "expect": {
                    "resolved": {k: ser_val(v) for k, v in resolved.items()},
                    "unresolved": [
                        {"path": u.path, "reason": u.reason} for u in unresolved
                    ],
                },
            }
        )

    add(
        "mixed",
        {
            "to": {"$from": "s1"},
            "body": "mail <EMAIL_1>",
            "n": 42,
            "bad": {"$from": "sX"},
        },
        vault={"<EMAIL_1>": "bob@corp.com"},
    )
    add("empty", {})
    add(
        "two_unresolved_order",
        {"a": {"$from": "sX"}, "b": {"$from": "sY.f"}, "c": {"$from": "1bad"}},
    )
    add(
        "all_resolved",
        {"x": {"$from": "s1.name"}, "y": "plain", "z": {"$from": "s2"}},
    )
    return rows


def safe_policy_detail_rows():
    rows = []

    def mk_verdict(source, reason, verdict):
        r = types.SimpleNamespace(value=reason) if reason is not None else None
        v = types.SimpleNamespace(value=verdict) if verdict is not None else None
        return types.SimpleNamespace(source_layer=source, reason=r, verdict=v)

    cases = [
        (None, None, None),
        ("", None, None),
        ("G6", "policy_violation", "REJECTED"),
        ("L2", "", ""),
        ("host", None, "BLOCKED"),
        ("host", "consent", None),
        ("cloud_validator", "untrusted_flow", "ALLOWED"),
    ]
    for source, reason, verdict in cases:
        v = mk_verdict(source, reason, verdict)
        rows.append(
            {
                "source": source,
                "reason": reason,
                "verdict": verdict,
                "expect": _safe_policy_detail(v),
            }
        )
    return rows


def main():
    import unicodedata

    assert unicodedata.unidata_version == "15.0.0", (
        f"reference must be Unicode 15.0.0, got {unicodedata.unidata_version}"
    )

    corpus = {
        "resolve_one": resolve_one_rows(),
        "resolve_args": resolve_args_rows(),
        "safe_policy_detail": safe_policy_detail_rows(),
    }
    os.makedirs(OUT, exist_ok=True)
    path = os.path.join(OUT, "camel_resolve.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(corpus, f, ensure_ascii=False, indent=2, sort_keys=True)
        f.write("\n")
    print(
        f"wrote {path}: "
        f"{len(corpus['resolve_one'])} resolve_one, "
        f"{len(corpus['resolve_args'])} resolve_args, "
        f"{len(corpus['safe_policy_detail'])} safe_policy_detail"
    )


if __name__ == "__main__":
    main()
