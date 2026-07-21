"""Regenerate the body_pipeline port's differential reference corpus, frozen from
the SAME reference CPython (unidata_version 15.0.0) that owns the kernel vectors.

    PYTHONPATH=/path/to/jarvis python vectors/gen/gen_body_pipeline_vectors.py

Emits (byte-stable, sorted keys, trailing newline):
  vectors/differential/body_leak_gate.json        -> leak_gate(body, vault)
  vectors/differential/body_should_compress.json   -> _should_compress(masked)

This file MUST NOT touch any vectors/conformance/*.json frozen oracle — it only
produces port-side differential artifacts by running the live reference
functions. The Rust side (body_pipeline.rs) reads these and asserts byte-exact.
"""

from __future__ import annotations

import json
import os
import random
import string
import sys

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
OUT = os.path.join(REPO, "vectors", "differential")

from server.security.body_pipeline import (  # noqa: E402
    leak_gate,
    _should_compress,
    _RESIDUAL_PII_RE,
)


def _leak_cases():
    curated = [
        # (body, vault)
        (None, {}),
        ("", {}),
        ("hello world", {}),
        ("just some benign text with no pii at all", {}),
        # ── structured PII: email variants ──
        ("reach bob@corp.com", {}),
        ("bob@corp com is dot-mangled", {}),          # @-glued fragment
        ("a@b more", {}),
        ("weird.name+tag%x@Example", {}),
        ("no email @ here alone", {}),
        # ── phone / 10+ digit run ──
        ("call +1 415 555 2671 now", {}),
        ("num 4155552671", {}),
        ("415-555-2671", {}),
        ("only 415555267 nine", {}),                  # 9 digits -> no
        ("+44 20 7946 0958", {}),
        # ── IBAN ──
        ("iban GB82WEST12345698765432 end", {}),
        ("DE89370400440532013000", {}),
        ("AB12 short", {}),
        # ── SSN / EIN ──
        ("ssn 012-34-5678", {}),
        ("ein 12-3456789", {}),
        ("nope 12-345678", {}),                       # 6 digits after -> no
        # ── bare long number ──
        ("acct 1234567890", {}),
        ("short 123456789", {}),                      # 9 -> no
        # ── payment card ──
        ("card 4111 1111 1111 1111", {}),
        ("4111-1111-1111-1111", {}),
        ("4111111111111", {}),                        # 13 digits bare -> matches long-num & card
        ("411111111111", {}),                         # 12 -> no card, no long(>=10) YES matches long? 12>=10 yes
        # ── vault residue: length filter ──
        ("name abc appears", {"n": "abc"}),           # len 3 -> not checked
        ("exactly test here", {"n": "test"}),         # len 4 -> checked, boundary -> leak
        ("meeting with Alice Johnson today", {"n": "Alice Johnson"}),
        ("AliceJohnsonExtra glued", {"n": "Alice Johnson"}),  # substring in word (no space) -> safe
        ("placeholder <NAME_1> only", {"NAME_1": "王小明明"}),  # <..> context -> safe
        ("。欧阳娜娜。", {"n": "欧阳娜娜"}),
        ("给欧阳娜娜打电话", {"n": "欧阳娜娜"}),        # adjacent word char -> safe
        ("multi one 王小明明 two", {"a": "zzz", "b": "王小明明"}),  # 2nd matches
        ("nothing matches here", {"a": "wxyz", "b": "qrst"}),
        ("value at end secret", {"n": "secret"}),
        ("secret at start value", {"n": "secret"}),
        ("wrapped(secret) parens", {"n": "secret"}),  # ( ) are non-word -> leak
        ("under_secret_score", {"n": "secret"}),      # _ is word char -> safe
    ]

    rng = random.Random(0xB0D1)
    fuzz = []
    # Bias the alphabet toward the structured-PII delimiters that drive the
    # regex (`@ . - + : space digits`) plus CJK, so the fuzz actually exercises
    # email/phone/IBAN/SSN/EIN/card/long-number boundaries, not just noise.
    alpha = string.ascii_letters + (string.digits * 3) + "   .-@_<>+:,;/"
    cjk = "王小明张伟李娜欧阳娜"
    pool = alpha + cjk

    def rand_token():
        # occasionally emit a PII-shaped token so word boundaries get stressed
        roll = rng.random()
        if roll < 0.15:
            return "".join(rng.choice(string.digits) for _ in range(rng.randint(8, 20)))
        if roll < 0.25:
            return f"{''.join(rng.choice(string.ascii_lowercase) for _ in range(rng.randint(1,6)))}@{''.join(rng.choice(string.ascii_lowercase) for _ in range(rng.randint(1,6)))}"
        if roll < 0.32:
            grp = lambda k: "".join(rng.choice(string.digits) for _ in range(k))  # noqa: E731
            sep = rng.choice([" ", "-", ""])
            return sep.join(grp(4) for _ in range(rng.randint(3, 5)))
        return "".join(rng.choice(pool) for _ in range(rng.randint(0, 12)))

    for _ in range(1200):
        ntok = rng.randint(0, 6)
        body = " ".join(rand_token() for _ in range(ntok))
        vault = {}
        for j in range(rng.randint(0, 3)):
            # vault values span the len<4 filter boundary + word-boundary edges
            vlen = rng.randint(0, 8)
            val = "".join(rng.choice(pool) for _ in range(vlen))
            vault[f"k{j}"] = val
            # sometimes plant the raw value into the body at a boundary
            if val and rng.random() < 0.35:
                sep = rng.choice([" ", ".", "(", ")", "", "_"])
                body = f"{body}{sep}{val}{sep}"
        fuzz.append((body, vault))

    return curated + fuzz


def _compress_cases():
    curated = [
        "",
        "short",
        "a" * 800,                                     # long, but 0 units -> no
        ("SECTION: value, and more; text. " * 30),     # long + many units -> yes
        ("FROM: a. TO: b. RE: c. BODY: d. END: e. X: f. " * 4),
        "one sentence. two sentence. three.",
        ("word " * 200),                               # 1000 chars, 0 units -> no
        ("clause, " * 60),                             # many commas + long -> yes
    ]
    rng = random.Random(0xC0FFEE)
    fuzz = []
    tokens = ["word", "SECTION:", "FROM:", ".", ",", ";", "\n", "Ab:", "A:", "value", "王小明"]
    for _ in range(200):
        n = rng.randint(0, 120)
        masked = " ".join(rng.choice(tokens) for _ in range(n))
        fuzz.append(masked)
    return curated + fuzz


def _dump(path, rows):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(rows, f, ensure_ascii=False, indent=2, sort_keys=True)
        f.write("\n")
    print(f"wrote {path} ({len(rows)} rows)")


def main():
    import unicodedata

    assert unicodedata.unidata_version == "15.0.0", (
        f"reference must be Unicode 15.0.0, got {unicodedata.unidata_version}"
    )

    leak_rows = []
    for body, vault in _leak_cases():
        leak_rows.append(
            {"body": body, "vault": vault, "expect": bool(leak_gate(body, vault))}
        )

    comp_rows = []
    for masked in _compress_cases():
        comp_rows.append({"masked": masked, "expect": bool(_should_compress(masked))})

    os.makedirs(OUT, exist_ok=True)
    _dump(os.path.join(OUT, "body_leak_gate.json"), leak_rows)
    _dump(os.path.join(OUT, "body_should_compress.json"), comp_rows)

    # sanity: emit the live VERBOSE pattern so a human can re-verify the vendored
    # de-verbosed RESIDUAL_PII constant in body_pipeline.rs.
    print("live _RESIDUAL_PII_RE.pattern (VERBOSE):", file=sys.stderr)
    print(_RESIDUAL_PII_RE.pattern, file=sys.stderr)


if __name__ == "__main__":
    main()
