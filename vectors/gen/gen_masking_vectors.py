"""Regenerate the masking/vault port's vendored Unicode tables, the vault
resolve golden, and the (opt-in) differential reference corpus — all frozen
from the SAME CPython whose `unicodedata` owns the conformance vectors.

Run against the reference interpreter (unidata_version MUST be 15.0.0, matching
the `unicode-normalization = "=0.1.22"` pin):

    PYTHONPATH=/path/to/jarvis python vectors/gen/gen_masking_vectors.py \
        --jarvis /path/to/jarvis [--ref-out /tmp/masking_ref]

Emits (byte-stable):
  crates/libsavana-ner/src/unicode_tables.rs          (WS_SET, CATEGORY, PY_ALPHA, CASEFOLD)
  crates/libsavana-ner/tests/fixtures/vault_resolve_golden.json
And, when --ref-out is given, the differential corpus for the opt-in
`tests/masking_differential.rs` harness (point MASKING_REF_DIR at it).

Guarding invariant: this file MUST NOT touch the five frozen
vectors/conformance/masking_*.json oracles — it only produces port-side
artifacts derived from them.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import re
import sys
import unicodedata
from datetime import datetime, timezone

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CRATE = os.path.join(REPO, "crates", "libsavana-ner")
MAXCP = 0x110000
BUCKET = {"keep": 0, "drop": 1, "space": 2, "nl": 3}
DROP_CATS = {"Cc", "Cf", "Cs", "Co", "Cn"}
NL_CATS = {"Zl", "Zp"}
_WS_RE = re.compile(r"\s")


def is_surr(cp: int) -> bool:
    return 0xD800 <= cp <= 0xDFFF


def require_reference_python() -> None:
    if unicodedata.unidata_version != "15.0.0":
        sys.exit(
            f"REFUSING: unidata_version={unicodedata.unidata_version}, need 15.0.0 "
            "(the version the vectors + `unicode-normalization =0.1.22` pin target)."
        )


# ── Table sources ──


def ws_set() -> list[int]:
    return [cp for cp in range(MAXCP) if not is_surr(cp) and _WS_RE.match(chr(cp))]


def category_ranges() -> list[list[int]]:
    def bucket(cp: int) -> str:
        if is_surr(cp):
            return "drop"
        cat = unicodedata.category(chr(cp))
        if cat in DROP_CATS:
            return "drop"
        if cat == "Zs":
            return "space"
        if cat in NL_CATS:
            return "nl"
        return "keep"

    out, lo, cur = [], 0, bucket(0)
    for cp in range(1, MAXCP):
        b = bucket(cp)
        if b != cur:
            out.append([lo, cp - 1, cur])
            lo, cur = cp, b
    out.append([lo, MAXCP - 1, cur])
    return out


def alpha_ranges() -> list[list[int]]:
    out, lo, cur = [], 0, chr(0).isalpha()
    for cp in range(1, MAXCP):
        a = False if is_surr(cp) else chr(cp).isalpha()
        if a != cur:
            if cur:
                out.append([lo, cp - 1])
            lo, cur = cp, a
    if cur:
        out.append([lo, MAXCP - 1])
    return out


def casefold_table() -> dict[int, list[int]]:
    cf = {}
    for cp in range(MAXCP):
        if is_surr(cp):
            continue
        f = chr(cp).casefold()
        if f != chr(cp):
            cf[cp] = [ord(c) for c in f]
    return cf


def emit_tables_rs() -> None:
    ws, cat, alpha, cf = ws_set(), category_ranges(), alpha_ranges(), casefold_table()
    L: list[str] = []
    p = L.append
    p("//! Unicode tables vendored from CPython 3.12.4 (unidata_version 15.0.0).")
    p("//!")
    p("//! GENERATED — do not edit by hand. Regenerate with")
    p("//! vectors/gen/gen_masking_vectors.py against the same CPython whose")
    p("//! `unicodedata` froze the conformance vectors. These reproduce")
    p("//! `str.casefold()` (full, length-changing), the `str.isalpha()` set, and")
    p("//! the `unicodedata.category` buckets `masking._normalize` switches on,")
    p("//! byte-exact for Unicode 15.0.0. NFKC itself comes from the")
    p("//! `unicode-normalization` crate pinned `=0.1.22` (also Unicode 15.0.0).")
    p("")
    p("/// Codepoints that Python's `re` `\\s` matches (str semantics). Note this")
    p("/// includes U+001C..U+001F, which are NOT Unicode `White_Space`.")
    p("#[rustfmt::skip]")
    p(f"pub(crate) static WS_SET: [u32; {len(ws)}] = [")
    for cp in ws:
        p(f"    0x{cp:x},")
    p("];")
    p("")
    p("/// `_normalize` category bucket per codepoint, RLE. 0=keep 1=drop 2=space")
    p("/// 3=newline. Sorted, contiguous, covers 0..=0x10FFFF. `(lo, hi, bucket)`.")
    p("#[rustfmt::skip]")
    p(f"pub(crate) static CATEGORY: [(u32, u32, u8); {len(cat)}] = [")
    for lo, hi, b in cat:
        p(f"    (0x{lo:x}, 0x{hi:x}, {BUCKET[b]}),")
    p("];")
    p("")
    p("/// Codepoints where Python `str.isalpha()` is true (general category")
    p("/// Lu/Ll/Lt/Lm/Lo). This is NARROWER than Rust `char::is_alphabetic`")
    p("/// (Alphabetic property, which also covers Nl and Other_Alphabetic marks),")
    p("/// so `_require_supported_script` must use THIS, not the std predicate.")
    p("/// Sorted, non-overlapping inclusive `(lo, hi)` ranges.")
    p("#[rustfmt::skip]")
    p(f"pub(crate) static PY_ALPHA: [(u32, u32); {len(alpha)}] = [")
    for lo, hi in alpha:
        p(f"    (0x{lo:x}, 0x{hi:x}),")
    p("];")
    p("")
    items = sorted(cf.items())
    p("/// Full case-fold map: codepoint -> folded scalar(s). Sorted by key.")
    p("/// Only codepoints whose fold differs from identity are present.")
    p("#[rustfmt::skip]")
    p(f"pub(crate) static CASEFOLD: [(u32, &[char]); {len(items)}] = [")
    for cp, folded in items:
        arr = ", ".join(f"'\\u{{{c:x}}}'" for c in folded)
        p(f"    (0x{cp:x}, &[{arr}]),")
    p("];")
    p("")
    dst = os.path.join(CRATE, "src", "unicode_tables.rs")
    open(dst, "w").write("\n".join(L))
    print(f"wrote {dst}: WS_SET {len(ws)}, CATEGORY {len(cat)}, PY_ALPHA {len(alpha)}, CASEFOLD {len(items)}")


# ── Vault resolve golden ──


def emit_vault_golden(V) -> None:
    secret = bytes(range(32))
    artifact_id, generation, mask_version = "00abcdef12", 3, V.DOC_MASK_VERSION
    vault = V.ScopedDocumentVault(
        artifact_id=artifact_id, generation=generation,
        expires_at=datetime(2999, 1, 1, tzinfo=timezone.utc),
        mask_version=mask_version, secret=secret,
    )
    puts = [("NAME", "Jane Doe"), ("NAME", "Jane Doe"),
            ("EMAIL", "jane@example.com"), ("PLACE", "Berlin"),
            ("ORG", "Straße GmbH")]
    tokens = {}
    for kind, raw in puts:
        tokens[(kind, raw)] = vault.put(kind, raw, pages=[1])
    digest = "evidence-digest-xyz"
    authorized = [tokens[("NAME", "Jane Doe")], tokens[("EMAIL", "jane@example.com")]]
    vault.authorize_evidence(digest, authorized)

    def claims(kind, counter):
        return json.dumps(
            {"artifact_id": artifact_id, "counter": counter, "generation": generation,
             "kind": kind, "mask_version": mask_version},
            sort_keys=True, separators=(",", ":"),
        )

    cases = []
    for (kind, raw), tok in tokens.items():
        m = V._TOKEN_RE.match(tok)
        _, _, _, counter, tag = m.groups()
        cases.append({"kind": kind, "raw": raw, "token": tok, "counter": int(counter),
                      "tag": tag, "claims_json": claims(kind, int(counter)),
                      "authorized": tok in authorized})

    def outcome(tok, dig):
        try:
            return {"raw": vault.resolve(tok, dig)}
        except V.DocumentVaultError as e:
            return {"code": e.code}

    good = tokens[("NAME", "Jane Doe")]
    unauth = tokens[("PLACE", "Berlin")]
    tampered = good[:-3] + ("0" if good[-3] != "0" else "1") + good[-2:]
    bad_scope = good.replace(f":{artifact_id}:", ":00abcdef99:")
    golden = {
        "secret_hex": secret.hex(), "artifact_id": artifact_id,
        "generation": generation, "mask_version": mask_version, "digest": digest,
        "cases": cases,
        "resolve": [
            {"desc": "authorized", "token": good, "digest": digest, "out": outcome(good, digest)},
            {"desc": "unauthorized_token", "token": unauth, "digest": digest, "out": outcome(unauth, digest)},
            {"desc": "wrong_digest", "token": good, "digest": "nope", "out": outcome(good, "nope")},
            {"desc": "tampered_tag", "token": tampered, "digest": digest, "out": outcome(tampered, digest)},
            {"desc": "wrong_scope", "token": bad_scope, "digest": digest, "out": outcome(bad_scope, digest)},
            {"desc": "garbage", "token": "[[not a token]]", "digest": digest, "out": outcome("[[not a token]]", digest)},
        ],
    }
    dst = os.path.join(CRATE, "tests", "fixtures", "vault_resolve_golden.json")
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    json.dump(golden, open(dst, "w"), indent=1)
    print(f"wrote {dst}: {len(cases)} cases, {len(golden['resolve'])} resolve outcomes")


# ── Differential reference corpus (opt-in; not vendored) ──


def emit_ref(M, out: str) -> None:
    os.makedirs(out, exist_ok=True)
    json.dump({int(k): v for k, v in casefold_table().items()}, open(f"{out}/casefold.json", "w"))
    nfkc = {}
    for cp in range(MAXCP):
        if is_surr(cp):
            continue
        o = unicodedata.normalize("NFKC", chr(cp))
        if o != chr(cp):
            nfkc[cp] = [ord(c) for c in o]
    json.dump(nfkc, open(f"{out}/nfkc_diff.json", "w"))

    random.seed(1234)
    strings = ["a\x1c\x1d\x1e\x1fb", "Straße", "STRASSE", "ｆｕｌｌｗｉｄｔｈ NBSP",
               "zero​width", "tab\tsep", "line sep", "汉字passthrough",
               "  spaced   run  ", "a\x1c b", "plain", "İstanbul", "ẞXX", "ǰabc",
               "grüße  \tGRAND", "Ångström", "ﬀ ligature", "café́", "\U0001d400\U0001d401 math"]
    pool = []
    for lo, hi in [(0x20, 0x7f), (0x80, 0x2ff), (0x300, 0x36f), (0x1e00, 0x1fff),
                   (0x2000, 0x206f), (0xfb00, 0xfb4f), (0xff00, 0xffef),
                   (0x4e00, 0x4f00), (0x1d400, 0x1d500), (0x2f800, 0x2f820)]:
        pool += [cp for cp in range(lo, hi) if not is_surr(cp)]
    for _ in range(4000):
        strings.append("".join(chr(random.choice(pool)) for _ in range(random.randint(0, 14))))
    marks = [0x300, 0x301, 0x302, 0x303, 0x304, 0x307, 0x308, 0x30c, 0x323, 0x327,
             0x328, 0x316, 0x1dc0, 0x35c, 0x345]
    bases = [ord("a"), ord("e"), ord("o"), ord("s"), 0x3b1, 0x1e00, 0xc5]
    for _ in range(6000):
        seq = [random.choice(bases)] + [random.choice(marks) for _ in range(random.randint(2, 5))]
        strings.append("".join(chr(c) for c in seq))

    corpus = []
    for s in strings:
        norm = M._normalize(s)
        folded, fs, fe = M._folded_scan_map(s)
        cp_form, cf_form = M._canonical_forms(s)
        corpus.append({"in": [ord(c) for c in s],
                       "normalize": [ord(c) for c in norm],
                       "fsm": [folded, list(fs), list(fe)],
                       "canon": [cp_form, cf_form]})
    json.dump(corpus, open(f"{out}/corpus.json", "w"))

    # leak-gate + supported-script fuzz
    random.seed(99)
    frags = ["call 415-555-0199", "+1 (212) 555 0123", "13800138000",
             "jane.doe@example.com", "192.168.0.1", "4111 1111 1111 1111",
             "SSN 078-05-1120", "GB29NWBK60161331926819", "AB123456",
             "١٢٣-٤٥-٦٧٨٩",
             "[[jarvis-doc:x]]", "no pii here", "汉字 text", "тест", "id 1234567"]

    def rand_token():
        aid = "".join(random.choice("0123456789abcdef") for _ in range(random.choice([8, 16, 40])))
        tag = "".join(random.choice("0123456789abcdef") for _ in range(16))
        return f"[[JARVIS-DOC:{aid}:{random.randint(1,999)}:NAME:{random.randint(1,99)}:{tag}]]"

    leak = []
    samples = list(frags)
    for _ in range(6000):
        parts = []
        for _ in range(random.randint(0, 4)):
            r = random.random()
            if r < 0.4:
                parts.append(random.choice(frags))
            elif r < 0.55:
                parts.append(rand_token())
            else:
                parts.append("".join(random.choice("0123456789 -+().@") for _ in range(random.randint(1, 20))))
        samples.append(random.choice([" ", "", "\t"]).join(parts))
    for s in samples:
        leak.append({"in": [ord(c) for c in s], "clean": M.masked_text_is_clean(s)})
    json.dump(leak, open(f"{out}/leak_fuzz.json", "w"))

    scr = []
    spool = list(range(0x20, 0x500)) + list(range(0x4e00, 0x4f00)) + list(range(0x2150, 0x2200))
    spool = [c for c in spool if not is_surr(c)]
    for _ in range(4000):
        s = "".join(chr(c) for c in random.choices(spool, k=random.randint(0, 10)))
        try:
            M._require_supported_script(s)
            ok = True
        except Exception:
            ok = False
        scr.append({"in": [ord(c) for c in s], "ok": ok})
    json.dump(scr, open(f"{out}/script_fuzz.json", "w"))
    print(f"wrote differential ref -> {out}: corpus {len(corpus)}, leak {len(leak)}, script {len(scr)}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--jarvis", required=True, help="path to the jarvis repo (for PYTHONPATH)")
    ap.add_argument("--ref-out", default=None, help="dir for the opt-in differential corpus")
    args = ap.parse_args()
    sys.path.insert(0, args.jarvis)
    require_reference_python()
    from server.documents import masking as M
    from server.documents import scoped_vault as V

    emit_tables_rs()
    emit_vault_golden(V)
    if args.ref_out:
        emit_ref(M, args.ref_out)


if __name__ == "__main__":
    main()
