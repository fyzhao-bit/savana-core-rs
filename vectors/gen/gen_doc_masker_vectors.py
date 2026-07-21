"""Freeze byte-exact oracle vectors for the Rust `doc_masker` port.

Runs the LIVE Python `StrictDocumentMasker.mask_pages` (the real orchestration
in `server/documents/masking.py`) over representative multi-page artifacts and
freezes, per case, the exact `{masked_pages, chunks, vault token->raw}` — or the
stable error code the pipeline raised.

The NER backend is a DETERMINISTIC injected detector (a per-case surface->kind
dictionary), NOT the ONNX model: the real strict NER is proven byte-exact
against Python separately (slice-1 + the live NER differential), and injecting a
deterministic detector makes THIS proof — the 2-phase reconciliation, the
windowing offset math, the cross-page seam split, and the authenticated vault
mint — fully reproducible and model-free. The masker ORCHESTRATION exercised
here is 100% the real live code path; only the entity source is swapped, exactly
as `StrictDocumentMasker`'s `ner_detector` injection point intends. The detector
algorithm below is mirrored EXACTLY by the Rust test's `DictDetector`.

Run against the reference interpreter (unidata_version MUST be 15.0.0):

    PYTHONPATH=/path/to/jarvis /tmp/civenv/bin/python \
        vectors/gen/gen_doc_masker_vectors.py --jarvis /path/to/jarvis

Emits: crates/libsavana-ner/../../vectors/conformance/doc_masker.json
"""

from __future__ import annotations

import argparse
import json
import os
import random
import sys
from datetime import datetime, timezone

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Fixed vault scope + secret, frozen into the vectors so the Rust side mints the
# byte-identical HMAC tags. (Same construction the vault_resolve golden uses.)
SECRET = bytes(range(32))
ARTIFACT_ID = "00abcdef12"
GENERATION = 3


def build_detector(pairs):
    """The deterministic injected NER stub — mirrored EXACTLY by Rust.

    For each (surface, kind) in `pairs` (declaration order preserved), find every
    NON-OVERLAPPING occurrence of `surface` in the given text (Python str.find →
    CHAR offsets), left to right. Collect all entities across all pairs, then
    STABLE-sort by start offset (ties keep declaration/scan order). Overlapping
    surfaces across different pairs (e.g. "Alice" and "Alice Wang") are allowed —
    `_merge_spans` is what resolves them, which is exactly what we want to test.
    """
    from server.security.ner_gate import Entity

    def det(text):
        out = []
        for surface, kind in pairs:
            start = 0
            while True:
                i = text.find(surface, start)
                if i < 0:
                    break
                out.append(Entity(type=kind, text=surface, start=i, end=i + len(surface)))
                start = i + len(surface)
        out.sort(key=lambda e: e.start)
        return out

    return det


def make_pages(RawPage, Observation, spec):
    pages = []
    for p in spec:
        obs = tuple(
            Observation(text=o[0], x=0.0, y=0.0, confidence=o[1])
            for o in p.get("obs", [])
        )
        pages.append(
            RawPage(
                page_number=p["page_number"],
                source=p.get("source", "text_layer"),
                text=p["text"],
                observations=obs,
                pixel_count=0,
            )
        )
    return pages


def run_case(M, V, RawPage, Observation, case):
    detector = build_detector(case.get("dict", []))
    masker = M.StrictDocumentMasker(ner_detector=detector)
    vault = V.ScopedDocumentVault(
        artifact_id=ARTIFACT_ID,
        generation=GENERATION,
        expires_at=datetime(2999, 1, 1, tzinfo=timezone.utc),
        mask_version=V.DOC_MASK_VERSION,
        secret=SECRET,
    )

    class Art:
        artifact_id = ARTIFACT_ID
        generation = GENERATION

    pages = make_pages(RawPage, Observation, case["pages"])
    try:
        doc = masker.mask_pages(Art(), pages, vault)
    except M.DocumentMaskError as exc:
        return {"raises": exc.code}

    return {
        "ok": {
            "pages": [[p.page_number, p.masked_text] for p in doc.pages],
            "chunks": [
                [c.chunk_id, c.page_start, c.page_end, c.masked_text]
                for c in doc.chunks
            ],
            "vault": [[tok, vault._entries[tok].raw] for tok in vault.issued_tokens],
        }
    }


def cases():
    long_entity = "Q" * 129  # exceeds MAX_SUPPORTED_ENTITY_SPAN_CHARS (128)
    return [
        # 1 — EN multi-page: structured email + CN phone, repeated NAME "Bob"
        # detected on p1 and SWEPT onto p2 (mask once -> mask everywhere).
        {
            "name": "en_multipage_sweep",
            "dict": [["Alice Wang", "NAME"], ["Bob", "NAME"], ["Berlin", "PLACE"]],
            "pages": [
                {"page_number": 1, "text": "Contact Alice Wang at jane@example.com. Bob lives in Berlin."},
                {"page_number": 2, "text": "Bob again. Call 13800138000 now."},
            ],
        },
        # 2 — Chinese: ZH name entity + CN national-ID structured pattern.
        {
            "name": "zh_page",
            "dict": [["王小明", "NAME"], ["北京", "PLACE"]],
            "pages": [
                {"page_number": 1, "text": "王小明住在北京，电话13800138000。身份证110101199003072316。"},
            ],
        },
        # 3 — Mixed EN + ZH on one page.
        {
            "name": "mixed_en_zh",
            "dict": [["李雷", "NAME"], ["Shanghai", "PLACE"], ["Acme", "ORG"]],
            "pages": [
                {"page_number": 1, "text": "李雷 works at Acme in Shanghai. Reach him: li@acme.cn"},
            ],
        },
        # 4 — Cross-page seam entity: "Alice Wang" straddles the page break; each
        # page alone never sees it whole, only the joined 256-char seam does.
        {
            "name": "cross_page_seam",
            "dict": [["Alice Wang", "NAME"]],
            "pages": [
                {"page_number": 1, "text": "The meeting notes mention Dr. Alice"},
                {"page_number": 2, "text": " Wang who chaired the review board."},
            ],
        },
        # 5 — Structured PII variety: SSN, IBAN, national id, IP, bank card.
        {
            "name": "structured_variety",
            "dict": [],
            "pages": [
                {"page_number": 1, "text": "SSN 078-05-1120, IBAN GB29NWBK60161331926819, id AB1234567, ip 192.168.0.1, card 4111 1111 1111 1111."},
            ],
        },
        # 6 — Overlap resolution: detector returns both "Alice" and "Alice Wang"
        # at the same start; the LONGER span must win in _merge_spans.
        {
            "name": "overlap_longer_wins",
            "dict": [["Alice", "MISC"], ["Alice Wang", "NAME"]],
            "pages": [
                {"page_number": 1, "text": "Hello Alice Wang, welcome."},
            ],
        },
        # 7 — Length-changing folded sweep: "Straße" vaulted on p1; "STRASSE" on
        # p2 folds to the same canonical form so the active sweep MASKS it (but
        # mints a distinct token, since dedup is by exact (kind, raw)).
        {
            "name": "casefold_sweep_sharp_s",
            "dict": [["Straße", "ORG"]],
            "pages": [
                {"page_number": 1, "text": "Employer: Straße GmbH is the firm."},
                {"page_number": 2, "text": "Later the report writes STRASSE in caps."},
            ],
        },
        # 8 — OCR confidence gate PASS: 5 nonblank obs, exactly 1 below 0.30 (20%,
        # not > 20%); the low-confidence run is dropped from the rebuilt text.
        {
            "name": "ocr_gate_pass",
            "dict": [["Alice Wang", "NAME"]],
            "pages": [
                {
                    "page_number": 1,
                    "source": "ocr",
                    "text": "ignored raw text",
                    "obs": [
                        ["Contact Alice Wang", 1.0],
                        ["at the front desk", 0.5],
                        ["garbled lowconf run", 0.2],
                        ["second floor", 0.3],
                        ["room seven", 1.0],
                    ],
                },
            ],
        },
        # 9 — Repeated entity everywhere: one token reused across three pages.
        {
            "name": "repeated_entity_one_token",
            "dict": [["Bob", "NAME"]],
            "pages": [
                {"page_number": 1, "text": "Bob started the project."},
                {"page_number": 2, "text": "Then Bob paused it."},
                {"page_number": 3, "text": "Finally Bob shipped it, thanks Bob."},
            ],
        },
        # 10 — Leak-gate exercised over structured PII + a vault value: masks,
        # then the residual scan runs in earnest and PASSES.
        {
            "name": "leak_gate_exercised",
            "dict": [["Jane Roe", "NAME"]],
            "pages": [
                {"page_number": 1, "text": "Jane Roe email jane.roe@corp.example, phone +1 212 555 0123, again Jane Roe."},
            ],
        },
        # 11 — ERROR: unsupported script (Cyrillic letter) → UNSUPPORTED_DOCUMENT_LANGUAGE.
        {
            "name": "err_unsupported_script",
            "dict": [],
            "pages": [
                {"page_number": 1, "text": "Contact Привет office today."},
            ],
        },
        # 12 — ERROR: OCR low confidence (2 of 5 nonblank below 0.30 = 40% > 20%).
        {
            "name": "err_ocr_low_confidence",
            "dict": [],
            "pages": [
                {
                    "page_number": 1,
                    "source": "ocr",
                    "text": "raw",
                    "obs": [
                        ["good line one", 1.0],
                        ["good line two", 0.5],
                        ["bad line a", 0.1],
                        ["bad line b", 0.2],
                        ["good line three", 0.3],
                    ],
                },
            ],
        },
        # 13 — ERROR: NER span exceeds MAX_SUPPORTED_ENTITY_SPAN_CHARS → boundary.
        {
            "name": "err_span_cap",
            "dict": [[long_entity, "NAME"]],
            "pages": [
                {"page_number": 1, "text": "prefix " + long_entity + " suffix"},
            ],
        },
        # 14 — ERROR: structured span touching a TRUNCATED cross-page seam edge is
        # ambiguous → boundary. A 300-digit run on p1 reaches the truncated tail.
        {
            "name": "err_seam_ambiguous",
            "dict": [],
            "pages": [
                {"page_number": 1, "text": "1" * 300},
                {"page_number": 2, "text": "1111111111 rest of the second page text."},
            ],
        },
        # 15 — Whitespace-only detected span is skipped (never vaulted/masked).
        {
            "name": "whitespace_span_skipped",
            "dict": [["   ", "NAME"], ["Bob", "NAME"]],
            "pages": [
                {"page_number": 1, "text": "Meet Bob   here soon."},
            ],
        },
        # 16 — Source-authored token lookalike is escaped BEFORE detection, so it
        # gains no vault authority; a real minted token appears alongside it.
        {
            "name": "lookalike_escaped",
            "dict": [["Bob", "NAME"]],
            "pages": [
                {"page_number": 1, "text": "Fake [[JARVIS-DOC:deadbeef:1:NAME:1:0000000000000000]] and real Bob."},
            ],
        },
    ]


# ── Randomized fuzz corpus (opt-in; not vendored, like masking_differential) ──

# Structured-PII fragments the detector never sees but the regex layer must find
# at byte-exact CHAR offsets even behind non-ASCII prefixes.
_PII_FRAGS = [
    "jane.doe@example.com",
    "a_b+c%d@sub.mail-host.org",
    "078-05-1120",
    "GB29NWBK60161331926819",
    "AB1234567",
    "13800138000",
    "+1 212 555 0123",
    "(020) 7946 0018",
    "192.168.0.1",
    "110101199003072316",
    "4111 1111 1111 1111",
    "1234567",
]
# A mix that stresses non-ASCII byte offsets (Latin-1 accents + Han), allowed
# letters, digits, punctuation, whitespace, and token-lookalike bait.
_ALPHABET = list("abcdefghijklmnop  ETABLR .,;\n0123456789") + [
    "é", "ü", "ñ", "ø", "Å", "王", "小", "明", "北", "京", "李", "雷",
]
_HAN_NAMES = ["王小明", "李雷", "北京", "上海", "张伟"]


def _rand_text(rng, min_len, max_len):
    n = rng.randint(min_len, max_len)
    parts = []
    while sum(len(p) for p in parts) < n:
        r = rng.random()
        if r < 0.18:
            parts.append(rng.choice(_PII_FRAGS))
        elif r < 0.24:
            parts.append(rng.choice(_HAN_NAMES))
        elif r < 0.27:
            parts.append("[[jarvis" + rng.choice([" ", "", "-DOC"]))
        else:
            parts.append("".join(rng.choice(_ALPHABET) for _ in range(rng.randint(1, 8))))
    return "".join(parts)[:max_len]


def _rand_dict(rng, pages_text):
    """Surfaces drawn from real substrings of the pages (so the detector finds
    them at real offsets) plus fixed Han names, occasionally a >128-char surface
    (span-cap raise) and a seam-straddling surface."""
    pairs = []
    joined = "\n".join(pages_text)
    kinds = ["NAME", "PLACE", "ORG", "MISC", "TIME"]
    for _ in range(rng.randint(0, 4)):
        if len(joined) < 2:
            break
        a = rng.randint(0, len(joined) - 1)
        b = min(len(joined), a + rng.randint(1, 12))
        surf = joined[a:b].strip("\n")
        if surf:
            pairs.append([surf, rng.choice(kinds)])
    if rng.random() < 0.3:
        pairs.append([rng.choice(_HAN_NAMES), "NAME"])
    # Seam-straddling surface: tail of page i + head of page i+1.
    if len(pages_text) >= 2 and rng.random() < 0.25:
        i = rng.randrange(len(pages_text) - 1)
        left, right = pages_text[i], pages_text[i + 1]
        if left and right:
            surf = left[-rng.randint(1, 6):] + right[: rng.randint(1, 6)]
            surf = surf.strip("\n")
            if 0 < len(surf) <= 60:
                pairs.append([surf, "NAME"])
    if rng.random() < 0.05:
        pairs.append(["Z" * rng.randint(129, 160), "NAME"])
    rng.shuffle(pairs)
    return pairs


def fuzz_cases(rng, count):
    out = []
    for _ in range(count):
        n_pages = rng.randint(1, 4)
        pages_text = []
        for _ in range(n_pages):
            if rng.random() < 0.06:  # occasional large page → multi-window NER
                template = _rand_text(rng, 40, 120)
                pages_text.append((template + " ") * rng.randint(35, 45))
            else:
                pages_text.append(_rand_text(rng, 0, 400))
        if rng.random() < 0.04:  # rare disallowed letter → unsupported raise
            pages_text[rng.randrange(n_pages)] += "Привет"
        pairs = _rand_dict(rng, pages_text)
        pages = [
            {"page_number": i + 1, "source": "text_layer", "text": t}
            for i, t in enumerate(pages_text)
        ]
        out.append({"name": f"fuzz_{len(out)}", "dict": pairs, "pages": pages})
    return out


def emit_fuzz(M, V, RawPage, Observation, out_dir, count, seed):
    os.makedirs(out_dir, exist_ok=True)
    rng = random.Random(seed)
    rows = []
    n_ok = n_err = 0
    for case in fuzz_cases(rng, count):
        result = run_case(M, V, RawPage, Observation, case)
        if "ok" in result:
            n_ok += 1
        else:
            n_err += 1
        rows.append({"name": case["name"], "dict": case["dict"], "pages": case["pages"], "expect": result})
    payload = {
        "secret_hex": SECRET.hex(),
        "artifact_id": ARTIFACT_ID,
        "generation": GENERATION,
        "mask_version": V.DOC_MASK_VERSION,
        "cases": rows,
    }
    dst = os.path.join(out_dir, "doc_masker_fuzz.json")
    with open(dst, "w") as fh:
        json.dump(payload, fh, ensure_ascii=False)
    print(f"wrote {dst}: {len(rows)} fuzz cases ({n_ok} ok, {n_err} raises), seed={seed}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--jarvis", required=True)
    ap.add_argument("--fuzz-out", default=None, help="dir for the opt-in fuzz corpus")
    ap.add_argument("--fuzz-count", type=int, default=800)
    ap.add_argument("--fuzz-seed", type=int, default=20260721)
    args = ap.parse_args()
    sys.path.insert(0, args.jarvis)

    import unicodedata

    if unicodedata.unidata_version != "15.0.0":
        sys.exit(f"REFUSING: unidata_version={unicodedata.unidata_version}, need 15.0.0")

    from server.documents import masking as M
    from server.documents import scoped_vault as V
    from server.documents.pdf_worker import RawPage, Observation

    out = {
        "secret_hex": SECRET.hex(),
        "artifact_id": ARTIFACT_ID,
        "generation": GENERATION,
        "mask_version": V.DOC_MASK_VERSION,
        "cases": [],
    }
    for case in cases():
        result = run_case(M, V, RawPage, Observation, case)
        out["cases"].append(
            {
                "name": case["name"],
                "dict": case.get("dict", []),
                "pages": case["pages"],
                "expect": result,
            }
        )

    dst = os.path.join(REPO, "vectors", "conformance", "doc_masker.json")
    with open(dst, "w") as fh:
        json.dump(out, fh, ensure_ascii=False, indent=1)
        fh.write("\n")
    n_ok = sum(1 for c in out["cases"] if "ok" in c["expect"])
    n_err = sum(1 for c in out["cases"] if "raises" in c["expect"])
    print(f"wrote {dst}: {len(out['cases'])} cases ({n_ok} ok, {n_err} raises)")

    if args.fuzz_out:
        emit_fuzz(M, V, RawPage, Observation, args.fuzz_out, args.fuzz_count, args.fuzz_seed)


if __name__ == "__main__":
    main()
