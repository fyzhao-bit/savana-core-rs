//! Byte-exact port of the fidelity-critical core of
//! `server/documents/masking.py` — the NFKC/casefold/offset-map primitives the
//! whole strict masker is built on.
//!
//! Coordinate-space contract (design §10): detection, replacement and residual
//! scanning all happen in ONE normalized space, so there is no byte back-map.
//! The two spaces that must reproduce CPython exactly are:
//!   * `normalize`  — `unicodedata.normalize("NFKC", …)` + control/zero-width
//!     removal + whitespace unification (`masking._normalize`).
//!   * `folded_scan_map` — `\s+`-run collapse + `.strip()` + FULL `.casefold()`
//!     with a per-folded-char origin-offset map back into the raw string
//!     (`masking._folded_scan_map`), the space the "mask once → mask
//!     everywhere" sweep runs in.
//!
//! Byte-exactness rests on three version-locked Unicode facts, all pinned to
//! the CPython (3.12.4 / unidata_version 15.0.0) that froze the vectors:
//!   * NFKC  → `unicode-normalization` crate pinned `=0.1.22` (Unicode 15.0.0).
//!   * casefold + category → tables vendored in `unicode_tables.rs`.
//!   * `\s`  → Python `re` str semantics (WS_SET), which is NOT `White_Space`.

use crate::unicode_tables::{CASEFOLD, CATEGORY, PY_ALPHA, WS_SET};
use std::cmp::Ordering;
use std::sync::OnceLock;
use unicode_normalization::UnicodeNormalization;

/// A masking refusal carrying only a stable code — never raw text (mirrors
/// `DocumentMaskError` / `models.CODE_*`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaskError {
    pub code: &'static str,
}

pub const CODE_MASK_BOUNDARY_FAILED: &str = "MASK_BOUNDARY_FAILED";
pub const CODE_UNSUPPORTED_DOCUMENT_LANGUAGE: &str = "UNSUPPORTED_DOCUMENT_LANGUAGE";

/// The `[[JARVIS-DOC:…]]` / `[[JARVIS-DOC-QUERY:…]]` scan grammars
/// (`masking._TOKEN_SCAN_RE` / `_QUERY_TOKEN_SCAN_RE`, masking.py:195-202).
/// Exposed as the single source of truth so `facts` (which strips/blanks these
/// exact shapes before pattern-matching) cannot silently drift from what the
/// leak gate below scans for — mirroring how `facts.py` imports
/// `masking.DOC_TOKEN_RE`/`QUERY_TOKEN_RE`.
pub const DOC_TOKEN_PATTERN: &str =
    r"\[\[JARVIS-DOC:[0-9a-f]{8,64}:\d{1,9}:[A-Z][A-Z0-9_]{0,31}:\d{1,9}:[0-9a-f]{16}\]\]";
pub const QUERY_TOKEN_PATTERN: &str = r"\[\[JARVIS-DOC-QUERY:[A-Z][A-Z0-9_]{0,31}:\d{1,9}\]\]";

impl MaskError {
    fn boundary() -> Self {
        MaskError {
            code: CODE_MASK_BOUNDARY_FAILED,
        }
    }
}

// ── Unicode primitives (byte-exact vs CPython 15.0.0) ──

/// True iff Python's `re` `\s` matches `c` (str semantics). WS_SET is the exact
/// enumerated set — it includes U+001C..U+001F, which `char::is_whitespace`
/// (Unicode `White_Space`) does NOT, so we must not use the std predicate.
#[inline]
fn is_ws(c: char) -> bool {
    WS_SET.binary_search(&(c as u32)).is_ok()
}

/// `_normalize` category bucket: 0=keep 1=drop 2=space 3=newline. CATEGORY is a
/// sorted, contiguous, gap-free RLE cover of 0..=0x10FFFF, so the last range
/// whose `lo <= cp` is the hit.
#[inline]
fn category_bucket(c: char) -> u8 {
    let cp = c as u32;
    let idx = match CATEGORY.binary_search_by(|&(lo, _, _)| lo.cmp(&cp)) {
        Ok(i) => i,
        Err(i) => i - 1, // CATEGORY[0].0 == 0, so cp>=0 always lands in a range
    };
    CATEGORY[idx].2
}

/// Push the FULL case fold of `c` onto `out` (may be 0<n chars; length-changing,
/// e.g. ß→ss, İ→i̇). Codepoints absent from CASEFOLD fold to themselves.
#[inline]
fn casefold_into(c: char, out: &mut String) {
    match CASEFOLD.binary_search_by(|&(cp, _)| cp.cmp(&(c as u32))) {
        Ok(i) => out.extend(CASEFOLD[i].1.iter().copied()),
        Err(_) => out.push(c),
    }
}

/// FULL case fold of a whole string — the `str.casefold()` equivalent.
pub fn casefold(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        casefold_into(c, &mut out);
    }
    out
}

// ── masking._normalize ──

/// Port of `masking._normalize`: NFKC, then drop control/format/surrogate/
/// private/unassigned (categories C*), map `Zs`→space and `Zl`/`Zp`→newline,
/// with `\n` preserved and `\t`→space special-cased before the category switch.
pub fn normalize(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.nfkc() {
        if c == '\n' {
            out.push('\n');
        } else if c == '\t' {
            out.push(' ');
        } else {
            match category_bucket(c) {
                0 => out.push(c),
                2 => out.push(' '),
                3 => out.push('\n'),
                _ => {} // 1 => drop
            }
        }
    }
    out
}

// ── scoped_vault.canonical_scan_forms ──

/// Collapse every maximal `\s`-run to a single space (mirrors
/// `_WS_RUN_RE.sub(" ", text)`), returned as a char vector for char-offset work.
fn collapse_ws(chars: &[char]) -> Vec<char> {
    let mut collapsed = Vec::with_capacity(chars.len());
    let mut i = 0;
    while i < chars.len() {
        if is_ws(chars[i]) {
            while i < chars.len() && is_ws(chars[i]) {
                i += 1;
            }
            collapsed.push(' ');
        } else {
            collapsed.push(chars[i]);
            i += 1;
        }
    }
    collapsed
}

/// Trim leading/trailing collapsed spaces (mirrors `.strip()` after collapse,
/// where the only remaining whitespace is single U+0020). Returns `[lo, hi)`.
fn strip_bounds(collapsed: &[char]) -> (usize, usize) {
    let mut lo = 0;
    let mut hi = collapsed.len();
    while lo < hi && collapsed[lo] == ' ' {
        lo += 1;
    }
    while hi > lo && collapsed[hi - 1] == ' ' {
        hi -= 1;
    }
    (lo, hi)
}

/// Port of `scoped_vault.canonical_scan_forms`: `(case-preserved, casefolded)`
/// whitespace-collapsed canonical forms. The vault folds every raw value with
/// this at `put()` time and the scanner folds scanned text with it, so the two
/// sides can never drift.
pub fn canonical_scan_forms(text: &str) -> (String, String) {
    let chars: Vec<char> = text.chars().collect();
    let collapsed = collapse_ws(&chars);
    let (lo, hi) = strip_bounds(&collapsed);
    let case_preserved: String = collapsed[lo..hi].iter().collect();
    let folded = casefold(&case_preserved);
    (case_preserved, folded)
}

// ── masking._folded_scan_map ──

/// Port of `masking._folded_scan_map`. Returns the casefolded canonical form
/// plus, for each folded-char index, the `[start, end)` **char** offsets in the
/// ORIGINAL `text` that produced it — so a hit in folded space maps back to the
/// exact raw substring even across length-changing folds (ß→ss) and whitespace
/// collapse. Fail-closed: if the reconstructed fold ≠ `canonical_scan_forms`'s
/// casefolded form, returns `MASK_BOUNDARY_FAILED` rather than under-masking.
#[allow(clippy::type_complexity)]
pub fn folded_scan_map(text: &str) -> Result<(String, Vec<usize>, Vec<usize>), MaskError> {
    let chars: Vec<char> = text.chars().collect();

    // Stage A — collapse each whitespace run to one space, recording origins.
    let mut collapsed: Vec<char> = Vec::with_capacity(chars.len());
    let mut starts: Vec<usize> = Vec::with_capacity(chars.len());
    let mut ends: Vec<usize> = Vec::with_capacity(chars.len());
    let mut i = 0;
    while i < chars.len() {
        if is_ws(chars[i]) {
            let run_start = i;
            while i < chars.len() && is_ws(chars[i]) {
                i += 1;
            }
            collapsed.push(' ');
            starts.push(run_start);
            ends.push(i);
        } else {
            collapsed.push(chars[i]);
            starts.push(i);
            ends.push(i + 1);
            i += 1;
        }
    }

    // Mirror `.strip()`: drop leading/trailing collapsed spaces.
    let (lo, hi) = strip_bounds(&collapsed);

    // Stage B — casefold each surviving char (may expand), carrying its origin
    // extent onto every folded char it produces.
    let mut folded = String::new();
    let mut f_start: Vec<usize> = Vec::new();
    let mut f_end: Vec<usize> = Vec::new();
    let mut tmp = String::new();
    for idx in lo..hi {
        tmp.clear();
        casefold_into(collapsed[idx], &mut tmp);
        for fc in tmp.chars() {
            folded.push(fc);
            f_start.push(starts[idx]);
            f_end.push(ends[idx]);
        }
    }

    // Fail-closed guard: the sweep space must equal the scan's canonical form.
    if folded != canonical_scan_forms(text).1 {
        return Err(MaskError::boundary());
    }
    Ok((folded, f_start, f_end))
}

// ── masking._require_supported_script ──

/// True iff Python `str.isalpha()` is true for `c` (categories Lu/Ll/Lt/Lm/Lo).
/// NOT `char::is_alphabetic` (Alphabetic property, broader — Nl, combining
/// Other_Alphabetic marks) — matching Python is what keeps the script gate
/// byte-exact. Table vendored from CPython 15.0.0.
pub fn is_py_alpha(c: char) -> bool {
    let cp = c as u32;
    PY_ALPHA
        .binary_search_by(|&(lo, hi)| {
            if cp < lo {
                Ordering::Greater
            } else if cp > hi {
                Ordering::Less
            } else {
                Ordering::Equal
            }
        })
        .is_ok()
}

/// Letter ranges the cloud path supports, checked post-NFKC (Latin + Han) —
/// `masking._ALLOWED_LETTER_RANGES`.
static ALLOWED_LETTER_RANGES: [(u32, u32); 15] = [
    (0x0041, 0x005A),
    (0x0061, 0x007A), // ASCII Latin
    (0x00C0, 0x02AF), // Latin-1/Ext-A/Ext-B/IPA
    (0x1E00, 0x1EFF), // Latin Extended Additional
    (0x2C60, 0x2C7F),
    (0xA720, 0xA7FF), // Latin Extended-C/D
    (0x3005, 0x3007), // 々〆〇
    (0x3400, 0x4DBF),
    (0x4E00, 0x9FFF), // Han
    (0xF900, 0xFAFF), // Han compatibility
    (0x20000, 0x2A6DF),
    (0x2A700, 0x2B73F), // Han extensions
    (0x2B740, 0x2B81F),
    (0x2B820, 0x2CEAF),
    (0x2F800, 0x2FA1F),
];

/// Port of `masking._require_supported_script`: reject any letter (Python
/// `isalpha` sense) outside the Latin+Han allow-list — the cloud path serves
/// English/Chinese only. Non-letters (digits, punctuation, symbols) pass.
pub fn require_supported_script(text: &str) -> Result<(), MaskError> {
    for c in text.chars() {
        if !is_py_alpha(c) {
            continue;
        }
        let cp = c as u32;
        if ALLOWED_LETTER_RANGES
            .iter()
            .any(|&(lo, hi)| lo <= cp && cp <= hi)
        {
            continue;
        }
        return Err(MaskError {
            code: CODE_UNSUPPORTED_DOCUMENT_LANGUAGE,
        });
    }
    Ok(())
}

// ── Leak gate: masking.masked_text_is_clean ──

/// Object-replacement char (`masking._TOKEN_STAND_IN`, U+FFFC): stands in for a
/// stripped token so removal can never glue two digit runs into a new match.
const TOKEN_STAND_IN: &str = "\u{fffc}";

/// One structured-PII pattern. `regex` (linear, RE2-style) covers 10 of 11;
/// the inline PHONE pattern's negative lookBEHIND + lookahead cannot be
/// expressed in a finite-automaton engine, so it is FLAGGED and delegated to
/// the backtracking `fancy-regex` engine (see `Structured::PHONE_LOOKAROUND`).
enum PatEngine {
    /// RE2-style — no backtracking, no lookaround/backrefs.
    Re(regex::Regex),
    /// FLAGGED lookaround exception: negative lookbehind AND lookahead.
    Fancy(fancy_regex::Regex),
}

impl PatEngine {
    fn is_match(&self, s: &str) -> bool {
        match self {
            PatEngine::Re(r) => r.is_match(s),
            // Fail CLOSED: a fancy-regex runtime error (e.g. a backtrack-limit
            // hit on adversarial input) counts as a hit, so the gate can only
            // ever OVER-report residual PII, never miss it.
            PatEngine::Fancy(r) => r.is_match(s).unwrap_or(true),
        }
    }
}

struct LeakPatterns {
    structured: Vec<(&'static str, PatEngine)>,
    lookalike_scan: regex::Regex,
    lookalike_source: regex::Regex,
    token_scan: regex::Regex,
    query_token_scan: regex::Regex,
}

fn patterns() -> &'static LeakPatterns {
    static P: OnceLock<LeakPatterns> = OnceLock::new();
    P.get_or_init(|| {
        let re = |p: &str| regex::Regex::new(p).expect("static pattern compiles");
        LeakPatterns {
            structured: vec![
                // slm_gate._RE_EMAIL
                ("EMAIL", PatEngine::Re(re(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"))),
                // slm_gate._RE_CC
                ("BANK_CARD", PatEngine::Re(re(r"\b(?:\d[ -]*?){13,19}\b"))),
                // slm_gate._RE_CN_ID
                ("CN_ID", PatEngine::Re(re(
                    r"[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]",
                ))),
                ("SSN", PatEngine::Re(re(r"\b\d{3}-\d{2}-\d{4}\b"))),
                ("IBAN", PatEngine::Re(re(r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b"))),
                ("NATIONAL_ID", PatEngine::Re(re(r"\b[A-Z]{1,2}\d{6,9}\b"))),
                // slm_gate._RE_PHONE_CN — kind "PHONE" (masking._STRUCTURED_PATTERNS).
                ("PHONE", PatEngine::Re(re(r"1[3-9]\d{9}"))),
                // FLAGGED: masking.py inline PHONE — negative lookbehind + lookahead.
                ("PHONE", PatEngine::Fancy(
                    fancy_regex::Regex::new(r"(?<![0-9A-Za-z])(?:\+?\d[ \-]?){9,}\d(?![0-9A-Za-z])")
                        .expect("fancy phone pattern compiles"),
                )),
                // slm_gate._RE_PHONE_GENERIC — kind "PHONE".
                ("PHONE", PatEngine::Re(re(
                    r"(?:\+\d{1,3}[- ]?)?\(?\d{2,4}\)?[- ]?\d{2,4}[- ]?\d{4,10}",
                ))),
                // slm_gate._RE_IP
                ("IP_ADDRESS", PatEngine::Re(re(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"))),
                ("ID_NUMBER", PatEngine::Re(re(r"\b\d{6,}\b"))),
            ],
            // `\s*` here only ever sees U+0020 (input is already canonicalized),
            // so regex `\s` (White_Space) and Python `\s` agree in this space.
            lookalike_scan: re(r"\[\[\s*jarvis"),
            // masking._LOOKALIKE_SOURCE_RE — case-insensitive, applied to the
            // POST-NORMALIZE page text where the only whitespace is U+0020/U+000A
            // (both `\s` in either engine), so Python `\s` and regex `\s` agree.
            lookalike_source: re(r"(?i)\[\[\s*(jarvis)"),
            token_scan: re(DOC_TOKEN_PATTERN),
            query_token_scan: re(QUERY_TOKEN_PATTERN),
        }
    })
}

/// Port of `masking.masked_text_is_clean`: true iff `text` carries no residual
/// structured PII and no token lookalike. Well-formed document/query tokens are
/// stripped to the stand-in first (so removal can't glue two digit runs into a
/// match), then the remainder is scanned in the shared canonical space.
pub fn masked_text_is_clean(text: &str) -> bool {
    let p = patterns();
    let stripped = p.token_scan.replace_all(text, TOKEN_STAND_IN);
    let stripped = p.query_token_scan.replace_all(&stripped, TOKEN_STAND_IN);
    let (collapsed, folded) = canonical_scan_forms(&stripped);
    if p.lookalike_scan.is_match(&folded) {
        return false;
    }
    !p.structured.iter().any(|(_, pat)| pat.is_match(&collapsed))
}

// ── Document-masker support (consumed by `doc_masker`) ──
//
// The strict document masker in `server/documents/masking.py` reuses the SAME
// canonical space, `\s` semantics, structured-PII pattern set, token grammar and
// lookalike escaping the leak gate above is built on. Exposing them here keeps a
// SINGLE definition of each — the pipeline port cannot silently drift from the
// gate it must stay a superset of.

/// True iff Python `re` `\s` matches `c` (str semantics; WS_SET). Re-exported so
/// the masker's sentence splitter tokenizes on the identical whitespace set.
#[inline]
pub fn is_python_ws(c: char) -> bool {
    is_ws(c)
}

/// Byte offsets of every char boundary in `text`, plus the trailing `text.len()`
/// sentinel. A regex match byte offset (always on a char boundary) maps to its
/// CHAR index by binary search — Python `re` over `str` yields CHAR indices, the
/// `regex`/`fancy-regex` engines yield BYTE indices, so every structured-match
/// span must be converted before it becomes a char-space document span.
fn char_boundaries(text: &str) -> Vec<usize> {
    let mut b = Vec::with_capacity(text.len() + 1);
    for (bo, _) in text.char_indices() {
        b.push(bo);
    }
    b.push(text.len());
    b
}

#[inline]
fn to_char_index(boundaries: &[usize], byte: usize) -> usize {
    boundaries
        .binary_search(&byte)
        .expect("regex offsets fall on char boundaries")
}

/// Port of `masking._structured_spans` detection: every structured-PII match
/// over `text`, as `(char_start, char_end, kind)`, in `_STRUCTURED_PATTERNS`
/// iteration order (pattern by pattern, each left-to-right, non-overlapping) —
/// the exact order `_merge_spans`'s stable sort tie-breaks on. Byte offsets are
/// converted to char offsets. Zero-width matches are dropped (Python filters
/// `match.end() > match.start()`).
pub fn structured_matches(text: &str) -> Vec<(usize, usize, &'static str)> {
    let p = patterns();
    let boundaries = char_boundaries(text);
    let mut out = Vec::new();
    for (kind, engine) in &p.structured {
        match engine {
            PatEngine::Re(r) => {
                for m in r.find_iter(text) {
                    if m.end() > m.start() {
                        out.push((
                            to_char_index(&boundaries, m.start()),
                            to_char_index(&boundaries, m.end()),
                            *kind,
                        ));
                    }
                }
            }
            PatEngine::Fancy(r) => {
                // Non-overlapping leftmost matches, like Python `finditer`. A
                // fancy-regex runtime error stops iteration for THIS pattern
                // (the residual leak gate is the fail-closed authority; over-
                // masking a detection is never a confidentiality loss).
                for m in r.find_iter(text).flatten() {
                    if m.end() > m.start() {
                        out.push((
                            to_char_index(&boundaries, m.start()),
                            to_char_index(&boundaries, m.end()),
                            *kind,
                        ));
                    }
                }
            }
        }
    }
    out
}

/// True iff any structured-PII pattern matches `text` (the residual-scan check —
/// `any(pattern.search(collapsed))`), match-only, no offsets.
pub fn has_structured_residue(text: &str) -> bool {
    patterns().structured.iter().any(|(_, e)| e.is_match(text))
}

/// True iff `folded` contains an unescaped `[[…jarvis` token lookalike
/// (`_LOOKALIKE_SCAN_RE.search`).
pub fn has_lookalike(folded: &str) -> bool {
    patterns().lookalike_scan.is_match(folded)
}

/// Port of `masking._escape_lookalikes`: rewrite every source-authored
/// `[[<ws>*jarvis` (case-insensitive) to `[[/jarvis`, DROPPING the interior
/// whitespace (Python's replacement is `"[[/" + group(1)`, keeping only the
/// matched `jarvis` in its original case). Runs on post-normalize text, so the
/// only whitespace `\s*` can consume is U+0020/U+000A.
pub fn escape_lookalikes(text: &str) -> String {
    patterns()
        .lookalike_source
        .replace_all(text, |caps: &regex::Captures| format!("[[/{}", &caps[1]))
        .into_owned()
}

/// Port of `masking._strip_issued_tokens`: replace every vault-ISSUED token with
/// the object-replacement stand-in in one pass; non-issued token-shaped strings
/// survive so the lookalike scan still flags them. Empty `issued` → unchanged.
pub fn strip_issued_tokens(text: &str, issued: &std::collections::HashSet<String>) -> String {
    if issued.is_empty() {
        return text.to_string();
    }
    patterns()
        .token_scan
        .replace_all(text, |caps: &regex::Captures| {
            let tok = &caps[0];
            if issued.contains(tok) {
                TOKEN_STAND_IN.to_string()
            } else {
                tok.to_string()
            }
        })
        .into_owned()
}

/// Every well-formed `[[JARVIS-DOC:…]]` token in `text`, as
/// `(char_start, char_end, token_string)` — for the chunk splitter's
/// no-token-bisection guard and the per-chunk issued-token recorder.
pub fn doc_token_spans(text: &str) -> Vec<(usize, usize, String)> {
    let boundaries = char_boundaries(text);
    patterns()
        .token_scan
        .find_iter(text)
        .map(|m| {
            (
                to_char_index(&boundaries, m.start()),
                to_char_index(&boundaries, m.end()),
                m.as_str().to_string(),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::fs;

    fn vectors(name: &str) -> Vec<Value> {
        let path = format!(
            "{}/../../vectors/conformance/{}",
            env!("CARGO_MANIFEST_DIR"),
            name
        );
        let raw = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
        let v: Value = serde_json::from_str(&raw).unwrap();
        v["vectors"].as_array().unwrap().clone()
    }

    #[test]
    fn masking_normalize_vectors_byte_exact() {
        let mut fails = 0;
        for row in vectors("masking_normalize.json") {
            let input = row["input"].as_str().unwrap();
            let expect = row["expect"]["value"].as_str().unwrap();
            let got = normalize(input);
            if got != expect {
                fails += 1;
                eprintln!(
                    "normalize FAIL id={} in={:?} got={:?} want={:?}",
                    row["id"], input, got, expect
                );
            }
        }
        assert_eq!(fails, 0, "masking_normalize rows diverged");
    }

    #[test]
    fn masking_folded_scan_map_vectors_byte_exact() {
        let mut fails = 0;
        for row in vectors("masking_folded_scan_map.json") {
            let input = row["input"].as_str().unwrap();
            let want = &row["expect"]["value"];
            let want_folded = want[0].as_str().unwrap();
            let want_s: Vec<usize> = want[1]
                .as_array()
                .unwrap()
                .iter()
                .map(|x| x.as_u64().unwrap() as usize)
                .collect();
            let want_e: Vec<usize> = want[2]
                .as_array()
                .unwrap()
                .iter()
                .map(|x| x.as_u64().unwrap() as usize)
                .collect();
            let (folded, s, e) = folded_scan_map(input).expect("no boundary failure");
            if folded != want_folded || s != want_s || e != want_e {
                fails += 1;
                eprintln!(
                    "fsm FAIL id={} in={:?}\n got=({:?},{:?},{:?})\nwant=({:?},{:?},{:?})",
                    row["id"], input, folded, s, e, want_folded, want_s, want_e
                );
            }
        }
        assert_eq!(fails, 0, "masking_folded_scan_map rows diverged");
    }

    #[test]
    fn masking_canonical_scan_forms_vectors_byte_exact() {
        let mut fails = 0;
        for row in vectors("masking_canonical_scan_forms.json") {
            let input = row["input"].as_str().unwrap();
            let want = &row["expect"]["value"];
            let (cp, cf) = canonical_scan_forms(input);
            if cp != want[0].as_str().unwrap() || cf != want[1].as_str().unwrap() {
                fails += 1;
                eprintln!(
                    "canon FAIL id={} in={:?} got=({cp:?},{cf:?})",
                    row["id"], input
                );
            }
        }
        assert_eq!(fails, 0, "masking_canonical_scan_forms rows diverged");
    }

    #[test]
    fn masking_supported_script_vectors() {
        let mut fails = 0;
        for row in vectors("masking_supported_script.json") {
            let input = row["input"].as_str().unwrap();
            let got = require_supported_script(input);
            let ok = if let Some(raises) = row["expect"].get("raises") {
                got == Err(MaskError {
                    code: CODE_UNSUPPORTED_DOCUMENT_LANGUAGE,
                }) && raises == "UNSUPPORTED_DOCUMENT_LANGUAGE"
            } else {
                got.is_ok() && row["expect"]["value"] == "ok"
            };
            if !ok {
                fails += 1;
                eprintln!("script FAIL id={} in={input:?} got={got:?}", row["id"]);
            }
        }
        assert_eq!(fails, 0, "masking_supported_script rows diverged");
    }

    #[test]
    fn masking_leak_gate_vectors() {
        let mut fails = 0;
        for row in vectors("masking_leak_gate.json") {
            let input = row["input"].as_str().unwrap();
            let want = row["expect"]["value"].as_bool().unwrap();
            let got = masked_text_is_clean(input);
            if got != want {
                fails += 1;
                eprintln!(
                    "leak FAIL id={} in={input:?} got={got} want={want}",
                    row["id"]
                );
            }
        }
        assert_eq!(fails, 0, "masking_leak_gate rows diverged");
    }

    // Length-changing full casefold sanity (the property NFKC/`to_lowercase`
    // would silently break).
    #[test]
    fn full_casefold_is_length_changing() {
        assert_eq!(casefold("Straße"), "strasse");
        assert_eq!(casefold("ẞ"), "ss");
        assert_eq!(casefold("ﬀ"), "ff");
        assert_eq!(casefold("İ"), "i\u{307}");
        assert_eq!(casefold("Σ"), "σ");
    }
}
