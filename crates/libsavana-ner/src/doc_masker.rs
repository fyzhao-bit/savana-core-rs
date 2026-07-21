//! Byte-exact port of the ORCHESTRATION on top of the masking crux:
//! `server/documents/masking.py`'s `StrictDocumentMasker._mask_pages` — the
//! per-page confidence gate, normalize/script/escape, cross-page seam
//! reconciliation, the 2-phase detect→mint / sweep→apply→scan pipeline, and the
//! semantic chunker — plus the authenticated vault MINT it drives
//! (`scoped_vault::ScopedDocumentVault::put`).
//!
//! Everything fidelity-critical this sits on is already proven byte-exact vs
//! live CPython 15.0.0 and REUSED here, never re-vendored: `normalize`,
//! `require_supported_script`, `escape_lookalikes`, `canonical_scan_forms`,
//! `folded_scan_map`, `structured_matches`, the leak-gate patterns
//! (`masking`), and the HMAC token `put`/`resolve` (`scoped_vault`). This module
//! adds only the reconciliation + windowing + mint control flow, all in the ONE
//! normalized CHAR coordinate space (no byte back-map).
//!
//! The NER backend is injected via [`NerDetect`] exactly as Python's
//! `ner_detector` parameter is: the real `NerGate` (`detect_strict`) is the
//! production detector; the differential (`tests/doc_masker_differential.rs`)
//! injects a deterministic dictionary detector so the 2-phase reconciliation,
//! the seam split, the span cap, and the mint are proven model-free and fully
//! reproducible. The strict NER itself is proven byte-exact separately.

use crate::masking::{
    self, canonical_scan_forms, escape_lookalikes, folded_scan_map, has_lookalike,
    has_structured_residue, is_py_alpha, normalize, require_supported_script, strip_issued_tokens,
    structured_matches, MaskError, CODE_MASK_BOUNDARY_FAILED, CODE_UNSUPPORTED_DOCUMENT_LANGUAGE,
};
use crate::scoped_vault::{ScopedDocumentVault, DOC_MASK_VERSION};
use std::collections::{HashMap, HashSet};

// ── Code-owned masking constants (masking.py §"Code-owned masking constants") ──
const NER_WINDOW_CHARS: usize = 4096;
const NER_WINDOW_OVERLAP_CHARS: usize = 256;
const MAX_SUPPORTED_ENTITY_SPAN_CHARS: usize = 128;
const PAGE_JOIN_EDGE_CHARS: usize = 256;
const MAX_OCR_CHARS_PER_PAGE: usize = 50_000;
const MAX_OCR_CHARS_PER_DOC: usize = 1_000_000;

const MIN_OBSERVATION_CONFIDENCE_LATIN: f64 = 0.30;
const MIN_RETAINED_MEDIAN_CONFIDENCE_LATIN: f64 = 0.30;
const MIN_OBSERVATION_CONFIDENCE_HAN: f64 = 0.30;
const MIN_RETAINED_MEDIAN_CONFIDENCE_HAN: f64 = 0.30;
const MAX_DISCARDED_NONBLANK_PERCENT: i64 = 20;

const CHUNK_TARGET_CHARS: usize = 1600;
const CHUNK_MAX_CHARS: usize = 2000;
const MIN_SCANNED_VALUE_CHARS: usize = 5;

/// `models.CODE_OCR_LOW_CONFIDENCE`.
pub const CODE_OCR_LOW_CONFIDENCE: &str = "OCR_LOW_CONFIDENCE";

fn boundary() -> MaskError {
    MaskError {
        code: CODE_MASK_BOUNDARY_FAILED,
    }
}
fn low_confidence() -> MaskError {
    MaskError {
        code: CODE_OCR_LOW_CONFIDENCE,
    }
}
fn unsupported() -> MaskError {
    MaskError {
        code: CODE_UNSUPPORTED_DOCUMENT_LANGUAGE,
    }
}

// ── Han-letter ranges for the confidence gate's script classification
//    (masking._HAN_LETTER_RANGES) ──
const HAN_LETTER_RANGES: [(u32, u32); 9] = [
    (0x3005, 0x3007),
    (0x3400, 0x4dbf),
    (0x4e00, 0x9fff),
    (0xf900, 0xfaff),
    (0x20000, 0x2a6df),
    (0x2a700, 0x2b73f),
    (0x2b740, 0x2b81f),
    (0x2b820, 0x2ceaf),
    (0x2f800, 0x2fa1f),
];

fn is_han_letter(cp: u32) -> bool {
    HAN_LETTER_RANGES
        .iter()
        .any(|&(lo, hi)| lo <= cp && cp <= hi)
}

// ── Injected NER (mirrors Python's `ner_detector`) ──

/// One detected entity in CHAR offsets into the text the detector was given —
/// the Rust analogue of `ner_gate.Entity` (`type`/`start`/`end`; `text` unused
/// by the pipeline, which recomputes the raw from offsets).
#[derive(Debug, Clone)]
pub struct DetectedEntity {
    pub start: usize,
    pub end: usize,
    pub kind: String,
}

/// A detector backend failure or unavailability — carries no detail (the
/// pipeline maps it to a terminal `MASK_BOUNDARY_FAILED`, never echoing input).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NerDetectError;

/// The injectable strict NER detector. `Err(NerDetectError)` means the backend
/// failed or was unavailable — the pipeline maps that to a terminal
/// `MASK_BOUNDARY_FAILED` with no detail carried over (Python's `_detect`
/// try/except).
pub trait NerDetect {
    fn detect(&mut self, text: &str) -> Result<Vec<DetectedEntity>, NerDetectError>;
}

/// Adapter making the real fail-closed `NerGate` a [`NerDetect`] — the
/// production path (`_default_detector` → `detect_strict`). Any `NerError`
/// (backend missing or inference failure) becomes a boundary fail.
impl NerDetect for crate::NerGate {
    fn detect(&mut self, text: &str) -> Result<Vec<DetectedEntity>, NerDetectError> {
        let spans = self.detect_strict(text).map_err(|_| NerDetectError)?;
        Ok(spans
            .into_iter()
            .map(|s| DetectedEntity {
                start: s.start,
                end: s.end,
                kind: s.entity_type,
            })
            .collect())
    }
}

// ── Public data model (the `MaskedDocument` shape the differential compares) ──

#[derive(Debug, Clone)]
pub struct Observation {
    pub text: String,
    pub confidence: f64,
}

#[derive(Debug, Clone)]
pub struct RawPage {
    pub page_number: i64,
    pub source: String,
    pub text: String,
    pub observations: Vec<Observation>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaskedPage {
    pub page_number: i64,
    pub masked_text: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaskedChunk {
    pub chunk_id: String,
    pub page_start: i64,
    pub page_end: i64,
    pub masked_text: String,
}

#[derive(Debug, Clone)]
pub struct MaskedDocument {
    pub artifact_id: String,
    pub generation: u32,
    pub mask_version: String,
    pub pages: Vec<MaskedPage>,
    pub chunks: Vec<MaskedChunk>,
}

/// `masking._Span` — a detected/reconciled span in CHAR offsets, carrying the
/// vault kind that will mint its token.
#[derive(Debug, Clone)]
struct DocSpan {
    start: usize,
    end: usize,
    kind: String,
}

// ── `_KIND_RE` (`^[A-Z][A-Z0-9_]{0,31}$`) — the detect-time kind guard ──
fn is_kind(s: &str) -> bool {
    let b = s.as_bytes();
    if b.is_empty() || b.len() > 32 || !b[0].is_ascii_uppercase() {
        return false;
    }
    b[1..]
        .iter()
        .all(|&c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == b'_')
}

/// The full-page strict masker — port of `StrictDocumentMasker`.
pub struct StrictDocumentMasker;

impl Default for StrictDocumentMasker {
    fn default() -> Self {
        Self
    }
}

impl StrictDocumentMasker {
    pub fn new() -> Self {
        Self
    }

    /// Port of `mask_pages`: scope re-check, then `_mask_pages`. Any vault
    /// refusal or unexpected internal error would already be a terminal
    /// `MaskError`; the scope mismatch is `MASK_BOUNDARY_FAILED`.
    pub fn mask_pages(
        &self,
        detector: &mut dyn NerDetect,
        artifact_id: &str,
        generation: u32,
        pages: &[RawPage],
        vault: &mut ScopedDocumentVault,
    ) -> Result<MaskedDocument, MaskError> {
        if vault.artifact_id() != artifact_id
            || vault.generation() != generation
            || vault.mask_version() != DOC_MASK_VERSION
        {
            return Err(boundary());
        }
        self.mask_pages_inner(detector, artifact_id, generation, pages, vault)
    }

    #[allow(clippy::too_many_lines)]
    fn mask_pages_inner(
        &self,
        detector: &mut dyn NerDetect,
        artifact_id: &str,
        generation: u32,
        pages: &[RawPage],
        vault: &mut ScopedDocumentVault,
    ) -> Result<MaskedDocument, MaskError> {
        // Defensive re-checks of the worker-stage bounds.
        let mut total_chars = 0usize;
        let mut last_page_number = 0i64;
        for page in pages {
            let len = page.text.chars().count();
            if len > MAX_OCR_CHARS_PER_PAGE {
                return Err(boundary());
            }
            total_chars += len;
            if page.page_number <= last_page_number {
                return Err(boundary());
            }
            last_page_number = page.page_number;
        }
        if total_chars > MAX_OCR_CHARS_PER_DOC {
            return Err(boundary());
        }

        // Steps 1-4: confidence gate, normalize, script check, escape.
        let mut working: Vec<(i64, String)> = Vec::with_capacity(pages.len());
        for page in pages {
            let text = confidence_gated_text(page)?;
            let normalized = normalize(&text);
            require_supported_script(&normalized).map_err(|e| {
                // Preserve the specific UNSUPPORTED code (mask_pages re-raises
                // DocumentMaskError as-is; only vault/unexpected → boundary).
                if e.code == CODE_UNSUPPORTED_DOCUMENT_LANGUAGE {
                    unsupported()
                } else {
                    boundary()
                }
            })?;
            working.push((page.page_number, escape_lookalikes(&normalized)));
        }

        // Step 5: cross-page seams → extra page-scoped spans.
        let mut extra_spans: Vec<Vec<DocSpan>> = vec![Vec::new(); working.len()];
        for index in 0..working.len().saturating_sub(1) {
            let (left_extra, right_extra) =
                seam_spans(detector, &working[index].1, &working[index + 1].1)?;
            extra_spans[index].extend(left_extra);
            extra_spans[index + 1].extend(right_extra);
        }

        // Phase 1 — detect + vault, all pages (no replacement yet).
        let mut detected_by_page: Vec<Vec<DocSpan>> = Vec::with_capacity(working.len());
        for (index, (page_number, text)) in working.iter().enumerate() {
            let mut spans = structured_spans(text);
            spans.extend(ner_spans(detector, text)?);
            spans.extend(extra_spans[index].iter().cloned());
            let text_len = text.chars().count();
            let merged = merge_spans(spans, text_len)?;
            let tchars: Vec<char> = text.chars().collect();
            for span in &merged {
                let raw: String = tchars[span.start..span.end].iter().collect();
                if !raw.trim().is_empty() {
                    vault
                        .put(&span.kind, &raw, &[*page_number as u32])
                        .map_err(|_| boundary())?;
                }
            }
            detected_by_page.push(merged);
        }

        // First-seen `folded → ORIGINAL kind` over the now-complete vault.
        let mut kind_by_folded: HashMap<String, String> = HashMap::new();
        for (kind, raw) in vault.value_entries() {
            let folded = canonical_scan_forms(&raw).1;
            kind_by_folded.entry(folded).or_insert(kind);
        }

        // Phase 2 — active sweep + apply + scan, all pages, complete vault.
        let mut masked_pages: Vec<MaskedPage> = Vec::with_capacity(working.len());
        let mut stripped_pages: Vec<String> = Vec::with_capacity(working.len());
        for (index, (page_number, text)) in working.iter().enumerate() {
            let mut spans = detected_by_page[index].clone();
            spans.extend(known_value_spans(text, vault, &kind_by_folded)?);
            let text_len = text.chars().count();
            let merged = merge_spans(spans, text_len)?;
            let tchars: Vec<char> = text.chars().collect();
            let masked = apply_spans(&tchars, &merged, vault, *page_number)?;
            stripped_pages.push(scan_masked_page(&masked, vault)?);
            masked_pages.push(MaskedPage {
                page_number: *page_number,
                masked_text: masked,
            });
        }

        // Step 8 (cross-page): masked seams in canonical form, reusing each
        // page's cached token-stripped text.
        for index in 0..stripped_pages.len().saturating_sub(1) {
            let left: Vec<char> = stripped_pages[index].chars().collect();
            let right: Vec<char> = stripped_pages[index + 1].chars().collect();
            let left_tail: String = left[left.len().saturating_sub(PAGE_JOIN_EDGE_CHARS)..]
                .iter()
                .collect();
            let right_head: String = right[..right.len().min(PAGE_JOIN_EDGE_CHARS)]
                .iter()
                .collect();
            let seam = format!("{left_tail}{right_head}");
            if !is_clean(&seam, Some(vault)) {
                return Err(boundary());
            }
        }

        // Steps 9-10: chunk the masked pages; leak-gate every serialized chunk.
        let mut chunks: Vec<MaskedChunk> = Vec::new();
        // Snapshot page metadata first so the vault can be borrowed mutably in
        // the loop (record_chunks) without aliasing masked_pages.
        let page_meta: Vec<(i64, String)> = masked_pages
            .iter()
            .map(|p| (p.page_number, p.masked_text.clone()))
            .collect();
        for (page_number, masked_text) in &page_meta {
            for (sequence, piece) in chunk_page(masked_text)?.into_iter().enumerate() {
                let chunk = MaskedChunk {
                    chunk_id: format!("c{page_number:05}-{sequence:03}"),
                    page_start: *page_number,
                    page_end: *page_number,
                    masked_text: piece,
                };
                let serialized = serialize_chunk_json(&chunk);
                if !is_clean(&chunk.masked_text, Some(vault)) || !is_clean(&serialized, Some(vault))
                {
                    return Err(boundary());
                }
                let issued = vault.issued_token_set();
                let mut recorded: HashSet<String> = HashSet::new();
                for (_s, _e, token) in masking::doc_token_spans(&chunk.masked_text) {
                    if issued.contains(&token) && !recorded.contains(&token) {
                        recorded.insert(token.clone());
                        vault
                            .record_chunks(&token, &chunk.chunk_id)
                            .map_err(|_| boundary())?;
                    }
                }
                chunks.push(chunk);
            }
        }

        Ok(MaskedDocument {
            artifact_id: artifact_id.to_string(),
            generation,
            mask_version: DOC_MASK_VERSION.to_string(),
            pages: masked_pages,
            chunks,
        })
    }
}

// ── Step 1: confidence gating ──

fn confidence_gated_text(page: &RawPage) -> Result<String, MaskError> {
    if page.observations.is_empty() {
        if page.source == "ocr" && !page.text.trim().is_empty() {
            return Err(low_confidence());
        }
        return Ok(page.text.clone());
    }
    let nonblank: Vec<&Observation> = page
        .observations
        .iter()
        .filter(|o| !o.text.trim().is_empty())
        .collect();
    let han_dominant = page_is_han_dominant(nonblank.iter().map(|o| o.text.as_str()));
    let (min_confidence, min_retained_median) = if han_dominant {
        (
            MIN_OBSERVATION_CONFIDENCE_HAN,
            MIN_RETAINED_MEDIAN_CONFIDENCE_HAN,
        )
    } else {
        (
            MIN_OBSERVATION_CONFIDENCE_LATIN,
            MIN_RETAINED_MEDIAN_CONFIDENCE_LATIN,
        )
    };
    if !nonblank.is_empty() {
        let discarded = nonblank
            .iter()
            .filter(|o| o.confidence < min_confidence)
            .count() as i64;
        if discarded * 100 > (nonblank.len() as i64) * MAX_DISCARDED_NONBLANK_PERCENT {
            return Err(low_confidence());
        }
        let retained: Vec<f64> = nonblank
            .iter()
            .filter(|o| o.confidence >= min_confidence)
            .map(|o| o.confidence)
            .collect();
        if retained.is_empty() || median(&retained) < min_retained_median {
            return Err(low_confidence());
        }
    }
    let kept: Vec<&str> = page
        .observations
        .iter()
        .filter(|o| o.confidence >= min_confidence)
        .map(|o| o.text.as_str())
        .collect();
    Ok(kept.join("\n"))
}

/// `statistics.median`: mean of the two middle values for an even count, the
/// middle value for an odd count. Callers guarantee a non-empty slice.
fn median(values: &[f64]) -> f64 {
    let mut sorted = values.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).expect("confidences are finite"));
    let n = sorted.len();
    if n % 2 == 1 {
        sorted[n / 2]
    } else {
        (sorted[n / 2 - 1] + sorted[n / 2]) / 2.0
    }
}

/// Port of `_page_is_han_dominant`: true iff ≥50% of the letters (Python
/// `isalpha`) across the texts are Han. No letters → Latin (fail-closed).
fn page_is_han_dominant<'a>(texts: impl Iterator<Item = &'a str>) -> bool {
    let mut letters = 0i64;
    let mut han = 0i64;
    for text in texts {
        for c in text.chars() {
            if !is_py_alpha(c) {
                continue;
            }
            letters += 1;
            if is_han_letter(c as u32) {
                han += 1;
            }
        }
    }
    if letters == 0 {
        return false;
    }
    2 * han >= letters
}

// ── Step 5: cross-page seam reconciliation ──

fn seam_spans(
    detector: &mut dyn NerDetect,
    left_text: &str,
    right_text: &str,
) -> Result<(Vec<DocSpan>, Vec<DocSpan>), MaskError> {
    let left: Vec<char> = left_text.chars().collect();
    let right: Vec<char> = right_text.chars().collect();
    let ll = left.len();
    let rl = right.len();
    let tail_len = ll.min(PAGE_JOIN_EDGE_CHARS);
    let head_len = rl.min(PAGE_JOIN_EDGE_CHARS);
    let tail: String = left[ll - tail_len..].iter().collect();
    let head: String = right[..head_len].iter().collect();
    if tail.is_empty() || head.is_empty() {
        return Ok((Vec::new(), Vec::new()));
    }
    let seam = format!("{tail}{head}");
    let seam_len = tail_len + head_len;
    let seam_boundary = tail_len;
    let tail_truncated = ll > tail_len;
    let head_truncated = rl > head_len;

    let mut spans = structured_spans(&seam);
    for e in detect(detector, &seam)? {
        spans.push(DocSpan {
            start: e.start,
            end: e.end,
            kind: e.kind,
        });
    }

    let mut left_extra: Vec<DocSpan> = Vec::new();
    let mut right_extra: Vec<DocSpan> = Vec::new();
    let left_offset = ll - tail_len;
    for span in spans {
        if span.end <= seam_boundary || span.start >= seam_boundary {
            continue;
        }
        if (span.start == 0 && tail_truncated) || (span.end == seam_len && head_truncated) {
            return Err(boundary());
        }
        left_extra.push(DocSpan {
            start: left_offset + span.start,
            end: ll,
            kind: span.kind.clone(),
        });
        right_extra.push(DocSpan {
            start: 0,
            end: span.end - seam_boundary,
            kind: span.kind,
        });
    }
    Ok((left_extra, right_extra))
}

// ── Step 6: detection ──

fn structured_spans(text: &str) -> Vec<DocSpan> {
    structured_matches(text)
        .into_iter()
        .map(|(start, end, kind)| DocSpan {
            start,
            end,
            kind: kind.to_string(),
        })
        .collect()
}

fn ner_spans(detector: &mut dyn NerDetect, text: &str) -> Result<Vec<DocSpan>, MaskError> {
    let chars: Vec<char> = text.chars().collect();
    let n = chars.len();
    let step = NER_WINDOW_CHARS - NER_WINDOW_OVERLAP_CHARS;
    let mut spans: Vec<DocSpan> = Vec::new();
    let mut start = 0usize;
    loop {
        let end = (start + NER_WINDOW_CHARS).min(n);
        let window: String = chars[start..end].iter().collect();
        for e in detect(detector, &window)? {
            spans.push(DocSpan {
                start: start + e.start,
                end: start + e.end,
                kind: e.kind,
            });
        }
        if end >= n {
            break;
        }
        start += step;
    }
    Ok(spans)
}

/// Port of `_detect`: empty/whitespace → no spans; otherwise validate every
/// returned entity (bounds, kind grammar, and the NER-only span cap) — any
/// violation, or a detector failure, is a terminal `MASK_BOUNDARY_FAILED`.
fn detect(detector: &mut dyn NerDetect, text: &str) -> Result<Vec<DetectedEntity>, MaskError> {
    if text.trim().is_empty() {
        return Ok(Vec::new());
    }
    let entities = detector.detect(text).map_err(|_| boundary())?;
    let n = text.chars().count();
    for e in &entities {
        if e.end > n
            || e.start >= e.end
            || !is_kind(&e.kind)
            || (e.end - e.start) > MAX_SUPPORTED_ENTITY_SPAN_CHARS
        {
            return Err(boundary());
        }
    }
    Ok(entities)
}

// ── Step 6b: active whole-document vault-value sweep ──

fn known_value_spans(
    text: &str,
    vault: &ScopedDocumentVault,
    kind_by_folded: &HashMap<String, String>,
) -> Result<Vec<DocSpan>, MaskError> {
    let buckets = vault.folded_length_buckets();
    if buckets.is_empty() {
        return Ok(Vec::new());
    }
    let (folded, f_start, f_end) = folded_scan_map(text)?;
    let fchars: Vec<char> = folded.chars().collect();
    let text_length = fchars.len();
    let mut spans: Vec<DocSpan> = Vec::new();
    // Bucket iteration order is irrelevant: distinct lengths never collide at a
    // shared (start, len), and `_merge_spans` re-sorts everything afterwards.
    for (length, bucket) in buckets {
        let length = *length;
        if length < MIN_SCANNED_VALUE_CHARS || length > text_length {
            continue;
        }
        for start in 0..=(text_length - length) {
            let window: String = fchars[start..start + length].iter().collect();
            if !bucket.contains(&window) {
                continue;
            }
            if glued(&fchars, start, length, text_length) {
                continue;
            }
            let kind = kind_by_folded.get(&window).ok_or_else(boundary)?;
            spans.push(DocSpan {
                start: f_start[start],
                end: f_end[start + length - 1],
                kind: kind.clone(),
            });
        }
    }
    Ok(spans)
}

/// The `_is_clean_stripped` word-boundary guard: an ASCII-alphanumeric edge glued
/// to an ASCII-alphanumeric neighbour is a fragment inside a word (skip); a
/// CJK-edged value matches as a substring.
fn glued(fchars: &[char], start: usize, length: usize, text_length: usize) -> bool {
    let w0 = fchars[start];
    let wl = fchars[start + length - 1];
    let left_glued =
        w0.is_ascii_alphanumeric() && start > 0 && fchars[start - 1].is_ascii_alphanumeric();
    let right_glued = wl.is_ascii_alphanumeric()
        && start + length < text_length
        && fchars[start + length].is_ascii_alphanumeric();
    left_glued || right_glued
}

// ── Step 6: deterministic span reconciliation ──

fn merge_spans(spans: Vec<DocSpan>, length: usize) -> Result<Vec<DocSpan>, MaskError> {
    for span in &spans {
        // 0 <= start is guaranteed by usize; require start < end <= length.
        if !(span.start < span.end && span.end <= length) {
            return Err(boundary());
        }
    }
    let mut ordered = spans;
    // Stable sort by (start asc, span-length desc) — matches Python's stable
    // `sorted(..., key=(start, -(end-start)))`, so equal-key spans keep their
    // input order (detected before swept).
    ordered.sort_by(|a, b| {
        a.start
            .cmp(&b.start)
            .then_with(|| (b.end - b.start).cmp(&(a.end - a.start)))
    });
    let mut merged: Vec<DocSpan> = Vec::with_capacity(ordered.len());
    for span in ordered {
        if let Some(last) = merged.last_mut() {
            if span.start < last.end {
                let last_len = last.end - last.start;
                let span_len = span.end - span.start;
                if last_len < span_len {
                    last.kind = span.kind;
                }
                last.end = last.end.max(span.end);
                continue;
            }
        }
        merged.push(span);
    }
    Ok(merged)
}

// ── Step 7: replacement ──

fn apply_spans(
    text_chars: &[char],
    spans: &[DocSpan],
    vault: &mut ScopedDocumentVault,
    page_number: i64,
) -> Result<String, MaskError> {
    let mut chars: Vec<char> = text_chars.to_vec();
    // Right-to-left so earlier offsets stay valid AND put() is called in the
    // exact order Python does (matters only for spans a phase-2 merge extended
    // into a not-yet-vaulted (kind, raw), which then mint fresh counters here).
    for span in spans.iter().rev() {
        let raw: String = text_chars[span.start..span.end].iter().collect();
        if raw.trim().is_empty() {
            continue;
        }
        let token = vault
            .put(&span.kind, &raw, &[page_number as u32])
            .map_err(|_| boundary())?;
        chars.splice(span.start..span.end, token.chars());
    }
    Ok(chars.iter().collect())
}

// ── Step 8: residual scanning ──

fn scan_masked_page(masked: &str, vault: &ScopedDocumentVault) -> Result<String, MaskError> {
    let stripped = strip_issued_tokens(masked, &vault.issued_token_set());
    if !is_clean_stripped(&stripped, Some(vault)) {
        return Err(boundary());
    }
    // Explicit NER-window seam regions of the masked page (subsumed by the full
    // scan above; kept as an independent check).
    let schars: Vec<char> = stripped.chars().collect();
    let n = schars.len();
    let step = NER_WINDOW_CHARS - NER_WINDOW_OVERLAP_CHARS;
    let mut boundary_pos = step;
    while boundary_pos < n {
        let lo = boundary_pos.saturating_sub(NER_WINDOW_OVERLAP_CHARS);
        let hi = (boundary_pos + NER_WINDOW_OVERLAP_CHARS).min(n);
        let region: String = schars[lo..hi].iter().collect();
        if !is_clean_stripped(&region, Some(vault)) {
            return Err(boundary());
        }
        boundary_pos += step;
    }
    Ok(stripped)
}

fn is_clean(text: &str, vault: Option<&ScopedDocumentVault>) -> bool {
    let stripped = match vault {
        Some(v) => strip_issued_tokens(text, &v.issued_token_set()),
        None => text.to_string(),
    };
    is_clean_stripped(&stripped, vault)
}

fn is_clean_stripped(stripped: &str, vault: Option<&ScopedDocumentVault>) -> bool {
    let (collapsed, folded) = canonical_scan_forms(stripped);
    // 1. Unescaped token lookalikes / non-issued token-shaped strings.
    if has_lookalike(&folded) {
        return false;
    }
    // 2. Structured-PII residue (case-preserved canonical form).
    if has_structured_residue(&collapsed) {
        return false;
    }
    // 3. Every known vault value, length-bucketed.
    if let Some(v) = vault {
        let fchars: Vec<char> = folded.chars().collect();
        let text_length = fchars.len();
        for (length, bucket) in v.folded_length_buckets() {
            let length = *length;
            if length < MIN_SCANNED_VALUE_CHARS || length > text_length {
                continue;
            }
            for start in 0..=(text_length - length) {
                let window: String = fchars[start..start + length].iter().collect();
                if !bucket.contains(&window) {
                    continue;
                }
                if glued(&fchars, start, length, text_length) {
                    continue;
                }
                return false;
            }
        }
    }
    true
}

// ── Step 9: semantic chunking of the MASKED page ──

fn chunk_page(text: &str) -> Result<Vec<String>, MaskError> {
    if text.trim().is_empty() {
        return Ok(Vec::new());
    }
    let mut units: Vec<String> = Vec::new();
    for paragraph in paragraph_split(text) {
        let paragraph = paragraph.trim_matches('\n');
        if paragraph.trim().is_empty() {
            continue;
        }
        for sentence in sentence_split(paragraph) {
            if !sentence.is_empty() {
                units.push(sentence);
            }
        }
    }
    if units.is_empty() {
        units = vec![text.to_string()];
    }

    let mut chunks: Vec<String> = Vec::new();
    let mut buffer = String::new();
    for unit in units {
        let mut unit = unit;
        while unit.chars().count() > CHUNK_MAX_CHARS {
            let split_at = safe_split_point(&unit, CHUNK_MAX_CHARS)?;
            if !buffer.is_empty() {
                chunks.push(std::mem::take(&mut buffer));
            }
            let uchars: Vec<char> = unit.chars().collect();
            chunks.push(uchars[..split_at].iter().collect());
            unit = uchars[split_at..].iter().collect();
        }
        if unit.is_empty() {
            continue;
        }
        let candidate = if buffer.is_empty() {
            unit.clone()
        } else {
            format!("{buffer}\n{unit}")
        };
        if candidate.chars().count() <= CHUNK_TARGET_CHARS {
            buffer = candidate;
        } else {
            if !buffer.is_empty() {
                chunks.push(std::mem::take(&mut buffer));
            }
            buffer = unit;
        }
    }
    if !buffer.is_empty() {
        chunks.push(buffer);
    }
    Ok(chunks)
}

/// Port of `_safe_split_point`: a split at/before `limit` that never bisects a
/// token; fail-closed if the only candidate is `<= 0`.
fn safe_split_point(unit: &str, limit: usize) -> Result<usize, MaskError> {
    let mut split_at = limit;
    for (s, _e, _tok) in masking::doc_token_spans(unit) {
        let (start, end) = (s, _e);
        if start < split_at && split_at < end {
            split_at = start;
            break;
        }
    }
    if split_at == 0 {
        return Err(boundary());
    }
    Ok(split_at)
}

/// Split on runs of ≥2 newlines (`_PARAGRAPH_SPLIT_RE = \n{2,}`), dropping the
/// matched runs — `re.split` semantics.
fn paragraph_split(text: &str) -> Vec<String> {
    let chars: Vec<char> = text.chars().collect();
    let mut out: Vec<String> = Vec::new();
    let mut seg_start = 0usize;
    let mut i = 0usize;
    while i < chars.len() {
        if chars[i] == '\n' {
            let run_start = i;
            let mut j = i;
            while j < chars.len() && chars[j] == '\n' {
                j += 1;
            }
            if j - run_start >= 2 {
                out.push(chars[seg_start..run_start].iter().collect());
                seg_start = j;
            }
            i = j;
        } else {
            i += 1;
        }
    }
    out.push(chars[seg_start..].iter().collect());
    out
}

/// Split on `(?<=[.!?。！？；])\s+` (`_SENTENCE_SPLIT_RE`): a whitespace run whose
/// preceding char is a sentence-ender is a split point; the run is dropped.
fn sentence_split(text: &str) -> Vec<String> {
    const ENDERS: [char; 7] = ['.', '!', '?', '。', '！', '？', '；'];
    let chars: Vec<char> = text.chars().collect();
    let mut out: Vec<String> = Vec::new();
    let mut seg_start = 0usize;
    let mut i = 0usize;
    while i < chars.len() {
        if masking::is_python_ws(chars[i]) && i > 0 && ENDERS.contains(&chars[i - 1]) {
            out.push(chars[seg_start..i].iter().collect());
            let mut j = i;
            while j < chars.len() && masking::is_python_ws(chars[j]) {
                j += 1;
            }
            seg_start = j;
            i = j;
        } else {
            i += 1;
        }
    }
    out.push(chars[seg_start..].iter().collect());
    out
}

/// `json.dumps({chunk_id, masked_text, page_end, page_start}, sort_keys=True,
/// ensure_ascii=False, separators=(",", ":"))` — the exact chunk serialization
/// the per-chunk leak gate scans. Keys emit in sorted order.
fn serialize_chunk_json(chunk: &MaskedChunk) -> String {
    format!(
        "{{\"chunk_id\":{},\"masked_text\":{},\"page_end\":{},\"page_start\":{}}}",
        json_str(&chunk.chunk_id),
        json_str(&chunk.masked_text),
        chunk.page_end,
        chunk.page_start,
    )
}

/// Python `json` string encoding with `ensure_ascii=False`: escape `"` `\` and
/// the C0 control chars (`\n \r \t \b \f`, else `\u00xx` lowercase); everything
/// ≥ U+0020 (incl. non-ASCII) is emitted literally.
fn json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}
