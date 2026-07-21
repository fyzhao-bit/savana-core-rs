//! libsavana-ner — Rust port of server/security/ner_gate.py entity detection.
use serde::{Deserialize, Serialize};
use std::path::Path;

pub mod assets;
pub mod attempt_classifier;
pub mod capabilities;
pub mod chars;
pub mod dataflow_policy;
pub mod decode_en;
pub mod decode_zh;
pub mod infer_en;
pub mod infer_zh;
pub mod ontology;
pub mod pdp_tool;
pub mod sink_policy;
pub mod wordpiece;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EntityType {
    Name,
    Place,
    Org,
    Misc,
    Time,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Span {
    #[serde(rename = "type")]
    pub entity_type: String, // "NAME" | "PLACE" | "ORG" | "MISC" | "TIME"
    pub text: String,
    pub start: usize, // CHAR offset (see fidelity note)
    pub end: usize,
}

#[derive(Debug, thiserror::Error)]
pub enum NerError {
    #[error("ner_unavailable")]
    Unavailable,
    #[error("ner_failed")]
    Failed,
}

/// A Han (CJK unified ideograph) character in the ranges LAC covers —
/// `U+4E00..=U+9FFF` (CJK Unified Ideographs) or `U+3400..=U+4DBF`
/// (Extension A). Mirrors the script test used throughout `ner_gate.py`.
fn is_han(c: char) -> bool {
    ('\u{4e00}'..='\u{9fff}').contains(&c) || ('\u{3400}'..='\u{4dbf}').contains(&c)
}

/// The shared readiness heuristic from `NerGate._require_backends_ready`
/// (ner_gate.py:401-407), returning `(needs_en, needs_zh)`.
///
/// `needs_zh` is true when the text contains ANY Han character; `needs_en`
/// is true when it contains three or more ASCII letters
/// (`char.isascii() and char.isalpha()` — `char::is_ascii_alphabetic` is the
/// exact equivalent, true only for `a-zA-Z`). Model-free and pure, so callers
/// (and the readiness golden) can probe it without loading any backend.
pub fn readiness_flags(text: &str) -> (bool, bool) {
    let needs_zh = text.chars().any(is_han);
    let needs_en = text.chars().filter(|c| c.is_ascii_alphabetic()).count() >= 3;
    (needs_en, needs_zh)
}

/// Fail-closed NER gate — full port of `NerGate` (ner_gate.py:350-431). Holds
/// the English (bert-base-NER) and Chinese (Baidu LAC) ONNX backends; either
/// may be absent (`None`) if its assets failed to load, and `detect_strict`
/// fails closed only when the input's scripts actually require the missing
/// backend.
pub struct NerGate {
    en: Option<infer_en::EnModel>,
    zh: Option<infer_zh::ZhModel>,
}

impl NerGate {
    /// Load BOTH backends from `assets`. Each load failure is captured as
    /// `None` (not an error) — mirroring Python's per-backend try/except — so
    /// a gate with only one script's assets still serves that script;
    /// `detect_strict` fails closed only when a required backend is missing.
    pub fn load(assets: &Path) -> ort::Result<Self> {
        Ok(NerGate {
            en: infer_en::EnModel::load(assets).ok(),
            zh: infer_zh::ZhModel::load(assets).ok(),
        })
    }

    /// Script router — port of `NerGate._detect` (ner_gate.py:371-390). Runs
    /// the Chinese backend when the text has any Han character and the English
    /// backend when it has ≥3 ASCII letters (ZH spans pushed FIRST, then EN,
    /// so the stable merge sort resolves same-`(start,len)` ties toward the ZH
    /// span), then collapses overlaps with [`merge_nonoverlapping`].
    fn detect(&mut self, text: &str) -> ort::Result<Vec<Span>> {
        let cjk = text.chars().filter(|&c| is_han(c)).count();
        let latin = text.chars().filter(|c| c.is_ascii_alphabetic()).count();

        let mut spans: Vec<Span> = Vec::new();
        if cjk > 0 {
            if let Some(zh) = self.zh.as_mut() {
                spans.extend(decode_zh::extract(zh, text)?);
            }
        }
        if latin >= 3 {
            if let Some(en) = self.en.as_mut() {
                spans.extend(decode_en::extract(en, text)?);
            }
        }
        Ok(merge_nonoverlapping(spans))
    }

    /// Fail-closed entity detection — port of `NerGate.detect_strict`
    /// (ner_gate.py:415-431). Empty/whitespace text → no spans. Otherwise the
    /// readiness check runs first: if the text needs a backend that failed to
    /// load, return `NerError::Unavailable` WITHOUT running inference; if
    /// inference/decode then errors, return `NerError::Failed`. Errors carry
    /// only stable codes, never the input text.
    pub fn detect_strict(&mut self, text: &str) -> Result<Vec<Span>, NerError> {
        if text.trim().is_empty() {
            return Ok(vec![]);
        }
        let (needs_en, needs_zh) = readiness_flags(text);
        if (needs_zh && self.zh.is_none()) || (needs_en && self.en.is_none()) {
            return Err(NerError::Unavailable);
        }
        self.detect(text).map_err(|_| NerError::Failed)
    }
}

/// Mirror of `NerGate._detect`'s overlap resolution (ner_gate.py:382-390):
/// sort by start ascending then span length descending, then greedily keep a
/// span only when it starts at or after the end of the last kept span
/// (prefer earlier start, then longer). Rust's stable `sort_by` matches
/// Python's stable `list.sort`, so spans that tie on both keys retain input
/// order. Word-snap can make one word's leading-subword entity a prefix of
/// the whole-word entity (e.g. raw "Acme" 27..31 and "Acme Corp" 27..36);
/// this collapses that pair to the longer span, exactly as Python does.
fn merge_nonoverlapping(mut spans: Vec<Span>) -> Vec<Span> {
    spans.sort_by(|a, b| {
        a.start
            .cmp(&b.start)
            .then_with(|| (b.end - b.start).cmp(&(a.end - a.start)))
    });
    let mut merged: Vec<Span> = Vec::with_capacity(spans.len());
    let mut last_end: isize = -1;
    for s in spans {
        if s.start as isize >= last_end {
            last_end = s.end as isize;
            merged.push(s);
        }
    }
    merged
}

#[cfg(test)]
mod smoke {
    use super::*;
    #[test]
    fn types_exist() {
        let s = Span {
            entity_type: "NAME".into(),
            text: "x".into(),
            start: 0,
            end: 1,
        };
        assert_eq!(s.end, 1);
        assert_eq!(EntityType::Name as u8, 0);
    }
}
