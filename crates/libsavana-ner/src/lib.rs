//! libsavana-ner — Rust port of server/security/ner_gate.py entity detection.
use serde::{Deserialize, Serialize};
use std::path::Path;

pub mod assets;
pub mod chars;
pub mod decode_en;
pub mod infer_en;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    En,
    Zh,
}

#[derive(Debug, thiserror::Error)]
pub enum NerError {
    #[error("ner_unavailable")]
    Unavailable,
    #[error("ner_failed")]
    Failed,
}

/// TEMPORARY English-only gate (Phase 4). Phase 6 will fold in the Chinese
/// backend and the cross-script merge; for now this exercises the EN inference
/// and BIO-decode path end-to-end so it can be proven byte-exact against the
/// Python golden. Mirrors the English branch of `NerGate.detect_strict`:
/// three or more ASCII letters require the EN backend (fail-closed if it is
/// unavailable), fewer than three short-circuit to "no entities".
pub struct NerGate {
    en: Option<infer_en::EnModel>,
}

impl NerGate {
    /// Load the EN backend from `assets`. A load failure is captured as
    /// `en: None` (not an error) so callers can still handle non-English text;
    /// `detect_strict` fails closed only when English text actually needs it.
    pub fn load(assets: &Path) -> ort::Result<Self> {
        Ok(NerGate {
            en: infer_en::EnModel::load(assets).ok(),
        })
    }

    /// Fail-closed English entity detection. Empty/whitespace text → no spans.
    /// Text with ≥3 ASCII letters requires the EN backend: missing ⇒
    /// `NerError::Unavailable`; an inference/decode error ⇒ `NerError::Failed`.
    pub fn detect_strict(&mut self, text: &str) -> Result<Vec<Span>, NerError> {
        if text.trim().is_empty() {
            return Ok(vec![]);
        }
        let latin = text.chars().filter(|c| c.is_ascii_alphabetic()).count();
        if latin >= 3 && self.en.is_none() {
            return Err(NerError::Unavailable);
        }
        let mut spans = vec![];
        if latin >= 3 {
            if let Some(en) = self.en.as_mut() {
                spans = decode_en::extract(en, text).map_err(|_| NerError::Failed)?;
            }
        }
        Ok(merge_nonoverlapping(spans))
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
