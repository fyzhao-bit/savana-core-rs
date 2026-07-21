//! English BIO decode + sliding-window union — mirror of `_OnnxEn.extract`
//! and `_OnnxEn._run_window` in `server/security/ner_gate.py` (lines 202-280).
//!
//! `_run_window` (numeric) is split so the ONNX run lives in
//! [`crate::infer_en::EnModel::logits`]; everything here is deterministic:
//! per-token argmax (first-max-wins, matching numpy), the B-/I-/O state
//! machine, whole-word boundary snapping, sliding-window framing for inputs
//! over 510 content tokens, dedup of identical `(start,end,type)` spans, and
//! the raw→normalised type map (`PER→NAME, LOC→PLACE, ORG→ORG, MISC→MISC`).
//!
//! Offsets are CHAR indices into `text.chars()` — Python `str` indexing.

use crate::infer_en::EnModel;
use crate::Span;
use std::collections::HashSet;

// bert-base has 512 absolute position embeddings; long inputs are processed
// in bounded, overlapping token windows and their detections unioned.
const MAX_TOKENS: usize = 512;
const WINDOW_OVERLAP_TOKENS: usize = 64;

/// Mirror of Python `_wc`: `c.isalnum() or c == "'"`.
fn is_wordchar(c: char) -> bool {
    c.is_alphanumeric() || c == '\''
}

/// Raw→normalised entity-type map (`_OnnxEn._NORM`). Types absent from the
/// map are dropped by the caller.
fn norm_type(raw: &str) -> Option<&'static str> {
    match raw {
        "PER" => Some("NAME"),
        "LOC" => Some("PLACE"),
        "ORG" => Some("ORG"),
        "MISC" => Some("MISC"),
        _ => None,
    }
}

/// A pre-normalisation detection: raw CoNLL type + snapped char offsets.
type RawEnt = (String, usize, usize);

/// Snap `(start,end)` to whole-word boundaries and push the entity. Mirrors
/// Python `flush()`: expand left while the preceding char is a word char,
/// expand right while the current char is a word char, then emit. Resets
/// `cur` to `None` (like Python setting `cur["type"] = None`).
fn flush(cur: &mut Option<RawEnt>, chars: &[char], out: &mut Vec<RawEnt>) {
    if let Some((ty, mut s, mut e)) = cur.take() {
        while s > 0 && is_wordchar(chars[s - 1]) {
            s -= 1;
        }
        while e < chars.len() && is_wordchar(chars[e]) {
            e += 1;
        }
        out.push((ty, s, e));
    }
}

/// Port of `_run_window`: run one token window through the model, then walk
/// the per-token argmax labels through the B-/I-/O state machine, snapping
/// each entity to whole-word boundaries. Returns raw (un-normalised) spans.
fn run_window(
    model: &mut EnModel,
    toks: &[(i64, usize, usize)],
    chars: &[char],
) -> ort::Result<Vec<RawEnt>> {
    let ids: Vec<i64> = toks.iter().map(|t| t.0).collect();
    let logits = model.logits(&ids)?; // [n, L]; mutable borrow of model ends here
    let labels = model.labels();

    let mut ents: Vec<RawEnt> = Vec::new();
    let mut cur: Option<RawEnt> = None;

    for (i, &(_, ts, te)) in toks.iter().enumerate() {
        if ts == 0 && te == 0 {
            continue; // [CLS]/[SEP]
        }
        // numpy argmax: FIRST index of the max (strictly-greater ⇒ first wins).
        let row = logits.row(i);
        let mut idx = 0usize;
        let mut best = row[0];
        for (j, &v) in row.iter().enumerate().skip(1) {
            if v > best {
                best = v;
                idx = j;
            }
        }
        let lab = if idx < labels.len() {
            labels[idx].as_str()
        } else {
            "O"
        };

        let cur_type = cur.as_ref().map(|c| c.0.as_str());
        if lab.starts_with("B-") || (lab.starts_with("I-") && cur_type.is_none()) {
            flush(&mut cur, chars, &mut ents);
            cur = Some((lab[2..].to_string(), ts, te));
        } else if lab.starts_with("I-") && cur_type == Some(&lab[2..]) {
            if let Some(c) = cur.as_mut() {
                c.2 = te;
            }
        } else {
            flush(&mut cur, chars, &mut ents);
        }
    }
    flush(&mut cur, chars, &mut ents);
    Ok(ents)
}

/// Port of `_OnnxEn.extract`: tokenize, run (single pass for ≤510 content
/// tokens, else overlapping windows unioned), dedup identical
/// `(start,end,type)` spans, then map raw types through `_NORM`, dropping
/// unmapped types. Char offsets throughout.
pub fn extract(model: &mut EnModel, text: &str) -> ort::Result<Vec<Span>> {
    if text.trim().is_empty() {
        return Ok(vec![]);
    }
    let chars: Vec<char> = text.chars().collect();
    let toks = model.wordpiece().encode(text); // [CLS] + content + [SEP]
    if toks.len() <= 2 {
        return Ok(vec![]); // no content between [CLS] and [SEP]
    }
    let content = &toks[1..toks.len() - 1];
    let budget = MAX_TOKENS - 2; // leave room for [CLS]/[SEP]
    let cls = model.wordpiece().cls_id;
    let sep = model.wordpiece().sep_id;

    let mut raw: Vec<RawEnt> = Vec::new();
    if content.len() <= budget {
        raw = run_window(model, &toks, &chars)?; // short input: single pass
    } else {
        let step = budget - WINDOW_OVERLAP_TOKENS;
        let mut i = 0usize;
        loop {
            let end = (i + budget).min(content.len());
            let block = &content[i..end];
            let mut framed: Vec<(i64, usize, usize)> = Vec::with_capacity(block.len() + 2);
            framed.push((cls, 0, 0));
            framed.extend_from_slice(block);
            framed.push((sep, 0, 0));
            raw.extend(run_window(model, &framed, &chars)?);
            if i + budget >= content.len() {
                break;
            }
            i += step;
        }
    }

    // Dedup identical (start, end, type) spans from window overlap, preserving
    // first-seen order (matches Python's `seen`/`merged` loop).
    let mut seen: HashSet<(usize, usize, String)> = HashSet::new();
    let mut spans: Vec<Span> = Vec::new();
    for (ty, s, e) in raw {
        if !seen.insert((s, e, ty.clone())) {
            continue;
        }
        if let Some(norm) = norm_type(&ty) {
            let stext: String = chars[s..e].iter().collect();
            spans.push(Span {
                entity_type: norm.to_string(),
                text: stext,
                start: s,
                end: e,
            });
        }
    }
    Ok(spans)
}
