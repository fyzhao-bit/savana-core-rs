//! Chinese Viterbi decode + BIO grouping — mirror of `_OnnxZh.extract` and
//! `_OnnxZh._viterbi` in `server/security/ner_gate.py` (lines 310-347).
//!
//! The ONNX run lives in [`crate::infer_zh::ZhModel::emissions`]; everything
//! here is deterministic: the CRF Viterbi best-path (first-max ties, matching
//! numpy `argmax`), then the char-level BIO grouping into `_KEEP`-mapped
//! spans. Offsets are CHAR indices into `text.chars()` — Python `str` slicing.

use crate::infer_zh::{ZhModel, NTAGS};
use crate::Span;
use ndarray::Array2;

/// Mirror of `_OnnxZh._KEEP`: LAC coarse label → normalised entity type.
/// Labels absent from the map are dropped by the caller.
fn keep(lab: &str) -> Option<&'static str> {
    match lab {
        "PER" => Some("NAME"),
        "LOC" => Some("PLACE"),
        "ORG" => Some("ORG"),
        "TIME" => Some("TIME"),
        "nz" | "nw" => Some("MISC"),
        _ => None,
    }
}

/// CRF Viterbi best path — port of `_OnnxZh._viterbi`.
///
/// `em` is `[seq, NTAGS]` emissions, `trans` is `[NTAGS, NTAGS]` with
/// `trans[from, to]`. For each destination tag `to` at step `t`, the best
/// source `from` maximises `dp[from] + trans[from, to]`; numpy `argmax`
/// breaks ties toward the LOWEST index (first-max), replicated by the strict
/// `>` comparison. The final tag is `argmax(dp)` (also first-max), then the
/// path is walked back through the stored back-pointers.
fn viterbi(em: &Array2<f32>, trans: &Array2<f32>, seq: usize) -> Vec<i64> {
    if seq == 0 {
        return Vec::new();
    }
    // dp = em[0].copy()
    let mut dp: Vec<f32> = em.row(0).to_vec();
    // back[t][to] = best `from` chosen for destination `to` at step t.
    let mut back = vec![vec![0i64; NTAGS]; seq];

    for t in 1..seq {
        let mut new_dp = vec![0f32; NTAGS];
        for to in 0..NTAGS {
            // argmax_from dp[from] + trans[from, to], first-max on ties.
            let mut best_from = 0usize;
            let mut best_score = dp[0] + trans[[0, to]];
            for from in 1..NTAGS {
                let s = dp[from] + trans[[from, to]];
                if s > best_score {
                    best_score = s;
                    best_from = from;
                }
            }
            back[t][to] = best_from as i64;
            new_dp[to] = best_score + em[[t, to]];
        }
        dp = new_dp;
    }

    let mut path = vec![0i64; seq];
    // path[seq-1] = argmax(dp), first-max.
    let mut best_i = 0usize;
    let mut best_v = dp[0];
    for (i, &v) in dp.iter().enumerate().skip(1) {
        if v > best_v {
            best_v = v;
            best_i = i;
        }
    }
    path[seq - 1] = best_i as i64;
    for t in (1..seq).rev() {
        path[t - 1] = back[t][path[t] as usize];
    }
    path
}

/// Look up a tag id, defaulting UNMAPPED ids (there are `NTAGS`=59 model tags
/// but only 49 in `tag.dic`) to the literal `"n-B"` — exactly Python's
/// `id2tag.get(int(tags[i]), "n-B")`. `"n-B".rsplit("-",1)[0]` == "n" (not in
/// `_KEEP` ⇒ dropped) and `"n-B".ends_with("-I")` is false.
fn tag_str(model: &ZhModel, id: i64) -> &str {
    model.id2tag().get(&id).map(String::as_str).unwrap_or("n-B")
}

/// Strip the trailing `-B`/`-I`/`-O` suffix — Python `raw.rsplit("-", 1)[0]`,
/// i.e. split on the LAST hyphen. `"PER-B"→"PER"`, `"nw-I"→"nw"`,
/// `"n-B"→"n"`, a tag with no hyphen → itself.
fn coarse(raw: &str) -> &str {
    raw.rsplit_once('-').map(|(head, _)| head).unwrap_or(raw)
}

/// Port of `_OnnxZh.extract`: empty/whitespace → `[]`; else compute
/// emissions, run Viterbi, and group the per-char tags into `_KEEP`-mapped
/// spans with CHAR offsets. A group starts at any tag, then extends over
/// following chars whose tag ends with `-I`; the group's coarse label decides
/// whether it is kept and how it is typed.
pub fn extract(model: &mut ZhModel, text: &str) -> ort::Result<Vec<Span>> {
    if text.trim().is_empty() {
        return Ok(vec![]);
    }
    let chars: Vec<char> = text.chars().collect();
    let n = chars.len();

    let em = model.emissions(&chars)?; // mutable borrow of model ends here
    let tags = viterbi(&em, model.trans(), n);

    let mut out: Vec<Span> = Vec::new();
    let mut i = 0usize;
    while i < n {
        let raw = tag_str(model, tags[i]);
        let lab = coarse(raw).to_string();
        let start = i;
        i += 1;
        while i < n && tag_str(model, tags[i]).ends_with("-I") {
            i += 1;
        }
        if let Some(norm) = keep(&lab) {
            let stext: String = chars[start..i].iter().collect();
            out.push(Span {
                entity_type: norm.to_string(),
                text: stext,
                start,
                end: i,
            });
        }
    }
    Ok(out)
}
