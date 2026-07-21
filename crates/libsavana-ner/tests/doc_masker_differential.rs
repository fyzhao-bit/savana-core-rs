//! Differential: the Rust `doc_masker` pipeline vs the LIVE Python
//! `StrictDocumentMasker.mask_pages`, byte-exact.
//!
//! `vectors/conformance/doc_masker.json` is frozen by
//! `vectors/gen/gen_doc_masker_vectors.py`, which runs the REAL Python masker
//! orchestration over representative multi-page artifacts with a DETERMINISTIC
//! injected NER (a per-case surface→kind dictionary — the strict ONNX NER is
//! proven byte-exact separately, so injecting a deterministic detector isolates
//! and proves THIS port's new surface: the 2-phase reconciliation, the window
//! offset math, the cross-page seam split, the residual leak scan, and the
//! authenticated vault MINT). The `DictDetector` below mirrors that generator's
//! detector algorithm EXACTLY, and the Rust vault is minted with the SAME
//! secret/artifact/generation frozen into the vectors, so token HMAC tags must
//! match to the byte.
//!
//! Asserted per case: masked text per page AND per chunk, the vault token→raw
//! map (token strings incl. the hmac16), or the exact stable error code — and,
//! for every success case, that a minted token round-trips through the
//! already-ported `resolve`.

use libsavana_ner::doc_masker::{
    DetectedEntity, MaskedChunk, MaskedPage, NerDetect, NerDetectError, Observation, RawPage,
    StrictDocumentMasker,
};
use libsavana_ner::scoped_vault::ScopedDocumentVault;
use serde_json::Value;
use std::fs;

/// The deterministic injected NER — a byte-for-byte mirror of the generator's
/// `build_detector`: for each `(surface, kind)` in declaration order, every
/// NON-OVERLAPPING CHAR occurrence of `surface`, then a STABLE sort by start.
struct DictDetector {
    pairs: Vec<(Vec<char>, String)>,
}

fn find_sub(hay: &[char], needle: &[char], from: usize) -> Option<usize> {
    if needle.is_empty() {
        return Some(from.min(hay.len()));
    }
    if needle.len() > hay.len() {
        return None;
    }
    let mut i = from;
    while i + needle.len() <= hay.len() {
        if hay[i..i + needle.len()] == needle[..] {
            return Some(i);
        }
        i += 1;
    }
    None
}

impl NerDetect for DictDetector {
    fn detect(&mut self, text: &str) -> Result<Vec<DetectedEntity>, NerDetectError> {
        let tchars: Vec<char> = text.chars().collect();
        let mut out: Vec<DetectedEntity> = Vec::new();
        for (surf, kind) in &self.pairs {
            let mut start = 0usize;
            while let Some(pos) = find_sub(&tchars, surf, start) {
                out.push(DetectedEntity {
                    start: pos,
                    end: pos + surf.len(),
                    kind: kind.clone(),
                });
                start = pos + surf.len();
                if surf.is_empty() {
                    break;
                }
            }
        }
        out.sort_by_key(|e| e.start);
        Ok(out)
    }
}

fn vectors() -> Value {
    let path = format!(
        "{}/../../vectors/conformance/doc_masker.json",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}")))
        .unwrap()
}

fn hex_to_bytes(h: &str) -> Vec<u8> {
    (0..h.len() / 2)
        .map(|i| u8::from_str_radix(&h[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

fn build_detector(case: &Value) -> DictDetector {
    let pairs = case["dict"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| {
            let surf: Vec<char> = p[0].as_str().unwrap().chars().collect();
            let kind = p[1].as_str().unwrap().to_string();
            (surf, kind)
        })
        .collect();
    DictDetector { pairs }
}

fn build_pages(case: &Value) -> Vec<RawPage> {
    case["pages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| {
            let observations = p
                .get("obs")
                .and_then(|o| o.as_array())
                .map(|arr| {
                    arr.iter()
                        .map(|o| Observation {
                            text: o[0].as_str().unwrap().to_string(),
                            confidence: o[1].as_f64().unwrap(),
                        })
                        .collect()
                })
                .unwrap_or_default();
            RawPage {
                page_number: p["page_number"].as_i64().unwrap(),
                source: p
                    .get("source")
                    .and_then(|s| s.as_str())
                    .unwrap_or("text_layer")
                    .to_string(),
                text: p["text"].as_str().unwrap().to_string(),
                observations,
            }
        })
        .collect()
}

#[test]
fn doc_masker_pipeline_byte_exact() {
    let v = vectors();
    let secret = hex_to_bytes(v["secret_hex"].as_str().unwrap());
    let artifact_id = v["artifact_id"].as_str().unwrap();
    let generation = v["generation"].as_u64().unwrap() as u32;
    let mask_version = v["mask_version"].as_str().unwrap();

    let masker = StrictDocumentMasker::new();
    let mut fails = 0u64;
    let mut ok_cases = 0u64;
    let mut err_cases = 0u64;
    let mut roundtrips = 0u64;

    for case in v["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let mut detector = build_detector(case);
        let pages = build_pages(case);
        let mut vault = ScopedDocumentVault::new(&secret, artifact_id, generation, mask_version);
        let got = masker.mask_pages(&mut detector, artifact_id, generation, &pages, &mut vault);
        let expect = &case["expect"];

        if let Some(code) = expect.get("raises").and_then(|c| c.as_str()) {
            err_cases += 1;
            match got {
                Err(e) if e.code == code => {}
                other => {
                    fails += 1;
                    eprintln!("[{name}] expected raises {code}, got {other:?}");
                }
            }
            continue;
        }

        ok_cases += 1;
        let doc = match got {
            Ok(d) => d,
            Err(e) => {
                fails += 1;
                eprintln!("[{name}] expected ok, got Err({})", e.code);
                continue;
            }
        };
        let ok = &expect["ok"];

        // masked pages
        let want_pages: Vec<MaskedPage> = ok["pages"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| MaskedPage {
                page_number: p[0].as_i64().unwrap(),
                masked_text: p[1].as_str().unwrap().to_string(),
            })
            .collect();
        if doc.pages != want_pages {
            fails += 1;
            eprintln!("[{name}] PAGES diverged");
            for (g, w) in doc.pages.iter().zip(want_pages.iter()) {
                if g != w {
                    eprintln!(
                        "  p{} got={:?}\n       want={:?}",
                        g.page_number, g.masked_text, w.masked_text
                    );
                }
            }
            if doc.pages.len() != want_pages.len() {
                eprintln!(
                    "  page count got={} want={}",
                    doc.pages.len(),
                    want_pages.len()
                );
            }
        }

        // masked chunks
        let want_chunks: Vec<MaskedChunk> = ok["chunks"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| MaskedChunk {
                chunk_id: c[0].as_str().unwrap().to_string(),
                page_start: c[1].as_i64().unwrap(),
                page_end: c[2].as_i64().unwrap(),
                masked_text: c[3].as_str().unwrap().to_string(),
            })
            .collect();
        if doc.chunks != want_chunks {
            fails += 1;
            eprintln!("[{name}] CHUNKS diverged");
            for (g, w) in doc.chunks.iter().zip(want_chunks.iter()) {
                if g != w {
                    eprintln!("  got={g:?}\n  want={w:?}");
                }
            }
            if doc.chunks.len() != want_chunks.len() {
                eprintln!(
                    "  chunk count got={} want={}",
                    doc.chunks.len(),
                    want_chunks.len()
                );
            }
        }

        // vault token → raw, in first-put order (token strings incl. hmac16)
        let want_vault: Vec<(String, String)> = ok["vault"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| {
                (
                    e[0].as_str().unwrap().to_string(),
                    e[1].as_str().unwrap().to_string(),
                )
            })
            .collect();
        let got_vault = vault.entries_in_order();
        if got_vault != want_vault {
            fails += 1;
            eprintln!("[{name}] VAULT diverged");
            eprintln!("  got ={got_vault:?}");
            eprintln!("  want={want_vault:?}");
        }

        // Round-trip: a minted token rehydrates through the ported `resolve`.
        if let Some((token, raw)) = want_vault.first() {
            let digest = "evidence-digest-roundtrip";
            vault
                .authorize_evidence(digest, &[token.as_str()])
                .expect("authorize minted token");
            match vault.resolve(token, digest) {
                Ok(got_raw) if &got_raw == raw => roundtrips += 1,
                other => {
                    fails += 1;
                    eprintln!("[{name}] ROUNDTRIP failed: resolve={other:?} want raw={raw:?}");
                }
            }
        }
    }

    eprintln!(
        "doc_masker differential: {ok_cases} ok cases, {err_cases} error cases, \
         {roundtrips} mint→resolve round-trips, {fails} failures"
    );
    assert_eq!(fails, 0, "doc_masker pipeline diverged from live CPython");
}
