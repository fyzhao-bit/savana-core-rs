//! Opt-in randomized fuzz differential for the `doc_masker` pipeline vs live
//! CPython — the broad honesty backstop behind the 16 committed conformance
//! cases. It sweeps ~800 random multi-page artifacts (non-ASCII-prefixed
//! structured PII stressing the byte→char offset conversion, overlapping and
//! seam-straddling dictionary entities, large multi-window pages, and the error
//! paths) so a regex-offset skew or a reconciliation-ordering bug can't hide.
//!
//! Reference data comes from CPython via
//!   PYTHONPATH=<jarvis> python vectors/gen/gen_doc_masker_vectors.py \
//!       --jarvis <jarvis> --fuzz-out <dir>
//! The test is a NO-OP unless `DOC_MASKER_FUZZ_DIR` points at that dir, so it
//! never runs in ordinary `cargo test` (the corpus is regenerable and
//! deterministic, not vendored). Run explicitly:
//!   DOC_MASKER_FUZZ_DIR=<dir> cargo test -p libsavana-ner \
//!       --test doc_masker_fuzz -- --nocapture

use libsavana_ner::doc_masker::{
    DetectedEntity, MaskedChunk, MaskedPage, NerDetect, NerDetectError, Observation, RawPage,
    StrictDocumentMasker,
};
use libsavana_ner::scoped_vault::ScopedDocumentVault;
use serde_json::Value;
use std::fs;

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
            (
                p[0].as_str().unwrap().chars().collect(),
                p[1].as_str().unwrap().to_string(),
            )
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
fn doc_masker_fuzz_byte_exact() {
    let Ok(dir) = std::env::var("DOC_MASKER_FUZZ_DIR") else {
        eprintln!("SKIP doc_masker fuzz (set DOC_MASKER_FUZZ_DIR)");
        return;
    };
    let raw = fs::read_to_string(format!("{dir}/doc_masker_fuzz.json")).unwrap();
    let v: Value = serde_json::from_str(&raw).unwrap();
    let secret = hex_to_bytes(v["secret_hex"].as_str().unwrap());
    let artifact_id = v["artifact_id"].as_str().unwrap();
    let generation = v["generation"].as_u64().unwrap() as u32;
    let mask_version = v["mask_version"].as_str().unwrap();
    let masker = StrictDocumentMasker::new();

    let mut fails = 0u64;
    let mut ok = 0u64;
    let mut err = 0u64;
    for case in v["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let mut detector = build_detector(case);
        let pages = build_pages(case);
        let mut vault = ScopedDocumentVault::new(&secret, artifact_id, generation, mask_version);
        let got = masker.mask_pages(&mut detector, artifact_id, generation, &pages, &mut vault);
        let expect = &case["expect"];

        if let Some(code) = expect.get("raises").and_then(|c| c.as_str()) {
            err += 1;
            match got {
                Err(e) if e.code == code => {}
                other => {
                    fails += 1;
                    if fails <= 20 {
                        eprintln!("[{name}] want raises {code}, got {other:?}");
                    }
                }
            }
            continue;
        }
        ok += 1;
        let doc = match got {
            Ok(d) => d,
            Err(e) => {
                fails += 1;
                if fails <= 20 {
                    eprintln!("[{name}] want ok, got Err({})", e.code);
                }
                continue;
            }
        };
        let want = &expect["ok"];
        let want_pages: Vec<MaskedPage> = want["pages"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| MaskedPage {
                page_number: p[0].as_i64().unwrap(),
                masked_text: p[1].as_str().unwrap().to_string(),
            })
            .collect();
        let want_chunks: Vec<MaskedChunk> = want["chunks"]
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
        let want_vault: Vec<(String, String)> = want["vault"]
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
        if doc.pages != want_pages
            || doc.chunks != want_chunks
            || vault.entries_in_order() != want_vault
        {
            fails += 1;
            if fails <= 20 {
                eprintln!("[{name}] DIVERGED");
                if doc.pages != want_pages {
                    eprintln!("  pages got ={:?}", doc.pages);
                    eprintln!("  pages want={want_pages:?}");
                }
                if doc.chunks != want_chunks {
                    eprintln!("  chunks got ={:?}", doc.chunks);
                    eprintln!("  chunks want={want_chunks:?}");
                }
                if vault.entries_in_order() != want_vault {
                    eprintln!("  vault got ={:?}", vault.entries_in_order());
                    eprintln!("  vault want={want_vault:?}");
                }
            }
        }
    }
    eprintln!(
        "doc_masker fuzz: {} cases ({ok} ok, {err} raises), {fails} failures",
        v["cases"].as_array().unwrap().len()
    );
    assert_eq!(fails, 0, "doc_masker fuzz diverged from live CPython");
}
