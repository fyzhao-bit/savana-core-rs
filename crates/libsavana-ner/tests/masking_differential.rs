//! Broad differential harness: Rust masking primitives vs live CPython 15.0.0.
//!
//! This is the honesty backstop behind the small committed conformance rows —
//! it sweeps the WHOLE codepoint space (1,112,064 scalars) for NFKC + casefold
//! and a ~10k-string corpus (incl. dense combining-mark canonical-reordering
//! torture) + ~6k leak-gate + ~4k script fuzz, so a Unicode-version skew or a
//! lookaround-emulation bug can't hide behind a handful of ASCII-ish vectors.
//!
//! Reference data comes from CPython via `vectors/gen/gen_masking_vectors.py
//! --ref-out <dir>`. The tests are a NO-OP unless `MASKING_REF_DIR` points at
//! that dir, so they never run in ordinary `cargo test` (the multi-MB corpus is
//! not vendored — it is regenerable and deterministic). Run explicitly:
//!   MASKING_REF_DIR=<dir> cargo test -p libsavana-ner \
//!     --test masking_differential -- --nocapture

use libsavana_ner::masking::{
    canonical_scan_forms, casefold, folded_scan_map, masked_text_is_clean, normalize,
    require_supported_script,
};
use serde_json::Value;
use std::fs;

fn ref_dir() -> Option<String> {
    std::env::var("MASKING_REF_DIR").ok()
}

fn load(dir: &str, name: &str) -> Value {
    serde_json::from_str(&fs::read_to_string(format!("{dir}/{name}")).unwrap()).unwrap()
}

fn cps_to_string(v: &Value) -> String {
    v.as_array()
        .unwrap()
        .iter()
        .map(|x| char::from_u32(x.as_u64().unwrap() as u32).unwrap())
        .collect()
}

fn is_surr(cp: u32) -> bool {
    (0xD800..=0xDFFF).contains(&cp)
}

#[test]
fn nfkc_single_codepoint_sweep() {
    let Some(dir) = ref_dir() else {
        eprintln!("SKIP nfkc sweep (set MASKING_REF_DIR)");
        return;
    };
    // Reference: {cp: [nfkc cps]} for every cp whose NFKC differs from identity.
    let m = load(&dir, "nfkc_diff.json");
    let m = m.as_object().unwrap();
    use unicode_normalization::UnicodeNormalization;
    let mut fails = 0u64;
    let mut checked = 0u64;
    for cp in 0u32..0x110000 {
        if is_surr(cp) {
            continue;
        }
        let c = char::from_u32(cp).unwrap();
        let got: String = std::iter::once(c).nfkc().collect();
        let want: String = match m.get(&cp.to_string()) {
            Some(v) => cps_to_string(v),
            None => c.to_string(),
        };
        checked += 1;
        if got != want {
            if fails < 20 {
                eprintln!(
                    "NFKC DIFF cp=U+{cp:04X} got={:?} want={:?}",
                    got.chars()
                        .map(|c| format!("{:04X}", c as u32))
                        .collect::<Vec<_>>(),
                    want.chars()
                        .map(|c| format!("{:04X}", c as u32))
                        .collect::<Vec<_>>(),
                );
            }
            fails += 1;
        }
    }
    eprintln!("NFKC single-cp sweep: {checked} checked, {fails} diffs");
    assert_eq!(fails, 0, "NFKC diverged from CPython 15.0.0");
}

#[test]
fn casefold_single_codepoint_sweep() {
    let Some(dir) = ref_dir() else {
        eprintln!("SKIP casefold sweep (set MASKING_REF_DIR)");
        return;
    };
    let m = load(&dir, "casefold.json");
    let m = m.as_object().unwrap();
    let mut fails = 0u64;
    let mut checked = 0u64;
    for cp in 0u32..0x110000 {
        if is_surr(cp) {
            continue;
        }
        let c = char::from_u32(cp).unwrap();
        let got = casefold(&c.to_string());
        let want: String = match m.get(&cp.to_string()) {
            Some(v) => cps_to_string(v),
            None => c.to_string(),
        };
        checked += 1;
        if got != want {
            if fails < 20 {
                eprintln!("CASEFOLD DIFF cp=U+{cp:04X} got={got:?} want={want:?}");
            }
            fails += 1;
        }
    }
    eprintln!("casefold single-cp sweep: {checked} checked, {fails} diffs");
    assert_eq!(fails, 0, "casefold diverged from CPython 15.0.0");
}

#[test]
fn end_to_end_corpus() {
    let Some(dir) = ref_dir() else {
        eprintln!("SKIP corpus (set MASKING_REF_DIR)");
        return;
    };
    let corpus = load(&dir, "corpus.json");
    let mut norm_fail = 0u64;
    let mut fsm_fail = 0u64;
    let mut canon_fail = 0u64;
    let rows = corpus.as_array().unwrap();
    for row in rows {
        let s = cps_to_string(&row["in"]);

        // normalize
        if let Some(exp) = row["normalize"].as_array() {
            let want: String = exp
                .iter()
                .map(|x| char::from_u32(x.as_u64().unwrap() as u32).unwrap())
                .collect();
            let got = normalize(&s);
            if got != want {
                if norm_fail < 12 {
                    eprintln!("normalize DIFF in={s:?}\n  got={got:?}\n want={want:?}");
                }
                norm_fail += 1;
            }
        }

        // folded_scan_map
        if let Some(fsm) = row["fsm"].as_array() {
            let want_folded = fsm[0].as_str().unwrap();
            let want_s: Vec<usize> = fsm[1]
                .as_array()
                .unwrap()
                .iter()
                .map(|x| x.as_u64().unwrap() as usize)
                .collect();
            let want_e: Vec<usize> = fsm[2]
                .as_array()
                .unwrap()
                .iter()
                .map(|x| x.as_u64().unwrap() as usize)
                .collect();
            match folded_scan_map(&s) {
                Ok((folded, gs, ge)) => {
                    if folded != want_folded || gs != want_s || ge != want_e {
                        if fsm_fail < 12 {
                            eprintln!(
                                "fsm DIFF in={s:?}\n  got=({folded:?},{gs:?},{ge:?})\n want=({want_folded:?},{want_s:?},{want_e:?})"
                            );
                        }
                        fsm_fail += 1;
                    }
                }
                Err(e) => {
                    eprintln!("fsm ERR in={s:?} code={}", e.code);
                    fsm_fail += 1;
                }
            }
        }

        // canonical_scan_forms
        if let Some(canon) = row["canon"].as_array() {
            let (cp, cf) = canonical_scan_forms(&s);
            if cp != canon[0].as_str().unwrap() || cf != canon[1].as_str().unwrap() {
                if canon_fail < 12 {
                    eprintln!("canon DIFF in={s:?} got=({cp:?},{cf:?})");
                }
                canon_fail += 1;
            }
        }
    }
    eprintln!(
        "corpus {} rows: normalize {norm_fail} fail, fsm {fsm_fail} fail, canon {canon_fail} fail",
        rows.len()
    );
    assert_eq!(norm_fail + fsm_fail + canon_fail, 0, "corpus diverged");
}

#[test]
fn leak_gate_fuzz() {
    let Some(dir) = ref_dir() else {
        eprintln!("SKIP leak fuzz (set MASKING_REF_DIR)");
        return;
    };
    let rows = load(&dir, "leak_fuzz.json");
    let rows = rows.as_array().unwrap();
    let mut fails = 0u64;
    for row in rows {
        let s = cps_to_string(&row["in"]);
        let want = row["clean"].as_bool().unwrap();
        let got = masked_text_is_clean(&s);
        if got != want {
            if fails < 20 {
                eprintln!("leak DIFF in={s:?} got={got} want={want}");
            }
            fails += 1;
        }
    }
    eprintln!("leak-gate fuzz: {} rows, {fails} diffs", rows.len());
    assert_eq!(fails, 0, "masked_text_is_clean diverged from CPython");
}

#[test]
fn supported_script_fuzz() {
    let Some(dir) = ref_dir() else {
        eprintln!("SKIP script fuzz (set MASKING_REF_DIR)");
        return;
    };
    let rows = load(&dir, "script_fuzz.json");
    let rows = rows.as_array().unwrap();
    let mut fails = 0u64;
    for row in rows {
        let s = cps_to_string(&row["in"]);
        let want = row["ok"].as_bool().unwrap();
        let got = require_supported_script(&s).is_ok();
        if got != want {
            if fails < 20 {
                eprintln!("script DIFF in={s:?} got={got} want={want}");
            }
            fails += 1;
        }
    }
    eprintln!("supported-script fuzz: {} rows, {fails} diffs", rows.len());
    assert_eq!(fails, 0, "require_supported_script diverged from CPython");
}
