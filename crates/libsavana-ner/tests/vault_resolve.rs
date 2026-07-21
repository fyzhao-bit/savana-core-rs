//! Golden test for `scoped_vault` resolve: HMAC tag + constant-time verify +
//! grant-scoped rehydration, frozen from the same CPython that owns
//! `server/documents/scoped_vault.py`. Fixture: tests/fixtures/…json.

use libsavana_ner::scoped_vault::ScopedDocumentVault;
use serde_json::Value;
use std::fs;

fn golden() -> Value {
    let path = format!(
        "{}/tests/fixtures/vault_resolve_golden.json",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap()
}

fn hex_to_bytes(h: &str) -> Vec<u8> {
    (0..h.len() / 2)
        .map(|i| u8::from_str_radix(&h[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

fn build(g: &Value) -> ScopedDocumentVault {
    let secret = hex_to_bytes(g["secret_hex"].as_str().unwrap());
    let mut vault = ScopedDocumentVault::new(
        &secret,
        g["artifact_id"].as_str().unwrap(),
        g["generation"].as_u64().unwrap() as u32,
        g["mask_version"].as_str().unwrap(),
    );
    // Re-issue exactly the golden puts (dedup + monotonic counters reproduce
    // the frozen tokens) and re-authorize the golden digest.
    for case in g["cases"].as_array().unwrap() {
        let kind = case["kind"].as_str().unwrap();
        let raw = case["raw"].as_str().unwrap();
        let tok = vault.put(kind, raw, &[1]).unwrap();
        assert_eq!(
            tok,
            case["token"].as_str().unwrap(),
            "token/tag mismatch for kind={kind} raw={raw}"
        );
        assert_eq!(
            vault.tag(kind, case["counter"].as_u64().unwrap() as u32),
            case["tag"].as_str().unwrap(),
            "tag mismatch"
        );
    }
    let digest = g["digest"].as_str().unwrap();
    let authorized: Vec<&str> = g["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c["authorized"].as_bool().unwrap())
        .map(|c| c["token"].as_str().unwrap())
        .collect();
    vault.authorize_evidence(digest, &authorized).unwrap();
    vault
}

#[test]
fn tokens_and_tags_byte_exact() {
    let g = golden();
    // build() asserts every token+tag reproduces CPython's HMAC output.
    let _ = build(&g);
}

#[test]
fn resolve_outcomes_match_cpython() {
    let g = golden();
    let vault = build(&g);
    let mut fails = 0;
    for r in g["resolve"].as_array().unwrap() {
        let token = r["token"].as_str().unwrap();
        let digest = r["digest"].as_str().unwrap();
        let out = &r["out"];
        let got = vault.resolve(token, digest);
        let ok = if let Some(raw) = out.get("raw") {
            got.as_deref().ok() == raw.as_str()
        } else {
            let code = out["code"].as_str().unwrap();
            got.as_ref().err().map(|e| e.code) == Some(code)
        };
        if !ok {
            fails += 1;
            eprintln!("resolve FAIL {}: got={got:?} want={out:?}", r["desc"]);
        }
    }
    assert_eq!(fails, 0, "vault resolve diverged from CPython");
}
