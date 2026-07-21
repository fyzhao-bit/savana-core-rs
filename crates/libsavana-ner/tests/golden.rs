use libsavana_ner::wordpiece::WordPiece;
use libsavana_ner::{NerGate, Span};
use std::path::Path;

fn vectors_dir() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("vectors")
}

#[derive(serde::Deserialize)]
struct TokRow {
    text: String,
    tokens: Vec<(i64, usize, usize)>,
}

#[test]
fn tokenize_matches_python_golden() {
    let path = vectors_dir().join("tokenize.json");
    if !path.exists() {
        eprintln!("SKIP: no tokenize.json");
        return;
    }
    let rows: Vec<TokRow> = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    if rows.is_empty() {
        eprintln!("SKIP: empty");
        return;
    }
    let assets = match std::env::var("SAVANA_NER_ASSETS") {
        Ok(a) => a,
        Err(_) => {
            eprintln!("SKIP: SAVANA_NER_ASSETS unset (no-asset tier)");
            return;
        }
    };
    let wp = WordPiece::from_vocab_file(Path::new(&assets).join("en/vocab.txt")).unwrap();
    for row in rows {
        let got = wp.encode(&row.text);
        assert_eq!(got, row.tokens, "tokenize divergence on {:?}", row.text);
    }
}

#[derive(serde::Deserialize)]
struct GoldenSpan {
    #[serde(rename = "type")]
    entity_type: String,
    text: String,
    start: usize,
    end: usize,
}

#[derive(serde::Deserialize)]
struct SpanRow {
    text: String,
    error: Option<String>,
    spans: Vec<GoldenSpan>,
}

/// Byte-exact parity check for the FULL pipeline: `NerGate::detect_strict`
/// must reproduce the golden spans generated from the LIVE Python NER pipeline
/// for EVERY row — English, Chinese, AND mixed EN+ZH — including the script
/// router and the cross-script overlap merge. Requires `SAVANA_NER_ASSETS`
/// (both backends' assets) and `ORT_DYLIB_PATH` (the same libonnxruntime
/// Python uses); skips gracefully when the assets are absent (the no-asset CI
/// tier), like the tokenize test.
#[test]
fn all_spans_match_python_golden() {
    let path = vectors_dir().join("spans.json");
    if !path.exists() {
        eprintln!("SKIP: no spans.json");
        return;
    }
    let rows: Vec<SpanRow> = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    if rows.is_empty() {
        eprintln!("SKIP: empty spans.json");
        return;
    }
    let assets = match std::env::var("SAVANA_NER_ASSETS") {
        Ok(a) => a,
        Err(_) => {
            eprintln!("SKIP: SAVANA_NER_ASSETS unset (no-asset tier)");
            return;
        }
    };
    let mut gate = NerGate::load(Path::new(&assets)).expect("load NerGate");

    let mut asserted = 0usize;
    for row in &rows {
        let got = gate.detect_strict(&row.text);
        match (&row.error, got) {
            // The golden corpus contains no error rows, but honour the schema:
            // an error row must map to a fail-closed Err.
            (Some(_), Ok(spans)) => {
                panic!("expected error for {:?}, got spans {:?}", row.text, spans)
            }
            (Some(_), Err(_)) => {}
            (None, Err(e)) => panic!("unexpected error for {:?}: {e:?}", row.text),
            (None, Ok(spans)) => {
                let want: Vec<Span> = row
                    .spans
                    .iter()
                    .map(|g| Span {
                        entity_type: g.entity_type.clone(),
                        text: g.text.clone(),
                        start: g.start,
                        end: g.end,
                    })
                    .collect();
                assert_eq!(spans, want, "span divergence on {:?}", row.text);
                asserted += 1;
            }
        }
    }
    assert!(asserted > 0, "no rows asserted — golden corpus empty?");
    eprintln!("all_spans_match_python_golden: asserted {asserted} rows (EN + ZH + mixed)");
}

#[derive(serde::Deserialize)]
struct ReadinessRow {
    text: String,
    needs_en: bool,
    needs_zh: bool,
}

/// Byte-exact parity check for the readiness heuristic: `readiness_flags` must
/// return `(needs_en, needs_zh)` from the LIVE Python
/// `NerGate._require_backends_ready` for every row. This is MODEL-FREE (pure
/// script counting), so — unlike the span goldens — it runs in the no-asset CI
/// tier with no dylib or ONNX assets required.
#[test]
fn readiness_matches_python_golden() {
    let path = vectors_dir().join("readiness.json");
    if !path.exists() {
        eprintln!("SKIP: no readiness.json");
        return;
    }
    let rows: Vec<ReadinessRow> = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert!(!rows.is_empty(), "readiness.json is empty");
    for row in &rows {
        let got = libsavana_ner::readiness_flags(&row.text);
        assert_eq!(
            got,
            (row.needs_en, row.needs_zh),
            "readiness divergence on {:?}",
            row.text
        );
    }
    eprintln!(
        "readiness_matches_python_golden: asserted {} rows (model-free)",
        rows.len()
    );
}
