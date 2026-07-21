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

/// Returns true if `s` contains a Han (CJK unified ideograph) character — those
/// rows exercise the Chinese backend, which this phase does not wire.
fn has_cjk(s: &str) -> bool {
    s.chars().any(|c| ('\u{4e00}'..='\u{9fff}').contains(&c))
}

/// Byte-exact parity check for the English backend: `NerGate::detect_strict`
/// must reproduce the golden spans generated from the LIVE Python NER pipeline
/// for every non-CJK row. Requires `SAVANA_NER_ASSETS` (model/vocab/config) and
/// `ORT_DYLIB_PATH` (the same libonnxruntime Python uses); skips gracefully
/// when the assets are absent (the no-asset CI tier), like the tokenize test.
#[test]
fn en_spans_match_python_golden() {
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
        if has_cjk(&row.text) {
            continue; // Chinese rows exercise the zh backend (not this phase).
        }
        let got = gate.detect_strict(&row.text);
        match (&row.error, got) {
            // The English golden corpus contains no error rows, but honour the
            // schema: an error row must map to a fail-closed Err.
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
                assert_eq!(spans, want, "EN span divergence on {:?}", row.text);
                asserted += 1;
            }
        }
    }
    assert!(
        asserted > 0,
        "no English rows asserted — golden corpus empty?"
    );
    eprintln!("en_spans_match_python_golden: asserted {asserted} English rows");
}
