use libsavana_ner::wordpiece::WordPiece;
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
    let assets = std::env::var("SAVANA_NER_ASSETS").expect("SAVANA_NER_ASSETS for golden tests");
    let wp = WordPiece::from_vocab_file(Path::new(&assets).join("en/vocab.txt")).unwrap();
    for row in rows {
        let got = wp.encode(&row.text);
        assert_eq!(got, row.tokens, "tokenize divergence on {:?}", row.text);
    }
}
