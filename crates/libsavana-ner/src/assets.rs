//! Asset readers for the ONNX NER backends. Mirrors
//! `server/security/ner_gate.py` lines 141-177 (`_read_labels`, `_read_dic`,
//! `_read_kv`) and the CRF transition-matrix load in `_OnnxZh.__init__`
//! (line 299: `np.fromfile(..., dtype="<f4").reshape(NTAGS, NTAGS)`).
//!
//! Pure parsing only — no ONNX runtime involved.

use crate::wordpiece::split_python_lines;
use ndarray::Array2;
use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::Path;

/// Mirrors Python `_read_dic(path, value_first=True)`: `{value: int(id)}`.
///
/// Each line is `"id\tvalue"`. A line is only considered if it contains a
/// tab strictly after the first character (`tab > 0` in Python, matching
/// `line.find("\t")`); a line starting with a tab, or with no tab at all, is
/// skipped.
///
/// The `id` prefix is parsed with `str::parse::<i64>`, mirroring Python's
/// `int(line[:tab])`, which raises `ValueError` on malformed input rather
/// than silently coercing it. Real asset files are well-formed, so this only
/// fires on a corrupt/foreign file — in that case this fails closed with an
/// `io::Error` (kind `InvalidData`) rather than panicking, so a bad asset
/// degrades to `NerGate::load` capturing `Err` (backend → `None`, gate
/// reports `ner_unavailable`) instead of unwinding past `.ok()`. The error
/// message is intentionally stable and does not echo the offending text.
pub fn read_dic_value_first<P: AsRef<Path>>(path: P) -> io::Result<HashMap<String, i64>> {
    let content = fs::read_to_string(path)?;
    let mut out = HashMap::new();
    for line in split_python_lines(&content) {
        if let Some(tab) = line.find('\t') {
            if tab > 0 {
                let id: i64 = line[..tab].parse().map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "read_dic_value_first: invalid id",
                    )
                })?;
                out.insert(line[tab + 1..].to_string(), id);
            }
        }
    }
    Ok(out)
}

/// Mirrors Python `_read_dic(path, value_first=False)`: `{int(id): value}`.
///
/// See [`read_dic_value_first`] for the line-parsing and id-parsing
/// semantics (identical here, only the resulting map's key/value roles are
/// swapped).
pub fn read_dic_id_first<P: AsRef<Path>>(path: P) -> io::Result<HashMap<i64, String>> {
    let content = fs::read_to_string(path)?;
    let mut out = HashMap::new();
    for line in split_python_lines(&content) {
        if let Some(tab) = line.find('\t') {
            if tab > 0 {
                let id: i64 = line[..tab].parse().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "read_dic_id_first: invalid id")
                })?;
                out.insert(id, line[tab + 1..].to_string());
            }
        }
    }
    Ok(out)
}

/// Mirrors Python `_read_kv`: `{key: value}` from `"key\tvalue"` lines.
///
/// Same tab-position rule as [`read_dic_value_first`]: a line is only kept
/// when it has a tab strictly after position 0.
pub fn read_kv<P: AsRef<Path>>(path: P) -> io::Result<HashMap<String, String>> {
    let content = fs::read_to_string(path)?;
    let mut out = HashMap::new();
    for line in split_python_lines(&content) {
        if let Some(tab) = line.find('\t') {
            if tab > 0 {
                out.insert(line[..tab].to_string(), line[tab + 1..].to_string());
            }
        }
    }
    Ok(out)
}

/// Mirrors Python `_read_labels`: reads a `config.json` with an `id2label`
/// object (`{"0": "O", "1": "B-MISC", ...}`) and returns
/// `[id2label[str(i)] for i in range(len(id2label))]`.
pub fn read_labels<P: AsRef<Path>>(path: P) -> io::Result<Vec<String>> {
    let content = fs::read_to_string(path)?;
    let json: serde_json::Value = serde_json::from_str(&content)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let id2 = json
        .get("id2label")
        .and_then(|v| v.as_object())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "config.json: missing id2label object",
            )
        })?;
    let n = id2.len();
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let key = i.to_string();
        let val = id2.get(&key).and_then(|v| v.as_str()).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("config.json: id2label missing contiguous key {key:?}"),
            )
        })?;
        out.push(val.to_string());
    }
    Ok(out)
}

/// Mirrors `np.fromfile(path, dtype="<f4").reshape(ntags, ntags)` from
/// `_OnnxZh.__init__`: reads the whole file as little-endian `f32`s and
/// reshapes into an `ntags x ntags` row-major matrix.
///
/// Unlike `np.fromfile` (which would silently drop trailing bytes that
/// don't form a full element, and `reshape` would then raise if the element
/// count doesn't divide evenly), a byte count that doesn't exactly equal
/// `ntags * ntags * 4` is treated as a hard error here — no truncation.
pub fn read_crf<P: AsRef<Path>>(path: P, ntags: usize) -> io::Result<Array2<f32>> {
    let bytes = fs::read(path)?;
    let expected = ntags
        .checked_mul(ntags)
        .and_then(|n| n.checked_mul(4))
        .expect("read_crf: ntags too large, byte-count computation overflowed");
    if bytes.len() != expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "crf.bin size mismatch: expected {expected} bytes for a {ntags}x{ntags} f32 matrix, got {}",
                bytes.len()
            ),
        ));
    }
    let data: Vec<f32> = bytes
        .chunks_exact(4)
        .map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect();
    Array2::from_shape_vec((ntags, ntags), data)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn temp_with(contents: &[u8]) -> NamedTempFile {
        let mut f = NamedTempFile::new().expect("create temp file");
        f.write_all(contents).expect("write temp file");
        f
    }

    #[test]
    fn read_dic_value_first_and_id_first() {
        let f = temp_with(b"0\tOOV\n5\t\xe4\xb8\xad\n"); // "0\tOOV\n5\t中\n"
        let value_first = read_dic_value_first(f.path()).unwrap();
        assert_eq!(value_first.get("OOV"), Some(&0));
        assert_eq!(value_first.get("中"), Some(&5));
        assert_eq!(value_first.len(), 2);

        let id_first = read_dic_id_first(f.path()).unwrap();
        assert_eq!(id_first.get(&5), Some(&"中".to_string()));
        assert_eq!(id_first.get(&0), Some(&"OOV".to_string()));
        assert_eq!(id_first.len(), 2);
    }

    #[test]
    fn read_kv_reads_key_value_pairs() {
        let f = temp_with("，\t,\n".as_bytes());
        let m = read_kv(f.path()).unwrap();
        assert_eq!(m.get("，"), Some(&",".to_string()));
        assert_eq!(m.len(), 1);
    }

    #[test]
    fn read_labels_from_config_json() {
        let f = temp_with(br#"{"id2label":{"0":"O","1":"B-PER"}}"#);
        let labels = read_labels(f.path()).unwrap();
        assert_eq!(labels, vec!["O".to_string(), "B-PER".to_string()]);
    }

    #[test]
    fn read_crf_round_trips_little_endian_f32() {
        let values: [f32; 4] = [1.5, -2.25, 0.0, 3.0];
        let mut bytes = Vec::new();
        for v in values {
            bytes.extend_from_slice(&v.to_le_bytes());
        }
        let f = temp_with(&bytes);
        let m = read_crf(f.path(), 2).unwrap();
        assert_eq!(m.shape(), [2, 2]);
        assert_eq!(m[[0, 0]], 1.5);
        assert_eq!(m[[0, 1]], -2.25);
        assert_eq!(m[[1, 0]], 0.0);
        assert_eq!(m[[1, 1]], 3.0);
    }

    #[test]
    fn read_crf_rejects_wrong_byte_count() {
        let f = temp_with(&[0u8; 4]); // one f32, but ntags=2 needs 4 f32s (16 bytes)
        let err = read_crf(f.path(), 2).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn read_dic_malformed_id_is_err_not_panic() {
        // A non-integer id prefix must fail closed with an `io::Error`
        // (kind `InvalidData`), not panic — a corrupt asset should degrade
        // to `NerGate::load` capturing `Err` and the gate reporting
        // `ner_unavailable`, never unwind past `.ok()`.
        let f = temp_with(b"nope\tOOV\n");
        let err = read_dic_value_first(f.path()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);

        let err = read_dic_id_first(f.path()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn leading_tab_line_is_skipped() {
        // Tab at index 0 ("\tx") must NOT be treated as a valid separator
        // (Python's `tab > 0` check is strict); only the well-formed second
        // line ("0\tOOV") should be picked up.
        let f = temp_with(b"\tx\n0\tOOV\n");
        let m = read_dic_value_first(f.path()).unwrap();
        assert_eq!(m.len(), 1);
        assert_eq!(m.get("OOV"), Some(&0));

        let kv = read_kv(f.path()).unwrap();
        assert_eq!(kv.len(), 1);
        assert_eq!(kv.get("0"), Some(&"OOV".to_string()));
    }

    /// Loads the real Android NER assets (word/tag/q2b dics, EN config.json,
    /// CRF binary) and prints summary stats, confirming the readers work on
    /// production data end-to-end. Gated behind `SAVANA_NER_ASSETS` since
    /// those files live outside this repo.
    ///
    /// Run with:
    ///   SAVANA_NER_ASSETS=/path/to/apps/android/app/src/main/assets/ner \
    ///     cargo test -p libsavana-ner real_assets_sanity -- --nocapture --ignored
    #[test]
    fn real_assets_sanity() {
        let Ok(dir) = std::env::var("SAVANA_NER_ASSETS") else {
            eprintln!("skipping real_assets_sanity: SAVANA_NER_ASSETS not set");
            return;
        };
        let base = Path::new(&dir);

        let tag = read_dic_id_first(base.join("zh/tag.dic")).unwrap();
        let word = read_dic_value_first(base.join("zh/word.dic")).unwrap();
        let q2b = read_kv(base.join("zh/q2b.dic")).unwrap();
        let labels = read_labels(base.join("en/config.json")).unwrap();
        let crf = read_crf(base.join("zh/crf.bin"), 59).unwrap();

        println!("tag.dic tags: {}", tag.len());
        println!("word.dic words: {}", word.len());
        println!("word.dic contains OOV: {}", word.contains_key("OOV"));
        println!("q2b.dic entries: {}", q2b.len());
        println!("en labels ({}): {:?}", labels.len(), labels);
        println!("crf.bin shape: {:?} (OK)", crf.shape());

        assert!(!tag.is_empty());
        assert!(!word.is_empty());
        assert!(word.contains_key("OOV"));
        assert_eq!(labels.len(), 9);
        assert_eq!(
            labels,
            vec!["O", "B-MISC", "I-MISC", "B-PER", "I-PER", "B-ORG", "I-ORG", "B-LOC", "I-LOC"]
        );
        assert_eq!(crf.shape(), [59, 59]);
    }
}
