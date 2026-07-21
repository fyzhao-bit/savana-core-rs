//! Port of `_WordPiece` from `server/security/ner_gate.py` lines 79-138.
//!
//! Offsets returned by `encode` are CHAR (Unicode scalar value / codepoint)
//! indices, matching Python `str` indexing — NOT byte offsets. We collect
//! input into `Vec<char>` and index by position to mirror that exactly.

use crate::chars::{is_cjk, is_control, is_punct, is_ws};
use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::Path;

/// BERT WordPiece tokenizer (cased), char-offset tracking.
pub struct WordPiece {
    vocab: HashMap<String, i64>,
    unk: String,
    max_chars: usize,
    pub unk_id: i64,
    pub cls_id: i64,
    pub sep_id: i64,
}

impl WordPiece {
    /// Mirrors Python `_WordPiece.__init__` defaults:
    /// unk="[UNK]", cls="[CLS]", sep="[SEP]", max_chars=200.
    pub fn new(vocab: HashMap<String, i64>) -> Self {
        let unk = "[UNK]".to_string();
        let unk_id = *vocab.get(unk.as_str()).unwrap_or(&100);
        let cls_id = *vocab.get("[CLS]").unwrap_or(&101);
        let sep_id = *vocab.get("[SEP]").unwrap_or(&102);
        Self {
            vocab,
            unk,
            max_chars: 200,
            unk_id,
            cls_id,
            sep_id,
        }
    }

    /// Reads a BERT vocab.txt (one token per line, id = 0-based line number),
    /// mirroring Python's `_read_vocab`:
    /// `{line.rstrip("\n"): i for i, line in enumerate(f)}`.
    pub fn from_vocab_file<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let content = fs::read_to_string(path)?;
        Ok(Self::new(read_vocab(&content)))
    }

    /// Mirrors Python `_WordPiece.encode`.
    pub fn encode(&self, text: &str) -> Vec<(i64, usize, usize)> {
        let mut out = Vec::new();
        out.push((self.cls_id, 0, 0));
        for (word, ws, _we) in self.words(text) {
            for (piece, ps, pe) in self.wordpiece(&word) {
                let id = *self.vocab.get(&piece).unwrap_or(&self.unk_id);
                out.push((id, ws + ps, ws + pe));
            }
        }
        out.push((self.sep_id, 0, 0));
        out
    }

    /// Mirrors Python `_WordPiece._words`.
    fn words(&self, text: &str) -> Vec<(String, usize, usize)> {
        let chars: Vec<char> = text.chars().collect();
        let n = chars.len();
        let mut words = Vec::new();
        let mut i = 0usize;
        while i < n {
            let c = chars[i];
            if is_ws(c) || is_control(c) {
                i += 1;
                continue;
            }
            if is_cjk(c as u32) || is_punct(c) {
                words.push((c.to_string(), i, i + 1));
                i += 1;
                continue;
            }
            let start = i;
            let mut sb = String::new();
            while i < n {
                let d = chars[i];
                if is_ws(d) || is_control(d) || is_cjk(d as u32) || is_punct(d) {
                    break;
                }
                sb.push(d);
                i += 1;
            }
            words.push((sb, start, i));
        }
        words
    }

    /// Mirrors Python `_WordPiece._wordpiece`.
    fn wordpiece(&self, word: &str) -> Vec<(String, usize, usize)> {
        let chars: Vec<char> = word.chars().collect();
        let n = chars.len();
        if n > self.max_chars {
            return vec![(self.unk.clone(), 0, n)];
        }
        let mut out = Vec::new();
        let mut start = 0usize;
        while start < n {
            let mut end = n;
            let mut cur: Option<String> = None;
            while start < end {
                let sub: String = chars[start..end].iter().collect();
                let piece = if start > 0 { format!("##{sub}") } else { sub };
                if self.vocab.contains_key(&piece) {
                    cur = Some(piece);
                    break;
                }
                end -= 1;
            }
            match cur {
                None => return vec![(self.unk.clone(), 0, n)],
                Some(p) => {
                    out.push((p, start, end));
                    start = end;
                }
            }
        }
        out
    }
}

/// Mirrors Python `_read_vocab`: `{line.rstrip("\n"): i for i, line in enumerate(f)}`,
/// where `open(path, encoding="utf-8")` applies universal-newline translation
/// (`\r\n` and lone `\r` become `\n`) before line splitting.
fn read_vocab(content: &str) -> HashMap<String, i64> {
    split_python_lines(content)
        .into_iter()
        .enumerate()
        .map(|(i, l)| (l, i as i64))
        .collect()
}

/// Splits file content into logical lines the way Python's `for line in f`
/// does for a UTF-8 text-mode file: universal-newline translation (`\r\n`
/// and lone `\r` become `\n`) is applied first, then a single trailing `\n`
/// terminates the last real line without producing a spurious extra
/// (empty-string) entry the way a naive `split('\n')` would. Each returned
/// element already has its line terminator stripped, matching
/// `line.rstrip("\n")`.
pub(crate) fn split_python_lines(content: &str) -> Vec<String> {
    let normalized = normalize_newlines(content);
    if normalized.is_empty() {
        return Vec::new();
    }
    let body = normalized.strip_suffix('\n').unwrap_or(&normalized);
    body.split('\n').map(|s| s.to_string()).collect()
}

fn normalize_newlines(s: &str) -> String {
    if !s.contains('\r') {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\r' {
            if chars.peek() == Some(&'\n') {
                chars.next();
            }
            out.push('\n');
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vocab(tokens: &[&str]) -> HashMap<String, i64> {
        tokens
            .iter()
            .enumerate()
            .map(|(i, t)| (t.to_string(), i as i64))
            .collect()
    }

    #[test]
    fn read_vocab_matches_python_enumerate_semantics() {
        // Trailing newline: 3 real lines, no spurious 4th empty entry.
        let m = read_vocab("a\nb\nc\n");
        assert_eq!(m.len(), 3);
        assert_eq!(m["c"], 2);

        // No trailing newline: last unterminated line still counts.
        let m = read_vocab("a\nb\nc");
        assert_eq!(m.len(), 3);
        assert_eq!(m["c"], 2);

        // Empty file: no lines.
        let m = read_vocab("");
        assert_eq!(m.len(), 0);

        // Blank line before EOF is a real (empty-string) entry.
        let m = read_vocab("a\n\n");
        assert_eq!(m.len(), 2);
        assert_eq!(m[""], 1);
    }

    #[test]
    fn encode_simple_word() {
        let wp = WordPiece::new(vocab(&["[UNK]", "[CLS]", "[SEP]", "hello", "world"]));
        let toks = wp.encode("hello");
        assert_eq!(toks[0], (wp.cls_id, 0, 0));
        assert_eq!(toks[1], (3, 0, 5));
        assert_eq!(toks[2], (wp.sep_id, 0, 0));
    }
}
