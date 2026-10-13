//! Rows and texts: `table`, `_text`, `_number`, `_fold`, `_record_key`,
//! `_lookup`, `_bounded` and `_mode` of the reference.
//!
//! Python's whitespace (`str.isspace`, so `strip()`, `split()` and the `re`
//! class `\s`) is Unicode `White_Space` plus U+001C..U+001F ([`is_space`]);
//! its line boundaries (`str.splitlines`) are the ten in [`is_line_break`].
//! Both sets are written out here, so they depend on neither language's
//! Unicode tables. Folding does use tables: NFKC from unicode-normalization
//! 0.1.22 (Unicode 15.0, as CPython 3.12's `unicodedata`) and Rust 1.82's
//! lowercase (Unicode 15.1), which agrees with CPython 3.12's `str.lower()`
//! on every code point, final sigma included (`tests::unicode_tables`).

use std::collections::HashMap;

use unicode_normalization::UnicodeNormalization;

use crate::json::{self, Value};
use crate::pyfloat;
use crate::ComputeOutput;

pub(crate) const MAX_ROWS: usize = 256;
pub(crate) const MAX_ITEMS: usize = 32;
const MAX_ITEM_BYTES: usize = 160;
const MAX_TEXT_BYTES: usize = 480;
const SEPARATOR: &str = "; ";
/// `_record_key`: the fields that name a record, in order.
const KEY_FIELDS: [&str; 5] = ["id", "id_", "name", "title", "filename"];

/// Python's `str.isspace()`.
pub(crate) fn is_space(c: char) -> bool {
    matches!(
        c,
        '\t'..='\r'
            | '\u{1c}'..=' '
            | '\u{85}'
            | '\u{a0}'
            | '\u{1680}'
            | '\u{2000}'..='\u{200a}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{202f}'
            | '\u{205f}'
            | '\u{3000}'
    )
}

/// Python's `str.splitlines()` boundaries (`\r\n` counts once there; here
/// it yields an extra empty line, which every caller drops).
fn is_line_break(c: char) -> bool {
    matches!(
        c,
        '\n' | '\r'
            | '\u{b}'
            | '\u{c}'
            | '\u{1c}'
            | '\u{1d}'
            | '\u{1e}'
            | '\u{85}'
            | '\u{2028}'
            | '\u{2029}'
    )
}

/// Python's `str.strip()`.
pub(crate) fn strip(text: &str) -> &str {
    text.trim_matches(is_space)
}

/// `_fold`: NFKC, then full lowercase (`str.lower()`, with final sigma),
/// then `strip()`.
pub(crate) fn fold(text: &str) -> String {
    let normal: String = text.nfkc().collect();
    strip(&normal.to_lowercase()).to_string()
}

/// The first match of `-?[0-9]+(?:,[0-9]{3})*(?:\.[0-9]+)?` in `text`.
pub(crate) fn first_number(text: &str) -> Option<&str> {
    let bytes = text.as_bytes();
    let start = (0..bytes.len()).find(|&at| {
        bytes[at].is_ascii_digit()
            || (bytes[at] == b'-' && bytes.get(at + 1).is_some_and(u8::is_ascii_digit))
    })?;
    let mut end = start + usize::from(bytes[start] == b'-');
    while bytes.get(end).is_some_and(u8::is_ascii_digit) {
        end += 1;
    }
    while bytes.get(end) == Some(&b',')
        && (1..=3).all(|k| bytes.get(end + k).is_some_and(u8::is_ascii_digit))
    {
        end += 4;
    }
    if bytes.get(end) == Some(&b'.') && bytes.get(end + 1).is_some_and(u8::is_ascii_digit) {
        end += 1;
        while bytes.get(end).is_some_and(u8::is_ascii_digit) {
            end += 1;
        }
    }
    Some(&text[start..end])
}

/// `_number` of a text: its first number, commas removed, as a float.
pub(crate) fn text_number(text: &str) -> Option<f64> {
    first_number(text)?.replace(',', "").parse().ok()
}

/// Python's `float(int)` for an exact integer: correctly rounded, and
/// infinite beyond the float range (the reference's `_float`).
fn int_float(negative: bool, digits: &str) -> f64 {
    let magnitude: f64 = digits.parse().unwrap_or(f64::INFINITY);
    if negative {
        -magnitude
    } else {
        magnitude
    }
}

/// `_number`: a number's value, or a text's first number; `None` for
/// anything else.
pub(crate) fn value_number(value: &Value) -> Option<f64> {
    match value {
        Value::Int { negative, digits } => Some(int_float(*negative, digits)),
        Value::Float(x) => Some(*x),
        Value::Str(text) => text_number(text),
        _ => None,
    }
}

/// `_text`: a value as text; `None` only for null.
pub(crate) fn value_text(value: &Value) -> Option<String> {
    Some(match value {
        Value::Null => return None,
        Value::Bool(true) => "true".to_string(),
        Value::Bool(false) => "false".to_string(),
        Value::Int { negative, digits } => pyfloat::format_number(int_float(*negative, digits)),
        Value::Float(x) => pyfloat::format_number(*x),
        Value::Str(text) => text.clone(),
        Value::List(items) => {
            let parts: Vec<String> = items
                .iter()
                .filter_map(value_text)
                .filter(|t| !t.is_empty())
                .collect();
            parts.join(SEPARATOR)
        }
        Value::Object(_) => {
            let mut out = String::new();
            json::dumps_sorted(value, &mut out);
            out
        }
    })
}

/// `_record_key`: the first naming field with a text, else the position.
fn record_key(record: &Value, index: usize) -> String {
    KEY_FIELDS
        .iter()
        .filter_map(|name| record.get(name).and_then(value_text))
        .find(|text| !text.is_empty())
        .unwrap_or_else(|| (index + 1).to_string())
}

/// `table(text)`: one input's ordered `(key, value)` rows, at most
/// [`MAX_ROWS`], every key nonempty.
pub(crate) fn table(text: &str) -> Vec<(String, Value)> {
    let value = match json::parse(text) {
        Some(value) => value,
        None => return text_rows(text),
    };
    let mut rows = Vec::new();
    match value {
        Value::Object(entries) => {
            rows.extend(
                entries
                    .into_iter()
                    .filter(|(key, _)| !key.is_empty())
                    .take(MAX_ROWS),
            );
        }
        Value::List(items) => {
            for (index, item) in items.into_iter().enumerate() {
                let key = match &item {
                    Value::Object(_) => record_key(&item, index),
                    other => value_text(other).unwrap_or_default(),
                };
                if !key.is_empty() {
                    rows.push((key, item));
                    if rows.len() == MAX_ROWS {
                        break;
                    }
                }
            }
        }
        Value::Str(inner) => return text_rows(&inner),
        Value::Null => {}
        scalar => {
            if let Some(key) = value_text(&scalar).filter(|key| !key.is_empty()) {
                rows.push((key, scalar));
            }
        }
    }
    rows
}

/// A text's rows: its nonblank lines, stripped; a single line holding ";"
/// is split there; of several lines, a first line "Label: A" gives "A".
fn text_rows(text: &str) -> Vec<(String, Value)> {
    // One more line than the rows tells "more than one line" apart.
    let mut lines: Vec<&str> = text
        .split(is_line_break)
        .map(strip)
        .filter(|line| !line.is_empty())
        .take(MAX_ROWS + 1)
        .collect();
    let items: Vec<String> = if lines.len() == 1 && lines[0].contains(';') {
        lines[0]
            .split(';')
            .map(strip)
            .filter(|item| !item.is_empty())
            .take(MAX_ROWS)
            .map(str::to_string)
            .collect()
    } else {
        if lines.len() > 1 {
            if let Some(rest) = label_rest(lines[0]) {
                lines[0] = strip(rest);
            }
        }
        lines
            .into_iter()
            .take(MAX_ROWS)
            .map(str::to_string)
            .collect()
    };
    items
        .into_iter()
        .map(|line| (line.clone(), Value::Str(line)))
        .collect()
}

/// `_LABEL = ^[A-Za-z][A-Za-z ]{0,39}:\s*(\S.*)$` on one stripped line:
/// the text after the label, when there is one. (The reference's extra
/// "no digit before the colon" test always holds after this match.)
fn label_rest(line: &str) -> Option<&str> {
    let mut chars = line.char_indices();
    if !chars.next()?.1.is_ascii_alphabetic() {
        return None;
    }
    for (count, (at, c)) in chars.enumerate() {
        if c == ':' {
            // `.` excludes only "\n", which a line never holds.
            let rest = line[at + 1..].trim_start_matches(is_space);
            return (!rest.is_empty()).then_some(rest);
        }
        if !(c.is_ascii_alphabetic() || c == ' ') || count >= 39 {
            return None;
        }
    }
    None
}

/// `_lookup`: a joined input's rows by exact key, then by folded key (the
/// first row wins either way).
pub(crate) struct Lookup<'a> {
    exact: HashMap<&'a str, &'a Value>,
    folded: HashMap<String, &'a Value>,
}

impl<'a> Lookup<'a> {
    pub(crate) fn new(rows: &'a [(String, Value)]) -> Self {
        let mut exact = HashMap::new();
        let mut folded = HashMap::new();
        for (key, value) in rows {
            exact.entry(key.as_str()).or_insert(value);
            folded.entry(fold(key)).or_insert(value);
        }
        Lookup { exact, folded }
    }

    /// `exact[key] if key in exact else folded.get(_fold(key))`.
    pub(crate) fn get(&self, key: &str, folded_key: &mut Option<String>) -> Option<&'a Value> {
        if let Some(value) = self.exact.get(key) {
            return Some(value);
        }
        let folded_key = folded_key.get_or_insert_with(|| fold(key));
        self.folded.get(folded_key.as_str()).copied()
    }
}

/// `" ".join(text.split())`.
fn collapse(text: &str) -> String {
    let mut out = String::new();
    for word in text.split(is_space).filter(|word| !word.is_empty()) {
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(word);
    }
    out
}

/// The longest prefix of whole characters within `limit` bytes (UTF-8
/// truncation, then decoding with "ignore").
fn truncate(mut text: String, limit: usize) -> String {
    if text.len() > limit {
        let mut end = limit;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
    }
    text
}

/// `_bounded`: at most [`MAX_ITEMS`] items, each whitespace-collapsed and
/// cut to 160 bytes, kept while the joined text fits 480 bytes.
pub(crate) fn bounded(items: impl IntoIterator<Item = String>) -> ComputeOutput {
    let mut kept: Vec<String> = Vec::new();
    let mut size = 0usize;
    for item in items.into_iter().take(MAX_ITEMS) {
        let item = truncate(collapse(&item), MAX_ITEM_BYTES);
        size += item.len() + if kept.is_empty() { 0 } else { SEPARATOR.len() };
        if size > MAX_TEXT_BYTES {
            break;
        }
        kept.push(item);
    }
    ComputeOutput {
        text: kept.join(SEPARATOR),
        items: kept,
    }
}

/// `_mode`: the most frequent nonempty text (ties: the first in code point
/// order), or the empty output.
pub(crate) fn mode(texts: impl IntoIterator<Item = Option<String>>) -> ComputeOutput {
    let mut counts: HashMap<String, usize> = HashMap::new();
    for text in texts.into_iter().flatten().filter(|text| !text.is_empty()) {
        *counts.entry(text).or_insert(0) += 1;
    }
    let best = counts.values().copied().max().unwrap_or(0);
    match counts
        .into_iter()
        .filter(|(_, n)| *n == best)
        .map(|(text, _)| text)
        .min()
    {
        Some(text) => bounded([text]),
        None => ComputeOutput::default(),
    }
}
