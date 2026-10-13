//! JSON exactly as the reference reads and writes it.
//!
//! Reading is CPython's `json.loads` (its C scanner, `strict=True`) under the
//! reference's explicit rules (`_json` in `dojo_compute.py`): a text that is
//! not JSON there is not JSON here, and every accepted text gives the same
//! value. Those rules are the scanner's own grammar (only `" \t\n\r"` is
//! whitespace, no control character inside a string, `\uXXXX` escapes, no
//! leading zeros, a leading U+FEFF refused) plus:
//!
//! * `NaN`, `Infinity` and `-Infinity` are refused;
//! * a string (or key) holding a lone surrogate is refused;
//! * arrays/objects nested more than [`MAX_JSON_DEPTH`] deep are refused;
//! * an integer literal of more than [`MAX_INT_DIGITS`] digits is refused
//!   (CPython's default `int_max_str_digits`).
//!
//! An object keeps its keys in first-seen order and a repeated key keeps its
//! first position with its last value, as a Python `dict` does. An integer
//! literal stays exact (Python `int`); a fraction or exponent makes a float,
//! read correctly rounded as Python's `float()` reads it (an overflowing
//! literal is infinite).
//!
//! Writing is `json.dumps(value, ensure_ascii=False, sort_keys=True)` for
//! `_text(dict)` and the escaping of `canonical()` for the step's output.

use std::collections::HashMap;

use crate::pyfloat;

/// Arrays/objects nested deeper than this make a text plain text.
pub(crate) const MAX_JSON_DEPTH: usize = 128;
/// An integer literal with more digits than this makes a text plain text.
pub(crate) const MAX_INT_DIGITS: usize = 4300;
/// Objects at least this large index their keys while parsing, so that a
/// repeated key is found in constant time.
const INDEXED_OBJECT: usize = 16;

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Value {
    Null,
    Bool(bool),
    /// A Python `int`: its decimal digits (no sign, no leading zero except
    /// for zero itself, which is never negative).
    Int {
        negative: bool,
        digits: String,
    },
    Float(f64),
    Str(String),
    List(Vec<Value>),
    /// Entries in first-seen order, keys unique.
    Object(Vec<(String, Value)>),
}

impl Value {
    /// `dict.get(key)` for an object; `None` for anything else.
    pub(crate) fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Object(entries) => entries.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }
}

/// `text` as JSON, or `None` when the reference would treat it as plain text.
pub(crate) fn parse(text: &str) -> Option<Value> {
    if text.starts_with('\u{feff}') {
        return None;
    }
    let mut parser = Parser {
        text,
        bytes: text.as_bytes(),
        pos: 0,
    };
    parser.skip_ws();
    let value = parser.value(0)?;
    parser.skip_ws();
    (parser.pos == parser.bytes.len()).then_some(value)
}

struct Parser<'a> {
    text: &'a str,
    bytes: &'a [u8],
    pos: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn peek_at(&self, offset: usize) -> Option<u8> {
        self.bytes.get(self.pos.checked_add(offset)?).copied()
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos += 1;
        }
    }

    fn skip_digits(&mut self) {
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.pos += 1;
        }
    }

    /// One value at `pos`; `depth` is the number of arrays/objects open
    /// around it.
    fn value(&mut self, depth: usize) -> Option<Value> {
        match self.peek()? {
            b'"' => {
                self.pos += 1;
                self.string().map(Value::Str)
            }
            b'{' => self.object(depth + 1),
            b'[' => self.array(depth + 1),
            b'n' => self.literal(b"null", Value::Null),
            b't' => self.literal(b"true", Value::Bool(true)),
            b'f' => self.literal(b"false", Value::Bool(false)),
            // `NaN`, `Infinity` and `-Infinity` are refused, and so is any
            // other text that is not a number.
            _ => self.number(),
        }
    }

    fn literal(&mut self, word: &[u8], value: Value) -> Option<Value> {
        let end = self.pos.checked_add(word.len())?;
        if self.bytes.get(self.pos..end)? != word {
            return None;
        }
        self.pos = end;
        Some(value)
    }

    fn object(&mut self, depth: usize) -> Option<Value> {
        if depth > MAX_JSON_DEPTH {
            return None;
        }
        self.pos += 1; // '{'
        let mut entries: Vec<(String, Value)> = Vec::new();
        let mut index: Option<HashMap<String, usize>> = None;
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Some(Value::Object(entries));
        }
        loop {
            if self.peek()? != b'"' {
                return None;
            }
            self.pos += 1;
            let key = self.string()?;
            self.skip_ws();
            if self.peek()? != b':' {
                return None;
            }
            self.pos += 1;
            self.skip_ws();
            let value = self.value(depth)?;
            insert(&mut entries, &mut index, key, value);
            self.skip_ws();
            match self.peek()? {
                b'}' => {
                    self.pos += 1;
                    return Some(Value::Object(entries));
                }
                b',' => {
                    self.pos += 1;
                    self.skip_ws();
                }
                _ => return None,
            }
        }
    }

    fn array(&mut self, depth: usize) -> Option<Value> {
        if depth > MAX_JSON_DEPTH {
            return None;
        }
        self.pos += 1; // '['
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Some(Value::List(items));
        }
        loop {
            items.push(self.value(depth)?);
            self.skip_ws();
            match self.peek()? {
                b']' => {
                    self.pos += 1;
                    return Some(Value::List(items));
                }
                b',' => {
                    self.pos += 1;
                    self.skip_ws();
                }
                _ => return None,
            }
        }
    }

    /// The rest of a string whose opening quote was read.
    fn string(&mut self) -> Option<String> {
        let mut out = String::new();
        loop {
            let start = self.pos;
            while let Some(byte) = self.peek() {
                if byte == b'"' || byte == b'\\' {
                    break;
                }
                if byte < 0x20 {
                    return None; // strict: a raw control character
                }
                self.pos += 1;
            }
            // `start..pos` ends before an ASCII byte (or at the end), so it
            // lies on character boundaries.
            out.push_str(self.text.get(start..self.pos)?);
            if self.peek()? == b'"' {
                self.pos += 1;
                return Some(out);
            }
            self.pos += 1; // '\\'
            let escape = self.peek()?;
            self.pos += 1;
            match escape {
                b'"' => out.push('"'),
                b'\\' => out.push('\\'),
                b'/' => out.push('/'),
                b'b' => out.push('\u{8}'),
                b'f' => out.push('\u{c}'),
                b'n' => out.push('\n'),
                b'r' => out.push('\r'),
                b't' => out.push('\t'),
                b'u' => {
                    let unit = self.hex4()?;
                    let code = match unit {
                        0xD800..=0xDBFF => {
                            // Only a high surrogate escape followed at once by
                            // a low surrogate escape is a character.
                            if self.peek() != Some(b'\\') || self.peek_at(1) != Some(b'u') {
                                return None;
                            }
                            self.pos += 2;
                            let low = self.hex4()?;
                            if !(0xDC00..=0xDFFF).contains(&low) {
                                return None;
                            }
                            0x10000 + ((unit - 0xD800) << 10) + (low - 0xDC00)
                        }
                        0xDC00..=0xDFFF => return None,
                        _ => unit,
                    };
                    out.push(char::from_u32(code)?);
                }
                _ => return None,
            }
        }
    }

    fn hex4(&mut self) -> Option<u32> {
        let mut unit = 0u32;
        for _ in 0..4 {
            let digit = char::from(self.peek()?).to_digit(16)?;
            unit = unit * 16 + digit;
            self.pos += 1;
        }
        Some(unit)
    }

    /// `-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][-+]?[0-9]+)?`, the longest match.
    fn number(&mut self) -> Option<Value> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        match self.peek()? {
            b'0' => self.pos += 1,
            b'1'..=b'9' => self.skip_digits(),
            _ => return None,
        }
        let mut is_float = false;
        if self.peek() == Some(b'.') && matches!(self.peek_at(1), Some(b'0'..=b'9')) {
            is_float = true;
            self.pos += 1;
            self.skip_digits();
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            let mark = self.pos;
            self.pos += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.pos += 1;
            }
            if matches!(self.peek(), Some(b'0'..=b'9')) {
                is_float = true;
                self.skip_digits();
            } else {
                self.pos = mark;
            }
        }
        let literal = self.text.get(start..self.pos)?;
        if is_float {
            return literal.parse::<f64>().ok().map(Value::Float);
        }
        let (negative, digits) = match literal.strip_prefix('-') {
            Some(digits) => (true, digits),
            None => (false, literal),
        };
        if digits.len() > MAX_INT_DIGITS {
            return None;
        }
        Some(Value::Int {
            negative: negative && digits != "0",
            digits: digits.to_string(),
        })
    }
}

/// A Python dict assignment: a new key goes last, a repeated key keeps its
/// place and takes the new value.
fn insert(
    entries: &mut Vec<(String, Value)>,
    index: &mut Option<HashMap<String, usize>>,
    key: String,
    value: Value,
) {
    if index.is_none() && entries.len() >= INDEXED_OBJECT {
        *index = Some(
            entries
                .iter()
                .enumerate()
                .map(|(at, (k, _))| (k.clone(), at))
                .collect(),
        );
    }
    let found = match index {
        Some(index) => index.get(&key).copied(),
        None => entries.iter().position(|(k, _)| *k == key),
    };
    match found {
        Some(at) => entries[at].1 = value,
        None => {
            if let Some(index) = index {
                index.insert(key.clone(), entries.len());
            }
            entries.push((key, value));
        }
    }
}

/// Appends `text` as a JSON string the way `json.dumps(..., ensure_ascii=False)`
/// writes it: only `"`, `\` and control characters are escaped.
pub(crate) fn escape_into(text: &str, out: &mut String) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                let code = c as usize;
                out.push_str("\\u00");
                out.push(char::from(HEX[code >> 4]));
                out.push(char::from(HEX[code & 0xf]));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// `json.dumps(value, ensure_ascii=False, sort_keys=True)`: separators
/// `", "` and `": "`, keys in code point order, floats as `repr`.
pub(crate) fn dumps_sorted(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Int { negative, digits } => {
            if *negative {
                out.push('-');
            }
            out.push_str(digits);
        }
        Value::Float(x) => {
            if x.is_nan() {
                out.push_str("NaN");
            } else if x.is_infinite() {
                out.push_str(if *x > 0.0 { "Infinity" } else { "-Infinity" });
            } else {
                out.push_str(&pyfloat::repr(*x));
            }
        }
        Value::Str(text) => escape_into(text, out),
        Value::List(items) => {
            out.push('[');
            for (at, item) in items.iter().enumerate() {
                if at > 0 {
                    out.push_str(", ");
                }
                dumps_sorted(item, out);
            }
            out.push(']');
        }
        Value::Object(entries) => {
            let mut sorted: Vec<&(String, Value)> = entries.iter().collect();
            sorted.sort_by(|a, b| a.0.cmp(&b.0));
            out.push('{');
            for (at, (key, item)) in sorted.into_iter().enumerate() {
                if at > 0 {
                    out.push_str(", ");
                }
                escape_into(key, out);
                out.push_str(": ");
                dumps_sorted(item, out);
            }
            out.push('}');
        }
    }
}
