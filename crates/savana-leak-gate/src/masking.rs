//! Masking text before a model sees it: every span the leak gate counts as
//! sensitive ([`pii_spans`]) becomes a typed placeholder (`<EMAIL_1>`,
//! `<DATE_1>`, `<PERSONAL_DATA_1>`, ...), and a reply gets its own values back.
//!
//! One [`MaskTable`] serves one model call: equal values share one placeholder
//! across every text masked with it, numbered per kind in order of first
//! appearance, so the masked texts are a pure function of the texts and their
//! order. [`MaskTable::mask`] checks its result the way the strict leak-gate
//! duty does ([`redact_pii`] leaves the text unchanged) and fails closed when
//! a text already carries placeholder syntax, a span would overlap a
//! placeholder, or spans remain after `MAX_PASSES`. [`MaskTable::unmask`]
//! puts the call's own placeholders back and turns any other
//! placeholder-shaped text (one the model could not have seen) into
//! [`UNKNOWN_VALUE`].
//!
//! The kernel's executor masks a model-backed call with this table
//! (`savana_policy_core::v2::mask_model_request_v2`); the experiment harness
//! mirrors it through the Python binding, so both use this one definition.
use crate::{pii_spans, redact_pii, PiiClassV2};
use zeroize::Zeroize;

const MAX_PASSES: usize = 4;
/// What a reply says in place of a placeholder that is not in its own call's
/// table.
pub const UNKNOWN_VALUE: &str = "(a hidden value)";
const KINDS: [&str; 5] = [
    "CREDENTIAL",
    "PERSONAL_DATA",
    "PROTECTED_REFERENCE",
    "EMAIL",
    "DATE",
];
/// Punctuation a span may carry at its edges stays in the text; the masked
/// value is the token itself.
const EDGE: &str = "\"'\u{2018}\u{2019}\u{201c}\u{201d}()[]{}<>.,;:!?";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaskError {
    /// The text already carries placeholder syntax.
    Collision,
    /// A sensitive span overlaps a placeholder.
    Overlap,
    /// Sensitive spans remain after masking.
    Residual,
    /// The leak gate returned an invalid span.
    Span,
}
impl MaskError {
    /// Stable code, for evidence and for the Python surface.
    pub fn code(self) -> &'static str {
        match self {
            Self::Collision => "mask_collision",
            Self::Overlap => "mask_overlap",
            Self::Residual => "mask_residual",
            Self::Span => "mask_span",
        }
    }
}
impl std::fmt::Display for MaskError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}
impl std::error::Error for MaskError {}

/// One call's placeholders and the values they stand for.
#[derive(Default)]
pub struct MaskTable {
    bindings: Vec<(String, String)>,
    counters: Vec<(&'static str, usize)>,
}
impl Drop for MaskTable {
    fn drop(&mut self) {
        for (_, value) in &mut self.bindings {
            value.zeroize();
        }
    }
}
impl std::fmt::Debug for MaskTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MaskTable")
            .field("placeholders", &self.bindings.len())
            .finish_non_exhaustive()
    }
}

fn rank(class: PiiClassV2) -> u8 {
    match class {
        PiiClassV2::Credential => 0,
        PiiClassV2::PersonalData => 1,
        PiiClassV2::ProtectedReference => 2,
    }
}

fn kind(class: PiiClassV2, value: &str) -> &'static str {
    match class {
        PiiClassV2::PersonalData if value.contains('@') => "EMAIL",
        PiiClassV2::PersonalData if is_date(value) => "DATE",
        PiiClassV2::PersonalData => "PERSONAL_DATA",
        PiiClassV2::Credential => "CREDENTIAL",
        PiiClassV2::ProtectedReference => "PROTECTED_REFERENCE",
    }
}

fn is_date(value: &str) -> bool {
    let b = value.as_bytes();
    b.len() == 10
        && b.iter().enumerate().all(|(i, c)| {
            if i == 4 || i == 7 {
                *c == b'-'
            } else {
                c.is_ascii_digit()
            }
        })
}

/// Every placeholder in `text`, as byte ranges, in order.
fn placeholders(text: &str) -> Vec<(usize, usize)> {
    let mut found = Vec::new();
    let bytes = text.as_bytes();
    let mut at = 0;
    while let Some(offset) = text[at..].find('<') {
        let start = at + offset;
        let rest = &text[start + 1..];
        let matched = KINDS.iter().find_map(|kind| {
            let tail = rest.strip_prefix(kind)?.strip_prefix('_')?;
            let digits = tail.bytes().take_while(u8::is_ascii_digit).count();
            (digits > 0 && !tail.starts_with('0') && tail.as_bytes().get(digits) == Some(&b'>'))
                .then(|| start + 1 + kind.len() + 1 + digits + 1)
        });
        match matched {
            Some(end) => {
                found.push((start, end));
                at = end;
            }
            None => at = start + 1,
        }
        if at >= bytes.len() {
            break;
        }
    }
    found
}

/// The leak gate's spans in `text`: a span that is one alphanumeric run is
/// widened to the whole word it lies in, edge punctuation is trimmed, and
/// overlapping spans merge (the stronger class wins).
fn units(text: &str) -> Result<Vec<(usize, usize, PiiClassV2)>, MaskError> {
    let mut widened = Vec::new();
    for span in pii_spans(text) {
        let (mut start, mut end) = (span.start, span.end);
        if start >= end
            || end > text.len()
            || !text.is_char_boundary(start)
            || !text.is_char_boundary(end)
        {
            return Err(MaskError::Span);
        }
        while start < end {
            let c = text[start..].chars().next().ok_or(MaskError::Span)?;
            if !EDGE.contains(c) {
                break;
            }
            start += c.len_utf8();
        }
        while end > start {
            let c = text[..end].chars().next_back().ok_or(MaskError::Span)?;
            if !EDGE.contains(c) {
                break;
            }
            end -= c.len_utf8();
        }
        if start == end {
            return Err(MaskError::Span);
        }
        if text[start..end].chars().all(char::is_alphanumeric) {
            while let Some(c) = text[..start].chars().next_back() {
                if !c.is_alphanumeric() {
                    break;
                }
                start -= c.len_utf8();
            }
            while let Some(c) = text[end..].chars().next() {
                if !c.is_alphanumeric() {
                    break;
                }
                end += c.len_utf8();
            }
        }
        widened.push((start, end, span.class));
    }
    widened.sort_by_key(|(start, end, class)| (*start, *end, rank(*class)));
    let mut merged: Vec<(usize, usize, PiiClassV2)> = Vec::new();
    for (start, end, class) in widened {
        match merged.last_mut() {
            Some(last) if start < last.1 => {
                last.1 = last.1.max(end);
                if rank(class) < rank(last.2) {
                    last.2 = class;
                }
            }
            _ => merged.push((start, end, class)),
        }
    }
    Ok(merged)
}

impl MaskTable {
    fn placeholder(&mut self, class: PiiClassV2, value: &str) -> String {
        let kind = kind(class, value);
        let prefix = format!("<{kind}_");
        if let Some((placeholder, _)) = self
            .bindings
            .iter()
            .find(|(p, v)| p.starts_with(&prefix) && v == value)
        {
            return placeholder.clone();
        }
        let next = match self.counters.iter_mut().find(|(k, _)| *k == kind) {
            Some((_, n)) => {
                *n += 1;
                *n
            }
            None => {
                self.counters.push((kind, 1));
                1
            }
        };
        let placeholder = format!("<{kind}_{next}>");
        self.bindings.push((placeholder.clone(), value.to_owned()));
        placeholder
    }

    /// `text` with every sensitive span replaced, repeated until the leak
    /// gate finds nothing left.
    pub fn mask(&mut self, text: &str) -> Result<String, MaskError> {
        if !placeholders(text).is_empty() {
            return Err(MaskError::Collision);
        }
        let mut text = text.to_owned();
        for _ in 0..MAX_PASSES {
            let units = units(&text)?;
            if units.is_empty() {
                if redact_pii(&text) != text {
                    return Err(MaskError::Residual);
                }
                return Ok(text);
            }
            let placed = placeholders(&text);
            let mut out = String::with_capacity(text.len());
            let mut at = 0;
            for (start, end, class) in units {
                if placed.iter().any(|(a, b)| start < *b && *a < end) {
                    return Err(MaskError::Overlap);
                }
                out.push_str(&text[at..start]);
                let placeholder = self.placeholder(class, &text[start..end]);
                out.push_str(&placeholder);
                at = end;
            }
            out.push_str(&text[at..]);
            text.zeroize();
            text = out;
        }
        Err(MaskError::Residual)
    }

    /// A reply with this call's placeholders put back and every other
    /// placeholder neutralized.
    pub fn unmask(&self, text: &str) -> String {
        let mut out = String::with_capacity(text.len());
        let mut at = 0;
        for (start, end) in placeholders(text) {
            out.push_str(&text[at..start]);
            let placeholder = &text[start..end];
            match self.bindings.iter().find(|(p, _)| p == placeholder) {
                Some((_, value)) => out.push_str(value),
                None => out.push_str(UNKNOWN_VALUE),
            }
            at = end;
        }
        out.push_str(&text[at..]);
        out
    }

    /// Each placeholder with the value it stands for, in order of first
    /// appearance. For the owner's own side (binding a planner's placeholders
    /// back to its request's values); a model provider never sees this.
    pub fn bindings(&self) -> impl Iterator<Item = (&str, &str)> {
        self.bindings
            .iter()
            .map(|(placeholder, value)| (placeholder.as_str(), value.as_str()))
    }

    /// How many distinct values this call hid.
    pub fn len(&self) -> usize {
        self.bindings.len()
    }
    pub fn is_empty(&self) -> bool {
        self.bindings.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spans_widen_to_whole_words_and_keep_edge_punctuation() {
        let mut table = MaskTable::default();
        let masked = table
            .mask("Pay (DE89370400440532013000), then mail 'carol@example.org'.")
            .unwrap();
        assert!(masked.starts_with("Pay (<"), "{masked}");
        assert!(masked.contains("'<EMAIL_1>'."), "{masked}");
        assert_eq!(
            table.unmask(&masked),
            "Pay (DE89370400440532013000), then mail 'carol@example.org'."
        );
    }

    #[test]
    fn one_table_numbers_values_across_texts_and_fails_closed_on_placeholders() {
        let mut table = MaskTable::default();
        let first = table.mask("from ann@x.org on 2024-05-15").unwrap();
        let second = table.mask("ann@x.org and bob@x.org").unwrap();
        assert_eq!(first, "from <EMAIL_1> on <DATE_1>");
        assert_eq!(second, "<EMAIL_1> and <EMAIL_2>");
        assert_eq!(table.len(), 3);
        assert_eq!(
            table.unmask("<EMAIL_2>, <EMAIL_9>"),
            "bob@x.org, (a hidden value)"
        );
        assert_eq!(table.mask("say <DATE_1>"), Err(MaskError::Collision));
    }
}
