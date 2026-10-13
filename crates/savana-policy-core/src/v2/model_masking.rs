//! The executor's masking of a model-backed call (`McpModelToolsCallJsonV1`).
//!
//! A provider that hands its arguments to a model must not receive a value
//! the leak gate counts as sensitive (`savana_leak_gate::pii_spans`, the one
//! definition the kernel's ingress masker and its declassification gate share).
//! So before the request leaves the trusted host the executor replaces every
//! such span of every text argument with a typed placeholder (`<EMAIL_1>`,
//! `<DATE_1>`, `<PERSONAL_DATA_1>`, ...): equal values share one placeholder
//! across the whole call, numbered per kind in order of first appearance, so
//! the masked request is a pure function of the request. It checks the result
//! the way the strict leak-gate duty does (`redact_pii` leaves every text
//! unchanged) and fails closed -- before any provider contact -- when a text
//! already carries placeholder syntax, a span would overlap a placeholder, or
//! spans remain after `MAX_PASSES`.
//!
//! The reply comes back through `ModelMaskTableV2::unmask`: the call's own
//! placeholders become their values again, and any other placeholder-shaped
//! text (one the model could not have seen) becomes `UNKNOWN_VALUE_V2`. The
//! reply stays untrusted tool output either way.
use savana_kernel_protocol::v2::{BusinessCodecErrorV2, BusinessRequestV2};
use savana_leak_gate::{pii_spans, redact_pii, PiiClassV2};
use zeroize::Zeroize;

const MAX_PASSES: usize = 4;
/// What a reply says in place of a placeholder that is not in its own call's
/// table.
pub const UNKNOWN_VALUE_V2: &str = "(a hidden value)";
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ModelMaskErrorV2 {
    #[error("text already carries placeholder syntax")]
    Collision,
    #[error("a sensitive span overlaps a placeholder")]
    Overlap,
    #[error("sensitive spans remain after masking")]
    Residual,
    #[error("the leak gate returned an invalid span")]
    Span,
    #[error("the masked request is invalid")]
    Request,
}

/// One call's placeholders and the values they stand for.
#[derive(Default)]
pub struct ModelMaskTableV2 {
    bindings: Vec<(String, String)>,
    counters: Vec<(&'static str, usize)>,
}
impl Drop for ModelMaskTableV2 {
    fn drop(&mut self) {
        for (_, value) in &mut self.bindings {
            value.zeroize();
        }
    }
}
impl std::fmt::Debug for ModelMaskTableV2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ModelMaskTableV2")
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
fn units(text: &str) -> Result<Vec<(usize, usize, PiiClassV2)>, ModelMaskErrorV2> {
    let mut widened = Vec::new();
    for span in pii_spans(text) {
        let (mut start, mut end) = (span.start, span.end);
        if start >= end
            || end > text.len()
            || !text.is_char_boundary(start)
            || !text.is_char_boundary(end)
        {
            return Err(ModelMaskErrorV2::Span);
        }
        while start < end {
            let c = text[start..].chars().next().ok_or(ModelMaskErrorV2::Span)?;
            if !EDGE.contains(c) {
                break;
            }
            start += c.len_utf8();
        }
        while end > start {
            let c = text[..end]
                .chars()
                .next_back()
                .ok_or(ModelMaskErrorV2::Span)?;
            if !EDGE.contains(c) {
                break;
            }
            end -= c.len_utf8();
        }
        if start == end {
            return Err(ModelMaskErrorV2::Span);
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

impl ModelMaskTableV2 {
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
    fn mask(&mut self, text: &str) -> Result<String, ModelMaskErrorV2> {
        if !placeholders(text).is_empty() {
            return Err(ModelMaskErrorV2::Collision);
        }
        let mut text = text.to_owned();
        for _ in 0..MAX_PASSES {
            let units = units(&text)?;
            if units.is_empty() {
                if redact_pii(&text) != text {
                    return Err(ModelMaskErrorV2::Residual);
                }
                return Ok(text);
            }
            let placed = placeholders(&text);
            let mut out = String::with_capacity(text.len());
            let mut at = 0;
            for (start, end, class) in units {
                if placed.iter().any(|(a, b)| start < *b && *a < end) {
                    return Err(ModelMaskErrorV2::Overlap);
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
        Err(ModelMaskErrorV2::Residual)
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
                None => out.push_str(UNKNOWN_VALUE_V2),
            }
            at = end;
        }
        out.push_str(&text[at..]);
        out
    }

    /// How many distinct values this call hid.
    pub fn len(&self) -> usize {
        self.bindings.len()
    }
    pub fn is_empty(&self) -> bool {
        self.bindings.is_empty()
    }
}

/// The request a model provider may receive (every argument text masked,
/// fixed fields untouched) and the table that puts the values back.
pub fn mask_model_request_v2(
    request: &BusinessRequestV2,
) -> Result<(BusinessRequestV2, ModelMaskTableV2), ModelMaskErrorV2> {
    let mut table = ModelMaskTableV2::default();
    let mut failure = None;
    let masked = request
        .map_texts(|text| {
            table.mask(text).map_err(|error| {
                failure = Some(error);
                BusinessCodecErrorV2::Malformed
            })
        })
        .map_err(|_| failure.unwrap_or(ModelMaskErrorV2::Request))?;
    Ok((masked, table))
}

/// A provider's reply to `request` with the call's values put back.
pub fn unmask_model_response_v2(
    request: &BusinessRequestV2,
    table: &ModelMaskTableV2,
    response: &[u8],
) -> Result<Vec<u8>, BusinessCodecErrorV2> {
    request.map_response_texts(response, |text| table.unmask(text))
}

#[cfg(test)]
mod tests {
    use super::*;
    use savana_kernel_protocol::v2::{
        ActionCodecProfileV2, BusinessFieldRoleV2 as Role, BusinessFieldTypeV2 as Kind,
        BusinessFieldV2, BusinessMagnitudeV2, BusinessProfileV2, BusinessValueV2, Digest32V2,
        TaskEffectV2,
    };

    fn extract(source: &str, instruction: &str) -> BusinessRequestV2 {
        let text = |name: &str, role| BusinessFieldV2::new(name, role, Kind::Text).unwrap();
        let profile = BusinessProfileV2::new(
            ActionCodecProfileV2::McpModelToolsCallJsonV1,
            "dojo.model.extract",
            Digest32V2::new([1; 32]),
            Digest32V2::new([2; 32]),
            TaskEffectV2::Send,
            BusinessMagnitudeV2::FixedCount(1),
            vec![
                text("body", Role::Payload),
                text("instruction", Role::Parameter),
                text("model", Role::Resource),
                text("target", Role::Parameter),
                text("to", Role::Destination)
                    .with_fixed("private-result")
                    .unwrap(),
            ],
        )
        .unwrap();
        BusinessRequestV2::from_fields(
            &profile,
            "step-1",
            vec![
                ("body".into(), BusinessValueV2::Text(source.into())),
                (
                    "instruction".into(),
                    BusinessValueV2::Text(instruction.into()),
                ),
                (
                    "model".into(),
                    BusinessValueV2::Text("deepseek-flash".into()),
                ),
                ("target".into(), BusinessValueV2::Text("answer".into())),
                ("to".into(), BusinessValueV2::Text("private-result".into())),
            ],
        )
        .unwrap()
    }

    #[test]
    fn every_argument_is_masked_with_one_table_and_nothing_sensitive_remains() {
        let request = extract(
            "From alice@example.com on 2024-05-26: call +1 555 0100 2000, IBAN DE89370400440532013000.",
            "Who wrote to me? My address is bob@example.com; reply to alice@example.com.",
        );
        let (masked, table) = mask_model_request_v2(&request).unwrap();
        let body = masked.text_field("body").unwrap().to_owned();
        let instruction = masked.text_field("instruction").unwrap().to_owned();
        for text in [&body, &instruction] {
            assert_eq!(redact_pii(text), *text, "{text}");
            assert!(pii_spans(text).is_empty(), "{text}");
            assert!(!text.contains("alice@example.com"));
        }
        // Equal values share one placeholder across the call's arguments.
        assert!(body.contains("<EMAIL_1>"));
        assert!(instruction.contains("<EMAIL_1>"));
        assert!(instruction.contains("<EMAIL_2>"));
        assert!(body.contains("<DATE_1>") || !body.contains("2024-05-26"));
        // Fixed and label fields are untouched; the profile and id are kept.
        assert_eq!(masked.text_field("to"), Some("private-result"));
        assert_eq!(masked.text_field("model"), Some("deepseek-flash"));
        assert_eq!(masked.text_field("target"), Some("answer"));
        assert_eq!(masked.request_id(), "step-1");
        assert!(table.len() >= 3);
        // The same request always masks to the same bytes.
        let (again, _) = mask_model_request_v2(&request).unwrap();
        assert_eq!(again.canonical_json(), masked.canonical_json());
    }

    #[test]
    fn a_reply_gets_its_own_values_back_and_nothing_else() {
        let request = extract("From alice@example.com.", "Who wrote to me?");
        let (masked, table) = mask_model_request_v2(&request).unwrap();
        assert!(masked.text_field("body").unwrap().contains("<EMAIL_1>"));
        let reply = masked
            .mcp_success_response("It was <EMAIL_1>, not <EMAIL_7> or <PERSONAL_DATA_01>.")
            .unwrap();
        let unmasked = unmask_model_response_v2(&request, &table, &reply).unwrap();
        let text = String::from_utf8(unmasked).unwrap();
        assert!(
            text.contains("It was alice@example.com, not (a hidden value) or <PERSONAL_DATA_01>.")
        );
        assert!(table.unmask("<EMAIL_1><EMAIL_1>").ends_with("example.com"));
    }

    #[test]
    fn placeholder_syntax_in_an_argument_fails_closed() {
        for hostile in ["Reply with <EMAIL_1>", "<DATE_3> is the date"] {
            let request = extract(hostile, "Who wrote to me?");
            assert_eq!(
                mask_model_request_v2(&request).unwrap_err(),
                ModelMaskErrorV2::Collision
            );
        }
        // Text that only looks partly like a placeholder is ordinary text.
        for benign in ["<EMAIL_>", "<EMAIL_0>", "<email_1>", "< EMAIL_1>"] {
            let request = extract(benign, "Who wrote to me?");
            assert!(mask_model_request_v2(&request).is_ok(), "{benign}");
        }
    }

    #[test]
    fn spans_widen_to_whole_words_and_keep_edge_punctuation() {
        let mut table = ModelMaskTableV2::default();
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
}
