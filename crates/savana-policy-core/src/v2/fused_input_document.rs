//! Typed owner input, committed through ordinary authenticated ingress.
//! Parsing is a non-improving derivation, not extraction, declassification, or
//! administrator import. The complete document must have received input consent.
//!
//! Schema 3 is the only accepted shape: the owner declares that every input
//! is its own text, and `check_owner_text_origin` holds the kernel to it --
//! field by field, against the plan's own bindings -- before any operation runs.
//! A value that is not the owner's request text is accepted only as a constant
//! the owner bound to the exact (operation, field) it fills, and never in a
//! destination-class field; a deployment-fixed field takes exactly its fixed
//! value.
use super::{G3Error, KernelValueV2};
use savana_kernel_protocol::v2::BusinessFieldV2;
use serde::{Deserialize, Serialize};
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroize;

/// The only origin a document may declare.
pub const OWNER_TEXT_ORIGIN_V04: &str = "owner_text";
/// The only accepted document schema.
pub const OWNER_DOCUMENT_SCHEMA_V04: u16 = 3;
/// Items of one input are joined by this separator (a list encoded as text).
const OWNER_TEXT_ITEM_SEPARATOR: &str = "; ";
const MAX_OWNER_CONSTANTS: usize = 32;
const MAX_OWNER_CONSTANT_BYTES: usize = 128;
const MAX_OWNER_CONSTANT_FIELDS: usize = 32;
const MAX_OWNER_LIST_ITEMS: usize = 32;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FusedInputDocumentV04 {
    pub schema: u16,
    pub prompt: String,
    pub inputs: Vec<FusedInputTextV04>,
    pub origin: String,
    pub constants: Vec<FusedOwnerConstantV04>,
}

/// A value the owner declares itself (a date it restated, a search term it
/// accepted, a label of the program), with every field it may fill.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FusedOwnerConstantV04 {
    pub value: String,
    pub fields: Vec<FusedFieldRefV04>,
}

/// One field of one operation: the business profile's operation name and the
/// field's name.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct FusedFieldRefV04 {
    pub operation: String,
    pub field: String,
}

/// Where the plan puts one owner input: a field of an operation's signed
/// business profile. The caller resolves these from the compiled plan's
/// bindings and the active descriptors; this module never trusts a name the
/// document gives.
pub struct OwnerInputUseV04<'a> {
    pub slot: [u8; 16],
    pub operation: &'a str,
    pub field: &'a BusinessFieldV2,
}

/// One owner input: a text, or (with `items`, and `text` empty) a list of
/// texts for a text-list field. The business profile still decides which
/// field each may fill: a list never fills a text field, nor a text a list.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FusedInputTextV04 {
    pub slot: [u8; 16],
    pub text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub items: Option<Vec<String>>,
}
impl Drop for FusedInputTextV04 {
    fn drop(&mut self) {
        self.text.zeroize();
        self.items.iter_mut().flatten().for_each(Zeroize::zeroize);
    }
}
impl FusedInputTextV04 {
    fn valid(&self) -> bool {
        match &self.items {
            None => self.text.len() <= 16_384,
            Some(items) => {
                self.text.is_empty()
                    && items.len() <= MAX_OWNER_LIST_ITEMS
                    && items.iter().all(|i| !i.is_empty())
                    && items.iter().map(String::len).sum::<usize>() <= 16_384
            }
        }
    }
}
impl Drop for FusedOwnerConstantV04 {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}
impl FusedOwnerConstantV04 {
    fn valid(&self) -> bool {
        !self.value.is_empty()
            && self.value.len() <= MAX_OWNER_CONSTANT_BYTES
            && !self.value.chars().any(char::is_control)
            && !self.fields.is_empty()
            && self.fields.len() <= MAX_OWNER_CONSTANT_FIELDS
            && self.fields.iter().all(|f| {
                !f.operation.is_empty()
                    && f.operation.len() <= 256
                    && !f.field.is_empty()
                    && f.field.len() <= 64
            })
            && self.fields.windows(2).all(|p| p[0] < p[1])
    }
    fn binds(&self, value: &str, operation: &str, field: &str) -> bool {
        self.value == value
            && self
                .fields
                .iter()
                .any(|f| f.operation == operation && f.field == field)
    }
}
impl Drop for FusedInputDocumentV04 {
    fn drop(&mut self) {
        self.prompt.zeroize();
    }
}
impl FusedInputDocumentV04 {
    pub fn from_owned_value(value: &KernelValueV2) -> Result<Self, G3Error> {
        Self::parse(value.as_text().ok_or(G3Error::DeriveTypeMismatch)?)
    }
    pub fn parse(text: &str) -> Result<Self, G3Error> {
        if text.len() > 65_536 {
            return Err(G3Error::ValueEncodedBytesExceeded);
        }
        // Derived structs reject duplicate as well as unknown fields.
        let value: Self = serde_json::from_str(text).map_err(|_| G3Error::DeriveTypeMismatch)?;
        if value.schema != OWNER_DOCUMENT_SCHEMA_V04
            || value.origin != OWNER_TEXT_ORIGIN_V04
            || value.constants.len() > MAX_OWNER_CONSTANTS
            || !value.constants.iter().all(FusedOwnerConstantV04::valid)
            || value.constants.windows(2).any(|p| p[0].value >= p[1].value)
            || value.prompt.is_empty()
            || value.prompt.len() > 16_384
            || value.inputs.is_empty()
            || value.inputs.len() > 256
            || value.inputs.iter().any(|i| i.slot == [0; 16] || !i.valid())
            || value.inputs.windows(2).any(|p| p[0].slot >= p[1].slot)
        {
            return Err(G3Error::DeriveTypeMismatch);
        }
        Ok(value)
    }
    /// Every input is owner text for every field the plan puts it in (`uses`;
    /// an input no field uses fails too):
    ///
    /// - a deployment-fixed field takes exactly its fixed text;
    /// - otherwise the input is empty (an unset parameter), or every
    ///   "; "-separated item of a text, and every item of a list, is the
    ///   owner's own request text: a non-empty substring of the request, both
    ///   compared NFC normalized with whitespace runs folded to one space. In
    ///   a destination-class field (a destination, cc, bcc, an address a read
    ///   fetches) the match must also be a whole token -- it cannot be extended
    ///   by a letter or digit on either side -- so "bob@company.co" is not taken
    ///   from "bob@company.com";
    /// - or, outside destination-class fields only, the item is a constant the
    ///   owner bound to exactly this operation and field.
    ///
    /// A literal the request does not contain (an address an injected or
    /// compromised planner proposed) fails here, before any operation runs.
    pub fn check_owner_text_origin(&self, uses: &[OwnerInputUseV04<'_>]) -> Result<(), G3Error> {
        let request = folded_owner_text(&self.prompt);
        let owned = |item: &str, use_: &OwnerInputUseV04<'_>| {
            let destination = use_.field.role().is_destination_class();
            let folded = folded_owner_text(item);
            (!folded.is_empty()
                && if destination {
                    contains_whole_token(&request, &folded)
                } else {
                    request.contains(folded.as_str())
                })
                || (!destination
                    && self
                        .constants
                        .iter()
                        .any(|c| c.binds(item, use_.operation, use_.field.name())))
        };
        for input in &self.inputs {
            let mut used = false;
            for use_ in uses.iter().filter(|u| u.slot == input.slot) {
                used = true;
                let ok = match (use_.field.fixed(), &input.items) {
                    (Some(fixed), None) => input.text == fixed,
                    (Some(_), Some(_)) => false,
                    (None, Some(items)) => items.iter().all(|item| owned(item, use_)),
                    (None, None) => {
                        input.text.is_empty()
                            || owned(&input.text, use_)
                            || input
                                .text
                                .split(OWNER_TEXT_ITEM_SEPARATOR)
                                .all(|item| owned(item, use_))
                    }
                };
                if !ok {
                    return Err(G3Error::DeriveTypeMismatch);
                }
            }
            if !used {
                return Err(G3Error::DeriveTypeMismatch);
            }
        }
        Ok(())
    }
    pub(super) fn select(text: &str, slot: [u8; 16]) -> Result<KernelValueV2, G3Error> {
        let document = Self::parse(text)?;
        let input = document
            .inputs
            .iter()
            .find(|i| i.slot == slot)
            .ok_or(G3Error::DeriveFieldMissing)?;
        match &input.items {
            None => KernelValueV2::text(input.text.clone()),
            Some(items) => KernelValueV2::list(
                items
                    .iter()
                    .map(|i| KernelValueV2::text(i.clone()))
                    .collect::<Result<_, _>>()?,
            ),
        }
    }
}

/// NFC with every whitespace run (line breaks included) folded to one space.
fn folded_owner_text(text: &str) -> String {
    let normalized: String = text.nfc().collect();
    normalized.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Characters that join the parts of one address ("alice.bob@x.com",
/// "www.x.com/page"); any other non-alphanumeric character (whitespace, ',',
/// ';', quotes, brackets) separates tokens.
fn joins_address(c: char) -> bool {
    matches!(
        c,
        '.' | '@' | '-' | '_' | '/' | ':' | '+' | '%' | '#' | '~' | '=' | '&' | '?'
    )
}

/// Whether `needle` occurs in `haystack` as a whole token: it has a letter or
/// digit, and the text on either side does not continue it -- with a letter
/// or digit, directly or after one joining character. So "bob@company.co" is
/// not taken from "bob@company.com", nor "bob@x.com" from "alice.bob@x.com",
/// while a sentence's final punctuation ("... to bob@x.com.") still ends it.
fn contains_whole_token(haystack: &str, needle: &str) -> bool {
    if !needle.chars().any(char::is_alphanumeric) {
        return false;
    }
    let continues =
        |mut side: std::iter::Peekable<&mut dyn Iterator<Item = char>>| match side.next() {
            None => false,
            Some(c) if c.is_alphanumeric() => true,
            Some(c) if joins_address(c) => side.peek().is_some_and(|c| c.is_alphanumeric()),
            Some(_) => false,
        };
    haystack.match_indices(needle).any(|(start, _)| {
        let mut before = haystack[..start].chars().rev();
        let mut after = haystack[start + needle.len()..].chars();
        !continues((&mut before as &mut dyn Iterator<Item = char>).peekable())
            && !continues((&mut after as &mut dyn Iterator<Item = char>).peekable())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use savana_kernel_protocol::v2::{BusinessFieldRoleV2 as Role, BusinessFieldTypeV2 as Kind};

    const PROMPT: &str =
        "Send the Q3 plan to alice@x.com and bob@y.com, caf\u{e9} team. Ask bob@company.com too.";

    fn document(inputs: serde_json::Value, constants: serde_json::Value) -> String {
        serde_json::json!({"schema":3,"prompt":PROMPT,"origin":"owner_text",
            "constants":constants,"inputs":inputs})
        .to_string()
    }
    fn texts(texts: &[&str]) -> serde_json::Value {
        serde_json::json!(texts
            .iter()
            .enumerate()
            .map(|(i, t)| serde_json::json!({"slot":vec![i as u8 + 1;16],"text":t}))
            .collect::<Vec<_>>())
    }
    fn field(name: &str, role: Role, kind: Kind) -> BusinessFieldV2 {
        BusinessFieldV2::new(name, role, kind).unwrap()
    }
    fn check(doc: &str, uses: &[(u8, &str, &BusinessFieldV2)]) -> Result<(), G3Error> {
        let uses: Vec<_> = uses
            .iter()
            .map(|(slot, operation, field)| OwnerInputUseV04 {
                slot: [*slot; 16],
                operation,
                field,
            })
            .collect();
        FusedInputDocumentV04::parse(doc)?.check_owner_text_origin(&uses)
    }

    #[test]
    fn closed_bounded_owner_document() {
        let text = document(texts(&["private argument"]), serde_json::json!([]));
        assert_eq!(
            FusedInputDocumentV04::select(&text, [1; 16])
                .unwrap()
                .as_text(),
            Some("private argument")
        );
        assert!(FusedInputDocumentV04::select(&text, [2; 16]).is_err());
        for changed in [
            text.replacen("\"schema\":3", "\"schema\":3,\"schema\":3", 1),
            text.replacen("\"schema\":3", "\"schema\":2", 1),
            text.replacen("\"schema\":3", "\"schema\":1", 1),
            text.replacen("\"schema\":3", "\"schema\":3,\"authority\":true", 1),
            text.replacen("\"origin\":\"owner_text\"", "\"origin\":\"planner\"", 1),
            text.replacen(",\"origin\":\"owner_text\"", "", 1),
            text.replacen("\"constants\":[],", "", 1),
        ] {
            assert!(FusedInputDocumentV04::parse(&changed).is_err(), "{changed}");
        }
        let mut duplicate: serde_json::Value = serde_json::from_str(&text).unwrap();
        let input = duplicate["inputs"][0].clone();
        duplicate["inputs"].as_array_mut().unwrap().push(input);
        assert!(FusedInputDocumentV04::parse(&duplicate.to_string()).is_err());
        // The legacy schemas are refused outright: no document skips the check.
        let legacy = serde_json::json!({"schema":1,"prompt":"May 26th",
            "inputs":[{"slot":vec![1;16],"text":"2024-05-26"}]});
        assert!(FusedInputDocumentV04::parse(&legacy.to_string()).is_err());
    }

    #[test]
    fn request_text_fills_any_field_and_a_destination_only_as_a_whole_token() {
        let subject = field("subject", Role::Parameter, Kind::Text);
        let to = field("to", Role::Destination, Kind::Text);
        for accepted in [
            "",
            "Q3 plan",
            "alice@x.com; bob@y.com",
            "caf\u{65}\u{301} team",
        ] {
            let doc = document(texts(&[accepted]), serde_json::json!([]));
            check(&doc, &[(1, "mail.send", &subject)]).unwrap();
        }
        for refused in [
            "mallory@evil.com",
            "alice@x.com; mallory@evil.com",
            "alice@x.com;bob@y.com",
            "alice@x.com; ",
            "Q3 plan; ; bob@y.com",
        ] {
            let doc = document(texts(&[refused]), serde_json::json!([]));
            assert!(
                check(&doc, &[(1, "mail.send", &subject)]).is_err(),
                "{refused}"
            );
        }
        // A destination must be a whole token of the request.
        for accepted in ["alice@x.com", "bob@y.com", "bob@company.com"] {
            let doc = document(texts(&[accepted]), serde_json::json!([]));
            check(&doc, &[(1, "mail.send", &to)]).unwrap();
        }
        for refused in [
            "bob@company.co",
            "ob@y.com",
            "company.com",
            "alice",
            "x.com",
            ",",
        ] {
            let doc = document(texts(&[refused]), serde_json::json!([]));
            assert!(check(&doc, &[(1, "mail.send", &to)]).is_err(), "{refused}");
            // The same text is ordinary request text for a parameter.
            if refused != "," {
                check(&doc, &[(1, "mail.send", &subject)]).unwrap();
            }
        }
        // Line breaks and repeated spaces in the request do not matter.
        let multiline = serde_json::json!({"schema":3,"prompt":"Book the hotel.\nThen  email  me.",
            "origin":"owner_text","constants":[],
            "inputs":[{"slot":vec![1;16],"text":"Book the hotel. Then email me."},
                      {"slot":vec![2;16],"text":"email me"}]})
        .to_string();
        check(
            &multiline,
            &[(1, "mail.send", &subject), (2, "mail.send", &subject)],
        )
        .unwrap();
    }

    #[test]
    fn whole_tokens_stop_at_separators_and_sentence_punctuation() {
        let request =
            "mail alice.bob@x.com, carol@y.com (dave@z.com) and visit www.site.org/page. ok";
        for token in [
            "alice.bob@x.com",
            "carol@y.com",
            "dave@z.com",
            "www.site.org/page",
            "ok",
        ] {
            assert!(contains_whole_token(request, token), "{token}");
        }
        for part in [
            "bob@x.com",
            "alice.bob@x.co",
            "site.org/page",
            "www.site.org",
            "arol@y.com",
            "",
            ".",
        ] {
            assert!(!contains_whole_token(request, part), "{part}");
        }
    }

    #[test]
    fn constants_fill_only_the_fields_they_are_bound_to_and_never_a_destination() {
        let day = field("day", Role::Parameter, Kind::Text);
        let query = field("query", Role::Parameter, Kind::Text);
        let to = field("to", Role::Destination, Kind::Text);
        let cc = field("cc", Role::CopyDestination, Kind::TextList);
        let constants = serde_json::json!([
            {"value":"2024-05-26","fields":[{"operation":"calendar.day","field":"day"}]},
            {"value":"mallory@evil.com","fields":[
                {"operation":"mail.search","field":"query"},
                {"operation":"mail.send","field":"cc"},
                {"operation":"mail.send","field":"to"}]},
        ]);
        let doc = document(texts(&["2024-05-26"]), constants.clone());
        check(&doc, &[(1, "calendar.day", &day)]).unwrap();
        // Bound to another operation or field: refused.
        assert!(check(&doc, &[(1, "calendar.search", &day)]).is_err());
        assert!(check(&doc, &[(1, "calendar.day", &query)]).is_err());
        let doc = document(texts(&["mallory@evil.com"]), constants.clone());
        check(&doc, &[(1, "mail.search", &query)]).unwrap();
        // Even bound, a constant never fills a destination-class field, and
        // a slot used twice is held to every use.
        assert!(check(&doc, &[(1, "mail.send", &to)]).is_err());
        assert!(check(&doc, &[(1, "mail.search", &query), (1, "mail.send", &to)]).is_err());
        let list = document(
            serde_json::json!([{"slot":vec![1u8;16],"text":"","items":["mallory@evil.com"]}]),
            constants,
        );
        assert!(check(&list, &[(1, "mail.send", &cc)]).is_err());
        // An input that no field uses is refused.
        let doc = document(texts(&["Q3 plan", "Q3 plan"]), serde_json::json!([]));
        assert!(check(&doc, &[(1, "mail.send", &query)]).is_err());
    }

    #[test]
    fn a_fixed_field_takes_exactly_its_fixed_value() {
        let to = field("to", Role::Destination, Kind::Text)
            .with_fixed("private-result")
            .unwrap();
        let body = field("body", Role::Payload, Kind::Text)
            .with_fixed("")
            .unwrap();
        let doc = document(texts(&["private-result", ""]), serde_json::json!([]));
        check(&doc, &[(1, "file.list", &to), (2, "file.list", &body)]).unwrap();
        for refused in ["alice@x.com", "private-result ", ""] {
            let doc = document(texts(&[refused]), serde_json::json!([]));
            assert!(check(&doc, &[(1, "file.list", &to)]).is_err(), "{refused}");
        }
        let list = document(
            serde_json::json!([{"slot":vec![1u8;16],"text":"","items":["private-result"]}]),
            serde_json::json!([]),
        );
        assert!(check(&list, &[(1, "file.list", &to)]).is_err());
    }

    #[test]
    fn list_inputs_are_typed_and_every_item_is_owner_text() {
        let recipients = field("recipients", Role::Destination, Kind::TextList);
        let doc = |items: serde_json::Value, text: &str| {
            document(
                serde_json::json!([{"slot":vec![1u8;16],"text":text,"items":items}]),
                serde_json::json!([]),
            )
        };
        let good = doc(serde_json::json!(["alice@x.com", "bob@y.com"]), "");
        check(&good, &[(1, "mail.send", &recipients)]).unwrap();
        let value = FusedInputDocumentV04::select(&good, [1; 16]).unwrap();
        assert_eq!(value.text_list(), Some(vec!["alice@x.com", "bob@y.com"]));
        // An empty list is a list left unset; the profile decides if it may be.
        let empty = doc(serde_json::json!([]), "");
        assert_eq!(
            FusedInputDocumentV04::select(&empty, [1; 16])
                .unwrap()
                .text_list(),
            Some(vec![])
        );
        // An item not in the request fails, as does a joined pair as one item.
        for refused in [
            serde_json::json!(["alice@x.com", "mallory@evil.com"]),
            serde_json::json!(["alice@x.com; bob@y.com"]),
        ] {
            assert!(
                check(&doc(refused.clone(), ""), &[(1, "mail.send", &recipients)]).is_err(),
                "{refused}"
            );
        }
        // Closed shape: a list carries no text, no empty item, at most 32 items.
        for malformed in [
            doc(serde_json::json!(["alice@x.com"]), "alice@x.com"),
            doc(serde_json::json!([""]), ""),
            doc(serde_json::json!(vec!["alice@x.com"; 33]), ""),
            doc(serde_json::json!("alice@x.com"), ""),
        ] {
            assert!(
                FusedInputDocumentV04::parse(&malformed).is_err(),
                "{malformed}"
            );
        }
    }

    #[test]
    fn constant_declarations_are_closed_and_bounded() {
        let bound = |value: &str| serde_json::json!({"value":value,"fields":[{"operation":"a.b","field":"c"}]});
        let good = document(
            texts(&["Q3 plan"]),
            serde_json::json!([bound("x"), bound("y")]),
        );
        assert!(FusedInputDocumentV04::parse(&good).is_ok());
        let two_fields = serde_json::json!({"value":"x","fields":[
            {"operation":"a.b","field":"d"},{"operation":"a.b","field":"c"}]});
        for constants in [
            serde_json::json!([bound("y"), bound("x")]),
            serde_json::json!([bound("x"), bound("x")]),
            serde_json::json!([bound("")]),
            serde_json::json!([bound("a\nb")]),
            serde_json::json!([bound(&"x".repeat(129))]),
            serde_json::json!((0..33)
                .map(|i| bound(&format!("c{i:02}")))
                .collect::<Vec<_>>()),
            serde_json::json!([{"value":"x","fields":[]}]),
            serde_json::json!([two_fields]),
            serde_json::json!(["x"]),
            serde_json::json!([{"value":"x","fields":[{"operation":"a.b","field":"c","extra":1}]}]),
        ] {
            let doc = document(texts(&["Q3 plan"]), constants.clone());
            assert!(FusedInputDocumentV04::parse(&doc).is_err(), "{constants}");
        }
    }
}
