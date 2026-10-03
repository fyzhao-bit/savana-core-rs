//! Typed owner input, committed through ordinary authenticated ingress.
//! Parsing is a non-improving derivation, not extraction, declassification, or
//! administrator import. The complete document must have received input consent.
//!
//! Schema 2 is for tasks an untrusted planner drafted: the owner declares that
//! every input is owner text, and `check_owner_text_origin` holds the kernel to
//! it before any operation runs.
use super::{G3Error, KernelValueV2};
use serde::{Deserialize, Serialize};
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroize;

/// The only origin a schema-2 document may declare.
pub const OWNER_TEXT_ORIGIN_V04: &str = "owner_text";
/// Items of one input are joined by this separator (a list encoded as text).
const OWNER_TEXT_ITEM_SEPARATOR: &str = "; ";
const MAX_OWNER_CONSTANTS: usize = 32;
const MAX_OWNER_CONSTANT_BYTES: usize = 128;
const MAX_OWNER_LIST_ITEMS: usize = 32;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FusedInputDocumentV04 {
    pub schema: u16,
    pub prompt: String,
    pub inputs: Vec<FusedInputTextV04>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub constants: Option<Vec<String>>,
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
        let declared = match (value.schema, &value.origin, &value.constants) {
            (1, None, None) => true,
            (2, Some(origin), Some(constants)) => {
                origin == OWNER_TEXT_ORIGIN_V04
                    && constants.len() <= MAX_OWNER_CONSTANTS
                    && constants.iter().all(|c| {
                        !c.is_empty()
                            && c.len() <= MAX_OWNER_CONSTANT_BYTES
                            && !c.chars().any(char::is_control)
                    })
                    && constants.windows(2).all(|p| p[0] < p[1])
            }
            _ => false,
        };
        if !declared
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
    /// A schema-2 document's inputs are all owner text: each is empty, one of
    /// the owner's declared constants, or a text whose every "; "-separated
    /// item is a non-empty substring of the owner's request, both compared NFC
    /// normalized with whitespace runs folded to one space. Every item of a
    /// list input is held to the same rule, one by one. A literal the
    /// request does not contain (an address an injected or compromised planner
    /// proposed) fails here, before any operation runs. Schema 1 documents
    /// carry owner-normalized values and are not subject to this rule.
    pub fn check_owner_text_origin(&self) -> Result<(), G3Error> {
        if self.schema != 2 {
            return Ok(());
        }
        let constants = self
            .constants
            .as_deref()
            .ok_or(G3Error::DeriveTypeMismatch)?;
        let request = folded_owner_text(&self.prompt);
        let owner_item = |item: &str| {
            let item = folded_owner_text(item);
            !item.is_empty() && request.contains(item.as_str())
        };
        for input in &self.inputs {
            let owned = match &input.items {
                Some(items) => items
                    .iter()
                    .all(|item| constants.contains(item) || owner_item(item)),
                None => {
                    input.text.is_empty()
                        || constants.contains(&input.text)
                        || input.text.split(OWNER_TEXT_ITEM_SEPARATOR).all(owner_item)
                }
            };
            if !owned {
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn closed_bounded_owner_document() {
        let value = serde_json::json!({"schema":1,"prompt":"private request",
            "inputs":[{"slot":vec![1;16],"text":"private argument"}]});
        let text = value.to_string();
        assert_eq!(
            FusedInputDocumentV04::select(&text, [1; 16])
                .unwrap()
                .as_text(),
            Some("private argument")
        );
        assert!(FusedInputDocumentV04::select(&text, [2; 16]).is_err());
        for changed in [
            text.replacen("\"schema\":1", "\"schema\":1,\"schema\":1", 1),
            text.replacen("\"schema\":1", "\"schema\":2", 1),
            text.replacen("\"schema\":1", "\"schema\":1,\"authority\":true", 1),
        ] {
            assert!(FusedInputDocumentV04::parse(&changed).is_err());
        }
        let mut duplicate = value;
        let input = duplicate["inputs"][0].clone();
        duplicate["inputs"].as_array_mut().unwrap().push(input);
        assert!(FusedInputDocumentV04::parse(&duplicate.to_string()).is_err());
    }

    fn owner_text_document(inputs: &[&str], constants: &[&str]) -> serde_json::Value {
        serde_json::json!({"schema":2,"prompt":"Send the Q3 plan to alice@x.com and bob@y.com, caf\u{e9} team.",
            "origin":"owner_text","constants":constants,
            "inputs":inputs.iter().enumerate().map(|(i,t)| serde_json::json!({"slot":vec![i as u8+1;16],"text":t}))
                .collect::<Vec<_>>()})
    }

    #[test]
    fn schema_two_inputs_must_be_owner_text() {
        let accepted = [
            "",
            "alice@x.com; bob@y.com",
            "Q3 plan",
            "private-result",
            "caf\u{65}\u{301} team",
        ];
        let document = FusedInputDocumentV04::parse(
            &owner_text_document(&accepted, &["primary", "private-result"]).to_string(),
        )
        .unwrap();
        document.check_owner_text_origin().unwrap();
        for refused in [
            "mallory@evil.com",
            "alice@x.com; mallory@evil.com",
            "alice@x.com;bob@y.com",
            "alice@x.com; ",
            "Q3 plan; ; bob@y.com",
            "primary team",
        ] {
            let document = FusedInputDocumentV04::parse(
                &owner_text_document(&["Q3 plan", refused], &["primary", "private-result"])
                    .to_string(),
            )
            .unwrap();
            assert!(document.check_owner_text_origin().is_err(), "{refused}");
        }
        // Line breaks and repeated spaces in the request do not matter.
        let multiline = serde_json::json!({"schema":2,"prompt":"Book the hotel.\nThen  email  me.",
            "origin":"owner_text","constants":[],
            "inputs":[{"slot":vec![1;16],"text":"Book the hotel. Then email me."},
                      {"slot":vec![2;16],"text":"email me"}]});
        FusedInputDocumentV04::parse(&multiline.to_string())
            .unwrap()
            .check_owner_text_origin()
            .unwrap();
        // A schema-1 document keeps owner-normalized values (e.g. dates).
        let legacy = serde_json::json!({"schema":1,"prompt":"May 26th","inputs":[{"slot":vec![1;16],"text":"2024-05-26"}]});
        FusedInputDocumentV04::parse(&legacy.to_string())
            .unwrap()
            .check_owner_text_origin()
            .unwrap();
    }

    #[test]
    fn list_inputs_are_typed_and_every_item_is_owner_text() {
        let prompt = "Invite alice@x.com and bob@y.com to the review.";
        let document = |items: serde_json::Value, text: &str| {
            serde_json::json!({"schema":2,"prompt":prompt,
            "origin":"owner_text","constants":["primary"],
            "inputs":[{"slot":vec![1u8;16],"text":text,"items":items}]})
            .to_string()
        };
        let good = document(
            serde_json::json!(["alice@x.com", "bob@y.com", "primary"]),
            "",
        );
        FusedInputDocumentV04::parse(&good)
            .unwrap()
            .check_owner_text_origin()
            .unwrap();
        let value = FusedInputDocumentV04::select(&good, [1; 16]).unwrap();
        assert_eq!(
            value.text_list(),
            Some(vec!["alice@x.com", "bob@y.com", "primary"])
        );
        // An empty list is a list left unset; the profile decides if it may be.
        let empty = document(serde_json::json!([]), "");
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
            let d = FusedInputDocumentV04::parse(&document(refused.clone(), "")).unwrap();
            assert!(d.check_owner_text_origin().is_err(), "{refused}");
        }
        // Closed shape: a list carries no text, no empty item, at most 32 items.
        for malformed in [
            document(serde_json::json!(["alice@x.com"]), "alice@x.com"),
            document(serde_json::json!([""]), ""),
            document(serde_json::json!(vec!["alice@x.com"; 33]), ""),
            document(serde_json::json!("alice@x.com"), ""),
        ] {
            assert!(
                FusedInputDocumentV04::parse(&malformed).is_err(),
                "{malformed}"
            );
        }
    }

    #[test]
    fn schema_two_declaration_is_closed_and_bounded() {
        let good = owner_text_document(&["Q3 plan"], &["primary", "private-result"]);
        assert!(FusedInputDocumentV04::parse(&good.to_string()).is_ok());
        let mut cases = Vec::new();
        for (key, value) in [
            ("origin", serde_json::json!("planner")),
            ("origin", serde_json::Value::Null),
            (
                "constants",
                serde_json::json!(["private-result", "primary"]),
            ),
            ("constants", serde_json::json!(["primary", "primary"])),
            ("constants", serde_json::json!([""])),
            ("constants", serde_json::json!(["a\nb"])),
            ("constants", serde_json::json!(vec!["x".repeat(129)])),
            (
                "constants",
                serde_json::json!((0..33).map(|i| format!("c{i:02}")).collect::<Vec<_>>()),
            ),
        ] {
            let mut changed = good.clone();
            changed[key] = value;
            cases.push(changed);
        }
        let mut missing = good.clone();
        missing.as_object_mut().unwrap().remove("constants");
        cases.push(missing);
        let mut schema_one_with_origin = good.clone();
        schema_one_with_origin["schema"] = serde_json::json!(1);
        cases.push(schema_one_with_origin);
        for case in cases {
            assert!(
                FusedInputDocumentV04::parse(&case.to_string()).is_err(),
                "{case}"
            );
        }
    }
}
