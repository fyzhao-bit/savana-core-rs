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
const MAX_OWNER_CONSTANTS: usize = 16;
const MAX_OWNER_CONSTANT_BYTES: usize = 128;

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

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FusedInputTextV04 {
    pub slot: [u8; 16],
    pub text: String,
}
impl Drop for FusedInputTextV04 {
    fn drop(&mut self) { self.text.zeroize(); }
}
impl Drop for FusedInputDocumentV04 {
    fn drop(&mut self) { self.prompt.zeroize(); }
}
impl FusedInputDocumentV04 {
    pub fn from_owned_value(value: &KernelValueV2) -> Result<Self, G3Error> {
        Self::parse(value.as_text().ok_or(G3Error::DeriveTypeMismatch)?)
    }
    pub fn parse(text: &str) -> Result<Self, G3Error> {
        if text.len() > 65_536 { return Err(G3Error::ValueEncodedBytesExceeded); }
        // Derived structs reject duplicate as well as unknown fields.
        let value: Self = serde_json::from_str(text).map_err(|_| G3Error::DeriveTypeMismatch)?;
        let declared = match (value.schema, &value.origin, &value.constants) {
            (1, None, None) => true,
            (2, Some(origin), Some(constants)) => origin == OWNER_TEXT_ORIGIN_V04
                && constants.len() <= MAX_OWNER_CONSTANTS
                && constants.iter().all(|c| !c.is_empty() && c.len() <= MAX_OWNER_CONSTANT_BYTES
                    && !c.chars().any(char::is_control))
                && constants.windows(2).all(|p| p[0] < p[1]),
            _ => false,
        };
        if !declared || value.prompt.is_empty() || value.prompt.len() > 16_384
            || value.inputs.is_empty() || value.inputs.len() > 256
            || value.inputs.iter().any(|i| i.slot == [0;16] || i.text.len() > 16_384)
            || value.inputs.windows(2).any(|p| p[0].slot >= p[1].slot) {
            return Err(G3Error::DeriveTypeMismatch);
        }
        Ok(value)
    }
    /// A schema-2 document's inputs are all owner text: each is empty, one of
    /// the owner's declared constants, or a text whose every "; "-separated
    /// item is a non-empty NFC substring of the owner's request. A literal the
    /// request does not contain (an address an injected or compromised planner
    /// proposed) fails here, before any operation runs. Schema 1 documents
    /// carry owner-normalized values and are not subject to this rule.
    pub fn check_owner_text_origin(&self) -> Result<(), G3Error> {
        if self.schema != 2 {
            return Ok(());
        }
        let constants = self.constants.as_deref().ok_or(G3Error::DeriveTypeMismatch)?;
        let request: String = self.prompt.nfc().collect();
        for input in &self.inputs {
            if input.text.is_empty() || constants.iter().any(|c| *c == input.text) {
                continue;
            }
            if !input.text.split(OWNER_TEXT_ITEM_SEPARATOR).all(|item| {
                !item.is_empty() && request.contains(item.nfc().collect::<String>().as_str())
            }) {
                return Err(G3Error::DeriveTypeMismatch);
            }
        }
        Ok(())
    }
    pub(super) fn select(text: &str, slot: [u8;16]) -> Result<KernelValueV2, G3Error> {
        let document = Self::parse(text)?;
        let input = document.inputs.iter().find(|i| i.slot == slot)
            .ok_or(G3Error::DeriveFieldMissing)?;
        KernelValueV2::text(input.text.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn closed_bounded_owner_document() {
        let value = serde_json::json!({"schema":1,"prompt":"private request",
            "inputs":[{"slot":vec![1;16],"text":"private argument"}]});
        let text = value.to_string();
        assert_eq!(FusedInputDocumentV04::select(&text,[1;16]).unwrap().as_text(),Some("private argument"));
        assert!(FusedInputDocumentV04::select(&text,[2;16]).is_err());
        for changed in [text.replacen("\"schema\":1", "\"schema\":1,\"schema\":1",1),
            text.replacen("\"schema\":1", "\"schema\":2",1),
            text.replacen("\"schema\":1", "\"schema\":1,\"authority\":true",1)] {
            assert!(FusedInputDocumentV04::parse(&changed).is_err());
        }
        let mut duplicate=value;
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
        let accepted = ["", "alice@x.com; bob@y.com", "Q3 plan", "private-result", "caf\u{65}\u{301} team"];
        let document = FusedInputDocumentV04::parse(
            &owner_text_document(&accepted, &["primary", "private-result"]).to_string()).unwrap();
        document.check_owner_text_origin().unwrap();
        for refused in ["mallory@evil.com", "alice@x.com; mallory@evil.com", "alice@x.com;bob@y.com",
                        "alice@x.com; ", "Q3 plan; ; bob@y.com", "primary team"] {
            let document = FusedInputDocumentV04::parse(
                &owner_text_document(&["Q3 plan", refused], &["primary", "private-result"]).to_string()).unwrap();
            assert!(document.check_owner_text_origin().is_err(), "{refused}");
        }
        // A schema-1 document keeps owner-normalized values (e.g. dates).
        let legacy = serde_json::json!({"schema":1,"prompt":"May 26th","inputs":[{"slot":vec![1;16],"text":"2024-05-26"}]});
        FusedInputDocumentV04::parse(&legacy.to_string()).unwrap().check_owner_text_origin().unwrap();
    }

    #[test]
    fn schema_two_declaration_is_closed_and_bounded() {
        let good = owner_text_document(&["Q3 plan"], &["primary", "private-result"]);
        assert!(FusedInputDocumentV04::parse(&good.to_string()).is_ok());
        let mut cases = Vec::new();
        for (key, value) in [("origin", serde_json::json!("planner")), ("origin", serde_json::Value::Null),
                             ("constants", serde_json::json!(["private-result", "primary"])),
                             ("constants", serde_json::json!(["primary", "primary"])),
                             ("constants", serde_json::json!([""])),
                             ("constants", serde_json::json!(["a\nb"])),
                             ("constants", serde_json::json!(vec!["x".repeat(129)])),
                             ("constants", serde_json::json!((0..17).map(|i| format!("c{i:02}")).collect::<Vec<_>>()))] {
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
            assert!(FusedInputDocumentV04::parse(&case.to_string()).is_err(), "{case}");
        }
    }
}
