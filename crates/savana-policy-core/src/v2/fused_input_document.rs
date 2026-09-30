//! Typed owner input, committed through ordinary authenticated ingress.
//! Parsing is a non-improving derivation, not extraction, declassification, or
//! administrator import. The complete document must have received input consent.
use super::{G3Error, KernelValueV2};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FusedInputDocumentV04 {
    pub schema: u16,
    pub prompt: String,
    pub inputs: Vec<FusedInputTextV04>,
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
        if value.schema != 1 || value.prompt.is_empty() || value.prompt.len() > 16_384
            || value.inputs.is_empty() || value.inputs.len() > 256
            || value.inputs.iter().any(|i| i.slot == [0;16] || i.text.len() > 16_384)
            || value.inputs.windows(2).any(|p| p[0].slot >= p[1].slot) {
            return Err(G3Error::DeriveTypeMismatch);
        }
        Ok(value)
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
}
