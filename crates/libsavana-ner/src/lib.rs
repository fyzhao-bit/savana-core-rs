//! libsavana-ner — Rust port of server/security/ner_gate.py entity detection.
use serde::{Deserialize, Serialize};

pub mod chars;
pub mod wordpiece;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EntityType {
    Name,
    Place,
    Org,
    Misc,
    Time,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Span {
    #[serde(rename = "type")]
    pub entity_type: String, // "NAME" | "PLACE" | "ORG" | "MISC" | "TIME"
    pub text: String,
    pub start: usize, // CHAR offset (see fidelity note)
    pub end: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    En,
    Zh,
}

#[derive(Debug, thiserror::Error)]
pub enum NerError {
    #[error("ner_unavailable")]
    Unavailable,
    #[error("ner_failed")]
    Failed,
}

#[cfg(test)]
mod smoke {
    use super::*;
    #[test]
    fn types_exist() {
        let s = Span {
            entity_type: "NAME".into(),
            text: "x".into(),
            start: 0,
            end: 1,
        };
        assert_eq!(s.end, 1);
        assert_eq!(EntityType::Name as u8, 0);
    }
}
