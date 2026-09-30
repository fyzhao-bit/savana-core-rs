//! Closed, signed JSON projections for fixed public observation slots.
//! Parsing is not endorsement; selected text remains untrusted model input.
use crate::Error;
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::BTreeSet, fmt};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResultObservation {
    pub source: u16,
    /// Object keys or canonical decimal array indices; no wildcard, query,
    /// expression, recursive descent, or model-generated selector.
    pub path: Vec<String>,
}
impl ResultObservation {
    pub(crate) fn validate(&self) -> Result<(), Error> {
        if self.source == 0
            || self.path.len() > 16
            || self
                .path
                .iter()
                .any(|s| s.is_empty() || s.len() > 128 || s.chars().any(char::is_control))
        {
            return Err(Error::Invalid);
        }
        Ok(())
    }
}

/// Host-provided authenticated result snapshot. None is an explicitly approved
/// availability observation, not proof of failure or permission for a retry.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationSource {
    pub source: u16,
    pub bytes: Option<Vec<u8>>,
}

// serde_json::Value alone silently accepts duplicate object keys. Reject them
// before projection so implementation/parser disagreement cannot choose data.
struct UniqueJson(Value);
impl<'de> Deserialize<'de> for UniqueJson {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = UniqueJson;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("bounded JSON with unique keys")
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> Result<Self::Value, E> {
                Ok(UniqueJson(Value::Bool(v)))
            }
            fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(UniqueJson(Value::Null))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Self::Value, E> {
                Ok(UniqueJson(v.into()))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Self::Value, E> {
                Ok(UniqueJson(v.into()))
            }
            fn visit_f64<E: de::Error>(self, v: f64) -> Result<Self::Value, E> {
                serde_json::Number::from_f64(v)
                    .map(|n| UniqueJson(Value::Number(n)))
                    .ok_or_else(|| E::custom("invalid number"))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                Ok(UniqueJson(v.into()))
            }
            fn visit_string<E: de::Error>(self, v: String) -> Result<Self::Value, E> {
                Ok(UniqueJson(v.into()))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Self::Value, A::Error> {
                let mut out = Vec::new();
                while let Some(v) = a.next_element::<UniqueJson>()? {
                    if out.len() >= 4096 {
                        return Err(de::Error::custom("too many values"));
                    }
                    out.push(v.0);
                }
                Ok(UniqueJson(Value::Array(out)))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<Self::Value, A::Error> {
                let mut out = serde_json::Map::new();
                while let Some(k) = a.next_key::<String>()? {
                    if out.len() >= 4096 || out.contains_key(&k) {
                        return Err(de::Error::custom("duplicate or excessive keys"));
                    }
                    out.insert(k, a.next_value::<UniqueJson>()?.0);
                }
                Ok(UniqueJson(Value::Object(out)))
            }
        }
        d.deserialize_any(V)
    }
}

/// One scalar the kernel extracts from a verified result for a signed control.
/// Never a list, object, null or float: a result-derived control value must be
/// a single Text / non-negative integer / boolean, or extraction fails closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScalarSelectionV04 {
    Text(String),
    Unsigned(u64),
    Boolean(bool),
}

/// Reserved path step: decode the current node, which must be a JSON *string*,
/// as a nested strict JSON document and continue the path inside it. A tool's
/// output reaches the kernel as canonical JSON text inside the MCP response
/// (`result.content[0].text`), so this is how a signed path names a field of
/// the tool output itself. A string has no keys or indices, so this step can
/// never shadow an object key (on an object `$json` is an ordinary key) or an
/// array index. The nested text uses the same duplicate-key-rejecting parser.
pub const DECODE_JSON_TEXT_SEGMENT: &str = "$json";

fn walk(value: &Value, path: &[String]) -> Option<Value> {
    let mut current = value;
    for (index, key) in path.iter().enumerate() {
        if key == DECODE_JSON_TEXT_SEGMENT {
            if let Value::String(text) = current {
                let nested = serde_json::from_str::<UniqueJson>(text).ok()?.0;
                return walk(&nested, &path[index + 1..]);
            }
        }
        current = match current {
            Value::Object(map) => map.get(key)?,
            Value::Array(items) => key
                .parse::<usize>()
                .ok()
                .filter(|index| index.to_string() == *key)
                .and_then(|index| items.get(index))?,
            _ => return None,
        };
    }
    Some(current.clone())
}

/// Strict scalar projection for a signed result-derived control. Same bounded,
/// duplicate-key-rejecting parser and path grammar as observations; the node at
/// `path` must exist and be a single scalar. `max_bytes` bounds a text result's
/// UTF-8 length. This is projection, never endorsement: the caller keeps the
/// value's untrusted provenance.
pub fn select_scalar(bytes: &[u8], path: &[String], max_bytes: u16) -> Result<ScalarSelectionV04, Error> {
    if bytes.len() > 16 * 1024
        || path.len() > 16
        || path
            .iter()
            .any(|s| s.is_empty() || s.len() > 128 || s.chars().any(char::is_control))
    {
        return Err(Error::Invalid);
    }
    let value = serde_json::from_slice::<UniqueJson>(bytes)
        .map_err(|_| Error::Invalid)?
        .0;
    match walk(&value, path).ok_or(Error::Binding)? {
        Value::String(text) => {
            if text.len() > usize::from(max_bytes) {
                return Err(Error::Limit);
            }
            Ok(ScalarSelectionV04::Text(text))
        }
        Value::Bool(flag) => Ok(ScalarSelectionV04::Boolean(flag)),
        Value::Number(number) => number
            .as_u64()
            .map(ScalarSelectionV04::Unsigned)
            .ok_or(Error::Invalid),
        Value::Null | Value::Array(_) | Value::Object(_) => Err(Error::Invalid),
    }
}

pub(crate) fn render(
    context: &[u8],
    specs: &[ResultObservation],
    inputs: &[ObservationSource],
) -> Result<Vec<u8>, Error> {
    let required: BTreeSet<_> = specs.iter().map(|s| s.source).collect();
    if specs.is_empty()
        || specs.len() > 4
        || inputs.len() != required.len()
        || inputs.windows(2).any(|w| w[0].source >= w[1].source)
        || inputs.iter().map(|s| s.source).collect::<BTreeSet<_>>() != required
        || inputs
            .iter()
            .map(|s| s.bytes.as_ref().map_or(0, Vec::len))
            .sum::<usize>()
            > 16 * 1024
    {
        return Err(Error::Invalid);
    }
    let context = std::str::from_utf8(context).map_err(|_| Error::Invalid)?;
    let mut observations = Vec::new();
    for spec in specs {
        spec.validate()?;
        let input = inputs
            .iter()
            .find(|s| s.source == spec.source)
            .ok_or(Error::Binding)?;
        let selected = if let Some(bytes) = &input.bytes {
            let value = serde_json::from_slice::<UniqueJson>(bytes)
                .map_err(|_| Error::Invalid)?
                .0;
            walk(&value, &spec.path)
        } else {
            None
        };
        observations.push(match selected {
            Some(value)=>serde_json::json!({"source":spec.source,"path":spec.path,"status":"available","value":value}),
            None=>serde_json::json!({"source":spec.source,"path":spec.path,"status":"unavailable"}),
        });
    }
    let rendered =
        serde_json::to_vec(&serde_json::json!({"context":context,"observations":observations}))
            .map_err(|_| Error::Invalid)?;
    if rendered.len() > 4096 {
        return Err(Error::Limit);
    }
    Ok(rendered)
}
