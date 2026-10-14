//! Strict bounded JSON tree. Never deserialize into Value/Map before checking
//! duplicate keys: escaped aliases are compared after JSON string decoding.
use super::business_request::{BusinessCodecErrorV2, MAX_BUSINESS_JSON_BYTES_V2};
use serde::de::{DeserializeSeed, Error, MapAccess, SeqAccess, Visitor};
use std::{collections::BTreeMap, fmt};

#[derive(Clone, PartialEq, Eq)]
pub(super) enum Json {
    Text(String),
    Unsigned(u64),
    Signed(i64),
    Bool(bool),
    Object(BTreeMap<String, Json>),
    Array(Vec<Json>),
}
impl Json {
    pub(super) fn object(&self) -> Result<&BTreeMap<String, Json>, BusinessCodecErrorV2> {
        match self {
            Self::Object(v) => Ok(v),
            _ => Err(BusinessCodecErrorV2::Malformed),
        }
    }
    pub(super) fn text(&self) -> Result<&str, BusinessCodecErrorV2> {
        match self {
            Self::Text(v) => Ok(v),
            _ => Err(BusinessCodecErrorV2::Malformed),
        }
    }
    pub(super) fn canonical(&self) -> Vec<u8> {
        let mut output = Vec::new();
        self.write(&mut output);
        output
    }
    fn write(&self, out: &mut Vec<u8>) {
        match self {
            Self::Text(s) => out.extend_from_slice(
                serde_json::to_string(s)
                    .expect("string serialization is infallible")
                    .as_bytes(),
            ),
            Self::Unsigned(n) => out.extend_from_slice(n.to_string().as_bytes()),
            Self::Signed(n) => out.extend_from_slice(n.to_string().as_bytes()),
            Self::Bool(b) => out.extend_from_slice(if *b { b"true" } else { b"false" }),
            Self::Object(map) => {
                out.push(b'{');
                for (i, (key, value)) in map.iter().enumerate() {
                    if i != 0 {
                        out.push(b',');
                    }
                    Self::Text(key.clone()).write(out);
                    out.push(b':');
                    value.write(out);
                }
                out.push(b'}');
            }
            Self::Array(values) => {
                out.push(b'[');
                for (i, value) in values.iter().enumerate() {
                    if i != 0 {
                        out.push(b',');
                    }
                    value.write(out);
                }
                out.push(b']');
            }
        }
    }
}

struct Seed<'a> {
    depth: u8,
    remaining: &'a mut usize,
}
impl<'de> DeserializeSeed<'de> for Seed<'_> {
    type Value = Json;
    fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> Result<Json, D::Error> {
        if self.depth > 5 || *self.remaining == 0 {
            return Err(D::Error::custom("bounded JSON required"));
        }
        *self.remaining -= 1;
        d.deserialize_any(self)
    }
}
impl<'de> Visitor<'de> for Seed<'_> {
    type Value = Json;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("bounded JSON")
    }
    fn visit_bool<E: Error>(self, v: bool) -> Result<Json, E> {
        Ok(Json::Bool(v))
    }
    fn visit_u64<E: Error>(self, v: u64) -> Result<Json, E> {
        Ok(Json::Unsigned(v))
    }
    fn visit_i64<E: Error>(self, v: i64) -> Result<Json, E> {
        Ok(Json::Signed(v))
    }
    fn visit_str<E: Error>(self, v: &str) -> Result<Json, E> {
        if v.len() > MAX_BUSINESS_JSON_BYTES_V2 {
            return Err(E::custom("bounded JSON required"));
        }
        Ok(Json::Text(v.to_owned()))
    }
    fn visit_string<E: Error>(self, v: String) -> Result<Json, E> {
        if v.len() > MAX_BUSINESS_JSON_BYTES_V2 {
            return Err(E::custom("bounded JSON required"));
        }
        Ok(Json::Text(v))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Json, A::Error> {
        let mut result = BTreeMap::new();
        while let Some(key) = map.next_key::<String>()? {
            if key.len() > 128 || result.len() >= 32 || result.contains_key(&key) {
                return Err(A::Error::custom("unique bounded keys required"));
            }
            let value = map.next_value_seed(Seed {
                depth: self.depth + 1,
                remaining: self.remaining,
            })?;
            result.insert(key, value);
        }
        Ok(Json::Object(result))
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Json, A::Error> {
        let mut values = Vec::new();
        loop {
            // Inspect one bounded value beyond the limit, but never retain it.
            let value = sequence.next_element_seed(Seed {
                depth: self.depth + 1,
                remaining: self.remaining,
            })?;
            let Some(value) = value else {
                break;
            };
            if values.len() >= 32 {
                return Err(A::Error::custom("bounded array required"));
            }
            values.push(value);
        }
        Ok(Json::Array(values))
    }
}
pub(super) fn parse(bytes: &[u8]) -> Result<Json, BusinessCodecErrorV2> {
    // Bounds total allocation before JSON decoding, including string escape work.
    if bytes.is_empty() || bytes.len() > MAX_BUSINESS_JSON_BYTES_V2 {
        return Err(BusinessCodecErrorV2::Limit);
    }
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    let mut remaining = 256;
    let result = Seed {
        depth: 0,
        remaining: &mut remaining,
    }
    .deserialize(&mut decoder)
    .map_err(|_| BusinessCodecErrorV2::Malformed)?;
    decoder.end().map_err(|_| BusinessCodecErrorV2::Malformed)?;
    Ok(result)
}
pub(super) fn exact<'a>(
    value: &'a Json,
    keys: &[&str],
) -> Result<&'a BTreeMap<String, Json>, BusinessCodecErrorV2> {
    let map = value.object()?;
    if map.len() != keys.len() || keys.iter().any(|key| !map.contains_key(*key)) {
        return Err(BusinessCodecErrorV2::Malformed);
    }
    Ok(map)
}

#[cfg(test)]
mod tests {
    use super::parse;

    #[test]
    fn business_json_enforces_each_structural_bound_independently() {
        let nested = |n| format!("{}true{}", "[".repeat(n), "]".repeat(n));
        assert!(parse(nested(5).as_bytes()).is_ok());
        assert!(parse(nested(6).as_bytes()).is_err());
        let array = |n| format!("[{}]", vec!["true"; n].join(","));
        assert!(parse(array(32).as_bytes()).is_ok());
        assert!(parse(array(33).as_bytes()).is_err());
        let object = |n| {
            format!(
                "{{{}}}",
                (0..n)
                    .map(|i| format!("\"k{i}\":true"))
                    .collect::<Vec<_>>()
                    .join(",")
            )
        };
        assert!(parse(object(32).as_bytes()).is_ok());
        assert!(parse(object(33).as_bytes()).is_err());
        let key = |n| format!("{{\"{}\":true}}", "a".repeat(n));
        assert!(parse(key(128).as_bytes()).is_ok());
        assert!(parse(key(129).as_bytes()).is_err());
        // Eight nested arrays; 1 root + 8 arrays + 247 scalars = 256 nodes.
        let mut children = vec![array(31); 7];
        children.push(array(30));
        assert!(parse(format!("[{}]", children.join(",")).as_bytes()).is_ok());
        children[7] = array(31);
        assert!(parse(format!("[{}]", children.join(",")).as_bytes()).is_err());
    }
}
