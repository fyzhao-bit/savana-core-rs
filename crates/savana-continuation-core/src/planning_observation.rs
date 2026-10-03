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
pub fn select_scalar(
    bytes: &[u8],
    path: &[String],
    max_bytes: u16,
) -> Result<ScalarSelectionV04, Error> {
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

/// Strict list projection for a signed text-list control: the node at `path`
/// must be a JSON array of at most `MAX_TEXT_LIST_ITEMS_V04` strings whose
/// total UTF-8 length is at most `max_bytes`. Anything else fails closed.
pub fn select_text_list(
    bytes: &[u8],
    path: &[String],
    max_bytes: u16,
) -> Result<Vec<String>, Error> {
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
    let Value::Array(items) = walk(&value, path).ok_or(Error::Binding)? else {
        return Err(Error::Invalid);
    };
    if items.len() > MAX_TEXT_LIST_ITEMS_V04 {
        return Err(Error::Limit);
    }
    let mut total = 0usize;
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let Value::String(text) = item else {
            return Err(Error::Invalid);
        };
        total = total.saturating_add(text.len());
        if total > usize::from(max_bytes) {
            return Err(Error::Limit);
        }
        out.push(text);
    }
    Ok(out)
}

/// At most this many items in a text-list control.
pub const MAX_TEXT_LIST_ITEMS_V04: usize = 32;

/// A deterministic computation the kernel applies to an extracted text value
/// for an owner-signed computed control. The owner signs the operation and
/// the amount; the operand is the verified result value at the signed path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComputeOpV04 {
    /// "YYYY-MM-DD HH:MM" plus `amount` minutes, same format.
    AddMinutes,
    /// "YYYY-MM-DD" (optionally followed by " HH:MM", kept) plus `amount` days.
    AddDays,
    /// A non-negative decimal with at most two fraction digits plus `amount`
    /// hundredths, written with exactly two fraction digits; never negative.
    AddCents,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResultComputeV04 {
    pub op: ComputeOpV04,
    pub amount: i64,
}

impl ComputeOpV04 {
    pub const fn code(self) -> u16 {
        match self {
            Self::AddMinutes => 1,
            Self::AddDays => 2,
            Self::AddCents => 3,
        }
    }
    pub const fn from_code(code: u16) -> Option<Self> {
        match code {
            1 => Some(Self::AddMinutes),
            2 => Some(Self::AddDays),
            3 => Some(Self::AddCents),
            _ => None,
        }
    }
    /// The bound on `amount` (a year of minutes, ten years of days, ten
    /// million currency units in hundredths).
    pub const fn max_amount(self) -> i64 {
        match self {
            Self::AddMinutes => 527_040,
            Self::AddDays => 3_660,
            Self::AddCents => 1_000_000_000,
        }
    }
}

impl ResultComputeV04 {
    pub fn valid(&self) -> bool {
        self.amount.unsigned_abs() <= self.op.max_amount().unsigned_abs()
    }
    /// The computed text, or `None` when the operand is not exactly the form
    /// the operation reads (or the result leaves its range): fails closed.
    pub fn apply(&self, input: &str) -> Option<String> {
        if !self.valid() {
            return None;
        }
        match self.op {
            ComputeOpV04::AddMinutes => {
                let (date, time) = input.split_once(' ')?;
                let days = days_from_date(date)?;
                let minute = minutes_from_time(time)?;
                let total = (days * 1440 + minute).checked_add(self.amount)?;
                let (day, minute) = (total.div_euclid(1440), total.rem_euclid(1440));
                Some(format!(
                    "{} {:02}:{:02}",
                    date_from_days(day)?,
                    minute / 60,
                    minute % 60
                ))
            }
            ComputeOpV04::AddDays => {
                let (date, time) = match input.split_once(' ') {
                    Some((date, time)) => (date, Some(time)),
                    None => (input, None),
                };
                let day = days_from_date(date)?.checked_add(self.amount)?;
                let date = date_from_days(day)?;
                match time {
                    Some(time) => {
                        minutes_from_time(time)?;
                        Some(format!("{date} {time}"))
                    }
                    None => Some(date),
                }
            }
            ComputeOpV04::AddCents => {
                let cents = cents_from_decimal(input)?.checked_add(self.amount)?;
                if cents < 0 {
                    return None;
                }
                Some(format!("{}.{:02}", cents / 100, cents % 100))
            }
        }
    }
}

fn digits(text: &str, width: usize) -> Option<i64> {
    if text.len() != width || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

/// Days since 1970-01-01 of a strict "YYYY-MM-DD" civil date (1000..=9999).
fn days_from_date(text: &str) -> Option<i64> {
    let mut parts = text.split('-');
    let (y, m, d) = (
        digits(parts.next()?, 4)?,
        digits(parts.next()?, 2)?,
        digits(parts.next()?, 2)?,
    );
    if parts.next().is_some() || !(1000..=9999).contains(&y) || !(1..=12).contains(&m) {
        return None;
    }
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let month_days = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if !(1..=month_days[(m - 1) as usize]).contains(&d) {
        return None;
    }
    // Howard Hinnant's days_from_civil.
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146_097 + doe - 719_468)
}

fn date_from_days(days: i64) -> Option<String> {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    (1000..=9999)
        .contains(&y)
        .then(|| format!("{y:04}-{m:02}-{d:02}"))
}

fn minutes_from_time(text: &str) -> Option<i64> {
    let (h, m) = text.split_once(':')?;
    let (h, m) = (digits(h, 2)?, digits(m, 2)?);
    (h < 24 && m < 60).then_some(h * 60 + m)
}

fn cents_from_decimal(text: &str) -> Option<i64> {
    let (whole, fraction) = match text.split_once('.') {
        Some((whole, fraction)) => (whole, fraction),
        None => (text, ""),
    };
    if whole.is_empty()
        || whole.len() > 12
        || !whole.bytes().all(|b| b.is_ascii_digit())
        || (whole.len() > 1 && whole.starts_with('0'))
        || fraction.len() > 2
        || (text.contains('.') && fraction.is_empty())
        || !fraction.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    let whole: i64 = whole.parse().ok()?;
    let fraction: i64 = if fraction.is_empty() {
        0
    } else {
        format!("{fraction:0<2}").parse().ok()?
    };
    whole.checked_mul(100)?.checked_add(fraction)
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
