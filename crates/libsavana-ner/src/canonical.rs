//! Canonical evidence serialization + digest core — byte-exact port of the
//! pure functions in `server/documents/canonical.py` (canonical.py:45-109,
//! 56-75): `json_amount`, `canonical_json_bytes`, and `sha256_hex`.
//!
//! The evidence digest feeds every downstream proof, so both halves must be
//! byte-identical to CPython:
//!
//! * **`json_amount`** renders a money value the way Python's `Decimal` does —
//!   integral values collapse to a bare integer string (trailing zeros
//!   dropped, `Decimal("1000.00") -> "1000"`), fractional values keep their
//!   exact scale (`Decimal("12.50") -> "12.50"`), and `bool`/non-finite inputs
//!   raise the stable `CANONICAL_NUMBER_INVALID`. `rust_decimal` is NOT used:
//!   Python's `Decimal` preserves per-literal scale (`12.50` != `12.5`) and its
//!   `str()`/`format(_, "f")` rendering is reproduced directly by the [`Dec`]
//!   model below (sign + magnitude coefficient + base-10 exponent, exactly
//!   `Decimal.as_tuple()`), so the rendering is hand-matched rather than
//!   delegated. See the `digest_json_amount.json` conformance assertion.
//!
//! * **`canonical_json_bytes`** reproduces
//!   `json.dumps(v, sort_keys=True, ensure_ascii=False,
//!   separators=(",", ":"), allow_nan=False)` byte-for-byte: keys sorted by
//!   Unicode code point (== Rust `str` `Ord`, since UTF-8 byte order preserves
//!   code-point order), compact separators, raw non-ASCII, and the exact
//!   CPython escape set (which `serde_json`'s string escaper matches: `"` `\`,
//!   short `\b \t \n \f \r`, other C0 controls as lowercase `\u00xx`). The
//!   real pipeline only ever feeds it already-serialized members (money is a
//!   string by the time it arrives here — `Decimal` is not JSON-serializable
//!   in Python either), so the input is a plain [`serde_json::Value`] of
//!   strings / ints / bools / null / arrays / objects. A non-finite JSON float
//!   is refused (`allow_nan=False`), mirroring Python.

use sha2::{Digest, Sha256};

/// Start code point of every Unicode `Nd` (Decimal_Number) decade in Unicode
/// **15.0.0** — the `decimal(chr)==0` code points, vendored from the same
/// CPython 3.12.4 (`unicodedata.unidata_version == "15.0.0"`) that froze the
/// vectors and lock-stepped `unicode-normalization =0.1.22`. Each decade is a
/// contiguous run of ten digits `0..=9`, so a digit's value is `c - start`.
/// CPython's `Decimal(str)` transforms ANY such digit to ASCII before parsing
/// (`_PyUnicode_TransformDecimalAndSpaceToASCII`), and both Python `re` and
/// fancy-regex `\d` match exactly this `Nd` set — so `Dec::parse` must accept
/// Unicode digits identically (e.g. fullwidth `"５００" -> 500`).
const ND_DECADE_STARTS: [u32; 68] = [
    0x30, 0x660, 0x6F0, 0x7C0, 0x966, 0x9E6, 0xA66, 0xAE6, 0xB66, 0xBE6, 0xC66, 0xCE6, 0xD66,
    0xDE6, 0xE50, 0xED0, 0xF20, 0x1040, 0x1090, 0x17E0, 0x1810, 0x1946, 0x19D0, 0x1A80, 0x1A90,
    0x1B50, 0x1BB0, 0x1C40, 0x1C50, 0xA620, 0xA8D0, 0xA900, 0xA9D0, 0xA9F0, 0xAA50, 0xABF0, 0xFF10,
    0x104A0, 0x10D30, 0x11066, 0x110F0, 0x11136, 0x111D0, 0x112F0, 0x11450, 0x114D0, 0x11650,
    0x116C0, 0x11730, 0x118E0, 0x11950, 0x11C50, 0x11D50, 0x11DA0, 0x11F50, 0x16A60, 0x16AC0,
    0x16B50, 0x1D7CE, 0x1D7D8, 0x1D7E2, 0x1D7EC, 0x1D7F6, 0x1E140, 0x1E2F0, 0x1E4F0, 0x1E950,
    0x1FBF0,
];

/// The decimal digit value of `c` (0..=9) if it is a Unicode `Nd` digit — the
/// ASCII transform CPython's `Decimal` applies. ASCII digits take the fast path.
fn to_decimal_digit(c: char) -> Option<u32> {
    if c.is_ascii_digit() {
        return Some(c as u32 - '0' as u32);
    }
    let cp = c as u32;
    let idx = match ND_DECADE_STARTS.binary_search(&cp) {
        Ok(_) => return Some(0),
        Err(0) => return None,
        Err(i) => i - 1,
    };
    let v = cp - ND_DECADE_STARTS[idx];
    (v < 10).then_some(v)
}

/// Transform a run of decimal digits (ASCII or any Unicode `Nd`) to its ASCII
/// form, or `None` if any character is not a decimal digit — mirroring the
/// digit half of CPython's Decimal input transform.
fn transform_digits(s: &str) -> Option<String> {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        out.push((b'0' + to_decimal_digit(c)? as u8) as char);
    }
    Some(out)
}

/// Stable canonical-serialization refusal (canonical.py:45-53). `str(exc)` is
/// the bare code and nothing else — never a library message.
pub const CODE_CANONICAL_NUMBER_INVALID: &str = "CANONICAL_NUMBER_INVALID";

/// A refusal carrying only a stable design-§18 code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StableCodeError {
    pub code: &'static str,
}

impl StableCodeError {
    fn number_invalid() -> Self {
        StableCodeError {
            code: CODE_CANONICAL_NUMBER_INVALID,
        }
    }
}

/// A faithful model of the subset of Python `decimal.Decimal` the money
/// boundary produces and renders: a sign, a non-negative integer `coeff`
/// (Python's stripped coefficient — no leading zeros except a lone `0`), and a
/// base-10 `exp`, i.e. exactly `Decimal.as_tuple()` for finite values, plus the
/// two special forms the conformance vectors probe.
///
/// The domain is bounded by the upstream grammar (`facts._NUM`: amounts
/// `< 10**21` with at most 4 fractional digits) and by short sums/differences
/// of such amounts, all of which fit `u128` after exponent alignment — far
/// below CPython's default 28-digit context precision, so no rounding path is
/// exercised and `u128` arithmetic is exact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Dec {
    /// `coeff * 10**exp`, negated when `neg`. `coeff == 0` is the zero value.
    Finite { neg: bool, coeff: u128, exp: i32 },
    /// `Decimal("Infinity")` / `Decimal("-Infinity")`.
    Inf { neg: bool },
    /// `Decimal("NaN")`.
    NaN,
}

impl Dec {
    /// `Decimal(0)` — the reconciliation sum seed (facts.py:405).
    pub fn zero() -> Self {
        Dec::Finite {
            neg: false,
            coeff: 0,
            exp: 0,
        }
    }

    /// Parse the plain fixed-point strings the pipeline produces
    /// (`-?\d+(\.\d+)?`, the post-comma-strip form of `facts._parse_decimal`),
    /// plus the `Infinity`/`NaN`/`-Infinity` literals the digest vectors probe.
    /// Returns `None` for anything else (mirrors `_parse_decimal`'s
    /// `InvalidOperation -> None`). Leading zeros in the coefficient are
    /// stripped exactly as `Decimal(str)` does (integer parse drops them).
    pub fn parse(s: &str) -> Option<Dec> {
        let t = s.trim();
        // Special forms (CPython accepts these case-insensitively; the vectors
        // use canonical spelling). Only what json_amount needs to reject.
        let (neg_special, body) = match t.strip_prefix('-') {
            Some(rest) => (true, rest),
            None => (false, t.strip_prefix('+').unwrap_or(t)),
        };
        match body.to_ascii_lowercase().as_str() {
            "infinity" | "inf" => return Some(Dec::Inf { neg: neg_special }),
            "nan" => return Some(Dec::NaN),
            _ => {}
        }

        // Finite: optional sign, digits, optional fractional digits.
        let (neg, rest) = match t.strip_prefix('-') {
            Some(r) => (true, r),
            None => (false, t.strip_prefix('+').unwrap_or(t)),
        };
        if rest.is_empty() {
            return None;
        }
        let (int_part, frac_part) = match rest.split_once('.') {
            Some((i, f)) => (i, Some(f)),
            None => (rest, None),
        };
        if int_part.is_empty() {
            return None;
        }
        // Digits may be ASCII or any Unicode `Nd` (CPython's Decimal transforms
        // them to ASCII before parsing); a non-digit char fails the whole parse.
        let int_ascii = transform_digits(int_part)?;
        let frac_ascii = match frac_part {
            // A trailing dot with no fractional digits ("5.") is not produced
            // by the grammar and not accepted by `Decimal`'s fixed grammar here.
            Some("") => return None,
            Some(f) => Some(transform_digits(f)?),
            None => None,
        };
        let frac = frac_ascii.as_deref().unwrap_or("");
        let digits = format!("{int_ascii}{frac}");
        let coeff: u128 = digits.parse().ok()?;
        let exp = -(frac.len() as i32);
        Some(Dec::Finite { neg, coeff, exp })
    }

    fn is_finite(&self) -> bool {
        matches!(self, Dec::Finite { .. })
    }

    /// The base-10 digit string of the magnitude (`|coeff|`, no leading zeros
    /// except a lone `"0"`) — exactly Python's stripped coefficient tuple.
    fn digits(coeff: u128) -> String {
        coeff.to_string()
    }

    /// Whether the value equals its own integral rounding — Python's
    /// `value == value.to_integral_value()`. A finite value is integral iff its
    /// fractional digits (the last `-exp` of the coefficient) are all zero.
    fn is_integral(&self) -> bool {
        match self {
            Dec::Finite { coeff, exp, .. } => {
                if *exp >= 0 || *coeff == 0 {
                    return true;
                }
                let f = (-*exp) as usize;
                let d = Self::digits(*coeff);
                if d.len() <= f {
                    // magnitude < 1: integral only when coeff == 0 (handled).
                    false
                } else {
                    d[d.len() - f..].bytes().all(|b| b == b'0')
                }
            }
            _ => false,
        }
    }

    /// `str(int(value))` for an integral value: truncate toward zero (exact
    /// here) and render. The sign is dropped for zero (`int(Decimal("-0"))`
    /// is `0`).
    fn integral_str(&self) -> String {
        let (neg, coeff, exp) = match self {
            Dec::Finite { neg, coeff, exp } => (*neg, *coeff, *exp),
            _ => unreachable!("integral_str on non-finite"),
        };
        let d = Self::digits(coeff);
        let int_digits: String = if exp >= 0 {
            // coeff * 10**exp
            format!("{}{}", d, "0".repeat(exp as usize))
        } else {
            let f = (-exp) as usize;
            if d.len() > f {
                d[..d.len() - f].to_string()
            } else {
                "0".to_string()
            }
        };
        // Normalize a possibly all-zero / leading-zero integer string.
        let trimmed = int_digits.trim_start_matches('0');
        let mag = if trimmed.is_empty() { "0" } else { trimmed };
        if neg && mag != "0" {
            format!("-{mag}")
        } else {
            mag.to_string()
        }
    }

    /// `format(value, "f")` for a fractional value: plain fixed-point, sign
    /// preserved, no exponent, no separators, scale preserved.
    fn format_f(&self) -> String {
        let (neg, coeff, exp) = match self {
            Dec::Finite { neg, coeff, exp } => (*neg, *coeff, *exp),
            _ => unreachable!("format_f on non-finite"),
        };
        let sign = if neg { "-" } else { "" };
        let d = Self::digits(coeff);
        if exp >= 0 {
            return format!("{sign}{d}{}", "0".repeat(exp as usize));
        }
        let f = (-exp) as usize;
        if d.len() > f {
            format!("{sign}{}.{}", &d[..d.len() - f], &d[d.len() - f..])
        } else {
            let pad = "0".repeat(f - d.len());
            format!("{sign}0.{pad}{d}")
        }
    }

    /// Python `str(Decimal)` for the plain fixed-point values this pipeline
    /// produces (exponent `<= 0`, adjusted exponent well within the `-6`
    /// scientific-notation threshold). Used only as a dedup/dispatch KEY in
    /// `facts` (never egressed), so it must group values exactly as CPython's
    /// `str()` does: `12.50` and `12.5` are DISTINCT strings.
    pub fn to_py_str(&self) -> String {
        match self {
            // For the plain values this pipeline produces (exponent `<= 0`,
            // small magnitude) `str(Decimal)` and `format(_, "f")` coincide —
            // both emit fixed-point with the sign preserved (`format_f` keeps a
            // negative sign even on zero, matching `str`'s sign bit; `-0` never
            // actually arises here).
            Dec::Finite { .. } => self.format_f(),
            Dec::Inf { neg } => {
                if *neg {
                    "-Infinity".to_string()
                } else {
                    "Infinity".to_string()
                }
            }
            Dec::NaN => "NaN".to_string(),
        }
    }

    /// Numeric comparison (Python `Decimal.__lt__`) — used for the
    /// `extract_facts` sort key. Only finite values reach it (date facts sort
    /// with `Dec::zero()`).
    pub fn cmp_num(&self, other: &Dec) -> std::cmp::Ordering {
        use std::cmp::Ordering;
        let (an, ac, ae) = match self {
            Dec::Finite { neg, coeff, exp } => (*neg, *coeff, *exp),
            _ => (false, 0, 0),
        };
        let (bn, bc, be) = match other {
            Dec::Finite { neg, coeff, exp } => (*neg, *coeff, *exp),
            _ => (false, 0, 0),
        };
        let a_zero = ac == 0;
        let b_zero = bc == 0;
        if a_zero && b_zero {
            return Ordering::Equal;
        }
        // Effective sign (-1 negative, +1 non-negative). Zero is non-negative.
        let asign = if a_zero || !an { 1 } else { -1 };
        let bsign = if b_zero || !bn { 1 } else { -1 };
        if asign != bsign {
            return asign.cmp(&bsign);
        }
        // Same sign: compare magnitudes at a common exponent.
        let e = ae.min(be);
        let ma = ac.saturating_mul(10u128.pow((ae - e) as u32));
        let mb = bc.saturating_mul(10u128.pow((be - e) as u32));
        let ord = ma.cmp(&mb);
        if asign < 0 {
            ord.reverse()
        } else {
            ord
        }
    }

    /// Python `Decimal.__add__` for the bounded finite domain: align to the
    /// smaller exponent, add signed coefficients, keep the smaller exponent
    /// (max scale). No context rounding is reachable here (see [`Dec`] docs).
    pub fn add(&self, other: &Dec) -> Dec {
        let (an, ac, ae) = self.finite_parts();
        let (bn, bc, be) = other.finite_parts();
        let e = ae.min(be);
        let a = (ac as i128) * 10i128.pow((ae - e) as u32) * if an { -1 } else { 1 };
        let b = (bc as i128) * 10i128.pow((be - e) as u32) * if bn { -1 } else { 1 };
        let s = a + b;
        Dec::Finite {
            neg: s < 0,
            coeff: s.unsigned_abs(),
            exp: e,
        }
    }

    /// Python `Decimal.__sub__`.
    pub fn sub(&self, other: &Dec) -> Dec {
        let negated = match other {
            Dec::Finite { neg, coeff, exp } => Dec::Finite {
                neg: !*neg,
                coeff: *coeff,
                exp: *exp,
            },
            o => o.clone(),
        };
        self.add(&negated)
    }

    fn finite_parts(&self) -> (bool, u128, i32) {
        match self {
            Dec::Finite { neg, coeff, exp } => (*neg, *coeff, *exp),
            _ => (false, 0, 0),
        }
    }
}

/// The `Decimal | int | None` (and the `bool` subclass Python must reject)
/// input to `json_amount`. Real callers only ever build `None`/`Int`/`Dec`;
/// `Bool` exists to reproduce Python's `isinstance(value, bool)` refusal
/// (the `digest_json_amount.json` vector id 5).
#[derive(Debug, Clone)]
pub enum Amount {
    None,
    Bool(bool),
    Int(i128),
    Dec(Dec),
}

/// `json_amount` (canonical.py:78-109). Renders a money value as a canonical
/// lossless decimal string, or `None`, or refuses with
/// `CANONICAL_NUMBER_INVALID`.
pub fn json_amount(value: &Amount) -> Result<Option<String>, StableCodeError> {
    match value {
        Amount::None => Ok(None),
        // `bool` is an `int` subclass no legitimate amount uses.
        Amount::Bool(_) => Err(StableCodeError::number_invalid()),
        Amount::Int(v) => Ok(Some(v.to_string())),
        Amount::Dec(d) => {
            if !d.is_finite() {
                return Err(StableCodeError::number_invalid());
            }
            if d.is_integral() {
                Ok(Some(d.integral_str()))
            } else {
                Ok(Some(d.format_f()))
            }
        }
    }
}

/// Hex SHA-256 of `data` (canonical.py:71-75).
pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let digest = hasher.finalize();
    let mut out = String::with_capacity(64);
    for b in digest {
        use std::fmt::Write;
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// `canonical_json_bytes` (canonical.py:56-68): `json.dumps(value,
/// sort_keys=True, ensure_ascii=False, separators=(",", ":"),
/// allow_nan=False)` byte-exact, then UTF-8 encoded. A non-finite float is
/// refused (Python's `allow_nan=False` raises `ValueError`); the real payload
/// carries none.
pub fn canonical_json_bytes(value: &serde_json::Value) -> Result<Vec<u8>, StableCodeError> {
    let mut out = String::new();
    write_canonical(value, &mut out)?;
    Ok(out.into_bytes())
}

fn write_canonical(value: &serde_json::Value, out: &mut String) -> Result<(), StableCodeError> {
    use serde_json::Value;
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            if let Some(f) = n.as_f64() {
                if !f.is_finite() {
                    // `allow_nan=False`.
                    return Err(StableCodeError::number_invalid());
                }
            }
            // Integers render identically to Python; the payload has no floats.
            out.push_str(&n.to_string());
        }
        Value::String(s) => write_json_string(s, out),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(item, out)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            // sort_keys=True — by Unicode code point == Rust `str` Ord.
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_unstable();
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_json_string(k, out);
                out.push(':');
                write_canonical(&map[*k], out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

/// Emit a JSON string literal exactly as CPython's `json.dumps` does with
/// `ensure_ascii=False`: quote, escape `"` and `\`, use the short C-escapes for
/// `\b \t \n \f \r`, escape the remaining C0 controls as lowercase `\u00xx`,
/// pass every other code point (including non-ASCII and DEL) through raw.
/// `serde_json::to_string(&Value::String(_))` produces this same set, but is
/// re-implemented here so the byte layout is pinned in ONE place and cannot
/// drift with the dependency.
fn write_json_string(s: &str, out: &mut String) {
    use std::fmt::Write;
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{09}' => out.push_str("\\t"),
            '\u{0a}' => out.push_str("\\n"),
            '\u{0c}' => out.push_str("\\f"),
            '\u{0d}' => out.push_str("\\r"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};
    use std::fs;

    fn vectors(name: &str) -> Vec<Value> {
        let path = format!(
            "{}/../../vectors/conformance/{}",
            env!("CARGO_MANIFEST_DIR"),
            name
        );
        let raw = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
        let v: Value = serde_json::from_str(&raw).unwrap();
        v["vectors"].as_array().unwrap().clone()
    }

    fn amount_from_vector(input: &Value) -> Amount {
        match input["t"].as_str().unwrap() {
            "none" => Amount::None,
            "bool" => Amount::Bool(input["v"].as_bool().unwrap()),
            "int" => Amount::Int(input["v"].as_i64().unwrap() as i128),
            "dec" => Amount::Dec(Dec::parse(input["v"].as_str().unwrap()).expect("parse dec")),
            other => panic!("unknown amount tag {other}"),
        }
    }

    #[test]
    fn digest_json_amount_vectors_byte_exact() {
        let mut fails = 0;
        for row in vectors("digest_json_amount.json") {
            let amount = amount_from_vector(&row["input"]);
            let got = json_amount(&amount);
            let expect = &row["expect"];
            let ok = if let Some(raises) = expect.get("raises") {
                matches!(&got, Err(e) if e.code == raises.as_str().unwrap())
            } else {
                match (&got, &expect["value"]) {
                    (Ok(None), Value::Null) => true,
                    (Ok(Some(s)), Value::String(w)) => s == w,
                    _ => false,
                }
            };
            if !ok {
                fails += 1;
                eprintln!(
                    "json_amount FAIL id={} got={got:?} expect={expect}",
                    row["id"]
                );
            }
        }
        assert_eq!(fails, 0, "digest_json_amount rows diverged");
    }

    // ── json_amount rendering unit checks (Python-verified constants) ──
    #[test]
    fn json_amount_rendering_matches_python() {
        let cases: &[(&str, &str)] = &[
            ("12.50", "12.50"),
            ("1000.00", "1000"), // integral: trailing zeros dropped
            ("1000", "1000"),
            ("0.50", "0.50"),
            ("0.05", "0.05"),
            ("999999999999999999999.5", "999999999999999999999.5"),
            ("0", "0"),
            ("0.00", "0"), // integral zero
            ("-12.50", "-12.50"),
            ("-1000.00", "-1000"),
            ("-0.5", "-0.5"),
            ("100", "100"),
            ("100.10", "100.10"),
        ];
        for (raw, want) in cases {
            let d = Dec::parse(raw).unwrap();
            let got = json_amount(&Amount::Dec(d)).unwrap().unwrap();
            assert_eq!(&got, want, "json_amount({raw})");
        }
        assert_eq!(json_amount(&Amount::Int(5)).unwrap().unwrap(), "5");
        assert_eq!(json_amount(&Amount::Int(-42)).unwrap().unwrap(), "-42");
        assert!(json_amount(&Amount::None).unwrap().is_none());
        assert!(json_amount(&Amount::Bool(true)).is_err());
        assert!(json_amount(&Amount::Dec(Dec::Inf { neg: false })).is_err());
        assert!(json_amount(&Amount::Dec(Dec::NaN)).is_err());
    }

    #[test]
    fn parse_accepts_unicode_decimal_digits() {
        // Fullwidth (Nd) digits — CPython Decimal transforms them to ASCII.
        assert_eq!(Dec::parse("５００").unwrap().to_py_str(), "500");
        assert_eq!(Dec::parse("５.０").unwrap().to_py_str(), "5.0");
        // Arabic-Indic digits (U+0660 decade).
        assert_eq!(Dec::parse("١٢٣").unwrap().to_py_str(), "123");
        // Mixed ASCII + fullwidth.
        assert_eq!(Dec::parse("1２3").unwrap().to_py_str(), "123");
        // A non-digit char fails the whole parse.
        assert!(Dec::parse("1a2").is_none());
    }

    #[test]
    fn to_py_str_preserves_scale() {
        assert_eq!(Dec::parse("12.50").unwrap().to_py_str(), "12.50");
        assert_eq!(Dec::parse("12.5").unwrap().to_py_str(), "12.5");
        assert_eq!(Dec::parse("1000").unwrap().to_py_str(), "1000");
        assert_eq!(Dec::parse("0.50").unwrap().to_py_str(), "0.50");
        assert_eq!(Dec::parse("1234.50").unwrap().to_py_str(), "1234.50");
    }

    #[test]
    fn dec_arithmetic_matches_python() {
        // 12.50 + 1.50 = 14.00 ; json_amount -> "14"
        let a = Dec::parse("12.50").unwrap();
        let b = Dec::parse("1.50").unwrap();
        let s = a.add(&b);
        assert_eq!(json_amount(&Amount::Dec(s)).unwrap().unwrap(), "14");
        // 10.00 + 2.50 = 12.50
        let s = Dec::parse("10.00")
            .unwrap()
            .add(&Dec::parse("2.50").unwrap());
        assert_eq!(json_amount(&Amount::Dec(s)).unwrap().unwrap(), "12.50");
        // sum seed: Decimal(0) + 5 -> "5"
        let s = Dec::zero().add(&Dec::parse("5").unwrap());
        assert_eq!(json_amount(&Amount::Dec(s)).unwrap().unwrap(), "5");
        // 100.00 - 99.50 = 0.50
        let v = Dec::parse("100.00")
            .unwrap()
            .sub(&Dec::parse("99.50").unwrap());
        assert_eq!(json_amount(&Amount::Dec(v)).unwrap().unwrap(), "0.50");
        // 99.50 - 100.00 = -0.50
        let v = Dec::parse("99.50")
            .unwrap()
            .sub(&Dec::parse("100.00").unwrap());
        assert_eq!(json_amount(&Amount::Dec(v)).unwrap().unwrap(), "-0.50");
        // exact zero variance -> "0"
        let v = Dec::parse("100.00")
            .unwrap()
            .sub(&Dec::parse("100.00").unwrap());
        assert_eq!(json_amount(&Amount::Dec(v)).unwrap().unwrap(), "0");
    }

    #[test]
    fn dec_cmp_is_numeric() {
        use std::cmp::Ordering;
        assert_eq!(
            Dec::parse("12.50")
                .unwrap()
                .cmp_num(&Dec::parse("12.5").unwrap()),
            Ordering::Equal
        );
        assert_eq!(
            Dec::parse("2").unwrap().cmp_num(&Dec::parse("10").unwrap()),
            Ordering::Less
        );
        assert_eq!(
            Dec::parse("-5").unwrap().cmp_num(&Dec::zero()),
            Ordering::Less
        );
    }

    // ── canonical_json_bytes / sha256 ──
    #[test]
    fn canonical_json_bytes_sorts_and_compacts() {
        let v = json!({"b": 1, "a": "2.5", "z": Value::Null});
        let bytes = canonical_json_bytes(&v).unwrap();
        assert_eq!(
            &String::from_utf8(bytes).unwrap(),
            r#"{"a":"2.5","b":1,"z":null}"#
        );
    }

    #[test]
    fn canonical_json_bytes_escapes_and_unicode() {
        let v = json!({"k": "a\tb\n\"c\\\u{01}\u{7f}café"});
        let bytes = canonical_json_bytes(&v).unwrap();
        // ensure_ascii=False keeps café raw; \t \n short;  lowercase; DEL raw.
        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            "{\"k\":\"a\\tb\\n\\\"c\\\\\\u0001\u{7f}café\"}"
        );
    }

    #[test]
    fn sha256_hex_known() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    // Live differential fixture: (json payload, expected sha) pairs computed by
    // the reference CPython (`/tmp/civenv/bin/python`, PYTHONPATH=jarvis) over
    // `sha256_hex(canonical_json_bytes(payload))`. See
    // `vectors/differential/canonical_digest.json` and the pasted proof.
    #[test]
    fn canonical_digest_live_differential() {
        let path = format!(
            "{}/../../vectors/differential/canonical_digest.json",
            env!("CARGO_MANIFEST_DIR")
        );
        let raw = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
        let rows: Value = serde_json::from_str(&raw).unwrap();
        let mut fails = 0;
        let mut n = 0;
        for row in rows.as_array().unwrap() {
            n += 1;
            let payload = &row["payload"];
            let want = row["sha256"].as_str().unwrap();
            let got = sha256_hex(&canonical_json_bytes(payload).unwrap());
            if got != want {
                fails += 1;
                eprintln!("digest FAIL payload={payload} got={got} want={want}");
            }
        }
        assert!(n > 0, "no differential rows");
        assert_eq!(fails, 0, "{fails}/{n} canonical digest rows diverged");
    }

    // Live differential fixture for json_amount over a fuzz corpus.
    #[test]
    fn json_amount_live_differential() {
        let path = format!(
            "{}/../../vectors/differential/json_amount.json",
            env!("CARGO_MANIFEST_DIR")
        );
        let raw = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
        let rows: Value = serde_json::from_str(&raw).unwrap();
        let mut fails = 0;
        let mut n = 0;
        for row in rows.as_array().unwrap() {
            n += 1;
            let amount = amount_from_vector(&row["input"]);
            let got = json_amount(&amount);
            let want = &row["expect"];
            let ok = if let Some(raises) = want.get("raises") {
                matches!(&got, Err(e) if e.code == raises.as_str().unwrap())
            } else {
                match (&got, &want["value"]) {
                    (Ok(None), Value::Null) => true,
                    (Ok(Some(s)), Value::String(w)) => s == w,
                    _ => false,
                }
            };
            if !ok {
                fails += 1;
                eprintln!(
                    "json_amount diff FAIL in={} got={got:?} want={want}",
                    row["input"]
                );
            }
        }
        assert!(n > 0, "no differential rows");
        assert_eq!(fails, 0, "{fails}/{n} json_amount rows diverged");
    }
}
