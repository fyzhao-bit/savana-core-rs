//! Deterministic local fact extraction over MASKED chunk text — port of the
//! pure extractors in `server/documents/facts.py` (never a model): the
//! fail-CLOSED amount-number grammar (`amount_number_spans`), the bounded
//! date/amount/total grammar, and the `extract_facts` / `reconcile` pipeline.
//!
//! ## Regex engine choice (byte-exact vs CPython `re`)
//!
//! Python's amount grammar (`_NUM`) uses an **atomic group** `(?>…)` and
//! negative **lookbehind/lookahead** (`(?<![\d,])`, `(?!,\d)`); the masking
//! grammar (`_MASK_*`) adds `(?<![\d,\w])`. The `regex` crate (linear, no
//! backtracking) cannot express either, so — exactly as flagged for the
//! masking PHONE pattern — every facts pattern is compiled with
//! **`fancy-regex`** (a backtracking engine, PCRE/Python-like semantics), which
//! supports atomic groups and fixed-width lookaround. This is also the safest
//! choice for byte-exactness: both engines backtrack the same way. `\d`/`\w`/
//! `\s` are Unicode-aware in BOTH Python `re` (default) and fancy-regex, so an
//! adversarial non-ASCII decimal digit is matched identically AND parsed
//! identically: [`crate::canonical::Dec::parse`] transforms every Unicode `Nd`
//! digit to ASCII exactly as CPython's `Decimal` does (so fullwidth `"５００"`
//! extracts as `500`, matching `_parse_decimal`). The
//! bounded quantifiers (`{1,6}`, `{1,9}`, `{1,5}`) make catastrophic
//! backtracking unreachable, so a fancy-regex runtime error cannot occur on
//! these patterns; the iterators still handle `Err` conservatively.
//!
//! ## Offsets
//!
//! Python `re` reports CHARACTER (code-point) offsets; fancy-regex reports BYTE
//! offsets. `amount_number_spans` — the only function that EMITS offsets —
//! converts its reported number spans to char offsets (matching the frozen
//! `facts_amount_grammar.json`, whose CJK vector spans are char indices). The
//! token-blanking step replaces each ASCII token with same-count `\0`, so byte
//! AND char offsets are preserved and the conversion is exact. Every other
//! offset use (line-local total boundary, overlap dedup) is monotonic, so byte
//! space gives identical grouping.
//!
//! ## Decimal fidelity
//!
//! Money is [`crate::canonical::Dec`] (Python `Decimal` model), never a float:
//! `_parse_decimal` strips commas then parses; `reconcile` sums/subtracts with
//! `Dec::add`/`Dec::sub` (align-to-min-exponent, exact for the bounded domain);
//! merge dedup keys use `Dec::to_py_str` (Python `str(Decimal)`, so `12.50` and
//! `12.5` stay distinct); the `extract_facts` sort uses `Dec::cmp_num`
//! (numeric).

use std::collections::{BTreeSet, HashMap};
use std::sync::OnceLock;

use crate::canonical::Dec;
use crate::masking::{DOC_TOKEN_PATTERN, QUERY_TOKEN_PATTERN};

// Object-replacement char: keeps offsets from gluing two runs into a new match
// (facts.py `_TOKEN_STAND_IN`).
const TOKEN_STAND_IN: &str = "\u{fffc}";

pub const FACT_KIND_AMOUNT: &str = "amount";
pub const FACT_KIND_DATE: &str = "date";
pub const FACT_KIND_STATED_TOTAL: &str = "stated_total";
pub const RECONCILIATION_METRIC: &str = "documented_total";

/// `_MONTHS` (facts.py:46-52), in the SAME insertion order — the month-name
/// alternation is `sorted(_MONTHS, key=len, reverse=True)` and Rust's stable
/// `sort_by` preserves this order for equal-length names, so the compiled
/// alternation is identical to Python's.
const MONTHS: &[(&str, u32)] = &[
    ("january", 1),
    ("february", 2),
    ("march", 3),
    ("april", 4),
    ("may", 5),
    ("june", 6),
    ("july", 7),
    ("august", 8),
    ("september", 9),
    ("october", 10),
    ("november", 11),
    ("december", 12),
    ("jan", 1),
    ("feb", 2),
    ("mar", 3),
    ("apr", 4),
    ("jun", 6),
    ("jul", 7),
    ("aug", 8),
    ("sep", 9),
    ("oct", 10),
    ("nov", 11),
    ("dec", 12),
];

/// `_SYMBOL_MAP.get(symbol)` (facts.py:105-110).
fn symbol_map(symbol: &str) -> Option<&'static str> {
    Some(match symbol {
        "US$" => "USD",
        "NT$" => "TWD",
        "HK$" => "HKD",
        "$" => "USD",
        "€" => "EUR",
        "£" => "GBP",
        "¥" => "CNY",
        "￥" => "CNY",
        "人民币" => "CNY",
        _ => return None,
    })
}

/// `_CODE_MAP.get(symbol)` (facts.py:112-113): each code maps to itself, except
/// `RMB -> CNY`.
fn code_map(symbol: &str) -> Option<&'static str> {
    Some(match symbol {
        "USD" => "USD",
        "TWD" => "TWD",
        "CNY" => "CNY",
        "RMB" => "CNY",
        "EUR" => "EUR",
        "GBP" => "GBP",
        "JPY" => "JPY",
        "HKD" => "HKD",
        _ => return None,
    })
}

struct Patterns {
    doc_token: regex::Regex,
    query_token: regex::Regex,
    date: Vec<fancy_regex::Regex>,
    amount: Vec<fancy_regex::Regex>,
    total_key: fancy_regex::Regex,
    mask: Vec<fancy_regex::Regex>,
}

fn patterns() -> &'static Patterns {
    static P: OnceLock<Patterns> = OnceLock::new();
    P.get_or_init(|| {
        let fx = |p: &str| fancy_regex::Regex::new(p).expect("static facts pattern compiles");
        let rx = |p: &str| regex::Regex::new(p).expect("static token pattern compiles");

        // ── amount grammar (facts.py:96-121) ──
        let symbol_alt = r"US\$|NT\$|HK\$|\$|€|£|¥|￥|人民币";
        let code_alt = "USD|TWD|CNY|RMB|EUR|GBP|JPY|HKD";
        let num = concat!(
            r"(?<![\d,])(?:",
            r"\d{1,3}(?:,\d{3}){1,6}(?:\.\d{1,4})?(?!,\d)",
            r"|(?>\d{1,5})(?:\.\d{1,4})?(?!,\d)",
            r")"
        );
        let amount = vec![
            fx(&format!(r"(?P<cur>{symbol_alt})\s*(?P<num>{num})")),
            fx(&format!(r"\b(?P<cur>{code_alt})\s*(?P<num>{num})")),
            fx(&format!(r"(?P<num>{num})\s*(?P<cur>{code_alt})\b")),
            fx(&format!(r"(?P<num>{num})\s*(?P<cur>元)")),
        ];

        // ── date grammar (facts.py:53-71) ──
        let mut names: Vec<&str> = MONTHS.iter().map(|(n, _)| *n).collect();
        // sorted(_MONTHS, key=len, reverse=True); stable → ties keep insertion order.
        names.sort_by_key(|b| std::cmp::Reverse(b.len()));
        let month_name = names.join("|");
        let date = vec![
            fx(r"\b(?P<y>(?:19|20)\d{2})[-/](?P<m>\d{1,2})[-/](?P<d>\d{1,2})\b"),
            fx(&format!(
                r"(?i)\b(?P<mn>{month_name})\s+(?P<d>\d{{1,2}})(?:\s*,\s*|\s+)(?P<y>(?:19|20)\d{{2}})\b"
            )),
            fx(&format!(
                r"(?i)\b(?P<d>\d{{1,2}})\s+(?P<mn>{month_name})\s+(?P<y>(?:19|20)\d{{2}})\b"
            )),
            fx(r"(?P<y>(?:19|20)\d{2})年(?P<m>\d{1,2})月(?P<d>\d{1,2})日"),
        ];

        // ── total keyword (facts.py:125-127) ──
        let total_key = fx(r"(?i)\b(?:grand\s+total|total)\b|合計|合计|總計|总计|共計|共计");

        // ── masking-only grammar (facts.py:248-263) ──
        let sigil = concat!(
            r"US\$|NT\$|HK\$|\$|€|£|¥|￥",
            "|美元|美金|新台幣|新台币|港元|港幣|港币|人民幣|人民币|日元|日圓|日圆",
            "|英镑|英鎊|歐元|欧元|元|円"
        );
        let word = r"USD|TWD|CNY|RMB|EUR|GBP|JPY|HKD|dollars?|euros?|pounds?|yen";
        let mask_num = r"\d{1,3}(?:,\d{3}){1,6}(?:\.\d{1,9})?|\d{1,5}(?:\.\d{1,9})?";
        let mask = vec![
            fx(&format!(
                r"(?:{sigil}|\b(?:{word})\b)\s*[(\-]?\s*(?P<num>{mask_num})(?![\d,])"
            )),
            fx(&format!(
                r"(?<![\d,\w])(?P<num>{mask_num})\)?\s*(?:{sigil}|\b(?:{word})\b)"
            )),
        ];

        Patterns {
            doc_token: rx(DOC_TOKEN_PATTERN),
            query_token: rx(QUERY_TOKEN_PATTERN),
            date,
            amount,
            total_key,
            mask,
        }
    })
}

/// One deterministic fact with page/chunk citations (facts.py:147-158).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractedFact {
    pub fact_id: String,
    pub kind: String,
    pub value: Option<Dec>,
    pub currency: Option<String>,
    pub date: Option<String>,
    pub pages: Vec<i64>,
    pub chunk_ids: Vec<String>,
}

/// Stated-vs-computed total for one currency (facts.py:160-169).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconciliationEntry {
    pub metric: String,
    pub stated_amount: Option<Dec>,
    pub computed_amount: Option<Dec>,
    pub variance: Option<Dec>,
    pub currency: Option<String>,
    pub pages: Vec<i64>,
}

/// The minimal chunk shape extractors need (`CitedChunk`, facts.py:136-144).
#[derive(Debug, Clone)]
pub struct Chunk {
    pub chunk_id: String,
    pub pages: Vec<i64>,
    pub text: String,
}

fn strip_tokens(text: &str) -> String {
    let p = patterns();
    let stripped = p.doc_token.replace_all(text, TOKEN_STAND_IN);
    p.query_token
        .replace_all(&stripped, TOKEN_STAND_IN)
        .into_owned()
}

/// Replace every well-formed token with a SAME-LENGTH `\0` fill
/// (facts.py:266-279). Tokens are ASCII, so byte AND char offsets are preserved
/// and no amount can match inside a former token.
fn blank_tokens_preserving_length(text: &str) -> String {
    fn fill_nulls(re: &regex::Regex, text: &str) -> String {
        let mut out = String::with_capacity(text.len());
        let mut last = 0;
        for m in re.find_iter(text) {
            out.push_str(&text[last..m.start()]);
            // char count == byte count (ASCII token), and `\0` is 1 byte, so
            // this preserves the byte layout exactly.
            let count = text[m.start()..m.end()].chars().count();
            for _ in 0..count {
                out.push('\u{0}');
            }
            last = m.end();
        }
        out.push_str(&text[last..]);
        out
    }
    let p = patterns();
    let blanked = fill_nulls(&p.doc_token, text);
    fill_nulls(&p.query_token, &blanked)
}

fn parse_decimal(raw: &str) -> Option<Dec> {
    Dec::parse(&raw.replace(',', ""))
}

/// True Gregorian calendar validity (Python `datetime.date`), so `2026-02-30`
/// is silently NOT a fact.
fn valid_date(y: i32, m: u32, d: u32) -> bool {
    if !(1..=9999).contains(&y) || !(1..=12).contains(&m) {
        return false;
    }
    let leap = (y % 4 == 0) && (y % 100 != 0 || y % 400 == 0);
    let dim = match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if leap {
                29
            } else {
                28
            }
        }
        _ => 0,
    };
    (1..=dim).contains(&d)
}

/// `_normalize_date` (facts.py:177-185): ISO-normalize a captured date, or
/// `None` for a non-calendar date (refuse, never guess).
fn normalize_date(
    y: Option<&str>,
    mn: Option<&str>,
    m: Option<&str>,
    d: Option<&str>,
) -> Option<String> {
    let year: i32 = y?.parse().ok()?;
    let month: u32 = match mn {
        Some(name) => {
            let lname = name.to_lowercase();
            MONTHS.iter().find(|(n, _)| *n == lname).map(|(_, v)| *v)?
        }
        None => m?.parse().ok()?,
    };
    let day: u32 = d?.parse().ok()?;
    if valid_date(year, month, day) {
        Some(format!("{year:04}-{month:02}-{day:02}"))
    } else {
        None
    }
}

/// `_date_matches` (facts.py:188-201): all valid dates, ISO-normalized, deduped
/// by span across the ordered patterns (an invalid-date match does NOT reserve
/// its span, so a later overlapping pattern can still match it).
fn date_matches(text: &str) -> Vec<String> {
    let p = patterns();
    let mut taken: Vec<(usize, usize)> = Vec::new();
    let mut found: Vec<String> = Vec::new();
    for re in &p.date {
        for caps in re.captures_iter(text) {
            let caps = match caps {
                Ok(c) => c,
                Err(_) => break, // unreachable for bounded patterns
            };
            let whole = caps.get(0).unwrap();
            let span = (whole.start(), whole.end());
            if taken.iter().any(|&(s, e)| s < span.1 && span.0 < e) {
                continue;
            }
            let normalized = normalize_date(
                caps.name("y").map(|x| x.as_str()),
                caps.name("mn").map(|x| x.as_str()),
                caps.name("m").map(|x| x.as_str()),
                caps.name("d").map(|x| x.as_str()),
            );
            if let Some(iso) = normalized {
                taken.push(span);
                found.push(iso);
            }
        }
    }
    found
}

/// `_amount_matches` (facts.py:211-236): `(start, value, currency)` per amount
/// in a LINE, patterns in declared order, longer matches win on overlap. `start`
/// is the WHOLE-match start (byte offset — used only for the line-local total
/// boundary comparison, which is monotonic).
fn amount_matches(line: &str) -> Vec<(usize, Dec, Option<String>)> {
    let p = patterns();
    let mut candidates: Vec<(usize, usize, Dec, Option<String>)> = Vec::new();
    for re in &p.amount {
        for caps in re.captures_iter(line) {
            let caps = match caps {
                Ok(c) => c,
                Err(_) => break,
            };
            let whole = caps.get(0).unwrap();
            let num = caps.name("num").unwrap();
            let value = match parse_decimal(num.as_str()) {
                Some(v) => v,
                None => continue,
            };
            let symbol = caps.name("cur").unwrap().as_str();
            let mut currency = symbol_map(symbol)
                .or_else(|| code_map(symbol))
                .map(|s| s.to_string());
            if symbol == "元" {
                currency = Some("CNY".to_string());
            }
            candidates.push((whole.start(), whole.end(), value, currency));
        }
    }
    candidates.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| (b.1 - b.0).cmp(&(a.1 - a.0))));
    let mut taken: Vec<(usize, usize)> = Vec::new();
    let mut results: Vec<(usize, Dec, Option<String>)> = Vec::new();
    for (start, end, value, currency) in candidates {
        if taken.iter().any(|&(s, e)| s < end && start < e) {
            continue;
        }
        taken.push((start, end));
        results.push((start, value, currency));
    }
    results
}

/// `amount_number_spans` (facts.py:282-318): `(num_start, num_end, value)` for
/// each currency-associated amount NUMBER, using the fail-CLOSED masking
/// grammar, deduped by whole-match overlap (longest wins), ordered. Offsets are
/// CHARACTER offsets into the ORIGINAL `text`.
pub fn amount_number_spans(text: &str) -> Vec<(usize, usize, Dec)> {
    let p = patterns();
    let blanked = blank_tokens_preserving_length(text);
    // (m_start, m_end, num_start, num_end, value) — BYTE offsets in `blanked`.
    let mut candidates: Vec<(usize, usize, usize, usize, Dec)> = Vec::new();
    for re in &p.mask {
        for caps in re.captures_iter(&blanked) {
            let caps = match caps {
                Ok(c) => c,
                Err(_) => break,
            };
            let whole = caps.get(0).unwrap();
            let num = caps.name("num").unwrap();
            let value = match parse_decimal(num.as_str()) {
                Some(v) => v,
                None => continue,
            };
            candidates.push((whole.start(), whole.end(), num.start(), num.end(), value));
        }
    }
    candidates.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| (b.1 - b.0).cmp(&(a.1 - a.0))));
    let mut taken: Vec<(usize, usize)> = Vec::new();
    let mut results: Vec<(usize, usize, Dec)> = Vec::new();
    for (ms, me, ns, ne, value) in candidates {
        if taken.iter().any(|&(s, e)| s < me && ms < e) {
            continue;
        }
        taken.push((ms, me));
        results.push((
            byte_to_char(&blanked, ns),
            byte_to_char(&blanked, ne),
            value,
        ));
    }
    results.sort_by(|a, b| {
        a.0.cmp(&b.0)
            .then(a.1.cmp(&b.1))
            .then_with(|| a.2.cmp_num(&b.2))
    });
    results
}

/// Char offset of a byte boundary — the byte layout of `blanked` matches the
/// original text at every non-token position (tokens are 1-byte `\0`), so this
/// is the char offset into the original text too.
fn byte_to_char(s: &str, byte: usize) -> usize {
    s[..byte].chars().count()
}

type MergeKey = (String, Option<String>, Option<String>, Option<String>);

struct Slot {
    kind: String,
    value: Option<Dec>,
    currency: Option<String>,
    date: Option<String>,
    pages: BTreeSet<i64>,
    chunk_ids: BTreeSet<String>,
}

fn merge_add(
    slots: &mut Vec<Slot>,
    index: &mut HashMap<MergeKey, usize>,
    kind: &str,
    value: Option<Dec>,
    currency: Option<String>,
    day: Option<String>,
    chunk: &Chunk,
) {
    let key: MergeKey = (
        kind.to_string(),
        value.as_ref().map(|v| v.to_py_str()),
        currency.clone(),
        day.clone(),
    );
    let i = if let Some(&i) = index.get(&key) {
        i
    } else {
        let i = slots.len();
        index.insert(key, i);
        slots.push(Slot {
            kind: kind.to_string(),
            value,
            currency,
            date: day,
            pages: BTreeSet::new(),
            chunk_ids: BTreeSet::new(),
        });
        i
    };
    for &pg in &chunk.pages {
        slots[i].pages.insert(pg);
    }
    slots[i].chunk_ids.insert(chunk.chunk_id.clone());
}

/// `extract_facts` (facts.py:321-376): deterministic dates, amounts, and stated
/// totals with citations. Identical facts merge (union of pages/chunk ids);
/// ordering and `fact_id` assignment are fully deterministic.
pub fn extract_facts(chunks: &[Chunk]) -> Vec<ExtractedFact> {
    let mut slots: Vec<Slot> = Vec::new();
    let mut index: HashMap<MergeKey, usize> = HashMap::new();
    let total_key = &patterns().total_key;

    for chunk in chunks {
        let clean = strip_tokens(&chunk.text);
        for iso_date in date_matches(&clean) {
            merge_add(
                &mut slots,
                &mut index,
                FACT_KIND_DATE,
                None,
                None,
                Some(iso_date),
                chunk,
            );
        }
        for line in clean.split('\n') {
            let boundary = total_key.find(line).ok().flatten().map(|m| m.start());
            for (start, value, currency) in amount_matches(line) {
                if boundary.is_some_and(|b| start >= b) {
                    merge_add(
                        &mut slots,
                        &mut index,
                        FACT_KIND_STATED_TOTAL,
                        Some(value),
                        currency,
                        None,
                        chunk,
                    );
                } else {
                    merge_add(
                        &mut slots,
                        &mut index,
                        FACT_KIND_AMOUNT,
                        Some(value),
                        currency,
                        None,
                        chunk,
                    );
                }
            }
        }
    }

    // sort key: (kind, currency or "", value or 0 [numeric], date or "",
    //            sorted pages, sorted chunk_ids). Stable — full ties keep
    //            insertion order (Python `sorted` on a dict's values).
    slots.sort_by(|a, b| {
        a.kind
            .cmp(&b.kind)
            .then_with(|| {
                a.currency
                    .as_deref()
                    .unwrap_or("")
                    .cmp(b.currency.as_deref().unwrap_or(""))
            })
            .then_with(|| {
                let az = a.value.clone().unwrap_or_else(Dec::zero);
                let bz = b.value.clone().unwrap_or_else(Dec::zero);
                az.cmp_num(&bz)
            })
            .then_with(|| {
                a.date
                    .as_deref()
                    .unwrap_or("")
                    .cmp(b.date.as_deref().unwrap_or(""))
            })
            .then_with(|| pages_vec(&a.pages).cmp(&pages_vec(&b.pages)))
            .then_with(|| chunk_ids_vec(&a.chunk_ids).cmp(&chunk_ids_vec(&b.chunk_ids)))
    });

    slots
        .into_iter()
        .enumerate()
        .map(|(i, slot)| ExtractedFact {
            fact_id: format!("f{}", i + 1),
            kind: slot.kind,
            value: slot.value,
            currency: slot.currency,
            date: slot.date,
            pages: slot.pages.into_iter().collect(),
            chunk_ids: slot.chunk_ids.into_iter().collect(),
        })
        .collect()
}

fn pages_vec(s: &BTreeSet<i64>) -> Vec<i64> {
    s.iter().copied().collect()
}
fn chunk_ids_vec(s: &BTreeSet<String>) -> Vec<String> {
    s.iter().cloned().collect()
}

/// `reconcile` (facts.py:379-420): stated vs computed totals per currency;
/// unknown/conflicting sides stay `None`.
pub fn reconcile(facts: &[ExtractedFact]) -> Vec<ReconciliationEntry> {
    struct CurSlot {
        items: Vec<Dec>,
        stated: Vec<Dec>,
        pages: BTreeSet<i64>,
    }
    let mut keys: Vec<Option<String>> = Vec::new();
    let mut index: HashMap<Option<String>, usize> = HashMap::new();
    let mut slots: Vec<CurSlot> = Vec::new();

    for fact in facts {
        if fact.kind != FACT_KIND_AMOUNT && fact.kind != FACT_KIND_STATED_TOTAL {
            continue;
        }
        let i = if let Some(&i) = index.get(&fact.currency) {
            i
        } else {
            let i = slots.len();
            index.insert(fact.currency.clone(), i);
            keys.push(fact.currency.clone());
            slots.push(CurSlot {
                items: Vec::new(),
                stated: Vec::new(),
                pages: BTreeSet::new(),
            });
            i
        };
        let value = fact
            .value
            .clone()
            .expect("amount/stated_total fact carries a value");
        if fact.kind == FACT_KIND_AMOUNT {
            slots[i].items.push(value);
        } else {
            slots[i].stated.push(value);
        }
        for &pg in &fact.pages {
            slots[i].pages.insert(pg);
        }
    }

    // sorted(currencies, key=lambda cur: cur or "")
    let mut order: Vec<usize> = (0..slots.len()).collect();
    order.sort_by(|&a, &b| {
        keys[a]
            .as_deref()
            .unwrap_or("")
            .cmp(keys[b].as_deref().unwrap_or(""))
    });

    order
        .into_iter()
        .map(|i| {
            let slot = &slots[i];
            let stated_strs: BTreeSet<String> = slot.stated.iter().map(|v| v.to_py_str()).collect();
            let stated = if stated_strs.len() == 1 {
                Some(slot.stated[0].clone())
            } else {
                None
            };
            let computed = if slot.items.is_empty() {
                None
            } else {
                let mut acc = Dec::zero();
                for it in &slot.items {
                    acc = acc.add(it);
                }
                Some(acc)
            };
            let variance = match (&stated, &computed) {
                (Some(s), Some(c)) => Some(s.sub(c)),
                _ => None,
            };
            ReconciliationEntry {
                metric: RECONCILIATION_METRIC.to_string(),
                stated_amount: stated,
                computed_amount: computed,
                variance,
                currency: keys[i].clone(),
                pages: slot.pages.iter().copied().collect(),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::{json_amount, Amount};
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

    fn spans_to_json(spans: &[(usize, usize, Dec)]) -> Value {
        Value::Array(
            spans
                .iter()
                .map(|(s, e, v)| json!([*s, *e, v.to_py_str()]))
                .collect(),
        )
    }

    #[test]
    fn facts_amount_grammar_vectors_byte_exact() {
        let mut fails = 0;
        for row in vectors("facts_amount_grammar.json") {
            let input = row["input"].as_str().unwrap();
            let want = &row["expect"]["value"];
            let got = spans_to_json(&amount_number_spans(input));
            if &got != want {
                fails += 1;
                eprintln!(
                    "spans FAIL id={} in={input:?} got={got} want={want}",
                    row["id"]
                );
            }
        }
        assert_eq!(fails, 0, "facts_amount_grammar rows diverged");
    }

    #[test]
    fn invalid_calendar_date_is_not_a_fact() {
        assert_eq!(date_matches("2026-02-30"), Vec::<String>::new());
        assert_eq!(date_matches("2026-13-01"), Vec::<String>::new());
        assert_eq!(date_matches("2026-02-28"), vec!["2026-02-28".to_string()]);
        assert_eq!(date_matches("2024-02-29"), vec!["2024-02-29".to_string()]); // leap
        assert_eq!(date_matches("1900-02-29"), Vec::<String>::new()); // not leap
    }

    #[test]
    fn english_and_cjk_dates() {
        assert_eq!(
            date_matches("March 1, 2026"),
            vec!["2026-03-01".to_string()]
        );
        assert_eq!(date_matches("1 March 2026"), vec!["2026-03-01".to_string()]);
        assert_eq!(date_matches("2026年3月1日"), vec!["2026-03-01".to_string()]);
    }

    fn facts_to_json(facts: &[ExtractedFact]) -> Value {
        Value::Array(
            facts
                .iter()
                .map(|f| {
                    let value = f
                        .value
                        .clone()
                        .map(|d| json_amount(&Amount::Dec(d)).unwrap())
                        .unwrap_or(None);
                    json!({
                        "fact_id": f.fact_id,
                        "kind": f.kind,
                        "value": value,
                        "currency": f.currency,
                        "date": f.date,
                        "pages": f.pages,
                        "chunk_ids": f.chunk_ids,
                    })
                })
                .collect(),
        )
    }

    fn recon_to_json(entries: &[ReconciliationEntry]) -> Value {
        let amt = |d: &Option<Dec>| -> Value {
            match d {
                Some(x) => match json_amount(&Amount::Dec(x.clone())).unwrap() {
                    Some(s) => Value::String(s),
                    None => Value::Null,
                },
                None => Value::Null,
            }
        };
        Value::Array(
            entries
                .iter()
                .map(|e| {
                    json!({
                        "metric": e.metric,
                        "stated_amount": amt(&e.stated_amount),
                        "computed_amount": amt(&e.computed_amount),
                        "variance": amt(&e.variance),
                        "currency": e.currency,
                        "pages": e.pages,
                    })
                })
                .collect(),
        )
    }

    fn chunk_from_json(v: &Value) -> Chunk {
        Chunk {
            chunk_id: v["chunk_id"].as_str().unwrap().to_string(),
            pages: v["pages"]
                .as_array()
                .unwrap()
                .iter()
                .map(|p| p.as_i64().unwrap())
                .collect(),
            text: v["text"].as_str().unwrap().to_string(),
        }
    }

    // Live differential: Python computed the expected extraction over the same
    // chunk corpus / span inputs (`/tmp/civenv/bin/python`, PYTHONPATH=jarvis).
    #[test]
    fn facts_live_differential() {
        let path = format!(
            "{}/../../vectors/differential/facts.json",
            env!("CARGO_MANIFEST_DIR")
        );
        let raw = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
        let fixture: Value = serde_json::from_str(&raw).unwrap();

        // amount_number_spans corpus
        let mut fails = 0;
        for row in fixture["spans"].as_array().unwrap() {
            let input = row["input"].as_str().unwrap();
            let want = &row["expect"];
            let got = spans_to_json(&amount_number_spans(input));
            if &got != want {
                fails += 1;
                eprintln!("span diff FAIL in={input:?}\n got={got}\nwant={want}");
            }
        }
        assert_eq!(fails, 0, "amount_number_spans corpus diverged");

        // extract_facts + reconcile over chunk documents
        let mut dfails = 0;
        for doc in fixture["documents"].as_array().unwrap() {
            let chunks: Vec<Chunk> = doc["chunks"]
                .as_array()
                .unwrap()
                .iter()
                .map(chunk_from_json)
                .collect();
            let facts = extract_facts(&chunks);
            let recon = reconcile(&facts);
            let gf = facts_to_json(&facts);
            let gr = recon_to_json(&recon);
            if gf != doc["expect_facts"] {
                dfails += 1;
                eprintln!(
                    "facts diff FAIL doc={}\n got={gf}\nwant={}",
                    doc["name"], doc["expect_facts"]
                );
            }
            if gr != doc["expect_reconciliation"] {
                dfails += 1;
                eprintln!(
                    "recon diff FAIL doc={}\n got={gr}\nwant={}",
                    doc["name"], doc["expect_reconciliation"]
                );
            }
        }
        assert_eq!(dfails, 0, "facts/reconcile documents diverged");
    }
}
