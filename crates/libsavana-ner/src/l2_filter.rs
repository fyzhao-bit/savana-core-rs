//! Byte-exact port of the **deterministic** G2 security filter in
//! `server/security/l2_envelope.py` (the JARVIS L2 extraction boundary) plus its
//! `redact_pii` dependency from `server/security/slm_gate.py`.
//!
//! Scope contract (design §G2): the SLM extraction (`_extract`, via
//! `gate_llm.chat` with GBNF) and the `gate()` / `gate_v2()` orchestration STAY
//! in Python. Only the pure pre/post security functions cross to Rust —
//! everything here is model-free, deterministic, and (modulo the flagged
//! assumptions below) byte-exact vs live CPython.
//!
//! ## The regex-engine wall and how it is failed-closed / version-locked
//! These are SECURITY patterns; a miss is a bypass. Python `re` and the `regex`
//! crate disagree in three ways that would silently break byte-exactness, so the
//! three char-class escapes are rewritten to explicit classes vendored from the
//! pinned CPython 15.0.0 rather than taken from the engine:
//!
//! - `\b` word class: Python `\w` = `isalnum() ∪ '_'`; the `regex` crate's `\w` =
//!   `Alphabetic ∪ M ∪ Nd ∪ Pc ∪ Join_Control`. They differ on 2461
//!   marks/connectors (engine-word, py-non-word, a *bypass* risk) and 915 `No`
//!   numerics (py-word, engine-non-word, over-block). `\b` is rewritten to an
//!   explicit boundary over `PY_WORD_RANGES`.
//! - `\s`: Python `re` `\s` = `WS_SET` (29 cps, incl. U+001C..U+001F), which is
//!   NOT `\p{White_Space}`. Reuses the pinned `WS_SET` from `unicode_tables` (the
//!   ONE shared source), not the engine's `\s`.
//! - `\d`: Python `\d` = category Nd. Vendored as `PY_DECIMAL_RANGES`, because
//!   regex-syntax 0.8.11 bundles Unicode 16.0.0 — a version skew vs the kernel's
//!   pinned 15.0.0.
//!
//! `IGNORECASE` is left to the engine's simple case fold (`(?i)`): the only
//! case-bearing pattern literals are ASCII, and the two non-ASCII inputs that
//! fold to ASCII under Python `re.I` (U+212A KELVIN→k, U+017F LONG S→s) are
//! covered by the shared simple-fold definition — asserted in the differential.
//! Any fancy-regex runtime error fails CLOSED (counts as a match) for the
//! security blocklist, so it can only ever OVER-block, never miss.

use crate::unicode_tables::WS_SET;
use fancy_regex::Regex as Fancy;
use std::sync::OnceLock;

// ── Caps (l2_envelope.py:40-42) ──
const FREE_CAP: usize = 40;
const QUERY_CAP: usize = 100;
const CONTENT_CAP: usize = 160;

// ── Closed sets (l2_envelope.py) ──
const ALLOWED_INTENTS: &[&str] = &[
    "call",
    "web_search",
    "open_app",
    "navigate",
    "send_message",
    "order",
    "play_media",
    "set_reminder",
    "set_alarm",
    "schedule_event",
    "manage_list",
    "device_control",
    "research",
    "other",
];
const DECISION_INTENTS: &[&str] = &[
    "leave_decision",
    "urgency_triage",
    "purchase_decision",
    "schedule_decision",
    "attend_decision",
    "commute_decision",
    "food_decision",
    "break_decision",
    "priority_decision",
    "outfit_decision",
];
const ALLOWED_VERBS: &[&str] = &["on", "off", "up", "down", "mute", "set", "add", "remove"];
/// ENVELOPE_KEYS (l2_envelope.py:64-70) — iteration order is load-bearing:
/// `_whitelist_gate` builds the output dict in exactly this order.
const ENVELOPE_KEYS: &[&str] = &[
    "kind",
    "intent",
    "action",
    "app",
    "phone",
    "query",
    "destination",
    "contact",
    "topic",
    "item",
    "time",
    "content",
    "target",
    "value",
    "quantity",
    "mode",
    "verb",
];
const PAYLOAD_KEYS: &[&str] = &[
    "query",
    "item",
    "destination",
    "contact",
    "topic",
    "time",
    "content",
];
const VAULT_SLOTS: &[&str] = &["contact", "destination"];
const TIME_INTENTS: &[&str] = &["set_alarm", "set_reminder", "schedule_event"];

const STOP_WORDS: &[&str] = &[
    "play", "search", "open", "call", "send", "order", "find", "get", "set", "navigate", "go",
    "make", "do", "start", "stop", "close", "help", "show", "打开", "搜索", "播放", "打", "发",
    "点", "找", "看", "去", "帮",
];
const FILLER_WORDS: &[&str] = &[
    "play",
    "search",
    "find",
    "open",
    "order",
    "get",
    "watch",
    "listen",
    "put",
    "for",
    "on",
    "in",
    "at",
    "the",
    "a",
    "an",
    "me",
    "my",
    "some",
    "to",
    "from",
    "what",
    "is",
    "are",
    "between",
    "and",
    "vs",
    "compare",
    "difference",
    "播放",
    "搜索",
    "搜",
    "播",
    "打开",
    "点",
    "帮我",
    "给我",
    "在",
    "上",
    "hey",
    "hi",
    "ok",
    "okay",
    "hello",
    "你好",
    "jarvis",
    "alexa",
    "siri",
    "google",
    "bixby",
    "cortana",
];
const NON_APP_NAMES: &[&str] = &[
    "jarvis",
    "alexa",
    "siri",
    "google",
    "bixby",
    "cortana",
    "assistant",
    "hey",
    "hi",
    "ok",
    "okay",
    "hello",
    "你好",
];
const KNOWN_APPS: &[&str] = &[
    "uber eats",
    "ubereats",
    "doordash",
    "grubhub",
    "instacart",
    "postmates",
    "meituan",
    "美团",
    "饿了么",
    "eleme",
    "taobao",
    "淘宝",
    "jd",
    "京东",
    "amazon",
    "亚马逊",
    "spotify",
    "youtube",
    "yt music",
    "youtube music",
    "netflix",
    "disney+",
    "wechat",
    "微信",
    "alipay",
    "支付宝",
    "高德地图",
    "百度地图",
    "qq音乐",
    "网易云音乐",
];

/// Security content blocklist — the 21 deterministic patterns
/// (`_SECURITY_PATTERNS`, l2_envelope.py:155-184), joined with `|` and matched
/// case-insensitively, exactly as `_SECURITY_RE`.
const SECURITY_PATTERNS: &[&str] = &[
    r"\bignore\s+(all\s+)?(previous|above|following|prior)\s+(instructions?|prompts?|commands?|text)",
    r"\breveal\s+(your\s+)?(system\s+)?(prompts?|instructions?|secrets?)",
    r"\bpretend\s+(you\s+are|to\s+be)\b",
    r"\byou\s+are\s+(now|an?\s+)?(evil|unethical|unfiltered|uncensored|DAN|jailbreak)",
    r"\b(ransomware|malware|spyware|rootkit|backdoor|botnet|keylogger)\b",
    r"\b(write|create|code|develop|generate)\s+(me\s+)?(a\s+)?(virus|trojan|worm|exploit|payload)\b",
    r"\bhow\s+to\s+hack\s+(into\s+)?(someone|account|email|wifi|password|database|server|website)",
    r"\b(phishing|spear.phishing|social\s+engineering)\s+(attack|email|campaign|template)",
    r"\bddos\s+(attack|tool|script)",
    r"\b(extract|synthesi[sz]e|manufacture|cook|produce)\s+(safrole|mdma|meth|cocaine|heroin|lsd|fentanyl|ghb|ketamine)\b",
    r"\bhow\s+to\s+(make|extract|synthesi[sz]e|cook)\s+(drugs?|mdma|meth|cocaine|heroin|lsd|ecstasy)\b",
    r"\b(sarin|vx|mustard\s+gas|chlorine\s+gas|ricin|anthrax)\s+(production|synthesis|weapon)",
    r"\bhow\s+to\s+(make|build|create|construct)\s+(a\s+)?(bomb|explosive|detonator|weapon|gun|rifle)\b",
    r"\b(kill|murder|assassinate|torture)\s+(yourself|myself|someone|people|him|her|them)\b",
    r"\bcommit\s+suicide\b",
    r"\b(delete|remove|wipe|destroy|format|erase)\s+(all\s+)?(the\s+)?(files?|data|system|disk|drive|database)s?\b",
    r"\b(sudo|chmod\s+777|rm\s+-rf|>\s*/dev/null|fork\s+bomb)",
    r"\b(execute|run)\s+(sudo|rm\s+-rf|chmod)",
    r"\b(write|create|generate|draft)\s+(a\s+)?(fake|false|misleading|defamatory)\s+(news|article|post|story|tweet|review)",
    r"\bimpersonate\s+(a\s+)?(president|celebrity|politician|official)",
    r"\b(child\s+(pornography|abuse|exploitation)|csam|lolita|pedophil)",
];

// ── Unicode primitives (all vs pinned CPython 15.0.0) ──

#[inline]
fn is_ws(c: char) -> bool {
    WS_SET.binary_search(&(c as u32)).is_ok()
}

#[inline]
fn is_py_decimal(c: char) -> bool {
    let cp = c as u32;
    PY_DECIMAL_RANGES
        .binary_search_by(|&(lo, hi)| {
            if cp < lo {
                std::cmp::Ordering::Greater
            } else if cp > hi {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .is_ok()
}

/// Python `str.lower()`. Rust `str::to_lowercase()` applies the same Unicode
/// full+special lowercase mapping (incl. the Greek final-sigma rule and İ→i̇)
/// that CPython does; verified byte-exact on Greek/İ/ß in the differential.
/// Assumption: the two toolchains' lowercase tables agree for every codepoint
/// assigned in Unicode 15.0.0 (only codepoints newly assigned in 15.1/16.0 could
/// differ, and those cannot appear in a 15.0.0-era corpus).
#[inline]
fn py_lower(s: &str) -> String {
    s.to_lowercase()
}

/// Python `str.strip()` — strips leading/trailing chars where `str.isspace()`,
/// which is exactly `WS_SET` (asserted equal to `re` `\s` in the generator).
fn py_strip(s: &str) -> &str {
    s.trim_matches(|c: char| is_ws(c))
}

/// Python `str.lstrip(chars)` for an explicit char set.
fn lstrip_chars(s: &str, set: &[char]) -> String {
    s.trim_start_matches(|c: char| set.contains(&c)).to_string()
}

/// First `n` Unicode scalar values — Python `s[:n]` slicing semantics.
fn take_chars(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

/// Split on `re.split(r"[\s,;.!?]+", s)` then drop empties — the shared
/// tokenizer for `_echo_check` / `_extract_content` / `_normalize_app_slot`.
fn split_tokens(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for c in s.chars() {
        if is_ws(c) || matches!(c, ',' | ';' | '.' | '!' | '?') {
            if !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
        } else {
            cur.push(c);
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

// ── Regex fragment builders (version-locked to CPython 15.0.0) ──

fn class_body(ranges: &[(u32, u32)]) -> String {
    let mut s = String::new();
    for &(lo, hi) in ranges {
        if lo == hi {
            s.push_str(&format!(r"\x{{{lo:x}}}"));
        } else {
            s.push_str(&format!(r"\x{{{lo:x}}}-\x{{{hi:x}}}"));
        }
    }
    s
}

fn word_body() -> &'static str {
    static B: OnceLock<String> = OnceLock::new();
    B.get_or_init(|| class_body(&PY_WORD_RANGES))
}
fn decimal_body() -> &'static str {
    static B: OnceLock<String> = OnceLock::new();
    B.get_or_init(|| class_body(&PY_DECIMAL_RANGES))
}
fn ws_body() -> &'static str {
    static B: OnceLock<String> = OnceLock::new();
    B.get_or_init(|| {
        let ranges: Vec<(u32, u32)> = WS_SET.iter().map(|&c| (c, c)).collect();
        class_body(&ranges)
    })
}

/// Python `\b`, rewritten as its literal definition over the vendored 15.0.0
/// word class. `(?-i:…)` keeps the boundary class free of engine case folding
/// (the class is case-closed anyway, but this removes any 16.0-fold-table
/// dependency at the assertion). Correct for ANY adjacent char (both single-
/// sided and the `>`-branch case in pattern 17), being the exact XOR of the two
/// sides' word-ness.
fn boundary() -> &'static str {
    static B: OnceLock<String> = OnceLock::new();
    B.get_or_init(|| {
        let w = format!("(?-i:[{}])", word_body());
        format!("(?:(?<={w})(?!{w})|(?<!{w})(?={w}))")
    })
}

/// Rewrite a Python `re` pattern into a fancy-regex pattern that is byte-exact
/// vs CPython 15.0.0: `\b`→[`boundary`], `\s`→`[WS_SET]`, `\d`→`[Nd]`, `\w`→
/// `[PY_WORD]`, honoring character-class context (inside `[...]` the escapes
/// become the class *body*, not a bracketed class). All other escapes pass
/// through verbatim. `.` is left as-is (Python `.` and engine `.` agree: any
/// char except `\n`).
fn pythonize(pat: &str) -> String {
    let chars: Vec<char> = pat.chars().collect();
    let mut out = String::new();
    let mut i = 0;
    let mut in_class = false;
    while i < chars.len() {
        let c = chars[i];
        if c == '\\' && i + 1 < chars.len() {
            let n = chars[i + 1];
            match n {
                'b' if !in_class => out.push_str(boundary()),
                's' => {
                    if in_class {
                        out.push_str(ws_body());
                    } else {
                        out.push('[');
                        out.push_str(ws_body());
                        out.push(']');
                    }
                }
                'd' => {
                    if in_class {
                        out.push_str(decimal_body());
                    } else {
                        out.push('[');
                        out.push_str(decimal_body());
                        out.push(']');
                    }
                }
                'w' => {
                    if in_class {
                        out.push_str(word_body());
                    } else {
                        out.push('[');
                        out.push_str(word_body());
                        out.push(']');
                    }
                }
                _ => {
                    out.push('\\');
                    out.push(n);
                }
            }
            i += 2;
            continue;
        }
        if c == '[' && !in_class {
            in_class = true;
        } else if c == ']' && in_class {
            in_class = false;
        }
        out.push(c);
        i += 1;
    }
    out
}

/// Compile a Python `re` pattern to a byte-exact fancy-regex (CPython 15.0.0
/// `\b`/`\s`/`\d`/`\w` semantics via [`pythonize`] over the ONE vendored table
/// source). `pub(crate)` so sibling deterministic ports (`body_pipeline`) reuse
/// the SAME pinned-Unicode regex machinery instead of re-vendoring it.
pub(crate) fn build_fancy(pat: &str, ignorecase: bool) -> Fancy {
    let body = pythonize(pat);
    let full = if ignorecase {
        format!("(?i){body}")
    } else {
        body
    };
    Fancy::new(&full).expect("l2 pattern compiles")
}

// ── The security blocklist ──

fn security_re() -> &'static Fancy {
    static R: OnceLock<Fancy> = OnceLock::new();
    R.get_or_init(|| build_fancy(&SECURITY_PATTERNS.join("|"), true))
}

/// `_SECURITY_RE.search(s) is not None`. Fail CLOSED: any engine runtime error
/// counts as a match (block), so the blocklist can only over-block, never miss.
pub fn security_match(s: &str) -> bool {
    security_re().is_match(s).unwrap_or(true)
}

// ── Word-marker regexes for `_derive_multi_action_hints` (l2_envelope.py:106-114) ──

fn doc_word_re() -> &'static Fancy {
    static R: OnceLock<Fancy> = OnceLock::new();
    R.get_or_init(|| build_fancy(r"\b(?:document|file|fixture(?:-\d+)?)\b|文件|附件", true))
}
fn summary_word_re() -> &'static Fancy {
    static R: OnceLock<Fancy> = OnceLock::new();
    R.get_or_init(|| {
        build_fancy(
            r"\b(?:summary|summarize|summarise|summarized|summarised|summarizing|summarising)\b|总结|摘要",
            true,
        )
    })
}
fn send_word_re() -> &'static Fancy {
    static R: OnceLock<Fancy> = OnceLock::new();
    R.get_or_init(|| {
        build_fancy(
            r"\b(?:send|email|e-mail|mail|deliver)\b|发送|邮件|发给",
            true,
        )
    })
}
fn reminder_word_re() -> &'static Fancy {
    static R: OnceLock<Fancy> = OnceLock::new();
    R.get_or_init(|| build_fancy(r"\b(?:remind|reminder)\b|提醒", true))
}
fn followup_word_re() -> &'static Fancy {
    static R: OnceLock<Fancy> = OnceLock::new();
    R.get_or_init(|| build_fancy(r"\bfollow[ -]?up\b|跟进|后续", true))
}
fn email_ph_re() -> &'static Fancy {
    // fullmatch → anchor with \A…\z
    static R: OnceLock<Fancy> = OnceLock::new();
    R.get_or_init(|| build_fancy(r"\A(?:<(?:EMAIL|邮箱)_\d+>)\z", true))
}
fn fixture1_re() -> &'static Fancy {
    static R: OnceLock<Fancy> = OnceLock::new();
    // ASCII lookarounds — engine-safe as written.
    R.get_or_init(|| build_fancy(r"(?<![A-Za-z0-9_-])fixture-1(?![A-Za-z0-9_-])", true))
}

fn search(re: &Fancy, s: &str) -> bool {
    re.is_match(s).unwrap_or(false)
}

// ── redact_pii (slm_gate.py) — 17 sequential regex substitutions ──

struct RedactPat {
    re: Fancy,
    repl: &'static str,
}

fn redact_patterns() -> &'static Vec<RedactPat> {
    static P: OnceLock<Vec<RedactPat>> = OnceLock::new();
    P.get_or_init(|| {
        // (pattern, replacement, ignorecase) in _PII_PATTERNS order.
        let defs: &[(&str, &str, bool)] = &[
            (r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----[^-]*-----END\s+(?:RSA\s+)?PRIVATE\s+KEY-----", "[PRIVATE-KEY]", false),
            (r"eyJ[a-zA-Z0-9_\-+=/]{10,}\.[a-zA-Z0-9_\-+=/]{10,}\.[a-zA-Z0-9_\-+=/]{10,}", "[JWT-TOKEN]", false),
            (r"sk-ant-api\d{2}-[a-zA-Z0-9_-]{8,}", "[API-KEY]", false),
            (r"sk-(?:proj-)?[a-zA-Z0-9]{20,}", "[API-KEY]", false),
            (r"(?:AKIA|ASIA)[A-Z0-9]{16}", "[AWS-KEY]", false),
            (r"(?:Bearer|Basic)\s+[a-zA-Z0-9._\-=\+/]{16,}", "[AUTH-HEADER]", false),
            (r"(?:api[_-]?key|api[_-]?secret|access[_-]?token|auth[_-]?token|bearer)\s*[:=]\s*[a-zA-Z0-9._\-\+/]{16,}", "[API-KEY-PARAM]", false),
            (r"\b(?:\d[ -]*?){13,19}\b", "[银行卡号]", false),
            (r"[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]", "[身份证号]", false),
            (r"1[3-9]\d{9}", "[电话号码]", false),
            (r"(?:\+\d{1,3}[- ]?)?\(?\d{2,4}\)?[- ]?\d{2,4}[- ]?\d{4,10}", "[电话号码]", false),
            (r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", "[邮箱]", false),
            (r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", "[IP地址]", false),
            (r"(?:支付宝|alipay|微信|wechat)[^\n]{0,10}[:：]?\s*[a-zA-Z0-9._%+-]{3,40}", "[支付账户]", false),
            (r"(?:报税|税务|工资|薪资|银行|账单|合同|协议|劳动|身份证|护照|简历|体检|病历|贷款|保单|纳税|证明|隐私|机密|内部|保密)[^\n]{0,50}\.(?:pdf|docx?|xlsx?|csv|png|jpe?g|txt|json|xml|zip|rar|7z)", "[敏感文件名]", true),
            (r"(?:/Users/\w+|/home/\w+|~)/[^\n]{0,80}\.(?:pem|key|crt|cer|p12|pfx|ppk)(?:\s|$|\n)", "[敏感文件路径]", false),
            (r"id_(?:rsa|ed25519|ecdsa|dsa)(?:\.pub)?", "[SSH密钥]", false),
        ];
        defs.iter()
            .map(|&(p, r, ic)| RedactPat {
                re: build_fancy(p, ic),
                repl: r,
            })
            .collect()
    })
}

/// Byte-exact port of `slm_gate.redact_pii`: apply each PII pattern's `.sub`
/// sequentially (output of one feeds the next), in `_PII_PATTERNS` order.
pub fn redact_pii(text: &str) -> String {
    let mut out = text.to_string();
    for p in redact_patterns() {
        // Fancy `replace_all`; on a runtime error leave the text unchanged for
        // that pattern (matches Python producing no substitution on no-match).
        out = match p.re.replace_all(&out, fancy_regex::NoExpand(p.repl)) {
            std::borrow::Cow::Borrowed(_) => out,
            std::borrow::Cow::Owned(s) => s,
        };
    }
    out
}

/// Python `re.escape` (3.7+): escape exactly the 24 "special" chars.
/// `pub(crate)` — reused by `body_pipeline`'s leak-gate vault-value regex.
pub(crate) fn py_re_escape(s: &str) -> String {
    const SPECIAL: &[char] = &[
        '(', ')', '[', ']', '{', '}', '?', '*', '+', '-', '|', '^', '$', '\\', '.', '&', '~', '#',
        ' ', '\t', '\n', '\r', '\u{0b}', '\u{0c}',
    ];
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if SPECIAL.contains(&c) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

// ── Envelope: an insertion-ordered string map with Python-dict semantics ──

/// Ordered `str→str` map. `set` on an existing key updates in place (position
/// unchanged); on a new key it appends — exactly Python `dict` behavior, which
/// the whitelist/vault ordering depends on.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Envelope {
    pub entries: Vec<(String, String)>,
}

impl Envelope {
    pub fn new() -> Self {
        Envelope {
            entries: Vec::new(),
        }
    }
    pub fn get(&self, k: &str) -> Option<&str> {
        self.entries
            .iter()
            .find(|(kk, _)| kk == k)
            .map(|(_, v)| v.as_str())
    }
    /// Python `d.get(k, "")`.
    fn get_or_empty(&self, k: &str) -> &str {
        self.get(k).unwrap_or("")
    }
    /// Python truthiness of `d.get(k)`: present AND non-empty.
    fn truthy(&self, k: &str) -> bool {
        matches!(self.get(k), Some(v) if !v.is_empty())
    }
    fn contains(&self, k: &str) -> bool {
        self.entries.iter().any(|(kk, _)| kk == k)
    }
    fn set(&mut self, k: &str, v: &str) {
        if let Some(e) = self.entries.iter_mut().find(|(kk, _)| kk == k) {
            e.1 = v.to_string();
        } else {
            self.entries.push((k.to_string(), v.to_string()));
        }
    }
    fn setdefault(&mut self, k: &str, v: &str) {
        if !self.contains(k) {
            self.entries.push((k.to_string(), v.to_string()));
        }
    }
    fn remove(&mut self, k: &str) {
        self.entries.retain(|(kk, _)| kk != k);
    }
}

// ── The deterministic security functions (l2_envelope.py) ──

/// `_whitelist_gate` (l2_envelope.py:585-628). Only ENVELOPE_KEYS survive, each
/// sanitized/capped; free-text fields re-redacted; kind↔intent made consistent.
pub fn whitelist_gate(raw: &Envelope) -> Envelope {
    const STRIP_LEADING: &[char] = &[',', '.', ' ', ';', ':', '>', '-', '=', '"', '\''];
    const QUERY_STRIP: &[char] = &['>', '<', '=', '-', ':', '"', ' '];

    let mut clean = Envelope::new();
    for &key in ENVELOPE_KEYS {
        let raw_v = raw.get_or_empty(key);
        let v = lstrip_chars(py_strip(raw_v), STRIP_LEADING);
        if v.is_empty() {
            continue;
        }
        match key {
            "kind" => {
                let lo = py_lower(&v);
                clean.set(
                    key,
                    if matches!(lo.as_str(), "task" | "chat" | "decision") {
                        &lo
                    } else {
                        "chat"
                    },
                );
            }
            "intent" => {
                let lo = py_lower(&v);
                let ok = ALLOWED_INTENTS.contains(&lo.as_str())
                    || DECISION_INTENTS.contains(&lo.as_str());
                clean.set(key, if ok { &lo } else { "other" });
            }
            "phone" => clean.set(key, &take_chars(&v, 20)),
            "query" => {
                let q = lstrip_chars(&v, QUERY_STRIP);
                clean.set(key, &redact_pii(&take_chars(&q, QUERY_CAP)));
            }
            "action" => {
                let lo = py_lower(&v);
                if lo == "initial" {
                    clean.set(key, &lo);
                }
            }
            "verb" => {
                let lo = py_lower(&v);
                if ALLOWED_VERBS.contains(&lo.as_str()) {
                    clean.set(key, &lo);
                }
            }
            "content" => clean.set(key, &redact_pii(&take_chars(&v, CONTENT_CAP))),
            _ => clean.set(key, &redact_pii(&take_chars(&v, FREE_CAP))),
        }
    }
    clean.setdefault("kind", "chat");
    clean.setdefault("intent", "other");
    let kind = clean.get_or_empty("kind").to_string();
    let intent = clean.get_or_empty("intent").to_string();
    if kind == "decision" && !DECISION_INTENTS.contains(&intent.as_str()) {
        clean.set("kind", "chat");
        clean.set("intent", "other");
    } else if (kind == "task" || kind == "chat") && DECISION_INTENTS.contains(&intent.as_str()) {
        clean.set("intent", "other");
    }
    clean
}

/// `_sanitize_payloads` (l2_envelope.py:631-670). Mutates `gated` in place.
pub fn sanitize_payloads(gated: &mut Envelope, user_text: &str) {
    for &key in PAYLOAD_KEYS {
        let v = py_strip(gated.get_or_empty(key)).to_string();
        if v.is_empty() {
            continue;
        }
        // Python `if not echo: pop; elif v.lower() in STOP: pop` — both branches
        // pop, and `||` preserves the elif's short-circuit (py_lower is only
        // computed when the echo check passed).
        if !echo_check(user_text, &v) || STOP_WORDS.contains(&py_lower(&v).as_str()) {
            gated.remove(key);
        }
    }
    let intent = gated.get_or_empty("intent").to_string();
    if gated.truthy("time") && !TIME_INTENTS.contains(&intent.as_str()) {
        gated.remove("time");
    }
    let needs_content = matches!(
        intent.as_str(),
        "set_reminder" | "send_message" | "schedule_event"
    );
    let needs_item_or_query = matches!(
        intent.as_str(),
        "play_media" | "web_search" | "order" | "research"
    );
    if needs_content && !gated.truthy("content") {
        let fallback = extract_content(user_text, gated.get_or_empty("app"));
        if !fallback.is_empty() {
            gated.set("content", &redact_pii(&take_chars(&fallback, CONTENT_CAP)));
        }
    }
    if needs_item_or_query && !gated.truthy("item") && !gated.truthy("query") {
        let fallback = extract_content(user_text, gated.get_or_empty("app"));
        if !fallback.is_empty() {
            let field = if matches!(intent.as_str(), "web_search" | "research") {
                "query"
            } else {
                "item"
            };
            gated.set(field, &take_chars(&fallback, FREE_CAP));
        }
    }
}

/// `_security_filter` (l2_envelope.py:673-709). Deterministic blocklist over all
/// free-text fields AND the raw user text; on any hit strips the field and
/// forces kind=chat / intent=other.
pub fn security_filter(gated: &mut Envelope, user_text: &str) {
    const FREE_TEXT_KEYS: &[&str] = &["query", "content", "topic", "item", "target"];
    let mut blocked = false;
    for &key in FREE_TEXT_KEYS {
        let val = py_strip(gated.get_or_empty(key)).to_string();
        if val.is_empty() {
            continue;
        }
        if security_match(&val) {
            gated.remove(key);
            blocked = true;
        }
    }
    if security_match(user_text) {
        blocked = true;
    }
    if blocked {
        gated.set("kind", "chat");
        gated.set("intent", "other");
    }
}

/// `_guard_phone` (l2_envelope.py:712-723). Drop a fabricated raw-digit phone
/// whose digits are not grounded in the user's text.
pub fn guard_phone(gated: &mut Envelope, text: &str) {
    let ph = py_strip(gated.get_or_empty("phone")).to_string();
    if ph.is_empty() || ph.starts_with('<') {
        return;
    }
    let digits: String = ph.chars().filter(|&c| is_py_decimal(c)).collect();
    let text_digits: String = text.chars().filter(|&c| is_py_decimal(c)).collect();
    if digits.is_empty() || !text_digits.contains(&digits) {
        gated.remove("phone");
    }
}

/// `_vault_slots` (l2_envelope.py:726-743). Tokenize role-labeled slots into
/// `<TYPE_n>` placeholders, stashing the stripped real value in `vault`.
pub fn vault_slots(gated: &mut Envelope, vault: &mut Envelope) {
    let mut counters: Vec<(String, usize)> = Vec::new();
    for &slot in VAULT_SLOTS {
        let val = py_strip(gated.get_or_empty(slot)).to_string();
        if val.is_empty() || val.starts_with('<') {
            continue;
        }
        let typ = slot.to_uppercase();
        let n = {
            let e = counters.iter_mut().find(|(t, _)| *t == typ);
            match e {
                Some(c) => {
                    c.1 += 1;
                    c.1
                }
                None => {
                    counters.push((typ.clone(), 1));
                    1
                }
            }
        };
        let placeholder = format!("<{typ}_{n}>");
        vault.set(&placeholder, &val);
        gated.set(slot, &placeholder);
    }
}

/// `_extract_content` (l2_envelope.py:746-755). Strip verbs/prepositions/app
/// name from the lowercased text.
pub fn extract_content(user_text: &str, app: &str) -> String {
    let lowered = py_lower(user_text);
    let words = split_tokens(&lowered);
    let app_lower = py_lower(app);
    let meaningful: Vec<String> = words
        .into_iter()
        .filter(|w| {
            !FILLER_WORDS.contains(&w.as_str())
                && *w != app_lower
                && !(!app_lower.is_empty()
                    && (app_lower.contains(w.as_str()) || w.contains(&app_lower)))
        })
        .collect();
    py_strip(&meaningful.join(" ")).to_string()
}

/// `_normalize_app_slot` (l2_envelope.py:758-803). Move a known app/platform
/// name out of item/query into `app`.
pub fn normalize_app_slot(env: &mut Envelope, installed_apps: Option<&[String]>) {
    let intent = env.get_or_empty("intent").to_string();
    if !matches!(
        intent.as_str(),
        "order" | "play_media" | "web_search" | "research"
    ) {
        return;
    }
    let slot = if matches!(intent.as_str(), "order" | "play_media") {
        "item"
    } else {
        "query"
    };
    let value = py_strip(env.get_or_empty(slot)).to_string();
    if value.is_empty() {
        return;
    }
    let lower = py_lower(&value);

    let mut candidates: Vec<String> = KNOWN_APPS.iter().map(|s| s.to_string()).collect();
    if let Some(apps) = installed_apps {
        for a in apps {
            let al = py_lower(a);
            if a.chars().count() >= 3 && !NON_APP_NAMES.contains(&al.as_str()) {
                candidates.push(al);
            }
        }
    }
    // dict.fromkeys dedup, preserve first-seen order.
    let mut seen: Vec<String> = Vec::new();
    for c in candidates {
        if !seen.contains(&c) {
            seen.push(c);
        }
    }

    let mut hit: Option<String> = None;
    for app in &seen {
        if lower == *app
            || lower.contains(&format!(" {app}"))
            || lower.starts_with(&format!("{app} "))
            || lower.ends_with(&format!(" {app}"))
        {
            hit = Some(app.clone());
            break;
        }
    }
    let hit = match hit {
        Some(h) => h,
        None => return,
    };

    // re.sub(r"\b{escape(hit)}\b", " ", value, IGNORECASE)
    let pat = format!(r"\b{}\b", py_re_escape(&hit));
    let hit_re = build_fancy(&pat, true);
    let stripped = match hit_re.replace_all(&value, fancy_regex::NoExpand(" ")) {
        std::borrow::Cow::Borrowed(_) => value.clone(),
        std::borrow::Cow::Owned(s) => s,
    };
    // re.sub(r"\s{2,}", " ", stripped)
    let ws2 = ws_run2_re();
    let stripped = match ws2.replace_all(&stripped, fancy_regex::NoExpand(" ")) {
        std::borrow::Cow::Borrowed(_) => stripped,
        std::borrow::Cow::Owned(s) => s,
    };
    let stripped = py_strip(&stripped).to_string();
    let words = split_tokens(&stripped);
    let meaningful: Vec<String> = words
        .into_iter()
        .filter(|w| !FILLER_WORDS.contains(&py_lower(w).as_str()))
        .collect();
    let stripped = py_strip(&meaningful.join(" ")).to_string();

    if !env.truthy("app") {
        env.set("app", &hit);
    }
    env.set(slot, &stripped);
}

fn ws_run2_re() -> &'static Fancy {
    static R: OnceLock<Fancy> = OnceLock::new();
    R.get_or_init(|| build_fancy(r"\s{2,}", false))
}

/// `_echo_check` (l2_envelope.py:806-822). Is *payload* plausibly grounded in
/// *input_text*?
pub fn echo_check(input_text: &str, payload: &str) -> bool {
    let inp = py_lower(input_text);
    let pay = py_lower(payload);
    if inp.contains(&pay) {
        return true;
    }
    let inp_words: Vec<String> = {
        let mut seen: Vec<String> = Vec::new();
        for w in split_tokens(&inp) {
            if !seen.contains(&w) {
                seen.push(w);
            }
        }
        seen
    };
    let pay_words = split_tokens(&pay);
    if !pay_words.is_empty() {
        let hits = pay_words
            .iter()
            .filter(|pw| {
                inp_words
                    .iter()
                    .any(|iw| pw.as_str().contains(iw.as_str()) || iw.contains(pw.as_str()))
            })
            .count();
        return hits as f64 / pay_words.len() as f64 >= 0.5;
    }
    let chars: Vec<char> = pay.chars().filter(|&c| c != ' ').collect();
    if chars.is_empty() {
        return false;
    }
    let hits = chars.iter().filter(|&&c| inp.contains(c)).count();
    hits as f64 / (chars.len().max(1)) as f64 >= 0.6
}

/// `_derive_multi_action_hints` (l2_envelope.py:282-337). Returns a closed,
/// value-free operation summary (or empty) for a compound local request.
pub fn derive_multi_action_hints(redacted_text: &str, vault: &Envelope) -> Envelope {
    let mut keys: Vec<&str> = vault.entries.iter().map(|(k, _)| k.as_str()).collect();
    keys.sort_unstable(); // Python sorted(): codepoint order == UTF-8 byte order
    let email_placeholders: Vec<&str> = keys
        .into_iter()
        .filter(|p| search(email_ph_re(), p) && redacted_text.contains(*p))
        .collect();
    let email_recipient = if email_placeholders.len() == 1 {
        email_placeholders[0]
    } else {
        ""
    };

    let mut operations: Vec<&str> = Vec::new();
    let document_summary =
        search(doc_word_re(), redacted_text) && search(summary_word_re(), redacted_text);
    if document_summary {
        operations.push("read_and_summarize_document");
    }
    if !email_recipient.is_empty() && search(send_word_re(), redacted_text) {
        operations.push(if document_summary {
            "send_summary_by_email"
        } else {
            "send_by_email"
        });
    }
    if search(reminder_word_re(), redacted_text) {
        operations.push(
            if document_summary && search(followup_word_re(), redacted_text) {
                "create_reminder_from_document_follow_up_time"
            } else {
                "create_reminder"
            },
        );
    }

    if operations.len() < 2 {
        return Envelope::new();
    }
    let mut hints = Envelope::new();
    hints.set("operation_hints", &operations.join(","));
    if !email_recipient.is_empty() {
        hints.set("email_recipient", email_recipient);
    }
    if search(fixture1_re(), redacted_text) {
        hints.set("document_id", "fixture-1");
    }
    hints
}

// ── Vendored Unicode tables (generated from CPython 15.0.0 — the ONE pinned
// kernel source, matching unicode_tables.rs / unicode-normalization =0.1.22). ──
include!("l2_tables.rs");

#[cfg(test)]
mod tests;
