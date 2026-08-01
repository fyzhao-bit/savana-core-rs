//! The deterministic leak gate: ONE definition of what counts as sensitive,
//! shared by the component that masks and the component that verifies.
//!
//! Ported from the legacy `libsavana-ner::l2_filter`, itself a byte-exact port
//! of `server/security/l2_envelope.py` and `slm_gate.py`.
//!
//! ## Why this is its own crate
//!
//! Masking happens at ingress (`savana-input-runtime`); verification happens at
//! declassification (`savana-policy-core`). Those two crates are siblings — each
//! depends only on the protocol — so neither can own the definition without
//! inverting the dependency graph. They previously carried SEPARATE PII
//! definitions, a hand-written byte scanner covering five classes on one side
//! and these seventeen patterns on the other. Two definitions cannot agree by
//! inspection, and the one that masks disagreeing with the one that decides is
//! how a value gets declassified while still carrying the data the gate exists
//! to stop. Both now call the same functions here, so they agree by
//! construction rather than by review.
//!
//! ## The regex-engine wall
//!
//! These are security patterns, so a miss is a bypass. Python `re` and the
//! `regex` crate disagree on `\b`, `\s`, and `\d`, and the `\w` divergence is
//! in the bypass direction. Every class is therefore rewritten over the
//! vendored CPython 15.0.0 `tables` module rather than taken from the
//! engine, and Python's `\b` is rewritten as its literal two-sided definition.
//! That rewrite needs lookaround, which is why this uses `fancy-regex` rather
//! than the linear engine.
//!
//! Backtracking is bounded and every runtime error fails CLOSED — an engine
//! error counts as a blocklist hit — so adversarial input can only ever cause
//! the gate to over-block, never to miss.

#![forbid(unsafe_code)]

mod scanner;
mod tables;

use std::sync::OnceLock;

use fancy_regex::Regex as Fancy;
use sha2::{Digest as _, Sha256};

use scanner::scanned_spans;
use tables::{PY_DECIMAL_RANGES, PY_WORD_RANGES, WS_SET};

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

/// Backtracking steps a single gate match may take before the engine gives up
/// and returns an error, which every caller here treats as a hit.
///
/// This is fancy-regex 0.14's own default, pinned here so it becomes a property
/// of the gate rather than of the dependency: a future release that changes its
/// default must not silently change how much work adversarial input can extract
/// from the kernel, nor how readily the gate falls back to over-blocking.
pub const BACKTRACK_LIMIT: usize = 1_000_000;

/// Compile a Python `re` pattern to a byte-exact fancy-regex (CPython 15.0.0
/// `\b`/`\s`/`\d`/`\w` semantics via [`pythonize`] over the ONE vendored table
/// source).
fn build_fancy(pat: &str, ignorecase: bool) -> Fancy {
    let body = pythonize(pat);
    let full = if ignorecase {
        format!("(?i){body}")
    } else {
        body
    };
    fancy_regex::RegexBuilder::new(&full)
        .backtrack_limit(BACKTRACK_LIMIT)
        .build()
        .expect("leak-gate pattern compiles")
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

// ── Identity of the gate ──

/// SHA-256 over the blocklist and the PII table, domain-separated.
///
/// Binds WHICH gate ran into any evidence a caller records. Without it a replay
/// under an edited pattern set would reproduce the digest of a check that never
/// happened, and silently revalidate a value the current gate would reject.
pub fn pattern_set_digest() -> [u8; 32] {
    static D: OnceLock<[u8; 32]> = OnceLock::new();
    *D.get_or_init(|| {
        let mut hasher = Sha256::new();
        hasher.update(b"SAVANA_LEAK_GATE_PATTERNS_V2\0");
        hasher.update((SECURITY_PATTERNS.len() as u32).to_be_bytes());
        for pattern in SECURITY_PATTERNS {
            hasher.update((pattern.len() as u32).to_be_bytes());
            hasher.update(pattern.as_bytes());
        }
        let redactions = redact_patterns();
        hasher.update((redactions.len() as u32).to_be_bytes());
        for redaction in redactions {
            hasher.update((redaction.repl.len() as u32).to_be_bytes());
            hasher.update(redaction.repl.as_bytes());
        }
        hasher.finalize().into()
    })
}

// ── Spans, for the component that masks ──

/// What a matched span is, coarse enough to survive pattern-table edits.
///
/// Callers that must name a class to a recipient map these onward; the
/// distinction that matters at every boundary is credential versus personal
/// data, because the two have different consequences when they leak.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PiiClassV2 {
    /// Keys, tokens, and anything else that grants access on presentation.
    Credential,
    /// Data about a person: identifiers, contact details, account numbers.
    PersonalData,
    /// A path or filename whose name alone discloses protected content.
    ProtectedReference,
}

/// A region of the input the gate considers sensitive, in byte offsets into the
/// string it was given.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PiiSpanV2 {
    pub start: usize,
    pub end: usize,
    pub class: PiiClassV2,
}

/// Class per entry of the PII table, in `_PII_PATTERNS` order.
const PII_CLASSES: [PiiClassV2; 17] = [
    PiiClassV2::Credential,         // private key block
    PiiClassV2::Credential,         // JWT
    PiiClassV2::Credential,         // sk-ant-api
    PiiClassV2::Credential,         // sk-/sk-proj-
    PiiClassV2::Credential,         // AWS key id
    PiiClassV2::Credential,         // Bearer/Basic header
    PiiClassV2::Credential,         // api_key= / access_token= style
    PiiClassV2::PersonalData,       // bank card
    PiiClassV2::PersonalData,       // national id
    PiiClassV2::PersonalData,       // mainland mobile
    PiiClassV2::PersonalData,       // general telephone
    PiiClassV2::PersonalData,       // email
    PiiClassV2::PersonalData,       // IP address
    PiiClassV2::PersonalData,       // payment account
    PiiClassV2::ProtectedReference, // sensitive filename
    PiiClassV2::ProtectedReference, // sensitive file path
    PiiClassV2::Credential,         // ssh key filename
];

/// Every region [`redact_pii`] would rewrite, as spans into `text`.
///
/// This is the masking half of the same definition the verifying half uses.
/// [`redact_pii`] applies its table sequentially, so a later pattern never sees
/// text an earlier one already claimed; the equivalent here is to skip a match
/// that overlaps a claimed region. That keeps the ONE property both callers
/// depend on — `pii_spans(t).is_empty()` exactly when `redact_pii(t) == t` —
/// which the differential asserts over the whole corpus rather than by
/// inspection.
pub fn pii_spans(text: &str) -> Vec<PiiSpanV2> {
    // Candidates carry a precedence key: class strength first, then the order
    // the source produced them. Credential outranks the rest so that a region
    // both sources claim is masked as the more dangerous of the two — the
    // scanner reads `Bearer <anything>` as a credential where the table sees
    // only an address inside it, and the blunter reading is the safe one.
    let mut candidates: Vec<(u8, usize, PiiSpanV2)> = Vec::new();
    let mut order = 0;
    for span in scanned_spans(text) {
        candidates.push((
            class_rank(span.class),
            order,
            PiiSpanV2 {
                start: span.start,
                end: span.end,
                class: span.class,
            },
        ));
        order += 1;
    }
    for (pattern, class) in redact_patterns().iter().zip(PII_CLASSES) {
        let mut from = 0;
        // A pattern that errors mid-scan yields whatever it already found. The
        // blocklist fails closed by treating an error as a hit; the same
        // direction applies here, since a short span list only ever means the
        // verifier refuses the value later.
        while let Ok(Some(found)) = pattern.re.find_from_pos(text, from) {
            let (start, end) = (found.start(), found.end());
            if end == start {
                break;
            }
            from = end;
            candidates.push((class_rank(class), order, PiiSpanV2 { start, end, class }));
            order += 1;
        }
    }
    candidates.sort_unstable_by_key(|(rank, order, span)| (*rank, *order, span.start));

    let mut spans: Vec<PiiSpanV2> = Vec::new();
    for (_, _, span) in candidates {
        if spans
            .iter()
            .any(|claimed| span.start < claimed.end && claimed.start < span.end)
        {
            continue;
        }
        spans.push(span);
    }
    spans.sort_unstable_by_key(|span| (span.start, span.end));
    spans
}

const fn class_rank(class: PiiClassV2) -> u8 {
    match class {
        PiiClassV2::Credential => 0,
        PiiClassV2::ProtectedReference => 1,
        PiiClassV2::PersonalData => 2,
    }
}

#[cfg(test)]
mod tests;
