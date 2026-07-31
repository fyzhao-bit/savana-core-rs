//! The deterministic G2 leak gate: the security blocklist and PII redaction
//! that a declassification must pass before the kernel will lower a value's
//! confidentiality.
//!
//! Ported from the legacy `libsavana-ner::l2_filter`, itself a byte-exact port
//! of `server/security/l2_envelope.py` and `slm_gate.py`. Only the gate slice
//! crosses over — `security_match` and `redact_pii` and the pinned-Unicode
//! regex machinery they rest on. The JARVIS L2 envelope orchestration around
//! them stays in the legacy crate: it is V1 application logic over intents,
//! apps, and slots, and none of it belongs in the V2 kernel.
//!
//! ## Why this runs in the kernel rather than in a worker
//!
//! `kernel_declassification` takes a `leak_gate_digest` as a parameter, so
//! whoever calls it asserts the gate ran. If a masking worker produced that
//! digest the kernel would be trusting an outside component for a property it
//! cannot check: a sandbox stops a worker from exfiltrating plaintext, but it
//! does not stop one from claiming it masked. Declassification is the single
//! point where the kernel gives up a confidentiality guarantee, so the kernel
//! performs the check itself. Detection may be delegated — an ML NER model in
//! a measured worker can propose spans — but the gate that decides is here and
//! is deterministic, which is also what G5 replay requires.
//!
//! ## The regex-engine wall
//!
//! These are security patterns, so a miss is a bypass. Python `re` and the
//! `regex` crate disagree on `\b`, `\s`, and `\d`, and the `\w` divergence is
//! in the bypass direction. Every class is therefore rewritten over the
//! vendored CPython 15.0.0 tables in [`super::leak_gate_tables`] rather than
//! taken from the engine, and Python's `\b` is rewritten as its literal
//! two-sided definition. That rewrite needs lookaround, which is why the gate
//! uses `fancy-regex` rather than the linear engine.
//!
//! Backtracking is bounded and every runtime error fails CLOSED — an engine
//! error counts as a blocklist hit — so adversarial input can only ever cause
//! the gate to over-block, never to miss.

use std::sync::OnceLock;

use fancy_regex::Regex as Fancy;
use savana_kernel_protocol::v2::Digest32V2;
use sha2::{Digest as _, Sha256};

use super::leak_gate_tables::{PY_DECIMAL_RANGES, PY_WORD_RANGES, WS_SET};
use super::{value_digest_v2, G3Error, KernelValueV2};

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
pub(crate) const BACKTRACK_LIMIT_V2: usize = 1_000_000;

/// Compile a Python `re` pattern to a byte-exact fancy-regex (CPython 15.0.0
/// `\b`/`\s`/`\d`/`\w` semantics via [`pythonize`] over the ONE vendored table
/// source).
pub(crate) fn build_fancy(pat: &str, ignorecase: bool) -> Fancy {
    let body = pythonize(pat);
    let full = if ignorecase {
        format!("(?i){body}")
    } else {
        body
    };
    fancy_regex::RegexBuilder::new(&full)
        .backtrack_limit(BACKTRACK_LIMIT_V2)
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

// ── The kernel-facing gate ──

/// What the gate must prove about a value before a particular declassification.
///
/// The duty is not uniform across transitions, and making it uniform would
/// break the system in one of two directions. Requiring PII to be absent from
/// the approval display would render the human's decision meaningless — nobody
/// can meaningfully approve "send [电话号码] to [邮箱]?" — and the human-in-the-
/// loop control is what the whole design rests on. Requiring it of the
/// execution envelope would leave the executor with nothing real to act on.
/// Conversely, letting the planner envelope through unredacted would hand raw
/// personal data to an external model, which is the leak the gate exists to
/// stop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LeakGateDutyV2 {
    /// The recipient is entitled to see real values, so only the content
    /// blocklist applies. Injected instructions are not "data the recipient is
    /// entitled to" under any transition, so this is never empty.
    BlocklistOnly,
    /// The recipient is a language model, so the value must additionally carry
    /// no residual PII.
    BlocklistAndNoResidualPii,
}

/// Identity of the gate that ran: the blocklist and the PII table it used.
///
/// Bound into every gate digest so a record proves WHICH gate cleared it. Without
/// this a replay under an edited pattern set would reproduce the digest of a
/// check that never happened, and silently revalidate a value the current gate
/// would reject.
fn pattern_set_digest() -> Digest32V2 {
    static D: OnceLock<Digest32V2> = OnceLock::new();
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
        Digest32V2::new(hasher.finalize().into())
    })
}

/// Run the gate over every text leaf of `value` and return the evidence digest,
/// or reject the declassification.
///
/// The digest is computed here rather than accepted from the caller. A caller-
/// supplied digest is an assertion that the check happened, and the kernel
/// cannot distinguish an honest assertion from a fabricated one — which would
/// make the gate optional in exactly the place that gives up a confidentiality
/// guarantee. Detection may still be delegated to a measured worker that
/// proposes spans; this decision may not be.
pub(crate) fn enforce_for_declassification(
    value: &KernelValueV2,
    duty: LeakGateDutyV2,
) -> Result<Digest32V2, G3Error> {
    let mut rejection = None;
    value.every_text_leaf(&mut |text| {
        if security_match(text) {
            rejection = Some(G3Error::LeakGateBlockedContent);
            return false;
        }
        // Idempotence is the check: if redaction would still change this text,
        // the masking step either did not run or did not finish, so the value is
        // not in the state this transition claims it is.
        if duty == LeakGateDutyV2::BlocklistAndNoResidualPii && redact_pii(text) != text {
            rejection = Some(G3Error::LeakGateResidualPii);
            return false;
        }
        true
    });
    if let Some(error) = rejection {
        return Err(error);
    }

    let mut hasher = Sha256::new();
    hasher.update(b"SAVANA_LEAK_GATE_V2\0");
    hasher.update(pattern_set_digest().as_bytes());
    hasher.update(match duty {
        LeakGateDutyV2::BlocklistOnly => [1u8],
        LeakGateDutyV2::BlocklistAndNoResidualPii => [2u8],
    });
    hasher.update(value_digest_v2(value)?.as_bytes());
    Ok(Digest32V2::new(hasher.finalize().into()))
}
