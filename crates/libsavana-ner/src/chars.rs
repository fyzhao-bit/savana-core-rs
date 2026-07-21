//! Char-classification port of `server/security/ner_gate.py` lines 52-75.
//!
//! Mirrors CPython's `unicodedata.category(c)` semantics exactly for the
//! categories the tokenizer cares about (Zs; Cc/Cf/Cs/Co/Cn; P*), via the
//! `unicode-categories` crate.

use unicode_categories::UnicodeCategories;

const CJK_RANGES: &[(u32, u32)] = &[
    (0x4E00, 0x9FFF),
    (0x3400, 0x4DBF),
    (0x20000, 0x2A6DF),
    (0x2A700, 0x2B73F),
    (0x2B740, 0x2B81F),
    (0x2B820, 0x2CEAF),
    (0xF900, 0xFAFF),
    (0x2F800, 0x2FA1F),
];

/// Mirrors Python `_is_cjk`.
pub fn is_cjk(cp: u32) -> bool {
    CJK_RANGES.iter().any(|&(lo, hi)| lo <= cp && cp <= hi)
}

/// Mirrors Python `_is_ws`: literal whitespace chars, or Unicode category Zs.
pub fn is_ws(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\n' | '\r') || c.is_separator_space()
}

/// Mirrors Python `_is_control`: Cc/Cf/Cs/Co/Cn, excluding \t \n \r.
///
/// `unicode-categories` has no direct `Cs`/`Cn` queries: `Cs` (surrogate) is
/// unrepresentable by a Rust `char` by construction, and `Cn` (unassigned) is
/// derived here as "not a member of any known category" — the standard
/// complement definition, since the Unicode categories partition the full
/// codepoint space.
pub fn is_control(c: char) -> bool {
    if matches!(c, '\t' | '\n' | '\r') {
        return false;
    }
    if c.is_other_control() || c.is_other_format() || c.is_other_private_use() {
        return true;
    }
    !(c.is_letter()
        || c.is_mark()
        || c.is_number()
        || c.is_punctuation()
        || c.is_symbol()
        || c.is_separator())
}

/// Mirrors Python `_is_punct`: ASCII punctuation ranges, or Unicode category
/// starting with "P" (Pc/Pd/Pe/Pf/Pi/Po/Ps).
pub fn is_punct(c: char) -> bool {
    let cp = c as u32;
    if (33..=47).contains(&cp)
        || (58..=64).contains(&cp)
        || (91..=96).contains(&cp)
        || (123..=126).contains(&cp)
    {
        return true;
    }
    c.is_punctuation()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cjk() {
        assert!(is_cjk('中' as u32));
        assert!(!is_cjk('a' as u32));
    }

    #[test]
    fn ws() {
        assert!(is_ws(' '));
        assert!(is_ws('\t'));
        assert!(is_ws('\u{00A0}'));
    }

    #[test]
    fn control() {
        assert!(!is_control('\t'));
        assert!(!is_control('\n'));
        assert!(!is_control('\r'));
        assert!(is_control('\u{001C}'));
    }

    #[test]
    fn punct() {
        assert!(is_punct('!'));
        assert!(is_punct('@'));
        assert!(is_punct('。'));
        assert!(!is_punct('a'));
        assert!(!is_punct('中'));
    }
}
