//! Unicode 16.0.0 General_Category=Cf OR Default_Ignorable_Code_Point.
//! Factual ranges derived from the pinned Unicode Character Database:
//! <https://www.unicode.org/Public/16.0.0/ucd/UnicodeData.txt>
//! <https://www.unicode.org/Public/16.0.0/ucd/DerivedCoreProperties.txt>
//! Updates require a reviewed profile-version change, not host Unicode behavior.
//! Cc plus line/paragraph separators are rejected separately by the caller.
const RANGES: &[(u32, u32)] = &[
    (0xad, 0xad),
    (0x34f, 0x34f),
    (0x600, 0x605),
    (0x61c, 0x61c),
    (0x6dd, 0x6dd),
    (0x70f, 0x70f),
    (0x890, 0x891),
    (0x8e2, 0x8e2),
    (0x115f, 0x1160),
    (0x17b4, 0x17b5),
    (0x180b, 0x180f),
    (0x200b, 0x200f),
    (0x202a, 0x202e),
    (0x2060, 0x206f),
    (0x3164, 0x3164),
    (0xfe00, 0xfe0f),
    (0xfeff, 0xfeff),
    (0xffa0, 0xffa0),
    (0xfff0, 0xfffb),
    (0x110bd, 0x110bd),
    (0x110cd, 0x110cd),
    (0x13430, 0x1343f),
    (0x1bca0, 0x1bca3),
    (0x1d173, 0x1d17a),
    (0xe0000, 0xe0fff),
];

pub(super) fn formatting_or_ignorable(c: char) -> bool {
    let n = c as u32;
    RANGES.iter().any(|&(start, end)| n >= start && n <= end)
}
