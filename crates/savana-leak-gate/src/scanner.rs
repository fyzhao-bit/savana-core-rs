use crate::PiiClassV2;

// ── The byte scanner ──
//
// These detectors predate the pattern table and are NOT redundant with it. The
// table's credential-assignment pattern requires one of a fixed keyword list
// and a sixteen-character floor, so `password=hunter2` passes it untouched,
// and its bearer pattern requires a token-shaped value, so `Bearer <anything>`
// is not treated as a credential. The scanner is deliberately blunter on
// exactly those cases. Keeping both and taking the union is what makes the
// masker at least as strict as the verifier.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ScannedSpan {
    pub(crate) start: usize,
    pub(crate) end: usize,
    pub(crate) class: PiiClassV2,
}

pub(crate) fn scanned_spans(value: &str) -> Vec<ScannedSpan> {
    let bytes = value.as_bytes();
    let mut spans = Vec::new();
    detect_marker_to_token(
        bytes,
        b"-----BEGIN ",
        b"-----END ",
        PiiClassV2::Credential,
        &mut spans,
    );
    detect_prefixed_secret(bytes, b"bearer ", PiiClassV2::Credential, &mut spans);
    for prefix in [b"password=".as_slice(), b"api_key=", b"secret="] {
        detect_prefixed_secret(bytes, prefix, PiiClassV2::Credential, &mut spans);
    }
    detect_emails(bytes, &mut spans);
    detect_phone_numbers(bytes, &mut spans);
    spans
}

fn ascii_lowercase(bytes: &[u8]) -> Vec<u8> {
    bytes.iter().map(u8::to_ascii_lowercase).collect()
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    (!needle.is_empty() && needle.len() <= haystack.len())
        .then(|| {
            haystack
                .windows(needle.len())
                .position(|window| window == needle)
        })
        .flatten()
}

fn is_email_local(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b".!#$%&'*+/=?^_`{|}~-".contains(&byte)
}

fn is_email_domain(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-')
}

fn detect_marker_to_token(
    bytes: &[u8],
    start_marker: &[u8],
    end_marker: &[u8],
    class: PiiClassV2,
    spans: &mut Vec<ScannedSpan>,
) {
    let folded = ascii_lowercase(bytes);
    let start_folded = ascii_lowercase(start_marker);
    let end_folded = ascii_lowercase(end_marker);
    let mut cursor = 0;
    while let Some(relative_start) = find_bytes(&folded[cursor..], &start_folded) {
        let start = cursor + relative_start;
        let search_from = start + start_folded.len();
        let end = find_bytes(&folded[search_from..], &end_folded)
            .map(|relative| search_from + relative + end_folded.len())
            .unwrap_or(bytes.len());
        spans.push(ScannedSpan { start, end, class });
        cursor = end;
    }
}

fn detect_prefixed_secret(
    bytes: &[u8],
    prefix: &[u8],
    class: PiiClassV2,
    spans: &mut Vec<ScannedSpan>,
) {
    let folded = ascii_lowercase(bytes);
    let prefix = ascii_lowercase(prefix);
    let mut cursor = 0;
    while let Some(relative) = find_bytes(&folded[cursor..], &prefix) {
        let start = cursor + relative;
        let mut end = start + prefix.len();
        while end < bytes.len()
            && !bytes[end].is_ascii_whitespace()
            && !b",;\"'".contains(&bytes[end])
        {
            end += 1;
        }
        spans.push(ScannedSpan { start, end, class });
        cursor = end.max(start + 1);
    }
}

fn detect_emails(bytes: &[u8], spans: &mut Vec<ScannedSpan>) {
    for (index, byte) in bytes.iter().enumerate() {
        if *byte != b'@' {
            continue;
        }
        let mut start = index;
        while start > 0 && is_email_local(bytes[start - 1]) {
            start -= 1;
        }
        let mut end = index + 1;
        while end < bytes.len() && is_email_domain(bytes[end]) {
            end += 1;
        }
        let domain = &bytes[index + 1..end];
        if start < index
            && domain.contains(&b'.')
            && !domain.starts_with(b".")
            && !domain.ends_with(b".")
        {
            spans.push(ScannedSpan {
                start,
                end,
                class: PiiClassV2::PersonalData,
            });
        }
    }
}

fn detect_phone_numbers(bytes: &[u8], spans: &mut Vec<ScannedSpan>) {
    let mut cursor = 0;
    while cursor < bytes.len() {
        if !bytes[cursor].is_ascii_digit() && bytes[cursor] != b'+' {
            cursor += 1;
            continue;
        }
        let start = cursor;
        let mut digits = 0_usize;
        while cursor < bytes.len()
            && (bytes[cursor].is_ascii_digit() || b"+-(). ".contains(&bytes[cursor]))
        {
            digits += usize::from(bytes[cursor].is_ascii_digit());
            cursor += 1;
        }
        let mut end = cursor;
        while end > start && bytes[end - 1].is_ascii_whitespace() {
            end -= 1;
        }
        if (7..=15).contains(&digits) {
            spans.push(ScannedSpan {
                start,
                end,
                class: PiiClassV2::PersonalData,
            });
        }
        cursor = cursor.max(start + 1);
    }
}
