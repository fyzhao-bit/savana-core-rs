//! Classify texts with the kernel's own leak gate, for measuring what an
//! experiment actually sent to a model provider.
//!
//! Input on stdin: texts separated by NUL bytes. Output: one line per text,
//! `<credential spans> <personal-data spans> <protected-reference spans>
//! <blocklist match 0|1> <bytes>`, using exactly `pii_spans` and
//! `security_match` (the definitions the kernel's G2/G3 gate enforces).
use std::io::{self, BufWriter, Read, Write};

use savana_leak_gate::{pii_spans, security_match, PiiClassV2};

fn main() -> io::Result<()> {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;
    let mut out = BufWriter::new(io::stdout().lock());
    for chunk in input.split(|b| *b == 0) {
        let text = String::from_utf8_lossy(chunk);
        let (mut credential, mut personal, mut protected) = (0usize, 0usize, 0usize);
        for span in pii_spans(&text) {
            match span.class {
                PiiClassV2::Credential => credential += 1,
                PiiClassV2::PersonalData => personal += 1,
                PiiClassV2::ProtectedReference => protected += 1,
            }
        }
        writeln!(out, "{credential} {personal} {protected} {} {}", u8::from(security_match(&text)), chunk.len())?;
    }
    out.flush()
}
