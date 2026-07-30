use std::io::Write as _;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use savana_kernel_protocol::v2::UnixMillisV2;
use zeroize::Zeroizing;

use crate::worker_protocol::{
    decode_parser_worker_frame, encode_parser_complete_frame, encode_parser_failed_frame,
    encode_parser_page_frame, parser_transcript_begin, parser_transcript_step,
    verify_parser_worker_child_job, ParserWorkerFrameV2, ParserWorkerProtocolErrorV2,
    VerifiedParserWorkerJobV2, MAX_PARSER_CHUNK_BYTES, MAX_PARSER_JOB_DESCRIPTOR_BYTES,
    MAX_PARSER_ORIGINAL_BYTES, MAX_PARSER_WORKER_FRAME_BYTES,
};

const MAX_CHILD_JOB_FRAME_BYTES: usize =
    MAX_PARSER_JOB_DESCRIPTOR_BYTES + MAX_PARSER_ORIGINAL_BYTES + 256;

struct ChildJobV2 {
    verified: VerifiedParserWorkerJobV2,
    original: Zeroizing<Vec<u8>>,
    signing_key: SigningKey,
}

pub(crate) fn run_stdio() -> Result<(), &'static str> {
    let input = read_frame(std::io::stdin().lock(), MAX_CHILD_JOB_FRAME_BYTES)?;
    let now = unix_now()?;
    let frames = match decode_child_job(&input, now).and_then(|job| execute_job(&job, now)) {
        Ok(frames) => frames,
        Err(_) => vec![encode_parser_failed_frame(1).map_err(|_| "encode failure")?],
    };
    let mut stdout = std::io::stdout().lock();
    for frame in frames {
        write_frame(&mut stdout, &frame)?;
    }
    stdout.flush().map_err(|_| "flush worker output")
}

fn decode_child_job(
    bytes: &[u8],
    now: UnixMillisV2,
) -> Result<ChildJobV2, ParserWorkerProtocolErrorV2> {
    if bytes.is_empty() || bytes.len() > MAX_CHILD_JOB_FRAME_BYTES {
        return Err(ParserWorkerProtocolErrorV2::Bounds);
    }
    let mut decoder = minicbor::Decoder::new(bytes);
    require_array(&mut decoder, 5)?;
    if decoder
        .u16()
        .map_err(|_| ParserWorkerProtocolErrorV2::NonCanonical)?
        != 2
    {
        return Err(ParserWorkerProtocolErrorV2::NonCanonical);
    }
    let descriptor = decoder
        .bytes()
        .map_err(|_| ParserWorkerProtocolErrorV2::NonCanonical)?;
    let original = decoder
        .bytes()
        .map_err(|_| ParserWorkerProtocolErrorV2::NonCanonical)?;
    let seed = decode_fixed::<32>(&mut decoder)?;
    let parent_public_key = decode_fixed::<32>(&mut decoder)?;
    if decoder.position() != bytes.len() {
        return Err(ParserWorkerProtocolErrorV2::NonCanonical);
    }
    let canonical = encode_child_job(descriptor, original, &seed, &parent_public_key)?;
    if canonical != bytes {
        return Err(ParserWorkerProtocolErrorV2::NonCanonical);
    }
    let seed = Zeroizing::new(seed);
    let verified =
        verify_parser_worker_child_job(descriptor, original, parent_public_key, &seed, now)?;
    Ok(ChildJobV2 {
        verified,
        original: Zeroizing::new(original.to_vec()),
        signing_key: SigningKey::from_bytes(&seed),
    })
}

fn execute_job(
    job: &ChildJobV2,
    completed_at: UnixMillisV2,
) -> Result<Vec<Vec<u8>>, ParserWorkerProtocolErrorV2> {
    if completed_at.get() == 0 || completed_at.get() >= job.verified.expires_at().get() {
        return Err(ParserWorkerProtocolErrorV2::Expired);
    }
    // The first production worker intentionally supports the closed UTF-8
    // parser profile. Other document/OCR formats fail closed until a measured
    // codec implementing this same private ABI is installed.
    std::str::from_utf8(&job.original).map_err(|_| ParserWorkerProtocolErrorV2::BindingMismatch)?;
    if job.original.is_empty()
        || job.original.len() > job.verified.output_limit_bytes() as usize
        || job.verified.maximum_pages() == 0
    {
        return Err(ParserWorkerProtocolErrorV2::Bounds);
    }

    let chunks = job.original.chunks(MAX_PARSER_CHUNK_BYTES);
    let chunk_count = chunks.len();
    let mut frames = Vec::new();
    frames
        .try_reserve_exact(chunk_count.saturating_add(1))
        .map_err(|_| ParserWorkerProtocolErrorV2::Bounds)?;
    let mut transcript = parser_transcript_begin(&job.verified);
    for (chunk_index, chunk) in job.original.chunks(MAX_PARSER_CHUNK_BYTES).enumerate() {
        let frame = encode_parser_page_frame(
            job.verified.job_nonce(),
            0,
            u32::try_from(chunk_index).map_err(|_| ParserWorkerProtocolErrorV2::Bounds)?,
            chunk_index + 1 == chunk_count,
            chunk,
        )?;
        let decoded = decode_parser_worker_frame(&frame, &job.verified)?;
        let ParserWorkerFrameV2::Page(page) = decoded else {
            return Err(ParserWorkerProtocolErrorV2::NonCanonical);
        };
        transcript = parser_transcript_step(transcript, page.canonical_without_attestation());
        frames.push(frame);
    }
    frames.push(encode_parser_complete_frame(
        &job.verified,
        &job.signing_key,
        1,
        transcript,
        &job.original,
        completed_at,
    )?);
    Ok(frames)
}

fn encode_child_job(
    descriptor: &[u8],
    original: &[u8],
    seed: &[u8; 32],
    parent_public_key: &[u8; 32],
) -> Result<Vec<u8>, ParserWorkerProtocolErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(5)
        .and_then(|encoder| encoder.u16(2))
        .and_then(|encoder| encoder.bytes(descriptor))
        .and_then(|encoder| encoder.bytes(original))
        .and_then(|encoder| encoder.bytes(seed))
        .and_then(|encoder| encoder.bytes(parent_public_key))
        .map_err(|_| ParserWorkerProtocolErrorV2::Bounds)?;
    Ok(encoder.into_writer())
}

fn read_frame(mut input: impl std::io::Read, maximum: usize) -> Result<Vec<u8>, &'static str> {
    let mut header = [0_u8; 4];
    input
        .read_exact(&mut header)
        .map_err(|_| "read worker frame header")?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > maximum {
        return Err("worker frame exceeds bound");
    }
    let mut body = Vec::new();
    body.try_reserve_exact(length)
        .map_err(|_| "reserve worker frame")?;
    body.resize(length, 0);
    input
        .read_exact(&mut body)
        .map_err(|_| "read worker frame body")?;
    Ok(body)
}

fn write_frame(mut output: impl std::io::Write, payload: &[u8]) -> Result<(), &'static str> {
    if payload.is_empty() || payload.len() > MAX_PARSER_WORKER_FRAME_BYTES {
        return Err("worker output exceeds bound");
    }
    let length = u32::try_from(payload.len()).map_err(|_| "worker output exceeds u32")?;
    output
        .write_all(&length.to_be_bytes())
        .and_then(|_| output.write_all(payload))
        .map_err(|_| "write worker output")
}

fn unix_now() -> Result<UnixMillisV2, &'static str> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "clock before unix epoch")?
        .as_millis();
    let millis = u64::try_from(millis).map_err(|_| "clock exceeds u64")?;
    if millis == 0 {
        return Err("zero unix time");
    }
    Ok(UnixMillisV2::new(millis))
}

fn require_array(
    decoder: &mut minicbor::Decoder<'_>,
    expected: u64,
) -> Result<(), ParserWorkerProtocolErrorV2> {
    if decoder
        .array()
        .map_err(|_| ParserWorkerProtocolErrorV2::NonCanonical)?
        != Some(expected)
    {
        return Err(ParserWorkerProtocolErrorV2::NonCanonical);
    }
    Ok(())
}

fn decode_fixed<const N: usize>(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<[u8; N], ParserWorkerProtocolErrorV2> {
    decoder
        .bytes()
        .map_err(|_| ParserWorkerProtocolErrorV2::NonCanonical)?
        .try_into()
        .map_err(|_| ParserWorkerProtocolErrorV2::NonCanonical)
}

#[cfg(test)]
mod tests {
    use savana_kernel_protocol::v2::UnixMillisV2;

    use super::{decode_child_job, encode_child_job, execute_job};
    use crate::worker_protocol::test_support::fixture;
    use crate::worker_protocol::{decode_parser_worker_frame, ParserWorkerFrameV2};

    #[test]
    fn child_revalidates_job_and_emits_one_signed_terminal() {
        let fixture = fixture();
        let seed = fixture.ephemeral_signing_key.to_bytes();
        let input = encode_child_job(
            &fixture.descriptor,
            &fixture.original,
            &seed,
            &fixture.parent_public_key,
        )
        .unwrap();
        let job = decode_child_job(&input, UnixMillisV2::new(10)).unwrap();
        let frames = execute_job(&job, UnixMillisV2::new(11)).unwrap();

        assert_eq!(frames.len(), 2);
        assert!(matches!(
            decode_parser_worker_frame(&frames[0], &job.verified).unwrap(),
            ParserWorkerFrameV2::Page(_)
        ));
        assert!(matches!(
            decode_parser_worker_frame(&frames[1], &job.verified).unwrap(),
            ParserWorkerFrameV2::Complete(_)
        ));
    }

    #[test]
    fn child_rejects_a_seed_that_does_not_match_the_signed_descriptor() {
        let fixture = fixture();
        let input = encode_child_job(
            &fixture.descriptor,
            &fixture.original,
            &[0x55; 32],
            &fixture.parent_public_key,
        )
        .unwrap();
        assert!(decode_child_job(&input, UnixMillisV2::new(10)).is_err());
    }
}
