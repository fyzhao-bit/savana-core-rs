use std::io::Write as _;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use savana_kernel_protocol::v2::{Digest32V2, UnixMillisV2};
use zeroize::Zeroizing;

use crate::worker_protocol::{
    connector_material_digest, connector_response_digest, connector_transcript_begin,
    connector_transcript_step, decode_provider_response_frame, encode_connector_outcome_frame,
    encode_connector_prepared_frame, outcome_transcript_material, prepared_transcript_material,
    verify_connector_worker_child_job, ConnectorCodecJobModeV2, ConnectorOutcomeKindV2,
    ConnectorWorkerProtocolErrorV2, VerifiedConnectorWorkerJobV2, MAX_CONNECTOR_DESCRIPTOR_BYTES,
    MAX_CONNECTOR_FRAME_BYTES, MAX_CONNECTOR_MATERIAL_BYTES, MAX_CONNECTOR_RESPONSE_BYTES,
};

const MAX_CHILD_JOB_FRAME_BYTES: usize =
    MAX_CONNECTOR_DESCRIPTOR_BYTES + MAX_CONNECTOR_RESPONSE_BYTES + 512;

#[cfg(feature = "intent-bound-test-support")]
#[path = "intent_bound_worker_fixture.rs"]
pub(crate) mod intent_bound_fixture;

enum ChildInputV2 {
    Prepare(Zeroizing<Vec<u8>>),
    Decode { response: Zeroizing<Vec<u8>> },
}

struct ChildJobV2 {
    verified: VerifiedConnectorWorkerJobV2,
    input: ChildInputV2,
    signing_key: SigningKey,
}

pub(crate) fn run_stdio() -> Result<(), &'static str> {
    let first = read_frame(std::io::stdin().lock(), MAX_CHILD_JOB_FRAME_BYTES)?;
    let now = unix_now()?;
    let job = decode_child_job(&first, now).map_err(|_| "invalid connector job")?;
    let mut stdin = std::io::stdin().lock();
    let mut stdout = std::io::stdout().lock();
    match &job.input {
        ChildInputV2::Prepare(material) => {
            let (prepared, prepared_transcript) =
                prepare_frame(&job, material).map_err(|_| "prepare connector request")?;
            write_frame(&mut stdout, &prepared)?;
            stdout.flush().map_err(|_| "flush prepared request")?;
            let provider_frame = read_frame(&mut stdin, MAX_CONNECTOR_FRAME_BYTES)?;
            let (response, _effect_receipt) =
                decode_provider_response_frame(&provider_frame, &job.verified)
                    .map_err(|_| "invalid provider response")?;
            let terminal =
                completion_after_provider(&job, &provider_frame, prepared_transcript, &response)
                    .map_err(|_| "encode connector completion")?;
            write_frame(&mut stdout, &terminal)?;
        }
        ChildInputV2::Decode { response } => {
            let terminal = completion_for_retained(&job, response)
                .map_err(|_| "decode retained provider response")?;
            write_frame(&mut stdout, &terminal)?;
        }
    }
    stdout.flush().map_err(|_| "flush connector output")
}

fn decode_child_job(
    bytes: &[u8],
    now: UnixMillisV2,
) -> Result<ChildJobV2, ConnectorWorkerProtocolErrorV2> {
    if bytes.is_empty() || bytes.len() > MAX_CHILD_JOB_FRAME_BYTES {
        return Err(ConnectorWorkerProtocolErrorV2::Bounds);
    }
    let mut decoder = minicbor::Decoder::new(bytes);
    require_array(&mut decoder, 7)?;
    if decoder
        .u16()
        .map_err(|_| ConnectorWorkerProtocolErrorV2::NonCanonical)?
        != 2
    {
        return Err(ConnectorWorkerProtocolErrorV2::NonCanonical);
    }
    let descriptor = decoder
        .bytes()
        .map_err(|_| ConnectorWorkerProtocolErrorV2::NonCanonical)?;
    let mode = decoder
        .u16()
        .map_err(|_| ConnectorWorkerProtocolErrorV2::NonCanonical)?;
    let input = decoder
        .bytes()
        .map_err(|_| ConnectorWorkerProtocolErrorV2::NonCanonical)?;
    let effect_digest = decode_optional_digest(&mut decoder)?;
    let seed = decode_fixed::<32>(&mut decoder)?;
    let parent_public_key = decode_fixed::<32>(&mut decoder)?;
    if decoder.position() != bytes.len()
        || encode_child_job(
            descriptor,
            mode,
            input,
            effect_digest,
            &seed,
            &parent_public_key,
        )? != bytes
    {
        return Err(ConnectorWorkerProtocolErrorV2::NonCanonical);
    }
    let seed = Zeroizing::new(seed);
    let verified = verify_connector_worker_child_job(descriptor, parent_public_key, &seed, now)?;
    let input = match (mode, verified.mode()) {
        (1, ConnectorCodecJobModeV2::PrepareAndDecode)
            if effect_digest.is_none()
                && !input.is_empty()
                && input.len() <= MAX_CONNECTOR_MATERIAL_BYTES
                && connector_material_digest(input) == verified.bounded_material_digest() =>
        {
            ChildInputV2::Prepare(Zeroizing::new(input.to_vec()))
        }
        (2, ConnectorCodecJobModeV2::DecodeRetainedResponse)
            if !input.is_empty()
                && input.len() <= MAX_CONNECTOR_RESPONSE_BYTES
                && verified.retained_provider_response_digest()
                    == Some(connector_response_digest(input))
                && verified.retained_provider_response_length() == Some(input.len() as u32)
                && verified.effect_started_receipt_digest() == effect_digest =>
        {
            ChildInputV2::Decode {
                response: Zeroizing::new(input.to_vec()),
            }
        }
        _ => return Err(ConnectorWorkerProtocolErrorV2::BindingMismatch),
    };
    Ok(ChildJobV2 {
        verified,
        input,
        signing_key: SigningKey::from_bytes(&seed),
    })
}

fn prepare_frame(
    job: &ChildJobV2,
    material: &[u8],
) -> Result<(Vec<u8>, Digest32V2), ConnectorWorkerProtocolErrorV2> {
    let maximum_response_bytes = u32::try_from(MAX_CONNECTOR_RESPONSE_BYTES)
        .map_err(|_| ConnectorWorkerProtocolErrorV2::Bounds)?;
    let material_for_transcript =
        prepared_transcript_material(&job.verified, material, maximum_response_bytes)?;
    let transcript = connector_transcript_step(
        connector_transcript_begin(&job.verified),
        1,
        1,
        0,
        &material_for_transcript,
    );
    let frame = encode_connector_prepared_frame(
        &job.verified,
        &job.signing_key,
        material,
        maximum_response_bytes,
        transcript,
    )?;
    Ok((frame, transcript))
}

fn completion_after_provider(
    job: &ChildJobV2,
    provider_frame: &[u8],
    prepared_transcript: Digest32V2,
    response: &[u8],
) -> Result<Vec<u8>, ConnectorWorkerProtocolErrorV2> {
    let response_digest = connector_response_digest(response);
    let response_transcript =
        connector_transcript_step(prepared_transcript, 2, 2, 1, provider_frame);
    let outcome_material = outcome_transcript_material(
        &job.verified,
        ConnectorOutcomeKindV2::Completion,
        Some(response_digest),
        Some(response),
    )?;
    let outcome_transcript =
        connector_transcript_step(response_transcript, 1, 3, 2, &outcome_material);
    encode_connector_outcome_frame(
        &job.verified,
        &job.signing_key,
        ConnectorOutcomeKindV2::Completion,
        Some(response_digest),
        Some(response),
        outcome_transcript,
    )
}

fn completion_for_retained(
    job: &ChildJobV2,
    response: &[u8],
) -> Result<Vec<u8>, ConnectorWorkerProtocolErrorV2> {
    let response_digest = connector_response_digest(response);
    let outcome_material = outcome_transcript_material(
        &job.verified,
        ConnectorOutcomeKindV2::Completion,
        Some(response_digest),
        Some(response),
    )?;
    let outcome_transcript = connector_transcript_step(
        connector_transcript_begin(&job.verified),
        1,
        3,
        0,
        &outcome_material,
    );
    encode_connector_outcome_frame(
        &job.verified,
        &job.signing_key,
        ConnectorOutcomeKindV2::Completion,
        Some(response_digest),
        Some(response),
        outcome_transcript,
    )
}

fn encode_child_job(
    descriptor: &[u8],
    mode: u16,
    input: &[u8],
    effect_digest: Option<Digest32V2>,
    seed: &[u8; 32],
    parent_public_key: &[u8; 32],
) -> Result<Vec<u8>, ConnectorWorkerProtocolErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(7)
        .and_then(|encoder| encoder.u16(2))
        .and_then(|encoder| encoder.bytes(descriptor))
        .and_then(|encoder| encoder.u16(mode))
        .and_then(|encoder| encoder.bytes(input))
        .map_err(|_| ConnectorWorkerProtocolErrorV2::Bounds)?;
    match effect_digest {
        Some(value) => encoder
            .bytes(value.as_bytes())
            .map_err(|_| ConnectorWorkerProtocolErrorV2::Bounds)?,
        None => encoder
            .null()
            .map_err(|_| ConnectorWorkerProtocolErrorV2::Bounds)?,
    };
    encoder
        .bytes(seed)
        .and_then(|encoder| encoder.bytes(parent_public_key))
        .map_err(|_| ConnectorWorkerProtocolErrorV2::Bounds)?;
    Ok(encoder.into_writer())
}

fn read_frame(mut input: impl std::io::Read, maximum: usize) -> Result<Vec<u8>, &'static str> {
    let mut header = [0_u8; 4];
    input
        .read_exact(&mut header)
        .map_err(|_| "read connector frame header")?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > maximum {
        return Err("connector frame exceeds bound");
    }
    let mut body = Vec::new();
    body.try_reserve_exact(length)
        .map_err(|_| "reserve connector frame")?;
    body.resize(length, 0);
    input
        .read_exact(&mut body)
        .map_err(|_| "read connector frame body")?;
    Ok(body)
}

fn write_frame(mut output: impl std::io::Write, payload: &[u8]) -> Result<(), &'static str> {
    if payload.is_empty() || payload.len() > MAX_CONNECTOR_FRAME_BYTES {
        return Err("connector output exceeds bound");
    }
    let length = u32::try_from(payload.len()).map_err(|_| "connector output exceeds u32")?;
    output
        .write_all(&length.to_be_bytes())
        .and_then(|_| output.write_all(payload))
        .map_err(|_| "write connector output")
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
) -> Result<(), ConnectorWorkerProtocolErrorV2> {
    if decoder
        .array()
        .map_err(|_| ConnectorWorkerProtocolErrorV2::NonCanonical)?
        != Some(expected)
    {
        return Err(ConnectorWorkerProtocolErrorV2::NonCanonical);
    }
    Ok(())
}

fn decode_fixed<const N: usize>(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<[u8; N], ConnectorWorkerProtocolErrorV2> {
    decoder
        .bytes()
        .map_err(|_| ConnectorWorkerProtocolErrorV2::NonCanonical)?
        .try_into()
        .map_err(|_| ConnectorWorkerProtocolErrorV2::NonCanonical)
}

fn decode_optional_digest(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<Option<Digest32V2>, ConnectorWorkerProtocolErrorV2> {
    if decoder
        .datatype()
        .map_err(|_| ConnectorWorkerProtocolErrorV2::NonCanonical)?
        == minicbor::data::Type::Null
    {
        decoder
            .null()
            .map_err(|_| ConnectorWorkerProtocolErrorV2::NonCanonical)?;
        Ok(None)
    } else {
        Ok(Some(Digest32V2::new(decode_fixed::<32>(decoder)?)))
    }
}

#[cfg(test)]
mod tests {
    use savana_kernel_protocol::v2::{Digest32V2, UnixMillisV2};

    use super::{
        completion_after_provider, completion_for_retained, decode_child_job, encode_child_job,
        prepare_frame, ChildInputV2,
    };
    use crate::worker_protocol::test_support::fixture;
    use crate::worker_protocol::{
        decode_connector_worker_frame, encode_provider_response_frame, ConnectorCodecJobModeV2,
        ConnectorOutcomeKindV2, ConnectorWorkerFrameV2,
    };

    #[test]
    fn prepare_worker_never_receives_credentials_and_decodes_only_the_response() {
        let fixture = fixture(ConnectorCodecJobModeV2::PrepareAndDecode);
        let input = encode_child_job(
            &fixture.descriptor,
            1,
            &fixture.material,
            None,
            &fixture.ephemeral.to_bytes(),
            &fixture.parent_public_key,
        )
        .unwrap();
        let job = decode_child_job(&input, UnixMillisV2::new(10)).unwrap();
        let ChildInputV2::Prepare(material) = &job.input else {
            panic!("wrong mode");
        };
        let (prepared, transcript) = prepare_frame(&job, material).unwrap();
        assert!(matches!(
            decode_connector_worker_frame(&prepared, &job.verified).unwrap(),
            ConnectorWorkerFrameV2::Prepared(_)
        ));
        let response = b"provider response";
        let provider =
            encode_provider_response_frame(&job.verified, response, Digest32V2::new([15; 32]))
                .unwrap();
        let terminal = completion_after_provider(&job, &provider, transcript, response).unwrap();
        let ConnectorWorkerFrameV2::Outcome(outcome) =
            decode_connector_worker_frame(&terminal, &job.verified).unwrap()
        else {
            panic!("missing outcome");
        };
        assert_eq!(outcome.kind(), ConnectorOutcomeKindV2::Completion);
        assert_eq!(outcome.result(), Some(response.as_slice()));
    }

    #[test]
    fn retained_response_mode_is_bound_to_digest_length_and_effect_receipt() {
        let fixture = fixture(ConnectorCodecJobModeV2::DecodeRetainedResponse);
        let response = b"provider response";
        let input = encode_child_job(
            &fixture.descriptor,
            2,
            response,
            Some(Digest32V2::new([15; 32])),
            &fixture.ephemeral.to_bytes(),
            &fixture.parent_public_key,
        )
        .unwrap();
        let job = decode_child_job(&input, UnixMillisV2::new(10)).unwrap();
        let terminal = completion_for_retained(&job, response).unwrap();
        assert!(matches!(
            decode_connector_worker_frame(&terminal, &job.verified).unwrap(),
            ConnectorWorkerFrameV2::Outcome(_)
        ));

        let rebound = encode_child_job(
            &fixture.descriptor,
            2,
            b"different response",
            Some(Digest32V2::new([15; 32])),
            &fixture.ephemeral.to_bytes(),
            &fixture.parent_public_key,
        )
        .unwrap();
        assert!(decode_child_job(&rebound, UnixMillisV2::new(10)).is_err());
    }
}
