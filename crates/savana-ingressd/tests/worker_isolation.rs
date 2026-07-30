#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::process::{ChildStdin, ChildStdout, Command, Stdio};

use ed25519_dalek::SigningKey;
use savana_kernel_protocol::v2::{
    derive_ed25519_key_id_v2, encode_signed_parser_worker_job_descriptor_v2, ClosedMediaTypeV2,
    Digest32V2, FixedBytes32V2, ImplementationIdV2, Nonce32V2, ServiceIdentityV2,
    SignedParserWorkerJobDescriptorV2, UnixMillisV2, UnsignedParserWorkerJobDescriptorV2,
    VersionV2,
};
use sha2::{Digest as _, Sha256};

const OUTPUT_LIMITS_DOMAIN_V2: &[u8] = b"SAVANA_PARSER_OUTPUT_LIMITS_V2\0";

#[test]
fn installed_parser_worker_consumes_one_job_and_exits_after_one_terminal() {
    let original = b"measured parser input";
    let parent = SigningKey::from_bytes(&[0x21; 32]);
    let (mut child, mut input, mut output) = spawn_worker();
    let (ephemeral_public, ephemeral_key_id) = read_init(&mut output);
    let descriptor = descriptor(&parent, ephemeral_public, ephemeral_key_id, original);
    let job = child_job(&descriptor, original, &parent.verifying_key().to_bytes());
    write_frame(&mut input, &job);
    // The one-job worker must never process this queued second job.
    write_frame(&mut input, &job);
    drop(input);

    let page = read_frame(&mut output).unwrap();
    let terminal = read_frame(&mut output).unwrap();
    let mut eof = [0_u8; 1];
    assert_eq!(output.read(&mut eof).unwrap(), 0);
    assert!(child.wait().unwrap().success());
    assert_result_tag(&page, 1);
    assert_result_tag(&terminal, 2);
}

#[test]
fn installed_parser_worker_rejects_a_rebound_ephemeral_key() {
    let original = b"measured parser input";
    let parent = SigningKey::from_bytes(&[0x21; 32]);
    let rebound = SigningKey::from_bytes(&[0x44; 32]);
    let (mut child, mut input, mut output) = spawn_worker();
    let _ = read_init(&mut output);
    let rebound_public = rebound.verifying_key().to_bytes();
    let descriptor = descriptor(
        &parent,
        rebound_public,
        derive_ed25519_key_id_v2(rebound_public),
        original,
    );
    let job = child_job(&descriptor, original, &parent.verifying_key().to_bytes());
    write_frame(&mut input, &job);
    drop(input);

    let failure = read_frame(&mut output).unwrap();
    assert!(child.wait().unwrap().success());
    assert_result_tag(&failure, 3);
}

fn spawn_worker() -> (std::process::Child, ChildStdin, ChildStdout) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_savana-parser-worker"))
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let input = child.stdin.take().unwrap();
    let output = child.stdout.take().unwrap();
    (child, input, output)
}

fn read_init(input: &mut impl Read) -> ([u8; 32], savana_kernel_protocol::v2::Ed25519KeyIdV2) {
    let frame = read_frame(input).unwrap();
    let mut decoder = minicbor::Decoder::new(&frame);
    assert_eq!(decoder.array().unwrap(), Some(3));
    assert_eq!(decoder.u16().unwrap(), 0);
    let public: [u8; 32] = decoder.bytes().unwrap().try_into().unwrap();
    let key_id = savana_kernel_protocol::v2::Ed25519KeyIdV2::new(
        decoder.bytes().unwrap().try_into().unwrap(),
    );
    assert_eq!(decoder.position(), frame.len());
    assert_eq!(derive_ed25519_key_id_v2(public), key_id);
    (public, key_id)
}

fn descriptor(
    parent: &SigningKey,
    ephemeral_public: [u8; 32],
    ephemeral_key_id: savana_kernel_protocol::v2::Ed25519KeyIdV2,
    original: &[u8],
) -> Vec<u8> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let unsigned = UnsignedParserWorkerJobDescriptorV2::new(
        Digest32V2::new([1; 32]),
        Digest32V2::new([2; 32]),
        3,
        ServiceIdentityV2::new([4; 32]),
        Nonce32V2::new([5; 32]),
        Digest32V2::new([6; 32]),
        original.len() as u64,
        Digest32V2::new(Sha256::digest(original).into()),
        ClosedMediaTypeV2::new(1),
        ClosedMediaTypeV2::new(1),
        Digest32V2::new([7; 32]),
        ImplementationIdV2::new(1),
        Digest32V2::new([8; 32]),
        None,
        None,
        VersionV2::new(1, 0, 0),
        output_limits_digest(1024, 4),
        FixedBytes32V2::new(ephemeral_public),
        ephemeral_key_id,
        UnixMillisV2::new(now + 60_000),
    )
    .unwrap();
    let signed = SignedParserWorkerJobDescriptorV2::sign(unsigned, parent).unwrap();
    encode_signed_parser_worker_job_descriptor_v2(&signed).unwrap()
}

fn child_job(descriptor: &[u8], original: &[u8], parent_public_key: &[u8; 32]) -> Vec<u8> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(7)
        .unwrap()
        .u16(1)
        .unwrap()
        .bytes(descriptor)
        .unwrap()
        .bytes(original)
        .unwrap()
        .u32(1024)
        .unwrap()
        .u32(4)
        .unwrap()
        .bytes(output_limits_digest(1024, 4).as_bytes())
        .unwrap()
        .bytes(parent_public_key)
        .unwrap();
    encoder.into_writer()
}

fn output_limits_digest(output_limit_bytes: u32, maximum_pages: u32) -> Digest32V2 {
    let mut hasher = Sha256::new();
    hasher.update(OUTPUT_LIMITS_DOMAIN_V2);
    hasher.update(output_limit_bytes.to_be_bytes());
    hasher.update(maximum_pages.to_be_bytes());
    Digest32V2::new(hasher.finalize().into())
}

fn assert_result_tag(frame: &[u8], expected: u16) {
    let mut decoder = minicbor::Decoder::new(frame);
    assert_eq!(decoder.array().unwrap(), Some(2));
    assert_eq!(decoder.u16().unwrap(), expected);
    assert!(!decoder.bytes().unwrap().is_empty());
    assert_eq!(decoder.position(), frame.len());
}

fn write_frame(output: &mut impl Write, bytes: &[u8]) {
    output
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .unwrap();
    output.write_all(bytes).unwrap();
}

fn read_frame(input: &mut impl Read) -> Option<Vec<u8>> {
    let mut header = [0_u8; 4];
    if input.read_exact(&mut header).is_err() {
        return None;
    }
    let mut body = vec![0; u32::from_be_bytes(header) as usize];
    input.read_exact(&mut body).unwrap();
    Some(body)
}
