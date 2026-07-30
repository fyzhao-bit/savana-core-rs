#![forbid(unsafe_code)]

use std::io::{Read, Write};
use std::process::{Command, Stdio};

use ed25519_dalek::{Signer as _, SigningKey};
use savana_kernel_protocol::v2::derive_ed25519_key_id_v2;
use sha2::{Digest as _, Sha256};

const DESCRIPTOR_SIGNATURE_DOMAIN: &[u8] = b"SAVANA_CONNECTOR_CODEC_JOB_DESCRIPTOR_SIGNATURE_V2\0";
const MATERIAL_DOMAIN: &[u8] = b"SAVANA_CONNECTOR_CODEC_MATERIAL_V2\0";
const RESPONSE_DOMAIN: &[u8] = b"SAVANA_CONNECTOR_PROVIDER_RESPONSE_V2\0";

#[test]
fn installed_connector_worker_is_one_job_and_credential_free() {
    let material = b"credential-free request material";
    let parent = SigningKey::from_bytes(&[0x31; 32]);
    let ephemeral = SigningKey::from_bytes(&[0x32; 32]);
    let descriptor = descriptor(&parent, &ephemeral, material);
    let job = child_job(
        &descriptor,
        material,
        &ephemeral.to_bytes(),
        &parent.verifying_key().to_bytes(),
    );

    let mut child = Command::new(env!("CARGO_BIN_EXE_savana-connector-worker"))
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = child.stdout.take().unwrap();
    write_frame(&mut stdin, &job);
    stdin.flush().unwrap();

    let prepared = read_frame(&mut stdout).unwrap();
    let mut outer = minicbor::Decoder::new(&prepared);
    assert_eq!(outer.array().unwrap(), Some(4));
    assert_eq!(outer.u16().unwrap(), 1);
    let payload = outer.bytes().unwrap();
    let mut request = minicbor::Decoder::new(payload);
    assert_eq!(request.array().unwrap(), Some(9));
    assert_eq!(request.u16().unwrap(), 2);
    assert_eq!(request.bytes().unwrap(), &[12; 32]);
    assert_eq!(request.bytes().unwrap(), &[5; 32]);
    assert_eq!(request.u16().unwrap(), 1);
    assert_eq!(request.u16().unwrap(), 1);
    assert_eq!(request.bytes().unwrap(), material);

    let provider_response = b"provider response";
    let provider = provider_frame(provider_response);
    write_frame(&mut stdin, &provider);
    drop(stdin);

    let terminal = read_frame(&mut stdout).unwrap();
    let mut terminal_outer = minicbor::Decoder::new(&terminal);
    assert_eq!(terminal_outer.array().unwrap(), Some(4));
    assert_eq!(terminal_outer.u16().unwrap(), 3);
    let mut eof = [0_u8; 1];
    assert_eq!(stdout.read(&mut eof).unwrap(), 0);
    assert!(child.wait().unwrap().success());

    // The only bytes sent to the child are the signed descriptor, explicitly
    // credential-free material, the response, and one receipt digest. No
    // credential field exists in the child ABI.
    assert!(!job
        .windows(b"credential-secret".len())
        .any(|window| { window == b"credential-secret" }));
}

#[test]
fn installed_connector_worker_rejects_a_rebound_ephemeral_seed() {
    let material = b"credential-free request material";
    let parent = SigningKey::from_bytes(&[0x31; 32]);
    let ephemeral = SigningKey::from_bytes(&[0x32; 32]);
    let descriptor = descriptor(&parent, &ephemeral, material);
    let job = child_job(
        &descriptor,
        material,
        &[0x55; 32],
        &parent.verifying_key().to_bytes(),
    );
    let mut child = Command::new(env!("CARGO_BIN_EXE_savana-connector-worker"))
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    write_frame(&mut stdin, &job);
    drop(stdin);
    let mut stdout = child.stdout.take().unwrap();
    let mut byte = [0_u8; 1];
    assert_eq!(stdout.read(&mut byte).unwrap(), 0);
    assert!(!child.wait().unwrap().success());
}

fn descriptor(parent: &SigningKey, ephemeral: &SigningKey, material: &[u8]) -> Vec<u8> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let mut payload = minicbor::Encoder::new(Vec::new());
    payload
        .array(25)
        .unwrap()
        .u16(2)
        .unwrap()
        .bytes(&[1; 32])
        .unwrap()
        .bytes(&[2; 32])
        .unwrap()
        .u64(3)
        .unwrap()
        .u64(4)
        .unwrap()
        .bytes(&[5; 32])
        .unwrap()
        .bytes(&[6; 32])
        .unwrap()
        .bytes(&[7; 32])
        .unwrap()
        .bytes(&[8; 32])
        .unwrap()
        .bytes(&[9; 32])
        .unwrap()
        .bytes(&domain_hash(MATERIAL_DOMAIN, material))
        .unwrap()
        .bytes(&[10; 32])
        .unwrap()
        .bytes(&[11; 32])
        .unwrap()
        .u16(1)
        .unwrap()
        .u16(1)
        .unwrap()
        .u16(1)
        .unwrap()
        .bytes(&[12; 32])
        .unwrap()
        .bytes(&[13; 32])
        .unwrap()
        .bytes(&ephemeral.verifying_key().to_bytes())
        .unwrap()
        .bytes(derive_ed25519_key_id_v2(ephemeral.verifying_key().to_bytes()).as_bytes())
        .unwrap()
        .null()
        .unwrap()
        .null()
        .unwrap()
        .null()
        .unwrap()
        .null()
        .unwrap()
        .u64(now + 60_000)
        .unwrap();
    let payload = payload.into_writer();
    let digest: [u8; 32] = Sha256::digest(&payload).into();
    let mut signed = Vec::from(DESCRIPTOR_SIGNATURE_DOMAIN);
    signed.extend_from_slice(&digest);
    let signature = parent.sign(&signed).to_bytes();
    let mut outer = minicbor::Encoder::new(Vec::new());
    outer
        .array(3)
        .unwrap()
        .bytes(&payload)
        .unwrap()
        .bytes(derive_ed25519_key_id_v2(parent.verifying_key().to_bytes()).as_bytes())
        .unwrap()
        .bytes(&signature)
        .unwrap();
    outer.into_writer()
}

fn child_job(
    descriptor: &[u8],
    material: &[u8],
    ephemeral_seed: &[u8; 32],
    parent_public_key: &[u8; 32],
) -> Vec<u8> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(7)
        .unwrap()
        .u16(2)
        .unwrap()
        .bytes(descriptor)
        .unwrap()
        .u16(1)
        .unwrap()
        .bytes(material)
        .unwrap()
        .null()
        .unwrap()
        .bytes(ephemeral_seed)
        .unwrap()
        .bytes(parent_public_key)
        .unwrap();
    encoder.into_writer()
}

fn provider_frame(response: &[u8]) -> Vec<u8> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(5)
        .unwrap()
        .u16(2)
        .unwrap()
        .bytes(&[12; 32])
        .unwrap()
        .bytes(response)
        .unwrap()
        .bytes(&domain_hash(RESPONSE_DOMAIN, response))
        .unwrap()
        .bytes(&[15; 32])
        .unwrap();
    encoder.into_writer()
}

fn domain_hash(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(bytes);
    hasher.finalize().into()
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
