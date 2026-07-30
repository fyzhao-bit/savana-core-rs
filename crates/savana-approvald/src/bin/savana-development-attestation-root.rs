#![forbid(unsafe_code)]

use std::fs::OpenOptions;
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};

use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey};
use savana_approvald::HardwareAttestationRootV2;
use savana_kernel_protocol::v2::Digest32V2;
use sha2::{Digest as _, Sha256};

const OID_ECDSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
const OID_EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const OID_PRIME256V1: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const OID_BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];
const OID_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x0f];

fn main() {
    if let Err(error) = run(std::env::args_os()) {
        eprintln!("{error}");
        std::process::exit(70);
    }
}

fn run(mut arguments: impl Iterator<Item = std::ffi::OsString>) -> Result<(), &'static str> {
    let _program = arguments.next().ok_or("missing program name")?;
    let certificate_path = PathBuf::from(arguments.next().ok_or("missing certificate path")?);
    let aaguid = arguments.next().ok_or("missing AAGUID")?;
    if arguments.next().is_some() {
        return Err("unexpected argument");
    }
    if !certificate_path.is_absolute() {
        return Err("certificate path is not absolute");
    }
    let aaguid = aaguid
        .to_str()
        .ok_or("AAGUID is not UTF-8")
        .and_then(parse_aaguid)?;
    let (certificate, spki) = generate_root()?;
    let certificate_digest: [u8; 32] = Sha256::digest(&certificate).into();
    let spki_digest: [u8; 32] = Sha256::digest(&spki).into();
    HardwareAttestationRootV2::new(
        aaguid,
        Digest32V2::new(certificate_digest),
        Digest32V2::new(spki_digest),
        certificate.clone(),
    )
    .map_err(|_| "generated attestation root was not accepted")?;
    write_new_regular_file(&certificate_path, &certificate)?;
    println!("{} {}", hex(&certificate_digest), hex(&spki_digest));
    Ok(())
}

fn generate_root() -> Result<(Vec<u8>, Vec<u8>), &'static str> {
    let mut candidate = [0_u8; 32];
    let signing_key = loop {
        getrandom::getrandom(&mut candidate).map_err(|_| "cannot generate private key")?;
        if let Ok(key) = SigningKey::from_slice(&candidate) {
            break key;
        }
    };
    candidate.fill(0);

    let mut serial = [0_u8; 16];
    getrandom::getrandom(&mut serial).map_err(|_| "cannot generate certificate serial")?;
    serial[0] &= 0x7f;
    if serial.iter().all(|byte| *byte == 0) {
        serial[15] = 1;
    }

    let subject = name("Savana local development attestation root");
    let spki = spki(&signing_key);
    let extensions = extensions(&[
        extension(OID_BASIC_CONSTRAINTS, true, sequence(&boolean(true))),
        extension(OID_KEY_USAGE, true, bit_string(1, &[0x04])),
    ]);
    let tbs = tbs_certificate(&serial, &subject, &spki, &extensions);
    let signature: Signature = signing_key.sign(&tbs);
    let signature = signature.normalize_s().unwrap_or(signature);
    let mut certificate = Vec::new();
    certificate.extend_from_slice(&tbs);
    certificate.extend_from_slice(&algorithm());
    certificate.extend_from_slice(&bit_string(0, signature.to_der().as_bytes()));
    Ok((sequence(&certificate), spki))
}

fn write_new_regular_file(path: &Path, contents: &[u8]) -> Result<(), &'static str> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .open(path)
        .map_err(|_| "cannot create certificate")?;
    file.write_all(contents)
        .map_err(|_| "cannot write certificate")?;
    file.sync_all().map_err(|_| "cannot sync certificate")
}

fn parse_aaguid(value: &str) -> Result<[u8; 16], &'static str> {
    if value.len() != 32 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("AAGUID is invalid");
    }
    let mut decoded = [0_u8; 16];
    for (index, slot) in decoded.iter_mut().enumerate() {
        let offset = index * 2;
        *slot =
            u8::from_str_radix(&value[offset..offset + 2], 16).map_err(|_| "AAGUID is invalid")?;
    }
    if decoded == [0; 16] {
        return Err("AAGUID is invalid");
    }
    Ok(decoded)
}

fn tbs_certificate(serial: &[u8], subject: &[u8], spki: &[u8], extensions: &[u8]) -> Vec<u8> {
    let mut content = Vec::new();
    content.extend_from_slice(&der(0xa0, &integer(&[2])));
    content.extend_from_slice(&integer(serial));
    content.extend_from_slice(&algorithm());
    content.extend_from_slice(subject);
    let mut validity = Vec::new();
    validity.extend_from_slice(&der(0x17, b"240101000000Z"));
    validity.extend_from_slice(&der(0x17, b"491231235959Z"));
    content.extend_from_slice(&sequence(&validity));
    content.extend_from_slice(subject);
    content.extend_from_slice(spki);
    content.extend_from_slice(&der(0xa3, extensions));
    sequence(&content)
}

fn spki(key: &SigningKey) -> Vec<u8> {
    let mut parameters = Vec::new();
    parameters.extend_from_slice(&oid(OID_EC_PUBLIC_KEY));
    parameters.extend_from_slice(&oid(OID_PRIME256V1));
    let mut content = sequence(&parameters);
    content.extend_from_slice(&bit_string(
        0,
        key.verifying_key().to_encoded_point(false).as_bytes(),
    ));
    sequence(&content)
}

fn algorithm() -> Vec<u8> {
    sequence(&oid(OID_ECDSA_SHA256))
}

fn name(common_name: &str) -> Vec<u8> {
    let mut attribute = oid(&[0x55, 0x04, 0x03]);
    attribute.extend_from_slice(&der(0x0c, common_name.as_bytes()));
    sequence(&der(0x31, &sequence(&attribute)))
}

fn extensions(values: &[Vec<u8>]) -> Vec<u8> {
    sequence(&values.concat())
}

fn extension(oid_bytes: &[u8], critical: bool, value: Vec<u8>) -> Vec<u8> {
    let mut content = oid(oid_bytes);
    if critical {
        content.extend_from_slice(&boolean(true));
    }
    content.extend_from_slice(&octet_string(&value));
    sequence(&content)
}

fn sequence(content: &[u8]) -> Vec<u8> {
    der(0x30, content)
}

fn integer(content: &[u8]) -> Vec<u8> {
    der(0x02, content)
}

fn oid(content: &[u8]) -> Vec<u8> {
    der(0x06, content)
}

fn boolean(value: bool) -> Vec<u8> {
    der(0x01, &[if value { 0xff } else { 0 }])
}

fn octet_string(content: &[u8]) -> Vec<u8> {
    der(0x04, content)
}

fn bit_string(unused: u8, content: &[u8]) -> Vec<u8> {
    let mut value = vec![unused];
    value.extend_from_slice(content);
    der(0x03, &value)
}

fn der(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut output = vec![tag];
    if content.len() < 128 {
        output.push(content.len() as u8);
    } else {
        let length = (content.len() as u32).to_be_bytes();
        let first = length.iter().position(|byte| *byte != 0).unwrap_or(3);
        output.push(0x80 | (length.len() - first) as u8);
        output.extend_from_slice(&length[first..]);
    }
    output.extend_from_slice(content);
    output
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use savana_approvald::HardwareAttestationRootV2;
    use savana_kernel_protocol::v2::Digest32V2;
    use sha2::{Digest as _, Sha256};

    use super::{generate_root, parse_aaguid};

    #[test]
    fn generated_root_is_accepted_by_the_production_validator() {
        let (certificate, spki) = generate_root().unwrap();
        HardwareAttestationRootV2::new(
            [0x33; 16],
            Digest32V2::new(Sha256::digest(&certificate).into()),
            Digest32V2::new(Sha256::digest(&spki).into()),
            certificate,
        )
        .unwrap();
    }

    #[test]
    fn aaguid_parser_accepts_only_nonzero_canonical_width_hex() {
        assert_eq!(
            parse_aaguid("534156414e4144455631000000000001").unwrap(),
            *b"SAVANADEV1\0\0\0\0\0\x01"
        );
        assert!(parse_aaguid("00").is_err());
        assert!(parse_aaguid("00000000000000000000000000000000").is_err());
        assert!(parse_aaguid("gggggggggggggggggggggggggggggggg").is_err());
    }
}
