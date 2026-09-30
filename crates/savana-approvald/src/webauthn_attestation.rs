use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use p256::ecdsa::signature::Verifier as _;
use p256::ecdsa::{Signature, VerifyingKey};
use serde::de::{self, MapAccess, Visitor};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};

use savana_kernel_protocol::v2::{Digest32V2, Nonce32V2};

use crate::ApprovalErrorV2;

const RP_ID: &[u8] = b"localhost";
const ORIGIN: &str = "http://localhost:8766";
const TYPE: &str = "webauthn.create";
const FLAG_USER_PRESENT: u8 = 0x01;
const FLAG_USER_VERIFIED: u8 = 0x04;
const FLAG_BACKUP_ELIGIBLE: u8 = 0x08;
const FLAG_BACKUP_STATE: u8 = 0x10;
const FLAG_ATTESTED_CREDENTIAL_DATA: u8 = 0x40;
const FLAG_EXTENSION_DATA: u8 = 0x80;
const OID_ECDSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
const OID_EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const OID_PRIME256V1: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const OID_BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];
const OID_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x0f];
const OID_FIDO_AAGUID: &[u8] = &[
    0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xe5, 0x1c, 0x01, 0x01, 0x04,
];
const MAX_CERTIFICATES_V2: usize = 8;

#[derive(Debug, Clone)]
pub struct HardwareAttestationRootV2 {
    aaguid: [u8; 16],
    root_certificate_sha256: Digest32V2,
    root_spki_sha256: Digest32V2,
    root_certificate_der: Vec<u8>,
}

impl HardwareAttestationRootV2 {
    pub fn new(
        aaguid: [u8; 16],
        root_certificate_sha256: Digest32V2,
        root_spki_sha256: Digest32V2,
        root_certificate_der: Vec<u8>,
    ) -> Result<Self, ApprovalErrorV2> {
        if aaguid == [0; 16]
            || root_certificate_sha256.as_bytes() == &[0; 32]
            || root_spki_sha256.as_bytes() == &[0; 32]
            || root_certificate_der.is_empty()
            || root_certificate_der.len() > 64 * 1024
            || Sha256::digest(&root_certificate_der).as_slice()
                != root_certificate_sha256.as_bytes()
        {
            return Err(ApprovalErrorV2::InvalidCredential);
        }
        let parsed = parse_certificate(&root_certificate_der)?;
        if parsed.issuer != parsed.subject
            || !parsed.is_ca
            || !parsed.key_cert_sign
            || parsed.aaguid.is_some()
            || Sha256::digest(parsed.spki).as_slice() != root_spki_sha256.as_bytes()
        {
            return Err(ApprovalErrorV2::InvalidCredential);
        }
        verify_certificate_signature(&parsed, &parsed.public_key)?;
        Ok(Self {
            aaguid,
            root_certificate_sha256,
            root_spki_sha256,
            root_certificate_der,
        })
    }
}

#[derive(Debug, Clone, Copy)]
pub struct VerifiedEnrollmentAttestationV2 {
    pub aaguid: [u8; 16],
    pub p256_sec1_public_key: [u8; 65],
    pub signature_counter: u32,
}

/// Registration authorized by a one-use enrollment grant, with no hardware
/// provenance claim. Fields cannot be supplied by the browser/state-owner API.
#[derive(Debug, Clone, Copy)]
pub struct VerifiedPasskeyRegistrationV04 {
    pub(crate) aaguid: [u8; 16],
    pub(crate) public_key: [u8; 65],
    pub(crate) signature_counter: u32,
    pub(crate) backup_eligible: bool,
}

/// The passkey profile requests `attestation: none`. This validates the complete
/// registration transcript but deliberately does not claim hardware attestation.
pub fn verify_passkey_registration_v04(
    credential_id: &[u8],
    client_data_json: &[u8],
    attestation_object: &[u8],
    challenge: Nonce32V2,
) -> Result<VerifiedPasskeyRegistrationV04, ApprovalErrorV2> {
    if credential_id.is_empty()
        || credential_id.len() > 4096
        || client_data_json.is_empty()
        || client_data_json.len() > 64 * 1024
        || attestation_object.is_empty()
        || attestation_object.len() > 512 * 1024
        || challenge.as_bytes() == &[0; 32]
    {
        return Err(ApprovalErrorV2::InvalidCredential);
    }
    verify_client_data(client_data_json, challenge)?;
    let malformed = |_| ApprovalErrorV2::InvalidAuthenticatorData;
    let mut d = minicbor::Decoder::new(attestation_object);
    if d.map().map_err(malformed)? != Some(3) {
        return Err(ApprovalErrorV2::InvalidAuthenticatorData);
    }
    let mut fmt = None;
    let mut auth = None;
    let mut statement = false;
    for _ in 0..3 {
        match d.str().map_err(malformed)? {
            "fmt" if fmt.is_none() => fmt = Some(d.str().map_err(malformed)?),
            "authData" if auth.is_none() => auth = Some(d.bytes().map_err(malformed)?),
            "attStmt" if !statement => {
                if d.map().map_err(malformed)? != Some(0) {
                    return Err(ApprovalErrorV2::InvalidAuthenticatorData);
                }
                statement = true;
            }
            _ => return Err(ApprovalErrorV2::InvalidAuthenticatorData),
        }
    }
    if fmt != Some("none") || !statement || d.position() != attestation_object.len() {
        return Err(ApprovalErrorV2::InvalidAuthenticatorData);
    }
    let auth = auth.ok_or(ApprovalErrorV2::InvalidAuthenticatorData)?;
    let credential = parse_authenticator_data_for_assurance(auth, credential_id, true)?;
    Ok(VerifiedPasskeyRegistrationV04 {
        aaguid: credential.aaguid,
        public_key: credential.public_key,
        signature_counter: credential.signature_counter,
        backup_eligible: auth[32] & FLAG_BACKUP_ELIGIBLE != 0,
    })
}

pub fn verify_enrollment_attestation_v2(
    credential_id: &[u8],
    client_data_json: &[u8],
    attestation_object: &[u8],
    challenge: Nonce32V2,
    roots: &[HardwareAttestationRootV2],
    now: savana_kernel_protocol::v2::UnixMillisV2,
) -> Result<VerifiedEnrollmentAttestationV2, ApprovalErrorV2> {
    if credential_id.is_empty()
        || credential_id.len() > 4096
        || client_data_json.is_empty()
        || client_data_json.len() > 64 * 1024
        || attestation_object.is_empty()
        || attestation_object.len() > 512 * 1024
        || roots.is_empty()
    {
        return Err(ApprovalErrorV2::InvalidCredential);
    }
    verify_client_data(client_data_json, challenge)?;
    let object = parse_attestation_object(attestation_object)?;
    if object.format != "packed" || object.algorithm != -7 {
        return Err(ApprovalErrorV2::InvalidCredential);
    }
    let credential = parse_authenticator_data(object.authenticator_data, credential_id)?;
    let root = roots
        .iter()
        .find(|root| root.aaguid == credential.aaguid)
        .ok_or(ApprovalErrorV2::InvalidCredential)?;
    verify_attestation_chain(&object.certificates, root, credential.aaguid, now)?;

    let leaf = parse_certificate(
        object
            .certificates
            .first()
            .ok_or(ApprovalErrorV2::InvalidCredential)?,
    )?;
    let client_hash: [u8; 32] = Sha256::digest(client_data_json).into();
    let mut signed = Vec::new();
    signed
        .try_reserve_exact(object.authenticator_data.len() + client_hash.len())
        .map_err(|_| ApprovalErrorV2::AllocationFailure)?;
    signed.extend_from_slice(object.authenticator_data);
    signed.extend_from_slice(&client_hash);
    verify_low_s_signature(&leaf.public_key, &signed, object.signature)?;

    Ok(VerifiedEnrollmentAttestationV2 {
        aaguid: credential.aaguid,
        p256_sec1_public_key: credential.public_key,
        signature_counter: credential.signature_counter,
    })
}

struct AttestationObjectV2<'a> {
    format: &'a str,
    authenticator_data: &'a [u8],
    algorithm: i32,
    signature: &'a [u8],
    certificates: Vec<Vec<u8>>,
}

fn parse_attestation_object(bytes: &[u8]) -> Result<AttestationObjectV2<'_>, ApprovalErrorV2> {
    let mut decoder = minicbor::Decoder::new(bytes);
    let count = decoder
        .map()
        .map_err(|_| ApprovalErrorV2::InvalidAuthenticatorData)?
        .ok_or(ApprovalErrorV2::InvalidAuthenticatorData)?;
    if count != 3 {
        return Err(ApprovalErrorV2::InvalidAuthenticatorData);
    }
    let mut format = None;
    let mut auth_data = None;
    let mut algorithm = None;
    let mut signature = None;
    let mut certificates = None;
    for _ in 0..count {
        match decoder
            .str()
            .map_err(|_| ApprovalErrorV2::InvalidAuthenticatorData)?
        {
            "fmt" if format.is_none() => {
                format = Some(
                    decoder
                        .str()
                        .map_err(|_| ApprovalErrorV2::InvalidAuthenticatorData)?,
                );
            }
            "authData" if auth_data.is_none() => {
                auth_data = Some(
                    decoder
                        .bytes()
                        .map_err(|_| ApprovalErrorV2::InvalidAuthenticatorData)?,
                );
            }
            "attStmt" if algorithm.is_none() => {
                let entries = decoder
                    .map()
                    .map_err(|_| ApprovalErrorV2::InvalidAuthenticatorData)?
                    .ok_or(ApprovalErrorV2::InvalidAuthenticatorData)?;
                if entries != 3 {
                    return Err(ApprovalErrorV2::InvalidAuthenticatorData);
                }
                for _ in 0..entries {
                    match decoder
                        .str()
                        .map_err(|_| ApprovalErrorV2::InvalidAuthenticatorData)?
                    {
                        "alg" if algorithm.is_none() => {
                            algorithm = Some(
                                decoder
                                    .i32()
                                    .map_err(|_| ApprovalErrorV2::InvalidAuthenticatorData)?,
                            );
                        }
                        "sig" if signature.is_none() => {
                            signature = Some(
                                decoder
                                    .bytes()
                                    .map_err(|_| ApprovalErrorV2::InvalidAuthenticatorData)?,
                            );
                        }
                        "x5c" if certificates.is_none() => {
                            let length = decoder
                                .array()
                                .map_err(|_| ApprovalErrorV2::InvalidAuthenticatorData)?
                                .ok_or(ApprovalErrorV2::InvalidAuthenticatorData)?;
                            let length = usize::try_from(length)
                                .map_err(|_| ApprovalErrorV2::InvalidAuthenticatorData)?;
                            if length == 0 || length > MAX_CERTIFICATES_V2 {
                                return Err(ApprovalErrorV2::InvalidAuthenticatorData);
                            }
                            let mut values = Vec::new();
                            values
                                .try_reserve_exact(length)
                                .map_err(|_| ApprovalErrorV2::AllocationFailure)?;
                            for _ in 0..length {
                                let certificate = decoder
                                    .bytes()
                                    .map_err(|_| ApprovalErrorV2::InvalidAuthenticatorData)?;
                                if certificate.is_empty() || certificate.len() > 64 * 1024 {
                                    return Err(ApprovalErrorV2::InvalidAuthenticatorData);
                                }
                                values.push(certificate.to_vec());
                            }
                            certificates = Some(values);
                        }
                        _ => return Err(ApprovalErrorV2::InvalidAuthenticatorData),
                    }
                }
            }
            _ => return Err(ApprovalErrorV2::InvalidAuthenticatorData),
        }
    }
    if decoder.position() != bytes.len() {
        return Err(ApprovalErrorV2::InvalidAuthenticatorData);
    }
    Ok(AttestationObjectV2 {
        format: format.ok_or(ApprovalErrorV2::InvalidAuthenticatorData)?,
        authenticator_data: auth_data.ok_or(ApprovalErrorV2::InvalidAuthenticatorData)?,
        algorithm: algorithm.ok_or(ApprovalErrorV2::InvalidAuthenticatorData)?,
        signature: signature.ok_or(ApprovalErrorV2::InvalidAuthenticatorData)?,
        certificates: certificates.ok_or(ApprovalErrorV2::InvalidAuthenticatorData)?,
    })
}

struct ParsedAuthenticatorDataV2 {
    aaguid: [u8; 16],
    public_key: [u8; 65],
    signature_counter: u32,
}

fn parse_authenticator_data(
    bytes: &[u8],
    expected_credential_id: &[u8],
) -> Result<ParsedAuthenticatorDataV2, ApprovalErrorV2> {
    parse_authenticator_data_for_assurance(bytes, expected_credential_id, false)
}

fn parse_authenticator_data_for_assurance(
    bytes: &[u8],
    expected_credential_id: &[u8],
    passkey: bool,
) -> Result<ParsedAuthenticatorDataV2, ApprovalErrorV2> {
    if bytes.len() < 55 || &bytes[..32] != Sha256::digest(RP_ID).as_slice() {
        return Err(ApprovalErrorV2::InvalidAuthenticatorData);
    }
    let flags = bytes[32];
    if flags & FLAG_USER_PRESENT == 0
        || flags & FLAG_USER_VERIFIED == 0
        || flags & FLAG_ATTESTED_CREDENTIAL_DATA == 0
        || flags & FLAG_EXTENSION_DATA != 0
        || (!passkey && flags & (FLAG_BACKUP_ELIGIBLE | FLAG_BACKUP_STATE) != 0)
        || (flags & FLAG_BACKUP_STATE != 0 && flags & FLAG_BACKUP_ELIGIBLE == 0)
        || flags & 0x22 != 0
    {
        return Err(ApprovalErrorV2::InvalidAuthenticatorData);
    }
    let signature_counter = u32::from_be_bytes(
        bytes[33..37]
            .try_into()
            .map_err(|_| ApprovalErrorV2::InvalidAuthenticatorData)?,
    );
    if !passkey && signature_counter == 0 {
        return Err(ApprovalErrorV2::CounterReplay);
    }
    let aaguid: [u8; 16] = bytes[37..53]
        .try_into()
        .map_err(|_| ApprovalErrorV2::InvalidAuthenticatorData)?;
    if !passkey && aaguid == [0; 16] {
        return Err(ApprovalErrorV2::InvalidAuthenticatorData);
    }
    let credential_length = usize::from(u16::from_be_bytes(
        bytes[53..55]
            .try_into()
            .map_err(|_| ApprovalErrorV2::InvalidAuthenticatorData)?,
    ));
    let credential_end = 55usize
        .checked_add(credential_length)
        .ok_or(ApprovalErrorV2::InvalidAuthenticatorData)?;
    if credential_length == 0
        || credential_end >= bytes.len()
        || &bytes[55..credential_end] != expected_credential_id
    {
        return Err(ApprovalErrorV2::InvalidAuthenticatorData);
    }
    let (public_key, consumed) = parse_cose_p256_key(&bytes[credential_end..])?;
    if credential_end + consumed != bytes.len() {
        return Err(ApprovalErrorV2::InvalidAuthenticatorData);
    }
    Ok(ParsedAuthenticatorDataV2 {
        aaguid,
        public_key,
        signature_counter,
    })
}

fn parse_cose_p256_key(bytes: &[u8]) -> Result<([u8; 65], usize), ApprovalErrorV2> {
    let mut decoder = minicbor::Decoder::new(bytes);
    let entries = decoder
        .map()
        .map_err(|_| ApprovalErrorV2::InvalidAuthenticatorData)?
        .ok_or(ApprovalErrorV2::InvalidAuthenticatorData)?;
    if entries != 5 {
        return Err(ApprovalErrorV2::InvalidAuthenticatorData);
    }
    let mut kty = None;
    let mut alg = None;
    let mut curve = None;
    let mut x = None;
    let mut y = None;
    for _ in 0..entries {
        match decoder
            .i32()
            .map_err(|_| ApprovalErrorV2::InvalidAuthenticatorData)?
        {
            1 if kty.is_none() => {
                kty = Some(
                    decoder
                        .i32()
                        .map_err(|_| ApprovalErrorV2::InvalidAuthenticatorData)?,
                )
            }
            3 if alg.is_none() => {
                alg = Some(
                    decoder
                        .i32()
                        .map_err(|_| ApprovalErrorV2::InvalidAuthenticatorData)?,
                )
            }
            -1 if curve.is_none() => {
                curve = Some(
                    decoder
                        .i32()
                        .map_err(|_| ApprovalErrorV2::InvalidAuthenticatorData)?,
                )
            }
            -2 if x.is_none() => {
                x = Some(
                    <[u8; 32]>::try_from(
                        decoder
                            .bytes()
                            .map_err(|_| ApprovalErrorV2::InvalidAuthenticatorData)?,
                    )
                    .map_err(|_| ApprovalErrorV2::InvalidAuthenticatorData)?,
                )
            }
            -3 if y.is_none() => {
                y = Some(
                    <[u8; 32]>::try_from(
                        decoder
                            .bytes()
                            .map_err(|_| ApprovalErrorV2::InvalidAuthenticatorData)?,
                    )
                    .map_err(|_| ApprovalErrorV2::InvalidAuthenticatorData)?,
                )
            }
            _ => return Err(ApprovalErrorV2::InvalidAuthenticatorData),
        }
    }
    if kty != Some(2) || alg != Some(-7) || curve != Some(1) {
        return Err(ApprovalErrorV2::InvalidAuthenticatorData);
    }
    let mut key = [0_u8; 65];
    key[0] = 4;
    key[1..33].copy_from_slice(&x.ok_or(ApprovalErrorV2::InvalidAuthenticatorData)?);
    key[33..].copy_from_slice(&y.ok_or(ApprovalErrorV2::InvalidAuthenticatorData)?);
    VerifyingKey::from_sec1_bytes(&key).map_err(|_| ApprovalErrorV2::InvalidCredential)?;
    Ok((key, decoder.position()))
}

#[derive(Deserialize)]
#[serde(field_identifier, rename_all = "camelCase")]
enum ClientDataFieldV2 {
    #[serde(rename = "type")]
    Type,
    Challenge,
    Origin,
    CrossOrigin,
    TopOrigin,
    #[serde(other)]
    Other,
}

struct ClientDataV2 {
    ceremony_type: String,
    challenge: String,
    origin: String,
    cross_origin: bool,
    top_origin_seen: bool,
}

impl<'de> Deserialize<'de> for ClientDataV2 {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ClientVisitor;
        impl<'de> Visitor<'de> for ClientVisitor {
            type Value = ClientDataV2;

            fn expecting(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                formatter.write_str("WebAuthn CollectedClientData object")
            }

            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
                let mut ceremony_type = None;
                let mut challenge = None;
                let mut origin = None;
                let mut cross_origin = None;
                let mut top_origin_seen = false;
                while let Some(field) = map.next_key::<ClientDataFieldV2>()? {
                    match field {
                        ClientDataFieldV2::Type => {
                            if ceremony_type.is_some() {
                                return Err(de::Error::duplicate_field("type"));
                            }
                            ceremony_type = Some(map.next_value()?);
                        }
                        ClientDataFieldV2::Challenge => {
                            if challenge.is_some() {
                                return Err(de::Error::duplicate_field("challenge"));
                            }
                            challenge = Some(map.next_value()?);
                        }
                        ClientDataFieldV2::Origin => {
                            if origin.is_some() {
                                return Err(de::Error::duplicate_field("origin"));
                            }
                            origin = Some(map.next_value()?);
                        }
                        ClientDataFieldV2::CrossOrigin => {
                            if cross_origin.is_some() {
                                return Err(de::Error::duplicate_field("crossOrigin"));
                            }
                            cross_origin = Some(map.next_value()?);
                        }
                        ClientDataFieldV2::TopOrigin => {
                            if top_origin_seen {
                                return Err(de::Error::duplicate_field("topOrigin"));
                            }
                            top_origin_seen = true;
                            let _: serde_json::Value = map.next_value()?;
                        }
                        ClientDataFieldV2::Other => {
                            let _: serde_json::Value = map.next_value()?;
                        }
                    }
                }
                Ok(ClientDataV2 {
                    ceremony_type: ceremony_type.ok_or_else(|| de::Error::missing_field("type"))?,
                    challenge: challenge.ok_or_else(|| de::Error::missing_field("challenge"))?,
                    origin: origin.ok_or_else(|| de::Error::missing_field("origin"))?,
                    cross_origin: cross_origin.unwrap_or(false),
                    top_origin_seen,
                })
            }
        }
        deserializer.deserialize_map(ClientVisitor)
    }
}

fn verify_client_data(bytes: &[u8], challenge: Nonce32V2) -> Result<(), ApprovalErrorV2> {
    let client: ClientDataV2 =
        serde_json::from_slice(bytes).map_err(|_| ApprovalErrorV2::InvalidClientData)?;
    if client.ceremony_type != TYPE
        || client.challenge != URL_SAFE_NO_PAD.encode(challenge.as_bytes())
        || client.origin != ORIGIN
        || client.cross_origin
        || client.top_origin_seen
    {
        return Err(ApprovalErrorV2::InvalidClientData);
    }
    Ok(())
}

struct ParsedCertificateV2<'a> {
    tbs: &'a [u8],
    issuer: &'a [u8],
    subject: &'a [u8],
    spki: &'a [u8],
    public_key: VerifyingKey,
    signature: &'a [u8],
    not_before_seconds: i64,
    not_after_seconds: i64,
    is_ca: bool,
    digital_signature: bool,
    key_cert_sign: bool,
    aaguid: Option<[u8; 16]>,
}

#[derive(Clone, Copy)]
struct DerValueV2<'a> {
    tag: u8,
    full: &'a [u8],
    content: &'a [u8],
}

fn parse_certificate(bytes: &[u8]) -> Result<ParsedCertificateV2<'_>, ApprovalErrorV2> {
    let (certificate, consumed) = der_value(bytes)?;
    if certificate.tag != 0x30 || consumed != bytes.len() {
        return Err(ApprovalErrorV2::InvalidCredential);
    }
    let outer = der_children(certificate.content, 3, 3)?;
    if outer[0].tag != 0x30 || outer[1].tag != 0x30 || outer[2].tag != 0x03 {
        return Err(ApprovalErrorV2::InvalidCredential);
    }
    require_ecdsa_sha256_algorithm(outer[1])?;
    let tbs_children = der_children(outer[0].content, 6, 32)?;
    let version_offset = usize::from(tbs_children[0].tag == 0xa0);
    if tbs_children.len() < version_offset + 6
        || tbs_children[version_offset].tag != 0x02
        || tbs_children[version_offset + 1].tag != 0x30
        || tbs_children[version_offset + 2].tag != 0x30
        || tbs_children[version_offset + 3].tag != 0x30
        || tbs_children[version_offset + 4].tag != 0x30
        || tbs_children[version_offset + 5].tag != 0x30
    {
        return Err(ApprovalErrorV2::InvalidCredential);
    }
    if version_offset == 1 {
        let version = der_children(tbs_children[0].content, 1, 1)?;
        if version[0].tag != 0x02 || version[0].content != [2] {
            return Err(ApprovalErrorV2::InvalidCredential);
        }
    }
    require_ecdsa_sha256_algorithm(tbs_children[version_offset + 1])?;
    let (not_before_seconds, not_after_seconds) = parse_validity(tbs_children[version_offset + 3])?;
    let public_key = parse_spki(tbs_children[version_offset + 5])?;
    let mut is_ca = false;
    let mut basic_constraints_seen = false;
    let mut digital_signature = false;
    let mut key_cert_sign = false;
    let mut key_usage_seen = false;
    let mut aaguid = None;
    for optional in &tbs_children[version_offset + 6..] {
        match optional.tag {
            0x81 | 0x82 => {}
            0xa3 => {
                let parsed = parse_extensions(*optional)?;
                is_ca = parsed.is_ca;
                basic_constraints_seen = parsed.basic_constraints_seen;
                digital_signature = parsed.digital_signature;
                key_cert_sign = parsed.key_cert_sign;
                key_usage_seen = parsed.key_usage_seen;
                aaguid = parsed.aaguid;
            }
            _ => return Err(ApprovalErrorV2::InvalidCredential),
        }
    }
    if version_offset != 1 || !basic_constraints_seen || !key_usage_seen {
        return Err(ApprovalErrorV2::InvalidCredential);
    }
    if outer[2].content.first() != Some(&0) || outer[2].content.len() < 2 {
        return Err(ApprovalErrorV2::InvalidCredential);
    }
    Ok(ParsedCertificateV2 {
        tbs: outer[0].full,
        issuer: tbs_children[version_offset + 2].full,
        subject: tbs_children[version_offset + 4].full,
        spki: tbs_children[version_offset + 5].full,
        public_key,
        signature: &outer[2].content[1..],
        not_before_seconds,
        not_after_seconds,
        is_ca,
        digital_signature,
        key_cert_sign,
        aaguid,
    })
}

#[derive(Default)]
struct ParsedExtensionsV2 {
    is_ca: bool,
    basic_constraints_seen: bool,
    digital_signature: bool,
    key_cert_sign: bool,
    key_usage_seen: bool,
    aaguid: Option<[u8; 16]>,
}

fn parse_extensions(value: DerValueV2<'_>) -> Result<ParsedExtensionsV2, ApprovalErrorV2> {
    let wrapper = der_children(value.content, 1, 1)?;
    if wrapper[0].tag != 0x30 {
        return Err(ApprovalErrorV2::InvalidCredential);
    }
    let extensions = der_children(wrapper[0].content, 1, 64)?;
    let mut parsed = ParsedExtensionsV2::default();
    for extension in extensions {
        if extension.tag != 0x30 {
            return Err(ApprovalErrorV2::InvalidCredential);
        }
        let fields = der_children(extension.content, 2, 3)?;
        if fields[0].tag != 0x06 {
            return Err(ApprovalErrorV2::InvalidCredential);
        }
        let value_index = if fields.len() == 3 {
            if fields[1].tag != 0x01
                || fields[1].content.len() != 1
                || !matches!(fields[1].content[0], 0x00 | 0xff)
            {
                return Err(ApprovalErrorV2::InvalidCredential);
            }
            2
        } else {
            1
        };
        if fields[value_index].tag != 0x04 {
            return Err(ApprovalErrorV2::InvalidCredential);
        }
        match fields[0].content {
            OID_BASIC_CONSTRAINTS => {
                if parsed.basic_constraints_seen {
                    return Err(ApprovalErrorV2::InvalidCredential);
                }
                parsed.basic_constraints_seen = true;
                let (constraints, consumed) = der_value(fields[value_index].content)?;
                if constraints.tag != 0x30 || consumed != fields[value_index].content.len() {
                    return Err(ApprovalErrorV2::InvalidCredential);
                }
                let values = der_children(constraints.content, 0, 2)?;
                if let Some(ca) = values.first() {
                    if ca.tag != 0x01
                        || ca.content.len() != 1
                        || !matches!(ca.content[0], 0x00 | 0xff)
                    {
                        return Err(ApprovalErrorV2::InvalidCredential);
                    }
                    parsed.is_ca = ca.content[0] == 0xff;
                }
                if values.len() == 2 && values[1].tag != 0x02 {
                    return Err(ApprovalErrorV2::InvalidCredential);
                }
            }
            OID_KEY_USAGE => {
                if parsed.key_usage_seen {
                    return Err(ApprovalErrorV2::InvalidCredential);
                }
                parsed.key_usage_seen = true;
                let (usage, consumed) = der_value(fields[value_index].content)?;
                if usage.tag != 0x03
                    || consumed != fields[value_index].content.len()
                    || usage.content.len() < 2
                    || usage.content[0] > 7
                {
                    return Err(ApprovalErrorV2::InvalidCredential);
                }
                parsed.digital_signature = usage.content[1] & 0x80 != 0;
                parsed.key_cert_sign = usage.content[1] & 0x04 != 0;
            }
            OID_FIDO_AAGUID => {
                if parsed.aaguid.is_some() {
                    return Err(ApprovalErrorV2::InvalidCredential);
                }
                let (inner, consumed) = der_value(fields[value_index].content)?;
                if inner.tag != 0x04
                    || consumed != fields[value_index].content.len()
                    || inner.content.len() != 16
                {
                    return Err(ApprovalErrorV2::InvalidCredential);
                }
                parsed.aaguid = Some(
                    inner
                        .content
                        .try_into()
                        .map_err(|_| ApprovalErrorV2::InvalidCredential)?,
                );
            }
            _ => {}
        }
    }
    Ok(parsed)
}

fn parse_validity(value: DerValueV2<'_>) -> Result<(i64, i64), ApprovalErrorV2> {
    let values = der_children(value.content, 2, 2)?;
    let not_before = parse_der_time(values[0])?;
    let not_after = parse_der_time(values[1])?;
    if not_before >= not_after {
        return Err(ApprovalErrorV2::InvalidCredential);
    }
    Ok((not_before, not_after))
}

fn parse_der_time(value: DerValueV2<'_>) -> Result<i64, ApprovalErrorV2> {
    let bytes = value.content;
    let (year, offset) = match (value.tag, bytes.len()) {
        (0x17, 13) => {
            let short = parse_decimal(&bytes[..2])?;
            ((if short >= 50 { 1900 } else { 2000 }) + short, 2)
        }
        (0x18, 15) => (parse_decimal(&bytes[..4])?, 4),
        _ => return Err(ApprovalErrorV2::InvalidCredential),
    };
    if bytes.last() != Some(&b'Z') {
        return Err(ApprovalErrorV2::InvalidCredential);
    }
    let month = parse_decimal(&bytes[offset..offset + 2])?;
    let day = parse_decimal(&bytes[offset + 2..offset + 4])?;
    let hour = parse_decimal(&bytes[offset + 4..offset + 6])?;
    let minute = parse_decimal(&bytes[offset + 6..offset + 8])?;
    let second = parse_decimal(&bytes[offset + 8..offset + 10])?;
    if !(1970..=9999).contains(&year)
        || !(1..=12).contains(&month)
        || day == 0
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return Err(ApprovalErrorV2::InvalidCredential);
    }
    let days = days_from_civil(year, month, day);
    days.checked_mul(86_400)
        .and_then(|value| value.checked_add(i64::from(hour * 3600 + minute * 60 + second)))
        .ok_or(ApprovalErrorV2::InvalidCredential)
}

fn parse_decimal(bytes: &[u8]) -> Result<i32, ApprovalErrorV2> {
    if bytes.is_empty() || bytes.iter().any(|byte| !byte.is_ascii_digit()) {
        return Err(ApprovalErrorV2::InvalidCredential);
    }
    bytes.iter().try_fold(0_i32, |value, byte| {
        value
            .checked_mul(10)
            .and_then(|value| value.checked_add(i32::from(*byte - b'0')))
            .ok_or(ApprovalErrorV2::InvalidCredential)
    })
}

fn days_in_month(year: i32, month: i32) -> i32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        _ => 0,
    }
}

fn days_from_civil(year: i32, month: i32, day: i32) -> i64 {
    let adjusted_year = year - i32::from(month <= 2);
    let era = adjusted_year.div_euclid(400);
    let year_of_era = adjusted_year - era * 400;
    let shifted_month = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * shifted_month + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    i64::from(era * 146_097 + day_of_era - 719_468)
}

fn require_ecdsa_sha256_algorithm(value: DerValueV2<'_>) -> Result<(), ApprovalErrorV2> {
    let values = der_children(value.content, 1, 1)?;
    if values[0].tag != 0x06 || values[0].content != OID_ECDSA_SHA256 {
        return Err(ApprovalErrorV2::InvalidCredential);
    }
    Ok(())
}

fn parse_spki(value: DerValueV2<'_>) -> Result<VerifyingKey, ApprovalErrorV2> {
    let values = der_children(value.content, 2, 2)?;
    if values[0].tag != 0x30 || values[1].tag != 0x03 {
        return Err(ApprovalErrorV2::InvalidCredential);
    }
    let algorithm = der_children(values[0].content, 2, 2)?;
    if algorithm[0].tag != 0x06
        || algorithm[0].content != OID_EC_PUBLIC_KEY
        || algorithm[1].tag != 0x06
        || algorithm[1].content != OID_PRIME256V1
        || values[1].content.first() != Some(&0)
        || values[1].content.len() != 66
    {
        return Err(ApprovalErrorV2::InvalidCredential);
    }
    VerifyingKey::from_sec1_bytes(&values[1].content[1..])
        .map_err(|_| ApprovalErrorV2::InvalidCredential)
}

fn verify_attestation_chain(
    certificates: &[Vec<u8>],
    root: &HardwareAttestationRootV2,
    expected_aaguid: [u8; 16],
    now: savana_kernel_protocol::v2::UnixMillisV2,
) -> Result<(), ApprovalErrorV2> {
    let last = certificates
        .last()
        .ok_or(ApprovalErrorV2::InvalidCredential)?;
    if Sha256::digest(last).as_slice() != root.root_certificate_sha256.as_bytes()
        || last != &root.root_certificate_der
    {
        return Err(ApprovalErrorV2::InvalidCredential);
    }
    let parsed = certificates
        .iter()
        .map(|certificate| parse_certificate(certificate))
        .collect::<Result<Vec<_>, _>>()?;
    if Sha256::digest(parsed.last().unwrap().spki).as_slice() != root.root_spki_sha256.as_bytes() {
        return Err(ApprovalErrorV2::InvalidCredential);
    }
    let now_seconds =
        i64::try_from(now.get() / 1000).map_err(|_| ApprovalErrorV2::InvalidCredential)?;
    for (index, certificate) in parsed.iter().enumerate() {
        if now_seconds < certificate.not_before_seconds
            || now_seconds > certificate.not_after_seconds
        {
            return Err(ApprovalErrorV2::InvalidCredential);
        }
        if index == 0 {
            if certificate.is_ca
                || !certificate.digital_signature
                || certificate.key_cert_sign
                || certificate.aaguid != Some(expected_aaguid)
            {
                return Err(ApprovalErrorV2::InvalidCredential);
            }
        } else if !certificate.is_ca || !certificate.key_cert_sign || certificate.aaguid.is_some() {
            return Err(ApprovalErrorV2::InvalidCredential);
        }
    }
    for pair in parsed.windows(2) {
        if pair[0].issuer != pair[1].subject {
            return Err(ApprovalErrorV2::InvalidCredential);
        }
        verify_certificate_signature(&pair[0], &pair[1].public_key)?;
    }
    let root_certificate = parsed.last().unwrap();
    if root_certificate.issuer != root_certificate.subject {
        return Err(ApprovalErrorV2::InvalidCredential);
    }
    verify_certificate_signature(root_certificate, &root_certificate.public_key)
}

fn verify_certificate_signature(
    certificate: &ParsedCertificateV2<'_>,
    issuer_key: &VerifyingKey,
) -> Result<(), ApprovalErrorV2> {
    verify_low_s_signature(issuer_key, certificate.tbs, certificate.signature)
}

fn verify_low_s_signature(
    key: &VerifyingKey,
    message: &[u8],
    der_signature: &[u8],
) -> Result<(), ApprovalErrorV2> {
    let signature =
        Signature::from_der(der_signature).map_err(|_| ApprovalErrorV2::InvalidSignature)?;
    if signature.normalize_s().is_some() {
        return Err(ApprovalErrorV2::InvalidSignature);
    }
    key.verify(message, &signature)
        .map_err(|_| ApprovalErrorV2::InvalidSignature)
}

fn der_children(
    mut bytes: &[u8],
    minimum: usize,
    maximum: usize,
) -> Result<Vec<DerValueV2<'_>>, ApprovalErrorV2> {
    let mut values = Vec::new();
    while !bytes.is_empty() {
        if values.len() >= maximum {
            return Err(ApprovalErrorV2::InvalidCredential);
        }
        let (value, consumed) = der_value(bytes)?;
        values.push(value);
        bytes = &bytes[consumed..];
    }
    if values.len() < minimum {
        return Err(ApprovalErrorV2::InvalidCredential);
    }
    Ok(values)
}

fn der_value(bytes: &[u8]) -> Result<(DerValueV2<'_>, usize), ApprovalErrorV2> {
    if bytes.len() < 2 {
        return Err(ApprovalErrorV2::InvalidCredential);
    }
    let tag = bytes[0];
    let first = bytes[1];
    let (length, header) = if first & 0x80 == 0 {
        (usize::from(first), 2usize)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > core::mem::size_of::<usize>() || bytes.len() < 2 + count {
            return Err(ApprovalErrorV2::InvalidCredential);
        }
        if bytes[2] == 0 {
            return Err(ApprovalErrorV2::InvalidCredential);
        }
        let mut length = 0usize;
        for byte in &bytes[2..2 + count] {
            length = length
                .checked_mul(256)
                .and_then(|value| value.checked_add(usize::from(*byte)))
                .ok_or(ApprovalErrorV2::InvalidCredential)?;
        }
        if length < 128 {
            return Err(ApprovalErrorV2::InvalidCredential);
        }
        (length, 2 + count)
    };
    let end = header
        .checked_add(length)
        .filter(|end| *end <= bytes.len())
        .ok_or(ApprovalErrorV2::InvalidCredential)?;
    Ok((
        DerValueV2 {
            tag,
            full: &bytes[..end],
            content: &bytes[header..end],
        },
        end,
    ))
}

#[cfg(test)]
mod tests {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use p256::ecdsa::signature::Signer as _;
    use p256::ecdsa::{Signature, SigningKey};
    use sha2::{Digest as _, Sha256};

    use savana_kernel_protocol::v2::{Digest32V2, Nonce32V2, UnixMillisV2};

    use super::{
        verify_enrollment_attestation_v2, HardwareAttestationRootV2, FLAG_ATTESTED_CREDENTIAL_DATA,
        FLAG_BACKUP_ELIGIBLE, FLAG_USER_PRESENT, FLAG_USER_VERIFIED, OID_BASIC_CONSTRAINTS,
        OID_ECDSA_SHA256, OID_EC_PUBLIC_KEY, OID_FIDO_AAGUID, OID_KEY_USAGE, OID_PRIME256V1, RP_ID,
    };

    struct AttestationFixtureV2 {
        credential_id: Vec<u8>,
        client_data: Vec<u8>,
        auth_data: Vec<u8>,
        leaf_key: SigningKey,
        leaf_certificate: Vec<u8>,
        root_certificate: Vec<u8>,
        root_spki_digest: Digest32V2,
        aaguid: [u8; 16],
        challenge: Nonce32V2,
    }

    impl AttestationFixtureV2 {
        fn object(&self, flags: u8) -> Vec<u8> {
            let mut auth_data = self.auth_data.clone();
            auth_data[32] = flags;
            let mut signed = auth_data.clone();
            signed.extend_from_slice(&Sha256::digest(&self.client_data));
            let signature: Signature = self.leaf_key.sign(&signed);
            let signature = signature.normalize_s().unwrap_or(signature);
            let mut encoder = minicbor::Encoder::new(Vec::new());
            encoder
                .map(3)
                .unwrap()
                .str("fmt")
                .unwrap()
                .str("packed")
                .unwrap()
                .str("authData")
                .unwrap()
                .bytes(&auth_data)
                .unwrap()
                .str("attStmt")
                .unwrap()
                .map(3)
                .unwrap()
                .str("alg")
                .unwrap()
                .i32(-7)
                .unwrap()
                .str("sig")
                .unwrap()
                .bytes(signature.to_der().as_bytes())
                .unwrap()
                .str("x5c")
                .unwrap()
                .array(2)
                .unwrap()
                .bytes(&self.leaf_certificate)
                .unwrap()
                .bytes(&self.root_certificate)
                .unwrap();
            encoder.into_writer()
        }

        fn root(&self, aaguid: [u8; 16]) -> HardwareAttestationRootV2 {
            HardwareAttestationRootV2::new(
                aaguid,
                Digest32V2::new(Sha256::digest(&self.root_certificate).into()),
                self.root_spki_digest,
                self.root_certificate.clone(),
            )
            .unwrap()
        }
    }

    #[test]
    fn packed_attestation_requires_valid_chain_aaguid_lifetime_and_non_backup_key() {
        let fixture = fixture();
        let root = fixture.root(fixture.aaguid);
        let flags = FLAG_USER_PRESENT | FLAG_USER_VERIFIED | FLAG_ATTESTED_CREDENTIAL_DATA;
        let object = fixture.object(flags);
        let verified = verify_enrollment_attestation_v2(
            &fixture.credential_id,
            &fixture.client_data,
            &object,
            fixture.challenge,
            &[root.clone()],
            UnixMillisV2::new(1_800_000_000_000),
        )
        .unwrap();
        assert_eq!(verified.aaguid, fixture.aaguid);
        assert_eq!(verified.signature_counter, 1);

        assert!(verify_enrollment_attestation_v2(
            &fixture.credential_id,
            &fixture.client_data,
            &object,
            fixture.challenge,
            &[root.clone()],
            UnixMillisV2::new(2_600_000_000_000),
        )
        .is_err());
        assert!(verify_enrollment_attestation_v2(
            &fixture.credential_id,
            &fixture.client_data,
            &object,
            fixture.challenge,
            &[fixture.root([0x55; 16])],
            UnixMillisV2::new(1_800_000_000_000),
        )
        .is_err());
        let backup_object = fixture.object(flags | FLAG_BACKUP_ELIGIBLE);
        assert!(verify_enrollment_attestation_v2(
            &fixture.credential_id,
            &fixture.client_data,
            &backup_object,
            fixture.challenge,
            &[root],
            UnixMillisV2::new(1_800_000_000_000),
        )
        .is_err());
    }

    fn fixture() -> AttestationFixtureV2 {
        let root_key = SigningKey::from_bytes((&[0x11; 32]).into()).unwrap();
        let leaf_key = SigningKey::from_bytes((&[0x22; 32]).into()).unwrap();
        let root_name = name("Savana test attestation root");
        let leaf_name = name("Savana test authenticator");
        let root_spki = spki(&root_key);
        let leaf_spki = spki(&leaf_key);
        let aaguid = [0x33; 16];
        let root_extensions = extensions(&[
            extension(OID_BASIC_CONSTRAINTS, true, sequence(&boolean(true))),
            extension(OID_KEY_USAGE, true, bit_string(1, &[0x04])),
        ]);
        let leaf_extensions = extensions(&[
            extension(OID_BASIC_CONSTRAINTS, true, sequence(&[])),
            extension(OID_KEY_USAGE, true, bit_string(7, &[0x80])),
            extension(OID_FIDO_AAGUID, false, octet_string(&aaguid)),
        ]);
        let root_tbs = tbs_certificate(1, &root_name, &root_name, &root_spki, &root_extensions);
        let root_certificate = certificate(&root_tbs, &root_key);
        let leaf_tbs = tbs_certificate(2, &root_name, &leaf_name, &leaf_spki, &leaf_extensions);
        let leaf_certificate = certificate(&leaf_tbs, &root_key);
        let challenge = Nonce32V2::new([0x44; 32]);
        let client_data = format!(
            "{{\"type\":\"webauthn.create\",\"challenge\":\"{}\",\"origin\":\"http://localhost:8766\",\"crossOrigin\":false}}",
            URL_SAFE_NO_PAD.encode(challenge.as_bytes())
        )
        .into_bytes();
        let credential_id = vec![0x55; 32];
        let mut auth_data = Vec::new();
        auth_data.extend_from_slice(&Sha256::digest(RP_ID));
        auth_data.push(FLAG_USER_PRESENT | FLAG_USER_VERIFIED | FLAG_ATTESTED_CREDENTIAL_DATA);
        auth_data.extend_from_slice(&1_u32.to_be_bytes());
        auth_data.extend_from_slice(&aaguid);
        auth_data.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
        auth_data.extend_from_slice(&credential_id);
        let encoded = leaf_key.verifying_key().to_encoded_point(false);
        let x = encoded.x().unwrap();
        let y = encoded.y().unwrap();
        let mut cose = minicbor::Encoder::new(Vec::new());
        cose.map(5)
            .unwrap()
            .i32(1)
            .unwrap()
            .i32(2)
            .unwrap()
            .i32(3)
            .unwrap()
            .i32(-7)
            .unwrap()
            .i32(-1)
            .unwrap()
            .i32(1)
            .unwrap()
            .i32(-2)
            .unwrap()
            .bytes(x)
            .unwrap()
            .i32(-3)
            .unwrap()
            .bytes(y)
            .unwrap();
        auth_data.extend_from_slice(&cose.into_writer());
        AttestationFixtureV2 {
            credential_id,
            client_data,
            auth_data,
            leaf_key,
            leaf_certificate,
            root_certificate,
            root_spki_digest: Digest32V2::new(Sha256::digest(&root_spki).into()),
            aaguid,
            challenge,
        }
    }

    fn tbs_certificate(
        serial: u8,
        issuer: &[u8],
        subject: &[u8],
        spki: &[u8],
        extensions: &[u8],
    ) -> Vec<u8> {
        let mut content = Vec::new();
        content.extend_from_slice(&der(0xa0, &integer(&[2])));
        content.extend_from_slice(&integer(&[serial]));
        content.extend_from_slice(&algorithm());
        content.extend_from_slice(issuer);
        let mut validity = Vec::new();
        validity.extend_from_slice(&der(0x17, b"240101000000Z"));
        validity.extend_from_slice(&der(0x17, b"491231235959Z"));
        content.extend_from_slice(&sequence(&validity));
        content.extend_from_slice(subject);
        content.extend_from_slice(spki);
        content.extend_from_slice(&der(0xa3, extensions));
        sequence(&content)
    }

    fn certificate(tbs: &[u8], signer: &SigningKey) -> Vec<u8> {
        let signature: Signature = signer.sign(tbs);
        let signature = signature.normalize_s().unwrap_or(signature);
        let mut content = Vec::new();
        content.extend_from_slice(tbs);
        content.extend_from_slice(&algorithm());
        content.extend_from_slice(&bit_string(0, signature.to_der().as_bytes()));
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
        let content = values.concat();
        sequence(&content)
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
            let first = length.iter().position(|byte| *byte != 0).unwrap();
            output.push(0x80 | (length.len() - first) as u8);
            output.extend_from_slice(&length[first..]);
        }
        output.extend_from_slice(content);
        output
    }
}
