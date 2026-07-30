use minicbor::Encode as _;
use zeroize::Zeroizing;

use super::{
    cbor::V2DecodeContext, CredentialPublicStateV2, Digest32V2, EnrollmentCeremonyCapabilityV2,
    EnrollmentHandleV2, Nonce32V2, ZeroizingTextV2,
};
use crate::{ProtocolError, StableCode};

const MAX_ENROLLMENT_BROWSER_BODY_BYTES_V2: usize = 1024 * 1024;
const MAX_CREATION_OPTIONS_BYTES_V2: usize = 64 * 1024;
const MAX_CREDENTIAL_ID_BYTES_V2: usize = 4096;
const MAX_CLIENT_DATA_BYTES_V2: usize = 64 * 1024;
const MAX_ATTESTATION_OBJECT_BYTES_V2: usize = 512 * 1024;

pub struct BeginEnrollmentBrowserRequestV2 {
    enrollment: EnrollmentHandleV2,
    client_request_nonce: Nonce32V2,
    code: ZeroizingTextV2,
}

impl core::fmt::Debug for BeginEnrollmentBrowserRequestV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("BeginEnrollmentBrowserRequestV2")
            .field("enrollment", &self.enrollment)
            .field("client_request_nonce", &self.client_request_nonce)
            .field("code", &"<redacted>")
            .finish()
    }
}

impl BeginEnrollmentBrowserRequestV2 {
    pub fn new(
        enrollment: EnrollmentHandleV2,
        client_request_nonce: Nonce32V2,
        code: ZeroizingTextV2,
    ) -> Result<Self, ProtocolError> {
        if client_request_nonce.as_bytes() == &[0; 32] {
            return Err(malformed());
        }
        Ok(Self {
            enrollment,
            client_request_nonce,
            code,
        })
    }

    pub fn into_parts(self) -> (EnrollmentHandleV2, Nonce32V2, ZeroizingTextV2) {
        (self.enrollment, self.client_request_nonce, self.code)
    }
}

pub struct BeginEnrollmentBrowserResponseV2 {
    ceremony: EnrollmentCeremonyCapabilityV2,
    creation_options_json: Zeroizing<Vec<u8>>,
}

impl core::fmt::Debug for BeginEnrollmentBrowserResponseV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("BeginEnrollmentBrowserResponseV2")
            .field("ceremony", &self.ceremony)
            .field("creation_options_json", &"<redacted>")
            .finish()
    }
}

impl BeginEnrollmentBrowserResponseV2 {
    pub fn new(
        ceremony: EnrollmentCeremonyCapabilityV2,
        creation_options_json: Vec<u8>,
    ) -> Result<Self, ProtocolError> {
        if creation_options_json.is_empty()
            || creation_options_json.len() > MAX_CREATION_OPTIONS_BYTES_V2
        {
            return Err(malformed());
        }
        Ok(Self {
            ceremony,
            creation_options_json: Zeroizing::new(creation_options_json),
        })
    }
}

pub struct FinishEnrollmentBrowserRequestV2 {
    ceremony: EnrollmentCeremonyCapabilityV2,
    client_request_nonce: Nonce32V2,
    credential_id: Zeroizing<Vec<u8>>,
    client_data_json: Zeroizing<Vec<u8>>,
    attestation_object: Zeroizing<Vec<u8>>,
}

impl core::fmt::Debug for FinishEnrollmentBrowserRequestV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("FinishEnrollmentBrowserRequestV2")
            .field("ceremony", &self.ceremony)
            .field("client_request_nonce", &self.client_request_nonce)
            .finish_non_exhaustive()
    }
}

impl FinishEnrollmentBrowserRequestV2 {
    pub fn new(
        ceremony: EnrollmentCeremonyCapabilityV2,
        client_request_nonce: Nonce32V2,
        credential_id: Vec<u8>,
        client_data_json: Vec<u8>,
        attestation_object: Vec<u8>,
    ) -> Result<Self, ProtocolError> {
        if client_request_nonce.as_bytes() == &[0; 32]
            || credential_id.is_empty()
            || credential_id.len() > MAX_CREDENTIAL_ID_BYTES_V2
            || client_data_json.is_empty()
            || client_data_json.len() > MAX_CLIENT_DATA_BYTES_V2
            || attestation_object.is_empty()
            || attestation_object.len() > MAX_ATTESTATION_OBJECT_BYTES_V2
        {
            return Err(malformed());
        }
        Ok(Self {
            ceremony,
            client_request_nonce,
            credential_id: Zeroizing::new(credential_id),
            client_data_json: Zeroizing::new(client_data_json),
            attestation_object: Zeroizing::new(attestation_object),
        })
    }

    pub fn into_parts(self) -> FinishEnrollmentBrowserRequestPartsV2 {
        (
            self.ceremony,
            self.client_request_nonce,
            self.credential_id,
            self.client_data_json,
            self.attestation_object,
        )
    }
}

pub type FinishEnrollmentBrowserRequestPartsV2 = (
    EnrollmentCeremonyCapabilityV2,
    Nonce32V2,
    Zeroizing<Vec<u8>>,
    Zeroizing<Vec<u8>>,
    Zeroizing<Vec<u8>>,
);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FinishEnrollmentBrowserResponseV2 {
    credential_digest: Digest32V2,
    state: CredentialPublicStateV2,
}

impl FinishEnrollmentBrowserResponseV2 {
    pub fn new(
        credential_digest: Digest32V2,
        state: CredentialPublicStateV2,
    ) -> Result<Self, ProtocolError> {
        if credential_digest.as_bytes() == &[0; 32] {
            return Err(malformed());
        }
        Ok(Self {
            credential_digest,
            state,
        })
    }
}

pub fn encode_begin_enrollment_browser_request_v2(
    value: &BeginEnrollmentBrowserRequestV2,
) -> Result<Vec<u8>, ProtocolError> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder.array(3).map_err(ProtocolError::malformed)?;
    value
        .enrollment
        .encode(&mut encoder, &mut ())
        .and_then(|()| value.client_request_nonce.encode(&mut encoder, &mut ()))
        .and_then(|()| value.code.encode(&mut encoder, &mut ()))
        .map_err(ProtocolError::malformed)?;
    Ok(encoder.into_writer())
}

pub fn decode_begin_enrollment_browser_request_v2(
    bytes: &[u8],
) -> Result<BeginEnrollmentBrowserRequestV2, ProtocolError> {
    validate(bytes)?;
    let mut decoder = minicbor::Decoder::new(bytes);
    if decoder.array().map_err(ProtocolError::malformed)? != Some(3) {
        return Err(malformed());
    }
    let mut context = V2DecodeContext;
    let value = BeginEnrollmentBrowserRequestV2::new(
        minicbor::Decode::decode(&mut decoder, &mut context)
            .map_err(ProtocolError::from_typed_decode)?,
        minicbor::Decode::decode(&mut decoder, &mut context)
            .map_err(ProtocolError::from_typed_decode)?,
        minicbor::Decode::decode(&mut decoder, &mut context)
            .map_err(ProtocolError::from_typed_decode)?,
    )?;
    if decoder.position() != bytes.len()
        || encode_begin_enrollment_browser_request_v2(&value)? != bytes
    {
        return Err(malformed());
    }
    Ok(value)
}

pub fn encode_begin_enrollment_browser_response_v2(
    value: &BeginEnrollmentBrowserResponseV2,
) -> Result<Vec<u8>, ProtocolError> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder.array(2).map_err(ProtocolError::malformed)?;
    value
        .ceremony
        .encode(&mut encoder, &mut ())
        .map_err(ProtocolError::malformed)?;
    encoder
        .bytes(&value.creation_options_json)
        .map_err(ProtocolError::malformed)?;
    Ok(encoder.into_writer())
}

pub fn encode_finish_enrollment_browser_request_v2(
    value: &FinishEnrollmentBrowserRequestV2,
) -> Result<Vec<u8>, ProtocolError> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder.array(5).map_err(ProtocolError::malformed)?;
    value
        .ceremony
        .encode(&mut encoder, &mut ())
        .and_then(|()| value.client_request_nonce.encode(&mut encoder, &mut ()))
        .map_err(ProtocolError::malformed)?;
    for bytes in [
        value.credential_id.as_slice(),
        value.client_data_json.as_slice(),
        value.attestation_object.as_slice(),
    ] {
        encoder.bytes(bytes).map_err(ProtocolError::malformed)?;
    }
    Ok(encoder.into_writer())
}

pub fn decode_finish_enrollment_browser_request_v2(
    bytes: &[u8],
) -> Result<FinishEnrollmentBrowserRequestV2, ProtocolError> {
    validate(bytes)?;
    let mut decoder = minicbor::Decoder::new(bytes);
    if decoder.array().map_err(ProtocolError::malformed)? != Some(5) {
        return Err(malformed());
    }
    let mut context = V2DecodeContext;
    let value = FinishEnrollmentBrowserRequestV2::new(
        minicbor::Decode::decode(&mut decoder, &mut context)
            .map_err(ProtocolError::from_typed_decode)?,
        minicbor::Decode::decode(&mut decoder, &mut context)
            .map_err(ProtocolError::from_typed_decode)?,
        decoder.bytes().map_err(ProtocolError::malformed)?.to_vec(),
        decoder.bytes().map_err(ProtocolError::malformed)?.to_vec(),
        decoder.bytes().map_err(ProtocolError::malformed)?.to_vec(),
    )?;
    if decoder.position() != bytes.len()
        || encode_finish_enrollment_browser_request_v2(&value)? != bytes
    {
        return Err(malformed());
    }
    Ok(value)
}

pub fn encode_finish_enrollment_browser_response_v2(
    value: FinishEnrollmentBrowserResponseV2,
) -> Result<Vec<u8>, ProtocolError> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder.array(2).map_err(ProtocolError::malformed)?;
    value
        .credential_digest
        .encode(&mut encoder, &mut ())
        .and_then(|()| value.state.encode(&mut encoder, &mut ()))
        .map_err(ProtocolError::malformed)?;
    Ok(encoder.into_writer())
}

fn validate(bytes: &[u8]) -> Result<(), ProtocolError> {
    if bytes.is_empty() || bytes.len() > MAX_ENROLLMENT_BROWSER_BODY_BYTES_V2 {
        Err(malformed())
    } else {
        Ok(())
    }
}

fn malformed() -> ProtocolError {
    ProtocolError::stable(StableCode::ProtocolMalformedCbor)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enrollment_browser_requests_round_trip_canonically_and_reject_trailing_data() {
        let begin = BeginEnrollmentBrowserRequestV2::new(
            EnrollmentHandleV2::from_authority_entropy([1; 32]).unwrap(),
            Nonce32V2::new([2; 32]),
            ZeroizingTextV2::new("one-time-code".to_owned()).unwrap(),
        )
        .unwrap();
        let bytes = encode_begin_enrollment_browser_request_v2(&begin).unwrap();
        let decoded = decode_begin_enrollment_browser_request_v2(&bytes).unwrap();
        assert_eq!(
            encode_begin_enrollment_browser_request_v2(&decoded).unwrap(),
            bytes
        );

        let finish = FinishEnrollmentBrowserRequestV2::new(
            EnrollmentCeremonyCapabilityV2::from_authority_entropy([3; 32]).unwrap(),
            Nonce32V2::new([4; 32]),
            vec![5; 32],
            br#"{"type":"webauthn.create"}"#.to_vec(),
            vec![6; 128],
        )
        .unwrap();
        let bytes = encode_finish_enrollment_browser_request_v2(&finish).unwrap();
        let decoded = decode_finish_enrollment_browser_request_v2(&bytes).unwrap();
        assert_eq!(
            encode_finish_enrollment_browser_request_v2(&decoded).unwrap(),
            bytes
        );
        let mut trailing = bytes;
        trailing.push(0);
        assert!(decode_finish_enrollment_browser_request_v2(&trailing).is_err());
    }
}
