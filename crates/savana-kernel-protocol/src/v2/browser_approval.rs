use minicbor::Encode as _;
use zeroize::Zeroizing;

use super::{
    approval_display_digest_v2, cbor::V2DecodeContext, ApprovalDecisionCeremonyCapabilityV2,
    ApprovalDecisionV2, ApprovalPurposeV2, ApprovalTabSessionCapabilityV2,
    BoundedApprovalDisplayTextV2, BrowserWebAuthnAssertionV2, Digest32V2, Nonce32V2,
};
use crate::{ProtocolError, StableCode};

const MAX_APPROVAL_BROWSER_BODY_BYTES_V2: usize = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApprovalDisplayBrowserRequestV2 {
    tab: ApprovalTabSessionCapabilityV2,
}

impl ApprovalDisplayBrowserRequestV2 {
    pub const fn new(tab: ApprovalTabSessionCapabilityV2) -> Self {
        Self { tab }
    }

    pub const fn tab(self) -> ApprovalTabSessionCapabilityV2 {
        self.tab
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalDisplayViewV2 {
    purpose: ApprovalPurposeV2,
    display_projection_digest: Digest32V2,
    display_digest: Digest32V2,
    display_text: BoundedApprovalDisplayTextV2,
    display_declassification_provenance_digest: Digest32V2,
}

impl ApprovalDisplayViewV2 {
    pub fn new(
        purpose: ApprovalPurposeV2,
        display_projection_digest: Digest32V2,
        display_digest: Digest32V2,
        display_text: BoundedApprovalDisplayTextV2,
        display_declassification_provenance_digest: Digest32V2,
    ) -> Result<Self, ProtocolError> {
        if display_projection_digest.as_bytes() == &[0; 32]
            || display_digest.as_bytes() == &[0; 32]
            || display_text.as_bytes().len() > MAX_APPROVAL_BROWSER_BODY_BYTES_V2
            || approval_display_digest_v2(display_text.as_bytes()) != display_digest
            || display_declassification_provenance_digest.as_bytes() == &[0; 32]
        {
            return Err(malformed());
        }
        Ok(Self {
            purpose,
            display_projection_digest,
            display_digest,
            display_text,
            display_declassification_provenance_digest,
        })
    }

    pub const fn purpose(&self) -> ApprovalPurposeV2 {
        self.purpose
    }

    pub const fn display_projection_digest(&self) -> Digest32V2 {
        self.display_projection_digest
    }

    pub const fn display_digest(&self) -> Digest32V2 {
        self.display_digest
    }

    pub fn display_text(&self) -> &BoundedApprovalDisplayTextV2 {
        &self.display_text
    }

    pub const fn display_declassification_provenance_digest(&self) -> Digest32V2 {
        self.display_declassification_provenance_digest
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApprovalDecisionBrowserBeginRequestV2 {
    tab: ApprovalTabSessionCapabilityV2,
    client_request_nonce: Nonce32V2,
    decision: ApprovalDecisionV2,
}

impl ApprovalDecisionBrowserBeginRequestV2 {
    pub fn new(
        tab: ApprovalTabSessionCapabilityV2,
        client_request_nonce: Nonce32V2,
        decision: ApprovalDecisionV2,
    ) -> Result<Self, ProtocolError> {
        if client_request_nonce.as_bytes() == &[0; 32] {
            return Err(malformed());
        }
        Ok(Self {
            tab,
            client_request_nonce,
            decision,
        })
    }

    pub const fn tab(self) -> ApprovalTabSessionCapabilityV2 {
        self.tab
    }

    pub const fn client_request_nonce(self) -> Nonce32V2 {
        self.client_request_nonce
    }

    pub const fn decision(self) -> ApprovalDecisionV2 {
        self.decision
    }
}

pub struct ApprovalDecisionBrowserBeginResponseV2 {
    ceremony: ApprovalDecisionCeremonyCapabilityV2,
    public_key_options_json: Zeroizing<Vec<u8>>,
}

impl core::fmt::Debug for ApprovalDecisionBrowserBeginResponseV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ApprovalDecisionBrowserBeginResponseV2")
            .field("ceremony", &self.ceremony)
            .field("public_key_options_json", &"<redacted>")
            .finish()
    }
}

impl ApprovalDecisionBrowserBeginResponseV2 {
    pub fn new(
        ceremony: ApprovalDecisionCeremonyCapabilityV2,
        public_key_options_json: Vec<u8>,
    ) -> Result<Self, ProtocolError> {
        if public_key_options_json.is_empty() || public_key_options_json.len() > 8192 {
            return Err(malformed());
        }
        Ok(Self {
            ceremony,
            public_key_options_json: Zeroizing::new(public_key_options_json),
        })
    }

    pub fn into_parts(self) -> (ApprovalDecisionCeremonyCapabilityV2, Zeroizing<Vec<u8>>) {
        (self.ceremony, self.public_key_options_json)
    }
}

pub struct ApprovalDecisionBrowserFinishRequestV2 {
    ceremony: ApprovalDecisionCeremonyCapabilityV2,
    client_request_nonce: Nonce32V2,
    assertion: BrowserWebAuthnAssertionV2,
}

impl core::fmt::Debug for ApprovalDecisionBrowserFinishRequestV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ApprovalDecisionBrowserFinishRequestV2")
            .field("ceremony", &self.ceremony)
            .field("client_request_nonce", &self.client_request_nonce)
            .field("assertion", &"<redacted>")
            .finish()
    }
}

impl ApprovalDecisionBrowserFinishRequestV2 {
    pub fn new(
        ceremony: ApprovalDecisionCeremonyCapabilityV2,
        client_request_nonce: Nonce32V2,
        assertion: BrowserWebAuthnAssertionV2,
    ) -> Result<Self, ProtocolError> {
        if client_request_nonce.as_bytes() == &[0; 32] {
            return Err(malformed());
        }
        Ok(Self {
            ceremony,
            client_request_nonce,
            assertion,
        })
    }

    pub fn into_parts(
        self,
    ) -> (
        ApprovalDecisionCeremonyCapabilityV2,
        Nonce32V2,
        BrowserWebAuthnAssertionV2,
    ) {
        (self.ceremony, self.client_request_nonce, self.assertion)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalDecisionBrowserFinishResponseV2 {
    Denied,
    Approved,
}

pub fn encode_approval_display_browser_request_v2(
    value: ApprovalDisplayBrowserRequestV2,
) -> Result<Vec<u8>, ProtocolError> {
    minicbor::to_vec(value.tab).map_err(ProtocolError::malformed)
}

pub fn decode_approval_display_browser_request_v2(
    bytes: &[u8],
) -> Result<ApprovalDisplayBrowserRequestV2, ProtocolError> {
    validate(bytes)?;
    let mut decoder = minicbor::Decoder::new(bytes);
    let mut context = V2DecodeContext;
    let tab = minicbor::Decode::decode(&mut decoder, &mut context)
        .map_err(ProtocolError::from_typed_decode)?;
    let value = ApprovalDisplayBrowserRequestV2::new(tab);
    if decoder.position() != bytes.len()
        || encode_approval_display_browser_request_v2(value)? != bytes
    {
        return Err(malformed());
    }
    Ok(value)
}

pub fn encode_approval_display_view_v2(
    value: &ApprovalDisplayViewV2,
) -> Result<Vec<u8>, ProtocolError> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder.array(5).map_err(ProtocolError::malformed)?;
    value
        .purpose
        .encode(&mut encoder, &mut ())
        .and_then(|()| {
            value
                .display_projection_digest
                .encode(&mut encoder, &mut ())
        })
        .and_then(|()| value.display_digest.encode(&mut encoder, &mut ()))
        .map_err(ProtocolError::malformed)?;
    encoder
        .str(value.display_text.as_str())
        .map_err(ProtocolError::malformed)?;
    value
        .display_declassification_provenance_digest
        .encode(&mut encoder, &mut ())
        .map_err(ProtocolError::malformed)?;
    Ok(encoder.into_writer())
}

pub fn decode_approval_display_view_v2(
    bytes: &[u8],
) -> Result<ApprovalDisplayViewV2, ProtocolError> {
    validate(bytes)?;
    let mut decoder = minicbor::Decoder::new(bytes);
    if decoder.array().map_err(ProtocolError::malformed)? != Some(5) {
        return Err(malformed());
    }
    let mut context = V2DecodeContext;
    let value = ApprovalDisplayViewV2::new(
        minicbor::Decode::decode(&mut decoder, &mut context)
            .map_err(ProtocolError::from_typed_decode)?,
        minicbor::Decode::decode(&mut decoder, &mut context)
            .map_err(ProtocolError::from_typed_decode)?,
        minicbor::Decode::decode(&mut decoder, &mut context)
            .map_err(ProtocolError::from_typed_decode)?,
        BoundedApprovalDisplayTextV2::new(
            decoder.str().map_err(ProtocolError::malformed)?.to_owned(),
        )?,
        minicbor::Decode::decode(&mut decoder, &mut context)
            .map_err(ProtocolError::from_typed_decode)?,
    )?;
    if decoder.position() != bytes.len() || encode_approval_display_view_v2(&value)? != bytes {
        return Err(noncanonical());
    }
    Ok(value)
}

pub fn encode_approval_decision_browser_begin_request_v2(
    value: ApprovalDecisionBrowserBeginRequestV2,
) -> Result<Vec<u8>, ProtocolError> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder.array(3).map_err(ProtocolError::malformed)?;
    value
        .tab
        .encode(&mut encoder, &mut ())
        .and_then(|()| value.client_request_nonce.encode(&mut encoder, &mut ()))
        .and_then(|()| value.decision.encode(&mut encoder, &mut ()))
        .map_err(ProtocolError::malformed)?;
    Ok(encoder.into_writer())
}

pub fn decode_approval_decision_browser_begin_request_v2(
    bytes: &[u8],
) -> Result<ApprovalDecisionBrowserBeginRequestV2, ProtocolError> {
    validate(bytes)?;
    let mut decoder = minicbor::Decoder::new(bytes);
    if decoder.array().map_err(ProtocolError::malformed)? != Some(3) {
        return Err(malformed());
    }
    let mut context = V2DecodeContext;
    let value = ApprovalDecisionBrowserBeginRequestV2::new(
        minicbor::Decode::decode(&mut decoder, &mut context)
            .map_err(ProtocolError::from_typed_decode)?,
        minicbor::Decode::decode(&mut decoder, &mut context)
            .map_err(ProtocolError::from_typed_decode)?,
        minicbor::Decode::decode(&mut decoder, &mut context)
            .map_err(ProtocolError::from_typed_decode)?,
    )?;
    if decoder.position() != bytes.len()
        || encode_approval_decision_browser_begin_request_v2(value)? != bytes
    {
        return Err(malformed());
    }
    Ok(value)
}

pub fn encode_approval_decision_browser_begin_response_v2(
    value: &ApprovalDecisionBrowserBeginResponseV2,
) -> Result<Vec<u8>, ProtocolError> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder.array(2).map_err(ProtocolError::malformed)?;
    value
        .ceremony
        .encode(&mut encoder, &mut ())
        .map_err(ProtocolError::malformed)?;
    encoder
        .bytes(&value.public_key_options_json)
        .map_err(ProtocolError::malformed)?;
    Ok(encoder.into_writer())
}

pub fn decode_approval_decision_browser_begin_response_v2(
    bytes: &[u8],
) -> Result<ApprovalDecisionBrowserBeginResponseV2, ProtocolError> {
    validate(bytes)?;
    let mut decoder = minicbor::Decoder::new(bytes);
    if decoder.array().map_err(ProtocolError::malformed)? != Some(2) {
        return Err(malformed());
    }
    let mut context = V2DecodeContext;
    let value = ApprovalDecisionBrowserBeginResponseV2::new(
        minicbor::Decode::decode(&mut decoder, &mut context)
            .map_err(ProtocolError::from_typed_decode)?,
        decoder.bytes().map_err(ProtocolError::malformed)?.to_vec(),
    )?;
    if decoder.position() != bytes.len()
        || encode_approval_decision_browser_begin_response_v2(&value)? != bytes
    {
        return Err(noncanonical());
    }
    Ok(value)
}

pub fn encode_approval_decision_browser_finish_request_v2(
    value: &ApprovalDecisionBrowserFinishRequestV2,
) -> Result<Vec<u8>, ProtocolError> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder.array(3).map_err(ProtocolError::malformed)?;
    value
        .ceremony
        .encode(&mut encoder, &mut ())
        .and_then(|()| value.client_request_nonce.encode(&mut encoder, &mut ()))
        .map_err(ProtocolError::malformed)?;
    encode_assertion(&mut encoder, &value.assertion)?;
    Ok(encoder.into_writer())
}

pub fn decode_approval_decision_browser_finish_request_v2(
    bytes: &[u8],
) -> Result<ApprovalDecisionBrowserFinishRequestV2, ProtocolError> {
    validate(bytes)?;
    let mut decoder = minicbor::Decoder::new(bytes);
    if decoder.array().map_err(ProtocolError::malformed)? != Some(3) {
        return Err(malformed());
    }
    let mut context = V2DecodeContext;
    let ceremony = minicbor::Decode::decode(&mut decoder, &mut context)
        .map_err(ProtocolError::from_typed_decode)?;
    let nonce = minicbor::Decode::decode(&mut decoder, &mut context)
        .map_err(ProtocolError::from_typed_decode)?;
    let assertion = decode_assertion(&mut decoder)?;
    let value = ApprovalDecisionBrowserFinishRequestV2::new(ceremony, nonce, assertion)?;
    if decoder.position() != bytes.len()
        || encode_approval_decision_browser_finish_request_v2(&value)? != bytes
    {
        return Err(malformed());
    }
    Ok(value)
}

pub fn encode_approval_decision_browser_finish_response_v2(
    value: ApprovalDecisionBrowserFinishResponseV2,
) -> Result<Vec<u8>, ProtocolError> {
    minicbor::to_vec(match value {
        ApprovalDecisionBrowserFinishResponseV2::Denied => 1_u16,
        ApprovalDecisionBrowserFinishResponseV2::Approved => 2_u16,
    })
    .map_err(ProtocolError::malformed)
}

pub fn decode_approval_decision_browser_finish_response_v2(
    bytes: &[u8],
) -> Result<ApprovalDecisionBrowserFinishResponseV2, ProtocolError> {
    validate(bytes)?;
    let mut decoder = minicbor::Decoder::new(bytes);
    let mut context = V2DecodeContext;
    let tag: u16 = minicbor::Decode::decode(&mut decoder, &mut context)
        .map_err(ProtocolError::from_typed_decode)?;
    let value = match tag {
        1 => ApprovalDecisionBrowserFinishResponseV2::Denied,
        2 => ApprovalDecisionBrowserFinishResponseV2::Approved,
        _ => return Err(malformed()),
    };
    if decoder.position() != bytes.len()
        || encode_approval_decision_browser_finish_response_v2(value)? != bytes
    {
        return Err(noncanonical());
    }
    Ok(value)
}

fn encode_assertion<W: minicbor::encode::Write>(
    encoder: &mut minicbor::Encoder<W>,
    assertion: &BrowserWebAuthnAssertionV2,
) -> Result<(), ProtocolError> {
    encoder.array(5).map_err(ProtocolError::malformed)?;
    for bytes in [
        assertion.credential_id(),
        assertion.authenticator_data(),
        assertion.client_data_json(),
        assertion.signature(),
        assertion.user_handle(),
    ] {
        encoder.bytes(bytes).map_err(ProtocolError::malformed)?;
    }
    Ok(())
}

fn decode_assertion(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<BrowserWebAuthnAssertionV2, ProtocolError> {
    if decoder.array().map_err(ProtocolError::malformed)? != Some(5) {
        return Err(malformed());
    }
    BrowserWebAuthnAssertionV2::new(
        decoder.bytes().map_err(ProtocolError::malformed)?.to_vec(),
        decoder.bytes().map_err(ProtocolError::malformed)?.to_vec(),
        decoder.bytes().map_err(ProtocolError::malformed)?.to_vec(),
        decoder.bytes().map_err(ProtocolError::malformed)?.to_vec(),
        decoder.bytes().map_err(ProtocolError::malformed)?.to_vec(),
    )
}

fn validate(bytes: &[u8]) -> Result<(), ProtocolError> {
    if bytes.is_empty() || bytes.len() > MAX_APPROVAL_BROWSER_BODY_BYTES_V2 {
        Err(malformed())
    } else {
        Ok(())
    }
}

fn malformed() -> ProtocolError {
    ProtocolError::stable(StableCode::ProtocolMalformedCbor)
}

fn noncanonical() -> ProtocolError {
    ProtocolError::stable(StableCode::ProtocolNonCanonicalCbor)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn browser_view_encodes_exact_gated_text_and_node_digest() {
        let display =
            BoundedApprovalDisplayTextV2::new("批准：complete approval artifact".repeat(4))
                .unwrap();
        let node = Digest32V2::new([0x41; 32]);
        let view = ApprovalDisplayViewV2::new(
            ApprovalPurposeV2::ToolExecution,
            Digest32V2::new([0x42; 32]),
            approval_display_digest_v2(display.as_bytes()),
            display.clone(),
            node,
        )
        .unwrap();
        assert_eq!(view.display_text(), &display);
        assert_eq!(view.display_declassification_provenance_digest(), node);
        let encoded = encode_approval_display_view_v2(&view).unwrap();
        assert!(encoded
            .windows(display.as_bytes().len())
            .any(|window| window == display.as_bytes()));
        assert!(ApprovalDisplayViewV2::new(
            ApprovalPurposeV2::ToolExecution,
            Digest32V2::new([0x42; 32]),
            approval_display_digest_v2(display.as_bytes()),
            display,
            Digest32V2::new([0; 32]),
        )
        .is_err());
    }

    #[test]
    fn browser_view_refuses_invalid_utf8_controls_and_missing_node_before_display() {
        for forbidden in [vec![0xff, 0xfe], b"approve\nrelease".to_vec()] {
            assert!(BoundedApprovalDisplayTextV2::from_utf8_bytes(forbidden).is_err());
        }

        let display =
            BoundedApprovalDisplayTextV2::new("complete approval text".to_owned()).unwrap();
        assert!(ApprovalDisplayViewV2::new(
            ApprovalPurposeV2::Ingress,
            Digest32V2::new([0x42; 32]),
            approval_display_digest_v2(display.as_bytes()),
            display,
            Digest32V2::new([0; 32]),
        )
        .is_err());
    }

    #[test]
    fn binary_display_is_complete_reversible_canonical_base64() {
        let display = BoundedApprovalDisplayTextV2::from_binary(&[0x00, 0x81, 0xfe, 0xff]).unwrap();
        assert_eq!(display.as_str(), "base64:AIH+/w==");
    }

    #[test]
    fn approval_display_text_enforces_canonical_utf8_byte_bound() {
        assert!(BoundedApprovalDisplayTextV2::new(
            "x".repeat(super::super::MAX_APPROVAL_DISPLAY_BYTES_V2)
        )
        .is_ok());
        assert!(BoundedApprovalDisplayTextV2::new(
            "x".repeat(super::super::MAX_APPROVAL_DISPLAY_BYTES_V2 + 1)
        )
        .is_err());
        assert!(BoundedApprovalDisplayTextV2::new("e\u{301}".to_owned()).is_err());

        let largest_binary = vec![0x5a; 786_426];
        assert!(BoundedApprovalDisplayTextV2::from_binary(&largest_binary).is_ok());
        let oversized_binary = vec![0x5a; 786_427];
        assert!(BoundedApprovalDisplayTextV2::from_binary(&oversized_binary).is_err());
    }

    #[test]
    fn approval_browser_responses_round_trip_canonically_and_reject_trailing_data() {
        let display =
            BoundedApprovalDisplayTextV2::new("approve tool execution".to_owned()).unwrap();
        let view = ApprovalDisplayViewV2::new(
            ApprovalPurposeV2::ToolExecution,
            Digest32V2::new([0x51; 32]),
            approval_display_digest_v2(display.as_bytes()),
            display,
            Digest32V2::new([0x52; 32]),
        )
        .unwrap();
        let bytes = encode_approval_display_view_v2(&view).unwrap();
        let decoded = decode_approval_display_view_v2(&bytes).unwrap();
        assert_eq!(encode_approval_display_view_v2(&decoded).unwrap(), bytes);
        let mut trailing = bytes;
        trailing.push(0);
        assert!(decode_approval_display_view_v2(&trailing).is_err());

        let begin = ApprovalDecisionBrowserBeginResponseV2::new(
            ApprovalDecisionCeremonyCapabilityV2::from_authority_entropy([0x53; 32]).unwrap(),
            br#"{"challenge":"BAUG"}"#.to_vec(),
        )
        .unwrap();
        let bytes = encode_approval_decision_browser_begin_response_v2(&begin).unwrap();
        let decoded = decode_approval_decision_browser_begin_response_v2(&bytes).unwrap();
        assert_eq!(
            encode_approval_decision_browser_begin_response_v2(&decoded).unwrap(),
            bytes
        );
        let (_, public_key_options_json) = decoded.into_parts();
        assert_eq!(
            public_key_options_json.as_slice(),
            br#"{"challenge":"BAUG"}"#
        );
        let mut trailing = bytes;
        trailing.push(0);
        assert!(decode_approval_decision_browser_begin_response_v2(&trailing).is_err());

        let bytes = encode_approval_decision_browser_finish_response_v2(
            ApprovalDecisionBrowserFinishResponseV2::Approved,
        )
        .unwrap();
        let decoded = decode_approval_decision_browser_finish_response_v2(&bytes).unwrap();
        assert_eq!(
            encode_approval_decision_browser_finish_response_v2(decoded).unwrap(),
            bytes
        );
        assert!(decode_approval_decision_browser_finish_response_v2(&[0x18, 0x02]).is_err());
        let mut trailing = bytes;
        trailing.push(0);
        assert!(decode_approval_decision_browser_finish_response_v2(&trailing).is_err());
    }
}
