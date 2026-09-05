//! Closed application-turn delivery mapping. These are data codecs, not grants.
//! The producer must obtain the source from owned input and the destination from
//! the authenticated task contract. The receiver must authenticate the enclosing
//! executor transport and compare the decoded turn with its durable reservation.
use super::business_json::{exact, parse};
use super::business_request::identifier;
use super::{
    ActionCodecProfileV2, BusinessCodecErrorV2, BusinessFieldRoleV2, BusinessFieldTypeV2,
    BusinessFieldV2, BusinessMagnitudeV2, BusinessProfileV2, BusinessRequestV2, BusinessValueV2,
    Digest32V2, TaskEffectV2,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use zeroize::Zeroizing;

/// Binary payload bound before canonical base64 expansion. A release is one
/// counted effect; this is deliberately not described as a byte-metered profile.
pub const MAX_FINAL_RELEASE_BUSINESS_PAYLOAD_BYTES_V2: usize = 32 * 1024;
const OPERATION: &str = "/savana/final-release";

pub fn final_release_business_profile_v2(
    target: Digest32V2,
    credential: Digest32V2,
) -> Result<BusinessProfileV2, BusinessCodecErrorV2> {
    BusinessProfileV2::new(
        ActionCodecProfileV2::FixedJsonPostV1,
        OPERATION,
        target,
        credential,
        TaskEffectV2::FinalRelease,
        BusinessMagnitudeV2::FixedCount(1),
        vec![
            BusinessFieldV2::new(
                "destination",
                BusinessFieldRoleV2::Destination,
                BusinessFieldTypeV2::Text,
            )?,
            BusinessFieldV2::new(
                "payload",
                BusinessFieldRoleV2::Payload,
                BusinessFieldTypeV2::Text,
            )?,
            BusinessFieldV2::new(
                "resource",
                BusinessFieldRoleV2::Resource,
                BusinessFieldTypeV2::Text,
            )?,
        ],
    )
}

pub fn final_release_business_request_v2(
    profile: &BusinessProfileV2,
    request_id: &str,
    source_input_digest: Digest32V2,
    turn_binding: Digest32V2,
    payload: &[u8],
) -> Result<BusinessRequestV2, BusinessCodecErrorV2> {
    if profile
        != &final_release_business_profile_v2(
            profile.target_identity(),
            profile.credential_identity(),
        )?
    {
        return Err(BusinessCodecErrorV2::Unsupported);
    }
    if payload.len() > MAX_FINAL_RELEASE_BUSINESS_PAYLOAD_BYTES_V2 {
        return Err(BusinessCodecErrorV2::Limit);
    }
    BusinessRequestV2::from_fields(
        profile,
        request_id,
        vec![
            (
                "destination".into(),
                BusinessValueV2::Text(named_digest("application-turn:", turn_binding)?),
            ),
            (
                "payload".into(),
                BusinessValueV2::Text(URL_SAFE_NO_PAD.encode(payload)),
            ),
            (
                "resource".into(),
                BusinessValueV2::Text(named_digest("input:", source_input_digest)?),
            ),
        ],
    )
}

/// Decoded unprivileged delivery material. No signature or authorization is
/// implied by this type; the request ID is only a correlation identifier.
pub struct FinalReleaseDeliveryV2 {
    request_id: String,
    source_input_digest: Digest32V2,
    turn_binding: Digest32V2,
    payload: Zeroizing<Vec<u8>>,
}
impl std::fmt::Debug for FinalReleaseDeliveryV2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FinalReleaseDeliveryV2([redacted])")
    }
}
impl FinalReleaseDeliveryV2 {
    pub fn request_id(&self) -> &str {
        &self.request_id
    }
    pub fn source_input_digest(&self) -> Digest32V2 {
        self.source_input_digest
    }
    pub fn turn_binding(&self) -> Digest32V2 {
        self.turn_binding
    }
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

pub fn decode_final_release_delivery_v2(
    bytes: &[u8],
) -> Result<FinalReleaseDeliveryV2, BusinessCodecErrorV2> {
    let root = parse(bytes)?;
    let envelope = exact(&root, &["request_id", "method", "path", "body"])?;
    let request_id = envelope["request_id"].text()?;
    if !identifier(request_id, 128)
        || envelope["method"].text()? != "POST"
        || envelope["path"].text()? != OPERATION
    {
        return Err(BusinessCodecErrorV2::Malformed);
    }
    let body = exact(&envelope["body"], &["destination", "payload", "resource"])?;
    let source_input_digest = parse_named_digest(body["resource"].text()?, "input:")?;
    let turn_binding = parse_named_digest(body["destination"].text()?, "application-turn:")?;
    let encoded = body["payload"].text()?;
    if encoded.len() > MAX_FINAL_RELEASE_BUSINESS_PAYLOAD_BYTES_V2.div_ceil(3) * 4 {
        return Err(BusinessCodecErrorV2::Limit);
    }
    let payload = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| BusinessCodecErrorV2::Malformed)?,
    );
    if payload.len() > MAX_FINAL_RELEASE_BUSINESS_PAYLOAD_BYTES_V2
        || URL_SAFE_NO_PAD.encode(&*payload) != encoded
    {
        return Err(BusinessCodecErrorV2::Malformed);
    }
    Ok(FinalReleaseDeliveryV2 {
        request_id: request_id.into(),
        source_input_digest,
        turn_binding,
        payload,
    })
}

fn named_digest(prefix: &str, digest: Digest32V2) -> Result<String, BusinessCodecErrorV2> {
    use std::fmt::Write as _;
    if digest.as_bytes() == &[0; 32] {
        return Err(BusinessCodecErrorV2::Binding);
    }
    let mut text = String::with_capacity(prefix.len() + 64);
    text.push_str(prefix);
    for byte in digest.as_bytes() {
        write!(&mut text, "{byte:02x}").expect("string write");
    }
    Ok(text)
}
fn parse_named_digest(text: &str, prefix: &str) -> Result<Digest32V2, BusinessCodecErrorV2> {
    let hex = text
        .strip_prefix(prefix)
        .ok_or(BusinessCodecErrorV2::Malformed)?;
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(BusinessCodecErrorV2::Malformed);
    }
    let mut value = [0; 32];
    for (i, byte) in value.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|_| BusinessCodecErrorV2::Malformed)?;
    }
    if value == [0; 32] {
        return Err(BusinessCodecErrorV2::Binding);
    }
    Ok(Digest32V2::new(value))
}
