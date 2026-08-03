use minicbor::Encode as _;

use super::{
    cbor::V2DecodeContext, ApprovalDisplayAuthenticationTransferCapabilityV2, ContentKindV2,
    Digest32V2, IngressTabSessionCapabilityV2, InputPublicStateV2, Nonce32V2, ZeroizingBytesV2,
};
use crate::{ProtocolError, StableCode};

const MAX_INGRESS_BROWSER_BODY_BYTES_V2: usize = 1024 * 1024;

pub enum IngressBrowserRequestV2 {
    Begin {
        tab: IngressTabSessionCapabilityV2,
        client_request_nonce: Nonce32V2,
        content_kind: ContentKindV2,
        declared_total_bytes: u64,
        declared_content_digest: Option<Digest32V2>,
    },
    Append {
        tab: IngressTabSessionCapabilityV2,
        client_request_nonce: Nonce32V2,
        sequence: u32,
        chunk: ZeroizingBytesV2,
    },
    Finalize {
        tab: IngressTabSessionCapabilityV2,
        client_request_nonce: Nonce32V2,
        declared_content_digest: Digest32V2,
    },
    Abort {
        tab: IngressTabSessionCapabilityV2,
        client_request_nonce: Nonce32V2,
    },
}

impl core::fmt::Debug for IngressBrowserRequestV2 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Begin {
                tab,
                client_request_nonce,
                content_kind,
                declared_total_bytes,
                declared_content_digest,
            } => formatter
                .debug_struct("Begin")
                .field("tab", tab)
                .field("client_request_nonce", client_request_nonce)
                .field("content_kind", content_kind)
                .field("declared_total_bytes", declared_total_bytes)
                .field("declared_content_digest", declared_content_digest)
                .finish(),
            Self::Append {
                tab,
                client_request_nonce,
                sequence,
                ..
            } => formatter
                .debug_struct("Append")
                .field("tab", tab)
                .field("client_request_nonce", client_request_nonce)
                .field("sequence", sequence)
                .field("chunk", &"<redacted>")
                .finish(),
            Self::Finalize {
                tab,
                client_request_nonce,
                declared_content_digest,
            } => formatter
                .debug_struct("Finalize")
                .field("tab", tab)
                .field("client_request_nonce", client_request_nonce)
                .field("declared_content_digest", declared_content_digest)
                .finish(),
            Self::Abort {
                tab,
                client_request_nonce,
            } => formatter
                .debug_struct("Abort")
                .field("tab", tab)
                .field("client_request_nonce", client_request_nonce)
                .finish(),
        }
    }
}

impl IngressBrowserRequestV2 {
    pub const fn tab(&self) -> IngressTabSessionCapabilityV2 {
        match self {
            Self::Begin { tab, .. }
            | Self::Append { tab, .. }
            | Self::Finalize { tab, .. }
            | Self::Abort { tab, .. } => *tab,
        }
    }

    pub const fn client_request_nonce(&self) -> Nonce32V2 {
        match self {
            Self::Begin {
                client_request_nonce,
                ..
            }
            | Self::Append {
                client_request_nonce,
                ..
            }
            | Self::Finalize {
                client_request_nonce,
                ..
            }
            | Self::Abort {
                client_request_nonce,
                ..
            } => *client_request_nonce,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IngressUiAuthenticationCompleteBrowserResponseV2 {
    tab: IngressTabSessionCapabilityV2,
}

impl IngressUiAuthenticationCompleteBrowserResponseV2 {
    pub const fn new(tab: IngressTabSessionCapabilityV2) -> Self {
        Self { tab }
    }

    pub const fn tab(self) -> IngressTabSessionCapabilityV2 {
        self.tab
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngressBrowserMutationResponseV2 {
    Begun {
        next_sequence: u32,
    },
    ChunkAccepted {
        acknowledged_sequence: u32,
        cumulative_digest: Digest32V2,
    },
    FinalizeOpenApproval {
        transfer: ApprovalDisplayAuthenticationTransferCapabilityV2,
    },
    FinalizeCommitted {
        state: InputPublicStateV2,
    },
    FinalizeRejected {
        state: InputPublicStateV2,
    },
    Aborted,
}

pub fn encode_ingress_browser_request_v2(
    value: &IngressBrowserRequestV2,
) -> Result<Vec<u8>, ProtocolError> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    match value {
        IngressBrowserRequestV2::Begin {
            tab,
            client_request_nonce,
            content_kind,
            declared_total_bytes,
            declared_content_digest,
        } => {
            encoder
                .array(6)
                .and_then(|encoder| encoder.u16(1))
                .map_err(ProtocolError::malformed)?;
            tab.encode(&mut encoder, &mut ())
                .and_then(|()| client_request_nonce.encode(&mut encoder, &mut ()))
                .and_then(|()| content_kind.encode(&mut encoder, &mut ()))
                .map_err(ProtocolError::malformed)?;
            encoder
                .u64(*declared_total_bytes)
                .map_err(ProtocolError::malformed)?;
            encode_optional_digest(&mut encoder, *declared_content_digest)?;
        }
        IngressBrowserRequestV2::Append {
            tab,
            client_request_nonce,
            sequence,
            chunk,
        } => {
            encoder
                .array(5)
                .and_then(|encoder| encoder.u16(2))
                .map_err(ProtocolError::malformed)?;
            tab.encode(&mut encoder, &mut ())
                .and_then(|()| client_request_nonce.encode(&mut encoder, &mut ()))
                .map_err(ProtocolError::malformed)?;
            encoder
                .u32(*sequence)
                .and_then(|encoder| encoder.bytes(chunk.as_bytes()))
                .map_err(ProtocolError::malformed)?;
        }
        IngressBrowserRequestV2::Finalize {
            tab,
            client_request_nonce,
            declared_content_digest,
        } => {
            encoder
                .array(4)
                .and_then(|encoder| encoder.u16(3))
                .map_err(ProtocolError::malformed)?;
            tab.encode(&mut encoder, &mut ())
                .and_then(|()| client_request_nonce.encode(&mut encoder, &mut ()))
                .and_then(|()| declared_content_digest.encode(&mut encoder, &mut ()))
                .map_err(ProtocolError::malformed)?;
        }
        IngressBrowserRequestV2::Abort {
            tab,
            client_request_nonce,
        } => {
            encoder
                .array(3)
                .and_then(|encoder| encoder.u16(4))
                .map_err(ProtocolError::malformed)?;
            tab.encode(&mut encoder, &mut ())
                .and_then(|()| client_request_nonce.encode(&mut encoder, &mut ()))
                .map_err(ProtocolError::malformed)?;
        }
    }
    Ok(encoder.into_writer())
}

pub fn decode_ingress_browser_request_v2(
    bytes: &[u8],
) -> Result<IngressBrowserRequestV2, ProtocolError> {
    if bytes.is_empty() || bytes.len() > MAX_INGRESS_BROWSER_BODY_BYTES_V2 {
        return Err(malformed());
    }
    let mut decoder = minicbor::Decoder::new(bytes);
    let count = decoder.array().map_err(ProtocolError::malformed)?;
    let tag = decoder.u16().map_err(ProtocolError::malformed)?;
    let mut context = V2DecodeContext;
    let value = match (tag, count) {
        (1, Some(6)) => IngressBrowserRequestV2::Begin {
            tab: minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?,
            client_request_nonce: minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?,
            content_kind: minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?,
            declared_total_bytes: decoder.u64().map_err(ProtocolError::malformed)?,
            declared_content_digest: decode_optional_digest(&mut decoder, &mut context)?,
        },
        (2, Some(5)) => IngressBrowserRequestV2::Append {
            tab: minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?,
            client_request_nonce: minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?,
            sequence: decoder.u32().map_err(ProtocolError::malformed)?,
            chunk: ZeroizingBytesV2::new(
                decoder.bytes().map_err(ProtocolError::malformed)?.to_vec(),
            )?,
        },
        (3, Some(4)) => IngressBrowserRequestV2::Finalize {
            tab: minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?,
            client_request_nonce: minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?,
            declared_content_digest: minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?,
        },
        (4, Some(3)) => IngressBrowserRequestV2::Abort {
            tab: minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?,
            client_request_nonce: minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?,
        },
        _ => return Err(malformed()),
    };
    if value.client_request_nonce().as_bytes() == &[0; 32]
        || decoder.position() != bytes.len()
        || encode_ingress_browser_request_v2(&value)? != bytes
    {
        return Err(malformed());
    }
    Ok(value)
}

pub fn encode_ingress_ui_authentication_complete_browser_response_v2(
    value: IngressUiAuthenticationCompleteBrowserResponseV2,
) -> Result<Vec<u8>, ProtocolError> {
    minicbor::to_vec(value.tab).map_err(ProtocolError::malformed)
}

pub fn decode_ingress_ui_authentication_complete_browser_response_v2(
    bytes: &[u8],
) -> Result<IngressUiAuthenticationCompleteBrowserResponseV2, ProtocolError> {
    validate_body(bytes)?;
    let mut decoder = minicbor::Decoder::new(bytes);
    let mut context = V2DecodeContext;
    let value = IngressUiAuthenticationCompleteBrowserResponseV2::new(
        minicbor::Decode::decode(&mut decoder, &mut context)
            .map_err(ProtocolError::from_typed_decode)?,
    );
    if decoder.position() != bytes.len()
        || encode_ingress_ui_authentication_complete_browser_response_v2(value)? != bytes
    {
        return Err(noncanonical());
    }
    Ok(value)
}

pub fn encode_ingress_browser_mutation_response_v2(
    value: IngressBrowserMutationResponseV2,
) -> Result<Vec<u8>, ProtocolError> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    match value {
        IngressBrowserMutationResponseV2::Begun { next_sequence } => {
            encoder
                .array(2)
                .and_then(|encoder| encoder.u16(1))
                .and_then(|encoder| encoder.u32(next_sequence))
                .map_err(ProtocolError::malformed)?;
        }
        IngressBrowserMutationResponseV2::ChunkAccepted {
            acknowledged_sequence,
            cumulative_digest,
        } => {
            encoder
                .array(3)
                .and_then(|encoder| encoder.u16(2))
                .and_then(|encoder| encoder.u32(acknowledged_sequence))
                .map_err(ProtocolError::malformed)?;
            cumulative_digest
                .encode(&mut encoder, &mut ())
                .map_err(ProtocolError::malformed)?;
        }
        IngressBrowserMutationResponseV2::FinalizeOpenApproval { transfer } => {
            encoder
                .array(2)
                .and_then(|encoder| encoder.u16(3))
                .map_err(ProtocolError::malformed)?;
            transfer
                .encode(&mut encoder, &mut ())
                .map_err(ProtocolError::malformed)?;
        }
        IngressBrowserMutationResponseV2::Aborted => {
            encoder
                .array(1)
                .and_then(|encoder| encoder.u16(4))
                .map_err(ProtocolError::malformed)?;
        }
        IngressBrowserMutationResponseV2::FinalizeCommitted { state } => {
            encoder
                .array(2)
                .and_then(|encoder| encoder.u16(5))
                .map_err(ProtocolError::malformed)?;
            state
                .encode(&mut encoder, &mut ())
                .map_err(ProtocolError::malformed)?;
        }
        IngressBrowserMutationResponseV2::FinalizeRejected { state } => {
            encoder
                .array(2)
                .and_then(|encoder| encoder.u16(6))
                .map_err(ProtocolError::malformed)?;
            state
                .encode(&mut encoder, &mut ())
                .map_err(ProtocolError::malformed)?;
        }
    }
    Ok(encoder.into_writer())
}

pub fn decode_ingress_browser_mutation_response_v2(
    bytes: &[u8],
) -> Result<IngressBrowserMutationResponseV2, ProtocolError> {
    validate_body(bytes)?;
    let mut decoder = minicbor::Decoder::new(bytes);
    let count = decoder.array().map_err(ProtocolError::malformed)?;
    let tag = decoder.u16().map_err(ProtocolError::malformed)?;
    let mut context = V2DecodeContext;
    let value = match (tag, count) {
        (1, Some(2)) => IngressBrowserMutationResponseV2::Begun {
            next_sequence: decoder.u32().map_err(ProtocolError::malformed)?,
        },
        (2, Some(3)) => IngressBrowserMutationResponseV2::ChunkAccepted {
            acknowledged_sequence: decoder.u32().map_err(ProtocolError::malformed)?,
            cumulative_digest: minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?,
        },
        (3, Some(2)) => IngressBrowserMutationResponseV2::FinalizeOpenApproval {
            transfer: minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?,
        },
        (4, Some(1)) => IngressBrowserMutationResponseV2::Aborted,
        (5, Some(2)) => IngressBrowserMutationResponseV2::FinalizeCommitted {
            state: minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?,
        },
        (6, Some(2)) => IngressBrowserMutationResponseV2::FinalizeRejected {
            state: minicbor::Decode::decode(&mut decoder, &mut context)
                .map_err(ProtocolError::from_typed_decode)?,
        },
        _ => return Err(malformed()),
    };
    if decoder.position() != bytes.len()
        || encode_ingress_browser_mutation_response_v2(value)? != bytes
    {
        return Err(noncanonical());
    }
    Ok(value)
}

fn encode_optional_digest<W: minicbor::encode::Write>(
    encoder: &mut minicbor::Encoder<W>,
    value: Option<Digest32V2>,
) -> Result<(), ProtocolError> {
    match value {
        Some(value) => value
            .encode(encoder, &mut ())
            .map_err(ProtocolError::malformed),
        None => {
            encoder.null().map_err(ProtocolError::malformed)?;
            Ok(())
        }
    }
}

fn decode_optional_digest(
    decoder: &mut minicbor::Decoder<'_>,
    context: &mut V2DecodeContext,
) -> Result<Option<Digest32V2>, ProtocolError> {
    if decoder.datatype().map_err(ProtocolError::malformed)? == minicbor::data::Type::Null {
        decoder.null().map_err(ProtocolError::malformed)?;
        Ok(None)
    } else {
        Ok(Some(
            minicbor::Decode::decode(decoder, context).map_err(ProtocolError::from_typed_decode)?,
        ))
    }
}

fn validate_body(bytes: &[u8]) -> Result<(), ProtocolError> {
    if bytes.is_empty() || bytes.len() > MAX_INGRESS_BROWSER_BODY_BYTES_V2 {
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
    fn append_body_is_canonical_and_content_redacted() {
        let request = IngressBrowserRequestV2::Append {
            tab: IngressTabSessionCapabilityV2::from_authority_entropy([1; 32]).unwrap(),
            client_request_nonce: Nonce32V2::new([2; 32]),
            sequence: 0,
            chunk: ZeroizingBytesV2::new(b"secret".to_vec()).unwrap(),
        };
        let bytes = encode_ingress_browser_request_v2(&request).unwrap();
        let decoded = decode_ingress_browser_request_v2(&bytes).unwrap();
        assert_eq!(encode_ingress_browser_request_v2(&decoded).unwrap(), bytes);
        assert!(!format!("{decoded:?}").contains("secret"));
    }

    #[test]
    fn terminal_finalize_responses_are_closed_and_distinct() {
        let committed = encode_ingress_browser_mutation_response_v2(
            IngressBrowserMutationResponseV2::FinalizeCommitted {
                state: InputPublicStateV2::CommittedUnclaimed,
            },
        )
        .unwrap();
        let rejected = encode_ingress_browser_mutation_response_v2(
            IngressBrowserMutationResponseV2::FinalizeRejected {
                state: InputPublicStateV2::Denied,
            },
        )
        .unwrap();

        assert_eq!(committed[1], 5);
        assert_eq!(rejected[1], 6);
        assert_ne!(committed, rejected);
    }

    #[test]
    fn ingress_browser_responses_round_trip_canonically_and_reject_trailing_data() {
        let authentication = IngressUiAuthenticationCompleteBrowserResponseV2::new(
            IngressTabSessionCapabilityV2::from_authority_entropy([3; 32]).unwrap(),
        );
        let bytes =
            encode_ingress_ui_authentication_complete_browser_response_v2(authentication).unwrap();
        let decoded =
            decode_ingress_ui_authentication_complete_browser_response_v2(&bytes).unwrap();
        assert_eq!(
            encode_ingress_ui_authentication_complete_browser_response_v2(decoded).unwrap(),
            bytes
        );
        let mut trailing = bytes;
        trailing.push(0);
        assert!(decode_ingress_ui_authentication_complete_browser_response_v2(&trailing).is_err());

        let bytes =
            encode_ingress_browser_mutation_response_v2(IngressBrowserMutationResponseV2::Aborted)
                .unwrap();
        let decoded = decode_ingress_browser_mutation_response_v2(&bytes).unwrap();
        assert_eq!(
            encode_ingress_browser_mutation_response_v2(decoded).unwrap(),
            bytes
        );
        let noncanonical = [0x81, 0x18, 0x04];
        assert!(decode_ingress_browser_mutation_response_v2(&noncanonical).is_err());
        let mut trailing = bytes;
        trailing.push(0);
        assert!(decode_ingress_browser_mutation_response_v2(&trailing).is_err());
    }
}
