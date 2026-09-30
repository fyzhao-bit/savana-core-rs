//! Kernel-only private-session transport. No Agent route or action consent.
use super::*;
use crate::ProtocolError;
use minicbor::{Decode as _, Encode as _};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegisteredPrivateSessionV04 {
    pub record: ApprovalUiRecordHandleV2,
    pub transfer: PrivateSessionTransferV04,
}

pub fn encode_registered_private_session_v04(
    value: RegisteredPrivateSessionV04,
) -> Result<Vec<u8>, ProtocolError> {
    let mut e = minicbor::Encoder::new(Vec::new());
    e.array(3)
        .and_then(|e| e.u16(4))
        .map_err(ProtocolError::malformed)?;
    value
        .record
        .encode(&mut e, &mut ())
        .map_err(ProtocolError::malformed)?;
    value
        .transfer
        .encode(&mut e, &mut ())
        .map_err(ProtocolError::malformed)?;
    Ok(e.into_writer())
}

pub fn decode_registered_private_session_v04(
    bytes: &[u8],
) -> Result<RegisteredPrivateSessionV04, ProtocolError> {
    if bytes.len() > 256 {
        return Err(invalid());
    }
    let mut d = minicbor::Decoder::new(bytes);
    if d.array().map_err(ProtocolError::malformed)? != Some(3)
        || d.u16().map_err(ProtocolError::malformed)? != 4
    {
        return Err(invalid());
    }
    let value = RegisteredPrivateSessionV04 {
        record: ApprovalUiRecordHandleV2::decode(&mut d, &mut ())
            .map_err(ProtocolError::malformed)?,
        transfer: PrivateSessionTransferV04::decode(&mut d, &mut ())
            .map_err(ProtocolError::malformed)?,
    };
    if encode_registered_private_session_v04(value)? != bytes {
        return Err(invalid());
    }
    Ok(value)
}

pub fn encode_private_session_authentication_v04(
    value: Option<&SignedUiAuthenticationSettlementV2>,
) -> Result<Vec<u8>, ProtocolError> {
    let mut e = minicbor::Encoder::new(Vec::new());
    if let Some(value) = value {
        if value.purpose() != UiAuthenticationPurposeV2::PrivateSessionV04 {
            return Err(invalid());
        }
        e.array(2)
            .and_then(|e| e.u16(1))
            .and_then(|e| {
                e.bytes(
                    &encode_signed_ui_authentication_settlement_v2(value)
                        .map_err(|_| minicbor::encode::Error::message("invalid"))?,
                )
            })
            .map_err(ProtocolError::malformed)?;
    } else {
        e.array(1)
            .and_then(|e| e.u16(0))
            .map_err(ProtocolError::malformed)?;
    }
    Ok(e.into_writer())
}

pub fn decode_private_session_authentication_v04(
    bytes: &[u8],
) -> Result<Option<SignedUiAuthenticationSettlementV2>, ProtocolError> {
    if bytes.len() > 16 * 1024 {
        return Err(invalid());
    }
    let mut d = minicbor::Decoder::new(bytes);
    let n = d.array().map_err(ProtocolError::malformed)?;
    let tag = d.u16().map_err(ProtocolError::malformed)?;
    let value = match (n, tag) {
        (Some(1), 0) => None,
        (Some(2), 1) => Some(decode_signed_ui_authentication_settlement_v2(
            d.bytes().map_err(ProtocolError::malformed)?,
        )?),
        _ => return Err(invalid()),
    };
    if encode_private_session_authentication_v04(value.as_ref())? != bytes {
        return Err(invalid());
    }
    Ok(value)
}

fn invalid() -> ProtocolError {
    ProtocolError::stable(crate::StableCode::ProtocolMalformedCbor)
}

pub fn decode_private_session_begin_v04(
    bytes: &[u8],
) -> Result<PrivateSessionTransferV04, ProtocolError> {
    if bytes.len() > 128 {
        return Err(invalid());
    }
    let mut d = minicbor::Decoder::new(bytes);
    if d.array().map_err(ProtocolError::malformed)? != Some(2)
        || d.u16().map_err(ProtocolError::malformed)? != 4
    {
        return Err(invalid());
    }
    let t = PrivateSessionTransferV04::decode(&mut d, &mut ()).map_err(ProtocolError::malformed)?;
    if encode_private_session_begin_v04(t)? != bytes {
        return Err(invalid());
    }
    Ok(t)
}

pub fn encode_private_session_begin_v04(
    t: PrivateSessionTransferV04,
) -> Result<Vec<u8>, ProtocolError> {
    let mut e = minicbor::Encoder::new(Vec::new());
    e.array(2)
        .and_then(|e| e.u16(4))
        .map_err(ProtocolError::malformed)?;
    t.encode(&mut e, &mut ())
        .map_err(ProtocolError::malformed)?;
    Ok(e.into_writer())
}

pub fn decode_private_session_finish_v04(
    bytes: &[u8],
) -> Result<(PrivateSessionTransferV04, BrowserWebAuthnAssertionV2), ProtocolError> {
    if bytes.len() > 64 * 1024 {
        return Err(invalid());
    }
    let mut d = minicbor::Decoder::new(bytes);
    if d.array().map_err(ProtocolError::malformed)? != Some(3)
        || d.u16().map_err(ProtocolError::malformed)? != 4
    {
        return Err(invalid());
    }
    let t = PrivateSessionTransferV04::decode(&mut d, &mut ()).map_err(ProtocolError::malformed)?;
    if d.array().map_err(ProtocolError::malformed)? != Some(5) {
        return Err(invalid());
    }
    let mut fields = Vec::new();
    for _ in 0..5 {
        fields.push(d.bytes().map_err(ProtocolError::malformed)?);
    }
    let mut e = minicbor::Encoder::new(Vec::new());
    e.array(3)
        .and_then(|e| e.u16(4))
        .map_err(ProtocolError::malformed)?;
    t.encode(&mut e, &mut ())
        .map_err(ProtocolError::malformed)?;
    e.array(5).map_err(ProtocolError::malformed)?;
    for field in &fields {
        e.bytes(field).map_err(ProtocolError::malformed)?;
    }
    if zeroize::Zeroizing::new(e.into_writer()).as_slice() != bytes {
        return Err(invalid());
    }
    let mut it = fields.into_iter();
    Ok((
        t,
        BrowserWebAuthnAssertionV2::new(
            it.next().ok_or_else(invalid)?.to_vec(),
            it.next().ok_or_else(invalid)?.to_vec(),
            it.next().ok_or_else(invalid)?.to_vec(),
            it.next().ok_or_else(invalid)?.to_vec(),
            it.next().ok_or_else(invalid)?.to_vec(),
        )?,
    ))
}

pub fn encode_private_session_options_v04(options: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    if options.is_empty() || options.len() > 8192 {
        return Err(invalid());
    }
    let mut e = minicbor::Encoder::new(Vec::new());
    e.array(2)
        .and_then(|e| e.u16(4))
        .and_then(|e| e.bytes(options))
        .map_err(ProtocolError::malformed)?;
    Ok(e.into_writer())
}

pub fn encode_private_session_browser_v04(
    browser: PrivateSessionBrowserCapabilityV04,
) -> Result<Vec<u8>, ProtocolError> {
    let mut e = minicbor::Encoder::new(Vec::new());
    e.array(2)
        .and_then(|e| e.u16(4))
        .map_err(ProtocolError::malformed)?;
    browser
        .encode(&mut e, &mut ())
        .map_err(ProtocolError::malformed)?;
    Ok(e.into_writer())
}

pub fn decode_private_session_browser_v04(
    bytes: &[u8],
) -> Result<PrivateSessionBrowserCapabilityV04, ProtocolError> {
    if bytes.len() > 128 {
        return Err(invalid());
    }
    let mut d = minicbor::Decoder::new(bytes);
    if d.array().map_err(ProtocolError::malformed)? != Some(2)
        || d.u16().map_err(ProtocolError::malformed)? != 4
    {
        return Err(invalid());
    }
    let cap = PrivateSessionBrowserCapabilityV04::decode(&mut d, &mut ())
        .map_err(ProtocolError::malformed)?;
    if encode_private_session_browser_v04(cap)? != bytes {
        return Err(invalid());
    }
    Ok(cap)
}

pub fn encode_private_session_handoff_v04(
    transfer: Option<ApprovalDisplayAuthenticationTransferCapabilityV2>,
) -> Result<Vec<u8>, ProtocolError> {
    let mut e = minicbor::Encoder::new(Vec::new());
    e.array(2)
        .and_then(|e| e.u16(4))
        .map_err(ProtocolError::malformed)?;
    if let Some(t) = transfer {
        t.encode(&mut e, &mut ())
            .map_err(ProtocolError::malformed)?;
    } else {
        e.null().map_err(ProtocolError::malformed)?;
    }
    Ok(e.into_writer())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn private_session_wire_is_canonical_bounded_and_role_separated() {
        let record = ApprovalUiRecordHandleV2::from_authority_entropy([1; 32]).unwrap();
        let transfer = PrivateSessionTransferV04::from_authority_entropy([2; 32]).unwrap();
        let r = RegisteredPrivateSessionV04 { record, transfer };
        let bytes = encode_registered_private_session_v04(r).unwrap();
        assert_eq!(decode_registered_private_session_v04(&bytes).unwrap(), r);
        let mut tailed = bytes.clone();
        tailed.push(0);
        assert!(decode_registered_private_session_v04(&tailed).is_err());
        let begin = encode_private_session_begin_v04(transfer).unwrap();
        assert_eq!(decode_private_session_begin_v04(&begin).unwrap(), transfer);
        assert!(decode_private_session_begin_v04(&[0; 129]).is_err());
        for operation in [
            ApprovalServiceOperationV2::GetPrivateSessionAuthenticationV04 { record },
            ApprovalServiceOperationV2::AttachPrivateApprovalV04 {
                session: record,
                approval: ToolApprovalRecordHandleV2::from_authority_entropy([3; 32]).unwrap(),
                root: Digest32V2::new([4; 32]),
            },
            // Without a response contract approvald applied the attachment but
            // could not answer, so kerneld saw every delivery as unavailable.
            ApprovalServiceOperationV2::AttachPrivatePublicationV04 {
                session: record,
                publication: super::super::PrivatePublicationV04::new(
                    super::super::DurableTaskIdV2::new([8; 32]),
                    super::super::DurableRunIdV2::new([9; 32]),
                    Digest32V2::new([10; 32]),
                    super::super::BootIdV2::new([11; 32]),
                    super::super::DurableReleaseIdV2::new([12; 32]),
                    Digest32V2::new([13; 32]),
                    Digest32V2::new([14; 32]),
                    Digest32V2::new([15; 32]),
                    Digest32V2::new([16; 32]),
                    Digest32V2::new([17; 32]),
                    Digest32V2::new([18; 32]),
                )
                .unwrap(),
            },
        ] {
            let tag = operation.tag();
            let request = ApprovalServiceRequestV2::new(
                RequestIdV2::new([5; 16]),
                UnixMillisV2::new(99),
                operation,
            )
            .unwrap();
            let bytes = encode_approval_service_request_v2(&request).unwrap();
            assert!(kernel_service_operation_has_error_contract_v2(
                EndpointRoleV2::KernelApproval,
                tag
            ));
            assert!(KernelServiceApplicationResponseV2::success(
                EndpointRoleV2::KernelApproval,
                request.request_id(),
                tag,
                vec![0x80]
            )
            .is_ok());
            assert_eq!(
                decode_approval_service_request_v2(&bytes, EndpointRoleV2::KernelApproval, tag)
                    .unwrap(),
                request
            );
            for role in [
                EndpointRoleV2::AgentApproval,
                EndpointRoleV2::IngressApproval,
                EndpointRoleV2::ApprovalAdmin,
            ] {
                assert!(decode_approval_service_request_v2(&bytes, role, tag).is_err());
            }
        }
        let op = KernelIngressOperationV2::OpenPrivateSessionV04(
            GetTaskAuthorizationContextRequestV2::new(
                IngressUiAuthorizationHandleV2::from_authority_entropy([6; 32]).unwrap(),
                None,
            ),
        );
        let request = KernelServiceApplicationRequestV2::new(
            EndpointRoleV2::IngressKernel,
            RequestIdV2::new([7; 16]),
            UnixMillisV2::new(99),
            KernelServiceOperationV2::ingress(op),
        )
        .unwrap();
        assert!(encode_kernel_service_application_request_v2(&request).is_ok());
        assert!(kernel_service_operation_has_error_contract_v2(
            EndpointRoleV2::IngressKernel,
            57
        ));
        assert!(!kernel_service_operation_has_error_contract_v2(
            EndpointRoleV2::AgentKernel,
            57
        ));
    }

    #[test]
    fn private_session_http_does_not_accept_agent_origins_urls_or_get_mutations() {
        fn request(path: &str, port: u16, origin: u16, form: bool) -> Vec<u8> {
            let content = if form {
                "application/x-www-form-urlencoded"
            } else {
                "application/cbor"
            };
            format!("POST {path} HTTP/1.1\r\nHost: localhost:{port}\r\nOrigin: http://localhost:{origin}\r\nContent-Type: {content}\r\nContent-Length: 1\r\n\r\nx").into_bytes()
        }
        for (path, port, origin, form, service) in [
            (
                "/v04/session/open",
                8767,
                8767,
                false,
                FixedHttpServiceV2::Ingress,
            ),
            (
                "/v04/session/accept",
                8766,
                8767,
                true,
                FixedHttpServiceV2::Approval,
            ),
            (
                "/v04/session/begin",
                8766,
                8766,
                false,
                FixedHttpServiceV2::Approval,
            ),
            (
                "/v04/session/finish",
                8766,
                8766,
                false,
                FixedHttpServiceV2::Approval,
            ),
            (
                "/v04/session/poll",
                8766,
                8766,
                false,
                FixedHttpServiceV2::Approval,
            ),
        ] {
            assert!(read_fixed_http_request_v2(
                &mut request(path, port, origin, form).as_slice(),
                service
            )
            .is_ok());
            for wrong in [8765, 8768, 8888] {
                assert!(read_fixed_http_request_v2(
                    &mut request(path, port, wrong, form).as_slice(),
                    service
                )
                .is_err());
            }
            for suffix in ["?token=secret", "#secret"] {
                assert!(read_fixed_http_request_v2(
                    &mut request(&format!("{path}{suffix}"), port, origin, form).as_slice(),
                    service
                )
                .is_err());
            }
            assert!(read_fixed_http_request_v2(
                &mut format!("GET {path} HTTP/1.1\r\nHost: localhost:{port}\r\n\r\n").as_bytes(),
                service
            )
            .is_err());
        }
    }
}
