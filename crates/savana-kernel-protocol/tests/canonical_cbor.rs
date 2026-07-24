use savana_kernel_protocol::{
    decode_client_message, decode_server_message, encode_client_message, encode_server_message,
    BootId, ClientFinishV1, ClientId, ClientMessageV1, Digest32, HandshakeAcceptedV1, HardLimits,
    HealthSnapshotV1, KeyId, OperationV1, ProtocolVersion, RequestEnvelopeV1, RequestId,
    ResponseBodyV1, ResponseEnvelopeV1, ResponsePayloadV1, ServerMessageV1, Signature64,
    StableCode, UnixMillis,
};

mod support;

#[test]
fn client_canonical_round_trip_is_byte_exact() {
    let message = ClientMessageV1::Hello(support::client_hello());
    let encoded = encode_client_message(&message).unwrap();
    let decoded = decode_client_message(&encoded, &support::compiled_effective_limits()).unwrap();
    assert_eq!(decoded, message);
    assert_eq!(encode_client_message(&decoded).unwrap(), encoded);
}

#[test]
fn server_canonical_round_trip_is_byte_exact() {
    let message = support::server_message();
    let encoded = encode_server_message(&message).unwrap();
    let decoded = decode_server_message(&encoded, &support::compiled_effective_limits()).unwrap();
    assert_eq!(decoded, message);
    assert_eq!(encode_server_message(&decoded).unwrap(), encoded);
}

#[test]
fn every_closed_client_variant_round_trips() {
    let messages = [
        ClientMessageV1::Hello(support::client_hello()),
        ClientMessageV1::Finish(ClientFinishV1 {
            transcript_digest: Digest32::new([0x61; 32]),
            signature: Signature64::new([0x62; 64]),
        }),
        ClientMessageV1::Request(RequestEnvelopeV1 {
            version: ProtocolVersion::new(1, 0),
            request_id: RequestId::new([0x63; 16]),
            deadline_unix_ms: UnixMillis::new(1_234),
            operation: OperationV1::Health,
        }),
    ];
    for message in messages {
        let encoded = encode_client_message(&message).unwrap();
        assert_eq!(
            decode_client_message(&encoded, &support::compiled_effective_limits()).unwrap(),
            message
        );
    }
}

#[test]
fn every_closed_server_variant_round_trips() {
    let identity = support::server_identity();
    let messages = [
        support::server_message(),
        ServerMessageV1::Accepted(HandshakeAcceptedV1 {
            boot_id: BootId::new([0x71; 32]),
            protocol: ProtocolVersion::new(1, 0),
        }),
        ServerMessageV1::Response(ResponseEnvelopeV1 {
            version: ProtocolVersion::new(1, 0),
            request_id: RequestId::new([0x72; 16]),
            body: ResponseBodyV1::Ok(ResponsePayloadV1::Health(HealthSnapshotV1 {
                ready: false,
                identity,
                last_error: Some(StableCode::KernelUnavailable),
            })),
        }),
        ServerMessageV1::Response(ResponseEnvelopeV1 {
            version: ProtocolVersion::new(1, 0),
            request_id: RequestId::new([0x73; 16]),
            body: ResponseBodyV1::Err(StableCode::DeadlineExceeded),
        }),
    ];
    for message in messages {
        let encoded = encode_server_message(&message).unwrap();
        assert_eq!(
            decode_server_message(&encoded, &support::compiled_effective_limits()).unwrap(),
            message
        );
    }
}

#[test]
fn health_without_error_encodes_explicit_null_and_round_trips() {
    let message = ServerMessageV1::Response(ResponseEnvelopeV1 {
        version: ProtocolVersion::new(1, 0),
        request_id: RequestId::new([0x74; 16]),
        body: ResponseBodyV1::Ok(ResponsePayloadV1::Health(HealthSnapshotV1 {
            ready: false,
            identity: support::server_identity(),
            last_error: None,
        })),
    });
    let encoded = encode_server_message(&message).unwrap();
    assert_eq!(encoded.last(), Some(&0xf6));
    assert_eq!(
        decode_server_message(&encoded, &support::compiled_effective_limits()).unwrap(),
        message
    );
}

#[test]
fn rejects_invalid_supported_version_sets() {
    let cases = [
        support::encoded_hello_with_versions(&[]),
        support::encoded_hello_with_versions(&[
            ProtocolVersion::new(1, 0),
            ProtocolVersion::new(1, 0),
        ]),
        support::encoded_hello_with_versions(
            &(0..17)
                .map(|minor| ProtocolVersion::new(1, minor))
                .collect::<Vec<_>>(),
        ),
    ];
    for encoded in cases {
        let error =
            decode_client_message(&encoded, &support::compiled_effective_limits()).unwrap_err();
        assert_eq!(error.code(), StableCode::ProtocolMalformedCbor);
    }
}

#[test]
fn bounded_identifiers_reject_invalid_text() {
    assert_eq!(
        ClientId::try_from("").unwrap_err().code(),
        StableCode::ProtocolMalformedCbor
    );
    assert_eq!(
        KeyId::try_from("bad\0key").unwrap_err().code(),
        StableCode::ProtocolMalformedCbor
    );
    assert_eq!(
        ClientId::try_from("x".repeat(129)).unwrap_err().code(),
        StableCode::ProtocolMalformedCbor
    );
}

#[test]
fn rejects_non_shortest_integer_encoding() {
    let canonical =
        encode_client_message(&ClientMessageV1::Hello(support::client_hello())).unwrap();
    let non_shortest_zero = support::rewrite_protocol_minor_as_non_shortest(canonical);
    let error = decode_client_message(&non_shortest_zero, &support::compiled_effective_limits())
        .unwrap_err();
    assert_eq!(error.code(), StableCode::ProtocolNonCanonicalCbor);
}

#[test]
fn rejects_excessive_depth() {
    let mut nested = vec![0x81; HardLimits::COMPILED.cbor_depth() as usize + 1];
    nested.push(0xf6);
    let error = decode_client_message(&nested, &support::compiled_effective_limits()).unwrap_err();
    assert_eq!(error.code(), StableCode::ProtocolNestingTooDeep);
}

#[test]
fn rejects_declared_array_length_of_u64_max() {
    let mut encoded = vec![0x9b];
    encoded.extend_from_slice(&u64::MAX.to_be_bytes());
    let error = decode_client_message(&encoded, &support::compiled_effective_limits()).unwrap_err();
    assert_eq!(error.code(), StableCode::ProtocolFrameTooLarge);
}

#[test]
fn rejects_indefinite_array() {
    let error =
        decode_client_message(&[0x9f, 0xff], &support::compiled_effective_limits()).unwrap_err();
    assert_eq!(error.code(), StableCode::ProtocolMalformedCbor);
}

#[test]
fn rejects_trailing_bytes() {
    let mut encoded =
        encode_client_message(&ClientMessageV1::Hello(support::client_hello())).unwrap();
    encoded.push(0xf6);
    let error = decode_client_message(&encoded, &support::compiled_effective_limits()).unwrap_err();
    assert_eq!(error.code(), StableCode::ProtocolMalformedCbor);
}

#[test]
fn rejects_unknown_top_level_tag() {
    let cases: &[&[u8]] = &[
        &[0x82, 0x18, 0x63, 0x80],
        &[
            0x82, 0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x80,
        ],
    ];
    for encoded in cases {
        let error =
            decode_client_message(encoded, &support::compiled_effective_limits()).unwrap_err();
        assert_eq!(error.code(), StableCode::ProtocolUnknownOperation);
    }
}

#[test]
fn rejects_unsupported_cbor_types() {
    let cases: &[(&str, &[u8])] = &[
        ("map", &[0xa0]),
        ("tag", &[0xc0, 0xf6]),
        ("float", &[0xf9, 0x00, 0x00]),
        ("simple", &[0xf8, 0x00]),
    ];
    for (name, bytes) in cases {
        let error =
            decode_client_message(bytes, &support::compiled_effective_limits()).unwrap_err();
        assert_eq!(
            error.code(),
            StableCode::ProtocolMalformedCbor,
            "{name} must be rejected"
        );
    }
}

#[test]
fn rejects_wrong_fixed_array_length() {
    let error = decode_client_message(
        &[0x83, 0x00, 0x80, 0xf6],
        &support::compiled_effective_limits(),
    )
    .unwrap_err();
    assert_eq!(error.code(), StableCode::ProtocolMalformedCbor);
}

#[test]
fn rejects_unknown_requested_mode() {
    let mut small_tag =
        encode_client_message(&ClientMessageV1::Hello(support::client_hello())).unwrap();
    let last = small_tag
        .last_mut()
        .expect("fixture has requested-mode member");
    assert_eq!(*last, 0);
    *last = 2;
    let mut wide_tag =
        encode_client_message(&ClientMessageV1::Hello(support::client_hello())).unwrap();
    assert_eq!(wide_tag.pop(), Some(0));
    wide_tag.extend_from_slice(&[0x19, 0x01, 0x00]);
    for encoded in [small_tag, wide_tag] {
        let error =
            decode_client_message(&encoded, &support::compiled_effective_limits()).unwrap_err();
        assert_eq!(error.code(), StableCode::ProtocolUnknownOperation);
    }
}
