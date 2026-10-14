use savana_kernel_protocol::v2::*;

#[test]
fn final_release_capsule_checks_actual_bytes_destination_and_evidence_against_core() {
    check_release_capsule(false);
}

#[test]
fn final_result_release_capsule_checks_actual_bytes_destination_and_evidence_against_core() {
    check_release_capsule(true);
}

fn check_release_capsule(result: bool) {
    use sha2::{Digest as _, Sha256};
    let d = |n| Digest32V2::new([n; 32]);
    type Builder = fn(
        &BusinessProfileV2,
        &str,
        Digest32V2,
        Digest32V2,
        &[u8],
    ) -> Result<BusinessRequestV2, BusinessCodecErrorV2>;
    let (profile, build): (BusinessProfileV2, Builder) = if result {
        (
            final_result_release_business_profile_v04(d(1), d(2)).unwrap(),
            final_result_release_business_request_v04,
        )
    } else {
        (
            final_release_business_profile_v2(d(1), d(2)).unwrap(),
            final_release_business_request_v2,
        )
    };
    let request = build(&profile, "release-1", d(3), d(4), b"vault bytes").unwrap();
    let action = request.action_alternative(d(5)).unwrap();
    let content = ActionContentV2::new(
        d(6),
        1,
        1,
        0,
        action.clone(),
        1,
        request.payload_digest(),
        d(7),
        d(8),
        d(9),
        d(10),
        1,
    )
    .unwrap();
    let capsule = TaskExecutionPayloadV2::new(content.clone(), request).unwrap();
    let mut h = Sha256::new();
    h.update(b"SAVANA_FINAL_RELEASE_PAYLOAD_V2\0");
    h.update(11u64.to_be_bytes());
    h.update(b"vault bytes");
    let payload_digest = Digest32V2::new(h.finalize().into());
    let core = |payload, destination, evidence| {
        let binding = FinalReleaseSemanticBindingV2::from_nonzero_components(
            DurableReleaseIdV2::new([11; 32]),
            d(12),
            d(13),
            payload,
            evidence,
            d(14),
            destination,
            d(15),
            d(16),
            d(17),
            d(18),
        )
        .unwrap();
        DispatchCoreV2::new(
            d(19),
            d(20),
            1,
            1,
            DurableTaskIdV2::new([21; 32]),
            DurableRunIdV2::new([22; 32]),
            Nonce32V2::new([23; 32]),
            DispatchSubjectV2::final_release(binding, d(24)).unwrap(),
            ExecutorIdentityV2::new([17; 32]),
            HpkeX25519KeyIdV2::new([26; 32]),
            d(27),
            UnixMillisV2::new(100),
        )
        .unwrap()
        .with_task_binding(
            DispatchTaskBindingV2::new(action_content_digest_v2(&content).unwrap(), d(28), d(29))
                .unwrap(),
        )
    };
    assert!(capsule
        .check_core(&core(payload_digest, action.destination_digest(), d(7)))
        .is_ok());
    let exact = core(payload_digest, action.destination_digest(), d(7));
    let bytes = exact.canonical_bytes().unwrap();
    assert_eq!(DispatchCoreV2::from_canonical_bytes(&bytes).unwrap(), exact);
    assert!(DispatchCoreV2::from_canonical_bytes(&[bytes.as_slice(), &[0]].concat()).is_err());
    for changed in [
        core(d(99), action.destination_digest(), d(7)),
        core(payload_digest, d(99), d(7)),
        core(payload_digest, action.destination_digest(), d(99)),
    ] {
        assert!(capsule.check_core(&changed).is_err());
    }
}

#[test]
fn final_result_codec_cannot_reuse_original_input_namespace_or_profile() {
    let d = |n| Digest32V2::new([n; 32]);
    let profile = final_result_release_business_profile_v04(d(1), d(2)).unwrap();
    let old = final_release_business_profile_v2(d(1), d(2)).unwrap();
    let task = DurableTaskIdV2::new([1; 32]);
    let resource = fused_final_result_resource_v04(task, 2, d(3)).unwrap();
    assert_ne!(
        resource,
        fused_final_result_resource_v04(task, 3, d(3)).unwrap()
    );
    assert_ne!(
        resource,
        fused_final_result_resource_v04(task, 2, d(4)).unwrap()
    );
    assert_ne!(
        resource,
        fused_final_result_resource_v04(DurableTaskIdV2::new([2; 32]), 2, d(3)).unwrap()
    );
    assert!(fused_final_result_resource_v04(task, 0, d(3)).is_err());
    assert!(final_result_release_business_request_v04(&old, "r1", resource, d(4), b"x").is_err());
    assert!(final_release_business_request_v2(&profile, "r1", resource, d(4), b"x").is_err());
    for payload in [
        vec![],
        b"private\0bytes".to_vec(),
        vec![0xff; MAX_FINAL_RELEASE_BUSINESS_PAYLOAD_BYTES_V2],
    ] {
        let request =
            final_result_release_business_request_v04(&profile, "r1", resource, d(4), &payload)
                .unwrap();
        let delivery = decode_final_result_release_delivery_v04(&request.canonical_json()).unwrap();
        assert_eq!(delivery.resource(), resource);
        assert_eq!(delivery.turn_binding(), d(4));
        assert_eq!(delivery.payload(), payload);
        assert!(decode_final_release_delivery_v2(&request.canonical_json()).is_err());
        let text = String::from_utf8(request.canonical_json()).unwrap();
        for changed in [
            text.replace("result:", "input:"),
            text.replace("/savana/final-result-release", "/savana/final-release"),
            text.replace("\"body\":{", "\"body\":{\"extra\":true,"),
            text.replace("POST", "GET"),
        ] {
            assert!(decode_final_result_release_delivery_v04(changed.as_bytes()).is_err());
        }
    }
    assert!(final_result_release_business_request_v04(
        &profile,
        "r1",
        resource,
        d(4),
        &vec![0; MAX_FINAL_RELEASE_BUSINESS_PAYLOAD_BYTES_V2 + 1]
    )
    .is_err());
}

#[test]
fn closed_final_release_names_original_input_and_exact_application_turn() {
    let d = |n| Digest32V2::new([n; 32]);
    let profile = final_release_business_profile_v2(d(1), d(2)).unwrap();
    let request =
        final_release_business_request_v2(&profile, "release-1", d(3), d(4), b"private\0bytes")
            .unwrap();
    let delivery = decode_final_release_delivery_v2(&request.canonical_json()).unwrap();
    assert_eq!(delivery.source_input_digest(), d(3));
    assert_eq!(delivery.turn_binding(), d(4));
    assert_eq!(delivery.payload(), b"private\0bytes");
    assert_eq!(delivery.request_id(), "release-1");
    assert_eq!(request.profile().effect(), TaskEffectV2::FinalRelease);
    assert_eq!(request.magnitude(), 1);
    assert!(!format!("{delivery:?}").contains("private"));
    let source = String::from_utf8(request.canonical_json()).unwrap();
    for changed in [
        source.replace("POST", "GET"),
        source.replace("/savana/final-release", "/other"),
        source.replace("input:", "file:"),
        source.replace("application-turn:", "user:"),
        source.replace("\"body\":{", "\"body\":{\"extra\":true,"),
        source.replace(
            "\"method\":\"POST\"",
            "\"method\":\"POST\",\"method\":\"POST\"",
        ),
        source.replace("cHJpdmF0ZQBieXRlcw", "cHJpdmF0ZQBieXRlcw=="),
        source.replace("cHJpdmF0ZQBieXRlcw", "cHJpdmF0ZQBieXRlcx"),
    ] {
        assert!(decode_final_release_delivery_v2(changed.as_bytes()).is_err());
    }
    assert!(final_release_business_request_v2(&profile, "release-1", d(0), d(4), b"x").is_err());
    assert!(final_release_business_request_v2(&profile, "release-1", d(3), d(0), b"x").is_err());
    assert!(final_release_business_request_v2(
        &profile,
        "release-1",
        d(3),
        d(4),
        &vec![1; MAX_FINAL_RELEASE_BUSINESS_PAYLOAD_BYTES_V2 + 1]
    )
    .is_err());
    for payload in [
        vec![],
        vec![0xff; MAX_FINAL_RELEASE_BUSINESS_PAYLOAD_BYTES_V2],
    ] {
        let request =
            final_release_business_request_v2(&profile, "release-2", d(3), d(4), &payload).unwrap();
        assert_eq!(
            decode_final_release_delivery_v2(&request.canonical_json())
                .unwrap()
                .payload(),
            payload
        );
    }
}
