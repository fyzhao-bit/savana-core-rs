use savana_kernel_protocol::v2::*;

#[test]
fn final_release_capsule_checks_actual_bytes_destination_and_evidence_against_core() {
    use sha2::{Digest as _, Sha256};
    let d = |n| Digest32V2::new([n; 32]);
    let request = final_release_business_request_v2(
        &final_release_business_profile_v2(d(1), d(2)).unwrap(),
        "release-1",
        d(3),
        d(4),
        b"vault bytes",
    )
    .unwrap();
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
    for changed in [
        core(d(99), action.destination_digest(), d(7)),
        core(payload_digest, d(99), d(7)),
        core(payload_digest, action.destination_digest(), d(99)),
    ] {
        assert!(capsule.check_core(&changed).is_err());
    }
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
