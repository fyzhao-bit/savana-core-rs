use savana_platform_identity::{
    verify_native_peer_v2, BoundedIdentityStringV2, ExpectedNativePeerV2, NativeIdentityErrorV2,
    NativePeerMeasurementV2,
};

#[test]
fn measurements_are_nonzero_bounded_and_debug_redacted() {
    let role = BoundedIdentityStringV2::new("agent-kernel".to_owned()).unwrap();
    let observed = NativePeerMeasurementV2::linux(501, 20, 42, 99, [7; 32]).unwrap();
    assert_eq!(
        format!("{observed:?}"),
        "NativePeerMeasurementV2::Linux(<redacted>)"
    );
    assert!(NativePeerMeasurementV2::linux(501, 20, 0, 99, [7; 32]).is_err());
    assert!(NativePeerMeasurementV2::linux(501, 20, 42, 0, [7; 32]).is_err());
    assert!(NativePeerMeasurementV2::linux(501, 20, 42, 99, [0; 32]).is_err());
    assert!(BoundedIdentityStringV2::new("bad role".to_owned()).is_err());

    let expected = ExpectedNativePeerV2::linux(role.clone(), 501, 20, [7; 32]).unwrap();
    verify_native_peer_v2(&expected, &role, &observed).unwrap();
}

#[test]
fn expected_and_observed_comparison_rejects_each_security_field() {
    let role = BoundedIdentityStringV2::new("agent-kernel".to_owned()).unwrap();
    let other_role = BoundedIdentityStringV2::new("ingress-kernel".to_owned()).unwrap();
    let expected = ExpectedNativePeerV2::linux(role.clone(), 501, 20, [7; 32]).unwrap();

    for observed in [
        NativePeerMeasurementV2::linux(502, 20, 42, 99, [7; 32]).unwrap(),
        NativePeerMeasurementV2::linux(501, 21, 42, 99, [7; 32]).unwrap(),
        NativePeerMeasurementV2::linux(501, 20, 42, 99, [8; 32]).unwrap(),
    ] {
        assert_eq!(
            verify_native_peer_v2(&expected, &role, &observed),
            Err(NativeIdentityErrorV2::IdentityMismatch)
        );
    }
    assert_eq!(
        verify_native_peer_v2(
            &expected,
            &other_role,
            &NativePeerMeasurementV2::linux(501, 20, 42, 99, [7; 32]).unwrap()
        ),
        Err(NativeIdentityErrorV2::IdentityMismatch)
    );
}

#[test]
fn macos_comparison_rejects_each_locked_code_identity_field() {
    let role = BoundedIdentityStringV2::new("agent-kernel".to_owned()).unwrap();
    let bundle = BoundedIdentityStringV2::new("com.savana.agentd".to_owned()).unwrap();
    let team = BoundedIdentityStringV2::new("SAVANATEAM".to_owned()).unwrap();
    let expected = ExpectedNativePeerV2::macos(
        role.clone(),
        501,
        20,
        bundle.clone(),
        team.clone(),
        [1; 32],
        [2; 32],
        [3; 32],
    )
    .unwrap();
    let measurement = |euid, egid, bundle_id, team_id, code, requirement, entitlements| {
        NativePeerMeasurementV2::macos(
            [9; 32],
            euid,
            egid,
            bundle_id,
            team_id,
            code,
            requirement,
            entitlements,
        )
        .unwrap()
    };

    verify_native_peer_v2(
        &expected,
        &role,
        &measurement(
            501,
            20,
            bundle.clone(),
            team.clone(),
            [1; 32],
            [2; 32],
            [3; 32],
        ),
    )
    .unwrap();

    for observed in [
        measurement(
            502,
            20,
            bundle.clone(),
            team.clone(),
            [1; 32],
            [2; 32],
            [3; 32],
        ),
        measurement(
            501,
            21,
            bundle.clone(),
            team.clone(),
            [1; 32],
            [2; 32],
            [3; 32],
        ),
        measurement(
            501,
            20,
            BoundedIdentityStringV2::new("com.savana.ingressd".to_owned()).unwrap(),
            team.clone(),
            [1; 32],
            [2; 32],
            [3; 32],
        ),
        measurement(
            501,
            20,
            bundle.clone(),
            BoundedIdentityStringV2::new("OTHERTEAM".to_owned()).unwrap(),
            [1; 32],
            [2; 32],
            [3; 32],
        ),
        measurement(
            501,
            20,
            bundle.clone(),
            team.clone(),
            [4; 32],
            [2; 32],
            [3; 32],
        ),
        measurement(
            501,
            20,
            bundle.clone(),
            team.clone(),
            [1; 32],
            [4; 32],
            [3; 32],
        ),
        measurement(501, 20, bundle, team, [1; 32], [2; 32], [4; 32]),
    ] {
        assert_eq!(
            verify_native_peer_v2(&expected, &role, &observed),
            Err(NativeIdentityErrorV2::IdentityMismatch)
        );
    }
}

#[cfg(target_os = "macos")]
#[test]
fn macos_audit_token_parser_and_security_measurement_fail_closed() {
    use savana_platform_identity::{
        current_process_audit_token_v2, measure_macos_peer_v2, parse_macos_audit_token_v2,
    };

    let token = current_process_audit_token_v2().unwrap();
    let identity = parse_macos_audit_token_v2(token).unwrap();
    assert_eq!(identity.pid(), std::process::id());
    assert_eq!(identity.euid(), nix::unistd::geteuid().as_raw());
    assert_eq!(identity.egid(), nix::unistd::getegid().as_raw());

    match measure_macos_peer_v2(token) {
        Ok(NativePeerMeasurementV2::MacOs {
            audit_token,
            euid,
            egid,
            ..
        }) => {
            assert_eq!(audit_token, token);
            assert_eq!(euid, identity.euid());
            assert_eq!(egid, identity.egid());
        }
        Err(NativeIdentityErrorV2::CodeIdentityUnavailable) => {}
        other => panic!("unexpected macOS measurement result: {other:?}"),
    }
}

#[cfg(target_os = "macos")]
#[test]
fn macos_static_code_measurement_rejects_unsigned_files() {
    use std::io::Write as _;

    use savana_platform_identity::measure_macos_static_code_v2;

    let mut executable = tempfile::NamedTempFile::new().unwrap();
    executable.write_all(b"not signed Mach-O code").unwrap();
    executable.flush().unwrap();

    assert_eq!(
        measure_macos_static_code_v2(executable.path()),
        Err(NativeIdentityErrorV2::CodeIdentityUnavailable)
    );
}

#[cfg(target_os = "macos")]
#[test]
fn macos_current_service_pin_rejects_unlocked_identity() {
    use savana_platform_identity::pin_current_macos_service_v2;

    assert_eq!(
        pin_current_macos_service_v2(501, 20, [0; 32], [1; 32]).unwrap_err(),
        NativeIdentityErrorV2::InvalidMeasurement
    );
    assert_eq!(
        pin_current_macos_service_v2(501, 20, [1; 32], [0; 32]).unwrap_err(),
        NativeIdentityErrorV2::InvalidMeasurement
    );
}

#[cfg(target_os = "linux")]
#[test]
fn linux_measures_the_live_unix_peer_and_executable() {
    use std::io::Read as _;
    use std::os::unix::net::UnixStream;

    use sha2::{Digest as _, Sha256};

    let (left, mut right) = UnixStream::pair().unwrap();
    let pinned = savana_platform_identity::measure_linux_peer_v2(&left).unwrap();
    let observed = pinned.measurement();

    let executable = std::fs::read("/proc/self/exe").unwrap();
    let expected_digest: [u8; 32] = Sha256::digest(executable).into();
    assert_eq!(observed.executable_measurement(), Some(expected_digest));
    assert_eq!(observed.pid(), Some(std::process::id()));
    assert_ne!(observed.process_start_time(), Some(0));

    drop(left);
    drop(pinned);
    let mut byte = [0; 1];
    assert_eq!(right.read(&mut byte).unwrap(), 0);
}
