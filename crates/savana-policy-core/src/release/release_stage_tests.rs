use super::*;

use std::fs;
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};

use ed25519_dalek::{Signer, SigningKey};
use tempfile::TempDir;

#[test]
fn release_stage_holds_only_the_fixed_manifest_signature_and_executable_inodes() {
    let fixture = StageFixture::new();
    let stage = ReleaseStage::open_for_test(
        &fixture.stage,
        &fixture.executable,
        fixture.uid,
        fixture.gid,
    )
    .unwrap();

    assert_eq!(
        stage.manifest.identity,
        NodeIdentity::from_metadata(&fs::metadata(&fixture.manifest).unwrap())
    );
    assert_eq!(
        stage.signature.identity,
        NodeIdentity::from_metadata(&fs::metadata(&fixture.signature).unwrap())
    );
    assert_eq!(
        stage.executable.identity,
        NodeIdentity::from_metadata(&fs::metadata(&fixture.executable).unwrap())
    );
    assert_eq!(format!("{stage:?}"), "ReleaseStage(<descriptor-anchored>)");

    let wrong_current_exe = fixture.stage.join("bin/not-savana-kerneld");
    assert_eq!(
        ReleaseStage::open_for_test(&fixture.stage, &wrong_current_exe, fixture.uid, fixture.gid,)
            .unwrap_err()
            .code(),
        StableCode::IdentityReleaseMismatch
    );
}

#[test]
fn descriptor_anchored_verifier_authenticates_the_complete_signed_stage() {
    let (fixture, verifier) = StageFixture::signed();
    let stage = ReleaseStage::open_for_test(
        &fixture.stage,
        &fixture.executable,
        fixture.uid,
        fixture.gid,
    )
    .unwrap();

    let verified = verifier
        .verify_stage(&stage, UnixMillis::new(2_000))
        .unwrap();
    assert_eq!(verified.binary_digest(), hash_bytes(b"binary"));
    assert_eq!(verified.platform(), compiled_platform());
}

#[test]
fn descriptor_enumeration_rejects_a_stage_local_kernel_lock() {
    let (fixture, verifier) = StageFixture::signed();
    let stage_lock = fixture.stage.join("kernel-lock.json");
    fs::write(&stage_lock, b"not-authoritative").unwrap();
    set_mode(&stage_lock, 0o444);
    let stage = ReleaseStage::open_for_test(
        &fixture.stage,
        &fixture.executable,
        fixture.uid,
        fixture.gid,
    )
    .unwrap();

    assert_eq!(
        verifier
            .verify_stage(&stage, UnixMillis::new(2_000))
            .unwrap_err()
            .code(),
        StableCode::IdentityReleaseMismatch
    );
}

#[test]
fn descriptor_enumeration_rejects_missing_symlink_mode_and_hard_link_anomalies() {
    let (fixture, verifier) = StageFixture::signed();
    fs::remove_file(fixture.stage.join("policy/default-policy-v1.cbor")).unwrap();
    assert_stage_rejected(&fixture, &verifier);

    let (fixture, verifier) = StageFixture::signed();
    symlink("bin/savana-kerneld", fixture.stage.join("unexpected-link")).unwrap();
    assert_stage_rejected(&fixture, &verifier);

    let (fixture, verifier) = StageFixture::signed();
    set_mode(&fixture.stage.join("policy/default-policy-v1.cbor"), 0o644);
    assert_stage_rejected(&fixture, &verifier);

    let (fixture, verifier) = StageFixture::signed();
    fs::hard_link(
        fixture.stage.join("policy/default-policy-v1.cbor"),
        fixture._root.path().join("external-hard-link"),
    )
    .unwrap();
    assert_stage_rejected(&fixture, &verifier);
}

#[test]
fn descriptor_rechecks_reject_stage_and_manifest_pathname_replacement() {
    let (fixture, verifier) = StageFixture::signed();
    let stage = open_stage(&fixture);
    let moved_stage = fixture._root.path().join("moved-stage");
    fs::rename(&fixture.stage, &moved_stage).unwrap();
    fs::create_dir(&fixture.stage).unwrap();
    set_mode(&fixture.stage, 0o755);
    assert_eq!(
        verifier
            .verify_stage(&stage, UnixMillis::new(2_000))
            .unwrap_err()
            .code(),
        StableCode::IdentityReleaseMismatch
    );

    let (fixture, verifier) = StageFixture::signed();
    let stage = open_stage(&fixture);
    let old_manifest = fixture.manifest.with_extension("old");
    fs::rename(&fixture.manifest, &old_manifest).unwrap();
    fs::copy(&old_manifest, &fixture.manifest).unwrap();
    set_mode(&fixture.manifest, 0o444);
    assert_eq!(
        verifier
            .verify_stage(&stage, UnixMillis::new(2_000))
            .unwrap_err()
            .code(),
        StableCode::IdentityReleaseMismatch
    );
}

#[test]
fn release_stage_open_rejects_owner_mode_link_and_symlink_anomalies() {
    let fixture = StageFixture::new();
    set_mode(&fixture.stage, 0o775);
    assert_stage_open_rejected(&fixture, fixture.uid, fixture.gid);

    let fixture = StageFixture::new();
    set_mode(&fixture.manifest, 0o644);
    assert_stage_open_rejected(&fixture, fixture.uid, fixture.gid);

    let fixture = StageFixture::new();
    fs::hard_link(
        &fixture.signature,
        fixture._root.path().join("signature-hard-link"),
    )
    .unwrap();
    assert_stage_open_rejected(&fixture, fixture.uid, fixture.gid);

    let fixture = StageFixture::new();
    set_mode(&fixture.executable, 0o755);
    fs::remove_file(&fixture.executable).unwrap();
    symlink("../release/release-manifest-v1.cbor", &fixture.executable).unwrap();
    assert_stage_open_rejected(&fixture, fixture.uid, fixture.gid);

    let fixture = StageFixture::new();
    assert_stage_open_rejected(&fixture, fixture.uid.saturating_add(1), fixture.gid);
    assert_stage_open_rejected(&fixture, fixture.uid, fixture.gid.saturating_add(1));
}

#[test]
fn stage_payload_limits_are_inclusive_and_checked_before_payload_open() {
    let (fixture, _) = StageFixture::signed();
    let stage = open_stage(&fixture);
    let manifest = decode_manifest(&fs::read(&fixture.manifest).unwrap()).unwrap();
    for (relative_path, maximum) in [
        ("bin/savana-kerneld", MAXIMUM_DAEMON_EXECUTABLE_BYTES),
        (
            "installation/kernel-installation-profile-v1.cbor",
            MAXIMUM_INSTALLATION_PROFILE_BYTES,
        ),
        (
            "policy/default-policy-v1.cbor",
            MAXIMUM_DEFAULT_POLICY_BYTES,
        ),
        (
            "model/signed-model-manifest-v1.cbor",
            MAXIMUM_SIGNED_MODEL_MANIFEST_BYTES,
        ),
        ("model/assets/model.bin", MAXIMUM_MODEL_ASSET_BYTES),
        (compiled_platform().runtime_path(), MAXIMUM_RUNTIME_BYTES),
        (
            "approval/producer-registry-v1.cbor",
            MAXIMUM_OTHER_PAYLOAD_BYTES,
        ),
    ] {
        let mut at_limit = manifest.clone();
        payload_mut(&mut at_limit, relative_path).byte_length = maximum;
        assert!(validate_stage_payload_limits(&stage, &at_limit).is_ok());

        let mut above_limit = manifest.clone();
        payload_mut(&mut above_limit, relative_path).byte_length = maximum + 1;
        assert_eq!(
            validate_stage_payload_limits(&stage, &above_limit)
                .unwrap_err()
                .code(),
            StableCode::IdentityReleaseMismatch
        );
    }

    let mut zero_length = manifest.clone();
    payload_mut(&mut zero_length, "policy/default-policy-v1.cbor").byte_length = 0;
    assert_eq!(
        validate_stage_payload_limits(&stage, &zero_length)
            .unwrap_err()
            .code(),
        StableCode::IdentityReleaseMismatch
    );

    let mut wrong_signature_length = manifest;
    payload_mut(&mut wrong_signature_length, "policy/default-policy-v1.sig").byte_length = 63;
    assert_eq!(
        validate_stage_payload_limits(&stage, &wrong_signature_length)
            .unwrap_err()
            .code(),
        StableCode::IdentityReleaseMismatch
    );
}

#[test]
fn stage_model_subtotal_and_complete_total_use_checked_inclusive_addition() {
    let (fixture, _) = StageFixture::signed();
    let stage = open_stage(&fixture);
    let mut manifest = decode_manifest(&fs::read(&fixture.manifest).unwrap()).unwrap();
    manifest.payloads.push(ReleaseFileV1 {
        relative_path: "model/assets/second.bin".to_owned(),
        byte_length: MAXIMUM_MODEL_ASSET_BYTES,
        sha256: Digest32::new([0xa2; 32]),
    });
    payload_mut(&mut manifest, "model/assets/model.bin").byte_length = MAXIMUM_MODEL_ASSET_BYTES;
    assert!(validate_stage_payload_limits(&stage, &manifest).is_ok());

    manifest.payloads.push(ReleaseFileV1 {
        relative_path: "model/assets/third.bin".to_owned(),
        byte_length: 1,
        sha256: Digest32::new([0xa3; 32]),
    });
    assert_eq!(
        validate_stage_payload_limits(&stage, &manifest)
            .unwrap_err()
            .code(),
        StableCode::IdentityReleaseMismatch
    );

    let mut exact_total = decode_manifest(&fs::read(&fixture.manifest).unwrap()).unwrap();
    exact_total.payloads.push(ReleaseFileV1 {
        relative_path: "model/assets/second.bin".to_owned(),
        byte_length: MAXIMUM_MODEL_ASSET_BYTES,
        sha256: Digest32::new([0xa2; 32]),
    });
    for payload in &mut exact_total.payloads {
        payload.byte_length = if payload.relative_path == "policy/default-policy-v1.sig" {
            64
        } else {
            1
        };
    }
    payload_mut(&mut exact_total, "model/assets/model.bin").byte_length = MAXIMUM_MODEL_ASSET_BYTES;
    payload_mut(&mut exact_total, "model/assets/second.bin").byte_length =
        MAXIMUM_MODEL_ASSET_BYTES;
    payload_mut(&mut exact_total, compiled_platform().runtime_path()).byte_length =
        MAXIMUM_RUNTIME_BYTES;
    payload_mut(&mut exact_total, "bin/savana-kerneld").byte_length =
        MAXIMUM_DAEMON_EXECUTABLE_BYTES;
    payload_mut(&mut exact_total, "approval/producer-registry-v1.cbor").byte_length =
        MAXIMUM_OTHER_PAYLOAD_BYTES;
    let current_total = validate_stage_payload_limits(&stage, &exact_total).unwrap();
    let remaining = MAXIMUM_COMPLETE_STAGE_BYTES - current_total;
    payload_mut(&mut exact_total, "approval/ontology-v1.cbor").byte_length += remaining;
    assert_eq!(
        validate_stage_payload_limits(&stage, &exact_total).unwrap(),
        MAXIMUM_COMPLETE_STAGE_BYTES
    );
    payload_mut(&mut exact_total, "approval/ontology-v1.cbor").byte_length += 1;
    assert_eq!(
        validate_stage_payload_limits(&stage, &exact_total)
            .unwrap_err()
            .code(),
        StableCode::IdentityReleaseMismatch
    );
}

struct StageFixture {
    _root: TempDir,
    stage: PathBuf,
    manifest: PathBuf,
    signature: PathBuf,
    executable: PathBuf,
    uid: u32,
    gid: u32,
}

impl StageFixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let metadata = fs::metadata(root.path()).unwrap();
        let uid = metadata.uid();
        let gid = metadata.gid();
        let stage = fs::canonicalize(root.path()).unwrap().join("stage");
        let release = stage.join("release");
        let bin = stage.join("bin");
        fs::create_dir_all(&release).unwrap();
        fs::create_dir_all(&bin).unwrap();
        set_mode(&stage, 0o755);
        set_mode(&release, 0o755);
        set_mode(&bin, 0o755);

        let manifest = release.join("release-manifest-v1.cbor");
        let signature = release.join("release-manifest-v1.sig");
        let executable = bin.join("savana-kerneld");
        fs::write(&manifest, b"manifest").unwrap();
        fs::write(&signature, [0x51; 64]).unwrap();
        fs::write(&executable, b"binary").unwrap();
        set_mode(&manifest, 0o444);
        set_mode(&signature, 0o444);
        set_mode(&executable, 0o555);

        Self {
            _root: root,
            stage,
            manifest,
            signature,
            executable,
            uid,
            gid,
        }
    }

    fn signed() -> (Self, ReleaseVerifier) {
        let fixture = Self::new();
        let release_key = SigningKey::from_bytes(&[0x51; 32]);
        let daemon_key = SigningKey::from_bytes(&[0x61; 32]);
        let client_key = SigningKey::from_bytes(&[0x62; 32]);
        let policy_key = SigningKey::from_bytes(&[0x42; 32]);
        let platform = compiled_platform();
        let profile = KernelInstallationProfileV1 {
            schema_version: 1,
            installation_id: Digest32::new([0x71; 32]),
            platform,
            daemon_identity: InstallationPublicKeyV1 {
                key_id: KeyId::try_from("daemon-key").unwrap(),
                public_key: daemon_key.verifying_key().to_bytes(),
            },
            daemon_clients: vec![InstallationClientV1 {
                client_id: ClientId::try_from("jarvis-client").unwrap(),
                key_id: KeyId::try_from("jarvis-key").unwrap(),
                public_key: client_key.verifying_key().to_bytes(),
                role: InstallationClientRoleV1::JarvisKernelClient,
                peer_uid: 1_001,
                peer_gid: 1_003,
            }],
            policy_trust_roots: vec![PolicyTrustRootV1 {
                key_id: KeyId::try_from("policy-root").unwrap(),
                public_key: policy_key.verifying_key().to_bytes(),
                epoch: 3,
                revoked: false,
            }],
            daemon_uid: 1_002,
            daemon_gid: 1_002,
            jarvis_uid: 1_001,
            socket_path: platform.socket_path().to_owned(),
            selected_policy_path: platform.selected_policy_path().to_owned(),
            selected_policy_signature_path: platform.selected_policy_signature_path().to_owned(),
            socket_parent_mode: 0o750,
            socket_mode: 0o660,
        };
        let profile_bytes = encode_profile(&profile).unwrap();
        let runtime = platform.runtime_path();
        let payload_bytes = vec![
            ("bin/savana-kerneld", b"binary".to_vec()),
            ("policy/default-policy-v1.cbor", b"default-policy".to_vec()),
            ("policy/default-policy-v1.sig", vec![0x81; 64]),
            (
                "approval/producer-registry-v1.cbor",
                b"producer-registry".to_vec(),
            ),
            ("approval/ontology-v1.cbor", b"ontology".to_vec()),
            (
                "approval/approval-key-set-v1.cbor",
                b"approval-keys".to_vec(),
            ),
            (
                "model/signed-model-manifest-v1.cbor",
                b"model-manifest".to_vec(),
            ),
            (
                "installation/kernel-installation-profile-v1.cbor",
                profile_bytes.clone(),
            ),
            (runtime, b"onnx-runtime".to_vec()),
            ("model/assets/model.bin", b"model-asset".to_vec()),
        ];
        for (relative, bytes) in &payload_bytes {
            let path = fixture.stage.join(relative);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            set_all_directory_modes(&fixture.stage, path.parent().unwrap());
            if path.exists() {
                set_mode(&path, 0o644);
            }
            fs::write(&path, bytes).unwrap();
            set_mode(
                &path,
                if *relative == "bin/savana-kerneld" {
                    0o555
                } else {
                    0o444
                },
            );
        }
        let mut payloads = payload_bytes
            .iter()
            .map(|(relative_path, bytes)| ReleaseFileV1 {
                relative_path: (*relative_path).to_owned(),
                byte_length: bytes.len() as u64,
                sha256: hash_bytes(bytes),
            })
            .collect::<Vec<_>>();
        payloads
            .sort_by(|left, right| canonical_text_cmp(&left.relative_path, &right.relative_path));
        let mut manifest = ReleaseManifestV1 {
            schema_version: 1,
            release_version: "1.0.0".to_owned(),
            release_sequence: 1,
            release_target_id: Digest32::new([0x01; 32]),
            source_commit: "a".repeat(40),
            signing_key_id: KeyId::try_from("release-root").unwrap(),
            binary_sha256: hash_bytes(b"binary"),
            cargo_lock_sha256: Digest32::new([0xc1; 32]),
            rust_toolchain_sha256: Digest32::new([0xc2; 32]),
            protocol_major: PROTOCOL_MAJOR,
            minimum_minor: 0,
            maximum_minor: PROTOCOL_MINOR,
            supported_policy_schemas: vec![1],
            supported_model_schemas: vec![1],
            policy_trust_roots_digest: hash_bytes(
                &encode_policy_roots(&profile.policy_trust_roots).unwrap(),
            ),
            minimum_policy_version: 1,
            model_manifest_digest: Digest32::new([0xd1; 32]),
            producer_registry_digest: Digest32::new([0xd2; 32]),
            ontology_digest: Digest32::new([0xd3; 32]),
            approval_key_set_digest: Digest32::new([0xd4; 32]),
            resource_profile_digest: Digest32::new([0x31; 32]),
            installation_profile_digest: hash_bytes(&profile_bytes),
            payloads,
            issued_at: UnixMillis::new(1_000),
            expires_at: UnixMillis::new(4_000),
        };
        manifest.release_target_id = compute_release_target(&manifest).unwrap();
        let manifest_bytes = encode_manifest(&manifest).unwrap();
        let mut signed = Vec::with_capacity(RELEASE_DOMAIN.len() + manifest_bytes.len());
        signed.extend_from_slice(RELEASE_DOMAIN);
        signed.extend_from_slice(&manifest_bytes);
        let signature = release_key.sign(&signed).to_bytes();
        set_mode(&fixture.manifest, 0o644);
        set_mode(&fixture.signature, 0o644);
        fs::write(&fixture.manifest, &manifest_bytes).unwrap();
        fs::write(&fixture.signature, signature).unwrap();
        set_mode(&fixture.manifest, 0o444);
        set_mode(&fixture.signature, 0o444);

        let verifier = ReleaseVerifier::new(
            vec![ReleaseTrustRootV1 {
                key_id: KeyId::try_from("release-root").unwrap(),
                public_key: release_key.verifying_key().to_bytes(),
                not_before: UnixMillis::new(500),
                not_after: UnixMillis::new(5_000),
                revoked: false,
            }],
            vec![hash_bytes(&manifest_bytes)],
        )
        .unwrap();
        (fixture, verifier)
    }
}

fn set_mode(path: &Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

fn open_stage(fixture: &StageFixture) -> ReleaseStage {
    ReleaseStage::open_for_test(
        &fixture.stage,
        &fixture.executable,
        fixture.uid,
        fixture.gid,
    )
    .unwrap()
}

fn assert_stage_rejected(fixture: &StageFixture, verifier: &ReleaseVerifier) {
    let stage = open_stage(fixture);
    assert_eq!(
        verifier
            .verify_stage(&stage, UnixMillis::new(2_000))
            .unwrap_err()
            .code(),
        StableCode::IdentityReleaseMismatch
    );
}

fn assert_stage_open_rejected(fixture: &StageFixture, owner_uid: u32, owner_gid: u32) {
    assert_eq!(
        ReleaseStage::open_for_test(&fixture.stage, &fixture.executable, owner_uid, owner_gid,)
            .unwrap_err()
            .code(),
        StableCode::IdentityReleaseMismatch
    );
}

fn payload_mut<'manifest>(
    manifest: &'manifest mut ReleaseManifestV1,
    relative_path: &str,
) -> &'manifest mut ReleaseFileV1 {
    manifest
        .payloads
        .iter_mut()
        .find(|payload| payload.relative_path == relative_path)
        .unwrap()
}

fn set_all_directory_modes(stage: &Path, leaf_parent: &Path) {
    let mut current = stage.to_path_buf();
    set_mode(&current, 0o755);
    for component in leaf_parent.strip_prefix(stage).unwrap().components() {
        current.push(component);
        set_mode(&current, 0o755);
    }
}

#[cfg(target_os = "linux")]
const fn compiled_platform() -> InstallationPlatformV1 {
    InstallationPlatformV1::Linux
}

#[cfg(target_os = "macos")]
const fn compiled_platform() -> InstallationPlatformV1 {
    InstallationPlatformV1::MacOs
}
