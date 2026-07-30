use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::PermissionsExt as _;

use super::{DeploymentApplySelectorV2, FixedDeploymentSpoolV2, NativeIdentityErrorV2};

#[test]
fn apply_selector_accepts_only_exact_lowercase_digest_argument() {
    let digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let selector = DeploymentApplySelectorV2::parse_arguments(
        [
            OsString::from("savana-deploy"),
            OsString::from("apply"),
            OsString::from(digest),
        ]
        .into_iter(),
    )
    .unwrap();
    assert_eq!(
        selector.as_bytes(),
        &[
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
            0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67,
            0x89, 0xab, 0xcd, 0xef,
        ]
    );

    for arguments in [
        vec![OsString::from("savana-deploy")],
        vec![
            OsString::from("savana-deploy"),
            OsString::from("check"),
            OsString::from(digest),
        ],
        vec![
            OsString::from("savana-deploy"),
            OsString::from("apply"),
            OsString::from(digest.to_uppercase()),
        ],
        vec![
            OsString::from("savana-deploy"),
            OsString::from("apply"),
            OsString::from(format!("../{digest}")),
        ],
        vec![
            OsString::from("savana-deploy"),
            OsString::from("apply"),
            OsString::from(digest),
            OsString::from("extra"),
        ],
    ] {
        assert_eq!(
            DeploymentApplySelectorV2::parse_arguments(arguments.into_iter()).unwrap_err(),
            NativeIdentityErrorV2::InvalidDeploymentInvocation
        );
    }
}

#[test]
fn fixed_spool_opens_only_single_link_root_owned_descriptor_beneath_selector() {
    let ready = tempfile::tempdir().unwrap();
    fs::set_permissions(ready.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let digest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let selector = DeploymentApplySelectorV2::parse_arguments(
        [
            OsString::from("savana-deploy"),
            OsString::from("apply"),
            OsString::from(digest),
        ]
        .into_iter(),
    )
    .unwrap();
    let staged = ready.path().join(digest);
    fs::create_dir(&staged).unwrap();
    fs::set_permissions(&staged, fs::Permissions::from_mode(0o700)).unwrap();
    let descriptor = staged.join("DeploymentTransactionV2.cbor");
    fs::write(&descriptor, [0x82, 0x02, 0x01]).unwrap();
    fs::set_permissions(&descriptor, fs::Permissions::from_mode(0o400)).unwrap();

    let spool = FixedDeploymentSpoolV2::open_for_test(ready.path()).unwrap();
    let opened = spool.open_transaction(selector).unwrap();
    assert_eq!(opened.staging_id(), selector);
    assert_eq!(opened.descriptor_bytes(), [0x82, 0x02, 0x01]);

    let linked = staged.join("linked.cbor");
    fs::hard_link(&descriptor, &linked).unwrap();
    assert_eq!(
        spool.open_transaction(selector).unwrap_err(),
        NativeIdentityErrorV2::UnsafeDeploymentSpool
    );
    fs::remove_file(linked).unwrap();
    fs::remove_file(&descriptor).unwrap();
    std::os::unix::fs::symlink("/etc/passwd", &descriptor).unwrap();
    assert_eq!(
        spool.open_transaction(selector).unwrap_err(),
        NativeIdentityErrorV2::UnsafeDeploymentSpool
    );
}

#[test]
fn fixed_spool_component_walk_rejects_a_symlinked_ancestor() {
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let deployment = root.path().join("savana-deploy");
    let spool = deployment.join("spool");
    let ready = spool.join("ready");
    fs::create_dir(&deployment).unwrap();
    fs::create_dir(&spool).unwrap();
    fs::create_dir(&ready).unwrap();
    for directory in [&deployment, &spool, &ready] {
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).unwrap();
    }
    FixedDeploymentSpoolV2::open_compiled_chain_for_test(
        root.path(),
        &["savana-deploy", "spool", "ready"],
    )
    .unwrap();

    fs::remove_dir(&ready).unwrap();
    fs::remove_dir(&spool).unwrap();
    let outside = tempfile::tempdir().unwrap();
    fs::set_permissions(outside.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let outside_ready = outside.path().join("ready");
    fs::create_dir(&outside_ready).unwrap();
    fs::set_permissions(&outside_ready, fs::Permissions::from_mode(0o700)).unwrap();
    std::os::unix::fs::symlink(outside.path(), &spool).unwrap();
    assert_eq!(
        FixedDeploymentSpoolV2::open_compiled_chain_for_test(
            root.path(),
            &["savana-deploy", "spool", "ready"],
        )
        .unwrap_err(),
        NativeIdentityErrorV2::UnsafeDeploymentSpool
    );
}

#[test]
fn fixed_spool_enforces_the_frozen_one_mib_transaction_limit() {
    let ready = tempfile::tempdir().unwrap();
    fs::set_permissions(ready.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let digest = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let selector = DeploymentApplySelectorV2::parse_arguments(
        [
            OsString::from("savana-deploy"),
            OsString::from("apply"),
            OsString::from(digest),
        ]
        .into_iter(),
    )
    .unwrap();
    let staged = ready.path().join(digest);
    fs::create_dir(&staged).unwrap();
    fs::set_permissions(&staged, fs::Permissions::from_mode(0o700)).unwrap();
    let descriptor = staged.join("DeploymentTransactionV2.cbor");
    fs::write(&descriptor, vec![0_u8; 1_048_577]).unwrap();
    fs::set_permissions(&descriptor, fs::Permissions::from_mode(0o400)).unwrap();

    assert_eq!(
        FixedDeploymentSpoolV2::open_for_test(ready.path())
            .unwrap()
            .open_transaction(selector)
            .unwrap_err(),
        NativeIdentityErrorV2::UnsafeDeploymentSpool
    );
}
