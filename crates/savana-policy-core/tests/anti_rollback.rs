mod support;

use std::fs;

use savana_kernel_protocol::{Digest32, StableCode};
use savana_policy_core::{PolicyStore, PolicyVerifier};
use sha2::{Digest, Sha256};

fn open_store(path: &std::path::Path) -> PolicyStore {
    PolicyStore::open(path, support::verifier()).unwrap()
}

fn accept(store: &mut PolicyStore, policy: &support::TestPolicy) {
    let (bundle, signature) = support::signed(policy);
    store
        .verify_and_accept(&bundle, &signature, support::unix_now())
        .unwrap();
}

#[test]
fn exclusive_lifetime_lock_prevents_stale_store_rollback() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("policy.ledger");
    let mut first = open_store(&path);

    assert_eq!(
        PolicyStore::open(&path, support::verifier())
            .unwrap_err()
            .code(),
        StableCode::ProtocolIo
    );

    accept(&mut first, &support::valid_policy(8, 3));
    drop(first);

    let mut restarted = open_store(&path);
    assert_eq!(
        restarted.ledger_identity().unwrap().highest_policy_version,
        8
    );
    let older = support::valid_policy(7, 3);
    let (bundle, signature) = support::signed(&older);
    assert_eq!(
        restarted
            .verify_and_accept(&bundle, &signature, support::unix_now())
            .unwrap_err()
            .code(),
        StableCode::PolicyRollback
    );
}

#[test]
fn persistent_lock_file_is_regular_private_and_no_follow() {
    use std::os::unix::fs::{symlink, PermissionsExt};

    let dir = tempfile::tempdir().unwrap();
    let ledger_path = dir.path().join("policy.ledger");
    let lock_path = dir.path().join(".policy.ledger.lock");

    let store = open_store(&ledger_path);
    let metadata = fs::symlink_metadata(&lock_path).unwrap();
    assert!(metadata.file_type().is_file());
    assert!(!metadata.file_type().is_symlink());
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    drop(store);
    assert!(lock_path.exists());

    fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(
        PolicyStore::open(&ledger_path, support::verifier())
            .unwrap_err()
            .code(),
        StableCode::ProtocolIo
    );

    let symlink_dir = tempfile::tempdir().unwrap();
    let symlink_ledger = symlink_dir.path().join("policy.ledger");
    let symlink_lock = symlink_dir.path().join(".policy.ledger.lock");
    let target = symlink_dir.path().join("target");
    fs::write(&target, b"not a lock").unwrap();
    symlink(&target, &symlink_lock).unwrap();
    assert_eq!(
        PolicyStore::open(&symlink_ledger, support::verifier())
            .unwrap_err()
            .code(),
        StableCode::ProtocolIo
    );

    let directory_dir = tempfile::tempdir().unwrap();
    let directory_ledger = directory_dir.path().join("policy.ledger");
    fs::create_dir(directory_dir.path().join(".policy.ledger.lock")).unwrap();
    assert_eq!(
        PolicyStore::open(&directory_ledger, support::verifier())
            .unwrap_err()
            .code(),
        StableCode::ProtocolIo
    );
}

#[test]
fn genesis_identity_is_canonical_and_public() {
    let dir = tempfile::tempdir().unwrap();
    let store = open_store(&dir.path().join("policy.ledger"));
    let identity = store.ledger_identity().unwrap();
    assert_eq!(identity.highest_policy_version, 0);
    assert_eq!(identity.highest_key_epoch, 0);
    assert_eq!(identity.highest_policy_digest, Digest32::new([0; 32]));

    let canonical = support::encode_ledger(0, 0, [0; 32]);
    let mut hasher = Sha256::new();
    hasher.update(b"SAVANA_POLICY_LEDGER_V1\0");
    hasher.update(canonical);
    assert_eq!(
        identity.canonical_ledger_digest,
        Digest32::new(hasher.finalize().into())
    );
}

#[test]
fn durable_ledger_rejects_rollback_and_equivocation_after_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("policy.ledger");
    let mut store = open_store(&path);
    accept(&mut store, &support::valid_policy(7, 3));
    let accepted_identity = store.ledger_identity().unwrap();
    drop(store);

    let mut restarted = open_store(&path);
    assert_eq!(restarted.ledger_identity().unwrap(), accepted_identity);

    let older = support::valid_policy(6, 3);
    let (bundle, signature) = support::signed(&older);
    assert_eq!(
        restarted
            .verify_and_accept(&bundle, &signature, support::unix_now())
            .unwrap_err()
            .code(),
        StableCode::PolicyRollback
    );

    let mut different = support::valid_policy(7, 3);
    different.tools[0].descriptor_digest = [0x99; 32];
    let (bundle, signature) = support::signed(&different);
    assert_eq!(
        restarted
            .verify_and_accept(&bundle, &signature, support::unix_now())
            .unwrap_err()
            .code(),
        StableCode::PolicyEquivocation
    );
    drop(restarted);

    let changed_epoch = support::valid_policy(7, 4);
    let (bundle, signature) = support::signed(&changed_epoch);
    let epoch_four_verifier = PolicyVerifier::new(
        vec![support::trust_root(
            "policy-root",
            &support::signing_key(),
            4,
            false,
        )],
        support::active_target(),
    )
    .unwrap();
    let mut changed_epoch_store = PolicyStore::open(&path, epoch_four_verifier).unwrap();
    assert_eq!(
        changed_epoch_store
            .verify_and_accept(&bundle, &signature, support::unix_now())
            .unwrap_err()
            .code(),
        StableCode::PolicyEquivocation
    );
    drop(changed_epoch_store);

    let lower_epoch = support::valid_policy(8, 2);
    let (bundle, signature) = support::signed(&lower_epoch);
    let verifier = PolicyVerifier::new(
        vec![support::trust_root(
            "policy-root",
            &support::signing_key(),
            2,
            false,
        )],
        support::active_target(),
    )
    .unwrap();
    let mut lower_epoch_store = PolicyStore::open(&path, verifier).unwrap();
    assert_eq!(
        lower_epoch_store
            .verify_and_accept(&bundle, &signature, support::unix_now())
            .unwrap_err()
            .code(),
        StableCode::PolicyRollback
    );
}

#[test]
fn equal_identity_is_idempotent_and_higher_identity_is_durable() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("policy.ledger");
    let policy = support::valid_policy(7, 3);
    let mut store = open_store(&path);
    accept(&mut store, &policy);
    let first = store.ledger_identity().unwrap();
    accept(&mut store, &policy);
    assert_eq!(store.ledger_identity().unwrap(), first);

    let mut next = support::valid_policy(8, 3);
    next.tools[0].descriptor_digest = [0x31; 32];
    accept(&mut store, &next);
    assert_eq!(store.ledger_identity().unwrap().highest_policy_version, 8);
    drop(store);
    assert_eq!(
        open_store(&path)
            .ledger_identity()
            .unwrap()
            .highest_policy_version,
        8
    );

    let higher_epoch = support::valid_policy(9, 4);
    let (bundle, signature) = support::signed(&higher_epoch);
    let verifier = PolicyVerifier::new(
        vec![support::trust_root(
            "policy-root",
            &support::signing_key(),
            4,
            false,
        )],
        support::active_target(),
    )
    .unwrap();
    let mut higher_epoch_store = PolicyStore::open(&path, verifier).unwrap();
    higher_epoch_store
        .verify_and_accept(&bundle, &signature, support::unix_now())
        .unwrap();
    assert_eq!(
        higher_epoch_store
            .ledger_identity()
            .unwrap()
            .highest_key_epoch,
        4
    );
    drop(higher_epoch_store);
    assert_eq!(
        open_store(&path)
            .ledger_identity()
            .unwrap()
            .highest_policy_version,
        9
    );
}

#[test]
fn malformed_noncanonical_and_inconsistent_ledgers_are_rejected() {
    let cases = [
        ("malformed", vec![0xff]),
        ("wrong schema", {
            let mut bytes = support::encode_ledger(7, 3, [1; 32]);
            bytes[1] = 2;
            bytes
        }),
        (
            "zero with nonzero epoch",
            support::encode_ledger(0, 3, [0; 32]),
        ),
        ("zero with digest", support::encode_ledger(0, 0, [1; 32])),
        (
            "nonzero with zero epoch",
            support::encode_ledger(7, 0, [1; 32]),
        ),
        (
            "nonzero with zero digest",
            support::encode_ledger(7, 3, [0; 32]),
        ),
        ("trailing bytes", {
            let mut bytes = support::encode_ledger(7, 3, [1; 32]);
            bytes.push(0);
            bytes
        }),
        ("non-shortest version", {
            let bytes = support::encode_ledger(7, 3, [1; 32]);
            let mut rewritten = bytes.clone();
            let mut decoder = minicbor::Decoder::new(&bytes);
            assert_eq!(decoder.array().unwrap(), Some(4));
            assert_eq!(decoder.u16().unwrap(), 1);
            let position = decoder.position();
            assert_eq!(decoder.u64().unwrap(), 7);
            rewritten.splice(position..position + 1, [0x18, 0x07]);
            rewritten
        }),
    ];

    for (label, bytes) in cases {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy.ledger");
        fs::write(&path, &bytes).unwrap();
        let error = PolicyStore::open(&path, support::verifier()).expect_err(label);
        let expected = if label == "wrong schema" {
            StableCode::ProtocolUnsupportedVersion
        } else {
            StableCode::ProtocolMalformedCbor
        };
        assert_eq!(error.code(), expected, "{label}");
        assert_eq!(fs::read(&path).unwrap(), bytes, "{label}");
    }
}

#[test]
fn symlink_and_non_regular_ledger_paths_are_rejected() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("target");
    fs::write(&target, support::encode_ledger(0, 0, [0; 32])).unwrap();
    let link = dir.path().join("policy.ledger");
    symlink(&target, &link).unwrap();
    assert_eq!(
        PolicyStore::open(&link, support::verifier())
            .unwrap_err()
            .code(),
        StableCode::ProtocolIo
    );

    let directory_path = dir.path().join("ledger-dir");
    fs::create_dir(&directory_path).unwrap();
    assert_eq!(
        PolicyStore::open(&directory_path, support::verifier())
            .unwrap_err()
            .code(),
        StableCode::ProtocolIo
    );
}

#[test]
fn leftover_temporary_files_are_ignored_and_preserved() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("policy.ledger");
    let leftover = dir.path().join(".policy.ledger.tmp-deadbeef");
    fs::write(&leftover, b"untrusted partial state").unwrap();

    let mut store = open_store(&path);
    assert_eq!(store.ledger_identity().unwrap().highest_policy_version, 0);
    assert!(leftover.exists());
    accept(&mut store, &support::valid_policy(7, 3));
    assert!(leftover.exists());
}

#[test]
fn failed_persistence_does_not_advance_in_memory_high_water() {
    let dir = tempfile::tempdir().unwrap();
    let state_dir = dir.path().join("state");
    fs::create_dir(&state_dir).unwrap();
    let path = state_dir.join("policy.ledger");
    let mut store = open_store(&path);
    let before = store.ledger_identity().unwrap();
    let moved_state = dir.path().join("moved-state");
    fs::rename(&state_dir, &moved_state).unwrap();

    let policy = support::valid_policy(7, 3);
    let (bundle, signature) = support::signed(&policy);
    assert_eq!(
        store
            .verify_and_accept(&bundle, &signature, support::unix_now())
            .unwrap_err()
            .code(),
        StableCode::ProtocolIo
    );
    assert_eq!(store.ledger_identity().unwrap(), before);

    fs::rename(moved_state, &state_dir).unwrap();
    store
        .verify_and_accept(&bundle, &signature, support::unix_now())
        .unwrap();
    assert_eq!(store.ledger_identity().unwrap().highest_policy_version, 7);
}

#[test]
fn persisted_ledger_has_private_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("policy.ledger");
    let mut store = open_store(&path);
    accept(&mut store, &support::valid_policy(7, 3));
    assert_eq!(
        fs::metadata(path).unwrap().permissions().mode() & 0o777,
        0o600
    );
}
