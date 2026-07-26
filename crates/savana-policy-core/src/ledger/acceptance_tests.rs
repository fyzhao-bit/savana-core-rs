use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::process::ExitStatusExt;
use std::process::Command;

use ed25519_dalek::SigningKey;
use savana_kernel_protocol::{KeyId, StableCode};

use super::PolicyStore;
use crate::{PolicyTrustRootV1, PolicyVerifier};

use crate::test_support as support;

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
fn anchored_acceptance_persists_and_equal_identity_is_idempotent() {
    let root = tempfile::tempdir().unwrap();
    let state = root.path().join("state");
    fs::create_dir(&state).unwrap();
    fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
    let metadata = fs::metadata(&state).unwrap();
    let ledger = state.join("policy-ledger-v1.cbor");
    let mut store =
        PolicyStore::open_anchored(&ledger, metadata.uid(), metadata.gid(), support::verifier())
            .unwrap();
    let policy = support::valid_policy(7, 3);
    accept(&mut store, &policy);
    let first = fs::symlink_metadata(&ledger).unwrap();
    let inode = (first.dev(), first.ino());
    assert_eq!(first.uid(), metadata.uid());
    assert_eq!(first.gid(), metadata.gid());
    assert_eq!(first.mode() & 0o7777, 0o600);
    assert_eq!(first.nlink(), 1);
    accept(&mut store, &policy);
    let unchanged = fs::symlink_metadata(&ledger).unwrap();
    assert_eq!((unchanged.dev(), unchanged.ino()), inode);
    drop(store);
    assert_eq!(
        PolicyStore::open_anchored(&ledger, metadata.uid(), metadata.gid(), support::verifier(),)
            .unwrap()
            .ledger_identity()
            .unwrap()
            .highest_policy_version,
        7
    );
}

fn verifier_for_epoch(epoch: u64) -> PolicyVerifier {
    let key = SigningKey::from_bytes(&[0x42; 32]);
    PolicyVerifier::new(
        vec![PolicyTrustRootV1 {
            key_id: KeyId::try_from("policy-root").unwrap(),
            public_key: key.verifying_key().to_bytes(),
            epoch,
            revoked: false,
        }],
        support::active_target(),
    )
    .unwrap()
}

#[test]
fn key_epoch_transitions_preserve_rollback_equivocation_and_advancement_rules() {
    let root = tempfile::tempdir().unwrap();
    let ledger = root.path().join("policy.ledger");
    let mut initial = open_store(&ledger);
    accept(&mut initial, &support::valid_policy(7, 3));
    drop(initial);

    let same_version_new_epoch = support::valid_policy(7, 4);
    let (bundle, signature) = support::signed(&same_version_new_epoch);
    let mut epoch_four = PolicyStore::open(&ledger, verifier_for_epoch(4)).unwrap();
    assert_eq!(
        epoch_four
            .verify_and_accept(&bundle, &signature, support::unix_now())
            .unwrap_err()
            .code(),
        StableCode::PolicyEquivocation
    );
    drop(epoch_four);

    let higher_version_lower_epoch = support::valid_policy(8, 2);
    let (bundle, signature) = support::signed(&higher_version_lower_epoch);
    let mut epoch_two = PolicyStore::open(&ledger, verifier_for_epoch(2)).unwrap();
    assert_eq!(
        epoch_two
            .verify_and_accept(&bundle, &signature, support::unix_now())
            .unwrap_err()
            .code(),
        StableCode::PolicyRollback
    );
    drop(epoch_two);

    let higher_version_higher_epoch = support::valid_policy(9, 4);
    let (bundle, signature) = support::signed(&higher_version_higher_epoch);
    let mut epoch_four = PolicyStore::open(&ledger, verifier_for_epoch(4)).unwrap();
    epoch_four
        .verify_and_accept(&bundle, &signature, support::unix_now())
        .unwrap();
    assert_eq!(epoch_four.ledger_identity().unwrap().highest_key_epoch, 4);
    drop(epoch_four);
    assert_eq!(
        open_store(&ledger)
            .ledger_identity()
            .unwrap()
            .highest_policy_version,
        9
    );
}

#[test]
fn raw_transition_rejects_rollback_and_equivocation_after_restart() {
    let root = tempfile::tempdir().unwrap();
    let ledger = root.path().join("policy.ledger");
    let mut store = open_store(&ledger);
    accept(&mut store, &support::valid_policy(7, 3));
    drop(store);
    let mut restarted = open_store(&ledger);
    let (older, signature) = support::signed(&support::valid_policy(6, 3));
    assert_eq!(
        restarted
            .verify_and_accept(&older, &signature, support::unix_now())
            .unwrap_err()
            .code(),
        StableCode::PolicyRollback
    );
    let mut different = support::valid_policy(7, 3);
    different.tools[0].descriptor_digest = [0x99; 32];
    let (different, signature) = support::signed(&different);
    assert_eq!(
        restarted
            .verify_and_accept(&different, &signature, support::unix_now())
            .unwrap_err()
            .code(),
        StableCode::PolicyEquivocation
    );
}

#[test]
fn higher_identity_is_durable_and_lifetime_lock_excludes_stale_store() {
    let root = tempfile::tempdir().unwrap();
    let ledger = root.path().join("policy.ledger");
    let mut store = open_store(&ledger);
    assert_eq!(
        PolicyStore::open(&ledger, support::verifier())
            .unwrap_err()
            .code(),
        StableCode::ProtocolIo
    );
    accept(&mut store, &support::valid_policy(7, 3));
    let mut higher = support::valid_policy(8, 3);
    higher.tools[0].descriptor_digest = [0x31; 32];
    accept(&mut store, &higher);
    drop(store);
    assert_eq!(
        open_store(&ledger)
            .ledger_identity()
            .unwrap()
            .highest_policy_version,
        8
    );
}

#[test]
fn temporary_files_are_preserved_and_persisted_ledger_is_private() {
    let root = tempfile::tempdir().unwrap();
    let ledger = root.path().join("policy.ledger");
    let leftover = root.path().join(".policy.ledger.tmp-deadbeef");
    fs::write(&leftover, b"untrusted partial state").unwrap();
    let mut store = open_store(&ledger);
    accept(&mut store, &support::valid_policy(7, 3));
    assert!(leftover.exists());
    assert_eq!(
        fs::metadata(&ledger).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[test]
fn failed_persistence_does_not_advance_in_memory_high_water() {
    let root = tempfile::tempdir().unwrap();
    let state = root.path().join("state");
    fs::create_dir(&state).unwrap();
    let ledger = state.join("policy.ledger");
    let mut store = open_store(&ledger);
    let before = store.ledger_identity().unwrap();
    let moved = root.path().join("moved-state");
    fs::rename(&state, &moved).unwrap();
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
    fs::rename(&moved, &state).unwrap();
    store
        .verify_and_accept(&bundle, &signature, support::unix_now())
        .unwrap();
    assert_eq!(store.ledger_identity().unwrap().highest_policy_version, 7);
}

#[test]
fn initial_post_persistence_guard_aborts_subprocess() {
    const CHILD: &str = "SAVANA_TEST_INITIAL_ACCEPTANCE_CHILD";
    const ROOT: &str = "SAVANA_TEST_INITIAL_ACCEPTANCE_ROOT";
    if std::env::var_os(CHILD).is_some() {
        let root = std::path::PathBuf::from(std::env::var_os(ROOT).unwrap());
        let fixture = support::current_policy_fixture_at(&root);
        let release = fixture.release();
        let verifier = release.policy_verifier().unwrap();
        let store = PolicyStore::open(fixture.ledger_path(), verifier).unwrap();
        std::env::set_var("SAVANA_TEST_INITIAL_ACCEPTANCE_PANIC", "1");
        let _ = store.verify_and_accept_initial(
            release,
            fixture.policy_bytes(),
            fixture.policy_signature(),
            fixture.now(),
        );
        panic!("post-persistence injection did not abort");
    }

    let root = tempfile::tempdir().unwrap();
    let status = Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("ledger::acceptance_tests::initial_post_persistence_guard_aborts_subprocess")
        .arg("--nocapture")
        .env(CHILD, "1")
        .env(ROOT, root.path())
        .status()
        .unwrap();
    assert_eq!(status.signal(), Some(nix::libc::SIGABRT));

    let ledger = root.path().join("policy.ledger");
    let store = PolicyStore::open(&ledger, support::offline_verifier()).unwrap();
    assert_eq!(store.ledger_identity().unwrap().highest_policy_version, 7);
}
