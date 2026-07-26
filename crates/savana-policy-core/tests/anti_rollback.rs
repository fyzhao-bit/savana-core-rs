mod support;

use std::fs;
use std::os::unix::fs::PermissionsExt;

use savana_kernel_protocol::{Digest32, StableCode};
use savana_policy_core::PolicyStore;
use sha2::{Digest, Sha256};

fn open_store(path: &std::path::Path) -> PolicyStore {
    PolicyStore::open(path, support::verifier()).unwrap()
}

#[test]
fn persistent_lock_file_is_regular_private_and_no_follow() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().unwrap();
    let ledger_path = dir.path().join("policy.ledger");
    let lock_path = dir.path().join(".policy.ledger.lock");
    let store = open_store(&ledger_path);
    let metadata = fs::symlink_metadata(&lock_path).unwrap();
    assert!(metadata.file_type().is_file());
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    drop(store);

    fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(
        PolicyStore::open(&ledger_path, support::verifier())
            .unwrap_err()
            .code(),
        StableCode::ProtocolIo
    );

    let symlink_dir = tempfile::tempdir().unwrap();
    let target = symlink_dir.path().join("target");
    fs::write(&target, b"not a lock").unwrap();
    symlink(&target, symlink_dir.path().join(".policy.ledger.lock")).unwrap();
    assert_eq!(
        PolicyStore::open(
            &symlink_dir.path().join("policy.ledger"),
            support::verifier()
        )
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
