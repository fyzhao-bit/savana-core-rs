use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt as _};
use std::sync::{Arc, Mutex};

use ed25519_dalek::{Signer as _, SigningKey};
use savana_kernel_protocol::v2::{
    ActionTemplateIdV2, Digest32V2, DisplayProjectionIdV2, ExecutorIdentityV2, ImplementationIdV2,
    ProjectionIdV2, RoleIdV2, ToolClassIdV2, UnixMillisV2, VersionV2,
};
use savana_policy_core::v2::{
    AttemptKindV2, BoundedConnectorHostV2, BoundedConnectorRetryPolicyV2, ConnectorDescriptorV2,
    ConnectorRegistryStateV2, ConnectorTierV2, DurableConnectorRegistryStoreV2, EffectSetV2,
    ExecutorIdempotencyContractV2, G4Error, IdentifierV2, InternalValidatorDeclarationV2,
    RollbackProtectedStateAnchorV2, RollbackProtectedStateHeadV2, TestConnectorStoreCrashPointV2,
    UnsignedToolDescriptorV2, MAX_CONNECTOR_AUTHORITY_STATE_BYTES_V2,
};
use sha2::{Digest as _, Sha256};

const STATE_LEAF: &str = "connector-registry-v2.cbor";
const CONNECTOR_USER_DOMAIN: &[u8] = b"savana.connector.user.v2\0";
const DELTA_PAYLOAD_DOMAIN: &[u8] = b"savana.connector-registry.delta.v2.payload\0";
const DELTA_SIGNATURE_DOMAIN: &[u8] = b"savana.connector-registry.delta.v2.signature\0";

fn digest(byte: u8) -> Digest32V2 {
    Digest32V2::new([byte; 32])
}

fn domain_hash(domain: &[u8], bytes: &[u8]) -> Digest32V2 {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(bytes);
    Digest32V2::new(hasher.finalize().into())
}

fn private_directory() -> tempfile::TempDir {
    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    directory
}

#[derive(Clone)]
struct TestHighWater(Arc<Mutex<RollbackProtectedStateHeadV2>>);

impl Default for TestHighWater {
    fn default() -> Self {
        Self(Arc::new(Mutex::new(
            RollbackProtectedStateHeadV2::new(0, digest(0)).unwrap(),
        )))
    }
}

impl TestHighWater {
    fn head(&self) -> RollbackProtectedStateHeadV2 {
        *self.0.lock().unwrap()
    }
}

impl RollbackProtectedStateAnchorV2 for TestHighWater {
    fn current_head(&self) -> Result<RollbackProtectedStateHeadV2, G4Error> {
        Ok(self.head())
    }

    fn compare_and_advance(
        &mut self,
        expected: RollbackProtectedStateHeadV2,
        next: RollbackProtectedStateHeadV2,
    ) -> Result<(), G4Error> {
        let mut head = self.0.lock().unwrap();
        if *head != expected || next.sequence() != expected.sequence().checked_add(1).unwrap() {
            return Err(G4Error::DurableStateRollback);
        }
        *head = next;
        Ok(())
    }
}

fn tool(seed: u8) -> UnsignedToolDescriptorV2 {
    let contract = ExecutorIdempotencyContractV2::ConnectorIdempotentByExecutionNonce;
    UnsignedToolDescriptorV2::from_verified_manifest(
        2,
        VersionV2::new(1, 0, 0),
        digest(seed),
        IdentifierV2::new(format!("connector-tool-{seed}")).unwrap(),
        ActionTemplateIdV2::new(u32::from(seed) + 1),
        ToolClassIdV2::new(u32::from(seed) + 2),
        digest(seed.wrapping_add(1)),
        digest(seed.wrapping_add(2)),
        vec![RoleIdV2::new(1)],
        EffectSetV2::READ,
        AttemptKindV2::ToolRead,
        BoundedConnectorRetryPolicyV2::new(contract, 2, 1_000_000).unwrap(),
        vec![InternalValidatorDeclarationV2::new(
            ImplementationIdV2::new(u32::from(seed) + 3),
            VersionV2::new(1, 0, 0),
            digest(seed.wrapping_add(3)),
        )],
        ExecutorIdentityV2::new([seed.wrapping_add(4); 32]),
        ProjectionIdV2::new(u32::from(seed) + 4),
        digest(seed.wrapping_add(5)),
        DisplayProjectionIdV2::new(u32::from(seed) + 5),
        digest(seed.wrapping_add(6)),
        contract,
        UnixMillisV2::new(1),
        UnixMillisV2::new(10_000),
    )
    .unwrap()
}

fn user_connector(name: &str, seed: u8) -> ConnectorDescriptorV2 {
    let package_digest = digest(seed);
    let mut id_material = minicbor::Encoder::new(Vec::new());
    id_material.array(2).unwrap().str(name).unwrap();
    id_material
        .array(2)
        .unwrap()
        .u16(1)
        .unwrap()
        .bytes(package_digest.as_bytes())
        .unwrap();
    let connector_id = domain_hash(CONNECTOR_USER_DOMAIN, &id_material.into_writer());

    let mut descriptor = minicbor::Encoder::new(Vec::new());
    descriptor
        .array(7)
        .unwrap()
        .bytes(connector_id.as_bytes())
        .unwrap()
        .str(name)
        .unwrap()
        .u16(ConnectorTierV2::UserRegistered as u16)
        .unwrap()
        .array(2)
        .unwrap()
        .u16(1)
        .unwrap()
        .bytes(package_digest.as_bytes())
        .unwrap()
        .array(1)
        .unwrap();
    descriptor
        .writer_mut()
        .extend_from_slice(&minicbor::to_vec(tool(seed)).unwrap());
    descriptor
        .u16(EffectSetV2::READ.bits())
        .unwrap()
        .u64(1)
        .unwrap();
    ConnectorDescriptorV2::from_canonical_bytes(&descriptor.into_writer(), &[]).unwrap()
}

fn https_user_connector(
    name: &str,
    url: &str,
    allowlist: &[BoundedConnectorHostV2],
    seed: u8,
) -> ConnectorDescriptorV2 {
    let tls_pin = digest(seed);
    let mut id_material = minicbor::Encoder::new(Vec::new());
    id_material.array(2).unwrap().str(name).unwrap();
    id_material
        .array(3)
        .unwrap()
        .u16(2)
        .unwrap()
        .str(url)
        .unwrap()
        .bytes(tls_pin.as_bytes())
        .unwrap();
    let connector_id = domain_hash(CONNECTOR_USER_DOMAIN, &id_material.into_writer());

    let mut descriptor = minicbor::Encoder::new(Vec::new());
    descriptor
        .array(7)
        .unwrap()
        .bytes(connector_id.as_bytes())
        .unwrap()
        .str(name)
        .unwrap()
        .u16(ConnectorTierV2::UserRegistered as u16)
        .unwrap()
        .array(3)
        .unwrap()
        .u16(2)
        .unwrap()
        .str(url)
        .unwrap()
        .bytes(tls_pin.as_bytes())
        .unwrap()
        .array(1)
        .unwrap();
    descriptor
        .writer_mut()
        .extend_from_slice(&minicbor::to_vec(tool(seed)).unwrap());
    descriptor
        .u16(EffectSetV2::READ.bits())
        .unwrap()
        .u64(1)
        .unwrap();
    ConnectorDescriptorV2::from_canonical_bytes(&descriptor.into_writer(), allowlist).unwrap()
}

fn add_delta(
    sequence: u64,
    previous_head: Digest32V2,
    connector: &ConnectorDescriptorV2,
    settlement: Digest32V2,
    authority: &SigningKey,
) -> Vec<u8> {
    let mut payload = minicbor::Encoder::new(Vec::new());
    payload
        .array(6)
        .unwrap()
        .u16(1)
        .unwrap()
        .u64(sequence)
        .unwrap()
        .bytes(previous_head.as_bytes())
        .unwrap()
        .array(2)
        .unwrap()
        .u16(1)
        .unwrap();
    payload
        .writer_mut()
        .extend_from_slice(connector.canonical_bytes());
    payload
        .bytes(settlement.as_bytes())
        .unwrap()
        .u64(sequence)
        .unwrap();
    let payload = payload.into_writer();
    let payload_digest = domain_hash(DELTA_PAYLOAD_DOMAIN, &payload);
    let signature_digest = domain_hash(DELTA_SIGNATURE_DOMAIN, payload_digest.as_bytes());

    let mut signed = minicbor::Encoder::new(Vec::new());
    signed.array(3).unwrap();
    signed.writer_mut().extend_from_slice(&payload);
    signed
        .bytes(payload_digest.as_bytes())
        .unwrap()
        .bytes(&authority.sign(signature_digest.as_bytes()).to_bytes())
        .unwrap();
    signed.into_writer()
}

fn remove_delta(
    sequence: u64,
    previous_head: Digest32V2,
    connector_id: Digest32V2,
    authority: &SigningKey,
) -> Vec<u8> {
    let mut payload = minicbor::Encoder::new(Vec::new());
    payload
        .array(6)
        .unwrap()
        .u16(1)
        .unwrap()
        .u64(sequence)
        .unwrap()
        .bytes(previous_head.as_bytes())
        .unwrap()
        .array(2)
        .unwrap()
        .u16(2)
        .unwrap()
        .bytes(connector_id.as_bytes())
        .unwrap()
        .bytes(digest(0).as_bytes())
        .unwrap()
        .u64(sequence)
        .unwrap();
    let payload = payload.into_writer();
    let payload_digest = domain_hash(DELTA_PAYLOAD_DOMAIN, &payload);
    let signature_digest = domain_hash(DELTA_SIGNATURE_DOMAIN, payload_digest.as_bytes());

    let mut signed = minicbor::Encoder::new(Vec::new());
    signed.array(3).unwrap();
    signed.writer_mut().extend_from_slice(&payload);
    signed
        .bytes(payload_digest.as_bytes())
        .unwrap()
        .bytes(&authority.sign(signature_digest.as_bytes()).to_bytes())
        .unwrap();
    signed.into_writer()
}

fn genesis(authority: &SigningKey) -> ConnectorRegistryStateV2 {
    ConnectorRegistryStateV2::from_verified_genesis(
        digest(0x21),
        authority.verifying_key().to_bytes(),
        vec![],
        vec![],
    )
    .unwrap()
}

fn open_store(
    directory: &std::path::Path,
    state: ConnectorRegistryStateV2,
    high_water: TestHighWater,
) -> Result<DurableConnectorRegistryStoreV2, G4Error> {
    DurableConnectorRegistryStoreV2::open_for_test(directory, state, Box::new(high_water))
}

#[test]
fn authority_state_commits_with_the_registry_and_exact_retry_does_not_advance_high_water() {
    let directory = private_directory();
    let authority = SigningKey::from_bytes(&[0x24; 32]);
    let high_water = TestHighWater::default();
    let connector = user_connector("authority-state", 0x25);
    let delta = add_delta(1, digest(0x21), &connector, digest(0x26), &authority);
    let opaque = b"consumed-settlement-and-pending-handle";
    let mut store = open_store(directory.path(), genesis(&authority), high_water.clone()).unwrap();
    let initial_revision = store.revision().unwrap();

    let committed = store
        .commit(digest(0x21), initial_revision, Some(&delta), opaque)
        .unwrap();
    assert_eq!(committed.sequence(), 1);
    assert_eq!(store.authority_state().unwrap(), opaque);
    assert!(!fs::read(directory.path().join(STATE_LEAF))
        .unwrap()
        .windows(opaque.len())
        .any(|window| window == opaque));
    let committed_high_water = high_water.head();
    let replay = store
        .commit(digest(0x21), initial_revision, Some(&delta), opaque)
        .unwrap();
    assert_eq!(replay.sequence(), 1);
    assert_eq!(high_water.head(), committed_high_water);
    assert_eq!(
        store
            .commit(
                digest(0x21),
                initial_revision,
                Some(&delta),
                b"rebound-state",
            )
            .unwrap_err(),
        G4Error::IdempotencyConflict
    );
    drop(store);

    let mut reopened = open_store(directory.path(), genesis(&authority), high_water).unwrap();
    assert_eq!(reopened.authority_state().unwrap(), opaque);
    assert_eq!(reopened.snapshot().unwrap().sequence(), 1);
    assert_eq!(
        reopened
            .commit(digest(0x21), initial_revision, Some(&delta), opaque)
            .unwrap()
            .sequence(),
        1,
    );
}

#[test]
fn delayed_authority_only_commit_cannot_resurrect_stale_handles_or_settlements() {
    let directory = private_directory();
    let authority = SigningKey::from_bytes(&[0x2a; 32]);
    let high_water = TestHighWater::default();
    let mut store = open_store(directory.path(), genesis(&authority), high_water.clone()).unwrap();
    let registry_head = store.snapshot().unwrap().head_digest();
    let initial_revision = store.revision().unwrap();

    store
        .commit(registry_head, initial_revision, None, b"pending-handle")
        .unwrap();
    let pending_revision = store.revision().unwrap();
    store
        .commit(
            registry_head,
            pending_revision,
            None,
            b"consumed-settlement",
        )
        .unwrap();
    let committed_head = high_water.head();

    assert_eq!(
        store
            .commit(registry_head, pending_revision, None, b"pending-handle")
            .unwrap_err(),
        G4Error::StateConflict,
    );
    assert_eq!(store.authority_state().unwrap(), b"consumed-settlement");
    assert_eq!(high_water.head(), committed_head);
}

#[test]
fn authority_state_bound_is_exact_and_failure_does_not_advance_revision() {
    let directory = private_directory();
    let authority = SigningKey::from_bytes(&[0x2b; 32]);
    let high_water = TestHighWater::default();
    let mut store = open_store(directory.path(), genesis(&authority), high_water.clone()).unwrap();
    let registry_head = store.snapshot().unwrap().head_digest();
    let initial_revision = store.revision().unwrap();
    let exact = vec![0x5a; MAX_CONNECTOR_AUTHORITY_STATE_BYTES_V2];

    store
        .commit(registry_head, initial_revision, None, &exact)
        .unwrap();
    let exact_revision = store.revision().unwrap();
    let exact_high_water = high_water.head();
    let oversized = vec![0xa5; MAX_CONNECTOR_AUTHORITY_STATE_BYTES_V2 + 1];
    assert_eq!(
        store
            .commit(registry_head, exact_revision, None, &oversized)
            .unwrap_err(),
        G4Error::DescriptorLimitExceeded,
    );
    assert_eq!(store.revision().unwrap(), exact_revision);
    assert_eq!(store.authority_state().unwrap(), exact);
    assert_eq!(high_water.head(), exact_high_water);
}

#[test]
fn exact_canonical_journal_commit_restarts_and_replays_idempotently() {
    let directory = private_directory();
    let authority = SigningKey::from_bytes(&[0x31; 32]);
    let high_water = TestHighWater::default();
    let connector = user_connector("durable-mail", 0x32);
    let delta = add_delta(1, digest(0x21), &connector, digest(0x33), &authority);

    let mut store = open_store(directory.path(), genesis(&authority), high_water.clone()).unwrap();
    let committed = store.append_canonical_delta(&delta).unwrap();
    assert_eq!(committed.sequence(), 1);
    assert!(committed.contains_connector(connector.connector_id()));
    assert_eq!(committed.deltas()[0].canonical_bytes(), delta);
    let committed_high_water = high_water.head();
    drop(store);

    let mut reopened =
        open_store(directory.path(), genesis(&authority), high_water.clone()).unwrap();
    let recovered = reopened.snapshot().unwrap();
    assert_eq!(recovered.sequence(), 1);
    assert!(recovered.contains_connector(connector.connector_id()));
    assert_eq!(recovered.deltas()[0].canonical_bytes(), delta);
    let replay = reopened.append_canonical_delta(&delta).unwrap();
    assert_eq!(replay.sequence(), 1);
    assert_eq!(high_water.head(), committed_high_water);
}

#[test]
fn recovery_uses_genesis_for_unanchored_corruption_but_refuses_authenticated_invalid_or_missing_state(
) {
    let authority = SigningKey::from_bytes(&[0x41; 32]);
    let connector = user_connector("recovery-mail", 0x42);
    let delta = add_delta(1, digest(0x21), &connector, digest(0x43), &authority);

    let corrupt_directory = private_directory();
    let anchored = TestHighWater::default();
    let mut store = open_store(corrupt_directory.path(), genesis(&authority), anchored).unwrap();
    store.append_canonical_delta(&delta).unwrap();
    drop(store);
    let state_path = corrupt_directory.path().join(STATE_LEAF);
    let mut bytes = fs::read(&state_path).unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    fs::write(&state_path, bytes).unwrap();
    let recovered = open_store(
        corrupt_directory.path(),
        genesis(&authority),
        TestHighWater::default(),
    )
    .unwrap();
    assert_eq!(recovered.snapshot().unwrap().sequence(), 0);

    let invalid_directory = private_directory();
    let invalid_high_water = TestHighWater::default();
    let mut store = open_store(
        invalid_directory.path(),
        genesis(&authority),
        invalid_high_water.clone(),
    )
    .unwrap();
    store.append_canonical_delta(&delta).unwrap();
    drop(store);
    let wrong_authority = SigningKey::from_bytes(&[0x44; 32]);
    assert_eq!(
        open_store(
            invalid_directory.path(),
            genesis(&wrong_authority),
            invalid_high_water,
        )
        .unwrap_err(),
        G4Error::DurableStateCorrupt
    );

    let missing_directory = private_directory();
    let missing_high_water = TestHighWater::default();
    let mut store = open_store(
        missing_directory.path(),
        genesis(&authority),
        missing_high_water.clone(),
    )
    .unwrap();
    store.append_canonical_delta(&delta).unwrap();
    drop(store);
    fs::remove_file(missing_directory.path().join(STATE_LEAF)).unwrap();
    assert_eq!(
        open_store(
            missing_directory.path(),
            genesis(&authority),
            missing_high_water,
        )
        .unwrap_err(),
        G4Error::DurableStateRollback
    );
}

#[test]
fn every_atomic_commit_boundary_recovers_the_old_or_exact_new_journal() {
    use TestConnectorStoreCrashPointV2 as Crash;

    for point in Crash::ALL {
        let directory = private_directory();
        let authority = SigningKey::from_bytes(&[0x51; 32]);
        let high_water = TestHighWater::default();
        let connector = user_connector("crash-mail", 0x52);
        let delta = add_delta(1, digest(0x21), &connector, digest(0x53), &authority);
        let mut store =
            open_store(directory.path(), genesis(&authority), high_water.clone()).unwrap();
        assert!(matches!(
            store
                .append_canonical_delta_with_crash_for_test(&delta, point)
                .unwrap_err(),
            G4Error::DurableStateIo | G4Error::DurableCommitUncertain
        ));
        drop(store);

        let mut reopened = open_store(directory.path(), genesis(&authority), high_water).unwrap();
        let recovered = reopened.snapshot().unwrap();
        let expected_new = matches!(
            point,
            Crash::RenamedBeforeDirectoryFlush
                | Crash::DirectoryFlushed
                | Crash::Reopened
                | Crash::HighWaterAdvanced
        );
        assert_eq!(
            recovered.sequence(),
            u64::from(expected_new),
            "at {point:?}"
        );
        assert_eq!(
            recovered.contains_connector(connector.connector_id()),
            expected_new,
            "at {point:?}"
        );

        let converged = reopened.append_canonical_delta(&delta).unwrap();
        assert_eq!(
            converged.sequence(),
            1,
            "retry did not converge at {point:?}"
        );
        assert_eq!(converged.deltas()[0].canonical_bytes(), delta);
    }
}

#[test]
fn authenticated_older_snapshot_is_refused_behind_the_high_water() {
    let directory = private_directory();
    let authority = SigningKey::from_bytes(&[0x61; 32]);
    let high_water = TestHighWater::default();
    let connector = user_connector("rollback-mail", 0x62);
    let delta = add_delta(1, digest(0x21), &connector, digest(0x63), &authority);
    let mut store = open_store(directory.path(), genesis(&authority), high_water.clone()).unwrap();
    store.append_canonical_delta(&delta).unwrap();
    let old_snapshot = fs::read(directory.path().join(STATE_LEAF)).unwrap();
    let registry_head = store.snapshot().unwrap().head_digest();
    let revision = store.revision().unwrap();
    store
        .commit(registry_head, revision, None, b"new-authority-high-water")
        .unwrap();
    drop(store);

    fs::write(directory.path().join(STATE_LEAF), old_snapshot).unwrap();
    assert_eq!(
        open_store(directory.path(), genesis(&authority), high_water).unwrap_err(),
        G4Error::DurableStateRollback
    );
}

#[test]
fn unsafe_state_file_metadata_is_refused_instead_of_treated_as_corruption() {
    let authority = SigningKey::from_bytes(&[0x71; 32]);

    let symlink_directory = private_directory();
    let target = symlink_directory.path().join("target");
    fs::write(&target, b"not-a-store").unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
    symlink(&target, symlink_directory.path().join(STATE_LEAF)).unwrap();
    assert_eq!(
        open_store(
            symlink_directory.path(),
            genesis(&authority),
            TestHighWater::default(),
        )
        .unwrap_err(),
        G4Error::DurableStateIo
    );

    let hardlink_directory = private_directory();
    let target = hardlink_directory.path().join("target");
    fs::write(&target, b"not-a-store").unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
    fs::hard_link(&target, hardlink_directory.path().join(STATE_LEAF)).unwrap();
    assert_eq!(
        open_store(
            hardlink_directory.path(),
            genesis(&authority),
            TestHighWater::default(),
        )
        .unwrap_err(),
        G4Error::DurableStateIo
    );

    let mode_directory = private_directory();
    let state_path = mode_directory.path().join(STATE_LEAF);
    fs::write(&state_path, b"not-a-store").unwrap();
    fs::set_permissions(&state_path, fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(
        open_store(
            mode_directory.path(),
            genesis(&authority),
            TestHighWater::default(),
        )
        .unwrap_err(),
        G4Error::DurableStateIo
    );
}

#[test]
fn generation_narrowing_keeps_a_signed_add_inert_and_removable() {
    let directory = private_directory();
    let authority = SigningKey::from_bytes(&[0x81; 32]);
    let high_water = TestHighWater::default();
    let broad = vec![BoundedConnectorHostV2::new("example.com").unwrap()];
    let narrow = vec![BoundedConnectorHostV2::new("internal.example.com").unwrap()];
    let connector =
        https_user_connector("narrowed-mail", "https://api.example.com/mcp", &broad, 0x82);
    let broad_genesis = ConnectorRegistryStateV2::from_verified_genesis(
        digest(0x21),
        authority.verifying_key().to_bytes(),
        broad,
        vec![],
    )
    .unwrap();
    let delta = add_delta(1, digest(0x21), &connector, digest(0x83), &authority);
    let mut store = open_store(directory.path(), broad_genesis, high_water.clone()).unwrap();
    store.append_canonical_delta(&delta).unwrap();
    drop(store);

    let narrow_genesis = ConnectorRegistryStateV2::from_verified_genesis(
        digest(0x21),
        authority.verifying_key().to_bytes(),
        narrow,
        vec![],
    )
    .unwrap();
    let mut reopened = open_store(directory.path(), narrow_genesis, high_water).unwrap();
    let narrowed = reopened.snapshot().unwrap();
    assert!(!narrowed.contains_connector(connector.connector_id()));
    assert!(narrowed.contains_registered_connector(connector.connector_id()));
    let remove = remove_delta(
        2,
        narrowed.head_digest(),
        connector.connector_id(),
        &authority,
    );
    let removed = reopened.append_canonical_delta(&remove).unwrap();
    assert!(!removed.contains_registered_connector(connector.connector_id()));
    assert_eq!(removed.sequence(), 2);
}

#[test]
fn invalid_duplicate_unknown_remove_and_capacity_do_not_partially_commit() {
    let directory = private_directory();
    let authority = SigningKey::from_bytes(&[0x91; 32]);
    let high_water = TestHighWater::default();
    let mut store = open_store(directory.path(), genesis(&authority), high_water.clone()).unwrap();
    let unknown = remove_delta(1, digest(0x21), digest(0x92), &authority);
    assert_eq!(
        store.append_canonical_delta(&unknown).unwrap_err(),
        G4Error::InvalidDescriptor
    );
    assert_eq!(store.snapshot().unwrap().sequence(), 0);

    let mut first = None;
    for ordinal in 0_u8..16 {
        let connector = user_connector(&format!("capacity-{ordinal}"), 0xa0 + ordinal);
        let state = store.snapshot().unwrap();
        let delta = add_delta(
            state.sequence() + 1,
            state.head_digest(),
            &connector,
            digest(0xc0 + ordinal),
            &authority,
        );
        store.append_canonical_delta(&delta).unwrap();
        first.get_or_insert(connector);
    }
    let before_failure = store.snapshot().unwrap();
    let before_high_water = high_water.head();
    let duplicate = add_delta(
        before_failure.sequence() + 1,
        before_failure.head_digest(),
        first.as_ref().unwrap(),
        digest(0xd1),
        &authority,
    );
    assert_eq!(
        store.append_canonical_delta(&duplicate).unwrap_err(),
        G4Error::InvalidDescriptor
    );
    let overflow_connector = user_connector("capacity-overflow", 0xd2);
    let overflow = add_delta(
        before_failure.sequence() + 1,
        before_failure.head_digest(),
        &overflow_connector,
        digest(0xd3),
        &authority,
    );
    assert_eq!(
        store.append_canonical_delta(&overflow).unwrap_err(),
        G4Error::DescriptorLimitExceeded
    );
    let after_failure = store.snapshot().unwrap();
    assert_eq!(after_failure.sequence(), before_failure.sequence());
    assert_eq!(after_failure.head_digest(), before_failure.head_digest());
    assert_eq!(high_water.head(), before_high_water);
}
