use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;

use ed25519_dalek::{Signer as _, SigningKey};
use savana_execd::{ExecdConnectorRegistryTrustV2, ExecdConnectorRegistryV2};
use savana_kernel_protocol::v2::{
    derive_ed25519_key_id_v2, ActionTemplateIdV2, BoundedConnectorRegistryDeltaV2,
    ConnectorRegistrySyncModeV2, ConnectorRegistrySyncPageV2, ConnectorRegistrySyncRequestV2,
    ConnectorRegistrySyncScopeV2, ConnectorRegistrySyncStatusV2, Digest32V2, DisplayProjectionIdV2,
    Ed25519KeyIdV2, ExecutorIdentityV2, FixedBytes32V2, ImplementationIdV2, ProjectionIdV2,
    RoleIdV2, ToolClassIdV2, UnixMillisV2, VersionV2,
};
use savana_policy_core::v2::{
    connector_host_allowlist_digest_v2, descriptor_digest_v2, AttemptKindV2,
    BoundedConnectorHostV2, BoundedConnectorRetryPolicyV2, ConnectorDescriptorV2,
    ConnectorRegistryStateV2, ConnectorTierV2, DurableStateNamespaceV2, EffectSetV2,
    ExecutorIdempotencyContractV2, G4Error, IdentifierV2, InternalValidatorDeclarationV2,
    RollbackProtectedStateAnchorV2, RollbackProtectedStateHeadV2, UnsignedToolDescriptorV2,
};
use sha2::{Digest as _, Sha256};

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

fn tool(seed: u8) -> UnsignedToolDescriptorV2 {
    let contract = ExecutorIdempotencyContractV2::ConnectorIdempotentByExecutionNonce;
    UnsignedToolDescriptorV2::from_verified_manifest(
        2,
        VersionV2::new(1, 0, 0),
        digest(seed),
        IdentifierV2::new(format!("execd-tool-{seed}")).unwrap(),
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

fn user_stdio_connector(name: &str, seed: u8) -> ConnectorDescriptorV2 {
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
    raw_connector(
        name,
        domain_hash(CONNECTOR_USER_DOMAIN, &id_material.into_writer()),
        |encoder| {
            encoder
                .array(2)
                .unwrap()
                .u16(1)
                .unwrap()
                .bytes(package_digest.as_bytes())
                .unwrap();
        },
        seed,
        &[],
    )
}

fn user_https_connector(
    name: &str,
    url: &str,
    seed: u8,
    allowlist: &[BoundedConnectorHostV2],
) -> ConnectorDescriptorV2 {
    let pin = digest(seed);
    let mut id_material = minicbor::Encoder::new(Vec::new());
    id_material.array(2).unwrap().str(name).unwrap();
    id_material
        .array(3)
        .unwrap()
        .u16(2)
        .unwrap()
        .str(url)
        .unwrap()
        .bytes(pin.as_bytes())
        .unwrap();
    raw_connector(
        name,
        domain_hash(CONNECTOR_USER_DOMAIN, &id_material.into_writer()),
        |encoder| {
            encoder
                .array(3)
                .unwrap()
                .u16(2)
                .unwrap()
                .str(url)
                .unwrap()
                .bytes(pin.as_bytes())
                .unwrap();
        },
        seed,
        allowlist,
    )
}

fn raw_connector(
    name: &str,
    connector_id: Digest32V2,
    encode_transport: impl FnOnce(&mut minicbor::Encoder<Vec<u8>>),
    seed: u8,
    allowlist: &[BoundedConnectorHostV2],
) -> ConnectorDescriptorV2 {
    let descriptor_tool = tool(seed);
    let mut descriptor = minicbor::Encoder::new(Vec::new());
    descriptor
        .array(7)
        .unwrap()
        .bytes(connector_id.as_bytes())
        .unwrap()
        .str(name)
        .unwrap()
        .u16(ConnectorTierV2::UserRegistered as u16)
        .unwrap();
    encode_transport(&mut descriptor);
    descriptor.array(1).unwrap();
    descriptor
        .writer_mut()
        .extend_from_slice(&minicbor::to_vec(descriptor_tool).unwrap());
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
    authority: &SigningKey,
) -> Vec<u8> {
    add_delta_with_signer(
        sequence,
        previous_head,
        connector,
        authority,
        DELTA_SIGNATURE_DOMAIN,
    )
}

fn add_delta_with_signer(
    sequence: u64,
    previous_head: Digest32V2,
    connector: &ConnectorDescriptorV2,
    authority: &SigningKey,
    signature_domain: &[u8],
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
        .bytes(digest(0x77).as_bytes())
        .unwrap()
        .u64(sequence)
        .unwrap();
    let payload = payload.into_writer();
    let payload_digest = domain_hash(DELTA_PAYLOAD_DOMAIN, &payload);
    let signature_digest = domain_hash(signature_domain, payload_digest.as_bytes());
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

#[derive(Clone)]
struct TestAnchor(Arc<Mutex<RollbackProtectedStateHeadV2>>);

impl Default for TestAnchor {
    fn default() -> Self {
        Self(Arc::new(Mutex::new(
            RollbackProtectedStateHeadV2::new(0, digest(0)).unwrap(),
        )))
    }
}

impl RollbackProtectedStateAnchorV2 for TestAnchor {
    fn current_head(&self) -> Result<RollbackProtectedStateHeadV2, G4Error> {
        Ok(*self.0.lock().unwrap())
    }

    fn compare_and_advance(
        &mut self,
        expected: RollbackProtectedStateHeadV2,
        next: RollbackProtectedStateHeadV2,
    ) -> Result<(), G4Error> {
        let mut current = self.0.lock().unwrap();
        if *current != expected || next.sequence() != expected.sequence() + 1 {
            return Err(G4Error::DurableStateRollback);
        }
        *current = next;
        Ok(())
    }
}

fn private_directory() -> tempfile::TempDir {
    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    directory
}

fn enabled_trust(
    authority: &SigningKey,
    manifest: Digest32V2,
    generation: u64,
    allowlist: Vec<BoundedConnectorHostV2>,
) -> ExecdConnectorRegistryTrustV2 {
    ExecdConnectorRegistryTrustV2::from_authenticated_deployment(
        digest(0x31),
        manifest,
        generation,
        digest(0x32),
        derive_ed25519_key_id_v2(authority.verifying_key().to_bytes()),
        authority.verifying_key().to_bytes(),
        allowlist,
        vec![],
    )
    .unwrap()
}

fn namespace() -> DurableStateNamespaceV2 {
    DurableStateNamespaceV2::from_verified_installation(digest(0x31), digest(0x33)).unwrap()
}

fn open_enabled(
    directory: &std::path::Path,
    anchor: TestAnchor,
    trust: ExecdConnectorRegistryTrustV2,
) -> ExecdConnectorRegistryV2 {
    ExecdConnectorRegistryV2::open(
        &directory.join("connector-registry-v2.cbor"),
        [0x34; 32],
        namespace(),
        Box::new(anchor),
        trust,
    )
    .unwrap()
}

fn page_request(
    scope: ConnectorRegistrySyncScopeV2,
    base: &ConnectorRegistryStateV2,
    source: &ConnectorRegistryStateV2,
    deltas: Vec<Vec<u8>>,
    claimed_page_head: Digest32V2,
) -> ConnectorRegistrySyncRequestV2 {
    let final_sequence = base.sequence() + u64::try_from(deltas.len()).unwrap();
    let page = ConnectorRegistrySyncPageV2::new(
        base.sequence(),
        base.head_digest(),
        final_sequence,
        claimed_page_head,
        source.sequence(),
        source.head_digest(),
        deltas
            .into_iter()
            .map(|delta| BoundedConnectorRegistryDeltaV2::new(delta).unwrap())
            .collect(),
    )
    .unwrap();
    ConnectorRegistrySyncRequestV2::new(scope, ConnectorRegistrySyncModeV2::ApplyPage(page))
        .unwrap()
}

#[test]
fn zero_authority_is_genesis_only_and_dispatch_uses_the_live_head() {
    // Catches treating the disabled authority as a delta-sync capability and
    // catches admission against a caller-selected or stale digest.
    let directory = private_directory();
    let installation_id = digest(0x11);
    let genesis = digest(0x12);
    let trust = ExecdConnectorRegistryTrustV2::from_authenticated_deployment(
        installation_id,
        digest(0x13),
        7,
        genesis,
        Ed25519KeyIdV2::new([0; 32]),
        [0; 32],
        vec![],
        vec![],
    )
    .unwrap();
    let namespace =
        DurableStateNamespaceV2::from_verified_installation(installation_id, digest(0x14)).unwrap();
    let registry = ExecdConnectorRegistryV2::open(
        &directory.path().join("connector-registry-v2.cbor"),
        [0x15; 32],
        namespace,
        Box::new(TestAnchor::default()),
        trust,
    )
    .unwrap();

    let probe = ConnectorRegistrySyncRequestV2::new(
        registry.authenticated_scope(),
        ConnectorRegistrySyncModeV2::Probe,
    )
    .unwrap();
    let response = registry.synchronize(&probe).unwrap();
    assert_eq!(
        response.status(),
        ConnectorRegistrySyncStatusV2::DisabledGenesisOnly
    );
    assert_eq!(response.local_sequence(), 0);
    assert_eq!(response.local_head_digest(), genesis);

    let guard = registry.admit_head(genesis).unwrap();
    assert_eq!(guard.head_digest(), genesis);
    assert!(registry.admit_head(digest(0x16)).is_err());
}

#[test]
fn behind_by_one_refuses_old_head_then_converges_after_independent_sync() {
    let authority = SigningKey::from_bytes(&[0x41; 32]);
    let trust = enabled_trust(&authority, digest(0x42), 9, vec![]);
    let base = trust.genesis().clone();
    let connector = user_stdio_connector("behind-one", 0x43);
    let tool_digest = descriptor_digest_v2(&connector.tool_descriptors()[0]).unwrap();
    let delta = add_delta(1, base.head_digest(), &connector, &authority);
    let mut source = base.clone();
    source.replay_canonical_delta(&delta).unwrap();
    let directory = private_directory();
    let registry = open_enabled(directory.path(), TestAnchor::default(), trust);

    assert!(registry.admit_head(source.head_digest()).is_err());
    let request = page_request(
        registry.authenticated_scope(),
        &base,
        &source,
        vec![delta],
        source.head_digest(),
    );
    let response = registry.synchronize(&request).unwrap();
    assert_eq!(response.status(), ConnectorRegistrySyncStatusV2::Converged);
    assert_eq!(response.local_sequence(), 1);
    assert!(registry.admit_head(base.head_digest()).is_err());
    let guard = registry.admit_head(source.head_digest()).unwrap();
    let resolved = guard
        .resolve_active_tool_connector(connector.connector_id(), tool_digest)
        .unwrap();
    assert_eq!(resolved.canonical_bytes(), connector.canonical_bytes());
}

#[test]
fn multi_page_chain_reports_behind_then_converges_and_reopens_without_partial_later_page() {
    const FIRST_PAGE_DELTAS: usize = 256;
    const TOTAL_DELTAS: usize = FIRST_PAGE_DELTAS + 2;

    let authority = SigningKey::from_bytes(&[0x44; 32]);
    let wrong_authority = SigningKey::from_bytes(&[0x45; 32]);
    let trust = enabled_trust(&authority, digest(0x46), 17, vec![]);
    let base = trust.genesis().clone();
    let connector = user_stdio_connector("multi-page", 0x47);
    let mut source = base.clone();
    let mut deltas = Vec::with_capacity(TOTAL_DELTAS);
    for index in 0..TOTAL_DELTAS {
        let sequence = u64::try_from(index + 1).unwrap();
        let delta = if sequence % 2 == 1 {
            add_delta(sequence, source.head_digest(), &connector, &authority)
        } else {
            remove_delta(
                sequence,
                source.head_digest(),
                connector.connector_id(),
                &authority,
            )
        };
        source.replay_canonical_delta(&delta).unwrap();
        deltas.push(delta);
    }

    let mut after_first_page = base.clone();
    for delta in &deltas[..FIRST_PAGE_DELTAS] {
        after_first_page.replay_canonical_delta(delta).unwrap();
    }
    let mut after_penultimate_delta = after_first_page.clone();
    after_penultimate_delta
        .replay_canonical_delta(&deltas[FIRST_PAGE_DELTAS])
        .unwrap();

    let directory = private_directory();
    let anchor = TestAnchor::default();
    let registry = open_enabled(directory.path(), anchor.clone(), trust.clone());
    let probe = ConnectorRegistrySyncRequestV2::new(
        registry.authenticated_scope(),
        ConnectorRegistrySyncModeV2::Probe,
    )
    .unwrap();
    let response = registry.synchronize(&probe).unwrap();
    assert_eq!(response.status(), ConnectorRegistrySyncStatusV2::Behind);
    assert_eq!(response.local_sequence(), 0);
    assert_eq!(response.local_head_digest(), base.head_digest());

    let first_page = page_request(
        registry.authenticated_scope(),
        &base,
        &source,
        deltas[..FIRST_PAGE_DELTAS].to_vec(),
        after_first_page.head_digest(),
    );
    let response = registry.synchronize(&first_page).unwrap();
    assert_eq!(response.status(), ConnectorRegistrySyncStatusV2::Behind);
    assert_eq!(response.local_sequence(), FIRST_PAGE_DELTAS as u64);
    assert_eq!(response.local_head_digest(), after_first_page.head_digest());

    let invalid_last = remove_delta(
        TOTAL_DELTAS as u64,
        after_penultimate_delta.head_digest(),
        connector.connector_id(),
        &wrong_authority,
    );
    let invalid_later_page = page_request(
        registry.authenticated_scope(),
        &after_first_page,
        &source,
        vec![deltas[FIRST_PAGE_DELTAS].clone(), invalid_last],
        source.head_digest(),
    );
    assert!(registry.synchronize(&invalid_later_page).is_err());
    assert_eq!(
        registry
            .admit_head(after_first_page.head_digest())
            .unwrap()
            .sequence(),
        FIRST_PAGE_DELTAS as u64
    );
    assert!(registry.admit_head(source.head_digest()).is_err());
    drop(registry);

    let reopened = open_enabled(directory.path(), anchor.clone(), trust.clone());
    assert_eq!(
        reopened
            .admit_head(after_first_page.head_digest())
            .unwrap()
            .sequence(),
        FIRST_PAGE_DELTAS as u64
    );
    let final_page = page_request(
        reopened.authenticated_scope(),
        &after_first_page,
        &source,
        deltas[FIRST_PAGE_DELTAS..].to_vec(),
        source.head_digest(),
    );
    let response = reopened.synchronize(&final_page).unwrap();
    assert_eq!(response.status(), ConnectorRegistrySyncStatusV2::Converged);
    assert_eq!(response.local_sequence(), TOTAL_DELTAS as u64);
    assert_eq!(response.local_head_digest(), source.head_digest());
    assert_eq!(
        reopened
            .admit_head(source.head_digest())
            .unwrap()
            .sequence(),
        TOTAL_DELTAS as u64
    );
    drop(reopened);

    let final_reopen = open_enabled(directory.path(), anchor, trust);
    let final_guard = final_reopen.admit_head(source.head_digest()).unwrap();
    assert_eq!(final_guard.sequence(), TOTAL_DELTAS as u64);
    assert_eq!(final_guard.head_digest(), source.head_digest());
}

#[test]
fn wrong_key_domain_gap_fork_and_claimed_head_leave_execd_at_genesis() {
    let authority = SigningKey::from_bytes(&[0x51; 32]);
    let wrong = SigningKey::from_bytes(&[0x52; 32]);
    let connector = user_stdio_connector("attack", 0x53);
    let trust = enabled_trust(&authority, digest(0x54), 10, vec![]);
    let base = trust.genesis().clone();
    let correct = add_delta(1, base.head_digest(), &connector, &authority);
    let mut source = base.clone();
    source.replay_canonical_delta(&correct).unwrap();
    let attacks = [
        add_delta(1, base.head_digest(), &connector, &wrong),
        add_delta_with_signer(
            1,
            base.head_digest(),
            &connector,
            &authority,
            b"wrong.connector.delta.domain\0",
        ),
        add_delta(2, base.head_digest(), &connector, &authority),
        add_delta(1, digest(0x55), &connector, &authority),
    ];
    for attack in attacks {
        let directory = private_directory();
        let registry = open_enabled(
            directory.path(),
            TestAnchor::default(),
            enabled_trust(&authority, digest(0x54), 10, vec![]),
        );
        let request = page_request(
            registry.authenticated_scope(),
            &base,
            &source,
            vec![attack],
            source.head_digest(),
        );
        assert!(registry.synchronize(&request).is_err());
        assert_eq!(
            registry.admit_head(base.head_digest()).unwrap().sequence(),
            0
        );
    }

    let directory = private_directory();
    let registry = open_enabled(directory.path(), TestAnchor::default(), trust);
    let mut second_source = source.clone();
    let second = user_stdio_connector("second", 0x56);
    let second_delta = add_delta(2, source.head_digest(), &second, &authority);
    second_source.replay_canonical_delta(&second_delta).unwrap();
    let wrong_claim = page_request(
        registry.authenticated_scope(),
        &base,
        &second_source,
        vec![correct],
        digest(0x57),
    );
    assert!(registry.synchronize(&wrong_claim).is_err());
    assert_eq!(
        registry.admit_head(base.head_digest()).unwrap().sequence(),
        0
    );
}

#[test]
fn a_bad_second_delta_never_persists_or_publishes_the_first_page_entry() {
    let authority = SigningKey::from_bytes(&[0x61; 32]);
    let wrong = SigningKey::from_bytes(&[0x62; 32]);
    let trust = enabled_trust(&authority, digest(0x63), 11, vec![]);
    let base = trust.genesis().clone();
    let first_connector = user_stdio_connector("first", 0x64);
    let first = add_delta(1, base.head_digest(), &first_connector, &authority);
    let mut after_first = base.clone();
    after_first.replay_canonical_delta(&first).unwrap();
    let second_connector = user_stdio_connector("second", 0x65);
    let valid_second = add_delta(2, after_first.head_digest(), &second_connector, &authority);
    let invalid_second = add_delta(2, after_first.head_digest(), &second_connector, &wrong);
    let mut source = after_first;
    source.replay_canonical_delta(&valid_second).unwrap();
    let directory = private_directory();
    let anchor = TestAnchor::default();
    let registry = open_enabled(directory.path(), anchor.clone(), trust.clone());
    let request = page_request(
        registry.authenticated_scope(),
        &base,
        &source,
        vec![first, invalid_second],
        source.head_digest(),
    );
    assert!(registry.synchronize(&request).is_err());
    assert_eq!(
        registry.admit_head(base.head_digest()).unwrap().sequence(),
        0
    );
    drop(registry);

    let reopened = open_enabled(directory.path(), anchor, trust);
    assert_eq!(
        reopened.admit_head(base.head_digest()).unwrap().sequence(),
        0
    );
}

#[test]
fn mixed_generation_is_refused_and_narrowing_keeps_history_registered_but_inactive() {
    let authority = SigningKey::from_bytes(&[0x71; 32]);
    let broad = vec![BoundedConnectorHostV2::new("example.com").unwrap()];
    let narrow = vec![BoundedConnectorHostV2::new("internal.example.com").unwrap()];
    let broad_trust = enabled_trust(&authority, digest(0x72), 12, broad.clone());
    let base = broad_trust.genesis().clone();
    let connector =
        user_https_connector("narrowed", "https://api.example.com:9443/mcp", 0x73, &broad);
    let tool_digest = descriptor_digest_v2(&connector.tool_descriptors()[0]).unwrap();
    let delta = add_delta(1, base.head_digest(), &connector, &authority);
    let mut source = base.clone();
    source.replay_canonical_delta(&delta).unwrap();
    let directory = private_directory();
    let anchor = TestAnchor::default();
    let registry = open_enabled(directory.path(), anchor.clone(), broad_trust);

    let wrong_scope = ConnectorRegistrySyncScopeV2::new(
        digest(0x31),
        digest(0x72),
        13,
        digest(0x32),
        derive_ed25519_key_id_v2(authority.verifying_key().to_bytes()),
        FixedBytes32V2::new(authority.verifying_key().to_bytes()),
        connector_host_allowlist_digest_v2(&broad).unwrap(),
    )
    .unwrap();
    let wrong_generation =
        ConnectorRegistrySyncRequestV2::new(wrong_scope, ConnectorRegistrySyncModeV2::Probe)
            .unwrap();
    assert!(registry.synchronize(&wrong_generation).is_err());

    let request = page_request(
        registry.authenticated_scope(),
        &base,
        &source,
        vec![delta],
        source.head_digest(),
    );
    registry.synchronize(&request).unwrap();
    drop(registry);

    let narrowed = open_enabled(
        directory.path(),
        anchor,
        enabled_trust(&authority, digest(0x74), 13, narrow),
    );
    let guard = narrowed.admit_head(source.head_digest()).unwrap();
    assert!(guard.contains_registered_connector(connector.connector_id()));
    assert!(guard
        .resolve_active_tool_connector(connector.connector_id(), tool_digest)
        .is_err());
}

#[test]
fn corrupt_state_recovers_only_while_the_authenticated_anchor_is_genesis() {
    let authority = SigningKey::from_bytes(&[0x81; 32]);
    let trust = enabled_trust(&authority, digest(0x82), 14, vec![]);
    let directory = private_directory();
    let state_path = directory.path().join("connector-registry-v2.cbor");
    fs::write(&state_path, b"tampered").unwrap();
    fs::set_permissions(&state_path, fs::Permissions::from_mode(0o600)).unwrap();
    let recovered = open_enabled(directory.path(), TestAnchor::default(), trust.clone());
    assert_eq!(
        recovered
            .admit_head(trust.genesis().head_digest())
            .unwrap()
            .sequence(),
        0
    );

    let connector = user_stdio_connector("durable", 0x83);
    let base = trust.genesis().clone();
    let delta = add_delta(1, base.head_digest(), &connector, &authority);
    let mut source = base.clone();
    source.replay_canonical_delta(&delta).unwrap();
    let anchor = TestAnchor::default();
    let committed_directory = private_directory();
    let committed = open_enabled(committed_directory.path(), anchor.clone(), trust.clone());
    let request = page_request(
        committed.authenticated_scope(),
        &base,
        &source,
        vec![delta],
        source.head_digest(),
    );
    committed.synchronize(&request).unwrap();
    drop(committed);
    fs::write(
        committed_directory
            .path()
            .join("connector-registry-v2.cbor"),
        b"tampered",
    )
    .unwrap();
    assert!(ExecdConnectorRegistryV2::open(
        &committed_directory
            .path()
            .join("connector-registry-v2.cbor"),
        [0x34; 32],
        namespace(),
        Box::new(anchor),
        trust,
    )
    .is_err());
}

#[test]
fn replaying_an_old_delta_at_the_live_head_is_atomic_and_refused() {
    let authority = SigningKey::from_bytes(&[0x91; 32]);
    let trust = enabled_trust(&authority, digest(0x92), 15, vec![]);
    let base = trust.genesis().clone();
    let connector = user_stdio_connector("replay", 0x93);
    let delta = add_delta(1, base.head_digest(), &connector, &authority);
    let mut source = base.clone();
    source.replay_canonical_delta(&delta).unwrap();
    let directory = private_directory();
    let registry = open_enabled(directory.path(), TestAnchor::default(), trust);
    let first = page_request(
        registry.authenticated_scope(),
        &base,
        &source,
        vec![delta.clone()],
        source.head_digest(),
    );
    registry.synchronize(&first).unwrap();

    let replay_page = ConnectorRegistrySyncPageV2::new(
        source.sequence(),
        source.head_digest(),
        2,
        digest(0x94),
        2,
        digest(0x94),
        vec![BoundedConnectorRegistryDeltaV2::new(delta).unwrap()],
    )
    .unwrap();
    let replay = ConnectorRegistrySyncRequestV2::new(
        registry.authenticated_scope(),
        ConnectorRegistrySyncModeV2::ApplyPage(replay_page),
    )
    .unwrap();
    assert!(registry.synchronize(&replay).is_err());
    let guard = registry.admit_head(source.head_digest()).unwrap();
    assert_eq!(guard.sequence(), 1);
}

#[test]
fn dispatch_head_guard_blocks_registry_publication_until_the_effect_boundary_releases() {
    let authority = SigningKey::from_bytes(&[0xa1; 32]);
    let trust = enabled_trust(&authority, digest(0xa2), 16, vec![]);
    let base = trust.genesis().clone();
    let connector = user_stdio_connector("linearized", 0xa3);
    let delta = add_delta(1, base.head_digest(), &connector, &authority);
    let mut source = base.clone();
    source.replay_canonical_delta(&delta).unwrap();
    let directory = private_directory();
    let registry = Arc::new(open_enabled(directory.path(), TestAnchor::default(), trust));
    let request = page_request(
        registry.authenticated_scope(),
        &base,
        &source,
        vec![delta],
        source.head_digest(),
    );
    let dispatch_guard = registry.admit_head(base.head_digest()).unwrap();
    let (started_tx, started_rx) = mpsc::sync_channel(0);
    let (finished_tx, finished_rx) = mpsc::sync_channel(0);
    let syncing = Arc::clone(&registry);
    let worker = thread::spawn(move || {
        started_tx.send(()).unwrap();
        let result = syncing.synchronize(&request);
        finished_tx.send(result).unwrap();
    });
    started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    assert!(finished_rx.recv_timeout(Duration::from_millis(50)).is_err());
    assert_eq!(dispatch_guard.sequence(), 0);
    drop(dispatch_guard);

    let response = finished_rx
        .recv_timeout(Duration::from_secs(1))
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), ConnectorRegistrySyncStatusV2::Converged);
    worker.join().unwrap();
    assert_eq!(
        registry
            .admit_head(source.head_digest())
            .unwrap()
            .sequence(),
        1
    );
}
