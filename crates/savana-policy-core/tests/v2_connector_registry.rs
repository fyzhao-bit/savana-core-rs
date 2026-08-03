use ed25519_dalek::{Signer as _, SigningKey};
use savana_kernel_protocol::v2::{
    ActionTemplateIdV2, Digest32V2, DisplayProjectionIdV2, ExecutorIdentityV2, ImplementationIdV2,
    ProjectionIdV2, RoleIdV2, ToolClassIdV2, UnixMillisV2, VersionV2,
};
use savana_policy_core::v2::{
    user_tier_host_allowed_v2, AttemptKindV2, BoundedConnectorHostV2,
    BoundedConnectorRetryPolicyV2, BoundedConnectorUrlV2, ConnectorDescriptorV2,
    ConnectorRegistryStateV2, ConnectorStructuralRoleV2, ConnectorTierV2, ConnectorTransportV2,
    DeploymentHardLimitsV2, EffectSetV2, ExecutorIdempotencyContractV2, G4Error, IdentifierV2,
    InternalValidatorDeclarationV2, SharedVerifiedConnectorRegistryV2, UnsignedToolDescriptorV2,
};
use sha2::{Digest as _, Sha256};

const CONNECTOR_DEPLOYMENT_DOMAIN: &[u8] = b"savana.connector.deployment.v2\0";
const CONNECTOR_USER_DOMAIN: &[u8] = b"savana.connector.user.v2\0";
const DELTA_PAYLOAD_DOMAIN: &[u8] = b"savana.connector-registry.delta.v2.payload\0";
const DELTA_SIGNED_DOMAIN: &[u8] = b"savana.connector-registry.delta.v2.signed\0";
const DELTA_SIGNATURE_DOMAIN: &[u8] = b"savana.connector-registry.delta.v2.signature\0";
const REGISTRY_HEAD_DOMAIN: &[u8] = b"savana.connector-registry.head.v2\0";

#[derive(Clone)]
enum RawTransport<'a> {
    Stdio(Digest32V2),
    Https(&'a str, Digest32V2),
}

enum RawOperation<'a> {
    Add(&'a ConnectorDescriptorV2),
    Remove(Digest32V2),
}

fn digest(byte: u8) -> Digest32V2 {
    Digest32V2::new([byte; 32])
}

fn domain_hash(domain: &[u8], bytes: &[u8]) -> Digest32V2 {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(bytes);
    Digest32V2::new(hasher.finalize().into())
}

fn encode_raw_transport(encoder: &mut minicbor::Encoder<Vec<u8>>, transport: &RawTransport<'_>) {
    match transport {
        RawTransport::Stdio(package_digest) => {
            encoder
                .array(2)
                .unwrap()
                .u16(1)
                .unwrap()
                .bytes(package_digest.as_bytes())
                .unwrap();
        }
        RawTransport::Https(url, tls_identity_pin) => {
            encoder
                .array(3)
                .unwrap()
                .u16(2)
                .unwrap()
                .str(url)
                .unwrap()
                .bytes(tls_identity_pin.as_bytes())
                .unwrap();
        }
    }
}

fn connector_id_for(tier: u16, display_name: &str, transport: &RawTransport<'_>) -> Digest32V2 {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder.array(2).unwrap().str(display_name).unwrap();
    encode_raw_transport(&mut encoder, transport);
    let domain = match tier {
        1 => CONNECTOR_DEPLOYMENT_DOMAIN,
        2 => CONNECTOR_USER_DOMAIN,
        _ => CONNECTOR_USER_DOMAIN,
    };
    domain_hash(domain, &encoder.into_writer())
}

fn raw_descriptor_bytes(
    encoded_tier: u16,
    id_tier: u16,
    display_name: &str,
    transport: RawTransport<'_>,
    tool_descriptors: &[UnsignedToolDescriptorV2],
    requested_effects: u16,
    descriptor_version: u64,
) -> Vec<u8> {
    raw_descriptor_bytes_with_role(
        encoded_tier,
        id_tier,
        display_name,
        transport,
        tool_descriptors,
        requested_effects,
        ConnectorStructuralRoleV2::Sink.tag(),
        descriptor_version,
    )
}

#[allow(clippy::too_many_arguments)]
fn raw_descriptor_bytes_with_role(
    encoded_tier: u16,
    id_tier: u16,
    display_name: &str,
    transport: RawTransport<'_>,
    tool_descriptors: &[UnsignedToolDescriptorV2],
    requested_effects: u16,
    structural_role: u16,
    descriptor_version: u64,
) -> Vec<u8> {
    let connector_id = connector_id_for(id_tier, display_name, &transport);
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(8)
        .unwrap()
        .bytes(connector_id.as_bytes())
        .unwrap()
        .str(display_name)
        .unwrap()
        .u16(encoded_tier)
        .unwrap();
    encode_raw_transport(&mut encoder, &transport);
    encoder.array(tool_descriptors.len() as u64).unwrap();
    for descriptor in tool_descriptors {
        encoder
            .writer_mut()
            .extend_from_slice(&minicbor::to_vec(descriptor).unwrap());
    }
    encoder
        .u16(requested_effects)
        .unwrap()
        .u16(structural_role)
        .unwrap()
        .u64(descriptor_version)
        .unwrap();
    encoder.into_writer()
}

#[test]
fn structural_role_is_closed_signed_and_canonical_before_descriptor_version() {
    let authority = SigningKey::from_bytes(&[0x29; 32]);
    let tool = tool_descriptor(0x2a, EffectSetV2::SEND);
    let sink = raw_descriptor_bytes_with_role(
        2,
        2,
        "role-signed",
        RawTransport::Stdio(digest(0x2b)),
        std::slice::from_ref(&tool),
        EffectSetV2::SEND.bits(),
        ConnectorStructuralRoleV2::Sink.tag(),
        1,
    );
    let transform = raw_descriptor_bytes_with_role(
        2,
        2,
        "role-signed",
        RawTransport::Stdio(digest(0x2b)),
        std::slice::from_ref(&tool),
        EffectSetV2::SEND.bits(),
        ConnectorStructuralRoleV2::Transform.tag(),
        1,
    );
    let sink = ConnectorDescriptorV2::from_canonical_bytes(&sink, &[]).unwrap();
    let transform = ConnectorDescriptorV2::from_canonical_bytes(&transform, &[]).unwrap();
    assert_eq!(sink.structural_role(), ConnectorStructuralRoleV2::Sink);
    assert_eq!(
        transform.structural_role(),
        ConnectorStructuralRoleV2::Transform
    );
    assert_ne!(sink.canonical_bytes(), transform.canonical_bytes());

    let genesis = digest(0x2c);
    let sink_delta = signed_delta_bytes(
        1,
        genesis,
        RawOperation::Add(&sink),
        digest(0x2d),
        1,
        &authority,
    );
    let transform_delta = signed_delta_bytes(
        1,
        genesis,
        RawOperation::Add(&transform),
        digest(0x2d),
        1,
        &authority,
    );
    assert_ne!(
        domain_hash(DELTA_SIGNED_DOMAIN, &sink_delta),
        domain_hash(DELTA_SIGNED_DOMAIN, &transform_delta),
    );

    for role in [0, 4, u16::MAX] {
        let invalid = raw_descriptor_bytes_with_role(
            2,
            2,
            "role-invalid",
            RawTransport::Stdio(digest(0x2e)),
            std::slice::from_ref(&tool),
            EffectSetV2::SEND.bits(),
            role,
            1,
        );
        assert_eq!(
            ConnectorDescriptorV2::from_canonical_bytes(&invalid, &[]).unwrap_err(),
            G4Error::InvalidDescriptor,
        );
    }

    let mut missing = minicbor::Encoder::new(Vec::new());
    let connector_id = connector_id_for(2, "role-missing", &RawTransport::Stdio(digest(0x2f)));
    missing
        .array(7)
        .unwrap()
        .bytes(connector_id.as_bytes())
        .unwrap()
        .str("role-missing")
        .unwrap()
        .u16(2)
        .unwrap()
        .array(2)
        .unwrap()
        .u16(1)
        .unwrap()
        .bytes(digest(0x2f).as_bytes())
        .unwrap()
        .array(1)
        .unwrap();
    missing
        .writer_mut()
        .extend_from_slice(&minicbor::to_vec(&tool).unwrap());
    missing
        .u16(EffectSetV2::SEND.bits())
        .unwrap()
        .u64(1)
        .unwrap();
    assert_eq!(
        ConnectorDescriptorV2::from_canonical_bytes(&missing.into_writer(), &[]).unwrap_err(),
        G4Error::NonCanonicalDescriptor,
    );
}

fn tool_descriptor(seed: u8, effects: EffectSetV2) -> UnsignedToolDescriptorV2 {
    let contract = ExecutorIdempotencyContractV2::ConnectorIdempotentByExecutionNonce;
    UnsignedToolDescriptorV2::from_verified_manifest(
        2,
        VersionV2::new(1, 0, 0),
        digest(seed),
        IdentifierV2::new(format!("tool-{seed}")).unwrap(),
        ActionTemplateIdV2::new(u32::from(seed) + 1),
        ToolClassIdV2::new(u32::from(seed) + 2),
        digest(seed.wrapping_add(1)),
        digest(seed.wrapping_add(2)),
        vec![RoleIdV2::new(1)],
        effects,
        AttemptKindV2::ToolWrite,
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

fn parse_descriptor(
    tier: ConnectorTierV2,
    name: &str,
    transport: RawTransport<'_>,
    effects: EffectSetV2,
    allowlist: &[BoundedConnectorHostV2],
    seed: u8,
) -> ConnectorDescriptorV2 {
    let bytes = raw_descriptor_bytes(
        tier as u16,
        tier as u16,
        name,
        transport,
        &[tool_descriptor(seed, effects)],
        effects.bits(),
        1,
    );
    ConnectorDescriptorV2::from_canonical_bytes(&bytes, allowlist).unwrap()
}

fn signed_delta_bytes(
    sequence: u64,
    previous_head: Digest32V2,
    operation: RawOperation<'_>,
    settlement_digest: Digest32V2,
    issued_at_unix_ms: u64,
    signing_key: &SigningKey,
) -> Vec<u8> {
    signed_delta_bytes_with_domain(
        sequence,
        previous_head,
        operation,
        settlement_digest,
        issued_at_unix_ms,
        signing_key,
        DELTA_SIGNATURE_DOMAIN,
    )
}

#[allow(clippy::too_many_arguments)]
fn signed_delta_bytes_with_domain(
    sequence: u64,
    previous_head: Digest32V2,
    operation: RawOperation<'_>,
    settlement_digest: Digest32V2,
    issued_at_unix_ms: u64,
    signing_key: &SigningKey,
    signature_domain: &[u8],
) -> Vec<u8> {
    let mut payload_encoder = minicbor::Encoder::new(Vec::new());
    payload_encoder
        .array(6)
        .unwrap()
        .u16(1)
        .unwrap()
        .u64(sequence)
        .unwrap()
        .bytes(previous_head.as_bytes())
        .unwrap();
    match operation {
        RawOperation::Add(descriptor) => {
            payload_encoder.array(2).unwrap().u16(1).unwrap();
            payload_encoder
                .writer_mut()
                .extend_from_slice(descriptor.canonical_bytes());
        }
        RawOperation::Remove(connector_id) => {
            payload_encoder
                .array(2)
                .unwrap()
                .u16(2)
                .unwrap()
                .bytes(connector_id.as_bytes())
                .unwrap();
        }
    }
    payload_encoder
        .bytes(settlement_digest.as_bytes())
        .unwrap()
        .u64(issued_at_unix_ms)
        .unwrap();
    let payload = payload_encoder.into_writer();
    let payload_digest = domain_hash(DELTA_PAYLOAD_DOMAIN, &payload);
    let signature_digest = domain_hash(signature_domain, payload_digest.as_bytes());
    let signature = signing_key.sign(signature_digest.as_bytes()).to_bytes();

    let mut complete = minicbor::Encoder::new(Vec::new());
    complete.array(3).unwrap();
    complete.writer_mut().extend_from_slice(&payload);
    complete
        .bytes(payload_digest.as_bytes())
        .unwrap()
        .bytes(&signature)
        .unwrap();
    complete.into_writer()
}

fn expected_head(previous_head: Digest32V2, signed_delta: Digest32V2) -> Digest32V2 {
    let mut material = [0_u8; 64];
    material[..32].copy_from_slice(previous_head.as_bytes());
    material[32..].copy_from_slice(signed_delta.as_bytes());
    domain_hash(REGISTRY_HEAD_DOMAIN, &material)
}

#[allow(clippy::too_many_arguments)]
fn assert_state_unchanged(
    state: &ConnectorRegistryStateV2,
    expected_head: Digest32V2,
    expected_sequence: u64,
    expected_active_connectors: usize,
    expected_active_users: usize,
    expected_registered_connectors: usize,
    expected_registered_users: usize,
    expected_active_tools: usize,
    expected_registered_tools: usize,
    expected_deltas: usize,
) {
    assert_eq!(state.head_digest(), expected_head);
    assert_eq!(state.sequence(), expected_sequence);
    assert_eq!(state.active_connector_count(), expected_active_connectors);
    assert_eq!(state.active_user_connector_count(), expected_active_users);
    assert_eq!(
        state.registered_connector_count(),
        expected_registered_connectors
    );
    assert_eq!(
        state.registered_user_connector_count(),
        expected_registered_users
    );
    assert_eq!(state.active_tool_descriptor_count(), expected_active_tools);
    assert_eq!(
        state.registered_tool_descriptor_count(),
        expected_registered_tools
    );
    assert_eq!(state.deltas().len(), expected_deltas);
}

#[test]
fn host_predicate_normalizes_idna_and_uses_label_boundaries_and_exact_ips() {
    let unicode = BoundedConnectorHostV2::new("BÜCHER.Example.").unwrap();
    assert_eq!(unicode.as_str(), "xn--bcher-kva.example");
    assert!(
        user_tier_host_allowed_v2("api.bücher.example.", std::slice::from_ref(&unicode)).unwrap()
    );
    assert!(!user_tier_host_allowed_v2("evilbücher.example", &[unicode]).unwrap());

    let suffix = BoundedConnectorHostV2::new("example.com").unwrap();
    assert!(user_tier_host_allowed_v2("example.com", std::slice::from_ref(&suffix)).unwrap());
    assert!(user_tier_host_allowed_v2("api.example.com.", std::slice::from_ref(&suffix)).unwrap());
    assert!(!user_tier_host_allowed_v2("evilexample.com", &[suffix]).unwrap());
    assert!(!user_tier_host_allowed_v2("example.com", &[]).unwrap());

    let ipv4 = BoundedConnectorHostV2::new("192.0.2.1").unwrap();
    assert!(user_tier_host_allowed_v2("192.0.2.1", std::slice::from_ref(&ipv4)).unwrap());
    assert!(!user_tier_host_allowed_v2("192.0.2.10", &[ipv4]).unwrap());
    let ipv6 = BoundedConnectorHostV2::new("[2001:db8::1]").unwrap();
    assert!(user_tier_host_allowed_v2("[2001:0db8::1]", &[ipv6]).unwrap());

    for malformed in [
        "",
        ".",
        "example.com..",
        "bad..example.com",
        "-bad.example",
        "bad-.example",
        "white space.example",
        "example.com:443",
    ] {
        assert_eq!(
            user_tier_host_allowed_v2(malformed, &[]).unwrap_err(),
            G4Error::InvalidDescriptor,
            "malformed host {malformed:?} must fail closed"
        );
    }
}

#[test]
fn bounded_https_url_is_canonical_and_rejects_deceptive_or_non_https_forms() {
    let url = BoundedConnectorUrlV2::new("HTTPS://BÜCHER.Example.:443/mcp?q=1").unwrap();
    assert_eq!(url.as_str(), "https://xn--bcher-kva.example/mcp?q=1");
    assert_eq!(url.host().as_str(), "xn--bcher-kva.example");

    for invalid in [
        "http://example.com/mcp",
        "https://@example.com/mcp",
        "https://user@example.com/mcp",
        "https://user:secret@example.com/mcp",
        "https://example.com/mcp#approve-me",
        "https://example.com../mcp",
        "https://bad..example.com/mcp",
        "https:///missing-host",
    ] {
        assert_eq!(
            BoundedConnectorUrlV2::new(invalid).unwrap_err(),
            G4Error::InvalidDescriptor,
            "URL {invalid:?} must fail closed"
        );
    }
}

#[test]
fn descriptor_round_trip_separates_tier_ids_and_enforces_tier_and_tool_ceilings() {
    let allowlist = vec![BoundedConnectorHostV2::new("example.com").unwrap()];
    let transport = RawTransport::Https("https://api.example.com/mcp", digest(0x31));
    let requested = EffectSetV2::READ.union(EffectSetV2::SEND);
    let shipped = parse_descriptor(
        ConnectorTierV2::DeploymentShipped,
        "mail-api",
        transport.clone(),
        requested,
        &[],
        0x32,
    );
    let user = parse_descriptor(
        ConnectorTierV2::UserRegistered,
        "mail-api",
        transport.clone(),
        requested,
        &allowlist,
        0x32,
    );
    assert_ne!(shipped.connector_id(), user.connector_id());
    assert_eq!(
        shipped.connector_id(),
        connector_id_for(1, "mail-api", &transport)
    );
    assert_eq!(
        user.connector_id(),
        connector_id_for(2, "mail-api", &transport)
    );
    assert_eq!(user.display_name().as_str(), "mail-api");
    assert_eq!(user.tier(), ConnectorTierV2::UserRegistered);
    assert_eq!(user.requested_effects(), requested);
    assert_eq!(user.tool_descriptors().len(), 1);
    assert_eq!(user.descriptor_version(), 1);
    assert_eq!(
        ConnectorDescriptorV2::from_canonical_bytes(user.canonical_bytes(), &allowlist).unwrap(),
        user
    );
    assert!(matches!(
        user.transport(),
        ConnectorTransportV2::Https { canonical_url, .. }
            if canonical_url.as_str() == "https://api.example.com/mcp"
    ));

    let mismatched_tier_id = raw_descriptor_bytes(
        2,
        1,
        "mail-api",
        transport.clone(),
        &[tool_descriptor(0x33, requested)],
        requested.bits(),
        1,
    );
    assert_eq!(
        ConnectorDescriptorV2::from_canonical_bytes(&mismatched_tier_id, &allowlist).unwrap_err(),
        G4Error::InvalidDescriptor
    );

    let past_user_ceiling = requested.union(EffectSetV2::FINAL_RELEASE);
    let final_release = raw_descriptor_bytes(
        2,
        2,
        "mail-api",
        transport.clone(),
        &[tool_descriptor(0x34, past_user_ceiling)],
        past_user_ceiling.bits(),
        1,
    );
    assert_eq!(
        ConnectorDescriptorV2::from_canonical_bytes(&final_release, &allowlist).unwrap_err(),
        G4Error::InvalidDescriptor
    );

    let tool_past_connector = raw_descriptor_bytes(
        2,
        2,
        "mail-api",
        transport,
        &[tool_descriptor(0x35, EffectSetV2::SEND)],
        EffectSetV2::READ.bits(),
        1,
    );
    assert_eq!(
        ConnectorDescriptorV2::from_canonical_bytes(&tool_past_connector, &allowlist).unwrap_err(),
        G4Error::InvalidDescriptor
    );
}

#[test]
fn descriptor_rejects_forbidden_hosts_zero_fields_limits_and_noncanonical_cbor() {
    let tool = tool_descriptor(0x40, EffectSetV2::READ);
    let outside = raw_descriptor_bytes(
        2,
        2,
        "outside",
        RawTransport::Https("https://outside.example/mcp", digest(0x41)),
        std::slice::from_ref(&tool),
        EffectSetV2::READ.bits(),
        1,
    );
    assert_eq!(
        ConnectorDescriptorV2::from_canonical_bytes(&outside, &[]).unwrap_err(),
        G4Error::InvalidDescriptor
    );
    let shipped_outside = raw_descriptor_bytes(
        1,
        1,
        "outside",
        RawTransport::Https("https://outside.example/mcp", digest(0x41)),
        std::slice::from_ref(&tool),
        EffectSetV2::READ.bits(),
        1,
    );
    assert!(ConnectorDescriptorV2::from_canonical_bytes(&shipped_outside, &[]).is_ok());

    for invalid in [
        raw_descriptor_bytes(
            2,
            2,
            "bad name",
            RawTransport::Stdio(digest(0x42)),
            std::slice::from_ref(&tool),
            EffectSetV2::READ.bits(),
            1,
        ),
        raw_descriptor_bytes(
            2,
            2,
            "zero-package",
            RawTransport::Stdio(digest(0)),
            std::slice::from_ref(&tool),
            EffectSetV2::READ.bits(),
            1,
        ),
        raw_descriptor_bytes(
            2,
            2,
            "zero-pin",
            RawTransport::Https("https://example.com/mcp", digest(0)),
            std::slice::from_ref(&tool),
            EffectSetV2::READ.bits(),
            1,
        ),
        raw_descriptor_bytes(
            2,
            2,
            "zero-version",
            RawTransport::Stdio(digest(0x43)),
            std::slice::from_ref(&tool),
            EffectSetV2::READ.bits(),
            0,
        ),
        raw_descriptor_bytes(
            2,
            2,
            "no-tools",
            RawTransport::Stdio(digest(0x44)),
            &[],
            EffectSetV2::READ.bits(),
            1,
        ),
    ] {
        assert_eq!(
            ConnectorDescriptorV2::from_canonical_bytes(&invalid, &[]).unwrap_err(),
            G4Error::InvalidDescriptor
        );
    }

    let valid = raw_descriptor_bytes(
        2,
        2,
        "canonical",
        RawTransport::Stdio(digest(0x45)),
        std::slice::from_ref(&tool),
        EffectSetV2::READ.bits(),
        1,
    );
    let mut nonminimal = valid.clone();
    assert_eq!(nonminimal[0], 0x88);
    nonminimal.splice(0..1, [0x98, 0x08]);
    assert_eq!(
        ConnectorDescriptorV2::from_canonical_bytes(&nonminimal, &[]).unwrap_err(),
        G4Error::NonCanonicalDescriptor
    );
    let mut trailing = valid;
    trailing.push(0);
    assert_eq!(
        ConnectorDescriptorV2::from_canonical_bytes(&trailing, &[]).unwrap_err(),
        G4Error::NonCanonicalDescriptor
    );

    let too_many_tools = (0..=DeploymentHardLimitsV2::compiled().max_active_tool_descriptors())
        .map(|_| tool_descriptor(0x46, EffectSetV2::READ))
        .collect::<Vec<_>>();
    let overflow = raw_descriptor_bytes(
        2,
        2,
        "too-many-tools",
        RawTransport::Stdio(digest(0x47)),
        &too_many_tools,
        EffectSetV2::READ.bits(),
        1,
    );
    assert_eq!(
        ConnectorDescriptorV2::from_canonical_bytes(&overflow, &[]).unwrap_err(),
        G4Error::DescriptorLimitExceeded
    );
    assert_eq!(DeploymentHardLimitsV2::compiled().max_user_connectors(), 16);
}

#[test]
fn signed_chain_add_remove_readd_uses_exact_domains_and_removes_either_tier() {
    let authority = SigningKey::from_bytes(&[0x51; 32]);
    let genesis = digest(0x52);
    let allowlist = vec![BoundedConnectorHostV2::new("example.com").unwrap()];
    let shipped = parse_descriptor(
        ConnectorTierV2::DeploymentShipped,
        "shipped",
        RawTransport::Stdio(digest(0x53)),
        EffectSetV2::READ,
        &[],
        0x54,
    );
    let shipped_id = shipped.connector_id();
    let user = parse_descriptor(
        ConnectorTierV2::UserRegistered,
        "user-added",
        RawTransport::Https("https://api.example.com/mcp", digest(0x55)),
        EffectSetV2::READ.union(EffectSetV2::SEND),
        &allowlist,
        0x56,
    );
    let user_id = user.connector_id();
    let mut state = ConnectorRegistryStateV2::from_verified_genesis(
        genesis,
        authority.verifying_key().to_bytes(),
        allowlist,
        vec![shipped],
    )
    .unwrap();
    assert_state_unchanged(&state, genesis, 0, 1, 0, 1, 0, 1, 1, 0);

    let add = signed_delta_bytes(
        1,
        genesis,
        RawOperation::Add(&user),
        digest(0x57),
        10,
        &authority,
    );
    let add_signed_digest = domain_hash(DELTA_SIGNED_DOMAIN, &add);
    let add_head = expected_head(genesis, add_signed_digest);
    state.apply_canonical_delta(&add).unwrap();
    assert_state_unchanged(&state, add_head, 1, 2, 1, 2, 1, 2, 2, 1);
    assert!(state.contains_connector(user_id));
    let applied = state.deltas().last().unwrap();
    assert_eq!(applied.payload_digest(), payload_digest_from_complete(&add));
    assert_eq!(applied.signed_digest(), add_signed_digest);
    assert_eq!(applied.canonical_bytes(), add);

    let remove_shipped = signed_delta_bytes(
        2,
        add_head,
        RawOperation::Remove(shipped_id),
        digest(0),
        11,
        &authority,
    );
    state.apply_canonical_delta(&remove_shipped).unwrap();
    assert!(!state.contains_connector(shipped_id));
    assert!(state.contains_connector(user_id));

    let previous = state.head_digest();
    let remove_user = signed_delta_bytes(
        3,
        previous,
        RawOperation::Remove(user_id),
        digest(0),
        12,
        &authority,
    );
    state.apply_canonical_delta(&remove_user).unwrap();
    assert!(!state.contains_connector(user_id));

    let previous = state.head_digest();
    let readd = signed_delta_bytes(
        4,
        previous,
        RawOperation::Add(&user),
        digest(0x58),
        13,
        &authority,
    );
    state.apply_canonical_delta(&readd).unwrap();
    assert!(state.contains_connector(user_id));
    assert_eq!(state.active_user_connector_count(), 1);
}

#[test]
fn delta_signature_sequence_predecessor_replay_fork_and_canonicality_fail_atomically() {
    let authority = SigningKey::from_bytes(&[0x61; 32]);
    let wrong_authority = SigningKey::from_bytes(&[0x62; 32]);
    let genesis = digest(0x63);
    let user = parse_descriptor(
        ConnectorTierV2::UserRegistered,
        "atomic",
        RawTransport::Stdio(digest(0x64)),
        EffectSetV2::READ,
        &[],
        0x65,
    );
    let mut state = ConnectorRegistryStateV2::from_verified_genesis(
        genesis,
        authority.verifying_key().to_bytes(),
        vec![],
        vec![],
    )
    .unwrap();

    let missing_settlement = signed_delta_bytes(
        1,
        genesis,
        RawOperation::Add(&user),
        digest(0),
        10,
        &authority,
    );
    assert_eq!(
        state
            .apply_canonical_delta(&missing_settlement)
            .unwrap_err(),
        G4Error::InvalidDescriptor
    );
    assert_state_unchanged(&state, genesis, 0, 0, 0, 0, 0, 0, 0, 0);

    let wrong_key = signed_delta_bytes(
        1,
        genesis,
        RawOperation::Add(&user),
        digest(0x66),
        10,
        &wrong_authority,
    );
    assert_eq!(
        state.apply_canonical_delta(&wrong_key).unwrap_err(),
        G4Error::InvalidDescriptorSignature
    );
    assert_state_unchanged(&state, genesis, 0, 0, 0, 0, 0, 0, 0, 0);

    let wrong_domain = signed_delta_bytes_with_domain(
        1,
        genesis,
        RawOperation::Add(&user),
        digest(0x66),
        10,
        &authority,
        b"savana.connector-registry.delta.v2.wrong\0",
    );
    assert_eq!(
        state.apply_canonical_delta(&wrong_domain).unwrap_err(),
        G4Error::InvalidDescriptorSignature
    );
    assert_state_unchanged(&state, genesis, 0, 0, 0, 0, 0, 0, 0, 0);

    let gap = signed_delta_bytes(
        2,
        genesis,
        RawOperation::Add(&user),
        digest(0x66),
        10,
        &authority,
    );
    assert_eq!(
        state.apply_canonical_delta(&gap).unwrap_err(),
        G4Error::InvalidDescriptor
    );
    let wrong_previous = signed_delta_bytes(
        1,
        digest(0x67),
        RawOperation::Add(&user),
        digest(0x66),
        10,
        &authority,
    );
    assert_eq!(
        state.apply_canonical_delta(&wrong_previous).unwrap_err(),
        G4Error::InvalidDescriptor
    );
    assert_state_unchanged(&state, genesis, 0, 0, 0, 0, 0, 0, 0, 0);

    let valid = signed_delta_bytes(
        1,
        genesis,
        RawOperation::Add(&user),
        digest(0x66),
        10,
        &authority,
    );
    let mut bad_signature = valid.clone();
    *bad_signature.last_mut().unwrap() ^= 1;
    assert_eq!(
        state.apply_canonical_delta(&bad_signature).unwrap_err(),
        G4Error::InvalidDescriptorSignature
    );
    let mut noncanonical = valid.clone();
    noncanonical.splice(0..1, [0x98, 0x03]);
    assert_eq!(
        state.apply_canonical_delta(&noncanonical).unwrap_err(),
        G4Error::NonCanonicalDescriptor
    );
    assert_state_unchanged(&state, genesis, 0, 0, 0, 0, 0, 0, 0, 0);

    state.apply_canonical_delta(&valid).unwrap();
    let active_head = state.head_digest();
    assert_eq!(
        state.apply_canonical_delta(&valid).unwrap_err(),
        G4Error::InvalidDescriptor
    );
    let fork = signed_delta_bytes(
        1,
        genesis,
        RawOperation::Remove(user.connector_id()),
        digest(0),
        11,
        &authority,
    );
    assert_eq!(
        state.apply_canonical_delta(&fork).unwrap_err(),
        G4Error::InvalidDescriptor
    );
    assert_state_unchanged(&state, active_head, 1, 1, 1, 1, 1, 1, 1, 1);
}

#[test]
fn runtime_adds_only_user_tier_and_refuses_collisions_unknown_removals_and_capacity() {
    let authority = SigningKey::from_bytes(&[0x71; 32]);
    let genesis = digest(0x72);
    let shipped = parse_descriptor(
        ConnectorTierV2::DeploymentShipped,
        "cannot-mint",
        RawTransport::Stdio(digest(0x73)),
        EffectSetV2::READ,
        &[],
        0x74,
    );
    let mut state = ConnectorRegistryStateV2::from_verified_genesis(
        genesis,
        authority.verifying_key().to_bytes(),
        vec![],
        vec![],
    )
    .unwrap();
    let mint_shipped = signed_delta_bytes(
        1,
        genesis,
        RawOperation::Add(&shipped),
        digest(0x75),
        1,
        &authority,
    );
    assert_eq!(
        state.apply_canonical_delta(&mint_shipped).unwrap_err(),
        G4Error::InvalidDescriptor
    );
    assert_state_unchanged(&state, genesis, 0, 0, 0, 0, 0, 0, 0, 0);

    let unknown_remove = signed_delta_bytes(
        1,
        genesis,
        RawOperation::Remove(digest(0x76)),
        digest(0),
        1,
        &authority,
    );
    assert_eq!(
        state.apply_canonical_delta(&unknown_remove).unwrap_err(),
        G4Error::InvalidDescriptor
    );

    let mut last_added = None;
    for ordinal in 0_u8..16 {
        let name = format!("user-{ordinal}");
        let connector = parse_descriptor(
            ConnectorTierV2::UserRegistered,
            &name,
            RawTransport::Stdio(digest(0x80 + ordinal)),
            EffectSetV2::READ,
            &[],
            0xa0 + ordinal,
        );
        let delta = signed_delta_bytes(
            state.sequence() + 1,
            state.head_digest(),
            RawOperation::Add(&connector),
            digest(0xc0 + ordinal),
            u64::from(ordinal) + 1,
            &authority,
        );
        state.apply_canonical_delta(&delta).unwrap();
        last_added = Some(connector);
    }
    assert_eq!(state.active_user_connector_count(), 16);

    let duplicate = last_added.unwrap();
    let duplicate_delta = signed_delta_bytes(
        state.sequence() + 1,
        state.head_digest(),
        RawOperation::Add(&duplicate),
        digest(0xd1),
        20,
        &authority,
    );
    assert_eq!(
        state.apply_canonical_delta(&duplicate_delta).unwrap_err(),
        G4Error::InvalidDescriptor
    );

    let seventeenth = parse_descriptor(
        ConnectorTierV2::UserRegistered,
        "user-seventeen",
        RawTransport::Stdio(digest(0xd2)),
        EffectSetV2::READ,
        &[],
        0xd3,
    );
    let overflow = signed_delta_bytes(
        state.sequence() + 1,
        state.head_digest(),
        RawOperation::Add(&seventeenth),
        digest(0xd4),
        21,
        &authority,
    );
    assert_eq!(
        state.apply_canonical_delta(&overflow).unwrap_err(),
        G4Error::DescriptorLimitExceeded
    );

    let removed_id = duplicate.connector_id();
    let remove = signed_delta_bytes(
        state.sequence() + 1,
        state.head_digest(),
        RawOperation::Remove(removed_id),
        digest(0),
        22,
        &authority,
    );
    state.apply_canonical_delta(&remove).unwrap();
    let after_remove = signed_delta_bytes(
        state.sequence() + 1,
        state.head_digest(),
        RawOperation::Add(&seventeenth),
        digest(0xd5),
        23,
        &authority,
    );
    state.apply_canonical_delta(&after_remove).unwrap();
    assert_eq!(state.active_user_connector_count(), 16);
    assert!(state.contains_connector(seventeenth.connector_id()));
}

#[test]
fn zero_authority_is_genesis_only_and_narrowed_connectors_are_inert_but_removable() {
    let authority = SigningKey::from_bytes(&[0xe1; 32]);
    let genesis = digest(0xe2);
    let broad = vec![BoundedConnectorHostV2::new("example.com").unwrap()];
    let narrow = vec![BoundedConnectorHostV2::new("internal.example.com").unwrap()];
    let connector = parse_descriptor(
        ConnectorTierV2::UserRegistered,
        "host-policy",
        RawTransport::Https("https://api.example.com/mcp", digest(0xe3)),
        EffectSetV2::READ,
        &broad,
        0xe4,
    );
    let add = signed_delta_bytes(
        1,
        genesis,
        RawOperation::Add(&connector),
        digest(0xe5),
        1,
        &authority,
    );

    let mut disabled =
        ConnectorRegistryStateV2::from_verified_genesis(genesis, [0; 32], broad.clone(), vec![])
            .unwrap();
    assert_eq!(
        disabled.apply_canonical_delta(&add).unwrap_err(),
        G4Error::InvalidRegistryPublisher
    );
    assert_state_unchanged(&disabled, genesis, 0, 0, 0, 0, 0, 0, 0, 0);

    let mut broad_state = ConnectorRegistryStateV2::from_verified_genesis(
        genesis,
        authority.verifying_key().to_bytes(),
        broad,
        vec![],
    )
    .unwrap();
    broad_state.apply_canonical_delta(&add).unwrap();
    assert!(broad_state.contains_connector(connector.connector_id()));
    assert!(broad_state.contains_registered_connector(connector.connector_id()));
    let shared = SharedVerifiedConnectorRegistryV2::from_verified_state(broad_state).unwrap();

    let mut narrowed_state = ConnectorRegistryStateV2::from_verified_genesis(
        genesis,
        authority.verifying_key().to_bytes(),
        narrow,
        vec![],
    )
    .unwrap();
    assert_eq!(
        narrowed_state.apply_canonical_delta(&add).unwrap_err(),
        G4Error::InvalidDescriptor
    );
    assert_state_unchanged(&narrowed_state, genesis, 0, 0, 0, 0, 0, 0, 0, 0);

    narrowed_state.replay_canonical_delta(&add).unwrap();
    let narrowed_head = expected_head(genesis, domain_hash(DELTA_SIGNED_DOMAIN, &add));
    assert_state_unchanged(&narrowed_state, narrowed_head, 1, 0, 0, 1, 1, 0, 1, 1);
    assert!(!narrowed_state.contains_connector(connector.connector_id()));
    assert!(narrowed_state.contains_registered_connector(connector.connector_id()));
    shared
        .replace_verified_standing_policy_state(narrowed_state)
        .unwrap();
    let narrowed_snapshot = shared.snapshot().unwrap();
    assert!(!narrowed_snapshot.contains_connector(connector.connector_id()));
    assert!(narrowed_snapshot.contains_registered_connector(connector.connector_id()));

    let remove = signed_delta_bytes(
        2,
        narrowed_head,
        RawOperation::Remove(connector.connector_id()),
        digest(0),
        2,
        &authority,
    );
    shared.verify_and_apply_canonical_delta(&remove).unwrap();
    let narrowed_state = shared.snapshot().unwrap();
    assert_state_unchanged(
        &narrowed_state,
        expected_head(narrowed_head, domain_hash(DELTA_SIGNED_DOMAIN, &remove)),
        2,
        0,
        0,
        0,
        0,
        0,
        0,
        2,
    );
    assert!(!narrowed_state.contains_registered_connector(connector.connector_id()));
}

fn payload_digest_from_complete(bytes: &[u8]) -> Digest32V2 {
    let mut decoder = minicbor::Decoder::new(bytes);
    assert_eq!(decoder.array().unwrap(), Some(3));
    let payload_start = decoder.position();
    decoder.skip().unwrap();
    let payload_end = decoder.position();
    let payload_digest = decoder.bytes().unwrap();
    assert_eq!(payload_digest.len(), 32);
    assert_eq!(decoder.bytes().unwrap().len(), 64);
    assert_eq!(decoder.position(), bytes.len());
    let expected = domain_hash(DELTA_PAYLOAD_DOMAIN, &bytes[payload_start..payload_end]);
    assert_eq!(payload_digest, expected.as_bytes());
    expected
}
