use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::sync::Arc;

use ed25519_dalek::{Signature, VerifyingKey};
use savana_kernel_protocol::v2::Digest32V2;
use sha2::{Digest as _, Sha256};
use url::{Host, Url};

use super::descriptor::{
    decode_unsigned_descriptor, descriptor_digest_v2, MAX_ACTIVE_TOOL_DESCRIPTORS,
};
use super::{DeploymentHardLimitsV2, EffectSetV2, G4Error, IdentifierV2, UnsignedToolDescriptorV2};

const CONNECTOR_DESCRIPTOR_FIELDS_V2: u64 = 8;
const CONNECTOR_IDENTITY_FIELDS_V2: u64 = 2;
const CONNECTOR_TRANSPORT_STDIO_FIELDS_V2: u64 = 2;
const CONNECTOR_TRANSPORT_HTTPS_FIELDS_V2: u64 = 3;
const CONNECTOR_DELTA_FIELDS_V2: u64 = 3;
const CONNECTOR_DELTA_PAYLOAD_FIELDS_V2: u64 = 6;
const CONNECTOR_DELTA_OPERATION_FIELDS_V2: u64 = 2;
const CONNECTOR_DELTA_SCHEMA_VERSION_V2: u16 = 1;
const CONNECTOR_TRANSPORT_STDIO_TAG_V2: u16 = 1;
const CONNECTOR_TRANSPORT_HTTPS_TAG_V2: u16 = 2;
const CONNECTOR_DELTA_ADD_TAG_V2: u16 = 1;
const CONNECTOR_DELTA_REMOVE_TAG_V2: u16 = 2;
const MAX_CONNECTOR_HOST_INPUT_BYTES_V2: usize = 1_024;
const MAX_CONNECTOR_HOST_BYTES_V2: usize = 253;
const MAX_CONNECTOR_URL_BYTES_V2: usize = 4_096;
const CONNECTOR_DEPLOYMENT_ID_DOMAIN_V2: &[u8] = b"savana.connector.deployment.v2\0";
const CONNECTOR_USER_ID_DOMAIN_V2: &[u8] = b"savana.connector.user.v2\0";
const CONNECTOR_DEPLOYMENT_GENESIS_DOMAIN_V2: &[u8] = b"savana.connector.deployment-genesis.v2\0";
const CONNECTOR_DELTA_PAYLOAD_DOMAIN_V2: &[u8] = b"savana.connector-registry.delta.v2.payload\0";
const CONNECTOR_DELTA_SIGNED_DOMAIN_V2: &[u8] = b"savana.connector-registry.delta.v2.signed\0";
const CONNECTOR_DELTA_SIGNATURE_DOMAIN_V2: &[u8] =
    b"savana.connector-registry.delta.v2.signature\0";
const CONNECTOR_REGISTRY_HEAD_DOMAIN_V2: &[u8] = b"savana.connector-registry.head.v2\0";
const CONNECTOR_HOST_ALLOWLIST_DIGEST_DOMAIN_V2: &[u8] =
    b"savana.connector-registry.host-allowlist.v2\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u16)]
pub enum ConnectorTierV2 {
    DeploymentShipped = 1,
    UserRegistered = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u16)]
pub enum ConnectorStructuralRoleV2 {
    Source = 1,
    Transform = 2,
    Sink = 3,
}

impl ConnectorStructuralRoleV2 {
    pub const fn tag(self) -> u16 {
        self as u16
    }

    fn from_tag(tag: u16) -> Option<Self> {
        match tag {
            1 => Some(Self::Source),
            2 => Some(Self::Transform),
            3 => Some(Self::Sink),
            _ => None,
        }
    }
}

impl ConnectorTierV2 {
    pub const fn tag(self) -> u16 {
        self as u16
    }

    fn from_tag(tag: u16) -> Option<Self> {
        match tag {
            1 => Some(Self::DeploymentShipped),
            2 => Some(Self::UserRegistered),
            _ => None,
        }
    }

    fn id_domain(self) -> &'static [u8] {
        match self {
            Self::DeploymentShipped => CONNECTOR_DEPLOYMENT_ID_DOMAIN_V2,
            Self::UserRegistered => CONNECTOR_USER_ID_DOMAIN_V2,
        }
    }

    fn allows_effects(self, requested: EffectSetV2) -> bool {
        match self {
            Self::DeploymentShipped => true,
            Self::UserRegistered => !requested.contains(EffectSetV2::FINAL_RELEASE),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BoundedConnectorNameV2(IdentifierV2);

impl BoundedConnectorNameV2 {
    pub fn new(value: impl Into<String>) -> Result<Self, G4Error> {
        IdentifierV2::new(value)
            .map(Self)
            .map_err(|_| G4Error::InvalidDescriptor)
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum ConnectorHostKindV2 {
    Domain,
    Ip(IpAddr),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BoundedConnectorHostV2 {
    canonical: String,
    kind: ConnectorHostKindV2,
}

impl BoundedConnectorHostV2 {
    pub fn new(value: impl AsRef<str>) -> Result<Self, G4Error> {
        let value = value.as_ref();
        if value.is_empty()
            || value.len() > MAX_CONNECTOR_HOST_INPUT_BYTES_V2
            || value.chars().any(char::is_control)
        {
            return Err(G4Error::InvalidDescriptor);
        }

        let mut host = Host::parse(value).map_err(|_| G4Error::InvalidDescriptor)?;
        if let Host::Domain(domain) = &host {
            if let Some(without_dot) = domain.strip_suffix('.') {
                if without_dot.is_empty() || without_dot.ends_with('.') {
                    return Err(G4Error::InvalidDescriptor);
                }
                host = Host::parse(without_dot).map_err(|_| G4Error::InvalidDescriptor)?;
            }
        }

        let (canonical, kind) = match host {
            Host::Domain(domain) => {
                validate_canonical_domain(&domain)?;
                (domain, ConnectorHostKindV2::Domain)
            }
            Host::Ipv4(address) => (
                address.to_string(),
                ConnectorHostKindV2::Ip(IpAddr::V4(address)),
            ),
            Host::Ipv6(address) => (
                format!("[{address}]"),
                ConnectorHostKindV2::Ip(IpAddr::V6(address)),
            ),
        };
        if canonical.len() > MAX_CONNECTOR_HOST_BYTES_V2 {
            return Err(G4Error::InvalidDescriptor);
        }
        Ok(Self { canonical, kind })
    }

    pub fn as_str(&self) -> &str {
        &self.canonical
    }

    pub const fn is_ip_literal(&self) -> bool {
        matches!(self.kind, ConnectorHostKindV2::Ip(_))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BoundedConnectorUrlV2 {
    canonical: String,
    host: BoundedConnectorHostV2,
}

impl BoundedConnectorUrlV2 {
    pub fn new(value: impl AsRef<str>) -> Result<Self, G4Error> {
        let value = value.as_ref();
        let after_scheme = value.get(8..).ok_or(G4Error::InvalidDescriptor)?;
        let authority_end = after_scheme
            .find(['/', '?', '#', '\\'])
            .unwrap_or(after_scheme.len());
        let raw_authority = &after_scheme[..authority_end];
        if value.is_empty()
            || value.len() > MAX_CONNECTOR_URL_BYTES_V2
            || value.chars().any(char::is_control)
            || !value
                .get(..8)
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case("https://"))
            || raw_authority.is_empty()
            || raw_authority.contains('@')
        {
            return Err(G4Error::InvalidDescriptor);
        }
        let mut parsed = Url::parse(value).map_err(|_| G4Error::InvalidDescriptor)?;
        if parsed.scheme() != "https" || parsed.cannot_be_a_base() || parsed.fragment().is_some() {
            return Err(G4Error::InvalidDescriptor);
        }
        let host =
            BoundedConnectorHostV2::new(parsed.host_str().ok_or(G4Error::InvalidDescriptor)?)?;
        parsed
            .set_host(Some(host.as_str()))
            .map_err(|_| G4Error::InvalidDescriptor)?;
        if parsed.port() == Some(443) {
            parsed
                .set_port(None)
                .map_err(|_| G4Error::InvalidDescriptor)?;
        }
        let canonical = parsed.to_string();
        if canonical.len() > MAX_CONNECTOR_URL_BYTES_V2 {
            return Err(G4Error::InvalidDescriptor);
        }
        Ok(Self { canonical, host })
    }

    pub fn as_str(&self) -> &str {
        &self.canonical
    }

    pub const fn host(&self) -> &BoundedConnectorHostV2 {
        &self.host
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ConnectorTransportV2 {
    Stdio {
        package_digest: Digest32V2,
    },
    Https {
        canonical_url: BoundedConnectorUrlV2,
        tls_identity_pin: Digest32V2,
    },
}

impl ConnectorTransportV2 {
    pub fn stdio(package_digest: Digest32V2) -> Result<Self, G4Error> {
        if is_zero(package_digest.as_bytes()) {
            return Err(G4Error::InvalidDescriptor);
        }
        Ok(Self::Stdio { package_digest })
    }

    pub fn https(
        canonical_url: BoundedConnectorUrlV2,
        tls_identity_pin: Digest32V2,
    ) -> Result<Self, G4Error> {
        if is_zero(tls_identity_pin.as_bytes()) {
            return Err(G4Error::InvalidDescriptor);
        }
        Ok(Self::Https {
            canonical_url,
            tls_identity_pin,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectorDescriptorV2 {
    canonical_bytes: Vec<u8>,
    connector_id: Digest32V2,
    display_name: BoundedConnectorNameV2,
    tier: ConnectorTierV2,
    transport: ConnectorTransportV2,
    tool_descriptors: Vec<UnsignedToolDescriptorV2>,
    requested_effects: EffectSetV2,
    structural_role: ConnectorStructuralRoleV2,
    descriptor_version: u64,
}

impl ConnectorDescriptorV2 {
    pub fn from_canonical_bytes(
        bytes: &[u8],
        user_host_allowlist: &[BoundedConnectorHostV2],
    ) -> Result<Self, G4Error> {
        let value = Self::from_canonical_bytes_intrinsic(bytes)?;
        if !connector_is_active_under_allowlist(&value, user_host_allowlist)? {
            return Err(G4Error::InvalidDescriptor);
        }
        Ok(value)
    }

    /// Parses the exact signed descriptor for an agentd-local projection.
    ///
    /// This deliberately performs only intrinsic canonical and descriptor
    /// validation. Deployment allowlist authorization remains a kerneld
    /// decision and callers must not treat this projection parser as approval.
    pub fn from_canonical_bytes_for_local_projection(bytes: &[u8]) -> Result<Self, G4Error> {
        Self::from_canonical_bytes_intrinsic(bytes)
    }

    /// Identity a deployment-shipped connector derives from its name and
    /// transport. Its tool descriptors name this identity as their provider.
    pub fn deployment_shipped_id(
        display_name: &BoundedConnectorNameV2,
        transport: &ConnectorTransportV2,
    ) -> Result<Digest32V2, G4Error> {
        connector_id_v2(ConnectorTierV2::DeploymentShipped, display_name, transport)
    }

    /// Deployment authoring only. Startup never trusts this value directly; it
    /// re-parses the canonical bytes carried by the measured configuration.
    pub fn new_deployment_shipped(
        display_name: BoundedConnectorNameV2,
        transport: ConnectorTransportV2,
        tool_descriptors: Vec<UnsignedToolDescriptorV2>,
        requested_effects: EffectSetV2,
        structural_role: ConnectorStructuralRoleV2,
        descriptor_version: u64,
    ) -> Result<Self, G4Error> {
        let connector_id = Self::deployment_shipped_id(&display_name, &transport)?;
        let value = Self::from_decoded(
            connector_id,
            display_name,
            ConnectorTierV2::DeploymentShipped,
            transport,
            tool_descriptors,
            requested_effects,
            structural_role,
            descriptor_version,
        )?;
        if value
            .tool_descriptors
            .iter()
            .any(|tool| tool.provider_identity_digest() != connector_id)
        {
            return Err(G4Error::InvalidDescriptor);
        }
        Ok(value)
    }

    /// Genesis head binding one exact, connector-id-ordered deployment set.
    /// Registry synchronization compares heads only, so an unbound genesis
    /// would let kerneld and execd start from different connector sets.
    pub fn deployment_genesis_digest(connectors: &[Self]) -> Result<Digest32V2, G4Error> {
        if connectors.is_empty()
            || connectors
                .iter()
                .any(|connector| connector.tier != ConnectorTierV2::DeploymentShipped)
            || connectors
                .windows(2)
                .any(|pair| pair[0].connector_id.as_bytes() >= pair[1].connector_id.as_bytes())
        {
            return Err(G4Error::InvalidDescriptor);
        }
        let mut encoder = minicbor::Encoder::new(Vec::new());
        encoder
            .array(connectors.len() as u64)
            .map_err(|_| G4Error::NonCanonicalDescriptor)?;
        for connector in connectors {
            encoder
                .bytes(&connector.canonical_bytes)
                .map_err(|_| G4Error::NonCanonicalDescriptor)?;
        }
        Ok(domain_hash(
            CONNECTOR_DEPLOYMENT_GENESIS_DOMAIN_V2,
            &encoder.into_writer(),
        ))
    }

    /// Parses the deployment-shipped set carried by a measured daemon
    /// configuration. An empty set keeps the legacy opaque genesis digest; a
    /// non-empty set must be exactly the set that genesis digest commits to,
    /// and every tool must name its own connector as provider.
    pub fn verified_deployment_set(
        genesis_digest: Digest32V2,
        encoded: &[Vec<u8>],
        user_host_allowlist: &[BoundedConnectorHostV2],
    ) -> Result<Vec<Self>, G4Error> {
        let mut connectors = Vec::new();
        connectors
            .try_reserve_exact(encoded.len())
            .map_err(|_| G4Error::AllocationFailure)?;
        for bytes in encoded {
            let connector = Self::from_canonical_bytes(bytes, user_host_allowlist)?;
            if connector.tier != ConnectorTierV2::DeploymentShipped
                || connector
                    .tool_descriptors
                    .iter()
                    .any(|tool| tool.provider_identity_digest() != connector.connector_id)
            {
                return Err(G4Error::InvalidDescriptor);
            }
            connectors.push(connector);
        }
        if !connectors.is_empty() && Self::deployment_genesis_digest(&connectors)? != genesis_digest
        {
            return Err(G4Error::InvalidDescriptor);
        }
        Ok(connectors)
    }

    fn from_canonical_bytes_intrinsic(bytes: &[u8]) -> Result<Self, G4Error> {
        check_connector_object_size(bytes)?;
        let mut decoder = minicbor::Decoder::new(bytes);
        expect_array(&mut decoder, CONNECTOR_DESCRIPTOR_FIELDS_V2)?;
        let connector_id = decode_digest(&mut decoder)?;
        let display_name = BoundedConnectorNameV2::new(
            decoder.str().map_err(|_| G4Error::NonCanonicalDescriptor)?,
        )?;
        let tier = ConnectorTierV2::from_tag(decode_u16(&mut decoder)?)
            .ok_or(G4Error::InvalidDescriptor)?;
        let transport = decode_transport(&mut decoder)?;
        let tool_count =
            decode_bounded_array_length(&mut decoder, MAX_ACTIVE_TOOL_DESCRIPTORS as u64)?;
        let mut tool_descriptors = Vec::new();
        tool_descriptors
            .try_reserve_exact(tool_count)
            .map_err(|_| G4Error::AllocationFailure)?;
        for _ in 0..tool_count {
            let start = decoder.position();
            decoder
                .skip()
                .map_err(|_| G4Error::NonCanonicalDescriptor)?;
            let nested = decoder
                .input()
                .get(start..decoder.position())
                .ok_or(G4Error::NonCanonicalDescriptor)?;
            tool_descriptors.push(decode_unsigned_descriptor(nested)?);
        }
        let requested_effects =
            EffectSetV2::from_bits(decode_u16(&mut decoder)?).ok_or(G4Error::InvalidDescriptor)?;
        let structural_role = ConnectorStructuralRoleV2::from_tag(decode_u16(&mut decoder)?)
            .ok_or(G4Error::InvalidDescriptor)?;
        let descriptor_version = decode_u64(&mut decoder)?;
        require_eof(&decoder, bytes)?;

        let value = Self::from_decoded(
            connector_id,
            display_name,
            tier,
            transport,
            tool_descriptors,
            requested_effects,
            structural_role,
            descriptor_version,
        )?;
        if value.canonical_bytes != bytes {
            return Err(G4Error::NonCanonicalDescriptor);
        }
        Ok(value)
    }

    #[allow(clippy::too_many_arguments)]
    fn from_decoded(
        connector_id: Digest32V2,
        display_name: BoundedConnectorNameV2,
        tier: ConnectorTierV2,
        transport: ConnectorTransportV2,
        tool_descriptors: Vec<UnsignedToolDescriptorV2>,
        requested_effects: EffectSetV2,
        structural_role: ConnectorStructuralRoleV2,
        descriptor_version: u64,
    ) -> Result<Self, G4Error> {
        if descriptor_version == 0
            || tool_descriptors.is_empty()
            || !tier.allows_effects(requested_effects)
            || tool_descriptors
                .iter()
                .any(|descriptor| !requested_effects.contains(descriptor.effects()))
        {
            return Err(G4Error::InvalidDescriptor);
        }
        let mut tool_digests = BTreeSet::new();
        for descriptor in &tool_descriptors {
            let digest = descriptor_digest_v2(descriptor)?;
            if !tool_digests.insert(*digest.as_bytes()) {
                return Err(G4Error::InvalidDescriptor);
            }
        }
        let expected_id = connector_id_v2(tier, &display_name, &transport)?;
        if connector_id != expected_id {
            return Err(G4Error::InvalidDescriptor);
        }

        let mut value = Self {
            canonical_bytes: Vec::new(),
            connector_id,
            display_name,
            tier,
            transport,
            tool_descriptors,
            requested_effects,
            structural_role,
            descriptor_version,
        };
        value.canonical_bytes = encode_descriptor(&value)?;
        check_connector_object_size(&value.canonical_bytes)?;
        Ok(value)
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub const fn connector_id(&self) -> Digest32V2 {
        self.connector_id
    }

    pub const fn display_name(&self) -> &BoundedConnectorNameV2 {
        &self.display_name
    }

    pub const fn tier(&self) -> ConnectorTierV2 {
        self.tier
    }

    pub const fn transport(&self) -> &ConnectorTransportV2 {
        &self.transport
    }

    pub fn tool_descriptors(&self) -> &[UnsignedToolDescriptorV2] {
        &self.tool_descriptors
    }

    pub const fn requested_effects(&self) -> EffectSetV2 {
        self.requested_effects
    }

    pub const fn structural_role(&self) -> ConnectorStructuralRoleV2 {
        self.structural_role
    }

    pub const fn descriptor_version(&self) -> u64 {
        self.descriptor_version
    }
}

pub fn user_tier_host_allowed_v2(
    host: &str,
    allowlist: &[BoundedConnectorHostV2],
) -> Result<bool, G4Error> {
    let candidate = BoundedConnectorHostV2::new(host)?;
    Ok(allowlist
        .iter()
        .any(|allowed| match (&candidate.kind, &allowed.kind) {
            (ConnectorHostKindV2::Ip(candidate), ConnectorHostKindV2::Ip(allowed)) => {
                candidate == allowed
            }
            (ConnectorHostKindV2::Domain, ConnectorHostKindV2::Domain) => {
                candidate.canonical == allowed.canonical
                    || (candidate.canonical.len() > allowed.canonical.len()
                        && candidate.canonical.ends_with(&allowed.canonical)
                        && candidate.canonical.as_bytes()
                            [candidate.canonical.len() - allowed.canonical.len() - 1]
                            == b'.')
            }
            _ => false,
        }))
}

/// Commits the exact canonical standing-policy host list shared by kerneld
/// and execd. The list must already be the strictly ordered deployment value;
/// this function never sorts or widens caller input.
pub fn connector_host_allowlist_digest_v2(
    allowlist: &[BoundedConnectorHostV2],
) -> Result<Digest32V2, G4Error> {
    if allowlist
        .windows(2)
        .any(|pair| pair[0].as_str() >= pair[1].as_str())
    {
        return Err(G4Error::InvalidDescriptor);
    }
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(u64::try_from(allowlist.len()).map_err(|_| G4Error::DescriptorLimitExceeded)?)
        .map_err(|_| G4Error::AllocationFailure)?;
    for host in allowlist {
        encoder
            .str(host.as_str())
            .map_err(|_| G4Error::AllocationFailure)?;
    }
    Ok(domain_hash(
        CONNECTOR_HOST_ALLOWLIST_DIGEST_DOMAIN_V2,
        &encoder.into_writer(),
    ))
}

fn connector_is_active_under_allowlist(
    descriptor: &ConnectorDescriptorV2,
    allowlist: &[BoundedConnectorHostV2],
) -> Result<bool, G4Error> {
    match (descriptor.tier, &descriptor.transport) {
        (ConnectorTierV2::UserRegistered, ConnectorTransportV2::Https { canonical_url, .. }) => {
            user_tier_host_allowed_v2(canonical_url.host().as_str(), allowlist)
        }
        _ => Ok(true),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ConnectorRegistryOperationV2 {
    Add(Arc<ConnectorDescriptorV2>),
    Remove(Digest32V2),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectorRegistryDeltaV2 {
    canonical_bytes: Vec<u8>,
    sequence: u64,
    previous_head_digest: Digest32V2,
    operation: ConnectorRegistryOperationV2,
    settlement_digest: Digest32V2,
    issued_at_unix_ms: u64,
    payload_digest: Digest32V2,
    authority_signature: [u8; 64],
    signed_digest: Digest32V2,
}

/// A registry delta whose complete semantic payload has already cleared the
/// current registry's chain, tier, allowlist, and compiled-limit checks.
///
/// The only operation left to the kerneld-held connector authority is signing
/// [`Self::signature_digest`]. Callers cannot construct this type directly and
/// [`Self::finalize`] verifies the supplied signature before producing a
/// canonical delta.
#[derive(Debug, Clone)]
pub struct PreparedConnectorRegistryDeltaV2 {
    sequence: u64,
    previous_head_digest: Digest32V2,
    operation: ConnectorRegistryOperationV2,
    settlement_digest: Digest32V2,
    issued_at_unix_ms: u64,
    payload_digest: Digest32V2,
    signature_digest: Digest32V2,
    authority: VerifyingKey,
}

impl PreparedConnectorRegistryDeltaV2 {
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    pub const fn previous_head_digest(&self) -> Digest32V2 {
        self.previous_head_digest
    }

    pub const fn settlement_digest(&self) -> Digest32V2 {
        self.settlement_digest
    }

    pub const fn issued_at_unix_ms(&self) -> u64 {
        self.issued_at_unix_ms
    }

    pub const fn signature_digest(&self) -> Digest32V2 {
        self.signature_digest
    }

    pub fn connector_id(&self) -> Digest32V2 {
        match &self.operation {
            ConnectorRegistryOperationV2::Add(descriptor) => descriptor.connector_id(),
            ConnectorRegistryOperationV2::Remove(connector_id) => *connector_id,
        }
    }

    pub const fn is_add(&self) -> bool {
        matches!(self.operation, ConnectorRegistryOperationV2::Add(_))
    }

    pub fn finalize(
        self,
        authority_signature: [u8; 64],
    ) -> Result<ConnectorRegistryDeltaV2, G4Error> {
        let mut delta = ConnectorRegistryDeltaV2 {
            canonical_bytes: Vec::new(),
            sequence: self.sequence,
            previous_head_digest: self.previous_head_digest,
            operation: self.operation,
            settlement_digest: self.settlement_digest,
            issued_at_unix_ms: self.issued_at_unix_ms,
            payload_digest: self.payload_digest,
            authority_signature,
            signed_digest: Digest32V2::new([0; 32]),
        };
        delta.canonical_bytes = encode_delta(&delta)?;
        ConnectorRegistryDeltaV2::from_canonical_bytes_for_state(
            &delta.canonical_bytes,
            &self.authority,
            self.sequence,
            self.previous_head_digest,
        )
    }
}

impl ConnectorRegistryDeltaV2 {
    fn from_canonical_bytes_for_state(
        bytes: &[u8],
        authority: &VerifyingKey,
        expected_sequence: u64,
        expected_previous_head: Digest32V2,
    ) -> Result<Self, G4Error> {
        check_connector_object_size(bytes)?;
        let mut decoder = minicbor::Decoder::new(bytes);
        expect_array(&mut decoder, CONNECTOR_DELTA_FIELDS_V2)?;
        let payload_start = decoder.position();
        decoder
            .skip()
            .map_err(|_| G4Error::NonCanonicalDescriptor)?;
        let payload_end = decoder.position();
        let payload = decoder
            .input()
            .get(payload_start..payload_end)
            .ok_or(G4Error::NonCanonicalDescriptor)?;
        let payload_digest = decode_digest(&mut decoder)?;
        let authority_signature = decode_fixed::<64>(&mut decoder)?;
        require_eof(&decoder, bytes)?;

        if domain_hash(CONNECTOR_DELTA_PAYLOAD_DOMAIN_V2, payload) != payload_digest {
            return Err(G4Error::InvalidDescriptorSignature);
        }
        let signature_digest = domain_hash(
            CONNECTOR_DELTA_SIGNATURE_DOMAIN_V2,
            payload_digest.as_bytes(),
        );
        authority
            .verify_strict(
                signature_digest.as_bytes(),
                &Signature::from_bytes(&authority_signature),
            )
            .map_err(|_| G4Error::InvalidDescriptorSignature)?;
        let decoded = decode_delta_payload(payload, expected_sequence, expected_previous_head)?;

        let mut value = Self {
            canonical_bytes: Vec::new(),
            sequence: decoded.sequence,
            previous_head_digest: decoded.previous_head_digest,
            operation: decoded.operation,
            settlement_digest: decoded.settlement_digest,
            issued_at_unix_ms: decoded.issued_at_unix_ms,
            payload_digest,
            authority_signature,
            signed_digest: Digest32V2::new([0; 32]),
        };
        value.canonical_bytes = encode_delta(&value)?;
        if value.canonical_bytes != bytes {
            return Err(G4Error::NonCanonicalDescriptor);
        }
        value.signed_digest = domain_hash(CONNECTOR_DELTA_SIGNED_DOMAIN_V2, &value.canonical_bytes);
        Ok(value)
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    pub const fn previous_head_digest(&self) -> Digest32V2 {
        self.previous_head_digest
    }

    pub const fn settlement_digest(&self) -> Digest32V2 {
        self.settlement_digest
    }

    pub const fn issued_at_unix_ms(&self) -> u64 {
        self.issued_at_unix_ms
    }

    pub const fn payload_digest(&self) -> Digest32V2 {
        self.payload_digest
    }

    pub const fn authority_signature(&self) -> &[u8; 64] {
        &self.authority_signature
    }

    pub const fn signed_digest(&self) -> Digest32V2 {
        self.signed_digest
    }

    pub fn connector_id(&self) -> Digest32V2 {
        match &self.operation {
            ConnectorRegistryOperationV2::Add(descriptor) => descriptor.connector_id(),
            ConnectorRegistryOperationV2::Remove(connector_id) => *connector_id,
        }
    }

    pub const fn is_add(&self) -> bool {
        matches!(self.operation, ConnectorRegistryOperationV2::Add(_))
    }

    pub fn added_descriptor(&self) -> Option<&ConnectorDescriptorV2> {
        match &self.operation {
            ConnectorRegistryOperationV2::Add(descriptor) => Some(descriptor.as_ref()),
            ConnectorRegistryOperationV2::Remove(_) => None,
        }
    }
}

#[derive(Debug, Clone)]
struct DecodedConnectorDeltaV2 {
    sequence: u64,
    previous_head_digest: Digest32V2,
    operation: ConnectorRegistryOperationV2,
    settlement_digest: Digest32V2,
    issued_at_unix_ms: u64,
}

#[derive(Debug, Clone)]
pub struct ConnectorRegistryStateV2 {
    genesis_digest: Digest32V2,
    head_digest: Digest32V2,
    sequence: u64,
    authority: Option<VerifyingKey>,
    user_host_allowlist: Vec<BoundedConnectorHostV2>,
    registered: BTreeMap<[u8; 32], Arc<ConnectorDescriptorV2>>,
    registered_user_connectors: usize,
    registered_tool_descriptors: usize,
    active: BTreeMap<[u8; 32], Arc<ConnectorDescriptorV2>>,
    active_user_connectors: usize,
    active_tool_descriptors: usize,
    deltas: Vec<ConnectorRegistryDeltaV2>,
}

impl ConnectorRegistryStateV2 {
    /// Constructs the chain genesis from components already authenticated by
    /// the deployment channel. Runtime callers cannot add to this set except
    /// through [`Self::apply_canonical_delta`].
    pub fn from_verified_genesis(
        genesis_digest: Digest32V2,
        connector_authority_public_key: [u8; 32],
        user_host_allowlist: Vec<BoundedConnectorHostV2>,
        deployment_shipped_connectors: Vec<ConnectorDescriptorV2>,
    ) -> Result<Self, G4Error> {
        if is_zero(genesis_digest.as_bytes())
            || user_host_allowlist
                .windows(2)
                .any(|pair| pair[0].as_str() >= pair[1].as_str())
        {
            return Err(G4Error::InvalidDescriptor);
        }
        let authority = if is_zero(&connector_authority_public_key) {
            None
        } else {
            let authority = VerifyingKey::from_bytes(&connector_authority_public_key)
                .map_err(|_| G4Error::InvalidRegistryPublisher)?;
            if authority.is_weak() {
                return Err(G4Error::InvalidRegistryPublisher);
            }
            Some(authority)
        };

        let maximum_tools = MAX_ACTIVE_TOOL_DESCRIPTORS;
        let mut registered = BTreeMap::new();
        let mut active = BTreeMap::new();
        let mut active_tool_descriptors = 0_usize;
        for descriptor in deployment_shipped_connectors {
            if descriptor.tier != ConnectorTierV2::DeploymentShipped {
                return Err(G4Error::InvalidDescriptor);
            }
            active_tool_descriptors = active_tool_descriptors
                .checked_add(descriptor.tool_descriptors.len())
                .ok_or(G4Error::DescriptorLimitExceeded)?;
            if active_tool_descriptors > maximum_tools {
                return Err(G4Error::DescriptorLimitExceeded);
            }
            let id = *descriptor.connector_id.as_bytes();
            if registered.contains_key(&id) {
                return Err(G4Error::InvalidDescriptor);
            }
            let descriptor = Arc::new(descriptor);
            registered.insert(id, Arc::clone(&descriptor));
            active.insert(id, descriptor);
        }
        Ok(Self {
            genesis_digest,
            head_digest: genesis_digest,
            sequence: 0,
            authority,
            user_host_allowlist,
            registered,
            registered_user_connectors: 0,
            registered_tool_descriptors: active_tool_descriptors,
            active,
            active_user_connectors: 0,
            active_tool_descriptors,
            deltas: Vec::new(),
        })
    }

    /// Applies a newly received delta under the current standing host policy.
    /// A user-tier HTTPS Add outside that policy is not appended.
    pub fn apply_canonical_delta(&mut self, bytes: &[u8]) -> Result<(), G4Error> {
        self.apply_canonical_delta_with_policy(bytes, true)
    }

    /// Replays an already signed chain delta under the current generation.
    /// An Add that no longer clears the standing host policy remains registered
    /// and removable, but is omitted from the active connector view.
    pub fn replay_canonical_delta(&mut self, bytes: &[u8]) -> Result<(), G4Error> {
        self.apply_canonical_delta_with_policy(bytes, false)
    }

    /// Validates and freezes a new user-tier Add payload before the
    /// connector-authority key is allowed to sign it.
    pub fn prepare_add_delta(
        &self,
        canonical_descriptor: &[u8],
        settlement_digest: Digest32V2,
        issued_at_unix_ms: u64,
    ) -> Result<PreparedConnectorRegistryDeltaV2, G4Error> {
        if is_zero(settlement_digest.as_bytes()) || issued_at_unix_ms == 0 {
            return Err(G4Error::InvalidDescriptor);
        }
        let descriptor = ConnectorDescriptorV2::from_canonical_bytes(
            canonical_descriptor,
            &self.user_host_allowlist,
        )?;
        if descriptor.tier() != ConnectorTierV2::UserRegistered {
            return Err(G4Error::InvalidDescriptor);
        }
        self.prepare_delta(
            ConnectorRegistryOperationV2::Add(Arc::new(descriptor)),
            settlement_digest,
            issued_at_unix_ms,
        )
    }

    /// Validates and freezes a shrinking Remove payload. Removal deliberately
    /// carries the all-zero settlement digest because it requires an exact
    /// UI-authenticated session but no approvald decision.
    pub fn prepare_remove_delta(
        &self,
        connector_id: Digest32V2,
        issued_at_unix_ms: u64,
    ) -> Result<PreparedConnectorRegistryDeltaV2, G4Error> {
        if is_zero(connector_id.as_bytes()) || issued_at_unix_ms == 0 {
            return Err(G4Error::InvalidDescriptor);
        }
        self.prepare_delta(
            ConnectorRegistryOperationV2::Remove(connector_id),
            Digest32V2::new([0; 32]),
            issued_at_unix_ms,
        )
    }

    fn prepare_delta(
        &self,
        operation: ConnectorRegistryOperationV2,
        settlement_digest: Digest32V2,
        issued_at_unix_ms: u64,
    ) -> Result<PreparedConnectorRegistryDeltaV2, G4Error> {
        let authority = self
            .authority
            .as_ref()
            .ok_or(G4Error::InvalidRegistryPublisher)?
            .to_owned();
        self.validate_operation(&operation, true, MAX_ACTIVE_TOOL_DESCRIPTORS)?;
        let sequence = self
            .sequence
            .checked_add(1)
            .ok_or(G4Error::InvalidDescriptor)?;
        let prototype = ConnectorRegistryDeltaV2 {
            canonical_bytes: Vec::new(),
            sequence,
            previous_head_digest: self.head_digest,
            operation: operation.clone(),
            settlement_digest,
            issued_at_unix_ms,
            payload_digest: Digest32V2::new([0; 32]),
            authority_signature: [0; 64],
            signed_digest: Digest32V2::new([0; 32]),
        };
        let payload = encode_delta_payload(&prototype)?;
        let payload_digest = domain_hash(CONNECTOR_DELTA_PAYLOAD_DOMAIN_V2, &payload);
        let signature_digest = domain_hash(
            CONNECTOR_DELTA_SIGNATURE_DOMAIN_V2,
            payload_digest.as_bytes(),
        );
        Ok(PreparedConnectorRegistryDeltaV2 {
            sequence,
            previous_head_digest: self.head_digest,
            operation,
            settlement_digest,
            issued_at_unix_ms,
            payload_digest,
            signature_digest,
            authority,
        })
    }

    fn apply_canonical_delta_with_policy(
        &mut self,
        bytes: &[u8],
        require_active_add: bool,
    ) -> Result<(), G4Error> {
        self.apply_canonical_delta_with_policy_and_tool_limit(
            bytes,
            require_active_add,
            MAX_ACTIVE_TOOL_DESCRIPTORS,
        )
    }

    #[cfg(test)]
    fn replay_canonical_delta_with_tool_limit_for_test(
        &mut self,
        bytes: &[u8],
        maximum_tools: usize,
    ) -> Result<(), G4Error> {
        self.apply_canonical_delta_with_policy_and_tool_limit(bytes, false, maximum_tools)
    }

    fn apply_canonical_delta_with_policy_and_tool_limit(
        &mut self,
        bytes: &[u8],
        require_active_add: bool,
        maximum_tools: usize,
    ) -> Result<(), G4Error> {
        let authority = self
            .authority
            .as_ref()
            .ok_or(G4Error::InvalidRegistryPublisher)?;
        let expected_sequence = self
            .sequence
            .checked_add(1)
            .ok_or(G4Error::InvalidDescriptor)?;
        let delta = ConnectorRegistryDeltaV2::from_canonical_bytes_for_state(
            bytes,
            authority,
            expected_sequence,
            self.head_digest,
        )?;

        let add_is_active =
            self.validate_operation(&delta.operation, require_active_add, maximum_tools)?;

        self.deltas
            .try_reserve(1)
            .map_err(|_| G4Error::AllocationFailure)?;
        let next_head = connector_registry_head(self.head_digest, delta.signed_digest);
        match &delta.operation {
            ConnectorRegistryOperationV2::Add(descriptor) => {
                self.registered_user_connectors += 1;
                self.registered_tool_descriptors += descriptor.tool_descriptors.len();
                self.registered
                    .insert(*descriptor.connector_id.as_bytes(), Arc::clone(descriptor));
                if add_is_active {
                    self.active_tool_descriptors += descriptor.tool_descriptors.len();
                    self.active_user_connectors += 1;
                    self.active
                        .insert(*descriptor.connector_id.as_bytes(), Arc::clone(descriptor));
                }
            }
            ConnectorRegistryOperationV2::Remove(connector_id) => {
                let removed = self
                    .registered
                    .remove(connector_id.as_bytes())
                    .expect("registered connector was checked before mutation");
                if removed.tier == ConnectorTierV2::UserRegistered {
                    self.registered_user_connectors -= 1;
                }
                self.registered_tool_descriptors -= removed.tool_descriptors.len();
                if let Some(removed) = self.active.remove(connector_id.as_bytes()) {
                    self.active_tool_descriptors -= removed.tool_descriptors.len();
                    if removed.tier == ConnectorTierV2::UserRegistered {
                        self.active_user_connectors -= 1;
                    }
                }
            }
        }
        self.sequence = delta.sequence;
        self.head_digest = next_head;
        self.deltas.push(delta);
        Ok(())
    }

    fn validate_operation(
        &self,
        operation: &ConnectorRegistryOperationV2,
        require_active_add: bool,
        maximum_tools: usize,
    ) -> Result<bool, G4Error> {
        let maximum_users =
            usize::try_from(DeploymentHardLimitsV2::compiled().max_user_connectors())
                .map_err(|_| G4Error::DescriptorLimitExceeded)?;
        match operation {
            ConnectorRegistryOperationV2::Add(descriptor) => {
                if descriptor.tier != ConnectorTierV2::UserRegistered
                    || self
                        .registered
                        .contains_key(descriptor.connector_id.as_bytes())
                {
                    return Err(G4Error::InvalidDescriptor);
                }
                if self.registered_user_connectors >= maximum_users {
                    return Err(G4Error::DescriptorLimitExceeded);
                }
                if self
                    .registered_tool_descriptors
                    .checked_add(descriptor.tool_descriptors.len())
                    .is_none_or(|count| count > maximum_tools)
                {
                    return Err(G4Error::DescriptorLimitExceeded);
                }
                let is_active =
                    connector_is_active_under_allowlist(descriptor, &self.user_host_allowlist)?;
                if require_active_add && !is_active {
                    return Err(G4Error::InvalidDescriptor);
                }
                if is_active
                    && self
                        .active_tool_descriptors
                        .checked_add(descriptor.tool_descriptors.len())
                        .is_none_or(|count| count > maximum_tools)
                {
                    return Err(G4Error::DescriptorLimitExceeded);
                }
                Ok(is_active)
            }
            ConnectorRegistryOperationV2::Remove(connector_id) => {
                if !self.registered.contains_key(connector_id.as_bytes()) {
                    return Err(G4Error::InvalidDescriptor);
                }
                Ok(false)
            }
        }
    }

    pub const fn genesis_digest(&self) -> Digest32V2 {
        self.genesis_digest
    }

    pub const fn head_digest(&self) -> Digest32V2 {
        self.head_digest
    }

    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn connector_authority_public_key(&self) -> [u8; 32] {
        self.authority
            .as_ref()
            .map_or([0; 32], VerifyingKey::to_bytes)
    }

    pub fn user_host_allowlist(&self) -> &[BoundedConnectorHostV2] {
        &self.user_host_allowlist
    }

    pub fn active_connector_count(&self) -> usize {
        self.active.len()
    }

    pub const fn active_user_connector_count(&self) -> usize {
        self.active_user_connectors
    }

    pub fn registered_connector_count(&self) -> usize {
        self.registered.len()
    }

    pub const fn registered_user_connector_count(&self) -> usize {
        self.registered_user_connectors
    }

    pub const fn active_tool_descriptor_count(&self) -> usize {
        self.active_tool_descriptors
    }

    pub const fn registered_tool_descriptor_count(&self) -> usize {
        self.registered_tool_descriptors
    }

    pub fn contains_connector(&self, connector_id: Digest32V2) -> bool {
        self.active.contains_key(connector_id.as_bytes())
    }

    pub fn contains_registered_connector(&self, connector_id: Digest32V2) -> bool {
        self.registered.contains_key(connector_id.as_bytes())
    }

    pub fn active_connector(&self, connector_id: Digest32V2) -> Option<&ConnectorDescriptorV2> {
        self.active.get(connector_id.as_bytes()).map(Arc::as_ref)
    }

    pub fn registered_connector(&self, connector_id: Digest32V2) -> Option<&ConnectorDescriptorV2> {
        self.registered
            .get(connector_id.as_bytes())
            .map(Arc::as_ref)
    }

    pub fn registered_connectors(
        &self,
    ) -> impl ExactSizeIterator<Item = &ConnectorDescriptorV2> + '_ {
        self.registered.values().map(Arc::as_ref)
    }

    /// New task-bound requests identify a route through the exact signed tool
    /// descriptor, not the business-destination projection. Require a unique
    /// registered descriptor, its pinned connector identity (including tier/name),
    /// current activity and the closed HTTPS profile's exact target. No fallback
    /// to a deployment transport or an inactive/renamed/promoted connector.
    pub fn resolve_task_tool_connector(
        &self,
        tool: Digest32V2,
    ) -> Result<&ConnectorDescriptorV2, G4Error> {
        let mut found = None;
        for connector in self.registered_connectors() {
            for descriptor in connector.tool_descriptors() {
                if descriptor_digest_v2(descriptor)? != tool {
                    continue;
                }
                if found.is_some()
                    || descriptor.provider_identity_digest() != connector.connector_id()
                    || !self.contains_connector(connector.connector_id())
                {
                    return Err(G4Error::InvalidDescriptor);
                }
                let profile = descriptor.require_business_profile()?;
                let ConnectorTransportV2::Https {
                    canonical_url,
                    tls_identity_pin,
                } = connector.transport()
                else {
                    return Err(G4Error::InvalidDescriptor);
                };
                if profile.target_identity()
                    != savana_kernel_protocol::v2::business_target_identity_v2(
                        canonical_url.as_str(),
                        *tls_identity_pin,
                    )
                    .map_err(|_| G4Error::InvalidDescriptor)?
                {
                    return Err(G4Error::InvalidDescriptor);
                }
                found = Some(connector);
            }
        }
        found.ok_or(G4Error::InvalidDescriptor)
    }

    pub fn deltas(&self) -> &[ConnectorRegistryDeltaV2] {
        &self.deltas
    }

    pub(super) fn has_same_verified_registered_chain(&self, other: &Self) -> bool {
        self.genesis_digest == other.genesis_digest
            && self.head_digest == other.head_digest
            && self.sequence == other.sequence
            && self.authority.as_ref().map(VerifyingKey::to_bytes)
                == other.authority.as_ref().map(VerifyingKey::to_bytes)
            && self.registered_user_connectors == other.registered_user_connectors
            && self.registered_tool_descriptors == other.registered_tool_descriptors
            && self.registered.len() == other.registered.len()
            && self.registered.iter().zip(other.registered.iter()).all(
                |((left_id, left), (right_id, right))| {
                    left_id == right_id && left.canonical_bytes() == right.canonical_bytes()
                },
            )
            && self.deltas.len() == other.deltas.len()
            && self
                .deltas
                .iter()
                .zip(other.deltas.iter())
                .all(|(left, right)| left.canonical_bytes() == right.canonical_bytes())
    }
}

fn connector_id_v2(
    tier: ConnectorTierV2,
    display_name: &BoundedConnectorNameV2,
    transport: &ConnectorTransportV2,
) -> Result<Digest32V2, G4Error> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(CONNECTOR_IDENTITY_FIELDS_V2)
        .and_then(|encoder| encoder.str(display_name.as_str()))
        .map_err(|_| G4Error::NonCanonicalDescriptor)?;
    encode_transport(&mut encoder, transport)?;
    Ok(domain_hash(tier.id_domain(), &encoder.into_writer()))
}

fn validate_canonical_domain(domain: &str) -> Result<(), G4Error> {
    if domain.is_empty()
        || domain.len() > MAX_CONNECTOR_HOST_BYTES_V2
        || domain.bytes().any(|byte| byte.is_ascii_uppercase())
        || domain.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                || !label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                || !label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
        })
    {
        return Err(G4Error::InvalidDescriptor);
    }
    Ok(())
}

fn decode_transport(decoder: &mut minicbor::Decoder<'_>) -> Result<ConnectorTransportV2, G4Error> {
    let length = decoder
        .array()
        .map_err(|_| G4Error::NonCanonicalDescriptor)?
        .ok_or(G4Error::NonCanonicalDescriptor)?;
    let tag = decode_u16(decoder)?;
    match (length, tag) {
        (CONNECTOR_TRANSPORT_STDIO_FIELDS_V2, CONNECTOR_TRANSPORT_STDIO_TAG_V2) => {
            ConnectorTransportV2::stdio(decode_digest(decoder)?)
        }
        (CONNECTOR_TRANSPORT_HTTPS_FIELDS_V2, CONNECTOR_TRANSPORT_HTTPS_TAG_V2) => {
            let url = BoundedConnectorUrlV2::new(
                decoder.str().map_err(|_| G4Error::NonCanonicalDescriptor)?,
            )?;
            ConnectorTransportV2::https(url, decode_digest(decoder)?)
        }
        _ => Err(G4Error::InvalidDescriptor),
    }
}

fn encode_transport(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    transport: &ConnectorTransportV2,
) -> Result<(), G4Error> {
    match transport {
        ConnectorTransportV2::Stdio { package_digest } => {
            encoder
                .array(CONNECTOR_TRANSPORT_STDIO_FIELDS_V2)
                .and_then(|encoder| encoder.u16(CONNECTOR_TRANSPORT_STDIO_TAG_V2))
                .and_then(|encoder| encoder.bytes(package_digest.as_bytes()))
                .map_err(|_| G4Error::NonCanonicalDescriptor)?;
        }
        ConnectorTransportV2::Https {
            canonical_url,
            tls_identity_pin,
        } => {
            encoder
                .array(CONNECTOR_TRANSPORT_HTTPS_FIELDS_V2)
                .and_then(|encoder| encoder.u16(CONNECTOR_TRANSPORT_HTTPS_TAG_V2))
                .and_then(|encoder| encoder.str(canonical_url.as_str()))
                .and_then(|encoder| encoder.bytes(tls_identity_pin.as_bytes()))
                .map_err(|_| G4Error::NonCanonicalDescriptor)?;
        }
    }
    Ok(())
}

fn encode_descriptor(value: &ConnectorDescriptorV2) -> Result<Vec<u8>, G4Error> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(CONNECTOR_DESCRIPTOR_FIELDS_V2)
        .and_then(|encoder| encoder.bytes(value.connector_id.as_bytes()))
        .and_then(|encoder| encoder.str(value.display_name.as_str()))
        .and_then(|encoder| encoder.u16(value.tier.tag()))
        .map_err(|_| G4Error::NonCanonicalDescriptor)?;
    encode_transport(&mut encoder, &value.transport)?;
    encoder
        .array(value.tool_descriptors.len() as u64)
        .map_err(|_| G4Error::NonCanonicalDescriptor)?;
    for descriptor in &value.tool_descriptors {
        encoder.writer_mut().extend_from_slice(
            &minicbor::to_vec(descriptor).map_err(|_| G4Error::NonCanonicalDescriptor)?,
        );
    }
    encoder
        .u16(value.requested_effects.bits())
        .and_then(|encoder| encoder.u16(value.structural_role.tag()))
        .and_then(|encoder| encoder.u64(value.descriptor_version))
        .map_err(|_| G4Error::NonCanonicalDescriptor)?;
    Ok(encoder.into_writer())
}

fn decode_delta_payload(
    bytes: &[u8],
    expected_sequence: u64,
    expected_previous_head: Digest32V2,
) -> Result<DecodedConnectorDeltaV2, G4Error> {
    let mut decoder = minicbor::Decoder::new(bytes);
    expect_array(&mut decoder, CONNECTOR_DELTA_PAYLOAD_FIELDS_V2)?;
    if decode_u16(&mut decoder)? != CONNECTOR_DELTA_SCHEMA_VERSION_V2 {
        return Err(G4Error::InvalidDescriptor);
    }
    let sequence = decode_u64(&mut decoder)?;
    let previous_head_digest = decode_digest(&mut decoder)?;
    if sequence != expected_sequence || previous_head_digest != expected_previous_head {
        return Err(G4Error::InvalidDescriptor);
    }
    expect_array(&mut decoder, CONNECTOR_DELTA_OPERATION_FIELDS_V2)?;
    let operation_tag = decode_u16(&mut decoder)?;
    let operation = match operation_tag {
        CONNECTOR_DELTA_ADD_TAG_V2 => {
            let start = decoder.position();
            decoder
                .skip()
                .map_err(|_| G4Error::NonCanonicalDescriptor)?;
            let nested = decoder
                .input()
                .get(start..decoder.position())
                .ok_or(G4Error::NonCanonicalDescriptor)?;
            let descriptor = ConnectorDescriptorV2::from_canonical_bytes_intrinsic(nested)?;
            if descriptor.tier != ConnectorTierV2::UserRegistered {
                return Err(G4Error::InvalidDescriptor);
            }
            ConnectorRegistryOperationV2::Add(Arc::new(descriptor))
        }
        CONNECTOR_DELTA_REMOVE_TAG_V2 => {
            let connector_id = decode_digest(&mut decoder)?;
            if is_zero(connector_id.as_bytes()) {
                return Err(G4Error::InvalidDescriptor);
            }
            ConnectorRegistryOperationV2::Remove(connector_id)
        }
        _ => return Err(G4Error::InvalidDescriptor),
    };
    let settlement_digest = decode_digest(&mut decoder)?;
    if matches!(operation, ConnectorRegistryOperationV2::Add(_))
        && is_zero(settlement_digest.as_bytes())
    {
        return Err(G4Error::InvalidDescriptor);
    }
    let issued_at_unix_ms = decode_u64(&mut decoder)?;
    require_eof(&decoder, bytes)?;
    Ok(DecodedConnectorDeltaV2 {
        sequence,
        previous_head_digest,
        operation,
        settlement_digest,
        issued_at_unix_ms,
    })
}

fn encode_delta_payload(value: &ConnectorRegistryDeltaV2) -> Result<Vec<u8>, G4Error> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(CONNECTOR_DELTA_PAYLOAD_FIELDS_V2)
        .and_then(|encoder| encoder.u16(CONNECTOR_DELTA_SCHEMA_VERSION_V2))
        .and_then(|encoder| encoder.u64(value.sequence))
        .and_then(|encoder| encoder.bytes(value.previous_head_digest.as_bytes()))
        .map_err(|_| G4Error::NonCanonicalDescriptor)?;
    match &value.operation {
        ConnectorRegistryOperationV2::Add(descriptor) => {
            encoder
                .array(CONNECTOR_DELTA_OPERATION_FIELDS_V2)
                .and_then(|encoder| encoder.u16(CONNECTOR_DELTA_ADD_TAG_V2))
                .map_err(|_| G4Error::NonCanonicalDescriptor)?;
            encoder
                .writer_mut()
                .extend_from_slice(descriptor.canonical_bytes());
        }
        ConnectorRegistryOperationV2::Remove(connector_id) => {
            encoder
                .array(CONNECTOR_DELTA_OPERATION_FIELDS_V2)
                .and_then(|encoder| encoder.u16(CONNECTOR_DELTA_REMOVE_TAG_V2))
                .and_then(|encoder| encoder.bytes(connector_id.as_bytes()))
                .map_err(|_| G4Error::NonCanonicalDescriptor)?;
        }
    }
    encoder
        .bytes(value.settlement_digest.as_bytes())
        .and_then(|encoder| encoder.u64(value.issued_at_unix_ms))
        .map_err(|_| G4Error::NonCanonicalDescriptor)?;
    Ok(encoder.into_writer())
}

fn encode_delta(value: &ConnectorRegistryDeltaV2) -> Result<Vec<u8>, G4Error> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(CONNECTOR_DELTA_FIELDS_V2)
        .map_err(|_| G4Error::NonCanonicalDescriptor)?;
    encoder
        .writer_mut()
        .extend_from_slice(&encode_delta_payload(value)?);
    encoder
        .bytes(value.payload_digest.as_bytes())
        .and_then(|encoder| encoder.bytes(&value.authority_signature))
        .map_err(|_| G4Error::NonCanonicalDescriptor)?;
    Ok(encoder.into_writer())
}

fn connector_registry_head(
    previous_head: Digest32V2,
    signed_delta_digest: Digest32V2,
) -> Digest32V2 {
    let mut material = [0_u8; 64];
    material[..32].copy_from_slice(previous_head.as_bytes());
    material[32..].copy_from_slice(signed_delta_digest.as_bytes());
    domain_hash(CONNECTOR_REGISTRY_HEAD_DOMAIN_V2, &material)
}

fn check_connector_object_size(bytes: &[u8]) -> Result<(), G4Error> {
    let maximum = usize::try_from(DeploymentHardLimitsV2::compiled().max_manifest_bytes())
        .map_err(|_| G4Error::DescriptorLimitExceeded)?;
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(G4Error::DescriptorLimitExceeded);
    }
    Ok(())
}

fn expect_array(decoder: &mut minicbor::Decoder<'_>, expected: u64) -> Result<(), G4Error> {
    match decoder
        .array()
        .map_err(|_| G4Error::NonCanonicalDescriptor)?
    {
        Some(length) if length == expected => Ok(()),
        _ => Err(G4Error::NonCanonicalDescriptor),
    }
}

fn decode_bounded_array_length(
    decoder: &mut minicbor::Decoder<'_>,
    maximum: u64,
) -> Result<usize, G4Error> {
    let count = decoder
        .array()
        .map_err(|_| G4Error::NonCanonicalDescriptor)?
        .ok_or(G4Error::NonCanonicalDescriptor)?;
    if count > maximum {
        return Err(G4Error::DescriptorLimitExceeded);
    }
    usize::try_from(count).map_err(|_| G4Error::DescriptorLimitExceeded)
}

fn decode_u16(decoder: &mut minicbor::Decoder<'_>) -> Result<u16, G4Error> {
    decoder.u16().map_err(|_| G4Error::NonCanonicalDescriptor)
}

fn decode_u64(decoder: &mut minicbor::Decoder<'_>) -> Result<u64, G4Error> {
    decoder.u64().map_err(|_| G4Error::NonCanonicalDescriptor)
}

fn decode_digest(decoder: &mut minicbor::Decoder<'_>) -> Result<Digest32V2, G4Error> {
    Ok(Digest32V2::new(decode_fixed::<32>(decoder)?))
}

fn decode_fixed<const N: usize>(decoder: &mut minicbor::Decoder<'_>) -> Result<[u8; N], G4Error> {
    decoder
        .bytes()
        .map_err(|_| G4Error::NonCanonicalDescriptor)?
        .try_into()
        .map_err(|_| G4Error::NonCanonicalDescriptor)
}

fn require_eof(decoder: &minicbor::Decoder<'_>, bytes: &[u8]) -> Result<(), G4Error> {
    if decoder.position() != bytes.len() {
        return Err(G4Error::NonCanonicalDescriptor);
    }
    Ok(())
}

fn domain_hash(domain: &[u8], bytes: &[u8]) -> Digest32V2 {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(bytes);
    Digest32V2::new(hasher.finalize().into())
}

fn is_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer as _, SigningKey};
    use savana_kernel_protocol::v2::{
        ActionTemplateIdV2, DisplayProjectionIdV2, ExecutorIdentityV2, ImplementationIdV2,
        ProjectionIdV2, RoleIdV2, ToolClassIdV2, UnixMillisV2, VersionV2,
    };

    use super::*;
    use crate::v2::{
        AttemptKindV2, BoundedConnectorRetryPolicyV2, ExecutorIdempotencyContractV2,
        InternalValidatorDeclarationV2,
    };

    fn test_digest(byte: u8) -> Digest32V2 {
        Digest32V2::new([byte; 32])
    }

    fn test_tool(seed: u8) -> UnsignedToolDescriptorV2 {
        test_tool_for_provider(seed, test_digest(seed))
    }

    fn test_tool_for_provider(seed: u8, provider: Digest32V2) -> UnsignedToolDescriptorV2 {
        let contract = ExecutorIdempotencyContractV2::ConnectorIdempotentByExecutionNonce;
        UnsignedToolDescriptorV2::from_verified_manifest(
            2,
            VersionV2::new(1, 0, 0),
            provider,
            IdentifierV2::new(format!("tool-{seed}")).unwrap(),
            ActionTemplateIdV2::new(u32::from(seed) + 1),
            ToolClassIdV2::new(u32::from(seed) + 2),
            test_digest(seed.wrapping_add(1)),
            test_digest(seed.wrapping_add(2)),
            vec![RoleIdV2::new(1)],
            EffectSetV2::READ,
            AttemptKindV2::ToolWrite,
            BoundedConnectorRetryPolicyV2::new(contract, 2, 1_000_000).unwrap(),
            vec![InternalValidatorDeclarationV2::new(
                ImplementationIdV2::new(u32::from(seed) + 3),
                VersionV2::new(1, 0, 0),
                test_digest(seed.wrapping_add(3)),
            )],
            ExecutorIdentityV2::new([seed.wrapping_add(4); 32]),
            ProjectionIdV2::new(u32::from(seed) + 4),
            test_digest(seed.wrapping_add(5)),
            DisplayProjectionIdV2::new(u32::from(seed) + 5),
            test_digest(seed.wrapping_add(6)),
            contract,
            UnixMillisV2::new(1),
            UnixMillisV2::new(10_000),
        )
        .unwrap()
    }

    fn inactive_descriptor(name: &str, seed: u8) -> ConnectorDescriptorV2 {
        let display_name = BoundedConnectorNameV2::new(name).unwrap();
        let transport = ConnectorTransportV2::https(
            BoundedConnectorUrlV2::new(format!("https://outside-{seed}.example/mcp")).unwrap(),
            test_digest(seed.wrapping_add(1)),
        )
        .unwrap();
        let connector_id =
            connector_id_v2(ConnectorTierV2::UserRegistered, &display_name, &transport).unwrap();
        ConnectorDescriptorV2::from_decoded(
            connector_id,
            display_name,
            ConnectorTierV2::UserRegistered,
            transport,
            vec![test_tool(seed.wrapping_add(2))],
            EffectSetV2::READ,
            ConnectorStructuralRoleV2::Source,
            1,
        )
        .unwrap()
    }

    fn signed_add_delta(
        sequence: u64,
        previous_head_digest: Digest32V2,
        descriptor: ConnectorDescriptorV2,
        authority: &SigningKey,
    ) -> Vec<u8> {
        let mut delta = ConnectorRegistryDeltaV2 {
            canonical_bytes: Vec::new(),
            sequence,
            previous_head_digest,
            operation: ConnectorRegistryOperationV2::Add(Arc::new(descriptor)),
            settlement_digest: test_digest(0xf1),
            issued_at_unix_ms: sequence,
            payload_digest: test_digest(0),
            authority_signature: [0; 64],
            signed_digest: test_digest(0),
        };
        let payload = encode_delta_payload(&delta).unwrap();
        delta.payload_digest = domain_hash(CONNECTOR_DELTA_PAYLOAD_DOMAIN_V2, &payload);
        let signature_digest = domain_hash(
            CONNECTOR_DELTA_SIGNATURE_DOMAIN_V2,
            delta.payload_digest.as_bytes(),
        );
        delta.authority_signature = authority.sign(signature_digest.as_bytes()).to_bytes();
        encode_delta(&delta).unwrap()
    }

    #[test]
    fn strict_task_route_rechecks_profile_activity_and_signed_removal() {
        use savana_kernel_protocol::v2::{
            business_target_identity_v2, ActionCodecProfileV2, BusinessFieldRoleV2,
            BusinessFieldTypeV2, BusinessFieldV2, BusinessMagnitudeV2, BusinessProfileV2,
            TaskEffectV2,
        };
        let name = BoundedConnectorNameV2::new("task-reader").unwrap();
        let url = BoundedConnectorUrlV2::new("https://inside.example/mcp").unwrap();
        let transport = ConnectorTransportV2::https(url.clone(), test_digest(2)).unwrap();
        let id = connector_id_v2(ConnectorTierV2::UserRegistered, &name, &transport).unwrap();
        let tool = test_tool_for_provider(3, id);
        let profile = BusinessProfileV2::new(
            ActionCodecProfileV2::McpToolsCallJsonV1,
            "tool-3",
            business_target_identity_v2(url.as_str(), test_digest(2)).unwrap(),
            test_digest(4),
            TaskEffectV2::Read,
            BusinessMagnitudeV2::FixedCount(1),
            vec![
                BusinessFieldV2::new(
                    "body",
                    BusinessFieldRoleV2::Payload,
                    BusinessFieldTypeV2::Text,
                )
                .unwrap(),
                BusinessFieldV2::new(
                    "file",
                    BusinessFieldRoleV2::Resource,
                    BusinessFieldTypeV2::Text,
                )
                .unwrap(),
                BusinessFieldV2::new(
                    "to",
                    BusinessFieldRoleV2::Destination,
                    BusinessFieldTypeV2::Text,
                )
                .unwrap(),
            ],
        )
        .unwrap();
        let authority = SigningKey::from_bytes(&[0xe1; 32]);
        let genesis = test_digest(0xe2);
        for with_profile in [false, true] {
            let tool = if with_profile {
                tool.clone().with_business_profile(profile.clone()).unwrap()
            } else {
                tool.clone()
            };
            let digest = descriptor_digest_v2(&tool).unwrap();
            let descriptor = ConnectorDescriptorV2::from_decoded(
                id,
                name.clone(),
                ConnectorTierV2::UserRegistered,
                transport.clone(),
                vec![tool],
                EffectSetV2::READ,
                ConnectorStructuralRoleV2::Source,
                1,
            )
            .unwrap();
            let add = signed_add_delta(1, genesis, descriptor, &authority);
            let mut state = ConnectorRegistryStateV2::from_verified_genesis(
                genesis,
                authority.verifying_key().to_bytes(),
                vec![BoundedConnectorHostV2::new("inside.example").unwrap()],
                vec![],
            )
            .unwrap();
            state.apply_canonical_delta(&add).unwrap();
            assert_eq!(
                state.resolve_task_tool_connector(digest).is_ok(),
                with_profile
            );
            assert!(state
                .resolve_task_tool_connector(test_digest(0xfe))
                .is_err());
            let mut narrowed = ConnectorRegistryStateV2::from_verified_genesis(
                genesis,
                authority.verifying_key().to_bytes(),
                vec![],
                vec![],
            )
            .unwrap();
            narrowed.replay_canonical_delta(&add).unwrap();
            assert!(narrowed.contains_registered_connector(id));
            assert!(!narrowed.contains_connector(id));
            assert!(narrowed.resolve_task_tool_connector(digest).is_err());
            let remove = state.prepare_remove_delta(id, 2).unwrap();
            let signature = authority
                .sign(remove.signature_digest().as_bytes())
                .to_bytes();
            state
                .apply_canonical_delta(remove.finalize(signature).unwrap().canonical_bytes())
                .unwrap();
            assert!(state.resolve_task_tool_connector(digest).is_err());
        }
    }

    #[test]
    fn deployment_set_is_bound_to_genesis_and_resolves_its_own_task_tools() {
        use savana_kernel_protocol::v2::{
            business_target_identity_v2, ActionCodecProfileV2, BusinessFieldRoleV2,
            BusinessFieldTypeV2, BusinessFieldV2, BusinessMagnitudeV2, BusinessProfileV2,
            TaskEffectV2,
        };
        let build = |label: &str, seed: u8, provider: Option<Digest32V2>| {
            let name = BoundedConnectorNameV2::new(label).unwrap();
            let url = BoundedConnectorUrlV2::new(format!("https://{label}.example/mcp")).unwrap();
            let transport = ConnectorTransportV2::https(url.clone(), test_digest(seed)).unwrap();
            let id = ConnectorDescriptorV2::deployment_shipped_id(&name, &transport).unwrap();
            let profile = BusinessProfileV2::new(
                ActionCodecProfileV2::McpToolsCallJsonV1,
                &format!("tool-{}", seed + 1),
                business_target_identity_v2(url.as_str(), test_digest(seed)).unwrap(),
                test_digest(seed + 2),
                TaskEffectV2::Read,
                BusinessMagnitudeV2::FixedCount(1),
                [
                    ("body", BusinessFieldRoleV2::Payload),
                    ("file", BusinessFieldRoleV2::Resource),
                    ("to", BusinessFieldRoleV2::Destination),
                ]
                .into_iter()
                .map(|(field, role)| {
                    BusinessFieldV2::new(field, role, BusinessFieldTypeV2::Text).unwrap()
                })
                .collect(),
            )
            .unwrap();
            let tool = test_tool_for_provider(seed + 1, provider.unwrap_or(id))
                .with_business_profile(profile)
                .unwrap();
            ConnectorDescriptorV2::new_deployment_shipped(
                name,
                transport,
                vec![tool],
                EffectSetV2::READ,
                ConnectorStructuralRoleV2::Sink,
                1,
            )
        };
        assert!(build("foreign", 0x61, Some(test_digest(0x62))).is_err());
        let mut set = vec![
            build("calendar", 0x41, None).unwrap(),
            build("release", 0x51, None).unwrap(),
        ];
        set.sort_by_key(|connector| *connector.connector_id().as_bytes());
        let genesis = ConnectorDescriptorV2::deployment_genesis_digest(&set).unwrap();
        let encoded: Vec<Vec<u8>> = set
            .iter()
            .map(|connector| connector.canonical_bytes().to_vec())
            .collect();
        let loaded =
            ConnectorDescriptorV2::verified_deployment_set(genesis, &encoded, &[]).unwrap();
        assert_eq!(loaded, set);
        // Only the exact committed set loads; the legacy opaque digest stays
        // valid for an empty set alone.
        let reversed: Vec<_> = encoded.iter().rev().cloned().collect();
        for (digest, bytes) in [
            (test_digest(0xe2), encoded.as_slice()),
            (genesis, reversed.as_slice()),
            (genesis, &encoded[..1]),
        ] {
            assert!(ConnectorDescriptorV2::verified_deployment_set(digest, bytes, &[]).is_err());
        }
        assert!(
            ConnectorDescriptorV2::verified_deployment_set(test_digest(0xe2), &[], &[])
                .unwrap()
                .is_empty()
        );
        let user = inactive_descriptor("user-tier", 0x21)
            .canonical_bytes()
            .to_vec();
        assert!(ConnectorDescriptorV2::verified_deployment_set(
            genesis,
            &[user],
            &[BoundedConnectorHostV2::new("outside-33.example").unwrap()],
        )
        .is_err());
        let state =
            ConnectorRegistryStateV2::from_verified_genesis(genesis, [0; 32], vec![], loaded)
                .unwrap();
        for connector in &set {
            let digest = descriptor_digest_v2(&connector.tool_descriptors()[0]).unwrap();
            assert_eq!(
                state
                    .resolve_task_tool_connector(digest)
                    .unwrap()
                    .connector_id(),
                connector.connector_id()
            );
        }
    }

    #[test]
    fn inactive_replay_cannot_exceed_registered_tool_limit_or_mutate_state() {
        let authority = SigningKey::from_bytes(&[0xe1; 32]);
        let genesis = test_digest(0xe2);
        let mut state = ConnectorRegistryStateV2::from_verified_genesis(
            genesis,
            authority.verifying_key().to_bytes(),
            vec![],
            vec![],
        )
        .unwrap();

        let first = signed_add_delta(
            1,
            genesis,
            inactive_descriptor("inactive-one", 0x21),
            &authority,
        );
        state
            .replay_canonical_delta_with_tool_limit_for_test(&first, 1)
            .unwrap();
        assert_eq!(state.active_connector_count(), 0);
        assert_eq!(state.active_tool_descriptor_count(), 0);
        assert_eq!(state.registered_connector_count(), 1);
        assert_eq!(state.registered_user_connector_count(), 1);
        assert_eq!(state.registered_tool_descriptor_count(), 1);

        let before_head = state.head_digest();
        let before_sequence = state.sequence();
        let before_journal = state
            .deltas()
            .iter()
            .map(|delta| delta.canonical_bytes().to_vec())
            .collect::<Vec<_>>();
        let first_id = state.registered.keys().next().copied().unwrap();
        let second_descriptor = inactive_descriptor("inactive-two", 0x31);
        let second_id = *second_descriptor.connector_id().as_bytes();
        let second = signed_add_delta(2, before_head, second_descriptor, &authority);

        assert_eq!(
            state
                .replay_canonical_delta_with_tool_limit_for_test(&second, 1)
                .unwrap_err(),
            G4Error::DescriptorLimitExceeded
        );
        assert_eq!(state.head_digest(), before_head);
        assert_eq!(state.sequence(), before_sequence);
        assert_eq!(state.active_connector_count(), 0);
        assert_eq!(state.active_user_connector_count(), 0);
        assert_eq!(state.active_tool_descriptor_count(), 0);
        assert_eq!(state.registered_connector_count(), 1);
        assert_eq!(state.registered_user_connector_count(), 1);
        assert_eq!(state.registered_tool_descriptor_count(), 1);
        assert!(state.registered.contains_key(&first_id));
        assert!(!state.registered.contains_key(&second_id));
        assert_eq!(
            state
                .deltas()
                .iter()
                .map(|delta| delta.canonical_bytes().to_vec())
                .collect::<Vec<_>>(),
            before_journal
        );
    }
}
