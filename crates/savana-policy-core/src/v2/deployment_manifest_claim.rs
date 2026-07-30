use savana_kernel_protocol::v2::{Digest32V2, VaultKeyIdV2};

use super::deployment_manifest_primitives::{
    check_manifest_object_size, decode_bounded_array_length, decode_digest, decode_u16, decode_u64,
    expect_array, hash_domain, is_zero, require_canonical, require_eof,
};
use super::{
    ClosedStoreIdV2, DeploymentControlErrorV2, DeploymentHardLimitsV2,
    PersistentStoreCompatibilitySetV2,
};

const VAULT_KEY_READ_ITEM_FIELDS_V2: u64 = 3;
const AGENT_VIEW_ITEM_FIELDS_V2: u64 = 2;
const AGENT_CLAIM_EDGE_FIELDS_V2: u64 = 24;
const AGENT_CLAIM_EDGE_ID_FIELDS_V2: u64 = 5;
const AGENT_CLAIM_EDGE_ID_DOMAIN_V2: &[u8] = b"savana.agent-claim-compatibility.v2.id\0";
const AGENT_CLAIM_EDGE_DOMAIN_V2: &[u8] = b"savana.agent-claim-compatibility.v2.edge\0";
const VAULT_KEY_READ_SET_DOMAIN_V2: &[u8] = b"savana.set.vault-key-read.v2\0";
const AGENT_VIEW_PROJECTION_SET_DOMAIN_V2: &[u8] = b"savana.set.agent-view-projection.v2\0";
type AgentClaimEdgeSortKeyV2 = (
    u16,
    [u8; 32],
    [u8; 32],
    [u8; 32],
    [u8; 32],
    [u8; 32],
    [u8; 32],
    u16,
    [u8; 32],
);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u16)]
pub enum AgentClaimCompatibilityDirectionV2 {
    FromOldManifestIntoDestinationReadOnly = 1,
}

impl AgentClaimCompatibilityDirectionV2 {
    pub const fn from_tag(tag: u16) -> Option<Self> {
        match tag {
            1 => Some(Self::FromOldManifestIntoDestinationReadOnly),
            _ => None,
        }
    }

    pub const fn tag(self) -> u16 {
        self as u16
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VaultKeyReadSetItemV2 {
    vault_key_role_tag: u16,
    key_id: VaultKeyIdV2,
    key_epoch: u64,
}

impl VaultKeyReadSetItemV2 {
    pub fn new(
        vault_key_role_tag: u16,
        key_id: VaultKeyIdV2,
        key_epoch: u64,
    ) -> Result<Self, DeploymentControlErrorV2> {
        if vault_key_role_tag == 0 || key_epoch == 0 || is_zero(key_id.as_bytes()) {
            return Err(DeploymentControlErrorV2::InvalidSecurityStateManifest);
        }
        Ok(Self {
            vault_key_role_tag,
            key_id,
            key_epoch,
        })
    }

    pub const fn vault_key_role_tag(self) -> u16 {
        self.vault_key_role_tag
    }

    pub const fn key_id(self) -> VaultKeyIdV2 {
        self.key_id
    }

    pub const fn key_epoch(self) -> u64 {
        self.key_epoch
    }

    fn sort_key(self) -> (u16, u64, [u8; 32]) {
        (
            self.vault_key_role_tag,
            self.key_epoch,
            *self.key_id.as_bytes(),
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentViewProjectionSetItemV2 {
    projection_field_tag: u16,
    projection_rule_digest: Digest32V2,
}

impl AgentViewProjectionSetItemV2 {
    pub fn new(
        projection_field_tag: u16,
        projection_rule_digest: Digest32V2,
    ) -> Result<Self, DeploymentControlErrorV2> {
        if projection_field_tag == 0 || is_zero(projection_rule_digest.as_bytes()) {
            return Err(DeploymentControlErrorV2::InvalidSecurityStateManifest);
        }
        Ok(Self {
            projection_field_tag,
            projection_rule_digest,
        })
    }

    pub const fn projection_field_tag(self) -> u16 {
        self.projection_field_tag
    }

    pub const fn projection_rule_digest(self) -> Digest32V2 {
        self.projection_rule_digest
    }

    fn sort_key(self) -> (u16, [u8; 32]) {
        (
            self.projection_field_tag,
            *self.projection_rule_digest.as_bytes(),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentClaimCompatibilityMaterialV2 {
    pub direction: AgentClaimCompatibilityDirectionV2,
    pub from_manifest_lineage_digest: Digest32V2,
    pub to_manifest_lineage_digest: Digest32V2,
    pub logical_agentd_identity_digest: Digest32V2,
    pub from_agentd_code_identity_digest: Digest32V2,
    pub to_agentd_code_identity_digest: Digest32V2,
    pub from_kerneld_code_identity_digest: Digest32V2,
    pub to_kerneld_code_identity_digest: Digest32V2,
    pub from_protocol_lock_digest: Digest32V2,
    pub to_protocol_lock_digest: Digest32V2,
    pub protocol_abi_digest: Digest32V2,
    pub claim_schema_digest: Digest32V2,
    pub store_id: ClosedStoreIdV2,
    pub from_store_schema_epoch: u64,
    pub to_store_schema_epoch: u64,
    pub persistent_store_compatibility_digest: Digest32V2,
    pub vault_key_read_set: Vec<VaultKeyReadSetItemV2>,
    pub agent_view_projection_set: Vec<AgentViewProjectionSetItemV2>,
    pub not_before_unix_ms: u64,
    pub expires_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentClaimCompatibilityV2 {
    canonical_bytes: Vec<u8>,
    edge_id: Digest32V2,
    edge_identity_digest: Digest32V2,
    vault_key_read_set_digest: Digest32V2,
    agent_view_projection_set_digest: Digest32V2,
    material: AgentClaimCompatibilityMaterialV2,
}

impl AgentClaimCompatibilityV2 {
    pub fn new(
        material: AgentClaimCompatibilityMaterialV2,
    ) -> Result<Self, DeploymentControlErrorV2> {
        validate_material(&material)?;
        let vault_key_read_set_bytes = encode_vault_key_read_set(&material.vault_key_read_set)?;
        let agent_view_projection_set_bytes =
            encode_agent_view_projection_set(&material.agent_view_projection_set)?;
        let vault_key_read_set_digest = hash_counted_set(
            VAULT_KEY_READ_SET_DOMAIN_V2,
            material.vault_key_read_set.len(),
            &vault_key_read_set_bytes,
        )?;
        let agent_view_projection_set_digest = hash_counted_set(
            AGENT_VIEW_PROJECTION_SET_DOMAIN_V2,
            material.agent_view_projection_set.len(),
            &agent_view_projection_set_bytes,
        )?;
        let edge_id = compute_edge_id(&material)?;
        let identity_material = encode_edge(
            &material,
            edge_id,
            vault_key_read_set_digest,
            &vault_key_read_set_bytes,
            agent_view_projection_set_digest,
            &agent_view_projection_set_bytes,
            None,
        )?;
        let edge_identity_digest = hash_domain(AGENT_CLAIM_EDGE_DOMAIN_V2, &identity_material);
        let canonical_bytes = encode_edge(
            &material,
            edge_id,
            vault_key_read_set_digest,
            &vault_key_read_set_bytes,
            agent_view_projection_set_digest,
            &agent_view_projection_set_bytes,
            Some(edge_identity_digest),
        )?;
        Ok(Self {
            canonical_bytes,
            edge_id,
            edge_identity_digest,
            vault_key_read_set_digest,
            agent_view_projection_set_digest,
            material,
        })
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, DeploymentControlErrorV2> {
        check_manifest_object_size(bytes)?;
        let mut decoder = minicbor::Decoder::new(bytes);
        expect_array(&mut decoder, AGENT_CLAIM_EDGE_FIELDS_V2)?;
        let encoded_edge_id = decode_digest(&mut decoder)?;
        let direction = AgentClaimCompatibilityDirectionV2::from_tag(decode_u16(&mut decoder)?)
            .ok_or(DeploymentControlErrorV2::InvalidSecurityStateManifest)?;
        let from_manifest_lineage_digest = decode_digest(&mut decoder)?;
        let to_manifest_lineage_digest = decode_digest(&mut decoder)?;
        let logical_agentd_identity_digest = decode_digest(&mut decoder)?;
        let from_agentd_code_identity_digest = decode_digest(&mut decoder)?;
        let to_agentd_code_identity_digest = decode_digest(&mut decoder)?;
        let from_kerneld_code_identity_digest = decode_digest(&mut decoder)?;
        let to_kerneld_code_identity_digest = decode_digest(&mut decoder)?;
        let from_protocol_lock_digest = decode_digest(&mut decoder)?;
        let to_protocol_lock_digest = decode_digest(&mut decoder)?;
        let protocol_abi_digest = decode_digest(&mut decoder)?;
        let claim_schema_digest = decode_digest(&mut decoder)?;
        let store_id = ClosedStoreIdV2::from_tag(decode_u16(&mut decoder)?)
            .ok_or(DeploymentControlErrorV2::InvalidSecurityStateManifest)?;
        let from_store_schema_epoch = decode_u64(&mut decoder)?;
        let to_store_schema_epoch = decode_u64(&mut decoder)?;
        let persistent_store_compatibility_digest = decode_digest(&mut decoder)?;
        let vault_key_read_set = decode_vault_key_read_set(&mut decoder)?;
        let encoded_vault_digest = decode_digest(&mut decoder)?;
        let agent_view_projection_set = decode_agent_view_projection_set(&mut decoder)?;
        let encoded_view_digest = decode_digest(&mut decoder)?;
        let not_before_unix_ms = decode_u64(&mut decoder)?;
        let expires_at_unix_ms = decode_u64(&mut decoder)?;
        let encoded_identity_digest = decode_digest(&mut decoder)?;
        require_eof(&decoder, bytes)?;
        let value = Self::new(AgentClaimCompatibilityMaterialV2 {
            direction,
            from_manifest_lineage_digest,
            to_manifest_lineage_digest,
            logical_agentd_identity_digest,
            from_agentd_code_identity_digest,
            to_agentd_code_identity_digest,
            from_kerneld_code_identity_digest,
            to_kerneld_code_identity_digest,
            from_protocol_lock_digest,
            to_protocol_lock_digest,
            protocol_abi_digest,
            claim_schema_digest,
            store_id,
            from_store_schema_epoch,
            to_store_schema_epoch,
            persistent_store_compatibility_digest,
            vault_key_read_set,
            agent_view_projection_set,
            not_before_unix_ms,
            expires_at_unix_ms,
        })?;
        if encoded_edge_id != value.edge_id
            || encoded_vault_digest != value.vault_key_read_set_digest
            || encoded_view_digest != value.agent_view_projection_set_digest
            || encoded_identity_digest != value.edge_identity_digest
        {
            return Err(DeploymentControlErrorV2::InvalidSecurityStateManifest);
        }
        require_canonical(value.canonical_bytes(), bytes)?;
        Ok(value)
    }

    pub fn validate_destination(
        &self,
        destination_lineage_digest: Digest32V2,
        destination_protocol_lock_digest: Digest32V2,
        destination_agentd_code_identity_digest: Digest32V2,
        destination_kerneld_code_identity_digest: Digest32V2,
        store_compatibility: &PersistentStoreCompatibilitySetV2,
    ) -> Result<(), DeploymentControlErrorV2> {
        let compatibility = store_compatibility.entry(self.material.store_id);
        if self.material.to_manifest_lineage_digest != destination_lineage_digest
            || self.material.to_protocol_lock_digest != destination_protocol_lock_digest
            || self.material.protocol_abi_digest != destination_protocol_lock_digest
            || self.material.to_agentd_code_identity_digest
                != destination_agentd_code_identity_digest
            || self.material.to_kerneld_code_identity_digest
                != destination_kerneld_code_identity_digest
            || self.material.to_store_schema_epoch != compatibility.expected_current_schema_epoch()
            || self.material.persistent_store_compatibility_digest != compatibility.digest()
        {
            return Err(DeploymentControlErrorV2::InvalidSecurityStateManifest);
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub const fn edge_id(&self) -> Digest32V2 {
        self.edge_id
    }

    pub const fn edge_identity_digest(&self) -> Digest32V2 {
        self.edge_identity_digest
    }

    pub const fn material(&self) -> &AgentClaimCompatibilityMaterialV2 {
        &self.material
    }

    fn sort_key(&self) -> AgentClaimEdgeSortKeyV2 {
        (
            self.material.direction.tag(),
            *self.material.from_manifest_lineage_digest.as_bytes(),
            *self.material.to_manifest_lineage_digest.as_bytes(),
            *self.material.logical_agentd_identity_digest.as_bytes(),
            *self.material.from_protocol_lock_digest.as_bytes(),
            *self.material.to_protocol_lock_digest.as_bytes(),
            *self.material.claim_schema_digest.as_bytes(),
            self.material.store_id.tag(),
            *self.edge_id.as_bytes(),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentClaimCompatibilitySetV2 {
    canonical_bytes: Vec<u8>,
    edges: Vec<AgentClaimCompatibilityV2>,
}

impl AgentClaimCompatibilitySetV2 {
    pub fn new(edges: Vec<AgentClaimCompatibilityV2>) -> Result<Self, DeploymentControlErrorV2> {
        let maximum = usize::try_from(
            DeploymentHardLimitsV2::compiled().max_agent_claim_compatibility_edges(),
        )
        .map_err(|_| DeploymentControlErrorV2::InvalidSecurityStateManifest)?;
        if edges.len() > maximum
            || edges
                .windows(2)
                .any(|pair| pair[0].sort_key() >= pair[1].sort_key())
        {
            return Err(DeploymentControlErrorV2::InvalidSecurityStateManifest);
        }
        let mut encoder = minicbor::Encoder::new(Vec::new());
        encoder
            .array(edges.len() as u64)
            .map_err(|_| DeploymentControlErrorV2::InvalidSecurityStateManifest)?;
        for edge in &edges {
            encoder
                .writer_mut()
                .extend_from_slice(edge.canonical_bytes());
        }
        Ok(Self {
            canonical_bytes: encoder.into_writer(),
            edges,
        })
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, DeploymentControlErrorV2> {
        check_manifest_object_size(bytes)?;
        let mut decoder = minicbor::Decoder::new(bytes);
        let count = decode_bounded_array_length(
            &mut decoder,
            DeploymentHardLimitsV2::compiled().max_agent_claim_compatibility_edges(),
        )?;
        let mut edges = Vec::with_capacity(count);
        for _ in 0..count {
            let start = decoder.position();
            decoder
                .skip()
                .map_err(|_| DeploymentControlErrorV2::InvalidSecurityStateManifest)?;
            edges.push(AgentClaimCompatibilityV2::from_canonical_bytes(
                decoder
                    .input()
                    .get(start..decoder.position())
                    .ok_or(DeploymentControlErrorV2::InvalidSecurityStateManifest)?,
            )?);
        }
        require_eof(&decoder, bytes)?;
        let value = Self::new(edges)?;
        require_canonical(value.canonical_bytes(), bytes)?;
        Ok(value)
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub fn edges(&self) -> &[AgentClaimCompatibilityV2] {
        &self.edges
    }
}

fn validate_material(
    material: &AgentClaimCompatibilityMaterialV2,
) -> Result<(), DeploymentControlErrorV2> {
    let digests = [
        material.from_manifest_lineage_digest,
        material.to_manifest_lineage_digest,
        material.logical_agentd_identity_digest,
        material.from_agentd_code_identity_digest,
        material.to_agentd_code_identity_digest,
        material.from_kerneld_code_identity_digest,
        material.to_kerneld_code_identity_digest,
        material.from_protocol_lock_digest,
        material.to_protocol_lock_digest,
        material.protocol_abi_digest,
        material.claim_schema_digest,
        material.persistent_store_compatibility_digest,
    ];
    if material.from_manifest_lineage_digest == material.to_manifest_lineage_digest
        || material.store_id != ClosedStoreIdV2::AgentdRecovery
        || material.from_store_schema_epoch == 0
        || material.to_store_schema_epoch == 0
        || material.not_before_unix_ms >= material.expires_at_unix_ms
        || digests.iter().any(|digest| is_zero(digest.as_bytes()))
        || material.vault_key_read_set.len() as u64
            > DeploymentHardLimitsV2::compiled().max_agent_claim_vault_key_reads()
        || material.agent_view_projection_set.len() as u64
            > DeploymentHardLimitsV2::compiled().max_agent_claim_view_projections()
        || material
            .vault_key_read_set
            .windows(2)
            .any(|pair| pair[0].sort_key() >= pair[1].sort_key())
        || material
            .agent_view_projection_set
            .windows(2)
            .any(|pair| pair[0].sort_key() >= pair[1].sort_key())
    {
        return Err(DeploymentControlErrorV2::InvalidSecurityStateManifest);
    }
    Ok(())
}

fn compute_edge_id(
    material: &AgentClaimCompatibilityMaterialV2,
) -> Result<Digest32V2, DeploymentControlErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(AGENT_CLAIM_EDGE_ID_FIELDS_V2)
        .and_then(|encoder| encoder.u16(material.direction.tag()))
        .and_then(|encoder| encoder.bytes(material.from_manifest_lineage_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(material.to_manifest_lineage_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(material.logical_agentd_identity_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(material.claim_schema_digest.as_bytes()))
        .map_err(|_| DeploymentControlErrorV2::InvalidSecurityStateManifest)?;
    Ok(hash_domain(
        AGENT_CLAIM_EDGE_ID_DOMAIN_V2,
        &encoder.into_writer(),
    ))
}

#[allow(clippy::too_many_arguments)]
fn encode_edge(
    material: &AgentClaimCompatibilityMaterialV2,
    edge_id: Digest32V2,
    vault_key_read_set_digest: Digest32V2,
    vault_key_read_set_bytes: &[u8],
    agent_view_projection_set_digest: Digest32V2,
    agent_view_projection_set_bytes: &[u8],
    edge_identity_digest: Option<Digest32V2>,
) -> Result<Vec<u8>, DeploymentControlErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(if edge_identity_digest.is_some() {
            AGENT_CLAIM_EDGE_FIELDS_V2
        } else {
            AGENT_CLAIM_EDGE_FIELDS_V2 - 1
        })
        .and_then(|encoder| encoder.bytes(edge_id.as_bytes()))
        .and_then(|encoder| encoder.u16(material.direction.tag()))
        .and_then(|encoder| encoder.bytes(material.from_manifest_lineage_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(material.to_manifest_lineage_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(material.logical_agentd_identity_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(material.from_agentd_code_identity_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(material.to_agentd_code_identity_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(material.from_kerneld_code_identity_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(material.to_kerneld_code_identity_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(material.from_protocol_lock_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(material.to_protocol_lock_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(material.protocol_abi_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(material.claim_schema_digest.as_bytes()))
        .and_then(|encoder| encoder.u16(material.store_id.tag()))
        .and_then(|encoder| encoder.u64(material.from_store_schema_epoch))
        .and_then(|encoder| encoder.u64(material.to_store_schema_epoch))
        .and_then(|encoder| {
            encoder.bytes(material.persistent_store_compatibility_digest.as_bytes())
        })
        .map_err(|_| DeploymentControlErrorV2::InvalidSecurityStateManifest)?;
    encoder
        .writer_mut()
        .extend_from_slice(vault_key_read_set_bytes);
    encoder
        .bytes(vault_key_read_set_digest.as_bytes())
        .map_err(|_| DeploymentControlErrorV2::InvalidSecurityStateManifest)?;
    encoder
        .writer_mut()
        .extend_from_slice(agent_view_projection_set_bytes);
    encoder
        .bytes(agent_view_projection_set_digest.as_bytes())
        .and_then(|encoder| encoder.u64(material.not_before_unix_ms))
        .and_then(|encoder| encoder.u64(material.expires_at_unix_ms))
        .map_err(|_| DeploymentControlErrorV2::InvalidSecurityStateManifest)?;
    if let Some(digest) = edge_identity_digest {
        encoder
            .bytes(digest.as_bytes())
            .map_err(|_| DeploymentControlErrorV2::InvalidSecurityStateManifest)?;
    }
    Ok(encoder.into_writer())
}

fn encode_vault_key_read_set(
    items: &[VaultKeyReadSetItemV2],
) -> Result<Vec<u8>, DeploymentControlErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(items.len() as u64)
        .map_err(|_| DeploymentControlErrorV2::InvalidSecurityStateManifest)?;
    for item in items {
        encoder
            .array(VAULT_KEY_READ_ITEM_FIELDS_V2)
            .and_then(|encoder| encoder.u16(item.vault_key_role_tag))
            .and_then(|encoder| encoder.bytes(item.key_id.as_bytes()))
            .and_then(|encoder| encoder.u64(item.key_epoch))
            .map_err(|_| DeploymentControlErrorV2::InvalidSecurityStateManifest)?;
    }
    Ok(encoder.into_writer())
}

fn decode_vault_key_read_set(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<Vec<VaultKeyReadSetItemV2>, DeploymentControlErrorV2> {
    let count = decode_bounded_array_length(
        decoder,
        DeploymentHardLimitsV2::compiled().max_agent_claim_vault_key_reads(),
    )?;
    let mut items = Vec::with_capacity(count);
    for _ in 0..count {
        expect_array(decoder, VAULT_KEY_READ_ITEM_FIELDS_V2)?;
        let role = decode_u16(decoder)?;
        let key_bytes = decoder
            .bytes()
            .map_err(|_| DeploymentControlErrorV2::InvalidSecurityStateManifest)?;
        let key_bytes: [u8; 32] = key_bytes
            .try_into()
            .map_err(|_| DeploymentControlErrorV2::InvalidSecurityStateManifest)?;
        items.push(VaultKeyReadSetItemV2::new(
            role,
            VaultKeyIdV2::new(key_bytes),
            decode_u64(decoder)?,
        )?);
    }
    Ok(items)
}

fn encode_agent_view_projection_set(
    items: &[AgentViewProjectionSetItemV2],
) -> Result<Vec<u8>, DeploymentControlErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(items.len() as u64)
        .map_err(|_| DeploymentControlErrorV2::InvalidSecurityStateManifest)?;
    for item in items {
        encoder
            .array(AGENT_VIEW_ITEM_FIELDS_V2)
            .and_then(|encoder| encoder.u16(item.projection_field_tag))
            .and_then(|encoder| encoder.bytes(item.projection_rule_digest.as_bytes()))
            .map_err(|_| DeploymentControlErrorV2::InvalidSecurityStateManifest)?;
    }
    Ok(encoder.into_writer())
}

fn decode_agent_view_projection_set(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<Vec<AgentViewProjectionSetItemV2>, DeploymentControlErrorV2> {
    let count = decode_bounded_array_length(
        decoder,
        DeploymentHardLimitsV2::compiled().max_agent_claim_view_projections(),
    )?;
    let mut items = Vec::with_capacity(count);
    for _ in 0..count {
        expect_array(decoder, AGENT_VIEW_ITEM_FIELDS_V2)?;
        items.push(AgentViewProjectionSetItemV2::new(
            decode_u16(decoder)?,
            decode_digest(decoder)?,
        )?);
    }
    Ok(items)
}

fn hash_counted_set(
    domain: &[u8],
    count: usize,
    canonical_set: &[u8],
) -> Result<Digest32V2, DeploymentControlErrorV2> {
    let count =
        u64::try_from(count).map_err(|_| DeploymentControlErrorV2::InvalidSecurityStateManifest)?;
    let mut material = Vec::with_capacity(8 + canonical_set.len());
    material.extend_from_slice(&count.to_be_bytes());
    material.extend_from_slice(canonical_set);
    Ok(hash_domain(domain, &material))
}
