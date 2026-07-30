#[cfg(any(test, feature = "test-support"))]
use ed25519_dalek::SigningKey;
use savana_kernel_protocol::v2::Digest32V2;

use super::deployment_manifest_primitives::{
    check_manifest_object_size, decode_bounded_array_length, decode_digest, decode_nested,
    decode_u16, expect_array, hash_domain, require_canonical, require_eof,
};
use super::deployment_release_trust::{
    decode_component_ref, decode_domain_signature, encode_component_ref, encode_domain_signature,
    manifest_component_binding_digest,
};
use super::{
    AgentClaimCompatibilitySetV2, BinaryClosureV2, BootstrapTcbLockV2, ClosedLogicalPathIdV2,
    ClosedSecurityDomainV2, DeploymentControlErrorV2, DeploymentHardLimitsV2, FileTreeV2,
    ManifestComponentKindV2, ManifestComponentRefV2, ManifestDomainSignatureV2,
    PersistentStoreCompatibilitySetV2, PlatformClosureV2, PlatformLockV2, ReleaseTrustRootSetV2,
    SecurityStateClosureV2, SourceLockV2, VersionedIdentityV2,
};

const MANIFEST_SCHEMA_VERSION_V2: u16 = 2;
const MANIFEST_OBJECT_DOMAIN_TAG_V2: u16 = 1;
const MANIFEST_COMPLETE_FIELDS_V2: u64 = 17;
const MANIFEST_PAYLOAD_FIELDS_V2: u64 = 16;
const COMPONENT_SIGNATURE_FIELDS_V2: u64 = 3;
const COMPONENT_BINDING_FIELDS_V2: u64 = 2;
const MANIFEST_PAYLOAD_DOMAIN_V2: &[u8] = b"savana.security-state-manifest.v2.payload\0";
const MANIFEST_SIGNED_DOMAIN_V2: &[u8] = b"savana.security-state-manifest.v2.signed\0";
#[cfg(any(test, feature = "test-support"))]
const MANIFEST_COMPONENT_SIGNATURE_DOMAIN_V2: &[u8] = b"savana.manifest-component.v2.signature\0";
#[cfg(any(test, feature = "test-support"))]
const MANIFEST_RELEASE_SIGNATURE_DOMAIN_V2: &[u8] = b"savana.manifest-release.v2.signature\0";
#[cfg(any(test, feature = "test-support"))]
const MANIFEST_COMPONENT_SIGNATURE_TAG_V2: u16 = 1;
#[cfg(any(test, feature = "test-support"))]
const MANIFEST_RELEASE_SIGNATURE_TAG_V2: u16 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum InstallationClassV2 {
    NormalApplication = 1,
    BootstrapEpochBridge = 2,
}

impl InstallationClassV2 {
    pub const fn from_tag(tag: u16) -> Option<Self> {
        match tag {
            1 => Some(Self::NormalApplication),
            2 => Some(Self::BootstrapEpochBridge),
            _ => None,
        }
    }

    pub const fn tag(self) -> u16 {
        self as u16
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManifestComponentSignatureV2 {
    component: ManifestComponentRefV2,
    authorization_id: Digest32V2,
    signature: ManifestDomainSignatureV2,
}

impl ManifestComponentSignatureV2 {
    pub const fn component(self) -> ManifestComponentRefV2 {
        self.component
    }

    pub const fn authorization_id(self) -> Digest32V2 {
        self.authorization_id
    }

    pub const fn signature(self) -> ManifestDomainSignatureV2 {
        self.signature
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityStateManifestMaterialV2 {
    pub installation_class: InstallationClassV2,
    pub target_platform: PlatformLockV2,
    pub release: VersionedIdentityV2,
    pub source_lock: SourceLockV2,
    pub binary_closure: BinaryClosureV2,
    pub security_state: SecurityStateClosureV2,
    pub platform_closure: PlatformClosureV2,
    pub bootstrap_tcb_lock: BootstrapTcbLockV2,
    pub persistent_store_compatibility: PersistentStoreCompatibilitySetV2,
    pub agent_claim_compatibility_edges: AgentClaimCompatibilitySetV2,
    pub file_tree: FileTreeV2,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityStateManifestV2 {
    canonical_bytes: Vec<u8>,
    payload_digest: Digest32V2,
    signed_digest: Digest32V2,
    material: SecurityStateManifestMaterialV2,
    component_signature_set: Vec<ManifestComponentSignatureV2>,
    release_signature: ManifestDomainSignatureV2,
}

impl SecurityStateManifestV2 {
    pub fn from_canonical_bytes(
        bytes: &[u8],
        release_trust_root_set: &ReleaseTrustRootSetV2,
        verification_time_unix_ms: u64,
    ) -> Result<Self, DeploymentControlErrorV2> {
        check_manifest_object_size(bytes)?;
        let (material, component_signature_set, release_signature) = decode_manifest(bytes)?;
        Self::from_parts(
            material,
            component_signature_set,
            release_signature,
            release_trust_root_set,
            verification_time_unix_ms,
            Some(bytes),
        )
    }

    #[cfg(any(test, feature = "test-support"))]
    #[allow(clippy::too_many_arguments)]
    pub fn new_signed_for_test(
        material: SecurityStateManifestMaterialV2,
        release_trust_root_set: &ReleaseTrustRootSetV2,
        component_signing_key: &SigningKey,
        component_key_epoch: u64,
        release_signing_key: &SigningKey,
        release_key_epoch: u64,
        verification_time_unix_ms: u64,
    ) -> Result<Self, DeploymentControlErrorV2> {
        validate_material(&material, release_trust_root_set, verification_time_unix_ms)?;
        let projected = project_component_refs(&material)?;
        let authorizations = release_trust_root_set.component_authorizations();
        if authorizations.len() != projected.len() {
            return Err(DeploymentControlErrorV2::InvalidSecurityStateManifest);
        }
        let bindings: Vec<(ManifestComponentRefV2, Digest32V2)> = projected
            .iter()
            .zip(authorizations)
            .map(|(component, authorization)| {
                if authorization.component() != *component {
                    return Err(DeploymentControlErrorV2::InvalidSecurityStateManifest);
                }
                Ok((*component, authorization.authorization_id()))
            })
            .collect::<Result<_, _>>()?;
        let payload_digest = hash_domain(
            MANIFEST_PAYLOAD_DOMAIN_V2,
            &encode_manifest_payload(&material, &bindings)?,
        );
        let component_signature_set = bindings
            .iter()
            .map(|(component, authorization_id)| {
                let binding_digest = manifest_component_binding_digest(
                    *component,
                    *authorization_id,
                    payload_digest,
                )?;
                Ok(ManifestComponentSignatureV2 {
                    component: *component,
                    authorization_id: *authorization_id,
                    signature: ManifestDomainSignatureV2::sign_for_test(
                        MANIFEST_COMPONENT_SIGNATURE_TAG_V2,
                        MANIFEST_COMPONENT_SIGNATURE_DOMAIN_V2,
                        binding_digest,
                        component_signing_key,
                        component_key_epoch,
                    ),
                })
            })
            .collect::<Result<Vec<_>, DeploymentControlErrorV2>>()?;
        let release_signature = ManifestDomainSignatureV2::sign_for_test(
            MANIFEST_RELEASE_SIGNATURE_TAG_V2,
            MANIFEST_RELEASE_SIGNATURE_DOMAIN_V2,
            payload_digest,
            release_signing_key,
            release_key_epoch,
        );
        Self::from_parts(
            material,
            component_signature_set,
            release_signature,
            release_trust_root_set,
            verification_time_unix_ms,
            None,
        )
    }

    fn from_parts(
        material: SecurityStateManifestMaterialV2,
        component_signature_set: Vec<ManifestComponentSignatureV2>,
        release_signature: ManifestDomainSignatureV2,
        release_trust_root_set: &ReleaseTrustRootSetV2,
        verification_time_unix_ms: u64,
        original: Option<&[u8]>,
    ) -> Result<Self, DeploymentControlErrorV2> {
        validate_material(&material, release_trust_root_set, verification_time_unix_ms)?;
        let projected = project_component_refs(&material)?;
        if component_signature_set.len() != projected.len()
            || release_trust_root_set.component_authorizations().len() != projected.len()
        {
            return Err(DeploymentControlErrorV2::InvalidSecurityStateManifest);
        }
        let mut bindings = Vec::with_capacity(projected.len());
        for ((expected, signed), authorization) in projected
            .iter()
            .zip(&component_signature_set)
            .zip(release_trust_root_set.component_authorizations())
        {
            if signed.component != *expected
                || authorization.component() != *expected
                || signed.authorization_id != authorization.authorization_id()
            {
                return Err(DeploymentControlErrorV2::InvalidSecurityStateManifest);
            }
            bindings.push((signed.component, signed.authorization_id));
        }
        let payload_digest = hash_domain(
            MANIFEST_PAYLOAD_DOMAIN_V2,
            &encode_manifest_payload(&material, &bindings)?,
        );
        for signature in &component_signature_set {
            release_trust_root_set.verify_component_signature(
                signature.component,
                signature.authorization_id,
                signature.signature,
                manifest_component_binding_digest(
                    signature.component,
                    signature.authorization_id,
                    payload_digest,
                )?,
                verification_time_unix_ms,
            )?;
        }
        release_trust_root_set.verify_release_signature(
            release_signature,
            payload_digest,
            verification_time_unix_ms,
        )?;
        let canonical_bytes =
            encode_manifest_complete(&material, &component_signature_set, release_signature)?;
        if let Some(original) = original {
            require_canonical(&canonical_bytes, original)?;
        }
        let signed_digest = hash_domain(MANIFEST_SIGNED_DOMAIN_V2, &canonical_bytes);
        Ok(Self {
            canonical_bytes,
            payload_digest,
            signed_digest,
            material,
            component_signature_set,
            release_signature,
        })
    }

    pub fn validate_for_normal_transaction(&self) -> Result<(), DeploymentControlErrorV2> {
        if self.material.installation_class != InstallationClassV2::NormalApplication {
            return Err(DeploymentControlErrorV2::InvalidSecurityStateManifest);
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub const fn payload_digest(&self) -> Digest32V2 {
        self.payload_digest
    }

    pub const fn signed_digest(&self) -> Digest32V2 {
        self.signed_digest
    }

    pub const fn material(&self) -> &SecurityStateManifestMaterialV2 {
        &self.material
    }

    pub fn component_signature_set(&self) -> &[ManifestComponentSignatureV2] {
        &self.component_signature_set
    }

    pub const fn release_signature(&self) -> ManifestDomainSignatureV2 {
        self.release_signature
    }
}

fn validate_material(
    material: &SecurityStateManifestMaterialV2,
    release_trust_root_set: &ReleaseTrustRootSetV2,
    verification_time_unix_ms: u64,
) -> Result<(), DeploymentControlErrorV2> {
    if verification_time_unix_ms == 0
        || material.release.domain() != ClosedSecurityDomainV2::BinaryRelease
        || material.target_platform.target_os() != material.binary_closure.target_os()
        || material.target_platform.target_architecture()
            != material.binary_closure.target_architecture()
        || material.target_platform.target_os() != material.bootstrap_tcb_lock.target_os()
        || material.target_platform.target_architecture()
            != material.bootstrap_tcb_lock.target_architecture()
        || material
            .file_tree
            .merkle_root()
            .as_bytes()
            .iter()
            .all(|byte| *byte == 0)
    {
        return Err(DeploymentControlErrorV2::InvalidSecurityStateManifest);
    }
    validate_identity_time(&material.release, verification_time_unix_ms)?;
    for identity in material
        .security_state
        .identities()
        .iter()
        .chain(material.platform_closure.identities())
    {
        validate_identity_time(identity, verification_time_unix_ms)?;
    }
    release_trust_root_set
        .matches_versioned_identity(material.bootstrap_tcb_lock.release_trust_root_set())?;
    validate_file_tree_binding(material)?;
    let destination_lineage = material.release.manifest_lineage_digest()?;
    let protocol_lock = material
        .security_state
        .identity(ClosedSecurityDomainV2::ProtocolLock)
        .ok_or(DeploymentControlErrorV2::InvalidSecurityStateManifest)?
        .content_digest();
    for edge in material.agent_claim_compatibility_edges.edges() {
        edge.validate_destination(
            destination_lineage,
            protocol_lock,
            material
                .binary_closure
                .agentd()
                .platform_code_identity_digest(),
            material
                .binary_closure
                .kerneld()
                .platform_code_identity_digest(),
            &material.persistent_store_compatibility,
        )?;
    }
    Ok(())
}

fn validate_identity_time(
    identity: &VersionedIdentityV2,
    at_unix_ms: u64,
) -> Result<(), DeploymentControlErrorV2> {
    if at_unix_ms < identity.not_before_unix_ms() || at_unix_ms > identity.not_after_unix_ms() {
        return Err(DeploymentControlErrorV2::InvalidSecurityStateManifest);
    }
    Ok(())
}

fn validate_file_tree_binding(
    material: &SecurityStateManifestMaterialV2,
) -> Result<(), DeploymentControlErrorV2> {
    let binary = &material.binary_closure;
    let expected = [
        (ClosedLogicalPathIdV2::JarvisExecutable, binary.jarvis()),
        (ClosedLogicalPathIdV2::AgentdExecutable, binary.agentd()),
        (ClosedLogicalPathIdV2::IngressdExecutable, binary.ingressd()),
        (ClosedLogicalPathIdV2::KerneldExecutable, binary.kerneld()),
        (
            ClosedLogicalPathIdV2::ApprovaldExecutable,
            binary.approvald(),
        ),
        (ClosedLogicalPathIdV2::ExecdExecutable, binary.execd()),
        (
            ClosedLogicalPathIdV2::ApprovalctlExecutable,
            binary.approvalctl(),
        ),
        (
            ClosedLogicalPathIdV2::WorkerSandboxExecutable,
            binary.worker_sandbox(),
        ),
        (
            ClosedLogicalPathIdV2::ParserWorkerExecutable,
            &binary.parser_worker_set().artifacts()[0],
        ),
        (
            ClosedLogicalPathIdV2::ConnectorWorkerExecutable,
            &binary.connector_worker_set().artifacts()[0],
        ),
    ];
    for (path, artifact) in expected {
        let entry = material
            .file_tree
            .entries()
            .get(path.tag() as usize - 1)
            .ok_or(DeploymentControlErrorV2::InvalidSecurityStateManifest)?;
        if entry.artifact_identity() != Some(artifact) {
            return Err(DeploymentControlErrorV2::InvalidSecurityStateManifest);
        }
    }
    for entry in material.file_tree.entries() {
        if entry.artifact_identity().is_some_and(|artifact| {
            artifact.target_os() != material.target_platform.target_os()
                || artifact.target_architecture() != material.target_platform.target_architecture()
        }) {
            return Err(DeploymentControlErrorV2::InvalidSecurityStateManifest);
        }
    }
    Ok(())
}

fn project_component_refs(
    material: &SecurityStateManifestMaterialV2,
) -> Result<Vec<ManifestComponentRefV2>, DeploymentControlErrorV2> {
    let mut components = Vec::new();
    for artifact in material.binary_closure.fixed_artifacts() {
        components.push(ManifestComponentRefV2::new(
            ManifestComponentKindV2::BinaryArtifact,
            artifact.identity_digest(),
        )?);
    }
    for artifact in material
        .binary_closure
        .parser_worker_set()
        .artifacts()
        .iter()
        .chain(material.binary_closure.connector_worker_set().artifacts())
    {
        components.push(ManifestComponentRefV2::new(
            ManifestComponentKindV2::BinaryArtifact,
            artifact.identity_digest(),
        )?);
    }
    for identity in material.security_state.identities() {
        components.push(ManifestComponentRefV2::new(
            ManifestComponentKindV2::SecurityDomainObject,
            identity.content_digest(),
        )?);
    }
    for edge in material.agent_claim_compatibility_edges.edges() {
        components.push(ManifestComponentRefV2::new(
            ManifestComponentKindV2::SecurityDomainObject,
            edge.edge_identity_digest(),
        )?);
    }
    for identity in material.platform_closure.identities() {
        components.push(ManifestComponentRefV2::new(
            ManifestComponentKindV2::PlatformDomainObject,
            identity.content_digest(),
        )?);
    }
    for artifact in [
        material.bootstrap_tcb_lock.deploy_helper_identity(),
        material.bootstrap_tcb_lock.deploy_watchdog_identity(),
    ] {
        components.push(ManifestComponentRefV2::new(
            ManifestComponentKindV2::BootstrapArtifact,
            artifact.identity_digest(),
        )?);
    }
    components.sort_by_key(|component| {
        (
            component.kind().tag(),
            *component.component_identity_digest().as_bytes(),
        )
    });
    if components.windows(2).any(|pair| pair[0] == pair[1])
        || components.len() as u64 > DeploymentHardLimitsV2::compiled().max_component_signatures()
    {
        return Err(DeploymentControlErrorV2::InvalidSecurityStateManifest);
    }
    Ok(components)
}

fn decode_manifest(
    bytes: &[u8],
) -> Result<
    (
        SecurityStateManifestMaterialV2,
        Vec<ManifestComponentSignatureV2>,
        ManifestDomainSignatureV2,
    ),
    DeploymentControlErrorV2,
> {
    let mut decoder = minicbor::Decoder::new(bytes);
    expect_array(&mut decoder, MANIFEST_COMPLETE_FIELDS_V2)?;
    if decode_u16(&mut decoder)? != MANIFEST_SCHEMA_VERSION_V2
        || decode_u16(&mut decoder)? != MANIFEST_OBJECT_DOMAIN_TAG_V2
    {
        return Err(DeploymentControlErrorV2::InvalidSecurityStateManifest);
    }
    let installation_class = InstallationClassV2::from_tag(decode_u16(&mut decoder)?)
        .ok_or(DeploymentControlErrorV2::InvalidSecurityStateManifest)?;
    let target_platform = decode_nested(&mut decoder, PlatformLockV2::from_canonical_bytes)?;
    let release = decode_nested(&mut decoder, VersionedIdentityV2::from_canonical_bytes)?;
    if decode_digest(&mut decoder)? != DeploymentHardLimitsV2::compiled().digest() {
        return Err(DeploymentControlErrorV2::InvalidSecurityStateManifest);
    }
    let source_lock = decode_nested(&mut decoder, SourceLockV2::from_canonical_bytes)?;
    let binary_closure = decode_nested(&mut decoder, BinaryClosureV2::from_canonical_bytes)?;
    let security_state = decode_nested(&mut decoder, SecurityStateClosureV2::from_canonical_bytes)?;
    let platform_closure = decode_nested(&mut decoder, PlatformClosureV2::from_canonical_bytes)?;
    let bootstrap_tcb_lock = decode_nested(&mut decoder, BootstrapTcbLockV2::from_canonical_bytes)?;
    let persistent_store_compatibility = decode_nested(
        &mut decoder,
        PersistentStoreCompatibilitySetV2::from_canonical_bytes,
    )?;
    let agent_claim_compatibility_edges = decode_nested(
        &mut decoder,
        AgentClaimCompatibilitySetV2::from_canonical_bytes,
    )?;
    let file_tree = decode_nested(&mut decoder, FileTreeV2::from_canonical_bytes)?;
    if decode_digest(&mut decoder)? != file_tree.merkle_root() {
        return Err(DeploymentControlErrorV2::InvalidSecurityStateManifest);
    }
    let count = decode_bounded_array_length(
        &mut decoder,
        DeploymentHardLimitsV2::compiled().max_component_signatures(),
    )?;
    let mut component_signature_set = Vec::with_capacity(count);
    for _ in 0..count {
        expect_array(&mut decoder, COMPONENT_SIGNATURE_FIELDS_V2)?;
        component_signature_set.push(ManifestComponentSignatureV2 {
            component: decode_component_ref(&mut decoder)?,
            authorization_id: decode_digest(&mut decoder)?,
            signature: decode_domain_signature(&mut decoder)?,
        });
    }
    let release_signature = decode_domain_signature(&mut decoder)?;
    require_eof(&decoder, bytes)?;
    Ok((
        SecurityStateManifestMaterialV2 {
            installation_class,
            target_platform,
            release,
            source_lock,
            binary_closure,
            security_state,
            platform_closure,
            bootstrap_tcb_lock,
            persistent_store_compatibility,
            agent_claim_compatibility_edges,
            file_tree,
        },
        component_signature_set,
        release_signature,
    ))
}

fn encode_manifest_payload(
    material: &SecurityStateManifestMaterialV2,
    bindings: &[(ManifestComponentRefV2, Digest32V2)],
) -> Result<Vec<u8>, DeploymentControlErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encode_manifest_prefix(&mut encoder, MANIFEST_PAYLOAD_FIELDS_V2, material)?;
    encoder
        .array(bindings.len() as u64)
        .map_err(|_| DeploymentControlErrorV2::InvalidSecurityStateManifest)?;
    for (component, authorization_id) in bindings {
        encoder
            .array(COMPONENT_BINDING_FIELDS_V2)
            .map_err(|_| DeploymentControlErrorV2::InvalidSecurityStateManifest)?;
        encode_component_ref(&mut encoder, *component)?;
        encoder
            .bytes(authorization_id.as_bytes())
            .map_err(|_| DeploymentControlErrorV2::InvalidSecurityStateManifest)?;
    }
    Ok(encoder.into_writer())
}

fn encode_manifest_complete(
    material: &SecurityStateManifestMaterialV2,
    signatures: &[ManifestComponentSignatureV2],
    release_signature: ManifestDomainSignatureV2,
) -> Result<Vec<u8>, DeploymentControlErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encode_manifest_prefix(&mut encoder, MANIFEST_COMPLETE_FIELDS_V2, material)?;
    encoder
        .array(signatures.len() as u64)
        .map_err(|_| DeploymentControlErrorV2::InvalidSecurityStateManifest)?;
    for signature in signatures {
        encoder
            .array(COMPONENT_SIGNATURE_FIELDS_V2)
            .map_err(|_| DeploymentControlErrorV2::InvalidSecurityStateManifest)?;
        encode_component_ref(&mut encoder, signature.component)?;
        encoder
            .bytes(signature.authorization_id.as_bytes())
            .map_err(|_| DeploymentControlErrorV2::InvalidSecurityStateManifest)?;
        encode_domain_signature(&mut encoder, signature.signature)?;
    }
    encode_domain_signature(&mut encoder, release_signature)?;
    Ok(encoder.into_writer())
}

fn encode_manifest_prefix(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    field_count: u64,
    material: &SecurityStateManifestMaterialV2,
) -> Result<(), DeploymentControlErrorV2> {
    encoder
        .array(field_count)
        .and_then(|encoder| encoder.u16(MANIFEST_SCHEMA_VERSION_V2))
        .and_then(|encoder| encoder.u16(MANIFEST_OBJECT_DOMAIN_TAG_V2))
        .and_then(|encoder| encoder.u16(material.installation_class.tag()))
        .map_err(|_| DeploymentControlErrorV2::InvalidSecurityStateManifest)?;
    for nested in [
        material.target_platform.canonical_bytes(),
        material.release.canonical_bytes(),
    ] {
        encoder.writer_mut().extend_from_slice(nested);
    }
    encoder
        .bytes(DeploymentHardLimitsV2::compiled().digest().as_bytes())
        .map_err(|_| DeploymentControlErrorV2::InvalidSecurityStateManifest)?;
    for nested in [
        material.source_lock.canonical_bytes(),
        material.binary_closure.canonical_bytes(),
        material.security_state.canonical_bytes(),
        material.platform_closure.canonical_bytes(),
        material.bootstrap_tcb_lock.canonical_bytes(),
        material.persistent_store_compatibility.canonical_bytes(),
        material.agent_claim_compatibility_edges.canonical_bytes(),
        material.file_tree.canonical_bytes(),
    ] {
        encoder.writer_mut().extend_from_slice(nested);
    }
    encoder
        .bytes(material.file_tree.merkle_root().as_bytes())
        .map(|_| ())
        .map_err(|_| DeploymentControlErrorV2::InvalidSecurityStateManifest)
}
