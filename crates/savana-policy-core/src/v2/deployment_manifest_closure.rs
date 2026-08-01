use savana_kernel_protocol::v2::Digest32V2;

use super::deployment_manifest_primitives::{
    check_manifest_object_size, decode_nested, expect_array, hash_domain, is_zero,
    require_canonical, require_eof,
};
use super::{
    ArtifactIdentityV2, ArtifactSetIdentityV2, ClosedArtifactTypeV2, ClosedSecurityDomainV2,
    ClosedTargetArchitectureV2, ClosedTargetOsV2, DeploymentControlErrorV2, VersionedIdentityV2,
};

const BINARY_CLOSURE_FIELDS_V2: u64 = 10;
const SECURITY_STATE_CLOSURE_FIELDS_V2: u64 = 18;
const PLATFORM_CLOSURE_FIELDS_V2: u64 = 6;
const BOOTSTRAP_TCB_LOCK_FIELDS_V2: u64 = 13;
const BINARY_CLOSURE_DOMAIN_V2: &[u8] = b"savana.binary-closure.v2\0";
const SECURITY_STATE_CLOSURE_DOMAIN_V2: &[u8] = b"savana.security-state-closure.v2\0";
const PLATFORM_CLOSURE_DOMAIN_V2: &[u8] = b"savana.platform-closure.v2\0";
const BOOTSTRAP_TCB_LOCK_DOMAIN_V2: &[u8] = b"savana.bootstrap-tcb-lock.v2\0";

const SECURITY_STATE_DOMAINS_V2: [ClosedSecurityDomainV2; 18] = [
    ClosedSecurityDomainV2::Policy,
    ClosedSecurityDomainV2::Registry,
    ClosedSecurityDomainV2::Ontology,
    ClosedSecurityDomainV2::ModelSet,
    ClosedSecurityDomainV2::ResourceProfile,
    ClosedSecurityDomainV2::DestinationProjection,
    ClosedSecurityDomainV2::DisplayProjection,
    ClosedSecurityDomainV2::ValidatorSet,
    ClosedSecurityDomainV2::GrammarSchema,
    ClosedSecurityDomainV2::ProtocolLock,
    ClosedSecurityDomainV2::ServiceIdentityLock,
    ClosedSecurityDomainV2::ApprovalLock,
    ClosedSecurityDomainV2::JarvisArtifact,
    ClosedSecurityDomainV2::EgressPolicySet,
    ClosedSecurityDomainV2::ExecutorConnectorRegistry,
    ClosedSecurityDomainV2::ExecutorKeyLock,
    ClosedSecurityDomainV2::PlannerLock,
    ClosedSecurityDomainV2::CompletionEvidenceTrustPolicy,
];

const PLATFORM_DOMAINS_V2: [ClosedSecurityDomainV2; 6] = [
    ClosedSecurityDomainV2::ServiceUnitSet,
    ClosedSecurityDomainV2::SocketOrXpcUnitSet,
    ClosedSecurityDomainV2::ServiceStoreProjectionSet,
    ClosedSecurityDomainV2::SandboxProfileSet,
    ClosedSecurityDomainV2::EntitlementProfileSet,
    ClosedSecurityDomainV2::CodeIntegrityLock,
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BinaryClosureV2 {
    canonical_bytes: Vec<u8>,
    jarvis: ArtifactIdentityV2,
    agentd: ArtifactIdentityV2,
    ingressd: ArtifactIdentityV2,
    kerneld: ArtifactIdentityV2,
    approvald: ArtifactIdentityV2,
    execd: ArtifactIdentityV2,
    approvalctl: ArtifactIdentityV2,
    worker_sandbox: ArtifactIdentityV2,
    parser_worker_set: ArtifactSetIdentityV2,
    connector_worker_set: ArtifactSetIdentityV2,
    digest: Digest32V2,
}

impl BinaryClosureV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        jarvis: ArtifactIdentityV2,
        agentd: ArtifactIdentityV2,
        ingressd: ArtifactIdentityV2,
        kerneld: ArtifactIdentityV2,
        approvald: ArtifactIdentityV2,
        execd: ArtifactIdentityV2,
        approvalctl: ArtifactIdentityV2,
        worker_sandbox: ArtifactIdentityV2,
        parser_worker_set: ArtifactSetIdentityV2,
        connector_worker_set: ArtifactSetIdentityV2,
    ) -> Result<Self, DeploymentControlErrorV2> {
        let platform = (jarvis.target_os(), jarvis.target_architecture());
        let fixed = [
            (&jarvis, ClosedArtifactTypeV2::ControlShell),
            (&agentd, ClosedArtifactTypeV2::Daemon),
            (&ingressd, ClosedArtifactTypeV2::Daemon),
            (&kerneld, ClosedArtifactTypeV2::Daemon),
            (&approvald, ClosedArtifactTypeV2::Daemon),
            (&execd, ClosedArtifactTypeV2::Daemon),
            (&approvalctl, ClosedArtifactTypeV2::CommandLineTool),
            (&worker_sandbox, ClosedArtifactTypeV2::Worker),
        ];
        if fixed.iter().any(|(artifact, expected_type)| {
            artifact.artifact_type() != *expected_type
                || (artifact.target_os(), artifact.target_architecture()) != platform
        }) || parser_worker_set
            .artifacts()
            .iter()
            .chain(connector_worker_set.artifacts())
            .any(|artifact| (artifact.target_os(), artifact.target_architecture()) != platform)
        {
            return Err(DeploymentControlErrorV2::InvalidSecurityStateManifest);
        }
        let canonical_bytes = encode_nested_array(&[
            jarvis.canonical_bytes(),
            agentd.canonical_bytes(),
            ingressd.canonical_bytes(),
            kerneld.canonical_bytes(),
            approvald.canonical_bytes(),
            execd.canonical_bytes(),
            approvalctl.canonical_bytes(),
            worker_sandbox.canonical_bytes(),
            parser_worker_set.canonical_bytes(),
            connector_worker_set.canonical_bytes(),
        ])?;
        Ok(Self {
            digest: hash_domain(BINARY_CLOSURE_DOMAIN_V2, &canonical_bytes),
            canonical_bytes,
            jarvis,
            agentd,
            ingressd,
            kerneld,
            approvald,
            execd,
            approvalctl,
            worker_sandbox,
            parser_worker_set,
            connector_worker_set,
        })
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, DeploymentControlErrorV2> {
        check_manifest_object_size(bytes)?;
        let mut decoder = minicbor::Decoder::new(bytes);
        expect_array(&mut decoder, BINARY_CLOSURE_FIELDS_V2)?;
        let value = Self::new(
            decode_nested(&mut decoder, ArtifactIdentityV2::from_canonical_bytes)?,
            decode_nested(&mut decoder, ArtifactIdentityV2::from_canonical_bytes)?,
            decode_nested(&mut decoder, ArtifactIdentityV2::from_canonical_bytes)?,
            decode_nested(&mut decoder, ArtifactIdentityV2::from_canonical_bytes)?,
            decode_nested(&mut decoder, ArtifactIdentityV2::from_canonical_bytes)?,
            decode_nested(&mut decoder, ArtifactIdentityV2::from_canonical_bytes)?,
            decode_nested(&mut decoder, ArtifactIdentityV2::from_canonical_bytes)?,
            decode_nested(&mut decoder, ArtifactIdentityV2::from_canonical_bytes)?,
            decode_nested(&mut decoder, ArtifactSetIdentityV2::from_canonical_bytes)?,
            decode_nested(&mut decoder, ArtifactSetIdentityV2::from_canonical_bytes)?,
        )?;
        require_eof(&decoder, bytes)?;
        require_canonical(value.canonical_bytes(), bytes)?;
        Ok(value)
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub const fn digest(&self) -> Digest32V2 {
        self.digest
    }

    pub const fn target_os(&self) -> ClosedTargetOsV2 {
        self.jarvis.target_os()
    }

    pub const fn target_architecture(&self) -> ClosedTargetArchitectureV2 {
        self.jarvis.target_architecture()
    }

    pub fn fixed_artifacts(&self) -> [&ArtifactIdentityV2; 8] {
        [
            &self.jarvis,
            &self.agentd,
            &self.ingressd,
            &self.kerneld,
            &self.approvald,
            &self.execd,
            &self.approvalctl,
            &self.worker_sandbox,
        ]
    }

    pub const fn jarvis(&self) -> &ArtifactIdentityV2 {
        &self.jarvis
    }

    pub const fn agentd(&self) -> &ArtifactIdentityV2 {
        &self.agentd
    }

    pub const fn ingressd(&self) -> &ArtifactIdentityV2 {
        &self.ingressd
    }

    pub const fn kerneld(&self) -> &ArtifactIdentityV2 {
        &self.kerneld
    }

    pub const fn approvald(&self) -> &ArtifactIdentityV2 {
        &self.approvald
    }

    pub const fn execd(&self) -> &ArtifactIdentityV2 {
        &self.execd
    }

    pub const fn approvalctl(&self) -> &ArtifactIdentityV2 {
        &self.approvalctl
    }

    pub const fn worker_sandbox(&self) -> &ArtifactIdentityV2 {
        &self.worker_sandbox
    }

    pub const fn parser_worker_set(&self) -> &ArtifactSetIdentityV2 {
        &self.parser_worker_set
    }

    pub const fn connector_worker_set(&self) -> &ArtifactSetIdentityV2 {
        &self.connector_worker_set
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityStateClosureV2 {
    canonical_bytes: Vec<u8>,
    identities: [VersionedIdentityV2; 18],
    digest: Digest32V2,
}

impl SecurityStateClosureV2 {
    pub fn new(identities: [VersionedIdentityV2; 18]) -> Result<Self, DeploymentControlErrorV2> {
        validate_identity_domains(&identities, &SECURITY_STATE_DOMAINS_V2)?;
        let nested: Vec<&[u8]> = identities
            .iter()
            .map(VersionedIdentityV2::canonical_bytes)
            .collect();
        let canonical_bytes = encode_nested_array(&nested)?;
        Ok(Self {
            digest: hash_domain(SECURITY_STATE_CLOSURE_DOMAIN_V2, &canonical_bytes),
            canonical_bytes,
            identities,
        })
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, DeploymentControlErrorV2> {
        check_manifest_object_size(bytes)?;
        let mut decoder = minicbor::Decoder::new(bytes);
        expect_array(&mut decoder, SECURITY_STATE_CLOSURE_FIELDS_V2)?;
        let mut identities = Vec::with_capacity(18);
        for _ in 0..18 {
            identities.push(decode_nested(
                &mut decoder,
                VersionedIdentityV2::from_canonical_bytes,
            )?);
        }
        require_eof(&decoder, bytes)?;
        let identities: [VersionedIdentityV2; 18] = identities
            .try_into()
            .map_err(|_| DeploymentControlErrorV2::InvalidSecurityStateManifest)?;
        let value = Self::new(identities)?;
        require_canonical(value.canonical_bytes(), bytes)?;
        Ok(value)
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub const fn digest(&self) -> Digest32V2 {
        self.digest
    }

    pub const fn identities(&self) -> &[VersionedIdentityV2; 18] {
        &self.identities
    }

    pub const fn identity(&self, domain: ClosedSecurityDomainV2) -> Option<&VersionedIdentityV2> {
        let tag = domain.tag();
        if tag >= 2 && tag <= 19 {
            Some(&self.identities[(tag - 2) as usize])
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformClosureV2 {
    canonical_bytes: Vec<u8>,
    identities: [VersionedIdentityV2; 6],
    digest: Digest32V2,
}

impl PlatformClosureV2 {
    pub fn new(identities: [VersionedIdentityV2; 6]) -> Result<Self, DeploymentControlErrorV2> {
        validate_identity_domains(&identities, &PLATFORM_DOMAINS_V2)?;
        let nested: Vec<&[u8]> = identities
            .iter()
            .map(VersionedIdentityV2::canonical_bytes)
            .collect();
        let canonical_bytes = encode_nested_array(&nested)?;
        Ok(Self {
            digest: hash_domain(PLATFORM_CLOSURE_DOMAIN_V2, &canonical_bytes),
            canonical_bytes,
            identities,
        })
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, DeploymentControlErrorV2> {
        check_manifest_object_size(bytes)?;
        let mut decoder = minicbor::Decoder::new(bytes);
        expect_array(&mut decoder, PLATFORM_CLOSURE_FIELDS_V2)?;
        let mut identities = Vec::with_capacity(6);
        for _ in 0..6 {
            identities.push(decode_nested(
                &mut decoder,
                VersionedIdentityV2::from_canonical_bytes,
            )?);
        }
        require_eof(&decoder, bytes)?;
        let identities: [VersionedIdentityV2; 6] = identities
            .try_into()
            .map_err(|_| DeploymentControlErrorV2::InvalidSecurityStateManifest)?;
        let value = Self::new(identities)?;
        require_canonical(value.canonical_bytes(), bytes)?;
        Ok(value)
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub const fn digest(&self) -> Digest32V2 {
        self.digest
    }

    pub const fn identities(&self) -> &[VersionedIdentityV2; 6] {
        &self.identities
    }

    pub const fn identity(&self, domain: ClosedSecurityDomainV2) -> Option<&VersionedIdentityV2> {
        let tag = domain.tag();
        if tag >= 20 && tag <= 25 {
            Some(&self.identities[(tag - 20) as usize])
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapTcbLockV2 {
    canonical_bytes: Vec<u8>,
    deploy_helper_identity: ArtifactIdentityV2,
    deploy_watchdog_identity: ArtifactIdentityV2,
    deploy_recovery_identity: ArtifactIdentityV2,
    ledger_verifier_identity: ArtifactIdentityV2,
    ledger_schema_authority_digest: Digest32V2,
    bootstrap_native_profile_set_digest: Digest32V2,
    bootstrap_location_layout_digest: Digest32V2,
    bootstrap_static_file_tree_root: Digest32V2,
    deployment_trust_root_set: VersionedIdentityV2,
    activation_trust_root_set: VersionedIdentityV2,
    release_trust_root_set: VersionedIdentityV2,
    declassification_trust_root_set: VersionedIdentityV2,
    installation_epoch: u64,
    digest: Digest32V2,
}

impl BootstrapTcbLockV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        deploy_helper_identity: ArtifactIdentityV2,
        deploy_watchdog_identity: ArtifactIdentityV2,
        deploy_recovery_identity: ArtifactIdentityV2,
        ledger_verifier_identity: ArtifactIdentityV2,
        ledger_schema_authority_digest: Digest32V2,
        bootstrap_native_profile_set_digest: Digest32V2,
        bootstrap_location_layout_digest: Digest32V2,
        bootstrap_static_file_tree_root: Digest32V2,
        deployment_trust_root_set: VersionedIdentityV2,
        activation_trust_root_set: VersionedIdentityV2,
        release_trust_root_set: VersionedIdentityV2,
        declassification_trust_root_set: VersionedIdentityV2,
        installation_epoch: u64,
    ) -> Result<Self, DeploymentControlErrorV2> {
        let platform = (
            deploy_helper_identity.target_os(),
            deploy_helper_identity.target_architecture(),
        );
        let artifacts = [
            (&deploy_helper_identity, ClosedArtifactTypeV2::RootHelper),
            (&deploy_watchdog_identity, ClosedArtifactTypeV2::Watchdog),
            (
                &deploy_recovery_identity,
                ClosedArtifactTypeV2::RecoveryTool,
            ),
            (
                &ledger_verifier_identity,
                ClosedArtifactTypeV2::LedgerVerifier,
            ),
        ];
        if installation_epoch == 0
            || artifacts.iter().any(|(artifact, expected_type)| {
                artifact.artifact_type() != *expected_type
                    || (artifact.target_os(), artifact.target_architecture()) != platform
            })
            || [
                ledger_schema_authority_digest,
                bootstrap_native_profile_set_digest,
                bootstrap_location_layout_digest,
                bootstrap_static_file_tree_root,
            ]
            .iter()
            .any(|digest| is_zero(digest.as_bytes()))
            || deployment_trust_root_set.domain() != ClosedSecurityDomainV2::DeploymentTrustRootSet
            || activation_trust_root_set.domain() != ClosedSecurityDomainV2::ActivationTrustRootSet
            || release_trust_root_set.domain() != ClosedSecurityDomainV2::ReleaseTrustRootSet
            || declassification_trust_root_set.domain()
                != ClosedSecurityDomainV2::DeclassificationTrustRootSet
        {
            return Err(DeploymentControlErrorV2::InvalidSecurityStateManifest);
        }
        let mut encoder = minicbor::Encoder::new(Vec::new());
        encoder
            .array(BOOTSTRAP_TCB_LOCK_FIELDS_V2)
            .map_err(|_| DeploymentControlErrorV2::InvalidSecurityStateManifest)?;
        for artifact in [
            &deploy_helper_identity,
            &deploy_watchdog_identity,
            &deploy_recovery_identity,
            &ledger_verifier_identity,
        ] {
            encoder
                .writer_mut()
                .extend_from_slice(artifact.canonical_bytes());
        }
        encoder
            .bytes(ledger_schema_authority_digest.as_bytes())
            .and_then(|encoder| encoder.bytes(bootstrap_native_profile_set_digest.as_bytes()))
            .and_then(|encoder| encoder.bytes(bootstrap_location_layout_digest.as_bytes()))
            .and_then(|encoder| encoder.bytes(bootstrap_static_file_tree_root.as_bytes()))
            .map_err(|_| DeploymentControlErrorV2::InvalidSecurityStateManifest)?;
        for identity in [
            &deployment_trust_root_set,
            &activation_trust_root_set,
            &release_trust_root_set,
            &declassification_trust_root_set,
        ] {
            encoder
                .writer_mut()
                .extend_from_slice(identity.canonical_bytes());
        }
        encoder
            .u64(installation_epoch)
            .map_err(|_| DeploymentControlErrorV2::InvalidSecurityStateManifest)?;
        let canonical_bytes = encoder.into_writer();
        Ok(Self {
            digest: hash_domain(BOOTSTRAP_TCB_LOCK_DOMAIN_V2, &canonical_bytes),
            canonical_bytes,
            deploy_helper_identity,
            deploy_watchdog_identity,
            deploy_recovery_identity,
            ledger_verifier_identity,
            ledger_schema_authority_digest,
            bootstrap_native_profile_set_digest,
            bootstrap_location_layout_digest,
            bootstrap_static_file_tree_root,
            deployment_trust_root_set,
            activation_trust_root_set,
            release_trust_root_set,
            declassification_trust_root_set,
            installation_epoch,
        })
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, DeploymentControlErrorV2> {
        check_manifest_object_size(bytes)?;
        let mut decoder = minicbor::Decoder::new(bytes);
        expect_array(&mut decoder, BOOTSTRAP_TCB_LOCK_FIELDS_V2)?;
        let value = Self::new(
            decode_nested(&mut decoder, ArtifactIdentityV2::from_canonical_bytes)?,
            decode_nested(&mut decoder, ArtifactIdentityV2::from_canonical_bytes)?,
            decode_nested(&mut decoder, ArtifactIdentityV2::from_canonical_bytes)?,
            decode_nested(&mut decoder, ArtifactIdentityV2::from_canonical_bytes)?,
            super::deployment_manifest_primitives::decode_digest(&mut decoder)?,
            super::deployment_manifest_primitives::decode_digest(&mut decoder)?,
            super::deployment_manifest_primitives::decode_digest(&mut decoder)?,
            super::deployment_manifest_primitives::decode_digest(&mut decoder)?,
            decode_nested(&mut decoder, VersionedIdentityV2::from_canonical_bytes)?,
            decode_nested(&mut decoder, VersionedIdentityV2::from_canonical_bytes)?,
            decode_nested(&mut decoder, VersionedIdentityV2::from_canonical_bytes)?,
            decode_nested(&mut decoder, VersionedIdentityV2::from_canonical_bytes)?,
            super::deployment_manifest_primitives::decode_u64(&mut decoder)?,
        )?;
        require_eof(&decoder, bytes)?;
        require_canonical(value.canonical_bytes(), bytes)?;
        Ok(value)
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub const fn digest(&self) -> Digest32V2 {
        self.digest
    }

    pub const fn deploy_helper_identity(&self) -> &ArtifactIdentityV2 {
        &self.deploy_helper_identity
    }

    pub const fn deploy_watchdog_identity(&self) -> &ArtifactIdentityV2 {
        &self.deploy_watchdog_identity
    }

    pub const fn deploy_recovery_identity(&self) -> &ArtifactIdentityV2 {
        &self.deploy_recovery_identity
    }

    pub const fn ledger_verifier_identity(&self) -> &ArtifactIdentityV2 {
        &self.ledger_verifier_identity
    }

    pub const fn ledger_schema_authority_digest(&self) -> Digest32V2 {
        self.ledger_schema_authority_digest
    }

    pub const fn bootstrap_native_profile_set_digest(&self) -> Digest32V2 {
        self.bootstrap_native_profile_set_digest
    }

    pub const fn bootstrap_location_layout_digest(&self) -> Digest32V2 {
        self.bootstrap_location_layout_digest
    }

    pub const fn bootstrap_static_file_tree_root(&self) -> Digest32V2 {
        self.bootstrap_static_file_tree_root
    }

    pub const fn deployment_trust_root_set(&self) -> &VersionedIdentityV2 {
        &self.deployment_trust_root_set
    }

    pub const fn activation_trust_root_set(&self) -> &VersionedIdentityV2 {
        &self.activation_trust_root_set
    }

    pub const fn release_trust_root_set(&self) -> &VersionedIdentityV2 {
        &self.release_trust_root_set
    }

    pub const fn declassification_trust_root_set(&self) -> &VersionedIdentityV2 {
        &self.declassification_trust_root_set
    }

    pub const fn installation_epoch(&self) -> u64 {
        self.installation_epoch
    }

    pub const fn target_os(&self) -> ClosedTargetOsV2 {
        self.deploy_helper_identity.target_os()
    }

    pub const fn target_architecture(&self) -> ClosedTargetArchitectureV2 {
        self.deploy_helper_identity.target_architecture()
    }
}

fn validate_identity_domains<const N: usize>(
    identities: &[VersionedIdentityV2; N],
    expected_domains: &[ClosedSecurityDomainV2; N],
) -> Result<(), DeploymentControlErrorV2> {
    if identities
        .iter()
        .zip(expected_domains)
        .any(|(identity, expected)| identity.domain() != *expected)
    {
        return Err(DeploymentControlErrorV2::InvalidSecurityStateManifest);
    }
    Ok(())
}

fn encode_nested_array(values: &[&[u8]]) -> Result<Vec<u8>, DeploymentControlErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(values.len() as u64)
        .map_err(|_| DeploymentControlErrorV2::InvalidSecurityStateManifest)?;
    for value in values {
        encoder.writer_mut().extend_from_slice(value);
    }
    Ok(encoder.into_writer())
}
