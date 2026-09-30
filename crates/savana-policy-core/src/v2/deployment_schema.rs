use savana_kernel_protocol::v2::Digest32V2;
use sha2::{Digest as _, Sha256};

use super::{
    deployment_merkle::{deployment_merkle_root_v2, DeploymentMerkleDomainV2},
    DeploymentControlErrorV2, DeploymentHardLimitsV2,
};

const ARTIFACT_IDENTITY_SCHEMA_VERSION_V2: u16 = 2;
const ARTIFACT_IDENTITY_FIELDS_V2: u64 = 8;
const ARTIFACT_IDENTITY_MAX_BYTES_V2: usize = 512;
const ARTIFACT_IDENTITY_DOMAIN_V2: &[u8] = b"savana.artifact-identity.v2\0";
const PLATFORM_LOCK_FIELDS_V2: u64 = 8;
const PLATFORM_LOCK_DOMAIN_V2: &[u8] = b"savana.platform-lock.v2\0";
const FILE_TREE_ENTRY_FIELDS_V2: u64 = 9;
const NORMAL_FILE_TREE_ENTRY_COUNT_V2: usize = 40;
const STAGING_ENTRY_FIELDS_V2: u64 = 9;
const ROOT_PRINCIPAL_TAG_V2: u16 = 1;
const ROOT_GROUP_TAG_V2: u16 = 1;
const REQUIRED_STAGING_PREFIX_V2: [ClosedStagingPathIdV2; 7] = [
    ClosedStagingPathIdV2::MigrationPlan,
    ClosedStagingPathIdV2::ArtifactInstallPlan,
    ClosedStagingPathIdV2::ServiceTransitionPlan,
    ClosedStagingPathIdV2::IsolatedE2EPlan,
    ClosedStagingPathIdV2::EvidenceContract,
    ClosedStagingPathIdV2::ProtectedAcceptancePlan,
    ClosedStagingPathIdV2::ArtifactPayloadRoot,
];

macro_rules! closed_u16_enum {
    (
        $(#[$meta:meta])*
        $visibility:vis enum $name:ident {
            $($variant:ident = $tag:literal),+ $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[repr(u16)]
        $visibility enum $name {
            $($variant = $tag),+
        }

        impl $name {
            pub const ALL: &'static [Self] = &[$(Self::$variant),+];

            pub const fn from_tag(tag: u16) -> Option<Self> {
                match tag {
                    $($tag => Some(Self::$variant),)+
                    _ => None,
                }
            }

            pub const fn tag(self) -> u16 {
                self as u16
            }
        }
    };
}

closed_u16_enum! {
    /// Complete V2 persistent-store registry. No string or caller-selected ID is accepted.
    pub enum ClosedStoreIdV2 {
        KerneldVault = 1,
        KerneldProvenance = 2,
        KerneldReplay = 3,
        KerneldDispatch = 4,
        KerneldResult = 5,
        KerneldAudit = 6,
        ApprovaldWebAuthnCounter = 7,
        ApprovaldEnrollment = 8,
        ApprovaldRevocation = 9,
        ApprovaldSettlement = 10,
        ApprovaldReplay = 11,
        ExecdNonce = 12,
        ExecdEncryptedResult = 13,
        ExecdAcknowledgement = 14,
        ExecdConnectorJournal = 15,
        AgentdRecovery = 16,
        DeploymentLedger = 17,
        DeploymentEvidence = 18
    }
}

closed_u16_enum! {
    /// Platform-neutral logical installation roles resolved by the native path table.
    pub enum ClosedLogicalPathIdV2 {
        InstallationRootDirectory = 1,
        ExecutableRootDirectory = 2,
        ConfigurationRootDirectory = 3,
        ServiceDefinitionRootDirectory = 4,
        SandboxProfileRootDirectory = 5,
        JarvisExecutable = 6,
        AgentdExecutable = 7,
        IngressdExecutable = 8,
        KerneldExecutable = 9,
        ApprovaldExecutable = 10,
        ExecdExecutable = 11,
        ApprovalctlExecutable = 12,
        WorkerSandboxExecutable = 13,
        ParserWorkerExecutable = 14,
        ConnectorWorkerExecutable = 15,
        AgentdConfig = 16,
        IngressdConfig = 17,
        KerneldConfig = 18,
        ApprovaldConfig = 19,
        ExecdConfig = 20,
        KerneldServiceDefinition = 21,
        KerneldAgentEndpointDefinition = 22,
        KerneldIngressEndpointDefinition = 23,
        AgentdServiceDefinition = 24,
        AgentdControlEndpointDefinition = 25,
        AgentdJarvisHttpEndpointDefinition = 26,
        AgentdAgentHttpEndpointDefinition = 27,
        IngressdServiceDefinition = 28,
        IngressdHttpEndpointDefinition = 29,
        ApprovaldServiceDefinition = 30,
        ApprovaldAgentEndpointDefinition = 31,
        ApprovaldIngressEndpointDefinition = 32,
        ApprovaldAdminEndpointDefinition = 33,
        ApprovaldHttpEndpointDefinition = 34,
        ExecdServiceDefinition = 35,
        ExecdEndpointDefinition = 36,
        KernelTargetDefinition = 37,
        ParserSandboxProfile = 38,
        ConnectorNoNetworkSandboxProfile = 39,
        ConnectorCredentialAbsenceProfile = 40,
        DeployHelperExecutable = 41,
        DeployWatchdogExecutable = 42,
        DeployRecoveryExecutable = 43,
        LedgerVerifierExecutable = 44,
        DeploymentTrustRootSet = 45,
        ActivationTrustRootSet = 46,
        ReleaseTrustRootSet = 47,
        BootstrapActiveSelector = 48,
        BootstrapSlotClosure = 49,
        InstallationIdentityProfile = 50,
        LedgerGenesis = 51
    }
}

impl ClosedLogicalPathIdV2 {
    pub const fn is_bootstrap_owned(self) -> bool {
        matches!(
            self,
            Self::DeployHelperExecutable
                | Self::DeployWatchdogExecutable
                | Self::DeployRecoveryExecutable
                | Self::LedgerVerifierExecutable
                | Self::DeploymentTrustRootSet
                | Self::ActivationTrustRootSet
                | Self::ReleaseTrustRootSet
                | Self::BootstrapActiveSelector
                | Self::BootstrapSlotClosure
                | Self::InstallationIdentityProfile
                | Self::LedgerGenesis
        )
    }

    pub const fn parent(self) -> Option<Self> {
        match self {
            Self::InstallationRootDirectory => None,
            Self::ExecutableRootDirectory
            | Self::ConfigurationRootDirectory
            | Self::ServiceDefinitionRootDirectory
            | Self::SandboxProfileRootDirectory => Some(Self::InstallationRootDirectory),
            Self::JarvisExecutable
            | Self::AgentdExecutable
            | Self::IngressdExecutable
            | Self::KerneldExecutable
            | Self::ApprovaldExecutable
            | Self::ExecdExecutable
            | Self::ApprovalctlExecutable
            | Self::WorkerSandboxExecutable
            | Self::ParserWorkerExecutable
            | Self::ConnectorWorkerExecutable
            | Self::DeployHelperExecutable
            | Self::DeployWatchdogExecutable
            | Self::DeployRecoveryExecutable
            | Self::LedgerVerifierExecutable => Some(Self::ExecutableRootDirectory),
            Self::AgentdConfig
            | Self::IngressdConfig
            | Self::KerneldConfig
            | Self::ApprovaldConfig
            | Self::ExecdConfig
            | Self::DeploymentTrustRootSet
            | Self::ActivationTrustRootSet
            | Self::ReleaseTrustRootSet
            | Self::BootstrapActiveSelector
            | Self::BootstrapSlotClosure
            | Self::InstallationIdentityProfile
            | Self::LedgerGenesis => Some(Self::ConfigurationRootDirectory),
            Self::KerneldServiceDefinition
            | Self::KerneldAgentEndpointDefinition
            | Self::KerneldIngressEndpointDefinition
            | Self::AgentdServiceDefinition
            | Self::AgentdControlEndpointDefinition
            | Self::AgentdJarvisHttpEndpointDefinition
            | Self::AgentdAgentHttpEndpointDefinition
            | Self::IngressdServiceDefinition
            | Self::IngressdHttpEndpointDefinition
            | Self::ApprovaldServiceDefinition
            | Self::ApprovaldAgentEndpointDefinition
            | Self::ApprovaldIngressEndpointDefinition
            | Self::ApprovaldAdminEndpointDefinition
            | Self::ApprovaldHttpEndpointDefinition
            | Self::ExecdServiceDefinition
            | Self::ExecdEndpointDefinition
            | Self::KernelTargetDefinition => Some(Self::ServiceDefinitionRootDirectory),
            Self::ParserSandboxProfile
            | Self::ConnectorNoNetworkSandboxProfile
            | Self::ConnectorCredentialAbsenceProfile => Some(Self::SandboxProfileRootDirectory),
        }
    }

    pub const fn is_directory(self) -> bool {
        matches!(
            self,
            Self::InstallationRootDirectory
                | Self::ExecutableRootDirectory
                | Self::ConfigurationRootDirectory
                | Self::ServiceDefinitionRootDirectory
                | Self::SandboxProfileRootDirectory
        )
    }

    pub const fn required_mode(self) -> u32 {
        if self.is_directory() {
            0o755
        } else if matches!(
            self,
            Self::JarvisExecutable
                | Self::AgentdExecutable
                | Self::IngressdExecutable
                | Self::KerneldExecutable
                | Self::ApprovaldExecutable
                | Self::ExecdExecutable
                | Self::ApprovalctlExecutable
                | Self::WorkerSandboxExecutable
                | Self::ParserWorkerExecutable
                | Self::ConnectorWorkerExecutable
                | Self::DeployHelperExecutable
                | Self::DeployWatchdogExecutable
                | Self::DeployRecoveryExecutable
                | Self::LedgerVerifierExecutable
        ) {
            0o555
        } else {
            0o444
        }
    }

    pub const fn expected_artifact_type(self) -> Option<ClosedArtifactTypeV2> {
        match self {
            Self::InstallationRootDirectory
            | Self::ExecutableRootDirectory
            | Self::ConfigurationRootDirectory
            | Self::ServiceDefinitionRootDirectory
            | Self::SandboxProfileRootDirectory => None,
            Self::JarvisExecutable => Some(ClosedArtifactTypeV2::ControlShell),
            Self::AgentdExecutable
            | Self::IngressdExecutable
            | Self::KerneldExecutable
            | Self::ApprovaldExecutable
            | Self::ExecdExecutable => Some(ClosedArtifactTypeV2::Daemon),
            Self::ApprovalctlExecutable => Some(ClosedArtifactTypeV2::CommandLineTool),
            Self::WorkerSandboxExecutable
            | Self::ParserWorkerExecutable
            | Self::ConnectorWorkerExecutable => Some(ClosedArtifactTypeV2::Worker),
            Self::AgentdConfig
            | Self::IngressdConfig
            | Self::KerneldConfig
            | Self::ApprovaldConfig
            | Self::ExecdConfig
            | Self::DeploymentTrustRootSet
            | Self::ActivationTrustRootSet
            | Self::ReleaseTrustRootSet
            | Self::BootstrapActiveSelector
            | Self::BootstrapSlotClosure
            | Self::InstallationIdentityProfile
            | Self::LedgerGenesis => Some(ClosedArtifactTypeV2::Configuration),
            Self::KerneldServiceDefinition
            | Self::AgentdServiceDefinition
            | Self::IngressdServiceDefinition
            | Self::ApprovaldServiceDefinition
            | Self::ExecdServiceDefinition
            | Self::KernelTargetDefinition => Some(ClosedArtifactTypeV2::ServiceDefinition),
            Self::KerneldAgentEndpointDefinition
            | Self::KerneldIngressEndpointDefinition
            | Self::AgentdControlEndpointDefinition
            | Self::AgentdJarvisHttpEndpointDefinition
            | Self::AgentdAgentHttpEndpointDefinition
            | Self::IngressdHttpEndpointDefinition
            | Self::ApprovaldAgentEndpointDefinition
            | Self::ApprovaldIngressEndpointDefinition
            | Self::ApprovaldAdminEndpointDefinition
            | Self::ApprovaldHttpEndpointDefinition
            | Self::ExecdEndpointDefinition => Some(ClosedArtifactTypeV2::EndpointDefinition),
            Self::ParserSandboxProfile
            | Self::ConnectorNoNetworkSandboxProfile
            | Self::ConnectorCredentialAbsenceProfile => Some(ClosedArtifactTypeV2::SandboxProfile),
            Self::DeployHelperExecutable => Some(ClosedArtifactTypeV2::RootHelper),
            Self::DeployWatchdogExecutable => Some(ClosedArtifactTypeV2::Watchdog),
            Self::DeployRecoveryExecutable => Some(ClosedArtifactTypeV2::RecoveryTool),
            Self::LedgerVerifierExecutable => Some(ClosedArtifactTypeV2::LedgerVerifier),
        }
    }
}

closed_u16_enum! {
    /// Exact staging roles. Bootstrap-owned installation paths intentionally have no variant.
    pub enum ClosedStagingPathIdV2 {
        MigrationPlan = 1,
        ArtifactInstallPlan = 2,
        ServiceTransitionPlan = 3,
        IsolatedE2EPlan = 4,
        EvidenceContract = 5,
        ProtectedAcceptancePlan = 6,
        ArtifactPayloadRoot = 7,
        JarvisExecutable = 10,
        AgentdExecutable = 11,
        IngressdExecutable = 12,
        KerneldExecutable = 13,
        ApprovaldExecutable = 14,
        ExecdExecutable = 15,
        ApprovalctlExecutable = 16,
        WorkerSandboxExecutable = 17,
        ParserWorkerExecutable = 18,
        ConnectorWorkerExecutable = 19,
        AgentdConfig = 20,
        IngressdConfig = 21,
        KerneldConfig = 22,
        ApprovaldConfig = 23,
        ExecdConfig = 24,
        KerneldServiceDefinition = 25,
        KerneldAgentEndpointDefinition = 26,
        KerneldIngressEndpointDefinition = 27,
        AgentdServiceDefinition = 28,
        AgentdControlEndpointDefinition = 29,
        AgentdJarvisHttpEndpointDefinition = 30,
        AgentdAgentHttpEndpointDefinition = 31,
        IngressdServiceDefinition = 32,
        IngressdHttpEndpointDefinition = 33,
        ApprovaldServiceDefinition = 34,
        ApprovaldAgentEndpointDefinition = 35,
        ApprovaldIngressEndpointDefinition = 36,
        ApprovaldAdminEndpointDefinition = 37,
        ApprovaldHttpEndpointDefinition = 38,
        ExecdServiceDefinition = 39,
        ExecdEndpointDefinition = 40,
        KernelTargetDefinition = 41,
        ParserSandboxProfile = 42,
        ConnectorNoNetworkSandboxProfile = 43,
        ConnectorCredentialAbsenceProfile = 44
    }
}

impl ClosedStagingPathIdV2 {
    pub const fn target_logical_path(self) -> Option<ClosedLogicalPathIdV2> {
        use ClosedLogicalPathIdV2 as Logical;
        match self {
            Self::MigrationPlan
            | Self::ArtifactInstallPlan
            | Self::ServiceTransitionPlan
            | Self::IsolatedE2EPlan
            | Self::EvidenceContract
            | Self::ProtectedAcceptancePlan
            | Self::ArtifactPayloadRoot => None,
            Self::JarvisExecutable => Some(Logical::JarvisExecutable),
            Self::AgentdExecutable => Some(Logical::AgentdExecutable),
            Self::IngressdExecutable => Some(Logical::IngressdExecutable),
            Self::KerneldExecutable => Some(Logical::KerneldExecutable),
            Self::ApprovaldExecutable => Some(Logical::ApprovaldExecutable),
            Self::ExecdExecutable => Some(Logical::ExecdExecutable),
            Self::ApprovalctlExecutable => Some(Logical::ApprovalctlExecutable),
            Self::WorkerSandboxExecutable => Some(Logical::WorkerSandboxExecutable),
            Self::ParserWorkerExecutable => Some(Logical::ParserWorkerExecutable),
            Self::ConnectorWorkerExecutable => Some(Logical::ConnectorWorkerExecutable),
            Self::AgentdConfig => Some(Logical::AgentdConfig),
            Self::IngressdConfig => Some(Logical::IngressdConfig),
            Self::KerneldConfig => Some(Logical::KerneldConfig),
            Self::ApprovaldConfig => Some(Logical::ApprovaldConfig),
            Self::ExecdConfig => Some(Logical::ExecdConfig),
            Self::KerneldServiceDefinition => Some(Logical::KerneldServiceDefinition),
            Self::KerneldAgentEndpointDefinition => Some(Logical::KerneldAgentEndpointDefinition),
            Self::KerneldIngressEndpointDefinition => {
                Some(Logical::KerneldIngressEndpointDefinition)
            }
            Self::AgentdServiceDefinition => Some(Logical::AgentdServiceDefinition),
            Self::AgentdControlEndpointDefinition => Some(Logical::AgentdControlEndpointDefinition),
            Self::AgentdJarvisHttpEndpointDefinition => {
                Some(Logical::AgentdJarvisHttpEndpointDefinition)
            }
            Self::AgentdAgentHttpEndpointDefinition => {
                Some(Logical::AgentdAgentHttpEndpointDefinition)
            }
            Self::IngressdServiceDefinition => Some(Logical::IngressdServiceDefinition),
            Self::IngressdHttpEndpointDefinition => Some(Logical::IngressdHttpEndpointDefinition),
            Self::ApprovaldServiceDefinition => Some(Logical::ApprovaldServiceDefinition),
            Self::ApprovaldAgentEndpointDefinition => {
                Some(Logical::ApprovaldAgentEndpointDefinition)
            }
            Self::ApprovaldIngressEndpointDefinition => {
                Some(Logical::ApprovaldIngressEndpointDefinition)
            }
            Self::ApprovaldAdminEndpointDefinition => {
                Some(Logical::ApprovaldAdminEndpointDefinition)
            }
            Self::ApprovaldHttpEndpointDefinition => Some(Logical::ApprovaldHttpEndpointDefinition),
            Self::ExecdServiceDefinition => Some(Logical::ExecdServiceDefinition),
            Self::ExecdEndpointDefinition => Some(Logical::ExecdEndpointDefinition),
            Self::KernelTargetDefinition => Some(Logical::KernelTargetDefinition),
            Self::ParserSandboxProfile => Some(Logical::ParserSandboxProfile),
            Self::ConnectorNoNetworkSandboxProfile => {
                Some(Logical::ConnectorNoNetworkSandboxProfile)
            }
            Self::ConnectorCredentialAbsenceProfile => {
                Some(Logical::ConnectorCredentialAbsenceProfile)
            }
        }
    }
}

closed_u16_enum! {
    pub enum ClosedArtifactTypeV2 {
        ControlShell = 1,
        Daemon = 2,
        CommandLineTool = 3,
        Worker = 4,
        Configuration = 5,
        ServiceDefinition = 6,
        EndpointDefinition = 7,
        SandboxProfile = 8,
        EntitlementProfile = 9,
        StaticAsset = 10,
        ModelArtifact = 11,
        RootHelper = 12,
        Watchdog = 13,
        RecoveryTool = 14,
        LedgerVerifier = 15
    }
}

closed_u16_enum! {
    pub enum ClosedTargetOsV2 {
        Linux = 1,
        MacOs = 2
    }
}

closed_u16_enum! {
    pub enum ClosedTargetArchitectureV2 {
        X86_64 = 1,
        Aarch64 = 2
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformLockV2 {
    canonical_bytes: Vec<u8>,
    target_os: ClosedTargetOsV2,
    target_architecture: ClosedTargetArchitectureV2,
    os_release_identity_digest: Digest32V2,
    kernel_abi_digest: Digest32V2,
    service_manager_identity_digest: Digest32V2,
    filesystem_capabilities_digest: Digest32V2,
    native_sandbox_capabilities_digest: Digest32V2,
    digest: Digest32V2,
}

impl PlatformLockV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        target_os: ClosedTargetOsV2,
        target_architecture: ClosedTargetArchitectureV2,
        os_release_identity_digest: Digest32V2,
        kernel_abi_digest: Digest32V2,
        service_manager_identity_digest: Digest32V2,
        filesystem_capabilities_digest: Digest32V2,
        native_sandbox_capabilities_digest: Digest32V2,
    ) -> Result<Self, DeploymentControlErrorV2> {
        let canonical_bytes = encode_platform_lock(
            target_os,
            target_architecture,
            os_release_identity_digest,
            kernel_abi_digest,
            service_manager_identity_digest,
            filesystem_capabilities_digest,
            native_sandbox_capabilities_digest,
        )?;
        Self::from_canonical_bytes(&canonical_bytes)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, DeploymentControlErrorV2> {
        if bytes.is_empty() || bytes.len() > 512 {
            return Err(DeploymentControlErrorV2::InvalidDeploymentPlan);
        }
        let mut decoder = minicbor::Decoder::new(bytes);
        expect_array(
            &mut decoder,
            PLATFORM_LOCK_FIELDS_V2,
            DeploymentControlErrorV2::InvalidDeploymentPlan,
        )?;
        if decode_u16(
            &mut decoder,
            DeploymentControlErrorV2::InvalidDeploymentPlan,
        )? != 2
        {
            return Err(DeploymentControlErrorV2::InvalidDeploymentPlan);
        }
        let target_os = ClosedTargetOsV2::from_tag(decode_u16(
            &mut decoder,
            DeploymentControlErrorV2::InvalidDeploymentPlan,
        )?)
        .ok_or(DeploymentControlErrorV2::InvalidDeploymentPlan)?;
        let target_architecture = ClosedTargetArchitectureV2::from_tag(decode_u16(
            &mut decoder,
            DeploymentControlErrorV2::InvalidDeploymentPlan,
        )?)
        .ok_or(DeploymentControlErrorV2::InvalidDeploymentPlan)?;
        let os_release_identity_digest = decode_digest(
            &mut decoder,
            DeploymentControlErrorV2::InvalidDeploymentPlan,
        )?;
        let kernel_abi_digest = decode_digest(
            &mut decoder,
            DeploymentControlErrorV2::InvalidDeploymentPlan,
        )?;
        let service_manager_identity_digest = decode_digest(
            &mut decoder,
            DeploymentControlErrorV2::InvalidDeploymentPlan,
        )?;
        let filesystem_capabilities_digest = decode_digest(
            &mut decoder,
            DeploymentControlErrorV2::InvalidDeploymentPlan,
        )?;
        let native_sandbox_capabilities_digest = decode_digest(
            &mut decoder,
            DeploymentControlErrorV2::InvalidDeploymentPlan,
        )?;
        if decoder.position() != bytes.len()
            || [
                os_release_identity_digest,
                kernel_abi_digest,
                service_manager_identity_digest,
                filesystem_capabilities_digest,
                native_sandbox_capabilities_digest,
            ]
            .iter()
            .any(|digest| is_zero(digest.as_bytes()))
        {
            return Err(DeploymentControlErrorV2::InvalidDeploymentPlan);
        }
        let canonical_bytes = encode_platform_lock(
            target_os,
            target_architecture,
            os_release_identity_digest,
            kernel_abi_digest,
            service_manager_identity_digest,
            filesystem_capabilities_digest,
            native_sandbox_capabilities_digest,
        )?;
        if canonical_bytes != bytes {
            return Err(DeploymentControlErrorV2::InvalidDeploymentPlan);
        }
        let digest = hash_domain(PLATFORM_LOCK_DOMAIN_V2, bytes);
        Ok(Self {
            canonical_bytes,
            target_os,
            target_architecture,
            os_release_identity_digest,
            kernel_abi_digest,
            service_manager_identity_digest,
            filesystem_capabilities_digest,
            native_sandbox_capabilities_digest,
            digest,
        })
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub const fn target_os(&self) -> ClosedTargetOsV2 {
        self.target_os
    }

    pub const fn target_architecture(&self) -> ClosedTargetArchitectureV2 {
        self.target_architecture
    }

    pub const fn os_release_identity_digest(&self) -> Digest32V2 {
        self.os_release_identity_digest
    }

    pub const fn kernel_abi_digest(&self) -> Digest32V2 {
        self.kernel_abi_digest
    }

    pub const fn service_manager_identity_digest(&self) -> Digest32V2 {
        self.service_manager_identity_digest
    }

    pub const fn filesystem_capabilities_digest(&self) -> Digest32V2 {
        self.filesystem_capabilities_digest
    }

    pub const fn native_sandbox_capabilities_digest(&self) -> Digest32V2 {
        self.native_sandbox_capabilities_digest
    }

    pub const fn digest(&self) -> Digest32V2 {
        self.digest
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactIdentityV2 {
    canonical_bytes: Vec<u8>,
    artifact_type: ClosedArtifactTypeV2,
    target_os: ClosedTargetOsV2,
    target_architecture: ClosedTargetArchitectureV2,
    byte_length: u64,
    sha256: Digest32V2,
    platform_code_identity_digest: Digest32V2,
    execution_profile_digest: Digest32V2,
    identity_digest: Digest32V2,
}

impl ArtifactIdentityV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        artifact_type: ClosedArtifactTypeV2,
        target_os: ClosedTargetOsV2,
        target_architecture: ClosedTargetArchitectureV2,
        byte_length: u64,
        sha256: Digest32V2,
        platform_code_identity_digest: Digest32V2,
        execution_profile_digest: Digest32V2,
    ) -> Result<Self, DeploymentControlErrorV2> {
        let canonical_bytes = encode_artifact_identity(
            artifact_type,
            target_os,
            target_architecture,
            byte_length,
            sha256,
            platform_code_identity_digest,
            execution_profile_digest,
        )?;
        Self::from_canonical_bytes(&canonical_bytes)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, DeploymentControlErrorV2> {
        if bytes.is_empty() || bytes.len() > ARTIFACT_IDENTITY_MAX_BYTES_V2 {
            return Err(DeploymentControlErrorV2::InvalidArtifactIdentity);
        }
        let mut decoder = minicbor::Decoder::new(bytes);
        expect_array(
            &mut decoder,
            ARTIFACT_IDENTITY_FIELDS_V2,
            DeploymentControlErrorV2::InvalidArtifactIdentity,
        )?;
        let schema_version = decode_u16(
            &mut decoder,
            DeploymentControlErrorV2::InvalidArtifactIdentity,
        )?;
        let artifact_type = ClosedArtifactTypeV2::from_tag(decode_u16(
            &mut decoder,
            DeploymentControlErrorV2::InvalidArtifactIdentity,
        )?)
        .ok_or(DeploymentControlErrorV2::InvalidArtifactIdentity)?;
        let target_os = ClosedTargetOsV2::from_tag(decode_u16(
            &mut decoder,
            DeploymentControlErrorV2::InvalidArtifactIdentity,
        )?)
        .ok_or(DeploymentControlErrorV2::InvalidArtifactIdentity)?;
        let target_architecture = ClosedTargetArchitectureV2::from_tag(decode_u16(
            &mut decoder,
            DeploymentControlErrorV2::InvalidArtifactIdentity,
        )?)
        .ok_or(DeploymentControlErrorV2::InvalidArtifactIdentity)?;
        let byte_length = decoder
            .u64()
            .map_err(|_| DeploymentControlErrorV2::InvalidArtifactIdentity)?;
        let sha256 = decode_digest(
            &mut decoder,
            DeploymentControlErrorV2::InvalidArtifactIdentity,
        )?;
        let platform_code_identity_digest = decode_digest(
            &mut decoder,
            DeploymentControlErrorV2::InvalidArtifactIdentity,
        )?;
        let execution_profile_digest = decode_digest(
            &mut decoder,
            DeploymentControlErrorV2::InvalidArtifactIdentity,
        )?;
        if decoder.position() != bytes.len()
            || schema_version != ARTIFACT_IDENTITY_SCHEMA_VERSION_V2
            || byte_length == 0
            || byte_length > DeploymentHardLimitsV2::compiled().max_single_artifact_bytes()
            || [
                sha256,
                platform_code_identity_digest,
                execution_profile_digest,
            ]
            .iter()
            .any(|digest| is_zero(digest.as_bytes()))
        {
            return Err(DeploymentControlErrorV2::InvalidArtifactIdentity);
        }
        let canonical_bytes = encode_artifact_identity(
            artifact_type,
            target_os,
            target_architecture,
            byte_length,
            sha256,
            platform_code_identity_digest,
            execution_profile_digest,
        )?;
        if canonical_bytes != bytes {
            return Err(DeploymentControlErrorV2::InvalidArtifactIdentity);
        }
        let identity_digest = hash_domain(ARTIFACT_IDENTITY_DOMAIN_V2, bytes);
        Ok(Self {
            canonical_bytes,
            artifact_type,
            target_os,
            target_architecture,
            byte_length,
            sha256,
            platform_code_identity_digest,
            execution_profile_digest,
            identity_digest,
        })
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub const fn artifact_type(&self) -> ClosedArtifactTypeV2 {
        self.artifact_type
    }

    pub const fn target_os(&self) -> ClosedTargetOsV2 {
        self.target_os
    }

    pub const fn target_architecture(&self) -> ClosedTargetArchitectureV2 {
        self.target_architecture
    }

    pub const fn byte_length(&self) -> u64 {
        self.byte_length
    }

    pub const fn sha256(&self) -> Digest32V2 {
        self.sha256
    }

    pub const fn platform_code_identity_digest(&self) -> Digest32V2 {
        self.platform_code_identity_digest
    }

    pub const fn execution_profile_digest(&self) -> Digest32V2 {
        self.execution_profile_digest
    }

    pub const fn identity_digest(&self) -> Digest32V2 {
        self.identity_digest
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
enum FileTreeEntryKindV2 {
    Directory = 1,
    RegularFile = 2,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileTreeEntryV2 {
    logical_path_id: ClosedLogicalPathIdV2,
    parent_logical_path_id: Option<ClosedLogicalPathIdV2>,
    entry_kind: FileTreeEntryKindV2,
    mode: u32,
    acl_digest: Digest32V2,
    xattr_digest: Digest32V2,
    artifact_identity: Option<ArtifactIdentityV2>,
}

impl FileTreeEntryV2 {
    pub fn new_directory(
        logical_path_id: ClosedLogicalPathIdV2,
        acl_digest: Digest32V2,
        xattr_digest: Digest32V2,
    ) -> Result<Self, DeploymentControlErrorV2> {
        let value = Self {
            logical_path_id,
            parent_logical_path_id: logical_path_id.parent(),
            entry_kind: FileTreeEntryKindV2::Directory,
            mode: logical_path_id.required_mode(),
            acl_digest,
            xattr_digest,
            artifact_identity: None,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn new_regular_file(
        logical_path_id: ClosedLogicalPathIdV2,
        acl_digest: Digest32V2,
        xattr_digest: Digest32V2,
        artifact_identity: ArtifactIdentityV2,
    ) -> Result<Self, DeploymentControlErrorV2> {
        let value = Self {
            logical_path_id,
            parent_logical_path_id: logical_path_id.parent(),
            entry_kind: FileTreeEntryKindV2::RegularFile,
            mode: logical_path_id.required_mode(),
            acl_digest,
            xattr_digest,
            artifact_identity: Some(artifact_identity),
        };
        value.validate()?;
        Ok(value)
    }

    pub const fn logical_path_id(&self) -> ClosedLogicalPathIdV2 {
        self.logical_path_id
    }

    pub const fn parent_logical_path_id(&self) -> Option<ClosedLogicalPathIdV2> {
        self.parent_logical_path_id
    }

    pub const fn mode(&self) -> u32 {
        self.mode
    }

    pub fn artifact_identity(&self) -> Option<&ArtifactIdentityV2> {
        self.artifact_identity.as_ref()
    }

    fn validate(&self) -> Result<(), DeploymentControlErrorV2> {
        if self.logical_path_id.is_bootstrap_owned()
            || self.parent_logical_path_id != self.logical_path_id.parent()
            || self.mode != self.logical_path_id.required_mode()
            || is_zero(self.acl_digest.as_bytes())
            || is_zero(self.xattr_digest.as_bytes())
        {
            return Err(DeploymentControlErrorV2::InvalidDeploymentTree);
        }
        match (self.entry_kind, self.artifact_identity.as_ref()) {
            (FileTreeEntryKindV2::Directory, None) if self.logical_path_id.is_directory() => Ok(()),
            (FileTreeEntryKindV2::RegularFile, Some(identity))
                if !self.logical_path_id.is_directory()
                    && self.logical_path_id.expected_artifact_type()
                        == Some(identity.artifact_type()) =>
            {
                Ok(())
            }
            _ => Err(DeploymentControlErrorV2::InvalidDeploymentTree),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileTreeV2 {
    canonical_bytes: Vec<u8>,
    entries: Vec<FileTreeEntryV2>,
    merkle_root: Digest32V2,
}

impl FileTreeV2 {
    pub fn new(entries: Vec<FileTreeEntryV2>) -> Result<Self, DeploymentControlErrorV2> {
        validate_file_tree_entries(&entries)?;
        let canonical_bytes = encode_file_tree(&entries)?;
        build_file_tree(canonical_bytes, entries)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, DeploymentControlErrorV2> {
        let maximum = usize::try_from(DeploymentHardLimitsV2::compiled().max_manifest_bytes())
            .map_err(|_| DeploymentControlErrorV2::DeploymentTreeLimitExceeded)?;
        if bytes.is_empty() || bytes.len() > maximum {
            return Err(DeploymentControlErrorV2::DeploymentTreeLimitExceeded);
        }
        let mut decoder = minicbor::Decoder::new(bytes);
        let count = decoder
            .array()
            .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentTree)?
            .ok_or(DeploymentControlErrorV2::InvalidDeploymentTree)?;
        let count = usize::try_from(count)
            .map_err(|_| DeploymentControlErrorV2::DeploymentTreeLimitExceeded)?;
        if count != NORMAL_FILE_TREE_ENTRY_COUNT_V2 {
            return Err(DeploymentControlErrorV2::InvalidDeploymentTree);
        }
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(count)
            .map_err(|_| DeploymentControlErrorV2::DeploymentTreeLimitExceeded)?;
        for _ in 0..count {
            entries.push(decode_file_tree_entry(&mut decoder)?);
        }
        if decoder.position() != bytes.len() {
            return Err(DeploymentControlErrorV2::InvalidDeploymentTree);
        }
        validate_file_tree_entries(&entries)?;
        let canonical = encode_file_tree(&entries)?;
        if canonical != bytes {
            return Err(DeploymentControlErrorV2::InvalidDeploymentTree);
        }
        build_file_tree(canonical, entries)
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub fn entries(&self) -> &[FileTreeEntryV2] {
        &self.entries
    }

    pub const fn merkle_root(&self) -> Digest32V2 {
        self.merkle_root
    }
}

fn validate_file_tree_entries(entries: &[FileTreeEntryV2]) -> Result<(), DeploymentControlErrorV2> {
    if entries.len() != NORMAL_FILE_TREE_ENTRY_COUNT_V2 {
        return Err(DeploymentControlErrorV2::InvalidDeploymentTree);
    }
    for (entry, expected) in entries.iter().zip(
        ClosedLogicalPathIdV2::ALL
            .iter()
            .take(NORMAL_FILE_TREE_ENTRY_COUNT_V2),
    ) {
        entry.validate()?;
        if entry.logical_path_id != *expected {
            return Err(DeploymentControlErrorV2::InvalidDeploymentTree);
        }
        if let Some(parent) = entry.parent_logical_path_id {
            let parent_index = usize::from(parent.tag() - 1);
            if parent_index >= entries.len()
                || !entries[parent_index].logical_path_id.is_directory()
            {
                return Err(DeploymentControlErrorV2::InvalidDeploymentTree);
            }
        }
    }
    Ok(())
}

fn build_file_tree(
    canonical_bytes: Vec<u8>,
    entries: Vec<FileTreeEntryV2>,
) -> Result<FileTreeV2, DeploymentControlErrorV2> {
    let encoded_entries = entries
        .iter()
        .map(encode_file_tree_entry)
        .collect::<Result<Vec<_>, _>>()?;
    let references = encoded_entries
        .iter()
        .map(Vec::as_slice)
        .collect::<Vec<_>>();
    let merkle_root = deployment_merkle_root_v2(DeploymentMerkleDomainV2::FileTree, &references)?;
    Ok(FileTreeV2 {
        canonical_bytes,
        entries,
        merkle_root,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
enum StagingEntryKindV2 {
    Directory = 1,
    RegularFile = 2,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagingEntryV2 {
    logical_path_id: ClosedStagingPathIdV2,
    entry_kind: StagingEntryKindV2,
    size: u64,
    sha256: Digest32V2,
    mode: u32,
    acl_digest: Digest32V2,
    xattr_digest: Digest32V2,
}

impl StagingEntryV2 {
    pub fn new_regular(
        logical_path_id: ClosedStagingPathIdV2,
        size: u64,
        sha256: Digest32V2,
        mode: u32,
        acl_digest: Digest32V2,
        xattr_digest: Digest32V2,
    ) -> Result<Self, DeploymentControlErrorV2> {
        let value = Self {
            logical_path_id,
            entry_kind: StagingEntryKindV2::RegularFile,
            size,
            sha256,
            mode,
            acl_digest,
            xattr_digest,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn new_directory(
        logical_path_id: ClosedStagingPathIdV2,
        mode: u32,
        acl_digest: Digest32V2,
        xattr_digest: Digest32V2,
    ) -> Result<Self, DeploymentControlErrorV2> {
        let value = Self {
            logical_path_id,
            entry_kind: StagingEntryKindV2::Directory,
            size: 0,
            sha256: Digest32V2::new([0; 32]),
            mode,
            acl_digest,
            xattr_digest,
        };
        value.validate()?;
        Ok(value)
    }

    pub const fn logical_path_id(&self) -> ClosedStagingPathIdV2 {
        self.logical_path_id
    }

    pub const fn size(&self) -> u64 {
        self.size
    }

    pub const fn sha256(&self) -> Digest32V2 {
        self.sha256
    }

    fn validate(&self) -> Result<(), DeploymentControlErrorV2> {
        if is_zero(self.acl_digest.as_bytes()) || is_zero(self.xattr_digest.as_bytes()) {
            return Err(DeploymentControlErrorV2::InvalidDeploymentTree);
        }
        match self.entry_kind {
            StagingEntryKindV2::Directory => {
                if self.logical_path_id != ClosedStagingPathIdV2::ArtifactPayloadRoot
                    || self.size != 0
                    || !is_zero(self.sha256.as_bytes())
                    || self.mode != 0o700
                {
                    return Err(DeploymentControlErrorV2::InvalidDeploymentTree);
                }
            }
            StagingEntryKindV2::RegularFile => {
                if self.logical_path_id == ClosedStagingPathIdV2::ArtifactPayloadRoot
                    || self.size == 0
                    || self.size > DeploymentHardLimitsV2::compiled().max_single_artifact_bytes()
                    || is_zero(self.sha256.as_bytes())
                    || self.mode != 0o600
                {
                    return Err(DeploymentControlErrorV2::InvalidDeploymentTree);
                }
                if self.logical_path_id.tag() <= 6
                    && self.size > DeploymentHardLimitsV2::compiled().max_plan_bytes()
                {
                    return Err(DeploymentControlErrorV2::DeploymentPlanLimitExceeded);
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagingTreeV2 {
    canonical_bytes: Vec<u8>,
    entries: Vec<StagingEntryV2>,
    merkle_root: Digest32V2,
    total_bytes: u64,
}

impl StagingTreeV2 {
    pub fn new(entries: Vec<StagingEntryV2>) -> Result<Self, DeploymentControlErrorV2> {
        validate_staging_entries(&entries)?;
        let canonical_bytes = encode_staging_tree(&entries)?;
        build_staging_tree(canonical_bytes, entries)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, DeploymentControlErrorV2> {
        let maximum = usize::try_from(DeploymentHardLimitsV2::compiled().max_attestation_bytes())
            .map_err(|_| DeploymentControlErrorV2::DeploymentTreeLimitExceeded)?;
        if bytes.is_empty() || bytes.len() > maximum {
            return Err(DeploymentControlErrorV2::DeploymentTreeLimitExceeded);
        }
        let mut decoder = minicbor::Decoder::new(bytes);
        let count = decoder
            .array()
            .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentTree)?
            .ok_or(DeploymentControlErrorV2::InvalidDeploymentTree)?;
        if count > DeploymentHardLimitsV2::compiled().max_file_tree_entries() {
            return Err(DeploymentControlErrorV2::DeploymentTreeLimitExceeded);
        }
        let count = usize::try_from(count)
            .map_err(|_| DeploymentControlErrorV2::DeploymentTreeLimitExceeded)?;
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(count)
            .map_err(|_| DeploymentControlErrorV2::DeploymentTreeLimitExceeded)?;
        for _ in 0..count {
            entries.push(decode_staging_entry(&mut decoder)?);
        }
        if decoder.position() != bytes.len() {
            return Err(DeploymentControlErrorV2::InvalidDeploymentTree);
        }
        validate_staging_entries(&entries)?;
        let canonical = encode_staging_tree(&entries)?;
        if canonical != bytes {
            return Err(DeploymentControlErrorV2::InvalidDeploymentTree);
        }
        build_staging_tree(canonical, entries)
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub fn entries(&self) -> &[StagingEntryV2] {
        &self.entries
    }

    pub const fn merkle_root(&self) -> Digest32V2 {
        self.merkle_root
    }

    pub const fn total_bytes(&self) -> u64 {
        self.total_bytes
    }
}

fn build_staging_tree(
    canonical_bytes: Vec<u8>,
    entries: Vec<StagingEntryV2>,
) -> Result<StagingTreeV2, DeploymentControlErrorV2> {
    let encoded_entries = entries
        .iter()
        .map(encode_staging_entry)
        .collect::<Result<Vec<_>, _>>()?;
    let references = encoded_entries
        .iter()
        .map(Vec::as_slice)
        .collect::<Vec<_>>();
    let merkle_root =
        deployment_merkle_root_v2(DeploymentMerkleDomainV2::StagingTree, &references)?;
    let total_bytes = entries.iter().try_fold(0_u64, |sum, entry| {
        sum.checked_add(entry.size)
            .ok_or(DeploymentControlErrorV2::DeploymentTreeLimitExceeded)
    })?;
    Ok(StagingTreeV2 {
        canonical_bytes,
        entries,
        merkle_root,
        total_bytes,
    })
}

fn validate_staging_entries(entries: &[StagingEntryV2]) -> Result<(), DeploymentControlErrorV2> {
    let limits = DeploymentHardLimitsV2::compiled();
    if entries.len() < REQUIRED_STAGING_PREFIX_V2.len() + 1
        || entries.len() as u64 > limits.max_file_tree_entries()
    {
        return Err(DeploymentControlErrorV2::InvalidDeploymentTree);
    }
    for (entry, expected) in entries
        .iter()
        .take(REQUIRED_STAGING_PREFIX_V2.len())
        .zip(REQUIRED_STAGING_PREFIX_V2)
    {
        if entry.logical_path_id != expected {
            return Err(DeploymentControlErrorV2::InvalidDeploymentTree);
        }
    }
    let mut previous = None;
    let mut total = 0_u64;
    for entry in entries {
        entry.validate()?;
        if previous.is_some_and(|value| value >= entry.logical_path_id) {
            return Err(DeploymentControlErrorV2::InvalidDeploymentTree);
        }
        previous = Some(entry.logical_path_id);
        total = total
            .checked_add(entry.size)
            .ok_or(DeploymentControlErrorV2::DeploymentTreeLimitExceeded)?;
        if total > limits.max_staging_tree_bytes() {
            return Err(DeploymentControlErrorV2::DeploymentTreeLimitExceeded);
        }
    }
    Ok(())
}

fn encode_artifact_identity(
    artifact_type: ClosedArtifactTypeV2,
    target_os: ClosedTargetOsV2,
    target_architecture: ClosedTargetArchitectureV2,
    byte_length: u64,
    sha256: Digest32V2,
    platform_code_identity_digest: Digest32V2,
    execution_profile_digest: Digest32V2,
) -> Result<Vec<u8>, DeploymentControlErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encode_artifact_identity_into(
        &mut encoder,
        artifact_type,
        target_os,
        target_architecture,
        byte_length,
        sha256,
        platform_code_identity_digest,
        execution_profile_digest,
    )?;
    Ok(encoder.into_writer())
}

#[allow(clippy::too_many_arguments)]
fn encode_platform_lock(
    target_os: ClosedTargetOsV2,
    target_architecture: ClosedTargetArchitectureV2,
    os_release_identity_digest: Digest32V2,
    kernel_abi_digest: Digest32V2,
    service_manager_identity_digest: Digest32V2,
    filesystem_capabilities_digest: Digest32V2,
    native_sandbox_capabilities_digest: Digest32V2,
) -> Result<Vec<u8>, DeploymentControlErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(PLATFORM_LOCK_FIELDS_V2)
        .and_then(|encoder| encoder.u16(2))
        .and_then(|encoder| encoder.u16(target_os.tag()))
        .and_then(|encoder| encoder.u16(target_architecture.tag()))
        .and_then(|encoder| encoder.bytes(os_release_identity_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(kernel_abi_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(service_manager_identity_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(filesystem_capabilities_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(native_sandbox_capabilities_digest.as_bytes()))
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentPlan)?;
    Ok(encoder.into_writer())
}

#[allow(clippy::too_many_arguments)]
fn encode_artifact_identity_into(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    artifact_type: ClosedArtifactTypeV2,
    target_os: ClosedTargetOsV2,
    target_architecture: ClosedTargetArchitectureV2,
    byte_length: u64,
    sha256: Digest32V2,
    platform_code_identity_digest: Digest32V2,
    execution_profile_digest: Digest32V2,
) -> Result<(), DeploymentControlErrorV2> {
    encoder
        .array(ARTIFACT_IDENTITY_FIELDS_V2)
        .and_then(|encoder| encoder.u16(ARTIFACT_IDENTITY_SCHEMA_VERSION_V2))
        .and_then(|encoder| encoder.u16(artifact_type.tag()))
        .and_then(|encoder| encoder.u16(target_os.tag()))
        .and_then(|encoder| encoder.u16(target_architecture.tag()))
        .and_then(|encoder| encoder.u64(byte_length))
        .and_then(|encoder| encoder.bytes(sha256.as_bytes()))
        .and_then(|encoder| encoder.bytes(platform_code_identity_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(execution_profile_digest.as_bytes()))
        .map(|_| ())
        .map_err(|_| DeploymentControlErrorV2::InvalidArtifactIdentity)
}

fn encode_file_tree(entries: &[FileTreeEntryV2]) -> Result<Vec<u8>, DeploymentControlErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(entries.len() as u64)
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentTree)?;
    for entry in entries {
        encode_file_tree_entry_into(&mut encoder, entry)?;
    }
    Ok(encoder.into_writer())
}

fn encode_file_tree_entry(entry: &FileTreeEntryV2) -> Result<Vec<u8>, DeploymentControlErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encode_file_tree_entry_into(&mut encoder, entry)?;
    Ok(encoder.into_writer())
}

fn encode_file_tree_entry_into(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    entry: &FileTreeEntryV2,
) -> Result<(), DeploymentControlErrorV2> {
    encoder
        .array(FILE_TREE_ENTRY_FIELDS_V2)
        .and_then(|encoder| encoder.u16(entry.logical_path_id.tag()))
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentTree)?;
    encode_optional_logical_path(encoder, entry.parent_logical_path_id)?;
    encoder
        .u16(entry.entry_kind as u16)
        .and_then(|encoder| encoder.u16(ROOT_PRINCIPAL_TAG_V2))
        .and_then(|encoder| encoder.u16(ROOT_GROUP_TAG_V2))
        .and_then(|encoder| encoder.u32(entry.mode))
        .and_then(|encoder| encoder.bytes(entry.acl_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(entry.xattr_digest.as_bytes()))
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentTree)?;
    match entry.artifact_identity.as_ref() {
        None => encoder
            .array(1)
            .and_then(|encoder| encoder.u16(0))
            .map(|_| ())
            .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentTree),
        Some(identity) => {
            encoder
                .array(2)
                .and_then(|encoder| encoder.u16(1))
                .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentTree)?;
            encode_artifact_identity_into(
                encoder,
                identity.artifact_type,
                identity.target_os,
                identity.target_architecture,
                identity.byte_length,
                identity.sha256,
                identity.platform_code_identity_digest,
                identity.execution_profile_digest,
            )
            .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentTree)
        }
    }
}

fn encode_optional_logical_path(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    value: Option<ClosedLogicalPathIdV2>,
) -> Result<(), DeploymentControlErrorV2> {
    match value {
        None => encoder
            .array(1)
            .and_then(|encoder| encoder.u16(0))
            .map(|_| ())
            .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentTree),
        Some(value) => encoder
            .array(2)
            .and_then(|encoder| encoder.u16(1))
            .and_then(|encoder| encoder.u16(value.tag()))
            .map(|_| ())
            .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentTree),
    }
}

fn decode_file_tree_entry(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<FileTreeEntryV2, DeploymentControlErrorV2> {
    expect_array(
        decoder,
        FILE_TREE_ENTRY_FIELDS_V2,
        DeploymentControlErrorV2::InvalidDeploymentTree,
    )?;
    let logical_path_id = ClosedLogicalPathIdV2::from_tag(decode_u16(
        decoder,
        DeploymentControlErrorV2::InvalidDeploymentTree,
    )?)
    .ok_or(DeploymentControlErrorV2::InvalidDeploymentTree)?;
    let parent_logical_path_id = decode_optional_logical_path(decoder)?;
    let entry_kind = match decode_u16(decoder, DeploymentControlErrorV2::InvalidDeploymentTree)? {
        1 => FileTreeEntryKindV2::Directory,
        2 => FileTreeEntryKindV2::RegularFile,
        _ => return Err(DeploymentControlErrorV2::InvalidDeploymentTree),
    };
    if decode_u16(decoder, DeploymentControlErrorV2::InvalidDeploymentTree)?
        != ROOT_PRINCIPAL_TAG_V2
        || decode_u16(decoder, DeploymentControlErrorV2::InvalidDeploymentTree)?
            != ROOT_GROUP_TAG_V2
    {
        return Err(DeploymentControlErrorV2::InvalidDeploymentTree);
    }
    let mode = decoder
        .u32()
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentTree)?;
    let acl_digest = decode_digest(decoder, DeploymentControlErrorV2::InvalidDeploymentTree)?;
    let xattr_digest = decode_digest(decoder, DeploymentControlErrorV2::InvalidDeploymentTree)?;
    let artifact_identity = decode_optional_artifact_identity(decoder)?;
    let value = FileTreeEntryV2 {
        logical_path_id,
        parent_logical_path_id,
        entry_kind,
        mode,
        acl_digest,
        xattr_digest,
        artifact_identity,
    };
    value.validate()?;
    Ok(value)
}

fn decode_optional_logical_path(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<Option<ClosedLogicalPathIdV2>, DeploymentControlErrorV2> {
    let length = decoder
        .array()
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentTree)?;
    let tag = decode_u16(decoder, DeploymentControlErrorV2::InvalidDeploymentTree)?;
    match (tag, length) {
        (0, Some(1)) => Ok(None),
        (1, Some(2)) => ClosedLogicalPathIdV2::from_tag(decode_u16(
            decoder,
            DeploymentControlErrorV2::InvalidDeploymentTree,
        )?)
        .map(Some)
        .ok_or(DeploymentControlErrorV2::InvalidDeploymentTree),
        _ => Err(DeploymentControlErrorV2::InvalidDeploymentTree),
    }
}

fn decode_optional_artifact_identity(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<Option<ArtifactIdentityV2>, DeploymentControlErrorV2> {
    let length = decoder
        .array()
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentTree)?;
    let tag = decode_u16(decoder, DeploymentControlErrorV2::InvalidDeploymentTree)?;
    match (tag, length) {
        (0, Some(1)) => Ok(None),
        (1, Some(2)) => decode_artifact_identity_from_decoder(decoder).map(Some),
        _ => Err(DeploymentControlErrorV2::InvalidDeploymentTree),
    }
}

fn decode_artifact_identity_from_decoder(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<ArtifactIdentityV2, DeploymentControlErrorV2> {
    expect_array(
        decoder,
        ARTIFACT_IDENTITY_FIELDS_V2,
        DeploymentControlErrorV2::InvalidDeploymentTree,
    )?;
    if decode_u16(decoder, DeploymentControlErrorV2::InvalidDeploymentTree)?
        != ARTIFACT_IDENTITY_SCHEMA_VERSION_V2
    {
        return Err(DeploymentControlErrorV2::InvalidDeploymentTree);
    }
    let artifact_type = ClosedArtifactTypeV2::from_tag(decode_u16(
        decoder,
        DeploymentControlErrorV2::InvalidDeploymentTree,
    )?)
    .ok_or(DeploymentControlErrorV2::InvalidDeploymentTree)?;
    let target_os = ClosedTargetOsV2::from_tag(decode_u16(
        decoder,
        DeploymentControlErrorV2::InvalidDeploymentTree,
    )?)
    .ok_or(DeploymentControlErrorV2::InvalidDeploymentTree)?;
    let target_architecture = ClosedTargetArchitectureV2::from_tag(decode_u16(
        decoder,
        DeploymentControlErrorV2::InvalidDeploymentTree,
    )?)
    .ok_or(DeploymentControlErrorV2::InvalidDeploymentTree)?;
    let byte_length = decoder
        .u64()
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentTree)?;
    let sha256 = decode_digest(decoder, DeploymentControlErrorV2::InvalidDeploymentTree)?;
    let platform_code_identity_digest =
        decode_digest(decoder, DeploymentControlErrorV2::InvalidDeploymentTree)?;
    let execution_profile_digest =
        decode_digest(decoder, DeploymentControlErrorV2::InvalidDeploymentTree)?;
    ArtifactIdentityV2::new(
        artifact_type,
        target_os,
        target_architecture,
        byte_length,
        sha256,
        platform_code_identity_digest,
        execution_profile_digest,
    )
    .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentTree)
}

fn encode_staging_tree(entries: &[StagingEntryV2]) -> Result<Vec<u8>, DeploymentControlErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(entries.len() as u64)
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentTree)?;
    for entry in entries {
        encode_staging_entry_into(&mut encoder, entry)?;
    }
    Ok(encoder.into_writer())
}

fn encode_staging_entry(entry: &StagingEntryV2) -> Result<Vec<u8>, DeploymentControlErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encode_staging_entry_into(&mut encoder, entry)?;
    Ok(encoder.into_writer())
}

fn encode_staging_entry_into(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    entry: &StagingEntryV2,
) -> Result<(), DeploymentControlErrorV2> {
    encoder
        .array(STAGING_ENTRY_FIELDS_V2)
        .and_then(|encoder| encoder.u16(entry.logical_path_id.tag()))
        .and_then(|encoder| encoder.u16(entry.entry_kind as u16))
        .and_then(|encoder| encoder.u64(entry.size))
        .and_then(|encoder| encoder.bytes(entry.sha256.as_bytes()))
        .and_then(|encoder| encoder.u16(ROOT_PRINCIPAL_TAG_V2))
        .and_then(|encoder| encoder.u16(ROOT_GROUP_TAG_V2))
        .and_then(|encoder| encoder.u32(entry.mode))
        .and_then(|encoder| encoder.bytes(entry.acl_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(entry.xattr_digest.as_bytes()))
        .map(|_| ())
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentTree)
}

fn decode_staging_entry(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<StagingEntryV2, DeploymentControlErrorV2> {
    expect_array(
        decoder,
        STAGING_ENTRY_FIELDS_V2,
        DeploymentControlErrorV2::InvalidDeploymentTree,
    )?;
    let logical_path_id = ClosedStagingPathIdV2::from_tag(decode_u16(
        decoder,
        DeploymentControlErrorV2::InvalidDeploymentTree,
    )?)
    .ok_or(DeploymentControlErrorV2::InvalidDeploymentTree)?;
    let entry_kind = match decode_u16(decoder, DeploymentControlErrorV2::InvalidDeploymentTree)? {
        1 => StagingEntryKindV2::Directory,
        2 => StagingEntryKindV2::RegularFile,
        _ => return Err(DeploymentControlErrorV2::InvalidDeploymentTree),
    };
    let size = decoder
        .u64()
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentTree)?;
    let sha256 = decode_digest(decoder, DeploymentControlErrorV2::InvalidDeploymentTree)?;
    if decode_u16(decoder, DeploymentControlErrorV2::InvalidDeploymentTree)?
        != ROOT_PRINCIPAL_TAG_V2
        || decode_u16(decoder, DeploymentControlErrorV2::InvalidDeploymentTree)?
            != ROOT_GROUP_TAG_V2
    {
        return Err(DeploymentControlErrorV2::InvalidDeploymentTree);
    }
    let mode = decoder
        .u32()
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentTree)?;
    let acl_digest = decode_digest(decoder, DeploymentControlErrorV2::InvalidDeploymentTree)?;
    let xattr_digest = decode_digest(decoder, DeploymentControlErrorV2::InvalidDeploymentTree)?;
    let value = StagingEntryV2 {
        logical_path_id,
        entry_kind,
        size,
        sha256,
        mode,
        acl_digest,
        xattr_digest,
    };
    value.validate()?;
    Ok(value)
}

fn expect_array(
    decoder: &mut minicbor::Decoder<'_>,
    expected: u64,
    error: DeploymentControlErrorV2,
) -> Result<(), DeploymentControlErrorV2> {
    if decoder.array().map_err(|_| error)? != Some(expected) {
        return Err(error);
    }
    Ok(())
}

fn decode_u16(
    decoder: &mut minicbor::Decoder<'_>,
    error: DeploymentControlErrorV2,
) -> Result<u16, DeploymentControlErrorV2> {
    decoder.u16().map_err(|_| error)
}

fn decode_digest(
    decoder: &mut minicbor::Decoder<'_>,
    error: DeploymentControlErrorV2,
) -> Result<Digest32V2, DeploymentControlErrorV2> {
    let bytes = decoder.bytes().map_err(|_| error)?;
    let bytes: [u8; 32] = bytes.try_into().map_err(|_| error)?;
    Ok(Digest32V2::new(bytes))
}

fn hash_domain(domain: &[u8], bytes: &[u8]) -> Digest32V2 {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(bytes);
    Digest32V2::new(hash.finalize().into())
}

fn is_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}
