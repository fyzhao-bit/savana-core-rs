#![deny(unsafe_code)]

use core::fmt;

mod deployment_invocation;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
mod macos_activation;
#[cfg(target_os = "macos")]
mod macos_peer;
mod worker_sandbox;

#[cfg(test)]
#[path = "deployment_invocation_tests.rs"]
mod deployment_invocation_tests;

pub use deployment_invocation::{
    harden_root_deployment_process_v2, DeploymentApplySelectorV2, FixedDeploymentSpoolV2,
    StagedDeploymentTransactionBytesV2,
};
#[cfg(target_os = "linux")]
pub use linux::{
    measure_current_linux_process_v2, measure_linux_peer_v2, pin_current_linux_service_v2,
    take_systemd_listeners_v2, take_systemd_unix_listeners_v2, InheritedSystemdListenerV2,
    InheritedUnixListenerV2, PinnedLinuxPeerMeasurementV2,
};
#[cfg(target_os = "macos")]
pub use macos::{
    current_process_audit_token_v2, measure_macos_peer_v2, measure_macos_static_code_v2,
    parse_macos_audit_token_v2, pin_current_macos_service_v2, MacOsAuditIdentityV2,
    MacOsCodeIdentityMeasurementV2, PinnedMacOsServiceV2,
};
#[cfg(target_os = "macos")]
pub use macos_activation::{
    launchd_unix_socket_path_matches_v2, take_launchd_tcp_listeners_v2,
    take_launchd_unix_listeners_v2, InheritedTcpListenerV2, InheritedUnixListenerV2,
};
#[cfg(all(target_os = "macos", feature = "test-support"))]
pub use macos_activation::{
    take_launchd_tcp_listeners_with_v2, take_launchd_unix_listeners_with_v2,
};
#[cfg(target_os = "macos")]
pub use macos_peer::{macos_unix_peer_audit_token_v2, measure_macos_unix_peer_v2};
pub use worker_sandbox::{run_worker_sandbox_v2, WorkerSandboxErrorV2};

/// Fail-closed production boundary for the target-specific non-exportable
/// signer and monotonic rollback authority. A platform adapter may replace
/// this only inside this sealed crate once its measured target parameters are
/// compiled and attested.
pub fn require_native_deployment_platform_authority_v2() -> Result<(), NativeIdentityErrorV2> {
    open_native_deployment_authority_handles_v2().map(drop)
}

/// Opens the one target-native authority bundle. Production platform modules
/// construct this bundle only after the non-exportable signing key and
/// monotonic rollback facility have both been measured and attested.
pub fn open_native_deployment_authority_handles_v2(
) -> Result<NativeDeploymentAuthorityHandlesV2, NativeIdentityErrorV2> {
    Err(NativeIdentityErrorV2::NativePlatformAuthorityUnavailable)
}

/// Opens the immutable bootstrap trust material selected by the measured
/// native platform closure. It is kept separate from the signing and rollback
/// handles because it contains public canonical objects, not key capability.
pub fn open_native_deployment_bootstrap_trust_material_v2(
) -> Result<NativeDeploymentBootstrapTrustMaterialV2, NativeIdentityErrorV2> {
    Err(NativeIdentityErrorV2::NativePlatformAuthorityUnavailable)
}

const MAX_IDENTITY_BYTES_V2: usize = 255;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BoundedIdentityStringV2(String);

impl BoundedIdentityStringV2 {
    pub fn new(value: String) -> Result<Self, NativeIdentityErrorV2> {
        if value.is_empty()
            || value.len() > MAX_IDENTITY_BYTES_V2
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return Err(NativeIdentityErrorV2::InvalidMeasurement);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum NativePeerMeasurementV2 {
    Linux {
        uid: u32,
        gid: u32,
        pid: u32,
        process_start_time: u64,
        executable_measurement: [u8; 32],
    },
    MacOs {
        audit_token: [u8; 32],
        euid: u32,
        egid: u32,
        bundle_id: BoundedIdentityStringV2,
        team_id: BoundedIdentityStringV2,
        code_directory_measurement: [u8; 32],
        designated_requirement_measurement: [u8; 32],
        entitlement_measurement: [u8; 32],
    },
}

impl NativePeerMeasurementV2 {
    pub fn linux(
        uid: u32,
        gid: u32,
        pid: u32,
        process_start_time: u64,
        executable_measurement: [u8; 32],
    ) -> Result<Self, NativeIdentityErrorV2> {
        if pid == 0 || process_start_time == 0 || is_zero(&executable_measurement) {
            return Err(NativeIdentityErrorV2::InvalidMeasurement);
        }
        Ok(Self::Linux {
            uid,
            gid,
            pid,
            process_start_time,
            executable_measurement,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn macos(
        audit_token: [u8; 32],
        euid: u32,
        egid: u32,
        bundle_id: BoundedIdentityStringV2,
        team_id: BoundedIdentityStringV2,
        code_directory_measurement: [u8; 32],
        designated_requirement_measurement: [u8; 32],
        entitlement_measurement: [u8; 32],
    ) -> Result<Self, NativeIdentityErrorV2> {
        if is_zero(&audit_token)
            || is_zero(&code_directory_measurement)
            || is_zero(&designated_requirement_measurement)
            || is_zero(&entitlement_measurement)
        {
            return Err(NativeIdentityErrorV2::InvalidMeasurement);
        }
        Ok(Self::MacOs {
            audit_token,
            euid,
            egid,
            bundle_id,
            team_id,
            code_directory_measurement,
            designated_requirement_measurement,
            entitlement_measurement,
        })
    }

    pub const fn pid(&self) -> Option<u32> {
        match self {
            Self::Linux { pid, .. } => Some(*pid),
            Self::MacOs { .. } => None,
        }
    }

    pub const fn process_start_time(&self) -> Option<u64> {
        match self {
            Self::Linux {
                process_start_time, ..
            } => Some(*process_start_time),
            Self::MacOs { .. } => None,
        }
    }

    pub const fn executable_measurement(&self) -> Option<[u8; 32]> {
        match self {
            Self::Linux {
                executable_measurement,
                ..
            } => Some(*executable_measurement),
            Self::MacOs { .. } => None,
        }
    }
}

impl fmt::Debug for NativePeerMeasurementV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Linux { .. } => formatter.write_str("NativePeerMeasurementV2::Linux(<redacted>)"),
            Self::MacOs { .. } => formatter.write_str("NativePeerMeasurementV2::MacOs(<redacted>)"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExpectedNativePeerV2 {
    Linux {
        role_identity: BoundedIdentityStringV2,
        uid: u32,
        gid: u32,
        executable_measurement: [u8; 32],
    },
    MacOs {
        role_identity: BoundedIdentityStringV2,
        euid: u32,
        egid: u32,
        bundle_id: BoundedIdentityStringV2,
        team_id: BoundedIdentityStringV2,
        code_directory_measurement: [u8; 32],
        designated_requirement_measurement: [u8; 32],
        entitlement_measurement: [u8; 32],
    },
}

impl ExpectedNativePeerV2 {
    pub fn linux(
        role_identity: BoundedIdentityStringV2,
        uid: u32,
        gid: u32,
        executable_measurement: [u8; 32],
    ) -> Result<Self, NativeIdentityErrorV2> {
        if is_zero(&executable_measurement) {
            return Err(NativeIdentityErrorV2::InvalidMeasurement);
        }
        Ok(Self::Linux {
            role_identity,
            uid,
            gid,
            executable_measurement,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn macos(
        role_identity: BoundedIdentityStringV2,
        euid: u32,
        egid: u32,
        bundle_id: BoundedIdentityStringV2,
        team_id: BoundedIdentityStringV2,
        code_directory_measurement: [u8; 32],
        designated_requirement_measurement: [u8; 32],
        entitlement_measurement: [u8; 32],
    ) -> Result<Self, NativeIdentityErrorV2> {
        if is_zero(&code_directory_measurement)
            || is_zero(&designated_requirement_measurement)
            || is_zero(&entitlement_measurement)
        {
            return Err(NativeIdentityErrorV2::InvalidMeasurement);
        }
        Ok(Self::MacOs {
            role_identity,
            euid,
            egid,
            bundle_id,
            team_id,
            code_directory_measurement,
            designated_requirement_measurement,
            entitlement_measurement,
        })
    }
}

pub fn verify_native_peer_v2(
    expected: &ExpectedNativePeerV2,
    endpoint_role: &BoundedIdentityStringV2,
    observed: &NativePeerMeasurementV2,
) -> Result<(), NativeIdentityErrorV2> {
    let matches = match (expected, observed) {
        (
            ExpectedNativePeerV2::Linux {
                role_identity,
                uid,
                gid,
                executable_measurement,
            },
            NativePeerMeasurementV2::Linux {
                uid: observed_uid,
                gid: observed_gid,
                executable_measurement: observed_executable,
                ..
            },
        ) => {
            role_identity == endpoint_role
                && uid == observed_uid
                && gid == observed_gid
                && executable_measurement == observed_executable
        }
        (
            ExpectedNativePeerV2::MacOs {
                role_identity,
                euid,
                egid,
                bundle_id,
                team_id,
                code_directory_measurement,
                designated_requirement_measurement,
                entitlement_measurement,
            },
            NativePeerMeasurementV2::MacOs {
                euid: observed_euid,
                egid: observed_egid,
                bundle_id: observed_bundle,
                team_id: observed_team,
                code_directory_measurement: observed_code,
                designated_requirement_measurement: observed_requirement,
                entitlement_measurement: observed_entitlements,
                ..
            },
        ) => {
            role_identity == endpoint_role
                && euid == observed_euid
                && egid == observed_egid
                && bundle_id == observed_bundle
                && team_id == observed_team
                && code_directory_measurement == observed_code
                && designated_requirement_measurement == observed_requirement
                && entitlement_measurement == observed_entitlements
        }
        _ => false,
    };
    if matches {
        Ok(())
    } else {
        Err(NativeIdentityErrorV2::IdentityMismatch)
    }
}

mod sealed_native_rollback_authority_v2 {
    pub trait Sealed {}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum NativeDeploymentSignatureDomainV2 {
    LedgerActivation = 5,
    InstallationEpochActivation = 6,
    StoreCompatibility = 8,
    VerificationEvidence = 9,
    CommitAttestation = 10,
    EvidenceGcCheckpoint = 13,
    RollbackVerificationEvidence = 17,
    RollbackVerificationAttestation = 18,
    LedgerSlot = 21,
    InstallationEvidenceEnvelope = 22,
    DurableDeploymentTransactionCore = 25,
    DurableDeploymentTransactionRecord = 26,
    RecoveryRollbackReadinessEvidence = 27,
}

impl NativeDeploymentSignatureDomainV2 {
    #[cfg(any(test, feature = "test-support"))]
    const fn domain(self) -> &'static [u8] {
        match self {
            Self::LedgerActivation => b"savana.deployment-ledger.v2.activation\0",
            Self::InstallationEpochActivation => b"savana.installation-epoch.v2.activation\0",
            Self::StoreCompatibility => b"savana.store-compatibility.v2.signature\0",
            Self::VerificationEvidence => b"savana.verification-evidence.v2.signature\0",
            Self::CommitAttestation => b"savana.commit-attestation.v2.signature\0",
            Self::EvidenceGcCheckpoint => b"savana.evidence-gc-checkpoint.v2.signature\0",
            Self::RollbackVerificationEvidence => {
                b"savana.rollback-verification-evidence.v2.signature\0"
            }
            Self::RollbackVerificationAttestation => {
                b"savana.rollback-verification-attestation.v2.signature\0"
            }
            Self::LedgerSlot => b"savana.ledger-slot.v2.signature\0",
            Self::InstallationEvidenceEnvelope => b"savana.installation-evidence.v2.envelope\0",
            Self::DurableDeploymentTransactionCore => {
                b"savana.durable-deployment-core.v2.signature\0"
            }
            Self::DurableDeploymentTransactionRecord => {
                b"savana.durable-deployment-record.v2.signature\0"
            }
            Self::RecoveryRollbackReadinessEvidence => {
                b"savana.recovery-rollback-readiness.v2.signature\0"
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeDeploymentSignatureRequestV2 {
    domain: NativeDeploymentSignatureDomainV2,
    installation_id: [u8; 32],
    installation_epoch: u64,
    payload_digest: [u8; 32],
}

impl NativeDeploymentSignatureRequestV2 {
    pub fn new(
        domain: NativeDeploymentSignatureDomainV2,
        installation_id: [u8; 32],
        installation_epoch: u64,
        payload_digest: [u8; 32],
    ) -> Result<Self, NativeIdentityErrorV2> {
        if is_zero(&installation_id) || installation_epoch == 0 || is_zero(&payload_digest) {
            return Err(NativeIdentityErrorV2::InvalidMeasurement);
        }
        Ok(Self {
            domain,
            installation_id,
            installation_epoch,
            payload_digest,
        })
    }

    pub const fn domain(self) -> NativeDeploymentSignatureDomainV2 {
        self.domain
    }

    pub const fn installation_id(self) -> [u8; 32] {
        self.installation_id
    }

    pub const fn installation_epoch(self) -> u64 {
        self.installation_epoch
    }

    pub const fn payload_digest(self) -> [u8; 32] {
        self.payload_digest
    }

    #[cfg(any(test, feature = "test-support"))]
    fn signature_input(self) -> [u8; 32] {
        let mut hash = sha2::Sha256::new();
        use sha2::Digest as _;
        hash.update(b"savana.domain-signature.v2\0");
        hash.update((self.domain as u16).to_be_bytes());
        hash.update(self.domain.domain());
        hash.update(self.payload_digest);
        hash.finalize().into()
    }
}

mod sealed_native_deployment_signing_authority_v2 {
    pub trait Sealed {}
}

/// A platform-owned activation signer whose private key is never returned to
/// Rust callers. The closed request enum prevents arbitrary-message signing.
pub trait NativeDeploymentSigningAuthorityV2:
    sealed_native_deployment_signing_authority_v2::Sealed
{
    fn authority_identity(&self) -> [u8; 32];

    fn installation_id(&self) -> [u8; 32];

    fn key_id(&self) -> [u8; 32];

    fn key_epoch(&self) -> u64;

    fn public_key(&self) -> [u8; 32];

    fn sign(
        &mut self,
        request: NativeDeploymentSignatureRequestV2,
    ) -> Result<[u8; 64], NativeIdentityErrorV2>;
}

#[cfg(any(test, feature = "test-support"))]
pub struct TestNativeDeploymentSigningAuthorityV2 {
    authority_identity: [u8; 32],
    installation_id: [u8; 32],
    key_epoch: u64,
    signing_key: ed25519_dalek::SigningKey,
    key_id: [u8; 32],
}

#[cfg(any(test, feature = "test-support"))]
impl TestNativeDeploymentSigningAuthorityV2 {
    pub fn new_for_test(
        authority_identity: [u8; 32],
        installation_id: [u8; 32],
        key_epoch: u64,
        signing_seed: [u8; 32],
    ) -> Result<Self, NativeIdentityErrorV2> {
        if is_zero(&authority_identity)
            || is_zero(&installation_id)
            || key_epoch == 0
            || is_zero(&signing_seed)
        {
            return Err(NativeIdentityErrorV2::InvalidMeasurement);
        }
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&signing_seed);
        let mut hash = sha2::Sha256::new();
        use sha2::Digest as _;
        hash.update(b"savana.ed25519-key-id.v2\0");
        hash.update(signing_key.verifying_key().to_bytes());
        let key_id = hash.finalize().into();
        Ok(Self {
            authority_identity,
            installation_id,
            key_epoch,
            signing_key,
            key_id,
        })
    }
}

#[cfg(any(test, feature = "test-support"))]
impl sealed_native_deployment_signing_authority_v2::Sealed
    for TestNativeDeploymentSigningAuthorityV2
{
}

#[cfg(any(test, feature = "test-support"))]
impl NativeDeploymentSigningAuthorityV2 for TestNativeDeploymentSigningAuthorityV2 {
    fn authority_identity(&self) -> [u8; 32] {
        self.authority_identity
    }

    fn installation_id(&self) -> [u8; 32] {
        self.installation_id
    }

    fn key_id(&self) -> [u8; 32] {
        self.key_id
    }

    fn key_epoch(&self) -> u64 {
        self.key_epoch
    }

    fn public_key(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    fn sign(
        &mut self,
        request: NativeDeploymentSignatureRequestV2,
    ) -> Result<[u8; 64], NativeIdentityErrorV2> {
        if request.installation_id != self.installation_id
            || request.installation_epoch != self.key_epoch
        {
            return Err(NativeIdentityErrorV2::IdentityMismatch);
        }
        use ed25519_dalek::Signer as _;
        Ok(self.signing_key.sign(&request.signature_input()).to_bytes())
    }
}

/// A platform-owned, non-exportable monotonic deployment authority.
///
/// The private sealing supertrait deliberately prevents application crates
/// from supplying a file-backed or in-memory production substitute.
pub trait NativeRollbackAuthorityV2: sealed_native_rollback_authority_v2::Sealed {
    fn authority_identity(&self) -> [u8; 32];

    fn read_generation(
        &mut self,
        installation_id: [u8; 32],
        installation_epoch: u64,
    ) -> Result<u64, NativeIdentityErrorV2>;

    fn compare_and_advance(
        &mut self,
        installation_id: [u8; 32],
        installation_epoch: u64,
        expected_generation: u64,
        next_generation: u64,
    ) -> Result<(), NativeIdentityErrorV2>;
}

/// A non-cloneable platform bundle that keeps signing and rollback authority
/// together while still exposing their two deliberately non-interchangeable
/// sealed interfaces.
pub struct NativeDeploymentAuthorityHandlesV2 {
    signing: Box<dyn NativeDeploymentSigningAuthorityV2>,
    rollback: Box<dyn NativeRollbackAuthorityV2>,
}

#[cfg(any(test, feature = "test-support"))]
const MAX_BOOTSTRAP_TRUST_CHAIN_RECORDS_V2: usize = 64;
#[cfg(any(test, feature = "test-support"))]
const MAX_BOOTSTRAP_TRUST_OBJECT_BYTES_V2: usize = 4 * 1024 * 1024;
#[cfg(any(test, feature = "test-support"))]
const MAX_BOOTSTRAP_TRUST_TOTAL_BYTES_V2: usize = 16 * 1024 * 1024;

/// Bounded canonical trust chains rooted in one installer/MDM public key.
/// There are no paths, provider strings, optional chains, or unknown object
/// families in this transfer object.
#[derive(Clone, PartialEq, Eq)]
pub struct NativeDeploymentBootstrapTrustMaterialV2 {
    installer_key_id: [u8; 32],
    installer_key_epoch: u64,
    installer_public_key: [u8; 32],
    deployment_trust_root_chain: Vec<Vec<u8>>,
    activation_trust_root_chain: Vec<Vec<u8>>,
    declassification_trust_root_chain: Vec<Vec<u8>>,
    release_trust_root_chain: Vec<Vec<u8>>,
}

impl std::fmt::Debug for NativeDeploymentBootstrapTrustMaterialV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeDeploymentBootstrapTrustMaterialV2")
            .field("installer_key_id", &self.installer_key_id)
            .field("installer_key_epoch", &self.installer_key_epoch)
            .field(
                "deployment_chain_length",
                &self.deployment_trust_root_chain.len(),
            )
            .field(
                "activation_chain_length",
                &self.activation_trust_root_chain.len(),
            )
            .field(
                "declassification_chain_length",
                &self.declassification_trust_root_chain.len(),
            )
            .field("release_chain_length", &self.release_trust_root_chain.len())
            .finish_non_exhaustive()
    }
}

impl NativeDeploymentBootstrapTrustMaterialV2 {
    #[cfg(any(test, feature = "test-support"))]
    #[allow(clippy::too_many_arguments)]
    pub fn new_for_test(
        installer_key_id: [u8; 32],
        installer_key_epoch: u64,
        installer_public_key: [u8; 32],
        deployment_trust_root_chain: Vec<Vec<u8>>,
        activation_trust_root_chain: Vec<Vec<u8>>,
        declassification_trust_root_chain: Vec<Vec<u8>>,
        release_trust_root_chain: Vec<Vec<u8>>,
    ) -> Result<Self, NativeIdentityErrorV2> {
        Self::new(
            installer_key_id,
            installer_key_epoch,
            installer_public_key,
            deployment_trust_root_chain,
            activation_trust_root_chain,
            declassification_trust_root_chain,
            release_trust_root_chain,
        )
    }

    #[allow(clippy::too_many_arguments)]
    #[cfg(any(test, feature = "test-support"))]
    fn new(
        installer_key_id: [u8; 32],
        installer_key_epoch: u64,
        installer_public_key: [u8; 32],
        deployment_trust_root_chain: Vec<Vec<u8>>,
        activation_trust_root_chain: Vec<Vec<u8>>,
        declassification_trust_root_chain: Vec<Vec<u8>>,
        release_trust_root_chain: Vec<Vec<u8>>,
    ) -> Result<Self, NativeIdentityErrorV2> {
        let mut hash = sha2::Sha256::new();
        use sha2::Digest as _;
        hash.update(b"savana.ed25519-key-id.v2\0");
        hash.update(installer_public_key);
        let derived_key_id: [u8; 32] = hash.finalize().into();
        if installer_key_epoch == 0
            || is_zero(&installer_key_id)
            || is_zero(&installer_public_key)
            || derived_key_id != installer_key_id
        {
            return Err(NativeIdentityErrorV2::InvalidMeasurement);
        }
        let chains = [
            &deployment_trust_root_chain,
            &activation_trust_root_chain,
            &declassification_trust_root_chain,
            &release_trust_root_chain,
        ];
        let mut total = 0_usize;
        for chain in chains {
            if chain.is_empty() || chain.len() > MAX_BOOTSTRAP_TRUST_CHAIN_RECORDS_V2 {
                return Err(NativeIdentityErrorV2::InvalidMeasurement);
            }
            for object in chain {
                if object.is_empty() || object.len() > MAX_BOOTSTRAP_TRUST_OBJECT_BYTES_V2 {
                    return Err(NativeIdentityErrorV2::InvalidMeasurement);
                }
                total = total
                    .checked_add(object.len())
                    .ok_or(NativeIdentityErrorV2::InvalidMeasurement)?;
                if total > MAX_BOOTSTRAP_TRUST_TOTAL_BYTES_V2 {
                    return Err(NativeIdentityErrorV2::InvalidMeasurement);
                }
            }
        }
        Ok(Self {
            installer_key_id,
            installer_key_epoch,
            installer_public_key,
            deployment_trust_root_chain,
            activation_trust_root_chain,
            declassification_trust_root_chain,
            release_trust_root_chain,
        })
    }

    pub const fn installer_key_id(&self) -> [u8; 32] {
        self.installer_key_id
    }

    pub const fn installer_key_epoch(&self) -> u64 {
        self.installer_key_epoch
    }

    pub const fn installer_public_key(&self) -> [u8; 32] {
        self.installer_public_key
    }

    pub fn deployment_trust_root_chain(&self) -> &[Vec<u8>] {
        &self.deployment_trust_root_chain
    }

    pub fn activation_trust_root_chain(&self) -> &[Vec<u8>] {
        &self.activation_trust_root_chain
    }

    pub fn declassification_trust_root_chain(&self) -> &[Vec<u8>] {
        &self.declassification_trust_root_chain
    }

    pub fn release_trust_root_chain(&self) -> &[Vec<u8>] {
        &self.release_trust_root_chain
    }
}

impl std::fmt::Debug for NativeDeploymentAuthorityHandlesV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeDeploymentAuthorityHandlesV2")
            .field(
                "signing_authority_identity",
                &self.signing.authority_identity(),
            )
            .field(
                "rollback_authority_identity",
                &self.rollback.authority_identity(),
            )
            .finish_non_exhaustive()
    }
}

impl NativeDeploymentAuthorityHandlesV2 {
    pub fn split(
        &mut self,
    ) -> (
        &mut dyn NativeDeploymentSigningAuthorityV2,
        &mut dyn NativeRollbackAuthorityV2,
    ) {
        (self.signing.as_mut(), self.rollback.as_mut())
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn new_for_test(
        signing: TestNativeDeploymentSigningAuthorityV2,
        rollback: TestNativeRollbackAuthorityV2,
    ) -> Result<Self, NativeIdentityErrorV2> {
        if signing.installation_id != rollback.installation_id
            || signing.key_epoch != rollback.installation_epoch
        {
            return Err(NativeIdentityErrorV2::IdentityMismatch);
        }
        Ok(Self {
            signing: Box::new(signing),
            rollback: Box::new(rollback),
        })
    }
}

#[cfg(any(test, feature = "test-support"))]
#[derive(Debug, Clone)]
pub struct TestNativeRollbackAuthorityV2 {
    authority_identity: [u8; 32],
    installation_id: [u8; 32],
    installation_epoch: u64,
    state: std::sync::Arc<std::sync::Mutex<TestNativeRollbackStateV2>>,
}

#[cfg(any(test, feature = "test-support"))]
#[derive(Debug)]
struct TestNativeRollbackStateV2 {
    generation: u64,
    fail_next_advance: bool,
}

#[cfg(any(test, feature = "test-support"))]
impl TestNativeRollbackAuthorityV2 {
    pub fn new_for_test(
        authority_identity: [u8; 32],
        installation_id: [u8; 32],
        installation_epoch: u64,
        generation: u64,
    ) -> Result<Self, NativeIdentityErrorV2> {
        if is_zero(&authority_identity)
            || is_zero(&installation_id)
            || installation_epoch == 0
            || generation == 0
        {
            return Err(NativeIdentityErrorV2::InvalidMeasurement);
        }
        Ok(Self {
            authority_identity,
            installation_id,
            installation_epoch,
            state: std::sync::Arc::new(std::sync::Mutex::new(TestNativeRollbackStateV2 {
                generation,
                fail_next_advance: false,
            })),
        })
    }

    pub fn fail_next_advance_for_test(&mut self) {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .fail_next_advance = true;
    }

    pub fn generation_for_test(&self) -> u64 {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .generation
    }

    fn require_tuple(
        &self,
        installation_id: [u8; 32],
        installation_epoch: u64,
    ) -> Result<(), NativeIdentityErrorV2> {
        if installation_id != self.installation_id || installation_epoch != self.installation_epoch
        {
            return Err(NativeIdentityErrorV2::IdentityMismatch);
        }
        Ok(())
    }
}

#[cfg(any(test, feature = "test-support"))]
impl sealed_native_rollback_authority_v2::Sealed for TestNativeRollbackAuthorityV2 {}

#[cfg(any(test, feature = "test-support"))]
impl NativeRollbackAuthorityV2 for TestNativeRollbackAuthorityV2 {
    fn authority_identity(&self) -> [u8; 32] {
        self.authority_identity
    }

    fn read_generation(
        &mut self,
        installation_id: [u8; 32],
        installation_epoch: u64,
    ) -> Result<u64, NativeIdentityErrorV2> {
        self.require_tuple(installation_id, installation_epoch)?;
        Ok(self
            .state
            .lock()
            .map_err(|_| NativeIdentityErrorV2::Io)?
            .generation)
    }

    fn compare_and_advance(
        &mut self,
        installation_id: [u8; 32],
        installation_epoch: u64,
        expected_generation: u64,
        next_generation: u64,
    ) -> Result<(), NativeIdentityErrorV2> {
        self.require_tuple(installation_id, installation_epoch)?;
        let mut state = self.state.lock().map_err(|_| NativeIdentityErrorV2::Io)?;
        if state.fail_next_advance {
            state.fail_next_advance = false;
            return Err(NativeIdentityErrorV2::Io);
        }
        if state.generation != expected_generation
            || expected_generation.checked_add(1) != Some(next_generation)
        {
            return Err(NativeIdentityErrorV2::IdentityMismatch);
        }
        state.generation = next_generation;
        Ok(())
    }
}

#[cfg(test)]
mod native_deployment_authority_handle_tests {
    use super::{
        NativeDeploymentAuthorityHandlesV2, NativeDeploymentBootstrapTrustMaterialV2,
        NativeDeploymentSignatureDomainV2, NativeDeploymentSignatureRequestV2,
        NativeDeploymentSigningAuthorityV2, TestNativeDeploymentSigningAuthorityV2,
        TestNativeRollbackAuthorityV2, MAX_BOOTSTRAP_TRUST_OBJECT_BYTES_V2,
    };

    #[test]
    fn bundled_authorities_preserve_one_installation_tuple_and_separate_operations() {
        let installation_id = [0x21; 32];
        let mut handles = NativeDeploymentAuthorityHandlesV2::new_for_test(
            TestNativeDeploymentSigningAuthorityV2::new_for_test(
                [0x22; 32],
                installation_id,
                7,
                [0x23; 32],
            )
            .unwrap(),
            TestNativeRollbackAuthorityV2::new_for_test([0x24; 32], installation_id, 7, 11)
                .unwrap(),
        )
        .unwrap();
        let (signing, rollback) = handles.split();
        let request = NativeDeploymentSignatureRequestV2::new(
            NativeDeploymentSignatureDomainV2::LedgerActivation,
            installation_id,
            7,
            [0x25; 32],
        )
        .unwrap();
        assert_ne!(signing.sign(request).unwrap(), [0; 64]);
        assert_eq!(rollback.read_generation(installation_id, 7).unwrap(), 11);
        rollback
            .compare_and_advance(installation_id, 7, 11, 12)
            .unwrap();
        assert_eq!(rollback.read_generation(installation_id, 7).unwrap(), 12);
    }

    #[test]
    fn bundled_authorities_reject_cross_installation_pairing() {
        let signing = TestNativeDeploymentSigningAuthorityV2::new_for_test(
            [0x31; 32], [0x32; 32], 1, [0x33; 32],
        )
        .unwrap();
        let rollback =
            TestNativeRollbackAuthorityV2::new_for_test([0x34; 32], [0x35; 32], 1, 1).unwrap();
        assert!(NativeDeploymentAuthorityHandlesV2::new_for_test(signing, rollback).is_err());
    }

    #[test]
    fn bootstrap_trust_material_rejects_missing_or_unbounded_chains() {
        let signing = TestNativeDeploymentSigningAuthorityV2::new_for_test(
            [0x41; 32], [0x42; 32], 3, [0x43; 32],
        )
        .unwrap();
        let key_id = signing.key_id();
        let public_key = signing.public_key();
        assert!(NativeDeploymentBootstrapTrustMaterialV2::new_for_test(
            key_id,
            3,
            public_key,
            Vec::new(),
            vec![vec![1]],
            vec![vec![1]],
            vec![vec![1]],
        )
        .is_err());
        assert!(NativeDeploymentBootstrapTrustMaterialV2::new_for_test(
            key_id,
            3,
            public_key,
            vec![vec![1; MAX_BOOTSTRAP_TRUST_OBJECT_BYTES_V2 + 1]],
            vec![vec![1]],
            vec![vec![1]],
            vec![vec![1]],
        )
        .is_err());
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum NativeIdentityErrorV2 {
    #[error("native peer measurement is invalid")]
    InvalidMeasurement,
    #[error("native peer identity does not match the active edge")]
    IdentityMismatch,
    #[error("native code identity is unavailable")]
    CodeIdentityUnavailable,
    #[error("native peer process exited during measurement")]
    ProcessExited,
    #[error("native platform identity I/O failed")]
    Io,
    #[error("deployment helper invocation is not the exact closed apply form")]
    InvalidDeploymentInvocation,
    #[error("deployment spool identity or descriptor is unsafe")]
    UnsafeDeploymentSpool,
    #[error("the target native deployment authority is not compiled and attested")]
    NativePlatformAuthorityUnavailable,
}

#[cfg(any(target_os = "linux", test))]
fn parse_systemd_listener_activation_v2(
    listen_pid: Option<&str>,
    listen_fds: Option<&str>,
    listen_fd_names: Option<&str>,
    current_pid: u32,
    expected_names: &[&str],
) -> Result<Vec<i32>, NativeIdentityErrorV2> {
    if current_pid == 0
        || expected_names.is_empty()
        || expected_names.len() > 16
        || expected_names.iter().any(|name| !valid_listener_name(name))
        || expected_names
            .iter()
            .enumerate()
            .any(|(index, name)| expected_names[..index].contains(name))
    {
        return Err(NativeIdentityErrorV2::InvalidMeasurement);
    }
    let pid = listen_pid
        .ok_or(NativeIdentityErrorV2::InvalidMeasurement)?
        .parse::<u32>()
        .map_err(|_| NativeIdentityErrorV2::InvalidMeasurement)?;
    let count = listen_fds
        .ok_or(NativeIdentityErrorV2::InvalidMeasurement)?
        .parse::<usize>()
        .map_err(|_| NativeIdentityErrorV2::InvalidMeasurement)?;
    let names = listen_fd_names.ok_or(NativeIdentityErrorV2::InvalidMeasurement)?;
    let mut actual_names = Vec::new();
    actual_names
        .try_reserve_exact(count)
        .map_err(|_| NativeIdentityErrorV2::Io)?;
    actual_names.extend(names.split(':'));
    if pid != current_pid
        || count != expected_names.len()
        || actual_names.len() != count
        || actual_names.iter().any(|name| !valid_listener_name(name))
        || actual_names
            .iter()
            .enumerate()
            .any(|(index, name)| actual_names[..index].contains(name))
    {
        return Err(NativeIdentityErrorV2::InvalidMeasurement);
    }
    expected_names
        .iter()
        .map(|expected| {
            let offset = actual_names
                .iter()
                .position(|actual| actual == expected)
                .ok_or(NativeIdentityErrorV2::InvalidMeasurement)?;
            i32::try_from(3_usize + offset).map_err(|_| NativeIdentityErrorV2::InvalidMeasurement)
        })
        .collect()
}

#[cfg(any(target_os = "linux", target_os = "macos", test))]
fn valid_listener_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

const fn is_zero(bytes: &[u8; 32]) -> bool {
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != 0 {
            return false;
        }
        index += 1;
    }
    true
}

#[cfg(test)]
mod activation_tests {
    use super::parse_systemd_listener_activation_v2;

    #[test]
    fn systemd_listener_activation_is_exact_pid_count_and_name_set() {
        assert_eq!(
            parse_systemd_listener_activation_v2(
                Some("42"),
                Some("2"),
                Some("savana-agent-kernel:savana-ingress-kernel"),
                42,
                &["savana-agent-kernel", "savana-ingress-kernel"],
            )
            .unwrap(),
            vec![3, 4],
        );
        assert_eq!(
            parse_systemd_listener_activation_v2(
                Some("42"),
                Some("2"),
                Some("savana-ingress-kernel:savana-agent-kernel"),
                42,
                &["savana-agent-kernel", "savana-ingress-kernel"],
            )
            .unwrap(),
            vec![4, 3],
        );
        for invalid in [
            (
                Some("41"),
                Some("2"),
                Some("savana-agent-kernel:savana-ingress-kernel"),
            ),
            (Some("42"), Some("1"), Some("savana-agent-kernel")),
            (
                Some("42"),
                Some("2"),
                Some("savana-agent-kernel:savana-agent-kernel"),
            ),
            (
                Some("42"),
                Some("2"),
                Some("savana-agent-kernel:savana-ingress-kernel:extra"),
            ),
            (
                None,
                Some("2"),
                Some("savana-agent-kernel:savana-ingress-kernel"),
            ),
        ] {
            assert!(parse_systemd_listener_activation_v2(
                invalid.0,
                invalid.1,
                invalid.2,
                42,
                &["savana-agent-kernel", "savana-ingress-kernel"],
            )
            .is_err());
        }
    }
}
