use std::fs;
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};
use std::path::{Path, PathBuf};

use savana_kernel_protocol::v2::{Digest32V2, Ed25519KeyIdV2, ServiceIdentityV2};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};

use super::{
    ClosedServiceIdV2, DeploymentTrustErrorV2, PlatformDeploymentTrustV2,
    PlatformServiceObservationV2, ServiceAuthorityHandlesV2, ServiceDeploymentLockV2,
    VerifiedDaemonStartupV2, VerifiedDeploymentManifestV2,
};

const SERVICE_COUNT_V2: usize = 5;
const MAX_MANIFEST_BYTES_V2: usize = 1024 * 1024;
const MAX_PROJECTION_BYTES_V2: usize = 1024 * 1024;
const MAX_BOOTSTRAP_BYTES_V2: usize = 128 * 1024;
const MAX_ARTIFACT_BYTES_V2: usize = 256 * 1024 * 1024;
const CONFIG_PATH_DOMAIN_V2: &[u8] = b"SAVANA_CONFIG_PATH_IDENTITY_V2\0";
const SOCKET_PATH_DOMAIN_V2: &[u8] = b"SAVANA_SOCKET_PATH_IDENTITY_V2\0";

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilesystemServiceObservationConfigV2 {
    pub service: String,
    pub service_identity: String,
    pub process_uid: u32,
    pub process_gid: u32,
    pub executable_path: PathBuf,
    pub config_path: PathBuf,
    pub endpoint: FilesystemServiceEndpointConfigV2,
    pub sandbox_profile_path: PathBuf,
    pub keystore_authority_identity: String,
    pub rollback_authority_identity: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum FilesystemServiceEndpointConfigV2 {
    UnixSocket { path: PathBuf },
    LoopbackTcp { port: u16 },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestRootDtoV2 {
    key_id: String,
    public_key: String,
}

struct FilesystemDeploymentTrustV2 {
    observations: Vec<PlatformServiceObservationV2>,
    authorities: Vec<ServiceAuthorityHandlesV2>,
    effect_projection: Vec<u8>,
}

impl PlatformDeploymentTrustV2 for FilesystemDeploymentTrustV2 {
    fn observe_service(
        &mut self,
        service: ClosedServiceIdV2,
    ) -> Result<PlatformServiceObservationV2, DeploymentTrustErrorV2> {
        let index = self
            .observations
            .iter()
            .position(|observation| observation.lock.service == service)
            .ok_or(DeploymentTrustErrorV2::PlatformUnavailable)?;
        Ok(self.observations.remove(index))
    }

    fn acquire_service_authorities(
        &mut self,
        service: ClosedServiceIdV2,
    ) -> Result<ServiceAuthorityHandlesV2, DeploymentTrustErrorV2> {
        let index = self
            .authorities
            .iter()
            .position(|authority| authority.service == service)
            .ok_or(DeploymentTrustErrorV2::PlatformUnavailable)?;
        Ok(self.authorities.remove(index))
    }

    fn read_effect_ledger_projection(&mut self) -> Result<Vec<u8>, DeploymentTrustErrorV2> {
        if self.effect_projection.is_empty() {
            return Err(DeploymentTrustErrorV2::PlatformUnavailable);
        }
        Ok(std::mem::take(&mut self.effect_projection))
    }
}

pub fn load_verified_filesystem_startup_v2(
    manifest_root_path: &Path,
    signed_manifest_path: &Path,
    effect_ledger_projection_path: &Path,
    services: &[FilesystemServiceObservationConfigV2],
) -> Result<VerifiedDaemonStartupV2, DeploymentTrustErrorV2> {
    // File-backed authority identities and systemd credential files are an
    // integration harness, not non-exportable key or monotonic rollback
    // authority. A release binary must not turn their presence into a
    // production startup proof.
    if !cfg!(all(
        debug_assertions,
        feature = "filesystem-integration-authority"
    )) {
        return Err(DeploymentTrustErrorV2::MissingPlatformAuthority);
    }
    if services.len() != SERVICE_COUNT_V2 {
        return Err(DeploymentTrustErrorV2::IncompleteManifest);
    }
    let root_bytes = read_verified_regular_file_v2(manifest_root_path, 4096, Some((0, 0, 0o444)))?;
    let root: ManifestRootDtoV2 = serde_json::from_slice(&root_bytes)
        .map_err(|_| DeploymentTrustErrorV2::NonCanonicalManifest)?;
    let signed_manifest =
        read_verified_regular_file_v2(signed_manifest_path, MAX_MANIFEST_BYTES_V2, None)?;
    let manifest = VerifiedDeploymentManifestV2::verify(
        &signed_manifest,
        Ed25519KeyIdV2::new(decode_hex_32_v2(&root.key_id)?),
        decode_hex_32_v2(&root.public_key)?,
    )?;
    let mut observations = Vec::new();
    let mut authorities = Vec::new();
    observations
        .try_reserve_exact(SERVICE_COUNT_V2)
        .map_err(|_| DeploymentTrustErrorV2::PlatformUnavailable)?;
    authorities
        .try_reserve_exact(SERVICE_COUNT_V2)
        .map_err(|_| DeploymentTrustErrorV2::PlatformUnavailable)?;
    for (expected, config) in ClosedServiceIdV2::ALL.iter().zip(services) {
        let service = parse_service_id(&config.service)?;
        if service != *expected || config.process_uid == 0 || config.process_gid == 0 {
            return Err(DeploymentTrustErrorV2::IncompleteManifest);
        }
        let executable = read_measured_artifact(&config.executable_path, MAX_ARTIFACT_BYTES_V2)?;
        let daemon_config = read_measured_artifact(&config.config_path, MAX_BOOTSTRAP_BYTES_V2)?;
        let sandbox = read_measured_artifact(&config.sandbox_profile_path, MAX_BOOTSTRAP_BYTES_V2)?;
        if !is_trusted_executable(&executable.metadata)
            || !is_trusted_bootstrap(&daemon_config.metadata)
            || !is_trusted_static_artifact(&sandbox.metadata)
        {
            return Err(DeploymentTrustErrorV2::UnsafeFilesystem);
        }
        let endpoint = observe_endpoint(
            service,
            config.process_uid,
            config.process_gid,
            &config.endpoint,
        )?;
        if endpoint.owner_uid != config.process_uid {
            return Err(DeploymentTrustErrorV2::UnsafeSocket);
        }
        let keystore = Digest32V2::new(decode_hex_32_v2(&config.keystore_authority_identity)?);
        let rollback = Digest32V2::new(decode_hex_32_v2(&config.rollback_authority_identity)?);
        let lock = ServiceDeploymentLockV2 {
            service,
            service_identity: ServiceIdentityV2::new(decode_hex_32_v2(&config.service_identity)?),
            uid: config.process_uid,
            gid: config.process_gid,
            executable_digest: executable.digest,
            config_digest: daemon_config.digest,
            config_path_digest: path_digest(CONFIG_PATH_DOMAIN_V2, &config.config_path)?,
            socket_path_digest: endpoint.identity_digest,
            socket_uid: endpoint.owner_uid,
            socket_gid: endpoint.group_gid,
            socket_mode: endpoint.mode,
            code_identity_digest: executable.digest,
            sandbox_profile_digest: sandbox.digest,
            keystore_authority_identity: keystore,
            rollback_authority_identity: rollback,
        };
        observations.push(PlatformServiceObservationV2 {
            lock,
            executable_is_regular_single_link: executable.regular_single_link,
            config_is_regular_single_link: daemon_config.regular_single_link,
            executable_parent_root_owned_not_writable: executable.parent_trusted,
            config_parent_root_owned_not_writable: daemon_config.parent_trusted,
            endpoint_identity_is_verified: true,
        });
        authorities.push(ServiceAuthorityHandlesV2 {
            service,
            keystore_authority_identity: keystore,
            rollback_authority_identity: rollback,
        });
    }
    let effect_projection = read_verified_regular_file_v2(
        effect_ledger_projection_path,
        MAX_PROJECTION_BYTES_V2,
        None,
    )?;
    let mut platform = FilesystemDeploymentTrustV2 {
        observations,
        authorities,
        effect_projection,
    };
    VerifiedDaemonStartupV2::verify(manifest, &mut platform)
}

pub fn read_verified_regular_file_v2(
    path: &Path,
    maximum: usize,
    exact_identity: Option<(u32, u32, u32)>,
) -> Result<Vec<u8>, DeploymentTrustErrorV2> {
    if !path.is_absolute() {
        return Err(DeploymentTrustErrorV2::UnsafeFilesystem);
    }
    let before =
        fs::symlink_metadata(path).map_err(|_| DeploymentTrustErrorV2::UnsafeFilesystem)?;
    if before.file_type().is_symlink()
        || !before.is_file()
        || before.nlink() != 1
        || usize::try_from(before.len()).is_err()
        || usize::try_from(before.len()).unwrap_or(usize::MAX) > maximum
    {
        return Err(DeploymentTrustErrorV2::UnsafeFilesystem);
    }
    if let Some((uid, gid, mode)) = exact_identity {
        if before.uid() != uid || before.gid() != gid || before.mode() & 0o7777 != mode {
            return Err(DeploymentTrustErrorV2::UnsafeFilesystem);
        }
    }
    let bytes = fs::read(path).map_err(|_| DeploymentTrustErrorV2::UnsafeFilesystem)?;
    let after = fs::symlink_metadata(path).map_err(|_| DeploymentTrustErrorV2::UnsafeFilesystem)?;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || bytes.len() > maximum
    {
        return Err(DeploymentTrustErrorV2::UnsafeFilesystem);
    }
    Ok(bytes)
}

pub fn decode_hex_32_v2(value: &str) -> Result<[u8; 32], DeploymentTrustErrorV2> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(DeploymentTrustErrorV2::NonCanonicalManifest);
    }
    let mut decoded = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        decoded[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Ok(decoded)
}

struct MeasuredArtifactV2 {
    metadata: fs::Metadata,
    digest: Digest32V2,
    regular_single_link: bool,
    parent_trusted: bool,
}

fn read_measured_artifact(
    path: &Path,
    maximum: usize,
) -> Result<MeasuredArtifactV2, DeploymentTrustErrorV2> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| DeploymentTrustErrorV2::UnsafeFilesystem)?;
    let regular_single_link =
        !metadata.file_type().is_symlink() && metadata.is_file() && metadata.nlink() == 1;
    if !regular_single_link {
        return Err(DeploymentTrustErrorV2::UnsafeFilesystem);
    }
    let bytes = read_verified_regular_file_v2(path, maximum, None)?;
    let parent = path
        .parent()
        .ok_or(DeploymentTrustErrorV2::UnsafeFilesystem)?;
    let parent_metadata =
        fs::symlink_metadata(parent).map_err(|_| DeploymentTrustErrorV2::UnsafeFilesystem)?;
    let parent_trusted = !parent_metadata.file_type().is_symlink()
        && parent_metadata.is_dir()
        && parent_metadata.uid() == 0
        && parent_metadata.mode() & 0o022 == 0;
    Ok(MeasuredArtifactV2 {
        metadata,
        digest: Digest32V2::new(Sha256::digest(&bytes).into()),
        regular_single_link,
        parent_trusted,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ObservedEndpointV2 {
    identity_digest: Digest32V2,
    owner_uid: u32,
    group_gid: u32,
    mode: u32,
}

fn observe_endpoint(
    service: ClosedServiceIdV2,
    process_uid: u32,
    process_gid: u32,
    endpoint: &FilesystemServiceEndpointConfigV2,
) -> Result<ObservedEndpointV2, DeploymentTrustErrorV2> {
    match endpoint {
        FilesystemServiceEndpointConfigV2::UnixSocket { path } => {
            let socket =
                fs::symlink_metadata(path).map_err(|_| DeploymentTrustErrorV2::UnsafeSocket)?;
            if socket.file_type().is_symlink()
                || !socket.file_type().is_socket()
                || socket.mode() & 0o7777 != 0o660
                || socket.uid() != process_uid
                || socket.gid() == 0
            {
                return Err(DeploymentTrustErrorV2::UnsafeSocket);
            }
            Ok(ObservedEndpointV2 {
                identity_digest: path_digest(SOCKET_PATH_DOMAIN_V2, path)?,
                owner_uid: socket.uid(),
                group_gid: socket.gid(),
                mode: socket.mode() & 0o7777,
            })
        }
        FilesystemServiceEndpointConfigV2::LoopbackTcp { port } => {
            let expected_port = match service {
                ClosedServiceIdV2::Agentd => 8765,
                ClosedServiceIdV2::Ingressd => 8767,
                ClosedServiceIdV2::Approvald => 8766,
                ClosedServiceIdV2::Kerneld | ClosedServiceIdV2::Execd => {
                    return Err(DeploymentTrustErrorV2::UnsafeSocket);
                }
            };
            if *port != expected_port {
                return Err(DeploymentTrustErrorV2::UnsafeSocket);
            }
            let identity = format!("tcp://127.0.0.1:{port}");
            Ok(ObservedEndpointV2 {
                identity_digest: text_identity_digest(SOCKET_PATH_DOMAIN_V2, &identity)?,
                owner_uid: process_uid,
                group_gid: process_gid,
                mode: 0,
            })
        }
    }
}

fn is_trusted_executable(metadata: &fs::Metadata) -> bool {
    metadata.uid() == 0
        && metadata.gid() == 0
        && metadata.mode() & 0o022 == 0
        && metadata.mode() & 0o6000 == 0
        && metadata.mode() & 0o111 != 0
}

fn is_trusted_bootstrap(metadata: &fs::Metadata) -> bool {
    metadata.uid() == 0 && metadata.gid() == 0 && metadata.mode() & 0o7777 == 0o444
}

fn is_trusted_static_artifact(metadata: &fs::Metadata) -> bool {
    metadata.uid() == 0
        && metadata.gid() == 0
        && metadata.mode() & 0o022 == 0
        && metadata.mode() & 0o6000 == 0
}

fn parse_service_id(value: &str) -> Result<ClosedServiceIdV2, DeploymentTrustErrorV2> {
    match value {
        "kerneld" => Ok(ClosedServiceIdV2::Kerneld),
        "agentd" => Ok(ClosedServiceIdV2::Agentd),
        "ingressd" => Ok(ClosedServiceIdV2::Ingressd),
        "approvald" => Ok(ClosedServiceIdV2::Approvald),
        "execd" => Ok(ClosedServiceIdV2::Execd),
        _ => Err(DeploymentTrustErrorV2::IncompleteManifest),
    }
}

fn path_digest(domain: &[u8], path: &Path) -> Result<Digest32V2, DeploymentTrustErrorV2> {
    let value = path
        .to_str()
        .ok_or(DeploymentTrustErrorV2::UnsafeFilesystem)?;
    if !path.is_absolute() || value.is_empty() || value.len() > 4096 {
        return Err(DeploymentTrustErrorV2::UnsafeFilesystem);
    }
    text_identity_digest(domain, value)
}

fn text_identity_digest(domain: &[u8], value: &str) -> Result<Digest32V2, DeploymentTrustErrorV2> {
    let length =
        u32::try_from(value.len()).map_err(|_| DeploymentTrustErrorV2::UnsafeFilesystem)?;
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(length.to_be_bytes());
    hasher.update(value.as_bytes());
    Ok(Digest32V2::new(hasher.finalize().into()))
}

fn hex_nibble(value: u8) -> Result<u8, DeploymentTrustErrorV2> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(DeploymentTrustErrorV2::NonCanonicalManifest),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        observe_endpoint, ClosedServiceIdV2, DeploymentTrustErrorV2,
        FilesystemServiceEndpointConfigV2,
    };

    #[test]
    fn loopback_endpoint_is_closed_to_the_compiled_service_port() {
        let endpoint = FilesystemServiceEndpointConfigV2::LoopbackTcp { port: 8767 };
        let observed = observe_endpoint(ClosedServiceIdV2::Ingressd, 701, 702, &endpoint).unwrap();
        assert_eq!(observed.owner_uid, 701);
        assert_eq!(observed.group_gid, 702);
        assert_eq!(observed.mode, 0);
        assert_ne!(observed.identity_digest.as_bytes(), &[0; 32]);

        assert_eq!(
            observe_endpoint(
                ClosedServiceIdV2::Ingressd,
                701,
                702,
                &FilesystemServiceEndpointConfigV2::LoopbackTcp { port: 8768 }
            ),
            Err(DeploymentTrustErrorV2::UnsafeSocket)
        );
        assert_eq!(
            observe_endpoint(ClosedServiceIdV2::Kerneld, 701, 702, &endpoint),
            Err(DeploymentTrustErrorV2::UnsafeSocket)
        );
    }

    #[test]
    fn service_observation_requires_process_identity_and_a_closed_endpoint() {
        let valid = r#"{
            "service":"ingressd",
            "service_identity":"1111111111111111111111111111111111111111111111111111111111111111",
            "process_uid":701,
            "process_gid":702,
            "executable_path":"/usr/libexec/savana/savana-ingressd",
            "config_path":"/etc/savana/ingressd-bootstrap-v2.json",
            "endpoint":{"kind":"loopback-tcp","port":8767},
            "sandbox_profile_path":"/etc/savana/sandbox/ingressd-v2.profile",
            "keystore_authority_identity":"2222222222222222222222222222222222222222222222222222222222222222",
            "rollback_authority_identity":"3333333333333333333333333333333333333333333333333333333333333333"
        }"#;
        let decoded: super::FilesystemServiceObservationConfigV2 =
            serde_json::from_str(valid).unwrap();
        assert_eq!(decoded.process_uid, 701);
        assert_eq!(decoded.process_gid, 702);

        let legacy = valid
            .replace("\"process_uid\":701,", "")
            .replace("\"process_gid\":702,", "");
        assert!(
            serde_json::from_str::<super::FilesystemServiceObservationConfigV2>(&legacy).is_err()
        );
        let caller_selected = valid.replace(
            r#""kind":"loopback-tcp","port":8767"#,
            r#""kind":"caller-selected","port":8767"#,
        );
        assert!(
            serde_json::from_str::<super::FilesystemServiceObservationConfigV2>(&caller_selected)
                .is_err()
        );
    }
}
