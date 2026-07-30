#![forbid(unsafe_code)]

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("savana-approvalctl is available only on the verified Linux deployment");
    std::process::exit(78);
}

#[cfg(target_os = "linux")]
fn main() {
    if let Err(message) = linux::run() {
        eprintln!("{message}");
        std::process::exit(1);
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::fs;
    use std::os::unix::fs::MetadataExt as _;
    use std::os::unix::net::UnixStream;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use ed25519_dalek::SigningKey;
    use savana_approvald::ApprovalSuiteOneClientV2;
    use savana_kernel_protocol::v2::{
        derive_ed25519_key_id_v2, BootIdV2, ClosedCredentialRevocationReasonV2, Digest32V2,
        Ed25519KeyIdV2, EnrollmentProfileIdV2, Nonce32V2, PeerIdentityBindingV2, ServiceIdentityV2,
        UnixMillisV2,
    };
    use savana_platform_identity::{measure_linux_peer_v2, NativePeerMeasurementV2};
    use savana_policy_core::v2::{
        decode_hex_32_v2, load_verified_filesystem_startup_v2, read_verified_regular_file_v2,
        FilesystemServiceObservationConfigV2,
    };
    use serde::Deserialize;
    use zeroize::Zeroizing;

    const CONFIG_PATH: &str = "/etc/savana/approvalctl-bootstrap-v2.json";
    const MANIFEST_ROOT_PATH: &str = "/etc/savana/trust/deployment-manifest-root-v2.json";
    const SERVER_PUBLIC_KEY_PATH: &str = "/etc/savana/approvalctl/keys/approvald-admin-v2.pub";
    const CREDENTIAL_DIRECTORY: &str = "/run/credentials/savana-approvalctl.service";
    const CLIENT_SEED_CREDENTIAL: &str = "approval-admin-v2.seed";
    const CLIENT_BOOT_CREDENTIAL: &str = "approvalctl-boot-v2.id";
    const APPROVALD_BOOT_CREDENTIAL: &str = "approvald-boot-v2.id";
    const MAX_CONFIG_BYTES: usize = 128 * 1024;

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct BootstrapV2 {
        signed_manifest_path: PathBuf,
        effect_ledger_projection_path: PathBuf,
        services: Vec<FilesystemServiceObservationConfigV2>,
        client_identity: String,
        client_key_id: String,
        server_key_id: String,
    }

    pub(super) fn run() -> Result<(), &'static str> {
        if nix::unistd::geteuid().as_raw() != 0 || nix::unistd::getegid().as_raw() != 0 {
            return Err("approvalctl requires the root-only administration identity");
        }
        let config_bytes = read_verified_regular_file_v2(
            Path::new(CONFIG_PATH),
            MAX_CONFIG_BYTES,
            Some((0, 0, 0o444)),
        )
        .map_err(|_| "approvalctl deployment configuration is unavailable")?;
        let config: BootstrapV2 = serde_json::from_slice(&config_bytes)
            .map_err(|_| "approvalctl deployment configuration is invalid")?;
        let startup = load_verified_filesystem_startup_v2(
            Path::new(MANIFEST_ROOT_PATH),
            &config.signed_manifest_path,
            &config.effect_ledger_projection_path,
            &config.services,
        )
        .map_err(|_| "approvalctl deployment trust verification failed")?;
        let seed = Zeroizing::new(read_credential_32(CLIENT_SEED_CREDENTIAL)?);
        let signing = SigningKey::from_bytes(&seed);
        let client_key_id = Ed25519KeyIdV2::new(parse_hex_32(&config.client_key_id)?);
        let server_key_id = Ed25519KeyIdV2::new(parse_hex_32(&config.server_key_id)?);
        let server_public_key = read_public_key(Path::new(SERVER_PUBLIC_KEY_PATH))?;
        if derive_ed25519_key_id_v2(signing.verifying_key().to_bytes()) != client_key_id
            || derive_ed25519_key_id_v2(server_public_key) != server_key_id
        {
            return Err("approvalctl key identity does not match the deployment");
        }
        let edge = startup
            .approval_admin_handshake_edge(
                ServiceIdentityV2::new(parse_hex_32(&config.client_identity)?),
                client_key_id,
                server_key_id,
                BootIdV2::new(read_credential_32(APPROVALD_BOOT_CREDENTIAL)?),
            )
            .map_err(|_| "approvalctl administration edge is unavailable")?;
        let client = ApprovalSuiteOneClientV2::from_verified_deployment(
            edge,
            BootIdV2::new(read_credential_32(CLIENT_BOOT_CREDENTIAL)?),
            current_process_binding()?,
            signing,
            server_public_key,
        )
        .map_err(|_| "approvalctl secure client could not start")?;
        let deadline = deadline()?;
        let mut arguments = std::env::args_os();
        let _program = arguments.next();
        let command = arguments
            .next()
            .and_then(|value| value.into_string().ok())
            .ok_or("usage: savana-approvalctl health | create-enrollment PROFILE | revoke DIGEST REASON")?;
        match command.as_str() {
            "health" if arguments.next().is_none() => {
                let health = client
                    .health(deadline)
                    .map_err(|_| "approvald administration health failed")?;
                println!("state={:?}", health.state());
            }
            "create-enrollment" => {
                let profile = arguments
                    .next()
                    .and_then(|value| value.into_string().ok())
                    .ok_or("create-enrollment requires a numeric profile")?
                    .parse::<u32>()
                    .map_err(|_| "enrollment profile is invalid")?;
                if profile == 0 || arguments.next().is_some() {
                    return Err("enrollment profile is invalid");
                }
                let response = client
                    .create_enrollment_code(
                        EnrollmentProfileIdV2::new(profile),
                        Nonce32V2::new(random_nonzero()?),
                        deadline,
                    )
                    .map_err(|_| "enrollment code creation failed or is indeterminate")?;
                let (handle, code, expires_at) = response.into_parts();
                let handle = minicbor::to_vec(handle)
                    .map_err(|_| "enrollment handle encoding failed")?;
                println!("enrollment={}", URL_SAFE_NO_PAD.encode(handle));
                println!("code={}", code.as_str());
                println!("expires_at_unix_ms={}", expires_at.get());
                println!("browser=http://localhost:8766/v2/enrollment/bootstrap");
            }
            "revoke" => {
                let digest = arguments
                    .next()
                    .and_then(|value| value.into_string().ok())
                    .ok_or("revoke requires a credential digest")?;
                let reason = arguments
                    .next()
                    .and_then(|value| value.into_string().ok())
                    .ok_or("revoke requires compromised, replaced, or administrator")?;
                if arguments.next().is_some() {
                    return Err("revoke accepts exactly a digest and reason");
                }
                let reason = match reason.as_str() {
                    "compromised" => ClosedCredentialRevocationReasonV2::Compromised,
                    "replaced" => ClosedCredentialRevocationReasonV2::Replaced,
                    "administrator" => ClosedCredentialRevocationReasonV2::Administrator,
                    _ => return Err("credential revocation reason is invalid"),
                };
                let state = client
                    .revoke_credential(
                        Digest32V2::new(parse_hex_32(&digest)?),
                        reason,
                        deadline,
                    )
                    .map_err(|_| "credential revocation failed")?;
                println!("state={state:?}");
            }
            _ => {
                return Err(
                    "usage: savana-approvalctl health | create-enrollment PROFILE | revoke DIGEST REASON",
                )
            }
        }
        Ok(())
    }

    fn current_process_binding() -> Result<PeerIdentityBindingV2, &'static str> {
        let (left, right) = UnixStream::pair().map_err(|_| "peer measurement failed")?;
        let pinned = measure_linux_peer_v2(&left).map_err(|_| "peer measurement failed")?;
        drop(right);
        match pinned.measurement() {
            NativePeerMeasurementV2::Linux {
                uid,
                gid,
                pid,
                process_start_time,
                executable_measurement,
            } => PeerIdentityBindingV2::linux(
                *uid,
                *gid,
                *pid,
                *process_start_time,
                Digest32V2::new(*executable_measurement),
            )
            .map_err(|_| "peer measurement failed"),
            _ => Err("peer measurement failed"),
        }
    }

    fn read_public_key(path: &Path) -> Result<[u8; 32], &'static str> {
        read_verified_regular_file_v2(path, 32, Some((0, 0, 0o444)))
            .map_err(|_| "approvald public key is unavailable")?
            .try_into()
            .map_err(|_| "approvald public key is invalid")
    }

    fn read_credential_32(name: &str) -> Result<[u8; 32], &'static str> {
        if name.is_empty() || name.contains('/') {
            return Err("approvalctl credential name is invalid");
        }
        let directory = Path::new(CREDENTIAL_DIRECTORY);
        let metadata = fs::symlink_metadata(directory)
            .map_err(|_| "approvalctl credential directory is unavailable")?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || metadata.uid() != 0
            || metadata.mode() & 0o022 != 0
        {
            return Err("approvalctl credential directory is invalid");
        }
        read_verified_regular_file_v2(&directory.join(name), 32, Some((0, 0, 0o400)))
            .map_err(|_| "approvalctl credential is unavailable")?
            .try_into()
            .map_err(|_| "approvalctl credential is invalid")
    }

    fn parse_hex_32(value: &str) -> Result<[u8; 32], &'static str> {
        decode_hex_32_v2(value).map_err(|_| "hex identity is invalid")
    }

    fn deadline() -> Result<UnixMillisV2, &'static str> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "system clock is invalid")?;
        let now = u64::try_from(now.as_millis()).map_err(|_| "system clock is invalid")?;
        Ok(UnixMillisV2::new(
            now.checked_add(5_000).ok_or("system clock is invalid")?,
        ))
    }

    fn random_nonzero() -> Result<[u8; 32], &'static str> {
        for _ in 0..4 {
            let mut bytes = [0_u8; 32];
            getrandom::getrandom(&mut bytes).map_err(|_| "secure entropy is unavailable")?;
            if bytes != [0; 32] {
                return Ok(bytes);
            }
        }
        Err("secure entropy is unavailable")
    }
}
