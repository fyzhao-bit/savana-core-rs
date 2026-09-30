//! Measured, non-root Linux task-entry client. No interpreter is trusted as
//! this peer. This does not register credentials, issue roots or execute tools.
#![forbid(unsafe_code)]

use savana_kernel_protocol::v2::*;
use std::io::{Read, Write};

const MAX_FRAME: usize = 1024 * 1024;
type Result<T> = std::result::Result<T, &'static str>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Command {
    Health,
    Prepare,
}

struct ResponseBinding {
    request: RequestIdV2,
    boot: BootIdV2,
    identity: ServiceIdentityV2,
    manifest: Digest32V2,
    generation: u64,
}

fn command(value: &str) -> Result<Command> {
    match value {
        "health" => Ok(Command::Health),
        "prepare-ingress" => Ok(Command::Prepare),
        _ => Err("ownerctl supports only health or prepare-ingress"),
    }
}

fn write_frame(stream: &mut impl Write, bytes: &[u8]) -> Result<()> {
    if bytes.is_empty() || bytes.len() > MAX_FRAME {
        return Err("ownerctl invalid request frame");
    }
    stream
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .and_then(|()| stream.write_all(bytes))
        .and_then(|()| stream.flush())
        .map_err(|_| "ownerctl request outcome unknown; do not automatically retry")
}

fn read_response(
    stream: &mut impl Read,
    expected: &ResponseBinding,
    operation: Command,
) -> Result<String> {
    let mut length = [0; 4];
    stream
        .read_exact(&mut length)
        .map_err(|_| "ownerctl response unavailable; outcome unknown")?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > MAX_FRAME {
        return Err("ownerctl response frame rejected");
    }
    let mut bytes = vec![0; length];
    stream
        .read_exact(&mut bytes)
        .map_err(|_| "ownerctl incomplete response; outcome unknown")?;
    let response = decode_agent_control_response_envelope_v2(&bytes)
        .map_err(|_| "ownerctl response rejected")?;
    let bound = AgentControlResponseEnvelopeV2::from_authenticated_connection(
        expected.request,
        expected.boot,
        expected.identity,
        expected.manifest,
        expected.generation,
        response.response(),
    )
    .map_err(|_| "ownerctl response binding rejected")?;
    if encode_agent_control_response_envelope_v2(&bound)
        .map_err(|_| "ownerctl response binding rejected")?
        != bytes
    {
        return Err("ownerctl response deployment or request identity mismatch");
    }
    match (operation, response.response()) {
        (Command::Health, AgentControlResponseV2::Health(value)) => {
            let state = match value.state() {
                PublicServiceStateV2::Starting => "starting",
                PublicServiceStateV2::Ready => "ready",
                PublicServiceStateV2::DegradedFailClosed => "degraded_fail_closed",
                PublicServiceStateV2::Fenced => "fenced",
            };
            Ok(serde_json::json!({"state": state}).to_string())
        }
        (Command::Prepare, AgentControlResponseV2::PrepareIngress(value)) => match value.bootstrap() {
            JarvisBootstrapActionV2::OpenIngress { url }
                if url.kind() == BootstrapKindV2::Ingress && url.origin() == FixedOriginV2::Jarvis8765 =>
                Ok(serde_json::json!({"bootstrap_url": url.to_string(), "authenticated": false, "task_authorized": false}).to_string()),
            _ => Err("ownerctl expected an Ingress bootstrap; no Agent fallback"),
        },
        (_, AgentControlResponseV2::Error(_)) => Err("ownerctl operation refused by kernel control"),
        _ => Err("ownerctl unexpected response operation"),
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

#[cfg(not(target_os = "linux"))]
fn run() -> Result<()> {
    Err("ownerctl requires the verified Linux deployment")
}

#[cfg(target_os = "linux")]
fn run() -> Result<()> {
    use savana_platform_identity::{NativePeerMeasurementV2, OwnerControlRendezvousV2};
    use savana_policy_core::v2::{
        decode_hex_32_v2, load_verified_filesystem_startup_v2, read_verified_regular_file_v2,
        ClosedServiceIdV2, FilesystemServiceObservationConfigV2,
    };
    use serde::Deserialize;
    use sha2::{Digest as _, Sha256};
    use std::os::unix::net::UnixStream;
    use std::path::{Path, PathBuf};
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    const CONFIG: &str = "/etc/savana/agentd-bootstrap-v2.json";
    const EXECUTABLE: &str = "/usr/libexec/savana/savana-ownerctl";
    const SOCKET: &str = "/run/savana/agentd/jarvis/control.sock";
    // A subset of the daemon's configuration; exact bytes are verified against
    // its signed manifest before ANY field below is used as authority.
    #[derive(Deserialize)]
    struct Config {
        signed_manifest_path: PathBuf,
        effect_ledger_projection_path: PathBuf,
        services: Vec<FilesystemServiceObservationConfigV2>,
        jarvis_control_identity: String,
        jarvis_expected_uid: u32,
        jarvis_expected_gid: u32,
        jarvis_executable_digest: String,
    }

    fn entropy<const N: usize>() -> Result<[u8; N]> {
        let mut bytes = [0; N];
        getrandom::getrandom(&mut bytes).map_err(|_| "ownerctl entropy unavailable")?;
        if bytes == [0; N] {
            return Err("ownerctl entropy rejected");
        }
        Ok(bytes)
    }
    fn boot(name: &str) -> Result<BootIdV2> {
        let bytes = savana_platform_identity::read_linux_service_credential_v2(
            savana_platform_identity::LinuxCredentialServiceV2::OwnerControl,
            name,
            32,
        )
        .map_err(|_| "ownerctl boot credential unavailable")?;
        let bytes: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| "ownerctl boot credential rejected")?;
        if bytes == [0; 32] {
            return Err("ownerctl boot credential rejected");
        }
        Ok(BootIdV2::new(bytes))
    }

    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 1 {
        return Err("usage: savana-ownerctl health | prepare-ingress");
    }
    let operation = command(&args[0])?;
    let config_bytes =
        read_verified_regular_file_v2(Path::new(CONFIG), 128 * 1024, Some((0, 0, 0o444)))
            .map_err(|_| "ownerctl trusted configuration unavailable")?;
    let config: Config =
        serde_json::from_slice(&config_bytes).map_err(|_| "ownerctl configuration rejected")?;
    let startup = load_verified_filesystem_startup_v2(
        Path::new("/etc/savana/trust/deployment-manifest-root-v2.json"),
        &config.signed_manifest_path,
        &config.effect_ledger_projection_path,
        &config.services,
    )
    .map_err(|_| "ownerctl deployment verification failed")?;
    startup
        .verify_loaded_service_config_v2(ClosedServiceIdV2::Agentd, &config_bytes)
        .map_err(|_| "ownerctl signed configuration mismatch")?;
    let uid = nix::unistd::geteuid().as_raw();
    let gid = nix::unistd::getegid().as_raw();
    if uid == 0 || uid != config.jarvis_expected_uid || gid != config.jarvis_expected_gid {
        return Err("ownerctl requires the dedicated unprivileged owner identity");
    }
    if std::fs::read_link("/proc/self/exe").map_err(|_| "ownerctl executable unavailable")?
        != Path::new(EXECUTABLE)
    {
        return Err("ownerctl must run from its fixed installed path");
    }
    let executable = read_verified_regular_file_v2(
        Path::new(EXECUTABLE),
        256 * 1024 * 1024,
        Some((0, 0, 0o755)),
    )
    .map_err(|_| "ownerctl trusted executable unavailable")?;
    let digest: [u8; 32] = Sha256::digest(&executable).into();
    if digest
        != decode_hex_32_v2(&config.jarvis_executable_digest)
            .map_err(|_| "ownerctl digest rejected")?
    {
        return Err("ownerctl executable is not enrolled in the signed deployment");
    }
    drop(executable);
    let server = startup
        .service_lock(ClosedServiceIdV2::Agentd)
        .ok_or("ownerctl agent service unavailable")?;
    let caller_identity = ServiceIdentityV2::new(
        decode_hex_32_v2(&config.jarvis_control_identity)
            .map_err(|_| "ownerctl caller identity rejected")?,
    );
    let caller_boot = boot("jarvis-boot-v2.id")?;
    let server_boot = boot("agentd-boot-v2.id")?;
    let rendezvous = OwnerControlRendezvousV2::bind(entropy()?)
        .map_err(|_| "ownerctl reverse listener unavailable")?;
    let mut initial =
        UnixStream::connect(SOCKET).map_err(|_| "ownerctl control socket unavailable")?;
    let timeout = Some(Duration::from_secs(10));
    initial
        .set_read_timeout(timeout)
        .and_then(|()| initial.set_write_timeout(timeout))
        .map_err(|_| "ownerctl deadline setup failed")?;
    // Keep the PIDFD/executable pin alive through the entire exchange. This is
    // independent of the reciprocal agentd check on the ownerctl process.
    let (mut stream, peer) = rendezvous
        .connect(&mut initial, Instant::now() + Duration::from_secs(10))
        .map_err(|_| "ownerctl measured reverse connection failed")?;
    drop(initial);
    if !matches!(peer.measurement(), NativePeerMeasurementV2::Linux { uid, gid, executable_measurement, .. }
        if *uid == server.uid && *gid == server.gid && executable_measurement == server.executable_digest.as_bytes())
    {
        return Err("ownerctl server identity mismatch");
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "ownerctl clock unavailable")?
        .as_millis();
    let deadline = u64::try_from(now)
        .ok()
        .and_then(|n| n.checked_add(10_000))
        .ok_or("ownerctl deadline overflow")?;
    let request_id = RequestIdV2::new(entropy()?);
    let request = AgentControlRequestEnvelopeV2::from_authenticated_connection(
        request_id,
        caller_boot,
        server_boot,
        caller_identity,
        server.service_identity,
        startup.active_state_manifest_digest(),
        startup.deployment_generation(),
        UnixMillisV2::new(deadline),
        match operation {
            Command::Health => AgentControlOperationV2::Health,
            Command::Prepare => AgentControlOperationV2::PrepareIngress(
                PrepareIngressRequestV2::new(Nonce32V2::new(entropy()?)),
            ),
        },
    )
    .map_err(|_| "ownerctl request rejected")?;
    let payload = encode_agent_control_request_envelope_v2(&request)
        .map_err(|_| "ownerctl encoding failed")?;
    write_frame(&mut stream, &payload)?;
    let output = read_response(
        &mut stream,
        &ResponseBinding {
            request: request_id,
            boot: server_boot,
            identity: server.service_identity,
            manifest: startup.active_state_manifest_digest(),
            generation: startup.deployment_generation(),
        },
        operation,
    )?;
    // Caller must use a private pipe, not journal output; the URL is one-use.
    println!("{output}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn binding() -> ResponseBinding {
        ResponseBinding {
            request: RequestIdV2::new([1; 16]),
            boot: BootIdV2::new([2; 32]),
            identity: ServiceIdentityV2::new([3; 32]),
            manifest: Digest32V2::new([4; 32]),
            generation: 1,
        }
    }

    fn frame(binding: &ResponseBinding, response: AgentControlResponseV2) -> Vec<u8> {
        let envelope = AgentControlResponseEnvelopeV2::from_authenticated_connection(
            binding.request,
            binding.boot,
            binding.identity,
            binding.manifest,
            binding.generation,
            response,
        )
        .unwrap();
        let bytes = encode_agent_control_response_envelope_v2(&envelope).unwrap();
        let mut frame = Vec::new();
        write_frame(&mut frame, &bytes).unwrap();
        frame
    }

    #[test]
    fn responses_bind_request_boot_identity_manifest_and_generation() {
        let value = AgentControlResponseV2::health(PublicServiceStateV2::Ready);
        assert_eq!(
            read_response(
                &mut Cursor::new(frame(&binding(), value)),
                &binding(),
                Command::Health
            )
            .unwrap(),
            "{\"state\":\"ready\"}"
        );
        for field in 0..5 {
            let mut wrong = binding();
            match field {
                0 => wrong.request = RequestIdV2::new([9; 16]),
                1 => wrong.boot = BootIdV2::new([9; 32]),
                2 => wrong.identity = ServiceIdentityV2::new([9; 32]),
                3 => wrong.manifest = Digest32V2::new([9; 32]),
                _ => wrong.generation = 2,
            }
            assert!(read_response(
                &mut Cursor::new(frame(&wrong, value)),
                &binding(),
                Command::Health
            )
            .is_err());
        }
        assert!(read_response(
            &mut Cursor::new(frame(&binding(), value)),
            &binding(),
            Command::Prepare
        )
        .is_err());
    }

    #[test]
    fn closed_command_surface_has_no_status_execute_enroll_or_arbitrary_requests() {
        assert_eq!(command("health"), Ok(Command::Health));
        assert_eq!(command("prepare-ingress"), Ok(Command::Prepare));
        for value in [
            "",
            "enroll",
            "task-status",
            "execute",
            "approve",
            "--socket",
            "prepare-ingress extra",
        ] {
            assert!(command(value).is_err());
        }
    }

    #[test]
    fn prepare_exports_only_the_ingress_url_not_task_authority() {
        let url = JarvisBootstrapUrlV2::from_agentd_selector(
            BootstrapKindV2::Ingress,
            JarvisBootstrapSelectorV2::from_authority_entropy([6; 32]).unwrap(),
        );
        let response = AgentControlResponseV2::prepare_ingress(PrepareIngressResponseV2::new(
            TaskHandleV2::from_authority_entropy([7; 32]).unwrap(),
            JarvisBootstrapActionV2::OpenIngress { url },
        ));
        let output = read_response(
            &mut Cursor::new(frame(&binding(), response)),
            &binding(),
            Command::Prepare,
        )
        .unwrap();
        let json: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert_eq!(json["bootstrap_url"], url.to_string());
        assert_eq!(json["authenticated"], false);
        assert_eq!(json["task_authorized"], false);
        assert_eq!(json.as_object().unwrap().len(), 3);
        assert!(read_response(
            &mut Cursor::new(frame(&binding(), response)),
            &binding(),
            Command::Health
        )
        .is_err());
    }

    #[test]
    fn framing_is_bounded_and_incomplete_or_unrelated_responses_fail_closed() {
        let expected = binding();
        for frame in [
            vec![],
            vec![0; 4],
            ((MAX_FRAME + 1) as u32).to_be_bytes().to_vec(),
            vec![0, 0, 0, 2, 0x80],
        ] {
            assert!(read_response(&mut Cursor::new(frame), &expected, Command::Health).is_err());
        }
        let mut out = Vec::new();
        assert!(write_frame(&mut out, &[]).is_err());
        assert!(write_frame(&mut out, &vec![0; MAX_FRAME + 1]).is_err());
        assert!(out.is_empty());
        write_frame(&mut out, &[1, 2]).unwrap();
        assert_eq!(out, vec![0, 0, 0, 2, 1, 2]);
    }
}
