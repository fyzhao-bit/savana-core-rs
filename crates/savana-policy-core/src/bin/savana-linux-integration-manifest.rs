//! Offline authoring for the explicitly file-backed Linux integration profile.
//! Does not provision accounts, mint roots for tasks, or claim hardware trust.
#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path};

use ed25519_dalek::{Signer, SigningKey};
use savana_kernel_protocol::v2::{derive_ed25519_key_id_v2, EndpointRoleV2};
use savana_policy_core::v2::{
    listener_identity_digest_v2, load_verified_filesystem_startup_v2,
    FilesystemServiceEndpointConfigV2, FilesystemServiceObservationConfigV2,
    VerifiedDeploymentManifestV2,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const CONFIG: &str = "/etc/savana";
const SERVICES: [&str; 5] = ["kerneld", "agentd", "ingressd", "approvald", "execd"];
const ACCOUNTS: [&str; 5] = [
    "savana-kernel",
    "savana-agent",
    "savana-ingress",
    "savana-approval",
    "savana-exec",
];
const SOCKETS: [&str; 3] = [
    "/run/savana/kerneld/agentd/kerneld.sock",
    "/run/savana/kerneld/ingressd/kerneld.sock",
    "/run/savana/execd/kerneld/execd.sock",
];
const SIGNATURE_DOMAIN: &[u8] = b"SAVANA_DEPLOYMENT_MANIFEST_SIGNATURE_V2\0";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Template {
    installation_id: String,
    active_state_manifest_digest: String,
    declassification_rule_set_digest: String,
    active_state_manifest_sequence: u64,
    deployment_generation: u64,
    effect_fence_epoch: u64,
    protocol_abi_digest: String,
    release_identity_digest: String,
    model_set_identity_digest: String,
    resource_profile_identity_digest: String,
    approval_lock_identity_digest: String,
    planner_lock_identity_digest: String,
    executor_key_lock_identity_digest: String,
    kernel_envelope_signing_key_id: String,
    ledger_projection_identity: String,
    effect_ledger_head_digest: String,
    ledger_projection_signing_key_id: String,
    ledger_projection_signing_public_key: String,
    /// Each pair is [client key id, server key id], in closed edge order.
    edge_keys: [[String; 2]; 3],
}

struct Measurement {
    observation: FilesystemServiceObservationConfigV2,
    executable: [u8; 32],
    config: [u8; 32],
    sandbox: [u8; 32],
    socket_path: [u8; 32],
    socket_gid: u32,
    socket_mode: u32,
}

fn main() {
    if !cfg!(all(target_os = "linux", debug_assertions)) {
        eprintln!("Linux debug integration authoring only; no production authority");
        std::process::exit(69);
    }
    if let Err(error) = run() {
        eprintln!("integration manifest rejected: {error}");
        std::process::exit(70);
    }
}

fn run() -> Result<(), String> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() == 1 && args[0] == "--check-startup" {
        let bytes = read_artifact(
            Path::new("/etc/savana/kerneld-bootstrap-v2.json"),
            131072,
            Kind::Config,
        )?;
        let config: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|_| "invalid kernel bootstrap")?;
        let services: Vec<FilesystemServiceObservationConfigV2> = serde_json::from_value(
            config
                .get("services")
                .ok_or("missing observations")?
                .clone(),
        )
        .map_err(|_| "invalid observations")?;
        // This is the actual debug integration startup verifier, including
        // signed effect-ledger binding. Merely signing a manifest isn't ready.
        load_verified_filesystem_startup_v2(
            Path::new("/etc/savana/trust/deployment-manifest-root-v2.json"),
            Path::new("/etc/savana/deployment-manifest-v2.cbor"),
            Path::new("/etc/savana/effect-ledger-projection-v2.cbor"),
            &services,
        )
        .map_err(|e| format!("integration startup not ready: {e}"))?;
        println!("File-backed startup measurements verified; live services and user authentication still require separate checks.");
        return Ok(());
    }
    if args.len() != 2 || args[0] != "--file-backed-integration" {
        return Err("usage: savana-linux-integration-manifest --file-backed-integration <absolute-seed-path>".into());
    }
    if !nix::unistd::Uid::effective().is_root() {
        return Err("root-owned installation required".into());
    }
    let template: Template = serde_json::from_slice(&read_artifact(
        Path::new("/etc/savana/integration-manifest-input.json"),
        131072,
        Kind::Config,
    )?)
    .map_err(|_| "invalid manifest input")?;
    let seed_bytes = Zeroizing::new(read_artifact(Path::new(&args[1]), 32, Kind::Seed)?);
    let seed = Zeroizing::new(
        <[u8; 32]>::try_from(seed_bytes.as_slice()).map_err(|_| "seed must contain 32 bytes")?,
    );
    if *seed == [0; 32] {
        return Err("zero seed".into());
    }
    let measured = measure()?;
    let (signed, public_key) = sign(&template, &measured, &seed)?;
    // Verify both outputs before creating either. No existing state is replaced.
    let root_path = Path::new("/etc/savana/trust/deployment-manifest-root-v2.json");
    let manifest_path = Path::new("/etc/savana/deployment-manifest-v2.cbor");
    for path in [root_path, manifest_path] {
        trusted_parent(path)?;
        match fs::symlink_metadata(path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            _ => return Err("output already exists or cannot be inspected".into()),
        }
    }
    let root = serde_json::to_vec(&serde_json::json!({
        "key_id": hex(derive_ed25519_key_id_v2(public_key).as_bytes()),
        "public_key": hex(&public_key),
    }))
    .map_err(|_| "root encoding failed")?;
    write_new(root_path, &root)?;
    write_new(manifest_path, &signed)?;
    println!("Signed Linux integration measurements. File-backed keys; NOT production or hardware acceptance.");
    Ok(())
}

#[derive(Clone, Copy)]
enum Kind {
    Config,
    Executable,
    Static,
    Seed,
}

fn trusted_parent(path: &Path) -> Result<(), String> {
    if !path.is_absolute()
        || path
            .components()
            .any(|c| !matches!(c, Component::RootDir | Component::Normal(_)))
    {
        return Err("noncanonical absolute path".into());
    }
    for parent in path.parent().ok_or("missing parent")?.ancestors() {
        let m = fs::symlink_metadata(parent).map_err(|_| "missing parent")?;
        if !m.is_dir() || m.file_type().is_symlink() || m.uid() != 0 || m.mode() & 0o022 != 0 {
            return Err("untrusted parent directory".into());
        }
    }
    Ok(())
}

fn read_artifact(path: &Path, max: usize, kind: Kind) -> Result<Vec<u8>, String> {
    trusted_parent(path)?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| "cannot open artifact")?;
    let before = file.metadata().map_err(|_| "cannot inspect artifact")?;
    let mode = before.mode() & 0o7777;
    let valid_mode = match kind {
        Kind::Config => mode == 0o444,
        Kind::Seed => mode == 0o600,
        Kind::Executable => mode & 0o6022 == 0 && mode & 0o111 != 0,
        Kind::Static => mode & 0o6022 == 0,
    };
    if !before.is_file()
        || before.nlink() != 1
        || before.uid() != 0
        || before.gid() != 0
        || !valid_mode
        || before.len() > max as u64
    {
        return Err("unsafe artifact ownership, type, size or mode".into());
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(max as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "artifact read failed")?;
    let after = file.metadata().map_err(|_| "artifact disappeared")?;
    if bytes.len() > max
        || before.len() != bytes.len() as u64
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
    {
        return Err("artifact changed while measuring".into());
    }
    Ok(bytes)
}

fn measure() -> Result<Vec<Measurement>, String> {
    let mut output = Vec::new();
    let mut canonical_observations = None;
    let mut uids = BTreeSet::new();
    let mut gids = BTreeSet::new();
    for (index, name) in SERVICES.iter().enumerate() {
        let path = format!("{CONFIG}/{name}-bootstrap-v2.json");
        let bytes = read_artifact(Path::new(&path), 131072, Kind::Config)?;
        let config: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|_| "invalid bootstrap")?;
        let observations = config
            .get("services")
            .ok_or("missing service observations")?
            .clone();
        if canonical_observations
            .as_ref()
            .is_some_and(|v| v != &observations)
        {
            return Err("service observations differ between bootstraps".into());
        }
        canonical_observations = Some(observations.clone());
        let observations: Vec<FilesystemServiceObservationConfigV2> =
            serde_json::from_value(observations).map_err(|_| "invalid service observations")?;
        if observations.len() != 5
            || observations
                .iter()
                .zip(SERVICES)
                .any(|(v, name)| v.service != name)
        {
            return Err("service list is not the closed ordered set".into());
        }
        let obs = observations
            .into_iter()
            .nth(index)
            .ok_or("missing observation")?;
        let user = nix::unistd::User::from_name(ACCOUNTS[index])
            .map_err(|_| "account lookup failed")?
            .ok_or("missing service account")?;
        if obs.process_uid == 0
            || obs.process_gid == 0
            || obs.process_uid != user.uid.as_raw()
            || obs.process_gid != user.gid.as_raw()
            || !uids.insert(obs.process_uid)
            || !gids.insert(obs.process_gid)
        {
            return Err("service accounts must match distinct non-root identities".into());
        }
        if obs.config_path != Path::new(&path)
            || obs.executable_path != Path::new(&format!("/usr/libexec/savana/savana-{name}"))
            || obs.sandbox_profile_path
                != Path::new(&format!("/usr/lib/systemd/system/savana-{name}.service"))
        {
            return Err("unexpected installed service path".into());
        }
        let (socket_path, socket_gid, socket_mode) = match (&obs.endpoint, index) {
            (FilesystemServiceEndpointConfigV2::LoopbackTcp { port }, 2 | 3)
                if *port == if index == 2 { 8767 } else { 8766 } =>
            {
                (
                    text_digest(
                        b"SAVANA_SOCKET_PATH_IDENTITY_V2\0",
                        &format!("tcp://127.0.0.1:{port}"),
                    ),
                    obs.process_gid,
                    0,
                )
            }
            (FilesystemServiceEndpointConfigV2::UnixSocket { path }, 0 | 1 | 4) => {
                let expected = match index {
                    0 => SOCKETS[0],
                    1 => "/run/savana/agentd/jarvis/control.sock",
                    _ => SOCKETS[2],
                };
                if path != Path::new(expected) {
                    return Err("unexpected socket path".into());
                }
                let m = socket_metadata(path, obs.process_uid)?;
                (
                    text_digest(b"SAVANA_SOCKET_PATH_IDENTITY_V2\0", expected),
                    m.gid(),
                    0o660,
                )
            }
            _ => return Err("unexpected endpoint".into()),
        };
        let executable = Sha256::digest(read_artifact(
            &obs.executable_path,
            256 * 1024 * 1024,
            Kind::Executable,
        )?)
        .into();
        let sandbox = Sha256::digest(read_artifact(
            &obs.sandbox_profile_path,
            131072,
            Kind::Static,
        )?)
        .into();
        output.push(Measurement {
            observation: obs,
            executable,
            config: Sha256::digest(&bytes).into(),
            sandbox,
            socket_path,
            socket_gid,
            socket_mode,
        });
    }
    Ok(output)
}

fn socket_metadata(path: &Path, uid: u32) -> Result<fs::Metadata, String> {
    use std::os::unix::fs::FileTypeExt;
    // Runtime parents belong to the dedicated service; the signed pathname,
    // actual socket uid/gid/mode and inherited FD are rechecked by startup.
    for parent in path.parent().ok_or("missing socket parent")?.ancestors() {
        let m = fs::symlink_metadata(parent).map_err(|_| "missing socket directory")?;
        if !m.is_dir()
            || m.file_type().is_symlink()
            || ![0, uid].contains(&m.uid())
            || m.mode() & 0o022 != 0
        {
            return Err("unsafe socket parent directory".into());
        }
    }
    let m = fs::symlink_metadata(path).map_err(|_| "listener socket not materialized")?;
    if !m.file_type().is_socket() || m.uid() != uid || m.gid() == 0 || m.mode() & 0o7777 != 0o660 {
        return Err("invalid listener ownership or mode".into());
    }
    Ok(m)
}

fn sign(
    t: &Template,
    services: &[Measurement],
    seed: &[u8; 32],
) -> Result<(Vec<u8>, [u8; 32]), String> {
    let mut e = minicbor::Encoder::new(Vec::new());
    let encode =
        |_: minicbor::encode::Error<std::convert::Infallible>| "CBOR encoding failed".to_owned();
    e.array(21).and_then(|e| e.u16(2)).map_err(encode)?;
    for v in [
        &t.installation_id,
        &t.active_state_manifest_digest,
        &t.declassification_rule_set_digest,
    ] {
        e.bytes(&digest(v)?).map_err(encode)?;
    }
    for v in [
        t.active_state_manifest_sequence,
        t.deployment_generation,
        t.effect_fence_epoch,
    ] {
        e.u64(v).map_err(encode)?;
    }
    for v in [
        &t.protocol_abi_digest,
        &t.release_identity_digest,
        &t.model_set_identity_digest,
        &t.resource_profile_identity_digest,
        &t.approval_lock_identity_digest,
        &t.planner_lock_identity_digest,
        &t.executor_key_lock_identity_digest,
        &t.kernel_envelope_signing_key_id,
        &t.ledger_projection_identity,
        &t.effect_ledger_head_digest,
        &t.ledger_projection_signing_key_id,
        &t.ledger_projection_signing_public_key,
    ] {
        e.bytes(&digest(v)?).map_err(encode)?;
    }
    e.array(services.len() as u64).map_err(encode)?;
    for (index, s) in services.iter().enumerate() {
        let o = &s.observation;
        let identity = digest(&o.service_identity)?;
        e.array(15)
            .and_then(|e| e.u16(index as u16 + 1))
            .and_then(|e| e.bytes(&identity))
            .and_then(|e| e.u32(o.process_uid))
            .and_then(|e| e.u32(o.process_gid))
            .map_err(encode)?;
        for v in [
            s.executable,
            s.config,
            text_digest(
                b"SAVANA_CONFIG_PATH_IDENTITY_V2\0",
                o.config_path.to_str().ok_or("non-UTF8 path")?,
            ),
            s.socket_path,
        ] {
            e.bytes(&v).map_err(encode)?;
        }
        e.u32(o.process_uid)
            .and_then(|e| e.u32(s.socket_gid))
            .and_then(|e| e.u32(s.socket_mode))
            .map_err(encode)?;
        for v in [
            s.executable,
            s.sandbox,
            digest(&o.keystore_authority_identity)?,
            digest(&o.rollback_authority_identity)?,
        ] {
            e.bytes(&v).map_err(encode)?;
        }
    }
    e.array(3).map_err(encode)?;
    for (index, (client, server, role, role_name)) in [
        (1, 0, EndpointRoleV2::AgentKernel, "agent-kernel"),
        (2, 0, EndpointRoleV2::IngressKernel, "ingress-kernel"),
        (0, 4, EndpointRoleV2::KernelExecutor, "kernel-executor"),
    ]
    .into_iter()
    .enumerate()
    {
        let s = services.get(client).ok_or("missing client")?;
        let target = services.get(server).ok_or("missing server")?;
        let path = Path::new(SOCKETS[index]);
        let m = socket_metadata(path, target.observation.process_uid)?;
        if m.gid() != s.observation.process_gid {
            return Err("listener group does not identify the client role".into());
        }
        let listener = listener_identity_digest_v2(role, path, m.uid(), m.gid(), 0o660)
            .map_err(|_| "invalid listener identity")?;
        e.array(8)
            .and_then(|e| e.u16(index as u16 + 1))
            .and_then(|e| e.u16(client as u16 + 1))
            .and_then(|e| e.u16(server as u16 + 1))
            .and_then(|e| e.u16(role.tag()))
            .and_then(|e| e.bytes(listener.as_bytes()))
            .map_err(encode)?;
        for key in &t.edge_keys[index] {
            e.bytes(&digest(key)?).map_err(encode)?;
        }
        e.array(5)
            .and_then(|e| e.u16(1))
            .and_then(|e| e.str(role_name))
            .and_then(|e| e.u32(s.observation.process_uid))
            .and_then(|e| e.u32(s.observation.process_gid))
            .and_then(|e| e.bytes(&s.executable))
            .map_err(encode)?;
    }
    let payload = e.into_writer();
    let key = SigningKey::from_bytes(seed);
    let public = key.verifying_key().to_bytes();
    let id = derive_ed25519_key_id_v2(public);
    let signature = key
        .sign(&[SIGNATURE_DOMAIN, &Sha256::digest(&payload)].concat())
        .to_bytes();
    let mut e = minicbor::Encoder::new(Vec::new());
    e.array(3)
        .and_then(|e| e.bytes(&payload))
        .and_then(|e| e.bytes(id.as_bytes()))
        .and_then(|e| e.bytes(&signature))
        .map_err(encode)?;
    let bytes = e.into_writer();
    VerifiedDeploymentManifestV2::verify(&bytes, id, public)
        .map_err(|_| "signed manifest failed independent runtime validation")?;
    Ok((bytes, public))
}

fn digest(value: &str) -> Result<[u8; 32], String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("digest must be 64 lowercase hex characters".into());
    }
    let mut result = [0; 32];
    for (i, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let nibble = |b: u8| if b <= b'9' { b - b'0' } else { b - b'a' + 10 };
        result[i] = nibble(pair[0]) * 16 + nibble(pair[1]);
    }
    if result == [0; 32] {
        return Err("zero digest".into());
    }
    Ok(result)
}

fn text_digest(domain: &[u8], value: &str) -> [u8; 32] {
    Sha256::digest(
        [
            domain,
            &(value.len() as u32).to_be_bytes(),
            value.as_bytes(),
        ]
        .concat(),
    )
    .into()
}
fn hex(value: &[u8]) -> String {
    value.iter().map(|v| format!("{v:02x}")).collect()
}
fn write_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o444)
        .open(path)
        .map_err(|_| "output exists or is unsafe")?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| "output write failed")?;
    // Installation normally runs with umask 0077. The runtime root contract
    // nevertheless requires exactly 0444, not the umask-masked 0400.
    file.set_permissions(fs::Permissions::from_mode(0o444))
        .and_then(|_| file.sync_all())
        .map_err(|_| "output mode update failed")?;
    fs::File::open(path.parent().ok_or("missing output parent")?)
        .and_then(|f| f.sync_all())
        .map_err(|_| "output directory sync failed".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn digest_is_strict_and_nonzero() {
        assert_eq!(digest(&"01".repeat(32)).unwrap(), [1; 32]);
        for v in [
            "00".repeat(32),
            "AA".repeat(32),
            "gg".repeat(32),
            "01".repeat(31),
        ] {
            assert!(digest(&v).is_err());
        }
    }
    #[test]
    fn pathname_hash_binds_domain_and_length() {
        let path = "/etc/savana/kerneld-bootstrap-v2.json";
        assert_ne!(
            text_digest(b"config\0", path),
            text_digest(b"socket\0", path)
        );
        assert_ne!(
            text_digest(b"config\0", path),
            Sha256::digest(path.as_bytes()).as_slice()
        );
    }
    #[test]
    fn output_never_overwrites() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("manifest");
        write_new(&path, b"first").unwrap();
        assert!(write_new(&path, b"replacement").is_err());
        assert_eq!(fs::read(path).unwrap(), b"first");
    }
    #[test]
    fn refuses_writable_or_relative_parent() {
        assert!(trusted_parent(Path::new("relative/seed")).is_err());
        assert!(trusted_parent(Path::new("/tmp/seed")).is_err());
        assert!(trusted_parent(Path::new("/etc/savana/../seed")).is_err());
    }
}
