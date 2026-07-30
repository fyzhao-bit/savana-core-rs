use std::path::{Path, PathBuf};

use serde::Deserialize;

const MAX_PROFILE_BYTES_V2: u64 = 64 * 1024;
const MAX_READ_ONLY_PATHS_V2: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum WorkerSandboxErrorV2 {
    #[error("the worker sandbox invocation is invalid")]
    InvalidInvocation,
    #[error("the measured worker sandbox profile is invalid")]
    InvalidProfile,
    #[error("the native worker sandbox is unavailable")]
    SandboxUnavailable,
    #[error("the worker could not be executed")]
    ExecutionFailed,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NetworkProfileV2 {
    version: u16,
    deny_all_network: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IsolationProfileV2 {
    version: u16,
    worker_program: PathBuf,
    read_only_paths: Vec<PathBuf>,
    memory_limit_bytes: u64,
    cpu_time_seconds: u64,
    output_file_limit_bytes: u64,
    open_file_limit: u64,
    process_limit: u64,
    deny_all_network: Option<bool>,
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
struct ValidatedIsolationProfileV2 {
    read_only_paths: Vec<PathBuf>,
    memory_limit_bytes: u64,
    cpu_time_seconds: u64,
    output_file_limit_bytes: u64,
    open_file_limit: u64,
    process_limit: u64,
}

/// Enters the measured one-job worker sandbox and replaces the current
/// process with the exact worker program. This function returns only on
/// failure.
pub fn run_worker_sandbox_v2(
    arguments: impl IntoIterator<Item = String>,
) -> Result<(), WorkerSandboxErrorV2> {
    let arguments = arguments.into_iter().collect::<Vec<_>>();
    let invocation = parse_invocation(&arguments)?;
    let isolation = read_isolation_profile(invocation.isolation_profile, invocation.worker)?;
    if let Some(network_profile) = invocation.network_profile {
        read_network_profile(network_profile)?;
    } else if isolation.deny_all_network != Some(true) {
        return Err(WorkerSandboxErrorV2::InvalidProfile);
    }
    let validated = validate_isolation_profile(isolation)?;
    platform_enter_and_exec(invocation.worker, invocation.worker_arguments, validated)
}

struct InvocationV2<'argument> {
    network_profile: Option<&'argument Path>,
    isolation_profile: &'argument Path,
    worker: &'argument Path,
    worker_arguments: &'argument [String],
}

fn parse_invocation(arguments: &[String]) -> Result<InvocationV2<'_>, WorkerSandboxErrorV2> {
    let separator = arguments
        .iter()
        .position(|argument| argument == "--")
        .ok_or(WorkerSandboxErrorV2::InvalidInvocation)?;
    if separator + 1 >= arguments.len() {
        return Err(WorkerSandboxErrorV2::InvalidInvocation);
    }
    let options = &arguments[..separator];
    let worker = Path::new(&arguments[separator + 1]);
    if !worker.is_absolute() {
        return Err(WorkerSandboxErrorV2::InvalidInvocation);
    }
    match options {
        [profile_flag, profile] if profile_flag == "--profile" => Ok(InvocationV2 {
            network_profile: None,
            isolation_profile: Path::new(profile),
            worker,
            worker_arguments: &arguments[separator + 2..],
        }),
        [network_flag, network, credential_flag, credential]
            if network_flag == "--no-network-profile"
                && credential_flag == "--credential-absence-profile" =>
        {
            Ok(InvocationV2 {
                network_profile: Some(Path::new(network)),
                isolation_profile: Path::new(credential),
                worker,
                worker_arguments: &arguments[separator + 2..],
            })
        }
        _ => Err(WorkerSandboxErrorV2::InvalidInvocation),
    }
}

fn read_network_profile(path: &Path) -> Result<(), WorkerSandboxErrorV2> {
    let profile: NetworkProfileV2 = read_profile(path)?;
    if profile.version != 2 || !profile.deny_all_network {
        return Err(WorkerSandboxErrorV2::InvalidProfile);
    }
    Ok(())
}

fn read_isolation_profile(
    path: &Path,
    worker: &Path,
) -> Result<IsolationProfileV2, WorkerSandboxErrorV2> {
    let profile: IsolationProfileV2 = read_profile(path)?;
    if profile.version != 2 || profile.worker_program != worker {
        return Err(WorkerSandboxErrorV2::InvalidProfile);
    }
    Ok(profile)
}

fn read_profile<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, WorkerSandboxErrorV2> {
    if !path.is_absolute() {
        return Err(WorkerSandboxErrorV2::InvalidProfile);
    }
    let file = std::fs::File::open(path).map_err(|_| WorkerSandboxErrorV2::InvalidProfile)?;
    let metadata = file
        .metadata()
        .map_err(|_| WorkerSandboxErrorV2::InvalidProfile)?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_PROFILE_BYTES_V2 {
        return Err(WorkerSandboxErrorV2::InvalidProfile);
    }
    serde_json::from_reader(file).map_err(|_| WorkerSandboxErrorV2::InvalidProfile)
}

fn validate_isolation_profile(
    profile: IsolationProfileV2,
) -> Result<ValidatedIsolationProfileV2, WorkerSandboxErrorV2> {
    if profile.read_only_paths.len() > MAX_READ_ONLY_PATHS_V2
        || profile.memory_limit_bytes < 16 * 1024 * 1024
        || profile.memory_limit_bytes > 4 * 1024 * 1024 * 1024
        || profile.cpu_time_seconds == 0
        || profile.cpu_time_seconds > 300
        || profile.output_file_limit_bytes > 16 * 1024 * 1024
        || profile.open_file_limit < 4
        || profile.open_file_limit > 64
        || profile.process_limit != 1
    {
        return Err(WorkerSandboxErrorV2::InvalidProfile);
    }
    let mut prior: Option<&Path> = None;
    for path in &profile.read_only_paths {
        if !path.is_absolute()
            || path == Path::new("/")
            || is_forbidden_read_path(path)
            || prior.is_some_and(|prior| prior.as_os_str() >= path.as_os_str())
        {
            return Err(WorkerSandboxErrorV2::InvalidProfile);
        }
        prior = Some(path);
    }
    Ok(ValidatedIsolationProfileV2 {
        read_only_paths: profile.read_only_paths,
        memory_limit_bytes: profile.memory_limit_bytes,
        cpu_time_seconds: profile.cpu_time_seconds,
        output_file_limit_bytes: profile.output_file_limit_bytes,
        open_file_limit: profile.open_file_limit,
        process_limit: profile.process_limit,
    })
}

fn is_forbidden_read_path(path: &Path) -> bool {
    [
        "/boot", "/dev", "/etc", "/home", "/proc", "/root", "/run", "/sys", "/tmp", "/var",
    ]
    .iter()
    .any(|prefix| path.starts_with(prefix))
}

#[cfg(target_os = "linux")]
fn platform_enter_and_exec(
    worker: &Path,
    worker_arguments: &[String],
    profile: ValidatedIsolationProfileV2,
) -> Result<(), WorkerSandboxErrorV2> {
    linux_worker_sandbox::enter_and_exec(worker, worker_arguments, profile)
}

#[cfg(target_os = "macos")]
fn platform_enter_and_exec(
    worker: &Path,
    worker_arguments: &[String],
    profile: ValidatedIsolationProfileV2,
) -> Result<(), WorkerSandboxErrorV2> {
    macos_worker_sandbox::enter_and_exec(worker, worker_arguments, profile)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn platform_enter_and_exec(
    _worker: &Path,
    _worker_arguments: &[String],
    _profile: ValidatedIsolationProfileV2,
) -> Result<(), WorkerSandboxErrorV2> {
    Err(WorkerSandboxErrorV2::SandboxUnavailable)
}

#[cfg(target_os = "linux")]
mod linux_worker_sandbox;
#[cfg(target_os = "macos")]
mod macos_worker_sandbox;

#[cfg(test)]
mod tests {
    use super::{parse_invocation, validate_isolation_profile, IsolationProfileV2};
    use std::path::PathBuf;

    #[test]
    fn invocation_accepts_only_the_two_closed_daemon_shapes() {
        let parser = vec![
            "--profile".to_owned(),
            "/profile".to_owned(),
            "--".to_owned(),
            "/worker".to_owned(),
        ];
        assert!(parse_invocation(&parser).is_ok());
        let connector = vec![
            "--no-network-profile".to_owned(),
            "/network".to_owned(),
            "--credential-absence-profile".to_owned(),
            "/credentials".to_owned(),
            "--".to_owned(),
            "/worker".to_owned(),
        ];
        assert!(parse_invocation(&connector).is_ok());
        let fallback = vec!["--".to_owned(), "/worker".to_owned()];
        assert!(parse_invocation(&fallback).is_err());
    }

    #[test]
    fn isolation_profile_rejects_secret_roots_and_unsafe_limits() {
        let profile = IsolationProfileV2 {
            version: 2,
            worker_program: PathBuf::from("/usr/libexec/savana/worker"),
            read_only_paths: vec![PathBuf::from("/etc/savana")],
            memory_limit_bytes: 64 * 1024 * 1024,
            cpu_time_seconds: 5,
            output_file_limit_bytes: 0,
            open_file_limit: 4,
            process_limit: 1,
            deny_all_network: Some(true),
        };
        assert!(validate_isolation_profile(profile).is_err());
    }

    #[test]
    fn isolation_profile_reserves_one_descriptor_for_dynamic_worker_startup() {
        let profile = IsolationProfileV2 {
            version: 2,
            worker_program: PathBuf::from("/usr/libexec/savana/worker"),
            read_only_paths: vec![],
            memory_limit_bytes: 64 * 1024 * 1024,
            cpu_time_seconds: 5,
            output_file_limit_bytes: 0,
            open_file_limit: 3,
            process_limit: 1,
            deny_all_network: Some(true),
        };
        assert!(validate_isolation_profile(profile).is_err());
    }
}
