#![cfg(target_os = "macos")]

use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};

#[test]
fn macos_worker_wrapper_enters_deny_default_profile_and_executes_exact_worker() {
    if !require_native_seatbelt_or_skip() {
        return;
    }
    let status = run_probe("ok", 64 * 1024 * 1024);
    assert!(status.success(), "sandbox wrapper exited {status}");
}

#[test]
fn macos_worker_wrapper_denies_unlisted_files() {
    if !require_native_seatbelt_or_skip() {
        return;
    }
    let status = run_probe("forbidden-file", 64 * 1024 * 1024);
    assert!(status.success(), "file-denial probe exited {status}");
}

#[test]
fn macos_worker_wrapper_denies_network_creation_and_use() {
    if !require_native_seatbelt_or_skip() {
        return;
    }
    let status = run_probe("forbidden-network", 64 * 1024 * 1024);
    assert!(status.success(), "network-denial probe exited {status}");
}

#[test]
fn macos_worker_wrapper_kills_a_worker_above_its_physical_footprint_limit() {
    if !require_native_seatbelt_or_skip() {
        return;
    }
    let status = run_probe("exceed-memory", 16 * 1024 * 1024);
    assert!(
        !status.success(),
        "over-limit worker unexpectedly succeeded"
    );
}

fn run_probe(command: &str, memory_limit_bytes: u64) -> ExitStatus {
    let worker = Path::new(env!("CARGO_BIN_EXE_savana-worker-sandbox-probe"));
    let directory = tempfile::tempdir().unwrap();
    let profile = directory.path().join("profile.json");
    let profile_bytes = serde_json::to_vec_pretty(&serde_json::json!({
        "version": 2,
        "worker_program": worker,
        "read_only_paths": [],
        "memory_limit_bytes": memory_limit_bytes,
        "cpu_time_seconds": 5,
        "output_file_limit_bytes": 0,
        "open_file_limit": 8,
        "process_limit": 1,
        "deny_all_network": true
    }))
    .unwrap();
    std::fs::write(&profile, profile_bytes).unwrap();
    Command::new(env!("CARGO_BIN_EXE_savana-worker-sandbox"))
        .args(["--profile", profile.to_str().unwrap(), "--"])
        .arg(worker)
        .arg(command)
        .status()
        .unwrap()
}

fn require_native_seatbelt_or_skip() -> bool {
    if host_permits_nested_seatbelt() {
        return true;
    }
    assert_ne!(
        std::env::var_os("SAVANA_REQUIRE_NATIVE_MACOS_SANDBOX_TEST").as_deref(),
        Some(std::ffi::OsStr::new("1")),
        "the release runner does not permit the mandatory native macOS Seatbelt test"
    );
    eprintln!("skipping native Seatbelt execution: the parent sandbox forbids sandbox_init");
    false
}

fn host_permits_nested_seatbelt() -> bool {
    Command::new("/usr/bin/sandbox-exec")
        .args(["-p", "(version 1)\n(allow default)", "/usr/bin/true"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}
