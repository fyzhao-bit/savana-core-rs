#![cfg(target_os = "linux")]

use std::fs;
use std::process::Command;

#[test]
fn native_wrapper_executes_only_after_landlock_seccomp_and_limits_are_available() {
    let directory = tempfile::tempdir().unwrap();
    let profile = directory.path().join("profile.json");
    fs::write(
        &profile,
        r#"{
  "version": 2,
  "worker_program": "/bin/true",
  "read_only_paths": [],
  "memory_limit_bytes": 67108864,
  "cpu_time_seconds": 5,
  "output_file_limit_bytes": 0,
  "open_file_limit": 4,
  "process_limit": 1,
  "deny_all_network": true
}"#,
    )
    .unwrap();
    let status = Command::new(env!("CARGO_BIN_EXE_savana-worker-sandbox"))
        .arg("--profile")
        .arg(profile)
        .arg("--")
        .arg("/bin/true")
        .status()
        .unwrap();
    assert!(status.success());
}

#[test]
fn native_wrapper_denies_unlisted_files_inside_the_worker() {
    let directory = tempfile::tempdir().unwrap();
    let profile = directory.path().join("profile.json");
    fs::write(
        &profile,
        r#"{
  "version": 2,
  "worker_program": "/bin/bash",
  "read_only_paths": [],
  "memory_limit_bytes": 67108864,
  "cpu_time_seconds": 5,
  "output_file_limit_bytes": 0,
  "open_file_limit": 4,
  "process_limit": 1,
  "deny_all_network": true
}"#,
    )
    .unwrap();
    let status = Command::new(env!("CARGO_BIN_EXE_savana-worker-sandbox"))
        .arg("--profile")
        .arg(profile)
        .arg("--")
        .arg("/bin/bash")
        .arg("-c")
        .arg("if exec 3</etc/passwd; then exit 90; else exit 0; fi")
        .status()
        .unwrap();
    assert!(status.success());
}
