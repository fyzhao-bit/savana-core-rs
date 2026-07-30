#![cfg(target_os = "macos")]

use std::path::Path;

use savana_kernel_protocol::StableCode;
use savana_kerneld::test_support::probe_macos_v2_startup;

#[test]
fn macos_startup_fails_before_ready_when_development_config_is_missing() {
    let probe = probe_macos_v2_startup(Path::new(
        "/Library/Application Support/Savana/Development/config/kerneld-bootstrap-v2.json",
    ));
    assert_eq!(probe.result(), Err(StableCode::KernelUnavailable));
    assert_eq!(probe.workers_started(), 0);
    assert_eq!(probe.activation_completed(), 0);
}
