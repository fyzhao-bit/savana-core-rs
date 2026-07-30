#![cfg(target_os = "macos")]

#[test]
fn macos_startup_rejects_nonfixed_bootstrap_path() {
    assert_eq!(
        savana_execd::run(std::path::Path::new("/tmp/execd-bootstrap-v2.json")),
        Err(savana_execd::ExecdDaemonErrorV2::DeploymentUnavailable)
    );
}
