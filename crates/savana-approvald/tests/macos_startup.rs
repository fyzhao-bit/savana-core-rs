#![cfg(target_os = "macos")]

#[test]
fn macos_startup_rejects_nonfixed_bootstrap_path() {
    assert_eq!(
        savana_approvald::run(std::path::Path::new("/tmp/approvald-bootstrap-v2.json")),
        Err(savana_approvald::ApprovaldDaemonErrorV2::DeploymentUnavailable)
    );
}
