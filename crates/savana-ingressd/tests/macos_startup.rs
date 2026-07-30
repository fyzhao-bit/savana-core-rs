#![cfg(target_os = "macos")]

#[test]
fn macos_startup_rejects_nonfixed_bootstrap_path() {
    assert_eq!(
        savana_ingressd::run(std::path::Path::new("/tmp/ingressd-bootstrap-v2.json")),
        Err(savana_ingressd::IngressdDaemonErrorV2::DeploymentUnavailable)
    );
}
