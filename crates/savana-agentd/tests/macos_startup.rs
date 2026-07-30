#![cfg(target_os = "macos")]

#[test]
fn macos_startup_rejects_nonfixed_bootstrap_path() {
    assert_eq!(
        savana_agentd::run(std::path::Path::new("/tmp/agentd-bootstrap-v2.json")),
        Err(savana_agentd::AgentdDaemonErrorV2::DeploymentUnavailable)
    );
}
