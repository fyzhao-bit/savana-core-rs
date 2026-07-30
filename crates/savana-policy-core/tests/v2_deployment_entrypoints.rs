use std::process::Command;

#[test]
fn deploy_rejects_every_non_closed_invocation_before_platform_access() {
    let binary = env!("CARGO_BIN_EXE_savana-deploy");
    for arguments in [
        Vec::<&str>::new(),
        vec!["prepare"],
        vec!["apply"],
        vec!["apply", "00"],
        vec![
            "apply",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ],
        vec![
            "apply",
            "1111111111111111111111111111111111111111111111111111111111111111",
            "extra",
        ],
    ] {
        assert_eq!(
            Command::new(binary)
                .args(arguments)
                .status()
                .unwrap()
                .code(),
            Some(64)
        );
    }
}

#[test]
fn deployment_entrypoints_never_report_success_without_native_authority() {
    let selector = "1111111111111111111111111111111111111111111111111111111111111111";
    let apply = Command::new(env!("CARGO_BIN_EXE_savana-deploy"))
        .args(["apply", selector])
        .status()
        .unwrap()
        .code()
        .unwrap();
    assert!(matches!(apply, 69 | 74 | 77));

    assert_eq!(
        Command::new(env!("CARGO_BIN_EXE_savana-deploy-watchdog"))
            .arg("extra")
            .status()
            .unwrap()
            .code(),
        Some(64)
    );
    let watchdog = Command::new(env!("CARGO_BIN_EXE_savana-deploy-watchdog"))
        .status()
        .unwrap()
        .code()
        .unwrap();
    assert!(matches!(watchdog, 69 | 74 | 77));
}
