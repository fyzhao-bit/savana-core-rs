use std::process::{Command, Output};

fn run(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_savana-kerneld"))
        .args(arguments)
        .output()
        .unwrap()
}

#[test]
fn malformed_cli_is_silent_and_exits_64() {
    for arguments in [
        Vec::<&str>::new(),
        vec!["--config"],
        vec!["-c", "/etc/savana/kerneld-bootstrap-v1.json"],
        vec!["--config", "relative.json"],
        vec!["--config", "/etc/savana/kerneld-bootstrap-v1.json", "extra"],
    ] {
        let output = run(&arguments);
        assert_eq!(output.status.code(), Some(64));
        assert!(output.stdout.is_empty());
        assert!(output.stderr.is_empty());
    }
}

#[test]
fn unavailable_v2_startup_exits_1_and_only_emits_typed_redacted_audit() {
    let output = run(&["--config", "/etc/savana/kerneld-bootstrap-v2.json"]);

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        "{\"event\":\"BootstrapFailed\",\"code\":\"KERNEL_UNAVAILABLE\"}\n"
    );
}
