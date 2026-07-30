#![cfg(target_os = "macos")]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::{fs, os::unix::fs::PermissionsExt as _};

const ROOT: &str = "/Library/Application Support/Savana/Development";

struct JobContract {
    leaf: &'static str,
    label: &'static str,
    user: &'static str,
    program: &'static str,
    sockets: &'static [SocketContract],
}

enum SocketContract {
    Unix(&'static str, &'static str),
    Tcp(&'static str, u16),
}

#[test]
fn development_plists_have_the_exact_closed_graph() {
    let contracts = [
        JobContract {
            leaf: "com.savana.development.kerneld.plist",
            label: "com.savana.development.kerneld",
            user: "_savana_kernel_dev",
            program: "savana-kerneld",
            sockets: &[
                SocketContract::Unix(
                    "savana-agent-kernel",
                    "/Library/Application Support/Savana/Development/run/kerneld/agentd/kerneld.sock",
                ),
                SocketContract::Unix(
                    "savana-ingress-kernel",
                    "/Library/Application Support/Savana/Development/run/kerneld/ingressd/kerneld.sock",
                ),
            ],
        },
        JobContract {
            leaf: "com.savana.development.agentd.plist",
            label: "com.savana.development.agentd",
            user: "_savana_agent_dev",
            program: "savana-agentd",
            sockets: &[
                SocketContract::Unix(
                    "savana-jarvis-agent-control",
                    "/Library/Application Support/Savana/Development/run/agentd/jarvis/control.sock",
                ),
                SocketContract::Tcp("savana-jarvis-http", 8765),
                SocketContract::Tcp("savana-agent-http", 8768),
            ],
        },
        JobContract {
            leaf: "com.savana.development.ingressd.plist",
            label: "com.savana.development.ingressd",
            user: "_savana_ingress_dev",
            program: "savana-ingressd",
            sockets: &[SocketContract::Tcp("savana-ingress-http", 8767)],
        },
        JobContract {
            leaf: "com.savana.development.approvald.plist",
            label: "com.savana.development.approvald",
            user: "_savana_approval_dev",
            program: "savana-approvald",
            sockets: &[
                SocketContract::Unix(
                    "savana-agent-approval",
                    "/Library/Application Support/Savana/Development/run/approvald/agentd/approvald.sock",
                ),
                SocketContract::Unix(
                    "savana-ingress-approval",
                    "/Library/Application Support/Savana/Development/run/approvald/ingressd/approvald.sock",
                ),
                SocketContract::Unix(
                    "savana-admin-approval",
                    "/Library/Application Support/Savana/Development/run/approvald/admin/approvald.sock",
                ),
                SocketContract::Tcp("savana-approval-http", 8766),
            ],
        },
        JobContract {
            leaf: "com.savana.development.execd.plist",
            label: "com.savana.development.execd",
            user: "_savana_exec_dev",
            program: "savana-execd",
            sockets: &[SocketContract::Unix(
                "savana-kernel-executor",
                "/Library/Application Support/Savana/Development/run/execd/kerneld/execd.sock",
            )],
        },
        JobContract {
            leaf: "com.savana.development.jarvis-python.plist",
            label: "com.savana.development.jarvis-python",
            user: "_savana_jarvis_dev",
            program: "savana-jarvis-python",
            sockets: &[],
        },
    ];

    for contract in contracts {
        let path = deployment_root()
            .join("deploy/launchd/development")
            .join(contract.leaf);
        assert!(path.is_file(), "missing {}", path.display());
        assert!(
            Command::new("/usr/bin/plutil")
                .args(["-lint", path.to_str().unwrap()])
                .status()
                .unwrap()
                .success(),
            "invalid plist {}",
            path.display()
        );
        assert_eq!(extract(&path, "Label"), contract.label);
        assert_eq!(extract(&path, "UserName"), contract.user);
        assert_eq!(
            extract(&path, "Program"),
            format!("{ROOT}/bin/{}", contract.program)
        );
        if contract.program == "savana-jarvis-python" {
            assert_eq!(
                extract(&path, "ProgramArguments.1"),
                format!("{ROOT}/config/jarvis-python-v2.json")
            );
        } else {
            assert_eq!(extract(&path, "ProgramArguments.1"), "--config");
            assert_eq!(
                extract(&path, "ProgramArguments.2"),
                format!(
                    "{ROOT}/config/{}-bootstrap-v2.json",
                    contract.program.trim_start_matches("savana-")
                )
            );
        }
        assert_eq!(
            extract(&path, "EnvironmentVariables.SAVANA_AUTHORITY_CLASS"),
            "development"
        );
        for socket in contract.sockets {
            match socket {
                SocketContract::Unix(key, path_name) => {
                    assert_eq!(
                        extract(&path, &format!("Sockets.{key}.SockPathName")),
                        *path_name
                    );
                    assert_eq!(extract(&path, &format!("Sockets.{key}.SockType")), "stream");
                }
                SocketContract::Tcp(key, port) => {
                    assert_eq!(
                        extract(&path, &format!("Sockets.{key}.SockNodeName")),
                        "127.0.0.1"
                    );
                    assert_eq!(
                        extract(&path, &format!("Sockets.{key}.SockServiceName")),
                        port.to_string()
                    );
                }
            }
        }
    }
}

#[test]
fn installer_and_uninstaller_reject_open_invocation_shapes() {
    let scripts = deployment_root().join("deploy/macos/development");
    let install = scripts.join("install.sh");
    let uninstall = scripts.join("uninstall.sh");
    for arguments in [
        Vec::<&str>::new(),
        vec!["relative/build"],
        vec!["/absolute/build", "extra"],
    ] {
        assert_eq!(
            Command::new(&install)
                .args(arguments)
                .status()
                .unwrap()
                .code(),
            Some(64)
        );
    }
    assert_eq!(
        Command::new(&uninstall)
            .arg("unexpected")
            .status()
            .unwrap()
            .code(),
        Some(64)
    );
}

#[test]
fn installer_copies_each_deployment_helper_exactly_once() {
    let install = deployment_root().join("deploy/macos/development/install.sh");
    let source = fs::read_to_string(install).unwrap();
    for helper in [
        "savana-development-manifest",
        "savana-development-material",
        "savana-macos-code-identity",
    ] {
        assert_eq!(
            source
                .matches(&format!("\"$build_directory/libexec/{helper}\""))
                .count(),
            1,
            "{helper} must be supplied to install exactly once"
        );
    }
}

#[test]
fn validator_accepts_only_a_complete_nonmutating_build_fixture() {
    let fixture = tempfile::tempdir().unwrap();
    for directory in [
        "bin",
        "config",
        "artifacts",
        "entitlements",
        "libexec",
        "sandbox",
        "signing",
    ] {
        fs::create_dir(fixture.path().join(directory)).unwrap();
    }
    let executable = std::env::current_exe().unwrap();
    for worker in [
        "savana-worker-sandbox",
        "savana-parser-worker",
        "savana-connector-worker",
    ] {
        let binary = fixture.path().join("bin").join(worker);
        fs::copy(&executable, &binary).unwrap();
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o755)).unwrap();
    }
    for service in [
        "kerneld",
        "agentd",
        "ingressd",
        "approvald",
        "execd",
        "jarvis-python",
    ] {
        let binary = fixture.path().join(format!("bin/savana-{service}"));
        fs::copy(&executable, &binary).unwrap();
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(
            fixture.path().join(format!(
                "entitlements/com.savana.development.{service}.plist"
            )),
            b"<?xml version=\"1.0\" encoding=\"UTF-8\"?><plist version=\"1.0\"><dict/></plist>",
        )
        .unwrap();
    }
    for leaf in [
        "agentd-bootstrap-v2.json",
        "approvald-bootstrap-v2.json",
        "execd-bootstrap-v2.json",
        "ingressd-bootstrap-v2.json",
        "jarvis-python-v2.json",
        "kerneld-bootstrap-v2.json",
        "development-manifest-template-v2.json",
    ] {
        fs::write(fixture.path().join("config").join(leaf), b"{}").unwrap();
    }
    for leaf in [
        "effect-ledger-projection-v2.cbor",
        "input-runtime-assets-v2.cbor",
    ] {
        fs::write(fixture.path().join("artifacts").join(leaf), b"x").unwrap();
    }
    for leaf in [
        "parser-profile-v2.json",
        "connector-no-network-profile-v2.json",
        "connector-credential-absence-profile-v2.json",
    ] {
        fs::write(fixture.path().join("sandbox").join(leaf), b"{}").unwrap();
    }
    fs::write(
        fixture.path().join("signing/deployment-manifest-v2.seed"),
        [7_u8; 32],
    )
    .unwrap();
    for helper in [
        "savana-development-manifest",
        "savana-development-material",
        "savana-macos-code-identity",
    ] {
        let path = fixture.path().join("libexec").join(helper);
        fs::write(&path, b"#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    let output = Command::new(deployment_root().join("deploy/macos/development/validate.sh"))
        .arg(fixture.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains(
        "planned launchd labels: com.savana.development.kerneld com.savana.development.agentd"
    ));
    assert!(stdout.contains("planned Security.framework Team ID: SAVANADEV1"));

    fs::remove_file(fixture.path().join("signing/deployment-manifest-v2.seed")).unwrap();
    assert_eq!(
        Command::new(deployment_root().join("deploy/macos/development/validate.sh"))
            .arg(fixture.path())
            .status()
            .unwrap()
            .code(),
        Some(66)
    );
}

fn extract(path: &Path, key: &str) -> String {
    let output = Command::new("/usr/bin/plutil")
        .args(["-extract", key, "raw", "-o", "-", path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "missing {key} in {}: {}",
        path.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

fn deployment_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap()
        .to_path_buf()
}
