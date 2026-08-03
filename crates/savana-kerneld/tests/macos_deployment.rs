#![cfg(target_os = "macos")]

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::{fs, os::unix::fs::PermissionsExt as _};

use savana_input_runtime::{SignedInputRuntimeAssetsV2, VerifiedInputRuntimeAssetsV2};
use savana_kernel_protocol::v2::{
    derive_ed25519_key_id_v2, Digest32V2, Ed25519KeyIdV2, EffectLedgerProjectionBindingV2,
    UnixMillisV2, VersionV2,
};
use savana_policy_core::v2::{
    AttemptKindV2, ClosedDeclassificationPurposeV2, DeclassificationRuleSetV2, EffectSetV2,
    InstallerOrMdmVerifierV2, OperationalTrustRootSetV2, SignedToolDescriptorV2,
    VerifiedRegistryPublisherV2,
};

const ROOT: &str = "/Library/Application Support/Savana/Development";
const AUDIT_FIFO: &str = "/Library/Application Support/Savana/Development/run/kerneld-audit.fifo";

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
        assert_eq!(extract(&path, "InitGroups"), "true");
        assert_eq!(
            extract(&path, "Program"),
            format!(
                "/Library/PrivilegedHelperTools/SavanaDevelopment/{}",
                contract.program
            )
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
        let service = contract.program.trim_start_matches("savana-");
        assert_eq!(
            extract(&path, "StandardOutPath"),
            format!("/Library/Logs/Savana/Development/{service}.log")
        );
        assert_eq!(
            extract(&path, "StandardErrorPath"),
            if service == "kerneld" {
                AUDIT_FIFO.to_owned()
            } else {
                format!("/Library/Logs/Savana/Development/{service}.error.log")
            }
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
fn development_audit_bridge_is_a_separate_least_privilege_job() {
    let path = deployment_root()
        .join("deploy/launchd/development")
        .join("com.savana.development.audit-bridge.plist");
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
    assert_eq!(
        extract(&path, "Label"),
        "com.savana.development.audit-bridge"
    );
    assert_eq!(extract(&path, "UserName"), "_savana_audit_dev");
    assert_eq!(extract(&path, "GroupName"), "_savana_audit_dev");
    assert_eq!(extract(&path, "InitGroups"), "true");
    assert_eq!(
        extract(&path, "Program"),
        "/Library/PrivilegedHelperTools/SavanaDevelopment/savana-development-audit-bridge"
    );
    assert_eq!(
        extract(&path, "ProgramArguments.0"),
        "/Library/PrivilegedHelperTools/SavanaDevelopment/savana-development-audit-bridge"
    );
    assert_eq!(extract(&path, "KeepAlive"), "true");
    assert_eq!(extract(&path, "ProcessType"), "Background");
    assert_eq!(
        extract(&path, "StandardOutPath"),
        "/Library/Logs/Savana/Development/audit-bridge.log"
    );
    assert_eq!(
        extract(&path, "StandardErrorPath"),
        "/Library/Logs/Savana/Development/audit-bridge.error.log"
    );
    assert!(!fs::read_to_string(path)
        .unwrap()
        .contains("<key>Sockets</key>"));
}

#[test]
fn development_audit_bridge_is_packaged_started_first_and_has_no_ipc_edge() {
    let scripts = deployment_root().join("deploy/macos/development");
    let build = fs::read_to_string(scripts.join("build.sh")).unwrap();
    let sign = fs::read_to_string(scripts.join("sign.sh")).unwrap();
    let validate = fs::read_to_string(scripts.join("validate.sh")).unwrap();
    let install = fs::read_to_string(scripts.join("install.sh")).unwrap();
    let uninstall = fs::read_to_string(scripts.join("uninstall.sh")).unwrap();

    for source in [&build, &sign, &validate, &install] {
        assert!(source.contains("savana-development-audit-bridge"));
    }
    assert!(install.contains("_savana_audit_dev"));
    assert!(install.contains("\"$install_root/run/kerneld-audit.fifo\""));
    assert!(install.contains("\"$log_root/kerneld-audit.log\""));
    assert!(install.contains("/usr/bin/mkfifo -m 0640 \"$install_root/run/kerneld-audit.fifo\""));
    assert!(install.contains("/usr/sbin/chown _savana_kernel_dev:_savana_audit_dev"));
    assert!(install.contains("for edge_group in $ipc_edge_groups; do"));
    assert!(!install.contains("for edge_group in $edge_groups; do"));
    assert!(
        install
            .find("/bin/launchctl bootstrap system \"$bridge_plist\"")
            .unwrap()
            < install
                .find("for service in kerneld approvald execd ingressd agentd jarvis-python")
                .unwrap()
    );
    for edge in [
        "_savana_agent_kernel_dev",
        "_savana_ingress_kernel_dev",
        "_savana_kernel_exec_dev",
        "_savana_agent_approval_dev",
        "_savana_ingress_approval_dev",
        "_savana_jarvis_agent_dev",
    ] {
        let edge_line = install
            .lines()
            .find(|line| line.contains("add_edge_members") && line.contains(edge))
            .unwrap();
        assert!(!edge_line.contains("_savana_audit_dev"));
    }
    assert!(uninstall.contains("audit-bridge"));
    assert!(uninstall.contains("_savana_audit_dev"));
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
fn development_builder_has_a_closed_two_repository_invocation() {
    let build = deployment_root().join("deploy/macos/development/build.sh");
    for arguments in [
        Vec::<&str>::new(),
        vec!["relative/build", "/absolute/python"],
        vec!["/absolute/build", "relative/python"],
        vec!["/absolute/build", "/absolute/python", "extra"],
    ] {
        assert_eq!(
            Command::new(&build)
                .args(arguments)
                .status()
                .unwrap()
                .code(),
            Some(64)
        );
    }
    let source = fs::read_to_string(build).unwrap();
    assert!(source.contains("VIRTUAL_ENV=\"$python_environment\""));
    assert!(source.contains("/usr/bin/env -u CONDA_PREFIX"));
    assert!(source.contains("PYINSTALLER_CONFIG_DIR=\"$temporary_directory/pyinstaller\""));
    assert!(source.contains("--add-data"));
    assert!(source.contains("secure_pdf_v2.yaml:server/runtime/tool_packs"));
    assert!(source.contains("--exclude-module torch"));
    for binary in [
        "savana-kerneld",
        "savana-agentd",
        "savana-ingressd",
        "savana-approvald",
        "savana-execd",
        "savana-parser-worker",
        "savana-connector-worker",
        "savana-worker-sandbox",
        "savana-development-manifest",
        "savana-development-material",
        "savana-development-attestation-root",
        "savana-macos-code-identity",
        "savana-jarvis-python",
        "savana-development-audit-bridge",
    ] {
        assert!(source.contains(binary), "{binary} is missing");
    }
}

#[test]
fn installer_copies_each_deployment_helper_exactly_once() {
    let install = deployment_root().join("deploy/macos/development/install.sh");
    let source = fs::read_to_string(install).unwrap();
    for helper in [
        "savana-development-manifest",
        "savana-development-material",
        "savana-development-attestation-root",
        "savana-macos-code-identity",
    ] {
        assert_eq!(
            source
                .matches(&format!("\"$build_directory/signed/libexec/{helper}\""))
                .count(),
            1,
            "{helper} must be supplied to install exactly once"
        );
    }
}

#[test]
fn installer_creates_root_owned_launch_images_from_the_signed_services() {
    let install = deployment_root().join("deploy/macos/development/install.sh");
    let source = fs::read_to_string(install).unwrap();
    assert!(source.contains("launcher_root=\"/Library/PrivilegedHelperTools/SavanaDevelopment\""));
    assert!(source.contains("/usr/bin/install -d -o root -g wheel -m 0755 \"$launcher_root\""));
    assert!(source.contains(
        "\"$build_directory/signed/bin/savana-$service\" \"$launcher_root/savana-$service\""
    ));
    assert!(source.contains("verify_installed_identity \"$launcher_root/savana-$service\""));
    assert!(source.contains(
        "/usr/bin/cmp -s \"$install_root/bin/savana-$service\" \"$launcher_root/savana-$service\""
    ));
}

#[test]
fn installer_allocates_only_currently_unused_account_identifiers() {
    let install = deployment_root().join("deploy/macos/development/install.sh");
    let source = fs::read_to_string(install).unwrap();
    assert!(!source.contains("dscl . -search /Groups PrimaryGroupID"));
    assert!(!source.contains("dscl . -search /Users UniqueID"));
    assert!(source.contains("dscl . -list /Groups PrimaryGroupID"));
    assert!(source.contains("dscl . -list /Users UniqueID"));
    assert!(source.contains("$NF == candidate"));
}

#[test]
fn installer_signals_exit_after_running_rollback() {
    let install = deployment_root().join("deploy/macos/development/install.sh");
    let source = fs::read_to_string(install).unwrap();
    assert!(source.contains("trap cleanup EXIT"));
    assert!(source.contains("trap 'rollback_on_signal 129' HUP"));
    assert!(source.contains("trap 'rollback_on_signal 130' INT"));
    assert!(source.contains("trap 'rollback_on_signal 143' TERM"));
    assert!(source.contains("trap - EXIT HUP INT TERM"));
}

#[test]
fn installer_preserves_private_service_logs_before_failed_install_rollback() {
    let install = deployment_root().join("deploy/macos/development/install.sh");
    let source = fs::read_to_string(install).unwrap();
    let archive = source
        .find("savana-development-install-failure.XXXXXX")
        .expect("private failure-log archive is missing");
    let remove_root = source
        .find("/bin/rm -rf \"$install_root\"")
        .expect("installation root rollback is missing");
    assert!(archive < remove_root);
    assert!(source.contains("/bin/cp -R \"$log_root\" \"$failure_log_directory/log\""));
    assert!(source.contains("/bin/chmod -R go-rwx \"$failure_log_directory\""));
    assert!(source.contains("preserved service failure logs: $failure_log_directory"));
}

#[test]
fn installer_kickstarts_the_socket_activated_graph_before_readiness_checks() {
    let install = deployment_root().join("deploy/macos/development/install.sh");
    let source = fs::read_to_string(install).unwrap();
    let bootstrap = source
        .find("/bin/launchctl bootstrap system")
        .expect("launchd bootstrap is missing");
    let kickstart = source
        .find("/bin/launchctl kickstart -k")
        .expect("launchd kickstart is missing");
    let readiness = source
        .find("state = running")
        .expect("launchd readiness check is missing");
    assert!(bootstrap < kickstart);
    assert!(kickstart < readiness);
    assert!(source.contains("\"system/com.savana.development.$service\""));
}

#[test]
fn installer_requires_stable_pids_and_a_real_ui_response_before_commit() {
    let source =
        fs::read_to_string(deployment_root().join("deploy/macos/development/install.sh")).unwrap();
    assert!(source.contains("wait_for_v2_ui()"));
    assert!(source.contains("ui_deadline=$((SECONDS + 180))"));
    assert!(source.contains("V2 UI readiness deadline exceeded"));
    assert!(source.contains("snapshot_launchd_pid()"));
    assert!(source.contains("\"$temporary_directory/$service.pid\""));
    assert!(source.contains("stability_deadline=$((SECONDS + 90))"));
    assert!(source.contains("/bin/sleep 15"));
    assert!(source.contains("launchd service graph did not converge to stable PIDs"));
    assert!(source.contains(
        "/usr/bin/curl --fail --silent --max-time 2 \\\n      --resolve localhost:8765:127.0.0.1 \\\n      http://localhost:8765/v2/shell >/dev/null"
    ));
    let ui = source.find("wait_for_v2_ui\n").unwrap();
    let snapshot = source.find("snapshot_launchd_pid()").unwrap();
    let stability = source
        .find("launchd service graph did not converge to stable PIDs")
        .unwrap();
    let committed = source.find("installation_committed=1").unwrap();
    assert!(ui < snapshot);
    assert!(stability < committed);
}

#[test]
fn installer_keeps_the_runtime_root_closed_and_system_logs_private() {
    let install = deployment_root().join("deploy/macos/development/install.sh");
    let source = fs::read_to_string(install).unwrap();
    assert!(source.contains("install_parent=\"/Library/Application Support/Savana\""));
    assert!(source.contains("/usr/bin/install -d -o root -g wheel -m 0711 \"$install_parent\""));
    assert!(source
        .contains("/usr/bin/install -d -o root -g _savana_runtime_dev -m 0750 \"$install_root\""));
    assert!(source.contains(
        "/usr/bin/install -d -o root -g _savana_runtime_dev -m 0750 \"$install_root/$directory\""
    ));
    assert!(source.contains(
        "for directory in bin config config/approvald config/policy config/tls config/trust"
    ));
    assert!(source.contains(
        "/usr/bin/install -d -o \"$account\" -g \"$account\" -m 0700 \"$install_root/state/$service\""
    ));
    assert!(source.contains("/usr/bin/install -d -o root -g wheel -m 0711 \"$log_root\""));
    assert!(source.contains("/usr/bin/install -o \"$account\" -g \"$account\" -m 0600 /dev/null"));
    assert!(!source.contains("/usr/bin/install -d -o root -g wheel -m 0711 \"$install_root\""));
    assert!(!source.contains("\"$install_root/log/$service.log\""));
    assert!(source.contains("\"$log_root/$service.log\""));
}

#[test]
fn installer_makes_manifest_socket_parents_observable_without_opening_the_sockets() {
    let source =
        fs::read_to_string(deployment_root().join("deploy/macos/development/install.sh")).unwrap();
    for directory in [
        "$install_root/run/agentd/jarvis",
        "$install_root/run/kerneld/agentd",
        "$install_root/run/execd/kerneld",
    ] {
        let install_line = source
            .lines()
            .find(|line| line.contains("-m 0711") && line.ends_with('\\'))
            .unwrap_or("");
        assert!(
            source.contains(&format!("-m 0711 \\\n  \"{directory}\"")),
            "manifest socket parent must be traversable but not listable: {directory}; nearest install line: {install_line}"
        );
    }
    for (plist, socket) in [
        (
            "com.savana.development.agentd.plist",
            "savana-jarvis-agent-control",
        ),
        (
            "com.savana.development.kerneld.plist",
            "savana-agent-kernel",
        ),
        (
            "com.savana.development.execd.plist",
            "savana-kernel-executor",
        ),
    ] {
        let path = deployment_root()
            .join("deploy/launchd/development")
            .join(plist);
        assert_eq!(
            extract(&path, &format!("Sockets.{socket}.SockPathMode")),
            "432"
        );
    }
}

#[test]
fn installer_materializes_numeric_launchd_socket_identities_before_bootstrap() {
    let install = deployment_root().join("deploy/macos/development/install.sh");
    let source = fs::read_to_string(install).unwrap();
    assert!(source.contains("/usr/libexec/PlistBuddy -c \"Delete :Sockets:$socket:SockPathOwner\""));
    assert!(source.contains(
        "/usr/libexec/PlistBuddy -c \"Add :Sockets:$socket:SockPathOwner integer $owner\""
    ));
    assert!(source.contains(
        "/usr/libexec/PlistBuddy -c \"Add :Sockets:$socket:SockPathGroup integer $group\""
    ));
    for mapping in [
        "materialize_socket_identity agentd savana-jarvis-agent-control _savana_agent_dev _savana_jarvis_agent_dev",
        "materialize_socket_identity kerneld savana-agent-kernel _savana_kernel_dev _savana_agent_kernel_dev",
        "materialize_socket_identity kerneld savana-ingress-kernel _savana_kernel_dev _savana_ingress_kernel_dev",
        "materialize_socket_identity approvald savana-agent-approval _savana_approval_dev _savana_agent_approval_dev",
        "materialize_socket_identity approvald savana-ingress-approval _savana_approval_dev _savana_ingress_approval_dev",
        "materialize_socket_identity approvald savana-admin-approval root wheel",
        "materialize_socket_identity execd savana-kernel-executor _savana_exec_dev _savana_kernel_exec_dev",
    ] {
        assert!(source.contains(mapping), "missing {mapping}");
    }
    let materialize = source.find("materialize_socket_identity agentd").unwrap();
    let bootstrap = source.find("/bin/launchctl bootstrap system").unwrap();
    assert!(materialize < bootstrap);
}

#[test]
fn installer_rehardens_generated_trust_files_after_atomic_replacement() {
    let source =
        fs::read_to_string(deployment_root().join("deploy/macos/development/install.sh")).unwrap();

    assert!(source.contains("harden_generated_trust_file()"));
    assert!(source.contains("/usr/sbin/chown root:wheel \"$1\""));
    assert!(source.contains("/bin/chmod 0444 \"$1\""));
    assert!(source.contains("for service in kerneld agentd ingressd approvald execd; do"));
    assert!(source.contains(
        "harden_generated_trust_file \"$install_root/config/$service-bootstrap-v2.json\""
    ));
    for leaf in [
        "jarvis-python-v2.json",
        "development-manifest-template-v2.json",
        "trust/deployment-manifest-root-v2.json",
        "deployment-manifest-v2.cbor",
    ] {
        assert!(
            source.contains(&format!(
                "harden_generated_trust_file \"$install_root/config/{leaf}\""
            )),
            "missing post-generation hardening for {leaf}"
        );
    }

    let material = source
        .find("\"$install_root/libexec/savana-development-material\" \"$install_root\"")
        .unwrap();
    let harden_bootstrap = source
        .find("harden_generated_trust_file \"$install_root/config/$service-bootstrap-v2.json\"")
        .unwrap();
    let manifest = source
        .rfind("\"$install_root/libexec/savana-development-manifest\"")
        .unwrap();
    let harden_root = source
        .find(
            "harden_generated_trust_file \"$install_root/config/trust/deployment-manifest-root-v2.json\"",
        )
        .unwrap();
    let bootstrap = source
        .find("/bin/launchctl bootstrap system \"$bridge_plist\"")
        .unwrap();
    assert!(material < harden_bootstrap);
    assert!(manifest < harden_bootstrap);
    assert!(manifest < harden_root);
    assert!(harden_bootstrap < harden_root);
    assert!(harden_root < bootstrap);
}

#[test]
fn installer_rehardens_generated_public_keys_for_frozen_daemon_loaders() {
    let source =
        fs::read_to_string(deployment_root().join("deploy/macos/development/install.sh")).unwrap();
    let material = source
        .find("\"$install_root/libexec/savana-development-material\"")
        .expect("development material generation is missing");
    let public_keys = source
        .find("harden_generated_public_keys")
        .expect("generated public-key hardening is missing");
    let bootstrap = source
        .find("/bin/launchctl bootstrap system \"$bridge_plist\"")
        .expect("launchd bootstrap is missing");

    assert!(source.contains(
        "/usr/bin/find \"$install_root/config\" -type f -name '*.pub' -exec /usr/sbin/chown root:wheel {} \\;"
    ));
    assert!(source.contains(
        "/usr/bin/find \"$install_root/config\" -type f -name '*.pub' -exec /bin/chmod 0444 {} \\;"
    ));
    assert!(material < public_keys);
    assert!(public_keys < bootstrap);
}

#[test]
fn installer_rehardens_generated_sandbox_profiles_after_atomic_replacement() {
    let source =
        fs::read_to_string(deployment_root().join("deploy/macos/development/install.sh")).unwrap();
    let material = source
        .find("\"$install_root/libexec/savana-development-material\" \"$install_root\"")
        .expect("development material generation is missing");
    let ingress_profile = source
        .find("/usr/sbin/chown _savana_ingress_dev:_savana_ingress_dev")
        .expect("parser profile identity restoration is missing");
    let connector_profile = source
        .find("/usr/sbin/chown _savana_exec_dev:_savana_exec_dev")
        .expect("connector profile identity restoration is missing");
    let bootstrap = source
        .find("/bin/launchctl bootstrap system \"$bridge_plist\"")
        .expect("launchd bootstrap is missing");

    assert!(source
        .contains("/bin/chmod 0444 \"$install_root/sandbox/ingressd/parser-profile-v2.json\""));
    assert!(source.contains("/bin/chmod 0444 \\\n"));
    assert!(source
        .contains("\"$install_root/sandbox/execd/connector-credential-absence-profile-v2.json\""));
    assert!(material < ingress_profile);
    assert!(material < connector_profile);
    assert!(ingress_profile < bootstrap);
    assert!(connector_profile < bootstrap);
}

#[test]
fn installer_provisions_a_pinned_development_webauthn_attestation_root() {
    let source =
        fs::read_to_string(deployment_root().join("deploy/macos/development/install.sh")).unwrap();
    let config = fs::read_to_string(
        deployment_root().join("deploy/macos/development/tls/webauthn-attestation-root.cnf"),
    )
    .unwrap();

    assert!(config.contains("basicConstraints = critical,CA:true,pathlen:0"));
    assert!(config.contains("keyUsage = critical,keyCertSign,cRLSign"));
    assert!(!source.contains("webauthn-attestation-root.key.pem"));
    assert!(!source.contains("/usr/bin/openssl ecparam -name prime256v1 -genkey"));
    assert!(source.contains("development-webauthn-attestation-root-v2.der"));
    assert!(source.contains("attestation_root_certificate_sha256="));
    assert!(source.contains("attestation_root_spki_sha256="));
    assert!(source.contains("/usr/bin/plutil -replace attestation_roots -json"));
    assert!(source.contains("attestation_aaguid=534156414e4144455631000000000001"));
    assert!(source.contains("\"$install_root/libexec/savana-development-attestation-root\""));
    assert!(source.contains(
        "\"$temporary_directory/webauthn-attestation-root.cert.der\" \\\n    \"$attestation_aaguid\""
    ));

    let patch = source
        .find("/usr/bin/plutil -replace attestation_roots -json")
        .expect("attestation root config patch is missing");
    let material = source
        .find("\"$install_root/libexec/savana-development-material\" \"$install_root\"")
        .expect("development material generation is missing");
    let manifest = source
        .rfind("\"$install_root/libexec/savana-development-manifest\"")
        .expect("manifest generation is missing");
    assert!(patch < material);
    assert!(material < manifest);
}

#[test]
fn installer_restores_root_wheel_identity_on_launchd_admin_socket_before_kickstart() {
    let source =
        fs::read_to_string(deployment_root().join("deploy/macos/development/install.sh")).unwrap();
    let bootstrap_loop = source
        .find("for service in kerneld approvald execd ingressd agentd jarvis-python; do")
        .expect("service bootstrap loop is missing");
    let admin_socket = source
        .find(
            "/usr/sbin/chown root:wheel \\\n  \"$install_root/run/approvald/admin/approvald.sock\"",
        )
        .expect("admin socket identity restoration is missing");
    let kickstart_loop = source[bootstrap_loop..]
        .find("deadline=$((SECONDS + 60))")
        .map(|offset| bootstrap_loop + offset)
        .expect("service kickstart loop is missing");

    assert!(source.contains("/bin/chmod 0600 \"$install_root/run/approvald/admin/approvald.sock\""));
    assert!(bootstrap_loop < admin_socket);
    assert!(admin_socket < kickstart_loop);
}

#[test]
fn installer_reuses_complete_daemon_accounts_without_rewriting_them() {
    let install = deployment_root().join("deploy/macos/development/install.sh");
    let source = fs::read_to_string(install).unwrap();
    assert!(source.contains("created_users=\"\""));
    assert!(source.contains("created_primary_groups=\"\""));
    assert!(source.contains("if [ \"$existing_account_count\" -eq 0 ]; then"));
    assert!(source.contains("created_users=\"$created_users $account\""));
    assert!(source.contains("created_primary_groups=\"$created_primary_groups $account\""));
    assert!(source.contains("ensure_existing_account \"$account\""));
    assert!(source.contains("verify_user_attribute \"$account\" PrimaryGroupID \"$identifier\""));
    assert!(source.contains("verify_group_identifier \"$account\" \"$identifier\""));
    assert!(source.contains("for user in $created_users; do"));
    assert!(source.contains("for group in $created_primary_groups; do"));
    assert!(source.contains("case \"$existing_account_count\" in"));
    assert!(source.contains("create_user _savana_audit_dev"));
    assert!(source.contains("create_user _savana_audit_dev"));
    assert!(source.contains("sub(/^dsAttrTypeNative:/, \"\", key)"));
    assert!(source.contains("/usr/bin/dscacheutil -flushcache"));
    assert!(source.contains("require_group_membership \"$account\" _savana_runtime_dev"));
    let membership = source
        .find("/usr/bin/dscl . -append /Groups/_savana_runtime_dev")
        .unwrap();
    let flush = source.find("/usr/bin/dscacheutil -flushcache").unwrap();
    let directories = source
        .find("/usr/bin/install -d -o root -g _savana_runtime_dev")
        .unwrap();
    assert!(membership < flush);
    assert!(flush < directories);
}

#[test]
fn installer_repairs_only_a_missing_primary_group_after_verifying_the_locked_user() {
    let source =
        fs::read_to_string(deployment_root().join("deploy/macos/development/install.sh")).unwrap();
    assert!(source.contains("ensure_existing_account()"));
    assert!(source.contains("verify_existing_user \"$account\""));
    assert!(source.contains("primary group identifier is already occupied: $identifier"));
    assert!(source.contains("create_group \"$account\" \"$identifier\""));
    assert!(source.contains("created_primary_groups=\"$created_primary_groups $account\""));
    assert!(source.contains("ensure_existing_account \"$account\""));
    let verify = source.find("verify_existing_user \"$account\"").unwrap();
    let repair = source
        .find("create_group \"$account\" \"$identifier\"")
        .unwrap();
    assert!(verify < repair);
}

#[test]
fn signing_is_user_provisioned_and_installer_never_handles_the_private_key() {
    let scripts = deployment_root().join("deploy/macos/development");
    let install = fs::read_to_string(scripts.join("install.sh")).unwrap();
    let trust = fs::read_to_string(scripts.join("trust-signing.sh")).unwrap();
    let sign = fs::read_to_string(scripts.join("sign.sh")).unwrap();
    let system_trust = fs::read_to_string(scripts.join("trust-system-signing.command")).unwrap();
    for forbidden in [
        "security create-keychain",
        "security import",
        "openssl pkcs12",
        "codesign --force",
    ] {
        assert!(
            !install.contains(forbidden),
            "root installer must not contain {forbidden}"
        );
    }
    assert!(trust.contains("/usr/bin/openssl pkcs12 -export \\"));
    assert!(!trust.contains("pkcs12 -export -legacy"));
    assert!(trust.contains("-p codeSign"));
    assert!(trust.contains("Savana Development Code Signing"));
    assert!(!trust.contains("--team-identifier"));
    assert!(!sign.contains("--team-identifier"));
    assert!(trust.contains("TeamIdentifier=not set"));
    assert!(sign.contains("-r=\"$designated_requirement\""));
    assert!(sign.contains("designated_requirement=\"designated => anchor"));
    assert!(sign.contains("-R=\"$test_requirement\""));
    assert!(sign.contains("certificate root = H\\\"$certificate_sha1\\\""));
    assert!(sign.contains("\\\"$certificate\\\""));
    assert!(install.contains("\"$build_directory/signed/bin/savana-$service\""));
    assert!(install.contains("/usr/bin/codesign --verify --strict"));
    assert!(install.contains("certificate root = H\\\"$expected_certificate_sha1\\\""));
    assert!(install.contains("unexpected Apple Team ID"));
    assert!(system_trust.contains("add-trusted-cert"));
    assert!(system_trust.contains("-d -r trustRoot -p codeSign"));
}

#[test]
fn installer_rolls_back_account_edges_in_dependency_order() {
    let install = deployment_root().join("deploy/macos/development/install.sh");
    let source = fs::read_to_string(install).unwrap();
    let first_user_delete = source
        .find("for user in $created_users; do")
        .expect("initial user rollback loop is missing");
    let delete_edges = source[first_user_delete..]
        .find("for group in $edge_groups; do")
        .map(|offset| first_user_delete + offset)
        .expect("edge-group rollback loop is missing");
    let retry_user_delete = source[delete_edges..]
        .find("for user in $created_users; do")
        .map(|offset| delete_edges + offset)
        .expect("user rollback retry is missing");
    let delete_primary_groups = source[retry_user_delete..]
        .find("for group in $created_primary_groups; do")
        .map(|offset| retry_user_delete + offset)
        .expect("primary-group rollback loop is missing");
    assert!(first_user_delete < delete_edges);
    assert!(delete_edges < retry_user_delete);
    assert!(retry_user_delete < delete_primary_groups);
    assert!(source.contains("installation failed at line ${BASH_LINENO[0]}"));
    assert!(source.contains("create_deferred_user_attribute \"$name\" UniqueID \"$uid\""));
    assert!(source.contains("create_deferred_user_attribute \"$name\" NFSHomeDirectory /var/empty"));
    assert!(source.contains("verify_user_attribute \"$name\" UniqueID \"$uid\""));
    assert!(source.contains("verify_user_attribute \"$name\" NFSHomeDirectory /var/empty"));
    assert!(source.contains("existing_account_count=0"));
    assert!(source.contains("for account in $product_users; do"));
    assert!(source.contains("development daemon accounts are only partially present"));
    assert!(source.contains("key == (attribute \":\")"));
    assert!(source.contains("[ \"$recorded\" = \"$value\" ]"));
}

#[test]
fn uninstaller_retains_only_verified_locked_service_identities() {
    let source =
        fs::read_to_string(deployment_root().join("deploy/macos/development/uninstall.sh"))
            .unwrap();
    assert!(source.contains("delete_directory_record()"));
    assert!(source.contains("cannot remove development directory record: $path"));
    assert!(source.contains("verify_locked_service_account()"));
    assert!(source.contains("verify_locked_service_account \"$user\""));
    assert!(source.contains("delete_directory_record Groups \"$group\""));
    assert!(!source.contains("delete_directory_record Users \"$user\""));
    assert!(!source.contains("delete_directory_record Groups \"$user\""));
    assert!(source.contains("locked development service identities retained"));
    assert!(source.contains("/usr/bin/dscacheutil -flushcache"));
    assert!(!source.contains("/usr/bin/dscl . -delete \"/Users/$user\" >/dev/null 2>&1 || true"));
    assert!(!source.contains("/usr/bin/dscl . -delete \"/Groups/$group\" >/dev/null 2>&1 || true"));
}

#[test]
fn development_material_binds_parser_files_to_the_installed_ingress_account() {
    let helper =
        deployment_root().join("crates/savana-policy-core/src/bin/savana-development-material.rs");
    let source = fs::read_to_string(helper).unwrap();
    assert!(source.contains("account_identity(\"_savana_ingress_dev\")?"));
    assert!(source.contains("&[\"parser\", \"file_owner_uid\"]"));
    assert!(source.contains("&[\"parser\", \"file_owner_gid\"]"));
    assert!(source.contains("let connector_authority = if connector_authority_enabled"));
    assert!(source.contains("connector-authority-v2.seed"));
    assert!(source.contains("connector_authority: connector_authority.as_ref()"));
    assert!(source.contains("fn connector_authority_mode("));
    for path in [
        "state/kerneld/kernel-agent-authority-state-v2.cbor",
        "state/kerneld/kernel-g4-state-v2.cbor",
        "state/agentd/agent-task-state-v2.cbor",
        "state/approvald/approval-protocol-state-v2.cbor",
        "state/execd/execd-journal-v2.cbor",
        "state/execd/connector-registry-v2.cbor",
        "state/execd/connector-registry-anchor-v2.bin",
    ] {
        assert!(source.contains(path), "missing exact durable path: {path}");
    }
    assert!(source.contains("provider-server-spki-v2.der"));
    assert!(source.contains("&[\"provider\", \"server_spki_sha256\"]"));
}

#[test]
fn installer_requires_connector_authority_private_material_exactly_when_enabled() {
    let source =
        fs::read_to_string(deployment_root().join("deploy/macos/development/install.sh")).unwrap();
    assert!(source.contains(
        "connector_authority_credential=\"$install_root/credentials/kerneld/connector-authority-v2.seed\""
    ));
    assert!(source
        .contains("disabled connector authority unexpectedly materialized a private credential"));
    assert!(source.contains("enabled connector authority has incomplete private material"));
    assert!(source.contains("/usr/bin/stat -f %z \"$connector_authority_credential\""));
    assert!(source.contains("provider-server.spki.der"));
    assert!(source.contains("provider-server-spki-v2.der"));
}

#[test]
fn installer_and_validator_close_over_the_signed_tool_descriptor() {
    let scripts = deployment_root().join("deploy/macos/development");
    let install = fs::read_to_string(scripts.join("install.sh")).unwrap();
    let validate = fs::read_to_string(scripts.join("validate.sh")).unwrap();
    assert!(
        install.contains("\"$build_directory/artifacts/development-draft-report-tool-v2.cbor\"")
    );
    assert!(
        install.contains("\"$install_root/config/policy/development-draft-report-tool-v2.cbor\"")
    );
    assert!(validate.contains("development-draft-report-tool-v2.cbor"));
}

#[test]
fn planner_privacy_deployment_provisions_distinct_mapper_identity_and_private_credentials() {
    let root = deployment_root();
    let install = fs::read_to_string(root.join("deploy/macos/development/install.sh")).unwrap();
    let validate = fs::read_to_string(root.join("deploy/macos/development/validate.sh")).unwrap();
    let systemd = fs::read_to_string(root.join("deploy/systemd/savana-agentd.service")).unwrap();

    assert!(validate.contains("mapper-server.ext"));
    assert!(install
        .contains("issue_runtime_certificate mapper-server mapper.savana-development.invalid"));
    assert!(install
        .contains("issue_runtime_certificate mapper-client savana-agentd-mapper-development"));
    assert!(install.contains("mapper-server.spki.der"));
    assert!(install.contains("mapper-server-spki-v2.der"));
    assert!(install.contains("credentials/agentd/mapper-root-v2.der"));
    assert!(install.contains("credentials/agentd/mapper-client-v2.der"));
    assert!(install.contains("credentials/agentd/mapper-client-v2.pk8"));
    assert!(install.contains("mapper-server.cert.pem mapper-server.key.pem"));

    for credential in [
        "mapper-root-v2.der",
        "mapper-client-v2.der",
        "mapper-client-v2.pk8",
    ] {
        assert!(systemd.contains(&format!("LoadCredentialEncrypted={credential}:")));
    }
    assert!(systemd.contains("IPAddressDeny=any"));
    assert!(!systemd.contains("IPAddressAllow="));
    assert!(systemd.contains(
        "ExecStartPre=/usr/libexec/savana/savana-systemd-agentd-network-policy-v2 validate /etc/savana/agentd-bootstrap-v2.json"
    ));
}

#[test]
fn mapper_tls_profile_executes_to_distinct_server_auth_identity() {
    let fixture = tempfile::tempdir().unwrap();
    let ca_key = fixture.path().join("ca.key.pem");
    let ca_cert = fixture.path().join("ca.cert.pem");
    assert!(Command::new("/usr/bin/openssl")
        .args(["req", "-x509", "-newkey", "rsa:2048", "-nodes"])
        .args(["-keyout", ca_key.to_str().unwrap()])
        .args(["-out", ca_cert.to_str().unwrap()])
        .args(["-days", "1", "-subj", "/CN=Savana test CA"])
        .status()
        .unwrap()
        .success());

    let mut certificates = Vec::new();
    for (leaf, host, profile) in [
        (
            "planner",
            "planner.savana-development.invalid",
            "planner-server.ext",
        ),
        (
            "mapper",
            "mapper.savana-development.invalid",
            "mapper-server.ext",
        ),
    ] {
        let key = fixture.path().join(format!("{leaf}.key.pem"));
        let csr = fixture.path().join(format!("{leaf}.csr.pem"));
        let certificate = fixture.path().join(format!("{leaf}.cert.pem"));
        let serial = fixture.path().join(format!("{leaf}.srl"));
        assert!(Command::new("/usr/bin/openssl")
            .args(["req", "-new", "-newkey", "rsa:2048", "-nodes"])
            .args(["-keyout", key.to_str().unwrap()])
            .args(["-out", csr.to_str().unwrap()])
            .args(["-subj", &format!("/CN={host}")])
            .status()
            .unwrap()
            .success());
        assert!(Command::new("/usr/bin/openssl")
            .args(["x509", "-req", "-in", csr.to_str().unwrap()])
            .args(["-CA", ca_cert.to_str().unwrap()])
            .args(["-CAkey", ca_key.to_str().unwrap()])
            .args(["-CAserial", serial.to_str().unwrap(), "-CAcreateserial"])
            .args(["-out", certificate.to_str().unwrap(), "-days", "1"])
            .args([
                "-extfile",
                deployment_root()
                    .join("deploy/macos/development/tls")
                    .join(profile)
                    .to_str()
                    .unwrap(),
            ])
            .status()
            .unwrap()
            .success());
        assert!(Command::new("/usr/bin/openssl")
            .args(["verify", "-CAfile", ca_cert.to_str().unwrap()])
            .arg(&certificate)
            .status()
            .unwrap()
            .success());
        let certificate_text = Command::new("/usr/bin/openssl")
            .args([
                "x509",
                "-in",
                certificate.to_str().unwrap(),
                "-text",
                "-noout",
            ])
            .output()
            .unwrap();
        assert!(certificate_text.status.success());
        let certificate_text = String::from_utf8(certificate_text.stdout).unwrap();
        assert!(certificate_text.contains(&format!("DNS:{host}")));
        assert!(certificate_text.contains("TLS Web Server Authentication"));

        let public_key = Command::new("/usr/bin/openssl")
            .args([
                "x509",
                "-in",
                certificate.to_str().unwrap(),
                "-pubkey",
                "-noout",
            ])
            .output()
            .unwrap();
        assert!(public_key.status.success());
        let mut spki_command = Command::new("/usr/bin/openssl")
            .args(["pkey", "-pubin", "-outform", "DER"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        spki_command
            .stdin
            .as_mut()
            .unwrap()
            .write_all(&public_key.stdout)
            .unwrap();
        let spki = spki_command.wait_with_output().unwrap();
        assert!(spki.status.success());
        certificates.push(spki.stdout);
    }
    assert_ne!(certificates[0], certificates[1]);
}

#[test]
fn validator_never_executes_artifacts_from_the_untrusted_build_directory() {
    let validate =
        fs::read_to_string(deployment_root().join("deploy/macos/development/validate.sh")).unwrap();
    assert!(!validate.contains("--validate-connector-host-v2"));
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
    let bridge = fixture.path().join("bin/savana-development-audit-bridge");
    fs::copy(&executable, &bridge).unwrap();
    fs::set_permissions(&bridge, fs::Permissions::from_mode(0o755)).unwrap();
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
    let zero = "00".repeat(32);
    let genesis = "11".repeat(32);
    let valid_agentd = serde_json::json!({
        "planner_catalog_state_path":
            "/Library/Application Support/Savana/Development/state/agentd/planner-catalog-state-v2.cbor",
        "planner_catalog_rollback_anchor_path":
            "/Library/Application Support/Savana/Development/state/agentd/planner-catalog-anchor-v2.cbor",
        "planner_catalog_store_id": "44".repeat(32),
        "planner_shipped_catalog": [{
            "tool_class": 202,
            "action_template": 102,
            "structural_role": 3,
            "effects": 1,
            "semantic_name": "development.draft_due_diligence_report",
            "semantic_description":
                "development shipped due diligence report drafting tool"
        }],
        "planner_host": "planner.savana-development.invalid",
        "planner_port": 9443,
        "planner_connect_addresses": ["127.0.0.1:9443"],
        "planner_server_spki_sha256": "22".repeat(32),
        "intent_trust_deployment_ceiling": 1,
        "private_mapper_host": "mapper.savana-development.invalid",
        "private_mapper_port": 9445,
        "private_mapper_connect_addresses": ["127.0.0.1:9445"],
        "private_mapper_server_spki_sha256": "33".repeat(32)
    });
    fs::write(
        fixture.path().join("config/agentd-bootstrap-v2.json"),
        serde_json::to_vec(&valid_agentd).unwrap(),
    )
    .unwrap();
    fs::write(
        fixture.path().join("config/kerneld-bootstrap-v2.json"),
        serde_json::to_vec(&serde_json::json!({
            "policy_runtime": {
                "executor_connector_registry_digest": genesis,
                "connector_registry_genesis_digest": genesis,
                "connector_authority_key_id": zero,
                "connector_authority_public_key": zero,
                "user_tier_host_allowlist": []
            }
        }))
        .unwrap(),
    )
    .unwrap();
    for leaf in [
        "declassification-installer-root-v2.json",
        "declassification-rule-set-v2.cbor",
        "declassification-trust-root-set-v2.cbor",
        "development-draft-report-tool-v2.cbor",
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
        "savana-development-attestation-root",
        "savana-macos-code-identity",
    ] {
        let path = fixture.path().join("libexec").join(helper);
        fs::write(&path, b"#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    let validator_marker = fixture.path().join("untrusted-validator-executed");
    let untrusted_validator = fixture
        .path()
        .join("libexec/savana-development-build-inputs");
    fs::write(
        &untrusted_validator,
        b"#!/bin/sh\n: > \"$SAVANA_VALIDATOR_MARKER\"\nexit 0\n",
    )
    .unwrap();
    fs::set_permissions(&untrusted_validator, fs::Permissions::from_mode(0o755)).unwrap();

    let output = Command::new(deployment_root().join("deploy/macos/development/validate.sh"))
        .arg(fixture.path())
        .env("SAVANA_VALIDATOR_MARKER", &validator_marker)
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
    assert!(stdout.contains("planned logical development authority ID: SAVANADEV1"));
    assert!(
        !validator_marker.exists(),
        "validator executed an untrusted build-directory artifact"
    );

    let kerneld_path = fixture.path().join("config/kerneld-bootstrap-v2.json");
    let mut kerneld: serde_json::Value =
        serde_json::from_slice(&fs::read(&kerneld_path).unwrap()).unwrap();
    kerneld["policy_runtime"]["connector_authority_public_key"] =
        serde_json::Value::String("22".repeat(32));
    fs::write(&kerneld_path, serde_json::to_vec(&kerneld).unwrap()).unwrap();
    assert_eq!(
        Command::new(deployment_root().join("deploy/macos/development/validate.sh"))
            .arg(fixture.path())
            .status()
            .unwrap()
            .code(),
        Some(66)
    );
    kerneld["policy_runtime"]["connector_authority_public_key"] =
        serde_json::Value::String("00".repeat(32));
    fs::write(&kerneld_path, serde_json::to_vec(&kerneld).unwrap()).unwrap();

    for invalid_host in [
        "bad..example.com",
        "-bad.example",
        "bad_.example",
        "192.0.002.1",
        "[2001:0db8::1]",
        "bücher.example",
        "0x7f.0.0.1",
        "example.1",
        "example.077",
    ] {
        kerneld["policy_runtime"]["user_tier_host_allowlist"] = serde_json::json!([invalid_host]);
        fs::write(&kerneld_path, serde_json::to_vec(&kerneld).unwrap()).unwrap();
        assert_eq!(
            Command::new(deployment_root().join("deploy/macos/development/validate.sh"))
                .arg(fixture.path())
                .status()
                .unwrap()
                .code(),
            Some(66),
            "validator accepted noncanonical connector host {invalid_host:?}"
        );
    }

    kerneld["policy_runtime"]["user_tier_host_allowlist"] = serde_json::Value::Array(
        (0..=4_096)
            .map(|index| serde_json::Value::String(format!("host{index:04}.example")))
            .collect(),
    );
    fs::write(&kerneld_path, serde_json::to_vec(&kerneld).unwrap()).unwrap();
    assert_eq!(
        Command::new(deployment_root().join("deploy/macos/development/validate.sh"))
            .arg(fixture.path())
            .status()
            .unwrap()
            .code(),
        Some(66),
        "validator accepted more than 4096 connector hosts"
    );

    kerneld["policy_runtime"]["user_tier_host_allowlist"] =
        serde_json::json!(["192.0.2.1", "example.com", "xn--bcher-kva.example"]);
    fs::write(&kerneld_path, serde_json::to_vec(&kerneld).unwrap()).unwrap();
    assert!(
        Command::new(deployment_root().join("deploy/macos/development/validate.sh"))
            .arg(fixture.path())
            .env("SAVANA_VALIDATOR_MARKER", &validator_marker)
            .status()
            .unwrap()
            .success(),
        "validator rejected canonical connector hosts"
    );
    assert!(
        !validator_marker.exists(),
        "validator executed an untrusted build-directory artifact while checking hosts"
    );

    let agentd_path = fixture.path().join("config/agentd-bootstrap-v2.json");
    for (name, invalid) in [
        {
            let mut value = valid_agentd.clone();
            value
                .as_object_mut()
                .unwrap()
                .remove("intent_trust_deployment_ceiling");
            ("missing ceiling", value)
        },
        {
            let mut value = valid_agentd.clone();
            value["intent_trust_deployment_ceiling"] = serde_json::json!(0);
            ("zero ceiling", value)
        },
        {
            let mut value = valid_agentd.clone();
            value["intent_trust_deployment_ceiling"] = serde_json::json!(3);
            ("unknown ceiling", value)
        },
        {
            let mut value = valid_agentd.clone();
            value["private_mapper_server_spki_sha256"] =
                value["planner_server_spki_sha256"].clone();
            ("aliased private mapper pin", value)
        },
        {
            let mut value = valid_agentd.clone();
            value["planner_connect_addresses"] = serde_json::json!([]);
            ("empty planner connect addresses", value)
        },
        {
            let mut value = valid_agentd.clone();
            value["planner_connect_addresses"] =
                serde_json::json!(["127.0.0.1:9443", "127.0.0.1:9443"]);
            ("duplicate planner connect addresses", value)
        },
        {
            let mut value = valid_agentd.clone();
            value["planner_connect_addresses"] =
                serde_json::json!(["127.0.0.2:9443", "127.0.0.1:9443"]);
            ("unsorted planner connect addresses", value)
        },
        {
            let mut value = valid_agentd.clone();
            value["planner_connect_addresses"] = serde_json::json!(["0.0.0.0:9443"]);
            ("unsafe planner connect address", value)
        },
        {
            let mut value = valid_agentd.clone();
            value["private_mapper_connect_addresses"] = serde_json::json!(["127.0.0.1:9444"]);
            ("mapper connect address port mismatch", value)
        },
        {
            let mut value = valid_agentd.clone();
            value["planner_catalog_state_path"] =
                serde_json::json!("/tmp/planner-catalog-state-v2.cbor");
            ("catalog outside private state", value)
        },
        {
            let mut value = valid_agentd.clone();
            value["planner_catalog_rollback_anchor_path"] = serde_json::json!(
                "/Library/Application Support/Savana/Development/state/agentd/../planner-catalog-anchor-v2.cbor"
            );
            ("catalog parent traversal", value)
        },
        {
            let mut value = valid_agentd.clone();
            value["planner_shipped_catalog"]
                .as_array_mut()
                .unwrap()
                .push(serde_json::json!({
                    "tool_class": 999,
                    "action_template": 999,
                    "structural_role": 1,
                    "effects": 1,
                    "semantic_name": "unmeasured",
                    "semantic_description": "not part of the measured development deployment"
                }));
            ("unmeasured catalog row", value)
        },
    ] {
        fs::write(&agentd_path, serde_json::to_vec(&invalid).unwrap()).unwrap();
        assert_eq!(
            Command::new(deployment_root().join("deploy/macos/development/validate.sh"))
                .arg(fixture.path())
                .status()
                .unwrap()
                .code(),
            Some(66),
            "validator accepted {name}"
        );
    }
    fs::write(&agentd_path, serde_json::to_vec(&valid_agentd).unwrap()).unwrap();

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

#[test]
fn build_input_generator_emits_cryptographically_bound_runtime_inputs() {
    let fixture = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_savana-development-build-inputs"))
        .arg(fixture.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let config = fixture.path().join("config");
    let artifacts = fixture.path().join("artifacts");
    let template: serde_json::Value = serde_json::from_slice(
        &fs::read(config.join("development-manifest-template-v2.json")).unwrap(),
    )
    .unwrap();
    let kerneld: serde_json::Value =
        serde_json::from_slice(&fs::read(config.join("kerneld-bootstrap-v2.json")).unwrap())
            .unwrap();
    let agentd: serde_json::Value =
        serde_json::from_slice(&fs::read(config.join("agentd-bootstrap-v2.json")).unwrap())
            .unwrap();
    assert_eq!(
        kerneld["agent_authority_state_path"].as_str(),
        Some(
            "/Library/Application Support/Savana/Development/state/kerneld/kernel-agent-authority-state-v2.cbor"
        )
    );
    assert_eq!(
        kerneld["g4_state_path"].as_str(),
        Some(
            "/Library/Application Support/Savana/Development/state/kerneld/kernel-g4-state-v2.cbor"
        )
    );
    assert_eq!(
        agentd["task_state_path"].as_str(),
        Some(
            "/Library/Application Support/Savana/Development/state/agentd/agent-task-state-v2.cbor"
        )
    );
    let approvald: serde_json::Value =
        serde_json::from_slice(&fs::read(config.join("approvald-bootstrap-v2.json")).unwrap())
            .unwrap();
    assert_eq!(
        approvald["state_path"].as_str(),
        Some(
            "/Library/Application Support/Savana/Development/state/approvald/approval-protocol-state-v2.cbor"
        )
    );
    let execd: serde_json::Value =
        serde_json::from_slice(&fs::read(config.join("execd-bootstrap-v2.json")).unwrap()).unwrap();
    let zero_digest = "00".repeat(32);
    assert_eq!(
        execd["journal_path"].as_str(),
        Some("/Library/Application Support/Savana/Development/state/execd/execd-journal-v2.cbor")
    );
    assert_eq!(
        execd["connector_registry_path"].as_str(),
        Some(
            "/Library/Application Support/Savana/Development/state/execd/connector-registry-v2.cbor"
        )
    );
    assert_eq!(
        execd["connector_registry_anchor_path"].as_str(),
        Some(
            "/Library/Application Support/Savana/Development/state/execd/connector-registry-anchor-v2.bin"
        )
    );
    assert_ne!(execd["store_id"], execd["connector_registry_store_id"]);
    assert_eq!(
        execd["connector_set_digest"],
        execd["connector_registry_genesis_digest"]
    );
    assert_eq!(
        execd["connector_authority_key_id"].as_str(),
        Some(zero_digest.as_str())
    );
    assert_eq!(
        execd["connector_authority_public_key"].as_str(),
        Some(zero_digest.as_str())
    );
    assert_eq!(
        execd["provider"]["canonical_url"].as_str(),
        Some("https://provider.savana-development.invalid:9444/")
    );
    assert_ne!(
        hex_32(execd["provider"]["server_spki_sha256"].as_str().unwrap()),
        [0; 32]
    );
    assert_eq!(agentd["planner_route_id"].as_u64(), Some(1));
    assert_eq!(
        agentd["planner_catalog_state_path"].as_str(),
        Some(
            "/Library/Application Support/Savana/Development/state/agentd/planner-catalog-state-v2.cbor"
        )
    );
    assert_eq!(
        agentd["planner_catalog_rollback_anchor_path"].as_str(),
        Some(
            "/Library/Application Support/Savana/Development/state/agentd/planner-catalog-anchor-v2.cbor"
        )
    );
    assert_ne!(
        hex_32(agentd["planner_catalog_store_id"].as_str().unwrap()),
        [0; 32]
    );
    assert_eq!(
        agentd["planner_shipped_catalog"].as_array().unwrap().len(),
        1
    );
    assert_eq!(
        agentd["planner_shipped_catalog"][0],
        serde_json::json!({
            "tool_class": 202,
            "action_template": 102,
            "structural_role": 3,
            "effects": 1,
            "semantic_name": "development.draft_due_diligence_report",
            "semantic_description":
                "development shipped due diligence report drafting tool"
        })
    );
    assert_eq!(
        agentd["planner_host"].as_str(),
        Some("planner.savana-development.invalid")
    );
    assert_eq!(agentd["planner_port"].as_u64(), Some(9443));
    assert_eq!(
        agentd["planner_connect_addresses"],
        serde_json::json!(["127.0.0.1:9443"])
    );
    assert_eq!(
        agentd["private_mapper_host"].as_str(),
        Some("mapper.savana-development.invalid")
    );
    assert_eq!(agentd["private_mapper_port"].as_u64(), Some(9445));
    assert_eq!(
        agentd["private_mapper_connect_addresses"],
        serde_json::json!(["127.0.0.1:9445"])
    );
    assert_eq!(agentd["intent_trust_deployment_ceiling"].as_u64(), Some(1));
    let planner_pin = hex_32(agentd["planner_server_spki_sha256"].as_str().unwrap());
    let mapper_pin = hex_32(
        agentd["private_mapper_server_spki_sha256"]
            .as_str()
            .unwrap(),
    );
    assert_ne!(planner_pin, [0; 32]);
    assert_ne!(mapper_pin, [0; 32]);
    assert_ne!(planner_pin, mapper_pin);
    let jarvis_entitlements = fs::read_to_string(
        fixture
            .path()
            .join("entitlements/com.savana.development.jarvis-python.plist"),
    )
    .unwrap();
    assert!(jarvis_entitlements
        .contains("<key>com.apple.security.cs.disable-library-validation</key><true/>"));

    let projection_key = hex_32(
        template["ledger_projection_signing_public_key"]
            .as_str()
            .unwrap(),
    );
    let projection_key_id = Ed25519KeyIdV2::new(hex_32(
        template["ledger_projection_signing_key_id"]
            .as_str()
            .unwrap(),
    ));
    assert_eq!(derive_ed25519_key_id_v2(projection_key), projection_key_id);
    let projection_binding = EffectLedgerProjectionBindingV2::from_verified_deployment(
        Digest32V2::new(hex_32(template["installation_id"].as_str().unwrap())),
        Digest32V2::new(hex_32(
            template["active_state_manifest_digest"].as_str().unwrap(),
        )),
        template["deployment_generation"].as_u64().unwrap(),
        template["effect_fence_epoch"].as_u64().unwrap(),
        Digest32V2::new(hex_32(
            template["ledger_projection_identity"].as_str().unwrap(),
        )),
        Digest32V2::new(hex_32(
            template["effect_ledger_head_digest"].as_str().unwrap(),
        )),
        projection_key_id,
        projection_key,
    )
    .unwrap();
    savana_kernel_protocol::v2::verify_effect_ledger_projection_v2(
        &fs::read(artifacts.join("effect-ledger-projection-v2.cbor")).unwrap(),
        projection_binding,
    )
    .unwrap();

    let input_key = hex_32(
        kerneld["input_runtime_publisher_public_key"]
            .as_str()
            .unwrap(),
    );
    let input_key_id = Ed25519KeyIdV2::new(hex_32(
        kerneld["input_runtime_publisher_key_id"].as_str().unwrap(),
    ));
    assert_eq!(derive_ed25519_key_id_v2(input_key), input_key_id);
    let input = fs::read(artifacts.join("input-runtime-assets-v2.cbor")).unwrap();
    let input = SignedInputRuntimeAssetsV2::from_canonical_bytes(&input).unwrap();
    VerifiedInputRuntimeAssetsV2::verify(
        &input,
        input_key_id,
        input_key,
        UnixMillisV2::new(current_unix_millis()),
    )
    .unwrap();

    let declassification_installer: serde_json::Value = serde_json::from_slice(
        &fs::read(artifacts.join("declassification-installer-root-v2.json")).unwrap(),
    )
    .unwrap();
    let declassification_verifier = InstallerOrMdmVerifierV2::new(
        Ed25519KeyIdV2::new(hex_32(
            declassification_installer["key_id"].as_str().unwrap(),
        )),
        declassification_installer["key_epoch"].as_u64().unwrap(),
        hex_32(declassification_installer["public_key"].as_str().unwrap()),
    )
    .unwrap();
    let declassification_roots = OperationalTrustRootSetV2::from_canonical_bytes(
        &fs::read(artifacts.join("declassification-trust-root-set-v2.cbor")).unwrap(),
        &declassification_verifier,
    )
    .unwrap();
    let declassification_rules = DeclassificationRuleSetV2::from_canonical_bytes(
        &fs::read(artifacts.join("declassification-rule-set-v2.cbor")).unwrap(),
        &declassification_roots,
        current_unix_millis(),
    )
    .unwrap();
    assert_eq!(declassification_rules.rules().len(), 5);
    assert_eq!(
        declassification_rules
            .rules()
            .iter()
            .map(|rule| rule.purpose())
            .collect::<Vec<_>>(),
        ClosedDeclassificationPurposeV2::ALL
    );
    assert_eq!(
        declassification_rules.signed_digest().as_bytes(),
        &hex_32(
            template["declassification_rule_set_digest"]
                .as_str()
                .unwrap()
        )
    );
    assert_eq!(
        kerneld["declassification_rule_set_path"].as_str(),
        Some(
            "/Library/Application Support/Savana/Development/config/policy/declassification-rule-set-v2.cbor"
        )
    );

    let policy = &kerneld["policy_runtime"];
    let disabled = "00".repeat(32);
    assert_eq!(
        policy["connector_registry_genesis_digest"],
        policy["executor_connector_registry_digest"]
    );
    assert_eq!(
        policy["connector_authority_key_id"].as_str(),
        Some(disabled.as_str())
    );
    assert_eq!(
        policy["connector_authority_public_key"].as_str(),
        Some(disabled.as_str())
    );
    assert!(policy["user_tier_host_allowlist"]
        .as_array()
        .unwrap()
        .is_empty());
    let registry_key = hex_32(policy["registry_publisher_public_key"].as_str().unwrap());
    let registry_key_id = Ed25519KeyIdV2::new(hex_32(
        policy["registry_publisher_key_id"].as_str().unwrap(),
    ));
    assert_eq!(derive_ed25519_key_id_v2(registry_key), registry_key_id);
    let publisher = VerifiedRegistryPublisherV2::from_verified_manifest(
        registry_key_id,
        registry_key,
        UnixMillisV2::new(policy["registry_not_before"].as_u64().unwrap()),
        UnixMillisV2::new(policy["registry_expires_at"].as_u64().unwrap()),
    )
    .unwrap();
    let descriptor = fs::read(artifacts.join("development-draft-report-tool-v2.cbor")).unwrap();
    let descriptor = SignedToolDescriptorV2::from_canonical_bytes(&descriptor)
        .unwrap()
        .verify(
            &publisher,
            VersionV2::new(2, 0, 0),
            UnixMillisV2::new(current_unix_millis()),
        )
        .unwrap();
    assert_eq!(descriptor.unsigned().action_template().get(), 102);
    assert_eq!(descriptor.unsigned().tool_class().get(), 202);
    assert_eq!(descriptor.unsigned().effects(), EffectSetV2::READ);
    assert_eq!(
        descriptor.unsigned().attempt_kind(),
        AttemptKindV2::ToolRead
    );
    let expected_digest = policy["policy_activations"][0]["descriptor_digest"]
        .as_str()
        .unwrap();
    assert_eq!(
        descriptor.descriptor_digest().as_bytes(),
        &hex_32(expected_digest)
    );
    assert_eq!(
        policy["manifest_constraints"][0]["descriptor_digest"]
            .as_str()
            .unwrap(),
        expected_digest
    );
}

fn current_unix_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .try_into()
        .unwrap()
}

fn hex_32(value: &str) -> [u8; 32] {
    assert_eq!(value.len(), 64);
    let mut output = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let pair = std::str::from_utf8(pair).unwrap();
        output[index] = u8::from_str_radix(pair, 16).unwrap();
    }
    output
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
