use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

const UNIT_DIRECTORY: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../deploy/systemd");
const CONFIG_DIRECTORY: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../deploy/config");

#[test]
fn production_units_fix_every_listener_and_required_hardening_control() {
    let directory = Path::new(UNIT_DIRECTORY);
    let expected_descriptors = BTreeSet::from([
        "savana-agent-kernel",
        "savana-ingress-kernel",
        "savana-kernel-executor",
        "savana-agent-approval",
        "savana-ingress-approval",
        "savana-admin-approval",
        "savana-approval-http",
        "savana-jarvis-agent-control",
        "savana-jarvis-http",
        "savana-agent-http",
        "savana-ingress-http",
    ])
    .into_iter()
    .map(str::to_owned)
    .collect();
    let mut observed_descriptors = BTreeSet::new();
    let mut observed_ports = BTreeSet::new();
    let mut services = 0;
    let mut deployment_services = 0;
    for entry in fs::read_dir(directory).unwrap() {
        let path = entry.unwrap().path();
        let body = fs::read_to_string(&path).unwrap();
        match path.extension().and_then(|value| value.to_str()) {
            Some("service") => {
                let deployment_service = path
                    .file_name()
                    .and_then(|value| value.to_str())
                    .is_some_and(|name| name.starts_with("savana-deploy"));
                if deployment_service {
                    deployment_services += 1;
                    for required in [
                        "User=root",
                        "Group=root",
                        "UMask=0077",
                        "NoNewPrivileges=yes",
                        "PrivateTmp=yes",
                        "ProtectSystem=strict",
                        "ProtectHome=yes",
                        "MemoryDenyWriteExecute=yes",
                        "RestrictNamespaces=yes",
                        "RestrictAddressFamilies=AF_UNIX",
                        "IPAddressDeny=any",
                        "SocketBindDeny=any",
                    ] {
                        assert!(
                            body.lines().any(|line| line == required),
                            "{} omits {required}",
                            path.display()
                        );
                    }
                    assert!(!body.contains("LoadCredential"));
                    continue;
                }
                services += 1;
                for required in [
                    "UMask=0077",
                    "RuntimeDirectoryMode=0711",
                    "NoNewPrivileges=yes",
                    "CapabilityBoundingSet=",
                    "AmbientCapabilities=",
                    "PrivateTmp=yes",
                    "PrivateDevices=yes",
                    "DevicePolicy=closed",
                    "ProtectSystem=strict",
                    "ProtectHome=yes",
                    "ProtectKernelTunables=yes",
                    "ProtectKernelModules=yes",
                    "ProtectKernelLogs=yes",
                    "ProtectControlGroups=yes",
                    "ProtectClock=yes",
                    "ProtectHostname=yes",
                    "ProtectProc=invisible",
                    "ProcSubset=pid",
                    "LockPersonality=yes",
                    "MemoryDenyWriteExecute=yes",
                    "RestrictRealtime=yes",
                    "RestrictSUIDSGID=yes",
                    "RestrictNamespaces=yes",
                    "RemoveIPC=yes",
                    "KeyringMode=private",
                    "SystemCallArchitectures=native",
                    "SocketBindDeny=any",
                ] {
                    assert!(
                        body.lines().any(|line| line == required),
                        "{} omits {required}",
                        path.display()
                    );
                }
                assert!(!body.contains("LoadCredential="));
                assert!(body.contains("LoadCredentialEncrypted="));
                if body.contains("StateDirectory=") {
                    assert!(
                        body.lines().any(|line| line == "StateDirectoryMode=0700"),
                        "{} does not keep its durable state private",
                        path.display()
                    );
                }
            }
            Some("socket") => {
                let descriptor = body
                    .lines()
                    .find_map(|line| line.strip_prefix("FileDescriptorName="))
                    .unwrap();
                assert!(observed_descriptors.insert(descriptor.to_owned()));
                if let Some(port) = body.lines().find_map(|line| {
                    line.strip_prefix("ListenStream=127.0.0.1:")
                        .and_then(|value| value.parse::<u16>().ok())
                }) {
                    assert!(observed_ports.insert(port));
                }
                assert!(!body.contains("ListenStream=0.0.0.0"));
                assert!(!body.contains("ListenStream=[::]"));
            }
            _ => {}
        }
    }
    assert_eq!(services, 5);
    assert_eq!(deployment_services, 2);
    assert_eq!(observed_descriptors, expected_descriptors);
    assert_eq!(observed_ports, BTreeSet::from([8765, 8766, 8767, 8768]));
}

#[test]
fn deployment_recovery_gate_and_private_store_layout_are_fixed() {
    let directory = Path::new(UNIT_DIRECTORY);
    let kernel_target = fs::read_to_string(directory.join("savana-kernel.target")).unwrap();
    assert!(kernel_target.contains("Requires=savana-deployment-recovery.target "));
    assert!(kernel_target.contains("After=savana-deployment-recovery.target "));

    let recovery = fs::read_to_string(directory.join("savana-deployment-recovery.target")).unwrap();
    assert!(recovery.contains("Requires=savana-deploy-watchdog.service"));
    assert!(recovery.contains("Before=savana-kernel.target"));
    let watchdog = fs::read_to_string(directory.join("savana-deploy-watchdog.service")).unwrap();
    assert!(watchdog.contains("Type=notify"));
    assert!(watchdog.contains("Before=savana-deployment-recovery.target savana-kernel.target"));
    let apply = fs::read_to_string(directory.join("savana-deploy@.service")).unwrap();
    assert!(apply.contains("ExecStart=/usr/libexec/savana/savana-deploy apply %i"));
    assert!(apply.contains("Conflicts=savana-kernel.target"));

    let tmpfiles = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/tmpfiles/savana-deployment.conf"),
    )
    .unwrap();
    for path in [
        "/var/lib/savana/deployment",
        "/var/lib/savana/deployment/auxiliary-evidence",
        "/var/lib/savana/deployment/evidence",
        "/var/lib/savana/deployment/evidence-gc-checkpoints",
        "/var/lib/savana/deployment/transaction-cores",
        "/var/lib/savana/deployment/transaction-heads",
        "/var/lib/savana-deploy/spool/ready",
        "/var/lib/savana-deploy/store/sha256",
    ] {
        assert!(
            tmpfiles
                .lines()
                .any(|line| line.starts_with(&format!("d {path} 0700 root root "))),
            "missing private tmpfiles entry for {path}"
        );
    }
}

#[test]
fn live_kernel_clients_expose_only_sighup_reload_to_systemd() {
    for unit in ["savana-agentd.service", "savana-ingressd.service"] {
        let body = fs::read_to_string(Path::new(UNIT_DIRECTORY).join(unit)).unwrap();
        assert!(body
            .lines()
            .any(|line| line == "ExecReload=/bin/kill -HUP $MAINPID"));
        assert_eq!(
            body.lines()
                .filter(|line| line.starts_with("ExecReload="))
                .count(),
            1,
            "{unit} must have one closed reload action"
        );
    }
}

#[test]
fn role_socket_groups_and_bootstrap_observation_shape_are_exact() {
    let unit = |name: &str| {
        fs::read_to_string(Path::new(UNIT_DIRECTORY).join(name))
            .unwrap_or_else(|error| panic!("cannot read {name}: {error}"))
    };
    for (name, user, group) in [
        (
            "savana-kerneld-agent.socket",
            "savana-kernel",
            "savana-agent",
        ),
        (
            "savana-kerneld-ingress.socket",
            "savana-kernel",
            "savana-ingress",
        ),
        ("savana-execd.socket", "savana-exec", "savana-kernel"),
        (
            "savana-approvald-agent.socket",
            "savana-approval",
            "savana-agent",
        ),
        (
            "savana-approvald-ingress.socket",
            "savana-approval",
            "savana-ingress",
        ),
    ] {
        let body = unit(name);
        assert!(body
            .lines()
            .any(|line| line == format!("SocketUser={user}")));
        assert!(body
            .lines()
            .any(|line| line == format!("SocketGroup={group}")));
        assert!(body.lines().any(|line| line == "SocketMode=0660"));
    }

    let observations: serde_json::Value = serde_json::from_slice(
        &fs::read(Path::new(CONFIG_DIRECTORY).join("service-observations-v2.example.json"))
            .unwrap(),
    )
    .unwrap();
    let services = observations.as_array().unwrap();
    assert_eq!(services.len(), 5);
    assert_eq!(
        services
            .iter()
            .map(|entry| entry["service"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["kerneld", "agentd", "ingressd", "approvald", "execd"]
    );
    assert_eq!(services[2]["endpoint"]["kind"], "loopback-tcp");
    assert_eq!(services[2]["endpoint"]["port"], 8767);
    assert_eq!(services[3]["endpoint"]["kind"], "loopback-tcp");
    assert_eq!(services[3]["endpoint"]["port"], 8766);
    assert!(services
        .iter()
        .all(|entry| entry["process_uid"].as_u64().is_some()
            && entry["process_gid"].as_u64().is_some()));
}
