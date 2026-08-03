use std::fs;
use std::path::Path;
use std::process::Command;

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_savana-systemd-agentd-network-policy-v2")
}

fn write_bootstrap(path: &Path, ceiling: u16, include_third_party: bool) {
    let mut value = serde_json::json!({
        "planner_host": "planner.example.invalid",
        "planner_port": 9443,
        "planner_connect_addresses": ["127.0.0.1:9443"],
        "private_mapper_host": "mapper.example.invalid",
        "private_mapper_port": 9445,
        "private_mapper_connect_addresses": ["127.0.0.1:9445"],
        "intent_trust_deployment_ceiling": ceiling
    });
    if include_third_party {
        value["third_party_mapper_host"] = serde_json::json!("mapper.tee.example");
        value["third_party_mapper_port"] = serde_json::json!(10445);
        value["third_party_mapper_server_spki_sha256"] = serde_json::json!("33".repeat(32));
        value["third_party_mapper_connect_addresses"] =
            serde_json::json!(["192.0.2.10:10445", "[2001:db8::10]:10445"]);
    }
    fs::write(path, serde_json::to_vec(&value).unwrap()).unwrap();
}

fn render(path: &Path) -> std::process::Output {
    Command::new(binary())
        .arg("render")
        .arg(path)
        .output()
        .unwrap()
}

#[test]
fn rendered_drop_in_is_exactly_bound_to_unique_measured_ips() {
    let fixture = tempfile::tempdir().unwrap();
    let bootstrap_path = fixture.path().join("agentd-bootstrap-v2.json");
    write_bootstrap(&bootstrap_path, 2, true);

    let output = render(&bootstrap_path);
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "[Service]\nIPAddressDeny=any\nIPAddressAllow=127.0.0.1\nIPAddressAllow=192.0.2.10\nIPAddressAllow=2001:db8::10\n"
    );

    assert!(!Command::new(binary())
        .arg("install")
        .arg(&bootstrap_path)
        .arg(fixture.path().join("attacker-chosen.conf"))
        .status()
        .unwrap()
        .success());
}

#[test]
fn renderer_rejects_noncanonical_unbounded_or_incomplete_measurements() {
    let fixture = tempfile::tempdir().unwrap();
    let bootstrap_path = fixture.path().join("agentd-bootstrap-v2.json");
    let invalid_lists = [
        serde_json::json!([]),
        serde_json::json!(["127.0.0.1:9443", "127.0.0.1:9443"]),
        serde_json::json!(["127.0.0.2:9443", "127.0.0.1:9443"]),
        serde_json::json!(["127.000.000.001:9443"]),
        serde_json::json!(["0.0.0.0:9443"]),
        serde_json::json!(["224.0.0.1:9443"]),
        serde_json::json!(["255.255.255.255:9443"]),
        serde_json::json!(["[::]:9443"]),
        serde_json::json!(["[ff02::1]:9443"]),
        serde_json::json!(["127.0.0.1:0"]),
        serde_json::json!(["127.0.0.1:9444"]),
        serde_json::json!([
            "127.0.0.1:9443",
            "127.0.0.2:9443",
            "127.0.0.3:9443",
            "127.0.0.4:9443",
            "127.0.0.5:9443",
            "127.0.0.6:9443",
            "127.0.0.7:9443",
            "127.0.0.8:9443",
            "127.0.0.9:9443"
        ]),
    ];
    for invalid in invalid_lists {
        let value = serde_json::json!({
            "planner_host": "planner.example.invalid",
            "planner_port": 9443,
            "planner_connect_addresses": invalid,
            "private_mapper_host": "mapper.example.invalid",
            "private_mapper_port": 9445,
            "private_mapper_connect_addresses": ["127.0.0.1:9445"],
            "intent_trust_deployment_ceiling": 1
        });
        fs::write(&bootstrap_path, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(!render(&bootstrap_path).status.success());
    }

    for incomplete in [
        serde_json::json!({
            "planner_host": "planner.example.invalid",
            "planner_port": 9443,
            "planner_connect_addresses": ["127.0.0.1:9443"],
            "private_mapper_host": "mapper.example.invalid",
            "private_mapper_port": 9445,
            "private_mapper_connect_addresses": ["127.0.0.1:9445"],
            "intent_trust_deployment_ceiling": 2,
            "third_party_mapper_host": "third.example"
        }),
        serde_json::json!({
            "planner_host": "planner.example.invalid",
            "planner_port": 9443,
            "planner_connect_addresses": ["127.0.0.1:9443"],
            "private_mapper_host": "mapper.example.invalid",
            "private_mapper_port": 9445,
            "private_mapper_connect_addresses": ["127.0.0.1:9445"],
            "intent_trust_deployment_ceiling": 2,
            "third_party_mapper_connect_addresses": ["192.0.2.1:10445"]
        }),
    ] {
        fs::write(&bootstrap_path, serde_json::to_vec(&incomplete).unwrap()).unwrap();
        assert!(!render(&bootstrap_path).status.success());
    }
}

#[test]
fn ceiling_and_third_party_network_closure_are_coherent() {
    let fixture = tempfile::tempdir().unwrap();
    let bootstrap_path = fixture.path().join("agentd-bootstrap-v2.json");
    for ceiling in [0, 3] {
        write_bootstrap(&bootstrap_path, ceiling, false);
        assert!(!render(&bootstrap_path).status.success());
    }
    write_bootstrap(&bootstrap_path, 1, true);
    assert!(!render(&bootstrap_path).status.success());
    write_bootstrap(&bootstrap_path, 1, false);
    assert!(render(&bootstrap_path).status.success());
    write_bootstrap(&bootstrap_path, 2, false);
    assert!(render(&bootstrap_path).status.success());
}

#[test]
fn base_service_is_fail_closed_and_requires_fixed_drop_in_validation() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let unit = fs::read_to_string(root.join("deploy/systemd/savana-agentd.service")).unwrap();
    assert!(unit.contains("IPAddressDeny=any"));
    assert!(!unit.contains("IPAddressAllow="));
    assert!(unit.contains(
        "ExecStartPre=/usr/libexec/savana/savana-systemd-agentd-network-policy-v2 validate /etc/savana/agentd-bootstrap-v2.json"
    ));
    assert!(!unit.contains("20-measured-network.conf "));
}
