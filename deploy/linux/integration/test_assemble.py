"""Configuration tests, NOT daemon/native deployment acceptance.

Set SAVANA_FRESH_TEST_TEMPLATES to a freshly generated synthetic template tree.
ELF-looking bytes below test authoring only; they are never executed/installed.
"""
import importlib.util
import hashlib
import json
import os
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric import ed25519


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


assemble = load("assemble")
install = load("install")
admin = load("admin")
REPO = Path(__file__).resolve().parents[3]
IDS = dict(zip((*assemble.SERVICES, "jarvis"), range(64001, 64007)))


@pytest.fixture
def inputs(tmp_path):
    source = os.environ.get("SAVANA_FRESH_TEST_TEMPLATES")
    if not source:
        pytest.skip("fresh synthetic Rust template output required")
    binaries = tmp_path / "binaries"
    binaries.mkdir()
    for name in [*("savana-" + s for s in assemble.SERVICES), "savana-worker-sandbox",
                 "savana-parser-worker", "savana-connector-worker", "savana-approvalctl",
                 "savana-linux-identity-broker", "savana-systemd-agentd-network-policy-v2",
                 "savana-linux-integration-manifest"]:
        (binaries / name).write_bytes(b"\x7fELFsynthetic-not-executable:" + name.encode())
    return Path(source), binaries, tmp_path / "stage"


@pytest.fixture
def stage(inputs):
    templates, binaries, out = inputs
    assemble.assemble(templates, binaries, REPO, out, IDS)
    return out


def config(stage, service):
    return json.loads((stage / f"etc/savana/{service}-bootstrap-v2.json").read_bytes())


def test_credentials_cover_every_enabled_unit(stage):
    install.validate_credential_coverage(stage, install.service_units(REPO))
    units = "\n".join(install.service_units(REPO).values())
    assert "final-release-provider-tls-private-key-v2.der" in units
    assert "kernel-approval-v04.seed" in units
    assert units.count("RuntimeDirectoryPreserve=yes") == 5
    approval = install.service_units(REPO)["/usr/lib/systemd/system/savana-approvald.service"]
    assert "RuntimeDirectory=savana/approvald\n" not in approval
    assert "StateDirectory=savana/approvald\n" in approval
    for service in ["kerneld", "execd"]:
        unit = install.service_units(REPO)[f"/usr/lib/systemd/system/savana-{service}.service"]
        assert "Type=notify\nNotifyAccess=main\n" in unit
        assert "TimeoutStartSec=120s\n" in unit


def test_missing_credential_rejected(stage):
    leaf = stage / "private/execd/final-release-provider-tls-private-key-v2.der"
    leaf.unlink()
    with pytest.raises(ValueError, match="missing integration credential"):
        install.validate_credential_coverage(stage, install.service_units(REPO))


def test_cross_service_boot_ids_and_isolation(stage):
    for name in ["kerneld", "approvald"]:
        leaves = list((stage / "private").glob("*/" + name + "-boot-v2.id"))
        assert len(leaves) > 1
        assert len({leaf.read_bytes() for leaf in leaves}) == 1
    for leaf in (stage / "private").rglob("*"):
        assert leaf.stat().st_mode & 0o777 == (0o700 if leaf.is_dir() else 0o600)
    observations = [config(stage, s)["services"] for s in assemble.SERVICES]
    assert all(value == observations[0] for value in observations)
    assert len({item["process_uid"] for item in observations[0]}) == 5


def test_kernel_approval_keys_match_and_are_separate(stage):
    seed = (stage / "private/kerneld/kernel-approval-v04.seed").read_bytes()
    public = ed25519.Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
    assert (stage / "etc/savana/keys/kernel-approval-v04.pub").read_bytes() == public
    assert seed != (stage / "private/kerneld/agent-kernel-v2.seed").read_bytes()
    assert config(stage, "kerneld")["kernel_approval"]["client_key_id"] == config(stage, "approvald")["kernel_approval"]["client_key_id"]


def test_agent_task_trust_verifies_correlation_not_authority_envelope(stage):
    from cryptography.exceptions import InvalidSignature
    correlation = ed25519.Ed25519PrivateKey.from_private_bytes(
        (stage / "private/kerneld/task-correlation-v2.seed").read_bytes())
    envelope = ed25519.Ed25519PrivateKey.from_private_bytes(
        (stage / "private/kerneld/authority-envelope-v2.seed").read_bytes())
    public = (stage / "etc/savana/agentd/keys/kerneld-task-authority-v2.pub").read_bytes()
    assert public == correlation.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
    assert public == (stage / "etc/savana/approvald/keys/kerneld-correlation-v2.pub").read_bytes()
    expected_id = hashlib.sha256(b"savana.ed25519-key-id.v2\0" + public).hexdigest()
    assert config(stage, "agentd")["kernel_task_authority_key_id"] == expected_id
    assert config(stage, "approvald")["kernel_correlation_key_id"] == expected_id
    message = b"synthetic-task-correlation-signature-check"
    verifier = ed25519.Ed25519PublicKey.from_public_bytes(public)
    verifier.verify(correlation.sign(message), message)
    with pytest.raises(InvalidSignature):
        verifier.verify(envelope.sign(message), message)


def test_approval_authority_pin_is_distinct_from_execution_and_correlation(stage):
    from cryptography.exceptions import InvalidSignature
    approval = config(stage, "approvald")
    authority = ed25519.Ed25519PrivateKey.from_private_bytes(
        (stage / "private/kerneld/authority-envelope-v2.seed").read_bytes())
    public = bytes.fromhex(approval["kernel_authority_envelope_public_key"])
    assert public == authority.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
    assert approval["kernel_authority_envelope_key_id"] == hashlib.sha256(
        b"savana.ed25519-key-id.v2\0" + public).hexdigest()
    message = b"synthetic-ui-authentication-envelope"
    verifier = ed25519.Ed25519PublicKey.from_public_bytes(public)
    verifier.verify(authority.sign(message), message)
    for leaf in ("envelope-signing-v2.seed", "task-correlation-v2.seed"):
        wrong = ed25519.Ed25519PrivateKey.from_private_bytes(
            (stage / "private/kerneld" / leaf).read_bytes())
        with pytest.raises(InvalidSignature):
            verifier.verify(wrong.sign(message), message)


def test_tls_client_certificates_match_private_keys(stage):
    for prefix in ["provider", "final-release"]:
        leaf = "provider" if prefix == "provider" else "final-release-provider"
        key = ser.load_der_private_key((stage / f"private/execd/{leaf}-tls-private-key-v2.der").read_bytes(), None)
        certificate = x509.load_der_x509_certificate((stage / f"etc/savana/tls/{prefix}-client-v2.der").read_bytes())
        assert key.public_key().public_numbers() == certificate.public_key().public_numbers()


def test_no_authority_or_authentication_fabricated(stage):
    report = json.loads((stage / "integration-report.json").read_bytes())
    assert report["profile"] == "file-backed-integration"
    assert all(value is False for name, value in report.items() if name != "profile")
    approval = config(stage, "approvald")
    assert approval["hardware_credentials"] == []
    assert approval["enrollment_profiles"][0]["assurance"] == "user_verified_passkey"
    assert not list((stage / "etc/savana").glob("deployment-manifest-v2.cbor"))
    assert not (stage / "var/lib").exists()


def test_no_mac_paths_remain(stage):
    for leaf in (stage / "etc/savana").glob("*.json"):
        assert assemble.MAC not in leaf.read_text()


def test_fresh_generation_never_reuses_private_keys(inputs):
    templates, binaries, out = inputs
    assemble.assemble(templates, binaries, REPO, out, IDS)
    other = out.with_name("other-stage")
    assemble.assemble(templates, binaries, REPO, other, IDS)
    assert (out / "private/kerneld/kernel-approval-v04.seed").read_bytes() != (other / "private/kerneld/kernel-approval-v04.seed").read_bytes()


def test_existing_output_rejected(stage, inputs):
    templates, binaries, _ = inputs
    with pytest.raises(ValueError, match="existing staging"):
        assemble.assemble(templates, binaries, REPO, stage, IDS)


def test_install_public_permissions_with_private_umask(stage, tmp_path):
    root = tmp_path / "installed"
    old = os.umask(0o077)
    try:
        install.install_public_artifacts(stage, root)
    finally:
        os.umask(old)
    for subtree in ["etc/savana", "usr/libexec/savana"]:
        directory = root / subtree
        assert directory.stat().st_mode & 0o777 == 0o755
        for leaf in directory.rglob("*"):
            assert leaf.stat().st_mode & 0o777 == (0o755 if leaf.is_dir() or leaf.parent == root / "usr/libexec/savana" and leaf.name.startswith("savana-") else 0o444)
    assert not (root / "private").exists()
    with pytest.raises(FileExistsError):
        install.install_public_artifacts(stage, root)


def test_dropin_directory_permissions_with_private_umask(tmp_path):
    target = tmp_path / "savana-agentd.service.d/identity-broker.conf"
    old = os.umask(0o077)
    try:
        install.put(target, b"[Service]\n")
    finally:
        os.umask(old)
    assert target.parent.stat().st_mode & 0o777 == 0o755
    assert target.stat().st_mode & 0o777 == 0o444


def test_private_staging_umask_never_becomes_public_artifact_mode(stage,tmp_path):
    for name in ('kerneld-bootstrap-v2.json','integration-manifest-input.json'):
        (stage/'etc/savana'/name).chmod(0o400)
    root=tmp_path/'normalized-install'
    install.install_public_artifacts(stage,root)
    for name in ('kerneld-bootstrap-v2.json','integration-manifest-input.json'):
        assert (root/'etc/savana'/name).stat().st_mode&0o777==0o444


@pytest.mark.parametrize("bad", [dict(IDS, kerneld=0), dict(IDS, agentd=IDS["kerneld"]), dict(IDS, kerneld=True)])
def test_invalid_identity_rejected(inputs, bad):
    templates, binaries, out = inputs
    with pytest.raises(ValueError):
        assemble.assemble(templates, binaries, REPO, out, bad)
    assert not out.exists()


def test_non_linux_binary_rejected(inputs):
    templates, binaries, out = inputs
    (binaries / "savana-kerneld").write_bytes(b"not-ELF")
    with pytest.raises(ValueError, match="Linux ELF"):
        assemble.assemble(templates, binaries, REPO, out, IDS)


def test_administration_uses_closed_credentials_and_no_automatic_consent():
    command = admin.invocation("enroll")
    assert "--pipe" in command and "--unit=savana-approvalctl.service" in command
    assert command[-3:] == ["/usr/libexec/savana/savana-approvalctl", "create-enrollment", "1"]
    assert sum("LoadCredentialEncrypted=" in item for item in command) == 3
    assert admin.invocation("health")[-1] == "health"
    with pytest.raises(ValueError):
        admin.invocation("approve")


def test_owner_control_install_probe_never_prepares_a_task(monkeypatch):
    calls = []
    def health(command, **kwargs):
        calls.append(command)
        assert kwargs == dict(timeout=40, text=True)
        return '{"state":"ready"}'
    monkeypatch.setattr(install.subprocess, "check_output", health)
    install.verify_owner_control()
    assert calls == [["/usr/libexec/savana/savana-integration-admin", "owner-health"]]


@pytest.mark.parametrize("reply", ['{}', '{"state":"fenced"}',
                                  '{"state":"ready","authenticated":true}', 'not-json'])
def test_owner_control_install_probe_fails_closed(monkeypatch, reply):
    monkeypatch.setattr(install.subprocess, "check_output", lambda *args, **kwargs: reply)
    with pytest.raises((ValueError, RuntimeError)):
        install.verify_owner_control()


def test_owner_control_is_opt_in_and_measured_in_both_directions(inputs):
    templates, binaries, out = inputs
    binary = b"\x7fELFsynthetic-not-executable:savana-ownerctl"
    (binaries / "savana-ownerctl").write_bytes(binary)
    assemble.assemble(templates, binaries, REPO, out, IDS, owner_control=True)
    import hashlib
    digest = hashlib.sha256(binary).hexdigest()
    assert config(out, "agentd")["jarvis_executable_digest"] == digest
    assert (out / "usr/libexec/savana/savana-ownerctl").read_bytes() == binary
    owner = dict(uid=IDS["jarvis"], gid=IDS["jarvis"], executable_sha256=list(bytes.fromhex(digest)))
    edges = json.loads((out / "etc/savana/identity-broker-v2.json").read_bytes())["edges"]
    assert sum(e["caller"] == owner for e in edges) == 1
    assert sum(e["peer"] == owner for e in edges) == 1
    owner_credentials = out / "private/ownerctl"
    assert {p.name for p in owner_credentials.iterdir()} == {"jarvis-boot-v2.id", "agentd-boot-v2.id"}
    for p in owner_credentials.iterdir():
        assert p.read_bytes() == (out / "private/agentd" / p.name).read_bytes()
    report = json.loads((out / "integration-report.json").read_bytes())
    assert report["owner_control_enabled"] is True
    assert report["owner_intake_configured"] is False
    assert report["authenticated"] is False
    assert report["cloud_models_enabled"] is False


def test_disabled_owner_control_adds_no_executable_or_credentials(stage):
    assert not (stage / "private/ownerctl").exists()
    assert not (stage / "usr/libexec/savana/savana-ownerctl").exists()
    assert config(stage, "agentd")["jarvis_executable_digest"] == config(stage, "approvald")["admin_executable_digest"]


def test_protected_transport_requires_explicit_owner_profile(inputs):
    templates, binaries, out = inputs
    with pytest.raises(ValueError, match="owner"):
        assemble.assemble(templates, binaries, REPO, out, IDS, protected_experiment=True)
    assert not out.exists()


def test_protected_transport_pins_match_and_operator_key_is_separate(inputs):
    templates, binaries, out = inputs
    (binaries / "savana-ownerctl").write_bytes(b"\x7fELFsynthetic-owner")
    assemble.assemble(templates, binaries, REPO, out, IDS,
                      owner_control=True, protected_experiment=True)
    kernel, executor = config(out, "kerneld"), config(out, "execd")
    endpoints = json.loads((out / "etc/savana/experiment-endpoints-v04.json").read_bytes())
    assert endpoints["schema"] == 2
    assert endpoints["entries"] == []  # no invented tasks, roots or enrollment
    # The reviewed read-tool catalog is copied verbatim for the profile generator.
    staged_catalog = (out / "etc/savana/read-tool-catalog-v04.json").read_bytes()
    assert staged_catalog == Path(__file__).with_name("read-tool-catalog-v04.json").read_bytes()
    assert json.loads(staged_catalog)["schema"] == 1
    pins = []
    for role, block in [("provider", "provider"), ("release_provider", "final_release_provider"),
                        ("model_worker", None)]:
        endpoint = endpoints[role]
        def material(field):
            return (out / "private/experiment" / Path(endpoint[field]).name).read_bytes()
        certificate = x509.load_pem_x509_certificate(material("certificate"))
        key = ser.load_pem_private_key(material("private_key"), None)
        assert key.public_key().public_numbers() == certificate.public_key().public_numbers()
        spki = hashlib.sha256(key.public_key().public_bytes(ser.Encoding.DER, ser.PublicFormat.SubjectPublicKeyInfo)).digest()
        if block:
            assert spki.hex() == executor[block]["server_spki_sha256"]
            assert endpoint["client_certificate_sha256"] == executor[block]["client_certificate_digests"][0]
        else:
            model = kernel["fused_model_workers"][0]
            assert spki == bytes(model["server_spki_sha256"])
            assert endpoint["socket"] == model["socket"]
            assert "address" not in endpoint
            assert endpoint["client_certificate_sha256"] == hashlib.sha256(bytes(model["client_certificate_der"])).hexdigest()
            identity = json.loads((out / "etc/savana/experiment-model-identity.json").read_bytes())
            host = model["host"].encode()
            assert identity["recipient"] == hashlib.sha256(b"SAVANA_FUSED_MTLS_RECIPIENT_V04\0" + len(host).to_bytes(4, "big") + host + spki + b"/savana.fused.v04/exchange").hexdigest()
            assert identity["disclosure_authorized"] is False
        pins.append(endpoint["client_certificate_sha256"])
    assert len(set(pins)) == 3
    assert endpoints["provider"]["address"] != endpoints["release_provider"]["address"]
    seed = (out / "private/experiment-operator/managed-admin-v04.seed").read_bytes()
    public = ed25519.Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
    assert kernel["managed_admin"]["public_key"] == public.hex()
    assert kernel["managed_admin"]["key_id"] == hashlib.sha256(b"savana.ed25519-key-id.v2\0" + public).hexdigest()
    for role in (*assemble.SERVICES, "experiment"):
        assert all(p.read_bytes() != seed for p in (out / "private" / role).iterdir())
    units = install.service_units(REPO, protected_experiment=True)
    install.validate_credential_coverage(out, units)
    unit = units["/usr/lib/systemd/system/savana-kerneld.service"]
    assert "LoadCredentialEncrypted=fused-model-client-v04.pk8:" in unit
    assert "managed-admin-v04.seed" not in "\n".join(units.values())
    assert any("managed-admin" in name for name in units)


def test_default_profile_does_not_enable_experimental_trust(stage):
    assert "managed_admin" not in config(stage, "kerneld")
    assert "fused_model_workers" not in config(stage, "kerneld")
    assert not (stage / "private/experiment").exists()
    assert not (stage / "etc/savana/experiment-endpoints-v04.json").exists()
    assert not (stage / "etc/savana/read-tool-catalog-v04.json").exists()


def test_experiment_units_keep_private_operator_and_kernel_credentials_out(inputs):
    templates, binaries, out = inputs
    (binaries / "savana-ownerctl").write_bytes(b"\x7fELFsynthetic-owner")
    assemble.assemble(templates, binaries, REPO, out, IDS,
                      owner_control=True, protected_experiment=True)
    units = install.experiment_units(REPO)
    service = units["/usr/lib/systemd/system/savana-protected-experiment.service"]
    socket = units["/usr/lib/systemd/system/savana-protected-experiment.socket"]
    assert "User=savana-experiment\n" in service
    assert "Restart=no\n" in service
    assert "InaccessiblePaths=-/var/lib/savana -/etc/savana/credentials/experiment-operator" in service
    assert "[Install]" not in service + socket
    assert "SocketUser=root\nSocketGroup=savana-kernel\nSocketMode=0660" in socket
    assert "FileDescriptorName=savana-fused-model-v04" in socket
    lines = [line for line in service.splitlines() if line.startswith("LoadCredentialEncrypted=")]
    assert len(lines) == 10
    # Only the model API key is a future, separately provided credential.
    assert not (out / "private/experiment/deepseek-api-key").exists()
    for line in lines:
        name, path = line.split("=", 1)[1].split(":", 1)
        assert path == f"/etc/savana/credentials/experiment/{name}.cred"
        if name != "deepseek-api-key":
            assert (out / "private/experiment" / name).is_file()


def test_owner_administration_is_unprivileged_has_no_signing_keys_or_network():
    for action in ["owner-health", "prepare-ingress"]:
        command = admin.invocation(action)
        assert "--pipe" in command and "--unit=savana-ownerctl.service" in command
        assert "--property=User=savana-jarvis" in command
        assert "--property=Group=savana-jarvis" in command
        assert "--property=RestrictAddressFamilies=AF_UNIX" in command
        assert "--property=IPAddressDeny=any" in command
        assert "--property=CapabilityBoundingSet=" in command
        credentials = [v for v in command if "LoadCredentialEncrypted=" in v]
        assert len(credentials) == 2
        assert all("-boot-v2.id" in v and ".seed" not in v for v in credentials)
        assert command[-2] == "/usr/libexec/savana/savana-ownerctl"
        assert command[-1] == ("health" if action == "owner-health" else action)
    with pytest.raises(ValueError):
        admin.owner_invocation("enroll")


@pytest.mark.parametrize("state", ["ActiveState=failed\nMainPID=0\n", "ActiveState=active\nSubState=running\nMainPID=1\n"])
def test_health_rejects_missing_or_failed_service(monkeypatch, state):
    monkeypatch.setattr(install.subprocess, "check_output", lambda *args, **kwargs: state)
    with pytest.raises(RuntimeError, match="did not remain running"):
        install.verify_services()


def test_health_rejects_restart(monkeypatch):
    rows = "ActiveState=active\nSubState=running\nMainPID=12\nNRestarts=0\n" * 5
    values = iter([rows, rows.replace("NRestarts=0", "NRestarts=1")])
    monkeypatch.setattr(install.subprocess, "check_output", lambda *args, **kwargs: next(values))
    monkeypatch.setattr(install.time, "sleep", lambda seconds: None)
    with pytest.raises(RuntimeError, match="restarted"):
        install.verify_services()


def test_health_rejects_delayed_startup_failure(monkeypatch):
    rows = "ActiveState=active\nSubState=running\nMainPID=12\nNRestarts=0\n" * 5
    values = iter([rows] * 4 + [rows.replace("NRestarts=0", "NRestarts=1")])
    monkeypatch.setattr(install.subprocess, "check_output", lambda *args, **kwargs: next(values))
    monkeypatch.setattr(install.time, "sleep", lambda seconds: None)
    with pytest.raises(RuntimeError, match="restarted"):
        install.verify_services()


@pytest.mark.parametrize("crash_after_http", [False, True])
def test_health_checks_real_readiness_then_rechecks_processes(monkeypatch, crash_after_http):
    rows = "ActiveState=active\nSubState=running\nMainPID=12\nNRestarts=0\n" * 5
    calls = []
    def output(args, **kwargs):
        if args[0].endswith("savana-integration-admin"):
            assert args[1:] == ["health"]
            return "state=Ready\n"
        calls.append(args)
        if len(calls) == 17 and crash_after_http:
            return rows.replace("NRestarts=0", "NRestarts=1")
        return rows
    class Connection:
        def __init__(self, *args, **kwargs): pass
        def request(self, method, path, headers):
            assert (method, path, headers) == ("GET", "/v2/enrollment/bootstrap", {"Host":"localhost:8766"})
        def getresponse(self): return self
        status = 200
        def read(self, maximum): return b"page"
        def close(self): pass
    monkeypatch.setattr(install.subprocess, "check_output", output)
    monkeypatch.setattr(install.time, "sleep", lambda seconds: None)
    monkeypatch.setattr(install.http.client, "HTTPConnection", Connection)
    if crash_after_http:
        with pytest.raises(RuntimeError, match="changed during health"):
            install.verify_services()
    else:
        install.verify_services()
    assert len(calls) == 17
