#!/usr/bin/env python3
"""Assemble NEW file-backed Linux integration inputs; never edit live state.

Input templates must have just been generated on this disposable host by the
Rust development-build-inputs tool. Output is a NEW private staging directory.
This tool does not install, start services, grant a task root or approve actions.
"""
import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization as ser
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, x25519
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

SERVICES = ("kerneld", "agentd", "ingressd", "approvald", "execd")
ACCOUNTS = ("kernel", "agent", "ingress", "approval", "exec")
MAC = "/Library/Application Support/Savana/Development/"
ALPN = b"savana-provider-v2"


def sha(data):
    return hashlib.sha256(data).digest()


def relocate(value):
    if isinstance(value, dict):
        return {key: relocate(item) for key, item in value.items()}
    if isinstance(value, list):
        return [relocate(item) for item in value]
    if isinstance(value, str) and value.startswith(MAC):
        for old, new in [("config/", "/etc/savana/"), ("state/", "/var/lib/savana/"),
                         ("sandbox/ingressd/", "/usr/libexec/savana/"),
                         ("sandbox/execd/", "/usr/libexec/savana/")]:
            if value.startswith(MAC + old):
                return new + value[len(MAC + old):]
        raise ValueError("unsupported template pathname")
    return value


def assemble(templates: Path, binaries: Path, repo: Path, out: Path, ids: dict, *, owner_control=False,
             protected_experiment=False):
    if protected_experiment and not owner_control:
        raise ValueError("protected experiment requires measured owner control")
    if out.exists() or out.is_symlink():
        raise ValueError("refusing existing staging output")
    if set(ids) != set(SERVICES) | {"jarvis"} or len(set(ids.values())) != 6:
        raise ValueError("six distinct service identities required")
    if any(type(uid) is not int or not 1 <= uid <= 2**31 - 1 for uid in ids.values()):
        raise ValueError("non-root numeric identities required")
    out.mkdir(mode=0o700)

    def put(path, data, mode=0o444):
        target = out / path.lstrip("/")
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with target.open("xb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        target.chmod(mode)

    def obj(path, data):
        put(path, json.dumps(data, sort_keys=True, separators=(",", ":")).encode())

    configs = {s: relocate(json.loads((templates / f"config/{s}-bootstrap-v2.json").read_bytes())) for s in SERVICES}
    template = json.loads((templates / "config/development-manifest-template-v2.json").read_bytes())
    # The original random placeholder is intentionally rejected at the end.
    placeholder = configs["kerneld"]["ui_settlement_key_id"]
    names = ["agent_client", "agent_server", "ingress_client", "ingress_server",
             "executor_client", "executor_server", "envelope", "authority", "correlation",
             "task_authorization", "agent_approval", "ingress_approval", "admin_approval",
             "approval_server", "settlement", "parser", "receipt", "connector", "kernel_approval"]
    keys = {}
    for name in names:
        private = ed25519.Ed25519PrivateKey.generate()
        seed = private.private_bytes(ser.Encoding.Raw, ser.PrivateFormat.Raw, ser.NoEncryption())
        public = private.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
        keys[name] = (seed, public, sha(b"savana.ed25519-key-id.v2\0" + public).hex())
    if protected_experiment:
        private = ed25519.Ed25519PrivateKey.generate()
        seed = private.private_bytes(ser.Encoding.Raw, ser.PrivateFormat.Raw, ser.NoEncryption())
        public = private.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
        keys["managed_admin"] = (seed, public, sha(b"savana.ed25519-key-id.v2\0" + public).hex())
    boots = {s: os.urandom(32) for s in (*SERVICES, "machine", "jarvis", "approvalctl")}
    credentials = {s: {} for s in (*SERVICES, "approvalctl")}

    def credential(service, leaf, key=None):
        credentials[service][leaf] = keys[key][0] if key else os.urandom(32)

    for service, leaf, key in [
        ("kerneld", "agent-kernel-v2.seed", "agent_server"),
        ("kerneld", "ingress-kernel-v2.seed", "ingress_server"),
        ("kerneld", "executor-kernel-v2.seed", "executor_client"),
        ("kerneld", "envelope-signing-v2.seed", "envelope"),
        ("kerneld", "authority-envelope-v2.seed", "authority"),
        ("kerneld", "task-correlation-v2.seed", "correlation"),
        ("kerneld", "task-authorization-v2.seed", "task_authorization"),
        ("kerneld", "kernel-approval-v04.seed", "kernel_approval"),
        ("agentd", "agent-kernel-v2.seed", "agent_client"),
        ("agentd", "agent-approval-v2.seed", "agent_approval"),
        ("ingressd", "ingress-kernel-v2.seed", "ingress_client"),
        ("ingressd", "ingress-approval-v2.seed", "ingress_approval"),
        ("ingressd", "parser-descriptor-v2.seed", "parser"),
        ("approvald", "approval-server-v2.seed", "approval_server"),
        ("approvald", "approval-settlement-v2.seed", "settlement"),
        ("execd", "executor-server-v2.seed", "executor_server"),
        ("execd", "effect-receipt-v2.seed", "receipt"),
        ("execd", "connector-descriptor-v2.seed", "connector"),
        ("approvalctl", "approval-admin-v2.seed", "admin_approval"),
    ]:
        credential(service, leaf, key)
    for service, prefixes in {
        "kerneld": ["vault", "agent-authority-state", "g4-state"],
        "agentd": ["task-state"], "approvald": ["approval-state"], "execd": ["journal"],
    }.items():
        for prefix in prefixes:
            credential(service, prefix + "-encryption-v2.key")
            anchor = prefix.removesuffix("-state")
            credential(service, anchor + "-anchor-authentication-v2.key")
    for service, boot_names in {
        "kerneld": ["kerneld"], "agentd": ["agentd", "kerneld", "approvald", "machine", "jarvis"],
        "ingressd": ["ingressd", "kerneld", "approvald"], "approvald": ["approvald"],
        "execd": ["execd"], "approvalctl": ["approvalctl", "approvald"],
    }.items():
        for name in boot_names:
            credentials[service][name + "-boot-v2.id"] = boots[name]
    public_paths = {
        "kerneld/keys/agentd-kernel-v2.pub": "agent_client", "kerneld/keys/ingressd-kernel-v2.pub": "ingress_client",
        "kerneld/keys/execd-kernel-v2.pub": "executor_server", "agentd/keys/kerneld-agent-v2.pub": "agent_server",
        # Agentd verifies SignedDurableTaskCorrelationV2, not authority envelopes.
        "agentd/keys/kerneld-task-authority-v2.pub": "correlation", "agentd/keys/approvald-agent-v2.pub": "approval_server",
        "ingressd/keys/kerneld-ingress-v2.pub": "ingress_server", "ingressd/keys/approvald-v2.pub": "approval_server",
        "approvald/keys/kerneld-envelope-v2.pub": "envelope", "approvald/keys/kerneld-correlation-v2.pub": "correlation",
        "approvald/keys/agentd-approval-v2.pub": "agent_approval", "approvald/keys/ingressd-approval-v2.pub": "ingress_approval",
        "approvald/keys/admin-approval-v2.pub": "admin_approval", "execd/keys/kerneld-executor-v2.pub": "executor_client",
        "execd/keys/kerneld-envelope-v2.pub": "envelope", "approvalctl/keys/approvald-admin-v2.pub": "approval_server",
        "keys/approval-server-v2.pub": "approval_server", "keys/kernel-approval-v04.pub": "kernel_approval",
    }
    for path, name in public_paths.items():
        put("etc/savana/" + path, keys[name][1])
    def pair(target, id_field, public_field, key):
        target[id_field], target[public_field] = keys[key][2], keys[key][1].hex()
    kernel, agent, ingress, approval, executor = (configs[s] for s in SERVICES)
    if protected_experiment:
        # An independently pinned operator key, never a kernel/Agent credential.
        kernel["managed_admin"] = dict(key_id=keys["managed_admin"][2], public_key=keys["managed_admin"][1].hex())
        credentials["experiment-operator"] = {"managed-admin-v04.seed": keys["managed_admin"][0]}
        credentials["experiment"] = {}
    for field, name in [("agentd_boot_id", "agentd"), ("approvald_boot_id", "approvald"), ("machine_boot_id", "machine")]:
        kernel[field] = boots[name].hex()
    for prefix, key in [("ui_settlement", "settlement"), ("ingress_settlement", "settlement"), ("task_authorization", "task_authorization")]:
        pair(kernel, prefix + "_key_id", prefix + "_public_key", key)
    pair(kernel["parser_trust"], "descriptor_key_id", "descriptor_public_key", "parser")
    policy = kernel["policy_runtime"]
    pair(policy, "tool_settlement_key_id", "tool_settlement_public_key", "settlement")
    pair(policy, "executor_receipt_key_id", "executor_receipt_public_key", "receipt")
    seal = x25519.X25519PrivateKey.generate()
    seal_public = seal.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
    credentials["execd"]["execution-seal-v2.key"] = seal.private_bytes(ser.Encoding.Raw, ser.PrivateFormat.Raw, ser.NoEncryption())
    seal_id = sha(b"SAVANA_HPKE_X25519_KEY_ID_V2\0" + seal_public).hex()
    policy.update(execd_boot_id=boots["execd"].hex(), executor_seal_key_id=seal_id, executor_seal_public_key=seal_public.hex())
    agent.update(kernel_task_authority_key_id=keys["correlation"][2], approval_client_key_id=keys["agent_approval"][2], approval_server_key_id=keys["approval_server"][2])
    ingress.update(approval_client_key_id=keys["ingress_approval"][2], approval_server_key_id=keys["approval_server"][2])
    ingress["parser"].update(descriptor_key_id=keys["parser"][2], file_owner_uid=0, file_owner_gid=0)
    approval.update(kernel_correlation_key_id=keys["correlation"][2], settlement_key_id=keys["settlement"][2],
        kernel_authority_envelope_key_id=keys["authority"][2],
        kernel_authority_envelope_public_key=keys["authority"][1].hex(),
        server_key_id=keys["approval_server"][2], agent_client_key_id=keys["agent_approval"][2], ingress_client_key_id=keys["ingress_approval"][2],
        admin_client_key_id=keys["admin_approval"][2], admin_expected_uid=0, admin_expected_gid=0,
        agent_listener_gid=ids["agentd"], ingress_listener_gid=ids["ingressd"],
        enrollment_profiles=[dict(profile=1, code_lifetime_ms=300000, ceremony_lifetime_ms=300000, assurance="user_verified_passkey")])
    kernel["kernel_approval"] = dict(client_key_id=keys["kernel_approval"][2], server_key_id=keys["approval_server"][2], server_public_key_path="/etc/savana/keys/approval-server-v2.pub")
    approval["kernel_approval"] = dict(client_key_id=keys["kernel_approval"][2], client_public_key_path="/etc/savana/keys/kernel-approval-v04.pub", listener_gid=ids["kerneld"])
    executor.update(effect_receipt_key_id=keys["receipt"][2], seal_key_id=seal_id)

    digests = {}
    for name in [*("savana-" + s for s in SERVICES), "savana-worker-sandbox", "savana-parser-worker", "savana-connector-worker", "savana-approvalctl", "savana-linux-identity-broker", "savana-systemd-agentd-network-policy-v2", "savana-linux-integration-manifest", *(["savana-ownerctl"] if owner_control else [])]:
        data = (binaries / name).read_bytes()
        if not data.startswith(b"\x7fELF"):
            raise ValueError("Linux ELF binaries required")
        digests[name] = sha(data).hex()
        put("usr/libexec/savana/" + name, data, 0o755)
    # Only an explicitly enabled measured native client may prepare tasks.
    # An interpreter never receives this peer identity. This does not grant a
    # task root, enroll private planning or enable a browser authentication bridge.
    owner_binary = "savana-ownerctl" if owner_control else "savana-approvalctl"
    agent.update(jarvis_expected_uid=ids["jarvis"], jarvis_expected_gid=ids["jarvis"],
        jarvis_executable_digest=digests[owner_binary], jarvis_code_identity_digest=digests[owner_binary])
    if owner_control:
        credentials["ownerctl"] = {name + "-boot-v2.id": boots[name] for name in ["agentd", "jarvis"]}
    approval.update(admin_executable_digest=digests["savana-approvalctl"], admin_code_identity_digest=digests["savana-approvalctl"])
    parser = ingress["parser"]
    parser.update(sandbox_program_digest=digests["savana-worker-sandbox"], worker_artifact_digest=digests["savana-parser-worker"])
    kernel["parser_trust"]["worker_artifact_digest"] = digests["savana-parser-worker"]
    worker = executor["worker"]
    worker.update(sandbox_program_digest=digests["savana-worker-sandbox"], worker_artifact_digest=digests["savana-connector-worker"])
    for name, key, target in [("parser-profile-v2", "sandbox_profile_digest", parser),
                              ("connector-no-network-profile-v2", "no_network_profile_digest", worker),
                              ("connector-credential-absence-profile-v2", "credential_absence_profile_digest", worker)]:
        profile = json.loads((repo / f"deploy/sandbox/{name}.example.json").read_bytes())
        if "read_only_paths" in profile:
            profile["read_only_paths"] = []
        data = json.dumps(profile, sort_keys=True, separators=(",", ":")).encode()
        put("usr/libexec/savana/" + name + ".json", data)
        target[key] = sha(data).hex()

    # No cloud credential is imported and no service is contacted. The explicit
    # experimental profile retains service keys for separate unprivileged TLS
    # endpoints; the default profile continues to discard those server keys.
    now = datetime.now(timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Savana disposable integration")])
    ca = x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=5)).not_valid_after(now+timedelta(days=2)).add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True).sign(ca_key, hashes.SHA256())
    ca_der = ca.public_bytes(ser.Encoding.DER)
    put("etc/savana/tls/runtime-root-v2.der", ca_der)
    def tls(name, client):
        key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        cert = x509.CertificateBuilder().subject_name(subject).issuer_name(ca_name).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=5)).not_valid_after(now+timedelta(days=2)).add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True).add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH if client else ExtendedKeyUsageOID.SERVER_AUTH]), critical=False).add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False).sign(ca_key, hashes.SHA256())
        return cert.public_bytes(ser.Encoding.DER), key.private_bytes(ser.Encoding.DER, ser.PrivateFormat.PKCS8, ser.NoEncryption()), sha(key.public_key().public_bytes(ser.Encoding.DER, ser.PublicFormat.SubjectPublicKeyInfo))
    experiment = {"schema": 2, "entries": []}
    def endpoint_credentials(prefix, certificate, private, client):
        base = "/run/credentials/savana-protected-experiment.service/"
        credentials["experiment"][prefix + "-server.pem"] = x509.load_der_x509_certificate(certificate).public_bytes(ser.Encoding.PEM)
        credentials["experiment"][prefix + "-server.pk8.pem"] = ser.load_der_private_key(private, None).private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.NoEncryption())
        credentials["experiment"][prefix + "-client-ca.pem"] = ca.public_bytes(ser.Encoding.PEM)
        return dict(certificate=base+prefix+"-server.pem", private_key=base+prefix+"-server.pk8.pem",
            client_ca=base+prefix+"-client-ca.pem", client_certificate_sha256=sha(client).hex())

    if protected_experiment:
        host, path = "fused.savana-experiment.invalid", "/run/savana-model/fused-v04.sock"
        server_cert, server_private, spki = tls(host, False)
        client_cert, client_private, _ = tls("kernel-fused-client.savana-experiment.invalid", True)
        leaf = "fused-model-client-v04.pk8"
        credentials["kerneld"][leaf] = client_private
        kernel["fused_model_workers"] = [dict(host=host, socket=path, server_spki_sha256=list(spki),
            root_certificate_der=list(ca_der), client_certificate_der=list(client_cert), private_key_credential=leaf)]
        experiment["model_worker"] = dict(endpoint_credentials("model", server_cert, server_private, client_cert),
                                          socket=path, profile=1)
        # Published descriptor identity only; not a declassification permit.
        recipient = sha(b"SAVANA_FUSED_MTLS_RECIPIENT_V04\0" + len(host).to_bytes(4,"big") + host.encode()
                        + spki + b"/savana.fused.v04/exchange")
        obj("etc/savana/experiment-model-identity.json", dict(schema=1, recipient=recipient.hex(),
            model_profile=1, disclosure_authorized=False))
    for name, prefix in [("planner", "planner"), ("mapper", "private_mapper")]:
        host = f"{name}.savana-development.invalid"
        _, _, spki = tls(host, False)
        cert, private, _ = tls(f"{name}-client.savana-development.invalid", True)
        agent[prefix + "_server_spki_sha256"] = spki.hex()
        credentials["agentd"].update({name+"-root-v2.der": ca_der, name+"-client-v2.der": cert, name+"-client-v2.pk8": private})
    for name, block, port in [("provider", "provider", 9444), ("final-release", "final_release_provider", 43191)]:
        provider = executor[block]
        host = provider["server_name"]
        server_cert, server_private, spki = tls(host, False)
        cert, private, _ = tls(name + "-client.savana-development.invalid", True)
        cert_path = f"/etc/savana/tls/{name}-client-v2.der"
        put(cert_path, cert)
        credential_name = "provider-tls-private-key-v2.der" if name == "provider" else "final-release-provider-tls-private-key-v2.der"
        credentials["execd"][credential_name] = private
        encoded_host = host.encode()
        binding = sha(b"SAVANA_PROVIDER_TLS_ENDPOINT_BINDING_V2\0" + bytes([4,127,0,0,1]) + port.to_bytes(2,"big") + len(encoded_host).to_bytes(2,"big") + encoded_host + sha(ca_der) + sha(cert) + len(ALPN).to_bytes(2,"big") + ALPN)
        provider.update(server_spki_sha256=spki.hex(), root_certificate_digest=sha(ca_der).hex(),
            client_certificate_paths=[cert_path], client_certificate_digests=[sha(cert).hex()],
            endpoint_binding_digest=binding.hex(), credential_handle_identity_digest=sha(b"SAVANA_PROVIDER_CREDENTIAL_HANDLE_IDENTITY_V2\0" + sha(cert)).hex())
        if protected_experiment:
            role = "provider" if name == "provider" else "release_provider"
            experiment[role] = dict(endpoint_credentials(name, server_cert, server_private, cert),
                address=["127.0.0.1", port], url=f"https://{host}:{port}/" + ("mcp" if name == "provider" else "release"),
                alpn=ALPN.decode())
    if protected_experiment:
        # This is deliberately NOT a runnable episode configuration: authentic
        # task/run/root/plan bindings must be obtained after real owner admission.
        obj("etc/savana/experiment-endpoints-v04.json", experiment)

    observations = []
    for index, service in enumerate(SERVICES):
        endpoint = {"kind": "loopback-tcp", "port": 8767 if service == "ingressd" else 8766}
        if service in ("kerneld", "agentd", "execd"):
            endpoint = {"kind": "unix-socket", "path": {"kerneld":"/run/savana/kerneld/agentd/kerneld.sock", "agentd":"/run/savana/agentd/jarvis/control.sock", "execd":"/run/savana/execd/kerneld/execd.sock"}[service]}
        observations.append(dict(service=service, process_uid=ids[service], process_gid=ids[service],
            executable_path=f"/usr/libexec/savana/savana-{service}", config_path=f"/etc/savana/{service}-bootstrap-v2.json",
            sandbox_profile_path=f"/usr/lib/systemd/system/savana-{service}.service", endpoint=endpoint,
            **template["services"][service]))
    for service, config in configs.items():
        config["services"] = observations
        if placeholder in json.dumps(config):
            raise ValueError(f"unresolved bootstrap field in {service}")
        obj(f"etc/savana/{service}-bootstrap-v2.json", config)
    obj("etc/savana/approvalctl-bootstrap-v2.json", dict(signed_manifest_path="/etc/savana/deployment-manifest-v2.cbor", effect_ledger_projection_path="/etc/savana/effect-ledger-projection-v2.cbor", services=observations, client_identity=approval["admin_client_identity"], client_key_id=keys["admin_approval"][2], server_key_id=keys["approval_server"][2]))
    template.pop("services")
    template.pop("edges")
    template.update(kernel_envelope_signing_key_id=keys["envelope"][2], edge_keys=[[keys[a][2],keys[b][2]] for a,b in [("agent_client","agent_server"),("ingress_client","ingress_server"),("executor_client","executor_server")]])
    obj("etc/savana/integration-manifest-input.json", template)
    for source in (templates / "artifacts").iterdir():
        leaf = source.name
        subdir = "trust/" if leaf.startswith("declassification-") and "rule-set" not in leaf else "policy/" if leaf.startswith("declassification-rule") or "tool-" in leaf else ""
        put("etc/savana/" + subdir + leaf, source.read_bytes())
    put("etc/savana/effect-gate-v2", b"")
    put("private/manifest.seed", (templates / "signing/deployment-manifest-v2.seed").read_bytes(), 0o600)
    for service, values in credentials.items():
        for leaf, data in values.items():
            put(f"private/{service}/{leaf}", data, 0o600)
    # Exact directional broker policy; no blanket trust in Python or a UID.
    def peer(service):
        return dict(uid=ids[service], gid=ids[service], executable_sha256=list(bytes.fromhex(digests["savana-" + service])))
    edges = [("kerneld","agentd"),("agentd","kerneld"),("kerneld","ingressd"),("ingressd","kerneld"),
             ("kerneld","execd"),("execd","kerneld"),("approvald","agentd"),("agentd","approvald"),
             ("approvald","ingressd"),("ingressd","approvald"),("approvald","kerneld"),("kerneld","approvald")]
    broker = [dict(caller=peer(a), peer=peer(b)) for a,b in edges]
    broker.append(dict(caller=peer("approvald"), peer=dict(uid=0,gid=0,executable_sha256=list(bytes.fromhex(digests["savana-approvalctl"])))))
    if owner_control:
        owner = dict(uid=ids["jarvis"], gid=ids["jarvis"], executable_sha256=list(bytes.fromhex(digests["savana-ownerctl"])))
        broker.extend([dict(caller=owner, peer=peer("agentd")), dict(caller=peer("agentd"), peer=owner)])
    obj("etc/savana/identity-broker-v2.json", dict(version=2, edges=broker))
    obj("integration-report.json", dict(profile="file-backed-integration", production_security_accepted=False,
        installed=False, authenticated=False, owner_intake_configured=False, owner_control_enabled=owner_control,
        protected_experiment_transport_configured=protected_experiment, cloud_models_enabled=False))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fresh-templates", type=Path, required=True)
    parser.add_argument("--binaries", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--owner-control", action="store_true", help="enroll only the measured Rust task-entry client")
    parser.add_argument("--protected-experiment", action="store_true", help="stage separate admin trust and Unix mTLS endpoints; no task grants")
    parser.add_argument("--accounts", type=Path, required=True)
    args = parser.parse_args()
    assemble(args.fresh_templates, args.binaries, Path(__file__).resolve().parents[3], args.output,
             json.loads(args.accounts.read_bytes()), owner_control=args.owner_control,
             protected_experiment=args.protected_experiment)
    print("Fresh file-backed integration inputs assembled; not installed or authenticated.")


if __name__ == "__main__":
    main()
