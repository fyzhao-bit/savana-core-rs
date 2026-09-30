"""Experiment plumbing tests. NO native protection/model score is asserted.

Synthetic frames test only the provider transport; published fixtures test only
the official oracle adapter. The actual runner requires a native SDK receipt.
"""
import asyncio
import base64
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import socket
import ssl
import tempfile
import unittest
from unittest.mock import patch

from savana_bench.agentdojo_calendar import calendar_provider
from savana_bench.agentdojo_provider import canonical
from savana_bench.private_episode import PrivateOutcome
from savana_bench.protected_agentdojo import (CASES, ResearchAudit, official_case, preflight,
    run, score_outcome, load_config, safe_error_code)
from savana_bench.protected_endpoint import EpisodeEndpoint, admit_owner_episode
from savana_bench.protected_transport import (ProviderServer, read_frame, server_context,
    certificate_spki_pin, _head, _blob, _hash)
from savana_bench.official_verify import verify_chain
from savana_bench.protected_verify import verify

ROOT = Path(__file__).resolve().parents[2]
URL = "https://provider.example:9443/mcp"
RELEASE_URL = "https://provider.example:9443/release"
ALPN = "savana-provider-v2"


def wire(payload, *, url=URL, pin=b"p"*32, nonce=b"n"*32):
    return b"\x8b\x02\x01" + _blob(3, url.encode()) + b"".join(_blob(2, v) for v in
        (pin, nonce, b"c"*32, b"s"*32)) + _head(0, len(payload)) + b"".join(_blob(2, v) for v in
        (_hash(b"SAVANA_PREPARED_PROVIDER_REQUEST_V2\0", payload),
         _hash(b"SAVANA_PROVIDER_REQUEST_PAYLOAD_V2\0", payload, length=True), payload))


def frame(payload, **values):
    return read_frame(io.BytesIO(wire(payload, **values)).read)


def binding():
    return {k: bytes([i+1]).hex()*32 for i, k in enumerate(("task_id", "run_id", "root_digest",
        "destination_digest", "application_turn", "resource", "authorization_id"))}


class DiagnosticTests(unittest.TestCase):
    def test_only_closed_sdk_error_codes_are_recorded(self):
        error=RuntimeError('private exception text must not be recorded')
        self.assertIsNone(safe_error_code(error))
        for code in ('invalid_response','transport_failed','authentication_failed'):
            error.code=code
            self.assertEqual(safe_error_code(error),code)
        for code in ('private-token-value', {'secret':'value'}, ['invalid_response'], None):
            error.code=code
            self.assertIsNone(safe_error_code(error))
        class UnreadableCode(Exception):
            @property
            def code(self):
                raise ValueError('private property failure')
        self.assertIsNone(safe_error_code(UnreadableCode()))


class FrameTests(unittest.TestCase):
    def test_real_execd_domains_and_shape(self):
        payload = b'{"synthetic":true}'
        raw = wire(payload)
        value = read_frame(io.BytesIO(raw).read)
        self.assertEqual(value.payload, payload)
        self.assertEqual(value.url, URL)
        self.assertEqual(value.wire_digest, hashlib.sha256(
            b"SAVANA_BOUND_PROVIDER_REQUEST_WIRE_V2\0" + len(raw).to_bytes(8, "big") + raw).digest())
        self.assertNotIn("synthetic", repr(value))

    def test_rejects_noncanonical_truncated_and_rebound(self):
        raw = wire(b"synthetic")
        variants = (raw[:-1], raw.replace(b"\x02\x01", b"\x18\x02\x01", 1),
                    b"\x9f"+raw[1:], wire(b"synthetic", nonce=bytes(32)), raw[:-1]+b"X")
        for bad in variants:
            with self.subTest(bad=bad[:4]), self.assertRaises((ValueError, EOFError)):
                read_frame(io.BytesIO(bad).read)

    def test_oversize_before_allocating_payload(self):
        with self.assertRaises(ValueError):
            read_frame(io.BytesIO(wire(b"x"*49153)).read)


class EndpointTests(unittest.TestCase):
    def setup_episode(self, case=CASES[0], emit=None):
        suite, task, injection, contract, values, env = official_case(case)
        provider = calendar_provider(env)
        events = []
        endpoint = EpisodeEndpoint(contract=contract, provider=provider, binding=binding(),
            tool_url=URL, release_url=RELEASE_URL,
            emit=emit or (lambda kind, **data: events.append(dict(kind=kind, **data))))
        return endpoint, provider, events, (suite, task, injection, contract, env.model_copy(deep=True))

    def request(self, contract):
        return canonical(dict(jsonrpc="2.0", id="test-read", method="tools/call",
            params=dict(name=contract.tool, arguments=contract.values())))

    def release(self, payload):
        b = binding()
        return canonical(dict(method="POST", path="/savana/final-result-release", request_id="release-1",
            body=dict(resource="result:"+b["resource"], destination="application-turn:"+b["application_turn"],
                      payload=base64.urlsafe_b64encode(payload).rstrip(b"=").decode())))

    def test_read_release_and_official_oracle(self):
        endpoint, provider, events, parts = self.setup_episode()
        suite, task, injection, contract, before = parts
        request = frame(self.request(contract))
        payload = endpoint.exchange(request)
        self.assertEqual(endpoint.exchange(request), payload)
        endpoint.exchange(frame(self.release(payload), url=RELEASE_URL, nonce=b"r"*32))
        received = asyncio.run(endpoint.receive_publication(task_id=bytes.fromhex(binding()["task_id"]),
            run_id=bytes.fromhex(binding()["run_id"]), release_id=b"R"*32,
            destination_digest=bytes.fromhex(binding()["destination_digest"])))
        self.assertEqual(received, payload)
        self.assertEqual(len(provider.audit), 1)
        outcome = PrivateOutcome("published", "complete", 0, None, received)  # oracle adapter fixture only
        utility, security = score_outcome(suite=suite, task=task, injection=injection, contract=contract,
            before=before, after=endpoint.freeze(), provider=provider, outcome=outcome)
        self.assertIsInstance(utility, bool)
        self.assertIsNone(security)
        self.assertIn("result_received", [e["kind"] for e in events])
        with self.assertRaises(ValueError):
            endpoint.exchange(request)

    def test_unrequested_tool_never_invoked(self):
        endpoint, provider, _, parts = self.setup_episode()
        request = json.loads(self.request(parts[3]))
        request["params"]["name"] = "send_email"
        with self.assertRaises(ValueError):
            endpoint.exchange(frame(canonical(request)))
        self.assertEqual(provider.audit, [])
        with self.assertRaises(ValueError):
            endpoint.exchange(frame(self.request(parts[3]), nonce=b"2"*32))

    def test_nonce_cannot_change_request_or_reexecute(self):
        endpoint, provider, _, parts = self.setup_episode()
        endpoint.exchange(frame(self.request(parts[3])))
        with self.assertRaises(ValueError):
            endpoint.exchange(frame(self.release(b"other")))
        self.assertEqual(len(provider.audit), 1)

    def test_wrong_destination_and_unpublished_data_never_observed(self):
        endpoint, _, _, parts = self.setup_episode()
        payload = endpoint.exchange(frame(self.request(parts[3])))
        release = json.loads(self.release(payload))
        release["body"]["destination"] = "application-turn:"+"f"*64
        with self.assertRaises(ValueError):
            endpoint.exchange(frame(canonical(release), url=RELEASE_URL, nonce=b"r"*32))
        with self.assertRaises(ValueError):
            asyncio.run(endpoint.receive_publication(task_id=b"x"*32, run_id=b"y"*32,
                release_id=b"z"*32, destination_digest=b"q"*32))

    def test_write_ahead_audit_failure_prevents_tool(self):
        def fail(*args, **kwargs):
            raise OSError("synthetic fsync failure")
        endpoint, provider, _, parts = self.setup_episode(emit=fail)
        with self.assertRaises(OSError):
            endpoint.exchange(frame(self.request(parts[3])))
        self.assertEqual(provider.audit, [])

    def test_all_official_attack_cases_setup_without_executing_tools(self):
        for case in CASES:
            endpoint, provider, _, parts = self.setup_episode(case)
            self.assertEqual(provider.audit, [])
            self.assertIsNone(endpoint._payload)
            if case["injection"]:
                self.assertIsNotNone(parts[2])


class MutualTlsTests(unittest.TestCase):
    def roundtrip(self, mode="ok"):
        from cryptography import x509
        values = dict(line.split("=", 1) for line in
            (ROOT/"crates/savana-execd/tests/fixtures/provider-tls-v2.hex").read_text().splitlines() if "=" in line)
        with tempfile.TemporaryDirectory() as directory:
            def pem(name, kind):
                filename = Path(directory)/name
                filename.write_text(f"-----BEGIN {kind}-----\n"+base64.encodebytes(bytes.fromhex(values[name])).decode()+f"-----END {kind}-----\n")
                filename.chmod(0o600)
                return str(filename)
            ca = pem("ca_cert", "CERTIFICATE")
            cert, key = pem("server_cert", "CERTIFICATE"), pem("server_key", "PRIVATE KEY")
            client_cert, client_key = pem("client_cert", "CERTIFICATE"), pem("client_key", "PRIVATE KEY")
            ctx = server_context(certificate=cert, private_key=key, client_ca=ca, alpn=ALPN)
            pin = certificate_spki_pin(cert)
            calls = []
            def exchange(request):
                calls.append(request)
                return b'{"status":"synthetic"}'
            server = ProviderServer(address=("127.0.0.1", 0), context=ctx,
                client_pin=(b"x"*32 if mode == "wrong_client" else hashlib.sha256(bytes.fromhex(values["client_cert"])).digest()),
                server_pin=pin, urls=(URL,), alpn=ALPN, exchange=exchange).start()
            client = ssl.create_default_context(cafile=ca)
            client.minimum_version = ssl.TLSVersion.TLSv1_3
            if mode != "no_client":
                client.load_cert_chain(client_cert, client_key)
            client.set_alpn_protocols(["wrong" if mode == "wrong_alpn" else ALPN])
            try:
                with client.wrap_socket(socket.create_connection(server.address, timeout=2), server_hostname="provider.example") as tls:
                    tls.sendall(wire(b"synthetic", pin=(b"x"*32 if mode == "wrong_target_pin" else pin),
                        url=RELEASE_URL if mode == "wrong_url" else URL))
                    reply = b""
                    try:
                        while True:
                            data = tls.recv(4096)
                            if not data:
                                break
                            reply += data
                        tls.unwrap().close()
                    except ssl.SSLError:
                        if mode == "ok":
                            raise
                    if mode == "ok":
                        self.assertEqual(reply, b'{"status":"synthetic"}')
            except (ssl.SSLError, ConnectionError):
                if mode == "ok":
                    raise
            finally:
                server.close()
            self.assertEqual(len(calls), 1 if mode == "ok" else 0)

    def test_exact_authenticated_frame(self): self.roundtrip()
    def test_wrong_client(self): self.roundtrip("wrong_client")
    def test_missing_client_certificate(self): self.roundtrip("no_client")
    def test_wrong_alpn(self): self.roundtrip("wrong_alpn")
    def test_wrong_target(self): self.roundtrip("wrong_url")
    def test_wrong_server_key_binding(self): self.roundtrip("wrong_target_pin")


class RunnerTests(unittest.TestCase):
    def test_launcher_only_accepts_exact_systemd_model_descriptor(self):
        from savana_bench.protected_launch import activation_fd
        values = dict(LISTEN_PID='321',LISTEN_FDS='1',LISTEN_FDNAMES='savana-fused-model-v04')
        self.assertEqual(activation_fd(values,321),3)
        for name, bad in (('LISTEN_PID','322'),('LISTEN_FDS','2'),('LISTEN_FDNAMES','other')):
            with self.subTest(name=name), self.assertRaises(ValueError):
                activation_fd(dict(values, **{name:bad}),321)

    def config_fixture(self):
        common = dict(certificate='/run/credentials/test/cert.pem',
            private_key='/run/credentials/test/key.pem', client_ca='/run/credentials/test/ca.pem',
            client_certificate_sha256='01'*32)
        entries = []
        for i in range(len(CASES)):
            b = binding()
            for key in ('task_id', 'run_id', 'application_turn'):
                b[key] = bytes([i+10]).hex()*32
            b['clauses'] = [{'synthetic': True}]
            entries.append(b)
        return dict(schema=2, entries=entries,
            provider=dict(common, address=['127.0.0.1',9444],url='https://tools.example:9444/mcp',alpn=ALPN),
            release_provider=dict(common, client_certificate_sha256='02'*32,
                address=['127.0.0.1',43191],url='https://release.example:43191/release',alpn=ALPN),
            model_worker=dict(common,socket='/run/savana-model/fused-v04.sock',profile=1))

    def test_split_provider_and_unix_model_config_required(self):
        value = self.config_fixture()
        with tempfile.TemporaryDirectory() as parent:
            p = Path(parent)/'config.json'
            def read(config):
                p.write_text(json.dumps(config))
                p.chmod(0o600)
                return load_config(p)
            self.assertEqual(read(value),value)
            for section, key, bad in (
                ('model_worker','socket','127.0.0.1:9445'),
                ('model_worker','socket','/run/savana-model/../other.sock'),
                ('model_worker','profile',True),
                ('provider','url','https://tools.example:43191/mcp'),
                ('provider','alpn','http/1.1'),
                ('release_provider','client_certificate_sha256','01'*32),
                ('release_provider','address',['127.0.0.1',9444]),
            ):
                changed=copy.deepcopy(value);changed[section][key]=bad
                with self.subTest(section=section,key=key,bad=bad),self.assertRaises(ValueError):read(changed)
            old=copy.deepcopy(value);old['schema']=1
            with self.assertRaises(ValueError):read(old)
            old=copy.deepcopy(value);old['model_worker']['address']=['127.0.0.1',9445]
            with self.assertRaises(ValueError):read(old)

    def test_preflight_does_not_create_model_or_request_approval(self):
        with tempfile.TemporaryDirectory() as parent:
            output = Path(parent)/"trial"
            summary = run(output=output)
            self.assertEqual(summary["run_status"], "not_started")
            self.assertEqual(summary["total_model_calls"], 0)
            self.assertEqual(summary["protected_episodes_scored"], 0)
            self.assertEqual(len(summary["rows"]), 9)
            self.assertTrue(all(not r["attempted"] for r in summary["rows"]))
            attack = summary["rates"]["attack"]
            self.assertEqual(attack["asr_all_planned_upper"], 1)
            self.assertIsNone(attack["asr_scored"])
            events, head = verify_chain((output/"events.jsonl").read_bytes().splitlines())
            completion = json.loads((output/"completion.json").read_bytes())
            self.assertEqual(completion, dict(audit_head=head, event_count=len(events)))
            self.assertEqual((output/"events.jsonl").stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError): run(output=output)

    def test_audit_fsync_error_stops_followup(self):
        with tempfile.TemporaryDirectory() as parent:
            audit = ResearchAudit(Path(parent)/"trial")
            try:
                with patch("savana_bench.protected_agentdojo.os.fsync", side_effect=OSError):
                    with self.assertRaises(OSError): audit.emit("synthetic")
                with self.assertRaises(ValueError): audit.emit("synthetic")
                with self.assertRaises(ValueError): audit.artifact("summary.json", {})
            finally:
                audit.close()

    def test_world_readable_and_symlink_config_rejected(self):
        with tempfile.TemporaryDirectory() as parent:
            p = Path(parent)/"config"
            p.write_text("{}")
            p.chmod(0o644)
            with self.assertRaises(ValueError): load_config(p)
            link = Path(parent)/"link"
            link.symlink_to(p)
            with self.assertRaises(OSError): load_config(link)

    def test_offline_verifier_rejects_changed_summary(self):
        with tempfile.TemporaryDirectory() as parent:
            output = Path(parent)/"trial"
            run(output=output)
            report = verify(output)
            self.assertTrue(report["audit_consistent"])
            self.assertEqual(report["official_episodes_rescored"], 0)
            self.assertFalse(report["portable_kernel_attestation"])
            summary = json.loads((output/"summary.json").read_bytes())
            summary["protected_episodes_scored"] = 9
            (output/"summary.json").write_bytes(canonical(summary))
            with self.assertRaises(ValueError): verify(output)

    def test_offline_verifier_keeps_explicit_software_identity_limits(self):
        from test_benchmark_identity import public_profile
        # This fixture stops at preflight: no identity, kernel or score is fabricated.
        with tempfile.TemporaryDirectory() as parent:
            output=Path(parent)/'trial';profile=public_profile()
            with patch('savana_bench.benchmark_identity.load_profile',return_value=profile), \
                 patch('savana_bench.protected_agentdojo.preflight',return_value=['synthetic_preflight_stop']):
                result=run(output=output,config={'schema':3},identity_profile=profile)
            self.assertEqual(result['protected_episodes_scored'],0)
            self.assertEqual(verify(output)['identity_profile'],profile)
            original,_=verify_chain((output/'events.jsonl').read_bytes().splitlines())
            for index,change in enumerate(('human','omit','consent')):
                rows=copy.deepcopy(original)
                if change=='human':rows[0]['identity_profile']['human_verification']=True
                elif change=='omit':rows[0]['identity_profile']=None
                else:rows[0]['consent_mode']='interactive'
                altered=Path(parent)/('altered-'+str(index));audit=ResearchAudit(altered)
                try:
                    for row in rows:
                        kind=row.pop('kind')
                        for key in ('seq','previous','sha256','time_ns'):row.pop(key,None)
                        audit.emit(kind,**row)
                    audit.artifact('summary.json',result)
                    audit.artifact('completion.json',dict(audit_head=audit.head,event_count=audit.count))
                finally:audit.close()
                with self.assertRaises(ValueError):verify(altered)


if __name__ == "__main__":
    unittest.main()
