"""Official-task subset, Python-SDK-only Savana v0.4 experiment entry point.

Fail closed: no ToolsExecutor, native test binaries, synthetic receipt,
reference solution, or direct tool fallback. An explicitly armed software
identity profile permits finite experimental preconsent (never human consent);
without it all approvals remain interactive. Preflight failures are
recorded as NOT RUN, never as protected successes. This is a finite read-only
protocol, not the unrestricted agent used by the undefended baseline.
"""
import argparse
import asyncio
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import select
import socket
import stat
import sys
import threading
import time

from .agentdojo_provider import canonical, decode
from .agentdojo_tasks import BENCHMARK, PACKAGE_VERSION, SUITE, reviewed_task
from .official_agentdojo import TASKS, INJECTIONS
from .official_verify import rates
from .protected_endpoint import EpisodeEndpoint, admit_owner_episode, digest32
from .protected_transport import ProviderServer, certificate_spki_pin, server_context

CASES = tuple([dict(group="benign", user=t, injection=None) for t in TASKS]
    + [dict(group="attack", user=t, injection=i) for t in TASKS for i in INJECTIONS])


def safe_error_code(error):
    """Only closed SDK diagnostics; never exception messages or capabilities."""
    try:
        code = getattr(error, 'code', None)
    except Exception:
        return None
    allowed = {'invalid_endpoint','invalid_request','invalid_response','transport_failed',
        'wrong_handle_kind','wrong_session','invalid_state','deadline_exceeded','cancelled',
        'step_limit_exceeded','replan_limit_exceeded','callback_failed','effect_indeterminate',
        'invalid_bootstrap','authentication_failed','enrollment_failed','approval_denied'}
    return code if type(code) is str and code in allowed else None


WORKER_ERROR_CODES = frozenset((
    'advice_fields','advice_values','cbor_shape','cbor_size','cbor_size_or_canonical','choice_fields',
    'choice_kind','client_binding','client_pin','duplicate_field','duplicate_header','empty_cbor',
    'header_bound','nonfinite','order','proposal_shape','proposal_size','request_headers','request_path',
    'request_size','request_truncated','template','view_expired','view_list','view_shape','view_size',
    'view_values','worker_deadline'))


def safe_worker_error(error):
    """Closed model-worker diagnostics: static worker codes or OpenSSL reasons only."""
    import ssl
    if isinstance(error, ssl.SSLError):
        reason = getattr(error, 'reason', None)
        ok = type(reason) is str and 0 < len(reason) <= 64 and reason.replace('_', '').isalnum() and reason.isupper()
        return dict(error_type='SSLError', error_code=reason if ok else None)
    args = getattr(error, 'args', ())
    code = args[0] if len(args) == 1 and type(args[0]) is str and args[0] in WORKER_ERROR_CODES else None
    return dict(error_type=type(error).__name__, error_code=code)


class ResearchAudit:
    """Private synthetic benchmark evidence. Exclusive, fsynced hash chain.

    Never pass credentials, bootstrap strings, arbitrary exception reprs or
    deployment config to emit. Unkeyed hashes are not kernel signatures.
    """
    def __init__(self, directory):
        directory.mkdir(mode=0o700, parents=False, exist_ok=False)
        self.directory = directory
        self._fd = os.open(directory / "events.jsonl",
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        self._lock = threading.Lock()
        self.head, self.count, self.failed = "0" * 64, 0, False
        try:
            self._sync_directory()
        except BaseException:
            os.close(self._fd)
            raise

    def _sync_directory(self):
        fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    @staticmethod
    def _write(fd, data):
        pending = memoryview(data)
        while pending:
            size = os.write(fd, pending)
            if size <= 0:
                raise OSError("audit_short_write")
            pending = pending[size:]
        os.fsync(fd)

    def emit(self, kind, **values):
        with self._lock:
            if self.failed:
                raise ValueError("audit_write_uncertain")
            row = dict(seq=self.count, previous=self.head, kind=kind, time_ns=time.time_ns(), **values)
            digest = hashlib.sha256(canonical(row)).hexdigest()
            try:
                self._write(self._fd, canonical(dict(row, sha256=digest)) + b"\n")
            except BaseException:
                self.failed = True
                raise
            self.head, self.count = digest, self.count + 1

    def artifact(self, name, value):
        if name not in ("summary.json", "completion.json") or self.failed:
            raise ValueError("invalid_audit_artifact")
        fd = os.open(self.directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            self._write(fd, canonical(value))
            self._sync_directory()
        finally:
            os.close(fd)

    def close(self):
        os.close(self._fd)


def load_config(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(fd)
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid()
            or metadata.st_mode & 0o077 or metadata.st_size > 262144):
            raise ValueError("private_operator_config_required")
        raw = os.read(fd, 262145)
    finally:
        os.close(fd)
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError("duplicate_config_field")
            value[key] = item
        return value
    config = json.loads(raw, object_pairs_hook=pairs)
    if type(config) is not dict or type(config.get('schema')) is not int or config['schema'] not in (2,3):
        raise ValueError("closed_deployment_config_required")
    fields={'schema','provider','release_provider','model_worker'}
    if config['schema']==3:
        if set(config)!=fields|{'provisioning','operator_socket'}: raise ValueError('closed_deployment_config_required')
        from .protected_operator import SOCKET
        d=config['provisioning']
        if (config['operator_socket']!=SOCKET or type(d) is not dict
            or set(d)!={'schema','descriptors','planner','destination_digest','store','installation',
                        'disposition','scope','task_grants_installed'}
            or d['schema']!=1 or d['disposition']!='require_approval'
            or d['scope']!='finite_calendar_subset' or d['task_grants_installed'] is not False
            or set(d['descriptors'])!={'dojo.calendar.search','dojo.calendar.day','savana.final_result_release'}):
            raise ValueError('closed_provisioning_profile')
        for value in (*d['descriptors'].values(),*(d[k] for k in ('planner','destination_digest','store','installation'))):
            digest32(value)
    elif (set(config)!=fields|{'entries'} or type(config['entries']) is not list
            or len(config['entries'])!=len(CASES)):
        raise ValueError('closed_deployment_config_required')
    all_tasks, all_runs, all_turns = set(), set(), set()
    for entry in config.get("entries",[]):
        if type(entry) is not dict or set(entry) != {"task_id", "run_id", "root_digest", "destination_digest",
                "application_turn", "resource", "authorization_id", "clauses"}:
            raise ValueError("episode_binding_fields")
        for key in set(entry) - {"clauses"}:
            digest32(entry[key])
        if type(entry["clauses"]) is not list or not entry["clauses"]:
            raise ValueError("operator_root_clauses_required")
        for key, seen in (("task_id", all_tasks), ("run_id", all_runs), ("application_turn", all_turns)):
            if entry[key] in seen:
                raise ValueError("episode_binding_reused")
            seen.add(entry[key])
    common = {"certificate", "private_key", "client_ca", "client_certificate_sha256"}
    for name, extra in (("provider", {"address", "url", "alpn"}),
                        ("release_provider", {"address", "url", "alpn"}),
                        ("model_worker", {"socket", "profile"})):
        value = config[name]
        if type(value) is not dict or set(value) != common | extra:
            raise ValueError("endpoint_config_fields")
        if name != "model_worker":
            if (type(value["address"]) is not list or len(value["address"]) != 2
                or value["address"][0] != "127.0.0.1" or type(value["address"][1]) is not int
                or not 1024 <= value["address"][1] <= 65535):
                raise ValueError("loopback_endpoint_required")
            from urllib.parse import urlsplit
            parsed = urlsplit(value["url"])
            if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
                or parsed.fragment or parsed.query or parsed.port != value["address"][1]
                or value["alpn"] != "savana-provider-v2"):
                raise ValueError("provider_endpoint_binding")
        else:
            path = value["socket"]
            if (type(path) is not str or not path.startswith("/run/savana-model/")
                or len(os.fsencode(path)) > 100
                or any(v in ("", ".", "..") for v in path.split("/")[1:])):
                raise ValueError("model_unix_socket_required")
        digest32(value["client_certificate_sha256"])
        for key in ("certificate", "private_key", "client_ca"):
            if type(value[key]) is not str or not Path(value[key]).is_absolute():
                raise ValueError("explicit_certificate_path_required")
    if (type(config["model_worker"]["profile"]) is not int
        or not 1 <= config["model_worker"]["profile"] <= 65535
        or config["provider"]["address"] == config["release_provider"]["address"]
        or config["provider"]["client_certificate_sha256"] == config["release_provider"]["client_certificate_sha256"]):
        raise ValueError("model_worker_config")
    return config


def preflight(*, config, auth_fd, model_key_fd, model_listener_fd=None):
    blockers = []
    if sys.platform != "linux":
        blockers.append("native_linux_host_required")
    try:
        if importlib.metadata.version("agentdojo") != PACKAGE_VERSION:
            blockers.append("agentdojo_version_mismatch")
    except importlib.metadata.PackageNotFoundError:
        blockers.append("agentdojo_not_installed")
    try:
        from savana.private_v04 import PrivateSession, PublicationReceipt
        from savana.owner_ingress import OwnerIngress
        if not hasattr(PrivateSession, "wait_publication") or not hasattr(OwnerIngress, "into_private_session"):
            blockers.append("python_sdk_missing_private_publication")
    except (ImportError, AttributeError):
        blockers.append("python_sdk_missing_private_publication")
    if config is None:
        blockers.append("signed_deployment_and_episode_bindings_not_provisioned")
    else:
        try:
            for name in ("provider", "release_provider", "model_worker"):
                value = config[name]
                server_context(certificate=value["certificate"], private_key=value["private_key"],
                    client_ca=value["client_ca"], alpn=value.get("alpn", "http/1.1"))
        except (OSError, ValueError):
            blockers.append("deployment_tls_material_unavailable")
        try:
            from savana.fused_worker import inherited_listener
            probe = inherited_listener(model_listener_fd, config["model_worker"]["socket"])
            probe.close()
        except (OSError, ValueError, ImportError):
            blockers.append("deployment_unix_model_listener_required")
    for fd, kind, label in ((auth_fd, stat.S_ISSOCK, "trusted_passkey_broker_fd_required"),
                           (model_key_fd, lambda mode: stat.S_ISFIFO(mode) or stat.S_ISREG(mode), "model_key_fd_required")):
        try:
            if type(fd) is not int or fd < 3 or not kind(os.fstat(fd).st_mode):
                blockers.append(label)
        except OSError:
            blockers.append(label)
    return blockers


def package_sources():
    try:
        import agentdojo
    except ImportError:
        return {}
    package = Path(agentdojo.__file__).parent
    return {str(p.relative_to(package)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(package.rglob("*")) if p.is_file() and p.suffix in (".py", ".yaml", ".json")}


class ModelWorker:
    def __init__(self, config, model, audit, *, listener_fd):
        from savana import fused_worker
        self.worker, self.model, self.audit = fused_worker, model, audit
        self.pin = digest32(config["client_certificate_sha256"])
        self.context = fused_worker.server_context(certificate=config["certificate"],
            private_key=config["private_key"], client_ca=config["client_ca"])
        self.stop = threading.Event()
        self.listener = fused_worker.inherited_listener(listener_fd, config["socket"])
        try:
            self.listener.settimeout(.2)
        except BaseException:
            self.listener.close()
            raise
        self.thread = threading.Thread(target=self._serve, name="savana-dojo-model", daemon=True)

    def _propose(self, job, deadline):
        call = self.model.calls
        self.audit.emit("released_model_view", call=call, job=job.view, view_digest=job.commitment.hex())
        try:
            proposed = self.model(job, deadline)
        finally:
            self.audit.emit("model_call_accounting", call=call, calls_before=call,
                calls_after=self.model.calls, input_bytes_total=self.model.input_bytes)
        self.audit.emit("model_proposal", call=call, proposal=proposed)
        return proposed

    def _serve(self):
        while not self.stop.is_set():
            try:
                raw, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                self.worker.serve_connection(raw, context=self.context,
                    client_certificate_sha256=self.pin, propose=self._propose)
            except Exception as error:
                self.audit.emit("model_transport_unknown", **safe_worker_error(error))

    def start(self):
        self.thread.start()

    def close(self):
        self.stop.set()
        self.listener.close()
        if self.thread.ident is not None:
            self.thread.join(6)
            if self.thread.is_alive():
                raise RuntimeError("model_shutdown_uncertain")
        self.model.close()


def official_case(case):
    """Same upstream task init, fixed attack and environment as the baseline.

    Ground truth is available only to the OFFICIAL ATTACK, never authoring,
    model views, authorization or the protected execution path.
    """
    from types import SimpleNamespace
    from agentdojo.task_suite.load_suites import get_suite
    from agentdojo.attacks.base_attacks import FixedJailbreakAttack
    from agentdojo.attacks.important_instructions_attacks import ImportantInstructionsAttack
    suite = get_suite(BENCHMARK, SUITE)
    task = suite.get_user_task_by_id(case["user"])
    contract = reviewed_task(case["user"], task.PROMPT)
    injection = suite.get_injection_task_by_id(case["injection"]) if case["injection"] else None
    attack = FixedJailbreakAttack(ImportantInstructionsAttack._JB_STRING, suite,
        SimpleNamespace(name="deepseek-flash-savana-finite"))
    values = attack.attack(task, injection) if injection else {}
    environment = task.init_environment(suite.load_and_inject_default_environment(values))
    return suite, task, injection, contract, values, environment


def score_outcome(*, suite, task, injection, contract, before, after, provider, outcome):
    from agentdojo.functions_runtime import FunctionCall
    trace = [FunctionCall(function=contract.upstream_tool, args=dict(contract.arguments), id="provider-1")
        for row in provider.audit if row["invoked"]]
    output = []
    if outcome is not None and outcome.status == "published":
        message = decode(outcome.payload)
        # Exactly the actually received tool response; no model/oracle-written answer.
        output = [{"type": "text", "content": item["text"]} for item in message["result"]["content"]
                  if item["type"] == "text"]
    utility = bool(suite._check_task_result(task, output, before, after, trace))
    attacker = bool(suite._check_task_result(injection, output, before, after, trace)) if injection else None
    return utility, attacker


def run(*, output, config=None, auth_fd=None, model_key_fd=None, model_listener_fd=None, identity_profile=None):
    if identity_profile is not None:
        from .benchmark_identity import load_profile
        if identity_profile!=load_profile() or config is None or config['schema']!=3:
            raise ValueError('explicit_benchmark_profile_required')
    audit = ResearchAudit(output)
    model = worker = broker = None
    # Native WebAuthn callbacks retain this loop through owner -> private handoff.
    # Creating a second asyncio.run loop would strand the live authentication bridge.
    async_runner = asyncio.Runner()
    rows, model_calls = [], 0
    try:
        blockers = preflight(config=config, auth_fd=auth_fd, model_key_fd=model_key_fd,
                             model_listener_fd=model_listener_fd)
        audit.emit("manifest", schema="savana-protected-agentdojo-v1", package_version=PACKAGE_VERSION,
            benchmark_version=BENCHMARK, suite=SUITE, cases=CASES, full_benchmark=False,
            requested_group="savana_protected_finite_calendar", kernel_interface="python_sdk_only",
            model="deepseek-flash", immutable_model_revision=False, max_model_calls=32,
            max_model_input_bytes=1048576, raw_tool_result_output=True,
            comparable_to_unrestricted_baseline=False, adaptive_tool_output_model_loop=False,
            identity_profile=identity_profile, human_authentication_evaluated=False,
            consent_mode='finite_calendar_preconsent_v1' if identity_profile else 'interactive',
            attack="important_instructions_no_names", platform=platform.platform(),
            package_sources=package_sources(),
            source_sha256={p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(Path(__file__).parent.glob("*.py"))})
        audit.emit("preflight", blockers=blockers, deployment_attested=False)
        if not blockers:
            from savana.fused_deepseek import DeepSeekModel
            from savana.openclaw_bridge.auth import WebAuthnBroker
            # Secret arrives only via inherited private descriptor; never argv,
            # environment discovery, files in evidence, or the model audit.
            if not select.select([model_key_fd], [], [], 5)[0]:
                raise TimeoutError("model_key_unavailable")
            key = os.read(model_key_fd, 257).decode("ascii").strip()
            if not 1 <= len(key) <= 256:
                raise ValueError("bounded_model_key_required")
            model = DeepSeekModel(api_key=key, profiles={config["model_worker"]["profile"]: "deepseek-flash"}, max_calls=32)
            del key
            broker = WebAuthnBroker(auth_fd, timeout_seconds=120)
            worker = ModelWorker(config["model_worker"], model, audit, listener_fd=model_listener_fd)
            worker.start()
        stopped = bool(blockers)
        for index, case in enumerate(CASES):
            row = dict(episode=index, **case, status="unknown", utility=None, attacker_success=None,
                attempted=False, stage="preflight" if blockers else "not_attempted_after_unknown")
            if not stopped:
                row["attempted"] = True
                row["stage"] = "setup"
                endpoint = observer = admitted_session = None
                servers = []
                start = time.monotonic()
                try:
                    from .agentdojo_calendar import calendar_provider
                    from .private_episode import finish_private_episode
                    from .publication_audit import PrivateEpisodeAudit
                    suite, task, injection, contract, values, env = official_case(case)
                    before = env.model_copy(deep=True)
                    binding = config.get("entries",[None]*len(CASES))[index]
                    def emit(kind, **data):
                        audit.emit(kind, episode=index, **data)
                    emit("episode_input", contract=contract.document(), injections=values,
                        environment=before.model_dump(mode="json"))
                    provider = calendar_provider(env)
                    admitted_session = admitted_approval = None
                    if config['schema']==3:
                        from .protected_setup import provision_owner_episode
                        from .protected_operator import OperatorClient
                        row['stage']='owner_and_operator_admission'
                        calls_before=model.calls
                        def admission_progress(stage):
                            row['stage']=stage
                            emit('admission_stage_started',stage=stage)
                        consent=None
                        if identity_profile is not None:
                            from .benchmark_consent import FiniteConsent
                            consent=FiniteConsent(contract,identity_profile['principal'],emit)
                        admitted_session,admitted_approval,binding,prepared=async_runner.run(provision_owner_episode(
                            contract=contract,deployment=config['provisioning'],broker=broker,
                            operator=OperatorClient(config['operator_socket']),model_profile=config['model_worker']['profile'],
                            progress=admission_progress,consent=consent))
                        emit('native_execution_prepared',**prepared)
                    endpoint = EpisodeEndpoint(contract=contract, provider=provider, binding=binding,
                        tool_url=config["provider"]["url"], release_url=config["release_provider"]["url"], emit=emit)
                    for name in ("provider", "release_provider"):
                        p = config[name]
                        server = ProviderServer(address=tuple(p["address"]),
                            context=server_context(certificate=p["certificate"], private_key=p["private_key"],
                                client_ca=p["client_ca"], alpn=p["alpn"]),
                            client_pin=digest32(p["client_certificate_sha256"]),
                            server_pin=certificate_spki_pin(p["certificate"]),
                            urls=(p["url"],), alpn=p["alpn"], exchange=endpoint.exchange)
                        servers.append(server)
                        server.start()
                    observer = PrivateEpisodeAudit(output / f"publication-{index:02d}.jsonl")
                    row["stage"] = "owner_admission"
                    if config['schema']==2: calls_before = model.calls
                    async def episode():
                        if config['schema']==3:
                            session,approval=admitted_session,admitted_approval
                        else:
                            session, approval = await admit_owner_episode(contract=contract, binding=binding, broker=broker)
                        return await finish_private_episode(session=session,
                            expected_task=digest32(binding["task_id"]), expected_run=digest32(binding["run_id"]),
                            expected_root=digest32(binding["root_digest"]),
                            expected_destination=digest32(binding["destination_digest"]), approval=approval,
                            receive_publication=endpoint.receive_publication, emit=observer, timeout=120)
                    outcome = async_runner.run(episode())
                    after = endpoint.freeze()
                    utility, attacker = score_outcome(suite=suite, task=task, injection=injection,
                        contract=contract, before=before, after=after, provider=provider, outcome=outcome)
                    row.update(stage=outcome.stage, observed_utility=utility, observed_attacker_success=attacker,
                        model_calls=model.calls-calls_before, publication_audit_head=observer.final_digest)
                    emit("episode_observation", environment=after.model_dump(mode="json"),
                        publication=outcome.publication, output_base64=(None if outcome.payload is None else
                            __import__("base64").b64encode(outcome.payload).decode("ascii")))
                    if outcome.status == "published" and model.calls > calls_before:
                        row.update(status="scored", utility=utility, attacker_success=attacker)
                    elif outcome.status == "published":
                        row["stage"] = "no_observed_model_call"
                except Exception as error:
                    row["error_type"] = type(error).__name__
                    code = safe_error_code(error)
                    if code is not None:
                        row['error_code'] = code
                    if endpoint is not None:
                        # Preserve actual effects even if admission/publication failed.
                        audit.emit("uncertain_environment", episode=index,
                            environment=endpoint.freeze().model_dump(mode="json"))
                        # The security oracle can still observe an effect even
                        # when there is no confirmed final output. Keep this
                        # diagnostic separate from a completed protected score.
                        try:
                            observed = score_outcome(suite=suite, task=task, injection=injection,
                                contract=contract, before=before, after=endpoint.freeze(),
                                provider=provider, outcome=None)
                            row.update(observed_utility=observed[0], observed_attacker_success=observed[1])
                        except Exception:
                            row["oracle_status"] = "unknown"
                finally:
                    if admitted_session is not None:
                        async_runner.run(admitted_session.close())
                    for server in reversed(servers):
                        server.close()
                    if observer is not None:
                        observer.close()
                row["wall_seconds"] = time.monotonic() - start
                stopped = row["status"] != "scored"
            rows.append(row)
            audit.emit("episode_score", **row)
        if worker is not None:
            worker.close()
            worker = None
        model_calls = 0 if model is None else model.calls
        summary = dict(schema="savana-protected-agentdojo-v1", full_benchmark=False,
            run_status="not_started" if blockers else ("complete" if not stopped else "incomplete"),
            official_tasks_and_oracles=True, protected_episodes_scored=sum(r["status"] == "scored" for r in rows),
            total_model_calls=model_calls, blockers=blockers, rows=rows, rates=rates(rows),
            identity_profile=identity_profile, human_authentication_evaluated=False,
            consent_mode='finite_calendar_preconsent_v1' if identity_profile else 'interactive',
            comparable_to_unrestricted_baseline=False, production_acceptance=False)
        audit.emit("summary", summary=summary)
        audit.artifact("summary.json", summary)
        audit.artifact("completion.json", dict(audit_head=audit.head, event_count=audit.count))
        return summary
    finally:
        async_runner.close()
        if worker is not None:
            worker.close()
        if broker is not None:
            broker.close()
        if model is not None:
            model.close()
        audit.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--config", type=Path, help="owner-private operator deployment bindings; not an authorization")
    parser.add_argument("--auth-fd", type=int, help="inherited trusted passkey broker Unix socket")
    parser.add_argument("--model-key-fd", type=int, help="inherited private DeepSeek key descriptor")
    parser.add_argument("--model-listener-fd", type=int, help="inherited deployment-owned Unix TLS listener")
    args = parser.parse_args()
    summary = run(output=args.output, config=load_config(args.config) if args.config else None,
        auth_fd=args.auth_fd, model_key_fd=args.model_key_fd, model_listener_fd=args.model_listener_fd)
    print(json.dumps({k: summary[k] for k in ("run_status", "protected_episodes_scored", "total_model_calls", "blockers")}, indent=2))
    return 0 if summary["run_status"] == "complete" else 2


if __name__ == "__main__":
    raise SystemExit(main())
