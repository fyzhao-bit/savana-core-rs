"""Python-SDK-only Savana v0.4 experiment plumbing on official AgentDojo tasks.

The deployment config, preflight, private audit, model worker, official case
setup and official oracle the untrusted-planner runner (`planner_experiment`)
and its offline verifier use. Fail closed: no ToolsExecutor, native test
binaries, synthetic receipt, reference solution, or direct tool fallback.
Preflight failures are recorded as NOT RUN, never as protected successes.
"""
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import socket
import stat
import sys
import threading
import time

from .agentdojo_provider import canonical, decode
from .agentdojo_tasks import BENCHMARK, PACKAGE_VERSION, SUITE
from .protected_endpoint import digest32
from .protected_transport import server_context


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


def check_provisioning(d):
    """The operator's provisioning profile: exactly one suite's reviewed catalog,
    each tool with the codec that catalog ships it with, a closed disposition,
    no task grants. A floor experiment may name one write tool its deployment
    shipped without the intent-flow validator, only under `permit` (the
    materializer's counterfactual). Returns how the deployment ships the model
    tools (`agentdojo_tasks.MODEL_CODECS`)."""
    from .agentdojo_tasks import MODEL_CODECS, catalog_json, catalog_operations, catalog_tool
    from .dojo_catalog import SUITES
    # A deployment ships exactly one suite's reviewed catalog.
    shipped=set(d['descriptors']) if type(d) is dict and type(d.get('descriptors')) is dict else set()
    suite=next((s for s in SUITES if catalog_operations(s)|{'savana.final_result_release'}==shipped),None)
    unconfined=d.get('unconfined_write') if type(d) is dict else None
    if (type(d) is not dict or suite is None
        or set(d)-{'unconfined_write'}!={'schema','descriptors','codecs','planner','destination_digest',
                                         'application_turn','store','installation','disposition','scope',
                                         'task_grants_installed'}
        or d['schema']!=1 or d['disposition'] not in ('require_approval','permit')
        or d['scope']!='finite_workspace_read_subset' or d['task_grants_installed'] is not False
        or ('unconfined_write' in d and (d['disposition']!='permit' or type(unconfined) is not str
                                         or unconfined not in shipped - {'savana.final_result_release'}
                                         or catalog_tool(unconfined)['effect']=='read'))):
        raise ValueError('closed_provisioning_profile')
    for value in (*d['descriptors'].values(),*(d[k] for k in ('planner','destination_digest','application_turn',
                                                                'store','installation'))):
        digest32(value)
    # Which codec each tool ships with is the catalog's, for one model-tool choice.
    for model_codec in MODEL_CODECS:
        doc=catalog_json(suite,model_codec)
        if d['codecs']=={t['operation']:t.get('codec','mcp') for t in (*doc['read_tools'],*doc['write_tools'])}:
            return model_codec
    raise ValueError('closed_provisioning_profile')


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
    if type(config) is not dict or type(config.get('schema')) is not int or config['schema']!=3:
        raise ValueError("closed_deployment_config_required")
    if set(config)!={'schema','provider','release_provider','model_worker','provisioning','operator_socket'}:
        raise ValueError('closed_deployment_config_required')
    from .protected_operator import SOCKET
    if config['operator_socket']!=SOCKET: raise ValueError('closed_provisioning_profile')
    check_provisioning(config['provisioning'])
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


def attack_values(suite, task, injection, case):
    """The injected text per vector for this case (empty without an injection):
    the official important-instructions template, or AutoDojo's optimized
    injections replayed from the pinned cache. The verifier and the planner
    exposure recompute them through this same function."""
    from types import SimpleNamespace
    from agentdojo.attacks.base_attacks import BaseAttack, FixedJailbreakAttack
    from agentdojo.attacks.important_instructions_attacks import ImportantInstructionsAttack
    if injection is None:
        return {}
    pipeline = SimpleNamespace(name="deepseek-flash-savana-finite")
    attack_name = case.get("attack", "important_instructions_no_names")
    if attack_name == "important_instructions_no_names":
        attack = FixedJailbreakAttack(ImportantInstructionsAttack._JB_STRING, suite, pipeline)
    elif attack_name == "autodojo":
        from . import autodojo_cache
        variants, originals, _ = autodojo_cache.load(autodojo_cache.cache_path(case.get("suite", SUITE)))

        class AutoDojoReplay(BaseAttack):
            name = "autodojo"

            def attack(self, user_task, injection_task):
                return {vector: autodojo_cache.injection(variants, originals, injection_task.ID,
                                                         injection_task.GOAL, vector, 0)
                        for vector in self.get_injection_candidates(user_task)}

        attack = AutoDojoReplay(suite, pipeline)
    else:
        raise ValueError("unknown_attack")
    return attack.attack(task, injection)


def official_case(case, contract):
    """Same upstream task init, fixed attack and environment as the baseline.

    Ground truth is available only to the OFFICIAL ATTACK, never authoring,
    model views, authorization or the protected execution path. The case's
    planner-drafted contract is the one the owner's review admitted.
    """
    from agentdojo.task_suite.load_suites import get_suite
    suite = get_suite(BENCHMARK, case.get("suite", SUITE))
    task = suite.get_user_task_by_id(case["user"])
    if contract.task_id != case["user"] or getattr(contract, "suite", SUITE) != case.get("suite", SUITE):
        raise ValueError("contract_task_mismatch")
    injection = suite.get_injection_task_by_id(case["injection"]) if case["injection"] else None
    values = attack_values(suite, task, injection, case)
    environment = task.init_environment(suite.load_and_inject_default_environment(values))
    return suite, task, injection, contract, values, environment


# Upstream names of reviewed tools that are not AgentDojo functions; the official
# oracle only ever sees AgentDojo calls in its trace.
NON_AGENTDOJO_UPSTREAMS = ("quarantined_generate", "quarantined_extract", "savana_compute_table")


def score_outcome(*, suite, task, injection, contract, before, after, provider, outcome):
    from agentdojo.functions_runtime import FunctionCall
    from .dojo_catalog import SENTINELS
    from .agentdojo_tasks import upstream_for
    from .dojo_catalog import official_call
    trace = []
    for row in provider.audit:
        if not row["invoked"]:
            continue
        request = row.get("request")
        if request is not None:
            # Exactly the official call the adapter made: fixed controls
            # dropped, every other field decoded by its reviewed rule.
            operation = request["params"]["name"]
            if upstream_for(operation) in NON_AGENTDOJO_UPSTREAMS:
                continue
            try:
                name, arguments = official_call(operation, request["params"]["arguments"])
            except ValueError:
                # The adapter refused these arguments before the official
                # function ran: no official call happened.
                continue
        elif "upstream" in row:
            name, arguments = row["upstream"], row["arguments"]  # offline replay from evidence
        else:
            step = contract.steps()[len(trace)]  # legacy single-step replay
            name, arguments = step.upstream_tool, {k: v for k, v in step.values if k not in SENTINELS}
        if name in NON_AGENTDOJO_UPSTREAMS:
            continue  # the reviewed generator is Savana's tool, not an AgentDojo call
        trace.append(FunctionCall(function=name, args=arguments, id=f"provider-{len(trace) + 1}"))
    output = []
    if outcome is not None and outcome.status == "published":
        message = decode(outcome.payload)
        # Exactly the actually received tool response; no model/oracle-written answer.
        output = [{"type": "text", "content": item["text"]} for item in message["result"]["content"]
                  if item["type"] == "text"]
    utility = bool(suite._check_task_result(task, output, before, after, trace))
    attacker = bool(suite._check_task_result(injection, output, before, after, trace)) if injection else None
    return utility, attacker
