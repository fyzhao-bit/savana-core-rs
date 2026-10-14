"""Native v0.4 → execd → real AgentDojo runtime conformance, no LLM.

Uses explicit debug kernel fixtures with synthetic signatures/rollback anchors.
NOT AgentDojo official task/attack scores, a production adapter or attestation.
"""
import asyncio
import hashlib
import importlib.metadata
import os
from pathlib import Path
import shutil
import struct
import tempfile

from .agentdojo_provider import MAX_BYTES, canonical, synthetic_mail_provider
from .agentdojo_publication import SyntheticResultReceiver
from .component_loop import source_digest, stop

TEST = "v2_agent_authority::tests::fused_compiler_tests::fused_agentdojo_provider_roundtrip_v04"
SCHEDULE = (("two_steps", 32, 2), ("reopen", 33, 2), ("approval", 34, 2),
            ("revoked", 35, 1), ("three_steps", 36, 3),
            ("final_publication", 41, 2), ("publication_reopen", 42, 2))


def inspect_effects(provider, expected, injection, publication=False):
    """Independent observation of actual AgentDojo outbox and provider frames."""
    emails = list(provider.env.inbox.sent)
    rows = provider.audit
    if len(rows) != expected or len(emails) != expected:
        return False
    ids = [r["request"]["id"] for r in rows]
    if len(set(ids)) != expected or any(r["status"] != "succeeded" for r in rows):
        return False
    for index, (row, email, alias, label, recipient) in enumerate(zip(
        rows, emails, ("Alice", "Bob", "Carol"), ("A", "B", "C"),
        ("alice@example.org", "bob@example.org", "carol@example.org"),
    )):
        args = row["request"]["params"]["arguments"]
        if (args["to"] != alias or args["file"] != label or email.subject != label
            or list(email.recipients) != [recipient] or email.body != args["body"]
            or email.attachments or email.cc or email.bcc):
            return False
        if index:
            # The entire previous authenticated MCP reply becomes the next
            # payload, never control fields. Compare hash to actual sent bytes.
            if hashlib.sha256(email.body.encode()).hexdigest() != rows[index - 1]["response_sha256"]:
                return False
            if injection and "UNTRUSTED INJECTION" not in email.body:
                return False
    publications = getattr(provider, "publications", [])
    if publication:
        return (len(publications) == 1 and expected > 0
                and publications[0]["payload_sha256"] == rows[-1]["response_sha256"]
                and publications[0]["turn"] == "application-turn:" + "04" * 32)
    return not publications


async def one_probe(executable, case, expected, injection, timeout):
    provider = synthetic_mail_provider(injection=injection)
    publication = case in (41, 42)
    if publication:
        provider = SyntheticResultReceiver(provider, turn="04" * 32)
    errors, tasks, writers = [], set(), set()

    async def handle(reader, writer):
        writers.add(writer)
        try:
            async with asyncio.timeout(6):
                size = struct.unpack("!I", await reader.readexactly(4))[0]
                if not 0 < size <= MAX_BYTES:
                    raise ValueError("frame_size")
                request = await reader.readexactly(size)
                reply = provider.exchange(request)
                writer.write(struct.pack("!I", len(reply)) + reply)
                await writer.drain()
        except Exception:
            errors.append("provider_transport_error")
        finally:
            writer.close()
            await writer.wait_closed()
            writers.discard(writer)

    def accept(reader, writer):
        task = asyncio.create_task(handle(reader, writer))
        tasks.add(task)
        task.add_done_callback(tasks.discard)

    # Short private path: macOS and Linux Unix sockets have small path limits.
    with tempfile.TemporaryDirectory(prefix="savana-adj-", dir="/tmp") as directory:
        socket = Path(directory) / "p.sock"
        server = await asyncio.start_unix_server(accept, path=str(socket))
        os.chmod(socket, 0o600)
        process = None
        status, output = "error", b""
        try:
            env = {**{k: os.environ[k] for k in ("PATH", "LANG", "LC_ALL") if k in os.environ},
                   "SAVANA_AGENTDOJO_TEST_SOCKET": str(socket),
                   "SAVANA_AGENTDOJO_TEST_CASE": str(case)}
            process = await asyncio.create_subprocess_exec(
                str(executable), TEST, "--exact", "--ignored", "--test-threads=1",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
                env=env, start_new_session=True,
            )
            try:
                output, _ = await asyncio.wait_for(process.communicate(), timeout)
                passed = (process.returncode == 0 and
                          b"1 passed; 0 failed; 0 ignored" in output)
                status = "completed" if passed and not errors and inspect_effects(provider, expected, injection, publication) else "error"
            except TimeoutError:
                status = "timeout"
        finally:
            if process is not None:
                await stop(process)
            server.close()
            await server.wait_closed()
            for writer in list(writers):
                writer.close()
            if tasks:
                await asyncio.gather(*list(tasks), return_exceptions=True)
        return {
            "status": status, "effect_count": len(provider.env.inbox.sent),
            "expected_effects": expected, "injection": injection,
            "dataflow_verified": status == "completed",
            "model_safety_rate": None,
            "audit": provider.audit,
            "publications": getattr(provider, "publications", []),
            "expected_publications": int(publication),
            "publication_count": len(getattr(provider, "publications", [])),
            "outbox": [m.model_dump(mode="json") for m in provider.env.inbox.sent],
        }, output


async def run(*, kernel_test, output, timeout=45):
    # Cargo may rebuild the caller's path while trials are running. Pin one
    # private executable snapshot for the entire schedule, never hash one build
    # and silently execute another. This is provenance, not build attestation.
    executable = Path(kernel_test).resolve(strict=True)
    if not executable.is_file() or not os.access(executable, os.X_OK):
        raise ValueError("invalid_test_executable")
    with tempfile.TemporaryDirectory(prefix="savana-kernel-", dir="/tmp") as directory:
        pinned = Path(directory) / "kernel-test"
        with executable.open("rb") as source, pinned.open("xb") as target:
            before = os.fstat(source.fileno())
            if not 0 < before.st_size <= 512 * 1024 * 1024:
                raise ValueError("invalid_test_executable_size")
            shutil.copyfileobj(source, target, 1024 * 1024)
            after = os.fstat(source.fileno())
            if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                    after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                raise ValueError("test_executable_changed_while_copying")
        pinned.chmod(0o500)
        return await _run_pinned(kernel_test=pinned, output=output, timeout=timeout)


async def _run_pinned(*, kernel_test, output, timeout=45):
    if type(timeout) is not int or not 1 <= timeout <= 300:
        raise ValueError("invalid_timeout")
    version = importlib.metadata.version("agentdojo")
    if version != "0.1.35":
        raise ValueError("agentdojo_version_not_reviewed")
    executable = Path(kernel_test).resolve(strict=True)
    if not executable.is_file() or not os.access(executable, os.X_OK):
        raise ValueError("invalid_test_executable")
    # Ensure the exact ignored case exists before creating a result directory.
    probe = await asyncio.create_subprocess_exec(str(executable), "--list",
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, start_new_session=True)
    try:
        listing, _ = await asyncio.wait_for(probe.communicate(), 10)
    finally:
        await stop(probe)
    if probe.returncode != 0 or f"{TEST}: test".encode() not in listing.splitlines():
        raise ValueError("missing_exact_native_test")
    output = Path(output)
    manifest = {
        "schema": "savana-agentdojo-native-conformance-v1",
        "scope": "synthetic_native_provider_conformance",
        "agentdojo_version": version,
        "agentdojo_source_sha256": runtime_digest(),
        "source_tree_sha256": source_digest(),
        "kernel_test_sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
        "kernel_test_pinned_for_entire_schedule": True,
        "official_benchmark_tasks": False, "model_evaluation": False,
        "production_acceptance": False,
        "schedule": [{"case": name, "native_case": case, "expected_effects": count,
                      "expected_publications": int(case in (41, 42)), "injection": injection}
                     for name, case, count in SCHEDULE for injection in (False, True)],
    }
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    (output / "manifest.json").write_bytes(canonical(manifest))
    rows = []
    for index, item in enumerate(manifest["schedule"]):
        # Persist trial start so interruption cannot silently remove a case.
        (output / f"{index:02d}.started.json").write_bytes(canonical(item))
        result, log = await one_probe(executable, item["native_case"], item["expected_effects"], item["injection"], timeout)
        (output / f"{index:02d}.audit.json").write_bytes(canonical(result))
        (output / f"{index:02d}.kernel.log").write_bytes(log)
        rows.append({**item, **{k: v for k, v in result.items() if k not in ("audit", "outbox", "publications")}})
    if hashlib.sha256(executable.read_bytes()).hexdigest() != manifest["kernel_test_sha256"]:
        raise ValueError("pinned_executable_changed")
    summary = {"scope": manifest["scope"], "agentdojo_version": version,
               "total": len(rows), "passed": sum(r["status"] == "completed" for r in rows),
               "model_evaluation": False, "official_benchmark_tasks": False,
               "production_acceptance": False, "cases": rows}
    (output / "summary.json").write_bytes(canonical(summary))
    return summary


def runtime_digest():
    """Bind installed implementation bytes, not just a mutable version string."""
    import agentdojo
    root = Path(agentdojo.__file__).resolve().parent
    h = hashlib.sha256()
    for path in sorted(root.rglob("*.py")):
        name = path.relative_to(root).as_posix().encode()
        data = path.read_bytes()
        h.update(len(name).to_bytes(4, "big") + name + hashlib.sha256(data).digest())
    return h.hexdigest()
