"""Python-SDK-only completion leg for an already admitted private v0.4 task.

This is NOT an official AgentDojo runner or an authorization/bootstrap factory.
The caller owns the real authenticated session and approved result receiver.
No tool executor, Rust binary subprocess, internal IPC, raw vault reads, model
answer fallback, synthetic receipt, oracle or automatic approval lives here.
"""
import asyncio
from dataclasses import dataclass, field
import math
import inspect
import time


@dataclass(frozen=True)
class PrivateOutcome:
    # "published" means receipt + bytes matched, not task utility or safety.
    status: str
    stage: str
    duration_seconds: float
    publication: dict | None = field(default=None, repr=False)
    payload: bytes | None = field(default=None, repr=False)


def _record(emit, event):
    # A forgotten coroutine must never masquerade as a flushed audit record.
    result = emit(event)
    if inspect.isawaitable(result):
        if inspect.iscoroutine(result):
            result.close()
        raise TypeError("synchronous_durable_audit_writer_required")


async def finish_private_episode(*, session, expected_task, expected_run,
        expected_root, expected_destination, approval, receive_publication,
        emit, timeout=120.0):
    """Observe a committed release, then match bytes from its approved receiver.

    receive_publication is an async application transport callback, invoked with
    task_id/run_id/release_id/destination_digest; it must read the already
    published result, never execute an upstream tool. emit receives owner-only
    metadata dictionaries synchronously; it must durably record them or raise. No prompts,
    payloads, passkeys, credentials or exception strings are emitted here.

    Setup/infrastructure failure, denial, timeout and receiver mismatch remain
    Unknown. Only the separate official oracle may evaluate utility/attacks on
    the actual environment, including effects before an Unknown outcome. An
    Unknown is not proof of no effects and MUST NOT be dropped from denominators.
    The session is closed after observation, without cancelling the remote run.
    """
    from savana.private_v04 import PrivateSession, PublicationReceipt

    if type(session) is not PrivateSession:
        raise TypeError("native_private_session_required")
    bindings = (expected_task, expected_run, expected_root, expected_destination)
    if any(type(v) is not bytes or len(v) != 32 or v == bytes(32) for v in bindings):
        raise ValueError("exact_publication_scope_required")
    if any(not callable(v) for v in (approval, receive_publication, emit)):
        raise ValueError("explicit_approval_receiver_and_audit_required")
    if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 900:
        raise ValueError("bounded_timeout_required")
    started = time.monotonic()
    stage, status, metadata, payload = "wait_publication", "unknown", None, None
    try:
        _record(emit, {"kind": "private_wait_started", "task_id": expected_task.hex(),
              "run_id": expected_run.hex(), "root_digest": expected_root.hex(),
              "destination_digest": expected_destination.hex()})
        async with asyncio.timeout(timeout):
            receipt = await session.wait_publication(expected_task=expected_task,
                expected_root=expected_root, approval=approval, timeout=timeout)
            stage = "publication_scope"
            if (type(receipt) is not PublicationReceipt
                or receipt.task_id != expected_task or receipt.run_id != expected_run
                or receipt.root_digest != expected_root
                or receipt.destination_digest != expected_destination):
                raise ValueError("publication_scope_mismatch")
            metadata = {name: getattr(receipt, name).hex() for name in (
                "task_id", "run_id", "root_digest", "release_id", "destination_digest",
                "payload_digest", "approval_digest", "receipt_digest", "audit_digest", "commit_digest")}
            _record(emit, {"kind": "private_publication_committed", **metadata})
            stage = "receive_publication"
            received = await receive_publication(task_id=receipt.task_id,
                run_id=receipt.run_id, release_id=receipt.release_id,
                destination_digest=receipt.destination_digest)
            stage = "match_payload"
            if type(received) is not bytes or not receipt.matches_payload(received):
                raise ValueError("publication_payload_mismatch")
            _record(emit, {"kind": "private_payload_verified", "commit_digest": receipt.commit_digest.hex(),
                  "payload_digest": receipt.payload_digest.hex(), "payload_bytes": len(received)})
            payload, status, stage = received, "published", "complete"
    except asyncio.CancelledError:
        # Caller must retain the attempted case and check real environment state.
        raise
    except Exception:
        # Never treat refusal/timeout as attack resistance; details stay private.
        status, payload = "unknown", None
    finally:
        try:
            await session.close()
        except asyncio.CancelledError:
            raise
        except Exception:
            status, stage, payload = "unknown", "close", None
    # Audit failure propagates: a run without its final record is not scored.
    _record(emit, {"kind": "private_episode_observed", "status": status, "stage": stage,
          "utility": None, "attacker_success": None})
    return PrivateOutcome(status, stage, time.monotonic() - started, metadata, payload)
