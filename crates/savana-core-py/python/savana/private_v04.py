"""Trusted owner-side v0.4 interface, never an LLM/Agent tool surface.

The transfer must already have been issued by authenticated Ingress for an
enrolled, committed private task. This module does not enroll tasks, publish
results or run an AgentDojo tool. No fallback to the public V2 Agent session.
"""
import asyncio
import math

import savana_core as _core
from .client import _bridge

PublicationReceipt = _core._PrivatePublicationV04
__all__ = ["connect", "connect_from_ingress", "PrivateSession", "PublicationReceipt"]


class _WebAuthnBridge:
    def __init__(self, provider, loop):
        # Native WebAuthn expects methods, not a callback function. Bridge each
        # async method explicitly; never send a coroutine object to Rust.
        self.assert_credential = _bridge(provider.assert_credential, loop)


async def _drain(worker):
    """Finish local cleanup even if cancellation is requested repeatedly."""
    while not worker.done():
        try:
            await asyncio.shield(worker)
        except asyncio.CancelledError:
            continue
        except BaseException:
            break
    try:
        return worker.result()
    except BaseException as error:
        return error


async def connect(*, identity, transfer, webauthn):
    """Authenticate the owner using a 43-character private Ingress transfer.

    Authentication may enable kernel admission; it does not approve an action
    or confirm that the owner clock has admitted/completed the task.
    """
    loop = asyncio.get_running_loop()
    return await _connect(_core._Client().private_session_v04,
                          identity, transfer, webauthn, loop)


async def connect_from_ingress(*, identity, ingress_tab, webauthn):
    """Use an existing authenticated Ingress tab; no intermediate token export.

    The trusted intake must already have committed input and installed a signed
    root/private plan. Never obtain this capability from Agent/HTTP input or
    browser scraping. This function cannot create that prior authorization.
    """
    loop = asyncio.get_running_loop()
    return await _connect(_core._Client().private_session_from_ingress_v04,
                          identity, ingress_tab, webauthn, loop)


async def _connect(method, identity, reference, webauthn, loop):
    worker = asyncio.create_task(asyncio.to_thread(
        method, identity._inner, reference, _WebAuthnBridge(webauthn, loop),
    ))
    try:
        inner = await asyncio.shield(worker)
    except asyncio.CancelledError:
        # Do not leave an authenticated capability alive in a discarded worker.
        # The server-side authentication is NOT rolled back by local cleanup.
        outcome = await _drain(worker)
        if not isinstance(outcome, BaseException):
            await _drain(asyncio.create_task(asyncio.to_thread(outcome.close)))
        raise
    return PrivateSession._from_core(inner)


class PrivateSession:
    __slots__ = ("_inner", "_lock", "_closed")

    def __init__(self):
        raise TypeError("PrivateSession values are returned by private_v04.connect")

    @classmethod
    def _from_core(cls, inner):
        self = object.__new__(cls)
        self._inner = inner
        self._lock = asyncio.Lock()
        self._closed = False
        return self

    async def _call(self, method, *args):
        async with self._lock:
            if self._closed:
                raise _core.SavanaError("private_session_closed")
            worker = asyncio.create_task(asyncio.to_thread(method, *args))
            try:
                return await asyncio.shield(worker)
            except asyncio.CancelledError:
                # Drain I/O/callback before releasing the session lock.
                # Cancellation cannot unsign or refund an already sent decision.
                await _drain(worker)
                self._closed = True
                await _drain(asyncio.create_task(asyncio.to_thread(self._inner.close)))
                raise

    async def poll_approval(self):
        """Return whether a private approval awaits review, NOT task status."""
        return await self._call(self._inner.poll_approval)

    async def poll_publication(self):
        """Return native committed publication metadata, or None/unknown.

        This is not a portable attestation or application-storage receipt. It
        contains no raw output. Use receipt.matches_payload(already_received)
        before scoring/delivering a result obtained from the approved receiver.
        """
        return await self._call(self._inner.poll_publication)

    async def wait_publication(self, *, expected_task, expected_root, approval,
                               timeout=120.0, poll_interval=1.0):
        """Service explicit approval callbacks until kernel publication.

        No tool execution, root issuance, implicit approval or direct-runtime
        fallback. Timeout closes local capabilities but does NOT cancel/refund
        the remote run; uncertain effects must remain Unknown in experiments.
        """
        if any(type(v) is not bytes or len(v) != 32 or v == bytes(32)
               for v in (expected_task, expected_root)):
            raise ValueError("exact_task_and_root_required")
        if (not callable(approval) or any(type(v) not in (int, float) or not math.isfinite(v)
                for v in (timeout, poll_interval))
                or not 0 < timeout <= 900 or not 0.1 <= poll_interval <= 5):
            raise ValueError("explicit_approval_and_bounded_wait_required")
        try:
            async with asyncio.timeout(timeout):
                while True:
                    receipt = await self.poll_publication()
                    if receipt is not None:
                        if receipt.task_id != expected_task or receipt.root_digest != expected_root:
                            raise _core.SavanaError("private_publication_scope_mismatch")
                        return receipt
                    if await self.poll_approval():
                        if not await self.review_pending(approval):
                            raise _core.ApprovalDenied("private_decision_denied")
                    await asyncio.sleep(poll_interval)
        except BaseException:
            await _drain(asyncio.create_task(self.close()))
            raise

    async def review_pending(self, approval):
        """Review one handoff with display auth, user choice and signed decision.

        The callback receives the native ApprovalRequest with authenticated
        display and purpose ("tool_execution" or "final_release"). Login and
        prior tool decisions never imply approval to publish a final result.
        Returns True for a confirmed approval or False for a confirmed denial.
        Exceptions/uncertainty must never be classified as safe or completed.
        """
        loop = asyncio.get_running_loop()
        return await self._call(self._inner.review_pending, _bridge(approval, loop))

    async def close(self):
        """Forget local capabilities only; does not cancel/revoke the kernel run."""
        async with self._lock:
            if not self._closed:
                self._closed = True
                worker = asyncio.create_task(asyncio.to_thread(self._inner.close))
                try:
                    await asyncio.shield(worker)
                except asyncio.CancelledError:
                    await _drain(worker)
                    raise

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, traceback):
        await self.close()

    def __repr__(self):
        return "PrivateSessionV04(<private-owner>)"
