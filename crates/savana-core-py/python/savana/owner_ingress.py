"""Trusted, text-only owner intake; never expose this module as an Agent tool.

Bootstrap issuance, an interactive WebAuthn provider and signed private-plan
installation are deployment prerequisites, not fabricated by this SDK.
"""
import asyncio

import savana_core as _core
from .client import _bridge
from .private_v04 import PrivateSession, _WebAuthnBridge, _drain

__all__ = ["connect", "OwnerIngress"]


async def _close(inner):
    await _drain(asyncio.create_task(asyncio.to_thread(inner.close)))


async def connect(*, bootstrap, webauthn):
    """Authenticate an existing registered passkey against a real Ingress task.

    Accepts a raw kernel-issued bootstrap, not a URL or enrollment code. Login
    neither commits text nor grants task authority. No SDK Identity is needed.
    """
    loop = asyncio.get_running_loop()
    worker = asyncio.create_task(asyncio.to_thread(
        _core._Client().owner_ingress, bootstrap, _WebAuthnBridge(webauthn, loop),
    ))
    try:
        inner = await asyncio.shield(worker)
    except asyncio.CancelledError:
        outcome = await _drain(worker)
        if not isinstance(outcome, BaseException):
            await _close(outcome)
        raise
    return OwnerIngress._from_core(inner)


class OwnerIngress:
    __slots__ = ("_inner", "_lock", "_closed")

    def __init__(self):
        raise TypeError("OwnerIngress values are returned by owner_ingress.connect")

    @classmethod
    def _from_core(cls, inner):
        self = object.__new__(cls)
        self._inner, self._lock, self._closed = inner, asyncio.Lock(), False
        return self

    async def _call(self, method, *args, handoff=False):
        async with self._lock:
            if self._closed:
                raise _core.SavanaError("owner_ingress_closed")
            worker = asyncio.create_task(asyncio.to_thread(method, *args))
            try:
                result = await asyncio.shield(worker)
            except asyncio.CancelledError:
                outcome = await _drain(worker)
                self._closed = True
                if handoff and not isinstance(outcome, BaseException):
                    await _close(outcome)
                await _close(self._inner)
                raise
            except BaseException:
                self._closed = True
                await _close(self._inner)
                raise
            if handoff:
                self._closed = True
                return PrivateSession._from_core(result)
            return result

    async def task_authorization_context(self):
        """Owner-only kernel context; not a grant and not a model input."""
        return await self._call(self._inner.task_authorization_context)

    async def commit_text(self, text, approval):
        """Commit one 1..65536-byte UTF-8 text after distinct signed approval."""
        if not isinstance(text, str) or not 0 < len(text.encode("utf-8")) <= 65536:
            raise ValueError("text must contain 1..65536 UTF-8 bytes")
        return await self._call(self._inner.commit_text, text,
                                _bridge(approval, asyncio.get_running_loop()))

    async def approve_task_authorization(self, draft, approval):
        """Review and sign a typed draft; cannot infer authority from chat."""
        return await self._call(self._inner.approve_task_authorization, draft,
                                _bridge(approval, asyncio.get_running_loop()))

    async def into_private_session(self):
        """One-way handoff after input commit and root approval.

        The kernel still checks a signed v0.4 plan, owner, boot and expiry.
        Failure never falls back to the Agent API or retries automatically.
        """
        return await self._call(self._inner.into_private_session, handoff=True)

    async def close(self):
        """Forget local capabilities; no remote rollback, cancellation or refund."""
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

    async def __aexit__(self, *_):
        await self.close()

    def __repr__(self):
        return "OwnerIngress(<private-owner>)"
