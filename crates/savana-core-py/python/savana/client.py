import asyncio
from enum import Enum
from pathlib import Path

import savana_core as _core


Handle = _core.Handle
MaskedView = _core.MaskedView
Plan = _core.Plan
PlanStep = _core.PlanStep
ApprovalRequest = _core.ApprovalRequest
ExecutionResult = _core.ExecutionResult
ConnectorDescriptor = _core.ConnectorDescriptor
TaskAuthorizationDraft = _core.TaskAuthorizationDraft
TaskAuthorizationReceipt = _core.TaskAuthorizationReceipt
RunLimits = _core.RunLimits
AgentEvent = _core.AgentEvent
SavanaError = _core.SavanaError
AuthError = _core.AuthError
ApprovalDenied = _core.ApprovalDenied
PolicyRefused = _core.PolicyRefused


class IntentPrivacy(str, Enum):
    PRIVATE = "private"
    THIRD_PARTY = "third_party"


class ContentKind(str, Enum):
    CHAT_TEXT = "chat_text"
    PLAIN_TEXT = "plain_text"
    PARSED_DOCUMENT = "parsed_document"


def _bridge(callback, loop):
    """Let an async callback be invoked from the blocking worker thread.

    The core invokes approval / webauthn / event callbacks synchronously on the
    thread that runs the blocking operation, so a coroutine function cannot be
    called there directly. If ``callback`` is async, wrap it so the coroutine
    runs on ``loop`` while the worker thread blocks on its result; the wrapper
    returns exactly what the coroutine returns (a ``bool`` for approvals). The
    event loop stays free to run that coroutine because it is only awaiting the
    ``to_thread`` future, so there is no deadlock. Sync callbacks (and ``None``)
    pass through unchanged, so existing callers are unaffected.
    """
    if callback is None or not asyncio.iscoroutinefunction(callback):
        return callback

    def _sync(*args, **kwargs):
        return asyncio.run_coroutine_threadsafe(
            callback(*args, **kwargs), loop
        ).result()

    return _sync


class Identity:
    __slots__ = ("_inner",)

    def __init__(self, inner=None):
        raise TypeError("Identity values are returned by Identity.load or Client.enroll")

    @classmethod
    def _from_core(cls, inner):
        self = object.__new__(cls)
        self._inner = inner
        return self

    @classmethod
    def load(cls, path):
        return cls._from_core(_core._Identity.load(str(Path(path))))

    def __repr__(self):
        return "Identity(<public-credential>)"


class Client:
    __slots__ = ("_inner",)

    def __init__(self):
        self._inner = _core._Client()

    async def session(self, identity, bootstrap, webauthn, approval):
        loop = asyncio.get_running_loop()
        inner = await asyncio.to_thread(
            self._inner.session,
            identity._inner,
            bootstrap,
            _bridge(webauthn, loop),
            _bridge(approval, loop),
        )
        return Session._from_core(inner)

    async def enroll(self, enrollment_token, code, webauthn, identity_path):
        loop = asyncio.get_running_loop()
        inner = await asyncio.to_thread(
            self._inner.enroll,
            enrollment_token,
            code,
            _bridge(webauthn, loop),
            str(Path(identity_path)),
        )
        return Identity._from_core(inner)

    def __repr__(self):
        return "Client(<fixed-loopback>)"


class Session:
    __slots__ = ("_inner", "_close_lock", "_closed")

    def __init__(self, inner=None):
        raise TypeError("Session values are returned by Client.session")

    @classmethod
    def _from_core(cls, inner):
        self = object.__new__(cls)
        self._inner = inner
        self._close_lock = asyncio.Lock()
        self._closed = False
        return self

    @property
    def initial_document(self):
        return self._inner.initial_document

    async def ingest_text(self, text, content_kind):
        return await asyncio.to_thread(
            self._inner.ingest_text,
            text,
            content_kind.value,
        )

    async def ingest_file(self, path, content_kind):
        return await asyncio.to_thread(
            self._inner.ingest_file,
            str(Path(path)),
            content_kind.value,
        )

    async def read_view(self, handle):
        return await asyncio.to_thread(self._inner.read_view, handle)

    async def establish_task_authorization(self, draft):
        """Submit structured data on authenticated ingress; Rust issues authority."""
        return await asyncio.to_thread(self._inner.establish_task_authorization, draft)

    async def approve_task_authorization(self, draft, approval):
        """Run distinct task-level approval, not a tool-action approval."""
        loop = asyncio.get_running_loop()
        return await asyncio.to_thread(
            self._inner.approve_task_authorization, draft, _bridge(approval, loop)
        )

    async def revoke_task_authorization(self, draft):
        return await asyncio.to_thread(self._inner.revoke_task_authorization, draft)

    async def recover_task_authorization(self, request_digest, approval):
        """Reauthenticate and resume an existing issuance; never create a replacement."""
        loop = asyncio.get_running_loop()
        return await asyncio.to_thread(
            self._inner.recover_task_authorization, request_digest, _bridge(approval, loop)
        )

    async def run_planner(self, intent_privacy):
        return await asyncio.to_thread(
            self._inner.run_planner,
            intent_privacy.value,
        )

    async def execute(self, plan, approval):
        loop = asyncio.get_running_loop()
        return await asyncio.to_thread(
            self._inner.execute, plan, _bridge(approval, loop)
        )

    async def run_agent(self, intent_privacy, limits, approval, events):
        loop = asyncio.get_running_loop()
        task = asyncio.ensure_future(
            asyncio.to_thread(
                self._inner.run_agent,
                intent_privacy.value,
                limits,
                _bridge(approval, loop),
                _bridge(events, loop),
            )
        )
        try:
            return await asyncio.shield(task)
        except asyncio.CancelledError:
            # The autonomous loop is the one call that can run long, so honor
            # task cancellation: trip the RunLimits cancel flag the core already
            # polls before every request, then drain the worker thread so the
            # session stays reusable/closeable before the cancellation
            # propagates. Single-shot ops have no cancel token and are left to
            # their bounded IO timeouts.
            try:
                limits.cancel()
            except AttributeError:
                pass
            await asyncio.gather(task, return_exceptions=True)
            raise

    async def release(self, document, approval):
        loop = asyncio.get_running_loop()
        return await asyncio.to_thread(
            self._inner.release, document, _bridge(approval, loop)
        )

    async def register_connector(self, descriptor, approval):
        loop = asyncio.get_running_loop()
        return await asyncio.to_thread(
            self._inner.register_connector, descriptor, _bridge(approval, loop)
        )

    async def remove_connector(self, connector):
        return await asyncio.to_thread(self._inner.remove_connector, connector)

    async def list_connectors(self):
        return await asyncio.to_thread(self._inner.list_connectors)

    async def revoke(self, document):
        return await asyncio.to_thread(self._inner.revoke, document)

    async def close(self):
        async with self._close_lock:
            if self._closed:
                return None
            self._closed = True
            return await asyncio.to_thread(self._inner.close)

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, traceback):
        await self.close()
        return False

    def __repr__(self):
        return "Session(<authenticated>)"
