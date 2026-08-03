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

    async def session(self, identity, bootstrap, webauthn):
        inner = await asyncio.to_thread(
            self._inner.session,
            identity._inner,
            bootstrap,
            webauthn,
        )
        return Session._from_core(inner)

    async def enroll(self, enrollment_token, code, webauthn, identity_path):
        inner = await asyncio.to_thread(
            self._inner.enroll,
            enrollment_token,
            code,
            webauthn,
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

    async def read_view(self, document):
        return await asyncio.to_thread(self._inner.read_view, document)

    async def run_planner(self, intent_privacy):
        return await asyncio.to_thread(
            self._inner.run_planner,
            intent_privacy.value,
        )

    async def execute(self, plan, approval):
        return await asyncio.to_thread(self._inner.execute, plan, approval)

    async def run_agent(self, intent_privacy, limits, approval, events):
        return await asyncio.to_thread(
            self._inner.run_agent,
            intent_privacy.value,
            limits,
            approval,
            events,
        )

    async def release(self, document, approval):
        return await asyncio.to_thread(self._inner.release, document, approval)

    async def register_connector(self, descriptor, approval):
        return await asyncio.to_thread(
            self._inner.register_connector,
            descriptor,
            approval,
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
