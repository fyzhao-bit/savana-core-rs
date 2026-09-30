"""Private Linux operator API, deliberately separate from Agent Client/Session.

Requires root and an independently signed canonical Rust command. No signing
keys are loaded by this module. Never expose it as an Agent/MCP/chat tool.
"""
import asyncio

import savana_core as _core


def prepare_artifact(kind: str, document: bytes):
    """Privately validate/canonicalize a command or profile without sending it.

    Kinds: command, planning_draft, planning_profile, storage_profile, dispatch_policy,
    source_policy, recipe_approval. Rust returns canonical_bytes() and the purpose-separated
    signing_digest(). Review the canonical bytes, then use the independently
    provisioned signing authority. This helper holds no signing key, does not
    approve anything and does not validate the current kernel deployment.
    """
    if not isinstance(kind, str) or not isinstance(document, bytes):
        raise TypeError("kind must be str and document must be bytes")
    if not 0 < len(document) <= 256 * 1024:
        raise ValueError("invalid private artifact size")
    return _core._managed_admin_prepare_artifact(kind, document)


async def submit_signed(command: bytes, signature: bytes):
    """Return a private historical receipt (redacted repr, explicit private_json).

    An exception or cancellation does NOT prove rollback. Retain and resubmit
    exactly the same bytes/signature to resolve uncertain delivery. This helper
    does not generate IDs, sign commands, retry, or change task authorization.
    Parsing, peer checks, framing, deadlines and receipt validation run in Rust.
    """
    if not isinstance(command, bytes) or not isinstance(signature, bytes):
        raise TypeError("command and signature must be bytes")
    if not 0 < len(command) <= 256 * 1024 or len(signature) != 64:
        raise ValueError("invalid signed command size")
    return await asyncio.to_thread(_core._managed_admin_submit_signed, command, signature)
