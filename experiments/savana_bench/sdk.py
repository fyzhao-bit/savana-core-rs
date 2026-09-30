"""V2 SDK COMPONENT adapter. Not a complete private v0.4 benchmark adapter.

No model routing, approval simulation, trust creation or oracle is hidden here.
The caller supplies an authenticated fresh session, a task-derived root draft,
real approval callback and limits. Attack labels are never passed to this API.
"""
import asyncio
from dataclasses import dataclass
import time


@dataclass(frozen=True)
class ComponentOutcome:
    status: str
    stage: str
    duration_seconds: float
    # Deliberately no prompt, exception string, credentials or raw event output.


async def run_v2_component(*, open_session, prompt, draft, limits, approval,
                           sdk=None):
    if sdk is None:
        import savana as sdk
    if not callable(approval):
        raise ValueError("explicit_approval_callback_required")
    started = time.monotonic()
    stage = "session"
    status = "error"
    session = None
    try:
        session = await open_session()
        stage = "ingest"
        await session.ingest_text(prompt, sdk.ContentKind.CHAT_TEXT)
        stage = "authorize"
        await session.establish_task_authorization(draft)
        stage = "agent"
        await session.run_agent(sdk.IntentPrivacy.PRIVATE, limits, approval, None)
        status = "completed"
    except (sdk.PolicyRefused, sdk.ApprovalDenied):
        # Root/setup rejection is a setup failure, not an agent safety success.
        status = "refused" if stage == "agent" else "error"
    except asyncio.CancelledError:
        limits.cancel()
        raise
    except TimeoutError:
        status = "timeout"
    except Exception:
        status = "error"
    finally:
        if session is not None:
            try:
                await session.close()
            except Exception:
                status = "error"
                stage = "close"
    return ComponentOutcome(status, stage, time.monotonic() - started)
