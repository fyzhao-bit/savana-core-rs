"""One reviewed official episode behind the authenticated execd endpoint.

This object is NOT an authorization gate. Its only production caller must be
ProviderServer after mTLS. A restart cannot resume it; ambiguous effects stay
Unknown. Neither model proposals nor the score runner invoke the tool runtime.
"""
import asyncio
import base64
import hashlib
import json
import re
import threading

from .agentdojo_provider import canonical, decode


def digest32(value):
    if type(value) is not str or not re.fullmatch(r"[0-9a-f]{64}", value) or value == "0" * 64:
        raise ValueError("nonzero_hex_digest_required")
    return bytes.fromhex(value)


class EpisodeEndpoint:
    def __init__(self, *, contract, provider, binding, tool_url, release_url, emit):
        self.contract, self.provider, self.emit = contract, provider, emit
        self.binding = {k: digest32(binding[k]) for k in
            ("task_id", "run_id", "root_digest", "destination_digest", "application_turn", "resource")}
        self.tool_url, self.release_url = tool_url, release_url
        self._lock = threading.Lock()
        self._seen, self._results, self._payload = {}, [], None
        self._release_id, self._closed, self._failed = None, False, False

    def exchange(self, frame):
        with self._lock:
            if self._closed or self._failed:
                raise ValueError("episode_endpoint_closed")
            if frame.nonce in self._seen:
                prior, response = self._seen[frame.nonce]
                if prior != frame.wire_digest or response is None:
                    raise ValueError("executor_nonce_rebound_or_unknown")
                return response
            if len(self._seen) >= len(self.contract.steps()) + 1:
                raise ValueError("episode_attempt_limit")
            self._seen[frame.nonce] = (frame.wire_digest, None)
            # Write-ahead evidence before any official function is invoked.
            # Failure poisons this endpoint; no new nonce can bypass ambiguity.
            try:
                self.emit("provider_attempt", nonce=frame.nonce.hex(), core=frame.core.hex(),
                    subject=frame.subject.hex(), wire_digest=frame.wire_digest.hex(),
                    payload_sha256=hashlib.sha256(frame.payload).hexdigest(), url=frame.url,
                    target_pin=frame.pin.hex(), payload_base64=base64.b64encode(frame.payload).decode("ascii"))
                response = self._exchange(frame)
                self.emit("provider_reply", nonce=frame.nonce.hex(),
                    response_sha256=hashlib.sha256(response).hexdigest())
            except BaseException:
                self._failed = True
                raise
            self._seen[frame.nonce] = (frame.wire_digest, response)
            return response

    def _exchange(self, frame):
        # Canonical business JSON is independently bound by the outer frame.
        # Larger bound allows base64 expansion of the final 32 KiB result.
        def pairs(items):
            result = {}
            for key, value in items:
                if key in result:
                    raise ValueError("duplicate_business_field")
                result[key] = value
            return result
        request = json.loads(frame.payload, object_pairs_hook=pairs)
        if canonical(request) != frame.payload or type(request) is not dict:
            raise ValueError("noncanonical_business_request")
        if request.get("method") == "tools/call":
            number = len(self._results)
            if (frame.url != self.tool_url or self._payload is not None
                or number >= len(self.contract.steps())
                or request.get("params") != self.expected_tool_params(number)):
                raise ValueError("reviewed_tool_request_mismatch")
            step = self.contract.steps()[number]
            response = self.provider.exchange(frame.payload)
            result = decode(response)
            if result["result"]["structuredContent"]["savana_status"] != "succeeded":
                raise ValueError("official_tool_outcome_unknown")
            self._results.append(response)
            # Exactly what the official function received: the fixed synthetic
            # controls are checked and dropped by the provider adapter, and every
            # other field decoded by its reviewed rule (the reviewed generator
            # tools are Savana's own, recorded as sent).
            from .agentdojo_calendar import SENTINELS
            from .dojo_catalog import CATALOG, official_call
            arguments = request["params"]["arguments"]
            if any(t["operation"] == step.tool for t in CATALOG):
                _, official = official_call(step.tool, arguments)
            else:
                official = {k: v for k, v in arguments.items() if k not in SENTINELS}
            self.emit("official_tool_result", operation=number + 1, tool=step.upstream_tool,
                arguments=official,
                response=result,
                environment=self.provider.env.model_dump(mode="json"))
            return response
        if (frame.url != self.release_url or set(request) != {"method", "path", "request_id", "body"}
            or request["method"] != "POST" or request["path"] != "/savana/final-result-release"
            or type(request["request_id"]) is not str
            or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", request["request_id"])):
            raise ValueError("final_release_request_mismatch")
        body = request["body"]
        if (type(body) is not dict or set(body) != {"resource", "destination", "payload"}
            or body["resource"] != "result:" + self.binding["resource"].hex()
            or body["destination"] != "application-turn:" + self.binding["application_turn"].hex()
            or type(body["payload"]) is not str):
            raise ValueError("final_release_destination_mismatch")
        raw = body["payload"].encode("ascii")
        payload = base64.b64decode(raw + b"=" * (-len(raw) % 4), altchars=b"-_", validate=True)
        if (base64.urlsafe_b64encode(payload).rstrip(b"=") != raw or len(payload) > 32768
            or len(self._results) != len(self.contract.steps())
            or payload != self._results[-1] or self._payload is not None):
            raise ValueError("final_release_payload_mismatch")
        # The receiver stores bytes before acknowledging. The kernel commit is
        # observed independently through PrivateSession, never inferred here.
        self.emit("result_received", payload_base64=body["payload"],
            payload_sha256=hashlib.sha256(payload).hexdigest(), resource=body["resource"],
            destination=body["destination"], request_id=request["request_id"])
        self._payload = payload
        return canonical({"request_id": request["request_id"], "status": "succeeded"})

    def expected_tool_params(self, number):
        """The one authorized call for reviewed operation `number` (0-based);
        derived fields are recomputed HERE from the actual earlier results. The
        kernel extracts independently; a disagreement refuses the call before
        the provider runs."""
        from .agentdojo_tasks import expected_step_call
        return expected_step_call(self.contract, number, self._results)

    def completed_results(self):
        with self._lock:
            return list(self._results)

    async def receive_publication(self, *, task_id, run_id, release_id, destination_digest):
        with self._lock:
            if (self._failed or self._payload is None
                or any(value != self.binding[key] for key, value in (
                    ("task_id", task_id), ("run_id", run_id), ("destination_digest", destination_digest)))
                or type(release_id) is not bytes or len(release_id) != 32 or not any(release_id)
                or self._release_id not in (None, release_id)):
                raise ValueError("publication_not_received_in_this_episode")
            self._release_id = release_id
            return self._payload

    def freeze(self):
        with self._lock:
            self._closed = True
            return self.provider.env.model_copy(deep=True)


async def admit_owner_episode(*, contract, binding, broker):
    """Only public Python SDK calls enter the kernel. No key or direct IPC.

    Requires a real bootstrap from the trusted broker, the independently
    installed signed plan/registry, and distinct input/root user approvals.
    An operator-supplied draft is never treated as an admitted authorization.
    """
    from savana.owner_ingress import connect

    async def approval(request):
        import time
        return await asyncio.to_thread(broker.decide_approval, request.display,
            request.purpose, int(time.time() * 1000) + 120000)

    ingress = await connect(bootstrap=await broker.next(), webauthn=broker)
    async with ingress:
        await ingress.commit_text(contract.prompt, approval)
        context = await ingress.task_authorization_context()
        draft = context.draft(digest32(binding["authorization_id"]), canonical(binding["clauses"]))
        receipt = await ingress.approve_task_authorization(draft, approval)
        if receipt.authorization_digest != digest32(binding["root_digest"]):
            raise ValueError("admitted_root_not_the_installed_plan_root")
        return await ingress.into_private_session(), approval
