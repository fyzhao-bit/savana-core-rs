"""One reviewed official episode behind the authenticated execd endpoint.

This object is NOT an authorization gate. Its only production caller must be
ProviderServer after mTLS. A restart cannot resume it; ambiguous effects stay
Unknown. Neither model proposals nor the score runner invoke the tool runtime.

It recomputes, independently of the kernel, the one call each operation may
make. Two kinds of operation never reach it: a guarded call whose condition
does not hold, and the compute step; the kernel's executor answers both
itself. The endpoint recomputes those answers from the actual earlier results
and accounts for them in order (`executor_local_result`) before the next call
it does receive. A deployment that ships the model tools with the model codec
(`model_codec="mcp_model"`) has the executor mask their arguments; the
endpoint expects exactly that masked call and records the reply with the
call's values back, as the executor retains it.

A call that does not come back succeeded ends what this episode can do: the
executor keeps its outcome Unknown and the kernel starts nothing more for the
task (an Unknown call blocks later steps, and with them the release). The
endpoint records which call it was and why (`official_tool_failed`, a closed
code from the provider), and `failed_step` tells the runner, which then stops
waiting for a publication that cannot come.
"""
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
    def __init__(self, *, contract, provider, binding, tool_url, release_url, emit, model_codec="mcp"):
        from .agentdojo_tasks import MODEL_CODECS
        if model_codec not in MODEL_CODECS:
            raise ValueError("model_codec")
        self.contract, self.provider, self.emit, self.model_codec = contract, provider, emit, model_codec
        self.binding = {k: digest32(binding[k]) for k in
            ("task_id", "run_id", "root_digest", "destination_digest", "application_turn", "resource")}
        self.tool_url, self.release_url = tool_url, release_url
        self._lock = threading.Lock()
        # Every operation's result as the kernel retains it, in order; `_local`
        # names the operations the executor answered itself.
        self._seen, self._results, self._local, self._payload = {}, [], set(), None
        self._release_id, self._closed, self._failed = None, False, False
        self._failed_step = None

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
                self._advance_local()
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
            if frame.url != self.tool_url or self._payload is not None or number >= len(self.contract.steps()):
                raise ValueError("reviewed_tool_request_mismatch")
            expected, masker = self.expected_tool_params(number)
            if request.get("params") != expected:
                raise ValueError("reviewed_tool_request_mismatch")
            step = self.contract.steps()[number]
            response = self.provider.exchange(frame.payload)
            status = decode(response)["result"]["structuredContent"]["savana_status"]
            if status != "succeeded":
                # The provider's own record of this request says why (a closed code).
                digest = hashlib.sha256(frame.payload).hexdigest()
                row = next((r for r in reversed(self.provider.audit) if r["request_sha256"] == digest), {})
                failed = dict(operation=number + 1, tool=step.tool, status=status, error=row.get("error"))
                self.emit("official_tool_failed", **failed)
                self._failed_step = failed
                raise ValueError("official_tool_outcome_unknown")
            # The provider's reply goes back as it is; the executor retains a
            # model call's reply with the call's own values back (any other
            # placeholder neutralized), and so does this record of it.
            retained = response
            if masker is not None:
                from .value_blind import unmask_model_reply
                retained = unmask_model_reply(masker, response)
            result = decode(retained)
            self._results.append(retained)
            # Exactly what the official function received: the fixed synthetic
            # controls are checked and dropped by the provider adapter, and every
            # other field decoded by its reviewed rule (the reviewed generator
            # tools are Savana's own, recorded as sent).
            from .dojo_catalog import SENTINELS
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
            or payload != self._released(payload) or self._payload is not None):
            raise ValueError("final_release_payload_mismatch")
        # The receiver stores bytes before acknowledging. The kernel commit is
        # observed independently through PrivateSession, never inferred here.
        self.emit("result_received", payload_base64=body["payload"],
            payload_sha256=hashlib.sha256(payload).hexdigest(), resource=body["resource"],
            destination=body["destination"], request_id=request["request_id"])
        self._payload = payload
        return canonical({"request_id": request["request_id"], "status": "succeeded"})

    def expected_tool_params(self, number):
        """(the one authorized call for reviewed operation `number` (0-based),
        as it reaches the provider; the Masker that puts its reply back, or
        None). Derived fields are recomputed HERE from the actual earlier
        results. The kernel extracts independently; a disagreement refuses the
        call before the provider runs."""
        from .agentdojo_tasks import expected_wire_params
        step = self.contract.steps()[number]
        if step.payload_from and step.payload_from - 1 in self._local:
            # A local answer's envelope carries the kernel's own request id; the
            # owner's review passes it on only by an edge to its text.
            raise ValueError("local_result_as_payload")
        return expected_wire_params(self.contract, number, self._results, self.model_codec)

    def _advance_local(self):
        """Account, in order, for each next operation the kernel's executor
        answers itself and never sends here: its answer is recomputed from the
        actual earlier results (`agentdojo_tasks.executor_local_text`)."""
        from .agentdojo_provider import response
        from .agentdojo_tasks import LOCAL_REQUEST_ID, executor_local_text
        while self._payload is None and len(self._results) < len(self.contract.steps()):
            number = len(self._results)
            text = executor_local_text(self.contract, number, self._results)
            if text is None:
                return
            reply = response(LOCAL_REQUEST_ID, "succeeded", text)
            self._results.append(reply)
            self._local.add(number)
            self.emit("executor_local_result", operation=number + 1, tool=self.contract.steps()[number].tool,
                      response=decode(reply))

    def _released(self, payload):
        """The last result as the kernel releases it. A local answer is known
        here up to the request id its envelope echoes: the kernel's own
        (`step-` and 64 hex digits), taken from the release itself."""
        last = len(self.contract.steps()) - 1
        if last not in self._local:
            return self._results[-1]
        try:
            echoed = decode(payload)["id"]
        except Exception:
            return None
        if type(echoed) is not str or not re.fullmatch(r"step-[0-9a-f]{64}", echoed):
            return None
        local = decode(self._results[-1])
        return canonical(dict(local, id=echoed))

    def failed_step(self):
        """The call that came back not succeeded ({operation, tool, status,
        error}), or None. Set once, and read without the endpoint's lock: the
        runner's wait asks while a provider call may be holding it."""
        failed = self._failed_step
        return None if failed is None else dict(failed)

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
