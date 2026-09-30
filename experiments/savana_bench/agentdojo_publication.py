"""Synthetic publication receiver for native conformance, NOT production auth.

Only the native debug executor's private socket may invoke this test seam.
The kernel test verifies the signed resource/root/approval; this independent
observer verifies the application turn and the actual terminal provider bytes.
No AgentDojo benchmark oracle or model score is implemented here.
"""
import base64
import hashlib
import re
import threading

from .agentdojo_provider import canonical, decode


class SyntheticResultReceiver:
    def __init__(self, provider, *, turn):
        if not isinstance(turn, str) or not re.fullmatch(r"[0-9a-f]{64}", turn) or turn == "0" * 64:
            raise ValueError("invalid_turn")
        self.provider, self.turn = provider, "application-turn:" + turn
        self.publications = []
        self._last_result = None
        self._release = None
        self._lock = threading.Lock()

    @property
    def env(self):
        return self.provider.env

    @property
    def audit(self):
        return self.provider.audit

    def exchange(self, data):
        request = decode(data)
        with self._lock:
            if isinstance(request, dict) and request.get("method") == "tools/call":
                if self._release is not None:
                    raise ValueError("already_published")
                result = self.provider.exchange(data)
                if decode(result)["result"]["structuredContent"]["savana_status"] == "succeeded":
                    self._last_result = result
                return result
            if (not isinstance(request, dict) or set(request) != {"method", "path", "request_id", "body"}
                or request["method"] != "POST" or request["path"] != "/savana/final-result-release"
                or not isinstance(request["request_id"], str)
                or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", request["request_id"])):
                raise ValueError("invalid_release")
            body = request["body"]
            if (not isinstance(body, dict) or set(body) != {"resource", "destination", "payload"}
                or body["destination"] != self.turn or not isinstance(body["resource"], str)
                or not re.fullmatch(r"result:[0-9a-f]{64}", body["resource"])
                or body["resource"] == "result:" + "0" * 64
                or not isinstance(body["payload"], str)):
                raise ValueError("invalid_release_binding")
            try:
                encoded = body["payload"].encode("ascii")
                payload = base64.b64decode(encoded + b"=" * (-len(encoded) % 4), altchars=b"-_", validate=True)
            except (ValueError, UnicodeError) as error:
                raise ValueError("invalid_release_payload") from error
            if base64.urlsafe_b64encode(payload).rstrip(b"=") != encoded or len(payload) > 32768:
                raise ValueError("invalid_release_payload")
            if self._last_result is None or payload != self._last_result:
                raise ValueError("not_the_terminal_provider_result")
            digest = hashlib.sha256(data).hexdigest()
            if self._release is not None:
                prior, response = self._release
                if digest != prior:
                    raise ValueError("release_rebound")
                return response
            response = canonical({"request_id": request["request_id"], "status": "succeeded"})
            self._release = digest, response
            self.publications.append({
                "request_sha256": digest, "request_id": request["request_id"],
                "resource": body["resource"], "turn": body["destination"],
                "payload_sha256": hashlib.sha256(payload).hexdigest(),
                "payload_bytes": len(payload), "response_sha256": hashlib.sha256(response).hexdigest(),
            })
            return response
