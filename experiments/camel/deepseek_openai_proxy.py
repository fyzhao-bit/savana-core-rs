"""Loopback OpenAI-compatible relay to DeepSeek for the CaMeL comparison runs.

The API key is read once from stdin (a pipe) and held only in this process's
memory; clients use a dummy key. The requested model must be one of MODELS and the served model is logged.
Requests are normalized for DeepSeek
(developer role -> system, text-part lists -> strings, temperature 0 unless
given, thinking disabled) exactly like the Savana-side DeepSeek client. The
log records sizes, status and timing only, never message bodies or the key.
"""
import http.client
import json
import ssl
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

KEY = sys.stdin.readline().strip()
sys.stdin.close()
if not KEY:
    raise SystemExit("no key on stdin")
PORT = int(sys.argv[1])
LOG = open(sys.argv[2], "a", buffering=1)
# Model names a client may request; anything else is refused before it leaves.
MODELS = ("deepseek-flash", "deepseek-v4-pro")
LOCK = threading.Lock()
COUNT = {"calls": 0}


def flatten(content):
    if isinstance(content, list):
        return "".join(p.get("text", "") for p in content if isinstance(p, dict) and p.get("type") == "text")
    return content


def normalize(body):
    body = dict(body)
    messages = []
    for m in body.get("messages", []):
        m = dict(m)
        if m.get("role") == "developer":
            m["role"] = "system"
        if "content" in m:
            m["content"] = flatten(m["content"])
        messages.append(m)
    body["messages"] = messages
    for k in ("reasoning_effort", "store", "service_tier", "parallel_tool_calls", "stream_options"):
        body.pop(k, None)
    body.setdefault("temperature", 0)
    body["thinking"] = {"type": "disabled"}
    return body


def served(data):
    """The model name the upstream reports for this response (None if absent)."""
    try:
        return json.loads(data).get("model")
    except (ValueError, AttributeError):
        return None


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        start = time.monotonic()
        raw = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        if not self.path.rstrip("/").endswith("/chat/completions"):
            self.send_error(404)
            return
        request = normalize(json.loads(raw))
        if request.get("model") not in MODELS:
            self.send_error(400, "model not allowed")
            return
        body = json.dumps(request, ensure_ascii=False).encode()
        status, data = 599, b'{"error":"upstream"}'
        for attempt in range(3):
            try:
                c = http.client.HTTPSConnection("api.deepseek.com", timeout=120, context=ssl.create_default_context())
                c.request("POST", "/chat/completions", body=body,
                          headers={"Authorization": "Bearer " + KEY, "Content-Type": "application/json"})
                r = c.getresponse()
                status, data = r.status, r.read()
                c.close()
                if status < 500 and status != 429:
                    break
            except Exception as e:  # network error: retry, logged without detail
                status, data = 599, json.dumps({"error": type(e).__name__}).encode()
            time.sleep(2 ** attempt)
        with LOCK:
            COUNT["calls"] += 1
            n = COUNT["calls"]
        LOG.write(json.dumps({"n": n, "status": status, "req_bytes": len(body), "resp_bytes": len(data),
                              "seconds": round(time.monotonic() - start, 2), "attempt": attempt,
                              "poisoned": b"SECRET INSTRUCTIONS FROM THE PARTY" in body,
                              "requested": request["model"], "served": served(data)}) + "\n")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
