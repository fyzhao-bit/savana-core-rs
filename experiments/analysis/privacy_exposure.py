"""What each model provider was actually sent, measured from exported,
offline-verified run evidence with the kernel's own leak-gate definitions
(`savana-leak-gate`: pii_spans classes and the injection blocklist), via the
`pii_scan` example binary (cargo build -p savana-leak-gate --example pii_scan
--release).

Channels per drafted episode:
  planner    the untrusted planner's input: the owner request + the reviewed
             catalog (the catalog carries no user data), sent by the harness
             directly, outside kernel mediation;
  extractor  each dojo.model.extract / dojo.model.generate call, dispatched by
             the kernel as an owner-approved SEND action: tool data (body and
             contexts) plus the owner request as instruction;
  kernel     the kernel-mediated model view (released_model_view), which the
             kernel's G2 gate requires to carry no residual PII;
and, for comparison, every official tool result of the episode (what an
undefended agent loop would hand its model).

Usage (from experiments/): python -m analysis.privacy_exposure --results DIR --scan BIN PREFIX...
"""
import argparse
import base64
import collections
import glob
import json
import os
import subprocess

EXTRACT_TOOLS = ("dojo.model.extract", "dojo.model.generate")


def scan(binary, texts):
    """[(credential, personal, protected, blocklist, bytes)] per text."""
    if not texts:
        return []
    data = b"\0".join(t.encode() for t in texts)
    out = subprocess.run([binary], input=data, capture_output=True, check=True).stdout.decode().split("\n")
    return [tuple(int(x) for x in line.split()) for line in out if line.strip()]


def verified_runs(results, prefix):
    for batch in sorted(glob.glob(f"{results}/{prefix}-*")):
        v = os.path.join(batch, "offline-verification.json")
        runs = glob.glob(f"{batch}/*/events.jsonl")
        if os.path.exists(v) and os.path.getsize(v) > 0 and len(runs) == 1:
            yield batch, runs[0]


def collect(results, prefix):
    planner, extractor, tools = [], [], []
    views = collections.Counter()
    for _batch, events in verified_runs(results, prefix):
        prompts = {}
        for line in open(events):
            e = json.loads(line)
            kind = e.get("kind")
            if kind == "episode_input" and isinstance(e.get("contract"), dict):
                prompts[e["episode"]] = e["contract"].get("prompt", "")
            elif kind == "root_drafted":
                planner.append(("draft", e["episode"]))
            elif kind == "released_model_view":
                views["views"] += 1
                views["public_view_bytes"] += len(e.get("job", {}).get("public_view") or [])
            elif kind == "official_tool_result":
                tools.append(json.dumps(e.get("response"), ensure_ascii=False))
            elif kind == "provider_attempt":
                p = json.loads(base64.b64decode(e["payload_base64"]))
                params = p.get("params") or {}
                if params.get("name") in EXTRACT_TOOLS:
                    a = params.get("arguments") or {}
                    data = "\n\n".join(a.get(k, "") for k in ("body", "context", "context2", "context3") if a.get(k))
                    extractor.append((data, a.get("instruction", "")))
        # each drafting call sends that episode's owner request
        planner[:] = [(prompts.get(ep, "") if kind == "draft" else kind, ep) for kind, ep in planner]
    return [p for p, _ep in planner], extractor, tools, views


def summarize(binary, texts):
    rows = scan(binary, texts)
    n = len(rows)
    return dict(n=n, bytes=sum(r[4] for r in rows),
                with_personal=sum(r[1] > 0 for r in rows), with_credential=sum(r[0] > 0 for r in rows),
                with_protected_ref=sum(r[2] > 0 for r in rows), with_injection=sum(r[3] > 0 for r in rows),
                personal_spans=sum(r[1] for r in rows))


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--results", required=True)
    ap.add_argument("--scan", required=True)
    ap.add_argument("prefix", nargs="+")
    args = ap.parse_args()
    for prefix in args.prefix:
        planner, extractor, tools, views = collect(args.results, prefix)
        print(f"\n## {prefix}")
        print("planner (owner request, harness->model, not gated):", summarize(args.scan, planner))
        print("extractor tool data (body+contexts, kernel-dispatched send):",
              summarize(args.scan, [d for d, _i in extractor]))
        print("extractor instruction (owner request):", summarize(args.scan, [i for _d, i in extractor]))
        print("kernel model view (G2-gated):", dict(views))
        print("all official tool results (undefended-agent exposure):", summarize(args.scan, tools))


if __name__ == "__main__":
    main()
