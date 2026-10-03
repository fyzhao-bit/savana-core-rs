"""What each model provider was actually sent, measured from exported,
offline-verified run evidence with the kernel's own leak-gate definitions
(`savana-leak-gate`: pii_spans classes and the injection blocklist), via the
`pii_scan` example binary (cargo build -p savana-leak-gate --example pii_scan
--release).

Channels per drafted episode:
  planner    the untrusted planner's input, recomputed draft by draft exactly
             as the offline verifier does (and checked against the recorded
             request digest): the request as the planner saw it (as written,
             or masked under the value-blind view), and everything the owner
             side sent it (system rules, request, reviewed catalog, refusal
             feedback), sent by the harness directly, outside kernel mediation;
  extractor  each dojo.model.extract / dojo.model.generate call, dispatched by
             the kernel as an owner-approved SEND action: tool data (body and
             contexts) plus the owner request as instruction, as the
             extraction connector actually sent them (recomputed under the
             case's extractor view, masked or raw);
  kernel     the kernel-mediated model view (released_model_view), which the
             kernel's G2 gate requires to carry no residual PII;
and, for comparison, every official tool result of the episode (what an
undefended agent loop would hand its model).

Usage (from experiments/, with agentdojo and savana_core importable):
    python -m analysis.privacy_exposure --results DIR --scan BIN PREFIX...
"""
import argparse
import base64
import collections
import glob
import hashlib
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


def planner_inputs(events):
    """(request as the planner saw it, all owner-sent message text) per
    recorded draft, recomputed from the manifest case, the official prompt and
    the episode's earlier drafts and refusals."""
    from agentdojo.task_suite.load_suites import get_suite
    from savana_bench.root_drafter import draft_request_body
    cases, history, out = None, collections.defaultdict(list), []
    pending = {}
    for e in events:
        kind = e.get("kind")
        if kind == "manifest":
            cases = e["cases"]
        elif kind == "root_drafted":
            case = cases[e["episode"]]
            official = get_suite("v1.2.2", case["suite"])
            prompt = official.get_user_task_by_id(case["user"]).PROMPT
            body = draft_request_body(official, prompt, model=case.get("planner_model", "deepseek-flash"),
                                      goal=case.get("goal"), history=tuple(history[e["episode"]]),
                                      view=case.get("planner_view", "request"))
            if hashlib.sha256(body).hexdigest() != e["request_sha256"]:
                raise ValueError(f"planner input not recomputable: episode {e['episode']}")
            messages = json.loads(body)["messages"]
            request = json.loads(messages[1]["content"])["request"]
            out.append((request, "\n\n".join(m["content"] for m in messages if m["role"] != "assistant")))
            pending[e["episode"]] = e["program_text"]
        elif kind == "program_refused":
            history[e["episode"]].append((pending[e["episode"]], e["reason"], e.get("step"), e.get("field")))
    return out


def extractor_sent(arguments, suite, view):
    """(data, instruction) the extractor's model was sent for one call."""
    if view == "raw":
        data = "\n\n".join(arguments.get(k, "") for k in ("body", "context", "context2", "context3")
                           if arguments.get(k))
        return data, arguments.get("instruction", "")
    from agentdojo.task_suite.load_suites import get_suite
    from savana_bench.dojo_provider import extract_request
    body, _bindings, _bound = extract_request(arguments, {t.name: t for t in get_suite("v1.2.2", suite).tools},
                                              view)
    user = json.loads(json.loads(body)["messages"][1]["content"])
    return "\n\n".join(user[k] for k in ("SOURCE", "CONTEXT") if user.get(k)), user["INSTRUCTION"]


def collect(results, prefix):
    planner, extractor, tools = [], [], []
    views = collections.Counter()
    for _batch, events in verified_runs(results, prefix):
        planner += planner_inputs([json.loads(line) for line in open(events)])
        cases = []
        for line in open(events):
            e = json.loads(line)
            kind = e.get("kind")
            if kind == "manifest":
                cases = e["cases"]
            if kind == "released_model_view":
                views["views"] += 1
                views["public_view_bytes"] += len(e.get("job", {}).get("public_view") or [])
            elif kind == "official_tool_result":
                tools.append(json.dumps(e.get("response"), ensure_ascii=False))
            elif kind == "provider_attempt":
                p = json.loads(base64.b64decode(e["payload_base64"]))
                params = p.get("params") or {}
                if params.get("name") in EXTRACT_TOOLS:
                    case = cases[e["episode"]]
                    view = case.get("extractor_view", "raw") if params["name"] == "dojo.model.extract" else "raw"
                    extractor.append(extractor_sent(params.get("arguments") or {}, case["suite"], view))
    return planner, extractor, tools, views


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
        print("planner request as seen (harness->model, not gated):", summarize(args.scan, [r for r, _a in planner]))
        print("planner, all owner-sent text (rules+request+catalog+feedback):",
              summarize(args.scan, [a for _r, a in planner]))
        print("extractor tool data (body+contexts, kernel-dispatched send):",
              summarize(args.scan, [d for d, _i in extractor]))
        print("extractor instruction (owner request):", summarize(args.scan, [i for _d, i in extractor]))
        print("kernel model view (G2-gated):", dict(views))
        print("all official tool results (undefended-agent exposure):", summarize(args.scan, tools))


if __name__ == "__main__":
    main()
