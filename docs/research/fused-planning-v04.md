# Fused V2 / v0.4 planning implementation

Status: implementation in progress, 2026-09-20. This document is not a release
certificate. Existing V2 execution checks remain mandatory. Cloud inference,
model downloads, deployment and destructive migration are outside this change.

## Agreed architecture

Private authenticated intake fixes the root and resource bindings. A local
publisher constructs frozen, recipient-scoped views. An optional advisor returns
bounded untrusted template/question references; the host validates them and
rebuilds the planner envelope. The planner proposes a registered abstract program.
Local compilation, residual checking and private binding precede ordinary V2
approval, G1–G7 and execd. Results remain private until the same publisher admits
a further observation. Raw model prose never becomes an authority or release rule.

V2 structural ordering remains an explicit compatibility mode, not an implicit
fallback. Deterministic local topological sorting does not need an LLM. New
template planning uses a different versioned schema. Local models are untrusted
candidate builders and have no execution credentials. A remote self-hosted model
is still outside the private boundary.

## Implementation order / acceptance

1. Closed review/planning schemas, bounded decoding, deterministic envelope
   reconstruction, public job identity separate from private task bindings.
2. Durable outbox and once-only result settlement in the existing encrypted,
   rollback-anchored owner; current recipient/time checks on every transmission.
3. Registered-plan compiler and explicit residual replacement checks; preserve
   old executions, observations, counters and unresolved obligations.
4. V2 adapters and isolated placeholder workers; no live cloud dependency.
5. Authenticated ingress/SDK/UI wiring and full output mediation; strict mode
   stays disabled until all paths, scheduling and recovery premises are verified.
6. Regression/adversarial tests, encrypted restart and uncertain-commit tests,
   documentation and native Linux acceptance (not substituted by Mac tests).

## Initial restricted profile

The first review protocol uses root-approved constant public views and a public
logical schedule. It must not publish current resource counts, budget remainders,
task/root hashes, private errors, variable secret-dependent call counts or raw
model output. Retransmissions retain exact original bytes, identity and deadline;
send attempts are charged durably before returning bytes. A lost response may
spend a retry but never mint one. Advisor failure uses only an admitted fallback
at its public cut. Advice is accepted at most once, not sampled until favorable.

The initial replacement fragment is deliberately narrower than an arbitrary
program compiler: reorder remaining root-registered operations with unchanged
bindings, mandatory dependency coverage and exact retained started prefix. This
does not establish general C1–C6/BC0–BC5/K1–K6, dynamic private-loop compilation or
strict inference for a whole deployed service. Broader fragments need independent
coverage and progress checks before enablement.

## Non-negotiable boundaries

- Signed local bookkeeping configuration cannot create disclosure or business
  authority. Live egress still requires the existing release gates and an approved
  recipient; a local audit read is never an egress capability.
- A new worker, model, plan or session cannot erase public history or consumption.
- Current task authority and owner revision are rechecked at commit.
- Unknown is neither success nor retry authorization.
- Missing models use deterministic test workers only in explicit tests; no fake
  successful business effects or silent cloud fallback.
