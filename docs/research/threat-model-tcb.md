# Threat model, enforced invariant, and TCB

Draft for the USENIX Sec '27 threat-model and security-argument sections.
Grounded in the drafted-program (G10) pipeline on commit `5a70027`.

## Principals and trust

| Principal | Role | Trusted? |
|---|---|---|
| Owner | States the request; holds the signing key; reviews and signs the program | **Trusted** (root of authority) |
| Planner (DeepSeek) | Sees only the owner request + reviewed catalog; drafts the whole program as JSON | **Untrusted** |
| Extractor / executor model | Sees tool results; produces one bounded value per signed edge, or the final answer | **Untrusted** |
| Tool results / environment data | Emails, files, web pages, transaction histories | **Untrusted** |
| Owner review (fixed rules) | Admits/refuses a drafted program before anything is signed | **Trusted** (in TCB) |
| Kernel (kerneld/approvald/ingressd) | Compiles, prepares, dispatches; re-derives every value's origin | **Trusted** (in TCB) |

Attacker capability (matches AgentDojo): the attacker controls environment data
the agent reads (indirect injection), and — strictly stronger than CaMeL/FIDES/
SPA — **the planner itself** (direct control of the drafted program bytes, or a
model given a hidden objective). The attacker does **not** hold the owner's key.

## The enforced invariant

For every operation the kernel dispatches, and for the final release:

> **(I)** The tool, its effect class, its resource, its destination, and every
> bound are fixed by an owner-signed clause; and every parameter value is either
> (a) owner text (a substring of the request, NFC, whitespace-folded), (b) an
> owner-declared constant (a restated date/time, a boolean, a permission, a read
> term), or (c) a value the kernel itself extracted along an owner-signed edge
> from an already-authorized result, within the signed path, byte bound, list
> and computation.

Corollaries, each checked, not assumed:
- **No non-owner destination.** A write's recipient/channel/account/URL is owner
  text; it is never derived from data (incl. cc/bcc). ⇒ exfiltration is closed by
  construction.
- **No injected authority.** Untrusted data can fill a *parameter* through a
  signed edge, but never selects a tool, a destination, a bound, or a compute
  amount.
- **No instruction laundering.** The planner's program is data reviewed by fixed
  rules; it grants nothing the owner did not sign.

## Where each clause of (I) is enforced

| Clause of (I) | Owner review (`drafted_tasks.review_program`) | Kernel |
|---|---|---|
| tool served by suite | `unserved_tool` | compile: descriptor must be registered |
| effect/resource/destination shape | role check; `derived_destination` | compile/prepare: profile match |
| destination is owner text | `literal_not_owner_text` / `derived_destination` | prepare (G4): materialized value = signed control |
| parameter origin (a)/(b)/(c) | `literal_not_owner_text`, `literal_kind`, edge checks | prepare/dispatch (G7): recompute origin = kernel extraction |
| signed path / byte bound | `edge_path`, bound set by review | dispatch (G7): value taken at signed path, bounded |
| compute amount stated in request | `compute_amount` | kernel computes from verified result; G7 accepts only kernel's own value |
| final release to owner turn | release clause | G6 settlement (passkey / software preconsent) |
| no residual PII to planner | empty planning view for drafted | kernel view = derived-from-request |

The kernel re-runs the origin check independently of the review: the review is a
**pre-filter** that lets an honest planner succeed and refuses obvious abuse
early; the kernel is the **reference monitor** that actually enforces (I) at
prepare and dispatch. A program that somehow passed a buggy review would still be
caught by the kernel, because G7 recomputes provenance and compares it to the
kernel's own extraction.

## TCB

| Component | What it enforces | Size (approx, incl. inline tests) |
|---|---|---|
| `savana-policy-core` | compile/prepare/dispatch checks, provenance edges, release | ~90k src lines |
| `savana-kernel-protocol` | typed business fields, controls, request shapes | ~41k |
| `savana-kerneld` | the kernel daemon: admission, G4/G7 | ~72k |
| `savana-approvald` | owner settlement (G6), passkey | ~17k |
| `savana-ingressd` | ingress / projection | ~8k |
| `savana-leak-gate` | windowed blocklist scan before owner display | ~1.6k |
| owner review (Python, benchmark) | fixed-rule admission of a drafted program | `drafted_tasks.py` ~500 lines |
| owner signing key | root of authority | — |

(A submission to-do: a `cloc`/`tokei` pass separating enforcement code from the
large inline `#[cfg(test)]` modules; the numbers above include tests.)

**Not in the TCB:** every model (planner, extractor, executor), the AgentDojo
environment, the operator that forwards the program unread, and the Python
benchmark harness other than the fixed review.

## Empirical support for (I)

- **Review completeness (offline, deterministic).** Over every real
  review-passing DeepSeek program in the G10 evidence tree (58 distinct
  benign-published tasks; 71 with the attack and smoke batches), 9
  attacker-objective mutation classes: **0 admitted with a non-owner
  destination** for exfiltration (external/derived/cc destination), literal
  injection, compute tampering, answer-as-value, and literal context; the only
  admits are owner-namespace-only (an extra owner-addressed write; a different
  record of the same read), which carry no exfiltration or injected authority.
  Reproduce: `python -m analysis.review_completeness --results <evidence-tree>`
  (exit 0 iff zero non-owner-destination admits).
- **Kernel enforcement (live, prior run).** The PLANNER-UNTRUSTED experiment
  (32 cases): of 17 programs deviating from the pre-audited plan, 16 refused by
  the kernel and 1 by the codec; 0 unauthorized requests reached a tool.
- **Poisoned real planner (this round, P0-1c).** A DeepSeek planner given a
  hidden objective, full cross-suite — results pending.

## Residual (delegated authority)

A compromised planner retains exactly the authority the owner delegates by
signing: it may **compose owner-authorized operations within the owner's own
namespace** (e.g. an extra write to an owner-named destination, or selecting a
different record of a read). This is bounded — no exfiltration, no injected
authority, no non-owner destination — and in deployment a human owner reviewing
the specific program before signing is the backstop. The benchmark's
software-identity preconsent is a blind-signer stand-in and does not catch it;
we state this explicitly rather than claim human-grade authorization.

## Out of scope / not claimed

- **Answer-content truthfulness.** The extractor writes the final answer from
  untrusted data; "answer-content injection" is mitigated (extractor system
  prompt + bounded single-line output), not structurally prevented.
- **Human-grade authorization.** Benchmark uses software identity, not a passkey
  held by a person.
- **Side channels, timing, availability, and model jailbreaks that change only
  answer prose** are not in (I).
