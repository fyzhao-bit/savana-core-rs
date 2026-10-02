# Related work: the 2026 wave of agent prompt-injection defenses

Draft for the USENIX Sec '27 related-work section. Positions Savana against the
closest systems and states, in one sentence, what is ours.

**Verification status.** Numbers below are transcribed from abstracts / search
summaries; arXiv is blocked from the experiment container, so each number marked
`[abs]` must be checked against the published PDF before submission. The
*structural* columns (who is trusted, where enforcement happens) are the load-
bearing comparison and do not depend on the exact numbers.

## The one-sentence position

Every listed defense keeps at least one model inside its trusted computing base:
the "clean" planner that sees only the user request is trusted to emit the plan,
the authorization graph, or the capability blueprint. **Savana puts no model in
the TCB.** The untrusted planner's whole program is data; authority comes only
from owner-signed clauses and edges; an out-of-process kernel re-derives every
value's origin at prepare and dispatch. "Instructions as data, authority by
signature."

## Positioning matrix

| System | Planner / "clean context" trusted? | Enforcement location | Value-level provenance | Human authorization step | Exfiltration structurally closed? | AgentDojo (model) |
|---|---|---|---|---|---|---|
| **Savana (this work)** | **No** — planner program is reviewed data | **Out-of-process kernel** (prepare + dispatch) | Yes — per value, owner-signed edges | Yes — passkey settlement (benchmark: software preconsent) | Yes — destinations owner-text only | benign 30/97; poisoned-planner ASR 0 `[ours]` |
| CaMeL \[debenedetti2025camel\] | Yes — P-LLM code is control | In-process interpreter + capabilities | Yes — capability labels | No | Partly — policy-dependent | benign 58/97; ASR 2/98 (same-condition, ours) |
| FIDES \[costa2025fides\] | Yes — planner under integrity lattice | In-process IFC | Yes — dual-lattice labels | No | Yes (confidentiality lattice) | `[abs]` |
| SPA \[spa2026\] | Yes — planner once per query | In-process dual-lattice IFC | Yes — labels across control deps | No | Yes | ASR 0.0%; utility 53→29% with IFC `[abs]` |
| ToolFence \[toolfence2026\] | Blueprint compiler + judge trusted | Deterministic monitor + judge | Yes — provenance on authority params | Judge grants capabilities (not a human) | Yes — capability shape | ASR ~0; clean-utility −3.8pp (Qwen3-max) `[abs]` |
| AuthGraph \[authgraph2026\] | Yes — authorization graph from clean context | Graph alignment check | Yes — parameter-source graph | No | Detection (1–2% ASR), not prevention | ASR 1–2% `[abs]` |
| PlanGuard \[planguard2026\] | Yes — isolated planner reference plan | Runtime plan-consistency check | Action-level, not value-level | No | Detection vs reference plan | `[abs]` |
| Progent \[shih2025progent\] | Policy author trusted | Tool-argument policy check | Argument-level | No | Policy-dependent | `[abs]` |

Columns, precisely:
- **Planner trusted** — does the design assume a model whose output is authority
  (plan / graph / blueprint) because it was run on a "clean" user-only context?
  Savana is the only "No": the planner is run on the user request alone *and* its
  output is still only a proposal that the fixed review and the kernel check.
- **Enforcement location** — in-process (same address space as the agent loop)
  vs a separate, smaller monitor. Savana's kernel is a separate process; the
  agent/model never shares its address space.
- **Value-level provenance** — does the monitor check where each *value* came
  from, not just which tool/argument shape is allowed?
- **Human authorization** — is there a point where a human (or a key only a human
  holds) must approve, distinct from a model/judge decision?
- **Exfiltration structurally closed** — is "send to a non-owner destination"
  impossible by construction (vs. detected / policy-dependent)? Savana: a write's
  destination must be owner text, enforced by the kernel; our offline review
  sweep admits 0 exfiltration/authority-injection mutations across 7 attack
  classes, over every real review-passing program in the G10 evidence tree.

## What is genuinely new vs. prior art

Savana is close in spirit to two older ideas and should cite them as such:
- **Capability systems** \[dennis1966, miller2006robust\]: authority is an
  unforgeable token, not a property of content. Savana's owner-signed clauses and
  edges are capabilities over *value origins*.
- **Verified untrusted programs** (e.g. an in-kernel verifier for untrusted
  bytecode): an untrusted program is admitted only after a checker proves bounded
  behavior, then runs under enforcement. Savana applies this to an LLM planner:
  the planner is untrusted, the review is the static checker, the kernel is the
  runtime monitor.

The contribution is the *combination* applied to LLM agents: even the planner is
untrusted, and a separate kernel re-derives every value's origin per call — which,
to our knowledge from the systems above, no prior agent defense does.

## Honest boundaries to state in the section

- Savana enforces **operational integrity** (origin of every value, destination,
  bound, tool). It does **not** certify the truthfulness of free-form answer text
  the extractor writes from untrusted data; that class ("answer-content
  injection", e.g. travel `injection_task_6`) is mitigated, not prevented. The
  0/2 gap vs. CaMeL on those pairs is measured, not proven.
- The residual authority a compromised planner keeps is **operation composition
  within the owner's own namespace** (an extra owner-addressed write; a different
  record of the same read). It carries no exfiltration and no injected authority;
  in deployment a human owner signing the specific program is the backstop. The
  benchmark's software-identity preconsent is a blind-signer stand-in and does
  not catch it — we say so.

## Bib entries to add (metadata to verify against PDFs)

```bibtex
@misc{spa2026,
  author = {Dylan Girrens and Guangjing Wang},
  title  = {{SPA}: Securing Persistent {LLM} Agents Across Queries with Plan-First Information-Flow Control},
  year   = {2026}, note = {arXiv:2608.27234; verify} }
@misc{toolfence2026,
  title  = {{ToolFence}: Fine-Grained Authorization for Secure Tool-Using {LLM} Agents},
  year   = {2026}, note = {arXiv:2609.37196; authors/venue verify} }
@misc{authgraph2026,
  title  = {Aligning Provenance with Authorization: A Dual-Graph Defense for {LLM} Agents},
  year   = {2026}, note = {arXiv:2605.26497; authors/venue verify} }
@misc{planguard2026,
  title  = {{PlanGuard}: Defending Agents against Indirect Prompt Injection via Planning-based Consistency Verification},
  year   = {2026}, note = {arXiv:2604.10134; authors/venue verify} }
```
