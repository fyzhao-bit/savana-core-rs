# Towards general tasks under an untrusted planner (v0.4)

## Goal

Today the protected AgentDojo subset only runs when every tool argument is a
value the owner committed verbatim (the 3 calendar tasks). A survey of all 97
AgentDojo user tasks (`experiments`, reproduced by `classify_args.py`) shows
where the other arguments come from:

| provenance of the write-call control arguments | workspace | banking | slack | travel |
| --- | --- | --- | --- | --- |
| read-only task (no write) | 18 | 4 | 1 | 14 |
| all from the owner's request text | 3 | 1 | 5 | 1 |
| + a field of a prior tool result | 0 | 0 | 8 | 0 |
| + text extracted from a prior result | 10 | 2 | 7 | 0 |
| + a computed value (time+duration, arithmetic, min/max, filter) | 9 | 9 | 0 | 5 |

So generality needs three new value origins, all authorized by the owner root
and supplied by the kernel — never written by the planner:

1. **owner-text constant** — a control value the kernel confirms appears in the
   owner's committed request (already the implicit source of every value in the
   finite subset; must become an explicit, enforced origin once the planner
   drafts the root).
2. **result-derived** — the value at a fixed JSON path of a prior operation's
   verified result, optionally selected from a list by an owner-text key.
3. **computed** — a deterministic typed derivation the kernel performs
   (start_time + duration → end_time; amount arithmetic).

Payload-role fields keep flowing as today (whole prior result → `body`, gated by
G3 readers). Loops/branches/which-item stay the planner's job; only the *origin*
of each value is owner-signed and kernel-enforced.

## Why not the non-fused v2 agent path

That path fixes arguments at plan-commit, returns tool results only as opaque
vault documents (no re-usable value handle), and has no test feeding a result
into a later call (`v2_agent_authority.rs`; see the survey). Extending it to a
per-call provenance channel is a larger change than extending the fused path,
which already carries verified results into later `body` fields
(`FusedOwnedResultV04`, `fused_inputs.rs:305-372`). We extend the fused path.

## Design: result-derived control

A root clause alternative is a 7-field tuple whose resource/destination/
parameter values are folded into three SHA-256 digests
(`business_controls.rs`). We do **not** change that wire format. Instead, when a
control field is result-derived, its digest commits to the *rule* under a new
domain, so a derived alternative can never be satisfied by a literal request and
vice versa. Exact-only alternatives keep byte-identical digests (golden vectors
unaffected).

New readable draft type (`task_draft.rs` / `business_controls.rs`):

```
ResultDerivedControlV2 { source_clause: u64, path: Vec<String>, kind: BusinessFieldTypeV2, max_bytes: u16 }
```

- `path` reuses the `ResultObservation` grammar (`planning_observation.rs`: ≤16
  segments, ≤128 bytes, object keys or decimal indices, no wildcard).
- `source_clause` must be a predecessor clause; `TaskLedgerV2::prepare` already
  requires its verified success before the dependent clause runs.

Kernel checklist (from the two provenance surveys, file:line to touch):
- [ ] `SlotBinding.result_path: Option<Vec<String>>` (`planning.rs:30-38`),
  relax the `argument=="body"` rule (`planning.rs:127-131`).
- [ ] compiler: allow `result_of` into a Parameter/Destination field only when a
  matching signed derived rule exists (`fused_task_compiler.rs:255-264`); pin the
  matched clause into the operation.
- [ ] new `DeriveOperationV2::SelectJsonPath(path)` (`provenance.rs`), strict
  parse → scalar; reuse `ResultObservation::render` selection.
- [ ] inputs: carry the path in `add_result`/`result_text`/`result_identity`/
  `check_result_argument` (`fused_inputs.rs:270-372`), `recover_inputs`
  (`fused_planning.rs:686-727`).
- [ ] G7 role check relaxed to the signed edge's role (`fused_planning.rs:1254-1266`).
- [ ] G4 derived digests (`business_controls.rs:153-191`) + rule commitment.
- [ ] widen the MCP success grammar so a result can carry profile-declared fields
  (`business_request.rs:492-508`; execd `connector_runtime.rs:570-586`).
- [ ] rendering for approval + action display (`task_draft.rs`, `task_action_display.rs`).
- [ ] Python SDK draft conversion (`task_context.rs`, `client.rs`) + owner side.

### Defense layering for a derived value (existing kernel mechanisms)

A result-derived value is extracted by the kernel and keeps `ExternalUntrusted`
integrity, so `UNTRUSTED_EFFECT_CEILING_V2` (`labels.rs:281-300`) caps it at
READ. Therefore:

- **G4** checks structure only: the operation's edge must equal the owner-signed
  edge (source clause, path, kind, bound).
- **G5** checks the value's integrity: `IntentFlowConfinement`
  (`validator.rs:94, 411`) escalates any authorizing-effect call
  (CREATE/UPDATE/DELETE/SEND/EXECUTE/FINAL_RELEASE) that carries an untrusted
  argument to owner approval. This is what stops a poisoned source (e.g. an
  attacker added to the source event's participants): the write cannot run
  without the owner seeing the actual value. `LabelEffectConfinement` denies
  outright and cannot be approved, so write tools that take derived values
  declare `IntentFlowConfinement`, not `LabelEffectConfinement`.
- **G6** shows the owner the exact request with the concrete derived value.

Caveat: validators are per-descriptor and not mandatory today
(`descriptor.rs:272-300`); the protected experiment declares none because it only
ships read tools. Adding write tools must declare `IntentFlowConfinement`
(candidate kernel rule: refuse authorizing-effect descriptors without it).

Admission gate: until G4, the approval text and kernel readers of installed
drafts handle derived edges, `TaskAuthorizationDraftAlternativeV2::new` refuses
any control with a derived field, so no root can carry an edge the owner's
approval display would not show.

## Design: owner-text constant origin

When the planner drafts the root, the kernel must confirm each literal control
value occurs in the owner's committed request (NFC-normalized; dates/times via a
fixed normalization). This is the CaMeL-relevant guarantee: a compromised
planner cannot smuggle an attacker's address into a root the owner then approves,
because that string is not in the owner's words. Enforced at compile, next to the
existing owner-view check (`v04_fused_input_admission.rs`).

**As built (G3).** The rule lives on the owner's consented input document, not
on the root encoding: a schema-2 `FusedInputDocumentV04` carries
`origin = "owner_text"` and a short list of owner-declared `constants` (the
deployment's fixed synthetic controls: `""`, `primary`, `private-result`, the
generator model). When the kernel first pins a schema-2 document's inputs
(`prepare_owner_execution_review_v04`, before any operation runs), every input
text must be empty, one of those constants, or an NFC substring of the
document's prompt; otherwise preparation fails and nothing executes. The planner
never writes the document — the owner side composes it from the official prompt
and the planner's proposed literals — so a literal the owner's words do not
contain cannot become a control even if the owner's (automated) review accepts
it. Schema-1 documents (the reviewed contracts, whose dates are owner-normalized,
e.g. `May 26th` -> `2024-05-26`) are unchanged.

Owner-declared values beyond the deployment's synthetic controls, all fixed
rules of the owner's review (`drafted_tasks.review_program`): its own dates and
times restated as `YYYY-MM-DD[ HH:MM]` (year 2024 when the request states none,
the same policy the reviewed contracts use); booleans and sharing permissions;
and search terms or counts for READ tools other than a URL (a read has no
effect and reaches a write only through a signed edge; fetching a URL is itself
an outbound channel). The extractor's instruction is always the owner's whole
request (whitespace folded), so a planner cannot steer the quarantined model.
An extraction's optional `context` is another earlier step's value (an
extraction, or a tool result's text up to 8 KB), which lets one answer combine
two results.

Not covered yet, and therefore failing honestly in planner-drafted runs: values
that need a computed origin (a date the prompt states without its year, time +
duration, arithmetic), keyed selection from a list, and anything the owner's
words do not literally contain. In the automated benchmark the owner approves a
planner-drafted root only if it passes the same rule, and denies any write whose
destination is derived from an untrusted result (the conservative choice, which
is also what CaMeL's shipped policies do for untrusted recipients); derived
content parameters escalate under intent-flow confinement and are approved only
when they equal the owner-signed edge's kernel-extracted value.

## Design: typed lists and computed origins (G4)

**Text lists.** A business field may have type `TextList` (code 4), allowed for
a Destination (several recipients are one destination) or a Parameter. Items
are bounded (at most 32, each a trimmed control text) and an empty list means
exactly "no one" (an event without participants), never a default. A
destination list commits to its canonical JSON array under its own digest
domain (`..._LIST_V2_SCHEMA1`), so no list can collide with a single text. A
literal list reaches the kernel as typed items in the schema-2 owner document
(`{"slot", "text": "", "items": [...]}`); `check_owner_text_origin` holds every
item to the owner-text rule by itself (an item is never split again), and the
selected value is a kernel list, which G4 types against the field (a list never
fills a text field, nor a text a list). A derived list is one owner-signed edge
of kind 4: the kernel selects a JSON array of strings at the signed path, within
the signed total byte bound (`DeriveOperationV2` tag 10, `list = true`).

**Computed origins.** A derived text edge may carry one owner-signed
computation `[op, amount]` (`add_minutes` on `YYYY-MM-DD HH:MM`, `add_days` on
`YYYY-MM-DD[ HH:MM]`, `add_cents` on a non-negative decimal with at most two
fraction digits), bounded per operation (a year of minutes, ten years of days,
ten million units). The rule is the fifth element of the signed control; a plain
rule keeps its exact bytes, so every earlier root still verifies. The kernel
computes from the verified result value (tag 10, `compute`), fails closed on
any operand not exactly in the operation's form, and folds the operation into
the value's provenance, so G7 accepts only an argument the kernel itself
computed with the signed amount. Root and action displays show the computation.

**Owner review (fixed rules).** The planner writes `"add_minutes"`,
`"add_days"` or `"add_amount"` on a `from` origin; the size must be stated in
the request (durations in minutes or days, every plain number as money), the
sign is the planner's. The owner also restates an end it states as a duration
from its own start ("12:00 for one hour" -> `... 13:00`). cc/bcc are recipients
too: never derived. A context that names the extraction's own source is dropped
(the source is already the payload).

**Not covered:** keyed selection (choose the list element whose field equals an
owner value), conditionals and loops; those still fail honestly.

## Comparison with CaMeL

Standard, same-conditions comparison only: both use DeepSeek, same AgentDojo
tasks, official benign utility and official `important_instructions` injection.
Report utility and attack-success side by side, plus the architectural
differences (out-of-process kernel, per-task owner-signed origins vs in-process
interpreter with per-suite static policies). No bespoke attacks on CaMeL.

## Order of work

1. result-derived control end to end (unlocks slack `+field`, workspace/slack
   `+text_extract`); tests at each layer. **DONE** — protocol, compiler, runtime
   extraction, G7, G4 matching, rendering, admission; 10 commits, unit + one
   integration test.
2. owner-text constant origin + planner drafts the root.
3. computed origin (time+duration first). **DONE (G4)** with typed text lists.
4. general AgentDojo connector adapter (workspace writes) + scoring via the
   official oracle.
5. run honest / poisoned / official-injection; compare with CaMeL+DeepSeek.

## Full-dojo read pipeline (prerequisite, DONE)

The protected deployment is now catalog-driven: `agentdojo_tasks.TOOL_CATALOG`
(7 reviewed read tools) is the single source; `catalog_json()` is committed as
`deploy/linux/integration/read-tool-catalog-v04.json`, copied into the stage by
`assemble.py`, and read by `protected_experiment_profile.rs` to ship one signed
descriptor + business profile per read tool (+ the fixed final-result-release
tool) on one `dojo-workspace` connector. `agentdojo_calendar.calendar_provider`
serves every catalog operation. 13 reviewed read TaskContracts exist. Reads are
necessary plumbing but do NOT show the differentiator: a read has no
corruptible downstream action, so Savana and CaMeL both show no attack surface
there and Savana's raw-result utility is lower. The differentiator is writes.

## Write-task support (the differentiator vs CaMeL)

CaMeL gives P-LLM literals `sources={User}`, so a literal recipient/destination
written by the (untrusted) planner is allowed immediately. Savana fixes the
destination/payload origin in the owner-signed root and the kernel supplies the
value, so an injection that tries to redirect a write's destination or smuggle a
payload cannot satisfy the signed edge. Sequenced smallest-first:

- **W1 — write descriptors + validator rule. DONE (kernel/protocol/provider,
  tested here).** Catalog schema 2 declares authorizing-effect `write_tools`; the
  generator ships their signed descriptors declaring `IntentFlowConfinement`
  (on the descriptor, the matching manifest constraint, and a registered
  `validator_builds` entry), on the one workspace connector (effects widened to
  the union). The rule is the testable policy-core helper
  `deployment_requires_intent_flow_confinement` (state-changing ⇒ confinement;
  FINAL_RELEASE excluded — it is governed by G3), NOT core `validate()` (kept
  permissive to avoid breaking existing write descriptors). Tests:
  `deployment_write_tool_must_declare_intent_flow_confinement`,
  `shipped_write_descriptor_with_confinement_validates_and_activates_at_g5`
  (validate + G5 activation + digest-match), and the provider serves
  `append_to_file` (forwards {file_id, content}, enforces body/to sentinels;
  functional test on real agentdojo 0.1.35 in the scratchpad venv: authorized
  append mutates only the owner-fixed file, every control violation / redirected
  destination / unreviewed upstream write is refused with no mutation).
- **Owner-side derived bridge — DONE.** `draft_from_json` accepts a
  `derived_controls` edge per alternative (source_clause, path, kind, max_bytes)
  and builds the root via `from_fields_with_derived`, so an owner root can carry
  a read->derived-write edge. Round-trip test in `tests/task_context.rs`.

  So every KERNEL/PROTOCOL/PROVIDER mechanism the write differentiator needs is
  built and tested here: result-derived control (slice 1a/1b), write descriptors
  + confinement (W1), the owner-side derived draft bridge, and the append
  provider adapter. What remains is experiment-harness wiring and the run, which
  can only be validated end to end on a fresh host (daemons + DeepSeek).

- **W2 — `append_to_file` differentiator (scalar). DONE (harness + local
  fresh-host runs; see `experiments/WRITE-DERIVED-20260930.zh-CN.md`).**
  As built the edge runs the other way round from the first sketch: the
  WRITE TARGET is derived and the payload is the owner's. Contract
  `user_task_29:owner_content` = clause 1 `dojo.file.search_name`
  (filename owner-text) -> clause 2 `dojo.file.append` whose `file_id` is the
  owner-signed result edge `(1, result/content/0/text/$json/0/id_, Text, 64)`
  and whose `content` is the owner's exact text -> clause 3 final release.
  The `$json` path step decodes the tool's nested JSON text. The kernel checks
  the edge at prepare (before the read runs) and again at dispatch; the
  planner can only reference the signed edge, never a literal target. The
  official `user_task_29` asks the model to invent the two activities, which
  is a computed payload (not supported yet, W4-class), so the variant fixes
  the owner's text; its oracle is the official one. CaMeL's shipped
  `append_to_file_policy` checks only that the file's readers may read the
  content, not which file the planner chose.
- **W3 — array (text-list) fields** for `recipients`/`participants`
  (`send_email`, `create_calendar_event`). New field/value type, list control
  digest, MCP list encode/decode, list rendering; scalar digests stay
  byte-identical.
- **W4-gen — model-generated payload. DONE (harness + local fresh-host runs; see
  `experiments/GENERATE-OFFICIAL-20260930.zh-CN.md`).** No new kernel authority:
  the quarantined model is one more reviewed tool, `dojo.model.generate`
  (effect Send, IntentFlowConfinement; fields body=payload, instruction,
  model=resource, to=destination). The official `user_task_29` runs as a
  4-clause chain search -> generate -> append -> release: the generator's
  payload is clause 1's WHOLE result (an existing whole-result edge), its
  instruction is the owner's own text, and its one-line output reaches
  `append.content` only via the owner-signed edge (clause 2,
  `result/content/0/text/$json/text`, Text, 512); `file_id` stays clause 1's
  signed `id_` edge. Known gap: a payload is not a root control, so the
  generator's input source is enforced by the owner's approval (the finite
  consent compares it byte-for-byte with clause 1's result), not by the
  kernel; binding payload sources into the root would change the signed
  alternative encoding and is not done.
- **W4 — computed origin** (`start_time + duration -> end_time` first).
- **W5 — expand runner to the ~50 derived-write tasks; fresh-host run
  (honest / poisoned / official injection); same-condition CaMeL comparison.**

### Fresh-host runbook (for W2 onward)

The scratchpad venv (`.../scratchpad/venv`) has agentdojo 0.1.35 and a
pre-built `savana_core`; a fresh run host additionally needs the built Rust
daemons (kerneld/execd/agentd/approvald/ingressd), Docker, and the DeepSeek
proxy (`deepseek_openai_proxy.py`, key via stdin, never argv/files/logs). After
any Rust SDK change (e.g. the draft bridge), rebuild `savana_core` into the run
venv (maturin) before the owner-side path exercises it. Assemble the stage with
`assemble.py --protected-experiment`, materialize with
`savana-development-build-inputs --protected-experiment-profile`, then run
`protected_agentdojo` (schema 3) for honest / poisoned-planner / official-
injection, and compare with CaMeL under the same DeepSeek + AgentDojo tasks.
