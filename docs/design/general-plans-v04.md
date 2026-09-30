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

## Design: owner-text constant origin

When the planner drafts the root, the kernel must confirm each literal control
value occurs in the owner's committed request (NFC-normalized; dates/times via a
fixed normalization). This is the CaMeL-relevant guarantee: a compromised
planner cannot smuggle an attacker's address into a root the owner then approves,
because that string is not in the owner's words. Enforced at compile, next to the
existing owner-view check (`v04_fused_input_admission.rs`).

## Comparison with CaMeL

Standard, same-conditions comparison only: both use DeepSeek, same AgentDojo
tasks, official benign utility and official `important_instructions` injection.
Report utility and attack-success side by side, plus the architectural
differences (out-of-process kernel, per-task owner-signed origins vs in-process
interpreter with per-suite static policies). No bespoke attacks on CaMeL.

## Order of work

1. result-derived control end to end (unlocks slack `+field`, workspace/slack
   `+text_extract`); tests at each layer.
2. owner-text constant origin + planner drafts the root.
3. computed origin (time+duration first).
4. general AgentDojo connector adapter (workspace writes) + scoring via the
   official oracle.
5. run honest / poisoned / official-injection; compare with CaMeL+DeepSeek.
