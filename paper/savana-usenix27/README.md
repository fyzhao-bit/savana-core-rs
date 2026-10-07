# Savana — USENIX Security '27 first full draft (2026-10-07)

`main.tex` is a complete first draft built on the owner's IFC skeleton
("Savana: Confining Disclosure and Effects in LLM Agents"). It keeps that
skeleton's structure and core design text, rewrites the framing around an
**untrusted planner**, and replaces the empty evaluation with measured results.
The earlier "task authority / private continuations" working paper in
`../usenix-sec27/` is left unchanged.

**This is not submission-ready.** It is 21 pages with the fallback style, and
the body runs to page 17 against a 13-page limit. G12 numbers are `TBD`, and
about ten `\todo{}` markers remain (`grep -n todo main.tex`).

## Build

pdfLaTeX + BibTeX:

    pdflatex main && bibtex main && pdflatex main && pdflatex main

If `usenix-2020-09.sty` sits next to `main.tex`, it is used. Otherwise
`usenix-fallback.sty` approximates the layout; the fallback is **not** for
submission. Built cleanly on 2026-10-07 with TeX Live (Ubuntu noble).

## How the draft was checked against the code

A read-only audit compared every concrete claim in the original skeleton with
the code on `codex/intent-bound-execution`. The draft follows the audit.

Changes from the skeleton:

- **Sizes and counts** come from the current branch:
  - 386,449 lines of Rust in 18 crates;
  - 2,302 tests and 66 `compile_fail` doctests;
  - 563 domain-separation strings and 8 inter-process edges;
  - 6 declassification transitions (with `BuildFusedModelEnvelope`) and
    8 provenance source kinds;
  - per role, 25 agent, 19 ingress, 6 executor, 4 control-shell and
    7 connector-control operations.
- **Skeleton names that are not implemented** were removed. These are
  `EndorseControl`, `SourceKindV2::ControlEndorsement`, `candidate_epoch`,
  `ControlNodeNotDerivable` and `Tool×OutsideIntent`; they exist only in a
  "proposed" design document. The draft describes what is implemented:
  - `ControlFacetV2` (with `Scope`, not `ResourceScope`);
  - `ControlSelectionV2` digest records;
  - `checked_control_endorsements_v2`, with evidence
    `ExplicitAlternative` / `CompleteContractSingleton` / `ActionApproval`
    and re-check → `StateConflict`;
  - G5 `IntentFlowConfinement` (RequireApproval).
- **Code names** were corrected to `UNTRUSTED_EFFECT_CEILING_V2`,
  `confined_effects` and `derive_normal`.
- **Approval:** one settlement key, with purposes separated by signature
  domains. The tool display is now JSON rendered from the exact business
  request.
- **The benchmark path** (fused v0.4) is described as audited:
  - owner document;
  - task authority (one clause per operation, plus final release);
  - `compile_planning` / `prepare` (`check_owner_text_origin`,
    `check_result_operation_rule_v04`);
  - per-operation G4–G7, then execd.
- **The ~60 s bound** is reported as an observed end-to-end bound. Its exact
  source is a TODO; the approval settlement expiry is the leading candidate.

## Where the numbers come from

All evaluation numbers come from offline-verified fresh-host batches under
`experiments/results/local-container-20260930/`. That directory is
gitignored and kept only in the experiment container. The reports are:

| Section | Source reports |
| --- | --- |
| RQ1 injection matrix | `experiments/AGENTDOJO-INJECTION-MATRIX-20261003.zh-CN.md` |
| RQ2 compromised planner | `experiments/AGENTDOJO-POISONED-PLANNER-20261003.zh-CN.md`, `…-CAMEL-20261004.zh-CN.md`, `docs/research/threat-model-tcb.md` (offline sweep) |
| RQ3 utility | `experiments/AGENTDOJO-RETRY-MODEL-20261003.zh-CN.md`, `AGENTDOJO-G11-20261003.zh-CN.md`, `CAMEL-V4PRO-20261005.zh-CN.md` |
| RQ4 privacy | `experiments/PRIVACY-VALUE-BLIND-20261003.zh-CN.md`, `PRIVACY-EXTRACTOR-20261003.zh-CN.md` |
| RQ5 cost | `experiments/KERNEL-PERF-20261001.zh-CN.md`, plus per-step timing measured from the evidence timestamps of the G11 and G12-smoke runs |

## Open items before submission

1. **Insert the G12 run** (deterministic compute steps, commit `ff45719`).
   It is blocked: the experiment driver's lock is held by a `dockerd` that
   inherited its file descriptor (see the session notes).
2. **Run a forced-attempt compromised-planner variant** live on both systems,
   and at least one adaptive attack (AutoDojo) and one more benchmark
   (AgentDyn).
3. **Confirm** v1.2 / v1.2.2 task equivalence for the CaMeL comparison.
4. **Pin down** the ~60 s bound.
5. **Refresh** the frozen-core manifest: 66 of its 331 entries have drifted.
6. **Verify** every bibliography entry tagged `verify` / `TODO`; several
   were assembled from search snippets.
7. **Cut about 4 pages** (candidates: §8 supply chain, §7.3 rules, parts of
   §5) and confirm against the official style file.
