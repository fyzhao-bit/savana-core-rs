# Task-trace research increment: verification record

Date: 2026-09-05. Branch: codex/intent-bound-execution.
Production Rust baseline remains 73e0684. This increment changes research
artifacts, paper/summary documentation and CI only. No production service,
credential, deployment, frozen V2 file or runtime authority check was changed.
No push or PR update is part of this increment.

## Requested scope delivered

1. [Version-specific closest-work comparison and necessary composition
   obligations](../research/task-authority-positioning.md), with explicit
   non-novel foundations, fair-baseline requirements and constructional
   counterexamples.
2. [Independent task-trace specification](../research/task-trace-spec.md),
   [finite implementation-shaped model and checker](../../verification/task_trace/README.md),
   [manual Rust correspondence](../research/task-trace-rust-map.md), generated
   counterexamples and CI reproduction.

The paper's contribution, security-argument, evidence, related-work, limitations
and open-science sections were updated. The old circular safe-prefix definition
was replaced with S1–S7 over independent authority/event history.

## Commands and observed results

Run from the repository root:

~~~sh
ruff format --check verification/task_trace
ruff check --select E,F,I verification/task_trace
python3 -m unittest verification.task_trace.test_check -v
python3 -m verification.task_trace.check \
  --check-recorded verification/task_trace/results.json
cargo test -p savana-policy-core --lib --locked task_state_ -- --nocapture
cargo test -p savana-policy-core --lib --locked \
  bounded_task_traces_match_independent_accounting_oracle -- --nocapture
cargo test -p savana-execd --lib --locked \
  task_bound_worker_request_mutations_stop_before_prepare_or_provider_attempt \
  -- --nocapture
cargo test -p savana-execd --lib --locked \
  owner_backed_attempt_commits_effect_start_before_transport_and_response_afterward \
  -- --nocapture
sh tools/check-frozen-v2-core.sh
git diff --check
~~~

| Check | Observed outcome |
| --- | --- |
| Research code format / E,F,I lint | Passed |
| Checker tests | 14 passed, including independent negative observations, positive witnesses, ABA, refund limits and report round-trip/tampering |
| Finite baseline graphs | All 11 queues exhausted; per-scenario sum 11,788 states and 59,003 edges; no S1–S7 violation; all required positive witnesses reached |
| Intentionally weakened model variants | All 11 found a counterexample for the expected invariant, shortest lengths 1–11 abstract events |
| Regenerated report vs recorded JSON | Identical JSON values and source SHA-256 values |
| Real Rust task-state tests | 14 passed; 218 other tests filtered |
| Real Rust bounded accounting oracle | 1 passed; 1,440 traces, 984 admitted / 1,896 refused probes, six accounting observations; 74.27 seconds |
| Real executor actual-request mutation test | 1 passed |
| Real executor durable-boundary ordering test | 1 passed |
| Frozen V2 source check | All listed 220 paths passed; no snapshot update |
| Whitespace check | Passed |

The full workspace, native nine-case integration fixture, Python SDK and
TypeScript plugin were **not rerun** in this research-only increment. Their
previous same-production-snapshot evidence remains in
[the prior verification record](intent-bound-execution.md); it is not counted
as newly executed here.

The generated graph totals are not added to the Rust trace count. These are
different abstractions and denominators, not independent user tasks or attack
trials. CI contains the checker tests and exact report regeneration; remote CI
execution has not been claimed.

### Negative checks and corrected tooling issues

~~~sh
python3 -m verification.task_trace.check \
  --scenario relation --baseline-only --max-states 1
~~~

This intentionally returns exit 1 and “incomplete”; it is a passing fail-closed
negative check, not a safe/exhausted graph. The report-tampering test increments
a recorded state count and requires comparison failure.

The first JSON comparison exposed a tooling bug: dataclass tuples serialize as
JSON arrays and return as Python lists. Comparing those directly to the
pre-serialization object always failed. The checker now compares JSON values
after canonical serialization, and a subprocess regression requires both
successful round-trip and rejection of a changed report. The initial failure
was not ignored or reclassified as success.

Source review also separated retained response from certified success, included
conservative post-retention decode failure, limited completion ACK to success,
and made the observer reject later effects after verified NoEffect. These refine
the research model; they did not modify production semantics.

## PDF verification

From paper/usenix-sec27:

~~~sh
latexmk -pdf -interaction=nonstopmode -halt-on-error \
  -outdir=../../tmp/pdfs/usenix -jobname=savana-intent-bound main.tex
~~~

Built with TeX Live 2025, latexmk 4.86a, pdfLaTeX and BibTeX. Final output:
output/pdf/savana-intent-bound.pdf, eleven letter-size pages.

- All citations and labels resolve; no overfull box or undefined-reference warning.
- All final pages rendered at 110 dpi and visually checked. Pages 1–10 were
  pixel-identical to the already reviewed render after the final appendix edit;
  page 11 was re-inspected.
- A twelve-page intermediate build had only a few trailing appendix lines on its
  last page. Redundant appendix text was condensed; no font or margin shrink was
  used. The final eleven-page layout has no orphan final page.
- Text extraction found nonempty pages, the exact reported graph counts, no
  unresolved citation markers and no word boxes within 25 points of a page edge.
- Metadata names anonymous authors. The repository is not an anonymous artifact.
- Underfull line/page advisories remain and were visually reviewed. The local
  style is still the explicitly documented fallback, not official-template
  certification.

SHA-256 of this delivered PDF:
dcfc295cda44ecabbb496f392bc4bb89acd4b17712c267f854f39b3c06c93afd.
The hash identifies the file, not a signed release or bit-for-bit reproducibility
across TeX environments and build timestamps.

## What remains unproved / unmeasured

No claim of a full Rust refinement proof, unbounded safety, complete crash
availability, general natural-language intent fidelity, hardware readiness or
provider-internal exactly-once semantics. The model's declared trust assumptions
and omitted transitions remain part of its result.

The source map specifically preserves prepare-linearized revocation and trusted
kernel ACK ordering. Execd does not independently prove another owner's commit
is durable. The two-owner model omits the separate vault transaction.

Existing dynamic-resource discovery, arbitrary synthesized final answers,
additional production connectors, end-to-end comparative experiments and user
approval-cost studies were not added under this request. Distinctiveness beyond
the scoped composition contribution and publication acceptance remain research
questions, not consequences of passing tests.
