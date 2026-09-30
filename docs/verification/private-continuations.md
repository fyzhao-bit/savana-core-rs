# Private-continuation prototype: verification record

Date: 2026-09-05. Branch: `codex/intent-bound-execution`.
This increment follows `debd3d8`; the production Rust baseline remains
`73e0684`. It adds `crates/savana-private-workflow`, its workspace/CI entries,
research documentation and paper revisions. The production V2 RPC, approval,
G1-G7 and dispatch paths, frozen manifest, deployed services, credentials and
user state are unchanged. This is not a production integration or deployment
acceptance record. No push or PR update is part of this increment.

## Delivered scope

- A bounded signed rule over runtime-discovered order objects, independently
  signed order/directory facts, exact tuple binding and fixed request generation.
- Durable one-use reservations, pre-transport attempt fencing, actual-request
  comparison, retained-response classification and conservative recovery.
- A planner-only serialized interface with three commands, opaque slots,
  cached bounded views, uniform refusal and an explicit leakage boundary.
- A real encrypted file adapter using the existing external rollback-anchor
  interface, adversarial/persistence/paired-world tests and an offline example.
- Revised paper, claim map, English/Chinese READMEs and Chinese summary.

See the [specification](../research/private-continuations.md) and
[crate README](../../crates/savana-private-workflow/README.md) for APIs,
trusted host obligations and the unimplemented production bridge.

## Commands and observed results

Executed locally on macOS with `rustc 1.82.0 (f6e511eec 2024-10-15)`.
From the repository root:

~~~sh
cargo check -p savana-private-workflow --offline
cargo fmt -p savana-private-workflow -- --check
cargo clippy -p savana-private-workflow --all-targets --no-deps --offline --locked -- -D warnings
cargo test -p savana-private-workflow --all-targets --offline --locked -- --nocapture
cargo build -p savana-private-workflow --release --offline --locked
private_fixture_dir=$(mktemp -d)
cargo run -p savana-private-workflow --example invoice_loop --offline --locked -- "$private_fixture_dir"
cargo test -p savana-policy-core --lib --offline --locked task_state_ -- --nocapture
python3 -m verification.task_trace.check --check-recorded verification/task_trace/results.json
sh tools/check-frozen-v2-core.sh
git diff --check
~~~

| Check | Observed outcome |
| --- | --- |
| New crate check, formatting and focused Clippy | Passed |
| New crate unit/adversarial tests | 26 passed; 0 failed; example test harness has 0 unit tests and is executed separately below |
| Optimized library build | Passed; no debug-only support required by the new crate |
| Offline executable example | Two objects discovered over two rounds; two local fixture transport calls; repeated discovery and encrypted-file reopen do not call again; nine distinct public view epochs |
| Existing Rust task-state regression | 14 passed; 218 unrelated tests filtered |
| Existing finite-model regeneration | All 11 baseline queues exhausted; per-configuration sum 11,788 states / 59,003 edges; all 11 declared faulty variants yield the expected counterexample; recorded JSON comparison passes |
| Frozen V2 check | All 220 listed paths passed; neither the manifest nor its file list changed |
| Whitespace check | Passed |

The final example used a new temporary directory,
`/private/tmp/savana-private-continuation-final.gAIZdW`, and left its encrypted
fixture state there. Its keys are explicit synthetic demo keys, and its anchor
is process-local memory. No real provider, model, browser or user credential is
contacted. The anchor is not recoverable in a new process; use a fresh directory
for each run. The example does exercise actual file synchronization/encryption
and the real Rust owner/codec, not a Python reimplementation of those rules.

CI now configures separate Ubuntu/macOS jobs for the new crate and fixture.
No remote CI execution is claimed. The full workspace, native nine-case fixture,
Python SDK and TypeScript plugin were **not rerun** in this increment. Their
older production-baseline evidence remains in
[the previous record](intent-bound-execution.md), not counted as new execution.
The S1-S7 finite checker was rerun unchanged: it does **not** cover the new
continuation state machine or prove its composition with the production path.

## What the 26 tests exercise

| Boundary | Implemented checks / witnesses |
| --- | --- |
| Root and source authority | Expected issuer/context/pins, role-separated signatures, closed root programs/bounds, root/query/source/time binding, canonical messages, duplicates and oversized inputs |
| Runtime discovery | Account/month/missing-invoice matching, no authority from note/amount, source rollback and same-version consistency, immutable directory and tuple, atomic overflow, permanent round bounds |
| One-use actions | Stale/cross-task/duplicate handles, exact replay and rediscovery, revoke/expiry/backwards time, permanent reservations and no refunds |
| Actual request and outcome | Worker field/operation/target/credential substitution refused before transport; only actual retained matching success becomes Done; every other result remains Unknown |
| Commit uncertainty | Six discovery/reservation cuts and six execution cuts, each spanning before/after persistence; no uncommitted authority published, no uncertain attempt re-sent |
| File store | Encrypted reopen, exclusive owner, rollback/tamper/deletion/wrong-key/wrong-namespace refusal, anchor-failure poisoning and adjacent recovery, permissions/symlink/hardlink/FIFO refusal |
| Planner output | Closed command grammar, cached views, no serialized private payload, permanent disclosure limits, private terminal commit even when disclosure is exhausted |
| Relational privacy witnesses | Three-round adaptive paired execution/reopen with different private requests, same-version hidden-field update, 48-configuration matrix, intentional count-leakage contrast |

The matrix is **8 eligibility masks x 3 outcome classes x 2 disclosure bounds**,
inside one of the 26 tests. These 48 configurations are not 48 independent
attacks, user tasks, privacy-rate measurements or a general noninterference
proof. Paired runs couple handle randomness and preserve the declared leakage
events. Different counts intentionally produce different views. Timing,
provider behavior and a different root's intent are not covered by that claim.

## Failures found and corrections

The initial planner-projection regression failed because a serde internally
tagged unit `Observe` variant accepted an extra field despite the enum's
`deny_unknown_fields`. It is now an empty struct variant, with extra/duplicate
field rejection covered by the final passing suite. The initial failure was
not treated as a pass.

Source review identified a potential hidden-field equality oracle: hashing the
whole signed order snapshot for same-version consistency would let changes to
notes or amounts affect acceptance. The consistency hash now contains only the
explicit authority-relevant fields. A paired same-version update regression
confirms unchanged planner observations when only those hidden values differ.

Storage review added `O_NONBLOCK` before regular-file validation. Substituted
state/lock FIFOs are rejected without waiting for a writer; the final file
test exercises both paths. This is in addition to link/type/mode/inode checks,
not a claim of process isolation against an attacker with trusted-owner access.

The first broad Clippy command, without `--no-deps`, failed on existing
dependency warnings: `large_enum_variant` in `kernel_ingress.rs`,
`format_collect` in `task_context.rs`, and `result_large_err` in `transport.rs`.
Those production files were not changed or given suppressions. The recorded
passing command is the scoped `--no-deps` run with warnings denied for the new
crate; it must not be called a clean whole-workspace lint result.

## Paper and PDF verification

From `paper/usenix-sec27`:

~~~sh
latexmk -pdf -interaction=nonstopmode -halt-on-error \
  -outdir=../../tmp/pdfs/usenix -jobname=savana-intent-bound main.tex
~~~

The revised title is **Savana: Binding Private Agent Continuations to Task
Authority**. Section 9 presents the new prototype; the abstract, contributions,
threat model, evidence, evaluation plan, related work, limitations and open
science statement distinguish it from the existing production implementation.
Section 11 remains an explicitly **unrun** empirical evaluation plan.

Built with TeX Live 2025 / latexmk 4.86a / pdfLaTeX / BibTeX. Final output is
`output/pdf/savana-intent-bound.pdf`, 13 letter-size pages, 225,912 bytes.

- All 13 pages rendered at 110 dpi and visually reviewed. After the final text
  clarification, 11 page PNGs were byte-identical to the reviewed version;
  changed pages 6 and 13 were re-inspected.
- The intermediate 14th page held only trailing appendix lines. Redundant
  appendix text was condensed, with no font/margin shrink. No orphan final
  page, clipped table, overlapping content or unresolved marker remains.
- Text/bounding-box checks found 13 nonempty pages and no word within 25 points
  of a page edge. The final log has no overfull box, undefined reference or
  citation warning. Underfull spacing advisories remain and were reviewed.
- PDF metadata names anonymous authors; the repository is not an anonymous
  artifact. The local layout is still the documented fallback, not official
  USENIX-template certification.

Delivered PDF SHA-256:
`67b8f78813556d1c8ad2a059bc728dc5576578f4bff203f42fe6e135c9db7802`.
This identifies the generated file, not a signed release or timestamp-independent
bit-for-bit TeX build.

Selected source SHA-256 values at verification:

~~~text
domain.rs  1f0f9eb12f0078c87173a402571970347458f30c168cf4780d32e40225310589
planner.rs a0ed2f403bfaa4dcc93608ec25a6fd81bb91ebf702390b1630537963239cee60
runtime.rs cc974cf41b5e2132c8a35fe818aabc566e319bd69073906097ab8739997117a3
store.rs   126440c6fc841a349b2f260830b3a5995c3a5876382031afb1c41106202e7778
tests.rs   aef4115c09b2beb3cc489e42f0b4ff215b250da448a36d7f6e88a479e850eb11
main.tex   3bf1ee8956288ed149e187bc304fac4cb1464fb2202a6d22f80880425ce5b916
~~~

## Remaining research and integration obligations

No full Rust refinement/noninterference proof, comparative security/utility
study, natural-language authority compiler, arbitrary private predicate or
generated-answer release is claimed. The fixed invoice controller is scriptable
and does not establish LLM autonomy benefits or novelty over equivalently
configured policy/IFC systems.

The rule issuer, scoped fact services, directory, owner, actual transport and
rollback anchor are trusted. A `ProviderTransport` identity getter is not
network attestation. A provider must enforce the order-version precondition.
The Rust planner facade is not hostile-code memory/process isolation. A real
production bridge must retain authenticated approvals, active registry and
manifest checks, G1-G7, executor mediation and the platform boundaries; these
cannot be skipped by calling the research transport hook from the product.
