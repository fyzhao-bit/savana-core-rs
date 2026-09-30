# Managed input pre-seal guard (v0.4)

## Implemented boundary

This is a narrow sender-side bridge guard, not a completed product/provider
integration or a general attachment channel. A signed `ManagedSourcePolicyV04`
may opt into `execution_projection: "utf8_payload_v1"`. Absence means private
retention/audit only. Unknown projections are refused; adding the projection
invalidates the old signature. There is no binary conversion or template engine.

`DurableG4StateV2::check_managed_execution_handoff_v04` is a Rust host method,
not a model tool, Python wrapper, HTTP route or transferable capability. In the
kernel's existing tool-dispatch path it runs after current G3 declassification /
reader judgment and durable G7 admission, but before HPKE encryption/signing and
executor dispatch. A nonzero digest alone is NOT evidence that G3 passed: the
trusted caller must perform the existing G3 gate. The production call does so.

For an enrolled managed execution the guard checks:

- The original durable nonce, core, task, ticket and presealed commitment match.
- The root, continuation profile, dispatch policy, source policy and execution
  deadline remain current; the journal is still `Prepared`.
- A real original G7 snapshot exists (no legacy backfill).
- The exact canonical `TaskExecutionPayloadV2` and live G3 node hash to the
  original presealed commitment; action content equals the original task binding.
- The signed source projection allows this use; target and immutable resource
  locator match; the business `payload` UTF-8 bytes equal the pinned source bytes.

The snapshot's label, revision, internal commitments and accounting metadata are
not appended to the outgoing message. Existing authorized business control fields
still travel in their existing envelope. This is not a claim that all object
identity metadata is hidden from the executor.

## Executor and compatibility

There is no new wire format. Kernel and execd share the old domain-separated
presealed digest functions, with fixed golden vectors preserving the old bytes.
Execd still authenticates the signed dispatch, decrypts HPKE with core binding,
checks the presealed digest, decodes the canonical task payload and checks its
core. The existing connector route/credential, worker request and effect gates
remain in place. Execd does not receive the private source catalog or independently
verify a new source-policy signature; it trusts the authenticated kernel decision.

Installing a signed projection upgrades encrypted owner payload schema to 9.
Older source policies omit the optional field and keep their exact signed
encoding. Source-only and snapshot-only paths retain schema 7/8; schema 9 cannot
be decoded as an older state. No live deployment migration/reset was performed.
Non-managed dispatch follows the existing path; missing accounting on an enrolled
dispatch is not treated as an ordinary non-managed dispatch.

## Failure and replay semantics

This guard is **after** durable G7 commit. Refusal prevents sealing/sending but
does not refund stable consumption or erase the original journal. This is a
conservative failure behavior, not all-or-none admission of the new projection
check. Recovery must use the original nonce and existing reconciliation path.
Editing or deleting a source after admission never refreshes bytes or consumption.
An exact still-prepared replay can use its old pin; revoked/expired/terminal
executions cannot use the private audit API to regain dispatch authority.
Already-dispatching work is handled by existing reconciliation, not a new handoff.

## Tests and remaining work

`durable_managed_handoff_tests.rs` exercises real owner admission, encrypted
restart and the pre-seal guard with test issuer keys and a fixed test G3 digest.
It is not an end-to-end G3 proof or a live provider execution. Cases include exact
replay after edit/delete, missing signed opt-in, changed plaintext/G3 digest,
payload/source mismatch, revocation, expiry, foreign preparation, terminal
journal, legacy missing pins, signature tampering and schema downgrade rejection.
Existing kernel G3 and executor tests remain separate regression coverage.

The next batch adds optional Linux issuer loading and automatic fact binding for
already-enrolled requests; see [managed admission](managed-admission-v04.md).
Still required: source import/admin and task enrollment UX, concrete provider semantics/recovery,
compiler/residual replacement, exclusive publisher, SDK/UI and native Linux
hardware/sandbox acceptance. The normal chat intake does not yet automatically
enroll a task or construct private source payloads. Cloud/DeepSeek remain disabled
placeholders; no provider/model request or deployment was made in this batch.
