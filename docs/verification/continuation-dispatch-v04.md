# v0.4 stable accounting in the real G7 transaction

Implementation record, 2026-09-19. Scope: optional additional tool-attempt
accounting in the existing Rust durable owner. This is not a replacement engine,
a dynamic authorization root, an exclusive publisher or an end-to-end deployment.

## Admission and trust boundary

1. Authenticated local administration installs the existing verified task and
   signed `ContinuationStorageProfileV04`.
2. It independently selects a trusted administrative signing key and verifies a
   `ContinuationDispatchPolicyV04` with `VerifiedContinuationDispatchPolicyV04::verify`.
   The policy pins the exact storage-profile hash, task, identity issuer public
   key, source, namespace, time window, evidence age and every domain's cost rule.
3. `install_continuation_dispatch_policy_v04` rechecks the installed profile and
   current task. No old task dispatch or stable reservation may already exist.
   Exact reinstall is a no-op; different policy installation fails, even if signed.

Administrative signature verification alone does not prove the resource issuer
honest or its identity mapping correct. This issuer is a trusted local/source
adapter, **not** the Agent, pLLM or arbitrary MCP output. It must map all aliases
and versions of an object to the same `(source, namespace, object, incarnation)`
and increase incarnation only for a genuinely new object. There is no path/hash
fallback. A first-party Rust-managed object source is now implemented; see
[managed resources](managed-resources-v04.md). External provider adapters and
effect-time identity/refinement tests are still required before deployment.
Compromised trusted issuers are outside the external-source guarantee.

No signing key is generated or embedded in production. Fixed private keys in tests
are fixtures only. There is no new public RPC that lets a planner select trust,
install a policy, query consumption or mint resource evidence.

## Preparation flow

`ContinuationResourceFactV04` binds policy identity, whole `ActionContentV2`
digest, stable resource identity and validity. Whole-action binding includes the
resource selector, task revision, action/destination, magnitude, payload and
provenance digests, plan and task pre-state. `ContinuationResourceEvidenceV04` is
explicitly **untrusted input**; its constructor only checks bounded canonical form.

The host attaches it using `TaskDispatchAuthorizationV2::with_continuation_resource`
and calls the normal `prepare_task_bound_tool_dispatch`. Under the existing
connector-registry guard, the owner:

1. Runs the original G5 decision, ticket, effect-gate and current task checks.
2. Rechecks current storage profile and dispatch policy; verifies the fact against
   the *stored* issuer key, source/namespace, full action and admission-time window.
3. Derives every charge from signed rules: fixed per execution, or verified action
   magnitude times a fixed multiplier with exact Count/Bytes unit and overflow
   checks. No caller supplies a charge or omits a configured domain.
4. Constructs the reservation from the **original G7 execution nonce**. Its request
   binding covers core digest, consumed ticket, sealed envelope, task contract,
   authorization (including endorsements/approval) and task transition digest.
5. Atomically persists and anchors the new reservation/fact, original task debit,
   original quota, original dispatch journal and intent transition. Only then can
   the existing kernel-prepared handoff return.

Every failure before commit leaves all these changes unapplied. Uncertain commit
poisons the owner and returns no handoff; reopen follows existing disk/anchor
reconciliation. This is one owner's atomic transaction, **not** a distributed
transaction with execd, the provider, or a browser.

## Replay, outcomes and bypass resistance

- Unenrolled tasks with no evidence retain original behavior. Evidence on an
  unenrolled task is rejected rather than silently ignored.
- Enrolled tasks cannot use the old tool entry point without evidence on a new
  attempt. They cannot insert arbitrary `RecordReservation` entries either.
- Replay resolves the original stored fact at its original admission time; the
  original task/core/lease and current profile/policy checks still apply. It does
  not re-fetch a fact or renew its validity, create a new nonce, or recharge.
  If a caller supplies evidence on replay, it must exactly match the original.
- Resource-fact freshness is a **new-reservation admission** condition, not a
  claim of live provider eligibility at effect time. Existing execution gates and
  any future read-set checks remain independently required.
- All terminal outcomes retain stable usage. Existing V2 proven-no-effect rules
  may refund their own magnitude; they cannot refund this separate stable ledger.
- Reopen independently re-verifies signed facts at their saved admission time,
  derives costs/bindings again, and requires one-to-one correspondence with every
  G7 entry for an enrolled task. Missing/duplicate/unlinked history fails closed.
- Expiry, revocation or parent amendment stops new preparation; it does not erase
  history. Controlled migration/replacement is not implemented by reinstalling.
- The legacy **final-release** route is intentionally blocked for enrolled tasks
  until the fixed publisher and current-reader/observation coupling are ready.

## Compatibility and privacy limits

Storage-only schema 5 is unchanged when no dispatch policy is installed. Explicit
dispatch enrollment atomically opts into schema 6; older binaries reject it.
There is no automatic downgrade or live deployment migration in this batch.

The extra accounting rules are not a Strict Inference mode: whole-egress closure,
private error handling, residual contracts and model/runtime refinement are still
pending. These private host APIs must not be exposed as model-visible resource or
balance oracles. Existing V2 root matching still applies, so this does not by itself
authorize previously unlisted resources dynamically. No new SDK/UI flow is active.

## Verification

`durable_continuation_dispatch_tests.rs` contains 15 new focused tests:

- One commit across new ledger, original task/quota and original G7 handoff;
  encrypted reopen and original replay without refresh or a new charge.
- Missing/wrong issuer, scope, action, time, stale fact and changed replay evidence.
- Authorized alias/new-step reuse of the same stable resource is rejected;
  genuinely distinct signed identity is accepted within remaining budgets.
- Multi-domain limit, old quota failure, precommit I/O and uncertain anchor failure
  before/after advancement; no partial record or premature handoff.
- Complete signed policy/domain checks, magnitude-unit and overflow rejection.
- Refusal to enroll over past execution or bookkeeping, policy replacement,
  unaccounted direct insertion, and legacy final release.
- Retained stable usage for success, proven-no-effect and indeterminate outcomes;
  revocation/expiry, canonical schema 6 reopen and cross-ledger corruption.

Tests exercise real encrypted files and existing owner/G7 code with a test rollback
anchor and test-only verified inputs. Terminal receipt-verification output is
injected at a private test seam; these tests do not contact execd/provider or prove
platform hardware rollback protection. Current development host is macOS.

```sh
cargo test -p savana-policy-core --lib continuation --locked
cargo test -p savana-policy-core --lib --locked
cargo check -p savana-kerneld --locked
tools/check-frozen-v2-core.sh
```

The Linux workflow includes the focused suite but was not run here. Cloud/DeepSeek
configuration remains disabled; no data was sent and no service was provisioned.

Local run results: **258/258 policy-core tests passed**, including **26/26** focused
continuation tests (15 new dispatch tests plus 11 prior storage tests). Kernel
compilation, targeted formatting, whitespace and frozen-source checks passed.
Library-only Clippy completed with the same three existing policy warnings
(argument count, large enum, manual range pattern); no new warning was reported
for these modules, and the overall strict lint baseline is not claimed clean.
