# Fused model scheduling and policy lifecycle boundary

2026-09-20. The initial batch added durable scheduling and a policy lease.
The follow-up [host integration](fused-host-v04.md) connects the daemon timer and
owner to this lease. It does **not** enable a cloud adapter, consumer chat flow,
or a complete privacy-preserving publisher.

## Signed slots, charged before I/O

`FusedPlanningProfileV04.delivery_schedule` is an optional signed list of
`FusedDeliverySlotV04 { id, round, role, opens_at, closes_at }`. Empty retains
the old canonical profile encoding and manual protocol behavior. A nonempty
schedule requires explicit fixed-view release approval. IDs are strictly ordered,
windows globally nonoverlapping and nonempty, and each window is contained in its
registered Advisor/Planner phase. At most 256 slots are accepted; each round/role
has at most its signed `max_deliveries`. A profile may intentionally omit a phase
or use fewer slots: this is not a task-completion guarantee.

`exchange_scheduled_fused_model_v04` takes a trusted host clock, owner revision,
current G3 release context and a pinned transport. It does not take request bytes
or a caller-selected round/role. One tick:

1. Rechecks the task root, revocation, validity, owner revision and clock floor.
2. Skips expired slots; never sends catch-up traffic.
3. For one due slot, reserves its original job/view. A Planner slot atomically
   freezes the envelope; absent advice stays empty. Advice cannot be newly
   accepted after the public advice cut, even before that freeze is recorded.
4. Commits skipped-slot cursor, reservation and any freeze before returning bytes.
5. Reuses the existing exact-reader G3/leak checks and bounded reply validation.

There is no same-slot retry after success, malformed output, timeout, G3 refusal,
or uncertain commit. A later separately signed slot permits another attempt with
the original frozen bytes. Manual `ReserveDelivery`, `FreezeEnvelope`, and the
old exchange helper reject scheduled profiles. Private activation and execution
progress cannot add slots. An idle tick with no skipped slot performs no write.

The adapter receives a deadline no later than the slot close, view deadline,
G3 rule/set/provenance expiry, or five seconds after call entry. The trusted
adapter must enforce that deadline during I/O; this is not forcible cancellation
of arbitrary/malicious Rust transport code. Outcomes remain private.

## Restore and migration

Schema 13 is selected only by an ordinary committed transaction installing a
schedule. It retains the cursor and claimed slot IDs in the same encrypted,
rollback-anchored owner snapshot. Restore checks sorted/unique claims, cursor
bounds, skipped/claimed timing against the persisted floor, and exact equality
between claimed slots and protocol delivery counters for every round/role.
Lower-schema snapshots containing schedules are rejected. No accounting reset,
new job ID, side database, live migration or deployment reset is introduced.

## Current deployment policy lease

`ActiveDeclassificationRuleSetV2::with_current_fused_policy` checks installation,
manifest and generation against the current bundle, reparses its signed rules
against current trust roots, and holds the publication read lock through the
handoff callback. A successor needs the same lock exclusively. Keeping an old
rules `Arc` is not sufficient for a new current-policy call.

The lease reports an expiry capped by the trust-root set and its earliest member
expiry, deliberately conservative. The host now caps exchange provenance by this
expiry, the session expiry and the real input's provenance expiry. Production
transports remain disabled. Lock ordering is owner then policy; a callback must
not re-enter deployment publication. A queued task revocation/update is serialized
after an in-flight owner call, not an ability to retract bytes already sent.

## Tests and remaining obligations

Seven scheduling tests use the actual encrypted owner and independent test
rollback anchor: malformed signed profiles, public-slot-only retries across
success/failure/reopen, skip/fallback/no catch-up, manual/stale/wrong-recipient/
revocation denial, slot-specific late reply rejection, precommit and both anchor
uncertainty cuts, and schema/cursor/counter corruption. Three kernel tests check
stale deployment/expired signer refusal, publication-lock exclusion (including a
second thread), and release of the read lock on callback panic.

Local regression: 358 policy-library tests, 315 serial kernel-library tests and
48 continuation-core tests passed; final focused fusion rerun: 37 passed.
Kernel, Rust client and Python-extension compilation passed. All 246 repository
source fingerprints match the explicitly refreshed source baseline. No signed
deployment manifest was changed; these are Mac-hosted tests, not native Linux
or real hardware-anchor acceptance.
Policy/kernel library Clippy completed successfully with warnings in existing
code (enum size, argument count and type complexity among them); no new warnings
were reported in the added schedule or lease functions.

Important limit: allowed transmission **windows** and at-most-once reservations
do not prove a fixed total observable transcript. The host must tick independently
of secrets, and service-level output mediation must account for absence, exact
timing, crashes, revocation and errors. No whole-service noninterference or Strict
Inference claim is established here. The bounded authenticated adapter,
private compiler/session/SDK/UI wiring, final
publication and native Linux/hardware-anchor acceptance remain outstanding.
