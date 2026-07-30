# Savana V2 G4 Implementation Plan

**Goal:** Implement the V2 policy × registry active set, closed ontology
evaluation, descriptor/attempt validation, immutable action-intent identity and
deduplication, and branch-typed quota accounting.

**Architecture:** `savana-policy-core::v2` remains the sole owner of G4
authorization semantics. Public inputs are validated closed DTOs; verified
registry, ontology, policy, and state objects have private fields. Runtime
authorization accepts stored G3 value/provenance records, not caller-provided
aggregate digests. State-changing intent/quota APIs compute their complete
next state first and publish it only on success.

## Global constraints

- All enum tags, ID types, collection limits, digest domains, and canonical
  ordering follow the V2 protocol/state specification exactly.
- Ontology depth is at most 8, total nodes at most 256, and `All`/`Any`
  contain 1–32 children.
- Ontology false and evaluation error both deny; private results distinguish
  them.
- Tool descriptors are schema version 2, signature/domain verified, time
  bounded, and selected only from the policy × registry active intersection.
- Non-idempotent connectors have exactly one attempt and zero retry elapsed
  time. Idempotent connectors use the bounded 1–8/30-second retry language.
- Action intent identity contains no opaque handle, request ID, or transport
  sequence and is deduplicated by exact revision/internal-step binding.
- Tool and final-release quota subjects never alias or share counters.
- No external validator attestation exists; G5 receives only manifest-bound
  internal validator declarations.

## Task 1: Closed G4 identifiers and ontology AST

- [x] Add distinct u32 ID newtypes and `VersionV2`.
- [x] Add bounded `OntologyScalarV2`, `FieldPathV2`, operands, context fields,
      manifest set references, and expression constructors.
- [x] Reject invalid path, ordering, child-count, depth, and node-count inputs
      before an expression becomes usable.
- [x] Add exact encoding vectors and one-over-limit tests.

## Task 2: Fail-closed ontology evaluator

- [x] Add immutable argument, ontology-set, and context views with private
      backing maps.
- [x] Resolve paths without coercion, regex, arithmetic, or dynamic namespace.
- [x] Return private `Match`, `NoMatch`, or `EvaluationError`; expose only
      permit/deny to callers.
- [x] Test missing paths, type mismatches, set/digest mismatch, `All`/`Any`
      short-circuit behavior, and resource failures.

## Task 3: Descriptor and active-registry validation

- [x] Add closed attempt/idempotency/retry types and internal validator
      declarations.
- [x] Decode and re-encode exact canonical unsigned descriptor bytes.
- [x] Verify descriptor digest/signature with the registry publisher key and
      enforce time, role, ordering, validator, projection, and retry rules.
- [ ] Compute the active tool set as the exact signed-policy × verified-registry
      intersection and expose only immutable tool records/boot-bound handles.

## Task 4: Stored G3 binding adapter

- [x] Resolve argument names to immutable stored value IDs, value digests,
      provenance digests, labels, and root evidence.
- [x] Compute argument/provenance/evidence/token digests only from resolved
      records; reject duplicate IDs, missing records, stale manifest/run,
      unknown vault slots, or executor/credential mismatch.
- [ ] Mint the private verified source/policy/declassification inputs consumed
      by G3; no raw digest source constructor becomes public.

## Task 5: Immutable action intent and deduplication

- [x] Implement `ToolExecutionSemanticBindingV2` and its exact digest domain.
- [x] Compute `ActionIntentIdV2` from installation, manifest, durable
      run/task, and semantic-binding digest.
- [x] Atomically create one intent per `(plan revision, internal step)`.
- [x] Return the same immutable intent/state on exact replay and reject
      request-id mutation as `IdempotencyConflict` and semantic rebinding as
      `StateConflict`.

## Task 6: Branch-typed quota

- [x] Implement distinct `ToolAttempt` and `FinalRelease` quota subjects.
- [x] Enforce `reserved + spent < effective_limit` with checked arithmetic.
- [x] Implement the exact reservation transition matrix and terminal states.
- [ ] Test cross-branch lookup rejection, boundary limits, replay, and every
      illegal transition with no state mutation.

## Task 7: Verification and review

- [x] Run format, workspace Clippy, protocol/policy-core all-target tests, and
      `git diff --check`.
- [x] Add compile-fail tests for raw verified-registry/ontology/source/intent
      construction.
- [ ] Independently review exact G4 ownership, authority boundaries, digest
      contents, deduplication, and quota behavior before G5.
