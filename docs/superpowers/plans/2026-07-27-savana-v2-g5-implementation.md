# Savana V2 G5 Implementation Plan

**Goal:** Execute only the exact manifest-bound internal validator set selected
by a verified active tool descriptor, fail closed on every missing,
mismatched, resource, or implementation failure, and persist one replayable
private decision without accepting an external attestation or verdict.

**Architecture:** `savana-policy-core::v2` owns a closed registry of Rust
validator implementations. Deployment verification mints immutable validator
artifacts from reproducible build-manifest identities. Descriptor declarations
are matched byte-for-byte against that registry before evaluation. The
evaluation API accepts only the verified G4 active descriptor, stored binding,
ontology, projection, and action-intent records. Validator details remain
private; callers receive only a non-authorizing decision-record digest and the
closed allow/deny/needs-approval branch selected by policy.

## Global constraints

- Initial V2 has no external validator DTO, key, attestation, endpoint,
  callback, dynamic library, script, caller reason, or caller verdict.
- Required declarations are strictly increasing, duplicate-free, and limited
  to 32.
- Every declaration must match
  `(implementation_id, semantic_version, build_manifest_digest)` exactly.
- Missing implementations, identity mismatch, panic-equivalent failure,
  timeout, resource exhaustion, malformed stored input, or ontology error
  denies.
- Validator execution cannot mint data, provenance, labels, authority,
  approval, quota, tickets, or execution nonces.
- One action intent has one immutable evaluation input digest and one stored
  decision. Exact replay returns it; changed input is `StateConflict`.
- Public traces contain only the private decision-record digest.

## Task 1: Manifest-bound internal validator registry

- [ ] Add immutable build-manifest identity and closed implementation kind.
- [ ] Validate strict declaration order, exact implementation identity, and the
      32-validator ceiling before registry activation.
- [ ] Reject unknown, duplicate, missing, or build/version-mismatched
      implementations.
- [ ] Add compile-fail coverage proving callers cannot register a callback or
      construct a verified implementation.

## Task 2: Closed evaluation context and outcomes

- [ ] Build a private context only from verified G4 stored arguments, labels,
      root evidence, ontology result, projections, descriptor, and intent.
- [ ] Implement closed Rust validators with explicit checked work budgets.
- [ ] Keep per-validator permit/deny/failure and reason material private.
- [ ] Require every descriptor validator in exact order; any non-permit result
      makes the aggregate fail closed.

## Task 3: Decision identity and replay

- [ ] Define canonical per-validator and aggregate decision records and exact
      domain-separated digests.
- [ ] Atomically store one decision per action intent and immutable evaluation
      input digest.
- [ ] Return the stored decision on exact replay and reject changed inputs
      without mutation.
- [ ] Expose only permit/deny/needs-approval plus `PublicDecisionTraceV2`.

## Task 4: Verification and review

- [ ] Add exact vectors, boundary tests, missing/mismatch tests, all failure
      paths, replay, and no-state-mutation tests.
- [ ] Run formatting, Clippy, protocol/policy-core tests, doc compile-fail
      tests, and `git diff --check`.
- [ ] Independently review G5 for callback/attestation injection, incomplete
      validator sets, fail-open behavior, mutable decisions, and reason leaks.
