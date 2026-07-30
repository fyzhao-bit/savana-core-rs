# Savana V2 G6/G7 Runtime Plan

## Goal

Implement the approval and dispatch boundaries so no caller-provided boolean,
effect disposition, nonce, or detached semantic record can authorize an
effect.

## G6

- [x] Add closed approval purposes, decisions, bindings, envelopes, and
      settlements with canonical encodings and disjoint signature domains.
- [x] Verify hardware WebAuthn assertions against the exact challenge,
      localhost RP/origin, UP/UV/non-backup flags, credential/principal,
      monotonic counter, strict P-256 signature, and active credential record.
- [x] Persist envelope registration, decision-challenge reservation,
      settlement, counter advance, denial, and one-use consumption.
- [x] Expose only opaque verified approval capabilities to the kernel
      transaction adapter.

## G7

- [x] Add the closed tool/final-release dispatch subject and canonical core
      digest.
- [x] Atomically consume ticket/approval, reserve the subject-bound quota,
      create the sole random execution nonce, advance intent/public state, and
      append `Prepared` WAL state.
- [x] Verify executor effect-start/no-effect/completion receipts against the
      exact nonce, subject, core, executor, manifest, generation, and fence
      epoch before minting an internal reconciliation proof.
- [x] Atomically reconcile WAL, quota, intent/public outcome, receipt
      evidence, and nonce tombstone. Never create a replacement nonce.
- [x] Encrypt persisted sensitive state, bind installation/store namespace,
      use an external rollback-protected head, and anchor filesystem I/O to a
      held parent descriptor.

## Verification

- [x] Add replay, purpose-confusion, challenge, counter, origin, flag,
      signature, subject, receipt, crash/restart, and atomicity tests.
- [x] Run format, Clippy with warnings denied, and full crate/workspace tests.
- [ ] Complete an independent security review of the integrated V2 runtime.
