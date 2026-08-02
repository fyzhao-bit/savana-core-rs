# Finalize response/publication atomicity plan

## Goal

Make `FinalizeInput` publish its finalized input and pending approval only after every
fallible response-construction step has completed. The returned response must carry
the exact handles and signed artifacts held by the unpublished pending candidate.

## Design

Introduce a closed runtime response builder selected by the dispatcher. It owns the
metadata needed to produce the caller's final response representation. Runtime
execution returns a prepared response rather than a bare canonical body. Ordinary
operations prepare after execution; `FinalizeInput` prepares inside
`KernelInputOwnerV2::finalize_with`, before the input bytes move to finalized state.

The builder variants cover raw-body, application, signed-envelope, and Suite-1
sealed-record delivery. Dispatch methods may only move the matching prepared variant.
The Suite-1 connection passes its one-shot server transport session into the builder
and receives a pre-sealed record; the connection performs only the channel write
after finalization.

## Tasks

1. Add a deterministic, test-only failure at the real response-builder boundary and
   a real dispatcher/core regression test. Demonstrate the current post-commit
   mutation (RED).
2. Add prepared-response and response-builder types to the dispatcher, thread the
   builder through the runtime request/owner, and preserve the existing test helper
   surface with a builder-free request context.
3. Move `FinalizeInput` body construction and selected response construction into
   the input finalization transaction. Expose only borrowed pending response material
   from the unpublished authority candidate and publish it infallibly afterward.
4. Add a Suite-1 dispatch path that consumes the authenticated response session and
   returns the pre-sealed record. Leave only channel I/O after dispatch.
5. Turn the RED regression GREEN: injected response construction failure leaves the
   input Receiving with byte-identical replay accepted and no pending record; a retry
   succeeds exactly once.
6. Run focused authority/owner/service/dispatch/connection tests, full protocol,
   approvald, and kerneld suites, formatting, checks, frozen positive/negative
   validation, and diff review. Commit without pushing.
