# Evidence-grounded private continuations: implementation plan

Scope approved on 2026-09-05: implement suggestions 1 (evidence-driven dynamic
authorization) and 2 (controlled-disclosure closed-loop planning), and revise
the paper. This is the previously proposed **bounded research prototype**, not
a migration of the running V2 deployment. No existing authority gate, frozen
wire format, credential, service or browser registration is removed or changed.

## Deliverables

1. An additive Rust workspace crate, `savana-private-workflow`, with a runnable
   order/invoice workflow. Authenticated root rules select a provider, account,
   month, merchant directory, request template and budgets; object identifiers
   are discovered only at runtime. Only separately authenticated, closed-schema
   source facts can instantiate a rule. A signed body is not automatically a
   trusted semantic assertion.
2. A deterministic continuation owner with durable one-use reservations,
   source/version/epoch binding, actual-request comparison, verified terminal
   results, and fail-closed uncertain outcomes. A concrete encrypted file store
   and rollback-anchor interface exercise reopen, commit failures and replay.
3. A separate planner-only facade: opaque non-content-derived handles, a closed
   command language, cached bounded projections, a declared leakage function,
   uniform refusal and no free-text/value-query interface. Private facts and
   request bytes do not belong to its serializable outputs.
4. Unit, adversarial, persistence and paired-world transcript tests; a runnable
   synthetic fixture using the real Rust owner and existing business-request
   codec. These are correctness witnesses, not comparative empirical results.
5. Paper/Chinese summary/claim-map updates and a rebuilt visually checked PDF.

## Boundaries

The root-signing service, source-fact service, merchant-directory service,
executor/transport and storage anchor are explicitly trusted. A model may
propose actions but cannot sign facts, set destinations, supply payload fields,
or ask arbitrary private predicates. The prototype supports one root revision,
bounded discovery rounds and an immutable directory snapshot. Changing the rule
requires a new authenticated task, not an agent-authored amendment.

This crate is not exposed as a new production RPC or browser route. Its native
adapter reuses the V2 business request/profile types, but installing a derived
request into production G1–G7/approval/dispatch remains a separate integration
step. No new proof object is accepted by the existing production executor.

The target privacy claim is equality of serialized planner observations for
worlds with equal **declared leakage**, under coupled handle randomness and the
same adaptive commands. Counts, branch eligibility, status, progress and the
bounded observation epochs are declared leakage. Timing/packet lengths outside
the serialized interface, provider side effects and endpoint compromise are
not hidden. Query quotas alone are not a privacy theorem.

## Work order

- Implement and test signed contracts/facts and canonical parsing.
- Implement persistent continuation transitions and codec-bound requests.
- Implement the planner facade and adaptive two-world tests.
- Run focused and compatibility checks; record exact outcomes.
- Update and render the paper; preserve unrun empirical sections as unrun.
