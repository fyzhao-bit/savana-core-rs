# Savana V2 G1/G2 Rust Input Runtime Plan

**Goal:** Implement the Rust-only input boundary that accepts bounded UTF-8
content, applies deterministic G1 normalization/injection/secret/PII gates,
tokenizes protected spans, and constructs a G2 planner envelope containing
only closed intent/template/relation types and opaque slot references.

## Security constraints

- Runtime assets are accepted only through an Ed25519-signed canonical
  manifest whose digests exactly match the loaded G1 rule set and G2
  extraction model.
- No callback, dynamic library, script, regex supplied by a caller, raw
  verdict, or external model response is accepted.
- Original and normalized text remains zeroizing Rust-owned data and never
  appears in `PlannerEnvelopeV2`.
- Prompt-injection denial is fail closed. PII/secret spans become stable
  internal protected values and fresh envelope-scoped opaque slot references.
- All input, rule, match, token, slot, relation, and encoded-envelope counts
  are checked against compiled ceilings and signed limits.
- G2 may emit only manifest-whitelisted intent, static template, action
  template, slot kind, and relation IDs. Ambiguous or unmatched extraction is
  denial, not fallback free text.
- Slot references and envelope nonce are wire-only and never become semantic
  value/action digests.

## Tasks

- [ ] Add signed canonical runtime asset manifest verification and exact asset
      digest binding.
- [ ] Add bounded Unicode normalization and forbidden-control/bidi checks.
- [ ] Add closed prompt-injection, PII, and secret detectors plus protected
      span tokenization.
- [ ] Add a closed deterministic extraction model and whitelist validation.
- [ ] Add `PlannerEnvelopeV2`, abstract slots/relations, and canonical
      no-content encoding.
- [ ] Add adversarial Unicode, overlap, ambiguity, asset-substitution,
      no-content-leak, and exact-vector tests.
- [ ] Run format, Clippy, workspace tests, and independent security review.
