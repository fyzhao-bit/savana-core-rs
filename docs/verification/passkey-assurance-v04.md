# v0.4 user-verified passkey profile

The authentication service now has two explicit profiles. This does not change
G1–G7, task-root authorization, resource budgets, release policy, service identity,
TPM deployment identity or the requirement for a separate action approval.

## Deployment selection (not a browser option)

Each root-owned approvald bootstrap `enrollment_profiles` entry accepts:

```json
{
  "profile": 2,
  "assurance": "user_verified_passkey",
  "code_lifetime_ms": 300000,
  "ceremony_lifetime_ms": 120000
}
```

An omitted `assurance` retains `attested_hardware`. Unknown spellings are rejected.
An enrollment grant selects its profile before the browser ceremony. The browser
cannot supply an assurance field or upgrade/downgrade a grant. Profiles with
hardware enrollment still require configured hardware attestation roots; a
passkey-only deployment can have an empty root list. Do not change an existing
profile's assurance in place: recovery rejects that reinterpretation. Add a new
profile and enroll a new credential instead. Existing identities are not migrated.

| Property | Attested hardware | User-verified passkey |
|---|---|---|
| Registration | Pinned packed ES256 certificate chain/AAGUID | ES256, `fmt=none`; no hardware provenance claim |
| Browser request | Existing direct/cross-platform options | Resident credential required, attachment unrestricted, attestation none |
| User presence / verification | Both required | Both required |
| Backup eligibility | Forbidden | May be true; must remain equal to registered value |
| Backup state | Forbidden | Allowed only when backup eligible |
| Signature counter | Nonzero and strictly increasing | Not replay authority; zero or non-increasing allowed |
| Replay authority | Exact one-use challenge plus counter | Exact one-use challenge in rollback-protected state |

Both profiles check RP ID `localhost`, exact origin `http://localhost:8766`,
ceremony type, principal, credential ID, challenge, expiry and the actual ES256
assertion signature. Cross-origin/top-origin data, malformed/duplicate fields,
unsupported algorithms and unrequested authenticator extensions fail closed.
Passkeys accept either valid ECDSA S form, as authenticators need not normalize S;
the legacy hardware rule remains unchanged. AAGUID zero is accepted only in the
passkey profile. Registration without attestation does not prove a hardware device
or its non-exportability. The later assertion demonstrates possession of the key.

This distinction follows [WebAuthn credential backup semantics](https://www.w3.org/TR/webauthn-3/#sctn-credential-backup).
Trust in the user's passkey provider, its synchronization and account recovery is
part of the passkey profile's boundary. This is **not** an equivalent substitute
for attested, non-backup hardware in a security claim or experiment.

## Receipts, recovery and compatibility

- Existing hardware receipts keep their schema-2 canonical bytes and strict
  constructors. Passkey receipts use schema 3 with an explicit assurance tag;
  actual BE/BS/counter values are signed, not rewritten as hardware values.
- Verification returns the assurance tag. The authentication-context digest also
  separates passkey evidence. Transplanting a signature to a hardware receipt
  fails verification. This is authentication evidence, not new task authority.
- The encrypted owner snapshot is schema 6. Credential assurance, fixed backup
  eligibility and enrollment-grant assurance survive restart. Completed challenges
  remain consumed even with counter zero. Revocation and rollback anchoring stay
  on the original durable path. Counter maxima are retained for consistency, not
  used as the passkey replay defense.
- Schema-4/5 snapshots load as hardware only; the next write is schema 6. Older
  binaries must not be used to read new snapshots. No state deletion is required
  or performed by this change.
- Rust/Python `Client.enroll` and the private-session API keep their signatures.
  The WebAuthn provider must honor server options and execute a real browser
  ceremony. An existing strict hardware provider does not automatically become a
  passkey provider. The SDK pins both exact old and new authentication page
  templates, rather than accepting arbitrary HTML.
- The native enrollment page uses the new options and explains the selected
  assurance before calling `navigator.credentials.create`. Successful login still
  does not approve any tool action.

## Verification scope

Regression tests include none-attestation parsing, zero counters, backup flags,
wrong origin/RP/challenge/principal/signature, profile-confused enrollment,
wire tag and signature substitution, exact browser enrollment through the durable
state owner, encrypted close/reopen replay rejection, removed/reinterpreted
deployment profiles, and the original hardware/approval regressions.

Local verification on 2026-09-21: 418 Rust tests across approvald, client and
kernel-protocol passed, including 15 new profile-related tests. A freshly built
native Python wheel passed 23 SDK tests. All 125 frontend tests and its production
build passed. The full workspace/all-targets check and 318-file source fingerprint
check passed. Socket tests required local-listener permission; browser DOM tests
used the bundled Node runtime because the Homebrew Node installation is broken.

These are synthetic cryptographic and transport tests. They do **not** establish
that the user's real phone/computer has completed registration, that AWS native
services have been installed, or that Python's live private-owner factory is
configured. The current localhost:8771 preview is not full native acceptance.
Cloud models remain disabled; no personal credentials or old state are fixtures.

For remote Linux acceptance, keep approvald loopback-only and forward its fixed
port to the user's browser. Opening an AWS public UI port, replacing `localhost`
with an arbitrary hostname, or signing in on port 8771 is not this protocol.
Enrollment/verification must be completed by the user, not by a synthetic signer.
