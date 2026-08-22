# macOS Secure Enclave Credential Design

**Date:** 2026-08-21

**Status:** Approved for implementation

**Applies to:** Savana V2 macOS product and development deployments

## 1. Purpose

Savana's macOS product must use the local Mac's Secure Enclave and the
currently enrolled Touch ID set for enrollment, authentication, approval
display, approval decisions, and every other owner-authentication ceremony.
The credential must be device-bound, non-exportable, and unusable after the
Touch ID enrollment set changes.

The existing WebAuthn implementation cannot provide this property on macOS.
It requests a `cross-platform` authenticator, accepts only packed direct
hardware attestation under a configured AAGUID/root pair, and rejects backup
eligible credentials. Apple Touch ID is a platform authenticator and modern
Apple passkeys may be synchronized. The development installer additionally
generates a local attestation root for which no real authenticator possesses a
certified private key. The current UI therefore advertises an enrollment path
that no physical Touch ID credential can complete.

This design adds a separate, truthful macOS platform-credential protocol. It
does not weaken the WebAuthn verifier, manufacture a fake browser attestation,
or allow a software-key fallback.

## 2. Security properties

The macOS product path MUST provide all of the following:

1. The P-256 private key is created by Security.framework with
   `kSecAttrTokenIDSecureEnclave` and never exported.
2. The keychain item is `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`.
3. Key use requires `privateKeyUsage AND biometryCurrentSet`.
4. Password, Apple Watch, companion-device, remote-device, and browser-passkey
   fallback are prohibited.
5. Adding, deleting, or re-enrolling a fingerprint invalidates the credential.
6. Approvald accepts platform-credential messages only from the pinned,
   signed, non-root user launcher over a dedicated Unix-domain service edge.
7. Python, JARVIS HTTP, the web UI, OpenClaw, MCP callers, and model processes
   never receive a private-key handle, signing oracle, challenge body, proof,
   or platform-credential capability.
8. Every signature is bound to the exact principal, purpose, ceremony,
   deployment, boot, policy, session/run/scope context, nonce, use sequence,
   and absolute expiry owned by Approvald.
9. A transfer, transaction, signature result, or completion can be consumed at
   most once. Replay and cross-purpose reuse fail closed.
10. macOS product mode never falls back to WebAuthn, a Python callback, a
    browser credential, a software P-256 key, or a password.

The trusted macOS launcher is the local hardware-origin attester. Approvald
does not claim that macOS exposes a manufacturer certificate chain for a
general Secure Enclave key. Instead, Approvald authenticates the launcher's
running code identity directly, and trusts that pinned code to invoke the
fixed Security.framework key-generation and signing operations. The launcher,
Approvald, deployment manifest, and platform-credential edge therefore form
one measured local TCB.

## 3. Non-goals

- This change does not accept Apple/iCloud passkeys.
- It does not change the Linux or enterprise FIDO2 hardware-key path.
- It does not expose Secure Enclave controls through Python or HTTP.
- It does not add biometric matching, fingerprint data, or LocalAuthentication
  results to kernel state.
- It does not permit unattended approvals or Touch ID reuse windows.
- It does not add account recovery. A lost or invalidated key requires a new
  root-minted enrollment.

## 4. Components and trust boundaries

### 4.1 Approvald

Approvald remains the only authority that creates ceremonies, owns exact
challenges, validates completions, advances durable credential state, and
settles approvals. It adds:

- an in-memory, bounded `MacPlatformCredentialStateV2` for live ceremonies;
- a durable `MacPlatformCredentialRecordV2` for enrolled public credentials;
- a dedicated `MacPlatformCredential` endpoint role and Suite-One service;
- a macOS listener at
  `/Library/Application Support/Savana/Development/run/approvald/mac-platform/approvald.sock`;
- exact peer measurement for the signed user launcher;
- platform-signature verification and transactional use-sequence advancement.

The new socket is not an ApprovalAdmin surface. It exposes only health,
claim, finish, and cancel operations for one live platform ceremony.

### 4.2 Rust client relay

`savana-client` adds a private `TrustedPlatformCredentialRelay` seam. The
production PyO3 client installs the macOS implementation unconditionally in
macOS product mode. The seam receives only an opaque ceremony claim and
returns a typed terminal completion. It does not receive WebAuthn options and
is not exposed to Python.

The Rust relay claims the ceremony from Approvald's existing signed JARVIS
relay edge, obtains a one-use launcher transfer and receipt, sends only the
transfer plus absolute expiry to the launcher, and waits for Approvald's typed
completion. A launcher failure triggers best-effort cancel. Once Approvald may
have accepted a finish, uncertainty is terminal and cannot be retried.

### 4.3 Signed user launcher

The existing `savana-approval-launcher` remains the only GUI-user process. It
adds a closed `RunMacPlatformCredential` operation. The JARVIS-facing message
contains exactly:

```text
magic || operation_tag || launcher_transfer[32] || expires_at_u64be
```

The launcher then connects directly to Approvald's dedicated macOS platform
socket. Both sides perform Suite-One authentication and OS peer measurement.
The launcher receives the exact operation only after the transfer is consumed.

The launcher contains the only Security.framework implementation. It has no
general sign API, accepts no caller-authored challenge, key label, reason,
policy, URL, RP ID, or access-control flags, and never opens a browser for this
operation.

### 4.4 Web UI and JARVIS

The web UI starts enrollment with the root-minted token and code and polls only
safe lifecycle state. It does not handle a WebAuthn ceremony on the macOS
platform path. JARVIS may request the zero-argument approval-center notifier,
but it cannot open or settle a platform credential itself.

The public Python SDK signatures remain unchanged. Compatibility WebAuthn
callback arguments remain accepted but are never invoked when the trusted
platform relay is configured.

## 5. Protocol types

All new values use canonical CBOR, exact round-trip validation, bounded byte
strings, nonzero authority entropy, redacted `Debug`, and independent domain
separation.

### 5.1 Capabilities

```text
MacPlatformCeremonyClaimV2 =
    IngressUi(IngressUiAuthenticationBrowserCeremonyCapabilityV2)
  | AgentUi(AgentUiAuthenticationBrowserCeremonyCapabilityV2)
  | ApprovalDisplayUi(ApprovalDisplayUiAuthenticationBrowserCeremonyCapabilityV2)
  | ApprovalDecision(ApprovalDecisionCeremonyCapabilityV2)
  | Enrollment(EnrollmentCeremonyCapabilityV2)

MacPlatformRelayReceiptV2          = opaque nonzero 32 bytes
MacPlatformLauncherTransferV2      = opaque nonzero 32 bytes
MacPlatformTransactionV2           = opaque nonzero 32 bytes
MacPlatformCredentialIdV2          = opaque nonzero 32 bytes
```

The wrapper domain prevents a WebAuthn relay claim from being decoded as a
platform claim even though both refer to the same underlying authority-owned
ceremony row. Approvald permits exactly one claim mode per ceremony.

### 5.2 JARVIS relay operations

The `JarvisApprovalRelay` role adds:

```text
120 ClaimMacPlatformCeremony { claim }
121 WaitMacPlatformCeremony  { receipt }
122 CancelMacPlatformCeremony { receipt }
```

Claim returns:

```text
ClaimedMacPlatformCeremonyV2 {
    receipt,
    launcher_transfer,
    expires_at
}
```

Wait returns one of:

```text
Pending | Denied | Expired | Indeterminate |
EnrollmentCompleted(FinishEnrollmentBrowserResponseV2) |
IngressUiCompleted(IngressUiAuthenticationBrowserFinishResponseV2) |
AgentUiCompleted(AgentUiAuthenticationBrowserFinishResponseV2) |
ApprovalDisplayCompleted(ApprovalDisplayBrowserFinishResponseV2) |
ApprovalDecisionCompleted(ApprovalDecisionBrowserFinishResponseV2)
```

The typed completion is generated by Approvald after signature verification
and the same authority transition used by the WebAuthn finish path. It is
delivered once. The SDK never fabricates a browser response or attestation.

### 5.3 Direct launcher operations

The new `MacPlatformCredential` role exposes:

```text
0   PlatformHealth
120 ClaimPlatformLaunch  { launcher_transfer }
121 FinishPlatformLaunch { transaction, result }
122 CancelPlatformLaunch { transaction }
```

`ClaimPlatformLaunch` consumes the transfer and returns:

```text
MacPlatformOperationV2 {
    transaction,
    kind: Enroll | Sign,
    credential_id: None | Some(MacPlatformCredentialIdV2),
    key_tag: bounded fixed-format bytes,
    challenge: MacPlatformChallengeV2,
    expires_at
}
```

The `key_tag` is authority-derived from the installation ID and credential ID.
It is never caller-authored. The launcher rejects a noncanonical tag.

Enrollment finish contains the credential ID, 65-byte uncompressed P-256
public key, and canonical low-S DER ECDSA signature. Sign finish contains the
credential ID and signature. Cancel contains no reason string and cannot be
converted into approval.

### 5.4 Signed challenge

The exact message passed to Secure Enclave signing is canonical CBOR prefixed
by:

```text
"SAVANA_MAC_PLATFORM_CREDENTIAL_V2\0"
```

It commits to:

```text
installation_id
deployment_generation
active_state_manifest_digest
approvald_identity
approvald_boot_id
credential_id
principal
ceremony_kind
approval_purpose
authentication_origin
return_origin
envelope_or_approval_digest
policy_digest
connection_binding_digest
conversation_id
turn_id
run_id
approval_scope_id
challenge_nonce
use_sequence
issued_at
expires_at
```

Fields that do not apply to a ceremony are encoded as typed `None`, never
empty strings or caller defaults. Enrollment uses sequence 0. An assertion
must use the credential record's current sequence plus one.

## 6. Secure Enclave key lifecycle

### 6.1 Enrollment

1. Root mints the existing one-use enrollment token and code.
2. The Rust client begins enrollment with Approvald.
3. The Rust platform relay claims the returned ceremony and forwards only the
   launcher transfer to the signed launcher.
4. Approvald authenticates the launcher directly and supplies an enrollment
   operation with a random credential ID, fixed key tag, and exact challenge.
5. The launcher creates a permanent P-256 Secure Enclave key with
   `WhenPasscodeSetThisDeviceOnly` and
   `privateKeyUsage AND biometryCurrentSet`.
6. The launcher immediately signs the enrollment challenge. This both proves
   possession and forces the initial Touch ID ceremony.
7. Approvald validates the public point and signature, consumes the enrollment
   code, persists the credential, and returns the typed enrollment completion.
8. The SDK persists the existing public identity document. It contains no
   private key, Keychain reference, or signing capability.

If any step fails before Approvald accepts finish, the launcher deletes a newly
created key best-effort and the result is denied or expired. If finish may have
been accepted, the result is indeterminate and neither enrollment nor key
creation is retried automatically.

### 6.2 Authentication and approvals

Approvald chooses the credential by principal and creates the exact next
challenge. The launcher looks up only the authority-supplied key tag and asks
Security.framework to sign. Touch ID is required for every signature; no
authentication reuse duration is configured. Approvald verifies the signature
and advances `use_sequence` in the same durable transaction that settles the
ceremony.

### 6.3 Biometric-set changes and deletion

If the key cannot be found or used because `biometryCurrentSet` changed, the
launcher returns `CredentialInvalidated`. Approvald durably revokes that
credential before returning a safe public failure code. The owner must mint a
new enrollment token and enroll again.

User cancellation is not invalidation. It produces `Denied` and leaves the
credential valid. Biometric lockout, unavailable UI, or ambiguous OS errors
fail closed without changing credential state.

## 7. State machine and terminal semantics

A live ceremony moves through:

```text
Created -> RelayClaimed -> LauncherClaimed -> FinishAccepted -> Delivered
```

Permitted terminal alternatives are:

```text
Created/RelayClaimed -> Denied | Expired
LauncherClaimed -> Denied | Expired | Indeterminate
FinishAccepted -> Completed | Indeterminate
```

Rules:

- Claim, launcher transfer, transaction, and completion are one-use.
- A browser relay claim and platform claim are mutually exclusive.
- Cancel before launcher claim is `Denied`; cancel after launcher claim is
  `Indeterminate` unless Approvald already has an explicit user-cancel result.
- Deadline checks occur before reference disclosure and before state mutation.
- `FinishAccepted` is never retried or inferred as approved after a transport
  failure.
- Restart loses live in-memory ceremonies and reports `Indeterminate`; durable
  credential records and committed use sequences remain authoritative.
- No terminal state is converted to another terminal state.

## 8. Deployment and peer identity

The macOS deployment adds a distinct launcher client key, boot identity,
service identity, handshake edge, socket definition, and expected peer
measurement. It does not reuse ApprovalAdmin or the JARVIS relay identity.

Approvald verifies the live launcher's:

- effective UID equals the logged-in console user's UID and is nonzero;
- bundle ID equals `com.savana.development.approval-launcher` in development;
- development team/authority equals the pinned deployment authority;
- code-directory, designated-requirement, and entitlement measurements equal
  the signed installed binary;
- launcher protocol key and boot identity match the dedicated manifest edge.

The launcher independently verifies Approvald's installed binary, service
identity, key, boot ID, and Suite-One handshake. Socket ownership and parent
directory traversal are installed with the minimum permissions needed by the
console user. Peer measurement remains authoritative; filesystem permissions
alone never authenticate a caller.

The installer removes the generated fake WebAuthn root from the macOS product
profile. Compatibility WebAuthn roots may exist only in an explicitly selected
hardware-key profile and are not consulted by the macOS platform path.

## 9. Public errors and UI

The UI renders only code-owned text. New stable public codes are:

```text
PLATFORM_CREDENTIAL_DENIED
PLATFORM_CREDENTIAL_EXPIRED
PLATFORM_CREDENTIAL_INVALIDATED
PLATFORM_CREDENTIAL_UNAVAILABLE
PLATFORM_CREDENTIAL_INDETERMINATE
PLATFORM_CREDENTIAL_PROTOCOL
```

The enrollment panel says that Touch ID is required and that changing the
enrolled fingerprint set requires re-enrollment. It never asks for a WebAuthn
security key in macOS product mode. Unknown internal errors remain generic.
No OS error string, challenge, key tag, capability, signature, or credential
identifier is returned through HTTP.

## 10. Compatibility and rollout

- Existing WebAuthn protocol types, routes, hardware attestation verification,
  and Linux behavior remain unchanged.
- Existing public Rust and Python SDK method signatures remain unchanged.
- macOS product construction requires the platform relay and fails closed if
  its deployment material, socket, launcher, or Secure Enclave support is
  absent.
- No runtime flag may downgrade macOS product mode to legacy WebAuthn or a
  Python callback.
- Development and production use the same platform protocol. Only pinned
  identities and paths differ.
- Existing unenrolled deployments enroll normally after upgrade. A deployment
  with an existing WebAuthn credential must explicitly revoke and re-enroll;
  credentials are not silently migrated.

## 11. Testing and acceptance

Implementation is accepted only when all of the following pass:

1. Canonical CBOR round trips and malformed/re-encoded rejection for every new
   protocol value and operation.
2. Role isolation proving JARVIS relay, ApprovalAdmin, browser, and launcher
   operations cannot cross endpoint roles.
3. State-machine tests for replay, cross-purpose substitution, expiry,
   cancellation, invalidation, duplicate finish, crash ambiguity, and strict
   terminal behavior.
4. Signature tests for wrong key, point, algorithm, DER, high-S form, domain,
   challenge field, context digest, sequence, and deadline.
5. SDK tests proving all five ceremony kinds use only the platform relay when
   configured and never invoke legacy WebAuthn callbacks.
6. Launcher unit tests through a `SecureEnclaveKeyStore` seam proving fixed
   attributes, fixed key tags, one operation at a time, cancellation mapping,
   invalidation mapping, low-S canonicalization, and zero caller-authored
   challenges.
7. Deployment tests for the separate key, role, edge, plist/socket, file modes,
   user identity, code measurement, and removal of the fake macOS WebAuthn
   root from the platform profile.
8. JARVIS tests proving Python receives no platform secret or signing callback,
   and UI tests for safe Touch ID lifecycle copy.
9. Full Rust, Python, Node, deployment, formatting, and diff checks.
10. A real Mac acceptance run that enrolls with Touch ID, authenticates a
    session, settles one approval, rejects cancellation, rejects replay, and
    confirms that a changed biometric set requires re-enrollment. Tests cannot
    substitute for this final device run.

## 12. References

- Apple, *Protecting keys with the Secure Enclave*:
  <https://developer.apple.com/documentation/Security/protecting-keys-with-the-secure-enclave>
- Apple, *Accessing Keychain Items with Face ID or Touch ID*:
  <https://developer.apple.com/documentation/localauthentication/accessing-keychain-items-with-face-id-or-touch-id>
- W3C, *Web Authentication Level 3*:
  <https://www.w3.org/TR/webauthn-3/>
