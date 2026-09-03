# macOS Secure Enclave Credential Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the impossible macOS browser-WebAuthn enrollment path with a device-only Secure Enclave P-256 credential that requires the current Touch ID set for every use, while preserving the existing public Rust and Python SDK interfaces.

**Architecture:** Approvald remains the only ceremony and approval authority. A Rust-only client relay moves one-use opaque capabilities to a signed user launcher; the launcher connects back to a dedicated Approvald Suite-One endpoint, obtains an authority-authored challenge, and asks Security.framework to use a non-exportable Secure Enclave key. Python, HTTP, OpenClaw, and the browser never receive the challenge, key handle, proof, or credential capability. The current WebAuthn path remains available only for explicitly selected non-macOS compatibility profiles.

**Tech Stack:** Rust 2021, canonical CBOR protocol types, Suite-One authenticated Unix sockets, P-256 ECDSA verification, PyO3, macOS Security.framework/LocalAuthentication, launchd, Python/FastAPI, TypeScript/Vitest.

**Spec:** `docs/superpowers/specs/2026-08-21-macos-secure-enclave-credential-design.md`

## Global Constraints

- Core worktree: `/Users/fz/Documents/jarvis/.worktrees/security-capabilities-assessment`
- JARVIS worktree: `/Users/fz/Documents/jarvis/.worktrees/openclaw-approval-broker`
- Preserve all existing uncommitted WebAuthn relay, OpenClaw broker, and deployment changes.
- Use RED-GREEN-REFACTOR for every behavior change. Run the named RED test before production edits and retain its failure output in the working log.
- Do not change `Client.session`, `Client.enroll`, or their Python signatures.
- Do not expose platform secrets or a signing callback through Python, HTTP, browser JavaScript, OpenClaw, or MCP.
- Do not add browser-WebAuthn, password, Apple Watch, remote-device, passkey, or software-key fallback in macOS product mode.
- Do not reuse `ApprovalAdmin` or the WebAuthn relay role/key/socket.
- Do not infer success after timeout, disconnect, restart, or ambiguous finish; return `Indeterminate`.
- Do not delete or weaken the existing packed WebAuthn attestation verifier.
- Do not commit generated dylibs, build products, deployment secrets, keychain material, or local runtime state.
- Each task ends with focused verification. A task may be committed only after its tests and `git diff --check` pass.

---

## Task 1: Add domain-separated platform protocol primitives

**Files:**

- Create: `crates/savana-kernel-protocol/src/v2/mac_platform_credential.rs`
- Modify: `crates/savana-kernel-protocol/src/v2/mod.rs`
- Modify: `crates/savana-kernel-protocol/src/v2/primitives.rs`
- Test: `crates/savana-kernel-protocol/src/v2/mac_platform_credential.rs`

- [ ] Add unit tests first for nonzero 32-byte construction, redacted `Debug`, canonical CBOR round trips, wrong-length rejection, zero rejection, trailing-data rejection, and cross-domain rejection for:
  `MacPlatformRelayReceiptV2`, `MacPlatformLauncherTransferV2`, `MacPlatformTransactionV2`, `MacPlatformCredentialIdV2`, and `MacPlatformChallengeNonceV2`.
- [ ] Add tests proving `MacPlatformCeremonyClaimV2` wraps all five existing ceremony capability types and cannot decode a `WebAuthnRelayCeremonyClaimV2` encoding.
- [ ] Run the RED tests:

```bash
cargo test -p savana-kernel-protocol mac_platform_credential -- --nocapture
```

- [ ] Implement private-field newtypes using the repository's existing opaque-value pattern, independent canonical CBOR tags, constant-time equality where secret/reference values are compared, and redacted formatting.
- [ ] Define bounded enums and records for:
  `MacPlatformCeremonyClaimV2`, `MacPlatformCeremonyKindV2`, `MacPlatformOperationKindV2`, `MacPlatformOperationV2`, `MacPlatformEnrollmentResultV2`, `MacPlatformSignatureResultV2`, and `MacPlatformLauncherResultV2`.
- [ ] Ensure constructors validate the exact 65-byte uncompressed P-256 public point shape and bounded key-tag length without accepting caller strings.
- [ ] Re-run the focused tests and protocol formatting:

```bash
cargo test -p savana-kernel-protocol mac_platform_credential -- --nocapture
cargo fmt --all -- --check
git diff --check
```

## Task 2: Add closed relay and direct-launcher operations with role isolation

**Files:**

- Modify: `crates/savana-kernel-protocol/src/v2/approval_relay.rs`
- Modify: `crates/savana-kernel-protocol/src/v2/approval_service.rs`
- Modify: `crates/savana-kernel-protocol/src/v2/transport.rs`
- Modify: `crates/savana-kernel-protocol/src/v2/application.rs`
- Test: `crates/savana-kernel-protocol/src/v2/approval_relay.rs`
- Test: `crates/savana-kernel-protocol/src/v2/approval_service.rs`
- Test: `crates/savana-kernel-protocol/src/v2/transport.rs`

- [ ] Add RED round-trip tests for relay operation tags 120/121/122:
  `ClaimMacPlatformCeremony`, `WaitMacPlatformCeremony`, and `CancelMacPlatformCeremony`.
- [ ] Add RED round-trip tests for the typed one-use relay result:
  `Pending`, `Denied`, `Expired`, `Indeterminate`, and each of the five existing typed completion responses.
- [ ] Add RED round-trip tests for the dedicated direct service operations:
  `PlatformHealth`, `ClaimPlatformLaunch`, `FinishPlatformLaunch`, and `CancelPlatformLaunch`.
- [ ] Add RED authorization tests proving the new direct operations are rejected under `ApprovalAdmin`, `JarvisApprovalRelay`, browser, client, and all unrelated endpoint roles; prove relay operations are rejected under the direct launcher role.
- [ ] Run RED:

```bash
cargo test -p savana-kernel-protocol approval_relay -- --nocapture
cargo test -p savana-kernel-protocol approval_service -- --nocapture
cargo test -p savana-kernel-protocol transport -- --nocapture
```

- [ ] Add `EndpointRoleV2::MacPlatformCredential` with a unique wire tag and a closed operation table. Keep `JarvisApprovalRelay` as the only role that accepts the three platform relay operations.
- [ ] Implement canonical request/response types and exact tag dispatch. Reject unknown map keys, duplicate keys, noncanonical encodings, and responses from the wrong operation family.
- [ ] Add `mac_platform_credential_handshake_edge()` as a distinct typed edge; never alias the admin or WebAuthn relay edge.
- [ ] Re-run focused protocol suites, then the full protocol crate:

```bash
cargo test -p savana-kernel-protocol approval_relay -- --nocapture
cargo test -p savana-kernel-protocol approval_service -- --nocapture
cargo test -p savana-kernel-protocol transport -- --nocapture
cargo test -p savana-kernel-protocol
cargo fmt --all -- --check
git diff --check
```

## Task 3: Implement Approvald's bounded live ceremony state machine

**Files:**

- Create: `crates/savana-approvald/src/mac_platform.rs`
- Modify: `crates/savana-approvald/src/lib.rs`
- Modify: `crates/savana-approvald/src/relay.rs`
- Modify: `crates/savana-approvald/src/ui_authority.rs`
- Test: `crates/savana-approvald/src/mac_platform.rs`

- [ ] Write RED tests for `Created -> RelayClaimed -> LauncherClaimed -> FinishAccepted -> Delivered` and every permitted terminal path.
- [ ] Add RED tests for duplicate claim, WebAuthn/platform mutual exclusion, transfer replay, transaction replay, wait result replay, expiry before disclosure, cancellation before launcher claim, cancellation after launcher claim, finish/cancel races, wrong ceremony type, and restart ambiguity.
- [ ] Add RED capacity tests that prove fixed maximum rows and no eviction of live authority state.
- [ ] Run RED:

```bash
cargo test -p savana-approvald mac_platform -- --nocapture
```

- [ ] Implement `MacPlatformCredentialStateV2` as a bounded mutex-protected authority table. Store only authority-generated opaque references, ceremony row references, exact immutable operation data, state, expiry, and terminal result.
- [ ] Generate receipt, launcher transfer, transaction, credential ID, and challenge nonce inside Approvald from nonzero cryptographic entropy.
- [ ] Make WebAuthn relay claim and platform relay claim atomically mutually exclusive against the same underlying ceremony row.
- [ ] Define cancellation semantics exactly: pre-launch cancel is `Denied`; post-launch uncertainty is `Indeterminate`; an explicit launcher user-cancel remains `Denied`; no terminal state can transition again.
- [ ] Re-run focused tests and existing WebAuthn relay tests to prove compatibility:

```bash
cargo test -p savana-approvald mac_platform -- --nocapture
cargo test -p savana-approvald relay -- --nocapture
git diff --check
```

## Task 4: Add exact challenge construction, credential records, and signature verification

**Files:**

- Modify: `crates/savana-kernel-protocol/src/v2/mac_platform_credential.rs`
- Modify: `crates/savana-approvald/src/mac_platform.rs`
- Modify: `crates/savana-approvald/src/protocol_service.rs`
- Modify: `crates/savana-approvald/Cargo.toml`
- Test: `crates/savana-approvald/src/mac_platform.rs`
- Test: `crates/savana-approvald/tests/` using the existing durable-state harness

- [ ] Add RED golden-vector tests for the prefixed canonical challenge. Flip every committed field individually and prove signature verification fails.
- [ ] Add RED tests for wrong credential, wrong P-256 point, non-DER, trailing DER, high-S, invalid scalar, expired result, old/new sequence, duplicate finish, and public-key substitution during enrollment.
- [ ] Add RED durable tests proving enrollment persists public key and sequence zero; successful use advances exactly once in the same commit as ceremony settlement; failure advances neither; invalidation revokes the credential.
- [ ] Run RED:

```bash
cargo test -p savana-approvald mac_platform_signature -- --nocapture
cargo test -p savana-approvald mac_platform_durable -- --nocapture
```

- [ ] Implement `MacPlatformChallengeV2` with domain prefix `SAVANA_MAC_PLATFORM_CREDENTIAL_V2\0` and the exact optional/required fields from the approved design. Use typed `Option`, never empty-string defaults.
- [ ] Implement `MacPlatformCredentialRecordV2` with credential ID, principal, public key, key-tag commitment, current use sequence, state (`Active`/`Revoked`), creation time, and deployment binding.
- [ ] Verify only P-256 ECDSA SHA-256 signatures and require canonical low-S DER. Perform signature verification before durable mutation.
- [ ] Route the five successful finishes through the same authority completion functions already used by their WebAuthn equivalents; do not fabricate browser attestation objects.
- [ ] Re-run tests:

```bash
cargo test -p savana-approvald mac_platform -- --nocapture
cargo test -p savana-approvald
cargo fmt --all -- --check
git diff --check
```

## Task 5: Wire Approvald's relay and dedicated launcher Suite-One services

**Files:**

- Modify: `crates/savana-approvald/src/client.rs`
- Modify: `crates/savana-approvald/src/suite_one.rs`
- Modify: `crates/savana-approvald/src/daemon.rs`
- Modify: `crates/savana-approvald/src/lib.rs`
- Modify: `crates/savana-policy-core/src/v2/deployment_trust.rs`
- Test: `crates/savana-approvald/src/client.rs`
- Test: `crates/savana-approvald/src/daemon.rs`
- Test: `crates/savana-policy-core/src/v2/deployment_trust.rs`

- [ ] Add RED tests for relay Claim/Wait/Cancel dispatch, direct Health/Claim/Finish/Cancel dispatch, wrong-role requests, wrong client identity, wrong edge, stale boot identity, wrong peer measurement, and disconnect after finish acceptance.
- [ ] Add RED tests proving the launcher never supplies challenge, key tag, credential ID selection, purpose, principal, or policy fields.
- [ ] Run RED focused suites.
- [ ] Add separate deployment fields for launcher client identity/key, Approvald platform service identity/key, boot credential, expected peer measurement, edge, and dedicated socket path.
- [ ] Add a dedicated listener whose allowed operation set is closed to the four direct operations. Enforce console-user non-root UID and exact signed launcher measurement before Suite-One application dispatch.
- [ ] Map authority state errors to stable typed protocol errors without returning internal identifiers or OS details.
- [ ] Re-run focused suites plus policy-core:

```bash
cargo test -p savana-approvald client -- --nocapture
cargo test -p savana-approvald daemon -- --nocapture
cargo test -p savana-approvald suite_one -- --nocapture
cargo test -p savana-policy-core deployment_trust -- --nocapture
git diff --check
```

## Task 6: Add the Rust-only client platform relay for all five ceremonies

**Files:**

- Create: `crates/savana-client/src/platform_credential.rs`
- Modify: `crates/savana-client/src/lib.rs`
- Modify: `crates/savana-client/src/auth.rs`
- Modify: `crates/savana-client/src/approval.rs`
- Modify: `crates/savana-client/src/session.rs`
- Test: `crates/savana-client/tests/auth_state_machine.rs`
- Test: `crates/savana-client/tests/session_workflows.rs`

- [ ] Add RED tests with recording fakes proving Ingress UI, Agent UI, Approval Display UI, Approval Decision, and Enrollment pass only `MacPlatformCeremonyClaimV2` to `TrustedPlatformCredentialRelay`.
- [ ] Add RED tests proving the legacy `WebAuthnProvider` and `TrustedWebAuthnRelay` are never called when the platform relay is configured, even when the platform relay denies, expires, becomes unavailable, or returns indeterminate.
- [ ] Add RED tests proving launcher-start failure triggers best-effort cancel, ambiguous wait never retries, typed completion kind mismatch fails closed, and no opaque claim is returned in `AuthError` text/debug.
- [ ] Run RED:

```bash
cargo test -p savana-client --test auth_state_machine platform -- --nocapture
cargo test -p savana-client --test session_workflows platform -- --nocapture
```

- [ ] Implement sealed Rust trait `TrustedPlatformCredentialRelay` and an internal client constructor/configuration path. Its public method receives only the typed opaque claim and returns the typed terminal completion.
- [ ] Add platform-first fixed selection to each ceremony only when macOS product construction installed the platform relay. There is no runtime fallback order: a selected platform path terminates on any platform error.
- [ ] Preserve all existing public `Client.session` and `Client.enroll` signatures.
- [ ] Re-run all client tests:

```bash
cargo test -p savana-client
cargo fmt --all -- --check
git diff --check
```

## Task 7: Bind the PyO3 production client to the native platform relay

**Files:**

- Create: `crates/savana-core-py/src/client/native_platform.rs`
- Modify: `crates/savana-core-py/src/client.rs`
- Modify: `crates/savana-core-py/Cargo.toml`
- Test: `crates/savana-core-py/src/client/native_platform.rs`
- Test: existing Python client SDK tests

- [ ] Add RED Rust tests for the fixed launcher wire (`magic || tag || transfer[32] || expires_at_u64be`), strict ACK parsing, path ownership/mode checks, claim/wait/cancel flow, timeout, launcher failure, and wrong completion type.
- [ ] Add RED Python tests proving the existing callback argument is accepted for compatibility but is not called on platform success, denial, expiry, invalidation, unavailable, or indeterminate.
- [ ] Add a Python boundary test that recursively inspects arguments/results/errors and proves no platform claim, transfer, transaction, key tag, challenge, credential ID, signature, or public key crosses PyO3.
- [ ] Run RED Rust and Python tests.
- [ ] Implement a `NativeTrustedPlatformCredentialRelay` entirely in Rust. Load fixed signed deployment material, use Approvald's signed relay client, send only the opaque launch transfer to the user launcher, then wait for Approvald.
- [ ] Make `PyClient::new` require the native platform relay in macOS product mode and fail closed during construction if configuration is absent or invalid. Retain the old WebAuthn constructor only for non-product compatibility builds.
- [ ] Re-run the focused core-py and Python SDK suites; verify no generated extension is staged.

## Task 8: Implement the signed macOS Secure Enclave launcher operation

**Files (JARVIS worktree):**

- Create: `native/savana_kernel_client/src/platform_credential.rs`
- Modify: `native/savana_kernel_client/src/approval_launcher.rs`
- Modify: `native/savana_kernel_client/src/bin/savana_approval_launcher.rs`
- Modify: `native/savana_kernel_client/src/lib.rs`
- Modify: `native/savana_kernel_client/Cargo.toml`
- Test: `native/savana_kernel_client/src/platform_credential.rs`
- Test: `native/savana_kernel_client/src/approval_launcher.rs`

- [ ] Add RED tests through a `SecureEnclaveKeyStore` seam for exact create attributes, authority-derived key tag only, one operation at a time, lookup, user cancel, biometric invalidation, unavailable UI, low-S output, cleanup of an uncommitted enrollment key, and no auto-retry.
- [ ] Add RED parser tests proving the JARVIS-facing socket rejects extra bytes, variable strings, URLs, challenge fields, caller key tags, wrong magic/tag, zero transfer, and expired requests.
- [ ] Add RED direct-client tests proving Approvald owns the operation fields and the launcher returns only a closed result enum.
- [ ] Select a maintained safe Rust binding to Security.framework after checking its current API and lockfile compatibility. Do not add handwritten unsafe FFI to the Savana crate.
- [ ] Implement Secure Enclave P-256 key creation with:
  `kSecAttrTokenIDSecureEnclave`, permanent private key, `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`, and access control `privateKeyUsage AND biometryCurrentSet`.
- [ ] Use a fixed LocalAuthentication context that disallows credential/passcode fallback and authentication reuse. Map user cancel to `Denied`, biometric set invalidation to `CredentialInvalidated`, and ambiguous OS/transport outcomes to `Indeterminate`.
- [ ] Sign only the exact byte string returned by Approvald; canonicalize/validate low-S DER before returning. Never implement a general signing function over caller bytes.
- [ ] Re-run native launcher tests, `cargo fmt`, and `cargo clippy -- -D warnings` for this crate.

## Task 9: Install, sign, and measure the dedicated macOS edge

**Files (core worktree):**

- Modify: `deploy/macos/development/build.sh`
- Modify: `deploy/macos/development/sign.sh`
- Modify: `deploy/macos/development/install.sh`
- Modify: `deploy/macos/development/uninstall.sh`
- Modify: `deploy/macos/development/validate.sh`
- Modify: `deploy/launchd/development/com.savana.development.approval-launcher.plist`
- Modify: `crates/savana-kerneld/src/bin/savana-development-build-inputs.rs`
- Modify: `crates/savana-policy-core/src/bin/savana-development-manifest.rs`
- Modify: `crates/savana-policy-core/src/bin/savana-development-material.rs`
- Test: `crates/savana-kerneld/tests/macos_deployment.rs`
- Test: `crates/savana-kerneld/tests/deployment_units.rs`

- [ ] Add RED deployment tests for distinct keys/identities/edge/socket, exact modes and parents, console-user UID, signed launcher code measurement, launcher-to-Approvald reciprocal measurement, plist arguments, uninstall cleanup, and validation failure when any component is substituted.
- [ ] Add a RED test proving the macOS platform profile no longer generates or requires the fake local WebAuthn attestation root/AAGUID.
- [ ] Install the direct socket at the approved path and pass only fixed deployment paths to the launcher. Do not place secrets in plist arguments, environment, stdout, or user-readable files.
- [ ] Generate distinct Suite-One materials and manifest bindings for `MacPlatformCredential`. Measure the final signed binary, then freeze the manifest/build inputs in the existing order.
- [ ] Keep the compatibility hardware-WebAuthn profile explicit and separate; do not remove its verifier or Linux files.
- [ ] Run:

```bash
cargo test -p savana-kerneld --test macos_deployment -- --nocapture
cargo test -p savana-kerneld --test deployment_units -- --nocapture
cargo test -p savana-policy-core
deploy/macos/development/validate.sh
git diff --check
```

## Task 10: Update JARVIS backend and enrollment UI without exposing secrets

**Files (JARVIS worktree):**

- Modify: `server/savana_backend/service.py`
- Modify: `server/savana_backend/sdk.py`
- Modify: `server/api/routes_savana.py`
- Modify: `apps/web/src/SavanaEnroll.tsx`
- Modify: `apps/web/src/statusCopy.ts`
- Modify: `apps/web/src/types.ts`
- Modify: `apps/web/src/api.ts`
- Test: `tests/test_savana_backend.py`
- Test: `tests/test_savana_api.py`
- Test: `apps/web/src/App.test.tsx`
- Test: `apps/web/src/api.test.ts`
- Test: `apps/web/src/useTaskSync.test.tsx`

- [ ] Add RED backend tests for the six stable platform error codes and generic handling of unknown internal errors. Assert response/log structures never contain capability bytes, challenge, key tag, credential ID, public key, or signature.
- [ ] Add RED UI tests for: “Touch ID is required”; “changing enrolled fingerprints requires re-enrollment”; pending launcher state; user cancellation; expired; invalidated; unavailable; indeterminate; and generic protocol failure.
- [ ] Add RED tests proving macOS product mode renders no browser WebAuthn button, security-key instruction, passkey wording, password fallback, or manual platform secret field.
- [ ] Map only stable code-owned status values across Python/HTTP. The UI starts enrollment with the existing token/code and polls safe lifecycle state.
- [ ] Preserve OpenClaw/MCP APIs. They may trigger the zero-argument approval-center notification, but cannot start or settle a platform credential.
- [ ] Run the complete JARVIS Python and frontend suites and `git diff --check`.

## Task 11: Document, verify, deploy, and perform the real Touch ID acceptance run

**Files:**

- Modify: core `README.md`
- Modify: core Chinese README if present
- Modify: `docs/client-sdk-v2.md`
- Modify: macOS deployment documentation
- Modify: JARVIS/OpenClaw integration documentation

- [ ] Document the unchanged public SDK surface, internal platform flow, macOS requirements, stable public errors, re-enrollment after biometric-set change, Linux/hardware-WebAuthn compatibility, and the absence of Python/HTTP signing interfaces.
- [ ] Run full core verification from the core worktree:

```bash
cargo fmt --all -- --check
cargo test --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
git diff --check
```

- [ ] Run full JARVIS verification from the JARVIS worktree using its repository-documented Python, Rust, frontend, and OpenClaw commands. Record every command and exact result.
- [ ] Build the native launcher and PyO3 extension, sign the complete deployment, install it, and run `deploy/macos/development/validate.sh` against installed paths.
- [ ] Confirm service logs show the platform endpoint, signed launcher, Approvald, JARVIS backend, and OpenClaw runtime ready without fallback warnings.
- [ ] Perform the physical acceptance run on this Mac:
  enroll with Touch ID; open a session with Touch ID; settle one approval with Touch ID; cancel one prompt; replay a consumed transfer/result and confirm rejection; change the enrolled Touch ID set and confirm the credential becomes invalid and re-enrollment is required.
- [ ] Inspect browser/network/backend logs and confirm no challenge, key tag, credential ID, signature, public key, or opaque platform capability escaped the Rust/launcher boundary.
- [ ] Only after all checks pass, update frozen hashes/pins generated by the documented build pipeline, create focused commits in each worktree, and report hashes plus any remaining baseline-only warnings. Do not push unless explicitly requested.
