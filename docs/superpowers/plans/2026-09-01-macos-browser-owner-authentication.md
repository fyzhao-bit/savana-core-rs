# macOS Browser Owner Authentication Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the macOS product browser flow complete every owner-authentication gate with the enrolled Savana Secure Enclave credential and Touch ID, without asking the browser or a phone for a `localhost` passkey.

**Architecture:** Approvald remains the only ceremony and approval authority. The browser arms and observes an opaque platform ceremony but cannot launch or attest Touch ID. JARVIS resolves its existing public `TaskHandleV2` through Agentd to an internal durable-task projection, claims exactly one matching Approvald ceremony through the pinned `JarvisApprovalRelay`, and sends only Approvald's one-use launcher transfer to the existing signed macOS launcher. The launcher reuses the current Secure Enclave operation; typed completion returns to Approvald and the browser later receives only the existing ingress transfer, approval tab, or approve/deny result. Linux keeps an explicitly configured WebAuthn compatibility profile.

**Tech Stack:** Rust 2021, canonical CBOR, Suite-One authenticated Unix sockets, Approvald/Agentd bounded state owners, PyO3, Python 3.12/FastAPI, React 18/TypeScript/Vitest, macOS Security.framework/LocalAuthentication, launchd.

**Spec:** `docs/superpowers/specs/2026-09-01-macos-browser-owner-authentication-design.md`

## Global Constraints

- Core worktree: `/Users/fz/Documents/jarvis/.worktrees/security-capabilities-assessment`
- JARVIS worktree: `/Users/fz/Documents/jarvis/.worktrees/openclaw-approval-broker`
- Preserve every pre-existing dirty-worktree change. Before each task, capture the exact pre-task diff for every touched dirty file. Stage only newly introduced hunks; if a hunk cannot be isolated safely, defer that task's commit rather than absorbing unrelated work.
- Use RED-GREEN-REFACTOR for every behavior change. Run each named RED test and confirm that it fails for the intended missing behavior before editing production code.
- The browser may retain its existing pre-authentication capability, approval tab, and typed completion, but must never receive a durable task ID, platform ceremony claim, relay receipt, launcher transfer, challenge, key tag, credential ID, or signature.
- Python may pass only the existing hexadecimal `TaskHandleV2` into the new internal control method and receive a closed public state. It must never receive the internal durable task ID or any Approvald/launcher capability.
- The platform path must be selected by verified deployment configuration, not user agent sniffing, runtime fallback order, or JavaScript feature detection.
- macOS product mode has no password, phone, passkey, WebAuthn, Apple Watch, remote-device, or software-key fallback. A platform denial or uncertainty terminates that attempt fail-closed.
- The explicit `hardware-webauthn-compatibility` deployment profile stays available for Linux and existing compatibility tests.
- Claim-by-task selection is exact: zero eligible ceremonies returns `NonePending`; one is claimed; more than one fails closed. Never select by insertion order, creation time, vector position, or “latest”.
- Browser refresh does not persist or reconstruct capabilities. The user cancels and restarts the pre-effect task.
- Do not change the existing public fifteen-method Savana client SDK surface, `agentd` service roles, `OPEN_MAC_PLATFORM_CREDENTIAL = 3`, or the Secure Enclave challenge/signature implementation.
- Do not add ports. Keep browser origins on 8765-8768, JARVIS on 8770, and existing authenticated Unix sockets.
- Logs may contain only stable code, task correlation digest, component, and state transition. They must not contain task/pre-auth handles, approval tabs, ceremony/claim/receipt/transfer/transaction values, credential/key/challenge/signature/public-key material, or enrollment values.
- Existing valid Secure Enclave credentials and use sequences remain intact; this browser-flow change does not clear state or require re-enrollment.
- Do not commit generated `.so` files, build products, deployment secrets, local credentials, Keychain/Secure Enclave material, or runtime state.
- Before every commit run the focused tests, `cargo fmt --all -- --check` for the affected Rust workspace, and `git diff --check`. Inspect `git diff --cached --stat` and `git diff --cached` before committing.

---

## Task 1: Add canonical platform browser status protocols and fixed routes

**Files:**

- Modify: `crates/savana-kernel-protocol/src/v2/browser.rs`
- Modify: `crates/savana-kernel-protocol/src/v2/browser_approval.rs`
- Modify: `crates/savana-kernel-protocol/src/v2/http.rs`
- Modify: `crates/savana-kernel-protocol/src/v2/mod.rs`
- Test: inline unit tests in those files

**Interfaces:**

```rust
pub enum OwnerAuthenticationProfileV2 {
    MacPlatform,
    HardwareWebAuthnCompatibility,
}

pub enum UiAuthenticationPlatformBeginResponseV2 {
    Ingress {
        ceremony: IngressUiAuthenticationBrowserCeremonyCapabilityV2,
        expires_at: UnixMillisV2,
    },
    ApprovalDisplay {
        ceremony: ApprovalDisplayUiAuthenticationBrowserCeremonyCapabilityV2,
        expires_at: UnixMillisV2,
    },
    Agent {
        ceremony: AgentUiAuthenticationBrowserCeremonyCapabilityV2,
        expires_at: UnixMillisV2,
    },
}

pub enum UiAuthenticationPlatformStatusRequestV2 {
    Ingress {
        ceremony: IngressUiAuthenticationBrowserCeremonyCapabilityV2,
        client_request_nonce: Nonce32V2,
    },
    ApprovalDisplay {
        ceremony: ApprovalDisplayUiAuthenticationBrowserCeremonyCapabilityV2,
        client_request_nonce: Nonce32V2,
    },
    Agent {
        ceremony: AgentUiAuthenticationBrowserCeremonyCapabilityV2,
        client_request_nonce: Nonce32V2,
    },
}

pub enum UiAuthenticationPlatformStatusResponseV2 {
    Pending,
    Completed(UiAuthenticationBrowserFinishResponseV2),
    Denied,
    Expired,
    CredentialInvalidated,
    Unavailable,
    Indeterminate,
    ProtocolFailure,
}

pub enum ApprovalDecisionPlatformStatusResponseV2 {
    Pending,
    Completed(ApprovalDecisionBrowserFinishResponseV2),
    Denied,
    Expired,
    CredentialInvalidated,
    Unavailable,
    Indeterminate,
    ProtocolFailure,
}

pub struct ApprovalDecisionPlatformBeginResponseV2 {
    ceremony: ApprovalDecisionCeremonyCapabilityV2,
    expires_at: UnixMillisV2,
}

pub struct ApprovalDecisionPlatformStatusRequestV2 {
    ceremony: ApprovalDecisionCeremonyCapabilityV2,
    client_request_nonce: Nonce32V2,
}
```

The platform begin routes reuse the already bounded begin requests:

- `UiAuthenticationBrowserBeginRequestV2` for `/v2/ui-auth/platform/begin`
- `ApprovalDecisionBrowserBeginRequestV2` for `/v2/approval/decision/platform/begin`

Status uses only the newly returned ceremony capability and the exact begin nonce; it never reuses the pre-authentication capability or approval tab.

- [ ] Add canonical profile tests for tags `1=MacPlatform` and `2=HardwareWebAuthnCompatibility`, exact bootstrap strings, cross-tag rejection, and unknown profile rejection.
- [ ] Add round-trip tests for every begin response and status request, proving nonzero ceremony capability, nonzero absolute expiry, exact UI/decision kind separation, and exact nonce preservation.
- [ ] Add round-trip tests for every status response variant and for all three UI completion kinds (`TransferToIngress`, `ApprovalDisplayReady`, `TransferToAgent`) plus both approval outcomes.
- [ ] Add rejection tests for unknown tags, wrong array lengths, trailing bytes, noncanonical CBOR, a UI completion inside the approval-decision response, and an approval completion inside the UI response.
- [ ] Add fixed-route tests for exactly these Approvald-only POST routes and their required `Origin: http://localhost:8766`:

```text
/v2/ui-auth/platform/begin
/v2/ui-auth/platform/status
/v2/approval/decision/platform/begin
/v2/approval/decision/platform/status
```

- [ ] Run RED and verify the failure names the missing status types/routes:

```bash
cargo test -p savana-kernel-protocol platform_status -- --nocapture
cargo test -p savana-kernel-protocol fixed_http_platform -- --nocapture
```

- [ ] Implement `OwnerAuthenticationProfileV2` in the protocol crate with exact string conversion for `mac-platform` and `hardware-webauthn-compatibility`; do not let HTTP or environment input construct it.
- [ ] Implement begin/status request codecs with distinct domain/kind tags. Implement status response tags `1=Pending`, `2=Completed`, `3=Denied`, `4=Expired`, `5=CredentialInvalidated`, `6=Unavailable`, `7=Indeterminate`, `8=ProtocolFailure`; encode a completion only under tag 2.
- [ ] Add the four `FixedHttpRouteV2` variants, exact path parsing, content type, and origin validation. Do not accept GET, query strings, 127.0.0.1, or another service origin.
- [ ] Re-run GREEN and the whole protocol crate:

```bash
cargo test -p savana-kernel-protocol platform_status -- --nocapture
cargo test -p savana-kernel-protocol fixed_http_platform -- --nocapture
cargo test -p savana-kernel-protocol
cargo fmt --all -- --check
git diff --check
```

- [ ] Commit only Task 1 hunks:

```bash
git commit -m "feat(protocol): add platform browser ceremony status"
```

## Task 2: Resolve a public task handle to an internal pending-authentication projection

**Files:**

- Modify: `crates/savana-kernel-protocol/src/v2/jarvis.rs`
- Modify: `crates/savana-kernel-protocol/src/v2/service.rs`
- Modify: `crates/savana-agentd/src/lib.rs`
- Modify: `crates/savana-agentd/src/agent_control.rs`
- Test: inline tests in the same files

**Interfaces:**

```rust
pub struct ResolvePendingOwnerAuthenticationRequestV2 {
    task: TaskHandleV2,
    client_request_nonce: Nonce32V2,
}

pub struct PendingOwnerAuthenticationTaskV2 {
    durable_task_id: DurableTaskIdV2,
    public_state_revision: u64,
    task_logical_expires_at: UnixMillisV2,
}

pub enum ResolvePendingOwnerAuthenticationResponseV2 {
    NonePending,
    Pending(PendingOwnerAuthenticationTaskV2),
}
```

Add request/response operation tag `13`; do not overload tags 10-12.

- [ ] Add protocol RED tests for canonical request/response round trips, zero nonce, zero revision, zero expiry, unknown tag, and response-family mismatch.
- [ ] Add Agentd RED tests proving the operation resolves only a task owned by the exact authenticated JARVIS creator context already enforced by `resolve_task`.
- [ ] Add RED tests for foreign creator, unknown task, expired task, terminal task, `ready`, `awaiting_input`, and `processing`; all return an existing public error or `NonePending`, never the durable ID.
- [ ] Add an exact replay RED test proving repeated read-only resolution of the same owned pending task returns the same internal projection without mutating the task or minting a new durable identity.
- [ ] Add positive RED cases only for `awaiting_ui_authentication` and `awaiting_ingress_approval`, verifying the internal projection carries the task's exact durable ID, current public revision, and logical expiry.
- [ ] Run RED:

```bash
cargo test -p savana-kernel-protocol resolve_pending_owner_authentication -- --nocapture
cargo test -p savana-agentd resolve_pending_owner_authentication -- --nocapture
```

- [ ] Implement `ResolvePendingOwnerAuthentication` by calling the existing creator-bound task resolver. Do not scan by durable ID and do not add a Python-facing field to `PublicTaskStatusV2`.
- [ ] Preserve revision/expiry in the internal response so the native JARVIS client can re-resolve immediately before launcher disclosure and cancel a claimed receipt if the task changed. Agentd must not send those fields to Approvald itself.
- [ ] Re-run GREEN:

```bash
cargo test -p savana-kernel-protocol resolve_pending_owner_authentication -- --nocapture
cargo test -p savana-agentd resolve_pending_owner_authentication -- --nocapture
cargo test -p savana-agentd
cargo fmt --all -- --check
git diff --check
```

- [ ] Commit only Task 2 hunks:

```bash
git commit -m "feat(agentd): resolve pending owner authentication by task"
```

## Task 3: Add the task-bound Approvald relay operation

**Files:**

- Modify: `crates/savana-kernel-protocol/src/v2/approval_relay.rs`
- Modify: `crates/savana-kernel-protocol/src/v2/approval_service.rs`
- Modify: `crates/savana-approvald/src/client.rs`
- Test: inline tests in those files

**Interfaces:**

```rust
pub struct ClaimPendingMacPlatformCeremonyForTaskV2 {
    durable_task_id: DurableTaskIdV2,
    client_request_nonce: Nonce32V2,
}

pub enum ClaimedPendingMacPlatformCeremonyV2 {
    NonePending,
    Claimed(ClaimedMacPlatformCeremonyV2),
}

ApprovalServiceOperationV2::ClaimPendingMacPlatformCeremonyForTask {
    request: ClaimPendingMacPlatformCeremonyForTaskV2,
}
```

Use relay operation tag `123`, owned only by `EndpointRoleV2::JarvisApprovalRelay`.

- [ ] Add RED canonical CBOR tests for the request and both responses, including zero durable ID/nonce, unknown tags, wrong array length, and trailing data.
- [ ] Add role-table RED tests proving tag 123 is accepted only for `JarvisApprovalRelay` and rejected for `ApprovalAdmin`, `MacPlatformCredential`, Agentd, Ingressd, and browser roles.
- [ ] Add client RED tests that `claim_pending_mac_platform_ceremony_for_task` sends no public task handle and returns only `NonePending` or the existing claimed platform transfer record.
- [ ] Run RED:

```bash
cargo test -p savana-kernel-protocol claim_pending_mac_platform_for_task -- --nocapture
cargo test -p savana-approvald claim_pending_mac_platform_for_task_client -- --nocapture
```

- [ ] Implement canonical request/response codecs, operation role/tag dispatch, and the typed `ApprovalSuiteOneClientV2` sender/decoder method. Task 4 adds server-side authority dispatch after unique selection exists. Do not add a new endpoint role, socket, or key.
- [ ] Re-run GREEN:

```bash
cargo test -p savana-kernel-protocol claim_pending_mac_platform_for_task -- --nocapture
cargo test -p savana-approvald claim_pending_mac_platform_for_task_client -- --nocapture
cargo test -p savana-kernel-protocol
cargo fmt --all -- --check
git diff --check
```

- [ ] Commit only Task 3 hunks:

```bash
git commit -m "feat(protocol): claim platform ceremony by durable task"
```

## Task 4: Bind Approvald UI rows to durable tasks and select exactly one ceremony

**Files:**

- Modify: `crates/savana-approvald/src/ui_authority.rs`
- Modify: `crates/savana-approvald/src/relay.rs`
- Modify: `crates/savana-approvald/src/mac_platform.rs`
- Modify: `crates/savana-approvald/src/lib.rs`
- Modify: `crates/savana-approvald/src/suite_one.rs`
- Test: inline tests in `ui_authority.rs`, `relay.rs`, and `mac_platform.rs`

**State additions:**

```rust
struct UiRecordV2 {
    durable_task_id: DurableTaskIdV2,
    // existing fields...
    platform_claim_nonce: Option<Nonce32V2>,
    platform_claimed: Option<ClaimedMacPlatformCeremonyV2>,
    platform_terminal: Option<UiPlatformTerminalV2>,
}

enum UiPlatformTerminalV2 {
    Denied,
    CredentialInvalidated,
    Unavailable,
    Indeterminate,
}
```

`durable_task_id` must come from the verified `UiAuthenticationChallengeProjectionV2::binding()`, covering `IngressNewTask`, `IngressExistingRun`, `ApprovalDisplay`, and `AgentContent`.

- [ ] Add RED registration tests proving Approvald stores the durable task ID only after the signed envelope has passed existing deployment/signature verification; a forged payload cannot influence selection.
- [ ] Add RED selection tests for zero, one, and two eligible rows with the same durable task ID. Two must fail closed without claiming either row.
- [ ] Add RED eligibility tests excluding rows with no armed ceremony, an expired ceremony, a completed UI settlement, a completed decision, an already WebAuthn-claimed ceremony, or an already platform-claimed ceremony.
- [ ] Add RED idempotency tests: the same durable task ID plus the same `client_request_nonce` returns the same claimed receipt/transfer; a different nonce after claim is rejected.
- [ ] Add RED tests for all four claim forms selected from a task row: ingress UI, agent UI, approval-display UI, and approval decision.
- [ ] Run RED:

```bash
cargo test -p savana-approvald task_bound_platform_claim -- --nocapture
cargo test -p savana-approvald relay_claim_registry -- --nocapture
```

- [ ] Resolve an existing same-nonce task claim before fresh candidate counting so an exact replay returns its original receipt even though it is no longer eligible as “unclaimed”. Then use a non-mutating `CeremonyClaimRegistryV2::is_claimed` query and count every fresh candidate before calling the existing exact `claim_mac_platform_relay`; preserve WebAuthn/platform mutual exclusion.
- [ ] Store terminal denial/unavailable/invalidation/indeterminate on the UI row when the launcher finishes, while retaining existing typed success settlement logic. Derive expiry from the row's existing ceremony deadline.
- [ ] Dispatch operation 123 through the current relay service and map multiple candidates to a fail-closed authenticated error, never `NonePending`.
- [ ] Re-run GREEN and the whole Approvald crate:

```bash
cargo test -p savana-approvald task_bound_platform_claim -- --nocapture
cargo test -p savana-approvald relay_claim_registry -- --nocapture
cargo test -p savana-approvald mac_platform -- --nocapture
cargo test -p savana-approvald
cargo fmt --all -- --check
git diff --check
```

- [ ] Commit only Task 4 hunks:

```bash
git commit -m "feat(approvald): bind platform ceremonies to durable tasks"
```

## Task 5: Implement platform begin/status lifecycle and deployment profile enforcement

**Files:**

- Modify: `crates/savana-approvald/src/ui_authority.rs`
- Modify: `crates/savana-approvald/src/daemon.rs`
- Modify: `crates/savana-kernel-protocol/src/v2/http.rs`
- Test: inline Approvald authority/daemon tests

**Deployment profile:** Reuse protocol `OwnerAuthenticationProfileV2`. The `approvald-bootstrap-v2.json` field is mandatory and named `owner_authentication_profile`; strict bootstrap deserialization maps only `mac-platform` and `hardware-webauthn-compatibility` to that type.

- [ ] Add RED configuration tests rejecting a missing, null, unknown, mixed-case, or extra profile value.
- [ ] Add RED authority tests showing platform begin arms exactly the existing ceremony capability/challenge but does not generate or return WebAuthn `public_key_options_json`.
- [ ] Add RED status tests for `Pending`, each typed success, `Denied`, `Expired`, `CredentialInvalidated`, `Unavailable`, and `Indeterminate`; a mismatched ceremony capability or nonce returns `ProtocolFailure` or a closed HTTP failure without leaking row existence.
- [ ] Add RED daemon tests proving `mac-platform` enables only the four platform routes for owner authentication and rejects the old WebAuthn begin/finish, browser enrollment, and WebAuthn relay routes.
- [ ] Add RED compatibility tests proving `hardware-webauthn-compatibility` keeps the old begin/finish/enrollment/relay routes and rejects the platform routes.
- [ ] Run RED:

```bash
cargo test -p savana-approvald owner_authentication_profile -- --nocapture
cargo test -p savana-approvald platform_browser_lifecycle -- --nocapture
```

- [ ] Refactor the existing UI/decision begin methods into shared ceremony creation plus profile-specific response construction. The mac begin response returns only the exact ceremony capability and absolute expiry; the mac path must not call `public_key_options` or embed `rpId: localhost`.
- [ ] Make status observation non-consuming. Existing JARVIS relay wait may consume its receipt, but the browser status must still resolve from the UI row's success/terminal fields and expiry.
- [ ] Pass the verified profile into HTTP request dispatch and `render_authentication_shell`; render only the fixed profile string and profile-appropriate button copy. Task 6 replaces/selects the profile-specific script assets after their RED behavior harnesses exist.
- [ ] Re-run GREEN:

```bash
cargo test -p savana-approvald owner_authentication_profile -- --nocapture
cargo test -p savana-approvald platform_browser_lifecycle -- --nocapture
cargo test -p savana-approvald
cargo fmt --all -- --check
git diff --check
```

- [ ] Commit only Task 5 hunks:

```bash
git commit -m "feat(approvald): enforce platform browser authentication profile"
```

## Task 6: Replace normal macOS browser WebAuthn calls with platform polling

**Files:**

- Modify: `crates/savana-kernel-protocol/src/v2/browser_assets.rs`
- Modify: `crates/savana-approvald/src/daemon.rs`
- Test: Node fake-DOM harnesses inline in `browser_assets.rs` and profile-selection tests in `daemon.rs`

**Browser behavior:**

```text
authentication button
  -> POST platform/begin with existing pre-auth capability + nonce
  -> receive ceremony capability + absolute expiry
  -> poll platform/status with ceremony capability + the same nonce
  -> consume only existing typed UI completion

approve/deny button
  -> POST decision/platform/begin with tab + nonce + exact decision
  -> receive decision ceremony capability + absolute expiry
  -> poll decision/platform/status with that capability + the same nonce
  -> render only Approved or Denied
```

- [ ] Add a RED Node harness for ingress authentication with `data-owner-authentication-profile="mac-platform"`; define `navigator.credentials` with a getter that throws, and prove the full pending-to-`TransferToIngress` flow succeeds without reading it.
- [ ] Add the same RED harness for approval-display authentication through `ApprovalDisplayReady`, then exercise both approve and deny decision paths through the decision platform routes.
- [ ] Add RED tests for denied, expired, invalidated, unavailable, indeterminate, protocol-failure, malformed completion, changed nonce, and page refresh; every path must stop polling and must not fall back to WebAuthn.
- [ ] Split the served asset constants so the macOS product asset contains no `navigator.credentials`, `PublicKeyCredential`, Passkey, security-key, phone, QR, password, or remote-device code/copy. Retain a separately named compatibility asset and run its existing relay/enrollment harness under `hardware-webauthn-compatibility`, proving `navigator.credentials.get/create` still work there.
- [ ] Run RED:

```bash
cargo test -p savana-kernel-protocol browser_assets_mac_platform -- --nocapture
cargo test -p savana-approvald browser_script_profile -- --nocapture
```

- [ ] Add a bounded `pollPlatformStatus(path, ceremony, nonce, expiresAt)` helper. Stop at the absolute begin expiry while treating Approvald's typed terminal status as authoritative. Use `cache: "no-store"`, `credentials: "omit"`, and the existing fixed-origin `post` helper. Do not store capabilities in local/session storage, URL fragments, service workers, or cookies.
- [ ] Branch on the exact server-rendered profile and have Approvald serve the corresponding fixed asset constant. Unknown/missing profile fails closed; user-agent or `PublicKeyCredential` detection is forbidden.
- [ ] Keep `runWebAuthnRelay`, browser enrollment, and all `navigator.credentials` references only in the compatibility asset. The mac product asset must not contain them even as unreachable functions.
- [ ] Re-run GREEN and existing browser tests:

```bash
cargo test -p savana-kernel-protocol browser_assets_mac_platform -- --nocapture
cargo test -p savana-kernel-protocol browser_assets -- --nocapture
cargo test -p savana-approvald browser_script_profile -- --nocapture
cargo test -p savana-kernel-protocol
cargo test -p savana-approvald
cargo fmt --all -- --check
git diff --check
```

- [ ] Commit only Task 6 hunks:

```bash
git commit -m "fix(browser): use macOS platform owner authentication"
```

## Task 7: Pin macOS product deployment to the platform profile

**Files:**

- Modify: `crates/savana-kerneld/src/bin/savana-development-build-inputs.rs`
- Modify: `crates/savana-kerneld/tests/macos_deployment.rs`
- Modify: `crates/savana-kerneld/tests/deployment_units.rs`
- Modify: `deploy/macos/development/validate.sh`
- Test: existing macOS deployment tests and validator

- [ ] Add RED tests that generated `approvald-bootstrap-v2.json` contains exactly `"owner_authentication_profile": "mac-platform"` and that installed config cannot omit or replace it.
- [ ] Add RED assertions that the macOS platform profile still emits empty `attestation_roots` and `hardware_credentials`; no fake localhost WebAuthn root/credential is introduced to make the browser pass.
- [ ] Add RED tests proving the existing relay/platform client identities, keys, boot credentials, launcher socket, and `OPEN_MAC_PLATFORM_CREDENTIAL` launchd unit remain present and distinct.
- [ ] Add a validator RED assertion rejecting `hardware-webauthn-compatibility` in the macOS product build.
- [ ] Run RED:

```bash
cargo test -p savana-kerneld --test macos_deployment owner_authentication_profile -- --nocapture
cargo test -p savana-kerneld --test deployment_units owner_authentication_profile -- --nocapture
```

- [ ] Emit the mandatory profile from the development input generator and validate it before signing/installing. Do not add another config file or runtime environment override.
- [ ] Re-run GREEN and shell validation:

```bash
cargo test -p savana-kerneld --test macos_deployment owner_authentication_profile -- --nocapture
cargo test -p savana-kerneld --test deployment_units owner_authentication_profile -- --nocapture
bash -n deploy/macos/development/validate.sh
cargo fmt --all -- --check
git diff --check
```

- [ ] Commit only Task 7 hunks:

```bash
git commit -m "feat(deploy): pin macOS owner authentication profile"
```

## Task 8: Add the task-only native JARVIS platform relay

**Files (JARVIS worktree):**

- Create: `native/savana_kernel_client/src/pending_owner_auth.rs`
- Modify: `native/savana_kernel_client/src/control.rs`
- Modify: `native/savana_kernel_client/src/lib.rs`
- Modify: `native/savana_kernel_client/src/approval_launcher.rs`
- Test: inline Rust tests in those files

**Public Python projection:**

```python
ControlClient.settle_pending_owner_authentication(task: str) -> {
    "state": "none_pending" | "completed" | "denied" | "expired"
             | "credential_invalidated" | "unavailable"
             | "indeterminate" | "protocol_failure"
}
```

The Rust method accepts only `TaskHandleV2`; it generates the nonce internally and never adds `durable_task_id` to a Python dictionary.

- [ ] Add RED control tests proving the new method first sends Agentd operation 13 and rejects a response with the wrong request ID, service identity, operation family, zero revision, or expired projection.
- [ ] Add RED relay tests with fakes for `NonePending`, exactly one claim, launcher ACK, pending wait, every terminal result, typed-completion mismatch, pre-write launcher failure with best-effort cancel, post-write/ACK-loss uncertainty, expiry, wait disconnect, and no retry after indeterminate.
- [ ] Add RED concurrency tests proving at most one settlement is in flight per exact `TaskHandleV2`; a concurrent same-task call returns a stable busy/protocol refusal and a different task remains independent.
- [ ] Add a RED lost-response test: if the first task-bound claim committed but its response was lost, replay the exact same `client_request_nonce`, recover the same receipt/transfer, and do not disclose the launcher transfer twice.
- [ ] Add a RED fresh-use test proving two sequential ceremonies for the same task/credential each perform a distinct claim, launcher request, Secure Enclave operation, and receipt wait; no prior terminal result or authentication window is reused.
- [ ] Add a RED recursive-boundary test proving task input and closed state output/error contain no durable ID, ceremony capability, receipt, transfer, challenge, credential/key tag, or signature.
- [ ] Add RED formatting/log tests proving `Debug`, `Display`, and stable errors contain only code/component/state and redact every value prohibited by the global logging constraint.
- [ ] Add RED launcher wire tests proving the sender reuses exactly `SAVL2\0\0\0 || 3 || transfer[32] || expires_at_u64be`, validates the signed launcher peer, requires the exact ACK, rejects trailing bytes, and never sends a URL or free-form string.
- [ ] Run RED from the JARVIS worktree:

```bash
cargo test --manifest-path native/savana_kernel_client/Cargo.toml pending_owner_auth -- --nocapture
```

- [ ] Implement internal `ControlClient::resolve_pending_owner_authentication`, then build a pinned `ApprovalSuiteOneClientV2` under `JarvisApprovalRelay` using the already installed relay seed, boot ID, Approvald public key, verified manifest, and current signed JARVIS process binding.
- [ ] Adapt the existing native platform relay loop: resolve projection A, call `claim_pending_mac_platform_ceremony_for_task` with only A's durable task ID plus a fresh nonce, then resolve projection B before launcher disclosure. If B is absent or its durable ID/revision/expiry differs from A, cancel the claimed receipt and return `none_pending` or fail indeterminate if cancellation is uncertain.
- [ ] After the A/B match, send only the launcher transfer to the existing launcher, wait by receipt, verify the typed completion family, and flatten it to the closed public state. A failure before any request byte is written may cancel; after write/flush, never resend the transfer—observe the receipt and return indeterminate if completion cannot be authenticated.
- [ ] Guard the whole method with an in-memory per-task in-flight set and remove the guard on every return/panic-safe scope exit. Retain the claim nonce until a definitive claim response or terminal indeterminate outcome so a dropped response can replay the exact request.
- [ ] Expose one PyO3 method on `PyControlClient`; update the module documentation from “exactly four operations” to enumerate the internal task-authentication method separately from the public SDK.
- [ ] Re-run GREEN and all native tests:

```bash
cargo test --manifest-path native/savana_kernel_client/Cargo.toml pending_owner_auth -- --nocapture
cargo test --manifest-path native/savana_kernel_client/Cargo.toml
cargo fmt --manifest-path native/savana_kernel_client/Cargo.toml -- --check
git diff --check
```

- [ ] Commit only Task 8 JARVIS hunks:

```bash
git commit -m "feat(jarvis): settle owner authentication by task"
```

## Task 9: Drive the native relay from the Python coordinator and keep HTTP capability-free

**Files (JARVIS worktree):**

- Modify: `server/savana_backend/control_plane.py`
- Modify: `server/savana_backend/session_control.py`
- Modify: `tests/test_control_plane.py`
- Modify: `tests/test_session_control.py`
- Modify: `tests/test_session_bootstrap_api.py`
- Modify: `apps/web/src/SavanaConnect.tsx`
- Modify: `apps/web/src/statusCopy.ts`
- Modify: `apps/web/src/App.test.tsx`
- Test: listed Python and TypeScript tests

- [ ] Add Python RED tests that `continue_session` calls `settle_pending_owner_authentication(task)` only when Agentd reports `awaiting_ui_authentication` or `awaiting_ingress_approval`; it must not call it for `awaiting_input`, `processing`, `ready`, or terminal states.
- [ ] Add RED mappings: `none_pending`/`completed` return `{"state": "awaiting_ingress"}` and allow the normal next poll. The terminal states raise exactly `PLATFORM_CREDENTIAL_DENIED`, `PLATFORM_CREDENTIAL_EXPIRED`, `PLATFORM_CREDENTIAL_INVALIDATED`, `PLATFORM_CREDENTIAL_UNAVAILABLE`, `PLATFORM_CREDENTIAL_INDETERMINATE`, or `PLATFORM_CREDENTIAL_PROTOCOL`; burn the pending task and best-effort cancel where the outcome is not already terminal.
- [ ] Add API RED tests proving owner/conversation binding, CSRF behavior, and the response surface are unchanged: no task handle, durable ID, agent URL, transfer, platform state internals, or ceremony capability appears over 8770.
- [ ] Add RED route tests proving OpenClaw, MCP tool payloads, connector/model input, and arbitrary browser requests cannot call the new native method or supply a task/ceremony/decision to it; only the owner-bound coordinator invokes it with its memory-only task.
- [ ] Add frontend RED tests proving the connect page opens one ingress URL, polls `/api/savana/session/continue`, shows the code-owned text `Waiting for Touch ID on this Mac.`, and offers only cancel/restart after a terminal platform failure. It must not ask for a passkey or call the compatibility `launchCeremony` during control-plane session bootstrap.
- [ ] Run RED from the JARVIS worktree:

```bash
.venv/bin/python -m pytest tests/test_control_plane.py tests/test_session_control.py tests/test_session_bootstrap_api.py -q
env PATH=/opt/homebrew/opt/node@24/bin:/usr/bin:/bin /opt/homebrew/opt/node@24/bin/npm --prefix apps/web test -- App.test.tsx
```

- [ ] Add `settle_pending_owner_authentication` to `_RawControlClient` and `ControlPlane`, preserving the existing RuntimeError-to-`ControlPlaneError` mapping.
- [ ] Split `_WAITING_CONTROL_STATES` into platform-authentication states and passive waiting states. Keep the task handle only in the coordinator's memory-only `_Pending` record.
- [ ] Update only connect-flow copy/comments. Leave the separately configured SDK WebAuthn compatibility UI available for Linux compatibility sessions.
- [ ] Re-run GREEN and related suites:

```bash
.venv/bin/python -m pytest tests/test_control_plane.py tests/test_session_control.py tests/test_session_bootstrap_api.py tests/test_savana_api.py -q
env PATH=/opt/homebrew/opt/node@24/bin:/usr/bin:/bin /opt/homebrew/opt/node@24/bin/npm --prefix apps/web test -- App.test.tsx api.test.ts statusCopy.test.ts
env PATH=/opt/homebrew/opt/node@24/bin:/usr/bin:/bin /opt/homebrew/opt/node@24/bin/npm --prefix apps/web run build
git diff --check
```

- [ ] Commit only Task 9 JARVIS hunks:

```bash
git commit -m "fix(server): drive macOS owner authentication natively"
```

## Task 10: Verify cross-repository security invariants and perform real macOS acceptance

**Files:**

- Modify only if the restart assertion is missing: `crates/savana-kerneld/tests/v2_crash_matrix.rs`
- Modify only if an assertion is missing: `docs/openclaw-deployment-acceptance-gate.md`
- Do not modify production code in this task; any failure returns to the responsible earlier task with a new RED regression test.

- [ ] From the core worktree, run focused and full verification:

```bash
cargo test -p savana-kernel-protocol
cargo test -p savana-agentd
cargo test -p savana-approvald
cargo test -p savana-kerneld --test macos_deployment -- --nocapture
cargo test -p savana-kerneld --test deployment_units -- --nocapture
cargo test -p savana-kerneld --test v2_crash_matrix -- --nocapture
cargo clippy -p savana-kernel-protocol -p savana-agentd -p savana-approvald -p savana-kerneld --all-targets -- -D warnings
cargo fmt --all -- --check
git diff --check
```

- [ ] From the JARVIS worktree, run native, Python, and frontend verification:

```bash
cargo test --manifest-path native/savana_kernel_client/Cargo.toml
cargo clippy --manifest-path native/savana_kernel_client/Cargo.toml --all-targets -- -D warnings
.venv/bin/python -m pytest tests/test_control_plane.py tests/test_session_control.py tests/test_session_bootstrap_api.py tests/test_savana_api.py -q
env PATH=/opt/homebrew/opt/node@24/bin:/usr/bin:/bin /opt/homebrew/opt/node@24/bin/npm --prefix apps/web test
env PATH=/opt/homebrew/opt/node@24/bin:/usr/bin:/bin /opt/homebrew/opt/node@24/bin/npm --prefix apps/web run build
git diff --check
```

- [ ] Run negative source/surface audits. Review every match; allowed `navigator.credentials` matches must be confined to explicit compatibility relay/enrollment code and tests:

```bash
rg -n "navigator\.credentials|rpId.*localhost|durable_task_id|launcher_transfer|MacPlatform.*(Challenge|Signature|CredentialId)" crates/savana-kernel-protocol/src/v2/browser_assets.rs /Users/fz/Documents/jarvis/.worktrees/openclaw-approval-broker/server /Users/fz/Documents/jarvis/.worktrees/openclaw-approval-broker/apps/web/src
```

- [ ] With explicit install approval, build, validate, sign, and install both repositories together. Do not clear credentials/state:

```bash
owner_auth_build_dir=$(/usr/bin/mktemp -d /private/tmp/savana-owner-auth.XXXXXX)
SAVANA_NODE24_BIN=/opt/homebrew/opt/node@24/bin/node deploy/macos/development/build.sh "$owner_auth_build_dir" "/Users/fz/Documents/jarvis/.worktrees/openclaw-approval-broker"
deploy/macos/development/validate.sh "$owner_auth_build_dir"
deploy/macos/development/sign.sh "$owner_auth_build_dir"
sudo deploy/macos/development/install.sh "$owner_auth_build_dir"
```
- [ ] Verify services/listeners before opening UI: Agentd control socket, Approvald relay/platform sockets, user launcher socket, ports 8765-8768, and JARVIS 8770 must all have their expected signed owners.
- [ ] Run the existing crash/restart harness with a live claimed ceremony and prove service restart never reconstructs success: the public task/control outcome becomes indeterminate or protocol failure, while durable credential sequence/revocation state remains authoritative.
- [ ] Perform the real acceptance sequence on the active Mac:

```text
1. Open JARVIS and click Connect secure session.
2. Complete ingress authentication with Touch ID on this Mac; no QR/passkey prompt appears.
3. Enter one request and complete approval-display authentication with Touch ID.
4. Press Approve and complete the decision with Touch ID; confirm the task advances exactly once.
5. Start a fresh task, press Deny, complete Touch ID, and confirm the denial advances only that task.
6. Confirm JARVIS reaches the expected ready/denied states and the kernel audit records the real typed settlements/use-sequence advances.
7. Repeat once with Touch ID cancel and confirm fail-closed behavior with no fallback.
8. Exercise one competing-tab ambiguity and one expired ceremony; neither may launch or settle the wrong task.
```

- [ ] Capture exact command output and service/audit evidence. Do not call the bug fixed until at least one ingress decision completes on the real installed build.
- [ ] Inspect both repositories for accidental staging and secrets:

```bash
git status --short
git diff --cached --stat
git diff --cached
```

- [ ] If the crash assertion or acceptance document changed, commit only those test/document hunks after all checks pass:

```bash
git commit -m "test: record macOS owner authentication acceptance"
```

## Completion Criteria

- All three browser owner-authentication points use the Mac Secure Enclave path in macOS product mode: initial UI authentication, approval-display authentication, and approve/deny authentication.
- The browser never calls WebAuthn in macOS product mode and never receives native authentication secrets/capabilities.
- JARVIS begins with only the existing `TaskHandleV2`; the durable task ID remains inside authenticated Rust control/relay code and never crosses Python or HTTP.
- Approvald selects exactly one eligible ceremony by durable task, fails closed on ambiguity, and preserves claim idempotency/mutual exclusion.
- Linux explicit WebAuthn compatibility tests remain green.
- Full core, native JARVIS, Python, and frontend suites pass.
- A real installed macOS build completes an ingress decision with Touch ID and produces authenticated kernel evidence.
