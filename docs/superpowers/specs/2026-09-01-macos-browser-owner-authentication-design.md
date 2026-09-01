# macOS Browser Owner Authentication Design

**Date:** 2026-09-01

**Status:** Approved for implementation

**Applies to:** Savana V2 macOS product and development deployments, the
Savana core repository, and the JARVIS macOS integration

## 1. Purpose

The macOS product currently enrolls a device-bound Secure Enclave credential,
but the initial browser ingress path still calls `navigator.credentials.get()`
with RP ID `localhost`. That asks Chrome or Safari for an unrelated browser
Passkey and may offer a phone QR code. A phone correctly reports that it has no
Passkey for `localhost` because the enrolled Savana key is not a WebAuthn
credential and is never synchronized off the Mac.

This design makes every owner-authentication ceremony in a browser-driven
kernel task use the existing Rust-only macOS platform relay and signed launcher.
It covers:

1. initial ingress UI authentication;
2. approval-display authentication for the ingress decision; and
3. the approve or deny decision authentication.

The browser continues to display kernel-owned ingress and approval pages. It
never receives a platform challenge, credential identifier, key tag, launcher
transfer, relay receipt, signature, public key, or platform-credential
capability. Python sees only the existing public task handle, public task state,
stable error code, and fixed one-time browser URL.

## 2. Security requirements

The implementation MUST preserve all of these properties:

1. macOS product mode never calls `navigator.credentials.get()` or
   `navigator.credentials.create()` for owner authentication or enrollment.
2. The Secure Enclave private key remains non-exportable and protected by
   `AccessibleWhenPasscodeSetThisDeviceOnly` and
   `privateKeyUsage AND biometryCurrentSet`.
3. Every use requires a fresh Touch ID decision. There is no authentication
   reuse window.
4. Approvald remains the only ceremony authority and signs or settles nothing
   until it verifies the exact Secure Enclave signature.
5. The signed, pinned JARVIS Rust control client is the only component allowed
   to claim a pending macOS browser ceremony from the `JarvisApprovalRelay`
   service edge.
6. The signed user launcher remains the only component that invokes
   Security.framework and the only process that receives the exact platform
   challenge.
7. Browser HTTP routes may arm and poll an existing UI ceremony, but cannot
   claim a platform ceremony, launch Touch ID, choose a credential, or submit a
   platform result.
8. A pending ceremony is selected by its kernel-owned `durable_task_id`, never
   by user text, URL input, Python-authored purpose, or a browser-supplied
   platform handle.
9. If zero or more than one matching live ceremony exists, the claim does not
   choose one. Zero returns a non-terminal `NonePending` result; ambiguity fails
   closed.
10. Password, Apple Watch, phone, remote-device, browser-Passkey, software-key,
    and legacy callback fallback are prohibited in macOS product mode.
11. Linux and an explicitly selected hardware-WebAuthn compatibility profile
    keep their existing behavior.
12. No new listening port or remotely reachable service is added.

## 3. Why the existing flow fails

The current browser script begins a UI ceremony at Approvald and immediately
passes the returned public-key options to `navigator.credentials.get()`. Those
options specify `rpId: "localhost"`. The macOS enrollment flow, however, uses
the native `TrustedPlatformCredentialRelay`; it creates a general P-256 Secure
Enclave key, not a browser credential registered under that RP ID.

Approvald can verify either a durable hardware-WebAuthn credential or a durable
macOS platform credential after settlement, but the browser finish route can
only construct a WebAuthn assertion. The presence of a platform credential in
durable state therefore cannot make a browser assertion succeed. Offering the
phone QR flow is a category error, not a missing synchronization step.

## 4. Selected architecture

### 4.1 Trusted profile selection

Approvald receives an immutable owner-authentication profile from its verified
deployment bootstrap:

```text
OwnerAuthenticationProfileV2 =
    MacPlatform
  | HardwareWebAuthnCompatibility
```

The macOS product and development manifests select `MacPlatform`. Linux or a
separately built compatibility deployment may select
`HardwareWebAuthnCompatibility`. There is no environment variable, HTTP
parameter, Python option, or runtime flag that changes this selection.

In `MacPlatform` mode, Approvald rejects the WebAuthn begin, finish, relay, and
enrollment browser routes before returning public-key options. In compatibility
mode, the new macOS platform browser routes are unavailable.

### 4.2 Browser ceremony surface

The existing browser pre-authentication transfer remains the entry to an
Approvald-owned UI record. macOS product pages use profile-specific routes that
do not return WebAuthn options:

```text
POST /v2/ui-auth/platform/begin
POST /v2/ui-auth/platform/status
POST /v2/approval/decision/platform/begin
POST /v2/approval/decision/platform/status
```

The authentication begin request contains the same existing
`pre_authentication` capability and client request nonce. The decision begin
request contains the existing approval tab, decision, and client request nonce.
The response contains only the existing typed browser ceremony capability and
its absolute expiry. It contains no challenge or credential-selection data.

The status request presents that browser ceremony capability and the matching
client request nonce. It returns one of:

```text
Pending
Completed(existing typed browser finish response)
Denied
Expired
CredentialInvalidated
Unavailable
Indeterminate
ProtocolFailure
```

`Completed` reuses the current finish response types. For ingress
authentication it carries the one-use transfer back to Ingressd. For approval
display it carries the approval tab. For a decision it carries only `Approved`
or `Denied`. These are already browser-visible outputs of the existing flow;
platform material is not added to them.

Status is idempotent for the exact ceremony and request nonce. A different
nonce for an existing ceremony fails as an idempotency conflict. Delivery does
not create or repeat a signature. Once the downstream one-use transfer is
consumed, downstream replay protection remains authoritative.

### 4.3 Task-bound native claim

The browser cannot invoke the platform relay. Instead, the existing JARVIS
session coordinator continues polling the public task. While Agentd reports an
owner-authentication waiting state, the coordinator calls a new safe method on
the signed Rust control extension:

```text
ControlClient.settle_pending_owner_authentication(task: TaskHandleV2)
    -> PendingOwnerAuthenticationPublicResultV2
```

Python supplies only the public task handle it already owns. It cannot select a
ceremony, purpose, credential, decision, challenge, or launcher operation.

The Rust control extension asks Agentd to resolve the task handle under the
same authenticated JARVIS control context. Agentd returns an internal bounded
projection containing:

```text
PendingOwnerAuthenticationTaskV2 {
    durable_task_id,
    public_state_revision,
    task_logical_expires_at
}
```

Agentd returns this projection only for the exact JARVIS principal and OS peer
that created the task and only while the task is in one of the existing
pre-effect owner-authentication states. It never exposes the projection through
the Python result dictionary.

The Rust extension then uses the already pinned `JarvisApprovalRelay` edge to
request:

```text
ClaimPendingMacPlatformCeremonyForTask {
    durable_task_id,
    client_request_nonce
}
```

Approvald searches its live UI and decision records for an unconsumed,
unexpired, platform-unclaimed ceremony whose signed binding contains that exact
`durable_task_id`. It may match an ingress UI authentication, approval-display
authentication, or approval decision. Approvald returns `NonePending` if no
browser ceremony has been armed yet and fails closed if more than one candidate
matches. It never guesses by creation order.

For one match, Approvald runs the existing mutually exclusive platform-claim
transition and returns the existing receipt, launcher transfer, and expiry over
the signed Rust relay edge. The browser and Python do not receive those values.

### 4.4 Existing launcher and Secure Enclave completion

The Rust control extension sends the one-use launcher transfer and absolute
expiry through the existing authenticated user-launcher socket. The launcher
continues to verify the pinned JARVIS peer, connect to Approvald's dedicated
platform socket, claim the exact authority-authored operation, and use the
Secure Enclave key.

No new launcher message format is introduced. The existing
`OPEN_MAC_PLATFORM_CREDENTIAL` operation is reused. Approvald verifies the
signature, advances the durable use sequence atomically with the settlement,
and stores the existing typed browser completion in the UI record. Browser
status polling can then return that completion.

### 4.5 Browser progression

The macOS product browser script follows this sequence:

```text
User clicks Authenticate / Show approval / Approve / Deny
  -> browser arms the typed platform ceremony at Approvald
  -> browser polls the matching status route
  -> JARVIS polls the public kernel task
  -> pinned Rust control extension resolves task -> durable_task_id
  -> Approvald claims the unique pending ceremony for that task
  -> signed launcher prompts for Touch ID
  -> Approvald verifies and commits the result
  -> browser status returns the existing typed completion
  -> browser continues to 8767, displays approval, or reports the decision
```

The browser status page uses code-owned text: `Waiting for Touch ID on this
Mac.` It contains no phone, QR, Passkey, security-key, password, or remote-device
instruction. Browser ceremony capabilities and request nonces remain in memory
only. A page refresh does not begin or recover a ceremony; the user must
explicitly cancel and restart the pre-effect task. The restart creates a new
task and does not reuse the abandoned or terminal ceremony.

## 5. Concurrency and replay rules

1. JARVIS keeps at most one native owner-authentication settlement in flight
   per `TaskHandleV2`.
2. Agentd resolves a task handle only for the authenticated creator context and
   exact current boot/deployment binding.
3. Approvald requires one exact live candidate for `durable_task_id`. Multiple
   browser tabs that create competing ceremonies cause an ambiguity failure;
   no Touch ID prompt is launched.
4. `client_request_nonce` makes the claim-by-task operation idempotent. An exact
   replay returns the same claim receipt. A different request under the same
   in-flight task conflicts.
5. Existing one-use launcher transfer, transaction, platform receipt, browser
   ceremony, settlement transfer, and approval decision rules remain in force.
6. If a response is lost after a platform claim, the Rust client first waits on
   the replayed receipt. Re-sending the consumed launcher transfer cannot cause
   another signature because the direct launcher claim is one-use.
7. Restart loses live ceremonies and reports `Indeterminate`; durable credential
   sequence and revocation state remain authoritative.

## 6. Failure semantics

The control extension and JARVIS backend expose only the existing stable
platform codes:

```text
PLATFORM_CREDENTIAL_DENIED
PLATFORM_CREDENTIAL_EXPIRED
PLATFORM_CREDENTIAL_INVALIDATED
PLATFORM_CREDENTIAL_UNAVAILABLE
PLATFORM_CREDENTIAL_INDETERMINATE
PLATFORM_CREDENTIAL_PROTOCOL
```

`NonePending` is not an error; it means the browser has not armed its next
ceremony, so normal task polling continues. Ambiguous candidates, binding
mismatches, cross-role requests, malformed responses, and unexpected terminal
types map to `PLATFORM_CREDENTIAL_PROTOCOL` without internal detail.

Touch ID cancellation produces `Denied` and does not revoke the credential. A
`biometryCurrentSet` invalidation durably revokes the credential and requires a
new root-minted enrollment. `Unavailable` and `Indeterminate` never fall back.
After any terminal failure the current ceremony is not retried; the user may
explicitly cancel and restart the entire pre-effect task.

Browser and HTTP errors contain code-owned text only. Logs may include the
stable code, task correlation digest, component, and state transition. Logs
must not include the task handle, browser ceremony capability, pre-authentication
capability, approval tab, platform claim, receipt, launcher transfer,
transaction, credential ID, key tag, challenge, signature, public key, or
enrollment values.

## 7. Component changes

### 7.1 Savana core repository

- `savana-kernel-protocol` adds the owner-authentication profile, task-bound
  claim request/response, platform browser begin/status values, fixed routes,
  and canonical CBOR codecs.
- `savana-agentd` resolves a public task handle to the internal bounded pending
  owner-authentication projection under the existing authenticated control
  context.
- `savana-approvald` enforces the deployment profile, implements unique
  task-bound pending ceremony selection, and exposes platform begin/status
  browser routes without platform material.
- `savana-kernel-protocol` browser assets branch only on the server-rendered
  trusted profile and remove WebAuthn calls and Passkey copy from macOS product
  pages.
- macOS deployment generation pins `MacPlatform`; compatibility deployments
  pin `HardwareWebAuthnCompatibility` explicitly.
- deployment validation proves that macOS product material does not require a
  fake WebAuthn attestation root and that the WebAuthn browser routes reject in
  product mode.

### 7.2 JARVIS repository

- `_savana_kernel_client.ControlClient` gains the task-only
  `settle_pending_owner_authentication` method. All Agentd and Approvald
  protocol values remain inside Rust.
- the Rust control client reuses the existing approval relay deployment
  material and existing signed launcher socket operation.
- `TrustedSessionBootstrapCoordinator.continue_session` invokes the task-only
  native settlement method while the public task remains in an owner-auth
  waiting state, then continues its existing polling behavior.
- the Python adapter maps only stable public results and never accepts a
  ceremony, purpose, decision, platform token, or credential parameter.
- `SavanaConnect` continues polling and displays native Touch ID lifecycle copy;
  it no longer offers or launches a WebAuthn relay for a macOS product task.

## 8. Compatibility and rollout

This change does not alter the public fifteen-method client SDK inventory. It
adds an internal JARVIS control operation, not a general Python SDK method.
OpenClaw and MCP callers cannot invoke it because it requires an owner-bound
pending task in the trusted session coordinator and accepts no connector or
model-authored input.

Existing native Secure Enclave credentials remain valid because their key tags,
public records, signature challenges, and use-sequence rules are unchanged.
No re-enrollment is required solely for this browser-flow fix. A deployment
that still contains only a hardware-WebAuthn credential must explicitly select
the compatibility profile or revoke and re-enroll for the macOS platform
profile; there is no silent migration.

The rollout is fail-closed. Core protocol and JARVIS native extension versions
must be installed together. A profile, ABI, manifest, route, or operation
mismatch prevents service readiness rather than falling back to WebAuthn.

## 9. Testing and acceptance

Implementation is accepted only after all of the following pass:

1. Canonical CBOR round trips and malformed, trailing, cross-kind, and
   re-encoded rejection for every new protocol value.
2. Agentd tests proving a task projection is returned only to its exact
   authenticated creator, only in allowed pre-effect states, and never through
   the public Python projection.
3. Approvald tests proving exact `durable_task_id` matching, zero-candidate
   `NonePending`, ambiguity rejection, expiry rejection, claim-mode mutual
   exclusion, exact nonce replay, and cross-role rejection.
4. Browser tests proving macOS product pages contain no
   `navigator.credentials.get`, `navigator.credentials.create`, Passkey,
   security-key, phone, QR, password, or remote-device path and never receive
   WebAuthn public-key options.
5. Compatibility tests proving the explicitly selected hardware-WebAuthn
   profile retains its existing browser behavior and cannot call the macOS
   platform status routes.
6. JARVIS Rust tests proving the public method accepts only a task handle,
   never projects internal task binding or platform values into Python, keeps
   one in-flight operation per task, and uses the existing launcher message.
7. Coordinator tests for no pending ceremony, successful ingress
   authentication, approval-display authentication, approve, deny, cancellation,
   expiry, invalidation, unavailable, indeterminate, ambiguity, and task
   restart.
8. Full core and JARVIS unit/integration suites, formatting, linting, macOS
   deployment validation, signing validation, and manifest validation.
9. A real Mac acceptance run that:
   - enrolls the device with Touch ID;
   - connects a new session without a browser Passkey or QR prompt;
   - authenticates the ingress page with Touch ID;
   - submits input;
   - authenticates the approval display with Touch ID;
   - approves once with Touch ID and denies once with Touch ID;
   - confirms every prompt advances the exact task and use sequence;
   - confirms replay, a competing tab, and an expired ceremony fail closed;
   - confirms no browser, Python, HTTP, OpenClaw, MCP, or log surface contains
     platform material.

The macOS product is not considered fixed until this real acceptance run
reaches an active JARVIS kernel session and completes one ingress decision.
