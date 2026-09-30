# Managed request admission and Linux issuer (v0.4)

This batch connects the existing authenticated kernel tool-dispatch route to
first-party resource evidence issuance. It does **not** enroll every chat as a
managed task, create task permissions automatically, or deploy a Linux instance.

## Request path

1. Existing caller identity, task/root, intent, ticket, descriptor and current
   G3 execution-handoff gates still run first.
2. After connector synchronization and checked control endorsements, kerneld
   invokes `DurableG4StateV2::bind_managed_dispatch_input_v04` before G7 prepare.
3. For a newly admitted task enrolled in continuation dispatch, the helper decodes
   the exact existing task execution payload and checks its matched action. It
   resolves only the source/namespace pinned by that task's signed policy, then
   matches the exact immutable locator. Display labels, paths and incoming
   source/revision/signature fields cannot select trusted evidence.
4. The current source must permit `Utf8PayloadV1`; target, issuer, time window and
   object bytes must match. A tombstone or changed payload is refused. The kernel
   uses the independently provisioned issuer to sign the current source fact.
5. Existing G7 re-verifies that signed fact and object revision, then atomically
   commits the resource debit, task/quota state, original journal and snapshot.
   The pre-seal guard, HPKE, signature and execd checks remain unchanged.

The binder does not mutate state or charge. If data changes between binding and
G7, G7 fails without a partial debit. A fresh binding can accept a same-content
rename with the new revision; it does not mint a new object or reset consumption.
The post-G7 pre-seal guard still conservatively retains charges on its own refusal.

For an existing execution the binder does not issue a new fact, require the live
issuer key, or read current object bytes. Original G7 replay and the pre-seal guard
remain responsible for checking the exact stored dispatch and immutable snapshot.
This supports deletion/restart without reinterpreting current content as old input;
it does not restore expired, revoked or terminal execution authority.

Unenrolled tasks keep their existing path. Externally sourced continuation tasks
cannot silently use this first-party issuer: their independent source adapters
remain pending. The helper refuses already-attached facts rather than treating
caller material as evidence that the managed admission step ran.

## Linux-only, optional deployment configuration

The already manifest-verified kerneld bootstrap accepts an optional
`managed_resource_issuer` object with exactly `key_id` and `public_key` fields,
both canonical lowercase 32-byte hex strings. The ID must be the existing
protocol's derived Ed25519 key ID for that public key. The corresponding fixed
credential name is `managed-resource-v04.seed`; its content is exactly 32 bytes.
It uses the existing native credential reader and ownership/mode checks.

- Both configuration and credential absent: disabled, no fallback signer.
- Only one present, zero/mismatched key, or reused role material: startup fails.
- The signed source and dispatch policies must independently pin this public key.
- The issuer is checked on initial startup and deployment reload. Source policies
  remain immutable; this does not implement in-place issuer rotation.
- macOS may continue with this option absent; enabling it there is rejected.

`deploy/systemd/savana-kerneld-managed-resources-v04.conf` is an **uninstalled opt-in
drop-in**, not a change to the default service. An operator must provision its
encrypted credential and include the matching bootstrap in a properly signed
deployment. No credential was generated or installed by this implementation.
No secret is exposed through a status, chat, MCP or SDK endpoint. The signing key
and transient material use the existing zeroizing software-key pattern; this is
not evidence of TPM/HSM non-exportable signing or native platform acceptance.

## Tests and limits

Eleven owner tests cover successful automatic fact binding/G7/snapshot handoff,
missing/wrong keys, absent projection, injected signed facts, changed/deleted
objects, issue-to-G7 races and refresh, same-label confusion, malformed messages,
revocation/expiry, replay after encrypted reopen without reissuance, legacy ordinary
tasks, and external-source refusal. Two native issuer-constructor tests cover
disabled/missing/extra credentials, expected key/ID and purpose-key separation.
These use test credentials and the existing owner/G7 fixtures, not a live browser
to provider run. Linux CI includes the constructor tests; it has not been run here.

Still required for a turnkey chat product: authenticated source import/admin and
task enrollment UX, trusted private request construction (the binder verifies an
existing payload; it does not inject private source bytes into a model request),
provider effects/recovery, compiler/residual replacement, exclusive publication,
SDK/UI and native Linux deployment acceptance. Cloud/DeepSeek stay disabled.
