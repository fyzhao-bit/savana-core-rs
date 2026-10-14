# Experiment transport and task-authoring wiring — 2026-09-25

This is implementation and regression evidence, **not a protected AgentDojo
score, full v0.4 acceptance, production TPM acceptance, or a live upgrade**.
The previous running deployment and its state were not replaced or deleted.

## Changes

- Model worker: adopt the actual Rust Unix mTLS transport instead of binding a
  TCP listener. Accept only a matching inherited AF_UNIX/SOCK_STREAM listener,
  with SO_ACCEPTCONN and protected path ownership/ancestors. Duplicate the FD;
  never unlink/rebind the service manager's socket. Per-connection TLS chain,
  client pin, ALPN, bounded canonical view and deadline checks remain.
- Provider and publication: separate loopback TLS endpoints, client pins,
  private keys, exact URLs and lifecycle cleanup. Schema 2 refuses ambiguous
  schema 1 configuration; no TCP model fallback.
- Optional fresh B deployment profile: independent managed-admin trust/key,
  narrowly loaded kernel model client credential, root-owned admin socket and
  separately encrypted experiment server credentials. Default profile unchanged.
- Optional systemd experiment service/socket and closed Python launcher. The
  launcher checks exact activation metadata, root-owned authentication-broker
  path/peer, unprivileged identity and closed credential paths. No auto-restart,
  exported secret environment value, root operator key or kernel-state access.
  Real broker, episode bindings and API key remain prerequisites.
- Native SDK context: owner-only `private_binding_json()` exports already
  verified task metadata. `final_result_resource()` reuses the Rust selector
  codec and refuses a descriptor absent from the authenticated context. Neither
  method issues authority or changes the context wire format.
- Python task authoring: reviewed clauses are generated from clean catalog
  contracts plus actual registered metadata; the root digest comes only from
  the native receipt returned by explicit approval. Existing roots/pending
  issuance require recovery rather than silent reset. The resulting planning
  command is unsigned and canonicalized by the native SDK, not submitted by a
  model or disguised as successful admission.

## Local verification

Built a fresh isolated macOS SDK without replacing the frontend environment.

```text
pytest deploy/linux/integration/test_assemble.py experiments/tests \
  crates/savana-core-py/tests/test_owner_ingress.py -q
185 passed, 10 skipped, 29 subtests passed

cargo test --offline --locked -p savana-kernel-protocol --test task_context
3 passed
```

Tests used fresh synthetic templates. Mac skips Linux listener checks; other
optional integration skips were not counted as passes. Existing Python
deprecation warnings remain. An imported `test_command` utility was renamed
locally in the test module to prevent pytest treating it as a fixture-based test.
No paid model request or user authentication occurred.

Fourteen Linux ARM64 B artifacts and the CPython 3.12+ ABI extension were rebuilt
offline. Build-source snapshots matched before packaging. Explicit allowlist:
113 files, 32,762,961-byte archive; no credentials, personal data or prior state.

```text
SHA-256 d9c4f75b99ce768367d48566d8d4c367b708cca8d77e4a6c92b52b22cd75de88
bucket  savana-protected-20260924-wlqdul-377521353256
object  artifacts/experiment-wiring-20260925.tgz
```

S3 returned AES256 encryption and lifecycle expiry 2026-09-27 00:00 UTC. No new
instance, public inbound rule, GPU, model service or extended lifetime was added.

## AWS verification

Existing authorized host: `i-071646e066afc6302`, region `ap-southeast-1`.
SSM command `8e1de041-1ed9-4ecf-99cb-a2cab0b6120a` completed **Success / exit 0**.

- Candidate binaries/code: `/opt/savana-experiment-wiring-20260925`.
- Fresh target-generated synthetic keys/configuration:
  `/root/savana-experiment-wiring-20260925/stage` (root-only).
- Archive SHA-256 verified before extraction.
- Assembly and credential coverage checks passed:

```json
{"candidate_only":true,"live_state_changed":false,
 "managed_admin_configured":true,"fused_model_workers":1,
 "model_transport":"unix-mtls","separate_provider_identities":true,
 "episode_bindings":0}
```

The candidate Python suite ran as the isolated `savana-experiment` account with
read-only deployment sources, no capabilities, no home/device access and network
restricted to localhost. **37 tests passed in 4.822 seconds**. This included the
real Linux inherited-listener checks, mutual TLS, malformed/wrong-client/wrong-
target rejection, nonce/audit behavior, official oracle adapters and native SDK
parsing of authored commands. Fixture approval tests do not establish real
passkey authentication or live planning admission.

`systemd-analyze verify` accepted the new service/socket. It emitted only an
unrelated distribution `acpid.socket` legacy `/var/run` warning. The still-running
old deployment's owner health returned `{"state":"ready"}`; the expiry timer
remained active. The scheduled termination remains 2026-09-25 05:23:52 UTC.

Local raw operational receipt:
`/private/tmp/savana-protected-aws.wlqDuL/result-8e1de041-1ed9-4ecf-99cb-a2cab0b6120a.json`.
Build receipts and upload inventory:
`/private/tmp/savana-experiment-wiring.W9eJd0`.

## Remaining execution boundary

The candidate is staged, not activated. Signed task/descriptor/G3 provisioning,
owned private-input intake/pinning, exact execution-recipe approval and runtime
episode binding must still be composed with the authenticated owner path.
`protected_setup` prepares the command after actual root approval but does not
pretend the unsigned private input slots are owned/provenanced kernel values.
The new service does not implement a real browser/passkey broker by itself.

No enrollment or API key was requested during this iteration. No formal
AgentDojo episode ran: **0 model calls and 0 protected scores**. The current
finite single-read runner is not an adaptive tool-output planning benchmark.
