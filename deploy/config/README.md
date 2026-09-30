# Production bootstrap inputs

These files document the fixed Linux deployment shape. They are templates, not
accepted production credentials: every `REPLACE_WITH_*` value must be produced
by the signed release/deployment builder, and the numeric UID/GID values must
equal the installed system accounts.

Install the deployment manifest root as:

```text
/etc/savana/trust/deployment-manifest-root-v2.json
```

It must be root-owned, single-link, mode `0444`, and contain the exact key ID
derived from its Ed25519 public key.

Copy the five entries from `service-observations-v2.example.json`, without
changing their order, into the `services` member of every daemon bootstrap.
The process UID/GID is deliberately separate from artifact ownership:
executables, bootstraps, systemd units, public keys, and sandbox profiles are
root-owned immutable files, while each daemon runs as its dedicated non-root
account.

The endpoint union is closed:

- `unix-socket` requires an absolute live `SOCK_STREAM` path, owner equal to
  the service UID, a non-root role group, and mode `0660`;
- `loopback-tcp` accepts only the compiled primary ports: agentd `8765`,
  ingressd `8767`, and approvald `8766`.

Every inherited listener is rechecked again by the owning daemon before
readiness. Kerneld verifies both role-separated UDS listeners from their edge
locks; approvald verifies its agent and ingress UDS listeners against the
corresponding client service groups and its admin listener as root-only.
The opt-in `kernel_approval` blocks add a fifth Approvald descriptor for Kerneld
only, together with a separate client signing credential and exact native peer
verification. See the [Linux private approval wiring contract](../../docs/verification/kernel-approval-linux-v04.md).

Systemd encrypted credentials currently support integration deployment only.
They do not satisfy the production claim for non-exportable signing,
decryption, or rollback authority. Do not turn the templates into a
`PlatformComplete` claim until the selected TPM/HSM/PKCS#11 adapter and
hardware monotonic rollback anchor pass native server tests. Release builds
therefore reject this filesystem startup adapter with
`MissingPlatformAuthority` before taking listener ownership; use a debug
integration build with the explicit
`savana-policy-core/filesystem-integration-authority` Cargo feature only for
local/server UI wiring tests. A normal debug build also rejects this adapter.

The [Linux file-backed integration authoring tool](../../docs/verification/linux-file-backed-integration.md)
can sign measured Linux service/edge locks for that explicit debug profile.
It does not yet provision a complete installation, and a signed manifest alone
does not pass the separate signed-ledger startup check.

## Native Linux worker sandbox

Cross-UID process measurements now require the separate, fixed-path native
identity broker and its exact directional executable allowlist. Ordinary service
capability sets and `ProtectProc` are unchanged. This is an additional privileged
TCB component, not a native hardware authority. See
[the broker provisioning and acceptance contract](../../docs/verification/linux-identity-broker-v2.md).

## Worker execution

Install the `savana-worker-sandbox` binary from `savana-platform-identity` as
the measured sandbox program used by ingressd and execd. The three profiles
under `deploy/sandbox` are schema examples; the release builder must replace
their artifact paths, sign their digests into the active deployment, and
install them as root-owned, single-link, non-writable files.

The wrapper has no direct-worker fallback. Before `execve` it closes every
descriptor except stdin/stdout/stderr, sets no-new-privileges and bounded
rlimits, installs a Landlock deny-by-default filesystem policy, and installs
a seccomp filter that rejects network creation/use, namespace, mount, kernel
keyring, BPF, tracing, cross-process memory, and other escape syscalls.
Unsupported kernels fail before the worker runs.
