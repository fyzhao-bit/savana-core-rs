# Linux cross-UID identity broker

This adds a small privileged measurement component to the Linux TCB. It is not
a task-authority service, native signing adapter, monotonic anchor or proof that
the whole product can start. Existing V2 expected-role/UID/GID/executable checks,
Suite-1 authentication and G1–G7 remain mandatory after measurement.

## Why a separate component

The earlier AWS diagnostic confirmed that a low-privilege service cannot read
another UID's `/proc/PID/exe`; `ProtectProc=invisible` also hides that PID. Holding
a pidfd does not grant access. Ordinary Savana services retain separate UIDs,
empty capability sets and `ProtectProc=invisible`. They do not gain ptrace rights.

The new broker has only `CAP_SYS_PTRACE` in its capability bounding set so that
its code can open the peer's executable. This is a real TCB expansion, not a
claim that Linux somehow provides unprivileged cross-UID measurement. A broker
compromise is outside the protected threat model, just like a compromised
trusted kernel/installer. Its syscall filter excludes tracing/debug syscalls,
it has no credentials or state directory, cannot bind sockets or use IP, and
cannot access Savana vault/credential paths. These restrictions reduce exposure;
they do not make a compromised privileged broker harmless.

## Request and response binding

1. Non-root callers with a different-UID peer connect to the fixed root-owned
   `/run/savana-identity/measurement-v2.sock`. A full accept queue fails closed;
   connect is nonblocking. Same-UID/self measurement remains direct. Root tools
   retain their existing direct measurement path, without a broker exception.
2. The caller checks the root-owned, non-writable directory chain, socket owner
   and the broker connection's kernel credentials (`uid=0,gid=0`). No environment
   variable or caller-selected endpoint can redirect this connection.
3. The request consists only of a fixed four-byte version marker and **one
   already-connected Unix stream descriptor**, transferred by SCM_RIGHTS. It
   contains no selectable PID, path, executable digest, role or task data.
4. The broker obtains the requester's real socket credentials, pins/measures its
   executable and checks its exact root-installed allowlist entry. It obtains
   the target from SO_PEERCRED on the transferred socket, checks the directional
   edge, then pins/measures that process. It never reads/writes the subject socket.
5. The broker returns one fixed-size measurement plus the pinned executable FD.
   The caller independently checks the tuple against its original SO_PEERCRED,
   checks root-owned immutable executable metadata, hashes the FD, and rechecks
   its own pidfd obtained from **SO_PEERPIDFD**, not `pidfd_open` on an unbound
   numeric PID. The broker also uses SO_PEERPIDFD for requester and target.
   Original-process liveness is checked across `/proc` measurement, so process
   exit/PID reuse cannot substitute a new process. The returned object holds pidfd/executable
   leases. No open-by-path substitution is accepted in the response.

Missing policy, broker, edge, wrong code hash, wrong UID/GID, exited peer,
malformed descriptor transfer or timeout rejects the measurement. Failures return
no partial measurement. There is no caller-asserted digest or common-UID fallback.
The root-owned executable must be single-link, executable, non-set-ID, not
group/world writable, and no larger than 256 MiB. Descriptor transfers are
CLOEXEC and owned/closed by rustix, including truncated/extra-descriptor failures.
Each fixed frame has a three-second absolute IO deadline; partial input cannot
renew it. Executable IO still depends on the trusted local filesystem/OS.
SO_PEERPIDFD is a Linux 6.5+ requirement (or an equivalent backport). Unsupported
kernels fail closed, without the old numeric-PID fallback. See the
[kernel patch and ABI](https://lists.openwall.net/linux-kernel/2023/04/13/833).

## Provisioning contract

Install the built `savana-linux-identity-broker` at
`/usr/libexec/savana/savana-linux-identity-broker`, root:root 0755, and include its
artifact hash and these units in the reviewed deployment closure. Install:

- `savana-identity-broker-v2.socket` and `.service`;
- a root-controlled `savana-identity` connection group;
- `savana-identity-broker-client-v2.conf` as a service drop-in only for the measured
  clients that actually need measurement; do not add arbitrary users;
- `/etc/savana/identity-broker-v2.json`, root:root, single-link, not writable by
  group/others, with at most 64 exact directional edges.

The policy has `version: 2` and an `edges` array. Every edge contains `caller`
and `peer`, each with numeric `uid`, numeric primary `gid`, and
`executable_sha256` as exactly 32 JSON byte integers. Unknown fields, duplicate
edges, empty policies and zero hashes fail. Caller UID/GID must be nonzero.
A root:root **peer** is permitted only by an explicit pinned entry, for the
existing measured approval administrator; root is not a wildcard identity.
Policy is read only at startup; an authorized replacement requires a restart.
The downstream signed deployment role check is still authoritative.

No permissive example policy is supplied. The release/deployment builder must
derive exact tuples from the installed artifacts/accounts, not model output.
This change does not automatically install a group/unit/policy on an existing
host, silently upgrade signed releases, or grant `PlatformComplete`.

## Verification and remaining acceptance

Linux Rust 1.82 offline checks exercise descriptor transfer/ownership, directional
allowlists, hash/UID/GID mismatches, input size/shape rejection, absolute frame
deadlines and the original worker sandbox. The deployment-unit regression checks
the broker separately while keeping **all five ordinary services' original
hardening requirements unchanged**.

`tools/linux_identity_broker_acceptance.py --disposable-container` is a separate
root-only synthetic integration harness. It refuses a non-Docker context or a
missing `/run/savana-broker-test-only` marker and refuses existing test targets.
Run only with network disabled, repository/build mounted read-only, and fresh
tmpfs mounts for `/run` (0755), `/etc/savana` (0755), `/usr/libexec/savana`
(0755, executable) and `/tmp`. It creates two non-root UIDs, copies only built
test executables, and simulates systemd's inherited FD contract.

The orchestrator needs SYS_PTRACE, SETUID, SETGID, CHOWN, FSETID, KILL and SETPCAP
inside that disposable container. Before exec it reduces the broker's bounding
set to SYS_PTRACE alone. The broker itself verifies effective/permitted/bounding
sets are exactly this bit, ambient/inheritable are zero and NoNewPrivs is set.
Ordinary test processes drop privileges. Orchestrator privileges are **not** the
production broker service profile.
The initial container attempts failed on noexec tmpfs, missing synthetic-group
setup/cleanup capabilities and world-writable mount roots; the harness was
corrected to meet production checks, not by relaxing the checks.

Successful and denied scenarios include an absent broker, a permitted cross-UID
peer, wrong caller/peer hashes, an unlisted caller UID, an explicit pinned root
administrator, and no fallback after broker shutdown. These are actual process
tests, not a mocked broker. They are still **not** native systemd/ProtectProc
mount-namespace acceptance, x86_64 release acceptance or hardware-key acceptance.
The `identity-broker-processes` CI job builds both executables in the same Debian
userspace and runs this harness with networking disabled and read-only source
and build mounts. The build step alone may download locked dependencies. CI is
configured here; this local batch does not claim a completed remote CI run.
The temporary AWS machine from the previous run remains deleted. No new source
upload, AWS resource or paid model call is part of this implementation batch.
