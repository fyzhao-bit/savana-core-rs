# Linux measured owner task entry — 2026-09-24

Status: implemented and tested locally, **not installed on the existing AWS
deployment**, not an authenticated frontend/private-session acceptance result.
Existing passkey enrollment and kernel state were not modified by this work.

## Closed interface

`savana-ownerctl` is a native, non-root Linux executable with only two commands:

- `health`: return the agent service's public state.
- `prepare-ingress`: ask Agentd for a new owner-input task entry, returning a
  one-use Ingress URL. This creates neither a signed task root nor user consent.

There is no credential registration, approval, arbitrary socket/envelope,
task-status, execution or cloud/model command. Output explicitly retains
`authenticated=false` and `task_authorized=false`. It must travel over a private
pipe, not a journal, model transcript or MCP response. A timeout has an unknown
outcome; callers must not automatically retry task creation.

The executable loads the fixed root-owned Agentd configuration and verifies
its exact bytes against the signed filesystem deployment. It requires its own
fixed installed path, non-root role UID/GID and enrolled executable digest.
Only two boot-ID credentials are provided; it receives no signing key, encrypted
state key or direct private-state access. A successful response must bind the
request ID, server boot and identity, active state manifest and generation.
Frames are canonical CBOR and bounded to 1 MiB.

## Socket activation and actual peer identity

Linux `SO_PEERCRED` on a systemd-created listening socket describes its creator,
not necessarily the process which later accepts the connection. Measuring that
initial connection as if it identified Agentd would reject a real installation.

The new client therefore uses a bounded reverse rendezvous:

1. Agentd authenticates and pins the connecting Ownerctl process as before.
2. Ownerctl sends only `SOC2` and a fresh 32-byte nonce. It has not sent a control
   envelope. The nonce selects a fixed-prefix ephemeral abstract Unix address,
   not a caller-selected filesystem path or network destination.
3. Agentd connects back, then measures the listener owner against the **original
   accepted** PID, start time, UID/GID and executable identity. Its PIDFD pin is
   retained. A saturated reverse listener fails closed rather than blocking
   indefinitely in `connect`.
4. Ownerctl measures the actual connecting Agentd process against the verified
   deployment's role and executable digest. Only then does it send the request.
   Both processes retain their measurement pins throughout the exchange.

The preface cannot be a valid existing bounded frame length. Legacy framed
clients remain supported; the new Ownerctl never falls back to an unmeasured
direct connection. The rendezvous rejects zero/reused addresses and expired or
unbounded deadlines, times out when no peer arrives, and leaves no socket file.

## Installation boundaries

The integration build exports the native client. Fresh-host assembly/installation
must explicitly select `--owner-control`; the default remains disabled. Enabled
assembly binds the exact ELF digest into Agentd configuration and adds only the
two directional Ownerctl/Agentd measurement-broker edges. Python itself is not
enrolled as a trusted native peer.

The root-only administration wrapper provides `owner-health` and
`prepare-ingress`. It starts a fixed transient unit as `savana-jarvis`, with
AF_UNIX-only access, no capabilities, strict filesystem protection, no core dumps
and the two encrypted boot-ID credentials. Its output uses a private pipe.
An opted-in installation must verify `owner-health` returns exactly the Ready
projection; the installation check never prepares a task or performs consent.

This is still the lower-assurance, file-backed **B integration** profile, not
TPM-backed or production acceptance. The fresh installer deliberately refuses
existing deployments. Re-running it on the enrolled AWS host is not an upgrade.
The new Agentd executable and configuration change signed measurements; a
state-preserving signed upgrade is required before live use. Simply copying a
binary, editing the manifest, or regenerating credentials is not supported.

## Evidence and remaining work

Offline ARM64 Linux checks passed:

- All 120 Agentd library regression tests.
- Four Ownerctl framing, closed-command, response-binding and URL-projection
  tests.
- Six reverse-transport test entries, including one child-process harness. The
  inherited-listener test actually spawns a separate process and demonstrates
  that the initial peer is the listener creator while the reverse peer is the
  child acceptor. This is not a live systemd service test.
- Three closed Linux credential-reader unit tests.

Thirty-three Python build/assembly/administration checks passed. Assembly uses
synthetic, non-executable ELF-looking fixtures: these tests are not native
installation evidence. The four framing/projection tests also pass on macOS;
the executable intentionally refuses runtime use there.

Still required for the live frontend: preservation/verification of the existing
deployment state during upgrade; interactive WebAuthn and protected approval
handoff; trusted owner/conversation binding; and the signed synthetic-text-only,
no-tools/no-cloud private-planning profile. The private frontend remains guarded.
This component does not imply that any of those remaining gates has passed.
