# Linux TPM authority V3: runtime connection, not release acceptance

Status: implemented 2026-09-20. The V3 suite is connected to an isolated service
and Linux Vault, Agent-authority, G4 and Connector state-anchor consumers.
**The old deployment ledger/installer still uses V2 Ed25519, and its native
bootstrap gate remains closed.** There is no full product/hardware acceptance or
automatic enrollment/migration claim. Cloud models remain placeholders.

## Authority and interfaces

| Component | Allowed | Not allowed |
| --- | --- | --- |
| Offline installer | Sign an explicit first-install enrollment with an external Ed25519 trust root | Trust a root embedded in the proposed enrollment |
| TPM authority | Access the fixed TPM device, PCR signing key, enrollment guard and five NV heads | Accept generic TPM commands or caller-selected paths/handles/algorithms |
| Measured root deployer | Request the 13 V3 deployment signature purposes; access deployment head | Modify runtime private-state heads |
| Measured non-root kerneld | Read/advance Vault, Agent, G4 and Connector heads | Receive auth secrets, access TPM devices or request generic deployment signatures |
| Agent/model/Python host | Existing business APIs | Private TPM endpoint access |

`LinuxTpmAuthorityClientV3` exposes `sign`, `current_head`, and
`compare_and_advance`. These are internal native interfaces, not new public HTTP,
Python or MCP tools. The existing Rust state-owner traits adapt through
`crates/savana-kerneld/src/tpm_anchor_v3.rs`.

The fixed socket `/run/savana-tpm/authority-v3.sock` is root:savana-kernel 0660.
Both ends verify actual socket peer identity, a socket-derived pidfd and executable
measurement against signed roles. Kernel clients use the restricted identity
broker for cross-UID measurement; its policy needs an explicit kerneld-to-TPM-
broker edge. Group membership alone grants no operation. Both root brokers are TCB.

One fixed 256-byte request per connection binds operation, closed store slot,
enrollment digest, installation, epoch, store ID and a fresh nonce. Replies are
248 bytes and echo operation/enrollment/nonce. Unused fields must be zero. Unknown
operations, purposes, trailing bytes and role crossover are rejected. Errors close
the connection without logging request contents. Lost/malformed responses poison
the client, and mutation requests are never automatically replayed.

## Signed enrollment and boot policy

`TpmEnrollmentProposalV3` assembles public bytes; it grants no authority.
`signature_input()` is the domain-separated SHA256 input for the external installer
signature. `TpmEnrollmentV3::verify()` checks that signature with an external root,
canonical bounded encoding, validity interval, installation/epoch, PCR-only key,
Name/qualified Name, five distinct store IDs and measured client roles. Parsing
a public area and verifying installer authorization are not hardware attestation.

The production key is sign-only P-256/ECDSA-SHA256 with exact attributes
`0x000400b2`: fixedTPM, fixedParent, sensitiveDataOrigin, adminWithPolicy, sign.
userWithAuth is clear: even the correct password cannot bypass the policy. Its
32-byte authPolicy commits to PolicyPCR, PolicyCommandCode(Sign), PolicyPassword.
PolicyPassword extends the PolicyAuthValue code, per the TPM reference code.
SHA256 PCR selection is restricted to static PCR0..7 and must include PCR7.
The expected digest hashes selected PCR values in ascending order.

Each signature uses a fresh policy session. The TPM checks PCRs and their update
counter when the session authorizes Sign. The emulator test changes PCR7 after
policy evaluation but before Sign and requires rejection. The old password-only
public template remains verification/fixture compatibility; native open rejects
it. There is no runtime fallback. Host OS/device namespace and enrollment policy
remain trusted; this unsalted PolicyPassword profile does not protect against
physical bus interception. Secure Boot/event-log/measurement selection and genuine
TPM provenance must be validated during native enrollment.

A separate fixed NV index `0x01500010` pins
`SHA256(previous_enrollment_root || signed_enrollment_payload_digest)`.
Runtime can only check this guard, never update it. Every operation also proves
possession of the pinned PCR-gated key using a fresh challenge. Changed key/TPM,
expired enrollment or changed guard prevents service. PCR enforcement is atomic
with Sign, **not** with a subsequent NV write; no atomic PCR+NV transaction is claimed.

**First installation only:** previous enrollment root must be zero and all initial
state heads GENESIS. No silent old-state import, renewal, key/epoch migration or
reset-to-zero operation exists. These require a separate continuity protocol.
Do not clear an existing TPM or delete old state to work around this restriction.

## Whole-head NV commit and recovery

Indices `0x01500020..0x01500024` serve deployment, Vault, Agent, G4, Connector.
Each is an initialized SHA256 extend index, 32 bytes, exact attributes `0x20040044`
(AUTHREAD, AUTHWRITE, EXTEND, WRITTEN). Owner/policy writes, ORDERLY,
CLEAR_STCLEAR and write-lock flags are rejected. Runtime never defines, clears,
recreates or initializes indices. Each initial nonzero root comes from enrollment.

The event hash binds installation, store, epoch, NV Name, sequence and full state
digest. Next root is `SHA256(previous_root || event_hash)`. Commit:

1. Read/check NV public area and current root; require the full expected head.
2. Require exactly one sequence increment (checked overflow).
3. Write the inactive 108-byte journal slot, fsync, rename, fsync parent directory.
4. Execute NV_Extend once; read back the expected root before acknowledgment.

The encrypted state owner prepares its state before this anchor advances. Journal
records contain head digests, not private application records. At reopen, the
actual TPM root selects a matching journal record by recomputing its event and
extension hash. An uncommitted prepared record is not auto-committed. A TPM commit
with a lost reply recovers the new head. Old slots, tampering, same-sequence digest
substitution, wrong namespace/epoch, missing committed records and exhaustion fail
closed. A changed TPM root never silently becomes GENESIS.

This is not hardware CAS: a root-owned lifetime flock serializes the exclusive
writer per index. Journals use fixed `/var/lib/savana/tpm-v3`, descriptor-relative
no-follow IO, single-link regular files and mode 0600. Trusted Linux fsync/storage
semantics and TPM persistence are assumptions. Root/owner-hierarchy compromise,
physical attacks and denial of service are outside this profile.

## Native wiring and deployment material

Linux `v2_startup.rs` now requires TPM-backed anchors for all four runtime stores;
no Linux file-MAC fallback exists. macOS and explicit test fixtures retain their
old code. Verified startup installation/store IDs must match the signed profile.
The existing V2 native deployment bootstrap remains unavailable, so this wiring
does not alone produce a running product.

Install `savana-tpm-authority-v3.service`, its socket, and
`savana-kerneld-tpm-v3.conf` as a kerneld drop-in. Only the authority has
`DeviceAllow=/dev/tpmrm0 rw`; `/dev/tpm0` and ordinary private stores are inaccessible.
Kerneld stays device-isolated and receives only public `tpm-installer-v3.pub` and
`tpm-enrollment-v3.bin` credentials. Repository edits do not install these units.

The authority requires root:root 0600 `/etc/savana/tpm-v3-installer.pub` (32 bytes)
and `/etc/savana/tpm-enrollment-v3.bin` (at most 2048 bytes). Seven independently
generated nonzero 32-byte secret credentials belong only to it: signing-auth,
enrollment-auth, deployment-auth, vault-auth, agent-auth, g4-auth, connector-auth.
They come from the fixed systemd credential directory, not CLI values or an
environment-selected path. Keep encrypted source credentials root-only.

The kerneld credential reader now accepts systemd's exact root-owned per-UID
read ACL, or service ownership only on a read-only mount. Arbitrary named users,
group/world access, write permissions, symlinks, extra links and oversized data
are rejected; the prior hardcoded root/0400 assumption is removed on Linux.

## Evidence and remaining work

Tests cover signed enrollment/time/roles, canonical frames, PCR bypass/races,
whole-head recovery failures, strict ACL parsing and unit permissions. swtpm runs
the actual TPM protocol for signing, NV_Extend, lost-response reopen and old-slot
rejection. Its socket transport is cfg(test) only, not a production option.

Final local evidence (2026-09-20): Linux identity all-targets **58 passed** with
the one emulator case reported ignored in the ordinary suite; the exact emulator
case was then run separately and **passed**. Linux kerneld library **390 passed**,
unit-file contracts **7 passed**, V2 signing compatibility **5 passed**, macOS
identity library **39 passed**, and Python experiment suite **28 passed**.
Scoped macOS Clippy and Linux kerneld/Python-extension compilation passed. Existing
unrelated dead-code warnings remain in the kernel/execd compilation; Linux Clippy
was not run because that offline image lacks the component. The frozen source
inventory verifies **297 files**. No native systemd or real TPM acceptance is
included in these counts.

Still required:

- Full V3 deployment semantics and installer/watchdog migration. The separate
  [V3 record/journal layer](deployment-records-v3.md) now covers authenticated
  encoding, immutable history archival/replay, ledger semantics and two typed
  verification/commit consumers bound to the ledger chain; the remaining
  purpose-specific consumers and complete native deployment driver are open.
  The V2 native authority constructor and existing final `run_apply` transition
  remain fail-closed. A new signing API does not convert their Ed25519 fields.
- Hardware evidence and continuity-preserving renewal/epoch migration. A closed
  [native first-install adapter](tpm-first-install-v3.md) now provisions fresh
  fixed objects and activates externally approved enrollment; software-TPM tests
  pass, but native hardware/systemd acceptance has not run. The separate
  [offline authoring tool](tpm-enrollment-authoring-v3.md) never activates hardware.
  Neither tool opens the old native deployment bootstrap gate.
- Real systemd cross-UID broker, credentials and journal acceptance; real NitroTPM
  power-loss/reboot, PCR, disk rollback and TPM clear/replacement tests.
- Other full-product gates in experiment readiness, which remains false.

This batch did not create AWS resources, upload sources, mutate a real TPM, reset
old state, deploy, commit or push.

Primary references: [PolicyPCR](https://github.com/microsoft/ms-tpm-20-ref/blob/main/TPMCmd/tpm/src/command/EA/PolicyPCR.c),
[PolicyPassword](https://github.com/microsoft/ms-tpm-20-ref/blob/main/TPMCmd/tpm/src/command/EA/PolicyPassword.c),
[NV_Extend](https://github.com/microsoft/ms-tpm-20-ref/blob/main/TPMCmd/tpm/src/command/NVStorage/NV_Extend.c),
[TPM types](https://github.com/tpm2-software/tpm2-tss/blob/master/include/tss2/tss2_tpm2_types.h),
[systemd credentials](https://github.com/systemd/systemd/blob/main/src/core/exec-credential.c).
