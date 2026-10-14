# TPM V3 first installation (not full product deployment)

Implemented 2026-09-20. `savana-tpm-first-install` now has a production Linux
device path for **fresh installation only**. The actual closed TPM commands pass
disposable swtpm interoperability, including continuation into runtime NV anchors.
No real TPM or host installation was changed. This is not hardware attestation,
systemd deployment acceptance, an upgrade tool, or completion of the V2-to-V3
deployment-ledger migration. The native kernel bootstrap remains closed.

## Two explicit phases

1. A trusted packager installs the binary at
   `/usr/libexec/savana/savana-tpm-first-install`, the two manual-only unit files,
   reviewed public configuration, and seven independently generated 32-byte
   authorization values, durably protected with systemd encrypted credentials.
   Use the **same** credential files as the runtime TPM authority. No secret goes
   in argv, environment, JSON, logs, or the model. This tool does not generate an
   installer trust root or replace the packaging/credential-escrow process.
2. An operator starts `savana-tpm-first-install-v3.service` (`prepare`). Root/group
   ownership, no-follow fixed paths, canonical plan, absent application-state
   directories and absent old enrollment are checked. An exclusive, fsynced
   proposal output reservation is created before touching the hardware. All seven
   fixed TPM slots must be vacant, and actual selected PCRs must match the plan.
   Both `/var/lib/savana/deployment` and `/var/lib/savana/deployment-v3` must be
   absent too: existing deployment records cannot become a fresh GENESIS install.
3. Prepare creates policy-only P256 key `0x81010003`, defines enrollment guard
   `0x01500010` without writing it, and defines/initializes the five state indices
   `0x01500020..24` with independently random seeds. Public objects and roots are
   read back. The resulting unsigned canonical proposal is written to
   `/etc/savana/tpm-first-install-proposal-v3.bin` and fsynced. Epoch is fixed to 1,
   all application heads to GENESIS, previous enrollment root to zero.
4. The separately trusted installer reviews this actual public proposal using
   `savana-tpm-enroll` operation `inspect_prepared` (lowercase hex in JSON stdin).
   The result includes decoded `material` and `signature_input`. Sign the decoded
   32-byte input with the external Ed25519 installer key; do not sign hex text.
   `finalize_prepared` verifies the signature and returns the final binary as hex.
   The trusted packager installs that decoded binary at
   `/etc/savana/tpm-enrollment-v3.bin` and the independently trusted raw 32-byte
   public key at `/etc/savana/tpm-v3-installer.pub`.
5. An operator starts `savana-tpm-first-activate-v3.service` (`activate`). It checks
   the external signature and current time, exact equality with the reserved
   unsigned proposal, all five unchanged initial roots, and a fresh PCR-gated
   signature by the pinned TPM key. Only then does it extend the unwritten guard
   with the enrollment digest and verify the resulting root.
6. The existing runtime authority can check this guard and open these five state
   bindings. First installation and runtime share one exclusive lifetime lock;
   the installer cannot operate concurrently with a running authority.

The commands above describe deployment steps, not actions performed by this code
change. The source units intentionally have no `[Install]` auto-start target and
`Restart=no`. The device is fixed `/dev/tpmrm0`; no socket/TCTI, software signer,
caller-supplied handle, clear, undefine, old-object eviction, or migration option
exists. An empty owner-hierarchy authorization is currently required for creation;
owner-authorized fleet provisioning needs a separate reviewed adapter. Neither
an existing occupied TPM nor a differently provisioned owner is auto-repaired.

## Fixed plan

`/etc/savana/tpm-first-install-v3.json` is a root:root, single-link, mode 0400/0600
regular file, at most 16 KiB. Parent paths are root-owned and non-writable by
others; symlink traversal is rejected. Unknown and duplicate fields are rejected.

| Field | Required value |
| --- | --- |
| `schema` | Integer 3 |
| `installation_id` | Nonzero 32-byte lowercase hex |
| `store_ids` | Five distinct nonzero 32-byte lowercase hex IDs in deployment/Vault/Agent/G4/Connector order |
| `pcr_mask`, `pcr_digest` | PCR0..7 selection including PCR7, and SHA256 of selected live values in ascending order |
| `deployer`, `kernel`, `broker` | Each exactly `uid`, `gid`, `executable_sha256`; root deployer/broker, non-root kernel, distinct deployer/broker measurements |
| `not_before`, `expires` | Unix seconds with `not_before <= now < expires` |

Reviewed PCR provenance/Secure Boot/event logs and installed executable hashes
remain the trusted installer's responsibility; a self-asserted digest is not
hardware evidence. Native enrollment/activation checks possession and the chosen
PCR policy, not manufacturer provenance. Existing root/owner compromise and bus
interception exclusions are unchanged.

## Failure and recovery

- An occupied slot stops prepare **before any TPM mutation**. A live-PCR mismatch
  also stops before creating objects. Wrong/duplicate/zero auth values are rejected.
- The reserved proposal file, persistent key and indices are never auto-deleted.
  A partial prepare is deliberately fail-closed, not resumable or recoverable by
  rerunning this tool. Keep the durable credential escrow and failure evidence.
  A separately reviewed continuity/recovery procedure is still required.
- Only the transient key created by this invocation is flushed. A persistent key
  is never evicted, including when persistence succeeded but its reply was lost.
- An ambiguous activation reply is an error. On a fresh invocation an exact
  matching guard can succeed without another extend, after all other checks.
  A changed enrollment, expired profile, changed PCR/key, or consumed state head
  rejects activation. No mutation is retried on an ambiguous transport error.
- Activation holds the shared OS lock; this is not a multi-command hardware
  transaction. Trusted root, Linux storage durability and the TPM resource manager
  remain assumptions. PCR proof is atomic with Sign, not with later NV_Extend.
- Renewal, epoch migration and TPM replacement are unsupported. Do not clear the
  TPM, delete old state, or issue fresh GENESIS bindings to work around a refusal.

## Evidence

`tools/tpm_emulator_acceptance.py` now runs two isolated fresh emulator scenarios.
The first retains existing signing/PCR/race/NV tests; the second invokes
`tools/tpm_first_install_acceptance.py` and tests actual prepare → external fixture
signature → activate → runtime anchor open/advance/reopen. It also checks occupied
slots, wrong authorization, expiry, lost activation reply, idempotence, changed
signed role bindings and refusal after consumption. The transport exists only in
tests. Unit tests cover pre-mutation failure, strict public inspection/finalization,
closed native plan and manual unit/credential contracts.

These are software-TPM and component results, not real power-loss, physical TPM,
systemd, full product, or real-model measurements. The Python experiment readiness
gate intentionally stays false. Remaining product blockers are tracked in
[the implementation status](../research/v04-product-implementation.md).

Current run: Linux identity library **60 passed**, plus **7 integration tests**;
the two emulator tests are ignored by the ordinary suite and were then both run
explicitly and passed. macOS identity library **47 passed**; scoped all-targets
Clippy passed. Python experiment suite **44 passed**, including real Rust driver
subprocesses. The frozen production source inventory verifies **304 files**.
