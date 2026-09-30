# TPM V3 offline enrollment authoring

Implemented 2026-09-20. This closes the **public-material authoring** step, not
deployment-ledger migration, renewal or hardware
acceptance. `savana-tpm-enroll` never accesses TPM devices, installed state, private
keys, credentials or services. It does not reset an existing installation.
The separate [native first-install adapter](tpm-first-install-v3.md) now creates
actual TPM material and activates a separately approved profile; this offline
tool still cannot provision or activate a device.

Build with `cargo build --locked -p savana-platform-identity --bin savana-tpm-enroll`.
The executable accepts no command-line arguments. A single bounded JSON document
(at most 16 KiB) enters stdin; one JSON document exits stdout. Errors exit 2 with
a constant message. Binary fields are exact-length lowercase hex, not filenames.
Time is taken from the host's Unix-seconds clock. The native service independently
rechecks time, the installed trust root, measured roles, PCR-gated key and NV guard.

## Operations

1. `{"operation":"prepare","material":M}` validates M and emits
   `unsigned_enrollment` plus `signature_input`, a 32-byte domain-separated digest.
2. The existing, **externally trusted installer** signs the decoded 32-byte input
   with Ed25519. Do not sign the hex characters or hash the input a second time.
   The tool neither generates nor imports a private installer key.
3. `{"operation":"finalize","material":M,"installer_public_key":"...","signature":"..."}`
   reconstructs exactly the same proposal, attaches the external 64-byte signature
   and calls the native `TpmEnrollmentV3::verify` codec. Wrong material, key,
   signature, role, PCR policy, store order and validity are rejected.
4. `{"operation":"verify","enrollment":"...","installer_public_key":"..."}`
   rechecks a finalized binary. Output includes `enrollment_digest` and
   `expected_guard_root`. Both finalize and verify emit the `enrollment` hex for
   packaging by a separately authorized provisioner.

Every successful result explicitly says `hardware_attested:false, activated:false`.
A public key supplied to this authoring tool is an operator-selected verification
root, **not evidence that it is the root already installed on a machine**.

For a proposal produced by native preparation, use
`{"operation":"inspect_prepared","unsigned_enrollment":"..."}` to validate its
canonical encoding and obtain the same public `material` and `signature_input`.
`{"operation":"finalize_prepared","unsigned_enrollment":"...","installer_public_key":"...","signature":"..."}`
attaches an external signature to those exact bytes and calls the same runtime
verifier. Inspection creates no authorization. All time/size/closed-field rules
still apply; `prepare` also emits the decoded `material` for review.

## Public material M

All fields are mandatory; unknown/duplicate fields are rejected.

| Field | Meaning |
| --- | --- |
| `installation_id`, `epoch` | Nonzero 32-byte installation ID and positive u64 epoch |
| `signing_handle` | Numeric persistent TPM signing handle |
| `tpm2b_public`, `qualified_name` | Exact policy-only P256 public area and 34-byte qualified Name |
| `pcr_mask`, `pcr_digest` | Static SHA256 PCR0..7 selection including PCR7; 32-byte selected-value digest |
| `stores` | Exactly five entries ordered deployment, Vault, Agent, G4, Connector |
| `deployer`, `kernel`, `broker` | Each has numeric `uid`, `gid`, and 32-byte `executable_sha256` |
| `not_before`, `expires` | Unix seconds, `not_before <= now < expires` |

Each store has exactly `index`, `name`, `store_id`, `initial_root`. Indices are
`0x01500020..0x01500024` (encode as JSON decimal integers). The supplied 34-byte NV
Name must match the runtime's fixed initialized SHA256 extend template. Store IDs
are distinct nonzero 32-byte values; initial roots are nonzero 32-byte values.
The tool hardcodes GENESIS application heads and a zero previous-enrollment root.
There is no caller-selectable reset, migration or renewal field.

These values must come from reviewed provisioning measurements. This tool does
not establish that a public area came from a genuine TPM or that an initial root
is unused. Do not read arbitrary existing state and label it GENESIS. The native
path checks vacant slots and live PCRs; the trusted installer must separately establish hardware provenance
before the installer authorizes these values, and must never overwrite occupied
handles/indices or bypass the old-state continuity requirements.

## Batch 35 evidence (historical)

Four new Rust tests cover prepare → external sign → finalize → runtime verify,
changed material/wrong root/expiry, forbidden private/reset/migration fields,
PCR weakening, wrong store order and bounded/closed input. The Linux identity
library has 54 passing tests plus one explicitly ignored emulator test in this
run; macOS has 43 passing tests. The emulator was not rerun in this batch.
No real TPM, systemd installation, AWS resource, cloud model or production state
was changed. Existing V2 native bootstrap is still closed.

Batch 36 adds a fifth authoring test for bounded canonical prepared inspection and
rejection of unsigned finalization. Updated platform and emulator results are in
the [first-install evidence](tpm-first-install-v3.md#evidence).
