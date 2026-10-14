# TPM deployment signature suite V3

Historical batch-33 status (2026-09-20): additive signature/verification implementation, Linux device
adapter and synthetic swtpm interoperability. **Not production activation,
hardware attestation, boot-policy enforcement or a rollback anchor.** The user
selected a new TPM-compatible suite while preserving V2 compatibility.

**Current native connection:** batch 34 adds a mandatory policy-only PCR key,
signed first-install enrollment, an isolated authority, NV whole-head recovery and
Linux runtime anchor consumers. See the [current authority contract](tpm-authority-v3.md).
The password-only profile below is now verification/fixture compatibility, not a
native-open option. V2 deployment migration and real release acceptance remain open.

## Compatibility and scope

Existing V2 Ed25519 wire bytes, key IDs, trust roots, validators and native-authority
traits remain unchanged. The TPM adapter deliberately does not implement the V2
Ed25519 trait. It cannot smuggle P-256 bytes into an Ed25519-typed field. V3 is an
additive, separately named API in `savana-platform-identity`, not transport Suite-1
negotiation. No endpoint selects algorithms from untrusted input or retries V2
after a V3 failure. Old records stay on their original verifier.

`TpmSigningPublicV3` parses a bounded TPM2B_PUBLIC. The only accepted template is:

- ECC, NIST P-256, SHA-256 Name, ECDSA/SHA-256 scheme;
- exact attributes `0x00040072`: fixedTPM, fixedParent, sensitiveDataOrigin,
  userWithAuth and sign; no decrypt, restricted, NoDA or unknown flags;
- empty authPolicy, null symmetric algorithm and KDF;
- valid uncompressed P-256 point, two exact 32-byte coordinates.

This profile is a password-authorized TPM-resident signing key, **not** a PCR-policy
key. Empty authPolicy is intentional and must not be described as measured-boot
sealing. FixedTPM/fixedParent/sensitiveDataOrigin are checked together; accepting a
software-supplied public blob alone proves none of those hardware properties.

The trusted provisioner supplies the public blob, its qualified Name, persistent
handle, installation ID and key epoch. Runtime recomputes the TPM Name from the
public area and checks the complete public area/Name/qualified Name against those
pins. No TOFU and no regeneration if a persistent handle changes or disappears.
Key ID is SHA-256 of a V3 domain, suite tag and TPM Name, so template changes also
change identity. This is not an EK/AK certificate or remote-attestation verifier.

## Signature contract

Suite tag 2 means P-256/ECDSA-SHA256 **inside this V3 format only**. The signed hash
is SHA-256 over a fixed V3 domain, schema 3, suite 2, closed deployment-purpose tag,
installation ID, epoch, TPM-bound key ID and payload digest, in that order.
Installation/epoch/payload must be nonzero. The existing thirteen deployment
purposes are reused as tags, not their V2 signature encoding.

The canonical envelope is exactly 176 bytes:

| Field | Bytes |
| --- | ---: |
| `SVS3`, suite, purpose | 4 + 2 + 2 |
| installation, epoch, key ID, payload digest | 32 + 8 + 32 + 32 |
| low-S ECDSA signature, IEEE P1363 r then s | 64 |

Integers are big-endian. Unknown tags, alternate lengths, invalid/zero scalars,
high-S input, extra fields and trailing bytes are rejected. The TPM's signature
is normalized to low-S and verified against the pinned public key before return.
The public verifier requires both an externally trusted key and the complete
expected request; it returns a `VerifiedTpmSignatureV3`, not implicit authority to
execute, disclose, roll back, advance a counter or enroll a new root.

## Native boundary

`LinuxTpmDeploymentSignerV3::open(binding, Zeroizing<[u8; 32]>)` consumes a nonzero
32-byte authorization value. This value is not the private signing key. It must
come from the future trusted credential/provisioning path, never model output or
the command line. Secret-containing buffers are zeroized and no signer Debug,
key-export, generic-command, shell, configurable TCTI or simulator constructor is
available to production callers.

The adapter opens only `/dev/tpmrm0`, no-follow, close-on-exec and nonblocking;
requires a root-owned character device with no world access; and compares its
device number to `/sys/class/tpmrm/tpmrm0/dev`. Linux, the device/sysfs namespace
and provisioning remain trusted. Password sessions do not encrypt the host/TPM
bus; physical bus attacks and a compromised host OS are not covered by this
profile. The presence of a resource-manager node is not proof of genuine hardware.

The command subset is ReadPublic and Sign. The adapter checks the pinned object
at open and before each sign and independently verifies every returned signature.
It performs no Create/Clear/EvictControl/NV operation and does not alter a real
TPM's persistent configuration. Command/response sizes are bounded; userspace
response polling has a ten-second deadline per exchange, subject to OS/driver
scheduling. It is not a proof of a hard deadline for a stuck kernel syscall.

Only the exact, ten-byte TPM_RC_RETRY response permits resubmission, at most five
attempts. That TPM code reports that the command could not start. Lost responses,
IO errors, auth errors, other TPM codes and malformed frames never trigger replay.
An operation failure poisons the signer instance; it must be reopened and pinned
again. Caller context rejection occurs before issuing any TPM command and does
not poison an otherwise healthy instance.

## Verification

Unit cases cover context/domain separation, suite downgrade, noncanonical/high-S
signatures, malformed key attributes, invalid points, malformed/truncated public
responses, command encoding, wrong-key response verification, poisoning and exact
bounded retry. Software signing in these tests is a fixture, not a hardware path.

`tools/tpm_emulator_acceptance.py` creates a fresh swtpm instance and synthetic
key, then runs the exact explicitly ignored interoperability test. It checks three
real TPM-protocol signatures, round-trip verification, wrong authorization and a
wrong pinned key. Ordinary unit runs report that test ignored; only the harness
requires and counts its exact one-pass result. The Unix-socket test transport is
compiled under `cfg(test)` only, not enabled by `test-support` in production.

The harness refuses root, non-Docker execution, missing marker, or a visible host
TPM. Use fresh tmpfs, a non-root user, read-only source/cache, no capabilities and
no network. Its temporary synthetic keys disappear with that container. The test
image is built separately from `tools/tpm-test-image/Dockerfile`; package download
is not needed during testing. A CI job uses this same boundary. CI configuration
is not a claim that a remote CI run completed.

## Remaining production migration

The V2 `open_native_deployment_authority_handles_v2` and bootstrap-trust constructor
still fail closed. No production daemon currently selects V3 or gains TPM device
access. This batch does not remove `native_signer_and_monotonic_anchor` readiness.

Before enabling a Linux deployment:

1. Add reviewed enrollment and signed V3 trust/manifest selection for the new
   public binding. Define explicit old-record verification and epoch migration;
   do not auto-convert old signed records or regenerate missing keys.
2. Migrate deployment-record consumers to explicitly selected V3 envelopes with
   the same semantic validation, rather than treating this generic verifier as
   proof of deployment authorization. Bind role and validity in trusted roots.
3. Implement and verify the monotonic NV/state commit protocol, including crashes,
   concurrency, counter exhaustion and TPM clear/replacement. A signature is not
   a rollback-resistant counter. No file-backed substitute is enabled here.
4. Complete the boot/PCR/auth-policy and credential threat model, isolated signer
   service/device permissions and native AWS TPM acceptance. A software TPM test
   cannot close these gates. Existing browser/user approval remains mandatory.

No AWS resources, remote source upload, host TPM enrollment/clear, production
deployment, old-state reset, commit or push was performed in this batch.

## Primary references

- [TCG TPM 2.0 command specification](https://trustedcomputinggroup.org/wp-content/uploads/TPM-2.0-1.83-Part-3-Commands.pdf)
  for ReadPublic/Sign and ticket semantics.
- [TPM software stack constants/types](https://github.com/tpm2-software/tpm2-tss/blob/master/include/tss2/tss2_tpm2_types.h)
  for algorithms, object attributes, tags and TPM_RC_RETRY.
- [TPM reference session processing](https://github.com/microsoft/ms-tpm-20-ref/blob/main/TPMCmd/tpm/src/main/SessionProcess.c)
  for password-session response encoding.
