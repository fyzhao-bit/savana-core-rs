# Linux V3 deployment preparation: authorization and actual staging bytes

Status: implemented read-only prerequisites, **not a completed installer or boot
authority**. No activation, service control, grant reservation or fence removal
is authorized by these objects. V2 external Ed25519 transaction/rollback signatures
are unchanged; their expected ledger digest may bind the distinct V3 TPM payload.

## Data path

`VerifiedNativeDeploymentPreparationV3::verify` combines the fixed root spool,
the live `LinuxDeploymentJournalV3`, authenticated external trust chains and a
measured platform supplied by the native driver:

1. Read the exact descriptor beneath the compiled spool selector.
2. Replay native immutable history to the live TPM head and reviewed genesis.
3. Select exact role keys from authenticated trust roots; verify both signatures.
4. Bind the transaction to the V3 ledger's installation, epoch, generation,
   payload, phase, activation, fence, active manifest, identity profile and all
   high-water state, plus the four authenticated trust-root revisions.
5. Check current time/platform and prohibit reused transactions/grants. Idle
   preparation rejects pending auxiliary records; Committed preparation requires
   typed verification/commit evidence for the exact anchored history. A mere
   `CommitAttestation` purpose tag is insufficient. RolledBack and bridge
   preparation remain unsupported until their typed completion evidence is wired.
6. Measure actual staged files, construct the canonical `StagingTreeV2`, compare
   its Merkle root with the signed intent, decode all six plans and compare each
   domain-separated plan digest. Descriptor bytes must equal the authorized bytes.
7. Verify the supplied canonical desired manifest with the authenticated release
   roots at the current time. Bind its signed digest, target platform, installation
   epoch and helper/watchdog identities to this exact transaction. Bind its entire
   bootstrap TCB lock to the selected V3 ledger; ordinary preparation cannot
   replace the bootstrap TCB.
8. Match every one of the 35 normal-release files to its closed staging role,
   exact signed length and SHA-256. Require exactly one parser and connector
   worker because the current closed layout has one slot per worker role.
9. Project all 29 versioned domains and reject lower sequences, same-sequence
   forks and lower signer-key epochs, including a lower epoch at a higher
   sequence. The resulting vector is a proposal, not a durable high-water update.
10. Recheck the retained files, complete native history/head and time after the
   potentially slow reads. Any revalidation failure poisons the preparation object.
   Reverification checks release signatures/component validity again, so retaining
   a previously verified manifest cannot extend its validity window.

The caller must keep the journal/mutex and revalidate before subsequent use.
This API does not independently measure the platform/TCB or load native trust
roots; it must not receive those values from the descriptor/model. Passing these
checks is not proof that installation or acceptance tests have actually run.

## Closed Linux staging layout

Fixed parent: `/var/lib/savana-deploy/spool/ready/<64 lowercase hex selector>`.
All directories are root/root 0700. The selector remains the V2 domain-separated
hash of the transaction ID and staging-tree digest. There are no caller paths.

The selector directory contains exactly:

- `DeploymentTransactionV2.cbor`: root/root, single-link regular file, 0400,
  1..1 MiB. Excluded from the Merkle tree to avoid a hash cycle, but not exempt
  from descriptor/attribute checks.
- `MigrationPlanV2.cbor`, `ArtifactInstallPlanV2.cbor`,
  `ServiceTransitionPlanV2.cbor`, `IsolatedE2EPlanV2.cbor`,
  `EvidenceContractV2.cbor`, `ProtectedAcceptancePlanV2.cbor`: tags 1..6 in this
  order, root/root single-link regular files, 0600, 1..4 MiB each.
- `ArtifactPayloadRoot`: tag 7, sole staging payload directory, 0700; the tree
  records zero size and zero content digest as required by the existing schema.

The payload directory contains only canonical decimal leaves `10` through `44`,
matching the existing closed staging-role registry. At least one payload is
required; aliases such as `010`, unknown tags and nested directories reject.
Payloads are root/root single-link regular files, 0600, at most 8 GiB each;
the checked total is at most 64 GiB. Payloads are hashed in 64 KiB chunks, not
read wholesale into memory. Plan bytes are bounded and retained for typed decode.
The low-level staging schema permits a subset. Manifest-bound V3 preparation now
requires all 35 payloads; a valid partial tree is not a prepared installation.
Installed permissions, ACLs, native executable identity and service semantics
remain separate measurements; content equality does not establish those facts.

## Filesystem checks

Descriptor-relative no-follow, close-on-exec and nonblocking opens; same device,
exact inode/owner/group/mode; file single-link checks; exact before/after inventory,
size, mtime and ctime; content rehash on revalidation. Retained descriptors do not
make files immutable: mutation is an error, and these checks do not authorize
reopening an arbitrary path later or installing without an effect fence.

This initial Linux profile requires **no ACL or xattr entries**. `flistxattr`
must report an empty set, including for the descriptor and directories; unsupported
queries fail closed. Therefore SELinux labels and file capabilities also reject;
the code does not strip them or silently treat them as empty. Empty-set digests are
`SHA256("savana.linux-staging.v3.empty-acl\0")` and
`SHA256("savana.linux-staging.v3.empty-xattr\0")`. These exact nonzero values enter
the canonical tree and must be approved by the external transaction signer.

## Validation and remaining activation boundary

Linux tests cover actual files, full six-plan positive flow, each wrong plan
digest, malformed but signed plan content, wrong selector/descriptor, extra or
missing entries, symlinks/hardlinks/FIFOs/directories, writable modes, xattrs,
oversized sparse plans, post-check mutation and poisoned revalidation.
The root-only fixed-spool test runs separately via
`tools/deployment_disk_acceptance.py`, requiring marked disposable Docker,
no TPM device, and fresh tmpfs mounts at `/var/lib/savana` and
`/var/lib/savana-deploy`. Tests do not install files into a live system.

Still required before native activation: native trust/platform/TCB acquisition,
recovery-manifest binding and actual materialization closure, store compatibility,
exclusive effect denial/quiescence, actual installation, runtime measurements,
acceptance evidence, watchdog recovery and authenticated daemon bootstrap.
The existing legacy apply path now includes staging measurement after its native
authorization checks; its unimplemented native authority is **not** bypassed.
The new preparation API is a native read-only building block, not an installed
operator command or successful end-to-end deployment.

The signed-manifest integration test exercises the real non-root Linux staging
reader with all 35 files and actual Ed25519 fixture signatures. Cross-platform
subcases reject every missing/altered/length-mismatched file and conflicts in every
one of the 29 high-water domains. Linux subcases additionally reject a different
transaction, not-yet-valid/expired authorization, expired release components,
signature tampering and retained-file mutation. Synthetic signing keys remain
test-only. The combined TPM-journal preparation is still not an installed service
or a measured-hardware acceptance result.
