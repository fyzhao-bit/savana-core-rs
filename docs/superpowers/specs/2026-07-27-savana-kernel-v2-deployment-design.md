# Savana Kernel V2 Deployment and Platform Design

> Date: 2026-07-27
>
> Status: implementation-authoritative deployment contract
>
> Scope: signed installation, native service isolation, restart activation,
> rollback, boot recovery, and completion evidence for Savana Kernel V2.

## 1. Authority and invariants

This document is the normative deployment companion to:

- [Savana Secure Kernel V2](./2026-07-27-savana-secure-kernel-v2-design.md)
- [V2 protocol and state design](./2026-07-27-savana-kernel-v2-protocol-state-design.md)

The following rules are unconditional:

1. A production installation activates one complete signed security state, not
   independently selected binaries and configuration fragments.
2. `DeploymentLedgerV2` is the sole authority for active state and
   highest-ever version state.
3. Rollback changes the active complete manifest; it never lowers a
   highest-ever entry.
4. A rollback target is complete, immutable, locally present, and proven
   compatible before the transaction is armed.
5. Operational security state, including WebAuthn counters, replay records,
   vault state, dispatch WAL, executor nonces, and audit chains, is never
   restored from an older snapshot.
6. The privileged helper accepts no caller-selected path, command, script,
   service name, environment entry, or partial manifest.
7. The helper that verifies an application transaction cannot replace itself,
   its watchdog, or the trust roots used to validate that transaction.
8. Native Linux and macOS controls are required product behavior. A build that
   cannot prove them may be `SourceImplemented`, but not
   `PlatformComplete` or `ProductComplete`.
9. No public live-reload, partial rollover, or signal-triggered security-state
   activation exists. Activation is a restart transaction.
10. Product completion requires the exact signed installed artifacts and
    service graph used by the required-mode end-to-end test.
11. Every deployment wire object uses the fixed-width canonical ABI in this
    document and Ed25519 only. An implementation with an algorithm-selection
    field, variable-width key ID, or implementation-defined timestamp is not
    V2.
12. An application deployment cannot update the deployment helper, deployment
    watchdog, deployment trust roots, activation trust roots, ledger schema
    authority, or their installation locations.
13. No external effect is authorized by a process-local readiness bit.
    Authorization requires the current ledger generation, current effect-fence
    epoch, and a live shared effect lease.
14. Evidence needed to validate a claim is retained independently from
    artifact retention. An evidence record must not pin every historical
    installation closure forever.

## 2. Complete security-state manifest

Every desired installation and every rollback target is represented by one
canonical `SecurityStateManifestV2`.

```text
enum InstallationClassV2 : u16 {
    NormalApplication = 1,
    BootstrapEpochBridge = 2
}

SecurityStateManifestV2 {
    schema_version: u16 = 2,
    domain_tag: ClosedDeploymentObjectDomainV2 = SecurityStateManifest,
    installation_class: InstallationClassV2,
    target_platform: PlatformLockV2,
    release: VersionedIdentityV2,

    deployment_hard_limits_digest: Digest32,
    source_lock: SourceLockV2,
    binary_closure: BinaryClosureV2,
    security_state: SecurityStateClosureV2,
    platform_closure: PlatformClosureV2,
    bootstrap_tcb_lock: BootstrapTcbLockV2,
    persistent_store_compatibility: [PersistentStoreCompatibilityV2],
    agent_claim_compatibility_edges: [AgentClaimCompatibilityV2],

    file_tree: [FileTreeEntryV2],
    file_tree_root: Digest32,
    component_signature_set: [ManifestComponentSignatureV2],
    release_signature: DomainSignatureV2
}
```

No field is optional. The manifest is not a patch and cannot inherit an
omitted item from the active installation. `NormalApplication` is the only
class accepted as an ordinary desired/rollback runtime manifest.
`BootstrapEpochBridge` is accepted only through section 8's signed offline
intent and only as the fenced, non-executable new-epoch ledger anchor defined
there. It cannot be an ordinary desired or normal-rollback target,
service-readiness authority, release-manifest entry, or
platform/product-completion subject. The only recovery use is the exact
`BootstrapBridgeRestore` branch of an authorized bridge-exit attempt before
the epoch's first normal commit, as defined in sections 5, 6, and 15; that
branch restores the already authenticated bridge and remains fenced.
An offline bootstrap slot, maintenance package, or TCB update still cannot be
encoded or relabelled as the bridge manifest itself.

### 2.1 Fixed-width canonical ABI and hard limits

All deployment metadata is a definite-length canonical CBOR array in the field
order shown here. Maps, floats, tags, indefinite lengths, non-shortest
integers, unknown enum tags, omitted or trailing fields, duplicate semantic
identities, and unconsumed bytes are rejected before signature evaluation.

The only primitive wire widths are:

```text
Digest32                 32 bytes
Nonce32                  32 bytes
Ed25519KeyIdV2           32 bytes
HpkeX25519KeyIdV2        32 bytes
ReplayAeadKeyIdV2        32 bytes
VaultKeyIdV2             32 bytes
Ed25519PublicKeyV2       32 bytes
Ed25519SignatureV2       64 bytes
UnixMillis               unsigned u64
DurationNanos            unsigned u64
schema/domain/enum tag   unsigned u16
mode bitset              unsigned u32
sequence/generation      unsigned u64
size/count               unsigned u64
boolean                  canonical false or true
```

`FixedBytesV2<N>` is a definite-length canonical CBOR byte string of exactly
`N` bytes. `BoundedNfcUtf8V2` is a definite-length canonical CBOR text string
whose bytes are valid UTF-8, already NFC-normalized, and no longer than
`max_text_identifier_bytes`. `BoundedArrayV2<T, N>` is notation for the same
canonical array encoding as `[T]` with decoded count at most `N`; it adds no
tag or wrapper. `BoundedSetV2` below is process-local pseudocode and never a
wire type.

```text
enum ClosedDeploymentObjectDomainV2 : u16 {
    SecurityStateManifest = 1,
    DeploymentTransactionIntent = 2,
    RollbackGrant = 3,
    ProductRelease = 4,
    BootstrapMaintenanceIntent = 5,
    DurableDeploymentTransactionCore = 6
}
```

Key-ID families are closed and non-interchangeable:

```text
Ed25519KeyIdV2 =
  SHA256("savana.ed25519-key-id.v2\0" || Ed25519PublicKeyV2)

HpkeX25519KeyIdV2 =
  SHA256("savana.hpke-x25519-key-id.v2\0" ||
         hpke_x25519_public_key_bstr32)
```

`VaultKeyIdV2` and `ReplayAeadKeyIdV2` are distinct CSPRNG-generated,
keystore-owned opaque 32-byte identifier types for non-exportable symmetric
keys; neither is a digest of key bytes. No one of these four types has a
decoder as another or as generic `Digest32`. Every deployment signature uses
`Ed25519KeyIdV2` and Ed25519; HPKE appears only in the executor envelope lock.
There is no algorithm-agility field in V2.

The helper, watchdog, validators, and release builder compile the same closed
`DeploymentHardLimitsV2` constants:

```text
DeploymentHardLimitsV2 {
    max_transaction_bytes: u64 = 1_048_576,
    max_manifest_bytes: u64 = 4_194_304,
    max_plan_bytes: u64 = 4_194_304,
    max_plan_steps: u64 = 4_096,
    max_transaction_head_records: u64 = 4_096,
    max_ledger_predecessor_records: u64 = 4_096,
    max_bootstrap_maintenance_records_per_package: u64 = 32,
    max_bootstrap_quiescent_role_heads: u64 = 4_096,
    max_prepare_duration_ns: u64 = 86_400_000_000_000,
    max_cutover_duration_ns: u64 = 3_600_000_000_000,
    max_boot_recovery_duration_ns: u64 = 3_600_000_000_000,
    max_clock_skew_ns: u64 = 300_000_000_000,
    max_file_tree_entries: u64 = 65_536,
    max_file_tree_depth: u64 = 64,
    max_single_artifact_bytes: u64 = 8_589_934_592,
    max_staging_tree_bytes: u64 = 68_719_476_736,
    max_component_signatures: u64 = 4_096,
    max_operational_trust_roots: u64 = 64,
    max_release_trust_roots: u64 = 64,
    max_persistent_stores: u64 = 64,
    max_agent_claim_compatibility_edges: u64 = 64,
    max_agent_claim_vault_key_reads: u64 = 64,
    max_agent_claim_view_projections: u64 = 256,
    max_agentd_replay_capsules: u64 = 65_536,
    max_agentd_replay_capsule_bytes: u64 = 1_073_741_824,
    max_agentd_replay_compatibility_edges: u64 = 64,
    max_native_measurements: u64 = 4_096,
    max_attestation_bytes: u64 = 16_777_216,
    max_text_identifier_bytes: u64 = 255
}
```

`deployment_hard_limits_digest` is:

```text
SHA256(
  "savana.deployment-hard-limits.v2\0"
  || canonical_cbor(DeploymentHardLimitsV2)
)
```

A manifest, plan, tree, or evidence object that exceeds any limit is rejected
before allocation proportional to attacker-controlled counts. A compiled
limits digest mismatch is a protocol-lock failure, not a request to negotiate.
All count, size, duration, and timestamp arithmetic is checked; overflow or
underflow is rejection.

Unless a more specific rule is stated, an object's `payload_digest` excludes
only that object's own digest and every `DomainSignatureV2` wrapper that
authenticates it. Raw `Ed25519SignatureV2` occurs on the wire only as the last
field of `DomainSignatureV2`; no other schema embeds a bare signature.
For the exact numeric domain `d`, exact compiled NUL-terminated ASCII domain
`D`, and already computed object payload digest `P`, the only legal signature
input is:

```text
DomainSignatureInputV2(d, P) =
  SHA256("savana.domain-signature.v2\0" || u16_be(d) || D || P)

signature =
  Ed25519.sign(signing_key, DomainSignatureInputV2(d, P))
```

The wrapper's domain, key ID, and key epoch must equal the role authorization
used to select the verification key before signature verification. A valid
signature moved to another wrapper domain, role, key epoch, or object is
invalid. Nested signed objects are included as their complete canonical bytes.
A field never directly or indirectly includes a signature that authenticates
that field.
Every closed optional value is encoded as a `u16` discriminant with
`None = 0` and `Some = 1`, followed, for `Some`, by the declared fixed-schema
value. No Rust/source ordinal is a wire value.

Every security-relevant enum declared in this document assigns an explicit
`u16` value to every variant. Declaration order, Rust discriminants, generated
source order, and platform-native constants are never wire values. Adding,
renumbering, aliasing, or reusing a tag requires a new protocol major.
Canonical vectors cover every accepted numeric tag plus rejection of `0`
where unassigned, gaps, unknown values, aliases, and the host-language ordinal.
For a payload variant, notation `Variant = N { ... }` means `u16_be(N)`
followed by the fields in the shown order.

### 2.2 Source lock

```text
SourceLockV2 {
    exact_ten_crate_source_digest: Digest32,
    cargo_lock_digest: Digest32,
    build_toolchain_digest: Digest32,
    reproducible_build_recipe_digest: Digest32,
    sbom_digest: Digest32
}
```

`source_lock_digest` is
`SHA256("savana.source-lock.v2\0" || canonical_cbor(SourceLockV2))`.

The source digest covers exactly these ten workspace crates:

```text
savana-kernel-protocol
savana-policy-core
savana-vault
savana-input-runtime
savana-platform-identity
savana-agentd
savana-kerneld
savana-ingressd
savana-approvald
savana-execd
```

Additional production data-plane crates are forbidden. Separate binary
targets for deploy/watchdog, parser/OCR workers, and connector workers are
covered by the same source and build locks.

### 2.2.1 Artifact identity

Every artifact identity uses this exact platform-bound schema:

```text
enum ClosedArtifactTypeV2 : u16 {
    ControlShell = 1,
    Daemon = 2,
    CommandLineTool = 3,
    Worker = 4,
    Configuration = 5,
    ServiceDefinition = 6,
    EndpointDefinition = 7,
    SandboxProfile = 8,
    EntitlementProfile = 9,
    StaticAsset = 10,
    ModelArtifact = 11,
    RootHelper = 12,
    Watchdog = 13,
    RecoveryTool = 14,
    LedgerVerifier = 15
}

enum ClosedTargetOsV2 : u16 {
    Linux = 1,
    MacOs = 2
}

enum ClosedTargetArchitectureV2 : u16 {
    X86_64 = 1,
    Aarch64 = 2
}

PlatformLockV2 {
    schema_version: u16 = 2,
    target_os: ClosedTargetOsV2,
    target_architecture: ClosedTargetArchitectureV2,
    os_release_identity_digest: Digest32,
    kernel_abi_digest: Digest32,
    service_manager_identity_digest: Digest32,
    filesystem_capabilities_digest: Digest32,
    native_sandbox_capabilities_digest: Digest32
}

PlatformLockDigest =
  SHA256("savana.platform-lock.v2\0" ||
         canonical_cbor(PlatformLockV2))

ArtifactIdentityV2 {
    schema_version: u16 = 2,
    artifact_type: ClosedArtifactTypeV2,
    target_os: ClosedTargetOsV2,
    target_architecture: ClosedTargetArchitectureV2,
    byte_length: u64,
    sha256: Digest32,
    platform_code_identity_digest: Digest32,
    execution_profile_digest: Digest32
}

ArtifactIdentityDigest =
  SHA256("savana.artifact-identity.v2\0" ||
         canonical_cbor(ArtifactIdentityV2))

ArtifactSetIdentityV2 = [ArtifactIdentityV2]
```

Every platform-lock digest is nonzero. These five digests resolve through the
signed platform closure and bind the exact distribution/macOS release,
kernel ABI, systemd/launchd implementation, required local-filesystem
durability features, and native sandbox feature set. A marketing OS name,
runtime feature probe, caller-supplied module path, or “compatible” kernel
cannot substitute for this lock.

All three digests are nonzero, `byte_length` is nonzero and no larger than
`max_single_artifact_bytes`, and the complete canonical object is used
wherever this document names `ArtifactIdentityV2`. On Linux,
`platform_code_identity_digest` resolves through the signed code-integrity
lock to the exact executable/content measurement. On macOS it resolves to the
signed CodeDirectory/designated-requirement tuple. The
`execution_profile_digest` resolves to the exact signed sandbox, entitlement,
or non-executable data profile. Neither field is a caller-selected string or
an unregistered native blob.

`ArtifactSetIdentityV2` contains exactly one artifact in V2 and is strictly
sorted by complete
`ArtifactIdentityDigest`; duplicate identities are rejected. Every member is
`Worker`, and every member has the same target OS and architecture. Its exact
digest is
`SHA256("savana.artifact-set-identity.v2\0" ||
canonical_cbor(ArtifactSetIdentityV2))`. The set wrapper is a grouping
identity only: component cardinality and signatures are still evaluated over
the individual worker. The exact-one rule follows from the closed file tree,
which has one parser-worker and one connector-worker logical executable role;
adding dynamically named worker paths requires a protocol major rather than
an unmeasured extra file.

### 2.3 Binary closure

```text
BinaryClosureV2 {
    jarvis: ArtifactIdentityV2,
    agentd: ArtifactIdentityV2,
    ingressd: ArtifactIdentityV2,
    kerneld: ArtifactIdentityV2,
    approvald: ArtifactIdentityV2,
    execd: ArtifactIdentityV2,
    approvalctl: ArtifactIdentityV2,
    worker_sandbox: ArtifactIdentityV2,
    parser_worker_set: ArtifactSetIdentityV2,
    connector_worker_set: ArtifactSetIdentityV2
}
```

`jarvis` identifies the fixed non-authoritative control shell. Every
production Rust daemon and worker is an exact signed artifact; a development
launcher or `cargo run` path cannot satisfy this closure.
`BinaryClosureDigest` is
`SHA256("savana.binary-closure.v2\0" ||
canonical_cbor(BinaryClosureV2))`.

### 2.4 Security-state closure

```text
SecurityStateClosureV2 {
    policy: VersionedIdentityV2,
    registry: VersionedIdentityV2,
    ontology: VersionedIdentityV2,
    model_set: VersionedIdentityV2,
    resource_profile: VersionedIdentityV2,
    destination_projection: VersionedIdentityV2,
    display_projection: VersionedIdentityV2,
    validator_set: VersionedIdentityV2,
    grammar_schema: VersionedIdentityV2,
    protocol_lock: VersionedIdentityV2,
    service_identity_lock: VersionedIdentityV2,
    approval_lock: VersionedIdentityV2,
    jarvis_artifact: VersionedIdentityV2,
    egress_policy_set: VersionedIdentityV2,
    executor_connector_registry: VersionedIdentityV2,
    executor_key_lock: VersionedIdentityV2,
    planner_lock: VersionedIdentityV2,
    completion_evidence_trust_policy: VersionedIdentityV2
}
```

`EgressPolicySet` is a separate signed security domain. It is not derived from
`DestinationProjection`, DNS, environment, a runtime proxy configuration, or
a service-manager override.
`SecurityStateClosureDigest` is
`SHA256("savana.security-state-closure.v2\0" ||
canonical_cbor(SecurityStateClosureV2))`.

### 2.5 Platform and measured bootstrap closure

```text
PlatformClosureV2 {
    service_unit_set: VersionedIdentityV2,
    socket_or_xpc_unit_set: VersionedIdentityV2,
    service_store_projection_set: VersionedIdentityV2,
    sandbox_profile_set: VersionedIdentityV2,
    entitlement_profile_set: VersionedIdentityV2,
    code_integrity_lock: VersionedIdentityV2
}

BootstrapTcbLockV2 {
    deploy_helper_identity: ArtifactIdentityV2,
    deploy_watchdog_identity: ArtifactIdentityV2,
    deploy_recovery_identity: ArtifactIdentityV2,
    ledger_verifier_identity: ArtifactIdentityV2,
    ledger_schema_authority_digest: Digest32,
    bootstrap_native_profile_set_digest: Digest32,
    bootstrap_location_layout_digest: Digest32,
    bootstrap_static_file_tree_root: Digest32,
    deployment_trust_root_set: VersionedIdentityV2,
    activation_trust_root_set: VersionedIdentityV2,
    release_trust_root_set: VersionedIdentityV2,
    installation_epoch: u64
}
```

`PlatformClosureDigest` is
`SHA256("savana.platform-closure.v2\0" ||
canonical_cbor(PlatformClosureV2))`.

```text
BootstrapTcbLockDigest =
  SHA256("savana.bootstrap-tcb-lock.v2\0" ||
         canonical_cbor(BootstrapTcbLockV2))
```

`BootstrapTcbLockV2` measures the static, already installed bootstrap TCB:
helper, watchdog, offline recovery, ledger verifier/schema authority, native
profiles, fixed locations/layout, complete static slot file tree, and all
three root sets. It intentionally excludes the fresh activation key,
installation identity profile, epoch attestation, and genesis ledger that are
created after a maintenance intent is signed; the later
`BootstrapSlotClosureV2` binds those values without a digest cycle. The lock is
not an application-deployment payload and cannot be changed by
`DeploymentTransactionV2`.

For every normal desired and rollback manifest, the complete canonical
`BootstrapTcbLockDigest` MUST equal `bootstrap_tcb_lock_digest` in the
complete `BootstrapSlotClosureV2` authenticated by the currently selected
`BootstrapActiveSelectorV2`, commit marker, and terminal maintenance record;
the manifest/selector/slot installation epoch must also match. The boot gate
separately recomputes the complete slot closure, including its
installation-specific profile, attestation, and genesis.
`ArtifactInstallPlanV2`, staging-tree validation, and helper path
validation reject every bootstrap-owned helper/watchdog/verifier/schema,
active-selector, trust-root, ledger-genesis, keystore, profile, receipt, or
installation location, including every bootstrap slot-closure, identity
profile, epoch-attestation, and genesis object. This prohibition applies even when the candidate
helper or watchdog binary was built as another binary target of the same
kerneld crate. Source checks may report the candidate build outputs, but
normal `ArtifactEvidenceV2` reaches `ArtifactComplete` only when the
reproducible helper/watchdog bytes equal the selected active slot. A changed
bootstrap output blocks normal artifact completion and can be installed or
activated only by section 8's offline ceremony.

### 2.6 Version, signature, and digest rules

```text
VersionedIdentityV2 {
    domain: ClosedSecurityDomainV2,
    sequence: u64,
    content_digest: Digest32,
    signer_key_id: Ed25519KeyIdV2,
    signer_key_epoch: u64,
    not_before_unix_ms: UnixMillis,
    not_after_unix_ms: UnixMillis
}

ManifestLineageDigestV2 =
  SHA256("savana.manifest-lineage.v2\0" ||
         canonical_cbor(the manifest's release VersionedIdentityV2))

DomainSignatureV2 {
    signature_domain: ClosedSignatureDomainV2,
    signer_key_id: Ed25519KeyIdV2,
    signer_key_epoch: u64,
    signature: Ed25519SignatureV2
}

enum ClosedSignatureDomainV2 : u16 {
    ManifestComponent = 1,
    ManifestRelease = 2,
    TransactionAuthorization = 3,
    RollbackGrant = 4,
    LedgerActivation = 5,
    InstallationEpochActivation = 6,
    InstallationEpochInstallerOrMdm = 7,
    StoreCompatibility = 8,
    VerificationEvidence = 9,
    CommitAttestation = 10,
    ReviewAttestation = 11,
    ProductCompletion = 12,
    EvidenceGcCheckpoint = 13,
    CompletionEvidenceTrustPolicy = 14,
    SourceEvidence = 15,
    ArtifactEvidence = 16,
    RollbackVerificationEvidence = 17,
    RollbackVerificationAttestation = 18,
    ProductRelease = 19,
    InstallIdentityProfile = 20,
    LedgerSlot = 21,
    InstallationEvidenceEnvelope = 22,
    BootstrapMaintenanceIntent = 23,
    BootstrapMaintenanceRecord = 24,
    DurableDeploymentTransactionCore = 25,
    DurableDeploymentTransactionRecord = 26,
    RecoveryRollbackReadinessEvidence = 27,
    OperationalTrustRootSet = 28,
    ReleaseTrustRootSet = 30,
    BootstrapActiveSelector = 31,
    BootstrapMaintenanceHead = 32
}
```

`ManifestLineageDigestV2` is the only construction-time identity allowed
inside an object that is itself embedded in a manifest. It prevents a
cryptographic self-reference: the complete signed manifest digest cannot
occur inside bytes over which that same digest is computed. Every distinct
normal or bridge manifest has a distinct `BinaryRelease` versioned identity;
reuse of one lineage for different complete manifest bytes is release-root
equivocation and is rejected by the release high-water. Ledger, transaction,
evidence, and externally written capsule records continue to bind the
complete signed manifest digest once it exists.

The numeric tags above map one-to-one to the following exact signature-domain
bytes. This table is exhaustive:

| Tag | Variant | Exact NUL-terminated ASCII domain |
|---:|---|---|
| 1 | `ManifestComponent` | `"savana.manifest-component.v2.signature\0"` |
| 2 | `ManifestRelease` | `"savana.manifest-release.v2.signature\0"` |
| 3 | `TransactionAuthorization` | `"savana.deployment-transaction.v2.authorization\0"` |
| 4 | `RollbackGrant` | `"savana.rollback-grant.v2.authorization\0"` |
| 5 | `LedgerActivation` | `"savana.deployment-ledger.v2.activation\0"` |
| 6 | `InstallationEpochActivation` | `"savana.installation-epoch.v2.activation\0"` |
| 7 | `InstallationEpochInstallerOrMdm` | `"savana.installation-epoch.v2.installer-or-mdm\0"` |
| 8 | `StoreCompatibility` | `"savana.store-compatibility.v2.signature\0"` |
| 9 | `VerificationEvidence` | `"savana.verification-evidence.v2.signature\0"` |
| 10 | `CommitAttestation` | `"savana.commit-attestation.v2.signature\0"` |
| 11 | `ReviewAttestation` | `"savana.review-attestation.v2.signature\0"` |
| 12 | `ProductCompletion` | `"savana.product-completion-attestation.v2.signature\0"` |
| 13 | `EvidenceGcCheckpoint` | `"savana.evidence-gc-checkpoint.v2.signature\0"` |
| 14 | `CompletionEvidenceTrustPolicy` | `"savana.completion-evidence-trust-policy.v2.signature\0"` |
| 15 | `SourceEvidence` | `"savana.source-evidence.v2.signature\0"` |
| 16 | `ArtifactEvidence` | `"savana.artifact-evidence.v2.signature\0"` |
| 17 | `RollbackVerificationEvidence` | `"savana.rollback-verification-evidence.v2.signature\0"` |
| 18 | `RollbackVerificationAttestation` | `"savana.rollback-verification-attestation.v2.signature\0"` |
| 19 | `ProductRelease` | `"savana.product-release.v2.signature\0"` |
| 20 | `InstallIdentityProfile` | `"savana.install-identity-profile.v2.signature\0"` |
| 21 | `LedgerSlot` | `"savana.ledger-slot.v2.signature\0"` |
| 22 | `InstallationEvidenceEnvelope` | `"savana.installation-evidence.v2.envelope\0"` |
| 23 | `BootstrapMaintenanceIntent` | `"savana.bootstrap-maintenance-intent.v2.signature\0"` |
| 24 | `BootstrapMaintenanceRecord` | `"savana.bootstrap-maintenance-record.v2.signature\0"` |
| 25 | `DurableDeploymentTransactionCore` | `"savana.durable-deployment-core.v2.signature\0"` |
| 26 | `DurableDeploymentTransactionRecord` | `"savana.durable-deployment-record.v2.signature\0"` |
| 27 | `RecoveryRollbackReadinessEvidence` | `"savana.recovery-rollback-readiness.v2.signature\0"` |
| 28 | `OperationalTrustRootSet` | `"savana.operational-trust-root-set.v2.signature\0"` |
| 30 | `ReleaseTrustRootSet` | `"savana.release-trust-root-set.v2.signature\0"` |
| 31 | `BootstrapActiveSelector` | `"savana.bootstrap-active-selector.v2.signature\0"` |
| 32 | `BootstrapMaintenanceHead` | `"savana.bootstrap-maintenance-head.v2.signature\0"` |

The protocol companion's private-worker signature
domains are decoded only by its own signed-object ABI and cannot be relabelled
as deployment domains.

The role-to-domain mapping is closed: authorized component signers use tag 1;
the `ManifestRelease` root uses tag 2; the deployment and rollback
authorizers use tags 3 and 4; the installation activation key uses tags 5, 6,
8 through 10, 13, 17, 18, 21, 22, and 25 through 27 as specified by the owning
schema; the independently authorized installer/MDM key uses tags 7, 20, 23,
24, 28, 30, 31, and 32; the evidence policy's Review, Product, Source, and Artifact
roles use tags 11, 12, 15, and 16 respectively; the
`CompletionEvidenceTrustPolicy` and `ProductRelease` release-root roles use
tags 14 and 19. Private worker wire signatures and domains are owned solely by
the protocol companion and are not members of
`ClosedSignatureDomainV2`. Tag 29 is deliberately unassigned in this
deployment enum and is rejected before key lookup; it is not reclaimed from
the protocol companion's private worker ABI. No role may sign a domain
omitted from this sentence.

The unsigned manifest payload digest is:

```text
ManifestComponentBindingV2 {
    component: ManifestComponentRefV2,
    authorization_id: Digest32
}

UnsignedSecurityStateManifestPayloadV2 {
    schema_version: u16 = 2,
    domain_tag: ClosedDeploymentObjectDomainV2 = SecurityStateManifest,
    installation_class: InstallationClassV2,
    target_platform: PlatformLockV2,
    release: VersionedIdentityV2,
    deployment_hard_limits_digest: Digest32,
    source_lock: SourceLockV2,
    binary_closure: BinaryClosureV2,
    security_state: SecurityStateClosureV2,
    platform_closure: PlatformClosureV2,
    bootstrap_tcb_lock: BootstrapTcbLockV2,
    persistent_store_compatibility: [PersistentStoreCompatibilityV2],
    agent_claim_compatibility_edges: [AgentClaimCompatibilityV2],
    file_tree: [FileTreeEntryV2],
    file_tree_root: Digest32,
    component_bindings: [ManifestComponentBindingV2]
}

SHA256(
  "savana.security-state-manifest.v2.payload\0"
  || canonical_cbor(UnsignedSecurityStateManifestPayloadV2)
)
```

`component_bindings` is the exact projected component order and is
byte-for-byte the `(component, authorization_id)` projection of
`component_signature_set`. Thus no signature wrapper is self-covered, while
the selected authorization for every component is covered. The complete
manifest remains the 17-field schema in section 2: its first 15 fields equal
the unsigned payload, followed by the complete component signature set and
the one release signature.

The manifest digest is:

```text
SHA256(
  "savana.security-state-manifest.v2.signed\0"
  || canonical_cbor(complete signed manifest)
)
```

Unknown fields, duplicate fields, omitted fields, extension maps,
non-canonical encodings, and trailing bytes are rejected.

`ClosedSecurityDomainV2` is an unsigned `u16` enum with exactly these tags
and no catch-all variant:

```text
enum ClosedSecurityDomainV2 : u16 {
    BinaryRelease = 1,
    Policy = 2,
    Registry = 3,
    Ontology = 4,
    ModelSet = 5,
    ResourceProfile = 6,
    DestinationProjection = 7,
    DisplayProjection = 8,
    ValidatorSet = 9,
    GrammarSchema = 10,
    ProtocolLock = 11,
    ServiceIdentityLock = 12,
    ApprovalLock = 13,
    JarvisArtifact = 14,
    EgressPolicySet = 15,
    ExecutorConnectorRegistry = 16,
    ExecutorKeyLock = 17,
    PlannerLock = 18,
    CompletionEvidenceTrustPolicy = 19,
    ServiceUnitSet = 20,
    SocketOrXpcUnitSet = 21,
    ServiceStoreProjectionSet = 22,
    SandboxProfileSet = 23,
    EntitlementProfileSet = 24,
    CodeIntegrityLock = 25,
    DeploymentTrustRootSet = 26,
    ActivationTrustRootSet = 27,
    ReleaseTrustRootSet = 28
}
```

The manifest validator requires exactly one versioned identity for every
domain represented by the fixed closure schemas above; platform selection
does not permit field omission. It rejects duplicate `(domain, sequence)`
tuples.

#### 2.6.1 Release roots and exact component-signature cardinality

The deployment and activation root families are complete signed objects, not
bare member-set digests:

```text
enum OperationalTrustRootSetBindingV2 : u16 {
    Deployment = 1 {
        deployment_trust_root_set_digest: Digest32
    },
    Activation = 2 {
        activation_trust_root_set_digest: Digest32
    }
}

UnsignedOperationalTrustRootSetV2 {
    schema_version: u16 = 2,
    product_family_digest: Digest32,
    root_set_sequence: u64,
    previous_operational_trust_root_set_signed_digest: None | Digest32,
    binding: OperationalTrustRootSetBindingV2,
    members: [OperationalTrustRootSetItemV2],
    not_before_unix_ms: UnixMillis,
    not_after_unix_ms: UnixMillis
}

OperationalTrustRootSetV2 {
    payload: UnsignedOperationalTrustRootSetV2,
    payload_digest: Digest32,
    installer_or_mdm_signature: DomainSignatureV2
}
```

`members` is nonempty, bounded by
`max_operational_trust_roots`, and strictly sorted by
`(purpose, key_id, key_epoch)`. Duplicate complete tuples and reuse of one
key ID under another purpose or epoch are rejected; multiple distinct keys
for one permitted purpose are allowed within the bound. The `Deployment`
branch permits only
`DeploymentAuthorization` and `RollbackAuthorization` members and requires
at least one of each; its digest field recomputes under the registered current
`deployment_trust_root_set_digest` domain. The `Activation` branch permits
only `InstallationActivation` and requires at least one; its digest field
recomputes under the registered current
`activation_trust_root_set_digest` domain. A family tag, purpose, member
vector, or member-set digest mismatch is rejected before signature lookup.
Every key ID recomputes from its public key, every member validity interval is
inside the root-set interval, and all time arithmetic is checked.

The payload and complete signed-object digests are respectively:

```text
OperationalTrustRootSetPayloadDigest =
  SHA256("savana.operational-trust-root-set.v2.payload\0" ||
         canonical_cbor(UnsignedOperationalTrustRootSetV2))

OperationalTrustRootSetSignedDigest =
  SHA256("savana.operational-trust-root-set.v2.signed\0" ||
         canonical_cbor(OperationalTrustRootSetV2))
```

The wrapper is exactly `OperationalTrustRootSet = 28` and is authorized only
by the independently installed OS-installer/MDM trust projection used by the
offline native package verifier. That projection and its private key are
outside every application manifest, Savana runtime service, and bootstrap
slot; its registered member-set digest is
`installer_or_mdm_trust_root_set_digest` in installation identity objects.
`root_set_sequence` is nonzero. Its predecessor is `None` if and only if the
sequence is one; every sequence greater than one has `Some` that binds the
immediately prior complete signed digest and increments the
resolved predecessor by exactly one, and preserves the exact
`product_family_digest` and `binding` variant. Deployment and Activation
predecessor/high-water chains are independent; a cross-family or
cross-binding predecessor is rejection. Sequence reuse, gaps, forks, and
rollback are rejected by the binding-specific native package high-water.

A `BootstrapTcbLockV2.deployment_trust_root_set` or
`.activation_trust_root_set` `VersionedIdentityV2` resolves exactly one such
signed object. Its domain is respectively `DeploymentTrustRootSet` or
`ActivationTrustRootSet`; its sequence, complete signed `content_digest`,
signer key/epoch, and validity interval must equal the resolved object and its
wrapper. It never places the member-set digest in `content_digest`.

The offline-maintained release-root set is:

```text
enum ReleaseSigningRoleV2 : u16 {
    ManifestComponent = 1,
    ManifestRelease = 2,
    ProductRelease = 3,
    CompletionEvidenceTrustPolicy = 4
}

ReleaseRootKeyV2 {
    role: ReleaseSigningRoleV2,
    public_key: Ed25519PublicKeyV2,
    key_id: Ed25519KeyIdV2,
    key_epoch: u64,
    not_before_unix_ms: UnixMillis,
    not_after_unix_ms: UnixMillis
}

enum ManifestComponentKindV2 : u16 {
    BinaryArtifact = 1,
    SecurityDomainObject = 2,
    PlatformDomainObject = 3,
    BootstrapArtifact = 4
}

ManifestComponentRefV2 {
    kind: ManifestComponentKindV2,
    component_identity_digest: Digest32
}

ComponentSignerAuthorizationV2 {
    authorization_id: Digest32,
    component: ManifestComponentRefV2,
    signer_key_id: Ed25519KeyIdV2,
    signer_key_epoch: u64
}

UnsignedReleaseTrustRootSetV2 {
    schema_version: u16 = 2,
    product_family_digest: Digest32,
    root_set_sequence: u64,
    previous_release_trust_root_set_signed_digest: None | Digest32,
    roots: [ReleaseRootKeyV2],
    component_authorizations: [ComponentSignerAuthorizationV2],
    release_trust_root_set_digest: Digest32,
    not_before_unix_ms: UnixMillis,
    not_after_unix_ms: UnixMillis
}

ReleaseTrustRootSetV2 {
    payload: UnsignedReleaseTrustRootSetV2,
    payload_digest: Digest32,
    installer_or_mdm_signature: DomainSignatureV2
}

ManifestComponentSignatureV2 {
    component: ManifestComponentRefV2,
    authorization_id: Digest32,
    signature: DomainSignatureV2
}
```

`roots` is nonempty and bounded by `max_release_trust_roots`;
`component_authorizations` is bounded by `max_component_signatures`. Roots
sort strictly by `(role tag, key_id bytes, key_epoch)`; authorizations sort
strictly by `(component kind, component_identity_digest, signer_key_id,
signer_key_epoch, authorization_id)`; duplicate complete items and duplicate
semantic component identities are rejected. Each key ID recomputes from its
public key. `release_trust_root_set_digest` recomputes
under section 18.8 from the complete tagged union of every root and component
authorization using that section's exact branch-specific union key; neither
list can be hidden from it. The root-set payload digest is
`SHA256("savana.release-trust-root-set.v2.payload\0" ||
canonical_cbor(UnsignedReleaseTrustRootSetV2))`; its complete signed digest is
`SHA256("savana.release-trust-root-set.v2.signed\0" ||
canonical_cbor(ReleaseTrustRootSetV2))`. Its wrapper is exactly
`ReleaseTrustRootSet = 30` and is authorized only by the independently
installed OS-installer/MDM root. `BootstrapTcbLockV2.release_trust_root_set`
binds that signed digest as its `content_digest`; an application manifest
cannot replace or reinterpret it.
`root_set_sequence` is nonzero; sequence one has a tagged `None` predecessor,
and every later sequence has `Some` containing the immediately prior complete
signed digest, increments that predecessor's sequence by exactly one, and
preserves `product_family_digest`. The native package high-water rejects
downgrade, gap, cross-family predecessor, fork, predecessor omission, or
sequence reuse with different bytes.

The manifest validator deterministically projects the exact component set:
every individual artifact in `BinaryClosureV2`, every parser and connector
worker artifact rather than only their set wrapper, every fixed
`SecurityStateClosureV2` identity, every fixed `PlatformClosureV2` identity,
every `AgentClaimCompatibilityV2` edge as a `SecurityDomainObject`, and the
helper/watchdog bootstrap artifacts. For each projected component
there must be exactly one `ComponentSignerAuthorizationV2` and exactly one
matching `ManifestComponentSignatureV2`; zero, two, a signature for an
unprojected component, or an authorization for a different digest is
rejection. Every component wrapper uses `ManifestComponent = 1` and signs:

```text
ManifestComponentBindingDigestV2 =
  SHA256("savana.manifest-component.v2.binding\0" ||
         canonical_cbor([component, authorization_id,
                         manifest_payload_digest]))
```

The complete manifest has exactly one `ManifestRelease = 2` signature from a
currently authorized `ManifestRelease` root; it signs
`manifest_payload_digest` through `DomainSignatureInputV2`. Product releases and completion
trust policies similarly require exactly one currently authorized root for
their respective roles. Root selection is never inferred from a component
signature or from the object being verified, avoiding a self-signing cycle.

#### 2.6.2 Closed runtime identity and key locks

The following payloads are immutable manifest components. Their component
signature is supplied by the manifest's exact signature set above; they do not
contain an inner signature or their own content digest.

```text
enum RuntimeEd25519KeyRoleV2 : u16 {
    JarvisAgentClientHandshake = 1,
    AgentdJarvisServerHandshake = 2,
    AgentdKernelClientHandshake = 3,
    KerneldAgentServerHandshake = 4,
    IngressdKernelClientHandshake = 5,
    KerneldIngressServerHandshake = 6,
    KerneldExecdClientHandshake = 7,
    ExecdKernelServerHandshake = 8,
    AgentdApprovalClientHandshake = 9,
    ApprovaldAgentServerHandshake = 10,
    IngressdApprovalClientHandshake = 11,
    ApprovaldIngressServerHandshake = 12,
    ApprovalctlAdminClientHandshake = 13,
    ApprovaldAdminServerHandshake = 14,
    RegistryPublisher = 15,
    KerneldApprovalEnvelope = 16,
    KerneldUiAuthenticationEnvelope = 17,
    KerneldTaskCorrelation = 18,
    KerneldExecutionEnvelope = 19,
    ExecdIdentity = 20,
    ExecdEffectReceipt = 21,
    IngressdParserJobDescriptor = 22,
    ExecdConnectorCodecJobDescriptor = 23
}

RuntimeEd25519VerificationEpochV2 {
    role: RuntimeEd25519KeyRoleV2,
    key_id: Ed25519KeyIdV2,
    key_epoch: u64,
    public_key: Ed25519PublicKeyV2,
    not_before_unix_ms: UnixMillis,
    verify_until_unix_ms: UnixMillis
}

RuntimeEd25519RoleLockV2 {
    role: RuntimeEd25519KeyRoleV2,
    active: RuntimeEd25519VerificationEpochV2,
    retired_verification: [RuntimeEd25519VerificationEpochV2]
}

enum RuntimeAeadKeyRoleV2 : u16 {
    AgentdDurableReplayEscrow = 1
}

enum RuntimeAeadAlgorithmV2 : u16 {
    XChaCha20Poly1305 = 1
}

RuntimeAeadKeyEpochIdentityV2 {
    role: RuntimeAeadKeyRoleV2 =
        AgentdDurableReplayEscrow,
    key_epoch: u64,
    key_id: ReplayAeadKeyIdV2,
    key_identity_digest: Digest32,
    nonexportable_key_handle_identity_digest: Digest32,
    algorithm: RuntimeAeadAlgorithmV2 = XChaCha20Poly1305,
    installation_id: Digest32,
    creating_manifest_lineage_digest: ManifestLineageDigestV2,
    agentd_service_identity_digest: Digest32,
    not_before_unix_ms: UnixMillis,
    encrypt_until_unix_ms: UnixMillis,
    decrypt_until_unix_ms: UnixMillis
}

enum ReplayCapsuleCompatibilityCapabilityV2 : u16 {
    ReadExisting = 1
}

enum ReplayCapsuleClassV2 : u16 {
    DurableTaskHandleEmission = 1
}

ReplayCapsuleCompatibilityEdgeV2 {
    from_manifest_lineage_digest: ManifestLineageDigestV2,
    to_manifest_lineage_digest: ManifestLineageDigestV2,
    store_id: ClosedStoreIdV2,
    persistent_store_compatibility_digest: Digest32,
    capability: ReplayCapsuleCompatibilityCapabilityV2 =
        ReadExisting,
    capsule_class: ReplayCapsuleClassV2 =
        DurableTaskHandleEmission,
    protocol_abi_digest: Digest32,
    role: RuntimeAeadKeyRoleV2 =
        AgentdDurableReplayEscrow,
    permitted_decrypt_key_epoch: u64,
    capsule_retain_until_unix_ms: UnixMillis,
    edge_identity_digest: Digest32
}

AgentdDurableReplayAeadLockV2 {
    role: RuntimeAeadKeyRoleV2 =
        AgentdDurableReplayEscrow,
    active: RuntimeAeadKeyEpochIdentityV2,
    retired_decrypt:
        BoundedArrayV2<RuntimeAeadKeyEpochIdentityV2, 4>,
    directed_compatibility_edges:
        [ReplayCapsuleCompatibilityEdgeV2]
}

ServiceIdentityEntryV2 {
    service: ClosedServiceIdV2,
    principal_identity_digest: Digest32,
    code_identity_digest: Digest32,
    sandbox_identity_digest: Digest32,
    permitted_key_roles: [RuntimeEd25519KeyRoleV2],
    permitted_aead_key_roles: [RuntimeAeadKeyRoleV2]
}

ServiceIdentityLockV2 {
    schema_version: u16 = 2,
    lock_sequence: u64,
    previous_content_digest: Digest32,
    services: [ServiceIdentityEntryV2],
    ed25519_role_locks: [RuntimeEd25519RoleLockV2],
    agentd_durable_replay_sealing:
        AgentdDurableReplayAeadLockV2,
    protocol_payload: ServiceIdentityLockProtocolPayloadV2,
    protocol_payload_digest: Digest32,
    not_before_unix_ms: UnixMillis,
    expires_at_unix_ms: UnixMillis
}

enum ExecutorHpkeKeyRoleV2 : u16 {
    ExecdEnvelopeUnsealing = 1
}

ExecutorHpkeVerificationEpochV2 {
    role: ExecutorHpkeKeyRoleV2,
    key_id: HpkeX25519KeyIdV2,
    key_epoch: u64,
    public_key: FixedBytesV2<32>,
    not_before_unix_ms: UnixMillis,
    decrypt_until_unix_ms: UnixMillis
}

ExecutorKeyLockV2 {
    schema_version: u16 = 2,
    lock_sequence: u64,
    previous_content_digest: Digest32,
    kerneld_execution_envelope_signing:
        RuntimeEd25519RoleLockV2,
    execd_identity_signing: RuntimeEd25519RoleLockV2,
    execd_effect_receipt_signing: RuntimeEd25519RoleLockV2,
    execd_connector_codec_job_descriptor_signing:
        RuntimeEd25519RoleLockV2,
    execd_hpke_unsealing_active: ExecutorHpkeVerificationEpochV2,
    execd_hpke_unsealing_retired:
        [ExecutorHpkeVerificationEpochV2],
    executor_connector_registry_digest: Digest32,
    journal_key_hierarchy_identity_digest: Digest32,
    not_before_unix_ms: UnixMillis,
    expires_at_unix_ms: UnixMillis
}

PlannerTlsClientEpochV2 {
    key_epoch: u64,
    credential_identity_digest: Digest32,
    nonexportable_key_handle_identity_digest: Digest32,
    certificate_chain_digest: Digest32,
    not_before_unix_ms: UnixMillis,
    usable_until_unix_ms: UnixMillis
}

enum FixedIpAddressV2 : u16 {
    V4 = 1 { octets: FixedBytesV2<4> },
    V6 = 2 { octets: FixedBytesV2<16> }
}

PlannerEndpointLockV2 {
    route_id: Digest32,
    address_family: ClosedAddressFamilyV2,
    literal_address: FixedIpAddressV2,
    transport: ClosedTransportV2 = TCP,
    port: u16,
    tls_version: u16 = 0x0304,
    server_spki_sha256: Digest32,
    application_protocol_digest: Digest32
}

PlannerLockV2 {
    schema_version: u16 = 2,
    lock_sequence: u64,
    previous_content_digest: Digest32,
    agentd_identity_digest: Digest32,
    active_mtls_client: PlannerTlsClientEpochV2,
    retired_verification_clients: [PlannerTlsClientEpochV2],
    endpoints: [PlannerEndpointLockV2],
    planner_request_deadline_ns: DurationNanos,
    not_before_unix_ms: UnixMillis,
    expires_at_unix_ms: UnixMillis
}
```

Every `ExecutorHpkeVerificationEpochV2.key_id` recomputes under the exact
`HpkeX25519KeyIdV2` formula from its X25519 public key. The protocol
`SealedExecutionEnvelopeV2.seal_key_id` must byte-equal that typed ID for the
selected active/retired epoch; an Ed25519, replay-AEAD, vault, or generic
digest decoder is rejected before HPKE processing.

`ReplayAeadKeyIdV2` is the protocol companion's distinct CSPRNG-generated
keystore identifier type; it has no decoder as `Digest32` or any public-key
ID. The additional diagnostic/index identity is not a substitute key ID and
is exactly:

```text
ReplayAeadKeyIdentityDigest =
  SHA256("savana.replay-aead-key-identity.v2\0" ||
         replay_aead_key_id_bstr32)
```

Every `RuntimeAeadKeyEpochIdentityV2.key_identity_digest` must equal that
formula over its typed `key_id`. The durable capsule
`ReplayCapsuleKeyBindingV2::AgentdDurableEscrow.key_id` must byte-equal this
typed field for the selected role/epoch; it never equals or decodes from
`key_identity_digest`.
In the agentd replay store's `observed_key_slot_set_digest`, the item for
`AgentdDurableReplayEscrow` must repeat that epoch, derived
`key_identity_digest`, and non-exportable handle identity from the manifest
lock. The agentd store validator resolves the typed `key_id` from that lock
and recomputes the digest; it never derives a typed ID from the observed
digest. `ObservedKeySlotSetItemV2.key_role_tag` is interpreted only under its
own `ClosedStoreIdV2` validator schema, so another store's numeric role tag
cannot be substituted for this runtime AEAD role.

Service entries sort by service tag; role locks sort by role and contain every
required role exactly once; retired verification epochs sort strictly by
`(key_epoch, key_id)` and are capped at four. An active key cannot occur in a
retired set, and one key ID cannot serve two roles. In every
`RuntimeEd25519RoleLockV2`, the outer role, active epoch role, and every
retired epoch role are equal; an empty, duplicate, substituted, or
cross-role epoch is rejection.

Private-key use is closed by this matrix:

| Identity | Exact `permitted_key_roles` / exceptional private role |
|---|---|
| `Jarvis` | `JarvisAgentClientHandshake` |
| `Agentd` | `AgentdJarvisServerHandshake`, `AgentdKernelClientHandshake`, `AgentdApprovalClientHandshake` |
| `Ingressd` | `IngressdKernelClientHandshake`, `IngressdApprovalClientHandshake`, `IngressdParserJobDescriptor` |
| `Kerneld` | `KerneldAgentServerHandshake`, `KerneldIngressServerHandshake`, `KerneldExecdClientHandshake`, `KerneldApprovalEnvelope`, `KerneldUiAuthenticationEnvelope`, `KerneldTaskCorrelation`, `KerneldExecutionEnvelope` |
| `Approvald` | `ApprovaldAgentServerHandshake`, `ApprovaldIngressServerHandshake`, `ApprovaldAdminServerHandshake` |
| `Execd` | `ExecdKernelServerHandshake`, `ExecdIdentity`, `ExecdEffectReceipt`, `ExecdConnectorCodecJobDescriptor` |
| `ParserWorkerTemplate`, `ConnectorWorkerTemplate` | empty; only a one-job ephemeral attestation handle is injected |
| private root `savana-approvalctl` | `ApprovalctlAdminClientHandshake`; it is not a runtime service entry |
| offline registry publisher | `RegistryPublisher`; it is not a runtime service entry |

Each service list is strictly role-sorted and duplicate-free; a role not shown
for that identity is forbidden. Approvald's four settlement families remain
solely in the protocol-defined `ApprovalLockV2` and cannot appear in this
matrix.

`ExecutorKeyLockV2`
requires the exact roles shown and rejects any role substitution. Its
`kerneld_execution_envelope_signing`, `execd_identity_signing`,
`execd_effect_receipt_signing`, and
`execd_connector_codec_job_descriptor_signing` locks must be byte-identical
to the corresponding `ServiceIdentityLockV2.ed25519_role_locks` entries for
roles 19, 20, 21, and 23. They are duplicate verification projections, not a
second rotation authority. The embedded protocol payload's task-correlation,
parser-descriptor, connector-codec-descriptor, and effect-receipt key IDs must
equal the active key IDs for roles 18, 22, 23, and 21 respectively. Its
durable replay-lock digest must equal the digest of the embedded
`agentd_durable_replay_sealing` object.

The exact subobject digests are:

```text
AgentdDurableReplayAeadLockDigest =
  SHA256("savana.agentd-durable-replay-aead-lock.v2\0" ||
         canonical_cbor(AgentdDurableReplayAeadLockV2))

ServiceIdentityLockProtocolPayloadDigest =
  SHA256("savana.service-identity-lock.protocol-payload.v2\0" ||
         canonical_cbor(ServiceIdentityLockProtocolPayloadV2))
```

`protocol_payload_digest` must equal the latter.
`protocol_payload.protocol_abi_digest` must byte-equal the destination
manifest's `security_state.protocol_lock.content_digest`; every protocol ABI
reference in a replay compatibility edge or worker descriptor must resolve to
that same value. A missing protocol payload, wrong subobject digest, disagreed
duplicate role lock, protocol/manifest ABI mismatch, or protocol key ID that
does not resolve to its exact active role prevents manifest activation.
Planner
endpoints sort by `(route_id, address_family, literal_address, transport,
port, server_spki_sha256)` and contain no hostname, DNS fallback, proxy, or
wildcard pin. Their canonical content digests use respectively:

```text
"savana.service-identity-lock.v2\0"
"savana.executor-key-lock.v2\0"
"savana.planner-lock.v2\0"
```

followed by the complete canonical payload. The `VersionedIdentityV2`
content digest and signer tuple must equal the validated component binding;
no lock signs itself or identifies its own component signature.

Only the `agentd` service entry may contain
`AgentdDurableReplayEscrow` in `permitted_aead_key_roles`, and it contains it
exactly once; every other service's AEAD-role list is empty. The active and
retired handles are non-exportable and usable only by the exact agentd code,
service, installation, and manifest identities. The role has the single
locked algorithm `XChaCha20Poly1305`; an algorithm substitution is a manifest
validation failure. It may protect only durable response-loss/replay capsules
for the protocol's `DurableTaskHandleEmission` class and named role, never
boot recovery state, action/effect state, task content, planner payloads,
approval data, vault data, or another service's journal. Each capsule authenticates
installation ID, creating manifest, protocol ABI, role, key epoch, agentd
identity, durable operation identity, expiry, and ciphertext digest.

`active` is the only key permitted to encrypt a new capsule, and only in its
closed `[not_before_unix_ms, encrypt_until_unix_ms]` interval. It may decrypt
only its own epoch through `decrypt_until_unix_ms`. `retired_decrypt` is
strictly increasing by key epoch, contains at most four entries, and is
decrypt-only: no retired handle can encrypt, reseal, or mint new mutation
authority. A retired handle cannot be removed while either a capsule remains
before its authenticated retain ceiling or an installed rollback manifest
can still read that epoch. Rotation that would require a fifth retained
decrypt epoch rejects deployment; it does not evict the oldest key.
Every epoch satisfies `not_before_unix_ms <= encrypt_until_unix_ms <=
decrypt_until_unix_ms`; the active epoch is strictly greater than every
retired epoch; typed replay key IDs, derived key-identity digests, and handle
identities are each unique across both collections; and all referenced key
epochs lie within the lock's validity interval.

Cross-manifest decryption is denied by default. It is allowed only when the
exact release-root-authorized destination manifest contains both the
applicable `PersistentStoreCompatibilityV2` declaration and one named,
directional `ReadExisting` compatibility edge. The edge's old/new manifest,
store ID, exact persistent-store-compatibility digest, protocol ABI, role,
capsule class, old decrypt-key epoch, and retention ceiling must all match the
capsule and current state. Edges are bounded by
`max_agentd_replay_compatibility_edges` and sort by `(from_manifest_lineage_digest,
to_manifest_lineage_digest, store_id, persistent_store_compatibility_digest,
capability, capsule_class, protocol_abi_digest, role, permitted_decrypt_key_epoch,
capsule_retain_until_unix_ms)`; `edge_identity_digest` recomputes from that
complete tuple excluding `edge_identity_digest` under
`"savana.agentd-replay-capsule-compatibility-edge.v2\0"`.

V2 never decrypts and re-encrypts, migrates, online-rewraps, extends, or
reseals an old capsule. Absent edge, absent store compatibility, missing
retired handle, ABI/role/epoch mismatch, failed AEAD, expired retention, or
service-identity mismatch yields the capsule's fail-closed durable
status/tombstone and no replay reconstruction. An installation-epoch change
permits no edge at all: old-epoch capsules remain audit evidence only, and
the new epoch creates a fresh active key. Capsule count and byte capacity are
specified only by `DeploymentHardLimitsV2` and the signed resource profile;
they are not fields of `ServiceIdentityLockV2`.

This `ReplayCapsuleCompatibilityEdgeV2` inside the exact
`ServiceIdentityLockV2` content digest is the sole edge ABI and vector
authority. The protocol companion consumes that manifest-resolved lock and
does not redeclare or independently sign the edge. A boot/action capsule,
another capsule class, or a second protocol-side edge registry is rejected
even when its AEAD verifies.

### 2.7 Exact file-tree closure and Merkle rule

`ClosedLogicalPathIdV2` is the following platform-neutral registry. The signed
`bootstrap_location_layout_digest` maps each logical role to its one compiled
native absolute path; a manifest never carries an absolute or relative path.

| Tags | Exact members in ascending tag order |
|---|---|
| 1–5 | `InstallationRootDirectory`, `ExecutableRootDirectory`, `ConfigurationRootDirectory`, `ServiceDefinitionRootDirectory`, `SandboxProfileRootDirectory` |
| 6–15 | `JarvisExecutable`, `AgentdExecutable`, `IngressdExecutable`, `KerneldExecutable`, `ApprovaldExecutable`, `ExecdExecutable`, `ApprovalctlExecutable`, `WorkerSandboxExecutable`, `ParserWorkerExecutable`, `ConnectorWorkerExecutable` |
| 16–20 | `AgentdConfig`, `IngressdConfig`, `KerneldConfig`, `ApprovaldConfig`, `ExecdConfig` |
| 21–29 | `KerneldServiceDefinition`, `KerneldAgentEndpointDefinition`, `KerneldIngressEndpointDefinition`, `AgentdServiceDefinition`, `AgentdControlEndpointDefinition`, `AgentdJarvisHttpEndpointDefinition`, `AgentdAgentHttpEndpointDefinition`, `IngressdServiceDefinition`, `IngressdHttpEndpointDefinition` |
| 30–37 | `ApprovaldServiceDefinition`, `ApprovaldAgentEndpointDefinition`, `ApprovaldIngressEndpointDefinition`, `ApprovaldAdminEndpointDefinition`, `ApprovaldHttpEndpointDefinition`, `ExecdServiceDefinition`, `ExecdEndpointDefinition`, `KernelTargetDefinition` |
| 38–40 | `ParserSandboxProfile`, `ConnectorNoNetworkSandboxProfile`, `ConnectorCredentialAbsenceProfile` |
| 41–51 | `DeployHelperExecutable`, `DeployWatchdogExecutable`, `DeployRecoveryExecutable`, `LedgerVerifierExecutable`, `DeploymentTrustRootSet`, `ActivationTrustRootSet`, `ReleaseTrustRootSet`, `BootstrapActiveSelector`, `BootstrapSlotClosure`, `InstallationIdentityProfile`, `LedgerGenesis` |

Tags 41–51 are bootstrap-owned. No normal staging or install-plan registry
contains a corresponding member, so a normal deployment cannot name them
even if it knows their native paths or byte digests. Tag `0`, gaps, values
above `51`, aliases, strings, hashes used as path IDs, and platform-selected
extensions are rejected.

The normal application file tree contains tags 1–40 exactly once in ascending
order. Tag 1 is its sole root; tags 2–5 are its four direct child
directories. Executable roles are children of tag 2, configurations of tag
3, service/endpoint definitions of tag 4, and sandbox profiles of tag 5.
Directories are root/root mode `0755`, executable roles mode `0555`, and
configuration/service/profile roles mode `0444`. The artifact type for every
regular-file role is compiled and must equal its embedded
`ArtifactIdentityV2`; a manifest cannot relabel configuration bytes as an
executable or place a bootstrap artifact in the normal tree.

Every installed directory and regular file has one entry:

```text
FileTreeEntryV2 {
    logical_path_id: ClosedLogicalPathIdV2,
    parent_logical_path_id: None | ClosedLogicalPathIdV2,
    entry_kind: FileTreeEntryKindV2,
    owner_principal: ClosedInstallPrincipalV2,
    owner_group: ClosedInstallGroupV2,
    mode: u32,
    acl_digest: Digest32,
    xattr_digest: Digest32,
    file_payload: None | {
        artifact_identity: ArtifactIdentityV2
    }
}

enum FileTreeEntryKindV2 : u16 {
    Directory = 1,
    RegularFile = 2
}
```

The file tree:

- uses compiled logical path IDs, never arbitrary filesystem paths;
- contains one root directory, lists every descendant directory and file
  exactly once in canonical logical-path order, and rejects an entry whose
  parent is absent or not a directory; the root alone has tagged `None` as
  parent and every other entry has tagged `Some`;
- rejects symlinks, hardlinks, devices, FIFOs, sockets, mount crossings, and
  unknown members;
- includes service units, socket/XPC definitions, sandbox profiles, native
  entitlements, and JARVIS artifacts;
- binds every expected owner, group, mode, ACL, xattr, code identity, and
  resource size.

For entry index `i` in canonical order:

```text
leaf[i] = SHA256(
  "savana.file-tree.v2.leaf\0"
  || u64_be(i)
  || canonical_cbor(FileTreeEntryV2[i])
)
```

Adjacent nodes are combined as:

```text
node = SHA256("savana.file-tree.v2.node\0" || left || right)
odd  = SHA256("savana.file-tree.v2.odd\0" || only_child)
```

The process repeats until one hash remains. The empty tree is invalid.
`file_tree_root` is:

```text
SHA256(
  "savana.file-tree.v2.root\0"
  || u64_be(entry_count)
  || final_node
)
```

No implicit directory, platform-generated file, duplicated last leaf,
implementation-selected balancing rule, or unordered collection is allowed.

## 3. The sole deployment ledger

`DeploymentLedgerV2` is the only authoritative active-state and freshness
record. Kerneld, approvald, agentd, ingressd, execd, JARVIS, and service
managers must not maintain an independent release high-water authority.

```text
DeploymentLedgerV2 {
    schema_version: u16 = 2,
    installation_id: Digest32,
    installation_epoch: u64,
    generation: u64,
    written_at_unix_ms: UnixMillis,
    phase: DeploymentPhaseV2,
    transaction_id: None | Nonce32,
    effects_fenced: bool,
    effect_fence_epoch: u64,

    active_manifest_digest: Digest32,
    active_activation: ActiveActivationV2,
    install_identity_profile_signed_digest: Digest32,
    bootstrap_tcb_lock_digest: Digest32,
    highest_ever: HighestEverV2,
    rollback_grant_state: RollbackGrantStateV2,
    rollback_origin_phase: None | RollbackOriginPhaseV2,
    transaction_head_digest: None | Digest32,

    previous_record_digest: Digest32,
    record_payload_digest: Digest32,
    activation_key_id: Ed25519KeyIdV2,
    record_signature: DomainSignatureV2
}

enum ActiveActivationV2 : u16 {
    Normal = 1,
    ConsumedRollback = 2 {
        failed_transaction_id: Nonce32,
        rollback_grant_id: Digest32
    },
    BootstrapBridge = 3 {
        maintenance_intent_signed_digest: Digest32,
        bridge_manifest_digest: Digest32,
        premaintenance_runtime_manifest_digest: Digest32,
        previous_installation_epoch: u64,
        previous_epoch_last_ledger_record_signed_digest: Digest32,
        previous_epoch_last_ledger_record_payload_digest: Digest32,
        restore_provenance:
            None | BootstrapBridgeRestoreProvenanceV2
    }
}

BootstrapBridgeRestoreProvenanceV2 {
    bridge_genesis_ledger_record_signed_digest: Digest32,
    failed_transaction_id: Nonce32,
    recovery_grant_id: Digest32,
    restore_origin_phase: RollbackOriginPhaseV2
}

enum RollbackGrantStateV2 : u16 {
    None = 0,
    Prearmed = 1,
    Consuming = 2,
    Consumed = 3,
    Burned = 4
}

enum RollbackOriginPhaseV2 : u16 {
    Armed = 1,
    Quiesced = 2,
    Installed = 3,
    Verified = 4
}

enum DeploymentPhaseV2 : u16 {
    IDLE = 1,
    PREPARED = 2,
    ARMED = 3,
    QUIESCED = 4,
    INSTALLED = 5,
    VERIFIED = 6,
    COMMITTED = 7,
    ABORTED = 8,
    ROLLBACK_PREPARED = 9,
    ROLLBACK_INSTALLED = 10,
    ROLLBACK_VERIFIED = 11,
    ROLLED_BACK = 12,
    FAILED_SAFE = 13,
    BOOTSTRAP_BRIDGE = 14,
    BRIDGE_RESTORE_PREPARED = 15,
    BRIDGE_RESTORE_INSTALLED = 16,
    BRIDGE_RESTORE_VERIFIED = 17
}
```

`HighestEverV2` has one `HighWaterEntryV2` for each domain:

```text
BinaryRelease
Policy
Registry
Ontology
ModelSet
ResourceProfile
DestinationProjection
DisplayProjection
ValidatorSet
GrammarSchema
ProtocolLock
ServiceIdentityLock
ApprovalLock
JarvisArtifact
EgressPolicySet
ExecutorConnectorRegistry
ExecutorKeyLock
PlannerLock
CompletionEvidenceTrustPolicy
ServiceUnitSet
SocketOrXpcUnitSet
ServiceStoreProjectionSet
SandboxProfileSet
EntitlementProfileSet
CodeIntegrityLock
DeploymentTrustRootSet
ActivationTrustRootSet
ReleaseTrustRootSet
```

```text
HighWaterEntryV2 {
    sequence: u64,
    content_digest: Digest32,
    key_epoch: u64
}
```

`HighestEverV2` is a fixed-length canonical array in ascending explicit
`ClosedSecurityDomainV2` tag order, which is exactly the domain order listed
above. Its digest is:

```text
SHA256(
  "savana.highest-ever.v2\0"
  || canonical_cbor(HighestEverV2)
)
```

For a normal installation:

- `BinaryRelease.sequence` is strictly greater than its highest-ever
  sequence;
- an unchanged domain repeats the exact previous tuple;
- a changed domain has a sequence strictly greater than that domain's
  highest-ever sequence;
- reuse of a sequence with another digest or key epoch is equivocation and
  causes fail-stop;
- no highest-ever entry ever decreases, including after rollback.

Every service receives the ledger and active manifest through the fixed
pre-opened descriptors or service-specific projection in section 16 and
validates:

- installation ID and ledger hash chain;
- active manifest digest and release signature;
- equality of the ledger and active manifest
  `bootstrap_tcb_lock_digest` values;
- all domain identities and highest-ever rules;
- complete artifact closure and file measurements;
- expected service identity, sandbox, entitlement, and code-integrity lock.

Before any such projection is made, the earliest boot gate independently
recomputes the complete selected `BootstrapSlotClosureV2`, verifies its
selector/marker/terminal-record chain, and requires
`DeploymentLedgerV2.bootstrap_tcb_lock_digest` and the active manifest's
complete canonical `BootstrapTcbLockDigest` to equal the closure's
`bootstrap_tcb_lock_digest` member. Neither the ledger nor the genesis record
contains the complete slot-closure digest, which would create a construction
cycle; the independently authenticated selector chain supplies that binding.
A cached copy is diagnostic only and cannot override the root ledger or the
selected slot closure.

`record_payload_digest` excludes only itself and its
`DomainSignatureV2` wrapper:

```text
SHA256(
  "savana.deployment-ledger.v2.record\0"
  || canonical_cbor(DeploymentLedgerV2 excluding
                    record_payload_digest and record_signature)
)
```

`record_signature` has domain `LedgerActivation = 5` and signs
`record_payload_digest` through `DomainSignatureInputV2`. Its key ID must equal
the record's `activation_key_id` and its epoch must equal
`installation_epoch`. The activation key is neither a release-signing key nor
a deployment-authorization key.

The complete signed ledger-record digest is:

```text
DeploymentLedgerRecordSignedDigest =
  SHA256("savana.deployment-ledger.v2.signed\0" ||
         canonical_cbor(complete DeploymentLedgerV2))
```

Every field named `genesis_ledger_record_digest` or
`new_genesis_ledger_record_digest` uses this complete signed digest.
`DeploymentLedgerV2.previous_record_digest`, dual-slot adjacency, and
transaction/evidence fields explicitly named `*_record_payload_digest`
continue to use `record_payload_digest`; the two digest classes are never
substitutable.

`transaction_head_digest` is tagged `None` only in the transaction-free
genesis `IDLE` record, the exact offline-created bridge-genesis
`BOOTSTRAP_BRIDGE` record, or an authenticated `IDLE` record produced by the
closed `ABORTED → IDLE` compaction below. Every transaction-bearing phase,
including `ABORTED`, `COMMITTED`, `ROLLED_BACK`, and `FAILED_SAFE`, contains
tagged `Some` with its exact final authenticated
`DurableDeploymentTransactionRecordV2` head and immutable core from section
15.3. Terminality never erases transaction provenance.

If no authenticated transaction/core exists—for example, both genesis slots
are invalid—the bootstrap gate reports an external boot-integrity failure and
starts no runtime service; it does not synthesize a `FAILED_SAFE` ledger
record with `None` provenance.

`ABORTED → IDLE` may clear the selected ledger field only after a signed,
flushed `EvidenceGcCheckpointV2` binds the final aborted head/core, terminal
ledger record, and predecessor-chain digest; the new `IDLE` record's
`previous_record_digest` names that exact `ABORTED` record. The referenced
head/core remain retained and reconstructible for audit and recovery. A
terminal head/core, its ancestry, or the checkpoint that preserves a compacted
`IDLE` provenance is not unreferenced GC material.

A bridge-origin `ABORTED → BOOTSTRAP_BRIDGE` transition never clears its
aborted head/core: the new fenced bridge record retains
`transaction_id = Some`, `transaction_head_digest = Some`, the unchanged
bridge active activation, and a burned unusable grant. A bridge restored
after `ARMED` similarly retains the final restore head/core and consumed
grant. Thus only the one offline bridge-genesis record has a `None` head.

The ledger phase, transaction ID, grant state, effects flag, and
`effect_fence_epoch` are one authenticated record. Each transition increments
`generation`. Every transition into `ARMED`, `ROLLBACK_PREPARED`,
`BRIDGE_RESTORE_PREPARED`, or `FAILED_SAFE`, and every change from fenced to
unfenced or unfenced to fenced, also increments `effect_fence_epoch`. Epoch
wrap is fail-stop.

The only phases from which a new transaction may enter `PREPARED` are
`IDLE`, `COMMITTED`, `ROLLED_BACK`, and `BOOTSTRAP_BRIDGE`. The last source is
legal only for an authorized bridge-exit attempt before the epoch's first
normal commit and its exact `BootstrapBridgeRestore` recovery target. A
normal-origin `ABORTED` is
compacted to `IDLE`; a bridge-origin `ABORTED` returns to fenced
`BOOTSTRAP_BRIDGE` without clearing provenance. A terminal
`ROLLED_BACK` record remains healthy and authoritative; it is never rewritten
to `IDLE` merely to report readiness.

## 4. Persistent-store compatibility

`ClosedStoreIdV2` is exactly:

```text
enum ClosedStoreIdV2 : u16 {
    KerneldVault = 1,
    KerneldProvenance = 2,
    KerneldReplay = 3,
    KerneldDispatch = 4,
    KerneldResult = 5,
    KerneldAudit = 6,
    ApprovaldWebAuthnCounter = 7,
    ApprovaldEnrollment = 8,
    ApprovaldRevocation = 9,
    ApprovaldSettlement = 10,
    ApprovaldReplay = 11,
    ExecdNonce = 12,
    ExecdEncryptedResult = 13,
    ExecdAcknowledgement = 14,
    ExecdConnectorJournal = 15,
    AgentdRecovery = 16,
    DeploymentLedger = 17,
    DeploymentEvidence = 18
}
```

There is no `Other`, numeric escape hatch, string store name, or
service-local reinterpretation. Every signed store set is strictly ordered by
these tags and covers each of the 18 members exactly once when the schema says
“every `ClosedStoreIdV2`.”

Operational stores are never package files and never roll back:

- kerneld vault, provenance, replay, dispatch, result, and audit stores;
- approvald WebAuthn counters, enrollment, revocation, settlement, and replay
  stores;
- execd nonce, encrypted result, acknowledgement, and connector journals;
- agentd durable public task/session recovery state;
- the deployment ledger and evidence records.

Every store has one manifest entry:

```text
InclusiveEpochRangeV2 {
    minimum: u64,
    maximum: u64
}

enum ClosedDigestRuleV2 : u16 {
    ExactCanonicalState = 1
}

PersistentStoreCompatibilityV2 {
    store_id: ClosedStoreIdV2,
    expected_current_schema_epoch: u64,
    desired_reader_range: InclusiveEpochRangeV2,
    desired_writer_range: InclusiveEpochRangeV2,
    rollback_reader_range: InclusiveEpochRangeV2,
    rollback_writer_range: InclusiveEpochRangeV2,
    migration_digest: Digest32,
    post_migration_state_digest_rule: ClosedDigestRuleV2,
    validator_artifact_digest: Digest32
}
```

Both epoch bounds are nonzero and `minimum <= maximum`. A range contains an
epoch only when `minimum <= epoch <= maximum`. `ExactCanonicalState` means
the service-specific validator hashes the complete canonical authenticated
post-migration store state under that store's compiled state-digest domain.
V2 has no caller-selected digest algorithm, projection, string rule, or
unknown enum fallback.

The exact digest of one declaration is
`SHA256("savana.persistent-store-compatibility.v2\0" ||
canonical_cbor(PersistentStoreCompatibilityV2))`; no store ID or reader range
may be projected out before hashing.

Cross-manifest reads of durable agent claims use the protocol companion's
exact closed schema:

```text
VaultKeyReadSetItemV2 {
    vault_key_role_tag: u16,
    key_id: VaultKeyIdV2,
    key_epoch: u64
}

AgentViewProjectionSetItemV2 {
    projection_field_tag: u16,
    projection_rule_digest: Digest32
}

enum AgentClaimCompatibilityDirectionV2 : u16 {
    FromOldManifestIntoDestinationReadOnly = 1
}

AgentClaimCompatibilityV2 {
    edge_id: Digest32,
    direction: AgentClaimCompatibilityDirectionV2 =
        FromOldManifestIntoDestinationReadOnly,
    from_manifest_lineage_digest: ManifestLineageDigestV2,
    to_manifest_lineage_digest: ManifestLineageDigestV2,
    logical_agentd_identity_digest: Digest32,
    from_agentd_code_identity_digest: Digest32,
    to_agentd_code_identity_digest: Digest32,
    from_kerneld_code_identity_digest: Digest32,
    to_kerneld_code_identity_digest: Digest32,
    from_protocol_lock_digest: Digest32,
    to_protocol_lock_digest: Digest32,
    protocol_abi_digest: Digest32,
    claim_schema_digest: Digest32,
    store_id: ClosedStoreIdV2,
    from_store_schema_epoch: u64,
    to_store_schema_epoch: u64,
    persistent_store_compatibility_digest: Digest32,
    vault_key_read_set: [VaultKeyReadSetItemV2],
    vault_key_read_set_digest: Digest32,
    agent_view_projection_set: [AgentViewProjectionSetItemV2],
    agent_view_projection_set_digest: Digest32,
    not_before_unix_ms: UnixMillis,
    expires_at_unix_ms: UnixMillis,
    edge_identity_digest: Digest32
}
```

The destination manifest's edge list is bounded by
`max_agent_claim_compatibility_edges`, strictly sorted by
`(direction, from_manifest_lineage_digest, to_manifest_lineage_digest,
logical_agentd_identity_digest, from_protocol_lock_digest,
to_protocol_lock_digest, claim_schema_digest, store_id, edge_id)`,
and contains no duplicate direction or semantic identity. Its
`edge_id` is
`SHA256("savana.agent-claim-compatibility.v2.id\0" ||
canonical_cbor([direction, from_manifest_lineage_digest,
to_manifest_lineage_digest,
logical_agentd_identity_digest, claim_schema_digest]))`. Its
`edge_identity_digest` is
`SHA256("savana.agent-claim-compatibility.v2.edge\0" ||
canonical_cbor(the preceding fields excluding edge_identity_digest))`. The
source and destination manifest digests, direction, same logical agentd
identity, both manifests' exact agentd and kerneld code identities, protocol
locks and compatible ABI, claim schema, store identity, old/new store epochs, exact
`PersistentStoreCompatibilityV2` digest, exact vault-key read items, exact
agent-view projection items, and closed validity interval must all match
current authenticated state. The two embedded item arrays are bounded,
respectively, by `max_agent_claim_vault_key_reads` and
`max_agent_claim_view_projections`, strictly sorted by their section 18.8
keys, duplicate-free, and recomputed through their registered set domains; a
verifier never trusts the opaque set digest without resolving the canonical
items. Source and destination
manifests must differ, `not_before_unix_ms < expires_at_unix_ms`, and the read
time—including the compiled skew bound—must lie inside that interval.

The default edge list is empty and cross-manifest claim read is denied.
Neither an overlapping reader range nor a matching agent name implies an
edge. Every nonempty edge is projected into the manifest component set and
therefore requires its own exact release-root component authorization and
component signature, with
`component_identity_digest = edge_identity_digest`, in addition to the
manifest release signature. An
expired, reverse-direction, wildcard, identity-renamed, ABI-only,
schema-only, broader-key, broader-view, out-of-window, or
store-digest-mismatched edge is rejected before vault access. No edge
authorizes claim mutation, resealing, key export, or evidence reuse.

This manifest-embedded `AgentClaimCompatibilityV2` is the sole wire and
authorization schema. It contains no standalone signature: its exact
`SecurityDomainObject` component binding and the manifest's release signature
authenticate it. The protocol companion directly references this type and
the edge's `to_protocol_lock_digest`, which must equal the destination
manifest's resolved protocol-lock digest; an independently signed
`SignedAgentClaimCompatibilityV2`, bare signature registry, alternate field
projection, or second edge-vector suite is nonconformant.

Manifest declarations alone are not compatibility proof. Before `ARMED`, the
helper coordinates a service write freeze and a filesystem-supported atomic
clone/snapshot of each actual production store. The non-root service validator
measures its authenticated header and schema state; the helper records the
signed result:

```text
ActualStoreStateV2 {
    store_id: ClosedStoreIdV2,
    source_filesystem_identity: Digest32,
    source_snapshot_identity: Digest32,
    authenticated_header_digest: Digest32,
    observed_schema_epoch: u64,
    observed_key_slot_set_digest: Digest32,
    observed_state_digest: Digest32
}

StoreCompatibilityAttestationV2 {
    schema_version: u16 = 2,
    transaction_intent_digest: Digest32,
    installation_id: Digest32,
    ledger_generation: u64,
    manifest_digest: Digest32,
    logical_data_origin_manifest_digest: Digest32,
    recovery_target_digest: Digest32,
    actual_store_state_set_digest: Digest32,
    desired_copy_validation_result_digest: Digest32,
    recovery_validation_result: RecoveryValidationResultV2,
    migration_simulation_result_digest: Digest32,
    validator_set_digest: Digest32,
    completed_at_unix_ms: UnixMillis,
    activation_key_id: Ed25519KeyIdV2,
    signature: DomainSignatureV2
}

enum RecoveryValidationResultV2 : u16 {
    NormalRollbackManifest = 1 {
        rollback_copy_validation_result_digest: Digest32
    },
    BootstrapBridgeRestore = 2 {
        unchanged_store_and_journal_integrity_result_digest: Digest32,
        native_effect_fence_measurement_digest: Digest32
    }
}
```

Its payload digest is
`SHA256("savana.store-compatibility.v2.payload\0" ||
canonical_cbor(StoreCompatibilityAttestationV2 excluding its signature
wrapper))`; the wrapper is exactly `StoreCompatibility = 8`, signed by the
record's activation key/epoch through `DomainSignatureInputV2`.

Each service-specific validator runs as that service's non-root UID in a
networkless, effect-fenced sandbox. It receives only a pre-opened descriptor
for its private copy-on-write clone and the exact non-exportable production
service key handles required to open that clone, constrained by the normal
service UID/code identity. It has no path access to the source
store, another service's copy, production endpoints, or release/deployment
keys. It must open, scan, validate, simulate the desired migration, perform a
bounded write/read/recovery cycle, and then repeat rollback reader/writer
validation on the resulting copy. The helper only measures and coordinates;
it does not substitute a root parser for the non-root service validator.

The attestation covers every `ClosedStoreIdV2` exactly once. A changed source
snapshot, store header, key-slot set, validator, desired manifest, logical
data-origin manifest, recovery target, or ledger generation invalidates it
and forces a new preflight. For an ordinary transaction the logical origin is
the expected pre-active normal manifest. For any authorized bridge-exit
attempt before the epoch's first normal commit, it is the retained
pre-maintenance normal manifest named by the
`BootstrapBridgeRestore` branch; the never-executed bridge is not a store
contract. The validation-result union tag must equal the recovery-target tag.
The normal branch runs the rollback manifest's reader/writer clone. The
bridge branch cannot run bridge services; instead its two fixed result
digests cover the unchanged authenticated operational-store headers/key-slot
sets, exact role-owned journal heads, absence of a new external effect, and
the already installed native effect fence. An arbitrary “success” digest or
normal rollback-readiness result cannot fill that branch. Migrations in every
rollback-capable or bridge-restorable
transaction are expand-only and non-destructive. A destructive or contract
migration requires a later normal transaction whose normal rollback release
already supports the contracted schema.

Immediately before `ARMED`, services enter a bounded write freeze and the
non-root validators remeasure the actual-store set; the helper compares their
signed set against the attestation. This freeze is not a process-local
boolean: the helper's exclusive POSIX EffectGate has drained every agentd
planner/kernel-dispatch/kernel-release guard and every execd dispatch guard;
the service manager stops the exact manifest service set; pidfd/audit-token
checks prove those processes and descendants exited; and no source-store write
descriptor or writer lock remains. A mismatch returns to preflight. A match
keeps this native admission barrier through `QUIESCED` and store migration, so
no write or new `PrepareEffect` WAL admission can enter between the proven
snapshot and cutover.

Private keys are not package files. Key rotation is valid only when:

- in a normal-recovery transaction, desired and rollback key slots are
  already provisioned and both public identities are bound by their complete
  manifests;
- in a bridge-recovery transaction, desired normal key slots are freshly
  provisioned as authorized, while the bridge has no usable runtime private
  key and restore never opens one;
- deletion of the old slot is deferred until a later committed transaction;
- parser and connector workers never receive persistent key material.

## 5. Deployment transaction

The helper accepts exactly one canonical-CBOR descriptor:

```text
enum DeploymentRecoveryTargetV2 : u16 {
    NormalRollbackManifest = 1 {
        rollback_manifest_digest: Digest32
    },
    BootstrapBridgeRestore = 2 {
        bridge_manifest_digest: Digest32,
        maintenance_intent_signed_digest: Digest32,
        bridge_genesis_ledger_record_signed_digest: Digest32,
        bootstrap_slot_closure_digest: Digest32,
        premaintenance_runtime_manifest_digest: Digest32
    }
}

TransactionIntentV2 {
    schema_version: u16 = 2,
    domain_tag: ClosedDeploymentObjectDomainV2 =
        DeploymentTransactionIntent,

    transaction_id: Nonce32,
    installation_id: Digest32,

    target_platform: PlatformLockV2,
    evidence_trust_policy_digest: Digest32,
    evidence_layer_limits_digest: Digest32,
    source_evidence_digest: Digest32,
    artifact_evidence_digest: Digest32,
    created_at_unix_ms: UnixMillis,
    not_before_unix_ms: UnixMillis,
    expires_at_unix_ms: UnixMillis,
    maximum_prepare_duration_ns: DurationNanos,
    maximum_cutover_duration_ns: DurationNanos,
    maximum_boot_recovery_duration_ns: DurationNanos,
    maximum_clock_skew_ns: DurationNanos,

    expected_pre_state: ExpectedPreStateV2,
    staging_tree_digest: Digest32,
    desired_manifest_digest: Digest32,
    recovery_target: DeploymentRecoveryTargetV2,

    migration_plan_digest: Digest32,
    artifact_install_plan_digest: Digest32,
    service_transition_plan_digest: Digest32,
    isolated_e2e_plan_digest: Digest32,
    evidence_contract_digest: Digest32,
    protected_acceptance_plan_digest: Digest32
}

DeploymentTransactionV2 {
    intent: TransactionIntentV2,
    transaction_intent_digest: Digest32,
    rollback_grant: RollbackGrantV2,
    transaction_payload_digest: Digest32,
    authorization_signature: DomainSignatureV2
}
```

```text
ExpectedPreStateV2 {
    ledger_generation: u64,
    ledger_record_payload_digest: Digest32,
    phase: DeploymentPhaseV2,
    active_activation: ActiveActivationV2,
    effects_fenced: bool,
    active_manifest_digest: Digest32,
    highest_ever_digest: Digest32,
    install_identity_profile_signed_digest: Digest32,
    deploy_helper_identity: ArtifactIdentityV2,
    deploy_watchdog_identity: ArtifactIdentityV2,
    deployment_trust_root_set_digest: Digest32,
    activation_trust_root_set_digest: Digest32,
    release_trust_root_set_digest: Digest32,
    bootstrap_slot_closure_digest: Digest32,
    installation_epoch: u64,
    effect_fence_epoch: u64
}
```

The recovery-target digest used by grants, store validation, evidence, and
durable heads is exactly:

```text
DeploymentRecoveryTargetDigestV2 =
  SHA256("savana.deployment-recovery-target.v2\0" ||
         canonical_cbor(DeploymentRecoveryTargetV2))
```

`NormalRollbackManifest` is mandatory for every ordinary pre-state and opens
exactly one complete signed `NormalApplication` manifest in the durable
transaction core. `BootstrapBridgeRestore` is legal only when the selected
pre-state phase is `BOOTSTRAP_BRIDGE`, its active activation is the exact
`BootstrapBridge` tuple named by the branch, no normal commit has occurred in
that epoch, and the desired manifest is a complete `NormalApplication`. Its
five digests
must resolve through the selected selector/slot closure, maintenance intent,
bridge genesis ledger, and retained pre-maintenance normal manifest. No
caller can choose this branch after a normal activation or point it at
another bridge.

The three `*_trust_root_set_digest` fields above are current-domain
member-set projections, not `VersionedIdentityV2.content_digest` values. The
helper resolves the complete signed deployment, activation, and release
root-set objects through the selected `BootstrapTcbLockV2`, recomputes their
three registered current-domain member digests, and requires exact equality
with `ExpectedPreStateV2` and the authenticated active state before
authorization lookup. A member digest cannot select a different complete
object with a mismatched sequence, signer, validity interval, predecessor, or
signed-object digest.

All four ledger-state fields are exact authorization inputs, not advisory
copies. The helper authenticates the selected ledger slot and requires its
generation, record payload digest, phase, complete tagged active-activation
value, effects flag, effect-fence epoch, active manifest, and highest-ever
digest to byte-equal `ExpectedPreStateV2` before grant or transaction
authorization lookup.

`transaction_id` is a cryptographically random `Nonce32`, generated before
authorization. It is never derived from a descriptor, signature, clock, path,
counter, or grant. A transaction ID already bound to another intent is
rejected; reuse with the same intent is accepted only as idempotent recovery
of that currently nonterminal ledger transaction. Every historical descriptor
also binds the exact pre-generation and installation epoch, so evidence GC
cannot make an old transaction replayable.

`transaction_intent_digest` is:

```text
SHA256(
  "savana.deployment-transaction.v2.intent\0"
  || canonical_cbor(TransactionIntentV2)
)
```

The rollback grant binds `transaction_intent_digest`; the intent does not
contain the grant. Its repeated `transaction_id` must byte-equal
`TransactionIntentV2.transaction_id`; it is the same random nonce, not a hash
of the transaction. No grant field references `transaction_payload_digest`.
The complete signed payload digest is:

```text
SHA256(
  "savana.deployment-transaction.v2.payload\0"
  || canonical_cbor([
       TransactionIntentV2,
       transaction_intent_digest,
       RollbackGrantV2
     ])
)
```

`transaction_payload_digest` equals that value. The authorization wrapper is
exactly `TransactionAuthorization = 3` and signs that digest through
`DomainSignatureInputV2`. Its key ID/epoch must resolve in the immutable
deployment trust-root set named by `ExpectedPreStateV2`.

Thus no digest contains itself and no authorization digest contains the
authorization signature that authenticates it.

Component and release signatures authorize artifact authenticity. They do not
authorize activation on a particular host. The transaction authorization
additionally binds:

- installation ID and exact expected ledger pre-state;
- exact evidence trust policy, limits, source evidence, and artifact evidence;
- desired manifest and the exact closed recovery-target branch;
- staging tree and random transaction ID;
- time window and platform lock;
- migration, artifact-install, service-transition, isolated-E2E,
  protected-acceptance, and evidence-contract plans;
- current helper, watchdog, install-identity, and trust-root identities.

No field is optional. Unknown fields, extension maps, caller-defined
operations, paths, commands, scripts, environment entries, service names, or
partial closures are rejected.

Before `PREPARED`, the helper validates the complete section 18 source→artifact
chain. The artifact evidence must bind exactly the intent's source-evidence
digest and embed the desired manifest; its trust-policy and limits digests
must equal the intent, and the manifest's
`completion_evidence_trust_policy` must identify that exact signed policy
whose limits digest is the same value. No platform, review, or product
evidence is accepted as transaction input.

Before `ARMED`, every relevant validity interval has at least:

```text
maximum_prepare_duration_ns
+ maximum_cutover_duration_ns
+ maximum_boot_recovery_duration_ns
+ maximum_clock_skew_ns
```

remaining.

### 5.1 Exact staging digest

`staging_tree_digest` intentionally excludes the fixed descriptor
`DeploymentTransactionV2.cbor`. It covers every other entry under the opened
ready-directory descriptor:

`ClosedStagingPathIdV2` is exact:

| Tags | Exact members in ascending tag order |
|---|---|
| 1–7 | `MigrationPlan`, `ArtifactInstallPlan`, `ServiceTransitionPlan`, `IsolatedE2EPlan`, `EvidenceContract`, `ProtectedAcceptancePlan`, `ArtifactPayloadRoot` |
| 10–19 | `JarvisExecutable`, `AgentdExecutable`, `IngressdExecutable`, `KerneldExecutable`, `ApprovaldExecutable`, `ExecdExecutable`, `ApprovalctlExecutable`, `WorkerSandboxExecutable`, `ParserWorkerExecutable`, `ConnectorWorkerExecutable` |
| 20–24 | `AgentdConfig`, `IngressdConfig`, `KerneldConfig`, `ApprovaldConfig`, `ExecdConfig` |
| 25–33 | `KerneldServiceDefinition`, `KerneldAgentEndpointDefinition`, `KerneldIngressEndpointDefinition`, `AgentdServiceDefinition`, `AgentdControlEndpointDefinition`, `AgentdJarvisHttpEndpointDefinition`, `AgentdAgentHttpEndpointDefinition`, `IngressdServiceDefinition`, `IngressdHttpEndpointDefinition` |
| 34–41 | `ApprovaldServiceDefinition`, `ApprovaldAgentEndpointDefinition`, `ApprovaldIngressEndpointDefinition`, `ApprovaldAdminEndpointDefinition`, `ApprovaldHttpEndpointDefinition`, `ExecdServiceDefinition`, `ExecdEndpointDefinition`, `KernelTargetDefinition` |
| 42–44 | `ParserSandboxProfile`, `ConnectorNoNetworkSandboxProfile`, `ConnectorCredentialAbsenceProfile` |

Tags `8`, `9`, values above `44`, and every bootstrap-owned logical path are
unassigned. The six plan entries and the single `ArtifactPayloadRoot`
directory occur exactly once as the first seven entries. At least one
artifact payload follows. All entries are strictly ordered by tag and
duplicate-free.

```text
StagingEntryV2 {
    logical_path_id: ClosedStagingPathIdV2,
    entry_kind: FileTreeEntryKindV2,
    size: u64,
    sha256: Digest32,
    owner: ROOT,
    group: ROOT,
    mode: u32,
    acl_digest: Digest32,
    xattr_digest: Digest32
}

staging_tree_digest =
  MerkleRootV2(
    "savana.staging-tree.v2",
    canonical_order(all staging entries except
                    DeploymentTransactionV2.cbor)
  )
```

`MerkleRootV2` uses the exact indexed leaf, binary node, odd-child, entry
count, and root rules in section 2.7 with the supplied domain prefix. The
ready directory contains exactly the descriptor plus the covered entries.
There is no ignored metadata, platform-generated file, sidecar, or implicit
directory.

### 5.2 Closed plan schemas

Every plan digest references one canonical object stored at a compiled staging
logical path. Plan objects are data, never programs:

```text
MigrationPlanV2 {
    steps: [MigrationStepV2]
}

enum MigrationStepV2 : u16 {
    AssertStoreEpoch = 1 {
        store_id: ClosedStoreIdV2,
        expected_epoch: u64
    },
    ExpandSchema = 2 {
        store_id: ClosedStoreIdV2,
        from_epoch: u64,
        to_epoch: u64,
        migration_artifact_digest: Digest32
    },
    ProvisionKeySlot = 3 {
        store_id: ClosedStoreIdV2,
        closed_slot_id: Digest32
    }
}

ArtifactInstallPlanV2 {
    operations: [ArtifactInstallOperationV2]
}

enum ArtifactInstallOperationV2 : u16 {
    MaterializeFile = 1 { logical_path_id: ClosedLogicalPathIdV2 },
    MaterializeDirectory = 2 { logical_path_id: ClosedLogicalPathIdV2 },
    VerifyNativeIdentity = 3 { logical_path_id: ClosedLogicalPathIdV2 }
}

ServiceTransitionPlanV2 {
    stop_order: [ClosedServiceIdV2],
    candidate_start_order: [ClosedServiceIdV2],
    rollback_start_order: [ClosedServiceIdV2],
    readiness_order: [ClosedServiceIdV2]
}

enum ClosedServiceIdV2 : u16 {
    Jarvis = 1,
    Agentd = 2,
    Ingressd = 3,
    Kerneld = 4,
    Approvald = 5,
    Execd = 6,
    ParserWorkerTemplate = 7,
    ConnectorWorkerTemplate = 8
}

IsolatedE2EPlanV2 {
    cases: [ClosedE2ECaseV2],
    planner_fixture_digest: Digest32,
    connector_fixture_digest: Digest32,
    isolation_profile_digest: Digest32
}

enum ClosedE2ECaseV2 : u16 {
    CanonicalHandshake = 1,
    SensitiveTransport = 2,
    InputProjection = 3,
    PlannerProjection = 4,
    ApprovalApprove = 5,
    ApprovalDeny = 6,
    WebAuthnUvCounterReplay = 7,
    GatesG1ThroughG7 = 8,
    ExactOnceIntent = 9,
    ExecutorNonce = 10,
    RawResultContainment = 11,
    ResultAcknowledgement = 12,
    CrashRecoveryNoReplay = 13,
    CrossRoleRejection = 14,
    V1Rejection = 15,
    NativeControlMeasurement = 16
}

EvidenceContractV2 {
    required_verification_fields: [ClosedVerificationFieldV2],
    required_commit_fields: [ClosedCommitFieldV2],
    required_review_count: u16,
    required_execution_platforms: [PlatformTupleV2],
    retention_class: ClosedEvidenceRetentionClassV2
}

ProtectedAcceptancePlanV2 {
    cases: [ClosedProtectedAcceptanceCaseV2],
    isolation_profile_digest: Digest32,
    controlled_sink_identity_digest: Digest32
}

enum ClosedProtectedAcceptanceCaseV2 : u16 {
    RealKeystoreAcl = 1,
    NonEmptyStoreOpen = 2,
    ExistingStateRecovery = 3,
    CanaryApproval = 4,
    CanaryDispatch = 5,
    CanaryExecutorNonce = 6,
    ControlledSinkReceipt = 7,
    ResultGateAndAcknowledgement = 8,
    RestartNoReplay = 9,
    SourceStoreUnchanged = 10,
    CloneDestroyed = 11
}

enum ClosedVerificationFieldV2 : u16 {
    StoreCompatibility = 1,
    NativeControls = 2,
    IsolatedE2E = 3,
    ProtectedAcceptance = 4,
    ServiceReadiness = 5,
    RollbackExercise = 6,
    LegacyAbsence = 7,
    CanonicalVectors = 8,
    NegativeTests = 9
}

enum ClosedCommitFieldV2 : u16 {
    VerificationEvidence = 1,
    CommittedLedgerRecord = 2,
    BurnedRollbackGrant = 3,
    UnfencedGeneration = 4,
    ActiveManifest = 5,
    HighestEver = 6,
    InstallationEpochAttestation = 7
}

enum ClosedEvidenceRetentionClassV2 : u16 {
    NormalBounded = 1,
    SignedLegalHoldMetadataOnly = 2
}

enum ClosedOsV2 : u16 {
    Linux = 1,
    MacOS = 2
}

enum ClosedArchitectureV2 : u16 {
    X86_64 = 1,
    AArch64 = 2
}

PlatformTupleV2 {
    os: ClosedOsV2,
    architecture: ClosedArchitectureV2
}
```

All staging entries are root/root. Plan and artifact payload files have mode
`0600`; `ArtifactPayloadRoot` is the sole directory and has mode `0700`,
zero size, and the all-zero file digest. Every regular file has nonzero size
and digest, each plan is bounded by `max_plan_bytes`, each payload by
`max_single_artifact_bytes`, and their checked total is bounded by
`max_staging_tree_bytes`. ACL and xattr digests are always nonzero, including
the registered digest for an empty set.

For `BootstrapBridgeRestore`, `ServiceTransitionPlanV2.stop_order` and
`.rollback_start_order` are exactly empty because no runtime service may
exist in the authenticated bridge pre-state and no bridge service may ever be
started. `candidate_start_order` and `readiness_order` enumerate only the
desired normal manifest's exact service DAG and are used solely in fenced
candidate verification. Bridge restore may materialize and verify the
retained bridge file closure, but it performs no service start/readiness,
isolated E2E, protected acceptance, planner call, or connector call. A
nonempty bridge stop/rollback-start order or a bridge identity in either
candidate list is rejected before `PREPARED`.

All arrays are bounded by `DeploymentHardLimitsV2`, duplicate-free, and in
their declared canonical order. The required case sets, service dependency
order, allowed epoch transitions, and evidence fields are compiled closed
tables. Unknown operations, strings interpreted as commands, executable
plugins, hooks, shell fragments, arbitrary arguments, dynamic services, and
dynamic fixture endpoints are rejected.

Migration steps are strictly ordered by
`(u16_be(store_id), u16_be(step_tag), typed fields in declared big-endian
order)` and therefore duplicate-free. Schema migration is expand-only
(`to_epoch > from_epoch > 0`), every store tag is in the 18-member registry,
and artifact/key-slot digests are nonzero. The normal artifact-install plan
is not a partial patch: it contains the five directory materializations in
logical-path order, then for each of logical paths 6–40 a
`MaterializeFile` immediately followed by `VerifyNativeIdentity`. This is
exactly 75 operations. Reordering, omission, duplication, or any
bootstrap-owned path is rejection.

Each plan digest is:

```text
SHA256(
  plan_domain
  || canonical_cbor(the complete plan object)
)
```

where `plan_domain` is exactly one of:

```text
"savana.migration-plan.v2\0"
"savana.artifact-install-plan.v2\0"
"savana.service-transition-plan.v2\0"
"savana.isolated-e2e-plan.v2\0"
"savana.evidence-contract.v2\0"
"savana.protected-acceptance-plan.v2\0"
```

The descriptor field and staging logical path determine the expected domain;
a digest from one plan domain cannot fill another field.

## 6. Rollback grant and complete rollback closure

Rollback does not lower high-water state. It consumes one exact prearmed grant:

```text
RollbackGrantV2 {
    schema_version: u16 = 2,
    domain_tag: ClosedDeploymentObjectDomainV2 = RollbackGrant,
    grant_id: Digest32,
    transaction_id: Nonce32,
    transaction_intent_digest: Digest32,
    installation_id: Digest32,
    installation_epoch: u64,
    expected_pre_active_manifest_digest: Digest32,
    attempted_manifest_digest: Digest32,
    recovery_target_digest: Digest32,
    phase_highwater: RecoveryPhaseHighWaterV2,
    expected_install_identity_profile_signed_digest: Digest32,
    issued_at_unix_ms: UnixMillis,
    not_before_unix_ms: UnixMillis,
    arm_expires_at_unix_ms: UnixMillis,
    rollback_support_until_unix_ms: UnixMillis,
    maximum_cutover_duration_ns: DurationNanos,
    maximum_boot_recovery_duration_ns: DurationNanos,
    signature: DomainSignatureV2
}

RollbackPhaseHighWaterV2 {
    prepared_digest: Digest32,
    armed_digest: Digest32,
    quiesced_digest: Digest32,
    installed_digest: Digest32,
    verified_digest: Digest32,
    rollback_prepared_from_armed_digest: Digest32,
    rollback_prepared_from_quiesced_digest: Digest32,
    rollback_prepared_from_installed_digest: Digest32,
    rollback_prepared_from_verified_digest: Digest32,
    rollback_installed_from_armed_digest: Digest32,
    rollback_installed_from_quiesced_digest: Digest32,
    rollback_installed_from_installed_digest: Digest32,
    rollback_installed_from_verified_digest: Digest32,
    rollback_verified_from_armed_digest: Digest32,
    rollback_verified_from_quiesced_digest: Digest32,
    rollback_verified_from_installed_digest: Digest32,
    rollback_verified_from_verified_digest: Digest32,
    rolled_back_from_armed_digest: Digest32,
    rolled_back_from_quiesced_digest: Digest32,
    rolled_back_from_installed_digest: Digest32,
    rolled_back_from_verified_digest: Digest32
}

BootstrapBridgeRestorePhaseHighWaterV2 {
    prepared_digest: Digest32,
    armed_digest: Digest32,
    quiesced_digest: Digest32,
    installed_digest: Digest32,
    verified_digest: Digest32,
    restore_prepared_from_armed_digest: Digest32,
    restore_prepared_from_quiesced_digest: Digest32,
    restore_prepared_from_installed_digest: Digest32,
    restore_prepared_from_verified_digest: Digest32,
    restore_installed_from_armed_digest: Digest32,
    restore_installed_from_quiesced_digest: Digest32,
    restore_installed_from_installed_digest: Digest32,
    restore_installed_from_verified_digest: Digest32,
    restore_verified_from_armed_digest: Digest32,
    restore_verified_from_quiesced_digest: Digest32,
    restore_verified_from_installed_digest: Digest32,
    restore_verified_from_verified_digest: Digest32,
    restored_bridge_from_armed_digest: Digest32,
    restored_bridge_from_quiesced_digest: Digest32,
    restored_bridge_from_installed_digest: Digest32,
    restored_bridge_from_verified_digest: Digest32
}

enum RecoveryPhaseHighWaterV2 : u16 {
    NormalRollback = 1 {
        values: RollbackPhaseHighWaterV2
    },
    BootstrapBridgeRestore = 2 {
        values: BootstrapBridgeRestorePhaseHighWaterV2
    }
}
```

Despite the retained wire name, `RollbackGrantV2` authorizes exactly one
closed recovery target. Its `recovery_target_digest` must equal
`DeploymentRecoveryTargetDigestV2` from the signed intent. The
`NormalRollbackManifest` branch follows the ordinary rollback state machine.
The `BootstrapBridgeRestore` branch is usable only for the first
bridge-origin transaction and follows the separate fenced bridge-restore
state machine in section 15; it can never authorize `ROLLED_BACK`, readiness,
or completion evidence.

Every grant alias is exact:
`expected_pre_active_manifest_digest =
intent.expected_pre_state.active_manifest_digest`,
`attempted_manifest_digest = intent.desired_manifest_digest`,
`expected_install_identity_profile_signed_digest =
intent.expected_pre_state.install_identity_profile_signed_digest`, and the
grant's transaction ID, installation ID/epoch, time/duration bounds, and
recovery-target digest equal the corresponding signed intent values. For a
bridge origin, the pre-active digest is the bridge; it is never replaced by
the retained logical-data-origin normal manifest.

The grant:

- has `grant_id = SHA256("savana.rollback-grant.v2.id\0" ||
  canonical_cbor(grant excluding grant_id and its signature wrapper))`;
- has exactly one `RollbackGrant = 4` wrapper signing `grant_id` through
  `DomainSignatureInputV2`;
- is included in the transaction payload and binds the exact
  `transaction_intent_digest`;
- is persisted before the transaction enters `ARMED`;
- is usable only by the root helper/watchdog;
- is usable only for its exact transaction and installation;
- is usable only before `COMMITTED`;
- may recover only the exact signed `DeploymentRecoveryTargetV2`; the normal
  branch activates its rollback manifest, while the bridge branch restores
  only the same non-executable fenced bridge;
- is consumed at most once.

The phase-high-water union tag must equal the recovery-target tag. For each
phase and recovery origin, the ledger's `highest_ever` digest equals the
corresponding field before a transition is allowed. `PREPARED`, `ARMED`, and
`QUIESCED` bind the pre-install high-water; `INSTALLED` and `VERIFIED` bind
the post-attempt high-water. The normal branch uses the four
`ROLLBACK_*`/`ROLLED_BACK` origin-specific groups. The bridge branch uses the
four `BRIDGE_RESTORE_*`/restored-`BOOTSTRAP_BRIDGE` groups. An origin before
`INSTALLED` retains the pre-install vector; an origin at `INSTALLED` or
`VERIFIED` retains the post-attempt vector through every restore phase and
the final bridge. No recovery lowers high-water and no phase is overloaded
with an implicit value.

`arm_expires_at_unix_ms` controls entry to `ARMED`.
`rollback_support_until_unix_ms` is the signed minimum retention and
compatibility horizon for the rollback manifest, validator, helper/watchdog,
trust material, key slots, and store reader/writer contract. It must be at
least:

```text
arm_expires_at_unix_ms
+ ceil(maximum_cutover_duration_ns / 1_000_000)
+ ceil(maximum_boot_recovery_duration_ns / 1_000_000)
+ ceil(maximum_clock_skew_ns / 1_000_000)
```

No transaction may arm unless all of those dependencies have validity and
retention guarantees through that instant. After arming, actual rollback
availability does not depend on a wall-clock check: suspension, clock change,
or power loss cannot make recovery unable to consume the already armed grant.
The support timestamp is an admission and retention obligation, not a
post-failure rejection condition.

The `NormalRollbackManifest` branch begins by durably changing the grant from
`Prearmed` to `Consuming`
at `ROLLBACK_PREPARED`; file installation and verification then advance through
`ROLLBACK_INSTALLED` and `ROLLBACK_VERIFIED`. Entry to final `ROLLED_BACK`
atomically records:

- the exact rollback manifest as active;
- `ConsumedRollback { failed_transaction_id, rollback_grant_id }`;
- the grant as `Consumed`;
- the origin-specific highest-ever entries unchanged.

The consumed activation may boot repeatedly until a later normal install. It
does not permit a second grant consumption. A later normal install is compared
against highest-ever, never against the lower active rollback identity.

`COMMITTED` atomically burns the grant before the external-effect fence is
removed. A committed transaction cannot later roll back through that grant.

In the `BootstrapBridgeRestore` branch, consumption begins only at
`BRIDGE_RESTORE_PREPARED`; exact bridge closure restoration and the
non-readiness integrity check advance through `BRIDGE_RESTORE_INSTALLED` and
`BRIDGE_RESTORE_VERIFIED`. The terminal fenced `BOOTSTRAP_BRIDGE` record
consumes the grant, names the same bridge, retains the origin-specific
highest-ever vector, and records `BootstrapBridgeRestoreProvenanceV2`. It
activates no runtime and creates no rollback/platform evidence.

For the normal branch, both desired and rollback manifests are complete. For
every file changed by
the desired manifest, rollback must:

1. restore an exact entry from the rollback manifest; or
2. install a strictly newer signed forward-rollback entry accepted by the
   rollback binaries.

“Keep the currently installed file,” a partial rollback list, or restoration
of an old operational database is invalid.

## 7. Root-only invocation and staging

`savana-deploy` and `savana-deploy-watchdog` are root-owned mode `0500`. They:

- are not setuid;
- expose no polkit, Authorization Services, launchd Mach, D-Bus, UDS, HTTP,
  stdin command, or other privilege-broker endpoint;
- reject `euid != 0` before parsing a descriptor;
- have no network capability and perform no download.

The only nonconstant argument to `savana-deploy apply` is one lowercase
64-hex `staging_id`.

The helper opens:

```text
Linux:
  /var/lib/savana-deploy/spool/ready/<staging_id>/

macOS:
  /Library/Application Support/Savana/Deployment/spool/ready/<staging_id>/
```

The descriptor filename is fixed:

```text
DeploymentTransactionV2.cbor
```

`staging_id` must equal the section 5.1 `staging_tree_digest`, whose explicit
exclusion of `DeploymentTransactionV2.cbor` prevents a digest cycle. No
descriptor or source path is accepted through argv, stdin, environment, cwd,
IPC, or inherited descriptors.

The spool and every ancestor are root-owned mode `0700`, local,
non-user-writable, and on the supported deployment filesystem. Only the signed
OS-native installer running as root may populate `spool/incoming`. It verifies
the complete staged tree and atomically renames it to
`spool/ready/<staging_id>`.

The helper:

- sets `umask(0077)`;
- changes cwd to `/`;
- clears the environment;
- closes every inherited descriptor except fixed standard error;
- never invokes a shell;
- uses compiled service IDs and fixed absolute service-manager APIs;
- resolves files from trusted directory descriptors with no-follow,
  beneath-only, and no-cross-device semantics;
- rejects symlinks, hardlinks where `st_nlink != 1`, devices, FIFOs, sockets,
  mount crossings, setuid/setgid bits, capabilities, unknown ACL/xattr
  entries, sparse-size mismatches, and unknown members;
- rechecks identity, type, owner, mode, size, digest, signature, code
  integrity, ACL, and xattr after opening and immediately before installation;
- never parses or reads runtime user data, service private keys, planner/tool
  credentials, WebAuthn secret state, vault records, or service-database
  contents. It may use only the fixed OS snapshot/clone API and pre-opened
  directory descriptors needed to coordinate section 4; content parsing and
  key use remain inside the non-root service validator.

`identity-state.ref`, when present at its compiled logical path, is a
fixed-grammar non-secret platform-keystore slot locator. Its digest is bound by
the transaction and manifest. It cannot be a filesystem path, bearer token,
private-key export, arbitrary provider URI, or caller-defined string.

## 8. Offline bootstrap TCB maintenance

V2 has no online bootstrap-update descriptor, decoder, helper verb, IPC
endpoint, service-manager action, or transaction surface. In particular,
`DeploymentTransactionV2` cannot modify:

- `savana-deploy`;
- `savana-deploy-watchdog`;
- deployment trust roots;
- the deployment-authorization verification key;
- deployment ledger code, schema authority, or location.

They may be maintained only by a separately signed OS-native package while
the machine is in offline maintenance mode. The package manager must prove
that JARVIS, every Savana service, every worker, `savana-deploy`, and
`savana-deploy-watchdog` are stopped; networking is deny-all; no application
transaction is nonterminal; and no executable from the old bootstrap TCB is
running. Neither the current helper nor its watchdog participates.

The offline wire objects are:

```text
enum BootstrapSlotIdV2 : u16 {
    A = 1,
    B = 2
}

enum BootstrapMaintenancePhaseV2 : u16 {
    Prepared = 1,
    FilesStaged = 2,
    RootsStaged = 3,
    KeystoreStaged = 4,
    IdentityProfileStaged = 5,
    GenesisStaged = 6,
    CommitMarkerDurable = 7,
    SelectorSwitched = 8,
    PostSwitchVerified = 9,
    Completed = 10,
    RollbackPrepared = 11,
    RolledBack = 12,
    FailedSafe = 13
}

BootstrapRoleTerminalHeadV2 {
    owning_service: ClosedServiceIdV2,
    durable_operation_id: Digest32,
    authenticated_head_signed_digest: Digest32,
    terminal_state_tag: u16
}

BootstrapEffectWorkQuiescenceV2 {
    selected_old_ledger_record_signed_digest: Digest32,
    role_terminal_heads: [BootstrapRoleTerminalHeadV2],
    nonterminal_work_count: u64 = 0
}

BootstrapMaintenanceIntentPayloadV2 {
    schema_version: u16 = 2,
    domain_tag: ClosedDeploymentObjectDomainV2 =
        BootstrapMaintenanceIntent,
    maintenance_id: Nonce32,
    product_family_digest: Digest32,
    package_identity_digest: Digest32,
    package_sequence: u64,
    previous_package_sequence: u64,
    installation_id: Digest32,
    old_installation_epoch: u64,
    new_installation_epoch: u64,
    old_active_slot: BootstrapSlotIdV2,
    new_inactive_slot: BootstrapSlotIdV2,
    old_bootstrap_tcb_lock: BootstrapTcbLockV2,
    new_bootstrap_tcb_lock: BootstrapTcbLockV2,
    old_bootstrap_file_tree_root: Digest32,
    new_bootstrap_file_tree_root: Digest32,
    old_deployment_trust_root_set_digest: Digest32,
    new_deployment_trust_root_set_digest: Digest32,
    old_activation_trust_root_set_digest: Digest32,
    new_activation_trust_root_set_digest: Digest32,
    old_release_trust_root_set_digest: Digest32,
    new_release_trust_root_set_digest: Digest32,
    expected_previous_maintenance_terminal_record_digest:
        None | Digest32,
    expected_previous_maintenance_record_sequence: u64,
    expected_maintenance_head_generation: u64,
    expected_maintenance_head_signed_digest: None | Digest32,
    expected_active_selector_signed_digest: Digest32,
    expected_selector_generation: u64,
    expected_last_ledger_generation: u64,
    expected_last_ledger_record_signed_digest: Digest32,
    expected_last_ledger_record_payload_digest: Digest32,
    expected_old_active_manifest_digest: Digest32,
    new_epoch_bridge_manifest_digest: Digest32,
    expected_highest_ever_digest: Digest32,
    expected_actual_store_state_set_digest: Digest32,
    expected_effect_work_quiescence: BootstrapEffectWorkQuiescenceV2,
    created_at_unix_ms: UnixMillis,
    not_before_unix_ms: UnixMillis,
    expires_at_unix_ms: UnixMillis
}

BootstrapMaintenanceIntentV2 {
    payload: BootstrapMaintenanceIntentPayloadV2,
    payload_digest: Digest32,
    installer_or_mdm_signature: DomainSignatureV2
}

BootstrapMaintenanceRecordPayloadV2 {
    schema_version: u16 = 2,
    installation_id: Digest32,
    maintenance_intent_digest: Digest32,
    package_sequence: u64,
    record_sequence: u64,
    previous_record_digest: None | Digest32,
    phase: BootstrapMaintenancePhaseV2,
    completed_step_set_digest: Digest32,
    staged_file_tree_root: None | Digest32,
    staged_deployment_trust_root_set_digest: None | Digest32,
    staged_activation_trust_root_set_digest: None | Digest32,
    staged_release_trust_root_set_digest: None | Digest32,
    new_activation_key_id: None | Ed25519KeyIdV2,
    new_install_identity_profile_signed_digest: None | Digest32,
    new_genesis_ledger_record_digest: None | Digest32,
    new_genesis_ledger_slot_pair_digest: None | Digest32,
    new_installation_epoch_attestation_digest: None | Digest32,
    attempted_new_bootstrap_slot_closure_digest: None | Digest32,
    commit_marker_digest: None | Digest32,
    selector_state_after_record: BootstrapSelectorStateAfterRecordV2,
    written_at_unix_ms: UnixMillis
}

enum BootstrapSelectorStateAfterRecordV2 : u16 {
    Valid = 1 {
        selector_generation: u64,
        selected_slot: BootstrapSlotIdV2,
        selected_slot_closure_digest: Digest32
    },
    NoValidSelector = 2
}

BootstrapMaintenanceRecordV2 {
    payload: BootstrapMaintenanceRecordPayloadV2,
    payload_digest: Digest32,
    installer_or_mdm_signature: DomainSignatureV2
}

enum BootstrapMaintenanceHeadSlotIdV2 : u16 {
    A = 1,
    B = 2
}

BootstrapMaintenanceHeadSlotV2 {
    schema_version: u16 = 2,
    head_slot_id: BootstrapMaintenanceHeadSlotIdV2,
    head_generation: u64,
    previous_head_signed_digest: None | Digest32,
    installation_id: Digest32,
    package_sequence: u64,
    maintenance_intent_digest: Digest32,
    record_sequence: u64,
    record_signed_digest: Digest32,
    phase: BootstrapMaintenancePhaseV2,
    checksum: Digest32,
    installer_or_mdm_signature: DomainSignatureV2
}

BootstrapGenesisLedgerSlotPairV2 {
    schema_version: u16 = 2,
    slot_a: LedgerSlotV2,
    slot_b: LedgerSlotV2
}

BootstrapSlotClosureV2 {
    schema_version: u16 = 2,
    installation_id: Digest32,
    installation_epoch: u64,
    package_sequence: u64,
    slot_id: BootstrapSlotIdV2,
    maintenance_intent_digest: Digest32,
    bootstrap_static_file_tree_root: Digest32,
    bootstrap_tcb_lock_digest: Digest32,
    new_epoch_bridge_manifest_digest: Digest32,
    install_identity_profile_signed_digest: Digest32,
    genesis_ledger_record_digest: Digest32,
    genesis_ledger_slot_pair_digest: Digest32,
    installation_epoch_attestation_digest: Digest32
}

BootstrapCommitMarkerV2 {
    maintenance_intent_digest: Digest32,
    package_sequence: u64,
    new_slot: BootstrapSlotIdV2,
    new_bootstrap_file_tree_root: Digest32,
    new_bootstrap_tcb_lock_digest: Digest32,
    new_epoch_bridge_manifest_digest: Digest32,
    new_install_identity_profile_signed_digest: Digest32,
    new_genesis_ledger_record_digest: Digest32,
    new_genesis_ledger_slot_pair_digest: Digest32,
    new_installation_epoch_attestation_digest: Digest32,
    new_bootstrap_slot_closure_digest: Digest32,
    maintenance_record_head_digest: Digest32
}

BootstrapActiveSelectorV2 {
    schema_version: u16 = 2,
    selector_generation: u64,
    selected_slot: BootstrapSlotIdV2,
    installation_id: Digest32,
    installation_epoch: u64,
    package_sequence: u64,
    maintenance_intent_digest: Digest32,
    commit_marker_digest: Digest32,
    selected_bootstrap_slot_closure_digest: Digest32,
    checksum: Digest32,
    installer_or_mdm_signature: DomainSignatureV2
}
```

For each `X ∈ {old, new}`, the intent's duplicated scalar fields are exact
aliases, not independent choices:

```text
X_bootstrap_tcb_lock.installation_epoch
  = X_installation_epoch
X_bootstrap_tcb_lock.bootstrap_static_file_tree_root
  = X_bootstrap_file_tree_root
```

Root-set identity is a semantic projection, not digest-byte aliasing. For
each `X` and each of the deployment, activation, and release root families,
the corresponding `X_bootstrap_tcb_lock` `VersionedIdentityV2` resolves
exactly one complete authenticated root-set object and one bounded canonical
member vector. Its domain, sequence, signer tuple, validity interval, and
`content_digest` must match that object. In particular,
`release_trust_root_set.content_digest` is the complete signed
`ReleaseTrustRootSetV2` digest, not a member-set digest. The verifier then
recomputes `X_deployment_trust_root_set_digest`,
`X_activation_trust_root_set_digest`, and
`X_release_trust_root_set_digest` from those same three vectors under the
respective `old-*` or `new-*` section-18.8 domains. It also recomputes the
current-domain member-set digest carried inside or identified by each
resolved object. Because those domains differ, current, old/new, and staged
digest bytes are never required to equal one another.

Every embedded `VersionedIdentityV2` and resolved root-set object must agree
on the complete identity and exact member vector. Any missing/extra/reordered
member, wrong field-specific domain digest, identity mismatch, or alias
disagreement is rejected before `Prepared` is signed; the slot closure,
marker, or selector cannot repair it later.

The intent's active-state anchors are exact. `previous_package_sequence`
equals the rollback-protected native package high-water and
`package_sequence = previous_package_sequence + 1` with checked arithmetic.
`expected_active_selector_signed_digest` resolves the sole old selector and
its generation equals `expected_selector_generation`; that selector names
`old_active_slot`, `old_installation_epoch`, and the complete old slot
closure/lock. `expected_last_ledger_generation`,
`expected_last_ledger_record_signed_digest`,
`expected_last_ledger_record_payload_digest`,
`expected_old_active_manifest_digest`, `expected_highest_ever_digest`, and
`expected_actual_store_state_set_digest` byte-equal the selected old ledger
and its authenticated store snapshot. A stale or partially matching anchor
rejects `Prepared`.

`expected_effect_work_quiescence.selected_old_ledger_record_signed_digest`
equals the same old signed ledger record. Its bounded terminal-head array is
strictly sorted by `(owning_service, durable_operation_id,
authenticated_head_signed_digest)`, duplicate-free, and contains every
current agentd planner-marker, kerneld dispatch-WAL, and execd journal head
exactly once after each owning role's signature and terminal-state machine is
verified under the old manifest. `nonterminal_work_count` is the literal
canonical zero. Before signing `Prepared`, offline recovery re-enumerates the
three role indexes and requires exact equality, no child beyond a listed
terminal head, and no prepared/started/indeterminate work requiring further
reconciliation. If the set is not quiescent, the old epoch must boot and
complete its role-owned recovery before maintenance; the offline package
cannot guess or terminalize it. Since no runtime executes in the bridge, the
later bridge-origin `ARMED` frozen nonterminal set is therefore exactly empty.

`new_epoch_bridge_manifest_digest` resolves exactly one complete signed
`SecurityStateManifestV2` whose class is `BootstrapEpochBridge`. Its
`bootstrap_tcb_lock` is byte-equal to `new_bootstrap_tcb_lock`, and its
complete component/release signature set verifies under the new release-root
object. The old active `NormalApplication` manifest is independently
reverified under the old selected roots.

The closed non-wire semantic projection is:

```text
RuntimeVersionedIdentitySemanticProjectionV2(I) =
  canonical_cbor([
    I.domain,
    I.content_digest,
    I.not_before_unix_ms,
    I.not_after_unix_ms
  ])

RuntimeSecurityStateSemanticProjectionV2(S) =
  canonical_cbor([
    RuntimeVersionedIdentitySemanticProjectionV2(S.policy),
    RuntimeVersionedIdentitySemanticProjectionV2(S.registry),
    RuntimeVersionedIdentitySemanticProjectionV2(S.ontology),
    RuntimeVersionedIdentitySemanticProjectionV2(S.model_set),
    RuntimeVersionedIdentitySemanticProjectionV2(S.resource_profile),
    RuntimeVersionedIdentitySemanticProjectionV2(S.destination_projection),
    RuntimeVersionedIdentitySemanticProjectionV2(S.display_projection),
    RuntimeVersionedIdentitySemanticProjectionV2(S.validator_set),
    RuntimeVersionedIdentitySemanticProjectionV2(S.grammar_schema),
    RuntimeVersionedIdentitySemanticProjectionV2(S.protocol_lock),
    RuntimeVersionedIdentitySemanticProjectionV2(S.service_identity_lock),
    RuntimeVersionedIdentitySemanticProjectionV2(S.approval_lock),
    RuntimeVersionedIdentitySemanticProjectionV2(S.jarvis_artifact),
    RuntimeVersionedIdentitySemanticProjectionV2(S.egress_policy_set),
    RuntimeVersionedIdentitySemanticProjectionV2(
      S.executor_connector_registry),
    RuntimeVersionedIdentitySemanticProjectionV2(S.executor_key_lock),
    RuntimeVersionedIdentitySemanticProjectionV2(S.planner_lock),
    RuntimeVersionedIdentitySemanticProjectionV2(
      S.completion_evidence_trust_policy)
  ])

RuntimePlatformClosureSemanticProjectionV2(P) =
  canonical_cbor([
    RuntimeVersionedIdentitySemanticProjectionV2(P.service_unit_set),
    RuntimeVersionedIdentitySemanticProjectionV2(P.socket_or_xpc_unit_set),
    RuntimeVersionedIdentitySemanticProjectionV2(
      P.service_store_projection_set),
    RuntimeVersionedIdentitySemanticProjectionV2(P.sandbox_profile_set),
    RuntimeVersionedIdentitySemanticProjectionV2(P.entitlement_profile_set),
    RuntimeVersionedIdentitySemanticProjectionV2(P.code_integrity_lock)
  ])

RuntimeApplicationSemanticProjectionV2(M) =
  canonical_cbor([
    M.target_platform,
    RuntimeVersionedIdentitySemanticProjectionV2(M.release),
    M.deployment_hard_limits_digest,
    M.binary_closure,
    RuntimeSecurityStateSemanticProjectionV2(M.security_state),
    RuntimePlatformClosureSemanticProjectionV2(M.platform_closure),
    M.persistent_store_compatibility,
    strictly_sorted_non_bootstrap_file_tree_entries(M)
  ])

RuntimeApplicationSemanticProjectionDigestV2(M) =
  SHA256("savana.runtime-application-semantic-projection.v2\0" ||
         RuntimeApplicationSemanticProjectionV2(M))
```

The manifest validator, not a caller, classifies file-tree entries through
the exact component projection in section 2.6.1; only entries whose projected
kind is `BootstrapArtifact` are excluded. The old normal and new bridge
projection bytes and digest must be identical. The bridge's
`agent_claim_compatibility_edges` is exactly empty. Its source/build
provenance, complete bootstrap lock, bootstrap-artifact entries,
component-authorization IDs/signer tuples, and signature wrappers may differ
only as required by the authenticated new bootstrap package and roots.

For the top-level release identity and each of the 24 identities in the
security/platform closures, structural field position supplies a bijective
old-to-bridge mapping. Domain, content digest, and validity interval are
identical. If signer key ID and epoch are unchanged and the old active
identity's `(sequence, content_digest, signer_key_epoch)` already equals that
domain's old high-water, the entire bridge identity is byte-identical to the
old identity. Otherwise—including a healthy rolled-back active identity below
high-water or any signer change—the bridge sequence equals the old high-water
sequence plus one with checked arithmetic, and its signer is the one exact
signer authorized for that same semantic component by the new release-root
set. Content, validity, field position, domain, and arbitrary sequence changes
are forbidden. Every bridge component
authorization/signature maps one-to-one to the same semantic runtime
component under the new roots.

The bridge genesis highest-ever vector is deterministic: its 25 application
domain entries equal the exact bridge identities' `(sequence,
content_digest, signer_key_epoch)` tuples, while the three trust-root entries
equal the exact new deployment, activation, and release identity tuples from
`new_bootstrap_tcb_lock`. An unchanged tuple repeats the old high-water; a
changed application tuple is only the single reauthorization step above; and
each root tuple follows its independently verified predecessor chain. No
other entry may increase or change. Every other manifest field is covered by
the equal semantic projection or the explicit empty-edge rule. The bridge
authorizes no executable, service, store read, replay edge, effect, ordinary
rollback target, evidence claim, or completion inheritance.

The one bridge-genesis `DeploymentLedgerV2` is also exact:

- installation ID is unchanged and installation epoch is
  `new_installation_epoch`;
- generation is `expected_last_ledger_generation + 1`, phase is
  `BOOTSTRAP_BRIDGE`, `transaction_id = None`,
  `transaction_head_digest = None`, `effects_fenced = true`, and
  `effect_fence_epoch` is the old selected ledger's fence epoch plus one;
- `active_manifest_digest = new_epoch_bridge_manifest_digest`;
- `active_activation = BootstrapBridge` repeats the complete signed
  maintenance-intent digest, bridge digest, old runtime-manifest digest,
  old epoch, and both old signed/payload ledger-record digests, with
  `restore_provenance = None`;
- install-profile and bootstrap-lock fields equal the newly staged profile
  and lock, highest-ever is exactly the deterministic vector above,
  rollback-grant state is `None`, and rollback-origin phase is `None`;
- `previous_record_digest =
  expected_last_ledger_record_payload_digest`, while the independently
  repeated previous complete signed digest in `active_activation` equals
  `expected_last_ledger_record_signed_digest`; and
- the record and its two slots are signed only by the fresh new-epoch
  activation key after all fields are fixed.

The bridge manifest exists before the maintenance intent, the intent exists
before the genesis ledger, and the genesis ledger exists before its immutable
pair, attestation, closure, marker, and selector. No field points backward in
the opposite direction, so no digest or signature cycle is permitted.

Every bridge-exit attempt before the epoch's first normal commit must use the old
`expected_old_active_manifest_digest`, not the never-executed bridge digest,
as the operational predecessor for store, agent-claim, and replay
compatibility. Its desired manifest is a complete `NormalApplication` bound
to the new TCB/epoch/profile, provisions a fresh agentd durable replay key
whose `creating_manifest_lineage_digest` is exactly the already signed
bridge manifest's lineage digest—never the maintenance intent or the desired
manifest itself—with no old-epoch retired key or read edge, and passes the full normal
authorization/evidence/plan/compatibility/E2E/protected-acceptance gates.
Any application change therefore occurs only in that normal transaction and
cannot be smuggled into the offline package.

The intent payload digest is
`SHA256("savana.bootstrap-maintenance-intent.v2.payload\0" ||
canonical_cbor(BootstrapMaintenanceIntentPayloadV2))`; its wrapper is exactly
`BootstrapMaintenanceIntent = 23`. A record payload digest is
`SHA256("savana.bootstrap-maintenance-record.v2.payload\0" ||
canonical_cbor(BootstrapMaintenanceRecordPayloadV2))`; its wrapper is exactly
`BootstrapMaintenanceRecord = 24`. Both use the same independently installed
installer/MDM signer identity authorized for this package sequence.
The referenced complete signed-object digests are exactly:

```text
BootstrapMaintenanceIntentSignedDigest =
  SHA256("savana.bootstrap-maintenance-intent.v2.signed\0" ||
         canonical_cbor(BootstrapMaintenanceIntentV2))

BootstrapMaintenanceRecordSignedDigest =
  SHA256("savana.bootstrap-maintenance-record.v2.signed\0" ||
         canonical_cbor(BootstrapMaintenanceRecordV2))
```

`maintenance_intent_digest` uses the first formula and every
`previous_record_digest`/maintenance-record-head reference uses the second;
payload and signed digests are never interchangeable.

Section 8 is maintenance of an already authenticated provisioned base; it is
not an unprovisioned-machine installer. The provisioned base must already
have one selected slot/closure, normal active manifest, authenticated ledger
pair, install profile, epoch attestation, and rollback-protected native
package high-water. A bare machine, missing old selector, or zero sentinel in
any mandatory old-state field has no decoder and cannot be
`PlatformComplete`. On the first section-8 maintenance of such a base,
`previous_package_sequence`, `expected_previous_maintenance_record_sequence`,
and `expected_maintenance_head_generation` are zero and both expected
optional head/terminal digests are `None`; every other old-state anchor
remains mandatory and authenticates that provisioned base.

The maintenance record chain is closed. After the first maintenance, the
expected head is the selected complete signed terminal `Completed` or
`RolledBack` head of
`previous_package_sequence`; its record sequence and complete signed record
digest equal the two previous-maintenance fields. The current package's
`Prepared` record has
`record_sequence = expected_previous_maintenance_record_sequence + 1` and
`previous_record_digest =
expected_previous_maintenance_terminal_record_digest`. Every descendant
increments `record_sequence` by exactly one, names the immediate predecessor's
complete signed record digest, and repeats the exact installation, intent,
and package sequence. A gap, fork, different immutable tuple, replayed phase,
or payload-digest substitution is equivocation and halts bootstrap.

The only phase edges are:

```text
Prepared → FilesStaged → RootsStaged → KeystoreStaged
  → IdentityProfileStaged → GenesisStaged
  → CommitMarkerDurable → SelectorSwitched
  → PostSwitchVerified → Completed

Prepared | FilesStaged | RootsStaged | KeystoreStaged
  | IdentityProfileStaged | GenesisStaged
  | CommitMarkerDurable | SelectorSwitched | PostSwitchVerified
  → RollbackPrepared → RolledBack

any nonterminal phase → FailedSafe
```

`Completed`, `RolledBack`, and `FailedSafe` are terminal. A post-selector
rollback edge is legal only before the epoch-activation ledger record defined
below could have made runtime activation possible. The chain has at most
`max_bootstrap_maintenance_records_per_package` records, so boot validation
never performs an unbounded scan.

Every durable record is selected by one alternating signed head slot:

```text
BootstrapMaintenanceHeadChecksum =
  SHA256("savana.bootstrap-maintenance-head.v2.checksum\0" ||
         canonical_cbor(BootstrapMaintenanceHeadSlotV2 excluding
                        checksum and installer_or_mdm_signature))

BootstrapMaintenanceHeadSignedDigest =
  SHA256("savana.bootstrap-maintenance-head.v2.signed\0" ||
         canonical_cbor(complete BootstrapMaintenanceHeadSlotV2))
```

The signature wrapper is exactly `BootstrapMaintenanceHead = 32`, its
`payload_digest` is the checksum, and it uses the exact tag-32 signature
domain. After appending/fsyncing one record, the offline writer overwrites
only the older A/B head slot with `head_generation = prior + 1`,
`previous_head_signed_digest` equal to the selected prior complete head
digest, and record tuple/phase equal to that new record; it then flushes,
reopens, and verifies the slot before advancing the rollback-protected native
`(package_sequence, head_generation, head_signed_digest)` high-water.

Head recovery uses the same closed conflict principle as the deployment
ledger: zero valid heads is legal only at the explicit first-maintenance
provisioned-base anchor above and is otherwise a boot-integrity halt; one
valid head must match the native high-water or be
its one fully durable immediate successor; equal-generation slots must have
the same logical fields excluding slot ID/checksum/signature; adjacent heads
require the newer predecessor to equal the older complete signed digest.
A gap, reversed predecessor, same-generation disagreement, high-water ahead
of durable media, or more than one distinct valid child is equivocation and
halts. One exact record written before its head slot is an orphan and is
ignored or idempotently adopted only when it is the sole valid immediate
child; it is never progress by itself. The selected head and its bounded
record ancestry are the sole authoritative maintenance phase; directory
order, timestamp, and “largest sequence found” are nonauthoritative.

```text
BootstrapSlotClosureDigest =
  SHA256("savana.bootstrap-slot-closure.v2\0" ||
         canonical_cbor(BootstrapSlotClosureV2))

BootstrapGenesisLedgerSlotPairDigest =
  SHA256("savana.bootstrap-genesis-ledger-slot-pair.v2\0" ||
         canonical_cbor(BootstrapGenesisLedgerSlotPairV2))
```

The closure's static file-tree root and TCB-lock digest must equal the selected
intent fields; its bridge manifest, profile, genesis record, immutable
genesis-pair, and epoch-attestation digests must equal the already
flushed/reopened objects produced for that same installation, epoch, package,
slot, and maintenance intent. Those objects in turn bind the same static
lock/profile/root/key identities required by their own schemas. The closure
contains no commit marker, selector, maintenance-record head, live mutable
ledger pair, or closure self-digest, so the construction is acyclic.

The immutable `BootstrapGenesisLedgerSlotPairV2` is canonical and complete.
`slot_a.slot_id = A`, `slot_b.slot_id = B`, and both slots contain
byte-identical canonical `record_bytes` decoding to the one complete signed
bridge-genesis `DeploymentLedgerV2`. All duplicated installation,
epoch/generation, predecessor, payload-digest, and activation-key fields
match that decoded record. Each slot has its own correctly recomputed
checksum and tag-21 slot signature, so only slot ID/checksum/signature differ.
The complete signed record digest equals
`new_genesis_ledger_record_digest`; the pair digest equals
`new_genesis_ledger_slot_pair_digest`. A payload-only record digest, two
different record encodings, wrong slot IDs, or copied slot signature is
rejected.

Each bootstrap A/B slot contains two distinct fixed paths locked by
`bootstrap_location_layout_digest`: the immutable genesis-pair snapshot above
and one live epoch ledger A/B pair. At `GenesisStaged` the live pair is an
exact verified copy of the immutable pair. After selection, only the live
pair advances. The bootstrap selector first chooses one bootstrap slot and
therefore one installation epoch; section 16.2 then selects only between that
slot's two live ledger records. The inactive/old bootstrap slot's ledger pair
is outside the conflict set and can never defeat the selected epoch by a
larger generation. Every live record in the selected pair must descend from
the immutable genesis record within that same installation ID/epoch.

`attempted_new_bootstrap_slot_closure_digest` is `None` before
`GenesisStaged` and exactly `Some(BootstrapSlotClosureDigest)` for the staged
new slot from `GenesisStaged` through every later record. It remains that
attempted-new digest even when rollback destroys the new slot, so audit never
rewrites history. Independently,
`selector_state_after_record = Valid` exactly when one authenticated selector
is valid after that record. Its generation, slot, and complete closure digest
must byte-equal that selector: the retained old closure before
`SelectorSwitched`, the new closure after a successful switch, and the
restored old closure after `RolledBack`. `NoValidSelector` is legal only in a
`FailedSafe` record caused by a missing/torn selector, a selector without its
exact durable commit marker, two active selectors, or another condition that
leaves no single valid selection. Every non-`FailedSafe` record requires
`Valid`; a `FailedSafe` record uses `Valid` only when the authenticated
failure still leaves exactly one valid selector. A missing selected closure,
unexplained digest switch, fabricated selector generation, or disagreement
with the signed selector is noncanonical and fail safe.

From `RootsStaged` through every later record, each of the three
`staged_*_trust_root_set_digest` fields is `Some` and is recomputed under its
own `staged-*` section-18.8 domain from the exact canonical member vector
resolved through the corresponding `new_bootstrap_tcb_lock` identity.
Before `RootsStaged` all three are `None`. Their vectors must be exactly equal
to the intended new vectors even though their staged-domain and new-domain
digest bytes differ. Missing, extra, reordered, cross-family, or
current/old/new/staged-domain-substituted members are rejection.

`completed_step_set_digest` is the registered digest of exactly the distinct
phase tags in the maximal same-`(installation_id,
maintenance_intent_digest, package_sequence)` suffix beginning at this
package's `Prepared` record and ending at the current record. The prior
package's terminal record is only the authenticated cross-package anchor and
is excluded. On the forward branch the set is exactly the contiguous prefix
from `Prepared` through the current phase. A rollback branch preserves that
forward prefix and then adds exactly `RollbackPrepared` and, when reached,
`RolledBack`; a branch that never reached a forward phase cannot claim it.
`FailedSafe` preserves the exact already reached prefix/rollback tags and adds
only `FailedSafe`. A skipped phase, missing ancestor phase, unrelated future
phase, duplicate record for one phase, or completed-set digest inconsistent
with the record chain is rejection.

Every optional progress field obeys this exhaustive membership matrix:

| Field | Owning completed phase | Exact `Some` value |
|---|---|---|
| `staged_file_tree_root` | `FilesStaged` | `new_bootstrap_file_tree_root` |
| all three `staged_*_trust_root_set_digest` fields | `RootsStaged` | the three staged-domain digests of the exact new canonical member vectors described above |
| `new_activation_key_id` | `KeystoreStaged` | the freshly generated non-exportable activation key ID subsequently bound by the profile and attestation |
| `new_install_identity_profile_signed_digest` | `IdentityProfileStaged` | the complete reopened signed profile digest |
| `new_genesis_ledger_record_digest` | `GenesisStaged` | the complete reopened signed genesis-ledger record digest |
| `new_genesis_ledger_slot_pair_digest` | `GenesisStaged` | `BootstrapGenesisLedgerSlotPairDigest` of the complete reopened immutable A/B genesis pair |
| `new_installation_epoch_attestation_digest` | `GenesisStaged` | the complete reopened dual-signed epoch-attestation digest |
| `attempted_new_bootstrap_slot_closure_digest` | `GenesisStaged` | the recomputed complete new `BootstrapSlotClosureDigest` |
| `commit_marker_digest` | `CommitMarkerDurable` | the complete reopened commit-marker digest |

A field is `Some` if and only if its owning phase is in the completed set.
Once present, its bytes remain identical in every descendant record,
including rollback and `FailedSafe`; a rollback before its owning phase keeps
it `None`. Early `Some`, late `None`, changed bytes, or a value inconsistent
with the named durable object is noncanonical. This table is exhaustive:
there is no phase-specific inference or unregistered progress field.

`commit_marker_digest` is exactly:

```text
BootstrapCommitMarkerDigest =
  SHA256("savana.bootstrap-maintenance-commit-marker.v2\0" ||
         canonical_cbor(BootstrapCommitMarkerV2))
```

The selector checksum is exactly
`SHA256("savana.bootstrap-active-selector.v2.checksum\0" ||
canonical_cbor(BootstrapActiveSelectorV2 excluding checksum and signature))`.
The complete signed selector digest used by
`expected_active_selector_signed_digest` and native high-water state is:

```text
BootstrapActiveSelectorSignedDigest =
  SHA256("savana.bootstrap-active-selector.v2.signed\0" ||
         canonical_cbor(complete BootstrapActiveSelectorV2))
```

Its signature wrapper is exactly `BootstrapActiveSelector = 31`; the
wrapper's `payload_digest` is that checksum, its exact signature-domain bytes
are `"savana.bootstrap-active-selector.v2.signature\0"`, and the generic
`DomainSignatureInputV2` binds tag 31, those bytes, and that checksum.
A tag-24 record wrapper, a selector wrapper over a maintenance-record payload
digest, or a selector checksum copied into any other domain is rejected
before key lookup.

Let the intent's authenticated old selector generation be `g`. Every forward
record before `SelectorSwitched` names `Valid(g, old_active_slot,
old_closure)`. `SelectorSwitched`, `PostSwitchVerified`, and `Completed` name
the one newly signed `Valid(g + 1, new_inactive_slot, new_closure)`. Rollback
before a switch leaves the exact old selector at `g`; rollback after a switch
first atomically installs a newly signed old-slot selector at `g + 2`, then
records that value in `RolledBack`. All arithmetic is checked. A reused,
decreased, skipped, phase-inconsistent, or checksum/payload substituted
generation is rejected against both the record chain and rollback-protected
native `(selector_generation, selector_signed_digest)` high-water.

The commit marker and selector must repeat the exact recomputed slot-closure
digest. The selector's selected slot/installation/epoch/package/intent must
equal the closure and marker; its `commit_marker_digest` must open that exact
marker. A selector that reaches the right static lock through a different
profile, attestation, genesis, slot, or closure digest is rejected.
`BootstrapCommitMarkerV2.maintenance_record_head_digest` is exactly the
complete signed digest of the already durable `GenesisStaged` maintenance
record for that intent. It never names the later `CommitMarkerDurable` record:
the marker is written first, and that later record points forward to
`commit_marker_digest`. Any reverse reference would create a forbidden digest
cycle.

The bootstrap TCB occupies two fixed, complete, root-owned A/B slots and one
fixed selector path. A slot contains its helper, watchdog, recovery code,
schema authority, all three trust-root sets, fixed native profiles, identity
profile, epoch attestation, genesis ledger, and recomputable
`BootstrapSlotClosureV2`. The selector is the sole active-slot authority and
authenticates the exact closure through both its repeated digest and commit
marker; directory timestamps, package-manager “current” metadata, symlinks,
and highest lexical version are nonauthoritative.
`old_active_slot` and `new_inactive_slot` must differ, package sequence must be
strictly greater than the separately durable OS-package high-water, and
`new_installation_epoch = old_installation_epoch + 1` with checked arithmetic.

Maintenance executes in exactly this durable order:

1. append and flush `Prepared` after authenticating the intent, old selector,
   both slots, last ledger/highest-ever/store state, offline boot gate, and
   deny-all network state;
2. materialize and verify the complete new file closure in the inactive slot,
   then append/flush `FilesStaged`;
3. materialize and verify deployment, activation, and release root sets, then
   append/flush `RootsStaged`;
4. create a fresh non-exportable activation key and append/flush
   `KeystoreStaged`; no old private key is copied;
5. construct and verify the signed install identity profile and append/flush
   `IdentityProfileStaged`;
6. validate the unchanged actual operational stores; construct, sign, flush,
   reopen, and digest the new genesis ledger with a highest-ever vector
   exactly equal to the deterministic bridge vector above; construct both the
   immutable genesis A/B pair and initially identical live A/B pair, flush,
   reopen, authenticate every slot, and recompute
   `BootstrapGenesisLedgerSlotPairDigest`; then construct and dual-sign the
   installation-epoch attestation that binds that complete signed genesis
   digest. Construct, write, flush, reopen, and recompute the acyclic
   `BootstrapSlotClosureV2` over the static file tree/lock plus the signed
   bridge manifest, identity profile, genesis record, immutable genesis pair,
   and epoch attestation, and append/flush
   `GenesisStaged` with that attempted-new closure digest while the selected
   closure remains the old slot;
7. write, flush, reopen, and verify `BootstrapCommitMarkerV2` with the same
   slot-closure digest, then
   append/flush `CommitMarkerDurable`;
8. atomically replace the single selector with the signed new selector and
   the same selected-slot closure digest, flush its parent directory, then
   append/flush `SelectorSwitched`;
9. boot the new slot only in offline post-switch verification mode, reverify
   every static lock/file/root/key/profile/attestation/genesis/slot-closure
   cross-reference, and append/flush `PostSwitchVerified` followed by
   `Completed`, retaining that closure digest. Completion leaves the selected
   live ledger in fenced `BOOTSTRAP_BRIDGE`; it starts no JARVIS or Savana
   runtime service and emits no readiness/evidence claim.

Before `SelectorSwitched`, a power loss deterministically resumes from the
last valid record or writes `RollbackPrepared`, destroys only the inactive
new slot/key, and writes `RolledBack`; the old selector never changed. After
`SelectorSwitched`, recovery first attempts forward completion from the exact
commit marker and recomputed slot closure. If forward validation is
irrecoverable before any Savana
runtime activation, it appends `RollbackPrepared`, atomically restores a
signed selector for the retained old slot, destroys the unused new key/slot,
and appends `RolledBack`. The OS-package high-water nevertheless remains at
the attempted new sequence, so this recovery cannot make that package
replayable. A missing/torn selector, a selector without its exact durable
commit marker, two active selectors, an absent retained slot, or disagreement
between selector and record chain is `FailedSafe`, never “pick the newest
directory.”

The old slot and selector recovery material are mandatory and measured
through `Completed` or `RolledBack`; no boolean field may claim retention
instead of verifying it. A later offline package may retire it only after the
new epoch has a normal committed runtime and its separately authorized
retention policy permits removal. Bridge exit and ordinary application
transactions never delete bootstrap slots.

Linux locks one distribution-supported offline/early-boot package primitive:
both slots and selector reside on one supported local filesystem; file and
verity writes are `fsync`ed; each slot directory is `fsync`ed; selector
replacement is one same-directory `renameat(2)` of a fully flushed temporary
file followed by parent-directory `fsync`; and the package-sequence plus
selector-generation/signed-digest high-waters use the distribution's
rollback-protected package database.
macOS locks one notarized OS-installer primitive: both slots are sealed APFS
trees; every file and selector temporary receives `F_FULLFSYNC`; selector
replacement is one same-directory atomic `renameat(2)` followed by directory
`fsync`; and the monotonic package sequence plus
selector-generation/signed-digest high-water are stored in the
installer/MDM-managed rollback-protected receipt database. A platform lacking
those exact durability and anti-rollback primitives is not
`PlatformComplete`.

The earliest boot gate validates the selector, complete maintenance record
chain, commit marker, selected slot, package high-water, and current
installation epoch before it can load any Savana executable. While any
maintenance phase other than `Completed` or `RolledBack` is selected, only
the fixed OS offline recovery environment may execute; normal service-manager
activation and application deployment are denied. Power-loss tests inject
failure before and after every file, root, keystore, profile, genesis, record,
commit-marker, selector, post-switch verification, rollback-selector, and
directory-flush boundary on both platforms.

Evidence from the preceding installation epoch remains audit history but
cannot be used to claim `PlatformComplete` or `ProductComplete` for the new
epoch. The offline package operation itself can never emit current-V2
`ProductCompletionAttestationV2`; completion must be reproven on the new
epoch.

## 9. Install identity and edge isolation

Initial root installation, and every later offline installation-epoch
maintenance, creates an immutable `InstallIdentityProfileV2`.

```text
UnsignedInstallIdentityProfileV2 {
    schema_version: u16 = 2,
    installation_id: Digest32,
    installation_epoch: u64,
    platform: PlatformLockV2,
    principals: ClosedPrincipalMapV2,
    edge_groups_or_app_groups: ClosedEdgeMapV2,
    code_identity_lock: VersionedIdentityV2,
    activation_key_mode: ActivationKeyModeV2,
    activation_public_key: Ed25519PublicKeyV2,
    activation_key_id: Ed25519KeyIdV2,
    activation_trust_root_set_digest: Digest32,
    installer_or_mdm_signer_key_id: Ed25519KeyIdV2,
    installer_or_mdm_signer_key_epoch: u64,
    installer_or_mdm_trust_root_set_digest: Digest32
}

InstallIdentityProfileV2 {
    payload: UnsignedInstallIdentityProfileV2,
    profile_payload_digest: Digest32,
    installer_or_mdm_signature: DomainSignatureV2
}

enum ActivationKeyModeV2 : u16 {
    LocalHardwareBound = 1,
    MdmProvisioned = 2
}
```

The payload maps symbolic identities to numeric UID/GID values on Linux or exact
designated code requirements/App Groups on macOS. It is root-owned mode
`0444`; its complete signed digest is in every deployment transaction and
ledger state.

`profile_payload_digest` is
`SHA256("savana.install-identity-profile.v2.payload\0" ||
canonical_cbor(UnsignedInstallIdentityProfileV2))`. The wrapper is exactly
`InstallIdentityProfile = 20`; its signer ID/epoch must equal the two payload
fields and resolve through the exact
`installer_or_mdm_trust_root_set_digest`. The complete identity is:

```text
install_identity_profile_signed_digest =
  SHA256("savana.install-identity-profile.v2.signed\0" ||
         canonical_cbor(InstallIdentityProfileV2))
```

There is one unsigned payload and no self-referential profile digest.

Each installation epoch has exactly one activation key, either:

- a locally generated non-exportable key bound to the OS hardware/system
  keystore; or
- an MDM-provisioned non-exportable device key whose certificate policy and
  EKU are restricted to Savana ledger activation.

The activation key is independent of release, deployment authorization,
bootstrap-package, runtime-service, approval, planner, and executor keys.
Importing the same private key into more than one installation is forbidden.
The initial trust chain is:

```text
UnsignedInstallationEpochAttestationV2 {
    schema_version: u16 = 2,
    installation_id: Digest32,
    installation_epoch: u64,
    platform: PlatformLockV2,
    bootstrap_tcb_lock_digest: Digest32,
    install_identity_profile_signed_digest: Digest32,
    activation_key_mode: ActivationKeyModeV2,
    activation_public_key: Ed25519PublicKeyV2,
    activation_key_id: Ed25519KeyIdV2,
    platform_key_attestation_digest: Digest32,
    activation_trust_root_set_digest: Digest32,
    installer_or_mdm_signer_key_id: Ed25519KeyIdV2,
    installer_or_mdm_signer_key_epoch: u64,
    installer_or_mdm_trust_root_set_digest: Digest32,
    genesis_ledger_record_digest: Digest32,
    created_at_unix_ms: UnixMillis
}

InstallationEpochAttestationV2 {
    payload: UnsignedInstallationEpochAttestationV2,
    payload_digest: Digest32,
    activation_signature: DomainSignatureV2,
    installer_or_mdm_signature: DomainSignatureV2
}
```

The payload digest is
`SHA256("savana.installation-epoch-attestation.v2.payload\0" ||
canonical_cbor(UnsignedInstallationEpochAttestationV2))`. Both signatures
exclude both signature wrappers and sign that one digest. The activation
wrapper is exactly `InstallationEpochActivation = 6` and proves possession of
the payload's new activation key; its signer key ID equals
`activation_key_id` and its signer epoch equals `installation_epoch`. The
independent installer/MDM wrapper is
exactly `InstallationEpochInstallerOrMdm = 7`; its key ID/epoch and root-set
identity must equal the payload fields. A tag 6 signature under the
installer/MDM key, a tag 7 signature under the activation key, or signatures
over different payload encodings are rejection.

The complete signed attestation digest used by every subsequent reference is:

```text
installation_epoch_attestation_digest =
  SHA256("savana.installation-epoch-attestation.v2.signed\0" ||
         canonical_cbor(InstallationEpochAttestationV2))
```

The genesis ledger record, signed profile, and attestation cross-reference the
same exact installation, epoch, platform, bootstrap lock, key, signer/root-set
identity, and genesis digest. Missing hardware/system-keystore attestation, a
pre-existing activation key, a payload-only later reference, or a reference to
either individual signature fails closed.

Dedicated locked, non-login service principals are:

```text
savana-agentd
savana-ingressd
savana-kerneld
savana-approvald
savana-execd
savana-parser
savana-connector
```

`savana-parser` and `savana-connector` are distinct transient per-job
identities, not aliases for `savana-execd` and not shared with one another.
`savana-approvalctl` is not a daemon identity: it is the private
root-admin binary described below and can use only the admin edge.

JARVIS is bound to exactly one enrolled OS principal per service instance.
Shared JARVIS client identities across OS users are forbidden. Multi-user
operation uses a separately identified and keyed instance per user.

No service belongs to another service's primary group. Each IPC edge gets a
unique access group. Parser and connector workers have no supplementary group
and no access to service keys or durable state.

## 10. Linux local IPC topology

Linux uses one role-specific traversal directory and group per edge:

```text
/run/savana/agentd/jarvis/agentd.sock
/run/savana/kerneld/agentd/kerneld.sock
/run/savana/kerneld/ingressd/kerneld.sock
/run/savana/execd/kerneld/execd.sock
/run/savana/approvald/agentd/approvald.sock
/run/savana/approvald/ingressd/approvald.sock
/run/savana/approvald/admin/approvald.sock
```

The common service parent is root-owned mode `0711`. Each role leaf is owned
by the server service, mode `0710`, with exactly one edge group. A non-admin
socket is server-owned mode `0660` with that edge group. No two client roles
share a leaf directory or socket group.

The admin directory and socket are root-owned mode `0700` and `0600`. The
service manager creates the admin socket and passes its descriptor to
approvald. approvald accepts only an exact root peer credential plus the
role-specific approval-admin transcript authenticated by the private
root-owned `savana-approvalctl` key. `savana-approvalctl` is installed mode
`0500`, measured in `BinaryClosureV2`, links only the closed admin client, and
has no alternate transport or general approval API.

Persistent daemons accept only socket-activated descriptors whose inode, owner, mode,
path, and service-manager unit digest match the active manifest. They never
fall back to binding a caller-selected or generally writable path.

The service manager also creates the four fixed loopback HTTP listeners.
Agentd alone receives the descriptors for `127.0.0.1:8765` and
`127.0.0.1:8768`; approvald alone receives `127.0.0.1:8766`; ingressd alone
receives `127.0.0.1:8767`. Agentd serves the manifest-signed static JARVIS
shell and no-content bootstrap at 8765 and the authenticated agent content
origin at 8768. JARVIS receives no INET/INET6 listener, cannot call
`bind(2)`, and holds only its role-specific AgentControl client descriptor and
non-exportable client-authentication handle. Task status and cancellation use
that authenticated AgentControl edge; they are not unauthenticated loopback
HTTP relay operations. A unit that swaps 8765 and 8768 ownership, passes
either listener to JARVIS, or lets two processes accept one listener fails
readiness.

Linux edge groups:

```text
G_JARVIS_AGENT       enrolled JARVIS principal
G_AGENT_KERNEL       savana-agentd
G_INGRESS_KERNEL     savana-ingressd
G_KERNEL_EXECD       savana-kerneld
G_AGENT_APPROVAL     savana-agentd
G_INGRESS_APPROVAL   savana-ingressd
```

Parser/OCR and connector workers are not IPC endpoints, public operations, or
reusable socket-activated services. For every job, the measured
root/service-manager transient launcher creates a fresh anonymous
`SOCK_SEQPACKET` socketpair (or equivalently framed one-shot pipe), passes one
end to the exact parent and the other to exactly one new process under the
dedicated locked `savana-parser` or `savana-connector` UID, then closes every
launcher copy. No filesystem socket path, listening descriptor, `Accept=yes`
unit, launchd Mach service, connection lookup name, or second client exists.

The private worker wire/crypto ABI has one authority: the protocol companion's
exact parser types—`SignedParserWorkerJobDescriptorV2`,
`SignedParserWorkerResultAttestationV2`, `ParserWorkerPipeFrameV2` closed
`Job`/`Page`/`Complete`/`Failed` framing, `ParserWorkerPageFrameV2`, and
`ParserWorkerPageTranscriptStep[n]`—and its exact connector-codec
types—`SignedConnectorCodecJobDescriptorV2`,
`ConnectorCodecPipeFrameV2` closed
`Job`/`PreparedRequest`/`ProviderResponse`/`Outcome` framing,
`PreparedProviderRequestV2`,
`ConnectorCodecDecodedCompletionV2`,
`ConnectorCodecOutcomePayloadV2`,
`SignedConnectorCodecPreparedRequestAttestationV2`,
`SignedConnectorCodecOutcomeAttestationV2`, the closed
`PrepareAndDecode`/`DecodeRetainedResponse` mode matrix, and
`ConnectorCodecTranscriptStep[n]`. That authority includes every signature
domain, subject/input/provider-response binding, page/result model, ordered
transcript, and canonical/golden vector. The destination manifest's exact
`security_state.protocol_lock.content_digest` must identify that protocol ABI.
This deployment document defines no alternate worker payload, signature
wrapper, digest domain, or wire projection; `ClosedSignatureDomainV2` does not
contain the protocol-owned worker signature domains.
The same protocol lock also fixes the service-side
`ExecutorEffectStartedReceiptRecordV2` and
`ExecutorFinalReleaseAuditEvidenceV2` schemas, their complete signed-receipt
and evidence digest domains, and the closed execd journal DAG. They are
runtime protocol ABI, not new worker signing authority and not deployment
signature domains.

The launcher binds the protocol descriptor to the active installation,
manifest, protocol ABI, parent identity, worker artifact, random job nonce,
resource limits, deadline, anonymous channel identities, and one job-scoped
ephemeral attestation public key. Before the worker is spawned or any
role-specific input is made available, the measured parent verifies the
descriptor's canonical bytes, signature, exact active role lock/key epoch,
manifest, and protocol binding. The launcher passes that exact already
verified canonical descriptor on the one anonymous job channel; the worker
independently rejects any noncanonical descriptor or disagreement in job
nonce, parent/worker identities, channel identities, resource/deadline
bounds, mode, or its own ephemeral public-key handle. The worker is not given
a rotating parent public-key projection and does not claim to reverify the
parent signature. It then consumes exactly one mode-specific one-job
transcript. A parser emits bounded page frames followed by exactly one
terminal complete/failed result attestation. A `PrepareAndDecode` connector
codec may emit one signed prepared-request attestation, receive exactly one
credential-free retained provider response from execd after execd's durable
effect-start boundary, and emit one signed outcome attestation; a
`DecodeRetainedResponse` recovery codec emits only the signed outcome and
causes no provider transport. Thus a connector job may legally sign the two
distinct attestations fixed by its mode, not an invented single-result ABI.
The ephemeral private key is a single sealed memory-only non-exportable
handle, signs only those protocol-authorized one-job attestation domains, is
zeroized before process exit, and is never persisted. Reuse of a nonce, a
second job/channel endpoint, an illegal mode/frame count, a
parser/connector-domain mismatch, or an attestation under the parent key is
rejected. Before launch the parent durably reserves the protocol job/attempt
nonce; it advances and terminalizes only the exact parser or connector record
states required by the protocol before accepting or projecting output.

Ingressd accepts protocol `ExtractedPage` provenance only after verifying the
exact signed protocol descriptor/result chain, worker peer, job nonce,
artifact, input digest, ordered frame/page transcript, deadline, and durable
parent terminal-nonce record. Browser requests may supply only the protocol's
original-source/chat-text variants; browser-selected extracted provenance is
rejected before kernel submission.

The worker's measured descriptor set is exactly its anonymous one-shot end,
signed job descriptor, sealed ephemeral attestation-key handle, fixed standard
error, and only its role-specific bounded input resources. A parser may receive
read-only parser/model resources and original-source input; a connector codec
may receive only credential-free bounded material or the exact retained
provider response named by its descriptor. It has no listener, browser
descriptor, network, credential or keystore handle, durable store, persistent
service key, writable code/resource path, inherited gate, or second job input.
Linux uses a sealed `memfd` and per-activation keyring handle accessible only
to the exact post-exec worker identity; macOS uses a launchd job-scoped memory
object and ephemeral Keychain/Secure Enclave handle with an ACL for that exact
audit token. Descriptor inventory, creation, zeroization, nonce
terminalization, launcher-copy closure, and process exit are measured and
covered by native-control tests.

## 11. macOS local IPC topology

Production macOS uses a distinct launchd Mach/XPC service for each persistent
daemon edge:

```text
group.com.savana.jarvis-agent.agentd
group.com.savana.agent-kernel.kerneld
group.com.savana.ingress-kernel.kerneld
group.com.savana.kernel-execd.execd
group.com.savana.agent-approval.approvald
group.com.savana.ingress-approval.approvald
com.savana.approval.admin
```

Every non-admin edge has a distinct App Group. An App Group is not reused for
another role. Credentials, vault data, databases, and user data are not stored
in App Group containers.

Each XPC connection carries exactly one canonical V2 request and at most one
canonical response, then is invalidated. Before request decoding, the server
verifies:

- XPC audit token;
- expected euid and egid;
- exact designated code requirement;
- exact Bundle ID and Team ID;
- active CodeDirectory identity;
- role-specific transcript key;
- active manifest's XPC-service and entitlement locks.

The admin XPC service accepts only an audit token whose euid is zero, the exact
signed `savana-approvalctl` designated requirement, and the approval-admin
transcript key. It has no generic root-client fallback.

Every daemon is a separate LaunchDaemon running under its own locked,
non-login UID; agentd is not a per-user LaunchAgent. JARVIS remains the
enrolled per-user client. Parser and connector workers use only the anonymous
per-job transient-launch contract in section 10 under their distinct locked
UIDs; no worker Mach/XPC service name or reusable listener exists.

Agentd's entitlement/XPC lock contains both roles: server registration only
for the JARVIS→agentd Mach service and client lookup only for its exact
kerneld and approvald services. A server-only or client-only agentd profile is
invalid.

Launchd separately injects the fixed `localhost:8765` and
`localhost:8768` listener descriptors into agentd, `8766` into approvald, and
`8767` into ingressd. The 8765 resource bundle is the exact signed static
JARVIS shell/bootstrap artifact; no JARVIS process or WebView receives a
listening descriptor. JARVIS has only client lookup for the exact
JARVIS→agentd XPC service and the code-bound client key. Listener descriptor
number, local address, port, owner job, resource-bundle digest, and route set
are fixed by `SocketOrXpcUnitSet` and `EntitlementProfileSet`.

## 12. Key ownership

Every persistent daemon edge has distinct client and server handshake keys:

| Edge | Client private key owner | Server private key owner |
|---|---|---|
| JARVIS → agentd | enrolled JARVIS principal | agentd JARVIS endpoint |
| agentd → kerneld | agentd | kerneld agent endpoint |
| ingressd → kerneld | ingressd | kerneld ingress endpoint |
| kerneld → execd | kerneld | execd kernel endpoint |
| agentd → approvald | agentd | approvald agent endpoint |
| ingressd → approvald | ingressd | approvald ingress endpoint |
| approvalctl → approvald | root-only approvalctl key | approvald admin endpoint |

Anonymous worker jobs instead use the protocol's exact parent one-job signer
and descriptor-bound ephemeral result key; neither worker has a persistent
server/handshake key.

Additional separation:

- kerneld daemon/envelope signing keys are distinct from handshake keys;
- approvald UI-authentication-, ingress-, tool-, and release-settlement
  signing keys are four distinct keys and are distinct from handshake keys;
- agentd alone owns the planner credential;
- execd alone owns tool credentials, envelope-unsealing keys, and its journal
  key hierarchy;
- parser/OCR and connector workers hold no persistent handshake, signing,
  planner, approval, vault, or tool key;
- deploy and watchdog hold no runtime-service private key.

On Linux, private-key directories are service-owned mode `0700` and key files
are `0400`; public verification locks are root-owned `0444`.

The JARVIS client key is never a user-readable filesystem key. Linux exposes
only an opaque non-exportable signing handle backed by the platform keystore
or kernel keyring and an enforced LSM/IMA policy for the exact fs-verity
JARVIS code identity. Another process with the enrolled user's ordinary UID
cannot invoke the handle, duplicate it, read key bytes, or inherit it across
exec. A Linux platform without code-domain-bound handle enforcement cannot
produce `PlatformComplete`.

On macOS, private keys are non-exportable Keychain items whose ACL binds the
exact designated code requirement and a role-specific keychain access group.

Possession of one edge key, Unix group, App Group, Keychain group, or public
verification key never authorizes another edge.

## 13. Linux sandbox profile

Every non-root production service uses a signed systemd unit with at least:

```text
UMask=0077
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
PrivateTmp=yes
PrivateDevices=yes
DevicePolicy=closed
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
ProtectProc=invisible
ProcSubset=pid
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
RestrictNamespaces=yes
RemoveIPC=yes
KeyringMode=private
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@clock @debug @module @mount @obsolete @privileged @raw-io @reboot @swap
SystemCallErrorNumber=EPERM
IPAddressDeny=any
SocketBindDeny=any
```

Each unit has an exact signed `ReadWritePaths` list containing only its own
bounded runtime, state, and journal directories. Every other Savana state and
credential directory is an explicit `InaccessiblePaths` entry.

Per-process network policy:

| Process | Address families and network |
|---|---|
| JARVIS | `AF_UNIX` AgentControl client only; no loopback listener/server and no outbound network |
| kerneld | `AF_UNIX` only |
| ingressd | `AF_UNIX`; inherited loopback listener only; no outbound network |
| approvald | `AF_UNIX`; inherited loopback listener only; no outbound network |
| agentd | `AF_UNIX AF_INET AF_INET6`; inherited 8765/8768 listeners plus separately fixed planner egress |
| execd | `AF_UNIX AF_INET AF_INET6`; only signed connector CIDR/port entries |
| parser/OCR worker | `PrivateNetwork=yes`; cgroup-BPF deny-all; seccomp denies `socket`/`socketpair`/`connect`/`bind`/`listen`/`accept*`; only the inherited anonymous channel is usable |
| connector worker | the same exact `PrivateNetwork`/cgroup-BPF/seccomp socket-creation and connection denial; only the inherited codec channel is usable, and execd performs the authorized transport |

The independent signed domain is:

```text
EgressPolicySetV2 {
    sequence: u64,
    linux_enforcement: LinuxEgressEnforcementV2 =
        AtomicCgroupBpfAddressTransportPort,
    agentd_rules: [StaticEgressRuleV2],
    execd_rules: [StaticEgressRuleV2],
    deny_all_other: true,
    dynamic_proxy_forbidden: true
}

StaticEgressRuleV2 {
    address_family: ClosedAddressFamilyV2,
    literal_network_and_prefix: FixedIpPrefixV2,
    transport: ClosedTransportV2,
    first_port: u16,
    last_port: u16,
    endpoint_identity_pin_digest: Digest32
}

enum ClosedAddressFamilyV2 : u16 {
    IPv4 = 1,
    IPv6 = 2
}

enum ClosedTransportV2 : u16 {
    TCP = 1,
    UDP = 2
}

enum LinuxEgressEnforcementV2 : u16 {
    AtomicCgroupBpfAddressTransportPort = 1
}
```

Normal Linux egress is enforced by the one manifest-bound cgroup-BPF
implementation above, not merely during deployment fencing. Before agentd or
execd starts, the root installer attaches one deny-by-default program to each
exact service cgroup and atomically publishes an immutable generation map.
Each allow entry matches the service cgroup identity and exact
`(address_family, destination address/prefix, transport, destination port)`;
failure to parse transport headers, fragments that cannot be classified,
noninitial fragments, IPv4-mapped ambiguity, map-generation mismatch, or an
unknown cgroup denies. Map replacement builds and verifies the complete new
generation off-path and changes one generation selector atomically; there is
no per-rule permissive update window. The active program, maps, attachment
IDs, cgroup identities, generation, and test measurements are fixed by
`EgressPolicySet`, `ServiceUnitSet`, and `CodeIntegrityLock`.

Systemd `IPAddressAllow` entries come only from the same active
`EgressPolicySetV2` and are mandatory coarse defense in depth, but they cannot
substitute for or widen the cgroup-BPF address+transport+port decision. A
hostname, runtime DNS result, PAC file, environment proxy, SOCKS/HTTP CONNECT
endpoint, transparent proxy, service-mesh sidecar, or separately configurable
egress broker cannot widen either layer. Destinations that cannot be
represented by the signed literal rules are rejected in V2. The normal
deny-all program and its closed allows are installed and measured before
either network-capable service starts.

The kernel egress program does not authenticate TLS. Agentd independently
requires TLS 1.3, its exact non-exportable mTLS client epoch, route, port,
application protocol, and server SPKI hash from `PlannerLockV2`; execd applies
the corresponding connector credential and SPKI identities from the exact
`ExecutorConnectorRegistry`/`ExecutorKeyLockV2`. A socket allowed by BPF is
still unusable until the application-layer lock verifies the handshake.
Address match with a wrong port or transport, or a valid TLS chain with a
wrong SPKI/mTLS identity, fails closed and creates no planner request or
external effect.

Each daemon also applies a manifest-bound Landlock allowlist after opening its
fixed startup descriptors. Failure to install the required seccomp, Landlock,
namespace, cgroup, network, memory, or filesystem restrictions makes readiness
fail closed.

Production Linux requires artifact immutability and verification:

- fs-verity on supported ext4, f2fs, or btrfs artifacts;
- signed manifest verification before service start;
- file owner/mode/ACL/xattr and fs-verity measurement match;
- no mutable executable, model, policy, registry, ontology, projection, or
  validator file is reachable.

A filesystem or kernel that cannot enforce the required profile cannot produce
`PlatformComplete`.

## 14. macOS sandbox and code-integrity profile

Every GUI/service/XPC component is Developer-ID signed and notarized, uses the
Hardened Runtime and library validation, and has exact signed Bundle ID, Team
ID, CodeDirectory hash, entitlements, and designated requirement.
`com.apple.security.app-sandbox = true` is mandatory for JARVIS, every daemon,
and every worker. Absence of the entitlement or failure of the sandbox
extension check is a readiness failure.

The signed entitlement lock forbids at least:

```text
com.apple.security.get-task-allow
com.apple.security.cs.disable-library-validation
com.apple.security.cs.allow-jit
com.apple.security.cs.allow-unsigned-executable-memory
com.apple.security.automation.apple-events
unscoped user-selected or absolute-path file access
camera, microphone, contacts, calendar, location, Bluetooth, USB
```

Allowed network entitlements are closed by role:

- JARVIS has no network-server entitlement and may only use the exact
  AgentControl XPC client;
- ingressd and approvald may own only their inherited fixed 8767 and 8766
  loopback servers, respectively;
- kerneld has no network-client or network-server entitlement;
- agentd has both network-server and network-client entitlements: server only
  for its launchd-provided 8765 and 8768 listeners and client only for the
  signed planner destinations;
- execd has network-client only for signed connector destinations;
- parser/OCR and connector workers have no network entitlement;
- deploy and watchdog are root-signed hardened binaries with no network
  entitlement.

A manifest-bound PF anchor implements the active `EgressPolicySetV2` with
literal addresses and ports only. It uses the numeric locked agentd and execd
UIDs from `InstallIdentityProfileV2`, never runtime username lookup. Installer
and readiness checks prove that each UID maps to exactly one locked account,
that no other service uses it, and that each running PID's audit token, euid,
and designated requirement agree.

The effective PF policy is deny-first: a complete replacement anchor with the
closed allow rules and a final deny-all is loaded and measured atomically
before agentd or execd starts. A separate higher-priority effect-fence anchor
denies all outbound traffic for those UIDs while fenced; its successful load
is required before `ARMED`, and it is removed only after the committed ledger
record is durable. There is no permissive interval during anchor replacement.
Dynamic proxy, PAC, runtime DNS widening, transparent proxy, Network Extension
override, or sidecar egress is rejected. Failure to load or verify either
active anchor makes readiness fail closed.

Parser/OCR and connector workers are transient one-job processes launched
with anonymous channels, not XPC services. Each:

- accepts one inherited anonymous channel and sealed protocol job descriptor;
- validates parent audit token and exact signed protocol job digest;
- has a minimal per-job sandbox profile;
- has no access to another job, service durable state, or persistent keys;
- exits after one protocol job/transcript; the connector mode may contain the
  exact prepared-request and outcome attestations before that one exit;
- leaves no plaintext disk-backed temporary file.

The production installer verifies notarization, designated requirements,
entitlements, XPC dictionaries, App Groups, launchd plists, PF rules, and code
identity against the active manifest before arming.

## 15. Deployment state machine

```text
IDLE | COMMITTED | ROLLED_BACK
  → PREPARED
  → ARMED
  → QUIESCED
  → INSTALLED
  → VERIFIED
  → COMMITTED

PREPARED
  → ABORTED
  → IDLE

ARMED | QUIESCED | INSTALLED | VERIFIED
  → ROLLBACK_PREPARED
  → ROLLBACK_INSTALLED
  → ROLLBACK_VERIFIED
  → ROLLED_BACK

ROLLBACK_PREPARED | ROLLBACK_INSTALLED | ROLLBACK_VERIFIED
  → FAILED_SAFE

PREPARED | ARMED | QUIESCED | INSTALLED | VERIFIED
  → FAILED_SAFE

BOOTSTRAP_BRIDGE
  → PREPARED
  → ARMED
  → QUIESCED
  → INSTALLED
  → VERIFIED
  → COMMITTED

bridge-origin PREPARED
  → ABORTED
  → BOOTSTRAP_BRIDGE

bridge-origin ARMED | QUIESCED | INSTALLED | VERIFIED
  → BRIDGE_RESTORE_PREPARED
  → BRIDGE_RESTORE_INSTALLED
  → BRIDGE_RESTORE_VERIFIED
  → BOOTSTRAP_BRIDGE

BRIDGE_RESTORE_PREPARED | BRIDGE_RESTORE_INSTALLED
  | BRIDGE_RESTORE_VERIFIED
  → FAILED_SAFE
```

The first three paths are legal only for
`NormalRollbackManifest`; the last three bridge paths are legal only for the
one `BootstrapBridgeRestore` transaction whose expected pre-state is the
selected bridge. A phase tag alone never chooses the branch. No other ledger
transition is valid. Any transition to `FAILED_SAFE` requires
an authenticated current ledger, immutable transaction core, complete current
head ancestry, and a newly appended/flushed failure-evidence head before the
ledger CAS. It raises or retains both ledger and OS effect fences. If those
prerequisites cannot be authenticated, recovery enters the external
boot-integrity halt defined below and does not fabricate a `FAILED_SAFE`
ledger record.

### 15.1 State meanings

`IDLE`

- one active complete manifest;
- no outstanding transaction;
- `effects_fenced = false`.

`BOOTSTRAP_BRIDGE`

- the selected active manifest class and active-activation branch are both
  the exact bridge values authenticated by section 8;
- `effects_fenced = true`, the native deny-all fence remains installed, and
  no JARVIS, daemon, worker, planner, connector, store-read, or effect path
  may start;
- the offline genesis form has no transaction head; an aborted or restored
  form retains its exact terminal head/core and burned or consumed grant;
- only a newly authorized bridge-exit attempt for that same bridge may enter
  `PREPARED`; retries remain legal until one normal `COMMITTED` record exists.

`PREPARED`

- transaction, desired manifest, exact recovery target, artifacts, actual-store
  compatibility attestation, native controls, closed plans, and evidence
  contract verified;
- no active-state mutation;
- grant not yet usable;
- safe abort remains possible; an ordinary origin returns through `IDLE`,
  while a bridge origin returns only to fenced `BOOTSTRAP_BRIDGE`.

`ARMED`

- transaction record and rollback grant are durable;
- the durable transaction head binds the complete frozen agentd
  planner-marker, kerneld dispatch-WAL-head, and execd journal-head set;
- `effects_fenced = true`;
- the incremented `effect_fence_epoch` and OS deny-all egress fence are
  durable/measured;
- watchdog identity and deadline are durable;
- services may not create new external effects.
- for a bridge origin the pre-arm service/frozen-work sets are both exactly
  empty, but the exclusive EffectGate and native fence are still measured and
  durably bound.

`QUIESCED`

- all runtime services stopped accepting new work;
- every item in the exact `ARMED` frozen set has exactly one allowed
  role-authenticated terminal descendant and no extra marker/WAL/journal item
  exists;
- in-flight effects are reconciled to terminal or public indeterminate states
  only by the journal-owning service;
- agentd, kerneld, and execd durable recovery indexes are flushed;
- service-manager stop set matches the signed transition plan.

`INSTALLED`

- desired complete file tree is durable in the content-addressed store;
- the ledger names the desired candidate under the transaction fence;
- highest-ever updates are durable;
- candidate services may start only in deployment-verification mode;
- no readiness, isolated E2E, or protected acceptance result is implied by
  this phase.

`VERIFIED`

- `VerificationEvidenceV2` is durable for the exact installed generation;
- all services passed identity/readiness and native-control checks;
- isolated V2 required-mode E2E, actual-store validation, and protected
  acceptance passed against the exact candidate;
- no general external-effect path has been unfenced.

`COMMITTED`

- desired manifest is normal active state;
- while holding the exclusive effect lease, the helper atomically records the
  normal activation, burned rollback grant, `effects_fenced = false`, and
  incremented `effect_fence_epoch`, then removes the still-active OS fence
  before releasing the lease;
- `CommitAttestationV2` is post-commit and reconstructible from the committed
  ledger plus retained verification evidence;
- the healthy committed record may transition directly to the next
  `PREPARED`.

`ABORTED`

- active state is unchanged;
- no grant is usable;
- prepared staging may be garbage-collected.
- a bridge origin cannot become unfenced `IDLE`; it returns to the same
  `BOOTSTRAP_BRIDGE` while retaining the aborted provenance.

`ROLLBACK_PREPARED`

- general effects remain fenced;
- watchdog/helper is consuming the exact rollback grant;
- only fixed recovery service-manager operations are allowed.

`ROLLBACK_INSTALLED`

- the exact complete rollback file tree is durable;
- the authenticated ledger names the rollback candidate and consuming grant
  under the original rollback-origin phase;
- highest-ever equals the grant's origin-specific value;
- rollback services are still restricted to recovery verification.

`ROLLBACK_VERIFIED`

- rollback services have passed identity, native-control, actual-store
  reader/writer, journal recovery, and readiness checks;
- exactly one closed terminal-readiness branch is durable: a verified-origin
  `RollbackVerificationEvidenceV2`, or an early-origin
  `RecoveryRollbackReadinessEvidenceV2`;
- general effects remain fenced.

`ROLLED_BACK`

- rollback complete manifest is active through a consumed rollback record;
- highest-ever remains unchanged;
- rollback readiness and recovery state are validated before entry;
- it is a healthy terminal phase with the consumed activation retained;
- it uses the same ledger-first, OS-fence-second, exclusive-lease release
  sequence as commit;
- it never changes to `IDLE` merely because it is healthy;
- the next transaction may transition directly from `ROLLED_BACK` to
  `PREPARED`.

`BRIDGE_RESTORE_PREPARED`

- the grant's `BootstrapBridgeRestore` branch is consuming;
- the exact source phase is durable, all general effects remain fenced, and
  no bridge service-manager start is permitted.

`BRIDGE_RESTORE_INSTALLED`

- the already authenticated bridge file closure is restored and remeasured;
- the ledger again names the exact bridge manifest/activation tuple with
  `restore_provenance = Some`, retains the source phase's required
  highest-ever vector, and remains fenced;
- no bridge executable or store contract is opened.

`BRIDGE_RESTORE_VERIFIED`

- one `BootstrapBridgeRestoreIntegrityV2` digest is durable in the signed
  transaction head and proves the exact retained closure, unchanged
  authenticated stores/journals, and native deny-all fence;
- no normal readiness, isolated-E2E, protected-acceptance, rollback
  verification, platform, review, or product evidence exists.

The terminal bridge transition consumes the grant and returns to
`BOOTSTRAP_BRIDGE` with `effects_fenced = true`, an incremented fence epoch,
the exact restore provenance, and the final restore head. It never removes
the OS fence and never enters `ROLLED_BACK`.

`FAILED_SAFE`

- no service may accept normal data or create an external effect;
- boot recovery remains the only allowed deployment operation;
- root/operator intervention is required.

### 15.2 Effect-envelope contract and non-racy effect fence

The sealed dispatch/effect envelope interface has two mandatory authenticated
fields:

```text
deployment_generation: u64
effect_fence_epoch: u64
```

`deployment_generation` is exactly the issuing
`DeploymentLedgerV2.generation`; `effect_fence_epoch` is exactly the same
record's field.

They are covered by the sealed-envelope AEAD/signature, kerneld dispatch WAL
record and recovery index, execd prepared/started/terminal journal records,
connector request transcript, executor status response, and audit record.
Kerneld may issue an effect envelope only from the current unfenced ledger
record. Execd rejects an envelope whose pair does not exactly match its
freshly read ledger record.

The protocol/state companion and its canonical/golden vectors must include
these fields at all of those boundaries. An implementation is not V2
conformant, and cannot claim `SourceImplemented`, until that companion schema,
Rust types, WAL/journal recovery rules, and cross-version rejection vectors
are updated consistently.

The root-owned effect lease is the manifest-bound `EffectGateV2`, a fixed
local-filesystem inode independent of the deployment mutex. It has two
non-interchangeable descriptor profiles:

- the service manager opens the gate read-only and injects one
  shared-lock-only descriptor into agentd and one into execd on fixed
  descriptor numbers; it separately injects a read-only ledger projection;
- deploy and watchdog alone receive a read/write descriptor for exclusive
  locking plus the root-only ledger write descriptors;
- immediately after service-manager handoff, each process verifies the
  expected file identity, open mode, descriptor number, owner, filesystem,
  manifest measurement, and absence of extra gate/ledger descriptors, then
  marks runtime copies close-on-exec;
- agentd, execd, parser/connector workers, and every other nondeployment
  process lack pathname traversal, write-open, descriptor-duplication to
  another role, ledger-slot, and exclusive-lock authority. A generic
  “read/write lock mode” parameter is not exposed to them.

The read-only ledger projection contains the complete authenticated selected
record and its fixed manifest, generation, fence, and predecessor metadata
needed for independent validation, but no writable slot, selector,
directory, rename, truncation, or activation-key handle. It is refreshed only
by helper/watchdog using the ledger-first durability protocol. A service must
  reread the projection through its fixed descriptor and validate
canonical bytes, installation tuple, signature, generation, and fence epoch
after acquiring a shared gate; a cached in-memory state is insufficient.
The gate inode identity, both descriptor profiles, fixed descriptor numbers,
projection layout, open flags, lock API, holder roles, unit/job identities,
and sandbox/code-identity rules are measured by
`SecurityStateClosureV2.service_identity_lock`, `ServiceUnitSet`,
`SandboxProfileSet`, and `CodeIntegrityLock`; a locally improvised FD
arrangement is not conformant.

Linux and macOS both use process-associated POSIX `fcntl` record locks
(`F_SETLK`/`F_SETLKW`), never Linux OFD locks and never `flock`, on the one
gate inode. The service-manager descriptors are opened `O_RDONLY`; the
compiled service coordinator can request only `F_RDLCK`. The kernel therefore
rejects `F_WRLCK` on that descriptor, while filesystem permissions, service
UID, Landlock/App Sandbox, seccomp/code-signing policy, and unit/job
descriptor policy prevent a write-open replacement. Only the root-owned
helper/watchdog processes receive `O_RDWR` descriptors and may request
`F_WRLCK`. Reopening through `/proc/self/fd`, `SCM_RIGHTS` transfer, and a
caller-supplied lock type are forbidden.

The lock owner is the process that calls `fcntl`, not the service manager and
not the inherited open-file description. Systemd or launchd may retain its
own descriptor copy without retaining, inheriting, or delaying the service
process's record lock; service process exit releases that process's lock.
The launchd-managed service descriptor set contains only the read-open gate
and read-only ledger projection. Sandbox rules, Hardened
Runtime/designated requirements, UID separation, and the fixed launchd job
definition deny write-open or cross-job FD transfer. The root-only
deploy/watchdog job is the only job whose measured descriptor set contains
the write-open gate and ledger authority. A valid ordinary read FD cannot be
upgraded into exclusive or ledger-write authority on either OS.

Each of agentd and execd has exactly one process-global
`EffectGateCoordinatorV2`. It is the only module that receives the gate FD or
can invoke the lock API:

```text
EffectGateCoordinatorV2 {
    owning_service: ClosedServiceIdV2,
    verified_gate_descriptor_number: u32,
    verified_ledger_projection_descriptor_number: u32,
    mutex: ProcessPrivateMutexV2,
    active_count: u32,
    shared_lock_held: bool,
    active_operation_ids: BoundedSetV2<Digest32>
}

enum EffectGateOperationKindV2 : u16 {
    PlannerExchange = 1,
    ExecutorDispatch = 2,
    AgentKernelDispatchRequest = 3,
    AgentKernelReleaseRequest = 4
}
```

`mutex`, `active_count`, `shared_lock_held`, and `active_operation_ids` are
process-local implementation state, not wire data. Under that mutex, only a
`0 → 1` transition may successfully install `F_RDLCK`; after that syscall it
verifies the read-only ledger projection before returning a non-cloneable
internal operation guard. A second or later concurrent operation increments
`active_count` without another `fcntl` call. An operation may decrement only
after its role-owned durable marker/journal has reached the required terminal
or reconciled state. Only `1 → 0` may issue `F_UNLCK`, and it does so after
the last terminal record is flushed. Counter overflow, missing operation ID,
double release, poison, cancellation, or an unlock failure terminates the
process fail-closed.

POSIX record locks are process-associated and are not reference-counted
leases. Repeated `F_RDLCK` calls therefore never represent multiple holds,
and any business-code `F_UNLCK` can invalidate all concurrent work. Closing
any descriptor for the same inode in that process can also drop its record
locks on both supported OSes. Business modules therefore receive only the
internal guard; they have no raw FD, `open`, `close`, `fcntl`, duplication,
`SCM_RIGHTS`, fork, or exec operation. The coordinator is the only owner of
the one in-process gate FD, no other FD for that inode is permitted in the
process, and the fixed process wrappers reject `fork`/`exec` while
initialized.

The operation rules are:

- agentd obtains a coordinator guard before its durable planner marker and
  retains it through the exact durable response/failure reconciliation;
- agentd obtains the same coordinator guard before invoking the protocol's
  exact kerneld dispatch and release operations (op29 and op34), binds the
  request marker to the current generation/fence epoch, and retains it until
  kerneld's durable response or durable failure is authenticated; neither
  call can create a `PrepareEffect` WAL record outside a live guard;
- execd obtains a coordinator guard before writing `Prepared`, revalidates
  `effects_fenced = false`, `deployment_generation`, and
  `effect_fence_epoch` through its read-only projection, and retains it
  through connector completion plus the durable terminal or indeterminate
  journal record;
- every permitted same-nonce connector retry remains one active operation
  under the original guard; a worker/thread handoff cannot release or
  reacquire it;
- operation A completing before concurrent B decrements the count but leaves
  the kernel lock held; B completing before A has the symmetric result.

Agentd acquires its shared-only descriptor before writing a planner marker,
then revalidates the read-only ledger projection and durably binds the marker
to the exact installation, manifest, generation, fence epoch, planner request,
agentd process identity, boot identity, start time, and compiled planner
deadline. The caller cannot extend that deadline. A response or failure is
durably reconciled before release.

If the deadline expires while the shared hold remains, helper/watchdog
validates the marker and exact process identity, stops that exact
service-manager unit/job and every descriptor-inheriting descendant, waits
for that service process to exit and its process-associated lock to
disappear, and runs the fixed agentd recovery path.
Recovery writes and flushes the canonical failed/indeterminate planner result
for the same marker and generation; it cannot accept a late response or
create a replacement planner request. Only after exact-process termination,
durable fail-closed reconciliation, and proof that no process lock holder
remains
may deployment continue toward the exclusive acquisition. Linux uses the
unit cgroup and pidfd/start identity; macOS uses the launchd job and
`EVFILT_PROC`/audit-token identity. A lock wait, process-name match, PID alone,
or deletion of the marker is not reconciliation.

Crash release of a shared lock proves only that no live process retains that
kernel lock; it does not prove that planner, kernel-WAL, or executor-journal
work is terminal. Native acceptance explicitly starts a service from a
manager-retained inherited gate FD, acquires the service's POSIX read lock,
kills the service without cleanup, proves the manager's still-open FD does
not retain the lock, and proves the helper can then acquire `F_WRLCK`; an OFD
lock implementation fails this test. Arming therefore uses this exact
sequence:

```text
enum FrozenEffectWorkKindV2 : u16 {
    AgentdPlannerMarker = 1,
    KerneldDispatchWalHead = 2,
    ExecdJournalHead = 3
}

FrozenEffectWorkItemV2 {
    kind: FrozenEffectWorkKindV2,
    owning_service: ClosedServiceIdV2,
    durable_operation_id: Digest32,
    nonce_or_request_digest: Digest32,
    authenticated_head_digest: Digest32,
    observed_state_tag: u16
}

FrozenEffectWorkSetV2 {
    installation_id: Digest32,
    transaction_id: Nonce32,
    pre_arm_ledger_record_digest: Digest32,
    pre_arm_generation: u64,
    pre_arm_effect_fence_epoch: u64,
    items: [FrozenEffectWorkItemV2],
    frozen_effect_work_set_digest: Digest32
}
```

1. Helper/watchdog acquires the gate exclusively; no new coordinator guard can
   begin.
2. While retaining exclusive ownership, it first installs and measures the OS
   deny-all effect fence for agentd, execd, and inherited connector transport.
3. Still retaining exclusive ownership and the OS deny fence, it asks the
   service manager to stop the normal-mode agentd, kerneld, and execd jobs and
   proves each exact process/code/start identity exited. The manager's retained
   inherited gate descriptors hold no process-associated lock. This is the
   kerneld/store writer-admission barrier; exclusive ownership already proves
   every agentd planner/op29/op34 and execd dispatch coordinator guard drained.
   Only then does the helper authenticate, freeze, and completely enumerate the
   exact durable agentd planner-marker, kerneld dispatch-WAL-head, and execd
   journal-head set, so no `PrepareEffect`, completion append, or recovery
   append can race enumeration. Items sort by
   `(kind, owning_service, durable_operation_id,
   authenticated_head_digest)` and duplicates fail. The set digest uses the
   registry in section 18.8.
4. It appends the deployment transaction head containing that exact set and
   its measurement, then ledger-CASes into `ARMED`, binding the head/set,
   setting `effects_fenced = true`, and incrementing
   `effect_fence_epoch`. The ledger and OS deny measurements are flushed.
5. It releases the exclusive gate. Only the exact role-specific services are
   then started in dual-fence recovery mode: the ledger fence and OS deny-all
   both remain active, and no planner or connector egress is possible.
6. Agentd writes only its own planner reconciliation record; kerneld writes
   only its own dispatch WAL; execd writes only its own executor journal.
   Deploy and watchdog have read-only verification access to those projections
   and must never create, edit, terminalize, or sign a role journal record.
   Every frozen pre-effect/`Prepared` orphan becomes durable
   `FailedNoEffect`; every frozen `EffectStarted` orphan whose exact outcome
   is not already authenticated becomes durable `Indeterminate`; planner
   markers become their canonical failed or indeterminate terminal. Kerneld
   reconciles quota and public state from those role-authenticated records.
7. Helper/watchdog re-enumerates under the frozen transaction. Every original
   item must have exactly one allowed terminal descendant, and no additional
   marker, WAL, journal head, nonce, or request may exist. Only then does it
   append the next transaction head and CAS the ledger to `QUIESCED`.

A missing/corrupt current ledger head is an external boot-integrity halt and
cannot be converted into a new ledger record. With an authenticated current
chain, an extra frozen item, a role writing another role's journal,
`EffectStarted → FailedNoEffect`, an unresolved frozen item, or entering or
completing `QUIESCED` before exact-set reconciliation writes the exact
head-retaining `FAILED_SAFE` transition.

Linux uses the same manifest-bound cgroup-BPF implementation as normal egress
with a higher-priority deny-all generation loaded before any allow can apply;
macOS uses the higher-priority PF fence anchor in section 14. The supported
platform locks one implementation and its measurement. A stale but correctly
sandboxed process is therefore stopped by both the ledger/lease protocol and
OS egress enforcement.

To unfence `COMMITTED` or healthy `ROLLED_BACK`, the helper again holds the
exclusive effect lease, proves the normal `EgressPolicySetV2` is loaded,
writes and flushes the terminal ledger record with `effects_fenced = false`
and an incremented epoch, removes the temporary deny-all fence, and only then
releases the exclusive lease. Before the record, both ledger and OS deny.
Between the record and fence removal, the OS denies and the lease excludes.
Between fence removal and lease release, the lease excludes. A crash before
terminal durability recovers fenced; a later crash recovers the exact
terminal sequence before runtime activation. There is never a fail-open
interval.

### 15.3 Short-held deployment lock and watchdog identity

There is one root-owned deployment mutex, but it is held only to validate a
ledger generation and perform a bounded compare-and-set of ownership or one
ledger record. No code may hold it while waiting for the effect lease, a
service stop/start, child process, filesystem copy, signature scan, E2E test,
network namespace, durability flush outside the record being committed, or
wall-clock deadline.

The durable owner claim is:

```text
DeploymentOwnerV2 {
    transaction_id: Nonce32,
    owner_role: DeploymentOwnerRoleV2,
    boot_id: Digest32,
    pid: u64,
    process_start_identity: u64,
    executable_identity_digest: Digest32,
    operation_nonce: Nonce32,
    heartbeat_generation: u64,
    heartbeat_deadline_monotonic_ns: MonotonicNanos
}

enum DeploymentOwnerRoleV2 : u16 {
    Helper = 1,
    Watchdog = 2
}

enum DurableDeploymentRecoveryTargetV2 : u16 {
    NormalRollbackManifest = 1 {
        rollback_manifest: SecurityStateManifestV2
    },
    BootstrapBridgeRestore = 2 {
        bridge_manifest: SecurityStateManifestV2,
        maintenance_intent_signed_digest: Digest32,
        bridge_genesis_ledger_record_signed_digest: Digest32,
        bootstrap_slot_closure_digest: Digest32,
        premaintenance_runtime_manifest_digest: Digest32
    }
}
```

The owner claim is not the deployment transaction itself. The immutable
transaction core and its append-only progress head are:

```text
DurableDeploymentTransactionCorePayloadV2 {
    schema_version: u16 = 2,
    domain_tag: ClosedDeploymentObjectDomainV2 =
        DurableDeploymentTransactionCore,
    installation_id: Digest32,
    installation_epoch: u64,
    transaction_id: Nonce32,
    signed_transaction: DeploymentTransactionV2,
    staging_selector: Digest32,
    staging_tree_digest: Digest32,
    desired_manifest: SecurityStateManifestV2,
    recovery_target: DurableDeploymentRecoveryTargetV2,
    migration_plan: MigrationPlanV2,
    artifact_install_plan: ArtifactInstallPlanV2,
    service_transition_plan: ServiceTransitionPlanV2,
    isolated_e2e_plan: IsolatedE2EPlanV2,
    evidence_contract: EvidenceContractV2,
    protected_acceptance_plan: ProtectedAcceptancePlanV2,
    expected_pre_state: ExpectedPreStateV2,
    initial_owner: DeploymentOwnerV2,
    watchdog_boot_id: Digest32,
    watchdog_process_identity_digest: Digest32,
    watchdog_deadline_monotonic_ns: MonotonicNanos,
    created_at_unix_ms: UnixMillis
}

DurableDeploymentTransactionCoreV2 {
    payload: DurableDeploymentTransactionCorePayloadV2,
    payload_digest: Digest32,
    activation_signature: DomainSignatureV2
}

enum ClosedDurableDeploymentStepV2 : u16 {
    TransactionAuthenticated = 1,
    StagingTreeVerified = 2,
    DesiredManifestVerified = 3,
    RecoveryTargetVerified = 4,
    PlansVerified = 5,
    StoreCompatibilityVerified = 6,
    GrantPrearmed = 7,
    ExclusiveEffectGateAcquired = 8,
    OsEffectDenyInstalled = 9,
    EffectWorkSetFrozen = 10,
    ArmedTransitionReady = 11,
    RoleJournalsReconciled = 12,
    ServicesQuiesced = 13,
    DesiredArtifactsInstalled = 14,
    CandidateVerified = 15,
    GrantBurnReady = 16,
    CommitTransitionReady = 17,
    RollbackGrantConsumeReady = 18,
    RollbackArtifactsInstalled = 19,
    RollbackReadinessVerified = 20,
    RollbackTransitionReady = 21,
    BridgeRestoreGrantConsumeReady = 22,
    BridgeClosureRestored = 23,
    BridgeRestoreIntegrityVerified = 24,
    BridgeRestoreTransitionReady = 25
}

enum DurableDeploymentEvidenceRefV2 : u16 {
    StoreCompatibility = 1 { digest: Digest32 },
    NativeControlMeasurementSet = 2 { digest: Digest32 },
    FrozenEffectWorkSet = 3 { digest: Digest32 },
    RoleJournalReconciliation = 4 { digest: Digest32 },
    VerificationEvidence = 5 { digest: Digest32 },
    RollbackVerificationEvidence = 6 { digest: Digest32 },
    RecoveryRollbackReadinessEvidence = 7 { digest: Digest32 },
    BootstrapBridgeRestoreIntegrity = 8 { digest: Digest32 },
    DeploymentFailure = 9 { digest: Digest32 }
}

enum ClosedDeploymentFailureClassV2 : u16 {
    AuthenticatedStateCorruption = 1,
    NativeEffectFenceFailure = 2,
    RollbackAuthorityFailure = 3,
    ServiceQuiescenceIndeterminate = 4,
    ArtifactInstallIndeterminate = 5,
    CandidateVerificationFailure = 6,
    RollbackVerificationFailure = 7,
    BridgeRestoreFailure = 8,
    DurabilityOutcomeUncertain = 9
}

DeploymentFailureEvidenceV2 {
    schema_version: u16 = 2,
    installation_id: Digest32,
    installation_epoch: u64,
    transaction_id: Nonce32,
    core_signed_digest: Digest32,
    source_head_signed_digest: Digest32,
    source_phase: DeploymentPhaseV2,
    failed_transition_target: DeploymentPhaseV2,
    failure_class: ClosedDeploymentFailureClassV2,
    failure_detail_digest: Digest32,
    effects_fenced: true,
    rollback_grant_state: RollbackGrantStateV2 = Burned,
    native_fence_measurement_digest: Digest32,
    observed_at_unix_ms: UnixMillis
}

DeploymentFailureEvidenceDigest =
  SHA256("savana.deployment-failure-evidence.v2\0" ||
         canonical_cbor(DeploymentFailureEvidenceV2))
```

Failure evidence contains no caller string, OS error text, path, command, or
unbounded diagnostic payload. Its source phase is one of `PREPARED`, `ARMED`,
`QUIESCED`, `INSTALLED`, `VERIFIED`, the three nonterminal normal rollback
phases, or the three nonterminal bridge-restore phases. Its failed target is
neither `IDLE` nor `FAILED_SAFE`. Every digest is nonzero. The object is
wrapped by installation-evidence kind 9, flushed and reopened before its
complete envelope signed digest may appear under durable evidence-ref tag 9.
A `FAILED_SAFE` head preserves the exact already reached step prefix and has
exactly one such ref; every other phase has none.

```text

BootstrapBridgeRestoreIntegrityV2 {
    schema_version: u16 = 2,
    installation_id: Digest32,
    installation_epoch: u64,
    transaction_id: Nonce32,
    transaction_intent_digest: Digest32,
    recovery_target_digest: Digest32,
    restore_origin_phase: RollbackOriginPhaseV2,
    bridge_restore_installed_ledger_generation: u64,
    bridge_restore_installed_effect_fence_epoch: u64,
    bridge_restore_installed_effects_fenced: true,
    bridge_manifest_digest: Digest32,
    bridge_genesis_ledger_record_signed_digest: Digest32,
    bootstrap_slot_closure_digest: Digest32,
    premaintenance_runtime_manifest_digest: Digest32,
    retained_highest_ever_digest: Digest32,
    actual_store_state_set_digest: Digest32,
    role_journal_reconciliation_digest: Digest32,
    native_effect_fence_measurement_digest: Digest32,
    bridge_file_closure_verification_result_digest: Digest32,
    verified_at_unix_ms: UnixMillis
}

DurableDeploymentTransactionRecordPayloadV2 {
    schema_version: u16 = 2,
    installation_id: Digest32,
    installation_epoch: u64,
    transaction_id: Nonce32,
    core_signed_digest: Digest32,
    head_sequence: u64,
    previous_head_digest: None | Digest32,
    expected_previous_ledger_record_digest: Digest32,
    expected_previous_ledger_generation: u64,
    target_phase: DeploymentPhaseV2,
    completed_steps: [ClosedDurableDeploymentStepV2],
    evidence_refs: [DurableDeploymentEvidenceRefV2],
    owner: DeploymentOwnerV2,
    watchdog_deadline_monotonic_ns: MonotonicNanos,
    written_at_unix_ms: UnixMillis
}

DurableDeploymentTransactionRecordV2 {
    payload: DurableDeploymentTransactionRecordPayloadV2,
    payload_digest: Digest32,
    activation_signature: DomainSignatureV2
}
```

The core's `staging_selector` is not a second caller-chosen staging identity.
It is exactly:

```text
SHA256("savana.staging-selector.v2\0" ||
       transaction_id ||
       staging_tree_digest)
```

where both inputs come from the signed transaction intent. This binds the
fixed spool leaf deterministically without adding an unsigned alias or path.
The lowercase 64-hex spool argument is this digest and no other value.

`BootstrapBridgeRestoreIntegrityV2` has no standalone signing authority. Its
digest is exactly
`SHA256("savana.bootstrap-bridge-restore-integrity.v2\0" ||
canonical_cbor(BootstrapBridgeRestoreIntegrityV2))` and appears exactly once
under evidence-ref tag 8 in the activation-key-signed durable head that
enters `BRIDGE_RESTORE_VERIFIED`. Every field is recomputed from the selected
closure/genesis, transaction core, installed restore ledger, authenticated
store/journal snapshot, and native fence. It contains no readiness,
isolated-E2E, protected-acceptance, or completion result.

The core contains the complete signed transaction—including its exact intent,
grant, payload digest, and authorization wrapper—rather than references that
could be rebound. Every repeated digest in the core must recompute from the
embedded manifest, recovery-target branch, or plan and equal both the signed
intent and staging selector. The desired manifest and, for
`NormalRollbackManifest`, the rollback manifest are complete signed canonical
objects. For `BootstrapBridgeRestore`, the embedded complete bridge manifest
must reproduce the signed digest and every other branch field must equal the
selected closure/genesis/activation tuple; no bridge bytes come from staging.
The core's initial owner tuple and watchdog deadline are exact, not a PID-only
hint.

The five `*TransitionReady`/`*Ready` step names record only that every
precondition for the following ledger CAS is durable. They never claim the
successor ledger already exists; successful selection of the ledger record
that references that head is the sole proof that the phase/grant transition
committed.

The core payload digest is
`SHA256("savana.durable-deployment-core.v2.payload\0" ||
canonical_cbor(DurableDeploymentTransactionCorePayloadV2))`; its wrapper is
`DurableDeploymentTransactionCore = 25`. A record payload digest is
`SHA256("savana.durable-deployment-record.v2.payload\0" ||
canonical_cbor(DurableDeploymentTransactionRecordPayloadV2))`; its wrapper is
`DurableDeploymentTransactionRecord = 26`. Both wrappers use the installation
activation key/epoch. Completed-step tags are strictly increasing and may
only extend the prior head's exact prefix. Evidence refs sort by `(variant
tag, digest)`, contain no duplicate variant/digest, and may appear only after
the referenced durable object is flushed. A head never references its
successor ledger record: the ledger references the already durable head, so
the graph is acyclic.

The two complete signed-object digests are distinct and exact:

```text
DurableDeploymentTransactionCoreSignedDigest =
  SHA256("savana.durable-deployment-core.v2.signed\0" ||
         canonical_cbor(complete DurableDeploymentTransactionCoreV2))

DurableDeploymentTransactionRecordSignedDigest =
  SHA256("savana.durable-deployment-record.v2.signed\0" ||
         canonical_cbor(complete DurableDeploymentTransactionRecordV2))
```

Every `core_signed_digest`, `previous_head_digest`,
`transaction_head_digest`, and `final_transaction_head_signed_digest` field
uses the corresponding complete signed-object digest above. Neither digest
may be substituted with a payload digest, signature input, wrapper digest, or
raw signature.

The recovery suffix is a closed union. A normal rollback appends exactly
steps 18, 19, 20, and 21 as it enters
`ROLLBACK_PREPARED`, `ROLLBACK_INSTALLED`, `ROLLBACK_VERIFIED`, and
`ROLLED_BACK`; evidence-ref 6 or 7 appears exactly at normal rollback
verification according to origin. A bridge restore instead appends exactly
steps 22, 23, 24, and 25 as it enters
`BRIDGE_RESTORE_PREPARED`, `BRIDGE_RESTORE_INSTALLED`,
`BRIDGE_RESTORE_VERIFIED`, and terminal `BOOTSTRAP_BRIDGE`; evidence-ref 8
appears exactly with step 24. Tags 18–21 and rollback evidence refs are
forbidden in the bridge branch, while tags 22–25 and ref 8 are forbidden in
the normal branch. The common prefix through the exact source phase is
retained, including candidate `VerificationEvidence` only if `VERIFIED` was
actually reached.

Head sequence starts at one, increments by exactly one, and the complete
ancestry is bounded by `max_transaction_head_records`; ledger predecessor
validation is independently bounded by `max_ledger_predecessor_records`.

The first core and head are written, flushed, reopened, and authenticated
before the ledger can enter `PREPARED`. Every later phase uses this one order:

1. under the short deployment mutex, read and authenticate the selected ledger
   and current transaction head;
2. construct the next append-only head whose expected previous ledger
   digest/generation equal that exact ledger and whose previous-head digest
   equals the currently referenced head;
3. append, flush, reopen, and authenticate the new head;
4. compare-and-set the ledger from that exact previous record to a record
   whose `transaction_head_digest = Some(new complete signed head digest)` and
   whose phase equals `target_phase`;
5. flush and re-read the ledger before releasing the mutex.

A head written before a failed ledger CAS is not progress and cannot be
selected by generation, timestamp, or longest-chain rules. It is eligible
only for bounded GC after both ledger slots, the selected head ancestry, and
all recovery/evidence references prove it unreachable. If the selected ledger
record or its referenced head/core/ancestry/wrapper cannot be authenticated,
the boot gate enters an external boot-integrity halt and recovery never
reconstructs or guesses a head from filesystem contents. If the complete
current chain is authenticated but the next durable step proves a wrong
expected predecessor/generation, non-prefix completed set, illegal target
phase, missing required evidence, or another closed transition failure, the
helper may append the exact failure-evidence head and ledger-CAS only from a
source phase listed above into `FAILED_SAFE`.

Boot recovery authenticates the immutable core, entire referenced head chain,
ledger predecessor chain, owner/takeover record, embedded transaction,
manifests, plans, and referenced evidence, then resumes only the first
incomplete idempotent step. Crash injection is mandatory immediately before
and after core write/flush/reopen, every head append/flush/reopen, every ledger
CAS/flush/reopen, every evidence-ref publication, owner takeover, and
unreferenced-head GC.

On Linux the watchdog opens and retains a `pidfd` for the helper and validates
PID, boot ID, process start identity, executable fs-verity measurement, UID,
and transaction operation nonce. It signals or takes over only through that
pidfd, so PID reuse cannot select another process. On macOS it uses the audit
token, `proc_pidinfo` start identity, code-signing requirement, and
`EVFILT_PROC` exit watch as the equivalent closed process identity.

Heartbeat renewal and takeover are short mutex/CAS operations. On an expired
heartbeat, the watchdog first revalidates the exact process identity, records
a fenced takeover generation, terminates that exact stuck helper if still
alive, waits without holding the deployment mutex, and then resumes
idempotently. A live helper cannot starve the watchdog by retaining the
mutex. Crash release of either mutex or effect lease does not itself unfence
effects.

### 15.4 Boot recovery

At boot, recovery runs before any Savana runtime service:

1. validate the offline-maintenance selector under its independent tag-31
   wrapper, complete maintenance chain, selected bootstrap slot, commit
   marker, exact recomputed `BootstrapSlotClosureV2`, installation epoch, and
   package high-water; any in-progress
   maintenance keeps normal services disabled;
2. validate both ledger slots' canonical bytes, checksums, signatures, and
   installation tuples without selecting by generation alone;
3. apply the section 16.2 dual-slot conflict table and validate the complete
   manifest named by the selected authenticated ledger record;
4. require every transaction-bearing phase—including every terminal
   phase—to reference the exact final durable head; authenticate its immutable
   core, complete head ancestry, embedded signed transaction/manifests/plans,
   evidence refs, and ledger predecessor bindings;
5. if the selected phase is nonterminal, acquire the deployment lock and
   resume only the first incomplete idempotent durable step, or consume the
   exact rollback grant;
6. validate rollback readiness and all role-owned journal reconciliation; if
   the current ledger/core/head chain remains fully authenticated but that
   validation fails, append the exact failure head and enter a head-retaining
   `FAILED_SAFE`; otherwise remain in the external boot-integrity halt;
7. only then permit service-manager activation.

Every runtime service independently requires `IDLE`, `COMMITTED`, or
`ROLLED_BACK` with `effects_fenced = false` before normal readiness. A stale
process cannot outlive the fence: every effect boundary verifies the exact
generation/epoch pair and lease protocol above.

## 16. Durable storage and atomicity

Installed manifests and artifacts use a content-addressed store:

```text
Linux:
  /var/lib/savana-deploy/store/sha256/<manifest_digest>/

macOS:
  /Library/Application Support/Savana/Deployment/store/sha256/<manifest_digest>/
```

The store:

- is root-owned mode `0700`;
- contains immutable complete manifests;
- never uses a mutable symlink as the authority;
- is never directly traversed by JARVIS or a non-root service;
- retains the active closure and every desired/rollback closure referenced by
  a nonterminal transaction or usable grant.

### 16.1 Service-specific read-only projections

The root store's mode remains `0700`; weakening it to make service startup
work is forbidden. Services validate only their exact active subset through a
manifest-bound `ServiceStoreProjectionSetV2`.

On Linux, the service manager either:

- creates a separate root-constructed read-only bind/projection namespace for
  each service, with a root-owned `0710` traversal directory and that
  service's UID as the only permitted reader; or
- opens the exact ledger, manifest, and artifact descriptors as root, applies
  read-only/no-exec/no-device/no-suid mount and open-file constraints, and
  passes only those pre-opened descriptors to the service.

The projection is service-specific: it contains no other service's binary,
private configuration, store, key locator, or evidence. The service validates
descriptor identity, fs-verity, file digest, and projection-set digest before
readiness. A general bind of the root store, supplementary store-reader group,
world-readable ancestor, path reopened after startup, or mutable projection is
forbidden.

On macOS, executable resources reside in their signed, sealed bundle where
possible. Other active data is copied or cloned by root into a
service-specific immutable read-only projection whose exact paths and hashes
are in `ServiceStoreProjectionSetV2`; alternatively launchd supplies fixed
pre-opened read-only descriptors. The App Sandbox profile permits only that
service's projection. No App Group contains the canonical store, shared
projection, ledger authority, evidence, credential, or operational database.

Ledger views passed to services are authenticated read-only copies or
descriptors of the selected authoritative slot. They are sufficient for
independent verification but cannot be written and never become an
independent active-state authority.

### 16.2 Dual-slot ledger selection

The ledger has exactly two fixed self-contained slots and no authoritative
selector:

```text
LedgerSlotV2 {
    slot_id: LedgerSlotIdV2,
    installation_id: Digest32,
    installation_epoch: u64,
    generation: u64,
    previous_record_digest: Digest32,
    record_bytes: BoundedCanonicalCborV2,
    record_payload_digest: Digest32,
    checksum: Digest32,
    activation_key_id: Ed25519KeyIdV2,
    signature: DomainSignatureV2
}

enum LedgerSlotIdV2 : u16 {
    A = 1,
    B = 2
}
```

All duplicated slot-header fields must equal the decoded
`DeploymentLedgerV2` fields. `checksum` is
`SHA256("savana.ledger-slot.v2.checksum\0" || slot_id ||
record_bytes)`; the wrapper is exactly `LedgerSlot = 21`, signs `checksum`
through `DomainSignatureInputV2`, and must use `activation_key_id` at the
slot's installation epoch.

To advance generation `g` to `g + 1`, the writer overwrites only the older
slot, fully flushes the new record and containing directory/volume, then
reopens and verifies it. The other slot remains the recovery predecessor.
An optional cached slot-name hint is diagnostic and may be deleted or wrong;
it is never signed state and never affects selection.

Recovery applies this closed conflict table:

1. no valid slot: external boot-integrity halt;
2. one valid slot: select it only if its installation tuple and signature
   validate;
3. two slots at the same generation with byte-identical `record_bytes` and
   equal `record_payload_digest` (apart from their correct slot IDs): select
   that record;
4. two different `record_bytes` or record digests at the same generation:
   equivocation and external boot-integrity halt;
5. adjacent generations: select the newer only when its
   `previous_record_digest` equals the older `record_payload_digest`;
6. a generation gap, reversed predecessor, mismatched installation ID/epoch,
   signature/key mismatch, valid checksum with invalid canonical bytes, or
   any other pair: external boot-integrity halt.

There is no “highest generation wins” fallback outside this table and no
repair by copying an unauthenticated slot. These selection failures occur
before an authoritative ledger record exists, so they never synthesize a
`FAILED_SAFE` phase or signature.

### 16.3 Bounded artifact and evidence collection

Evidence references digests and measurements; an evidence reference does not
make an artifact closure reachable. Artifact GC roots are exactly:

- the currently active manifest;
- desired and rollback manifests of the one nonterminal transaction;
- rollback material for a prearmed/consuming grant through
  `rollback_support_until_unix_ms`;
- the current installation-epoch bootstrap closure;
- an explicit signed legal-hold object, if the product enables that separately
  from V2 completion.

After commit burns a grant, its desired closure remains active and the former
rollback closure ceases to be a GC root. After healthy rollback, the rollback
closure remains active and the failed desired closure ceases to be a root.
GC recomputes reachability from canonical manifests, deletes only whole
unreachable digest directories, and writes an authenticated GC attestation.

The normal bounded evidence policy keeps the current epoch attestation; one
current `ProductCompletionAttestationV2` and the exact trust policy, source
evidence, artifact evidence, deterministic platform evidence, verification,
domain-tagged commit or rollback-verification terminal evidence, review,
epoch, and ledger-proof metadata needed to validate it; all records for a
nonterminal transaction; and at most the newest 256 other
terminal transaction evidence bundles or 400 days, whichever bound is reached
first. Replacing the current product attestation atomically replaces that one
bounded proof bundle. A stricter signed legal hold may retain metadata, but it
still does not implicitly retain artifact bytes. Pruning emits:

```text
enum CompactedTransactionProvenanceV2 : u16 {
    None = 0,
    Aborted = 1 {
        aborted_ledger_record_digest: Digest32,
        transaction_core_signed_digest: Digest32,
        final_transaction_head_signed_digest: Digest32,
        predecessor_chain_digest: Digest32
    }
}

EvidenceGcCheckpointV2 {
    installation_id: Digest32,
    installation_epoch: u64,
    pruned_prefix_last_digest: Digest32,
    retained_first_digest: Digest32,
    retained_last_digest: Digest32,
    retained_count: u64,
    gc_policy_digest: Digest32,
    compacted_transaction_provenance:
        CompactedTransactionProvenanceV2,
    completed_at_unix_ms: UnixMillis,
    activation_key_id: Ed25519KeyIdV2,
    signature: DomainSignatureV2
}
```

The checkpoint preserves hash-chain continuity and deletion accountability
without retaining the pruned artifact closures. Its payload digest is
`SHA256("savana.evidence-gc-checkpoint.v2.payload\0" ||
canonical_cbor(checkpoint excluding its wrapper))`; its wrapper is exactly
`EvidenceGcCheckpoint = 13`.

For `CompactedTransactionProvenanceV2::Aborted`, the
`predecessor_chain_digest` binds the already authenticated durable-head
ancestry before the separately named final head:

```text
SHA256(
  "savana.durable-deployment-predecessor-chain.v2\0"
  || u64_be(predecessor_head_count)
  || predecessor_head_1_signed_digest
  || ...
  || predecessor_head_n_signed_digest
)
```

The predecessor digests are in ascending `head_sequence` order and exclude
`final_transaction_head_signed_digest`. The count is therefore one less than
the complete authenticated chain length. Reordering, omission, duplication,
including the final head twice, or substituting payload digests is invalid.

Durable transaction cores and heads referenced by either ledger slot, a
ledger predecessor retained for conflict resolution, or an `Aborted`
compaction provenance are ledger provenance rather than prunable evidence.
They remain byte-reconstructible regardless of the 256-bundle/400-day
evidence window. `CompactedTransactionProvenanceV2::None` is required unless
the checkpoint is the exact prerequisite of one `ABORTED → IDLE` transition.

Linux durability requires:

- file `fsync` after content writes;
- parent-directory `fsync` after creation/rename;
- `syncfs` before phase transitions that depend on a complete staged tree;
- one supported local filesystem for store and ledger slots.

macOS durability requires:

- `F_FULLFSYNC` for ledger and manifest files;
- directory `fsync` after creation/rename;
- one local APFS volume for store and ledger slots.

NFS, SMB, FUSE, removable media, cross-device rename, and unknown durability
semantics are rejected. Failure of any durability primitive stops before the
next state transition or triggers the prearmed rollback path.

## 17. Isolated verification and protected post-deploy acceptance

The signed `isolated_e2e_plan_digest` identifies a closed test plan. It cannot
contain arbitrary commands.

The plan starts candidate services in a manifest-bound isolated namespace or
launchd test domain with:

- fresh test-only keystore identities;
- fresh empty operational stores;
- no production planner, tool, WebAuthn, vault, or connector credential;
- loopback-only deterministic planner and connector fixtures;
- no route to production destinations;
- the exact candidate binaries, policy, registry, ontology, models,
  projections, validators, grammar/schema, service units, and sandboxes.

The E2E must prove:

- V2 canonical and sensitive transport handshakes;
- original input reaches only ingressd/Rust data plane;
- JARVIS receives only `JarvisVisibleV2`;
- agentd receives only allowed `AgentViewV2`;
- the planner fixture receives only the abstract `PlannerEnvelopeV2`;
- approve and deny settlements, UV/counter/replay behavior;
- G1-G7 transitions and mandatory leak gates;
- exact-once action intent and executor nonce behavior;
- raw tool result returns only to kerneld;
- result gating and acknowledgement;
- restart recovery without effect replay;
- all cross-role and V1-on-V2 attempts fail closed;
- required native security controls are active, not merely configured.

Normal runtime services remain effect-fenced through verification. A candidate
test cannot mutate production operational stores or communicate with a
production external destination.

The empty-store isolated E2E is necessary but not sufficient for
`VERIFIED`. After `INSTALLED`, the helper also executes the signed
`ProtectedAcceptancePlanV2` against the exact installed service units,
separate service UIDs, code identities, sandboxes, and real non-exportable
production keystore handles.

Protected acceptance uses atomic copy-on-write clones of the actual
non-empty operational stores measured by
`StoreCompatibilityAttestationV2`. Each clone contains the real authenticated
headers, schema epochs, key-slot references, and representative existing
records plus a transaction-scoped synthetic canary. It is mounted only to its
own service under the service's normal UID. The source stores remain frozen
and read-only for the duration; an empty clone, synthetic-only database,
exported/replaced key, test keychain, or root-process substitute is invalid.

The exact candidate graph must:

- open and authenticate every cloned non-empty store with its real
  hardware/system-keystore handle;
- recover and scan the bounded existing-state sample without corrupting it;
- perform a signed canary approval, sealed dispatch, executor nonce,
  connector receipt, result gate, acknowledgement, restart, and no-replay
  cycle;
- use the real role keys and ACL/code-identity checks;
- emit the canary effect only to the plan's controlled isolation sink.

The sink is a manifest-measured, transaction-scoped fixture connected by a
pre-opened local `AF_UNIX`/XPC endpoint. It has no route to production or the
Internet, accepts only the exact canary nonce, records a bounded digest-only
receipt, and exits. The global OS deny-all egress fence remains active. No
temporary PF/cgroup-BPF Internet exception, runtime proxy, DNS resolution, or
caller-selected destination is allowed.

The helper verifies clone destruction and source-store identity after the
test. Any key ACL failure, empty actual-state sample, unexpected state
mutation, sink mismatch, production egress attempt, or incomplete cleanup
forces rollback. The resulting
`protected_acceptance_result_digest` is part of
`VerificationEvidenceV2`.

## 18. Deployment evidence

Every transition writes an authenticated audit record, but deployment proof is
split by temporal authority. A precommit verifier cannot claim that a future
commit happened, and commit cannot depend on postcommit evidence.

The four completion layers named by the master specification map to the
concrete objects here without creating extra layers:

- `SourceEvidenceV2` binds the exact revision, three design digests, corrected
  protocol vectors, source checks, fuzz/model results, and legacy scan;
- `ArtifactEvidenceV2` binds exactly one source-evidence digest,
  `SourceLockV2`, the complete signed manifest, and binary-target closure;
- one `VerificationEvidenceV2` plus exactly one reconstructible
  `CommitAttestationV2` or
  `RollbackVerificationEvidenceV2`/`RollbackVerificationAttestationV2`
  terminal branch is the concrete `PlatformEvidenceV2` proof;
- `ProductCompletionAttestationV2` is the concrete signed
  `ProductEvidenceV2` aggregation.

### 18.1 Evidence trust and layer limits

Release-side evidence and host-local evidence have different authorities.
Source, artifact, review, and product evidence use role-specific keys from one
release-root-signed policy:

```text
EvidenceLayerLimitsV2 {
    max_trust_policy_bytes: u64 = 1_048_576,
    max_source_evidence_bytes: u64 = 1_048_576,
    max_artifact_evidence_bytes: u64 = 8_388_608,
    max_verification_evidence_bytes: u64 = 16_777_216,
    max_commit_attestation_bytes: u64 = 1_048_576,
    max_rollback_verification_evidence_bytes: u64 = 16_777_216,
    max_rollback_verification_attestation_bytes: u64 = 1_048_576,
    max_recovery_rollback_readiness_evidence_bytes: u64 = 16_777_216,
    max_review_attestation_bytes: u64 = 1_048_576,
    max_product_release_bytes: u64 = 4_194_304,
    max_product_evidence_bytes: u64 = 4_194_304,
    max_authorized_keys_per_role: u64 = 64,
    max_release_manifests: u64 = 64,
    max_required_platform_tuples: u64 = 64,
    max_platform_evidence_refs: u64 = 64,
    required_final_review_count: u64 = 3
}

enum EvidenceSignerRoleV2 : u16 {
    Source = 1,
    Artifact = 2,
    Review = 3,
    Product = 4
}

AuthorizedEvidenceSignerV2 {
    role: EvidenceSignerRoleV2,
    public_key: Ed25519PublicKeyV2,
    key_id: Ed25519KeyIdV2,
    key_epoch: u64,
    independence_group_digest: Digest32,
    not_before_unix_ms: UnixMillis,
    not_after_unix_ms: UnixMillis
}

CompletionEvidenceTrustPolicyV2 {
    schema_version: u16 = 2,
    product_family_digest: Digest32,
    policy_sequence: u64,
    evidence_layer_limits_digest: Digest32,
    source_signers: [AuthorizedEvidenceSignerV2],
    artifact_signers: [AuthorizedEvidenceSignerV2],
    review_signers: [AuthorizedEvidenceSignerV2],
    product_signers: [AuthorizedEvidenceSignerV2],
    release_trust_root_set_signed_digest: Digest32,
    release_trust_root_set_digest: Digest32,
    policy_payload_digest: Digest32,
    signature: DomainSignatureV2
}
```

The limits digest is
`SHA256("savana.evidence-layer-limits.v2\0" ||
canonical_cbor(EvidenceLayerLimitsV2))`. Each signer array is strictly sorted
by `(key_id bytes, key_epoch)`, duplicate-free, bounded by the limits, and
contains only its named role. A key ID cannot occur in two role arrays.
Source, Artifact, and Product entries use the compiled all-zero independence
group; Review entries use a nonzero policy-authorized group that must equal
the signed review field. The policy contains at least one Source, Artifact,
and Product signer and at least three Review signers in three distinct
nonzero independence groups.

`policy_payload_digest` is
`SHA256("savana.completion-evidence-trust-policy.v2.payload\0" ||
canonical_cbor(policy excluding policy_payload_digest and its wrapper))`.
The wrapper is exactly `CompletionEvidenceTrustPolicy = 14`, signs
`policy_payload_digest` through `DomainSignatureInputV2`, and must resolve to
the `CompletionEvidenceTrustPolicy` role in the exact offline
`ReleaseTrustRootSetV2` named by
`release_trust_root_set_signed_digest`; its recomputed member-set digest must
equal `release_trust_root_set_digest`. A deployment-authorization,
activation, service, approval, or reviewer key cannot sign the policy. The
signed policy digest is
`SHA256("savana.completion-evidence-trust-policy.v2.signed\0" ||
canonical_cbor(complete signed policy))`.

Every `SecurityStateManifestV2` carries that digest as its versioned
`CompletionEvidenceTrustPolicy` domain, and the signed product release binds
the identical digest. Its normal high-water rules prevent policy downgrade.
Source, artifact, review, or product evidence signed by an absent, expired,
wrong-role, wrong-epoch, or cross-policy key is invalid.

Host-local transition audit, store compatibility, verification, commit,
rollback verification, and GC evidence use the installation evidence
envelope:

```text
InstallationEvidenceEnvelopeV2 {
    installation_id: Digest32,
    installation_epoch: u64,
    evidence_sequence: u64,
    previous_evidence_digest: Digest32,
    evidence_kind: ClosedInstallationEvidenceKindV2,
    evidence_bytes: BoundedCanonicalCborV2,
    evidence_digest: Digest32,
    activation_key_id: Ed25519KeyIdV2,
    signature: DomainSignatureV2
}

enum ClosedInstallationEvidenceKindV2 : u16 {
    TransitionAudit = 1,
    StoreCompatibility = 2,
    Verification = 3,
    Commit = 4,
    RollbackVerificationEvidence = 5,
    EvidenceGcCheckpoint = 6,
    RollbackVerificationAttestation = 7,
    RecoveryRollbackReadinessEvidence = 8,
    DeploymentFailure = 9
}
```

`TransitionAudit = 1` wraps exactly:

```text
TransitionAuditV2 {
    schema_version: u16 = 2,
    installation_id: Digest32,
    installation_epoch: u64,
    transaction_id: Nonce32,
    core_signed_digest: Digest32,
    branch: DeploymentBranchV2,
    from_phase: DeploymentPhaseV2,
    to_phase: DeploymentPhaseV2,
    source_ledger_signed_digest: Digest32,
    source_ledger_generation: u64,
    source_head_signed_digest: None | Digest32,
    candidate_head_signed_digest: Digest32,
    candidate_head_sequence: u64,
    candidate_ledger_signed_digest: Digest32,
    candidate_ledger_generation: u64,
    effects_fenced_after: bool,
    effect_fence_epoch_after: u64,
    written_at_unix_ms: UnixMillis
}
```

Its deterministic item digest is
`SHA256("savana.deployment-transition-audit.v2\0" ||
canonical_cbor(TransitionAuditV2))`. The transition graph must accept the
exact `(branch, from_phase, to_phase)`, the candidate ledger generation must
equal `source_ledger_generation + 1`, and every required digest and scalar is
nonzero. The helper publishes and reopens this activation-key-enveloped
candidate authorization after all source/core/head/evidence validation and
before head publication. A durable audit whose candidate ledger never became
selected records an attempted exact CAS, not a claim that a future commit
occurred; authenticated ledger selection remains the sole commit authority.
Thus a crash can leave an auditable rejected/orphan candidate without
creating progress, while no selected transition can lack its prior audit.

The envelope is signed by the activation key in the exact
`InstallationEpochAttestationV2` and is the host hash chain summarized by
`EvidenceGcCheckpointV2`. `SourceEvidenceV2`, `ArtifactEvidenceV2`,
`ReviewAttestationV2`, and `ProductCompletionAttestationV2` are standalone
release-side signed objects and are never rewritten under a host activation
key.

The `Verification`, `Commit`, `RollbackVerificationEvidence`, and
`RollbackVerificationAttestation` evidence-kind tags wrap only their
same-named fixed schemas. A decoder cannot select a schema from payload
contents, and a valid payload under one kind is invalid under every other
kind.

`evidence_bytes` must satisfy both `DeploymentHardLimitsV2` and its
type-specific `EvidenceLayerLimitsV2` bound. `evidence_digest` is
`SHA256("savana.installation-evidence.v2.item\0" ||
u16_be(evidence_kind) || evidence_bytes)`. Sequence `1` carries the all-zero
`previous_evidence_digest`; every later sequence carries the complete signed
digest of its immediate predecessor and no later sequence may carry zero.
The envelope payload and complete signed digests are respectively:

```text
InstallationEvidenceEnvelopePayloadDigest =
  SHA256("savana.installation-evidence.v2.payload\0" ||
         canonical_cbor([
           installation_id,
           installation_epoch,
           evidence_sequence,
           previous_evidence_digest,
           evidence_kind,
           evidence_bytes,
           evidence_digest,
           activation_key_id
         ]))

InstallationEvidenceEnvelopeSignedDigest =
  SHA256("savana.installation-evidence.v2.signed\0" ||
         canonical_cbor(complete InstallationEvidenceEnvelopeV2))
```

The wrapper is exactly
`InstallationEvidenceEnvelope = 22`, uses the matching installation
activation key/epoch, and signs
`InstallationEvidenceEnvelopePayloadDigest` through
`DomainSignatureInputV2`. Every `previous_evidence_digest` uses
`InstallationEvidenceEnvelopeSignedDigest`, never the item or payload digest.

### 18.2 Exact source evidence

```text
SourceRevisionV2 {
    repository_identity_digest: Digest32,
    revision_object_digest: Digest32,
    complete_workspace_tree_digest: Digest32,
    dirty_worktree: false
}

SourceEvidenceV2 {
    schema_version: u16 = 2,
    evidence_trust_policy_digest: Digest32,
    evidence_layer_limits_digest: Digest32,
    source_revision: SourceRevisionV2,
    exact_ten_crate_source_digest: Digest32,
    cargo_lock_digest: Digest32,
    secure_kernel_design_digest: Digest32,
    protocol_state_design_digest: Digest32,
    deployment_design_digest: Digest32,
    corrected_protocol_vector_set_digest: Digest32,
    unit_test_result_digest: Digest32,
    property_test_result_digest: Digest32,
    model_check_result_digest: Digest32,
    fuzz_result_set_digest: Digest32,
    legacy_source_scan_result_digest: Digest32,
    required_source_check_set_digest: Digest32,
    completed_at_unix_ms: UnixMillis,
    source_evidence_payload_digest: Digest32,
    signature: DomainSignatureV2
}
```

`revision_object_digest` hashes the immutable VCS commit object bytes;
`complete_workspace_tree_digest` hashes the canonical complete checked-out
tree including the three design documents, with no ignored untracked source.
`dirty_worktree` is the literal canonical `false`. The exact ten-crate digest
and Cargo lock digest must equal the corresponding frozen revision contents.
`source_revision_digest` used by the next layer is
`SHA256("savana.source-revision.v2\0" ||
canonical_cbor(SourceRevisionV2))`.

`required_source_check_set_digest` is the exact-set digest of the compiled
required unit, property, model-check, fuzz, protocol-vector, and legacy-scan
check identities. Every required identity contributes one result digest; an
omission, duplicate, skipped result, stale vector, expected failure, or
result produced from another revision/design tuple is rejection.
Each category result digest is a domain-separated, strictly sorted,
duplicate-free set of canonical records binding check ID, tool identity,
tested source revision and design tuple, canonical `passed: bool`, and output
digest. Only records with `passed = true` for the exact required set qualify.

The payload digest excludes itself and `signature` and is
`SHA256("savana.source-evidence.v2.payload\0" ||
canonical_cbor(the preceding fields))`. Its signature wrapper is exactly
`SourceEvidence = 15` and uses a `Source` key whose epoch and validity
interval cover `completed_at_unix_ms` in the bound trust policy. The
referenced source-evidence digest is
`SHA256("savana.source-evidence.v2.signed\0" ||
canonical_cbor(complete signed SourceEvidenceV2))`. It may establish only
`SourceImplemented`.

### 18.3 Exact artifact evidence

```text
SignedBinaryTargetClosureEvidenceV2 {
    jarvis: ArtifactIdentityV2,
    agentd: ArtifactIdentityV2,
    ingressd: ArtifactIdentityV2,
    kerneld: ArtifactIdentityV2,
    approvald: ArtifactIdentityV2,
    execd: ArtifactIdentityV2,
    approvalctl: ArtifactIdentityV2,
    worker_sandbox: ArtifactIdentityV2,
    parser_worker_set: ArtifactSetIdentityV2,
    connector_worker_set: ArtifactSetIdentityV2,
    deploy_helper: ArtifactIdentityV2,
    deploy_watchdog: ArtifactIdentityV2
}

ArtifactEvidenceV2 {
    schema_version: u16 = 2,
    evidence_trust_policy_digest: Digest32,
    evidence_layer_limits_digest: Digest32,
    source_evidence_digest: Digest32,
    source_revision_digest: Digest32,
    source_lock_digest: Digest32,
    exact_ten_crate_name_set_digest: Digest32,
    exact_ten_crate_source_digest: Digest32,
    cargo_lock_digest: Digest32,
    reproducible_toolchain_digest: Digest32,
    reproducible_build_recipe_digest: Digest32,
    reproducible_build_result_digest: Digest32,
    sbom_digest: Digest32,
    security_state_manifest: SecurityStateManifestV2,
    security_state_manifest_digest: Digest32,
    signed_binary_targets: SignedBinaryTargetClosureEvidenceV2,
    signed_binary_target_closure_digest: Digest32,
    signature_validation_result_digest: Digest32,
    completed_at_unix_ms: UnixMillis,
    artifact_evidence_payload_digest: Digest32,
    signature: DomainSignatureV2
}
```

`signed_binary_target_closure_digest` is
`SHA256("savana.signed-binary-target-closure.v2\0" ||
canonical_cbor(SignedBinaryTargetClosureEvidenceV2))`.

`exact_ten_crate_name_set_digest` uses the registered
`CrateNameSetItemV2` encoding and domain in section 18.8; its nine ordinals and
NFC UTF-8 names equal section 2.2 exactly. The embedded complete signed
manifest must reproduce
`security_state_manifest_digest`; its `SourceLockV2` fields must equal the
artifact fields, reproduce `source_lock_digest`, and equal the referenced
`SourceEvidenceV2` revision, ten-crate, and Cargo-lock fields. The fixed
binary-target closure covers every daemon,
JARVIS, private approvalctl, all parser/OCR and connector workers, deploy
helper, and watchdog. It must equal the manifest's `BinaryClosureV2` plus
`BootstrapTcbLockV2`; no development, omitted, unsigned, extra, or
cross-manifest target is accepted. For a normal application release, the
reproducibly built deploy-helper/watchdog identities must therefore byte-match
the already selected bootstrap slot; a changed build result cannot be hidden
as evidence-only output or attain `ArtifactComplete`.

The reproducible build result is produced from that exact source evidence,
toolchain, recipe, and Cargo lock, and the SBOM enumerates the same complete
target/file closure. `signature_validation_result_digest` covers every
component, target, manifest, and release signature under the manifest's trust
locks.

The payload digest excludes itself and `signature` and is
`SHA256("savana.artifact-evidence.v2.payload\0" ||
canonical_cbor(the preceding fields))`. Its signature wrapper is exactly
`ArtifactEvidence = 16` and uses an `Artifact` key whose epoch and validity
interval cover `completed_at_unix_ms` in the bound policy. The referenced
artifact-evidence digest is
`SHA256("savana.artifact-evidence.v2.signed\0" ||
canonical_cbor(complete signed ArtifactEvidenceV2))`. It binds exactly one
source-evidence digest and may establish only `ArtifactComplete`.

### 18.4 Precommit verification evidence

`VerificationEvidenceV2` is written and flushed before entering `VERIFIED`:

```text
VerificationEvidenceV2 {
    schema_version: u16 = 2,
    evidence_trust_policy_digest: Digest32,
    evidence_layer_limits_digest: Digest32,
    source_evidence_digest: Digest32,
    artifact_evidence_digest: Digest32,
    installation_id: Digest32,
    installation_epoch: u64,
    transaction_id: Nonce32,
    transaction_intent_digest: Digest32,
    transaction_payload_digest: Digest32,
    installed_ledger_generation: u64,
    installed_effect_fence_epoch: u64,
    installed_manifest_digest: Digest32,
    highest_ever_digest: Digest32,
    recovery_target_digest: Digest32,
    rollback_grant_id: Digest32,

    source_lock_digest: Digest32,
    protocol_lock_digest: Digest32,
    binary_closure_digest: Digest32,
    security_state_digest: Digest32,
    platform_closure_digest: Digest32,
    install_identity_profile_signed_digest: Digest32,

    store_compatibility_attestation_digest: Digest32,
    native_control_measurement_set_digest: Digest32,
    effect_fence_result_digest: Digest32,
    isolated_e2e_result_digest: Digest32,
    protected_acceptance_result_digest: Digest32,
    service_readiness_result_digest: Digest32,
    rollback_exercise_result_digest: Digest32,
    legacy_absence_result_digest: Digest32,
    canonical_vector_result_digest: Digest32,
    negative_test_result_digest: Digest32,
    evidence_contract_digest: Digest32,
    verified_at_unix_ms: UnixMillis,
    helper_identity: ArtifactIdentityV2,
    watchdog_identity: ArtifactIdentityV2,
    activation_key_id: Ed25519KeyIdV2,
    evidence_signature: DomainSignatureV2
}
```

It covers one exact installed generation while still fenced. The referenced
artifact evidence must reference the same source evidence and trust
policy, and its embedded signed manifest digest must equal
`installed_manifest_digest`. All duplicated source-lock, binary, platform,
and manifest fields must match byte-for-byte. It contains no commit
generation, unfenced claim, review result, product-evidence digest, or
product-completion claim.

### 18.5 Reconstructible terminal and platform evidence

After the final unfenced `COMMITTED` ledger record is durable, an evidence
collector that does not participate in the commit deterministically creates:

```text
CommitAttestationV2 {
    schema_version: u16 = 2,
    evidence_trust_policy_digest: Digest32,
    evidence_layer_limits_digest: Digest32,
    source_evidence_digest: Digest32,
    artifact_evidence_digest: Digest32,
    installation_id: Digest32,
    installation_epoch: u64,
    platform: PlatformTupleV2,
    transaction_id: Nonce32,
    transaction_intent_digest: Digest32,
    transaction_payload_digest: Digest32,
    verification_evidence_digest: Digest32,
    committed_ledger_generation: u64,
    committed_record_payload_digest: Digest32,
    committed_manifest_digest: Digest32,
    committed_highest_ever_digest: Digest32,
    committed_effect_fence_epoch: u64,
    committed_effects_fenced: false,
    rollback_grant_id: Digest32,
    rollback_grant_final_state: Burned,
    active_activation: Normal,
    source_lock_digest: Digest32,
    protocol_lock_digest: Digest32,
    platform_closure_digest: Digest32,
    installation_epoch_attestation_digest: Digest32,
    committed_at_unix_ms: UnixMillis,
    activation_key_id: Ed25519KeyIdV2,
    signature: DomainSignatureV2
}
```

Every field is reconstructible from the signed transaction, retained
`VerificationEvidenceV2`, authenticated ledger transition chain, active
manifest, and installation-epoch attestation. Rebuilding it yields identical
canonical bytes. Absence or delayed creation of this attestation cannot undo a
commit; disagreement with the reconstruction is equivocation and fails the
completion claim.

The commit's source/artifact/policy/limits fields must equal those in
`VerificationEvidenceV2`. Its committed manifest must equal both the verified
manifest and the complete manifest embedded in `ArtifactEvidenceV2`.
The inner verification and commit signatures and their installation evidence
envelopes use the exact activation key from
`InstallationEpochAttestationV2`; a release-side evidence signer cannot
replace that host proof.

A failed candidate that reached `VERIFIED` can instead exercise the prearmed
rollback. Before entering `ROLLBACK_VERIFIED`, the helper writes and flushes:

```text
RollbackVerificationEvidenceV2 {
    schema_version: u16 = 2,
    evidence_trust_policy_digest: Digest32,
    evidence_layer_limits_digest: Digest32,
    source_evidence_digest: Digest32,
    artifact_evidence_digest: Digest32,
    installation_id: Digest32,
    installation_epoch: u64,
    platform: PlatformTupleV2,
    transaction_id: Nonce32,
    transaction_intent_digest: Digest32,
    transaction_payload_digest: Digest32,
    candidate_verification_evidence_digest: Digest32,
    rollback_origin_phase: RollbackOriginPhaseV2,
    rollback_installed_ledger_generation: u64,
    rollback_installed_effect_fence_epoch: u64,
    rollback_installed_effects_fenced: true,
    attempted_manifest_digest: Digest32,
    rollback_manifest_digest: Digest32,
    highest_ever_digest: Digest32,
    rollback_grant_id: Digest32,
    attempted_source_lock_digest: Digest32,
    attempted_protocol_lock_digest: Digest32,
    attempted_platform_closure_digest: Digest32,
    rollback_source_lock_digest: Digest32,
    rollback_protocol_lock_digest: Digest32,
    rollback_platform_closure_digest: Digest32,
    rollback_store_compatibility_attestation_digest: Digest32,
    rollback_native_control_measurement_set_digest: Digest32,
    rollback_effect_fence_result_digest: Digest32,
    rollback_isolated_e2e_result_digest: Digest32,
    rollback_protected_acceptance_result_digest: Digest32,
    rollback_service_readiness_result_digest: Digest32,
    rollback_recovery_result_digest: Digest32,
    rollback_legacy_absence_result_digest: Digest32,
    verified_at_unix_ms: UnixMillis,
    helper_identity: ArtifactIdentityV2,
    watchdog_identity: ArtifactIdentityV2,
    activation_key_id: Ed25519KeyIdV2,
    signature: DomainSignatureV2
}
```

The rollback origin is the explicit `Verified = 4` tag. The referenced
candidate `VerificationEvidenceV2` must be valid for the same transaction,
installation, source/artifact pair, attempted manifest, policy, limits, and
attempted source/protocol/platform locks. The rollback manifest must be the
transaction's exact prearmed target. Its actual-store, native-control,
effect-fence, isolated-E2E, protected-acceptance, readiness, recovery, and
legacy-absence results cover that complete rollback manifest while the
installation is still fenced. A rollback from `ARMED`, `QUIESCED`, or
`INSTALLED` remains a valid recovery path, but uses the separate closed
recovery evidence below.

```text
enum RecoveryRollbackOriginMeasurementsV2 : u16 {
    Armed = 1 {
        armed_ledger_record_digest: Digest32,
        frozen_effect_work_set_digest: Digest32,
        os_effect_deny_measurement_digest: Digest32
    },
    Quiesced = 2 {
        quiesced_ledger_record_digest: Digest32,
        frozen_effect_work_set_digest: Digest32,
        role_journal_reconciliation_digest: Digest32
    },
    Installed = 3 {
        installed_ledger_record_digest: Digest32,
        attempted_file_tree_root: Digest32,
        attempted_store_migration_result_digest: Digest32,
        role_journal_reconciliation_digest: Digest32
    }
}

RecoveryRollbackReadinessEvidenceV2 {
    schema_version: u16 = 2,
    evidence_trust_policy_digest: Digest32,
    evidence_layer_limits_digest: Digest32,
    source_evidence_digest: Digest32,
    artifact_evidence_digest: Digest32,
    installation_id: Digest32,
    installation_epoch: u64,
    platform: PlatformTupleV2,
    transaction_id: Nonce32,
    transaction_intent_digest: Digest32,
    transaction_payload_digest: Digest32,
    rollback_origin_phase: RollbackOriginPhaseV2,
    origin_measurements: RecoveryRollbackOriginMeasurementsV2,
    rollback_installed_ledger_generation: u64,
    rollback_installed_effect_fence_epoch: u64,
    rollback_installed_effects_fenced: true,
    attempted_manifest_digest: Digest32,
    rollback_manifest_digest: Digest32,
    highest_ever_digest: Digest32,
    rollback_grant_id: Digest32,
    rollback_store_compatibility_attestation_digest: Digest32,
    rollback_native_control_measurement_set_digest: Digest32,
    rollback_effect_fence_result_digest: Digest32,
    rollback_service_readiness_result_digest: Digest32,
    rollback_recovery_result_digest: Digest32,
    rollback_legacy_absence_result_digest: Digest32,
    role_journal_reconciliation_digest: Digest32,
    verified_at_unix_ms: UnixMillis,
    helper_identity: ArtifactIdentityV2,
    watchdog_identity: ArtifactIdentityV2,
    activation_key_id: Ed25519KeyIdV2,
    signature: DomainSignatureV2
}

enum RollbackTerminalReadinessRefV2 : u16 {
    VerifiedOrigin = 1 {
        candidate_verification_evidence_digest: Digest32,
        rollback_verification_evidence_digest: Digest32
    },
    RecoveryOrigin = 2 {
        recovery_rollback_readiness_evidence_digest: Digest32
    }
}
```

`RecoveryRollbackReadinessEvidenceV2` contains no candidate
`VerificationEvidenceV2`, isolated-E2E, protected-acceptance, candidate
readiness, or candidate-completion field. Its origin tag must equal the
ledger's explicit `Armed = 1`, `Quiesced = 2`, or `Installed = 3` origin and
select the identically tagged measurement union; `Verified = 4` is rejected.
It binds the exact phase measurements, frozen marker/journal set where that
set exists, role-owned journal reconciliation, rollback store compatibility,
native controls, fence, readiness, recovery, and legacy absence. Its payload
digest uses
`"savana.recovery-rollback-readiness.v2.payload\0"` and its wrapper is exactly
`RecoveryRollbackReadinessEvidence = 27`. It is wrapped in installation
evidence kind 8 after durability.

After the final healthy, unfenced `ROLLED_BACK` record is durable, the same
nonparticipating evidence collector deterministically creates:

```text
RollbackVerificationAttestationV2 {
    schema_version: u16 = 2,
    evidence_trust_policy_digest: Digest32,
    evidence_layer_limits_digest: Digest32,
    source_evidence_digest: Digest32,
    artifact_evidence_digest: Digest32,
    installation_id: Digest32,
    installation_epoch: u64,
    platform: PlatformTupleV2,
    transaction_id: Nonce32,
    transaction_intent_digest: Digest32,
    transaction_payload_digest: Digest32,
    terminal_readiness: RollbackTerminalReadinessRefV2,
    rolled_back_ledger_generation: u64,
    rolled_back_record_payload_digest: Digest32,
    attempted_manifest_digest: Digest32,
    active_rollback_manifest_digest: Digest32,
    rolled_back_highest_ever_digest: Digest32,
    rolled_back_effect_fence_epoch: u64,
    rolled_back_effects_fenced: false,
    rollback_grant_id: Digest32,
    rollback_grant_final_state: Consumed,
    active_activation: ActiveActivationV2,
    rollback_origin_phase: RollbackOriginPhaseV2,
    attempted_source_lock_digest: Digest32,
    attempted_protocol_lock_digest: Digest32,
    attempted_platform_closure_digest: Digest32,
    active_rollback_source_lock_digest: Digest32,
    active_rollback_protocol_lock_digest: Digest32,
    active_rollback_platform_closure_digest: Digest32,
    installation_epoch_attestation_digest: Digest32,
    rolled_back_at_unix_ms: UnixMillis,
    activation_key_id: Ed25519KeyIdV2,
    signature: DomainSignatureV2
}
```

Every field is reconstructible from the signed transaction, the closed
`terminal_readiness` branch, authenticated ledger transition chain, active
rollback manifest, and installation-epoch attestation.
`active_activation` must be the `ConsumedRollback = 2` variant containing the
same failed transaction and rollback-grant IDs, and
`rollback_origin_phase` must equal the branch evidence. The final ledger
generation, record, active manifest, unchanged highest-ever digest, consumed
grant, and unfenced effect epoch must match the terminal `ROLLED_BACK` record
exactly.

`VerifiedOrigin = 1` requires origin `Verified = 4`, the exact candidate
`VerificationEvidenceV2`, and existing `RollbackVerificationEvidenceV2`;
this is the only rollback branch eligible for `PlatformEvidenceV2` and
`PlatformComplete`. `RecoveryOrigin = 2` requires one valid
`RecoveryRollbackReadinessEvidenceV2` for origin `Armed`, `Quiesced`, or
`Installed`. It is sufficient to reach a healthy repeated-boot
`ROLLED_BACK`, but can never populate a platform-evidence terminal reference,
review set, or product completion. Any generic/optional digest pair, branch
tag inferred from payload bytes, or early origin paired with candidate
verification is rejection.

The rollback evidence and attestation signatures and their installation
evidence envelopes use the exact activation key in
`InstallationEpochAttestationV2`. Their standalone size bounds and fixed
signature domains are distinct from both Verification and Commit.

The preterminal verification and exactly one terminal attestation compose,
but do not add, the third monotonic layer:

```text
enum PlatformTerminalOutcomeV2 : u16 {
    Committed = 1,
    RolledBack = 2
}

enum PlatformTerminalAttestationRefV2 : u16 {
    Committed = 1 {
        commit_attestation_digest: Digest32
    },
    RolledBack = 2 {
        rollback_verification_attestation_digest: Digest32
    }
}

PlatformEvidenceV2 {
    schema_version: u16 = 2,
    evidence_trust_policy_digest: Digest32,
    evidence_layer_limits_digest: Digest32,
    source_evidence_digest: Digest32,
    artifact_evidence_digest: Digest32,
    platform: PlatformTupleV2,
    installation_id: Digest32,
    installation_epoch: u64,
    manifest_digest: Digest32,
    final_active_manifest_digest: Digest32,
    source_lock_digest: Digest32,
    protocol_lock_digest: Digest32,
    platform_closure_digest: Digest32,
    final_ledger_generation: u64,
    final_effect_fence_epoch: u64,
    final_effects_fenced: false,
    verification_evidence_digest: Digest32,
    terminal_attestation: PlatformTerminalAttestationRefV2,
    native_control_measurement_set_digest: Digest32,
    effect_fence_result_digest: Digest32,
    store_compatibility_attestation_digest: Digest32,
    isolated_e2e_result_digest: Digest32,
    protected_acceptance_result_digest: Digest32,
    service_readiness_result_digest: Digest32,
    rollback_exercise_result_digest: Digest32
}
```

This object is a deterministic canonical projection of the signed
preterminal verification, exactly one domain-tagged terminal attestation, and
the lower-layer evidence; it has no independent signer. The
`PlatformTerminalAttestationRefV2` tag and its single variant payload form a
closed union: no absent, second, generic, or caller-labelled terminal digest
is encoded. `PlatformTerminalOutcomeV2` is the flattened reference tag and
has the identical fixed mapping (`Committed = 1`, `RolledBack = 2`); any tag
outside that mapping or disagreement with the union variant is rejection.

For `Committed = 1`, the payload digest must identify a valid
`CommitAttestationV2`; its final generation, fence epoch, active manifest,
verification digest, and every duplicated lower-layer field must match the
platform object, and `final_active_manifest_digest` equals `manifest_digest`.
For `RolledBack = 2`, the payload digest must identify a valid
`RollbackVerificationAttestationV2`; its final generation, fence epoch,
active rollback manifest, and every duplicated lower-layer field must match.
Its `terminal_readiness` must be exactly `VerifiedOrigin = 1`, whose candidate
verification digest equals `verification_evidence_digest`; a
`RecoveryOrigin = 2` attestation is rejected by this decoder. The
`manifest_digest` remains the attempted manifest embedded in the one artifact
evidence and
`final_active_manifest_digest` is the transaction's exact rollback manifest.
The rollback attestation must in turn bind the exact rollback-verification
evidence and its store, native-control, effect-fence, isolated-E2E,
protected-acceptance, readiness, recovery, and legacy results.

Every common measurement field in `PlatformEvidenceV2` is copied from the
exact candidate `VerificationEvidenceV2`, including store compatibility,
native controls, effect fence, required-mode E2E, protected acceptance,
readiness, and rollback exercise. Both terminal branches must reference that
same verification digest and the same single source/artifact/policy/limits
chain. A commit digest decoded under the rollback tag, a rollback digest
decoded under the commit tag, two terminal digests, a field copied across
different transactions, or any redundant-field disagreement is rejection.
The platform-evidence digest is
`SHA256("savana.platform-evidence.v2\0" ||
canonical_cbor(PlatformEvidenceV2))`. Because it contains the already signed
verification and one terminal-attestation digest but no lower object contains
the platform-evidence digest, this composition is acyclic.
A precommit verification record alone cannot establish `PlatformComplete`;
only the valid final composition may do so.

### 18.6 Independent review attestation

Each final reviewer signs:

```text
ReviewAttestationV2 {
    schema_version: u16 = 2,
    evidence_trust_policy_digest: Digest32,
    evidence_layer_limits_digest: Digest32,
    review_subject_digest: Digest32,
    source_evidence_digest: Digest32,
    artifact_evidence_set_digest: Digest32,
    platform_evidence_set_digest: Digest32,
    source_lock_set_digest: Digest32,
    protocol_lock_digest: Digest32,
    deployment_spec_digest: Digest32,
    release_manifest_set_digest: Digest32,
    terminal_attestation_set_digest: Digest32,
    reviewer_identity_digest: Digest32,
    reviewer_independence_group: Digest32,
    critical_count: u64,
    important_count: u64,
    minor_count: u64,
    reviewed_at_unix_ms: UnixMillis,
    signature: DomainSignatureV2
}
```

The three required attestations must have distinct reviewer identities and
independence groups, use distinct `Review` keys whose epochs and validity
intervals cover `reviewed_at_unix_ms` in the bound trust policy, and bind the
same exact source evidence, artifact set, platform
set, release-manifest set, subject, and terminal-attestation set. All three
severity fields are zero. A prose review, mutable URL, aggregate count without
a frozen subject, wrong-role signer, or review of another
source/artifact/platform set does not qualify.

The review payload digest is
`SHA256("savana.review-attestation.v2.payload\0" ||
canonical_cbor(ReviewAttestationV2 excluding signature))`; its wrapper is
exactly `ReviewAttestation = 11`.

The terminal-attestation set is exactly the strictly sorted,
duplicate-free set of `(terminal tag, terminal attestation digest)` pairs
projected from the reviewed platform-evidence set. The tag is part of each set
item and cannot be dropped or inferred from the referenced bytes.

`review_subject_digest` is
`SHA256("savana.review-subject.v2\0" || canonical_cbor([
source_evidence_digest, artifact_evidence_set_digest,
platform_evidence_set_digest, release_manifest_set_digest,
terminal_attestation_set_digest, source_lock_set_digest, protocol_lock_digest,
deployment_spec_digest]))`. It contains no review or product-evidence digest.

### 18.7 Signed product release and exact product-completion tuple set

The only product-level claim is:

```text
RequiredPlatformReleaseTupleV2 {
    os: ClosedOsV2,
    architecture: ClosedArchitectureV2,
    manifest_digest: Digest32,
    source_lock_digest: Digest32,
    protocol_lock_digest: Digest32,
    platform_closure_digest: Digest32
}

SignedReleaseManifestEntryV2 {
    manifest_digest: Digest32,
    manifest_payload_digest: Digest32,
    manifest_release_signature: DomainSignatureV2
}

ProductReleasePayloadV2 {
    schema_version: u16 = 2,
    domain_tag: ClosedDeploymentObjectDomainV2 = ProductRelease,
    product_family_digest: Digest32,
    product_identity_digest: Digest32,
    release_identity_digest: Digest32,
    release_sequence: u64,
    previous_product_release_signed_digest: None | Digest32,
    evidence_trust_policy_digest: Digest32,
    evidence_layer_limits_digest: Digest32,
    release_trust_root_set_signed_digest: Digest32,
    release_trust_root_set_digest: Digest32,
    release_manifests: [SignedReleaseManifestEntryV2],
    release_manifest_set_digest: Digest32,
    required_platform_tuples: [RequiredPlatformReleaseTupleV2],
    required_platform_tuple_set_digest: Digest32,
    issued_at_unix_ms: UnixMillis,
    not_before_unix_ms: UnixMillis,
    expires_at_unix_ms: UnixMillis
}

ProductReleaseV2 {
    payload: ProductReleasePayloadV2,
    payload_digest: Digest32,
    release_root_signature: DomainSignatureV2
}

PlatformEvidenceRefV2 {
    os: ClosedOsV2,
    architecture: ClosedArchitectureV2,
    installation_id: Digest32,
    installation_epoch: u64,
    manifest_digest: Digest32,
    final_active_manifest_digest: Digest32,
    evidence_trust_policy_digest: Digest32,
    evidence_layer_limits_digest: Digest32,
    source_evidence_digest: Digest32,
    artifact_evidence_digest: Digest32,
    platform_evidence_digest: Digest32,
    terminal_outcome: PlatformTerminalOutcomeV2,
    terminal_attestation_digest: Digest32,
    source_lock_digest: Digest32,
    protocol_lock_digest: Digest32,
    platform_closure_digest: Digest32,
    verification_evidence_digest: Digest32
}

ProductCompletionAttestationV2 {
    schema_version: u16 = 2,
    product_release: ProductReleaseV2,
    evidence_trust_policy_digest: Digest32,
    evidence_layer_limits_digest: Digest32,
    product_release_digest: Digest32,
    release_manifest_set_digest: Digest32,
    required_platform_tuple_set_digest: Digest32,
    source_evidence_digest: Digest32,
    artifact_evidence_set_digest: Digest32,
    platform_evidence_set_digest: Digest32,
    platform_evidence_refs: [PlatformEvidenceRefV2],
    terminal_attestation_set_digest: Digest32,
    review_attestation_set_digest: Digest32,
    legacy_absence_result_digest: Digest32,
    issued_at_unix_ms: UnixMillis,
    signature: DomainSignatureV2
}
```

`release_manifests` is bounded by `max_release_manifests`, strictly sorted by
`manifest_digest`, and has no duplicate digest. Every entry resolves to
exactly one complete canonical
signed `SecurityStateManifestV2`; the resolved object's manifest digest,
payload digest, and required `ManifestRelease` wrapper must equal the three
entry fields. An entry that identifies only a
payload, resolves to two signed manifests, or substitutes a release signature
from another manifest is rejected.

`required_platform_tuples` is bounded by
`max_required_platform_tuples`, strictly sorted by all six fields in their
schema order, and contains no duplicate `(os, architecture)`. It is
exactly the six-field projection of every resolved release manifest:
`(os, architecture, manifest_digest, source_lock_digest,
protocol_lock_digest, platform_closure_digest)`. A two-field advertisement,
an inferred closure, a missing manifest, or an additional tuple is not a
release.

The release payload digest is
`SHA256("savana.product-release.v2.payload\0" ||
canonical_cbor(ProductReleasePayloadV2))`; the release wrapper is exactly
`ProductRelease = 19`. `release_root_signature` must be one valid
`DomainSignatureV2` made by a currently authorized `ProductRelease` role in
the exact `ReleaseTrustRootSetV2` named by
`release_trust_root_set_signed_digest`; that object's registered member-set
digest must equal `release_trust_root_set_digest`. Release sequence is
strictly monotonic and nonzero for a product identity; sequence one has no
predecessor, and every later sequence binds the complete signed digest of the
immediately prior product release. Downgrade, fork, expired release, not-yet-valid
release, or a release/root-set cycle fails closed.

`product_release_digest` is the complete signed-object digest
`SHA256("savana.product-release.v2.signed\0" ||
canonical_cbor(ProductReleaseV2))`. The two set digests inside the payload
recompute only through the exact `release_manifest_set_digest` and
`required_platform_tuple_set_digest` registry rows in section 18.8.

In the four-layer vocabulary, `ProductEvidenceV2` is exactly the complete
signed canonical bytes of `ProductCompletionAttestationV2`. There is no
second product-evidence wrapper, unsigned dashboard record, or alternate
completion object.

The verifier first authenticates the embedded `product_release`, recomputes
its payload and complete signed digest, resolves and authenticates every
signed release manifest, and then requires exact equality of
`product_release_digest`, evidence policy, evidence limits,
`release_manifest_set_digest`, and `required_platform_tuple_set_digest`
between the product completion object and that release. The product object's
manifest and artifact evidence may reference only those exact signed
manifest entries; a digest-correct payload under a different signature is a
different manifest and is rejected.

`platform_evidence_refs` is bounded by `max_platform_evidence_refs`, strictly
increasing by `(os tag, architecture tag, manifest_digest bytes,
installation_id bytes, installation_epoch)`, and contains no duplicate
OS/architecture tuple. Each reference must reproduce one valid
`PlatformEvidenceV2`: its source/artifact/platform, verification, terminal
attestation, attempted and final-active manifest, installation, policy,
limits, source-lock, protocol-lock, and platform-closure digests must all
match that one chain.
`terminal_outcome` and `terminal_attestation_digest` must be the exact
numeric tag and sole payload digest encoded by that platform evidence's
`terminal_attestation` union.

All references use the single `source_evidence_digest` and trust-policy digest
in the product object. `artifact_evidence_set_digest` is the exact set of
artifact digests in the references; `platform_evidence_set_digest` is the
exact set of platform-evidence digests.
`terminal_attestation_set_digest` is the exact set of canonical
`(terminal_outcome, terminal_attestation_digest)` pairs, not a digest-only set
that could erase the domain tag. Projecting each reference to `(os,
architecture, manifest_digest, source_lock_digest, protocol_lock_digest,
platform_closure_digest)` must equal exactly, field for field, the canonical
six-field required tuple set declared by the embedded signed product release.

Duplicates, an omitted advertised tuple, an extra tuple, another installation
epoch for the referenced evidence, or mixing any source, artifact, manifest,
verification, terminal attestation, platform, release, policy, or limits
value from different chains is rejected. The terminal-attestation and review
digest sets must likewise
equal, not merely overlap, the canonical sets derived from
`platform_evidence_refs` and exactly three qualifying reviews. All reviews
must bind those same source/artifact/platform sets. The product signature
wrapper is exactly `ProductCompletion = 12` and uses a `Product`
key whose epoch and validity interval cover `issued_at_unix_ms` in the bound
policy; no activation, source-build, artifact-build, reviewer, or release-root
key may emit `ProductComplete`.

`legacy_absence_result_digest` is the exact-set digest of the source
evidence's legacy-source scan, every referenced candidate verification's
installed legacy-absence result, and, for each `RolledBack = 2` reference,
that branch's rollback-verification legacy-absence result. It cannot be
replaced by a product-signer assertion. Every registered
`LegacyAbsenceSetItemV2.absent` value is canonical `true`; scope and subject
must project exactly from those lower-layer objects.
Only a valid complete `ProductCompletionAttestationV2` may establish
`ProductComplete`.

### 18.8 Exhaustive exact-set digest registry

These are the closed item schemas used by the registry:

```text
enum OperationalTrustRootPurposeV2 : u16 {
    DeploymentAuthorization = 1,
    RollbackAuthorization = 2,
    InstallationActivation = 3,
    InstallerOrMdm = 4
}

OperationalTrustRootSetItemV2 {
    purpose: OperationalTrustRootPurposeV2,
    key_id: Ed25519KeyIdV2,
    key_epoch: u64,
    public_key: Ed25519PublicKeyV2,
    not_before_unix_ms: UnixMillis,
    not_after_unix_ms: UnixMillis
}

enum ReleaseTrustRootSetItemV2 : u16 {
    Root = 1 { root: ReleaseRootKeyV2 },
    ComponentAuthorization = 2 {
        authorization: ComponentSignerAuthorizationV2
    }
}

ObservedKeySlotSetItemV2 {
    key_role_tag: u16,
    key_epoch: u64,
    key_identity_digest: Digest32,
    nonexportable_key_handle_identity_digest: Digest32
}

StoreValidatorSetItemV2 {
    store_id: ClosedStoreIdV2,
    service: ClosedServiceIdV2,
    validator_artifact_digest: Digest32,
    validator_code_identity_digest: Digest32
}

enum SourceCheckCategoryV2 : u16 {
    Unit = 1,
    Property = 2,
    ModelCheck = 3,
    Fuzz = 4,
    ProtocolVector = 5,
    LegacySourceScan = 6
}

RequiredSourceCheckIdentityV2 {
    category: SourceCheckCategoryV2,
    check_identity_digest: Digest32
}

SourceCheckResultSetItemV2 {
    category: SourceCheckCategoryV2,
    check_identity_digest: Digest32,
    tool_identity_digest: Digest32,
    source_revision_digest: Digest32,
    design_tuple_digest: Digest32,
    passed: bool,
    output_digest: Digest32
}

CrateNameSetItemV2 {
    crate_ordinal: u16,
    crate_name: BoundedNfcUtf8V2
}

NativeControlMeasurementSetItemV2 {
    control_identity_digest: Digest32,
    expected_profile_digest: Digest32,
    measured_value_digest: Digest32,
    passed: bool
}

TerminalAttestationSetItemV2 {
    terminal_outcome: PlatformTerminalOutcomeV2,
    terminal_attestation_digest: Digest32
}

enum LegacyAbsenceScopeV2 : u16 {
    SourceTree = 1,
    InstalledCandidate = 2,
    InstalledRollback = 3
}

LegacyAbsenceSetItemV2 {
    scope: LegacyAbsenceScopeV2,
    subject_digest: Digest32,
    result_digest: Digest32,
    absent: bool
}
```

For `ReleaseTrustRootSetItemV2`, the semantic primary key is
`(1, root.role, root.key_id, root.key_epoch)` for `Root` and
`(2, authorization.component.kind,
authorization.component.component_identity_digest)` for
`ComponentAuthorization`. Two authorizations for one component are therefore
duplicates even if they name different signer keys or authorization IDs.

For each registered field `F`, and for no other caller-selected domain, the
digest is exactly:

```text
SHA256(
  exact_ascii_domain_for_F
  || u64_be(item_count)
  || canonical_cbor(items in the registry's strict order)
)
```

The domain bytes below include the displayed terminal `\0`. Item count is
bounded before allocation. Decoding, semantic validation, and strict sorting
precede hashing. Duplicate complete items and duplicate semantic primary keys
are rejected; a verifier never sorts attacker-supplied bytes to repair an
invalid producer order.

| Exact field | Exact NUL-terminated ASCII domain | Exact item schema | Strict sort key |
|---|---|---|---|
| `activation_trust_root_set_digest` | `"savana.set.activation-trust-root.v2\0"` | `OperationalTrustRootSetItemV2`, purpose `InstallationActivation` only | `(purpose, key_id, key_epoch)` |
| `agent_view_projection_set_digest` | `"savana.set.agent-view-projection.v2\0"` | `AgentViewProjectionSetItemV2` | `(projection_field_tag, projection_rule_digest)` |
| `actual_store_state_set_digest` | `"savana.set.actual-store-state.v2\0"` | complete `ActualStoreStateV2` | `(store_id)` |
| `artifact_evidence_set_digest` | `"savana.set.artifact-evidence.v2\0"` | `Digest32` complete signed artifact-evidence digest | digest bytes |
| `completed_step_set_digest` | `"savana.set.bootstrap-maintenance-completed-step.v2\0"` | one `BootstrapMaintenancePhaseV2` numeric tag | numeric tag |
| `corrected_protocol_vector_set_digest` | `"savana.set.corrected-protocol-vector.v2\0"` | `SourceCheckResultSetItemV2`, category `ProtocolVector` only | `(check_identity_digest, tool_identity_digest)` |
| `deployment_trust_root_set_digest` | `"savana.set.deployment-trust-root.v2\0"` | `OperationalTrustRootSetItemV2`, purpose `DeploymentAuthorization` or `RollbackAuthorization` | `(purpose, key_id, key_epoch)` |
| `exact_ten_crate_name_set_digest` | `"savana.set.exact-ten-crate-name.v2\0"` | `CrateNameSetItemV2`; ordinals and names equal section 2.2 exactly | `(crate_ordinal)` |
| `expected_actual_store_state_set_digest` | `"savana.set.expected-actual-store-state.v2\0"` | complete `ActualStoreStateV2` | `(store_id)` |
| `frozen_effect_work_set_digest` | `"savana.set.frozen-effect-work.v2\0"` | complete `FrozenEffectWorkItemV2` | `(kind, owning_service, durable_operation_id, authenticated_head_digest)` |
| `fuzz_result_set_digest` | `"savana.set.fuzz-result.v2\0"` | `SourceCheckResultSetItemV2`, category `Fuzz` only | `(check_identity_digest, tool_identity_digest)` |
| `legacy_source_scan_result_digest` | `"savana.set.legacy-source-scan-result.v2\0"` | `SourceCheckResultSetItemV2`, category `LegacySourceScan` only | `(check_identity_digest, tool_identity_digest)` |
| `model_check_result_digest` | `"savana.set.model-check-result.v2\0"` | `SourceCheckResultSetItemV2`, category `ModelCheck` only | `(check_identity_digest, tool_identity_digest)` |
| `property_test_result_digest` | `"savana.set.property-test-result.v2\0"` | `SourceCheckResultSetItemV2`, category `Property` only | `(check_identity_digest, tool_identity_digest)` |
| `unit_test_result_digest` | `"savana.set.unit-test-result.v2\0"` | `SourceCheckResultSetItemV2`, category `Unit` only | `(check_identity_digest, tool_identity_digest)` |
| `installer_or_mdm_trust_root_set_digest` | `"savana.set.installer-or-mdm-trust-root.v2\0"` | `OperationalTrustRootSetItemV2`, purpose `InstallerOrMdm` only | `(purpose, key_id, key_epoch)` |
| `native_control_measurement_set_digest` | `"savana.set.native-control-measurement.v2\0"` | `NativeControlMeasurementSetItemV2` | `(control_identity_digest)` |
| `new_activation_trust_root_set_digest` | `"savana.set.new-activation-trust-root.v2\0"` | `OperationalTrustRootSetItemV2`, purpose `InstallationActivation` only | `(purpose, key_id, key_epoch)` |
| `new_deployment_trust_root_set_digest` | `"savana.set.new-deployment-trust-root.v2\0"` | `OperationalTrustRootSetItemV2`, deployment/rollback purposes only | `(purpose, key_id, key_epoch)` |
| `new_release_trust_root_set_digest` | `"savana.set.new-release-trust-root.v2\0"` | `ReleaseTrustRootSetItemV2` | `Root`: `(1, root.role, root.key_id, root.key_epoch, canonical_cbor(root))`; `ComponentAuthorization`: `(2, authorization.component.kind, authorization.component.component_identity_digest, authorization.signer_key_id, authorization.signer_key_epoch, authorization.authorization_id, canonical_cbor(authorization))` |
| `observed_key_slot_set_digest` | `"savana.set.observed-key-slot.v2\0"` | `ObservedKeySlotSetItemV2` | `(key_role_tag, key_epoch, key_identity_digest)` |
| `old_activation_trust_root_set_digest` | `"savana.set.old-activation-trust-root.v2\0"` | `OperationalTrustRootSetItemV2`, purpose `InstallationActivation` only | `(purpose, key_id, key_epoch)` |
| `old_deployment_trust_root_set_digest` | `"savana.set.old-deployment-trust-root.v2\0"` | `OperationalTrustRootSetItemV2`, deployment/rollback purposes only | `(purpose, key_id, key_epoch)` |
| `old_release_trust_root_set_digest` | `"savana.set.old-release-trust-root.v2\0"` | `ReleaseTrustRootSetItemV2` | `Root`: `(1, root.role, root.key_id, root.key_epoch, canonical_cbor(root))`; `ComponentAuthorization`: `(2, authorization.component.kind, authorization.component.component_identity_digest, authorization.signer_key_id, authorization.signer_key_epoch, authorization.authorization_id, canonical_cbor(authorization))` |
| `platform_evidence_set_digest` | `"savana.set.platform-evidence.v2\0"` | `Digest32` deterministic platform-evidence digest | digest bytes |
| `release_manifest_set_digest` | `"savana.set.release-manifest.v2\0"` | complete `SignedReleaseManifestEntryV2` | `(manifest_digest, manifest_payload_digest, complete signature-wrapper bytes)` |
| `release_trust_root_set_digest` | `"savana.set.release-trust-root.v2\0"` | `ReleaseTrustRootSetItemV2` | `Root`: `(1, root.role, root.key_id, root.key_epoch, canonical_cbor(root))`; `ComponentAuthorization`: `(2, authorization.component.kind, authorization.component.component_identity_digest, authorization.signer_key_id, authorization.signer_key_epoch, authorization.authorization_id, canonical_cbor(authorization))` |
| `required_platform_tuple_set_digest` | `"savana.set.required-platform-tuple.v2\0"` | complete `RequiredPlatformReleaseTupleV2` | all six fields in schema order |
| `required_source_check_set_digest` | `"savana.set.required-source-check.v2\0"` | `RequiredSourceCheckIdentityV2` | `(category, check_identity_digest)` |
| `review_attestation_set_digest` | `"savana.set.review-attestation.v2\0"` | `Digest32` complete signed review-attestation digest | digest bytes |
| `rollback_native_control_measurement_set_digest` | `"savana.set.rollback-native-control-measurement.v2\0"` | `NativeControlMeasurementSetItemV2` | `(control_identity_digest)` |
| `source_lock_set_digest` | `"savana.set.source-lock.v2\0"` | `Digest32` source-lock digest | digest bytes |
| `staged_activation_trust_root_set_digest` | `"savana.set.staged-activation-trust-root.v2\0"` | `OperationalTrustRootSetItemV2`, purpose `InstallationActivation` only | `(purpose, key_id, key_epoch)` |
| `staged_deployment_trust_root_set_digest` | `"savana.set.staged-deployment-trust-root.v2\0"` | `OperationalTrustRootSetItemV2`, deployment/rollback purposes only | `(purpose, key_id, key_epoch)` |
| `staged_release_trust_root_set_digest` | `"savana.set.staged-release-trust-root.v2\0"` | `ReleaseTrustRootSetItemV2` | `Root`: `(1, root.role, root.key_id, root.key_epoch, canonical_cbor(root))`; `ComponentAuthorization`: `(2, authorization.component.kind, authorization.component.component_identity_digest, authorization.signer_key_id, authorization.signer_key_epoch, authorization.authorization_id, canonical_cbor(authorization))` |
| `terminal_attestation_set_digest` | `"savana.set.terminal-attestation.v2\0"` | `TerminalAttestationSetItemV2` | `(terminal_outcome, terminal_attestation_digest)` |
| `validator_set_digest` | `"savana.set.store-validator.v2\0"` | `StoreValidatorSetItemV2` | `(store_id, service, validator_artifact_digest)` |
| `vault_key_read_set_digest` | `"savana.set.vault-key-read.v2\0"` | `VaultKeyReadSetItemV2` | `(vault_key_role_tag, key_epoch, key_id)` |
| `legacy_absence_result_digest` | `"savana.set.legacy-absence-result.v2\0"` | `LegacyAbsenceSetItemV2`, `absent = true` only | `(scope, subject_digest, result_digest)` |

The four old/new/staged/current release-root fields cover the identical
closed `Root`/`ComponentAuthorization` item union but retain distinct
domains. Likewise, current/old/new/staged activation and deployment fields
never share a domain. Consequently a valid set digest copied between two
fields is invalid even if their item bytes happen to match. Golden vectors
cover zero, one, and maximum item counts for every row; cross-field
substitution, alternate sort, duplicate key, missing NUL, host-endian count,
unknown enum tag, and non-canonical CBOR are mandatory rejection vectors.

All evidence and attestations use bounded canonical objects, fixed digest
domains, and Ed25519 only through `DomainSignatureV2`. They record
measurements and exact result digests, never unstructured success strings.
Source-only test output is not a platform tuple and cannot be promoted by
relabeling.

Source and artifact evidence use their explicit payload and complete-signed
object domains above. The remaining signed evidence/release objects use this
closed table:

| Object | Exact payload-digest ASCII domain | Required wrapper |
|---|---|---|
| `VerificationEvidenceV2` | `"savana.verification-evidence.v2.payload\0"` | `VerificationEvidence = 9` |
| `CommitAttestationV2` | `"savana.commit-attestation.v2.payload\0"` | `CommitAttestation = 10` |
| `RollbackVerificationEvidenceV2` | `"savana.rollback-verification-evidence.v2.payload\0"` | `RollbackVerificationEvidence = 17` |
| `RollbackVerificationAttestationV2` | `"savana.rollback-verification-attestation.v2.payload\0"` | `RollbackVerificationAttestation = 18` |
| `RecoveryRollbackReadinessEvidenceV2` | `"savana.recovery-rollback-readiness.v2.payload\0"` | `RecoveryRollbackReadinessEvidence = 27` |
| `ReviewAttestationV2` | `"savana.review-attestation.v2.payload\0"` | `ReviewAttestation = 11` |
| `ProductReleaseV2` | `"savana.product-release.v2.payload\0"` | `ProductRelease = 19` |
| `ProductCompletionAttestationV2` | `"savana.product-completion-attestation.v2.payload\0"` | `ProductCompletion = 12` |

For each row, the payload digest excludes only the final signature wrapper
and is `SHA256(exact payload domain || canonical_cbor(payload fields))`. The
complete signed object digest used by references is
`SHA256(the same ASCII domain with ".payload\0" replaced by ".signed\0" ||
canonical_cbor(complete object including DomainSignatureV2))`. No producer
supplies a domain, raw `Ed25519SignatureV2` is illegal in these objects, and a
wrapper tag from another row is rejected before key lookup.

The monotonic dependency graph is closed:

```text
SourceEvidenceV2
  → ArtifactEvidenceV2
  → VerificationEvidenceV2
  → (CommitAttestationV2
     | RollbackVerificationEvidenceV2
       + RollbackVerificationAttestationV2)
  → PlatformEvidenceV2
  → ReviewAttestationV2
  → ProductCompletionAttestationV2

ProductReleaseV2
  → ProductCompletionAttestationV2
```

The arrow means “the later object contains the earlier signed digest.” Source
evidence contains no artifact, platform, review, or product digest. Artifact
evidence contains exactly one source digest and no platform, review, or
product digest. Verification and either terminal branch contain exactly one
matching source/artifact pair and no platform, review, or product digest.
The rollback-attestation branch additionally contains the matching candidate
verification and rollback-verification digests; the commit branch contains
neither rollback digest.
`PlatformEvidenceV2` is the unsigned deterministic composition defined above.
Reviews contain the final lower-layer sets but no product digest. Product
evidence embeds exactly one independently signed product release and contains
only already final lower-layer objects and reviews. An early-origin
`RecoveryRollbackReadinessEvidenceV2` may support an operational
`ROLLED_BACK` terminal record but has no edge into `PlatformEvidenceV2`,
review, or product completion. Neither
the transaction, manifest, product release, nor trust policy contains a
platform- or product-evidence digest. Any reverse edge, self digest, mismatched
duplicate field, or cross-policy/release substitution is rejection.

## 19. Platform-complete gates

An OS/architecture tuple is `PlatformComplete` only when all of the following
are green for the exact installed manifest:

1. reproducible release build and source/SBOM/toolchain locks;
2. fixed-width/Ed25519 and explicit-enum-tag canonical manifest, intent,
   payload, grant, plans,
   ledger slots, operational/release trust-root sets, bootstrap
   intent/record/marker/selector/slot closure, epoch attestation, evidence
   trust policy, source/artifact
   evidence, verification, commit, rollback-verification, terminal-union,
   platform-composition, review, and product golden vectors;
3. signature, expiry, equivocation, downgrade, and installation-binding
   negative tests;
4. crash injection at every deployment phase and every durability boundary;
5. power-loss recovery, PID-reuse, short-held-lock, helper/watchdog takeover,
   shared-only/exclusive EffectGate capability, planner-hold expiry,
   effect-lease, and simultaneous race tests;
6. full rollback closure, phase-bound high-water, support-horizon, actual-store
   snapshot, non-root copy-validator, migration, and key-slot tests;
7. root-helper adversarial filesystem tests for links, mounts, races,
   permissions, ACL/xattr, sparse files, unknown entries, hard limits, and the
   exact descriptor-excluding staging Merkle rule;
8. exact service identity, approvalctl admin edge, parser/connector
   transient UID/job-nonce isolation, anonymous one-shot channels, local IPC,
   key ACL, and cross-role
   rejection tests;
9. measured native sandbox, service-specific store projection, code integrity,
   deny-first egress/effect fence, network, and filesystem controls;
10. isolated required-mode E2E with production-format signed artifacts;
11. protected post-deploy acceptance with real keystore handles, cloned
    non-empty actual state, and the controlled isolation sink;
12. install, distinct `INSTALLED`/`VERIFIED`, reconstructible postcommit or
    rollback-terminal attestation, failed candidate rollback through distinct
    `ROLLBACK_INSTALLED`/`ROLLBACK_VERIFIED`/`ROLLED_BACK`, repeated reboot
    after consumed rollback, and later forward upgrade above highest-ever;
13. dual-slot conflict-table, generation/fence-envelope, WAL/journal binding,
    crash-window, bounded evidence GC, and artifact reachability tests;
14. offline OS-native bootstrap maintenance creates a new installation epoch,
    fresh activation key, initial attestation, and no inherited completion
    claim;
15. proof that V1 dispatchers, fallback mode, Python authority/data paths,
    public reload, debug bypasses, and development launchers are absent;
16. fuzzing of all privileged canonical decoders, closed plan enums, bounded
    evidence decoders, and staged-tree validators;
17. monotonic four-layer evidence-chain validation, exact-set validation for
    source/artifact/platform/domain-tagged-terminal tuples, and three
    independently authorized `ReviewAttestationV2` values reporting
    `Critical=0, Important=0, Minor=0`.
18. the exhaustive section 18.8 field/domain/item/order vectors, including
    every trust-root alias, agent claim set, legacy-absence set, and
    cross-field substitution rejection;
19. a valid signed `ProductReleaseV2` whose signed manifest entries and exact
    six-field required platform tuples are set-equal to completion evidence;
20. dual-signature installation-epoch/profile vectors proving both wrappers
    cover identical payload bytes and resolve through the exact signer/root
    sets;
21. concurrent A/B EffectGate coordinator ordering, service crash with a
    manager-retained inherited FD, frozen-work exact-set reconciliation, and
    proof that helper/watchdog never write role journals;
22. atomic Linux cgroup-BPF generation replacement and rejection at wrong
    address, transport, port, TLS/SPKI pin, service cgroup, or manifest
    generation;
23. the protocol-owned signed parser-worker descriptor/result domains and
    frame transcript plus the signed connector-codec job descriptor,
    `Job`/`PreparedRequest`/`ProviderResponse`/`Outcome` frames,
    prepared-request/outcome attestation domains, ordered codec transcript,
    `PrepareAndDecode`/`DecodeRetainedResponse` mode and recovery matrices,
    effect-receipt binding, ephemeral-key, exact input/response, artifact,
    nonce, anonymous-channel, network/credential absence, browser-origin
    provenance, and `protocol_payload`/manifest/worker ABI equality vectors,
    plus crash/recovery vectors for `ProviderAttemptPrepared`,
    `ProviderRetryPrepared`, `EffectStarted`, `ProviderResponseRetained`,
    `ReleaseEvidencePrepared`, and the terminal completion states, proving
    full `ExecutorEffectStartedReceiptRecordV2` recovery,
    retained-response recovery, retry lineage/spent-state preservation, and
    the `ExecutorFinalReleaseAuditEvidenceV2` predecessor before any
    service-signed final receipt;
24. terminal transaction-head/core retention, head-before-ledger crash
    boundaries, bootstrap selector tag-31 substitution tests, and pre/post
    selector power-loss recovery.
25. every normal desired/rollback manifest's bootstrap-lock digest equals the
    selected active offline slot, and every normal artifact/install plan is
    mechanically free of bootstrap-owned paths and objects even when those
    binaries share the kerneld source crate.

`ProductComplete` requires independent `PlatformComplete` evidence for every
advertised production platform. For this design that means the supported
Linux and macOS architecture tuples declared in the release manifest.

## 20. Required negative tests

At minimum, tests must prove rejection of:

- normal installation at or below any changed highest-ever sequence;
- sequence reuse with a different digest or key epoch;
- omission, duplication, or downgrade of `DisplayProjection`,
  `EgressPolicySet`, `ExecutorConnectorRegistry`, `ExecutorKeyLock`,
  `PlannerLock`, `CompletionEvidenceTrustPolicy`, `ReleaseTrustRootSet`, or
  `ServiceStoreProjectionSet`;
- an oversized descriptor/tree/plan/evidence object, unknown enum, noncanonical
  or implicit/aliased/Rust-ordinal enum tag, noncanonical primitive width,
  non-Ed25519 signature, cross-domain plan digest, an
  `Ed25519KeyIdV2`/`HpkeX25519KeyIdV2`/`ReplayAeadKeyIdV2`/`VaultKeyIdV2`
  cross-family decode or substitution, ambiguous Merkle tree, or staging
  digest that includes or ignores the wrong entry;
- a raw signature outside `DomainSignatureV2`, a valid wrapper moved between
  any two defined signature domains, a tag/domain literal disagreement, or
  a `BootstrapActiveSelectorV2` accepted under
  `BootstrapMaintenanceRecord = 24`;
- an `OperationalTrustRootSet = 28` wrapper with a binding/purpose/member
  mismatch, member digest under the other family domain, cross-family or
  cross-binding predecessor, sequence gap/fork, or
  `VersionedIdentityV2.content_digest` replaced by its member-set digest;
- a transaction ID reused for a different intent or outside idempotent
  recovery of the current nonterminal transaction, a nonrandom or
  descriptor-derived transaction ID, an intent/grant/payload digest mismatch,
  or any attempted digest/signature cycle;
- rollback without the exact prearmed grant;
- a grant for another install, transaction, pre-state, desired state, rollback
  state, intent digest, identity profile, installation epoch, phase high-water,
  or support horizon;
- second consumption of a grant;
- rollback after commit;
- a rollback that skips or conflates `ROLLBACK_INSTALLED`,
  `ROLLBACK_VERIFIED`, or `ROLLED_BACK`, or uses the high-water value for a
  different rollback-origin phase;
- partial rollback closure, manifest-declared compatibility without actual
  store attestation, root-only validation substituted for the service UID
  copy-validator, or rollback-incompatible persistent store;
- replacement of helper/watchdog/trust roots through an application
  transaction;
- a normal desired or rollback manifest whose `BootstrapTcbLockV2` differs
  from the selected active offline slot, or a normal staging/install plan that
  contains any bootstrap-owned path, helper, watchdog, verifier/schema,
  selector, trust root, ledger genesis, keystore, profile, or receipt;
- any online bootstrap-maintenance surface, helper self-replacement, trust-root
  live rotation, partial offline package, reused activation key, missing epoch
  attestation, or old-epoch completion claim;
- a torn/missing selector, selector without its exact commit marker, tag-31
  selector signature over any digest other than its checksum, selector switch
  before files/roots/keystore/profile/genesis durability, pre-switch resume
  that changes the old selector, post-switch recovery that guesses a slot, a
  slot closure/attestation using a genesis payload digest instead of the
  complete signed ledger digest, or a commit marker naming the later
  `CommitMarkerDurable` head instead of its durable `GenesisStaged`
  predecessor;
- an installation profile referenced by payload digest rather than complete
  signed digest, a tag-6/tag-7 signature swap, two epoch signatures over
  different payload encodings, or signer ID/epoch/root-set disagreement;
- non-root helper invocation;
- arbitrary path, service, command, script, environment, or inherited-fd
  input;
- user-writable ancestor, link, mount crossing, file swap, hardlink,
  capability, unexpected ACL/xattr, or unknown tree member;
- ledger/store on unsupported or nonlocal filesystems;
- direct non-root traversal of the `0700` root store, a shared store-reader
  group, mutable projection, cross-service projection, or App Group store;
- two different valid ledger slots at one generation, a generation gap,
  invalid predecessor, installation-epoch conflict, or an unauthenticated
  selector overriding the conflict table;
- `None` transaction head in any transaction-bearing or terminal phase,
  terminal head/core deletion, ledger selection with a missing/mismatched
  durable head/core, head append treated as progress before ledger CAS, or GC
  of an aborted head/core retained by compacted `IDLE` provenance;
- a service starting during a nonterminal transaction or while effect-fenced;
- an effect envelope missing/mismatching `deployment_generation` or
  `effect_fence_epoch`, an execd path that releases its shared lease before a
  durable terminal/indeterminate record, helper arming without the exclusive
  lease, or any missing OS deny-all fence;
- agentd or execd receiving a write-open gate or writable ledger descriptor,
  obtaining an exclusive lock through its read-open descriptor, reopening or
  transferring gate authority, inheriting it into a worker, or relying on a
  cached ledger value after shared acquisition;
- Linux OFD/flock use, a second in-process FD for the gate inode, any
  business-code open/close/dup/fcntl/fork/exec path, A completing before B and
  releasing B's lock, B completing before A and releasing A's lock, or a
  crashed service lock remaining held merely because systemd/launchd retains
  the inherited open-file description;
- arming before OS deny installation or complete frozen-set capture, releasing
  the exclusive gate before the `ARMED` head/ledger flush, an extra or missing
  frozen marker/WAL/journal head, helper/watchdog writing a role journal,
  `EffectStarted` mapped to `FailedNoEffect`, or entry to `QUIESCED` before
  every exact frozen item has one allowed terminal descendant;
- agentd invoking kerneld op29/op34 without a coordinator guard, releasing the
  guard before kerneld's durable response/failure, or a concurrent dispatch
  crossing exclusive acquisition/frozen-set enumeration and creating an
  unenumerated `PrepareEffect` WAL record;
- a planner hold without the compiled deadline and durable exact-process
  marker, a caller-extended deadline, expiry without terminating the exact
  unit/job and descendants, a late response accepted after expiry, or
  deployment continuing before durable fail-closed reconciliation;
- watchdog starvation by a held deployment mutex, takeover without exact
  pidfd/process identity, or PID-reuse confusion;
- one role using another role's socket, XPC service, group, App Group, key, or
  designated requirement;
- a same-UID Linux process reading or invoking the JARVIS client key, an
  exportable JARVIS key, or an opaque handle surviving unauthorized exec;
- a parser/connector job under the wrong/shared UID, without the measured
  transient launcher and anonymous one-shot channel, with a reused/wrong-domain
  nonce, or with more than one request;
- a browser-originated `ExtractedPage`, parser output without its signed
  descriptor/result pair, parent-signed worker result, reused or persistent
  ephemeral result key, noncontiguous/duplicate page, input/artifact/deadline
  mismatch, inherited network/gate/store FD, or accepted result before durable
  nonce terminalization;
- a connector-codec descriptor, prepared request, provider response, or
  outcome under the parser/parent/wrong ephemeral key or signature domain;
  cross-job/channel/nonce/attempt substitution; reordered, missing, duplicate,
  or mode-illegal frames; `PrepareAndDecode` without the exact effect-start
  receipt before provider-response processing; `DecodeRetainedResponse`
  emitting an external byte; a changed stable binding on retry; more than the
  mode's exact prepared-request/outcome attestation count; a worker outcome
  containing `ExecutorCompletionDescriptorV2`,
  `ExecutorCompletionPayloadV2`, a service-signed receipt, journal record, or
  audit authority; a `ProviderRetryPrepared` descendant becoming
  `FailedNoEffect`; loss/change of prior spent/effect-receipt lineage on
  retry; a durable provider response without
  `ProviderResponseRetained`; or release-success publication before
  `ReleaseEvidencePrepared` and its exact audit/evidence gates;
- a `ServiceIdentityLockProtocolPayloadV2.protocol_abi_digest` that differs
  from the manifest `ProtocolLock` content digest, or a replay edge/worker
  descriptor that substitutes a third protocol ABI while either of those two
  fields remains validly signed;
- existence of a parser/connector filesystem socket path, reusable listener,
  systemd `Accept=yes` worker unit, launchd worker service name, successful
  external connection attempt, retained launcher channel copy, or a second job
  on one anonymous channel;
- approval admin access by a non-private binary, generic root XPC client, or
  non-admin transcript;
- missing seccomp, Landlock, systemd, PF, App Sandbox, Hardened Runtime,
  entitlement, notarization, or code-identity enforcement;
- Linux normal egress without the exact atomic cgroup-BPF generation map, with
  `IPAddressAllow` treated as authority, or accepting the wrong service
  cgroup, literal address/prefix, transport, destination port, TLS version,
  mTLS identity, application protocol, or SPKI pin;
- macOS agentd missing either required server/client entitlement, sharing a
  LaunchDaemon UID, PF identity resolved by mutable name, or any dynamic proxy,
  PAC, DNS, sidecar, or transparent-egress widening;
- a test service contacting a production planner/tool/destination; protected
  acceptance using empty state, test/exported keys, or a non-isolated sink;
- precommit evidence claiming commit, commit depending on postcommit evidence,
  preterminal rollback evidence claiming final `ROLLED_BACK`, a
  non-reconstructible commit/rollback terminal attestation, or evidence
  generated from a different manifest/generation/epoch than the active
  installed state;
- source evidence for a dirty/different revision, wrong design digest,
  stale/missing protocol vector, skipped required test/fuzz/model result, or
  incomplete legacy scan;
- artifact evidence with another source-evidence digest, toolchain, SBOM,
  source lock, manifest, ten-crate closure, unsigned/extra/missing binary
  target, or wrong-role signer;
- source, artifact, review, or product evidence under an absent, expired,
  wrong-epoch, wrong-role, cross-policy, or unauthorized signer;
- a release trust-root set with a missing/extra component authorization,
  missing/duplicate component signature, component/signature cardinality
  mismatch, wrong branch-specific union order, old/new/staged/current
  member-vector or digest-domain substitution, self-signing root cycle, or
  application-selected release root;
- a replay capsule sealed by a retired epoch, decrypted by a fifth retained
  epoch, carrying a `ReplayAeadKeyIdV2` that differs from its selected
  role/epoch or derived key-identity digest, decoded as a generic `Digest32`,
  read cross-manifest without the exact directional `ReadExisting`
  edge and `PersistentStoreCompatibilityV2` digest, online-rewrapped/resealed,
  retained beyond its ceiling, decrypted by a non-agentd role, used for boot
  or action/effect state instead of `DurableTaskHandleEmission`, supplied
  under a protocol-local duplicate edge ABI, or made available after an
  installation-epoch change;
- an agent claim read with an empty/missing/reversed/expired compatibility
  edge, changed logical agentd identity, protocol ABI or claim schema
  mismatch, broader vault-key/view set, store-compatibility mismatch, or edge
  lacking exact release-root component authorization;
- verification, commit, rollback-verification, or platform composition whose
  source/artifact/policy digests disagree, that binds zero or multiple
  artifact evidence values, or that introduces a reverse/self/higher-layer
  evidence edge;
- a rollback platform-evidence branch without the exact candidate
  verification, with an origin other than `Verified = 4`, with a
  `RecoveryOrigin` terminal-readiness reference, a non-`ConsumedRollback`
  activation, a final phase other than healthy unfenced `ROLLED_BACK`, or a
  mismatch in its actual-store/native-control/effect-fence/E2E/readiness
  results;
- an early `Armed`/`Quiesced`/`Installed` rollback lacking its exact
  phase-tagged measurements or role-journal reconciliation, paired with
  candidate verification, or promoted from operational `ROLLED_BACK` into
  platform evidence, review, or product completion;
- a terminal tag/digest mismatch, a commit digest under `RolledBack = 2`, a
  rollback attestation under `Committed = 1`, a second terminal digest,
  rollback data smuggled into `CommitAttestationV2`, commit data smuggled into
  `RollbackVerificationAttestationV2`, or any duplicated terminal/platform
  field that disagrees;
- a product attestation with a subset, superset, duplicate, or cross-release
  mixture of source, artifact, platform, domain-tagged terminal, or review
  tuples, or whose legacy-absence digest is not the exact lower-layer result
  set;
- a product release with an unsigned/payload-only/ambiguous manifest entry,
  wrong release root, nonmonotonic sequence, invalid predecessor, a two-field
  platform advertisement, or any missing/extra/mismatched member of the exact
  six-field `(os, architecture, manifest, source-lock, protocol-lock,
  platform-closure)` tuple set;
- any registered set using another field's domain, caller-supplied domain,
  missing NUL, host-endian count, alternate order, duplicate semantic key,
  unknown item tag, noncanonical item, or omitted/extra item;
- evidence implicitly pinning historical artifact closures, GC deleting a
  reachable closure, or pruning without an authenticated bounded checkpoint;
- source-only test results being labelled `PlatformComplete` or
  `ProductComplete`.

## 21. Deployment completion rule

Deployment work is complete only when:

- the exact schemas and state machine in this document are implemented;
- the root helper/watchdog and native manifests are signed release artifacts;
- the sole-ledger and rollback semantics survive exhaustive crash injection;
- Linux and macOS isolation are measured on supported native systems;
- isolated required-mode E2E and protected real-keystore/non-empty-state
  acceptance pass on the exact signed installed closures;
- legacy and fallback paths are absent;
- the exact revision has valid `SourceEvidenceV2`, each installed manifest has
  valid `ArtifactEvidenceV2`, and each platform has exact
  `VerificationEvidenceV2`, exactly one reconstructible
  `CommitAttestationV2` or rollback-verification terminal branch, and the
  deterministic `PlatformEvidenceV2` composition;
- three independent reviews of the frozen source and artifacts report
  `Critical=0, Important=0, Minor=0`; and
- `ProductCompletionAttestationV2` contains exact set-equal platform,
  domain-tagged terminal-attestation, and review tuples for every advertised
  production platform.

Until then, the strongest allowed status is the exact independently
verifiable attestation actually present. A label, dashboard state, installer
exit code, offline bootstrap update, or missing-tuple aggregate cannot emit a
broader product-security claim.
