# Private managed administration and atomic enrollment (v0.4)

## Implemented scope

This includes the Rust owner-side command/transaction layer, an opt-in native
Linux root-only admin socket, and Rust/Python operator submission wrappers.
It is **not yet a consumer browser management route or turnkey signing/import
utility**. No administrator credential or live state was created or modified.
Existing task approval settlements are not reinterpreted as permission to mutate
the private source. The operator transport does not grant rights to chat users.

`VerifiedManagedAdminCommandV04::verify` verifies a bounded canonical signed
command against an independently selected administrator key, installation and
owner store. `DurableG4StateV2::apply_managed_admin_v04` applies that proof and
persists the exact historical receipt in the same transaction as the mutation.
The Linux host authenticates the private operator using root Unix peer credentials
and chooses a separately pinned public key from the verified signed deployment
bootstrap. The owner thread reverifies every submission, including receipt replays.
The command cannot select its own trust key. Administrator-key provisioning,
online rotation/revocation and a consumer authentication UI remain unimplemented;
changing admin trust requires a verified configuration and daemon restart.

Supported command operations:

| Operation | Effect |
| --- | --- |
| `RegisterSource` | Install an independently signed immutable source policy |
| `CreateResource` | Import private bytes under a fresh owner-generated object ID |
| `UpdateResource` | Edit by exact expected revision, or tombstone with `value: null` |
| `EnrollTask` | Atomically install signed continuation storage and accounting policies under an already installed task root |
| `EnrollPlanning` | Install a signed finite planning profile under the existing root |
| `ApprovePlanningRecipes` | Install one separately signed immutable recipe allowlist for that profile, without G6/G7 authority |

`ApprovePlanningRecipes` requires a canonical `FusedRecipeApprovalV04` with its own
purpose-separated signature by the selected operator key. It binds schema/recipe
version, installation, manifest, task/root, exact planning-profile digest, deployment
generation, validity and the complete sorted operation-to-recipe mapping. It cannot
be mixed with legacy exact execution bindings. The owner rejects missing/wrong
profiles, stale/revoked roots, clock regression, lifetime widening, existing task
effects and any second approval installation (even under a new command ID).

Admission stores the record and `PlanningRecipesApproved` receipt atomically in
encrypted rollback-protected payload schema **14**. Exact command replay returns
the historical receipt even after expiry or root revocation, but cannot revive
authority. Restore validates the profile/root link and receipt-to-approval digest;
schema downgrade or loss/substitution of the record is rejected.

The declared deployment generation is pinned in the signed artifact. The private
compiler compares it against the actual current-deployment lease when checking
the recipe; receipt/admission alone is not evidence that this generation is live.
The compiler's result is private and informational: G7 still refuses recipe-only
execution. There is no new Agent RPC, and no consumer signing UI is implemented.

Offline preparation now accepts `prepare_artifact("recipe_approval", bytes)` in
Rust/Python. It validates/canonicalizes only; operators must independently review
the local action/source material and sign the resulting digest. No private key is
loaded and no command is submitted by preparation.

The administrator cannot choose an object birth ID through creation. An enrollment
command cannot create a task root, amend its permissions, execute an action, grant
model access, or publish private values. Source and task policies retain their own
purpose-separated signatures and verification. Resource-fact issuer and command
administrator must differ for source registration/enrollment.

## Signed data and bounded processing

`ManagedAdminCommandV04` contains schema 1, installation, owner store, nonzero
request ID, not-before/expiry, and one closed operation. Its canonical JSON and
purpose-separated signing digest bind the entire operation including imported
bytes, labels, revisions and nested policies/signatures. Incoming commands are
limited to 256 KiB before decoding; canonical round-trip, signature, unknown-field
and namespace checks are required. Existing object, source, profile and global
state bounds also apply. No paths, templates or model-produced facts are resolved.

These bytes are private administrative input. Do not place signed import commands
in model prompts, public logs, URLs, or an unauthenticated status channel. The
local transport protects requests/receipts with root-only Unix socket access;
signatures alone do not provide confidentiality. OS/root compromise is outside
this local transport's protection, and it is not remote encrypted transport.
The owner stores imported content in its existing
encrypted, rollback-protected state, not in the receipt journal.

## Retry, failure and recovery

The encrypted journal binds each request ID to command digest, verified issuer
and result. Exact replay returns the original private receipt, including the
original generated object ID. Reusing an ID with different contents or issuer is
refused. A new ID is a distinct operation: this is request deduplication, **not**
external business-entity deduplication.

The operation and receipt commit together using the existing owner/anchor path.
Before-commit failure leaves neither mutation nor receipt. An uncertain commit
poisons the owner until recovery; after authenticated reopen, the original
command retrieves the recovered receipt rather than creating another object.
Enrollment installs both policies or neither. Replay and exact re-enrollment do
not clear reservations, snapshots, observation history or stable consumption.

An expired **new** command is refused. An already committed exact command may
return its historical receipt after expiry, deletion or task revocation. That
receipt is an observation, not current authority; it never resurrects data or
unrevokes the task. Private receipts intentionally have redacted Debug output and
no public serialization implementation.

The journal retains at most 1024 receipts per owner with no delete/reset API.
When full, new mutations fail atomically; exact replay remains available.
Capacity exhaustion is a conservative operational limit, not permission to evict
old IDs. Larger installations need an explicitly reviewed retention design.

## Storage compatibility and tests

The first successful admin command upgrades owner payload schema to 10. The
optional empty admin journal is omitted, preserving earlier continuation encodings
until first use. A schema below 10 cannot carry the journal. Reopen validates
nonzero unique IDs, issuer keys, result shapes and links to retained source,
object/revision and enrolled task/profile records. No live migration was run.

Fifteen focused tests exercise registration signatures, encrypted creation and
restart/retry, changed-command/issuer conflicts, edit/delete replay, stale revisions,
expiry, malformed/noncanonical/oversized input, cross-store proof refusal, atomic
enrollment, missing source/root, real G7 consumption preservation, revoked roots,
precommit failure, both uncertain-anchor cuts, schema/link corruption and journal
capacity. Tests operate on temporary encrypted owners with test keys; they are
not native Linux or browser end-to-end acceptance.

## Linux operator endpoint and SDK

The optional bootstrap field is `managed_admin: {"key_id": "<64 hex>",
"public_key": "<64 hex>"}`. It is inside the existing signed service configuration,
not taken from the submitted command or process environment. Key ID, strong key,
installation/store binding and role separation are checked. No private admin seed
is loaded into kerneld. Absent means disabled; macOS rejects an enabled setting.

Activation requires the additional inherited descriptor
`savana-managed-admin-v04` at `/run/savana/kerneld/admin/managed-v04.sock`.
Unexpected, missing, incorrectly named or unsafe listeners fail startup. The
optional socket unit creates a root:root `0600` socket under root:root `0711`
`admin/`: traversal permits the unprivileged daemon to inspect socket metadata,
but does not allow another UID to connect. Both peer UID and GID must be zero.
The optional `savana-kerneld-managed-admin-v04.conf` service drop-in and socket
file are shipped but not installed/enabled by this change. They must be included
in the reviewed deployment alongside the signed bootstrap and measured binaries.

Wire format (local/private only): 4-byte big-endian canonical-command length,
exact command bytes (1..262144), 64 signature bytes, then client write-half EOF.
Extra/truncated bytes are refused before mutation. The response is a 4-byte length
and JSON, bounded by the SDK to 4096 bytes. A successful response carries schema,
`committed`, request ID, command digest, and typed historical result. Failure is
generic `not_confirmed` or a disconnected stream, not an assertion of rollback.
Each connection has an absolute five-second I/O/admission deadline, updated before
each read/write. Durable work already claimed may finish after the caller times
out; the exact signed command resolves this ambiguity. No automatic retries occur.

The transport has one dedicated bounded worker, shares the existing bounded owner
queue with Agent/Ingress, and writes through the same `DurableG4StateV2` instance.
It never opens a second owner/database or passes through Agent authorization.
Disabled admin trust, wrong signatures and expired new commands fail closed.
The SDK uses the fixed local path, root filesystem checks and root server peer
credentials (systemd created the listening socket), then binds the private reply
to the exact request/digest and operation result. It exposes no remote URL option.

Python, in an already authorized **local operator process**, after an independent
signing workflow produced canonical bytes and a signature:

```python
from savana.managed_admin import submit_signed

receipt = await submit_signed(canonical_command_bytes, signature_bytes)
private_result_json = receipt.private_json()  # private operator UI only
```

Python performs only size/type checks and offloads to Rust. Rust parses the
command, checks the local endpoint, frames I/O and validates the receipt. There is
no `sign`, `grant`, or permission-minting API here. The receipt cannot be directly
constructed from Python and has a redacted repr. Neither `private_json()` nor
Python heap copies are promised secret-zeroizing; do not log them. Cancelling the
Python coroutine does not cancel already-claimed native durable work.

Additional verification: real owner-thread registration/import/delete/retry and
wrong-key/expired-queue cases; bounded frames, half-close and absolute socket
deadlines; native non-root/unsupported-platform peer rejection; SDK canonical
command and exact-result checks; real Python-extension argument/receipt tests and
wrapper offload/no-retry tests. The host run passed 311 kerneld tests, the client
all-target suite, and 3 Python wrapper tests. Linux-target `savana-client` compile
passed; kerneld Linux cross-check was blocked in `ring` by the missing Linux C
toolchain/sysroot. Native Linux CI coverage is added but has not been run here.

Still pending: key provisioning/signing workflow, consumer source import/enrollment
approval UI, private payload construction, provider effects/recovery, residual
replacement/compiler, exclusive publication and native Linux deployment acceptance.
Cloud/DeepSeek remain disabled placeholders.
