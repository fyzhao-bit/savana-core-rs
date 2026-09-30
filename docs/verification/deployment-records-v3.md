# TPM-backed deployment records V3

Implemented 2026-09-20. This is an authenticated record/journal/archive layer,
ledger-history verifier and two typed evidence consumers. **It is not the completed V3 deployment state machine,
V2 migration, installer/watchdog integration, or a kernel boot permit.** Old V2
Ed25519 records and their fail-closed production constructors are unchanged.
Cloud models remain disabled placeholders; no existing installation was changed.

## Separate wire format and trust boundary

`VerifiedDeploymentRecordEnvelopeV3::verify_for` verifies a bounded, canonical
`SDR3` envelope. It binds the independently verified enrollment digest,
installation, epoch, deployment store, closed purpose, sequence, previous head,
deployment generation, transaction, timestamp and entire payload. The maximum
payload is 1 MiB. Unknown purposes, trailing bytes, wrong bindings, expired
enrollment, future timestamps and changed payloads reject. A zero transaction is
installation scope only; typed consumers decide whether that scope is legal.

All 13 existing purpose tags have V3 cryptographic envelopes, **not 13 completed
semantic consumers**. LedgerActivation now has a ledger consumer alongside the
VerificationEvidence and CommitAttestation consumers. Signing uses the separate V3 P-256 suite. No 64-byte V2
Ed25519 signature or 32-byte Ed25519 key field is repurposed as a TPM field.
The full signed record has a domain-separated digest used as its deployment
state head. An authenticated payload is still just bytes until the relevant
semantic consumer checks it. Neither the envelope nor the typed evidence below
can be converted into a V2 startup authorization.

## Two typed consumers

`VerificationClaimsV3` canonically binds the 28 existing verification digest
roles, installation epoch, transaction, deployment generation, fence, time, and
exact root-helper/watchdog artifact identities. `VerifiedVerificationEvidenceV3`
compares every field against independently reconstructed expected claims and
checks the record installation, epoch and timestamp relationship.

`CommitClaimsV3` canonically binds 16 commit digest roles, platform, epoch,
transaction, generation, fence, time and closed terminal flags. Its verifier also
requires the supplied verified evidence's exact signed-record digest, the same
enrollment and transaction, later generation and journal sequence, the next
fence, nondecreasing evidence time, matching OS/architecture and 13 shared
material digests. An externally signed but different enrollment cannot be
spliced into this chain even with the same TPM key and installation/epoch.

`validate_installed_ledger` additionally checks the actual Installed ledger's
identity, epoch, transaction, generation, fence, profile and high-water digest.
The candidate installed manifest is not confused with the old active manifest:
the transaction core must still authorize that candidate. `validate_committed_ledger`
matches the actual Committed payload digest, active manifest, high-water digest,
time and exact terminal state. Both require the complete intervening journal
ancestry, same enrollment/transaction/generation and no intervening ledger update.

Expected claims must come from the trusted deployment driver and actual measured
materials, **never from the object's self-declared claims or a model**. These
interfaces do not acquire measurements, authorize a transaction or open bootstrap.
Present NV commitment must come from the native journal, not a caller-invented
head. In
particular, a correctly signed prepared record is not an active deployment.

## Native durable journal

`LinuxDeploymentJournalV3::open_fixed` is root-only and uses only the fixed
measured TPM authority, native clock, and `/var/lib/savana/deployment-v3`.
There is no production signer, path, clock or transport injection. The existing
authority enforces deployer role, enrollment guard and PCR-gated key possession.
The Deployment NV slot is exclusive to this journal protocol; its sequence and
digest must not be mixed with the old V2 ledger protocol.

The directory must already exist as root:root 0700. Parent directories are
descriptor-opened without following symlinks and must be root-owned and not
writable by other users. The fixed lifetime lock is rechecked against its inode,
as is the directory. Records and preparation files must be single-link regular
root files with mode 0400/0600; special files are opened nonblocking so a FIFO
cannot hang before the file-type check. An existing legacy deployment directory
causes refusal rather than an implicit import or reset.

Commit ordering:

1. Authenticate both A/B slots and obtain the current full head from the TPM
   authority. Require the caller's expected head to match.
2. Sign and verify the exact next record. Durably publish its immutable
   content-addressed archive file, using no-replace rename. Then write the alternate slot using a
   checked temporary, file fsync, atomic rename and directory fsync.
3. Advance the Deployment NV head once through the existing authority; require
   exact head readback before returning success.

On reopen, only the record whose full signed hash equals the anchored head is
committed. A valid next record is exposed separately as prepared and is never
auto-promoted. Explicit resumption must supply the exact same scope/payload and
reuses the original signature/bytes. A different pending operation rejects.
A lost reply after NV advancement reopens at the new committed head; replaying
the old expected head rejects. Any ambiguous error poisons the live handle.
Missing committed records, disk rollback, wrong-slot records and discontinuity
fail closed. There is no automatic discard, reset, refund or garbage collection.

The A/B slots still retain at most two records, but the new immutable archive
retains every committed record in the same root-only directory. `history()` walks
backward from the live full TPM head, verifying each record hash, signature,
enrollment, predecessor and timestamp, then returns chronological records. It
never enumerates arbitrary files or treats orphan/prepared files as committed.
Open and append validate the full prior archive; deleting a record that already
left the A/B slots still prevents reopening. An archive failure precedes any A/B
publication or NV advance. There is no silent legacy archive reconstruction.

History is bounded at 4096 records and 16 MiB of canonical records. At the limit
new appends fail closed; automatic compaction/GC, epoch migration and renewal are
not implemented. Rechecking full history is deliberately not claimed as an
incremental-verification or performance result. Orphans are retained, not deleted.

## Ledger state and history semantics

`DeploymentLedgerStateV3` has a distinct canonical `SLV3` payload with all 29
high-water entries in closed order. Its unsigned constructor is not authority.
The authenticated consumer binds this payload to the V3 envelope and reuses the
existing phase/fence/grant transition rules without reinterpreting a V2 signature.
Normal, abort, rollback and failed-safe paths are checked. Bootstrap bridge/epoch
migration is explicitly rejected until its continuity protocol is implemented.

Successors require exact generation and payload predecessor, retained identity
profile/TCB lock, nondecreasing time and high-water sequences/key epochs. An equal
high-water sequence cannot change digest or key epoch. Active manifest changes
are confined to their terminal transitions; rollback origin must match the phase
actually left. These checks do not replace transaction-head or rollback-grant
authorization and target verification.
The rollback-grant ID is explicit in every transaction-bearing ledger record,
immutable within that transaction, and must match a terminal rollback activation.
History remembers IDs from Prepared onward, including grants burned by abort or
normal commit; using another transaction in between cannot make them fresh again.

`DeploymentLedgerHistoryV3::verify` requires the reviewed genesis payload digest,
fresh epoch-1 genesis, complete contiguous history and an exact live terminal head.
It rejects reuse of any earlier deployment transaction or reserved/burned/consumed rollback grant,
not just the immediately previous one. Intervening evidence is bounded at 64
records; a hidden ledger update, gap or enrollment switch rejects. Trailing
evidence remains separate and cannot silently advance the last ledger phase.
`validate_normal_commit` composes the actual Installed and Committed records with
the two typed consumers and requires the checked commit attestation to end this
history. `load_native` reads through the fixed measured-root journal and rechecks
the current head. These methods still grant no daemon startup capability.

## Verification and limits

- Seven envelope/journal tests cover all purpose tags, tampering, interrupted
  durability, lost replies, exact resumption, rollback, archive failure/missing
  ancestry and invalid input.
- Five semantic tests cover both typed consumers, all 28/16 digest bindings,
  roles, timestamps, transaction/fence/generation and cross-enrollment splicing.
- Nine ledger tests cover normal/abort/rollback/failed-safe paths, all 29
  high-water domains, bounded canonical decoding, context/phase mutations,
  signed ancestry, spent identities and the composed normal commit chain.
- The fresh-install swtpm scenario executes real TPM policy signing and
  Deployment NV advance/reopen, including a lost acknowledgment and removed
  committed record. Its record storage is an in-memory fault-injection fixture.
- A separate root-only disposable tmpfs test executes the actual native disk
  adapter: durability/reopen, immutable archive/no-overwrite, competing locks, permissions, symlinks, hardlinks,
  FIFOs, replaced directory/lock, bounds and refusal of legacy state.
  The harness also checks the fixed root staging spool in its own fresh tmpfs.
  `tools/deployment_disk_acceptance.py` refuses host TPM devices, non-tmpfs or
  nonempty storage and ambiguous test binaries. CI runs it separately after the
  offline software-TPM harness. This does not prove the combined real service
  deployment, systemd isolation or physical power-loss behavior.

Latest run results and remaining product gates are recorded in
[the implementation status](../research/v04-product-implementation.md).
The Python full-product readiness gate remains false. Full V3 deployment ledger
and transition semantics, the remaining purpose-specific consumers, native
installer/watchdog/bootstrap wiring, hardware validation, and the documented
private intake/approval/publication/compiler gaps remain unfinished.

Focused local checks:

```sh
cargo test --offline --locked -p savana-platform-identity --lib
cargo test --offline --locked -p savana-policy-core --lib deployment_evidence_v3
cargo test --offline --locked -p savana-policy-core --test v2_deployment_control --test v2_deployment_entrypoints --test v2_deployment_native_signing
PYTHONPATH=experiments SAVANA_COMPONENT_DRIVER=target/debug/examples/benchmark_driver python3 -m unittest discover -s experiments/tests -v
sh tools/check-frozen-v2-core.sh
```

The two privileged/emulator harnesses must run with the disposable-container
constraints in `.github/workflows/continuation-core-linux.yml`, not against an
operator's installed state. The Rust experiment child must already be built;
omitting it and skipping its tests is not equivalent evidence.
