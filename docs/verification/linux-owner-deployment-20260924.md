# Owner-control deployment — 2026-09-24

**Current status:** activated after explicit user authorization to retire the
temporary host's old state and enrollment. Native startup, five-service
stability and measured owner-control health now pass. New user enrollment is
still pending. Cloud models remain disabled. This is the file-backed B profile,
not production/TPM acceptance. The initial staging record below is historical;
see the activation record for changes since then.

## Verified work

- Rebuilt all 14 installable/template-generation Linux artifacts serially in an
  offline ARM64 container. Workspace build artifacts were cleaned first; the
  receipt binds 482 build-source files and all exported executable hashes.
- Separately built the synthetic private-workflow benchmark driver and debug
  kernel test executable. These test-support artifacts are not installed as
  service executables and have not yet been run as experiments on this host.
- Created an allowlisted source/deployment/synthetic-test bundle. It contains
  no local generated keys, cloud credentials, personal data, old kernel state,
  existing experiment results or Git metadata.
- Confirmed all four S3 public-access blocks, uploaded with AES256 server-side
  encryption to the already authorized temporary private bucket, and staged
  the bundle in `/opt/savana-owner-next-20260924` on the existing test instance.
- Remote SHA-256 verification and all 712 payload file checks passed. The
  archive also contains the inventory itself. SSM staging command
  `550acb34-a775-4ab9-959e-83446c7f7c5e` exited 0 and reported
  `staged_files_verified=712 services_changed=false`.

Bundle SHA-256:
`939efc69f6519d30f70cf94cdf805ab5afdec9ac4a9808bedd096479c1840ae1`

The preceding read-only native check found all five kernel services plus the
identity broker active/running with zero restarts; signed admin health returned
Ready (SSM `9dd4df86-ef41-48f9-94f9-a144e5829312`). This verifies the **old running
deployment**, not the staged new one.

## Initial activation gate (before authorization)

The B installer is fresh-host-only. The new Agentd binary and owner-control
configuration change signed measurements; copying them over the old deployment
would not be a valid state-preserving upgrade. The old host also contains an
enrolled credential, so no automatic wipe or state reset was performed.

The user was asked whether to authorize retiring the old test deployment and
re-enrolling, or retain it while implementing a state-preserving upgrade. No
answer had arrived when this staging record was written. A retirement helper
was prepared but **not executed**. It has a fixed instance selector, inventories
exact service/account targets, preserves the expiry guard and quarantines old
state locally rather than uploading it. It is not an automatic rollback or
state-migration mechanism.

Local receipts and operation scripts are under
`/private/tmp/savana-owner-deploy.Ca1IkS`. Existing temporary AWS run metadata
remains under `/private/tmp/savana-linux-retry.9xRIue`.

The existing instance's expiry remains **2026-09-24 19:02:44 UTC / 15:02:44 EDT**.
No new instance, inbound firewall rule, GPU, model deployment, or expiry
extension was created. The new S3 object replaces the old synthetic build object;
the old local bundle is retained. No claim of exact accumulated AWS charges is
made.

After authorized activation, native startup and the new measured `owner-health`
exchange must pass before experimental execution. Synthetic component-suite
and AgentDojo provider-conformance runs must remain distinct from official
AgentDojo task/attack or model success rates. Interactive private-task intake
and the signed scoped planning profile still require their own acceptance.

## Authorized activation and native fix

The user explicitly approved retiring this exact temporary machine's old
Savana state and registration, installing the new version and re-enrolling.
SSM command `406627b9-0340-443c-adc8-b86f77001a0e` retired the exact old units,
accounts and installation paths. Old configuration, encrypted state, binaries
and units were moved into `/root/savana-retired-owner-20260924` (root-only) on
the same instance. Runtime sockets were quarantined separately. Nothing from
that backup was uploaded; device-side passkeys were not deleted. This is not
state-preserving migration and the backup lasts only as long as the temporary
instance. The expiry guard was not changed.

The fresh installer generated private material on the instance, verified the
signed startup measurements and started five services. Its final owner-control
gate failed, so the install attempt was recorded as failed rather than accepted.
Bounded syscall tracing of **health only**, without request payloads, identified
a performance cause: unoptimized SHA-256 took about 1.32 seconds to measure the
Agentd executable and 0.25 seconds for ownerctl. Reciprocal requests queue at
the broker; the second reply arrived after the existing three-second deadline.
The reverse connection and identity checks had succeeded before that timeout.

The only code change for this failure is `[profile.dev.package.sha2]` with
`opt-level = 3`, retaining debug assertions and overflow checks. No deadline,
identity rule, signature rule or permission was relaxed. Linux owner-control
tests passed (6 tests, including the inherited-listener child harness), as did
11 Linux broker tests. The broker helper was rebuilt offline for ARM64; this
helper is root-owned but is not one of the five manifest-measured executables.

SSM `48a3f07a-487a-4067-b8a1-7abb3bba9792` verified the exact old helper hash,
kept a root-only helper backup, atomically installed the new helper and restarted
**only the broker service**. The five signed binaries/configurations were not
replaced or re-signed. `--check-startup`, the installer's complete service check,
and three additional measured owner-health round trips all passed (four health
round trips total). The command exited 0 and reported
`deployment_verified=true authenticated=false private_intake_configured=false`.
The advisory installation status was written only after those checks passed.

This is intentionally a mixed build: the original 14-artifact bundle plus the
optimized broker helper. The original build/source receipts and the patch
receipt must be retained together; do not claim all binaries were rebuilt with
the new optimization. Public patch receipts are in the local operation directory
and `/opt/savana-owner-broker-fix-20260924` on the host. The same private S3 object
was reused for this code-only patch; the original full bundle remains local and
staged on the instance.

The localhost enrollment tunnel was restored. Both the page and script return
HTTP 200; the script has a JavaScript content type and its SHA-256 matches the
selected Rust source. In-app browser navigation still returned an empty response;
its exact cause is not confirmed. The closed HTTP parser deliberately rejects
ambient Cookie/Authorization headers, so a clean browser session was requested
without relaxing that boundary. No new enrollment code has been minted yet.

## Experiment execution record

Synthetic experiments use a separate unprivileged `savana-experiment` account,
read-only exported source and separate test executables, not the service binaries.
Runtime units deny network access and capabilities, protect the system/home,
and use private temporary directories. They receive no production credentials.

The first component-suite launch (`c5ea3174-1a80-4d79-a86f-646d0cd9f322`)
failed at systemd NAMESPACE setup before Python started: the output path under
`/var/tmp` was hidden by `PrivateTmp`. No episode ran. That failure is retained.
A distinct retry uses `/opt/savana-experiment-results-20260924` for explicit
write access, retaining the other sandbox restrictions.

The retry (`f695c1f2-8497-4409-a281-ce2cce2fbff4`) completed with complete audits
for all 84 episodes: 72 completed tasks, 12 intentionally refusing controls,
60 confirmed scripted attack injections with zero observed unauthorized effects,
228 encrypted state-reopen checks with zero counter resets/repeated effects,
and zero Unknown. The 36 completable reopen/no-reopen pairs had no utility
mismatch. Reopen paired wall-time delta: median 71.157 ms, nearest-rank p95
135.593 ms. These are debug component timings, not production overhead.

AgentDojo 0.1.35 was installed in a separate unprivileged virtual environment;
transitive package versions are captured in the result provenance. No model
weights or model calls were used. The network-denied conformance run
(`5293933f-63fa-437c-a7fa-134731778b6a`) passed 10/10 cases and verified 20 actual
simulated email effects. Cases cover two/three dependent steps, encrypted state
reopen, signed per-step approval and revocation, each with normal and injected
tool-output text. Test fixture signatures/authorities are synthetic; these runs
do not use the five deployed service processes or a newly authenticated user.

All manifests, started markers, audits, kernel logs, summaries and public
build/dependency receipts were downloaded via bounded SSM chunks, without any
new S3 write permission. The complete 123,514-byte archive SHA-256 is
`dc937b5a36a02c1e5c2dcac1d0be27cc1450b189df104038f4019698f5101957`.
Local records: `experiments/results/aws-native-20260924/`.
These are not official AgentDojo task/attack scores or model safety rates.

The post-experiment native check (`6290ef7b-7aa2-49b5-9f21-49f22b0f69ea`)
returned signed admin Ready and measured owner-control ready. All five services
and the broker remained active/running with zero automatic restarts, and the
original expiry timer remained active. Interactive re-enrollment remains pending;
the trusted full-product intake/planning acceptance gaps have not been hidden
by these component results.
