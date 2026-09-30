# Linux B profile: file-backed integration (not production)

For the optional measured native task-entry client added on 2026-09-24, see
[Linux owner control](linux-owner-control.md). Its local tests do not count as
installation on the enrolled AWS host or as completed frontend integration.

The user explicitly selected this lower-assurance profile for UI integration on
2026-09-21. It does not authorize bypassing passkey verification, exact action
approval, signed roots, executable measurement, separate service UIDs or G1–G7.
File-backed keys can be exported by a sufficiently privileged host attacker;
file-backed recovery anchors do not provide hardware rollback resistance.
Do not count this profile as native hardware acceptance or full-product security
benchmark evidence. Cloud models remain disabled placeholders.

## Linux manifest authoring

`savana-linux-integration-manifest` is an additional Linux-specific authoring
tool, not a port that substitutes Mac code identities for Linux measurements.
Build explicitly with:

```sh
cargo build --locked -p savana-policy-core \
  --features filesystem-integration-authority \
  --bin savana-linux-integration-manifest
```

It refuses to run outside Linux debug builds. The existing release startup
rejection remains unchanged, even if the feature is enabled. No production
platform-authority claim is introduced.

The installer must first supply:

- Five distinct non-root accounts named `savana-kernel`, `savana-agent`,
  `savana-ingress`, `savana-approval`, `savana-exec`.
- Actual root-owned, single-link executables under `/usr/libexec/savana/` and
  measured service units under `/usr/lib/systemd/system/`.
- Final root:root 0444 `/etc/savana/{service}-bootstrap-v2.json` files with the
  same closed, ordered five-element `services` observation list. Paths are
  checked against the installed Linux layout, not accepted as arbitrary input.
- Existing role sockets at their fixed `/run/savana/` paths. Each socket must
  have its expected non-root service owner, exact client primary group and
  0660 mode. Their parents cannot be symlinks or group/world writable.
- `/etc/savana/integration-manifest-input.json`, root:root 0444. Its scalar
  fields are the existing V2 manifest header: installation/state/declassification
  digests; state sequence, generation and fence epoch; protocol/release/model/
  resource/approval/planner/executor lock digests; kernel envelope key ID; ledger
  identity/head/key ID/public key. `edge_keys` is exactly three `[client, server]`
  key-ID pairs in AgentKernel, IngressKernel, KernelExecutor order. Unknown fields,
  noncanonical or zero hex digests, zero epochs and reused edge keys are rejected.
- A fresh, root:root 0600, exactly 32-byte signing seed in a trusted directory.
  This is integration-only material, never an imported old kernel credential.

Then run as the trusted installer:

```sh
savana-linux-integration-manifest --file-backed-integration /root/NEW-SEED
savana-linux-integration-manifest --check-startup
```

Authoring measures the actual files using bounded, no-follow descriptor reads,
encodes Linux native peers and signs the existing canonical V2 format. Before
writing, it invokes the runtime manifest verifier. It refuses existing output
files, writes/fsyncs the public root and signed manifest with exact 0444 modes,
and never rewrites live state. An interrupted two-file publication can leave
incomplete new files; it is not an atomic upgrade/install transaction. Startup
fails closed. A disposable installer must recover this explicitly, not delete
an existing installation automatically.

`--check-startup` uses the actual filesystem startup verifier, including the
separately signed effect-ledger projection. Signing a valid manifest alone is
not a successful startup, much less a running five-service deployment.

## Verification performed

Four unit tests check digest parsing, domain-separated pathname measurement,
unsafe path rejection and refusal to overwrite. The Linux-only disposable
container check is `tools/linux_integration_manifest_acceptance.py`. It uses
fresh synthetic accounts, real Unix sockets and `/bin/true` as **non-running
measurement fixtures**, not fake Savana daemons. It checks signed manifest
acceptance and rejection of public seeds, incorrect role groups, inconsistent
bootstrap lists, writable binaries, repeated role keys, existing outputs and
missing signed ledger projection. This is authoring evidence only.

## Fresh-host assembly and installation

`deploy/linux/integration/build.py` builds explicit Linux binaries serially to
avoid concurrent linker memory exhaustion. It separates the data-template
generator's development feature from the runtime's filesystem-integration
feature, and strips only exported copies (debug-build enforcement remains).

`assemble.py` creates fresh isolated service credentials, boot IDs, Ed25519 and
X25519 identities, local TLS identities for the disabled model/provider routes,
five consistent observation lists, signed input artifacts and exact directional
broker policy. Kernel-to-Approval uses its own independent key. Passkey profile
1 explicitly requires user verification; no enrollment or task consent is made.
Agent native-control authority is **not** given to an arbitrary Python process.

`install.py --file-backed-integration --binaries /absolute/new/binaries` is a
fresh-host installer candidate. It requires root, native systemd and an explicit
root-owned `/run/savana-file-backed-disposable` marker. It refuses existing
Savana accounts, units, configuration, binaries or state; it never erases or
upgrades a deployment. It allocates distinct paired UIDs/GIDs, encrypts fresh
credentials with systemd's host-key backend, installs the original hardening
units plus the required identity/kernel-approval/final-release drop-ins, creates
socket activation endpoints, signs the installed measurements and invokes the
actual startup verifier. Missing credential references fail before publication.

After starting services it requires stable process IDs and restart counters,
a signed root-only Approval health round trip reporting Ready, and HTTP 200
from the native enrollment page. The generated status explicitly retains
`user_authenticated=false`, `private_intake_configured=false`, and
`production_security_accepted=false`. The installer has **not yet passed native
systemd acceptance**; these are implemented checks, not claimed results.

Once native installation is verified, the root-only
`savana-integration-admin enroll` helper starts the fixed approvalctl unit with
its three encrypted credentials and prints a short-lived enrollment code only
to the invoking administrator's pipe. It does not log the code to journald,
automatically approve anything, or perform the user's passkey ceremony.

Generate templates and private material **on the disposable target host**. Never
upload local staged keys, credentials, personal content or prior kernel state.
Keep ports private and forward localhost:8766 for enrollment without changing
the WebAuthn origin. B's host-key credentials and file anchors are not TPM-backed.

## Additional checks and remaining work

The common Linux credential reader now serves all five closed service unit
names. It accepts only the exact service-UID ACL, or a UID-owned read-only mount
fallback; it rejects root callers, foreign users, permissive modes, symlinks,
hardlinks and oversized blobs. Fifty real Linux process/filesystem checks and
three reader unit tests passed. AWS's actual systemd layout was also inspected:
the service owns the credential directory/files, the group remains root, modes
are 0500/0400, no ACL is present and the mount is read-only. The reader now
accepts root or the service's own GID **only** in that owner-only/read-only
fallback. Fifteen additional real-process checks on a dedicated read-only
synthetic volume passed (five valid readers, five foreign users, five root
callers); the original fifty checks still pass. These are not full native
service acceptance.

Nineteen Python assembly/admin/health checks passed using newly generated
synthetic templates and **non-executable ELF-looking test bytes**. They validate
configuration and refusal behavior, not native binary execution. An unrestricted
combined build initially exhausted Docker memory. A subsequent serial build in
a 3-GiB/2-CPU container passed for all thirteen exported Linux binaries. A fresh
container then installed those real artifacts with synthetic isolated accounts
and sockets: manifest signing and the actual signed startup-artifact verifier
both passed. `check_staged.py` reproduces that check; it does not start daemons
or replace native systemd acceptance.

Native staging checks additionally run the real verifier under all five
non-root service identities, and assert ten disallowed cross-role socket
connections fail with permission denial. The three sockets measured by every
reader have execute-only traversal for other users on their parent directories;
the sockets themselves retain exact 0660 ownership and role groups. Other
private edges retain 0710 parents. B units preserve runtime directories across
daemon restarts so a failed daemon does not unlink socket-activation endpoints.
The native installer also accounts for the pre-existing expiry guard, explicit
public directory modes under umask 0077, and trusted seed ancestors under /root.
The root-only administration socket retains mode 0600. Its parent gets a named,
traverse-only ACL for Approvald so it can stat its inherited listener; this does
not grant Approvald or other service users permission to connect as administrator.

The Python UI still needs a trusted task intake
factory and a real browser WebAuthn provider; its absent-provider guard remains.
Disposable AWS Linux 6.12 ARM instances were used for attempted native acceptance,
with no inbound rules, encrypted storage, IMDSv2 and a four-hour termination
schedule. No local generated keys or old state were uploaded. The first native
attempts exposed installer path/permission/lifetime issues and the systemd
root-GID fallback above; they **did not pass** the stable-service/admin-health
gate. The corrected binaries rebuilt successfully, but their deployment upload
was blocked by the permission reviewer pending explicit authorization for the
complete build payload and the private S3 staging destination. All three
temporary instances were terminated; the staged build object/bucket, temporary
security group, instance profile, two IAM roles and expiry schedule were deleted.
The local synthetic read-only credential volume was also removed. Source and
corrected build artifacts remain local; no running deployment is claimed.
Do not describe the current localhost UI as a connected AWS deployment or an
authenticated private session before the remaining integration is verified.

The UI's operator-selected `SAVANA_PRIVATE_DEPLOYMENT_MODE=file-backed-integration`
only reports the chosen lower-assurance profile. It does not create authority,
enable an absent owner, or change kernel verification. The status always reports
`production_security_accepted: false`.

## Native follow-up, 2026-09-21/22

The user subsequently authorized the complete Linux binary/deployment-source
bundle through an account-private temporary S3 bucket. The next native attempt
exposed three additional integration errors:

- A root-owned admin directory under a service-owned runtime parent prevented
  systemd-tmpfiles ACL application. The Approval runtime parent is now root-owned
  and is not managed/chowned by that service's RuntimeDirectory setting. Role
  subdirectories retain their separate ownership; the admin socket stays 0600.
- A four-sample Type=simple check returned success before Kerneld/Execd had
  finished initialization. **That short-check success is invalidated**, not
  native acceptance. Approval health and the enrollment page really worked,
  but they did not prove Kernel/Executor readiness.
- The B build still loaded mandatory TPM enrollment, and the executor compared
  installer-owned worker files against its runtime UID. Kerneld now has an
  explicit `linux-file-backed-integration` feature (forbidden in release builds)
  selecting authenticated file anchors at compile time. Default Linux retains
  mandatory TPM enrollment with no failure-triggered fallback. Executor worker
  artifacts must be exactly root:root on Linux.

Kernel and Executor now send systemd READY=1 only after constructing their real
serving state. The B installer selects Type=notify for those services, waits for
stable PIDs/restart counters for fifteen seconds, checks signed Approval health
and enrollment HTTP, and checks PIDs again afterward. Implemented checks alone
are not passing evidence; the new native run is recorded below.

The 2026-09-21 follow-up instance expired under the four-hour guard. On 2026-09-22
read-only AWS checks confirmed the instance/volume absent, then the temporary
bucket, security group and IAM resources were removed. No user enrollment or
private task had been performed there.

### Native B startup accepted, 2026-09-22

The fresh ARM64 Amazon Linux 2023 installation passed the stricter installer
gate (SSM command `3ad5fae0-1702-49ff-848e-6587b9f23d0c`, exit 0).
Kernel and Executor reported readiness, all five services maintained stable
PIDs/restart counters, signed admin health returned Ready, and the native
enrollment page returned HTTP 200. A separate follow-up at 21:11 UTC
(`e6d251f6-35e9-4d7e-b11f-608029b21a7f`) found all five services and the identity
broker active/running with zero restarts. A localhost:8766 page was fetched,
but the later port-ownership check below shows that it was the old Mac service,
**not evidence of an AWS tunnel**. No inbound cloud security-group rule was added.

Local checks for this revision passed: 22 Python installer/assembly/admin
checks, two readiness notification tests, two file-anchor tests, five executor
daemon tests, the frozen manifest check, and whitespace validation. The Python
configuration tests still use synthetic non-executable ELF-looking fixtures;
only the AWS run above is native startup evidence.

This accepts **B-profile installation/startup/health only**. It does not accept
TPM anti-rollback, hardware-backed security, reboot recovery, user passkey
enrollment, trusted private-task intake, frontend owner binding, model execution
or an end-to-end private workflow. The UI remains guarded while its trusted
owner factory is absent. The temporary instance has a four-hour termination
guard (2026-09-23 01:06:32 UTC); a live localhost page is not permanent hosting.

### Wrong local endpoint discovered on follow-up

At 21:21 UTC the enrollment browser recorded `TypeError: Failed to fetch` on
the begin request, after the five-minute code lifetime. Its async click handler
did not catch errors, leaving the button disabled and the original status text
visible. This is not evidence that a passkey was enrolled. The source handler
now clears one-time fields before sending, catches every failure into a fixed
uncertain-outcome message, and never retries a possibly consumed code. Six DOM
regressions pass, including six enrollment outcome cases in the new test.

The localhost JavaScript contained a relay implementation absent from this
worktree. Its SHA-256 was `6bb398e356ee65371f424b0267c744c38492effad548d2cdcbf78fdc406f1ecb`,
exactly matching the `security-capabilities-assessment` worktree's browser asset.
This was initially attributed to shared Cargo cache reuse, but that diagnosis
was **incorrect**: the old Mac launchd Approvald was still running as PID 588,
and its plist reserves both 127.0.0.1:8766 and [::1]:8766. No old-instance SSM
session was active. The old AWS binary itself contains the private-v0.4 session
script and does not contain the legacy relay. A successful localhost page load
therefore did not mean that the browser had reached Linux; an AWS-minted code
was being sent to a different installation (and was expired by the observed
attempt). No successful enrollment was observed.

As defensive build hardening, the builder now cleans every workspace package
(not third-party dependency builds), hashes workspace sources before/after
compilation, and writes exported binary hashes in a separate local receipt.
Packaging compares the receipt with current source and all thirteen binaries.
This is not claimed as the root-cause fix. Correcting the endpoint requires
stopping the old Mac listener with administrator authorization, establishing
the private SSM tunnel, and comparing the served script with the selected source.
No old kernel state or credential is copied to the replacement installation.

The clean build completed for thirteen binaries, and the package gate compared
the source receipt and all output hashes before uploading 55 allowlisted files
(binaries, deployment files and a begin-only synthetic enrollment probe). Bundle
SHA-256: `21e1d380da68260376e8774ea6b98523242a78d652df3d553ab85b4bc04fae05`.
The expected current browser asset SHA-256 is
`7d922b4c53d9eff24c778fc82c8eee8623a6b6723986a8692b218698d6593b7b`.
Twenty-five installer/build tests passed with synthetic templates (no skips);
six browser behavior tests passed. Workspace-generated build caches were removed
and regenerated; no source or user kernel state was removed by the rebuild.

The replacement native installation passed the strict startup gate (SSM
`0b0e95b3-5fb9-4981-9447-53c39c6b5a9d`, exit 0). A begin-only native test
(`2c448a24-71d1-4321-939f-56f2da12b93b`, exit 0) used the real root admin
client and verified that enrollment returned localhost RP, attestation=none,
residentKey=required and userVerification=required. It created no credential
and performed no user authentication. Signed admin health remained Ready and
all five services had zero restarts. The separate diagnostic tunnel on local
18766 (with the proper Host header) returned the exact expected current script
hash above. This is genuine Linux endpoint evidence, unlike the occupied 8766.
The production origin is not changed to 18766. Local administrator authorization
is still required to release 8766 before the user can register through that
origin. The replacement expires at 2026-09-23 01:34:04 UTC.

The replaced `savana-b-ready-20260922-bchrxp` test instance and its temporary
volume were destroyed after the replacement checks passed. Its private bundle
bucket, dedicated security group, instance profile/roles and expiry schedule
were also removed. No local Mac credential, Mac kernel state or source file was
deleted. Releasing the Mac launchd listener remains a separate, reversible
administrator action; passwordless sudo was unavailable.

At 23:27 UTC the user reported running the Mac stop command. Read-only launchd
inspection confirmed the old Approval service absent. The detached private SSM
tunnel then bound localhost:8766 successfully and verified the exact current
script hash; direct enrollment GET returned HTTP 200 and remote signed admin
health returned Ready. However, the in-app browser still rendered an
ERR_EMPTY_RESPONSE page on reload and a fresh navigation. This remaining browser
failure is not yet diagnosed; it must not be reported as successful registration.
No new enrollment code was minted in that follow-up. Browser cookies, session
stores and security settings were not inspected, cleared or bypassed.

### 2026-09-24 disposable re-deployment

After the previous instance expired, the user authorized continuing the rebuild.
The previous run's volume was absent and its private build bucket, security group,
instance profile and temporary roles were removed. The local allowlisted bundle
was retained. No Mac state or credential was removed.

Run `savana-b-retry-20260924-9xriue` reuses the verified bundle above, not a new
source build. Instance `i-027888c2f225ddbe6` has no inbound security-group rules,
encrypted delete-on-termination storage, and both guest and AWS expiry guards.
The scheduled termination is 2026-09-24 19:02:44 UTC. Cost Explorer access was
denied; actual cumulative spend is unknown. The AWS price API returned USD
0.102/hour for the selected m7g.large Linux instance (four-hour compute estimate
USD 0.408, excluding storage, IPv4, transfer and other charges). This estimate is
not evidence that the total project budget has been reconciled.

Strict native installation passed with exit 0 in 1m28.34s (SSM
`7ef89cc2-d9d6-4858-9571-cf49ac70baf9`). The synthetic begin-only enrollment
probe passed in 15.59s (`cb92e474-ad20-4aa3-af88-e395700bcd84`): required resident
credential and user verification, localhost RP, no credential creation or user
authentication. Signed health returned Ready and all five services were running
with zero restarts. The detached private SSM tunnel on localhost:8766 returned
the expected script hash and direct enrollment GET returned HTTP 200.

The in-app browser still failed to display the enrollment form. This remains an
unresolved browser-path issue, not successful registration. No user enrollment
code was minted during this rebuild; a code should only be minted when the user
is ready to complete its five-minute ceremony. This remains B file-backed
integration acceptance, not TPM/hardware acceptance or a completed private-chat
end-to-end test. Cloud models remain placeholders.
