# Corrected-deployment attempt — 2026-09-25

## Actual result

After the user reported registration complete, SSM
`c4f4cb4e-b2b6-4b4d-816d-05f188a51e5b` started the real Python-SDK-only experiment
on `i-071646e066afc6302` at 04:55:37 UTC. The process exited 2 at 04:55:40.
All preflight checks in that deployed version passed, but they did not prove
the complete pre-authentication route.

Run: `398583f904ac49babec75e259f59f8fe`.

- First benign case: attempted, `SavanaError`, `owner_and_operator_admission`,
  2.938 seconds. The other eight cases were not attempted after Unknown.
- **0 model calls; 0 scored episodes; 9 Unknown.** No protection rate is available.
- The failure was before a WebAuthn request, not evidence of failed registration.
- No user approval, new root, tool call or final publication was fabricated.
  No automatic experiment retry or state reset followed the failure.

A separate diagnostic-only SDK call stopped before supplying any WebAuthn
assertion. SSM `6346901f-c51e-4574-977a-ecca57c6c8ed` reported
`invalid_response`, `webauthn_requested=false`, `task_approved=false`,
`model_calls=0`. Its one-use preparation is not a benchmark episode or success.

## Reproduced configuration defect

The kernel wires `authority-envelope-v2.seed` into both the Agent and Ingress
authority configurations. Ingress signs `SignedUiAuthenticationEnvelopeV2`
with that key. The old Approvald startup instead used the global manifest's
execution-envelope key and `kerneld-envelope-v2.pub` when constructing
`ProtocolApprovalServiceV2`. Linux assembly generates distinct authority and
execution keys. Thus the UI authentication envelope cannot pass that verifier.
The earlier correlation-key correction did not correct this second role mismatch.

## Source changes, not yet a deployed acceptance claim

- Approvald now requires an explicit authority-envelope public key and key ID
  in its measured bootstrap configuration. ID mismatch, zero key, and reuse of
  execution/correlation keys fail closed. The original execution-key check
  against the signed manifest remains; the execution key is not replaced.
- Linux assembly and the shared template/material generators emit the new pins.
- Administration preflight rejects missing/wrong/non-separated authority pins.
- The runner records closed admission stages and a whitelist of SDK error codes;
  it does not log arbitrary exception messages, capabilities or assertions.
- Regression coverage includes valid authority signatures, rejection of
  execution/correlation signatures, wrong pins and pre-auth failure without retry.

These changes are local source changes. This report does not claim they were
installed on the running AWS deployment. They require rebuilt native artifacts
and a verified signed deployment update; directly editing a measured live
bootstrap or merging role keys is not an acceptable workaround. Existing state
and enrollment have not been cleared again.

The **Python preflight guard only** was subsequently deployed in SSM operation
`b33a3fc8-fa46-431d-aed4-704a1740b83b`. Two source/test files were delivered via
the existing private S3 bucket; the old administration module was backed up on
the same host. The archive SHA-256 is
`dbf2c225befd0d217b5b8276b2d9d4214eae3e1e3eb6c1284360147c9e21c5fb`.
Native binaries, measured configuration and enrollment were not changed.
Readback now correctly reports `authority_envelope_trust=false` and
`ready_to_request_real_authentication=false`; both new preflight unit tests passed
on AWS. This guard prevents another misleading readiness report, but does not
repair the active native deployment by itself.

## Verification

- Linux ARM64, isolated offline container: **55 Approvald unit/transport tests
  passed**, including the new distinct-role signature regression.
- Mac host: 54 approval tests passed before the last added signature test; that
  additional test also passed separately. The initial sandboxed full run had
  three socket permission failures; rerunning with local networking allowed
  passed all 54. No permission failure was counted as a pass.
- Deployment assembly: **37 tests passed**, using freshly generated synthetic
  template inputs retained from the preceding build.
- Focused Python experiment/admin/setup regression: **31 tests and 20 subtests
  passed**; six dependency/asyncio deprecation warnings.
- Complete Python experiment suite: **158 passed, 10 skipped, 29 subtests
  passed**, six warnings. Skipped tests are not acceptance evidence.
- Shared template/material generators passed their Cargo checks. Changed
  Approvald files and the material generator passed targeted rustfmt checks.
  Unrelated pre-existing formatting in the template generator/support module
  was not bulk-rewritten. `git diff --check` passed.

These are regression checks, not real user authentication or benchmark scores.

## Rebuilt candidate, not activated

The offline Linux ARM64 build subsequently completed for all **14 native
binaries plus the CPython 3.12 stable-ABI SDK**. Workspace package cache entries
were cleaned by the existing build script; source snapshots before/after the
build match. Both build receipts cover the same **498 Rust source/build files**.

Local candidate directory: `/private/tmp/savana-authority-pin-fix.KeOBJe`.

- Approvald SHA-256: `780aa59059fa16e9eb52dc4fa6a73eb9826c47f934ac1f0841037865c7558e1b`.
- SDK SHA-256: `46638aa305c5ea859c1012cce82bc77c450263c2ec175ba09eb24a025ed3ed99`.
- Profile: B/file-backed integration, not production TPM acceptance.
- Existing dead-code/unused-variable compiler warnings remain; the build passed.

Activating this candidate requires a signed deployment replacement/migration.
It is not safe to copy a new executable or edit pinned fields into the old
measured installation. The user subsequently approved another archive/reinstall
and a two-hour extension within the original approximate $10 total budget.
The existing host expired before that extension could be applied; neither the
native replacement nor the extension completed (see the lifecycle record below).

The allowlisted complete candidate bundle contains 128 files, is 35,518,322
bytes, and has SHA-256
`750cc721f980fb0f1a0f211601575ab594d81c0f3571c4e6a69e1364a581fb40`.
This bundle remains local and has not been uploaded or activated.

## Retained evidence

The three original artifacts are saved unchanged under
`experiments/results/aws-protected-20260925-corrected-attempt/398583f904ac49babec75e259f59f8fe/`.

- Archive size: 29,194 bytes.
- Archive SHA-256: `8fd7021be5d1c673127f1aa3ab456557fa00a5f68c85e460f4e60731a9c83839`.
- 13 events; completion head:
  `6ee89a81354f1c218171a76d990209222970a20217c617dc4e61512ebf7a9576`.
- The verifier was run against the exact old experiment source reconstructed
  from the retained deployment bundles: `audit_consistent=true`,
  `official_episodes_rescored=0`.

Only synthetic benchmark evidence was exported, not credentials, enrollment
material or private kernel state. This unkeyed audit consistency check is not a
portable kernel attestation. The scope remains a finite nine-case calendar
subset without adaptive post-tool model replanning, not full AgentDojo.

## Authorized extension lost the race with expiry

At the next continuation, the clock read 05:23:36 UTC, just before the original
05:23:52 UTC (01:23:52 New York) expiry. The first AWS read returned the instance
as `running` and its original termination schedule as enabled. A subsequent
attempt to read that same schedule before updating it returned
`ResourceNotFoundException`; the schedule used `ActionAfterCompletion=DELETE`.
The update call was therefore never reached, and no timer-changing SSM command
was submitted.

Follow-up readback of exact instance `i-071646e066afc6302` returned:

```json
{
  "State": {"Code": 48, "Name": "terminated"},
  "StateReason": {
    "Code": "Client.InstanceInitiatedShutdown",
    "Message": "Client.InstanceInitiatedShutdown: Instance initiated shutdown"
  },
  "BlockDeviceMappings": []
}
```

SSM returned no managed-instance entry. This is a terminated host, not a stopped
one that can be restarted. No fresh archive/reinstall ran. The existing AMI
deregistration and snapshot deletion schedules were still enabled for 05:28:52
and 05:33:52 UTC respectively when checked; they were left unchanged. Their
eventual completion has not been verified in this record.

The complete candidate and both exported failed-run evidence archives were
rehashed locally and still match the SHA-256 values recorded above and in
`experiment-first-run-20260925.md`. This does not imply the old host-private
state, enrollment, or encrypted model credential was exported or is recoverable.
No new instance or increased budget was provisioned. Continuing on AWS requires
authorization to create a replacement host, with a fresh bounded lifetime and
fresh authentication; the prior confirmation was for extending the old host.
