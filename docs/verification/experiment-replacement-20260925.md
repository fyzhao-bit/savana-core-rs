# Replacement AWS experiment host — 2026-09-25

## Authorization and scope

After the previous host reached its original expiry, the user approved creating
one replacement within the **original approximate USD 10 total budget**, not a
new USD 10 allowance. No previous kernel state, enrollment or private host key
was copied. Kernel access from the experiment remains through the Python SDK.

This is the B/file-backed integration profile, not production TPM-backed
rollback-protection acceptance. The planned experiment remains the finite
nine-case AgentDojo calendar subset described in the preceding reports. It is
not the complete benchmark or an adaptive post-tool model replanning result.

## Actual resources and guardrails

- Region: `ap-southeast-1`.
- Instance: `i-0f3fc9cb9a755b254`, `m7g.large`, fresh AL2023 ARM64.
- Run: `savana-replacement-20260925-q8qs09`.
- Expiry: **2026-09-25 16:11:22 UTC / 12:11:22 America/New_York**.
- Both an AWS Scheduler termination and an absolute systemd shutdown timer are
  configured. The local timer is calendar-based, so daemon reload or reboot
  does not extend the deadline.
- Current AWS pricing API readback: USD 0.102/hour for the instance; two-hour
  instance-only allowance USD 0.204. This is not an invoice or a total-cost claim;
  disk, snapshot, IPv4, storage, API/model and previous-run charges are separate.
- No inbound security-group rules; TCP 443 outbound only. Administration and
  local authentication use SSM. IMDSv2 required, hop limit 1.
- Private encrypted artifact bucket:
  `savana-replacement-20260925-q8qs09-377521353256`, public access blocked,
  TLS-only policy and one-day artifact expiration.
- Fresh encrypted base-image snapshot `snap-01a3f5ffd699d88fb` and image
  `ami-0cb884d9d8b66021f`; cleanup is scheduled five and ten minutes after the
  instance deadline respectively. No prior Savana disk is used as the base.

The pre-provisioning EC2 query found no pending/running/stopping/stopped instance
tagged `Project=SavanaAcceptance` in this region. This does not assert that all
unrelated account resources or costs were inspected.

## Verified payload and boot

The previously built candidate was rehashed and each allowlisted archive member
verified before upload:

- 128 allowlisted files plus the inventory; 35,518,322-byte compressed bundle.
- SHA-256: `750cc721f980fb0f1a0f211601575ab594d81c0f3571c4e6a69e1364a581fb40`.
- Payload: Linux native binaries, Python SDK, deployment scripts and synthetic
  tests only. No model/AWS credential, personal data or previous kernel state.
- Native binaries and SDK use the source snapshot recorded in
  `experiment-corrected-attempt-20260925.md`.

SSM `a1783df8-3ea5-4a38-8ff1-2df6dff50909` installed runtime dependencies.
SSM `bb3ed785-1ff3-40d9-b59c-d4dced05dbbd` enrolled the Amazon Linux boot keys
and requested reboot. Readback `b3a3de14-453f-407c-b735-b77870297e22` returned
Secure Boot `Enabled`, TPM PCRs 0 and 7, and the unchanged 16:11:22 UTC expiry.
Hardware availability does not change the file-backed runtime profile claim.

## Installation and real pre-authentication route

SSM `119af152-8e98-4f68-bf51-12edb70ec320` completed the fresh native/SDK
installation with response code 0, including stable service and signed owner
control health checks. Readback `26fffe5e-081e-4bae-a30f-5f1369897cb6` confirmed
the installed runtime and auth/operator services with zero restarts.

The systemd host-key credential backend warns that its secret is not on
OS-detected encrypted media. The EC2 disk is EBS-encrypted, but this is still
the file-backed B profile, not a TPM-sealed or production-security claim.

**SSM `6bd8bc9a-0e56-44db-b3a0-a242cd64ee34` exercised the actual Python SDK:**

1. `savana.owner_control.issue_bootstrap()` prepared a real one-use task entry.
2. A child under `savana-experiment` called `savana.owner_ingress.connect()`.
3. Its WebAuthn callback was reached and deliberately raised before producing
   any assertion. The bootstrap was passed on stdin, not logged or put in argv.

The diagnostic returned `webauthn_requested=true`, `task_approved=false`,
`model_calls=0`, and exited 0 because the expected callback was reached. The
closed error-code whitelist reported `other` for the intentional callback
exception; this is not a successful login, task, model call, or scored episode.
Both `task_correlation_trust` and `authority_envelope_trust` were true. This
crosses the pre-authentication point that failed on the previous two deployments.

## Local user-authentication connection and model credential

The local gateway now targets only `i-0f3fc9cb9a755b254` over SSM:
remote 8766 to local 18766, and remote 8786 to local 18786. The old gateway's
exact PID/command was checked before terminating that gateway process; unrelated
Mac kernel listeners were not modified. The new bearer is held in a local 0600
file and is not sent to browser JavaScript or printed in the transcript.

Actual HTTP checks through the new tunnels returned:

| Resource | Status | Content type |
| --- | --- | --- |
| `/experiment-auth` | 200 | `text/html; charset=utf-8` |
| `/__experiment/app.js` | 200 | `text/javascript; charset=utf-8` |
| `/v2/enrollment/bootstrap` | 200 | `text/html; charset=utf-8` |
| `/v2/savana-ui.js` | 200 | `application/javascript; charset=utf-8` |

The previously authorized DeepSeek credential was read from the local process
environment and sent only over the authenticated SSM tunnel to the closed
credential-installation endpoint. It returned HTTP 200 and stored the credential
with systemd host-key encryption. No plaintext key was included in S3, code,
command arguments or experiment logs; **no provider request was made**. This
does not assert that the provider currently accepts the credential.

The user was asked whether they are ready to register before minting a
short-lived enrollment code. No code or passkey assertion was manufactured to
advance the experiment. As of this checkpoint: no actual user authentication,
root consent, benchmark tool execution, model call, or score on the new host.

## Final readiness readback

SSM `1a3f2ff2-283f-4e15-8a57-b86432a3da64` completed successfully:

- All 16 administration prerequisite checks are true, including both distinct
  signature-role pins and encrypted model credential presence.
- `ready_to_request_real_authentication=true`;
  `passkey_authentication_confirmed=false`.
- The installed SDK SHA-256 is
  `46638aa305c5ea859c1012cce82bc77c450263c2ec175ba09eb24a025ed3ed99`;
  installed Approvald SHA-256 is
  `780aa59059fa16e9eb52dc4fa6a73eb9826c47f934ac1f0841037865c7558e1b`.
  Both match the rebuilt candidate.
- AgentDojo package version is `0.1.35`; benchmark output directory has zero runs.
- Five native services plus auth/operator are active/running, with zero restarts.
- Both authority/correlation preflight regression tests passed under the
  unprivileged experiment account (2 tests, 0.002 seconds).

Remaining live boundary: real user passkey registration, followed by the actual
experiment's login and explicit task approvals. No unattended bypass or
automatic approval was installed. These successful prerequisites do not prove
that all later execution/publication stages will succeed.

## First protected attempt on the replacement

The user requested enrollment and then reported completion. Enrollment command
`91a12696-6856-4c7d-8947-64763fadeb7f` issued a five-minute one-use ceremony;
its handle/code are intentionally omitted from this report. The user's report
is not itself cryptographic proof of successful authentication.

SSM `c6e34200-cb47-4943-9ff3-3938896174f2` started the guarded experiment after
all 16 prerequisites remained true. The process was active/running at startup.
At **14:27:54 UTC**, the authenticated local gateway reported a real pending
`webauthn.assert` request. The user was directed to `/experiment-auth`; no
assertion, consent, or approval was submitted by the assistant.

The attempt subsequently ended; it is not a completed score:

- Run: `705d51444e7843f08f20bb87fa2670ce`.
- `owner_bootstrap` began at 14:27:41.944 UTC and `owner_authentication` at
  14:27:42.804 UTC.
- The first benign case ended at 14:29:38.049 UTC with `AuthBrokerError` at
  `owner_authentication`, total case duration 118.093 seconds. The authentication
  stage duration of roughly 115 seconds matches the broker's response deadline.
- No confirmed assertion reached the next admission stage. This does not prove
  that the user did not click: a local read-only queue query also timed out once
  before a subsequent query recovered. The evidence does not distinguish user
  absence from a browser/transport problem during that interval.
- **0 model calls, 0 scored episodes, 9 Unknown** (the remaining eight cases
  were not attempted). No success or protection rate is claimed.
- The systemd process exited 2. No automatic rerun, enrollment reset, kernel
  state clear, or audit overwrite followed.

SSM outcome readback: `2f3f0f74-735d-4880-a152-f8fd30708a29`.
The original `events.jsonl`, `summary.json`, and `completion.json` were downloaded
unchanged to
`experiments/results/aws-replacement-attempt-20260925/705d51444e7843f08f20bb87fa2670ce/`.
Only synthetic evidence was exported, not credentials or private kernel state.

- Transport archive: 49,767 bytes, SHA-256
  `b7cd8fefe2ef7a77872212304e27e5a4d8354a5e15d642233b5afded059032f0`.
- Audit: 15 events, head
  `917b54e7a4bb5a402fd2c4dcafb6d4f843a9be70120c02ab3f08ad38e1d8d0ef`.
- The offline verifier accepted source/package binding, hash chain and summary
  consistency: `audit_consistent=true`, `official_episodes_rescored=0`.
  This is an unkeyed audit consistency check, not portable kernel attestation.

The next attempt must be explicitly initiated after the user is on the
experiment authentication page in the browser holding the registered passkey.
Preserve this failed attempt separately; a fresh start is not recovery or
completion of this run.

## Explicit rerun and SDK correction

The next user-requested attempt crossed real passkey authentication, then
failed in the Python SDK's native owner-input adapter before any model call.
The SDK-only correction, regression tests, deployment receipt and preserved
failed-run evidence are recorded in
[Owner-input SDK digest correction](experiment-sdk-input-digest-20260925.md).
Native kernel binaries, processes, state and passkey enrollment were preserved.
