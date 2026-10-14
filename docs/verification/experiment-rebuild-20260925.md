# Authorized replacement after expiry — 2026-09-25 evening

## Why a new deployment was needed

The previous temporary host `i-0f3fc9cb9a755b254` had been terminated under
its original expiry policy. CloudTrail records `TerminateInstances` without an
error at 2026-09-25 12:11:42 America/New_York, with state `terminated`.
The user explicitly authorized another deployment within the original
approximate USD 10 total budget. This is not permission to reset an active run,
replay uncertain approvals, extend expiry indefinitely, or report test scores.

## Budget evidence and guardrails

Cost Explorer returned `AccessDeniedException: User not enabled for cost
explorer access`. No precise billed total or remaining balance is claimed.
CloudTrail creation/termination records were instead inspected for all ten
`Project=SavanaAcceptance` instances created in `ap-southeast-1` since September
20. There were no remaining project-tagged instances, volumes or snapshots.

Using USD 0.15/hour as a conservative compute-rate bound gives a historical
compute estimate of USD 2.92384. Reserving USD 0.60 for the new compute window
and USD 2 for non-compute charges produces a planning estimate of USD 5.52384.
The reserve is not a measured invoice or a guaranteed billing limit; unrelated
account resources are outside this estimate. The current AWS pricing response
for this `m7g.large` is USD 0.102/hour, so four instance-hours are USD 0.408.
Raw resource/timing estimates are in
`experiments/results/aws-rebuild-20260925/budget-check.json`.

- New instance: `i-0a8df7cc8d6bf2851`, AL2023 ARM64, `m7g.large`.
- Run: `savana-rebuild-20260925-cqkdzx`.
- Deadline: **2026-09-26 01:24:35 UTC / September 25 21:24:35 New York**.
- Exact-instance AWS Scheduler termination plus absolute systemd shutdown.
  Reboot/reload does not extend the deadline. The root volume deletes on
  termination; this is a disposable deployment, not persistent credential backup.
- No inbound security-group rules; only TCP 443 outbound; SSM administration.
  IMDSv2 required with hop limit 1.
- Private AES256 artifact bucket with public access blocked, TLS required and
  one-day artifact expiry. Fresh encrypted Amazon base-image copy; no old
  Savana filesystem, enrollment, key or kernel state imported.
- Image `ami-0ee1d5e237d3ca152` and snapshot `snap-03b58e993287ed242` have
  cleanup schedules five and ten minutes after the instance deadline.

## Payload provenance

The payload was composed from the exact previously verified 128-file native
deployment bundle, the owner-input SDK digest fix, and the seven-file Python
browser-readiness patch. It contains 130 allowlisted files plus an inventory,
35,525,430 compressed bytes, SHA-256
`ec39c95c16c3d4c535cc7c8ed3d8859d475c883b9423c7f4424acef02a1f6d5e`.

Native kernel binaries are unchanged from the earlier verified build. The
SDK is SHA-256
`160ed884fcc1c74e4922f9f13d9b694c6ad78100b16aaef4340f2a31173328bd`;
its separate build manifest is preserved rather than misrepresented as the
native daemons' original source snapshot. All bundled experiment Python
module hashes match the current worktree at packaging time.

The artifact contains Linux binaries, Python/deployment source and synthetic
tests only. No model/AWS credentials, personal data or old kernel state was
uploaded to S3. The same narrow SDK and browser-ready changes described in
[the earlier SDK report](experiment-sdk-input-digest-20260925.md) and
[the browser-ready report](experiment-browser-ready-20260925.md) are included.

## Boot verification

- Dependencies command `e4d1cfee-3223-4f8b-9cea-708fad04216f`: Success/0;
  Python 3.12.14 and both TPM devices present.
- Official Amazon Linux boot-key enrollment/reboot command
  `9131cb29-eb65-491b-862f-bc7ad58e4239`: Success/0.
- Readback `64fbb253-fcbc-4bfe-a593-1a6e5b1b37fa`: Success/0; Secure Boot
  `Enabled`, PCR 0/7 readable, expiry guard active with unchanged deadline.

This remains the **B/file-backed integration profile**. TPM hardware presence
and Secure Boot do not turn it into TPM-sealed production rollback protection.
No score, enrollment, authentication or task approval is implied by boot or
installation checks. The intended experiment is still the finite nine-case
AgentDojo calendar subset, not full AgentDojo or adaptive post-tool replanning.

## Installed validation and current handoff boundary

Fresh installation `e11d25f8-1b0d-4e71-93b0-2ffed2885f1e` returned Success/0.
The installation log includes the expected file-backed systemd host-key warning
that the credential secret is not on OS-detected encrypted media; EC2 EBS
encryption is not being represented as TPM sealing.

`36be20d4-8934-48e5-a0de-b2b8c91fd4af` verified all 130 installed file hashes,
the SDK digest and AgentDojo 0.1.35. Five native services plus auth/operator
were active/running with zero restarts. The active runs directory was empty.
Installed Python regression suites passed **43 tests**: readiness 7, HTTP
bridge 6, administration 2, protected endpoint/oracle plumbing 22, operator 6.
Synthetic fixtures are not real authentication or benchmark evidence.

The independent real-SDK diagnostic
`04a661dc-51b4-4bfe-8289-49ec0ebde36c` reached the actual WebAuthn callback,
then intentionally stopped without producing any assertion, approving a task
or calling a model. The test run's concurrent owner-health check returned false;
the later serialized readback `2604dd17-d5d4-4ec4-9992-1152a88797a7` returned
owner-control true and all prerequisites true **except model credential**.
The benchmark service remained inactive/dead. No actual experiment was started.

Local gateway reconnection is blocked on explicit permission to copy the new
private experiment bridge bearer to a local 0600 file: the tool safety reviewer
rejected this export as not explicitly covered by the deployment authorization.
No indirect export or alternative credential path was attempted. The old local
gateway still points at the terminated host; it is not a usable new enrollment
or experiment route. Installing the previously authorized model key over the
new private tunnel, fresh enrollment and actual user approval remain undone.
No short-lived enrollment code has been minted on the new host.

## Explicitly authorized private connection

The user then explicitly authorized copying the new bridge bearer to a private
local file and provisioning the previously authorized DeepSeek credential over
SSM. The connection step was resumed under that new authorization, not through
a workaround to the rejected export.

Command `f6bcea50-c0ee-47d9-b447-1a6e6fc1d608` encrypted the 43-byte bridge
bearer using a newly generated local RSA-3072 public key, OAEP/SHA-256 and a
fixed transfer label. SSM command output contained only ciphertext. The local
helper decrypted it without printing it and saved `browser.token` mode 0600;
the local transfer key is also mode 0600. Neither bearer nor model key was
included in S3 artifacts, shell arguments, documentation or chat output.

The two local SSM forwards now target `i-0a8df7cc8d6bf2851`: 18766 to 8766,
and 18786 to 8786. Only the exact prior experiment gateway process was replaced.
No Mac kernel listener or unrelated process was changed. The authenticated
credential-installation endpoint returned HTTP 200 and stored the previously
authorized model key using the server's systemd host-key encryption. No model
provider request was made; provider acceptance of the key is not yet tested.

The local gateway returned HTTP 200 for the authorization page, its script,
the native enrollment page and native script, with correct HTML/JavaScript
MIME types. Final sequential route checks returned 200/no pending request,
200/enrollment HTML and 200/native JavaScript. Browser automation itself timed
out at the page-focus operation, so actual visual page state was **not**
verified and no browser button was clicked.

Readback `675812f3-0d72-4b46-9aee-c213610cf100` returned Success/0 with all
16 prerequisites true, unchanged five native PIDs, zero restarts, and the
original expiry. `ready_to_request_real_authentication=true` is not proof of
enrollment or login. The experiment remained inactive/dead. No registration
code, WebAuthn assertion, task approval, model call or scored result was created
in this connection step. The remaining handoff is a fresh real user enrollment,
then explicit browser start and the normal independent approvals.

## Requested enrollment issuance

After the user explicitly requested generation, command
`46c6df15-cd9f-4093-b7a7-87b3f34df639` successfully issued one enrollment
ceremony, expiring at Unix milliseconds `1790372745842`. The one-use handle/code
were encrypted with an ephemeral AES-GCM key wrapped by the local RSA public
key before SSM returned them, then decrypted only for delivery to the user.
They are intentionally absent from this report and repository artifacts.
Issuance is not registration, authentication or task approval. No second code
was automatically minted and no registration button was activated.

## User-reported enrollment and start gate

The user subsequently reported completion. This is recorded as a user report,
not substituted for cryptographic login evidence. Command
`9ce87348-8700-4e31-8a51-a1cb52c83d52` checked the unchanged 130-file deployment,
empty run directory, inactive experiment and no pending bridge request before
arming one new process. The local authenticated route then returned HTTP 200
with `experiment.ready` and 888 seconds remaining. No readiness response,
passkey assertion or task approval was submitted by the assistant. Successful
login and protected benchmark completion remain to be established by the
actual user-controlled continuation.

## First real start outcome

The user clicked start; run `6e76f2211c6845c085dd6e4e126317f1` opened a real
`owner_authentication` stage at 2026-09-25 21:55:24.175 UTC. The local bridge
returned `webauthn.assert`, initially with 98 seconds remaining and later 45.
Readback `f87867a0-d745-42ca-8f36-0c1e9303b041` confirmed five audit events,
active execution and no model request at that point.

The later user completion report did not correspond to accepted authentication.
Readback `80a2c279-444d-4567-9755-0bd988439b4d` showed process exit 2 and the
same run ending at `owner_authentication` with `AuthBrokerError`. The closed
auth-service diagnostic in `6d071014-ec9d-4368-b65c-b07a53d3d2be` specifically
reported `request_expired / webauthn.assert` at **21:57:19.402 UTC** (17:57:19
New York). No accepted response arrived within the broker window. This does
not establish whether the user clicked, whether a browser prompt appeared, or
whether an attempted browser submission failed in transit.

Result: **zero model calls, zero scored episodes, nine Unknown**. No new
authentication, enrollment or rerun was automatically created after expiry.
The unchanged `events.jsonl`, `summary.json` and `completion.json` were saved
under `experiments/results/aws-rebuild-attempt-20260925/6e76f2211c6845c085dd6e4e126317f1/`.
The audit has 15 events and head
`a01db227effc17baf0afc810ba501fd6977c1863e6ff168448c286ce2daf44e7`.
Export size is 50,182 bytes, transport SHA-256
`04c86d7d78eb14a232d1d0cda60f7d2b1b1604a0bbb74f92316d21e04105f476`.
No credential or private kernel state was included in the export.

## Explicit retry after authentication expiry

The user explicitly requested another attempt. Command
`f6370aa9-c19c-4e50-bbbb-6d0327edab6e` returned Success/0 after verifying
the prior run's three evidence-file hashes and retaining the unchanged run at
`/var/lib/savana-benchmark/retained-runs/6e76f2211c6845c085dd6e4e126317f1`.
Neither enrollment nor kernel state was cleared. All 16 prerequisites passed;
the experiment was rearmed with PID 4672, active/running, zero restarts.
This is readiness for a new user-controlled start, not successful passkey
authentication or a benchmark score. The original instance expiry remains
unchanged. No start, assertion or approval was submitted by the assistant.

## Second real start outcome

After the user reported completion, read-only command
`22aea9fe-24bd-4baf-823a-9a1ad99892f8` found run
`840980446e894d85b67c1987d5a2df61` terminated with exit 2. The owner
authentication stage started at Unix nanoseconds `1790374421508173650` and
ended at `1790374454465090252` with SDK `SavanaError / invalid_response`,
not the previous `AuthBrokerError`. There were **zero model calls, zero scored
episodes and nine Unknown**. The authenticated local pending endpoint returned
no pending request. This is not evidence of successful kernel authentication.

Read-only diagnostic `75ea9a76-9bcb-4845-ac2e-4a81ea7670e1` found no closed
`request_expired` or `cancellation_received` events in the auth journal for
22:09–22:16 UTC. All five native services remained active/running with zero
restarts. It did not establish whether the failure was an HTTP/CBOR response
failure, assertion rejection, or subsequent settlement handoff failure: the
SDK currently collapses multiple response checks into `invalid_response`, and
the native HTTP workers discard their detailed errors. No credential, raw
assertion or private kernel-state file was read to infer a cause. No further
experiment, enrollment, service restart or state reset was initiated.

The server retains all 15 audit events; head:
`bdc301946450729d8193980b9f9bce1b62f728e8276c2d21ab2f103c5b8ce52c`.
Readback SHA-256 values (not a claim of a new local artifact export):

- `events.jsonl`: `54d59499e37234e8f360992d4a9320ddfc87daf11d64934dbed566aa4ba43939`
- `summary.json`: `ad39ea05e847686dc462d19b809fb9ff05d5bc2cc83e91965dd0418ec80249a7`
- `completion.json`: `1757c159aa056b6b884acf0e6bf9abded1235fb8a840caa3d6c5431ce1811496`
