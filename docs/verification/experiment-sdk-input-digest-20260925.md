# Owner-input SDK digest correction — 2026-09-25

## Observed failure, not a benchmark result

The user explicitly requested a rerun, then completed the actual passkey login.
Run `7b5f0621459a4bdbb9f1a27cdaddc45e` advanced from `owner_authentication`
to `owner_input_commit`. It failed 0.292573502 seconds after entering input
commit with `SavanaError`, code `invalid_response`. The first episode took
56.299438649 seconds in total; the process exited 2.

This establishes that the login boundary was crossed, not that input was
committed or a task root approved. The result remains **0 model calls, 0 scored
episodes, 9 Unknown**. It is neither a successful protection result nor an
attacker-success result. No automatic replay or state reset followed.

- Start SSM command: `de1568c1-d1cf-42a1-aadb-365e5cb8e425`.
- Outcome: `33732d07-68c8-4ca9-951f-a49063c95ca6`.
- Stage/audit readback: `5e8520da-f24f-4f5a-9dec-4e2b1e03c206`.
- Original artifacts, downloaded unchanged:
  `experiments/results/aws-replacement-attempt-20260925/7b5f0621459a4bdbb9f1a27cdaddc45e/`.
- 16 audit events, head
  `8e96d07b54fd456b23b101ae6442bbe602426065c0936662dbc2bc420cf5a4f6`.
- Export: 50,021 bytes; transport SHA-256
  `c59f797585eadf13a29047fea093e0e13893d85005560ca71d75232a886503da`.
- Offline verification: `audit_consistent=true`, `official_episodes_rescored=0`.
  This checks an unkeyed hash chain and source/package consistency; it is not
  portable kernel attestation.

## Cause and boundary-preserving fix

`savana-client::owner_ingress::OwnerIngress::commit_text` incorrectly required
the input chunk response's `cumulative_digest` to equal `SHA256(plaintext)`.
These are different protocol values:

1. The declared content digest is the plain SHA-256 of the exact text bytes.
2. The cumulative digest is a domain-separated chain binding the private input
   session, channel, sequence and chunk bytes. Ingressd verifies the kernel's
   acknowledgement and chain value before returning it to the browser client.

The browser Begin response does not disclose the private input-session handle
or chain seed. The SDK therefore cannot independently reconstruct that chain;
comparing it with the plain text hash rejected a valid input. The previous SDK
mock fixture incorrectly used a plain text hash as the cumulative digest and
hid the incompatibility.

The SDK now checks the response variant and exact acknowledged sequence, while
treating the session commitment as opaque. This does **not** remove the plain
content digest: Begin and both Finalize calls still submit the exact SHA-256.
Ingressd still checks accumulated byte count, declared digest, actual text hash
and kernel chunk commitments. Finalize still requires a separate signed user
approval. Unexpected early commitment, denied approval, credential switching,
uncertain transport and wrong sequence remain fail-closed without replay.

No manual IPC, manufactured assertion, auto-approval or kernel change was used.
Experiments continue to enter through the Python API and its native SDK.

## Reproduction and regression coverage

The replacement test fixture uses the actual protocol helpers
`input_channel_begin_digest_v2`, `input_chunk_digest_v2` and
`input_channel_step_digest_v2` with a synthetic private server session.

- With the old SDK, `commit_is_bounded_signed_once_and_not_task_authority`
  reproduced `InvalidResponse` (1 failed).
- With the corrected SDK, all 11 owner-ingress tests passed.
- All 130 `savana-client` unit/integration tests passed.
- Ingressd's `declared_digest_parsed_document_and_abort_rules_are_closed`
  test passed separately (1 test).

The fixture is not real authentication evidence. Only the actual failed run's
stage transition establishes that this user's login passed. A successful new
end-to-end task and model call remain unverified.

## SDK-only deployment, preserving enrollment and kernel state

An offline Linux ARM64 build produced the `cp312-abi3` Python extension. All
workspace package artifacts in the dedicated disposable Docker build volume
were cleaned first. Source hashes were checked before/after the build.
Relative to the previously deployed SDK snapshot, the only changed build
source is `crates/savana-client/src/owner_ingress.rs`.

- Old SDK SHA-256:
  `46638aa305c5ea859c1012cce82bc77c450263c2ec175ba09eb24a025ed3ed99`.
- New SDK SHA-256:
  `160ed884fcc1c74e4922f9f13d9b694c6ad78100b16aaef4340f2a31173328bd`.
- Extension size: 22,960,024 bytes.
- Build receipt SHA-256:
  `f3c6f0f74510cac9f68e11f3b6be135d4a842e2e1092ec6987ce08975725ca57`.
- Preflight SSM: `4f55b33b-c468-4c76-a8eb-0fc3ace80f0d`.
- Installation SSM: `3f0da5b7-34e2-4a81-87d3-f311993b9369`, exit 0.

Only the extension and source-hash build receipt were uploaded to the existing
encrypted private artifact bucket, under `artifacts/sdk-input-digest/`. The
old extension is retained at
`/root/savana-sdk-input-digest-20260925/old.abi3.so` on the temporary host.
The new extension was atomically installed and imported successfully under
the unprivileged `savana-experiment` account. Only the Python auth/operator
sockets and services were stopped/restarted to reload their SDK.

All five native service binary hashes, PIDs and restart counters matched
before/after; each restart counter remains zero. No kernel state, input,
authorization, enrollment or encrypted credential was cleared or restored.
All 16 administration prerequisites returned true afterward. The status
command's `passkey_authentication_confirmed=false` is its conservative static
readiness field, not evidence that the earlier successful login was revoked.

This is a separate SDK build, not a claim that native daemons were rebuilt from
the new SDK snapshot. Their existing measured binaries remain installed. The
host remains the B/file-backed integration profile, not TPM-backed production
acceptance. The original expiry and approximate total budget were not extended.

At the deployment checkpoint the corrected experiment had not been started. A fresh, separately
identified attempt requires the user to be ready for real login, input approval
and task authorization at `http://localhost:8766/experiment-auth`. Registration
does not need to be repeated.

## User-approved rerun after SDK deployment

The user subsequently confirmed readiness. SSM
`7d210b04-2e09-49eb-b1b3-c59596285a22` verified the new SDK hash and all
16 administration prerequisites, moved the previous run unchanged into
`/var/lib/savana-benchmark/retained-runs/7b5f0621459a4bdbb9f1a27cdaddc45e`,
and started a new process. This was a separate requested attempt, not replay
of an uncertain kernel operation. Kernel state and enrollment were preserved.

The new run was `b6063e263e10475fbb9130d9c043e3d4`. It crossed
`owner_authentication`, then ended at `owner_input_commit` with
`AuthBrokerError`, not the former `invalid_response`. The first episode lasted
80.715080376 seconds. Its result is still **0 model calls, 0 scored episodes,
9 Unknown**, process exit 2. Input approval and task authorization are not
confirmed. Do not infer user cancellation or timeout from this generic error.

During this attempt, two local read-only `/__experiment/pending` requests
timed out. Inspection found the 18766 SSM listener absent and the old 18786
tunnel reporting destination-connection failures. Both exact task-owned SSM
forwarders were reconnected, without restarting kernel/auth services or
submitting an assertion. The replacement listener startup exceeded the local
10-second readiness probe, but a subsequent check found both listeners and
returned HTTP 200 with no pending request. This establishes restoration of
the local forwarding route, not the exact cause of `AuthBrokerError` and not
successful approval. No further run was started automatically.

- Outcome readback: `34a491f6-4bf7-4a47-95dc-f81416b2e6f1`.
- Completion readback: `a2bab7f5-1fb0-4630-97fe-fb48b61f83d9`.
- Original local evidence:
  `experiments/results/aws-replacement-attempt-20260925/b6063e263e10475fbb9130d9c043e3d4/`.
- Audit: 16 events; head
  `c0f7e183f72b659de91b9683f84fe4e901cda31bdb410f39738d97f432981ff1`.
- Export: 50,352 bytes; transport SHA-256
  `87d4ba659a973a70f6843f663df6cdfb984a902ef4fc88740b30ae0ea41c6cd8`.

Future starts must check the *local* authenticated forwarding route as well
as the remote administration prerequisites before opening a short-lived real
authentication request. A healthy remote broker alone does not establish that
the user's browser can reach it.

## Next explicit continuation

After the user requested continuation, the local HTML, JavaScript and
authenticated `/__experiment/pending` route all returned HTTP 200, with no
prior pending ceremony. The start helper repeated that local check immediately
before submitting SSM `2adf0694-a0e3-4e10-8e68-3203dd8fe1d4`.
That command verified the corrected SDK hash and remote prerequisites,
retained run `b6063e263e10475fbb9130d9c043e3d4` unchanged, and started a
separately identified run. Its startup readback was `active/running`.

The local authenticated route then returned an actual pending
`webauthn.assert`. The user was instructed to review the request, then remain
on the experiment-auth page for subsequent independent input/task approvals.
No assertion or approval was submitted by the assistant. This is a startup
checkpoint, not a completed run, authenticated input or score.

### Disabled-button follow-up

The user subsequently reported that the button could not be clicked. Direct
browser inspection found `Waiting for the server experiment...`, both buttons
disabled, and `Server did not confirm this request.` The assistant did not
activate either button or change the page state.

SSM `9dc76bab-972f-4f81-b1cf-c453bf6040e6` confirmed that run
`1b1b7ffaea1649a1b283ecf73b1875bc` had ended with `AuthBrokerError` at
`owner_authentication`, first-case duration 118.046573808 seconds and process
exit 2. That duration is consistent with the 115-second broker wait following
bootstrap. No authenticated continuation was reached. All nine cases remain
Unknown, with zero model calls and zero scored episodes.

Local gateway reads timed out intermittently. A direct authenticated SSM read
returned HTTP 200/no pending request in 0.314 seconds; a later gateway read
returned the same in 3.494 seconds. The current disabled state is therefore
consistent with no live ceremony, while the intermittent forwarding issue is
not proven resolved. No further run was started or enrollment changed.

The original evidence was retained unchanged under
`experiments/results/aws-replacement-attempt-20260925/1b1b7ffaea1649a1b283ecf73b1875bc/`.
The audit has 15 events and head
`28483c6b45e4df4610798a6ee26d2b80e837348796c081acfb9d8173f7687d66`.
Export size is 49,786 bytes, SHA-256
`601f237f2aa0870d5b7c3e5a331f870db098b6556911f29929a112c97d879f6e`.
Offline consistency verification passed with zero official episodes rescored.

The startup UX should be changed to coordinate browser readiness before
issuing short-lived authentication, and the forwarding instability diagnosed;
neither proposal is implemented by this read-only follow-up. Expired requests
must not be revived and approval requirements must not be bypassed.

The subsequent requested implementation is recorded separately in
[Browser-coordinated experiment start](experiment-browser-ready-20260925.md).
It preserves this checkpoint and its failed-run evidence unchanged.
