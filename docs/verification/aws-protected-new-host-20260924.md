# New AWS protected-experiment host — 2026-09-24

This is a new temporary host requested by the user, not an upgrade of the old
Savana host. Only current Linux binaries, Python/deployment source and synthetic
test fixtures were uploaded. No laptop/cloud credentials, personal data, previous
kernel state or enrollment were copied. Experiment admission remains Python SDK
only; installation does not fabricate task consent or model scores.

## Infrastructure verified

- Region: `ap-southeast-1`; instance: `i-071646e066afc6302`.
- ARM64 `m7g.large`, Amazon Linux 2023, kernel
  `6.12.103-129.197.amzn2023.aarch64`.
- The repository's eight EC2 prerequisite checks passed: running Linux,
  matching architecture, UEFI, NitroTPM configuration, IMDSv2/hop limit 1,
  no inbound security-group rules, and encrypted attached EBS.
- SSM is online; `/dev/tpm0` and `/dev/tpmrm0` exist; TPM reports version 2.
- After enrollment of the distribution's Secure Boot keys and a reboot,
  `amazon-linux-sb --exit-code status` returned `Enabled`; SHA-256 PCRs 0/7
  were readable. Boot-check command: `190de2c1-f5e7-4ff6-aab2-a973fdff6867`.
- No public SSH, web approval endpoint, GPU or cloud model deployment was added.

This is still the **file-backed B integration profile**, not production TPM
signing, hardware-authority attestation or anti-rollback acceptance. Presence
of a TPM and Secure Boot does not prove those application-level properties.

## Fresh build and transfer

Fourteen Linux runtime/installer artifacts and the CPython 3.12+ stable-ABI
extension were built offline for ARM64. Exported binaries and build-source
fingerprints were checked before packaging; daemon and SDK source snapshots
match. The explicit 108-file allowlist and hashes are in the upload inventory.

- Archive: 32,744,249 bytes.
- SHA-256: `e7824c1d3638004f946be4bb4c246e212c28785a2bdb72eb7bd73fafb0c410b5`.
- Temporary bucket: `savana-protected-20260924-wlqdul-377521353256`.
- Object: `artifacts/bundle.tgz`; all public access blocked, TLS required,
  AES256 server-side encryption, lifecycle expiration configured.
- Target deployment source: `/opt/savana-protected`.
- Local operational receipts: `/private/tmp/savana-protected-aws.wlqDuL`.

## Cost and expiry

The queried on-demand instance rate was USD 0.102/hour: a four-hour compute
allowance of USD 0.408, excluding EBS, IPv4, storage and other charges. This is
not an account-wide billing cap or final bill.

The exact-instance termination schedule is enabled for **2026-09-25
05:23:52 UTC / 01:23:52 EDT**. A guest expiry timer is a second guard. Dedicated
AMI and snapshot deletion are scheduled five and ten minutes later. The S3
object has separate lifecycle expiry; bucket, security group and IAM metadata
are not automatically deleted by those schedules.

## Installation and experiment acceptance

Fresh installation completed, SSM command
`3c4b4992-4af8-4176-b419-9a55e43e7299`, exit 0. The remote archive digest,
file-backed signed startup measurements, stable five-service startup, approval
administration health and measured owner-control exchange all passed.
`owner-health` returned `{"state":"ready"}`; the expiry timer remained active.

Python 3.12 and a separate unprivileged `savana-experiment` virtual environment
are installed. Dependency setup command
`40d8ac5d-1cb1-4421-8046-8ebc8ac2a86a` exited 0. AgentDojo is pinned to 0.1.35
and cryptography to 50.0.0. Dependency installation was bounded and denied
link-local networking, including instance metadata. The SDK extension is
`/opt/savana-protected/python/savana_core.abi3.so`.

The installer uses host-key encrypted systemd credentials in the B profile.
It reports that the host credential key is not on guest-encrypted media; AWS
EBS encryption was verified separately and is not a TPM signer or guest disk
encryption claim. Fresh service UIDs 64001–64006 also produce useradd range
warnings; exact allocated UID/GID bindings were verified by the installer.

Python/TLS regression completed: **27 tests passed in 4.764 seconds**, SSM
`99be155a-89fb-4ee6-bbe9-730c9b8b8524`, exit 0. This covers the worker protocol,
mutual TLS, exact destination/key/client/ALPN binding, nonce deduplication,
bounded frame parsing, audit failure handling and the official-oracle adapter.
These are synthetic plumbing tests, not kernel-protected model scores.

The native Python entry point was actually invoked on the server, SSM
`12811d3c-2a15-4cb2-81f5-fad6031da2a3`. Linux, AgentDojo version and SDK private
publication interface checks passed. It exited **2 (`not_started`)**, reporting
exactly these remaining blockers:

1. `signed_deployment_and_episode_bindings_not_provisioned`.
2. `trusted_passkey_broker_fd_required`.
3. `model_key_fd_required`.

Consequently there are **9 planned samples, 0 scored, 0 model calls**. All nine
remain Unknown; this is not a 0% attack-success result or a successful protected
experiment. The installer deliberately leaves model/provider routes disabled
and does not create reviewed private planning profiles. New-machine provisioning
does not solve that remaining deployment-authoring work. A real approval broker
and secret descriptor must also be connected without faking user consent.

The scope of the runner remains the finite single-read calendar subset, **not**
the full adaptive multi-step AgentDojo benchmark. See
[the runner description](../../experiments/AGENTDOJO-PROTECTED-RUNNER.zh-CN.md).

Final check `9df44805-e28b-4b65-8f04-58c79dd68050` exited 0: all five services
and the identity broker were active/running with **zero restarts**; owner health
was still ready. Server-side and downloaded local offline verification both
passed, with zero official episodes rescored. The exact downloaded artifacts
are in [aws-protected-preflight-20260924](../../experiments/results/aws-protected-preflight-20260924/summary.json).
Their audit head is
`c0bf620b3f344231a38c4eee97b4c6dcd62781290d0f7735fa7c460f9a98a0ab`.
This is an evidence-integrity result, not a portable kernel attestation.

### Explicit start request: still blocked before kernel admission

After the user requested a run, EC2 again reported `running` and SSM `Online`.
SSM command `d64befe0-5f1c-4aec-960f-ad9f8b268244` checked the actual deployed
configuration (printing only booleans/counts) and invoked the original Python
protected runner as the unprivileged experiment user. All five services were
active, but the configuration check reported:

```json
{"managed_admin_configured":false,"fused_model_workers_configured":0,"managed_admin_socket_exists":false}
```

The runner exited 2 with the same three missing prerequisites, `not_started`,
zero scored episodes and zero model calls. This was **Python launch preflight**,
not a G1–G7 denial, attack blocked by the kernel, or an AgentDojo outcome. The
isolated new output is `/var/lib/savana-benchmark/start-request-20260924-2148`.
No deployment trust, state, credential, approval rule or expiry was changed.
The per-command local receipt is in the operational receipt directory above.

In particular this is not just a missing API key: the deployed profile has no
managed task-plan installation endpoint and no fused-model worker. A reviewed
signed deployment configuration and the missing experiment provisioning path
are required before asking for real user authentication or spending model calls.

## Access during the temporary lifetime

Use the user's own AWS profile and SSM; no public SSH key or inbound rule exists:

```sh
aws --profile default --region ap-southeast-1 ssm start-session \
  --target i-071646e066afc6302
```

Native installation is under `/usr/libexec/savana`, `/etc/savana` and
`/var/lib/savana`. Experiment source is under
`/opt/savana-protected/experiments`; use `/opt/savana-bench-venv/bin/python` with
`PYTHONPATH=/opt/savana-protected/python:/opt/savana-protected/experiments`.
The dedicated experiment account is `savana-experiment`. Its preflight artifacts
are private under `/var/lib/savana-benchmark/native-preflight`.
