# AWS Linux acceptance — not a production deployment certificate

The user selected AWS for Linux acceptance on 2026-09-20 and subsequently
authorized using the local credentials with an approximately USD 10 budget.
The selected local default configuration uses ap-southeast-1. This authorizes
an isolated temporary acceptance environment, not changes to or deletion of
existing business resources. Use a dedicated role and security group, bound
runtime, and clean up only resources recorded as created for this acceptance run.
Use synthetic fixtures only. Do not upload personal task inputs, existing vaults,
enrollment databases or local signing keys. Google Cloud and cloud models remain
disabled. The AWS host is a test environment, not an implicit change to the
product's private-data trust boundary.

## Read-only inventory gate

`tools/aws_v04_preflight.py` requires an explicit CLI profile, region, expected
account and existing instance ID. It can call only STS GetCallerIdentity and five
EC2 Describe APIs. It never creates, starts, stops, modifies or terminates anything,
installs software, opens ports, sends remote commands or reads instance user data.

Example (all values must be replaced with the confirmed target):

```sh
python3 tools/aws_v04_preflight.py --profile CONFIRMED_PROFILE \
  --region CONFIRMED_REGION --account CONFIRMED_ACCOUNT \
  --instance-id CONFIRMED_INSTANCE_ID
```

The checks bind the instance owner, image and instance type, require Linux/UEFI,
configured NitroTPM 2.0 support, IMDSv2 with hop limit 1, attached encrypted EBS,
and security groups with **no inbound rules**. This profile is intended for SSM
and explicitly established loopback port forwarding. Savana UI ports must not be
opened publicly. Inventory mismatches and missing fields fail closed. Existing
rules are reported as failed checks, never automatically removed.

Exit 0 means these inventory prerequisites passed, **not** that Savana is ready.
The report always marks production acceptance as `not_run`, hardware authority
and rollback verification as false. It does not attest Secure Boot, in-guest TPM
devices, PCRs, monotonic storage, IAM adequacy, SSM connectivity or a running
Savana service. Tests use fixture inventories and never AWS credentials.

The checked AWS fields follow the official [instance-type API](https://docs.aws.amazon.com/cli/latest/reference/ec2/describe-instance-types.html)
and [image API](https://docs.aws.amazon.com/cli/latest/reference/ec2/describe-images.html).
NitroTPM needs a compatible type, a TPM-enabled image and UEFI; instance-family
support alone is insufficient. See [AWS prerequisites](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/enable-nitrotpm-prerequisites.html).

## Required on-instance acceptance

### First real AWS infrastructure run (2026-09-20)

A disposable x86_64 m6i.large host was created in ap-southeast-1 using an
encrypted copy of the official AL2023 2023.12.20260918.0 snapshot, registered
with UEFI and TPM 2.0 enabled. Existing business instances were not modified.
The dedicated security group has no inbound rules and only HTTPS egress;
administration uses a separate SSM-only instance role. No SSH key, public UI,
cloud model, personal data or production key was installed.

Observed results, not merely configuration assumptions:

- All eight read-only inventory prerequisites passed.
- `/dev/tpm0` and `/dev/tpmrm0` exist; TPM tools report TPM 2.0, AMZN/NitroTPM.
- The initial boot had Secure Boot disabled. The official AL2023 enrollment
  tool verified bootloader/kernel signatures; enrollment without an interactive
  answer failed safely. Rerunning with its documented `--yes` option (not
  `--force`) succeeded. After reboot, `amazon-linux-sb --exit-code status`
  returned `Enabled`, and PCRs 0/7 were readable. No remote attestation or
  application signer/rollback proof is implied by these observations.
- The guest expiry timer is active. A separate AWS Scheduler task is enabled
  to terminate exactly this disposable instance at 2026-09-21 02:00 UTC, even
  if its guest timer fails. Root volume deletion is enabled on termination.
- The current price API returned USD 0.12/hour for this instance type, before
  EBS, IPv4 and other charges. The four-hour compute allowance is USD 0.48;
  this is an estimate, not a final bill or a global AWS spending cap.

The first source-transfer attempt was blocked by the execution safety review;
SSM history confirmed that none of those attempts was dispatched. The host was
stopped to avoid idle compute spend. The user then explicitly approved transfer
of the identity module and synthetic tests, excluding credentials, personal data
and old kernel state. Only that source scope was uploaded after resuming the host.
See the native results below. No full product/service startup, signer or rollback
acceptance was performed.

Additional AWS cleanup tasks were configured to deregister only the temporary
image at 02:05 UTC and delete only its copied snapshot at 02:10 UTC. These are
scheduled actions, not evidence that deletion has already happened. The expiry
role is limited to the exact instance/image/snapshot IDs with run-tag checks.
The short-lived image/snapshot/role/security-group inventory
is retained locally for exact cleanup; never delete the source Amazon snapshot
or pre-existing customer resources. This infrastructure run does not complete
the code-level or hardware-authority gates listed below.

### Approved native identity run and startup fixes (2026-09-20)

The 48,548-byte initial source archive (SHA-256
`6fcb8a1d4104d03b46bc120e7b1b449d1e421cb55a8f7db3cd294db5a78ae9f4`)
contained only the identity crate, its synthetic tests/example and Cargo manifests.
Remote integrity was checked before extraction. The temporary build workspace
changed only its member list to that crate; no other product crates were uploaded.
The supplied lockfile was retained for dependency selection, then subsequent
checks used `--locked`. AWS used Amazon Linux Rust 1.98.0; an independent local
ARM Linux run used the repository minimum Rust 1.82.0 offline.

The actual `measure_linux_peer_v2` function was exercised in both debug and
release builds, installed root:root 0755, with separate non-root test identities:

| Synthetic service pairing | Ordinary process | With key production systemd restrictions |
| --- | --- | --- |
| Same UID | Accepted | Accepted |
| Different UIDs | Rejected (`Io`) | Rejected (`Io`) |

The restrictions included ProtectProc=invisible, ProcSubset=pid, no capabilities,
NoNewPrivileges, restricted address families, read-only system and the production
syscall-filter shape. This is a targeted peer test, not a full production unit
startup. Independent commands demonstrated that reading the other UID's
`/proc/PID/exe` returns Permission denied and the hardened view hides its process
directory entirely. A pidfd does not waive these access checks. Thus distinct-UID
production peer measurement is a **confirmed deployment blocker**, not fixed by
these changes. Do not combine service UIDs, grant broad ptrace capabilities to
ordinary services, or replace executable measurement with caller-supplied claims.

The first full native module suite also exposed two worker-startup failures:

1. The configured four-descriptor limit was applied before Landlock construction.
   The ruleset occupied fd 3, so opening its path rule failed with `EMFILE`.
   The final descriptor limit now applies after temporary rule descriptors close,
   still before seccomp and exec. Other resource limits retain their earlier order.
2. Dynamic ELF startup needed execution of its system interpreter, but only the
   selected worker had execute permission. The fix grants execute/read only to
   the fixed architecture-specific glibc loader after checking the opened file is
   root-owned, regular, executable and not group/world-writable. Rules bind to the
   verified descriptor. No directory-wide execute or caller-chosen loader grant
   was added. Missing/unsupported loaders still do not create a permissive fallback.

Final validation: **21 tests pass on AWS x86_64 and 21 on offline ARM Linux**
(13 library, four sandbox, four native-peer tests), including the exact final
soft/hard descriptor limit of four, blocked unlisted file reads, blocked unrelated
direct execution and blocked network access. These checks are regression evidence,
not proof against every native-code behavior. The new diagnostic/script retain
the failing cross-UID cases without changing production identity checks. CI now
runs the native wrapper suite, and the frozen source inventory also covers the
13 production identity-crate manifest/source files previously absent from it.

The approved transport was SSM Run Command. Source payloads may remain in AWS
control-plane command history after instance/disk deletion; deleting the host is
not a claim that all AWS logs or backups have been erased. No credentials or
personal/kernel-state data were included. No commit or push was performed.

Cleanup completed after the native run: the disposable instance reached
`terminated`; its attached volumes are gone. The temporary AMI was deregistered,
its owned copy snapshot deleted, and the dedicated security group, instance
profile, both roles and all three fallback schedules removed. The original
business instance remained running. These disposable guest files cannot be
recovered from the deleted disk/snapshot; local source and test records remain.
AWS control-plane history is subject to its own retention as noted above.
No final AWS bill is asserted; the run was short-lived within the planned budget.

### Remaining acceptance gates

- Validate boot mode, Secure Boot/PCR policy and TPM device access on the selected
  image, not just EC2 inventory. Provision independent development authorities;
  never copy host or production seeds into the test instance.
- Implement and test the production authority/rollback adapters. The existing
  `MissingPlatformAuthority` release gate must not be removed. NitroTPM availability
  alone does not turn exportable filesystem seeds into non-exportable signers.
- Exercise actual distinct service UIDs, measured peer verification, systemd
  inherited sockets, namespace restrictions and credential permissions. Same-UID
  container transport tests do not establish this.
- Run human approval with a supported enrolled WebAuthn hardware authenticator.
  NitroTPM is server-side state protection; it does not replace user consent or
  the user's hardware credential. Preserve the fixed localhost browser origins
  through the approved tunnel; do not rewrite RP IDs to make a test pass.
- Test restart, unknown execution outcome, old/replayed approval, expired/revoked
  root, rollback and stale image/state rejection without issuing a new task or
  refunding consumption. AWS documents that TPM state is not in EBS snapshots;
  a disk snapshot is not a full security-state migration. See [NitroTPM
  considerations](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/enable-nitrotpm-prerequisites.html).
- Complete authenticated intake/session recovery, private handoff delivery,
  exclusive publication and the accepted compiler fragment before declaring a
  consumer workflow complete. A successful prerequisite report waives none of
  these code-level gates.
