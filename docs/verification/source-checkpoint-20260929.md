# Local source checkpoint — 2026-09-29

Scope: save the accumulated Linux/v0.4 source, Python SDK, experiment harness,
tests, deployment tooling and research documentation on the development branch
`codex/intent-bound-execution`. This is not AWS deployment, a release, a full
kernel security review, or a protected AgentDojo score.

## Checks performed

- GitHub fetch/read of the user's `fyzhao-bit/savana-core-rs` repository succeeded.
  The local branch contains the fetched `main` tip; no remote history rewrite is
  needed. The destination development branch did not exist when checked.
- `cargo check --workspace --all-targets --offline`: passed on the local macOS
  host. Linux-only ownerctl helpers generated dead-code warnings. No claim is
  made about a new Linux execution, all-features clippy or the full Rust tests.
- Focused Python suite: **71 tests passed**, including local HTTP/mTLS,
  explicit software-identity setup, finite preconsent, readiness, operator,
  owner setup, endpoint/oracle and audit consistency tests. The Python package
  was copied from this worktree into a fresh temporary SDK directory and used
  the previously built local native extension. An initial run failed imports
  because the old temporary SDK directory had missing Python package files;
  it is not counted as passing, and no product code was changed to hide it.
- `git diff --check`: passed for tracked edits before staging. Once new files
  were staged, `git diff --cached --check` also identified existing blank lines
  at EOF in `savana-protected-experiment.socket` and
  `savana-tpm-first-activate-v3.service`. Those files are preserved as supplied;
  the latter is in the frozen boundary. This is not a clean full-CI claim.
- Source-only scan found no matches for provider keys, AWS access IDs, GitHub
  tokens, PEM private-key blocks or credential-bearing URLs in the selected
  changes. This is a bounded pattern scan, not a proof that source contains no
  secret. Binary artifacts, credential extensions and files over 2 MiB were also
  checked; none occurred in the selected change list.
- Approximately 1,000 raw result/log files under `experiments/results/` are
  deliberately excluded and retained locally. The directory is now ignored;
  no experiment evidence was deleted. Historical documentation may reference
  these non-published artifacts. Curated public evidence requires a separate
  review/export; the source push is not that export.

## Known failing integrity gate — preserved, not bypassed

`tools/check-frozen-v2-core.sh` returned exit 1: **314 matching files, 17
mismatches** against the pre-existing working-tree freeze manifest:

```text
crates/savana-approvald/src/daemon.rs
crates/savana-approvald/src/protocol_service.rs
crates/savana-client/src/managed_admin.rs
crates/savana-core-py/src/client.rs
crates/savana-kernel-protocol/src/v2/task_context.rs
crates/savana-kerneld/src/bin/savana-development-build-inputs.rs
crates/savana-kerneld/src/v2_agent_authority.rs
crates/savana-kerneld/src/v2_core_services.rs
crates/savana-kerneld/src/v2_value_owner.rs
crates/savana-policy-core/src/bin/savana-development-material.rs
crates/savana-policy-core/src/v2/continuation_state.rs
crates/savana-policy-core/src/v2/durable.rs
crates/savana-policy-core/src/v2/managed_admin.rs
crates/savana-policy-core/src/v2/mod.rs
crates/savana-policy-core/src/v2/provenance.rs
deploy/linux/integration/assemble.py
deploy/linux/integration/install.py
```

The freeze files already contained earlier uncommitted changes and are preserved
as part of the checkpoint. They were **not** regenerated in this push-only task.
The frozen-core CI step is therefore expected to fail until the changed boundary
is reviewed and verified and an explicit new freeze baseline is established.
Do not label the checkpoint release-ready or silently disable the checker.

## Experimental identity limitation

The opt-in software identity emulates WebAuthn UP/UV and does not prove human
presence or hardware authentication. Defaults remain interactive; the finite
benchmark profile must be armed explicitly. Its new server path remains
undeployed and unmeasured. See the
[identity-mode record](../../experiments/SOFTWARE-IDENTITY-BENCHMARK.zh-CN.md).
