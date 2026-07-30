# macOS Development Audit Bridge Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Supply the frozen macOS kerneld with a validated FIFO audit sink through a signed, least-privilege development deployment adapter.

**Architecture:** A new development-only Rust binary opens and validates a fixed FIFO and private append-mode audit log, then forwards bytes without receiving kernel IPC access. launchd starts this bridge before the existing six product services; kerneld uses the FIFO as `StandardErrorPath`, and installation fails closed if the bridge is unavailable.

**Tech Stack:** Rust 1.82, `rustix`, Cargo workspace, macOS launchd plists, Bash deployment scripts, Apple codesigning.

## Global Constraints

- Do not modify frozen kerneld behavior or relax its audit validation.
- Keep the six product services and every existing IPC edge unchanged.
- The audit bridge uses `_savana_audit_dev` and belongs only to its primary group and `_savana_runtime_dev`.
- Fixed FIFO: `/Library/Application Support/Savana/Development/run/kerneld-audit.fifo`.
- Fixed log: `/Library/Logs/Savana/Development/kerneld-audit.log`, mode `0600`.
- All bridge binaries are signed, identity-verified, and byte-identical between canonical and launch-image locations.
- Startup, rollback, and uninstall fail closed around symlinks and unexpected file types.

---

### Task 1: Lock the deployment contract with failing tests

**Files:**
- Modify: `crates/savana-kerneld/tests/macos_deployment.rs`

**Interfaces:**
- Consumes: existing deployment source files and `extract()` plist helper.
- Produces: regression requirements for the bridge plist, FIFO path, account isolation, packaging, startup order, rollback, and uninstall.

- [x] **Step 1: Write failing deployment tests**

Add tests that require:

```rust
assert_eq!(
    extract(&kerneld_plist, "StandardErrorPath"),
    "/Library/Application Support/Savana/Development/run/kerneld-audit.fifo"
);
assert_eq!(extract(&bridge_plist, "UserName"), "_savana_audit_dev");
assert_eq!(
    extract(&bridge_plist, "Program"),
    "/Library/PrivilegedHelperTools/SavanaDevelopment/savana-development-audit-bridge"
);
```

Also assert the build, validation, signing, installation, identity verification,
bootstrap order, cleanup, and absence of audit-account edge memberships using
the exact fixed names in Global Constraints.

- [x] **Step 2: Run tests and verify RED**

Run:

```bash
cargo test -p savana-kerneld --test macos_deployment audit_bridge -- --nocapture
```

Expected: FAIL because the bridge crate, plist, packaging, and FIFO deployment
do not exist and kerneld still points to `/dev/null`.

- [x] **Step 3: Commit the regression contract with the implementation task**

Keep the failing tests unstaged until Task 3 supplies the complete deployment
implementation, so the branch never records an intentionally failing commit.

---

### Task 2: Implement the fixed-path Rust audit bridge with TDD

**Files:**
- Create: `crates/savana-development-audit-bridge/Cargo.toml`
- Create: `crates/savana-development-audit-bridge/src/lib.rs`
- Create: `crates/savana-development-audit-bridge/src/main.rs`
- Create: `crates/savana-development-audit-bridge/Cargo.lock`

**Interfaces:**
- Consumes: a FIFO and regular log at fixed production paths; test-only entry point accepts fixture paths.
- Produces: `savana-development-audit-bridge` executable and `run_with_paths(fifo: &Path, log: &Path) -> Result<(), BridgeError>`.

- [x] **Step 1: Add failing library tests**

Tests create real temporary FIFOs and files and require:

```rust
#[test]
fn forwards_fifo_bytes_to_private_log() { /* real FIFO, writer, bridge */ }

#[test]
fn rejects_symlinked_fifo() { /* symlink to FIFO must fail */ }

#[test]
fn rejects_non_fifo_input() { /* regular input must fail */ }

#[test]
fn rejects_non_private_or_non_regular_log() { /* wrong mode/type must fail */ }
```

The forwarding test ends through a test-only stop signal after confirming exact
byte equality.

- [x] **Step 2: Run tests and verify RED**

Run:

```bash
cargo test -p savana-development-audit-bridge -- --nocapture
```

Expected: FAIL because `run_with_paths` and validation are not implemented.

- [x] **Step 3: Implement minimal fail-closed forwarding**

Use safe `rustix` APIs with `O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK`. Validate the
FIFO with `fstat`, validate a single-link regular log owned by the effective
user with exact mode `0600`, then poll/read/write in bounded buffers. Retry
`EINTR`, wait on `EAGAIN`, preserve exact bytes, and sync written data. The
production binary accepts no arguments and uses only the two fixed paths.

- [x] **Step 4: Run bridge tests and workspace formatting**

Run:

```bash
cargo test -p savana-development-audit-bridge -- --nocapture
cargo fmt --all -- --check
```

Expected: all bridge tests PASS and formatting is clean.

---

### Task 3: Integrate signed packaging and launchd lifecycle

**Files:**
- Create: `deploy/launchd/development/com.savana.development.audit-bridge.plist`
- Modify: `deploy/launchd/development/com.savana.development.kerneld.plist`
- Modify: `deploy/macos/development/build.sh`
- Modify: `deploy/macos/development/sign.sh`
- Modify: `deploy/macos/development/validate.sh`
- Modify: `deploy/macos/development/install.sh`
- Modify: `deploy/macos/development/uninstall.sh`
- Modify: `crates/savana-kerneld/tests/macos_deployment.rs`

**Interfaces:**
- Consumes: signed bridge binary and local development certificate.
- Produces: bridge account, FIFO/log resources, bridge launchd job, kerneld FIFO stderr, guarded rollback and uninstall.

- [x] **Step 1: Add the bridge plist and kerneld FIFO path**

Create a KeepAlive background job for the fixed signed launch image under
`_savana_audit_dev`. Change only kerneld's `StandardErrorPath` to the fixed
FIFO.

- [x] **Step 2: Add build, validation, and signing**

Build the bridge package, copy it to `bin`, validate it as a real executable,
and sign it as `com.savana.development.audit-bridge` without service
entitlements.

- [x] **Step 3: Add account and resource installation**

Support clean installs, existing six-account development installs, and complete
seven-account installs. Track only newly created accounts for rollback. Create
the FIFO as `_savana_kernel_dev:_savana_audit_dev` mode `0640` and the audit
log as `_savana_audit_dev:_savana_audit_dev` mode `0600`. Do not add
`_savana_audit_dev` to any edge group.

- [x] **Step 4: Add identity checks and ordered launch**

Install canonical and launch-image bridge copies, verify both signatures and
byte equality, bootstrap/kickstart the bridge first, wait for it to remain
running, then load and check the six product services.

- [x] **Step 5: Add rollback and uninstall**

Boot out the six services before the bridge and remove the bridge plist and
artifacts with existing symlink guards. Retain only service identities that
still satisfy the locked-account contract; remove runtime and IPC edge groups.

- [x] **Step 6: Run deployment tests and verify GREEN**

Run:

```bash
cargo test -p savana-kerneld --test macos_deployment -- --nocapture
```

Expected: all macOS deployment tests PASS.

- [ ] **Step 7: Commit the bridge implementation**

Stage only the bridge crate, workspace metadata, bridge/kerneld plists,
deployment scripts, and deployment tests, then commit:

```bash
git commit -m "fix(deploy): bridge macOS kernel audit output"
```

---

### Task 4: Build, sign, install, and exercise the server

**Files:**
- Runtime artifact only: a new private `/private/tmp/savana-development-*` build directory.
- Runtime installation only: fixed paths listed in the approved design.

**Interfaces:**
- Consumes: Rust worktree, Python server worktree, system-trusted Savana development certificate.
- Produces: running six-service graph accessed by the existing server UI.

- [x] **Step 1: Build and sign a fresh package**

Run the development build against
`/Users/fz/Documents/jarvis/.worktrees/jarvis-kerneld`, then sign it with the
trusted local development identity.

- [ ] **Step 2: Install with administrator privileges**

Run the staged installer. Confirm the bridge is running before kerneld and all
six product launchd jobs remain in `state = running`.

- [ ] **Step 3: Verify audit delivery and isolation**

Confirm kerneld audit JSON reaches `kerneld-audit.log`, the FIFO remains a FIFO,
the audit log is `0600`, and `_savana_audit_dev` has no service-edge group.

- [ ] **Step 4: Exercise Python V2 from the server UI**

Open `http://localhost:8765/v2/shell`, perform a real request through the V2
browser surface and Python planner/provider interfaces, and verify no
`KERNEL_V2_REQUIRED` fallback or V1 call occurs.

- [x] **Step 5: Run final regression and frozen-core checks**

Run:

```bash
cargo test --workspace
tools/check-frozen-v2-core.sh
```

Run the Python kernel V2 tests in the Python worktree. Expected: all relevant
tests PASS and the frozen-core checker reports no kernel changes.
