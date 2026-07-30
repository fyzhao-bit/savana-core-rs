# macOS Development Audit Bridge Design

## Goal

Allow the frozen Rust kernel to retain its complete audit-sink validation while
running under macOS launchd in the local development deployment.

## Problem

`savana-kerneld` accepts only a nonblocking FIFO, Unix socket, or character
device for its audit sink. It also requires an immediate successful writable
poll. A launchd `StandardErrorPath` regular file is rejected by type, while
macOS reports `POLLNVAL` when polling `/dev/null`. Omitting
`StandardErrorPath` also supplies `/dev/null`.

A system launchd probe confirmed that a named FIFO is reported as a FIFO and
returns `POLLOUT`. The deployment therefore needs a reader to hold and drain
the FIFO before launchd starts kerneld.

## Architecture

Add a development-only, signed Rust executable named
`savana-development-audit-bridge`. It is a deployment adapter, not a seventh
product service and not part of the kernel API.

The installer creates a fixed, non-symlink FIFO inside the development runtime
directory and a private audit log. A dedicated
`com.savana.development.audit-bridge` launchd job starts first under its own
low-privilege account. The bridge validates its fixed inputs, opens the FIFO,
signals readiness through launchd-visible process state, and continuously
copies complete audit bytes to the append-only private log. Kerneld's
`StandardErrorPath` points to that FIFO.

The bridge receives no kernel socket membership, opaque handles, signing
material, TLS material, or Python/server credentials. It cannot invoke any
kernel IPC operation.

## Filesystem and Identity

- Executable: canonical signed copy under the development install root and a
  byte-identical launch image under
  `/Library/PrivilegedHelperTools/SavanaDevelopment`.
- FIFO:
  `/Library/Application Support/Savana/Development/run/kerneld-audit.fifo`.
- Log: `/Library/Logs/Savana/Development/kerneld-audit.log`, mode `0600`.
- Account: `_savana_audit_dev`, with no login shell and no membership in any
  service-edge group.
- The FIFO and log are created by the installer at fixed paths. The bridge
  rejects symlinks, an unexpected file type, or ownership/mode inconsistent
  with the installed development layout.

## Startup and Failure Behavior

1. The installer creates and validates the account, directories, FIFO, and
   private log.
2. It verifies the signed bridge identity and byte equality between the
   canonical binary and launch image.
3. It bootstraps the audit bridge before the six product services.
4. It waits until the bridge job is running and the FIFO has an active reader.
5. It bootstraps kerneld and the remaining product service graph.

If the bridge cannot validate or open its resources, it exits nonzero and the
installer fails closed. launchd keeps the bridge alive. If the reader
disappears later, kerneld's existing nonblocking audit writes fail according to
the frozen kernel policy; there is no fallback to a regular file or
`/dev/null`.

Rollback and uninstall boot out the bridge first, remove the FIFO and launch
image, and remove the dedicated account only through the same guarded
development cleanup path used for the other accounts.

## Packaging

The bridge is built as a separate development-support crate. The macOS build
script includes it only in the development package. The signing script signs
it with the same locally trusted development code-signing identity, and the
installer independently verifies that identity.

It is not added to the kernel release manifest, does not change the frozen
kernel crate, and does not expand the Python or IPC interfaces.

## Verification

Automated deployment tests must first fail and then pass for:

- the bridge launchd job, fixed paths, account, and startup ordering;
- kerneld using the FIFO rather than a regular file or `/dev/null`;
- signed packaging and installed byte equality for the bridge;
- rollback and uninstall cleanup;
- absence of kernel IPC group membership for the bridge account.

The bridge has unit/integration tests for FIFO validation, symlink rejection,
private-log validation, byte forwarding, partial writes, interrupted system
calls, reader restart behavior, and fail-closed startup.

End-to-end verification installs the signed package, proves all six product
services stay running, exercises the Python V2 call path from the server UI,
checks that kernel audit events reach the private log, and runs the frozen V2
core checker to prove the kernel itself did not change.
