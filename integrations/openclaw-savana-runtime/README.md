# Savana runtime for OpenClaw

This package is the production, text-only OpenClaw adapter for Savana. It is
maintained in the `savana-core-rs` repository. OpenClaw upstream is a pinned,
read-only compatibility dependency: this integration does not modify or push
code to the OpenClaw repository.

## Security boundary

OpenClaw owns channels, Gateway sessions, progress presentation, and the final
transcript. Savana exclusively owns planning, G1-G7 policy, approvals,
connector execution, private data, and final release.

The plugin registers exactly one provider (`savana`), one model (`agent`), and
one agent harness (`savana`). It registers no OpenClaw tool and no MCP server.
The harness accepts only the current user text when it exactly matches
OpenClaw's current inbound context. It rejects assembled prompts, attachments,
injected/resumed context, tool catalogs, MCP catalogs, fallback selection, and
any runtime other than `savana`.

One accepted turn is:

```text
current inbound text
  -> bounded NDJSON bridge
  -> Python public Savana SDK
  -> ingest_text(CHAT_TEXT)
  -> run_agent(PRIVATE, bounded RunLimits)
  -> one trusted FD 3 approval.decision for every tool call
  -> opaque document handle
  -> one trusted FD 3 approval.decision for final release
  -> execd dispatch-kind-selected final-release transport
  -> fixed 127.0.0.1 TLS 1.3/mTLS receiver
  -> durable single-flight release journal
  -> one turn.released UTF-8 value
  -> one OpenClaw assistant message
```

No status-only result can become assistant text. A release timeout, bridge or
receiver crash, duplicate delivery, cross-turn delivery, quarantined output,
or indeterminate effect seals/fails the turn without an assistant reply. Only
a proven `failed_no_effect` can clear an unclaimed reservation.

## Exact compatibility

- OpenClaw: `2026.7.1-2` exactly.
- Bridge protocol: `1`.
- Bridge/package version: `0.1.0`.
- Node: the exact engine range in `package.json`. In particular, Node 25 must
  be `>=25.9.0`; Node 25.6 is suitable for local typechecking only, not the
  production deployment.
- Python: 3.12 or later, using the abi3 wheel built from this repository.

Version drift fails plugin loading before a turn can run.

## Build and install from this repository

Use a reviewed commit of this repository and an absolute checkout path:

```sh
cargo test -p savana-openclaw-release
maturin build --manifest-path crates/savana-core-py/Cargo.toml --release
python3 -m pip install --no-deps /absolute/path/to/savana_core-0.1.0-cp312-abi3-*.whl
cd integrations/openclaw-savana-runtime
npm ci
npm run typecheck
npm test
openclaw plugins install /absolute/path/to/savana-core-rs/integrations/openclaw-savana-runtime
```

Do not install this adapter from an OpenClaw checkout and do not copy it into
the OpenClaw source tree.

## Bridge deployment file

The plugin receives only the absolute path to a private bridge configuration.
The file is closed-schema JSON and must be mode `0600` on POSIX:

```json
{
  "version": 1,
  "identity_path": "/var/lib/savana/openclaw/identity.cbor",
  "execd_bootstrap_path": "/etc/savana/execd-bootstrap-v2.json",
  "webauthn_fd": 3,
  "release_journal_path": "/var/lib/savana/openclaw/release.cbor",
  "release_canonical_host": "release.savana.example",
  "release_listen_port": 43191,
  "client_root_certificate_path": "/etc/savana/openclaw/execd-ca.der",
  "server_certificate_path": "/etc/savana/openclaw/receiver.der",
  "server_private_key_path": "/var/lib/savana/openclaw/receiver-key.pkcs8.der",
  "expected_client_spki_pin_path": "/var/lib/savana/openclaw/execd-client-spki.sha256",
  "max_steps": 24,
  "max_replans": 4,
  "turn_timeout_seconds": 120,
  "approval_timeout_seconds": 120,
  "release_delivery_timeout_seconds": 30
}
```

The five limits above must exactly match the corresponding values in the
OpenClaw plugin configuration. The doctor check rejects drift between the two
closed configurations.

`release_listen_port` is fixed, nonzero, and exclusive to this product. The
root-owned execd bootstrap must use `provider_routing_mode` value
`split-final-release` and a distinct `final_release_provider` naming the exact
canonical URL
`https://release.savana.example:43191/savana/final-release`, receiver
certificate/SPKI, TLS 1.3, ALPN `savana-provider-v2`, client certificate and
private-key credential. Execd selects this transport only from the already
authenticated `FinalRelease` dispatch kind. Tool execution remains on the
separately pinned tool provider. Both sockets connect only through
`127.0.0.1`; the canonical hosts are TLS identities, not DNS routing inputs.

The base `deploy/systemd/savana-execd.service` remains usable with
`legacy-shared` and therefore does not request the final-release private key.
A split deployment must install
`deploy/systemd/savana-execd-split-final-release.conf` as an execd service
drop-in and provision its separately encrypted credential before restart.

The identity, bridge config, receiver private key, and raw 32-byte execd client
SPKI pin must be private regular files without symlinks. Certificate inputs
are DER; the private key is PKCS#8 DER. The release connector is deployment
authority and cannot be self-registered by chat or by the user-tier connector
workflow.

The OpenClaw parent process must inherit the product-owned authentication
broker socket as descriptor 3. The TypeScript bridge passes only that
descriptor to Python. Bootstrap tokens and WebAuthn material are requested
over the framed broker protocol; they must never appear in JSON, environment
variables, argv, stdin/stdout logs, or transcripts.

For every SDK approval callback Python sends one length-prefixed request on
that same private socket:

```json
{
  "protocol_version": 1,
  "type": "approval.decide",
  "approval_id": "fresh-43-character-base64url-value",
  "display": "the exact bounded Savana approval display",
  "purpose": "tool_execution",
  "deadline_unix_ms": 1900000000000
}
```

The product broker must present the display in trusted Savana UI and return an
exact `approval.decision` carrying the same ID and a boolean `approved`.
Every read or write tool call gets a new decision. Denial, window close,
timeout, malformed response, or broker failure denies the callback and ends
the whole agent loop; there is no retry, replan, substitute tool, or fallback.
OpenClaw receives only `turn.event {event: "approval_required", purpose}`.
It never receives the display or ID and cannot answer an approval through chat.

## OpenClaw configuration

The production profile must explicitly select `savana/agent`, pin the model to
the `savana` harness, deny every OpenClaw tool, define no fallback, and omit
top-level MCP configuration:

```json
{
  "plugins": {
    "enabled": true,
    "allow": ["savana"],
    "slots": { "memory": "none" },
    "entries": {
      "savana": {
        "enabled": true,
        "config": {
          "pythonExecutable": "/opt/savana/venv/bin/python3",
          "bridgeConfigPath": "/var/lib/savana/openclaw/bridge.json",
          "protocolVersion": 1,
          "bridgeVersion": "0.1.0",
          "openclawVersion": "2026.7.1-2",
          "maxSteps": 24,
          "maxReplans": 4,
          "turnTimeoutSeconds": 120,
          "approvalTimeoutSeconds": 120,
          "releaseDeliveryTimeoutSeconds": 30,
          "logLevel": "warn"
        }
      }
    }
  },
  "agents": {
    "list": [
      {
        "id": "personal",
        "model": { "primary": "savana/agent" },
        "models": {
          "savana/agent": { "agentRuntime": { "id": "savana" } }
        },
        "memorySearch": { "enabled": false },
        "tools": { "deny": ["*"] }
      }
    ]
  },
  "session": {
    "maintenance": {
      "mode": "enforce",
      "pruneAfter": "7d",
      "maxEntries": 100,
      "resetArchiveRetention": "7d",
      "maxDiskBytes": 67108864
    }
  }
}
```

Do not add `fallbacks`, `tools.allow`, `tools.alsoAllow`, provider tool
overrides, or `mcp`. These are rejected by the preflight and the harness still
fails closed if OpenClaw supplies them at runtime.

## Preflight

Run the plugin-owned read-only preflight before starting the Gateway:

```sh
openclaw savana doctor --json
```

The report keeps the stable check id `savana.runtime`. The pinned OpenClaw CLI
does not load external runtime-registered checks into its core
`doctor --lint --only` registry, so this package exposes the same check through
its explicitly activated `savana` operator command.

The check verifies the exact versions, plugin/model/harness selection, no
fallback, tool/MCP denial, disabled OpenClaw memory, bounded transcript
retention, private files, FD 3 broker binding, fixed service origins, matching
receiver certificate/private key, nonzero client SPKI pin, fixed release URL,
the root-owned execd split-routing mode, exact release address/URL, server
SPKI, root/client certificate digests, endpoint binding, credential identity,
and at least one active connector returned by a fresh authenticated Savana
session. Its probe uses `--doctor-config`, so it does not bind or compete with
the production release port. Findings contain only stable check names and
generic messages. Live installation and hardware-WebAuthn evidence remain in
[`docs/openclaw-deployment-acceptance-gate.md`](../../docs/openclaw-deployment-acceptance-gate.md).

## Reset and recovery

OpenClaw reset closes the corresponding native Savana session and discards the
in-memory opaque binding. It never resumes or serializes handles. A normal
failed-no-effect turn can be retried as a new user turn.

If the release journal is sealed, stop new turns and use the Savana operator
reconciliation procedure to determine the actual execd/vault outcome before
clearing it. Never delete or edit `release.cbor`, rotate the port/certificate,
or replay the OpenClaw message as a recovery shortcut.

## Honest privacy boundary

The adapter prevents OpenClaw's model/tool loop from seeing Savana private
values and only returns explicitly released bytes. OpenClaw still receives the
original channel message before Savana, bounded approval/lifecycle state, and
the released final answer; it receives no approval display, approval ID, tool
arguments, or private tool result. Its normal session/transcript storage may
retain the values it does receive. Channel transport, OpenClaw Gateway
security, and transcript retention remain outside the Rust kernel boundary.

OpenClaw upstream is not modified by this integration and no code is pushed to
its repository.
