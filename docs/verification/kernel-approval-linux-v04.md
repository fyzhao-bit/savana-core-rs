# Private kernel approval: Linux startup wiring

This is service startup wiring, not consumer workflow or hardware acceptance.
Google Cloud/DeepSeek remain disabled placeholders. No existing deployment is
modified by adding these files to the repository.

## Provisioning contract

Both bootstraps are immutable, root-owned inputs whose hashes are bound by the
signed deployment manifest. Changes require the normal verified release and
deployment process, not an unverified runtime option or environment override.

Kerneld's optional `kernel_approval` block has exactly these fields:

```json
{
  "client_key_id": "REPLACE_WITH_DERIVED_KERNEL_APPROVAL_KEY_ID",
  "server_key_id": "REPLACE_WITH_DERIVED_APPROVAL_SERVER_KEY_ID",
  "server_public_key_path": "/etc/savana/keys/approval-server-v2.pub"
}
```

Approvald's corresponding block has exactly these fields:

```json
{
  "client_key_id": "REPLACE_WITH_SAME_KERNEL_APPROVAL_KEY_ID",
  "client_public_key_path": "/etc/savana/keys/kernel-approval-v04.pub",
  "listener_gid": 901
}
```

`901` is illustrative; it must equal the actual Kerneld primary GID in the
verified service lock. Public keys are raw 32-byte Ed25519 keys in root-owned,
single-link files with mode `0444`. IDs are derived from the actual keys. The
Kerneld private seed is available only through the fixed systemd credential
`kernel-approval-v04.seed`, 32 bytes, root-owned mode `0400` in the service
credential directory. It must not reuse another service/authority/storage key.
Approvald receives only that client's public key. Its existing server handshake
key authenticates the server, with the independent KernelApproval role in the
authenticated transcript; its user-decision settlement key stays separate.

Install these opt-in units through the verified deployment builder:

- `savana-approvald-kernel-v04.socket` as a socket unit;
- `savana-approvald-kernel-v04.conf` as
  `savana-approvald.service.d/kernel-approval-v04.conf`;
- `savana-kerneld-approval-v04.conf` as
  `savana-kerneld.service.d/kernel-approval-v04.conf`.

Also install `deploy/tmpfiles/savana-kernel-approval-v04.conf` under
`/usr/lib/tmpfiles.d/`. It gives the role directory owner `savana-approval`, group
`savana-kernel`, mode `0710` before socket activation. Merely setting SocketUser
and SocketGroup does not set the owner of automatically created parent
directories; DirectoryMode alone can otherwise leave Kerneld unable to traverse
the path. See the [systemd socket documentation](https://github.com/systemd/systemd/blob/main/man/systemd.socket.xml).

The socket path is compiled, not configurable:
`/run/savana/approvald/kerneld/approvald.sock`. Its name is
`savana-kernel-approval`, owner `savana-approval`, group `savana-kernel`, mode
`0660`. The daemon verifies inherited descriptor count/names, listening socket,
path, owner and group. The authenticated native peer must match the Kerneld
service lock, including executable measurement. No Agent/Ingress group or
credential is added to Kerneld.

The client is constructed after startup verification and installed in the
private policy runtime before the owner begins serving. It uses the current
kernel boot ID and self-peer binding. A malformed enabled block, unavailable
credential, key-ID mismatch, role-key reuse, root GID or unexpected descriptor
fails startup. An unconfigured client with a stray private credential is also
rejected. With neither configuration nor credential, the legacy deployment
shape is unchanged and fused approvals remain pending. macOS rejects the new
configuration: it does not silently route to a development socket.

## Runtime boundary

The existing private action driver sends exact archived pairs and polls signed
decisions. G6 remains responsible for authorization; G7 remains responsible for
dispatch. Roles survive approval state reopen and no challenge is regenerated.
The transport is tied to its deployment generation and Approvald boot. Changing
those bindings does not fall back to old credentials; this addition does not
implement transparent live rekeying of private workflows.

The returned display transfer still needs a trusted, authenticated consumer
delivery route. The [private handoff receiver](private-approval-ui-v04.md) now
accepts it only on the Approval origin and requires hardware authentication,
but does not issue or discover handoffs. This implementation does not publish it in Agent status, expose pending
private actions to a planner, or create a public approval queue. Consumer intake,
authenticated session recovery and exclusive publication remain separate work.

Systemd encrypted credentials remain an **integration** adapter, not a
non-exportable TPM/HSM or rollback-anchor implementation. The existing release
build gate (`MissingPlatformAuthority`) remains intact. Do not claim production
hardware security or full product readiness from successful compilation/tests.

See [fused host boundaries](fused-host-v04.md) and
[bootstrap deployment requirements](../../deploy/config/README.md).
