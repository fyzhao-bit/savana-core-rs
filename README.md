# savana-core-rs

Savana's Rust security-kernel workspace. Every crate is built with
`#![forbid(unsafe_code)]`.

The current kernel boundary is split into:

- `savana-kernel-protocol`: bounded framing, canonical CBOR, frozen V1 wire
  types, stable error codes, and hard resource ceilings;
- `savana-policy-core`: signed policy/release verification, anti-rollback
  state, descriptor-anchored release identity, and narrow verified
  projections;
- `savana-kerneld`: fail-closed bootstrap, daemon-key ownership, authenticated
  Unix-domain transport, bounded workers, audit/panic/signal handling, and the
  public one-shot daemon entry point; and
- `libsavana-ner`: the existing Rust NER implementation used to detect and mask
  sensitive spans before text leaves the device.

Protocol `1.0` is currently a pre-release slice. The daemon exposes mutual
authentication followed by one `Health` request per connection. Policy
decisions, vault operations, approvals, and NER operations are intentionally
not wire-visible yet.

The daemon's public Rust API is deliberately narrow:

```rust
pub fn run(config_path: &Path) -> Result<(), DaemonError>;
```

`DaemonError` is opaque and exposes only its stable code. Handshake state,
peer credentials, signing keys, unsigned configuration DTOs, socket controls,
and authenticated connection capabilities remain internal.

The byte-level contract is documented in
[`docs/protocol-v1.md`](docs/protocol-v1.md). Cross-language fixtures and
deterministic regeneration commands are in
[`vectors/kerneld/README.md`](vectors/kerneld/README.md).

Run the kernel gates with Rust 1.82:

```bash
cargo +1.82.0 fmt --all -- --check
cargo +1.82.0 clippy -p savana-kernel-protocol \
  -p savana-policy-core -p savana-kerneld \
  --all-targets --locked -- -D warnings
cargo +1.82.0 test -p savana-kernel-protocol \
  -p savana-policy-core -p savana-kerneld \
  --all-targets --locked
```

CI runs those packages on both Linux and macOS while retaining the legacy NER
job. The production Unix-socket tests require a host that permits filesystem
Unix-domain socket binding.

ONNX model assets are not vendored. `libsavana-ner` resolves them at runtime
from the local directory named by `SAVANA_NER_ASSETS`.
