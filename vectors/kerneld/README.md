# Kernel protocol V1 golden vectors

These files freeze the current pre-release V1 encodings for cross-language
clients:

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| `client-hello-v1.cbor` | 76 | `0e441513e7ffe707c34576841bfe265dec625f2a45ad0cb2bed3f7ffd8125059` |
| `server-hello-v1.cbor` | 406 | `d8218d95a92a67d688c2b78bee1321332f6d8b5e9be114537adfd20d2d0c9ec4` |
| `policy-flow-v1.cbor` | 3,121 | `96077e5b1808a488dd62408858be20b807cae3f1979f53d576dba5a7fb878ac6` |
| `policy-bundle-v1.cbor` | 899 | `6a63e3bded3897bc74fa36825ba6cf019bf79806af8c61902b90ad5b2d9e0cbd` |
| `policy-bundle-v1.sig` | 64 | `99a565b4d266a071bb4691e5e4c555504fded6a2881c5c457ce410334ec7fc67` |
| `release-manifest-v1.cbor` | 1,132 | `6116e7cda7a6d568e815c92b22202e3bee84c30c7ca1222a27ed125f4c92db4f` |
| `release-manifest-v1.sig` | 64 | `55d19f2f854f3312cc33a040c787eff0fd7096d51d2957573543f0b9d633b94f` |

## Test-only identities

The generators contain deterministic fixture seeds and no production
key-loading path. Production bootstrap trust roots must explicitly differ from
these identities.

| Fixture | Raw Ed25519 public key |
| --- | --- |
| Policy signing key (`policy-root`) | `2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12` |
| Release signing key (`release-root`) | `c050c5637a44fa8629fff3cccce2300cb362a63d99d95fc54145266f4332445a` |
| Installation daemon key (`daemon-key`) | `af06a3e3291714e4f356c19c9b15cd1951ec6e6662aa77be07547f289383341d` |
| Installation client key (`jarvis-key`) | `2df04125f0015afb47ce853aef8772094ff9498c14cb1b9e12973c2927da0fa6` |

`server-hello-v1.cbor` contains a valid daemon signature over
`SAVANA_DAEMON_HELLO_V1\0 || canonical_cbor(transcript)`. The policy and
release `.sig` files are valid detached signatures for the corresponding CBOR
files and documented public keys.

`policy-flow-v1.cbor` remains an array of 12 byte strings, each containing one
complete client or server wire message. Its approval display commitment uses
`SAVANA_APPROVAL_DISPLAY_V1\0`. Ontology snapshots and events are signed
startup/state artifacts rather than tags `10..19`, so they are frozen by the
protocol and signature conformance tests instead of being inserted as non-wire
items into this operation corpus.

## Regenerate and compare

Run from the repository root with Rust 1.82:

```bash
vector_stage="$(mktemp -d)"
mkdir "$vector_stage/wire" "$vector_stage/signed" "$vector_stage/candidate"
rustup run 1.82.0 cargo run --locked -p savana-kernel-protocol \
  --example generate_wire_vectors -- --output "$vector_stage/wire"
rustup run 1.82.0 cargo run --locked -p savana-policy-core \
  --example generate_signed_vectors -- --output "$vector_stage/signed"

install -m 0644 vectors/kerneld/README.md \
  "$vector_stage/candidate/README.md"
install -m 0644 "$vector_stage/wire/client-hello-v1.cbor" \
  "$vector_stage/candidate/client-hello-v1.cbor"
install -m 0644 "$vector_stage/wire/server-hello-v1.cbor" \
  "$vector_stage/candidate/server-hello-v1.cbor"
install -m 0644 "$vector_stage/wire/policy-flow-v1.cbor" \
  "$vector_stage/candidate/policy-flow-v1.cbor"
install -m 0644 "$vector_stage/signed/policy-bundle-v1.cbor" \
  "$vector_stage/candidate/policy-bundle-v1.cbor"
install -m 0644 "$vector_stage/signed/policy-bundle-v1.sig" \
  "$vector_stage/candidate/policy-bundle-v1.sig"
install -m 0644 "$vector_stage/signed/release-manifest-v1.cbor" \
  "$vector_stage/candidate/release-manifest-v1.cbor"
install -m 0644 "$vector_stage/signed/release-manifest-v1.sig" \
  "$vector_stage/candidate/release-manifest-v1.sig"

diff -ru vectors/kerneld "$vector_stage/candidate"
```

Each generator must receive its own pre-existing empty staging directory; it
does not create the output directory. Without `--overwrite`, any directory
entry causes exit status 64 before a vector is written. With `--overwrite`,
every existing entry must be one of the eight documented names and a regular
non-symlink file; each generator replaces only its own exact target names using
atomic entry replacement, without modifying other hard links to a previous
target. The candidate merge above names every source and destination
explicitly, so neither generator writes into a directory already populated by
the other.

Both generators pin the validated output directory with a directory descriptor;
all enumeration, temporary creation, and rename operations remain relative to
that descriptor. Trailing separators and `.` components are removed before the
final-component no-follow check; `..` components are rejected.
Temporary names contain 128 bits from the operating system random source, and
the still-open temporary descriptor is checked against the directory entry
before and after rename for exact identity, mode, link count, length, and
contents. The generators sync the installed entry and directory, then recheck
every entry they installed before returning success. Without `--overwrite`, the
final rename also uses no-replace semantics so a concurrently created target is
preserved.

Atomicity is per directory entry, not across all three or four outputs. A
nonzero exit can therefore leave earlier complete entries installed; discard
that staging or candidate directory and regenerate it from scratch. Error paths
also deliberately leave any still-linked random temporary entry in place:
automatic pathname cleanup would introduce another check/unlink race.

The capability and final checks do not make a shared writable directory
immutable. Use a caller-owned staging directory that no untrusted concurrent
process can modify; a writer with the same effective UID can always change an
entry after the generator's last check. If that isolation cannot be guaranteed,
discard the directory instead of accepting it as release evidence.

After reviewing the diff, bytes, and hashes, repeat only the seven generated
vector `install -m 0644` commands above (omit the README copy), changing each
destination prefix from `"$vector_stage/candidate/"` to `vectors/kerneld/`.
Do not merge a staging directory recursively.

Review bytes and hashes before accepting a change:

```bash
xxd -g1 vectors/kerneld/client-hello-v1.cbor
xxd -g1 vectors/kerneld/server-hello-v1.cbor
xxd -g1 vectors/kerneld/policy-flow-v1.cbor
xxd -g1 vectors/kerneld/policy-bundle-v1.cbor
xxd -g1 vectors/kerneld/policy-bundle-v1.sig
xxd -g1 vectors/kerneld/release-manifest-v1.cbor
xxd -g1 vectors/kerneld/release-manifest-v1.sig
shasum -a 256 vectors/kerneld/*
```

Any intentional byte change requires a matching schema/version review,
`docs/protocol-v1.md` update, regenerated vectors, and cross-language client
review in the same change.
