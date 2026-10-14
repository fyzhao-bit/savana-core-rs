# v0.4 model worker: native configuration, Unix mTLS, Python callback

2026-09-24. Implemented and locally tested communication path; **not a completed
AgentDojo protected pipeline or a live deployment acceptance record**.

## Implemented path

```text
manifest-verified kerneld bootstrap
  -> bounded, pinned worker registry (no network at construction)
owner clock -> signed delivery slot -> current root/session/provenance/G3 checks
  -> durable delivery reservation -> frozen ModelView bytes
  -> Unix socket -> end-to-end mTLS -> Python worker
  -> explicit model-profile callback -> proposal/advice (no tool execution)
  -> canonical reply bound to the original job/view
  -> Rust reply validation -> durable settlement/activation
  -> existing G4/G5/G6/G7 path, NOT an automatic execution grant
```

The new worker implements `FusedModelTransportV04`; the existing release code
remains responsible for G3 and the public schedule. The native startup installs
workers from `fused_model_workers` in the manifest-verified bootstrap. The
default empty list remains disabled. There is no Agent RPC, environment override
or model-supplied URL for installing/rebinding a worker.

Files:

- `crates/savana-agentd/src/fused_model_transport.rs`: production Unix/TLS client.
- `crates/savana-kerneld/src/v04_model_workers.rs`: bounded config/credential loader.
- `crates/savana-kerneld/src/v2_startup.rs`: verified startup and cold-reload binding.
- `crates/savana-core-py/python/savana/fused_worker.py`: Python TLS endpoint/codec.
- `crates/savana-core-py/python/savana/fused_deepseek.py`: explicit provider callback.

## Configuration and identity

`fused_model_workers` is an optional array (maximum 8 entries). Each entry has
exactly these fields; unknown fields and duplicate recipient identities fail:

| Field | Meaning |
|---|---|
| `host` | Lowercase certificate DNS name, not a DNS lookup instruction |
| `socket` | Absolute local Unix socket pathname, at most 100 bytes, no parent components |
| `server_spki_sha256` | 32-byte array pinning the model endpoint's TLS public key |
| `root_certificate_der` | Deployment-approved CA certificate bytes, at most 16 KiB |
| `client_certificate_der` | Client certificate bytes, at most 16 KiB |
| `private_key_credential` | Protected systemd credential name beginning `fused-model-`, never a pathname |

The client PKCS#8 DER key is read from the existing protected kerneld credential
directory with its existing identity/permission checks. It is not embedded in
bootstrap JSON or passed through Python/Agent arguments. A signed bootstrap
change still needs a newly verified deployment manifest; editing JSON alone
does not authorize a deployment. New credentials must be provisioned through
the deployment workflow; the code does not generate/install them silently.

`fused_model_recipient_v04(host, spki)` returns:

```text
SHA256("SAVANA_FUSED_MTLS_RECIPIENT_V04\0"
       || u32_be(host_utf8_length) || host_utf8 || spki_sha256
       || "/savana.fused.v04/exchange")
```

Signed planning profiles and G3 reader sets must explicitly approve this digest.
Registering a worker does not create such approval. Identity denotes the pinned
endpoint, not an attested model-weight revision; model-profile routing behind
that endpoint is the trusted operator's responsibility.

The normalized entire worker configuration is fingerprinted. A policy reload
with a changed fingerprint is refused before publishing the successor: worker
changes require a verified cold restart. No silent retention of old routing
under changed config, and no runtime model-selected endpoint changes.

## Transport contract

- The kernel opens only one AF_UNIX connection, without DNS/TCP or fallback.
  A separately deployed local tunnel may forward TLS bytes to a remote endpoint;
  TLS must terminate at the configured model worker, not at a plaintext proxy.
- Existing mTLS credentials verify CA/hostname and require HTTP/1.1 ALPN. The
  server SPKI pin is checked **before any HTTP header or view byte is sent**.
- The Python endpoint additionally requires an exact client certificate SHA-256
  pin after the TLS client-certificate check and before reading the application.
- POST path is fixed. Body is one canonical definite-length CBOR byte string
  containing the original canonical JSON `ModelView`.
- Response is one canonical CBOR byte string containing canonical `PlanProposal`
  or `ReviewAdvice` JSON. Python computes the native domain-separated commitment
  from the **original view bytes**, not a JSON reordering or rewritten view.
- Existing maximum 5-second exchange deadline and 16-KiB reply limit remain.
  Every OS read/write uses the remaining monotonic budget, including TLS IO.
  The worker does not change the public delivery schedule to wait for a model.
- Redirect, compression, chunked body, cookies, oversized reply, extra bytes,
  noncanonical CBOR and unclean TLS EOF fail closed. No automatic retries.
- Transport failure is not a safe task result. The existing durable reservation
  is not refunded or reissued by this adapter.

## Python operator APIs (not LLM tools)

```python
from savana.fused_worker import server_context, serve_connection
from savana.fused_deepseek import DeepSeekModel

# Certificates and the accepted Unix socket come from operator-managed setup.
context = server_context(
    certificate=server_certificate_pem,
    private_key=server_private_key_pem,
    client_ca=kernel_client_ca_pem,
)
model = DeepSeekModel(api_key_in_memory, profiles={1: "deepseek-flash"})
try:
    serve_connection(
        accepted_unix_socket,
        context=context,
        client_certificate_sha256=kernel_client_cert_sha256_bytes,
        propose=model,
    )
finally:
    model.close()
```

This example consumes already provisioned objects; it is not a registration,
authorization, listener installer or real API invocation performed by this change.
An alternate callback takes `(ModelJob, absolute_monotonic_deadline)` and returns
`{"choice": ...}` for planner or `{"templates": [...], "questions": [...]}` for
advisor. Python only checks syntax and binds job/view; Rust checks authority,
membership, dependencies, frozen prefix and any eventual effects.

The DeepSeek adapter sends only the approved view (with public UTF-8 bytes decoded
for comprehension) and a fixed protocol prompt. It exposes no tools, local/private
stores, task answers or arbitrary provider destinations. It calls a fixed HTTPS
endpoint with a registered model profile, temperature 0, thinking disabled,
JSON-object output, maximum 512 tokens and explicit request/call budgets.
Credentials are supplied in local process memory, never auto-discovered or logged.
Redirects, wrong model name, tool calls, malformed JSON and incomplete replies
close the callback without retries or synthetic results. This does not attest an
immutable DeepSeek model version. No paid call was made in these tests.

Python callbacks must enforce their deadline. DNS/runtime stalls or a deliberately
non-cooperating callback can outlive the Python worker's local deadline; Rust
independently stops waiting and rejects a late reply. A remote model taking more
than the permitted slot is Unavailable, not a reason to weaken the schedule.

## Verified here and remaining work

- Linux production kerneld offline compilation in an existing ARM64 container.
- Six Unix mTLS tests on Linux, including real Rust -> Python interoperability
  checked against native `ModelView::commitment` and `PlanProposal` serialization.
- 49 host-side fused/configuration regressions (G3 scheduler, activation,
  private actions, approvals, recovery and new worker config checks).
- With `test-support` enabled, the broader fused selection passed 85 tests;
  one opt-in integration test remained ignored. This is not native deployment
  acceptance, and the two Rust selections overlap rather than adding coverage counts.
- Eight Python codec/TLS tests and four mocked DeepSeek transport tests.
- Full Python experiment regression: 108 tests passed without skips (18.747 s),
  with `SAVANA_COMPONENT_DRIVER` pointing at the existing local Rust component
  driver. This includes, rather than adds to, the 12 Python tests above.
- No live AWS deployment, new enrollment, public model call, or official protected
  AgentDojo episode. Repository test certificates were used only in tests.

The independent communication tests do not constitute a single full native
multi-service production run. The new worker is optional and remains inactive in
existing deployments until signed configuration, credentials and endpoint are
provisioned. The general task/compiler integration, dynamic authorized observation
and final publication, and official AgentDojo tool path were separate unfinished
items at this communication checkpoint. The subsequent
[finite compiler and dynamic-observation implementation](task-compilation-and-observation-v04.md)
adds signed task compilation and bounded result projections through G3; final
publication and official task/tool adaptation remain unfinished. No fallback to
the baseline or synthetic mailbox fixture was added.
