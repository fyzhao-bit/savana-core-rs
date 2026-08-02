# Task 8 report: Add UI-only connector approval control

## Outcome

Implemented the Task 8 connector-registration control and approval boundary without adding Task 9 registry mutation or persistence. A connector proposal can enter kerneld only through a descriptor-only action on an existing authenticated agent browser tab. Agentd records the tab's fixed `Agent8768` origin and current boot, requires either its unconsumed post-authentication authorization or its complete claimed-session state, and applies that gate before session claim or any connector kernel call. Absent, forged, unauthenticated, stale-boot, wrong-origin, and internally inconsistent tabs therefore produce no connector client dispatch. The browser cannot select an origin, construct a kernel-accepted authorization, or submit a raw connector operation.

Kerneld now prepares an opaque, connector-specific, one-use authorization. It binds the exact canonical descriptor bytes and domain-separated digest, current verified connector-registry head, live session commitment, authenticated principal, durable task and run, fixed `Agent8768` origin, authenticated agentd identity and boot, active manifest, deployment generation, issue/expiry times, and a consumed bit. Proposal revalidates every binding, reparses the descriptor against the current user-tier host allowlist, requires the unchanged verified registry head and enabled G7 authority, and refuses replay, expiry, a closed session, descriptor tampering, a stale deployment, or a fabricated handle.

The accepted proposal produces a purpose-4 connector-registration approval envelope and a signed fixed-origin approval-display authentication envelope. Its human display contains the exact tier, display name, full HTTPS URL and TLS identity pin or stdio package digest, connector effects, every tool name/effects/full canonical semantics, and the complete canonical descriptor. The display is bounded and control-character-free, and is released only through a real tag-3 `BuildApprovalDisplay` provenance declassification whose handoff is independently admitted. Approvald supports the distinct connector purpose and settlement signature domain; purpose substitution with tool approval fails.

No connector delta is signed or applied, no registry head advances, and no connector journal, recovery, or executor consumption path was added. Execd explicitly refuses the connector-control operation at its service edge.

## Files changed

- `crates/savana-kernel-protocol/src/v2/kernel_connector.rs`, `kernel_service.rs`, `mod.rs`, `handles.rs`, and `application.rs`
  - Added canonical tags 70/71, bounded request/response codecs, descriptor-only digesting, opaque connector UI authorization handles, and the separate `KernelConnectorControlOperationV2` service branch.
  - Kept connector registration absent from `KernelAgentOperationV2` and updated the exhaustive service/application operation contracts.
- `crates/savana-kernel-protocol/src/v2/signed.rs`, `approval_service.rs`, and `browser_agent.rs`
  - Added approval purpose 4, the connector binding of exact descriptor digest plus previous head, distinct envelope/settlement signature domains, and connector settlement verification.
  - Added the descriptor-only authenticated-tab action and fixed approval-display response; there is no browser-supplied origin or authorization field.
- `crates/savana-kernel-protocol/tests/v2_kernel_connector_wire.rs` and `v2_operation_matrix.rs`
  - Added canonical wire, malformed/noncanonical/oversize, digest-domain, purpose-substitution, and complete operation-matrix coverage.
- `crates/savana-kerneld/src/v2_agent_authority.rs`, `v2_core_services.rs`, and `v2_kernel_owner.rs`
  - Added the ephemeral one-use authorization lifecycle, exact live-session/G7/head/descriptor checks, complete bounded display construction, tag-3 declassification, signed approval envelopes, service routing, and exhaustive handler coverage.
- `crates/savana-agentd/src/browser_authority.rs` and `kernel_client.rs`
  - Added the explicit pre-kernel `Agent8768`/current-boot/authenticated-state tab gate, routed only the admitted action through the separate connector-control transport, consumed the opaque preparation, registered the resulting approval with approvald, and returned only the fixed approval post carrier.
- `crates/savana-approvald/src/lib.rs`, `protocol_service.rs`, and `ui_authority.rs`
  - Added connector approval registration, distinct purpose-4 settlement and recovery verification, and UI-authority handle storage.
- `crates/savana-execd/src/v2_service.rs`
  - Refused connector-control operations at the executor edge; Task 10 remains the later verified-chain consumer.
- `crates/savana-policy-core/src/v2/connector_registry.rs`
  - Exposed the already-verified canonical user host allowlist through a narrow read-only accessor for descriptor revalidation.
- `crates/savana-kerneld/Cargo.toml` and `Cargo.lock`
  - Added the existing workspace Base64 dependency used to render complete canonical semantics without truncation.
- `deploy/frozen-v2-core.files` and `deploy/frozen-v2-core.sha256`
  - Added the new connector protocol module to the frozen boundary and refreshed all 12 changed frozen-core hashes.

## Enforced invariants

- UI origin is not a wire enum. The only browser request is an action authenticated by a live tab capability. Agentd records and rechecks the fixed `Agent8768` origin, current boot, and exact fresh-or-claimed authentication state before any kernel call; kerneld independently fixes the origin to `Agent8768` and requires the authenticated agentd identity, exact agentd kernel-client boot, and session-derived opaque authorization.
- The connector control vocabulary is a separate `KernelConnectorControlOperationV2`. It is not a new `KernelAgentOperationV2` variant, and legacy agent tags remain unchanged.
- A preparation is usable once, only before the earlier of the five-minute control TTL and session expiry, and only for its exact descriptor, session, principal, task, run, origin, caller boot, manifest, generation, and previous registry head.
- Failed descriptor/head/declassification checks do not consume an authorization; a successfully constructed proposal does. A second use is refused as already consumed.
- Both preparation and proposal parse the exact bytes with `ConnectorDescriptorV2::from_canonical_bytes` against the verified registry's current user-tier allowlist. Only `UserRegistered` descriptors not already present in the verified chain are eligible.
- Disabled G7 connector authority (zero key identity/public key or absent credential), a genesis mismatch, stale head, poisoned/unavailable registry, missing tag 3, or an inadmissible provenance handoff all fail closed.
- Approval purpose 4 has independent envelope and settlement signature domains. Its binding is exactly descriptor digest plus previous head, and a connector settlement cannot verify as a tool settlement.
- Human-visible approval data is exact and untruncated: tier/name, complete transport identity, connector effects, every tool's name/effects/canonical descriptor semantics, and complete canonical connector bytes. Invalid UTF-8, control characters, or data exceeding the bounded approval-display type are refused.
- No Task 9 authority exists in this change: there is no connector-delta signing call, registry apply, durable connector journal, replay/recovery, or head mutation.

## TDD and review evidence

### RED/GREEN: separate wire and purpose vocabulary

The connector wire tests were added first and failed to compile because the connector operation type, opaque handle, tags 70/71 codecs, purpose-4 binding, and settlement verifier did not exist. The final protocol suite proves canonical round trips, descriptor digest separation, malformed/noncanonical/oversize refusal, purpose substitution failure, and an exhaustive 44-operation service matrix while the legacy agent operation surface remains closed.

### RED/GREEN: one-use UI authorization and complete display

Kerneld tests were added against unknown sessions, caller-fabricated handles, exact descriptor tampering, replay, zero authority, missing tag 3, invalid UTF-8, control characters, and the required complete display. The initial implementation could not satisfy the tests because there was no connector-specific session authorization, G7 validation, or approval-display provenance path. The final focused tests pass and inspect the verified purpose-4 envelope, previous-head binding, signed UI principal/origins, tag-3 provenance digest, every tool semantic payload, full descriptor bytes, and the consumed replay state.

Post-review lifecycle regressions additionally cover wrong authenticated peer identity and boot, manifest and generation drift, fixed-origin tampering, closed and exactly expired sessions, principal/task/run substitution, equality at the exact five-minute authorization TTL, and a real authority-signed registry delta that advances the verified head. The display matrix covers both the full HTTPS URL/TLS-pin path and the full stdio package-digest path; a canonical 4,096-tool descriptor deterministically exceeds the approval-display bound and is refused instead of truncated.

### RED/GREEN: browser-origin admission

The first independent review classified the absence of an agentd browser-authority origin regression as an Important acceptance blocker. The deterministic test was written first and failed to compile because no load-bearing connector-tab admission gate existed. Agentd now admits a connector action only when the exact tab capability is present, current-boot, fixed to `Agent8768`, and in one of the two valid authenticated states: an unconsumed post-authentication authorization or a fully claimed session. The test uses a downstream-dispatch counter and proves absent, forged, unauthenticated, stale-boot, `Approval8766`, and inconsistent tab states all leave it at zero, while an authenticated `Agent8768` tab reaches the dispatch boundary once.

### RED/GREEN: distinct settlement purpose

Approvald's real hardware-assertion fixture first required a connector settlement purpose unavailable in the legacy approval service. The final test completes the WebAuthn settlement, verifies it under the connector domain, and proves the identical signed settlement fails tool-execution verification.

### Static review follow-up

Strict Clippy found one needless borrow in the new descriptor-only browser encoder. It was corrected, then strict protocol Clippy and the complete protocol suite were rerun successfully.

The expanded head-drift/display fixtures initially exposed two test-construction errors: the synthetic registry delta used kerneld's length-prefixed digest helper instead of the registry's exact raw domain hash, and a bulk descriptor seed wrapped a required projection digest through zero. Both fixture bugs were corrected without relaxing production validation; the resulting signed head advance and 4,096-tool display tests pass.

### Independent security review

The first independent production trace found no Critical or Important production-code defect, but raised the missing browser-origin regression as one Important test-assurance blocker and identified lifecycle/head-drift and stdio/oversize display depth as Minor gaps. All three matrices were added and passed. The final independent re-review reported no Critical, Important, or Minor finding, confirmed the pre-dispatch gate closes the blocker without a production regression, and approved Task 8.

## Verification evidence

Focused and package verification included:

```text
cargo test -p savana-kernel-protocol --all-features --locked
cargo test -p savana-approvald --all-features --locked
cargo test -p savana-execd --all-features --locked
cargo test -p savana-agentd --all-features --locked -- --test-threads=1
cargo test -p savana-kerneld --lib connector_control_ --all-features --locked
cargo test -p savana-kerneld --all-features --locked -- --test-threads=1
cargo test -p savana-agentd -p savana-approvald -p savana-execd -p savana-kerneld --all-features --locked --no-run
```

Results:

- kernel protocol: 31 library tests and every integration group passed, including all 4 connector wire tests;
- approvald: 11 library tests plus all binary/integration groups passed;
- execd: 32 library tests plus all integration groups passed;
- agentd exact post-review native-permission run: 43 library tests plus main and macOS startup passed;
- kerneld post-review connector-focused selection: 9 passed, including 5 Task 8 control/display tests and 4 G7 connector-authority startup tests; the broader non-listener V2 unit selection passed 108 tests before the final test-only matrix expansion;
- kerneld exact native-permission serial run: 269 library tests, CLI, 4 deployment-unit tests, 31 macOS deployment tests, the 11-case attack matrix, 4 fail-stop tests, 4 protocol tests, 19 rollover tests, 6 production-state-machine tests, concurrency/crash/end-to-end/final-mode groups, and 31 documentation tests all passed;
- all touched runtime packages compiled together in test mode.

The final tree was checked with:

```text
cargo check --workspace --all-targets --all-features --locked
cargo clippy -p savana-kernel-protocol --all-targets --all-features --locked -- -D warnings -A clippy::result-large-err
cargo clippy -p savana-agentd -p savana-approvald -p savana-execd -p savana-policy-core --all-targets --all-features --locked -- -D warnings -A clippy::result-large-err
cargo clippy -p savana-kerneld --all-targets --all-features --locked -- -D warnings -A clippy::result-large-err -A clippy::large-enum-variant -A clippy::type-complexity -A clippy::too-many-arguments -A clippy::clone-on-copy
cargo fmt --all -- --check
git diff --check
sh tools/check-frozen-v2-core.sh
sh tools/tests/check-frozen-v2-core.sh tools/check-frozen-v2-core.sh
```

Every command exited zero. The only allowed Clippy categories are the named pre-existing workspace baselines. The first sandboxed agentd/kerneld attempts could not create native Unix sockets and produced permission failures (plus kerneld poison cascades); the required exact suites were rerun outside that sandbox with native socket permissions and passed completely, with kerneld serialized and no concurrent Cargo process.

## Deliberate limitations and later-task boundaries

- Task 8 creates an approval proposal and purpose-4 settlement vocabulary only. Task 9 owns settlement consumption, connector-authority signing, durable append/recovery, idempotent replay, and verified registry-head advance.
- Execd refuses this control operation. Later tasks independently verify and consume the connector chain for execution.
- The opaque preparation state is intentionally ephemeral and boot-local. It is not recovered after kerneld restart.

No push was performed.
