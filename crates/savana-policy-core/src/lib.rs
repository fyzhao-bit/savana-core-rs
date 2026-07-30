#![forbid(unsafe_code)]
#![doc = r#"
Unsigned policy wire DTOs are not part of the public API:

```compile_fail
use savana_policy_core::PolicyBundleV1;
```

A verified policy does not expose its backing unsigned bundle:

```compile_fail
use savana_policy_core::VerifiedPolicyV1;

fn unsigned_bundle(policy: &VerifiedPolicyV1) {
    let _ = policy.bundle();
}
```

Unsigned release and installation-profile DTOs are also private:

```compile_fail
use savana_policy_core::{KernelInstallationProfileV1, ReleaseManifestV1};
```

A verified release exposes only narrow projections, not either backing DTO:

```compile_fail
use savana_policy_core::VerifiedReleaseIdentity;

fn unsigned_release(identity: &VerifiedReleaseIdentity) {
    let _ = identity.manifest();
    let _ = identity.profile();
}
```

Selected-policy provenance primitives remain internal to the closed binding
check:

```compile_fail
use savana_policy_core::VerifiedPolicyV1;

fn signature_digest(policy: &VerifiedPolicyV1) {
    let _ = policy.signature_digest();
}
```

```compile_fail
use savana_policy_core::VerifiedPolicyV1;

fn signing_public_key(policy: &VerifiedPolicyV1) {
    let _ = policy.signing_public_key();
}
```

```compile_fail
use savana_policy_core::VerifiedPolicyV1;

fn active_release_target(policy: &VerifiedPolicyV1) {
    let _ = policy.active_release_target_id();
}
```

A verified approval envelope exposes only verified projections, not its backing
signed artifact:

```compile_fail
use savana_policy_core::VerifiedApprovalEnvelopeV1;

fn signed_artifact(envelope: &VerifiedApprovalEnvelopeV1) {
    let _ = &envelope.artifact;
}
```

Verified ingress exposes only its authorization role and policy digest. Raw
identity, replay, request, boot, and connection-binding projections remain
engine-internal:

```compile_fail
use savana_policy_core::VerifiedIngressV1;

fn raw_ingress(ingress: &VerifiedIngressV1) {
    let _ = ingress.principal();
    let _ = ingress.request_digest();
    let _ = ingress.nonce();
    let _ = ingress.boot_id();
    let _ = ingress.connection_binding_digest();
}
```

The current-policy capability can only be minted by consuming verified release,
policy, and durable-ledger state:

```compile_fail
use savana_policy_core::{CurrentPolicyCapability, VerifiedPolicyV1};

fn forge(policy: VerifiedPolicyV1) {
    let _ = CurrentPolicyCapability::new(policy);
}
```

```compile_fail
use savana_policy_core::CurrentPolicyCapability;

fn clone_current(current: CurrentPolicyCapability) {
    let _ = current.clone();
}
```

```compile_fail
use savana_policy_core::CurrentPolicyCapability;

fn default_current() {
    let _ = CurrentPolicyCapability::default();
}
```

```compile_fail
use savana_policy_core::{CurrentPolicyCapability, VerifiedPolicyV1};

fn convert(policy: VerifiedPolicyV1) {
    let _: CurrentPolicyCapability = policy.into();
}
```

```compile_fail
use savana_policy_core::CurrentPolicyCapability;

fn raw_fields(current: CurrentPolicyCapability) {
    let CurrentPolicyCapability { store, .. } = current;
    drop(store);
}
```

```compile_fail
use savana_policy_core::CurrentPolicyCapability;

fn backing_policy(current: &CurrentPolicyCapability) {
    let _ = current.backing_policy();
}
```

```compile_fail
use savana_policy_core::{CurrentPolicyCapability, VerifiedPolicyV1};

fn unchecked(policy: VerifiedPolicyV1) {
    let _ = CurrentPolicyCapability::unchecked(policy);
}
```

The pre-capability raw acceptance transition is crate-private:

```compile_fail
use savana_kernel_protocol::{Signature64, UnixMillis};
use savana_policy_core::PolicyStore;

fn old_raw_acceptance(store: &mut PolicyStore) {
    let _ = store.verify_and_accept(
        &[],
        &Signature64::new([0; 64]),
        UnixMillis::new(0),
    );
}
```

Authenticated contexts cannot be forged or cloned from raw fields:

```compile_fail
use savana_policy_core::AuthenticatedCallContext;

fn forge() {
    let _ = AuthenticatedCallContext::new();
}
```

Context issuers are instance-bound and non-cloneable:

```compile_fail
use savana_policy_core::AuthenticatedContextIssuer;

fn clone_issuer(issuer: AuthenticatedContextIssuer) {
    let _ = issuer.clone();
}
```

The engine can only consume a current-policy capability, never a raw verified
policy:

```compile_fail
use std::sync::Arc;
use savana_kernel_protocol::{BootId, StableCode, UnixMillis};
use savana_policy_core::{Clock, PolicyEngine, RandomSource, VerifiedPolicyV1};

struct Dependencies;

impl Clock for Dependencies {
    fn wall_now(&self) -> Result<UnixMillis, StableCode> {
        Ok(UnixMillis::new(1))
    }

    fn monotonic_now_millis(&self) -> Result<u64, StableCode> {
        Ok(1)
    }
}

impl RandomSource for Dependencies {
    fn fill(&self, output: &mut [u8]) -> Result<usize, StableCode> {
        output.fill(1);
        Ok(output.len())
    }
}

fn raw_engine(policy: VerifiedPolicyV1) {
    let clock: Arc<dyn Clock + Send + Sync> = Arc::new(Dependencies);
    let random: Arc<dyn RandomSource + Send + Sync> = Arc::new(Dependencies);
    let _ = PolicyEngine::new(policy, BootId::new([1; 32]), clock, random);
}
```

Raw policy replacement is not part of the engine API:

```compile_fail
use savana_policy_core::{PolicyEngine, VerifiedPolicyV1};

fn raw_replacement(engine: &PolicyEngine, policy: VerifiedPolicyV1) {
    engine.replace_policy(policy);
}
```

Live persistence-fault selection is an engine-internal test seam.  It is not
part of the public API, including when the debug-only `test-support` feature
is enabled:

```compile_fail
use savana_policy_core::LivePersistenceFault;
```

```compile_fail
use savana_policy_core::PolicyEngine;

fn inject() {
    let _ = PolicyEngine::inject_live_persistence_fault_for_test;
}
```

```compile_fail
use savana_policy_core::PolicyStore;

fn inject() {
    let _ = PolicyStore::inject_live_persistence_fault;
}
```

V2 provenance records cannot be forged from public fields or have their
computed security label replaced:

```compile_fail
use savana_policy_core::v2::{ProvenanceRecordV2, SecurityLabelV2};

fn replace_label(record: &mut ProvenanceRecordV2, label: SecurityLabelV2) {
    record.label = label;
}
```

Their domain-separated provenance digest is also immutable:

```compile_fail
use savana_kernel_protocol::v2::Digest32V2;
use savana_policy_core::v2::ProvenanceRecordV2;

fn replace_digest(record: &mut ProvenanceRecordV2) {
    record.provenance_digest = Digest32V2::new([0; 32]);
}
```

Raw V2 source constructors are not part of the external policy-core API:

```compile_fail
use savana_policy_core::v2::ProvenanceRecordV2;

fn forge_kernel_trusted() {
    let _ = ProvenanceRecordV2::policy_constant;
}
```

The raw verified-source label mint is private as well:

```compile_fail
use savana_policy_core::v2::SecurityLabelV2;

fn forge_label() {
    let _ = SecurityLabelV2::from_verified_source;
}
```

V2 registry publisher authority can be inspected only after the deployment
verifier mints it; a caller cannot turn an arbitrary public key into registry
authority:

```compile_fail
use savana_kernel_protocol::v2::{Ed25519KeyIdV2, UnixMillisV2};
use savana_policy_core::v2::VerifiedRegistryPublisherV2;

fn forge_publisher() {
    let _ = VerifiedRegistryPublisherV2::from_manifest(
        Ed25519KeyIdV2::new([1; 32]),
        [2; 32],
        UnixMillisV2::new(1),
        UnixMillisV2::new(2),
    );
}
```

Signed tool descriptor bytes are public input, but the verified descriptor
cannot be assembled from raw fields:

```compile_fail
use savana_kernel_protocol::v2::{Digest32V2, Ed25519KeyIdV2};
use savana_policy_core::v2::{UnsignedToolDescriptorV2, VerifiedToolDescriptorV2};

fn forge_verified(unsigned: UnsignedToolDescriptorV2) {
    let _ = VerifiedToolDescriptorV2 {
        unsigned,
        descriptor_digest: Digest32V2::new([1; 32]),
        publisher_key_id: Ed25519KeyIdV2::new([2; 32]),
    };
}
```

Verified ontology sets cannot be minted from caller-selected members or
digests:

```compile_fail
use savana_kernel_protocol::v2::{Digest32V2, NamespaceIdV2, OntologySetIdV2};
use savana_policy_core::v2::VerifiedOntologySetV2;

fn forge_set() {
    let _ = VerifiedOntologySetV2::new(
        NamespaceIdV2::new(1),
        OntologySetIdV2::new(1),
        Digest32V2::new([1; 32]),
        vec![],
    );
}
```

Handle-free semantic bindings are public read-only records. Their constructor
is reserved for the stored-value, active-registry, projection, and policy
authorization path:

```compile_fail
use savana_policy_core::v2::ToolExecutionSemanticBindingV2;

fn forge_intent_binding() {
    let _ = ToolExecutionSemanticBindingV2::from_verified_authorization;
}
```

Resolved stored bindings cannot be populated with caller-provided aggregate
digests:

```compile_fail
use savana_policy_core::v2::VerifiedStoredBindingsV2;

fn forge_stored_binding() {
    let _ = VerifiedStoredBindingsV2 {
        arguments: vec![],
        argument_digest: todo!(),
        provenance_set_digest: todo!(),
        evidence_digest: todo!(),
        token_set_digest: todo!(),
    };
}
```

The G5 validator registry accepts no callback, script, dynamic library, or
caller-created verified implementation:

```compile_fail
use savana_policy_core::v2::{
    InternalValidatorImplementationKindV2, VerifiedInternalValidatorImplementationV2,
};

fn register_callback(callback: fn() -> bool) {
    let _ = VerifiedInternalValidatorImplementationV2::new(
        InternalValidatorImplementationKindV2::ArgumentBindingIntegrity,
        callback,
    );
}
```
"#]

#[cfg(test)]
extern crate self as savana_policy_core;

#[cfg(test)]
#[path = "../tests/support/mod.rs"]
mod test_support;

#[cfg(all(feature = "test-support", not(debug_assertions)))]
compile_error!("test-support cannot be enabled in a release build");

mod atomic_file;
mod bundle;
mod current_policy;
mod engine;
mod error;
mod ledger;
mod lock_file;
mod provenance;
mod release;
mod runtime;
mod signature;
mod validate;

pub mod v2;

pub use bundle::AuthorityRoleV1;
pub use current_policy::CurrentPolicyCapability;
pub use engine::{
    CommittedPolicyRollover, PolicyEngine, PolicyRolloverDisposition, PolicyRolloverFailure,
    PolicyRolloverGuard,
};
pub use error::PolicyError;
pub use ledger::{PolicyLedgerIdentity, PolicyStateCapability, PolicyStore};
pub use release::{
    InstallationClientRoleV1, InstallationClientV1, InstallationPlatformV1,
    InstallationPublicKeyV1, ReleaseStage, ReleaseTrustRootV1, ReleaseVerifier,
    VerifiedReleaseIdentity,
};
pub use runtime::{AuthenticatedCallContext, AuthenticatedContextIssuer, Clock, RandomSource};
pub use signature::{PolicyTrustRootV1, PolicyVerifier};
pub use validate::{
    PolicyIdentity, VerifiedApprovalEnvelopeV1, VerifiedApprovalReceiptV1, VerifiedAuthorityV1,
    VerifiedIngressV1, VerifiedOntologyEventV1, VerifiedOntologySnapshotV1,
    VerifiedPlannerAttestationV1, VerifiedPolicyV1, VerifiedRegistrySnapshotV1,
    VerifiedValidatorAttestationV1,
};
