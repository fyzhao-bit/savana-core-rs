#![forbid(unsafe_code)]
#![doc = r#"
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

#[cfg(all(feature = "test-support", not(debug_assertions)))]
compile_error!("test-support cannot be enabled in a release build");

#[cfg(all(feature = "macos-development-authority", not(debug_assertions)))]
compile_error!("macos-development-authority cannot be enabled in a release build");

mod atomic_file;
mod error;
mod lock_file;
mod runtime;

#[cfg(all(target_os = "macos", feature = "macos-development-authority"))]
mod macos_development_startup;

pub mod v2;

#[cfg(all(target_os = "macos", feature = "macos-development-authority"))]
pub use macos_development_startup::load_verified_macos_development_startup_v2;

pub use error::PolicyError;
pub use runtime::{Clock, RandomSource};
