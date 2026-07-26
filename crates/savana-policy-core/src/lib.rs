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
mod error;
mod ledger;
mod lock_file;
mod provenance;
mod release;
mod signature;
mod validate;

pub use bundle::AuthorityRoleV1;
pub use current_policy::CurrentPolicyCapability;
pub use error::PolicyError;
pub use ledger::{PolicyLedgerIdentity, PolicyStateCapability, PolicyStore};
pub use release::{
    InstallationClientRoleV1, InstallationClientV1, InstallationPlatformV1,
    InstallationPublicKeyV1, ReleaseStage, ReleaseTrustRootV1, ReleaseVerifier,
    VerifiedReleaseIdentity,
};
pub use signature::{PolicyTrustRootV1, PolicyVerifier};
pub use validate::{
    PolicyIdentity, VerifiedApprovalEnvelopeV1, VerifiedApprovalReceiptV1, VerifiedAuthorityV1,
    VerifiedIngressV1, VerifiedOntologyEventV1, VerifiedOntologySnapshotV1,
    VerifiedPlannerAttestationV1, VerifiedPolicyV1, VerifiedRegistrySnapshotV1,
    VerifiedValidatorAttestationV1,
};
