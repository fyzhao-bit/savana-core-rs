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
"#]

mod atomic_file;
mod bundle;
mod error;
mod ledger;
mod lock_file;
mod release;
mod signature;
mod validate;

pub use bundle::AuthorityRoleV1;
pub use error::PolicyError;
pub use ledger::{PolicyLedgerIdentity, PolicyStore};
pub use release::{
    InstallationClientRoleV1, InstallationClientV1, InstallationPlatformV1,
    InstallationPublicKeyV1, ReleaseTrustRootV1, ReleaseVerifier, VerifiedReleaseIdentity,
};
pub use signature::{PolicyTrustRootV1, PolicyVerifier};
pub use validate::{PolicyIdentity, VerifiedAuthorityV1, VerifiedPolicyV1};
