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
"#]

mod atomic_file;
mod bundle;
mod error;
mod ledger;
mod lock_file;
mod signature;
mod validate;

pub use bundle::AuthorityRoleV1;
pub use error::PolicyError;
pub use ledger::{PolicyLedgerIdentity, PolicyStore};
pub use signature::{PolicyTrustRootV1, PolicyVerifier};
pub use validate::{PolicyIdentity, VerifiedAuthorityV1, VerifiedPolicyV1};
