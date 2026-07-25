#![forbid(unsafe_code)]
#![doc = r#"
The unsigned lock DTO is not part of the public API:

```compile_fail
use savana_kerneld::KernelLockV1;
```

The daemon signing identity exposes neither its seed nor a generic signer:

```compile_fail
use savana_kerneld::DaemonSigningIdentity;

fn seed(identity: &DaemonSigningIdentity) {
    let _ = identity.seed();
}
```

```compile_fail
use savana_kerneld::DaemonSigningIdentity;

fn arbitrary_signature(identity: &DaemonSigningIdentity) {
    let _ = identity.sign(b"caller-selected-domain");
}
```
"#]

mod config;
mod error;
mod identity;
mod key_file;

pub use config::DaemonConfig;
pub use error::DaemonError;
pub use key_file::{load_daemon_signing_key, DaemonSigningIdentity};
