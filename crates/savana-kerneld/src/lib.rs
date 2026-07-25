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

Handshake state, peer credentials, pending state, and connection capabilities
are daemon-internal:

```compile_fail
use savana_kerneld::HandshakeService;
```

```compile_fail
use savana_kerneld::PendingHandshake;
```

```compile_fail
use savana_kerneld::PeerIdentity;
```

```compile_fail
use savana_kerneld::ConnectionContext;
```

Pending and authenticated connection state cannot be cloned:

```compile_fail
use savana_kerneld::PendingHandshake;

fn clone_pending(pending: &PendingHandshake) {
    let _ = pending.clone();
}
```

```compile_fail
use savana_kerneld::ConnectionContext;

fn clone_context(context: &ConnectionContext) {
    let _ = context.clone();
}
```

External callers cannot manufacture a server identity with a chosen boot ID:

```compile_fail
use savana_kernel_protocol::{BootId, ProtocolVersion};
use savana_kerneld::{DaemonConfig, DaemonSigningIdentity};

fn forge(
    config: &DaemonConfig,
    signing: &DaemonSigningIdentity,
    boot_id: BootId,
    protocol: ProtocolVersion,
) {
    let _ = config.server_identity(signing, boot_id, protocol);
}
```

There is no public generic handshake-transcript encoder; the daemon's actual
typed encoder remains internal:

```compile_fail
use savana_kerneld::canonical_transcript;
```

Connection capabilities cannot be read or constructed:

```compile_fail
use savana_kerneld::ConnectionContext;

fn capability(context: &ConnectionContext) {
    let _ = context.capability();
}
```

Configured clients do not gain a public lookup helper:

```compile_fail
use savana_kerneld::resolve_client;
```

The replay cache cannot be imported or enumerated:

```compile_fail
use savana_kerneld::ReplayState;
```
"#]

mod config;
mod error;
// Task 6 connects this crate-private state machine to the bounded UDS worker.
#[allow(dead_code)]
mod handshake;
mod identity;
mod key_file;
// Task 6 makes the replay state reachable through the connection worker.
#[allow(dead_code)]
mod state;

pub use config::DaemonConfig;
pub use error::DaemonError;
pub use key_file::{load_daemon_signing_key, DaemonSigningIdentity};
