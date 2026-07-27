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

Linux peer PID is deliberately absent from the credential projection:

```compile_fail
use savana_kerneld::PeerIdentity;

fn peer_pid(peer: &PeerIdentity) {
    let _ = peer.pid();
}
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

The authenticated Unix transport and all of its resource controls remain
crate-private:

```compile_fail
use savana_kerneld::KernelServer;
```

```compile_fail
use savana_kerneld::ServerLimits;
```

```compile_fail
use savana_kerneld::SocketConfig;
```

```compile_fail
use savana_kerneld::BoundListener;
```

```compile_fail
use savana_kerneld::Shutdown;
```

```compile_fail
use savana_kerneld::Clock;
```

```compile_fail
use savana_kerneld::admit;
```

Bootstrap, audit, panic, and signal ownership are also daemon-internal:

```compile_fail
use savana_kerneld::PreparedRuntime;
```

```compile_fail
use savana_kerneld::AuditSink;
```

```compile_fail
use savana_kerneld::PanicHookGuard;
```

```compile_fail
use savana_kerneld::SignalController;
```

External callers cannot substitute an arbitrary socket path:

```compile_fail
use savana_kerneld::SocketConfig;

fn substitute_path() {
    let _ = SocketConfig::for_test(
        "/tmp/attacker.sock".into(),
        1,
        2,
        3,
    );
}
```
"#]

#[cfg(all(feature = "test-support", not(debug_assertions)))]
compile_error!("test-support cannot be enabled in a release build");

mod audit;
#[allow(dead_code)]
mod bootstrap;
mod config;
mod error;
mod fs_cap;
#[allow(dead_code)]
mod handshake;
mod key_file;
mod ops;
mod panic_report;
#[allow(dead_code)]
mod peer;
#[allow(dead_code)]
mod policy_runtime;
mod runtime_deps;
mod selected_policy;
#[allow(dead_code)]
mod server;
mod signal_control;
#[allow(dead_code)]
mod socket;
#[cfg(test)]
mod startup_identity_tests;
#[allow(dead_code)]
mod state;

pub(crate) use config::DaemonConfig;
pub use error::DaemonError;
pub(crate) use key_file::DaemonSigningIdentity;

#[cfg(feature = "test-support")]
#[doc(hidden)]
pub mod test_support {
    use std::path::Path;
    use std::sync::Arc;

    use savana_kernel_protocol::BootId;
    use savana_policy_core::{Clock, PolicyIdentity, RandomSource};

    use crate::bootstrap::PreparedRuntime;
    use crate::DaemonError;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct RuntimeIdentities {
        pub engine_boot_id: BootId,
        pub handshake_boot_id: BootId,
        pub engine_policy_identity: PolicyIdentity,
        pub handshake_policy_identity: PolicyIdentity,
    }

    pub fn prepare_with_dependencies(
        config_path: &Path,
        boot_id: BootId,
        clock: Arc<dyn Clock + Send + Sync>,
        random: Arc<dyn RandomSource + Send + Sync>,
    ) -> Result<RuntimeIdentities, DaemonError> {
        let prepared =
            PreparedRuntime::prepare_with_test_dependencies(config_path, boot_id, clock, random)?;
        let (engine_boot_id, handshake_boot_id, engine_policy_identity, handshake_policy_identity) =
            prepared.test_identities()?;
        Ok(RuntimeIdentities {
            engine_boot_id,
            handshake_boot_id,
            engine_policy_identity,
            handshake_policy_identity,
        })
    }
}

use std::path::Path;
use std::sync::Arc;

use audit::{AuditEvent, AuditSink};
use bootstrap::{acquire_run_ownership, PreparedRuntime};
use panic_report::PanicHookGuard;
use savana_kernel_protocol::StableCode;
use signal_control::{SignalController, SignalMaskGuard, SigpipeGuard};

pub fn run(config_path: &Path) -> Result<(), DaemonError> {
    acquire_run_ownership()?;

    let mask = SignalMaskGuard::block_shutdown().map_err(DaemonError::stable)?;
    let sigpipe = match SigpipeGuard::install() {
        Ok(sigpipe) => sigpipe,
        Err(code) => return finish_before_audit(code, mask, None),
    };
    let (audit, panic_descriptor) = match AuditSink::establish() {
        Ok(established) => established,
        Err(code) => return finish_before_audit(code, mask, Some(sigpipe)),
    };
    let audit = Arc::new(audit);
    let panic = PanicHookGuard::install(panic_descriptor);
    let mut signals = match SignalController::install(mask, sigpipe) {
        Ok(signals) => signals,
        Err((code, mask, sigpipe)) => {
            return finish_signal_install_failure(code, &audit, panic, mask, sigpipe);
        }
    };

    let prepared = match PreparedRuntime::prepare(config_path) {
        Ok(prepared) => prepared,
        Err(error) => {
            return finish_bootstrap_failure(error.code(), &audit, panic, signals);
        }
    };
    if panic.publish_release(prepared.release_digest()).is_err() {
        return finish_bootstrap_failure(StableCode::KernelUnavailable, &audit, panic, signals);
    }
    let bound = match prepared.bind(Arc::clone(&audit)) {
        Ok(bound) => bound,
        Err(error) => {
            return finish_bootstrap_failure(error.code(), &audit, panic, signals);
        }
    };
    let runtime_result = bound.run(&mut signals);
    finish_runtime(runtime_result, &audit, panic, signals)
}

fn finish_before_audit(
    code: StableCode,
    mut mask: SignalMaskGuard,
    mut sigpipe: Option<SigpipeGuard>,
) -> Result<(), DaemonError> {
    let mut final_code = code;
    if mask.restore().is_err() {
        final_code = StableCode::KernelUnavailable;
    }
    if sigpipe
        .as_mut()
        .is_some_and(|guard| guard.unregister().is_err())
    {
        final_code = StableCode::KernelUnavailable;
    }
    Err(DaemonError::stable(final_code))
}

fn finish_signal_install_failure(
    code: StableCode,
    audit: &AuditSink,
    panic: PanicHookGuard,
    mut mask: SignalMaskGuard,
    mut sigpipe: SigpipeGuard,
) -> Result<(), DaemonError> {
    let mut final_code = code;
    if mask.restore().is_err() {
        final_code = StableCode::KernelUnavailable;
    }
    if audit
        .emit(AuditEvent::BootstrapFailed { code: final_code })
        .is_err()
    {
        final_code = StableCode::KernelUnavailable;
    }
    panic.restore();
    if sigpipe.unregister().is_err() {
        final_code = StableCode::KernelUnavailable;
    }
    Err(DaemonError::stable(final_code))
}

fn finish_bootstrap_failure(
    code: StableCode,
    audit: &AuditSink,
    panic: PanicHookGuard,
    mut signals: SignalController,
) -> Result<(), DaemonError> {
    let mut final_code = code;
    if signals.final_drain_and_restore().is_err() {
        final_code = StableCode::KernelUnavailable;
    }
    if audit
        .emit(AuditEvent::BootstrapFailed { code: final_code })
        .is_err()
    {
        final_code = StableCode::KernelUnavailable;
    }
    panic.restore();
    if signals.unregister().is_err() {
        final_code = StableCode::KernelUnavailable;
    }
    Err(DaemonError::stable(final_code))
}

fn finish_runtime(
    runtime_result: Result<(), DaemonError>,
    audit: &AuditSink,
    panic: PanicHookGuard,
    mut signals: SignalController,
) -> Result<(), DaemonError> {
    let mut fatal = runtime_result.err().map(DaemonError::code);
    if signals.final_drain_and_restore().is_err() {
        fatal = Some(StableCode::KernelUnavailable);
    }
    let reason = signals.shutdown_reason();
    if fatal.is_none() && reason.is_none() {
        fatal = Some(StableCode::KernelUnavailable);
    }
    let final_audit = match (fatal, reason) {
        (Some(code), _) => audit.emit(AuditEvent::Fatal { code }),
        (None, Some(reason)) => audit.emit(AuditEvent::Stopped { reason }),
        (None, None) => Err(StableCode::KernelUnavailable),
    };
    if final_audit.is_err() {
        fatal = Some(StableCode::KernelUnavailable);
    }
    panic.restore();
    if signals.unregister().is_err() {
        fatal = Some(StableCode::KernelUnavailable);
    }
    match fatal {
        Some(code) => Err(DaemonError::stable(code)),
        None => Ok(()),
    }
}
