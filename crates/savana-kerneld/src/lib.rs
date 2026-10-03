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

Live policy rollover has no public trigger, coordinator, lifecycle control, or
test-support escape hatch:

```compile_fail
use savana_kerneld::PolicyRolloverCoordinator;
```

```compile_fail
use savana_kerneld::DaemonPublicationGuard;
```

```compile_fail
use savana_kerneld::TestLifecycleControl;
```

```compile_fail
use savana_kerneld::test_support::refresh_selected_policy;
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
#[cfg(all(feature = "macos-development-authority", not(debug_assertions)))]
compile_error!("macos-development-authority is forbidden in release builds");
#[cfg(all(feature = "linux-file-backed-integration", not(debug_assertions)))]
compile_error!("linux-file-backed-integration is forbidden in release builds");

mod audit;
#[allow(dead_code)]
mod bootstrap;
mod config;
#[allow(dead_code)] // Consumed by V2 daemon startup before readiness publication.
mod deployment_trust;
mod error;
mod fs_cap;
#[allow(dead_code)]
mod handshake;
mod key_file;
#[cfg(all(feature = "test-support", debug_assertions))]
mod lifecycle_control;
mod ops;
#[cfg_attr(not(feature = "test-support"), allow(dead_code))]
mod panic_report;
#[allow(dead_code)]
mod peer;
#[allow(dead_code)]
mod policy_runtime;
#[cfg_attr(not(feature = "test-support"), allow(dead_code))]
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
#[cfg(target_os = "linux")]
mod tpm_anchor_v3;
mod v04_managed_admin;
#[cfg(unix)]
mod v04_model_workers;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod v2_activation;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod v2_agent_authority;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod v2_agent_durable;
#[allow(dead_code)] // Activated after V2 mutual authentication completes.
mod v2_channel;
#[allow(dead_code)] // Activated after V2 mutual authentication completes.
mod v2_connection;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod v2_connector_authority;
#[cfg(test)]
mod v2_connector_authority_tests;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod v2_core_services;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod v2_data_plane;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod v2_declassification_policy;
#[allow(dead_code)] // Activated by the V2 authenticated dispatch routes.
mod v2_dispatch;
#[allow(dead_code)] // Activated by the verified V2 listener startup path.
mod v2_edge;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod v2_executor_client;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod v2_ingress_authority;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod v2_input_owner;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod v2_kernel_owner;
#[allow(dead_code)] // Activated by the final V2 daemon startup path.
mod v2_listener;
mod v2_managed_resource;
#[allow(dead_code)] // Activated by the V2 startup recovery pass.
mod v2_recovery;
#[allow(dead_code)] // Activated by the V2 authenticated dispatch routes.
mod v2_runtime;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod v2_server;
mod v2_startup;
#[allow(dead_code)] // Activated by the V2 authenticated dispatch routes.
mod v2_state_owner;
mod v2_task_authority;
#[allow(dead_code)] // Activated by the native V2 listener entry point.
mod v2_transport_owner;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod v2_value_owner;

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
    pub enum V2DeclassificationRolloverScenario {
        ValidSuccessor,
        RuleSetRollback,
        WrongManifestPin,
        BadRuleSetSignature,
        ExpiredRuleSet,
        ExpiresBeforePublication,
        IncompleteEndpointRuntime,
        GenerationGap,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct V2DeclassificationRolloverProbe {
        result: Result<(), savana_kernel_protocol::StableCode>,
        old_digest: savana_kernel_protocol::v2::Digest32V2,
        candidate_digest: savana_kernel_protocol::v2::Digest32V2,
        verified_successor_constructed: bool,
        ingress_request_digest: savana_kernel_protocol::v2::Digest32V2,
        agent_request_digest: savana_kernel_protocol::v2::Digest32V2,
        ingress_request_generation: u64,
        agent_request_generation: u64,
        active_generation: u64,
        admission_resumed: bool,
    }

    impl V2DeclassificationRolloverProbe {
        pub(crate) const fn new(
            result: Result<(), savana_kernel_protocol::StableCode>,
            old_digest: savana_kernel_protocol::v2::Digest32V2,
            candidate_digest: savana_kernel_protocol::v2::Digest32V2,
            verified_successor_constructed: bool,
            ingress_request_digest: savana_kernel_protocol::v2::Digest32V2,
            agent_request_digest: savana_kernel_protocol::v2::Digest32V2,
            ingress_request_generation: u64,
            agent_request_generation: u64,
            active_generation: u64,
            admission_resumed: bool,
        ) -> Self {
            Self {
                result,
                old_digest,
                candidate_digest,
                verified_successor_constructed,
                ingress_request_digest,
                agent_request_digest,
                ingress_request_generation,
                agent_request_generation,
                active_generation,
                admission_resumed,
            }
        }

        pub const fn result(self) -> Result<(), savana_kernel_protocol::StableCode> {
            self.result
        }

        pub const fn old_digest(self) -> savana_kernel_protocol::v2::Digest32V2 {
            self.old_digest
        }

        pub const fn candidate_digest(self) -> savana_kernel_protocol::v2::Digest32V2 {
            self.candidate_digest
        }

        pub const fn verified_successor_constructed(self) -> bool {
            self.verified_successor_constructed
        }

        pub const fn ingress_request_digest(self) -> savana_kernel_protocol::v2::Digest32V2 {
            self.ingress_request_digest
        }

        pub const fn agent_request_digest(self) -> savana_kernel_protocol::v2::Digest32V2 {
            self.agent_request_digest
        }

        pub const fn ingress_request_generation(self) -> u64 {
            self.ingress_request_generation
        }

        pub const fn agent_request_generation(self) -> u64 {
            self.agent_request_generation
        }

        pub const fn active_generation(self) -> u64 {
            self.active_generation
        }

        pub const fn admission_resumed(self) -> bool {
            self.admission_resumed
        }
    }

    pub fn probe_v2_declassification_rollover(
        scenario: V2DeclassificationRolloverScenario,
    ) -> V2DeclassificationRolloverProbe {
        crate::v2_startup::probe_declassification_rollover(scenario)
    }

    #[cfg(target_os = "macos")]
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct MacOsV2StartupProbe {
        result: Result<(), savana_kernel_protocol::StableCode>,
        workers_started: usize,
        activation_completed: usize,
    }

    #[cfg(target_os = "macos")]
    impl MacOsV2StartupProbe {
        pub const fn result(self) -> Result<(), savana_kernel_protocol::StableCode> {
            self.result
        }

        pub const fn workers_started(self) -> usize {
            self.workers_started
        }

        pub const fn activation_completed(self) -> usize {
            self.activation_completed
        }
    }

    #[cfg(target_os = "macos")]
    pub fn probe_macos_v2_startup(path: &Path) -> MacOsV2StartupProbe {
        struct ProbeLifecycle {
            workers_started: usize,
            activation_completed: usize,
        }

        impl crate::server::ServerLifecycle for ProbeLifecycle {
            fn workers_started(&mut self) -> Result<(), savana_kernel_protocol::StableCode> {
                self.workers_started += 1;
                Ok(())
            }

            fn activation_completed(&mut self) -> Result<(), savana_kernel_protocol::StableCode> {
                self.activation_completed += 1;
                Ok(())
            }

            fn poll_shutdown(&mut self) -> Result<bool, savana_kernel_protocol::StableCode> {
                Ok(true)
            }
        }

        let mut lifecycle = ProbeLifecycle {
            workers_started: 0,
            activation_completed: 0,
        };
        let result = crate::v2_startup::run(
            path,
            savana_kernel_protocol::v2::BootIdV2::new([0x51; 32]),
            &mut lifecycle,
        );
        MacOsV2StartupProbe {
            result,
            workers_started: lifecycle.workers_started,
            activation_completed: lifecycle.activation_completed,
        }
    }

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

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct V2IngressReleaseEvidence {
        pub protected_value_count: usize,
        pub provenance_root_evidence_count: usize,
        pub vault_segment_count: usize,
    }

    #[allow(clippy::too_many_arguments)]
    pub fn execute_v2_ingress_pipeline_for_release_evidence(
        input_runtime: &savana_input_runtime::InputRuntimeV2,
        vault: &mut savana_vault::DurableVaultServiceV2,
        transfer: savana_ingressd::IngressKernelTransferV2,
        installation_id: savana_kernel_protocol::v2::Digest32V2,
        active_state_manifest_digest: savana_kernel_protocol::v2::Digest32V2,
        producer_identity: savana_kernel_protocol::v2::ProducerIdentityV2,
        durable_task_id: savana_kernel_protocol::v2::DurableTaskIdV2,
        durable_run_id: savana_kernel_protocol::v2::DurableRunIdV2,
        now: savana_kernel_protocol::v2::UnixMillisV2,
        expires_at: savana_kernel_protocol::v2::UnixMillisV2,
    ) -> Result<V2IngressReleaseEvidence, DaemonError> {
        let accepted = crate::v2_runtime::accept_ingress_into_kernel(
            input_runtime,
            vault,
            transfer,
            installation_id,
            active_state_manifest_digest,
            producer_identity,
            durable_task_id,
            durable_run_id,
            savana_policy_core::v2::EffectSetV2::SEND,
            now,
            expires_at,
        )
        .map_err(|_| DaemonError::stable(savana_kernel_protocol::StableCode::KernelUnavailable))?;
        Ok(V2IngressReleaseEvidence {
            protected_value_count: accepted.gated_input().protected_values().len(),
            provenance_root_evidence_count: accepted.provenance().root_evidence().as_slice().len(),
            vault_segment_count: vault.segment_count(),
        })
    }
}

use std::path::Path;
use std::sync::Arc;

use audit::{AuditEvent, AuditSink};
use bootstrap::acquire_run_ownership;
#[cfg(all(feature = "test-support", debug_assertions))]
use bootstrap::BootstrapContext;
#[cfg(all(feature = "test-support", debug_assertions))]
use bootstrap::PreparedRuntime;
use panic_report::PanicHookGuard;
#[cfg(all(feature = "test-support", debug_assertions))]
use runtime_deps::SystemClock;
use runtime_deps::{ProcessSecrets, SystemRandom};
use savana_kernel_protocol::StableCode;
#[cfg(all(feature = "test-support", debug_assertions))]
use savana_policy_core::{Clock, RandomSource};
use signal_control::{SignalController, SignalMaskGuard, SigpipeGuard};

#[cfg(all(feature = "test-support", debug_assertions))]
const TEST_PROCESS_ENTROPY_ENV: &str = "SAVANA_TEST_PROCESS_ENTROPY";
#[cfg(all(feature = "test-support", debug_assertions))]
const TEST_V1_RUNTIME_ENV: &str = "SAVANA_TEST_V1_RUNTIME";
#[cfg(all(feature = "test-support", debug_assertions))]
const TEST_V1_RUNTIME_VALUE: &str = "frozen-regression-v1";

#[cfg(all(feature = "test-support", debug_assertions))]
enum ProcessEntropyStep {
    Fill(u8),
    Error,
    Short,
    Zero,
}

#[cfg(all(feature = "test-support", debug_assertions))]
struct ScriptedProcessRandom {
    steps: std::sync::Mutex<std::collections::VecDeque<ProcessEntropyStep>>,
}

#[cfg(all(feature = "test-support", debug_assertions))]
impl ScriptedProcessRandom {
    fn from_environment_value(value: &std::ffi::OsStr) -> Result<Self, StableCode> {
        use std::os::unix::ffi::OsStrExt;

        let steps = match value.as_bytes() {
            b"fail-boot" => vec![ProcessEntropyStep::Error],
            b"short-boot" => vec![ProcessEntropyStep::Short],
            b"zero-boot" => vec![ProcessEntropyStep::Zero],
            b"fail-audit" => vec![ProcessEntropyStep::Fill(0x11), ProcessEntropyStep::Error],
            b"short-audit" => vec![ProcessEntropyStep::Fill(0x11), ProcessEntropyStep::Short],
            b"zero-audit" => vec![ProcessEntropyStep::Fill(0x11), ProcessEntropyStep::Zero],
            b"fail-engine" => vec![
                ProcessEntropyStep::Fill(0x11),
                ProcessEntropyStep::Fill(0x22),
                ProcessEntropyStep::Error,
            ],
            b"short-engine" => vec![
                ProcessEntropyStep::Fill(0x11),
                ProcessEntropyStep::Fill(0x22),
                ProcessEntropyStep::Short,
            ],
            b"zero-engine" => vec![
                ProcessEntropyStep::Fill(0x11),
                ProcessEntropyStep::Fill(0x22),
                ProcessEntropyStep::Zero,
            ],
            _ => return Err(StableCode::KernelUnavailable),
        };
        Ok(Self {
            steps: std::sync::Mutex::new(steps.into()),
        })
    }
}

#[cfg(all(feature = "test-support", debug_assertions))]
impl RandomSource for ScriptedProcessRandom {
    fn fill(&self, output: &mut [u8]) -> Result<usize, StableCode> {
        let step = self
            .steps
            .lock()
            .map_err(|_| StableCode::KernelUnavailable)?
            .pop_front()
            .ok_or(StableCode::KernelUnavailable)?;
        match step {
            ProcessEntropyStep::Fill(fill) => {
                output.fill(fill);
                Ok(output.len())
            }
            ProcessEntropyStep::Error => Err(StableCode::KernelUnavailable),
            ProcessEntropyStep::Short => {
                output.fill(0x5a);
                Ok(output.len().saturating_sub(1))
            }
            ProcessEntropyStep::Zero => {
                output.fill(0);
                Ok(output.len())
            }
        }
    }
}

#[cfg(all(feature = "test-support", debug_assertions))]
fn select_process_random(
    context: &BootstrapContext,
) -> Result<Arc<dyn RandomSource + Send + Sync>, StableCode> {
    let Some(value) = std::env::var_os(TEST_PROCESS_ENTROPY_ENV) else {
        return Ok(Arc::new(SystemRandom));
    };
    let random = scripted_entropy_for_mapped_root(context.uses_mapped_layout(), &value)?;
    Ok(Arc::new(random))
}

#[cfg(all(feature = "test-support", debug_assertions))]
fn scripted_entropy_for_mapped_root(
    mapped_root_is_verified: bool,
    value: &std::ffi::OsStr,
) -> Result<ScriptedProcessRandom, StableCode> {
    if !mapped_root_is_verified {
        return Err(StableCode::KernelUnavailable);
    }
    ScriptedProcessRandom::from_environment_value(value)
}

#[cfg(all(test, feature = "test-support", debug_assertions))]
mod process_entropy_tests {
    use std::ffi::OsStr;

    use super::*;

    #[test]
    fn entropy_script_requires_a_verified_mapped_root_and_known_value() {
        assert!(matches!(
            scripted_entropy_for_mapped_root(false, OsStr::new("fail-boot")),
            Err(StableCode::KernelUnavailable)
        ));
        assert!(matches!(
            scripted_entropy_for_mapped_root(true, OsStr::new("unknown-script")),
            Err(StableCode::KernelUnavailable)
        ));
        assert!(matches!(
            scripted_entropy_for_mapped_root(true, OsStr::new("")),
            Err(StableCode::KernelUnavailable)
        ));
    }
}

pub fn run(config_path: &Path) -> Result<(), DaemonError> {
    #[cfg(all(feature = "test-support", debug_assertions))]
    if std::env::var_os(TEST_V1_RUNTIME_ENV)
        .as_deref()
        .is_some_and(|value| value == std::ffi::OsStr::new(TEST_V1_RUNTIME_VALUE))
    {
        return run_v1_test_support(config_path);
    }
    run_v2_production(config_path)
}

fn run_v2_production(config_path: &Path) -> Result<(), DaemonError> {
    acquire_run_ownership()?;

    let mask = SignalMaskGuard::block_shutdown().map_err(DaemonError::stable)?;
    let sigpipe = match SigpipeGuard::install() {
        Ok(sigpipe) => sigpipe,
        Err(code) => return finish_before_audit(code, mask, None),
    };
    let secrets = match ProcessSecrets::draw(&SystemRandom) {
        Ok(secrets) => secrets,
        Err(code) => return finish_before_audit(code, mask, Some(sigpipe)),
    };
    let boot_id = savana_kernel_protocol::v2::BootIdV2::new(*secrets.boot_id.as_bytes());
    let (audit, panic_descriptor) = match AuditSink::establish(secrets.audit_secret) {
        Ok(established) => established,
        Err(code) => return finish_before_audit(code, mask, Some(sigpipe)),
    };
    let audit = Arc::new(audit);
    let panic = PanicHookGuard::install(panic_descriptor);
    let mut signals = match SignalController::install(mask, sigpipe) {
        Ok(signals) => signals,
        Err(error) => {
            let (code, mask, sigpipe) = *error;
            return finish_signal_install_failure(code, &audit, panic, mask, sigpipe);
        }
    };

    match v2_startup::run(config_path, boot_id, &mut signals) {
        Ok(()) => finish_runtime(
            Ok(()),
            &audit,
            panic,
            signals,
            #[cfg(all(feature = "test-support", debug_assertions))]
            false,
        ),
        Err(code) => finish_bootstrap_failure(code, &audit, panic, signals),
    }
}

#[cfg(all(feature = "test-support", debug_assertions))]
fn run_v1_test_support(config_path: &Path) -> Result<(), DaemonError> {
    acquire_run_ownership()?;

    let mask = SignalMaskGuard::block_shutdown().map_err(DaemonError::stable)?;
    let sigpipe = match SigpipeGuard::install() {
        Ok(sigpipe) => sigpipe,
        Err(code) => return finish_before_audit(code, mask, None),
    };
    #[cfg(all(feature = "test-support", debug_assertions))]
    let prepared_context = match BootstrapContext::open(config_path) {
        Ok(context) => context,
        Err(error) => {
            let secrets = match ProcessSecrets::draw(&SystemRandom) {
                Ok(secrets) => secrets,
                Err(code) => return finish_before_audit(code, mask, Some(sigpipe)),
            };
            let (audit, panic_descriptor) = match AuditSink::establish(secrets.audit_secret) {
                Ok(established) => established,
                Err(code) => return finish_before_audit(code, mask, Some(sigpipe)),
            };
            let audit = Arc::new(audit);
            let panic = PanicHookGuard::install(panic_descriptor);
            let signals = match SignalController::install(mask, sigpipe) {
                Ok(signals) => signals,
                Err(error) => {
                    let (code, mask, sigpipe) = *error;
                    return finish_signal_install_failure(code, &audit, panic, mask, sigpipe);
                }
            };
            return finish_bootstrap_failure(error.code(), &audit, panic, signals);
        }
    };
    #[cfg(all(feature = "test-support", debug_assertions))]
    let random = match select_process_random(&prepared_context) {
        Ok(random) => random,
        Err(code) => return finish_before_audit(code, mask, Some(sigpipe)),
    };
    #[cfg(not(all(feature = "test-support", debug_assertions)))]
    let random: Arc<dyn RandomSource + Send + Sync> = Arc::new(SystemRandom);
    let secrets = match ProcessSecrets::draw(random.as_ref()) {
        Ok(secrets) => secrets,
        Err(code) => return finish_before_audit(code, mask, Some(sigpipe)),
    };
    let boot_id = secrets.boot_id;
    let (audit, panic_descriptor) = match AuditSink::establish(secrets.audit_secret) {
        Ok(established) => established,
        Err(code) => return finish_before_audit(code, mask, Some(sigpipe)),
    };
    let audit = Arc::new(audit);
    let panic = PanicHookGuard::install(panic_descriptor);
    let mut signals = match SignalController::install(mask, sigpipe) {
        Ok(signals) => signals,
        Err(error) => {
            let (code, mask, sigpipe) = *error;
            return finish_signal_install_failure(code, &audit, panic, mask, sigpipe);
        }
    };

    let clock: Arc<dyn Clock + Send + Sync> = Arc::new(SystemClock::new());
    #[cfg(all(feature = "test-support", debug_assertions))]
    let prepared_result =
        PreparedRuntime::prepare_from_context(prepared_context, boot_id, clock, random);
    #[cfg(not(all(feature = "test-support", debug_assertions)))]
    let prepared_result =
        PreparedRuntime::prepare_with_dependencies(config_path, boot_id, clock, random);
    let prepared = match prepared_result {
        Ok(prepared) => prepared,
        Err(error) => {
            return finish_bootstrap_failure(error.code(), &audit, panic, signals);
        }
    };
    #[cfg(all(feature = "test-support", debug_assertions))]
    let (test_control, controlled_shutdown) = match lifecycle_control::requested() {
        Ok(false) => (None, None),
        Ok(true) => {
            let mut control = match prepared.begin_test_lifecycle_control() {
                Ok(control) => control,
                Err(error) => {
                    return finish_bootstrap_failure(error.code(), &audit, panic, signals);
                }
            };
            let completion = control.graceful_completion_marker();
            if let Err(code) = control.wait_for_continue() {
                return finish_bootstrap_failure(code, &audit, panic, signals);
            }
            (Some(control), Some(completion))
        }
        Err(code) => return finish_bootstrap_failure(code, &audit, panic, signals),
    };
    if panic.publish_release(prepared.release_digest()).is_err() {
        #[cfg(all(feature = "test-support", debug_assertions))]
        if let Some(control) = test_control.as_ref() {
            control.report_pre_activation_failure(StableCode::KernelUnavailable);
        }
        return finish_bootstrap_failure(StableCode::KernelUnavailable, &audit, panic, signals);
    }
    let bound = match prepared.bind(Arc::clone(&audit)) {
        Ok(bound) => bound,
        Err(error) => {
            #[cfg(all(feature = "test-support", debug_assertions))]
            if let Some(control) = test_control.as_ref() {
                control.report_pre_activation_failure(error.code());
            }
            return finish_bootstrap_failure(error.code(), &audit, panic, signals);
        }
    };
    #[cfg(all(feature = "test-support", debug_assertions))]
    let runtime_result = match test_control {
        Some(control) => bound.run_with_test_lifecycle(&mut signals, control),
        None => bound.run(&mut signals),
    };
    #[cfg(not(all(feature = "test-support", debug_assertions)))]
    let runtime_result = bound.run(&mut signals);
    #[cfg(all(feature = "test-support", debug_assertions))]
    let controlled_shutdown = controlled_shutdown
        .as_ref()
        .is_some_and(|marker| marker.load(std::sync::atomic::Ordering::Acquire));
    finish_runtime(
        runtime_result,
        &audit,
        panic,
        signals,
        #[cfg(all(feature = "test-support", debug_assertions))]
        controlled_shutdown,
    )
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
    #[cfg(all(feature = "test-support", debug_assertions))] controlled_shutdown: bool,
) -> Result<(), DaemonError> {
    let mut fatal = runtime_result.err().map(DaemonError::code);
    if signals.final_drain_and_restore().is_err() {
        fatal = Some(StableCode::KernelUnavailable);
    }
    let reason = signals.shutdown_reason();
    if fatal.is_none() && reason.is_none() && !cfg!(all(feature = "test-support", debug_assertions))
    {
        fatal = Some(StableCode::KernelUnavailable);
    }
    let final_audit = match (fatal, reason) {
        (Some(code), _) => audit.emit(AuditEvent::Fatal { code }),
        (None, Some(reason)) => audit.emit(AuditEvent::Stopped { reason }),
        #[cfg(all(feature = "test-support", debug_assertions))]
        (None, None) if controlled_shutdown => Ok(()),
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
