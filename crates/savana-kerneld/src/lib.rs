#![forbid(unsafe_code)]
#![doc = r#"
Audit, panic, and signal ownership are daemon-internal:

```compile_fail
use savana_kerneld::AuditSink;
```

```compile_fail
use savana_kerneld::PanicHookGuard;
```

```compile_fail
use savana_kerneld::SignalController;
```

Declassification-rule rollover has no public trigger or coordinator:

```compile_fail
use savana_kerneld::PolicyRolloverCoordinator;
```

```compile_fail
use savana_kerneld::V2GenerationRuntime;
```
"#]

#[cfg(all(feature = "test-support", not(debug_assertions)))]
compile_error!("test-support cannot be enabled in a release build");
#[cfg(all(feature = "macos-development-authority", not(debug_assertions)))]
compile_error!("macos-development-authority is forbidden in release builds");
#[cfg(all(feature = "linux-file-backed-integration", not(debug_assertions)))]
compile_error!("linux-file-backed-integration is forbidden in release builds");

mod audit;
mod bootstrap;
mod deployment_trust;
mod error;
mod panic_report;
mod policy_runtime;
mod runtime_deps;
mod server;
mod signal_control;
#[cfg(all(target_os = "linux", not(feature = "linux-file-backed-integration")))]
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
mod v2_channel;
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
mod v2_dispatch;
mod v2_edge;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod v2_executor_client;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod v2_ingress_authority;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod v2_input_owner;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod v2_kernel_owner;
mod v2_listener;
mod v2_managed_resource;
mod v2_runtime;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod v2_server;
mod v2_startup;
mod v2_state_owner;
mod v2_task_authority;
mod v2_transport_owner;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod v2_value_owner;

pub use error::DaemonError;

#[cfg(feature = "test-support")]
#[doc(hidden)]
pub mod test_support {
    #[cfg(target_os = "macos")]
    use std::path::Path;

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
use panic_report::PanicHookGuard;
use runtime_deps::{draw_nonzero_32, SystemRandom};
use savana_kernel_protocol::StableCode;
use signal_control::{SignalController, SignalMaskGuard, SigpipeGuard};

pub fn run(config_path: &Path) -> Result<(), DaemonError> {
    acquire_run_ownership()?;

    let mask = SignalMaskGuard::block_shutdown().map_err(DaemonError::stable)?;
    let sigpipe = match SigpipeGuard::install() {
        Ok(sigpipe) => sigpipe,
        Err(code) => return finish_before_audit(code, mask, None),
    };
    let boot_id = match draw_nonzero_32(&SystemRandom) {
        Ok(boot) => savana_kernel_protocol::v2::BootIdV2::new(boot),
        Err(code) => return finish_before_audit(code, mask, Some(sigpipe)),
    };
    let (audit, panic_descriptor) = match AuditSink::establish() {
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
        Ok(()) => finish_runtime(Ok(()), &audit, panic, signals),
        Err(code) => finish_bootstrap_failure(code, &audit, panic, signals),
    }
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
