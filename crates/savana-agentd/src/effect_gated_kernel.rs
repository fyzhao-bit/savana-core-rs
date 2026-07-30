use std::fs::File;
use std::time::Instant;

use savana_kernel_protocol::v2::{Digest32V2, EffectLedgerProjectionBindingV2};

use crate::effect_gate::{
    EffectGateCoordinatorV2, EffectGateErrorV2, EffectGateGuardV2, EffectGateOperationKindV2,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EffectGatedKernelClientErrorV2 {
    InvalidOperation,
    DeadlineExceeded,
    Fenced,
    Unavailable,
}

pub(crate) trait GuardedKernelMutationTransportV2: Send {
    /// The unforgeable crate-private guard parameter makes an operation 29/34
    /// transport call impossible through this interface without a live gate.
    fn dispatch_guarded(
        &mut self,
        operation_tag: u16,
        canonical_request: &[u8],
        guard: &EffectGateGuardV2,
        deadline: Instant,
    ) -> Result<Vec<u8>, EffectGatedKernelClientErrorV2>;
}

/// Process-wide gate binding for agentd's effectful kerneld operations.
///
/// Planner work and operations 29/34 must use this object; it owns the only
/// gate coordinator and keeps the RAII guard alive through the complete
/// request/response exchange.
pub(crate) struct EffectGatedKernelMutationClientV2<T> {
    gate: EffectGateCoordinatorV2,
    transport: T,
}

impl<T> std::fmt::Debug for EffectGatedKernelMutationClientV2<T> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EffectGatedKernelMutationClientV2")
            .finish_non_exhaustive()
    }
}

impl<T: GuardedKernelMutationTransportV2> EffectGatedKernelMutationClientV2<T> {
    pub(crate) fn from_verified_effect_gate(
        transport: T,
        shared_only_effect_gate_descriptor: File,
        read_only_ledger_projection_descriptor: File,
        projection_binding: EffectLedgerProjectionBindingV2,
    ) -> Result<Self, EffectGatedKernelClientErrorV2> {
        let gate = EffectGateCoordinatorV2::from_shared_only_descriptors(
            shared_only_effect_gate_descriptor,
            read_only_ledger_projection_descriptor,
            projection_binding,
        )
        .map_err(map_gate_error)?;
        Ok(Self { gate, transport })
    }

    pub(crate) fn dispatch_effect(
        &mut self,
        operation_tag: u16,
        operation_id: Digest32V2,
        canonical_request: &[u8],
        deadline: Instant,
    ) -> Result<Vec<u8>, EffectGatedKernelClientErrorV2> {
        if !matches!(operation_tag, 29 | 34) || canonical_request.is_empty() {
            return Err(EffectGatedKernelClientErrorV2::InvalidOperation);
        }
        let operation = match operation_tag {
            29 => EffectGateOperationKindV2::ExecutionDispatch,
            34 => EffectGateOperationKindV2::ReleaseDispatch,
            _ => return Err(EffectGatedKernelClientErrorV2::InvalidOperation),
        };
        let guard = self
            .gate
            .acquire(operation, operation_id, deadline)
            .map_err(map_gate_error)?;
        self.transport
            .dispatch_guarded(operation_tag, canonical_request, &guard, deadline)
    }

    pub(crate) fn fence(&self, deadline: Instant) -> Result<(), EffectGatedKernelClientErrorV2> {
        self.gate.fence(deadline).map_err(map_gate_error)
    }
}

const fn map_gate_error(error: EffectGateErrorV2) -> EffectGatedKernelClientErrorV2 {
    match error {
        EffectGateErrorV2::DeadlineExceeded => EffectGatedKernelClientErrorV2::DeadlineExceeded,
        EffectGateErrorV2::Fenced => EffectGatedKernelClientErrorV2::Fenced,
        EffectGateErrorV2::Unavailable => EffectGatedKernelClientErrorV2::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use std::fs::{File, OpenOptions};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use savana_kernel_protocol::v2::Digest32V2;

    use super::{
        EffectGatedKernelClientErrorV2, EffectGatedKernelMutationClientV2,
        GuardedKernelMutationTransportV2,
    };
    use crate::effect_gate::{EffectGateCoordinatorV2, EffectGateGuardV2};

    struct FakeTransport {
        observed: Arc<Mutex<Vec<u16>>>,
    }

    impl GuardedKernelMutationTransportV2 for FakeTransport {
        fn dispatch_guarded(
            &mut self,
            operation_tag: u16,
            canonical_request: &[u8],
            _guard: &EffectGateGuardV2,
            _deadline: Instant,
        ) -> Result<Vec<u8>, EffectGatedKernelClientErrorV2> {
            assert!(!canonical_request.is_empty());
            self.observed.lock().unwrap().push(operation_tag);
            Ok(vec![0x80])
        }
    }

    fn readonly_file() -> (tempfile::TempDir, File) {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("effect-gate");
        File::create(&path).unwrap();
        let file = OpenOptions::new().read(true).open(path).unwrap();
        (directory, file)
    }

    #[test]
    fn only_effect_operations_are_sent_and_always_hold_a_live_guard() {
        let (_directory, descriptor) = readonly_file();
        let observed = Arc::new(Mutex::new(Vec::new()));
        let transport = FakeTransport {
            observed: Arc::clone(&observed),
        };
        let gate = EffectGateCoordinatorV2::from_shared_only_descriptor(descriptor).unwrap();
        let mut client = EffectGatedKernelMutationClientV2 { gate, transport };
        let deadline = Instant::now() + Duration::from_secs(1);

        assert_eq!(
            client
                .dispatch_effect(29, Digest32V2::new([1; 32]), &[0x80], deadline)
                .unwrap(),
            vec![0x80]
        );
        assert_eq!(
            client
                .dispatch_effect(30, Digest32V2::new([2; 32]), &[0x80], deadline)
                .unwrap_err(),
            EffectGatedKernelClientErrorV2::InvalidOperation
        );
        assert_eq!(*observed.lock().unwrap(), vec![29]);

        client.fence(deadline).unwrap();
        assert_eq!(
            client
                .dispatch_effect(34, Digest32V2::new([3; 32]), &[0x80], deadline)
                .unwrap_err(),
            EffectGatedKernelClientErrorV2::Fenced
        );
    }
}
