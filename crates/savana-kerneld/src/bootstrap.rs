use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::sync::Arc;

use savana_kernel_protocol::StableCode;

use crate::policy_runtime::PolicyRolloverCoordinator;
use crate::DaemonError;

static RUN_OWNED: AtomicBool = AtomicBool::new(false);

pub(crate) fn acquire_run_ownership() -> Result<(), DaemonError> {
    RUN_OWNED
        .compare_exchange(false, true, AtomicOrdering::AcqRel, AtomicOrdering::Acquire)
        .map(|_| ())
        .map_err(|_| DaemonError::stable(StableCode::KernelUnavailable))
}

/// Builds the single coordinator used to publish verified V2 deployment
/// successors. Keeping construction here prevents startup paths from growing
/// an independent rules-only rollover surface.
pub(crate) fn v2_policy_rollover_coordinator(
    runtime: Arc<crate::policy_runtime::V2GenerationRuntime>,
) -> Arc<PolicyRolloverCoordinator> {
    Arc::new(PolicyRolloverCoordinator::new_v2(runtime))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_global_run_ownership_is_never_reset_after_acquisition() {
        acquire_run_ownership().unwrap();
        assert_eq!(
            acquire_run_ownership().unwrap_err().code(),
            StableCode::KernelUnavailable
        );
    }
}
