use savana_kernel_protocol::StableCode;

/// What the V2 kernel server reports to its process owner: worker start,
/// activation, and the shutdown and rollover requests it polls for.
pub(crate) trait ServerLifecycle {
    fn workers_started(&mut self) -> Result<(), StableCode>;

    fn activation_completed(&mut self) -> Result<(), StableCode> {
        Ok(())
    }

    fn poll_shutdown(&mut self) -> Result<bool, StableCode>;

    fn take_v2_rollover_request(&mut self) -> Result<bool, StableCode> {
        Ok(false)
    }
}
