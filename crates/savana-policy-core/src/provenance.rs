use crate::validate::PolicyIdentity;
use savana_kernel_protocol::StableCode;

use crate::PolicyError;

#[allow(dead_code)]
pub(crate) trait PolicyBound {
    fn verified_policy_identity(&self) -> PolicyIdentity;

    fn is_current_for(&self, current: PolicyIdentity) -> bool {
        self.verified_policy_identity() == current
    }
}

pub(crate) fn require_current_policy(
    artifact: &impl PolicyBound,
    current: PolicyIdentity,
) -> Result<(), PolicyError> {
    if !artifact.is_current_for(current) {
        return Err(PolicyError::stable(StableCode::AttestationBindingMismatch));
    }
    Ok(())
}
