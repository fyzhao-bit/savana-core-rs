use crate::validate::PolicyIdentity;

#[allow(dead_code)]
pub(crate) trait PolicyBound {
    fn verified_policy_identity(&self) -> PolicyIdentity;

    fn is_current_for(&self, current: PolicyIdentity) -> bool {
        self.verified_policy_identity() == current
    }
}
