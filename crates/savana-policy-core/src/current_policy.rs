use savana_kernel_protocol::Digest32;

use crate::{PolicyLedgerIdentity, PolicyStore, VerifiedPolicyV1, VerifiedReleaseIdentity};

#[allow(dead_code)]
pub struct CurrentPolicyCapability {
    pub(crate) store: PolicyStore,
    pub(crate) policy: VerifiedPolicyV1,
    pub(crate) ledger_identity: PolicyLedgerIdentity,
    pub(crate) release: VerifiedReleaseIdentity,
    pub(crate) resource_profile_digest: Digest32,
}

#[allow(dead_code)]
pub(crate) struct AcceptedCurrentPolicy {
    pub(crate) store: PolicyStore,
    pub(crate) policy: VerifiedPolicyV1,
    pub(crate) ledger_identity: PolicyLedgerIdentity,
    pub(crate) release: VerifiedReleaseIdentity,
    pub(crate) resource_profile_digest: Digest32,
}

impl CurrentPolicyCapability {
    pub(crate) fn into_accepted(self) -> AcceptedCurrentPolicy {
        let Self {
            store,
            policy,
            ledger_identity,
            release,
            resource_profile_digest,
        } = self;
        AcceptedCurrentPolicy {
            store,
            policy,
            ledger_identity,
            release,
            resource_profile_digest,
        }
    }
}

impl std::fmt::Debug for CurrentPolicyCapability {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("CurrentPolicyCapability(<current>)")
    }
}
