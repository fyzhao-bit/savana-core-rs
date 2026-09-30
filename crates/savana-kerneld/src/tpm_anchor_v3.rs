//! Consumers share the authenticated TPM broker protocol, never its credentials.
use crate::v2_agent_durable::{
    KernelAgentAuthorityRollbackAnchorV2, KernelAgentAuthorityStateHeadV2,
};
use savana_kernel_protocol::v2::Digest32V2;
use savana_platform_identity::{
    LinuxTpmAuthorityClientV3, TpmEnrollmentV3, TpmStateHeadV3, TpmStoreV3,
};
use savana_policy_core::v2::{
    G4Error, RollbackProtectedStateAnchorV2, RollbackProtectedStateHeadV2,
};
use savana_vault::{VaultErrorV2, VaultRollbackAnchorV2, VaultStateHeadV2};
use std::sync::Mutex;

pub(crate) struct TpmAnchorV3 {
    client: Mutex<LinuxTpmAuthorityClientV3>,
    store: TpmStoreV3,
}
impl TpmAnchorV3 {
    pub(crate) fn open(
        enrollment: TpmEnrollmentV3,
        store: TpmStoreV3,
        installation: Digest32V2,
        store_id: Digest32V2,
    ) -> Result<Self, ()> {
        let binding = enrollment.store_binding(store);
        if store == TpmStoreV3::Deployment
            || binding.installation_id() != *installation.as_bytes()
            || binding.store_id() != *store_id.as_bytes()
        {
            return Err(());
        }
        let mut client = LinuxTpmAuthorityClientV3::new(enrollment).map_err(|_| ())?;
        client.current_head(store).map_err(|_| ())?; // no deferred discovery/fallback
        Ok(Self {
            client: Mutex::new(client),
            store,
        })
    }
    fn read(&self) -> Result<TpmStateHeadV3, ()> {
        self.client
            .lock()
            .map_err(|_| ())?
            .current_head(self.store)
            .map_err(|_| ())
    }
    fn advance(&mut self, expected: (u64, Digest32V2), next: (u64, Digest32V2)) -> Result<(), ()> {
        let expected = TpmStateHeadV3::new(expected.0, *expected.1.as_bytes()).map_err(|_| ())?;
        let next = TpmStateHeadV3::new(next.0, *next.1.as_bytes()).map_err(|_| ())?;
        self.client
            .get_mut()
            .map_err(|_| ())?
            .compare_and_advance(self.store, expected, next)
            .map_err(|_| ())
    }
}
impl RollbackProtectedStateAnchorV2 for TpmAnchorV3 {
    fn current_head(&self) -> Result<RollbackProtectedStateHeadV2, G4Error> {
        let h = self.read().map_err(|_| G4Error::DurableStateRollback)?;
        RollbackProtectedStateHeadV2::new(h.sequence(), Digest32V2::new(h.digest()))
    }
    fn compare_and_advance(
        &mut self,
        expected: RollbackProtectedStateHeadV2,
        next: RollbackProtectedStateHeadV2,
    ) -> Result<(), G4Error> {
        self.advance(
            (expected.sequence(), expected.state_digest()),
            (next.sequence(), next.state_digest()),
        )
        .map_err(|_| G4Error::DurableStateRollback)
    }
}
impl VaultRollbackAnchorV2 for TpmAnchorV3 {
    fn current_head(&self) -> Result<VaultStateHeadV2, VaultErrorV2> {
        let h = self.read().map_err(|_| VaultErrorV2::RollbackDetected)?;
        VaultStateHeadV2::new(h.sequence(), Digest32V2::new(h.digest()))
    }
    fn compare_and_advance(
        &mut self,
        expected: VaultStateHeadV2,
        next: VaultStateHeadV2,
    ) -> Result<(), VaultErrorV2> {
        self.advance(
            (expected.sequence(), expected.state_digest()),
            (next.sequence(), next.state_digest()),
        )
        .map_err(|_| VaultErrorV2::CommitUncertain)
    }
}
impl KernelAgentAuthorityRollbackAnchorV2 for TpmAnchorV3 {
    fn current_head(&self) -> Result<KernelAgentAuthorityStateHeadV2, ()> {
        let h = self.read()?;
        KernelAgentAuthorityStateHeadV2::new(h.sequence(), Digest32V2::new(h.digest()))
    }
    fn compare_and_advance(
        &mut self,
        expected: KernelAgentAuthorityStateHeadV2,
        next: KernelAgentAuthorityStateHeadV2,
    ) -> Result<(), ()> {
        self.advance(
            (expected.sequence(), expected.digest()),
            (next.sequence(), next.digest()),
        )
    }
}
