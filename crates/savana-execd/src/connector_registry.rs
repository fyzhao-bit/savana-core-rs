use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, RwLock, RwLockReadGuard};

use savana_kernel_protocol::v2::{
    derive_ed25519_key_id_v2, ConnectorRegistrySyncModeV2, ConnectorRegistrySyncRequestV2,
    ConnectorRegistrySyncResponseV2, ConnectorRegistrySyncScopeV2, ConnectorRegistrySyncStatusV2,
    Digest32V2, Ed25519KeyIdV2, FixedBytes32V2,
};
use savana_policy_core::v2::{
    connector_host_allowlist_digest_v2, descriptor_digest_v2, BoundedConnectorHostV2,
    ConnectorDescriptorV2, ConnectorRegistryStateV2, DurableConnectorRegistryStoreV2,
    DurableStateNamespaceV2, RollbackProtectedStateAnchorV2,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ExecdConnectorRegistryErrorV2 {
    #[error("connector registry deployment scope does not match authenticated execd state")]
    DeploymentMismatch,
    #[error("connector registry canonical chain verification failed")]
    Verification,
    #[error("connector registry durable state is unavailable")]
    DurableState,
    #[error("connector registry owner is poisoned")]
    Poisoned,
    #[error("dispatch connector registry head is stale or divergent")]
    HeadMismatch,
    #[error("dispatch does not resolve to exactly one active connector descriptor")]
    ConnectorInactive,
}

#[derive(Debug, Clone)]
pub struct ExecdConnectorRegistryTrustV2 {
    installation_id: Digest32V2,
    scope: ConnectorRegistrySyncScopeV2,
    genesis: ConnectorRegistryStateV2,
}

impl ExecdConnectorRegistryTrustV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn from_authenticated_deployment(
        installation_id: Digest32V2,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
        genesis_head_digest: Digest32V2,
        authority_key_id: Ed25519KeyIdV2,
        authority_public_key: [u8; 32],
        user_host_allowlist: Vec<BoundedConnectorHostV2>,
        deployment_shipped_connectors: Vec<ConnectorDescriptorV2>,
    ) -> Result<Self, ExecdConnectorRegistryErrorV2> {
        let key_id_is_zero = authority_key_id.as_bytes() == &[0; 32];
        let public_key_is_zero = authority_public_key == [0; 32];
        if key_id_is_zero != public_key_is_zero
            || (!public_key_is_zero
                && derive_ed25519_key_id_v2(authority_public_key) != authority_key_id)
        {
            return Err(ExecdConnectorRegistryErrorV2::DeploymentMismatch);
        }
        let allowlist_digest = connector_host_allowlist_digest_v2(&user_host_allowlist)
            .map_err(|_| ExecdConnectorRegistryErrorV2::DeploymentMismatch)?;
        let genesis = ConnectorRegistryStateV2::from_verified_genesis(
            genesis_head_digest,
            authority_public_key,
            user_host_allowlist,
            deployment_shipped_connectors,
        )
        .map_err(|_| ExecdConnectorRegistryErrorV2::DeploymentMismatch)?;
        let scope = ConnectorRegistrySyncScopeV2::new(
            installation_id,
            active_state_manifest_digest,
            deployment_generation,
            genesis_head_digest,
            authority_key_id,
            FixedBytes32V2::new(authority_public_key),
            allowlist_digest,
        )
        .map_err(|_| ExecdConnectorRegistryErrorV2::DeploymentMismatch)?;
        Ok(Self {
            installation_id,
            scope,
            genesis,
        })
    }

    pub const fn installation_id(&self) -> Digest32V2 {
        self.installation_id
    }

    pub const fn scope(&self) -> ConnectorRegistrySyncScopeV2 {
        self.scope
    }

    pub const fn genesis(&self) -> &ConnectorRegistryStateV2 {
        &self.genesis
    }
}

/// Execd's independently verified, durable registry owner. Sync publication
/// takes the write side; a dispatch guard holds the read side through the last
/// pre-effect boundary and the complete provider attempt.
pub struct ExecdConnectorRegistryV2 {
    trust: ExecdConnectorRegistryTrustV2,
    state: RwLock<ConnectorRegistryStateV2>,
    store: Mutex<DurableConnectorRegistryStoreV2>,
    poisoned: AtomicBool,
}

impl std::fmt::Debug for ExecdConnectorRegistryV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExecdConnectorRegistryV2")
            .field(
                "deployment_generation",
                &self.trust.scope.deployment_generation(),
            )
            .field("poisoned", &self.poisoned.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}

impl ExecdConnectorRegistryV2 {
    pub fn open(
        path: &Path,
        master_encryption_key: [u8; 32],
        namespace: DurableStateNamespaceV2,
        rollback_anchor: Box<dyn RollbackProtectedStateAnchorV2>,
        trust: ExecdConnectorRegistryTrustV2,
    ) -> Result<Self, ExecdConnectorRegistryErrorV2> {
        if namespace.installation_id() != trust.installation_id {
            return Err(ExecdConnectorRegistryErrorV2::DeploymentMismatch);
        }
        let store = DurableConnectorRegistryStoreV2::open(
            path,
            master_encryption_key,
            namespace,
            rollback_anchor,
            trust.genesis.clone(),
        )
        .map_err(|_| ExecdConnectorRegistryErrorV2::DurableState)?;
        if !store
            .authority_state()
            .map_err(|_| ExecdConnectorRegistryErrorV2::DurableState)?
            .is_empty()
        {
            return Err(ExecdConnectorRegistryErrorV2::DeploymentMismatch);
        }
        let state = store
            .snapshot()
            .map_err(|_| ExecdConnectorRegistryErrorV2::DurableState)?;
        Ok(Self {
            trust,
            state: RwLock::new(state),
            store: Mutex::new(store),
            poisoned: AtomicBool::new(false),
        })
    }

    pub const fn authenticated_scope(&self) -> ConnectorRegistrySyncScopeV2 {
        self.trust.scope
    }

    pub fn synchronize(
        &self,
        request: &ConnectorRegistrySyncRequestV2,
    ) -> Result<ConnectorRegistrySyncResponseV2, ExecdConnectorRegistryErrorV2> {
        self.ensure_usable()?;
        if request.scope() != &self.trust.scope {
            return Err(ExecdConnectorRegistryErrorV2::DeploymentMismatch);
        }
        let mut state = self.state.write().map_err(|_| {
            self.poisoned.store(true, Ordering::Release);
            ExecdConnectorRegistryErrorV2::Poisoned
        })?;
        self.ensure_usable()?;
        match request.mode() {
            ConnectorRegistrySyncModeV2::Probe => {
                let status = if self.trust.scope.authority_enabled() {
                    ConnectorRegistrySyncStatusV2::Behind
                } else if state.sequence() == 0
                    && state.head_digest() == self.trust.genesis.head_digest()
                {
                    ConnectorRegistrySyncStatusV2::DisabledGenesisOnly
                } else {
                    self.poisoned.store(true, Ordering::Release);
                    return Err(ExecdConnectorRegistryErrorV2::Poisoned);
                };
                sync_response(status, &state)
            }
            ConnectorRegistrySyncModeV2::ApplyPage(page) => {
                if !self.trust.scope.authority_enabled() {
                    return Err(ExecdConnectorRegistryErrorV2::DeploymentMismatch);
                }
                if page.base_sequence() != state.sequence()
                    || page.base_head_digest() != state.head_digest()
                {
                    let status = if state.sequence() == page.source_final_sequence()
                        && state.head_digest() == page.source_final_head_digest()
                    {
                        ConnectorRegistrySyncStatusV2::Converged
                    } else if page.base_sequence() > state.sequence() {
                        ConnectorRegistrySyncStatusV2::Behind
                    } else {
                        ConnectorRegistrySyncStatusV2::Diverged
                    };
                    return sync_response(status, &state);
                }

                let mut staged = state.clone();
                for delta in page.deltas() {
                    staged
                        .replay_canonical_delta(delta.as_bytes())
                        .map_err(|_| ExecdConnectorRegistryErrorV2::Verification)?;
                }
                if staged.sequence() != page.page_final_sequence()
                    || staged.head_digest() != page.page_final_head_digest()
                {
                    return Err(ExecdConnectorRegistryErrorV2::Verification);
                }
                let mut store = self.store.lock().map_err(|_| {
                    self.poisoned.store(true, Ordering::Release);
                    ExecdConnectorRegistryErrorV2::Poisoned
                })?;
                let durable_before = store
                    .snapshot()
                    .map_err(|_| ExecdConnectorRegistryErrorV2::DurableState)?;
                if durable_before.sequence() != state.sequence()
                    || durable_before.head_digest() != state.head_digest()
                {
                    self.poisoned.store(true, Ordering::Release);
                    return Err(ExecdConnectorRegistryErrorV2::Poisoned);
                }
                let revision = store.revision().map_err(|_| {
                    self.poisoned.store(true, Ordering::Release);
                    ExecdConnectorRegistryErrorV2::DurableState
                })?;
                let deltas = page
                    .deltas()
                    .iter()
                    .map(|delta| delta.as_bytes())
                    .collect::<Vec<_>>();
                let expected_head = state.head_digest();
                let durable = store
                    .replay_canonical_deltas_atomically(expected_head, revision, &deltas)
                    .map_err(|_| {
                        self.poisoned.store(true, Ordering::Release);
                        ExecdConnectorRegistryErrorV2::DurableState
                    })?;
                if durable.sequence() != staged.sequence()
                    || durable.head_digest() != staged.head_digest()
                {
                    self.poisoned.store(true, Ordering::Release);
                    return Err(ExecdConnectorRegistryErrorV2::Poisoned);
                }
                *state = durable;
                let status = if state.sequence() == page.source_final_sequence()
                    && state.head_digest() == page.source_final_head_digest()
                {
                    ConnectorRegistrySyncStatusV2::Converged
                } else {
                    ConnectorRegistrySyncStatusV2::Behind
                };
                sync_response(status, &state)
            }
        }
    }

    pub fn admit_head(
        &self,
        expected_head: Digest32V2,
    ) -> Result<ExecdConnectorRegistryGuardV2<'_>, ExecdConnectorRegistryErrorV2> {
        self.ensure_usable()?;
        let guard = self.state.read().map_err(|_| {
            self.poisoned.store(true, Ordering::Release);
            ExecdConnectorRegistryErrorV2::Poisoned
        })?;
        self.ensure_usable()?;
        if guard.head_digest() != expected_head {
            return Err(ExecdConnectorRegistryErrorV2::HeadMismatch);
        }
        Ok(ExecdConnectorRegistryGuardV2 { guard })
    }

    pub fn current_head_digest(&self) -> Result<Digest32V2, ExecdConnectorRegistryErrorV2> {
        self.ensure_usable()?;
        let guard = self.state.read().map_err(|_| {
            self.poisoned.store(true, Ordering::Release);
            ExecdConnectorRegistryErrorV2::Poisoned
        })?;
        current_head_after_lock(&self.poisoned, &guard)
    }

    #[cfg(test)]
    pub(crate) fn poison_for_test(&self) {
        self.poisoned.store(true, Ordering::Release);
    }

    fn ensure_usable(&self) -> Result<(), ExecdConnectorRegistryErrorV2> {
        if self.poisoned.load(Ordering::Acquire) {
            Err(ExecdConnectorRegistryErrorV2::Poisoned)
        } else {
            Ok(())
        }
    }
}

fn current_head_after_lock(
    poisoned: &AtomicBool,
    state: &ConnectorRegistryStateV2,
) -> Result<Digest32V2, ExecdConnectorRegistryErrorV2> {
    if poisoned.load(Ordering::Acquire) {
        Err(ExecdConnectorRegistryErrorV2::Poisoned)
    } else {
        Ok(state.head_digest())
    }
}

pub struct ExecdConnectorRegistryGuardV2<'owner> {
    guard: RwLockReadGuard<'owner, ConnectorRegistryStateV2>,
}

impl std::fmt::Debug for ExecdConnectorRegistryGuardV2<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ExecdConnectorRegistryGuardV2")
            .field("sequence", &self.guard.sequence())
            .field("head", &self.guard.head_digest())
            .finish_non_exhaustive()
    }
}

impl ExecdConnectorRegistryGuardV2<'_> {
    pub fn head_digest(&self) -> Digest32V2 {
        self.guard.head_digest()
    }

    pub fn sequence(&self) -> u64 {
        self.guard.sequence()
    }

    pub fn active_host_allowlist(&self) -> &[BoundedConnectorHostV2] {
        self.guard.user_host_allowlist()
    }

    pub fn resolve_active_tool_connector(
        &self,
        connector_id: Digest32V2,
        tool_descriptor_digest: Digest32V2,
    ) -> Result<ConnectorDescriptorV2, ExecdConnectorRegistryErrorV2> {
        let connector = self
            .guard
            .active_connector(connector_id)
            .ok_or(ExecdConnectorRegistryErrorV2::ConnectorInactive)?;
        let matches = connector
            .tool_descriptors()
            .iter()
            .filter(|descriptor| {
                descriptor_digest_v2(descriptor).ok() == Some(tool_descriptor_digest)
            })
            .count();
        if matches != 1 {
            return Err(ExecdConnectorRegistryErrorV2::ConnectorInactive);
        }
        Ok(connector.clone())
    }

    pub fn contains_registered_connector(&self, connector_id: Digest32V2) -> bool {
        self.guard.contains_registered_connector(connector_id)
    }
}

fn sync_response(
    status: ConnectorRegistrySyncStatusV2,
    state: &ConnectorRegistryStateV2,
) -> Result<ConnectorRegistrySyncResponseV2, ExecdConnectorRegistryErrorV2> {
    ConnectorRegistrySyncResponseV2::new(status, state.sequence(), state.head_digest())
        .map_err(|_| ExecdConnectorRegistryErrorV2::Verification)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicBool;

    use savana_kernel_protocol::v2::Digest32V2;
    use savana_policy_core::v2::ConnectorRegistryStateV2;

    use super::{current_head_after_lock, ExecdConnectorRegistryErrorV2};

    #[test]
    fn health_head_projection_rechecks_poison_after_acquiring_state_lock() {
        let state = ConnectorRegistryStateV2::from_verified_genesis(
            Digest32V2::new([0x41; 32]),
            [0; 32],
            Vec::new(),
            Vec::new(),
        )
        .unwrap();
        let poisoned = AtomicBool::new(true);
        assert_eq!(
            current_head_after_lock(&poisoned, &state),
            Err(ExecdConnectorRegistryErrorV2::Poisoned)
        );
    }
}
