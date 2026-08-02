#[cfg(any(test, feature = "test-support"))]
use std::path::Path;

use savana_kernel_protocol::v2::{Digest32V2, Ed25519KeyIdV2};
use savana_platform_identity::{
    NativeDeploymentAuthorityHandlesV2, NativeDeploymentBootstrapTrustMaterialV2,
};

use super::{
    AuthenticatedDeploymentLedgerSnapshotV2, DeploymentActivationVerifierV2,
    DeploymentAuthorizationKeyRefsV2, DeploymentAuthorizationVerifierV2, DeploymentControlErrorV2,
    DeploymentLedgerRecordV2, DeploymentLedgerStoreV2, DeploymentTransactionV2,
    InstallerOrMdmVerifierV2, OperationalTrustRootPurposeV2, OperationalTrustRootSetV2,
    ReleaseTrustRootSetV2,
};

/// Four complete installer-authenticated trust-root chains. Keeping every
/// predecessor alive here prevents a current root object from being accepted
/// without proving its exact genesis-to-current ancestry.
#[derive(Debug, Clone)]
pub struct AuthenticatedNativeDeploymentTrustV2 {
    installer_verifier: InstallerOrMdmVerifierV2,
    deployment_chain: Vec<OperationalTrustRootSetV2>,
    activation_chain: Vec<OperationalTrustRootSetV2>,
    declassification_chain: Vec<OperationalTrustRootSetV2>,
    release_chain: Vec<ReleaseTrustRootSetV2>,
}

impl AuthenticatedNativeDeploymentTrustV2 {
    pub fn verify(
        material: &NativeDeploymentBootstrapTrustMaterialV2,
    ) -> Result<Self, DeploymentControlErrorV2> {
        let installer_verifier = InstallerOrMdmVerifierV2::new(
            Ed25519KeyIdV2::new(material.installer_key_id()),
            material.installer_key_epoch(),
            material.installer_public_key(),
        )?;
        let deployment_chain = decode_operational_chain(
            material.deployment_trust_root_chain(),
            &installer_verifier,
            1,
        )?;
        let activation_chain = decode_operational_chain(
            material.activation_trust_root_chain(),
            &installer_verifier,
            2,
        )?;
        let declassification_chain = decode_operational_chain(
            material.declassification_trust_root_chain(),
            &installer_verifier,
            3,
        )?;
        let release_chain =
            decode_release_chain(material.release_trust_root_chain(), &installer_verifier)?;
        let deployment = deployment_chain
            .last()
            .ok_or(DeploymentControlErrorV2::InvalidOperationalTrustRootSet)?;
        let activation = activation_chain
            .last()
            .ok_or(DeploymentControlErrorV2::InvalidOperationalTrustRootSet)?;
        let declassification = declassification_chain
            .last()
            .ok_or(DeploymentControlErrorV2::InvalidOperationalTrustRootSet)?;
        let release = release_chain
            .last()
            .ok_or(DeploymentControlErrorV2::InvalidSecurityStateManifest)?;
        if deployment.product_family_digest() != activation.product_family_digest()
            || deployment.product_family_digest() != declassification.product_family_digest()
            || deployment.product_family_digest() != release.product_family_digest()
        {
            return Err(DeploymentControlErrorV2::InvalidOperationalTrustRootSet);
        }
        Ok(Self {
            installer_verifier,
            deployment_chain,
            activation_chain,
            declassification_chain,
            release_chain,
        })
    }

    pub const fn installer_verifier(&self) -> &InstallerOrMdmVerifierV2 {
        &self.installer_verifier
    }

    pub fn deployment_trust_root_set(&self) -> &OperationalTrustRootSetV2 {
        self.deployment_chain
            .last()
            .expect("authenticated deployment chain is nonempty")
    }

    pub fn activation_trust_root_set(&self) -> &OperationalTrustRootSetV2 {
        self.activation_chain
            .last()
            .expect("authenticated activation chain is nonempty")
    }

    pub fn release_trust_root_set(&self) -> &ReleaseTrustRootSetV2 {
        self.release_chain
            .last()
            .expect("authenticated release chain is nonempty")
    }

    pub fn declassification_trust_root_set(&self) -> &OperationalTrustRootSetV2 {
        self.declassification_chain
            .last()
            .expect("authenticated declassification chain is nonempty")
    }

    pub fn transaction_authorization_verifiers(
        &self,
        canonical_transaction: &[u8],
    ) -> Result<
        (
            DeploymentAuthorizationVerifierV2,
            DeploymentAuthorizationVerifierV2,
        ),
        DeploymentControlErrorV2,
    > {
        let key_refs = DeploymentAuthorizationKeyRefsV2::peek(canonical_transaction)?;
        self.transaction_authorization_verifiers_for_key_refs(&key_refs)
    }

    pub fn transaction_authorization_verifiers_for_key_refs(
        &self,
        key_refs: &DeploymentAuthorizationKeyRefsV2,
    ) -> Result<
        (
            DeploymentAuthorizationVerifierV2,
            DeploymentAuthorizationVerifierV2,
        ),
        DeploymentControlErrorV2,
    > {
        let rollback = self.deployment_trust_root_set().authorization_verifier(
            OperationalTrustRootPurposeV2::RollbackAuthorization,
            key_refs.rollback_key_id(),
            key_refs.rollback_key_epoch(),
            key_refs.authorization_time_unix_ms(),
        )?;
        let transaction = self.deployment_trust_root_set().authorization_verifier(
            OperationalTrustRootPurposeV2::DeploymentAuthorization,
            key_refs.transaction_key_id(),
            key_refs.transaction_key_epoch(),
            key_refs.authorization_time_unix_ms(),
        )?;
        Ok((rollback, transaction))
    }

    /// Binds a signature-authenticated staged transaction to the exact root
    /// revisions from this already installer-authenticated native trust chain.
    pub fn validate_authenticated_transaction_pre_state(
        &self,
        transaction: &DeploymentTransactionV2,
        selected: &DeploymentLedgerRecordV2,
    ) -> Result<(), DeploymentControlErrorV2> {
        transaction.validate_authenticated_pre_state(
            selected,
            self.deployment_trust_root_set()
                .binding()
                .member_set_digest(),
            self.activation_trust_root_set()
                .binding()
                .member_set_digest(),
            self.release_trust_root_set()
                .release_trust_root_set_digest(),
            self.declassification_trust_root_set()
                .binding()
                .member_set_digest(),
        )
    }
}

fn decode_operational_chain(
    bytes: &[Vec<u8>],
    verifier: &InstallerOrMdmVerifierV2,
    expected_binding_tag: u16,
) -> Result<Vec<OperationalTrustRootSetV2>, DeploymentControlErrorV2> {
    let mut chain = Vec::new();
    chain
        .try_reserve_exact(bytes.len())
        .map_err(|_| DeploymentControlErrorV2::InvalidOperationalTrustRootSet)?;
    for canonical in bytes {
        let current = OperationalTrustRootSetV2::from_canonical_bytes(canonical, verifier)?;
        if current.binding().tag() != expected_binding_tag {
            return Err(DeploymentControlErrorV2::InvalidOperationalTrustRootSet);
        }
        current.validate_predecessor(chain.last())?;
        chain.push(current);
    }
    if chain.is_empty() {
        return Err(DeploymentControlErrorV2::InvalidOperationalTrustRootSet);
    }
    Ok(chain)
}

fn decode_release_chain(
    bytes: &[Vec<u8>],
    verifier: &InstallerOrMdmVerifierV2,
) -> Result<Vec<ReleaseTrustRootSetV2>, DeploymentControlErrorV2> {
    let mut chain = Vec::new();
    chain
        .try_reserve_exact(bytes.len())
        .map_err(|_| DeploymentControlErrorV2::InvalidSecurityStateManifest)?;
    for canonical in bytes {
        let current = ReleaseTrustRootSetV2::from_canonical_bytes(canonical, verifier)?;
        current.validate_predecessor(chain.last())?;
        chain.push(current);
    }
    if chain.is_empty() {
        return Err(DeploymentControlErrorV2::InvalidSecurityStateManifest);
    }
    Ok(chain)
}

/// The first authenticated production bootstrap boundary. The ledger store is
/// opened only from the native activation key identity and the paired
/// monotonic rollback authority; no filesystem key or caller verifier enters
/// this object.
pub struct AuthenticatedNativeDeploymentLedgerV2 {
    ledger_store: DeploymentLedgerStoreV2,
    snapshot: AuthenticatedDeploymentLedgerSnapshotV2,
    activation_verifier: DeploymentActivationVerifierV2,
    signing_authority_identity: Digest32V2,
    rollback_authority_identity: Digest32V2,
}

impl std::fmt::Debug for AuthenticatedNativeDeploymentLedgerV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthenticatedNativeDeploymentLedgerV2")
            .field(
                "installation_id",
                &self.activation_verifier.installation_id(),
            )
            .field("installation_epoch", &self.activation_verifier.key_epoch())
            .field(
                "selected_generation",
                &self.snapshot.selected_record().projection().generation(),
            )
            .field(
                "signing_authority_identity",
                &self.signing_authority_identity,
            )
            .field(
                "rollback_authority_identity",
                &self.rollback_authority_identity,
            )
            .finish_non_exhaustive()
    }
}

impl AuthenticatedNativeDeploymentLedgerV2 {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub fn open_fixed_platform(
        handles: &mut NativeDeploymentAuthorityHandlesV2,
    ) -> Result<Self, DeploymentControlErrorV2> {
        let (activation_verifier, signing_authority_identity, rollback_authority_identity) =
            verifier_material(handles)?;
        let ledger_store = DeploymentLedgerStoreV2::open_fixed_platform(
            activation_verifier.clone(),
            rollback_authority_identity,
        )?;
        Self::authenticate(
            ledger_store,
            activation_verifier,
            signing_authority_identity,
            rollback_authority_identity,
            handles,
        )
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn open_for_test(
        directory: &Path,
        handles: &mut NativeDeploymentAuthorityHandlesV2,
    ) -> Result<Self, DeploymentControlErrorV2> {
        let (activation_verifier, signing_authority_identity, rollback_authority_identity) =
            verifier_material(handles)?;
        let ledger_store = DeploymentLedgerStoreV2::open_for_test(
            directory,
            activation_verifier.clone(),
            rollback_authority_identity,
        )?;
        Self::authenticate(
            ledger_store,
            activation_verifier,
            signing_authority_identity,
            rollback_authority_identity,
            handles,
        )
    }

    fn authenticate(
        ledger_store: DeploymentLedgerStoreV2,
        activation_verifier: DeploymentActivationVerifierV2,
        signing_authority_identity: Digest32V2,
        rollback_authority_identity: Digest32V2,
        handles: &mut NativeDeploymentAuthorityHandlesV2,
    ) -> Result<Self, DeploymentControlErrorV2> {
        let (_, rollback) = handles.split();
        let snapshot = ledger_store.load_selected_authenticated(rollback)?;
        let selected = snapshot.selected_record().projection();
        if selected.installation_id() != activation_verifier.installation_id()
            || selected.installation_epoch() != activation_verifier.key_epoch()
        {
            return Err(DeploymentControlErrorV2::InstallationTupleMismatch);
        }
        Ok(Self {
            ledger_store,
            snapshot,
            activation_verifier,
            signing_authority_identity,
            rollback_authority_identity,
        })
    }

    pub const fn snapshot(&self) -> &AuthenticatedDeploymentLedgerSnapshotV2 {
        &self.snapshot
    }

    pub const fn activation_verifier(&self) -> &DeploymentActivationVerifierV2 {
        &self.activation_verifier
    }

    pub const fn signing_authority_identity(&self) -> Digest32V2 {
        self.signing_authority_identity
    }

    pub const fn rollback_authority_identity(&self) -> Digest32V2 {
        self.rollback_authority_identity
    }

    pub fn recovery_plan_without_transaction(
        &self,
    ) -> Result<super::AuthenticatedDeploymentRecoveryPlanV2, DeploymentControlErrorV2> {
        let projection = self.snapshot.selected_record().projection();
        if projection.transaction_id().is_some() || projection.transaction_head_digest().is_some() {
            return Err(DeploymentControlErrorV2::TransactionBindingMismatch);
        }
        super::AuthenticatedDeploymentRecoveryPlanV2::without_transaction(projection.phase())
    }

    pub fn into_ledger_store(self) -> DeploymentLedgerStoreV2 {
        self.ledger_store
    }
}

fn verifier_material(
    handles: &mut NativeDeploymentAuthorityHandlesV2,
) -> Result<(DeploymentActivationVerifierV2, Digest32V2, Digest32V2), DeploymentControlErrorV2> {
    let (signing, rollback) = handles.split();
    let signing_authority_identity = Digest32V2::new(signing.authority_identity());
    let rollback_authority_identity = Digest32V2::new(rollback.authority_identity());
    if signing_authority_identity
        .as_bytes()
        .iter()
        .all(|byte| *byte == 0)
    {
        return Err(DeploymentControlErrorV2::NativeSigningAuthorityUnavailable);
    }
    if rollback_authority_identity
        .as_bytes()
        .iter()
        .all(|byte| *byte == 0)
    {
        return Err(DeploymentControlErrorV2::NativeRollbackAuthorityUnavailable);
    }
    let activation_verifier = DeploymentActivationVerifierV2::new(
        Digest32V2::new(signing.installation_id()),
        Ed25519KeyIdV2::new(signing.key_id()),
        signing.key_epoch(),
        signing.public_key(),
    )?;
    Ok((
        activation_verifier,
        signing_authority_identity,
        rollback_authority_identity,
    ))
}
