use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::sync::{Arc, Mutex};

use ed25519_dalek::SigningKey;
use savana_kernel_protocol::v2::{
    derive_ed25519_key_id_v2, ActionTemplateIdV2, AgentSessionHandleV2, ApprovalDecisionV2,
    ApprovalPurposeV2, ApprovedConnectorRegistrationHandleV2, BootIdV2,
    BoundedConnectorRegistrySnapshotV2, ConnectorRemovalAuthorizationHandleV2, Digest32V2,
    DisplayProjectionIdV2, ExecutorIdentityV2, ImplementationIdV2, Nonce32V2,
    PendingConnectorRegistrationHandleV2, PrepareConnectorRegistrationRequestV2, PrincipalIdV2,
    ProjectionIdV2, ProposeConnectorRegistrationRequestV2, ProposeConnectorRegistrationResponseV2,
    RoleIdV2, SignedApprovalSettlementV2, ToolClassIdV2, UnixMillisV2,
    UnsignedApprovalSettlementV2, VersionV2,
};
use savana_kernel_protocol::StableCode;
use savana_policy_core::v2::{
    AttemptKindV2, BoundedConnectorHostV2, BoundedConnectorRetryPolicyV2, ConnectorDescriptorV2,
    ConnectorRegistryStateV2, ConnectorTierV2, DurableConnectorRegistryStoreV2, EffectSetV2,
    ExecutorIdempotencyContractV2, G4Error, IdentifierV2, InternalValidatorDeclarationV2,
    RollbackProtectedStateAnchorV2, RollbackProtectedStateHeadV2,
    SharedVerifiedConnectorRegistryV2, UnsignedToolDescriptorV2,
};
use sha2::{Digest as _, Sha256};

use crate::v2_agent_authority::tests::{
    install_connector_runtime, planner_authority_fixture, PlannerAuthorityFixtureV2,
};
use crate::v2_connector_authority::{
    ConnectorRegistryMutationV2, KernelConnectorAuthorityErrorV2, KernelConnectorAuthorityV2,
    TestConnectorCommitCrashPointV2,
};

const CALLER_BOOT_ID: BootIdV2 = BootIdV2::new([0x8c; 32]);
const ACTIVE_MANIFEST: Digest32V2 = Digest32V2::new([0x85; 32]);
const ROLLED_MANIFEST: Digest32V2 = Digest32V2::new([0x86; 32]);
const INSTALLATION_ID: Digest32V2 = Digest32V2::new([0x89; 32]);
const DEPLOYMENT_GENERATION: u64 = 1;
const HANDLE_KEY: [u8; 32] = [0xd7; 32];
const CONNECTOR_USER_DOMAIN: &[u8] = b"savana.connector.user.v2\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TestConnectorSettlementMutationV2 {
    ExactApprove,
    DifferentExactApproval,
    ExactDeny,
    WrongPurpose,
    WrongPrincipal,
    WrongChallenge,
    WrongHead,
    Expired,
}

#[derive(Debug, Clone)]
struct TestConnectorProposalV2 {
    response: ProposeConnectorRegistrationResponseV2,
}

impl TestConnectorProposalV2 {
    fn pending_handle(&self) -> PendingConnectorRegistrationHandleV2 {
        self.response.pending()
    }
}

#[derive(Clone)]
struct TestConnectorHighWaterV2(Arc<Mutex<RollbackProtectedStateHeadV2>>);

impl Default for TestConnectorHighWaterV2 {
    fn default() -> Self {
        Self(Arc::new(Mutex::new(
            RollbackProtectedStateHeadV2::new(0, Digest32V2::new([0; 32])).unwrap(),
        )))
    }
}

impl RollbackProtectedStateAnchorV2 for TestConnectorHighWaterV2 {
    fn current_head(&self) -> Result<RollbackProtectedStateHeadV2, G4Error> {
        self.0
            .lock()
            .map(|head| *head)
            .map_err(|_| G4Error::DurableStateIo)
    }

    fn compare_and_advance(
        &mut self,
        expected: RollbackProtectedStateHeadV2,
        next: RollbackProtectedStateHeadV2,
    ) -> Result<(), G4Error> {
        let mut head = self.0.lock().map_err(|_| G4Error::DurableStateIo)?;
        if *head != expected
            || next.sequence()
                != expected
                    .sequence()
                    .checked_add(1)
                    .ok_or(G4Error::DurableStateRollback)?
        {
            return Err(G4Error::DurableStateRollback);
        }
        *head = next;
        Ok(())
    }
}

struct TestConnectorAuthorityHarnessV2 {
    directory: tempfile::TempDir,
    high_water: TestConnectorHighWaterV2,
    genesis: ConnectorRegistryStateV2,
    agent: PlannerAuthorityFixtureV2,
    authority: Option<KernelConnectorAuthorityV2>,
    enabled: bool,
}

impl TestConnectorAuthorityHarnessV2 {
    fn enabled() -> Self {
        Self::new(true)
    }

    fn disabled() -> Self {
        Self::new(false)
    }

    fn new(enabled: bool) -> Self {
        let mut agent = planner_authority_fixture();
        install_connector_runtime(&mut agent, enabled);
        agent.extend_connector_session(UnixMillisV2::new(1_000_000));
        let shared = agent.connector_registry();
        let genesis = shared.snapshot().unwrap();
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let high_water = TestConnectorHighWaterV2::default();
        let authority = if enabled {
            let store = DurableConnectorRegistryStoreV2::open_for_test(
                directory.path(),
                genesis.clone(),
                Box::new(high_water.clone()),
            )
            .unwrap();
            KernelConnectorAuthorityV2::from_durable_store(store, shared, HANDLE_KEY).unwrap()
        } else {
            KernelConnectorAuthorityV2::disabled(shared, HANDLE_KEY).unwrap()
        };
        Self {
            directory,
            high_water,
            genesis,
            agent,
            authority: Some(authority),
            enabled,
        }
    }

    fn propose_named_add(
        &mut self,
        name: &str,
        tool_count: usize,
    ) -> Result<TestConnectorProposalV2, KernelConnectorAuthorityErrorV2> {
        let descriptor = test_connector_descriptor(name, tool_count);
        let session = self.agent.connector_session();
        let caller_identity = self.agent.connector_caller_identity();
        let prepared = self
            .agent
            .connector_agent()
            .prepare_connector_registration(
                &PrepareConnectorRegistrationRequestV2::new(session, descriptor.clone())
                    .map_err(|_| KernelConnectorAuthorityErrorV2::BindingMismatch)?,
                CALLER_BOOT_ID,
                caller_identity,
                ACTIVE_MANIFEST,
                DEPLOYMENT_GENERATION,
                UnixMillisV2::new(200),
            )?;
        let request =
            ProposeConnectorRegistrationRequestV2::new(prepared.authorization(), descriptor)
                .map_err(|_| KernelConnectorAuthorityErrorV2::BindingMismatch)?;
        let authority = self
            .authority
            .as_mut()
            .ok_or(KernelConnectorAuthorityErrorV2::Unavailable)?;
        let (agent, values) = self.agent.connector_agent_and_values();
        let response = authority.propose_add(
            &request,
            agent,
            values,
            CALLER_BOOT_ID,
            caller_identity,
            ACTIVE_MANIFEST,
            DEPLOYMENT_GENERATION,
            UnixMillisV2::new(201),
        )?;
        Ok(TestConnectorProposalV2 { response })
    }

    fn settlement_for(
        &self,
        proposal: &TestConnectorProposalV2,
        mutation: TestConnectorSettlementMutationV2,
    ) -> Result<SignedApprovalSettlementV2, KernelConnectorAuthorityErrorV2> {
        let envelope_key = SigningKey::from_bytes(&[0x91; 32]);
        let unsigned_envelope = proposal
            .response
            .envelope()
            .verify(
                derive_ed25519_key_id_v2(envelope_key.verifying_key().to_bytes()),
                envelope_key.verifying_key().to_bytes(),
                INSTALLATION_ID,
                ACTIVE_MANIFEST,
                DEPLOYMENT_GENERATION,
                ApprovalPurposeV2::ConnectorRegistration,
                self.agent.connector_principal(),
                UnixMillisV2::new(202),
            )
            .map_err(|_| KernelConnectorAuthorityErrorV2::BindingMismatch)?;
        let exact_digest = proposal
            .response
            .envelope()
            .envelope_digest()
            .map_err(|_| KernelConnectorAuthorityErrorV2::BindingMismatch)?;
        let purpose = if mutation == TestConnectorSettlementMutationV2::WrongPurpose {
            ApprovalPurposeV2::FinalRelease
        } else {
            ApprovalPurposeV2::ConnectorRegistration
        };
        let envelope_digest = if mutation == TestConnectorSettlementMutationV2::WrongHead {
            Digest32V2::new([0xe1; 32])
        } else {
            exact_digest
        };
        let principal = if mutation == TestConnectorSettlementMutationV2::WrongPrincipal {
            PrincipalIdV2::new([0xe2; 32])
        } else {
            unsigned_envelope.expected_principal()
        };
        let challenge = if mutation == TestConnectorSettlementMutationV2::WrongChallenge {
            Nonce32V2::new([0xe3; 32])
        } else {
            unsigned_envelope.decision_challenge()
        };
        let decision = if mutation == TestConnectorSettlementMutationV2::ExactDeny {
            ApprovalDecisionV2::Deny
        } else {
            ApprovalDecisionV2::Approve
        };
        let issued_at = UnixMillisV2::new(202);
        let expires_at = if mutation == TestConnectorSettlementMutationV2::Expired {
            UnixMillisV2::new(203)
        } else {
            UnixMillisV2::new(20_000)
        };
        let mut nonce = *exact_digest.as_bytes();
        nonce[0] ^= if mutation == TestConnectorSettlementMutationV2::DifferentExactApproval {
            0x5a
        } else {
            0xa5
        };
        if nonce == [0; 32] {
            nonce[0] = 1;
        }
        SignedApprovalSettlementV2::sign(
            UnsignedApprovalSettlementV2::new(
                INSTALLATION_ID,
                ACTIVE_MANIFEST,
                DEPLOYMENT_GENERATION,
                purpose,
                envelope_digest,
                decision,
                principal,
                Digest32V2::new([0xe4; 32]),
                Digest32V2::new([0xe5; 32]),
                true,
                true,
                false,
                false,
                1,
                challenge,
                Nonce32V2::new(nonce),
                issued_at,
                expires_at,
            )
            .map_err(|_| KernelConnectorAuthorityErrorV2::BindingMismatch)?,
            &SigningKey::from_bytes(&[0x92; 32]),
        )
        .map_err(|_| KernelConnectorAuthorityErrorV2::BindingMismatch)
    }

    fn authorize_add(
        &mut self,
        pending: PendingConnectorRegistrationHandleV2,
        settlement: &SignedApprovalSettlementV2,
    ) -> Result<ApprovedConnectorRegistrationHandleV2, KernelConnectorAuthorityErrorV2> {
        self.authorize_add_for_active(pending, settlement, ACTIVE_MANIFEST, DEPLOYMENT_GENERATION)
    }

    fn authorize_add_for_active(
        &mut self,
        pending: PendingConnectorRegistrationHandleV2,
        settlement: &SignedApprovalSettlementV2,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
    ) -> Result<ApprovedConnectorRegistrationHandleV2, KernelConnectorAuthorityErrorV2> {
        self.authorize_add_at(
            pending,
            settlement,
            active_state_manifest_digest,
            deployment_generation,
            UnixMillisV2::new(203),
        )
    }

    fn authorize_add_at(
        &mut self,
        pending: PendingConnectorRegistrationHandleV2,
        settlement: &SignedApprovalSettlementV2,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
        now: UnixMillisV2,
    ) -> Result<ApprovedConnectorRegistrationHandleV2, KernelConnectorAuthorityErrorV2> {
        self.authority
            .as_mut()
            .ok_or(KernelConnectorAuthorityErrorV2::Unavailable)?
            .authorize_add(
                pending,
                settlement,
                self.agent.connector_agent(),
                active_state_manifest_digest,
                deployment_generation,
                now,
            )
    }

    fn apply_approved_add(
        &mut self,
        approved: ApprovedConnectorRegistrationHandleV2,
    ) -> Result<ConnectorRegistryMutationV2, KernelConnectorAuthorityErrorV2> {
        self.apply_approved_add_for_active(approved, ACTIVE_MANIFEST, DEPLOYMENT_GENERATION)
    }

    fn apply_approved_add_for_active(
        &mut self,
        approved: ApprovedConnectorRegistrationHandleV2,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
    ) -> Result<ConnectorRegistryMutationV2, KernelConnectorAuthorityErrorV2> {
        self.authority
            .as_mut()
            .ok_or(KernelConnectorAuthorityErrorV2::Unavailable)?
            .apply_approved_add(
                approved,
                self.agent.connector_agent(),
                active_state_manifest_digest,
                deployment_generation,
            )
    }

    fn apply_approved_add_crashing(
        &mut self,
        approved: ApprovedConnectorRegistrationHandleV2,
        point: TestConnectorCommitCrashPointV2,
    ) -> Result<ConnectorRegistryMutationV2, KernelConnectorAuthorityErrorV2> {
        self.authority
            .as_mut()
            .ok_or(KernelConnectorAuthorityErrorV2::Unavailable)?
            .apply_approved_add_with_crash_for_test(
                approved,
                self.agent.connector_agent(),
                ACTIVE_MANIFEST,
                DEPLOYMENT_GENERATION,
                point,
            )
    }

    fn add_named_connector(
        &mut self,
        name: &str,
        tool_count: usize,
    ) -> Result<ConnectorRegistryMutationV2, KernelConnectorAuthorityErrorV2> {
        let proposal = self.propose_named_add(name, tool_count)?;
        let settlement =
            self.settlement_for(&proposal, TestConnectorSettlementMutationV2::ExactApprove)?;
        let approved = self.authorize_add(proposal.pending_handle(), &settlement)?;
        self.apply_approved_add(approved)
    }

    fn restart(mut self) -> Result<Self, KernelConnectorAuthorityErrorV2> {
        drop(self.authority.take());
        if self.enabled {
            let store = DurableConnectorRegistryStoreV2::open_for_test(
                self.directory.path(),
                self.genesis.clone(),
                Box::new(self.high_water.clone()),
            )?;
            let shared = SharedVerifiedConnectorRegistryV2::from_verified_state(store.snapshot()?)?;
            self.agent.replace_connector_registry(shared.clone());
            self.authority = Some(KernelConnectorAuthorityV2::from_durable_store(
                store, shared, HANDLE_KEY,
            )?);
        } else {
            let shared = self.agent.connector_registry();
            self.authority = Some(KernelConnectorAuthorityV2::disabled(shared, HANDLE_KEY)?);
        }
        Ok(self)
    }

    fn durable_add_record_count(&self) -> usize {
        self.authority
            .as_ref()
            .map(KernelConnectorAuthorityV2::add_record_count_for_test)
            .unwrap_or_default()
    }

    fn heavy_record_count(&self) -> usize {
        self.authority
            .as_ref()
            .map(KernelConnectorAuthorityV2::heavy_record_count_for_test)
            .unwrap_or_default()
    }

    fn encoded_authority_state_len(&self) -> usize {
        self.authority
            .as_ref()
            .ok_or(KernelConnectorAuthorityErrorV2::Unavailable)
            .and_then(KernelConnectorAuthorityV2::encoded_state_len_for_test)
            .unwrap()
    }

    fn replace_approved_settlement_for_test(
        &mut self,
        approved: ApprovedConnectorRegistrationHandleV2,
        settlement: &SignedApprovalSettlementV2,
    ) {
        self.authority
            .as_mut()
            .unwrap()
            .replace_approved_settlement_for_test(approved, settlement)
            .unwrap();
    }

    fn duplicate_committed_add_summary_for_test(&mut self) {
        self.authority
            .as_mut()
            .unwrap()
            .duplicate_committed_add_summary_for_test()
            .unwrap();
    }

    fn corrupt_committed_add_settlement_digest_for_test(&mut self) {
        self.authority
            .as_mut()
            .unwrap()
            .corrupt_committed_add_settlement_digest_for_test()
            .unwrap();
    }

    fn narrow_generation_so_connector_is_inert(
        &mut self,
    ) -> Result<(), KernelConnectorAuthorityErrorV2> {
        drop(self.authority.take());
        let narrowed = ConnectorRegistryStateV2::from_verified_genesis(
            self.genesis.genesis_digest(),
            self.genesis.connector_authority_public_key(),
            Vec::new(),
            Vec::new(),
        )?;
        self.genesis = narrowed.clone();
        let store = DurableConnectorRegistryStoreV2::open_for_test(
            self.directory.path(),
            narrowed,
            Box::new(self.high_water.clone()),
        )?;
        let shared = SharedVerifiedConnectorRegistryV2::from_verified_state(store.snapshot()?)?;
        self.agent.replace_connector_registry(shared.clone());
        self.authority = Some(KernelConnectorAuthorityV2::from_durable_store(
            store, shared, HANDLE_KEY,
        )?);
        Ok(())
    }

    fn prepare_remove(
        &mut self,
        connector_id: Digest32V2,
    ) -> Result<ConnectorRemovalAuthorizationHandleV2, KernelConnectorAuthorityErrorV2> {
        let session = self.agent.connector_session();
        let caller = self.agent.connector_caller_identity();
        self.authority
            .as_mut()
            .ok_or(KernelConnectorAuthorityErrorV2::Unavailable)?
            .prepare_remove(
                session,
                connector_id,
                self.agent.connector_agent(),
                CALLER_BOOT_ID,
                caller,
                ACTIVE_MANIFEST,
                DEPLOYMENT_GENERATION,
                UnixMillisV2::new(204),
            )
            .map(|prepared| prepared.authorization())
    }

    fn remove(
        &mut self,
        connector_id: Digest32V2,
        authorization: ConnectorRemovalAuthorizationHandleV2,
    ) -> Result<ConnectorRegistryMutationV2, KernelConnectorAuthorityErrorV2> {
        let session = self.agent.connector_session();
        let caller = self.agent.connector_caller_identity();
        self.authority
            .as_mut()
            .ok_or(KernelConnectorAuthorityErrorV2::Unavailable)?
            .remove(
                session,
                authorization,
                connector_id,
                self.agent.connector_agent(),
                CALLER_BOOT_ID,
                caller,
                ACTIVE_MANIFEST,
                DEPLOYMENT_GENERATION,
                UnixMillisV2::new(205),
            )
    }

    fn remove_with_wrong_session(
        &mut self,
        connector_id: Digest32V2,
        authorization: ConnectorRemovalAuthorizationHandleV2,
    ) -> Result<ConnectorRegistryMutationV2, KernelConnectorAuthorityErrorV2> {
        let caller = self.agent.connector_caller_identity();
        self.authority
            .as_mut()
            .ok_or(KernelConnectorAuthorityErrorV2::Unavailable)?
            .remove(
                AgentSessionHandleV2::from_authority_entropy([0xf1; 32]).unwrap(),
                authorization,
                connector_id,
                self.agent.connector_agent(),
                CALLER_BOOT_ID,
                caller,
                ACTIVE_MANIFEST,
                DEPLOYMENT_GENERATION,
                UnixMillisV2::new(205),
            )
    }

    fn remove_with_wrong_principal(
        &mut self,
        connector_id: Digest32V2,
        authorization: ConnectorRemovalAuthorizationHandleV2,
    ) -> Result<ConnectorRegistryMutationV2, KernelConnectorAuthorityErrorV2> {
        let original = self
            .agent
            .replace_connector_principal(PrincipalIdV2::new([0xf2; 32]));
        let result = self.remove(connector_id, authorization);
        self.agent.replace_connector_principal(original);
        result
    }

    fn remove_with_wrong_head(
        &mut self,
        connector_id: Digest32V2,
        authorization: ConnectorRemovalAuthorizationHandleV2,
    ) -> Result<ConnectorRegistryMutationV2, KernelConnectorAuthorityErrorV2> {
        let authority = self
            .authority
            .as_mut()
            .ok_or(KernelConnectorAuthorityErrorV2::Unavailable)?;
        let original =
            authority.replace_removal_head_for_test(authorization, Digest32V2::new([0xf3; 32]))?;
        let session = self.agent.connector_session();
        let caller = self.agent.connector_caller_identity();
        let result = authority.remove(
            session,
            authorization,
            connector_id,
            self.agent.connector_agent(),
            CALLER_BOOT_ID,
            caller,
            ACTIVE_MANIFEST,
            DEPLOYMENT_GENERATION,
            UnixMillisV2::new(205),
        );
        authority.replace_removal_head_for_test(authorization, original)?;
        result
    }

    fn snapshot(
        &mut self,
    ) -> Result<BoundedConnectorRegistrySnapshotV2, KernelConnectorAuthorityErrorV2> {
        let session = self.agent.connector_session();
        let caller = self.agent.connector_caller_identity();
        let snapshot = self
            .authority
            .as_ref()
            .ok_or(KernelConnectorAuthorityErrorV2::Unavailable)?
            .snapshot(
                session,
                self.agent.connector_agent(),
                CALLER_BOOT_ID,
                caller,
                ACTIVE_MANIFEST,
                DEPLOYMENT_GENERATION,
                UnixMillisV2::new(205),
            )?;
        BoundedConnectorRegistrySnapshotV2::new(snapshot.canonical_bytes().to_vec())
            .map_err(|_| KernelConnectorAuthorityErrorV2::LimitExceeded)
    }

    fn shared_snapshot(&self) -> ConnectorRegistryStateV2 {
        self.agent.connector_registry().snapshot().unwrap()
    }

    fn registry_head(&self) -> Digest32V2 {
        self.shared_snapshot().head_digest()
    }

    fn registry_sequence(&self) -> u64 {
        self.shared_snapshot().sequence()
    }

    fn registered_connector_count(&self) -> usize {
        self.shared_snapshot().registered_connector_count()
    }

    fn registered_tool_count(&self) -> usize {
        self.shared_snapshot().registered_tool_descriptor_count()
    }

    fn is_registered(&self, connector_id: Digest32V2) -> bool {
        self.shared_snapshot()
            .contains_registered_connector(connector_id)
    }

    fn is_active(&self, connector_id: Digest32V2) -> bool {
        self.shared_snapshot().contains_connector(connector_id)
    }

    fn sign_count(&self) -> u64 {
        self.authority.as_ref().unwrap().sign_count()
    }

    fn was_published_after_durable_reopen(&self) -> bool {
        self.authority
            .as_ref()
            .unwrap()
            .published_after_durable_reopen_for_test()
    }
}

fn test_connector_descriptor(name: &str, tool_count: usize) -> Vec<u8> {
    let tls_pin = Digest32V2::new(Sha256::digest(name.as_bytes()).into());
    let url = "https://api.example.com/mcp/v2?scope=full";
    let tools = (0..tool_count)
        .map(|index| test_connector_tool(name, index))
        .collect::<Vec<_>>();
    let mut identity = minicbor::Encoder::new(Vec::new());
    identity
        .array(2)
        .unwrap()
        .str(name)
        .unwrap()
        .array(3)
        .unwrap()
        .u16(2)
        .unwrap()
        .str(url)
        .unwrap()
        .bytes(tls_pin.as_bytes())
        .unwrap();
    let connector_id = Digest32V2::new(
        Sha256::new()
            .chain_update(CONNECTOR_USER_DOMAIN)
            .chain_update(identity.into_writer())
            .finalize()
            .into(),
    );
    let mut descriptor = minicbor::Encoder::new(Vec::new());
    descriptor
        .array(7)
        .unwrap()
        .bytes(connector_id.as_bytes())
        .unwrap()
        .str(name)
        .unwrap()
        .u16(ConnectorTierV2::UserRegistered.tag())
        .unwrap()
        .array(3)
        .unwrap()
        .u16(2)
        .unwrap()
        .str(url)
        .unwrap()
        .bytes(tls_pin.as_bytes())
        .unwrap()
        .array(tools.len() as u64)
        .unwrap();
    for tool in &tools {
        descriptor
            .writer_mut()
            .extend_from_slice(&minicbor::to_vec(tool).unwrap());
    }
    descriptor
        .u16(EffectSetV2::READ.bits())
        .unwrap()
        .u64(1)
        .unwrap();
    let bytes = descriptor.into_writer();
    ConnectorDescriptorV2::from_canonical_bytes(
        &bytes,
        &[BoundedConnectorHostV2::new("example.com").unwrap()],
    )
    .unwrap();
    bytes
}

fn test_connector_tool(name: &str, index: usize) -> UnsignedToolDescriptorV2 {
    let seed = Sha256::digest(format!("{name}:{index}").as_bytes());
    let byte = (seed[0] % 190).saturating_add(1);
    let contract = ExecutorIdempotencyContractV2::ConnectorIdempotentByExecutionNonce;
    UnsignedToolDescriptorV2::from_verified_manifest(
        2,
        VersionV2::new(1, 0, 0),
        Digest32V2::new([byte; 32]),
        IdentifierV2::new(format!("{name}.tool.{index}")).unwrap(),
        ActionTemplateIdV2::new(u32::from(byte) + 1),
        ToolClassIdV2::new(u32::from(byte) + 2),
        Digest32V2::new([byte.wrapping_add(1); 32]),
        Digest32V2::new([byte.wrapping_add(2); 32]),
        vec![RoleIdV2::new(1)],
        EffectSetV2::READ,
        AttemptKindV2::ToolRead,
        BoundedConnectorRetryPolicyV2::new(contract, 2, 1_000_000).unwrap(),
        vec![InternalValidatorDeclarationV2::new(
            ImplementationIdV2::new(u32::from(byte) + 3),
            VersionV2::new(1, 0, 0),
            Digest32V2::new([byte.wrapping_add(3); 32]),
        )],
        ExecutorIdentityV2::new([byte.wrapping_add(4); 32]),
        ProjectionIdV2::new(u32::from(byte) + 4),
        Digest32V2::new([byte.wrapping_add(5); 32]),
        DisplayProjectionIdV2::new(u32::from(byte) + 5),
        Digest32V2::new([byte.wrapping_add(6); 32]),
        contract,
        UnixMillisV2::new(1),
        UnixMillisV2::new(1_000_000),
    )
    .unwrap()
}

#[test]
fn purpose_four_settlement_is_exact_one_use_and_a_for_b_is_rejected() {
    let mut harness = TestConnectorAuthorityHarnessV2::enabled();
    let a = harness.propose_named_add("connector-a", 1).unwrap();
    let b = harness.propose_named_add("connector-b", 1).unwrap();

    for mutation in [
        TestConnectorSettlementMutationV2::WrongPurpose,
        TestConnectorSettlementMutationV2::WrongPrincipal,
        TestConnectorSettlementMutationV2::WrongChallenge,
        TestConnectorSettlementMutationV2::WrongHead,
        TestConnectorSettlementMutationV2::Expired,
    ] {
        let settlement = harness.settlement_for(&a, mutation).unwrap();
        let expected = if mutation == TestConnectorSettlementMutationV2::Expired {
            StableCode::ApprovalReplayed
        } else {
            StableCode::ApprovalBindingMismatch
        };
        assert_eq!(
            harness
                .authorize_add(a.pending_handle(), &settlement)
                .unwrap_err()
                .stable_code(),
            expected
        );
    }

    let settlement_a = harness
        .settlement_for(&a, TestConnectorSettlementMutationV2::ExactApprove)
        .unwrap();
    assert!(harness
        .authorize_add(b.pending_handle(), &settlement_a)
        .is_err());

    let denied = harness
        .settlement_for(&a, TestConnectorSettlementMutationV2::ExactDeny)
        .unwrap();
    assert!(harness.authorize_add(a.pending_handle(), &denied).is_err());
    assert!(harness.authorize_add(a.pending_handle(), &denied).is_err());

    let proposal = harness.propose_named_add("connector-c", 1).unwrap();
    let settlement = harness
        .settlement_for(&proposal, TestConnectorSettlementMutationV2::ExactApprove)
        .unwrap();
    let approved = harness
        .authorize_add(proposal.pending_handle(), &settlement)
        .unwrap();
    assert_eq!(
        harness
            .authorize_add(proposal.pending_handle(), &settlement)
            .unwrap(),
        approved
    );
    let conflicting = harness
        .settlement_for(
            &proposal,
            TestConnectorSettlementMutationV2::DifferentExactApproval,
        )
        .unwrap();
    assert!(harness
        .authorize_add(proposal.pending_handle(), &conflicting)
        .is_err());
}

#[test]
fn approved_authorization_replay_survives_ttl_without_losing_exact_success() {
    let mut harness = TestConnectorAuthorityHarnessV2::enabled();
    let proposal = harness.propose_named_add("approved-replay", 1).unwrap();
    let settlement = harness
        .settlement_for(&proposal, TestConnectorSettlementMutationV2::ExactApprove)
        .unwrap();
    let approved = harness
        .authorize_add(proposal.pending_handle(), &settlement)
        .unwrap();

    assert_eq!(
        harness
            .authorize_add_at(
                proposal.pending_handle(),
                &settlement,
                ACTIVE_MANIFEST,
                DEPLOYMENT_GENERATION,
                UnixMillisV2::new(1_000_001),
            )
            .unwrap(),
        approved
    );
    assert_eq!(harness.heavy_record_count(), 1);
    let mut restarted = harness.restart().unwrap();
    assert_eq!(
        restarted
            .authorize_add_at(
                proposal.pending_handle(),
                &settlement,
                ACTIVE_MANIFEST,
                DEPLOYMENT_GENERATION,
                UnixMillisV2::new(1_000_001),
            )
            .unwrap(),
        approved
    );
}

#[test]
fn recovered_approved_record_is_cryptographically_reverified_before_signing() {
    let mut harness = TestConnectorAuthorityHarnessV2::enabled();
    let proposal_a = harness.propose_named_add("forged-approved-a", 1).unwrap();
    let settlement_a = harness
        .settlement_for(&proposal_a, TestConnectorSettlementMutationV2::ExactApprove)
        .unwrap();
    let approved_a = harness
        .authorize_add(proposal_a.pending_handle(), &settlement_a)
        .unwrap();

    let proposal_b = harness.propose_named_add("forged-approved-b", 1).unwrap();
    let settlement_b = harness
        .settlement_for(&proposal_b, TestConnectorSettlementMutationV2::ExactApprove)
        .unwrap();
    harness.replace_approved_settlement_for_test(approved_a, &settlement_b);

    let mut restarted = harness.restart().unwrap();
    assert_eq!(
        restarted.apply_approved_add(approved_a),
        Err(KernelConnectorAuthorityErrorV2::BindingMismatch)
    );
    assert_eq!(restarted.sign_count(), 0);
    assert_eq!(restarted.registered_connector_count(), 0);
}

#[test]
fn terminal_and_stale_records_compact_heavy_material_but_keep_replay_tombstones() {
    let mut denied = TestConnectorAuthorityHarnessV2::enabled();
    let denied_proposal = denied.propose_named_add("compact-denied", 4).unwrap();
    let pending_len = denied.encoded_authority_state_len();
    assert_eq!(denied.heavy_record_count(), 1);
    let denied_settlement = denied
        .settlement_for(
            &denied_proposal,
            TestConnectorSettlementMutationV2::ExactDeny,
        )
        .unwrap();
    assert_eq!(
        denied.authorize_add(denied_proposal.pending_handle(), &denied_settlement),
        Err(KernelConnectorAuthorityErrorV2::Denied)
    );
    assert_eq!(denied.heavy_record_count(), 0);
    assert!(denied.encoded_authority_state_len() < pending_len / 2);
    let mut denied = denied.restart().unwrap();
    assert_eq!(
        denied.authorize_add(denied_proposal.pending_handle(), &denied_settlement),
        Err(KernelConnectorAuthorityErrorV2::Denied)
    );
    assert_eq!(denied.heavy_record_count(), 0);

    let mut expired = TestConnectorAuthorityHarnessV2::enabled();
    let expired_proposal = expired.propose_named_add("compact-expired", 4).unwrap();
    let expired_pending_len = expired.encoded_authority_state_len();
    let expired_settlement = expired
        .settlement_for(
            &expired_proposal,
            TestConnectorSettlementMutationV2::ExactApprove,
        )
        .unwrap();
    assert_eq!(
        expired.authorize_add_at(
            expired_proposal.pending_handle(),
            &expired_settlement,
            ACTIVE_MANIFEST,
            DEPLOYMENT_GENERATION,
            UnixMillisV2::new(1_000_001),
        ),
        Err(KernelConnectorAuthorityErrorV2::Expired)
    );
    assert_eq!(expired.heavy_record_count(), 0);
    assert!(expired.encoded_authority_state_len() < expired_pending_len / 2);
    let expired = expired.restart().unwrap();
    assert_eq!(expired.heavy_record_count(), 0);

    let mut committed = TestConnectorAuthorityHarnessV2::enabled();
    let result = committed
        .add_named_connector("compact-committed", 4)
        .unwrap();
    assert_eq!(committed.heavy_record_count(), 0);
    let removal = committed.prepare_remove(result.connector_id()).unwrap();
    assert_eq!(committed.heavy_record_count(), 1);
    committed.remove(result.connector_id(), removal).unwrap();
    assert_eq!(committed.heavy_record_count(), 0);
    let committed = committed.restart().unwrap();
    assert_eq!(committed.heavy_record_count(), 0);
}

#[test]
fn terminal_retry_flood_is_bounded_to_small_durable_tombstones() {
    let mut harness = TestConnectorAuthorityHarnessV2::enabled();
    for index in 0..12 {
        let proposal = harness
            .propose_named_add(&format!("terminal-flood-{index}"), 1)
            .unwrap();
        let settlement = harness
            .settlement_for(&proposal, TestConnectorSettlementMutationV2::ExactDeny)
            .unwrap();
        assert_eq!(
            harness.authorize_add(proposal.pending_handle(), &settlement),
            Err(KernelConnectorAuthorityErrorV2::Denied)
        );
    }
    assert_eq!(harness.durable_add_record_count(), 12);
    assert_eq!(harness.heavy_record_count(), 0);
    assert!(harness.encoded_authority_state_len() < 16 * 1024);

    let restarted = harness.restart().unwrap();
    assert_eq!(restarted.durable_add_record_count(), 12);
    assert_eq!(restarted.heavy_record_count(), 0);
    assert!(restarted.encoded_authority_state_len() < 16 * 1024);
}

#[test]
fn recovery_requires_a_bijective_semantic_mapping_to_the_signed_registry_journal() {
    let mut duplicate = TestConnectorAuthorityHarnessV2::enabled();
    duplicate.add_named_connector("journal-a", 1).unwrap();
    duplicate.add_named_connector("journal-b", 1).unwrap();
    duplicate.duplicate_committed_add_summary_for_test();
    assert_eq!(
        duplicate.restart().err(),
        Some(KernelConnectorAuthorityErrorV2::BindingMismatch)
    );

    let mut settlement = TestConnectorAuthorityHarnessV2::enabled();
    settlement
        .add_named_connector("journal-settlement", 1)
        .unwrap();
    settlement.corrupt_committed_add_settlement_digest_for_test();
    assert_eq!(
        settlement.restart().err(),
        Some(KernelConnectorAuthorityErrorV2::BindingMismatch)
    );
}

#[test]
fn pending_and_approved_adds_cannot_cross_deployment_rollover() {
    let mut pending_harness = TestConnectorAuthorityHarnessV2::enabled();
    let pending = pending_harness
        .propose_named_add("pending-before-rollover", 1)
        .unwrap();
    let pending_settlement = pending_harness
        .settlement_for(&pending, TestConnectorSettlementMutationV2::ExactApprove)
        .unwrap();
    let pending_result = pending_harness.authorize_add_for_active(
        pending.pending_handle(),
        &pending_settlement,
        ROLLED_MANIFEST,
        DEPLOYMENT_GENERATION + 1,
    );

    let mut approved_harness = TestConnectorAuthorityHarnessV2::enabled();
    let proposal = approved_harness
        .propose_named_add("approved-before-rollover", 1)
        .unwrap();
    let settlement = approved_harness
        .settlement_for(&proposal, TestConnectorSettlementMutationV2::ExactApprove)
        .unwrap();
    let approved = approved_harness
        .authorize_add(proposal.pending_handle(), &settlement)
        .unwrap();
    let approved_result = approved_harness.apply_approved_add_for_active(
        approved,
        ROLLED_MANIFEST,
        DEPLOYMENT_GENERATION + 1,
    );

    assert_eq!(
        pending_result.unwrap_err().stable_code(),
        StableCode::ApprovalBindingMismatch
    );
    assert_eq!(
        approved_result.unwrap_err().stable_code(),
        StableCode::ApprovalBindingMismatch
    );
    assert_eq!(pending_harness.sign_count(), 0);
    assert_eq!(approved_harness.sign_count(), 0);
    assert_eq!(pending_harness.registered_connector_count(), 0);
    assert_eq!(approved_harness.registered_connector_count(), 0);
}

#[test]
fn mapping_loss_restart_and_retry_reuse_one_unexpired_durable_proposal() {
    let mut harness = TestConnectorAuthorityHarnessV2::enabled();
    let first = harness.propose_named_add("mapping-loss", 1).unwrap();
    let expected = first.response.clone();
    let mut restarted = harness.restart().unwrap();

    for _ in 0..12 {
        let replay = restarted.propose_named_add("mapping-loss", 1).unwrap();
        assert_eq!(replay.response, expected);
    }
    assert_eq!(restarted.durable_add_record_count(), 1);
}

#[test]
fn committed_add_replay_returns_identical_delta_without_resigning_or_recounting() {
    let mut harness = TestConnectorAuthorityHarnessV2::enabled();
    let proposal = harness.propose_named_add("durable", 2).unwrap();
    let settlement = harness
        .settlement_for(&proposal, TestConnectorSettlementMutationV2::ExactApprove)
        .unwrap();
    let approved = harness
        .authorize_add(proposal.pending_handle(), &settlement)
        .unwrap();

    let committed = harness.apply_approved_add(approved).unwrap();
    assert_eq!(harness.sign_count(), 1);
    assert_eq!(harness.registered_connector_count(), 1);
    assert_eq!(harness.registered_tool_count(), 2);
    assert!(harness.was_published_after_durable_reopen());

    let replay = harness.apply_approved_add(approved).unwrap();
    assert_eq!(replay, committed);
    assert_eq!(harness.sign_count(), 1);
    assert_eq!(harness.registered_connector_count(), 1);
    assert_eq!(harness.registered_tool_count(), 2);

    let mut restarted = harness.restart().unwrap();
    assert_eq!(restarted.apply_approved_add(approved).unwrap(), committed);
    assert_eq!(restarted.sign_count(), 1);
    assert_eq!(restarted.registry_head(), committed.head_digest());
}

#[test]
fn every_commit_boundary_has_no_pre_durable_visibility_and_restart_converges() {
    for point in TestConnectorCommitCrashPointV2::ALL {
        let mut harness = TestConnectorAuthorityHarnessV2::enabled();
        let proposal = harness.propose_named_add("crash-safe", 1).unwrap();
        let settlement = harness
            .settlement_for(&proposal, TestConnectorSettlementMutationV2::ExactApprove)
            .unwrap();
        let approved = harness
            .authorize_add(proposal.pending_handle(), &settlement)
            .unwrap();
        let old_head = harness.registry_head();

        let attempt = harness.apply_approved_add_crashing(approved, point);
        if !point.is_after_durable_reopen() {
            assert_eq!(harness.registry_head(), old_head);
            assert_eq!(harness.registered_connector_count(), 0);
        }

        let mut restarted = harness.restart().unwrap();
        let recovered = restarted.apply_approved_add(approved).unwrap();
        if let Ok(response) = attempt {
            assert_eq!(response, recovered);
        }
        assert_eq!(restarted.registry_head(), recovered.head_digest());
        assert_eq!(restarted.registered_connector_count(), 1);
        assert_eq!(restarted.sign_count(), 1);
    }
}

#[test]
fn removal_is_ui_session_bound_without_approval_and_survives_narrowing() {
    let mut harness = TestConnectorAuthorityHarnessV2::enabled();
    let committed = harness.add_named_connector("removable", 1).unwrap();
    let connector_id = committed.connector_id();
    harness.narrow_generation_so_connector_is_inert().unwrap();
    assert!(harness.is_registered(connector_id));
    assert!(!harness.is_active(connector_id));

    let authorization = harness.prepare_remove(connector_id).unwrap();
    assert!(harness
        .remove_with_wrong_session(connector_id, authorization)
        .is_err());
    assert!(harness
        .remove_with_wrong_principal(connector_id, authorization)
        .is_err());
    assert!(harness
        .remove_with_wrong_head(connector_id, authorization)
        .is_err());
    let removed = harness.remove(connector_id, authorization).unwrap();
    assert!(!harness.is_registered(connector_id));
    assert_eq!(
        harness.remove(connector_id, authorization).unwrap(),
        removed
    );
    assert!(harness.prepare_remove(connector_id).is_err());

    let mut restarted = harness.restart().unwrap();
    assert_eq!(
        restarted.remove(connector_id, authorization).unwrap(),
        removed
    );
    assert!(!restarted.is_registered(connector_id));
}

#[test]
fn disabled_and_capacity_states_expose_no_mutating_authority() {
    let mut disabled = TestConnectorAuthorityHarnessV2::disabled();
    assert!(disabled.propose_named_add("disabled", 1).is_err());
    assert!(disabled.snapshot().is_err());
    assert_eq!(disabled.sign_count(), 0);

    let mut enabled = TestConnectorAuthorityHarnessV2::enabled();
    for index in 0..16 {
        enabled
            .add_named_connector(&format!("connector-{index}"), 1)
            .unwrap();
    }
    let head = enabled.registry_head();
    let sequence = enabled.registry_sequence();
    let signs = enabled.sign_count();
    assert!(enabled.add_named_connector("overflow", 1).is_err());
    assert_eq!(enabled.registry_head(), head);
    assert_eq!(enabled.registry_sequence(), sequence);
    assert_eq!(enabled.sign_count(), signs);
    assert_eq!(enabled.registered_connector_count(), 16);
}

#[test]
fn maximum_registry_snapshot_is_a_compact_browser_projection() {
    let mut harness = TestConnectorAuthorityHarnessV2::enabled();
    for index in 0..16 {
        harness
            .add_named_connector(&format!("large-projection-connector-{index}"), 1)
            .unwrap();
    }

    let snapshot = harness.snapshot().unwrap();
    assert!(snapshot.as_bytes().len() < 2 * 1024);
    assert!(!snapshot
        .as_bytes()
        .windows(b"large-projection-connector-15".len())
        .any(|window| window == b"large-projection-connector-15"));
}
