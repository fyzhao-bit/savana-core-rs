use savana_kernel_protocol::v2::{Digest32V2, Nonce32V2};
use sha2::{Digest as _, Sha256};

use super::deployment_manifest_primitives::{
    decode_bounded_array_length, decode_digest, decode_u16, decode_u64, expect_array, hash_domain,
    is_zero, require_canonical, require_eof,
};
use super::{
    ClosedServiceIdV2, DeploymentControlErrorV2, DeploymentHardLimitsV2, RollbackOriginPhaseV2,
};

const NATIVE_CONTROL_ITEM_FIELDS_V2: u64 = 4;
const FROZEN_EFFECT_WORK_ITEM_FIELDS_V2: u64 = 6;
const FROZEN_EFFECT_WORK_SET_FIELDS_V2: u64 = 7;
const FROZEN_EFFECT_WORK_SET_SCHEMA_VERSION_V2: u16 = 2;
const ROLE_RECONCILIATION_ITEM_FIELDS_V2: u64 = 6;
const ROLE_RECONCILIATION_FIELDS_V2: u64 = 9;
const ROLE_RECONCILIATION_SCHEMA_VERSION_V2: u16 = 2;
const BRIDGE_RESTORE_INTEGRITY_FIELDS_V2: u64 = 20;
const BRIDGE_RESTORE_INTEGRITY_SCHEMA_VERSION_V2: u16 = 2;
const NATIVE_CONTROL_SET_DOMAIN_V2: &[u8] = b"savana.set.native-control-measurement.v2\0";
const FROZEN_EFFECT_WORK_SET_DOMAIN_V2: &[u8] = b"savana.set.frozen-effect-work.v2\0";
const FROZEN_EFFECT_WORK_OBJECT_DOMAIN_V2: &[u8] = b"savana.frozen-effect-work-set.v2\0";
const ROLE_RECONCILIATION_SET_DOMAIN_V2: &[u8] = b"savana.set.role-journal-reconciliation.v2\0";
const ROLE_RECONCILIATION_OBJECT_DOMAIN_V2: &[u8] = b"savana.role-journal-reconciliation.v2\0";
const BRIDGE_RESTORE_INTEGRITY_DOMAIN_V2: &[u8] = b"savana.bootstrap-bridge-restore-integrity.v2\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeControlMeasurementSetItemV2 {
    control_identity_digest: Digest32V2,
    expected_profile_digest: Digest32V2,
    measured_value_digest: Digest32V2,
    passed: bool,
}

impl NativeControlMeasurementSetItemV2 {
    pub fn new(
        control_identity_digest: Digest32V2,
        expected_profile_digest: Digest32V2,
        measured_value_digest: Digest32V2,
        passed: bool,
    ) -> Result<Self, DeploymentControlErrorV2> {
        if !passed
            || [
                control_identity_digest,
                expected_profile_digest,
                measured_value_digest,
            ]
            .iter()
            .any(|digest| is_zero(digest.as_bytes()))
        {
            return Err(DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence);
        }
        Ok(Self {
            control_identity_digest,
            expected_profile_digest,
            measured_value_digest,
            passed,
        })
    }

    pub const fn control_identity_digest(self) -> Digest32V2 {
        self.control_identity_digest
    }

    pub const fn expected_profile_digest(self) -> Digest32V2 {
        self.expected_profile_digest
    }

    pub const fn measured_value_digest(self) -> Digest32V2 {
        self.measured_value_digest
    }

    pub const fn passed(self) -> bool {
        self.passed
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeControlMeasurementSetV2 {
    canonical_bytes: Vec<u8>,
    items: Vec<NativeControlMeasurementSetItemV2>,
    digest: Digest32V2,
}

impl NativeControlMeasurementSetV2 {
    pub fn new(
        items: Vec<NativeControlMeasurementSetItemV2>,
    ) -> Result<Self, DeploymentControlErrorV2> {
        validate_native_control_items(&items)?;
        let canonical_bytes = encode_native_control_items(&items)?;
        let digest = exact_set_digest(NATIVE_CONTROL_SET_DOMAIN_V2, items.len(), &canonical_bytes)?;
        Ok(Self {
            canonical_bytes,
            items,
            digest,
        })
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, DeploymentControlErrorV2> {
        check_runtime_evidence_size(bytes)?;
        let mut decoder = minicbor::Decoder::new(bytes);
        let count = decode_bounded_array_length(
            &mut decoder,
            DeploymentHardLimitsV2::compiled().max_native_measurements(),
        )
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence)?;
        let mut items = Vec::with_capacity(count);
        for _ in 0..count {
            expect_array(&mut decoder, NATIVE_CONTROL_ITEM_FIELDS_V2)
                .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence)?;
            items.push(NativeControlMeasurementSetItemV2::new(
                decode_digest(&mut decoder)
                    .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence)?,
                decode_digest(&mut decoder)
                    .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence)?,
                decode_digest(&mut decoder)
                    .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence)?,
                decoder
                    .bool()
                    .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence)?,
            )?);
        }
        require_eof(&decoder, bytes)
            .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence)?;
        let value = Self::new(items)?;
        require_canonical(value.canonical_bytes(), bytes)
            .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence)?;
        Ok(value)
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub fn items(&self) -> &[NativeControlMeasurementSetItemV2] {
        &self.items
    }

    pub const fn digest(&self) -> Digest32V2 {
        self.digest
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u16)]
pub enum FrozenEffectWorkKindV2 {
    AgentdPlannerMarker = 1,
    KerneldDispatchWalHead = 2,
    ExecdJournalHead = 3,
}

impl FrozenEffectWorkKindV2 {
    const fn from_tag(tag: u16) -> Option<Self> {
        match tag {
            1 => Some(Self::AgentdPlannerMarker),
            2 => Some(Self::KerneldDispatchWalHead),
            3 => Some(Self::ExecdJournalHead),
            _ => None,
        }
    }

    pub const fn tag(self) -> u16 {
        self as u16
    }

    const fn owning_service(self) -> ClosedServiceIdV2 {
        match self {
            Self::AgentdPlannerMarker => ClosedServiceIdV2::Agentd,
            Self::KerneldDispatchWalHead => ClosedServiceIdV2::Kerneld,
            Self::ExecdJournalHead => ClosedServiceIdV2::Execd,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrozenEffectWorkItemV2 {
    kind: FrozenEffectWorkKindV2,
    owning_service: ClosedServiceIdV2,
    durable_operation_id: Digest32V2,
    nonce_or_request_digest: Digest32V2,
    authenticated_head_digest: Digest32V2,
    observed_state_tag: u16,
}

impl FrozenEffectWorkItemV2 {
    pub fn new(
        kind: FrozenEffectWorkKindV2,
        owning_service: ClosedServiceIdV2,
        durable_operation_id: Digest32V2,
        nonce_or_request_digest: Digest32V2,
        authenticated_head_digest: Digest32V2,
        observed_state_tag: u16,
    ) -> Result<Self, DeploymentControlErrorV2> {
        if owning_service != kind.owning_service()
            || observed_state_tag == 0
            || [
                durable_operation_id,
                nonce_or_request_digest,
                authenticated_head_digest,
            ]
            .iter()
            .any(|digest| is_zero(digest.as_bytes()))
        {
            return Err(DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence);
        }
        Ok(Self {
            kind,
            owning_service,
            durable_operation_id,
            nonce_or_request_digest,
            authenticated_head_digest,
            observed_state_tag,
        })
    }

    pub const fn kind(self) -> FrozenEffectWorkKindV2 {
        self.kind
    }

    pub const fn owning_service(self) -> ClosedServiceIdV2 {
        self.owning_service
    }

    pub const fn durable_operation_id(self) -> Digest32V2 {
        self.durable_operation_id
    }

    pub const fn nonce_or_request_digest(self) -> Digest32V2 {
        self.nonce_or_request_digest
    }

    pub const fn authenticated_head_digest(self) -> Digest32V2 {
        self.authenticated_head_digest
    }

    pub const fn observed_state_tag(self) -> u16 {
        self.observed_state_tag
    }

    fn sort_key(self) -> (u16, u16, [u8; 32], [u8; 32]) {
        (
            self.kind.tag(),
            self.owning_service.tag(),
            *self.durable_operation_id.as_bytes(),
            *self.authenticated_head_digest.as_bytes(),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrozenEffectWorkSetV2 {
    canonical_bytes: Vec<u8>,
    installation_id: Digest32V2,
    transaction_id: Nonce32V2,
    pre_arm_ledger_record_digest: Digest32V2,
    pre_arm_generation: u64,
    pre_arm_effect_fence_epoch: u64,
    items: Vec<FrozenEffectWorkItemV2>,
    frozen_effect_work_set_digest: Digest32V2,
    digest: Digest32V2,
}

impl FrozenEffectWorkSetV2 {
    pub fn new(
        installation_id: Digest32V2,
        transaction_id: Nonce32V2,
        pre_arm_ledger_record_digest: Digest32V2,
        pre_arm_generation: u64,
        pre_arm_effect_fence_epoch: u64,
        items: Vec<FrozenEffectWorkItemV2>,
    ) -> Result<Self, DeploymentControlErrorV2> {
        validate_frozen_work_fields(
            installation_id,
            transaction_id,
            pre_arm_ledger_record_digest,
            pre_arm_generation,
            pre_arm_effect_fence_epoch,
            &items,
        )?;
        let item_bytes = encode_frozen_items(&items)?;
        let frozen_effect_work_set_digest =
            exact_set_digest(FROZEN_EFFECT_WORK_SET_DOMAIN_V2, items.len(), &item_bytes)?;
        let canonical_bytes = encode_frozen_set(
            installation_id,
            transaction_id,
            pre_arm_ledger_record_digest,
            pre_arm_generation,
            pre_arm_effect_fence_epoch,
            &items,
            frozen_effect_work_set_digest,
        )?;
        let digest = hash_domain(FROZEN_EFFECT_WORK_OBJECT_DOMAIN_V2, &canonical_bytes);
        Ok(Self {
            canonical_bytes,
            installation_id,
            transaction_id,
            pre_arm_ledger_record_digest,
            pre_arm_generation,
            pre_arm_effect_fence_epoch,
            items,
            frozen_effect_work_set_digest,
            digest,
        })
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, DeploymentControlErrorV2> {
        check_runtime_evidence_size(bytes)?;
        let mut decoder = minicbor::Decoder::new(bytes);
        expect_array(&mut decoder, FROZEN_EFFECT_WORK_SET_FIELDS_V2)
            .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence)?;
        if decode_u16(&mut decoder)
            .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence)?
            != FROZEN_EFFECT_WORK_SET_SCHEMA_VERSION_V2
        {
            return Err(DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence);
        }
        let installation_id = decode_digest(&mut decoder)
            .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence)?;
        let transaction_id = Nonce32V2::new(
            *decode_digest(&mut decoder)
                .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence)?
                .as_bytes(),
        );
        let pre_arm_ledger_record_digest = decode_digest(&mut decoder)
            .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence)?;
        let pre_arm_generation = decode_u64(&mut decoder)
            .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence)?;
        let pre_arm_effect_fence_epoch = decode_u64(&mut decoder)
            .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence)?;
        let count = decode_bounded_array_length(
            &mut decoder,
            DeploymentHardLimitsV2::compiled().max_plan_steps(),
        )
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence)?;
        let mut items = Vec::with_capacity(count);
        for _ in 0..count {
            items.push(decode_frozen_item(&mut decoder)?);
        }
        let encoded_set_digest = decode_digest(&mut decoder)
            .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence)?;
        require_eof(&decoder, bytes)
            .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence)?;
        let value = Self::new(
            installation_id,
            transaction_id,
            pre_arm_ledger_record_digest,
            pre_arm_generation,
            pre_arm_effect_fence_epoch,
            items,
        )?;
        if value.frozen_effect_work_set_digest != encoded_set_digest {
            return Err(DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence);
        }
        require_canonical(value.canonical_bytes(), bytes)
            .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence)?;
        Ok(value)
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub const fn installation_id(&self) -> Digest32V2 {
        self.installation_id
    }

    pub const fn transaction_id(&self) -> Nonce32V2 {
        self.transaction_id
    }

    pub const fn pre_arm_ledger_record_digest(&self) -> Digest32V2 {
        self.pre_arm_ledger_record_digest
    }

    pub const fn pre_arm_generation(&self) -> u64 {
        self.pre_arm_generation
    }

    pub const fn pre_arm_effect_fence_epoch(&self) -> u64 {
        self.pre_arm_effect_fence_epoch
    }

    pub fn items(&self) -> &[FrozenEffectWorkItemV2] {
        &self.items
    }

    pub const fn frozen_effect_work_set_digest(&self) -> Digest32V2 {
        self.frozen_effect_work_set_digest
    }

    pub const fn digest(&self) -> Digest32V2 {
        self.digest
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoleJournalReconciliationItemV2 {
    kind: FrozenEffectWorkKindV2,
    owning_service: ClosedServiceIdV2,
    durable_operation_id: Digest32V2,
    frozen_authenticated_head_digest: Digest32V2,
    terminal_authenticated_head_digest: Digest32V2,
    terminal_state_tag: u16,
}

impl RoleJournalReconciliationItemV2 {
    pub fn new(
        kind: FrozenEffectWorkKindV2,
        owning_service: ClosedServiceIdV2,
        durable_operation_id: Digest32V2,
        frozen_authenticated_head_digest: Digest32V2,
        terminal_authenticated_head_digest: Digest32V2,
        terminal_state_tag: u16,
    ) -> Result<Self, DeploymentControlErrorV2> {
        if owning_service != kind.owning_service()
            || terminal_state_tag == 0
            || frozen_authenticated_head_digest == terminal_authenticated_head_digest
            || [
                durable_operation_id,
                frozen_authenticated_head_digest,
                terminal_authenticated_head_digest,
            ]
            .iter()
            .any(|digest| is_zero(digest.as_bytes()))
        {
            return Err(DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence);
        }
        Ok(Self {
            kind,
            owning_service,
            durable_operation_id,
            frozen_authenticated_head_digest,
            terminal_authenticated_head_digest,
            terminal_state_tag,
        })
    }

    pub const fn kind(self) -> FrozenEffectWorkKindV2 {
        self.kind
    }

    pub const fn owning_service(self) -> ClosedServiceIdV2 {
        self.owning_service
    }

    pub const fn durable_operation_id(self) -> Digest32V2 {
        self.durable_operation_id
    }

    pub const fn frozen_authenticated_head_digest(self) -> Digest32V2 {
        self.frozen_authenticated_head_digest
    }

    pub const fn terminal_authenticated_head_digest(self) -> Digest32V2 {
        self.terminal_authenticated_head_digest
    }

    pub const fn terminal_state_tag(self) -> u16 {
        self.terminal_state_tag
    }

    fn sort_key(self) -> (u16, u16, [u8; 32], [u8; 32]) {
        (
            self.kind.tag(),
            self.owning_service.tag(),
            *self.durable_operation_id.as_bytes(),
            *self.frozen_authenticated_head_digest.as_bytes(),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleJournalReconciliationV2 {
    canonical_bytes: Vec<u8>,
    installation_id: Digest32V2,
    transaction_id: Nonce32V2,
    frozen_effect_work_set_digest: Digest32V2,
    armed_ledger_record_signed_digest: Digest32V2,
    armed_ledger_generation: u64,
    items: Vec<RoleJournalReconciliationItemV2>,
    role_journal_reconciliation_set_digest: Digest32V2,
    reconciled_at_unix_ms: u64,
    digest: Digest32V2,
}

impl RoleJournalReconciliationV2 {
    pub fn new(
        frozen: &FrozenEffectWorkSetV2,
        armed_ledger_record_signed_digest: Digest32V2,
        armed_ledger_generation: u64,
        items: Vec<RoleJournalReconciliationItemV2>,
        reconciled_at_unix_ms: u64,
    ) -> Result<Self, DeploymentControlErrorV2> {
        let fields = RoleJournalReconciliationFieldsV2 {
            installation_id: frozen.installation_id,
            transaction_id: frozen.transaction_id,
            frozen_effect_work_set_digest: frozen.digest,
            armed_ledger_record_signed_digest,
            armed_ledger_generation,
            items,
            reconciled_at_unix_ms,
        };
        let value = Self::from_fields(fields)?;
        value.validate_frozen_set(frozen)?;
        Ok(value)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, DeploymentControlErrorV2> {
        check_runtime_evidence_size(bytes)?;
        let mut decoder = minicbor::Decoder::new(bytes);
        expect_array(&mut decoder, ROLE_RECONCILIATION_FIELDS_V2)
            .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence)?;
        if decode_u16(&mut decoder)
            .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence)?
            != ROLE_RECONCILIATION_SCHEMA_VERSION_V2
        {
            return Err(DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence);
        }
        let installation_id = decode_digest(&mut decoder)
            .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence)?;
        let transaction_id = Nonce32V2::new(
            *decode_digest(&mut decoder)
                .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence)?
                .as_bytes(),
        );
        let frozen_effect_work_set_digest = decode_digest(&mut decoder)
            .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence)?;
        let armed_ledger_record_signed_digest = decode_digest(&mut decoder)
            .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence)?;
        let armed_ledger_generation = decode_u64(&mut decoder)
            .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence)?;
        let count = decode_bounded_array_length(
            &mut decoder,
            DeploymentHardLimitsV2::compiled().max_plan_steps(),
        )
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence)?;
        let mut items = Vec::with_capacity(count);
        for _ in 0..count {
            items.push(decode_role_reconciliation_item(&mut decoder)?);
        }
        let encoded_set_digest = decode_digest(&mut decoder)
            .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence)?;
        let reconciled_at_unix_ms = decode_u64(&mut decoder)
            .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence)?;
        require_eof(&decoder, bytes)
            .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence)?;
        let value = Self::from_fields(RoleJournalReconciliationFieldsV2 {
            installation_id,
            transaction_id,
            frozen_effect_work_set_digest,
            armed_ledger_record_signed_digest,
            armed_ledger_generation,
            items,
            reconciled_at_unix_ms,
        })?;
        if value.role_journal_reconciliation_set_digest != encoded_set_digest {
            return Err(DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence);
        }
        require_canonical(value.canonical_bytes(), bytes)
            .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence)?;
        Ok(value)
    }

    fn from_fields(
        fields: RoleJournalReconciliationFieldsV2,
    ) -> Result<Self, DeploymentControlErrorV2> {
        validate_role_reconciliation_fields(&fields)?;
        let item_bytes = encode_role_reconciliation_items(&fields.items)?;
        let role_journal_reconciliation_set_digest = exact_set_digest(
            ROLE_RECONCILIATION_SET_DOMAIN_V2,
            fields.items.len(),
            &item_bytes,
        )?;
        let canonical_bytes =
            encode_role_reconciliation(&fields, role_journal_reconciliation_set_digest)?;
        let digest = hash_domain(ROLE_RECONCILIATION_OBJECT_DOMAIN_V2, &canonical_bytes);
        Ok(Self {
            canonical_bytes,
            installation_id: fields.installation_id,
            transaction_id: fields.transaction_id,
            frozen_effect_work_set_digest: fields.frozen_effect_work_set_digest,
            armed_ledger_record_signed_digest: fields.armed_ledger_record_signed_digest,
            armed_ledger_generation: fields.armed_ledger_generation,
            items: fields.items,
            role_journal_reconciliation_set_digest,
            reconciled_at_unix_ms: fields.reconciled_at_unix_ms,
            digest,
        })
    }

    pub fn validate_frozen_set(
        &self,
        frozen: &FrozenEffectWorkSetV2,
    ) -> Result<(), DeploymentControlErrorV2> {
        if self.installation_id != frozen.installation_id
            || self.transaction_id != frozen.transaction_id
            || self.frozen_effect_work_set_digest != frozen.digest
            || self.items.len() != frozen.items.len()
            || self
                .items
                .iter()
                .zip(&frozen.items)
                .any(|(terminal, source)| {
                    terminal.kind != source.kind
                        || terminal.owning_service != source.owning_service
                        || terminal.durable_operation_id != source.durable_operation_id
                        || terminal.frozen_authenticated_head_digest
                            != source.authenticated_head_digest
                })
        {
            return Err(DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence);
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub const fn installation_id(&self) -> Digest32V2 {
        self.installation_id
    }

    pub const fn transaction_id(&self) -> Nonce32V2 {
        self.transaction_id
    }

    pub const fn frozen_effect_work_set_digest(&self) -> Digest32V2 {
        self.frozen_effect_work_set_digest
    }

    pub const fn armed_ledger_record_signed_digest(&self) -> Digest32V2 {
        self.armed_ledger_record_signed_digest
    }

    pub const fn armed_ledger_generation(&self) -> u64 {
        self.armed_ledger_generation
    }

    pub fn items(&self) -> &[RoleJournalReconciliationItemV2] {
        &self.items
    }

    pub const fn role_journal_reconciliation_set_digest(&self) -> Digest32V2 {
        self.role_journal_reconciliation_set_digest
    }

    pub const fn reconciled_at_unix_ms(&self) -> u64 {
        self.reconciled_at_unix_ms
    }

    pub const fn digest(&self) -> Digest32V2 {
        self.digest
    }
}

#[derive(Debug)]
struct RoleJournalReconciliationFieldsV2 {
    installation_id: Digest32V2,
    transaction_id: Nonce32V2,
    frozen_effect_work_set_digest: Digest32V2,
    armed_ledger_record_signed_digest: Digest32V2,
    armed_ledger_generation: u64,
    items: Vec<RoleJournalReconciliationItemV2>,
    reconciled_at_unix_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapBridgeRestoreIntegrityV2 {
    canonical_bytes: Vec<u8>,
    installation_id: Digest32V2,
    installation_epoch: u64,
    transaction_id: Nonce32V2,
    transaction_intent_digest: Digest32V2,
    recovery_target_digest: Digest32V2,
    restore_origin_phase: RollbackOriginPhaseV2,
    bridge_restore_installed_ledger_generation: u64,
    bridge_restore_installed_effect_fence_epoch: u64,
    bridge_manifest_digest: Digest32V2,
    bridge_genesis_ledger_record_signed_digest: Digest32V2,
    bootstrap_slot_closure_digest: Digest32V2,
    premaintenance_runtime_manifest_digest: Digest32V2,
    retained_highest_ever_digest: Digest32V2,
    actual_store_state_set_digest: Digest32V2,
    role_journal_reconciliation_digest: Digest32V2,
    native_effect_fence_measurement_digest: Digest32V2,
    bridge_file_closure_verification_result_digest: Digest32V2,
    verified_at_unix_ms: u64,
    digest: Digest32V2,
}

impl BootstrapBridgeRestoreIntegrityV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        installation_id: Digest32V2,
        installation_epoch: u64,
        transaction_id: Nonce32V2,
        transaction_intent_digest: Digest32V2,
        recovery_target_digest: Digest32V2,
        restore_origin_phase: RollbackOriginPhaseV2,
        bridge_restore_installed_ledger_generation: u64,
        bridge_restore_installed_effect_fence_epoch: u64,
        bridge_manifest_digest: Digest32V2,
        bridge_genesis_ledger_record_signed_digest: Digest32V2,
        bootstrap_slot_closure_digest: Digest32V2,
        premaintenance_runtime_manifest_digest: Digest32V2,
        retained_highest_ever_digest: Digest32V2,
        actual_store_state_set_digest: Digest32V2,
        role_journal_reconciliation_digest: Digest32V2,
        native_effect_fence_measurement_digest: Digest32V2,
        bridge_file_closure_verification_result_digest: Digest32V2,
        verified_at_unix_ms: u64,
    ) -> Result<Self, DeploymentControlErrorV2> {
        Self::from_fields(BridgeRestoreIntegrityFieldsV2 {
            installation_id,
            installation_epoch,
            transaction_id,
            transaction_intent_digest,
            recovery_target_digest,
            restore_origin_phase,
            bridge_restore_installed_ledger_generation,
            bridge_restore_installed_effect_fence_epoch,
            bridge_manifest_digest,
            bridge_genesis_ledger_record_signed_digest,
            bootstrap_slot_closure_digest,
            premaintenance_runtime_manifest_digest,
            retained_highest_ever_digest,
            actual_store_state_set_digest,
            role_journal_reconciliation_digest,
            native_effect_fence_measurement_digest,
            bridge_file_closure_verification_result_digest,
            verified_at_unix_ms,
        })
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, DeploymentControlErrorV2> {
        check_runtime_evidence_size(bytes)?;
        let mut decoder = minicbor::Decoder::new(bytes);
        expect_array(&mut decoder, BRIDGE_RESTORE_INTEGRITY_FIELDS_V2)
            .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence)?;
        if decode_u16(&mut decoder)
            .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence)?
            != BRIDGE_RESTORE_INTEGRITY_SCHEMA_VERSION_V2
        {
            return Err(DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence);
        }
        let installation_id = decode_digest(&mut decoder)
            .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence)?;
        let installation_epoch = decode_u64(&mut decoder)
            .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence)?;
        let transaction_id = Nonce32V2::new(
            *decode_digest(&mut decoder)
                .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence)?
                .as_bytes(),
        );
        let transaction_intent_digest = decode_digest(&mut decoder)
            .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence)?;
        let recovery_target_digest = decode_digest(&mut decoder)
            .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence)?;
        let restore_origin_phase = decode_rollback_origin(
            decode_u16(&mut decoder)
                .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence)?,
        )?;
        let bridge_restore_installed_ledger_generation = decode_u64(&mut decoder)
            .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence)?;
        let bridge_restore_installed_effect_fence_epoch = decode_u64(&mut decoder)
            .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence)?;
        let effects_fenced = decoder
            .bool()
            .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence)?;
        let fields = BridgeRestoreIntegrityFieldsV2 {
            installation_id,
            installation_epoch,
            transaction_id,
            transaction_intent_digest,
            recovery_target_digest,
            restore_origin_phase,
            bridge_restore_installed_ledger_generation,
            bridge_restore_installed_effect_fence_epoch,
            bridge_manifest_digest: decode_digest(&mut decoder)
                .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence)?,
            bridge_genesis_ledger_record_signed_digest: decode_digest(&mut decoder)
                .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence)?,
            bootstrap_slot_closure_digest: decode_digest(&mut decoder)
                .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence)?,
            premaintenance_runtime_manifest_digest: decode_digest(&mut decoder)
                .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence)?,
            retained_highest_ever_digest: decode_digest(&mut decoder)
                .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence)?,
            actual_store_state_set_digest: decode_digest(&mut decoder)
                .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence)?,
            role_journal_reconciliation_digest: decode_digest(&mut decoder)
                .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence)?,
            native_effect_fence_measurement_digest: decode_digest(&mut decoder)
                .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence)?,
            bridge_file_closure_verification_result_digest: decode_digest(&mut decoder)
                .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence)?,
            verified_at_unix_ms: decode_u64(&mut decoder)
                .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence)?,
        };
        require_eof(&decoder, bytes)
            .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence)?;
        if !effects_fenced {
            return Err(DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence);
        }
        let value = Self::from_fields(fields)?;
        require_canonical(value.canonical_bytes(), bytes)
            .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence)?;
        Ok(value)
    }

    fn from_fields(
        fields: BridgeRestoreIntegrityFieldsV2,
    ) -> Result<Self, DeploymentControlErrorV2> {
        validate_bridge_restore_integrity_fields(&fields)?;
        let canonical_bytes = encode_bridge_restore_integrity(&fields)?;
        let digest = hash_domain(BRIDGE_RESTORE_INTEGRITY_DOMAIN_V2, &canonical_bytes);
        Ok(Self {
            canonical_bytes,
            installation_id: fields.installation_id,
            installation_epoch: fields.installation_epoch,
            transaction_id: fields.transaction_id,
            transaction_intent_digest: fields.transaction_intent_digest,
            recovery_target_digest: fields.recovery_target_digest,
            restore_origin_phase: fields.restore_origin_phase,
            bridge_restore_installed_ledger_generation: fields
                .bridge_restore_installed_ledger_generation,
            bridge_restore_installed_effect_fence_epoch: fields
                .bridge_restore_installed_effect_fence_epoch,
            bridge_manifest_digest: fields.bridge_manifest_digest,
            bridge_genesis_ledger_record_signed_digest: fields
                .bridge_genesis_ledger_record_signed_digest,
            bootstrap_slot_closure_digest: fields.bootstrap_slot_closure_digest,
            premaintenance_runtime_manifest_digest: fields.premaintenance_runtime_manifest_digest,
            retained_highest_ever_digest: fields.retained_highest_ever_digest,
            actual_store_state_set_digest: fields.actual_store_state_set_digest,
            role_journal_reconciliation_digest: fields.role_journal_reconciliation_digest,
            native_effect_fence_measurement_digest: fields.native_effect_fence_measurement_digest,
            bridge_file_closure_verification_result_digest: fields
                .bridge_file_closure_verification_result_digest,
            verified_at_unix_ms: fields.verified_at_unix_ms,
            digest,
        })
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub const fn installation_id(&self) -> Digest32V2 {
        self.installation_id
    }

    pub const fn installation_epoch(&self) -> u64 {
        self.installation_epoch
    }

    pub const fn transaction_id(&self) -> Nonce32V2 {
        self.transaction_id
    }

    pub const fn transaction_intent_digest(&self) -> Digest32V2 {
        self.transaction_intent_digest
    }

    pub const fn recovery_target_digest(&self) -> Digest32V2 {
        self.recovery_target_digest
    }

    pub const fn restore_origin_phase(&self) -> RollbackOriginPhaseV2 {
        self.restore_origin_phase
    }

    pub const fn bridge_restore_installed_ledger_generation(&self) -> u64 {
        self.bridge_restore_installed_ledger_generation
    }

    pub const fn bridge_restore_installed_effect_fence_epoch(&self) -> u64 {
        self.bridge_restore_installed_effect_fence_epoch
    }

    pub const fn bridge_manifest_digest(&self) -> Digest32V2 {
        self.bridge_manifest_digest
    }

    pub const fn bridge_genesis_ledger_record_signed_digest(&self) -> Digest32V2 {
        self.bridge_genesis_ledger_record_signed_digest
    }

    pub const fn bootstrap_slot_closure_digest(&self) -> Digest32V2 {
        self.bootstrap_slot_closure_digest
    }

    pub const fn premaintenance_runtime_manifest_digest(&self) -> Digest32V2 {
        self.premaintenance_runtime_manifest_digest
    }

    pub const fn retained_highest_ever_digest(&self) -> Digest32V2 {
        self.retained_highest_ever_digest
    }

    pub const fn actual_store_state_set_digest(&self) -> Digest32V2 {
        self.actual_store_state_set_digest
    }

    pub const fn role_journal_reconciliation_digest(&self) -> Digest32V2 {
        self.role_journal_reconciliation_digest
    }

    pub const fn native_effect_fence_measurement_digest(&self) -> Digest32V2 {
        self.native_effect_fence_measurement_digest
    }

    pub const fn bridge_file_closure_verification_result_digest(&self) -> Digest32V2 {
        self.bridge_file_closure_verification_result_digest
    }

    pub const fn verified_at_unix_ms(&self) -> u64 {
        self.verified_at_unix_ms
    }

    pub const fn digest(&self) -> Digest32V2 {
        self.digest
    }
}

#[derive(Debug, Clone, Copy)]
struct BridgeRestoreIntegrityFieldsV2 {
    installation_id: Digest32V2,
    installation_epoch: u64,
    transaction_id: Nonce32V2,
    transaction_intent_digest: Digest32V2,
    recovery_target_digest: Digest32V2,
    restore_origin_phase: RollbackOriginPhaseV2,
    bridge_restore_installed_ledger_generation: u64,
    bridge_restore_installed_effect_fence_epoch: u64,
    bridge_manifest_digest: Digest32V2,
    bridge_genesis_ledger_record_signed_digest: Digest32V2,
    bootstrap_slot_closure_digest: Digest32V2,
    premaintenance_runtime_manifest_digest: Digest32V2,
    retained_highest_ever_digest: Digest32V2,
    actual_store_state_set_digest: Digest32V2,
    role_journal_reconciliation_digest: Digest32V2,
    native_effect_fence_measurement_digest: Digest32V2,
    bridge_file_closure_verification_result_digest: Digest32V2,
    verified_at_unix_ms: u64,
}

fn validate_native_control_items(
    items: &[NativeControlMeasurementSetItemV2],
) -> Result<(), DeploymentControlErrorV2> {
    if items.is_empty()
        || items.len() as u64 > DeploymentHardLimitsV2::compiled().max_native_measurements()
        || items.windows(2).any(|pair| {
            pair[0].control_identity_digest.as_bytes() >= pair[1].control_identity_digest.as_bytes()
        })
    {
        return Err(DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence);
    }
    Ok(())
}

fn validate_frozen_work_fields(
    installation_id: Digest32V2,
    transaction_id: Nonce32V2,
    pre_arm_ledger_record_digest: Digest32V2,
    pre_arm_generation: u64,
    pre_arm_effect_fence_epoch: u64,
    items: &[FrozenEffectWorkItemV2],
) -> Result<(), DeploymentControlErrorV2> {
    if is_zero(installation_id.as_bytes())
        || is_zero(transaction_id.as_bytes())
        || is_zero(pre_arm_ledger_record_digest.as_bytes())
        || pre_arm_generation == 0
        || pre_arm_effect_fence_epoch == 0
        || items.len() as u64 > DeploymentHardLimitsV2::compiled().max_plan_steps()
        || items
            .windows(2)
            .any(|pair| pair[0].sort_key() >= pair[1].sort_key())
    {
        return Err(DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence);
    }
    Ok(())
}

fn validate_role_reconciliation_fields(
    fields: &RoleJournalReconciliationFieldsV2,
) -> Result<(), DeploymentControlErrorV2> {
    if is_zero(fields.installation_id.as_bytes())
        || is_zero(fields.transaction_id.as_bytes())
        || is_zero(fields.frozen_effect_work_set_digest.as_bytes())
        || is_zero(fields.armed_ledger_record_signed_digest.as_bytes())
        || fields.armed_ledger_generation == 0
        || fields.reconciled_at_unix_ms == 0
        || fields.items.len() as u64 > DeploymentHardLimitsV2::compiled().max_plan_steps()
        || fields
            .items
            .windows(2)
            .any(|pair| pair[0].sort_key() >= pair[1].sort_key())
    {
        return Err(DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence);
    }
    Ok(())
}

fn validate_bridge_restore_integrity_fields(
    fields: &BridgeRestoreIntegrityFieldsV2,
) -> Result<(), DeploymentControlErrorV2> {
    if is_zero(fields.installation_id.as_bytes())
        || is_zero(fields.transaction_id.as_bytes())
        || fields.installation_epoch == 0
        || fields.bridge_restore_installed_ledger_generation == 0
        || fields.bridge_restore_installed_effect_fence_epoch == 0
        || fields.verified_at_unix_ms == 0
        || [
            fields.transaction_intent_digest,
            fields.recovery_target_digest,
            fields.bridge_manifest_digest,
            fields.bridge_genesis_ledger_record_signed_digest,
            fields.bootstrap_slot_closure_digest,
            fields.premaintenance_runtime_manifest_digest,
            fields.retained_highest_ever_digest,
            fields.actual_store_state_set_digest,
            fields.role_journal_reconciliation_digest,
            fields.native_effect_fence_measurement_digest,
            fields.bridge_file_closure_verification_result_digest,
        ]
        .iter()
        .any(|digest| is_zero(digest.as_bytes()))
    {
        return Err(DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence);
    }
    Ok(())
}

fn encode_native_control_items(
    items: &[NativeControlMeasurementSetItemV2],
) -> Result<Vec<u8>, DeploymentControlErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(items.len() as u64)
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence)?;
    for item in items {
        encoder
            .array(NATIVE_CONTROL_ITEM_FIELDS_V2)
            .and_then(|encoder| encoder.bytes(item.control_identity_digest.as_bytes()))
            .and_then(|encoder| encoder.bytes(item.expected_profile_digest.as_bytes()))
            .and_then(|encoder| encoder.bytes(item.measured_value_digest.as_bytes()))
            .and_then(|encoder| encoder.bool(item.passed))
            .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence)?;
    }
    Ok(encoder.into_writer())
}

fn encode_role_reconciliation_items(
    items: &[RoleJournalReconciliationItemV2],
) -> Result<Vec<u8>, DeploymentControlErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(items.len() as u64)
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence)?;
    for item in items {
        encoder
            .array(ROLE_RECONCILIATION_ITEM_FIELDS_V2)
            .and_then(|encoder| encoder.u16(item.kind.tag()))
            .and_then(|encoder| encoder.u16(item.owning_service.tag()))
            .and_then(|encoder| encoder.bytes(item.durable_operation_id.as_bytes()))
            .and_then(|encoder| encoder.bytes(item.frozen_authenticated_head_digest.as_bytes()))
            .and_then(|encoder| encoder.bytes(item.terminal_authenticated_head_digest.as_bytes()))
            .and_then(|encoder| encoder.u16(item.terminal_state_tag))
            .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence)?;
    }
    Ok(encoder.into_writer())
}

fn encode_role_reconciliation(
    fields: &RoleJournalReconciliationFieldsV2,
    set_digest: Digest32V2,
) -> Result<Vec<u8>, DeploymentControlErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(ROLE_RECONCILIATION_FIELDS_V2)
        .and_then(|encoder| encoder.u16(ROLE_RECONCILIATION_SCHEMA_VERSION_V2))
        .and_then(|encoder| encoder.bytes(fields.installation_id.as_bytes()))
        .and_then(|encoder| encoder.bytes(fields.transaction_id.as_bytes()))
        .and_then(|encoder| encoder.bytes(fields.frozen_effect_work_set_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(fields.armed_ledger_record_signed_digest.as_bytes()))
        .and_then(|encoder| encoder.u64(fields.armed_ledger_generation))
        .and_then(|encoder| encoder.array(fields.items.len() as u64))
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence)?;
    for item in &fields.items {
        encoder
            .array(ROLE_RECONCILIATION_ITEM_FIELDS_V2)
            .and_then(|encoder| encoder.u16(item.kind.tag()))
            .and_then(|encoder| encoder.u16(item.owning_service.tag()))
            .and_then(|encoder| encoder.bytes(item.durable_operation_id.as_bytes()))
            .and_then(|encoder| encoder.bytes(item.frozen_authenticated_head_digest.as_bytes()))
            .and_then(|encoder| encoder.bytes(item.terminal_authenticated_head_digest.as_bytes()))
            .and_then(|encoder| encoder.u16(item.terminal_state_tag))
            .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence)?;
    }
    encoder
        .bytes(set_digest.as_bytes())
        .and_then(|encoder| encoder.u64(fields.reconciled_at_unix_ms))
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence)?;
    Ok(encoder.into_writer())
}

fn encode_bridge_restore_integrity(
    fields: &BridgeRestoreIntegrityFieldsV2,
) -> Result<Vec<u8>, DeploymentControlErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(BRIDGE_RESTORE_INTEGRITY_FIELDS_V2)
        .and_then(|encoder| encoder.u16(BRIDGE_RESTORE_INTEGRITY_SCHEMA_VERSION_V2))
        .and_then(|encoder| encoder.bytes(fields.installation_id.as_bytes()))
        .and_then(|encoder| encoder.u64(fields.installation_epoch))
        .and_then(|encoder| encoder.bytes(fields.transaction_id.as_bytes()))
        .and_then(|encoder| encoder.bytes(fields.transaction_intent_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(fields.recovery_target_digest.as_bytes()))
        .and_then(|encoder| encoder.u16(fields.restore_origin_phase as u16))
        .and_then(|encoder| encoder.u64(fields.bridge_restore_installed_ledger_generation))
        .and_then(|encoder| encoder.u64(fields.bridge_restore_installed_effect_fence_epoch))
        .and_then(|encoder| encoder.bool(true))
        .and_then(|encoder| encoder.bytes(fields.bridge_manifest_digest.as_bytes()))
        .and_then(|encoder| {
            encoder.bytes(fields.bridge_genesis_ledger_record_signed_digest.as_bytes())
        })
        .and_then(|encoder| encoder.bytes(fields.bootstrap_slot_closure_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(fields.premaintenance_runtime_manifest_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(fields.retained_highest_ever_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(fields.actual_store_state_set_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(fields.role_journal_reconciliation_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(fields.native_effect_fence_measurement_digest.as_bytes()))
        .and_then(|encoder| {
            encoder.bytes(
                fields
                    .bridge_file_closure_verification_result_digest
                    .as_bytes(),
            )
        })
        .and_then(|encoder| encoder.u64(fields.verified_at_unix_ms))
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence)?;
    Ok(encoder.into_writer())
}

fn encode_frozen_items(
    items: &[FrozenEffectWorkItemV2],
) -> Result<Vec<u8>, DeploymentControlErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(items.len() as u64)
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence)?;
    for item in items {
        encode_frozen_item(&mut encoder, *item)?;
    }
    Ok(encoder.into_writer())
}

fn encode_frozen_set(
    installation_id: Digest32V2,
    transaction_id: Nonce32V2,
    pre_arm_ledger_record_digest: Digest32V2,
    pre_arm_generation: u64,
    pre_arm_effect_fence_epoch: u64,
    items: &[FrozenEffectWorkItemV2],
    set_digest: Digest32V2,
) -> Result<Vec<u8>, DeploymentControlErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(FROZEN_EFFECT_WORK_SET_FIELDS_V2)
        .and_then(|encoder| encoder.u16(FROZEN_EFFECT_WORK_SET_SCHEMA_VERSION_V2))
        .and_then(|encoder| encoder.bytes(installation_id.as_bytes()))
        .and_then(|encoder| encoder.bytes(transaction_id.as_bytes()))
        .and_then(|encoder| encoder.bytes(pre_arm_ledger_record_digest.as_bytes()))
        .and_then(|encoder| encoder.u64(pre_arm_generation))
        .and_then(|encoder| encoder.u64(pre_arm_effect_fence_epoch))
        .and_then(|encoder| encoder.array(items.len() as u64))
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence)?;
    for item in items {
        encode_frozen_item(&mut encoder, *item)?;
    }
    encoder
        .bytes(set_digest.as_bytes())
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence)?;
    Ok(encoder.into_writer())
}

fn encode_frozen_item(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    item: FrozenEffectWorkItemV2,
) -> Result<(), DeploymentControlErrorV2> {
    encoder
        .array(FROZEN_EFFECT_WORK_ITEM_FIELDS_V2)
        .and_then(|encoder| encoder.u16(item.kind.tag()))
        .and_then(|encoder| encoder.u16(item.owning_service.tag()))
        .and_then(|encoder| encoder.bytes(item.durable_operation_id.as_bytes()))
        .and_then(|encoder| encoder.bytes(item.nonce_or_request_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(item.authenticated_head_digest.as_bytes()))
        .and_then(|encoder| encoder.u16(item.observed_state_tag))
        .map(|_| ())
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence)
}

fn decode_frozen_item(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<FrozenEffectWorkItemV2, DeploymentControlErrorV2> {
    expect_array(decoder, FROZEN_EFFECT_WORK_ITEM_FIELDS_V2)
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence)?;
    let kind = FrozenEffectWorkKindV2::from_tag(
        decode_u16(decoder)
            .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence)?,
    )
    .ok_or(DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence)?;
    let service = decode_service(
        decode_u16(decoder)
            .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence)?,
    )?;
    FrozenEffectWorkItemV2::new(
        kind,
        service,
        decode_digest(decoder)
            .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence)?,
        decode_digest(decoder)
            .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence)?,
        decode_digest(decoder)
            .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence)?,
        decode_u16(decoder)
            .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence)?,
    )
}

fn decode_role_reconciliation_item(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<RoleJournalReconciliationItemV2, DeploymentControlErrorV2> {
    expect_array(decoder, ROLE_RECONCILIATION_ITEM_FIELDS_V2)
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence)?;
    let kind = FrozenEffectWorkKindV2::from_tag(
        decode_u16(decoder)
            .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence)?,
    )
    .ok_or(DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence)?;
    let service = decode_service(
        decode_u16(decoder)
            .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence)?,
    )?;
    RoleJournalReconciliationItemV2::new(
        kind,
        service,
        decode_digest(decoder)
            .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence)?,
        decode_digest(decoder)
            .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence)?,
        decode_digest(decoder)
            .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence)?,
        decode_u16(decoder)
            .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence)?,
    )
}

fn decode_rollback_origin(tag: u16) -> Result<RollbackOriginPhaseV2, DeploymentControlErrorV2> {
    match tag {
        1 => Ok(RollbackOriginPhaseV2::Armed),
        2 => Ok(RollbackOriginPhaseV2::Quiesced),
        3 => Ok(RollbackOriginPhaseV2::Installed),
        4 => Ok(RollbackOriginPhaseV2::Verified),
        _ => Err(DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence),
    }
}

fn decode_service(tag: u16) -> Result<ClosedServiceIdV2, DeploymentControlErrorV2> {
    match tag {
        1 => Ok(ClosedServiceIdV2::Kerneld),
        2 => Ok(ClosedServiceIdV2::Agentd),
        3 => Ok(ClosedServiceIdV2::Ingressd),
        4 => Ok(ClosedServiceIdV2::Approvald),
        5 => Ok(ClosedServiceIdV2::Execd),
        _ => Err(DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence),
    }
}

fn exact_set_digest(
    domain: &[u8],
    count: usize,
    canonical_items: &[u8],
) -> Result<Digest32V2, DeploymentControlErrorV2> {
    let count = u64::try_from(count)
        .map_err(|_| DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence)?;
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(count.to_be_bytes());
    hash.update(canonical_items);
    Ok(Digest32V2::new(hash.finalize().into()))
}

fn check_runtime_evidence_size(bytes: &[u8]) -> Result<(), DeploymentControlErrorV2> {
    if bytes.is_empty()
        || u64::try_from(bytes.len()).ok().is_none_or(|length| {
            length > DeploymentHardLimitsV2::compiled().max_attestation_bytes()
        })
    {
        return Err(DeploymentControlErrorV2::InvalidDeploymentRuntimeEvidence);
    }
    Ok(())
}
