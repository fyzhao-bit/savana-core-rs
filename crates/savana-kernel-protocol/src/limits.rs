use crate::{ProtocolError, ResourceLimitsV1, StableCode};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HardLimits {
    frame_bytes: u64,
    cbor_depth: u64,
    pages: u64,
    chars_per_page: u64,
    chars_per_document: u64,
    observations: u64,
    vault_entries: u64,
    vault_raw_bytes: u64,
    runs_per_client: u64,
    vaults_per_client: u64,
    approval_ledger_entries: u64,
    model_manifest_bytes: u64,
    model_assets: u64,
    model_tensor_contracts: u64,
    model_tensor_rank: u64,
    single_model_asset_bytes: u64,
    total_model_asset_bytes: u64,
    ner_workers: u64,
    ner_queue: u64,
    ner_text_bytes: u64,
    model_probes: u64,
    model_probe_spans: u64,
    ner_failure_threshold: u64,
    request_deadline_ms: u64,
    policy_tools: u64,
    policy_authorities: u64,
    policy_error_mappings: u64,
    policy_model_digests: u64,
    policy_tool_name_set: u64,
    policy_valid_pairs: u64,
    policy_attempt_limits: u64,
    policy_snapshot_authorities: u64,
    policy_validator_requirements: u64,
    policy_validators_per_tool: u64,
    policy_constraints_per_tool: u64,
    policy_release_targets: u64,
}

macro_rules! limit_getters {
    (direct; $($field:ident),+ $(,)?) => {
        $(
            pub const fn $field(&self) -> u64 {
                self.$field
            }
        )+
    };
    ($target:ident; $($field:ident),+ $(,)?) => {
        $(
            pub const fn $field(&self) -> u64 {
                self.$target.$field
            }
        )+
    };
}

impl HardLimits {
    pub const COMPILED: Self = Self {
        frame_bytes: 8 * 1024 * 1024,
        cbor_depth: 32,
        pages: 2_048,
        chars_per_page: 50_000,
        chars_per_document: 1_000_000,
        observations: 100_000,
        vault_entries: 20_000,
        vault_raw_bytes: 32 * 1024 * 1024,
        runs_per_client: 128,
        vaults_per_client: 512,
        approval_ledger_entries: 65_536,
        model_manifest_bytes: 256 * 1024,
        model_assets: 32,
        model_tensor_contracts: 32,
        model_tensor_rank: 8,
        single_model_asset_bytes: 256 * 1024 * 1024,
        total_model_asset_bytes: 512 * 1024 * 1024,
        ner_workers: 4,
        ner_queue: 128,
        ner_text_bytes: 200_000,
        model_probes: 16,
        model_probe_spans: 512,
        ner_failure_threshold: 32,
        request_deadline_ms: 120_000,
        policy_tools: 256,
        policy_authorities: 64,
        policy_error_mappings: 256,
        policy_model_digests: 32,
        policy_tool_name_set: 256,
        policy_valid_pairs: 1_536,
        policy_attempt_limits: 6,
        policy_snapshot_authorities: 16,
        policy_validator_requirements: 256,
        policy_validators_per_tool: 32,
        policy_constraints_per_tool: 64,
        policy_release_targets: 16,
    };

    limit_getters!(direct;
        frame_bytes,
        cbor_depth,
        pages,
        chars_per_page,
        chars_per_document,
        observations,
        vault_entries,
        vault_raw_bytes,
        runs_per_client,
        vaults_per_client,
        approval_ledger_entries,
        model_manifest_bytes,
        model_assets,
        model_tensor_contracts,
        model_tensor_rank,
        single_model_asset_bytes,
        total_model_asset_bytes,
        ner_workers,
        ner_queue,
        ner_text_bytes,
        model_probes,
        model_probe_spans,
        ner_failure_threshold,
        request_deadline_ms,
        policy_tools,
        policy_authorities,
        policy_error_mappings,
        policy_model_digests,
        policy_tool_name_set,
        policy_valid_pairs,
        policy_attempt_limits,
        policy_snapshot_authorities,
        policy_validator_requirements,
        policy_validators_per_tool,
        policy_constraints_per_tool,
        policy_release_targets,
    );

    pub fn lower(&self, requested: &ResourceLimitsV1) -> Result<EffectiveLimits, ProtocolError> {
        if requested.frame_bytes > self.frame_bytes
            || requested.cbor_depth > self.cbor_depth
            || requested.pages > self.pages
            || requested.chars_per_page > self.chars_per_page
            || requested.chars_per_document > self.chars_per_document
            || requested.observations > self.observations
            || requested.vault_entries > self.vault_entries
            || requested.vault_raw_bytes > self.vault_raw_bytes
            || requested.runs_per_client > self.runs_per_client
            || requested.vaults_per_client > self.vaults_per_client
            || requested.approval_ledger_entries > self.approval_ledger_entries
            || requested.model_manifest_bytes > self.model_manifest_bytes
            || requested.model_assets > self.model_assets
            || requested.model_tensor_contracts > self.model_tensor_contracts
            || requested.model_tensor_rank > self.model_tensor_rank
            || requested.single_model_asset_bytes > self.single_model_asset_bytes
            || requested.total_model_asset_bytes > self.total_model_asset_bytes
            || requested.ner_workers > self.ner_workers
            || requested.ner_queue > self.ner_queue
            || requested.ner_text_bytes > self.ner_text_bytes
            || requested.model_probes > self.model_probes
            || requested.model_probe_spans > self.model_probe_spans
            || requested.ner_failure_threshold > self.ner_failure_threshold
            || requested.request_deadline_ms > self.request_deadline_ms
        {
            return Err(ProtocolError::stable(StableCode::PolicyLimitExceeded));
        }

        Ok(EffectiveLimits::from_lowered(self, requested))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EffectiveLimits {
    limits: ResourceLimitsV1,
}

impl EffectiveLimits {
    fn from_lowered(_hard: &HardLimits, requested: &ResourceLimitsV1) -> Self {
        Self { limits: *requested }
    }

    limit_getters!(limits;
        frame_bytes,
        cbor_depth,
        pages,
        chars_per_page,
        chars_per_document,
        observations,
        vault_entries,
        vault_raw_bytes,
        runs_per_client,
        vaults_per_client,
        approval_ledger_entries,
        model_manifest_bytes,
        model_assets,
        model_tensor_contracts,
        model_tensor_rank,
        single_model_asset_bytes,
        total_model_asset_bytes,
        ner_workers,
        ner_queue,
        ner_text_bytes,
        model_probes,
        model_probe_spans,
        ner_failure_threshold,
        request_deadline_ms,
    );

    pub(crate) fn check_frame_bytes(&self, length: usize) -> Result<(), ProtocolError> {
        let length = u64::try_from(length)
            .map_err(|_| ProtocolError::stable(StableCode::ProtocolFrameTooLarge))?;
        if length > self.frame_bytes() {
            return Err(ProtocolError::stable(StableCode::ProtocolFrameTooLarge));
        }
        Ok(())
    }

    pub(crate) fn check_wire_items(&self, length: u64) -> Result<(), ProtocolError> {
        if length > self.frame_bytes() {
            return Err(ProtocolError::stable(StableCode::ProtocolFrameTooLarge));
        }
        Ok(())
    }

    pub(crate) fn check_wire_bytes(&self, length: usize) -> Result<(), ProtocolError> {
        self.check_frame_bytes(length)
    }
}
