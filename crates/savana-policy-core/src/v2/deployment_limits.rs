use savana_kernel_protocol::v2::Digest32V2;
use sha2::{Digest as _, Sha256};

use super::descriptor::MAX_ACTIVE_TOOL_DESCRIPTORS;

const HARD_LIMITS_DOMAIN_V2: &[u8] = b"savana.deployment-hard-limits.v2\0";

const HARD_LIMIT_VALUES_V2: [u64; 32] = [
    1_048_576,
    4_194_304,
    4_194_304,
    4_096,
    4_096,
    4_096,
    32,
    4_096,
    86_400_000_000_000,
    3_600_000_000_000,
    3_600_000_000_000,
    300_000_000_000,
    65_536,
    64,
    8_589_934_592,
    68_719_476_736,
    4_096,
    64,
    64,
    64,
    64,
    64,
    256,
    65_536,
    1_073_741_824,
    64,
    4_096,
    16_777_216,
    255,
    64,
    16,
    16,
];

const HARD_LIMITS_CANONICAL_CBOR_V2: &[u8] = &[
    0x98, 0x20, 0x1a, 0x00, 0x10, 0x00, 0x00, 0x1a, 0x00, 0x40, 0x00, 0x00, 0x1a, 0x00, 0x40, 0x00,
    0x00, 0x19, 0x10, 0x00, 0x19, 0x10, 0x00, 0x19, 0x10, 0x00, 0x18, 0x20, 0x19, 0x10, 0x00, 0x1b,
    0x00, 0x00, 0x4e, 0x94, 0x91, 0x4f, 0x00, 0x00, 0x1b, 0x00, 0x00, 0x03, 0x46, 0x30, 0xb8, 0xa0,
    0x00, 0x1b, 0x00, 0x00, 0x03, 0x46, 0x30, 0xb8, 0xa0, 0x00, 0x1b, 0x00, 0x00, 0x00, 0x45, 0xd9,
    0x64, 0xb8, 0x00, 0x1a, 0x00, 0x01, 0x00, 0x00, 0x18, 0x40, 0x1b, 0x00, 0x00, 0x00, 0x02, 0x00,
    0x00, 0x00, 0x00, 0x1b, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x19, 0x10, 0x00, 0x18,
    0x40, 0x18, 0x40, 0x18, 0x40, 0x18, 0x40, 0x18, 0x40, 0x19, 0x01, 0x00, 0x1a, 0x00, 0x01, 0x00,
    0x00, 0x1a, 0x40, 0x00, 0x00, 0x00, 0x18, 0x40, 0x19, 0x10, 0x00, 0x1a, 0x01, 0x00, 0x00, 0x00,
    0x18, 0xff, 0x18, 0x40, 0x10, 0x10,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeploymentHardLimitsV2;

impl DeploymentHardLimitsV2 {
    pub const fn compiled() -> Self {
        Self
    }

    pub const fn values(self) -> &'static [u64; 32] {
        &HARD_LIMIT_VALUES_V2
    }

    pub const fn canonical_bytes(self) -> &'static [u8] {
        HARD_LIMITS_CANONICAL_CBOR_V2
    }

    pub fn digest(self) -> Digest32V2 {
        let mut hash = Sha256::new();
        hash.update(HARD_LIMITS_DOMAIN_V2);
        hash.update(HARD_LIMITS_CANONICAL_CBOR_V2);
        Digest32V2::new(hash.finalize().into())
    }

    pub const fn max_transaction_bytes(self) -> u64 {
        HARD_LIMIT_VALUES_V2[0]
    }

    pub const fn max_manifest_bytes(self) -> u64 {
        HARD_LIMIT_VALUES_V2[1]
    }

    pub const fn max_plan_bytes(self) -> u64 {
        HARD_LIMIT_VALUES_V2[2]
    }

    pub const fn max_plan_steps(self) -> u64 {
        HARD_LIMIT_VALUES_V2[3]
    }

    pub const fn max_transaction_head_records(self) -> u64 {
        HARD_LIMIT_VALUES_V2[4]
    }

    pub const fn max_ledger_predecessor_records(self) -> u64 {
        HARD_LIMIT_VALUES_V2[5]
    }

    pub const fn max_active_tool_descriptors(self) -> u64 {
        MAX_ACTIVE_TOOL_DESCRIPTORS as u64
    }

    pub const fn max_prepare_duration_ns(self) -> u64 {
        HARD_LIMIT_VALUES_V2[8]
    }

    pub const fn max_cutover_duration_ns(self) -> u64 {
        HARD_LIMIT_VALUES_V2[9]
    }

    pub const fn max_boot_recovery_duration_ns(self) -> u64 {
        HARD_LIMIT_VALUES_V2[10]
    }

    pub const fn max_clock_skew_ns(self) -> u64 {
        HARD_LIMIT_VALUES_V2[11]
    }

    pub const fn max_file_tree_entries(self) -> u64 {
        HARD_LIMIT_VALUES_V2[12]
    }

    pub const fn max_file_tree_depth(self) -> u64 {
        HARD_LIMIT_VALUES_V2[13]
    }

    pub const fn max_single_artifact_bytes(self) -> u64 {
        HARD_LIMIT_VALUES_V2[14]
    }

    pub const fn max_staging_tree_bytes(self) -> u64 {
        HARD_LIMIT_VALUES_V2[15]
    }

    pub const fn max_component_signatures(self) -> u64 {
        HARD_LIMIT_VALUES_V2[16]
    }

    pub const fn max_operational_trust_roots(self) -> u64 {
        HARD_LIMIT_VALUES_V2[17]
    }

    pub const fn max_release_trust_roots(self) -> u64 {
        HARD_LIMIT_VALUES_V2[18]
    }

    pub const fn max_persistent_stores(self) -> u64 {
        HARD_LIMIT_VALUES_V2[19]
    }

    pub const fn max_agent_claim_compatibility_edges(self) -> u64 {
        HARD_LIMIT_VALUES_V2[20]
    }

    pub const fn max_agent_claim_vault_key_reads(self) -> u64 {
        HARD_LIMIT_VALUES_V2[21]
    }

    pub const fn max_agent_claim_view_projections(self) -> u64 {
        HARD_LIMIT_VALUES_V2[22]
    }

    pub const fn max_native_measurements(self) -> u64 {
        HARD_LIMIT_VALUES_V2[26]
    }

    pub const fn max_attestation_bytes(self) -> u64 {
        HARD_LIMIT_VALUES_V2[27]
    }

    pub const fn max_text_identifier_bytes(self) -> u64 {
        HARD_LIMIT_VALUES_V2[28]
    }

    pub const fn max_declassification_rules(self) -> u64 {
        HARD_LIMIT_VALUES_V2[29]
    }

    pub const fn max_declassification_readers(self) -> u64 {
        HARD_LIMIT_VALUES_V2[30]
    }

    pub const fn max_user_connectors(self) -> u64 {
        HARD_LIMIT_VALUES_V2[31]
    }
}
