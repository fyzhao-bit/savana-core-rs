use savana_kernel_protocol::v2::Digest32V2;

use super::deployment_manifest_primitives::{
    check_manifest_object_size, decode_bounded_array_length, decode_digest, decode_nested,
    decode_u16, decode_u64, expect_array, hash_domain, is_zero, require_canonical, require_eof,
};
use super::{
    ClosedDigestRuleV2, ClosedStoreIdV2, DeploymentControlErrorV2, DeploymentHardLimitsV2,
    InclusiveEpochRangeV2,
};

const PERSISTENT_STORE_COMPATIBILITY_FIELDS_V2: u64 = 9;
const PERSISTENT_STORE_COMPATIBILITY_DOMAIN_V2: &[u8] =
    b"savana.persistent-store-compatibility.v2\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistentStoreCompatibilityV2 {
    canonical_bytes: Vec<u8>,
    store_id: ClosedStoreIdV2,
    expected_current_schema_epoch: u64,
    desired_reader_range: InclusiveEpochRangeV2,
    desired_writer_range: InclusiveEpochRangeV2,
    rollback_reader_range: InclusiveEpochRangeV2,
    rollback_writer_range: InclusiveEpochRangeV2,
    migration_digest: Digest32V2,
    post_migration_state_digest_rule: ClosedDigestRuleV2,
    validator_artifact_digest: Digest32V2,
    digest: Digest32V2,
}

impl PersistentStoreCompatibilityV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        store_id: ClosedStoreIdV2,
        expected_current_schema_epoch: u64,
        desired_reader_range: InclusiveEpochRangeV2,
        desired_writer_range: InclusiveEpochRangeV2,
        rollback_reader_range: InclusiveEpochRangeV2,
        rollback_writer_range: InclusiveEpochRangeV2,
        migration_digest: Digest32V2,
        post_migration_state_digest_rule: ClosedDigestRuleV2,
        validator_artifact_digest: Digest32V2,
    ) -> Result<Self, DeploymentControlErrorV2> {
        if expected_current_schema_epoch == 0
            || !desired_reader_range.contains(desired_writer_range.minimum())
            || !desired_reader_range.contains(desired_writer_range.maximum())
            || !rollback_reader_range.contains(rollback_writer_range.minimum())
            || !rollback_reader_range.contains(rollback_writer_range.maximum())
            || is_zero(migration_digest.as_bytes())
            || is_zero(validator_artifact_digest.as_bytes())
        {
            return Err(DeploymentControlErrorV2::InvalidSecurityStateManifest);
        }
        let mut encoder = minicbor::Encoder::new(Vec::new());
        encoder
            .array(PERSISTENT_STORE_COMPATIBILITY_FIELDS_V2)
            .and_then(|encoder| encoder.u16(store_id.tag()))
            .and_then(|encoder| encoder.u64(expected_current_schema_epoch))
            .map_err(|_| DeploymentControlErrorV2::InvalidSecurityStateManifest)?;
        for range in [
            desired_reader_range,
            desired_writer_range,
            rollback_reader_range,
            rollback_writer_range,
        ] {
            encoder
                .writer_mut()
                .extend_from_slice(range.canonical_bytes());
        }
        encoder
            .bytes(migration_digest.as_bytes())
            .and_then(|encoder| encoder.u16(post_migration_state_digest_rule.tag()))
            .and_then(|encoder| encoder.bytes(validator_artifact_digest.as_bytes()))
            .map_err(|_| DeploymentControlErrorV2::InvalidSecurityStateManifest)?;
        let canonical_bytes = encoder.into_writer();
        Ok(Self {
            digest: hash_domain(PERSISTENT_STORE_COMPATIBILITY_DOMAIN_V2, &canonical_bytes),
            canonical_bytes,
            store_id,
            expected_current_schema_epoch,
            desired_reader_range,
            desired_writer_range,
            rollback_reader_range,
            rollback_writer_range,
            migration_digest,
            post_migration_state_digest_rule,
            validator_artifact_digest,
        })
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, DeploymentControlErrorV2> {
        check_manifest_object_size(bytes)?;
        let mut decoder = minicbor::Decoder::new(bytes);
        expect_array(&mut decoder, PERSISTENT_STORE_COMPATIBILITY_FIELDS_V2)?;
        let store_id = ClosedStoreIdV2::from_tag(decode_u16(&mut decoder)?)
            .ok_or(DeploymentControlErrorV2::InvalidSecurityStateManifest)?;
        let expected_current_schema_epoch = decode_u64(&mut decoder)?;
        let desired_reader_range =
            decode_nested(&mut decoder, InclusiveEpochRangeV2::from_canonical_bytes)?;
        let desired_writer_range =
            decode_nested(&mut decoder, InclusiveEpochRangeV2::from_canonical_bytes)?;
        let rollback_reader_range =
            decode_nested(&mut decoder, InclusiveEpochRangeV2::from_canonical_bytes)?;
        let rollback_writer_range =
            decode_nested(&mut decoder, InclusiveEpochRangeV2::from_canonical_bytes)?;
        let migration_digest = decode_digest(&mut decoder)?;
        let post_migration_state_digest_rule =
            ClosedDigestRuleV2::from_tag(decode_u16(&mut decoder)?)
                .ok_or(DeploymentControlErrorV2::InvalidSecurityStateManifest)?;
        let validator_artifact_digest = decode_digest(&mut decoder)?;
        require_eof(&decoder, bytes)?;
        let value = Self::new(
            store_id,
            expected_current_schema_epoch,
            desired_reader_range,
            desired_writer_range,
            rollback_reader_range,
            rollback_writer_range,
            migration_digest,
            post_migration_state_digest_rule,
            validator_artifact_digest,
        )?;
        require_canonical(value.canonical_bytes(), bytes)?;
        Ok(value)
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub const fn store_id(&self) -> ClosedStoreIdV2 {
        self.store_id
    }

    pub const fn expected_current_schema_epoch(&self) -> u64 {
        self.expected_current_schema_epoch
    }

    pub const fn desired_reader_range(&self) -> InclusiveEpochRangeV2 {
        self.desired_reader_range
    }

    pub const fn desired_writer_range(&self) -> InclusiveEpochRangeV2 {
        self.desired_writer_range
    }

    pub const fn rollback_reader_range(&self) -> InclusiveEpochRangeV2 {
        self.rollback_reader_range
    }

    pub const fn rollback_writer_range(&self) -> InclusiveEpochRangeV2 {
        self.rollback_writer_range
    }

    pub const fn migration_digest(&self) -> Digest32V2 {
        self.migration_digest
    }

    pub const fn post_migration_state_digest_rule(&self) -> ClosedDigestRuleV2 {
        self.post_migration_state_digest_rule
    }

    pub const fn validator_artifact_digest(&self) -> Digest32V2 {
        self.validator_artifact_digest
    }

    pub const fn digest(&self) -> Digest32V2 {
        self.digest
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistentStoreCompatibilitySetV2 {
    canonical_bytes: Vec<u8>,
    entries: [PersistentStoreCompatibilityV2; 18],
}

impl PersistentStoreCompatibilitySetV2 {
    pub fn new(
        entries: [PersistentStoreCompatibilityV2; 18],
    ) -> Result<Self, DeploymentControlErrorV2> {
        if entries
            .iter()
            .zip(ClosedStoreIdV2::ALL)
            .any(|(entry, expected)| entry.store_id() != *expected)
        {
            return Err(DeploymentControlErrorV2::InvalidSecurityStateManifest);
        }
        let mut encoder = minicbor::Encoder::new(Vec::new());
        encoder
            .array(entries.len() as u64)
            .map_err(|_| DeploymentControlErrorV2::InvalidSecurityStateManifest)?;
        for entry in &entries {
            encoder
                .writer_mut()
                .extend_from_slice(entry.canonical_bytes());
        }
        Ok(Self {
            canonical_bytes: encoder.into_writer(),
            entries,
        })
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, DeploymentControlErrorV2> {
        check_manifest_object_size(bytes)?;
        let mut decoder = minicbor::Decoder::new(bytes);
        let count = decode_bounded_array_length(
            &mut decoder,
            DeploymentHardLimitsV2::compiled().max_persistent_stores(),
        )?;
        if count != ClosedStoreIdV2::ALL.len() {
            return Err(DeploymentControlErrorV2::InvalidSecurityStateManifest);
        }
        let mut entries = Vec::with_capacity(count);
        for _ in 0..count {
            entries.push(decode_nested(
                &mut decoder,
                PersistentStoreCompatibilityV2::from_canonical_bytes,
            )?);
        }
        require_eof(&decoder, bytes)?;
        let entries: [PersistentStoreCompatibilityV2; 18] = entries
            .try_into()
            .map_err(|_| DeploymentControlErrorV2::InvalidSecurityStateManifest)?;
        let value = Self::new(entries)?;
        require_canonical(value.canonical_bytes(), bytes)?;
        Ok(value)
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub const fn entries(&self) -> &[PersistentStoreCompatibilityV2; 18] {
        &self.entries
    }

    pub const fn entry(&self, store_id: ClosedStoreIdV2) -> &PersistentStoreCompatibilityV2 {
        &self.entries[store_id.tag() as usize - 1]
    }
}
