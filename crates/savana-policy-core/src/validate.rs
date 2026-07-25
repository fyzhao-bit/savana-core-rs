use std::cmp::Ordering;

use savana_kernel_protocol::{
    AttemptKindV1, ConstraintId, Digest32, EffectiveLimits, HardLimits, KeyId, StableCode,
    ToolName, UnixMillis, ValidatorId, PROTOCOL_MAJOR, PROTOCOL_MINOR,
};
use sha2::{Digest, Sha256};

use crate::bundle::{
    AllowedToolV1, AuthorityKeyV1, AuthorityRoleV1, PolicyBundleV1, ToolAttemptV1,
};
use crate::PolicyError;

const MAXIMUM_PER_RUN: u32 = 65_536;
const MAXIMUM_TTL_SECONDS: u32 = 120;
const MAXIMUM_SNAPSHOT_ENTRIES: u32 = 100_000;
const MAXIMUM_CONSTRAINTS_PER_TOOL: u16 = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyIdentity {
    pub digest: Digest32,
    pub policy_version: u64,
    pub key_epoch: u64,
    pub expires_at: UnixMillis,
}

#[derive(Clone, PartialEq, Eq)]
pub struct VerifiedPolicyV1 {
    bundle: PolicyBundleV1,
    identity: PolicyIdentity,
    effective_limits: EffectiveLimits,
    signature_digest: Digest32,
    signing_public_key: [u8; 32],
    active_release_target_id: Digest32,
    resource_profile_digest: Digest32,
}

impl std::fmt::Debug for VerifiedPolicyV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("VerifiedPolicyV1(<verified>)")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedAuthorityV1<'policy> {
    authority: &'policy AuthorityKeyV1,
}

impl VerifiedAuthorityV1<'_> {
    pub const fn key_id(&self) -> &KeyId {
        &self.authority.key_id
    }

    pub const fn role(&self) -> AuthorityRoleV1 {
        self.authority.role
    }

    pub const fn public_key(&self) -> &[u8; 32] {
        &self.authority.public_key
    }

    pub const fn epoch(&self) -> u64 {
        self.authority.epoch
    }

    pub const fn not_before(&self) -> UnixMillis {
        self.authority.not_before
    }

    pub const fn not_after(&self) -> UnixMillis {
        self.authority.not_after
    }
}

impl VerifiedPolicyV1 {
    pub const fn identity(&self) -> PolicyIdentity {
        self.identity
    }

    pub const fn effective_limits(&self) -> &EffectiveLimits {
        &self.effective_limits
    }

    pub const fn signing_key_id(&self) -> &KeyId {
        &self.bundle.signing_key_id
    }

    pub(crate) const fn signature_digest(&self) -> Digest32 {
        self.signature_digest
    }

    pub(crate) const fn signing_public_key(&self) -> &[u8; 32] {
        &self.signing_public_key
    }

    pub(crate) const fn active_release_target_id(&self) -> Digest32 {
        self.active_release_target_id
    }

    pub const fn resource_profile_digest(&self) -> Digest32 {
        self.resource_profile_digest
    }

    pub fn authority(
        &self,
        key_id: &KeyId,
        role: AuthorityRoleV1,
    ) -> Option<VerifiedAuthorityV1<'_>> {
        self.bundle
            .authorities
            .iter()
            .find(|authority| {
                authority.key_id == *key_id
                    && authority.role == role
                    && authority_valid_for_policy(authority, &self.bundle)
            })
            .map(|authority| VerifiedAuthorityV1 { authority })
    }
}

pub(crate) fn validate_policy(
    bundle: PolicyBundleV1,
    canonical_bytes: &[u8],
    signature_digest: Digest32,
    signing_public_key: [u8; 32],
    active_release_target_id: Digest32,
    now: UnixMillis,
) -> Result<VerifiedPolicyV1, PolicyError> {
    validate_version_and_time(&bundle, now)?;
    validate_scalars(&bundle)?;
    let effective_limits = HardLimits::COMPILED.lower(&bundle.resources)?;
    validate_ordering(&bundle)?;
    validate_authorities(&bundle)?;
    validate_tools_and_attempts(&bundle)?;
    validate_ontology_and_validators(&bundle)?;
    validate_release_and_mappings(&bundle, active_release_target_id)?;
    let canonical_resources = minicbor::to_vec(bundle.resources).map_err(PolicyError::io)?;
    let resource_profile_digest =
        domain_digest(b"SAVANA_RESOURCE_PROFILE_V1\0", &canonical_resources);

    let identity = PolicyIdentity {
        digest: Digest32::new(Sha256::digest(canonical_bytes).into()),
        policy_version: bundle.policy_version,
        key_epoch: bundle.key_epoch,
        expires_at: bundle.expires_at,
    };
    Ok(VerifiedPolicyV1 {
        bundle,
        identity,
        effective_limits,
        signature_digest,
        signing_public_key,
        active_release_target_id,
        resource_profile_digest,
    })
}

fn validate_version_and_time(bundle: &PolicyBundleV1, now: UnixMillis) -> Result<(), PolicyError> {
    if bundle.schema_version != 1
        || bundle.protocol.major != PROTOCOL_MAJOR
        || bundle.protocol.minimum_minor > PROTOCOL_MINOR
    {
        return Err(PolicyError::stable(StableCode::ProtocolUnsupportedVersion));
    }
    if bundle.policy_version == 0
        || bundle.key_epoch == 0
        || bundle.issued_at.get() >= bundle.expires_at.get()
    {
        return Err(malformed());
    }
    if now.get() < bundle.issued_at.get() {
        return Err(PolicyError::stable(StableCode::PolicyNotYetValid));
    }
    if now.get() >= bundle.expires_at.get() {
        return Err(PolicyError::stable(StableCode::PolicyExpired));
    }
    Ok(())
}

fn validate_scalars(bundle: &PolicyBundleV1) -> Result<(), PolicyError> {
    let release = &bundle.release;
    if release.challenge_ttl_seconds > MAXIMUM_TTL_SECONDS
        || release.receipt_ttl_seconds > MAXIMUM_TTL_SECONDS
        || bundle.ontology.max_snapshot_entries > MAXIMUM_SNAPSHOT_ENTRIES
        || bundle.ontology.max_constraints_per_tool > MAXIMUM_CONSTRAINTS_PER_TOOL
        || bundle
            .attempts
            .limits
            .iter()
            .any(|limit| limit.maximum_per_run > MAXIMUM_PER_RUN)
    {
        return Err(PolicyError::stable(StableCode::PolicyLimitExceeded));
    }
    if release.challenge_ttl_seconds == 0
        || release.receipt_ttl_seconds == 0
        || bundle.ontology.max_snapshot_entries == 0
        || bundle.ontology.max_constraints_per_tool == 0
        || bundle
            .attempts
            .limits
            .iter()
            .any(|limit| limit.maximum_per_run == 0)
        || !release.require_authenticated_user_assertion
        || !release.consume_vault_on_success
        || !bundle.sink.deny_on_missing_attestation
    {
        return Err(malformed());
    }
    Ok(())
}

fn validate_ordering(bundle: &PolicyBundleV1) -> Result<(), PolicyError> {
    if !sorted_text(bundle.tools.iter().map(|tool| tool.name.as_str()))
        || !sorted_text(
            bundle
                .authorities
                .iter()
                .map(|authority| authority.key_id.as_str()),
        )
        || !sorted_text(
            bundle
                .dataflow
                .no_side_effect_tools
                .iter()
                .map(ToolName::as_str),
        )
        || !sorted_text(
            bundle
                .dataflow
                .consent_overridable_tools
                .iter()
                .map(ToolName::as_str),
        )
        || !sorted_text(bundle.dataflow.high_risk_tools.iter().map(ToolName::as_str))
        || !sorted_tool_attempts(&bundle.attempts.valid_pairs)
        || !sorted_attempts(bundle.attempts.limits.iter().map(|limit| limit.attempt))
        || !sorted_attempts(bundle.attempts.cloud_blocked.iter().copied())
        || !sorted_text(
            bundle
                .ontology
                .snapshot_authority_key_ids
                .iter()
                .map(KeyId::as_str),
        )
        || !sorted_text(
            bundle
                .sink
                .validator_requirements
                .iter()
                .map(|requirement| requirement.tool.as_str()),
        )
        || !sorted_digests(bundle.release.compatible_release_target_ids.as_slice())
        || !sorted_digests(&bundle.accepted_model_manifest_digests)
        || !bundle.error_map.windows(2).all(|pair| {
            matches!(
                pair,
                [left, right] if left.policy_reason_tag < right.policy_reason_tag
            )
        })
    {
        return Err(malformed());
    }
    for tool in &bundle.tools {
        if !sorted_text(tool.constraint_ids.iter().map(ConstraintId::as_str))
            || !sorted_text(tool.validator_ids.iter().map(ValidatorId::as_str))
        {
            return Err(malformed());
        }
    }
    for requirement in &bundle.sink.validator_requirements {
        if !sorted_text(requirement.validator_ids.iter().map(ValidatorId::as_str)) {
            return Err(malformed());
        }
    }
    Ok(())
}

fn validate_authorities(bundle: &PolicyBundleV1) -> Result<(), PolicyError> {
    let mut role_present = [false; 8];
    for authority in &bundle.authorities {
        if authority.epoch == 0
            || authority.public_key == [0; 32]
            || authority.not_before.get() >= authority.not_after.get()
        {
            return Err(malformed());
        }
        if authority_valid_for_policy(authority, bundle) {
            let present = role_present
                .get_mut(usize::from(authority.role.tag()))
                .ok_or_else(malformed)?;
            *present = true;
        }
    }
    if role_present.iter().any(|present| !present) {
        return Err(malformed());
    }
    Ok(())
}

fn validate_tools_and_attempts(bundle: &PolicyBundleV1) -> Result<(), PolicyError> {
    for name in bundle
        .dataflow
        .no_side_effect_tools
        .iter()
        .chain(&bundle.dataflow.consent_overridable_tools)
        .chain(&bundle.dataflow.high_risk_tools)
    {
        if find_tool(bundle, name.as_str()).is_none() {
            return Err(malformed());
        }
    }
    for pair in &bundle.attempts.valid_pairs {
        if find_tool(bundle, pair.tool.as_str()).is_none() {
            return Err(malformed());
        }
    }
    for tool in &bundle.tools {
        if !bundle
            .attempts
            .valid_pairs
            .iter()
            .any(|pair| pair.tool == tool.name && pair.attempt == tool.attempt)
        {
            return Err(malformed());
        }
    }
    Ok(())
}

fn validate_ontology_and_validators(bundle: &PolicyBundleV1) -> Result<(), PolicyError> {
    for key_id in &bundle.ontology.snapshot_authority_key_ids {
        let valid = find_authority(bundle, key_id.as_str()).is_some_and(|authority| {
            authority.role == AuthorityRoleV1::Ontology
                && authority_valid_for_policy(authority, bundle)
        });
        if !valid {
            return Err(malformed());
        }
    }

    for tool in &bundle.tools {
        for validator_id in &tool.validator_ids {
            if !is_valid_validator(bundle, validator_id.as_str()) {
                return Err(malformed());
            }
        }
    }

    for requirement in &bundle.sink.validator_requirements {
        if requirement.validator_ids.is_empty() {
            return Err(malformed());
        }
        let tool = find_tool(bundle, requirement.tool.as_str()).ok_or_else(malformed)?;
        for validator_id in &requirement.validator_ids {
            if !tool
                .validator_ids
                .iter()
                .any(|listed| listed == validator_id)
            {
                return Err(malformed());
            }
        }
    }
    Ok(())
}

fn validate_release_and_mappings(
    bundle: &PolicyBundleV1,
    active_release_target_id: Digest32,
) -> Result<(), PolicyError> {
    if bundle
        .release
        .compatible_release_target_ids
        .as_slice()
        .is_empty()
        || bundle.accepted_model_manifest_digests.is_empty()
    {
        return Err(malformed());
    }
    if !bundle
        .release
        .compatible_release_target_ids
        .as_slice()
        .contains(&active_release_target_id)
    {
        return Err(PolicyError::stable(StableCode::PolicyReleaseIncompatible));
    }
    Ok(())
}

fn authority_valid_for_policy(authority: &AuthorityKeyV1, bundle: &PolicyBundleV1) -> bool {
    !authority.revoked
        && authority.not_before.get() <= bundle.issued_at.get()
        && authority.not_after.get() >= bundle.expires_at.get()
}

fn is_valid_validator(bundle: &PolicyBundleV1, key_id: &str) -> bool {
    find_authority(bundle, key_id).is_some_and(|authority| {
        authority.role == AuthorityRoleV1::Validator
            && authority_valid_for_policy(authority, bundle)
    })
}

fn find_tool<'bundle>(
    bundle: &'bundle PolicyBundleV1,
    name: &str,
) -> Option<&'bundle AllowedToolV1> {
    bundle.tools.iter().find(|tool| tool.name.as_str() == name)
}

fn find_authority<'bundle>(
    bundle: &'bundle PolicyBundleV1,
    key_id: &str,
) -> Option<&'bundle AuthorityKeyV1> {
    bundle
        .authorities
        .iter()
        .find(|authority| authority.key_id.as_str() == key_id)
}

fn sorted_text<'value>(values: impl IntoIterator<Item = &'value str>) -> bool {
    let mut previous = None;
    for value in values {
        if previous.is_some_and(|prior| canonical_text_cmp(prior, value) != Ordering::Less) {
            return false;
        }
        previous = Some(value);
    }
    true
}

fn canonical_text_cmp(left: &str, right: &str) -> Ordering {
    left.len()
        .cmp(&right.len())
        .then_with(|| left.as_bytes().cmp(right.as_bytes()))
}

fn sorted_tool_attempts(values: &[ToolAttemptV1]) -> bool {
    values.windows(2).all(|pair| {
        matches!(
            pair,
            [left, right]
                if canonical_text_cmp(left.tool.as_str(), right.tool.as_str())
                    .then_with(|| left.attempt.tag().cmp(&right.attempt.tag()))
                    == Ordering::Less
        )
    })
}

fn sorted_attempts(values: impl IntoIterator<Item = AttemptKindV1>) -> bool {
    let mut previous = None;
    for value in values {
        if previous.is_some_and(|prior: AttemptKindV1| prior.tag() >= value.tag()) {
            return false;
        }
        previous = Some(value);
    }
    true
}

fn sorted_digests(values: &[Digest32]) -> bool {
    values
        .windows(2)
        .all(|pair| matches!(pair, [left, right] if left.as_bytes() < right.as_bytes()))
}

fn malformed() -> PolicyError {
    PolicyError::stable(StableCode::ProtocolMalformedCbor)
}

fn domain_digest(domain: &[u8], bytes: &[u8]) -> Digest32 {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(bytes);
    Digest32::new(hasher.finalize().into())
}
