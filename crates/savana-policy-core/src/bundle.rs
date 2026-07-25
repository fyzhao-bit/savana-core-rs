use minicbor::{Decode, Encode};
use savana_kernel_protocol::{
    AttemptKindV1, ConstraintId, Digest32, HardLimits, KeyId, ResourceLimitsV1, StableCode,
    ToolName, UnixMillis, ValidatorId,
};

use crate::PolicyError;

#[derive(Debug, Clone, PartialEq, Eq, Encode)]
#[cbor(array)]
pub struct ProtocolRangeV1 {
    #[n(0)]
    pub major: u16,
    #[n(1)]
    pub minimum_minor: u16,
    #[n(2)]
    pub maximum_minor: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Encode)]
#[cbor(array)]
pub struct DataflowPolicyV1 {
    #[n(0)]
    pub no_side_effect_tools: Vec<ToolName>,
    #[n(1)]
    pub consent_overridable_tools: Vec<ToolName>,
    #[n(2)]
    pub high_risk_tools: Vec<ToolName>,
}

#[derive(Debug, Clone, PartialEq, Eq, Encode)]
#[cbor(array)]
pub struct ToolAttemptV1 {
    #[n(0)]
    pub tool: ToolName,
    #[n(1)]
    pub attempt: AttemptKindV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Encode)]
#[cbor(array)]
pub struct AttemptLimitV1 {
    #[n(0)]
    pub attempt: AttemptKindV1,
    #[n(1)]
    pub maximum_per_run: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Encode)]
#[cbor(array)]
pub struct AttemptPolicyV1 {
    #[n(0)]
    pub valid_pairs: Vec<ToolAttemptV1>,
    #[n(1)]
    pub limits: Vec<AttemptLimitV1>,
    #[n(2)]
    pub cloud_blocked: Vec<AttemptKindV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Encode)]
#[cbor(array)]
pub struct OntologyPolicyV1 {
    #[n(0)]
    pub snapshot_authority_key_ids: Vec<KeyId>,
    #[n(1)]
    pub max_snapshot_entries: u32,
    #[n(2)]
    pub max_constraints_per_tool: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Encode)]
#[cbor(array)]
pub struct ToolValidatorRequirementV1 {
    #[n(0)]
    pub tool: ToolName,
    #[n(1)]
    pub validator_ids: Vec<ValidatorId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Encode)]
#[cbor(array)]
pub struct SinkPolicyV1 {
    #[n(0)]
    pub validator_requirements: Vec<ToolValidatorRequirementV1>,
    #[n(1)]
    pub deny_on_missing_attestation: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundedDigestSet(Vec<Digest32>);

impl BoundedDigestSet {
    pub fn new(values: Vec<Digest32>) -> Result<Self, PolicyError> {
        if values.is_empty() {
            return Err(PolicyError::stable(StableCode::ProtocolMalformedCbor));
        }
        if values.len() > HardLimits::COMPILED.policy_release_targets() as usize {
            return Err(PolicyError::stable(StableCode::PolicyLimitExceeded));
        }
        if !values
            .windows(2)
            .all(|pair| matches!(pair, [left, right] if left.as_bytes() < right.as_bytes()))
        {
            return Err(PolicyError::stable(StableCode::ProtocolMalformedCbor));
        }
        Ok(Self(values))
    }

    pub fn as_slice(&self) -> &[Digest32] {
        &self.0
    }

    pub(crate) fn from_decoded(values: Vec<Digest32>) -> Self {
        Self(values)
    }
}

impl<C> Encode<C> for BoundedDigestSet {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        encoder.array(self.0.len() as u64)?;
        for digest in &self.0 {
            digest.encode(encoder, context)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Encode)]
#[cbor(array)]
pub struct ReleasePolicyV1 {
    #[n(0)]
    pub challenge_ttl_seconds: u32,
    #[n(1)]
    pub receipt_ttl_seconds: u32,
    #[n(2)]
    pub require_authenticated_user_assertion: bool,
    #[n(3)]
    pub consume_vault_on_success: bool,
    #[n(4)]
    pub compatible_release_target_ids: BoundedDigestSet,
}

#[derive(Debug, Clone, PartialEq, Eq, Encode)]
#[cbor(array)]
pub struct AllowedToolV1 {
    #[n(0)]
    pub name: ToolName,
    #[n(1)]
    pub descriptor_digest: Digest32,
    #[n(2)]
    pub attempt: AttemptKindV1,
    #[n(3)]
    pub constraint_ids: Vec<ConstraintId>,
    #[n(4)]
    pub validator_ids: Vec<ValidatorId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorityRoleV1 {
    Ingress,
    Planner,
    Registry,
    Ontology,
    Validator,
    Approval,
    ModelManifest,
    Release,
}

impl AuthorityRoleV1 {
    pub const fn tag(self) -> u8 {
        match self {
            Self::Ingress => 0,
            Self::Planner => 1,
            Self::Registry => 2,
            Self::Ontology => 3,
            Self::Validator => 4,
            Self::Approval => 5,
            Self::ModelManifest => 6,
            Self::Release => 7,
        }
    }
}

impl<C> Encode<C> for AuthorityRoleV1 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        _context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        encoder.u8(self.tag())?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityKeyV1 {
    pub key_id: KeyId,
    pub role: AuthorityRoleV1,
    pub public_key: [u8; 32],
    pub epoch: u64,
    pub not_before: UnixMillis,
    pub not_after: UnixMillis,
    pub revoked: bool,
}

impl<C> Encode<C> for AuthorityKeyV1 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        encoder.array(7)?;
        self.key_id.encode(encoder, context)?;
        self.role.encode(encoder, context)?;
        encoder.bytes(&self.public_key)?;
        encoder.u64(self.epoch)?;
        self.not_before.encode(encoder, context)?;
        self.not_after.encode(encoder, context)?;
        encoder.bool(self.revoked)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Encode)]
#[cbor(array)]
pub struct StableErrorMappingV1 {
    #[n(0)]
    pub policy_reason_tag: u16,
    #[n(1)]
    pub stable_code: StableCode,
}

#[derive(Debug, Clone, PartialEq, Eq, Encode)]
#[cbor(array)]
pub struct PolicyBundleV1 {
    #[n(0)]
    pub schema_version: u16,
    #[n(1)]
    pub protocol: ProtocolRangeV1,
    #[n(2)]
    pub policy_version: u64,
    #[n(3)]
    pub key_epoch: u64,
    #[n(4)]
    pub issued_at: UnixMillis,
    #[n(5)]
    pub expires_at: UnixMillis,
    #[n(6)]
    pub signing_key_id: KeyId,
    #[n(7)]
    pub dataflow: DataflowPolicyV1,
    #[n(8)]
    pub attempts: AttemptPolicyV1,
    #[n(9)]
    pub ontology: OntologyPolicyV1,
    #[n(10)]
    pub sink: SinkPolicyV1,
    #[n(11)]
    pub release: ReleasePolicyV1,
    #[n(12)]
    pub tools: Vec<AllowedToolV1>,
    #[n(13)]
    pub authorities: Vec<AuthorityKeyV1>,
    #[n(14)]
    pub resources: ResourceLimitsV1,
    #[n(15)]
    pub accepted_model_manifest_digests: Vec<Digest32>,
    #[n(16)]
    pub error_map: Vec<StableErrorMappingV1>,
}

pub(crate) fn decode_canonical_policy(bytes: &[u8]) -> Result<PolicyBundleV1, PolicyError> {
    if bytes.len() as u64 > HardLimits::COMPILED.frame_bytes() {
        return Err(PolicyError::stable(StableCode::PolicyLimitExceeded));
    }
    let mut decoder = minicbor::Decoder::new(bytes);
    expect_array(&mut decoder, 17)?;
    let bundle = PolicyBundleV1 {
        schema_version: decode_u16(&mut decoder)?,
        protocol: decode_protocol(&mut decoder)?,
        policy_version: decode_u64(&mut decoder)?,
        key_epoch: decode_u64(&mut decoder)?,
        issued_at: UnixMillis::new(decode_u64(&mut decoder)?),
        expires_at: UnixMillis::new(decode_u64(&mut decoder)?),
        signing_key_id: decode_typed(&mut decoder)?,
        dataflow: decode_dataflow(&mut decoder)?,
        attempts: decode_attempts(&mut decoder)?,
        ontology: decode_ontology(&mut decoder)?,
        sink: decode_sink(&mut decoder)?,
        release: decode_release(&mut decoder)?,
        tools: decode_vec(
            &mut decoder,
            HardLimits::COMPILED.policy_tools(),
            decode_tool,
        )?,
        authorities: decode_vec(
            &mut decoder,
            HardLimits::COMPILED.policy_authorities(),
            decode_authority,
        )?,
        resources: decode_typed(&mut decoder)?,
        accepted_model_manifest_digests: decode_vec(
            &mut decoder,
            HardLimits::COMPILED.policy_model_digests(),
            decode_typed,
        )?,
        error_map: decode_vec(
            &mut decoder,
            HardLimits::COMPILED.policy_error_mappings(),
            decode_error_mapping,
        )?,
    };
    if decoder.position() != bytes.len() {
        return Err(malformed());
    }
    let canonical = minicbor::to_vec(&bundle).map_err(PolicyError::io)?;
    if canonical != bytes {
        return Err(malformed());
    }
    Ok(bundle)
}

fn decode_protocol(decoder: &mut minicbor::Decoder<'_>) -> Result<ProtocolRangeV1, PolicyError> {
    expect_array(decoder, 3)?;
    Ok(ProtocolRangeV1 {
        major: decode_u16(decoder)?,
        minimum_minor: decode_u16(decoder)?,
        maximum_minor: decode_u16(decoder)?,
    })
}

fn decode_dataflow(decoder: &mut minicbor::Decoder<'_>) -> Result<DataflowPolicyV1, PolicyError> {
    expect_array(decoder, 3)?;
    Ok(DataflowPolicyV1 {
        no_side_effect_tools: decode_vec(
            decoder,
            HardLimits::COMPILED.policy_tool_name_set(),
            decode_typed,
        )?,
        consent_overridable_tools: decode_vec(
            decoder,
            HardLimits::COMPILED.policy_tool_name_set(),
            decode_typed,
        )?,
        high_risk_tools: decode_vec(
            decoder,
            HardLimits::COMPILED.policy_tool_name_set(),
            decode_typed,
        )?,
    })
}

fn decode_attempts(decoder: &mut minicbor::Decoder<'_>) -> Result<AttemptPolicyV1, PolicyError> {
    expect_array(decoder, 3)?;
    Ok(AttemptPolicyV1 {
        valid_pairs: decode_vec(
            decoder,
            HardLimits::COMPILED.policy_valid_pairs(),
            decode_tool_attempt,
        )?,
        limits: decode_vec(
            decoder,
            HardLimits::COMPILED.policy_attempt_limits(),
            decode_attempt_limit,
        )?,
        cloud_blocked: decode_vec(
            decoder,
            HardLimits::COMPILED.policy_attempt_limits(),
            decode_typed,
        )?,
    })
}

fn decode_tool_attempt(decoder: &mut minicbor::Decoder<'_>) -> Result<ToolAttemptV1, PolicyError> {
    expect_array(decoder, 2)?;
    Ok(ToolAttemptV1 {
        tool: decode_typed(decoder)?,
        attempt: decode_typed(decoder)?,
    })
}

fn decode_attempt_limit(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<AttemptLimitV1, PolicyError> {
    expect_array(decoder, 2)?;
    Ok(AttemptLimitV1 {
        attempt: decode_typed(decoder)?,
        maximum_per_run: decode_u32(decoder)?,
    })
}

fn decode_ontology(decoder: &mut minicbor::Decoder<'_>) -> Result<OntologyPolicyV1, PolicyError> {
    expect_array(decoder, 3)?;
    Ok(OntologyPolicyV1 {
        snapshot_authority_key_ids: decode_vec(
            decoder,
            HardLimits::COMPILED.policy_snapshot_authorities(),
            decode_typed,
        )?,
        max_snapshot_entries: decode_u32(decoder)?,
        max_constraints_per_tool: decode_u16(decoder)?,
    })
}

fn decode_sink(decoder: &mut minicbor::Decoder<'_>) -> Result<SinkPolicyV1, PolicyError> {
    expect_array(decoder, 2)?;
    Ok(SinkPolicyV1 {
        validator_requirements: decode_vec(
            decoder,
            HardLimits::COMPILED.policy_validator_requirements(),
            decode_validator_requirement,
        )?,
        deny_on_missing_attestation: decoder.bool().map_err(|_| malformed())?,
    })
}

fn decode_validator_requirement(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<ToolValidatorRequirementV1, PolicyError> {
    expect_array(decoder, 2)?;
    Ok(ToolValidatorRequirementV1 {
        tool: decode_typed(decoder)?,
        validator_ids: decode_vec(
            decoder,
            HardLimits::COMPILED.policy_validators_per_tool(),
            decode_typed,
        )?,
    })
}

fn decode_release(decoder: &mut minicbor::Decoder<'_>) -> Result<ReleasePolicyV1, PolicyError> {
    expect_array(decoder, 5)?;
    Ok(ReleasePolicyV1 {
        challenge_ttl_seconds: decode_u32(decoder)?,
        receipt_ttl_seconds: decode_u32(decoder)?,
        require_authenticated_user_assertion: decoder.bool().map_err(|_| malformed())?,
        consume_vault_on_success: decoder.bool().map_err(|_| malformed())?,
        compatible_release_target_ids: BoundedDigestSet::from_decoded(decode_vec(
            decoder,
            HardLimits::COMPILED.policy_release_targets(),
            decode_typed,
        )?),
    })
}

fn decode_tool(decoder: &mut minicbor::Decoder<'_>) -> Result<AllowedToolV1, PolicyError> {
    expect_array(decoder, 5)?;
    Ok(AllowedToolV1 {
        name: decode_typed(decoder)?,
        descriptor_digest: decode_typed(decoder)?,
        attempt: decode_typed(decoder)?,
        constraint_ids: decode_vec(
            decoder,
            HardLimits::COMPILED.policy_constraints_per_tool(),
            decode_typed,
        )?,
        validator_ids: decode_vec(
            decoder,
            HardLimits::COMPILED.policy_validators_per_tool(),
            decode_typed,
        )?,
    })
}

fn decode_authority(decoder: &mut minicbor::Decoder<'_>) -> Result<AuthorityKeyV1, PolicyError> {
    expect_array(decoder, 7)?;
    let key_id = decode_typed(decoder)?;
    let role = match decoder.u8().map_err(|_| malformed())? {
        0 => AuthorityRoleV1::Ingress,
        1 => AuthorityRoleV1::Planner,
        2 => AuthorityRoleV1::Registry,
        3 => AuthorityRoleV1::Ontology,
        4 => AuthorityRoleV1::Validator,
        5 => AuthorityRoleV1::Approval,
        6 => AuthorityRoleV1::ModelManifest,
        7 => AuthorityRoleV1::Release,
        _ => return Err(malformed()),
    };
    let public_key = decoder
        .bytes()
        .map_err(|_| malformed())?
        .try_into()
        .map_err(|_| malformed())?;
    Ok(AuthorityKeyV1 {
        key_id,
        role,
        public_key,
        epoch: decode_u64(decoder)?,
        not_before: UnixMillis::new(decode_u64(decoder)?),
        not_after: UnixMillis::new(decode_u64(decoder)?),
        revoked: decoder.bool().map_err(|_| malformed())?,
    })
}

fn decode_error_mapping(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<StableErrorMappingV1, PolicyError> {
    expect_array(decoder, 2)?;
    Ok(StableErrorMappingV1 {
        policy_reason_tag: decode_u16(decoder)?,
        stable_code: decode_typed(decoder)?,
    })
}

fn decode_vec<'bytes, T, F>(
    decoder: &mut minicbor::Decoder<'bytes>,
    maximum: u64,
    mut decode: F,
) -> Result<Vec<T>, PolicyError>
where
    F: FnMut(&mut minicbor::Decoder<'bytes>) -> Result<T, PolicyError>,
{
    let length = decoder
        .array()
        .map_err(|_| malformed())?
        .ok_or_else(malformed)?;
    if length > maximum {
        return Err(PolicyError::stable(StableCode::PolicyLimitExceeded));
    }
    let capacity = usize::try_from(length)
        .map_err(|_| PolicyError::stable(StableCode::PolicyLimitExceeded))?;
    let mut values = Vec::with_capacity(capacity);
    for _ in 0..length {
        values.push(decode(decoder)?);
    }
    Ok(values)
}

fn expect_array(decoder: &mut minicbor::Decoder<'_>, expected: u64) -> Result<(), PolicyError> {
    match decoder.array().map_err(|_| malformed())? {
        Some(actual) if actual == expected => Ok(()),
        _ => Err(malformed()),
    }
}

fn decode_typed<'bytes, T>(decoder: &mut minicbor::Decoder<'bytes>) -> Result<T, PolicyError>
where
    T: Decode<'bytes, ()>,
{
    T::decode(decoder, &mut ()).map_err(|_| malformed())
}

fn decode_u16(decoder: &mut minicbor::Decoder<'_>) -> Result<u16, PolicyError> {
    decoder.u16().map_err(|_| malformed())
}

fn decode_u32(decoder: &mut minicbor::Decoder<'_>) -> Result<u32, PolicyError> {
    decoder.u32().map_err(|_| malformed())
}

fn decode_u64(decoder: &mut minicbor::Decoder<'_>) -> Result<u64, PolicyError> {
    decoder.u64().map_err(|_| malformed())
}

fn malformed() -> PolicyError {
    PolicyError::stable(StableCode::ProtocolMalformedCbor)
}
