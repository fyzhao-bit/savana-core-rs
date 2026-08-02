#[cfg(any(
    test,
    feature = "test-support",
    feature = "macos-development-authority"
))]
use ed25519_dalek::SigningKey;
use ed25519_dalek::{Signature, VerifyingKey};
use savana_kernel_protocol::v2::Digest32V2;
use sha2::{Digest as _, Sha256};

use super::deployment_manifest_primitives::{
    check_manifest_object_size, decode_bounded_array_length, decode_digest, decode_nested,
    decode_u16, decode_u64, expect_array, hash_domain, is_zero, require_canonical, require_eof,
};
use super::deployment_release_trust::{decode_domain_signature, encode_domain_signature};
use super::{
    DeclassificationTransitionV2, DeploymentControlErrorV2, DeploymentHardLimitsV2, LeakGateDutyV2,
    ManifestDomainSignatureV2, OperationalTrustRootPurposeV2, OperationalTrustRootSetBindingV2,
    OperationalTrustRootSetV2,
};

const RULE_SET_SCHEMA_VERSION_V2: u16 = 1;
const RULE_SET_FIELDS_V2: u64 = 3;
const RULE_SET_PAYLOAD_FIELDS_V2: u64 = 8;
const RULE_FIELDS_V2: u64 = 8;
const RULE_SET_SIGNATURE_TAG_V2: u16 = 29;
const MAX_APPROVAL_AGE_MS_V2: u64 = 300_000;
const RULE_SET_PAYLOAD_DOMAIN_V2: &[u8] = b"savana.declassification-rule-set.v2.payload\0";
const RULE_SET_SIGNED_DOMAIN_V2: &[u8] = b"savana.declassification-rule-set.v2.signed\0";
const RULE_SET_SIGNATURE_DOMAIN_V2: &[u8] = b"savana.declassification-rule-set.v2.signature\0";
const RULE_DOMAIN_V2: &[u8] = b"savana.declassification-rule.v2\0";
const PURPOSE_DOMAIN_V2: &[u8] = b"savana.declassification-purpose.v2\0";
const IMPLEMENTATION_DOMAIN_V2: &[u8] = b"savana.declassification-implementation.v2\0";
const DOMAIN_SIGNATURE_INPUT_V2: &[u8] = b"savana.domain-signature.v2\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u16)]
pub enum ClosedDeclassificationPurposeV2 {
    AgentIngressMasking = 1,
    PlannerCall = 2,
    ApprovalDisplay = 3,
    ExecutionHandoff = 4,
    FinalRelease = 5,
}

impl ClosedDeclassificationPurposeV2 {
    pub const ALL: [Self; 5] = [
        Self::AgentIngressMasking,
        Self::PlannerCall,
        Self::ApprovalDisplay,
        Self::ExecutionHandoff,
        Self::FinalRelease,
    ];

    pub const fn tag(self) -> u16 {
        self as u16
    }

    pub const fn owning_transition_tag(self) -> u16 {
        self.tag()
    }

    pub const fn canonical_name(self) -> &'static str {
        match self {
            Self::AgentIngressMasking => "agent-ingress-masking",
            Self::PlannerCall => "planner-call",
            Self::ApprovalDisplay => "approval-display",
            Self::ExecutionHandoff => "execution-handoff",
            Self::FinalRelease => "final-release",
        }
    }

    pub fn purpose_digest(self) -> Digest32V2 {
        hash_domain(PURPOSE_DOMAIN_V2, self.canonical_name().as_bytes())
    }

    fn from_digest(digest: Digest32V2) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|purpose| purpose.purpose_digest() == digest)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclassificationRuleV2 {
    canonical_bytes: Vec<u8>,
    transition_tag: u16,
    purpose: ClosedDeclassificationPurposeV2,
    purpose_digest: Digest32V2,
    implementation_digest: Digest32V2,
    duty_floor: LeakGateDutyV2,
    reader_identities: Option<Vec<Digest32V2>>,
    consent_max_age_ms: Option<u64>,
    not_before_unix_ms: u64,
    not_after_unix_ms: u64,
    rule_digest: Digest32V2,
}

impl DeclassificationRuleV2 {
    #[cfg(any(
        test,
        feature = "test-support",
        feature = "macos-development-authority"
    ))]
    #[allow(clippy::too_many_arguments)]
    pub fn new_for_test(
        transition_tag: u16,
        purpose: ClosedDeclassificationPurposeV2,
        implementation_digest: Digest32V2,
        duty_floor: LeakGateDutyV2,
        reader_identities: Option<Vec<Digest32V2>>,
        consent_max_age_ms: Option<u64>,
        not_before_unix_ms: u64,
        not_after_unix_ms: u64,
    ) -> Result<Self, DeploymentControlErrorV2> {
        Self::new(
            transition_tag,
            purpose.purpose_digest(),
            implementation_digest,
            duty_floor,
            reader_identities,
            consent_max_age_ms,
            not_before_unix_ms,
            not_after_unix_ms,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new(
        transition_tag: u16,
        purpose_digest: Digest32V2,
        implementation_digest: Digest32V2,
        duty_floor: LeakGateDutyV2,
        reader_identities: Option<Vec<Digest32V2>>,
        consent_max_age_ms: Option<u64>,
        not_before_unix_ms: u64,
        not_after_unix_ms: u64,
    ) -> Result<Self, DeploymentControlErrorV2> {
        let purpose = ClosedDeclassificationPurposeV2::from_digest(purpose_digest)
            .ok_or(DeploymentControlErrorV2::InvalidDeclassificationRuleSet)?;
        if transition_tag != purpose.owning_transition_tag()
            || is_zero(implementation_digest.as_bytes())
            || not_before_unix_ms >= not_after_unix_ms
        {
            return Err(DeploymentControlErrorV2::InvalidDeclassificationRuleSet);
        }
        match (transition_tag, reader_identities.as_deref()) {
            (1..=3, None) => {}
            (4..=5, Some(readers))
                if !readers.is_empty()
                    && readers.len() as u64
                        <= DeploymentHardLimitsV2::compiled().max_declassification_readers()
                    && !readers.iter().any(|reader| is_zero(reader.as_bytes()))
                    && !readers
                        .windows(2)
                        .any(|pair| pair[0].as_bytes() >= pair[1].as_bytes()) => {}
            _ => return Err(DeploymentControlErrorV2::InvalidDeclassificationRuleSet),
        }
        match (transition_tag, consent_max_age_ms) {
            (1..=4, None) | (5, None) => {}
            (5, Some(age)) if (1..=MAX_APPROVAL_AGE_MS_V2).contains(&age) => {}
            _ => return Err(DeploymentControlErrorV2::InvalidDeclassificationRuleSet),
        }
        let mut value = Self {
            canonical_bytes: Vec::new(),
            transition_tag,
            purpose,
            purpose_digest,
            implementation_digest,
            duty_floor,
            reader_identities,
            consent_max_age_ms,
            not_before_unix_ms,
            not_after_unix_ms,
            rule_digest: Digest32V2::new([0; 32]),
        };
        value.canonical_bytes = encode_rule(&value)?;
        value.rule_digest = hash_domain(RULE_DOMAIN_V2, &value.canonical_bytes);
        Ok(value)
    }

    pub const fn transition_tag(&self) -> u16 {
        self.transition_tag
    }

    pub const fn purpose(&self) -> ClosedDeclassificationPurposeV2 {
        self.purpose
    }

    pub const fn purpose_digest(&self) -> Digest32V2 {
        self.purpose_digest
    }

    pub const fn implementation_digest(&self) -> Digest32V2 {
        self.implementation_digest
    }

    pub const fn duty_floor(&self) -> LeakGateDutyV2 {
        self.duty_floor
    }

    pub fn reader_identities(&self) -> &[Digest32V2] {
        self.reader_identities.as_deref().unwrap_or(&[])
    }

    pub const fn consent_max_age_ms(&self) -> Option<u64> {
        self.consent_max_age_ms
    }

    pub const fn not_before_unix_ms(&self) -> u64 {
        self.not_before_unix_ms
    }

    pub const fn not_after_unix_ms(&self) -> u64 {
        self.not_after_unix_ms
    }

    pub const fn rule_digest(&self) -> Digest32V2 {
        self.rule_digest
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    fn sort_key(&self) -> (u16, [u8; 32]) {
        (self.transition_tag, *self.purpose_digest.as_bytes())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclassificationRuleSetV2 {
    canonical_bytes: Vec<u8>,
    product_family_digest: Digest32V2,
    rule_set_sequence: u64,
    previous_signed_digest: Option<Digest32V2>,
    rules: Vec<DeclassificationRuleV2>,
    not_before_unix_ms: u64,
    not_after_unix_ms: u64,
    trust_root_set_digest: Digest32V2,
    payload_digest: Digest32V2,
    signed_digest: Digest32V2,
    authority_signature: ManifestDomainSignatureV2,
}

impl DeclassificationRuleSetV2 {
    pub fn from_canonical_bytes(
        bytes: &[u8],
        root_set: &OperationalTrustRootSetV2,
        now_unix_ms: u64,
    ) -> Result<Self, DeploymentControlErrorV2> {
        invalid(check_manifest_object_size(bytes))?;
        let mut decoded = decode_complete(bytes)?;
        validate_payload(&decoded)?;
        if decoded.trust_root_set_digest != root_set.signed_digest()
            || decoded.product_family_digest != root_set.product_family_digest()
            || !matches!(
                root_set.binding(),
                OperationalTrustRootSetBindingV2::Declassification { .. }
            )
            || now_unix_ms < decoded.not_before_unix_ms
            || now_unix_ms > decoded.not_after_unix_ms
        {
            return Err(DeploymentControlErrorV2::InvalidDeclassificationRuleSet);
        }
        let payload = encode_payload(&decoded)?;
        if hash_domain(RULE_SET_PAYLOAD_DOMAIN_V2, &payload) != decoded.payload_digest {
            return Err(DeploymentControlErrorV2::InvalidDeclassificationRuleSet);
        }
        verify_authority_signature(
            root_set,
            decoded.authority_signature,
            decoded.payload_digest,
            now_unix_ms,
        )?;
        let canonical_bytes = encode_complete(&decoded)?;
        invalid(require_canonical(&canonical_bytes, bytes))?;
        let signed_digest = hash_domain(RULE_SET_SIGNED_DOMAIN_V2, &canonical_bytes);
        Ok(Self {
            canonical_bytes,
            product_family_digest: decoded.product_family_digest,
            rule_set_sequence: decoded.rule_set_sequence,
            previous_signed_digest: decoded.previous_signed_digest,
            rules: std::mem::take(&mut decoded.rules),
            not_before_unix_ms: decoded.not_before_unix_ms,
            not_after_unix_ms: decoded.not_after_unix_ms,
            trust_root_set_digest: decoded.trust_root_set_digest,
            payload_digest: decoded.payload_digest,
            signed_digest,
            authority_signature: decoded.authority_signature,
        })
    }

    #[cfg(any(
        test,
        feature = "test-support",
        feature = "macos-development-authority"
    ))]
    #[allow(clippy::too_many_arguments)]
    pub fn new_signed_for_test(
        product_family_digest: Digest32V2,
        rule_set_sequence: u64,
        previous_signed_digest: Option<Digest32V2>,
        rules: Vec<DeclassificationRuleV2>,
        not_before_unix_ms: u64,
        not_after_unix_ms: u64,
        root_set: &OperationalTrustRootSetV2,
        signing_key: &SigningKey,
        signer_key_epoch: u64,
        now_unix_ms: u64,
    ) -> Result<Self, DeploymentControlErrorV2> {
        let mut decoded = DecodedRuleSetV2 {
            product_family_digest,
            rule_set_sequence,
            previous_signed_digest,
            rules,
            not_before_unix_ms,
            not_after_unix_ms,
            trust_root_set_digest: root_set.signed_digest(),
            payload_digest: Digest32V2::new([0; 32]),
            authority_signature: ManifestDomainSignatureV2::empty_for_decode(),
        };
        validate_payload(&decoded)?;
        decoded.payload_digest =
            hash_domain(RULE_SET_PAYLOAD_DOMAIN_V2, &encode_payload(&decoded)?);
        decoded.authority_signature = ManifestDomainSignatureV2::sign_for_test(
            RULE_SET_SIGNATURE_TAG_V2,
            RULE_SET_SIGNATURE_DOMAIN_V2,
            decoded.payload_digest,
            signing_key,
            signer_key_epoch,
        );
        Self::from_canonical_bytes(&encode_complete(&decoded)?, root_set, now_unix_ms)
    }

    pub fn validate_predecessor(
        &self,
        predecessor: Option<&Self>,
    ) -> Result<(), DeploymentControlErrorV2> {
        match (
            self.rule_set_sequence,
            self.previous_signed_digest,
            predecessor,
        ) {
            (1, None, None) => Ok(()),
            (sequence, Some(expected), Some(previous))
                if sequence == previous.rule_set_sequence.checked_add(1).unwrap_or(0)
                    && expected == previous.signed_digest
                    && self.product_family_digest == previous.product_family_digest =>
            {
                Ok(())
            }
            _ => Err(DeploymentControlErrorV2::InvalidDeclassificationRuleSet),
        }
    }

    pub fn authorizing_rule(
        &self,
        transition_tag: u16,
        purpose_digest: Digest32V2,
    ) -> Option<&DeclassificationRuleV2> {
        self.rules.iter().find(|rule| {
            rule.transition_tag == transition_tag && rule.purpose_digest == purpose_digest
        })
    }

    pub fn rule_by_digest(&self, rule_digest: Digest32V2) -> Option<&DeclassificationRuleV2> {
        self.rules
            .iter()
            .find(|rule| rule.rule_digest == rule_digest)
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub const fn product_family_digest(&self) -> Digest32V2 {
        self.product_family_digest
    }

    pub const fn rule_set_sequence(&self) -> u64 {
        self.rule_set_sequence
    }

    pub const fn previous_signed_digest(&self) -> Option<Digest32V2> {
        self.previous_signed_digest
    }

    pub fn rules(&self) -> &[DeclassificationRuleV2] {
        &self.rules
    }

    pub const fn not_before_unix_ms(&self) -> u64 {
        self.not_before_unix_ms
    }

    pub const fn not_after_unix_ms(&self) -> u64 {
        self.not_after_unix_ms
    }

    pub const fn trust_root_set_digest(&self) -> Digest32V2 {
        self.trust_root_set_digest
    }

    pub const fn payload_digest(&self) -> Digest32V2 {
        self.payload_digest
    }

    pub const fn signed_digest(&self) -> Digest32V2 {
        self.signed_digest
    }

    pub const fn authority_signature(&self) -> ManifestDomainSignatureV2 {
        self.authority_signature
    }
}

pub fn declassification_implementation_digest_v2(transition_tag: u16) -> Option<Digest32V2> {
    let contract: &[u8] = match transition_tag {
        1 => b"mask-tokenize-and-leak-check-v1",
        2 => b"build-planner-envelope-v1",
        3 => b"build-approval-display-v1",
        4 => b"build-execution-envelope-v1",
        5 => b"build-final-release-v1",
        _ => return None,
    };
    let mut hash = Sha256::new();
    hash.update(IMPLEMENTATION_DOMAIN_V2);
    hash.update(transition_tag.to_be_bytes());
    hash.update(1_u16.to_be_bytes());
    hash.update(contract);
    if matches!(transition_tag, 1 | 2) {
        hash.update(savana_leak_gate::pattern_set_digest());
    }
    Some(Digest32V2::new(hash.finalize().into()))
}

#[derive(Debug, Clone)]
struct DecodedRuleSetV2 {
    product_family_digest: Digest32V2,
    rule_set_sequence: u64,
    previous_signed_digest: Option<Digest32V2>,
    rules: Vec<DeclassificationRuleV2>,
    not_before_unix_ms: u64,
    not_after_unix_ms: u64,
    trust_root_set_digest: Digest32V2,
    payload_digest: Digest32V2,
    authority_signature: ManifestDomainSignatureV2,
}

fn validate_payload(value: &DecodedRuleSetV2) -> Result<(), DeploymentControlErrorV2> {
    if is_zero(value.product_family_digest.as_bytes())
        || value.rule_set_sequence == 0
        || (value.rule_set_sequence == 1) != value.previous_signed_digest.is_none()
        || value
            .previous_signed_digest
            .is_some_and(|digest| is_zero(digest.as_bytes()))
        || value.not_before_unix_ms >= value.not_after_unix_ms
        || is_zero(value.trust_root_set_digest.as_bytes())
        || value.rules.is_empty()
        || value.rules.len() as u64
            > DeploymentHardLimitsV2::compiled().max_declassification_rules()
        || value
            .rules
            .windows(2)
            .any(|pair| pair[0].sort_key() >= pair[1].sort_key())
        || value.rules.iter().any(|rule| {
            rule.not_before_unix_ms < value.not_before_unix_ms
                || rule.not_after_unix_ms > value.not_after_unix_ms
        })
    {
        return Err(DeploymentControlErrorV2::InvalidDeclassificationRuleSet);
    }
    Ok(())
}

fn decode_complete(bytes: &[u8]) -> Result<DecodedRuleSetV2, DeploymentControlErrorV2> {
    let mut decoder = minicbor::Decoder::new(bytes);
    invalid(expect_array(&mut decoder, RULE_SET_FIELDS_V2))?;
    let mut payload = invalid(decode_nested(&mut decoder, decode_payload))?;
    payload.payload_digest = invalid(decode_digest(&mut decoder))?;
    payload.authority_signature = invalid(decode_domain_signature(&mut decoder))?;
    invalid(require_eof(&decoder, bytes))?;
    Ok(payload)
}

fn decode_payload(bytes: &[u8]) -> Result<DecodedRuleSetV2, DeploymentControlErrorV2> {
    let mut decoder = minicbor::Decoder::new(bytes);
    invalid(expect_array(&mut decoder, RULE_SET_PAYLOAD_FIELDS_V2))?;
    if invalid(decode_u16(&mut decoder))? != RULE_SET_SCHEMA_VERSION_V2 {
        return Err(DeploymentControlErrorV2::InvalidDeclassificationRuleSet);
    }
    let product_family_digest = invalid(decode_digest(&mut decoder))?;
    let rule_set_sequence = invalid(decode_u64(&mut decoder))?;
    let previous_signed_digest = decode_optional_digest(&mut decoder)?;
    let count = invalid(decode_bounded_array_length(
        &mut decoder,
        DeploymentHardLimitsV2::compiled().max_declassification_rules(),
    ))?;
    let mut rules = Vec::new();
    rules
        .try_reserve_exact(count)
        .map_err(|_| DeploymentControlErrorV2::InvalidDeclassificationRuleSet)?;
    for _ in 0..count {
        rules.push(decode_rule(&mut decoder)?);
    }
    let not_before_unix_ms = invalid(decode_u64(&mut decoder))?;
    let not_after_unix_ms = invalid(decode_u64(&mut decoder))?;
    let trust_root_set_digest = invalid(decode_digest(&mut decoder))?;
    invalid(require_eof(&decoder, bytes))?;
    Ok(DecodedRuleSetV2 {
        product_family_digest,
        rule_set_sequence,
        previous_signed_digest,
        rules,
        not_before_unix_ms,
        not_after_unix_ms,
        trust_root_set_digest,
        payload_digest: Digest32V2::new([0; 32]),
        authority_signature: ManifestDomainSignatureV2::empty_for_decode(),
    })
}

fn encode_complete(value: &DecodedRuleSetV2) -> Result<Vec<u8>, DeploymentControlErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(RULE_SET_FIELDS_V2)
        .map_err(|_| DeploymentControlErrorV2::InvalidDeclassificationRuleSet)?;
    encoder
        .writer_mut()
        .extend_from_slice(&encode_payload(value)?);
    encoder
        .bytes(value.payload_digest.as_bytes())
        .map_err(|_| DeploymentControlErrorV2::InvalidDeclassificationRuleSet)?;
    invalid(encode_domain_signature(
        &mut encoder,
        value.authority_signature,
    ))?;
    Ok(encoder.into_writer())
}

fn encode_payload(value: &DecodedRuleSetV2) -> Result<Vec<u8>, DeploymentControlErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(RULE_SET_PAYLOAD_FIELDS_V2)
        .and_then(|encoder| encoder.u16(RULE_SET_SCHEMA_VERSION_V2))
        .and_then(|encoder| encoder.bytes(value.product_family_digest.as_bytes()))
        .and_then(|encoder| encoder.u64(value.rule_set_sequence))
        .map_err(|_| DeploymentControlErrorV2::InvalidDeclassificationRuleSet)?;
    encode_optional_digest(&mut encoder, value.previous_signed_digest)?;
    encoder
        .array(value.rules.len() as u64)
        .map_err(|_| DeploymentControlErrorV2::InvalidDeclassificationRuleSet)?;
    for rule in &value.rules {
        encoder
            .writer_mut()
            .extend_from_slice(rule.canonical_bytes());
    }
    encoder
        .u64(value.not_before_unix_ms)
        .and_then(|encoder| encoder.u64(value.not_after_unix_ms))
        .and_then(|encoder| encoder.bytes(value.trust_root_set_digest.as_bytes()))
        .map_err(|_| DeploymentControlErrorV2::InvalidDeclassificationRuleSet)?;
    Ok(encoder.into_writer())
}

fn decode_rule(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<DeclassificationRuleV2, DeploymentControlErrorV2> {
    invalid(expect_array(decoder, RULE_FIELDS_V2))?;
    let transition_tag = invalid(decode_u16(decoder))?;
    let purpose_digest = invalid(decode_digest(decoder))?;
    let implementation_digest = invalid(decode_digest(decoder))?;
    let duty_floor = LeakGateDutyV2::from_tag(invalid(decode_u16(decoder))?)
        .ok_or(DeploymentControlErrorV2::InvalidDeclassificationRuleSet)?;
    let readers = decode_readers(decoder)?;
    let consent = decode_consent(decoder)?;
    DeclassificationRuleV2::new(
        transition_tag,
        purpose_digest,
        implementation_digest,
        duty_floor,
        readers,
        consent,
        invalid(decode_u64(decoder))?,
        invalid(decode_u64(decoder))?,
    )
}

fn encode_rule(value: &DeclassificationRuleV2) -> Result<Vec<u8>, DeploymentControlErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(RULE_FIELDS_V2)
        .and_then(|encoder| encoder.u16(value.transition_tag))
        .and_then(|encoder| encoder.bytes(value.purpose_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(value.implementation_digest.as_bytes()))
        .and_then(|encoder| encoder.u16(value.duty_floor.tag()))
        .map_err(|_| DeploymentControlErrorV2::InvalidDeclassificationRuleSet)?;
    encode_readers(&mut encoder, value.reader_identities.as_deref())?;
    encode_consent(&mut encoder, value.consent_max_age_ms)?;
    encoder
        .u64(value.not_before_unix_ms)
        .and_then(|encoder| encoder.u64(value.not_after_unix_ms))
        .map_err(|_| DeploymentControlErrorV2::InvalidDeclassificationRuleSet)?;
    Ok(encoder.into_writer())
}

fn decode_readers(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<Option<Vec<Digest32V2>>, DeploymentControlErrorV2> {
    let length = decoder
        .array()
        .map_err(|_| DeploymentControlErrorV2::InvalidDeclassificationRuleSet)?
        .ok_or(DeploymentControlErrorV2::InvalidDeclassificationRuleSet)?;
    match (length, invalid(decode_u16(decoder))?) {
        (1, 0) => Ok(None),
        (2, 1) => {
            let count = invalid(decode_bounded_array_length(
                decoder,
                DeploymentHardLimitsV2::compiled().max_declassification_readers(),
            ))?;
            let mut readers = Vec::new();
            readers
                .try_reserve_exact(count)
                .map_err(|_| DeploymentControlErrorV2::InvalidDeclassificationRuleSet)?;
            for _ in 0..count {
                readers.push(invalid(decode_digest(decoder))?);
            }
            Ok(Some(readers))
        }
        _ => Err(DeploymentControlErrorV2::InvalidDeclassificationRuleSet),
    }
}

fn encode_readers(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    readers: Option<&[Digest32V2]>,
) -> Result<(), DeploymentControlErrorV2> {
    match readers {
        None => encoder
            .array(1)
            .and_then(|encoder| encoder.u16(0))
            .map(|_| ())
            .map_err(|_| DeploymentControlErrorV2::InvalidDeclassificationRuleSet),
        Some(readers) => {
            encoder
                .array(2)
                .and_then(|encoder| encoder.u16(1))
                .and_then(|encoder| encoder.array(readers.len() as u64))
                .map_err(|_| DeploymentControlErrorV2::InvalidDeclassificationRuleSet)?;
            for reader in readers {
                encoder
                    .bytes(reader.as_bytes())
                    .map_err(|_| DeploymentControlErrorV2::InvalidDeclassificationRuleSet)?;
            }
            Ok(())
        }
    }
}

fn decode_consent(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<Option<u64>, DeploymentControlErrorV2> {
    let length = decoder
        .array()
        .map_err(|_| DeploymentControlErrorV2::InvalidDeclassificationRuleSet)?
        .ok_or(DeploymentControlErrorV2::InvalidDeclassificationRuleSet)?;
    match (length, invalid(decode_u16(decoder))?) {
        (1, 0) => Ok(None),
        (2, 1) => Ok(Some(invalid(decode_u64(decoder))?)),
        _ => Err(DeploymentControlErrorV2::InvalidDeclassificationRuleSet),
    }
}

fn encode_consent(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    max_age_ms: Option<u64>,
) -> Result<(), DeploymentControlErrorV2> {
    match max_age_ms {
        None => encoder
            .array(1)
            .and_then(|encoder| encoder.u16(0))
            .map(|_| ())
            .map_err(|_| DeploymentControlErrorV2::InvalidDeclassificationRuleSet),
        Some(max_age_ms) => encoder
            .array(2)
            .and_then(|encoder| encoder.u16(1))
            .and_then(|encoder| encoder.u64(max_age_ms))
            .map(|_| ())
            .map_err(|_| DeploymentControlErrorV2::InvalidDeclassificationRuleSet),
    }
}

fn decode_optional_digest(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<Option<Digest32V2>, DeploymentControlErrorV2> {
    let length = decoder
        .array()
        .map_err(|_| DeploymentControlErrorV2::InvalidDeclassificationRuleSet)?
        .ok_or(DeploymentControlErrorV2::InvalidDeclassificationRuleSet)?;
    match (length, invalid(decode_u16(decoder))?) {
        (1, 0) => Ok(None),
        (2, 1) => Ok(Some(invalid(decode_digest(decoder))?)),
        _ => Err(DeploymentControlErrorV2::InvalidDeclassificationRuleSet),
    }
}

fn encode_optional_digest(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    digest: Option<Digest32V2>,
) -> Result<(), DeploymentControlErrorV2> {
    match digest {
        None => encoder
            .array(1)
            .and_then(|encoder| encoder.u16(0))
            .map(|_| ())
            .map_err(|_| DeploymentControlErrorV2::InvalidDeclassificationRuleSet),
        Some(digest) => encoder
            .array(2)
            .and_then(|encoder| encoder.u16(1))
            .and_then(|encoder| encoder.bytes(digest.as_bytes()))
            .map(|_| ())
            .map_err(|_| DeploymentControlErrorV2::InvalidDeclassificationRuleSet),
    }
}

fn verify_authority_signature(
    root_set: &OperationalTrustRootSetV2,
    signature: ManifestDomainSignatureV2,
    payload_digest: Digest32V2,
    now_unix_ms: u64,
) -> Result<(), DeploymentControlErrorV2> {
    if signature.domain_tag() != RULE_SET_SIGNATURE_TAG_V2
        || is_zero(signature.signature().as_bytes())
        || !root_set.authorizes(
            OperationalTrustRootPurposeV2::DeclassificationAuthority,
            signature.signer_key_id(),
            signature.signer_key_epoch(),
            now_unix_ms,
        )
    {
        return Err(DeploymentControlErrorV2::InvalidDeclassificationRuleSet);
    }
    let member = root_set
        .members()
        .iter()
        .find(|member| {
            member.purpose() == OperationalTrustRootPurposeV2::DeclassificationAuthority
                && member.key_id() == signature.signer_key_id()
                && member.key_epoch() == signature.signer_key_epoch()
        })
        .ok_or(DeploymentControlErrorV2::InvalidDeclassificationRuleSet)?;
    let key = VerifyingKey::from_bytes(&member.public_key())
        .map_err(|_| DeploymentControlErrorV2::InvalidDeclassificationRuleSet)?;
    key.verify_strict(
        &domain_signature_input(payload_digest),
        &Signature::from_bytes(signature.signature().as_bytes()),
    )
    .map_err(|_| DeploymentControlErrorV2::InvalidDeclassificationRuleSet)
}

fn domain_signature_input(payload_digest: Digest32V2) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(DOMAIN_SIGNATURE_INPUT_V2);
    hash.update(RULE_SET_SIGNATURE_TAG_V2.to_be_bytes());
    hash.update(RULE_SET_SIGNATURE_DOMAIN_V2);
    hash.update(payload_digest.as_bytes());
    hash.finalize().into()
}

fn invalid<T>(result: Result<T, DeploymentControlErrorV2>) -> Result<T, DeploymentControlErrorV2> {
    result.map_err(|_| DeploymentControlErrorV2::InvalidDeclassificationRuleSet)
}

pub(crate) fn compiled_implementation_digest(
    transition: DeclassificationTransitionV2,
) -> Digest32V2 {
    declassification_implementation_digest_v2(transition.tag())
        .expect("closed transition always has a compiled implementation identity")
}
