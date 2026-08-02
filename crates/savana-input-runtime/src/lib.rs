#![forbid(unsafe_code)]

use ed25519_dalek::{Signature, VerifyingKey};
use minicbor::Encode as _;
use savana_kernel_protocol::v2::{
    ActionTemplateIdV2, Digest32V2, Ed25519KeyIdV2, Nonce32V2, PlannerRouteIdV2, RelationIdV2,
    SlotKindV2, UnixMillisV2,
};
use sha2::{Digest as _, Sha256};
use unicode_normalization::{is_nfc, UnicodeNormalization as _};
use zeroize::Zeroizing;

const ASSET_SCHEMA_VERSION: u16 = 2;
const PLANNER_SCHEMA_VERSION: u16 = 2;
const MAX_ASSET_BYTES: usize = 8 * 1024 * 1024;
const MAX_INPUT_BYTES: usize = 8 * 1024 * 1024;
const MAX_RULES: usize = 1_024;
const MAX_RULE_TEXT_BYTES: usize = 256;
const MAX_ACTION_TEMPLATES: usize = 256;
const MAX_PROTECTED_SPANS: usize = 20_000;
const MAX_RELATIONS: usize = 512;
const ASSET_DIGEST_DOMAIN: &[u8] = b"SAVANA_INPUT_RUNTIME_ASSET_V2\0";
const ASSET_SIGNATURE_DOMAIN: &[u8] = b"SAVANA_INPUT_RUNTIME_ASSET_SIGNATURE_V2\0";
const INPUT_COMMITMENT_DOMAIN: &[u8] = b"SAVANA_G1_INPUT_COMMITMENT_V2\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum InputRuntimeError {
    #[error("input-runtime artifact is not exact canonical V2 CBOR")]
    NonCanonicalAsset,
    #[error("input-runtime artifact signature or publisher binding is invalid")]
    InvalidAssetSignature,
    #[error("input-runtime artifact is outside its validity window")]
    AssetNotActive,
    #[error("input-runtime artifact violates a compiled or signed limit")]
    AssetLimitExceeded,
    #[error("input-runtime input exceeds the active limit")]
    InputLimitExceeded,
    #[error("input-runtime input contains forbidden Unicode controls")]
    ForbiddenUnicode,
    #[error("G1 denied an indirect prompt-injection rule")]
    PromptInjectionDenied,
    #[error("G2 extraction was unmatched or ambiguous")]
    ExtractionDenied,
    #[error("G2 extraction attempted an unapproved closed identifier")]
    WhitelistDenied,
    #[error("input-runtime entropy failed closed")]
    EntropyUnavailable,
    #[error("input-runtime allocation failed")]
    AllocationFailure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InputChannelV2 {
    OriginalSource,
    ChatText,
    ExtractedPage,
    ToolResult,
}

impl InputChannelV2 {
    const fn tag(self) -> u16 {
        match self {
            Self::OriginalSource => 1,
            Self::ChatText => 2,
            Self::ExtractedPage => 3,
            Self::ToolResult => 4,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum DetectionClassV2 {
    /// Keys, tokens, and anything else that grants access on presentation.
    Credential,
    /// Data about a person: identifiers, contact details, account numbers.
    PersonalData,
    /// A path or filename whose name alone discloses protected content.
    ProtectedReference,
}

impl DetectionClassV2 {
    /// Slot kinds 1-5 named the five hand-written detectors this crate used
    /// before the gate became the single definition. They are deliberately not
    /// reused: a durable slot recorded as kind 1 means "email address", and
    /// redefining 1 would silently change what already-persisted records say.
    /// The retired numbers stay retired and the current classes start at 6.
    const fn default_slot_kind(self) -> SlotKindV2 {
        SlotKindV2::new(match self {
            Self::Credential => 6,
            Self::PersonalData => 7,
            Self::ProtectedReference => 8,
        })
    }

    const fn from_gate(class: savana_leak_gate::PiiClassV2) -> Self {
        match class {
            savana_leak_gate::PiiClassV2::Credential => Self::Credential,
            savana_leak_gate::PiiClassV2::PersonalData => Self::PersonalData,
            savana_leak_gate::PiiClassV2::ProtectedReference => Self::ProtectedReference,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IntentKindV2 {
    SendMessage,
    Search,
    SummarizeDocument,
    StoreRecord,
}

impl IntentKindV2 {
    const fn tag(self) -> u16 {
        match self {
            Self::SendMessage => 1,
            Self::Search => 2,
            Self::SummarizeDocument => 3,
            Self::StoreRecord => 4,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClosedCardinalityV2 {
    ExactlyOne,
    ZeroOrOne,
    OneOrMore,
    ZeroOrMore,
}

impl ClosedCardinalityV2 {
    const fn tag(self) -> u16 {
        match self {
            Self::ExactlyOne => 1,
            Self::ZeroOrOne => 2,
            Self::OneOrMore => 3,
            Self::ZeroOrMore => 4,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PlannerSlotConfidentialityV2 {
    PublicStructural,
    ConfidentialAbstract,
}

impl PlannerSlotConfidentialityV2 {
    const fn tag(self) -> u16 {
        match self {
            Self::PublicStructural => 1,
            Self::ConfidentialAbstract => 2,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PlannerSlotRefV2([u8; 16]);

impl PlannerSlotRefV2 {
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl<C> minicbor::Encode<C> for PlannerSlotRefV2 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        _context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        encoder.bytes(&self.0)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlannerLimitsV2 {
    maximum_steps: u16,
    maximum_dependencies_per_step: u16,
    maximum_arguments_per_step: u16,
    maximum_encoded_plan_bytes: u32,
}

impl PlannerLimitsV2 {
    pub const fn maximum_steps(self) -> u16 {
        self.maximum_steps
    }

    pub const fn maximum_dependencies_per_step(self) -> u16 {
        self.maximum_dependencies_per_step
    }

    pub const fn maximum_arguments_per_step(self) -> u16 {
        self.maximum_arguments_per_step
    }

    pub const fn maximum_encoded_plan_bytes(self) -> u32 {
        self.maximum_encoded_plan_bytes
    }
}

impl<C> minicbor::Encode<C> for PlannerLimitsV2 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        _context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        encoder
            .array(4)?
            .u16(self.maximum_steps)?
            .u16(self.maximum_dependencies_per_step)?
            .u16(self.maximum_arguments_per_step)?
            .u32(self.maximum_encoded_plan_bytes)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbstractSlotV2 {
    reference: PlannerSlotRefV2,
    kind: SlotKindV2,
    cardinality: ClosedCardinalityV2,
    confidentiality: PlannerSlotConfidentialityV2,
    permitted_relations: Vec<RelationIdV2>,
}

impl AbstractSlotV2 {
    pub const fn reference(&self) -> PlannerSlotRefV2 {
        self.reference
    }

    pub const fn kind(&self) -> SlotKindV2 {
        self.kind
    }
}

impl<C> minicbor::Encode<C> for AbstractSlotV2 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        encoder.array(5)?;
        self.reference.encode(encoder, context)?;
        self.kind.encode(encoder, context)?;
        encoder
            .u16(self.cardinality.tag())?
            .u16(self.confidentiality.tag())?
            .array(self.permitted_relations.len() as u64)?;
        for relation in &self.permitted_relations {
            relation.encode(encoder, context)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbstractRelationV2 {
    relation: RelationIdV2,
    left: PlannerSlotRefV2,
    right: PlannerSlotRefV2,
}

impl<C> minicbor::Encode<C> for AbstractRelationV2 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        encoder.array(3)?;
        self.relation.encode(encoder, context)?;
        self.left.encode(encoder, context)?;
        self.right.encode(encoder, context)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannerEnvelopeV2 {
    planner_route: PlannerRouteIdV2,
    task_template: u32,
    intent: IntentKindV2,
    allowed_action_templates: Vec<ActionTemplateIdV2>,
    slots: Vec<AbstractSlotV2>,
    relations: Vec<AbstractRelationV2>,
    effective_limits: PlannerLimitsV2,
    envelope_nonce: Nonce32V2,
    expires_at: UnixMillisV2,
}

impl PlannerEnvelopeV2 {
    pub const fn planner_route(&self) -> PlannerRouteIdV2 {
        self.planner_route
    }

    pub const fn task_template(&self) -> u32 {
        self.task_template
    }

    pub const fn intent(&self) -> IntentKindV2 {
        self.intent
    }

    pub fn allowed_action_templates(&self) -> &[ActionTemplateIdV2] {
        &self.allowed_action_templates
    }

    pub const fn effective_limits(&self) -> PlannerLimitsV2 {
        self.effective_limits
    }

    pub fn slots(&self) -> &[AbstractSlotV2] {
        &self.slots
    }

    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, InputRuntimeError> {
        minicbor::to_vec(self).map_err(|_| InputRuntimeError::AssetLimitExceeded)
    }
}

impl<C> minicbor::Encode<C> for PlannerEnvelopeV2 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        encoder.array(10)?.u16(PLANNER_SCHEMA_VERSION)?;
        self.planner_route.encode(encoder, context)?;
        encoder.u32(self.task_template)?.u16(self.intent.tag())?;
        encoder.array(self.allowed_action_templates.len() as u64)?;
        for template in &self.allowed_action_templates {
            template.encode(encoder, context)?;
        }
        encoder.array(self.slots.len() as u64)?;
        for slot in &self.slots {
            slot.encode(encoder, context)?;
        }
        encoder.array(self.relations.len() as u64)?;
        for relation in &self.relations {
            relation.encode(encoder, context)?;
        }
        self.effective_limits.encode(encoder, context)?;
        self.envelope_nonce.encode(encoder, context)?;
        self.expires_at.encode(encoder, context)?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct ProtectedValueV2 {
    class: DetectionClassV2,
    value: Zeroizing<String>,
    slot_reference: PlannerSlotRefV2,
    start: usize,
    end: usize,
}

impl ProtectedValueV2 {
    pub const fn class(&self) -> DetectionClassV2 {
        self.class
    }

    pub fn value(&self) -> &str {
        &self.value
    }

    pub const fn slot_reference(&self) -> PlannerSlotRefV2 {
        self.slot_reference
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaskedInputPlaceholderV2 {
    token: String,
    class: DetectionClassV2,
}

impl MaskedInputPlaceholderV2 {
    pub fn token(&self) -> &str {
        &self.token
    }

    pub const fn class(&self) -> DetectionClassV2 {
        self.class
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaskedAgentInputV2 {
    text: String,
    placeholders: Vec<MaskedInputPlaceholderV2>,
}

impl MaskedAgentInputV2 {
    pub fn text(&self) -> &str {
        &self.text
    }

    pub fn placeholders(&self) -> &[MaskedInputPlaceholderV2] {
        &self.placeholders
    }
}

#[derive(Debug)]
pub struct GatedPlannerInputV2 {
    normalized_input: Zeroizing<String>,
    protected_values: Vec<ProtectedValueV2>,
    input_commitment: Digest32V2,
    planner_envelope: PlannerEnvelopeV2,
}

impl GatedPlannerInputV2 {
    pub fn normalized_input(&self) -> &str {
        &self.normalized_input
    }

    pub fn protected_values(&self) -> &[ProtectedValueV2] {
        &self.protected_values
    }

    pub const fn input_commitment(&self) -> Digest32V2 {
        self.input_commitment
    }

    pub const fn planner_envelope(&self) -> &PlannerEnvelopeV2 {
        &self.planner_envelope
    }

    pub fn masked_agent_input(&self) -> Result<MaskedAgentInputV2, InputRuntimeError> {
        let mut text = String::new();
        text.try_reserve(self.normalized_input.len())
            .map_err(|_| InputRuntimeError::AllocationFailure)?;
        let mut placeholders = Vec::new();
        placeholders
            .try_reserve_exact(self.protected_values.len())
            .map_err(|_| InputRuntimeError::AllocationFailure)?;
        let mut cursor = 0_usize;
        for (ordinal, protected) in self.protected_values.iter().enumerate() {
            if protected.start < cursor
                || protected.end <= protected.start
                || protected.end > self.normalized_input.len()
                || !self.normalized_input.is_char_boundary(protected.start)
                || !self.normalized_input.is_char_boundary(protected.end)
            {
                return Err(InputRuntimeError::ForbiddenUnicode);
            }
            let token = placeholder_token(ordinal, protected.slot_reference)?;
            text.push_str(
                self.normalized_input
                    .get(cursor..protected.start)
                    .ok_or(InputRuntimeError::ForbiddenUnicode)?,
            );
            text.push_str(&token);
            placeholders.push(MaskedInputPlaceholderV2 {
                token,
                class: protected.class,
            });
            cursor = protected.end;
        }
        text.push_str(
            self.normalized_input
                .get(cursor..)
                .ok_or(InputRuntimeError::ForbiddenUnicode)?,
        );
        if text.len() > MAX_INPUT_BYTES {
            return Err(InputRuntimeError::InputLimitExceeded);
        }
        Ok(MaskedAgentInputV2 { text, placeholders })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct InjectionRuleV2 {
    rule_id: u32,
    needle: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ExtractionRuleV2 {
    rule_id: u32,
    trigger: String,
    intent: IntentKindV2,
    task_template: u32,
    allowed_action_templates: Vec<ActionTemplateIdV2>,
    link_relation: Option<RelationIdV2>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ActiveInputLimitsV2 {
    maximum_input_bytes: u32,
    maximum_protected_spans: u16,
    planner_limits: PlannerLimitsV2,
}

#[derive(Debug, Clone)]
struct UnsignedInputRuntimeAssetsV2 {
    not_before: UnixMillisV2,
    expires_at: UnixMillisV2,
    planner_route: PlannerRouteIdV2,
    limits: ActiveInputLimitsV2,
    injection_rules: Vec<InjectionRuleV2>,
    extraction_rules: Vec<ExtractionRuleV2>,
}

#[derive(Debug, Clone)]
pub struct SignedInputRuntimeAssetsV2 {
    unsigned_payload: Vec<u8>,
    publisher_key_id: Ed25519KeyIdV2,
    signature: [u8; 64],
}

impl SignedInputRuntimeAssetsV2 {
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, InputRuntimeError> {
        if bytes.len() > MAX_ASSET_BYTES {
            return Err(InputRuntimeError::AssetLimitExceeded);
        }
        let mut decoder = minicbor::Decoder::new(bytes);
        require_array(&mut decoder, 3)?;
        let unsigned_payload = decoder
            .bytes()
            .map_err(|_| InputRuntimeError::NonCanonicalAsset)?
            .to_vec();
        let publisher_key_id = Ed25519KeyIdV2::new(decode_fixed::<32>(&mut decoder)?);
        let signature = decode_fixed::<64>(&mut decoder)?;
        if decoder.position() != bytes.len() {
            return Err(InputRuntimeError::NonCanonicalAsset);
        }
        decode_unsigned_assets(&unsigned_payload)?;
        let signed = Self {
            unsigned_payload,
            publisher_key_id,
            signature,
        };
        if minicbor::to_vec(&signed).map_err(|_| InputRuntimeError::NonCanonicalAsset)? != bytes {
            return Err(InputRuntimeError::NonCanonicalAsset);
        }
        Ok(signed)
    }
}

impl<C> minicbor::Encode<C> for SignedInputRuntimeAssetsV2 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        encoder.array(3)?.bytes(&self.unsigned_payload)?;
        self.publisher_key_id.encode(encoder, context)?;
        encoder.bytes(&self.signature)?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct VerifiedInputRuntimeAssetsV2 {
    unsigned: UnsignedInputRuntimeAssetsV2,
    asset_digest: Digest32V2,
}

impl VerifiedInputRuntimeAssetsV2 {
    pub fn verify(
        signed: &SignedInputRuntimeAssetsV2,
        expected_publisher_key_id: Ed25519KeyIdV2,
        verifying_key: [u8; 32],
        now: UnixMillisV2,
    ) -> Result<Self, InputRuntimeError> {
        if signed.publisher_key_id != expected_publisher_key_id {
            return Err(InputRuntimeError::InvalidAssetSignature);
        }
        let key = VerifyingKey::from_bytes(&verifying_key)
            .map_err(|_| InputRuntimeError::InvalidAssetSignature)?;
        let asset_digest = domain_hash(ASSET_DIGEST_DOMAIN, &signed.unsigned_payload);
        let mut signed_bytes = Vec::with_capacity(ASSET_SIGNATURE_DOMAIN.len() + 32);
        signed_bytes.extend_from_slice(ASSET_SIGNATURE_DOMAIN);
        signed_bytes.extend_from_slice(asset_digest.as_bytes());
        key.verify_strict(&signed_bytes, &Signature::from_bytes(&signed.signature))
            .map_err(|_| InputRuntimeError::InvalidAssetSignature)?;
        let unsigned = decode_unsigned_assets(&signed.unsigned_payload)?;
        if now.get() < unsigned.not_before.get() || now.get() >= unsigned.expires_at.get() {
            return Err(InputRuntimeError::AssetNotActive);
        }
        Ok(Self {
            unsigned,
            asset_digest,
        })
    }

    pub const fn asset_digest(&self) -> Digest32V2 {
        self.asset_digest
    }
}

pub struct InputRuntimeV2 {
    assets: VerifiedInputRuntimeAssetsV2,
}

impl InputRuntimeV2 {
    pub const fn new(assets: VerifiedInputRuntimeAssetsV2) -> Self {
        Self { assets }
    }

    pub fn process(
        &self,
        channel: InputChannelV2,
        original_input: &str,
        now: UnixMillisV2,
    ) -> Result<GatedPlannerInputV2, InputRuntimeError> {
        if now.get() < self.assets.unsigned.not_before.get()
            || now.get() >= self.assets.unsigned.expires_at.get()
        {
            return Err(InputRuntimeError::AssetNotActive);
        }
        if original_input.len() > MAX_INPUT_BYTES
            || original_input.len()
                > usize::try_from(self.assets.unsigned.limits.maximum_input_bytes)
                    .map_err(|_| InputRuntimeError::InputLimitExceeded)?
        {
            return Err(InputRuntimeError::InputLimitExceeded);
        }
        reject_forbidden_unicode(original_input)?;
        let normalized = original_input.nfc().collect::<String>();
        reject_forbidden_unicode(&normalized)?;
        let folded = normalized.to_lowercase();
        if self
            .assets
            .unsigned
            .injection_rules
            .iter()
            .any(|rule| folded.contains(&rule.needle))
        {
            return Err(InputRuntimeError::PromptInjectionDenied);
        }

        let extraction = select_extraction_rule(&self.assets.unsigned.extraction_rules, &folded)?;
        let spans = detect_protected_spans(&normalized)?;
        let span_limit = usize::from(self.assets.unsigned.limits.maximum_protected_spans);
        if spans.len() > span_limit || spans.len() > MAX_PROTECTED_SPANS {
            return Err(InputRuntimeError::InputLimitExceeded);
        }
        let (nonce, references) = draw_envelope_entropy(spans.len())?;
        let mut protected_values = Vec::new();
        let mut slots = Vec::new();
        protected_values
            .try_reserve_exact(spans.len())
            .map_err(|_| InputRuntimeError::AllocationFailure)?;
        slots
            .try_reserve_exact(spans.len())
            .map_err(|_| InputRuntimeError::AllocationFailure)?;
        for (span, reference) in spans.iter().zip(references) {
            let value = normalized
                .get(span.start..span.end)
                .ok_or(InputRuntimeError::ForbiddenUnicode)?;
            protected_values.push(ProtectedValueV2 {
                class: span.class,
                value: Zeroizing::new(value.to_owned()),
                slot_reference: reference,
                start: span.start,
                end: span.end,
            });
            slots.push(AbstractSlotV2 {
                reference,
                kind: span.class.default_slot_kind(),
                cardinality: ClosedCardinalityV2::ExactlyOne,
                confidentiality: PlannerSlotConfidentialityV2::ConfidentialAbstract,
                permitted_relations: extraction.link_relation.into_iter().collect(),
            });
        }
        let relations = build_relations(&slots, extraction.link_relation)?;
        let expires_at = UnixMillisV2::new(
            now.get()
                .checked_add(60_000)
                .ok_or(InputRuntimeError::AssetLimitExceeded)?
                .min(self.assets.unsigned.expires_at.get()),
        );
        let planner_envelope = PlannerEnvelopeV2 {
            planner_route: self.assets.unsigned.planner_route,
            task_template: extraction.task_template,
            intent: extraction.intent,
            allowed_action_templates: extraction.allowed_action_templates.clone(),
            slots,
            relations,
            effective_limits: self.assets.unsigned.limits.planner_limits,
            envelope_nonce: nonce,
            expires_at,
        };
        let input_commitment = input_commitment(channel, &normalized);
        Ok(GatedPlannerInputV2 {
            normalized_input: Zeroizing::new(normalized),
            protected_values,
            input_commitment,
            planner_envelope,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DetectedSpanV2 {
    start: usize,
    end: usize,
    class: DetectionClassV2,
}

fn reject_forbidden_unicode(value: &str) -> Result<(), InputRuntimeError> {
    if value.chars().any(|character| {
        matches!(
            character,
            '\0' | '\u{202a}'
                | '\u{202b}'
                | '\u{202c}'
                | '\u{202d}'
                | '\u{202e}'
                | '\u{2066}'
                | '\u{2067}'
                | '\u{2068}'
                | '\u{2069}'
        ) || (character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
    }) {
        return Err(InputRuntimeError::ForbiddenUnicode);
    }
    Ok(())
}

fn select_extraction_rule<'rules>(
    rules: &'rules [ExtractionRuleV2],
    folded: &str,
) -> Result<&'rules ExtractionRuleV2, InputRuntimeError> {
    let mut matched = rules.iter().filter(|rule| folded.contains(&rule.trigger));
    let selected = matched.next().ok_or(InputRuntimeError::ExtractionDenied)?;
    if matched.next().is_some() {
        return Err(InputRuntimeError::ExtractionDenied);
    }
    Ok(selected)
}

/// Every region the leak gate considers sensitive.
///
/// This crate used to carry its own hand-written detectors — a byte scanner for
/// five classes, covering emails, phone numbers, `bearer `, three credential
/// assignment prefixes, and private key blocks. The kernel verifies
/// declassification against a different and much broader definition, and two
/// definitions of "sensitive" cannot agree by inspection: anything the masker
/// missed but the verifier catches (bank card numbers, national identifiers, IP
/// addresses, JWTs, cloud keys, sensitive paths) would leave a value masked
/// here and refused there. Both sides now call the same function, so they agree
/// by construction. The gate's differential asserts the exact property this
/// relies on: spans are found precisely when redaction would rewrite something.
fn detect_protected_spans(value: &str) -> Result<Vec<DetectedSpanV2>, InputRuntimeError> {
    let mut spans = Vec::new();
    let found = savana_leak_gate::pii_spans(value);
    spans
        .try_reserve_exact(found.len())
        .map_err(|_| InputRuntimeError::AllocationFailure)?;
    // `pii_spans` already returns spans sorted and non-overlapping, asserted
    // over the gate's whole corpus, so there is nothing to reconcile here.
    for span in found {
        spans.push(DetectedSpanV2 {
            start: span.start,
            end: span.end,
            class: DetectionClassV2::from_gate(span.class),
        });
    }
    canonicalize_spans(spans)
}

fn canonicalize_spans(
    mut spans: Vec<DetectedSpanV2>,
) -> Result<Vec<DetectedSpanV2>, InputRuntimeError> {
    spans.sort_unstable_by(|left, right| {
        left.start
            .cmp(&right.start)
            .then_with(|| right.end.cmp(&left.end))
            .then_with(|| right.class.cmp(&left.class))
    });
    let mut selected: Vec<DetectedSpanV2> = Vec::new();
    selected
        .try_reserve_exact(spans.len())
        .map_err(|_| InputRuntimeError::AllocationFailure)?;
    for span in spans {
        if let Some(last) = selected.last_mut() {
            if span.start < last.end {
                last.end = last.end.max(span.end);
                last.class = last.class.max(span.class);
                continue;
            }
        }
        selected.push(span);
    }
    Ok(selected)
}

fn draw_envelope_entropy(
    slot_count: usize,
) -> Result<(Nonce32V2, Vec<PlannerSlotRefV2>), InputRuntimeError> {
    let mut nonce = [0_u8; 32];
    getrandom::getrandom(&mut nonce).map_err(|_| InputRuntimeError::EntropyUnavailable)?;
    if nonce == [0; 32] {
        return Err(InputRuntimeError::EntropyUnavailable);
    }
    let mut references = Vec::new();
    references
        .try_reserve_exact(slot_count)
        .map_err(|_| InputRuntimeError::AllocationFailure)?;
    for _ in 0..slot_count {
        let mut reference = [0_u8; 16];
        getrandom::getrandom(&mut reference).map_err(|_| InputRuntimeError::EntropyUnavailable)?;
        if reference == [0; 16]
            || references
                .iter()
                .any(|prior: &PlannerSlotRefV2| prior.0 == reference)
        {
            return Err(InputRuntimeError::EntropyUnavailable);
        }
        references.push(PlannerSlotRefV2(reference));
    }
    Ok((Nonce32V2::new(nonce), references))
}

fn build_relations(
    slots: &[AbstractSlotV2],
    relation: Option<RelationIdV2>,
) -> Result<Vec<AbstractRelationV2>, InputRuntimeError> {
    let Some(relation) = relation else {
        return Ok(Vec::new());
    };
    if slots.len() < 2 {
        return Ok(Vec::new());
    }
    let count = slots.len() - 1;
    if count > MAX_RELATIONS {
        return Err(InputRuntimeError::AssetLimitExceeded);
    }
    let mut relations = Vec::new();
    relations
        .try_reserve_exact(count)
        .map_err(|_| InputRuntimeError::AllocationFailure)?;
    for pair in slots.windows(2) {
        relations.push(AbstractRelationV2 {
            relation,
            left: pair[0].reference,
            right: pair[1].reference,
        });
    }
    Ok(relations)
}

fn input_commitment(channel: InputChannelV2, normalized: &str) -> Digest32V2 {
    let mut hasher = Sha256::new();
    hasher.update(INPUT_COMMITMENT_DOMAIN);
    hasher.update(channel.tag().to_be_bytes());
    hasher.update((normalized.len() as u64).to_be_bytes());
    hasher.update(normalized.as_bytes());
    Digest32V2::new(hasher.finalize().into())
}

fn placeholder_token(
    ordinal: usize,
    reference: PlannerSlotRefV2,
) -> Result<String, InputRuntimeError> {
    const ALPHA_HEX: &[u8; 16] = b"abcdefghijklmnop";
    let ordinal = u32::try_from(ordinal).map_err(|_| InputRuntimeError::InputLimitExceeded)?;
    let mut token = String::new();
    token
        .try_reserve_exact(59)
        .map_err(|_| InputRuntimeError::AllocationFailure)?;
    token.push_str("[SAVANA_REDACTED_");
    for byte in ordinal.to_be_bytes() {
        token.push(char::from(ALPHA_HEX[usize::from(byte >> 4)]));
        token.push(char::from(ALPHA_HEX[usize::from(byte & 0x0f)]));
    }
    token.push('_');
    for byte in reference.as_bytes() {
        token.push(char::from(ALPHA_HEX[usize::from(byte >> 4)]));
        token.push(char::from(ALPHA_HEX[usize::from(byte & 0x0f)]));
    }
    token.push(']');
    Ok(token)
}

fn decode_unsigned_assets(bytes: &[u8]) -> Result<UnsignedInputRuntimeAssetsV2, InputRuntimeError> {
    if bytes.len() > MAX_ASSET_BYTES {
        return Err(InputRuntimeError::AssetLimitExceeded);
    }
    let mut decoder = minicbor::Decoder::new(bytes);
    require_array(&mut decoder, 7)?;
    if decoder
        .u16()
        .map_err(|_| InputRuntimeError::NonCanonicalAsset)?
        != ASSET_SCHEMA_VERSION
    {
        return Err(InputRuntimeError::NonCanonicalAsset);
    }
    let not_before = UnixMillisV2::new(
        decoder
            .u64()
            .map_err(|_| InputRuntimeError::NonCanonicalAsset)?,
    );
    let expires_at = UnixMillisV2::new(
        decoder
            .u64()
            .map_err(|_| InputRuntimeError::NonCanonicalAsset)?,
    );
    let planner_route = PlannerRouteIdV2::new(
        decoder
            .u32()
            .map_err(|_| InputRuntimeError::NonCanonicalAsset)?,
    );
    require_array(&mut decoder, 6)?;
    let maximum_input_bytes = decoder
        .u32()
        .map_err(|_| InputRuntimeError::NonCanonicalAsset)?;
    let maximum_protected_spans = decoder
        .u16()
        .map_err(|_| InputRuntimeError::NonCanonicalAsset)?;
    let planner_limits = PlannerLimitsV2 {
        maximum_steps: decoder
            .u16()
            .map_err(|_| InputRuntimeError::NonCanonicalAsset)?,
        maximum_dependencies_per_step: decoder
            .u16()
            .map_err(|_| InputRuntimeError::NonCanonicalAsset)?,
        maximum_arguments_per_step: decoder
            .u16()
            .map_err(|_| InputRuntimeError::NonCanonicalAsset)?,
        maximum_encoded_plan_bytes: decoder
            .u32()
            .map_err(|_| InputRuntimeError::NonCanonicalAsset)?,
    };
    let injection_count = bounded_array(&mut decoder, MAX_RULES)?;
    let mut injection_rules = Vec::new();
    injection_rules
        .try_reserve_exact(injection_count)
        .map_err(|_| InputRuntimeError::AllocationFailure)?;
    for _ in 0..injection_count {
        require_array(&mut decoder, 2)?;
        let rule_id = decoder
            .u32()
            .map_err(|_| InputRuntimeError::NonCanonicalAsset)?;
        let needle = decode_rule_text(&mut decoder)?;
        injection_rules.push(InjectionRuleV2 { rule_id, needle });
    }
    let extraction_count = bounded_array(&mut decoder, MAX_RULES)?;
    let mut extraction_rules = Vec::new();
    extraction_rules
        .try_reserve_exact(extraction_count)
        .map_err(|_| InputRuntimeError::AllocationFailure)?;
    for _ in 0..extraction_count {
        require_array(&mut decoder, 6)?;
        let rule_id = decoder
            .u32()
            .map_err(|_| InputRuntimeError::NonCanonicalAsset)?;
        let trigger = decode_rule_text(&mut decoder)?;
        let intent = decode_intent(
            decoder
                .u16()
                .map_err(|_| InputRuntimeError::NonCanonicalAsset)?,
        )?;
        let task_template = decoder
            .u32()
            .map_err(|_| InputRuntimeError::NonCanonicalAsset)?;
        let action_count = bounded_array(&mut decoder, MAX_ACTION_TEMPLATES)?;
        let mut allowed_action_templates = Vec::new();
        allowed_action_templates
            .try_reserve_exact(action_count)
            .map_err(|_| InputRuntimeError::AllocationFailure)?;
        for _ in 0..action_count {
            allowed_action_templates.push(ActionTemplateIdV2::new(
                decoder
                    .u32()
                    .map_err(|_| InputRuntimeError::NonCanonicalAsset)?,
            ));
        }
        let link_relation = match decoder
            .datatype()
            .map_err(|_| InputRuntimeError::NonCanonicalAsset)?
        {
            minicbor::data::Type::Null => {
                decoder
                    .null()
                    .map_err(|_| InputRuntimeError::NonCanonicalAsset)?;
                None
            }
            _ => Some(RelationIdV2::new(
                decoder
                    .u32()
                    .map_err(|_| InputRuntimeError::NonCanonicalAsset)?,
            )),
        };
        extraction_rules.push(ExtractionRuleV2 {
            rule_id,
            trigger,
            intent,
            task_template,
            allowed_action_templates,
            link_relation,
        });
    }
    if decoder.position() != bytes.len() {
        return Err(InputRuntimeError::NonCanonicalAsset);
    }
    let unsigned = UnsignedInputRuntimeAssetsV2 {
        not_before,
        expires_at,
        planner_route,
        limits: ActiveInputLimitsV2 {
            maximum_input_bytes,
            maximum_protected_spans,
            planner_limits,
        },
        injection_rules,
        extraction_rules,
    };
    validate_assets(&unsigned)?;
    if encode_unsigned_assets(&unsigned)? != bytes {
        return Err(InputRuntimeError::NonCanonicalAsset);
    }
    Ok(unsigned)
}

fn encode_unsigned_assets(
    assets: &UnsignedInputRuntimeAssetsV2,
) -> Result<Vec<u8>, InputRuntimeError> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(7)
        .and_then(|encoder| encoder.u16(ASSET_SCHEMA_VERSION))
        .and_then(|encoder| encoder.u64(assets.not_before.get()))
        .and_then(|encoder| encoder.u64(assets.expires_at.get()))
        .map_err(|_| InputRuntimeError::NonCanonicalAsset)?;
    assets
        .planner_route
        .encode(&mut encoder, &mut ())
        .map_err(|_| InputRuntimeError::NonCanonicalAsset)?;
    encoder
        .array(6)
        .and_then(|encoder| encoder.u32(assets.limits.maximum_input_bytes))
        .and_then(|encoder| encoder.u16(assets.limits.maximum_protected_spans))
        .and_then(|encoder| encoder.u16(assets.limits.planner_limits.maximum_steps))
        .and_then(|encoder| encoder.u16(assets.limits.planner_limits.maximum_dependencies_per_step))
        .and_then(|encoder| encoder.u16(assets.limits.planner_limits.maximum_arguments_per_step))
        .and_then(|encoder| encoder.u32(assets.limits.planner_limits.maximum_encoded_plan_bytes))
        .and_then(|encoder| encoder.array(assets.injection_rules.len() as u64))
        .map_err(|_| InputRuntimeError::NonCanonicalAsset)?;
    for rule in &assets.injection_rules {
        encoder
            .array(2)
            .and_then(|encoder| encoder.u32(rule.rule_id))
            .and_then(|encoder| encoder.str(&rule.needle))
            .map_err(|_| InputRuntimeError::NonCanonicalAsset)?;
    }
    encoder
        .array(assets.extraction_rules.len() as u64)
        .map_err(|_| InputRuntimeError::NonCanonicalAsset)?;
    for rule in &assets.extraction_rules {
        encoder
            .array(6)
            .and_then(|encoder| encoder.u32(rule.rule_id))
            .and_then(|encoder| encoder.str(&rule.trigger))
            .and_then(|encoder| encoder.u16(rule.intent.tag()))
            .and_then(|encoder| encoder.u32(rule.task_template))
            .and_then(|encoder| encoder.array(rule.allowed_action_templates.len() as u64))
            .map_err(|_| InputRuntimeError::NonCanonicalAsset)?;
        for template in &rule.allowed_action_templates {
            template
                .encode(&mut encoder, &mut ())
                .map_err(|_| InputRuntimeError::NonCanonicalAsset)?;
        }
        match rule.link_relation {
            Some(relation) => {
                relation
                    .encode(&mut encoder, &mut ())
                    .map_err(|_| InputRuntimeError::NonCanonicalAsset)?;
            }
            None => {
                encoder
                    .null()
                    .map_err(|_| InputRuntimeError::NonCanonicalAsset)?;
            }
        };
    }
    Ok(encoder.into_writer())
}

fn validate_assets(assets: &UnsignedInputRuntimeAssetsV2) -> Result<(), InputRuntimeError> {
    if assets.not_before.get() >= assets.expires_at.get()
        || assets.planner_route.get() == 0
        || assets.limits.maximum_input_bytes == 0
        || usize::try_from(assets.limits.maximum_input_bytes).unwrap_or(usize::MAX)
            > MAX_INPUT_BYTES
        || assets.limits.maximum_protected_spans == 0
        || usize::from(assets.limits.maximum_protected_spans) > MAX_PROTECTED_SPANS
        || assets.limits.planner_limits.maximum_steps == 0
        || assets.limits.planner_limits.maximum_steps > 256
        || assets.limits.planner_limits.maximum_dependencies_per_step > 256
        || assets.limits.planner_limits.maximum_arguments_per_step > 256
        || assets.limits.planner_limits.maximum_encoded_plan_bytes == 0
        || assets.injection_rules.len() > MAX_RULES
        || assets.extraction_rules.is_empty()
        || assets.extraction_rules.len() > MAX_RULES
    {
        return Err(InputRuntimeError::AssetLimitExceeded);
    }
    if assets
        .injection_rules
        .windows(2)
        .any(|pair| pair[0].rule_id >= pair[1].rule_id)
        || assets
            .extraction_rules
            .windows(2)
            .any(|pair| pair[0].rule_id >= pair[1].rule_id)
    {
        return Err(InputRuntimeError::NonCanonicalAsset);
    }
    for rule in &assets.injection_rules {
        if rule.rule_id == 0
            || rule.needle.is_empty()
            || rule.needle.len() > MAX_RULE_TEXT_BYTES
            || !is_nfc(&rule.needle)
            || rule.needle != rule.needle.to_lowercase()
        {
            return Err(InputRuntimeError::NonCanonicalAsset);
        }
    }
    for rule in &assets.extraction_rules {
        if rule.rule_id == 0
            || rule.trigger.is_empty()
            || rule.trigger.len() > MAX_RULE_TEXT_BYTES
            || !is_nfc(&rule.trigger)
            || rule.trigger != rule.trigger.to_lowercase()
            || rule.task_template == 0
            || rule.allowed_action_templates.is_empty()
            || rule
                .allowed_action_templates
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            || rule
                .allowed_action_templates
                .iter()
                .any(|template| template.get() == 0)
            || rule
                .link_relation
                .is_some_and(|relation| relation.get() == 0)
        {
            return Err(InputRuntimeError::WhitelistDenied);
        }
    }
    Ok(())
}

fn decode_rule_text(decoder: &mut minicbor::Decoder<'_>) -> Result<String, InputRuntimeError> {
    let value = decoder
        .str()
        .map_err(|_| InputRuntimeError::NonCanonicalAsset)?;
    if value.is_empty() || value.len() > MAX_RULE_TEXT_BYTES || !is_nfc(value) {
        return Err(InputRuntimeError::NonCanonicalAsset);
    }
    Ok(value.to_owned())
}

fn decode_intent(tag: u16) -> Result<IntentKindV2, InputRuntimeError> {
    match tag {
        1 => Ok(IntentKindV2::SendMessage),
        2 => Ok(IntentKindV2::Search),
        3 => Ok(IntentKindV2::SummarizeDocument),
        4 => Ok(IntentKindV2::StoreRecord),
        _ => Err(InputRuntimeError::WhitelistDenied),
    }
}

fn domain_hash(domain: &[u8], bytes: &[u8]) -> Digest32V2 {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(bytes);
    Digest32V2::new(hasher.finalize().into())
}

fn bounded_array(
    decoder: &mut minicbor::Decoder<'_>,
    maximum: usize,
) -> Result<usize, InputRuntimeError> {
    let Some(length) = decoder
        .array()
        .map_err(|_| InputRuntimeError::NonCanonicalAsset)?
    else {
        return Err(InputRuntimeError::NonCanonicalAsset);
    };
    let length = usize::try_from(length).map_err(|_| InputRuntimeError::AssetLimitExceeded)?;
    if length > maximum {
        return Err(InputRuntimeError::AssetLimitExceeded);
    }
    Ok(length)
}

fn require_array(
    decoder: &mut minicbor::Decoder<'_>,
    expected: u64,
) -> Result<(), InputRuntimeError> {
    if decoder
        .array()
        .map_err(|_| InputRuntimeError::NonCanonicalAsset)?
        != Some(expected)
    {
        return Err(InputRuntimeError::NonCanonicalAsset);
    }
    Ok(())
}

fn decode_fixed<const N: usize>(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<[u8; N], InputRuntimeError> {
    decoder
        .bytes()
        .map_err(|_| InputRuntimeError::NonCanonicalAsset)?
        .try_into()
        .map_err(|_| InputRuntimeError::NonCanonicalAsset)
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer as _, SigningKey};

    use super::*;

    fn assets() -> (SignedInputRuntimeAssetsV2, Ed25519KeyIdV2, [u8; 32]) {
        let unsigned = UnsignedInputRuntimeAssetsV2 {
            not_before: UnixMillisV2::new(10),
            expires_at: UnixMillisV2::new(10_000),
            planner_route: PlannerRouteIdV2::new(7),
            limits: ActiveInputLimitsV2 {
                maximum_input_bytes: 4096,
                maximum_protected_spans: 32,
                planner_limits: PlannerLimitsV2 {
                    maximum_steps: 8,
                    maximum_dependencies_per_step: 8,
                    maximum_arguments_per_step: 8,
                    maximum_encoded_plan_bytes: 65_536,
                },
            },
            injection_rules: vec![
                InjectionRuleV2 {
                    rule_id: 1,
                    needle: "ignore previous instructions".to_owned(),
                },
                InjectionRuleV2 {
                    rule_id: 2,
                    needle: "reveal system prompt".to_owned(),
                },
            ],
            extraction_rules: vec![
                ExtractionRuleV2 {
                    rule_id: 1,
                    trigger: "send".to_owned(),
                    intent: IntentKindV2::SendMessage,
                    task_template: 11,
                    allowed_action_templates: vec![ActionTemplateIdV2::new(21)],
                    link_relation: Some(RelationIdV2::new(31)),
                },
                ExtractionRuleV2 {
                    rule_id: 2,
                    trigger: "summarize".to_owned(),
                    intent: IntentKindV2::SummarizeDocument,
                    task_template: 12,
                    allowed_action_templates: vec![ActionTemplateIdV2::new(22)],
                    link_relation: None,
                },
            ],
        };
        let payload = encode_unsigned_assets(&unsigned).unwrap();
        let signing = SigningKey::from_bytes(&[0x41; 32]);
        let key_id = Ed25519KeyIdV2::new([0x42; 32]);
        let digest = domain_hash(ASSET_DIGEST_DOMAIN, &payload);
        let mut signed_bytes = Vec::new();
        signed_bytes.extend_from_slice(ASSET_SIGNATURE_DOMAIN);
        signed_bytes.extend_from_slice(digest.as_bytes());
        let signed = SignedInputRuntimeAssetsV2 {
            unsigned_payload: payload,
            publisher_key_id: key_id,
            signature: signing.sign(&signed_bytes).to_bytes(),
        };
        (signed, key_id, signing.verifying_key().to_bytes())
    }

    fn runtime() -> InputRuntimeV2 {
        let (signed, key_id, key) = assets();
        let canonical = minicbor::to_vec(&signed).unwrap();
        let parsed = SignedInputRuntimeAssetsV2::from_canonical_bytes(&canonical).unwrap();
        InputRuntimeV2::new(
            VerifiedInputRuntimeAssetsV2::verify(&parsed, key_id, key, UnixMillisV2::new(100))
                .unwrap(),
        )
    }

    #[test]
    fn signed_assets_reject_substitution_wrong_key_and_noncanonical_bytes() {
        let (signed, key_id, key) = assets();
        let mut canonical = minicbor::to_vec(&signed).unwrap();
        let last = canonical.last_mut().unwrap();
        *last ^= 1;
        let modified = SignedInputRuntimeAssetsV2::from_canonical_bytes(&canonical).unwrap();
        assert_eq!(
            VerifiedInputRuntimeAssetsV2::verify(&modified, key_id, key, UnixMillisV2::new(100))
                .unwrap_err(),
            InputRuntimeError::InvalidAssetSignature
        );
        assert_eq!(
            VerifiedInputRuntimeAssetsV2::verify(
                &signed,
                Ed25519KeyIdV2::new([0xff; 32]),
                key,
                UnixMillisV2::new(100)
            )
            .unwrap_err(),
            InputRuntimeError::InvalidAssetSignature
        );
    }

    #[test]
    fn g1_normalizes_tokenizes_and_denies_injection_and_bidi_controls() {
        let runtime = runtime();
        let accepted = runtime
            .process(
                InputChannelV2::ChatText,
                "Send to alice@example.test and +1 (212) 555-0100",
                UnixMillisV2::new(200),
            )
            .unwrap();
        assert_eq!(accepted.protected_values().len(), 2);
        assert_eq!(
            accepted.protected_values()[0].class(),
            DetectionClassV2::PersonalData
        );
        assert_ne!(accepted.input_commitment().as_bytes(), &[0; 32]);
        let masked = accepted.masked_agent_input().unwrap();
        assert!(!masked.text().contains("alice@example.test"));
        assert!(!masked.text().contains("+1 (212) 555-0100"));
        assert_eq!(masked.placeholders().len(), 2);
        for (ordinal, placeholder) in masked.placeholders().iter().enumerate() {
            assert!(masked.text().contains(placeholder.token()));
            let ordinal = u32::try_from(ordinal).unwrap();
            let encoded_ordinal = ordinal
                .to_be_bytes()
                .into_iter()
                .flat_map(|byte| [byte >> 4, byte & 0x0f])
                .map(|nibble| char::from(b'a' + nibble))
                .collect::<String>();
            assert!(placeholder
                .token()
                .starts_with(&format!("[SAVANA_REDACTED_{encoded_ordinal}_")));
        }
        assert_eq!(
            runtime
                .process(
                    InputChannelV2::ChatText,
                    "Send and IGNORE PREVIOUS INSTRUCTIONS",
                    UnixMillisV2::new(200)
                )
                .unwrap_err(),
            InputRuntimeError::PromptInjectionDenied
        );
        assert_eq!(
            runtime
                .process(
                    InputChannelV2::ChatText,
                    "Send \u{202e}secret",
                    UnixMillisV2::new(200)
                )
                .unwrap_err(),
            InputRuntimeError::ForbiddenUnicode
        );
    }

    #[test]
    fn masked_placeholder_tokens_are_not_residual_pii() {
        let reference = PlannerSlotRefV2([0x08; 16]);
        let token = placeholder_token(0, reference).unwrap();

        assert_eq!(savana_leak_gate::redact_pii(&token), token);
    }

    #[test]
    fn g2_is_closed_ambiguous_fail_closed_and_planner_bytes_contain_no_input() {
        let runtime = runtime();
        let gated = runtime
            .process(
                InputChannelV2::ChatText,
                "Send to alice@example.test password=hunter2",
                UnixMillisV2::new(200),
            )
            .unwrap();
        assert_eq!(gated.planner_envelope().intent(), IntentKindV2::SendMessage);
        assert_eq!(
            gated.planner_envelope().planner_route(),
            PlannerRouteIdV2::new(7)
        );
        assert_eq!(gated.planner_envelope().task_template(), 11);
        assert_eq!(
            gated.planner_envelope().effective_limits().maximum_steps(),
            8
        );
        assert_eq!(
            gated
                .planner_envelope()
                .effective_limits()
                .maximum_dependencies_per_step(),
            8
        );
        assert_eq!(
            gated
                .planner_envelope()
                .effective_limits()
                .maximum_arguments_per_step(),
            8
        );
        assert_eq!(
            gated
                .planner_envelope()
                .effective_limits()
                .maximum_encoded_plan_bytes(),
            65_536
        );
        assert_eq!(gated.planner_envelope().slots().len(), 2);
        let wire = gated.planner_envelope().to_canonical_bytes().unwrap();
        for forbidden in [b"alice@example.test".as_slice(), b"hunter2", b"password"] {
            assert!(!wire
                .windows(forbidden.len())
                .any(|window| window == forbidden));
        }
        assert_eq!(
            runtime
                .process(
                    InputChannelV2::ChatText,
                    "Please send and summarize alice@example.test",
                    UnixMillisV2::new(200)
                )
                .unwrap_err(),
            InputRuntimeError::ExtractionDenied
        );
        assert_eq!(
            runtime
                .process(
                    InputChannelV2::ChatText,
                    "Do something unknown",
                    UnixMillisV2::new(200)
                )
                .unwrap_err(),
            InputRuntimeError::ExtractionDenied
        );
    }

    #[test]
    fn secret_overlap_prefers_the_stronger_closed_class() {
        let runtime = runtime();
        let gated = runtime
            .process(
                InputChannelV2::ChatText,
                "Send Bearer alice@example.test",
                UnixMillisV2::new(200),
            )
            .unwrap();
        assert_eq!(gated.protected_values().len(), 1);
        assert_eq!(
            gated.protected_values()[0].class(),
            DetectionClassV2::Credential
        );
    }
}
