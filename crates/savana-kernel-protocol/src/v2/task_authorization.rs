//! Bounded, unprivileged task-contract material. Parsing, hashing, or signing this
//! module's objects does not grant execution authority. Trusted issuance, current
//! policy, durable consumption, and effect-gated execution are separate obligations.
use super::{Digest32V2, DurableTaskIdV2, Ed25519SignatureV2, PrincipalIdV2, UnixMillisV2};
use crate::{ProtocolError, StableCode};
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use sha2::{Digest as _, Sha256};

pub const MAX_TASK_AUTHORIZATION_BYTES_V2: usize = 1024 * 1024;
pub const MAX_TASK_AUTHORIZATION_CLAUSES_V2: usize = 64;
pub const MAX_ACTION_ALTERNATIVES_V2: usize = 64;
pub const MAX_TASK_PREDECESSORS_V2: usize = 32;
const SIGN_DOMAIN: &[u8] = b"SAVANA_TASK_AUTHORIZATION_SIGNATURE_V2_SCHEMA1\0";
const TASK_DOMAIN: &[u8] = b"SAVANA_TASK_AUTHORIZATION_DIGEST_V2_SCHEMA1\0";
const ACTION_DOMAIN: &[u8] = b"SAVANA_ACTION_CONTENT_DIGEST_V2_SCHEMA1\0";

fn malformed() -> ProtocolError {
    ProtocolError::stable(StableCode::ProtocolMalformedCbor)
}
fn nonzero(bytes: &[u8]) -> Result<(), ProtocolError> {
    if bytes.iter().all(|b| *b == 0) {
        Err(malformed())
    } else {
        Ok(())
    }
}
type Encoder = minicbor::Encoder<Vec<u8>>;
type Decoder<'a> = minicbor::Decoder<'a>;
trait Wire: Sized {
    fn put(&self, e: &mut Encoder) -> Result<(), ProtocolError>;
    fn get(d: &mut Decoder<'_>) -> Result<Self, ProtocolError>;
}
fn array(d: &mut Decoder<'_>, n: u64) -> Result<(), ProtocolError> {
    if d.array().map_err(ProtocolError::malformed)? == Some(n) {
        Ok(())
    } else {
        Err(malformed())
    }
}
impl Wire for u64 {
    fn put(&self, e: &mut Encoder) -> Result<(), ProtocolError> {
        e.u64(*self).map_err(ProtocolError::malformed)?;
        Ok(())
    }
    fn get(d: &mut Decoder<'_>) -> Result<Self, ProtocolError> {
        d.u64().map_err(ProtocolError::malformed)
    }
}
impl Wire for bool {
    fn put(&self, e: &mut Encoder) -> Result<(), ProtocolError> {
        e.bool(*self).map_err(ProtocolError::malformed)?;
        Ok(())
    }
    fn get(d: &mut Decoder<'_>) -> Result<Self, ProtocolError> {
        d.bool().map_err(ProtocolError::malformed)
    }
}
macro_rules! fixed_wire {
    ($($ty:ident),+) => { $(impl Wire for $ty {
        fn put(&self, e: &mut Encoder) -> Result<(), ProtocolError> { e.bytes(self.as_bytes()).map_err(ProtocolError::malformed)?; Ok(()) }
        fn get(d: &mut Decoder<'_>) -> Result<Self, ProtocolError> { Ok(Self::new(d.bytes().map_err(ProtocolError::malformed)?.try_into().map_err(|_| malformed())?)) }
    })+ };
}
fixed_wire!(
    Digest32V2,
    PrincipalIdV2,
    DurableTaskIdV2,
    Ed25519SignatureV2
);
impl Wire for UnixMillisV2 {
    fn put(&self, e: &mut Encoder) -> Result<(), ProtocolError> {
        self.get().put(e)
    }
    fn get(d: &mut Decoder<'_>) -> Result<Self, ProtocolError> {
        Ok(Self::new(u64::get(d)?))
    }
}
macro_rules! closed_enum {
    ($name:ident { $($variant:ident = $tag:literal),+ $(,)? }) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        #[repr(u8)]
        pub enum $name { $($variant = $tag),+ }
        impl Wire for $name {
            fn put(&self, e: &mut Encoder) -> Result<(), ProtocolError> { (*self as u64).put(e) }
            fn get(d: &mut Decoder<'_>) -> Result<Self, ProtocolError> {
                match u64::get(d)? { $($tag => Ok(Self::$variant),)+ _ => Err(malformed()) }
            }
        }
    };
}
closed_enum!(TaskEvidenceKindV2 { AuthenticatedStructuredInput = 1, ApprovedDraft = 2 });
closed_enum!(ActionCodecProfileV2 { McpToolsCallJsonV1 = 1, FixedJsonPostV1 = 2 });
closed_enum!(TaskEffectV2 { Read = 1, Create = 2, Update = 3, Delete = 4, Send = 5, Execute = 6, FinalRelease = 7 });
closed_enum!(MagnitudeUnitV2 { Count = 1, Bytes = 2 });

#[derive(Debug, Clone, PartialEq, Eq)]
struct BoundedList<T, const N: usize>(Vec<T>);
impl<T, const N: usize> BoundedList<T, N> {
    fn new(values: Vec<T>) -> Result<Self, ProtocolError> {
        if values.len() > N {
            return Err(malformed());
        }
        Ok(Self(values))
    }
}
impl<T: Wire, const N: usize> Wire for BoundedList<T, N> {
    fn put(&self, e: &mut Encoder) -> Result<(), ProtocolError> {
        e.array(u64::try_from(self.0.len()).map_err(|_| malformed())?)
            .map_err(ProtocolError::malformed)?;
        for v in &self.0 {
            v.put(e)?;
        }
        Ok(())
    }
    fn get(d: &mut Decoder<'_>) -> Result<Self, ProtocolError> {
        let len = d
            .array()
            .map_err(ProtocolError::malformed)?
            .ok_or_else(malformed)?;
        let len = usize::try_from(len).map_err(|_| malformed())?;
        if len > N {
            return Err(malformed());
        }
        let mut values = Vec::new();
        values
            .try_reserve_exact(len)
            .map_err(ProtocolError::malformed)?;
        for _ in 0..len {
            values.push(T::get(d)?);
        }
        Ok(Self(values))
    }
}
macro_rules! struct_wire {
    ($ty:ident, $len:literal, $($field:ident),+ $(,)?) => {
        impl Wire for $ty {
            fn put(&self, e: &mut Encoder) -> Result<(), ProtocolError> {
                self.validate()?;
                e.array($len).map_err(ProtocolError::malformed)?;
                $(self.$field.put(e)?;)+ Ok(())
            }
            fn get(d: &mut Decoder<'_>) -> Result<Self, ProtocolError> {
                array(d, $len)?;
                let value = Self { $($field: Wire::get(d)?),+ };
                value.validate()?; Ok(value)
            }
        }
    };
}
macro_rules! getters {
    ($($field:ident: $ty:ty),+ $(,)?) => { $(pub const fn $field(&self) -> $ty { self.$field })+ };
}

/// A complete tuple, never independently combinable sets. Codec names do not
/// imply that a runtime mapping has been implemented or approved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionAlternativeV2 {
    tool_descriptor_digest: Digest32V2,
    codec_profile: ActionCodecProfileV2,
    effect: TaskEffectV2,
    resource_digest: Digest32V2,
    destination_digest: Digest32V2,
    parameters_digest: Digest32V2,
    magnitude_unit: MagnitudeUnitV2,
}
impl ActionAlternativeV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tool_descriptor_digest: Digest32V2,
        codec_profile: ActionCodecProfileV2,
        effect: TaskEffectV2,
        resource_digest: Digest32V2,
        destination_digest: Digest32V2,
        parameters_digest: Digest32V2,
        magnitude_unit: MagnitudeUnitV2,
    ) -> Result<Self, ProtocolError> {
        let value = Self {
            tool_descriptor_digest,
            codec_profile,
            effect,
            resource_digest,
            destination_digest,
            parameters_digest,
            magnitude_unit,
        };
        value.validate()?;
        Ok(value)
    }
    fn validate(&self) -> Result<(), ProtocolError> {
        for digest in [
            self.tool_descriptor_digest,
            self.resource_digest,
            self.destination_digest,
            self.parameters_digest,
        ] {
            nonzero(digest.as_bytes())?;
        }
        Ok(())
    }
    getters!(tool_descriptor_digest: Digest32V2, codec_profile: ActionCodecProfileV2, effect: TaskEffectV2, resource_digest: Digest32V2, destination_digest: Digest32V2, parameters_digest: Digest32V2, magnitude_unit: MagnitudeUnitV2);
}
struct_wire!(
    ActionAlternativeV2,
    7,
    tool_descriptor_digest,
    codec_profile,
    effect,
    resource_digest,
    destination_digest,
    parameters_digest,
    magnitude_unit
);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskAuthorizationClauseV2 {
    clause_id: u64,
    alternatives: BoundedList<ActionAlternativeV2, MAX_ACTION_ALTERNATIVES_V2>,
    maximum_single_magnitude: u64,
    total_magnitude_budget: u64,
    maximum_attempts: u64,
    predecessor_clause_ids: BoundedList<u64, MAX_TASK_PREDECESSORS_V2>,
    retry_after_proven_no_effect: bool,
}
impl TaskAuthorizationClauseV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        clause_id: u64,
        alternatives: Vec<ActionAlternativeV2>,
        maximum_single_magnitude: u64,
        total_magnitude_budget: u64,
        maximum_attempts: u64,
        predecessor_clause_ids: Vec<u64>,
        retry_after_proven_no_effect: bool,
    ) -> Result<Self, ProtocolError> {
        let value = Self {
            clause_id,
            alternatives: BoundedList::new(alternatives)?,
            maximum_single_magnitude,
            total_magnitude_budget,
            maximum_attempts,
            predecessor_clause_ids: BoundedList::new(predecessor_clause_ids)?,
            retry_after_proven_no_effect,
        };
        value.validate()?;
        Ok(value)
    }
    fn validate(&self) -> Result<(), ProtocolError> {
        if self.clause_id == 0
            || self.alternatives.0.is_empty()
            || self.maximum_single_magnitude == 0
            || self.maximum_single_magnitude > self.total_magnitude_budget
            || self.maximum_attempts == 0
        {
            return Err(malformed());
        }
        for (i, alt) in self.alternatives.0.iter().enumerate() {
            alt.validate()?;
            // One scalar budget cannot combine different physical units.
            if alt.magnitude_unit != self.alternatives.0[0].magnitude_unit {
                return Err(malformed());
            }
            if self.alternatives.0[..i].contains(alt) {
                return Err(malformed());
            }
        }
        for (i, id) in self.predecessor_clause_ids.0.iter().enumerate() {
            if *id == 0 || *id == self.clause_id || self.predecessor_clause_ids.0[..i].contains(id)
            {
                return Err(malformed());
            }
        }
        Ok(())
    }
    getters!(clause_id: u64, maximum_single_magnitude: u64,total_magnitude_budget: u64,maximum_attempts: u64,retry_after_proven_no_effect: bool);
    pub fn alternatives(&self) -> &[ActionAlternativeV2] {
        &self.alternatives.0
    }
    pub fn predecessor_clause_ids(&self) -> &[u64] {
        &self.predecessor_clause_ids.0
    }
}
struct_wire!(
    TaskAuthorizationClauseV2,
    7,
    clause_id,
    alternatives,
    maximum_single_magnitude,
    total_magnitude_budget,
    maximum_attempts,
    predecessor_clause_ids,
    retry_after_proven_no_effect
);

/// Independently versioned schema 1; not a modification to any frozen V1 wire type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskAuthorizationV2 {
    schema: u64,
    authorization_id: Digest32V2,
    principal: PrincipalIdV2,
    task: DurableTaskIdV2,
    revision: u64,
    installation_digest: Digest32V2,
    manifest_digest: Digest32V2,
    not_before: UnixMillisV2,
    expires_at: UnixMillisV2,
    evidence_kind: TaskEvidenceKindV2,
    user_evidence_digest: Digest32V2,
    rendering_digest: Digest32V2,
    clauses: BoundedList<TaskAuthorizationClauseV2, MAX_TASK_AUTHORIZATION_CLAUSES_V2>,
}
impl TaskAuthorizationV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        authorization_id: Digest32V2,
        principal: PrincipalIdV2,
        task: DurableTaskIdV2,
        revision: u64,
        installation_digest: Digest32V2,
        manifest_digest: Digest32V2,
        not_before: UnixMillisV2,
        expires_at: UnixMillisV2,
        evidence_kind: TaskEvidenceKindV2,
        user_evidence_digest: Digest32V2,
        rendering_digest: Digest32V2,
        clauses: Vec<TaskAuthorizationClauseV2>,
    ) -> Result<Self, ProtocolError> {
        let value = Self {
            schema: 1,
            authorization_id,
            principal,
            task,
            revision,
            installation_digest,
            manifest_digest,
            not_before,
            expires_at,
            evidence_kind,
            user_evidence_digest,
            rendering_digest,
            clauses: BoundedList::new(clauses)?,
        };
        value.validate()?;
        Ok(value)
    }
    fn validate(&self) -> Result<(), ProtocolError> {
        if self.schema != 1
            || self.revision == 0
            || self.not_before.get() >= self.expires_at.get()
            || self.clauses.0.is_empty()
        {
            return Err(malformed());
        }
        nonzero(self.principal.as_bytes())?;
        nonzero(self.task.as_bytes())?;
        for digest in [
            self.authorization_id,
            self.installation_digest,
            self.manifest_digest,
            self.user_evidence_digest,
            self.rendering_digest,
        ] {
            nonzero(digest.as_bytes())?;
        }
        let mut previous = 0;
        for clause in &self.clauses.0 {
            clause.validate()?;
            if clause.clause_id <= previous {
                return Err(malformed());
            }
            previous = clause.clause_id;
        }
        // Bounded DFS accepts arbitrary stable IDs, including forward dependencies.
        fn visit(
            i: usize,
            clauses: &[TaskAuthorizationClauseV2],
            marks: &mut [u8; 64],
        ) -> Result<(), ProtocolError> {
            if marks[i] == 1 {
                return Err(malformed());
            }
            if marks[i] == 2 {
                return Ok(());
            }
            marks[i] = 1;
            for id in clauses[i].predecessor_clause_ids() {
                let j = clauses
                    .binary_search_by_key(id, |c| c.clause_id)
                    .map_err(|_| malformed())?;
                visit(j, clauses, marks)?;
            }
            marks[i] = 2;
            Ok(())
        }
        let mut marks = [0; 64];
        for i in 0..self.clauses.0.len() {
            visit(i, &self.clauses.0, &mut marks)?;
        }
        Ok(())
    }
    getters!(schema: u64,authorization_id: Digest32V2,principal: PrincipalIdV2,task: DurableTaskIdV2,revision: u64,installation_digest: Digest32V2,manifest_digest: Digest32V2,not_before: UnixMillisV2,expires_at: UnixMillisV2,evidence_kind: TaskEvidenceKindV2,user_evidence_digest: Digest32V2,rendering_digest: Digest32V2);
    pub fn clauses(&self) -> &[TaskAuthorizationClauseV2] {
        &self.clauses.0
    }
}
struct_wire!(
    TaskAuthorizationV2,
    13,
    schema,
    authorization_id,
    principal,
    task,
    revision,
    installation_digest,
    manifest_digest,
    not_before,
    expires_at,
    evidence_kind,
    user_evidence_digest,
    rendering_digest,
    clauses
);

/// Exact proposed content, without an approval/endorsement/authorization digest.
/// Its authorization ID is a reference, not proof of authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionContentV2 {
    schema: u64,
    authorization_id: Digest32V2,
    authorization_revision: u64,
    clause_id: u64,
    alternative_index: u64,
    action: ActionAlternativeV2,
    magnitude: u64,
    payload_digest: Digest32V2,
    provenance_digest: Digest32V2,
    plan_revision_digest: Digest32V2,
    candidate_domain_digest: Digest32V2,
    pre_state_digest: Digest32V2,
    pre_state_revision: u64,
}
impl ActionContentV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        authorization_id: Digest32V2,
        authorization_revision: u64,
        clause_id: u64,
        alternative_index: u64,
        action: ActionAlternativeV2,
        magnitude: u64,
        payload_digest: Digest32V2,
        provenance_digest: Digest32V2,
        plan_revision_digest: Digest32V2,
        candidate_domain_digest: Digest32V2,
        pre_state_digest: Digest32V2,
        pre_state_revision: u64,
    ) -> Result<Self, ProtocolError> {
        let value = Self {
            schema: 1,
            authorization_id,
            authorization_revision,
            clause_id,
            alternative_index,
            action,
            magnitude,
            payload_digest,
            provenance_digest,
            plan_revision_digest,
            candidate_domain_digest,
            pre_state_digest,
            pre_state_revision,
        };
        value.validate()?;
        Ok(value)
    }
    fn validate(&self) -> Result<(), ProtocolError> {
        if self.schema != 1
            || self.authorization_revision == 0
            || self.clause_id == 0
            || self.alternative_index >= 64
            || self.magnitude == 0
        {
            return Err(malformed());
        }
        for digest in [
            self.authorization_id,
            self.payload_digest,
            self.provenance_digest,
            self.plan_revision_digest,
            self.candidate_domain_digest,
            self.pre_state_digest,
        ] {
            nonzero(digest.as_bytes())?;
        }
        self.action.validate()
    }
    getters!(schema: u64,authorization_id: Digest32V2,authorization_revision: u64,clause_id: u64,alternative_index: u64,magnitude: u64,payload_digest: Digest32V2,provenance_digest: Digest32V2,plan_revision_digest: Digest32V2,candidate_domain_digest: Digest32V2,pre_state_digest: Digest32V2,pre_state_revision: u64);
    pub const fn action(&self) -> &ActionAlternativeV2 {
        &self.action
    }
}
struct_wire!(
    ActionContentV2,
    13,
    schema,
    authorization_id,
    authorization_revision,
    clause_id,
    alternative_index,
    action,
    magnitude,
    payload_digest,
    provenance_digest,
    plan_revision_digest,
    candidate_domain_digest,
    pre_state_digest,
    pre_state_revision
);

// Allocation is structurally bounded before encoding: at most 64*64 alternatives,
// each with four 32-byte digests; all other collections and scalar widths bounded.
// The largest representable contract is below 1 MiB even with every u64 at MAX.
fn encode<T: Wire>(value: &T, limit: usize) -> Result<Vec<u8>, ProtocolError> {
    let mut e = Encoder::new(Vec::new());
    value.put(&mut e)?;
    let bytes = e.into_writer();
    if bytes.len() > limit {
        return Err(malformed());
    }
    Ok(bytes)
}
fn decode<T: Wire>(bytes: &[u8], limit: usize) -> Result<T, ProtocolError> {
    if bytes.is_empty() || bytes.len() > limit {
        return Err(malformed());
    }
    let mut d = Decoder::new(bytes);
    let value = T::get(&mut d)?;
    if d.position() != bytes.len() {
        return Err(malformed());
    }
    if encode(&value, limit)? != bytes {
        return Err(ProtocolError::stable(StableCode::ProtocolNonCanonicalCbor));
    }
    Ok(value)
}
pub fn encode_task_authorization_v2(value: &TaskAuthorizationV2) -> Result<Vec<u8>, ProtocolError> {
    encode(value, MAX_TASK_AUTHORIZATION_BYTES_V2)
}
pub fn decode_task_authorization_v2(bytes: &[u8]) -> Result<TaskAuthorizationV2, ProtocolError> {
    decode(bytes, MAX_TASK_AUTHORIZATION_BYTES_V2)
}
pub fn encode_action_content_v2(value: &ActionContentV2) -> Result<Vec<u8>, ProtocolError> {
    encode(value, 1024)
}
pub fn decode_action_content_v2(bytes: &[u8]) -> Result<ActionContentV2, ProtocolError> {
    decode(bytes, 1024)
}
fn hash(domain: &[u8], bytes: &[u8]) -> Digest32V2 {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(bytes);
    Digest32V2::new(hash.finalize().into())
}
pub fn task_authorization_digest_v2(
    value: &TaskAuthorizationV2,
) -> Result<Digest32V2, ProtocolError> {
    Ok(hash(TASK_DOMAIN, &encode_task_authorization_v2(value)?))
}
pub fn action_content_digest_v2(value: &ActionContentV2) -> Result<Digest32V2, ProtocolError> {
    Ok(hash(ACTION_DOMAIN, &encode_action_content_v2(value)?))
}

#[derive(Clone, PartialEq, Eq)]
pub struct SignedTaskAuthorizationV2 {
    canonical_payload: Vec<u8>,
    signature: Ed25519SignatureV2,
}
impl core::fmt::Debug for SignedTaskAuthorizationV2 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SignedTaskAuthorizationV2")
            .field("payload_bytes", &self.canonical_payload.len())
            .finish_non_exhaustive()
    }
}
impl SignedTaskAuthorizationV2 {
    /// Parses bounded canonical material only; does not authenticate the issuer.
    pub fn from_canonical_parts(
        canonical_payload: Vec<u8>,
        signature: Ed25519SignatureV2,
    ) -> Result<Self, ProtocolError> {
        decode_task_authorization_v2(&canonical_payload)?;
        nonzero(signature.as_bytes())?;
        Ok(Self {
            canonical_payload,
            signature,
        })
    }
    pub fn canonical_payload(&self) -> &[u8] {
        &self.canonical_payload
    }
    pub const fn signature(&self) -> Ed25519SignatureV2 {
        self.signature
    }
}
impl Wire for SignedTaskAuthorizationV2 {
    fn put(&self, e: &mut Encoder) -> Result<(), ProtocolError> {
        e.array(3).map_err(ProtocolError::malformed)?;
        1u64.put(e)?;
        e.bytes(&self.canonical_payload)
            .map_err(ProtocolError::malformed)?;
        self.signature.put(e)
    }
    fn get(d: &mut Decoder<'_>) -> Result<Self, ProtocolError> {
        array(d, 3)?;
        if u64::get(d)? != 1 {
            return Err(malformed());
        }
        let payload = d.bytes().map_err(ProtocolError::malformed)?;
        if payload.len() > MAX_TASK_AUTHORIZATION_BYTES_V2 {
            return Err(malformed());
        }
        let signature = Ed25519SignatureV2::get(d)?;
        Self::from_canonical_parts(payload.to_vec(), signature)
    }
}
pub fn encode_signed_task_authorization_v2(
    value: &SignedTaskAuthorizationV2,
) -> Result<Vec<u8>, ProtocolError> {
    encode(value, MAX_TASK_AUTHORIZATION_BYTES_V2 + 128)
}
pub fn decode_signed_task_authorization_v2(
    bytes: &[u8],
) -> Result<SignedTaskAuthorizationV2, ProtocolError> {
    decode(bytes, MAX_TASK_AUTHORIZATION_BYTES_V2 + 128)
}
fn signing_message(payload: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    let len = SIGN_DOMAIN
        .len()
        .checked_add(payload.len())
        .ok_or_else(malformed)?;
    let mut message = Vec::new();
    message
        .try_reserve_exact(len)
        .map_err(ProtocolError::malformed)?;
    message.extend_from_slice(SIGN_DOMAIN);
    message.extend_from_slice(payload);
    Ok(message)
}
/// The caller must source this key from the dedicated trusted issuer. A signature
/// made with an arbitrary planner key confers no authority.
pub fn sign_task_authorization_v2(
    value: TaskAuthorizationV2,
    key: &SigningKey,
) -> Result<SignedTaskAuthorizationV2, ProtocolError> {
    let canonical_payload = encode_task_authorization_v2(&value)?;
    let signature =
        Ed25519SignatureV2::new(key.sign(&signing_message(&canonical_payload)?).to_bytes());
    SignedTaskAuthorizationV2::from_canonical_parts(canonical_payload, signature)
}
/// Validates material against externally supplied trust context, never a wire key.
/// The returned type remains material, not an execution permit. Time is [start,end).
#[allow(clippy::too_many_arguments)]
pub fn verify_task_authorization_v2(
    value: &SignedTaskAuthorizationV2,
    expected_key: &VerifyingKey,
    expected_principal: PrincipalIdV2,
    expected_task: DurableTaskIdV2,
    expected_installation: Digest32V2,
    expected_manifest: Digest32V2,
    now: UnixMillisV2,
) -> Result<TaskAuthorizationV2, ProtocolError> {
    let material = decode_task_authorization_v2(&value.canonical_payload)?;
    expected_key
        .verify_strict(
            &signing_message(&value.canonical_payload)?,
            &Signature::from_bytes(value.signature.as_bytes()),
        )
        .map_err(ProtocolError::malformed)?;
    if material.principal != expected_principal
        || material.task != expected_task
        || material.installation_digest != expected_installation
        || material.manifest_digest != expected_manifest
        || now.get() < material.not_before.get()
        || now.get() >= material.expires_at.get()
    {
        return Err(malformed());
    }
    Ok(material)
}
