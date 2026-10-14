use std::cmp::Ordering;

use savana_kernel_protocol::v2::{
    Digest32V2, DurableRunIdV2, ExecutorIdentityV2, InternalSlotDigestV2, RelationIdV2, SlotKindV2,
    ValueInternalIdV2,
};
use sha2::{Digest as _, Sha256};

use super::{
    digest::{
        argument_digest_v2, evidence_digest_v2, provenance_set_digest_v2, token_set_digest_v2,
        ArgumentDigestEntryV2, EvidenceDigestEntryV2, ProvenanceSetDigestEntryV2,
        TokenSetDigestEntryV2,
    },
    provenance_digest_v2, value_digest_v2, ArgumentNameV2, G4Error, IdentifierV2, KernelValueV2,
    ProvenanceRecordV2, SecurityLabelV2,
};

const MAX_ARGUMENTS: usize = 256;
const MAX_TOKEN_SLOTS: usize = 64;
const MAX_STORED_VALUES: usize = 65_536;
const MAX_PERMITTED_RELATIONS: usize = 64;
const MAX_SLOT_RELATIONS: usize = 512;

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

impl<C> minicbor::Encode<C> for ClosedCardinalityV2 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        _context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        encoder.array(1)?.u16(self.tag())?;
        Ok(())
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

impl<C> minicbor::Encode<C> for PlannerSlotConfidentialityV2 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        _context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        encoder.array(1)?.u16(self.tag())?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResolvedSlotRelationSemanticV2 {
    relation: RelationIdV2,
    left_slot_ordinal: u16,
    right_slot_ordinal: u16,
}

impl ResolvedSlotRelationSemanticV2 {
    pub const fn new(
        relation: RelationIdV2,
        left_slot_ordinal: u16,
        right_slot_ordinal: u16,
    ) -> Self {
        Self {
            relation,
            left_slot_ordinal,
            right_slot_ordinal,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedResolvedRelationSetV2 {
    slot_count: u16,
    relations: Vec<ResolvedSlotRelationSemanticV2>,
    // A complete task tuple is not an ontology RelationId. Keep its evidence
    // domain separate instead of inventing ontology edges for field pairs.
    task_relation: Option<(Digest32V2, Digest32V2, Digest32V2)>,
}

impl VerifiedResolvedRelationSetV2 {
    pub fn from_verified_plan_envelope(
        slot_count: u16,
        relations: Vec<ResolvedSlotRelationSemanticV2>,
    ) -> Result<Self, G4Error> {
        if slot_count == 0
            || usize::from(slot_count) > MAX_ARGUMENTS
            || relations.len() > MAX_SLOT_RELATIONS
            || relations
                .windows(2)
                .any(|pair| relation_semantic_cmp(&pair[0], &pair[1]) != Ordering::Less)
            || relations.iter().any(|relation| {
                relation.left_slot_ordinal >= slot_count
                    || relation.right_slot_ordinal >= slot_count
            })
        {
            return Err(G4Error::InvalidInternalSlotBinding);
        }
        Ok(Self {
            slot_count,
            relations,
            task_relation: None,
        })
    }

    pub fn from_task_match(
        slot_count: u16,
        matched: &super::VerifiedTaskMatchV2,
    ) -> Result<Self, G4Error> {
        let mut relation = Self::from_verified_plan_envelope(slot_count, Vec::new())?;
        let digest = super::task_authorization::hash_parts(
            b"SAVANA_MATCHED_TASK_RELATION_V2_SCHEMA1\0",
            &[
                matched.authorization().digest().as_bytes(),
                matched.content_digest().as_bytes(),
                matched.candidates().digest().as_bytes(),
                &matched.deployment_generation().to_be_bytes(),
            ],
        );
        relation.task_relation = Some((
            matched.authorization().material().installation_digest(),
            matched.authorization().material().manifest_digest(),
            digest,
        ));
        Ok(relation)
    }

    #[cfg(test)]
    pub(crate) fn new_for_test(
        slot_count: u16,
        relations: Vec<ResolvedSlotRelationSemanticV2>,
    ) -> Result<Self, G4Error> {
        Self::from_verified_plan_envelope(slot_count, relations)
    }
}

impl<C> minicbor::Encode<C> for ResolvedSlotRelationSemanticV2 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        encoder.array(3)?;
        self.relation.encode(encoder, context)?;
        encoder
            .u16(self.left_slot_ordinal)?
            .u16(self.right_slot_ordinal)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedInternalSlotMaterialV2 {
    installation_id: Digest32V2,
    active_state_manifest_digest: Digest32V2,
    durable_run_id: DurableRunIdV2,
    slot_ordinal: u16,
    kind: SlotKindV2,
    cardinality: ClosedCardinalityV2,
    confidentiality: PlannerSlotConfidentialityV2,
    permitted_relations: Vec<RelationIdV2>,
    value_internal_id: ValueInternalIdV2,
    value_digest: Digest32V2,
    provenance_digest: Digest32V2,
    relation_semantics_digest: Digest32V2,
}

impl VerifiedInternalSlotMaterialV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn from_resolved_envelope(
        installation_id: Digest32V2,
        active_state_manifest_digest: Digest32V2,
        durable_run_id: DurableRunIdV2,
        slot_ordinal: u16,
        kind: SlotKindV2,
        cardinality: ClosedCardinalityV2,
        confidentiality: PlannerSlotConfidentialityV2,
        permitted_relations: Vec<RelationIdV2>,
        value_internal_id: ValueInternalIdV2,
        value_digest: Digest32V2,
        provenance_digest: Digest32V2,
        resolved_relations: &VerifiedResolvedRelationSetV2,
    ) -> Result<Self, G4Error> {
        let mut incident_relations = Vec::new();
        incident_relations
            .try_reserve_exact(resolved_relations.relations.len())
            .map_err(|_| G4Error::AllocationFailure)?;
        incident_relations.extend(
            resolved_relations
                .relations
                .iter()
                .filter(|relation| {
                    relation.left_slot_ordinal == slot_ordinal
                        || relation.right_slot_ordinal == slot_ordinal
                })
                .copied(),
        );
        if [
            installation_id,
            active_state_manifest_digest,
            Digest32V2::new(*durable_run_id.as_bytes()),
            Digest32V2::new(*value_internal_id.as_bytes()),
            value_digest,
            provenance_digest,
        ]
        .iter()
        .any(|digest| is_zero(digest.as_bytes()))
            || slot_ordinal >= resolved_relations.slot_count
            || permitted_relations.len() > MAX_PERMITTED_RELATIONS
            || permitted_relations
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            || incident_relations.iter().any(|relation| {
                permitted_relations
                    .binary_search(&relation.relation)
                    .is_err()
            })
        {
            return Err(G4Error::InvalidInternalSlotBinding);
        }
        let relation_semantics_digest = relation_semantics_digest_v2(&incident_relations)?;
        let slot = Self {
            installation_id,
            active_state_manifest_digest,
            durable_run_id,
            slot_ordinal,
            kind,
            cardinality,
            confidentiality,
            permitted_relations,
            value_internal_id,
            value_digest,
            provenance_digest,
            relation_semantics_digest,
        };
        if resolved_relations.task_relation.is_some() {
            slot.with_task_relation(resolved_relations)
        } else {
            Ok(slot)
        }
    }

    /// Bind the entire checked task relation to a resolved slot. This does not
    /// grant value effects or create ontology relations. The current owner must
    /// still recheck the match and G5/G7 before dispatch.
    pub fn with_task_relation(
        mut self,
        relations: &VerifiedResolvedRelationSetV2,
    ) -> Result<Self, G4Error> {
        let (installation, manifest, relation) = relations
            .task_relation
            .ok_or(G4Error::InvalidInternalSlotBinding)?;
        if self.installation_id != installation
            || self.active_state_manifest_digest != manifest
            || self.slot_ordinal >= relations.slot_count
            || !relations.relations.is_empty()
            || !self.permitted_relations.is_empty()
        {
            return Err(G4Error::InvalidInternalSlotBinding);
        }
        self.relation_semantics_digest = super::task_authorization::hash_parts(
            b"SAVANA_TASK_SLOT_RELATION_V2_SCHEMA1\0",
            &[
                relation.as_bytes(),
                &relations.slot_count.to_be_bytes(),
                &self.slot_ordinal.to_be_bytes(),
            ],
        );
        Ok(self)
    }

    pub fn internal_slot_digest(&self) -> Result<InternalSlotDigestV2, G4Error> {
        let canonical = minicbor::to_vec(self).map_err(|_| G4Error::BindingDigestFailure)?;
        let digest = domain_hash(b"SAVANA_INTERNAL_SLOT_V2\0", &canonical);
        Ok(InternalSlotDigestV2::new(*digest.as_bytes()))
    }

    /// Verify a recipe's neutral slot witness against the *exact* G4 argument.
    /// Only the task relation may be added. Ontology relations, wrong ordinals,
    /// substituted ownership/value/provenance and already-bound slots fail.
    pub(crate) fn check_fused_recipe_witness(
        &self,
        ordinal: usize,
        argument: &super::StableActionArgumentBindingV2,
        relations: &VerifiedResolvedRelationSetV2,
    ) -> Result<(), G4Error> {
        if usize::from(self.slot_ordinal) != ordinal
            || !self.permitted_relations.is_empty()
            || self.relation_semantics_digest != relation_semantics_digest_v2(&[])?
            || self.value_internal_id != argument.value_internal_id()
            || self.value_digest != argument.value_digest()
            || self.provenance_digest != argument.provenance_digest()
            || self
                .clone()
                .with_task_relation(relations)?
                .internal_slot_digest()?
                != argument.internal_slot_digest()
        {
            return Err(G4Error::InvalidInternalSlotBinding);
        }
        Ok(())
    }
}

impl<C> minicbor::Encode<C> for VerifiedInternalSlotMaterialV2 {
    fn encode<W: minicbor::encode::Write>(
        &self,
        encoder: &mut minicbor::Encoder<W>,
        context: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        encoder.array(12)?;
        self.installation_id.encode(encoder, context)?;
        self.active_state_manifest_digest.encode(encoder, context)?;
        self.durable_run_id.encode(encoder, context)?;
        encoder.u16(self.slot_ordinal)?;
        self.kind.encode(encoder, context)?;
        self.cardinality.encode(encoder, context)?;
        self.confidentiality.encode(encoder, context)?;
        encoder.array(self.permitted_relations.len() as u64)?;
        for relation in &self.permitted_relations {
            relation.encode(encoder, context)?;
        }
        self.value_internal_id.encode(encoder, context)?;
        self.value_digest.encode(encoder, context)?;
        self.provenance_digest.encode(encoder, context)?;
        self.relation_semantics_digest.encode(encoder, context)?;
        Ok(())
    }
}

#[derive(Clone, Copy)]
pub struct StoredValueRecordV2<'value> {
    value_internal_id: ValueInternalIdV2,
    internal_slot_digest: InternalSlotDigestV2,
    durable_run_id: DurableRunIdV2,
    active_state_manifest_digest: Digest32V2,
    value: &'value KernelValueV2,
    provenance: &'value ProvenanceRecordV2,
}

impl<'value> StoredValueRecordV2<'value> {
    pub const fn value_internal_id(&self) -> ValueInternalIdV2 {
        self.value_internal_id
    }
    pub fn from_store(
        slot: &VerifiedInternalSlotMaterialV2,
        value: &'value KernelValueV2,
        provenance: &'value ProvenanceRecordV2,
    ) -> Result<Self, G4Error> {
        let internal_slot_digest = slot.internal_slot_digest()?;
        let value_internal_id = slot.value_internal_id;
        let durable_run_id = slot.durable_run_id;
        let active_state_manifest_digest = slot.active_state_manifest_digest;
        if is_zero(value_internal_id.as_bytes()) || is_zero(internal_slot_digest.as_bytes()) {
            return Err(G4Error::StoredValueMismatch);
        }
        if provenance.run_internal_id() != durable_run_id
            || provenance.active_state_manifest_digest() != active_state_manifest_digest
        {
            return Err(G4Error::StaleStoredBinding);
        }
        let value_digest = value_digest_v2(value).map_err(|_| G4Error::BindingDigestFailure)?;
        let provenance_digest =
            provenance_digest_v2(provenance).map_err(|_| G4Error::BindingDigestFailure)?;
        if value_digest != provenance.value_digest()
            || provenance_digest != provenance.provenance_digest()
            || value_digest != slot.value_digest
            || provenance_digest != slot.provenance_digest
        {
            return Err(G4Error::StoredValueMismatch);
        }
        Ok(Self {
            value_internal_id,
            internal_slot_digest,
            durable_run_id,
            active_state_manifest_digest,
            value,
            provenance,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPlanArgumentV2 {
    argument_name: ArgumentNameV2,
    internal_slot_digest: InternalSlotDigestV2,
    value_internal_id: ValueInternalIdV2,
    value_digest: Digest32V2,
    provenance_digest: Digest32V2,
}

impl VerifiedPlanArgumentV2 {
    pub fn from_verified_plan(
        argument_name: ArgumentNameV2,
        slot: &VerifiedInternalSlotMaterialV2,
    ) -> Result<Self, G4Error> {
        Ok(Self {
            argument_name,
            internal_slot_digest: slot.internal_slot_digest()?,
            value_internal_id: slot.value_internal_id,
            value_digest: slot.value_digest,
            provenance_digest: slot.provenance_digest,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedRequiredTokenV2 {
    token_slot_id: IdentifierV2,
    vault_segment_internal_id: Digest32V2,
    credential_version_digest: Digest32V2,
}

impl VerifiedRequiredTokenV2 {
    pub const fn from_verified_policy(
        token_slot_id: IdentifierV2,
        vault_segment_internal_id: Digest32V2,
        credential_version_digest: Digest32V2,
    ) -> Self {
        Self {
            token_slot_id,
            vault_segment_internal_id,
            credential_version_digest,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredVaultCredentialV2 {
    token_slot_id: IdentifierV2,
    vault_segment_internal_id: Digest32V2,
    credential_version_digest: Digest32V2,
    executor_identity: ExecutorIdentityV2,
}

impl StoredVaultCredentialV2 {
    pub fn from_vault(
        token_slot_id: IdentifierV2,
        vault_segment_internal_id: Digest32V2,
        credential_version_digest: Digest32V2,
        executor_identity: ExecutorIdentityV2,
    ) -> Result<Self, G4Error> {
        if is_zero(vault_segment_internal_id.as_bytes())
            || is_zero(credential_version_digest.as_bytes())
            || is_zero(executor_identity.as_bytes())
        {
            return Err(G4Error::CredentialBindingMismatch);
        }
        Ok(Self {
            token_slot_id,
            vault_segment_internal_id,
            credential_version_digest,
            executor_identity,
        })
    }
}

pub struct ResolvedStoredArgumentV2<'value> {
    argument_name: ArgumentNameV2,
    value_internal_id: ValueInternalIdV2,
    internal_slot_digest: InternalSlotDigestV2,
    value: &'value KernelValueV2,
    provenance: &'value ProvenanceRecordV2,
}

impl<'value> ResolvedStoredArgumentV2<'value> {
    pub const fn argument_name(&self) -> &ArgumentNameV2 {
        &self.argument_name
    }

    pub const fn value_internal_id(&self) -> ValueInternalIdV2 {
        self.value_internal_id
    }

    pub const fn internal_slot_digest(&self) -> InternalSlotDigestV2 {
        self.internal_slot_digest
    }

    pub const fn value(&self) -> &'value KernelValueV2 {
        self.value
    }

    pub const fn provenance(&self) -> &'value ProvenanceRecordV2 {
        self.provenance
    }

    pub const fn label(&self) -> SecurityLabelV2 {
        self.provenance.label()
    }

    pub fn root_evidence(&self) -> &[Digest32V2] {
        self.provenance.root_evidence().as_slice()
    }

    pub const fn value_digest(&self) -> Digest32V2 {
        self.provenance.value_digest()
    }

    pub const fn provenance_digest(&self) -> Digest32V2 {
        self.provenance.provenance_digest()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedStoredTokenV2 {
    pub(crate) token_slot_id: IdentifierV2,
    pub(crate) vault_segment_internal_id: Digest32V2,
    pub(crate) credential_version_digest: Digest32V2,
    pub(crate) executor_identity_digest: Digest32V2,
}

impl ResolvedStoredTokenV2 {
    pub const fn token_slot_id(&self) -> &IdentifierV2 {
        &self.token_slot_id
    }

    pub const fn vault_segment_internal_id(&self) -> Digest32V2 {
        self.vault_segment_internal_id
    }

    pub const fn credential_version_digest(&self) -> Digest32V2 {
        self.credential_version_digest
    }

    pub const fn executor_identity_digest(&self) -> Digest32V2 {
        self.executor_identity_digest
    }
}

pub struct VerifiedStoredBindingsV2<'value> {
    arguments: Vec<ResolvedStoredArgumentV2<'value>>,
    tokens: Vec<ResolvedStoredTokenV2>,
    argument_digest: Digest32V2,
    provenance_set_digest: Digest32V2,
    evidence_digest: Digest32V2,
    token_set_digest: Digest32V2,
    executor_identity_digest: Digest32V2,
}

impl std::fmt::Debug for VerifiedStoredBindingsV2<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VerifiedStoredBindingsV2")
            .field("argument_count", &self.arguments.len())
            .field("token_count", &self.tokens.len())
            .finish_non_exhaustive()
    }
}

impl<'value> VerifiedStoredBindingsV2<'value> {
    /// Project immutable owned values through the descriptor's closed business
    /// grammar. This returns data, not authorization or elevated provenance.
    /// The native caller must select the profile from its active signed registry.
    pub fn business_request(
        &self,
        profile: &savana_kernel_protocol::v2::BusinessProfileV2,
        request_id: &str,
    ) -> Result<savana_kernel_protocol::v2::BusinessRequestV2, G4Error> {
        use savana_kernel_protocol::v2::BusinessRequestV2;
        if self.arguments.len() != profile.fields().len() {
            return Err(G4Error::InvalidIntentBinding);
        }
        let fields = self
            .arguments
            .iter()
            .map(|argument| {
                let value = argument
                    .value()
                    .business_value()
                    .ok_or(G4Error::InvalidIntentBinding)?;
                Ok((argument.argument_name().as_str().to_owned(), value))
            })
            .collect::<Result<Vec<_>, G4Error>>()?;
        BusinessRequestV2::from_fields(profile, request_id, fields)
            .map_err(|_| G4Error::InvalidIntentBinding)
    }

    pub fn arguments(&self) -> &[ResolvedStoredArgumentV2<'value>] {
        &self.arguments
    }

    pub fn tokens(&self) -> &[ResolvedStoredTokenV2] {
        &self.tokens
    }

    pub const fn argument_digest(&self) -> Digest32V2 {
        self.argument_digest
    }

    pub const fn provenance_set_digest(&self) -> Digest32V2 {
        self.provenance_set_digest
    }

    pub const fn evidence_digest(&self) -> Digest32V2 {
        self.evidence_digest
    }

    pub const fn token_set_digest(&self) -> Digest32V2 {
        self.token_set_digest
    }

    pub const fn executor_identity_digest(&self) -> Digest32V2 {
        self.executor_identity_digest
    }
}

pub struct StoredBindingResolverV2;

impl StoredBindingResolverV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn resolve<'value>(
        durable_run_id: DurableRunIdV2,
        active_state_manifest_digest: Digest32V2,
        executor_identity: ExecutorIdentityV2,
        arguments: &[VerifiedPlanArgumentV2],
        stored_values: &[StoredValueRecordV2<'value>],
        required_tokens: &[VerifiedRequiredTokenV2],
        stored_credentials: &[StoredVaultCredentialV2],
    ) -> Result<VerifiedStoredBindingsV2<'value>, G4Error> {
        validate_collection_shapes(
            arguments,
            stored_values,
            required_tokens,
            stored_credentials,
        )?;
        if arguments.iter().enumerate().any(|(index, argument)| {
            arguments[..index]
                .iter()
                .any(|prior| prior.value_internal_id == argument.value_internal_id)
        }) {
            return Err(G4Error::DuplicateStoredValueIdentity);
        }

        let mut resolved_arguments = Vec::new();
        let mut argument_entries = Vec::new();
        let mut provenance_entries = Vec::new();
        let mut evidence_entries = Vec::new();
        for collection in [
            &mut resolved_arguments as &mut dyn FallibleReserve,
            &mut argument_entries,
            &mut provenance_entries,
            &mut evidence_entries,
        ] {
            collection.reserve(arguments.len())?;
        }

        for expected in arguments {
            let stored = stored_values
                .iter()
                .find(|record| record.value_internal_id == expected.value_internal_id)
                .ok_or(G4Error::MissingStoredValue)?;
            if stored.durable_run_id != durable_run_id
                || stored.active_state_manifest_digest != active_state_manifest_digest
            {
                return Err(G4Error::StaleStoredBinding);
            }
            if stored.internal_slot_digest != expected.internal_slot_digest
                || stored.provenance.value_digest() != expected.value_digest
                || stored.provenance.provenance_digest() != expected.provenance_digest
            {
                return Err(G4Error::StoredValueMismatch);
            }
            resolved_arguments.push(ResolvedStoredArgumentV2 {
                argument_name: expected.argument_name.clone(),
                value_internal_id: stored.value_internal_id,
                internal_slot_digest: stored.internal_slot_digest,
                value: stored.value,
                provenance: stored.provenance,
            });
            argument_entries.push(ArgumentDigestEntryV2::new(
                expected.argument_name.clone(),
                stored.value_internal_id,
                expected.value_digest,
                expected.provenance_digest,
            ));
            provenance_entries.push(ProvenanceSetDigestEntryV2::new(
                stored.value_internal_id,
                expected.value_digest,
                expected.provenance_digest,
            ));
            evidence_entries.push(EvidenceDigestEntryV2::new(
                expected.value_digest,
                expected.provenance_digest,
            ));
        }
        provenance_entries.sort_unstable_by(provenance_entry_cmp);
        evidence_entries.sort_unstable_by(evidence_entry_cmp);

        let mut token_entries = Vec::new();
        let mut resolved_tokens = Vec::new();
        token_entries
            .try_reserve_exact(required_tokens.len())
            .map_err(|_| G4Error::AllocationFailure)?;
        resolved_tokens
            .try_reserve_exact(required_tokens.len())
            .map_err(|_| G4Error::AllocationFailure)?;
        for required in required_tokens {
            let stored = stored_credentials
                .iter()
                .find(|credential| credential.token_slot_id == required.token_slot_id)
                .ok_or(G4Error::UnknownVaultTokenSlot)?;
            if stored.vault_segment_internal_id != required.vault_segment_internal_id
                || stored.credential_version_digest != required.credential_version_digest
                || stored.executor_identity != executor_identity
            {
                return Err(G4Error::CredentialBindingMismatch);
            }
            token_entries.push(TokenSetDigestEntryV2::new(
                required.token_slot_id.clone(),
                stored.vault_segment_internal_id,
                stored.credential_version_digest,
                stored.executor_identity,
            ));
            resolved_tokens.push(ResolvedStoredTokenV2 {
                token_slot_id: required.token_slot_id.clone(),
                vault_segment_internal_id: stored.vault_segment_internal_id,
                credential_version_digest: stored.credential_version_digest,
                executor_identity_digest: Digest32V2::new(*stored.executor_identity.as_bytes()),
            });
        }

        Ok(VerifiedStoredBindingsV2 {
            argument_digest: argument_digest_v2(&argument_entries)
                .map_err(|_| G4Error::BindingDigestFailure)?,
            provenance_set_digest: provenance_set_digest_v2(&argument_entries, &provenance_entries)
                .map_err(|_| G4Error::BindingDigestFailure)?,
            evidence_digest: evidence_digest_v2(&evidence_entries)
                .map_err(|_| G4Error::BindingDigestFailure)?,
            token_set_digest: token_set_digest_v2(&token_entries)
                .map_err(|_| G4Error::BindingDigestFailure)?,
            arguments: resolved_arguments,
            tokens: resolved_tokens,
            executor_identity_digest: Digest32V2::new(*executor_identity.as_bytes()),
        })
    }
}

fn validate_collection_shapes(
    arguments: &[VerifiedPlanArgumentV2],
    stored_values: &[StoredValueRecordV2<'_>],
    required_tokens: &[VerifiedRequiredTokenV2],
    stored_credentials: &[StoredVaultCredentialV2],
) -> Result<(), G4Error> {
    if arguments.len() > MAX_ARGUMENTS
        || stored_values.len() > MAX_STORED_VALUES
        || required_tokens.len() > MAX_TOKEN_SLOTS
        || stored_credentials.len() > MAX_TOKEN_SLOTS
    {
        return Err(G4Error::DescriptorLimitExceeded);
    }
    if arguments.windows(2).any(|pair| {
        pair[0].argument_name.as_str().as_bytes() >= pair[1].argument_name.as_str().as_bytes()
    }) || stored_values
        .windows(2)
        .any(|pair| pair[0].value_internal_id.as_bytes() >= pair[1].value_internal_id.as_bytes())
        || required_tokens.windows(2).any(|pair| {
            pair[0].token_slot_id.as_str().as_bytes() >= pair[1].token_slot_id.as_str().as_bytes()
        })
        || stored_credentials.windows(2).any(|pair| {
            pair[0].token_slot_id.as_str().as_bytes() >= pair[1].token_slot_id.as_str().as_bytes()
        })
    {
        return Err(G4Error::NonCanonicalOrder);
    }
    Ok(())
}

fn provenance_entry_cmp(
    left: &ProvenanceSetDigestEntryV2,
    right: &ProvenanceSetDigestEntryV2,
) -> Ordering {
    minicbor::to_vec(left)
        .unwrap_or_default()
        .cmp(&minicbor::to_vec(right).unwrap_or_default())
}

fn evidence_entry_cmp(left: &EvidenceDigestEntryV2, right: &EvidenceDigestEntryV2) -> Ordering {
    minicbor::to_vec(left)
        .unwrap_or_default()
        .cmp(&minicbor::to_vec(right).unwrap_or_default())
}

fn relation_semantics_digest_v2(
    relations: &[ResolvedSlotRelationSemanticV2],
) -> Result<Digest32V2, G4Error> {
    let canonical = minicbor::to_vec(relations).map_err(|_| G4Error::BindingDigestFailure)?;
    Ok(domain_hash(
        b"SAVANA_SLOT_RELATION_SEMANTICS_V2\0",
        &canonical,
    ))
}

fn relation_semantic_cmp(
    left: &ResolvedSlotRelationSemanticV2,
    right: &ResolvedSlotRelationSemanticV2,
) -> Ordering {
    left.relation
        .cmp(&right.relation)
        .then_with(|| left.left_slot_ordinal.cmp(&right.left_slot_ordinal))
        .then_with(|| left.right_slot_ordinal.cmp(&right.right_slot_ordinal))
}

fn domain_hash(domain: &[u8], canonical: &[u8]) -> Digest32V2 {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(canonical);
    Digest32V2::new(hasher.finalize().into())
}

trait FallibleReserve {
    fn reserve(&mut self, additional: usize) -> Result<(), G4Error>;
}

impl<T> FallibleReserve for Vec<T> {
    fn reserve(&mut self, additional: usize) -> Result<(), G4Error> {
        self.try_reserve_exact(additional)
            .map_err(|_| G4Error::AllocationFailure)
    }
}

fn is_zero<const N: usize>(bytes: &[u8; N]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

#[cfg(test)]
#[path = "binding_tests.rs"]
mod tests;
