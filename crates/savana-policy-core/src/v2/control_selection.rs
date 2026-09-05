//! Control-plane evidence is deliberately disjoint from ordinary value provenance.
//! No endorsement constructor accepts a boolean, raw digest, or runtime candidate list.
use super::{
    task_authorization::{hash_parts, is_zero},
    task_effect_set_v2, EffectSetV2, IntegrityV2, TaskAuthorizationErrorV2 as Error,
    TaskMatchContextV2, VerifiedTaskMatchV2,
};
use savana_kernel_protocol::v2::{
    ActionCodecProfileV2, Digest32V2, MagnitudeUnitV2, TaskActionApprovalContextV2,
    VerifiedTaskActionApprovalV2,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ControlFacetV2 {
    Tool,
    EffectKind,
    Scope,
    Magnitude,
    Argument,
    Destination,
    Trigger,
}
impl ControlFacetV2 {
    pub const ALL: [Self; 7] = [
        Self::Tool,
        Self::EffectKind,
        Self::Scope,
        Self::Magnitude,
        Self::Argument,
        Self::Destination,
        Self::Trigger,
    ];
    pub const fn tag(self) -> u8 {
        match self {
            Self::Tool => 1,
            Self::EffectKind => 2,
            Self::Scope => 3,
            Self::Magnitude => 4,
            Self::Argument => 5,
            Self::Destination => 6,
            Self::Trigger => 7,
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlSelectionV2 {
    facet: ControlFacetV2,
    content_digest: Digest32V2,
    proposer_parent: Digest32V2,
    selected_digest: Digest32V2,
}
impl ControlSelectionV2 {
    pub fn from_match(
        m: &VerifiedTaskMatchV2,
        proposer_parent: Digest32V2,
    ) -> Result<[Self; 7], Error> {
        if is_zero(proposer_parent) {
            return Err(Error::SelectionMismatch);
        }
        Ok(ControlFacetV2::ALL.map(|facet| Self {
            facet,
            content_digest: m.content_digest(),
            proposer_parent,
            selected_digest: facet_digest(m, facet),
        }))
    }
    pub fn facet(&self) -> ControlFacetV2 {
        self.facet
    }
    pub fn proposer_parent(&self) -> Digest32V2 {
        self.proposer_parent
    }
    pub fn content_digest(&self) -> Digest32V2 {
        self.content_digest
    }
    pub fn selected_digest(&self) -> Digest32V2 {
        self.selected_digest
    }
    pub const fn integrity(&self) -> IntegrityV2 {
        IntegrityV2::ExternalUntrusted
    }
    pub const fn allowed_effects(&self) -> EffectSetV2 {
        EffectSetV2::READ
    }
    pub fn digest(&self) -> Digest32V2 {
        hash_parts(
            b"SAVANA_CONTROL_SELECTION_V2_SCHEMA1\0",
            &[
                &[self.facet.tag()],
                self.content_digest.as_bytes(),
                self.proposer_parent.as_bytes(),
                self.selected_digest.as_bytes(),
                &IntegrityV2::ExternalUntrusted.tag().to_be_bytes(),
                &EffectSetV2::READ.bits().to_be_bytes(),
            ],
        )
    }
}
fn facet_digest(m: &VerifiedTaskMatchV2, facet: ControlFacetV2) -> Digest32V2 {
    let c = m.content();
    let a = c.action();
    let projection = match facet {
        ControlFacetV2::Tool => {
            let codec: u8 = match a.codec_profile() {
                ActionCodecProfileV2::McpToolsCallJsonV1 => 1,
                ActionCodecProfileV2::FixedJsonPostV1 => 2,
            };
            [a.tool_descriptor_digest().as_bytes().as_slice(), &[codec]].concat()
        }
        ControlFacetV2::EffectKind => task_effect_set_v2(a.effect()).bits().to_be_bytes().to_vec(),
        ControlFacetV2::Scope => a.resource_digest().as_bytes().to_vec(),
        ControlFacetV2::Magnitude => {
            let unit: u8 = match a.magnitude_unit() {
                MagnitudeUnitV2::Count => 1,
                MagnitudeUnitV2::Bytes => 2,
            };
            [&[unit], c.magnitude().to_be_bytes().as_slice()].concat()
        }
        ControlFacetV2::Argument => a.parameters_digest().as_bytes().to_vec(),
        ControlFacetV2::Destination => a.destination_digest().as_bytes().to_vec(),
        ControlFacetV2::Trigger => {
            let mut p = Vec::new();
            p.extend_from_slice(c.pre_state_digest().as_bytes());
            p.extend_from_slice(&c.pre_state_revision().to_be_bytes());
            for id in m.clause().predecessor_clause_ids() {
                p.extend_from_slice(&id.to_be_bytes());
            }
            p
        }
    };
    hash_parts(
        b"SAVANA_CONTROL_FACET_V2_SCHEMA1\0",
        &[&[facet.tag()], &projection],
    )
}
/// Closed evidence choices. An explicit alternative is still checked against the
/// entire relation; requesting this branch is not itself proof of membership.
#[derive(Debug, Clone, Copy)]
pub enum ControlEvidenceV2<'a> {
    ExplicitAlternative,
    /// One complete alternative and exactly one allowed positive magnitude.
    CompleteContractSingleton,
    ActionApproval {
        approval: &'a VerifiedTaskActionApprovalV2,
        expected_context: &'a TaskActionApprovalContextV2,
    },
}
#[derive(Debug, Clone, PartialEq, Eq)]
enum CheckedEvidence {
    ExplicitAlternative,
    CompleteContractSingleton,
    ActionApproval(VerifiedTaskActionApprovalV2),
}
impl CheckedEvidence {
    fn tag(&self) -> u8 {
        match self {
            Self::ExplicitAlternative => 1,
            Self::CompleteContractSingleton => 2,
            Self::ActionApproval(_) => 3,
        }
    }
    fn settlement_digest(&self) -> Option<Digest32V2> {
        match self {
            Self::ActionApproval(a) => Some(a.digest()),
            _ => None,
        }
    }
    fn recheck(
        &self,
        m: &VerifiedTaskMatchV2,
        current: &TaskMatchContextV2<'_>,
    ) -> Result<(), Error> {
        match self {
            Self::ExplicitAlternative => Ok(()),
            Self::CompleteContractSingleton => {
                if m.candidates().candidate_count() == 1
                    && m.clause().maximum_single_magnitude() == 1
                {
                    Ok(())
                } else {
                    Err(Error::EvidenceMismatch)
                }
            }
            Self::ActionApproval(a) => check_approval(m, a, a.material().context(), current),
        }
    }
}
fn check_approval(
    m: &VerifiedTaskMatchV2,
    a: &VerifiedTaskActionApprovalV2,
    c: &TaskActionApprovalContextV2,
    current: &TaskMatchContextV2<'_>,
) -> Result<(), Error> {
    let auth = m.authorization().material();
    if c.content_digest != m.content_digest()
        || c.authorization_id != auth.authorization_id()
        || c.authorization_revision != auth.revision()
        || c.principal != auth.principal()
        || c.task != auth.task()
        || c.installation_digest != auth.installation_digest()
        || c.manifest_digest != auth.manifest_digest()
        || c.deployment_generation != current.deployment_generation
    {
        return Err(Error::EvidenceMismatch);
    }
    a.recheck(c, current.now)
        .map_err(|_| Error::EvidenceMismatch)
}
/// Not a KernelValueV2 and not a ProvenanceRecordV2. Normal value derivation
/// cannot consume this type as either a value or a provenance parent.
/// ```compile_fail
/// use savana_policy_core::v2::{ControlEndorsementV2,ProvenanceRecordV2,
///     ProvenanceContextV2,KernelValueV2,DeriveOperationV2,EffectSetV2};
/// fn derive(ctx: ProvenanceContextV2, value: &KernelValueV2, endorsement: &ControlEndorsementV2) {
///     ProvenanceRecordV2::derived(ctx, DeriveOperationV2::normalize_nfc(),
///         &[(value, endorsement)], EffectSetV2::ALL);
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlEndorsementV2 {
    selection: ControlSelectionV2,
    contract_digest: Digest32V2,
    candidate_digest: Digest32V2,
    pre_state_digest: Digest32V2,
    pre_state_revision: u64,
    deployment_generation: u64,
    evidence: CheckedEvidence,
}
impl ControlEndorsementV2 {
    pub fn facet(&self) -> ControlFacetV2 {
        self.selection.facet
    }
    pub fn selection(&self) -> &ControlSelectionV2 {
        &self.selection
    }
    pub fn settlement_digest(&self) -> Option<Digest32V2> {
        self.evidence.settlement_digest()
    }
    /// The nonce comes only from the same immutable, signature-verified proof as
    /// settlement_digest(). Cloning this evidence does not consume the nonce.
    pub fn settlement_nonce(&self) -> Option<Digest32V2> {
        match &self.evidence {
            CheckedEvidence::ActionApproval(approval) => {
                Some(approval.material().context().settlement_nonce)
            }
            _ => None,
        }
    }
    pub fn digest(&self) -> Digest32V2 {
        let settlement = self.settlement_digest();
        let bytes = settlement
            .as_ref()
            .map(|d| d.as_bytes().as_slice())
            .unwrap_or(&[]);
        hash_parts(
            b"SAVANA_CONTROL_ENDORSEMENT_V2_SCHEMA1\0",
            &[
                self.selection.digest().as_bytes(),
                self.contract_digest.as_bytes(),
                self.candidate_digest.as_bytes(),
                self.pre_state_digest.as_bytes(),
                &self.pre_state_revision.to_be_bytes(),
                &self.deployment_generation.to_be_bytes(),
                &[self.evidence.tag()],
                bytes,
            ],
        )
    }
}
pub fn checked_control_endorsements_v2(
    m: &VerifiedTaskMatchV2,
    selections: &[ControlSelectionV2],
    evidence: ControlEvidenceV2<'_>,
    current: &TaskMatchContextV2<'_>,
) -> Result<[ControlEndorsementV2; 7], Error> {
    m.recheck(current)?; // No evidence branch may precede the whole-action match.
    let first = selections.first().ok_or(Error::SelectionMismatch)?;
    let expected = ControlSelectionV2::from_match(m, first.proposer_parent)?;
    if selections != expected {
        return Err(Error::SelectionMismatch);
    }
    let evidence = match evidence {
        ControlEvidenceV2::ExplicitAlternative => CheckedEvidence::ExplicitAlternative,
        ControlEvidenceV2::CompleteContractSingleton => CheckedEvidence::CompleteContractSingleton,
        ControlEvidenceV2::ActionApproval {
            approval,
            expected_context,
        } => {
            check_approval(m, approval, expected_context, current)?;
            CheckedEvidence::ActionApproval(approval.clone())
        }
    };
    evidence.recheck(m, current)?;
    Ok(expected.map(|selection| ControlEndorsementV2 {
        selection,
        contract_digest: m.authorization().digest(),
        candidate_digest: m.candidates().digest(),
        pre_state_digest: m.content().pre_state_digest(),
        pre_state_revision: m.content().pre_state_revision(),
        deployment_generation: m.deployment_generation(),
        evidence: evidence.clone(),
    }))
}
/// A digest of verified static evidence, explicitly not a dispatch capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthorizationDigestV2(Digest32V2);
impl AuthorizationDigestV2 {
    pub fn digest(self) -> Digest32V2 {
        self.0
    }
}
/// `transition_digest` commits to an acyclic next-state projection: expected
/// pre-state/revision, charged clause/magnitude/attempt delta, successor revision.
/// It MUST exclude this authorization digest and future evidence containing it.
/// Only the atomic owner can establish/consume that transition authoritatively.
/// Endorsements must be exactly seven, in facet order; never silently sorted.
pub fn authorization_digest_v2(
    m: &VerifiedTaskMatchV2,
    endorsements: &[ControlEndorsementV2],
    policy_identity: Digest32V2,
    transition_digest: Digest32V2,
    current: &TaskMatchContextV2<'_>,
) -> Result<AuthorizationDigestV2, Error> {
    m.recheck(current)?;
    if endorsements.len() != 7 || is_zero(policy_identity) || is_zero(transition_digest) {
        return Err(Error::InvalidDigestInput);
    }
    let first = &endorsements[0];
    let selections = ControlSelectionV2::from_match(m, first.selection.proposer_parent)?;
    for (e, s) in endorsements.iter().zip(selections) {
        if e.selection != s
            || e.contract_digest != m.authorization().digest()
            || e.candidate_digest != m.candidates().digest()
            || e.pre_state_digest != m.content().pre_state_digest()
            || e.pre_state_revision != m.content().pre_state_revision()
            || e.deployment_generation != m.deployment_generation()
            || e.evidence != first.evidence
        {
            return Err(Error::EvidenceMismatch);
        }
        e.evidence.recheck(m, current)?;
    }
    let mut endorsement_bytes = Vec::with_capacity(7 * 32);
    for e in endorsements {
        endorsement_bytes.extend_from_slice(e.digest().as_bytes());
    }
    // One evidence choice for the whole action; at most one settlement, already
    // deduplicated across facets. The owner must consume its nonce exactly once.
    let settlement = first.settlement_digest();
    let settlement_bytes = settlement
        .as_ref()
        .map(|d| d.as_bytes().as_slice())
        .unwrap_or(&[]);
    Ok(AuthorizationDigestV2(hash_parts(
        b"SAVANA_AUTHORIZATION_DIGEST_V2_SCHEMA1\0",
        &[
            m.content_digest().as_bytes(),
            m.authorization().digest().as_bytes(),
            m.candidates().digest().as_bytes(),
            m.content().pre_state_digest().as_bytes(),
            &m.content().pre_state_revision().to_be_bytes(),
            &m.deployment_generation().to_be_bytes(),
            &endorsement_bytes,
            settlement_bytes,
            policy_identity.as_bytes(),
            transition_digest.as_bytes(),
        ],
    )))
}
