//! Readable, unprivileged contract proposal, separate from the later signed root.
//! No approval/settlement/final-authorization digest is an input to this object.
//! Identity fields are claims until checked against the authenticated owner, and
//! each profile must exactly match a currently active signed tool descriptor.
use super::super::{
    approval_display_digest_v2, decode_business_controls_v2, encode_business_controls_v2,
    BoundedApprovalDisplayTextV2, BusinessControlsV2, BusinessMagnitudeV2,
};
use super::*;

pub const MAX_TASK_AUTHORIZATION_DRAFT_BYTES_V2: usize = 1024 * 1024;
const DRAFT_DOMAIN: &[u8] = b"SAVANA_TASK_AUTHORIZATION_DRAFT_V2_SCHEMA1\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskAuthorizationDraftAlternativeV2 {
    descriptor_digest: Digest32V2,
    controls: BusinessControlsV2,
}
impl TaskAuthorizationDraftAlternativeV2 {
    pub fn new(
        descriptor_digest: Digest32V2,
        controls: BusinessControlsV2,
    ) -> Result<Self, ProtocolError> {
        nonzero(descriptor_digest.as_bytes())?;
        // Result-derived controls are now admitted: render_approval_text shows
        // each edge (source clause + path) to the owner, G4 matches under the
        // signed rule, and the only kernel reader of installed-draft controls is
        // the final-release path, whose profile never carries a derived field.
        Ok(Self {
            descriptor_digest,
            controls,
        })
    }
    pub fn descriptor_digest(&self) -> Digest32V2 {
        self.descriptor_digest
    }
    pub fn controls(&self) -> &BusinessControlsV2 {
        &self.controls
    }
    pub fn action_alternative(&self) -> Result<ActionAlternativeV2, ProtocolError> {
        self.controls
            .action_alternative(self.descriptor_digest)
            .map_err(|_| malformed())
    }
}
impl Wire for TaskAuthorizationDraftAlternativeV2 {
    fn put(&self, e: &mut Encoder) -> Result<(), ProtocolError> {
        e.array(2).map_err(ProtocolError::malformed)?;
        self.descriptor_digest.put(e)?;
        e.bytes(&encode_business_controls_v2(&self.controls).map_err(|_| malformed())?)
            .map_err(ProtocolError::malformed)?;
        // Stop aggregate encoding early, including constructor callers. The
        // output never grows with the full Cartesian product of list limits.
        if e.writer_mut().len() > MAX_TASK_AUTHORIZATION_DRAFT_BYTES_V2 {
            return Err(malformed());
        }
        Ok(())
    }
    fn get(d: &mut Decoder<'_>) -> Result<Self, ProtocolError> {
        array(d, 2)?;
        Self::new(
            Digest32V2::get(d)?,
            decode_business_controls_v2(d.bytes().map_err(ProtocolError::malformed)?)
                .map_err(|_| malformed())?,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskAuthorizationDraftClauseV2 {
    clause_id: u64,
    alternatives: BoundedList<TaskAuthorizationDraftAlternativeV2, MAX_ACTION_ALTERNATIVES_V2>,
    maximum_single_magnitude: u64,
    total_magnitude_budget: u64,
    maximum_attempts: u64,
    predecessor_clause_ids: BoundedList<u64, MAX_TASK_PREDECESSORS_V2>,
    retry_after_proven_no_effect: bool,
}
impl TaskAuthorizationDraftClauseV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        clause_id: u64,
        alternatives: Vec<TaskAuthorizationDraftAlternativeV2>,
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
        self.authorization_clause().map(|_| ())
    }
    pub fn authorization_clause(&self) -> Result<TaskAuthorizationClauseV2, ProtocolError> {
        for alt in &self.alternatives.0 {
            if let BusinessMagnitudeV2::FixedCount(n) = alt.controls.profile().magnitude_rule() {
                if n > self.maximum_single_magnitude {
                    return Err(malformed());
                }
            }
        }
        TaskAuthorizationClauseV2::new(
            self.clause_id,
            self.alternatives
                .0
                .iter()
                .map(|a| a.action_alternative())
                .collect::<Result<_, _>>()?,
            self.maximum_single_magnitude,
            self.total_magnitude_budget,
            self.maximum_attempts,
            self.predecessor_clause_ids.0.clone(),
            self.retry_after_proven_no_effect,
        )
    }
    getters!(clause_id: u64, maximum_single_magnitude: u64, total_magnitude_budget: u64, maximum_attempts: u64, retry_after_proven_no_effect: bool);
    pub fn alternatives(&self) -> &[TaskAuthorizationDraftAlternativeV2] {
        &self.alternatives.0
    }
    pub fn predecessor_clause_ids(&self) -> &[u64] {
        &self.predecessor_clause_ids.0
    }
}
struct_wire!(
    TaskAuthorizationDraftClauseV2,
    7,
    clause_id,
    alternatives,
    maximum_single_magnitude,
    total_magnitude_budget,
    maximum_attempts,
    predecessor_clause_ids,
    retry_after_proven_no_effect
);

/// Creation/amendment material only. Revocation is a separate owner operation.
/// `revision == 1` creates; subsequent revisions replace the full clause set and
/// retain existing consumption. Only the durable owner can validate that history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskAuthorizationDraftV2 {
    schema: u64,
    authorization_id: Digest32V2,
    principal: PrincipalIdV2,
    task: DurableTaskIdV2,
    revision: u64,
    installation_digest: Digest32V2,
    manifest_digest: Digest32V2,
    deployment_generation: u64,
    not_before: UnixMillisV2,
    expires_at: UnixMillisV2,
    source_input_digest: Digest32V2,
    clauses: BoundedList<TaskAuthorizationDraftClauseV2, MAX_TASK_AUTHORIZATION_CLAUSES_V2>,
}
impl TaskAuthorizationDraftV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        authorization_id: Digest32V2,
        principal: PrincipalIdV2,
        task: DurableTaskIdV2,
        revision: u64,
        installation_digest: Digest32V2,
        manifest_digest: Digest32V2,
        deployment_generation: u64,
        not_before: UnixMillisV2,
        expires_at: UnixMillisV2,
        source_input_digest: Digest32V2,
        clauses: Vec<TaskAuthorizationDraftClauseV2>,
    ) -> Result<Self, ProtocolError> {
        let value = Self {
            schema: 1,
            authorization_id,
            principal,
            task,
            revision,
            installation_digest,
            manifest_digest,
            deployment_generation,
            not_before,
            expires_at,
            source_input_digest,
            clauses: BoundedList::new(clauses)?,
        };
        value.validate()?;
        // The nested controls make the aggregate bound independent of list bounds.
        encode_task_authorization_draft_v2(&value)?;
        value.render_approval_text()?;
        Ok(value)
    }
    fn validate(&self) -> Result<(), ProtocolError> {
        if self.schema != 1
            || self.revision == 0
            || self.deployment_generation == 0
            || self.not_before.get() >= self.expires_at.get()
        {
            return Err(malformed());
        }
        nonzero(self.principal.as_bytes())?;
        nonzero(self.task.as_bytes())?;
        for digest in [
            self.authorization_id,
            self.installation_digest,
            self.manifest_digest,
            self.source_input_digest,
        ] {
            nonzero(digest.as_bytes())?;
        }
        validate_clauses(&self.authorization_clauses()?)
    }
    pub fn authorization_clauses(&self) -> Result<Vec<TaskAuthorizationClauseV2>, ProtocolError> {
        self.clauses
            .0
            .iter()
            .map(|c| c.authorization_clause())
            .collect()
    }
    getters!(authorization_id: Digest32V2, principal: PrincipalIdV2, task: DurableTaskIdV2, revision: u64, installation_digest: Digest32V2, manifest_digest: Digest32V2, deployment_generation: u64, not_before: UnixMillisV2, expires_at: UnixMillisV2, source_input_digest: Digest32V2);
    pub fn clauses(&self) -> &[TaskAuthorizationDraftClauseV2] {
        &self.clauses.0
    }
    /// This is still unsigned material, NOT an authenticated issuance API. Only
    /// the trusted owner may select evidence kind and supply verified evidence.
    pub fn to_unsigned_authorization(
        &self,
        evidence_kind: TaskEvidenceKindV2,
        user_evidence_digest: Digest32V2,
    ) -> Result<TaskAuthorizationV2, ProtocolError> {
        TaskAuthorizationV2::new(
            self.authorization_id,
            self.principal,
            self.task,
            self.revision,
            self.installation_digest,
            self.manifest_digest,
            self.not_before,
            self.expires_at,
            evidence_kind,
            user_evidence_digest,
            approval_display_digest_v2(self.render_approval_text()?.as_bytes()),
            self.authorization_clauses()?,
        )
    }
    /// Exact deterministic text projection, not HTML. UI must render as text,
    /// not interpret values as markup. No truncation or Unicode normalization:
    /// text that cannot satisfy the approval channel's NFC rule is refused.
    pub fn render_approval_text(&self) -> Result<BoundedApprovalDisplayTextV2, ProtocolError> {
        let mut clauses = Vec::new();
        // Present only when some alternative signs a result-derived edge, so an
        // exact-only root renders byte-identically to before.
        let any_derived = self.clauses.0.iter().any(|c| {
            c.alternatives
                .0
                .iter()
                .any(|a| !a.controls.derived().is_empty())
        });
        for clause in &self.clauses.0 {
            let mut alternatives = Vec::new();
            for (index, alt) in clause.alternatives.0.iter().enumerate() {
                let p = alt.controls.profile();
                let fields: serde_json::Value =
                    serde_json::from_slice(&alt.controls.canonical_values_json())
                        .map_err(ProtocolError::malformed)?;
                let rule = match p.magnitude_rule() {
                    BusinessMagnitudeV2::CountField => {
                        serde_json::json!({"kind":"CountField", "meaning":"Positive count selected later within clause limits"})
                    }
                    BusinessMagnitudeV2::FixedCount(n) => {
                        serde_json::json!({"kind":"FixedCount", "count":n})
                    }
                    BusinessMagnitudeV2::Utf8PayloadBytes => {
                        serde_json::json!({"kind":"Utf8PayloadBytes", "meaning":"Decoded payload UTF-8 bytes, not request/TLS bytes or remote storage"})
                    }
                };
                let roles: serde_json::Map<String, serde_json::Value> = p.fields().iter().map(|f| (f.name().into(), serde_json::json!({"role":format!("{:?}",f.role()), "type":format!("{:?}",f.kind())}))).collect();
                let mut alternative = serde_json::json!({
                    "alternative_index":index, "descriptor_digest":hex(alt.descriptor_digest.as_bytes()),
                    "profile_digest":hex(p.digest().as_bytes()), "codec":format!("{:?}",p.codec()), "operation":p.operation(),
                    "target_identity":hex(p.target_identity().as_bytes()), "credential_identity":hex(p.credential_identity().as_bytes()),
                    "effect":format!("{:?}",p.effect()), "fields":fields, "field_mapping":roles, "magnitude_rule":rule,
                });
                // A result-derived field carries no value here: show the owner
                // the edge (which clause's result, which path) so they approve
                // the source of the value, not a value they cannot see.
                if !alt.controls.derived().is_empty() {
                    let derived: serde_json::Map<String, serde_json::Value> = alt
                        .controls
                        .derived()
                        .iter()
                        .map(|(name, r)| {
                            let mut edge = serde_json::json!({
                                "source_clause": r.source_clause(),
                                "path": r.path(),
                                "type": format!("{:?}", r.kind()),
                                "max_bytes": r.max_bytes(),
                                "meaning": "The value the kernel extracts from the verified result of source_clause at this JSON path",
                            });
                            // A computed field also shows the owner-signed computation.
                            if let Some(c) = r.compute() {
                                edge["compute"] = serde_json::json!({"op": c.op().name(), "amount": c.amount()});
                                edge["meaning"] = serde_json::json!("The value the kernel extracts from the verified result of source_clause at this JSON path, then computes with compute");
                            }
                            (name.clone(), edge)
                        })
                        .collect();
                    alternative["derived_fields"] = serde_json::Value::Object(derived);
                }
                alternatives.push(alternative);
            }
            clauses.push(serde_json::json!({"clause_id":clause.clause_id, "alternatives":alternatives, "maximum_single_magnitude":clause.maximum_single_magnitude, "total_magnitude_budget":clause.total_magnitude_budget, "maximum_attempts":clause.maximum_attempts, "predecessor_clause_ids":clause.predecessor_clause_ids.0, "retry_after_proven_no_effect":clause.retry_after_proven_no_effect}));
        }
        let projection = serde_json::json!({
            "rendering_schema":if any_derived {2} else {1}, "operation":if self.revision == 1 {"Create task authorization"} else {"Replace task authorization; retain prior consumption"},
            "authorization_id":hex(self.authorization_id.as_bytes()), "revision":self.revision, "expected_previous_revision":self.revision-1,
            "principal":hex(self.principal.as_bytes()), "task":hex(self.task.as_bytes()), "installation_digest":hex(self.installation_digest.as_bytes()),
            "manifest_digest":hex(self.manifest_digest.as_bytes()), "deployment_generation":self.deployment_generation,
            "not_before_unix_ms":self.not_before.get(), "expires_at_unix_ms":self.expires_at.get(), "source_input_digest":hex(self.source_input_digest.as_bytes()),
            "scope":"Choose only complete alternatives within a clause; never cross-pair fields. Payload is chosen later and remains subject to data gates. All listed predecessors require verified success. Attempts remain consumed even after proven no effect; only the permitted magnitude charge may be refunded. Unknown outcomes remain charged.",
            "clauses":clauses,
        });
        BoundedApprovalDisplayTextV2::new(
            serde_json::to_string(&projection).map_err(ProtocolError::malformed)?,
        )
    }
}
struct_wire!(
    TaskAuthorizationDraftV2,
    12,
    schema,
    authorization_id,
    principal,
    task,
    revision,
    installation_digest,
    manifest_digest,
    deployment_generation,
    not_before,
    expires_at,
    source_input_digest,
    clauses
);
fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(DIGITS[(b >> 4) as usize] as char);
        s.push(DIGITS[(b & 15) as usize] as char);
    }
    s
}
pub fn encode_task_authorization_draft_v2(
    value: &TaskAuthorizationDraftV2,
) -> Result<Vec<u8>, ProtocolError> {
    encode(value, MAX_TASK_AUTHORIZATION_DRAFT_BYTES_V2)
}
pub fn decode_task_authorization_draft_v2(
    bytes: &[u8],
) -> Result<TaskAuthorizationDraftV2, ProtocolError> {
    let value: TaskAuthorizationDraftV2 = decode(bytes, MAX_TASK_AUTHORIZATION_DRAFT_BYTES_V2)?;
    value.render_approval_text()?;
    Ok(value)
}
pub fn task_authorization_draft_digest_v2(
    value: &TaskAuthorizationDraftV2,
) -> Result<Digest32V2, ProtocolError> {
    Ok(hash(
        DRAFT_DOMAIN,
        &encode_task_authorization_draft_v2(value)?,
    ))
}
