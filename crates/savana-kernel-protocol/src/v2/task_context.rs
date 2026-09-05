//! Authenticated task metadata, not an authorization or a signing capability.
use super::super::{decode_business_profile_v2, encode_business_profile_v2, BusinessProfileV2};
use super::*;

#[derive(Clone, PartialEq, Eq)]
pub struct TaskAuthorizationToolContextV2 {
    descriptor_digest: Digest32V2,
    name: String,
    profile: BusinessProfileV2,
}
impl core::fmt::Debug for TaskAuthorizationToolContextV2 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("TaskAuthorizationToolContextV2(<redacted>)")
    }
}
impl TaskAuthorizationToolContextV2 {
    pub fn new(
        descriptor_digest: Digest32V2,
        name: String,
        profile: BusinessProfileV2,
    ) -> Result<Self, ProtocolError> {
        nonzero(descriptor_digest.as_bytes())?;
        if name.is_empty()
            || name.len() > 128
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        {
            return Err(malformed());
        }
        Ok(Self {
            descriptor_digest,
            name,
            profile,
        })
    }
    pub fn descriptor_digest(&self) -> Digest32V2 {
        self.descriptor_digest
    }
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn profile(&self) -> &BusinessProfileV2 {
        &self.profile
    }
}
impl Wire for TaskAuthorizationToolContextV2 {
    fn put(&self, e: &mut Encoder) -> Result<(), ProtocolError> {
        e.array(3).map_err(ProtocolError::malformed)?;
        self.descriptor_digest.put(e)?;
        e.str(self.name()).map_err(ProtocolError::malformed)?;
        e.bytes(&encode_business_profile_v2(&self.profile).map_err(|_| malformed())?)
            .map_err(ProtocolError::malformed)?;
        Ok(())
    }
    fn get(d: &mut Decoder<'_>) -> Result<Self, ProtocolError> {
        array(d, 3)?;
        let digest = Digest32V2::get(d)?;
        let name = d.str().map_err(ProtocolError::malformed)?;
        // Bound before allocating the caller-controlled string.
        if name.len() > 128 {
            return Err(malformed());
        }
        Self::new(
            digest,
            name.into(),
            decode_business_profile_v2(d.bytes().map_err(ProtocolError::malformed)?)
                .map_err(|_| malformed())?,
        )
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct TaskAuthorizationContextV2 {
    principal: PrincipalIdV2,
    task: DurableTaskIdV2,
    installation: Digest32V2,
    manifest: Digest32V2,
    generation: u64,
    source: Digest32V2,
    not_before: UnixMillisV2,
    expires_at: UnixMillisV2,
    identity: Option<(Digest32V2, u64)>,
    tools: BoundedList<TaskAuthorizationToolContextV2, 64>,
    pending: BoundedList<Digest32V2, 64>,
}
impl core::fmt::Debug for TaskAuthorizationContextV2 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("TaskAuthorizationContextV2(<redacted>)")
    }
}
impl TaskAuthorizationContextV2 {
    /// Closed JSON convenience grammar for SDKs: clauses contain exact named
    /// alternatives and flat [name,value] control pairs, never wildcard lists.
    /// Identity/source/profile fields cannot be supplied through this grammar.
    pub fn draft_from_json(
        &self,
        authorization_id: Digest32V2,
        bytes: &[u8],
    ) -> Result<TaskAuthorizationDraftV2, ProtocolError> {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Clause {
            clause_id: u64,
            alternatives: Vec<Alternative>,
            maximum_single_magnitude: u64,
            total_magnitude_budget: u64,
            maximum_attempts: u64,
            predecessor_clause_ids: Vec<u64>,
            retry_after_proven_no_effect: bool,
        }
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Alternative {
            descriptor_digest: String,
            controls: Vec<(String, Value)>,
        }
        #[derive(serde::Deserialize)]
        #[serde(untagged)]
        enum Value {
            Text(String),
            Unsigned(u64),
            Boolean(bool),
        }
        if bytes.len() > 1024 * 1024 {
            return Err(malformed());
        }
        let clauses: Vec<Clause> = serde_json::from_slice(bytes).map_err(|_| malformed())?;
        if clauses.len() > MAX_TASK_AUTHORIZATION_CLAUSES_V2 {
            return Err(malformed());
        }
        let clauses = clauses
            .into_iter()
            .map(|clause| {
                if clause.alternatives.len() > MAX_ACTION_ALTERNATIVES_V2 {
                    return Err(malformed());
                }
                let alternatives = clause
                    .alternatives
                    .into_iter()
                    .map(|a| {
                        let tool = self
                            .tools()
                            .iter()
                            .find(|t| hex(t.descriptor_digest.as_bytes()) == a.descriptor_digest)
                            .ok_or_else(malformed)?;
                        let fields = a
                            .controls
                            .into_iter()
                            .map(|(k, v)| {
                                (
                                    k,
                                    match v {
                                        Value::Text(s) => super::super::BusinessValueV2::Text(s),
                                        Value::Unsigned(n) => {
                                            super::super::BusinessValueV2::Unsigned(n)
                                        }
                                        Value::Boolean(b) => {
                                            super::super::BusinessValueV2::Boolean(b)
                                        }
                                    },
                                )
                            })
                            .collect();
                        let controls =
                            super::super::BusinessControlsV2::from_fields(tool.profile(), fields)
                                .map_err(|_| malformed())?;
                        TaskAuthorizationDraftAlternativeV2::new(tool.descriptor_digest(), controls)
                    })
                    .collect::<Result<_, ProtocolError>>()?;
                TaskAuthorizationDraftClauseV2::new(
                    clause.clause_id,
                    alternatives,
                    clause.maximum_single_magnitude,
                    clause.total_magnitude_budget,
                    clause.maximum_attempts,
                    clause.predecessor_clause_ids,
                    clause.retry_after_proven_no_effect,
                )
            })
            .collect::<Result<_, ProtocolError>>()?;
        self.draft(authorization_id, clauses)
    }
    /// Nonsecret tool metadata only. No original input, previous contract control
    /// values, signing material or executable tickets are exposed here.
    pub fn tools_json(&self) -> Result<String, ProtocolError> {
        let tools: Vec<_> = self.tools().iter().map(|t| {
            let p = t.profile();
            let fields: Vec<_> = p.fields().iter().filter(|f| matches!(f.role(), super::super::BusinessFieldRoleV2::Resource | super::super::BusinessFieldRoleV2::Destination | super::super::BusinessFieldRoleV2::Parameter)).map(|f| serde_json::json!({"name": f.name(), "role": f.role() as u8, "type": f.kind() as u8})).collect();
            serde_json::json!({"descriptor_digest": hex(t.descriptor_digest.as_bytes()), "name": t.name(), "effect": p.effect() as u8, "operation": p.operation(), "fields": fields})
        }).collect();
        serde_json::to_string(&tools).map_err(|_| malformed())
    }
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        principal: PrincipalIdV2,
        task: DurableTaskIdV2,
        installation: Digest32V2,
        manifest: Digest32V2,
        generation: u64,
        source: Digest32V2,
        not_before: UnixMillisV2,
        expires_at: UnixMillisV2,
        identity: Option<(Digest32V2, u64)>,
        tools: Vec<TaskAuthorizationToolContextV2>,
        pending: Vec<Digest32V2>,
    ) -> Result<Self, ProtocolError> {
        for bytes in [
            principal.as_bytes(),
            task.as_bytes(),
            installation.as_bytes(),
            manifest.as_bytes(),
            source.as_bytes(),
        ] {
            nonzero(bytes)?;
        }
        if generation == 0 || not_before.get() == 0 || not_before.get() >= expires_at.get() {
            return Err(malformed());
        }
        if let Some((id, revision)) = identity {
            nonzero(id.as_bytes())?;
            if revision == 0 {
                return Err(malformed());
            }
        }
        for (i, tool) in tools.iter().enumerate() {
            if tools[..i]
                .iter()
                .any(|t| t.descriptor_digest == tool.descriptor_digest)
            {
                return Err(malformed());
            }
        }
        for (i, id) in pending.iter().enumerate() {
            nonzero(id.as_bytes())?;
            if pending[..i].contains(id) {
                return Err(malformed());
            }
        }
        Ok(Self {
            principal,
            task,
            installation,
            manifest,
            generation,
            source,
            not_before,
            expires_at,
            identity,
            tools: BoundedList::new(tools)?,
            pending: BoundedList::new(pending)?,
        })
    }
    pub fn principal(&self) -> PrincipalIdV2 {
        self.principal
    }
    pub fn task(&self) -> DurableTaskIdV2 {
        self.task
    }
    pub fn source_input_digest(&self) -> Digest32V2 {
        self.source
    }
    pub fn authorization_identity(&self) -> Option<(Digest32V2, u64)> {
        self.identity
    }
    pub fn tools(&self) -> &[TaskAuthorizationToolContextV2] {
        &self.tools.0
    }
    pub fn pending_requests(&self) -> &[Digest32V2] {
        &self.pending.0
    }
    /// Builds unprivileged proposal material. The issuer still rechecks the
    /// authenticated input session, active descriptors and durable revision.
    pub fn draft(
        &self,
        authorization_id: Digest32V2,
        clauses: Vec<TaskAuthorizationDraftClauseV2>,
    ) -> Result<TaskAuthorizationDraftV2, ProtocolError> {
        let revision = match self.identity {
            Some((id, revision)) if id == authorization_id => revision,
            None => 1,
            _ => return Err(malformed()),
        };
        for clause in &clauses {
            for alternative in clause.alternatives() {
                if !self.tools.0.iter().any(|tool| {
                    tool.descriptor_digest == alternative.descriptor_digest()
                        && tool.profile() == alternative.controls().profile()
                }) {
                    return Err(malformed());
                }
            }
        }
        TaskAuthorizationDraftV2::new(
            authorization_id,
            self.principal,
            self.task,
            revision,
            self.installation,
            self.manifest,
            self.generation,
            self.not_before,
            self.expires_at,
            self.source,
            clauses,
        )
    }
}
impl Wire for TaskAuthorizationContextV2 {
    fn put(&self, e: &mut Encoder) -> Result<(), ProtocolError> {
        e.array(12).map_err(ProtocolError::malformed)?;
        1u64.put(e)?;
        self.principal.put(e)?;
        self.task.put(e)?;
        self.installation.put(e)?;
        self.manifest.put(e)?;
        self.generation.put(e)?;
        self.source.put(e)?;
        self.not_before.put(e)?;
        self.expires_at.put(e)?;
        if let Some((id, revision)) = self.identity {
            e.array(2).map_err(ProtocolError::malformed)?;
            id.put(e)?;
            revision.put(e)?;
        } else {
            e.null().map_err(ProtocolError::malformed)?;
        }
        self.tools.put(e)?;
        self.pending.put(e)
    }
    fn get(d: &mut Decoder<'_>) -> Result<Self, ProtocolError> {
        array(d, 12)?;
        if u64::get(d)? != 1 {
            return Err(malformed());
        }
        let principal = PrincipalIdV2::get(d)?;
        let task = DurableTaskIdV2::get(d)?;
        let installation = Digest32V2::get(d)?;
        let manifest = Digest32V2::get(d)?;
        let generation = u64::get(d)?;
        let source = Digest32V2::get(d)?;
        let not_before = <UnixMillisV2 as Wire>::get(d)?;
        let expires_at = <UnixMillisV2 as Wire>::get(d)?;
        let identity =
            if d.datatype().map_err(ProtocolError::malformed)? == minicbor::data::Type::Null {
                d.null().map_err(ProtocolError::malformed)?;
                None
            } else {
                array(d, 2)?;
                Some((Digest32V2::get(d)?, u64::get(d)?))
            };
        Self::new(
            principal,
            task,
            installation,
            manifest,
            generation,
            source,
            not_before,
            expires_at,
            identity,
            BoundedList::<TaskAuthorizationToolContextV2, 64>::get(d)?.0,
            BoundedList::<Digest32V2, 64>::get(d)?.0,
        )
    }
}
pub fn encode_task_authorization_context_v2(
    value: &TaskAuthorizationContextV2,
) -> Result<Vec<u8>, ProtocolError> {
    encode(value, 1024 * 1024)
}
pub fn decode_task_authorization_context_v2(
    bytes: &[u8],
) -> Result<TaskAuthorizationContextV2, ProtocolError> {
    decode(bytes, 1024 * 1024)
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
