//! Pending task material lives in the existing encrypted, rollback-protected
//! owner. A pending record is NOT a grant and cannot authorize any dispatch.
use super::{G4Error, VerifiedTaskAuthorizationV2};
use savana_kernel_protocol::v2::{
    decode_signed_approval_envelope_v2, decode_task_authorization_draft_v2,
    encode_signed_approval_envelope_v2, encode_task_authorization_draft_v2,
    task_authorization_draft_digest_v2, ApprovalBindingV2, ApprovalPurposeV2, Digest32V2,
    SignedApprovalEnvelopeV2, TaskAuthorizationChangeV2, TaskAuthorizationDraftV2,
    TaskEvidenceKindV2,
};
use savana_kernel_protocol::v2::{
    decode_signed_ui_authentication_envelope_v2, encode_signed_ui_authentication_envelope_v2,
    FixedOriginV2, SignedUiAuthenticationEnvelopeV2, UiAuthenticationBindingV2,
    UiAuthenticationPurposeV2,
};

const MAX_PENDING: usize = 4096;
const MAX_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone, PartialEq, Eq)]
pub struct PendingTaskAuthorizationV2 {
    draft: TaskAuthorizationDraftV2,
    request_digest: Digest32V2,
    previous_authorization: Option<Digest32V2>,
    envelope: Option<SignedApprovalEnvelopeV2>,
    display_authentication: Option<SignedUiAuthenticationEnvelopeV2>,
    installed: Option<Digest32V2>,
}
impl std::fmt::Debug for PendingTaskAuthorizationV2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PendingTaskAuthorizationV2(<redacted>)")
    }
}
impl PendingTaskAuthorizationV2 {
    pub fn draft(&self) -> &TaskAuthorizationDraftV2 {
        &self.draft
    }
    pub fn request_digest(&self) -> Digest32V2 {
        self.request_digest
    }
    pub fn previous_authorization(&self) -> Option<Digest32V2> {
        self.previous_authorization
    }
    pub fn envelope(&self) -> Option<&SignedApprovalEnvelopeV2> {
        self.envelope.as_ref()
    }
    pub fn display_authentication(&self) -> Option<&SignedUiAuthenticationEnvelopeV2> {
        self.display_authentication.as_ref()
    }
    pub fn installed_digest(&self) -> Option<Digest32V2> {
        self.installed
    }
    pub fn draft_digest(&self) -> Result<Digest32V2, G4Error> {
        task_authorization_draft_digest_v2(&self.draft).map_err(corrupt)
    }
    fn validate(&self) -> Result<(), G4Error> {
        if zero(self.request_digest)
            || self.previous_authorization.is_some_and(zero)
            || self.installed.is_some_and(zero)
            || (self.draft.revision() == 1) != self.previous_authorization.is_none()
            || self.envelope.is_some() != self.display_authentication.is_some()
        {
            return Err(G4Error::StateConflict);
        }
        if let Some(envelope) = &self.envelope {
            // Structural check only. The native issuer separately verifies its
            // configured envelope key and the approval service's settlement key.
            let e = envelope.unverified_material().map_err(corrupt)?;
            let ui = self
                .display_authentication
                .as_ref()
                .ok_or(G4Error::StateConflict)?
                .unverified_material()
                .map_err(corrupt)?;
            if ui.installation_id() != self.draft.installation_digest()
                || ui.active_state_manifest_digest() != self.draft.manifest_digest()
                || ui.deployment_generation() != self.draft.deployment_generation()
                || ui.purpose() != UiAuthenticationPurposeV2::ApprovalDisplay
                || ui.expected_principal() != Some(self.draft.principal())
                || ui.binding()
                    != (UiAuthenticationBindingV2::ApprovalDisplay {
                        durable_task_id: self.draft.task(),
                        approval_envelope_digest: envelope.envelope_digest().map_err(corrupt)?,
                        approval_purpose: ApprovalPurposeV2::TaskAuthorization,
                        display_digest: e.display_digest(),
                    })
                || ui.authentication_origin() != FixedOriginV2::Approval8766
                || ui.return_origin() != FixedOriginV2::Approval8766
                || ui.issued_at() != e.issued_at()
                || ui.expires_at() != e.expires_at()
            {
                return Err(G4Error::StateConflict);
            }
            let change = if self.draft.revision() == 1 {
                TaskAuthorizationChangeV2::Create
            } else {
                TaskAuthorizationChangeV2::Amend
            };
            if e.purpose() != ApprovalPurposeV2::TaskAuthorization
                || e.binding()
                    != (ApprovalBindingV2::TaskAuthorization {
                        authorization_id: self.draft.authorization_id(),
                        task: self.draft.task(),
                        revision: self.draft.revision(),
                        change,
                        draft_digest: self.draft_digest()?,
                    })
                || e.installation_id() != self.draft.installation_digest()
                || e.active_state_manifest_digest() != self.draft.manifest_digest()
                || e.deployment_generation() != self.draft.deployment_generation()
                || e.expected_principal() != self.draft.principal()
                || e.display_text() != &self.draft.render_approval_text().map_err(corrupt)?
                || e.issued_at().get() < self.draft.not_before().get()
                || e.expires_at().get() > self.draft.expires_at().get()
            {
                return Err(G4Error::StateConflict);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct TaskIssuanceLedgerV2 {
    records: Vec<PendingTaskAuthorizationV2>,
}
impl TaskIssuanceLedgerV2 {
    pub(crate) fn installed_draft(&self, digest: Digest32V2) -> Option<&TaskAuthorizationDraftV2> {
        self.records
            .iter()
            .find(|r| r.installed == Some(digest))
            .map(|r| &r.draft)
    }
    pub(crate) fn find(&self, request: Digest32V2) -> Option<&PendingTaskAuthorizationV2> {
        self.records.iter().find(|r| r.request_digest == request)
    }
    pub(crate) fn record(
        &mut self,
        draft: TaskAuthorizationDraftV2,
        request_digest: Digest32V2,
        previous_authorization: Option<Digest32V2>,
    ) -> Result<bool, G4Error> {
        if let Some(r) = self.find(request_digest) {
            return if r.draft == draft {
                Ok(false)
            } else {
                Err(G4Error::StateConflict)
            };
        }
        if self.records.len() >= MAX_PENDING {
            return Err(G4Error::StateConflict);
        }
        // Even uninstalled proposals cannot reassign an authorization identity
        // to another task or principal, nor create a fresh identity on retry.
        if self.records.iter().any(|r| {
            (r.draft.task() == draft.task()
                && (r.draft.authorization_id() != draft.authorization_id()
                    || r.draft.principal() != draft.principal()))
                || (r.draft.authorization_id() == draft.authorization_id()
                    && r.draft.task() != draft.task())
        }) {
            return Err(G4Error::StateConflict);
        }
        let r = PendingTaskAuthorizationV2 {
            draft,
            request_digest,
            previous_authorization,
            envelope: None,
            display_authentication: None,
            installed: None,
        };
        r.validate()?;
        self.records.push(r);
        self.encode()?; // Bound aggregate readable data, not just list lengths.
        Ok(true)
    }
    pub(crate) fn attach_envelope(
        &mut self,
        request: Digest32V2,
        envelope: SignedApprovalEnvelopeV2,
        display_authentication: SignedUiAuthenticationEnvelopeV2,
    ) -> Result<bool, G4Error> {
        let r = self
            .records
            .iter_mut()
            .find(|r| r.request_digest == request)
            .ok_or(G4Error::StateConflict)?;
        if let Some(old) = &r.envelope {
            return if old == &envelope
                && r.display_authentication.as_ref() == Some(&display_authentication)
            {
                Ok(false)
            } else {
                Err(G4Error::StateConflict)
            };
        }
        if r.installed.is_some() {
            return Err(G4Error::StateConflict);
        }
        r.envelope = Some(envelope);
        r.display_authentication = Some(display_authentication);
        r.validate()?;
        self.encode()?;
        Ok(true)
    }
    pub(crate) fn finish(
        &mut self,
        request: Digest32V2,
        authorization: &VerifiedTaskAuthorizationV2,
        current: Option<Digest32V2>,
    ) -> Result<bool, G4Error> {
        let r = self
            .records
            .iter_mut()
            .find(|r| r.request_digest == request)
            .ok_or(G4Error::StateConflict)?;
        if let Some(installed) = r.installed {
            return if installed == authorization.digest() {
                Ok(false)
            } else {
                Err(G4Error::StateConflict)
            };
        }
        let m = authorization.material();
        if r.previous_authorization != current
            || (m.evidence_kind() == TaskEvidenceKindV2::ApprovedDraft && r.envelope.is_none())
            || r.draft
                .to_unsigned_authorization(m.evidence_kind(), m.user_evidence_digest())
                .map_err(corrupt)?
                != *m
        {
            return Err(G4Error::StateConflict);
        }
        r.installed = Some(authorization.digest());
        Ok(true)
    }
    pub(crate) fn validate(&self) -> Result<(), G4Error> {
        if self.records.len() > MAX_PENDING {
            return Err(G4Error::DurableStateCorrupt);
        }
        for (i, r) in self.records.iter().enumerate() {
            r.validate().map_err(corrupt)?;
            if self.records[..i].iter().any(|p| {
                p.request_digest == r.request_digest
                    || (p.draft.task() == r.draft.task()
                        && (p.draft.authorization_id() != r.draft.authorization_id()
                            || p.draft.principal() != r.draft.principal()))
                    || (p.draft.authorization_id() == r.draft.authorization_id()
                        && p.draft.task() != r.draft.task())
            }) {
                return Err(G4Error::DurableStateCorrupt);
            }
        }
        self.encode()?;
        Ok(())
    }
    pub(crate) fn validate_authority_references(
        &self,
        tasks: &super::task_state::TaskLedgerV2,
    ) -> Result<(), G4Error> {
        for r in &self.records {
            if let Some(current) = tasks.current(r.draft.task())? {
                let m = current.authorization().material();
                if m.authorization_id() != r.draft.authorization_id()
                    || m.principal() != r.draft.principal()
                    || m.installation_digest() != r.draft.installation_digest()
                {
                    return Err(G4Error::DurableStateCorrupt);
                }
            }
            if let Some(previous) = r.previous_authorization {
                let p = tasks
                    .historical(previous)
                    .ok_or(G4Error::DurableStateCorrupt)?
                    .material();
                if p.task() != r.draft.task()
                    || p.authorization_id() != r.draft.authorization_id()
                    || p.principal() != r.draft.principal()
                    || p.revision().checked_add(1) != Some(r.draft.revision())
                {
                    return Err(G4Error::DurableStateCorrupt);
                }
            }
            if let Some(installed) = r.installed {
                let m = tasks
                    .historical(installed)
                    .ok_or(G4Error::DurableStateCorrupt)?
                    .material();
                if r.draft
                    .to_unsigned_authorization(m.evidence_kind(), m.user_evidence_digest())
                    .map_err(corrupt)?
                    != *m
                    || (m.evidence_kind() == TaskEvidenceKindV2::ApprovedDraft
                        && r.envelope.is_none())
                {
                    return Err(G4Error::DurableStateCorrupt);
                }
            }
        }
        Ok(())
    }
    pub(crate) fn encode(&self) -> Result<Vec<u8>, G4Error> {
        let mut e = minicbor::Encoder::new(Vec::new());
        e.array(2)
            .and_then(|e| e.u8(1))
            .and_then(|e| e.array(self.records.len() as u64))
            .map_err(corrupt)?;
        for r in &self.records {
            let draft_bytes = encode_task_authorization_draft_v2(&r.draft).map_err(corrupt)?;
            e.array(6)
                .and_then(|e| e.bytes(&draft_bytes))
                .map_err(corrupt)?;
            e.bytes(r.request_digest.as_bytes()).map_err(corrupt)?;
            put_digest(&mut e, r.previous_authorization)?;
            e.array(u64::from(r.envelope.is_some())).map_err(corrupt)?;
            if let Some(envelope) = &r.envelope {
                e.bytes(&encode_signed_approval_envelope_v2(envelope).map_err(corrupt)?)
                    .map_err(corrupt)?;
            }
            e.array(u64::from(r.display_authentication.is_some()))
                .map_err(corrupt)?;
            if let Some(ui) = &r.display_authentication {
                e.bytes(&encode_signed_ui_authentication_envelope_v2(ui).map_err(corrupt)?)
                    .map_err(corrupt)?;
            }
            put_digest(&mut e, r.installed)?;
            if e.writer().len() > MAX_BYTES {
                return Err(G4Error::StateConflict);
            }
        }
        Ok(e.into_writer())
    }
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, G4Error> {
        if bytes.len() > MAX_BYTES {
            return Err(G4Error::DurableStateCorrupt);
        }
        let mut d = minicbor::Decoder::new(bytes);
        exact(&mut d, 2)?;
        if d.u8().map_err(corrupt)? != 1 {
            return Err(G4Error::DurableStateCorrupt);
        }
        let n = d
            .array()
            .map_err(corrupt)?
            .filter(|n| *n <= MAX_PENDING as u64)
            .ok_or(G4Error::DurableStateCorrupt)?;
        let mut records = Vec::new();
        for _ in 0..n {
            exact(&mut d, 6)?;
            let draft =
                decode_task_authorization_draft_v2(d.bytes().map_err(corrupt)?).map_err(corrupt)?;
            let request_digest = get_digest(&mut d)?;
            let previous_authorization = optional_digest(&mut d)?;
            let envelope = match d.array().map_err(corrupt)? {
                Some(0) => None,
                Some(1) => Some(
                    decode_signed_approval_envelope_v2(d.bytes().map_err(corrupt)?)
                        .map_err(corrupt)?,
                ),
                _ => return Err(G4Error::DurableStateCorrupt),
            };
            let display_authentication = match d.array().map_err(corrupt)? {
                Some(0) => None,
                Some(1) => Some(
                    decode_signed_ui_authentication_envelope_v2(d.bytes().map_err(corrupt)?)
                        .map_err(corrupt)?,
                ),
                _ => return Err(G4Error::DurableStateCorrupt),
            };
            let installed = optional_digest(&mut d)?;
            records.push(PendingTaskAuthorizationV2 {
                draft,
                request_digest,
                previous_authorization,
                envelope,
                display_authentication,
                installed,
            });
        }
        let value = Self { records };
        value.validate()?;
        if d.position() != bytes.len() || value.encode()? != bytes {
            return Err(G4Error::DurableStateCorrupt);
        }
        Ok(value)
    }
}
fn corrupt<T>(_: T) -> G4Error {
    G4Error::DurableStateCorrupt
}
fn zero(d: Digest32V2) -> bool {
    d.as_bytes().iter().all(|b| *b == 0)
}
fn exact(d: &mut minicbor::Decoder<'_>, n: u64) -> Result<(), G4Error> {
    if d.array().map_err(corrupt)? == Some(n) {
        Ok(())
    } else {
        Err(G4Error::DurableStateCorrupt)
    }
}
fn get_digest(d: &mut minicbor::Decoder<'_>) -> Result<Digest32V2, G4Error> {
    Ok(Digest32V2::new(
        d.bytes().map_err(corrupt)?.try_into().map_err(corrupt)?,
    ))
}
fn optional_digest(d: &mut minicbor::Decoder<'_>) -> Result<Option<Digest32V2>, G4Error> {
    match d.array().map_err(corrupt)? {
        Some(0) => Ok(None),
        Some(1) => Ok(Some(get_digest(d)?)),
        _ => Err(G4Error::DurableStateCorrupt),
    }
}
fn put_digest(
    e: &mut minicbor::Encoder<Vec<u8>>,
    value: Option<Digest32V2>,
) -> Result<(), G4Error> {
    e.array(u64::from(value.is_some())).map_err(corrupt)?;
    if let Some(d) = value {
        e.bytes(d.as_bytes()).map_err(corrupt)?;
    }
    Ok(())
}
