//! Content-bound approval material. Signing is an approval-service primitive, not
//! a user-authentication ceremony. Verified values are not dispatch capabilities;
//! the durable owner must atomically consume their settlement nonce exactly once.
use super::{Digest32V2, DurableTaskIdV2, Ed25519SignatureV2, PrincipalIdV2, UnixMillisV2};
use crate::{ProtocolError, StableCode};
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use sha2::{Digest as _, Sha256};

pub const MAX_TASK_ACTION_APPROVAL_BYTES_V2: usize = 1024;
const SIGN_DOMAIN: &[u8] = b"SAVANA_TASK_ACTION_APPROVAL_SIGNATURE_V2_SCHEMA1\0";
const DIGEST_DOMAIN: &[u8] = b"SAVANA_TASK_ACTION_APPROVAL_DIGEST_V2_SCHEMA1\0";
fn invalid() -> ProtocolError {
    ProtocolError::stable(StableCode::ProtocolMalformedCbor)
}
fn nonzero(b: &[u8]) -> Result<(), ProtocolError> {
    if b.iter().all(|v| *v == 0) {
        Err(invalid())
    } else {
        Ok(())
    }
}

/// Expected values must come from trusted current state and the actual ceremony.
/// This is context material, never evidence by itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskActionApprovalContextV2 {
    pub content_digest: Digest32V2,
    pub authorization_id: Digest32V2,
    pub authorization_revision: u64,
    pub principal: PrincipalIdV2,
    pub task: DurableTaskIdV2,
    pub installation_digest: Digest32V2,
    pub manifest_digest: Digest32V2,
    pub deployment_generation: u64,
    pub challenge_nonce: Digest32V2,
    pub settlement_nonce: Digest32V2,
    pub authentication_context_digest: Digest32V2,
    pub display_digest: Digest32V2,
}
impl TaskActionApprovalContextV2 {
    fn validate(&self) -> Result<(), ProtocolError> {
        if self.authorization_revision == 0 || self.deployment_generation == 0 {
            return Err(invalid());
        }
        for b in [
            self.content_digest.as_bytes(),
            self.authorization_id.as_bytes(),
            self.principal.as_bytes(),
            self.task.as_bytes(),
            self.installation_digest.as_bytes(),
            self.manifest_digest.as_bytes(),
            self.challenge_nonce.as_bytes(),
            self.settlement_nonce.as_bytes(),
            self.authentication_context_digest.as_bytes(),
            self.display_digest.as_bytes(),
        ] {
            nonzero(b)?;
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskActionApprovalDecisionV2 {
    Approve,
    Deny,
}
impl TaskActionApprovalDecisionV2 {
    fn tag(self) -> u8 {
        match self {
            Self::Approve => 1,
            Self::Deny => 2,
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskActionApprovalV2 {
    context: TaskActionApprovalContextV2,
    decision: TaskActionApprovalDecisionV2,
    issued_at: UnixMillisV2,
    expires_at: UnixMillisV2,
}
impl TaskActionApprovalV2 {
    pub fn new(
        context: TaskActionApprovalContextV2,
        decision: TaskActionApprovalDecisionV2,
        issued_at: UnixMillisV2,
        expires_at: UnixMillisV2,
    ) -> Result<Self, ProtocolError> {
        context.validate()?;
        if issued_at.get() >= expires_at.get() {
            return Err(invalid());
        }
        Ok(Self {
            context,
            decision,
            issued_at,
            expires_at,
        })
    }
    pub fn context(&self) -> &TaskActionApprovalContextV2 {
        &self.context
    }
    pub fn decision(&self) -> TaskActionApprovalDecisionV2 {
        self.decision
    }
    pub fn issued_at(&self) -> UnixMillisV2 {
        self.issued_at
    }
    pub fn expires_at(&self) -> UnixMillisV2 {
        self.expires_at
    }
    fn check(
        &self,
        c: &TaskActionApprovalContextV2,
        now: UnixMillisV2,
    ) -> Result<(), ProtocolError> {
        if &self.context != c
            || self.decision != TaskActionApprovalDecisionV2::Approve
            || now.get() < self.issued_at.get()
            || now.get() >= self.expires_at.get()
        {
            Err(invalid())
        } else {
            Ok(())
        }
    }
}
pub fn encode_task_action_approval_v2(m: &TaskActionApprovalV2) -> Result<Vec<u8>, ProtocolError> {
    let c = &m.context;
    let mut e = minicbor::Encoder::new(Vec::new());
    e.array(16)
        .and_then(|e| e.u8(1))
        .and_then(|e| e.bytes(c.content_digest.as_bytes()))
        .and_then(|e| e.bytes(c.authorization_id.as_bytes()))
        .and_then(|e| e.u64(c.authorization_revision))
        .and_then(|e| e.bytes(c.principal.as_bytes()))
        .and_then(|e| e.bytes(c.task.as_bytes()))
        .and_then(|e| e.bytes(c.installation_digest.as_bytes()))
        .and_then(|e| e.bytes(c.manifest_digest.as_bytes()))
        .and_then(|e| e.u64(c.deployment_generation))
        .and_then(|e| e.u8(m.decision.tag()))
        .and_then(|e| e.bytes(c.challenge_nonce.as_bytes()))
        .and_then(|e| e.bytes(c.settlement_nonce.as_bytes()))
        .and_then(|e| e.bytes(c.authentication_context_digest.as_bytes()))
        .and_then(|e| e.bytes(c.display_digest.as_bytes()))
        .and_then(|e| e.u64(m.issued_at.get()))
        .and_then(|e| e.u64(m.expires_at.get()))
        .map_err(ProtocolError::malformed)?;
    Ok(e.into_writer())
}
fn fixed<const N: usize>(d: &mut minicbor::Decoder<'_>) -> Result<[u8; N], ProtocolError> {
    d.bytes()
        .map_err(ProtocolError::malformed)?
        .try_into()
        .map_err(|_| invalid())
}
pub fn decode_task_action_approval_v2(bytes: &[u8]) -> Result<TaskActionApprovalV2, ProtocolError> {
    if bytes.is_empty() || bytes.len() > MAX_TASK_ACTION_APPROVAL_BYTES_V2 {
        return Err(invalid());
    }
    let mut d = minicbor::Decoder::new(bytes);
    if d.array().map_err(ProtocolError::malformed)? != Some(16)
        || d.u64().map_err(ProtocolError::malformed)? != 1
    {
        return Err(invalid());
    }
    let content_digest = Digest32V2::new(fixed(&mut d)?);
    let authorization_id = Digest32V2::new(fixed(&mut d)?);
    let authorization_revision = d.u64().map_err(ProtocolError::malformed)?;
    let principal = PrincipalIdV2::new(fixed(&mut d)?);
    let task = DurableTaskIdV2::new(fixed(&mut d)?);
    let installation_digest = Digest32V2::new(fixed(&mut d)?);
    let manifest_digest = Digest32V2::new(fixed(&mut d)?);
    let deployment_generation = d.u64().map_err(ProtocolError::malformed)?;
    let decision = match d.u8().map_err(ProtocolError::malformed)? {
        1 => TaskActionApprovalDecisionV2::Approve,
        2 => TaskActionApprovalDecisionV2::Deny,
        _ => return Err(invalid()),
    };
    let challenge_nonce = Digest32V2::new(fixed(&mut d)?);
    let settlement_nonce = Digest32V2::new(fixed(&mut d)?);
    let authentication_context_digest = Digest32V2::new(fixed(&mut d)?);
    let display_digest = Digest32V2::new(fixed(&mut d)?);
    let issued_at = UnixMillisV2::new(d.u64().map_err(ProtocolError::malformed)?);
    let expires_at = UnixMillisV2::new(d.u64().map_err(ProtocolError::malformed)?);
    let m = TaskActionApprovalV2::new(
        TaskActionApprovalContextV2 {
            content_digest,
            authorization_id,
            authorization_revision,
            principal,
            task,
            installation_digest,
            manifest_digest,
            deployment_generation,
            challenge_nonce,
            settlement_nonce,
            authentication_context_digest,
            display_digest,
        },
        decision,
        issued_at,
        expires_at,
    )?;
    if d.position() != bytes.len() {
        return Err(invalid());
    }
    if encode_task_action_approval_v2(&m)? != bytes {
        return Err(ProtocolError::stable(StableCode::ProtocolNonCanonicalCbor));
    }
    Ok(m)
}
#[derive(Clone, PartialEq, Eq)]
pub struct SignedTaskActionApprovalV2 {
    canonical_payload: Vec<u8>,
    signature: Ed25519SignatureV2,
}
impl core::fmt::Debug for SignedTaskActionApprovalV2 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SignedTaskActionApprovalV2")
            .field("payload_bytes", &self.canonical_payload.len())
            .finish_non_exhaustive()
    }
}
impl SignedTaskActionApprovalV2 {
    pub fn from_canonical_parts(
        canonical_payload: Vec<u8>,
        signature: Ed25519SignatureV2,
    ) -> Result<Self, ProtocolError> {
        decode_task_action_approval_v2(&canonical_payload)?;
        nonzero(signature.as_bytes())?;
        Ok(Self {
            canonical_payload,
            signature,
        })
    }
    pub fn canonical_payload(&self) -> &[u8] {
        &self.canonical_payload
    }
    pub fn signature(&self) -> Ed25519SignatureV2 {
        self.signature
    }
}
pub fn encode_signed_task_action_approval_v2(
    s: &SignedTaskActionApprovalV2,
) -> Result<Vec<u8>, ProtocolError> {
    let mut e = minicbor::Encoder::new(Vec::new());
    e.array(3)
        .and_then(|e| e.u8(1))
        .and_then(|e| e.bytes(&s.canonical_payload))
        .and_then(|e| e.bytes(s.signature.as_bytes()))
        .map_err(ProtocolError::malformed)?;
    Ok(e.into_writer())
}
pub fn decode_signed_task_action_approval_v2(
    bytes: &[u8],
) -> Result<SignedTaskActionApprovalV2, ProtocolError> {
    if bytes.len() > MAX_TASK_ACTION_APPROVAL_BYTES_V2 + 128 {
        return Err(invalid());
    }
    let mut d = minicbor::Decoder::new(bytes);
    if d.array().map_err(ProtocolError::malformed)? != Some(3)
        || d.u64().map_err(ProtocolError::malformed)? != 1
    {
        return Err(invalid());
    }
    let payload = d.bytes().map_err(ProtocolError::malformed)?;
    if payload.len() > MAX_TASK_ACTION_APPROVAL_BYTES_V2 {
        return Err(invalid());
    }
    let s = SignedTaskActionApprovalV2::from_canonical_parts(
        payload.to_vec(),
        Ed25519SignatureV2::new(fixed(&mut d)?),
    )?;
    if d.position() != bytes.len() {
        return Err(invalid());
    }
    if encode_signed_task_action_approval_v2(&s)? != bytes {
        return Err(ProtocolError::stable(StableCode::ProtocolNonCanonicalCbor));
    }
    Ok(s)
}
fn message(payload: &[u8]) -> Vec<u8> {
    [SIGN_DOMAIN, payload].concat()
}
/// Only the trusted approval service may use its signing key, after authentication.
pub fn sign_task_action_approval_v2(
    m: TaskActionApprovalV2,
    key: &SigningKey,
) -> Result<SignedTaskActionApprovalV2, ProtocolError> {
    let payload = encode_task_action_approval_v2(&m)?;
    let signature = Ed25519SignatureV2::new(key.sign(&message(&payload)).to_bytes());
    SignedTaskActionApprovalV2::from_canonical_parts(payload, signature)
}
/// Evidence of signature/context verification, not of persistent one-use consumption.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedTaskActionApprovalV2 {
    material: TaskActionApprovalV2,
    digest: Digest32V2,
}
impl VerifiedTaskActionApprovalV2 {
    pub fn material(&self) -> &TaskActionApprovalV2 {
        &self.material
    }
    pub fn digest(&self) -> Digest32V2 {
        self.digest
    }
    pub fn recheck(
        &self,
        c: &TaskActionApprovalContextV2,
        now: UnixMillisV2,
    ) -> Result<(), ProtocolError> {
        self.material.check(c, now)
    }
}
pub fn verify_task_action_approval_v2(
    s: &SignedTaskActionApprovalV2,
    key: &VerifyingKey,
    c: &TaskActionApprovalContextV2,
    now: UnixMillisV2,
) -> Result<VerifiedTaskActionApprovalV2, ProtocolError> {
    let material = decode_task_action_approval_v2(&s.canonical_payload)?;
    key.verify_strict(
        &message(&s.canonical_payload),
        &Signature::from_bytes(s.signature.as_bytes()),
    )
    .map_err(ProtocolError::malformed)?;
    material.check(c, now)?;
    let mut h = Sha256::new();
    h.update(DIGEST_DOMAIN);
    h.update(encode_signed_task_action_approval_v2(s)?);
    Ok(VerifiedTaskActionApprovalV2 {
        material,
        digest: Digest32V2::new(h.finalize().into()),
    })
}
