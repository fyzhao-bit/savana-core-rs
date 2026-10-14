//! Additional accounting on existing G7 preparation, not new effect authority.
use super::continuation_state::ContinuationStorageProfileV04;
use super::dispatch::{DispatchSubjectV2, KernelDispatchJournalEntryV2};
use super::{G4Error, TaskDispatchBindingV2};
use ed25519_dalek::{Signature, VerifyingKey};
use savana_continuation_core::ledger::{Charge, Reservation, ResourceKey};
use savana_kernel_protocol::v2::{action_content_digest_v2, MagnitudeUnitV2, UnixMillisV2};
use serde::{Deserialize, Serialize};

const MAX_BYTES: usize = 16 * 1024;
const POLICY_DOMAIN: &[u8] = b"SAVANA_CONTINUATION_DISPATCH_POLICY_V04\0";
const RESOURCE_DOMAIN: &[u8] = b"SAVANA_CONTINUATION_RESOURCE_FACT_V04\0";
fn hash(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    *super::task_authorization::hash_parts(domain, &[bytes]).as_bytes()
}
fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, G4Error> {
    let bytes = serde_json::to_vec(value).map_err(|_| G4Error::StateConflict)?;
    if bytes.len() > MAX_BYTES {
        return Err(G4Error::StateConflict);
    }
    Ok(bytes)
}
fn decode<T: serde::de::DeserializeOwned + Serialize>(bytes: &[u8]) -> Result<T, G4Error> {
    if bytes.len() > MAX_BYTES {
        return Err(G4Error::StateConflict);
    }
    let value = serde_json::from_slice(bytes).map_err(|_| G4Error::StateConflict)?;
    if encode(&value)? != bytes {
        return Err(G4Error::StateConflict);
    }
    Ok(value)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContinuationMagnitudeV04 {
    Count,
    Bytes,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum ContinuationChargeBasisV04 {
    PerExecution {
        amount: u64,
    },
    Magnitude {
        unit: ContinuationMagnitudeV04,
        multiplier: u64,
    },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContinuationChargeRuleV04 {
    pub domain: u16,
    pub basis: ContinuationChargeBasisV04,
}

/// Signed local administrative opt-in to *additional* stable accounting.
/// The pinned resource issuer is trusted to preserve object/incarnation identity
/// across aliases and versions. Its key never comes from the submitted facts.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContinuationDispatchPolicyV04 {
    pub schema: u16,
    pub task: [u8; 32],
    pub storage_profile: [u8; 32],
    pub resource_issuer: [u8; 32],
    pub source: [u8; 32],
    pub namespace: [u8; 32],
    pub not_before: u64,
    pub expires_at: u64,
    pub max_evidence_age_ms: u64,
    pub charges: Vec<ContinuationChargeRuleV04>,
}
impl ContinuationDispatchPolicyV04 {
    pub fn signing_digest(&self) -> Result<[u8; 32], G4Error> {
        self.validate()?;
        Ok(hash(POLICY_DOMAIN, &encode(self)?))
    }
    fn validate(&self) -> Result<(), G4Error> {
        if self.schema != 1
            || self.not_before >= self.expires_at
            || self.max_evidence_age_ms == 0
            || self.max_evidence_age_ms > 3_600_000
            || [
                self.task,
                self.storage_profile,
                self.resource_issuer,
                self.source,
                self.namespace,
            ]
            .contains(&[0; 32])
            || self.charges.is_empty()
            || self.charges.len() > 8
            || !self.charges.windows(2).all(|w| w[0].domain < w[1].domain)
            || self.charges.iter().any(|c| match c.basis {
                ContinuationChargeBasisV04::PerExecution { amount } => amount == 0,
                ContinuationChargeBasisV04::Magnitude { multiplier, .. } => multiplier == 0,
            })
        {
            return Err(G4Error::StateConflict);
        }
        let key =
            VerifyingKey::from_bytes(&self.resource_issuer).map_err(|_| G4Error::StateConflict)?;
        if key.is_weak() {
            return Err(G4Error::StateConflict);
        }
        Ok(())
    }
    pub(super) fn validate_profile(
        &self,
        profile: &ContinuationStorageProfileV04,
    ) -> Result<(), G4Error> {
        self.validate()?;
        if self.storage_profile != profile.signing_digest()?
            || self.task != profile.task
            || self.not_before < profile.not_before
            || self.expires_at > profile.expires_at
            || self
                .charges
                .iter()
                .map(|c| c.domain)
                .ne(profile.domains.iter().map(|d| d.domain))
        {
            return Err(G4Error::StateConflict);
        }
        Ok(())
    }
    pub(super) fn current(&self, now: UnixMillisV2) -> Result<(), G4Error> {
        if now.get() < self.not_before || now.get() >= self.expires_at {
            return Err(G4Error::StateConflict);
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct VerifiedContinuationDispatchPolicyV04 {
    pub(super) policy: ContinuationDispatchPolicyV04,
}
impl VerifiedContinuationDispatchPolicyV04 {
    /// Trust key/profile are independently selected by authenticated local admin,
    /// not taken from a planner candidate. Installation rechecks stored bindings.
    pub fn verify(
        bytes: &[u8],
        signature: &[u8; 64],
        issuer: &VerifyingKey,
        profile: &ContinuationStorageProfileV04,
        now: UnixMillisV2,
    ) -> Result<Self, G4Error> {
        let policy: ContinuationDispatchPolicyV04 = decode(bytes)?;
        policy.validate_profile(profile)?;
        policy.current(now)?;
        issuer
            .verify_strict(&policy.signing_digest()?, &Signature::from_bytes(signature))
            .map_err(|_| G4Error::StateConflict)?;
        Ok(Self { policy })
    }
}

/// Private context-bound identity fact. Full content binds the exact resource
/// selector AND action, including task revision, destination and payload digest.
/// A path/version/handle/plan revision is never used as stable object identity.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContinuationResourceFactV04 {
    pub schema: u16,
    pub policy: [u8; 32],
    pub action_content: [u8; 32],
    pub resource: ResourceKey,
    pub issued_at: u64,
    pub expires_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub managed_revision: Option<u64>,
}
impl ContinuationResourceFactV04 {
    pub fn signing_digest(&self) -> Result<[u8; 32], G4Error> {
        if self.schema != 1
            || self.managed_revision == Some(0)
            || self.issued_at >= self.expires_at
            || [
                self.policy,
                self.action_content,
                self.resource.source,
                self.resource.namespace,
                self.resource.object,
            ]
            .contains(&[0; 32])
        {
            return Err(G4Error::StateConflict);
        }
        Ok(hash(RESOURCE_DOMAIN, &encode(self)?))
    }
}

/// Untrusted signed input, NOT verified authority. Verification occurs inside
/// the guarded owner transaction against stored policy and exact G7 binding.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContinuationResourceEvidenceV04 {
    pub(super) fact: ContinuationResourceFactV04,
    signature: Vec<u8>,
}
impl std::fmt::Debug for ContinuationResourceEvidenceV04 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ContinuationResourceEvidenceV04")
            .finish_non_exhaustive()
    }
}
impl ContinuationResourceEvidenceV04 {
    pub fn from_signed(bytes: &[u8], signature: &[u8; 64]) -> Result<Self, G4Error> {
        let fact: ContinuationResourceFactV04 = decode(bytes)?;
        fact.signing_digest()?;
        Ok(Self {
            fact,
            signature: signature.to_vec(),
        })
    }
    fn verify(
        &self,
        policy: &ContinuationDispatchPolicyV04,
        binding: &TaskDispatchBindingV2,
        admitted_at: UnixMillisV2,
    ) -> Result<(), G4Error> {
        let f = &self.fact;
        policy.current(admitted_at)?;
        if f.policy != policy.signing_digest()?
            || f.action_content
                != *action_content_digest_v2(binding.content())
                    .map_err(|_| G4Error::StateConflict)?
                    .as_bytes()
            || f.resource.source != policy.source
            || f.resource.namespace != policy.namespace
            || f.issued_at < policy.not_before
            || f.issued_at > admitted_at.get()
            || admitted_at.get() >= f.expires_at
            || f.expires_at > policy.expires_at
            || admitted_at.get() - f.issued_at > policy.max_evidence_age_ms
        {
            return Err(G4Error::StateConflict);
        }
        let signature =
            Signature::from_slice(&self.signature).map_err(|_| G4Error::StateConflict)?;
        VerifyingKey::from_bytes(&policy.resource_issuer)
            .map_err(|_| G4Error::StateConflict)?
            .verify_strict(&f.signing_digest()?, &signature)
            .map_err(|_| G4Error::StateConflict)
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DispatchAccountingV04 {
    pub policy: ContinuationDispatchPolicyV04,
    pub records: Vec<AccountedDispatchV04>,
    /// First record admitted by snapshot-aware code. Earlier schema-7 records
    /// remain missing, never backfilled using present-day source bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot_start: Option<usize>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AccountedDispatchV04 {
    pub execution: [u8; 32],
    pub admitted_at: u64,
    pub evidence: ContinuationResourceEvidenceV04,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot: Option<super::managed_execution::StoredManagedExecutionSnapshotV04>,
}

pub(super) fn reservation(
    policy: &ContinuationDispatchPolicyV04,
    evidence: &ContinuationResourceEvidenceV04,
    entry: &KernelDispatchJournalEntryV2,
    binding: &TaskDispatchBindingV2,
    admitted_at: UnixMillisV2,
) -> Result<Reservation, G4Error> {
    if *entry.core.durable_task_id.as_bytes() != policy.task
        || !matches!(entry.core.subject, DispatchSubjectV2::ToolExecution { .. })
    {
        return Err(G4Error::StateConflict);
    }
    evidence.verify(policy, binding, admitted_at)?;
    let charges = policy
        .charges
        .iter()
        .map(|rule| {
            let amount = match &rule.basis {
                ContinuationChargeBasisV04::PerExecution { amount } => *amount,
                ContinuationChargeBasisV04::Magnitude { unit, multiplier } => {
                    let expected = match unit {
                        ContinuationMagnitudeV04::Count => MagnitudeUnitV2::Count,
                        ContinuationMagnitudeV04::Bytes => MagnitudeUnitV2::Bytes,
                    };
                    if binding.content().action().magnitude_unit() != expected {
                        return Err(G4Error::StateConflict);
                    }
                    binding
                        .content()
                        .magnitude()
                        .checked_mul(*multiplier)
                        .ok_or(G4Error::StateConflict)?
                }
            };
            Ok(Charge {
                domain: rule.domain,
                amount,
            })
        })
        .collect::<Result<Vec<_>, G4Error>>()?;
    let request_binding = *super::task_authorization::hash_parts(
        b"SAVANA_CONTINUATION_G7_RESERVATION_V04\0",
        &[
            entry.core_digest.as_bytes(),
            entry.sealed_envelope_digest.as_bytes(),
            entry.consumed_ticket_digest.as_bytes(),
            binding.contract_digest().as_bytes(),
            binding.authorization_digest().as_bytes(),
            binding.transition_digest().as_bytes(),
        ],
    )
    .as_bytes();
    Ok(Reservation {
        execution: *entry.core.execution_nonce.as_bytes(),
        request_binding,
        resource: evidence.fact.resource,
        charges,
    })
}
