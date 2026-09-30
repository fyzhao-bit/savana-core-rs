//! Private, immutable source snapshots at G7 admission. These are input records,
//! NOT execution permissions or declassified output. No wire format is exposed.
use super::{ContinuationDispatchPolicyV04, ContinuationResourceFactV04, G4Error};
use savana_continuation_core::ledger::{Reservation, ResourceKey};
use savana_kernel_protocol::v2::{Digest32V2, Nonce32V2};
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SnapshotBody {
    pub schema: u16,
    pub execution: [u8; 32],
    pub request_binding: [u8; 32],
    pub dispatch_policy: [u8; 32],
    pub source_policy: [u8; 32],
    pub action_content: [u8; 32],
    pub resource: ResourceKey,
    pub revision: u64,
    pub label: String,
    pub content: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StoredManagedExecutionSnapshotV04 {
    pub body: SnapshotBody,
    commitment: [u8; 32],
}

impl StoredManagedExecutionSnapshotV04 {
    pub(super) fn new(body: SnapshotBody) -> Result<Self, G4Error> {
        let commitment = Self::digest(&body)?;
        Ok(Self { body, commitment })
    }
    fn digest(body: &SnapshotBody) -> Result<[u8; 32], G4Error> {
        if body.schema != 1
            || body.revision == 0
            || body.content.len() > 32 * 1024
            || body.label.len() > 256
            || body.label.chars().any(char::is_control)
            || [
                body.execution,
                body.request_binding,
                body.dispatch_policy,
                body.source_policy,
                body.action_content,
            ]
            .contains(&[0; 32])
        {
            return Err(G4Error::StateConflict);
        }
        super::managed_resource_locator_v04(body.resource)?;
        let bytes = serde_json::to_vec(body).map_err(|_| G4Error::StateConflict)?;
        Ok(*super::task_authorization::hash_parts(
            b"SAVANA_MANAGED_EXECUTION_SNAPSHOT_V04\0",
            &[&bytes],
        )
        .as_bytes())
    }
    pub(super) fn validate_binding(
        &self,
        policy: &ContinuationDispatchPolicyV04,
        reservation: &Reservation,
        fact: &ContinuationResourceFactV04,
    ) -> Result<(), G4Error> {
        let b = &self.body;
        if b.execution != reservation.execution
            || b.request_binding != reservation.request_binding
            || b.resource != reservation.resource
            || b.resource != fact.resource
            || Some(b.revision) != fact.managed_revision
            || b.action_content != fact.action_content
            || b.dispatch_policy != policy.signing_digest()?
            || b.dispatch_policy != fact.policy
            || Self::digest(b)? != self.commitment
        {
            return Err(G4Error::StateConflict);
        }
        Ok(())
    }
    pub(super) fn private_view(&self) -> ManagedExecutionSnapshotV04 {
        ManagedExecutionSnapshotV04 {
            stored: self.clone(),
        }
    }
}

/// Private host/audit read, not authority to send bytes to execd or a model.
/// The host authenticates the reader. No public constructor/Deserialize/Serialize.
pub struct ManagedExecutionSnapshotV04 {
    stored: StoredManagedExecutionSnapshotV04,
}
impl std::fmt::Debug for ManagedExecutionSnapshotV04 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ManagedExecutionSnapshotV04")
            .finish_non_exhaustive()
    }
}
impl ManagedExecutionSnapshotV04 {
    pub fn execution_nonce(&self) -> Nonce32V2 {
        Nonce32V2::new(self.stored.body.execution)
    }
    pub fn resource(&self) -> ResourceKey {
        self.stored.body.resource
    }
    pub fn revision(&self) -> u64 {
        self.stored.body.revision
    }
    pub fn label(&self) -> &str {
        &self.stored.body.label
    }
    pub fn content(&self) -> &[u8] {
        &self.stored.body.content
    }
    /// Private integrity commitment. It is not safe public metadata: it commits
    /// private content and identities and must stay within the trusted boundary.
    pub fn commitment(&self) -> Digest32V2 {
        Digest32V2::new(self.stored.commitment)
    }
}
