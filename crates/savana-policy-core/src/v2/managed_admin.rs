//! Signed PRIVATE administration, not an Agent command or an execution grant.
//! Transport authentication/trust-key selection remain the trusted host's job.
use super::{
    ContinuationDispatchPolicyV04, ContinuationStorageProfileV04, G4Error, ManagedSourcePolicyV04,
};
use ed25519_dalek::{Signature, VerifyingKey};
use savana_continuation_core::ledger::ResourceKey;
use savana_kernel_protocol::v2::{Digest32V2, UnixMillisV2};
use serde::{Deserialize, Serialize};

const MAX_COMMAND_BYTES: usize = 256 * 1024;
const MAX_RECEIPTS: usize = 1024;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedAdminCommandV04 {
    pub schema: u16,
    pub installation: [u8; 32],
    pub store: [u8; 32],
    pub request: [u8; 32],
    pub not_before: u64,
    pub expires_at: u64,
    pub operation: ManagedAdminOperationV04,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ManagedAdminOperationV04 {
    RegisterSource {
        policy: ManagedSourcePolicyV04,
        signature: Vec<u8>,
    },
    CreateResource {
        source: [u8; 32],
        namespace: [u8; 32],
        label: String,
        content: Vec<u8>,
    },
    UpdateResource {
        resource: ResourceKey,
        expected_revision: u64,
        value: Option<ManagedAdminValueV04>,
    },
    EnrollTask {
        profile: Box<ContinuationStorageProfileV04>,
        profile_signature: Vec<u8>,
        dispatch: ContinuationDispatchPolicyV04,
        dispatch_signature: Vec<u8>,
    },
    EnrollPlanning {
        profile: Box<super::FusedPlanningProfileV04>,
        profile_signature: Vec<u8>,
    },
    /// Compile against the current root and active tool registry. Approval is
    /// the outer administrator signature; this does not mint a task root.
    CompilePlanning {
        task: [u8; 32],
        draft: Box<super::FusedTaskDraftV04>,
    },
    /// Resolve consented owner inputs and return an UNSIGNED exact recipe
    /// review. This never approves the recipe, a G6 operation or a release.
    PreparePlanningExecution {
        task: [u8; 32],
        root: [u8; 32],
    },
    ApprovePlanningRecipes {
        approval: Box<super::FusedRecipeApprovalV04>,
        approval_signature: Vec<u8>,
    },
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedAdminValueV04 {
    pub label: String,
    pub content: Vec<u8>,
}

impl ManagedAdminCommandV04 {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, G4Error> {
        if let ManagedAdminOperationV04::PreparePlanningExecution { task, root } = &self.operation {
            if *task == [0;32] || *root == [0;32] { return Err(G4Error::StateConflict); }
        }
        if let ManagedAdminOperationV04::CompilePlanning { task, draft } = &self.operation {
            if *task == [0; 32] {
                return Err(G4Error::StateConflict);
            }
            draft.signing_digest()?;
        }
        if self.schema != 1
            || self.not_before >= self.expires_at
            || [self.installation, self.store, self.request].contains(&[0; 32])
        {
            return Err(G4Error::StateConflict);
        }
        let bytes = serde_json::to_vec(self).map_err(|_| G4Error::StateConflict)?;
        if bytes.len() > MAX_COMMAND_BYTES {
            return Err(G4Error::StateConflict);
        }
        Ok(bytes)
    }
    pub fn signing_digest(&self) -> Result<[u8; 32], G4Error> {
        Ok(*super::task_authorization::hash_parts(
            b"SAVANA_MANAGED_ADMIN_COMMAND_V04\0",
            &[&self.canonical_bytes()?],
        )
        .as_bytes())
    }
}

/// No public fields, Deserialize, or unchecked constructor. Verification alone
/// does not check time: the owner permits expired exact receipt replays only.
pub struct VerifiedManagedAdminCommandV04 {
    pub(super) command: ManagedAdminCommandV04,
    pub(super) issuer: VerifyingKey,
    pub(super) digest: [u8; 32],
}
impl VerifiedManagedAdminCommandV04 {
    pub fn validity(&self) -> (u64, u64) { (self.command.not_before, self.command.expires_at) }
    /// Authenticated operator instruction, not a model or Agent request.
    pub fn planning_execution_request(&self, now: UnixMillisV2) -> Result<Option<([u8;32],[u8;32])>, G4Error> {
        self.current(now)?;
        Ok(match self.command.operation {
            ManagedAdminOperationV04::PreparePlanningExecution { task, root } => Some((task, root)),
            _ => None,
        })
    }
    /// The untrusted draft of a compile command, for host checks that need
    /// kernel-held owner material the pure compiler does not see.
    pub fn compile_planning_draft(&self) -> Option<([u8; 32], &super::FusedTaskDraftV04)> {
        match &self.command.operation {
            ManagedAdminOperationV04::CompilePlanning { task, draft } => Some((*task, draft)),
            _ => None,
        }
    }
    /// Select expected key, installation and owner store independently of bytes.
    pub fn verify(
        bytes: &[u8],
        signature: &[u8; 64],
        issuer: &VerifyingKey,
        installation: Digest32V2,
        store: Digest32V2,
    ) -> Result<Self, G4Error> {
        if bytes.len() > MAX_COMMAND_BYTES || issuer.is_weak() {
            return Err(G4Error::StateConflict);
        }
        let command: ManagedAdminCommandV04 =
            serde_json::from_slice(bytes).map_err(|_| G4Error::StateConflict)?;
        if command.canonical_bytes()? != bytes
            || command.installation != *installation.as_bytes()
            || command.store != *store.as_bytes()
        {
            return Err(G4Error::StateConflict);
        }
        let digest = command.signing_digest()?;
        issuer
            .verify_strict(&digest, &Signature::from_bytes(signature))
            .map_err(|_| G4Error::StateConflict)?;
        Ok(Self {
            command,
            issuer: *issuer,
            digest,
        })
    }
    pub(super) fn current(&self, now: UnixMillisV2) -> Result<(), G4Error> {
        if now.get() < self.command.not_before || now.get() >= self.command.expires_at {
            return Err(G4Error::StateConflict);
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ManagedAdminResultV04 {
    SourceRegistered {
        source: [u8; 32],
        namespace: [u8; 32],
    },
    ResourceCreated {
        resource: ResourceKey,
    },
    ResourceUpdated {
        resource: ResourceKey,
        revision: u64,
    },
    TaskEnrolled {
        task: [u8; 32],
        profile: [u8; 32],
    },
    PlanningEnrolled {
        task: [u8; 32],
        profile: [u8; 32],
    },
    PlanningRecipesApproved {
        task: [u8; 32],
        approval: [u8; 32],
    },
    PlanningExecutionPrepared {
        task: [u8; 32],
        run: [u8; 32],
        approval: Box<super::FusedRecipeApprovalV04>,
    },
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    request: [u8; 32],
    digest: [u8; 32],
    issuer: [u8; 32],
    result: ManagedAdminResultV04,
}

/// PRIVATE historical observation, not proof that authority is still current.
/// Deliberately not serializable; the host must authenticate any private reader.
#[derive(Clone, PartialEq, Eq)]
pub struct ManagedAdminReceiptV04 {
    entry: Entry,
}
impl ManagedAdminReceiptV04 {
    pub fn request(&self) -> [u8; 32] {
        self.entry.request
    }
    pub fn command_digest(&self) -> [u8; 32] {
        self.entry.digest
    }
    pub fn result(&self) -> &ManagedAdminResultV04 {
        &self.entry.result
    }
}
impl std::fmt::Debug for ManagedAdminReceiptV04 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ManagedAdminReceiptV04(<private observation>)")
    }
}

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ManagedAdminJournalV04 {
    entries: Vec<Entry>,
}
impl ManagedAdminJournalV04 {
    pub(super) fn results(&self) -> impl Iterator<Item = &ManagedAdminResultV04> {
        self.entries.iter().map(|entry| &entry.result)
    }
    pub(super) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    pub(super) fn replay(
        &self,
        proof: &VerifiedManagedAdminCommandV04,
    ) -> Result<Option<ManagedAdminReceiptV04>, G4Error> {
        let Some(entry) = self
            .entries
            .iter()
            .find(|e| e.request == proof.command.request)
        else {
            return Ok(None);
        };
        if entry.digest != proof.digest || entry.issuer != proof.issuer.to_bytes() {
            return Err(G4Error::StateConflict);
        }
        Ok(Some(ManagedAdminReceiptV04 {
            entry: entry.clone(),
        }))
    }
    pub(super) fn append(
        &mut self,
        proof: &VerifiedManagedAdminCommandV04,
        result: ManagedAdminResultV04,
    ) -> Result<ManagedAdminReceiptV04, G4Error> {
        if self.entries.len() >= MAX_RECEIPTS
            || self
                .entries
                .iter()
                .any(|e| e.request == proof.command.request)
        {
            return Err(G4Error::StateConflict);
        }
        let entry = Entry {
            request: proof.command.request,
            digest: proof.digest,
            issuer: proof.issuer.to_bytes(),
            result,
        };
        self.entries.push(entry.clone());
        Ok(ManagedAdminReceiptV04 { entry })
    }
    pub(super) fn validate(&self) -> Result<(), G4Error> {
        if self.entries.len() > MAX_RECEIPTS {
            return Err(G4Error::DurableStateCorrupt);
        }
        for (i, e) in self.entries.iter().enumerate() {
            if [e.request, e.digest, e.issuer].contains(&[0; 32])
                || VerifyingKey::from_bytes(&e.issuer)
                    .map_err(|_| G4Error::DurableStateCorrupt)?
                    .is_weak()
                || self.entries[..i].iter().any(|old| old.request == e.request)
            {
                return Err(G4Error::DurableStateCorrupt);
            }
            let valid = match &e.result {
                ManagedAdminResultV04::SourceRegistered { source, namespace } => {
                    *source != [0; 32] && *namespace != [0; 32]
                }
                ManagedAdminResultV04::ResourceCreated { resource } => {
                    super::managed_resource_locator_v04(*resource).is_ok()
                }
                ManagedAdminResultV04::ResourceUpdated { resource, revision } => {
                    *revision > 0 && super::managed_resource_locator_v04(*resource).is_ok()
                }
                ManagedAdminResultV04::TaskEnrolled { task, profile }
                | ManagedAdminResultV04::PlanningEnrolled { task, profile } => {
                    *task != [0; 32] && *profile != [0; 32]
                }
                ManagedAdminResultV04::PlanningRecipesApproved { task, approval } => {
                    *task != [0; 32] && *approval != [0; 32]
                }
                ManagedAdminResultV04::PlanningExecutionPrepared { task, run, approval } => {
                    *task != [0;32] && *run != [0;32] && approval.task == *task
                        && approval.signing_digest().is_ok()
                }
            };
            if !valid {
                return Err(G4Error::DurableStateCorrupt);
            }
        }
        Ok(())
    }
}

pub(super) fn signature(bytes: &[u8]) -> Result<[u8; 64], G4Error> {
    bytes.try_into().map_err(|_| G4Error::StateConflict)
}
