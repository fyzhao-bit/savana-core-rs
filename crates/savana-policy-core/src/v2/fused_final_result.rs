//! Private terminal data recovered from authenticated execution state. This is
//! neither declassified output nor a publication/approval/dispatch capability.
use super::{DispatchCoreV2, G4Error, KernelValueV2, ProvenanceRecordV2};
use savana_kernel_protocol::v2::{Digest32V2, DurableTaskIdV2};

pub struct FusedFinalResultCandidateV04 {
    task: DurableTaskIdV2,
    root: Digest32V2,
    profile: Digest32V2,
    source: u16,
    core: DispatchCoreV2,
    result_commit: Digest32V2,
    value: KernelValueV2,
    provenance: ProvenanceRecordV2,
    digest: Digest32V2,
    release: Option<super::fused_planning::FusedFinalReleaseV04>,
}

impl FusedFinalResultCandidateV04 {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn from_owned_result(
        task: DurableTaskIdV2,
        root: Digest32V2,
        profile: Digest32V2,
        source: u16,
        core: DispatchCoreV2,
        result_commit: Digest32V2,
        value: KernelValueV2,
        provenance: ProvenanceRecordV2,
        release: Option<super::fused_planning::FusedFinalReleaseV04>,
    ) -> Result<Self, G4Error> {
        let bytes = value.as_bytes_value().ok_or(G4Error::StateConflict)?;
        if bytes.len() > savana_kernel_protocol::v2::MAX_FINAL_RELEASE_BUSINESS_PAYLOAD_BYTES_V2 {
            return Err(G4Error::StateConflict);
        }
        let core_bytes = minicbor::to_vec(&core).map_err(|_| G4Error::StateConflict)?;
        let digest = super::task_authorization::hash_parts(
            b"SAVANA_FUSED_FINAL_RESULT_CANDIDATE_V04\0",
            &[
                task.as_bytes(),
                root.as_bytes(),
                profile.as_bytes(),
                &source.to_be_bytes(),
                &core_bytes,
                result_commit.as_bytes(),
                provenance.provenance_digest().as_bytes(),
                bytes,
            ],
        );
        Ok(Self {
            task,
            root,
            profile,
            source,
            core,
            result_commit,
            value,
            provenance,
            digest,
            release,
        })
    }
    pub fn task(&self) -> DurableTaskIdV2 {
        self.task
    }
    pub fn root(&self) -> Digest32V2 {
        self.root
    }
    pub fn profile(&self) -> Digest32V2 {
        self.profile
    }
    pub fn source(&self) -> u16 {
        self.source
    }
    pub fn core(&self) -> &DispatchCoreV2 {
        &self.core
    }
    pub fn result_commit(&self) -> Digest32V2 {
        self.result_commit
    }
    pub fn value(&self) -> &KernelValueV2 {
        &self.value
    }
    /// Trusted-host bytes only; possession does not authorize their disclosure.
    pub fn private_payload(&self) -> &[u8] {
        self.value
            .as_bytes_value()
            .expect("validated terminal bytes")
    }
    pub fn provenance(&self) -> &ProvenanceRecordV2 {
        &self.provenance
    }
    pub fn digest(&self) -> Digest32V2 {
        self.digest
    }
    pub fn release(&self) -> Option<&super::fused_planning::FusedFinalReleaseV04> {
        self.release.as_ref()
    }
}
