//! Transported completion evidence; it is not trusted until the terminal receipt
//! has been verified against the expected executor key and exact dispatch.
use super::{Digest32V2, ExecutorCompletionDescriptorV2};
use crate::{ProtocolError, StableCode};
use sha2::{Digest as _, Sha256};

#[derive(Clone, PartialEq, Eq)]
pub struct TaskCompletionEvidenceV2 {
    authorization: Digest32V2,
    application_request: Digest32V2,
    retained_response: Digest32V2,
    terminal_receipt: Vec<u8>,
}

impl std::fmt::Debug for TaskCompletionEvidenceV2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TaskCompletionEvidenceV2")
            .finish_non_exhaustive()
    }
}

impl TaskCompletionEvidenceV2 {
    pub fn new(
        authorization: Digest32V2,
        application_request: Digest32V2,
        retained_response: Digest32V2,
        terminal_receipt: Vec<u8>,
    ) -> Result<Self, ProtocolError> {
        if [authorization, application_request, retained_response]
            .iter()
            .any(|d| d.as_bytes() == &[0; 32])
            || terminal_receipt.is_empty()
            || terminal_receipt.len() > 1024
        {
            return Err(ProtocolError::stable(StableCode::ProtocolMalformedCbor));
        }
        Ok(Self {
            authorization,
            application_request,
            retained_response,
            terminal_receipt,
        })
    }
    pub fn authorization_digest(&self) -> Digest32V2 {
        self.authorization
    }
    pub fn application_request_digest(&self) -> Digest32V2 {
        self.application_request
    }
    pub fn retained_response_digest(&self) -> Digest32V2 {
        self.retained_response
    }
    pub fn terminal_receipt(&self) -> &[u8] {
        &self.terminal_receipt
    }
    pub fn evidence_digest(
        &self,
        completion: ExecutorCompletionDescriptorV2,
    ) -> Result<Digest32V2, ProtocolError> {
        task_completion_evidence_digest_v2(
            self.authorization,
            self.application_request,
            self.retained_response,
            completion,
        )
    }
}

pub fn task_completion_evidence_digest_v2(
    authorization: Digest32V2,
    application_request: Digest32V2,
    retained_response: Digest32V2,
    completion: ExecutorCompletionDescriptorV2,
) -> Result<Digest32V2, ProtocolError> {
    if [authorization, application_request, retained_response]
        .iter()
        .any(|d| d.as_bytes() == &[0; 32])
    {
        return Err(ProtocolError::stable(StableCode::ProtocolMalformedCbor));
    }
    let mut encoder = minicbor::Encoder::new(Vec::new());
    super::kernel_executor::encode_completion_descriptor(&mut encoder, completion)?;
    let completion = encoder.into_writer();
    let mut hash = Sha256::new();
    hash.update(b"SAVANA_TASK_COMPLETION_EVIDENCE_V2_SCHEMA1\0");
    for part in [
        authorization.as_bytes().as_slice(),
        application_request.as_bytes().as_slice(),
        retained_response.as_bytes().as_slice(),
        completion.as_slice(),
    ] {
        hash.update((part.len() as u64).to_be_bytes());
        hash.update(part);
    }
    Ok(Digest32V2::new(hash.finalize().into()))
}
