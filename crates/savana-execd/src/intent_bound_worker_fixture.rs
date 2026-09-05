//! In-memory untrusted worker for integration tests. Uses the actual child codec
//! and supervisor protocol; deliberately does not claim process/OS isolation.
use super::*;
use crate::worker_supervisor::{
    ConnectorWorkerChildV2, ConnectorWorkerInputV2, ConnectorWorkerSupervisorErrorV2 as Error,
    VerifiedConnectorSandboxLauncherV2,
};
use std::time::Instant;

pub(crate) struct Launcher {
    pub now: UnixMillisV2,
    pub substitute_request: bool,
}

impl VerifiedConnectorSandboxLauncherV2 for Launcher {
    fn launch_one_job(
        &self,
        job: &VerifiedConnectorWorkerJobV2,
        seed: Zeroizing<[u8; 32]>,
        _deadline: Instant,
    ) -> Result<Box<dyn ConnectorWorkerChildV2>, Error> {
        Ok(Box::new(Child {
            seed,
            parent: job.parent_public_key(),
            now: self.now,
            substitute_request: self.substitute_request,
            job: None,
            prepared_transcript: None,
            next: None,
            terminal: false,
        }))
    }
}

struct Child {
    seed: Zeroizing<[u8; 32]>,
    parent: [u8; 32],
    now: UnixMillisV2,
    substitute_request: bool,
    job: Option<ChildJobV2>,
    prepared_transcript: Option<Digest32V2>,
    next: Option<Vec<u8>>,
    terminal: bool,
}

impl ConnectorWorkerChildV2 for Child {
    fn send_job(
        &mut self,
        descriptor: &[u8],
        input: ConnectorWorkerInputV2<'_>,
        _deadline: Instant,
    ) -> Result<(), Error> {
        if self.job.is_some() {
            return Err(Error::ProtocolViolation);
        }
        let (mode, bytes, effect) = match input {
            ConnectorWorkerInputV2::Prepare {
                credential_free_material,
            } => (1, credential_free_material, None),
            ConnectorWorkerInputV2::DecodeRetainedResponse {
                retained_provider_response,
                effect_started_receipt_digest,
            } => (
                2,
                retained_provider_response,
                Some(effect_started_receipt_digest),
            ),
        };
        let frame = encode_child_job(descriptor, mode, bytes, effect, &self.seed, &self.parent)
            .map_err(Error::Protocol)?;
        let job = decode_child_job(&frame, self.now).map_err(Error::Protocol)?;
        match &job.input {
            ChildInputV2::Prepare(material) => {
                // A correctly signed worker frame carrying different application
                // bytes must still be refused before the provider attempt.
                let substituted;
                let material = if self.substitute_request {
                    let mut request: serde_json::Value =
                        serde_json::from_slice(material).map_err(|_| Error::ProtocolViolation)?;
                    if request.get("jsonrpc").is_some() {
                        request["params"]["arguments"]["to"] =
                            serde_json::Value::String("Mallory".into());
                    } else {
                        request["body"]["destination"] = serde_json::Value::String(format!(
                            "application-turn:{}",
                            "05".repeat(32)
                        ));
                    }
                    substituted =
                        serde_json::to_vec(&request).map_err(|_| Error::ProtocolViolation)?;
                    substituted.as_slice()
                } else {
                    material.as_slice()
                };
                let (prepared, transcript) =
                    prepare_frame(&job, material).map_err(Error::Protocol)?;
                self.next = Some(prepared);
                self.prepared_transcript = Some(transcript);
            }
            ChildInputV2::Decode { response } => {
                self.next = Some(completion_for_retained(&job, response).map_err(Error::Protocol)?);
                self.terminal = true;
            }
        }
        self.job = Some(job);
        Ok(())
    }
    fn receive_frame(&mut self, _deadline: Instant) -> Result<Option<Vec<u8>>, Error> {
        Ok(self.next.take())
    }
    fn send_provider_response(&mut self, frame: &[u8], _deadline: Instant) -> Result<(), Error> {
        let job = self.job.as_ref().ok_or(Error::ProtocolViolation)?;
        let (response, _) =
            decode_provider_response_frame(frame, &job.verified).map_err(Error::Protocol)?;
        self.next = Some(
            completion_after_provider(
                job,
                frame,
                self.prepared_transcript.ok_or(Error::ProtocolViolation)?,
                &response,
            )
            .map_err(Error::Protocol)?,
        );
        self.terminal = true;
        Ok(())
    }
    fn finish_after_terminal(&mut self, _deadline: Instant) -> Result<(), Error> {
        if self.terminal && self.next.is_none() {
            Ok(())
        } else {
            Err(Error::ProtocolViolation)
        }
    }
    fn kill_and_reap(&mut self) {
        self.next = None;
    }
}
