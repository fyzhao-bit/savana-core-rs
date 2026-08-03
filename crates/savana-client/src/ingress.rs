use std::fs::{File, Metadata};
use std::io::{Cursor, Seek as _, SeekFrom};
use std::path::Path;

use savana_kernel_protocol::v2::{
    decode_ingress_browser_mutation_response_v2, encode_ingress_browser_request_v2,
    AgentBrowserActionV2, AgentBrowserMutationResponseV2, ContentKindV2, Digest32V2,
    FixedBrowserFormPostCarrierV2, IngressBrowserMutationResponseV2, IngressBrowserRequestV2,
    IngressTabSessionCapabilityV2, InputPublicStateV2, ZeroizingBytesV2,
};
use sha2::{Digest as _, Sha256};

use crate::approval::ApprovalOutcome;
use crate::session::LocalSessionState;
use crate::{
    ApprovalDenied, BrowserContentType, BrowserOrigin, BrowserRequest, BrowserRoute,
    BrowserService, ContentKind, SavanaError, Session,
};

const INGRESS_CHUNK_BYTES: usize = 256 * 1024;

impl Session {
    pub fn ingest_text(&mut self, text: &str, kind: ContentKind) -> Result<(), SavanaError> {
        if text.is_empty() {
            return Err(SavanaError::InvalidRequest);
        }
        let bytes = text.as_bytes();
        let digest = Digest32V2::new(Sha256::digest(bytes).into());
        self.ingest_reader(Cursor::new(bytes), bytes.len() as u64, digest, kind)
    }

    pub fn ingest_file(&mut self, path: &Path, kind: ContentKind) -> Result<(), SavanaError> {
        self.require_open()?;
        let mut file = open_input_file(path)?;
        let metadata = file.metadata().map_err(|_| SavanaError::InvalidRequest)?;
        validate_file_metadata(&metadata)?;
        let declared_total_bytes = metadata.len();
        let (digest, observed) = hash_reader(&mut file)?;
        if observed != declared_total_bytes {
            return Err(SavanaError::InvalidRequest);
        }
        file.seek(SeekFrom::Start(0))
            .map_err(|_| SavanaError::InvalidRequest)?;
        self.ingest_reader(file, declared_total_bytes, digest, kind)
    }

    fn ingest_reader(
        &mut self,
        mut reader: impl std::io::Read,
        declared_total_bytes: u64,
        digest: Digest32V2,
        kind: ContentKind,
    ) -> Result<(), SavanaError> {
        self.require_open()?;
        if declared_total_bytes == 0 {
            return Err(SavanaError::InvalidRequest);
        }
        let prepared = match self.agent_action(AgentBrowserActionV2::PrepareFollowupIngress) {
            Ok(response) => response,
            Err(error) => {
                self.state = LocalSessionState::Closed;
                return Err(error);
            }
        };
        let bootstrap = match prepared {
            AgentBrowserMutationResponseV2::FollowupOpenIngress {
                post: FixedBrowserFormPostCarrierV2::AgentFollowupIngress(bootstrap),
            } => bootstrap,
            _ => {
                self.state = LocalSessionState::Closed;
                return Err(SavanaError::InvalidResponse);
            }
        };
        let tab = match self.authenticate_followup_ingress(bootstrap) {
            Ok(tab) => tab,
            Err(error) => {
                self.state = LocalSessionState::Closed;
                return Err(error);
            }
        };
        let begin_nonce = match self.nonces.nonce() {
            Ok(nonce) => nonce,
            Err(error) => {
                self.state = LocalSessionState::Closed;
                return Err(error);
            }
        };
        let begun = self.ingress_mutation(
            BrowserRoute::IngressInputBegin,
            IngressBrowserRequestV2::Begin {
                tab,
                client_request_nonce: begin_nonce,
                content_kind: protocol_content_kind(kind),
                declared_total_bytes,
                declared_content_digest: Some(digest),
            },
        );
        match begun {
            Ok(IngressBrowserMutationResponseV2::Begun { next_sequence: 0 }) => {}
            Ok(_) => {
                self.abort_after_error(tab);
                return Err(SavanaError::InvalidResponse);
            }
            Err(error) => {
                self.abort_after_error(tab);
                return Err(error);
            }
        }

        let mut sequence = 0_u32;
        let mut total = 0_u64;
        let mut observed_hasher = Sha256::new();
        loop {
            let mut chunk = vec![0_u8; INGRESS_CHUNK_BYTES];
            let length = match reader.read(&mut chunk) {
                Ok(length) => length,
                Err(_) => {
                    self.abort_after_error(tab);
                    return Err(SavanaError::InvalidRequest);
                }
            };
            if length == 0 {
                break;
            }
            chunk.truncate(length);
            total = match total.checked_add(length as u64) {
                Some(total) if total <= declared_total_bytes => total,
                _ => {
                    self.abort_after_error(tab);
                    return Err(SavanaError::InvalidRequest);
                }
            };
            observed_hasher.update(&chunk);
            let append_nonce = match self.nonces.nonce() {
                Ok(nonce) => nonce,
                Err(error) => {
                    self.abort_after_error(tab);
                    return Err(error);
                }
            };
            let request = IngressBrowserRequestV2::Append {
                tab,
                client_request_nonce: append_nonce,
                sequence,
                chunk: ZeroizingBytesV2::new(chunk).map_err(|_| SavanaError::InvalidRequest)?,
            };
            let appended = self.ingress_mutation(BrowserRoute::IngressInputChunk, request);
            match appended {
                Ok(IngressBrowserMutationResponseV2::ChunkAccepted {
                    acknowledged_sequence,
                    ..
                }) if acknowledged_sequence == sequence => {}
                Ok(_) => {
                    self.abort_after_error(tab);
                    return Err(SavanaError::InvalidResponse);
                }
                Err(error) => {
                    self.abort_after_error(tab);
                    return Err(error);
                }
            }
            sequence = match sequence.checked_add(1) {
                Some(sequence) => sequence,
                None => {
                    self.abort_after_error(tab);
                    return Err(SavanaError::InvalidRequest);
                }
            };
        }
        if total != declared_total_bytes
            || Digest32V2::new(observed_hasher.finalize().into()) != digest
        {
            self.abort_after_error(tab);
            return Err(SavanaError::InvalidRequest);
        }

        let first_request = match finalize_request(self, tab, digest) {
            Ok(request) => request,
            Err(error) => {
                self.abort_after_error(tab);
                return Err(error);
            }
        };
        let first_finalize =
            self.ingress_mutation(BrowserRoute::IngressInputFinalize, first_request);
        let transfer = match first_finalize {
            Ok(IngressBrowserMutationResponseV2::FinalizeOpenApproval { transfer }) => transfer,
            Ok(_) => {
                self.state = LocalSessionState::Closed;
                return Err(SavanaError::InvalidResponse);
            }
            Err(error) => {
                self.state = LocalSessionState::Closed;
                return Err(error);
            }
        };
        let outcome = match self.approve_ingress(transfer) {
            Ok(outcome) => outcome,
            Err(error) => {
                self.state = LocalSessionState::Closed;
                return Err(error);
            }
        };
        let final_request = match finalize_request(self, tab, digest) {
            Ok(request) => request,
            Err(error) => {
                self.state = LocalSessionState::Closed;
                return Err(error);
            }
        };
        let final_response =
            match self.ingress_mutation(BrowserRoute::IngressInputFinalize, final_request) {
                Ok(response) => response,
                Err(error) => {
                    self.state = LocalSessionState::Closed;
                    return Err(error);
                }
            };
        let result = match (outcome, final_response) {
            (
                ApprovalOutcome::Approved,
                IngressBrowserMutationResponseV2::FinalizeCommitted {
                    state: InputPublicStateV2::CommittedUnclaimed | InputPublicStateV2::AgentClaimed,
                },
            ) => Ok(()),
            (
                ApprovalOutcome::Denied,
                IngressBrowserMutationResponseV2::FinalizeRejected {
                    state: InputPublicStateV2::Denied,
                },
            ) => Err(ApprovalDenied.into()),
            _ => Err(SavanaError::InvalidResponse),
        };
        if matches!(&result, Err(SavanaError::InvalidResponse)) {
            self.state = LocalSessionState::Closed;
        }
        result
    }

    fn ingress_mutation(
        &self,
        route: BrowserRoute,
        request: IngressBrowserRequestV2,
    ) -> Result<IngressBrowserMutationResponseV2, SavanaError> {
        let response = self.send_browser_request(BrowserRequest {
            service: BrowserService::Ingress,
            route,
            origin: BrowserOrigin::Ingress,
            content_type: BrowserContentType::CanonicalCbor,
            body: encode_ingress_browser_request_v2(&request)
                .map_err(|_| SavanaError::InvalidRequest)?,
        })?;
        decode_ingress_browser_mutation_response_v2(response.body())
            .map_err(|_| SavanaError::InvalidResponse)
    }

    fn abort_after_error(&mut self, tab: IngressTabSessionCapabilityV2) {
        let Ok(nonce) = self.nonces.nonce() else {
            self.state = LocalSessionState::Closed;
            return;
        };
        if !matches!(
            self.ingress_mutation(
                BrowserRoute::IngressInputAbort,
                IngressBrowserRequestV2::Abort {
                    tab,
                    client_request_nonce: nonce,
                },
            ),
            Ok(IngressBrowserMutationResponseV2::Aborted)
        ) {
            self.state = LocalSessionState::Closed;
        }
    }
}

fn finalize_request(
    session: &Session,
    tab: IngressTabSessionCapabilityV2,
    digest: Digest32V2,
) -> Result<IngressBrowserRequestV2, SavanaError> {
    Ok(IngressBrowserRequestV2::Finalize {
        tab,
        client_request_nonce: session.nonces.nonce()?,
        declared_content_digest: digest,
    })
}

const fn protocol_content_kind(kind: ContentKind) -> ContentKindV2 {
    match kind {
        ContentKind::ChatText => ContentKindV2::ChatText,
        ContentKind::PlainText => ContentKindV2::PlainText,
        ContentKind::ParsedDocument => ContentKindV2::ParsedDocument,
    }
}

fn hash_reader(reader: &mut impl std::io::Read) -> Result<(Digest32V2, u64), SavanaError> {
    let mut hasher = Sha256::new();
    let mut total = 0_u64;
    let mut chunk = [0_u8; INGRESS_CHUNK_BYTES];
    loop {
        let length = reader
            .read(&mut chunk)
            .map_err(|_| SavanaError::InvalidRequest)?;
        if length == 0 {
            break;
        }
        total = total
            .checked_add(length as u64)
            .ok_or(SavanaError::InvalidRequest)?;
        hasher.update(&chunk[..length]);
    }
    Ok((Digest32V2::new(hasher.finalize().into()), total))
}

fn validate_file_metadata(metadata: &Metadata) -> Result<(), SavanaError> {
    if !metadata.is_file() || metadata.len() == 0 {
        return Err(SavanaError::InvalidRequest);
    }
    Ok(())
}

#[cfg(unix)]
fn open_input_file(path: &Path) -> Result<File, SavanaError> {
    use rustix::fs::{open, Mode, OFlags};

    let descriptor = open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|_| SavanaError::InvalidRequest)?;
    Ok(File::from(descriptor))
}

#[cfg(not(unix))]
fn open_input_file(path: &Path) -> Result<File, SavanaError> {
    File::open(path).map_err(|_| SavanaError::InvalidRequest)
}
