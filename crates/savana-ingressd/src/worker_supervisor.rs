use std::time::Instant;

use savana_kernel_protocol::v2::{Digest32V2, UnixMillisV2};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use crate::worker_protocol::{
    decode_parser_worker_frame, parser_output_digest, parser_transcript_begin,
    parser_transcript_step, verify_parser_worker_job, ParserWorkerFrameV2,
    ParserWorkerProtocolErrorV2, VerifiedParserWorkerJobV2, VerifiedParserWorkerTrustV2,
    MAX_PARSER_WORKER_FRAME_BYTES,
};

const MAX_PARSER_FRAMES: usize = 8_192;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum ParserWorkerSupervisorErrorV2 {
    #[error("a verified parser sandbox launcher is unavailable")]
    SandboxUnavailable,
    #[error("the parser worker could not be launched")]
    LaunchFailed,
    #[error("the parser worker deadline was exceeded")]
    DeadlineExceeded,
    #[error("the parser worker violated its one-job protocol")]
    ProtocolViolation,
    #[error("the parser worker reported a closed failure class")]
    WorkerFailed,
    #[error("the parser worker protocol failed")]
    Protocol(ParserWorkerProtocolErrorV2),
}

pub(crate) trait ParserWorkerChildV2: Send {
    fn send_job(
        &mut self,
        canonical_descriptor: &[u8],
        original: &[u8],
        deadline: Instant,
    ) -> Result<(), ParserWorkerSupervisorErrorV2>;

    fn receive_frame(
        &mut self,
        deadline: Instant,
    ) -> Result<Option<Vec<u8>>, ParserWorkerSupervisorErrorV2>;

    /// Waits for process exit and proves channel EOF immediately followed the
    /// one terminal frame.
    fn finish_after_terminal(
        &mut self,
        deadline: Instant,
    ) -> Result<(), ParserWorkerSupervisorErrorV2>;

    fn kill_and_reap(&mut self);
}

pub(crate) trait VerifiedParserSandboxLauncherV2: Send + Sync {
    fn launch_one_job(
        &self,
        job: &VerifiedParserWorkerJobV2,
        ephemeral_signing_seed: Zeroizing<[u8; 32]>,
        deadline: Instant,
    ) -> Result<Box<dyn ParserWorkerChildV2>, ParserWorkerSupervisorErrorV2>;
}

pub(crate) struct ParserWorkerSupervisorV2 {
    trust: VerifiedParserWorkerTrustV2,
    launcher: Box<dyn VerifiedParserSandboxLauncherV2>,
}

impl std::fmt::Debug for ParserWorkerSupervisorV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ParserWorkerSupervisorV2")
            .field("trust", &self.trust)
            .finish_non_exhaustive()
    }
}

impl ParserWorkerSupervisorV2 {
    pub(crate) fn from_verified_launcher(
        trust: VerifiedParserWorkerTrustV2,
        launcher: Option<Box<dyn VerifiedParserSandboxLauncherV2>>,
    ) -> Result<Self, ParserWorkerSupervisorErrorV2> {
        let launcher = launcher.ok_or(ParserWorkerSupervisorErrorV2::SandboxUnavailable)?;
        Ok(Self { trust, launcher })
    }

    pub(crate) fn run_one_job(
        &self,
        canonical_descriptor: &[u8],
        original: Zeroizing<Vec<u8>>,
        ephemeral_signing_seed: Zeroizing<[u8; 32]>,
        now: UnixMillisV2,
        deadline: Instant,
    ) -> Result<VerifiedParserWorkerOutputV2, ParserWorkerSupervisorErrorV2> {
        if Instant::now() >= deadline {
            return Err(ParserWorkerSupervisorErrorV2::DeadlineExceeded);
        }
        let job =
            verify_parser_worker_job(canonical_descriptor, original.as_slice(), &self.trust, now)
                .map_err(ParserWorkerSupervisorErrorV2::Protocol)?;
        if !job.ephemeral_seed_matches(&ephemeral_signing_seed) {
            return Err(ParserWorkerSupervisorErrorV2::ProtocolViolation);
        }
        let mut child = self
            .launcher
            .launch_one_job(&job, ephemeral_signing_seed, deadline)?;
        let result = run_child_protocol(child.as_mut(), &job, original.as_slice(), now, deadline);
        if result.is_err() {
            child.kill_and_reap();
        }
        result
    }
}

pub(crate) struct VerifiedParserWorkerOutputV2 {
    bytes: Zeroizing<Vec<u8>>,
    page_count: u32,
    output_digest: Digest32V2,
}

impl std::fmt::Debug for VerifiedParserWorkerOutputV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VerifiedParserWorkerOutputV2")
            .field("page_count", &self.page_count)
            .field("output_digest", &self.output_digest)
            .finish_non_exhaustive()
    }
}

impl VerifiedParserWorkerOutputV2 {
    pub(crate) fn into_bytes(self) -> Zeroizing<Vec<u8>> {
        self.bytes
    }

    pub(crate) const fn page_count(&self) -> u32 {
        self.page_count
    }

    pub(crate) const fn output_digest(&self) -> Digest32V2 {
        self.output_digest
    }
}

fn run_child_protocol(
    child: &mut dyn ParserWorkerChildV2,
    job: &VerifiedParserWorkerJobV2,
    original: &[u8],
    now: UnixMillisV2,
    deadline: Instant,
) -> Result<VerifiedParserWorkerOutputV2, ParserWorkerSupervisorErrorV2> {
    ensure_deadline(deadline)?;
    child.send_job(job.canonical_descriptor(), original, deadline)?;
    let mut transcript = parser_transcript_begin(job);
    let mut output = Zeroizing::new(Vec::new());
    output
        .try_reserve(job.output_limit_bytes() as usize)
        .map_err(|_| ParserWorkerSupervisorErrorV2::ProtocolViolation)?;
    let mut next_page = 0_u32;
    let mut next_chunk = 0_u32;
    let mut page_is_open = false;

    for _ in 0..MAX_PARSER_FRAMES {
        ensure_deadline(deadline)?;
        let encoded = child
            .receive_frame(deadline)?
            .ok_or(ParserWorkerSupervisorErrorV2::ProtocolViolation)?;
        if encoded.len() > MAX_PARSER_WORKER_FRAME_BYTES {
            return Err(ParserWorkerSupervisorErrorV2::ProtocolViolation);
        }
        match decode_parser_worker_frame(&encoded, job)
            .map_err(ParserWorkerSupervisorErrorV2::Protocol)?
        {
            ParserWorkerFrameV2::Page(page) => {
                if page.job_nonce() != job.job_nonce()
                    || page.page_index() != next_page
                    || page.page_chunk_index() != next_chunk
                    || next_page >= job.maximum_pages()
                    || page.extracted_chunk_digest()
                        != Digest32V2::new(Sha256::digest(page.extracted_chunk()).into())
                {
                    return Err(ParserWorkerSupervisorErrorV2::ProtocolViolation);
                }
                let new_len = output
                    .len()
                    .checked_add(page.extracted_chunk().len())
                    .ok_or(ParserWorkerSupervisorErrorV2::ProtocolViolation)?;
                if new_len > job.output_limit_bytes() as usize {
                    return Err(ParserWorkerSupervisorErrorV2::ProtocolViolation);
                }
                output.extend_from_slice(page.extracted_chunk());
                transcript =
                    parser_transcript_step(transcript, page.canonical_without_attestation());
                page_is_open = !page.final_chunk_for_page();
                if page.final_chunk_for_page() {
                    next_page = next_page
                        .checked_add(1)
                        .ok_or(ParserWorkerSupervisorErrorV2::ProtocolViolation)?;
                    next_chunk = 0;
                } else {
                    next_chunk = next_chunk
                        .checked_add(1)
                        .ok_or(ParserWorkerSupervisorErrorV2::ProtocolViolation)?;
                }
            }
            ParserWorkerFrameV2::Complete(complete) => {
                let output_digest = parser_output_digest(&output);
                if output.is_empty()
                    || page_is_open
                    || next_page == 0
                    || complete.page_count() != next_page
                    || complete.transcript_digest() != transcript
                    || complete.extracted_byte_length() != output.len() as u64
                    || complete.extracted_output_digest() != output_digest
                    || complete.completed_at().get() < now.get()
                    || complete.completed_at().get() >= job.expires_at().get()
                {
                    return Err(ParserWorkerSupervisorErrorV2::ProtocolViolation);
                }
                child.finish_after_terminal(deadline)?;
                return Ok(VerifiedParserWorkerOutputV2 {
                    bytes: output,
                    page_count: next_page,
                    output_digest,
                });
            }
            ParserWorkerFrameV2::Failed(failure_class) => {
                let _closed_failure_class = failure_class;
                child.finish_after_terminal(deadline)?;
                return Err(ParserWorkerSupervisorErrorV2::WorkerFailed);
            }
        }
    }
    Err(ParserWorkerSupervisorErrorV2::ProtocolViolation)
}

fn ensure_deadline(deadline: Instant) -> Result<(), ParserWorkerSupervisorErrorV2> {
    if Instant::now() >= deadline {
        Err(ParserWorkerSupervisorErrorV2::DeadlineExceeded)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use ed25519_dalek::SigningKey;
    use savana_kernel_protocol::v2::{
        Digest32V2, Ed25519KeyIdV2, Nonce32V2, ServiceIdentityV2, UnixMillisV2,
    };
    use zeroize::Zeroizing;

    use super::{
        ParserWorkerChildV2, ParserWorkerSupervisorErrorV2, ParserWorkerSupervisorV2,
        VerifiedParserSandboxLauncherV2,
    };
    use crate::worker_protocol::test_support::{
        complete_frame, fixture, page_frame, ParserFixtureV2,
    };
    use crate::worker_protocol::{
        decode_parser_worker_frame, parser_transcript_begin, parser_transcript_step,
        verify_parser_worker_job, ParserWorkerFrameV2, VerifiedParserWorkerJobV2,
        VerifiedParserWorkerTrustV2, MAX_PARSER_WORKER_FRAME_BYTES,
    };

    struct FakeChild {
        frames: VecDeque<Vec<u8>>,
        clean_exit: bool,
        killed: Arc<AtomicBool>,
        jobs_sent: Arc<AtomicUsize>,
    }

    impl ParserWorkerChildV2 for FakeChild {
        fn send_job(
            &mut self,
            canonical_descriptor: &[u8],
            original: &[u8],
            _deadline: Instant,
        ) -> Result<(), ParserWorkerSupervisorErrorV2> {
            if canonical_descriptor.is_empty() || original.is_empty() {
                return Err(ParserWorkerSupervisorErrorV2::ProtocolViolation);
            }
            self.jobs_sent.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }

        fn receive_frame(
            &mut self,
            _deadline: Instant,
        ) -> Result<Option<Vec<u8>>, ParserWorkerSupervisorErrorV2> {
            Ok(self.frames.pop_front())
        }

        fn finish_after_terminal(
            &mut self,
            _deadline: Instant,
        ) -> Result<(), ParserWorkerSupervisorErrorV2> {
            if self.clean_exit && self.frames.is_empty() {
                Ok(())
            } else {
                Err(ParserWorkerSupervisorErrorV2::ProtocolViolation)
            }
        }

        fn kill_and_reap(&mut self) {
            self.killed.store(true, Ordering::SeqCst);
            self.frames.clear();
        }
    }

    struct FakeLauncher {
        frames: Vec<Vec<u8>>,
        clean_exit: bool,
        launches: Arc<AtomicUsize>,
        killed: Arc<AtomicBool>,
        jobs_sent: Arc<AtomicUsize>,
    }

    impl VerifiedParserSandboxLauncherV2 for FakeLauncher {
        fn launch_one_job(
            &self,
            _job: &VerifiedParserWorkerJobV2,
            _ephemeral_signing_seed: Zeroizing<[u8; 32]>,
            _deadline: Instant,
        ) -> Result<Box<dyn ParserWorkerChildV2>, ParserWorkerSupervisorErrorV2> {
            self.launches.fetch_add(1, Ordering::SeqCst);
            Ok(Box::new(FakeChild {
                frames: self.frames.clone().into(),
                clean_exit: self.clean_exit,
                killed: Arc::clone(&self.killed),
                jobs_sent: Arc::clone(&self.jobs_sent),
            }))
        }
    }

    fn trust(fixture: &ParserFixtureV2) -> VerifiedParserWorkerTrustV2 {
        VerifiedParserWorkerTrustV2::from_verified_deployment(
            Digest32V2::new([1; 32]),
            Digest32V2::new([2; 32]),
            3,
            ServiceIdentityV2::new([4; 32]),
            Digest32V2::new([7; 32]),
            Digest32V2::new([8; 32]),
            Ed25519KeyIdV2::new([9; 32]),
            fixture.parent_public_key,
        )
        .unwrap()
    }

    fn valid_frames(fixture: &ParserFixtureV2) -> Vec<Vec<u8>> {
        let job = verify_parser_worker_job(
            &fixture.descriptor,
            &fixture.original,
            &trust(fixture),
            UnixMillisV2::new(100),
        )
        .unwrap();
        let page = page_frame(job.job_nonce(), 0, 0, true, b"parsed output");
        let decoded = decode_parser_worker_frame(&page, &job).unwrap();
        let ParserWorkerFrameV2::Page(decoded_page) = decoded else {
            panic!("page");
        };
        let transcript = parser_transcript_step(
            parser_transcript_begin(&job),
            decoded_page.canonical_without_attestation(),
        );
        let complete = complete_frame(
            &fixture.ephemeral_signing_key,
            fixture.ephemeral_key_id,
            job.job_nonce(),
            job.descriptor_digest(),
            transcript,
            1,
            b"parsed output",
            UnixMillisV2::new(110),
        )
        .unwrap();
        vec![page, complete]
    }

    fn supervisor(
        fixture: &ParserFixtureV2,
        frames: Vec<Vec<u8>>,
        clean_exit: bool,
    ) -> (
        ParserWorkerSupervisorV2,
        Arc<AtomicUsize>,
        Arc<AtomicBool>,
        Arc<AtomicUsize>,
    ) {
        let launches = Arc::new(AtomicUsize::new(0));
        let killed = Arc::new(AtomicBool::new(false));
        let jobs_sent = Arc::new(AtomicUsize::new(0));
        let launcher = FakeLauncher {
            frames,
            clean_exit,
            launches: Arc::clone(&launches),
            killed: Arc::clone(&killed),
            jobs_sent: Arc::clone(&jobs_sent),
        };
        (
            ParserWorkerSupervisorV2::from_verified_launcher(
                trust(fixture),
                Some(Box::new(launcher)),
            )
            .unwrap(),
            launches,
            killed,
            jobs_sent,
        )
    }

    #[test]
    fn valid_one_job_transcript_returns_only_verified_bounded_output() {
        let fixture = fixture();
        let (supervisor, launches, killed, jobs_sent) =
            supervisor(&fixture, valid_frames(&fixture), true);
        let output = supervisor
            .run_one_job(
                &fixture.descriptor,
                Zeroizing::new(fixture.original.clone()),
                Zeroizing::new(fixture.ephemeral_signing_key.to_bytes()),
                UnixMillisV2::new(100),
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap();

        assert_eq!(output.page_count(), 1);
        assert_eq!(output.into_bytes().as_slice(), b"parsed output");
        assert_eq!(launches.load(Ordering::SeqCst), 1);
        assert_eq!(jobs_sent.load(Ordering::SeqCst), 1);
        assert!(!killed.load(Ordering::SeqCst));
    }

    #[test]
    fn invalid_parent_signature_or_original_binding_is_rejected_before_launch() {
        let mut fixture = fixture();
        let frames = valid_frames(&fixture);
        let (supervisor, launches, _, _) = supervisor(&fixture, frames, true);
        let last = fixture.descriptor.len() - 1;
        fixture.descriptor[last] ^= 1;
        let seed = Zeroizing::new(fixture.ephemeral_signing_key.to_bytes());

        assert!(matches!(
            supervisor.run_one_job(
                &fixture.descriptor,
                Zeroizing::new(fixture.original),
                seed,
                UnixMillisV2::new(100),
                Instant::now() + Duration::from_secs(1),
            ),
            Err(ParserWorkerSupervisorErrorV2::Protocol(_))
        ));
        assert_eq!(launches.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn wrong_ephemeral_key_and_frame_after_terminal_kill_and_reap_the_child() {
        let fixture = fixture();
        let job = verify_parser_worker_job(
            &fixture.descriptor,
            &fixture.original,
            &trust(&fixture),
            UnixMillisV2::new(100),
        )
        .unwrap();
        let page = page_frame(Nonce32V2::new([5; 32]), 0, 0, true, b"parsed output");
        let decoded = decode_parser_worker_frame(&page, &job).unwrap();
        let ParserWorkerFrameV2::Page(decoded_page) = decoded else {
            panic!("page");
        };
        let transcript = parser_transcript_step(
            parser_transcript_begin(&job),
            decoded_page.canonical_without_attestation(),
        );
        let wrong_key = SigningKey::from_bytes(&[0x33; 32]);
        let wrong_complete = complete_frame(
            &wrong_key,
            fixture.ephemeral_key_id,
            job.job_nonce(),
            job.descriptor_digest(),
            transcript,
            1,
            b"parsed output",
            UnixMillisV2::new(110),
        )
        .unwrap();
        let (wrong_supervisor, _, wrong_killed, _) =
            supervisor(&fixture, vec![page.clone(), wrong_complete], true);
        assert!(wrong_supervisor
            .run_one_job(
                &fixture.descriptor,
                Zeroizing::new(fixture.original.clone()),
                Zeroizing::new(fixture.ephemeral_signing_key.to_bytes()),
                UnixMillisV2::new(100),
                Instant::now() + Duration::from_secs(1),
            )
            .is_err());
        assert!(wrong_killed.load(Ordering::SeqCst));

        let mut repeated = valid_frames(&fixture);
        repeated.push(page);
        let (repeated_supervisor, _, repeated_killed, _) = supervisor(&fixture, repeated, true);
        assert_eq!(
            repeated_supervisor
                .run_one_job(
                    &fixture.descriptor,
                    Zeroizing::new(fixture.original),
                    Zeroizing::new(fixture.ephemeral_signing_key.to_bytes()),
                    UnixMillisV2::new(100),
                    Instant::now() + Duration::from_secs(1),
                )
                .unwrap_err(),
            ParserWorkerSupervisorErrorV2::ProtocolViolation
        );
        assert!(repeated_killed.load(Ordering::SeqCst));
    }

    #[test]
    fn oversized_frame_and_missing_sandbox_fail_closed() {
        let fixture = fixture();
        assert_eq!(
            ParserWorkerSupervisorV2::from_verified_launcher(trust(&fixture), None).unwrap_err(),
            ParserWorkerSupervisorErrorV2::SandboxUnavailable
        );
        let (supervisor, _, killed, _) = supervisor(
            &fixture,
            vec![vec![0; MAX_PARSER_WORKER_FRAME_BYTES + 1]],
            true,
        );
        assert!(supervisor
            .run_one_job(
                &fixture.descriptor,
                Zeroizing::new(fixture.original),
                Zeroizing::new(fixture.ephemeral_signing_key.to_bytes()),
                UnixMillisV2::new(100),
                Instant::now() + Duration::from_secs(1),
            )
            .is_err());
        assert!(killed.load(Ordering::SeqCst));
    }
}
