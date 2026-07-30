#![forbid(unsafe_code)]

#[cfg(all(feature = "macos-development-authority", not(debug_assertions)))]
compile_error!("macos-development-authority is forbidden in release builds");

use std::fmt;

use hmac::{Hmac, Mac as _};
use savana_kernel_protocol::v2::{
    BootIdV2, Digest32V2, Nonce32V2, PrincipalIdV2, ServiceIdentityV2, UnixMillisV2,
};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

mod browser_authority;
mod daemon;
mod kernel_client;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod protocol_parser;
#[allow(dead_code)] // Constructed only by verified production deployment state.
mod sandbox_process;
mod state_owner;
#[allow(dead_code)] // Superseded by the protocol-native production worker; retained for ABI tests.
mod worker_process;
#[allow(dead_code)] // Activated by the production parser worker supervisor.
mod worker_protocol;
#[allow(dead_code)] // Activated by the production parser worker supervisor.
mod worker_supervisor;
pub use browser_authority::{
    IngressBrowserAuthorityErrorV2, IngressBrowserAuthorityV2, PreparedBrowserAuthenticationV2,
};
pub use daemon::{run, IngressdDaemonErrorV2};
pub use kernel_client::{IngressKernelClientErrorV2, SuiteOneIngressKernelClientV2};
pub use state_owner::{IngressStateOwnerErrorV2, IngressStateOwnerV2};

/// Private executable entry point for the installed one-job parser worker.
///
/// This is public only so the package's fixed worker binary can call into the
/// library. It is not part of the ingress service API.
#[doc(hidden)]
pub fn run_parser_worker_stdio_v2() -> Result<(), &'static str> {
    protocol_parser::run_protocol_parser_worker_stdio_v2()
}

const TAB_CAPABILITY_DOMAIN: &[u8] = b"SAVANA_INGRESS_TAB_CAPABILITY_V2\0";
const FINALIZED_CAPABILITY_DOMAIN: &[u8] = b"SAVANA_FINALIZED_INGRESS_CAPABILITY_V2\0";
const CAPABILITY_DERIVATION_DOMAIN: &[u8] = b"SAVANA_INGRESS_CAPABILITY_DERIVATION_V2\0";
const SESSION_ID_DOMAIN: &[u8] = b"SAVANA_INGRESS_SESSION_INTERNAL_ID_V2\0";
const CHUNK_DOMAIN: &[u8] = b"SAVANA_INPUT_CHUNK_V2\0";
const CHANNEL_BEGIN_DOMAIN: &[u8] = b"SAVANA_INPUT_CHANNEL_BEGIN_V2\0";
const CHANNEL_STEP_DOMAIN: &[u8] = b"SAVANA_INPUT_CHANNEL_STEP_V2\0";
const REQUEST_DOMAIN: &[u8] = b"SAVANA_INGRESS_BROWSER_REQUEST_V2\0";
const MAX_CHUNK_BYTES: usize = 256 * 1024;
const MAX_REPLAY_RECORDS: usize = 4_096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum IngressErrorV2 {
    #[error("ingress input is invalid")]
    InvalidInput,
    #[error("ingress capability is invalid or belongs to another context")]
    InvalidCapability,
    #[error("ingress object expired")]
    Expired,
    #[error("ingress request nonce was reused with different bytes")]
    IdempotencyConflict,
    #[error("ingress chunk sequence is not the exact next sequence")]
    InvalidSequence,
    #[error("ingress content digest or declared length does not match")]
    DigestMismatch,
    #[error("parsed input requires verified parser evidence")]
    ParserEvidenceRequired,
    #[error("ingress session failed closed")]
    FailedClosed,
    #[error("ingress object was already consumed")]
    AlreadyConsumed,
    #[error("ingress state conflicts with the requested transition")]
    StateConflict,
    #[error("ingress allocation or entropy failed")]
    AllocationFailure,
    #[error("ingress clock moved below its accepted floor")]
    ClockRollback,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ContentKindV2 {
    ChatText,
    PlainText,
    ParsedDocument,
}

impl ContentKindV2 {
    const fn tag(self) -> u16 {
        match self {
            Self::ChatText => 1,
            Self::PlainText => 2,
            Self::ParsedDocument => 3,
        }
    }

    const fn direct_channel_tag(self) -> u16 {
        match self {
            Self::ChatText => 3,
            Self::PlainText | Self::ParsedDocument => 1,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IngressPublicStateV2 {
    AwaitingBegin,
    Receiving,
    Finalized,
    Transferred,
    Aborted,
    Expired,
    FailedClosed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IngressStateV2 {
    AwaitingBegin,
    Receiving,
    Finalized,
    Transferred,
    Aborted,
    Expired,
    FailedClosed,
}

impl IngressStateV2 {
    const fn public(self) -> IngressPublicStateV2 {
        match self {
            Self::AwaitingBegin => IngressPublicStateV2::AwaitingBegin,
            Self::Receiving => IngressPublicStateV2::Receiving,
            Self::Finalized => IngressPublicStateV2::Finalized,
            Self::Transferred => IngressPublicStateV2::Transferred,
            Self::Aborted => IngressPublicStateV2::Aborted,
            Self::Expired => IngressPublicStateV2::Expired,
            Self::FailedClosed => IngressPublicStateV2::FailedClosed,
        }
    }

    const fn terminal(self) -> bool {
        matches!(
            self,
            Self::Transferred | Self::Aborted | Self::Expired | Self::FailedClosed
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IngressBrowserContextV2 {
    ingressd_boot_id: BootIdV2,
    peer_identity_digest: Digest32V2,
    expires_at: UnixMillisV2,
}

impl IngressBrowserContextV2 {
    pub fn from_authenticated_origin(
        ingressd_boot_id: BootIdV2,
        peer_identity_digest: Digest32V2,
        expires_at: UnixMillisV2,
    ) -> Result<Self, IngressErrorV2> {
        if is_zero(ingressd_boot_id.as_bytes())
            || is_zero(peer_identity_digest.as_bytes())
            || expires_at.get() == 0
        {
            return Err(IngressErrorV2::InvalidInput);
        }
        Ok(Self {
            ingressd_boot_id,
            peer_identity_digest,
            expires_at,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedIngressUiAuthorizationV2 {
    principal: PrincipalIdV2,
    authentication_context_digest: Digest32V2,
    tab_binding_digest: Digest32V2,
    expires_at: UnixMillisV2,
}

impl VerifiedIngressUiAuthorizationV2 {
    pub fn from_verified_ui_settlement(
        principal: PrincipalIdV2,
        authentication_context_digest: Digest32V2,
        tab_binding_digest: Digest32V2,
        expires_at: UnixMillisV2,
    ) -> Result<Self, IngressErrorV2> {
        if is_zero(principal.as_bytes())
            || is_zero(authentication_context_digest.as_bytes())
            || is_zero(tab_binding_digest.as_bytes())
            || expires_at.get() == 0
        {
            return Err(IngressErrorV2::InvalidInput);
        }
        Ok(Self {
            principal,
            authentication_context_digest,
            tab_binding_digest,
            expires_at,
        })
    }

    #[cfg(test)]
    fn new_for_test(
        principal: PrincipalIdV2,
        authentication_context_digest: Digest32V2,
        tab_binding_digest: Digest32V2,
        expires_at: UnixMillisV2,
    ) -> Self {
        Self::from_verified_ui_settlement(
            principal,
            authentication_context_digest,
            tab_binding_digest,
            expires_at,
        )
        .unwrap()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthenticatedKernelIngressReceiverV2 {
    kernel_boot_id: BootIdV2,
    kernel_identity: ServiceIdentityV2,
    expires_at: UnixMillisV2,
}

impl AuthenticatedKernelIngressReceiverV2 {
    pub fn from_mutual_authentication(
        kernel_boot_id: BootIdV2,
        kernel_identity: ServiceIdentityV2,
        expires_at: UnixMillisV2,
    ) -> Result<Self, IngressErrorV2> {
        if is_zero(kernel_boot_id.as_bytes())
            || is_zero(kernel_identity.as_bytes())
            || expires_at.get() == 0
        {
            return Err(IngressErrorV2::InvalidInput);
        }
        Ok(Self {
            kernel_boot_id,
            kernel_identity,
            expires_at,
        })
    }

    #[cfg(test)]
    fn new_for_test(
        kernel_boot_id: BootIdV2,
        kernel_identity: ServiceIdentityV2,
        expires_at: UnixMillisV2,
    ) -> Self {
        Self::from_mutual_authentication(kernel_boot_id, kernel_identity, expires_at).unwrap()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct IngressTabSessionCapabilityV2 {
    token: [u8; 32],
    tab_internal_id: Digest32V2,
}

impl fmt::Debug for IngressTabSessionCapabilityV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("IngressTabSessionCapabilityV2(<opaque>)")
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct FinalizedIngressV2 {
    token: [u8; 32],
    session_internal_id: Digest32V2,
}

impl fmt::Debug for FinalizedIngressV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FinalizedIngressV2(<opaque>)")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IngressBeginAckV2 {
    next_sequence: u32,
}

impl IngressBeginAckV2 {
    pub const fn next_sequence(self) -> u32 {
        self.next_sequence
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IngressAppendAckV2 {
    acknowledged_sequence: u32,
    cumulative_digest: Digest32V2,
}

impl IngressAppendAckV2 {
    pub const fn acknowledged_sequence(self) -> u32 {
        self.acknowledged_sequence
    }

    pub const fn cumulative_digest(self) -> Digest32V2 {
        self.cumulative_digest
    }
}

pub struct IngressKernelTransferV2 {
    installation_id: Digest32V2,
    active_state_manifest_digest: Digest32V2,
    principal: PrincipalIdV2,
    authentication_context_digest: Digest32V2,
    tab_binding_digest: Digest32V2,
    content_kind: ContentKindV2,
    declared_content_digest: Digest32V2,
    cumulative_digest: Digest32V2,
    content: Zeroizing<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedIngressProvenanceEvidenceV2 {
    installation_id: Digest32V2,
    active_state_manifest_digest: Digest32V2,
    principal: PrincipalIdV2,
    authentication_context_digest: Digest32V2,
    tab_binding_digest: Digest32V2,
    content_kind: ContentKindV2,
    declared_content_digest: Digest32V2,
    cumulative_digest: Digest32V2,
}

impl VerifiedIngressProvenanceEvidenceV2 {
    pub const fn installation_id(self) -> Digest32V2 {
        self.installation_id
    }

    pub const fn active_state_manifest_digest(self) -> Digest32V2 {
        self.active_state_manifest_digest
    }

    pub const fn principal(self) -> PrincipalIdV2 {
        self.principal
    }

    pub const fn authentication_context_digest(self) -> Digest32V2 {
        self.authentication_context_digest
    }

    pub const fn tab_binding_digest(self) -> Digest32V2 {
        self.tab_binding_digest
    }

    pub const fn content_kind(self) -> ContentKindV2 {
        self.content_kind
    }

    pub const fn declared_content_digest(self) -> Digest32V2 {
        self.declared_content_digest
    }

    pub const fn cumulative_digest(self) -> Digest32V2 {
        self.cumulative_digest
    }
}

impl savana_policy_core::v2::VerifiedIngressProvenanceEvidenceSourceV2
    for VerifiedIngressProvenanceEvidenceV2
{
    fn active_state_manifest_digest_v2(&self) -> Digest32V2 {
        self.active_state_manifest_digest
    }

    fn authentication_context_digest_v2(&self) -> Digest32V2 {
        self.authentication_context_digest
    }

    fn declared_content_digest_v2(&self) -> Digest32V2 {
        self.declared_content_digest
    }

    fn tab_binding_digest_v2(&self) -> Digest32V2 {
        self.tab_binding_digest
    }
}

impl fmt::Debug for IngressKernelTransferV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IngressKernelTransferV2")
            .field("content_kind", &self.content_kind)
            .field("encoded_len", &self.content.len())
            .finish_non_exhaustive()
    }
}

impl IngressKernelTransferV2 {
    pub const fn installation_id(&self) -> Digest32V2 {
        self.installation_id
    }

    pub const fn active_state_manifest_digest(&self) -> Digest32V2 {
        self.active_state_manifest_digest
    }

    pub const fn principal(&self) -> PrincipalIdV2 {
        self.principal
    }

    pub const fn authentication_context_digest(&self) -> Digest32V2 {
        self.authentication_context_digest
    }

    pub const fn tab_binding_digest(&self) -> Digest32V2 {
        self.tab_binding_digest
    }

    pub const fn content_kind(&self) -> ContentKindV2 {
        self.content_kind
    }

    pub const fn declared_content_digest(&self) -> Digest32V2 {
        self.declared_content_digest
    }

    pub const fn cumulative_digest(&self) -> Digest32V2 {
        self.cumulative_digest
    }

    pub fn into_zeroizing_bytes(self) -> Zeroizing<Vec<u8>> {
        self.content
    }

    pub fn into_provenance_evidence_and_bytes(
        self,
    ) -> (VerifiedIngressProvenanceEvidenceV2, Zeroizing<Vec<u8>>) {
        (
            VerifiedIngressProvenanceEvidenceV2 {
                installation_id: self.installation_id,
                active_state_manifest_digest: self.active_state_manifest_digest,
                principal: self.principal,
                authentication_context_digest: self.authentication_context_digest,
                tab_binding_digest: self.tab_binding_digest,
                content_kind: self.content_kind,
                declared_content_digest: self.declared_content_digest,
                cumulative_digest: self.cumulative_digest,
            },
            self.content,
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReplayResponseV2 {
    Begun(IngressBeginAckV2),
    Appended(IngressAppendAckV2),
    Finalized(FinalizedIngressV2),
    Aborted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ReplayRecordV2 {
    request_nonce: Nonce32V2,
    request_digest: Digest32V2,
    response: ReplayResponseV2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ChunkRecordV2 {
    sequence: u32,
    start: usize,
    length: usize,
    chunk_digest: Digest32V2,
    cumulative_digest: Digest32V2,
}

struct IngressTabRecordV2 {
    capability_digest: Digest32V2,
    tab_internal_id: Digest32V2,
    browser_context: IngressBrowserContextV2,
    principal: PrincipalIdV2,
    authentication_context_digest: Digest32V2,
    tab_binding_digest: Digest32V2,
    authorization_expires_at: UnixMillisV2,
    state: IngressStateV2,
    session_internal_id: Option<Digest32V2>,
    content_kind: Option<ContentKindV2>,
    declared_total_bytes: Option<u64>,
    begin_declared_content_digest: Option<Digest32V2>,
    cumulative_digest: Option<Digest32V2>,
    finalized_content_digest: Option<Digest32V2>,
    finalized_capability_digest: Option<Digest32V2>,
    next_sequence: u32,
    content: Zeroizing<Vec<u8>>,
    chunks: Vec<ChunkRecordV2>,
    replay: Vec<ReplayRecordV2>,
}

impl fmt::Debug for IngressTabRecordV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IngressTabRecordV2")
            .field("state", &self.state)
            .field("content_kind", &self.content_kind)
            .field("encoded_len", &self.content.len())
            .field("next_sequence", &self.next_sequence)
            .finish_non_exhaustive()
    }
}

pub struct IngressServiceV2 {
    installation_id: Digest32V2,
    active_state_manifest_digest: Digest32V2,
    ingressd_boot_id: BootIdV2,
    ingressd_identity: ServiceIdentityV2,
    expected_kernel_boot_id: BootIdV2,
    expected_kernel_identity: ServiceIdentityV2,
    maximum_sessions: usize,
    maximum_input_bytes: usize,
    accepted_time_floor_ms: u64,
    capability_key: Zeroizing<[u8; 32]>,
    consumed_authorizations: Vec<Digest32V2>,
    tabs: Vec<IngressTabRecordV2>,
}

impl fmt::Debug for IngressServiceV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IngressServiceV2")
            .field("ingressd_identity", &self.ingressd_identity)
            .field("tab_count", &self.tabs.len())
            .field("accepted_time_floor_ms", &self.accepted_time_floor_ms)
            .finish_non_exhaustive()
    }
}

impl IngressServiceV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn from_verified_deployment(
        installation_id: Digest32V2,
        active_state_manifest_digest: Digest32V2,
        ingressd_boot_id: BootIdV2,
        ingressd_identity: ServiceIdentityV2,
        expected_kernel_boot_id: BootIdV2,
        expected_kernel_identity: ServiceIdentityV2,
        maximum_sessions: usize,
        maximum_input_bytes: usize,
    ) -> Result<Self, IngressErrorV2> {
        if [
            installation_id.as_bytes(),
            active_state_manifest_digest.as_bytes(),
            ingressd_boot_id.as_bytes(),
            ingressd_identity.as_bytes(),
            expected_kernel_boot_id.as_bytes(),
            expected_kernel_identity.as_bytes(),
        ]
        .iter()
        .any(|value| is_zero(value))
            || maximum_sessions == 0
            || maximum_sessions > 65_536
            || maximum_input_bytes == 0
            || maximum_input_bytes > 8 * 1024 * 1024
        {
            return Err(IngressErrorV2::InvalidInput);
        }
        let mut capability_key = [0_u8; 32];
        getrandom::getrandom(&mut capability_key).map_err(|_| IngressErrorV2::AllocationFailure)?;
        if capability_key == [0; 32] {
            return Err(IngressErrorV2::AllocationFailure);
        }
        Ok(Self {
            installation_id,
            active_state_manifest_digest,
            ingressd_boot_id,
            ingressd_identity,
            expected_kernel_boot_id,
            expected_kernel_identity,
            maximum_sessions,
            maximum_input_bytes,
            accepted_time_floor_ms: 0,
            capability_key: Zeroizing::new(capability_key),
            consumed_authorizations: Vec::new(),
            tabs: Vec::new(),
        })
    }

    pub fn open_authenticated_tab(
        &mut self,
        authorization: VerifiedIngressUiAuthorizationV2,
        browser_context: IngressBrowserContextV2,
        now: UnixMillisV2,
    ) -> Result<IngressTabSessionCapabilityV2, IngressErrorV2> {
        self.accept_time(now)?;
        self.validate_browser_context(browser_context, now)?;
        if now.get() >= authorization.expires_at.get() {
            return Err(IngressErrorV2::Expired);
        }
        if self
            .consumed_authorizations
            .contains(&authorization.tab_binding_digest)
        {
            return Err(IngressErrorV2::AlreadyConsumed);
        }
        if self.tabs.len() >= self.maximum_sessions {
            return Err(IngressErrorV2::AllocationFailure);
        }
        let mut token = [0_u8; 32];
        let mut entropy = [0_u8; 32];
        getrandom::getrandom(&mut token).map_err(|_| IngressErrorV2::AllocationFailure)?;
        getrandom::getrandom(&mut entropy).map_err(|_| IngressErrorV2::AllocationFailure)?;
        if token == [0; 32] || entropy == [0; 32] {
            return Err(IngressErrorV2::AllocationFailure);
        }
        let tab_internal_id = domain_hash_many(
            b"SAVANA_INGRESS_TAB_INTERNAL_ID_V2\0",
            &[
                self.installation_id.as_bytes(),
                self.ingressd_boot_id.as_bytes(),
                authorization.tab_binding_digest.as_bytes(),
                &entropy,
            ],
        );
        let capability_digest = capability_digest(
            TAB_CAPABILITY_DOMAIN,
            self.installation_id,
            self.ingressd_boot_id,
            &token,
        );
        self.tabs
            .try_reserve(1)
            .map_err(|_| IngressErrorV2::AllocationFailure)?;
        self.consumed_authorizations
            .try_reserve(1)
            .map_err(|_| IngressErrorV2::AllocationFailure)?;
        self.tabs.push(IngressTabRecordV2 {
            capability_digest,
            tab_internal_id,
            browser_context,
            principal: authorization.principal,
            authentication_context_digest: authorization.authentication_context_digest,
            tab_binding_digest: authorization.tab_binding_digest,
            authorization_expires_at: authorization.expires_at,
            state: IngressStateV2::AwaitingBegin,
            session_internal_id: None,
            content_kind: None,
            declared_total_bytes: None,
            begin_declared_content_digest: None,
            cumulative_digest: None,
            finalized_content_digest: None,
            finalized_capability_digest: None,
            next_sequence: 0,
            content: Zeroizing::new(Vec::new()),
            chunks: Vec::new(),
            replay: Vec::new(),
        });
        self.consumed_authorizations
            .push(authorization.tab_binding_digest);
        Ok(IngressTabSessionCapabilityV2 {
            token,
            tab_internal_id,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn begin(
        &mut self,
        tab: &IngressTabSessionCapabilityV2,
        browser_context: IngressBrowserContextV2,
        client_request_nonce: Nonce32V2,
        content_kind: ContentKindV2,
        declared_total_bytes: u64,
        declared_content_digest: Option<Digest32V2>,
        now: UnixMillisV2,
    ) -> Result<IngressBeginAckV2, IngressErrorV2> {
        self.accept_time(now)?;
        if is_zero(client_request_nonce.as_bytes())
            || declared_total_bytes == 0
            || declared_total_bytes > self.maximum_input_bytes as u64
            || declared_content_digest.is_some_and(|digest| is_zero(digest.as_bytes()))
        {
            return Err(IngressErrorV2::InvalidInput);
        }
        let request_digest =
            begin_request_digest(content_kind, declared_total_bytes, declared_content_digest);
        let index = self.resolve_tab(tab, browser_context, now)?;
        if let Some(response) = replay_lookup(
            &self.tabs[index].replay,
            client_request_nonce,
            request_digest,
        )? {
            return match response {
                ReplayResponseV2::Begun(value) => Ok(value),
                _ => Err(IngressErrorV2::IdempotencyConflict),
            };
        }
        if self.tabs[index].state != IngressStateV2::AwaitingBegin {
            return Err(IngressErrorV2::StateConflict);
        }
        let mut entropy = [0_u8; 32];
        getrandom::getrandom(&mut entropy).map_err(|_| IngressErrorV2::AllocationFailure)?;
        if entropy == [0; 32] {
            return Err(IngressErrorV2::AllocationFailure);
        }
        let session_internal_id = domain_hash_many(
            SESSION_ID_DOMAIN,
            &[
                self.installation_id.as_bytes(),
                self.tabs[index].tab_internal_id.as_bytes(),
                &entropy,
            ],
        );
        let cumulative_digest = domain_hash_many(
            CHANNEL_BEGIN_DOMAIN,
            &[
                session_internal_id.as_bytes(),
                &content_kind.direct_channel_tag().to_be_bytes(),
            ],
        );
        let response = IngressBeginAckV2 { next_sequence: 0 };
        let record = &mut self.tabs[index];
        record.session_internal_id = Some(session_internal_id);
        record.content_kind = Some(content_kind);
        record.declared_total_bytes = Some(declared_total_bytes);
        record.begin_declared_content_digest = declared_content_digest;
        record.cumulative_digest = Some(cumulative_digest);
        record.state = IngressStateV2::Receiving;
        push_replay(
            record,
            ReplayRecordV2 {
                request_nonce: client_request_nonce,
                request_digest,
                response: ReplayResponseV2::Begun(response),
            },
        )?;
        Ok(response)
    }

    pub fn append(
        &mut self,
        tab: &IngressTabSessionCapabilityV2,
        browser_context: IngressBrowserContextV2,
        client_request_nonce: Nonce32V2,
        sequence: u32,
        chunk: Vec<u8>,
        now: UnixMillisV2,
    ) -> Result<IngressAppendAckV2, IngressErrorV2> {
        self.accept_time(now)?;
        if is_zero(client_request_nonce.as_bytes())
            || chunk.is_empty()
            || chunk.len() > MAX_CHUNK_BYTES
        {
            return Err(IngressErrorV2::InvalidInput);
        }
        let request_digest = append_request_digest(sequence, &chunk);
        let index = self.resolve_tab(tab, browser_context, now)?;
        if let Some(response) = replay_lookup(
            &self.tabs[index].replay,
            client_request_nonce,
            request_digest,
        )? {
            return match response {
                ReplayResponseV2::Appended(value) => Ok(value),
                _ => Err(IngressErrorV2::IdempotencyConflict),
            };
        }
        let record = &mut self.tabs[index];
        if record.state == IngressStateV2::FailedClosed {
            return Err(IngressErrorV2::FailedClosed);
        }
        if record.state != IngressStateV2::Receiving {
            return Err(IngressErrorV2::StateConflict);
        }
        if sequence < record.next_sequence {
            let existing = record
                .chunks
                .iter()
                .find(|accepted| accepted.sequence == sequence)
                .ok_or(IngressErrorV2::FailedClosed)?;
            let exact = record
                .content
                .get(existing.start..existing.start + existing.length)
                .is_some_and(|bytes| bytes == chunk)
                && existing.chunk_digest
                    == input_chunk_digest(
                        record
                            .session_internal_id
                            .ok_or(IngressErrorV2::FailedClosed)?,
                        record
                            .content_kind
                            .ok_or(IngressErrorV2::FailedClosed)?
                            .direct_channel_tag(),
                        sequence,
                        &chunk,
                    );
            if !exact {
                fail_closed(record);
                return Err(IngressErrorV2::FailedClosed);
            }
            let response = IngressAppendAckV2 {
                acknowledged_sequence: sequence,
                cumulative_digest: existing.cumulative_digest,
            };
            push_replay(
                record,
                ReplayRecordV2 {
                    request_nonce: client_request_nonce,
                    request_digest,
                    response: ReplayResponseV2::Appended(response),
                },
            )?;
            return Ok(response);
        }
        if sequence != record.next_sequence {
            return Err(IngressErrorV2::InvalidSequence);
        }
        let declared_total = record
            .declared_total_bytes
            .ok_or(IngressErrorV2::FailedClosed)?;
        let new_len = record
            .content
            .len()
            .checked_add(chunk.len())
            .ok_or(IngressErrorV2::InvalidInput)?;
        if new_len > self.maximum_input_bytes || new_len as u64 > declared_total {
            fail_closed(record);
            return Err(IngressErrorV2::DigestMismatch);
        }
        let session_internal_id = record
            .session_internal_id
            .ok_or(IngressErrorV2::FailedClosed)?;
        let content_kind = record.content_kind.ok_or(IngressErrorV2::FailedClosed)?;
        let prior_cumulative = record
            .cumulative_digest
            .ok_or(IngressErrorV2::FailedClosed)?;
        let chunk_digest = input_chunk_digest(
            session_internal_id,
            content_kind.direct_channel_tag(),
            sequence,
            &chunk,
        );
        let cumulative_digest = domain_hash_many(
            CHANNEL_STEP_DOMAIN,
            &[
                prior_cumulative.as_bytes(),
                &sequence.to_be_bytes(),
                chunk_digest.as_bytes(),
            ],
        );
        record
            .content
            .try_reserve(chunk.len())
            .map_err(|_| IngressErrorV2::AllocationFailure)?;
        record
            .chunks
            .try_reserve(1)
            .map_err(|_| IngressErrorV2::AllocationFailure)?;
        let start = record.content.len();
        record.content.extend_from_slice(&chunk);
        record.chunks.push(ChunkRecordV2 {
            sequence,
            start,
            length: chunk.len(),
            chunk_digest,
            cumulative_digest,
        });
        record.cumulative_digest = Some(cumulative_digest);
        record.next_sequence = record
            .next_sequence
            .checked_add(1)
            .ok_or(IngressErrorV2::FailedClosed)?;
        let response = IngressAppendAckV2 {
            acknowledged_sequence: sequence,
            cumulative_digest,
        };
        push_replay(
            record,
            ReplayRecordV2 {
                request_nonce: client_request_nonce,
                request_digest,
                response: ReplayResponseV2::Appended(response),
            },
        )?;
        Ok(response)
    }

    pub fn finalize(
        &mut self,
        tab: &IngressTabSessionCapabilityV2,
        browser_context: IngressBrowserContextV2,
        client_request_nonce: Nonce32V2,
        declared_content_digest: Digest32V2,
        now: UnixMillisV2,
    ) -> Result<FinalizedIngressV2, IngressErrorV2> {
        self.accept_time(now)?;
        if is_zero(client_request_nonce.as_bytes()) || is_zero(declared_content_digest.as_bytes()) {
            return Err(IngressErrorV2::InvalidInput);
        }
        let request_digest = domain_hash_many(
            REQUEST_DOMAIN,
            &[b"finalize", declared_content_digest.as_bytes()],
        );
        let index = self.resolve_tab(tab, browser_context, now)?;
        if let Some(response) = replay_lookup(
            &self.tabs[index].replay,
            client_request_nonce,
            request_digest,
        )? {
            return match response {
                ReplayResponseV2::Finalized(value) => Ok(value),
                _ => Err(IngressErrorV2::IdempotencyConflict),
            };
        }
        let record = &mut self.tabs[index];
        if record.state == IngressStateV2::FailedClosed {
            return Err(IngressErrorV2::FailedClosed);
        }
        if record.state != IngressStateV2::Receiving {
            return Err(IngressErrorV2::StateConflict);
        }
        if record.content_kind == Some(ContentKindV2::ParsedDocument) {
            return Err(IngressErrorV2::ParserEvidenceRequired);
        }
        let actual_digest = Digest32V2::new(Sha256::digest(record.content.as_slice()).into());
        let declared_total = record
            .declared_total_bytes
            .ok_or(IngressErrorV2::FailedClosed)?;
        if record.content.is_empty()
            || record.content.len() as u64 != declared_total
            || actual_digest != declared_content_digest
            || record
                .begin_declared_content_digest
                .is_some_and(|digest| digest != actual_digest)
        {
            fail_closed(record);
            return Err(IngressErrorV2::DigestMismatch);
        }
        let session_internal_id = record
            .session_internal_id
            .ok_or(IngressErrorV2::FailedClosed)?;
        let token = derive_capability(
            &self.capability_key,
            FINALIZED_CAPABILITY_DOMAIN,
            self.installation_id,
            self.ingressd_boot_id,
            session_internal_id,
            actual_digest,
        )?;
        let finalized = FinalizedIngressV2 {
            token,
            session_internal_id,
        };
        record.finalized_content_digest = Some(actual_digest);
        record.finalized_capability_digest = Some(capability_digest(
            FINALIZED_CAPABILITY_DOMAIN,
            self.installation_id,
            self.ingressd_boot_id,
            &token,
        ));
        record.state = IngressStateV2::Finalized;
        push_replay(
            record,
            ReplayRecordV2 {
                request_nonce: client_request_nonce,
                request_digest,
                response: ReplayResponseV2::Finalized(finalized),
            },
        )?;
        Ok(finalized)
    }

    pub fn consume_for_kernel(
        &mut self,
        finalized: FinalizedIngressV2,
        receiver: AuthenticatedKernelIngressReceiverV2,
        now: UnixMillisV2,
    ) -> Result<IngressKernelTransferV2, IngressErrorV2> {
        self.accept_time(now)?;
        if receiver.kernel_boot_id != self.expected_kernel_boot_id
            || receiver.kernel_identity != self.expected_kernel_identity
            || now.get() >= receiver.expires_at.get()
        {
            return Err(IngressErrorV2::InvalidCapability);
        }
        let expected_capability = capability_digest(
            FINALIZED_CAPABILITY_DOMAIN,
            self.installation_id,
            self.ingressd_boot_id,
            &finalized.token,
        );
        let record = self
            .tabs
            .iter_mut()
            .find(|record| {
                record.session_internal_id == Some(finalized.session_internal_id)
                    && record.finalized_capability_digest == Some(expected_capability)
            })
            .ok_or(IngressErrorV2::InvalidCapability)?;
        match record.state {
            IngressStateV2::Finalized => {}
            IngressStateV2::Transferred => return Err(IngressErrorV2::AlreadyConsumed),
            IngressStateV2::Expired => return Err(IngressErrorV2::Expired),
            IngressStateV2::FailedClosed => return Err(IngressErrorV2::FailedClosed),
            _ => return Err(IngressErrorV2::StateConflict),
        }
        let content = std::mem::replace(&mut record.content, Zeroizing::new(Vec::new()));
        let transfer = IngressKernelTransferV2 {
            installation_id: self.installation_id,
            active_state_manifest_digest: self.active_state_manifest_digest,
            principal: record.principal,
            authentication_context_digest: record.authentication_context_digest,
            tab_binding_digest: record.tab_binding_digest,
            content_kind: record.content_kind.ok_or(IngressErrorV2::FailedClosed)?,
            declared_content_digest: record
                .finalized_content_digest
                .ok_or(IngressErrorV2::FailedClosed)?,
            cumulative_digest: record
                .cumulative_digest
                .ok_or(IngressErrorV2::FailedClosed)?,
            content,
        };
        record.state = IngressStateV2::Transferred;
        record.chunks.clear();
        Ok(transfer)
    }

    pub fn abort(
        &mut self,
        tab: &IngressTabSessionCapabilityV2,
        browser_context: IngressBrowserContextV2,
        client_request_nonce: Nonce32V2,
        now: UnixMillisV2,
    ) -> Result<IngressPublicStateV2, IngressErrorV2> {
        self.accept_time(now)?;
        if is_zero(client_request_nonce.as_bytes()) {
            return Err(IngressErrorV2::InvalidInput);
        }
        let request_digest = domain_hash_many(REQUEST_DOMAIN, &[b"abort"]);
        let index = self.resolve_tab(tab, browser_context, now)?;
        if let Some(response) = replay_lookup(
            &self.tabs[index].replay,
            client_request_nonce,
            request_digest,
        )? {
            return match response {
                ReplayResponseV2::Aborted => Ok(IngressPublicStateV2::Aborted),
                _ => Err(IngressErrorV2::IdempotencyConflict),
            };
        }
        let record = &mut self.tabs[index];
        match record.state {
            IngressStateV2::AwaitingBegin
            | IngressStateV2::Receiving
            | IngressStateV2::FailedClosed => {
                record.state = IngressStateV2::Aborted;
                clear_content(record);
                push_replay(
                    record,
                    ReplayRecordV2 {
                        request_nonce: client_request_nonce,
                        request_digest,
                        response: ReplayResponseV2::Aborted,
                    },
                )?;
                Ok(IngressPublicStateV2::Aborted)
            }
            IngressStateV2::Aborted => Ok(IngressPublicStateV2::Aborted),
            IngressStateV2::Expired => Err(IngressErrorV2::Expired),
            _ => Err(IngressErrorV2::StateConflict),
        }
    }

    pub fn state(
        &mut self,
        tab: &IngressTabSessionCapabilityV2,
        browser_context: IngressBrowserContextV2,
        now: UnixMillisV2,
    ) -> Result<IngressPublicStateV2, IngressErrorV2> {
        self.accept_time(now)?;
        let index = self.resolve_tab(tab, browser_context, now)?;
        expire_if_needed(&mut self.tabs[index], now);
        Ok(self.tabs[index].state.public())
    }

    fn accept_time(&mut self, now: UnixMillisV2) -> Result<(), IngressErrorV2> {
        if now.get() == 0 || now.get() < self.accepted_time_floor_ms {
            return Err(IngressErrorV2::ClockRollback);
        }
        self.accepted_time_floor_ms = now.get();
        Ok(())
    }

    fn validate_browser_context(
        &self,
        browser_context: IngressBrowserContextV2,
        now: UnixMillisV2,
    ) -> Result<(), IngressErrorV2> {
        if browser_context.ingressd_boot_id != self.ingressd_boot_id
            || now.get() >= browser_context.expires_at.get()
        {
            return Err(IngressErrorV2::InvalidCapability);
        }
        Ok(())
    }

    fn resolve_tab(
        &mut self,
        tab: &IngressTabSessionCapabilityV2,
        browser_context: IngressBrowserContextV2,
        now: UnixMillisV2,
    ) -> Result<usize, IngressErrorV2> {
        self.validate_browser_context(browser_context, now)?;
        let capability_digest = capability_digest(
            TAB_CAPABILITY_DOMAIN,
            self.installation_id,
            self.ingressd_boot_id,
            &tab.token,
        );
        let index = self
            .tabs
            .iter()
            .position(|record| {
                record.capability_digest == capability_digest
                    && record.tab_internal_id == tab.tab_internal_id
                    && record.browser_context == browser_context
            })
            .ok_or(IngressErrorV2::InvalidCapability)?;
        expire_if_needed(&mut self.tabs[index], now);
        if self.tabs[index].state == IngressStateV2::Expired {
            return Err(IngressErrorV2::Expired);
        }
        Ok(index)
    }
}

fn replay_lookup(
    records: &[ReplayRecordV2],
    request_nonce: Nonce32V2,
    request_digest: Digest32V2,
) -> Result<Option<ReplayResponseV2>, IngressErrorV2> {
    let Some(record) = records
        .iter()
        .find(|record| record.request_nonce == request_nonce)
    else {
        return Ok(None);
    };
    if record.request_digest != request_digest {
        return Err(IngressErrorV2::IdempotencyConflict);
    }
    Ok(Some(record.response))
}

fn push_replay(
    record: &mut IngressTabRecordV2,
    replay: ReplayRecordV2,
) -> Result<(), IngressErrorV2> {
    if record.replay.len() >= MAX_REPLAY_RECORDS {
        fail_closed(record);
        return Err(IngressErrorV2::FailedClosed);
    }
    record
        .replay
        .try_reserve(1)
        .map_err(|_| IngressErrorV2::AllocationFailure)?;
    record.replay.push(replay);
    Ok(())
}

fn begin_request_digest(
    content_kind: ContentKindV2,
    declared_total_bytes: u64,
    declared_content_digest: Option<Digest32V2>,
) -> Digest32V2 {
    let optional = declared_content_digest.unwrap_or(Digest32V2::new([0; 32]));
    domain_hash_many(
        REQUEST_DOMAIN,
        &[
            b"begin",
            &content_kind.tag().to_be_bytes(),
            &declared_total_bytes.to_be_bytes(),
            optional.as_bytes(),
        ],
    )
}

fn append_request_digest(sequence: u32, chunk: &[u8]) -> Digest32V2 {
    domain_hash_many(
        REQUEST_DOMAIN,
        &[
            b"append",
            &sequence.to_be_bytes(),
            &(chunk.len() as u64).to_be_bytes(),
            chunk,
        ],
    )
}

fn input_chunk_digest(
    session_internal_id: Digest32V2,
    channel_tag: u16,
    sequence: u32,
    chunk: &[u8],
) -> Digest32V2 {
    domain_hash_many(
        CHUNK_DOMAIN,
        &[
            session_internal_id.as_bytes(),
            &channel_tag.to_be_bytes(),
            &sequence.to_be_bytes(),
            &(chunk.len() as u32).to_be_bytes(),
            chunk,
        ],
    )
}

fn capability_digest(
    domain: &[u8],
    installation_id: Digest32V2,
    boot_id: BootIdV2,
    token: &[u8; 32],
) -> Digest32V2 {
    domain_hash_many(
        domain,
        &[installation_id.as_bytes(), boot_id.as_bytes(), token],
    )
}

fn derive_capability(
    key: &[u8; 32],
    kind: &[u8],
    installation_id: Digest32V2,
    boot_id: BootIdV2,
    stable_id: Digest32V2,
    binding_digest: Digest32V2,
) -> Result<[u8; 32], IngressErrorV2> {
    let mut mac =
        <Hmac<Sha256>>::new_from_slice(key).map_err(|_| IngressErrorV2::AllocationFailure)?;
    mac.update(CAPABILITY_DERIVATION_DOMAIN);
    mac.update(kind);
    mac.update(installation_id.as_bytes());
    mac.update(boot_id.as_bytes());
    mac.update(stable_id.as_bytes());
    mac.update(binding_digest.as_bytes());
    let token: [u8; 32] = mac.finalize().into_bytes().into();
    if token == [0; 32] {
        return Err(IngressErrorV2::AllocationFailure);
    }
    Ok(token)
}

fn domain_hash_many(domain: &[u8], fields: &[&[u8]]) -> Digest32V2 {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    for field in fields {
        hasher.update(field);
    }
    Digest32V2::new(hasher.finalize().into())
}

fn expire_if_needed(record: &mut IngressTabRecordV2, now: UnixMillisV2) {
    let expires_at = record
        .authorization_expires_at
        .get()
        .min(record.browser_context.expires_at.get());
    if now.get() >= expires_at && !record.state.terminal() {
        record.state = IngressStateV2::Expired;
        clear_content(record);
    }
}

fn fail_closed(record: &mut IngressTabRecordV2) {
    record.state = IngressStateV2::FailedClosed;
    clear_content(record);
}

fn clear_content(record: &mut IngressTabRecordV2) {
    record.content = Zeroizing::new(Vec::new());
    record.chunks.clear();
}

fn is_zero(bytes: &[u8; 32]) -> bool {
    bytes == &[0; 32]
}

#[cfg(test)]
mod tests {
    use savana_kernel_protocol::v2::{
        BootIdV2, Digest32V2, Nonce32V2, PrincipalIdV2, ServiceIdentityV2, UnixMillisV2,
    };
    use sha2::{Digest as _, Sha256};

    use super::*;

    fn service() -> IngressServiceV2 {
        IngressServiceV2::from_verified_deployment(
            Digest32V2::new([1; 32]),
            Digest32V2::new([2; 32]),
            BootIdV2::new([3; 32]),
            ServiceIdentityV2::new([4; 32]),
            BootIdV2::new([13; 32]),
            ServiceIdentityV2::new([14; 32]),
            128,
            1024 * 1024,
        )
        .unwrap()
    }

    fn browser(peer: u8) -> IngressBrowserContextV2 {
        IngressBrowserContextV2::from_authenticated_origin(
            BootIdV2::new([3; 32]),
            Digest32V2::new([peer; 32]),
            UnixMillisV2::new(10_000),
        )
        .unwrap()
    }

    fn authorization() -> VerifiedIngressUiAuthorizationV2 {
        VerifiedIngressUiAuthorizationV2::new_for_test(
            PrincipalIdV2::new([6; 32]),
            Digest32V2::new([7; 32]),
            Digest32V2::new([8; 32]),
            UnixMillisV2::new(5_000),
        )
    }

    #[test]
    fn authenticated_tab_accepts_exact_order_and_byte_identical_replay() {
        let mut service = service();
        let tab = service
            .open_authenticated_tab(authorization(), browser(9), UnixMillisV2::new(100))
            .unwrap();
        let content = b"hello secure ingress";
        let declared = Digest32V2::new(Sha256::digest(content).into());
        let begun = service
            .begin(
                &tab,
                browser(9),
                Nonce32V2::new([10; 32]),
                ContentKindV2::ChatText,
                content.len() as u64,
                Some(declared),
                UnixMillisV2::new(101),
            )
            .unwrap();
        assert_eq!(begun.next_sequence(), 0);

        let first = service
            .append(
                &tab,
                browser(9),
                Nonce32V2::new([11; 32]),
                0,
                content.to_vec(),
                UnixMillisV2::new(102),
            )
            .unwrap();
        let replay = service
            .append(
                &tab,
                browser(9),
                Nonce32V2::new([11; 32]),
                0,
                content.to_vec(),
                UnixMillisV2::new(103),
            )
            .unwrap();
        assert_eq!(first, replay);
        assert_eq!(first.acknowledged_sequence(), 0);
        assert_ne!(first.cumulative_digest(), Digest32V2::new([0; 32]));

        let finalized = service
            .finalize(
                &tab,
                browser(9),
                Nonce32V2::new([12; 32]),
                declared,
                UnixMillisV2::new(104),
            )
            .unwrap();
        let receiver = AuthenticatedKernelIngressReceiverV2::new_for_test(
            BootIdV2::new([13; 32]),
            ServiceIdentityV2::new([14; 32]),
            UnixMillisV2::new(1_000),
        );
        let transfer = service
            .consume_for_kernel(finalized, receiver, UnixMillisV2::new(105))
            .unwrap();
        assert_eq!(transfer.content_kind(), ContentKindV2::ChatText);
        assert_eq!(transfer.principal(), PrincipalIdV2::new([6; 32]));
        assert_eq!(transfer.into_zeroizing_bytes().as_slice(), content);
        assert!(matches!(
            service.consume_for_kernel(finalized, receiver, UnixMillisV2::new(106)),
            Err(IngressErrorV2::AlreadyConsumed)
        ));
    }

    #[test]
    fn tab_peer_sequence_and_replay_confusion_fail_closed() {
        let mut service = service();
        let tab = service
            .open_authenticated_tab(authorization(), browser(9), UnixMillisV2::new(200))
            .unwrap();
        service
            .begin(
                &tab,
                browser(9),
                Nonce32V2::new([20; 32]),
                ContentKindV2::PlainText,
                3,
                None,
                UnixMillisV2::new(201),
            )
            .unwrap();
        assert_eq!(
            service.append(
                &tab,
                browser(10),
                Nonce32V2::new([21; 32]),
                0,
                b"abc".to_vec(),
                UnixMillisV2::new(202),
            ),
            Err(IngressErrorV2::InvalidCapability)
        );
        assert_eq!(
            service.append(
                &tab,
                browser(9),
                Nonce32V2::new([22; 32]),
                1,
                b"abc".to_vec(),
                UnixMillisV2::new(202),
            ),
            Err(IngressErrorV2::InvalidSequence)
        );
        service
            .append(
                &tab,
                browser(9),
                Nonce32V2::new([23; 32]),
                0,
                b"abc".to_vec(),
                UnixMillisV2::new(203),
            )
            .unwrap();
        assert_eq!(
            service.append(
                &tab,
                browser(9),
                Nonce32V2::new([23; 32]),
                0,
                b"abd".to_vec(),
                UnixMillisV2::new(204),
            ),
            Err(IngressErrorV2::IdempotencyConflict)
        );
        assert_eq!(
            service.append(
                &tab,
                browser(9),
                Nonce32V2::new([24; 32]),
                0,
                b"abd".to_vec(),
                UnixMillisV2::new(205),
            ),
            Err(IngressErrorV2::FailedClosed)
        );
        assert_eq!(
            service.state(&tab, browser(9), UnixMillisV2::new(206)),
            Ok(IngressPublicStateV2::FailedClosed)
        );
    }

    #[test]
    fn declared_digest_parsed_document_and_abort_rules_are_closed() {
        let mut digest_mismatch = service();
        let tab = digest_mismatch
            .open_authenticated_tab(authorization(), browser(9), UnixMillisV2::new(300))
            .unwrap();
        digest_mismatch
            .begin(
                &tab,
                browser(9),
                Nonce32V2::new([30; 32]),
                ContentKindV2::ChatText,
                3,
                Some(Digest32V2::new([31; 32])),
                UnixMillisV2::new(301),
            )
            .unwrap();
        digest_mismatch
            .append(
                &tab,
                browser(9),
                Nonce32V2::new([32; 32]),
                0,
                b"abc".to_vec(),
                UnixMillisV2::new(302),
            )
            .unwrap();
        assert_eq!(
            digest_mismatch.finalize(
                &tab,
                browser(9),
                Nonce32V2::new([33; 32]),
                Digest32V2::new(Sha256::digest(b"abc").into()),
                UnixMillisV2::new(303),
            ),
            Err(IngressErrorV2::DigestMismatch)
        );

        let mut parsed = service();
        let tab = parsed
            .open_authenticated_tab(authorization(), browser(9), UnixMillisV2::new(310))
            .unwrap();
        parsed
            .begin(
                &tab,
                browser(9),
                Nonce32V2::new([34; 32]),
                ContentKindV2::ParsedDocument,
                3,
                None,
                UnixMillisV2::new(311),
            )
            .unwrap();
        parsed
            .append(
                &tab,
                browser(9),
                Nonce32V2::new([35; 32]),
                0,
                b"pdf".to_vec(),
                UnixMillisV2::new(312),
            )
            .unwrap();
        assert_eq!(
            parsed.finalize(
                &tab,
                browser(9),
                Nonce32V2::new([36; 32]),
                Digest32V2::new(Sha256::digest(b"pdf").into()),
                UnixMillisV2::new(313),
            ),
            Err(IngressErrorV2::ParserEvidenceRequired)
        );
        assert_eq!(
            parsed
                .abort(
                    &tab,
                    browser(9),
                    Nonce32V2::new([37; 32]),
                    UnixMillisV2::new(314),
                )
                .unwrap(),
            IngressPublicStateV2::Aborted
        );
    }
}
