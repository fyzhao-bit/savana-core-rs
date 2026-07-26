#[cfg(test)]
use std::sync::atomic::{AtomicU8, Ordering as AtomicOrdering};
use std::sync::Mutex;

use ed25519_dalek::{Signature, VerifyingKey};
use savana_kernel_protocol::{
    BootId, ClientFinishV1, ClientHelloV1, ClientId, Digest32, HandshakeAcceptedV1,
    HandshakeTranscriptV1, KeyId, Nonce32, ProtocolVersion, RequestedMode, ServerIdentityV1,
    SignedServerHelloV1, StableCode, UnixMillis, PROTOCOL_MAJOR, PROTOCOL_MINOR,
};
use savana_policy_core::InstallationClientRoleV1;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::peer::PeerIdentity;
use crate::state::ReplayState;
#[cfg(test)]
use crate::state::ReplayStatus;
use crate::{DaemonConfig, DaemonSigningIdentity};

const PENDING_WINDOW_MS: u64 = 5_000;
const MAXIMUM_CLIENTS: usize = 16;
const CLIENT_FINISH_DOMAIN: &[u8] = b"SAVANA_CLIENT_FINISH_V1\0";

#[derive(Clone)]
struct ConfiguredClient {
    client_id: ClientId,
    key_id: KeyId,
    public_key: [u8; 32],
    role: InstallationClientRoleV1,
    peer_uid: u32,
    peer_gid: u32,
}

#[derive(Clone)]
struct RuntimeIdentity {
    protocol_major: u16,
    minimum_minor: u16,
    maximum_minor: u16,
    daemon_key_id: KeyId,
    daemon_public_key: [u8; 32],
    clients: Box<[ConfiguredClient]>,
    release_digest: Digest32,
    policy_digest: Digest32,
    policy_version: u64,
    model_manifest_digest: Digest32,
    approval_key_set_digest: Digest32,
    resource_profile_digest: Digest32,
    release_expires_at: UnixMillis,
    policy_expires_at: UnixMillis,
}

impl RuntimeIdentity {
    fn from_config(config: &DaemonConfig) -> Self {
        let clients = config
            .daemon_clients()
            .iter()
            .map(|client| ConfiguredClient {
                client_id: client.client_id().clone(),
                key_id: client.key_id().clone(),
                public_key: *client.public_key(),
                role: client.role(),
                peer_uid: client.peer_uid(),
                peer_gid: client.peer_gid(),
            })
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Self {
            protocol_major: config.protocol_major(),
            minimum_minor: config.minimum_minor(),
            maximum_minor: config.maximum_minor(),
            daemon_key_id: config.daemon_identity().key_id().clone(),
            daemon_public_key: *config.daemon_identity().public_key(),
            clients,
            release_digest: config.release_digest(),
            policy_digest: config.policy_digest(),
            policy_version: config.policy_version(),
            model_manifest_digest: config.model_manifest_digest(),
            approval_key_set_digest: config.approval_key_set_digest(),
            resource_profile_digest: config.resource_profile_digest(),
            release_expires_at: config.release_expires_at(),
            policy_expires_at: config.policy_expires_at(),
        }
    }

    fn server_identity(
        &self,
        boot_id: BootId,
        protocol: ProtocolVersion,
    ) -> Result<ServerIdentityV1, StableCode> {
        if protocol != ProtocolVersion::new(PROTOCOL_MAJOR, PROTOCOL_MINOR)
            || protocol.major != self.protocol_major
            || protocol.minor < self.minimum_minor
            || protocol.minor > self.maximum_minor
        {
            return Err(StableCode::ProtocolUnsupportedVersion);
        }
        Ok(ServerIdentityV1 {
            daemon_key_id: self.daemon_key_id.clone(),
            boot_id,
            protocol,
            release_digest: self.release_digest,
            policy_digest: self.policy_digest,
            policy_version: self.policy_version,
            model_manifest_digest: self.model_manifest_digest,
            approval_key_set_digest: self.approval_key_set_digest,
            resource_profile_digest: self.resource_profile_digest,
        })
    }

    fn validate_time(&self, now: UnixMillis) -> Result<(), StableCode> {
        if now.get() >= self.release_expires_at.get() {
            return Err(StableCode::IdentityReleaseMismatch);
        }
        if now.get() >= self.policy_expires_at.get() {
            return Err(StableCode::PolicyExpired);
        }
        Ok(())
    }
}

trait EntropySource: Send + Sync {
    fn fill_32(&self, output: &mut [u8; 32]) -> Result<(), ()>;
}

struct SystemEntropy;

impl EntropySource for SystemEntropy {
    fn fill_32(&self, output: &mut [u8; 32]) -> Result<(), ()> {
        getrandom::getrandom(output).map_err(|_| ())
    }
}

#[cfg(test)]
struct TransportTestEntropy {
    next: AtomicU8,
}

#[cfg(test)]
impl TransportTestEntropy {
    const fn new() -> Self {
        Self {
            next: AtomicU8::new(0x31),
        }
    }
}

#[cfg(test)]
impl EntropySource for TransportTestEntropy {
    fn fill_32(&self, output: &mut [u8; 32]) -> Result<(), ()> {
        let value = self.next.fetch_add(1, AtomicOrdering::AcqRel);
        if value == 0 {
            return Err(());
        }
        output.fill(value);
        Ok(())
    }
}

pub(crate) struct HandshakeService {
    runtime: RuntimeIdentity,
    signing_identity: DaemonSigningIdentity,
    boot_id: BootId,
    entropy: Box<dyn EntropySource>,
    state: Mutex<ReplayState>,
}

impl std::fmt::Debug for HandshakeService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("HandshakeService(<private>)")
    }
}

pub(crate) struct PendingHandshake {
    client_index: usize,
    partition_index: usize,
    slot_index: usize,
    peer: PeerIdentity,
    transcript: HandshakeTranscriptV1,
    transcript_digest: Digest32,
    expires_at: UnixMillis,
}

impl std::fmt::Debug for PendingHandshake {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PendingHandshake(<private>)")
    }
}

pub(crate) struct ConnectionContext {
    capability: Zeroizing<[u8; 32]>,
    client_id: ClientId,
    peer: PeerIdentity,
    boot_id: BootId,
    protocol: ProtocolVersion,
    mode: RequestedMode,
    expires_at: UnixMillis,
}

impl std::fmt::Debug for ConnectionContext {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ConnectionContext(<authenticated>)")
    }
}

impl ConnectionContext {
    pub(crate) fn client_id(&self) -> &ClientId {
        &self.client_id
    }

    pub(crate) const fn peer(&self) -> &PeerIdentity {
        &self.peer
    }

    pub(crate) const fn protocol(&self) -> ProtocolVersion {
        self.protocol
    }

    pub(crate) const fn mode(&self) -> RequestedMode {
        self.mode
    }

    pub(crate) const fn expires_at(&self) -> UnixMillis {
        self.expires_at
    }

    pub(crate) fn accepted(&self) -> HandshakeAcceptedV1 {
        HandshakeAcceptedV1 {
            boot_id: self.boot_id,
            protocol: self.protocol,
        }
    }
}

impl HandshakeService {
    pub(crate) fn new(
        config: &DaemonConfig,
        signing_identity: DaemonSigningIdentity,
        startup_now: UnixMillis,
    ) -> Result<Self, StableCode> {
        let service = Self::new_inner(
            RuntimeIdentity::from_config(config),
            signing_identity,
            startup_now,
            Box::new(SystemEntropy),
        )?;
        config
            .server_identity(
                &service.signing_identity,
                service.boot_id,
                ProtocolVersion::new(PROTOCOL_MAJOR, PROTOCOL_MINOR),
            )
            .map_err(|error| error.code())?;
        Ok(service)
    }

    pub(crate) fn refresh_before_bind(&self, now: UnixMillis) -> Result<(), StableCode> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| StableCode::KernelUnavailable)?;
        state.observe(now)?;
        self.runtime.validate_time(now)
    }

    pub(crate) fn started_identity(&self) -> Result<ServerIdentityV1, StableCode> {
        self.runtime.server_identity(
            self.boot_id,
            ProtocolVersion::new(PROTOCOL_MAJOR, PROTOCOL_MINOR),
        )
    }

    fn new_inner(
        runtime: RuntimeIdentity,
        signing_identity: DaemonSigningIdentity,
        startup_now: UnixMillis,
        entropy: Box<dyn EntropySource>,
    ) -> Result<Self, StableCode> {
        if !(1..=MAXIMUM_CLIENTS).contains(&runtime.clients.len())
            || signing_identity.public_key() != runtime.daemon_public_key
        {
            return Err(StableCode::IdentityKeyPermissions);
        }
        let boot_id = BootId::new(nonzero_entropy(entropy.as_ref())?);
        let state = Mutex::new(ReplayState::new(runtime.clients.len(), startup_now));
        Ok(Self {
            runtime,
            signing_identity,
            boot_id,
            entropy,
            state,
        })
    }

    #[cfg(test)]
    pub(crate) fn new_for_transport_test(
        client_public_key: [u8; 32],
        peer: PeerIdentity,
        startup_now: UnixMillis,
        expires_at: UnixMillis,
    ) -> Result<Self, StableCode> {
        Self::new_for_transport_test_with_expiries(
            client_public_key,
            peer,
            startup_now,
            expires_at,
            expires_at,
        )
    }

    #[cfg(test)]
    pub(crate) fn new_for_transport_test_with_expiries(
        client_public_key: [u8; 32],
        peer: PeerIdentity,
        startup_now: UnixMillis,
        release_expires_at: UnixMillis,
        policy_expires_at: UnixMillis,
    ) -> Result<Self, StableCode> {
        let daemon_key = ed25519_dalek::SigningKey::from_bytes(&[0x61; 32]);
        let runtime = RuntimeIdentity {
            protocol_major: PROTOCOL_MAJOR,
            minimum_minor: PROTOCOL_MINOR,
            maximum_minor: PROTOCOL_MINOR,
            daemon_key_id: KeyId::try_from("transport-daemon-key")
                .map_err(|_| StableCode::KernelUnavailable)?,
            daemon_public_key: daemon_key.verifying_key().to_bytes(),
            clients: vec![ConfiguredClient {
                client_id: ClientId::try_from("transport-client")
                    .map_err(|_| StableCode::KernelUnavailable)?,
                key_id: KeyId::try_from("transport-client-key")
                    .map_err(|_| StableCode::KernelUnavailable)?,
                public_key: client_public_key,
                role: InstallationClientRoleV1::JarvisKernelClient,
                peer_uid: peer.uid(),
                peer_gid: peer.gid(),
            }]
            .into_boxed_slice(),
            release_digest: Digest32::new([0x81; 32]),
            policy_digest: Digest32::new([0x82; 32]),
            policy_version: 7,
            model_manifest_digest: Digest32::new([0x83; 32]),
            approval_key_set_digest: Digest32::new([0x84; 32]),
            resource_profile_digest: Digest32::new([0x85; 32]),
            release_expires_at,
            policy_expires_at,
        };
        Self::new_inner(
            runtime,
            DaemonSigningIdentity::from_seed_for_test([0x61; 32]),
            startup_now,
            Box::new(TransportTestEntropy::new()),
        )
    }

    pub(crate) fn preauthorize_peer(&self, peer: &PeerIdentity) -> Result<(), StableCode> {
        if self
            .runtime
            .clients
            .iter()
            .any(|client| client.peer_uid == peer.uid() && client.peer_gid == peer.gid())
        {
            Ok(())
        } else {
            Err(StableCode::IdentityPeerRejected)
        }
    }

    #[cfg(test)]
    fn new_with_entropy_for_test(
        runtime: RuntimeIdentity,
        signing_identity: DaemonSigningIdentity,
        startup_now: UnixMillis,
        entropy: Box<dyn EntropySource>,
    ) -> Result<Self, StableCode> {
        Self::new_inner(runtime, signing_identity, startup_now, entropy)
    }

    pub(crate) fn start(
        &self,
        peer: &PeerIdentity,
        hello: ClientHelloV1,
        now: UnixMillis,
    ) -> Result<(PendingHandshake, SignedServerHelloV1), StableCode> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| StableCode::KernelUnavailable)?;
        state.observe(now)?;
        let expires_at = UnixMillis::new(
            now.get()
                .checked_add(PENDING_WINDOW_MS)
                .ok_or(StableCode::KernelUnavailable)?,
        );
        self.runtime.validate_time(now)?;
        validate_hello(&hello)?;
        let protocol = negotiate_version(&self.runtime, &hello.supported_versions)?;
        let client_index = resolve_client(&self.runtime, &hello)?;
        let client = &self.runtime.clients[client_index];
        verify_peer(client, peer)?;
        let slot_index = state.reserve_slot(client_index, hello.client_nonce, now)?;

        let server_nonce = Nonce32::new(nonzero_entropy(self.entropy.as_ref())?);
        let transcript = HandshakeTranscriptV1 {
            client: hello,
            server_nonce,
            server: self.runtime.server_identity(self.boot_id, protocol)?,
        };
        let digest = transcript_digest(&transcript)?;
        let signature = self
            .signing_identity
            .sign_daemon_hello(&transcript)
            .map_err(|error| error.code())?;
        let signed_hello = SignedServerHelloV1 {
            transcript: transcript.clone(),
            signature,
        };
        let pending = PendingHandshake {
            client_index,
            partition_index: client_index,
            slot_index,
            peer: *peer,
            transcript: transcript.clone(),
            transcript_digest: digest,
            expires_at,
        };
        state.commit_pending(
            client_index,
            slot_index,
            pending.transcript.client.client_nonce,
            digest,
            expires_at,
        )?;
        Ok((pending, signed_hello))
    }

    pub(crate) fn finish(
        &self,
        peer: &PeerIdentity,
        pending: PendingHandshake,
        finish: ClientFinishV1,
        now: UnixMillis,
    ) -> Result<ConnectionContext, StableCode> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| StableCode::KernelUnavailable)?;
        state.observe(now)?;
        self.runtime.validate_time(now)?;
        if *peer != pending.peer {
            return Err(StableCode::IdentityPeerRejected);
        }
        if now.get() >= pending.expires_at.get() {
            return Err(StableCode::DeadlineExceeded);
        }
        let client = self.validate_pending_identity(&pending)?;
        state.validate_pending(
            pending.partition_index,
            pending.slot_index,
            pending.transcript.client.client_nonce,
            pending.transcript_digest,
            pending.expires_at,
        )?;
        if finish.transcript_digest != pending.transcript_digest {
            return Err(StableCode::IdentityTranscriptMismatch);
        }
        verify_client_finish(client, &finish)?;
        let capability = nonzero_capability(self.entropy.as_ref())?;
        let context = ConnectionContext {
            capability,
            client_id: client.client_id.clone(),
            peer: pending.peer,
            boot_id: self.boot_id,
            protocol: pending.transcript.server.protocol,
            mode: pending.transcript.client.requested_mode,
            expires_at: UnixMillis::new(
                self.runtime
                    .release_expires_at
                    .get()
                    .min(self.runtime.policy_expires_at.get()),
            ),
        };
        state.mark_finished(pending.partition_index, pending.slot_index)?;
        Ok(context)
    }

    pub(crate) fn validate_context_identity(
        &self,
        context: &ConnectionContext,
        now: UnixMillis,
    ) -> Result<ServerIdentityV1, StableCode> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| StableCode::KernelUnavailable)?;
        state.observe(now)?;
        self.runtime.validate_time(now)?;

        let expected_expiry = UnixMillis::new(
            self.runtime
                .release_expires_at
                .get()
                .min(self.runtime.policy_expires_at.get()),
        );
        let configured_client = self.runtime.clients.iter().any(|client| {
            client.client_id == context.client_id
                && client.peer_uid == context.peer.uid()
                && client.peer_gid == context.peer.gid()
        });
        match context.mode {
            RequestedMode::Required | RequestedMode::Shadow => {}
        }
        if context.boot_id != self.boot_id
            || context.protocol != ProtocolVersion::new(PROTOCOL_MAJOR, PROTOCOL_MINOR)
            || context.expires_at != expected_expiry
            || !configured_client
        {
            return Err(StableCode::IdentityTranscriptMismatch);
        }
        self.runtime.server_identity(self.boot_id, context.protocol)
    }

    fn validate_pending_identity(
        &self,
        pending: &PendingHandshake,
    ) -> Result<&ConfiguredClient, StableCode> {
        if pending.partition_index != pending.client_index {
            return Err(StableCode::IdentityTranscriptMismatch);
        }
        let client = self
            .runtime
            .clients
            .get(pending.client_index)
            .ok_or(StableCode::IdentityTranscriptMismatch)?;
        let negotiated_protocol =
            negotiate_version(&self.runtime, &pending.transcript.client.supported_versions)
                .map_err(|_| StableCode::IdentityTranscriptMismatch)?;
        if pending.transcript.server.protocol != negotiated_protocol {
            return Err(StableCode::IdentityTranscriptMismatch);
        }
        let expected_server = self
            .runtime
            .server_identity(self.boot_id, negotiated_protocol)
            .map_err(|_| StableCode::IdentityTranscriptMismatch)?;
        if pending.transcript.client.client_id != client.client_id
            || pending.transcript.client.client_key_id != client.key_id
            || pending.transcript.client.client_nonce.as_bytes() == &[0; 32]
            || pending.transcript.server_nonce.as_bytes() == &[0; 32]
            || pending.transcript.server != expected_server
            || validate_hello(&pending.transcript.client).is_err()
            || transcript_digest(&pending.transcript)? != pending.transcript_digest
        {
            return Err(StableCode::IdentityTranscriptMismatch);
        }
        Ok(client)
    }

    #[cfg(test)]
    fn finish_replayed_for_test(
        &self,
        peer: &PeerIdentity,
        finish: ClientFinishV1,
        now: UnixMillis,
    ) -> Result<(), StableCode> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| StableCode::KernelUnavailable)?;
        state.observe(now)?;
        self.runtime.validate_time(now)?;
        if !self
            .runtime
            .clients
            .iter()
            .any(|client| client.peer_uid == peer.uid() && client.peer_gid == peer.gid())
        {
            return Err(StableCode::IdentityPeerRejected);
        }
        match state.status_for_digest(finish.transcript_digest) {
            Some((_, expires_at)) if now.get() >= expires_at.get() => {
                Err(StableCode::DeadlineExceeded)
            }
            Some((ReplayStatus::Pending | ReplayStatus::Finished, _)) => {
                Err(StableCode::IdentityReplay)
            }
            None => Err(StableCode::IdentityTranscriptMismatch),
        }
    }

    #[cfg(test)]
    fn boot_id_for_test(&self) -> BootId {
        self.boot_id
    }

    #[cfg(test)]
    fn poison_state_for_test(&self) {
        let _panic_guard = crate::panic_report::PROCESS_PANIC_TEST_LOCK.lock().unwrap();
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _state_guard = self.state.lock().unwrap();
            panic!("poison handshake state for test");
        }));
    }
}

fn validate_hello(hello: &ClientHelloV1) -> Result<(), StableCode> {
    if hello.client_nonce.as_bytes() == &[0; 32]
        || !(1..=16).contains(&hello.supported_versions.len())
        || hello
            .supported_versions
            .iter()
            .enumerate()
            .any(|(index, version)| hello.supported_versions[..index].contains(version))
    {
        return Err(StableCode::ProtocolMalformedCbor);
    }
    Ok(())
}

fn negotiate_version(
    runtime: &RuntimeIdentity,
    supported: &[ProtocolVersion],
) -> Result<ProtocolVersion, StableCode> {
    let compiled = ProtocolVersion::new(PROTOCOL_MAJOR, PROTOCOL_MINOR);
    if runtime.protocol_major == compiled.major
        && runtime.minimum_minor <= compiled.minor
        && compiled.minor <= runtime.maximum_minor
        && supported.contains(&compiled)
    {
        Ok(compiled)
    } else {
        Err(StableCode::ProtocolUnsupportedVersion)
    }
}

fn resolve_client(runtime: &RuntimeIdentity, hello: &ClientHelloV1) -> Result<usize, StableCode> {
    runtime
        .clients
        .iter()
        .position(|client| {
            client.client_id == hello.client_id
                && client.key_id == hello.client_key_id
                && client.role == InstallationClientRoleV1::JarvisKernelClient
        })
        .ok_or(StableCode::IdentityUnknownClient)
}

fn verify_peer(client: &ConfiguredClient, peer: &PeerIdentity) -> Result<(), StableCode> {
    if client.peer_uid != peer.uid() || client.peer_gid != peer.gid() {
        return Err(StableCode::IdentityPeerRejected);
    }
    Ok(())
}

fn verify_client_finish(
    client: &ConfiguredClient,
    finish: &ClientFinishV1,
) -> Result<(), StableCode> {
    let verifying_key = VerifyingKey::from_bytes(&client.public_key)
        .map_err(|_| StableCode::IdentityInvalidSignature)?;
    if verifying_key.is_weak() {
        return Err(StableCode::IdentityInvalidSignature);
    }
    let mut signed = Vec::with_capacity(CLIENT_FINISH_DOMAIN.len() + 32);
    signed.extend_from_slice(CLIENT_FINISH_DOMAIN);
    signed.extend_from_slice(finish.transcript_digest.as_bytes());
    verifying_key
        .verify_strict(&signed, &Signature::from_bytes(finish.signature.as_bytes()))
        .map_err(|_| StableCode::IdentityInvalidSignature)
}

fn nonzero_entropy(source: &dyn EntropySource) -> Result<[u8; 32], StableCode> {
    let mut value = [0_u8; 32];
    source
        .fill_32(&mut value)
        .map_err(|_| StableCode::KernelUnavailable)?;
    if value == [0; 32] {
        return Err(StableCode::KernelUnavailable);
    }
    Ok(value)
}

fn nonzero_capability(source: &dyn EntropySource) -> Result<Zeroizing<[u8; 32]>, StableCode> {
    let mut value = Zeroizing::new([0_u8; 32]);
    source
        .fill_32(&mut value)
        .map_err(|_| StableCode::KernelUnavailable)?;
    if value.iter().all(|byte| *byte == 0) {
        return Err(StableCode::KernelUnavailable);
    }
    Ok(value)
}

fn canonical_transcript(transcript: &HandshakeTranscriptV1) -> Result<Vec<u8>, StableCode> {
    minicbor::to_vec(transcript).map_err(|_| StableCode::KernelUnavailable)
}

fn transcript_digest(transcript: &HandshakeTranscriptV1) -> Result<Digest32, StableCode> {
    Ok(Digest32::new(
        Sha256::digest(canonical_transcript(transcript)?).into(),
    ))
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier, Mutex};

    use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
    use savana_kernel_protocol::{
        BootId, ClientFinishV1, ClientHelloV1, ClientId, Digest32, KeyId, Nonce32, ProtocolVersion,
        RequestedMode, Signature64, StableCode, UnixMillis,
    };

    use super::*;
    use crate::key_file::DaemonSigningIdentity;

    const STARTUP_NOW: UnixMillis = UnixMillis::new(1_000);
    const NOW: UnixMillis = UnixMillis::new(2_000);
    const GOLDEN_TRANSCRIPT_HEX: &str = concat!(
        "83",
        "85",
        "5820",
        "1111111111111111",
        "1111111111111111",
        "1111111111111111",
        "1111111111111111",
        "81",
        "820100",
        "6e",
        "666978747572652d636c69656e74",
        "72",
        "666978747572652d636c69656e742d6b6579",
        "00",
        "5820",
        "4444444444444444",
        "4444444444444444",
        "4444444444444444",
        "4444444444444444",
        "89",
        "72",
        "666978747572652d6461656d6f6e2d6b6579",
        "5820",
        "2222222222222222",
        "2222222222222222",
        "2222222222222222",
        "2222222222222222",
        "820100",
        "5820",
        "3131313131313131",
        "3131313131313131",
        "3131313131313131",
        "3131313131313131",
        "5820",
        "3232323232323232",
        "3232323232323232",
        "3232323232323232",
        "3232323232323232",
        "07",
        "5820",
        "3333333333333333",
        "3333333333333333",
        "3333333333333333",
        "3333333333333333",
        "5820",
        "3434343434343434",
        "3434343434343434",
        "3434343434343434",
        "3434343434343434",
        "5820",
        "3535353535353535",
        "3535353535353535",
        "3535353535353535",
        "3535353535353535",
    );
    const GOLDEN_DIGEST: [u8; 32] = [
        0x3d, 0x52, 0x2b, 0x01, 0x5c, 0x9e, 0xf7, 0x43, 0xf1, 0x7a, 0x9f, 0x9d, 0x36, 0xfb, 0xbb,
        0x7d, 0x64, 0x96, 0x0c, 0x81, 0x01, 0x4f, 0xf7, 0xdc, 0xb4, 0x99, 0xe3, 0x28, 0xae, 0xac,
        0xce, 0xe7,
    ];
    const CROSS_BOOT_DIGEST: [u8; 32] = [
        0xe7, 0x3b, 0xf2, 0x2d, 0x10, 0xc7, 0x4f, 0xce, 0xd7, 0x99, 0x68, 0xd5, 0x5d, 0x86, 0xb3,
        0x1d, 0x6e, 0x75, 0xf6, 0x60, 0x13, 0x6e, 0xf0, 0x1e, 0xc7, 0x84, 0x3b, 0xfd, 0x5a, 0xfc,
        0xcc, 0x2e,
    ];
    const SHADOW_DIGEST: [u8; 32] = [
        0x57, 0x01, 0x34, 0xa2, 0xbc, 0x25, 0xc9, 0x20, 0xa5, 0x64, 0xe2, 0x44, 0xbd, 0x9d, 0xd2,
        0xad, 0xae, 0xdf, 0x68, 0xf1, 0x02, 0x56, 0x84, 0x49, 0xe9, 0x1e, 0x47, 0xf6, 0xa3, 0x30,
        0x7a, 0x24,
    ];
    const DOUBLE_HASH: [u8; 32] = [
        0x19, 0x87, 0xda, 0x87, 0xb6, 0xa4, 0x44, 0x61, 0x68, 0x16, 0xd3, 0x6f, 0x0a, 0xc3, 0x79,
        0x44, 0xca, 0x95, 0xb0, 0x5f, 0xb1, 0x31, 0xdb, 0x32, 0xd7, 0x59, 0xa7, 0xcd, 0x75, 0x51,
        0xed, 0x00,
    ];
    const TAGGED_TRANSCRIPT_HASH: [u8; 32] = [
        0xcb, 0x1c, 0xff, 0x05, 0x29, 0xf4, 0xa6, 0x12, 0xb9, 0x0f, 0x51, 0x34, 0x2d, 0xcc, 0x3d,
        0x9e, 0xa1, 0x22, 0x66, 0xbb, 0x26, 0xef, 0xc9, 0xa4, 0x4c, 0x6b, 0x04, 0xdc, 0x60, 0x55,
        0x9f, 0x8d,
    ];
    const FRAMED_TRANSCRIPT_HASH: [u8; 32] = [
        0xb7, 0xc2, 0x78, 0x21, 0xf2, 0x36, 0x01, 0xa9, 0x8f, 0x43, 0x90, 0xac, 0x18, 0x9b, 0xbc,
        0xca, 0x54, 0xf1, 0x19, 0xff, 0xab, 0xa8, 0xf0, 0x9b, 0xff, 0x30, 0x37, 0x00, 0xca, 0xae,
        0xa4, 0xb5,
    ];

    #[test]
    fn golden_transcript_and_both_signature_inputs_are_exact() {
        let fixture = HandshakeFixture::new();
        let (pending, hello) = fixture
            .service
            .start(&fixture.peer, fixture.client_hello.clone(), fixture.now)
            .unwrap();
        let transcript_bytes = canonical_transcript(&hello.transcript).unwrap();
        let expected = decode_hex(GOLDEN_TRANSCRIPT_HEX);

        assert_eq!(GOLDEN_TRANSCRIPT_HEX.len(), 674);
        assert_eq!(transcript_bytes.len(), 337);
        assert_eq!(expected.last(), Some(&0x35));
        assert_eq!(transcript_bytes, expected);
        assert_eq!(
            *transcript_digest(&hello.transcript).unwrap().as_bytes(),
            GOLDEN_DIGEST
        );
        assert_ne!(GOLDEN_DIGEST, DOUBLE_HASH);
        assert_ne!(GOLDEN_DIGEST, TAGGED_TRANSCRIPT_HASH);
        assert_ne!(GOLDEN_DIGEST, FRAMED_TRANSCRIPT_HASH);

        let mut daemon_input = b"SAVANA_DAEMON_HELLO_V1\0".to_vec();
        daemon_input.extend_from_slice(&expected);
        assert_eq!(daemon_input.len(), 360);
        VerifyingKey::from_bytes(&fixture.runtime.daemon_public_key)
            .unwrap()
            .verify_strict(
                &daemon_input,
                &Signature::from_bytes(hello.signature.as_bytes()),
            )
            .unwrap();

        let finish = fixture.sign_finish(&hello.transcript);
        let mut client_input = b"SAVANA_CLIENT_FINISH_V1\0".to_vec();
        client_input.extend_from_slice(&GOLDEN_DIGEST);
        assert_eq!(client_input.len(), 56);
        fixture.client_keys[0]
            .verifying_key()
            .verify_strict(
                &client_input,
                &Signature::from_bytes(finish.signature.as_bytes()),
            )
            .unwrap();

        fixture
            .service
            .finish(&fixture.peer, pending, finish, fixture.now)
            .unwrap();
    }

    #[test]
    fn golden_digest_changes_for_cross_boot_and_shadow_transcripts() {
        let fixture = HandshakeFixture::new();
        let (_, hello) = fixture
            .service
            .start(&fixture.peer, fixture.client_hello.clone(), fixture.now)
            .unwrap();

        let mut cross_boot = hello.transcript.clone();
        cross_boot.server.boot_id = BootId::new([0x23; 32]);
        assert_eq!(
            *transcript_digest(&cross_boot).unwrap().as_bytes(),
            CROSS_BOOT_DIGEST
        );

        let mut shadow = hello.transcript;
        shadow.client.requested_mode = RequestedMode::Shadow;
        assert_eq!(
            *transcript_digest(&shadow).unwrap().as_bytes(),
            SHADOW_DIGEST
        );
    }

    #[test]
    fn transcript_binds_both_nonces_and_all_public_identities() {
        let fixture = HandshakeFixture::new();
        let (pending, hello) = fixture
            .service
            .start(&fixture.peer, fixture.client_hello.clone(), fixture.now)
            .unwrap();

        assert_eq!(
            hello.transcript.server.release_digest,
            fixture.runtime.release_digest
        );
        assert_eq!(
            hello.transcript.server.policy_digest,
            fixture.runtime.policy_digest
        );
        assert_eq!(
            hello.transcript.server.model_manifest_digest,
            fixture.runtime.model_manifest_digest
        );
        assert_eq!(
            hello.transcript.server.approval_key_set_digest,
            fixture.runtime.approval_key_set_digest
        );
        assert_eq!(
            hello.transcript.server.resource_profile_digest,
            fixture.runtime.resource_profile_digest
        );
        assert_eq!(hello.transcript.server_nonce, Nonce32::new([0x44; 32]));
        assert_eq!(hello.transcript.client, fixture.client_hello);

        let finish = fixture.sign_finish(&hello.transcript);
        let context = fixture
            .service
            .finish(&fixture.peer, pending, finish, fixture.now)
            .unwrap();
        assert_eq!(context.client_id(), &fixture.client_id);
        assert_eq!(context.peer(), &fixture.peer);
        assert_eq!(context.protocol(), ProtocolVersion::new(1, 0));
        assert_eq!(context.mode(), RequestedMode::Required);
    }

    #[test]
    fn negotiation_is_order_independent_and_selects_the_only_common_version() {
        let fixture = HandshakeFixture::new();
        for (offset, versions) in [
            vec![ProtocolVersion::new(1, 0)],
            vec![ProtocolVersion::new(2, 0), ProtocolVersion::new(1, 0)],
            vec![ProtocolVersion::new(1, 1), ProtocolVersion::new(1, 0)],
        ]
        .into_iter()
        .enumerate()
        {
            let hello = fixture.hello(
                0,
                Nonce32::new([0x20 + u8::try_from(offset).unwrap(); 32]),
                versions,
                RequestedMode::Required,
            );
            let (_, signed) = fixture
                .service
                .start(
                    &fixture.peer,
                    hello,
                    UnixMillis::new(NOW.get() + u64::try_from(offset).unwrap()),
                )
                .unwrap();
            assert_eq!(
                signed.transcript.server.protocol,
                ProtocolVersion::new(1, 0)
            );
        }
    }

    #[test]
    fn runtime_identity_never_constructs_an_uncompiled_protocol_version() {
        let mut runtime = test_runtime(1);
        runtime.maximum_minor = 1;

        assert_eq!(
            runtime
                .server_identity(BootId::new([0x22; 32]), ProtocolVersion::new(1, 1),)
                .unwrap_err(),
            StableCode::ProtocolUnsupportedVersion
        );
    }

    #[test]
    fn hello_cardinality_duplicates_and_zero_nonce_are_malformed_before_negotiation() {
        let fixture = HandshakeFixture::new();
        let cases = [
            fixture.hello(
                0,
                Nonce32::new([0x20; 32]),
                Vec::new(),
                RequestedMode::Required,
            ),
            fixture.hello(
                0,
                Nonce32::new([0x21; 32]),
                (0_u16..17)
                    .map(|minor| ProtocolVersion::new(2, minor))
                    .collect(),
                RequestedMode::Required,
            ),
            fixture.hello(
                0,
                Nonce32::new([0x22; 32]),
                vec![ProtocolVersion::new(2, 0), ProtocolVersion::new(2, 0)],
                RequestedMode::Required,
            ),
            fixture.hello(
                0,
                Nonce32::new([0; 32]),
                vec![ProtocolVersion::new(2, 0)],
                RequestedMode::Required,
            ),
        ];

        for (offset, hello) in cases.into_iter().enumerate() {
            assert_eq!(
                fixture
                    .service
                    .start(
                        &fixture.peer,
                        hello,
                        UnixMillis::new(NOW.get() + u64::try_from(offset).unwrap()),
                    )
                    .unwrap_err(),
                StableCode::ProtocolMalformedCbor
            );
        }
    }

    #[test]
    fn no_common_version_precedes_unknown_client() {
        let fixture = HandshakeFixture::new();
        let hello = ClientHelloV1 {
            client_nonce: Nonce32::new([0x19; 32]),
            supported_versions: vec![ProtocolVersion::new(2, 0)],
            client_id: ClientId::try_from("unknown-client").unwrap(),
            client_key_id: KeyId::try_from("unknown-key").unwrap(),
            requested_mode: RequestedMode::Required,
        };

        assert_eq!(
            fixture
                .service
                .start(&fixture.peer, hello, fixture.now)
                .unwrap_err(),
            StableCode::ProtocolUnsupportedVersion
        );
    }

    #[test]
    fn exact_client_key_and_peer_are_required_in_that_order() {
        let fixture = HandshakeFixture::new();
        let wrong_client = ClientHelloV1 {
            client_nonce: Nonce32::new([0x20; 32]),
            supported_versions: vec![ProtocolVersion::new(1, 0)],
            client_id: fixture.client_id.clone(),
            client_key_id: KeyId::try_from("unknown-key").unwrap(),
            requested_mode: RequestedMode::Required,
        };
        assert_eq!(
            fixture
                .service
                .start(&fixture.peer, wrong_client, fixture.now)
                .unwrap_err(),
            StableCode::IdentityUnknownClient
        );

        let unknown_client = ClientHelloV1 {
            client_nonce: Nonce32::new([0x21; 32]),
            supported_versions: vec![ProtocolVersion::new(1, 0)],
            client_id: ClientId::try_from("unknown-client").unwrap(),
            client_key_id: fixture.runtime.clients[0].key_id.clone(),
            requested_mode: RequestedMode::Required,
        };
        assert_eq!(
            fixture
                .service
                .start(
                    &fixture.peer,
                    unknown_client,
                    UnixMillis::new(NOW.get() + 1),
                )
                .unwrap_err(),
            StableCode::IdentityUnknownClient
        );

        for (offset, wrong_peer) in [
            PeerIdentity::new_for_test(fixture.peer.uid().wrapping_add(1), fixture.peer.gid()),
            PeerIdentity::new_for_test(fixture.peer.uid(), fixture.peer.gid().wrapping_add(1)),
        ]
        .into_iter()
        .enumerate()
        {
            assert_eq!(
                fixture
                    .service
                    .start(
                        &wrong_peer,
                        fixture.hello(
                            0,
                            Nonce32::new([0x22 + u8::try_from(offset).unwrap(); 32]),
                            vec![ProtocolVersion::new(1, 0)],
                            RequestedMode::Required,
                        ),
                        UnixMillis::new(NOW.get() + 2 + u64::try_from(offset).unwrap()),
                    )
                    .unwrap_err(),
                StableCode::IdentityPeerRejected
            );
        }
    }

    #[test]
    fn required_and_shadow_modes_are_copied_without_rewriting() {
        for (mode, nonce) in [
            (RequestedMode::Required, Nonce32::new([0x20; 32])),
            (RequestedMode::Shadow, Nonce32::new([0x21; 32])),
        ] {
            let fixture = HandshakeFixture::new();
            let hello = fixture.hello(0, nonce, vec![ProtocolVersion::new(1, 0)], mode);
            let (pending, signed) = fixture
                .service
                .start(&fixture.peer, hello, fixture.now)
                .unwrap();
            assert_eq!(signed.transcript.client.requested_mode, mode);
            let finish = fixture.sign_finish(&signed.transcript);
            let context = fixture
                .service
                .finish(&fixture.peer, pending, finish, fixture.now)
                .unwrap();
            assert_eq!(context.mode(), mode);
        }
    }

    #[test]
    fn peer_preauthorization_matches_any_verified_client_before_hello() {
        let fixture = HandshakeFixture::with_clients(2);

        fixture
            .service
            .preauthorize_peer(&fixture.peers[0])
            .unwrap();
        fixture
            .service
            .preauthorize_peer(&fixture.peers[1])
            .unwrap();
        assert_eq!(
            fixture
                .service
                .preauthorize_peer(&PeerIdentity::new_for_test(
                    fixture.peers[0].uid().wrapping_add(100),
                    fixture.peers[0].gid(),
                ))
                .unwrap_err(),
            StableCode::IdentityPeerRejected
        );
    }

    #[test]
    fn authenticated_context_revalidation_returns_exact_signed_identity() {
        let fixture = HandshakeFixture::new();
        let (pending, signed) = fixture
            .service
            .start(&fixture.peer, fixture.client_hello.clone(), fixture.now)
            .unwrap();
        let finish = fixture.sign_finish(&signed.transcript);
        let context = fixture
            .service
            .finish(&fixture.peer, pending, finish, fixture.now)
            .unwrap();

        assert_eq!(
            fixture
                .service
                .validate_context_identity(&context, UnixMillis::new(fixture.now.get() + 1))
                .unwrap(),
            signed.transcript.server
        );
    }

    #[test]
    fn context_projection_rejects_tampered_runtime_bindings() {
        let cases: [fn(&mut ConnectionContext); 3] = [
            |context| context.boot_id = BootId::new([0x91; 32]),
            |context| context.protocol = ProtocolVersion::new(1, 1),
            |context| context.expires_at = UnixMillis::new(context.expires_at.get() - 1),
        ];

        for mutate in cases {
            let fixture = HandshakeFixture::new();
            let (pending, signed) = fixture
                .service
                .start(&fixture.peer, fixture.client_hello.clone(), fixture.now)
                .unwrap();
            let finish = fixture.sign_finish(&signed.transcript);
            let mut context = fixture
                .service
                .finish(&fixture.peer, pending, finish, fixture.now)
                .unwrap();
            mutate(&mut context);

            assert_eq!(
                fixture
                    .service
                    .validate_context_identity(&context, UnixMillis::new(fixture.now.get() + 1),)
                    .unwrap_err(),
                StableCode::IdentityTranscriptMismatch
            );
        }
    }

    #[test]
    fn every_pending_transcript_identity_mismatch_fails_closed() {
        assert_pending_mutation(|pending| {
            pending.transcript.server.boot_id = BootId::new([0x23; 32]);
        });
        assert_pending_mutation(|pending| {
            pending.transcript.server.protocol = ProtocolVersion::new(1, 1);
        });
        assert_pending_mutation(|pending| {
            pending.transcript.client.requested_mode = RequestedMode::Shadow;
        });
        assert_pending_mutation(|pending| {
            pending.transcript.client.client_id = ClientId::try_from("other-client").unwrap();
        });
        assert_pending_mutation(|pending| {
            pending.transcript.client.client_key_id = KeyId::try_from("other-key").unwrap();
        });
        assert_pending_mutation(|pending| {
            pending.transcript.client.supported_versions = vec![ProtocolVersion::new(2, 0)];
        });
        assert_pending_mutation(|pending| {
            pending.transcript.client.client_nonce = Nonce32::new([0x91; 32]);
        });
        assert_pending_mutation(|pending| {
            pending.transcript.server_nonce = Nonce32::new([0x92; 32]);
        });
        assert_pending_mutation(|pending| {
            pending.transcript.server.release_digest = Digest32::new([0x93; 32]);
        });
        assert_pending_mutation(|pending| {
            pending.transcript.server.policy_digest = Digest32::new([0x94; 32]);
        });
        assert_pending_mutation(|pending| {
            pending.transcript.server.policy_version += 1;
        });
        assert_pending_mutation(|pending| {
            pending.transcript.server.daemon_key_id = KeyId::try_from("other-daemon-key").unwrap();
        });
        assert_pending_mutation(|pending| {
            pending.transcript.server.model_manifest_digest = Digest32::new([0x95; 32]);
        });
        assert_pending_mutation(|pending| {
            pending.transcript.server.approval_key_set_digest = Digest32::new([0x96; 32]);
        });
        assert_pending_mutation(|pending| {
            pending.transcript.server.resource_profile_digest = Digest32::new([0x97; 32]);
        });
        assert_pending_mutation(|pending| {
            pending.client_index = usize::MAX;
        });
        assert_pending_mutation(|pending| {
            pending.partition_index = usize::MAX;
        });
    }

    #[test]
    fn changed_finish_digest_precedes_signature_validation() {
        let fixture = HandshakeFixture::new();
        let (pending, hello) = fixture
            .service
            .start(&fixture.peer, fixture.client_hello.clone(), fixture.now)
            .unwrap();
        let finish = ClientFinishV1 {
            transcript_digest: Digest32::new([0xee; 32]),
            signature: Signature64::new([0; 64]),
        };

        assert_eq!(
            fixture
                .service
                .finish(&fixture.peer, pending, finish, fixture.now)
                .unwrap_err(),
            StableCode::IdentityTranscriptMismatch
        );
        assert_eq!(hello.transcript.client, fixture.client_hello);
    }

    #[test]
    fn correct_digest_with_bad_signature_is_invalid_signature() {
        let fixture = HandshakeFixture::new();
        let (pending, hello) = fixture
            .service
            .start(&fixture.peer, fixture.client_hello.clone(), fixture.now)
            .unwrap();
        let finish = ClientFinishV1 {
            transcript_digest: transcript_digest(&hello.transcript).unwrap(),
            signature: Signature64::new([0; 64]),
        };

        assert_eq!(
            fixture
                .service
                .finish(&fixture.peer, pending, finish, fixture.now)
                .unwrap_err(),
            StableCode::IdentityInvalidSignature
        );
    }

    #[test]
    fn finish_rechecks_the_exact_peer_before_deadline_or_transcript() {
        let fixture = HandshakeFixture::new();
        let (pending, hello) = fixture
            .service
            .start(&fixture.peer, fixture.client_hello.clone(), fixture.now)
            .unwrap();
        let changed_peer =
            PeerIdentity::new_for_test(fixture.peer.uid().wrapping_add(1), fixture.peer.gid());
        let finish = fixture.sign_finish(&hello.transcript);

        assert_eq!(
            fixture
                .service
                .finish(
                    &changed_peer,
                    pending,
                    finish,
                    UnixMillis::new(NOW.get() + 5_000),
                )
                .unwrap_err(),
            StableCode::IdentityPeerRejected
        );
    }

    #[test]
    fn pending_and_finished_nonce_replays_are_retained_until_expiry() {
        let fixture = HandshakeFixture::new();
        let (pending, hello) = fixture
            .service
            .start(&fixture.peer, fixture.client_hello.clone(), fixture.now)
            .unwrap();
        assert_eq!(
            fixture
                .service
                .start(&fixture.peer, fixture.client_hello.clone(), fixture.now,)
                .unwrap_err(),
            StableCode::IdentityReplay
        );
        let finish = fixture.sign_finish(&hello.transcript);
        fixture
            .service
            .finish(&fixture.peer, pending, finish.clone(), fixture.now)
            .unwrap();
        assert_eq!(
            fixture
                .service
                .finish_replayed_for_test(&fixture.peer, finish, fixture.now)
                .unwrap_err(),
            StableCode::IdentityReplay
        );
        assert_eq!(
            fixture
                .service
                .start(&fixture.peer, fixture.client_hello.clone(), fixture.now,)
                .unwrap_err(),
            StableCode::IdentityReplay
        );
    }

    #[test]
    fn invalid_digest_and_signature_do_not_release_pending_nonce() {
        for invalid_finish in [InvalidFinish::Digest, InvalidFinish::Signature] {
            let fixture = HandshakeFixture::new();
            let (pending, hello) = fixture
                .service
                .start(&fixture.peer, fixture.client_hello.clone(), fixture.now)
                .unwrap();
            let finish = match invalid_finish {
                InvalidFinish::Digest => ClientFinishV1 {
                    transcript_digest: Digest32::new([0xee; 32]),
                    signature: Signature64::new([0; 64]),
                },
                InvalidFinish::Signature => ClientFinishV1 {
                    transcript_digest: transcript_digest(&hello.transcript).unwrap(),
                    signature: Signature64::new([0; 64]),
                },
            };
            assert!(fixture
                .service
                .finish(&fixture.peer, pending, finish, fixture.now)
                .is_err());
            assert_eq!(
                fixture
                    .service
                    .start(
                        &fixture.peer,
                        fixture.client_hello.clone(),
                        UnixMillis::new(NOW.get() + 1),
                    )
                    .unwrap_err(),
                StableCode::IdentityReplay
            );
            assert_eq!(
                fixture
                    .service
                    .finish_replayed_for_test(
                        &fixture.peer,
                        fixture.sign_finish(&hello.transcript),
                        UnixMillis::new(NOW.get() + 1),
                    )
                    .unwrap_err(),
                StableCode::IdentityReplay
            );
        }
    }

    #[test]
    fn dropping_pending_or_rejecting_peer_does_not_release_the_nonce() {
        let fixture = HandshakeFixture::new();
        let (pending, _) = fixture
            .service
            .start(&fixture.peer, fixture.client_hello.clone(), fixture.now)
            .unwrap();
        drop(pending);
        assert_eq!(
            fixture
                .service
                .start(
                    &fixture.peer,
                    fixture.client_hello.clone(),
                    UnixMillis::new(NOW.get() + 1),
                )
                .unwrap_err(),
            StableCode::IdentityReplay
        );

        let fixture = HandshakeFixture::new();
        let (pending, hello) = fixture
            .service
            .start(&fixture.peer, fixture.client_hello.clone(), fixture.now)
            .unwrap();
        let changed_peer =
            PeerIdentity::new_for_test(fixture.peer.uid().wrapping_add(1), fixture.peer.gid());
        let finish = fixture.sign_finish(&hello.transcript);
        assert_eq!(
            fixture
                .service
                .finish(&changed_peer, pending, finish, fixture.now)
                .unwrap_err(),
            StableCode::IdentityPeerRejected
        );
        assert_eq!(
            fixture
                .service
                .start(
                    &fixture.peer,
                    fixture.client_hello.clone(),
                    UnixMillis::new(NOW.get() + 1),
                )
                .unwrap_err(),
            StableCode::IdentityReplay
        );
    }

    #[test]
    fn capability_failure_leaves_the_cache_entry_pending() {
        for failure in [EntropyStep::Fail, EntropyStep::Zero] {
            let fixture = HandshakeFixture::with_entropy(vec![
                EntropyStep::Value([0x22; 32]),
                EntropyStep::Value([0x44; 32]),
                failure,
            ])
            .unwrap();
            let (pending, hello) = fixture
                .service
                .start(&fixture.peer, fixture.client_hello.clone(), fixture.now)
                .unwrap();
            let finish = fixture.sign_finish(&hello.transcript);
            let replayed_finish = finish.clone();
            assert_eq!(
                fixture
                    .service
                    .finish(&fixture.peer, pending, finish, fixture.now)
                    .unwrap_err(),
                StableCode::KernelUnavailable
            );
            assert_eq!(
                fixture
                    .service
                    .start(
                        &fixture.peer,
                        fixture.client_hello.clone(),
                        UnixMillis::new(NOW.get() + 1),
                    )
                    .unwrap_err(),
                StableCode::IdentityReplay
            );
            assert_eq!(
                fixture
                    .service
                    .finish_replayed_for_test(
                        &fixture.peer,
                        replayed_finish,
                        UnixMillis::new(NOW.get() + 1),
                    )
                    .unwrap_err(),
                StableCode::IdentityReplay
            );
        }
    }

    #[test]
    fn same_nonce_is_independent_across_client_partitions() {
        let fixture = HandshakeFixture::with_clients(2);
        let nonce = Nonce32::new([0x71; 32]);
        let first = fixture.hello(
            0,
            nonce,
            vec![ProtocolVersion::new(1, 0)],
            RequestedMode::Required,
        );
        let second = fixture.hello(
            1,
            nonce,
            vec![ProtocolVersion::new(1, 0)],
            RequestedMode::Required,
        );

        assert!(fixture
            .service
            .start(&fixture.peers[0], first, fixture.now)
            .is_ok());
        assert!(fixture
            .service
            .start(&fixture.peers[1], second, UnixMillis::new(NOW.get() + 1),)
            .is_ok());
    }

    #[test]
    fn full_partition_rejects_without_spilling_or_blocking_another_client() {
        let fixture = HandshakeFixture::with_clients(2);
        for byte in 1_u8..=128 {
            let hello = fixture.hello(
                0,
                Nonce32::new([byte; 32]),
                vec![ProtocolVersion::new(1, 0)],
                RequestedMode::Required,
            );
            fixture
                .service
                .start(&fixture.peers[0], hello, fixture.now)
                .unwrap();
        }
        assert_eq!(
            fixture
                .service
                .start(
                    &fixture.peers[0],
                    fixture.hello(
                        0,
                        Nonce32::new([0xff; 32]),
                        vec![ProtocolVersion::new(1, 0)],
                        RequestedMode::Required,
                    ),
                    fixture.now,
                )
                .unwrap_err(),
            StableCode::KernelOverloaded
        );
        assert!(fixture
            .service
            .start(
                &fixture.peers[1],
                fixture.hello(
                    1,
                    Nonce32::new([1; 32]),
                    vec![ProtocolVersion::new(1, 0)],
                    RequestedMode::Required,
                ),
                fixture.now,
            )
            .is_ok());
    }

    #[test]
    fn concurrent_same_nonce_admission_has_exactly_one_winner() {
        let runtime = test_runtime(1);
        let calls = Arc::new(AtomicUsize::new(0));
        let service = HandshakeService::new_with_entropy_for_test(
            runtime.clone(),
            DaemonSigningIdentity::from_seed_for_test([0x61; 32]),
            STARTUP_NOW,
            Box::new(CountingEntropy {
                calls: Arc::clone(&calls),
            }),
        )
        .unwrap();
        calls.store(0, Ordering::SeqCst);
        let service = Arc::new(service);
        let peer = peer_for(&runtime, 0);
        let hello = hello_for(
            &runtime,
            0,
            Nonce32::new([0x11; 32]),
            vec![ProtocolVersion::new(1, 0)],
            RequestedMode::Required,
        );
        let barrier = Arc::new(Barrier::new(17));
        let results = std::thread::scope(|scope| {
            let mut handles = Vec::new();
            for _ in 0..16 {
                let service = Arc::clone(&service);
                let barrier = Arc::clone(&barrier);
                let hello = hello.clone();
                handles.push(scope.spawn(move || {
                    barrier.wait();
                    service.start(&peer, hello, NOW)
                }));
            }
            barrier.wait();
            handles
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .collect::<Vec<_>>()
        });

        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| { matches!(result, Err(StableCode::IdentityReplay)) })
                .count(),
            15
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn deadline_is_exactly_five_seconds_and_equality_is_expired() {
        let fixture = HandshakeFixture::new();
        let (pending, hello) = fixture
            .service
            .start(&fixture.peer, fixture.client_hello.clone(), fixture.now)
            .unwrap();
        let finish = fixture.sign_finish(&hello.transcript);
        assert!(fixture
            .service
            .finish(
                &fixture.peer,
                pending,
                finish,
                UnixMillis::new(NOW.get() + 4_999),
            )
            .is_ok());

        let fixture = HandshakeFixture::new();
        let (pending, hello) = fixture
            .service
            .start(&fixture.peer, fixture.client_hello.clone(), fixture.now)
            .unwrap();
        let finish = fixture.sign_finish(&hello.transcript);
        assert_eq!(
            fixture
                .service
                .finish(
                    &fixture.peer,
                    pending,
                    finish,
                    UnixMillis::new(NOW.get() + 5_000),
                )
                .unwrap_err(),
            StableCode::DeadlineExceeded
        );
    }

    #[test]
    fn finish_never_cleans_expired_slots_and_later_start_cleans_only_its_partition() {
        let fixture = HandshakeFixture::with_clients(2);
        let first_hello = fixture.hello(
            0,
            Nonce32::new([0x11; 32]),
            vec![ProtocolVersion::new(1, 0)],
            RequestedMode::Required,
        );
        let second_hello = fixture.hello(
            1,
            Nonce32::new([0x11; 32]),
            vec![ProtocolVersion::new(1, 0)],
            RequestedMode::Required,
        );
        let (first_pending, first_signed) = fixture
            .service
            .start(&fixture.peers[0], first_hello, fixture.now)
            .unwrap();
        let (second_pending, second_signed) = fixture
            .service
            .start(&fixture.peers[1], second_hello, fixture.now)
            .unwrap();
        let first_digest = transcript_digest(&first_signed.transcript).unwrap();
        let second_digest = transcript_digest(&second_signed.transcript).unwrap();
        drop(second_pending);
        let finish = fixture.sign_finish(&first_signed.transcript);
        let deadline = UnixMillis::new(NOW.get() + PENDING_WINDOW_MS);

        assert_eq!(
            fixture
                .service
                .finish(&fixture.peers[0], first_pending, finish, deadline)
                .unwrap_err(),
            StableCode::DeadlineExceeded
        );
        {
            let state = fixture.service.state.lock().unwrap();
            assert!(state.status_for_digest(first_digest).is_some());
            assert!(state.status_for_digest(second_digest).is_some());
        }

        fixture
            .service
            .start(
                &fixture.peers[0],
                fixture.hello(
                    0,
                    Nonce32::new([0x12; 32]),
                    vec![ProtocolVersion::new(1, 0)],
                    RequestedMode::Required,
                ),
                deadline,
            )
            .unwrap();
        let state = fixture.service.state.lock().unwrap();
        assert!(state.status_for_digest(first_digest).is_none());
        assert!(state.status_for_digest(second_digest).is_some());
    }

    #[test]
    fn checked_deadline_overflow_precedes_runtime_expiry() {
        let mut runtime = test_runtime(1);
        runtime.release_expires_at = UnixMillis::new(u64::MAX);
        runtime.policy_expires_at = UnixMillis::new(u64::MAX);
        let service = build_service(
            runtime.clone(),
            UnixMillis::new(u64::MAX - 5_000),
            vec![EntropyStep::Value([0x22; 32])],
        )
        .unwrap();
        let hello = hello_for(
            &runtime,
            0,
            Nonce32::new([0x11; 32]),
            vec![ProtocolVersion::new(1, 0)],
            RequestedMode::Required,
        );
        let peer = peer_for(&runtime, 0);

        assert_eq!(
            service
                .start(&peer, hello, UnixMillis::new(u64::MAX - 4_999))
                .unwrap_err(),
            StableCode::KernelUnavailable
        );
    }

    #[test]
    fn release_and_policy_expiry_are_rechecked_with_release_priority() {
        let mut policy_runtime = test_runtime(1);
        policy_runtime.release_expires_at = UnixMillis::new(4_000);
        policy_runtime.policy_expires_at = UnixMillis::new(3_000);
        let policy_fixture = HandshakeFixture::with_runtime(policy_runtime).unwrap();
        assert_eq!(
            policy_fixture
                .service
                .start(
                    &policy_fixture.peer,
                    policy_fixture.client_hello.clone(),
                    UnixMillis::new(3_000),
                )
                .unwrap_err(),
            StableCode::PolicyExpired
        );

        let mut finish_policy_runtime = test_runtime(1);
        finish_policy_runtime.release_expires_at = UnixMillis::new(4_000);
        finish_policy_runtime.policy_expires_at = UnixMillis::new(3_000);
        let finish_policy_fixture = HandshakeFixture::with_runtime(finish_policy_runtime).unwrap();
        let (pending, hello) = finish_policy_fixture
            .service
            .start(
                &finish_policy_fixture.peer,
                finish_policy_fixture.client_hello.clone(),
                finish_policy_fixture.now,
            )
            .unwrap();
        let finish = finish_policy_fixture.sign_finish(&hello.transcript);
        assert_eq!(
            finish_policy_fixture
                .service
                .finish(
                    &finish_policy_fixture.peer,
                    pending,
                    finish,
                    UnixMillis::new(3_000),
                )
                .unwrap_err(),
            StableCode::PolicyExpired
        );

        let mut release_runtime = test_runtime(1);
        release_runtime.release_expires_at = UnixMillis::new(3_000);
        release_runtime.policy_expires_at = UnixMillis::new(3_000);
        let release_fixture = HandshakeFixture::with_runtime(release_runtime).unwrap();
        assert_eq!(
            release_fixture
                .service
                .start(
                    &release_fixture.peer,
                    release_fixture.client_hello.clone(),
                    UnixMillis::new(3_000),
                )
                .unwrap_err(),
            StableCode::IdentityReleaseMismatch
        );

        let mut finish_runtime = test_runtime(1);
        finish_runtime.release_expires_at = UnixMillis::new(3_000);
        finish_runtime.policy_expires_at = UnixMillis::new(3_000);
        let finish_fixture = HandshakeFixture::with_runtime(finish_runtime).unwrap();
        let (pending, hello) = finish_fixture
            .service
            .start(
                &finish_fixture.peer,
                finish_fixture.client_hello.clone(),
                finish_fixture.now,
            )
            .unwrap();
        let finish = finish_fixture.sign_finish(&hello.transcript);
        assert_eq!(
            finish_fixture
                .service
                .finish(
                    &finish_fixture.peer,
                    pending,
                    finish,
                    UnixMillis::new(3_000),
                )
                .unwrap_err(),
            StableCode::IdentityReleaseMismatch
        );
    }

    #[test]
    fn clock_floor_starts_at_bootstrap_time_and_failed_calls_advance_it() {
        let fixture = HandshakeFixture::new();
        assert_eq!(
            fixture
                .service
                .start(
                    &fixture.peer,
                    fixture.client_hello.clone(),
                    UnixMillis::new(STARTUP_NOW.get() - 1),
                )
                .unwrap_err(),
            StableCode::KernelUnavailable
        );

        let unsupported = fixture.hello(
            0,
            Nonce32::new([0x31; 32]),
            vec![ProtocolVersion::new(2, 0)],
            RequestedMode::Required,
        );
        assert_eq!(
            fixture
                .service
                .start(&fixture.peer, unsupported, UnixMillis::new(3_000))
                .unwrap_err(),
            StableCode::ProtocolUnsupportedVersion
        );
        assert_eq!(
            fixture
                .service
                .start(
                    &fixture.peer,
                    fixture.client_hello.clone(),
                    UnixMillis::new(2_999),
                )
                .unwrap_err(),
            StableCode::KernelUnavailable
        );
    }

    #[test]
    fn pre_bind_freshness_advances_the_clock_floor_and_rechecks_expiry() {
        let fixture = HandshakeFixture::new();
        fixture
            .service
            .refresh_before_bind(UnixMillis::new(2_500))
            .unwrap();
        assert_eq!(
            fixture
                .service
                .refresh_before_bind(UnixMillis::new(2_499))
                .unwrap_err(),
            StableCode::KernelUnavailable
        );

        let mut runtime = test_runtime(1);
        runtime.release_expires_at = UnixMillis::new(2_500);
        let expired = HandshakeFixture::with_runtime(runtime).unwrap();
        assert_eq!(
            expired
                .service
                .refresh_before_bind(UnixMillis::new(2_500))
                .unwrap_err(),
            StableCode::IdentityReleaseMismatch
        );
    }

    #[test]
    fn failed_finish_also_advances_the_process_clock_floor() {
        let fixture = HandshakeFixture::new();
        let (first_pending, first_hello) = fixture
            .service
            .start(&fixture.peer, fixture.client_hello.clone(), fixture.now)
            .unwrap();
        let second_hello_value = fixture.hello(
            0,
            Nonce32::new([0x12; 32]),
            vec![ProtocolVersion::new(1, 0)],
            RequestedMode::Required,
        );
        let (second_pending, second_hello) = fixture
            .service
            .start(
                &fixture.peer,
                second_hello_value,
                UnixMillis::new(NOW.get() + 1),
            )
            .unwrap();
        let invalid = ClientFinishV1 {
            transcript_digest: transcript_digest(&first_hello.transcript).unwrap(),
            signature: Signature64::new([0; 64]),
        };
        assert_eq!(
            fixture
                .service
                .finish(
                    &fixture.peer,
                    first_pending,
                    invalid,
                    UnixMillis::new(3_000),
                )
                .unwrap_err(),
            StableCode::IdentityInvalidSignature
        );
        let valid = fixture.sign_finish(&second_hello.transcript);
        assert_eq!(
            fixture
                .service
                .finish(&fixture.peer, second_pending, valid, UnixMillis::new(2_999),)
                .unwrap_err(),
            StableCode::KernelUnavailable
        );
    }

    #[test]
    fn entropy_failures_also_advance_the_process_clock_floor() {
        let fixture =
            HandshakeFixture::with_entropy(vec![EntropyStep::Value([0x22; 32]), EntropyStep::Fail])
                .unwrap();
        assert_eq!(
            fixture
                .service
                .start(
                    &fixture.peer,
                    fixture.client_hello.clone(),
                    UnixMillis::new(3_000),
                )
                .unwrap_err(),
            StableCode::KernelUnavailable
        );
        assert_eq!(
            fixture
                .service
                .start(
                    &fixture.peer,
                    fixture.client_hello.clone(),
                    UnixMillis::new(2_999),
                )
                .unwrap_err(),
            StableCode::KernelUnavailable
        );

        let fixture = HandshakeFixture::with_entropy(vec![
            EntropyStep::Value([0x22; 32]),
            EntropyStep::Value([0x44; 32]),
            EntropyStep::Fail,
        ])
        .unwrap();
        let (pending, hello) = fixture
            .service
            .start(&fixture.peer, fixture.client_hello.clone(), fixture.now)
            .unwrap();
        let finish = fixture.sign_finish(&hello.transcript);
        assert_eq!(
            fixture
                .service
                .finish(&fixture.peer, pending, finish, UnixMillis::new(3_000),)
                .unwrap_err(),
            StableCode::KernelUnavailable
        );
        assert_eq!(
            fixture
                .service
                .start(
                    &fixture.peer,
                    fixture.hello(
                        0,
                        Nonce32::new([0x12; 32]),
                        vec![ProtocolVersion::new(1, 0)],
                        RequestedMode::Required,
                    ),
                    UnixMillis::new(2_999),
                )
                .unwrap_err(),
            StableCode::KernelUnavailable
        );
    }

    #[test]
    fn boot_server_nonce_and_capability_entropy_fail_closed() {
        let runtime = test_runtime(1);
        assert_eq!(
            build_service(runtime.clone(), STARTUP_NOW, vec![EntropyStep::Fail]).unwrap_err(),
            StableCode::KernelUnavailable
        );
        assert_eq!(
            build_service(runtime.clone(), STARTUP_NOW, vec![EntropyStep::Zero]).unwrap_err(),
            StableCode::KernelUnavailable
        );

        for bad_server_entropy in [EntropyStep::Fail, EntropyStep::Zero] {
            let fixture = HandshakeFixture::with_entropy(vec![
                EntropyStep::Value([0x22; 32]),
                bad_server_entropy,
                EntropyStep::Value([0x44; 32]),
            ])
            .unwrap();
            assert_eq!(
                fixture
                    .service
                    .start(&fixture.peer, fixture.client_hello.clone(), fixture.now,)
                    .unwrap_err(),
                StableCode::KernelUnavailable
            );
            assert!(fixture
                .service
                .start(
                    &fixture.peer,
                    fixture.client_hello.clone(),
                    UnixMillis::new(NOW.get() + 1),
                )
                .is_ok());
        }
    }

    #[test]
    fn daemon_signing_key_must_match_the_verified_runtime_identity() {
        let mut runtime = test_runtime(1);
        runtime.daemon_public_key = SigningKey::from_bytes(&[0x62; 32])
            .verifying_key()
            .to_bytes();

        assert_eq!(
            build_service(runtime, STARTUP_NOW, vec![EntropyStep::Value([0x22; 32])],).unwrap_err(),
            StableCode::IdentityKeyPermissions
        );
    }

    #[test]
    fn a_new_service_owns_a_fresh_boot_and_an_empty_cache() {
        let first = HandshakeFixture::with_entropy(vec![
            EntropyStep::Value([0x22; 32]),
            EntropyStep::Value([0x44; 32]),
        ])
        .unwrap();
        let second = HandshakeFixture::with_entropy(vec![
            EntropyStep::Value([0x23; 32]),
            EntropyStep::Value([0x44; 32]),
        ])
        .unwrap();

        assert_ne!(
            first.service.boot_id_for_test(),
            second.service.boot_id_for_test()
        );
        assert!(first
            .service
            .start(&first.peer, first.client_hello.clone(), first.now)
            .is_ok());
        assert!(second
            .service
            .start(&second.peer, second.client_hello.clone(), second.now)
            .is_ok());
    }

    #[test]
    fn poisoned_clock_and_replay_state_is_kernel_unavailable() {
        let fixture = HandshakeFixture::new();
        fixture.service.poison_state_for_test();

        assert_eq!(
            fixture
                .service
                .start(&fixture.peer, fixture.client_hello.clone(), fixture.now,)
                .unwrap_err(),
            StableCode::KernelUnavailable
        );

        let fixture = HandshakeFixture::new();
        let (pending, hello) = fixture
            .service
            .start(&fixture.peer, fixture.client_hello.clone(), fixture.now)
            .unwrap();
        let finish = fixture.sign_finish(&hello.transcript);
        fixture.service.poison_state_for_test();
        assert_eq!(
            fixture
                .service
                .finish(&fixture.peer, pending, finish, fixture.now)
                .unwrap_err(),
            StableCode::KernelUnavailable
        );
    }

    #[test]
    fn accepted_message_and_context_derive_exact_boot_version_and_runtime_expiry() {
        let mut runtime = test_runtime(1);
        runtime.release_expires_at = UnixMillis::new(12_000);
        runtime.policy_expires_at = UnixMillis::new(9_000);
        let fixture = HandshakeFixture::with_runtime(runtime).unwrap();
        let (pending, hello) = fixture
            .service
            .start(&fixture.peer, fixture.client_hello.clone(), fixture.now)
            .unwrap();
        let finish = fixture.sign_finish(&hello.transcript);
        let context = fixture
            .service
            .finish(&fixture.peer, pending, finish, fixture.now)
            .unwrap();
        let accepted = context.accepted();

        assert_eq!(accepted.boot_id, hello.transcript.server.boot_id);
        assert_eq!(accepted.protocol, hello.transcript.server.protocol);
        assert_eq!(context.expires_at(), UnixMillis::new(9_000));
        assert!(context.capability.as_ref().iter().any(|byte| *byte != 0));
        assert_zeroizing(&context.capability);
        assert_eq!(format!("{context:?}"), "ConnectionContext(<authenticated>)");
    }

    #[test]
    fn pending_and_connection_context_are_statically_non_clone() {
        let _ = <PendingHandshake as AmbiguousIfClone<_>>::marker;
        let _ = <ConnectionContext as AmbiguousIfClone<_>>::marker;
    }

    fn assert_pending_mutation(mutate: impl FnOnce(&mut PendingHandshake)) {
        let fixture = HandshakeFixture::new();
        let (mut pending, hello) = fixture
            .service
            .start(&fixture.peer, fixture.client_hello.clone(), fixture.now)
            .unwrap();
        mutate(&mut pending);
        let finish = fixture.sign_finish(&hello.transcript);
        assert_eq!(
            fixture
                .service
                .finish(&fixture.peer, pending, finish, fixture.now)
                .unwrap_err(),
            StableCode::IdentityTranscriptMismatch
        );
    }

    fn assert_zeroizing(_: &zeroize::Zeroizing<[u8; 32]>) {}

    fn decode_hex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| (nibble(pair[0]) << 4) | nibble(pair[1]))
            .collect()
    }

    fn nibble(value: u8) -> u8 {
        match value {
            b'0'..=b'9' => value - b'0',
            b'a'..=b'f' => value - b'a' + 10,
            _ => panic!("test fixture is valid lowercase hex"),
        }
    }

    #[derive(Clone, Copy)]
    enum InvalidFinish {
        Digest,
        Signature,
    }

    trait AmbiguousIfClone<Marker> {
        fn marker() {}
    }

    impl<T: ?Sized> AmbiguousIfClone<()> for T {}

    struct CloneMarker;

    impl<T: Clone> AmbiguousIfClone<CloneMarker> for T {}

    #[derive(Clone)]
    enum EntropyStep {
        Value([u8; 32]),
        Zero,
        Fail,
    }

    struct ScriptedEntropy {
        steps: Mutex<VecDeque<EntropyStep>>,
    }

    impl ScriptedEntropy {
        fn new(steps: Vec<EntropyStep>) -> Self {
            Self {
                steps: Mutex::new(steps.into()),
            }
        }
    }

    impl EntropySource for ScriptedEntropy {
        fn fill_32(&self, output: &mut [u8; 32]) -> Result<(), ()> {
            match self.steps.lock().map_err(|_| ())?.pop_front() {
                Some(EntropyStep::Value(value)) => {
                    *output = value;
                    Ok(())
                }
                Some(EntropyStep::Zero) => {
                    *output = [0; 32];
                    Ok(())
                }
                Some(EntropyStep::Fail) => Err(()),
                None => {
                    *output = [0x66; 32];
                    Ok(())
                }
            }
        }
    }

    struct CountingEntropy {
        calls: Arc<AtomicUsize>,
    }

    impl EntropySource for CountingEntropy {
        fn fill_32(&self, output: &mut [u8; 32]) -> Result<(), ()> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            *output = [0x22_u8.wrapping_add(u8::try_from(call).unwrap_or(0)); 32];
            Ok(())
        }
    }

    struct HandshakeFixture {
        service: HandshakeService,
        runtime: RuntimeIdentity,
        peers: Vec<PeerIdentity>,
        peer: PeerIdentity,
        client_id: ClientId,
        client_hello: ClientHelloV1,
        client_keys: Vec<SigningKey>,
        now: UnixMillis,
    }

    impl HandshakeFixture {
        fn new() -> Self {
            Self::with_runtime(test_runtime(1)).unwrap()
        }

        fn with_clients(count: usize) -> Self {
            Self::with_runtime(test_runtime(count)).unwrap()
        }

        fn with_runtime(runtime: RuntimeIdentity) -> Result<Self, StableCode> {
            Self::with_runtime_and_entropy(
                runtime,
                vec![
                    EntropyStep::Value([0x22; 32]),
                    EntropyStep::Value([0x44; 32]),
                    EntropyStep::Value([0x55; 32]),
                ],
            )
        }

        fn with_entropy(steps: Vec<EntropyStep>) -> Result<Self, StableCode> {
            Self::with_runtime_and_entropy(test_runtime(1), steps)
        }

        fn with_runtime_and_entropy(
            runtime: RuntimeIdentity,
            steps: Vec<EntropyStep>,
        ) -> Result<Self, StableCode> {
            let client_keys = client_keys(runtime.clients.len());
            let peers = (0..runtime.clients.len())
                .map(|index| peer_for(&runtime, index))
                .collect::<Vec<_>>();
            let peer = peers[0];
            let client_id = runtime.clients[0].client_id.clone();
            let client_hello = hello_for(
                &runtime,
                0,
                Nonce32::new([0x11; 32]),
                vec![ProtocolVersion::new(1, 0)],
                RequestedMode::Required,
            );
            let service = build_service(runtime.clone(), STARTUP_NOW, steps)?;
            Ok(Self {
                service,
                runtime,
                peers,
                peer,
                client_id,
                client_hello,
                client_keys,
                now: NOW,
            })
        }

        fn hello(
            &self,
            client: usize,
            nonce: Nonce32,
            versions: Vec<ProtocolVersion>,
            mode: RequestedMode,
        ) -> ClientHelloV1 {
            hello_for(&self.runtime, client, nonce, versions, mode)
        }

        fn sign_finish(
            &self,
            transcript: &savana_kernel_protocol::HandshakeTranscriptV1,
        ) -> ClientFinishV1 {
            let digest = transcript_digest(transcript).unwrap();
            let client = self
                .runtime
                .clients
                .iter()
                .position(|configured| configured.client_id == transcript.client.client_id)
                .unwrap();
            let mut input = b"SAVANA_CLIENT_FINISH_V1\0".to_vec();
            input.extend_from_slice(digest.as_bytes());
            ClientFinishV1 {
                transcript_digest: digest,
                signature: Signature64::new(self.client_keys[client].sign(&input).to_bytes()),
            }
        }
    }

    fn build_service(
        runtime: RuntimeIdentity,
        startup_now: UnixMillis,
        steps: Vec<EntropyStep>,
    ) -> Result<HandshakeService, StableCode> {
        HandshakeService::new_with_entropy_for_test(
            runtime,
            DaemonSigningIdentity::from_seed_for_test([0x61; 32]),
            startup_now,
            Box::new(ScriptedEntropy::new(steps)),
        )
    }

    fn test_runtime(client_count: usize) -> RuntimeIdentity {
        let daemon_key = SigningKey::from_bytes(&[0x61; 32]);
        let keys = client_keys(client_count);
        let clients = keys
            .iter()
            .enumerate()
            .map(|(index, key)| ConfiguredClient {
                client_id: ClientId::try_from(if index == 0 {
                    "fixture-client".to_owned()
                } else {
                    format!("fixture-client-{index}")
                })
                .unwrap(),
                key_id: KeyId::try_from(if index == 0 {
                    "fixture-client-key".to_owned()
                } else {
                    format!("fixture-client-key-{index}")
                })
                .unwrap(),
                public_key: key.verifying_key().to_bytes(),
                role: InstallationClientRoleV1::JarvisKernelClient,
                peer_uid: 5_001 + u32::try_from(index).unwrap(),
                peer_gid: 6_001,
            })
            .collect::<Vec<_>>()
            .into_boxed_slice();
        RuntimeIdentity {
            protocol_major: 1,
            minimum_minor: 0,
            maximum_minor: 0,
            daemon_key_id: KeyId::try_from("fixture-daemon-key").unwrap(),
            daemon_public_key: daemon_key.verifying_key().to_bytes(),
            clients,
            release_digest: Digest32::new([0x31; 32]),
            policy_digest: Digest32::new([0x32; 32]),
            policy_version: 7,
            model_manifest_digest: Digest32::new([0x33; 32]),
            approval_key_set_digest: Digest32::new([0x34; 32]),
            resource_profile_digest: Digest32::new([0x35; 32]),
            release_expires_at: UnixMillis::new(20_000),
            policy_expires_at: UnixMillis::new(15_000),
        }
    }

    fn client_keys(count: usize) -> Vec<SigningKey> {
        (0..count)
            .map(|index| {
                SigningKey::from_bytes(&[0x71_u8.wrapping_add(u8::try_from(index).unwrap()); 32])
            })
            .collect()
    }

    fn hello_for(
        runtime: &RuntimeIdentity,
        client: usize,
        nonce: Nonce32,
        versions: Vec<ProtocolVersion>,
        mode: RequestedMode,
    ) -> ClientHelloV1 {
        ClientHelloV1 {
            client_nonce: nonce,
            supported_versions: versions,
            client_id: runtime.clients[client].client_id.clone(),
            client_key_id: runtime.clients[client].key_id.clone(),
            requested_mode: mode,
        }
    }

    fn peer_for(runtime: &RuntimeIdentity, client: usize) -> PeerIdentity {
        PeerIdentity::new_for_test(
            runtime.clients[client].peer_uid,
            runtime.clients[client].peer_gid,
        )
    }
}
