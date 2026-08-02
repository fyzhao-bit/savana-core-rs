use std::time::Instant;

use ed25519_dalek::SigningKey;
use savana_kernel_protocol::v2::{
    BootIdV2, KernelServiceHandshakeEdgeV2, Nonce32V2, PeerIdentityBindingV2,
    V2PendingServerHandshake, V2ServerHandshake, V2ServerTransportSession, VerifiedV2HandshakePeer,
};
use savana_kernel_protocol::StableCode;
use x25519_dalek::StaticSecret;
use zeroize::{Zeroize, Zeroizing};

use crate::v2_state_owner::{StateOwnerErrorV2, StateOwnerV2};

const MAX_HANDSHAKE_REPLAYS: usize = 65_536;
const MAX_VERIFIED_PROCESS_BINDINGS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KernelV2HandshakeError {
    Malformed,
    IdentityRejected,
    Replay,
    Busy,
    DeadlineExceeded,
    Unavailable,
}

struct HandshakeReservationV2(Zeroizing<[u8; 32]>);

impl std::fmt::Debug for HandshakeReservationV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("HandshakeReservationV2(<redacted>)")
    }
}

pub(crate) struct StartedKernelV2Handshake {
    reservation: HandshakeReservationV2,
    server_hello: Vec<u8>,
}

impl std::fmt::Debug for StartedKernelV2Handshake {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StartedKernelV2Handshake")
            .field("reservation", &self.reservation)
            .field("server_hello_bytes", &self.server_hello.len())
            .finish()
    }
}

impl StartedKernelV2Handshake {
    pub(crate) fn server_hello(&self) -> &[u8] {
        &self.server_hello
    }
}

pub(crate) struct CompletedKernelV2Handshake {
    accepted_record: Vec<u8>,
    session: V2ServerTransportSession,
    peer: VerifiedV2HandshakePeer,
}

impl std::fmt::Debug for CompletedKernelV2Handshake {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CompletedKernelV2Handshake")
            .field("accepted_record_bytes", &self.accepted_record.len())
            .field("session", &self.session)
            .field("peer", &self.peer)
            .finish()
    }
}

impl CompletedKernelV2Handshake {
    pub(crate) fn accepted_record(&self) -> &[u8] {
        &self.accepted_record
    }

    pub(crate) const fn peer(&self) -> &VerifiedV2HandshakePeer {
        &self.peer
    }

    pub(crate) fn into_parts(self) -> (Vec<u8>, V2ServerTransportSession, VerifiedV2HandshakePeer) {
        (self.accepted_record, self.session, self.peer)
    }
}

enum HandshakeOwnerCommandV2 {
    Start {
        observed_peer: PeerIdentityBindingV2,
        client_hello: Vec<u8>,
        expires_at: Instant,
    },
    Finish {
        reservation: HandshakeReservationV2,
        client_finish: Vec<u8>,
    },
}

enum HandshakeOwnerResponseV2 {
    Started(StartedKernelV2Handshake),
    Completed(Box<CompletedKernelV2Handshake>),
}

struct PendingHandshakeV2 {
    reservation: [u8; 32],
    observed_peer: PeerIdentityBindingV2,
    expires_at: Instant,
    pending: V2PendingServerHandshake,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HandshakeReplayKeyV2 {
    observed_peer: PeerIdentityBindingV2,
    client_boot_id: BootIdV2,
    client_nonce: Nonce32V2,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct VerifiedProcessBootV2 {
    observed_peer: PeerIdentityBindingV2,
    client_boot_id: BootIdV2,
}

pub(crate) struct KernelV2HandshakeOwner {
    owner: StateOwnerV2<
        HandshakeOwnerCommandV2,
        Result<HandshakeOwnerResponseV2, KernelV2HandshakeError>,
    >,
}

impl std::fmt::Debug for KernelV2HandshakeOwner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("KernelV2HandshakeOwner")
            .field("owner", &self.owner)
            .finish_non_exhaustive()
    }
}

impl KernelV2HandshakeOwner {
    pub(crate) fn spawn(
        edge: KernelServiceHandshakeEdgeV2,
        client_public_key: [u8; 32],
        server_signing_key: SigningKey,
        capacity: usize,
    ) -> Result<Self, KernelV2HandshakeError> {
        if capacity == 0 {
            return Err(KernelV2HandshakeError::Unavailable);
        }
        let mut pending = Vec::<PendingHandshakeV2>::with_capacity(capacity);
        let mut replay = Vec::<HandshakeReplayKeyV2>::new();
        let mut process_boots = Vec::<VerifiedProcessBootV2>::new();
        let owner = StateOwnerV2::spawn("savana-kerneld-v2-handshake", capacity, move |command| {
            pending.retain(|entry| entry.expires_at > Instant::now());
            Ok(match command {
                HandshakeOwnerCommandV2::Start {
                    observed_peer,
                    client_hello,
                    expires_at,
                } => start_handshake(
                    edge,
                    client_public_key,
                    &server_signing_key,
                    capacity,
                    &mut pending,
                    &mut replay,
                    &process_boots,
                    observed_peer,
                    &client_hello,
                    expires_at,
                )
                .map(HandshakeOwnerResponseV2::Started),
                HandshakeOwnerCommandV2::Finish {
                    mut reservation,
                    client_finish,
                } => {
                    let result = finish_handshake(
                        &mut pending,
                        &mut process_boots,
                        &reservation.0,
                        &client_finish,
                    )
                    .map(Box::new)
                    .map(HandshakeOwnerResponseV2::Completed);
                    reservation.0.zeroize();
                    result
                }
            })
        })
        .map_err(map_state_owner_error)?;
        Ok(Self { owner })
    }

    pub(crate) fn start(
        &self,
        observed_peer: PeerIdentityBindingV2,
        client_hello: Vec<u8>,
        deadline: Instant,
    ) -> Result<StartedKernelV2Handshake, KernelV2HandshakeError> {
        let response = self
            .owner
            .request(
                HandshakeOwnerCommandV2::Start {
                    observed_peer,
                    client_hello,
                    expires_at: deadline,
                },
                deadline,
            )
            .map_err(map_state_owner_error)??;
        match response {
            HandshakeOwnerResponseV2::Started(started) => Ok(started),
            HandshakeOwnerResponseV2::Completed(_) => Err(KernelV2HandshakeError::Unavailable),
        }
    }

    pub(crate) fn finish(
        &self,
        started: StartedKernelV2Handshake,
        client_finish: Vec<u8>,
        deadline: Instant,
    ) -> Result<CompletedKernelV2Handshake, KernelV2HandshakeError> {
        let response = self
            .owner
            .request(
                HandshakeOwnerCommandV2::Finish {
                    reservation: started.reservation,
                    client_finish,
                },
                deadline,
            )
            .map_err(map_state_owner_error)??;
        match response {
            HandshakeOwnerResponseV2::Completed(completed) => Ok(*completed),
            HandshakeOwnerResponseV2::Started(_) => Err(KernelV2HandshakeError::Unavailable),
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn start_handshake(
    edge: KernelServiceHandshakeEdgeV2,
    client_public_key: [u8; 32],
    server_signing_key: &SigningKey,
    pending_capacity: usize,
    pending_entries: &mut Vec<PendingHandshakeV2>,
    replay_entries: &mut Vec<HandshakeReplayKeyV2>,
    process_boots: &[VerifiedProcessBootV2],
    observed_peer: PeerIdentityBindingV2,
    client_hello: &[u8],
    expires_at: Instant,
) -> Result<StartedKernelV2Handshake, KernelV2HandshakeError> {
    if Instant::now() >= expires_at {
        return Err(KernelV2HandshakeError::DeadlineExceeded);
    }
    if pending_entries.len() >= pending_capacity || replay_entries.len() >= MAX_HANDSHAKE_REPLAYS {
        return Err(KernelV2HandshakeError::Busy);
    }
    let server_nonce = Nonce32V2::new(draw_nonzero()?);
    let ephemeral_secret = StaticSecret::from(draw_nonzero()?);
    let (pending, server_hello) = V2ServerHandshake::accept_client_hello(
        edge,
        observed_peer.clone(),
        client_hello,
        server_nonce,
        ephemeral_secret,
        client_public_key,
        server_signing_key,
    )
    .map_err(map_protocol_error)?;
    if process_boots.iter().any(|entry| {
        entry.observed_peer == observed_peer && entry.client_boot_id != pending.client_boot_id()
    }) {
        return Err(KernelV2HandshakeError::IdentityRejected);
    }
    let replay_key = HandshakeReplayKeyV2 {
        observed_peer: observed_peer.clone(),
        client_boot_id: pending.client_boot_id(),
        client_nonce: pending.client_nonce(),
    };
    if replay_entries.iter().any(|entry| entry == &replay_key) {
        return Err(KernelV2HandshakeError::Replay);
    }
    replay_entries
        .try_reserve(1)
        .map_err(|_| KernelV2HandshakeError::Unavailable)?;
    pending_entries
        .try_reserve(1)
        .map_err(|_| KernelV2HandshakeError::Unavailable)?;
    let reservation = draw_unique_reservation(pending_entries)?;
    replay_entries.push(replay_key);
    pending_entries.push(PendingHandshakeV2 {
        reservation,
        observed_peer,
        expires_at,
        pending,
    });
    Ok(StartedKernelV2Handshake {
        reservation: HandshakeReservationV2(Zeroizing::new(reservation)),
        server_hello,
    })
}

fn finish_handshake(
    pending_entries: &mut Vec<PendingHandshakeV2>,
    process_boots: &mut Vec<VerifiedProcessBootV2>,
    reservation: &[u8; 32],
    client_finish: &[u8],
) -> Result<CompletedKernelV2Handshake, KernelV2HandshakeError> {
    let index = pending_entries
        .iter()
        .position(|entry| &entry.reservation == reservation)
        .ok_or(KernelV2HandshakeError::IdentityRejected)?;
    let entry = pending_entries.swap_remove(index);
    if Instant::now() >= entry.expires_at {
        return Err(KernelV2HandshakeError::DeadlineExceeded);
    }
    let (accepted_record, session, peer) = entry
        .pending
        .accept_client_finish(client_finish)
        .map_err(map_protocol_error)?;
    if let Some(existing) = process_boots
        .iter()
        .find(|existing| existing.observed_peer == entry.observed_peer)
    {
        if existing.client_boot_id != peer.client_boot_id() {
            return Err(KernelV2HandshakeError::IdentityRejected);
        }
    } else {
        if process_boots.len() >= MAX_VERIFIED_PROCESS_BINDINGS {
            return Err(KernelV2HandshakeError::Busy);
        }
        process_boots
            .try_reserve(1)
            .map_err(|_| KernelV2HandshakeError::Unavailable)?;
        process_boots.push(VerifiedProcessBootV2 {
            observed_peer: entry.observed_peer,
            client_boot_id: peer.client_boot_id(),
        });
    }
    Ok(CompletedKernelV2Handshake {
        accepted_record,
        session,
        peer,
    })
}

fn draw_nonzero() -> Result<[u8; 32], KernelV2HandshakeError> {
    for _ in 0..4 {
        let mut bytes = [0_u8; 32];
        getrandom::getrandom(&mut bytes).map_err(|_| KernelV2HandshakeError::Unavailable)?;
        if bytes != [0; 32] {
            return Ok(bytes);
        }
    }
    Err(KernelV2HandshakeError::Unavailable)
}

fn draw_unique_reservation(
    pending_entries: &[PendingHandshakeV2],
) -> Result<[u8; 32], KernelV2HandshakeError> {
    for _ in 0..4 {
        let reservation = draw_nonzero()?;
        if pending_entries
            .iter()
            .all(|entry| entry.reservation != reservation)
        {
            return Ok(reservation);
        }
    }
    Err(KernelV2HandshakeError::Unavailable)
}

const fn map_protocol_error(
    error: savana_kernel_protocol::ProtocolError,
) -> KernelV2HandshakeError {
    match error.code() {
        StableCode::IdentityReplay => KernelV2HandshakeError::Replay,
        StableCode::ProtocolAllocationRefused | StableCode::ProtocolFrameTooLarge => {
            KernelV2HandshakeError::Unavailable
        }
        StableCode::ProtocolMalformedFrame
        | StableCode::ProtocolTruncatedFrame
        | StableCode::ProtocolMalformedCbor
        | StableCode::ProtocolNonCanonicalCbor
        | StableCode::ProtocolNestingTooDeep
        | StableCode::ProtocolUnknownField
        | StableCode::ProtocolUnknownOperation
        | StableCode::ProtocolUnsupportedVersion => KernelV2HandshakeError::Malformed,
        _ => KernelV2HandshakeError::IdentityRejected,
    }
}

const fn map_state_owner_error(error: StateOwnerErrorV2) -> KernelV2HandshakeError {
    match error {
        StateOwnerErrorV2::RuntimeBusy => KernelV2HandshakeError::Busy,
        StateOwnerErrorV2::DeadlineExceeded => KernelV2HandshakeError::DeadlineExceeded,
        StateOwnerErrorV2::RuntimeUnavailable => KernelV2HandshakeError::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use ed25519_dalek::SigningKey;
    use savana_kernel_protocol::v2::{
        derive_ed25519_key_id_v2, BootIdV2, Digest32V2, EndpointRoleV2,
        KernelServiceHandshakeEdgeV2, Nonce32V2, PeerIdentityBindingV2, ServiceIdentityV2,
        V2ClientHandshake,
    };
    use x25519_dalek::StaticSecret;

    use super::{KernelV2HandshakeError, KernelV2HandshakeOwner};

    fn edge(client_key: &SigningKey, server_key: &SigningKey) -> KernelServiceHandshakeEdgeV2 {
        KernelServiceHandshakeEdgeV2::from_verified_deployment(
            EndpointRoleV2::AgentKernel,
            Digest32V2::new([1; 32]),
            ServiceIdentityV2::new([2; 32]),
            ServiceIdentityV2::new([3; 32]),
            derive_ed25519_key_id_v2(client_key.verifying_key().to_bytes()),
            derive_ed25519_key_id_v2(server_key.verifying_key().to_bytes()),
            BootIdV2::new([4; 32]),
            5,
            Digest32V2::new([6; 32]),
            7,
            8,
            Digest32V2::new([9; 32]),
            Digest32V2::new([10; 32]),
            Digest32V2::new([11; 32]),
            Digest32V2::new([12; 32]),
            Digest32V2::new([13; 32]),
            Digest32V2::new([14; 32]),
        )
        .unwrap()
    }

    fn observed() -> PeerIdentityBindingV2 {
        PeerIdentityBindingV2::linux(501, 502, 503, 504, Digest32V2::new([0x15; 32])).unwrap()
    }

    fn client_hello(
        edge: KernelServiceHandshakeEdgeV2,
        boot: u8,
        nonce: u8,
        client_key: &SigningKey,
    ) -> (V2ClientHandshake, Vec<u8>) {
        V2ClientHandshake::start(
            edge,
            BootIdV2::new([boot; 32]),
            Nonce32V2::new([nonce; 32]),
            observed(),
            StaticSecret::from([nonce.wrapping_add(1); 32]),
            client_key,
        )
        .unwrap()
    }

    #[test]
    fn owner_completes_exact_handshake_and_rejects_nonce_replay() {
        let client_key = SigningKey::from_bytes(&[0x21; 32]);
        let server_key = SigningKey::from_bytes(&[0x22; 32]);
        let server_public_key = server_key.verifying_key().to_bytes();
        let edge = edge(&client_key, &server_key);
        let owner = KernelV2HandshakeOwner::spawn(
            edge,
            client_key.verifying_key().to_bytes(),
            server_key,
            4,
        )
        .unwrap();
        let (client_pending, hello) = client_hello(edge, 0x23, 0x24, &client_key);
        let started = owner
            .start(
                observed(),
                hello.clone(),
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap();
        assert!(matches!(
            owner.start(observed(), hello, Instant::now() + Duration::from_secs(1),),
            Err(KernelV2HandshakeError::Replay)
        ));
        let (finish, mut client_session) = client_pending
            .accept_server_hello(started.server_hello(), server_public_key, &client_key)
            .unwrap();
        let completed = owner
            .finish(started, finish, Instant::now() + Duration::from_secs(1))
            .unwrap();
        assert_eq!(completed.peer().client_boot_id(), BootIdV2::new([0x23; 32]));
        client_session
            .accept_server_confirmation(completed.accepted_record())
            .unwrap();
    }

    #[test]
    fn same_measured_process_cannot_change_authenticated_boot_id() {
        let client_key = SigningKey::from_bytes(&[0x31; 32]);
        let server_key = SigningKey::from_bytes(&[0x32; 32]);
        let server_public_key = server_key.verifying_key().to_bytes();
        let edge = edge(&client_key, &server_key);
        let owner = KernelV2HandshakeOwner::spawn(
            edge,
            client_key.verifying_key().to_bytes(),
            server_key,
            4,
        )
        .unwrap();
        let (client_pending, hello) = client_hello(edge, 0x33, 0x34, &client_key);
        let started = owner
            .start(observed(), hello, Instant::now() + Duration::from_secs(1))
            .unwrap();
        let (finish, _) = client_pending
            .accept_server_hello(started.server_hello(), server_public_key, &client_key)
            .unwrap();
        owner
            .finish(started, finish, Instant::now() + Duration::from_secs(1))
            .unwrap();

        let (_, changed_boot_hello) = client_hello(edge, 0x35, 0x36, &client_key);
        assert!(matches!(
            owner.start(
                observed(),
                changed_boot_hello,
                Instant::now() + Duration::from_secs(1),
            ),
            Err(KernelV2HandshakeError::IdentityRejected)
        ));
    }

    #[test]
    fn pending_handshake_table_is_bounded() {
        let client_key = SigningKey::from_bytes(&[0x41; 32]);
        let server_key = SigningKey::from_bytes(&[0x42; 32]);
        let edge = edge(&client_key, &server_key);
        let owner = KernelV2HandshakeOwner::spawn(
            edge,
            client_key.verifying_key().to_bytes(),
            server_key,
            1,
        )
        .unwrap();
        let (_, first) = client_hello(edge, 0x43, 0x44, &client_key);
        let (_, second) = client_hello(edge, 0x43, 0x45, &client_key);
        let _started = owner
            .start(observed(), first, Instant::now() + Duration::from_secs(1))
            .unwrap();
        assert!(matches!(
            owner.start(observed(), second, Instant::now() + Duration::from_secs(1),),
            Err(KernelV2HandshakeError::Busy)
        ));
    }
}
