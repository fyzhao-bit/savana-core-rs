use chacha20poly1305::aead::{AeadInPlace as _, KeyInit as _};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, Tag};
use ed25519_dalek::{
    Signature as Ed25519Signature, Signer as _, SigningKey, VerifyingKey as Ed25519VerifyingKey,
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac as _};
use sha2::{Digest as _, Sha256};
use unicode_normalization::UnicodeNormalization as _;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::{ProtocolError, StableCode};

use super::{
    cbor::{scan_single, V2DecodeContext},
    BootIdV2, Digest32V2, Ed25519KeyIdV2, EndpointRoleV2, Nonce32V2, RequestIdV2,
    ServiceIdentityV2, PROTOCOL_MAJOR, PROTOCOL_MINOR, SUITE_ID,
};

const HANDSHAKE_MAGIC: &[u8; 8] = b"SAVANA2\0";
const RECORD_MAGIC: &[u8; 4] = b"SV2R";
const HANDSHAKE_PREFIX_BYTES: usize = 16;
const HANDSHAKE_LENGTH_BYTES: usize = 4;
pub const HANDSHAKE_FRAME_HEADER_BYTES_V2: usize = HANDSHAKE_PREFIX_BYTES + HANDSHAKE_LENGTH_BYTES;
pub const MAX_HANDSHAKE_BODY_BYTES_V2: usize = 16 * 1024;
pub const RECORD_FRAME_HEADER_BYTES_V2: usize = 10;
pub const MAX_RECORD_HEADER_BYTES_V2: usize = 512;
const MAX_RECORD_PLAINTEXT_BYTES: usize = 8 * 1024 * 1024;
const AEAD_TAG_BYTES: usize = 16;
pub const MAX_RECORD_CIPHERTEXT_BYTES_V2: usize = MAX_RECORD_PLAINTEXT_BYTES + AEAD_TAG_BYTES;
const CLIENT_HELLO_FIELDS: u64 = 7;
const TRANSCRIPT_FIELDS: u64 = 28;
const SERVER_HELLO_FIELDS: u64 = 3;
const CLIENT_FINISH_FIELDS: u64 = 4;
const HANDSHAKE_ACCEPTED_FIELDS: u64 = 2;
const RECORD_HEADER_FIELDS: u64 = 11;
const REQUESTED_MODE_REQUIRED: u16 = 1;
const HANDSHAKE_TRANSCRIPT_DOMAIN: &[u8] = b"SAVANA_HANDSHAKE_TRANSCRIPT_V2\0";
const SERVER_HELLO_DOMAIN: &[u8] = b"SAVANA_SERVER_HELLO_V2\0";
const CLIENT_FINISH_DOMAIN: &[u8] = b"SAVANA_CLIENT_FINISH_V2\0";
const HANDSHAKE_SALT_DOMAIN: &[u8] = b"SAVANA_HANDSHAKE_SALT_V2\0";
const SESSION_KEYS_DOMAIN: &[u8] = b"SAVANA_SESSION_KEYS_V2\0";
const C2S_KEY_LABEL: &[u8] = b"SAVANA_C2S_KEY_V2\0";
const S2C_KEY_LABEL: &[u8] = b"SAVANA_S2C_KEY_V2\0";
const C2S_IV_LABEL: &[u8] = b"SAVANA_C2S_IV_V2\0";
const S2C_IV_LABEL: &[u8] = b"SAVANA_S2C_IV_V2\0";
const CLIENT_CONFIRM_LABEL: &[u8] = b"SAVANA_CLIENT_CONFIRM_V2\0";
const SERVER_CONFIRM_LABEL: &[u8] = b"SAVANA_SERVER_CONFIRM_V2\0";
const CLIENT_CONFIRM_MAC_DOMAIN: &[u8] = b"SAVANA_CLIENT_CONFIRM_MAC_V2\0";
const SERVER_CONFIRM_MAC_DOMAIN: &[u8] = b"SAVANA_SERVER_CONFIRM_MAC_V2\0";
const RECORD_AAD_DOMAIN: &[u8] = b"SAVANA_RECORD_AAD_V2\0";
const ED25519_KEY_ID_DOMAIN: &[u8] = b"savana.ed25519-key-id.v2\0";

type HmacSha256 = Hmac<Sha256>;
type ClientFinishFieldsV2 = (Digest32V2, [u8; 64], [u8; 64], [u8; 32]);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HandshakeMessageKindV2 {
    ClientHello,
    ServerHello,
    ClientFinish,
}

impl HandshakeMessageKindV2 {
    const fn tag(self) -> u8 {
        match self {
            Self::ClientHello => 1,
            Self::ServerHello => 2,
            Self::ClientFinish => 3,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DirectionV2 {
    ClientToServer,
    ServerToClient,
}

impl DirectionV2 {
    const fn tag(self) -> u16 {
        match self {
            Self::ClientToServer => 1,
            Self::ServerToClient => 2,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MessageKindV2 {
    HandshakeAccepted,
    ApplicationRequest,
    ApplicationResponse,
}

impl MessageKindV2 {
    const fn tag(self) -> u16 {
        match self {
            Self::HandshakeAccepted => 1,
            Self::ApplicationRequest => 2,
            Self::ApplicationResponse => 3,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KernelServiceHandshakeEdgeV2 {
    role: EndpointRoleV2,
    installation_id: Digest32V2,
    client_identity: ServiceIdentityV2,
    server_identity: ServiceIdentityV2,
    client_key_id: Ed25519KeyIdV2,
    server_key_id: Ed25519KeyIdV2,
    server_boot_id: BootIdV2,
    active_state_manifest_sequence: u64,
    active_state_manifest_digest: Digest32V2,
    deployment_generation: u64,
    effect_fence_epoch: u64,
    release_identity_digest: Digest32V2,
    model_set_identity_digest: Digest32V2,
    resource_profile_identity_digest: Digest32V2,
    approval_lock_identity_digest: Digest32V2,
    planner_lock_identity_digest: Digest32V2,
    executor_key_lock_identity_digest: Digest32V2,
}

impl KernelServiceHandshakeEdgeV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn from_verified_deployment(
        role: EndpointRoleV2,
        installation_id: Digest32V2,
        client_identity: ServiceIdentityV2,
        server_identity: ServiceIdentityV2,
        client_key_id: Ed25519KeyIdV2,
        server_key_id: Ed25519KeyIdV2,
        server_boot_id: BootIdV2,
        active_state_manifest_sequence: u64,
        active_state_manifest_digest: Digest32V2,
        deployment_generation: u64,
        effect_fence_epoch: u64,
        release_identity_digest: Digest32V2,
        model_set_identity_digest: Digest32V2,
        resource_profile_identity_digest: Digest32V2,
        approval_lock_identity_digest: Digest32V2,
        planner_lock_identity_digest: Digest32V2,
        executor_key_lock_identity_digest: Digest32V2,
    ) -> Result<Self, ProtocolError> {
        let value = Self {
            role,
            installation_id,
            client_identity,
            server_identity,
            client_key_id,
            server_key_id,
            server_boot_id,
            active_state_manifest_sequence,
            active_state_manifest_digest,
            deployment_generation,
            effect_fence_epoch,
            release_identity_digest,
            model_set_identity_digest,
            resource_profile_identity_digest,
            approval_lock_identity_digest,
            planner_lock_identity_digest,
            executor_key_lock_identity_digest,
        };
        value.validate()?;
        Ok(value)
    }

    pub const fn role(self) -> EndpointRoleV2 {
        self.role
    }

    pub const fn installation_id(self) -> Digest32V2 {
        self.installation_id
    }

    pub const fn client_identity(self) -> ServiceIdentityV2 {
        self.client_identity
    }

    pub const fn server_identity(self) -> ServiceIdentityV2 {
        self.server_identity
    }

    pub const fn server_boot_id(self) -> BootIdV2 {
        self.server_boot_id
    }

    pub const fn active_state_manifest_digest(self) -> Digest32V2 {
        self.active_state_manifest_digest
    }

    pub const fn deployment_generation(self) -> u64 {
        self.deployment_generation
    }

    fn validate(&self) -> Result<(), ProtocolError> {
        if !matches!(
            self.role,
            EndpointRoleV2::AgentKernel
                | EndpointRoleV2::IngressKernel
                | EndpointRoleV2::KernelExecutor
                | EndpointRoleV2::AgentApproval
                | EndpointRoleV2::IngressApproval
                | EndpointRoleV2::ApprovalAdmin
        ) || self.active_state_manifest_sequence == 0
            || self.deployment_generation == 0
            || self.effect_fence_epoch == 0
            || [
                self.installation_id.as_bytes().as_slice(),
                self.client_identity.as_bytes().as_slice(),
                self.server_identity.as_bytes().as_slice(),
                self.client_key_id.as_bytes().as_slice(),
                self.server_key_id.as_bytes().as_slice(),
                self.server_boot_id.as_bytes().as_slice(),
                self.active_state_manifest_digest.as_bytes().as_slice(),
                self.release_identity_digest.as_bytes().as_slice(),
                self.model_set_identity_digest.as_bytes().as_slice(),
                self.resource_profile_identity_digest.as_bytes().as_slice(),
                self.approval_lock_identity_digest.as_bytes().as_slice(),
                self.planner_lock_identity_digest.as_bytes().as_slice(),
                self.executor_key_lock_identity_digest.as_bytes().as_slice(),
            ]
            .into_iter()
            .any(is_zero)
        {
            return Err(identity_mismatch());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerIdentityBindingV2 {
    Linux {
        uid: u32,
        gid: u32,
        pid: u32,
        process_start_time: u64,
        executable_measurement: Digest32V2,
    },
    MacOs {
        audit_token: [u8; 32],
        euid: u32,
        egid: u32,
        bundle_id: String,
        team_id: String,
        code_directory_digest: Digest32V2,
    },
}

impl PeerIdentityBindingV2 {
    pub fn linux(
        uid: u32,
        gid: u32,
        pid: u32,
        process_start_time: u64,
        executable_measurement: Digest32V2,
    ) -> Result<Self, ProtocolError> {
        if pid == 0 || process_start_time == 0 || is_zero(executable_measurement.as_bytes()) {
            return Err(identity_mismatch());
        }
        Ok(Self::Linux {
            uid,
            gid,
            pid,
            process_start_time,
            executable_measurement,
        })
    }

    pub fn macos(
        audit_token: [u8; 32],
        euid: u32,
        egid: u32,
        bundle_id: String,
        team_id: String,
        code_directory_digest: Digest32V2,
    ) -> Result<Self, ProtocolError> {
        if is_zero(&audit_token)
            || !valid_identifier(&bundle_id)
            || !valid_identifier(&team_id)
            || is_zero(code_directory_digest.as_bytes())
        {
            return Err(identity_mismatch());
        }
        Ok(Self::MacOs {
            audit_token,
            euid,
            egid,
            bundle_id,
            team_id,
            code_directory_digest,
        })
    }

    fn validate(&self) -> Result<(), ProtocolError> {
        match self {
            Self::Linux {
                pid,
                process_start_time,
                executable_measurement,
                ..
            } if *pid != 0
                && *process_start_time != 0
                && !is_zero(executable_measurement.as_bytes()) =>
            {
                Ok(())
            }
            Self::MacOs {
                audit_token,
                bundle_id,
                team_id,
                code_directory_digest,
                ..
            } if !is_zero(audit_token)
                && valid_identifier(bundle_id)
                && valid_identifier(team_id)
                && !is_zero(code_directory_digest.as_bytes()) =>
            {
                Ok(())
            }
            _ => Err(identity_mismatch()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedV2HandshakePeer {
    role: EndpointRoleV2,
    client_identity: ServiceIdentityV2,
    client_boot_id: BootIdV2,
    transcript_digest: Digest32V2,
}

impl VerifiedV2HandshakePeer {
    pub const fn role(self) -> EndpointRoleV2 {
        self.role
    }

    pub const fn client_identity(self) -> ServiceIdentityV2 {
        self.client_identity
    }

    pub const fn client_boot_id(self) -> BootIdV2 {
        self.client_boot_id
    }

    pub const fn transcript_digest(self) -> Digest32V2 {
        self.transcript_digest
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ClientHelloBodyV2 {
    client_identity: ServiceIdentityV2,
    client_boot_id: BootIdV2,
    client_key_id: Ed25519KeyIdV2,
    client_nonce: Nonce32V2,
    client_ephemeral_x25519: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HandshakeTranscriptV2 {
    edge: KernelServiceHandshakeEdgeV2,
    client_boot_id: BootIdV2,
    client_nonce: Nonce32V2,
    server_nonce: Nonce32V2,
    client_ephemeral_x25519: [u8; 32],
    server_ephemeral_x25519: [u8; 32],
    observed_client_peer: PeerIdentityBindingV2,
}

pub struct V2ClientHandshake {
    edge: KernelServiceHandshakeEdgeV2,
    hello: ClientHelloBodyV2,
    expected_observed_peer: PeerIdentityBindingV2,
    ephemeral_secret: StaticSecret,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum V2ServerHelloAcceptanceErrorV2 {
    GenerationAuthorityMismatch,
    Terminal(ProtocolError),
}

impl std::fmt::Debug for V2ClientHandshake {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("V2ClientHandshake(<ephemeral>)")
    }
}

impl V2ClientHandshake {
    pub fn start(
        edge: KernelServiceHandshakeEdgeV2,
        client_boot_id: BootIdV2,
        client_nonce: Nonce32V2,
        expected_observed_peer: PeerIdentityBindingV2,
        ephemeral_secret: StaticSecret,
        client_signing_key: &SigningKey,
    ) -> Result<(Self, Vec<u8>), ProtocolError> {
        edge.validate()?;
        expected_observed_peer.validate()?;
        require_key_id(
            edge.client_key_id,
            client_signing_key.verifying_key().to_bytes(),
        )?;
        let client_ephemeral_x25519 = X25519PublicKey::from(&ephemeral_secret).to_bytes();
        if is_zero(client_boot_id.as_bytes())
            || is_zero(client_nonce.as_bytes())
            || is_zero(&client_ephemeral_x25519)
        {
            return Err(identity_mismatch());
        }
        let hello = ClientHelloBodyV2 {
            client_identity: edge.client_identity,
            client_boot_id,
            client_key_id: edge.client_key_id,
            client_nonce,
            client_ephemeral_x25519,
        };
        let body = encode_client_hello_body(&hello)?;
        let frame = encode_handshake_frame(edge.role, HandshakeMessageKindV2::ClientHello, &body)?;
        Ok((
            Self {
                edge,
                hello,
                expected_observed_peer,
                ephemeral_secret,
            },
            frame,
        ))
    }

    pub fn accept_server_hello(
        self,
        frame: &[u8],
        server_public_key: [u8; 32],
        client_signing_key: &SigningKey,
    ) -> Result<(Vec<u8>, V2ClientTransportSession), ProtocolError> {
        self.accept_server_hello_classified(frame, server_public_key, client_signing_key)
            .map_err(|error| match error {
                V2ServerHelloAcceptanceErrorV2::GenerationAuthorityMismatch => identity_mismatch(),
                V2ServerHelloAcceptanceErrorV2::Terminal(error) => error,
            })
    }

    pub fn accept_server_hello_classified(
        self,
        frame: &[u8],
        server_public_key: [u8; 32],
        client_signing_key: &SigningKey,
    ) -> Result<(Vec<u8>, V2ClientTransportSession), V2ServerHelloAcceptanceErrorV2> {
        let terminal = V2ServerHelloAcceptanceErrorV2::Terminal;
        require_key_id(self.edge.server_key_id, server_public_key).map_err(terminal)?;
        require_key_id(
            self.edge.client_key_id,
            client_signing_key.verifying_key().to_bytes(),
        )
        .map_err(terminal)?;
        let body =
            decode_handshake_frame(frame, self.edge.role, HandshakeMessageKindV2::ServerHello)
                .map_err(terminal)?;
        let (transcript_bytes, transcript_digest, server_signature) =
            decode_server_hello_body(body).map_err(terminal)?;
        let expected_digest = transcript_digest_for(&transcript_bytes);
        if transcript_digest != expected_digest {
            return Err(terminal(identity_mismatch()));
        }
        verify_server_signature(transcript_digest, server_signature, server_public_key)
            .map_err(terminal)?;
        let transcript = decode_transcript(&transcript_bytes).map_err(terminal)?;
        if transcript.edge != self.edge
            && generation_authority_is_the_only_transcript_mismatch(
                &self.edge,
                &self.hello,
                &self.expected_observed_peer,
                &transcript,
            )
        {
            return Err(V2ServerHelloAcceptanceErrorV2::GenerationAuthorityMismatch);
        }
        require_client_transcript(
            &self.edge,
            &self.hello,
            &self.expected_observed_peer,
            &transcript,
        )
        .map_err(terminal)?;
        let shared_secret = self
            .ephemeral_secret
            .diffie_hellman(&X25519PublicKey::from(transcript.server_ephemeral_x25519))
            .to_bytes();
        let keys = derive_session_keys(
            shared_secret,
            transcript.client_nonce,
            transcript.server_nonce,
            transcript_digest,
            self.edge.role,
        )
        .map_err(terminal)?;
        let client_signature =
            sign_client_finish(transcript_digest, server_signature, client_signing_key);
        let client_confirm_mac = client_confirm_mac(
            &keys.client_confirm_key,
            transcript_digest,
            server_signature,
            client_signature,
        )
        .map_err(terminal)?;
        let finish_body = encode_client_finish_body(
            transcript_digest,
            server_signature,
            client_signature,
            client_confirm_mac,
        )
        .map_err(terminal)?;
        let finish_frame = encode_handshake_frame(
            self.edge.role,
            HandshakeMessageKindV2::ClientFinish,
            &finish_body,
        )
        .map_err(terminal)?;
        let expected_server_confirm_mac = server_confirm_mac(
            &keys.server_confirm_key,
            transcript_digest,
            client_confirm_mac,
        )
        .map_err(terminal)?;
        Ok((
            finish_frame,
            V2ClientTransportSession {
                role: self.edge.role,
                transcript_digest,
                c2s_key: keys.c2s_key,
                s2c_key: keys.s2c_key,
                c2s_iv: keys.c2s_iv,
                s2c_iv: keys.s2c_iv,
                expected_server_confirm_mac,
                confirmed: false,
                request_binding: None,
                response_opened: false,
            },
        ))
    }
}

pub struct V2ServerHandshake;

impl V2ServerHandshake {
    #[allow(clippy::too_many_arguments)]
    pub fn accept_client_hello(
        edge: KernelServiceHandshakeEdgeV2,
        observed_client_peer: PeerIdentityBindingV2,
        frame: &[u8],
        server_nonce: Nonce32V2,
        ephemeral_secret: StaticSecret,
        client_public_key: [u8; 32],
        server_signing_key: &SigningKey,
    ) -> Result<(V2PendingServerHandshake, Vec<u8>), ProtocolError> {
        edge.validate()?;
        observed_client_peer.validate()?;
        require_key_id(edge.client_key_id, client_public_key)?;
        require_key_id(
            edge.server_key_id,
            server_signing_key.verifying_key().to_bytes(),
        )?;
        if is_zero(server_nonce.as_bytes()) {
            return Err(identity_mismatch());
        }
        let body = decode_handshake_frame(frame, edge.role, HandshakeMessageKindV2::ClientHello)?;
        let hello = decode_client_hello_body(body)?;
        if hello.client_identity != edge.client_identity
            || hello.client_key_id != edge.client_key_id
            || is_zero(hello.client_boot_id.as_bytes())
            || is_zero(hello.client_nonce.as_bytes())
            || is_zero(&hello.client_ephemeral_x25519)
        {
            return Err(identity_mismatch());
        }
        let server_ephemeral_x25519 = X25519PublicKey::from(&ephemeral_secret).to_bytes();
        if is_zero(&server_ephemeral_x25519) {
            return Err(identity_mismatch());
        }
        let transcript = HandshakeTranscriptV2 {
            edge,
            client_boot_id: hello.client_boot_id,
            client_nonce: hello.client_nonce,
            server_nonce,
            client_ephemeral_x25519: hello.client_ephemeral_x25519,
            server_ephemeral_x25519,
            observed_client_peer,
        };
        let transcript_bytes = encode_transcript(&transcript)?;
        let transcript_digest = transcript_digest_for(&transcript_bytes);
        let server_signature = server_signing_key
            .sign(&signature_input(
                SERVER_HELLO_DOMAIN,
                &[transcript_digest.as_bytes()],
            ))
            .to_bytes();
        let shared_secret = ephemeral_secret
            .diffie_hellman(&X25519PublicKey::from(hello.client_ephemeral_x25519))
            .to_bytes();
        let keys = derive_session_keys(
            shared_secret,
            hello.client_nonce,
            server_nonce,
            transcript_digest,
            edge.role,
        )?;
        let server_body =
            encode_server_hello_body(&transcript_bytes, transcript_digest, server_signature)?;
        let server_frame =
            encode_handshake_frame(edge.role, HandshakeMessageKindV2::ServerHello, &server_body)?;
        Ok((
            V2PendingServerHandshake {
                edge,
                client_boot_id: hello.client_boot_id,
                client_nonce: hello.client_nonce,
                transcript_digest,
                server_signature,
                client_public_key,
                keys,
            },
            server_frame,
        ))
    }
}

pub struct V2PendingServerHandshake {
    edge: KernelServiceHandshakeEdgeV2,
    client_boot_id: BootIdV2,
    client_nonce: Nonce32V2,
    transcript_digest: Digest32V2,
    server_signature: [u8; 64],
    client_public_key: [u8; 32],
    keys: DerivedSessionKeysV2,
}

impl std::fmt::Debug for V2PendingServerHandshake {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("V2PendingServerHandshake(<ephemeral>)")
    }
}

impl V2PendingServerHandshake {
    pub const fn client_boot_id(&self) -> BootIdV2 {
        self.client_boot_id
    }

    pub const fn client_nonce(&self) -> Nonce32V2 {
        self.client_nonce
    }

    pub const fn transcript_digest(&self) -> Digest32V2 {
        self.transcript_digest
    }

    pub fn accept_client_finish(
        self,
        frame: &[u8],
    ) -> Result<(Vec<u8>, V2ServerTransportSession, VerifiedV2HandshakePeer), ProtocolError> {
        let body =
            decode_handshake_frame(frame, self.edge.role, HandshakeMessageKindV2::ClientFinish)?;
        let (transcript_digest, server_signature, client_signature, received_client_confirm_mac) =
            decode_client_finish_body(body)?;
        if transcript_digest != self.transcript_digest || server_signature != self.server_signature
        {
            return Err(identity_mismatch());
        }
        verify_client_signature(
            transcript_digest,
            server_signature,
            client_signature,
            self.client_public_key,
        )?;
        let expected_client_confirm = client_confirm_mac(
            &self.keys.client_confirm_key,
            transcript_digest,
            server_signature,
            client_signature,
        )?;
        if received_client_confirm_mac != expected_client_confirm {
            return Err(identity_mismatch());
        }
        let server_confirm_mac = server_confirm_mac(
            &self.keys.server_confirm_key,
            transcript_digest,
            received_client_confirm_mac,
        )?;
        let accepted_plaintext = encode_handshake_accepted(transcript_digest, server_confirm_mac)?;
        let accepted = seal_record(
            &self.keys.s2c_key,
            &self.keys.s2c_iv,
            transcript_digest,
            RecordHeaderV2 {
                direction: DirectionV2::ServerToClient,
                sequence: 0,
                role: self.edge.role,
                kind: MessageKindV2::HandshakeAccepted,
                request_id: RequestIdV2::new([0; 16]),
                operation_tag: u16::MAX,
                plaintext_length: checked_plaintext_length(&accepted_plaintext)?,
            },
            &accepted_plaintext,
        )?;
        Ok((
            accepted,
            V2ServerTransportSession {
                role: self.edge.role,
                transcript_digest,
                c2s_key: self.keys.c2s_key,
                s2c_key: self.keys.s2c_key,
                c2s_iv: self.keys.c2s_iv,
                s2c_iv: self.keys.s2c_iv,
                request_binding: None,
                response_sent: false,
            },
            VerifiedV2HandshakePeer {
                role: self.edge.role,
                client_identity: self.edge.client_identity,
                client_boot_id: self.client_boot_id,
                transcript_digest,
            },
        ))
    }
}

pub struct V2ClientTransportSession {
    role: EndpointRoleV2,
    transcript_digest: Digest32V2,
    c2s_key: Zeroizing<[u8; 32]>,
    s2c_key: Zeroizing<[u8; 32]>,
    c2s_iv: Zeroizing<[u8; 12]>,
    s2c_iv: Zeroizing<[u8; 12]>,
    expected_server_confirm_mac: [u8; 32],
    confirmed: bool,
    request_binding: Option<(RequestIdV2, u16)>,
    response_opened: bool,
}

impl std::fmt::Debug for V2ClientTransportSession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("V2ClientTransportSession(<traffic-keys-redacted>)")
    }
}

impl V2ClientTransportSession {
    pub fn accept_server_confirmation(&mut self, record: &[u8]) -> Result<(), ProtocolError> {
        if self.confirmed {
            return Err(identity_replay());
        }
        let opened = open_record(
            &self.s2c_key,
            &self.s2c_iv,
            self.transcript_digest,
            record,
            ExpectedRecordV2 {
                direction: DirectionV2::ServerToClient,
                sequence: 0,
                role: self.role,
                kind: MessageKindV2::HandshakeAccepted,
                request_id: RequestIdV2::new([0; 16]),
                operation_tag: u16::MAX,
            },
        )?;
        let (digest, server_confirm_mac) = decode_handshake_accepted(opened.plaintext())?;
        if digest != self.transcript_digest
            || server_confirm_mac != self.expected_server_confirm_mac
        {
            return Err(identity_mismatch());
        }
        self.confirmed = true;
        Ok(())
    }

    pub fn seal_application_request(
        &mut self,
        request_id: RequestIdV2,
        operation_tag: u16,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, ProtocolError> {
        if !self.confirmed || self.request_binding.is_some() || is_zero(request_id.as_bytes()) {
            return Err(identity_replay());
        }
        let record = seal_record(
            &self.c2s_key,
            &self.c2s_iv,
            self.transcript_digest,
            RecordHeaderV2 {
                direction: DirectionV2::ClientToServer,
                sequence: 0,
                role: self.role,
                kind: MessageKindV2::ApplicationRequest,
                request_id,
                operation_tag,
                plaintext_length: checked_plaintext_length(plaintext)?,
            },
            plaintext,
        )?;
        self.request_binding = Some((request_id, operation_tag));
        Ok(record)
    }

    pub fn open_application_response(
        &mut self,
        record: &[u8],
    ) -> Result<OpenedV2Record, ProtocolError> {
        if !self.confirmed || self.response_opened {
            return Err(identity_replay());
        }
        let (request_id, operation_tag) = self.request_binding.ok_or_else(identity_replay)?;
        let opened = open_record(
            &self.s2c_key,
            &self.s2c_iv,
            self.transcript_digest,
            record,
            ExpectedRecordV2 {
                direction: DirectionV2::ServerToClient,
                sequence: 1,
                role: self.role,
                kind: MessageKindV2::ApplicationResponse,
                request_id,
                operation_tag,
            },
        )?;
        self.response_opened = true;
        Ok(opened)
    }
}

pub struct V2ServerTransportSession {
    role: EndpointRoleV2,
    transcript_digest: Digest32V2,
    c2s_key: Zeroizing<[u8; 32]>,
    s2c_key: Zeroizing<[u8; 32]>,
    c2s_iv: Zeroizing<[u8; 12]>,
    s2c_iv: Zeroizing<[u8; 12]>,
    request_binding: Option<(RequestIdV2, u16)>,
    response_sent: bool,
}

impl std::fmt::Debug for V2ServerTransportSession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("V2ServerTransportSession(<traffic-keys-redacted>)")
    }
}

impl V2ServerTransportSession {
    pub fn open_application_request(
        &mut self,
        record: &[u8],
    ) -> Result<OpenedV2Record, ProtocolError> {
        if self.request_binding.is_some() {
            return Err(identity_replay());
        }
        let header = peek_record_header(record)?;
        if is_zero(header.request_id.as_bytes()) {
            return Err(identity_mismatch());
        }
        let opened = open_record(
            &self.c2s_key,
            &self.c2s_iv,
            self.transcript_digest,
            record,
            ExpectedRecordV2 {
                direction: DirectionV2::ClientToServer,
                sequence: 0,
                role: self.role,
                kind: MessageKindV2::ApplicationRequest,
                request_id: header.request_id,
                operation_tag: header.operation_tag,
            },
        )?;
        self.request_binding = Some((opened.request_id, opened.operation_tag));
        Ok(opened)
    }

    pub fn seal_application_response(
        &mut self,
        request_id: RequestIdV2,
        operation_tag: u16,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, ProtocolError> {
        if self.response_sent
            || is_zero(request_id.as_bytes())
            || self.request_binding != Some((request_id, operation_tag))
        {
            return Err(identity_replay());
        }
        let record = seal_record(
            &self.s2c_key,
            &self.s2c_iv,
            self.transcript_digest,
            RecordHeaderV2 {
                direction: DirectionV2::ServerToClient,
                sequence: 1,
                role: self.role,
                kind: MessageKindV2::ApplicationResponse,
                request_id,
                operation_tag,
                plaintext_length: checked_plaintext_length(plaintext)?,
            },
            plaintext,
        )?;
        self.response_sent = true;
        Ok(record)
    }
}

pub struct OpenedV2Record {
    request_id: RequestIdV2,
    operation_tag: u16,
    plaintext: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for OpenedV2Record {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OpenedV2Record")
            .field("request_id", &"<redacted>")
            .field("operation_tag", &self.operation_tag)
            .field("plaintext", &"<redacted>")
            .finish()
    }
}

impl OpenedV2Record {
    pub const fn request_id(&self) -> RequestIdV2 {
        self.request_id
    }

    pub const fn operation_tag(&self) -> u16 {
        self.operation_tag
    }

    pub fn plaintext(&self) -> &[u8] {
        &self.plaintext
    }
}

struct DerivedSessionKeysV2 {
    c2s_key: Zeroizing<[u8; 32]>,
    s2c_key: Zeroizing<[u8; 32]>,
    c2s_iv: Zeroizing<[u8; 12]>,
    s2c_iv: Zeroizing<[u8; 12]>,
    client_confirm_key: Zeroizing<[u8; 32]>,
    server_confirm_key: Zeroizing<[u8; 32]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RecordHeaderV2 {
    direction: DirectionV2,
    sequence: u64,
    role: EndpointRoleV2,
    kind: MessageKindV2,
    request_id: RequestIdV2,
    operation_tag: u16,
    plaintext_length: u32,
}

#[derive(Debug, Clone, Copy)]
struct ExpectedRecordV2 {
    direction: DirectionV2,
    sequence: u64,
    role: EndpointRoleV2,
    kind: MessageKindV2,
    request_id: RequestIdV2,
    operation_tag: u16,
}

pub fn derive_ed25519_key_id_v2(public_key: [u8; 32]) -> Ed25519KeyIdV2 {
    let mut hasher = Sha256::new();
    hasher.update(ED25519_KEY_ID_DOMAIN);
    hasher.update(public_key);
    Ed25519KeyIdV2::new(hasher.finalize().into())
}

fn encode_client_hello_body(value: &ClientHelloBodyV2) -> Result<Vec<u8>, ProtocolError> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(CLIENT_HELLO_FIELDS)
        .and_then(|encoder| encoder.u16(2))
        .and_then(|encoder| encoder.bytes(value.client_identity.as_bytes()))
        .and_then(|encoder| encoder.bytes(value.client_boot_id.as_bytes()))
        .and_then(|encoder| encoder.bytes(value.client_key_id.as_bytes()))
        .and_then(|encoder| encoder.bytes(value.client_nonce.as_bytes()))
        .and_then(|encoder| encoder.bytes(&value.client_ephemeral_x25519))
        .and_then(|encoder| encoder.array(1))
        .and_then(|encoder| encoder.u16(REQUESTED_MODE_REQUIRED))
        .map_err(ProtocolError::malformed)?;
    Ok(encoder.into_writer())
}

fn decode_client_hello_body(bytes: &[u8]) -> Result<ClientHelloBodyV2, ProtocolError> {
    require_handshake_body(bytes)?;
    let mut decoder = minicbor::Decoder::new(bytes);
    if decoder.array().map_err(ProtocolError::malformed)? != Some(CLIENT_HELLO_FIELDS)
        || decoder.u16().map_err(ProtocolError::malformed)? != 2
    {
        return Err(malformed());
    }
    let value = ClientHelloBodyV2 {
        client_identity: ServiceIdentityV2::new(decode_fixed::<32>(&mut decoder)?),
        client_boot_id: BootIdV2::new(decode_fixed::<32>(&mut decoder)?),
        client_key_id: Ed25519KeyIdV2::new(decode_fixed::<32>(&mut decoder)?),
        client_nonce: Nonce32V2::new(decode_fixed::<32>(&mut decoder)?),
        client_ephemeral_x25519: decode_fixed::<32>(&mut decoder)?,
    };
    if decoder.array().map_err(ProtocolError::malformed)? != Some(1)
        || decoder.u16().map_err(ProtocolError::malformed)? != REQUESTED_MODE_REQUIRED
        || decoder.position() != bytes.len()
        || encode_client_hello_body(&value)? != bytes
    {
        return Err(malformed());
    }
    Ok(value)
}

fn encode_transcript(value: &HandshakeTranscriptV2) -> Result<Vec<u8>, ProtocolError> {
    value.edge.validate()?;
    value.observed_client_peer.validate()?;
    let edge = value.edge;
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(TRANSCRIPT_FIELDS)
        .and_then(|encoder| encoder.u16(2))
        .and_then(|encoder| encoder.u16(PROTOCOL_MAJOR))
        .and_then(|encoder| encoder.u16(PROTOCOL_MINOR))
        .and_then(|encoder| encoder.u16(SUITE_ID))
        .map_err(ProtocolError::malformed)?;
    minicbor::Encode::encode(&edge.role, &mut encoder, &mut ())
        .map_err(ProtocolError::malformed)?;
    encoder
        .array(1)
        .and_then(|encoder| encoder.u16(REQUESTED_MODE_REQUIRED))
        .and_then(|encoder| encoder.bytes(edge.installation_id.as_bytes()))
        .and_then(|encoder| encoder.bytes(edge.client_identity.as_bytes()))
        .and_then(|encoder| encoder.bytes(edge.server_identity.as_bytes()))
        .and_then(|encoder| encoder.bytes(value.client_boot_id.as_bytes()))
        .and_then(|encoder| encoder.bytes(edge.client_key_id.as_bytes()))
        .and_then(|encoder| encoder.bytes(edge.server_key_id.as_bytes()))
        .and_then(|encoder| encoder.bytes(value.client_nonce.as_bytes()))
        .and_then(|encoder| encoder.bytes(value.server_nonce.as_bytes()))
        .and_then(|encoder| encoder.bytes(&value.client_ephemeral_x25519))
        .and_then(|encoder| encoder.bytes(&value.server_ephemeral_x25519))
        .map_err(ProtocolError::malformed)?;
    encode_peer_binding(&mut encoder, &value.observed_client_peer)?;
    encoder
        .bytes(edge.server_boot_id.as_bytes())
        .and_then(|encoder| encoder.u64(edge.active_state_manifest_sequence))
        .and_then(|encoder| encoder.bytes(edge.active_state_manifest_digest.as_bytes()))
        .and_then(|encoder| encoder.u64(edge.deployment_generation))
        .and_then(|encoder| encoder.u64(edge.effect_fence_epoch))
        .and_then(|encoder| encoder.bytes(edge.release_identity_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(edge.model_set_identity_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(edge.resource_profile_identity_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(edge.approval_lock_identity_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(edge.planner_lock_identity_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(edge.executor_key_lock_identity_digest.as_bytes()))
        .map_err(ProtocolError::malformed)?;
    let bytes = encoder.into_writer();
    if bytes.len() > MAX_HANDSHAKE_BODY_BYTES_V2 {
        return Err(allocation_refused());
    }
    Ok(bytes)
}

fn decode_transcript(bytes: &[u8]) -> Result<HandshakeTranscriptV2, ProtocolError> {
    require_handshake_body(bytes)?;
    let mut decoder = minicbor::Decoder::new(bytes);
    if decoder.array().map_err(ProtocolError::malformed)? != Some(TRANSCRIPT_FIELDS)
        || decoder.u16().map_err(ProtocolError::malformed)? != 2
        || decoder.u16().map_err(ProtocolError::malformed)? != PROTOCOL_MAJOR
        || decoder.u16().map_err(ProtocolError::malformed)? != PROTOCOL_MINOR
        || decoder.u16().map_err(ProtocolError::malformed)? != SUITE_ID
    {
        return Err(malformed());
    }
    let mut context = V2DecodeContext;
    let role =
        <EndpointRoleV2 as minicbor::Decode<V2DecodeContext>>::decode(&mut decoder, &mut context)
            .map_err(ProtocolError::from_typed_decode)?;
    if decoder.array().map_err(ProtocolError::malformed)? != Some(1)
        || decoder.u16().map_err(ProtocolError::malformed)? != REQUESTED_MODE_REQUIRED
    {
        return Err(malformed());
    }
    let installation_id = Digest32V2::new(decode_fixed::<32>(&mut decoder)?);
    let client_identity = ServiceIdentityV2::new(decode_fixed::<32>(&mut decoder)?);
    let server_identity = ServiceIdentityV2::new(decode_fixed::<32>(&mut decoder)?);
    let client_boot_id = BootIdV2::new(decode_fixed::<32>(&mut decoder)?);
    let client_key_id = Ed25519KeyIdV2::new(decode_fixed::<32>(&mut decoder)?);
    let server_key_id = Ed25519KeyIdV2::new(decode_fixed::<32>(&mut decoder)?);
    let client_nonce = Nonce32V2::new(decode_fixed::<32>(&mut decoder)?);
    let server_nonce = Nonce32V2::new(decode_fixed::<32>(&mut decoder)?);
    let client_ephemeral_x25519 = decode_fixed::<32>(&mut decoder)?;
    let server_ephemeral_x25519 = decode_fixed::<32>(&mut decoder)?;
    let observed_client_peer = decode_peer_binding(&mut decoder)?;
    let server_boot_id = BootIdV2::new(decode_fixed::<32>(&mut decoder)?);
    let active_state_manifest_sequence = decoder.u64().map_err(ProtocolError::malformed)?;
    let active_state_manifest_digest = Digest32V2::new(decode_fixed::<32>(&mut decoder)?);
    let deployment_generation = decoder.u64().map_err(ProtocolError::malformed)?;
    let effect_fence_epoch = decoder.u64().map_err(ProtocolError::malformed)?;
    let release_identity_digest = Digest32V2::new(decode_fixed::<32>(&mut decoder)?);
    let model_set_identity_digest = Digest32V2::new(decode_fixed::<32>(&mut decoder)?);
    let resource_profile_identity_digest = Digest32V2::new(decode_fixed::<32>(&mut decoder)?);
    let approval_lock_identity_digest = Digest32V2::new(decode_fixed::<32>(&mut decoder)?);
    let planner_lock_identity_digest = Digest32V2::new(decode_fixed::<32>(&mut decoder)?);
    let executor_key_lock_identity_digest = Digest32V2::new(decode_fixed::<32>(&mut decoder)?);
    if decoder.position() != bytes.len() {
        return Err(malformed());
    }
    let value = HandshakeTranscriptV2 {
        edge: KernelServiceHandshakeEdgeV2::from_verified_deployment(
            role,
            installation_id,
            client_identity,
            server_identity,
            client_key_id,
            server_key_id,
            server_boot_id,
            active_state_manifest_sequence,
            active_state_manifest_digest,
            deployment_generation,
            effect_fence_epoch,
            release_identity_digest,
            model_set_identity_digest,
            resource_profile_identity_digest,
            approval_lock_identity_digest,
            planner_lock_identity_digest,
            executor_key_lock_identity_digest,
        )?,
        client_boot_id,
        client_nonce,
        server_nonce,
        client_ephemeral_x25519,
        server_ephemeral_x25519,
        observed_client_peer,
    };
    if encode_transcript(&value)? != bytes {
        return Err(noncanonical());
    }
    Ok(value)
}

fn encode_peer_binding<W: minicbor::encode::Write>(
    encoder: &mut minicbor::Encoder<W>,
    peer: &PeerIdentityBindingV2,
) -> Result<(), ProtocolError> {
    match peer {
        PeerIdentityBindingV2::Linux {
            uid,
            gid,
            pid,
            process_start_time,
            executable_measurement,
        } => {
            encoder
                .array(6)
                .and_then(|encoder| encoder.u16(1))
                .and_then(|encoder| encoder.u32(*uid))
                .and_then(|encoder| encoder.u32(*gid))
                .and_then(|encoder| encoder.u32(*pid))
                .and_then(|encoder| encoder.u64(*process_start_time))
                .and_then(|encoder| encoder.bytes(executable_measurement.as_bytes()))
                .map_err(ProtocolError::malformed)?;
        }
        PeerIdentityBindingV2::MacOs {
            audit_token,
            euid,
            egid,
            bundle_id,
            team_id,
            code_directory_digest,
        } => {
            encoder
                .array(7)
                .and_then(|encoder| encoder.u16(2))
                .and_then(|encoder| encoder.bytes(audit_token))
                .and_then(|encoder| encoder.u32(*euid))
                .and_then(|encoder| encoder.u32(*egid))
                .and_then(|encoder| encoder.str(bundle_id))
                .and_then(|encoder| encoder.str(team_id))
                .and_then(|encoder| encoder.bytes(code_directory_digest.as_bytes()))
                .map_err(ProtocolError::malformed)?;
        }
    }
    Ok(())
}

fn decode_peer_binding(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<PeerIdentityBindingV2, ProtocolError> {
    let length = decoder.array().map_err(ProtocolError::malformed)?;
    match (length, decoder.u16().map_err(ProtocolError::malformed)?) {
        (Some(6), 1) => PeerIdentityBindingV2::linux(
            decoder.u32().map_err(ProtocolError::malformed)?,
            decoder.u32().map_err(ProtocolError::malformed)?,
            decoder.u32().map_err(ProtocolError::malformed)?,
            decoder.u64().map_err(ProtocolError::malformed)?,
            Digest32V2::new(decode_fixed::<32>(decoder)?),
        ),
        (Some(7), 2) => PeerIdentityBindingV2::macos(
            decode_fixed::<32>(decoder)?,
            decoder.u32().map_err(ProtocolError::malformed)?,
            decoder.u32().map_err(ProtocolError::malformed)?,
            decoder.str().map_err(ProtocolError::malformed)?.to_owned(),
            decoder.str().map_err(ProtocolError::malformed)?.to_owned(),
            Digest32V2::new(decode_fixed::<32>(decoder)?),
        ),
        _ => Err(malformed()),
    }
}

fn encode_server_hello_body(
    transcript: &[u8],
    transcript_digest: Digest32V2,
    server_signature: [u8; 64],
) -> Result<Vec<u8>, ProtocolError> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(SERVER_HELLO_FIELDS)
        .and_then(|encoder| encoder.bytes(transcript))
        .and_then(|encoder| encoder.bytes(transcript_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(&server_signature))
        .map_err(ProtocolError::malformed)?;
    Ok(encoder.into_writer())
}

fn decode_server_hello_body(
    bytes: &[u8],
) -> Result<(Vec<u8>, Digest32V2, [u8; 64]), ProtocolError> {
    require_handshake_body(bytes)?;
    let mut decoder = minicbor::Decoder::new(bytes);
    if decoder.array().map_err(ProtocolError::malformed)? != Some(SERVER_HELLO_FIELDS) {
        return Err(malformed());
    }
    let transcript = decoder.bytes().map_err(ProtocolError::malformed)?.to_vec();
    let digest = Digest32V2::new(decode_fixed::<32>(&mut decoder)?);
    let signature = decode_fixed::<64>(&mut decoder)?;
    if decoder.position() != bytes.len()
        || encode_server_hello_body(&transcript, digest, signature)? != bytes
    {
        return Err(noncanonical());
    }
    Ok((transcript, digest, signature))
}

fn encode_client_finish_body(
    transcript_digest: Digest32V2,
    server_signature: [u8; 64],
    client_signature: [u8; 64],
    client_confirm_mac: [u8; 32],
) -> Result<Vec<u8>, ProtocolError> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(CLIENT_FINISH_FIELDS)
        .and_then(|encoder| encoder.bytes(transcript_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(&server_signature))
        .and_then(|encoder| encoder.bytes(&client_signature))
        .and_then(|encoder| encoder.bytes(&client_confirm_mac))
        .map_err(ProtocolError::malformed)?;
    Ok(encoder.into_writer())
}

fn decode_client_finish_body(bytes: &[u8]) -> Result<ClientFinishFieldsV2, ProtocolError> {
    require_handshake_body(bytes)?;
    let mut decoder = minicbor::Decoder::new(bytes);
    if decoder.array().map_err(ProtocolError::malformed)? != Some(CLIENT_FINISH_FIELDS) {
        return Err(malformed());
    }
    let transcript_digest = Digest32V2::new(decode_fixed::<32>(&mut decoder)?);
    let server_signature = decode_fixed::<64>(&mut decoder)?;
    let client_signature = decode_fixed::<64>(&mut decoder)?;
    let client_confirm_mac = decode_fixed::<32>(&mut decoder)?;
    if decoder.position() != bytes.len()
        || encode_client_finish_body(
            transcript_digest,
            server_signature,
            client_signature,
            client_confirm_mac,
        )? != bytes
    {
        return Err(noncanonical());
    }
    Ok((
        transcript_digest,
        server_signature,
        client_signature,
        client_confirm_mac,
    ))
}

fn encode_handshake_accepted(
    transcript_digest: Digest32V2,
    server_confirm_mac: [u8; 32],
) -> Result<Vec<u8>, ProtocolError> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(HANDSHAKE_ACCEPTED_FIELDS)
        .and_then(|encoder| encoder.bytes(transcript_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(&server_confirm_mac))
        .map_err(ProtocolError::malformed)?;
    Ok(encoder.into_writer())
}

fn decode_handshake_accepted(bytes: &[u8]) -> Result<(Digest32V2, [u8; 32]), ProtocolError> {
    scan_single(bytes)?;
    let mut decoder = minicbor::Decoder::new(bytes);
    if decoder.array().map_err(ProtocolError::malformed)? != Some(HANDSHAKE_ACCEPTED_FIELDS) {
        return Err(malformed());
    }
    let digest = Digest32V2::new(decode_fixed::<32>(&mut decoder)?);
    let confirm = decode_fixed::<32>(&mut decoder)?;
    if decoder.position() != bytes.len() || encode_handshake_accepted(digest, confirm)? != bytes {
        return Err(noncanonical());
    }
    Ok((digest, confirm))
}

fn encode_handshake_frame(
    role: EndpointRoleV2,
    kind: HandshakeMessageKindV2,
    body: &[u8],
) -> Result<Vec<u8>, ProtocolError> {
    if body.is_empty() || body.len() > MAX_HANDSHAKE_BODY_BYTES_V2 {
        return Err(allocation_refused());
    }
    let body_length = u32::try_from(body.len()).map_err(|_| allocation_refused())?;
    let mut frame =
        Vec::with_capacity(HANDSHAKE_PREFIX_BYTES + HANDSHAKE_LENGTH_BYTES + body.len());
    frame.extend_from_slice(HANDSHAKE_MAGIC);
    frame.extend_from_slice(&PROTOCOL_MAJOR.to_be_bytes());
    frame.extend_from_slice(&PROTOCOL_MINOR.to_be_bytes());
    frame.extend_from_slice(&SUITE_ID.to_be_bytes());
    frame.push(role_prefix_tag(role)?);
    frame.push(kind.tag());
    frame.extend_from_slice(&body_length.to_be_bytes());
    frame.extend_from_slice(body);
    Ok(frame)
}

fn decode_handshake_frame(
    frame: &[u8],
    expected_role: EndpointRoleV2,
    expected_kind: HandshakeMessageKindV2,
) -> Result<&[u8], ProtocolError> {
    if frame.len() < HANDSHAKE_PREFIX_BYTES + HANDSHAKE_LENGTH_BYTES
        || &frame[..8] != HANDSHAKE_MAGIC
        || u16::from_be_bytes(frame[8..10].try_into().map_err(|_| malformed())?) != PROTOCOL_MAJOR
        || u16::from_be_bytes(frame[10..12].try_into().map_err(|_| malformed())?) != PROTOCOL_MINOR
        || u16::from_be_bytes(frame[12..14].try_into().map_err(|_| malformed())?) != SUITE_ID
        || frame[14] != role_prefix_tag(expected_role)?
        || frame[15] != expected_kind.tag()
    {
        return Err(malformed());
    }
    let length = u32::from_be_bytes(frame[16..20].try_into().map_err(|_| malformed())?) as usize;
    if length == 0
        || length > MAX_HANDSHAKE_BODY_BYTES_V2
        || frame.len() != HANDSHAKE_PREFIX_BYTES + HANDSHAKE_LENGTH_BYTES + length
    {
        return Err(malformed());
    }
    Ok(&frame[20..])
}

fn transcript_digest_for(transcript: &[u8]) -> Digest32V2 {
    let mut hasher = Sha256::new();
    hasher.update(HANDSHAKE_TRANSCRIPT_DOMAIN);
    hasher.update(transcript);
    Digest32V2::new(hasher.finalize().into())
}

fn verify_server_signature(
    transcript_digest: Digest32V2,
    signature: [u8; 64],
    public_key: [u8; 32],
) -> Result<(), ProtocolError> {
    let key = Ed25519VerifyingKey::from_bytes(&public_key).map_err(|_| invalid_signature())?;
    key.verify_strict(
        &signature_input(SERVER_HELLO_DOMAIN, &[transcript_digest.as_bytes()]),
        &Ed25519Signature::from_bytes(&signature),
    )
    .map_err(|_| invalid_signature())
}

fn sign_client_finish(
    transcript_digest: Digest32V2,
    server_signature: [u8; 64],
    signing_key: &SigningKey,
) -> [u8; 64] {
    signing_key
        .sign(&signature_input(
            CLIENT_FINISH_DOMAIN,
            &[transcript_digest.as_bytes(), &server_signature],
        ))
        .to_bytes()
}

fn verify_client_signature(
    transcript_digest: Digest32V2,
    server_signature: [u8; 64],
    client_signature: [u8; 64],
    public_key: [u8; 32],
) -> Result<(), ProtocolError> {
    let key = Ed25519VerifyingKey::from_bytes(&public_key).map_err(|_| invalid_signature())?;
    key.verify_strict(
        &signature_input(
            CLIENT_FINISH_DOMAIN,
            &[transcript_digest.as_bytes(), &server_signature],
        ),
        &Ed25519Signature::from_bytes(&client_signature),
    )
    .map_err(|_| invalid_signature())
}

fn derive_session_keys(
    shared_secret: [u8; 32],
    client_nonce: Nonce32V2,
    server_nonce: Nonce32V2,
    transcript_digest: Digest32V2,
    role: EndpointRoleV2,
) -> Result<DerivedSessionKeysV2, ProtocolError> {
    let shared_secret = Zeroizing::new(shared_secret);
    if is_zero(shared_secret.as_ref()) {
        return Err(identity_mismatch());
    }
    let mut salt_hasher = Sha256::new();
    salt_hasher.update(HANDSHAKE_SALT_DOMAIN);
    salt_hasher.update(client_nonce.as_bytes());
    salt_hasher.update(server_nonce.as_bytes());
    let salt: [u8; 32] = salt_hasher.finalize().into();
    let hkdf = Hkdf::<Sha256>::new(Some(&salt), shared_secret.as_ref());
    let mut context_hasher = Sha256::new();
    context_hasher.update(SESSION_KEYS_DOMAIN);
    context_hasher.update(transcript_digest.as_bytes());
    context_hasher.update([role_prefix_tag(role)?]);
    let context: [u8; 32] = context_hasher.finalize().into();
    Ok(DerivedSessionKeysV2 {
        c2s_key: Zeroizing::new(hkdf_expand::<32>(&hkdf, C2S_KEY_LABEL, &context)?),
        s2c_key: Zeroizing::new(hkdf_expand::<32>(&hkdf, S2C_KEY_LABEL, &context)?),
        c2s_iv: Zeroizing::new(hkdf_expand::<12>(&hkdf, C2S_IV_LABEL, &context)?),
        s2c_iv: Zeroizing::new(hkdf_expand::<12>(&hkdf, S2C_IV_LABEL, &context)?),
        client_confirm_key: Zeroizing::new(hkdf_expand::<32>(
            &hkdf,
            CLIENT_CONFIRM_LABEL,
            &context,
        )?),
        server_confirm_key: Zeroizing::new(hkdf_expand::<32>(
            &hkdf,
            SERVER_CONFIRM_LABEL,
            &context,
        )?),
    })
}

fn hkdf_expand<const N: usize>(
    hkdf: &Hkdf<Sha256>,
    label: &[u8],
    context: &[u8; 32],
) -> Result<[u8; N], ProtocolError> {
    let mut info = Vec::with_capacity(label.len() + context.len());
    info.extend_from_slice(label);
    info.extend_from_slice(context);
    let mut output = [0_u8; N];
    hkdf.expand(&info, &mut output)
        .map_err(|_| identity_mismatch())?;
    Ok(output)
}

fn client_confirm_mac(
    key: &[u8; 32],
    transcript_digest: Digest32V2,
    server_signature: [u8; 64],
    client_signature: [u8; 64],
) -> Result<[u8; 32], ProtocolError> {
    hmac(
        key,
        CLIENT_CONFIRM_MAC_DOMAIN,
        &[
            transcript_digest.as_bytes(),
            &server_signature,
            &client_signature,
        ],
    )
}

fn server_confirm_mac(
    key: &[u8; 32],
    transcript_digest: Digest32V2,
    client_confirm_mac: [u8; 32],
) -> Result<[u8; 32], ProtocolError> {
    hmac(
        key,
        SERVER_CONFIRM_MAC_DOMAIN,
        &[transcript_digest.as_bytes(), &client_confirm_mac],
    )
}

fn hmac(key: &[u8; 32], domain: &[u8], fields: &[&[u8]]) -> Result<[u8; 32], ProtocolError> {
    let mut mac =
        <HmacSha256 as hmac::Mac>::new_from_slice(key).map_err(|_| identity_mismatch())?;
    mac.update(domain);
    for field in fields {
        mac.update(field);
    }
    Ok(mac.finalize().into_bytes().into())
}

fn seal_record(
    key: &[u8; 32],
    iv: &[u8; 12],
    transcript_digest: Digest32V2,
    header: RecordHeaderV2,
    plaintext: &[u8],
) -> Result<Vec<u8>, ProtocolError> {
    if usize::try_from(header.plaintext_length).ok() != Some(plaintext.len())
        || plaintext.len() > MAX_RECORD_PLAINTEXT_BYTES
    {
        return Err(allocation_refused());
    }
    let header_bytes = encode_record_header(header)?;
    let aad = record_aad(transcript_digest, &header_bytes);
    let nonce = record_nonce(iv, header.sequence);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let mut ciphertext = plaintext.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(Nonce::from_slice(&nonce), &aad, &mut ciphertext)
        .map_err(|_| identity_mismatch())?;
    ciphertext.extend_from_slice(&tag);
    let header_length = u16::try_from(header_bytes.len()).map_err(|_| allocation_refused())?;
    let ciphertext_length = u32::try_from(ciphertext.len()).map_err(|_| allocation_refused())?;
    let mut frame = Vec::with_capacity(10 + header_bytes.len() + ciphertext.len());
    frame.extend_from_slice(RECORD_MAGIC);
    frame.extend_from_slice(&header_length.to_be_bytes());
    frame.extend_from_slice(&ciphertext_length.to_be_bytes());
    frame.extend_from_slice(&header_bytes);
    frame.extend_from_slice(&ciphertext);
    Ok(frame)
}

fn open_record(
    key: &[u8; 32],
    iv: &[u8; 12],
    transcript_digest: Digest32V2,
    frame: &[u8],
    expected: ExpectedRecordV2,
) -> Result<OpenedV2Record, ProtocolError> {
    let (header, header_bytes, ciphertext) = split_record(frame)?;
    if header.direction != expected.direction
        || header.sequence != expected.sequence
        || header.role != expected.role
        || header.kind != expected.kind
        || header.request_id != expected.request_id
        || header.operation_tag != expected.operation_tag
    {
        return Err(identity_mismatch());
    }
    let plaintext_length =
        usize::try_from(header.plaintext_length).map_err(|_| allocation_refused())?;
    if ciphertext.len() != plaintext_length + AEAD_TAG_BYTES {
        return Err(malformed());
    }
    let split = ciphertext.len() - AEAD_TAG_BYTES;
    let mut plaintext = Zeroizing::new(ciphertext[..split].to_vec());
    let tag = Tag::from_slice(&ciphertext[split..]);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let aad = record_aad(transcript_digest, header_bytes);
    let nonce = record_nonce(iv, header.sequence);
    cipher
        .decrypt_in_place_detached(Nonce::from_slice(&nonce), &aad, &mut plaintext, tag)
        .map_err(|_| identity_mismatch())?;
    Ok(OpenedV2Record {
        request_id: header.request_id,
        operation_tag: header.operation_tag,
        plaintext,
    })
}

fn peek_record_header(frame: &[u8]) -> Result<RecordHeaderV2, ProtocolError> {
    split_record(frame).map(|(header, _, _)| header)
}

fn split_record(frame: &[u8]) -> Result<(RecordHeaderV2, &[u8], &[u8]), ProtocolError> {
    if frame.len() < 10 || &frame[..4] != RECORD_MAGIC {
        return Err(malformed());
    }
    let header_length = usize::from(u16::from_be_bytes(
        frame[4..6].try_into().map_err(|_| malformed())?,
    ));
    let ciphertext_length =
        u32::from_be_bytes(frame[6..10].try_into().map_err(|_| malformed())?) as usize;
    if header_length == 0
        || header_length > MAX_RECORD_HEADER_BYTES_V2
        || !(AEAD_TAG_BYTES..=MAX_RECORD_CIPHERTEXT_BYTES_V2).contains(&ciphertext_length)
        || frame.len() != 10 + header_length + ciphertext_length
    {
        return Err(malformed());
    }
    let header_bytes = &frame[10..10 + header_length];
    let header = decode_record_header(header_bytes)?;
    if ciphertext_length
        != usize::try_from(header.plaintext_length).map_err(|_| allocation_refused())?
            + AEAD_TAG_BYTES
    {
        return Err(malformed());
    }
    Ok((header, header_bytes, &frame[10 + header_length..]))
}

fn encode_record_header(value: RecordHeaderV2) -> Result<Vec<u8>, ProtocolError> {
    let ciphertext_length = value
        .plaintext_length
        .checked_add(AEAD_TAG_BYTES as u32)
        .ok_or_else(allocation_refused)?;
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(RECORD_HEADER_FIELDS)
        .and_then(|encoder| encoder.u16(PROTOCOL_MAJOR))
        .and_then(|encoder| encoder.u16(PROTOCOL_MINOR))
        .and_then(|encoder| encoder.u16(SUITE_ID))
        .and_then(|encoder| encoder.array(1))
        .and_then(|encoder| encoder.u16(value.direction.tag()))
        .and_then(|encoder| encoder.u64(value.sequence))
        .map_err(ProtocolError::malformed)?;
    minicbor::Encode::encode(&value.role, &mut encoder, &mut ())
        .map_err(ProtocolError::malformed)?;
    encoder
        .array(1)
        .and_then(|encoder| encoder.u16(value.kind.tag()))
        .and_then(|encoder| encoder.bytes(value.request_id.as_bytes()))
        .and_then(|encoder| encoder.u16(value.operation_tag))
        .and_then(|encoder| encoder.u32(value.plaintext_length))
        .and_then(|encoder| encoder.u32(ciphertext_length))
        .map_err(ProtocolError::malformed)?;
    let bytes = encoder.into_writer();
    if bytes.len() > MAX_RECORD_HEADER_BYTES_V2 {
        return Err(allocation_refused());
    }
    Ok(bytes)
}

fn decode_record_header(bytes: &[u8]) -> Result<RecordHeaderV2, ProtocolError> {
    if bytes.len() > MAX_RECORD_HEADER_BYTES_V2 {
        return Err(allocation_refused());
    }
    scan_single(bytes)?;
    let mut decoder = minicbor::Decoder::new(bytes);
    if decoder.array().map_err(ProtocolError::malformed)? != Some(RECORD_HEADER_FIELDS)
        || decoder.u16().map_err(ProtocolError::malformed)? != PROTOCOL_MAJOR
        || decoder.u16().map_err(ProtocolError::malformed)? != PROTOCOL_MINOR
        || decoder.u16().map_err(ProtocolError::malformed)? != SUITE_ID
        || decoder.array().map_err(ProtocolError::malformed)? != Some(1)
    {
        return Err(malformed());
    }
    let direction = match decoder.u16().map_err(ProtocolError::malformed)? {
        1 => DirectionV2::ClientToServer,
        2 => DirectionV2::ServerToClient,
        _ => return Err(malformed()),
    };
    let sequence = decoder.u64().map_err(ProtocolError::malformed)?;
    let mut context = V2DecodeContext;
    let role =
        <EndpointRoleV2 as minicbor::Decode<V2DecodeContext>>::decode(&mut decoder, &mut context)
            .map_err(ProtocolError::from_typed_decode)?;
    if decoder.array().map_err(ProtocolError::malformed)? != Some(1) {
        return Err(malformed());
    }
    let kind = match decoder.u16().map_err(ProtocolError::malformed)? {
        1 => MessageKindV2::HandshakeAccepted,
        2 => MessageKindV2::ApplicationRequest,
        3 => MessageKindV2::ApplicationResponse,
        _ => return Err(malformed()),
    };
    let value = RecordHeaderV2 {
        direction,
        sequence,
        role,
        kind,
        request_id: RequestIdV2::new(decode_fixed::<16>(&mut decoder)?),
        operation_tag: decoder.u16().map_err(ProtocolError::malformed)?,
        plaintext_length: decoder.u32().map_err(ProtocolError::malformed)?,
    };
    let ciphertext_length = decoder.u32().map_err(ProtocolError::malformed)?;
    if decoder.position() != bytes.len()
        || ciphertext_length
            != value
                .plaintext_length
                .checked_add(AEAD_TAG_BYTES as u32)
                .ok_or_else(allocation_refused)?
        || encode_record_header(value)? != bytes
    {
        return Err(noncanonical());
    }
    Ok(value)
}

fn require_client_transcript(
    edge: &KernelServiceHandshakeEdgeV2,
    hello: &ClientHelloBodyV2,
    expected_observed_peer: &PeerIdentityBindingV2,
    transcript: &HandshakeTranscriptV2,
) -> Result<(), ProtocolError> {
    if &transcript.edge != edge
        || transcript.client_boot_id != hello.client_boot_id
        || transcript.client_nonce != hello.client_nonce
        || transcript.client_ephemeral_x25519 != hello.client_ephemeral_x25519
        || transcript.edge.client_identity != hello.client_identity
        || transcript.edge.client_key_id != hello.client_key_id
        || &transcript.observed_client_peer != expected_observed_peer
        || is_zero(transcript.server_nonce.as_bytes())
        || is_zero(&transcript.server_ephemeral_x25519)
    {
        return Err(identity_mismatch());
    }
    Ok(())
}

fn generation_authority_is_the_only_transcript_mismatch(
    expected_edge: &KernelServiceHandshakeEdgeV2,
    hello: &ClientHelloBodyV2,
    expected_observed_peer: &PeerIdentityBindingV2,
    transcript: &HandshakeTranscriptV2,
) -> bool {
    let received_edge = &transcript.edge;
    received_edge.role == expected_edge.role
        && received_edge.installation_id == expected_edge.installation_id
        && received_edge.client_identity == expected_edge.client_identity
        && received_edge.server_identity == expected_edge.server_identity
        && received_edge.client_key_id == expected_edge.client_key_id
        && received_edge.server_key_id == expected_edge.server_key_id
        && received_edge.server_boot_id == expected_edge.server_boot_id
        && received_edge.release_identity_digest == expected_edge.release_identity_digest
        && received_edge.model_set_identity_digest == expected_edge.model_set_identity_digest
        && received_edge.resource_profile_identity_digest
            == expected_edge.resource_profile_identity_digest
        && received_edge.approval_lock_identity_digest
            == expected_edge.approval_lock_identity_digest
        && received_edge.planner_lock_identity_digest == expected_edge.planner_lock_identity_digest
        && received_edge.executor_key_lock_identity_digest
            == expected_edge.executor_key_lock_identity_digest
        && (received_edge.active_state_manifest_sequence
            != expected_edge.active_state_manifest_sequence
            || received_edge.active_state_manifest_digest
                != expected_edge.active_state_manifest_digest
            || received_edge.deployment_generation != expected_edge.deployment_generation
            || received_edge.effect_fence_epoch != expected_edge.effect_fence_epoch)
        && transcript.client_boot_id == hello.client_boot_id
        && transcript.client_nonce == hello.client_nonce
        && transcript.client_ephemeral_x25519 == hello.client_ephemeral_x25519
        && transcript.edge.client_identity == hello.client_identity
        && transcript.edge.client_key_id == hello.client_key_id
        && &transcript.observed_client_peer == expected_observed_peer
        && !is_zero(transcript.server_nonce.as_bytes())
        && !is_zero(&transcript.server_ephemeral_x25519)
}

fn require_handshake_body(bytes: &[u8]) -> Result<(), ProtocolError> {
    if bytes.is_empty() || bytes.len() > MAX_HANDSHAKE_BODY_BYTES_V2 {
        return Err(allocation_refused());
    }
    scan_single(bytes)
}

fn require_key_id(expected: Ed25519KeyIdV2, public_key: [u8; 32]) -> Result<(), ProtocolError> {
    if expected != derive_ed25519_key_id_v2(public_key) {
        return Err(identity_mismatch());
    }
    Ed25519VerifyingKey::from_bytes(&public_key)
        .map(|_| ())
        .map_err(|_| invalid_signature())
}

fn record_aad(transcript_digest: Digest32V2, header: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(RECORD_AAD_DOMAIN.len() + 32 + header.len());
    aad.extend_from_slice(RECORD_AAD_DOMAIN);
    aad.extend_from_slice(transcript_digest.as_bytes());
    aad.extend_from_slice(header);
    aad
}

fn record_nonce(iv: &[u8; 12], sequence: u64) -> [u8; 12] {
    let mut encoded = [0_u8; 12];
    encoded[4..].copy_from_slice(&sequence.to_be_bytes());
    for (output, input) in encoded.iter_mut().zip(iv) {
        *output ^= *input;
    }
    encoded
}

fn signature_input(domain: &[u8], fields: &[&[u8]]) -> Vec<u8> {
    let capacity = domain.len() + fields.iter().map(|field| field.len()).sum::<usize>();
    let mut input = Vec::with_capacity(capacity);
    input.extend_from_slice(domain);
    for field in fields {
        input.extend_from_slice(field);
    }
    input
}

fn role_prefix_tag(role: EndpointRoleV2) -> Result<u8, ProtocolError> {
    u8::try_from(role.tag()).map_err(|_| malformed())
}

fn checked_plaintext_length(bytes: &[u8]) -> Result<u32, ProtocolError> {
    if bytes.len() > MAX_RECORD_PLAINTEXT_BYTES {
        return Err(allocation_refused());
    }
    u32::try_from(bytes.len()).map_err(|_| allocation_refused())
}

fn decode_fixed<const N: usize>(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<[u8; N], ProtocolError> {
    decoder
        .bytes()
        .map_err(ProtocolError::malformed)?
        .try_into()
        .map_err(|_| malformed())
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.nfc().eq(value.chars())
        && !value.chars().any(char::is_control)
}

fn is_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

fn malformed() -> ProtocolError {
    ProtocolError::stable(StableCode::ProtocolMalformedCbor)
}

fn noncanonical() -> ProtocolError {
    ProtocolError::stable(StableCode::ProtocolNonCanonicalCbor)
}

fn allocation_refused() -> ProtocolError {
    ProtocolError::stable(StableCode::ProtocolAllocationRefused)
}

fn identity_mismatch() -> ProtocolError {
    ProtocolError::stable(StableCode::IdentityTranscriptMismatch)
}

fn invalid_signature() -> ProtocolError {
    ProtocolError::stable(StableCode::IdentityInvalidSignature)
}

fn identity_replay() -> ProtocolError {
    ProtocolError::stable(StableCode::IdentityReplay)
}
