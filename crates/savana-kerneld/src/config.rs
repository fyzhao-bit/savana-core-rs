use savana_kernel_protocol::{Digest32, Signature64, StableCode};
use savana_policy_core::{
    InstallationClientV1, InstallationPublicKeyV1, VerifiedPolicyV1, VerifiedReleaseIdentity,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::DaemonError;

const MAXIMUM_LOCK_BYTES: usize = 256 * 1024;

#[derive(Clone)]
pub(crate) struct DaemonConfig {
    protocol_major: u16,
    minimum_minor: u16,
    maximum_minor: u16,
    daemon_identity: InstallationPublicKeyV1,
    daemon_clients: Vec<InstallationClientV1>,
    socket_path: String,
    selected_policy_path: String,
    selected_policy_signature_path: String,
    release_digest: Digest32,
    model_manifest_digest: Digest32,
    approval_key_set_digest: Digest32,
    release_expires_at: savana_kernel_protocol::UnixMillis,
}

impl std::fmt::Debug for DaemonConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("DaemonConfig(<verified>)")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LockPublicKey {
    key_id: String,
    public_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LockClient {
    client_id: String,
    key_id: String,
    public_key: String,
    role: String,
    peer_uid: u32,
    peer_gid: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LockPolicyRoot {
    key_id: String,
    public_key: String,
    epoch: u64,
    revoked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KernelLockV1 {
    schema_version: u16,
    protocol_major: u16,
    minimum_minor: u16,
    maximum_minor: u16,
    allowed_release_digests: Vec<String>,
    release_signature_digest: String,
    release_target_id: String,
    source_commit: String,
    installation_profile_digest: String,
    installation_id: String,
    platform: String,
    daemon_identity: LockPublicKey,
    daemon_clients: Vec<LockClient>,
    policy_trust_roots: Vec<LockPolicyRoot>,
    daemon_uid: u32,
    daemon_gid: u32,
    jarvis_uid: u32,
    socket_path: String,
    selected_policy_path: String,
    selected_policy_signature_path: String,
    socket_parent_mode: u16,
    socket_mode: u16,
    minimum_policy_version: u64,
    selected_policy_digest: String,
    selected_policy_signature_digest: String,
    selected_policy_version: u64,
    selected_policy_signing_key_id: String,
    selected_policy_key_epoch: u64,
    model_manifest_digest: String,
    producer_registry_digest: String,
    ontology_digest: String,
    approval_key_set_digest: String,
    resource_profile_digest: String,
}

impl DaemonConfig {
    pub fn from_verified(
        lock_bytes: &[u8],
        release: &VerifiedReleaseIdentity,
        policy: &VerifiedPolicyV1,
        selected_policy_signature: &Signature64,
    ) -> Result<Self, DaemonError> {
        release
            .verify_selected_policy_binding(policy, selected_policy_signature)
            .map_err(|_| release_mismatch())?;
        let lock = parse_canonical_lock(lock_bytes)?;
        verify_lock(&lock, release, policy, selected_policy_signature)?;
        let socket_client_gid = release
            .daemon_clients()
            .first()
            .map(InstallationClientV1::peer_gid)
            .ok_or_else(release_mismatch)?;
        if socket_client_gid == release.daemon_gid()
            || release
                .daemon_clients()
                .iter()
                .any(|client| client.peer_gid() != socket_client_gid)
        {
            return Err(release_mismatch());
        }
        Ok(Self {
            protocol_major: release.protocol_major(),
            minimum_minor: release.minimum_minor(),
            maximum_minor: release.maximum_minor(),
            daemon_identity: release.daemon_identity().clone(),
            daemon_clients: release.daemon_clients().to_vec(),
            socket_path: release.socket_path().to_owned(),
            selected_policy_path: release.selected_policy_path().to_owned(),
            selected_policy_signature_path: release.selected_policy_signature_path().to_owned(),
            release_digest: release.release_digest(),
            model_manifest_digest: release.model_manifest_digest(),
            approval_key_set_digest: release.approval_key_set_digest(),
            release_expires_at: release.expires_at(),
        })
    }

    pub fn socket_path(&self) -> &str {
        &self.socket_path
    }

    pub fn selected_policy_path(&self) -> &str {
        &self.selected_policy_path
    }

    pub fn selected_policy_signature_path(&self) -> &str {
        &self.selected_policy_signature_path
    }

    pub fn daemon_identity(&self) -> &InstallationPublicKeyV1 {
        &self.daemon_identity
    }

    pub fn daemon_clients(&self) -> &[InstallationClientV1] {
        &self.daemon_clients
    }

    pub(crate) const fn protocol_major(&self) -> u16 {
        self.protocol_major
    }

    pub(crate) const fn minimum_minor(&self) -> u16 {
        self.minimum_minor
    }

    pub(crate) const fn maximum_minor(&self) -> u16 {
        self.maximum_minor
    }

    pub(crate) const fn release_digest(&self) -> Digest32 {
        self.release_digest
    }

    pub(crate) const fn model_manifest_digest(&self) -> Digest32 {
        self.model_manifest_digest
    }

    pub(crate) const fn approval_key_set_digest(&self) -> Digest32 {
        self.approval_key_set_digest
    }

    pub(crate) const fn release_expires_at(&self) -> savana_kernel_protocol::UnixMillis {
        self.release_expires_at
    }
}

fn parse_canonical_lock(bytes: &[u8]) -> Result<KernelLockV1, DaemonError> {
    if bytes.len() > MAXIMUM_LOCK_BYTES {
        return Err(release_mismatch());
    }
    let lock: KernelLockV1 = serde_json::from_slice(bytes).map_err(|_| release_mismatch())?;
    let canonical = serde_json::to_vec(&lock).map_err(|_| release_mismatch())?;
    if canonical != bytes {
        return Err(release_mismatch());
    }
    Ok(lock)
}

fn verify_lock(
    lock: &KernelLockV1,
    release: &VerifiedReleaseIdentity,
    policy: &VerifiedPolicyV1,
    selected_policy_signature: &Signature64,
) -> Result<(), DaemonError> {
    let policy_identity = policy.identity();
    if lock.schema_version != 1
        || lock.protocol_major != release.protocol_major()
        || lock.minimum_minor != release.minimum_minor()
        || lock.maximum_minor != release.maximum_minor()
        || lock.allowed_release_digests.len() != 1
        || decode_hex32(&lock.allowed_release_digests[0])? != release.release_digest()
        || decode_hex32(&lock.release_signature_digest)? != release.release_signature_digest()
        || decode_hex32(&lock.release_target_id)? != release.release_target_id()
        || lock.source_commit != release.source_commit()
        || decode_hex32(&lock.installation_profile_digest)? != release.installation_profile_digest()
        || decode_hex32(&lock.installation_id)? != release.installation_id()
        || lock.platform != release.platform().as_lock_str()
        || lock.daemon_identity.key_id != release.daemon_identity().key_id().as_str()
        || decode_hex32(&lock.daemon_identity.public_key)?
            != Digest32::new(*release.daemon_identity().public_key())
        || lock.daemon_uid != release.daemon_uid()
        || lock.daemon_gid != release.daemon_gid()
        || lock.jarvis_uid != release.jarvis_uid()
        || lock.socket_path != release.socket_path()
        || lock.selected_policy_path != release.selected_policy_path()
        || lock.selected_policy_signature_path != release.selected_policy_signature_path()
        || lock.socket_parent_mode != release.socket_parent_mode()
        || lock.socket_mode != release.socket_mode()
        || lock.minimum_policy_version != release.minimum_policy_version()
        || decode_hex32(&lock.selected_policy_digest)? != policy_identity.digest
        || decode_hex32(&lock.selected_policy_signature_digest)?
            != hash_signature(selected_policy_signature)
        || lock.selected_policy_version != policy_identity.policy_version
        || lock.selected_policy_signing_key_id != policy.signing_key_id().as_str()
        || lock.selected_policy_key_epoch != policy_identity.key_epoch
        || decode_hex32(&lock.model_manifest_digest)? != release.model_manifest_digest()
        || decode_hex32(&lock.producer_registry_digest)? != release.producer_registry_digest()
        || decode_hex32(&lock.ontology_digest)? != release.ontology_digest()
        || decode_hex32(&lock.approval_key_set_digest)? != release.approval_key_set_digest()
        || decode_hex32(&lock.resource_profile_digest)? != release.resource_profile_digest()
    {
        return Err(release_mismatch());
    }
    verify_clients(lock, release)?;
    verify_policy_roots(lock, release)?;
    Ok(())
}

fn verify_clients(
    lock: &KernelLockV1,
    release: &VerifiedReleaseIdentity,
) -> Result<(), DaemonError> {
    if lock.daemon_clients.len() != release.daemon_clients().len() {
        return Err(release_mismatch());
    }
    for (locked, verified) in lock.daemon_clients.iter().zip(release.daemon_clients()) {
        if locked.client_id != verified.client_id().as_str()
            || locked.key_id != verified.key_id().as_str()
            || decode_hex32(&locked.public_key)? != Digest32::new(*verified.public_key())
            || locked.role != verified.role().as_lock_str()
            || locked.peer_uid != verified.peer_uid()
            || locked.peer_gid != verified.peer_gid()
        {
            return Err(release_mismatch());
        }
    }
    Ok(())
}

fn verify_policy_roots(
    lock: &KernelLockV1,
    release: &VerifiedReleaseIdentity,
) -> Result<(), DaemonError> {
    if lock.policy_trust_roots.len() != release.policy_trust_roots().len() {
        return Err(release_mismatch());
    }
    for (locked, verified) in lock
        .policy_trust_roots
        .iter()
        .zip(release.policy_trust_roots())
    {
        if locked.key_id != verified.key_id.as_str()
            || decode_hex32(&locked.public_key)? != Digest32::new(verified.public_key)
            || locked.epoch != verified.epoch
            || locked.revoked != verified.revoked
        {
            return Err(release_mismatch());
        }
    }
    Ok(())
}

fn decode_hex32(value: &str) -> Result<Digest32, DaemonError> {
    if value.len() != 64
        || !value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(release_mismatch());
    }
    let mut decoded = [0_u8; 32];
    for (target, pair) in decoded.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        *target = (decode_nibble(pair[0]) << 4) | decode_nibble(pair[1]);
    }
    Ok(Digest32::new(decoded))
}

fn decode_nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        _ => 0,
    }
}

fn hash_signature(signature: &Signature64) -> Digest32 {
    Digest32::new(Sha256::digest(signature.as_bytes()).into())
}

fn release_mismatch() -> DaemonError {
    DaemonError::stable(StableCode::IdentityReleaseMismatch)
}
