use std::ffi::{OsStr, OsString};
use std::fs::{self, File};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use aes_gcm::aead::{Aead as _, Payload};
use aes_gcm::{Aes256Gcm, KeyInit as _, Nonce};
use hmac::{Hmac, Mac as _};
use minicbor::Encode as _;
use nix::fcntl::{Flock, FlockArg};
use rustix::fs::{
    fchmod, open as rustix_open, openat, renameat, statat, unlinkat, AtFlags, FileType, Mode,
    OFlags,
};
use rustix::io::Errno;
use savana_kernel_protocol::v2::{
    BootIdV2, Digest32V2, DurableReleaseIdV2, DurableRunIdV2, DurableTaskIdV2,
    FinalReleaseSemanticBindingV2, Nonce32V2, PrincipalIdV2, ServiceIdentityV2, UnixMillisV2,
};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use super::{
    decode_vault_state_tag, is_zero, vault_segment_digest, AuthorizedVaultReleaseV2,
    DocumentCapabilityRecordV2, KernelPreparedReleaseDispatchV2, LiveVaultSegmentV2,
    MaskedDocumentHandleV2, PendingVaultReleaseV2, PendingVaultSegmentV2, VaultAccessContextV2,
    VaultDispatchPreparedV2, VaultErrorV2, VaultIngressMaterialV2, VaultPublicStateV2,
    VaultReleaseMaterialV2, VaultReleaseRecordV2, VaultReleaseRecoveryProjectionV2,
    VaultSegmentRecordV2, VaultServiceV2, VaultStateV2, VerifiedFinalReleaseApprovalV2,
};

const STATE_FILE_NAME: &str = "vault-state-v2.cbor";
const LOCK_FILE_NAME: &str = ".vault-state-v2.cbor.lock";
const SCHEMA_VERSION: u16 = 4;
const ENCRYPTION_DOMAIN: &[u8] = b"SAVANA_VAULT_STATE_ENCRYPTION_V2\0";
const KEY_DERIVATION_DOMAIN: &[u8] = b"SAVANA_VAULT_STATE_KEY_DERIVATION_V2\0";
const HEAD_DOMAIN: &[u8] = b"SAVANA_VAULT_STATE_HEAD_V2\0";
const NONCE_BYTES: usize = 12;
const MAX_STATE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_SEGMENTS: usize = 65_536;
const MAX_SEGMENT_BYTES: usize = 8 * 1024 * 1024;
const TEMP_ATTEMPTS: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VaultStateHeadV2 {
    sequence: u64,
    state_digest: Digest32V2,
}

impl Default for VaultStateHeadV2 {
    fn default() -> Self {
        Self::GENESIS
    }
}

impl VaultStateHeadV2 {
    const GENESIS: Self = Self {
        sequence: 0,
        state_digest: Digest32V2::new([0; 32]),
    };

    pub fn new(sequence: u64, state_digest: Digest32V2) -> Result<Self, VaultErrorV2> {
        if (sequence == 0 && !is_zero(state_digest.as_bytes()))
            || (sequence != 0 && is_zero(state_digest.as_bytes()))
        {
            return Err(VaultErrorV2::RollbackDetected);
        }
        Ok(Self {
            sequence,
            state_digest,
        })
    }

    pub const fn sequence(self) -> u64 {
        self.sequence
    }

    pub const fn state_digest(self) -> Digest32V2 {
        self.state_digest
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DurableVaultNamespaceV2 {
    installation_id: Digest32V2,
    store_id: Digest32V2,
}

impl DurableVaultNamespaceV2 {
    pub fn from_verified_installation(
        installation_id: Digest32V2,
        store_id: Digest32V2,
    ) -> Result<Self, VaultErrorV2> {
        if is_zero(installation_id.as_bytes()) || is_zero(store_id.as_bytes()) {
            return Err(VaultErrorV2::DurableState);
        }
        Ok(Self {
            installation_id,
            store_id,
        })
    }

    pub const fn installation_id(self) -> Digest32V2 {
        self.installation_id
    }

    pub const fn store_id(self) -> Digest32V2 {
        self.store_id
    }
}

pub trait VaultRollbackAnchorV2: Send {
    fn current_head(&self) -> Result<VaultStateHeadV2, VaultErrorV2>;

    fn compare_and_advance(
        &mut self,
        expected: VaultStateHeadV2,
        next: VaultStateHeadV2,
    ) -> Result<(), VaultErrorV2>;
}

pub struct DurableVaultServiceV2 {
    path: PathBuf,
    anchored_path: AnchoredPathV2,
    namespace: DurableVaultNamespaceV2,
    encryption_key: Zeroizing<[u8; 32]>,
    sequence: u64,
    previous_state_digest: Digest32V2,
    current_head: VaultStateHeadV2,
    rollback_anchor: Box<dyn VaultRollbackAnchorV2>,
    service: VaultServiceV2,
    poisoned: bool,
    lock: StateLockV2,
}

impl std::fmt::Debug for DurableVaultServiceV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DurableVaultServiceV2")
            .field("path", &self.path)
            .field("sequence", &self.sequence)
            .field("segment_count", &self.service.segments.len())
            .field("poisoned", &self.poisoned)
            .finish_non_exhaustive()
    }
}

impl DurableVaultServiceV2 {
    pub fn open(
        path: &Path,
        master_encryption_key: [u8; 32],
        namespace: DurableVaultNamespaceV2,
        mut rollback_anchor: Box<dyn VaultRollbackAnchorV2>,
        deployment: VaultServiceV2,
    ) -> Result<Self, VaultErrorV2> {
        if path.file_name().and_then(|name| name.to_str()) != Some(STATE_FILE_NAME)
            || master_encryption_key == [0; 32]
            || deployment.installation_id != namespace.installation_id
            || !deployment.segments.is_empty()
            || !deployment.documents.is_empty()
            || deployment.accepted_time_floor_ms != 0
        {
            return Err(VaultErrorV2::DurableState);
        }
        let anchored_path = AnchoredPathV2::open(path)?;
        let lock = StateLockV2::acquire(
            &anchored_path.parent,
            OsStr::new(LOCK_FILE_NAME),
            anchored_path.owner_uid,
            anchored_path.owner_gid,
        )?;
        anchored_path.recheck_parent()?;
        let encryption_key = derive_encryption_key(&master_encryption_key, namespace)?;
        let anchored_head = rollback_anchor.current_head()?;
        let (sequence, previous_state_digest, service, current_head) =
            match anchored_path.read_existing()? {
                Some(bytes) => {
                    let (sequence, previous_state_digest, service) =
                        decode_encrypted_snapshot(&bytes, &encryption_key, namespace, deployment)?;
                    let snapshot_head = VaultStateHeadV2 {
                        sequence,
                        state_digest: state_head_digest(namespace, &bytes),
                    };
                    if snapshot_head == anchored_head {
                        (sequence, previous_state_digest, service, snapshot_head)
                    } else if sequence
                        == anchored_head
                            .sequence
                            .checked_add(1)
                            .ok_or(VaultErrorV2::RollbackDetected)?
                        && previous_state_digest == anchored_head.state_digest
                    {
                        rollback_anchor.compare_and_advance(anchored_head, snapshot_head)?;
                        (sequence, previous_state_digest, service, snapshot_head)
                    } else {
                        return Err(VaultErrorV2::RollbackDetected);
                    }
                }
                None => {
                    if anchored_head != VaultStateHeadV2::GENESIS {
                        return Err(VaultErrorV2::RollbackDetected);
                    }
                    (
                        0,
                        Digest32V2::new([0; 32]),
                        deployment,
                        VaultStateHeadV2::GENESIS,
                    )
                }
            };
        Ok(Self {
            path: path.to_owned(),
            anchored_path,
            namespace,
            encryption_key,
            sequence,
            previous_state_digest,
            current_head,
            rollback_anchor,
            service,
            poisoned: false,
            lock,
        })
    }

    pub fn segment_count(&self) -> usize {
        self.service.segments.len()
    }

    pub fn recovery_projection(
        &self,
    ) -> Result<Vec<VaultReleaseRecoveryProjectionV2>, VaultErrorV2> {
        self.ensure_usable()?;
        self.service.recovery_projection()
    }

    pub fn authenticated_state_head(&self) -> Result<VaultStateHeadV2, VaultErrorV2> {
        self.ensure_usable()?;
        Ok(self.current_head)
    }

    pub fn create_pending_ingress(
        &mut self,
        material: VaultIngressMaterialV2,
        now: UnixMillisV2,
    ) -> Result<PendingVaultSegmentV2, VaultErrorV2> {
        self.mutate(|service| service.create_pending_ingress(material, now))
    }

    pub fn ingest_verified(
        &mut self,
        material: VaultIngressMaterialV2,
        now: UnixMillisV2,
    ) -> Result<LiveVaultSegmentV2, VaultErrorV2> {
        self.mutate(|service| service.ingest_verified(material, now))
    }

    pub fn create_pending_tool_result(
        &mut self,
        material: VaultIngressMaterialV2,
        now: UnixMillisV2,
    ) -> Result<PendingVaultSegmentV2, VaultErrorV2> {
        self.mutate(|service| service.create_pending_tool_result(material, now))
    }

    pub fn recover_committed_tool_result(
        &mut self,
        task: DurableTaskIdV2,
        run: DurableRunIdV2,
        principal: PrincipalIdV2,
        commit: Digest32V2,
        expires_at: UnixMillisV2,
        now: UnixMillisV2,
    ) -> Result<LiveVaultSegmentV2, VaultErrorV2> {
        self.mutate(|service| {
            service.recover_committed_tool_result(task, run, principal, commit, expires_at, now)
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn prepare_committed_tool_result_release(
        &mut self,
        task: DurableTaskIdV2,
        run: DurableRunIdV2,
        principal: PrincipalIdV2,
        commit: Digest32V2,
        expires: UnixMillisV2,
        material: VaultReleaseMaterialV2,
        now: UnixMillisV2,
    ) -> Result<PendingVaultReleaseV2, VaultErrorV2> {
        self.mutate(|s| {
            s.prepare_committed_tool_result_release(
                task, run, principal, commit, expires, material, now,
            )
        })
    }

    pub fn commit_ingress(
        &mut self,
        pending: PendingVaultSegmentV2,
        now: UnixMillisV2,
    ) -> Result<LiveVaultSegmentV2, VaultErrorV2> {
        self.mutate(|service| service.commit_ingress(pending, now))
    }

    pub fn issue_masked_document(
        &mut self,
        live: &LiveVaultSegmentV2,
        context: VaultAccessContextV2,
        now: UnixMillisV2,
    ) -> Result<MaskedDocumentHandleV2, VaultErrorV2> {
        self.mutate(|service| service.issue_masked_document(live, context, now))
    }

    pub fn read_agent_bytes(
        &mut self,
        document: &MaskedDocumentHandleV2,
        context: VaultAccessContextV2,
        now: UnixMillisV2,
    ) -> Result<Zeroizing<Vec<u8>>, VaultErrorV2> {
        self.mutate(|service| service.read_agent_bytes(document, context, now))
    }

    pub fn read_agent_bytes_for_authenticated_agent(
        &mut self,
        document: &MaskedDocumentHandleV2,
        boot_id: savana_kernel_protocol::v2::BootIdV2,
        service_identity: savana_kernel_protocol::v2::ServiceIdentityV2,
        peer_identity_digest: Digest32V2,
        now: UnixMillisV2,
    ) -> Result<Zeroizing<Vec<u8>>, VaultErrorV2> {
        self.mutate(|service| {
            service.read_agent_bytes_for_authenticated_agent(
                document,
                boot_id,
                service_identity,
                peer_identity_digest,
                now,
            )
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn read_release_bytes_for_authenticated_agent(
        &mut self,
        document: &MaskedDocumentHandleV2,
        boot_id: savana_kernel_protocol::v2::BootIdV2,
        service_identity: savana_kernel_protocol::v2::ServiceIdentityV2,
        peer_identity_digest: Digest32V2,
        durable_run_id: savana_kernel_protocol::v2::DurableRunIdV2,
        now: UnixMillisV2,
    ) -> Result<Zeroizing<Vec<u8>>, VaultErrorV2> {
        self.mutate(|service| {
            service.read_release_bytes_for_authenticated_agent(
                document,
                boot_id,
                service_identity,
                peer_identity_digest,
                durable_run_id,
                now,
            )
        })
    }

    pub fn prepare_release(
        &mut self,
        document: &MaskedDocumentHandleV2,
        context: VaultAccessContextV2,
        material: VaultReleaseMaterialV2,
        now: UnixMillisV2,
    ) -> Result<PendingVaultReleaseV2, VaultErrorV2> {
        self.mutate(|service| service.prepare_release(document, context, material, now))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn prepare_release_for_authenticated_agent(
        &mut self,
        document: &MaskedDocumentHandleV2,
        boot_id: savana_kernel_protocol::v2::BootIdV2,
        service_identity: savana_kernel_protocol::v2::ServiceIdentityV2,
        peer_identity_digest: Digest32V2,
        durable_run_id: savana_kernel_protocol::v2::DurableRunIdV2,
        material: VaultReleaseMaterialV2,
        now: UnixMillisV2,
    ) -> Result<PendingVaultReleaseV2, VaultErrorV2> {
        self.mutate(|service| {
            service.prepare_release_for_authenticated_agent(
                document,
                boot_id,
                service_identity,
                peer_identity_digest,
                durable_run_id,
                material,
                now,
            )
        })
    }

    pub fn authorize_release(
        &mut self,
        pending: PendingVaultReleaseV2,
        approval: VerifiedFinalReleaseApprovalV2,
        now: UnixMillisV2,
    ) -> Result<AuthorizedVaultReleaseV2, VaultErrorV2> {
        self.mutate(|service| service.authorize_release(pending, approval, now))
    }

    pub fn mark_dispatch_prepared(
        &mut self,
        authorized: AuthorizedVaultReleaseV2,
        commit: KernelPreparedReleaseDispatchV2,
        now: UnixMillisV2,
    ) -> Result<VaultDispatchPreparedV2, VaultErrorV2> {
        self.mutate(|service| service.mark_dispatch_prepared(authorized, commit, now))
    }

    pub fn mark_dispatching(
        &mut self,
        prepared: VaultDispatchPreparedV2,
        now: UnixMillisV2,
    ) -> Result<(), VaultErrorV2> {
        self.mutate(|service| service.mark_dispatching(prepared, now))
    }

    pub fn commit_known_release(
        &mut self,
        prepared: VaultDispatchPreparedV2,
        final_release_receipt_digest: Digest32V2,
        release_audit_digest: Digest32V2,
        now: UnixMillisV2,
    ) -> Result<(), VaultErrorV2> {
        self.mutate(|service| {
            service.commit_known_release(
                prepared,
                final_release_receipt_digest,
                release_audit_digest,
                now,
            )
        })
    }

    pub fn mark_indeterminate(
        &mut self,
        prepared: VaultDispatchPreparedV2,
        now: UnixMillisV2,
    ) -> Result<(), VaultErrorV2> {
        self.mutate(|service| service.mark_indeterminate(prepared, now))
    }

    pub fn mark_failed_no_effect_by_identity(
        &mut self,
        durable_release_id: savana_kernel_protocol::v2::DurableReleaseIdV2,
        execution_nonce: savana_kernel_protocol::v2::Nonce32V2,
        dispatch_core_digest: Digest32V2,
        dispatch_subject_digest: Digest32V2,
        now: UnixMillisV2,
    ) -> Result<(), VaultErrorV2> {
        self.mutate(|service| {
            service.mark_failed_no_effect_by_identity(
                durable_release_id,
                execution_nonce,
                dispatch_core_digest,
                dispatch_subject_digest,
                now,
            )
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn commit_known_release_by_identity(
        &mut self,
        durable_release_id: savana_kernel_protocol::v2::DurableReleaseIdV2,
        execution_nonce: savana_kernel_protocol::v2::Nonce32V2,
        dispatch_core_digest: Digest32V2,
        dispatch_subject_digest: Digest32V2,
        final_release_receipt_digest: Digest32V2,
        release_audit_digest: Digest32V2,
        now: UnixMillisV2,
    ) -> Result<(), VaultErrorV2> {
        self.mutate(|service| {
            service.commit_known_release_by_identity(
                durable_release_id,
                execution_nonce,
                dispatch_core_digest,
                dispatch_subject_digest,
                final_release_receipt_digest,
                release_audit_digest,
                now,
            )
        })
    }

    pub fn mark_indeterminate_by_identity(
        &mut self,
        durable_release_id: savana_kernel_protocol::v2::DurableReleaseIdV2,
        execution_nonce: savana_kernel_protocol::v2::Nonce32V2,
        dispatch_core_digest: Digest32V2,
        dispatch_subject_digest: Digest32V2,
        now: UnixMillisV2,
    ) -> Result<(), VaultErrorV2> {
        self.mutate(|service| {
            service.mark_indeterminate_by_identity(
                durable_release_id,
                execution_nonce,
                dispatch_core_digest,
                dispatch_subject_digest,
                now,
            )
        })
    }

    pub fn revoke(
        &mut self,
        document: &MaskedDocumentHandleV2,
        context: VaultAccessContextV2,
        now: UnixMillisV2,
    ) -> Result<VaultPublicStateV2, VaultErrorV2> {
        self.mutate(|service| service.revoke(document, context, now))
    }

    pub fn revoke_for_authenticated_agent(
        &mut self,
        document: &MaskedDocumentHandleV2,
        boot_id: savana_kernel_protocol::v2::BootIdV2,
        service_identity: savana_kernel_protocol::v2::ServiceIdentityV2,
        peer_identity_digest: Digest32V2,
        now: UnixMillisV2,
    ) -> Result<VaultPublicStateV2, VaultErrorV2> {
        self.mutate(|service| {
            service.revoke_for_authenticated_agent(
                document,
                boot_id,
                service_identity,
                peer_identity_digest,
                now,
            )
        })
    }

    pub fn public_state(
        &mut self,
        document: &MaskedDocumentHandleV2,
        context: VaultAccessContextV2,
        now: UnixMillisV2,
    ) -> Result<VaultPublicStateV2, VaultErrorV2> {
        self.mutate(|service| service.public_state(document, context, now))
    }

    pub fn state_record_digest(
        &mut self,
        document: &MaskedDocumentHandleV2,
        context: VaultAccessContextV2,
        now: UnixMillisV2,
    ) -> Result<Digest32V2, VaultErrorV2> {
        self.mutate(|service| service.state_record_digest(document, context, now))
    }

    pub fn invalidate_for_restart(
        &mut self,
        live: &LiveVaultSegmentV2,
        now: UnixMillisV2,
    ) -> Result<VaultPublicStateV2, VaultErrorV2> {
        self.mutate(|service| service.invalidate_for_restart(live, now))
    }

    fn mutate<T>(
        &mut self,
        operation: impl FnOnce(&mut VaultServiceV2) -> Result<T, VaultErrorV2>,
    ) -> Result<T, VaultErrorV2> {
        self.ensure_usable()?;
        let mut next = self.service.clone();
        let result = operation(&mut next)?;
        self.commit(next)?;
        Ok(result)
    }

    fn ensure_usable(&self) -> Result<(), VaultErrorV2> {
        if self.poisoned {
            Err(VaultErrorV2::CommitUncertain)
        } else {
            Ok(())
        }
    }

    fn commit(&mut self, next: VaultServiceV2) -> Result<(), VaultErrorV2> {
        let sequence = self
            .sequence
            .checked_add(1)
            .ok_or(VaultErrorV2::DurableState)?;
        let previous_state_digest = self.current_head.state_digest;
        validate_service(&next)?;
        let bytes = encode_encrypted_snapshot(
            sequence,
            previous_state_digest,
            &next,
            &self.encryption_key,
            self.namespace,
        )?;
        let next_head = VaultStateHeadV2 {
            sequence,
            state_digest: state_head_digest(self.namespace, &bytes),
        };
        self.lock.recheck()?;
        match self.anchored_path.replace(&bytes) {
            Ok(()) => {
                if self
                    .rollback_anchor
                    .compare_and_advance(self.current_head, next_head)
                    .is_err()
                {
                    self.poisoned = true;
                    return Err(VaultErrorV2::CommitUncertain);
                }
                self.service = next;
                self.sequence = sequence;
                self.previous_state_digest = previous_state_digest;
                self.current_head = next_head;
                Ok(())
            }
            Err(after_rename) => {
                if after_rename {
                    self.poisoned = true;
                    Err(VaultErrorV2::CommitUncertain)
                } else {
                    Err(VaultErrorV2::DurableState)
                }
            }
        }
    }
}

fn encode_encrypted_snapshot(
    sequence: u64,
    previous_state_digest: Digest32V2,
    service: &VaultServiceV2,
    key: &[u8; 32],
    namespace: DurableVaultNamespaceV2,
) -> Result<Vec<u8>, VaultErrorV2> {
    let payload = encode_snapshot_payload(sequence, previous_state_digest, service)?;
    let mut nonce = [0_u8; NONCE_BYTES];
    getrandom::getrandom(&mut nonce).map_err(|_| VaultErrorV2::DurableState)?;
    if nonce == [0; NONCE_BYTES] {
        return Err(VaultErrorV2::DurableState);
    }
    let aad = encryption_aad(namespace, sequence, previous_state_digest, &nonce);
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| VaultErrorV2::DurableAuthentication)?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: payload.as_slice(),
                aad: &aad,
            },
        )
        .map_err(|_| VaultErrorV2::DurableAuthentication)?;
    encode_encrypted_envelope(sequence, previous_state_digest, &nonce, &ciphertext)
}

fn decode_encrypted_snapshot(
    bytes: &[u8],
    key: &[u8; 32],
    namespace: DurableVaultNamespaceV2,
    deployment: VaultServiceV2,
) -> Result<(u64, Digest32V2, VaultServiceV2), VaultErrorV2> {
    if bytes.len() as u64 > MAX_STATE_BYTES {
        return Err(VaultErrorV2::DurableState);
    }
    let mut decoder = minicbor::Decoder::new(bytes);
    require_array(&mut decoder, 5)?;
    if decoder.u16().map_err(|_| VaultErrorV2::DurableState)? != SCHEMA_VERSION {
        return Err(VaultErrorV2::DurableState);
    }
    let sequence = decoder.u64().map_err(|_| VaultErrorV2::DurableState)?;
    let previous_state_digest = Digest32V2::new(decode_fixed::<32>(&mut decoder)?);
    let nonce = decode_fixed::<NONCE_BYTES>(&mut decoder)?;
    let ciphertext = decoder.bytes().map_err(|_| VaultErrorV2::DurableState)?;
    if decoder.position() != bytes.len()
        || encode_encrypted_envelope(sequence, previous_state_digest, &nonce, ciphertext)? != bytes
    {
        return Err(VaultErrorV2::DurableState);
    }
    let aad = encryption_aad(namespace, sequence, previous_state_digest, &nonce);
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| VaultErrorV2::DurableAuthentication)?;
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| VaultErrorV2::DurableAuthentication)?,
    );
    let service = decode_snapshot_payload(&plaintext, sequence, previous_state_digest, deployment)?;
    if encode_snapshot_payload(sequence, previous_state_digest, &service)?.as_slice()
        != plaintext.as_slice()
    {
        return Err(VaultErrorV2::DurableState);
    }
    Ok((sequence, previous_state_digest, service))
}

fn encode_encrypted_envelope(
    sequence: u64,
    previous_state_digest: Digest32V2,
    nonce: &[u8; NONCE_BYTES],
    ciphertext: &[u8],
) -> Result<Vec<u8>, VaultErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(5)
        .and_then(|encoder| encoder.u16(SCHEMA_VERSION))
        .and_then(|encoder| encoder.u64(sequence))
        .map_err(|_| VaultErrorV2::AllocationFailure)?;
    previous_state_digest
        .encode(&mut encoder, &mut ())
        .map_err(|_| VaultErrorV2::AllocationFailure)?;
    encoder
        .bytes(nonce)
        .and_then(|encoder| encoder.bytes(ciphertext))
        .map_err(|_| VaultErrorV2::AllocationFailure)?;
    let bytes = encoder.into_writer();
    if bytes.len() as u64 > MAX_STATE_BYTES {
        return Err(VaultErrorV2::AllocationFailure);
    }
    Ok(bytes)
}

fn encode_snapshot_payload(
    sequence: u64,
    previous_state_digest: Digest32V2,
    service: &VaultServiceV2,
) -> Result<Zeroizing<Vec<u8>>, VaultErrorV2> {
    validate_service(service)?;
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(10)
        .and_then(|encoder| encoder.u16(SCHEMA_VERSION))
        .and_then(|encoder| encoder.u64(sequence))
        .map_err(|_| VaultErrorV2::AllocationFailure)?;
    previous_state_digest
        .encode(&mut encoder, &mut ())
        .map_err(|_| VaultErrorV2::AllocationFailure)?;
    service
        .installation_id
        .encode(&mut encoder, &mut ())
        .map_err(|_| VaultErrorV2::AllocationFailure)?;
    service
        .active_state_manifest_digest
        .encode(&mut encoder, &mut ())
        .map_err(|_| VaultErrorV2::AllocationFailure)?;
    encoder
        .u64(service.accepted_time_floor_ms)
        .and_then(|encoder| encoder.u32(service.maximum_segments as u32))
        .and_then(|encoder| encoder.bytes(service.capability_key.as_slice()))
        .and_then(|encoder| encoder.array(service.segments.len() as u64))
        .map_err(|_| VaultErrorV2::AllocationFailure)?;
    for segment in &service.segments {
        encode_segment(&mut encoder, segment)?;
    }
    encoder
        .array(service.documents.len() as u64)
        .map_err(|_| VaultErrorV2::AllocationFailure)?;
    for document in &service.documents {
        encode_document(&mut encoder, document)?;
    }
    Ok(Zeroizing::new(encoder.into_writer()))
}

fn encode_document(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    document: &DocumentCapabilityRecordV2,
) -> Result<(), VaultErrorV2> {
    encoder
        .array(7)
        .map_err(|_| VaultErrorV2::AllocationFailure)?;
    for digest in [
        document.token_digest,
        document.internal_id,
        document.context.peer_identity_digest,
    ] {
        digest
            .encode(encoder, &mut ())
            .map_err(|_| VaultErrorV2::AllocationFailure)?;
    }
    document
        .context
        .boot_id
        .encode(encoder, &mut ())
        .map_err(|_| VaultErrorV2::AllocationFailure)?;
    document
        .context
        .service_identity
        .encode(encoder, &mut ())
        .map_err(|_| VaultErrorV2::AllocationFailure)?;
    document
        .context
        .durable_run_id
        .encode(encoder, &mut ())
        .map_err(|_| VaultErrorV2::AllocationFailure)?;
    encoder
        .u64(document.context.expires_at.get())
        .map(|_| ())
        .map_err(|_| VaultErrorV2::AllocationFailure)
}

fn encode_segment(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    segment: &VaultSegmentRecordV2,
) -> Result<(), VaultErrorV2> {
    encoder
        .array(13)
        .map_err(|_| VaultErrorV2::AllocationFailure)?;
    for digest in [segment.internal_id, segment.authority_digest] {
        digest
            .encode(encoder, &mut ())
            .map_err(|_| VaultErrorV2::AllocationFailure)?;
    }
    segment
        .durable_task_id
        .encode(encoder, &mut ())
        .map_err(|_| VaultErrorV2::AllocationFailure)?;
    segment
        .durable_run_id
        .encode(encoder, &mut ())
        .map_err(|_| VaultErrorV2::AllocationFailure)?;
    segment
        .authenticated_principal
        .encode(encoder, &mut ())
        .map_err(|_| VaultErrorV2::AllocationFailure)?;
    for digest in [
        segment.provenance_digest,
        segment.input_commit_digest,
        segment.segment_digest,
    ] {
        digest
            .encode(encoder, &mut ())
            .map_err(|_| VaultErrorV2::AllocationFailure)?;
    }
    encoder
        .u64(segment.expires_at.get())
        .and_then(|encoder| encoder.u64(segment.state_revision))
        .and_then(|encoder| encoder.u16(super::vault_state_tag(segment.state)))
        .and_then(|encoder| encoder.bytes(segment.sensitive_bytes.as_slice()))
        .map_err(|_| VaultErrorV2::AllocationFailure)?;
    match segment.release.as_ref() {
        Some(release) => encode_release(encoder, release),
        None => encoder
            .null()
            .map(|_| ())
            .map_err(|_| VaultErrorV2::AllocationFailure),
    }
}

fn encode_release(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    release: &VaultReleaseRecordV2,
) -> Result<(), VaultErrorV2> {
    encoder
        .array(11)
        .map_err(|_| VaultErrorV2::AllocationFailure)?;
    release
        .capability_digest
        .encode(encoder, &mut ())
        .map_err(|_| VaultErrorV2::AllocationFailure)?;
    release
        .binding
        .encode(encoder, &mut ())
        .map_err(|_| VaultErrorV2::AllocationFailure)?;
    release
        .binding_digest
        .encode(encoder, &mut ())
        .map_err(|_| VaultErrorV2::AllocationFailure)?;
    encode_optional_fixed(
        encoder,
        release.approval_principal.map(|value| *value.as_bytes()),
    )?;
    encode_optional_fixed(
        encoder,
        release
            .approval_settlement_digest
            .map(|value| *value.as_bytes()),
    )?;
    encode_optional_fixed(
        encoder,
        release
            .consumed_ticket_digest
            .map(|value| *value.as_bytes()),
    )?;
    encode_optional_fixed(
        encoder,
        release.execution_nonce.map(|value| *value.as_bytes()),
    )?;
    encode_optional_fixed(
        encoder,
        release.dispatch_core_digest.map(|value| *value.as_bytes()),
    )?;
    encode_optional_fixed(
        encoder,
        release
            .dispatch_subject_digest
            .map(|value| *value.as_bytes()),
    )?;
    encode_optional_fixed(
        encoder,
        release
            .final_release_receipt_digest
            .map(|value| *value.as_bytes()),
    )?;
    encode_optional_fixed(
        encoder,
        release.release_audit_digest.map(|value| *value.as_bytes()),
    )
}

fn encode_optional_fixed<const N: usize>(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    value: Option<[u8; N]>,
) -> Result<(), VaultErrorV2> {
    match value {
        Some(bytes) => encoder
            .bytes(&bytes)
            .map(|_| ())
            .map_err(|_| VaultErrorV2::AllocationFailure),
        None => encoder
            .null()
            .map(|_| ())
            .map_err(|_| VaultErrorV2::AllocationFailure),
    }
}

fn decode_snapshot_payload(
    bytes: &[u8],
    expected_sequence: u64,
    expected_previous_state_digest: Digest32V2,
    mut service: VaultServiceV2,
) -> Result<VaultServiceV2, VaultErrorV2> {
    let mut decoder = minicbor::Decoder::new(bytes);
    require_array(&mut decoder, 10)?;
    if decoder.u16().map_err(|_| VaultErrorV2::DurableState)? != SCHEMA_VERSION
        || decoder.u64().map_err(|_| VaultErrorV2::DurableState)? != expected_sequence
        || Digest32V2::new(decode_fixed::<32>(&mut decoder)?) != expected_previous_state_digest
        || Digest32V2::new(decode_fixed::<32>(&mut decoder)?) != service.installation_id
        || Digest32V2::new(decode_fixed::<32>(&mut decoder)?)
            != service.active_state_manifest_digest
    {
        return Err(VaultErrorV2::DurableState);
    }
    service.accepted_time_floor_ms = decoder.u64().map_err(|_| VaultErrorV2::DurableState)?;
    let maximum_segments = decoder.u32().map_err(|_| VaultErrorV2::DurableState)? as usize;
    if maximum_segments != service.maximum_segments {
        return Err(VaultErrorV2::DurableState);
    }
    let capability_key = decode_fixed::<32>(&mut decoder)?;
    if capability_key == [0; 32] {
        return Err(VaultErrorV2::DurableState);
    }
    service.capability_key = Zeroizing::new(capability_key);
    let count = decode_count(&mut decoder, MAX_SEGMENTS)?;
    service
        .segments
        .try_reserve(count)
        .map_err(|_| VaultErrorV2::AllocationFailure)?;
    for _ in 0..count {
        service.segments.push(decode_segment(&mut decoder)?);
    }
    let document_count = decode_count(&mut decoder, super::MAX_DOCUMENT_CAPABILITIES)?;
    service
        .documents
        .try_reserve(document_count)
        .map_err(|_| VaultErrorV2::AllocationFailure)?;
    for _ in 0..document_count {
        service.documents.push(decode_document(&mut decoder)?);
    }
    if decoder.position() != bytes.len() {
        return Err(VaultErrorV2::DurableState);
    }
    validate_service(&service)?;
    Ok(service)
}

fn decode_document(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<DocumentCapabilityRecordV2, VaultErrorV2> {
    require_array(decoder, 7)?;
    let token_digest = Digest32V2::new(decode_fixed::<32>(decoder)?);
    let internal_id = Digest32V2::new(decode_fixed::<32>(decoder)?);
    let peer_identity_digest = Digest32V2::new(decode_fixed::<32>(decoder)?);
    let boot_id = BootIdV2::new(decode_fixed::<32>(decoder)?);
    let service_identity = ServiceIdentityV2::new(decode_fixed::<32>(decoder)?);
    let durable_run_id = DurableRunIdV2::new(decode_fixed::<32>(decoder)?);
    let expires_at = UnixMillisV2::new(decoder.u64().map_err(|_| VaultErrorV2::DurableState)?);
    Ok(DocumentCapabilityRecordV2 {
        token_digest,
        internal_id,
        context: super::VaultAccessContextV2 {
            boot_id,
            service_identity,
            peer_identity_digest,
            durable_run_id,
            expires_at,
        },
    })
}

fn decode_segment(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<VaultSegmentRecordV2, VaultErrorV2> {
    require_array(decoder, 13)?;
    let internal_id = Digest32V2::new(decode_fixed::<32>(decoder)?);
    let authority_digest = Digest32V2::new(decode_fixed::<32>(decoder)?);
    let durable_task_id = DurableTaskIdV2::new(decode_fixed::<32>(decoder)?);
    let durable_run_id = DurableRunIdV2::new(decode_fixed::<32>(decoder)?);
    let authenticated_principal = PrincipalIdV2::new(decode_fixed::<32>(decoder)?);
    let provenance_digest = Digest32V2::new(decode_fixed::<32>(decoder)?);
    let input_commit_digest = Digest32V2::new(decode_fixed::<32>(decoder)?);
    let segment_digest = Digest32V2::new(decode_fixed::<32>(decoder)?);
    let expires_at = UnixMillisV2::new(decoder.u64().map_err(|_| VaultErrorV2::DurableState)?);
    let state_revision = decoder.u64().map_err(|_| VaultErrorV2::DurableState)?;
    let state = decode_vault_state_tag(decoder.u16().map_err(|_| VaultErrorV2::DurableState)?)
        .ok_or(VaultErrorV2::DurableState)?;
    let sensitive_bytes = decoder.bytes().map_err(|_| VaultErrorV2::DurableState)?;
    if sensitive_bytes.len() > MAX_SEGMENT_BYTES {
        return Err(VaultErrorV2::DurableState);
    }
    let sensitive_bytes = Zeroizing::new(sensitive_bytes.to_vec());
    let release = if decoder.datatype().map_err(|_| VaultErrorV2::DurableState)?
        == minicbor::data::Type::Null
    {
        decoder.null().map_err(|_| VaultErrorV2::DurableState)?;
        None
    } else {
        Some(decode_release(decoder)?)
    };
    Ok(VaultSegmentRecordV2 {
        internal_id,
        authority_digest,
        durable_task_id,
        durable_run_id,
        authenticated_principal,
        provenance_digest,
        input_commit_digest,
        segment_digest,
        expires_at,
        state_revision,
        state,
        sensitive_bytes,
        release,
    })
}

fn decode_release(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<VaultReleaseRecordV2, VaultErrorV2> {
    require_array(decoder, 11)?;
    let capability_digest = Digest32V2::new(decode_fixed::<32>(decoder)?);
    let binding = decode_binding(decoder)?;
    let binding_digest = Digest32V2::new(decode_fixed::<32>(decoder)?);
    let approval_principal = decode_optional_fixed::<32>(decoder)?.map(PrincipalIdV2::new);
    let approval_settlement_digest = decode_optional_fixed::<32>(decoder)?.map(Digest32V2::new);
    let consumed_ticket_digest = decode_optional_fixed::<32>(decoder)?.map(Digest32V2::new);
    let execution_nonce = decode_optional_fixed::<32>(decoder)?.map(Nonce32V2::new);
    let dispatch_core_digest = decode_optional_fixed::<32>(decoder)?.map(Digest32V2::new);
    let dispatch_subject_digest = decode_optional_fixed::<32>(decoder)?.map(Digest32V2::new);
    let final_release_receipt_digest = decode_optional_fixed::<32>(decoder)?.map(Digest32V2::new);
    let release_audit_digest = decode_optional_fixed::<32>(decoder)?.map(Digest32V2::new);
    Ok(VaultReleaseRecordV2 {
        capability_digest,
        binding,
        binding_digest,
        approval_principal,
        approval_settlement_digest,
        consumed_ticket_digest,
        execution_nonce,
        dispatch_core_digest,
        dispatch_subject_digest,
        final_release_receipt_digest,
        release_audit_digest,
    })
}

fn decode_binding(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<FinalReleaseSemanticBindingV2, VaultErrorV2> {
    require_array(decoder, 11)?;
    FinalReleaseSemanticBindingV2::from_nonzero_components(
        DurableReleaseIdV2::new(decode_fixed::<32>(decoder)?),
        Digest32V2::new(decode_fixed::<32>(decoder)?),
        Digest32V2::new(decode_fixed::<32>(decoder)?),
        Digest32V2::new(decode_fixed::<32>(decoder)?),
        Digest32V2::new(decode_fixed::<32>(decoder)?),
        Digest32V2::new(decode_fixed::<32>(decoder)?),
        Digest32V2::new(decode_fixed::<32>(decoder)?),
        Digest32V2::new(decode_fixed::<32>(decoder)?),
        Digest32V2::new(decode_fixed::<32>(decoder)?),
        Digest32V2::new(decode_fixed::<32>(decoder)?),
        Digest32V2::new(decode_fixed::<32>(decoder)?),
    )
    .ok_or(VaultErrorV2::DurableState)
}

fn validate_service(service: &VaultServiceV2) -> Result<(), VaultErrorV2> {
    if is_zero(service.installation_id.as_bytes())
        || is_zero(service.active_state_manifest_digest.as_bytes())
        || is_zero(service.boot_id.as_bytes())
        || service.capability_key.iter().all(|byte| *byte == 0)
        || service.maximum_segments == 0
        || service.maximum_segments > MAX_SEGMENTS
        || service.segments.len() > service.maximum_segments
    {
        return Err(VaultErrorV2::DurableState);
    }
    for (position, segment) in service.segments.iter().enumerate() {
        if [
            segment.internal_id.as_bytes(),
            segment.authority_digest.as_bytes(),
            segment.durable_task_id.as_bytes(),
            segment.durable_run_id.as_bytes(),
            segment.authenticated_principal.as_bytes(),
            segment.provenance_digest.as_bytes(),
            segment.input_commit_digest.as_bytes(),
            segment.segment_digest.as_bytes(),
        ]
        .iter()
        .any(|value| is_zero(value))
            || segment.expires_at.get() == 0
            || segment.state_revision == 0
            || service.segments[..position]
                .iter()
                .any(|prior| prior.internal_id == segment.internal_id)
        {
            return Err(VaultErrorV2::DurableState);
        }
        let terminal = matches!(
            segment.state,
            VaultStateV2::Released
                | VaultStateV2::FailedNoEffect
                | VaultStateV2::Revoked
                | VaultStateV2::Expired
                | VaultStateV2::Indeterminate
                | VaultStateV2::RestartInvalidated
        );
        if terminal && !segment.sensitive_bytes.is_empty() {
            return Err(VaultErrorV2::DurableState);
        }
        if !terminal {
            let material = VaultIngressMaterialV2 {
                durable_task_id: segment.durable_task_id,
                durable_run_id: segment.durable_run_id,
                authenticated_principal: segment.authenticated_principal,
                provenance_digest: segment.provenance_digest,
                input_commit_digest: segment.input_commit_digest,
                expires_at: segment.expires_at,
                sensitive_bytes: Zeroizing::new(segment.sensitive_bytes.to_vec()),
            };
            if vault_segment_digest(
                service.installation_id,
                service.active_state_manifest_digest,
                segment.internal_id,
                &material,
            ) != segment.segment_digest
            {
                return Err(VaultErrorV2::DurableState);
            }
        }
        validate_release(segment)?;
    }
    if service.documents.len() > super::MAX_DOCUMENT_CAPABILITIES {
        return Err(VaultErrorV2::DurableState);
    }
    for (position, document) in service.documents.iter().enumerate() {
        if [
            document.token_digest.as_bytes(),
            document.internal_id.as_bytes(),
            document.context.boot_id.as_bytes(),
            document.context.service_identity.as_bytes(),
            document.context.peer_identity_digest.as_bytes(),
            document.context.durable_run_id.as_bytes(),
        ]
        .iter()
        .any(|value| is_zero(value))
            || document.context.expires_at.get() == 0
            || service.documents[..position]
                .iter()
                .any(|prior| prior.token_digest == document.token_digest)
            || !service.segments.iter().any(|segment| {
                segment.internal_id == document.internal_id
                    && segment.durable_run_id == document.context.durable_run_id
            })
        {
            return Err(VaultErrorV2::DurableState);
        }
    }
    Ok(())
}

fn validate_release(segment: &VaultSegmentRecordV2) -> Result<(), VaultErrorV2> {
    let Some(release) = segment.release.as_ref() else {
        if !matches!(
            segment.state,
            VaultStateV2::PendingIngress
                | VaultStateV2::Live
                | VaultStateV2::Revoked
                | VaultStateV2::Expired
                | VaultStateV2::RestartInvalidated
        ) {
            return Err(VaultErrorV2::DurableState);
        }
        return Ok(());
    };
    if is_zero(release.capability_digest.as_bytes())
        || release.binding.vault_segment_internal_id() != segment.internal_id
        || release.binding.vault_segment_digest() != segment.segment_digest
        || release.binding_digest
            != release
                .binding
                .semantic_digest()
                .ok_or(VaultErrorV2::DurableState)?
    {
        return Err(VaultErrorV2::DurableState);
    }
    let approval_pair =
        release.approval_principal.is_some() && release.approval_settlement_digest.is_some();
    let dispatch_identity = release.execution_nonce.is_some()
        && release.dispatch_core_digest.is_some()
        && release.dispatch_subject_digest.is_some();
    let dispatch_all = release.consumed_ticket_digest.is_some() && dispatch_identity;
    let completion_pair =
        release.final_release_receipt_digest.is_some() && release.release_audit_digest.is_some();
    if release.approval_principal.is_some() != release.approval_settlement_digest.is_some()
        || [
            release.execution_nonce.is_some(),
            release.dispatch_core_digest.is_some(),
            release.dispatch_subject_digest.is_some(),
        ]
        .iter()
        .any(|present| *present != dispatch_identity)
        || (release.consumed_ticket_digest.is_some() && !dispatch_identity)
        || release.final_release_receipt_digest.is_some() != release.release_audit_digest.is_some()
    {
        return Err(VaultErrorV2::DurableState);
    }
    let valid = match segment.state {
        VaultStateV2::Live | VaultStateV2::Revoked | VaultStateV2::Expired => {
            !approval_pair && !dispatch_identity && !completion_pair
        }
        VaultStateV2::ReleaseAuthorized => approval_pair && !dispatch_identity && !completion_pair,
        VaultStateV2::DispatchPrepared
        | VaultStateV2::Dispatching
        | VaultStateV2::Indeterminate => approval_pair && dispatch_all && !completion_pair,
        VaultStateV2::Released => approval_pair && dispatch_all && completion_pair,
        VaultStateV2::FailedNoEffect => approval_pair && dispatch_identity && !completion_pair,
        VaultStateV2::RestartInvalidated => !dispatch_identity && !completion_pair,
        VaultStateV2::PendingIngress => false,
    };
    if !valid {
        return Err(VaultErrorV2::DurableState);
    }
    Ok(())
}

fn derive_encryption_key(
    master: &[u8; 32],
    namespace: DurableVaultNamespaceV2,
) -> Result<Zeroizing<[u8; 32]>, VaultErrorV2> {
    let mut mac = <Hmac<Sha256> as hmac::Mac>::new_from_slice(master)
        .map_err(|_| VaultErrorV2::DurableState)?;
    mac.update(KEY_DERIVATION_DOMAIN);
    mac.update(namespace.installation_id.as_bytes());
    mac.update(namespace.store_id.as_bytes());
    Ok(Zeroizing::new(mac.finalize().into_bytes().into()))
}

fn encryption_aad(
    namespace: DurableVaultNamespaceV2,
    sequence: u64,
    previous_state_digest: Digest32V2,
    nonce: &[u8; NONCE_BYTES],
) -> Vec<u8> {
    let mut aad = Vec::from(ENCRYPTION_DOMAIN);
    aad.extend_from_slice(namespace.installation_id.as_bytes());
    aad.extend_from_slice(namespace.store_id.as_bytes());
    aad.extend_from_slice(&sequence.to_be_bytes());
    aad.extend_from_slice(previous_state_digest.as_bytes());
    aad.extend_from_slice(nonce);
    aad
}

fn state_head_digest(namespace: DurableVaultNamespaceV2, bytes: &[u8]) -> Digest32V2 {
    let mut hasher = Sha256::new();
    hasher.update(HEAD_DOMAIN);
    hasher.update(namespace.installation_id.as_bytes());
    hasher.update(namespace.store_id.as_bytes());
    hasher.update(bytes);
    Digest32V2::new(hasher.finalize().into())
}

struct AnchoredPathV2 {
    parent: File,
    parent_path: PathBuf,
    parent_dev: u64,
    parent_ino: u64,
    leaf: OsString,
    owner_uid: u32,
    owner_gid: u32,
}

impl AnchoredPathV2 {
    fn open(path: &Path) -> Result<Self, VaultErrorV2> {
        if !path.is_absolute() {
            return Err(VaultErrorV2::DurableState);
        }
        let parent_path = path.parent().ok_or(VaultErrorV2::DurableState)?;
        let leaf = path
            .file_name()
            .ok_or(VaultErrorV2::DurableState)?
            .to_os_string();
        let before = fs::symlink_metadata(parent_path).map_err(|_| VaultErrorV2::DurableState)?;
        if before.file_type().is_symlink() {
            return Err(VaultErrorV2::DurableState);
        }
        let descriptor = rustix_open(
            parent_path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| VaultErrorV2::DurableState)?;
        let parent = File::from(descriptor);
        let opened = parent.metadata().map_err(|_| VaultErrorV2::DurableState)?;
        if !opened.is_dir()
            || opened.dev() != before.dev()
            || opened.ino() != before.ino()
            || opened.uid() != before.uid()
            || opened.gid() != before.gid()
            || opened.mode() & 0o7777 != 0o700
        {
            return Err(VaultErrorV2::DurableState);
        }
        let anchored = Self {
            parent,
            parent_path: parent_path.to_owned(),
            parent_dev: opened.dev(),
            parent_ino: opened.ino(),
            leaf,
            owner_uid: opened.uid(),
            owner_gid: opened.gid(),
        };
        anchored.recheck_parent()?;
        Ok(anchored)
    }

    fn recheck_parent(&self) -> Result<(), VaultErrorV2> {
        let opened = self
            .parent
            .metadata()
            .map_err(|_| VaultErrorV2::DurableState)?;
        let linked =
            fs::symlink_metadata(&self.parent_path).map_err(|_| VaultErrorV2::DurableState)?;
        if linked.file_type().is_symlink()
            || !linked.is_dir()
            || opened.dev() != self.parent_dev
            || opened.ino() != self.parent_ino
            || linked.dev() != self.parent_dev
            || linked.ino() != self.parent_ino
            || linked.uid() != self.owner_uid
            || linked.gid() != self.owner_gid
            || linked.mode() & 0o7777 != 0o700
        {
            return Err(VaultErrorV2::DurableState);
        }
        Ok(())
    }

    fn read_existing(&self) -> Result<Option<Vec<u8>>, VaultErrorV2> {
        let before = match statat(&self.parent, &self.leaf, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => stat,
            Err(Errno::NOENT) => return Ok(None),
            Err(_) => return Err(VaultErrorV2::DurableState),
        };
        if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile {
            return Err(VaultErrorV2::DurableState);
        }
        let descriptor = openat(
            &self.parent,
            &self.leaf,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| VaultErrorV2::DurableState)?;
        let mut file = File::from(descriptor);
        let opened = file.metadata().map_err(|_| VaultErrorV2::DurableState)?;
        if !opened.is_file()
            || i128::from(before.st_dev) != i128::from(opened.dev())
            || before.st_ino != opened.ino()
            || before.st_uid != self.owner_uid
            || before.st_gid != self.owner_gid
            || opened.uid() != self.owner_uid
            || opened.gid() != self.owner_gid
            || opened.mode() & 0o7777 != 0o600
            || opened.nlink() != 1
            || opened.len() > MAX_STATE_BYTES
        {
            return Err(VaultErrorV2::DurableState);
        }
        let capacity = usize::try_from(opened.len()).map_err(|_| VaultErrorV2::DurableState)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(capacity)
            .map_err(|_| VaultErrorV2::AllocationFailure)?;
        file.read_to_end(&mut bytes)
            .map_err(|_| VaultErrorV2::DurableState)?;
        let after = statat(&self.parent, &self.leaf, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| VaultErrorV2::DurableState)?;
        if bytes.len() != capacity
            || i128::from(after.st_dev) != i128::from(opened.dev())
            || after.st_ino != opened.ino()
            || u64::try_from(after.st_size).ok() != Some(opened.len())
        {
            return Err(VaultErrorV2::DurableState);
        }
        self.recheck_parent()?;
        Ok(Some(bytes))
    }

    fn replace(&self, bytes: &[u8]) -> Result<(), bool> {
        let (temporary_leaf, mut temporary) =
            create_temporary(&self.parent, &self.leaf, self.owner_uid, self.owner_gid)
                .map_err(|_| false)?;
        let before_rename = (|| {
            temporary
                .write_all(bytes)
                .map_err(|_| VaultErrorV2::DurableState)?;
            temporary
                .sync_all()
                .map_err(|_| VaultErrorV2::DurableState)?;
            validate_file_at(
                &self.parent,
                &temporary_leaf,
                &temporary,
                self.owner_uid,
                self.owner_gid,
                u64::try_from(bytes.len()).map_err(|_| VaultErrorV2::DurableState)?,
            )?;
            self.recheck_parent()
        })();
        if before_rename.is_err() {
            let _ = unlinkat(&self.parent, &temporary_leaf, AtFlags::empty());
            return Err(false);
        }
        if renameat(&self.parent, &temporary_leaf, &self.parent, &self.leaf).is_err() {
            let _ = unlinkat(&self.parent, &temporary_leaf, AtFlags::empty());
            return Err(false);
        }
        validate_file_at(
            &self.parent,
            &self.leaf,
            &temporary,
            self.owner_uid,
            self.owner_gid,
            u64::try_from(bytes.len()).map_err(|_| true)?,
        )
        .map_err(|_| true)?;
        self.parent.sync_all().map_err(|_| true)?;
        self.recheck_parent().map_err(|_| true)
    }
}

fn create_temporary(
    parent: &File,
    final_leaf: &OsStr,
    owner_uid: u32,
    owner_gid: u32,
) -> Result<(OsString, File), VaultErrorV2> {
    for _ in 0..TEMP_ATTEMPTS {
        let mut random = [0_u8; 16];
        getrandom::getrandom(&mut random).map_err(|_| VaultErrorV2::DurableState)?;
        let mut temporary_leaf = OsString::from(".");
        temporary_leaf.push(final_leaf);
        temporary_leaf.push(".tmp-");
        temporary_leaf.push(hex(&random));
        match openat(
            parent,
            &temporary_leaf,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_bits_truncate(0o600),
        ) {
            Ok(descriptor) => {
                let file = File::from(descriptor);
                fchmod(&file, Mode::from_bits_truncate(0o600))
                    .map_err(|_| VaultErrorV2::DurableState)?;
                validate_file_at(parent, &temporary_leaf, &file, owner_uid, owner_gid, 0)?;
                return Ok((temporary_leaf, file));
            }
            Err(Errno::EXIST) => {}
            Err(_) => return Err(VaultErrorV2::DurableState),
        }
    }
    Err(VaultErrorV2::DurableState)
}

fn validate_file_at(
    parent: &File,
    leaf: &OsStr,
    file: &File,
    owner_uid: u32,
    owner_gid: u32,
    expected_length: u64,
) -> Result<(), VaultErrorV2> {
    let opened = file.metadata().map_err(|_| VaultErrorV2::DurableState)?;
    let linked =
        statat(parent, leaf, AtFlags::SYMLINK_NOFOLLOW).map_err(|_| VaultErrorV2::DurableState)?;
    if !opened.is_file()
        || opened.uid() != owner_uid
        || opened.gid() != owner_gid
        || opened.mode() & 0o7777 != 0o600
        || opened.nlink() != 1
        || opened.len() != expected_length
        || FileType::from_raw_mode(linked.st_mode) != FileType::RegularFile
        || i128::from(linked.st_dev) != i128::from(opened.dev())
        || linked.st_ino != opened.ino()
        || linked.st_uid != owner_uid
        || linked.st_gid != owner_gid
        || linked.st_mode & 0o7777 != 0o600
        || linked.st_nlink != 1
        || u64::try_from(linked.st_size).ok() != Some(expected_length)
    {
        return Err(VaultErrorV2::DurableState);
    }
    Ok(())
}

struct StateLockV2 {
    file: Flock<File>,
    parent: File,
    leaf: OsString,
    owner_uid: u32,
    owner_gid: u32,
}

impl StateLockV2 {
    fn acquire(
        parent: &File,
        leaf: &OsStr,
        owner_uid: u32,
        owner_gid: u32,
    ) -> Result<Self, VaultErrorV2> {
        let descriptor = openat(
            parent,
            leaf,
            OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::from_bits_truncate(0o600),
        )
        .map_err(|_| VaultErrorV2::DurableState)?;
        let file = File::from(descriptor);
        fchmod(&file, Mode::from_bits_truncate(0o600)).map_err(|_| VaultErrorV2::DurableState)?;
        validate_file_at(parent, leaf, &file, owner_uid, owner_gid, 0)?;
        let file = Flock::lock(file, FlockArg::LockExclusiveNonblock)
            .map_err(|_| VaultErrorV2::DurableState)?;
        validate_file_at(parent, leaf, &file, owner_uid, owner_gid, 0)?;
        parent.sync_all().map_err(|_| VaultErrorV2::DurableState)?;
        Ok(Self {
            file,
            parent: parent.try_clone().map_err(|_| VaultErrorV2::DurableState)?,
            leaf: leaf.to_os_string(),
            owner_uid,
            owner_gid,
        })
    }

    fn recheck(&self) -> Result<(), VaultErrorV2> {
        validate_file_at(
            &self.parent,
            &self.leaf,
            &self.file,
            self.owner_uid,
            self.owner_gid,
            0,
        )
    }
}

fn require_array(decoder: &mut minicbor::Decoder<'_>, expected: u64) -> Result<(), VaultErrorV2> {
    if decoder.array().map_err(|_| VaultErrorV2::DurableState)? != Some(expected) {
        return Err(VaultErrorV2::DurableState);
    }
    Ok(())
}

fn decode_count(
    decoder: &mut minicbor::Decoder<'_>,
    maximum: usize,
) -> Result<usize, VaultErrorV2> {
    let count = decoder
        .array()
        .map_err(|_| VaultErrorV2::DurableState)?
        .ok_or(VaultErrorV2::DurableState)?;
    let count = usize::try_from(count).map_err(|_| VaultErrorV2::DurableState)?;
    if count > maximum {
        return Err(VaultErrorV2::DurableState);
    }
    Ok(count)
}

fn decode_fixed<const N: usize>(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<[u8; N], VaultErrorV2> {
    decoder
        .bytes()
        .map_err(|_| VaultErrorV2::DurableState)?
        .try_into()
        .map_err(|_| VaultErrorV2::DurableState)
}

fn decode_optional_fixed<const N: usize>(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<Option<[u8; N]>, VaultErrorV2> {
    if decoder.datatype().map_err(|_| VaultErrorV2::DurableState)? == minicbor::data::Type::Null {
        decoder.null().map_err(|_| VaultErrorV2::DurableState)?;
        Ok(None)
    } else {
        Ok(Some(decode_fixed::<N>(decoder)?))
    }
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}
