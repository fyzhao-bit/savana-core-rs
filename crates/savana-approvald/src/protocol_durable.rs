use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use aes_gcm::aead::{Aead as _, Payload};
use aes_gcm::{Aes256Gcm, KeyInit as _, Nonce};
use hmac::{Hmac, Mac as _};
use savana_kernel_protocol::v2::{
    ApprovalDecisionV2, ApprovalPurposeV2, ApprovalSettlementViewV2,
    ClosedCredentialRevocationReasonV2, CreateEnrollmentCodeResponseV2, CredentialPublicStateV2,
    Digest32V2, EndpointRoleV2, EnrollmentHandleV2, PrincipalIdV2, ServiceIdentityV2,
    SignedAgentAuthenticationAttemptClosureProofV2, SignedAgentAuthenticationClosureDescriptorV2,
    SignedApprovalEnvelopeV2 as ProtocolSignedApprovalEnvelopeV2,
    SignedApprovalSettlementV2 as ProtocolSignedApprovalSettlementV2,
    SignedUiAuthenticationEnvelopeV2 as ProtocolSignedUiAuthenticationEnvelopeV2,
    SignedUiAuthenticationSettlementV2 as ProtocolSignedUiAuthenticationSettlementV2, UnixMillisV2,
    ZeroizingTextV2,
};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use crate::durable::{AnchoredPathV2, StateLockV2};
use crate::{
    ApprovalChallengeProjectionV2, ApprovalErrorV2, ApprovalRollbackAnchorV2, ApprovalStateHeadV2,
    ConsumedEnrollmentCodeV2, DurableApprovalNamespaceV2, ProtocolApprovalServiceV2,
    UiAuthenticationChallengeProjectionV2, WebAuthnAssertionV2,
};

const STATE_FILE_NAME: &str = "approval-protocol-state-v2.cbor";
const LOCK_FILE_NAME: &str = ".approval-protocol-state-v2.cbor.lock";
const ENCRYPTION_DOMAIN: &[u8] = b"SAVANA_PROTOCOL_APPROVAL_STATE_ENCRYPTION_V2\0";
const KEY_DERIVATION_DOMAIN: &[u8] = b"SAVANA_PROTOCOL_APPROVAL_STATE_KEY_DERIVATION_V2\0";
const HEAD_DOMAIN: &[u8] = b"SAVANA_PROTOCOL_APPROVAL_STATE_HEAD_V2\0";
const STATE_DIGEST_DOMAIN: &[u8] = b"SAVANA_PROTOCOL_APPROVAL_MUTABLE_STATE_V2\0";
const NONCE_BYTES: usize = 12;
const MAX_STATE_BYTES: usize = 64 * 1024 * 1024;

/// Rollback-protected encrypted owner state for protocol-native approval
/// envelopes, WebAuthn counters, and settlements.
pub struct DurableProtocolApprovalServiceV2 {
    path: PathBuf,
    anchored_path: AnchoredPathV2,
    namespace: DurableApprovalNamespaceV2,
    encryption_key: Zeroizing<[u8; 32]>,
    sequence: u64,
    current_head: ApprovalStateHeadV2,
    rollback_anchor: Box<dyn ApprovalRollbackAnchorV2>,
    service: ProtocolApprovalServiceV2,
    poisoned: bool,
    lock: StateLockV2,
}

impl std::fmt::Debug for DurableProtocolApprovalServiceV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DurableProtocolApprovalServiceV2")
            .field("path", &self.path)
            .field("sequence", &self.sequence)
            .field("poisoned", &self.poisoned)
            .finish_non_exhaustive()
    }
}

impl DurableProtocolApprovalServiceV2 {
    pub fn open(
        path: &Path,
        master_encryption_key: [u8; 32],
        namespace: DurableApprovalNamespaceV2,
        mut rollback_anchor: Box<dyn ApprovalRollbackAnchorV2>,
        deployment: ProtocolApprovalServiceV2,
    ) -> Result<Self, ApprovalErrorV2> {
        if path.file_name().and_then(|name| name.to_str()) != Some(STATE_FILE_NAME)
            || master_encryption_key == [0; 32]
            || deployment.installation_id() != namespace.installation_id()
            || !deployment.is_pristine()
        {
            return Err(ApprovalErrorV2::DurableState);
        }
        let anchored_path = AnchoredPathV2::open(path)?;
        let lock = StateLockV2::acquire(
            &anchored_path.parent,
            OsStr::new(LOCK_FILE_NAME),
            anchored_path.owner_uid,
            anchored_path.owner_gid,
        )?;
        let encryption_key = derive_encryption_key(&master_encryption_key, namespace)?;
        let anchored_head = rollback_anchor.current_head()?;
        let (sequence, service, current_head) = match anchored_path.read_existing()? {
            Some(bytes) => {
                let (sequence, previous_state_digest, mutable_state) =
                    decrypt_snapshot(&bytes, &encryption_key, namespace)?;
                let snapshot_head =
                    ApprovalStateHeadV2::new(sequence, state_head_digest(namespace, &bytes))?;
                if snapshot_head == anchored_head {
                    if sequence > 1 && previous_state_digest.as_bytes() == &[0; 32] {
                        return Err(ApprovalErrorV2::RollbackDetected);
                    }
                } else if sequence
                    == anchored_head
                        .sequence()
                        .checked_add(1)
                        .ok_or(ApprovalErrorV2::RollbackDetected)?
                    && previous_state_digest == anchored_head.state_digest()
                {
                    rollback_anchor.compare_and_advance(anchored_head, snapshot_head)?;
                } else {
                    return Err(ApprovalErrorV2::RollbackDetected);
                }
                let service =
                    ProtocolApprovalServiceV2::restore_mutable_state(deployment, &mutable_state)?;
                (sequence, service, snapshot_head)
            }
            None => {
                if anchored_head != ApprovalStateHeadV2::default() {
                    return Err(ApprovalErrorV2::RollbackDetected);
                }
                (0, deployment, ApprovalStateHeadV2::default())
            }
        };
        Ok(Self {
            path: path.to_owned(),
            anchored_path,
            namespace,
            encryption_key,
            sequence,
            current_head,
            rollback_anchor,
            service,
            poisoned: false,
            lock,
        })
    }

    pub fn load_verified_hardware_credential(
        &mut self,
        credential_digest: Digest32V2,
        principal: PrincipalIdV2,
        aaguid: [u8; 16],
        p256_sec1_public_key: [u8; 65],
        signature_counter: u32,
    ) -> Result<(), ApprovalErrorV2> {
        self.mutate(|service| {
            service.load_verified_hardware_credential(
                credential_digest,
                principal,
                aaguid,
                p256_sec1_public_key,
                signature_counter,
            )
        })
    }

    pub fn create_enrollment_code(
        &mut self,
        profile: savana_kernel_protocol::v2::EnrollmentProfileIdV2,
        client_request_nonce: savana_kernel_protocol::v2::Nonce32V2,
        now: UnixMillisV2,
    ) -> Result<CreateEnrollmentCodeResponseV2, ApprovalErrorV2> {
        self.mutate(|service| service.create_enrollment_code(profile, client_request_nonce, now))
    }

    pub fn consume_enrollment_code(
        &mut self,
        handle: EnrollmentHandleV2,
        code: &ZeroizingTextV2,
        now: UnixMillisV2,
    ) -> Result<ConsumedEnrollmentCodeV2, ApprovalErrorV2> {
        self.mutate(|service| service.consume_enrollment_code(handle, code, now))
    }

    pub fn register_enrolled_hardware_credential(
        &mut self,
        enrollment: EnrollmentHandleV2,
        credential_digest: Digest32V2,
        aaguid: [u8; 16],
        p256_sec1_public_key: [u8; 65],
        signature_counter: u32,
    ) -> Result<CredentialPublicStateV2, ApprovalErrorV2> {
        self.mutate(|service| {
            service.register_enrolled_hardware_credential(
                enrollment,
                credential_digest,
                aaguid,
                p256_sec1_public_key,
                signature_counter,
            )
        })
    }

    pub fn revoke_credential(
        &mut self,
        credential_digest: Digest32V2,
        reason: ClosedCredentialRevocationReasonV2,
    ) -> Result<CredentialPublicStateV2, ApprovalErrorV2> {
        self.mutate(|service| service.revoke_credential(credential_digest, reason))
    }

    pub fn register_approval_envelope(
        &mut self,
        envelope: &ProtocolSignedApprovalEnvelopeV2,
        now: UnixMillisV2,
    ) -> Result<Digest32V2, ApprovalErrorV2> {
        self.mutate(|service| service.register_approval_envelope(envelope, now))
    }

    pub fn register_approval_pair(
        &mut self,
        role: EndpointRoleV2,
        envelope: &ProtocolSignedApprovalEnvelopeV2,
        display_authentication: &ProtocolSignedUiAuthenticationEnvelopeV2,
        now: UnixMillisV2,
    ) -> Result<(Digest32V2, Digest32V2, ApprovalPurposeV2), ApprovalErrorV2> {
        self.mutate(|service| {
            service.register_approval_pair(role, envelope, display_authentication, now)
        })
    }

    pub fn settle_approval(
        &mut self,
        envelope_digest: Digest32V2,
        decision: ApprovalDecisionV2,
        assertion: &WebAuthnAssertionV2,
        now: UnixMillisV2,
    ) -> Result<ProtocolSignedApprovalSettlementV2, ApprovalErrorV2> {
        self.mutate(|service| service.settle_approval(envelope_digest, decision, assertion, now))
    }

    pub fn approval_challenge(
        &self,
        envelope_digest: Digest32V2,
        now: UnixMillisV2,
    ) -> Result<ApprovalChallengeProjectionV2, ApprovalErrorV2> {
        if self.poisoned {
            return Err(ApprovalErrorV2::CommitUncertain);
        }
        self.service.approval_challenge(envelope_digest, now)
    }

    pub fn approval_settlement_view(
        &self,
        envelope_digest: Digest32V2,
        now: UnixMillisV2,
    ) -> Result<ApprovalSettlementViewV2, ApprovalErrorV2> {
        if self.poisoned {
            return Err(ApprovalErrorV2::CommitUncertain);
        }
        self.service.approval_settlement_view(envelope_digest, now)
    }

    pub fn register_ui_authentication_envelope(
        &mut self,
        envelope: &ProtocolSignedUiAuthenticationEnvelopeV2,
        now: UnixMillisV2,
    ) -> Result<Digest32V2, ApprovalErrorV2> {
        self.mutate(|service| service.register_ui_authentication_envelope(envelope, now))
    }

    pub fn settle_ui_authentication(
        &mut self,
        envelope_digest: Digest32V2,
        assertion: &WebAuthnAssertionV2,
        now: UnixMillisV2,
    ) -> Result<ProtocolSignedUiAuthenticationSettlementV2, ApprovalErrorV2> {
        self.mutate(|service| service.settle_ui_authentication(envelope_digest, assertion, now))
    }

    pub fn ui_authentication_challenge(
        &self,
        envelope_digest: Digest32V2,
        now: UnixMillisV2,
    ) -> Result<UiAuthenticationChallengeProjectionV2, ApprovalErrorV2> {
        if self.poisoned {
            return Err(ApprovalErrorV2::CommitUncertain);
        }
        self.service
            .ui_authentication_challenge(envelope_digest, now)
    }

    pub fn close_agent_authentication_attempt(
        &mut self,
        descriptor: &SignedAgentAuthenticationClosureDescriptorV2,
        caller_identity: ServiceIdentityV2,
        now: UnixMillisV2,
    ) -> Result<SignedAgentAuthenticationAttemptClosureProofV2, ApprovalErrorV2> {
        self.mutate(|service| {
            service.close_agent_authentication_attempt(descriptor, caller_identity, now)
        })
    }

    pub const fn current_head(&self) -> ApprovalStateHeadV2 {
        self.current_head
    }

    fn mutate<T>(
        &mut self,
        operation: impl FnOnce(&mut ProtocolApprovalServiceV2) -> Result<T, ApprovalErrorV2>,
    ) -> Result<T, ApprovalErrorV2> {
        if self.poisoned {
            return Err(ApprovalErrorV2::CommitUncertain);
        }
        let before = mutable_state_digest(&self.service)?;
        let mut next = self.service.clone();
        let result = operation(&mut next)?;
        if mutable_state_digest(&next)? != before {
            self.commit(next)?;
        }
        Ok(result)
    }

    fn commit(&mut self, next: ProtocolApprovalServiceV2) -> Result<(), ApprovalErrorV2> {
        let sequence = self
            .sequence
            .checked_add(1)
            .ok_or(ApprovalErrorV2::DurableState)?;
        let previous_state_digest = self.current_head.state_digest();
        let mutable_state = next.encode_mutable_state()?;
        let bytes = encrypt_snapshot(
            sequence,
            previous_state_digest,
            &mutable_state,
            &self.encryption_key,
            self.namespace,
        )?;
        let next_head =
            ApprovalStateHeadV2::new(sequence, state_head_digest(self.namespace, &bytes))?;
        self.lock.recheck()?;
        match self.anchored_path.replace(&bytes) {
            Ok(()) => {
                if self
                    .rollback_anchor
                    .compare_and_advance(self.current_head, next_head)
                    .is_err()
                {
                    self.poisoned = true;
                    return Err(ApprovalErrorV2::CommitUncertain);
                }
                self.service = next;
                self.sequence = sequence;
                self.current_head = next_head;
                Ok(())
            }
            Err(after_rename) => {
                if after_rename {
                    self.poisoned = true;
                    Err(ApprovalErrorV2::CommitUncertain)
                } else {
                    Err(ApprovalErrorV2::DurableState)
                }
            }
        }
    }
}

fn mutable_state_digest(
    service: &ProtocolApprovalServiceV2,
) -> Result<Digest32V2, ApprovalErrorV2> {
    let mut hasher = Sha256::new();
    hasher.update(STATE_DIGEST_DOMAIN);
    hasher.update(service.encode_mutable_state()?);
    Ok(Digest32V2::new(hasher.finalize().into()))
}

fn derive_encryption_key(
    master: &[u8; 32],
    namespace: DurableApprovalNamespaceV2,
) -> Result<Zeroizing<[u8; 32]>, ApprovalErrorV2> {
    let mut mac = <Hmac<Sha256> as hmac::Mac>::new_from_slice(master)
        .map_err(|_| ApprovalErrorV2::DurableState)?;
    mac.update(KEY_DERIVATION_DOMAIN);
    mac.update(namespace.installation_id().as_bytes());
    mac.update(namespace.store_id().as_bytes());
    Ok(Zeroizing::new(mac.finalize().into_bytes().into()))
}

fn encrypt_snapshot(
    sequence: u64,
    previous_state_digest: Digest32V2,
    mutable_state: &[u8],
    key: &[u8; 32],
    namespace: DurableApprovalNamespaceV2,
) -> Result<Vec<u8>, ApprovalErrorV2> {
    let mut nonce = [0_u8; NONCE_BYTES];
    getrandom::getrandom(&mut nonce).map_err(|_| ApprovalErrorV2::DurableState)?;
    if nonce == [0; NONCE_BYTES] {
        return Err(ApprovalErrorV2::DurableState);
    }
    let aad = encryption_aad(namespace, sequence, previous_state_digest, &nonce);
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|_| ApprovalErrorV2::DurableAuthentication)?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: mutable_state,
                aad: &aad,
            },
        )
        .map_err(|_| ApprovalErrorV2::DurableAuthentication)?;
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(5)
        .and_then(|encoder| encoder.u16(2))
        .and_then(|encoder| encoder.u64(sequence))
        .and_then(|encoder| encoder.bytes(previous_state_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(&nonce))
        .and_then(|encoder| encoder.bytes(&ciphertext))
        .map_err(|_| ApprovalErrorV2::AllocationFailure)?;
    Ok(encoder.into_writer())
}

fn decrypt_snapshot(
    bytes: &[u8],
    key: &[u8; 32],
    namespace: DurableApprovalNamespaceV2,
) -> Result<(u64, Digest32V2, Zeroizing<Vec<u8>>), ApprovalErrorV2> {
    if bytes.is_empty() || bytes.len() > MAX_STATE_BYTES {
        return Err(ApprovalErrorV2::DurableState);
    }
    let mut decoder = minicbor::Decoder::new(bytes);
    if decoder.array().map_err(|_| ApprovalErrorV2::DurableState)? != Some(5)
        || decoder.u16().map_err(|_| ApprovalErrorV2::DurableState)? != 2
    {
        return Err(ApprovalErrorV2::DurableState);
    }
    let sequence = decoder.u64().map_err(|_| ApprovalErrorV2::DurableState)?;
    if sequence == 0 {
        return Err(ApprovalErrorV2::DurableState);
    }
    let previous_state_digest = Digest32V2::new(decode_fixed::<32>(&mut decoder)?);
    let nonce = decode_fixed::<NONCE_BYTES>(&mut decoder)?;
    let ciphertext = decoder.bytes().map_err(|_| ApprovalErrorV2::DurableState)?;
    if ciphertext.is_empty() || ciphertext.len() > MAX_STATE_BYTES {
        return Err(ApprovalErrorV2::DurableState);
    }
    if decoder.position() != bytes.len() {
        return Err(ApprovalErrorV2::DurableState);
    }
    let aad = encryption_aad(namespace, sequence, previous_state_digest, &nonce);
    let cipher =
        Aes256Gcm::new_from_slice(key).map_err(|_| ApprovalErrorV2::DurableAuthentication)?;
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| ApprovalErrorV2::DurableAuthentication)?;
    if plaintext.is_empty() || plaintext.len() > MAX_STATE_BYTES {
        return Err(ApprovalErrorV2::DurableState);
    }
    Ok((sequence, previous_state_digest, Zeroizing::new(plaintext)))
}

fn encryption_aad(
    namespace: DurableApprovalNamespaceV2,
    sequence: u64,
    previous_state_digest: Digest32V2,
    nonce: &[u8; NONCE_BYTES],
) -> Vec<u8> {
    let mut aad = Vec::from(ENCRYPTION_DOMAIN);
    aad.extend_from_slice(namespace.installation_id().as_bytes());
    aad.extend_from_slice(namespace.store_id().as_bytes());
    aad.extend_from_slice(&sequence.to_be_bytes());
    aad.extend_from_slice(previous_state_digest.as_bytes());
    aad.extend_from_slice(nonce);
    aad
}

fn state_head_digest(namespace: DurableApprovalNamespaceV2, bytes: &[u8]) -> Digest32V2 {
    let mut hasher = Sha256::new();
    hasher.update(HEAD_DOMAIN);
    hasher.update(namespace.installation_id().as_bytes());
    hasher.update(namespace.store_id().as_bytes());
    hasher.update(bytes);
    Digest32V2::new(hasher.finalize().into())
}

fn decode_fixed<const N: usize>(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<[u8; N], ApprovalErrorV2> {
    decoder
        .bytes()
        .map_err(|_| ApprovalErrorV2::DurableState)?
        .try_into()
        .map_err(|_| ApprovalErrorV2::DurableState)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;
    use std::sync::{Arc, Mutex};

    use ed25519_dalek::SigningKey;
    use p256::ecdsa::SigningKey as P256SigningKey;
    use savana_kernel_protocol::v2::{
        derive_ed25519_key_id_v2, Digest32V2, PrincipalIdV2, ServiceIdentityV2,
    };

    use super::DurableProtocolApprovalServiceV2;
    use crate::{
        ApprovalErrorV2, ApprovalRollbackAnchorV2, ApprovalStateHeadV2, DurableApprovalNamespaceV2,
        ProtocolApprovalServiceV2,
    };

    #[derive(Clone, Default)]
    struct TestAnchor(Arc<Mutex<ApprovalStateHeadV2>>);

    impl ApprovalRollbackAnchorV2 for TestAnchor {
        fn current_head(&self) -> Result<ApprovalStateHeadV2, ApprovalErrorV2> {
            self.0
                .lock()
                .map(|head| *head)
                .map_err(|_| ApprovalErrorV2::DurableState)
        }

        fn compare_and_advance(
            &mut self,
            expected: ApprovalStateHeadV2,
            next: ApprovalStateHeadV2,
        ) -> Result<(), ApprovalErrorV2> {
            let mut head = self.0.lock().map_err(|_| ApprovalErrorV2::DurableState)?;
            if *head != expected || next.sequence() != expected.sequence() + 1 {
                return Err(ApprovalErrorV2::RollbackDetected);
            }
            *head = next;
            Ok(())
        }
    }

    fn deployment() -> ProtocolApprovalServiceV2 {
        let kernel = SigningKey::from_bytes(&[0x41; 32]);
        let settlement = SigningKey::from_bytes(&[0x42; 32]);
        let correlation = SigningKey::from_bytes(&[0x46; 32]);
        ProtocolApprovalServiceV2::from_verified_deployment(
            Digest32V2::new([0x43; 32]),
            Digest32V2::new([0x44; 32]),
            5,
            savana_kernel_protocol::v2::BootIdV2::new([0x47; 32]),
            3,
            ServiceIdentityV2::new([0x45; 32]),
            derive_ed25519_key_id_v2(kernel.verifying_key().to_bytes()),
            kernel.verifying_key().to_bytes(),
            derive_ed25519_key_id_v2(correlation.verifying_key().to_bytes()),
            correlation.verifying_key().to_bytes(),
            derive_ed25519_key_id_v2(settlement.verifying_key().to_bytes()),
            settlement.to_bytes(),
            32,
        )
        .unwrap()
    }

    #[test]
    fn protocol_state_recovers_counters_and_rejects_anchor_rollback() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.path().join("approval-protocol-state-v2.cbor");
        let namespace = DurableApprovalNamespaceV2::from_verified_installation(
            Digest32V2::new([0x43; 32]),
            Digest32V2::new([0x46; 32]),
        )
        .unwrap();
        let anchor = TestAnchor::default();
        let credential_key = P256SigningKey::from_slice(&[0x47; 32]).unwrap();
        let credential_public = credential_key.verifying_key().to_encoded_point(false);
        {
            let mut durable = DurableProtocolApprovalServiceV2::open(
                &path,
                [0x48; 32],
                namespace,
                Box::new(anchor.clone()),
                deployment(),
            )
            .unwrap();
            durable
                .load_verified_hardware_credential(
                    Digest32V2::new([0x49; 32]),
                    PrincipalIdV2::new([0x4a; 32]),
                    [0x4b; 16],
                    credential_public.as_bytes().try_into().unwrap(),
                    7,
                )
                .unwrap();
            assert_eq!(durable.current_head().sequence(), 1);
        }
        {
            let mut recovered = DurableProtocolApprovalServiceV2::open(
                &path,
                [0x48; 32],
                namespace,
                Box::new(anchor),
                deployment(),
            )
            .unwrap();
            assert_eq!(
                recovered
                    .load_verified_hardware_credential(
                        Digest32V2::new([0x49; 32]),
                        PrincipalIdV2::new([0x4a; 32]),
                        [0x4b; 16],
                        credential_public.as_bytes().try_into().unwrap(),
                        7,
                    )
                    .unwrap_err(),
                ApprovalErrorV2::InvalidCredential
            );
        }
        let ahead_anchor = TestAnchor(Arc::new(Mutex::new(
            ApprovalStateHeadV2::new(2, Digest32V2::new([0x4c; 32])).unwrap(),
        )));
        assert_eq!(
            DurableProtocolApprovalServiceV2::open(
                &path,
                [0x48; 32],
                namespace,
                Box::new(ahead_anchor),
                deployment(),
            )
            .unwrap_err(),
            ApprovalErrorV2::RollbackDetected
        );
    }

    #[test]
    fn task_root_approval_pair_is_atomic_encrypted_and_restart_recoverable() {
        use savana_kernel_protocol::v2::*;
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.path().join("approval-protocol-state-v2.cbor");
        let namespace = DurableApprovalNamespaceV2::from_verified_installation(
            Digest32V2::new([0x43; 32]),
            Digest32V2::new([0x46; 32]),
        )
        .unwrap();
        let anchor = TestAnchor::default();
        let key = SigningKey::from_bytes(&[0x41; 32]);
        let principal = PrincipalIdV2::new([0x51; 32]);
        let task = DurableTaskIdV2::new([0x52; 32]);
        let text = BoundedApprovalDisplayTextV2::new(
            "task-root secret readable controls: A -> Alice".into(),
        )
        .unwrap();
        let display_digest = approval_display_digest_v2(text.as_bytes());
        let approval = SignedApprovalEnvelopeV2::sign(
            UnsignedApprovalEnvelopeV2::new(
                Digest32V2::new([0x43; 32]),
                Digest32V2::new([0x44; 32]),
                5,
                ApprovalPurposeV2::TaskAuthorization,
                Nonce32V2::new([0x53; 32]),
                Nonce32V2::new([0x54; 32]),
                ApprovalBindingV2::TaskAuthorization {
                    authorization_id: Digest32V2::new([0x55; 32]),
                    task,
                    revision: 1,
                    change: TaskAuthorizationChangeV2::Create,
                    draft_digest: Digest32V2::new([0x56; 32]),
                },
                principal,
                Digest32V2::new([0x56; 32]),
                display_digest,
                text.clone(),
                Some(Digest32V2::new([0x57; 32])),
                ServiceIdentityV2::new([0x45; 32]),
                UnixMillisV2::new(100),
                UnixMillisV2::new(1000),
            )
            .unwrap(),
            &key,
        )
        .unwrap();
        let digest = approval.envelope_digest().unwrap();
        let ui = SignedUiAuthenticationEnvelopeV2::sign(
            UnsignedUiAuthenticationEnvelopeV2::new(
                Digest32V2::new([0x43; 32]),
                Digest32V2::new([0x44; 32]),
                5,
                UiAuthenticationPurposeV2::ApprovalDisplay,
                UiAuthenticationBindingV2::ApprovalDisplay {
                    durable_task_id: task,
                    approval_envelope_digest: digest,
                    approval_purpose: ApprovalPurposeV2::TaskAuthorization,
                    display_digest,
                },
                Some(principal),
                FixedOriginV2::Approval8766,
                FixedOriginV2::Approval8766,
                Nonce32V2::new([0x58; 32]),
                UnixMillisV2::new(100),
                UnixMillisV2::new(1000),
            )
            .unwrap(),
            &key,
        )
        .unwrap();
        let pair;
        {
            let mut owner = DurableProtocolApprovalServiceV2::open(
                &path,
                [0x48; 32],
                namespace,
                Box::new(anchor.clone()),
                deployment(),
            )
            .unwrap();
            let before = owner.current_head();
            assert!(owner
                .register_approval_pair(
                    EndpointRoleV2::AgentApproval,
                    &approval,
                    &ui,
                    UnixMillisV2::new(200)
                )
                .is_err());
            assert_eq!(before, owner.current_head());
            assert!(!path.exists());
            pair = owner
                .register_approval_pair(
                    EndpointRoleV2::IngressApproval,
                    &approval,
                    &ui,
                    UnixMillisV2::new(200),
                )
                .unwrap();
            assert_eq!(
                owner.current_head().sequence(),
                1,
                "pair is one owner commit"
            );
            assert_eq!(pair.0, digest);
            assert!(!fs::read(&path)
                .unwrap()
                .windows(text.as_bytes().len())
                .any(|w| w == text.as_bytes()));
        }
        let mut recovered = DurableProtocolApprovalServiceV2::open(
            &path,
            [0x48; 32],
            namespace,
            Box::new(anchor),
            deployment(),
        )
        .unwrap();
        assert_eq!(
            recovered
                .approval_challenge(digest, UnixMillisV2::new(300))
                .unwrap()
                .display_text(),
            &text
        );
        assert_eq!(
            recovered
                .approval_settlement_view(digest, UnixMillisV2::new(300))
                .unwrap(),
            ApprovalSettlementViewV2::Pending
        );
        assert_eq!(
            recovered
                .register_approval_pair(
                    EndpointRoleV2::IngressApproval,
                    &approval,
                    &ui,
                    UnixMillisV2::new(300)
                )
                .unwrap(),
            pair
        );
    }
}
