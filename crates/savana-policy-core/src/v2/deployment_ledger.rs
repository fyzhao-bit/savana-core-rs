use ed25519_dalek::{Signature, VerifyingKey};
#[cfg(any(test, feature = "test-support"))]
use ed25519_dalek::{Signer as _, SigningKey};
use savana_kernel_protocol::v2::{
    derive_ed25519_key_id_v2, Digest32V2, Ed25519KeyIdV2, Ed25519SignatureV2, Nonce32V2,
};
use savana_platform_identity::{
    NativeDeploymentSignatureDomainV2, NativeDeploymentSignatureRequestV2,
    NativeDeploymentSigningAuthorityV2,
};
use sha2::{Digest as _, Sha256};

use super::{
    DeploymentBranchV2, DeploymentControlErrorV2, DeploymentLedgerProjectionV2, DeploymentPhaseV2,
    DurableDeploymentTransactionRecordV2, LedgerSlotIdV2, RollbackGrantStateV2,
    VerifiedLedgerSlotV2,
};

const LEDGER_SCHEMA_VERSION_V2: u16 = 2;
const LEDGER_RECORD_FIELDS_V2: u64 = 21;
const LEDGER_PAYLOAD_FIELDS_V2: u64 = 19;
const LEDGER_SLOT_FIELDS_V2: u64 = 10;
const HIGHEST_EVER_DOMAIN_COUNT_V2: usize = 28;
const MAX_LEDGER_RECORD_BYTES_V2: usize = 4 * 1024 * 1024;
const MAX_LEDGER_SLOT_BYTES_V2: usize = MAX_LEDGER_RECORD_BYTES_V2 + 1024;
const LEDGER_RECORD_DIGEST_DOMAIN_V2: &[u8] = b"savana.deployment-ledger.v2.record\0";
const LEDGER_SIGNED_DIGEST_DOMAIN_V2: &[u8] = b"savana.deployment-ledger.v2.signed\0";
const LEDGER_SLOT_CHECKSUM_DOMAIN_V2: &[u8] = b"savana.ledger-slot.v2.checksum\0";
const HIGHEST_EVER_DIGEST_DOMAIN_V2: &[u8] = b"savana.highest-ever.v2\0";
const DOMAIN_SIGNATURE_INPUT_V2: &[u8] = b"savana.domain-signature.v2\0";
const LEDGER_ACTIVATION_SIGNATURE_DOMAIN_V2: &[u8] = b"savana.deployment-ledger.v2.activation\0";
const LEDGER_SLOT_SIGNATURE_DOMAIN_V2: &[u8] = b"savana.ledger-slot.v2.signature\0";
const LEDGER_ACTIVATION_SIGNATURE_TAG_V2: u16 = 5;
const LEDGER_SLOT_SIGNATURE_TAG_V2: u16 = 21;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum ClosedSecurityDomainV2 {
    BinaryRelease = 1,
    Policy = 2,
    Registry = 3,
    Ontology = 4,
    ModelSet = 5,
    ResourceProfile = 6,
    DestinationProjection = 7,
    DisplayProjection = 8,
    ValidatorSet = 9,
    GrammarSchema = 10,
    ProtocolLock = 11,
    ServiceIdentityLock = 12,
    ApprovalLock = 13,
    JarvisArtifact = 14,
    EgressPolicySet = 15,
    ExecutorConnectorRegistry = 16,
    ExecutorKeyLock = 17,
    PlannerLock = 18,
    CompletionEvidenceTrustPolicy = 19,
    ServiceUnitSet = 20,
    SocketOrXpcUnitSet = 21,
    ServiceStoreProjectionSet = 22,
    SandboxProfileSet = 23,
    EntitlementProfileSet = 24,
    CodeIntegrityLock = 25,
    DeploymentTrustRootSet = 26,
    ActivationTrustRootSet = 27,
    ReleaseTrustRootSet = 28,
}

impl ClosedSecurityDomainV2 {
    pub const ALL: [Self; HIGHEST_EVER_DOMAIN_COUNT_V2] = [
        Self::BinaryRelease,
        Self::Policy,
        Self::Registry,
        Self::Ontology,
        Self::ModelSet,
        Self::ResourceProfile,
        Self::DestinationProjection,
        Self::DisplayProjection,
        Self::ValidatorSet,
        Self::GrammarSchema,
        Self::ProtocolLock,
        Self::ServiceIdentityLock,
        Self::ApprovalLock,
        Self::JarvisArtifact,
        Self::EgressPolicySet,
        Self::ExecutorConnectorRegistry,
        Self::ExecutorKeyLock,
        Self::PlannerLock,
        Self::CompletionEvidenceTrustPolicy,
        Self::ServiceUnitSet,
        Self::SocketOrXpcUnitSet,
        Self::ServiceStoreProjectionSet,
        Self::SandboxProfileSet,
        Self::EntitlementProfileSet,
        Self::CodeIntegrityLock,
        Self::DeploymentTrustRootSet,
        Self::ActivationTrustRootSet,
        Self::ReleaseTrustRootSet,
    ];

    pub const fn tag(self) -> u16 {
        self as u16
    }

    pub const fn from_tag(tag: u16) -> Option<Self> {
        match tag {
            1 => Some(Self::BinaryRelease),
            2 => Some(Self::Policy),
            3 => Some(Self::Registry),
            4 => Some(Self::Ontology),
            5 => Some(Self::ModelSet),
            6 => Some(Self::ResourceProfile),
            7 => Some(Self::DestinationProjection),
            8 => Some(Self::DisplayProjection),
            9 => Some(Self::ValidatorSet),
            10 => Some(Self::GrammarSchema),
            11 => Some(Self::ProtocolLock),
            12 => Some(Self::ServiceIdentityLock),
            13 => Some(Self::ApprovalLock),
            14 => Some(Self::JarvisArtifact),
            15 => Some(Self::EgressPolicySet),
            16 => Some(Self::ExecutorConnectorRegistry),
            17 => Some(Self::ExecutorKeyLock),
            18 => Some(Self::PlannerLock),
            19 => Some(Self::CompletionEvidenceTrustPolicy),
            20 => Some(Self::ServiceUnitSet),
            21 => Some(Self::SocketOrXpcUnitSet),
            22 => Some(Self::ServiceStoreProjectionSet),
            23 => Some(Self::SandboxProfileSet),
            24 => Some(Self::EntitlementProfileSet),
            25 => Some(Self::CodeIntegrityLock),
            26 => Some(Self::DeploymentTrustRootSet),
            27 => Some(Self::ActivationTrustRootSet),
            28 => Some(Self::ReleaseTrustRootSet),
            _ => None,
        }
    }

    pub const fn index(self) -> usize {
        self.tag() as usize - 1
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HighWaterEntryV2 {
    sequence: u64,
    content_digest: Digest32V2,
    key_epoch: u64,
}

impl HighWaterEntryV2 {
    pub fn new(
        sequence: u64,
        content_digest: Digest32V2,
        key_epoch: u64,
    ) -> Result<Self, DeploymentControlErrorV2> {
        let value = Self {
            sequence,
            content_digest,
            key_epoch,
        };
        value.validate()?;
        Ok(value)
    }

    pub const fn sequence(self) -> u64 {
        self.sequence
    }

    pub const fn content_digest(self) -> Digest32V2 {
        self.content_digest
    }

    pub const fn key_epoch(self) -> u64 {
        self.key_epoch
    }

    fn validate(self) -> Result<(), DeploymentControlErrorV2> {
        if is_zero(self.content_digest.as_bytes()) || self.key_epoch == 0 {
            return Err(DeploymentControlErrorV2::InvalidLedgerRecord);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HighestEverV2 {
    entries: [HighWaterEntryV2; HIGHEST_EVER_DOMAIN_COUNT_V2],
}

impl HighestEverV2 {
    pub fn new(
        entries: [HighWaterEntryV2; HIGHEST_EVER_DOMAIN_COUNT_V2],
    ) -> Result<Self, DeploymentControlErrorV2> {
        let value = Self { entries };
        value.validate()?;
        Ok(value)
    }

    pub const fn entries(&self) -> &[HighWaterEntryV2; HIGHEST_EVER_DOMAIN_COUNT_V2] {
        &self.entries
    }

    pub const fn entry(&self, domain: ClosedSecurityDomainV2) -> HighWaterEntryV2 {
        self.entries[domain.index()]
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, DeploymentControlErrorV2> {
        let mut encoder = minicbor::Encoder::new(Vec::new());
        encode_highest_ever(&mut encoder, self)?;
        Ok(encoder.into_writer())
    }

    pub fn digest(&self) -> Result<Digest32V2, DeploymentControlErrorV2> {
        Ok(hash_domain(
            HIGHEST_EVER_DIGEST_DOMAIN_V2,
            &self.canonical_bytes()?,
        ))
    }

    pub fn with_advanced(
        &self,
        domain: ClosedSecurityDomainV2,
        next: HighWaterEntryV2,
    ) -> Result<Self, DeploymentControlErrorV2> {
        next.validate()?;
        let current = self.entry(domain);
        if next.sequence < current.sequence
            || (next.sequence == current.sequence && next != current)
        {
            return Err(DeploymentControlErrorV2::HighestEverMismatch);
        }
        let mut value = self.clone();
        value.entries[domain.index()] = next;
        Ok(value)
    }

    fn validate(&self) -> Result<(), DeploymentControlErrorV2> {
        for entry in self.entries {
            entry.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum RollbackOriginPhaseV2 {
    Armed = 1,
    Quiesced = 2,
    Installed = 3,
    Verified = 4,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapBridgeRestoreProvenanceV2 {
    bridge_genesis_ledger_record_signed_digest: Digest32V2,
    failed_transaction_id: Nonce32V2,
    recovery_grant_id: Digest32V2,
    restore_origin_phase: RollbackOriginPhaseV2,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapBridgeActivationV2 {
    maintenance_intent_signed_digest: Digest32V2,
    bridge_manifest_digest: Digest32V2,
    premaintenance_runtime_manifest_digest: Digest32V2,
    previous_installation_epoch: u64,
    previous_epoch_last_ledger_record_signed_digest: Digest32V2,
    previous_epoch_last_ledger_record_payload_digest: Digest32V2,
    restore_provenance: Option<BootstrapBridgeRestoreProvenanceV2>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActiveActivationV2 {
    Normal,
    ConsumedRollback {
        failed_transaction_id: Nonce32V2,
        rollback_grant_id: Digest32V2,
    },
    BootstrapBridge(Box<BootstrapBridgeActivationV2>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeploymentActivationUpdateV2 {
    Retain,
    CommitNormal {
        active_manifest_digest: Digest32V2,
    },
    ActivateRollback {
        active_manifest_digest: Digest32V2,
        rollback_grant_id: Digest32V2,
    },
    RestoreBootstrapBridge {
        bridge_genesis_ledger_record_signed_digest: Digest32V2,
        recovery_grant_id: Digest32V2,
    },
}

impl ActiveActivationV2 {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, DeploymentControlErrorV2> {
        self.validate()?;
        let mut encoder = minicbor::Encoder::new(Vec::new());
        encode_active_activation(&mut encoder, self)?;
        Ok(encoder.into_writer())
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, DeploymentControlErrorV2> {
        let mut decoder = minicbor::Decoder::new(bytes);
        let value = decode_active_activation(&mut decoder)?;
        if decoder.position() != bytes.len() || value.canonical_bytes()? != bytes {
            return Err(DeploymentControlErrorV2::NonCanonicalLedgerEncoding);
        }
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), DeploymentControlErrorV2> {
        match self {
            Self::Normal => Ok(()),
            Self::ConsumedRollback {
                failed_transaction_id,
                rollback_grant_id,
            } => require_nonzero(&[
                failed_transaction_id.as_bytes(),
                rollback_grant_id.as_bytes(),
            ]),
            Self::BootstrapBridge(value) => {
                if value.previous_installation_epoch == 0 {
                    return Err(DeploymentControlErrorV2::InvalidLedgerRecord);
                }
                require_nonzero(&[
                    value.maintenance_intent_signed_digest.as_bytes(),
                    value.bridge_manifest_digest.as_bytes(),
                    value.premaintenance_runtime_manifest_digest.as_bytes(),
                    value
                        .previous_epoch_last_ledger_record_signed_digest
                        .as_bytes(),
                    value
                        .previous_epoch_last_ledger_record_payload_digest
                        .as_bytes(),
                ])?;
                if let Some(provenance) = &value.restore_provenance {
                    require_nonzero(&[
                        provenance
                            .bridge_genesis_ledger_record_signed_digest
                            .as_bytes(),
                        provenance.failed_transaction_id.as_bytes(),
                        provenance.recovery_grant_id.as_bytes(),
                    ])?;
                }
                Ok(())
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DomainSignatureV2 {
    domain_tag: u16,
    signer_key_id: Ed25519KeyIdV2,
    signer_key_epoch: u64,
    signature: Ed25519SignatureV2,
}

#[derive(Debug, Clone)]
pub struct DeploymentActivationVerifierV2 {
    installation_id: Digest32V2,
    key_id: Ed25519KeyIdV2,
    key_epoch: u64,
    verifying_key: VerifyingKey,
}

impl DeploymentActivationVerifierV2 {
    pub fn new(
        installation_id: Digest32V2,
        key_id: Ed25519KeyIdV2,
        key_epoch: u64,
        public_key: [u8; 32],
    ) -> Result<Self, DeploymentControlErrorV2> {
        if is_zero(installation_id.as_bytes())
            || key_epoch == 0
            || is_zero(key_id.as_bytes())
            || derive_ed25519_key_id_v2(public_key) != key_id
        {
            return Err(DeploymentControlErrorV2::ActivationKeyMismatch);
        }
        let verifying_key = VerifyingKey::from_bytes(&public_key)
            .map_err(|_| DeploymentControlErrorV2::ActivationKeyMismatch)?;
        Ok(Self {
            installation_id,
            key_id,
            key_epoch,
            verifying_key,
        })
    }

    pub const fn key_id(&self) -> Ed25519KeyIdV2 {
        self.key_id
    }

    pub const fn installation_id(&self) -> Digest32V2 {
        self.installation_id
    }

    pub const fn key_epoch(&self) -> u64 {
        self.key_epoch
    }

    fn verify(
        &self,
        signature: DomainSignatureV2,
        expected_domain_tag: u16,
        expected_domain: &[u8],
        digest: Digest32V2,
    ) -> Result<(), DeploymentControlErrorV2> {
        self.verify_domain_signature_parts(
            signature.domain_tag,
            signature.signer_key_id,
            signature.signer_key_epoch,
            signature.signature,
            expected_domain_tag,
            expected_domain,
            digest,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn verify_domain_signature_parts(
        &self,
        domain_tag: u16,
        signer_key_id: Ed25519KeyIdV2,
        signer_key_epoch: u64,
        signature: Ed25519SignatureV2,
        expected_domain_tag: u16,
        expected_domain: &[u8],
        digest: Digest32V2,
    ) -> Result<(), DeploymentControlErrorV2> {
        if domain_tag != expected_domain_tag
            || signer_key_id != self.key_id
            || signer_key_epoch != self.key_epoch
        {
            return Err(DeploymentControlErrorV2::ActivationKeyMismatch);
        }
        let input = domain_signature_input(expected_domain_tag, expected_domain, digest);
        self.verifying_key
            .verify_strict(&input, &Signature::from_bytes(signature.as_bytes()))
            .map_err(|_| DeploymentControlErrorV2::InvalidActivationSignature)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeploymentLedgerRecordV2 {
    canonical_bytes: Vec<u8>,
    signed_record_digest: Digest32V2,
    projection: DeploymentLedgerProjectionV2,
    written_at_unix_ms: u64,
    active_manifest_digest: Digest32V2,
    active_activation: ActiveActivationV2,
    install_identity_profile_signed_digest: Digest32V2,
    bootstrap_tcb_lock_digest: Digest32V2,
    highest_ever: HighestEverV2,
    rollback_origin_phase: Option<RollbackOriginPhaseV2>,
}

impl DeploymentLedgerRecordV2 {
    pub fn from_canonical_bytes(
        bytes: &[u8],
        verifier: &DeploymentActivationVerifierV2,
    ) -> Result<Self, DeploymentControlErrorV2> {
        if bytes.is_empty() || bytes.len() > MAX_LEDGER_RECORD_BYTES_V2 {
            return Err(DeploymentControlErrorV2::InvalidLedgerRecord);
        }
        let decoded = decode_record(bytes)?;
        decoded.validate()?;
        if encode_complete_record(&decoded)? != bytes {
            return Err(DeploymentControlErrorV2::NonCanonicalLedgerEncoding);
        }
        if decoded.installation_id != verifier.installation_id
            || decoded.installation_epoch != verifier.key_epoch
        {
            return Err(DeploymentControlErrorV2::InstallationTupleMismatch);
        }
        if decoded.activation_key_id != verifier.key_id {
            return Err(DeploymentControlErrorV2::ActivationKeyMismatch);
        }
        let expected_payload_digest = hash_domain(
            LEDGER_RECORD_DIGEST_DOMAIN_V2,
            &encode_record_payload(&decoded)?,
        );
        if decoded.record_payload_digest != expected_payload_digest {
            return Err(DeploymentControlErrorV2::LedgerPayloadDigestMismatch);
        }
        verifier.verify(
            decoded.record_signature,
            LEDGER_ACTIVATION_SIGNATURE_TAG_V2,
            LEDGER_ACTIVATION_SIGNATURE_DOMAIN_V2,
            expected_payload_digest,
        )?;
        let projection = decoded.projection()?;
        Ok(Self {
            canonical_bytes: bytes.to_vec(),
            signed_record_digest: hash_domain(LEDGER_SIGNED_DIGEST_DOMAIN_V2, bytes),
            projection,
            written_at_unix_ms: decoded.written_at_unix_ms,
            active_manifest_digest: decoded.active_manifest_digest,
            active_activation: decoded.active_activation,
            install_identity_profile_signed_digest: decoded.install_identity_profile_signed_digest,
            bootstrap_tcb_lock_digest: decoded.bootstrap_tcb_lock_digest,
            highest_ever: decoded.highest_ever,
            rollback_origin_phase: decoded.rollback_origin_phase,
        })
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub const fn record_payload_digest(&self) -> Digest32V2 {
        self.projection.record_payload_digest()
    }

    pub const fn signed_record_digest(&self) -> Digest32V2 {
        self.signed_record_digest
    }

    pub const fn projection(&self) -> &DeploymentLedgerProjectionV2 {
        &self.projection
    }

    pub const fn highest_ever(&self) -> &HighestEverV2 {
        &self.highest_ever
    }

    pub const fn written_at_unix_ms(&self) -> u64 {
        self.written_at_unix_ms
    }

    pub const fn active_manifest_digest(&self) -> Digest32V2 {
        self.active_manifest_digest
    }

    pub const fn active_activation(&self) -> &ActiveActivationV2 {
        &self.active_activation
    }

    pub const fn install_identity_profile_signed_digest(&self) -> Digest32V2 {
        self.install_identity_profile_signed_digest
    }

    pub const fn bootstrap_tcb_lock_digest(&self) -> Digest32V2 {
        self.bootstrap_tcb_lock_digest
    }

    pub const fn rollback_origin_phase(&self) -> Option<RollbackOriginPhaseV2> {
        self.rollback_origin_phase
    }

    pub fn validate_successor(
        &self,
        successor: &Self,
        branch: DeploymentBranchV2,
    ) -> Result<(), DeploymentControlErrorV2> {
        let transition = self
            .projection
            .validate_successor(&successor.projection, branch)?;
        let current_record = decode_record(&self.canonical_bytes)?;
        let successor_record = decode_record(&successor.canonical_bytes)?;
        validate_active_state_successor(&current_record, &successor_record, transition)?;
        validate_rollback_origin_successor(&current_record, &successor_record, transition)?;
        for (current, next) in self
            .highest_ever
            .entries
            .iter()
            .zip(&successor.highest_ever.entries)
        {
            if next.sequence < current.sequence
                || (next.sequence == current.sequence
                    && (next.content_digest != current.content_digest
                        || next.key_epoch != current.key_epoch))
            {
                return Err(DeploymentControlErrorV2::HighestEverMismatch);
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_successor_signed_with_authority(
        current: &Self,
        branch: DeploymentBranchV2,
        durable_head: &DurableDeploymentTransactionRecordV2,
        activation_update: DeploymentActivationUpdateV2,
        highest_ever: HighestEverV2,
        written_at_unix_ms: u64,
        authority: &mut dyn NativeDeploymentSigningAuthorityV2,
        verifier: &DeploymentActivationVerifierV2,
    ) -> Result<Self, DeploymentControlErrorV2> {
        durable_head.validate_expected_previous_ledger(current)?;
        let current_projection = current.projection();
        let target_phase = durable_head.target_phase();
        let transition =
            super::DeploymentTransitionV2::new(branch, current_projection.phase(), target_phase)?;
        let starts_new_transaction = target_phase == DeploymentPhaseV2::Prepared
            && matches!(
                current_projection.phase(),
                DeploymentPhaseV2::Idle
                    | DeploymentPhaseV2::Committed
                    | DeploymentPhaseV2::RolledBack
                    | DeploymentPhaseV2::BootstrapBridge
            );
        if durable_head.installation_id() != current_projection.installation_id()
            || (!starts_new_transaction
                && current_projection.transaction_id() != Some(durable_head.transaction_id()))
        {
            return Err(DeploymentControlErrorV2::TransactionBindingMismatch);
        }

        let mut decoded = decode_record(current.canonical_bytes())?;
        if written_at_unix_ms < decoded.written_at_unix_ms {
            return Err(DeploymentControlErrorV2::InvalidLedgerRecord);
        }
        let signer_key_id = Ed25519KeyIdV2::new(authority.key_id());
        if authority.installation_id() != *decoded.installation_id.as_bytes()
            || authority.key_epoch() != decoded.installation_epoch
            || verifier.installation_id() != decoded.installation_id
            || verifier.key_epoch() != decoded.installation_epoch
            || verifier.key_id() != signer_key_id
        {
            return Err(DeploymentControlErrorV2::ActivationKeyMismatch);
        }

        if target_phase == DeploymentPhaseV2::Installed {
            highest_ever.validate()?;
        } else if highest_ever != decoded.highest_ever {
            return Err(DeploymentControlErrorV2::HighestEverMismatch);
        }
        decoded.highest_ever = highest_ever;
        decoded.active_activation = successor_activation(
            &decoded,
            transition,
            activation_update,
            durable_head.transaction_id(),
        )?;
        if let ActiveActivationV2::ConsumedRollback { .. } = decoded.active_activation {
            if let DeploymentActivationUpdateV2::ActivateRollback {
                active_manifest_digest,
                ..
            } = activation_update
            {
                decoded.active_manifest_digest = active_manifest_digest;
            }
        } else if let DeploymentActivationUpdateV2::CommitNormal {
            active_manifest_digest,
        } = activation_update
        {
            decoded.active_manifest_digest = active_manifest_digest;
        }

        let (effects_fenced, effect_fence_epoch) =
            successor_fence(current_projection, target_phase)?;
        decoded.schema_version = LEDGER_SCHEMA_VERSION_V2;
        decoded.generation = decoded
            .generation
            .checked_add(1)
            .ok_or(DeploymentControlErrorV2::InvalidLedgerRecord)?;
        decoded.written_at_unix_ms = written_at_unix_ms;
        decoded.phase = target_phase;
        decoded.transaction_id = Some(durable_head.transaction_id());
        decoded.effects_fenced = effects_fenced;
        decoded.effect_fence_epoch = effect_fence_epoch;
        decoded.rollback_grant_state = successor_grant_state(current_projection, target_phase)?;
        decoded.rollback_origin_phase = successor_rollback_origin(
            current_projection,
            decoded.rollback_origin_phase,
            target_phase,
        )?;
        decoded.transaction_head_digest = Some(durable_head.signed_digest());
        decoded.previous_record_digest = current.record_payload_digest();
        decoded.record_payload_digest = Digest32V2::new([1; 32]);
        decoded.activation_key_id = signer_key_id;
        decoded.record_signature = DomainSignatureV2 {
            domain_tag: LEDGER_ACTIVATION_SIGNATURE_TAG_V2,
            signer_key_id,
            signer_key_epoch: decoded.installation_epoch,
            signature: Ed25519SignatureV2::new([1; 64]),
        };
        decoded.validate_without_payload_and_signature()?;
        decoded.record_payload_digest = hash_domain(
            LEDGER_RECORD_DIGEST_DOMAIN_V2,
            &encode_record_payload(&decoded)?,
        );
        let request = NativeDeploymentSignatureRequestV2::new(
            NativeDeploymentSignatureDomainV2::LedgerActivation,
            *decoded.installation_id.as_bytes(),
            decoded.installation_epoch,
            *decoded.record_payload_digest.as_bytes(),
        )
        .map_err(|_| DeploymentControlErrorV2::NativeSigningAuthorityUnavailable)?;
        decoded.record_signature.signature = Ed25519SignatureV2::new(
            authority
                .sign(request)
                .map_err(|_| DeploymentControlErrorV2::NativeSigningAuthorityUnavailable)?,
        );
        let successor = Self::from_canonical_bytes(&encode_complete_record(&decoded)?, verifier)?;
        current.validate_successor(&successor, branch)?;
        Ok(successor)
    }

    pub(super) fn new_idle_successor_signed_with_authority(
        current: &Self,
        checkpoint: &super::EvidenceGcCheckpointV2,
        aborted_chain: &[DurableDeploymentTransactionRecordV2],
        written_at_unix_ms: u64,
        authority: &mut dyn NativeDeploymentSigningAuthorityV2,
        verifier: &DeploymentActivationVerifierV2,
    ) -> Result<Self, DeploymentControlErrorV2> {
        checkpoint.validate_aborted_binding(current, aborted_chain)?;
        if written_at_unix_ms < checkpoint.window().completed_at_unix_ms() {
            return Err(DeploymentControlErrorV2::InvalidEvidenceGcCheckpoint);
        }
        super::DeploymentTransitionV2::new(
            DeploymentBranchV2::Normal,
            current.projection().phase(),
            DeploymentPhaseV2::Idle,
        )?;
        let mut decoded = decode_record(current.canonical_bytes())?;
        if written_at_unix_ms < decoded.written_at_unix_ms {
            return Err(DeploymentControlErrorV2::InvalidLedgerRecord);
        }
        let signer_key_id = Ed25519KeyIdV2::new(authority.key_id());
        if authority.installation_id() != *decoded.installation_id.as_bytes()
            || authority.key_epoch() != decoded.installation_epoch
            || verifier.installation_id() != decoded.installation_id
            || verifier.key_epoch() != decoded.installation_epoch
            || verifier.key_id() != signer_key_id
        {
            return Err(DeploymentControlErrorV2::ActivationKeyMismatch);
        }

        decoded.generation = decoded
            .generation
            .checked_add(1)
            .ok_or(DeploymentControlErrorV2::InvalidLedgerRecord)?;
        decoded.written_at_unix_ms = written_at_unix_ms;
        decoded.phase = DeploymentPhaseV2::Idle;
        decoded.transaction_id = None;
        decoded.effects_fenced = false;
        decoded.rollback_grant_state = RollbackGrantStateV2::None;
        decoded.rollback_origin_phase = None;
        decoded.transaction_head_digest = None;
        decoded.previous_record_digest = current.record_payload_digest();
        decoded.record_payload_digest = Digest32V2::new([1; 32]);
        decoded.activation_key_id = signer_key_id;
        decoded.record_signature = DomainSignatureV2 {
            domain_tag: LEDGER_ACTIVATION_SIGNATURE_TAG_V2,
            signer_key_id,
            signer_key_epoch: decoded.installation_epoch,
            signature: Ed25519SignatureV2::new([1; 64]),
        };
        decoded.validate_without_payload_and_signature()?;
        decoded.record_payload_digest = hash_domain(
            LEDGER_RECORD_DIGEST_DOMAIN_V2,
            &encode_record_payload(&decoded)?,
        );
        let request = NativeDeploymentSignatureRequestV2::new(
            NativeDeploymentSignatureDomainV2::LedgerActivation,
            *decoded.installation_id.as_bytes(),
            decoded.installation_epoch,
            *decoded.record_payload_digest.as_bytes(),
        )
        .map_err(|_| DeploymentControlErrorV2::NativeSigningAuthorityUnavailable)?;
        decoded.record_signature.signature = Ed25519SignatureV2::new(
            authority
                .sign(request)
                .map_err(|_| DeploymentControlErrorV2::NativeSigningAuthorityUnavailable)?,
        );
        let successor = Self::from_canonical_bytes(&encode_complete_record(&decoded)?, verifier)?;
        current.validate_successor(&successor, DeploymentBranchV2::Normal)?;
        Ok(successor)
    }

    #[cfg(any(test, feature = "test-support"))]
    #[allow(clippy::too_many_arguments)]
    pub fn new_signed_for_test(
        installation_id: Digest32V2,
        installation_epoch: u64,
        generation: u64,
        previous_record_digest: Digest32V2,
        phase: DeploymentPhaseV2,
        transaction_id: Option<Nonce32V2>,
        effects_fenced: bool,
        effect_fence_epoch: u64,
        rollback_grant_state: RollbackGrantStateV2,
        transaction_head_digest: Option<Digest32V2>,
        written_at_unix_ms: u64,
        seed: u8,
        signing_key: &SigningKey,
    ) -> Result<Self, DeploymentControlErrorV2> {
        Self::new_signed_with_origin_for_test(
            installation_id,
            installation_epoch,
            generation,
            previous_record_digest,
            phase,
            transaction_id,
            effects_fenced,
            effect_fence_epoch,
            rollback_grant_state,
            None,
            transaction_head_digest,
            written_at_unix_ms,
            seed,
            signing_key,
        )
    }

    #[cfg(any(test, feature = "test-support"))]
    #[allow(clippy::too_many_arguments)]
    pub fn new_signed_with_origin_for_test(
        installation_id: Digest32V2,
        installation_epoch: u64,
        generation: u64,
        previous_record_digest: Digest32V2,
        phase: DeploymentPhaseV2,
        transaction_id: Option<Nonce32V2>,
        effects_fenced: bool,
        effect_fence_epoch: u64,
        rollback_grant_state: RollbackGrantStateV2,
        rollback_origin_phase: Option<RollbackOriginPhaseV2>,
        transaction_head_digest: Option<Digest32V2>,
        written_at_unix_ms: u64,
        seed: u8,
        signing_key: &SigningKey,
    ) -> Result<Self, DeploymentControlErrorV2> {
        let activation_key_id = derive_ed25519_key_id_v2(signing_key.verifying_key().to_bytes());
        let entries = std::array::from_fn(|index| HighWaterEntryV2 {
            sequence: u64::try_from(index).unwrap_or(0) + 1,
            content_digest: Digest32V2::new(
                [seed.wrapping_add(u8::try_from(index).unwrap_or(0)); 32],
            ),
            key_epoch: 1,
        });
        let mut decoded = DecodedDeploymentLedgerRecordV2 {
            schema_version: LEDGER_SCHEMA_VERSION_V2,
            installation_id,
            installation_epoch,
            generation,
            written_at_unix_ms,
            phase,
            transaction_id,
            effects_fenced,
            effect_fence_epoch,
            active_manifest_digest: Digest32V2::new([seed.wrapping_add(29); 32]),
            active_activation: ActiveActivationV2::Normal,
            install_identity_profile_signed_digest: Digest32V2::new([seed.wrapping_add(30); 32]),
            bootstrap_tcb_lock_digest: Digest32V2::new([seed.wrapping_add(31); 32]),
            highest_ever: HighestEverV2 { entries },
            rollback_grant_state,
            rollback_origin_phase,
            transaction_head_digest,
            previous_record_digest,
            record_payload_digest: Digest32V2::new([0; 32]),
            activation_key_id,
            record_signature: DomainSignatureV2 {
                domain_tag: LEDGER_ACTIVATION_SIGNATURE_TAG_V2,
                signer_key_id: activation_key_id,
                signer_key_epoch: installation_epoch,
                signature: Ed25519SignatureV2::new([0; 64]),
            },
        };
        decoded.validate_without_payload_and_signature()?;
        decoded.record_payload_digest = hash_domain(
            LEDGER_RECORD_DIGEST_DOMAIN_V2,
            &encode_record_payload(&decoded)?,
        );
        decoded.record_signature.signature = Ed25519SignatureV2::new(
            signing_key
                .sign(&domain_signature_input(
                    LEDGER_ACTIVATION_SIGNATURE_TAG_V2,
                    LEDGER_ACTIVATION_SIGNATURE_DOMAIN_V2,
                    decoded.record_payload_digest,
                ))
                .to_bytes(),
        );
        let bytes = encode_complete_record(&decoded)?;
        let verifier = DeploymentActivationVerifierV2::new(
            installation_id,
            activation_key_id,
            installation_epoch,
            signing_key.verifying_key().to_bytes(),
        )?;
        Self::from_canonical_bytes(&bytes, &verifier)
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn with_high_water_entry_for_test(
        &self,
        domain_index: usize,
        sequence: u64,
        content_digest: Digest32V2,
        key_epoch: u64,
        signing_key: &SigningKey,
    ) -> Result<Self, DeploymentControlErrorV2> {
        if domain_index >= HIGHEST_EVER_DOMAIN_COUNT_V2 {
            return Err(DeploymentControlErrorV2::HighestEverMismatch);
        }
        let mut decoded = decode_record(&self.canonical_bytes)?;
        let key_id = derive_ed25519_key_id_v2(signing_key.verifying_key().to_bytes());
        if decoded.activation_key_id != key_id {
            return Err(DeploymentControlErrorV2::ActivationKeyMismatch);
        }
        decoded.highest_ever.entries[domain_index] = HighWaterEntryV2 {
            sequence,
            content_digest,
            key_epoch,
        };
        decoded.highest_ever.validate()?;
        decoded.record_payload_digest = hash_domain(
            LEDGER_RECORD_DIGEST_DOMAIN_V2,
            &encode_record_payload(&decoded)?,
        );
        decoded.record_signature.signature = Ed25519SignatureV2::new(
            signing_key
                .sign(&domain_signature_input(
                    LEDGER_ACTIVATION_SIGNATURE_TAG_V2,
                    LEDGER_ACTIVATION_SIGNATURE_DOMAIN_V2,
                    decoded.record_payload_digest,
                ))
                .to_bytes(),
        );
        let verifier = DeploymentActivationVerifierV2::new(
            decoded.installation_id,
            key_id,
            decoded.installation_epoch,
            signing_key.verifying_key().to_bytes(),
        )?;
        Self::from_canonical_bytes(&encode_complete_record(&decoded)?, &verifier)
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn with_active_manifest_for_test(
        &self,
        active_manifest_digest: Digest32V2,
        signing_key: &SigningKey,
    ) -> Result<Self, DeploymentControlErrorV2> {
        let mut decoded = decode_record(&self.canonical_bytes)?;
        let key_id = derive_ed25519_key_id_v2(signing_key.verifying_key().to_bytes());
        if decoded.activation_key_id != key_id || is_zero(active_manifest_digest.as_bytes()) {
            return Err(DeploymentControlErrorV2::ActivationKeyMismatch);
        }
        decoded.active_manifest_digest = active_manifest_digest;
        decoded.record_payload_digest = hash_domain(
            LEDGER_RECORD_DIGEST_DOMAIN_V2,
            &encode_record_payload(&decoded)?,
        );
        decoded.record_signature.signature = Ed25519SignatureV2::new(
            signing_key
                .sign(&domain_signature_input(
                    LEDGER_ACTIVATION_SIGNATURE_TAG_V2,
                    LEDGER_ACTIVATION_SIGNATURE_DOMAIN_V2,
                    decoded.record_payload_digest,
                ))
                .to_bytes(),
        );
        let verifier = DeploymentActivationVerifierV2::new(
            decoded.installation_id,
            key_id,
            decoded.installation_epoch,
            signing_key.verifying_key().to_bytes(),
        )?;
        Self::from_canonical_bytes(&encode_complete_record(&decoded)?, &verifier)
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn with_bootstrap_tcb_lock_for_test(
        &self,
        bootstrap_tcb_lock_digest: Digest32V2,
        signing_key: &SigningKey,
    ) -> Result<Self, DeploymentControlErrorV2> {
        let mut decoded = decode_record(&self.canonical_bytes)?;
        let key_id = derive_ed25519_key_id_v2(signing_key.verifying_key().to_bytes());
        if decoded.activation_key_id != key_id || is_zero(bootstrap_tcb_lock_digest.as_bytes()) {
            return Err(DeploymentControlErrorV2::ActivationKeyMismatch);
        }
        decoded.bootstrap_tcb_lock_digest = bootstrap_tcb_lock_digest;
        decoded.record_payload_digest = hash_domain(
            LEDGER_RECORD_DIGEST_DOMAIN_V2,
            &encode_record_payload(&decoded)?,
        );
        decoded.record_signature.signature = Ed25519SignatureV2::new(
            signing_key
                .sign(&domain_signature_input(
                    LEDGER_ACTIVATION_SIGNATURE_TAG_V2,
                    LEDGER_ACTIVATION_SIGNATURE_DOMAIN_V2,
                    decoded.record_payload_digest,
                ))
                .to_bytes(),
        );
        let verifier = DeploymentActivationVerifierV2::new(
            decoded.installation_id,
            key_id,
            decoded.installation_epoch,
            signing_key.verifying_key().to_bytes(),
        )?;
        Self::from_canonical_bytes(&encode_complete_record(&decoded)?, &verifier)
    }
}

fn validate_active_state_successor(
    current: &DecodedDeploymentLedgerRecordV2,
    successor: &DecodedDeploymentLedgerRecordV2,
    transition: super::DeploymentTransitionV2,
) -> Result<(), DeploymentControlErrorV2> {
    if successor.install_identity_profile_signed_digest
        != current.install_identity_profile_signed_digest
        || successor.bootstrap_tcb_lock_digest != current.bootstrap_tcb_lock_digest
    {
        return Err(DeploymentControlErrorV2::ActiveStateMismatch);
    }

    let valid = match transition.to() {
        DeploymentPhaseV2::Committed => {
            successor.active_manifest_digest != current.active_manifest_digest
                && successor.active_activation == ActiveActivationV2::Normal
        }
        DeploymentPhaseV2::RolledBack => {
            matches!(
                &successor.active_activation,
                ActiveActivationV2::ConsumedRollback {
                    failed_transaction_id,
                    ..
                } if Some(*failed_transaction_id) == current.transaction_id
            )
        }
        DeploymentPhaseV2::BootstrapBridge
            if transition.from() == DeploymentPhaseV2::BridgeRestoreVerified =>
        {
            successor.active_manifest_digest == current.active_manifest_digest
                && bridge_restore_activation_successor(
                    &current.active_activation,
                    &successor.active_activation,
                    current.transaction_id,
                )
        }
        _ => {
            successor.active_manifest_digest == current.active_manifest_digest
                && successor.active_activation == current.active_activation
        }
    };
    if !valid {
        return Err(DeploymentControlErrorV2::ActiveStateMismatch);
    }
    Ok(())
}

fn successor_activation(
    current: &DecodedDeploymentLedgerRecordV2,
    transition: super::DeploymentTransitionV2,
    update: DeploymentActivationUpdateV2,
    transaction_id: Nonce32V2,
) -> Result<ActiveActivationV2, DeploymentControlErrorV2> {
    match (transition.from(), transition.to(), update) {
        (
            _,
            DeploymentPhaseV2::Committed,
            DeploymentActivationUpdateV2::CommitNormal {
                active_manifest_digest,
            },
        ) if !is_zero(active_manifest_digest.as_bytes())
            && active_manifest_digest != current.active_manifest_digest =>
        {
            Ok(ActiveActivationV2::Normal)
        }
        (
            _,
            DeploymentPhaseV2::RolledBack,
            DeploymentActivationUpdateV2::ActivateRollback {
                active_manifest_digest,
                rollback_grant_id,
            },
        ) if !is_zero(active_manifest_digest.as_bytes())
            && !is_zero(rollback_grant_id.as_bytes()) =>
        {
            Ok(ActiveActivationV2::ConsumedRollback {
                failed_transaction_id: transaction_id,
                rollback_grant_id,
            })
        }
        (
            DeploymentPhaseV2::BridgeRestoreVerified,
            DeploymentPhaseV2::BootstrapBridge,
            DeploymentActivationUpdateV2::RestoreBootstrapBridge {
                bridge_genesis_ledger_record_signed_digest,
                recovery_grant_id,
            },
        ) if !is_zero(bridge_genesis_ledger_record_signed_digest.as_bytes())
            && !is_zero(recovery_grant_id.as_bytes()) =>
        {
            let ActiveActivationV2::BootstrapBridge(bridge) = &current.active_activation else {
                return Err(DeploymentControlErrorV2::ActiveStateMismatch);
            };
            let restore_origin_phase = current
                .rollback_origin_phase
                .ok_or(DeploymentControlErrorV2::RollbackOriginMismatch)?;
            Ok(ActiveActivationV2::BootstrapBridge(Box::new(
                BootstrapBridgeActivationV2 {
                    maintenance_intent_signed_digest: bridge.maintenance_intent_signed_digest,
                    bridge_manifest_digest: bridge.bridge_manifest_digest,
                    premaintenance_runtime_manifest_digest: bridge
                        .premaintenance_runtime_manifest_digest,
                    previous_installation_epoch: bridge.previous_installation_epoch,
                    previous_epoch_last_ledger_record_signed_digest: bridge
                        .previous_epoch_last_ledger_record_signed_digest,
                    previous_epoch_last_ledger_record_payload_digest: bridge
                        .previous_epoch_last_ledger_record_payload_digest,
                    restore_provenance: Some(BootstrapBridgeRestoreProvenanceV2 {
                        bridge_genesis_ledger_record_signed_digest,
                        failed_transaction_id: transaction_id,
                        recovery_grant_id,
                        restore_origin_phase,
                    }),
                },
            )))
        }
        (_, DeploymentPhaseV2::Committed, _)
        | (_, DeploymentPhaseV2::RolledBack, _)
        | (DeploymentPhaseV2::BridgeRestoreVerified, DeploymentPhaseV2::BootstrapBridge, _) => {
            Err(DeploymentControlErrorV2::ActiveStateMismatch)
        }
        (_, _, DeploymentActivationUpdateV2::Retain) => Ok(current.active_activation.clone()),
        _ => Err(DeploymentControlErrorV2::ActiveStateMismatch),
    }
}

fn successor_fence(
    current: &DeploymentLedgerProjectionV2,
    target: DeploymentPhaseV2,
) -> Result<(bool, u64), DeploymentControlErrorV2> {
    let incremented = || {
        current
            .effect_fence_epoch()
            .checked_add(1)
            .ok_or(DeploymentControlErrorV2::FenceTransitionMismatch)
    };
    match target {
        DeploymentPhaseV2::Armed
        | DeploymentPhaseV2::RollbackPrepared
        | DeploymentPhaseV2::BridgeRestorePrepared
        | DeploymentPhaseV2::FailedSafe => Ok((true, incremented()?)),
        DeploymentPhaseV2::Committed | DeploymentPhaseV2::RolledBack => Ok((false, incremented()?)),
        DeploymentPhaseV2::Idle => Ok((false, current.effect_fence_epoch())),
        DeploymentPhaseV2::Prepared | DeploymentPhaseV2::Aborted => {
            Ok((current.effects_fenced(), current.effect_fence_epoch()))
        }
        _ => Ok((true, current.effect_fence_epoch())),
    }
}

fn successor_grant_state(
    current: &DeploymentLedgerProjectionV2,
    target: DeploymentPhaseV2,
) -> Result<RollbackGrantStateV2, DeploymentControlErrorV2> {
    let state = match target {
        DeploymentPhaseV2::Prepared
        | DeploymentPhaseV2::Armed
        | DeploymentPhaseV2::Quiesced
        | DeploymentPhaseV2::Installed
        | DeploymentPhaseV2::Verified => RollbackGrantStateV2::Prearmed,
        DeploymentPhaseV2::RollbackPrepared
        | DeploymentPhaseV2::RollbackInstalled
        | DeploymentPhaseV2::RollbackVerified
        | DeploymentPhaseV2::BridgeRestorePrepared
        | DeploymentPhaseV2::BridgeRestoreInstalled
        | DeploymentPhaseV2::BridgeRestoreVerified => RollbackGrantStateV2::Consuming,
        DeploymentPhaseV2::RolledBack => RollbackGrantStateV2::Consumed,
        DeploymentPhaseV2::Committed
        | DeploymentPhaseV2::Aborted
        | DeploymentPhaseV2::FailedSafe => RollbackGrantStateV2::Burned,
        DeploymentPhaseV2::BootstrapBridge
            if current.phase() == DeploymentPhaseV2::BridgeRestoreVerified =>
        {
            RollbackGrantStateV2::Consumed
        }
        DeploymentPhaseV2::BootstrapBridge => RollbackGrantStateV2::Burned,
        DeploymentPhaseV2::Idle => RollbackGrantStateV2::None,
    };
    Ok(state)
}

fn successor_rollback_origin(
    current: &DeploymentLedgerProjectionV2,
    current_origin: Option<RollbackOriginPhaseV2>,
    target: DeploymentPhaseV2,
) -> Result<Option<RollbackOriginPhaseV2>, DeploymentControlErrorV2> {
    match target {
        DeploymentPhaseV2::RollbackPrepared | DeploymentPhaseV2::BridgeRestorePrepared => {
            let origin = match current.phase() {
                DeploymentPhaseV2::Armed => RollbackOriginPhaseV2::Armed,
                DeploymentPhaseV2::Quiesced => RollbackOriginPhaseV2::Quiesced,
                DeploymentPhaseV2::Installed => RollbackOriginPhaseV2::Installed,
                DeploymentPhaseV2::Verified => RollbackOriginPhaseV2::Verified,
                _ => return Err(DeploymentControlErrorV2::RollbackOriginMismatch),
            };
            Ok(Some(origin))
        }
        DeploymentPhaseV2::RollbackInstalled
        | DeploymentPhaseV2::RollbackVerified
        | DeploymentPhaseV2::RolledBack
        | DeploymentPhaseV2::BridgeRestoreInstalled
        | DeploymentPhaseV2::BridgeRestoreVerified
        | DeploymentPhaseV2::FailedSafe
        | DeploymentPhaseV2::BootstrapBridge => Ok(current_origin),
        _ => Ok(None),
    }
}

fn bridge_restore_activation_successor(
    current: &ActiveActivationV2,
    successor: &ActiveActivationV2,
    transaction_id: Option<Nonce32V2>,
) -> bool {
    let (ActiveActivationV2::BootstrapBridge(current), ActiveActivationV2::BootstrapBridge(next)) =
        (current, successor)
    else {
        return false;
    };
    current.maintenance_intent_signed_digest == next.maintenance_intent_signed_digest
        && current.bridge_manifest_digest == next.bridge_manifest_digest
        && current.premaintenance_runtime_manifest_digest
            == next.premaintenance_runtime_manifest_digest
        && current.previous_installation_epoch == next.previous_installation_epoch
        && current.previous_epoch_last_ledger_record_signed_digest
            == next.previous_epoch_last_ledger_record_signed_digest
        && current.previous_epoch_last_ledger_record_payload_digest
            == next.previous_epoch_last_ledger_record_payload_digest
        && next
            .restore_provenance
            .as_ref()
            .is_some_and(|provenance| Some(provenance.failed_transaction_id) == transaction_id)
}

fn validate_rollback_origin_successor(
    current: &DecodedDeploymentLedgerRecordV2,
    successor: &DecodedDeploymentLedgerRecordV2,
    transition: super::DeploymentTransitionV2,
) -> Result<(), DeploymentControlErrorV2> {
    let expected = match transition.to() {
        DeploymentPhaseV2::RollbackPrepared | DeploymentPhaseV2::BridgeRestorePrepared => {
            Some(match transition.from() {
                DeploymentPhaseV2::Armed => RollbackOriginPhaseV2::Armed,
                DeploymentPhaseV2::Quiesced => RollbackOriginPhaseV2::Quiesced,
                DeploymentPhaseV2::Installed => RollbackOriginPhaseV2::Installed,
                DeploymentPhaseV2::Verified => RollbackOriginPhaseV2::Verified,
                _ => return Err(DeploymentControlErrorV2::RollbackOriginMismatch),
            })
        }
        DeploymentPhaseV2::RollbackInstalled
        | DeploymentPhaseV2::RollbackVerified
        | DeploymentPhaseV2::RolledBack
        | DeploymentPhaseV2::BridgeRestoreInstalled
        | DeploymentPhaseV2::BridgeRestoreVerified
        | DeploymentPhaseV2::FailedSafe => current.rollback_origin_phase,
        DeploymentPhaseV2::BootstrapBridge
            if transition.from() == DeploymentPhaseV2::BridgeRestoreVerified =>
        {
            current.rollback_origin_phase
        }
        _ => None,
    };
    if successor.rollback_origin_phase != expected {
        return Err(DeploymentControlErrorV2::RollbackOriginMismatch);
    }
    Ok(())
}

#[derive(Debug, Clone)]
pub struct SignedLedgerSlotV2 {
    canonical_bytes: Vec<u8>,
}

impl SignedLedgerSlotV2 {
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub fn verify_canonical_bytes(
        bytes: &[u8],
        verifier: &DeploymentActivationVerifierV2,
    ) -> Result<VerifiedLedgerSlotV2, DeploymentControlErrorV2> {
        if bytes.is_empty() || bytes.len() > MAX_LEDGER_SLOT_BYTES_V2 {
            return Err(DeploymentControlErrorV2::InvalidLedgerSlot);
        }
        let decoded = decode_slot(bytes)?;
        if encode_slot(&decoded)? != bytes {
            return Err(DeploymentControlErrorV2::NonCanonicalLedgerEncoding);
        }
        let record =
            DeploymentLedgerRecordV2::from_canonical_bytes(&decoded.record_bytes, verifier)?;
        let projection = record.projection();
        if decoded.installation_id != projection.installation_id()
            || decoded.installation_epoch != projection.installation_epoch()
            || decoded.generation != projection.generation()
            || decoded.previous_record_digest != projection.previous_record_digest()
            || decoded.record_payload_digest != projection.record_payload_digest()
            || decoded.activation_key_id != verifier.key_id
            || decoded.installation_epoch != verifier.key_epoch
        {
            return Err(DeploymentControlErrorV2::InvalidLedgerSlot);
        }
        let checksum = ledger_slot_checksum(decoded.slot_id, &decoded.record_bytes);
        if checksum != decoded.checksum {
            return Err(DeploymentControlErrorV2::LedgerSlotChecksumMismatch);
        }
        verifier.verify(
            decoded.signature,
            LEDGER_SLOT_SIGNATURE_TAG_V2,
            LEDGER_SLOT_SIGNATURE_DOMAIN_V2,
            checksum,
        )?;
        VerifiedLedgerSlotV2::from_authenticated_slot(decoded.slot_id, record)
    }

    pub fn new_signed_with_authority(
        slot_id: LedgerSlotIdV2,
        record: &DeploymentLedgerRecordV2,
        authority: &mut dyn NativeDeploymentSigningAuthorityV2,
        verifier: &DeploymentActivationVerifierV2,
    ) -> Result<Self, DeploymentControlErrorV2> {
        let projection = record.projection();
        let activation_key_id = Ed25519KeyIdV2::new(authority.key_id());
        if authority.installation_id() != *projection.installation_id().as_bytes()
            || authority.key_epoch() != projection.installation_epoch()
            || verifier.installation_id() != projection.installation_id()
            || verifier.key_epoch() != projection.installation_epoch()
            || verifier.key_id() != activation_key_id
        {
            return Err(DeploymentControlErrorV2::ActivationKeyMismatch);
        }
        let checksum = ledger_slot_checksum(slot_id, record.canonical_bytes());
        let request = NativeDeploymentSignatureRequestV2::new(
            NativeDeploymentSignatureDomainV2::LedgerSlot,
            *projection.installation_id().as_bytes(),
            projection.installation_epoch(),
            *checksum.as_bytes(),
        )
        .map_err(|_| DeploymentControlErrorV2::NativeSigningAuthorityUnavailable)?;
        let signature = DomainSignatureV2 {
            domain_tag: LEDGER_SLOT_SIGNATURE_TAG_V2,
            signer_key_id: activation_key_id,
            signer_key_epoch: projection.installation_epoch(),
            signature: Ed25519SignatureV2::new(
                authority
                    .sign(request)
                    .map_err(|_| DeploymentControlErrorV2::NativeSigningAuthorityUnavailable)?,
            ),
        };
        let decoded = DecodedLedgerSlotV2 {
            slot_id,
            installation_id: projection.installation_id(),
            installation_epoch: projection.installation_epoch(),
            generation: projection.generation(),
            previous_record_digest: projection.previous_record_digest(),
            record_bytes: record.canonical_bytes().to_vec(),
            record_payload_digest: projection.record_payload_digest(),
            checksum,
            activation_key_id,
            signature,
        };
        let canonical_bytes = encode_slot(&decoded)?;
        Self::verify_canonical_bytes(&canonical_bytes, verifier)?;
        Ok(Self { canonical_bytes })
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn new_signed_for_test(
        slot_id: LedgerSlotIdV2,
        record: &DeploymentLedgerRecordV2,
        signing_key: &SigningKey,
    ) -> Result<Self, DeploymentControlErrorV2> {
        let projection = record.projection();
        let activation_key_id = derive_ed25519_key_id_v2(signing_key.verifying_key().to_bytes());
        let checksum = ledger_slot_checksum(slot_id, record.canonical_bytes());
        let signature = DomainSignatureV2 {
            domain_tag: LEDGER_SLOT_SIGNATURE_TAG_V2,
            signer_key_id: activation_key_id,
            signer_key_epoch: projection.installation_epoch(),
            signature: Ed25519SignatureV2::new(
                signing_key
                    .sign(&domain_signature_input(
                        LEDGER_SLOT_SIGNATURE_TAG_V2,
                        LEDGER_SLOT_SIGNATURE_DOMAIN_V2,
                        checksum,
                    ))
                    .to_bytes(),
            ),
        };
        let decoded = DecodedLedgerSlotV2 {
            slot_id,
            installation_id: projection.installation_id(),
            installation_epoch: projection.installation_epoch(),
            generation: projection.generation(),
            previous_record_digest: projection.previous_record_digest(),
            record_bytes: record.canonical_bytes().to_vec(),
            record_payload_digest: projection.record_payload_digest(),
            checksum,
            activation_key_id,
            signature,
        };
        Ok(Self {
            canonical_bytes: encode_slot(&decoded)?,
        })
    }
}

#[derive(Debug, Clone)]
struct DecodedDeploymentLedgerRecordV2 {
    schema_version: u16,
    installation_id: Digest32V2,
    installation_epoch: u64,
    generation: u64,
    written_at_unix_ms: u64,
    phase: DeploymentPhaseV2,
    transaction_id: Option<Nonce32V2>,
    effects_fenced: bool,
    effect_fence_epoch: u64,
    active_manifest_digest: Digest32V2,
    active_activation: ActiveActivationV2,
    install_identity_profile_signed_digest: Digest32V2,
    bootstrap_tcb_lock_digest: Digest32V2,
    highest_ever: HighestEverV2,
    rollback_grant_state: RollbackGrantStateV2,
    rollback_origin_phase: Option<RollbackOriginPhaseV2>,
    transaction_head_digest: Option<Digest32V2>,
    previous_record_digest: Digest32V2,
    record_payload_digest: Digest32V2,
    activation_key_id: Ed25519KeyIdV2,
    record_signature: DomainSignatureV2,
}

impl DecodedDeploymentLedgerRecordV2 {
    fn validate_without_payload_and_signature(&self) -> Result<(), DeploymentControlErrorV2> {
        if self.schema_version != LEDGER_SCHEMA_VERSION_V2
            || self.installation_epoch == 0
            || self.generation == 0
            || self.written_at_unix_ms == 0
            || self.effect_fence_epoch == 0
            || self
                .activation_key_id
                .as_bytes()
                .iter()
                .all(|byte| *byte == 0)
        {
            return Err(DeploymentControlErrorV2::InvalidLedgerRecord);
        }
        require_nonzero(&[
            self.installation_id.as_bytes(),
            self.active_manifest_digest.as_bytes(),
            self.install_identity_profile_signed_digest.as_bytes(),
            self.bootstrap_tcb_lock_digest.as_bytes(),
        ])?;
        self.active_activation.validate()?;
        self.highest_ever.validate()?;
        let activation_matches_phase = match self.phase {
            DeploymentPhaseV2::Idle => matches!(
                &self.active_activation,
                ActiveActivationV2::Normal | ActiveActivationV2::ConsumedRollback { .. }
            ),
            DeploymentPhaseV2::RolledBack => {
                matches!(
                    &self.active_activation,
                    ActiveActivationV2::ConsumedRollback { .. }
                )
            }
            DeploymentPhaseV2::BootstrapBridge
            | DeploymentPhaseV2::BridgeRestorePrepared
            | DeploymentPhaseV2::BridgeRestoreInstalled
            | DeploymentPhaseV2::BridgeRestoreVerified => {
                matches!(
                    &self.active_activation,
                    ActiveActivationV2::BootstrapBridge(_)
                )
            }
            _ => true,
        };
        if !activation_matches_phase {
            return Err(DeploymentControlErrorV2::InvalidLedgerRecord);
        }
        let origin_matches_phase = match self.phase {
            DeploymentPhaseV2::RollbackPrepared
            | DeploymentPhaseV2::RollbackInstalled
            | DeploymentPhaseV2::RollbackVerified
            | DeploymentPhaseV2::RolledBack
            | DeploymentPhaseV2::BridgeRestorePrepared
            | DeploymentPhaseV2::BridgeRestoreInstalled
            | DeploymentPhaseV2::BridgeRestoreVerified => self.rollback_origin_phase.is_some(),
            DeploymentPhaseV2::BootstrapBridge => match &self.active_activation {
                ActiveActivationV2::BootstrapBridge(activation) => {
                    match &activation.restore_provenance {
                        Some(provenance) => {
                            self.rollback_origin_phase == Some(provenance.restore_origin_phase)
                        }
                        None => self.rollback_origin_phase.is_none(),
                    }
                }
                _ => false,
            },
            DeploymentPhaseV2::FailedSafe => true,
            _ => self.rollback_origin_phase.is_none(),
        };
        if !origin_matches_phase {
            return Err(DeploymentControlErrorV2::InvalidLedgerRecord);
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), DeploymentControlErrorV2> {
        self.validate_without_payload_and_signature()?;
        if is_zero(self.record_payload_digest.as_bytes())
            || is_zero(self.record_signature.signature.as_bytes())
        {
            return Err(DeploymentControlErrorV2::InvalidLedgerRecord);
        }
        Ok(())
    }

    fn projection(&self) -> Result<DeploymentLedgerProjectionV2, DeploymentControlErrorV2> {
        DeploymentLedgerProjectionV2::from_authenticated_record(
            self.installation_id,
            self.installation_epoch,
            self.generation,
            self.previous_record_digest,
            self.record_payload_digest,
            self.phase,
            self.transaction_id,
            self.effects_fenced,
            self.effect_fence_epoch,
            self.rollback_grant_state,
            self.transaction_head_digest,
        )
    }
}

#[derive(Debug, Clone)]
struct DecodedLedgerSlotV2 {
    slot_id: LedgerSlotIdV2,
    installation_id: Digest32V2,
    installation_epoch: u64,
    generation: u64,
    previous_record_digest: Digest32V2,
    record_bytes: Vec<u8>,
    record_payload_digest: Digest32V2,
    checksum: Digest32V2,
    activation_key_id: Ed25519KeyIdV2,
    signature: DomainSignatureV2,
}

fn encode_complete_record(
    value: &DecodedDeploymentLedgerRecordV2,
) -> Result<Vec<u8>, DeploymentControlErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(LEDGER_RECORD_FIELDS_V2)
        .map_err(|_| DeploymentControlErrorV2::InvalidLedgerRecord)?;
    encode_record_prefix(&mut encoder, value)?;
    encoder
        .bytes(value.record_payload_digest.as_bytes())
        .and_then(|encoder| encoder.bytes(value.activation_key_id.as_bytes()))
        .map_err(|_| DeploymentControlErrorV2::InvalidLedgerRecord)?;
    encode_domain_signature(&mut encoder, value.record_signature)?;
    Ok(encoder.into_writer())
}

fn encode_record_payload(
    value: &DecodedDeploymentLedgerRecordV2,
) -> Result<Vec<u8>, DeploymentControlErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(LEDGER_PAYLOAD_FIELDS_V2)
        .map_err(|_| DeploymentControlErrorV2::InvalidLedgerRecord)?;
    encode_record_prefix(&mut encoder, value)?;
    encoder
        .bytes(value.activation_key_id.as_bytes())
        .map_err(|_| DeploymentControlErrorV2::InvalidLedgerRecord)?;
    Ok(encoder.into_writer())
}

fn encode_record_prefix(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    value: &DecodedDeploymentLedgerRecordV2,
) -> Result<(), DeploymentControlErrorV2> {
    encoder
        .u16(value.schema_version)
        .and_then(|encoder| encoder.bytes(value.installation_id.as_bytes()))
        .and_then(|encoder| encoder.u64(value.installation_epoch))
        .and_then(|encoder| encoder.u64(value.generation))
        .and_then(|encoder| encoder.u64(value.written_at_unix_ms))
        .and_then(|encoder| encoder.u16(value.phase as u16))
        .map_err(|_| DeploymentControlErrorV2::InvalidLedgerRecord)?;
    encode_optional_nonce(encoder, value.transaction_id)?;
    encoder
        .bool(value.effects_fenced)
        .and_then(|encoder| encoder.u64(value.effect_fence_epoch))
        .and_then(|encoder| encoder.bytes(value.active_manifest_digest.as_bytes()))
        .map_err(|_| DeploymentControlErrorV2::InvalidLedgerRecord)?;
    encode_active_activation(encoder, &value.active_activation)?;
    encoder
        .bytes(value.install_identity_profile_signed_digest.as_bytes())
        .and_then(|encoder| encoder.bytes(value.bootstrap_tcb_lock_digest.as_bytes()))
        .map_err(|_| DeploymentControlErrorV2::InvalidLedgerRecord)?;
    encode_highest_ever(encoder, &value.highest_ever)?;
    encoder
        .u16(value.rollback_grant_state as u16)
        .map_err(|_| DeploymentControlErrorV2::InvalidLedgerRecord)?;
    encode_optional_origin(encoder, value.rollback_origin_phase)?;
    encode_optional_digest(encoder, value.transaction_head_digest)?;
    encoder
        .bytes(value.previous_record_digest.as_bytes())
        .map_err(|_| DeploymentControlErrorV2::InvalidLedgerRecord)?;
    Ok(())
}

fn decode_record(
    bytes: &[u8],
) -> Result<DecodedDeploymentLedgerRecordV2, DeploymentControlErrorV2> {
    let mut decoder = minicbor::Decoder::new(bytes);
    expect_array(&mut decoder, LEDGER_RECORD_FIELDS_V2)?;
    let value = DecodedDeploymentLedgerRecordV2 {
        schema_version: decode_u16(&mut decoder)?,
        installation_id: decode_digest(&mut decoder)?,
        installation_epoch: decode_u64(&mut decoder)?,
        generation: decode_u64(&mut decoder)?,
        written_at_unix_ms: decode_u64(&mut decoder)?,
        phase: decode_phase(&mut decoder)?,
        transaction_id: decode_optional_nonce(&mut decoder)?,
        effects_fenced: decoder
            .bool()
            .map_err(|_| DeploymentControlErrorV2::InvalidLedgerRecord)?,
        effect_fence_epoch: decode_u64(&mut decoder)?,
        active_manifest_digest: decode_digest(&mut decoder)?,
        active_activation: decode_active_activation(&mut decoder)?,
        install_identity_profile_signed_digest: decode_digest(&mut decoder)?,
        bootstrap_tcb_lock_digest: decode_digest(&mut decoder)?,
        highest_ever: decode_highest_ever(&mut decoder)?,
        rollback_grant_state: decode_grant_state(&mut decoder)?,
        rollback_origin_phase: decode_optional_origin(&mut decoder)?,
        transaction_head_digest: decode_optional_digest(&mut decoder)?,
        previous_record_digest: decode_digest(&mut decoder)?,
        record_payload_digest: decode_digest(&mut decoder)?,
        activation_key_id: decode_key_id(&mut decoder)?,
        record_signature: decode_domain_signature(&mut decoder)?,
    };
    if decoder.position() != bytes.len() {
        return Err(DeploymentControlErrorV2::InvalidLedgerRecord);
    }
    Ok(value)
}

fn encode_slot(value: &DecodedLedgerSlotV2) -> Result<Vec<u8>, DeploymentControlErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(LEDGER_SLOT_FIELDS_V2)
        .and_then(|encoder| encoder.u16(value.slot_id as u16))
        .and_then(|encoder| encoder.bytes(value.installation_id.as_bytes()))
        .and_then(|encoder| encoder.u64(value.installation_epoch))
        .and_then(|encoder| encoder.u64(value.generation))
        .and_then(|encoder| encoder.bytes(value.previous_record_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(&value.record_bytes))
        .and_then(|encoder| encoder.bytes(value.record_payload_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(value.checksum.as_bytes()))
        .and_then(|encoder| encoder.bytes(value.activation_key_id.as_bytes()))
        .map_err(|_| DeploymentControlErrorV2::InvalidLedgerSlot)?;
    encode_domain_signature(&mut encoder, value.signature)?;
    Ok(encoder.into_writer())
}

fn decode_slot(bytes: &[u8]) -> Result<DecodedLedgerSlotV2, DeploymentControlErrorV2> {
    let mut decoder = minicbor::Decoder::new(bytes);
    expect_array(&mut decoder, LEDGER_SLOT_FIELDS_V2)?;
    let slot_id = match decode_u16(&mut decoder)? {
        1 => LedgerSlotIdV2::A,
        2 => LedgerSlotIdV2::B,
        _ => return Err(DeploymentControlErrorV2::InvalidLedgerSlot),
    };
    let value = DecodedLedgerSlotV2 {
        slot_id,
        installation_id: decode_digest(&mut decoder)?,
        installation_epoch: decode_u64(&mut decoder)?,
        generation: decode_u64(&mut decoder)?,
        previous_record_digest: decode_digest(&mut decoder)?,
        record_bytes: decode_bounded_bytes(&mut decoder, MAX_LEDGER_RECORD_BYTES_V2)?,
        record_payload_digest: decode_digest(&mut decoder)?,
        checksum: decode_digest(&mut decoder)?,
        activation_key_id: decode_key_id(&mut decoder)?,
        signature: decode_domain_signature(&mut decoder)?,
    };
    if decoder.position() != bytes.len() {
        return Err(DeploymentControlErrorV2::InvalidLedgerSlot);
    }
    Ok(value)
}

fn encode_highest_ever(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    value: &HighestEverV2,
) -> Result<(), DeploymentControlErrorV2> {
    encoder
        .array(HIGHEST_EVER_DOMAIN_COUNT_V2 as u64)
        .map_err(|_| DeploymentControlErrorV2::InvalidLedgerRecord)?;
    for entry in value.entries {
        encoder
            .array(3)
            .and_then(|encoder| encoder.u64(entry.sequence))
            .and_then(|encoder| encoder.bytes(entry.content_digest.as_bytes()))
            .and_then(|encoder| encoder.u64(entry.key_epoch))
            .map_err(|_| DeploymentControlErrorV2::InvalidLedgerRecord)?;
    }
    Ok(())
}

fn decode_highest_ever(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<HighestEverV2, DeploymentControlErrorV2> {
    expect_array(decoder, HIGHEST_EVER_DOMAIN_COUNT_V2 as u64)?;
    let mut entries = [HighWaterEntryV2 {
        sequence: 0,
        content_digest: Digest32V2::new([0; 32]),
        key_epoch: 0,
    }; HIGHEST_EVER_DOMAIN_COUNT_V2];
    for entry in &mut entries {
        expect_array(decoder, 3)?;
        *entry = HighWaterEntryV2 {
            sequence: decode_u64(decoder)?,
            content_digest: decode_digest(decoder)?,
            key_epoch: decode_u64(decoder)?,
        };
    }
    Ok(HighestEverV2 { entries })
}

fn encode_active_activation(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    value: &ActiveActivationV2,
) -> Result<(), DeploymentControlErrorV2> {
    match value {
        ActiveActivationV2::Normal => {
            encoder
                .array(1)
                .and_then(|encoder| encoder.u16(1))
                .map_err(|_| DeploymentControlErrorV2::InvalidLedgerRecord)?;
        }
        ActiveActivationV2::ConsumedRollback {
            failed_transaction_id,
            rollback_grant_id,
        } => {
            encoder
                .array(3)
                .and_then(|encoder| encoder.u16(2))
                .and_then(|encoder| encoder.bytes(failed_transaction_id.as_bytes()))
                .and_then(|encoder| encoder.bytes(rollback_grant_id.as_bytes()))
                .map_err(|_| DeploymentControlErrorV2::InvalidLedgerRecord)?;
        }
        ActiveActivationV2::BootstrapBridge(value) => {
            encoder
                .array(8)
                .and_then(|encoder| encoder.u16(3))
                .and_then(|encoder| {
                    encoder.bytes(value.maintenance_intent_signed_digest.as_bytes())
                })
                .and_then(|encoder| encoder.bytes(value.bridge_manifest_digest.as_bytes()))
                .and_then(|encoder| {
                    encoder.bytes(value.premaintenance_runtime_manifest_digest.as_bytes())
                })
                .and_then(|encoder| encoder.u64(value.previous_installation_epoch))
                .and_then(|encoder| {
                    encoder.bytes(
                        value
                            .previous_epoch_last_ledger_record_signed_digest
                            .as_bytes(),
                    )
                })
                .and_then(|encoder| {
                    encoder.bytes(
                        value
                            .previous_epoch_last_ledger_record_payload_digest
                            .as_bytes(),
                    )
                })
                .map_err(|_| DeploymentControlErrorV2::InvalidLedgerRecord)?;
            encode_optional_restore_provenance(encoder, value.restore_provenance.as_ref())?;
        }
    }
    Ok(())
}

fn decode_active_activation(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<ActiveActivationV2, DeploymentControlErrorV2> {
    let length = decoder
        .array()
        .map_err(|_| DeploymentControlErrorV2::InvalidLedgerRecord)?;
    let tag = decode_u16(decoder)?;
    match (tag, length) {
        (1, Some(1)) => Ok(ActiveActivationV2::Normal),
        (2, Some(3)) => Ok(ActiveActivationV2::ConsumedRollback {
            failed_transaction_id: decode_nonce(decoder)?,
            rollback_grant_id: decode_digest(decoder)?,
        }),
        (3, Some(8)) => Ok(ActiveActivationV2::BootstrapBridge(Box::new(
            BootstrapBridgeActivationV2 {
                maintenance_intent_signed_digest: decode_digest(decoder)?,
                bridge_manifest_digest: decode_digest(decoder)?,
                premaintenance_runtime_manifest_digest: decode_digest(decoder)?,
                previous_installation_epoch: decode_u64(decoder)?,
                previous_epoch_last_ledger_record_signed_digest: decode_digest(decoder)?,
                previous_epoch_last_ledger_record_payload_digest: decode_digest(decoder)?,
                restore_provenance: decode_optional_restore_provenance(decoder)?,
            },
        ))),
        _ => Err(DeploymentControlErrorV2::InvalidLedgerRecord),
    }
}

fn encode_optional_restore_provenance(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    value: Option<&BootstrapBridgeRestoreProvenanceV2>,
) -> Result<(), DeploymentControlErrorV2> {
    match value {
        None => {
            encoder
                .array(1)
                .and_then(|encoder| encoder.u16(0))
                .map_err(|_| DeploymentControlErrorV2::InvalidLedgerRecord)?;
        }
        Some(value) => {
            encoder
                .array(2)
                .and_then(|encoder| encoder.u16(1))
                .and_then(|encoder| encoder.array(4))
                .and_then(|encoder| {
                    encoder.bytes(value.bridge_genesis_ledger_record_signed_digest.as_bytes())
                })
                .and_then(|encoder| encoder.bytes(value.failed_transaction_id.as_bytes()))
                .and_then(|encoder| encoder.bytes(value.recovery_grant_id.as_bytes()))
                .and_then(|encoder| encoder.u16(value.restore_origin_phase as u16))
                .map_err(|_| DeploymentControlErrorV2::InvalidLedgerRecord)?;
        }
    }
    Ok(())
}

fn decode_optional_restore_provenance(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<Option<BootstrapBridgeRestoreProvenanceV2>, DeploymentControlErrorV2> {
    let length = decoder
        .array()
        .map_err(|_| DeploymentControlErrorV2::InvalidLedgerRecord)?;
    match (decode_u16(decoder)?, length) {
        (0, Some(1)) => Ok(None),
        (1, Some(2)) => {
            expect_array(decoder, 4)?;
            Ok(Some(BootstrapBridgeRestoreProvenanceV2 {
                bridge_genesis_ledger_record_signed_digest: decode_digest(decoder)?,
                failed_transaction_id: decode_nonce(decoder)?,
                recovery_grant_id: decode_digest(decoder)?,
                restore_origin_phase: decode_origin(decoder)?,
            }))
        }
        _ => Err(DeploymentControlErrorV2::InvalidLedgerRecord),
    }
}

fn encode_optional_nonce(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    value: Option<Nonce32V2>,
) -> Result<(), DeploymentControlErrorV2> {
    match value {
        None => encoder
            .array(1)
            .and_then(|encoder| encoder.u16(0))
            .map(|_| ())
            .map_err(|_| DeploymentControlErrorV2::InvalidLedgerRecord),
        Some(value) => encoder
            .array(2)
            .and_then(|encoder| encoder.u16(1))
            .and_then(|encoder| encoder.bytes(value.as_bytes()))
            .map(|_| ())
            .map_err(|_| DeploymentControlErrorV2::InvalidLedgerRecord),
    }
}

fn decode_optional_nonce(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<Option<Nonce32V2>, DeploymentControlErrorV2> {
    let length = decoder
        .array()
        .map_err(|_| DeploymentControlErrorV2::InvalidLedgerRecord)?;
    match (decode_u16(decoder)?, length) {
        (0, Some(1)) => Ok(None),
        (1, Some(2)) => decode_nonce(decoder).map(Some),
        _ => Err(DeploymentControlErrorV2::InvalidLedgerRecord),
    }
}

fn encode_optional_digest(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    value: Option<Digest32V2>,
) -> Result<(), DeploymentControlErrorV2> {
    match value {
        None => encoder
            .array(1)
            .and_then(|encoder| encoder.u16(0))
            .map(|_| ())
            .map_err(|_| DeploymentControlErrorV2::InvalidLedgerRecord),
        Some(value) => encoder
            .array(2)
            .and_then(|encoder| encoder.u16(1))
            .and_then(|encoder| encoder.bytes(value.as_bytes()))
            .map(|_| ())
            .map_err(|_| DeploymentControlErrorV2::InvalidLedgerRecord),
    }
}

fn decode_optional_digest(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<Option<Digest32V2>, DeploymentControlErrorV2> {
    let length = decoder
        .array()
        .map_err(|_| DeploymentControlErrorV2::InvalidLedgerRecord)?;
    match (decode_u16(decoder)?, length) {
        (0, Some(1)) => Ok(None),
        (1, Some(2)) => decode_digest(decoder).map(Some),
        _ => Err(DeploymentControlErrorV2::InvalidLedgerRecord),
    }
}

fn encode_optional_origin(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    value: Option<RollbackOriginPhaseV2>,
) -> Result<(), DeploymentControlErrorV2> {
    match value {
        None => encoder
            .array(1)
            .and_then(|encoder| encoder.u16(0))
            .map(|_| ())
            .map_err(|_| DeploymentControlErrorV2::InvalidLedgerRecord),
        Some(value) => encoder
            .array(2)
            .and_then(|encoder| encoder.u16(1))
            .and_then(|encoder| encoder.u16(value as u16))
            .map(|_| ())
            .map_err(|_| DeploymentControlErrorV2::InvalidLedgerRecord),
    }
}

fn decode_optional_origin(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<Option<RollbackOriginPhaseV2>, DeploymentControlErrorV2> {
    let length = decoder
        .array()
        .map_err(|_| DeploymentControlErrorV2::InvalidLedgerRecord)?;
    match (decode_u16(decoder)?, length) {
        (0, Some(1)) => Ok(None),
        (1, Some(2)) => decode_origin(decoder).map(Some),
        _ => Err(DeploymentControlErrorV2::InvalidLedgerRecord),
    }
}

fn encode_domain_signature(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    value: DomainSignatureV2,
) -> Result<(), DeploymentControlErrorV2> {
    encoder
        .array(4)
        .and_then(|encoder| encoder.u16(value.domain_tag))
        .and_then(|encoder| encoder.bytes(value.signer_key_id.as_bytes()))
        .and_then(|encoder| encoder.u64(value.signer_key_epoch))
        .and_then(|encoder| encoder.bytes(value.signature.as_bytes()))
        .map(|_| ())
        .map_err(|_| DeploymentControlErrorV2::InvalidLedgerRecord)
}

fn decode_domain_signature(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<DomainSignatureV2, DeploymentControlErrorV2> {
    expect_array(decoder, 4)?;
    Ok(DomainSignatureV2 {
        domain_tag: decode_u16(decoder)?,
        signer_key_id: decode_key_id(decoder)?,
        signer_key_epoch: decode_u64(decoder)?,
        signature: Ed25519SignatureV2::new(decode_fixed_bytes::<64>(decoder)?),
    })
}

fn decode_phase(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<DeploymentPhaseV2, DeploymentControlErrorV2> {
    match decode_u16(decoder)? {
        1 => Ok(DeploymentPhaseV2::Idle),
        2 => Ok(DeploymentPhaseV2::Prepared),
        3 => Ok(DeploymentPhaseV2::Armed),
        4 => Ok(DeploymentPhaseV2::Quiesced),
        5 => Ok(DeploymentPhaseV2::Installed),
        6 => Ok(DeploymentPhaseV2::Verified),
        7 => Ok(DeploymentPhaseV2::Committed),
        8 => Ok(DeploymentPhaseV2::Aborted),
        9 => Ok(DeploymentPhaseV2::RollbackPrepared),
        10 => Ok(DeploymentPhaseV2::RollbackInstalled),
        11 => Ok(DeploymentPhaseV2::RollbackVerified),
        12 => Ok(DeploymentPhaseV2::RolledBack),
        13 => Ok(DeploymentPhaseV2::FailedSafe),
        14 => Ok(DeploymentPhaseV2::BootstrapBridge),
        15 => Ok(DeploymentPhaseV2::BridgeRestorePrepared),
        16 => Ok(DeploymentPhaseV2::BridgeRestoreInstalled),
        17 => Ok(DeploymentPhaseV2::BridgeRestoreVerified),
        _ => Err(DeploymentControlErrorV2::InvalidLedgerRecord),
    }
}

fn decode_grant_state(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<RollbackGrantStateV2, DeploymentControlErrorV2> {
    match decode_u16(decoder)? {
        0 => Ok(RollbackGrantStateV2::None),
        1 => Ok(RollbackGrantStateV2::Prearmed),
        2 => Ok(RollbackGrantStateV2::Consuming),
        3 => Ok(RollbackGrantStateV2::Consumed),
        4 => Ok(RollbackGrantStateV2::Burned),
        _ => Err(DeploymentControlErrorV2::InvalidLedgerRecord),
    }
}

fn decode_origin(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<RollbackOriginPhaseV2, DeploymentControlErrorV2> {
    match decode_u16(decoder)? {
        1 => Ok(RollbackOriginPhaseV2::Armed),
        2 => Ok(RollbackOriginPhaseV2::Quiesced),
        3 => Ok(RollbackOriginPhaseV2::Installed),
        4 => Ok(RollbackOriginPhaseV2::Verified),
        _ => Err(DeploymentControlErrorV2::InvalidLedgerRecord),
    }
}

fn expect_array(
    decoder: &mut minicbor::Decoder<'_>,
    expected: u64,
) -> Result<(), DeploymentControlErrorV2> {
    if decoder
        .array()
        .map_err(|_| DeploymentControlErrorV2::InvalidLedgerRecord)?
        != Some(expected)
    {
        return Err(DeploymentControlErrorV2::InvalidLedgerRecord);
    }
    Ok(())
}

fn decode_u16(decoder: &mut minicbor::Decoder<'_>) -> Result<u16, DeploymentControlErrorV2> {
    decoder
        .u16()
        .map_err(|_| DeploymentControlErrorV2::InvalidLedgerRecord)
}

fn decode_u64(decoder: &mut minicbor::Decoder<'_>) -> Result<u64, DeploymentControlErrorV2> {
    decoder
        .u64()
        .map_err(|_| DeploymentControlErrorV2::InvalidLedgerRecord)
}

fn decode_fixed_bytes<const N: usize>(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<[u8; N], DeploymentControlErrorV2> {
    decoder
        .bytes()
        .map_err(|_| DeploymentControlErrorV2::InvalidLedgerRecord)?
        .try_into()
        .map_err(|_| DeploymentControlErrorV2::InvalidLedgerRecord)
}

fn decode_bounded_bytes(
    decoder: &mut minicbor::Decoder<'_>,
    maximum: usize,
) -> Result<Vec<u8>, DeploymentControlErrorV2> {
    let bytes = decoder
        .bytes()
        .map_err(|_| DeploymentControlErrorV2::InvalidLedgerSlot)?;
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(DeploymentControlErrorV2::InvalidLedgerSlot);
    }
    Ok(bytes.to_vec())
}

fn decode_digest(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<Digest32V2, DeploymentControlErrorV2> {
    Ok(Digest32V2::new(decode_fixed_bytes::<32>(decoder)?))
}

fn decode_nonce(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<Nonce32V2, DeploymentControlErrorV2> {
    Ok(Nonce32V2::new(decode_fixed_bytes::<32>(decoder)?))
}

fn decode_key_id(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<Ed25519KeyIdV2, DeploymentControlErrorV2> {
    Ok(Ed25519KeyIdV2::new(decode_fixed_bytes::<32>(decoder)?))
}

fn ledger_slot_checksum(slot_id: LedgerSlotIdV2, record_bytes: &[u8]) -> Digest32V2 {
    let mut hasher = Sha256::new();
    hasher.update(LEDGER_SLOT_CHECKSUM_DOMAIN_V2);
    hasher.update((slot_id as u16).to_be_bytes());
    hasher.update(record_bytes);
    Digest32V2::new(hasher.finalize().into())
}

fn domain_signature_input(domain_tag: u16, domain: &[u8], digest: Digest32V2) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_SIGNATURE_INPUT_V2);
    hasher.update(domain_tag.to_be_bytes());
    hasher.update(domain);
    hasher.update(digest.as_bytes());
    hasher.finalize().into()
}

fn hash_domain(domain: &[u8], bytes: &[u8]) -> Digest32V2 {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(bytes);
    Digest32V2::new(hasher.finalize().into())
}

fn require_nonzero(values: &[&[u8; 32]]) -> Result<(), DeploymentControlErrorV2> {
    if values.iter().any(|value| is_zero(value)) {
        return Err(DeploymentControlErrorV2::InvalidLedgerRecord);
    }
    Ok(())
}

fn is_zero<const N: usize>(bytes: &[u8; N]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;

    use super::*;

    #[test]
    fn bootstrap_bridge_activation_round_trips_its_restore_provenance() {
        let activation =
            ActiveActivationV2::BootstrapBridge(Box::new(BootstrapBridgeActivationV2 {
                maintenance_intent_signed_digest: Digest32V2::new([1; 32]),
                bridge_manifest_digest: Digest32V2::new([2; 32]),
                premaintenance_runtime_manifest_digest: Digest32V2::new([3; 32]),
                previous_installation_epoch: 4,
                previous_epoch_last_ledger_record_signed_digest: Digest32V2::new([5; 32]),
                previous_epoch_last_ledger_record_payload_digest: Digest32V2::new([6; 32]),
                restore_provenance: Some(BootstrapBridgeRestoreProvenanceV2 {
                    bridge_genesis_ledger_record_signed_digest: Digest32V2::new([7; 32]),
                    failed_transaction_id: Nonce32V2::new([8; 32]),
                    recovery_grant_id: Digest32V2::new([9; 32]),
                    restore_origin_phase: RollbackOriginPhaseV2::Installed,
                }),
            }));
        let mut encoder = minicbor::Encoder::new(Vec::new());
        encode_active_activation(&mut encoder, &activation).unwrap();
        let bytes = encoder.into_writer();
        let mut decoder = minicbor::Decoder::new(&bytes);

        assert_eq!(decode_active_activation(&mut decoder).unwrap(), activation);
        assert_eq!(decoder.position(), bytes.len());
    }

    #[test]
    fn idle_accepts_the_retained_consumed_rollback_activation_after_safe_abort() {
        let signing_key = SigningKey::from_bytes(&[0xa1; 32]);
        let record = DeploymentLedgerRecordV2::new_signed_for_test(
            Digest32V2::new([0xa2; 32]),
            3,
            4,
            Digest32V2::new([0xa3; 32]),
            DeploymentPhaseV2::Idle,
            None,
            false,
            5,
            RollbackGrantStateV2::None,
            None,
            1_783_000_001_100,
            0xa4,
            &signing_key,
        )
        .unwrap();
        let mut decoded = decode_record(record.canonical_bytes()).unwrap();
        decoded.active_activation = ActiveActivationV2::ConsumedRollback {
            failed_transaction_id: Nonce32V2::new([0xa5; 32]),
            rollback_grant_id: Digest32V2::new([0xa6; 32]),
        };

        decoded.validate_without_payload_and_signature().unwrap();
    }
}
