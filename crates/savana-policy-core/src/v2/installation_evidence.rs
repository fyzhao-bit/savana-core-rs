use savana_kernel_protocol::v2::{Digest32V2, Ed25519KeyIdV2, Ed25519SignatureV2};
use savana_platform_identity::{
    NativeDeploymentSignatureDomainV2, NativeDeploymentSignatureRequestV2,
    NativeDeploymentSigningAuthorityV2,
};
use sha2::{Digest as _, Sha256};

use super::{
    CommitAttestationV2, DeploymentActivationVerifierV2, DeploymentControlErrorV2,
    DeploymentFailureEvidenceV2, DeploymentHardLimitsV2, EvidenceGcCheckpointV2,
    RecoveryRollbackReadinessEvidenceV2, RollbackVerificationAttestationV2,
    RollbackVerificationEvidenceV2, StoreCompatibilityAttestationV2, TransitionAuditV2,
    VerificationEvidenceV2,
};

const COMPLETE_FIELDS_V2: u64 = 9;
const PAYLOAD_FIELDS_V2: u64 = 8;
const DOMAIN_SIGNATURE_FIELDS_V2: u64 = 4;
const INSTALLATION_EVIDENCE_ENVELOPE_SIGNATURE_TAG_V2: u16 = 22;
const INSTALLATION_EVIDENCE_ITEM_DOMAIN_V2: &[u8] = b"savana.installation-evidence.v2.item\0";
const INSTALLATION_EVIDENCE_PAYLOAD_DOMAIN_V2: &[u8] = b"savana.installation-evidence.v2.payload\0";
const INSTALLATION_EVIDENCE_SIGNED_DOMAIN_V2: &[u8] = b"savana.installation-evidence.v2.signed\0";
const INSTALLATION_EVIDENCE_SIGNATURE_DOMAIN_V2: &[u8] =
    b"savana.installation-evidence.v2.envelope\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u16)]
pub enum ClosedInstallationEvidenceKindV2 {
    TransitionAudit = 1,
    StoreCompatibility = 2,
    Verification = 3,
    Commit = 4,
    RollbackVerificationEvidence = 5,
    EvidenceGcCheckpoint = 6,
    RollbackVerificationAttestation = 7,
    RecoveryRollbackReadinessEvidence = 8,
    DeploymentFailure = 9,
}

impl ClosedInstallationEvidenceKindV2 {
    const fn from_tag(tag: u16) -> Option<Self> {
        match tag {
            1 => Some(Self::TransitionAudit),
            2 => Some(Self::StoreCompatibility),
            3 => Some(Self::Verification),
            4 => Some(Self::Commit),
            5 => Some(Self::RollbackVerificationEvidence),
            6 => Some(Self::EvidenceGcCheckpoint),
            7 => Some(Self::RollbackVerificationAttestation),
            8 => Some(Self::RecoveryRollbackReadinessEvidence),
            9 => Some(Self::DeploymentFailure),
            _ => None,
        }
    }

    const fn tag(self) -> u16 {
        self as u16
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EnvelopeSignatureV2 {
    domain_tag: u16,
    signer_key_id: Ed25519KeyIdV2,
    signer_key_epoch: u64,
    signature: Ed25519SignatureV2,
}

#[derive(Clone, PartialEq, Eq)]
pub struct InstallationEvidenceEnvelopeV2 {
    canonical_bytes: Vec<u8>,
    installation_id: Digest32V2,
    installation_epoch: u64,
    evidence_sequence: u64,
    previous_evidence_signed_digest: Option<Digest32V2>,
    evidence_kind: ClosedInstallationEvidenceKindV2,
    evidence_bytes: Vec<u8>,
    evidence_digest: Digest32V2,
    payload_digest: Digest32V2,
    signed_digest: Digest32V2,
    activation_key_id: Ed25519KeyIdV2,
}

impl std::fmt::Debug for InstallationEvidenceEnvelopeV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("InstallationEvidenceEnvelopeV2")
            .field("installation_epoch", &self.installation_epoch)
            .field("evidence_sequence", &self.evidence_sequence)
            .field("evidence_kind", &self.evidence_kind)
            .field("evidence_length", &self.evidence_bytes.len())
            .field("evidence_digest", &self.evidence_digest)
            .field("signed_digest", &self.signed_digest)
            .finish_non_exhaustive()
    }
}

impl InstallationEvidenceEnvelopeV2 {
    pub fn from_canonical_bytes(
        bytes: &[u8],
        verifier: &DeploymentActivationVerifierV2,
    ) -> Result<Self, DeploymentControlErrorV2> {
        let maximum = usize::try_from(DeploymentHardLimitsV2::compiled().max_attestation_bytes())
            .map_err(|_| DeploymentControlErrorV2::InvalidInstallationEvidenceEnvelope)?;
        if bytes.is_empty() || bytes.len() > maximum.saturating_add(1024) {
            return Err(DeploymentControlErrorV2::InvalidInstallationEvidenceEnvelope);
        }
        let decoded = decode_complete(bytes)?;
        decoded.validate_shape()?;
        if encode_complete(&decoded)? != bytes {
            return Err(DeploymentControlErrorV2::NonCanonicalLedgerEncoding);
        }
        if decoded.installation_id != verifier.installation_id()
            || decoded.installation_epoch != verifier.key_epoch()
        {
            return Err(DeploymentControlErrorV2::InstallationTupleMismatch);
        }
        if decoded.activation_key_id != verifier.key_id() {
            return Err(DeploymentControlErrorV2::ActivationKeyMismatch);
        }
        validate_typed_evidence(&decoded, verifier)?;
        let evidence_digest = evidence_item_digest(decoded.evidence_kind, &decoded.evidence_bytes);
        if decoded.evidence_digest != evidence_digest {
            return Err(DeploymentControlErrorV2::InvalidInstallationEvidenceEnvelope);
        }
        let payload_digest = hash_domain(
            INSTALLATION_EVIDENCE_PAYLOAD_DOMAIN_V2,
            &encode_payload(&decoded)?,
        );
        verifier.verify_domain_signature_parts(
            decoded.signature.domain_tag,
            decoded.signature.signer_key_id,
            decoded.signature.signer_key_epoch,
            decoded.signature.signature,
            INSTALLATION_EVIDENCE_ENVELOPE_SIGNATURE_TAG_V2,
            INSTALLATION_EVIDENCE_SIGNATURE_DOMAIN_V2,
            payload_digest,
        )?;
        let signed_digest = hash_domain(INSTALLATION_EVIDENCE_SIGNED_DOMAIN_V2, bytes);
        Ok(Self {
            canonical_bytes: bytes.to_vec(),
            installation_id: decoded.installation_id,
            installation_epoch: decoded.installation_epoch,
            evidence_sequence: decoded.evidence_sequence,
            previous_evidence_signed_digest: decoded.previous_evidence_signed_digest(),
            evidence_kind: decoded.evidence_kind,
            evidence_bytes: decoded.evidence_bytes,
            evidence_digest,
            payload_digest,
            signed_digest,
            activation_key_id: decoded.activation_key_id,
        })
    }

    pub fn new_gc_checkpoint_signed_with_authority(
        evidence_sequence: u64,
        previous_evidence_signed_digest: Option<Digest32V2>,
        checkpoint: &EvidenceGcCheckpointV2,
        authority: &mut dyn NativeDeploymentSigningAuthorityV2,
        verifier: &DeploymentActivationVerifierV2,
    ) -> Result<Self, DeploymentControlErrorV2> {
        let installation_id = checkpoint.installation_id();
        let installation_epoch = checkpoint.installation_epoch();
        let activation_key_id = Ed25519KeyIdV2::new(authority.key_id());
        if authority.installation_id() != *installation_id.as_bytes()
            || authority.key_epoch() != installation_epoch
            || verifier.installation_id() != installation_id
            || verifier.key_epoch() != installation_epoch
            || verifier.key_id() != activation_key_id
            || checkpoint.activation_key_id() != activation_key_id
        {
            return Err(DeploymentControlErrorV2::ActivationKeyMismatch);
        }
        EvidenceGcCheckpointV2::from_canonical_bytes(checkpoint.canonical_bytes(), verifier)?;
        let evidence_bytes = checkpoint.canonical_bytes().to_vec();
        let evidence_kind = ClosedInstallationEvidenceKindV2::EvidenceGcCheckpoint;
        let evidence_digest = evidence_item_digest(evidence_kind, &evidence_bytes);
        let mut decoded = DecodedInstallationEvidenceEnvelopeV2 {
            installation_id,
            installation_epoch,
            evidence_sequence,
            previous_evidence_digest: previous_evidence_signed_digest
                .unwrap_or(Digest32V2::new([0; 32])),
            evidence_kind,
            evidence_bytes,
            evidence_digest,
            activation_key_id,
            signature: EnvelopeSignatureV2 {
                domain_tag: INSTALLATION_EVIDENCE_ENVELOPE_SIGNATURE_TAG_V2,
                signer_key_id: activation_key_id,
                signer_key_epoch: installation_epoch,
                signature: Ed25519SignatureV2::new([1; 64]),
            },
        };
        decoded.validate_shape()?;
        let payload_digest = hash_domain(
            INSTALLATION_EVIDENCE_PAYLOAD_DOMAIN_V2,
            &encode_payload(&decoded)?,
        );
        let request = NativeDeploymentSignatureRequestV2::new(
            NativeDeploymentSignatureDomainV2::InstallationEvidenceEnvelope,
            *installation_id.as_bytes(),
            installation_epoch,
            *payload_digest.as_bytes(),
        )
        .map_err(|_| DeploymentControlErrorV2::NativeSigningAuthorityUnavailable)?;
        decoded.signature.signature = Ed25519SignatureV2::new(
            authority
                .sign(request)
                .map_err(|_| DeploymentControlErrorV2::NativeSigningAuthorityUnavailable)?,
        );
        Self::from_canonical_bytes(&encode_complete(&decoded)?, verifier)
    }

    pub fn new_transition_audit_signed_with_authority(
        evidence_sequence: u64,
        previous_evidence_signed_digest: Option<Digest32V2>,
        audit: &TransitionAuditV2,
        authority: &mut dyn NativeDeploymentSigningAuthorityV2,
        verifier: &DeploymentActivationVerifierV2,
    ) -> Result<Self, DeploymentControlErrorV2> {
        let audit = TransitionAuditV2::from_canonical_bytes(audit.canonical_bytes())?;
        Self::new_typed_signed_with_authority(
            evidence_sequence,
            previous_evidence_signed_digest,
            audit.installation_id(),
            audit.installation_epoch(),
            verifier.key_id(),
            ClosedInstallationEvidenceKindV2::TransitionAudit,
            audit.canonical_bytes(),
            authority,
            verifier,
        )
    }

    pub fn new_deployment_failure_signed_with_authority(
        evidence_sequence: u64,
        previous_evidence_signed_digest: Option<Digest32V2>,
        failure: &DeploymentFailureEvidenceV2,
        authority: &mut dyn NativeDeploymentSigningAuthorityV2,
        verifier: &DeploymentActivationVerifierV2,
    ) -> Result<Self, DeploymentControlErrorV2> {
        let installation_id = failure.installation_id();
        let installation_epoch = failure.installation_epoch();
        let activation_key_id = Ed25519KeyIdV2::new(authority.key_id());
        if authority.installation_id() != *installation_id.as_bytes()
            || authority.key_epoch() != installation_epoch
            || verifier.installation_id() != installation_id
            || verifier.key_epoch() != installation_epoch
            || verifier.key_id() != activation_key_id
        {
            return Err(DeploymentControlErrorV2::ActivationKeyMismatch);
        }
        let failure = DeploymentFailureEvidenceV2::from_canonical_bytes(failure.canonical_bytes())?;
        let evidence_bytes = failure.canonical_bytes().to_vec();
        let evidence_kind = ClosedInstallationEvidenceKindV2::DeploymentFailure;
        let evidence_digest = evidence_item_digest(evidence_kind, &evidence_bytes);
        let mut decoded = DecodedInstallationEvidenceEnvelopeV2 {
            installation_id,
            installation_epoch,
            evidence_sequence,
            previous_evidence_digest: previous_evidence_signed_digest
                .unwrap_or(Digest32V2::new([0; 32])),
            evidence_kind,
            evidence_bytes,
            evidence_digest,
            activation_key_id,
            signature: EnvelopeSignatureV2 {
                domain_tag: INSTALLATION_EVIDENCE_ENVELOPE_SIGNATURE_TAG_V2,
                signer_key_id: activation_key_id,
                signer_key_epoch: installation_epoch,
                signature: Ed25519SignatureV2::new([1; 64]),
            },
        };
        decoded.validate_shape()?;
        let payload_digest = hash_domain(
            INSTALLATION_EVIDENCE_PAYLOAD_DOMAIN_V2,
            &encode_payload(&decoded)?,
        );
        let request = NativeDeploymentSignatureRequestV2::new(
            NativeDeploymentSignatureDomainV2::InstallationEvidenceEnvelope,
            *installation_id.as_bytes(),
            installation_epoch,
            *payload_digest.as_bytes(),
        )
        .map_err(|_| DeploymentControlErrorV2::NativeSigningAuthorityUnavailable)?;
        decoded.signature.signature = Ed25519SignatureV2::new(
            authority
                .sign(request)
                .map_err(|_| DeploymentControlErrorV2::NativeSigningAuthorityUnavailable)?,
        );
        Self::from_canonical_bytes(&encode_complete(&decoded)?, verifier)
    }

    pub fn new_store_compatibility_signed_with_authority(
        evidence_sequence: u64,
        previous_evidence_signed_digest: Option<Digest32V2>,
        attestation: &StoreCompatibilityAttestationV2,
        authority: &mut dyn NativeDeploymentSigningAuthorityV2,
        verifier: &DeploymentActivationVerifierV2,
    ) -> Result<Self, DeploymentControlErrorV2> {
        let installation_id = attestation.installation_id();
        let installation_epoch = attestation.installation_epoch();
        let activation_key_id = Ed25519KeyIdV2::new(authority.key_id());
        if authority.installation_id() != *installation_id.as_bytes()
            || authority.key_epoch() != installation_epoch
            || verifier.installation_id() != installation_id
            || verifier.key_epoch() != installation_epoch
            || verifier.key_id() != activation_key_id
            || attestation.activation_key_id() != activation_key_id
        {
            return Err(DeploymentControlErrorV2::ActivationKeyMismatch);
        }
        let attestation = StoreCompatibilityAttestationV2::from_canonical_bytes(
            attestation.canonical_bytes(),
            verifier,
        )?;
        let evidence_bytes = attestation.canonical_bytes().to_vec();
        let evidence_kind = ClosedInstallationEvidenceKindV2::StoreCompatibility;
        let evidence_digest = evidence_item_digest(evidence_kind, &evidence_bytes);
        let mut decoded = DecodedInstallationEvidenceEnvelopeV2 {
            installation_id,
            installation_epoch,
            evidence_sequence,
            previous_evidence_digest: previous_evidence_signed_digest
                .unwrap_or(Digest32V2::new([0; 32])),
            evidence_kind,
            evidence_bytes,
            evidence_digest,
            activation_key_id,
            signature: EnvelopeSignatureV2 {
                domain_tag: INSTALLATION_EVIDENCE_ENVELOPE_SIGNATURE_TAG_V2,
                signer_key_id: activation_key_id,
                signer_key_epoch: installation_epoch,
                signature: Ed25519SignatureV2::new([1; 64]),
            },
        };
        decoded.validate_shape()?;
        let payload_digest = hash_domain(
            INSTALLATION_EVIDENCE_PAYLOAD_DOMAIN_V2,
            &encode_payload(&decoded)?,
        );
        let request = NativeDeploymentSignatureRequestV2::new(
            NativeDeploymentSignatureDomainV2::InstallationEvidenceEnvelope,
            *installation_id.as_bytes(),
            installation_epoch,
            *payload_digest.as_bytes(),
        )
        .map_err(|_| DeploymentControlErrorV2::NativeSigningAuthorityUnavailable)?;
        decoded.signature.signature = Ed25519SignatureV2::new(
            authority
                .sign(request)
                .map_err(|_| DeploymentControlErrorV2::NativeSigningAuthorityUnavailable)?,
        );
        Self::from_canonical_bytes(&encode_complete(&decoded)?, verifier)
    }

    pub fn new_verification_signed_with_authority(
        evidence_sequence: u64,
        previous_evidence_signed_digest: Option<Digest32V2>,
        evidence: &VerificationEvidenceV2,
        authority: &mut dyn NativeDeploymentSigningAuthorityV2,
        verifier: &DeploymentActivationVerifierV2,
    ) -> Result<Self, DeploymentControlErrorV2> {
        let installation_id = evidence.installation_id();
        let installation_epoch = evidence.installation_epoch();
        let activation_key_id = Ed25519KeyIdV2::new(authority.key_id());
        if authority.installation_id() != *installation_id.as_bytes()
            || authority.key_epoch() != installation_epoch
            || verifier.installation_id() != installation_id
            || verifier.key_epoch() != installation_epoch
            || verifier.key_id() != activation_key_id
            || evidence.activation_key_id() != activation_key_id
        {
            return Err(DeploymentControlErrorV2::ActivationKeyMismatch);
        }
        let evidence =
            VerificationEvidenceV2::from_canonical_bytes(evidence.canonical_bytes(), verifier)?;
        let evidence_bytes = evidence.canonical_bytes().to_vec();
        let evidence_kind = ClosedInstallationEvidenceKindV2::Verification;
        let evidence_digest = evidence_item_digest(evidence_kind, &evidence_bytes);
        let mut decoded = DecodedInstallationEvidenceEnvelopeV2 {
            installation_id,
            installation_epoch,
            evidence_sequence,
            previous_evidence_digest: previous_evidence_signed_digest
                .unwrap_or(Digest32V2::new([0; 32])),
            evidence_kind,
            evidence_bytes,
            evidence_digest,
            activation_key_id,
            signature: EnvelopeSignatureV2 {
                domain_tag: INSTALLATION_EVIDENCE_ENVELOPE_SIGNATURE_TAG_V2,
                signer_key_id: activation_key_id,
                signer_key_epoch: installation_epoch,
                signature: Ed25519SignatureV2::new([1; 64]),
            },
        };
        decoded.validate_shape()?;
        let payload_digest = hash_domain(
            INSTALLATION_EVIDENCE_PAYLOAD_DOMAIN_V2,
            &encode_payload(&decoded)?,
        );
        let request = NativeDeploymentSignatureRequestV2::new(
            NativeDeploymentSignatureDomainV2::InstallationEvidenceEnvelope,
            *installation_id.as_bytes(),
            installation_epoch,
            *payload_digest.as_bytes(),
        )
        .map_err(|_| DeploymentControlErrorV2::NativeSigningAuthorityUnavailable)?;
        decoded.signature.signature = Ed25519SignatureV2::new(
            authority
                .sign(request)
                .map_err(|_| DeploymentControlErrorV2::NativeSigningAuthorityUnavailable)?,
        );
        Self::from_canonical_bytes(&encode_complete(&decoded)?, verifier)
    }

    pub fn new_commit_signed_with_authority(
        evidence_sequence: u64,
        previous_evidence_signed_digest: Option<Digest32V2>,
        attestation: &CommitAttestationV2,
        authority: &mut dyn NativeDeploymentSigningAuthorityV2,
        verifier: &DeploymentActivationVerifierV2,
    ) -> Result<Self, DeploymentControlErrorV2> {
        let attestation =
            CommitAttestationV2::from_canonical_bytes(attestation.canonical_bytes(), verifier)?;
        Self::new_typed_signed_with_authority(
            evidence_sequence,
            previous_evidence_signed_digest,
            attestation.installation_id(),
            attestation.installation_epoch(),
            attestation.activation_key_id(),
            ClosedInstallationEvidenceKindV2::Commit,
            attestation.canonical_bytes(),
            authority,
            verifier,
        )
    }

    pub fn new_rollback_verification_evidence_signed_with_authority(
        evidence_sequence: u64,
        previous_evidence_signed_digest: Option<Digest32V2>,
        evidence: &RollbackVerificationEvidenceV2,
        authority: &mut dyn NativeDeploymentSigningAuthorityV2,
        verifier: &DeploymentActivationVerifierV2,
    ) -> Result<Self, DeploymentControlErrorV2> {
        let evidence = RollbackVerificationEvidenceV2::from_canonical_bytes(
            evidence.canonical_bytes(),
            verifier,
        )?;
        Self::new_typed_signed_with_authority(
            evidence_sequence,
            previous_evidence_signed_digest,
            evidence.installation_id(),
            evidence.installation_epoch(),
            evidence.activation_key_id(),
            ClosedInstallationEvidenceKindV2::RollbackVerificationEvidence,
            evidence.canonical_bytes(),
            authority,
            verifier,
        )
    }

    pub fn new_recovery_rollback_readiness_signed_with_authority(
        evidence_sequence: u64,
        previous_evidence_signed_digest: Option<Digest32V2>,
        evidence: &RecoveryRollbackReadinessEvidenceV2,
        authority: &mut dyn NativeDeploymentSigningAuthorityV2,
        verifier: &DeploymentActivationVerifierV2,
    ) -> Result<Self, DeploymentControlErrorV2> {
        let evidence = RecoveryRollbackReadinessEvidenceV2::from_canonical_bytes(
            evidence.canonical_bytes(),
            verifier,
        )?;
        Self::new_typed_signed_with_authority(
            evidence_sequence,
            previous_evidence_signed_digest,
            evidence.installation_id(),
            evidence.installation_epoch(),
            evidence.activation_key_id(),
            ClosedInstallationEvidenceKindV2::RecoveryRollbackReadinessEvidence,
            evidence.canonical_bytes(),
            authority,
            verifier,
        )
    }

    pub fn new_rollback_verification_attestation_signed_with_authority(
        evidence_sequence: u64,
        previous_evidence_signed_digest: Option<Digest32V2>,
        attestation: &RollbackVerificationAttestationV2,
        authority: &mut dyn NativeDeploymentSigningAuthorityV2,
        verifier: &DeploymentActivationVerifierV2,
    ) -> Result<Self, DeploymentControlErrorV2> {
        let attestation = RollbackVerificationAttestationV2::from_canonical_bytes(
            attestation.canonical_bytes(),
            verifier,
        )?;
        Self::new_typed_signed_with_authority(
            evidence_sequence,
            previous_evidence_signed_digest,
            attestation.installation_id(),
            attestation.installation_epoch(),
            attestation.activation_key_id(),
            ClosedInstallationEvidenceKindV2::RollbackVerificationAttestation,
            attestation.canonical_bytes(),
            authority,
            verifier,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new_typed_signed_with_authority(
        evidence_sequence: u64,
        previous_evidence_signed_digest: Option<Digest32V2>,
        installation_id: Digest32V2,
        installation_epoch: u64,
        evidence_activation_key_id: Ed25519KeyIdV2,
        evidence_kind: ClosedInstallationEvidenceKindV2,
        evidence_bytes: &[u8],
        authority: &mut dyn NativeDeploymentSigningAuthorityV2,
        verifier: &DeploymentActivationVerifierV2,
    ) -> Result<Self, DeploymentControlErrorV2> {
        let activation_key_id = Ed25519KeyIdV2::new(authority.key_id());
        if authority.installation_id() != *installation_id.as_bytes()
            || authority.key_epoch() != installation_epoch
            || verifier.installation_id() != installation_id
            || verifier.key_epoch() != installation_epoch
            || verifier.key_id() != activation_key_id
            || evidence_activation_key_id != activation_key_id
        {
            return Err(DeploymentControlErrorV2::ActivationKeyMismatch);
        }
        let evidence_bytes = evidence_bytes.to_vec();
        let evidence_digest = evidence_item_digest(evidence_kind, &evidence_bytes);
        let mut decoded = DecodedInstallationEvidenceEnvelopeV2 {
            installation_id,
            installation_epoch,
            evidence_sequence,
            previous_evidence_digest: previous_evidence_signed_digest
                .unwrap_or(Digest32V2::new([0; 32])),
            evidence_kind,
            evidence_bytes,
            evidence_digest,
            activation_key_id,
            signature: EnvelopeSignatureV2 {
                domain_tag: INSTALLATION_EVIDENCE_ENVELOPE_SIGNATURE_TAG_V2,
                signer_key_id: activation_key_id,
                signer_key_epoch: installation_epoch,
                signature: Ed25519SignatureV2::new([1; 64]),
            },
        };
        decoded.validate_shape()?;
        let payload_digest = hash_domain(
            INSTALLATION_EVIDENCE_PAYLOAD_DOMAIN_V2,
            &encode_payload(&decoded)?,
        );
        let request = NativeDeploymentSignatureRequestV2::new(
            NativeDeploymentSignatureDomainV2::InstallationEvidenceEnvelope,
            *installation_id.as_bytes(),
            installation_epoch,
            *payload_digest.as_bytes(),
        )
        .map_err(|_| DeploymentControlErrorV2::NativeSigningAuthorityUnavailable)?;
        decoded.signature.signature = Ed25519SignatureV2::new(
            authority
                .sign(request)
                .map_err(|_| DeploymentControlErrorV2::NativeSigningAuthorityUnavailable)?,
        );
        Self::from_canonical_bytes(&encode_complete(&decoded)?, verifier)
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub const fn installation_id(&self) -> Digest32V2 {
        self.installation_id
    }

    pub const fn installation_epoch(&self) -> u64 {
        self.installation_epoch
    }

    pub const fn evidence_sequence(&self) -> u64 {
        self.evidence_sequence
    }

    pub const fn previous_evidence_signed_digest(&self) -> Option<Digest32V2> {
        self.previous_evidence_signed_digest
    }

    pub const fn evidence_kind(&self) -> ClosedInstallationEvidenceKindV2 {
        self.evidence_kind
    }

    pub fn evidence_bytes(&self) -> &[u8] {
        &self.evidence_bytes
    }

    pub const fn evidence_digest(&self) -> Digest32V2 {
        self.evidence_digest
    }

    pub const fn payload_digest(&self) -> Digest32V2 {
        self.payload_digest
    }

    pub const fn signed_digest(&self) -> Digest32V2 {
        self.signed_digest
    }

    pub const fn activation_key_id(&self) -> Ed25519KeyIdV2 {
        self.activation_key_id
    }

    pub fn evidence_gc_checkpoint(
        &self,
        verifier: &DeploymentActivationVerifierV2,
    ) -> Result<EvidenceGcCheckpointV2, DeploymentControlErrorV2> {
        if self.evidence_kind != ClosedInstallationEvidenceKindV2::EvidenceGcCheckpoint {
            return Err(DeploymentControlErrorV2::InvalidInstallationEvidenceEnvelope);
        }
        let checkpoint =
            EvidenceGcCheckpointV2::from_canonical_bytes(&self.evidence_bytes, verifier)?;
        if checkpoint.installation_id() != self.installation_id
            || checkpoint.installation_epoch() != self.installation_epoch
            || checkpoint.activation_key_id() != self.activation_key_id
        {
            return Err(DeploymentControlErrorV2::InvalidInstallationEvidenceEnvelope);
        }
        Ok(checkpoint)
    }

    pub fn transition_audit(&self) -> Result<TransitionAuditV2, DeploymentControlErrorV2> {
        if self.evidence_kind != ClosedInstallationEvidenceKindV2::TransitionAudit {
            return Err(DeploymentControlErrorV2::InvalidInstallationEvidenceEnvelope);
        }
        let audit = TransitionAuditV2::from_canonical_bytes(&self.evidence_bytes)?;
        if audit.installation_id() != self.installation_id
            || audit.installation_epoch() != self.installation_epoch
        {
            return Err(DeploymentControlErrorV2::InvalidInstallationEvidenceEnvelope);
        }
        Ok(audit)
    }

    pub fn deployment_failure_evidence(
        &self,
    ) -> Result<DeploymentFailureEvidenceV2, DeploymentControlErrorV2> {
        if self.evidence_kind != ClosedInstallationEvidenceKindV2::DeploymentFailure {
            return Err(DeploymentControlErrorV2::InvalidInstallationEvidenceEnvelope);
        }
        let failure = DeploymentFailureEvidenceV2::from_canonical_bytes(&self.evidence_bytes)?;
        if failure.installation_id() != self.installation_id
            || failure.installation_epoch() != self.installation_epoch
        {
            return Err(DeploymentControlErrorV2::InvalidInstallationEvidenceEnvelope);
        }
        Ok(failure)
    }

    pub fn store_compatibility_attestation(
        &self,
        verifier: &DeploymentActivationVerifierV2,
    ) -> Result<StoreCompatibilityAttestationV2, DeploymentControlErrorV2> {
        if self.evidence_kind != ClosedInstallationEvidenceKindV2::StoreCompatibility {
            return Err(DeploymentControlErrorV2::InvalidInstallationEvidenceEnvelope);
        }
        let attestation =
            StoreCompatibilityAttestationV2::from_canonical_bytes(&self.evidence_bytes, verifier)?;
        if attestation.installation_id() != self.installation_id
            || attestation.installation_epoch() != self.installation_epoch
            || attestation.activation_key_id() != self.activation_key_id
        {
            return Err(DeploymentControlErrorV2::InvalidInstallationEvidenceEnvelope);
        }
        Ok(attestation)
    }

    pub fn verification_evidence(
        &self,
        verifier: &DeploymentActivationVerifierV2,
    ) -> Result<VerificationEvidenceV2, DeploymentControlErrorV2> {
        if self.evidence_kind != ClosedInstallationEvidenceKindV2::Verification {
            return Err(DeploymentControlErrorV2::InvalidInstallationEvidenceEnvelope);
        }
        let evidence =
            VerificationEvidenceV2::from_canonical_bytes(&self.evidence_bytes, verifier)?;
        if evidence.installation_id() != self.installation_id
            || evidence.installation_epoch() != self.installation_epoch
            || evidence.activation_key_id() != self.activation_key_id
        {
            return Err(DeploymentControlErrorV2::InvalidInstallationEvidenceEnvelope);
        }
        Ok(evidence)
    }

    pub fn commit_attestation(
        &self,
        verifier: &DeploymentActivationVerifierV2,
    ) -> Result<CommitAttestationV2, DeploymentControlErrorV2> {
        if self.evidence_kind != ClosedInstallationEvidenceKindV2::Commit {
            return Err(DeploymentControlErrorV2::InvalidInstallationEvidenceEnvelope);
        }
        let attestation =
            CommitAttestationV2::from_canonical_bytes(&self.evidence_bytes, verifier)?;
        if attestation.installation_id() != self.installation_id
            || attestation.installation_epoch() != self.installation_epoch
            || attestation.activation_key_id() != self.activation_key_id
        {
            return Err(DeploymentControlErrorV2::InvalidInstallationEvidenceEnvelope);
        }
        Ok(attestation)
    }

    pub fn rollback_verification_evidence(
        &self,
        verifier: &DeploymentActivationVerifierV2,
    ) -> Result<RollbackVerificationEvidenceV2, DeploymentControlErrorV2> {
        if self.evidence_kind != ClosedInstallationEvidenceKindV2::RollbackVerificationEvidence {
            return Err(DeploymentControlErrorV2::InvalidInstallationEvidenceEnvelope);
        }
        let evidence =
            RollbackVerificationEvidenceV2::from_canonical_bytes(&self.evidence_bytes, verifier)?;
        if evidence.installation_id() != self.installation_id
            || evidence.installation_epoch() != self.installation_epoch
            || evidence.activation_key_id() != self.activation_key_id
        {
            return Err(DeploymentControlErrorV2::InvalidInstallationEvidenceEnvelope);
        }
        Ok(evidence)
    }

    pub fn recovery_rollback_readiness_evidence(
        &self,
        verifier: &DeploymentActivationVerifierV2,
    ) -> Result<RecoveryRollbackReadinessEvidenceV2, DeploymentControlErrorV2> {
        if self.evidence_kind != ClosedInstallationEvidenceKindV2::RecoveryRollbackReadinessEvidence
        {
            return Err(DeploymentControlErrorV2::InvalidInstallationEvidenceEnvelope);
        }
        let evidence = RecoveryRollbackReadinessEvidenceV2::from_canonical_bytes(
            &self.evidence_bytes,
            verifier,
        )?;
        if evidence.installation_id() != self.installation_id
            || evidence.installation_epoch() != self.installation_epoch
            || evidence.activation_key_id() != self.activation_key_id
        {
            return Err(DeploymentControlErrorV2::InvalidInstallationEvidenceEnvelope);
        }
        Ok(evidence)
    }

    pub fn rollback_verification_attestation(
        &self,
        verifier: &DeploymentActivationVerifierV2,
    ) -> Result<RollbackVerificationAttestationV2, DeploymentControlErrorV2> {
        if self.evidence_kind != ClosedInstallationEvidenceKindV2::RollbackVerificationAttestation {
            return Err(DeploymentControlErrorV2::InvalidInstallationEvidenceEnvelope);
        }
        let attestation = RollbackVerificationAttestationV2::from_canonical_bytes(
            &self.evidence_bytes,
            verifier,
        )?;
        if attestation.installation_id() != self.installation_id
            || attestation.installation_epoch() != self.installation_epoch
            || attestation.activation_key_id() != self.activation_key_id
        {
            return Err(DeploymentControlErrorV2::InvalidInstallationEvidenceEnvelope);
        }
        Ok(attestation)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DecodedInstallationEvidenceEnvelopeV2 {
    installation_id: Digest32V2,
    installation_epoch: u64,
    evidence_sequence: u64,
    previous_evidence_digest: Digest32V2,
    evidence_kind: ClosedInstallationEvidenceKindV2,
    evidence_bytes: Vec<u8>,
    evidence_digest: Digest32V2,
    activation_key_id: Ed25519KeyIdV2,
    signature: EnvelopeSignatureV2,
}

impl DecodedInstallationEvidenceEnvelopeV2 {
    fn validate_shape(&self) -> Result<(), DeploymentControlErrorV2> {
        let maximum = usize::try_from(DeploymentHardLimitsV2::compiled().max_attestation_bytes())
            .map_err(|_| DeploymentControlErrorV2::InvalidInstallationEvidenceEnvelope)?;
        if self.installation_epoch == 0
            || self.evidence_sequence == 0
            || self.evidence_bytes.is_empty()
            || self.evidence_bytes.len() > maximum
            || is_zero(self.installation_id.as_bytes())
            || is_zero(self.evidence_digest.as_bytes())
            || is_zero(self.activation_key_id.as_bytes())
            || (self.evidence_sequence == 1) != is_zero(self.previous_evidence_digest.as_bytes())
            || self.signature.domain_tag != INSTALLATION_EVIDENCE_ENVELOPE_SIGNATURE_TAG_V2
            || self.signature.signer_key_id != self.activation_key_id
            || self.signature.signer_key_epoch != self.installation_epoch
            || is_zero(self.signature.signature.as_bytes())
        {
            return Err(DeploymentControlErrorV2::InvalidInstallationEvidenceEnvelope);
        }
        Ok(())
    }

    fn previous_evidence_signed_digest(&self) -> Option<Digest32V2> {
        (!is_zero(self.previous_evidence_digest.as_bytes()))
            .then_some(self.previous_evidence_digest)
    }
}

fn validate_typed_evidence(
    decoded: &DecodedInstallationEvidenceEnvelopeV2,
    verifier: &DeploymentActivationVerifierV2,
) -> Result<(), DeploymentControlErrorV2> {
    match decoded.evidence_kind {
        ClosedInstallationEvidenceKindV2::TransitionAudit => {
            let audit = TransitionAuditV2::from_canonical_bytes(&decoded.evidence_bytes)?;
            if audit.installation_id() != decoded.installation_id
                || audit.installation_epoch() != decoded.installation_epoch
            {
                return Err(DeploymentControlErrorV2::InvalidInstallationEvidenceEnvelope);
            }
            Ok(())
        }
        ClosedInstallationEvidenceKindV2::StoreCompatibility => {
            let attestation = StoreCompatibilityAttestationV2::from_canonical_bytes(
                &decoded.evidence_bytes,
                verifier,
            )?;
            if attestation.installation_id() != decoded.installation_id
                || attestation.installation_epoch() != decoded.installation_epoch
                || attestation.activation_key_id() != decoded.activation_key_id
            {
                return Err(DeploymentControlErrorV2::InvalidInstallationEvidenceEnvelope);
            }
            Ok(())
        }
        ClosedInstallationEvidenceKindV2::Verification => {
            let evidence =
                VerificationEvidenceV2::from_canonical_bytes(&decoded.evidence_bytes, verifier)?;
            if evidence.installation_id() != decoded.installation_id
                || evidence.installation_epoch() != decoded.installation_epoch
                || evidence.activation_key_id() != decoded.activation_key_id
            {
                return Err(DeploymentControlErrorV2::InvalidInstallationEvidenceEnvelope);
            }
            Ok(())
        }
        ClosedInstallationEvidenceKindV2::Commit => {
            let attestation =
                CommitAttestationV2::from_canonical_bytes(&decoded.evidence_bytes, verifier)?;
            if attestation.installation_id() != decoded.installation_id
                || attestation.installation_epoch() != decoded.installation_epoch
                || attestation.activation_key_id() != decoded.activation_key_id
            {
                return Err(DeploymentControlErrorV2::InvalidInstallationEvidenceEnvelope);
            }
            Ok(())
        }
        ClosedInstallationEvidenceKindV2::RollbackVerificationEvidence => {
            let evidence = RollbackVerificationEvidenceV2::from_canonical_bytes(
                &decoded.evidence_bytes,
                verifier,
            )?;
            if evidence.installation_id() != decoded.installation_id
                || evidence.installation_epoch() != decoded.installation_epoch
                || evidence.activation_key_id() != decoded.activation_key_id
            {
                return Err(DeploymentControlErrorV2::InvalidInstallationEvidenceEnvelope);
            }
            Ok(())
        }
        ClosedInstallationEvidenceKindV2::RecoveryRollbackReadinessEvidence => {
            let evidence = RecoveryRollbackReadinessEvidenceV2::from_canonical_bytes(
                &decoded.evidence_bytes,
                verifier,
            )?;
            if evidence.installation_id() != decoded.installation_id
                || evidence.installation_epoch() != decoded.installation_epoch
                || evidence.activation_key_id() != decoded.activation_key_id
            {
                return Err(DeploymentControlErrorV2::InvalidInstallationEvidenceEnvelope);
            }
            Ok(())
        }
        ClosedInstallationEvidenceKindV2::RollbackVerificationAttestation => {
            let attestation = RollbackVerificationAttestationV2::from_canonical_bytes(
                &decoded.evidence_bytes,
                verifier,
            )?;
            if attestation.installation_id() != decoded.installation_id
                || attestation.installation_epoch() != decoded.installation_epoch
                || attestation.activation_key_id() != decoded.activation_key_id
            {
                return Err(DeploymentControlErrorV2::InvalidInstallationEvidenceEnvelope);
            }
            Ok(())
        }
        ClosedInstallationEvidenceKindV2::EvidenceGcCheckpoint => {
            let checkpoint =
                EvidenceGcCheckpointV2::from_canonical_bytes(&decoded.evidence_bytes, verifier)?;
            if checkpoint.installation_id() != decoded.installation_id
                || checkpoint.installation_epoch() != decoded.installation_epoch
                || checkpoint.activation_key_id() != decoded.activation_key_id
            {
                return Err(DeploymentControlErrorV2::InvalidInstallationEvidenceEnvelope);
            }
            Ok(())
        }
        ClosedInstallationEvidenceKindV2::DeploymentFailure => {
            let failure =
                DeploymentFailureEvidenceV2::from_canonical_bytes(&decoded.evidence_bytes)?;
            if failure.installation_id() != decoded.installation_id
                || failure.installation_epoch() != decoded.installation_epoch
            {
                return Err(DeploymentControlErrorV2::InvalidInstallationEvidenceEnvelope);
            }
            Ok(())
        }
    }
}

fn evidence_item_digest(
    kind: ClosedInstallationEvidenceKindV2,
    evidence_bytes: &[u8],
) -> Digest32V2 {
    let mut hash = Sha256::new();
    hash.update(INSTALLATION_EVIDENCE_ITEM_DOMAIN_V2);
    hash.update(kind.tag().to_be_bytes());
    hash.update(evidence_bytes);
    Digest32V2::new(hash.finalize().into())
}

fn hash_domain(domain: &[u8], bytes: &[u8]) -> Digest32V2 {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(bytes);
    Digest32V2::new(hash.finalize().into())
}

fn decode_complete(
    bytes: &[u8],
) -> Result<DecodedInstallationEvidenceEnvelopeV2, DeploymentControlErrorV2> {
    let mut decoder = minicbor::Decoder::new(bytes);
    expect_array(&mut decoder, COMPLETE_FIELDS_V2)?;
    let installation_id = decode_digest(&mut decoder)?;
    let installation_epoch = decode_u64(&mut decoder)?;
    let evidence_sequence = decode_u64(&mut decoder)?;
    let previous_evidence_digest = decode_digest(&mut decoder)?;
    let evidence_kind = ClosedInstallationEvidenceKindV2::from_tag(decode_u16(&mut decoder)?)
        .ok_or(DeploymentControlErrorV2::InvalidInstallationEvidenceEnvelope)?;
    let evidence_bytes = decoder
        .bytes()
        .map_err(|_| DeploymentControlErrorV2::InvalidInstallationEvidenceEnvelope)?
        .to_vec();
    let evidence_digest = decode_digest(&mut decoder)?;
    let activation_key_id = decode_key_id(&mut decoder)?;
    let signature = decode_signature(&mut decoder)?;
    if decoder.position() != bytes.len() {
        return Err(DeploymentControlErrorV2::InvalidInstallationEvidenceEnvelope);
    }
    Ok(DecodedInstallationEvidenceEnvelopeV2 {
        installation_id,
        installation_epoch,
        evidence_sequence,
        previous_evidence_digest,
        evidence_kind,
        evidence_bytes,
        evidence_digest,
        activation_key_id,
        signature,
    })
}

fn encode_payload(
    decoded: &DecodedInstallationEvidenceEnvelopeV2,
) -> Result<Vec<u8>, DeploymentControlErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(PAYLOAD_FIELDS_V2)
        .map_err(|_| DeploymentControlErrorV2::InvalidInstallationEvidenceEnvelope)?;
    encode_preceding_fields(&mut encoder, decoded)?;
    Ok(encoder.into_writer())
}

fn encode_complete(
    decoded: &DecodedInstallationEvidenceEnvelopeV2,
) -> Result<Vec<u8>, DeploymentControlErrorV2> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(COMPLETE_FIELDS_V2)
        .map_err(|_| DeploymentControlErrorV2::InvalidInstallationEvidenceEnvelope)?;
    encode_preceding_fields(&mut encoder, decoded)?;
    encode_signature(&mut encoder, decoded.signature)?;
    Ok(encoder.into_writer())
}

fn encode_preceding_fields(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    decoded: &DecodedInstallationEvidenceEnvelopeV2,
) -> Result<(), DeploymentControlErrorV2> {
    encoder
        .bytes(decoded.installation_id.as_bytes())
        .and_then(|encoder| encoder.u64(decoded.installation_epoch))
        .and_then(|encoder| encoder.u64(decoded.evidence_sequence))
        .and_then(|encoder| encoder.bytes(decoded.previous_evidence_digest.as_bytes()))
        .and_then(|encoder| encoder.u16(decoded.evidence_kind.tag()))
        .and_then(|encoder| encoder.bytes(&decoded.evidence_bytes))
        .and_then(|encoder| encoder.bytes(decoded.evidence_digest.as_bytes()))
        .and_then(|encoder| encoder.bytes(decoded.activation_key_id.as_bytes()))
        .map(|_| ())
        .map_err(|_| DeploymentControlErrorV2::InvalidInstallationEvidenceEnvelope)
}

fn encode_signature(
    encoder: &mut minicbor::Encoder<Vec<u8>>,
    signature: EnvelopeSignatureV2,
) -> Result<(), DeploymentControlErrorV2> {
    encoder
        .array(DOMAIN_SIGNATURE_FIELDS_V2)
        .and_then(|encoder| encoder.u16(signature.domain_tag))
        .and_then(|encoder| encoder.bytes(signature.signer_key_id.as_bytes()))
        .and_then(|encoder| encoder.u64(signature.signer_key_epoch))
        .and_then(|encoder| encoder.bytes(signature.signature.as_bytes()))
        .map(|_| ())
        .map_err(|_| DeploymentControlErrorV2::InvalidInstallationEvidenceEnvelope)
}

fn decode_signature(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<EnvelopeSignatureV2, DeploymentControlErrorV2> {
    expect_array(decoder, DOMAIN_SIGNATURE_FIELDS_V2)?;
    let domain_tag = decode_u16(decoder)?;
    let signer_key_id = decode_key_id(decoder)?;
    let signer_key_epoch = decode_u64(decoder)?;
    let signature = decoder
        .bytes()
        .map_err(|_| DeploymentControlErrorV2::InvalidInstallationEvidenceEnvelope)?;
    let signature: [u8; 64] = signature
        .try_into()
        .map_err(|_| DeploymentControlErrorV2::InvalidInstallationEvidenceEnvelope)?;
    Ok(EnvelopeSignatureV2 {
        domain_tag,
        signer_key_id,
        signer_key_epoch,
        signature: Ed25519SignatureV2::new(signature),
    })
}

fn expect_array(
    decoder: &mut minicbor::Decoder<'_>,
    expected: u64,
) -> Result<(), DeploymentControlErrorV2> {
    if decoder
        .array()
        .map_err(|_| DeploymentControlErrorV2::InvalidInstallationEvidenceEnvelope)?
        != Some(expected)
    {
        return Err(DeploymentControlErrorV2::InvalidInstallationEvidenceEnvelope);
    }
    Ok(())
}

fn decode_u16(decoder: &mut minicbor::Decoder<'_>) -> Result<u16, DeploymentControlErrorV2> {
    decoder
        .u16()
        .map_err(|_| DeploymentControlErrorV2::InvalidInstallationEvidenceEnvelope)
}

fn decode_u64(decoder: &mut minicbor::Decoder<'_>) -> Result<u64, DeploymentControlErrorV2> {
    decoder
        .u64()
        .map_err(|_| DeploymentControlErrorV2::InvalidInstallationEvidenceEnvelope)
}

fn decode_digest(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<Digest32V2, DeploymentControlErrorV2> {
    let bytes = decoder
        .bytes()
        .map_err(|_| DeploymentControlErrorV2::InvalidInstallationEvidenceEnvelope)?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| DeploymentControlErrorV2::InvalidInstallationEvidenceEnvelope)?;
    Ok(Digest32V2::new(bytes))
}

fn decode_key_id(
    decoder: &mut minicbor::Decoder<'_>,
) -> Result<Ed25519KeyIdV2, DeploymentControlErrorV2> {
    Ok(Ed25519KeyIdV2::new(*decode_digest(decoder)?.as_bytes()))
}

fn is_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}
