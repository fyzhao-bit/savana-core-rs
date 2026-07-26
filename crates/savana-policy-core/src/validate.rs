use std::cmp::Ordering;

use ed25519_dalek::VerifyingKey;
use savana_kernel_protocol::{
    approval_display_digest, ApprovalChallengeV1, ApprovalReceiptV1, AttemptKindV1, BoundedText,
    ConstraintId, ConversationId, Digest32, EffectiveLimits, HardLimits, KeyId,
    MaskedDisplayBundleV1, Nonce32, OntologyEventV1, OntologySnapshotV1, PendingToolCallHandle,
    PlannerId, PrincipalId, RegistrySnapshotV1, RunId, SignedApprovalEnvelopeV1,
    SignedIngressEnvelopeV1, SignedOntologyEventV1, SignedOntologySnapshotV1,
    SignedPlannerAttestationV1, SignedRegistrySnapshotV1, SignedValidatorAttestationV1, StableCode,
    ToolName, UnixMillis, ValidatorId, PROTOCOL_MAJOR, PROTOCOL_MINOR,
};
use sha2::{Digest, Sha256};

use crate::bundle::{
    encode_planner_signing_payload, encode_validator_signing_payload, AllowedToolV1,
    AuthorityKeyV1, AuthorityRoleV1, PolicyBundleV1, ToolAttemptV1,
};
use crate::provenance::PolicyBound;
use crate::release::VerifiedReleaseIdentity;
use crate::signature::{verify_signature, SignatureDomain};
use crate::PolicyError;

const MAXIMUM_PER_RUN: u32 = 65_536;
const MAXIMUM_TTL_SECONDS: u32 = 120;
const MAXIMUM_SNAPSHOT_ENTRIES: u32 = 100_000;
const MAXIMUM_CONSTRAINTS_PER_TOOL: u16 = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyIdentity {
    pub digest: Digest32,
    pub policy_version: u64,
    pub key_epoch: u64,
    pub expires_at: UnixMillis,
}

#[derive(Clone, PartialEq, Eq)]
pub struct VerifiedPolicyV1 {
    bundle: PolicyBundleV1,
    identity: PolicyIdentity,
    effective_limits: EffectiveLimits,
    signature_digest: Digest32,
    signing_public_key: [u8; 32],
    active_release_target_id: Digest32,
    resource_profile_digest: Digest32,
}

impl std::fmt::Debug for VerifiedPolicyV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("VerifiedPolicyV1(<verified>)")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedAuthorityV1<'policy> {
    authority: &'policy AuthorityKeyV1,
}

impl VerifiedAuthorityV1<'_> {
    pub const fn key_id(&self) -> &KeyId {
        &self.authority.key_id
    }

    pub const fn role(&self) -> AuthorityRoleV1 {
        self.authority.role
    }

    pub const fn public_key(&self) -> &[u8; 32] {
        &self.authority.public_key
    }

    pub const fn epoch(&self) -> u64 {
        self.authority.epoch
    }

    pub const fn not_before(&self) -> UnixMillis {
        self.authority.not_before
    }

    pub const fn not_after(&self) -> UnixMillis {
        self.authority.not_after
    }
}

#[derive(Clone)]
pub struct VerifiedIngressV1 {
    artifact: SignedIngressEnvelopeV1,
    policy_identity: PolicyIdentity,
}

impl std::fmt::Debug for VerifiedIngressV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("VerifiedIngressV1(<verified>)")
    }
}

impl VerifiedIngressV1 {
    pub const fn role(&self) -> &savana_kernel_protocol::RoleId {
        &self.artifact.unsigned.role
    }

    pub const fn policy_digest(&self) -> Digest32 {
        self.artifact.unsigned.policy_digest
    }

    pub const fn principal(&self) -> &PrincipalId {
        &self.artifact.unsigned.principal
    }

    pub const fn conversation_id(&self) -> &ConversationId {
        &self.artifact.unsigned.conversation_id
    }

    pub const fn request_digest(&self) -> Digest32 {
        self.artifact.unsigned.request_digest
    }

    pub const fn issued_at(&self) -> UnixMillis {
        self.artifact.unsigned.issued_at
    }

    pub const fn expires_at(&self) -> UnixMillis {
        self.artifact.unsigned.expires_at
    }

    pub const fn nonce(&self) -> Nonce32 {
        self.artifact.unsigned.nonce
    }

    pub const fn authority_session_id(&self) -> Nonce32 {
        self.artifact.unsigned.authority_session_id
    }

    pub const fn authentication_context_digest(&self) -> Digest32 {
        self.artifact.unsigned.authentication_context_digest
    }

    pub const fn key_id(&self) -> &KeyId {
        &self.artifact.key_id
    }
}

#[derive(Clone)]
pub struct VerifiedPlannerAttestationV1 {
    artifact: SignedPlannerAttestationV1,
    policy_identity: PolicyIdentity,
}

impl std::fmt::Debug for VerifiedPlannerAttestationV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("VerifiedPlannerAttestationV1(<verified>)")
    }
}

impl VerifiedPlannerAttestationV1 {
    pub const fn run_id(&self) -> RunId {
        self.artifact.run_id
    }

    pub const fn planner_id(&self) -> &PlannerId {
        &self.artifact.planner_id
    }

    pub const fn planner_version(&self) -> &BoundedText {
        &self.artifact.planner_version
    }

    pub const fn prompt_digest(&self) -> Digest32 {
        self.artifact.prompt_digest
    }

    pub const fn output_digest(&self) -> Digest32 {
        self.artifact.output_digest
    }

    pub const fn issued_at(&self) -> UnixMillis {
        self.artifact.issued_at
    }

    pub const fn expires_at(&self) -> UnixMillis {
        self.artifact.expires_at
    }

    pub const fn nonce(&self) -> Nonce32 {
        self.artifact.nonce
    }

    pub const fn key_id(&self) -> &KeyId {
        &self.artifact.key_id
    }
}

#[derive(Clone)]
pub struct VerifiedRegistrySnapshotV1 {
    artifact: SignedRegistrySnapshotV1,
    policy_identity: PolicyIdentity,
}

impl std::fmt::Debug for VerifiedRegistrySnapshotV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("VerifiedRegistrySnapshotV1(<verified>)")
    }
}

impl VerifiedRegistrySnapshotV1 {
    pub const fn snapshot(&self) -> &RegistrySnapshotV1 {
        &self.artifact.unsigned
    }

    pub const fn key_id(&self) -> &KeyId {
        &self.artifact.key_id
    }
}

#[derive(Clone)]
pub struct VerifiedOntologySnapshotV1 {
    artifact: SignedOntologySnapshotV1,
    policy_identity: PolicyIdentity,
}

impl std::fmt::Debug for VerifiedOntologySnapshotV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("VerifiedOntologySnapshotV1(<verified>)")
    }
}

impl VerifiedOntologySnapshotV1 {
    pub const fn snapshot(&self) -> &OntologySnapshotV1 {
        &self.artifact.unsigned
    }

    pub const fn key_id(&self) -> &KeyId {
        &self.artifact.key_id
    }
}

#[derive(Clone)]
pub struct VerifiedOntologyEventV1 {
    artifact: SignedOntologyEventV1,
    policy_identity: PolicyIdentity,
}

impl std::fmt::Debug for VerifiedOntologyEventV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("VerifiedOntologyEventV1(<verified>)")
    }
}

impl VerifiedOntologyEventV1 {
    pub const fn event(&self) -> &OntologyEventV1 {
        &self.artifact.unsigned
    }

    pub const fn key_id(&self) -> &KeyId {
        &self.artifact.key_id
    }
}

#[derive(Clone)]
pub struct VerifiedValidatorAttestationV1 {
    artifact: SignedValidatorAttestationV1,
    policy_identity: PolicyIdentity,
}

impl std::fmt::Debug for VerifiedValidatorAttestationV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("VerifiedValidatorAttestationV1(<verified>)")
    }
}

impl VerifiedValidatorAttestationV1 {
    pub const fn validator_id(&self) -> &ValidatorId {
        &self.artifact.validator_id
    }

    pub const fn validator_version(&self) -> &BoundedText {
        &self.artifact.validator_version
    }

    pub const fn run_id(&self) -> RunId {
        self.artifact.run_id
    }

    pub const fn pending(&self) -> PendingToolCallHandle {
        self.artifact.pending
    }

    pub const fn argument_digest(&self) -> Digest32 {
        self.artifact.argument_digest
    }

    pub const fn verdict(&self) -> savana_kernel_protocol::ValidatorVerdictV1 {
        self.artifact.verdict
    }

    pub const fn public_reason(&self) -> StableCode {
        self.artifact.public_reason
    }

    pub const fn issued_at(&self) -> UnixMillis {
        self.artifact.issued_at
    }

    pub const fn expires_at(&self) -> UnixMillis {
        self.artifact.expires_at
    }

    pub const fn nonce(&self) -> Nonce32 {
        self.artifact.nonce
    }

    pub const fn key_id(&self) -> &KeyId {
        &self.artifact.key_id
    }
}

#[derive(Clone)]
/// A canonical receipt with verified policy-selected signature, role, and
/// validity window. It is not an authorization decision: callers must still
/// compare the stored challenge and reserve the one-time approval ledger.
pub struct VerifiedApprovalReceiptV1 {
    artifact: ApprovalReceiptV1,
    policy_identity: PolicyIdentity,
}

impl std::fmt::Debug for VerifiedApprovalReceiptV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("VerifiedApprovalReceiptV1(<verified>)")
    }
}

impl VerifiedApprovalReceiptV1 {
    pub const fn receipt(&self) -> &ApprovalReceiptV1 {
        &self.artifact
    }

    pub const fn challenge(&self) -> &ApprovalChallengeV1 {
        &self.artifact.unsigned.challenge
    }

    pub const fn key_id(&self) -> &KeyId {
        &self.artifact.unsigned.approval_key_id
    }
}

#[derive(Clone)]
/// A canonical envelope authenticated by the installation-pinned daemon and
/// bound to a verified policy. A live-session boot binding is still the
/// responsibility of the Authority/daemon integration.
pub struct VerifiedApprovalEnvelopeV1 {
    artifact: SignedApprovalEnvelopeV1,
    policy_identity: PolicyIdentity,
}

impl std::fmt::Debug for VerifiedApprovalEnvelopeV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("VerifiedApprovalEnvelopeV1(<verified>)")
    }
}

impl VerifiedApprovalEnvelopeV1 {
    pub const fn challenge(&self) -> &ApprovalChallengeV1 {
        &self.artifact.unsigned.challenge
    }

    pub const fn display(&self) -> &MaskedDisplayBundleV1 {
        &self.artifact.unsigned.display
    }

    pub const fn display_digest(&self) -> Digest32 {
        self.artifact.unsigned.display_digest
    }

    pub const fn daemon_key_id(&self) -> &KeyId {
        &self.artifact.daemon_key_id
    }
}

macro_rules! impl_policy_bound {
    ($($wrapper:ty),+ $(,)?) => {
        $(
            impl PolicyBound for $wrapper {
                fn verified_policy_identity(&self) -> PolicyIdentity {
                    self.policy_identity
                }
            }
        )+
    };
}

macro_rules! impl_artifact_equality {
    ($($wrapper:ty),+ $(,)?) => {
        $(
            impl PartialEq for $wrapper {
                fn eq(&self, other: &Self) -> bool {
                    self.artifact == other.artifact
                }
            }

            impl Eq for $wrapper {}
        )+
    };
}

impl_policy_bound!(
    VerifiedIngressV1,
    VerifiedPlannerAttestationV1,
    VerifiedRegistrySnapshotV1,
    VerifiedOntologySnapshotV1,
    VerifiedOntologyEventV1,
    VerifiedValidatorAttestationV1,
    VerifiedApprovalReceiptV1,
    VerifiedApprovalEnvelopeV1,
);

impl_artifact_equality!(
    VerifiedIngressV1,
    VerifiedPlannerAttestationV1,
    VerifiedRegistrySnapshotV1,
    VerifiedOntologySnapshotV1,
    VerifiedOntologyEventV1,
    VerifiedValidatorAttestationV1,
    VerifiedApprovalReceiptV1,
    VerifiedApprovalEnvelopeV1,
);

impl VerifiedPolicyV1 {
    pub const fn identity(&self) -> PolicyIdentity {
        self.identity
    }

    pub const fn effective_limits(&self) -> &EffectiveLimits {
        &self.effective_limits
    }

    pub const fn signing_key_id(&self) -> &KeyId {
        &self.bundle.signing_key_id
    }

    pub(crate) const fn signature_digest(&self) -> Digest32 {
        self.signature_digest
    }

    pub(crate) const fn signing_public_key(&self) -> &[u8; 32] {
        &self.signing_public_key
    }

    pub(crate) const fn active_release_target_id(&self) -> Digest32 {
        self.active_release_target_id
    }

    pub const fn resource_profile_digest(&self) -> Digest32 {
        self.resource_profile_digest
    }

    pub fn authority(
        &self,
        key_id: &KeyId,
        role: AuthorityRoleV1,
    ) -> Option<VerifiedAuthorityV1<'_>> {
        self.bundle
            .authorities
            .iter()
            .find(|authority| {
                authority.key_id == *key_id
                    && authority.role == role
                    && authority_valid_for_policy(authority, &self.bundle)
            })
            .map(|authority| VerifiedAuthorityV1 { authority })
    }

    pub fn verify_ingress(
        &self,
        canonical_artifact: &[u8],
        now: UnixMillis,
    ) -> Result<VerifiedIngressV1, PolicyError> {
        let artifact: SignedIngressEnvelopeV1 =
            decode_canonical_artifact(canonical_artifact, self.effective_limits.frame_bytes())?;
        let authority = self.producer_authority(
            &artifact.key_id,
            AuthorityRoleV1::Ingress,
            StableCode::AttestationInvalidSignature,
        )?;
        let payload = encode_canonical(&artifact.unsigned)?;
        verify_signature(
            SignatureDomain::IngressV1,
            &payload,
            &artifact.signature,
            &authority.public_key,
            StableCode::AttestationInvalidSignature,
        )?;
        self.validate_artifact_window(
            artifact.unsigned.issued_at,
            artifact.unsigned.expires_at,
            now,
            authority,
            StableCode::AttestationExpired,
        )?;
        if is_zero_nonce(artifact.unsigned.nonce)
            || is_zero_nonce(artifact.unsigned.authority_session_id)
        {
            return Err(PolicyError::stable(StableCode::AttestationBindingMismatch));
        }
        Ok(VerifiedIngressV1 {
            artifact,
            policy_identity: self.identity(),
        })
    }

    pub fn verify_planner_attestation(
        &self,
        canonical_artifact: &[u8],
        now: UnixMillis,
    ) -> Result<VerifiedPlannerAttestationV1, PolicyError> {
        let artifact: SignedPlannerAttestationV1 =
            decode_canonical_artifact(canonical_artifact, self.effective_limits.frame_bytes())?;
        let authority = self.producer_authority(
            &artifact.key_id,
            AuthorityRoleV1::Planner,
            StableCode::AttestationInvalidSignature,
        )?;
        let payload = encode_planner_signing_payload(&artifact)?;
        verify_signature(
            SignatureDomain::PlannerV1,
            &payload,
            &artifact.signature,
            &authority.public_key,
            StableCode::AttestationInvalidSignature,
        )?;
        if artifact.planner_id.as_str() != artifact.key_id.as_str() {
            return Err(PolicyError::stable(StableCode::AttestationBindingMismatch));
        }
        if is_zero_nonce(artifact.nonce) {
            return Err(PolicyError::stable(StableCode::AttestationBindingMismatch));
        }
        self.validate_artifact_window(
            artifact.issued_at,
            artifact.expires_at,
            now,
            authority,
            StableCode::AttestationBindingMismatch,
        )?;
        Ok(VerifiedPlannerAttestationV1 {
            artifact,
            policy_identity: self.identity(),
        })
    }

    pub fn verify_registry_snapshot(
        &self,
        canonical_artifact: &[u8],
        now: UnixMillis,
    ) -> Result<VerifiedRegistrySnapshotV1, PolicyError> {
        let artifact: SignedRegistrySnapshotV1 =
            decode_canonical_artifact(canonical_artifact, self.effective_limits.frame_bytes())?;
        let authority = self.producer_authority(
            &artifact.key_id,
            AuthorityRoleV1::Registry,
            StableCode::RegistryInvalidSignature,
        )?;
        let payload = encode_canonical(&artifact.unsigned)?;
        verify_signature(
            SignatureDomain::RegistryV1,
            &payload,
            &artifact.signature,
            &authority.public_key,
            StableCode::RegistryInvalidSignature,
        )?;
        self.validate_artifact_window(
            artifact.unsigned.issued_at,
            artifact.unsigned.expires_at,
            now,
            authority,
            StableCode::AttestationExpired,
        )?;
        Ok(VerifiedRegistrySnapshotV1 {
            artifact,
            policy_identity: self.identity(),
        })
    }

    pub fn verify_ontology_snapshot(
        &self,
        canonical_artifact: &[u8],
        now: UnixMillis,
    ) -> Result<VerifiedOntologySnapshotV1, PolicyError> {
        let artifact: SignedOntologySnapshotV1 =
            decode_canonical_artifact(canonical_artifact, self.effective_limits.frame_bytes())?;
        let authority = self.producer_authority(
            &artifact.key_id,
            AuthorityRoleV1::Ontology,
            StableCode::OntologyInvalidSignature,
        )?;
        if !self
            .bundle
            .ontology
            .snapshot_authority_key_ids
            .contains(&artifact.key_id)
        {
            return Err(PolicyError::stable(StableCode::OntologyInvalidSignature));
        }
        let payload = encode_canonical(&artifact.unsigned)?;
        verify_signature(
            SignatureDomain::OntologySnapshotV1,
            &payload,
            &artifact.signature,
            &authority.public_key,
            StableCode::OntologyInvalidSignature,
        )?;
        if u32::try_from(artifact.unsigned.entries.len()).map_or(true, |entries| {
            entries > self.bundle.ontology.max_snapshot_entries
        }) {
            return Err(PolicyError::stable(StableCode::PolicyLimitExceeded));
        }
        self.validate_artifact_window(
            artifact.unsigned.issued_at,
            artifact.unsigned.expires_at,
            now,
            authority,
            StableCode::AttestationBindingMismatch,
        )?;
        Ok(VerifiedOntologySnapshotV1 {
            artifact,
            policy_identity: self.identity(),
        })
    }

    pub fn verify_ontology_event(
        &self,
        canonical_artifact: &[u8],
        now: UnixMillis,
    ) -> Result<VerifiedOntologyEventV1, PolicyError> {
        let artifact: SignedOntologyEventV1 =
            decode_canonical_artifact(canonical_artifact, self.effective_limits.frame_bytes())?;
        let authority = self.producer_authority(
            &artifact.key_id,
            AuthorityRoleV1::Ontology,
            StableCode::OntologyInvalidSignature,
        )?;
        if !self
            .bundle
            .ontology
            .snapshot_authority_key_ids
            .contains(&artifact.key_id)
        {
            return Err(PolicyError::stable(StableCode::OntologyInvalidSignature));
        }
        let payload = encode_canonical(&artifact.unsigned)?;
        verify_signature(
            SignatureDomain::OntologyEventV1,
            &payload,
            &artifact.signature,
            &authority.public_key,
            StableCode::OntologyInvalidSignature,
        )?;
        self.validate_artifact_window(
            artifact.unsigned.issued_at,
            artifact.unsigned.expires_at,
            now,
            authority,
            StableCode::AttestationBindingMismatch,
        )?;
        Ok(VerifiedOntologyEventV1 {
            artifact,
            policy_identity: self.identity(),
        })
    }

    pub fn verify_validator_attestation(
        &self,
        canonical_artifact: &[u8],
        now: UnixMillis,
    ) -> Result<VerifiedValidatorAttestationV1, PolicyError> {
        let artifact: SignedValidatorAttestationV1 =
            decode_canonical_artifact(canonical_artifact, self.effective_limits.frame_bytes())?;
        let authority = self.producer_authority(
            &artifact.key_id,
            AuthorityRoleV1::Validator,
            StableCode::AttestationInvalidSignature,
        )?;
        let payload = encode_validator_signing_payload(&artifact)?;
        verify_signature(
            SignatureDomain::ValidatorV1,
            &payload,
            &artifact.signature,
            &authority.public_key,
            StableCode::AttestationInvalidSignature,
        )?;
        if artifact.validator_id.as_str() != artifact.key_id.as_str() {
            return Err(PolicyError::stable(StableCode::AttestationBindingMismatch));
        }
        if is_zero_nonce(artifact.nonce) {
            return Err(PolicyError::stable(StableCode::AttestationBindingMismatch));
        }
        self.validate_artifact_window(
            artifact.issued_at,
            artifact.expires_at,
            now,
            authority,
            StableCode::AttestationBindingMismatch,
        )?;
        Ok(VerifiedValidatorAttestationV1 {
            artifact,
            policy_identity: self.identity(),
        })
    }

    pub fn verify_approval_receipt(
        &self,
        canonical_artifact: &[u8],
        now: UnixMillis,
    ) -> Result<VerifiedApprovalReceiptV1, PolicyError> {
        let artifact: ApprovalReceiptV1 =
            decode_canonical_artifact(canonical_artifact, self.effective_limits.frame_bytes())?;
        let authority = self.producer_authority(
            &artifact.unsigned.approval_key_id,
            AuthorityRoleV1::Approval,
            StableCode::ApprovalInvalidSignature,
        )?;
        let payload = encode_canonical(&artifact.unsigned)?;
        verify_signature(
            SignatureDomain::ApprovalReceiptV1,
            &payload,
            &artifact.signature,
            &authority.public_key,
            StableCode::ApprovalInvalidSignature,
        )?;
        if artifact.unsigned.challenge.policy_version != self.bundle.policy_version {
            return Err(PolicyError::stable(StableCode::ApprovalBindingMismatch));
        }
        if is_zero_nonce(artifact.unsigned.challenge.challenge_id)
            || is_zero_nonce(artifact.unsigned.challenge.nonce)
            || is_zero_nonce(artifact.unsigned.receipt_nonce)
        {
            return Err(PolicyError::stable(StableCode::ApprovalBindingMismatch));
        }
        self.validate_artifact_window(
            artifact.unsigned.challenge.issued_at,
            artifact.unsigned.challenge.expires_at,
            now,
            authority,
            StableCode::ApprovalBindingMismatch,
        )?;
        self.validate_artifact_window(
            artifact.unsigned.issued_at,
            artifact.unsigned.expires_at,
            now,
            authority,
            StableCode::ApprovalBindingMismatch,
        )?;
        if artifact.unsigned.issued_at.get() < artifact.unsigned.challenge.issued_at.get()
            || artifact.unsigned.expires_at.get() > artifact.unsigned.challenge.expires_at.get()
            || window_millis(
                artifact.unsigned.challenge.issued_at,
                artifact.unsigned.challenge.expires_at,
            ) > u64::from(self.bundle.release.challenge_ttl_seconds) * 1_000
            || window_millis(artifact.unsigned.issued_at, artifact.unsigned.expires_at)
                > u64::from(self.bundle.release.receipt_ttl_seconds) * 1_000
        {
            return Err(PolicyError::stable(StableCode::ApprovalBindingMismatch));
        }
        Ok(VerifiedApprovalReceiptV1 {
            artifact,
            policy_identity: self.identity(),
        })
    }

    fn producer_authority(
        &self,
        key_id: &KeyId,
        role: AuthorityRoleV1,
        invalid_code: StableCode,
    ) -> Result<ProducerAuthority, PolicyError> {
        let authority = self
            .authority(key_id, role)
            .ok_or_else(|| PolicyError::stable(invalid_code))?;
        Ok(ProducerAuthority {
            public_key: *authority.public_key(),
            not_before: authority.not_before(),
            not_after: authority.not_after(),
        })
    }

    fn validate_artifact_window(
        &self,
        issued_at: UnixMillis,
        expires_at: UnixMillis,
        now: UnixMillis,
        authority: ProducerAuthority,
        binding_code: StableCode,
    ) -> Result<(), PolicyError> {
        if issued_at.get() >= expires_at.get() {
            return Err(malformed());
        }
        if issued_at.get() < self.bundle.issued_at.get()
            || expires_at.get() > self.bundle.expires_at.get()
            || issued_at.get() < authority.not_before.get()
            || expires_at.get() > authority.not_after.get()
        {
            return Err(PolicyError::stable(binding_code));
        }
        if now.get() < issued_at.get()
            || now.get() >= expires_at.get()
            || now.get() < self.bundle.issued_at.get()
            || now.get() >= self.bundle.expires_at.get()
            || now.get() < authority.not_before.get()
            || now.get() >= authority.not_after.get()
        {
            return Err(PolicyError::stable(StableCode::AttestationExpired));
        }
        Ok(())
    }
}

impl VerifiedReleaseIdentity {
    pub fn verify_approval_envelope(
        &self,
        policy: &VerifiedPolicyV1,
        canonical_artifact: &[u8],
        now: UnixMillis,
    ) -> Result<VerifiedApprovalEnvelopeV1, PolicyError> {
        let artifact: SignedApprovalEnvelopeV1 =
            decode_canonical_artifact(canonical_artifact, policy.effective_limits().frame_bytes())?;
        let pinned = self.daemon_identity();
        if artifact.daemon_key_id != *pinned.key_id()
            || artifact.unsigned.daemon_identity.daemon_key_id != *pinned.key_id()
        {
            return Err(PolicyError::stable(StableCode::ApprovalInvalidSignature));
        }
        let payload = encode_canonical(&artifact.unsigned)?;
        verify_signature(
            SignatureDomain::ApprovalEnvelopeV1,
            &payload,
            &artifact.signature,
            pinned.public_key(),
            StableCode::ApprovalInvalidSignature,
        )?;

        let identity = &artifact.unsigned.daemon_identity;
        let challenge = &artifact.unsigned.challenge;
        if identity.release_digest != self.release_digest()
            || identity.model_manifest_digest != self.model_manifest_digest()
            || identity.approval_key_set_digest != self.approval_key_set_digest()
            || identity.resource_profile_digest != self.resource_profile_digest()
            || identity.resource_profile_digest != policy.resource_profile_digest()
            || identity.policy_digest != policy.identity.digest
            || identity.policy_version != policy.identity.policy_version
            || policy.active_release_target_id() != self.release_target_id()
            || identity.protocol.major != self.protocol_major()
            || identity.protocol.minor < self.minimum_minor()
            || identity.protocol.minor > self.maximum_minor()
            || identity.policy_version < self.minimum_policy_version()
            || challenge.boot_id != identity.boot_id
            || challenge.policy_version != identity.policy_version
        {
            return Err(PolicyError::stable(StableCode::ApprovalBindingMismatch));
        }
        if is_zero_nonce(challenge.challenge_id) || is_zero_nonce(challenge.nonce) {
            return Err(PolicyError::stable(StableCode::ApprovalBindingMismatch));
        }
        if artifact.unsigned.display_digest != approval_display_digest(&artifact.unsigned.display)?
        {
            return Err(PolicyError::stable(StableCode::ApprovalBindingMismatch));
        }
        if challenge.issued_at.get() >= challenge.expires_at.get() {
            return Err(malformed());
        }
        if challenge.issued_at.get() < self.issued_at().get()
            || challenge.expires_at.get() > self.expires_at().get()
            || challenge.issued_at.get() < policy.bundle.issued_at.get()
            || challenge.expires_at.get() > policy.bundle.expires_at.get()
            || window_millis(challenge.issued_at, challenge.expires_at)
                > u64::from(policy.bundle.release.challenge_ttl_seconds) * 1_000
        {
            return Err(PolicyError::stable(StableCode::ApprovalBindingMismatch));
        }
        if now.get() < challenge.issued_at.get()
            || now.get() >= challenge.expires_at.get()
            || now.get() < self.issued_at().get()
            || now.get() >= self.expires_at().get()
            || now.get() < policy.bundle.issued_at.get()
            || now.get() >= policy.bundle.expires_at.get()
        {
            return Err(PolicyError::stable(StableCode::AttestationExpired));
        }
        Ok(VerifiedApprovalEnvelopeV1 {
            artifact,
            policy_identity: policy.identity(),
        })
    }
}

#[derive(Clone, Copy)]
struct ProducerAuthority {
    public_key: [u8; 32],
    not_before: UnixMillis,
    not_after: UnixMillis,
}

fn decode_canonical_artifact<'bytes, T>(
    bytes: &'bytes [u8],
    maximum_bytes: u64,
) -> Result<T, PolicyError>
where
    T: minicbor::Decode<'bytes, ()> + minicbor::Encode<()>,
{
    if u64::try_from(bytes.len()).map_or(true, |length| length > maximum_bytes) {
        return Err(PolicyError::stable(StableCode::PolicyLimitExceeded));
    }
    let mut decoder = minicbor::Decoder::new(bytes);
    let value = T::decode(&mut decoder, &mut ()).map_err(|_| malformed())?;
    if decoder.position() != bytes.len() {
        return Err(malformed());
    }
    let canonical = encode_canonical(&value)?;
    if canonical != bytes {
        return Err(malformed());
    }
    Ok(value)
}

fn encode_canonical<T>(value: &T) -> Result<Vec<u8>, PolicyError>
where
    T: minicbor::Encode<()>,
{
    minicbor::to_vec(value).map_err(|_| malformed())
}

fn window_millis(issued_at: UnixMillis, expires_at: UnixMillis) -> u64 {
    expires_at.get().saturating_sub(issued_at.get())
}

fn is_zero_nonce(value: Nonce32) -> bool {
    value.as_bytes() == &[0; 32]
}

pub(crate) fn validate_policy(
    bundle: PolicyBundleV1,
    canonical_bytes: &[u8],
    signature_digest: Digest32,
    signing_public_key: [u8; 32],
    active_release_target_id: Digest32,
    now: UnixMillis,
) -> Result<VerifiedPolicyV1, PolicyError> {
    validate_version_and_time(&bundle, now)?;
    validate_scalars(&bundle)?;
    let effective_limits = HardLimits::COMPILED.lower(&bundle.resources)?;
    validate_ordering(&bundle)?;
    validate_authorities(&bundle)?;
    validate_tools_and_attempts(&bundle)?;
    validate_ontology_and_validators(&bundle)?;
    validate_release_and_mappings(&bundle, active_release_target_id)?;
    let canonical_resources = minicbor::to_vec(bundle.resources).map_err(PolicyError::io)?;
    let resource_profile_digest =
        domain_digest(b"SAVANA_RESOURCE_PROFILE_V1\0", &canonical_resources);

    let identity = PolicyIdentity {
        digest: Digest32::new(Sha256::digest(canonical_bytes).into()),
        policy_version: bundle.policy_version,
        key_epoch: bundle.key_epoch,
        expires_at: bundle.expires_at,
    };
    Ok(VerifiedPolicyV1 {
        bundle,
        identity,
        effective_limits,
        signature_digest,
        signing_public_key,
        active_release_target_id,
        resource_profile_digest,
    })
}

fn validate_version_and_time(bundle: &PolicyBundleV1, now: UnixMillis) -> Result<(), PolicyError> {
    if bundle.schema_version != 1
        || bundle.protocol.major != PROTOCOL_MAJOR
        || bundle.protocol.minimum_minor > PROTOCOL_MINOR
    {
        return Err(PolicyError::stable(StableCode::ProtocolUnsupportedVersion));
    }
    if bundle.policy_version == 0
        || bundle.key_epoch == 0
        || bundle.issued_at.get() >= bundle.expires_at.get()
    {
        return Err(malformed());
    }
    if now.get() < bundle.issued_at.get() {
        return Err(PolicyError::stable(StableCode::PolicyNotYetValid));
    }
    if now.get() >= bundle.expires_at.get() {
        return Err(PolicyError::stable(StableCode::PolicyExpired));
    }
    Ok(())
}

fn validate_scalars(bundle: &PolicyBundleV1) -> Result<(), PolicyError> {
    let release = &bundle.release;
    if release.challenge_ttl_seconds > MAXIMUM_TTL_SECONDS
        || release.receipt_ttl_seconds > MAXIMUM_TTL_SECONDS
        || bundle.ontology.max_snapshot_entries > MAXIMUM_SNAPSHOT_ENTRIES
        || bundle.ontology.max_constraints_per_tool > MAXIMUM_CONSTRAINTS_PER_TOOL
        || bundle
            .attempts
            .limits
            .iter()
            .any(|limit| limit.maximum_per_run > MAXIMUM_PER_RUN)
    {
        return Err(PolicyError::stable(StableCode::PolicyLimitExceeded));
    }
    if release.challenge_ttl_seconds == 0
        || release.receipt_ttl_seconds == 0
        || bundle.ontology.max_snapshot_entries == 0
        || bundle.ontology.max_constraints_per_tool == 0
        || bundle
            .attempts
            .limits
            .iter()
            .any(|limit| limit.maximum_per_run == 0)
        || !release.require_authenticated_user_assertion
        || !release.consume_vault_on_success
        || !bundle.sink.deny_on_missing_attestation
    {
        return Err(malformed());
    }
    Ok(())
}

fn validate_ordering(bundle: &PolicyBundleV1) -> Result<(), PolicyError> {
    if !sorted_text(bundle.tools.iter().map(|tool| tool.name.as_str()))
        || !sorted_text(
            bundle
                .authorities
                .iter()
                .map(|authority| authority.key_id.as_str()),
        )
        || !sorted_text(
            bundle
                .dataflow
                .no_side_effect_tools
                .iter()
                .map(ToolName::as_str),
        )
        || !sorted_text(
            bundle
                .dataflow
                .consent_overridable_tools
                .iter()
                .map(ToolName::as_str),
        )
        || !sorted_text(bundle.dataflow.high_risk_tools.iter().map(ToolName::as_str))
        || !sorted_tool_attempts(&bundle.attempts.valid_pairs)
        || !sorted_attempts(bundle.attempts.limits.iter().map(|limit| limit.attempt))
        || !sorted_attempts(bundle.attempts.cloud_blocked.iter().copied())
        || !sorted_text(
            bundle
                .ontology
                .snapshot_authority_key_ids
                .iter()
                .map(KeyId::as_str),
        )
        || !sorted_text(
            bundle
                .sink
                .validator_requirements
                .iter()
                .map(|requirement| requirement.tool.as_str()),
        )
        || !sorted_digests(bundle.release.compatible_release_target_ids.as_slice())
        || !sorted_digests(&bundle.accepted_model_manifest_digests)
        || !bundle.error_map.windows(2).all(|pair| {
            matches!(
                pair,
                [left, right] if left.policy_reason_tag < right.policy_reason_tag
            )
        })
    {
        return Err(malformed());
    }
    for tool in &bundle.tools {
        if !sorted_text(tool.constraint_ids.iter().map(ConstraintId::as_str))
            || !sorted_text(tool.validator_ids.iter().map(ValidatorId::as_str))
        {
            return Err(malformed());
        }
    }
    for requirement in &bundle.sink.validator_requirements {
        if !sorted_text(requirement.validator_ids.iter().map(ValidatorId::as_str)) {
            return Err(malformed());
        }
    }
    Ok(())
}

fn validate_authorities(bundle: &PolicyBundleV1) -> Result<(), PolicyError> {
    let mut role_present = [false; 8];
    for (index, authority) in bundle.authorities.iter().enumerate() {
        if authority.epoch == 0
            || authority.public_key == [0; 32]
            || !usable_verifying_key(&authority.public_key)
            || authority.not_before.get() >= authority.not_after.get()
        {
            return Err(malformed());
        }
        if authority_valid_for_policy(authority, bundle) {
            if bundle.authorities[..index].iter().any(|prior| {
                authority_valid_for_policy(prior, bundle)
                    && prior.public_key == authority.public_key
            }) {
                return Err(malformed());
            }
            let present = role_present
                .get_mut(usize::from(authority.role.tag()))
                .ok_or_else(malformed)?;
            *present = true;
        }
    }
    if role_present.iter().any(|present| !present) {
        return Err(malformed());
    }
    Ok(())
}

fn usable_verifying_key(public_key: &[u8; 32]) -> bool {
    VerifyingKey::from_bytes(public_key).is_ok_and(|key| !key.is_weak())
}

fn validate_tools_and_attempts(bundle: &PolicyBundleV1) -> Result<(), PolicyError> {
    for name in bundle
        .dataflow
        .no_side_effect_tools
        .iter()
        .chain(&bundle.dataflow.consent_overridable_tools)
        .chain(&bundle.dataflow.high_risk_tools)
    {
        if find_tool(bundle, name.as_str()).is_none() {
            return Err(malformed());
        }
    }
    for pair in &bundle.attempts.valid_pairs {
        if find_tool(bundle, pair.tool.as_str()).is_none() {
            return Err(malformed());
        }
    }
    for tool in &bundle.tools {
        if !bundle
            .attempts
            .valid_pairs
            .iter()
            .any(|pair| pair.tool == tool.name && pair.attempt == tool.attempt)
        {
            return Err(malformed());
        }
    }
    Ok(())
}

fn validate_ontology_and_validators(bundle: &PolicyBundleV1) -> Result<(), PolicyError> {
    for key_id in &bundle.ontology.snapshot_authority_key_ids {
        let valid = find_authority(bundle, key_id.as_str()).is_some_and(|authority| {
            authority.role == AuthorityRoleV1::Ontology
                && authority_valid_for_policy(authority, bundle)
        });
        if !valid {
            return Err(malformed());
        }
    }

    for tool in &bundle.tools {
        for validator_id in &tool.validator_ids {
            if !is_valid_validator(bundle, validator_id.as_str()) {
                return Err(malformed());
            }
        }
    }

    for requirement in &bundle.sink.validator_requirements {
        if requirement.validator_ids.is_empty() {
            return Err(malformed());
        }
        let tool = find_tool(bundle, requirement.tool.as_str()).ok_or_else(malformed)?;
        for validator_id in &requirement.validator_ids {
            if !tool
                .validator_ids
                .iter()
                .any(|listed| listed == validator_id)
            {
                return Err(malformed());
            }
        }
    }
    Ok(())
}

fn validate_release_and_mappings(
    bundle: &PolicyBundleV1,
    active_release_target_id: Digest32,
) -> Result<(), PolicyError> {
    if bundle
        .release
        .compatible_release_target_ids
        .as_slice()
        .is_empty()
        || bundle.accepted_model_manifest_digests.is_empty()
    {
        return Err(malformed());
    }
    if !bundle
        .release
        .compatible_release_target_ids
        .as_slice()
        .contains(&active_release_target_id)
    {
        return Err(PolicyError::stable(StableCode::PolicyReleaseIncompatible));
    }
    Ok(())
}

fn authority_valid_for_policy(authority: &AuthorityKeyV1, bundle: &PolicyBundleV1) -> bool {
    !authority.revoked
        && authority.not_before.get() <= bundle.issued_at.get()
        && authority.not_after.get() >= bundle.expires_at.get()
}

fn is_valid_validator(bundle: &PolicyBundleV1, key_id: &str) -> bool {
    find_authority(bundle, key_id).is_some_and(|authority| {
        authority.role == AuthorityRoleV1::Validator
            && authority_valid_for_policy(authority, bundle)
    })
}

fn find_tool<'bundle>(
    bundle: &'bundle PolicyBundleV1,
    name: &str,
) -> Option<&'bundle AllowedToolV1> {
    bundle.tools.iter().find(|tool| tool.name.as_str() == name)
}

fn find_authority<'bundle>(
    bundle: &'bundle PolicyBundleV1,
    key_id: &str,
) -> Option<&'bundle AuthorityKeyV1> {
    bundle
        .authorities
        .iter()
        .find(|authority| authority.key_id.as_str() == key_id)
}

fn sorted_text<'value>(values: impl IntoIterator<Item = &'value str>) -> bool {
    let mut previous = None;
    for value in values {
        if previous.is_some_and(|prior| canonical_text_cmp(prior, value) != Ordering::Less) {
            return false;
        }
        previous = Some(value);
    }
    true
}

fn canonical_text_cmp(left: &str, right: &str) -> Ordering {
    left.len()
        .cmp(&right.len())
        .then_with(|| left.as_bytes().cmp(right.as_bytes()))
}

fn sorted_tool_attempts(values: &[ToolAttemptV1]) -> bool {
    values.windows(2).all(|pair| {
        matches!(
            pair,
            [left, right]
                if canonical_text_cmp(left.tool.as_str(), right.tool.as_str())
                    .then_with(|| left.attempt.tag().cmp(&right.attempt.tag()))
                    == Ordering::Less
        )
    })
}

fn sorted_attempts(values: impl IntoIterator<Item = AttemptKindV1>) -> bool {
    let mut previous = None;
    for value in values {
        if previous.is_some_and(|prior: AttemptKindV1| prior.tag() >= value.tag()) {
            return false;
        }
        previous = Some(value);
    }
    true
}

fn sorted_digests(values: &[Digest32]) -> bool {
    values
        .windows(2)
        .all(|pair| matches!(pair, [left, right] if left.as_bytes() < right.as_bytes()))
}

fn malformed() -> PolicyError {
    PolicyError::stable(StableCode::ProtocolMalformedCbor)
}

fn domain_digest(domain: &[u8], bytes: &[u8]) -> Digest32 {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(bytes);
    Digest32::new(hasher.finalize().into())
}

#[cfg(test)]
mod provenance_tests {
    use super::PolicyIdentity;
    use crate::provenance::PolicyBound;
    use ed25519_dalek::SigningKey;
    use savana_kernel_protocol::{KeyId, RegistrySnapshotV1, SignedRegistrySnapshotV1, UnixMillis};

    use crate::test_support as support;

    #[test]
    fn complete_producer_provenance_includes_policy_expiry() {
        let mut policy_value = support::valid_policy(7, 3);
        policy_value.expires_at = 3_000;
        let (policy_bytes, policy_signature) = support::signed(&policy_value);
        let policy = support::verifier()
            .verify(&policy_bytes, &policy_signature, support::unix_now())
            .unwrap();
        let first = policy.identity();
        let mut second_policy_value = support::valid_policy(7, 3);
        second_policy_value.expires_at = 3_001;
        let (second_bytes, second_signature) = support::signed(&second_policy_value);
        let second_policy = support::verifier()
            .verify(&second_bytes, &second_signature, support::unix_now())
            .unwrap();
        let second = PolicyIdentity {
            digest: first.digest,
            policy_version: first.policy_version,
            key_epoch: first.key_epoch,
            expires_at: second_policy.identity().expires_at,
        };
        let unsigned = RegistrySnapshotV1 {
            version: 1,
            previous_digest: None,
            tools: Vec::new(),
            issued_at: UnixMillis::new(1_000),
            expires_at: UnixMillis::new(2_500),
        };
        let payload = minicbor::to_vec(&unsigned).unwrap();
        let artifact = minicbor::to_vec(SignedRegistrySnapshotV1 {
            unsigned,
            key_id: KeyId::try_from("role-02").unwrap(),
            signature: support::detached_signature(
                b"SAVANA_REGISTRY_V1\0",
                &payload,
                &SigningKey::from_bytes(&[0x72; 32]),
            ),
        })
        .unwrap();
        let producer = policy
            .verify_registry_snapshot(&artifact, support::unix_now())
            .unwrap();
        let other_producer = second_policy
            .verify_registry_snapshot(&artifact, support::unix_now())
            .unwrap();
        assert_eq!(producer, other_producer);
        assert!(producer.is_current_for(first));
        assert!(!producer.is_current_for(second));
    }
}
