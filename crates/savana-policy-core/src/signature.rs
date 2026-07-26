use ed25519_dalek::{Signature, VerifyingKey};
use savana_kernel_protocol::{Digest32, KeyId, Signature64, StableCode, UnixMillis};
use sha2::{Digest, Sha256};

use crate::bundle::decode_canonical_policy;
use crate::validate::{validate_policy, VerifiedPolicyV1};
use crate::PolicyError;

const MAXIMUM_POLICY_ROOTS: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyTrustRootV1 {
    pub key_id: KeyId,
    pub public_key: [u8; 32],
    pub epoch: u64,
    pub revoked: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PolicyVerifierOrigin {
    Offline,
    ReleaseBound {
        release_digest: Digest32,
        installation_profile_digest: Digest32,
    },
}

#[derive(Clone)]
pub struct PolicyVerifier {
    roots: Vec<PolicyTrustRootV1>,
    active_release_target_id: Digest32,
    origin: PolicyVerifierOrigin,
}

#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub(crate) enum SignatureDomain {
    PolicyV1,
    ReleaseV1,
    DaemonHelloV1,
    ClientFinishV1,
    IngressV1,
    PlannerV1,
    RegistryV1,
    OntologySnapshotV1,
    OntologyEventV1,
    ValidatorV1,
    ApprovalEnvelopeV1,
    ApprovalReceiptV1,
}

impl SignatureDomain {
    pub(crate) const fn bytes(self) -> &'static [u8] {
        match self {
            Self::PolicyV1 => b"SAVANA_POLICY_V1\0",
            Self::ReleaseV1 => b"SAVANA_RELEASE_V1\0",
            Self::DaemonHelloV1 => b"SAVANA_DAEMON_HELLO_V1\0",
            Self::ClientFinishV1 => b"SAVANA_CLIENT_FINISH_V1\0",
            Self::IngressV1 => b"SAVANA_INGRESS_V1\0",
            Self::PlannerV1 => b"SAVANA_PLANNER_V1\0",
            Self::RegistryV1 => b"SAVANA_REGISTRY_V1\0",
            Self::OntologySnapshotV1 => b"SAVANA_ONTOLOGY_SNAPSHOT_V1\0",
            Self::OntologyEventV1 => b"SAVANA_ONTOLOGY_EVENT_V1\0",
            Self::ValidatorV1 => b"SAVANA_VALIDATOR_V1\0",
            Self::ApprovalEnvelopeV1 => b"SAVANA_APPROVAL_ENVELOPE_V1\0",
            Self::ApprovalReceiptV1 => b"SAVANA_APPROVAL_RECEIPT_V1\0",
        }
    }
}

impl PolicyVerifier {
    pub fn new(
        roots: Vec<PolicyTrustRootV1>,
        active_release_target_id: Digest32,
    ) -> Result<Self, PolicyError> {
        Self::validate_roots(&roots)?;
        Ok(Self {
            roots,
            active_release_target_id,
            origin: PolicyVerifierOrigin::Offline,
        })
    }

    pub(crate) fn for_release(
        roots: Vec<PolicyTrustRootV1>,
        active_release_target_id: Digest32,
        release_digest: Digest32,
        installation_profile_digest: Digest32,
    ) -> Result<Self, PolicyError> {
        Self::validate_roots(&roots)?;
        Ok(Self {
            roots,
            active_release_target_id,
            origin: PolicyVerifierOrigin::ReleaseBound {
                release_digest,
                installation_profile_digest,
            },
        })
    }

    fn validate_roots(roots: &[PolicyTrustRootV1]) -> Result<(), PolicyError> {
        if roots.is_empty() {
            return Err(PolicyError::stable(StableCode::ProtocolMalformedCbor));
        }
        if roots.len() > MAXIMUM_POLICY_ROOTS {
            return Err(PolicyError::stable(StableCode::PolicyLimitExceeded));
        }
        if !roots.windows(2).all(|pair| {
            matches!(
                pair,
                [left, right]
                    if canonical_text_cmp(left.key_id.as_str(), right.key_id.as_str())
                        == std::cmp::Ordering::Less
            )
        }) {
            return Err(PolicyError::stable(StableCode::ProtocolMalformedCbor));
        }
        if roots
            .iter()
            .any(|root| root.epoch == 0 || root.public_key == [0; 32])
        {
            return Err(PolicyError::stable(StableCode::PolicyInvalidSignature));
        }
        Ok(())
    }

    pub(crate) fn is_bound_to(&self, release: &crate::VerifiedReleaseIdentity) -> bool {
        self.origin
            == (PolicyVerifierOrigin::ReleaseBound {
                release_digest: release.release_digest(),
                installation_profile_digest: release.installation_profile_digest(),
            })
    }

    pub fn verify(
        &self,
        canonical_bundle: &[u8],
        signature: &Signature64,
        now: UnixMillis,
    ) -> Result<VerifiedPolicyV1, PolicyError> {
        let bundle = decode_canonical_policy(canonical_bundle)?;
        let root = self
            .roots
            .iter()
            .find(|root| root.key_id == bundle.signing_key_id)
            .filter(|root| !root.revoked && root.epoch == bundle.key_epoch)
            .ok_or_else(invalid_signature)?;
        verify_signature(
            SignatureDomain::PolicyV1,
            canonical_bundle,
            signature,
            &root.public_key,
            StableCode::PolicyInvalidSignature,
        )?;
        let signature_digest = Digest32::new(Sha256::digest(signature.as_bytes()).into());
        validate_policy(
            bundle,
            canonical_bundle,
            signature_digest,
            root.public_key,
            self.active_release_target_id,
            now,
        )
    }
}

impl std::fmt::Debug for PolicyVerifier {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PolicyVerifier(<verified>)")
    }
}

pub(crate) fn verify_signature(
    domain: SignatureDomain,
    canonical_payload: &[u8],
    signature: &Signature64,
    public_key: &[u8; 32],
    invalid_code: StableCode,
) -> Result<(), PolicyError> {
    let verifying_key =
        VerifyingKey::from_bytes(public_key).map_err(|_| PolicyError::stable(invalid_code))?;
    let detached_signature = Signature::from_bytes(signature.as_bytes());
    let domain = domain.bytes();
    let mut signed = Vec::with_capacity(domain.len() + canonical_payload.len());
    signed.extend_from_slice(domain);
    signed.extend_from_slice(canonical_payload);
    verifying_key
        .verify_strict(&signed, &detached_signature)
        .map_err(|_| PolicyError::stable(invalid_code))
}

fn canonical_text_cmp(left: &str, right: &str) -> std::cmp::Ordering {
    left.len()
        .cmp(&right.len())
        .then_with(|| left.as_bytes().cmp(right.as_bytes()))
}

fn invalid_signature() -> PolicyError {
    PolicyError::stable(StableCode::PolicyInvalidSignature)
}
