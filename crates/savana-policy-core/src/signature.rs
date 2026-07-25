use ed25519_dalek::{Signature, VerifyingKey};
use savana_kernel_protocol::{Digest32, KeyId, Signature64, StableCode, UnixMillis};

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

#[derive(Debug, Clone)]
pub struct PolicyVerifier {
    roots: Vec<PolicyTrustRootV1>,
    active_release_target_id: Digest32,
}

#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
enum SignatureDomain {
    PolicyV1,
    ReleaseV1,
    DaemonHelloV1,
    ClientFinishV1,
}

impl SignatureDomain {
    const fn bytes(self) -> &'static [u8] {
        match self {
            Self::PolicyV1 => b"SAVANA_POLICY_V1\0",
            Self::ReleaseV1 => b"SAVANA_RELEASE_V1\0",
            Self::DaemonHelloV1 => b"SAVANA_DAEMON_HELLO_V1\0",
            Self::ClientFinishV1 => b"SAVANA_CLIENT_FINISH_V1\0",
        }
    }
}

impl PolicyVerifier {
    pub fn new(
        roots: Vec<PolicyTrustRootV1>,
        active_release_target_id: Digest32,
    ) -> Result<Self, PolicyError> {
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
        Ok(Self {
            roots,
            active_release_target_id,
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
        let verifying_key =
            VerifyingKey::from_bytes(&root.public_key).map_err(|_| invalid_signature())?;
        let detached_signature = Signature::from_bytes(signature.as_bytes());
        let domain = SignatureDomain::PolicyV1.bytes();
        let mut signed = Vec::with_capacity(domain.len() + canonical_bundle.len());
        signed.extend_from_slice(domain);
        signed.extend_from_slice(canonical_bundle);
        verifying_key
            .verify_strict(&signed, &detached_signature)
            .map_err(|_| invalid_signature())?;
        validate_policy(bundle, canonical_bundle, self.active_release_target_id, now)
    }
}

fn canonical_text_cmp(left: &str, right: &str) -> std::cmp::Ordering {
    left.len()
        .cmp(&right.len())
        .then_with(|| left.as_bytes().cmp(right.as_bytes()))
}

fn invalid_signature() -> PolicyError {
    PolicyError::stable(StableCode::PolicyInvalidSignature)
}
