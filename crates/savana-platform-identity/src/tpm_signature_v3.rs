//! Additive deployment signature suite. Never reinterpret a V2 Ed25519 object.
//! Public-key parsing/verification alone is NOT hardware attestation or authority.
use p256::ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::tpm_wire::Reader;
use crate::NativeDeploymentSignatureDomainV2 as Domain;

const SUITE: u16 = 2;
const MAGIC: &[u8; 4] = b"SVS3";
const ENVELOPE_LEN: usize = 176;
pub(crate) const KEY_ATTRIBUTES: u32 = 0x0004_0072;
pub(crate) const POLICY_KEY_ATTRIBUTES: u32 = 0x0004_00b2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TpmSignatureErrorV3 {
    #[error("unsupported or malformed TPM signature object")]
    Malformed,
    #[error("TPM signing identity does not match the pinned binding")]
    BindingMismatch,
    #[error("invalid TPM deployment signature")]
    InvalidSignature,
    #[error("native TPM signing unavailable")]
    Unavailable,
    #[error("TPM operation failed; reopen and revalidate before further use")]
    OperationFailed,
}

/// Exact sign-only ECC/P256/SHA256 template, with either legacy password auth or
/// a policy-only SHA256 authPolicy. Native Linux startup requires the latter.
/// Parsing does not prove the source was a TPM. Trust pins come from enrollment.
#[derive(Clone, PartialEq, Eq)]
pub struct TpmSigningPublicV3 {
    area: Vec<u8>,
    name: [u8; 34],
    point: [u8; 65],
    key_id: [u8; 32],
    policy: Option<[u8; 32]>,
}

impl core::fmt::Debug for TpmSigningPublicV3 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("TpmSigningPublicV3(<public binding>)")
    }
}

impl TpmSigningPublicV3 {
    pub fn from_tpm2b_public(bytes: &[u8]) -> Result<Self, TpmSignatureErrorV3> {
        if bytes.len() > 128 {
            return Err(TpmSignatureErrorV3::Malformed);
        }
        let mut outer = Reader::new(bytes);
        let area = outer.sized()?;
        outer.end()?;
        let mut r = Reader::new(area);
        if r.u16()? != 0x23 || r.u16()? != 0x0b {
            return Err(TpmSignatureErrorV3::Malformed);
        }
        let attributes = r.u32()?;
        let auth_policy = r.sized()?;
        let policy = match (attributes, auth_policy.len()) {
            (KEY_ATTRIBUTES, 0) => None,
            (POLICY_KEY_ATTRIBUTES, 32) if auth_policy != [0; 32] => Some(
                auth_policy
                    .try_into()
                    .map_err(|_| TpmSignatureErrorV3::Malformed)?,
            ),
            _ => return Err(TpmSignatureErrorV3::Malformed),
        };
        if r.u16()? != 0x10
            || r.u16()? != 0x18
            || r.u16()? != 0x0b
            || r.u16()? != 3
            || r.u16()? != 0x10
        {
            return Err(TpmSignatureErrorV3::Malformed);
        }
        let x = r.sized()?;
        let y = r.sized()?;
        r.end()?;
        if x.len() != 32 || y.len() != 32 {
            return Err(TpmSignatureErrorV3::Malformed);
        }
        let mut point = [0; 65];
        point[0] = 4;
        point[1..33].copy_from_slice(x);
        point[33..].copy_from_slice(y);
        VerifyingKey::from_sec1_bytes(&point).map_err(|_| TpmSignatureErrorV3::Malformed)?;
        let mut name = [0; 34];
        name[..2].copy_from_slice(&0x0b_u16.to_be_bytes());
        name[2..].copy_from_slice(&Sha256::digest(area));
        let mut h = Sha256::new();
        h.update(b"savana.tpm-signing-key.v3\0");
        h.update(SUITE.to_be_bytes());
        h.update(name);
        Ok(Self {
            area: area.to_vec(),
            name,
            point,
            key_id: h.finalize().into(),
            policy,
        })
    }

    pub const fn name(&self) -> &[u8; 34] {
        &self.name
    }
    pub const fn key_id(&self) -> [u8; 32] {
        self.key_id
    }
    pub const fn auth_policy(&self) -> Option<[u8; 32]> {
        self.policy
    }
    pub const fn public_point(&self) -> &[u8; 65] {
        &self.point
    }
    pub fn tpm2b_public(&self) -> Vec<u8> {
        let mut bytes = (self.area.len() as u16).to_be_bytes().to_vec();
        bytes.extend_from_slice(&self.area);
        bytes
    }
}

/// Provisioner-supplied expected binding, not derived from an untrusted model
/// or from whichever object happens to occupy a TPM persistent handle today.
#[derive(Clone)]
pub struct TpmSigningBindingV3 {
    pub(crate) public: TpmSigningPublicV3,
    pub(crate) qualified_name: [u8; 34],
    pub(crate) handle: u32,
    pub(crate) installation: [u8; 32],
    pub(crate) epoch: u64,
    pub(crate) pcr: Option<crate::TpmPcrPolicyV3>,
}

impl TpmSigningBindingV3 {
    pub fn new(
        public: TpmSigningPublicV3,
        qualified_name: [u8; 34],
        handle: u32,
        installation: [u8; 32],
        epoch: u64,
    ) -> Result<Self, TpmSignatureErrorV3> {
        Self::with_policy(public, qualified_name, handle, installation, epoch, None)
    }
    pub fn new_with_pcr(
        public: TpmSigningPublicV3,
        qualified_name: [u8; 34],
        handle: u32,
        installation: [u8; 32],
        epoch: u64,
        pcr: crate::TpmPcrPolicyV3,
    ) -> Result<Self, TpmSignatureErrorV3> {
        Self::with_policy(
            public,
            qualified_name,
            handle,
            installation,
            epoch,
            Some(pcr),
        )
    }
    fn with_policy(
        public: TpmSigningPublicV3,
        qualified_name: [u8; 34],
        handle: u32,
        installation: [u8; 32],
        epoch: u64,
        pcr: Option<crate::TpmPcrPolicyV3>,
    ) -> Result<Self, TpmSignatureErrorV3> {
        if !(0x8100_0000..=0x81ff_ffff).contains(&handle)
            || installation == [0; 32]
            || epoch == 0
            || qualified_name[..2] != [0, 0x0b]
            || qualified_name[2..].iter().all(|b| *b == 0)
        {
            return Err(TpmSignatureErrorV3::Malformed);
        }
        if public.policy != pcr.map(|p| p.auth_policy()) {
            return Err(TpmSignatureErrorV3::BindingMismatch);
        }
        Ok(Self {
            public,
            qualified_name,
            handle,
            installation,
            epoch,
            pcr,
        })
    }
    pub const fn public(&self) -> &TpmSigningPublicV3 {
        &self.public
    }
    pub const fn qualified_name(&self) -> &[u8; 34] {
        &self.qualified_name
    }
    pub const fn persistent_handle(&self) -> u32 {
        self.handle
    }
    pub const fn installation_id(&self) -> [u8; 32] {
        self.installation
    }
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }
    pub const fn pcr_policy(&self) -> Option<crate::TpmPcrPolicyV3> {
        self.pcr
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TpmSignatureRequestV3 {
    domain: Domain,
    installation: [u8; 32],
    epoch: u64,
    payload_digest: [u8; 32],
}

impl TpmSignatureRequestV3 {
    pub fn new(
        domain: Domain,
        installation: [u8; 32],
        epoch: u64,
        payload_digest: [u8; 32],
    ) -> Result<Self, TpmSignatureErrorV3> {
        if installation == [0; 32] || epoch == 0 || payload_digest == [0; 32] {
            return Err(TpmSignatureErrorV3::Malformed);
        }
        Ok(Self {
            domain,
            installation,
            epoch,
            payload_digest,
        })
    }
    pub const fn domain(self) -> Domain {
        self.domain
    }
    pub const fn installation_id(self) -> [u8; 32] {
        self.installation
    }
    pub const fn epoch(self) -> u64 {
        self.epoch
    }
    pub const fn payload_digest(self) -> [u8; 32] {
        self.payload_digest
    }

    pub(crate) fn prehash(self, key_id: [u8; 32]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"savana.deployment-signature.v3\0");
        h.update(3_u16.to_be_bytes());
        h.update(SUITE.to_be_bytes());
        h.update((self.domain as u16).to_be_bytes());
        h.update(self.installation);
        h.update(self.epoch.to_be_bytes());
        h.update(key_id);
        h.update(self.payload_digest);
        h.finalize().into()
    }
}

/// Fixed 176-byte wire object: magic, suite, domain, installation, epoch,
/// TPM-bound key ID, payload digest, low-S IEEE-P1363 signature (r||s).
/// No embedded trusted key, algorithm negotiation, fallback, or DER ambiguity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TpmSignatureEnvelopeV3 {
    request: TpmSignatureRequestV3,
    key_id: [u8; 32],
    signature: [u8; 64],
}

pub struct VerifiedTpmSignatureV3 {
    request: TpmSignatureRequestV3,
    key_id: [u8; 32],
}
impl VerifiedTpmSignatureV3 {
    pub const fn request(&self) -> TpmSignatureRequestV3 {
        self.request
    }
    pub const fn key_id(&self) -> [u8; 32] {
        self.key_id
    }
}

impl TpmSignatureEnvelopeV3 {
    #[cfg(any(test, target_os = "linux"))]
    pub(crate) fn from_tpm_signature(
        request: TpmSignatureRequestV3,
        key: &TpmSigningPublicV3,
        signature: Signature,
    ) -> Result<Self, TpmSignatureErrorV3> {
        let signature = signature.normalize_s().unwrap_or(signature);
        let result = Self {
            request,
            key_id: key.key_id,
            signature: signature.to_bytes().into(),
        };
        result.verify(key, request)?;
        Ok(result)
    }

    pub fn to_bytes(&self) -> [u8; ENVELOPE_LEN] {
        let mut b = [0; ENVELOPE_LEN];
        b[..4].copy_from_slice(MAGIC);
        b[4..6].copy_from_slice(&SUITE.to_be_bytes());
        b[6..8].copy_from_slice(&(self.request.domain as u16).to_be_bytes());
        b[8..40].copy_from_slice(&self.request.installation);
        b[40..48].copy_from_slice(&self.request.epoch.to_be_bytes());
        b[48..80].copy_from_slice(&self.key_id);
        b[80..112].copy_from_slice(&self.request.payload_digest);
        b[112..].copy_from_slice(&self.signature);
        b
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, TpmSignatureErrorV3> {
        if bytes.len() != ENVELOPE_LEN {
            return Err(TpmSignatureErrorV3::Malformed);
        }
        let mut r = Reader::new(bytes);
        if r.take(4)? != MAGIC || r.u16()? != SUITE {
            return Err(TpmSignatureErrorV3::Malformed);
        }
        let domain = match r.u16()? {
            5 => Domain::LedgerActivation,
            6 => Domain::InstallationEpochActivation,
            8 => Domain::StoreCompatibility,
            9 => Domain::VerificationEvidence,
            10 => Domain::CommitAttestation,
            13 => Domain::EvidenceGcCheckpoint,
            17 => Domain::RollbackVerificationEvidence,
            18 => Domain::RollbackVerificationAttestation,
            21 => Domain::LedgerSlot,
            22 => Domain::InstallationEvidenceEnvelope,
            25 => Domain::DurableDeploymentTransactionCore,
            26 => Domain::DurableDeploymentTransactionRecord,
            27 => Domain::RecoveryRollbackReadinessEvidence,
            _ => return Err(TpmSignatureErrorV3::Malformed),
        };
        let installation = r.fixed()?;
        let epoch = u64::from_be_bytes(r.fixed()?);
        let key_id = r.fixed()?;
        let payload_digest = r.fixed()?;
        let signature = r.fixed()?;
        r.end()?;
        canonical_signature(&signature)?;
        if key_id == [0; 32] {
            return Err(TpmSignatureErrorV3::Malformed);
        }
        Ok(Self {
            request: TpmSignatureRequestV3::new(domain, installation, epoch, payload_digest)?,
            key_id,
            signature,
        })
    }

    pub fn verify(
        &self,
        key: &TpmSigningPublicV3,
        expected: TpmSignatureRequestV3,
    ) -> Result<VerifiedTpmSignatureV3, TpmSignatureErrorV3> {
        if self.request != expected || self.key_id != key.key_id {
            return Err(TpmSignatureErrorV3::BindingMismatch);
        }
        let signature = canonical_signature(&self.signature)?;
        VerifyingKey::from_sec1_bytes(&key.point)
            .map_err(|_| TpmSignatureErrorV3::Malformed)?
            .verify_prehash(&expected.prehash(self.key_id), &signature)
            .map_err(|_| TpmSignatureErrorV3::InvalidSignature)?;
        Ok(VerifiedTpmSignatureV3 {
            request: expected,
            key_id: self.key_id,
        })
    }
}

fn canonical_signature(bytes: &[u8; 64]) -> Result<Signature, TpmSignatureErrorV3> {
    let s = Signature::from_slice(bytes).map_err(|_| TpmSignatureErrorV3::InvalidSignature)?;
    if s.normalize_s().is_some() {
        return Err(TpmSignatureErrorV3::InvalidSignature);
    }
    Ok(s)
}

#[cfg(test)]
#[path = "tpm_signature_tests.rs"]
mod tests;
