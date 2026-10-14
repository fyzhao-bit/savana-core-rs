//! Offline enrollment authorization. Installer Ed25519 approval authorizes an
//! explicit V3 binding; it never changes the algorithm of a V2 signed record.
use crate::tpm_wire::Reader;
use crate::{
    TpmNvBindingV3, TpmPcrPolicyV3, TpmSignatureErrorV3 as Error, TpmSigningBindingV3,
    TpmSigningPublicV3, TpmStateHeadV3,
};
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum TpmStoreV3 {
    Deployment = 0,
    Vault = 1,
    Agent = 2,
    G4 = 3,
    Connector = 4,
}
impl TpmStoreV3 {
    pub const ALL: [Self; 5] = [
        Self::Deployment,
        Self::Vault,
        Self::Agent,
        Self::G4,
        Self::Connector,
    ];
    pub const fn index(self) -> u32 {
        0x0150_0020 + self as u32
    }
    #[cfg(target_os = "linux")]
    pub(crate) fn from_tag(tag: u8) -> Result<Self, Error> {
        Self::ALL.get(tag as usize).copied().ok_or(Error::Malformed)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TpmClientIdentityV3 {
    uid: u32,
    gid: u32,
    executable: [u8; 32],
}
impl TpmClientIdentityV3 {
    pub fn new(uid: u32, gid: u32, executable: [u8; 32]) -> Result<Self, Error> {
        if (uid == 0) != (gid == 0) || executable == [0; 32] {
            return Err(Error::Malformed);
        }
        Ok(Self {
            uid,
            gid,
            executable,
        })
    }
    pub const fn uid(self) -> u32 {
        self.uid
    }
    pub const fn gid(self) -> u32 {
        self.gid
    }
    pub const fn executable_digest(self) -> [u8; 32] {
        self.executable
    }
    #[cfg(target_os = "linux")]
    pub(crate) fn matches(self, peer: &crate::NativePeerMeasurementV2) -> bool {
        matches!(peer, crate::NativePeerMeasurementV2::Linux { uid, gid, executable_measurement, .. }
            if *uid == self.uid && *gid == self.gid && *executable_measurement == self.executable)
    }
}

/// An unsigned proposal can be prepared off-device. It grants no authority.
#[derive(Clone)]
pub struct TpmEnrollmentProposalV3 {
    pub(crate) signing: TpmSigningBindingV3,
    pub(crate) stores: [TpmNvBindingV3; 5],
    pub(crate) deployer: TpmClientIdentityV3,
    pub(crate) kernel: TpmClientIdentityV3,
    pub(crate) broker: TpmClientIdentityV3,
    pub(crate) not_before: u64,
    pub(crate) expires: u64,
    pub(crate) previous_enrollment_root: [u8; 32],
}
impl TpmEnrollmentProposalV3 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        signing: TpmSigningBindingV3,
        stores: [TpmNvBindingV3; 5],
        deployer: TpmClientIdentityV3,
        kernel: TpmClientIdentityV3,
        broker: TpmClientIdentityV3,
        not_before: u64,
        expires: u64,
        previous_enrollment_root: [u8; 32],
    ) -> Result<Self, Error> {
        if signing.pcr_policy().is_none()
            || not_before == 0
            || expires <= not_before
            || broker.uid != 0
            || deployer.uid != 0
            || kernel.uid == 0
            || kernel == deployer
            || broker == deployer
            // Migration needs its own continuity proof. Until that exists, this
            // enrollment format is first-install only, not a budget-reset API.
            || previous_enrollment_root != [0; 32]
        {
            return Err(Error::Malformed);
        }
        for (i, store) in stores.iter().enumerate() {
            if store.index != TpmStoreV3::ALL[i].index()
                || store.installation != signing.installation
                || store.epoch != signing.epoch
                || store.initial_head != TpmStateHeadV3::GENESIS
                || stores[..i].iter().any(|old| old.store == store.store)
            {
                return Err(Error::BindingMismatch);
            }
        }
        Ok(Self {
            signing,
            stores,
            deployer,
            kernel,
            broker,
            not_before,
            expires,
            previous_enrollment_root,
        })
    }
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut b = b"SVE3".to_vec();
        b.extend_from_slice(&3_u16.to_be_bytes());
        b.extend_from_slice(&2_u16.to_be_bytes());
        b.extend_from_slice(&self.not_before.to_be_bytes());
        b.extend_from_slice(&self.expires.to_be_bytes());
        b.extend_from_slice(&self.previous_enrollment_root);
        b.extend_from_slice(&self.signing.installation);
        b.extend_from_slice(&self.signing.epoch.to_be_bytes());
        b.extend_from_slice(&self.signing.handle.to_be_bytes());
        b.extend_from_slice(&self.signing.public.tpm2b_public());
        b.extend_from_slice(&self.signing.qualified_name);
        let p = self.signing.pcr.expect("constructor requires policy");
        b.push(p.mask());
        b.extend_from_slice(&p.pcr_digest());
        for s in &self.stores {
            b.extend_from_slice(&s.index.to_be_bytes());
            b.extend_from_slice(&s.name);
            b.extend_from_slice(&s.store);
            b.extend_from_slice(&s.initial_root);
            b.extend_from_slice(&s.initial_head.sequence().to_be_bytes());
            b.extend_from_slice(&s.initial_head.digest());
        }
        for c in [self.deployer, self.kernel, self.broker] {
            b.extend_from_slice(&c.uid.to_be_bytes());
            b.extend_from_slice(&c.gid.to_be_bytes());
            b.extend_from_slice(&c.executable);
        }
        b
    }
    /// Bytes signed by the *externally trusted* installer key. No embedded root.
    pub fn signature_input(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"savana.tpm-enrollment.v3\0");
        h.update(self.canonical_bytes());
        h.finalize().into()
    }
    pub fn attach_signature(&self, signature: [u8; 64]) -> Vec<u8> {
        let mut b = self.canonical_bytes();
        b.extend_from_slice(&signature);
        b
    }
    /// Parses public review material only. This creates no verified authority.
    pub fn from_canonical_bytes(payload: &[u8]) -> Result<Self, Error> {
        if payload.len() > 1984 {
            return Err(Error::Malformed);
        }
        parse_proposal(payload)
    }
}

/// Proof of installer approval, NOT proof of hardware provenance. Production
/// additionally checks this enrollment against its dedicated monotonic NV cell,
/// and proves possession of the pinned, PCR-gated key before serving requests.
#[derive(Clone)]
pub struct TpmEnrollmentV3 {
    pub(crate) proposal: TpmEnrollmentProposalV3,
    digest: [u8; 32],
}
impl TpmEnrollmentV3 {
    pub fn verify(bytes: &[u8], installer_key: [u8; 32], now: u64) -> Result<Self, Error> {
        if bytes.len() > 2048 || bytes.len() < 64 {
            return Err(Error::Malformed);
        }
        let (payload, signature) = bytes.split_at(bytes.len() - 64);
        let mut h = Sha256::new();
        h.update(b"savana.tpm-enrollment.v3\0");
        h.update(payload);
        let digest: [u8; 32] = h.finalize().into();
        VerifyingKey::from_bytes(&installer_key)
            .map_err(|_| Error::Malformed)?
            .verify_strict(
                &digest,
                &Signature::from_slice(signature).map_err(|_| Error::Malformed)?,
            )
            .map_err(|_| Error::InvalidSignature)?;
        let proposal = TpmEnrollmentProposalV3::from_canonical_bytes(payload)?;
        let value = Self { proposal, digest };
        value.check_time(now)?;
        Ok(value)
    }
    pub fn check_time(&self, now: u64) -> Result<(), Error> {
        if now < self.proposal.not_before || now >= self.proposal.expires {
            Err(Error::BindingMismatch)
        } else {
            Ok(())
        }
    }
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }
    pub fn signing_binding(&self) -> &TpmSigningBindingV3 {
        &self.proposal.signing
    }
    pub fn store_binding(&self, store: TpmStoreV3) -> &TpmNvBindingV3 {
        &self.proposal.stores[store as usize]
    }
    pub fn kernel_identity(&self) -> TpmClientIdentityV3 {
        self.proposal.kernel
    }
    pub fn broker_identity(&self) -> TpmClientIdentityV3 {
        self.proposal.broker
    }
    pub fn active_enrollment_root(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(self.proposal.previous_enrollment_root);
        h.update(self.digest);
        h.finalize().into()
    }
}
fn parse_proposal(payload: &[u8]) -> Result<TpmEnrollmentProposalV3, Error> {
    let mut r = Reader::new(payload);
    if r.take(4)? != b"SVE3" || r.u16()? != 3 || r.u16()? != 2 {
        return Err(Error::Malformed);
    }
    let not_before = u64::from_be_bytes(r.fixed()?);
    let expires = u64::from_be_bytes(r.fixed()?);
    let previous = r.fixed()?;
    let installation = r.fixed()?;
    let epoch = u64::from_be_bytes(r.fixed()?);
    let handle = r.u32()?;
    let area = r.sized()?;
    let mut public = (area.len() as u16).to_be_bytes().to_vec();
    public.extend_from_slice(area);
    let public = TpmSigningPublicV3::from_tpm2b_public(&public)?;
    let qualified = r.fixed()?;
    let mask = r.take(1)?[0];
    let pcr = TpmPcrPolicyV3::new(mask, r.fixed()?)?;
    let signing =
        TpmSigningBindingV3::new_with_pcr(public, qualified, handle, installation, epoch, pcr)?;
    let mut stores = Vec::new();
    for _ in 0..5 {
        let index = r.u32()?;
        let name = r.fixed()?;
        let store = r.fixed()?;
        let root = r.fixed()?;
        let head = TpmStateHeadV3::new(u64::from_be_bytes(r.fixed()?), r.fixed()?)?;
        stores.push(TpmNvBindingV3::new(
            index,
            name,
            installation,
            store,
            epoch,
            root,
            head,
        )?);
    }
    let mut identity = || TpmClientIdentityV3::new(r.u32()?, r.u32()?, r.fixed()?);
    let deployer = identity()?;
    let kernel = identity()?;
    let broker = identity()?;
    r.end()?;
    let proposal = TpmEnrollmentProposalV3::new(
        signing,
        stores.try_into().map_err(|_| Error::Malformed)?,
        deployer,
        kernel,
        broker,
        not_before,
        expires,
        previous,
    )?;
    if proposal.canonical_bytes() != payload {
        return Err(Error::Malformed);
    }
    Ok(proposal)
}
#[cfg(test)]
#[path = "tpm_enrollment_tests.rs"]
pub(crate) mod tests;
