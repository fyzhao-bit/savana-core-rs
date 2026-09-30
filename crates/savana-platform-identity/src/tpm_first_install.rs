//! Closed FIRST-install TPM provisioning. No clear, undefine, evict-old, renewal
//! or migration operation. The caller must durably escrow independently generated
//! authorization values before calling prepare. A partial failure is not rolled
//! back: occupied slots cause a subsequent prepare to fail without mutation.
use crate::tpm_wire::{command, exchange_command, response_body, Reader, Signer, Transport};
use crate::{
    NativeDeploymentSignatureDomainV2 as Domain, TpmClientIdentityV3, TpmEnrollmentProposalV3,
    TpmEnrollmentV3, TpmNvBindingV3, TpmPcrPolicyV3, TpmSignatureErrorV3 as Error,
    TpmSignatureRequestV3, TpmSigningBindingV3, TpmSigningPublicV3, TpmStateHeadV3, TpmStoreV3,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

pub(crate) const KEY_HANDLE: u32 = 0x8101_0003;
pub(crate) const GUARD_INDEX: u32 = 0x0150_0010;

/// Public parameters selected by the trusted installer. This is not a model API.
pub struct TpmFirstInstallSpecV3 {
    pub installation: [u8; 32],
    pub store_ids: [[u8; 32]; 5],
    pub pcr_policy: TpmPcrPolicyV3,
    pub deployer: TpmClientIdentityV3,
    pub kernel: TpmClientIdentityV3,
    pub broker: TpmClientIdentityV3,
    pub not_before: u64,
    pub expires: u64,
}

fn valid_secrets(auth: &[[u8; 32]; 7]) -> Result<(), Error> {
    if auth
        .iter()
        .enumerate()
        .any(|(i, v)| *v == [0; 32] || auth[..i].contains(v))
    {
        return Err(Error::Malformed);
    }
    Ok(())
}
fn sized(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), Error> {
    let len = u16::try_from(bytes.len()).map_err(|_| Error::Malformed)?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}
fn authorized(
    t: &mut impl Transport,
    code: u32,
    handles: &[u32],
    auth: &[u8],
    args: &[u8],
    response_handle: bool,
) -> Result<(Option<u32>, Vec<u8>), Error> {
    let mut body = Zeroizing::new(Vec::new());
    for h in handles {
        body.extend_from_slice(&h.to_be_bytes());
    }
    body.extend_from_slice(&(9 + auth.len() as u32).to_be_bytes());
    body.extend_from_slice(&[0x40, 0, 0, 9, 0, 0, 0]); // PW, empty nonce, attrs=0
    sized(&mut body, auth)?;
    body.extend_from_slice(args);
    let bytes = exchange_command(t, &Zeroizing::new(command(0x8002, code, &body)))?;
    let mut r = response_body(&bytes, 0x8002)?;
    let handle = if response_handle {
        Some(r.u32()?)
    } else {
        None
    };
    let count = r.u32()? as usize;
    let params = r.take(count)?.to_vec();
    if r.take(5)? != [0, 0, 1, 0, 0] {
        return Err(Error::Malformed);
    }
    r.end()?;
    Ok((handle, params))
}
fn vacant(t: &mut impl Transport, handle: u32) -> Result<(), Error> {
    let mut args = 1_u32.to_be_bytes().to_vec(); // TPM_CAP_HANDLES
    args.extend_from_slice(&handle.to_be_bytes());
    args.extend_from_slice(&1_u32.to_be_bytes());
    let response = exchange_command(t, &command(0x8001, 0x17a, &args))?;
    let mut r = response_body(&response, 0x8001)?;
    let more = r.take(1)?[0];
    if more > 1 || r.u32()? != 1 {
        return Err(Error::Malformed);
    }
    match r.u32()? {
        0 if more == 0 => (),
        1 if r.u32()? > handle => (),
        _ => return Err(Error::BindingMismatch),
    }
    r.end()
}
fn nv_public(t: &mut impl Transport, index: u32, written: bool) -> Result<(), Error> {
    let response = exchange_command(t, &command(0x8001, 0x169, &index.to_be_bytes()))?;
    let mut r = response_body(&response, 0x8001)?;
    let area = r.sized()?;
    let mut p = Reader::new(area);
    let expected = if written { 0x2004_0044 } else { 0x0004_0044 };
    if p.u32()? != index
        || p.u16()? != 0x0b
        || p.u32()? != expected
        || !p.sized()?.is_empty()
        || p.u16()? != 32
    {
        return Err(Error::BindingMismatch);
    }
    p.end()?;
    let name = r.sized()?;
    if name.len() != 34 || name[..2] != [0, 0x0b] || name[2..] != Sha256::digest(area)[..] {
        return Err(Error::BindingMismatch);
    }
    r.end()
}
fn nv_root(t: &mut impl Transport, index: u32, auth: &[u8; 32]) -> Result<[u8; 32], Error> {
    nv_public(t, index, true)?;
    let (_, bytes) = authorized(t, 0x14e, &[index, index], auth, &[0, 32, 0, 0], false)?;
    let mut r = Reader::new(&bytes);
    let root = r.sized()?.try_into().map_err(|_| Error::Malformed)?;
    r.end()?;
    Ok(root)
}
fn extend(
    t: &mut impl Transport,
    index: u32,
    auth: &[u8; 32],
    data: &[u8; 32],
) -> Result<(), Error> {
    let mut args = Vec::new();
    sized(&mut args, data)?;
    let (_, reply) = authorized(t, 0x136, &[index, index], auth, &args, false)?;
    if !reply.is_empty() {
        return Err(Error::Malformed);
    }
    Ok(())
}
fn initial_root(seed: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0; 32]);
    h.update(seed);
    h.finalize().into()
}
fn check_pcr(t: &mut impl Transport, policy: TpmPcrPolicyV3) -> Result<(), Error> {
    let selection = [0, 0, 0, 1, 0, 0x0b, 3, policy.mask(), 0, 0];
    let response = exchange_command(t, &command(0x8001, 0x17e, &selection))?;
    let mut r = response_body(&response, 0x8001)?;
    let _update_counter = r.u32()?;
    if r.take(selection.len())? != selection || r.u32()? != policy.mask().count_ones() {
        return Err(Error::BindingMismatch);
    }
    let mut hash = Sha256::new();
    for _ in 0..policy.mask().count_ones() {
        let pcr = r.sized()?;
        if pcr.len() != 32 {
            return Err(Error::Malformed);
        }
        hash.update(pcr);
    }
    r.end()?;
    if hash.finalize().as_slice() != policy.pcr_digest() {
        return Err(Error::BindingMismatch);
    }
    Ok(())
}
fn read_key(t: &mut impl Transport) -> Result<(TpmSigningPublicV3, [u8; 34]), Error> {
    let response = exchange_command(t, &command(0x8001, 0x173, &KEY_HANDLE.to_be_bytes()))?;
    let mut r = response_body(&response, 0x8001)?;
    let area = r.sized()?;
    let mut bytes = Vec::new();
    sized(&mut bytes, area)?;
    let public = TpmSigningPublicV3::from_tpm2b_public(&bytes)?;
    if r.sized()? != public.name() {
        return Err(Error::BindingMismatch);
    }
    let qualified = r.sized()?.try_into().map_err(|_| Error::Malformed)?;
    r.end()?;
    Ok((public, qualified))
}
fn create_key(
    t: &mut impl Transport,
    policy: TpmPcrPolicyV3,
    auth: &[u8; 32],
) -> Result<(), Error> {
    let mut sensitive = Zeroizing::new(Vec::new());
    sized(&mut sensitive, auth)?;
    sized(&mut sensitive, &[])?;
    let mut public = vec![0, 0x23, 0, 0x0b, 0, 4, 0, 0xb2];
    sized(&mut public, &policy.auth_policy())?;
    public.extend_from_slice(&[0, 0x10, 0, 0x18, 0, 0x0b, 0, 3, 0, 0x10, 0, 0, 0, 0]);
    let mut args = Zeroizing::new(Vec::new());
    sized(&mut args, &sensitive)?;
    sized(&mut args, &public)?;
    args.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // outsideInfo empty, creationPCR count=0
    let (handle, bytes) = authorized(t, 0x131, &[0x4000_0001], &[], &args, true)?;
    let handle = handle.ok_or(Error::Malformed)?;
    if handle >> 24 != 0x80 {
        return Err(Error::Malformed);
    }
    let result = (|| {
        let mut r = Reader::new(&bytes);
        let out = r.sized()?;
        let mut out_public = Vec::new();
        sized(&mut out_public, out)?;
        let out_public = TpmSigningPublicV3::from_tpm2b_public(&out_public)?;
        if out_public.auth_policy() != Some(policy.auth_policy()) {
            return Err(Error::BindingMismatch);
        }
        let _creation_data = r.sized()?;
        if r.sized()?.len() != 32 || r.u16()? != 0x8021 || r.u32()? != 0x4000_0001 {
            return Err(Error::Malformed);
        }
        // The creation ticket uses the TPM's internal proof hash, not the
        // object's SHA-256 name algorithm. It is bounded but is NOT our trust
        // evidence; readback and PCR-gated proof of possession are required.
        if !matches!(r.sized()?.len(), 20 | 32 | 48 | 64) || r.sized()? != out_public.name() {
            return Err(Error::Malformed);
        }
        r.end()?;
        let (_, reply) = authorized(
            t,
            0x120,
            &[0x4000_0001, handle],
            &[],
            &KEY_HANDLE.to_be_bytes(),
            false,
        )?;
        if !reply.is_empty() {
            return Err(Error::Malformed);
        }
        let (observed, _) = read_key(t)?;
        if observed != out_public {
            return Err(Error::BindingMismatch);
        }
        Ok(())
    })();
    // Flush only the transient resource created by this invocation. Never evict
    // the persistent object, even if persistence succeeded but its reply was lost.
    let _ = exchange_command(t, &command(0x8001, 0x165, &handle.to_be_bytes()));
    result
}
fn define_nv(t: &mut impl Transport, index: u32, auth: &[u8; 32]) -> Result<(), Error> {
    let mut area = index.to_be_bytes().to_vec();
    area.extend_from_slice(&[0, 0x0b, 0, 4, 0, 0x44, 0, 0, 0, 32]);
    let mut args = Zeroizing::new(Vec::new());
    sized(&mut args, auth)?;
    sized(&mut args, &area)?;
    let (_, reply) = authorized(t, 0x12a, &[0x4000_0001], &[], &args, false)?;
    if !reply.is_empty() {
        return Err(Error::Malformed);
    }
    nv_public(t, index, false)
}

pub(crate) fn prepare(
    t: &mut impl Transport,
    spec: TpmFirstInstallSpecV3,
    auth: &[[u8; 32]; 7],
    seeds: &[[u8; 32]; 5],
) -> Result<TpmEnrollmentProposalV3, Error> {
    valid_secrets(auth)?;
    if spec.installation == [0; 32]
        || spec.not_before == 0
        || spec.expires <= spec.not_before
        || spec.deployer.uid() != 0
        || spec.broker.uid() != 0
        || spec.kernel.uid() == 0
        || spec.deployer == spec.broker
        || seeds
            .iter()
            .enumerate()
            .any(|(i, s)| *s == [0; 32] || seeds[..i].contains(s))
        || spec
            .store_ids
            .iter()
            .enumerate()
            .any(|(i, s)| *s == [0; 32] || spec.store_ids[..i].contains(s))
    {
        return Err(Error::Malformed);
    }
    // Inspect ALL fixed slots before the first mutation. Never interpret an
    // occupied slot as ours, including after an interrupted earlier installation.
    for handle in [
        KEY_HANDLE,
        GUARD_INDEX,
        0x0150_0020,
        0x0150_0021,
        0x0150_0022,
        0x0150_0023,
        0x0150_0024,
    ] {
        vacant(t, handle)?;
    }
    check_pcr(t, spec.pcr_policy)?;
    create_key(t, spec.pcr_policy, &auth[0])?;
    define_nv(t, GUARD_INDEX, &auth[1])?; // intentionally UNWRITTEN until approval
    let mut stores = Vec::new();
    for (i, slot) in TpmStoreV3::ALL.iter().enumerate() {
        let index = slot.index();
        define_nv(t, index, &auth[i + 2])?;
        extend(t, index, &auth[i + 2], &seeds[i])?;
        let root = initial_root(&seeds[i]);
        if nv_root(t, index, &auth[i + 2])? != root {
            return Err(Error::BindingMismatch);
        }
        stores.push(TpmNvBindingV3::new(
            index,
            TpmNvBindingV3::expected_name(index),
            spec.installation,
            spec.store_ids[i],
            1,
            root,
            TpmStateHeadV3::GENESIS,
        )?);
    }
    let (public, qualified) = read_key(t)?;
    TpmEnrollmentProposalV3::new(
        TpmSigningBindingV3::new_with_pcr(
            public,
            qualified,
            KEY_HANDLE,
            spec.installation,
            1,
            spec.pcr_policy,
        )?,
        stores.try_into().map_err(|_| Error::Malformed)?,
        spec.deployer,
        spec.kernel,
        spec.broker,
        spec.not_before,
        spec.expires,
        [0; 32],
    )
}

/// First-install activation. Caller serializes with provisioning and the runtime
/// authority, authenticates the installer signature and checks the live clock.
/// A lost reply can be resolved by a new call: matching guard => no second extend.
pub(crate) fn activate<T: Transport>(
    mut t: T,
    enrollment: &TpmEnrollmentV3,
    auth: &[[u8; 32]; 7],
    now: u64,
) -> Result<(), Error> {
    valid_secrets(auth)?;
    enrollment.check_time(now)?;
    let b = enrollment.signing_binding();
    if b.handle != KEY_HANDLE || b.epoch() != 1 {
        return Err(Error::BindingMismatch);
    }
    for (i, slot) in TpmStoreV3::ALL.iter().enumerate() {
        // Refuse activation/repair if a state store has ever advanced.
        if nv_root(&mut t, slot.index(), &auth[i + 2])?
            != enrollment.store_binding(*slot).initial_root
        {
            return Err(Error::BindingMismatch);
        }
    }
    let mut signer = Signer::open(&mut t, b.clone(), Zeroizing::new(auth[0]))?;
    let mut nonce = [0; 32];
    getrandom::getrandom(&mut nonce).map_err(|_| Error::Unavailable)?;
    let mut h = Sha256::new();
    h.update(b"savana.tpm-first-install.v3\0");
    h.update(enrollment.digest());
    h.update(nonce);
    signer.sign(TpmSignatureRequestV3::new(
        Domain::InstallationEpochActivation,
        b.installation_id(),
        b.epoch(),
        h.finalize().into(),
    )?)?;
    drop(signer);
    if nv_public(&mut t, GUARD_INDEX, false).is_err() {
        // Only exact initialized target is idempotent. Other errors/roots cannot
        // trigger initialization, a reset, a renewal, or another NV mutation.
        if nv_root(&mut t, GUARD_INDEX, &auth[1])? == enrollment.active_enrollment_root() {
            return Ok(());
        }
        return Err(Error::BindingMismatch);
    }
    extend(&mut t, GUARD_INDEX, &auth[1], &enrollment.digest())?;
    if nv_root(&mut t, GUARD_INDEX, &auth[1])? != enrollment.active_enrollment_root() {
        return Err(Error::BindingMismatch);
    }
    Ok(())
}

// A borrowed transport keeps a single TPM connection/resource-manager session
// alive through policy signing and the enrollment guard operation.
impl<T: Transport> Transport for &mut T {
    fn exchange(&mut self, bytes: &[u8]) -> Result<Vec<u8>, Error> {
        (**self).exchange(bytes)
    }
}

#[cfg(test)]
#[path = "tpm_first_install_tests.rs"]
mod tests;
