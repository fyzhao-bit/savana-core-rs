//! Closed boot policy: SHA256 static PCRs (including PCR7), Sign, authValue.
//! Enrollment supplies the expected digest; runtime never learns/trusts it anew.
use crate::tpm_signature_v3::TpmSignatureErrorV3 as Error;
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TpmPcrPolicyV3 {
    mask: u8,
    digest: [u8; 32],
}
impl TpmPcrPolicyV3 {
    /// Digest of concatenated selected SHA256 PCR values in ascending order.
    /// Only static PCR0..7, and PCR7 is mandatory. This does not itself validate
    /// an event log, Secure Boot configuration, or hardware provenance.
    pub fn new(mask: u8, digest: [u8; 32]) -> Result<Self, Error> {
        if mask & 0x80 == 0 || digest == [0; 32] {
            return Err(Error::Malformed);
        }
        Ok(Self { mask, digest })
    }
    pub const fn mask(self) -> u8 {
        self.mask
    }
    pub const fn pcr_digest(self) -> [u8; 32] {
        self.digest
    }
    pub(crate) fn selection(self) -> [u8; 10] {
        [0, 0, 0, 1, 0, 0x0b, 3, self.mask, 0, 0]
    }
    pub fn auth_policy(self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update([0; 32]);
        h.update(0x17f_u32.to_be_bytes()); // PolicyPCR
        h.update(self.selection());
        h.update(self.digest);
        let first = h.finalize();
        let mut h = Sha256::new();
        h.update(first);
        h.update(0x16c_u32.to_be_bytes()); // PolicyCommandCode
        h.update(0x15d_u32.to_be_bytes()); // Sign
        let second = h.finalize();
        let mut h = Sha256::new();
        h.update(second);
        // PolicyPassword intentionally extends the PolicyAuthValue code.
        h.update(0x16b_u32.to_be_bytes());
        h.finalize().into()
    }
}

#[cfg(any(test, target_os = "linux"))]
pub(crate) fn start(
    t: &mut impl crate::tpm_wire::Transport,
    policy: TpmPcrPolicyV3,
) -> Result<u32, Error> {
    use crate::tpm_wire::{command, exchange_command, response_body};
    let mut nonce = [0; 32];
    getrandom::getrandom(&mut nonce).map_err(|_| Error::Unavailable)?;
    let mut body = Vec::new();
    body.extend_from_slice(&0x4000_0007_u32.to_be_bytes()); // no salt key
    body.extend_from_slice(&0x4000_0007_u32.to_be_bytes()); // unbound
    body.extend_from_slice(&32_u16.to_be_bytes());
    body.extend_from_slice(&nonce);
    body.extend_from_slice(&[0, 0, 1, 0, 0x10, 0, 0x0b]); // salt, policy, sym, hash
    let response = exchange_command(t, &command(0x8001, 0x176, &body))?;
    let mut r = response_body(&response, 0x8001)?;
    let handle = r.u32()?;
    if handle >> 24 != 3 {
        return Err(Error::Malformed);
    }
    let result = (|| {
        if r.sized()?.len() != 32 {
            return Err(Error::Malformed);
        }
        r.end()?;
        let mut pcr = 32_u16.to_be_bytes().to_vec();
        pcr.extend_from_slice(&policy.digest);
        pcr.extend_from_slice(&policy.selection());
        for (code, args) in [
            (0x17f, pcr),
            (0x16c, 0x15d_u32.to_be_bytes().to_vec()),
            (0x18c, vec![]),
        ] {
            let mut body = handle.to_be_bytes().to_vec();
            body.extend_from_slice(&args);
            let response = exchange_command(t, &command(0x8001, code, &body))?;
            response_body(&response, 0x8001)?.end()?;
        }
        Ok(handle)
    })();
    if result.is_err() {
        flush(t, handle);
    }
    result
}

#[cfg(any(test, target_os = "linux"))]
pub(crate) fn flush(t: &mut impl crate::tpm_wire::Transport, handle: u32) {
    use crate::tpm_wire::{command, exchange_command};
    // Best effort cleanup only; never hides/retries the failed authorized command.
    let _ = exchange_command(t, &command(0x8001, 0x165, &handle.to_be_bytes()));
}
