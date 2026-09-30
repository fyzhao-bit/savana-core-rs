//! Rollback anchor: TPM NV extend binds the whole state head, not only a counter.
//! The exclusive authority must serialize writers. TPM NV_Extend is not CAS.
use crate::tpm_signature_v3::TpmSignatureErrorV3 as Error;
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TpmStateHeadV3 {
    sequence: u64,
    digest: [u8; 32],
}
impl TpmStateHeadV3 {
    pub const GENESIS: Self = Self {
        sequence: 0,
        digest: [0; 32],
    };
    pub fn new(sequence: u64, digest: [u8; 32]) -> Result<Self, Error> {
        if (sequence == 0) != (digest == [0; 32]) {
            return Err(Error::Malformed);
        }
        Ok(Self { sequence, digest })
    }
    pub const fn sequence(self) -> u64 {
        self.sequence
    }
    pub const fn digest(self) -> [u8; 32] {
        self.digest
    }
}

/// Trusted enrollment pin. Creation is not attestation; never populate from
/// an unauthenticated file or by reading whichever NV index currently exists.
#[derive(Clone, Debug)]
pub struct TpmNvBindingV3 {
    pub(crate) index: u32,
    pub(crate) name: [u8; 34],
    pub(crate) installation: [u8; 32],
    pub(crate) store: [u8; 32],
    pub(crate) epoch: u64,
    pub(crate) initial_root: [u8; 32],
    pub(crate) initial_head: TpmStateHeadV3,
}
impl TpmNvBindingV3 {
    pub fn new(
        index: u32,
        name: [u8; 34],
        installation: [u8; 32],
        store: [u8; 32],
        epoch: u64,
        initial_root: [u8; 32],
        initial_head: TpmStateHeadV3,
    ) -> Result<Self, Error> {
        if !(0x0100_0000..=0x01ff_ffff).contains(&index)
            || installation == [0; 32]
            || store == [0; 32]
            || epoch == 0
            || initial_root == [0; 32]
            || name != Self::expected_name(index)
        {
            return Err(Error::Malformed);
        }
        Ok(Self {
            index,
            name,
            installation,
            store,
            epoch,
            initial_root,
            initial_head,
        })
    }
    /// Exact initialized SHA256 extend index: AUTHWRITE|AUTHREAD|WRITTEN,
    /// no owner/policy write, no ORDERLY/CLEAR_STCLEAR or write-lock flags.
    pub fn expected_name(index: u32) -> [u8; 34] {
        let mut area = index.to_be_bytes().to_vec();
        area.extend_from_slice(&[0, 0x0b]);
        area.extend_from_slice(&0x2004_0044_u32.to_be_bytes());
        area.extend_from_slice(&[0, 0, 0, 32]); // no policy, 32-byte NV data
        let mut name = [0; 34];
        name[..2].copy_from_slice(&[0, 0x0b]);
        name[2..].copy_from_slice(&Sha256::digest(area));
        name
    }
    pub const fn store_id(&self) -> [u8; 32] {
        self.store
    }
    pub const fn installation_id(&self) -> [u8; 32] {
        self.installation
    }
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }
}

#[cfg(any(test, target_os = "linux"))]
mod runtime {
    use super::*;
    use crate::tpm_wire::{command, exchange_command, response_body, Reader, Transport};
    use zeroize::Zeroizing;

    // The production implementation retains an exclusive OS lock over both slots.
    pub(crate) trait Journal {
        fn load(&self, slot: usize) -> Result<Option<Vec<u8>>, Error>;
        fn store(&mut self, slot: usize, bytes: &[u8]) -> Result<(), Error>;
    }

    pub(crate) struct NvAnchor<T, J> {
        transport: T,
        journal: J,
        binding: TpmNvBindingV3,
        auth: Zeroizing<[u8; 32]>,
        usable: bool,
    }
    impl<T: Transport, J: Journal> NvAnchor<T, J> {
        pub(crate) fn open(
            transport: T,
            journal: J,
            binding: TpmNvBindingV3,
            auth: Zeroizing<[u8; 32]>,
        ) -> Result<Self, Error> {
            if *auth == [0; 32] {
                return Err(Error::Malformed);
            }
            let mut value = Self {
                transport,
                journal,
                binding,
                auth,
                usable: true,
            };
            value.current_head()?;
            Ok(value)
        }
        fn public(&mut self) -> Result<(), Error> {
            let bytes = exchange_command(
                &mut self.transport,
                &command(0x8001, 0x169, &self.binding.index.to_be_bytes()),
            )?;
            let mut r = response_body(&bytes, 0x8001)?;
            let area = r.sized()?;
            let mut p = Reader::new(area);
            if p.u32()? != self.binding.index
                || p.u16()? != 0x0b
                || p.u32()? != 0x2004_0044
                || !p.sized()?.is_empty()
                || p.u16()? != 32
            {
                return Err(Error::BindingMismatch);
            }
            p.end()?;
            let name = r.sized()?;
            if name != self.binding.name || name[2..] != Sha256::digest(area)[..] {
                return Err(Error::BindingMismatch);
            }
            r.end()
        }
        fn authorized(&mut self, code: u32, args: &[u8]) -> Result<Vec<u8>, Error> {
            let mut body = Zeroizing::new(Vec::new());
            body.extend_from_slice(&self.binding.index.to_be_bytes());
            body.extend_from_slice(&self.binding.index.to_be_bytes());
            body.extend_from_slice(&41_u32.to_be_bytes());
            body.extend_from_slice(&[0x40, 0, 0, 9, 0, 0, 0, 0, 32]);
            body.extend_from_slice(self.auth.as_ref());
            body.extend_from_slice(args);
            let bytes = exchange_command(
                &mut self.transport,
                &Zeroizing::new(command(0x8002, code, &body)),
            )?;
            let mut r = response_body(&bytes, 0x8002)?;
            let n = r.u32()? as usize;
            let parameters = r.take(n)?.to_vec();
            if r.take(5)? != [0, 0, 1, 0, 0] {
                return Err(Error::Malformed);
            }
            r.end()?;
            Ok(parameters)
        }
        fn root(&mut self) -> Result<[u8; 32], Error> {
            self.public()?;
            let params = self.authorized(0x14e, &[0, 32, 0, 0])?;
            let mut r = Reader::new(&params);
            let root = r.sized()?.try_into().map_err(|_| Error::Malformed)?;
            r.end()?;
            Ok(root)
        }
        fn event(&self, head: TpmStateHeadV3) -> [u8; 32] {
            let mut h = Sha256::new();
            h.update(b"savana.tpm-state-head.v3\0");
            h.update(self.binding.installation);
            h.update(self.binding.store);
            h.update(self.binding.epoch.to_be_bytes());
            h.update(self.binding.name);
            h.update(head.sequence.to_be_bytes());
            h.update(head.digest);
            h.finalize().into()
        }
        fn extension(&self, root: [u8; 32], head: TpmStateHeadV3) -> [u8; 32] {
            let mut h = Sha256::new();
            h.update(root);
            h.update(self.event(head));
            h.finalize().into()
        }
        fn resolve(&self, root: [u8; 32]) -> Result<TpmStateHeadV3, Error> {
            if root == self.binding.initial_root {
                return Ok(self.binding.initial_head);
            }
            let mut found = None;
            for slot in 0..2 {
                if let Some(bytes) = self.journal.load(slot)? {
                    // A torn/incomplete inactive slot cannot authenticate a head.
                    if let Ok((head, previous, next)) = decode(&bytes) {
                        if next == root && self.extension(previous, head) == root {
                            if head.sequence <= self.binding.initial_head.sequence
                                || found.is_some_and(|old| old != head)
                            {
                                return Err(Error::BindingMismatch);
                            }
                            found = Some(head);
                        }
                    }
                }
            }
            found.ok_or(Error::BindingMismatch)
        }
        pub(crate) fn current_head(&mut self) -> Result<TpmStateHeadV3, Error> {
            if !self.usable {
                return Err(Error::Unavailable);
            }
            let result = self.root().and_then(|root| self.resolve(root));
            if result.is_err() {
                self.usable = false;
            }
            result
        }
        pub(crate) fn compare_and_advance(
            &mut self,
            expected: TpmStateHeadV3,
            next: TpmStateHeadV3,
        ) -> Result<(), Error> {
            if !self.usable {
                return Err(Error::Unavailable);
            }
            if expected.sequence.checked_add(1) != Some(next.sequence) || next.digest == [0; 32] {
                return Err(Error::BindingMismatch);
            }
            let result = (|| {
                let previous = self.root()?;
                if self.resolve(previous)? != expected {
                    return Err(Error::BindingMismatch);
                }
                let target = self.extension(previous, next);
                let mut record = b"SVN3".to_vec();
                record.extend_from_slice(&next.sequence.to_be_bytes());
                record.extend_from_slice(&next.digest);
                record.extend_from_slice(&previous);
                record.extend_from_slice(&target);
                // Mandatory durable prepare BEFORE TPM mutation. On an ambiguous
                // TPM result, reopen reads NV and selects the matching durable slot.
                self.journal.store((next.sequence % 2) as usize, &record)?;
                let mut args = 32_u16.to_be_bytes().to_vec();
                args.extend_from_slice(&self.event(next));
                if !self.authorized(0x136, &args)?.is_empty() {
                    return Err(Error::Malformed);
                }
                if self.root()? != target {
                    return Err(Error::BindingMismatch);
                }
                Ok(())
            })();
            if result.is_err() {
                self.usable = false;
            }
            result
        }
    }
    fn decode(bytes: &[u8]) -> Result<(TpmStateHeadV3, [u8; 32], [u8; 32]), Error> {
        if bytes.len() != 108 {
            return Err(Error::Malformed);
        }
        let mut r = Reader::new(bytes);
        if r.take(4)? != b"SVN3" {
            return Err(Error::Malformed);
        }
        let sequence = u64::from_be_bytes(r.fixed()?);
        let head = TpmStateHeadV3::new(sequence, r.fixed()?)?;
        let previous = r.fixed()?;
        let next = r.fixed()?;
        r.end()?;
        Ok((head, previous, next))
    }
}
#[cfg(any(test, target_os = "linux"))]
pub(crate) use runtime::{Journal, NvAnchor};
#[cfg(test)]
#[path = "tpm_nv_tests.rs"]
pub(crate) mod tests;
