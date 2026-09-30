//! Fixed Linux kernel TPM resource-manager device. No TCTI environment, TCP,
//! shell command, key export, simulator option or software fallback.
use crate::tpm_signature_v3::{
    TpmSignatureEnvelopeV3, TpmSignatureErrorV3 as Error, TpmSignatureRequestV3,
    TpmSigningBindingV3,
};
use crate::tpm_wire::{Signer, Transport, MAX_RESPONSE};
use rustix::event::{poll, PollFd, PollFlags, Timespec};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

/// A TPM-resident sign-only key capability. This does NOT implement the legacy
/// V2 Ed25519 trait or certify rollback/remote attestation readiness. A matching
/// PCR policy is mandatory and is evaluated by the TPM on every signature.
pub struct LinuxTpmDeploymentSignerV3 {
    signer: Signer<Device>,
}
impl LinuxTpmDeploymentSignerV3 {
    /// `binding` must come from trusted provisioning, never discovery/TOFU.
    /// Authorization is consumed/zeroized; it is not the ECC private key.
    pub fn open(binding: TpmSigningBindingV3, auth: Zeroizing<[u8; 32]>) -> Result<Self, Error> {
        if binding.pcr_policy().is_none() {
            return Err(Error::BindingMismatch);
        }
        Ok(Self {
            signer: Signer::open(Device::open()?, binding, auth)?,
        })
    }
    pub fn sign(
        &mut self,
        request: TpmSignatureRequestV3,
    ) -> Result<TpmSignatureEnvelopeV3, Error> {
        self.signer.sign(request)
    }
}

pub(crate) struct Device(File);
impl Device {
    pub(crate) fn open() -> Result<Self, Error> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC | nix::libc::O_NONBLOCK)
            .open("/dev/tpmrm0")
            .map_err(|_| Error::Unavailable)?;
        let m = file.metadata().map_err(|_| Error::Unavailable)?;
        if !m.file_type().is_char_device() || m.uid() != 0 || m.mode() & 0o007 != 0 {
            return Err(Error::Unavailable);
        }
        // The fixed node must be the kernel's tpmrm0, not a different character
        // device placed at that path. sysfs/device namespace is trusted OS state.
        let mut dev = String::new();
        File::open("/sys/class/tpmrm/tpmrm0/dev")
            .map_err(|_| Error::Unavailable)?
            .take(64)
            .read_to_string(&mut dev)
            .map_err(|_| Error::Unavailable)?;
        let expected = format!(
            "{}:{}",
            nix::sys::stat::major(m.rdev()),
            nix::sys::stat::minor(m.rdev())
        );
        if dev.trim() != expected {
            return Err(Error::Unavailable);
        }
        Ok(Self(file))
    }
}

impl Transport for Device {
    fn exchange(&mut self, command: &[u8]) -> Result<Vec<u8>, Error> {
        let deadline = Instant::now() + Duration::from_secs(10);
        // TPM device writes are one complete command, not a byte stream. A short
        // write or ambiguous failure poisons the signer; no automatic replay.
        if self.0.write(command).map_err(|_| Error::OperationFailed)? != command.len() {
            return Err(Error::OperationFailed);
        }
        loop {
            let mut bytes = [0; MAX_RESPONSE];
            match self.0.read(&mut bytes) {
                Ok(n) if n >= 10 => return Ok(bytes[..n].to_vec()),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    let left = deadline
                        .checked_duration_since(Instant::now())
                        .ok_or(Error::OperationFailed)?;
                    let timeout = Timespec::try_from(left).map_err(|_| Error::OperationFailed)?;
                    let mut fds = [PollFd::new(&self.0, PollFlags::IN)];
                    let count =
                        poll(&mut fds, Some(&timeout)).map_err(|_| Error::OperationFailed)?;
                    if count == 0 || !fds[0].revents().contains(PollFlags::IN) {
                        return Err(Error::OperationFailed);
                    }
                }
                _ => return Err(Error::OperationFailed),
            }
        }
    }
}
