//! Isolated TPM authority. Fixed endpoint, measured peer roles, signed enrollment,
//! PCR-gated key, active-enrollment NV pin, five independent durable NV heads.
use crate::linux_tpm::Device;
use crate::linux_tpm_journal::{check_file, root_dir, DiskJournal};
use crate::tpm_nv::{Journal, NvAnchor};
use crate::tpm_wire::Reader;
use crate::{
    LinuxTpmDeploymentSignerV3, NativeDeploymentSignatureDomainV2 as Domain, TpmEnrollmentV3,
    TpmNvBindingV3, TpmSignatureEnvelopeV3, TpmSignatureErrorV3 as Error, TpmSignatureRequestV3,
    TpmStateHeadV3, TpmStoreV3,
};
use rustix::fs::{openat, Mode, OFlags};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

const SOCKET: &str = "/run/savana-tpm/authority-v3.sock";
const REQUEST: usize = 256;
const RESPONSE: usize = 248;
const CREDENTIALS: &str = "/run/credentials/savana-tpm-authority-v3.service";
const GUARD_INDEX: u32 = 0x0150_0010;

fn now() -> Result<u64, Error> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|n| n.as_secs())
        .map_err(|_| Error::Unavailable)
}
fn read_fixed(directory: &str, name: &str, limit: u64) -> Result<Zeroizing<Vec<u8>>, Error> {
    let dir = root_dir(directory)?;
    let file = File::from(
        openat(
            &dir,
            name,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|_| Error::Unavailable)?,
    );
    check_file(&file, limit)?;
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::Unavailable)?;
    if bytes.len() as u64 > limit {
        return Err(Error::Malformed);
    }
    Ok(bytes)
}
fn credential(name: &str) -> Result<Zeroizing<[u8; 32]>, Error> {
    let bytes = read_fixed(CREDENTIALS, name, 32)?;
    Ok(Zeroizing::new(
        bytes.as_slice().try_into().map_err(|_| Error::Malformed)?,
    ))
}
fn distinct_credentials(values: &[Zeroizing<[u8; 32]>]) -> Result<(), Error> {
    if values.len() != 7
        || values
            .iter()
            .enumerate()
            .any(|(i, v)| **v == [0; 32] || values[..i].iter().any(|old| **old == **v))
    {
        return Err(Error::BindingMismatch);
    }
    Ok(())
}
struct NoJournal;
impl Journal for NoJournal {
    fn load(&self, _: usize) -> Result<Option<Vec<u8>>, Error> {
        Ok(None)
    }
    fn store(&mut self, _: usize, _: &[u8]) -> Result<(), Error> {
        Err(Error::Unavailable)
    }
}
struct Authority {
    _provisioning_lock: DiskJournal,
    enrollment: TpmEnrollmentV3,
    signer: LinuxTpmDeploymentSignerV3,
    guard: NvAnchor<Device, NoJournal>,
    stores: Vec<NvAnchor<Device, DiskJournal>>,
}
impl Authority {
    fn open() -> Result<Self, Error> {
        if !nix::unistd::geteuid().is_root() || nix::unistd::getegid().as_raw() != 0 {
            return Err(Error::Unavailable);
        }
        let provisioning_lock = DiskJournal::open(GUARD_INDEX)?;
        let root = read_fixed("/etc/savana", "tpm-v3-installer.pub", 32)?;
        let bytes = read_fixed("/etc/savana", "tpm-enrollment-v3.bin", 2048)?;
        let enrollment = TpmEnrollmentV3::verify(
            &bytes,
            root.as_slice().try_into().map_err(|_| Error::Malformed)?,
            now()?,
        )?;
        let me = crate::measure_current_linux_process_v2().map_err(|_| Error::Unavailable)?;
        if !enrollment.broker_identity().matches(me.measurement()) {
            return Err(Error::BindingMismatch);
        }
        let credentials = [
            "signing-auth",
            "enrollment-auth",
            "deployment-auth",
            "vault-auth",
            "agent-auth",
            "g4-auth",
            "connector-auth",
        ]
        .into_iter()
        .map(credential)
        .collect::<Result<Vec<_>, _>>()?;
        distinct_credentials(&credentials)?;
        let mut credentials = credentials.into_iter();
        let signer = LinuxTpmDeploymentSignerV3::open(
            enrollment.signing_binding().clone(),
            credentials.next().ok_or(Error::Unavailable)?,
        )?;
        let guard_binding = TpmNvBindingV3::new(
            GUARD_INDEX,
            TpmNvBindingV3::expected_name(GUARD_INDEX),
            enrollment.signing_binding().installation_id(),
            enrollment.digest(),
            enrollment.signing_binding().epoch(),
            enrollment.active_enrollment_root(),
            TpmStateHeadV3::GENESIS,
        )?;
        let guard = NvAnchor::open(
            Device::open()?,
            NoJournal,
            guard_binding,
            credentials.next().ok_or(Error::Unavailable)?,
        )?;
        let mut stores = Vec::new();
        for (slot, auth) in TpmStoreV3::ALL.into_iter().zip(credentials) {
            let binding = enrollment.store_binding(slot).clone();
            stores.push(NvAnchor::open(
                Device::open()?,
                DiskJournal::open(binding.index)?,
                binding,
                auth,
            )?);
        }
        let mut value = Self {
            _provisioning_lock: provisioning_lock,
            enrollment,
            signer,
            guard,
            stores,
        };
        value.check_live()?;
        Ok(value)
    }
    fn check_live(&mut self) -> Result<(), Error> {
        self.enrollment.check_time(now()?)?;
        self.guard.current_head()?; // old daemon cannot serve a superseded profile
                                    // Prove current possession under the enrolled PCR policy, including after
                                    // restart/TPM clear. A parsed public blob is not proof of possession.
        let mut nonce = [0; 32];
        getrandom::getrandom(&mut nonce).map_err(|_| Error::Unavailable)?;
        let mut h = Sha256::new();
        h.update(b"savana.tpm-authority-liveness.v3\0");
        h.update(self.enrollment.digest());
        h.update(nonce);
        let b = self.enrollment.signing_binding();
        self.signer.sign(TpmSignatureRequestV3::new(
            Domain::VerificationEvidence,
            b.installation_id(),
            b.epoch(),
            h.finalize().into(),
        )?)?;
        Ok(())
    }
    fn handle(&mut self, mut stream: UnixStream) -> Result<(), Error> {
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .map_err(|_| Error::Unavailable)?;
        stream
            .set_write_timeout(Some(Duration::from_secs(3)))
            .map_err(|_| Error::Unavailable)?;
        let peer = crate::measure_linux_peer_v2(&stream).map_err(|_| Error::Unavailable)?;
        let is_deployer = self
            .enrollment
            .proposal
            .deployer
            .matches(peer.measurement());
        let is_kernel = self.enrollment.proposal.kernel.matches(peer.measurement());
        if !is_deployer && !is_kernel {
            return Err(Error::BindingMismatch);
        }
        let mut bytes = [0; REQUEST];
        stream
            .read_exact(&mut bytes)
            .map_err(|_| Error::Unavailable)?;
        let mut extra = [0];
        if stream.read(&mut extra).map_err(|_| Error::Unavailable)? != 0 {
            return Err(Error::Malformed);
        }
        let req = Request::parse(&bytes, &self.enrollment)?;
        req.authorize(is_deployer, is_kernel)?;
        crate::linux::require_live(&peer._pidfd).map_err(|_| Error::Unavailable)?;
        self.check_live()?;
        let mut response = [0; RESPONSE];
        response[..4].copy_from_slice(b"STA3");
        response[4] = req.op;
        response[8..40].copy_from_slice(&self.enrollment.digest());
        response[40..72].copy_from_slice(&req.nonce);
        match req.op {
            1 => put_head(
                &mut response[72..112],
                self.stores[req.store as usize].current_head()?,
            ),
            2 => {
                self.stores[req.store as usize].compare_and_advance(req.expected, req.next)?;
                put_head(&mut response[72..112], req.next);
            }
            3 => {
                let b = self.enrollment.signing_binding();
                let request = TpmSignatureRequestV3::new(
                    req.domain.ok_or(Error::Malformed)?,
                    b.installation_id(),
                    b.epoch(),
                    req.payload,
                )?;
                response[72..].copy_from_slice(&self.signer.sign(request)?.to_bytes());
            }
            _ => return Err(Error::Malformed),
        }
        crate::linux::require_live(&peer._pidfd).map_err(|_| Error::Unavailable)?;
        stream
            .write_all(&response)
            .map_err(|_| Error::OperationFailed)
    }
}

fn put_head(bytes: &mut [u8], head: TpmStateHeadV3) {
    bytes[..8].copy_from_slice(&head.sequence().to_be_bytes());
    bytes[8..40].copy_from_slice(&head.digest());
}
fn head(bytes: &[u8]) -> Result<TpmStateHeadV3, Error> {
    let mut r = Reader::new(bytes);
    let value = TpmStateHeadV3::new(u64::from_be_bytes(r.fixed()?), r.fixed()?)?;
    r.end()?;
    Ok(value)
}
struct Request {
    op: u8,
    store: TpmStoreV3,
    domain: Option<Domain>,
    expected: TpmStateHeadV3,
    next: TpmStateHeadV3,
    payload: [u8; 32],
    nonce: [u8; 32],
}
impl Request {
    fn authorize(&self, is_deployer: bool, is_kernel: bool) -> Result<(), Error> {
        if is_deployer == is_kernel
            || (self.op == 3 && !is_deployer)
            || (self.op != 3 && (self.store == TpmStoreV3::Deployment) != is_deployer)
        {
            Err(Error::BindingMismatch)
        } else {
            Ok(())
        }
    }
    fn parse(bytes: &[u8; REQUEST], enrollment: &TpmEnrollmentV3) -> Result<Self, Error> {
        let b = enrollment.signing_binding();
        if &bytes[..4] != b"STA3"
            || bytes[8..40] != enrollment.digest()
            || bytes[40..72] != b.installation_id()
            || bytes[72..80] != b.epoch().to_be_bytes()
        {
            return Err(Error::BindingMismatch);
        }
        let store = TpmStoreV3::from_tag(bytes[5])?;
        if bytes[80..112] != enrollment.store_binding(store).store_id() {
            return Err(Error::BindingMismatch);
        }
        let op = bytes[4];
        let tag = u16::from_be_bytes(bytes[6..8].try_into().map_err(|_| Error::Malformed)?);
        let expected = head(&bytes[112..152])?;
        let next = head(&bytes[152..192])?;
        let payload = bytes[192..224].try_into().map_err(|_| Error::Malformed)?;
        let nonce = bytes[224..].try_into().map_err(|_| Error::Malformed)?;
        let domain = if op == 3 { Some(domain(tag)?) } else { None };
        if nonce == [0; 32]
            || !(1..=3).contains(&op)
            || (op != 3 && (tag != 0 || payload != [0; 32]))
            || (op != 2 && (expected != TpmStateHeadV3::GENESIS || next != TpmStateHeadV3::GENESIS))
            || (op == 3 && (store != TpmStoreV3::Deployment || payload == [0; 32]))
        {
            return Err(Error::Malformed);
        }
        Ok(Self {
            op,
            store,
            domain,
            expected,
            next,
            payload,
            nonce,
        })
    }
}
fn domain(tag: u16) -> Result<Domain, Error> {
    Ok(match tag {
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
        _ => return Err(Error::Malformed),
    })
}

/// Immutable trusted enrollment; no caller-configurable socket, algorithm or auth.
/// Each operation authenticates the live server and sends a fresh connection nonce.
pub struct LinuxTpmAuthorityClientV3 {
    enrollment: TpmEnrollmentV3,
    usable: bool,
}
impl LinuxTpmAuthorityClientV3 {
    pub fn new(enrollment: TpmEnrollmentV3) -> Result<Self, Error> {
        enrollment.check_time(now()?)?;
        Ok(Self {
            enrollment,
            usable: true,
        })
    }
    pub fn enrollment(&self) -> &TpmEnrollmentV3 {
        &self.enrollment
    }
    fn exchange(
        &mut self,
        op: u8,
        store: TpmStoreV3,
        tag: u16,
        expected: TpmStateHeadV3,
        next: TpmStateHeadV3,
        payload: [u8; 32],
    ) -> Result<[u8; RESPONSE], Error> {
        if !self.usable {
            return Err(Error::Unavailable);
        }
        let result = (|| {
            self.enrollment.check_time(now()?)?;
            let mut request = [0; REQUEST];
            request[..4].copy_from_slice(b"STA3");
            request[4] = op;
            request[5] = store as u8;
            request[6..8].copy_from_slice(&tag.to_be_bytes());
            request[8..40].copy_from_slice(&self.enrollment.digest());
            let b = self.enrollment.signing_binding();
            request[40..72].copy_from_slice(&b.installation_id());
            request[72..80].copy_from_slice(&b.epoch().to_be_bytes());
            request[80..112].copy_from_slice(&self.enrollment.store_binding(store).store_id());
            put_head(&mut request[112..152], expected);
            put_head(&mut request[152..192], next);
            request[192..224].copy_from_slice(&payload);
            getrandom::getrandom(&mut request[224..]).map_err(|_| Error::Unavailable)?;
            Request::parse(&request, &self.enrollment)?;
            let mut stream = UnixStream::connect(SOCKET).map_err(|_| Error::Unavailable)?;
            stream
                .set_read_timeout(Some(Duration::from_secs(60)))
                .map_err(|_| Error::Unavailable)?;
            stream
                .set_write_timeout(Some(Duration::from_secs(3)))
                .map_err(|_| Error::Unavailable)?;
            let server = crate::measure_linux_peer_v2(&stream).map_err(|_| Error::Unavailable)?;
            if !self
                .enrollment
                .broker_identity()
                .matches(server.measurement())
            {
                return Err(Error::BindingMismatch);
            }
            stream
                .write_all(&request)
                .map_err(|_| Error::OperationFailed)?;
            stream
                .shutdown(Shutdown::Write)
                .map_err(|_| Error::OperationFailed)?;
            let mut response = [0; RESPONSE];
            stream
                .read_exact(&mut response)
                .map_err(|_| Error::OperationFailed)?;
            let mut extra = [0];
            if stream
                .read(&mut extra)
                .map_err(|_| Error::OperationFailed)?
                != 0
            {
                return Err(Error::Malformed);
            }
            crate::linux::require_live(&server._pidfd).map_err(|_| Error::Unavailable)?;
            if response[..8] != [b'S', b'T', b'A', b'3', op, 0, 0, 0]
                || response[8..40] != self.enrollment.digest()
                || response[40..72] != request[224..]
                || (op != 3 && response[112..].iter().any(|b| *b != 0))
            {
                return Err(Error::Malformed);
            }
            Ok(response)
        })();
        if result.is_err() {
            self.usable = false;
        }
        result
    }
    pub fn current_head(&mut self, store: TpmStoreV3) -> Result<TpmStateHeadV3, Error> {
        let response = self.exchange(
            1,
            store,
            0,
            TpmStateHeadV3::GENESIS,
            TpmStateHeadV3::GENESIS,
            [0; 32],
        )?;
        let result = head(&response[72..112]);
        if result.is_err() {
            self.usable = false;
        }
        result
    }
    pub fn compare_and_advance(
        &mut self,
        store: TpmStoreV3,
        expected: TpmStateHeadV3,
        next: TpmStateHeadV3,
    ) -> Result<(), Error> {
        let response = self.exchange(2, store, 0, expected, next, [0; 32])?;
        if head(&response[72..112]) != Ok(next) {
            self.usable = false;
            return Err(Error::BindingMismatch);
        }
        Ok(())
    }
    pub fn sign(
        &mut self,
        request: TpmSignatureRequestV3,
    ) -> Result<TpmSignatureEnvelopeV3, Error> {
        let b = self.enrollment.signing_binding();
        if request.installation_id() != b.installation_id() || request.epoch() != b.epoch() {
            return Err(Error::BindingMismatch);
        }
        let response = self.exchange(
            3,
            TpmStoreV3::Deployment,
            request.domain() as u16,
            TpmStateHeadV3::GENESIS,
            TpmStateHeadV3::GENESIS,
            request.payload_digest(),
        )?;
        let result = (|| {
            let s = TpmSignatureEnvelopeV3::from_bytes(&response[72..])?;
            s.verify(self.enrollment.signing_binding().public(), request)?;
            Ok(s)
        })();
        if result.is_err() {
            self.usable = false;
        }
        result
    }
}

pub fn run_linux_tpm_authority_v3() -> Result<(), Error> {
    let mut authority = Authority::open()?;
    let mut listeners = crate::take_systemd_unix_listeners_v2(&["tpm-authority-v3"])
        .map_err(|_| Error::Unavailable)?;
    let (_, listener) = listeners.pop().ok_or(Error::Unavailable)?.into_parts();
    if listener
        .local_addr()
        .map_err(|_| Error::Unavailable)?
        .as_pathname()
        != Some(std::path::Path::new(SOCKET))
    {
        return Err(Error::BindingMismatch);
    }
    loop {
        let (stream, _) = listener.accept().map_err(|_| Error::Unavailable)?;
        // No request bytes, secrets, measured paths or detailed errors are logged.
        let _ = authority.handle(stream);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn authority_secrets_must_be_distinct_nonzero_and_complete() {
        let mut values: Vec<_> = (1..=7).map(|i| Zeroizing::new([i; 32])).collect();
        assert!(distinct_credentials(&values).is_ok());
        values[1] = Zeroizing::new([1; 32]);
        assert!(distinct_credentials(&values).is_err());
        values[1] = Zeroizing::new([0; 32]);
        assert!(distinct_credentials(&values).is_err());
        values.pop();
        assert!(distinct_credentials(&values).is_err());
    }
    fn request(e: &TpmEnrollmentV3, op: u8, store: TpmStoreV3) -> [u8; REQUEST] {
        let mut b = [0; REQUEST];
        b[..4].copy_from_slice(b"STA3");
        b[4] = op;
        b[5] = store as u8;
        b[8..40].copy_from_slice(&e.digest());
        b[40..72].copy_from_slice(&e.signing_binding().installation_id());
        b[72..80].copy_from_slice(&e.signing_binding().epoch().to_be_bytes());
        b[80..112].copy_from_slice(&e.store_binding(store).store_id());
        b[224..].fill(1);
        if op == 3 {
            b[6..8].copy_from_slice(&5_u16.to_be_bytes());
            b[192..224].fill(2);
        }
        b
    }
    #[test]
    fn request_roles_never_turn_kernel_into_a_signer_or_deployer_into_state_owner() {
        let e = crate::tpm_enrollment::tests::verified();
        for op in 1..=3 {
            for store in TpmStoreV3::ALL {
                let result = Request::parse(&request(&e, op, store), &e);
                if op == 3 && store != TpmStoreV3::Deployment {
                    assert!(result.is_err());
                    continue;
                }
                let r = result.unwrap();
                assert_eq!(
                    r.authorize(true, false).is_ok(),
                    store == TpmStoreV3::Deployment
                );
                assert_eq!(
                    r.authorize(false, true).is_ok(),
                    store != TpmStoreV3::Deployment
                );
                assert!(r.authorize(false, false).is_err());
                assert!(r.authorize(true, true).is_err());
            }
        }
    }
    #[test]
    fn protocol_rejects_cross_enrollment_scope_unknown_ops_and_unused_fields() {
        let e = crate::tpm_enrollment::tests::verified();
        let good = request(&e, 1, TpmStoreV3::G4);
        for offset in (0..224).filter(|i| *i != 4) {
            let mut b = good;
            b[offset] ^= 0x80;
            assert!(Request::parse(&b, &e).is_err(), "offset {offset}");
        }
        for op in [0, 4, 255] {
            let mut b = good;
            b[4] = op;
            assert!(Request::parse(&b, &e).is_err());
        }
        let mut b = good;
        b[224..].fill(0);
        assert!(Request::parse(&b, &e).is_err());
        let mut b = request(&e, 3, TpmStoreV3::Deployment);
        b[7] = 7;
        assert!(Request::parse(&b, &e).is_err());
    }
}
