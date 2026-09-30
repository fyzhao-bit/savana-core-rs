use super::*;

fn spec() -> TpmFirstInstallSpecV3 {
    TpmFirstInstallSpecV3 {
        installation: [1; 32],
        store_ids: std::array::from_fn(|i| [i as u8 + 11; 32]),
        pcr_policy: TpmPcrPolicyV3::new(0x81, Sha256::digest([0; 64]).into()).unwrap(),
        deployer: TpmClientIdentityV3::new(0, 0, [21; 32]).unwrap(),
        kernel: TpmClientIdentityV3::new(1001, 1001, [22; 32]).unwrap(),
        broker: TpmClientIdentityV3::new(0, 0, [23; 32]).unwrap(),
        not_before: 100,
        expires: 200,
    }
}
fn auth() -> [[u8; 32]; 7] {
    std::array::from_fn(|i| [i as u8 + 31; 32])
}
fn seeds() -> [[u8; 32]; 5] {
    std::array::from_fn(|i| [i as u8 + 41; 32])
}
struct Preflight {
    occupied: usize,
    calls: usize,
}
impl Transport for Preflight {
    fn exchange(&mut self, request: &[u8]) -> Result<Vec<u8>, Error> {
        assert_eq!(
            &request[6..10],
            &0x17a_u32.to_be_bytes(),
            "mutation before full vacancy check"
        );
        let occupied = self.calls == self.occupied;
        self.calls += 1;
        let mut body = vec![0, 0, 0, 0, 1];
        body.extend_from_slice(&u32::from(occupied).to_be_bytes());
        if occupied {
            body.extend_from_slice(&request[14..18]);
        }
        Ok(command(0x8001, 0, &body))
    }
}
#[test]
fn every_occupied_slot_stops_before_any_mutation() {
    for occupied in 0..7 {
        let mut t = Preflight { occupied, calls: 0 };
        assert!(prepare(&mut t, spec(), &auth(), &seeds()).is_err());
        assert_eq!(t.calls, occupied + 1);
    }
}
#[test]
fn malformed_plan_and_credentials_never_touch_tpm() {
    let mut t = Preflight {
        occupied: 0,
        calls: 0,
    };
    for bad in [[[0; 32]; 7], [[31; 32]; 7]] {
        assert!(prepare(&mut t, spec(), &bad, &seeds()).is_err());
    }
    let mut s = spec();
    s.kernel = s.deployer;
    assert!(prepare(&mut t, s, &auth(), &seeds()).is_err());
    let mut s = spec();
    s.store_ids[4] = s.store_ids[0];
    assert!(prepare(&mut t, s, &auth(), &seeds()).is_err());
    assert!(prepare(&mut t, spec(), &auth(), &[[0; 32]; 5]).is_err());
    assert_eq!(t.calls, 0);
    // Keep both closed paths compiled on non-Linux test hosts, too.
    let _ = activate::<Preflight>;
}

#[test]
fn wrong_live_pcr_stops_before_creating_objects() {
    struct WrongPcr {
        queries: usize,
    }
    impl Transport for WrongPcr {
        fn exchange(&mut self, request: &[u8]) -> Result<Vec<u8>, Error> {
            self.queries += 1;
            if self.queries <= 7 {
                assert_eq!(&request[6..10], &0x17a_u32.to_be_bytes());
                return Ok(command(0x8001, 0, &[0, 0, 0, 0, 1, 0, 0, 0, 0]));
            }
            assert_eq!(self.queries, 8, "must not mutate on wrong PCR");
            assert_eq!(&request[6..10], &0x17e_u32.to_be_bytes());
            let mut body = vec![0, 0, 0, 1];
            body.extend_from_slice(&request[10..]);
            body.extend_from_slice(&2_u32.to_be_bytes());
            for _ in 0..2 {
                sized(&mut body, &[99; 32])?;
            }
            Ok(command(0x8001, 0, &body))
        }
    }
    let mut transport = WrongPcr { queries: 0 };
    assert!(prepare(&mut transport, spec(), &auth(), &seeds()).is_err());
    assert_eq!(transport.queries, 8);
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires fresh disposable swtpm; never hardware acceptance"]
fn swtpm_first_install() {
    use ed25519_dalek::{Signer as _, SigningKey};
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    struct Emulator {
        socket: UnixStream,
        lose_guard_reply: bool,
    }
    impl Transport for Emulator {
        fn exchange(&mut self, bytes: &[u8]) -> Result<Vec<u8>, Error> {
            self.socket
                .write_all(bytes)
                .map_err(|_| Error::OperationFailed)?;
            let mut header = [0; 10];
            self.socket
                .read_exact(&mut header)
                .map_err(|_| Error::OperationFailed)?;
            let len = u32::from_be_bytes(header[2..6].try_into().unwrap()) as usize;
            assert!((10..=4096).contains(&len));
            let mut reply = header.to_vec();
            reply.resize(len, 0);
            self.socket
                .read_exact(&mut reply[10..])
                .map_err(|_| Error::OperationFailed)?;
            let rc = u32::from_be_bytes(header[6..10].try_into().unwrap());
            if rc != 0 {
                eprintln!(
                    "synthetic TPM command {:x?} response {rc:#x}",
                    &bytes[6..10]
                );
            }
            if self.lose_guard_reply
                && bytes[6..10] == 0x136_u32.to_be_bytes()
                && bytes[10..14] == GUARD_INDEX.to_be_bytes()
                && rc == 0
            {
                self.lose_guard_reply = false;
                return Err(Error::OperationFailed);
            }
            Ok(reply)
        }
    }
    assert!(std::path::Path::new("/.dockerenv").is_file());
    assert!(!std::path::Path::new("/dev/tpmrm0").exists());
    let root = std::path::PathBuf::from(std::env::var("SAVANA_TPM_FIRST_INSTALL_FIXTURE").unwrap());
    let connect = |lose_guard_reply| {
        let socket = UnixStream::connect(root.join("tpm.sock")).unwrap();
        socket
            .set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        socket
            .set_write_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        Emulator {
            socket,
            lose_guard_reply,
        }
    };
    let mut s = spec();
    s.pcr_policy = TpmPcrPolicyV3::new(
        0x81,
        Sha256::digest(std::fs::read(root.join("pcr.bin")).unwrap()).into(),
    )
    .unwrap();
    let proposal = prepare(&mut connect(false), s, &auth(), &seeds()).expect("fresh prepare");
    // Re-running cannot clear or overwrite any of the seven objects.
    assert!(prepare(&mut connect(false), spec(), &auth(), &seeds()).is_err());
    let key = SigningKey::from_bytes(&[91; 32]); // public synthetic fixture ONLY
    let bytes = proposal.attach_signature(key.sign(&proposal.signature_input()).to_bytes());
    let enrollment = TpmEnrollmentV3::verify(&bytes, key.verifying_key().to_bytes(), 150).unwrap();
    let mut wrong = auth();
    wrong[0] = [99; 32];
    assert!(activate(connect(false), &enrollment, &wrong, 150).is_err());
    nv_public(&mut connect(false), GUARD_INDEX, false).unwrap();
    assert!(activate(connect(false), &enrollment, &auth(), 200).is_err());
    nv_public(&mut connect(false), GUARD_INDEX, false).unwrap();
    // Inject a lost success reply AFTER the real TPM advances the guard.
    assert!(activate(connect(true), &enrollment, &auth(), 150).is_err());
    assert_eq!(
        nv_root(&mut connect(false), GUARD_INDEX, &auth()[1]).unwrap(),
        enrollment.active_enrollment_root()
    );
    activate(connect(false), &enrollment, &auth(), 150).expect("lost reply recovery");
    activate(connect(false), &enrollment, &auth(), 150).expect("idempotent activation");
    assert_eq!(
        nv_root(&mut connect(false), GUARD_INDEX, &auth()[1]).unwrap(),
        enrollment.active_enrollment_root()
    );
    let mut changed = proposal.clone();
    changed.kernel = TpmClientIdentityV3::new(1002, 1002, [77; 32]).unwrap();
    let changed = TpmEnrollmentV3::verify(
        &changed.attach_signature(key.sign(&changed.signature_input()).to_bytes()),
        key.verifying_key().to_bytes(),
        150,
    )
    .unwrap();
    assert!(activate(connect(false), &changed, &auth(), 150).is_err());
    assert_eq!(
        nv_root(&mut connect(false), GUARD_INDEX, &auth()[1]).unwrap(),
        enrollment.active_enrollment_root()
    );
    // The runtime anchor opens the provisioned objects without hand-built
    // fixture metadata, and reopens the same consumed head after activation.
    use crate::tpm_nv::{Journal, NvAnchor};
    #[derive(Clone, Default)]
    struct MemoryJournal(std::rc::Rc<std::cell::RefCell<[Option<Vec<u8>>; 2]>>);
    impl Journal for MemoryJournal {
        fn load(&self, slot: usize) -> Result<Option<Vec<u8>>, Error> {
            Ok(self.0.borrow()[slot].clone())
        }
        fn store(&mut self, slot: usize, bytes: &[u8]) -> Result<(), Error> {
            self.0.borrow_mut()[slot] = Some(bytes.to_vec());
            Ok(())
        }
    }
    for (i, slot) in TpmStoreV3::ALL.iter().enumerate() {
        let mut anchor = NvAnchor::open(
            connect(false),
            MemoryJournal::default(),
            enrollment.store_binding(*slot).clone(),
            Zeroizing::new(auth()[i + 2]),
        )
        .unwrap();
        assert_eq!(anchor.current_head().unwrap(), TpmStateHeadV3::GENESIS);
    }
    let journal = MemoryJournal::default();
    let consumed = TpmStateHeadV3::new(1, [88; 32]).unwrap();
    {
        let mut anchor = NvAnchor::open(
            connect(false),
            journal.clone(),
            enrollment.store_binding(TpmStoreV3::Vault).clone(),
            Zeroizing::new(auth()[3]),
        )
        .unwrap();
        anchor
            .compare_and_advance(TpmStateHeadV3::GENESIS, consumed)
            .unwrap();
    }
    let mut reopened = NvAnchor::open(
        connect(false),
        journal,
        enrollment.store_binding(TpmStoreV3::Vault).clone(),
        Zeroizing::new(auth()[3]),
    )
    .unwrap();
    assert_eq!(reopened.current_head().unwrap(), consumed);
    drop(reopened); // swtpm command socket serves one live connection at a time.
    assert_eq!(
        activate(connect(false), &enrollment, &auth(), 150),
        Err(Error::BindingMismatch)
    );
    assert_ne!(
        nv_root(&mut connect(false), TpmStoreV3::Vault.index(), &auth()[3]).unwrap(),
        initial_root(&seeds()[1])
    );
    crate::deployment_record_v3::tests::interoperability(&|| connect(false), &enrollment, &auth());
}
