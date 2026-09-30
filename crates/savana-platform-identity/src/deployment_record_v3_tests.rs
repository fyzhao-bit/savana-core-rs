use super::runtime::{Authority, Journal, Storage};
use super::*;
use p256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey};
use std::cell::{Cell, RefCell};
use std::rc::Rc;

#[derive(Clone)]
struct TestAuthority {
    enrollment: TpmEnrollmentV3,
    head: Rc<Cell<TpmStateHeadV3>>,
    signs: Rc<Cell<usize>>,
    advances: Rc<Cell<usize>>,
    lose_advance: Rc<Cell<bool>>,
    fail_advance: Rc<Cell<bool>>,
}
impl TestAuthority {
    fn new() -> Self {
        Self {
            enrollment: crate::tpm_enrollment::tests::verified(),
            head: Rc::new(Cell::new(TpmStateHeadV3::GENESIS)),
            signs: Rc::new(Cell::new(0)),
            advances: Rc::new(Cell::new(0)),
            lose_advance: Rc::new(Cell::new(false)),
            fail_advance: Rc::new(Cell::new(false)),
        }
    }
}
impl Authority for TestAuthority {
    fn enrollment(&self) -> &TpmEnrollmentV3 {
        &self.enrollment
    }
    fn head(&mut self) -> Result<TpmStateHeadV3, Error> {
        Ok(self.head.get())
    }
    fn sign(&mut self, request: TpmSignatureRequestV3) -> Result<TpmSignatureEnvelopeV3, Error> {
        self.signs.set(self.signs.get() + 1);
        let key = SigningKey::from_bytes((&[7; 32]).into()).unwrap();
        let public = self.enrollment.signing_binding().public();
        let sig: Signature = key.sign_prehash(&request.prehash(public.key_id())).unwrap();
        TpmSignatureEnvelopeV3::from_tpm_signature(request, public, sig)
    }
    fn advance(&mut self, expected: TpmStateHeadV3, next: TpmStateHeadV3) -> Result<(), Error> {
        if self.head.get() != expected || self.fail_advance.replace(false) {
            return Err(Error::OperationFailed);
        }
        self.head.set(next);
        self.advances.set(self.advances.get() + 1);
        if self.lose_advance.replace(false) {
            Err(Error::OperationFailed)
        } else {
            Ok(())
        }
    }
}
type Archive = std::collections::BTreeMap<(u64, [u8; 32]), Vec<u8>>;
#[derive(Clone, Default)]
struct Memory {
    slots: Rc<RefCell<[Option<Vec<u8>>; 2]>>,
    fail: Rc<Cell<u8>>,
    archive: Rc<RefCell<Archive>>,
    fail_archive: Rc<Cell<u8>>,
}
impl Storage for Memory {
    fn read_archive(&self, head: TpmStateHeadV3) -> Result<Option<Vec<u8>>, Error> {
        Ok(self
            .archive
            .borrow()
            .get(&(head.sequence(), head.digest()))
            .cloned())
    }
    fn write_archive(&mut self, head: TpmStateHeadV3, bytes: &[u8]) -> Result<(), Error> {
        let fault = self.fail_archive.replace(0);
        if fault == 1 {
            return Err(Error::OperationFailed);
        }
        let mut archive = self.archive.borrow_mut();
        let key = (head.sequence(), head.digest());
        if let Some(old) = archive.get(&key) {
            if old != bytes {
                return Err(Error::BindingMismatch);
            }
        } else {
            archive.insert(key, bytes.to_vec());
        }
        if fault == 2 {
            Err(Error::OperationFailed)
        } else {
            Ok(())
        }
    }
    fn read(&self, slot: usize) -> Result<Option<Vec<u8>>, Error> {
        Ok(self.slots.borrow()[slot].clone())
    }
    fn write(&mut self, slot: usize, bytes: &[u8]) -> Result<(), Error> {
        let failure = self.fail.replace(0);
        if failure == 1 {
            return Err(Error::OperationFailed);
        }
        self.slots.borrow_mut()[slot] = Some(bytes.to_vec());
        if failure == 2 {
            Err(Error::OperationFailed)
        } else {
            Ok(())
        }
    }
}
fn scope() -> DeploymentRecordScopeV3 {
    DeploymentRecordScopeV3::new(Domain::LedgerActivation, 1, [0; 32]).unwrap()
}
fn open(a: &TestAuthority, s: &Memory) -> Journal<TestAuthority, Memory> {
    Journal::open(a.clone(), s.clone(), 150).unwrap()
}

#[test]
fn actual_signed_bytes_advance_and_reopen_across_all_purposes() {
    let a = TestAuthority::new();
    let s = Memory::default();
    let mut previous = TpmStateHeadV3::GENESIS;
    for (i, tag) in [5, 6, 8, 9, 10, 13, 17, 18, 21, 22, 25, 26, 27]
        .iter()
        .enumerate()
    {
        let scope = DeploymentRecordScopeV3::new(domain(*tag).unwrap(), 2, [9; 32]).unwrap();
        let payload = [i as u8 + 1; 64];
        let record = open(&a, &s).append(previous, scope, &payload, 150).unwrap();
        assert_eq!(record.authenticated_payload(), payload);
        VerifiedDeploymentRecordEnvelopeV3::verify_for(
            record.canonical_bytes(),
            &a.enrollment,
            scope,
            previous,
            150,
        )
        .unwrap();
        let snapshot = open(&a, &s).snapshot(150).unwrap();
        assert_eq!(snapshot.head(), record.head());
        assert!(snapshot.prepared().is_none());
        assert_eq!(
            snapshot.committed().unwrap().canonical_bytes(),
            record.canonical_bytes()
        );
        previous = record.head();
    }
    assert_eq!(a.advances.get(), 13);
    let history = open(&a, &s).history(150).unwrap();
    assert_eq!(history.len(), 13);
    assert_eq!(history.last().unwrap().head(), previous);
}

#[test]
fn archive_failure_never_advances_and_missing_ancestry_never_reopens() {
    for fault in [1, 2] {
        let a = TestAuthority::new();
        let s = Memory::default();
        s.fail_archive.set(fault);
        assert!(open(&a, &s)
            .append(TpmStateHeadV3::GENESIS, scope(), b"one", 150)
            .is_err());
        assert_eq!(a.head.get(), TpmStateHeadV3::GENESIS);
        assert_eq!(a.advances.get(), 0);
        assert!(open(&a, &s).history(150).unwrap().is_empty());
        let first = open(&a, &s)
            .append(TpmStateHeadV3::GENESIS, scope(), b"one", 150)
            .unwrap();
        let second = open(&a, &s)
            .append(first.head(), scope(), b"two", 150)
            .unwrap();
        open(&a, &s)
            .append(second.head(), scope(), b"three", 150)
            .unwrap();
        // The first record has left A/B storage, but is still required history.
        let key = (first.head().sequence(), first.head().digest());
        let original = s.archive.borrow_mut().remove(&key).unwrap();
        assert!(Journal::open(a.clone(), s.clone(), 150).is_err());
        s.archive
            .borrow_mut()
            .insert(key, b"replaced history".to_vec());
        assert!(Journal::open(a.clone(), s.clone(), 150).is_err());
        s.archive.borrow_mut().insert(key, original);
        assert_eq!(open(&a, &s).history(150).unwrap().len(), 3);
    }
}

#[test]
fn signed_context_and_payload_cannot_be_reinterpreted() {
    let a = TestAuthority::new();
    let s = Memory::default();
    let record = open(&a, &s)
        .append(TpmStateHeadV3::GENESIS, scope(), b"evidence", 150)
        .unwrap();
    let bytes = record.canonical_bytes();
    for index in [
        0,
        4,
        6,
        8,
        40,
        72,
        80,
        112,
        120,
        152,
        160,
        192,
        200,
        204,
        bytes.len() - 1,
    ] {
        let mut changed = bytes.to_vec();
        changed[index] ^= 1;
        assert!(VerifiedDeploymentRecordEnvelopeV3::verify_for(
            &changed,
            &a.enrollment,
            scope(),
            TpmStateHeadV3::GENESIS,
            150
        )
        .is_err());
    }
    for changed in [
        DeploymentRecordScopeV3::new(Domain::LedgerSlot, 1, [0; 32]).unwrap(),
        DeploymentRecordScopeV3::new(Domain::LedgerActivation, 2, [0; 32]).unwrap(),
        DeploymentRecordScopeV3::new(Domain::LedgerActivation, 1, [1; 32]).unwrap(),
    ] {
        assert!(VerifiedDeploymentRecordEnvelopeV3::verify_for(
            bytes,
            &a.enrollment,
            changed,
            TpmStateHeadV3::GENESIS,
            150
        )
        .is_err());
    }
    for now in [99, 149, 200, u64::MAX] {
        assert!(VerifiedDeploymentRecordEnvelopeV3::verify_for(
            bytes,
            &a.enrollment,
            scope(),
            TpmStateHeadV3::GENESIS,
            now
        )
        .is_err());
    }
    for bad in [
        b"legacy-v2".to_vec(),
        [bytes, &[0]].concat(),
        bytes[..bytes.len() - 1].to_vec(),
        vec![0; MAX_RECORD + 1],
    ] {
        assert!(VerifiedDeploymentRecordEnvelopeV3::verify_for(
            &bad,
            &a.enrollment,
            scope(),
            TpmStateHeadV3::GENESIS,
            150
        )
        .is_err());
    }
}

#[test]
fn precommit_failure_retains_pending_but_never_activates_it() {
    for failure in [1, 2, 3] {
        let a = TestAuthority::new();
        let s = Memory::default();
        let mut journal = open(&a, &s);
        if failure == 3 {
            a.fail_advance.set(true);
        } else {
            s.fail.set(failure);
        }
        assert!(journal
            .append(TpmStateHeadV3::GENESIS, scope(), b"original", 150)
            .is_err());
        assert!(journal.snapshot(150).is_err());
        assert_eq!(a.advances.get(), 0);
        let snap = open(&a, &s).snapshot(150).unwrap();
        assert!(snap.committed().is_none());
        assert_eq!(snap.prepared().is_some(), failure != 1);
        let prepared = snap.prepared().map(|r| r.canonical_bytes().to_vec());
        if prepared.is_some() {
            assert!(open(&a, &s)
                .append(TpmStateHeadV3::GENESIS, scope(), b"replacement", 150)
                .is_err());
        }
        let done = open(&a, &s)
            .append(TpmStateHeadV3::GENESIS, scope(), b"original", 151)
            .unwrap();
        if let Some(prepared) = prepared {
            assert_eq!(done.canonical_bytes(), prepared);
            assert_eq!(a.signs.get(), 1);
        }
        assert_eq!(a.advances.get(), 1);
    }
}

#[test]
fn ambiguous_commit_reopens_without_replay_or_refund() {
    let a = TestAuthority::new();
    let s = Memory::default();
    let mut journal = open(&a, &s);
    a.lose_advance.set(true);
    assert!(journal
        .append(TpmStateHeadV3::GENESIS, scope(), b"consumed", 150)
        .is_err());
    assert!(journal
        .append(TpmStateHeadV3::GENESIS, scope(), b"consumed", 150)
        .is_err());
    let snap = open(&a, &s).snapshot(150).unwrap();
    assert_eq!(snap.head().sequence(), 1);
    assert_eq!(
        snap.committed().unwrap().authenticated_payload(),
        b"consumed"
    );
    assert!(snap.prepared().is_none());
    assert!(open(&a, &s)
        .append(TpmStateHeadV3::GENESIS, scope(), b"consumed", 150)
        .is_err());
    assert_eq!(a.advances.get(), 1);
    assert_eq!(a.signs.get(), 1);
}

#[test]
fn rollback_missing_committed_record_and_wrong_slot_fail_closed() {
    let a = TestAuthority::new();
    let s = Memory::default();
    let first = open(&a, &s)
        .append(TpmStateHeadV3::GENESIS, scope(), b"one", 150)
        .unwrap();
    let old = s.slots.borrow().clone();
    let second = open(&a, &s)
        .append(first.head(), scope(), b"two", 150)
        .unwrap();
    let current = s.slots.borrow().clone();
    *s.slots.borrow_mut() = old;
    assert!(Journal::open(a.clone(), s.clone(), 150).is_err());
    *s.slots.borrow_mut() = [None, None];
    assert!(Journal::open(a.clone(), s.clone(), 150).is_err());
    *s.slots.borrow_mut() = [current[1].clone(), current[0].clone()];
    assert!(Journal::open(a.clone(), s.clone(), 150).is_err());
    *s.slots.borrow_mut() = current;
    assert_eq!(open(&a, &s).snapshot(150).unwrap().head(), second.head());
    assert_eq!(a.advances.get(), 2);
}

#[test]
fn invalid_input_never_signs_or_advances() {
    let a = TestAuthority::new();
    let s = Memory::default();
    for payload in [vec![], vec![0; MAX_PAYLOAD + 1]] {
        assert!(open(&a, &s)
            .append(TpmStateHeadV3::GENESIS, scope(), &payload, 150)
            .is_err());
    }
    assert_eq!(a.signs.get(), 0);
    assert_eq!(a.advances.get(), 0);
    assert!(DeploymentRecordScopeV3::new(Domain::LedgerSlot, 0, [0; 32]).is_err());
}

// Called only by the explicitly ignored fresh-TPM test. Actual policy Sign and
// NV_Extend run through the production wire code; disk slots remain synthetic.
#[cfg(target_os = "linux")]
pub(crate) fn interoperability<T: crate::tpm_wire::Transport>(
    connect: &impl Fn() -> T,
    enrollment: &TpmEnrollmentV3,
    auth: &[[u8; 32]; 7],
) {
    use crate::tpm_nv::{tests::MemoryJournal, NvAnchor};
    use crate::tpm_wire::Signer;
    use zeroize::Zeroizing;
    struct EmulatorAuthority<'a, F> {
        connect: &'a F,
        enrollment: &'a TpmEnrollmentV3,
        auth: &'a [[u8; 32]; 7],
        nv: MemoryJournal,
        lose: &'a Cell<bool>,
    }
    impl<T: crate::tpm_wire::Transport, F: Fn() -> T> Authority for EmulatorAuthority<'_, F> {
        fn enrollment(&self) -> &TpmEnrollmentV3 {
            self.enrollment
        }
        fn head(&mut self) -> Result<TpmStateHeadV3, Error> {
            NvAnchor::open(
                (self.connect)(),
                self.nv.clone(),
                self.enrollment
                    .store_binding(TpmStoreV3::Deployment)
                    .clone(),
                Zeroizing::new(self.auth[2]),
            )?
            .current_head()
        }
        fn sign(
            &mut self,
            request: TpmSignatureRequestV3,
        ) -> Result<TpmSignatureEnvelopeV3, Error> {
            Signer::open(
                (self.connect)(),
                self.enrollment.signing_binding().clone(),
                Zeroizing::new(self.auth[0]),
            )?
            .sign(request)
        }
        fn advance(&mut self, expected: TpmStateHeadV3, next: TpmStateHeadV3) -> Result<(), Error> {
            NvAnchor::open(
                (self.connect)(),
                self.nv.clone(),
                self.enrollment
                    .store_binding(TpmStoreV3::Deployment)
                    .clone(),
                Zeroizing::new(self.auth[2]),
            )?
            .compare_and_advance(expected, next)?;
            if self.lose.replace(false) {
                Err(Error::OperationFailed)
            } else {
                Ok(())
            }
        }
    }
    let nv = MemoryJournal::default();
    let storage = Memory::default();
    let lose = Cell::new(false);
    let authority = || EmulatorAuthority {
        connect,
        enrollment,
        auth,
        nv: nv.clone(),
        lose: &lose,
    };
    let mut j = Journal::open(authority(), storage.clone(), 150).unwrap();
    let first = j
        .append(
            TpmStateHeadV3::GENESIS,
            scope(),
            b"synthetic-deployment-evidence",
            150,
        )
        .unwrap();
    drop(j);
    let mut j = Journal::open(authority(), storage.clone(), 150).unwrap();
    assert_eq!(j.snapshot(150).unwrap().head(), first.head());
    lose.set(true);
    assert!(j
        .append(first.head(), scope(), b"synthetic-commit-evidence", 150)
        .is_err());
    drop(j);
    let mut recovered = Journal::open(authority(), storage.clone(), 150).unwrap();
    let snap = recovered.snapshot(150).unwrap();
    assert_eq!(snap.head().sequence(), 2);
    assert_eq!(
        snap.committed().unwrap().authenticated_payload(),
        b"synthetic-commit-evidence"
    );
    assert_eq!(recovered.history(150).unwrap().len(), 2);
    assert!(recovered
        .append(first.head(), scope(), b"synthetic-commit-evidence", 150)
        .is_err());
    drop(recovered);
    storage.slots.borrow_mut()[0] = None;
    assert!(Journal::open(authority(), storage, 150).is_err());
}
