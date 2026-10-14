use super::*;
use crate::tpm_wire::{command, Transport};
use std::cell::RefCell;
use std::rc::Rc;
use zeroize::Zeroizing;

#[derive(Clone, Default)]
pub(crate) struct MemoryJournal(pub Rc<RefCell<[Option<Vec<u8>>; 2]>>);
impl Journal for MemoryJournal {
    fn load(&self, slot: usize) -> Result<Option<Vec<u8>>, Error> {
        Ok(self.0.borrow()[slot].clone())
    }
    fn store(&mut self, slot: usize, bytes: &[u8]) -> Result<(), Error> {
        self.0.borrow_mut()[slot] = Some(bytes.to_vec());
        Ok(())
    }
}
pub(crate) fn fixture_binding() -> TpmNvBindingV3 {
    let mut h = Sha256::new();
    h.update([0; 32]);
    h.update([9; 32]);
    TpmNvBindingV3::new(
        0x01500020,
        TpmNvBindingV3::expected_name(0x01500020),
        [1; 32],
        [2; 32],
        3,
        h.finalize().into(),
        TpmStateHeadV3::GENESIS,
    )
    .unwrap()
}
// Test-only transport with the same serialized TPM command/response boundary.
#[derive(Clone)]
struct Mock {
    root: Rc<RefCell<[u8; 32]>>,
    writes: Rc<RefCell<usize>>,
    lose: bool,
}
impl Mock {
    fn new() -> Self {
        Self {
            root: Rc::new(RefCell::new(fixture_binding().initial_root)),
            writes: Rc::new(RefCell::new(0)),
            lose: false,
        }
    }
}
fn response(tag: u16, body: &[u8]) -> Vec<u8> {
    command(tag, 0, body)
}
impl Transport for Mock {
    fn exchange(&mut self, bytes: &[u8]) -> Result<Vec<u8>, Error> {
        let code = u32::from_be_bytes(bytes[6..10].try_into().unwrap());
        if code == 0x169 {
            let mut area = 0x01500020_u32.to_be_bytes().to_vec();
            area.extend_from_slice(&[0, 0x0b, 0x20, 4, 0, 0x44, 0, 0, 0, 32]);
            let mut body = (area.len() as u16).to_be_bytes().to_vec();
            body.extend_from_slice(&area);
            body.extend_from_slice(&34_u16.to_be_bytes());
            body.extend_from_slice(&TpmNvBindingV3::expected_name(0x01500020));
            return Ok(response(0x8001, &body));
        }
        assert_eq!(&bytes[31..63], &[8; 32]);
        let params = match code {
            0x14e => {
                assert_eq!(&bytes[63..], &[0, 32, 0, 0]);
                let mut b = vec![0, 32];
                b.extend_from_slice(&*self.root.borrow());
                b
            }
            0x136 => {
                assert_eq!(bytes.len(), 97);
                assert_eq!(&bytes[63..65], &[0, 32]);
                let mut h = Sha256::new();
                h.update(*self.root.borrow());
                h.update(&bytes[65..]);
                *self.root.borrow_mut() = h.finalize().into();
                *self.writes.borrow_mut() += 1;
                if self.lose {
                    return Err(Error::OperationFailed);
                }
                vec![]
            }
            _ => panic!("unexpected command"),
        };
        let mut body = (params.len() as u32).to_be_bytes().to_vec();
        body.extend_from_slice(&params);
        body.extend_from_slice(&[0, 0, 1, 0, 0]);
        Ok(response(0x8002, &body))
    }
}
fn auth() -> Zeroizing<[u8; 32]> {
    Zeroizing::new([8; 32])
}

#[cfg(target_os = "linux")]
pub(crate) fn interoperability<T: Transport>(connect: impl Fn() -> T) {
    let j = MemoryJournal::default();
    let first = TpmStateHeadV3::new(1, [5; 32]).unwrap();
    {
        let mut a = NvAnchor::open(connect(), j.clone(), fixture_binding(), auth()).unwrap();
        a.compare_and_advance(TpmStateHeadV3::GENESIS, first)
            .unwrap();
        assert_eq!(a.current_head().unwrap(), first);
    }
    let old = j.0.borrow().clone();
    struct Lost<T>(T);
    impl<T: Transport> Transport for Lost<T> {
        fn exchange(&mut self, bytes: &[u8]) -> Result<Vec<u8>, Error> {
            let response = self.0.exchange(bytes)?;
            if bytes[6..10] == 0x136_u32.to_be_bytes() {
                Err(Error::OperationFailed)
            } else {
                Ok(response)
            }
        }
    }
    let second = TpmStateHeadV3::new(2, [6; 32]).unwrap();
    {
        let mut a = NvAnchor::open(Lost(connect()), j.clone(), fixture_binding(), auth()).unwrap();
        assert!(a.compare_and_advance(first, second).is_err());
        assert!(a.current_head().is_err());
    }
    {
        let mut a = NvAnchor::open(connect(), j.clone(), fixture_binding(), auth()).unwrap();
        assert_eq!(a.current_head().unwrap(), second);
    }
    *j.0.borrow_mut() = old;
    assert!(NvAnchor::open(connect(), j, fixture_binding(), auth()).is_err());
}

#[test]
fn prepared_commit_recovers_lost_response_without_refund_or_replay() {
    let mut transport = Mock::new();
    transport.lose = true;
    let journal = MemoryJournal::default();
    let mut a = NvAnchor::open(
        transport.clone(),
        journal.clone(),
        fixture_binding(),
        auth(),
    )
    .unwrap();
    let next = TpmStateHeadV3::new(1, [5; 32]).unwrap();
    assert!(a
        .compare_and_advance(TpmStateHeadV3::GENESIS, next)
        .is_err());
    assert_eq!(*transport.writes.borrow(), 1);
    assert!(a.current_head().is_err());
    transport.lose = false;
    let mut recovered =
        NvAnchor::open(transport.clone(), journal, fixture_binding(), auth()).unwrap();
    assert_eq!(recovered.current_head().unwrap(), next);
    assert!(recovered
        .compare_and_advance(TpmStateHeadV3::GENESIS, next)
        .is_err());
    assert_eq!(*transport.writes.borrow(), 1);
}

#[test]
fn journal_rollback_tampering_and_same_sequence_equivocation_fail() {
    let t = Mock::new();
    let j = MemoryJournal::default();
    let mut a = NvAnchor::open(t.clone(), j.clone(), fixture_binding(), auth()).unwrap();
    let first = TpmStateHeadV3::new(1, [5; 32]).unwrap();
    a.compare_and_advance(TpmStateHeadV3::GENESIS, first)
        .unwrap();
    let old = j.0.borrow().clone();
    let second = TpmStateHeadV3::new(2, [6; 32]).unwrap();
    a.compare_and_advance(first, second).unwrap();
    assert_eq!(a.current_head().unwrap(), second);
    assert!(a
        .compare_and_advance(second, TpmStateHeadV3::new(2, [7; 32]).unwrap())
        .is_err());
    let latest = j.0.borrow().clone();
    *j.0.borrow_mut() = old;
    assert!(NvAnchor::open(t.clone(), j.clone(), fixture_binding(), auth()).is_err());
    *j.0.borrow_mut() = latest;
    j.0.borrow_mut()[0].as_mut().unwrap()[12] ^= 1;
    assert!(NvAnchor::open(t, j, fixture_binding(), auth()).is_err());
}

#[test]
fn failed_durable_prepare_never_mutates_tpm_and_pending_does_not_auto_commit() {
    struct Fail;
    impl Journal for Fail {
        fn load(&self, _: usize) -> Result<Option<Vec<u8>>, Error> {
            Ok(None)
        }
        fn store(&mut self, _: usize, _: &[u8]) -> Result<(), Error> {
            Err(Error::OperationFailed)
        }
    }
    let t = Mock::new();
    let mut a = NvAnchor::open(t.clone(), Fail, fixture_binding(), auth()).unwrap();
    assert!(a
        .compare_and_advance(
            TpmStateHeadV3::GENESIS,
            TpmStateHeadV3::new(1, [5; 32]).unwrap()
        )
        .is_err());
    assert_eq!(*t.writes.borrow(), 0);
    let j = MemoryJournal::default();
    j.0.borrow_mut()[1] = Some(vec![0; 108]);
    let mut a = NvAnchor::open(t.clone(), j, fixture_binding(), auth()).unwrap();
    assert_eq!(a.current_head().unwrap(), TpmStateHeadV3::GENESIS);
    assert_eq!(*t.writes.borrow(), 0);
}

#[test]
fn namespace_and_public_template_are_bound_and_exhaustion_fails_closed() {
    let t = Mock::new();
    let j = MemoryJournal::default();
    let mut a = NvAnchor::open(t.clone(), j.clone(), fixture_binding(), auth()).unwrap();
    a.compare_and_advance(
        TpmStateHeadV3::GENESIS,
        TpmStateHeadV3::new(1, [4; 32]).unwrap(),
    )
    .unwrap();
    let mut wrong = fixture_binding();
    wrong.store = [3; 32];
    assert!(NvAnchor::open(t.clone(), j.clone(), wrong, auth()).is_err());
    let mut wrong = fixture_binding();
    wrong.epoch = 4;
    assert!(NvAnchor::open(t.clone(), j.clone(), wrong, auth()).is_err());
    assert!(a
        .compare_and_advance(
            TpmStateHeadV3::new(u64::MAX, [1; 32]).unwrap(),
            TpmStateHeadV3::GENESIS
        )
        .is_err());
    assert_eq!(*t.writes.borrow(), 1);
    assert!(TpmNvBindingV3::new(
        0x1500020,
        [0; 34],
        [1; 32],
        [2; 32],
        3,
        [3; 32],
        TpmStateHeadV3::GENESIS
    )
    .is_err());
}
