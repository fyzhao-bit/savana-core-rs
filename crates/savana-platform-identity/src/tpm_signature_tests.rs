use super::*;
use crate::tpm_wire::{Signer, Transport};
use p256::ecdsa::{signature::hazmat::PrehashSigner, SigningKey};
use std::cell::Cell;
use std::rc::Rc;
use zeroize::Zeroizing;

fn key() -> SigningKey {
    SigningKey::from_bytes((&[7; 32]).into()).unwrap()
}
fn public(k: &SigningKey) -> TpmSigningPublicV3 {
    let mut area = Vec::new();
    area.extend_from_slice(&[0, 0x23, 0, 0x0b]);
    area.extend_from_slice(&KEY_ATTRIBUTES.to_be_bytes());
    area.extend_from_slice(&[0, 0, 0, 0x10, 0, 0x18, 0, 0x0b, 0, 3, 0, 0x10]);
    let point = k.verifying_key().to_encoded_point(false);
    for coordinate in [point.x().unwrap(), point.y().unwrap()] {
        area.extend_from_slice(&32_u16.to_be_bytes());
        area.extend_from_slice(coordinate);
    }
    let mut bytes = (area.len() as u16).to_be_bytes().to_vec();
    bytes.extend_from_slice(&area);
    TpmSigningPublicV3::from_tpm2b_public(&bytes).unwrap()
}
fn request() -> TpmSignatureRequestV3 {
    TpmSignatureRequestV3::new(Domain::LedgerActivation, [1; 32], 3, [2; 32]).unwrap()
}
fn binding(p: TpmSigningPublicV3) -> TpmSigningBindingV3 {
    let mut q = [9; 34];
    q[..2].copy_from_slice(&[0, 0x0b]);
    TpmSigningBindingV3::new(p, q, 0x8101_0002, [1; 32], 3).unwrap()
}
fn signed() -> (TpmSignatureEnvelopeV3, TpmSigningPublicV3) {
    let key = key();
    let public = public(&key);
    let req = request();
    let signature: Signature = key.sign_prehash(&req.prehash(public.key_id())).unwrap();
    (
        TpmSignatureEnvelopeV3::from_tpm_signature(req, &public, signature).unwrap(),
        public,
    )
}

#[test]
fn suite_roundtrips_and_binds_every_context_field() {
    let (s, p) = signed();
    let restored = TpmSignatureEnvelopeV3::from_bytes(&s.to_bytes()).unwrap();
    let verified = restored.verify(&p, request()).unwrap();
    assert_eq!(verified.request(), request());
    assert_eq!(verified.key_id(), p.key_id());
    for wrong in [
        TpmSignatureRequestV3::new(Domain::LedgerSlot, [1; 32], 3, [2; 32]).unwrap(),
        TpmSignatureRequestV3::new(Domain::LedgerActivation, [5; 32], 3, [2; 32]).unwrap(),
        TpmSignatureRequestV3::new(Domain::LedgerActivation, [1; 32], 4, [2; 32]).unwrap(),
        TpmSignatureRequestV3::new(Domain::LedgerActivation, [1; 32], 3, [5; 32]).unwrap(),
    ] {
        assert!(restored.verify(&p, wrong).is_err());
        // Even replacing the declared expected request cannot validate the old signature.
        let mut changed = restored.clone();
        changed.request = wrong;
        assert!(changed.verify(&p, wrong).is_err());
    }
    let other = public(&SigningKey::from_bytes((&[8; 32]).into()).unwrap());
    assert!(restored.verify(&other, request()).is_err());
}

#[test]
fn all_thirteen_deployment_domains_are_pairwise_separated() {
    let domains = [
        Domain::LedgerActivation,
        Domain::InstallationEpochActivation,
        Domain::StoreCompatibility,
        Domain::VerificationEvidence,
        Domain::CommitAttestation,
        Domain::EvidenceGcCheckpoint,
        Domain::RollbackVerificationEvidence,
        Domain::RollbackVerificationAttestation,
        Domain::LedgerSlot,
        Domain::InstallationEvidenceEnvelope,
        Domain::DurableDeploymentTransactionCore,
        Domain::DurableDeploymentTransactionRecord,
        Domain::RecoveryRollbackReadinessEvidence,
    ];
    let key = key();
    let p = public(&key);
    for domain in domains {
        let req = TpmSignatureRequestV3::new(domain, [1; 32], 3, [2; 32]).unwrap();
        let raw: Signature = key.sign_prehash(&req.prehash(p.key_id())).unwrap();
        let signature = TpmSignatureEnvelopeV3::from_tpm_signature(req, &p, raw).unwrap();
        let signature = TpmSignatureEnvelopeV3::from_bytes(&signature.to_bytes()).unwrap();
        for other in domains {
            let expected = TpmSignatureRequestV3::new(other, [1; 32], 3, [2; 32]).unwrap();
            assert_eq!(signature.verify(&p, expected).is_ok(), other == domain);
        }
    }
}

#[test]
fn wire_rejects_downgrade_unknown_suite_domain_and_noncanonical_lengths() {
    let (signed, _) = signed();
    let bytes = signed.to_bytes();
    for offset in [0, 3, 4, 5, 6, 7] {
        let mut bad = bytes;
        bad[offset] = 0xff;
        assert!(TpmSignatureEnvelopeV3::from_bytes(&bad).is_err());
    }
    for n in 0..bytes.len() {
        assert!(TpmSignatureEnvelopeV3::from_bytes(&bytes[..n]).is_err());
    }
    let mut extended = bytes.to_vec();
    extended.push(0);
    assert!(TpmSignatureEnvelopeV3::from_bytes(&extended).is_err());
    let mut old_suite = bytes;
    old_suite[5] = 1;
    assert!(TpmSignatureEnvelopeV3::from_bytes(&old_suite).is_err());
}

#[test]
fn high_s_zero_and_tampered_signatures_are_rejected() {
    let (s, p) = signed();
    let mut b = s.to_bytes();
    let low = Signature::from_slice(&b[112..]).unwrap();
    let high = Signature::from_scalars(low.r().to_bytes(), (-low.s()).to_bytes()).unwrap();
    b[112..].copy_from_slice(&high.to_bytes());
    assert!(TpmSignatureEnvelopeV3::from_bytes(&b).is_err());
    b[112..].fill(0);
    assert!(TpmSignatureEnvelopeV3::from_bytes(&b).is_err());
    b = s.to_bytes();
    b[114] ^= 1;
    if let Ok(t) = TpmSignatureEnvelopeV3::from_bytes(&b) {
        assert!(t.verify(&p, request()).is_err());
    }
}

#[test]
fn exact_nonexportable_signing_template_is_required() {
    let p = public(&key());
    let b = p.tpm2b_public();
    assert_eq!(TpmSigningPublicV3::from_tpm2b_public(&b).unwrap(), p);
    // Every header bit is locked, including nameAlg, fixedTPM/fixedParent,
    // sensitiveDataOrigin, signing/decryption/policy and curve/hash selectors.
    for offset in 2..22 {
        let mut bad = b.clone();
        bad[offset] ^= 1;
        assert!(
            TpmSigningPublicV3::from_tpm2b_public(&bad).is_err(),
            "offset {offset}"
        );
    }
    for n in 0..b.len() {
        assert!(TpmSigningPublicV3::from_tpm2b_public(&b[..n]).is_err());
    }
    let mut bad = b.clone();
    bad.push(0);
    assert!(TpmSigningPublicV3::from_tpm2b_public(&bad).is_err());
    let mut bad = b;
    bad[24..56].fill(0);
    bad[58..].fill(0);
    assert!(TpmSigningPublicV3::from_tpm2b_public(&bad).is_err());
}

#[test]
fn empty_context_and_transient_handle_cannot_be_enrolled() {
    assert!(TpmSignatureRequestV3::new(Domain::LedgerSlot, [0; 32], 1, [2; 32]).is_err());
    assert!(TpmSignatureRequestV3::new(Domain::LedgerSlot, [1; 32], 0, [2; 32]).is_err());
    assert!(TpmSignatureRequestV3::new(Domain::LedgerSlot, [1; 32], 1, [0; 32]).is_err());
    assert!(TpmSigningBindingV3::new(public(&key()), [0; 34], 0x8101_0002, [1; 32], 1).is_err());
    let b = binding(public(&key()));
    for handle in [0, 0x8000_0001, 0x8200_0000] {
        assert!(
            TpmSigningBindingV3::new(b.public.clone(), b.qualified_name, handle, [1; 32], 1)
                .is_err()
        );
    }
}

fn response(tag: u16, body: &[u8]) -> Vec<u8> {
    let mut b = tag.to_be_bytes().to_vec();
    b.extend_from_slice(&((10 + body.len()) as u32).to_be_bytes());
    b.extend_from_slice(&[0; 4]);
    b.extend_from_slice(body);
    b
}
struct SoftwareFixture {
    calls: Rc<Cell<usize>>,
    fail_sign: bool,
    corrupt_signature: bool,
}
impl Transport for SoftwareFixture {
    fn exchange(&mut self, command: &[u8]) -> Result<Vec<u8>, TpmSignatureErrorV3> {
        self.calls.set(self.calls.get() + 1);
        let mut r = Reader::new(command);
        let tag = r.u16()?;
        assert_eq!(r.u32()? as usize, command.len());
        let code = r.u32()?;
        assert_eq!(r.u32()?, 0x8101_0002);
        let p = public(&key());
        if code == 0x173 {
            assert_eq!(tag, 0x8001);
            r.end()?;
            let mut bytes = p.tpm2b_public();
            bytes.extend_from_slice(&34_u16.to_be_bytes());
            bytes.extend_from_slice(p.name());
            bytes.extend_from_slice(&34_u16.to_be_bytes());
            bytes.extend_from_slice(&binding(p).qualified_name);
            return Ok(response(0x8001, &bytes));
        }
        assert_eq!(code, 0x15d);
        assert_eq!(tag, 0x8002);
        assert_eq!(r.u32()?, 41);
        assert_eq!(r.u32()?, 0x4000_0009);
        assert!(r.sized()?.is_empty());
        assert_eq!(r.take(1)?, [0]);
        assert_eq!(r.sized()?, [6; 32]);
        let digest = r.sized()?;
        assert_eq!(digest, request().prehash(p.key_id()));
        assert_eq!(r.take(4)?, [0, 0x18, 0, 0x0b]);
        assert_eq!(r.take(8)?, [0x80, 0x24, 0x40, 0, 0, 7, 0, 0]);
        r.end()?;
        if self.fail_sign {
            return Err(TpmSignatureErrorV3::OperationFailed);
        }
        let k = if self.corrupt_signature {
            SigningKey::from_bytes((&[8; 32]).into()).unwrap()
        } else {
            key()
        };
        let sig: Signature = k.sign_prehash(digest).unwrap();
        let mut body = 72_u32.to_be_bytes().to_vec();
        body.extend_from_slice(&[0, 0x18, 0, 0x0b]);
        for scalar in [sig.r().to_bytes(), sig.s().to_bytes()] {
            body.extend_from_slice(&32_u16.to_be_bytes());
            body.extend_from_slice(&scalar);
        }
        body.extend_from_slice(&[0, 0, 1, 0, 0]);
        Ok(response(0x8002, &body))
    }
}

#[test]
fn device_command_signs_exactly_one_prehash_and_verifies_result() {
    let calls = Rc::new(Cell::new(0));
    let p = public(&key());
    let fixture = SoftwareFixture {
        calls: calls.clone(),
        fail_sign: false,
        corrupt_signature: false,
    };
    let mut signer = Signer::open(fixture, binding(p.clone()), Zeroizing::new([6; 32])).unwrap();
    let signed = signer.sign(request()).unwrap();
    signed.verify(&p, request()).unwrap();
    assert_eq!(calls.get(), 3); // initial ReadPublic, per-operation ReadPublic, Sign
}

#[test]
fn failed_or_wrong_key_tpm_response_permanently_poisons_that_handle() {
    for fail_sign in [false, true] {
        let calls = Rc::new(Cell::new(0));
        let fixture = SoftwareFixture {
            calls: calls.clone(),
            fail_sign,
            corrupt_signature: !fail_sign,
        };
        let mut s =
            Signer::open(fixture, binding(public(&key())), Zeroizing::new([6; 32])).unwrap();
        assert!(s.sign(request()).is_err());
        let before = calls.get();
        assert_eq!(
            s.sign(request()).unwrap_err(),
            TpmSignatureErrorV3::Unavailable
        );
        assert_eq!(calls.get(), before);
    }
}

#[test]
fn wrong_context_never_reaches_tpm() {
    let calls = Rc::new(Cell::new(0));
    let fixture = SoftwareFixture {
        calls: calls.clone(),
        fail_sign: false,
        corrupt_signature: false,
    };
    let mut s = Signer::open(fixture, binding(public(&key())), Zeroizing::new([6; 32])).unwrap();
    let wrong = TpmSignatureRequestV3::new(Domain::LedgerActivation, [9; 32], 3, [2; 32]).unwrap();
    assert!(s.sign(wrong).is_err());
    assert_eq!(calls.get(), 1);
    assert!(s.sign(request()).is_ok());
}

#[test]
fn per_operation_remeasurement_rejects_handle_replacement() {
    struct Changed(SoftwareFixture);
    impl Transport for Changed {
        fn exchange(&mut self, command: &[u8]) -> Result<Vec<u8>, TpmSignatureErrorV3> {
            let mut bytes = self.0.exchange(command)?;
            if self.0.calls.get() == 2 {
                // The handle still exists but its qualified Name has changed.
                let last = bytes.len() - 1;
                bytes[last] ^= 1;
            }
            Ok(bytes)
        }
    }
    let calls = Rc::new(Cell::new(0));
    let fixture = Changed(SoftwareFixture {
        calls: calls.clone(),
        fail_sign: false,
        corrupt_signature: false,
    });
    let mut s = Signer::open(fixture, binding(public(&key())), Zeroizing::new([6; 32])).unwrap();
    assert_eq!(
        s.sign(request()).unwrap_err(),
        TpmSignatureErrorV3::BindingMismatch
    );
    assert_eq!(calls.get(), 2); // No Sign command was issued.
    assert_eq!(
        s.sign(request()).unwrap_err(),
        TpmSignatureErrorV3::Unavailable
    );
    assert_eq!(calls.get(), 2);
}

#[test]
fn untrusted_or_malformed_public_responses_fail_before_signing() {
    struct Bad(Vec<u8>);
    impl Transport for Bad {
        fn exchange(&mut self, _: &[u8]) -> Result<Vec<u8>, TpmSignatureErrorV3> {
            Ok(self.0.clone())
        }
    }
    let p = public(&key());
    let mut body = p.tpm2b_public();
    body.extend_from_slice(&34_u16.to_be_bytes());
    body.extend_from_slice(p.name());
    body.extend_from_slice(&34_u16.to_be_bytes());
    body.extend_from_slice(&binding(p.clone()).qualified_name);
    let good = response(0x8001, &body);
    for n in 0..good.len() {
        assert!(Signer::open(
            Bad(good[..n].to_vec()),
            binding(p.clone()),
            Zeroizing::new([6; 32])
        )
        .is_err());
    }
    for offset in [0, 2, 5, 9, good.len() - 1, good.len() - 36] {
        let mut bad = good.clone();
        bad[offset] ^= 1;
        assert!(Signer::open(Bad(bad), binding(p.clone()), Zeroizing::new([6; 32])).is_err());
    }
    assert!(Signer::open(Bad(good), binding(p), Zeroizing::new([0; 32])).is_err());
}

// This is never reachable in production builds, including `test-support`.
// swtpm interoperability is explicitly an emulator test, not TPM attestation.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires disposable swtpm fixture; never counts as hardware acceptance"]
fn swtpm_interoperability() {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    struct Emulator(UnixStream);
    impl Transport for Emulator {
        fn exchange(&mut self, command: &[u8]) -> Result<Vec<u8>, TpmSignatureErrorV3> {
            self.0
                .write_all(command)
                .map_err(|_| TpmSignatureErrorV3::OperationFailed)?;
            let mut header = [0; 10];
            self.0
                .read_exact(&mut header)
                .map_err(|_| TpmSignatureErrorV3::OperationFailed)?;
            let len = u32::from_be_bytes(header[2..6].try_into().unwrap()) as usize;
            if !(10..=4096).contains(&len) {
                return Err(TpmSignatureErrorV3::Malformed);
            }
            let mut bytes = header.to_vec();
            bytes.resize(len, 0);
            self.0
                .read_exact(&mut bytes[10..])
                .map_err(|_| TpmSignatureErrorV3::OperationFailed)?;
            let rc = u32::from_be_bytes(header[6..10].try_into().unwrap());
            if rc != 0 {
                eprintln!("synthetic TPM response code: {rc:#x}");
            }
            Ok(bytes)
        }
    }
    assert!(std::path::Path::new("/.dockerenv").is_file());
    let root = std::env::var("SAVANA_TPM_EMULATOR_FIXTURE").expect("explicit emulator fixture");
    let root = std::path::Path::new(&root);
    let p = TpmSigningPublicV3::from_tpm2b_public(&std::fs::read(root.join("public.bin")).unwrap())
        .unwrap();
    let q: [u8; 34] = std::fs::read(root.join("qualified.bin"))
        .unwrap()
        .try_into()
        .unwrap();
    let b = TpmSigningBindingV3::new(p.clone(), q, 0x8101_0002, [1; 32], 3).unwrap();
    let connect = || {
        let stream = UnixStream::connect(root.join("tpm.sock")).unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        stream
            .set_write_timeout(Some(std::time::Duration::from_secs(10)))
            .unwrap();
        Emulator(stream)
    };
    {
        let mut s = Signer::open(connect(), b.clone(), Zeroizing::new([6; 32])).unwrap();
        for _ in 0..3 {
            let signature = s.sign(request()).unwrap();
            signature.verify(&p, request()).unwrap();
            assert_eq!(
                TpmSignatureEnvelopeV3::from_bytes(&signature.to_bytes()).unwrap(),
                signature
            );
        }
    }
    {
        let mut s = Signer::open(connect(), b.clone(), Zeroizing::new([7; 32])).unwrap();
        assert!(s.sign(request()).is_err());
        assert_eq!(
            s.sign(request()).unwrap_err(),
            TpmSignatureErrorV3::Unavailable
        );
    }
    let wrong =
        TpmSigningBindingV3::new(public(&key()), q, b.handle, b.installation, b.epoch).unwrap();
    assert!(Signer::open(connect(), wrong, Zeroizing::new([6; 32])).is_err());
    crate::tpm_nv::tests::interoperability(&connect);
    let policy_public = TpmSigningPublicV3::from_tpm2b_public(
        &std::fs::read(root.join("policy-public.bin")).unwrap(),
    )
    .unwrap();
    let qualified = std::fs::read(root.join("policy-qualified.bin"))
        .unwrap()
        .try_into()
        .unwrap();
    let pcrs = std::fs::read(root.join("pcr.bin")).unwrap();
    assert_eq!(pcrs.len(), 64);
    let policy = crate::TpmPcrPolicyV3::new(0x81, Sha256::digest(&pcrs).into()).unwrap();
    assert_eq!(
        policy.auth_policy().as_slice(),
        std::fs::read(root.join("policy.bin")).unwrap()
    );
    let pb = TpmSigningBindingV3::new_with_pcr(
        policy_public.clone(),
        qualified,
        0x8101_0003,
        [1; 32],
        3,
        policy,
    )
    .unwrap();
    assert!(
        TpmSigningBindingV3::new(policy_public.clone(), qualified, 0x8101_0003, [1; 32], 3)
            .is_err()
    );
    {
        let mut signer = Signer::open(connect(), pb.clone(), Zeroizing::new([6; 32])).unwrap();
        for _ in 0..3 {
            signer
                .sign(request())
                .unwrap()
                .verify(&policy_public, request())
                .unwrap();
        }
    }
    {
        let mut signer = Signer::open(connect(), pb.clone(), Zeroizing::new([7; 32])).unwrap();
        assert!(signer.sign(request()).is_err());
    }
    // Even a caller able to bypass the Rust binding cannot bypass the TPM policy
    // using the correct password. Fixture only: never expose this override.
    {
        let mut bypass = pb.clone();
        bypass.pcr = None;
        let mut signer = Signer::open(connect(), bypass, Zeroizing::new([6; 32])).unwrap();
        assert!(signer.sign(request()).is_err());
    }
    // PCR mutation AFTER PolicyPCR but BEFORE Sign must be checked by the TPM,
    // not merely by an earlier host comparison.
    struct ChangeAfterPolicy {
        inner: Emulator,
    }
    impl Transport for ChangeAfterPolicy {
        fn exchange(&mut self, bytes: &[u8]) -> Result<Vec<u8>, TpmSignatureErrorV3> {
            let response = self.inner.exchange(bytes)?;
            if bytes.get(6..10) == Some(0x18c_u32.to_be_bytes().as_slice()) {
                // Same bounded connection: swtpm serializes its socket clients.
                let mut body = 7_u32.to_be_bytes().to_vec();
                body.extend_from_slice(&9_u32.to_be_bytes());
                body.extend_from_slice(&[0x40, 0, 0, 9, 0, 0, 0, 0, 0]);
                body.extend_from_slice(&[0, 0, 0, 1, 0, 0x0b]);
                body.extend_from_slice(&[0xab; 32]);
                let mutation = self
                    .inner
                    .exchange(&crate::tpm_wire::command(0x8002, 0x182, &body))?;
                crate::tpm_wire::response_body(&mutation, 0x8002)?;
            }
            Ok(response)
        }
    }
    {
        let transport = ChangeAfterPolicy { inner: connect() };
        let mut signer = Signer::open(transport, pb.clone(), Zeroizing::new([6; 32])).unwrap();
        assert!(signer.sign(request()).is_err());
        assert_eq!(
            signer.sign(request()).unwrap_err(),
            TpmSignatureErrorV3::Unavailable
        );
    }
    let mut signer = Signer::open(connect(), pb, Zeroizing::new([6; 32])).unwrap();
    assert!(signer.sign(request()).is_err()); // a fresh session cannot accept changed PCRs
}

#[test]
fn policy_binding_rejects_downgrade_and_wrong_measurements() {
    use crate::TpmPcrPolicyV3;
    assert!(TpmPcrPolicyV3::new(1, [1; 32]).is_err());
    assert!(TpmPcrPolicyV3::new(0x80, [0; 32]).is_err());
    let policy = TpmPcrPolicyV3::new(0x81, [1; 32]).unwrap();
    let mut bytes = public(&key()).tpm2b_public();
    bytes[6..10].copy_from_slice(&POLICY_KEY_ATTRIBUTES.to_be_bytes());
    bytes[10..12].copy_from_slice(&32_u16.to_be_bytes());
    bytes.splice(12..12, policy.auth_policy());
    let size = (bytes.len() - 2) as u16;
    bytes[..2].copy_from_slice(&size.to_be_bytes());
    let p = TpmSigningPublicV3::from_tpm2b_public(&bytes).unwrap();
    let q = binding(public(&key())).qualified_name;
    assert!(TpmSigningBindingV3::new(p.clone(), q, 0x81010003, [1; 32], 1).is_err());
    assert!(
        TpmSigningBindingV3::new_with_pcr(p.clone(), q, 0x81010003, [1; 32], 1, policy).is_ok()
    );
    let wrong = TpmPcrPolicyV3::new(0x80, [1; 32]).unwrap();
    assert!(TpmSigningBindingV3::new_with_pcr(p, q, 0x81010003, [1; 32], 1, wrong).is_err());
    bytes[6..10].copy_from_slice(&(POLICY_KEY_ATTRIBUTES | 0x40).to_be_bytes());
    assert!(TpmSigningPublicV3::from_tpm2b_public(&bytes).is_err());
}
