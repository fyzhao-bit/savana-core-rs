use super::*;
use ed25519_dalek::{Signer, SigningKey};

pub(crate) fn proposal() -> TpmEnrollmentProposalV3 {
    let policy = TpmPcrPolicyV3::new(0x81, [8; 32]).unwrap();
    let key = p256::ecdsa::SigningKey::from_bytes((&[7; 32]).into()).unwrap();
    let point = key.verifying_key().to_encoded_point(false);
    let mut area = vec![0, 0x23, 0, 0x0b, 0, 4, 0, 0xb2, 0, 32];
    area.extend_from_slice(&policy.auth_policy());
    area.extend_from_slice(&[0, 0x10, 0, 0x18, 0, 0x0b, 0, 3, 0, 0x10]);
    for c in [point.x().unwrap(), point.y().unwrap()] {
        area.extend_from_slice(&[0, 32]);
        area.extend_from_slice(c);
    }
    let mut bytes = (area.len() as u16).to_be_bytes().to_vec();
    bytes.extend_from_slice(&area);
    let public = TpmSigningPublicV3::from_tpm2b_public(&bytes).unwrap();
    let mut q = [9; 34];
    q[..2].copy_from_slice(&[0, 0x0b]);
    let signing =
        TpmSigningBindingV3::new_with_pcr(public, q, 0x81010003, [1; 32], 3, policy).unwrap();
    let stores = std::array::from_fn(|i| {
        let index = TpmStoreV3::ALL[i].index();
        TpmNvBindingV3::new(
            index,
            TpmNvBindingV3::expected_name(index),
            [1; 32],
            [10 + i as u8; 32],
            3,
            [20 + i as u8; 32],
            TpmStateHeadV3::GENESIS,
        )
        .unwrap()
    });
    TpmEnrollmentProposalV3::new(
        signing,
        stores,
        TpmClientIdentityV3::new(0, 0, [21; 32]).unwrap(),
        TpmClientIdentityV3::new(1001, 1001, [22; 32]).unwrap(),
        TpmClientIdentityV3::new(0, 0, [23; 32]).unwrap(),
        100,
        200,
        [0; 32],
    )
    .unwrap()
}
pub(crate) fn verified() -> TpmEnrollmentV3 {
    let p = proposal();
    let key = SigningKey::from_bytes(&[9; 32]);
    TpmEnrollmentV3::verify(
        &p.attach_signature(key.sign(&p.signature_input()).to_bytes()),
        key.verifying_key().to_bytes(),
        150,
    )
    .unwrap()
}

#[test]
fn signed_enrollment_binds_all_bytes_and_requires_external_root_and_time() {
    let p = proposal();
    let key = SigningKey::from_bytes(&[9; 32]);
    let bytes = p.attach_signature(key.sign(&p.signature_input()).to_bytes());
    let public = key.verifying_key().to_bytes();
    let value = TpmEnrollmentV3::verify(&bytes, public, 100).unwrap();
    assert_eq!(value.digest(), p.signature_input());
    for offset in 0..bytes.len() {
        let mut bad = bytes.clone();
        bad[offset] ^= 1;
        assert!(TpmEnrollmentV3::verify(&bad, public, 150).is_err());
    }
    for time in [0, 99, 200, u64::MAX] {
        assert!(TpmEnrollmentV3::verify(&bytes, public, time).is_err());
    }
    assert!(TpmEnrollmentV3::verify(
        &bytes,
        SigningKey::from_bytes(&[10; 32]).verifying_key().to_bytes(),
        150
    )
    .is_err());
    let mut extra = bytes;
    extra.push(0);
    assert!(TpmEnrollmentV3::verify(&extra, public, 150).is_err());
    assert!(TpmEnrollmentV3::verify(&p.canonical_bytes(), public, 150).is_err());
}

#[test]
fn even_installer_signed_malformed_roles_stores_and_downgrades_are_rejected() {
    let key = SigningKey::from_bytes(&[9; 32]);
    for mutate in 0..8 {
        let mut p = proposal();
        match mutate {
            0 => p.stores.swap(0, 1),
            1 => p.stores[2].store = p.stores[1].store,
            2 => p.stores[1].installation = [3; 32],
            3 => p.stores[1].epoch = 4,
            4 => p.kernel = p.deployer,
            5 => p.broker = p.kernel,
            6 => p.expires = p.not_before,
            _ => p.signing.pcr = Some(TpmPcrPolicyV3::new(0x80, [8; 32]).unwrap()),
        }
        let bytes = p.attach_signature(key.sign(&p.signature_input()).to_bytes());
        // Installation/epoch are stored once, so constructor catches mismatched
        // in-memory inputs before serialization; wire decoder checks shared scope.
        if mutate == 2 || mutate == 3 {
            assert!(TpmEnrollmentProposalV3::new(
                p.signing,
                p.stores,
                p.deployer,
                p.kernel,
                p.broker,
                p.not_before,
                p.expires,
                p.previous_enrollment_root
            )
            .is_err());
        } else {
            assert!(TpmEnrollmentV3::verify(&bytes, key.verifying_key().to_bytes(), 150).is_err());
        }
    }
}

#[test]
fn enrollment_activation_root_changes_with_authority_or_previous_root() {
    let a = verified();
    let mut b = a.clone();
    b.proposal.previous_enrollment_root = [1; 32];
    assert_ne!(a.active_enrollment_root(), b.active_enrollment_root());
    let mut b = a.clone();
    b.digest[0] ^= 1;
    assert_ne!(a.active_enrollment_root(), b.active_enrollment_root());
}

#[test]
fn first_install_profile_cannot_silently_migrate_or_reset_existing_state() {
    for migrate in [false, true] {
        let mut p = proposal();
        if migrate {
            p.previous_enrollment_root = [1; 32];
        } else {
            p.stores[1].initial_head = TpmStateHeadV3::new(4, [5; 32]).unwrap();
        }
        assert!(TpmEnrollmentProposalV3::new(
            p.signing,
            p.stores,
            p.deployer,
            p.kernel,
            p.broker,
            p.not_before,
            p.expires,
            p.previous_enrollment_root
        )
        .is_err());
    }
}
