//! Purpose-separated first-party resource issuer. Deployment-only, no RPC key.
use ed25519_dalek::SigningKey;
use savana_kernel_protocol::v2::{derive_ed25519_key_id_v2, Ed25519KeyIdV2};
use zeroize::Zeroizing;

pub(crate) struct KernelManagedResourceIssuerV04 {
    key: SigningKey,
}
impl KernelManagedResourceIssuerV04 {
    pub(crate) fn from_deployment(
        expected: Option<(Ed25519KeyIdV2, [u8; 32])>,
        seed: Option<[u8; 32]>,
        other_material: &[[u8; 32]],
    ) -> Result<Option<Self>, ()> {
        let seed = seed.map(Zeroizing::new);
        let (id, public, seed) = match (expected, seed) {
            (None, None) => return Ok(None),
            (Some((id, public)), Some(seed)) => (id, public, seed),
            _ => return Err(()),
        };
        let key = SigningKey::from_bytes(&seed);
        if *seed == [0; 32]
            || public == [0; 32]
            || key.verifying_key().is_weak()
            || key.verifying_key().to_bytes() != public
            || derive_ed25519_key_id_v2(public) != id
            || other_material.iter().any(|m| m == &*seed || m == &public)
        {
            return Err(());
        }
        Ok(Some(Self { key }))
    }

    pub(crate) fn signer(&self) -> &SigningKey {
        &self.key
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn managed_issuer_is_disabled_by_default_and_never_uses_fallback_material() {
        assert!(
            KernelManagedResourceIssuerV04::from_deployment(None, None, &[])
                .unwrap()
                .is_none()
        );
        assert!(
            KernelManagedResourceIssuerV04::from_deployment(None, Some([41; 32]), &[]).is_err()
        );
        let public = SigningKey::from_bytes(&[41; 32]).verifying_key().to_bytes();
        assert!(KernelManagedResourceIssuerV04::from_deployment(
            Some((derive_ed25519_key_id_v2(public), public)),
            None,
            &[]
        )
        .is_err());
    }
    #[test]
    fn managed_issuer_pins_public_key_id_and_distinct_role_material() {
        let seed = [41; 32];
        let public = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
        let expected = Some((derive_ed25519_key_id_v2(public), public));
        let issuer =
            KernelManagedResourceIssuerV04::from_deployment(expected, Some(seed), &[[42; 32]])
                .unwrap()
                .unwrap();
        assert_eq!(issuer.signer().verifying_key().to_bytes(), public);
        for other in [seed, public] {
            assert!(KernelManagedResourceIssuerV04::from_deployment(
                expected,
                Some(seed),
                &[other]
            )
            .is_err());
        }
        assert!(
            KernelManagedResourceIssuerV04::from_deployment(expected, Some([42; 32]), &[]).is_err()
        );
        assert!(KernelManagedResourceIssuerV04::from_deployment(
            Some((Ed25519KeyIdV2::new([7; 32]), public)),
            Some(seed),
            &[]
        )
        .is_err());
        assert!(
            KernelManagedResourceIssuerV04::from_deployment(expected, Some([0; 32]), &[]).is_err()
        );
    }
}
