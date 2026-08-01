use std::sync::{Arc, RwLock};

use savana_policy_core::v2::{
    DeclassificationRuleSetV2, DeploymentControlErrorV2, OperationalTrustRootSetV2,
};

#[derive(Clone)]
pub(crate) struct ActiveDeclassificationRuleSetV2 {
    trust_roots: Arc<OperationalTrustRootSetV2>,
    active: Arc<RwLock<Arc<DeclassificationRuleSetV2>>>,
}

impl ActiveDeclassificationRuleSetV2 {
    pub(crate) fn new(
        initial: DeclassificationRuleSetV2,
        trust_roots: Arc<OperationalTrustRootSetV2>,
    ) -> Result<Self, DeploymentControlErrorV2> {
        if initial.trust_root_set_digest() != trust_roots.signed_digest()
            || initial.product_family_digest() != trust_roots.product_family_digest()
        {
            return Err(DeploymentControlErrorV2::InvalidDeclassificationRuleSet);
        }
        Ok(Self {
            trust_roots,
            active: Arc::new(RwLock::new(Arc::new(initial))),
        })
    }

    pub(crate) fn snapshot(
        &self,
    ) -> Result<Arc<DeclassificationRuleSetV2>, DeploymentControlErrorV2> {
        self.active
            .read()
            .map(|active| Arc::clone(&active))
            .map_err(|_| DeploymentControlErrorV2::InvalidDeclassificationRuleSet)
    }

    pub(crate) fn rollover_from_canonical_bytes(
        &self,
        bytes: &[u8],
        now_unix_ms: u64,
    ) -> Result<(), DeploymentControlErrorV2> {
        let candidate =
            DeclassificationRuleSetV2::from_canonical_bytes(bytes, &self.trust_roots, now_unix_ms)?;
        let mut active = self
            .active
            .write()
            .map_err(|_| DeploymentControlErrorV2::InvalidDeclassificationRuleSet)?;
        candidate.validate_predecessor(Some(&active))?;
        *active = Arc::new(candidate);
        Ok(())
    }

    #[cfg(test)]
    fn trust_roots(&self) -> &OperationalTrustRootSetV2 {
        &self.trust_roots
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ed25519_dalek::SigningKey;
    use savana_kernel_protocol::v2::Digest32V2;
    use savana_policy_core::v2::{
        declassification_implementation_digest_v2, ClosedDeclassificationPurposeV2,
        DeclassificationRuleSetV2, DeclassificationRuleV2, LeakGateDutyV2,
        OperationalTrustRootPurposeV2, OperationalTrustRootSetItemV2, OperationalTrustRootSetV2,
    };

    use super::ActiveDeclassificationRuleSetV2;

    fn fixture() -> (
        OperationalTrustRootSetV2,
        SigningKey,
        DeclassificationRuleSetV2,
    ) {
        let installer = SigningKey::from_bytes(&[0x31; 32]);
        let authority = SigningKey::from_bytes(&[0x32; 32]);
        let family = Digest32V2::new([0x33; 32]);
        let member = OperationalTrustRootSetItemV2::new(
            OperationalTrustRootPurposeV2::DeclassificationAuthority,
            authority.verifying_key().to_bytes(),
            1,
            5,
            100,
        )
        .unwrap();
        let roots = OperationalTrustRootSetV2::new_declassification_signed_for_test(
            family,
            1,
            None,
            vec![member],
            5,
            100,
            &installer,
            1,
        )
        .unwrap();
        let initial = signed_rules(&roots, &authority, 1, None, 10, 90, 50);
        (roots, authority, initial)
    }

    fn signed_rules(
        roots: &OperationalTrustRootSetV2,
        authority: &SigningKey,
        sequence: u64,
        predecessor: Option<Digest32V2>,
        not_before: u64,
        not_after: u64,
        now: u64,
    ) -> DeclassificationRuleSetV2 {
        let rule = DeclassificationRuleV2::new_for_test(
            2,
            ClosedDeclassificationPurposeV2::PlannerCall,
            declassification_implementation_digest_v2(2).unwrap(),
            LeakGateDutyV2::BlocklistAndNoResidualPii,
            None,
            None,
            not_before,
            not_after,
        )
        .unwrap();
        DeclassificationRuleSetV2::new_signed_for_test(
            roots.product_family_digest(),
            sequence,
            predecessor,
            vec![rule],
            not_before,
            not_after,
            roots,
            authority,
            1,
            now,
        )
        .unwrap()
    }

    #[test]
    fn verified_successor_swaps_atomically_and_rollback_retains_active_set() {
        let (roots, authority, initial) = fixture();
        let initial_bytes = initial.canonical_bytes().to_vec();
        let initial_digest = initial.signed_digest();
        let active = ActiveDeclassificationRuleSetV2::new(initial, Arc::new(roots)).unwrap();
        let successor = signed_rules(
            active.trust_roots(),
            &authority,
            2,
            Some(initial_digest),
            20,
            90,
            50,
        );
        let successor_digest = successor.signed_digest();

        active
            .rollover_from_canonical_bytes(successor.canonical_bytes(), 50)
            .unwrap();
        assert_eq!(active.snapshot().unwrap().signed_digest(), successor_digest);

        assert!(active
            .rollover_from_canonical_bytes(&initial_bytes, 50)
            .is_err());
        assert_eq!(active.snapshot().unwrap().signed_digest(), successor_digest);
    }

    #[test]
    fn invalid_signature_digest_or_window_never_replaces_the_active_set() {
        let (roots, authority, initial) = fixture();
        let initial_digest = initial.signed_digest();
        let active = ActiveDeclassificationRuleSetV2::new(initial, Arc::new(roots)).unwrap();
        let successor = signed_rules(
            active.trust_roots(),
            &authority,
            2,
            Some(initial_digest),
            20,
            90,
            50,
        );

        let mut bad_signature = successor.canonical_bytes().to_vec();
        *bad_signature.last_mut().unwrap() ^= 1;
        let mut bad_digest = successor.canonical_bytes().to_vec();
        bad_digest[20] ^= 1;
        for (candidate, now) in [
            (bad_signature.as_slice(), 50),
            (bad_digest.as_slice(), 50),
            (successor.canonical_bytes(), 95),
        ] {
            assert!(active
                .rollover_from_canonical_bytes(candidate, now)
                .is_err());
            assert_eq!(active.snapshot().unwrap().signed_digest(), initial_digest);
        }
    }
}
