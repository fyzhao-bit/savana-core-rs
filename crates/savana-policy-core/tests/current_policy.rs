mod support;

use savana_kernel_protocol::StableCode;
use savana_policy_core::PolicyStore;

#[test]
fn only_the_matching_release_bound_verifier_mints_current_policy() {
    let fixture = support::current_policy_fixture();
    let ledger = fixture.ledger_path();
    let before = support::read_optional_ledger(ledger);

    let offline = PolicyStore::open(ledger, support::offline_verifier()).unwrap();
    assert_eq!(
        offline
            .verify_and_accept_initial(
                fixture.release(),
                fixture.policy_bytes(),
                fixture.policy_signature(),
                fixture.now(),
            )
            .unwrap_err()
            .code(),
        StableCode::IdentityReleaseMismatch
    );
    assert_eq!(support::read_optional_ledger(ledger), before);

    let other_release_store =
        PolicyStore::open(ledger, fixture.other_release().policy_verifier().unwrap()).unwrap();
    assert_eq!(
        other_release_store
            .verify_and_accept_initial(
                fixture.release(),
                fixture.policy_bytes(),
                fixture.policy_signature(),
                fixture.now(),
            )
            .unwrap_err()
            .code(),
        StableCode::IdentityReleaseMismatch
    );
    assert_eq!(support::read_optional_ledger(ledger), before);
}

#[test]
fn release_policy_mismatch_and_expired_release_precede_ledger_write() {
    let fixture = support::current_policy_fixture();
    for release in [
        fixture.release_with_wrong_resource_digest(),
        fixture.expired_release(),
    ] {
        let store =
            PolicyStore::open(fixture.ledger_path(), release.policy_verifier().unwrap()).unwrap();
        let before = support::read_optional_ledger(fixture.ledger_path());
        assert!(store
            .verify_and_accept_initial(
                release,
                fixture.policy_bytes(),
                fixture.policy_signature(),
                fixture.now(),
            )
            .is_err());
        assert_eq!(support::read_optional_ledger(fixture.ledger_path()), before);
    }
}

#[test]
fn successful_initial_acceptance_owns_the_lifetime_store_lock() {
    let fixture = support::current_policy_fixture();
    let release = fixture.release();
    let verifier = release.policy_verifier().unwrap();
    assert_eq!(format!("{verifier:?}"), "PolicyVerifier(<verified>)");
    let store = PolicyStore::open(fixture.ledger_path(), verifier).unwrap();
    let current = store
        .verify_and_accept_initial(
            release,
            fixture.policy_bytes(),
            fixture.policy_signature(),
            fixture.now(),
        )
        .unwrap();
    assert_eq!(format!("{current:?}"), "CurrentPolicyCapability(<current>)");
    assert!(PolicyStore::open(fixture.ledger_path(), support::offline_verifier()).is_err());
    drop(current);
    assert!(PolicyStore::open(fixture.ledger_path(), support::offline_verifier()).is_ok());
}
