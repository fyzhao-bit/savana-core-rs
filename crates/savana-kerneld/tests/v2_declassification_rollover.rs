#![cfg(feature = "test-support")]

//! The V2 declassification-rule rollover: a verified successor is published
//! whole or not at all, and both endpoints keep serving the old generation
//! when it is refused.

use savana_kerneld::test_support::{
    probe_v2_declassification_rollover, V2DeclassificationRolloverScenario,
};

#[test]
fn v2_valid_generation_successor_serves_real_agent_and_ingress_requests() {
    let observed =
        probe_v2_declassification_rollover(V2DeclassificationRolloverScenario::ValidSuccessor);

    assert_eq!(observed.result(), Ok(()));
    assert!(observed.verified_successor_constructed());
    assert_ne!(observed.old_digest(), observed.candidate_digest());
    assert_eq!(
        observed.ingress_request_digest(),
        observed.candidate_digest()
    );
    assert_eq!(observed.agent_request_digest(), observed.candidate_digest());
    assert_eq!(observed.ingress_request_generation(), 2);
    assert_eq!(observed.agent_request_generation(), 2);
    assert_eq!(observed.active_generation(), 2);
    assert!(observed.admission_resumed());
}

fn assert_v2_rollover_rejected_without_partial_publication(
    scenario: V2DeclassificationRolloverScenario,
    verified_successor_constructed: bool,
) {
    let observed = probe_v2_declassification_rollover(scenario);

    assert!(observed.result().is_err());
    assert_eq!(
        observed.verified_successor_constructed(),
        verified_successor_constructed
    );
    assert_eq!(observed.ingress_request_digest(), observed.old_digest());
    assert_eq!(observed.agent_request_digest(), observed.old_digest());
    assert_eq!(observed.ingress_request_generation(), 1);
    assert_eq!(observed.agent_request_generation(), 1);
    assert_eq!(observed.active_generation(), 1);
    assert!(observed.admission_resumed());
}

#[test]
fn v2_rule_set_rollback_retains_the_old_complete_runtime() {
    assert_v2_rollover_rejected_without_partial_publication(
        V2DeclassificationRolloverScenario::RuleSetRollback,
        true,
    );
}

#[test]
fn v2_wrong_manifest_pin_retains_the_old_complete_runtime() {
    assert_v2_rollover_rejected_without_partial_publication(
        V2DeclassificationRolloverScenario::WrongManifestPin,
        false,
    );
}

#[test]
fn v2_bad_rule_set_signature_retains_the_old_complete_runtime() {
    assert_v2_rollover_rejected_without_partial_publication(
        V2DeclassificationRolloverScenario::BadRuleSetSignature,
        false,
    );
}

#[test]
fn v2_expired_rule_set_retains_the_old_complete_runtime() {
    assert_v2_rollover_rejected_without_partial_publication(
        V2DeclassificationRolloverScenario::ExpiredRuleSet,
        false,
    );
}

#[test]
fn v2_rule_expiring_after_construction_is_rejected_before_publication() {
    assert_v2_rollover_rejected_without_partial_publication(
        V2DeclassificationRolloverScenario::ExpiresBeforePublication,
        true,
    );
}

#[test]
fn v2_incomplete_endpoint_runtime_never_constructs_a_verified_successor() {
    assert_v2_rollover_rejected_without_partial_publication(
        V2DeclassificationRolloverScenario::IncompleteEndpointRuntime,
        false,
    );
}

#[test]
fn v2_generation_gap_retains_the_old_complete_runtime() {
    assert_v2_rollover_rejected_without_partial_publication(
        V2DeclassificationRolloverScenario::GenerationGap,
        true,
    );
}
