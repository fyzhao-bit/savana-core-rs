mod support;

use savana_kernel_protocol::{BootId, ClientId, Digest32, Nonce32, StableCode, UnixMillis};
use savana_policy_core::{Clock, PolicyEngine, RandomSource};
use std::sync::Arc;

#[test]
fn dependencies_are_object_safe() {
    fn accepts(clock: Arc<dyn Clock + Send + Sync>, random: Arc<dyn RandomSource + Send + Sync>) {
        drop((clock, random));
    }
    let (clock, random) = support::healthy_dependencies();
    accepts(clock, random);
}

#[test]
fn engine_requires_full_nonzero_instance_entropy() {
    for random in [
        support::RandomBehavior::Error,
        support::RandomBehavior::Short(31),
        support::RandomBehavior::Zeros(32),
    ] {
        let current = support::fresh_current_policy();
        let error = PolicyEngine::new(
            current,
            BootId::new([0x41; 32]),
            support::clock(),
            support::random(random),
        )
        .err()
        .expect("invalid entropy must reject engine construction");
        assert_eq!(error.code(), StableCode::KernelUnavailable);
    }
}

#[test]
fn ordinary_bind_issues_an_opaque_redacted_context() {
    let (current, policy_identity) = support::current_policy_and_identity();
    let clock = support::clock();
    let (engine, issuer) = PolicyEngine::new(
        current,
        BootId::new([0x41; 32]),
        Arc::clone(&clock) as Arc<dyn Clock + Send + Sync>,
        support::random(support::RandomBehavior::Full),
    )
    .unwrap();
    let context = issuer
        .bind(
            ClientId::new("client-a").unwrap(),
            Nonce32::new([0x22; 32]),
            Digest32::new([0x33; 32]),
            policy_identity,
            BootId::new([0x41; 32]),
            501,
            UnixMillis::new(clock.now() + 1_000),
        )
        .unwrap();
    assert_eq!(format!("{issuer:?}"), "AuthenticatedContextIssuer(<bound>)");
    assert_eq!(
        format!("{context:?}"),
        "AuthenticatedCallContext(<authenticated>)"
    );
    drop((engine, context));
}
