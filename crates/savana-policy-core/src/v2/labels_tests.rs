use savana_policy_core::v2::{
    ArgumentNameV2, ConfidentialityV2, DeriveOperationV2, EffectSetV2, G3Error, IntegrityV2,
    ReaderSetV2, SecurityLabelV2,
};

#[test]
fn integrity_join_never_improves_trust() {
    let levels = [
        IntegrityV2::KernelTrusted,
        IntegrityV2::UserAuthorized,
        IntegrityV2::ExternalUntrusted,
    ];

    for (left_index, left) in levels.into_iter().enumerate() {
        for (right_index, right) in levels.into_iter().enumerate() {
            assert_eq!(left.join(right), levels[left_index.max(right_index)]);
        }
    }
}

#[test]
fn confidentiality_is_the_frozen_diamond() {
    use ConfidentialityV2::{AgentMasked, PlannerAbstract, Public, VaultBound};

    let cases = [
        (Public, Public, Public),
        (Public, PlannerAbstract, PlannerAbstract),
        (Public, AgentMasked, AgentMasked),
        (Public, VaultBound, VaultBound),
        (PlannerAbstract, PlannerAbstract, PlannerAbstract),
        (PlannerAbstract, AgentMasked, VaultBound),
        (PlannerAbstract, VaultBound, VaultBound),
        (AgentMasked, AgentMasked, AgentMasked),
        (AgentMasked, VaultBound, VaultBound),
        (VaultBound, VaultBound, VaultBound),
    ];

    for (left, right, expected) in cases {
        assert_eq!(left.join(right), expected);
        assert_eq!(right.join(left), expected);
    }
}

#[test]
fn reader_and_effect_sets_are_closed_u16_sets() {
    let readers = ReaderSetV2::KERNEL
        .union(ReaderSetV2::AGENT)
        .union(ReaderSetV2::EXTERNAL_PLANNER);
    assert_eq!(readers.bits(), 0x0023);
    assert_eq!(
        readers.intersection(ReaderSetV2::KERNEL.union(ReaderSetV2::INGRESS)),
        ReaderSetV2::KERNEL
    );
    assert_eq!(
        ReaderSetV2::from_bits(0x0040),
        Some(ReaderSetV2::EXTERNAL_SINK)
    );
    assert_eq!(ReaderSetV2::from_bits(0x0080), None);

    let effects = EffectSetV2::READ
        .union(EffectSetV2::UPDATE)
        .union(EffectSetV2::FINAL_RELEASE);
    assert_eq!(effects.bits(), 0x0045);
    assert_eq!(
        effects.intersection(EffectSetV2::READ.union(EffectSetV2::SEND)),
        EffectSetV2::READ
    );
    assert_eq!(
        EffectSetV2::from_bits(0x0040),
        Some(EffectSetV2::FINAL_RELEASE)
    );
    assert_eq!(EffectSetV2::from_bits(0x0080), None);
}

#[test]
fn normal_derivation_never_improves_authority() {
    let left = SecurityLabelV2::from_verified_source(
        IntegrityV2::KernelTrusted,
        ConfidentialityV2::PlannerAbstract,
        ReaderSetV2::KERNEL.union(ReaderSetV2::EXTERNAL_PLANNER),
        EffectSetV2::READ.union(EffectSetV2::EXECUTE),
    );
    let right = SecurityLabelV2::from_verified_source(
        IntegrityV2::ExternalUntrusted,
        ConfidentialityV2::AgentMasked,
        ReaderSetV2::KERNEL.union(ReaderSetV2::AGENT),
        EffectSetV2::READ.union(EffectSetV2::SEND),
    );

    let derived = SecurityLabelV2::derive_normal(
        &[left, right],
        EffectSetV2::READ.union(EffectSetV2::EXECUTE),
    )
    .unwrap();

    assert_eq!(derived.integrity(), IntegrityV2::ExternalUntrusted);
    assert_eq!(derived.confidentiality(), ConfidentialityV2::VaultBound);
    assert_eq!(derived.readers(), ReaderSetV2::KERNEL);
    assert_eq!(derived.effects(), EffectSetV2::READ);
}

#[test]
fn normal_derivation_requires_at_least_one_parent() {
    assert_eq!(
        SecurityLabelV2::derive_normal(&[], EffectSetV2::ALL),
        Err(G3Error::EmptyParents)
    );
}

#[test]
fn derive_operations_bind_their_exact_semantic_parameters() {
    let field = ArgumentNameV2::new("subject").unwrap();
    let select = DeriveOperationV2::select_object_field(field);
    assert_eq!(
        minicbor::to_vec(select).unwrap(),
        [0x82, 0x03, 0x67, b's', b'u', b'b', b'j', b'e', b'c', b't']
    );

    let fields = DeriveOperationV2::assemble_object(vec![
        ArgumentNameV2::new("a").unwrap(),
        ArgumentNameV2::new("b").unwrap(),
    ])
    .unwrap();
    assert_eq!(
        minicbor::to_vec(fields).unwrap(),
        [0x82, 0x05, 0x82, 0x61, b'a', 0x61, b'b']
    );
    assert_eq!(
        DeriveOperationV2::assemble_object(vec![
            ArgumentNameV2::new("b").unwrap(),
            ArgumentNameV2::new("a").unwrap(),
        ])
        .unwrap_err(),
        G3Error::NonCanonicalOrder
    );
}

#[test]
fn untrusted_sources_cannot_carry_authorizing_effects() {
    // A session grants one `policy_allowed_effects` set to every value it
    // produces, so without the ceiling a tool result or planner output would
    // carry SEND exactly like user input does.
    let session_effects = EffectSetV2::READ
        .union(EffectSetV2::SEND)
        .union(EffectSetV2::CREATE);

    let untrusted = SecurityLabelV2::from_verified_source(
        IntegrityV2::ExternalUntrusted,
        ConfidentialityV2::VaultBound,
        ReaderSetV2::KERNEL,
        session_effects,
    );
    assert_eq!(untrusted.effects(), EffectSetV2::READ);

    // Trusted sources are untouched: a recipient the user supplied through
    // ingress keeps the effects the session granted it.
    for integrity in [IntegrityV2::UserAuthorized, IntegrityV2::KernelTrusted] {
        let trusted = SecurityLabelV2::from_verified_source(
            integrity,
            ConfidentialityV2::AgentMasked,
            ReaderSetV2::KERNEL,
            session_effects,
        );
        assert_eq!(trusted.effects(), session_effects);
    }

    // An untrusted value that was never granted READ ends up with no effects
    // at all rather than silently gaining one.
    let write_only = SecurityLabelV2::from_verified_source(
        IntegrityV2::ExternalUntrusted,
        ConfidentialityV2::VaultBound,
        ReaderSetV2::KERNEL,
        EffectSetV2::SEND,
    );
    assert_eq!(write_only.effects(), EffectSetV2::EMPTY);
}

#[test]
fn derivation_strips_authorizing_effects_once_any_parent_is_untrusted() {
    // Both parents carry SEND, so effect intersection alone would preserve it.
    // The integrity join makes the result `ExternalUntrusted`, and the ceiling
    // must be re-applied after that join or a trusted parent would launder an
    // authorizing effect into untrusted data.
    let trusted = SecurityLabelV2::from_verified_source(
        IntegrityV2::UserAuthorized,
        ConfidentialityV2::AgentMasked,
        ReaderSetV2::KERNEL,
        EffectSetV2::READ.union(EffectSetV2::SEND),
    );
    let untrusted = SecurityLabelV2::from_verified_source(
        IntegrityV2::ExternalUntrusted,
        ConfidentialityV2::VaultBound,
        ReaderSetV2::KERNEL,
        EffectSetV2::READ.union(EffectSetV2::SEND),
    );

    let derived = SecurityLabelV2::derive_normal(
        &[trusted, untrusted],
        EffectSetV2::READ.union(EffectSetV2::SEND),
    )
    .unwrap();

    assert_eq!(derived.integrity(), IntegrityV2::ExternalUntrusted);
    assert_eq!(derived.effects(), EffectSetV2::READ);
    assert!(!derived.effects().contains(EffectSetV2::SEND));

    // Deriving only from trusted parents keeps the authorizing effect.
    let trusted_only = SecurityLabelV2::derive_normal(
        &[trusted, trusted],
        EffectSetV2::READ.union(EffectSetV2::SEND),
    )
    .unwrap();
    assert_eq!(trusted_only.integrity(), IntegrityV2::UserAuthorized);
    assert!(trusted_only.effects().contains(EffectSetV2::SEND));
}

#[test]
fn untrusted_effect_ceiling_is_read_only() {
    // Pin the ceiling: untrusted data stays readable, and every authorizing
    // effect stays outside it.
    assert_eq!(crate::v2::UNTRUSTED_EFFECT_CEILING_V2, EffectSetV2::READ);
    for effect in [
        EffectSetV2::CREATE,
        EffectSetV2::UPDATE,
        EffectSetV2::DELETE,
        EffectSetV2::SEND,
        EffectSetV2::EXECUTE,
        EffectSetV2::FINAL_RELEASE,
    ] {
        assert!(!crate::v2::UNTRUSTED_EFFECT_CEILING_V2.contains(effect));
    }
}
