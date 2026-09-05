use savana_kernel_protocol::v2::{
    Digest32V2, DurableRunIdV2, ExecutorIdentityV2, InternalSlotDigestV2, ProducerIdentityV2,
    RelationIdV2, SlotKindV2, UnixMillisV2, ValueInternalIdV2,
};

use super::{
    ClosedCardinalityV2, PlannerSlotConfidentialityV2, ResolvedSlotRelationSemanticV2,
    StoredBindingResolverV2, StoredValueRecordV2, StoredVaultCredentialV2,
    VerifiedInternalSlotMaterialV2, VerifiedPlanArgumentV2, VerifiedRequiredTokenV2,
    VerifiedResolvedRelationSetV2,
};
use crate::v2::{
    ArgumentNameV2, EffectSetV2, G4Error, IdentifierV2, KernelValueV2, ProvenanceContextV2,
    ProvenanceRecordV2,
};

#[test]
fn stored_binding_recomputes_all_g3_digests_from_immutable_records() {
    let fixture = fixture();
    let arguments = vec![VerifiedPlanArgumentV2::from_verified_plan(
        ArgumentNameV2::new("message").unwrap(),
        &fixture.slot_material,
    )
    .unwrap()];
    let required_tokens = vec![VerifiedRequiredTokenV2::from_verified_policy(
        IdentifierV2::new("mail_oauth").unwrap(),
        Digest32V2::new([0x31; 32]),
        Digest32V2::new([0x32; 32]),
    )];
    let credential = StoredVaultCredentialV2::from_vault(
        IdentifierV2::new("mail_oauth").unwrap(),
        Digest32V2::new([0x31; 32]),
        Digest32V2::new([0x32; 32]),
        fixture.executor,
    )
    .unwrap();
    let stored = StoredValueRecordV2::from_store(
        &fixture.slot_material,
        &fixture.value,
        &fixture.provenance,
    )
    .unwrap();

    let resolved = StoredBindingResolverV2::resolve(
        fixture.run,
        fixture.manifest,
        fixture.executor,
        &arguments,
        &[stored],
        &required_tokens,
        &[credential],
    )
    .unwrap();

    assert_ne!(resolved.argument_digest().as_bytes(), &[0; 32]);
    assert_ne!(resolved.provenance_set_digest().as_bytes(), &[0; 32]);
    assert_ne!(resolved.evidence_digest().as_bytes(), &[0; 32]);
    assert_ne!(resolved.token_set_digest().as_bytes(), &[0; 32]);
    assert_eq!(
        resolved.executor_identity_digest(),
        Digest32V2::new(*fixture.executor.as_bytes())
    );
    assert_eq!(resolved.arguments()[0].internal_slot_digest(), fixture.slot);
    assert_eq!(resolved.arguments()[0].label(), fixture.provenance.label());
    assert_eq!(
        resolved.arguments()[0].root_evidence(),
        fixture.provenance.root_evidence().as_slice()
    );
    assert_eq!(resolved.tokens().len(), 1);
    assert_eq!(resolved.tokens()[0].token_slot_id().as_str(), "mail_oauth");
    assert_eq!(
        resolved.tokens()[0].vault_segment_internal_id(),
        Digest32V2::new([0x31; 32])
    );
    assert_eq!(
        resolved.tokens()[0].credential_version_digest(),
        Digest32V2::new([0x32; 32])
    );
    assert_eq!(
        resolved.tokens()[0].executor_identity_digest(),
        Digest32V2::new(*fixture.executor.as_bytes())
    );
}

#[test]
fn internal_slot_digest_recomputes_relation_semantics_and_rejects_nonincident_relations() {
    let fixture = fixture();
    let changed_relations = VerifiedResolvedRelationSetV2::new_for_test(
        4,
        vec![
            ResolvedSlotRelationSemanticV2::new(RelationIdV2::new(1), 1, 2),
            ResolvedSlotRelationSemanticV2::new(RelationIdV2::new(1), 1, 3),
        ],
    )
    .unwrap();
    let changed = VerifiedInternalSlotMaterialV2::from_resolved_envelope(
        Digest32V2::new([0x10; 32]),
        fixture.manifest,
        fixture.run,
        1,
        SlotKindV2::new(1),
        ClosedCardinalityV2::ExactlyOne,
        PlannerSlotConfidentialityV2::ConfidentialAbstract,
        vec![RelationIdV2::new(1)],
        fixture.value_id,
        fixture.provenance.value_digest(),
        fixture.provenance.provenance_digest(),
        &changed_relations,
    )
    .unwrap();
    assert_ne!(
        fixture.slot_material.internal_slot_digest().unwrap(),
        changed.internal_slot_digest().unwrap()
    );
    assert_eq!(
        VerifiedResolvedRelationSetV2::new_for_test(
            2,
            vec![ResolvedSlotRelationSemanticV2::new(
                RelationIdV2::new(1),
                0,
                2,
            )],
        )
        .unwrap_err(),
        G4Error::InvalidInternalSlotBinding
    );
}

#[test]
fn stored_binding_rejects_stale_missing_mismatched_and_aliased_records() {
    let fixture = fixture();
    let stored = StoredValueRecordV2::from_store(
        &fixture.slot_material,
        &fixture.value,
        &fixture.provenance,
    )
    .unwrap();
    let exact = VerifiedPlanArgumentV2::from_verified_plan(
        ArgumentNameV2::new("a").unwrap(),
        &fixture.slot_material,
    )
    .unwrap();

    assert_eq!(
        StoredBindingResolverV2::resolve(
            DurableRunIdV2::new([0x99; 32]),
            fixture.manifest,
            fixture.executor,
            std::slice::from_ref(&exact),
            std::slice::from_ref(&stored),
            &[],
            &[],
        )
        .unwrap_err(),
        G4Error::StaleStoredBinding
    );
    assert_eq!(
        StoredBindingResolverV2::resolve(
            fixture.run,
            fixture.manifest,
            fixture.executor,
            std::slice::from_ref(&exact),
            &[],
            &[],
            &[],
        )
        .unwrap_err(),
        G4Error::MissingStoredValue
    );
    let mismatch_material = slot_material(
        fixture.run,
        fixture.manifest,
        fixture.value_id,
        fixture.provenance.value_digest(),
        fixture.provenance.provenance_digest(),
        2,
    );
    let mismatch = VerifiedPlanArgumentV2::from_verified_plan(
        ArgumentNameV2::new("a").unwrap(),
        &mismatch_material,
    )
    .unwrap();
    assert_eq!(
        StoredBindingResolverV2::resolve(
            fixture.run,
            fixture.manifest,
            fixture.executor,
            &[mismatch],
            std::slice::from_ref(&stored),
            &[],
            &[],
        )
        .unwrap_err(),
        G4Error::StoredValueMismatch
    );
    let alias = VerifiedPlanArgumentV2::from_verified_plan(
        ArgumentNameV2::new("b").unwrap(),
        &fixture.slot_material,
    )
    .unwrap();
    assert_eq!(
        StoredBindingResolverV2::resolve(
            fixture.run,
            fixture.manifest,
            fixture.executor,
            &[exact, alias],
            &[stored],
            &[],
            &[],
        )
        .unwrap_err(),
        G4Error::DuplicateStoredValueIdentity
    );
}

#[test]
fn token_resolution_rejects_unknown_and_cross_executor_credentials() {
    let fixture = fixture();
    let required = VerifiedRequiredTokenV2::from_verified_policy(
        IdentifierV2::new("mail_oauth").unwrap(),
        Digest32V2::new([0x31; 32]),
        Digest32V2::new([0x32; 32]),
    );
    assert_eq!(
        StoredBindingResolverV2::resolve(
            fixture.run,
            fixture.manifest,
            fixture.executor,
            &[],
            &[],
            std::slice::from_ref(&required),
            &[],
        )
        .unwrap_err(),
        G4Error::UnknownVaultTokenSlot
    );
    let wrong_executor = StoredVaultCredentialV2::from_vault(
        IdentifierV2::new("mail_oauth").unwrap(),
        Digest32V2::new([0x31; 32]),
        Digest32V2::new([0x32; 32]),
        ExecutorIdentityV2::new([0xee; 32]),
    )
    .unwrap();
    assert_eq!(
        StoredBindingResolverV2::resolve(
            fixture.run,
            fixture.manifest,
            fixture.executor,
            &[],
            &[],
            &[required],
            &[wrong_executor],
        )
        .unwrap_err(),
        G4Error::CredentialBindingMismatch
    );
}

struct Fixture {
    run: DurableRunIdV2,
    manifest: Digest32V2,
    executor: ExecutorIdentityV2,
    slot: InternalSlotDigestV2,
    slot_material: VerifiedInternalSlotMaterialV2,
    value_id: ValueInternalIdV2,
    value: KernelValueV2,
    provenance: ProvenanceRecordV2,
}

#[test]
fn stored_business_projection_uses_exact_owned_fields_without_coercion() {
    use savana_kernel_protocol::v2::*;
    let profile = BusinessProfileV2::new(
        ActionCodecProfileV2::McpToolsCallJsonV1,
        "mail.send",
        Digest32V2::new([71; 32]),
        Digest32V2::new([72; 32]),
        TaskEffectV2::Send,
        BusinessMagnitudeV2::CountField,
        vec![
            BusinessFieldV2::new(
                "body",
                BusinessFieldRoleV2::Payload,
                BusinessFieldTypeV2::Text,
            )
            .unwrap(),
            BusinessFieldV2::new(
                "file",
                BusinessFieldRoleV2::Resource,
                BusinessFieldTypeV2::Text,
            )
            .unwrap(),
            BusinessFieldV2::new(
                "quantity",
                BusinessFieldRoleV2::Magnitude,
                BusinessFieldTypeV2::Unsigned,
            )
            .unwrap(),
            BusinessFieldV2::new(
                "to",
                BusinessFieldRoleV2::Destination,
                BusinessFieldTypeV2::Text,
            )
            .unwrap(),
            BusinessFieldV2::new(
                "urgent",
                BusinessFieldRoleV2::Parameter,
                BusinessFieldTypeV2::Boolean,
            )
            .unwrap(),
        ],
    )
    .unwrap();
    let fields = |quantity, to| {
        vec![
            ("body", KernelValueV2::text("private payload").unwrap()),
            ("file", KernelValueV2::text("report-A").unwrap()),
            ("quantity", quantity),
            ("to", to),
            ("urgent", KernelValueV2::boolean(true)),
        ]
    };
    let result = project_business_fields(
        &profile,
        fields(
            KernelValueV2::integer(2),
            KernelValueV2::text("Alice").unwrap(),
        ),
    )
    .unwrap();
    assert_eq!(result.resource(), "report-A");
    assert_eq!(result.destination(), "Alice");
    assert_eq!(result.payload(), "private payload");
    assert_eq!(result.magnitude(), 2);
    assert_eq!(result.canonical_json(), br#"{"id":"request-1","jsonrpc":"2.0","method":"tools/call","params":{"arguments":{"body":"private payload","file":"report-A","quantity":2,"to":"Alice","urgent":true},"name":"mail.send"}}"#);
    for quantity in [
        KernelValueV2::integer(-1),
        KernelValueV2::text("2").unwrap(),
        KernelValueV2::null(),
        KernelValueV2::bytes(vec![2]).unwrap(),
    ] {
        assert!(project_business_fields(
            &profile,
            fields(quantity, KernelValueV2::text("Alice").unwrap())
        )
        .is_err());
    }
    assert!(project_business_fields(
        &profile,
        fields(
            KernelValueV2::integer(2),
            KernelValueV2::list(vec![KernelValueV2::text("Alice").unwrap()]).unwrap()
        )
    )
    .is_err());
    let mut extra = fields(
        KernelValueV2::integer(2),
        KernelValueV2::text("Alice").unwrap(),
    );
    extra.push(("z_auth_override", KernelValueV2::text("secret").unwrap()));
    assert!(project_business_fields(&profile, extra).is_err());
    let bob = project_business_fields(
        &profile,
        fields(
            KernelValueV2::integer(2),
            KernelValueV2::text("Bob").unwrap(),
        ),
    )
    .unwrap();
    assert_ne!(result.destination_digest(), bob.destination_digest());
    assert_ne!(result.digest(), bob.digest());
}

fn project_business_fields(
    profile: &savana_kernel_protocol::v2::BusinessProfileV2,
    fields: Vec<(&str, KernelValueV2)>,
) -> Result<savana_kernel_protocol::v2::BusinessRequestV2, G4Error> {
    let f = fixture();
    let context = ProvenanceContextV2::from_authenticated_runtime(
        ProducerIdentityV2::new([0x13; 32]),
        f.run,
        f.manifest,
        UnixMillisV2::new(100),
        UnixMillisV2::new(900),
    )
    .unwrap();
    let provenance: Vec<_> = fields
        .iter()
        .map(|(_, value)| {
            ProvenanceRecordV2::gated_ingress(
                value,
                context,
                Digest32V2::new([0x14; 32]),
                Digest32V2::new([0x15; 32]),
                Digest32V2::new([0x16; 32]),
                EffectSetV2::ALL,
            )
            .unwrap()
        })
        .collect();
    let slots: Vec<_> = provenance
        .iter()
        .enumerate()
        .map(|(i, p)| {
            slot_material(
                f.run,
                f.manifest,
                ValueInternalIdV2::new([100 + i as u8; 32]),
                p.value_digest(),
                p.provenance_digest(),
                i as u16,
            )
        })
        .collect();
    let arguments: Vec<_> = fields
        .iter()
        .zip(&slots)
        .map(|((name, _), slot)| {
            VerifiedPlanArgumentV2::from_verified_plan(ArgumentNameV2::new(*name).unwrap(), slot)
                .unwrap()
        })
        .collect();
    let records: Vec<_> = fields
        .iter()
        .zip(&slots)
        .zip(&provenance)
        .map(|(((_, value), slot), provenance)| {
            StoredValueRecordV2::from_store(slot, value, provenance).unwrap()
        })
        .collect();
    StoredBindingResolverV2::resolve(
        f.run,
        f.manifest,
        f.executor,
        &arguments,
        &records,
        &[],
        &[],
    )?
    .business_request(profile, "request-1")
}

fn fixture() -> Fixture {
    let run = DurableRunIdV2::new([0x11; 32]);
    let manifest = Digest32V2::new([0x12; 32]);
    let value = KernelValueV2::text("hello").unwrap();
    let context = ProvenanceContextV2::from_authenticated_runtime(
        ProducerIdentityV2::new([0x13; 32]),
        run,
        manifest,
        UnixMillisV2::new(100),
        UnixMillisV2::new(900),
    )
    .unwrap();
    let provenance = ProvenanceRecordV2::gated_ingress(
        &value,
        context,
        Digest32V2::new([0x14; 32]),
        Digest32V2::new([0x15; 32]),
        Digest32V2::new([0x16; 32]),
        EffectSetV2::ALL,
    )
    .unwrap();
    let value_id = ValueInternalIdV2::new([0x19; 32]);
    let slot_material = slot_material(
        run,
        manifest,
        value_id,
        provenance.value_digest(),
        provenance.provenance_digest(),
        1,
    );
    let slot = slot_material.internal_slot_digest().unwrap();
    Fixture {
        run,
        manifest,
        executor: ExecutorIdentityV2::new([0x17; 32]),
        slot,
        slot_material,
        value_id,
        value,
        provenance,
    }
}

fn slot_material(
    run: DurableRunIdV2,
    manifest: Digest32V2,
    value_internal_id: ValueInternalIdV2,
    value_digest: Digest32V2,
    provenance_digest: Digest32V2,
    slot_ordinal: u16,
) -> VerifiedInternalSlotMaterialV2 {
    let resolved_relations = VerifiedResolvedRelationSetV2::new_for_test(
        16,
        vec![ResolvedSlotRelationSemanticV2::new(
            RelationIdV2::new(1),
            slot_ordinal,
            slot_ordinal.saturating_add(1),
        )],
    )
    .unwrap();
    VerifiedInternalSlotMaterialV2::from_resolved_envelope(
        Digest32V2::new([0x10; 32]),
        manifest,
        run,
        slot_ordinal,
        SlotKindV2::new(1),
        ClosedCardinalityV2::ExactlyOne,
        PlannerSlotConfidentialityV2::ConfidentialAbstract,
        vec![RelationIdV2::new(1)],
        value_internal_id,
        value_digest,
        provenance_digest,
        &resolved_relations,
    )
    .unwrap()
}
