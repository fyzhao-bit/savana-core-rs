use savana_kernel_protocol::v2::{
    ActionTemplateIdV2, DisplayProjectionIdV2, DurableReleaseIdV2, DurableTaskIdV2, EntityIdV2,
    ImplementationIdV2, InternalStepIdV2, NamespaceIdV2, OntologySetIdV2, PlanRevisionDigestV2,
    PlannerRouteIdV2, ProjectionIdV2, RoleIdV2, RunRevisionDigestV2, ServiceIdentityV2,
    ToolClassIdV2, VersionV2,
};

#[test]
fn closed_manifest_ids_are_canonical_u32_newtypes() {
    assert_eq!(minicbor::to_vec(RoleIdV2::new(23)).unwrap(), [0x17]);
    assert_eq!(
        minicbor::to_vec(ActionTemplateIdV2::new(24)).unwrap(),
        [0x18, 0x18]
    );
    assert_eq!(ToolClassIdV2::new(7).get(), 7);
    assert_eq!(NamespaceIdV2::new(8).get(), 8);
    assert_eq!(EntityIdV2::new(9).get(), 9);
    assert_eq!(OntologySetIdV2::new(10).get(), 10);
    assert_eq!(ProjectionIdV2::new(11).get(), 11);
    assert_eq!(DisplayProjectionIdV2::new(12).get(), 12);
    assert_eq!(ImplementationIdV2::new(13).get(), 13);
    assert_eq!(PlannerRouteIdV2::new(14).get(), 14);
}

#[test]
fn version_and_semantic_identities_have_exact_shapes() {
    assert_eq!(
        minicbor::to_vec(VersionV2::new(1, 2, 3)).unwrap(),
        [0x83, 0x01, 0x02, 0x03]
    );
    assert_eq!(VersionV2::new(1, 2, 3).major(), 1);

    assert_eq!(
        minicbor::to_vec(ServiceIdentityV2::new([1; 32]))
            .unwrap()
            .len(),
        34
    );
    assert_eq!(
        minicbor::to_vec(DurableTaskIdV2::new([2; 32]))
            .unwrap()
            .len(),
        34
    );
    assert_eq!(
        minicbor::to_vec(DurableReleaseIdV2::new([3; 32]))
            .unwrap()
            .len(),
        34
    );
    assert_eq!(
        minicbor::to_vec(InternalStepIdV2::new([4; 32]))
            .unwrap()
            .len(),
        34
    );
    assert_eq!(
        minicbor::to_vec(RunRevisionDigestV2::new([5; 32]))
            .unwrap()
            .len(),
        34
    );
    assert_eq!(
        minicbor::to_vec(PlanRevisionDigestV2::new([6; 32]))
            .unwrap()
            .len(),
        34
    );
}
