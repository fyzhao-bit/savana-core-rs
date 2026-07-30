use crate::v2::{
    ArgumentNameV2, AttemptKindV2, ContextFieldV2, FieldNameV2, FieldPathV2, G4Error,
    KernelValueV2, OntologyExprV2, OntologyOperandV2, OntologyScalarV2,
};
use savana_kernel_protocol::v2::{
    Digest32V2, DurableTaskIdV2, NamespaceIdV2, OntologySetIdV2, PrincipalIdV2, RoleIdV2,
    ToolClassIdV2,
};

use super::{
    ManifestOntologySetRefV2, OntologyEvaluationContextV2, OntologyEvaluationV2,
    VerifiedOntologySetV2,
};

#[test]
fn ontology_scalar_operand_and_context_tags_are_exact() {
    assert_eq!(
        minicbor::to_vec(OntologyScalarV2::null()).unwrap(),
        [0x81, 0x00]
    );
    assert_eq!(
        minicbor::to_vec(OntologyScalarV2::boolean(true)).unwrap(),
        [0x82, 0x01, 0xf5]
    );
    assert_eq!(
        minicbor::to_vec(OntologyOperandV2::context(ContextFieldV2::Role)).unwrap(),
        [0x82, 0x03, 0x81, 0x01]
    );
}

#[test]
fn ontology_text_and_field_paths_are_bounded_and_nfc() {
    assert!(OntologyScalarV2::text("é").is_ok());
    assert_eq!(
        OntologyScalarV2::text("e\u{301}").unwrap_err(),
        G4Error::InvalidText
    );
    assert!(FieldPathV2::new(Vec::new()).is_ok());
    assert_eq!(
        FieldPathV2::new(
            (0..17)
                .map(|index| FieldNameV2::new(format!("f{index}")).unwrap())
                .collect()
        )
        .unwrap_err(),
        G4Error::PathLimitExceeded
    );
}

#[test]
fn ontology_boolean_nodes_enforce_children_depth_and_total_nodes() {
    assert_eq!(
        OntologyExprV2::all(Vec::new()).unwrap_err(),
        G4Error::BooleanChildCount
    );

    let leaf = || {
        OntologyExprV2::eq(
            OntologyOperandV2::context(ContextFieldV2::Role),
            OntologyOperandV2::literal(OntologyScalarV2::integer(1)),
        )
    };
    assert_eq!(
        OntologyExprV2::all((0..33).map(|_| leaf()).collect()).unwrap_err(),
        G4Error::BooleanChildCount
    );

    let mut too_deep = leaf();
    for _ in 0..7 {
        too_deep = OntologyExprV2::all(vec![too_deep]).unwrap();
    }
    assert_eq!(
        OntologyExprV2::all(vec![too_deep]).unwrap_err(),
        G4Error::OntologyDepthExceeded
    );

    let large = OntologyExprV2::all((0..32).map(|_| leaf()).collect()).unwrap();
    assert_eq!(
        OntologyExprV2::all((0..8).map(|_| large.clone()).collect()).unwrap_err(),
        G4Error::OntologyNodeLimitExceeded
    );
}

#[test]
fn ontology_evaluation_matches_exact_values_and_errors_fail_closed() {
    let argument_value = KernelValueV2::integer(7);
    let context = OntologyEvaluationContextV2::new(
        vec![(ArgumentNameV2::new("count").unwrap(), &argument_value)],
        Vec::new(),
        Vec::new(),
        RoleIdV2::new(3),
        ToolClassIdV2::new(4),
        AttemptKindV2::ToolWrite,
        PrincipalIdV2::new([5; 32]),
        DurableTaskIdV2::new([6; 32]),
    )
    .unwrap();

    let count = OntologyOperandV2::argument(
        ArgumentNameV2::new("count").unwrap(),
        FieldPathV2::new(Vec::new()).unwrap(),
    );
    let matches = OntologyExprV2::eq(
        count,
        OntologyOperandV2::literal(OntologyScalarV2::integer(7)),
    );
    assert_eq!(matches.evaluate(&context), OntologyEvaluationV2::Match);
    assert!(matches.evaluate(&context).permits());

    let missing = OntologyExprV2::eq(
        OntologyOperandV2::argument(
            ArgumentNameV2::new("missing").unwrap(),
            FieldPathV2::new(Vec::new()).unwrap(),
        ),
        OntologyOperandV2::literal(OntologyScalarV2::integer(7)),
    );
    assert_eq!(
        missing.evaluate(&context),
        OntologyEvaluationV2::EvaluationError
    );
    assert!(!missing.evaluate(&context).permits());

    let type_mismatch = OntologyExprV2::eq(
        OntologyOperandV2::context(ContextFieldV2::Role),
        OntologyOperandV2::literal(OntologyScalarV2::text("role").unwrap()),
    );
    assert_eq!(
        type_mismatch.evaluate(&context),
        OntologyEvaluationV2::EvaluationError
    );

    let false_expr = OntologyExprV2::eq(
        OntologyOperandV2::context(ContextFieldV2::Role),
        OntologyOperandV2::literal(OntologyScalarV2::integer(99)),
    );
    assert_eq!(
        OntologyExprV2::all(vec![false_expr, missing.clone()])
            .unwrap()
            .evaluate(&context),
        OntologyEvaluationV2::EvaluationError
    );
    assert_eq!(
        OntologyExprV2::any(vec![matches, missing])
            .unwrap()
            .evaluate(&context),
        OntologyEvaluationV2::EvaluationError
    );
}

#[test]
fn ontology_sets_require_the_exact_manifest_reference() {
    let set_digest = Digest32V2::new([9; 32]);
    let set = VerifiedOntologySetV2::new(
        NamespaceIdV2::new(1),
        OntologySetIdV2::new(2),
        set_digest,
        vec![OntologyScalarV2::integer(7)],
    )
    .unwrap();
    let context = OntologyEvaluationContextV2::new(
        Vec::new(),
        Vec::new(),
        vec![set],
        RoleIdV2::new(7),
        ToolClassIdV2::new(4),
        AttemptKindV2::ToolRead,
        PrincipalIdV2::new([5; 32]),
        DurableTaskIdV2::new([6; 32]),
    )
    .unwrap();
    let exact = OntologyExprV2::in_set(
        OntologyOperandV2::context(ContextFieldV2::Role),
        ManifestOntologySetRefV2::new(NamespaceIdV2::new(1), OntologySetIdV2::new(2), set_digest),
    );
    assert_eq!(exact.evaluate(&context), OntologyEvaluationV2::Match);

    let wrong_digest = OntologyExprV2::in_set(
        OntologyOperandV2::context(ContextFieldV2::Role),
        ManifestOntologySetRefV2::new(
            NamespaceIdV2::new(1),
            OntologySetIdV2::new(2),
            Digest32V2::new([8; 32]),
        ),
    );
    assert_eq!(
        wrong_digest.evaluate(&context),
        OntologyEvaluationV2::EvaluationError
    );
}
