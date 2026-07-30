use std::any::TypeId;
use std::collections::BTreeSet;

use savana_kernel_protocol::v2::{
    ActionIntentHandleV2, AgentSessionHandleV2, AgentUiAuthenticationPreparationHandleV2,
    AgentUiAuthorizationHandleV2, ArgumentNameV2, BoundedIdentityStringV2, ExecutionHandleV2,
    ExecutionTicketHandleV2, IngressKernelApprovalHandleV2,
    IngressUiAuthenticationPreparationHandleV2, IngressUiAuthorizationHandleV2,
    IngressWriteCapabilityV2, InputSessionHandleV2, KernelAgentViewCursorV2,
    KernelIngressBootstrapTransferCapabilityV2, MaskedDocumentHandleV2, NewTaskPreparationHandleV2,
    ParserExtractionHandleV2, PendingIngressHandleV2, PendingReleaseHandleV2,
    PendingToolCallHandleV2, PlanStepHandleV2, PlannerTicketHandleV2, ReleaseHandleV2,
    ReleaseKernelApprovalHandleV2, ReleaseTicketHandleV2, RunHandleV2, ToolHandleV2,
    ToolKernelApprovalHandleV2, ValueHandleV2, ZeroizingBytesV2,
};

#[test]
fn kernel_handle_is_fixed_width_nonzero_and_redacted() {
    let handle = AgentSessionHandleV2::from_authority_entropy([0x5a; 32])
        .expect("nonzero authority entropy must construct a handle");

    let mut expected = vec![0x58, 0x20];
    expected.extend_from_slice(&[0x5a; 32]);
    assert_eq!(minicbor::to_vec(handle).unwrap(), expected);
    assert_eq!(format!("{handle:?}"), "AgentSessionHandleV2(<redacted>)");
    assert!(AgentSessionHandleV2::from_authority_entropy([0; 32]).is_none());
}

#[test]
fn kernel_handle_types_and_hash_domains_cannot_be_substituted() {
    assert_ne!(
        TypeId::of::<AgentSessionHandleV2>(),
        TypeId::of::<RunHandleV2>()
    );
    assert_ne!(AgentSessionHandleV2::TYPE_DOMAIN, RunHandleV2::TYPE_DOMAIN);
    assert_ne!(RunHandleV2::TYPE_DOMAIN, ValueHandleV2::TYPE_DOMAIN);
}

#[test]
fn kernel_handle_decoder_rejects_zero_and_wrong_width_tokens() {
    let zero = [vec![0x58, 0x20], vec![0; 32]].concat();
    assert!(minicbor::decode::<AgentSessionHandleV2>(&zero).is_err());
    assert!(minicbor::decode::<AgentSessionHandleV2>(&[0x41, 0x5a]).is_err());
}

#[test]
fn kernel_handle_registry_has_one_type_and_hash_domain_per_authority() {
    let type_ids = [
        TypeId::of::<NewTaskPreparationHandleV2>(),
        TypeId::of::<AgentUiAuthenticationPreparationHandleV2>(),
        TypeId::of::<IngressUiAuthenticationPreparationHandleV2>(),
        TypeId::of::<KernelIngressBootstrapTransferCapabilityV2>(),
        TypeId::of::<IngressUiAuthorizationHandleV2>(),
        TypeId::of::<AgentUiAuthorizationHandleV2>(),
        TypeId::of::<IngressWriteCapabilityV2>(),
        TypeId::of::<InputSessionHandleV2>(),
        TypeId::of::<ParserExtractionHandleV2>(),
        TypeId::of::<PendingIngressHandleV2>(),
        TypeId::of::<AgentSessionHandleV2>(),
        TypeId::of::<RunHandleV2>(),
        TypeId::of::<ValueHandleV2>(),
        TypeId::of::<MaskedDocumentHandleV2>(),
        TypeId::of::<PlanStepHandleV2>(),
        TypeId::of::<PlannerTicketHandleV2>(),
        TypeId::of::<ToolHandleV2>(),
        TypeId::of::<ActionIntentHandleV2>(),
        TypeId::of::<PendingToolCallHandleV2>(),
        TypeId::of::<IngressKernelApprovalHandleV2>(),
        TypeId::of::<ToolKernelApprovalHandleV2>(),
        TypeId::of::<ReleaseKernelApprovalHandleV2>(),
        TypeId::of::<ExecutionTicketHandleV2>(),
        TypeId::of::<ExecutionHandleV2>(),
        TypeId::of::<PendingReleaseHandleV2>(),
        TypeId::of::<ReleaseTicketHandleV2>(),
        TypeId::of::<ReleaseHandleV2>(),
        TypeId::of::<KernelAgentViewCursorV2>(),
    ];
    assert_eq!(
        type_ids.iter().copied().collect::<BTreeSet<_>>().len(),
        type_ids.len()
    );

    let domains = [
        NewTaskPreparationHandleV2::TYPE_DOMAIN,
        AgentUiAuthenticationPreparationHandleV2::TYPE_DOMAIN,
        IngressUiAuthenticationPreparationHandleV2::TYPE_DOMAIN,
        KernelIngressBootstrapTransferCapabilityV2::TYPE_DOMAIN,
        IngressUiAuthorizationHandleV2::TYPE_DOMAIN,
        AgentUiAuthorizationHandleV2::TYPE_DOMAIN,
        IngressWriteCapabilityV2::TYPE_DOMAIN,
        InputSessionHandleV2::TYPE_DOMAIN,
        ParserExtractionHandleV2::TYPE_DOMAIN,
        PendingIngressHandleV2::TYPE_DOMAIN,
        AgentSessionHandleV2::TYPE_DOMAIN,
        RunHandleV2::TYPE_DOMAIN,
        ValueHandleV2::TYPE_DOMAIN,
        MaskedDocumentHandleV2::TYPE_DOMAIN,
        PlanStepHandleV2::TYPE_DOMAIN,
        PlannerTicketHandleV2::TYPE_DOMAIN,
        ToolHandleV2::TYPE_DOMAIN,
        ActionIntentHandleV2::TYPE_DOMAIN,
        PendingToolCallHandleV2::TYPE_DOMAIN,
        IngressKernelApprovalHandleV2::TYPE_DOMAIN,
        ToolKernelApprovalHandleV2::TYPE_DOMAIN,
        ReleaseKernelApprovalHandleV2::TYPE_DOMAIN,
        ExecutionTicketHandleV2::TYPE_DOMAIN,
        ExecutionHandleV2::TYPE_DOMAIN,
        PendingReleaseHandleV2::TYPE_DOMAIN,
        ReleaseTicketHandleV2::TYPE_DOMAIN,
        ReleaseHandleV2::TYPE_DOMAIN,
        KernelAgentViewCursorV2::TYPE_DOMAIN,
    ];
    assert_eq!(
        domains.iter().copied().collect::<BTreeSet<_>>().len(),
        domains.len()
    );
}

#[test]
fn bounded_wire_strings_reject_empty_oversized_and_unsafe_identifiers() {
    let argument = ArgumentNameV2::new("recipient".to_owned()).unwrap();
    assert_eq!(argument.as_str(), "recipient");
    assert!(ArgumentNameV2::new(String::new()).is_err());
    assert!(ArgumentNameV2::new("x".repeat(129)).is_err());
    assert!(ArgumentNameV2::new("line\nbreak".to_owned()).is_err());

    let identity = BoundedIdentityStringV2::new("com.savana.agentd".to_owned()).unwrap();
    assert_eq!(identity.as_str(), "com.savana.agentd");
    assert!(BoundedIdentityStringV2::new("雪".to_owned()).is_err());
    assert!(BoundedIdentityStringV2::new("x".repeat(256)).is_err());
}

#[test]
fn sensitive_wire_bytes_are_bounded_and_debug_redacted() {
    let value = ZeroizingBytesV2::new(vec![0x41, 0x42]).unwrap();
    assert_eq!(value.as_bytes(), &[0x41, 0x42]);
    assert_eq!(format!("{value:?}"), "ZeroizingBytesV2(<redacted>)");
    assert_eq!(minicbor::to_vec(&value).unwrap(), [0x42, 0x41, 0x42]);
    assert!(ZeroizingBytesV2::new(vec![0; 8 * 1024 * 1024 + 1]).is_err());
}
