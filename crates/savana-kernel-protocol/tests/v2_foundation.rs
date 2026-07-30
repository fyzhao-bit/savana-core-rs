use std::any::TypeId;

use savana_kernel_protocol::v2::{
    decode_agent_control_operation_v2, AgentControlOperationV2, EndpointRoleV2,
    JarvisBootstrapSelectorV2, RequestIdV2, TaskHandleV2,
};

#[test]
fn endpoint_roles_use_the_frozen_v2_tags() {
    let cases = [
        (EndpointRoleV2::JarvisAgentControl, 1_u8),
        (EndpointRoleV2::AgentKernel, 2),
        (EndpointRoleV2::IngressKernel, 3),
        (EndpointRoleV2::KernelExecutor, 4),
        (EndpointRoleV2::AgentApproval, 5),
        (EndpointRoleV2::IngressApproval, 6),
        (EndpointRoleV2::ApprovalAdmin, 7),
    ];

    for (role, tag) in cases {
        assert_eq!(minicbor::to_vec(role).unwrap(), [0x81, tag]);
    }
}

#[test]
fn task_handle_is_fixed_width_and_debug_redacted() {
    let mut operation = vec![0x82, 0x0b, 0x81, 0x58, 0x20];
    operation.extend_from_slice(&[0x5a; 32]);
    let handle = match decode_agent_control_operation_v2(&operation).unwrap() {
        AgentControlOperationV2::GetTaskStatus(request) => request.task(),
        _ => unreachable!(),
    };

    assert_eq!(format!("{handle:?}"), "TaskHandleV2(<opaque>)");
    let mut expected = vec![0x58, 0x20];
    expected.extend_from_slice(&[0x5a; 32]);
    assert_eq!(minicbor::to_vec(handle).unwrap(), expected);
    assert!(decode_agent_control_operation_v2(&[0x82, 0x0b, 0x81, 0x41, 0x5a]).is_err());
}

#[test]
fn selector_and_task_handle_remain_distinct_types() {
    assert_ne!(
        TypeId::of::<JarvisBootstrapSelectorV2>(),
        TypeId::of::<TaskHandleV2>()
    );
    assert_eq!(size_of::<JarvisBootstrapSelectorV2>(), 32);
    assert_eq!(size_of::<TaskHandleV2>(), 32);

    let request = RequestIdV2::new([1; 16]);
    assert_eq!(request.as_bytes(), &[1; 16]);
}
