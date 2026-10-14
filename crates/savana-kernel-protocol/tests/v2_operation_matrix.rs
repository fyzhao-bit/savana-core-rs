use std::collections::BTreeSet;

use savana_kernel_protocol::v2::{
    kernel_service_operation_has_error_contract_v2, kernel_service_operation_tags_for_role_v2,
    kernel_service_public_error_is_allowed_v2, EndpointRoleV2, PublicStableCodeV2,
};

const KERNEL_ROLES: [EndpointRoleV2; 3] = [
    EndpointRoleV2::AgentKernel,
    EndpointRoleV2::IngressKernel,
    EndpointRoleV2::KernelExecutor,
];

const NON_KERNEL_ROLES: [EndpointRoleV2; 4] = [
    EndpointRoleV2::JarvisAgentControl,
    EndpointRoleV2::AgentApproval,
    EndpointRoleV2::IngressApproval,
    EndpointRoleV2::ApprovalAdmin,
];

#[test]
fn all_57_kernel_operations_have_one_role_and_one_frozen_error_contract() {
    let mut routes = BTreeSet::new();
    for role in KERNEL_ROLES {
        let tags = kernel_service_operation_tags_for_role_v2(role).unwrap();
        assert!(tags.windows(2).all(|pair| pair[0] < pair[1]));
        for tag in tags {
            assert!(routes.insert((role.tag(), *tag)));
            assert!(kernel_service_operation_has_error_contract_v2(role, *tag));
            assert!(
                kernel_service_public_error_is_allowed_v2(
                    role,
                    *tag,
                    PublicStableCodeV2::ServiceUnavailable,
                ),
                "{role:?}/{tag} must retain a fail-closed unavailable response"
            );
        }
    }
    assert_eq!(routes.len(), 57);
    assert!(kernel_service_operation_has_error_contract_v2(
        EndpointRoleV2::KernelExecutor,
        64,
    ));
    assert!(kernel_service_public_error_is_allowed_v2(
        EndpointRoleV2::KernelExecutor,
        64,
        PublicStableCodeV2::RegistryMismatch,
    ));
}

#[test]
fn kernel_operation_registry_rejects_role_and_tag_substitution() {
    for role in NON_KERNEL_ROLES {
        assert!(kernel_service_operation_tags_for_role_v2(role).is_none());
    }

    for role in KERNEL_ROLES {
        let own = kernel_service_operation_tags_for_role_v2(role).unwrap();
        for other in KERNEL_ROLES {
            if role == other {
                continue;
            }
            for tag in kernel_service_operation_tags_for_role_v2(other).unwrap() {
                if own.contains(tag) {
                    continue;
                }
                assert!(!kernel_service_operation_has_error_contract_v2(role, *tag));
                assert!(!kernel_service_public_error_is_allowed_v2(
                    role,
                    *tag,
                    PublicStableCodeV2::ServiceUnavailable,
                ));
            }
        }
    }
}
