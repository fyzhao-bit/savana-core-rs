mod support;

use savana_client::{SavanaError, TaskAuthorizationDraft};
use savana_kernel_protocol::v2::*;
use support::task5::{authenticated_session, task_authorization_draft as draft};

#[test]
fn task_draft_sdk_is_data_only_closed_and_requires_authenticated_ingress() {
    let bytes = encode_task_authorization_draft_v2(&draft()).unwrap();
    let input = TaskAuthorizationDraft::from_canonical_bytes(&bytes).unwrap();
    assert_eq!(input.canonical_bytes(), bytes);
    assert!(!format!("{input:?}").contains("Alice"));
    for end in 0..bytes.len() {
        assert!(TaskAuthorizationDraft::from_canonical_bytes(&bytes[..end]).is_err());
    }
    let mut trailing = bytes;
    trailing.push(0);
    assert!(TaskAuthorizationDraft::from_canonical_bytes(&trailing).is_err());
    let (mut session, transport, _) = authenticated_session(vec![]);
    transport.take_requests();
    assert!(matches!(
        session.establish_task_authorization(&input),
        Err(SavanaError::InvalidState)
    ));
    assert!(matches!(
        session.revoke_task_authorization(&input),
        Err(SavanaError::InvalidState)
    ));
    assert!(transport.take_requests().is_empty());
}
