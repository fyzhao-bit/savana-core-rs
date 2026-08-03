mod support;

use savana_client::{ApprovalPurpose, BrowserRoute, ConnectorDescriptor, HandleKind, SavanaError};
use savana_kernel_protocol::v2::{
    decode_agent_browser_request_v2, encode_agent_browser_mutation_response_v2,
    AgentBrowserActionV2, AgentBrowserMutationResponseV2, AgentBrowserRequestV2,
    AgentPendingConnectorRegistrationRefV2, AgentSessionStatusV2,
    ApprovalDecisionBrowserFinishResponseV2, ApprovalDisplayAuthenticationTransferCapabilityV2,
    ApprovalPurposeV2, Digest32V2, ExecutorIdentityV2, FixedBrowserFormPostCarrierV2,
};
use savana_policy_core::v2::{
    AttemptKindV2, BoundedConnectorRetryPolicyV2, ConnectorDescriptorV2, ConnectorStructuralRoleV2,
    ConnectorTierV2, EffectSetV2, ExecutorIdempotencyContractV2, IdentifierV2,
    InternalValidatorDeclarationV2, UnsignedToolDescriptorV2,
};
use sha2::{Digest as _, Sha256};
use support::task5::{approval_responses, authenticated_session, cbor_response, RecordingDecision};

fn mutation(
    response: AgentBrowserMutationResponseV2,
) -> Result<savana_client::BrowserResponse, SavanaError> {
    cbor_response(encode_agent_browser_mutation_response_v2(&response).unwrap())
}

fn valid_descriptor() -> (Vec<u8>, Digest32V2) {
    const NAME: &str = "sdk-task5-connector";
    let digest = |byte| Digest32V2::new([byte; 32]);
    let package = digest(0xc1);
    let mut identity = minicbor::Encoder::new(Vec::new());
    identity
        .array(2)
        .unwrap()
        .str(NAME)
        .unwrap()
        .array(2)
        .unwrap()
        .u16(1)
        .unwrap()
        .bytes(package.as_bytes())
        .unwrap();
    let mut hasher = Sha256::new();
    hasher.update(b"savana.connector.user.v2\0");
    hasher.update(identity.into_writer());
    let connector_id = Digest32V2::new(hasher.finalize().into());
    let contract = ExecutorIdempotencyContractV2::ConnectorIdempotentByExecutionNonce;
    let tool = UnsignedToolDescriptorV2::from_verified_manifest(
        2,
        savana_kernel_protocol::v2::VersionV2::new(1, 0, 0),
        digest(0xc2),
        IdentifierV2::new("sdk.task5.send").unwrap(),
        savana_kernel_protocol::v2::ActionTemplateIdV2::new(778),
        savana_kernel_protocol::v2::ToolClassIdV2::new(777),
        digest(0xc3),
        digest(0xc4),
        vec![savana_kernel_protocol::v2::RoleIdV2::new(1)],
        EffectSetV2::SEND,
        AttemptKindV2::ToolWrite,
        BoundedConnectorRetryPolicyV2::new(contract, 2, 1_000).unwrap(),
        vec![InternalValidatorDeclarationV2::new(
            savana_kernel_protocol::v2::ImplementationIdV2::new(779),
            savana_kernel_protocol::v2::VersionV2::new(1, 0, 0),
            digest(0xc5),
        )],
        ExecutorIdentityV2::new([0xc6; 32]),
        savana_kernel_protocol::v2::ProjectionIdV2::new(780),
        digest(0xc7),
        savana_kernel_protocol::v2::DisplayProjectionIdV2::new(781),
        digest(0xc8),
        contract,
        savana_kernel_protocol::v2::UnixMillisV2::new(1),
        savana_kernel_protocol::v2::UnixMillisV2::new(10_000),
    )
    .unwrap();
    let mut descriptor = minicbor::Encoder::new(Vec::new());
    descriptor
        .array(8)
        .unwrap()
        .bytes(connector_id.as_bytes())
        .unwrap()
        .str(NAME)
        .unwrap()
        .u16(ConnectorTierV2::UserRegistered.tag())
        .unwrap()
        .array(2)
        .unwrap()
        .u16(1)
        .unwrap()
        .bytes(package.as_bytes())
        .unwrap()
        .array(1)
        .unwrap();
    descriptor
        .writer_mut()
        .extend_from_slice(&minicbor::to_vec(&tool).unwrap());
    descriptor
        .u16(EffectSetV2::SEND.bits())
        .unwrap()
        .u16(ConnectorStructuralRoleV2::Sink.tag())
        .unwrap()
        .u64(1)
        .unwrap();
    let bytes = descriptor.into_writer();
    assert_eq!(
        ConnectorDescriptorV2::from_canonical_bytes_for_local_projection(&bytes)
            .unwrap()
            .connector_id(),
        connector_id
    );
    (bytes, connector_id)
}

fn registry_snapshot(ids: &[(Digest32V2, bool)]) -> Vec<u8> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(6)
        .unwrap()
        .u16(1)
        .unwrap()
        .bytes(&[0x31; 32])
        .unwrap()
        .bytes(&[0x32; 32])
        .unwrap()
        .u64(7)
        .unwrap()
        .bytes(&[0x33; 32])
        .unwrap()
        .array(ids.len() as u64)
        .unwrap();
    for (id, active) in ids {
        encoder
            .array(2)
            .unwrap()
            .bytes(id.as_bytes())
            .unwrap()
            .bool(*active)
            .unwrap();
    }
    encoder.into_writer()
}

fn actions_after_authentication(
    requests: &[savana_client::BrowserRequest],
) -> Vec<AgentBrowserActionV2> {
    requests[4..]
        .iter()
        .filter(|request| request.route == BrowserRoute::AgentAction)
        .map(
            |request| match decode_agent_browser_request_v2(&request.body).unwrap() {
                AgentBrowserRequestV2::Act { action, .. } => action,
                _ => panic!("agent action route must contain Act"),
            },
        )
        .collect()
}

#[test]
fn malformed_or_noncanonical_descriptor_is_rejected_before_transport() {
    let (session, transport, _) = authenticated_session(Vec::new());
    transport.take_requests();

    assert!(ConnectorDescriptor::from_canonical_bytes(&[0x81, 0x01]).is_err());
    let (mut bytes, _) = valid_descriptor();
    bytes.push(0);
    assert!(ConnectorDescriptor::from_canonical_bytes(&bytes).is_err());

    assert!(transport.take_requests().is_empty());
    drop(session);
}

#[test]
fn registration_validates_then_approves_finalizes_and_returns_connector_handle() {
    let (canonical, connector_id) = valid_descriptor();
    let descriptor = ConnectorDescriptor::from_canonical_bytes(&canonical).unwrap();
    let pending =
        AgentPendingConnectorRegistrationRefV2::from_authority_entropy([0x41; 16]).unwrap();
    let transfer =
        ApprovalDisplayAuthenticationTransferCapabilityV2::from_authority_entropy([0x42; 32])
            .unwrap();
    let mut responses = vec![mutation(
        AgentBrowserMutationResponseV2::ConnectorOpenApproval {
            pending,
            post: FixedBrowserFormPostCarrierV2::AgentApprovalDisplay(transfer),
        },
    )];
    responses.extend(approval_responses(
        ApprovalPurposeV2::ConnectorRegistration,
        ApprovalDecisionBrowserFinishResponseV2::Approved,
    ));
    responses.push(mutation(
        AgentBrowserMutationResponseV2::ConnectorRegistrationCommitted {
            pending,
            signed_delta_digest: Digest32V2::new([0x43; 32]),
            head_digest: Digest32V2::new([0x44; 32]),
            sequence: 1,
            connector_id,
        },
    ));
    let (mut session, transport, _) = authenticated_session(responses);
    let approval = RecordingDecision::new(true);

    let connector = session.register_connector(&descriptor, &approval).unwrap();

    assert_eq!(connector.kind(), HandleKind::Connector);
    assert_eq!(
        approval.requests.lock().unwrap().as_slice(),
        [(
            "Approve exact operation".to_owned(),
            ApprovalPurpose::ConnectorRegistration,
        )]
    );
    let requests = transport.take_requests();
    assert_eq!(
        requests[4..]
            .iter()
            .map(|request| request.route)
            .collect::<Vec<_>>(),
        vec![
            BrowserRoute::AgentAction,
            BrowserRoute::ApprovalUiAuthenticationAccept,
            BrowserRoute::ApprovalUiAuthenticationBegin,
            BrowserRoute::ApprovalUiAuthenticationFinish,
            BrowserRoute::ApprovalDisplay,
            BrowserRoute::ApprovalDecisionBegin,
            BrowserRoute::ApprovalDecisionFinish,
            BrowserRoute::AgentAction,
        ]
    );
    assert_eq!(
        actions_after_authentication(&requests),
        vec![
            AgentBrowserActionV2::RegisterConnector(canonical),
            AgentBrowserActionV2::FinalizeConnectorRegistration(pending),
        ]
    );
}

#[test]
fn rejected_connector_approval_attempts_finalize_once_then_closes_locally() {
    let (canonical, _) = valid_descriptor();
    let descriptor = ConnectorDescriptor::from_canonical_bytes(&canonical).unwrap();
    let pending =
        AgentPendingConnectorRegistrationRefV2::from_authority_entropy([0x49; 16]).unwrap();
    let transfer =
        ApprovalDisplayAuthenticationTransferCapabilityV2::from_authority_entropy([0x4a; 32])
            .unwrap();
    let mut responses = vec![mutation(
        AgentBrowserMutationResponseV2::ConnectorOpenApproval {
            pending,
            post: FixedBrowserFormPostCarrierV2::AgentApprovalDisplay(transfer),
        },
    )];
    responses.extend(approval_responses(
        ApprovalPurposeV2::ConnectorRegistration,
        ApprovalDecisionBrowserFinishResponseV2::Denied,
    ));
    responses.push(Err(SavanaError::InvalidResponse));
    let (mut session, transport, _) = authenticated_session(responses);

    assert!(matches!(
        session.register_connector(&descriptor, &RecordingDecision::new(false)),
        Err(SavanaError::ApprovalDenied(_))
    ));

    let requests = transport.take_requests();
    assert_eq!(
        actions_after_authentication(&requests),
        vec![
            AgentBrowserActionV2::RegisterConnector(canonical),
            AgentBrowserActionV2::FinalizeConnectorRegistration(pending),
        ]
    );
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.route == BrowserRoute::AgentAction)
            .count(),
        2,
        "denied cleanup must be attempted once without retry"
    );
    assert!(matches!(
        session.list_connectors(),
        Err(SavanaError::InvalidState)
    ));
    assert!(transport.take_requests().is_empty());
}

#[test]
fn committed_registration_must_match_pending_and_descriptor_id() {
    let (canonical, connector_id) = valid_descriptor();
    let descriptor = ConnectorDescriptor::from_canonical_bytes(&canonical).unwrap();
    let pending =
        AgentPendingConnectorRegistrationRefV2::from_authority_entropy([0x51; 16]).unwrap();
    let different_pending =
        AgentPendingConnectorRegistrationRefV2::from_authority_entropy([0x52; 16]).unwrap();
    let transfer =
        ApprovalDisplayAuthenticationTransferCapabilityV2::from_authority_entropy([0x53; 32])
            .unwrap();
    for (committed_pending, committed_id) in [
        (different_pending, connector_id),
        (pending, Digest32V2::new([0x54; 32])),
    ] {
        let mut responses = vec![mutation(
            AgentBrowserMutationResponseV2::ConnectorOpenApproval {
                pending,
                post: FixedBrowserFormPostCarrierV2::AgentApprovalDisplay(transfer),
            },
        )];
        responses.extend(approval_responses(
            ApprovalPurposeV2::ConnectorRegistration,
            ApprovalDecisionBrowserFinishResponseV2::Approved,
        ));
        responses.push(mutation(
            AgentBrowserMutationResponseV2::ConnectorRegistrationCommitted {
                pending: committed_pending,
                signed_delta_digest: Digest32V2::new([0x55; 32]),
                head_digest: Digest32V2::new([0x56; 32]),
                sequence: 1,
                connector_id: committed_id,
            },
        ));
        let (mut session, transport, _) = authenticated_session(responses);
        assert!(matches!(
            session.register_connector(&descriptor, &RecordingDecision::new(true)),
            Err(SavanaError::InvalidState)
        ));
        assert_eq!(
            actions_after_authentication(&transport.take_requests()).len(),
            2,
            "ambiguous registration must not retry"
        );
    }
}

#[test]
fn snapshot_returns_only_session_bound_connector_id_handles() {
    let first = Digest32V2::new([0x61; 32]);
    let second = Digest32V2::new([0x62; 32]);
    let snapshot = registry_snapshot(&[(first, true), (second, false)]);
    let (mut session, transport, _) = authenticated_session(vec![mutation(
        AgentBrowserMutationResponseV2::ConnectorRegistrySnapshot {
            canonical_snapshot:
                savana_kernel_protocol::v2::BoundedConnectorRegistrySnapshotV2::new(snapshot)
                    .unwrap(),
        },
    )]);

    let connectors = session.list_connectors().unwrap();

    assert_eq!(connectors.len(), 2);
    assert!(connectors
        .iter()
        .all(|connector| connector.kind() == HandleKind::Connector));
    assert_eq!(
        actions_after_authentication(&transport.take_requests()),
        vec![AgentBrowserActionV2::SnapshotConnectors]
    );

    let (mut other, other_transport, _) = authenticated_session(Vec::new());
    other_transport.take_requests();
    assert!(matches!(
        other.remove_connector(&connectors[0]),
        Err(SavanaError::WrongSession)
    ));
    assert!(other_transport.take_requests().is_empty());
}

#[test]
fn malformed_ambiguous_or_noncanonical_snapshot_fails_without_retry() {
    let id = Digest32V2::new([0x71; 32]);
    let malformed = [
        vec![0x81, 0x01],
        registry_snapshot(&[(id, true), (id, false)]),
        {
            let mut bytes = registry_snapshot(&[(id, true)]);
            bytes[1] = 2;
            bytes
        },
    ];
    for snapshot in malformed {
        let (mut session, transport, _) = authenticated_session(vec![mutation(
            AgentBrowserMutationResponseV2::ConnectorRegistrySnapshot {
                canonical_snapshot:
                    savana_kernel_protocol::v2::BoundedConnectorRegistrySnapshotV2::new(snapshot)
                        .unwrap(),
            },
        )]);
        assert!(matches!(
            session.list_connectors(),
            Err(SavanaError::InvalidResponse)
        ));
        assert_eq!(
            actions_after_authentication(&transport.take_requests()),
            vec![AgentBrowserActionV2::SnapshotConnectors]
        );
    }
}

#[test]
fn removal_requires_connector_kind_and_exact_committed_id() {
    let connector_id = Digest32V2::new([0x81; 32]);
    let snapshot = registry_snapshot(&[(connector_id, true)]);
    let responses = vec![
        mutation(AgentBrowserMutationResponseV2::ConnectorRegistrySnapshot {
            canonical_snapshot:
                savana_kernel_protocol::v2::BoundedConnectorRegistrySnapshotV2::new(snapshot)
                    .unwrap(),
        }),
        mutation(AgentBrowserMutationResponseV2::ConnectorRemovalCommitted {
            signed_delta_digest: Digest32V2::new([0x82; 32]),
            head_digest: Digest32V2::new([0x83; 32]),
            sequence: 2,
            connector_id,
        }),
    ];
    let (mut session, transport, _) = authenticated_session(responses);
    let connector = session.list_connectors().unwrap().remove(0);

    session.remove_connector(&connector).unwrap();

    assert_eq!(
        actions_after_authentication(&transport.take_requests()),
        vec![
            AgentBrowserActionV2::SnapshotConnectors,
            AgentBrowserActionV2::RemoveConnector(connector_id),
        ]
    );

    let (mut wrong_kind_session, wrong_kind_transport, _) = authenticated_session(Vec::new());
    let document = wrong_kind_session.initial_document().clone();
    wrong_kind_transport.take_requests();
    assert!(matches!(
        wrong_kind_session.remove_connector(&document),
        Err(SavanaError::WrongHandleKind { .. })
    ));
    assert!(wrong_kind_transport.take_requests().is_empty());
}

#[test]
fn removal_mismatch_fails_closed_and_never_retries() {
    let connector_id = Digest32V2::new([0x91; 32]);
    let snapshot = registry_snapshot(&[(connector_id, true)]);
    let responses = vec![
        mutation(AgentBrowserMutationResponseV2::ConnectorRegistrySnapshot {
            canonical_snapshot:
                savana_kernel_protocol::v2::BoundedConnectorRegistrySnapshotV2::new(snapshot)
                    .unwrap(),
        }),
        mutation(AgentBrowserMutationResponseV2::ConnectorRemovalCommitted {
            signed_delta_digest: Digest32V2::new([0x92; 32]),
            head_digest: Digest32V2::new([0x93; 32]),
            sequence: 2,
            connector_id: Digest32V2::new([0x94; 32]),
        }),
    ];
    let (mut session, transport, _) = authenticated_session(responses);
    let connector = session.list_connectors().unwrap().remove(0);

    assert!(matches!(
        session.remove_connector(&connector),
        Err(SavanaError::InvalidState)
    ));

    assert_eq!(
        actions_after_authentication(&transport.take_requests()),
        vec![
            AgentBrowserActionV2::SnapshotConnectors,
            AgentBrowserActionV2::RemoveConnector(connector_id),
        ]
    );
}

#[test]
fn closed_session_rejects_every_connector_workflow_before_transport() {
    let (canonical, _) = valid_descriptor();
    let descriptor = ConnectorDescriptor::from_canonical_bytes(&canonical).unwrap();
    let (mut session, transport, _) = authenticated_session(vec![mutation(
        AgentBrowserMutationResponseV2::SessionClosed {
            state: AgentSessionStatusV2::Closed,
        },
    )]);
    let document = session.initial_document().clone();
    session.close().unwrap();
    transport.take_requests();

    assert!(matches!(
        session.register_connector(&descriptor, &RecordingDecision::new(true)),
        Err(SavanaError::InvalidState)
    ));
    assert!(matches!(
        session.remove_connector(&document),
        Err(SavanaError::InvalidState)
    ));
    assert!(matches!(
        session.list_connectors(),
        Err(SavanaError::InvalidState)
    ));
    assert!(transport.take_requests().is_empty());
}
