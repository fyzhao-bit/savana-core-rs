use savana_kernel_protocol::v2::*;
use sha2::{Digest as _, Sha256};

fn publication() -> PrivatePublicationV04 {
    let payload = b"actual released result";
    let mut h = Sha256::new();
    h.update(b"SAVANA_FINAL_RELEASE_PAYLOAD_V2\0");
    h.update((payload.len() as u64).to_be_bytes());
    h.update(payload);
    PrivatePublicationV04::new(
        DurableTaskIdV2::new([1; 32]),
        DurableRunIdV2::new([2; 32]),
        Digest32V2::new([3; 32]),
        BootIdV2::new([4; 32]),
        DurableReleaseIdV2::new([5; 32]),
        Digest32V2::new(h.finalize().into()),
        Digest32V2::new([7; 32]),
        Digest32V2::new([8; 32]),
        Digest32V2::new([9; 32]),
        Digest32V2::new([10; 32]),
        Digest32V2::new([11; 32]),
    )
    .unwrap()
}

#[test]
fn private_publication_canonical_unknown_and_exact_payload() {
    let p = publication();
    assert!(p.matches_payload(b"actual released result"));
    assert!(!p.matches_payload(b"model says completed"));
    assert!(!p.matches_payload(&vec![0; 32769]));
    for value in [None, Some(p)] {
        let bytes = encode_private_publication_status_v04(value).unwrap();
        assert_eq!(
            decode_private_publication_status_v04(&bytes).unwrap(),
            value
        );
        let mut extra = bytes.clone();
        extra.push(0);
        assert!(decode_private_publication_status_v04(&extra).is_err());
        let mut version = bytes;
        version[1] = 3;
        assert!(decode_private_publication_status_v04(&version).is_err());
    }
    let bytes = encode_private_publication_v04(p).unwrap();
    let mut zero_task = bytes.clone();
    zero_task[4..36].fill(0);
    assert!(decode_private_publication_v04(&zero_task).is_err());
    let mut long = bytes;
    long.push(0);
    assert!(decode_private_publication_v04(&long).is_err());
}

#[test]
fn private_publication_ipc_has_only_kernel_approval_role() {
    let operation = ApprovalServiceOperationV2::AttachPrivatePublicationV04 {
        session: ApprovalUiRecordHandleV2::from_authority_entropy([1; 32]).unwrap(),
        publication: publication(),
    };
    assert_eq!(operation.role(), EndpointRoleV2::KernelApproval);
    assert_eq!(operation.tag(), 27);
    let request =
        ApprovalServiceRequestV2::new(RequestIdV2::new([1; 16]), UnixMillisV2::new(500), operation)
            .unwrap();
    let encoded = encode_approval_service_request_v2(&request).unwrap();
    assert_eq!(
        decode_approval_service_request_v2(&encoded, EndpointRoleV2::KernelApproval, 27).unwrap(),
        request
    );
    assert!(
        decode_approval_service_request_v2(&encoded, EndpointRoleV2::AgentApproval, 27).is_err()
    );
}
