use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey as Ed25519SigningKey;
use p256::ecdsa::SigningKey as P256SigningKey;
use savana_approvald::{
    ApprovalErrorV2, ApprovalRollbackAnchorV2, ApprovalServiceV2, ApprovalStateHeadV2,
    ApprovalStateOwnerV2, DurableApprovalNamespaceV2,
};
use savana_kernel_protocol::v2::{Digest32V2, PrincipalIdV2};

#[derive(Clone, Default)]
struct TestAnchor(Arc<Mutex<ApprovalStateHeadV2>>);

impl ApprovalRollbackAnchorV2 for TestAnchor {
    fn current_head(&self) -> Result<ApprovalStateHeadV2, ApprovalErrorV2> {
        self.0
            .lock()
            .map(|head| *head)
            .map_err(|_| ApprovalErrorV2::DurableState)
    }

    fn compare_and_advance(
        &mut self,
        expected: ApprovalStateHeadV2,
        next: ApprovalStateHeadV2,
    ) -> Result<(), ApprovalErrorV2> {
        let mut head = self.0.lock().map_err(|_| ApprovalErrorV2::DurableState)?;
        if *head != expected {
            return Err(ApprovalErrorV2::RollbackDetected);
        }
        *head = next;
        Ok(())
    }
}

#[test]
fn durable_credential_mutation_runs_through_the_owner_thread() {
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let installation = Digest32V2::new([1; 32]);
    let kernel_key = Ed25519SigningKey::from_bytes(&[2; 32]);
    let deployment = ApprovalServiceV2::from_verified_deployment(
        installation,
        Digest32V2::new([3; 32]),
        4,
        Digest32V2::new([5; 32]),
        kernel_key.verifying_key().to_bytes(),
        Digest32V2::new([6; 32]),
        [7; 32],
    )
    .unwrap();
    let namespace = DurableApprovalNamespaceV2::from_verified_installation(
        installation,
        Digest32V2::new([8; 32]),
    )
    .unwrap();
    let owner = ApprovalStateOwnerV2::open(
        &root.path().join("approval-state-v2.cbor"),
        [9; 32],
        namespace,
        Box::new(TestAnchor::default()),
        deployment,
        4,
    )
    .unwrap();
    let p256_key = P256SigningKey::from_slice(&[10; 32]).unwrap();
    let mut sec1 = [0_u8; 65];
    sec1.copy_from_slice(p256_key.verifying_key().to_encoded_point(false).as_bytes());

    owner
        .load_verified_hardware_credential(
            Digest32V2::new([11; 32]),
            PrincipalIdV2::new([12; 32]),
            [13; 16],
            sec1,
            1,
            Instant::now() + Duration::from_secs(2),
        )
        .unwrap();
}
