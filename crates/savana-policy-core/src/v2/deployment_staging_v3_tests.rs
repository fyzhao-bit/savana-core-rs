use super::super::deployment_v3_test_support::{sign_transaction, transaction_material};
use super::super::*;
use super::*;
use sha2::{Digest, Sha256};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

const PLAN_NAMES: [&str; 6] = [
    "MigrationPlanV2.cbor",
    "ArtifactInstallPlanV2.cbor",
    "ServiceTransitionPlanV2.cbor",
    "IsolatedE2EPlanV2.cbor",
    "EvidenceContractV2.cbor",
    "ProtectedAcceptancePlanV2.cbor",
];
fn d(n: u8) -> Digest32V2 {
    Digest32V2::new([n; 32])
}
fn tags(e: &mut minicbor::Encoder<Vec<u8>>, end: u16) {
    e.array(u64::from(end)).unwrap();
    for n in 1..=end {
        e.u16(n).unwrap();
    }
}
fn plans() -> [Vec<u8>; 6] {
    let migration = MigrationPlanV2::new(vec![])
        .unwrap()
        .canonical_bytes()
        .to_vec();
    let artifacts = ArtifactInstallPlanV2::new(ArtifactInstallPlanV2::complete_operations())
        .unwrap()
        .canonical_bytes()
        .to_vec();
    let mut e = minicbor::Encoder::new(Vec::new());
    e.array(4).unwrap();
    for _ in 0..4 {
        e.array(1).unwrap().u16(4).unwrap();
    }
    let services = e.into_writer();
    let mut e = minicbor::Encoder::new(Vec::new());
    e.array(4).unwrap();
    tags(&mut e, 16);
    for n in [1, 2, 3] {
        e.bytes(d(n).as_bytes()).unwrap();
    }
    let isolated = e.into_writer();
    let mut e = minicbor::Encoder::new(Vec::new());
    e.array(5).unwrap();
    tags(&mut e, 9);
    tags(&mut e, 7);
    e.u16(2)
        .unwrap()
        .array(1)
        .unwrap()
        .array(2)
        .unwrap()
        .u16(1)
        .unwrap()
        .u16(1)
        .unwrap()
        .u16(1)
        .unwrap();
    let evidence = e.into_writer();
    let mut e = minicbor::Encoder::new(Vec::new());
    e.array(3).unwrap();
    tags(&mut e, 11);
    e.bytes(d(3).as_bytes())
        .unwrap()
        .bytes(d(4).as_bytes())
        .unwrap();
    [
        migration,
        artifacts,
        services,
        isolated,
        evidence,
        e.into_writer(),
    ]
}
fn fixture(
    overridden: Option<usize>,
    wrong_digest: Option<usize>,
) -> (
    tempfile::TempDir,
    DeploymentApplySelectorV2,
    DeploymentTransactionV2,
) {
    let state = DeploymentLedgerStateV3::new(DeploymentLedgerMaterialV3 {
        installation: d(1),
        epoch: 1,
        generation: 1,
        written_at_ms: 150000,
        phase: DeploymentPhaseV2::Idle,
        transaction: None,
        effects_fenced: false,
        fence_epoch: 1,
        active_manifest: d(2),
        active_activation: ActiveActivationV2::Normal,
        identity_profile: d(3),
        bootstrap_tcb_lock: d(4),
        highest_ever: HighestEverV2::new(std::array::from_fn(|_| {
            HighWaterEntryV2::new(1, d(5), 1).unwrap()
        }))
        .unwrap(),
        grant: RollbackGrantStateV2::None,
        rollback_grant_id: None,
        rollback_origin: None,
        transaction_head: None,
        previous_payload: d(0),
    })
    .unwrap();
    let mut material = transaction_material(&state);
    let mut plans = plans();
    let mut digests = [
        MigrationPlanV2::from_canonical_bytes(&plans[0])
            .unwrap()
            .digest(),
        ArtifactInstallPlanV2::from_canonical_bytes(&plans[1])
            .unwrap()
            .digest(),
        ServiceTransitionPlanV2::from_canonical_bytes(&plans[2])
            .unwrap()
            .digest(),
        IsolatedE2EPlanV2::from_canonical_bytes(&plans[3])
            .unwrap()
            .digest(),
        EvidenceContractV2::from_canonical_bytes(&plans[4])
            .unwrap()
            .digest(),
        ProtectedAcceptancePlanV2::from_canonical_bytes(&plans[5])
            .unwrap()
            .digest(),
    ];
    if let Some(i) = wrong_digest {
        digests[i] = d(199);
    }
    [
        material.migration_plan_digest,
        material.artifact_install_plan_digest,
        material.service_transition_plan_digest,
        material.isolated_e2e_plan_digest,
        material.evidence_contract_digest,
        material.protected_acceptance_plan_digest,
    ] = digests;
    if let Some(i) = overridden {
        plans[i] = vec![0xff];
    }
    let acl = Digest32V2::new(Sha256::digest(b"savana.linux-staging.v3.empty-acl\0").into());
    let xattr = Digest32V2::new(Sha256::digest(b"savana.linux-staging.v3.empty-xattr\0").into());
    let mut entries = Vec::new();
    for (i, bytes) in plans.iter().enumerate() {
        entries.push(
            StagingEntryV2::new_regular(
                ClosedStagingPathIdV2::from_tag(i as u16 + 1).unwrap(),
                bytes.len() as u64,
                Digest32V2::new(Sha256::digest(bytes).into()),
                0o600,
                acl,
                xattr,
            )
            .unwrap(),
        );
    }
    entries.push(
        StagingEntryV2::new_directory(
            ClosedStagingPathIdV2::ArtifactPayloadRoot,
            0o700,
            acl,
            xattr,
        )
        .unwrap(),
    );
    for tag in 10..=44 {
        let payload = format!("synthetic-{tag}");
        entries.push(
            StagingEntryV2::new_regular(
                ClosedStagingPathIdV2::from_tag(tag).unwrap(),
                payload.len() as u64,
                Digest32V2::new(Sha256::digest(payload.as_bytes()).into()),
                0o600,
                acl,
                xattr,
            )
            .unwrap(),
        );
    }
    material.staging_tree_digest = StagingTreeV2::new(entries).unwrap().merkle_root();
    let selector_digest =
        staging_selector_v2(material.transaction_id, material.staging_tree_digest);
    use std::fmt::Write as _;
    let leaf = selector_digest
        .as_bytes()
        .iter()
        .fold(String::new(), |mut s, b| {
            write!(s, "{b:02x}").unwrap();
            s
        });
    let selector = DeploymentApplySelectorV2::parse_arguments(
        ["deploy".into(), "apply".into(), leaf.clone().into()].into_iter(),
    )
    .unwrap();
    let transaction = sign_transaction(material);
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let dir = root.path().join(leaf);
    fs::create_dir(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    fs::create_dir(dir.join("ArtifactPayloadRoot")).unwrap();
    fs::set_permissions(
        dir.join("ArtifactPayloadRoot"),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    for (name, bytes) in PLAN_NAMES.iter().zip(plans) {
        write(&dir.join(name), &bytes, 0o600);
    }
    for tag in 10..=44 {
        write(
            &dir.join("ArtifactPayloadRoot").join(tag.to_string()),
            format!("synthetic-{tag}").as_bytes(),
            0o600,
        );
    }
    write(
        &dir.join("DeploymentTransactionV2.cbor"),
        transaction.canonical_bytes(),
        0o400,
    );
    (root, selector, transaction)
}
fn write(path: &Path, bytes: &[u8], mode: u32) {
    if path.exists() {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}
fn dir(root: &Path) -> std::path::PathBuf {
    fs::read_dir(root).unwrap().next().unwrap().unwrap().path()
}

#[test]
fn linux_staging_signed_transaction_measures_and_decodes_all_six_plans() {
    let (root, selector, tx) = fixture(None, None);
    let spool = FixedDeploymentSpoolV2::open_for_test(root.path()).unwrap();
    let mut verified = VerifiedDeploymentStagingV3::open(&spool, selector, &tx).unwrap();
    assert_eq!(
        verified.tree().merkle_root(),
        tx.intent().material().staging_tree_digest
    );
    assert_eq!(verified.tree().entries().len(), 42);
    assert_eq!(verified.artifacts().operations().len(), 75);
    assert_eq!(verified.evidence().required_review_count(), 2);
    verified.revalidate().unwrap();
    write(
        &dir(root.path()).join("ArtifactPayloadRoot/13"),
        b"changed kernel",
        0o600,
    );
    assert!(verified.revalidate().is_err());
}

#[test]
fn linux_staging_rejects_each_wrong_plan_digest_and_malformed_signed_plan() {
    for i in 0..6 {
        for malformed in [false, true] {
            let (root, selector, tx) = fixture(malformed.then_some(i), (!malformed).then_some(i));
            let spool = FixedDeploymentSpoolV2::open_for_test(root.path()).unwrap();
            assert!(
                VerifiedDeploymentStagingV3::open(&spool, selector, &tx).is_err(),
                "plan {i}, malformed {malformed}"
            );
        }
    }
}

#[test]
fn linux_staging_rejects_actual_byte_tamper_descriptor_swap_and_wrong_selector() {
    for case in 0..4 {
        let (root, selector, tx) = fixture(None, None);
        let staged = dir(root.path());
        match case {
            0 => write(
                &staged.join("ArtifactPayloadRoot/13"),
                b"different payload",
                0o600,
            ),
            1 => write(
                &staged.join("DeploymentTransactionV2.cbor"),
                b"different transaction",
                0o400,
            ),
            2 => write(&staged.join("unexpected"), b"extra", 0o600),
            3 => (),
            _ => unreachable!(),
        }
        let selector = if case == 3 {
            DeploymentApplySelectorV2::parse_arguments(
                ["deploy".into(), "apply".into(), "cc".repeat(32).into()].into_iter(),
            )
            .unwrap()
        } else {
            selector
        };
        let spool = FixedDeploymentSpoolV2::open_for_test(root.path()).unwrap();
        assert!(VerifiedDeploymentStagingV3::open(&spool, selector, &tx).is_err());
    }
}
