use savana_kernel_protocol::v2::Digest32V2;
use savana_policy_core::v2::{
    DeploymentBranchV2, DeploymentControlErrorV2, DeploymentHardLimitsV2, EvidenceContractV2,
    IsolatedE2EPlanV2, ProtectedAcceptancePlanV2, ServiceTransitionPlanV2,
};
use sha2::{Digest as _, Sha256};

const SERVICE_PLAN_DOMAIN: &[u8] = b"savana.service-transition-plan.v2\0";
const E2E_PLAN_DOMAIN: &[u8] = b"savana.isolated-e2e-plan.v2\0";
const EVIDENCE_CONTRACT_DOMAIN: &[u8] = b"savana.evidence-contract.v2\0";
const ACCEPTANCE_PLAN_DOMAIN: &[u8] = b"savana.protected-acceptance-plan.v2\0";

fn digest(byte: u8) -> [u8; 32] {
    [byte; 32]
}

fn domain_digest(domain: &[u8], bytes: &[u8]) -> Digest32V2 {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(bytes);
    Digest32V2::new(hash.finalize().into())
}

fn encode_tags(encoder: &mut minicbor::Encoder<Vec<u8>>, tags: &[u16]) {
    encoder.array(tags.len() as u64).unwrap();
    for tag in tags {
        encoder.u16(*tag).unwrap();
    }
}

fn service_plan(stop: &[u16], candidate: &[u16], rollback: &[u16], readiness: &[u16]) -> Vec<u8> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder.array(4).unwrap();
    encode_tags(&mut encoder, stop);
    encode_tags(&mut encoder, candidate);
    encode_tags(&mut encoder, rollback);
    encode_tags(&mut encoder, readiness);
    encoder.into_writer()
}

fn e2e_plan(cases: &[u16], planner: [u8; 32], connector: [u8; 32], isolation: [u8; 32]) -> Vec<u8> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder.array(4).unwrap();
    encode_tags(&mut encoder, cases);
    encoder.bytes(&planner).unwrap();
    encoder.bytes(&connector).unwrap();
    encoder.bytes(&isolation).unwrap();
    encoder.into_writer()
}

fn evidence_contract(
    verification: &[u16],
    commit: &[u16],
    review_count: u16,
    platforms: &[(u16, u16)],
    retention: u16,
) -> Vec<u8> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder.array(5).unwrap();
    encode_tags(&mut encoder, verification);
    encode_tags(&mut encoder, commit);
    encoder.u16(review_count).unwrap();
    encoder.array(platforms.len() as u64).unwrap();
    for (os, architecture) in platforms {
        encoder.array(2).unwrap();
        encoder.u16(*os).unwrap();
        encoder.u16(*architecture).unwrap();
    }
    encoder.u16(retention).unwrap();
    encoder.into_writer()
}

fn acceptance_plan(cases: &[u16], isolation: [u8; 32], sink: [u8; 32]) -> Vec<u8> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder.array(3).unwrap();
    encode_tags(&mut encoder, cases);
    encoder.bytes(&isolation).unwrap();
    encoder.bytes(&sink).unwrap();
    encoder.into_writer()
}

#[test]
fn service_transition_plan_accepts_only_closed_duplicate_free_service_orders() {
    let canonical = service_plan(
        &[2, 3, 5, 6, 4, 1],
        &[4, 5, 6, 3, 2, 1],
        &[4, 5, 6, 3, 2, 1],
        &[4, 5, 6, 3, 2, 1],
    );
    let plan = ServiceTransitionPlanV2::from_canonical_bytes(&canonical).unwrap();
    assert_eq!(plan.canonical_bytes(), canonical);
    assert_eq!(
        plan.digest(),
        domain_digest(SERVICE_PLAN_DOMAIN, &canonical)
    );
    assert!(plan
        .validate_branch_shape(DeploymentBranchV2::Normal)
        .is_ok());

    let duplicate = service_plan(&[2, 2], &[4], &[4], &[4]);
    assert_eq!(
        ServiceTransitionPlanV2::from_canonical_bytes(&duplicate).unwrap_err(),
        DeploymentControlErrorV2::InvalidDeploymentPlan
    );

    let unknown = service_plan(&[9], &[4], &[4], &[4]);
    assert_eq!(
        ServiceTransitionPlanV2::from_canonical_bytes(&unknown).unwrap_err(),
        DeploymentControlErrorV2::InvalidDeploymentPlan
    );
}

#[test]
fn bootstrap_bridge_service_plan_forbids_stop_and_rollback_start_orders() {
    let legal = service_plan(&[], &[4, 5, 6, 3, 2, 1], &[], &[4, 5, 6, 3, 2, 1]);
    let legal = ServiceTransitionPlanV2::from_canonical_bytes(&legal).unwrap();
    assert!(legal
        .validate_branch_shape(DeploymentBranchV2::BootstrapBridgeRestore)
        .is_ok());

    let illegal = service_plan(&[2], &[4], &[], &[4]);
    let illegal = ServiceTransitionPlanV2::from_canonical_bytes(&illegal).unwrap();
    assert_eq!(
        illegal
            .validate_branch_shape(DeploymentBranchV2::BootstrapBridgeRestore)
            .unwrap_err(),
        DeploymentControlErrorV2::InvalidDeploymentPlan
    );
}

#[test]
fn isolated_e2e_plan_requires_the_complete_ordered_closed_case_set() {
    let complete: Vec<u16> = (1..=16).collect();
    let canonical = e2e_plan(&complete, digest(1), digest(2), digest(3));
    let plan = IsolatedE2EPlanV2::from_canonical_bytes(&canonical).unwrap();
    assert_eq!(plan.canonical_bytes(), canonical);
    assert_eq!(plan.digest(), domain_digest(E2E_PLAN_DOMAIN, &canonical));

    let missing = e2e_plan(&complete[..15], digest(1), digest(2), digest(3));
    assert_eq!(
        IsolatedE2EPlanV2::from_canonical_bytes(&missing).unwrap_err(),
        DeploymentControlErrorV2::InvalidDeploymentPlan
    );

    let mut reordered = complete;
    reordered.swap(14, 15);
    let reordered = e2e_plan(&reordered, digest(1), digest(2), digest(3));
    assert_eq!(
        IsolatedE2EPlanV2::from_canonical_bytes(&reordered).unwrap_err(),
        DeploymentControlErrorV2::InvalidDeploymentPlan
    );
}

#[test]
fn evidence_contract_requires_complete_fields_and_sorted_unique_platforms() {
    let verification: Vec<u16> = (1..=9).collect();
    let commit: Vec<u16> = (1..=7).collect();
    let canonical = evidence_contract(
        &verification,
        &commit,
        2,
        &[(1, 1), (1, 2), (2, 1), (2, 2)],
        1,
    );
    let contract = EvidenceContractV2::from_canonical_bytes(&canonical).unwrap();
    assert_eq!(contract.canonical_bytes(), canonical);
    assert_eq!(
        contract.digest(),
        domain_digest(EVIDENCE_CONTRACT_DOMAIN, &canonical)
    );

    let missing_field = evidence_contract(&verification[..8], &commit, 2, &[(1, 1)], 1);
    assert_eq!(
        EvidenceContractV2::from_canonical_bytes(&missing_field).unwrap_err(),
        DeploymentControlErrorV2::InvalidDeploymentPlan
    );

    let duplicate_platform = evidence_contract(&verification, &commit, 2, &[(1, 1), (1, 1)], 1);
    assert_eq!(
        EvidenceContractV2::from_canonical_bytes(&duplicate_platform).unwrap_err(),
        DeploymentControlErrorV2::InvalidDeploymentPlan
    );

    let zero_review = evidence_contract(&verification, &commit, 0, &[(1, 1)], 1);
    assert_eq!(
        EvidenceContractV2::from_canonical_bytes(&zero_review).unwrap_err(),
        DeploymentControlErrorV2::InvalidDeploymentPlan
    );
}

#[test]
fn protected_acceptance_plan_requires_all_cases_and_nonzero_bindings() {
    let complete: Vec<u16> = (1..=11).collect();
    let canonical = acceptance_plan(&complete, digest(7), digest(8));
    let plan = ProtectedAcceptancePlanV2::from_canonical_bytes(&canonical).unwrap();
    assert_eq!(plan.canonical_bytes(), canonical);
    assert_eq!(
        plan.digest(),
        domain_digest(ACCEPTANCE_PLAN_DOMAIN, &canonical)
    );

    let missing = acceptance_plan(&complete[..10], digest(7), digest(8));
    assert_eq!(
        ProtectedAcceptancePlanV2::from_canonical_bytes(&missing).unwrap_err(),
        DeploymentControlErrorV2::InvalidDeploymentPlan
    );

    let zero_binding = acceptance_plan(&complete, [0; 32], digest(8));
    assert_eq!(
        ProtectedAcceptancePlanV2::from_canonical_bytes(&zero_binding).unwrap_err(),
        DeploymentControlErrorV2::InvalidDeploymentPlan
    );
}

#[test]
fn deployment_plans_reject_noncanonical_and_oversized_cbor() {
    let noncanonical = vec![0x9f, 0x80, 0x80, 0x80, 0x80, 0xff];
    assert_eq!(
        ServiceTransitionPlanV2::from_canonical_bytes(&noncanonical).unwrap_err(),
        DeploymentControlErrorV2::InvalidDeploymentPlan
    );

    let oversized = vec![0; 4_194_305];
    assert_eq!(
        IsolatedE2EPlanV2::from_canonical_bytes(&oversized).unwrap_err(),
        DeploymentControlErrorV2::DeploymentPlanLimitExceeded
    );
}

#[test]
fn deployment_hard_limits_are_one_canonical_protocol_lock() {
    let limits = DeploymentHardLimitsV2::compiled();
    assert_eq!(limits.max_transaction_bytes(), 1_048_576);
    assert_eq!(limits.max_plan_bytes(), 4_194_304);
    assert_eq!(limits.max_file_tree_entries(), 65_536);
    assert_eq!(limits.max_staging_tree_bytes(), 68_719_476_736);
    assert_eq!(limits.max_attestation_bytes(), 16_777_216);
    assert_eq!(
        limits.values(),
        &[
            1_048_576,
            4_194_304,
            4_194_304,
            4_096,
            4_096,
            4_096,
            32,
            4_096,
            86_400_000_000_000,
            3_600_000_000_000,
            3_600_000_000_000,
            300_000_000_000,
            65_536,
            64,
            8_589_934_592,
            68_719_476_736,
            4_096,
            64,
            64,
            64,
            64,
            64,
            256,
            65_536,
            1_073_741_824,
            64,
            4_096,
            16_777_216,
            255,
        ]
    );
    assert_eq!(
        limits.digest().as_bytes(),
        &decode_hex_32("8518c18736a469cf07432c4f7921ae08c5c684f1052ce87fff5b4deec9a7d79c")
    );
}

fn decode_hex_32(value: &str) -> [u8; 32] {
    assert_eq!(value.len(), 64);
    let mut output = [0; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]);
    }
    output
}

fn hex_nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        _ => panic!("invalid test vector"),
    }
}
