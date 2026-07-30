use super::deployment_merkle::{deployment_merkle_root_v2, DeploymentMerkleDomainV2};
use super::DeploymentControlErrorV2;

fn decode_hex(value: &str) -> [u8; 32] {
    assert_eq!(value.len(), 64);
    let mut output = [0; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (nibble(pair[0]) << 4) | nibble(pair[1]);
    }
    output
}

fn nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        _ => panic!("invalid test vector"),
    }
}

#[test]
fn file_tree_merkle_vectors_lock_index_pair_odd_and_root_domains() {
    let one = [&[0x81, 0x01][..]];
    let two = [&[0x81, 0x01][..], &[0x81, 0x02][..]];
    let three = [&[0x81, 0x01][..], &[0x81, 0x02][..], &[0x81, 0x03][..]];

    assert_eq!(
        deployment_merkle_root_v2(DeploymentMerkleDomainV2::FileTree, &one)
            .unwrap()
            .as_bytes(),
        &decode_hex("24340d8adc69750327cc092fff12725eb5f4f44ca12a2ebcf640a1127ce7f5a6")
    );
    assert_eq!(
        deployment_merkle_root_v2(DeploymentMerkleDomainV2::FileTree, &two)
            .unwrap()
            .as_bytes(),
        &decode_hex("a5628c7943fa9cb36785d9f93ca9332801b01b6e11c63bb2733cb4027399ec87")
    );
    assert_eq!(
        deployment_merkle_root_v2(DeploymentMerkleDomainV2::FileTree, &three)
            .unwrap()
            .as_bytes(),
        &decode_hex("681733dd31f4e7fbac79fa79155dc5479bda2d94e13a8d8f6fae1ff4090082ca")
    );
}

#[test]
fn staging_tree_merkle_uses_a_distinct_closed_domain() {
    let three = [&[0x81, 0x01][..], &[0x81, 0x02][..], &[0x81, 0x03][..]];
    assert_eq!(
        deployment_merkle_root_v2(DeploymentMerkleDomainV2::StagingTree, &three)
            .unwrap()
            .as_bytes(),
        &decode_hex("b278e703e31a92727974214dc3e18f126274659c3b146d3ebd934dbfac1d9938")
    );
}

#[test]
fn deployment_merkle_rejects_empty_and_over_limit_trees() {
    assert_eq!(
        deployment_merkle_root_v2(DeploymentMerkleDomainV2::FileTree, &[]).unwrap_err(),
        DeploymentControlErrorV2::InvalidDeploymentTree
    );

    let entry = &[0x80][..];
    let oversized = vec![entry; 65_537];
    assert_eq!(
        deployment_merkle_root_v2(DeploymentMerkleDomainV2::StagingTree, &oversized).unwrap_err(),
        DeploymentControlErrorV2::DeploymentTreeLimitExceeded
    );
}
