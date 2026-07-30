use savana_kernel_protocol::v2::Digest32V2;
use sha2::{Digest as _, Sha256};

use super::{DeploymentControlErrorV2, DeploymentHardLimitsV2};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DeploymentMerkleDomainV2 {
    FileTree,
    StagingTree,
}

impl DeploymentMerkleDomainV2 {
    const fn leaf(self) -> &'static [u8] {
        match self {
            Self::FileTree => b"savana.file-tree.v2.leaf\0",
            Self::StagingTree => b"savana.staging-tree.v2.leaf\0",
        }
    }

    const fn node(self) -> &'static [u8] {
        match self {
            Self::FileTree => b"savana.file-tree.v2.node\0",
            Self::StagingTree => b"savana.staging-tree.v2.node\0",
        }
    }

    const fn odd(self) -> &'static [u8] {
        match self {
            Self::FileTree => b"savana.file-tree.v2.odd\0",
            Self::StagingTree => b"savana.staging-tree.v2.odd\0",
        }
    }

    const fn root(self) -> &'static [u8] {
        match self {
            Self::FileTree => b"savana.file-tree.v2.root\0",
            Self::StagingTree => b"savana.staging-tree.v2.root\0",
        }
    }
}

pub(super) fn deployment_merkle_root_v2(
    domain: DeploymentMerkleDomainV2,
    canonical_entries: &[&[u8]],
) -> Result<Digest32V2, DeploymentControlErrorV2> {
    if canonical_entries.is_empty() {
        return Err(DeploymentControlErrorV2::InvalidDeploymentTree);
    }
    if canonical_entries.len() as u64 > DeploymentHardLimitsV2::compiled().max_file_tree_entries() {
        return Err(DeploymentControlErrorV2::DeploymentTreeLimitExceeded);
    }

    let mut level = Vec::new();
    level
        .try_reserve_exact(canonical_entries.len())
        .map_err(|_| DeploymentControlErrorV2::DeploymentTreeLimitExceeded)?;
    for (index, entry) in canonical_entries.iter().enumerate() {
        let index = u64::try_from(index)
            .map_err(|_| DeploymentControlErrorV2::DeploymentTreeLimitExceeded)?;
        level.push(hash_parts(&[domain.leaf(), &index.to_be_bytes(), entry]));
    }

    while level.len() > 1 {
        let next_len = level.len().div_ceil(2);
        let mut next = Vec::new();
        next.try_reserve_exact(next_len)
            .map_err(|_| DeploymentControlErrorV2::DeploymentTreeLimitExceeded)?;
        for pair in level.chunks(2) {
            let digest = if let [left, right] = pair {
                hash_parts(&[domain.node(), left, right])
            } else {
                hash_parts(&[domain.odd(), &pair[0]])
            };
            next.push(digest);
        }
        level = next;
    }

    let count = u64::try_from(canonical_entries.len())
        .map_err(|_| DeploymentControlErrorV2::DeploymentTreeLimitExceeded)?;
    Ok(Digest32V2::new(hash_parts(&[
        domain.root(),
        &count.to_be_bytes(),
        &level[0],
    ])))
}

fn hash_parts(parts: &[&[u8]]) -> [u8; 32] {
    let mut hash = Sha256::new();
    for part in parts {
        hash.update(part);
    }
    hash.finalize().into()
}
