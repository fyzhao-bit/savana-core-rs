#![cfg(target_os = "macos")]

use std::path::Path;

use savana_policy_core::load_verified_macos_development_startup_v2;
use savana_policy_core::v2::DeploymentTrustErrorV2;

#[test]
fn development_startup_rejects_authority_paths_outside_the_fixed_root() {
    let result = load_verified_macos_development_startup_v2(
        Path::new("/tmp/deployment-manifest-root-v2.json"),
        Path::new("/tmp/deployment-manifest-v2.cbor"),
        Path::new("/tmp/effect-ledger-projection-v2.cbor"),
        &[],
    );
    assert_eq!(
        result.unwrap_err(),
        DeploymentTrustErrorV2::UnsafeFilesystem
    );
}
