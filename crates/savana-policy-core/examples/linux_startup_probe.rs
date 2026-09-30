//! Disposable staged-artifact acceptance only; never authenticates a user.
use savana_policy_core::v2::{
    load_verified_filesystem_startup_v2, FilesystemServiceObservationConfigV2,
};
use std::path::Path;

fn main() {
    assert!(cfg!(target_os = "linux"));
    assert_ne!(nix::unistd::geteuid().as_raw(), 0);
    let value: serde_json::Value =
        serde_json::from_slice(&std::fs::read("/etc/savana/kerneld-bootstrap-v2.json").unwrap())
            .unwrap();
    let observations: Vec<FilesystemServiceObservationConfigV2> =
        serde_json::from_value(value["services"].clone()).unwrap();
    load_verified_filesystem_startup_v2(
        Path::new("/etc/savana/trust/deployment-manifest-root-v2.json"),
        Path::new("/etc/savana/deployment-manifest-v2.cbor"),
        Path::new("/etc/savana/effect-ledger-projection-v2.cbor"),
        &observations,
    )
    .expect("non-root signed startup-artifact verification");
    println!("non-root startup artifacts verified; no services/authentication claimed");
}
