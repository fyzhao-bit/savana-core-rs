use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

fn workspace_metadata(workspace_root: &Path) -> serde_json::Value {
    let output = Command::new(env!("CARGO"))
        .args(["metadata", "--locked", "--no-deps", "--format-version", "1"])
        .current_dir(workspace_root)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn rust_sources_below(directory: &Path, output: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(directory).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_sources_below(&path, output);
        } else if path.extension().and_then(|extension| extension.to_str()) == Some("rs") {
            output.push(path);
        }
    }
}

#[test]
fn production_workspace_contains_exactly_the_eleven_frozen_crates() {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap();
    let metadata = workspace_metadata(workspace_root);
    let packages = metadata["packages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|package| {
            (
                package["id"].as_str().unwrap(),
                package["name"].as_str().unwrap(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut members = metadata["workspace_members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|member| packages[member.as_str().unwrap()])
        .collect::<Vec<_>>();
    members.sort_unstable();

    assert_eq!(
        members,
        [
            "savana-agentd",
            "savana-approvald",
            "savana-execd",
            "savana-ingressd",
            "savana-input-runtime",
            "savana-kernel-protocol",
            "savana-kerneld",
            "savana-leak-gate",
            "savana-platform-identity",
            "savana-policy-core",
            "savana-vault",
        ]
    );
}

#[test]
fn unsafe_code_is_confined_to_the_audited_platform_adapter_files() {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap();
    let metadata = workspace_metadata(workspace_root);
    let allowed = [
        workspace_root.join("crates/savana-platform-identity/src/linux.rs"),
        workspace_root
            .join("crates/savana-platform-identity/src/worker_sandbox/linux_worker_sandbox.rs"),
        workspace_root.join("crates/savana-platform-identity/src/macos/ffi.rs"),
        workspace_root
            .join("crates/savana-platform-identity/src/worker_sandbox/macos_worker_sandbox.rs"),
    ];

    for package in metadata["packages"].as_array().unwrap() {
        let manifest = Path::new(package["manifest_path"].as_str().unwrap());
        let crate_root = manifest.parent().unwrap();
        let manifest_text = fs::read_to_string(manifest).unwrap();
        let is_platform_identity = package["name"].as_str().unwrap() == "savana-platform-identity";
        if is_platform_identity {
            assert!(
                manifest_text.contains("[lints.rust]\nunsafe_code = \"deny\""),
                "platform identity must deny unsafe at crate scope"
            );
        } else {
            assert!(
                manifest_text.contains("[lints]\nworkspace = true"),
                "{} must inherit workspace unsafe_code=forbid",
                package["name"]
            );
        }

        let mut sources = Vec::new();
        rust_sources_below(&crate_root.join("src"), &mut sources);
        for source in sources {
            let text = fs::read_to_string(&source).unwrap();
            let contains_unsafe_code = [
                "unsafe {",
                "unsafe fn ",
                "unsafe impl ",
                "unsafe trait ",
                "unsafe extern ",
            ]
            .iter()
            .any(|token| text.contains(token));
            assert!(
                !contains_unsafe_code || allowed.contains(&source),
                "unsafe code escaped the audited FFI boundary: {}",
                source.display()
            );
        }
    }
}
