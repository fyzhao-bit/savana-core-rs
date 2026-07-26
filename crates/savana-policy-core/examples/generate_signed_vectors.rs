#[path = "../tests/support/mod.rs"]
mod policy_support;

use std::cmp::Ordering;
use std::error::Error;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signer, SigningKey};
use savana_kernel_protocol::Signature64;
use sha2::{Digest, Sha256};

#[path = "../../../tools/vector_output.rs"]
mod vector_output;

use vector_output::OutputDirectory;

const RELEASE_DOMAIN: &[u8] = b"SAVANA_RELEASE_V1\0";
const RELEASE_TARGET_DOMAIN: &[u8] = b"SAVANA_RELEASE_TARGET_V1\0";
const TARGETS: [&str; 4] = [
    "policy-bundle-v1.cbor",
    "policy-bundle-v1.sig",
    "release-manifest-v1.cbor",
    "release-manifest-v1.sig",
];
const KNOWN_VECTOR_FILES: [&str; 8] = [
    "README.md",
    "client-hello-v1.cbor",
    "server-hello-v1.cbor",
    "policy-flow-v1.cbor",
    "policy-bundle-v1.cbor",
    "policy-bundle-v1.sig",
    "release-manifest-v1.cbor",
    "release-manifest-v1.sig",
];
fn main() {
    let status = run_cli(std::env::args_os());
    if status != 0 {
        std::process::exit(status);
    }
}

fn run_cli(arguments: impl Iterator<Item = OsString>) -> i32 {
    match generate(arguments) {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("signed vector generation failed: {error}");
            64
        }
    }
}

fn generate(arguments: impl Iterator<Item = OsString>) -> Result<(), Box<dyn Error>> {
    let (output_path, overwrite) = parse_arguments(arguments)?;
    let output = prepare_output(&output_path, overwrite)?;

    let (policy, policy_signature) = policy_support::signed(&policy_support::valid_policy(7, 3));
    let (release, release_signature) = release_vector();
    for (name, bytes) in [
        (TARGETS[0], policy.as_slice()),
        (TARGETS[1], policy_signature.as_bytes().as_slice()),
        (TARGETS[2], release.as_slice()),
        (TARGETS[3], release_signature.as_bytes().as_slice()),
    ] {
        write_vector(&output, name, bytes, overwrite)?;
    }
    output.finish(&KNOWN_VECTOR_FILES)?;
    Ok(())
}

fn parse_arguments(
    mut arguments: impl Iterator<Item = OsString>,
) -> Result<(PathBuf, bool), Box<dyn Error>> {
    let _program = arguments.next().ok_or("missing program name")?;
    let mut output = None;
    let mut overwrite = false;
    while let Some(argument) = arguments.next() {
        if argument == "--output" {
            if output.is_some() {
                return Err("duplicate --output".into());
            }
            output = Some(PathBuf::from(
                arguments.next().ok_or("missing --output value")?,
            ));
        } else if argument == "--overwrite" {
            if overwrite {
                return Err("duplicate --overwrite".into());
            }
            overwrite = true;
        } else {
            return Err("unknown argument".into());
        }
    }
    let output = output.ok_or("exactly one --output is required")?;
    if output.as_os_str().is_empty() {
        return Err("output directory is empty".into());
    }
    Ok((output, overwrite))
}

fn prepare_output(output: &Path, overwrite: bool) -> std::io::Result<OutputDirectory> {
    OutputDirectory::prepare(output, overwrite, &KNOWN_VECTOR_FILES)
}

fn write_vector(
    output: &OutputDirectory,
    name: &str,
    bytes: &[u8],
    overwrite: bool,
) -> std::io::Result<()> {
    output.write_vector(name, bytes, overwrite)
}

#[cfg(test)]
fn write_vector_with_hook<F>(
    output: &OutputDirectory,
    name: &str,
    bytes: &[u8],
    overwrite: bool,
    before_rename: F,
) -> std::io::Result<()>
where
    F: FnOnce(&std::fs::File, &std::ffi::OsStr) -> std::io::Result<()>,
{
    output.write_vector_with_hook(name, bytes, overwrite, before_rename)
}

fn release_vector() -> (Vec<u8>, Signature64) {
    let daemon_key = SigningKey::from_bytes(&[0x61; 32]);
    let client_key = SigningKey::from_bytes(&[0x62; 32]);
    let policy_key = SigningKey::from_bytes(&[0x42; 32]);
    let profile = encode_profile(
        &daemon_key.verifying_key().to_bytes(),
        &client_key.verifying_key().to_bytes(),
        &policy_key.verifying_key().to_bytes(),
    );
    let roots = encode_policy_roots(&policy_key.verifying_key().to_bytes());
    let roots_digest = sha256(&roots);
    let profile_digest = sha256(&profile);
    let resource_digest = [0x31; 32];
    let target = compute_release_target(roots_digest, resource_digest, profile_digest);

    let mut payloads = vec![
        ("bin/savana-kerneld", b"kernel-binary".to_vec()),
        ("policy/default-policy-v1.cbor", b"default-policy".to_vec()),
        ("policy/default-policy-v1.sig", vec![0x81; 64]),
        (
            "approval/producer-registry-v1.cbor",
            b"producer-registry".to_vec(),
        ),
        ("approval/ontology-v1.cbor", b"ontology".to_vec()),
        (
            "approval/approval-key-set-v1.cbor",
            b"approval-keys".to_vec(),
        ),
        (
            "model/signed-model-manifest-v1.cbor",
            b"model-manifest".to_vec(),
        ),
        ("installation/kernel-installation-profile-v1.cbor", profile),
        ("runtime/libonnxruntime.so", b"onnx-runtime".to_vec()),
        ("model/assets/model.bin", b"model-asset".to_vec()),
    ];
    payloads.sort_by(|left, right| canonical_text_cmp(left.0, right.0));

    let binary_digest = sha256(
        &payloads
            .iter()
            .find(|(path, _)| *path == "bin/savana-kerneld")
            .expect("fixed binary payload")
            .1,
    );
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(25)
        .unwrap()
        .u16(1)
        .unwrap()
        .str("1.0.0")
        .unwrap()
        .u64(1)
        .unwrap()
        .bytes(&target)
        .unwrap()
        .str(&"a".repeat(40))
        .unwrap()
        .str("release-root")
        .unwrap()
        .bytes(&binary_digest)
        .unwrap()
        .bytes(&[0xc1; 32])
        .unwrap()
        .bytes(&[0xc2; 32])
        .unwrap()
        .u16(1)
        .unwrap()
        .u16(0)
        .unwrap()
        .u16(0)
        .unwrap()
        .array(1)
        .unwrap()
        .u16(1)
        .unwrap()
        .array(1)
        .unwrap()
        .u16(1)
        .unwrap()
        .bytes(&roots_digest)
        .unwrap()
        .u64(1)
        .unwrap()
        .bytes(&[0xd1; 32])
        .unwrap()
        .bytes(&[0xd2; 32])
        .unwrap()
        .bytes(&[0xd3; 32])
        .unwrap()
        .bytes(&[0xd4; 32])
        .unwrap()
        .bytes(&resource_digest)
        .unwrap()
        .bytes(&profile_digest)
        .unwrap()
        .array(payloads.len() as u64)
        .unwrap();
    for (path, bytes) in payloads {
        encoder
            .array(3)
            .unwrap()
            .str(path)
            .unwrap()
            .u64(bytes.len() as u64)
            .unwrap()
            .bytes(&sha256(&bytes))
            .unwrap();
    }
    encoder.u64(1_000).unwrap().u64(4_000).unwrap();
    let manifest = encoder.into_writer();
    let release_key = SigningKey::from_bytes(&[0x51; 32]);
    let signature = detached_signature(RELEASE_DOMAIN, &manifest, &release_key);
    (manifest, signature)
}

fn encode_profile(daemon_key: &[u8; 32], client_key: &[u8; 32], policy_key: &[u8; 32]) -> Vec<u8> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(14)
        .unwrap()
        .u16(1)
        .unwrap()
        .bytes(&[0x71; 32])
        .unwrap()
        .u8(0)
        .unwrap()
        .array(2)
        .unwrap()
        .str("daemon-key")
        .unwrap()
        .bytes(daemon_key)
        .unwrap()
        .array(1)
        .unwrap()
        .array(6)
        .unwrap()
        .str("jarvis-client")
        .unwrap()
        .str("jarvis-key")
        .unwrap()
        .bytes(client_key)
        .unwrap()
        .u8(0)
        .unwrap()
        .u32(1_001)
        .unwrap()
        .u32(1_003)
        .unwrap();
    encoder
        .writer_mut()
        .extend_from_slice(&encode_policy_roots(policy_key));
    encoder
        .u32(1_002)
        .unwrap()
        .u32(1_002)
        .unwrap()
        .u32(1_001)
        .unwrap()
        .str("/run/savana/kernel/kerneld.sock")
        .unwrap()
        .str("/etc/savana/kernel/selected-policy-v1.cbor")
        .unwrap()
        .str("/etc/savana/kernel/selected-policy-v1.sig")
        .unwrap()
        .u16(0o750)
        .unwrap()
        .u16(0o660)
        .unwrap();
    encoder.into_writer()
}

fn encode_policy_roots(policy_key: &[u8; 32]) -> Vec<u8> {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(1)
        .unwrap()
        .array(4)
        .unwrap()
        .str("policy-root")
        .unwrap()
        .bytes(policy_key)
        .unwrap()
        .u64(3)
        .unwrap()
        .bool(false)
        .unwrap();
    encoder.into_writer()
}

fn compute_release_target(
    roots_digest: [u8; 32],
    resource_digest: [u8; 32],
    profile_digest: [u8; 32],
) -> [u8; 32] {
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder
        .array(7)
        .unwrap()
        .u16(1)
        .unwrap()
        .u16(0)
        .unwrap()
        .u16(0)
        .unwrap()
        .array(1)
        .unwrap()
        .u16(1)
        .unwrap()
        .bytes(&roots_digest)
        .unwrap()
        .bytes(&resource_digest)
        .unwrap()
        .bytes(&profile_digest)
        .unwrap();
    let mut hash = Sha256::new();
    hash.update(RELEASE_TARGET_DOMAIN);
    hash.update(encoder.into_writer());
    hash.finalize().into()
}

fn detached_signature(domain: &[u8], bytes: &[u8], key: &SigningKey) -> Signature64 {
    let mut message = Vec::with_capacity(domain.len() + bytes.len());
    message.extend_from_slice(domain);
    message.extend_from_slice(bytes);
    Signature64::new(key.sign(&message).to_bytes())
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn canonical_text_cmp(left: &str, right: &str) -> Ordering {
    left.len()
        .cmp(&right.len())
        .then_with(|| left.as_bytes().cmp(right.as_bytes()))
}

#[cfg(test)]
mod cli_tests {
    use std::ffi::OsString;
    use std::fs;
    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::{
        prepare_output, run_cli, write_vector, write_vector_with_hook, KNOWN_VECTOR_FILES, TARGETS,
    };

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory {
        path: PathBuf,
    }

    impl TestDirectory {
        fn new() -> Self {
            loop {
                let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
                let path = std::env::temp_dir().join(format!(
                    "savana-signed-vector-cli-{}-{sequence}",
                    std::process::id()
                ));
                match fs::create_dir(&path) {
                    Ok(()) => return Self { path },
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(error) => panic!("create isolated test directory: {error}"),
                }
            }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.path).expect("remove isolated test directory");
        }
    }

    fn arguments(output: &Path, overwrite: bool) -> std::vec::IntoIter<OsString> {
        let mut arguments = vec![
            OsString::from("generate_signed_vectors"),
            OsString::from("--output"),
            output.as_os_str().to_os_string(),
        ];
        if overwrite {
            arguments.push(OsString::from("--overwrite"));
        }
        arguments.into_iter()
    }

    fn sorted_entries(output: &Path) -> Vec<String> {
        let mut entries = fs::read_dir(output)
            .expect("read output directory")
            .map(|entry| {
                entry
                    .expect("read output entry")
                    .file_name()
                    .into_string()
                    .expect("test entry is UTF-8")
            })
            .collect::<Vec<_>>();
        entries.sort();
        entries
    }

    #[test]
    fn empty_output_succeeds_and_writes_only_signed_targets() {
        let output = TestDirectory::new();

        assert_eq!(run_cli(arguments(output.path(), false)), 0);

        let mut expected = TARGETS.map(str::to_owned).to_vec();
        expected.sort();
        assert_eq!(sorted_entries(output.path()), expected);
    }

    #[test]
    fn missing_output_is_rejected_without_creation() {
        let root = TestDirectory::new();
        let output = root.path().join("missing-output");

        assert_eq!(run_cli(arguments(&output, false)), 64);
        assert!(!output.exists());
    }

    #[test]
    fn non_empty_output_without_overwrite_exits_64_without_writing() {
        let output = TestDirectory::new();
        let readme = output.path().join("README.md");
        fs::write(&readme, b"keep this README").unwrap();

        assert_eq!(run_cli(arguments(output.path(), false)), 64);

        assert_eq!(fs::read(&readme).unwrap(), b"keep this README");
        assert_eq!(sorted_entries(output.path()), vec!["README.md"]);
    }

    #[test]
    fn existing_target_without_overwrite_exits_64_without_changes() {
        let output = TestDirectory::new();
        let existing = output.path().join(TARGETS[0]);
        fs::write(&existing, b"old policy vector").unwrap();

        assert_eq!(run_cli(arguments(output.path(), false)), 64);

        assert_eq!(fs::read(existing).unwrap(), b"old policy vector");
        assert!(!output.path().join(TARGETS[1]).exists());
    }

    #[test]
    fn overwrite_rejects_unknown_entry_without_changes() {
        let output = TestDirectory::new();
        let existing = output.path().join(TARGETS[0]);
        let unknown = output.path().join("unexpected.bin");
        fs::write(&existing, b"old policy vector").unwrap();
        fs::write(&unknown, b"unknown sentinel").unwrap();

        assert_eq!(run_cli(arguments(output.path(), true)), 64);

        assert_eq!(fs::read(existing).unwrap(), b"old policy vector");
        assert_eq!(fs::read(unknown).unwrap(), b"unknown sentinel");
        assert!(!output.path().join(TARGETS[1]).exists());
    }

    #[test]
    fn overwrite_rejects_symlink_target_without_following_or_partial_write() {
        let root = TestDirectory::new();
        let output = root.path().join("output");
        fs::create_dir(&output).unwrap();
        let first = output.join(TARGETS[0]);
        fs::write(&first, b"old policy vector").unwrap();
        let victim = root.path().join("victim");
        fs::write(&victim, b"do not follow").unwrap();
        symlink(&victim, output.join(TARGETS[1])).unwrap();

        assert_eq!(run_cli(arguments(&output, true)), 64);

        assert_eq!(fs::read(first).unwrap(), b"old policy vector");
        assert_eq!(fs::read(victim).unwrap(), b"do not follow");
    }

    #[test]
    fn output_symlink_with_trailing_separator_is_rejected_without_writing() {
        let root = TestDirectory::new();
        let real_output = root.path().join("real-output");
        let output_link = root.path().join("output-link");
        fs::create_dir(&real_output).unwrap();
        symlink(&real_output, &output_link).unwrap();
        let output_with_separator = PathBuf::from(format!("{}/", output_link.display()));

        assert_eq!(run_cli(arguments(&output_with_separator, true)), 64);
        assert!(sorted_entries(&real_output).is_empty());
    }

    #[test]
    fn overwrite_replaces_hard_link_without_modifying_victim() {
        let root = TestDirectory::new();
        let output = root.path().join("output");
        fs::create_dir(&output).unwrap();
        let victim = root.path().join("victim");
        fs::write(&victim, b"do not modify").unwrap();
        let target = output.join(TARGETS[0]);
        fs::hard_link(&victim, &target).unwrap();

        assert_eq!(run_cli(arguments(&output, true)), 0);

        assert_eq!(fs::read(&victim).unwrap(), b"do not modify");
        assert_ne!(fs::read(&target).unwrap(), b"do not modify");
        assert_ne!(
            fs::metadata(&victim).unwrap().ino(),
            fs::metadata(&target).unwrap().ino()
        );
    }

    #[test]
    fn overwrite_replaces_only_own_known_regular_files() {
        let output = TestDirectory::new();
        let readme = output.path().join("README.md");
        let wire_vector = output.path().join("client-hello-v1.cbor");
        fs::write(&readme, b"README sentinel").unwrap();
        fs::write(&wire_vector, b"wire sentinel").unwrap();
        for target in TARGETS {
            fs::write(output.path().join(target), b"old signed vector").unwrap();
        }

        assert_eq!(run_cli(arguments(output.path(), true)), 0);

        assert_eq!(fs::read(readme).unwrap(), b"README sentinel");
        assert_eq!(fs::read(wire_vector).unwrap(), b"wire sentinel");
        for target in TARGETS {
            assert_ne!(
                fs::read(output.path().join(target)).unwrap(),
                b"old signed vector"
            );
        }
    }

    #[test]
    fn overwrite_accepts_full_documented_corpus_and_preserves_wire_vectors() {
        let output = TestDirectory::new();
        let preserved = [
            ("README.md", b"README sentinel".as_slice()),
            ("client-hello-v1.cbor", b"client hello sentinel".as_slice()),
            ("server-hello-v1.cbor", b"server hello sentinel".as_slice()),
            ("policy-flow-v1.cbor", b"policy flow sentinel".as_slice()),
        ];
        for (name, bytes) in preserved {
            fs::write(output.path().join(name), bytes).unwrap();
        }
        for target in TARGETS {
            fs::write(output.path().join(target), b"old signed vector").unwrap();
        }

        assert_eq!(run_cli(arguments(output.path(), true)), 0);

        for (name, bytes) in preserved {
            assert_eq!(fs::read(output.path().join(name)).unwrap(), bytes);
        }
        for target in TARGETS {
            assert_ne!(
                fs::read(output.path().join(target)).unwrap(),
                b"old signed vector"
            );
        }
    }

    #[test]
    fn validated_output_directory_cannot_be_redirected_before_write() {
        let root = TestDirectory::new();
        let output = root.path().join("output");
        let anchored = root.path().join("anchored-output");
        fs::create_dir(&output).unwrap();
        let prepared = prepare_output(&output, true).unwrap();
        fs::rename(&output, &anchored).unwrap();
        fs::create_dir(&output).unwrap();
        let victim = output.join(TARGETS[0]);
        fs::write(&victim, b"victim sentinel").unwrap();

        assert!(write_vector(&prepared, TARGETS[0], b"trusted vector", true).is_err());
        assert_eq!(fs::read(victim).unwrap(), b"victim sentinel");
    }

    #[test]
    fn replaced_temporary_inode_cannot_produce_success() {
        let output = TestDirectory::new();
        let target = output.path().join(TARGETS[0]);
        let prepared = prepare_output(output.path(), true).unwrap();

        let result = write_vector_with_hook(
            &prepared,
            TARGETS[0],
            b"trusted vector",
            true,
            |_, temporary_leaf| {
                let temporary = output.path().join(temporary_leaf);
                fs::remove_file(&temporary)?;
                fs::write(&temporary, b"trusted vector")?;
                fs::set_permissions(&temporary, fs::Permissions::from_mode(0o644))
            },
        );

        assert!(result.is_err());
        assert_eq!(fs::read(target).unwrap(), b"trusted vector");
    }

    #[test]
    fn finish_rejects_replacement_of_an_earlier_installed_vector() {
        let output = TestDirectory::new();
        let target = output.path().join(TARGETS[0]);
        let replacement = output.path().join("replacement");
        let prepared = prepare_output(output.path(), true).unwrap();
        write_vector(&prepared, TARGETS[0], b"trusted vector", true).unwrap();
        fs::write(&replacement, b"hostile vector").unwrap();
        fs::rename(&replacement, &target).unwrap();

        assert!(prepared.finish(&KNOWN_VECTOR_FILES).is_err());
    }
}
