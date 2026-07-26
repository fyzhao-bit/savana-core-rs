use std::error::Error;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signer, SigningKey};
use savana_kernel_protocol::{
    encode_client_message, encode_server_message, BootId, ClientHelloV1, ClientId, ClientMessageV1,
    Digest32, HandshakeTranscriptV1, KeyId, Nonce32, ProtocolVersion, RequestedMode,
    ServerIdentityV1, ServerMessageV1, Signature64, SignedServerHelloV1,
};

#[path = "support/policy_flow_fixture.rs"]
mod policy_flow_fixture;
#[path = "../../../tools/vector_output.rs"]
mod vector_output;

use vector_output::OutputDirectory;

const TARGETS: [&str; 3] = [
    "client-hello-v1.cbor",
    "server-hello-v1.cbor",
    "policy-flow-v1.cbor",
];
const DAEMON_HELLO_DOMAIN: &[u8] = b"SAVANA_DAEMON_HELLO_V1\0";
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
            eprintln!("wire vector generation failed: {error}");
            64
        }
    }
}

fn generate(arguments: impl Iterator<Item = OsString>) -> Result<(), Box<dyn Error>> {
    let (output_path, overwrite) = parse_arguments(arguments)?;
    let output = prepare_output(&output_path, overwrite)?;

    let client = encode_client_message(&ClientMessageV1::Hello(client_hello()))?;
    let server = encode_server_message(&server_message()?)?;
    let policy_flow = encode_policy_flow()?;
    write_vector(&output, TARGETS[0], &client, overwrite)?;
    write_vector(&output, TARGETS[1], &server, overwrite)?;
    write_vector(&output, TARGETS[2], &policy_flow, overwrite)?;
    output.finish(&KNOWN_VECTOR_FILES)?;
    Ok(())
}

fn encode_policy_flow() -> Result<Vec<u8>, Box<dyn Error>> {
    let messages = policy_flow_fixture::encoded_messages();
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder.array(u64::try_from(messages.len())?)?;
    for message in messages {
        encoder.bytes(&message)?;
    }
    Ok(encoder.into_writer())
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

fn client_hello() -> ClientHelloV1 {
    ClientHelloV1 {
        client_nonce: Nonce32::new([0x11; 32]),
        supported_versions: vec![ProtocolVersion::new(1, 0)],
        client_id: ClientId::try_from("fixture-client").expect("fixed client ID"),
        client_key_id: KeyId::try_from("fixture-client-key").expect("fixed client key ID"),
        requested_mode: RequestedMode::Required,
    }
}

fn server_message() -> Result<ServerMessageV1, Box<dyn Error>> {
    let transcript = HandshakeTranscriptV1 {
        client: client_hello(),
        server_nonce: Nonce32::new([0x44; 32]),
        server: ServerIdentityV1 {
            daemon_key_id: KeyId::try_from("fixture-daemon-key").expect("fixed daemon key ID"),
            boot_id: BootId::new([0x22; 32]),
            protocol: ProtocolVersion::new(1, 0),
            release_digest: Digest32::new([0x31; 32]),
            policy_digest: Digest32::new([0x32; 32]),
            policy_version: 7,
            model_manifest_digest: Digest32::new([0x33; 32]),
            approval_key_set_digest: Digest32::new([0x34; 32]),
            resource_profile_digest: Digest32::new([0x35; 32]),
        },
    };
    let canonical =
        minicbor::to_vec(&transcript).map_err(|_| "fixed transcript encoding failed")?;
    let mut signature_input = Vec::with_capacity(DAEMON_HELLO_DOMAIN.len() + canonical.len());
    signature_input.extend_from_slice(DAEMON_HELLO_DOMAIN);
    signature_input.extend_from_slice(&canonical);
    let signature = SigningKey::from_bytes(&[0x61; 32]).sign(&signature_input);
    Ok(ServerMessageV1::Hello(SignedServerHelloV1 {
        transcript,
        signature: Signature64::new(signature.to_bytes()),
    }))
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
                    "savana-wire-vector-cli-{}-{sequence}",
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
            OsString::from("generate_wire_vectors"),
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
    fn empty_output_succeeds_and_writes_only_wire_targets() {
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
        fs::write(&existing, b"old client vector").unwrap();

        assert_eq!(run_cli(arguments(output.path(), false)), 64);

        assert_eq!(fs::read(existing).unwrap(), b"old client vector");
        assert!(!output.path().join(TARGETS[1]).exists());
    }

    #[test]
    fn overwrite_rejects_unknown_entry_without_changes() {
        let output = TestDirectory::new();
        let existing = output.path().join(TARGETS[0]);
        let unknown = output.path().join("unexpected.bin");
        fs::write(&existing, b"old client vector").unwrap();
        fs::write(&unknown, b"unknown sentinel").unwrap();

        assert_eq!(run_cli(arguments(output.path(), true)), 64);

        assert_eq!(fs::read(existing).unwrap(), b"old client vector");
        assert_eq!(fs::read(unknown).unwrap(), b"unknown sentinel");
        assert!(!output.path().join(TARGETS[1]).exists());
    }

    #[test]
    fn overwrite_rejects_symlink_target_without_following_or_partial_write() {
        let root = TestDirectory::new();
        let output = root.path().join("output");
        fs::create_dir(&output).unwrap();
        let first = output.join(TARGETS[0]);
        fs::write(&first, b"old client vector").unwrap();
        let victim = root.path().join("victim");
        fs::write(&victim, b"do not follow").unwrap();
        symlink(&victim, output.join(TARGETS[1])).unwrap();

        assert_eq!(run_cli(arguments(&output, true)), 64);

        assert_eq!(fs::read(first).unwrap(), b"old client vector");
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
    fn output_symlink_with_trailing_dot_is_rejected_without_writing() {
        let root = TestDirectory::new();
        let real_output = root.path().join("real-output");
        let output_link = root.path().join("output-link");
        fs::create_dir(&real_output).unwrap();
        symlink(&real_output, &output_link).unwrap();

        assert_eq!(run_cli(arguments(&output_link.join("."), true)), 64);
        assert!(sorted_entries(&real_output).is_empty());
    }

    #[test]
    fn output_parent_components_are_rejected_before_writing() {
        let root = TestDirectory::new();
        let intermediate = root.path().join("intermediate");
        let escaped = root.path().join("escaped");
        fs::create_dir(&intermediate).unwrap();
        fs::create_dir(&escaped).unwrap();
        let output = intermediate.join("..").join("escaped");

        assert_eq!(run_cli(arguments(&output, true)), 64);
        assert!(sorted_entries(&escaped).is_empty());
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
        let signed_vector = output.path().join("policy-bundle-v1.cbor");
        fs::write(&readme, b"README sentinel").unwrap();
        fs::write(&signed_vector, b"signed sentinel").unwrap();
        for target in TARGETS {
            fs::write(output.path().join(target), b"old wire vector").unwrap();
        }

        assert_eq!(run_cli(arguments(output.path(), true)), 0);

        assert_eq!(fs::read(readme).unwrap(), b"README sentinel");
        assert_eq!(fs::read(signed_vector).unwrap(), b"signed sentinel");
        for target in TARGETS {
            assert_ne!(
                fs::read(output.path().join(target)).unwrap(),
                b"old wire vector"
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
    fn changed_temporary_contents_cannot_produce_success() {
        let output = TestDirectory::new();
        let target = output.path().join(TARGETS[0]);
        let prepared = prepare_output(output.path(), true).unwrap();

        let result = write_vector_with_hook(
            &prepared,
            TARGETS[0],
            b"trusted vector",
            true,
            |_, temporary_leaf| fs::write(output.path().join(temporary_leaf), b"hostile vector"),
        );

        assert!(result.is_err());
        assert_eq!(fs::read(target).unwrap(), b"hostile vector");
    }

    #[test]
    fn output_replacement_during_write_cannot_redirect_install() {
        let root = TestDirectory::new();
        let output = root.path().join("output");
        let anchored = root.path().join("anchored-output");
        fs::create_dir(&output).unwrap();
        let prepared = prepare_output(&output, true).unwrap();

        let result =
            write_vector_with_hook(&prepared, TARGETS[0], b"trusted vector", true, |_, _| {
                fs::rename(&output, &anchored)?;
                fs::create_dir(&output)?;
                fs::write(output.join(TARGETS[0]), b"victim sentinel")
            });

        assert!(result.is_err());
        assert_eq!(
            fs::read(output.join(TARGETS[0])).unwrap(),
            b"victim sentinel"
        );
        assert_eq!(
            fs::read(anchored.join(TARGETS[0])).unwrap(),
            b"trusted vector"
        );
    }

    #[test]
    fn non_overwrite_install_preserves_concurrently_created_target() {
        let output = TestDirectory::new();
        let target = output.path().join(TARGETS[0]);
        let prepared = prepare_output(output.path(), false).unwrap();

        let result =
            write_vector_with_hook(&prepared, TARGETS[0], b"trusted vector", false, |_, _| {
                fs::write(&target, b"victim sentinel")
            });

        assert!(result.is_err());
        assert_eq!(fs::read(target).unwrap(), b"victim sentinel");
    }

    #[test]
    fn error_path_never_unlinks_through_replaced_output_path() {
        let root = TestDirectory::new();
        let output = root.path().join("output");
        let anchored = root.path().join("anchored-output");
        fs::create_dir(&output).unwrap();
        let prepared = prepare_output(&output, true).unwrap();
        let mut redirected_temporary = None;

        let result = write_vector_with_hook(
            &prepared,
            TARGETS[0],
            b"trusted vector",
            true,
            |_, temporary_leaf| {
                fs::remove_file(output.join(temporary_leaf))?;
                fs::rename(&output, &anchored)?;
                fs::create_dir(&output)?;
                let sentinel = output.join(temporary_leaf);
                fs::write(&sentinel, b"redirected sentinel")?;
                redirected_temporary = Some(sentinel);
                Ok(())
            },
        );

        assert!(result.is_err());
        assert_eq!(
            fs::read(redirected_temporary.unwrap()).unwrap(),
            b"redirected sentinel"
        );
    }

    #[test]
    fn failed_write_preserves_temporary_entry_for_forensic_discard() {
        let output = TestDirectory::new();
        let prepared = prepare_output(output.path(), true).unwrap();

        let result =
            write_vector_with_hook(&prepared, TARGETS[0], b"trusted vector", true, |_, _| {
                Err(std::io::Error::other("injected pre-rename failure"))
            });

        assert!(result.is_err());
        let entries = sorted_entries(output.path());
        assert_eq!(entries.len(), 1);
        assert!(entries[0].starts_with(&format!(".{}.tmp-", TARGETS[0])));
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
