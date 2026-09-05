#![forbid(unsafe_code)]

#[cfg(target_os = "macos")]
#[path = "../development_profiles.rs"]
mod development_profiles;

#[cfg(all(feature = "macos-development-authority", not(debug_assertions)))]
compile_error!("macos-development-authority is forbidden in release builds");

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("savana-development-material is available only on macOS");
    std::process::exit(69);
}

#[cfg(target_os = "macos")]
fn main() {
    if let Err(error) = macos::run() {
        eprintln!("{error}");
        std::process::exit(70);
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use std::collections::HashSet;
    use std::fs;
    use std::io::Write as _;
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
    use std::path::{Path, PathBuf};

    use ed25519_dalek::SigningKey;
    use savana_kernel_protocol::v2::derive_ed25519_key_id_v2;
    use serde_json::{Map, Value};
    use sha2::{Digest as _, Sha256};
    use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

    const ROOT: &str = "/Library/Application Support/Savana/Development";
    const MAX_JSON_BYTES: usize = 256 * 1024;
    const MAX_CERTIFICATE_BYTES: usize = 64 * 1024;
    const PROVIDER_ALPN: &[u8] = b"savana-provider-v2";
    const PROVIDER_SERVER_NAME: &str = "provider.savana-development.invalid";
    const FINAL_RELEASE_SERVER_NAME: &str = "release.savana-development.invalid";
    const PLANNER_SERVER_NAME: &str = "planner.savana-development.invalid";
    const MAPPER_SERVER_NAME: &str = "mapper.savana-development.invalid";

    struct Ed25519Material {
        seed: [u8; 32],
        public_key: [u8; 32],
        key_id: [u8; 32],
    }

    pub(super) fn run() -> Result<(), String> {
        let mut arguments = std::env::args_os().skip(1);
        let root = absolute(arguments.next(), "installation root")?;
        if arguments.next().is_some()
            || root != Path::new(ROOT)
            || std::env::var("SAVANA_AUTHORITY_CLASS").as_deref() != Ok("development")
        {
            return Err("invalid closed development-material invocation".to_owned());
        }
        require_safe_root(&root)?;
        let connector_authority_enabled =
            connector_authority_mode(&read_json(&root.join("config/kerneld-bootstrap-v2.json"))?)?;

        let mut issued = HashSet::new();
        let agent_client = ed25519(&mut issued)?;
        let agent_server = ed25519(&mut issued)?;
        let ingress_client = ed25519(&mut issued)?;
        let ingress_server = ed25519(&mut issued)?;
        let executor_client = ed25519(&mut issued)?;
        let executor_server = ed25519(&mut issued)?;
        let kernel_envelope = ed25519(&mut issued)?;
        let kernel_authority = ed25519(&mut issued)?;
        let kernel_correlation = ed25519(&mut issued)?;
        let task_authorization = ed25519(&mut issued)?;
        let registry_publisher = ed25519(&mut issued)?;
        let agent_approval = ed25519(&mut issued)?;
        let ingress_approval = ed25519(&mut issued)?;
        let admin_approval = ed25519(&mut issued)?;
        let approval_server = ed25519(&mut issued)?;
        let approval_settlement = ed25519(&mut issued)?;
        let parser_descriptor = ed25519(&mut issued)?;
        let effect_receipt = ed25519(&mut issued)?;
        let connector_descriptor = ed25519(&mut issued)?;
        let connector_authority = if connector_authority_enabled {
            Some(ed25519(&mut issued)?)
        } else {
            None
        };

        let kerneld_boot = random_unique(&mut issued)?;
        let agentd_boot = random_unique(&mut issued)?;
        let ingressd_boot = random_unique(&mut issued)?;
        let approvald_boot = random_unique(&mut issued)?;
        let execd_boot = random_unique(&mut issued)?;
        let machine_boot = random_unique(&mut issued)?;
        let jarvis_boot = random_unique(&mut issued)?;
        let seal_private = random_unique(&mut issued)?;
        let seal_public = X25519PublicKey::from(&StaticSecret::from(seal_private)).to_bytes();
        let seal_key_id = domain_digest(b"SAVANA_HPKE_X25519_KEY_ID_V2\0", &seal_public);

        write_credentials(
            &root,
            &[
                ("kerneld", "agent-kernel-v2.seed", agent_server.seed),
                ("kerneld", "kerneld-boot-v2.id", kerneld_boot),
                ("kerneld", "ingress-kernel-v2.seed", ingress_server.seed),
                ("kerneld", "envelope-signing-v2.seed", kernel_envelope.seed),
                (
                    "kerneld",
                    "authority-envelope-v2.seed",
                    kernel_authority.seed,
                ),
                (
                    "kerneld",
                    "task-correlation-v2.seed",
                    kernel_correlation.seed,
                ),
                (
                    "kerneld",
                    "task-authorization-v2.seed",
                    task_authorization.seed,
                ),
                (
                    "kerneld",
                    "vault-encryption-v2.key",
                    random_unique(&mut issued)?,
                ),
                (
                    "kerneld",
                    "vault-anchor-authentication-v2.key",
                    random_unique(&mut issued)?,
                ),
                (
                    "kerneld",
                    "agent-authority-state-encryption-v2.key",
                    random_unique(&mut issued)?,
                ),
                (
                    "kerneld",
                    "agent-authority-anchor-authentication-v2.key",
                    random_unique(&mut issued)?,
                ),
                (
                    "kerneld",
                    "g4-state-encryption-v2.key",
                    random_unique(&mut issued)?,
                ),
                (
                    "kerneld",
                    "g4-anchor-authentication-v2.key",
                    random_unique(&mut issued)?,
                ),
                ("kerneld", "executor-kernel-v2.seed", executor_client.seed),
                ("agentd", "agent-kernel-v2.seed", agent_client.seed),
                ("agentd", "agent-approval-v2.seed", agent_approval.seed),
                (
                    "agentd",
                    "task-state-encryption-v2.key",
                    random_unique(&mut issued)?,
                ),
                (
                    "agentd",
                    "task-anchor-authentication-v2.key",
                    random_unique(&mut issued)?,
                ),
                ("agentd", "agentd-boot-v2.id", agentd_boot),
                ("agentd", "kerneld-boot-v2.id", kerneld_boot),
                ("agentd", "approvald-boot-v2.id", approvald_boot),
                ("agentd", "machine-boot-v2.id", machine_boot),
                ("agentd", "jarvis-boot-v2.id", jarvis_boot),
                ("ingressd", "ingress-kernel-v2.seed", ingress_client.seed),
                (
                    "ingressd",
                    "ingress-approval-v2.seed",
                    ingress_approval.seed,
                ),
                (
                    "ingressd",
                    "parser-descriptor-v2.seed",
                    parser_descriptor.seed,
                ),
                ("ingressd", "ingressd-boot-v2.id", ingressd_boot),
                ("ingressd", "kerneld-boot-v2.id", kerneld_boot),
                ("ingressd", "approvald-boot-v2.id", approvald_boot),
                ("approvald", "approvald-boot-v2.id", approvald_boot),
                ("approvald", "approval-server-v2.seed", approval_server.seed),
                (
                    "approvald",
                    "approval-settlement-v2.seed",
                    approval_settlement.seed,
                ),
                (
                    "approvald",
                    "approval-state-encryption-v2.key",
                    random_unique(&mut issued)?,
                ),
                (
                    "approvald",
                    "approval-anchor-authentication-v2.key",
                    random_unique(&mut issued)?,
                ),
                ("execd", "executor-server-v2.seed", executor_server.seed),
                ("execd", "execd-boot-v2.id", execd_boot),
                ("execd", "effect-receipt-v2.seed", effect_receipt.seed),
                ("execd", "execution-seal-v2.key", seal_private),
                (
                    "execd",
                    "journal-encryption-v2.key",
                    random_unique(&mut issued)?,
                ),
                (
                    "execd",
                    "journal-anchor-authentication-v2.key",
                    random_unique(&mut issued)?,
                ),
                (
                    "execd",
                    "connector-descriptor-v2.seed",
                    connector_descriptor.seed,
                ),
                ("jarvis-python", "jarvis-boot-v2.id", jarvis_boot),
                (
                    "jarvis-python",
                    "approval-admin-v2.seed",
                    admin_approval.seed,
                ),
            ],
        )?;
        if let Some(connector_authority) = connector_authority.as_ref() {
            write_credentials(
                &root,
                &[(
                    "kerneld",
                    "connector-authority-v2.seed",
                    connector_authority.seed,
                )],
            )?;
        }

        write_public_keys(
            &root,
            &[
                ("kerneld/keys/agentd-kernel-v2.pub", agent_client.public_key),
                (
                    "kerneld/keys/ingressd-kernel-v2.pub",
                    ingress_client.public_key,
                ),
                (
                    "kerneld/keys/execd-kernel-v2.pub",
                    executor_server.public_key,
                ),
                ("agentd/keys/kerneld-agent-v2.pub", agent_server.public_key),
                (
                    "agentd/keys/kerneld-task-authority-v2.pub",
                    kernel_authority.public_key,
                ),
                (
                    "agentd/keys/approvald-agent-v2.pub",
                    approval_server.public_key,
                ),
                (
                    "ingressd/keys/kerneld-ingress-v2.pub",
                    ingress_server.public_key,
                ),
                ("ingressd/keys/approvald-v2.pub", approval_server.public_key),
                (
                    "approvald/keys/kerneld-envelope-v2.pub",
                    kernel_envelope.public_key,
                ),
                (
                    "approvald/keys/kerneld-correlation-v2.pub",
                    kernel_correlation.public_key,
                ),
                (
                    "approvald/keys/agentd-approval-v2.pub",
                    agent_approval.public_key,
                ),
                (
                    "approvald/keys/ingressd-approval-v2.pub",
                    ingress_approval.public_key,
                ),
                (
                    "approvald/keys/admin-approval-v2.pub",
                    admin_approval.public_key,
                ),
                (
                    "execd/keys/kerneld-executor-v2.pub",
                    executor_client.public_key,
                ),
                (
                    "execd/keys/kerneld-envelope-v2.pub",
                    kernel_envelope.public_key,
                ),
            ],
        )?;

        patch_configs(
            &root,
            RuntimePatch {
                agent_client: &agent_client,
                agent_server: &agent_server,
                ingress_client: &ingress_client,
                ingress_server: &ingress_server,
                executor_client: &executor_client,
                executor_server: &executor_server,
                kernel_envelope: &kernel_envelope,
                kernel_authority: &kernel_authority,
                kernel_correlation: &kernel_correlation,
                task_authorization: &task_authorization,
                registry_publisher: &registry_publisher,
                agent_approval: &agent_approval,
                ingress_approval: &ingress_approval,
                admin_approval: &admin_approval,
                approval_server: &approval_server,
                approval_settlement: &approval_settlement,
                parser_descriptor: &parser_descriptor,
                effect_receipt: &effect_receipt,
                connector_authority: connector_authority.as_ref(),
                agentd_boot,
                jarvis_boot,
                approvald_boot,
                execd_boot,
                machine_boot,
                seal_public,
                seal_key_id,
            },
        )
    }

    struct RuntimePatch<'a> {
        agent_client: &'a Ed25519Material,
        agent_server: &'a Ed25519Material,
        ingress_client: &'a Ed25519Material,
        ingress_server: &'a Ed25519Material,
        executor_client: &'a Ed25519Material,
        executor_server: &'a Ed25519Material,
        kernel_envelope: &'a Ed25519Material,
        kernel_authority: &'a Ed25519Material,
        kernel_correlation: &'a Ed25519Material,
        task_authorization: &'a Ed25519Material,
        registry_publisher: &'a Ed25519Material,
        agent_approval: &'a Ed25519Material,
        ingress_approval: &'a Ed25519Material,
        admin_approval: &'a Ed25519Material,
        approval_server: &'a Ed25519Material,
        approval_settlement: &'a Ed25519Material,
        parser_descriptor: &'a Ed25519Material,
        effect_receipt: &'a Ed25519Material,
        connector_authority: Option<&'a Ed25519Material>,
        agentd_boot: [u8; 32],
        jarvis_boot: [u8; 32],
        approvald_boot: [u8; 32],
        execd_boot: [u8; 32],
        machine_boot: [u8; 32],
        seal_public: [u8; 32],
        seal_key_id: [u8; 32],
    }

    fn patch_configs(root: &Path, patch: RuntimePatch<'_>) -> Result<(), String> {
        let ingress_sandbox = root.join("sandbox/ingressd/savana-worker-sandbox");
        let parser_worker = root.join("sandbox/ingressd/savana-parser-worker");
        let parser_profile_path = root.join("sandbox/ingressd/parser-profile-v2.json");
        let exec_sandbox = root.join("sandbox/execd/savana-worker-sandbox");
        let connector_worker = root.join("sandbox/execd/savana-connector-worker");
        let no_network_profile_path =
            root.join("sandbox/execd/connector-no-network-profile-v2.json");
        let credential_absence_profile_path =
            root.join("sandbox/execd/connector-credential-absence-profile-v2.json");
        patch_isolation_profile(&parser_profile_path, &parser_worker, true)?;
        patch_network_profile(&no_network_profile_path)?;
        patch_isolation_profile(&credential_absence_profile_path, &connector_worker, false)?;
        let ingress_sandbox_digest = file_digest(&ingress_sandbox)?;
        let parser_worker_digest = file_digest(&parser_worker)?;
        let parser_profile_digest = file_digest(&parser_profile_path)?;
        let exec_sandbox_digest = file_digest(&exec_sandbox)?;
        let connector_worker_digest = file_digest(&connector_worker)?;
        let no_network_profile_digest = file_digest(&no_network_profile_path)?;
        let credential_absence_profile_digest = file_digest(&credential_absence_profile_path)?;
        let signed_manifest = fixed_path(root, "config/deployment-manifest-v2.cbor");
        let ledger_projection = fixed_path(root, "config/effect-ledger-projection-v2.cbor");

        let mut kernel = read_json(&root.join("config/kerneld-bootstrap-v2.json"))?;
        set_value(
            &mut kernel,
            &["signed_manifest_path"],
            signed_manifest.clone(),
        )?;
        set_value(
            &mut kernel,
            &["effect_ledger_projection_path"],
            ledger_projection.clone(),
        )?;
        set_value(
            &mut kernel,
            &["input_runtime_assets_path"],
            fixed_path(root, "config/input-runtime-assets-v2.cbor"),
        )?;
        for (field, leaf) in [
            ("vault_state_path", "state/kerneld/vault-state-v2.cbor"),
            (
                "vault_rollback_anchor_path",
                "state/kerneld/vault-anchor-v2.cbor",
            ),
            (
                "agent_authority_state_path",
                "state/kerneld/kernel-agent-authority-state-v2.cbor",
            ),
            (
                "agent_authority_rollback_anchor_path",
                "state/kerneld/agent-authority-anchor-v2.cbor",
            ),
            ("g4_state_path", "state/kerneld/kernel-g4-state-v2.cbor"),
            ("g4_rollback_anchor_path", "state/kerneld/g4-anchor-v2.cbor"),
        ] {
            set_value(&mut kernel, &[field], fixed_path(root, leaf))?;
        }
        set_hex(&mut kernel, &["agentd_boot_id"], patch.agentd_boot)?;
        set_hex(&mut kernel, &["approvald_boot_id"], patch.approvald_boot)?;
        set_hex(&mut kernel, &["machine_boot_id"], patch.machine_boot)?;
        set_key_pair(
            &mut kernel,
            &["task_authorization_key_id"],
            &["task_authorization_public_key"],
            patch.task_authorization,
        )?;
        set_key_pair(
            &mut kernel,
            &["ui_settlement_key_id"],
            &["ui_settlement_public_key"],
            patch.approval_settlement,
        )?;
        set_key_pair(
            &mut kernel,
            &["ingress_settlement_key_id"],
            &["ingress_settlement_public_key"],
            patch.approval_settlement,
        )?;
        set_key_pair(
            &mut kernel,
            &["parser_trust", "descriptor_key_id"],
            &["parser_trust", "descriptor_public_key"],
            patch.parser_descriptor,
        )?;
        set_hex(
            &mut kernel,
            &["parser_trust", "worker_artifact_digest"],
            parser_worker_digest,
        )?;
        set_key_pair(
            &mut kernel,
            &["policy_runtime", "tool_settlement_key_id"],
            &["policy_runtime", "tool_settlement_public_key"],
            patch.approval_settlement,
        )?;
        set_hex(
            &mut kernel,
            &["policy_runtime", "execd_boot_id"],
            patch.execd_boot,
        )?;
        set_hex(
            &mut kernel,
            &["policy_runtime", "executor_seal_key_id"],
            patch.seal_key_id,
        )?;
        set_hex(
            &mut kernel,
            &["policy_runtime", "executor_seal_public_key"],
            patch.seal_public,
        )?;
        set_key_pair(
            &mut kernel,
            &["policy_runtime", "executor_receipt_key_id"],
            &["policy_runtime", "executor_receipt_public_key"],
            patch.effect_receipt,
        )?;
        if let Some(connector_authority) = patch.connector_authority {
            set_key_pair(
                &mut kernel,
                &["policy_runtime", "connector_authority_key_id"],
                &["policy_runtime", "connector_authority_public_key"],
                connector_authority,
            )?;
        } else if connector_authority_mode(&kernel)? {
            return Err("disabled connector authority changed during materialization".to_owned());
        }
        let planner_spki = read_bounded(
            &root.join("config/tls/planner-server-spki-v2.der"),
            MAX_CERTIFICATE_BYTES,
        )?;
        let mapper_spki = read_bounded(
            &root.join("config/tls/mapper-server-spki-v2.der"),
            MAX_CERTIFICATE_BYTES,
        )?;
        let mut agent = read_json(&root.join("config/agentd-bootstrap-v2.json"))?;
        set_value(
            &mut agent,
            &["signed_manifest_path"],
            signed_manifest.clone(),
        )?;
        set_value(
            &mut agent,
            &["effect_ledger_projection_path"],
            ledger_projection.clone(),
        )?;
        set_value(
            &mut agent,
            &["effect_gate_path"],
            fixed_path(root, "config/effect-gate-v2"),
        )?;
        set_value(
            &mut agent,
            &["task_state_path"],
            fixed_path(root, "state/agentd/agent-task-state-v2.cbor"),
        )?;
        set_value(
            &mut agent,
            &["rollback_anchor_path"],
            fixed_path(root, "state/agentd/task-anchor-v2.cbor"),
        )?;
        set_value(
            &mut agent,
            &["planner_catalog_state_path"],
            fixed_path(root, "state/agentd/planner-catalog-state-v2.cbor"),
        )?;
        set_value(
            &mut agent,
            &["planner_catalog_rollback_anchor_path"],
            fixed_path(root, "state/agentd/planner-catalog-anchor-v2.cbor"),
        )?;
        set_hex(
            &mut agent,
            &["kernel_task_authority_key_id"],
            patch.kernel_authority.key_id,
        )?;
        set_hex(
            &mut agent,
            &["approval_client_key_id"],
            patch.agent_approval.key_id,
        )?;
        set_hex(
            &mut agent,
            &["approval_server_key_id"],
            patch.approval_server.key_id,
        )?;
        set_value(
            &mut agent,
            &["planner_host"],
            Value::String(PLANNER_SERVER_NAME.to_owned()),
        )?;
        set_value(&mut agent, &["planner_port"], Value::from(9443_u16))?;
        set_value(
            &mut agent,
            &["planner_connect_addresses"],
            serde_json::json!(["127.0.0.1:9443"]),
        )?;
        set_hex(
            &mut agent,
            &["planner_server_spki_sha256"],
            Sha256::digest(&planner_spki).into(),
        )?;
        set_value(
            &mut agent,
            &["private_mapper_host"],
            Value::String(MAPPER_SERVER_NAME.to_owned()),
        )?;
        set_value(&mut agent, &["private_mapper_port"], Value::from(9445_u16))?;
        set_value(
            &mut agent,
            &["private_mapper_connect_addresses"],
            serde_json::json!(["127.0.0.1:9445"]),
        )?;
        set_hex(
            &mut agent,
            &["private_mapper_server_spki_sha256"],
            Sha256::digest(&mapper_spki).into(),
        )?;
        write_json(&root.join("config/agentd-bootstrap-v2.json"), &agent)?;

        let mut ingress = read_json(&root.join("config/ingressd-bootstrap-v2.json"))?;
        set_value(
            &mut ingress,
            &["signed_manifest_path"],
            signed_manifest.clone(),
        )?;
        set_value(
            &mut ingress,
            &["effect_ledger_projection_path"],
            ledger_projection.clone(),
        )?;
        set_hex(
            &mut ingress,
            &["approval_client_key_id"],
            patch.ingress_approval.key_id,
        )?;
        set_hex(
            &mut ingress,
            &["approval_server_key_id"],
            patch.approval_server.key_id,
        )?;
        set_hex(
            &mut ingress,
            &["parser", "descriptor_key_id"],
            patch.parser_descriptor.key_id,
        )?;
        set_value(
            &mut ingress,
            &["parser", "sandbox_program_path"],
            Value::String(ingress_sandbox.to_string_lossy().into_owned()),
        )?;
        set_hex(
            &mut ingress,
            &["parser", "sandbox_program_digest"],
            ingress_sandbox_digest,
        )?;
        set_value(
            &mut ingress,
            &["parser", "worker_program_path"],
            Value::String(parser_worker.to_string_lossy().into_owned()),
        )?;
        set_hex(
            &mut ingress,
            &["parser", "worker_artifact_digest"],
            parser_worker_digest,
        )?;
        set_value(
            &mut ingress,
            &["parser", "sandbox_profile_path"],
            Value::String(parser_profile_path.to_string_lossy().into_owned()),
        )?;
        set_hex(
            &mut ingress,
            &["parser", "sandbox_profile_digest"],
            parser_profile_digest,
        )?;
        let (ingress_uid, ingress_gid) = account_identity("_savana_ingress_dev")?;
        set_value(
            &mut ingress,
            &["parser", "file_owner_uid"],
            Value::from(ingress_uid),
        )?;
        set_value(
            &mut ingress,
            &["parser", "file_owner_gid"],
            Value::from(ingress_gid),
        )?;
        write_json(&root.join("config/ingressd-bootstrap-v2.json"), &ingress)?;

        let mut approval = read_json(&root.join("config/approvald-bootstrap-v2.json"))?;
        set_value(
            &mut approval,
            &["signed_manifest_path"],
            signed_manifest.clone(),
        )?;
        set_value(
            &mut approval,
            &["effect_ledger_projection_path"],
            ledger_projection.clone(),
        )?;
        set_value(
            &mut approval,
            &["state_path"],
            fixed_path(root, "state/approvald/approval-protocol-state-v2.cbor"),
        )?;
        set_value(
            &mut approval,
            &["rollback_anchor_path"],
            fixed_path(root, "state/approvald/approval-anchor-v2.cbor"),
        )?;
        set_value(
            &mut approval,
            &["kernel_envelope_public_key_path"],
            fixed_path(root, "config/approvald/keys/kerneld-envelope-v2.pub"),
        )?;
        set_value(
            &mut approval,
            &["kernel_correlation_public_key_path"],
            fixed_path(root, "config/approvald/keys/kerneld-correlation-v2.pub"),
        )?;
        set_hex(
            &mut approval,
            &["kernel_correlation_key_id"],
            patch.kernel_correlation.key_id,
        )?;
        set_hex(
            &mut approval,
            &["settlement_key_id"],
            patch.approval_settlement.key_id,
        )?;
        set_hex(
            &mut approval,
            &["server_key_id"],
            patch.approval_server.key_id,
        )?;
        for (path_field, id_field, leaf, material) in [
            (
                "agent_client_public_key_path",
                "agent_client_key_id",
                "agentd-approval-v2.pub",
                patch.agent_approval,
            ),
            (
                "ingress_client_public_key_path",
                "ingress_client_key_id",
                "ingressd-approval-v2.pub",
                patch.ingress_approval,
            ),
            (
                "admin_client_public_key_path",
                "admin_client_key_id",
                "admin-approval-v2.pub",
                patch.admin_approval,
            ),
        ] {
            set_value(
                &mut approval,
                &[path_field],
                fixed_path(root, &format!("config/approvald/keys/{leaf}")),
            )?;
            set_hex(&mut approval, &[id_field], material.key_id)?;
        }
        set_value(
            &mut approval,
            &["agent_listener_gid"],
            Value::from(group_identity("_savana_agent_approval_dev")?),
        )?;
        set_value(
            &mut approval,
            &["ingress_listener_gid"],
            Value::from(group_identity("_savana_ingress_approval_dev")?),
        )?;
        write_json(&root.join("config/approvald-bootstrap-v2.json"), &approval)?;

        let root_certificate_path = root.join("config/tls/runtime-root-v2.der");
        let client_certificate_path = root.join("config/tls/provider-client-v2.der");
        let root_certificate = read_bounded(&root_certificate_path, MAX_CERTIFICATE_BYTES)?;
        let client_certificate = read_bounded(&client_certificate_path, MAX_CERTIFICATE_BYTES)?;
        let endpoint_binding = provider_endpoint_binding(
            &root_certificate,
            &client_certificate,
            PROVIDER_ALPN,
            PROVIDER_SERVER_NAME,
            9444,
        );
        let credential_identity = domain_digest(
            b"SAVANA_PROVIDER_CREDENTIAL_HANDLE_IDENTITY_V2\0",
            &Sha256::digest(&client_certificate),
        );
        let mut exec = read_json(&root.join("config/execd-bootstrap-v2.json"))?;
        set_value(&mut exec, &["signed_manifest_path"], signed_manifest)?;
        set_value(
            &mut exec,
            &["effect_ledger_projection_path"],
            ledger_projection,
        )?;
        set_value(
            &mut exec,
            &["journal_path"],
            fixed_path(root, "state/execd/execd-journal-v2.cbor"),
        )?;
        set_value(
            &mut exec,
            &["rollback_anchor_path"],
            fixed_path(root, "state/execd/execution-anchor-v2.cbor"),
        )?;
        set_value(
            &mut exec,
            &["connector_registry_path"],
            fixed_path(root, "state/execd/connector-registry-v2.cbor"),
        )?;
        set_value(
            &mut exec,
            &["connector_registry_anchor_path"],
            fixed_path(root, "state/execd/connector-registry-anchor-v2.bin"),
        )?;
        for (exec_field, kernel_field) in [
            (
                "connector_registry_genesis_digest",
                "connector_registry_genesis_digest",
            ),
            ("connector_authority_key_id", "connector_authority_key_id"),
            (
                "connector_authority_public_key",
                "connector_authority_public_key",
            ),
            ("user_tier_host_allowlist", "user_tier_host_allowlist"),
        ] {
            let value = kernel
                .pointer(&format!("/policy_runtime/{kernel_field}"))
                .cloned()
                .ok_or_else(|| format!("missing policy_runtime.{kernel_field}"))?;
            set_value(&mut exec, &[exec_field], value)?;
        }
        set_value(
            &mut exec,
            &["effect_gate_path"],
            fixed_path(root, "config/effect-gate-v2"),
        )?;
        set_hex(
            &mut exec,
            &["effect_receipt_key_id"],
            patch.effect_receipt.key_id,
        )?;
        set_hex(&mut exec, &["seal_key_id"], patch.seal_key_id)?;
        set_value(
            &mut exec,
            &["worker", "sandbox_program_path"],
            Value::String(exec_sandbox.to_string_lossy().into_owned()),
        )?;
        set_hex(
            &mut exec,
            &["worker", "sandbox_program_digest"],
            exec_sandbox_digest,
        )?;
        set_value(
            &mut exec,
            &["worker", "worker_program_path"],
            Value::String(connector_worker.to_string_lossy().into_owned()),
        )?;
        set_hex(
            &mut exec,
            &["worker", "worker_artifact_digest"],
            connector_worker_digest,
        )?;
        set_value(
            &mut exec,
            &["worker", "no_network_profile_path"],
            Value::String(no_network_profile_path.to_string_lossy().into_owned()),
        )?;
        set_hex(
            &mut exec,
            &["worker", "no_network_profile_digest"],
            no_network_profile_digest,
        )?;
        set_value(
            &mut exec,
            &["worker", "credential_absence_profile_path"],
            Value::String(
                credential_absence_profile_path
                    .to_string_lossy()
                    .into_owned(),
            ),
        )?;
        set_hex(
            &mut exec,
            &["worker", "credential_absence_profile_digest"],
            credential_absence_profile_digest,
        )?;
        set_value(
            &mut exec,
            &["provider", "address"],
            Value::String("127.0.0.1:9444".to_owned()),
        )?;
        set_value(
            &mut exec,
            &["provider", "server_name"],
            Value::String(PROVIDER_SERVER_NAME.to_owned()),
        )?;
        set_value(
            &mut exec,
            &["provider", "canonical_url"],
            Value::String(format!("https://{PROVIDER_SERVER_NAME}:9444/")),
        )?;
        let provider_spki = read_bounded(
            &root.join("config/tls/provider-server-spki-v2.der"),
            MAX_CERTIFICATE_BYTES,
        )?;
        set_hex(
            &mut exec,
            &["provider", "server_spki_sha256"],
            Sha256::digest(provider_spki).into(),
        )?;
        set_value(
            &mut exec,
            &["provider", "root_certificate_path"],
            Value::String(root_certificate_path.to_string_lossy().into_owned()),
        )?;
        set_hex(
            &mut exec,
            &["provider", "root_certificate_digest"],
            Sha256::digest(&root_certificate).into(),
        )?;
        set_value(
            &mut exec,
            &["provider", "client_certificate_paths"],
            Value::Array(vec![Value::String(
                client_certificate_path.to_string_lossy().into_owned(),
            )]),
        )?;
        set_value(
            &mut exec,
            &["provider", "client_certificate_digests"],
            Value::Array(vec![Value::String(hex(Sha256::digest(
                &client_certificate,
            )
            .into()))]),
        )?;
        set_value(
            &mut exec,
            &["provider", "alpn_protocol_hex"],
            Value::String(hex_bytes(PROVIDER_ALPN)),
        )?;
        set_hex(
            &mut exec,
            &["provider", "endpoint_binding_digest"],
            endpoint_binding,
        )?;
        set_hex(
            &mut exec,
            &["provider", "credential_handle_identity_digest"],
            credential_identity,
        )?;
        let release_client_certificate_path = root.join("config/tls/final-release-client-v2.der");
        let release_client_certificate =
            read_bounded(&release_client_certificate_path, MAX_CERTIFICATE_BYTES)?;
        let release_endpoint_binding = provider_endpoint_binding(
            &root_certificate,
            &release_client_certificate,
            PROVIDER_ALPN,
            FINAL_RELEASE_SERVER_NAME,
            43191,
        );
        let release_credential_identity = domain_digest(
            b"SAVANA_PROVIDER_CREDENTIAL_HANDLE_IDENTITY_V2\0",
            &Sha256::digest(&release_client_certificate),
        );
        let release_spki = read_bounded(
            &root.join("config/tls/final-release-server-spki-v2.der"),
            MAX_CERTIFICATE_BYTES,
        )?;
        set_value(
            &mut exec,
            &["provider_routing_mode"],
            Value::String("split-final-release".to_owned()),
        )?;
        set_value(
            &mut exec,
            &["final_release_provider", "address"],
            Value::String("127.0.0.1:43191".to_owned()),
        )?;
        set_value(
            &mut exec,
            &["final_release_provider", "server_name"],
            Value::String(FINAL_RELEASE_SERVER_NAME.to_owned()),
        )?;
        set_value(
            &mut exec,
            &["final_release_provider", "canonical_url"],
            Value::String(format!(
                "https://{FINAL_RELEASE_SERVER_NAME}:43191/savana/final-release"
            )),
        )?;
        set_hex(
            &mut exec,
            &["final_release_provider", "server_spki_sha256"],
            Sha256::digest(release_spki).into(),
        )?;
        set_value(
            &mut exec,
            &["final_release_provider", "root_certificate_path"],
            Value::String(root_certificate_path.to_string_lossy().into_owned()),
        )?;
        set_hex(
            &mut exec,
            &["final_release_provider", "root_certificate_digest"],
            Sha256::digest(&root_certificate).into(),
        )?;
        set_value(
            &mut exec,
            &["final_release_provider", "client_certificate_paths"],
            Value::Array(vec![Value::String(
                release_client_certificate_path
                    .to_string_lossy()
                    .into_owned(),
            )]),
        )?;
        set_value(
            &mut exec,
            &["final_release_provider", "client_certificate_digests"],
            Value::Array(vec![Value::String(hex(Sha256::digest(
                &release_client_certificate,
            )
            .into()))]),
        )?;
        set_value(
            &mut exec,
            &["final_release_provider", "alpn_protocol_hex"],
            Value::String(hex_bytes(PROVIDER_ALPN)),
        )?;
        set_hex(
            &mut exec,
            &["final_release_provider", "endpoint_binding_digest"],
            release_endpoint_binding,
        )?;
        set_hex(
            &mut exec,
            &[
                "final_release_provider",
                "credential_handle_identity_digest",
            ],
            release_credential_identity,
        )?;
        write_json(&root.join("config/execd-bootstrap-v2.json"), &exec)?;

        // Materialize only the reviewed release mapping after the real transport
        // pins and credential identities exist. The legacy report descriptor is
        // retained without a profile and cannot enter strict execution.
        let legacy_path = root.join("config/policy/development-draft-report-tool-v2.cbor");
        let release_path = root.join("config/policy/development-final-release-tool-v3.cbor");
        let (reviewed_kernel, legacy, release) = crate::development_profiles::materialize(
            &kernel,
            &exec,
            &read_bounded(&legacy_path, 8 * 1024 * 1024)?,
            &legacy_path,
            &release_path,
            &SigningKey::from_bytes(&patch.registry_publisher.seed),
        )?;
        write_new(&release_path, &release, 0o444)?;
        replace_file(&legacy_path, &legacy)?;
        kernel = reviewed_kernel;
        write_json(&root.join("config/kerneld-bootstrap-v2.json"), &kernel)?;

        let mut template = read_json(&root.join("config/development-manifest-template-v2.json"))?;
        set_hex(
            &mut template,
            &["kernel_envelope_signing_key_id"],
            patch.kernel_envelope.key_id,
        )?;
        for (edge, client, server) in [
            ("agent_kernel", patch.agent_client, patch.agent_server),
            ("ingress_kernel", patch.ingress_client, patch.ingress_server),
            (
                "kernel_executor",
                patch.executor_client,
                patch.executor_server,
            ),
        ] {
            set_hex(
                &mut template,
                &["edges", edge, "client_handshake_key_id"],
                client.key_id,
            )?;
            set_hex(
                &mut template,
                &["edges", edge, "server_handshake_key_id"],
                server.key_id,
            )?;
        }
        let jarvis_control_identity = agent
            .get("jarvis_control_identity")
            .and_then(Value::as_str)
            .ok_or_else(|| "agent config has no JARVIS control identity".to_owned())?
            .to_owned();
        let agentd_identity = template
            .get("services")
            .and_then(|services| services.get("agentd"))
            .and_then(|agentd| agentd.get("service_identity"))
            .and_then(Value::as_str)
            .ok_or_else(|| "manifest template has no agentd identity".to_owned())?
            .to_owned();
        let active_manifest = template
            .get("active_state_manifest_digest")
            .and_then(Value::as_str)
            .ok_or_else(|| "manifest template has no active-state digest".to_owned())?
            .to_owned();
        let generation = template
            .get("deployment_generation")
            .and_then(Value::as_u64)
            .filter(|generation| *generation != 0)
            .ok_or_else(|| "manifest template has no deployment generation".to_owned())?;
        let mut jarvis = read_json(&root.join("config/jarvis-python-v2.json"))?;
        set_value(&mut jarvis, &["protocol_major"], Value::from(2_u16))?;
        set_value(&mut jarvis, &["protocol_minor"], Value::from(0_u16))?;
        set_value(
            &mut jarvis,
            &["deployment_generation"],
            Value::from(generation),
        )?;
        set_value(
            &mut jarvis,
            &["active_state_manifest_digest"],
            Value::String(active_manifest),
        )?;
        set_hex(&mut jarvis, &["caller_boot_id"], patch.jarvis_boot)?;
        set_value(
            &mut jarvis,
            &["caller_identity"],
            Value::String(jarvis_control_identity),
        )?;
        set_hex(&mut jarvis, &["service_boot_id"], patch.agentd_boot)?;
        set_value(
            &mut jarvis,
            &["service_identity"],
            Value::String(agentd_identity),
        )?;
        write_json(&root.join("config/jarvis-python-v2.json"), &jarvis)?;
        write_json(
            &root.join("config/development-manifest-template-v2.json"),
            &template,
        )
    }

    fn patch_isolation_profile(
        path: &Path,
        worker: &Path,
        require_network_denial: bool,
    ) -> Result<(), String> {
        let mut profile = read_json(path)?;
        let version = profile
            .get("version")
            .and_then(Value::as_u64)
            .ok_or_else(|| format!("sandbox profile has no version: {}", path.display()))?;
        if version != 2 {
            return Err(format!(
                "sandbox profile version is invalid: {}",
                path.display()
            ));
        }
        set_value(
            &mut profile,
            &["worker_program"],
            Value::String(worker.to_string_lossy().into_owned()),
        )?;
        set_value(&mut profile, &["read_only_paths"], Value::Array(Vec::new()))?;
        if require_network_denial {
            set_value(&mut profile, &["deny_all_network"], Value::Bool(true))?;
        }
        for (field, minimum, maximum) in [
            (
                "memory_limit_bytes",
                16 * 1024 * 1024,
                4_u64 * 1024 * 1024 * 1024,
            ),
            ("cpu_time_seconds", 1, 300),
            ("open_file_limit", 4, 64),
        ] {
            let value = profile
                .get(field)
                .and_then(Value::as_u64)
                .ok_or_else(|| format!("sandbox profile is missing {field}"))?;
            if value < minimum || value > maximum {
                return Err(format!("sandbox profile {field} is out of bounds"));
            }
        }
        if profile.get("process_limit").and_then(Value::as_u64) != Some(1)
            || profile
                .get("output_file_limit_bytes")
                .and_then(Value::as_u64)
                .is_none_or(|value| value > 16 * 1024 * 1024)
        {
            return Err("sandbox profile has unsafe process or output limits".to_owned());
        }
        write_json(path, &profile)
    }

    fn patch_network_profile(path: &Path) -> Result<(), String> {
        let profile = read_json(path)?;
        if profile.get("version").and_then(Value::as_u64) != Some(2)
            || profile.get("deny_all_network").and_then(Value::as_bool) != Some(true)
        {
            return Err("connector network profile is not deny-all".to_owned());
        }
        Ok(())
    }

    fn provider_endpoint_binding(
        root_certificate: &[u8],
        client_certificate: &[u8],
        alpn: &[u8],
        server_name: &str,
        port: u16,
    ) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"SAVANA_PROVIDER_TLS_ENDPOINT_BINDING_V2\0");
        hasher.update([4]);
        hasher.update([127, 0, 0, 1]);
        hasher.update(port.to_be_bytes());
        hasher.update((server_name.len() as u16).to_be_bytes());
        hasher.update(server_name.as_bytes());
        hasher.update(Sha256::digest(root_certificate));
        hasher.update(Sha256::digest(client_certificate));
        hasher.update((alpn.len() as u16).to_be_bytes());
        hasher.update(alpn);
        hasher.finalize().into()
    }

    fn ed25519(issued: &mut HashSet<[u8; 32]>) -> Result<Ed25519Material, String> {
        for _ in 0..16 {
            let seed = random_unique(issued)?;
            let public_key = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
            if public_key == [0; 32] || public_key == seed || !issued.insert(public_key) {
                continue;
            }
            let key_id = *derive_ed25519_key_id_v2(public_key).as_bytes();
            return Ok(Ed25519Material {
                seed,
                public_key,
                key_id,
            });
        }
        Err("secure entropy did not produce distinct Ed25519 material".to_owned())
    }

    fn random_unique(issued: &mut HashSet<[u8; 32]>) -> Result<[u8; 32], String> {
        for _ in 0..16 {
            let mut bytes = [0_u8; 32];
            getrandom::getrandom(&mut bytes)
                .map_err(|_| "secure entropy is unavailable".to_owned())?;
            if bytes != [0; 32] && issued.insert(bytes) {
                return Ok(bytes);
            }
        }
        Err("secure entropy did not produce unique material".to_owned())
    }

    fn account_identity(name: &str) -> Result<(u32, u32), String> {
        let account = nix::unistd::User::from_name(name)
            .map_err(|_| format!("development account lookup failed: {name}"))?
            .ok_or_else(|| format!("development account is missing: {name}"))?;
        let uid = account.uid.as_raw();
        let gid = account.gid.as_raw();
        if uid == 0 || gid == 0 {
            return Err(format!("development account is privileged: {name}"));
        }
        Ok((uid, gid))
    }

    fn group_identity(name: &str) -> Result<u32, String> {
        let group = nix::unistd::Group::from_name(name)
            .map_err(|_| format!("development group lookup failed: {name}"))?
            .ok_or_else(|| format!("development group is missing: {name}"))?;
        let gid = group.gid.as_raw();
        if gid == 0 {
            return Err(format!("development group is privileged: {name}"));
        }
        Ok(gid)
    }

    fn write_credentials(
        root: &Path,
        credentials: &[(&str, &str, [u8; 32])],
    ) -> Result<(), String> {
        for (service, leaf, bytes) in credentials {
            write_new(
                &root.join("credentials").join(service).join(leaf),
                bytes,
                0o400,
            )?;
        }
        Ok(())
    }

    fn write_public_keys(root: &Path, keys: &[(&str, [u8; 32])]) -> Result<(), String> {
        for (leaf, bytes) in keys {
            let path = root.join("config").join(leaf);
            let parent = path
                .parent()
                .ok_or_else(|| "public key path has no parent".to_owned())?;
            fs::create_dir_all(parent)
                .map_err(|_| format!("cannot create {}", parent.display()))?;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o755))
                .map_err(|_| format!("cannot set mode on {}", parent.display()))?;
            write_new(&path, bytes, 0o444)?;
        }
        Ok(())
    }

    fn set_key_pair(
        value: &mut Value,
        id_path: &[&str],
        public_path: &[&str],
        key: &Ed25519Material,
    ) -> Result<(), String> {
        set_hex(value, id_path, key.key_id)?;
        set_hex(value, public_path, key.public_key)
    }

    fn set_hex(value: &mut Value, path: &[&str], bytes: [u8; 32]) -> Result<(), String> {
        set_value(value, path, Value::String(hex(bytes)))
    }

    fn set_value(value: &mut Value, path: &[&str], replacement: Value) -> Result<(), String> {
        let (leaf, parents) = path
            .split_last()
            .ok_or_else(|| "empty JSON path".to_owned())?;
        let mut current = value;
        for component in parents {
            current = current
                .as_object_mut()
                .and_then(|object| object.get_mut(*component))
                .ok_or_else(|| format!("missing JSON object: {component}"))?;
        }
        let object = current
            .as_object_mut()
            .ok_or_else(|| "JSON parent is not an object".to_owned())?;
        if !object.contains_key(*leaf) {
            return Err(format!("missing JSON field: {leaf}"));
        }
        object.insert((*leaf).to_owned(), replacement);
        Ok(())
    }

    fn fixed_path(root: &Path, leaf: &str) -> Value {
        Value::String(root.join(leaf).to_string_lossy().into_owned())
    }

    fn connector_authority_mode(kernel: &Value) -> Result<bool, String> {
        let key_id = config_hex_32(kernel, &["policy_runtime", "connector_authority_key_id"])?;
        let public_key = config_hex_32(
            kernel,
            &["policy_runtime", "connector_authority_public_key"],
        )?;
        match (key_id == [0; 32], public_key == [0; 32]) {
            (true, true) => Ok(false),
            (false, false) => Ok(true),
            _ => {
                Err("connector authority must be either fully disabled or fully enabled".to_owned())
            }
        }
    }

    fn config_hex_32(value: &Value, path: &[&str]) -> Result<[u8; 32], String> {
        let mut current = value;
        for component in path {
            current = current
                .as_object()
                .and_then(|object| object.get(*component))
                .ok_or_else(|| format!("missing JSON field: {component}"))?;
        }
        let encoded = current
            .as_str()
            .ok_or_else(|| "connector authority field is not a string".to_owned())?;
        let bytes = encoded.as_bytes();
        if bytes.len() != 64 {
            return Err("connector authority field is not exact hex-32".to_owned());
        }
        let mut decoded = [0_u8; 32];
        for (index, output) in decoded.iter_mut().enumerate() {
            let high = lowercase_hex_nibble(bytes[index * 2])?;
            let low = lowercase_hex_nibble(bytes[index * 2 + 1])?;
            *output = (high << 4) | low;
        }
        Ok(decoded)
    }

    fn lowercase_hex_nibble(byte: u8) -> Result<u8, String> {
        match byte {
            b'0'..=b'9' => Ok(byte - b'0'),
            b'a'..=b'f' => Ok(byte - b'a' + 10),
            _ => Err("connector authority field is not canonical lowercase hex".to_owned()),
        }
    }

    fn read_json(path: &Path) -> Result<Value, String> {
        let value: Value = serde_json::from_slice(&read_bounded(path, MAX_JSON_BYTES)?)
            .map_err(|_| format!("invalid JSON: {}", path.display()))?;
        if !value.is_object() {
            return Err(format!("JSON root is not an object: {}", path.display()));
        }
        Ok(value)
    }

    fn file_digest(path: &Path) -> Result<[u8; 32], String> {
        Ok(Sha256::digest(read_bounded(path, 256 * 1024 * 1024)?).into())
    }

    fn write_json(path: &Path, value: &Value) -> Result<(), String> {
        let mut object = match value {
            Value::Object(object) => object.clone(),
            _ => return Err("JSON root is not an object".to_owned()),
        };
        sort_object(&mut object);
        let bytes = serde_json::to_vec(&Value::Object(object))
            .map_err(|_| "JSON serialization failed".to_owned())?;
        replace_file(path, &bytes)
    }

    fn sort_object(object: &mut Map<String, Value>) {
        for value in object.values_mut() {
            match value {
                Value::Object(child) => sort_object(child),
                Value::Array(values) => {
                    for value in values {
                        if let Value::Object(child) = value {
                            sort_object(child);
                        }
                    }
                }
                _ => {}
            }
        }
    }

    fn domain_digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(domain);
        hasher.update(bytes);
        hasher.finalize().into()
    }

    fn hex(bytes: [u8; 32]) -> String {
        hex_bytes(&bytes)
    }

    fn hex_bytes(bytes: &[u8]) -> String {
        use std::fmt::Write as _;

        let mut output = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
        }
        output
    }

    fn absolute(value: Option<std::ffi::OsString>, name: &str) -> Result<PathBuf, String> {
        let path = PathBuf::from(value.ok_or_else(|| format!("missing {name}"))?);
        if !path.is_absolute()
            || path.components().any(|component| {
                matches!(
                    component,
                    std::path::Component::ParentDir
                        | std::path::Component::CurDir
                        | std::path::Component::Prefix(_)
                )
            })
        {
            return Err(format!("{name} is not a closed absolute path"));
        }
        Ok(path)
    }

    fn require_safe_root(root: &Path) -> Result<(), String> {
        let metadata =
            fs::symlink_metadata(root).map_err(|_| "installation root is missing".to_owned())?;
        let runtime_group = nix::unistd::Group::from_name("_savana_runtime_dev")
            .map_err(|_| "runtime group lookup failed".to_owned())?
            .ok_or_else(|| "runtime group is missing".to_owned())?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || metadata.uid() != 0
            || metadata.gid() != runtime_group.gid.as_raw()
            || metadata.mode() & 0o7777 != 0o750
        {
            return Err("installation root has unsafe identity".to_owned());
        }
        Ok(())
    }

    fn read_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>, String> {
        let before =
            fs::symlink_metadata(path).map_err(|_| format!("cannot stat {}", path.display()))?;
        if before.file_type().is_symlink()
            || !before.is_file()
            || before.nlink() != 1
            || usize::try_from(before.len()).map_or(true, |length| length > maximum)
        {
            return Err(format!("unsafe input file {}", path.display()));
        }
        let bytes = fs::read(path).map_err(|_| format!("cannot read {}", path.display()))?;
        let after =
            fs::symlink_metadata(path).map_err(|_| format!("cannot restat {}", path.display()))?;
        if before.dev() != after.dev()
            || before.ino() != after.ino()
            || before.len() != after.len()
            || bytes.len() > maximum
        {
            return Err(format!("input file changed {}", path.display()));
        }
        Ok(bytes)
    }

    fn write_new(path: &Path, bytes: &[u8], mode: u32) -> Result<(), String> {
        let parent = path
            .parent()
            .ok_or_else(|| "output has no parent".to_owned())?;
        let metadata = fs::symlink_metadata(parent)
            .map_err(|_| format!("output parent is missing: {}", parent.display()))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(format!("unsafe output parent: {}", parent.display()));
        }
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(path)
            .map_err(|_| format!("cannot create {}", path.display()))?;
        file.write_all(bytes)
            .and_then(|()| file.flush())
            .map_err(|_| format!("cannot write {}", path.display()))?;
        file.sync_all()
            .map_err(|_| format!("cannot sync {}", path.display()))
    }

    fn replace_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
        let metadata =
            fs::symlink_metadata(path).map_err(|_| format!("cannot stat {}", path.display()))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.nlink() != 1 {
            return Err(format!("unsafe JSON output {}", path.display()));
        }
        let temporary = path.with_extension("savana-material-new");
        if fs::symlink_metadata(&temporary).is_ok() {
            return Err(format!("temporary output exists: {}", temporary.display()));
        }
        write_new(&temporary, bytes, 0o444)?;
        fs::rename(&temporary, path).map_err(|_| format!("cannot replace {}", path.display()))?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o444))
            .map_err(|_| format!("cannot set mode on {}", path.display()))
    }
}
