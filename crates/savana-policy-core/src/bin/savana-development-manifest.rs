#![forbid(unsafe_code)]

#[cfg(all(feature = "macos-development-authority", not(debug_assertions)))]
compile_error!("macos-development-authority is forbidden in release builds");

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("savana-development-manifest is available only on macOS");
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
    use std::fs;
    use std::io::Write as _;
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
    use std::path::{Path, PathBuf};

    use ed25519_dalek::{Signer as _, SigningKey};
    use savana_kernel_protocol::v2::{derive_ed25519_key_id_v2, EndpointRoleV2};
    use savana_platform_identity::{measure_macos_static_code_v2, MacOsCodeIdentityMeasurementV2};
    use serde::{Deserialize, Serialize};
    use sha2::{Digest as _, Sha256};

    const ROOT: &str = "/Library/Application Support/Savana/Development";
    const TEAM: &str = "SAVANADEV1";
    const MANIFEST_SIGNATURE_DOMAIN: &[u8] = b"SAVANA_DEPLOYMENT_MANIFEST_SIGNATURE_V2\0";
    const CONFIG_PATH_DOMAIN: &[u8] = b"SAVANA_CONFIG_PATH_IDENTITY_V2\0";
    const SOCKET_PATH_DOMAIN: &[u8] = b"SAVANA_SOCKET_PATH_IDENTITY_V2\0";
    const MAX_TEMPLATE_BYTES: usize = 256 * 1024;
    const MAX_CONFIG_BYTES: usize = 256 * 1024;
    const MAX_ARTIFACT_BYTES: usize = 256 * 1024 * 1024;

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Template {
        installation_id: String,
        active_state_manifest_digest: String,
        active_state_manifest_sequence: u64,
        deployment_generation: u64,
        effect_fence_epoch: u64,
        protocol_abi_digest: String,
        release_identity_digest: String,
        model_set_identity_digest: String,
        resource_profile_identity_digest: String,
        approval_lock_identity_digest: String,
        planner_lock_identity_digest: String,
        executor_key_lock_identity_digest: String,
        kernel_envelope_signing_key_id: String,
        ledger_projection_identity: String,
        effect_ledger_head_digest: String,
        ledger_projection_signing_key_id: String,
        ledger_projection_signing_public_key: String,
        services: ServiceTemplateSet,
        edges: EdgeTemplateSet,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ServiceTemplateSet {
        kerneld: ServiceTemplate,
        agentd: ServiceTemplate,
        ingressd: ServiceTemplate,
        approvald: ServiceTemplate,
        execd: ServiceTemplate,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ServiceTemplate {
        service_identity: String,
        keystore_authority_identity: String,
        rollback_authority_identity: String,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct EdgeTemplateSet {
        agent_kernel: EdgeKeys,
        ingress_kernel: EdgeKeys,
        kernel_executor: EdgeKeys,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct EdgeKeys {
        client_handshake_key_id: String,
        server_handshake_key_id: String,
    }

    #[derive(Clone)]
    struct ServiceMeasurement {
        tag: u16,
        name: &'static str,
        uid: u32,
        gid: u32,
        executable_digest: [u8; 32],
        config_digest: [u8; 32],
        config_path_digest: [u8; 32],
        socket_path_digest: [u8; 32],
        socket_uid: u32,
        socket_gid: u32,
        socket_mode: u32,
        code_identity: MacOsCodeIdentityMeasurementV2,
        sandbox_profile_digest: [u8; 32],
        template: ServiceTemplateValues,
    }

    #[derive(Clone)]
    struct ServiceTemplateValues {
        service_identity: [u8; 32],
        keystore_authority_identity: [u8; 32],
        rollback_authority_identity: [u8; 32],
    }

    struct EdgeMeasurement {
        edge_tag: u16,
        client_tag: u16,
        server_tag: u16,
        role_tag: u16,
        role_identity: &'static str,
        listener_identity_digest: [u8; 32],
        client_handshake_key_id: [u8; 32],
        server_handshake_key_id: [u8; 32],
        client: ServiceMeasurement,
    }

    #[derive(Serialize)]
    struct Observation {
        service: &'static str,
        service_identity: String,
        process_uid: u32,
        process_gid: u32,
        executable_path: String,
        config_path: String,
        endpoint: Endpoint,
        sandbox_profile_path: String,
        keystore_authority_identity: String,
        rollback_authority_identity: String,
    }

    #[derive(Serialize)]
    #[serde(tag = "kind", rename_all = "kebab-case")]
    enum Endpoint {
        UnixSocket { path: String },
        LoopbackTcp { port: u16 },
    }

    struct ServiceLayout {
        tag: u16,
        name: &'static str,
        account: &'static str,
        config_leaf: &'static str,
        endpoint: EndpointLayout,
        bundle: &'static str,
    }

    enum EndpointLayout {
        Unix {
            path: &'static str,
            owner: &'static str,
            group: &'static str,
            mode: u32,
        },
        Tcp {
            port: u16,
        },
    }

    pub(super) fn run() -> Result<(), String> {
        let mut arguments = std::env::args_os().skip(1);
        let template_path = absolute(arguments.next(), "manifest template")?;
        let seed_path = absolute(arguments.next(), "manifest signing seed")?;
        let root = absolute(arguments.next(), "installation root")?;
        let root_output = absolute(arguments.next(), "manifest root output")?;
        let manifest_output = absolute(arguments.next(), "signed manifest output")?;
        if arguments.next().is_some()
            || root != Path::new(ROOT)
            || root_output != Path::new(ROOT).join("config/trust/deployment-manifest-root-v2.json")
            || manifest_output != Path::new(ROOT).join("config/deployment-manifest-v2.cbor")
            || std::env::var("SAVANA_AUTHORITY_CLASS").as_deref() != Ok("development")
        {
            return Err("invalid closed development-manifest invocation".to_owned());
        }
        require_new_output(&root_output)?;
        require_new_output(&manifest_output)?;
        let template_bytes = read_bounded(&template_path, MAX_TEMPLATE_BYTES)?;
        let template: Template = serde_json::from_slice(&template_bytes)
            .map_err(|_| "manifest template is invalid".to_owned())?;
        let seed: [u8; 32] = read_bounded(&seed_path, 32)?
            .try_into()
            .map_err(|_| "manifest signing seed must be exactly 32 bytes".to_owned())?;
        if seed == [0; 32] {
            return Err("manifest signing seed is zero".to_owned());
        }

        let layouts = layouts();
        let jarvis_identity = measured_identity(
            &root.join("bin/savana-jarvis-python"),
            "com.savana.development.jarvis-python",
        )?;
        let observations = build_observations(&root, &layouts, &template.services)?;
        patch_bootstrap_configs(&root, &observations, &jarvis_identity)?;
        let services = measure_services(&root, &layouts, &template.services)?;
        let edges = measure_edges(&services, &template.edges)?;
        let payload = encode_payload(&template, &services, &edges)?;
        let signing_key = SigningKey::from_bytes(&seed);
        let key_id = derive_ed25519_key_id_v2(signing_key.verifying_key().to_bytes());
        let payload_digest: [u8; 32] = Sha256::digest(&payload).into();
        let mut signature_input =
            Vec::with_capacity(MANIFEST_SIGNATURE_DOMAIN.len() + payload_digest.len());
        signature_input.extend_from_slice(MANIFEST_SIGNATURE_DOMAIN);
        signature_input.extend_from_slice(&payload_digest);
        let signature = signing_key.sign(&signature_input).to_bytes();
        let signed = encode_signed(&payload, *key_id.as_bytes(), signature)?;
        savana_policy_core::v2::VerifiedDeploymentManifestV2::verify(
            &signed,
            key_id,
            signing_key.verifying_key().to_bytes(),
        )
        .map_err(|_| "generated deployment manifest did not verify".to_owned())?;

        let root_json = serde_json::json!({
            "key_id": hex(*key_id.as_bytes()),
            "public_key": hex(signing_key.verifying_key().to_bytes()),
        });
        write_new(
            &root_output,
            &serde_json::to_vec(&root_json)
                .map_err(|_| "manifest root serialization failed".to_owned())?,
        )?;
        write_new(&manifest_output, &signed)?;
        Ok(())
    }

    fn layouts() -> [ServiceLayout; 5] {
        [
            ServiceLayout {
                tag: 1,
                name: "kerneld",
                account: "_savana_kernel_dev",
                config_leaf: "kerneld-bootstrap-v2.json",
                endpoint: EndpointLayout::Unix {
                    path: "/Library/Application Support/Savana/Development/run/kerneld/agentd/kerneld.sock",
                    owner: "_savana_kernel_dev",
                    group: "_savana_agent_kernel_dev",
                    mode: 0o660,
                },
                bundle: "com.savana.development.kerneld",
            },
            ServiceLayout {
                tag: 2,
                name: "agentd",
                account: "_savana_agent_dev",
                config_leaf: "agentd-bootstrap-v2.json",
                endpoint: EndpointLayout::Unix {
                    path: "/Library/Application Support/Savana/Development/run/agentd/jarvis/control.sock",
                    owner: "_savana_agent_dev",
                    group: "_savana_jarvis_agent_dev",
                    mode: 0o660,
                },
                bundle: "com.savana.development.agentd",
            },
            ServiceLayout {
                tag: 3,
                name: "ingressd",
                account: "_savana_ingress_dev",
                config_leaf: "ingressd-bootstrap-v2.json",
                endpoint: EndpointLayout::Tcp { port: 8767 },
                bundle: "com.savana.development.ingressd",
            },
            ServiceLayout {
                tag: 4,
                name: "approvald",
                account: "_savana_approval_dev",
                config_leaf: "approvald-bootstrap-v2.json",
                endpoint: EndpointLayout::Tcp { port: 8766 },
                bundle: "com.savana.development.approvald",
            },
            ServiceLayout {
                tag: 5,
                name: "execd",
                account: "_savana_exec_dev",
                config_leaf: "execd-bootstrap-v2.json",
                endpoint: EndpointLayout::Unix {
                    path: "/Library/Application Support/Savana/Development/run/execd/kerneld/execd.sock",
                    owner: "_savana_exec_dev",
                    group: "_savana_kernel_exec_dev",
                    mode: 0o660,
                },
                bundle: "com.savana.development.execd",
            },
        ]
    }

    fn build_observations(
        root: &Path,
        layouts: &[ServiceLayout; 5],
        templates: &ServiceTemplateSet,
    ) -> Result<Vec<Observation>, String> {
        layouts
            .iter()
            .map(|layout| {
                let (uid, gid) = account_identity(layout.account)?;
                let template = service_template(layout.name, templates);
                let endpoint = match layout.endpoint {
                    EndpointLayout::Unix { path, .. } => Endpoint::UnixSocket {
                        path: path.to_owned(),
                    },
                    EndpointLayout::Tcp { port } => Endpoint::LoopbackTcp { port },
                };
                Ok(Observation {
                    service: layout.name,
                    service_identity: template.service_identity.clone(),
                    process_uid: uid,
                    process_gid: gid,
                    executable_path: root
                        .join(format!("bin/savana-{}", layout.name))
                        .to_string_lossy()
                        .into_owned(),
                    config_path: root
                        .join("config")
                        .join(layout.config_leaf)
                        .to_string_lossy()
                        .into_owned(),
                    endpoint,
                    sandbox_profile_path: root
                        .join(format!(
                            "config/com.savana.development.{}.entitlements.plist",
                            layout.name
                        ))
                        .to_string_lossy()
                        .into_owned(),
                    keystore_authority_identity: template.keystore_authority_identity.clone(),
                    rollback_authority_identity: template.rollback_authority_identity.clone(),
                })
            })
            .collect()
    }

    fn patch_bootstrap_configs(
        root: &Path,
        observations: &[Observation],
        jarvis: &MacOsCodeIdentityMeasurementV2,
    ) -> Result<(), String> {
        let services = serde_json::to_value(observations)
            .map_err(|_| "service observation serialization failed".to_owned())?;
        for leaf in [
            "kerneld-bootstrap-v2.json",
            "agentd-bootstrap-v2.json",
            "ingressd-bootstrap-v2.json",
            "approvald-bootstrap-v2.json",
            "execd-bootstrap-v2.json",
        ] {
            let path = root.join("config").join(leaf);
            let bytes = read_bounded(&path, MAX_CONFIG_BYTES)?;
            let mut value: serde_json::Value = serde_json::from_slice(&bytes)
                .map_err(|_| format!("bootstrap template is invalid: {leaf}"))?;
            let object = value
                .as_object_mut()
                .ok_or_else(|| format!("bootstrap template is not an object: {leaf}"))?;
            object.insert("services".to_owned(), services.clone());
            if leaf == "agentd-bootstrap-v2.json" {
                let (uid, gid) = account_identity("_savana_jarvis_dev")?;
                object.insert("jarvis_expected_uid".to_owned(), uid.into());
                object.insert("jarvis_expected_gid".to_owned(), gid.into());
                object.insert(
                    "jarvis_code_identity_digest".to_owned(),
                    hex(jarvis.code_directory_measurement()).into(),
                );
            }
            if leaf == "approvald-bootstrap-v2.json" {
                object.insert("admin_expected_uid".to_owned(), 0.into());
                object.insert("admin_expected_gid".to_owned(), 0.into());
                object.insert(
                    "admin_code_identity_digest".to_owned(),
                    hex(jarvis.code_directory_measurement()).into(),
                );
            }
            replace_file(
                &path,
                &serde_json::to_vec(&value)
                    .map_err(|_| format!("bootstrap serialization failed: {leaf}"))?,
            )?;
        }
        Ok(())
    }

    fn measure_services(
        root: &Path,
        layouts: &[ServiceLayout; 5],
        templates: &ServiceTemplateSet,
    ) -> Result<Vec<ServiceMeasurement>, String> {
        layouts
            .iter()
            .map(|layout| {
                let (uid, gid) = account_identity(layout.account)?;
                let executable_path = root.join(format!("bin/savana-{}", layout.name));
                let config_path = root.join("config").join(layout.config_leaf);
                let sandbox_path = root.join(format!(
                    "config/com.savana.development.{}.entitlements.plist",
                    layout.name
                ));
                let (socket_path_digest, socket_uid, socket_gid, socket_mode) =
                    match layout.endpoint {
                        EndpointLayout::Unix {
                            path,
                            owner,
                            group,
                            mode,
                        } => (
                            text_digest(SOCKET_PATH_DOMAIN, path)?,
                            account_identity(owner)?.0,
                            group_identity(group)?,
                            mode,
                        ),
                        EndpointLayout::Tcp { port } => (
                            text_digest(SOCKET_PATH_DOMAIN, &format!("tcp://127.0.0.1:{port}"))?,
                            uid,
                            gid,
                            0,
                        ),
                    };
                let template = service_template(layout.name, templates);
                Ok(ServiceMeasurement {
                    tag: layout.tag,
                    name: layout.name,
                    uid,
                    gid,
                    executable_digest: file_digest(&executable_path)?,
                    config_digest: file_digest(&config_path)?,
                    config_path_digest: text_digest(
                        CONFIG_PATH_DOMAIN,
                        config_path
                            .to_str()
                            .ok_or_else(|| "non-UTF-8 config path".to_owned())?,
                    )?,
                    socket_path_digest,
                    socket_uid,
                    socket_gid,
                    socket_mode,
                    code_identity: measured_identity(&executable_path, layout.bundle)?,
                    sandbox_profile_digest: file_digest(&sandbox_path)?,
                    template: ServiceTemplateValues {
                        service_identity: decode_hex(&template.service_identity)?,
                        keystore_authority_identity: decode_hex(
                            &template.keystore_authority_identity,
                        )?,
                        rollback_authority_identity: decode_hex(
                            &template.rollback_authority_identity,
                        )?,
                    },
                })
            })
            .collect()
    }

    fn measure_edges(
        services: &[ServiceMeasurement],
        templates: &EdgeTemplateSet,
    ) -> Result<Vec<EdgeMeasurement>, String> {
        let specs = [
            (
                1,
                2,
                1,
                EndpointRoleV2::AgentKernel,
                "agent-kernel",
                "/Library/Application Support/Savana/Development/run/kerneld/agentd/kerneld.sock",
                "_savana_kernel_dev",
                "_savana_agent_kernel_dev",
                &templates.agent_kernel,
            ),
            (
                2,
                3,
                1,
                EndpointRoleV2::IngressKernel,
                "ingress-kernel",
                "/Library/Application Support/Savana/Development/run/kerneld/ingressd/kerneld.sock",
                "_savana_kernel_dev",
                "_savana_ingress_kernel_dev",
                &templates.ingress_kernel,
            ),
            (
                3,
                1,
                5,
                EndpointRoleV2::KernelExecutor,
                "kernel-executor",
                "/Library/Application Support/Savana/Development/run/execd/kerneld/execd.sock",
                "_savana_exec_dev",
                "_savana_kernel_exec_dev",
                &templates.kernel_executor,
            ),
        ];
        specs
            .into_iter()
            .map(
                |(
                    edge_tag,
                    client_tag,
                    server_tag,
                    role,
                    role_identity,
                    path,
                    owner,
                    group,
                    keys,
                )| {
                    let client = services
                        .iter()
                        .find(|service| service.tag == client_tag)
                        .ok_or_else(|| "edge client service is missing".to_owned())?
                        .clone();
                    let uid = account_identity(owner)?.0;
                    let gid = group_identity(group)?;
                    let listener = savana_policy_core::v2::listener_identity_digest_v2(
                        role,
                        Path::new(path),
                        uid,
                        gid,
                        0o660,
                    )
                    .map_err(|_| "listener identity could not be derived".to_owned())?;
                    Ok(EdgeMeasurement {
                        edge_tag,
                        client_tag,
                        server_tag,
                        role_tag: role.tag(),
                        role_identity,
                        listener_identity_digest: *listener.as_bytes(),
                        client_handshake_key_id: decode_hex(&keys.client_handshake_key_id)?,
                        server_handshake_key_id: decode_hex(&keys.server_handshake_key_id)?,
                        client,
                    })
                },
            )
            .collect()
    }

    fn encode_payload(
        template: &Template,
        services: &[ServiceMeasurement],
        edges: &[EdgeMeasurement],
    ) -> Result<Vec<u8>, String> {
        let installation_id = decode_hex(&template.installation_id)?;
        let active_state_manifest_digest = decode_hex(&template.active_state_manifest_digest)?;
        let protocol_abi_digest = decode_hex(&template.protocol_abi_digest)?;
        let release_identity_digest = decode_hex(&template.release_identity_digest)?;
        let model_set_identity_digest = decode_hex(&template.model_set_identity_digest)?;
        let resource_profile_identity_digest =
            decode_hex(&template.resource_profile_identity_digest)?;
        let approval_lock_identity_digest = decode_hex(&template.approval_lock_identity_digest)?;
        let planner_lock_identity_digest = decode_hex(&template.planner_lock_identity_digest)?;
        let executor_key_lock_identity_digest =
            decode_hex(&template.executor_key_lock_identity_digest)?;
        let kernel_envelope_signing_key_id = decode_hex(&template.kernel_envelope_signing_key_id)?;
        let ledger_projection_identity = decode_hex(&template.ledger_projection_identity)?;
        let effect_ledger_head_digest = decode_hex(&template.effect_ledger_head_digest)?;
        let ledger_projection_signing_key_id =
            decode_hex(&template.ledger_projection_signing_key_id)?;
        let ledger_projection_signing_public_key =
            decode_hex(&template.ledger_projection_signing_public_key)?;

        let mut encoder = minicbor::Encoder::new(Vec::new());
        encoder
            .array(20)
            .and_then(|encoder| encoder.u16(2))
            .and_then(|encoder| encoder.bytes(&installation_id))
            .and_then(|encoder| encoder.bytes(&active_state_manifest_digest))
            .and_then(|encoder| encoder.u64(template.active_state_manifest_sequence))
            .and_then(|encoder| encoder.u64(template.deployment_generation))
            .and_then(|encoder| encoder.u64(template.effect_fence_epoch))
            .and_then(|encoder| encoder.bytes(&protocol_abi_digest))
            .and_then(|encoder| encoder.bytes(&release_identity_digest))
            .and_then(|encoder| encoder.bytes(&model_set_identity_digest))
            .and_then(|encoder| encoder.bytes(&resource_profile_identity_digest))
            .and_then(|encoder| encoder.bytes(&approval_lock_identity_digest))
            .and_then(|encoder| encoder.bytes(&planner_lock_identity_digest))
            .and_then(|encoder| encoder.bytes(&executor_key_lock_identity_digest))
            .and_then(|encoder| encoder.bytes(&kernel_envelope_signing_key_id))
            .and_then(|encoder| encoder.bytes(&ledger_projection_identity))
            .and_then(|encoder| encoder.bytes(&effect_ledger_head_digest))
            .and_then(|encoder| encoder.bytes(&ledger_projection_signing_key_id))
            .and_then(|encoder| encoder.bytes(&ledger_projection_signing_public_key))
            .and_then(|encoder| encoder.array(services.len() as u64))
            .map_err(|_| "manifest payload encoding failed".to_owned())?;
        for service in services {
            encoder
                .array(15)
                .and_then(|encoder| encoder.u16(service.tag))
                .and_then(|encoder| encoder.bytes(&service.template.service_identity))
                .and_then(|encoder| encoder.u32(service.uid))
                .and_then(|encoder| encoder.u32(service.gid))
                .and_then(|encoder| encoder.bytes(&service.executable_digest))
                .and_then(|encoder| encoder.bytes(&service.config_digest))
                .and_then(|encoder| encoder.bytes(&service.config_path_digest))
                .and_then(|encoder| encoder.bytes(&service.socket_path_digest))
                .and_then(|encoder| encoder.u32(service.socket_uid))
                .and_then(|encoder| encoder.u32(service.socket_gid))
                .and_then(|encoder| encoder.u32(service.socket_mode))
                .and_then(|encoder| {
                    encoder.bytes(&service.code_identity.code_directory_measurement())
                })
                .and_then(|encoder| encoder.bytes(&service.sandbox_profile_digest))
                .and_then(|encoder| encoder.bytes(&service.template.keystore_authority_identity))
                .and_then(|encoder| encoder.bytes(&service.template.rollback_authority_identity))
                .map_err(|_| format!("service encoding failed: {}", service.name))?;
        }
        encoder
            .array(edges.len() as u64)
            .map_err(|_| "edge array encoding failed".to_owned())?;
        for edge in edges {
            encoder
                .array(8)
                .and_then(|encoder| encoder.u16(edge.edge_tag))
                .and_then(|encoder| encoder.u16(edge.client_tag))
                .and_then(|encoder| encoder.u16(edge.server_tag))
                .and_then(|encoder| encoder.u16(edge.role_tag))
                .and_then(|encoder| encoder.bytes(&edge.listener_identity_digest))
                .and_then(|encoder| encoder.bytes(&edge.client_handshake_key_id))
                .and_then(|encoder| encoder.bytes(&edge.server_handshake_key_id))
                .and_then(|encoder| encoder.array(9))
                .and_then(|encoder| encoder.u16(2))
                .and_then(|encoder| encoder.str(edge.role_identity))
                .and_then(|encoder| encoder.u32(edge.client.uid))
                .and_then(|encoder| encoder.u32(edge.client.gid))
                .and_then(|encoder| encoder.str(edge.client.code_identity.bundle_id().as_str()))
                .and_then(|encoder| encoder.str(edge.client.code_identity.team_id().as_str()))
                .and_then(|encoder| {
                    encoder.bytes(&edge.client.code_identity.code_directory_measurement())
                })
                .and_then(|encoder| {
                    encoder.bytes(
                        &edge
                            .client
                            .code_identity
                            .designated_requirement_measurement(),
                    )
                })
                .and_then(|encoder| {
                    encoder.bytes(&edge.client.code_identity.entitlement_measurement())
                })
                .map_err(|_| "edge encoding failed".to_owned())?;
        }
        Ok(encoder.into_writer())
    }

    fn encode_signed(
        payload: &[u8],
        key_id: [u8; 32],
        signature: [u8; 64],
    ) -> Result<Vec<u8>, String> {
        let mut encoder = minicbor::Encoder::new(Vec::new());
        encoder
            .array(3)
            .and_then(|encoder| encoder.bytes(payload))
            .and_then(|encoder| encoder.bytes(&key_id))
            .and_then(|encoder| encoder.bytes(&signature))
            .map_err(|_| "signed manifest encoding failed".to_owned())?;
        Ok(encoder.into_writer())
    }

    fn service_template<'a>(name: &str, templates: &'a ServiceTemplateSet) -> &'a ServiceTemplate {
        match name {
            "kerneld" => &templates.kerneld,
            "agentd" => &templates.agentd,
            "ingressd" => &templates.ingressd,
            "approvald" => &templates.approvald,
            "execd" => &templates.execd,
            _ => unreachable!("closed service layout"),
        }
    }

    fn measured_identity(
        path: &Path,
        expected_bundle: &str,
    ) -> Result<MacOsCodeIdentityMeasurementV2, String> {
        let identity = measure_macos_static_code_v2(path)
            .map_err(|_| format!("Security.framework rejected {}", path.display()))?;
        if identity.bundle_id().as_str() != expected_bundle || identity.team_id().as_str() != TEAM {
            return Err(format!("code identity mismatch for {}", path.display()));
        }
        Ok(identity)
    }

    fn account_identity(name: &str) -> Result<(u32, u32), String> {
        let user = nix::unistd::User::from_name(name)
            .map_err(|_| format!("account lookup failed: {name}"))?
            .ok_or_else(|| format!("account is missing: {name}"))?;
        let uid = user.uid.as_raw();
        let gid = user.gid.as_raw();
        if uid == 0 || gid == 0 {
            return Err(format!("development account is privileged: {name}"));
        }
        Ok((uid, gid))
    }

    fn group_identity(name: &str) -> Result<u32, String> {
        let group = nix::unistd::Group::from_name(name)
            .map_err(|_| format!("group lookup failed: {name}"))?
            .ok_or_else(|| format!("group is missing: {name}"))?;
        let gid = group.gid.as_raw();
        if gid == 0 {
            return Err(format!("development group is privileged: {name}"));
        }
        Ok(gid)
    }

    fn file_digest(path: &Path) -> Result<[u8; 32], String> {
        let bytes = read_bounded(path, MAX_ARTIFACT_BYTES)?;
        Ok(Sha256::digest(bytes).into())
    }

    fn text_digest(domain: &[u8], value: &str) -> Result<[u8; 32], String> {
        let length =
            u32::try_from(value.len()).map_err(|_| "identity text is too long".to_owned())?;
        let mut hasher = Sha256::new();
        hasher.update(domain);
        hasher.update(length.to_be_bytes());
        hasher.update(value.as_bytes());
        Ok(hasher.finalize().into())
    }

    fn decode_hex(value: &str) -> Result<[u8; 32], String> {
        if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err("manifest identity is not 32-byte hex".to_owned());
        }
        let mut decoded = [0_u8; 32];
        for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
            let pair = std::str::from_utf8(pair).map_err(|_| "invalid hex".to_owned())?;
            decoded[index] = u8::from_str_radix(pair, 16).map_err(|_| "invalid hex".to_owned())?;
        }
        if decoded == [0; 32] {
            return Err("manifest identity is zero".to_owned());
        }
        Ok(decoded)
    }

    fn hex(bytes: [u8; 32]) -> String {
        use std::fmt::Write as _;

        let mut encoded = String::with_capacity(64);
        for byte in bytes {
            write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
        }
        encoded
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

    fn require_new_output(path: &Path) -> Result<(), String> {
        if path.exists() || fs::symlink_metadata(path).is_ok() {
            return Err(format!("output already exists: {}", path.display()));
        }
        let parent = path
            .parent()
            .ok_or_else(|| "output has no parent".to_owned())?;
        let metadata = fs::symlink_metadata(parent)
            .map_err(|_| format!("output parent is missing: {}", parent.display()))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(format!("unsafe output parent: {}", parent.display()));
        }
        Ok(())
    }

    fn write_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o444)
            .open(path)
            .map_err(|_| format!("cannot create {}", path.display()))?;
        file.write_all(bytes)
            .and_then(|()| file.flush())
            .map_err(|_| format!("cannot write {}", path.display()))?;
        file.sync_all()
            .map_err(|_| format!("cannot sync {}", path.display()))?;
        Ok(())
    }

    fn replace_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
        let metadata =
            fs::symlink_metadata(path).map_err(|_| format!("cannot stat {}", path.display()))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.nlink() != 1 {
            return Err(format!("unsafe bootstrap output {}", path.display()));
        }
        let temporary = path.with_extension("savana-new");
        if temporary.exists() || fs::symlink_metadata(&temporary).is_ok() {
            return Err(format!("temporary output exists: {}", temporary.display()));
        }
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o444)
            .open(&temporary)
            .map_err(|_| format!("cannot create {}", temporary.display()))?;
        file.write_all(bytes)
            .and_then(|()| file.flush())
            .map_err(|_| format!("cannot write {}", temporary.display()))?;
        file.sync_all()
            .map_err(|_| format!("cannot sync {}", temporary.display()))?;
        fs::rename(&temporary, path).map_err(|_| format!("cannot replace {}", path.display()))?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o444))
            .map_err(|_| format!("cannot set mode on {}", path.display()))?;
        Ok(())
    }
}
