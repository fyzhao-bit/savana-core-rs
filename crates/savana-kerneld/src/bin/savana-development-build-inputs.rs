#![forbid(unsafe_code)]

#[cfg(all(feature = "macos-development-authority", not(debug_assertions)))]
compile_error!("macos-development-authority is forbidden in release builds");

use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signer as _, SigningKey};
use savana_kernel_protocol::v2::{
    derive_ed25519_key_id_v2, ActionTemplateIdV2, Digest32V2, DisplayProjectionIdV2,
    Ed25519KeyIdV2, ExecutorIdentityV2, ProjectionIdV2, RoleIdV2, ToolClassIdV2, UnixMillisV2,
    VersionV2,
};
use savana_policy_core::v2::{
    declassification_implementation_digest_v2, descriptor_digest_v2, AttemptKindV2,
    BoundedConnectorRetryPolicyV2, ClosedDeclassificationPurposeV2, DeclassificationRuleSetV2,
    DeclassificationRuleV2, EffectSetV2, ExecutorIdempotencyContractV2, IdentifierV2,
    LeakGateDutyV2, OperationalTrustRootPurposeV2, OperationalTrustRootSetItemV2,
    OperationalTrustRootSetV2, UnsignedToolDescriptorV2,
};
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};
#[path = "support/protected_experiment_profile.rs"]
mod protected_experiment_profile;

const INSTALL_ROOT: &str = "/Library/Application Support/Savana/Development";
const EFFECT_PROJECTION_SIGNATURE_DOMAIN: &[u8] = b"SAVANA_EFFECT_LEDGER_PROJECTION_SIGNATURE_V2\0";
const INPUT_ASSET_DIGEST_DOMAIN: &[u8] = b"SAVANA_INPUT_RUNTIME_ASSET_V2\0";
const INPUT_ASSET_SIGNATURE_DOMAIN: &[u8] = b"SAVANA_INPUT_RUNTIME_ASSET_SIGNATURE_V2\0";
const TOOL_DESCRIPTOR_SIGNATURE_DOMAIN: &[u8] = b"SAVANA_TOOL_DESCRIPTOR_SIGNATURE_V2\0";
const PARSER_OUTPUT_LIMITS_DOMAIN: &[u8] = b"SAVANA_PARSER_OUTPUT_LIMITS_V2\0";
const TOOL_ARTIFACT_LEAF: &str = "development-draft-report-tool-v2.cbor";
const ACTIVE_NOT_BEFORE: u64 = 1;
const ACTIVE_EXPIRES_AT: u64 = u64::MAX;
const PLANNER_ROUTE: u32 = 1;
const ROLE_ID: u32 = 1;
const ACTION_TEMPLATE: u32 = 102;
const TOOL_CLASS: u32 = 202;
const DESTINATION_PROJECTION: u32 = 1;
const DISPLAY_PROJECTION: u32 = 1;
const PARSER_OUTPUT_LIMIT_BYTES: u32 = 1024 * 1024;
const PARSER_MAXIMUM_PAGES: u32 = 64;

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(70);
    }
}

fn run() -> Result<(), String> {
    let mut arguments = std::env::args_os().skip(1);
    let first = arguments.next().ok_or("missing output directory")?;
    if first == "--protected-experiment-profile" {
        let stage = arguments.next().map(PathBuf::from).ok_or("missing stage")?;
        if arguments.next().is_some() { return Err("unexpected argument".into()); }
        return protected_experiment_profile::materialize(&stage);
    }
    let output = Some(first).map(PathBuf::from).ok_or_else(|| {
        "usage: savana-development-build-inputs <absolute-empty-directory>".to_owned()
    })?;
    if arguments.next().is_some() || !output.is_absolute() {
        return Err("usage: savana-development-build-inputs <absolute-empty-directory>".to_owned());
    }
    require_empty_directory(&output)?;
    for directory in ["artifacts", "config", "entitlements", "sandbox", "signing"] {
        create_directory(&output.join(directory))?;
    }

    let mut issued = HashSet::new();
    let installation_id = random_unique(&mut issued)?;
    let active_state_manifest_digest = random_unique(&mut issued)?;
    let protocol_abi_digest = random_unique(&mut issued)?;
    let release_identity_digest = random_unique(&mut issued)?;
    let model_set_identity_digest = random_unique(&mut issued)?;
    let resource_profile_identity_digest = random_unique(&mut issued)?;
    let approval_lock_identity_digest = random_unique(&mut issued)?;
    let planner_lock_identity_digest = random_unique(&mut issued)?;
    let executor_key_lock_identity_digest = random_unique(&mut issued)?;
    let ledger_projection_identity = random_unique(&mut issued)?;
    let effect_ledger_head_digest = random_unique(&mut issued)?;
    let selected_record_digest = random_unique(&mut issued)?;
    let projection_predecessor_digest = [0_u8; 32];
    let deployment_generation = 1_u64;
    let effect_fence_epoch = 1_u64;

    let projection_key = signing_key(&mut issued)?;
    let projection_key_id = derive_ed25519_key_id_v2(projection_key.verifying_key().to_bytes());
    let effect_projection = signed_effect_projection(
        installation_id,
        active_state_manifest_digest,
        deployment_generation,
        effect_fence_epoch,
        ledger_projection_identity,
        effect_ledger_head_digest,
        selected_record_digest,
        projection_predecessor_digest,
        &projection_key,
        projection_key_id,
    )?;
    write_new(
        &output.join("artifacts/effect-ledger-projection-v2.cbor"),
        &effect_projection,
        0o644,
    )?;

    let input_key = signing_key(&mut issued)?;
    let input_key_id = derive_ed25519_key_id_v2(input_key.verifying_key().to_bytes());
    let input_assets = signed_input_assets(&input_key, input_key_id)?;
    write_new(
        &output.join("artifacts/input-runtime-assets-v2.cbor"),
        &input_assets,
        0o644,
    )?;

    let executor_identity = random_unique(&mut issued)?;
    let connector_set_digest = random_unique(&mut issued)?;
    let destination_projection_digest = random_unique(&mut issued)?;
    let display_projection_digest = random_unique(&mut issued)?;
    let registry_key = signing_key(&mut issued)?;
    let registry_key_id = derive_ed25519_key_id_v2(registry_key.verifying_key().to_bytes());
    let (tool_descriptor, tool_descriptor_digest) = signed_tool_descriptor(
        &registry_key,
        registry_key_id,
        executor_identity,
        destination_projection_digest,
        display_projection_digest,
    )?;
    write_new(
        &output.join("artifacts").join(TOOL_ARTIFACT_LEAF),
        &tool_descriptor,
        0o644,
    )?;

    let declassification_product_family = random_unique(&mut issued)?;
    let declassification_installer_key = signing_key(&mut issued)?;
    let declassification_authority_key = signing_key(&mut issued)?;
    let declassification_member = OperationalTrustRootSetItemV2::new(
        OperationalTrustRootPurposeV2::DeclassificationAuthority,
        declassification_authority_key.verifying_key().to_bytes(),
        1,
        ACTIVE_NOT_BEFORE,
        ACTIVE_EXPIRES_AT,
    )
    .map_err(|_| "could not create development declassification authority".to_owned())?;
    let declassification_roots = OperationalTrustRootSetV2::new_declassification_signed_for_test(
        Digest32V2::new(declassification_product_family),
        1,
        None,
        vec![declassification_member],
        ACTIVE_NOT_BEFORE,
        ACTIVE_EXPIRES_AT,
        &declassification_installer_key,
        1,
    )
    .map_err(|_| "could not sign development declassification trust root".to_owned())?;
    let destination_reader = final_release_destination_digest(executor_identity);
    let declassification_rules = development_declassification_rules(
        Digest32V2::new(executor_identity),
        Digest32V2::new(destination_reader),
    )?;
    let declassification_rule_set = DeclassificationRuleSetV2::new_signed_for_test(
        Digest32V2::new(declassification_product_family),
        1,
        None,
        declassification_rules,
        ACTIVE_NOT_BEFORE,
        ACTIVE_EXPIRES_AT,
        &declassification_roots,
        &declassification_authority_key,
        1,
        ACTIVE_NOT_BEFORE,
    )
    .map_err(|_| "could not sign development declassification rules".to_owned())?;
    let installer_key_id =
        derive_ed25519_key_id_v2(declassification_installer_key.verifying_key().to_bytes());
    write_json(
        &output.join("artifacts/declassification-installer-root-v2.json"),
        &json!({
            "key_id": hex(*installer_key_id.as_bytes()),
            "key_epoch": 1,
            "public_key": hex(declassification_installer_key.verifying_key().to_bytes())
        }),
    )?;
    write_new(
        &output.join("artifacts/declassification-trust-root-set-v2.cbor"),
        declassification_roots.canonical_bytes(),
        0o644,
    )?;
    write_new(
        &output.join("artifacts/declassification-rule-set-v2.cbor"),
        declassification_rule_set.canonical_bytes(),
        0o644,
    )?;

    let services = ServiceIdentities::new(&mut issued)?;
    let manifest_template = manifest_template(
        &mut issued,
        installation_id,
        active_state_manifest_digest,
        *declassification_rule_set.signed_digest().as_bytes(),
        protocol_abi_digest,
        release_identity_digest,
        model_set_identity_digest,
        resource_profile_identity_digest,
        approval_lock_identity_digest,
        planner_lock_identity_digest,
        executor_key_lock_identity_digest,
        ledger_projection_identity,
        effect_ledger_head_digest,
        projection_key_id,
        projection_key.verifying_key().to_bytes(),
        deployment_generation,
        effect_fence_epoch,
        &services,
    )?;
    write_json(
        &output.join("config/development-manifest-template-v2.json"),
        &manifest_template,
    )?;

    let parser_code_digest = random_unique(&mut issued)?;
    let parser_output_limits_digest = parser_output_limits_digest();
    let policy_activation_digest = random_unique(&mut issued)?;
    let quota_policy_digest = random_unique(&mut issued)?;
    let vault_store_id = random_unique(&mut issued)?;
    let agent_authority_store_id = random_unique(&mut issued)?;
    let g4_store_id = random_unique(&mut issued)?;
    let jarvis_control_identity = random_unique(&mut issued)?;
    let jarvis_principal = random_unique(&mut issued)?;
    let jarvis_peer_class = random_unique(&mut issued)?;
    let agent_task_store_id = random_unique(&mut issued)?;
    let planner_catalog_store_id = random_unique(&mut issued)?;
    let approval_store_id = random_unique(&mut issued)?;
    let exec_store_id = random_unique(&mut issued)?;
    let exec_connector_store_id = random_unique(&mut issued)?;
    let placeholder = random_unique(&mut issued)?;
    let placeholder_hex = hex(placeholder);
    let planner_server_spki_placeholder = hex(random_unique(&mut issued)?);
    let mapper_server_spki_placeholder = hex(random_unique(&mut issued)?);
    let disabled_connector_authority = "00".repeat(32);

    let installed_tool_path = format!("{INSTALL_ROOT}/config/policy/{TOOL_ARTIFACT_LEAF}");
    let policy_runtime = json!({
        "registry_version": [2, 0, 0],
        "registry_publisher_key_id": hex(*registry_key_id.as_bytes()),
        "registry_publisher_public_key": hex(registry_key.verifying_key().to_bytes()),
        "registry_not_before": ACTIVE_NOT_BEFORE,
        "registry_expires_at": ACTIVE_EXPIRES_AT,
        "signed_tool_descriptor_paths": [installed_tool_path],
        "policy_activations": [{
            "descriptor_digest": hex(*tool_descriptor_digest.as_bytes()),
            "registry_ordinal": 0,
            "policy_activation_digest": hex(policy_activation_digest)
        }],
        "manifest_constraints": [{
            "descriptor_digest": hex(*tool_descriptor_digest.as_bytes()),
            "maximum_attempts": 3,
            "maximum_elapsed_ns": 5_000_000_000_u64,
            "internal_validators": []
        }],
        "validator_builds": [],
        "role_id": ROLE_ID,
        "disposition": "require_approval",
        "tool_settlement_key_id": placeholder_hex,
        "tool_settlement_public_key": placeholder_hex,
        "quota_limit": 128,
        "quota_policy_digest": hex(quota_policy_digest),
        "execd_boot_id": placeholder_hex,
        "executor_identity": hex(executor_identity),
        "executor_seal_key_id": placeholder_hex,
        "executor_seal_public_key": placeholder_hex,
        "executor_connector_registry_digest": hex(connector_set_digest),
        "connector_registry_genesis_digest": hex(connector_set_digest),
        "connector_authority_key_id": disabled_connector_authority,
        "connector_authority_public_key": disabled_connector_authority,
        "user_tier_host_allowlist": [],
        "executor_receipt_key_id": placeholder_hex,
        "executor_receipt_public_key": placeholder_hex
    });
    let parser_trust = json!({
        "descriptor_key_id": placeholder_hex,
        "descriptor_public_key": placeholder_hex,
        "worker_artifact_digest": placeholder_hex,
        "implementation_id": 1,
        "semantic_version": [1, 0, 0],
        "parser_code_digest": hex(parser_code_digest),
        "renderer_code_digest": Value::Null,
        "ocr_model_set_digest": Value::Null,
        "normalization_version": [1, 0, 0],
        "output_limits_digest": hex(parser_output_limits_digest),
        "extension_class": 1,
        "maximum_pages": PARSER_MAXIMUM_PAGES,
        "maximum_output_bytes": PARSER_OUTPUT_LIMIT_BYTES
    });
    let kerneld = json!({
        "signed_manifest_path": format!("{INSTALL_ROOT}/config/deployment-manifest-v2.cbor"),
        "effect_ledger_projection_path": format!("{INSTALL_ROOT}/config/effect-ledger-projection-v2.cbor"),
        "declassification_installer_root_path": format!("{INSTALL_ROOT}/config/trust/declassification-installer-root-v2.json"),
        "declassification_trust_root_set_path": format!("{INSTALL_ROOT}/config/trust/declassification-trust-root-set-v2.cbor"),
        "declassification_rule_set_path": format!("{INSTALL_ROOT}/config/policy/declassification-rule-set-v2.cbor"),
        "input_runtime_assets_path": format!("{INSTALL_ROOT}/config/input-runtime-assets-v2.cbor"),
        "input_runtime_publisher_key_id": hex(*input_key_id.as_bytes()),
        "input_runtime_publisher_public_key": hex(input_key.verifying_key().to_bytes()),
        "ui_settlement_key_id": placeholder_hex,
        "ui_settlement_public_key": placeholder_hex,
        "ingress_settlement_key_id": placeholder_hex,
        "ingress_settlement_public_key": placeholder_hex,
        "task_authorization_key_id": placeholder_hex,
        "task_authorization_public_key": placeholder_hex,
        "agentd_boot_id": placeholder_hex,
        "approvald_boot_id": placeholder_hex,
        "machine_boot_id": placeholder_hex,
        "agentd_peer_identity_digest": hex(services.agentd.service_identity),
        "vault_state_path": format!("{INSTALL_ROOT}/state/kerneld/vault-state-v2.cbor"),
        "vault_rollback_anchor_path": format!("{INSTALL_ROOT}/state/kerneld/vault-anchor-v2.cbor"),
        "vault_store_id": hex(vault_store_id),
        "agent_authority_state_path": format!("{INSTALL_ROOT}/state/kerneld/kernel-agent-authority-state-v2.cbor"),
        "agent_authority_rollback_anchor_path": format!("{INSTALL_ROOT}/state/kerneld/agent-authority-anchor-v2.cbor"),
        "agent_authority_store_id": hex(agent_authority_store_id),
        "g4_state_path": format!("{INSTALL_ROOT}/state/kerneld/kernel-g4-state-v2.cbor"),
        "g4_rollback_anchor_path": format!("{INSTALL_ROOT}/state/kerneld/g4-anchor-v2.cbor"),
        "g4_store_id": hex(g4_store_id),
        "policy_allowed_effect_bits": EffectSetV2::ALL.bits(),
        "logical_run_ttl_ms": 300_000,
        "policy_runtime": policy_runtime,
        "parser_trust": parser_trust,
        "services": []
    });
    write_json(&output.join("config/kerneld-bootstrap-v2.json"), &kerneld)?;

    let agentd = json!({
        "signed_manifest_path": format!("{INSTALL_ROOT}/config/deployment-manifest-v2.cbor"),
        "effect_ledger_projection_path": format!("{INSTALL_ROOT}/config/effect-ledger-projection-v2.cbor"),
        "effect_gate_path": format!("{INSTALL_ROOT}/config/effect-gate-v2"),
        "services": [],
        "task_state_path": format!("{INSTALL_ROOT}/state/agentd/agent-task-state-v2.cbor"),
        "rollback_anchor_path": format!("{INSTALL_ROOT}/state/agentd/task-anchor-v2.cbor"),
        "store_id": hex(agent_task_store_id),
        "planner_catalog_state_path": format!("{INSTALL_ROOT}/state/agentd/planner-catalog-state-v2.cbor"),
        "planner_catalog_rollback_anchor_path": format!("{INSTALL_ROOT}/state/agentd/planner-catalog-anchor-v2.cbor"),
        "planner_catalog_store_id": hex(planner_catalog_store_id),
        "planner_shipped_catalog": [{
            "tool_class": TOOL_CLASS,
            "action_template": ACTION_TEMPLATE,
            "structural_role": savana_policy_core::v2::ConnectorStructuralRoleV2::Sink.tag(),
            "effects": EffectSetV2::READ.bits(),
            "semantic_name": "development.draft_due_diligence_report",
            "semantic_description": "development shipped due diligence report drafting tool"
        }],
        "kernel_task_authority_key_id": placeholder_hex,
        "approval_client_key_id": placeholder_hex,
        "approval_server_key_id": placeholder_hex,
        "planner_host": "planner.savana-development.invalid",
        "planner_port": 9443,
        "planner_connect_addresses": ["127.0.0.1:9443"],
        "planner_server_spki_sha256": planner_server_spki_placeholder,
        "intent_trust_deployment_ceiling": 1,
        "private_mapper_host": "mapper.savana-development.invalid",
        "private_mapper_port": 9445,
        "private_mapper_connect_addresses": ["127.0.0.1:9445"],
        "private_mapper_server_spki_sha256": mapper_server_spki_placeholder,
        "planner_route_id": PLANNER_ROUTE,
        "planner_template_id": 1,
        "planner_intent_tag": 3,
        "planner_maximum_steps": 256,
        "planner_maximum_dependencies_per_step": 256,
        "planner_maximum_arguments_per_step": 256,
        "planner_maximum_encoded_plan_bytes": 8 * 1024 * 1024,
        "release_executor_identity": hex(executor_identity),
        "release_destination_projection": DESTINATION_PROJECTION,
        "release_display_projection": DISPLAY_PROJECTION,
        "jarvis_control_identity": hex(jarvis_control_identity),
        "jarvis_principal": hex(jarvis_principal),
        "jarvis_os_peer_class": hex(jarvis_peer_class),
        "jarvis_expected_uid": 1,
        "jarvis_expected_gid": 1,
        "jarvis_executable_digest": placeholder_hex,
        "jarvis_code_identity_digest": placeholder_hex
    });
    write_json(&output.join("config/agentd-bootstrap-v2.json"), &agentd)?;

    let ingressd = json!({
        "signed_manifest_path": format!("{INSTALL_ROOT}/config/deployment-manifest-v2.cbor"),
        "effect_ledger_projection_path": format!("{INSTALL_ROOT}/config/effect-ledger-projection-v2.cbor"),
        "services": [],
        "approval_client_key_id": placeholder_hex,
        "approval_server_key_id": placeholder_hex,
        "parser": {
            "descriptor_key_id": placeholder_hex,
            "declared_media_type": 1,
            "detected_media_type": 1,
            "extension_class": 1,
            "implementation_id": 1,
            "semantic_version": [1, 0, 0],
            "parser_code_digest": hex(parser_code_digest),
            "renderer_code_digest": Value::Null,
            "ocr_model_set_digest": Value::Null,
            "normalization_version": [1, 0, 0],
            "worker_artifact_digest": placeholder_hex,
            "output_limit_bytes": PARSER_OUTPUT_LIMIT_BYTES,
            "maximum_pages": PARSER_MAXIMUM_PAGES,
            "output_limits_digest": hex(parser_output_limits_digest),
            "sandbox_program_path": format!("{INSTALL_ROOT}/sandbox/ingressd/savana-worker-sandbox"),
            "sandbox_program_digest": placeholder_hex,
            "worker_program_path": format!("{INSTALL_ROOT}/sandbox/ingressd/savana-parser-worker"),
            "sandbox_profile_path": format!("{INSTALL_ROOT}/sandbox/ingressd/parser-profile-v2.json"),
            "sandbox_profile_digest": placeholder_hex,
            "file_owner_uid": 1,
            "file_owner_gid": 1
        }
    });
    write_json(&output.join("config/ingressd-bootstrap-v2.json"), &ingressd)?;

    let approvald = json!({
        "signed_manifest_path": format!("{INSTALL_ROOT}/config/deployment-manifest-v2.cbor"),
        "effect_ledger_projection_path": format!("{INSTALL_ROOT}/config/effect-ledger-projection-v2.cbor"),
        "services": [],
        "state_path": format!("{INSTALL_ROOT}/state/approvald/approval-protocol-state-v2.cbor"),
        "rollback_anchor_path": format!("{INSTALL_ROOT}/state/approvald/approval-anchor-v2.cbor"),
        "store_id": hex(approval_store_id),
        "kernel_envelope_public_key_path": format!("{INSTALL_ROOT}/config/approvald/keys/kerneld-envelope-v2.pub"),
        "kernel_authority_envelope_key_id": placeholder_hex,
        "kernel_authority_envelope_public_key": placeholder_hex,
        "kernel_correlation_public_key_path": format!("{INSTALL_ROOT}/config/approvald/keys/kerneld-correlation-v2.pub"),
        "kernel_correlation_key_id": placeholder_hex,
        "settlement_key_id": placeholder_hex,
        "settlement_key_epoch": 1,
        "server_key_id": placeholder_hex,
        "agent_client_public_key_path": format!("{INSTALL_ROOT}/config/approvald/keys/agentd-approval-v2.pub"),
        "agent_client_key_id": placeholder_hex,
        "agent_listener_gid": 1,
        "ingress_client_public_key_path": format!("{INSTALL_ROOT}/config/approvald/keys/ingressd-approval-v2.pub"),
        "ingress_client_key_id": placeholder_hex,
        "ingress_listener_gid": 1,
        "admin_client_public_key_path": format!("{INSTALL_ROOT}/config/approvald/keys/admin-approval-v2.pub"),
        "admin_client_key_id": placeholder_hex,
        "admin_client_identity": hex(jarvis_control_identity),
        "admin_expected_uid": 1,
        "admin_expected_gid": 1,
        "admin_executable_digest": placeholder_hex,
        "admin_code_identity_digest": placeholder_hex,
        "enrollment_profiles": [
            {"profile": 1, "code_lifetime_ms": 120_000, "ceremony_lifetime_ms": 300_000}
        ],
        "attestation_roots": [],
        "hardware_credentials": []
    });
    write_json(
        &output.join("config/approvald-bootstrap-v2.json"),
        &approvald,
    )?;

    let execd = json!({
        "signed_manifest_path": format!("{INSTALL_ROOT}/config/deployment-manifest-v2.cbor"),
        "effect_ledger_projection_path": format!("{INSTALL_ROOT}/config/effect-ledger-projection-v2.cbor"),
        "services": [],
        "journal_path": format!("{INSTALL_ROOT}/state/execd/execd-journal-v2.cbor"),
        "rollback_anchor_path": format!("{INSTALL_ROOT}/state/execd/execution-anchor-v2.cbor"),
        "store_id": hex(exec_store_id),
        "effect_gate_path": format!("{INSTALL_ROOT}/config/effect-gate-v2"),
        "executor_identity": hex(executor_identity),
        "effect_receipt_key_id": placeholder_hex,
        "seal_key_id": placeholder_hex,
        "connector_set_digest": hex(connector_set_digest),
        "connector_registry_path": format!("{INSTALL_ROOT}/state/execd/connector-registry-v2.cbor"),
        "connector_registry_anchor_path": format!("{INSTALL_ROOT}/state/execd/connector-registry-anchor-v2.bin"),
        "connector_registry_store_id": hex(exec_connector_store_id),
        "connector_registry_genesis_digest": hex(connector_set_digest),
        "connector_authority_key_id": disabled_connector_authority,
        "connector_authority_public_key": disabled_connector_authority,
        "user_tier_host_allowlist": [],
        "journal_schema_version": 2,
        "journal_key_epoch": 1,
        "worker": {
            "sandbox_program_path": format!("{INSTALL_ROOT}/sandbox/execd/savana-worker-sandbox"),
            "sandbox_program_digest": placeholder_hex,
            "worker_program_path": format!("{INSTALL_ROOT}/sandbox/execd/savana-connector-worker"),
            "worker_artifact_digest": placeholder_hex,
            "no_network_profile_path": format!("{INSTALL_ROOT}/sandbox/execd/connector-no-network-profile-v2.json"),
            "no_network_profile_digest": placeholder_hex,
            "credential_absence_profile_path": format!("{INSTALL_ROOT}/sandbox/execd/connector-credential-absence-profile-v2.json"),
            "credential_absence_profile_digest": placeholder_hex
        },
        "provider_routing_mode": "split-final-release",
        "provider": {
            "address": "127.0.0.1:9444",
            "server_name": "provider.savana-development.invalid",
            "canonical_url": "https://provider.savana-development.invalid:9444/",
            "server_spki_sha256": placeholder_hex,
            "root_certificate_path": format!("{INSTALL_ROOT}/config/tls/runtime-root-v2.der"),
            "root_certificate_digest": placeholder_hex,
            "client_certificate_paths": [format!("{INSTALL_ROOT}/config/tls/provider-client-v2.der")],
            "client_certificate_digests": [placeholder_hex],
            "alpn_protocol_hex": "736176616e612d70726f76696465722d7632",
            "endpoint_binding_digest": placeholder_hex,
            "credential_handle_identity_digest": placeholder_hex
        },
        "final_release_provider": {
            "address": "127.0.0.1:43191",
            "server_name": "release.savana-development.invalid",
            "canonical_url": "https://release.savana-development.invalid:43191/savana/final-release",
            "server_spki_sha256": placeholder_hex,
            "root_certificate_path": format!("{INSTALL_ROOT}/config/tls/runtime-root-v2.der"),
            "root_certificate_digest": placeholder_hex,
            "client_certificate_paths": [format!("{INSTALL_ROOT}/config/tls/final-release-client-v2.der")],
            "client_certificate_digests": [placeholder_hex],
            "alpn_protocol_hex": "736176616e612d70726f76696465722d7632",
            "endpoint_binding_digest": placeholder_hex,
            "credential_handle_identity_digest": placeholder_hex
        }
    });
    write_json(&output.join("config/execd-bootstrap-v2.json"), &execd)?;

    let jarvis = json!({
        "protocol_major": 2,
        "protocol_minor": 0,
        "deployment_generation": deployment_generation,
        "active_state_manifest_digest": hex(active_state_manifest_digest),
        "caller_boot_id": placeholder_hex,
        "caller_identity": hex(jarvis_control_identity),
        "service_boot_id": placeholder_hex,
        "service_identity": hex(services.agentd.service_identity),
        "agentd_expected_uid": 1,
        "agentd_expected_gid": 1,
        "agentd_bundle_id": "com.savana.development.agentd",
        "agentd_team_id": "SAVANADEV1",
        "agentd_code_directory_measurement": placeholder_hex,
        "agentd_designated_requirement_measurement": placeholder_hex,
        "agentd_entitlement_measurement": placeholder_hex
    });
    write_json(&output.join("config/jarvis-python-v2.json"), &jarvis)?;

    write_sandbox_profiles(&output)?;
    write_entitlements(&output)?;
    write_new(
        &output.join("signing/deployment-manifest-v2.seed"),
        &random_unique(&mut issued)?,
        0o600,
    )?;
    println!("generated development build inputs: {}", output.display());
    Ok(())
}

#[derive(Clone, Copy)]
struct ServiceIdentity {
    service_identity: [u8; 32],
    keystore_authority_identity: [u8; 32],
    rollback_authority_identity: [u8; 32],
}

struct ServiceIdentities {
    kerneld: ServiceIdentity,
    agentd: ServiceIdentity,
    ingressd: ServiceIdentity,
    approvald: ServiceIdentity,
    execd: ServiceIdentity,
}

impl ServiceIdentities {
    fn new(issued: &mut HashSet<[u8; 32]>) -> Result<Self, String> {
        Ok(Self {
            kerneld: service_identity(issued)?,
            agentd: service_identity(issued)?,
            ingressd: service_identity(issued)?,
            approvald: service_identity(issued)?,
            execd: service_identity(issued)?,
        })
    }
}

fn service_identity(issued: &mut HashSet<[u8; 32]>) -> Result<ServiceIdentity, String> {
    Ok(ServiceIdentity {
        service_identity: random_unique(issued)?,
        keystore_authority_identity: random_unique(issued)?,
        rollback_authority_identity: random_unique(issued)?,
    })
}

#[allow(clippy::too_many_arguments)]
fn manifest_template(
    issued: &mut HashSet<[u8; 32]>,
    installation_id: [u8; 32],
    active_state_manifest_digest: [u8; 32],
    declassification_rule_set_digest: [u8; 32],
    protocol_abi_digest: [u8; 32],
    release_identity_digest: [u8; 32],
    model_set_identity_digest: [u8; 32],
    resource_profile_identity_digest: [u8; 32],
    approval_lock_identity_digest: [u8; 32],
    planner_lock_identity_digest: [u8; 32],
    executor_key_lock_identity_digest: [u8; 32],
    ledger_projection_identity: [u8; 32],
    effect_ledger_head_digest: [u8; 32],
    projection_key_id: Ed25519KeyIdV2,
    projection_public_key: [u8; 32],
    deployment_generation: u64,
    effect_fence_epoch: u64,
    services: &ServiceIdentities,
) -> Result<Value, String> {
    let placeholder = hex(random_unique(issued)?);
    Ok(json!({
        "installation_id": hex(installation_id),
        "active_state_manifest_digest": hex(active_state_manifest_digest),
        "declassification_rule_set_digest": hex(declassification_rule_set_digest),
        "active_state_manifest_sequence": 1,
        "deployment_generation": deployment_generation,
        "effect_fence_epoch": effect_fence_epoch,
        "protocol_abi_digest": hex(protocol_abi_digest),
        "release_identity_digest": hex(release_identity_digest),
        "model_set_identity_digest": hex(model_set_identity_digest),
        "resource_profile_identity_digest": hex(resource_profile_identity_digest),
        "approval_lock_identity_digest": hex(approval_lock_identity_digest),
        "planner_lock_identity_digest": hex(planner_lock_identity_digest),
        "executor_key_lock_identity_digest": hex(executor_key_lock_identity_digest),
        "kernel_envelope_signing_key_id": placeholder,
        "ledger_projection_identity": hex(ledger_projection_identity),
        "effect_ledger_head_digest": hex(effect_ledger_head_digest),
        "ledger_projection_signing_key_id": hex(*projection_key_id.as_bytes()),
        "ledger_projection_signing_public_key": hex(projection_public_key),
        "services": {
            "kerneld": service_template(services.kerneld),
            "agentd": service_template(services.agentd),
            "ingressd": service_template(services.ingressd),
            "approvald": service_template(services.approvald),
            "execd": service_template(services.execd)
        },
        "edges": {
            "agent_kernel": {
                "client_handshake_key_id": placeholder,
                "server_handshake_key_id": placeholder
            },
            "ingress_kernel": {
                "client_handshake_key_id": placeholder,
                "server_handshake_key_id": placeholder
            },
            "kernel_executor": {
                "client_handshake_key_id": placeholder,
                "server_handshake_key_id": placeholder
            }
        }
    }))
}

fn service_template(identity: ServiceIdentity) -> Value {
    json!({
        "service_identity": hex(identity.service_identity),
        "keystore_authority_identity": hex(identity.keystore_authority_identity),
        "rollback_authority_identity": hex(identity.rollback_authority_identity)
    })
}

#[allow(clippy::too_many_arguments)]
fn signed_effect_projection(
    installation_id: [u8; 32],
    active_state_manifest_digest: [u8; 32],
    deployment_generation: u64,
    effect_fence_epoch: u64,
    projection_identity: [u8; 32],
    authenticated_head_digest: [u8; 32],
    selected_record_digest: [u8; 32],
    predecessor_digest: [u8; 32],
    signing_key: &SigningKey,
    signing_key_id: Ed25519KeyIdV2,
) -> Result<Vec<u8>, String> {
    let mut payload = minicbor::Encoder::new(Vec::new());
    payload
        .array(11)
        .and_then(|encoder| encoder.u16(2))
        .and_then(|encoder| encoder.bytes(&installation_id))
        .and_then(|encoder| encoder.bytes(&active_state_manifest_digest))
        .and_then(|encoder| encoder.u64(deployment_generation))
        .and_then(|encoder| encoder.u64(effect_fence_epoch))
        .and_then(|encoder| encoder.bytes(&projection_identity))
        .and_then(|encoder| encoder.bytes(&authenticated_head_digest))
        .and_then(|encoder| encoder.bool(false))
        .and_then(|encoder| encoder.bool(true))
        .and_then(|encoder| encoder.bytes(&selected_record_digest))
        .and_then(|encoder| encoder.bytes(&predecessor_digest))
        .map_err(|_| "effect projection payload encoding failed".to_owned())?;
    let payload = payload.into_writer();
    let digest: [u8; 32] = Sha256::digest(&payload).into();
    let mut signature_input = Vec::from(EFFECT_PROJECTION_SIGNATURE_DOMAIN);
    signature_input.extend_from_slice(&digest);
    let signature = signing_key.sign(&signature_input).to_bytes();
    let mut signed = minicbor::Encoder::new(Vec::new());
    signed
        .array(3)
        .and_then(|encoder| encoder.bytes(&payload))
        .and_then(|encoder| encoder.bytes(signing_key_id.as_bytes()))
        .and_then(|encoder| encoder.bytes(&signature))
        .map_err(|_| "effect projection encoding failed".to_owned())?;
    Ok(signed.into_writer())
}

fn signed_input_assets(
    signing_key: &SigningKey,
    signing_key_id: Ed25519KeyIdV2,
) -> Result<Vec<u8>, String> {
    signed_input_assets_for_profile(signing_key, signing_key_id, false)
}

fn signed_input_assets_for_profile(
    signing_key: &SigningKey, signing_key_id: Ed25519KeyIdV2, protected: bool,
) -> Result<Vec<u8>, String> {
    let mut payload = minicbor::Encoder::new(Vec::new());
    payload
        .array(7)
        .and_then(|encoder| encoder.u16(2))
        .and_then(|encoder| encoder.u64(ACTIVE_NOT_BEFORE))
        .and_then(|encoder| encoder.u64(ACTIVE_EXPIRES_AT))
        .and_then(|encoder| encoder.u32(PLANNER_ROUTE))
        .and_then(|encoder| encoder.array(6))
        .and_then(|encoder| encoder.u32(1024 * 1024))
        .and_then(|encoder| encoder.u16(256))
        .and_then(|encoder| encoder.u16(64))
        .and_then(|encoder| encoder.u16(64))
        .and_then(|encoder| encoder.u16(64))
        .and_then(|encoder| encoder.u32(1024 * 1024))
        .and_then(|encoder| encoder.array(2))
        .and_then(|encoder| encoder.array(2))
        .and_then(|encoder| encoder.u32(1))
        .and_then(|encoder| encoder.str("ignore previous instructions"))
        .and_then(|encoder| encoder.array(2))
        .and_then(|encoder| encoder.u32(2))
        .and_then(|encoder| encoder.str("reveal system prompt"))
        .and_then(|encoder| encoder.array(1))
        .and_then(|encoder| encoder.array(6))
        .and_then(|encoder| encoder.u32(1))
        .and_then(|encoder| encoder.str(if protected { "\"inputs\":" } else { "summarize" }))
        .and_then(|encoder| encoder.u16(3))
        .and_then(|encoder| encoder.u32(1))
        .and_then(|encoder| encoder.array(if protected {3} else {1}))
        .and_then(|encoder| encoder.u32(ACTION_TEMPLATE))
        .map_err(|_| "input runtime asset encoding failed".to_owned())?;
    if protected { payload.u32(103).and_then(|e| e.u32(104)).map_err(|_| "template encoding")?; }
    payload.null().map_err(|_| "asset encoding")?;
    let payload = payload.into_writer();
    let digest = domain_digest(INPUT_ASSET_DIGEST_DOMAIN, &payload);
    let mut signature_input = Vec::from(INPUT_ASSET_SIGNATURE_DOMAIN);
    signature_input.extend_from_slice(&digest);
    let signature = signing_key.sign(&signature_input).to_bytes();
    let mut signed = minicbor::Encoder::new(Vec::new());
    signed
        .array(3)
        .and_then(|encoder| encoder.bytes(&payload))
        .and_then(|encoder| encoder.bytes(signing_key_id.as_bytes()))
        .and_then(|encoder| encoder.bytes(&signature))
        .map_err(|_| "signed input runtime asset encoding failed".to_owned())?;
    Ok(signed.into_writer())
}

fn signed_tool_descriptor(
    signing_key: &SigningKey,
    signing_key_id: Ed25519KeyIdV2,
    executor_identity: [u8; 32],
    destination_projection_digest: [u8; 32],
    display_projection_digest: [u8; 32],
) -> Result<(Vec<u8>, Digest32V2), String> {
    let contract = ExecutorIdempotencyContractV2::ConnectorIdempotentByExecutionNonce;
    let unsigned = UnsignedToolDescriptorV2::from_verified_manifest(
        2,
        VersionV2::new(2, 0, 0),
        Digest32V2::new(domain_digest(
            b"SAVANA_DEVELOPMENT_PROVIDER_IDENTITY_V2\0",
            b"python-provider",
        )),
        IdentifierV2::new("development.draft_due_diligence_report")
            .map_err(|_| "tool identifier is invalid".to_owned())?,
        ActionTemplateIdV2::new(ACTION_TEMPLATE),
        ToolClassIdV2::new(TOOL_CLASS),
        Digest32V2::new(domain_digest(
            b"SAVANA_DEVELOPMENT_ARGUMENT_SCHEMA_V2\0",
            b"document-text-v1",
        )),
        Digest32V2::new(domain_digest(
            b"SAVANA_DEVELOPMENT_RESULT_SCHEMA_V2\0",
            b"due-diligence-report-v1",
        )),
        vec![RoleIdV2::new(ROLE_ID)],
        EffectSetV2::READ,
        AttemptKindV2::ToolRead,
        BoundedConnectorRetryPolicyV2::new(contract, 3, 5_000_000_000)
            .map_err(|_| "tool retry policy is invalid".to_owned())?,
        Vec::new(),
        ExecutorIdentityV2::new(executor_identity),
        ProjectionIdV2::new(DESTINATION_PROJECTION),
        Digest32V2::new(destination_projection_digest),
        DisplayProjectionIdV2::new(DISPLAY_PROJECTION),
        Digest32V2::new(display_projection_digest),
        contract,
        UnixMillisV2::new(ACTIVE_NOT_BEFORE),
        UnixMillisV2::new(ACTIVE_EXPIRES_AT),
    )
    .map_err(|_| "tool descriptor is invalid".to_owned())?;
    let payload =
        minicbor::to_vec(&unsigned).map_err(|_| "tool descriptor encoding failed".to_owned())?;
    let digest =
        descriptor_digest_v2(&unsigned).map_err(|_| "tool descriptor digest failed".to_owned())?;
    let mut signature_input = Vec::from(TOOL_DESCRIPTOR_SIGNATURE_DOMAIN);
    signature_input.extend_from_slice(digest.as_bytes());
    let signature = signing_key.sign(&signature_input).to_bytes();
    let mut signed = minicbor::Encoder::new(Vec::new());
    signed
        .array(3)
        .and_then(|encoder| encoder.bytes(&payload))
        .and_then(|encoder| encoder.bytes(signing_key_id.as_bytes()))
        .and_then(|encoder| encoder.bytes(&signature))
        .map_err(|_| "signed tool descriptor encoding failed".to_owned())?;
    Ok((signed.into_writer(), digest))
}

fn parser_output_limits_digest() -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(PARSER_OUTPUT_LIMITS_DOMAIN);
    hasher.update(PARSER_OUTPUT_LIMIT_BYTES.to_be_bytes());
    hasher.update(PARSER_MAXIMUM_PAGES.to_be_bytes());
    hasher.finalize().into()
}

fn write_sandbox_profiles(root: &Path) -> Result<(), String> {
    write_json(
        &root.join("sandbox/parser-profile-v2.json"),
        &json!({
            "version": 2,
            "worker_program": format!("{INSTALL_ROOT}/sandbox/ingressd/savana-parser-worker"),
            "read_only_paths": [],
            "memory_limit_bytes": 268_435_456_u64,
            "cpu_time_seconds": 30,
            "output_file_limit_bytes": 0,
            "open_file_limit": 8,
            "process_limit": 1,
            "deny_all_network": true
        }),
    )?;
    write_json(
        &root.join("sandbox/connector-no-network-profile-v2.json"),
        &json!({"version": 2, "deny_all_network": true}),
    )?;
    write_json(
        &root.join("sandbox/connector-credential-absence-profile-v2.json"),
        &json!({
            "version": 2,
            "worker_program": format!("{INSTALL_ROOT}/sandbox/execd/savana-connector-worker"),
            "read_only_paths": [],
            "memory_limit_bytes": 268_435_456_u64,
            "cpu_time_seconds": 30,
            "output_file_limit_bytes": 0,
            "open_file_limit": 8,
            "process_limit": 1
        }),
    )
}

fn write_entitlements(root: &Path) -> Result<(), String> {
    const EMPTY_ENTITLEMENTS: &[u8] =
        b"<?xml version=\"1.0\" encoding=\"UTF-8\"?><plist version=\"1.0\"><dict/></plist>";
    const PYTHON_ENTITLEMENTS: &[u8] = b"<?xml version=\"1.0\" encoding=\"UTF-8\"?><plist version=\"1.0\"><dict><key>com.apple.security.cs.disable-library-validation</key><true/></dict></plist>";
    for service in [
        "kerneld",
        "agentd",
        "ingressd",
        "approvald",
        "execd",
        "jarvis-python",
    ] {
        let entitlements = if service == "jarvis-python" {
            PYTHON_ENTITLEMENTS
        } else {
            EMPTY_ENTITLEMENTS
        };
        write_new(
            &root.join(format!(
                "entitlements/com.savana.development.{service}.plist"
            )),
            entitlements,
            0o644,
        )?;
    }
    Ok(())
}

fn require_empty_directory(path: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| format!("output directory is unavailable: {}", path.display()))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(format!(
            "output directory is not a real directory: {}",
            path.display()
        ));
    }
    if fs::read_dir(path)
        .map_err(|_| format!("output directory cannot be read: {}", path.display()))?
        .next()
        .is_some()
    {
        return Err(format!("output directory is not empty: {}", path.display()));
    }
    Ok(())
}

fn create_directory(path: &Path) -> Result<(), String> {
    fs::create_dir(path).map_err(|_| format!("could not create {}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|_| format!("could not protect {}", path.display()))
}

fn write_json(path: &Path, value: &Value) -> Result<(), String> {
    let bytes =
        serde_json::to_vec(value).map_err(|_| format!("could not serialize {}", path.display()))?;
    write_new(path, &bytes, 0o644)
}

fn write_new(path: &Path, bytes: &[u8], mode: u32) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
        .map_err(|_| format!("could not create {}", path.display()))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| format!("could not write {}", path.display()))
}

fn signing_key(issued: &mut HashSet<[u8; 32]>) -> Result<SigningKey, String> {
    Ok(SigningKey::from_bytes(&random_unique(issued)?))
}

fn development_declassification_rules(
    executor_reader: Digest32V2,
    destination_reader: Digest32V2,
) -> Result<Vec<DeclassificationRuleV2>, String> {
    let specs = [
        (
            1,
            ClosedDeclassificationPurposeV2::AgentIngressMasking,
            LeakGateDutyV2::BlocklistAndNoResidualPii,
            None,
            None,
        ),
        (
            2,
            ClosedDeclassificationPurposeV2::PlannerCall,
            LeakGateDutyV2::BlocklistAndNoResidualPii,
            None,
            None,
        ),
        (
            3,
            ClosedDeclassificationPurposeV2::ApprovalDisplay,
            LeakGateDutyV2::BlocklistOnly,
            None,
            None,
        ),
        (
            4,
            ClosedDeclassificationPurposeV2::ExecutionHandoff,
            LeakGateDutyV2::BlocklistOnly,
            Some(vec![executor_reader]),
            None,
        ),
        (
            5,
            ClosedDeclassificationPurposeV2::FinalRelease,
            LeakGateDutyV2::BlocklistOnly,
            Some(vec![destination_reader]),
            Some(300_000),
        ),
    ];
    specs
        .into_iter()
        .map(|(tag, purpose, duty, readers, consent_age)| {
            DeclassificationRuleV2::new_for_test(
                tag,
                purpose,
                declassification_implementation_digest_v2(tag)
                    .ok_or_else(|| "unknown declassification transition".to_owned())?,
                duty,
                readers,
                consent_age,
                ACTIVE_NOT_BEFORE,
                ACTIVE_EXPIRES_AT,
            )
            .map_err(|_| "could not create development declassification rule".to_owned())
        })
        .collect()
}

fn final_release_destination_digest(executor_identity: [u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"SAVANA_FINAL_RELEASE_DESTINATION_V2\0");
    hasher.update(DESTINATION_PROJECTION.to_be_bytes());
    hasher.update(executor_identity);
    hasher.finalize().into()
}

fn random_unique(issued: &mut HashSet<[u8; 32]>) -> Result<[u8; 32], String> {
    for _ in 0..16 {
        let mut value = [0_u8; 32];
        getrandom::getrandom(&mut value)
            .map_err(|_| "operating-system entropy is unavailable".to_owned())?;
        if value != [0; 32] && issued.insert(value) {
            return Ok(value);
        }
    }
    Err("operating-system entropy repeated unexpectedly".to_owned())
}

fn domain_digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(bytes);
    hasher.finalize().into()
}

fn hex(bytes: [u8; 32]) -> String {
    use std::fmt::Write as _;

    let mut output = String::with_capacity(64);
    for byte in bytes {
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}
