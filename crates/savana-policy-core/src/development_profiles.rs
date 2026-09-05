//! Closed, development-only deployment materialization. No runtime authority API.
//! Called before signing the new deployment; never migrates a running ledger.
use std::path::Path;

use ed25519_dalek::{Signer as _, SigningKey};
use savana_kernel_protocol::v2::{
    business_target_identity_v2, derive_ed25519_key_id_v2, final_release_business_profile_v2,
    ActionTemplateIdV2, Digest32V2, Ed25519KeyIdV2, ExecutorIdentityV2, RoleIdV2, ToolClassIdV2,
    UnixMillisV2, VersionV2,
};
use savana_policy_core::v2::{
    descriptor_digest_v2, AttemptKindV2, BoundedConnectorRetryPolicyV2, EffectSetV2,
    ExecutorIdempotencyContractV2, IdentifierV2, SignedToolDescriptorV2, UnsignedToolDescriptorV2,
    VerifiedRegistryPublisherV2,
};
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};

pub(crate) fn materialize(
    kernel: &Value,
    exec: &Value,
    legacy_bytes: &[u8],
    legacy_path: &Path,
    release_path: &Path,
    publisher_key: &SigningKey,
) -> Result<(Value, Vec<u8>, Vec<u8>), String> {
    let fail = || "reviewed development profile binding is invalid".to_owned();
    let policy = kernel.get("policy_runtime").ok_or_else(fail)?;
    let version = VersionV2::new(2, 0, 0);
    if policy.get("registry_version") != Some(&json!([2, 0, 0]))
        || policy.get("signed_tool_descriptor_paths") != Some(&json!([legacy_path]))
        || exec.get("provider_routing_mode") != Some(&json!("split-final-release"))
        || policy["policy_activations"].as_array().map(Vec::len) != Some(1)
        || policy["manifest_constraints"].as_array().map(Vec::len) != Some(1)
    {
        return Err(fail());
    }
    let start = number(policy, "registry_not_before")?;
    let end = number(policy, "registry_expires_at")?;
    let old_key_id = Ed25519KeyIdV2::new(digest(policy, "registry_publisher_key_id")?);
    let old_key = digest(policy, "registry_publisher_public_key")?;
    if derive_ed25519_key_id_v2(old_key) != old_key_id
        || publisher_key.verifying_key().to_bytes() == old_key
    {
        return Err(fail());
    }
    let old_publisher = VerifiedRegistryPublisherV2::from_verified_manifest(
        old_key_id,
        old_key,
        UnixMillisV2::new(start),
        UnixMillisV2::new(end),
    )
    .map_err(|_| fail())?;
    let legacy = SignedToolDescriptorV2::from_canonical_bytes(legacy_bytes)
        .and_then(|signed| signed.verify(&old_publisher, version, UnixMillisV2::new(start)))
        .map_err(|_| fail())?;
    if legacy.unsigned().provider_tool_id().as_str() != "development.draft_due_diligence_report"
        || legacy.unsigned().business_profile().is_some()
        || legacy.unsigned().action_template().get() != 102
        || legacy.unsigned().tool_class().get() != 202
        || policy["policy_activations"][0]["registry_ordinal"] != json!(0)
        || digest(&policy["policy_activations"][0], "descriptor_digest")?
            != *legacy.descriptor_digest().as_bytes()
        || digest(&policy["manifest_constraints"][0], "descriptor_digest")?
            != *legacy.descriptor_digest().as_bytes()
    {
        return Err(fail());
    }
    let transport = &exec["final_release_provider"];
    let url = transport["canonical_url"].as_str().ok_or_else(fail)?;
    // This reviewed codec is not a general-purpose web/MCP forwarding profile.
    if url != "https://release.savana-development.invalid:43191/savana/final-release"
        || transport["address"] != json!("127.0.0.1:43191")
        || transport["server_name"] != json!("release.savana-development.invalid")
        || transport["alpn_protocol_hex"] != json!(hex(b"savana-provider-v2"))
    {
        return Err(fail());
    }
    let target = business_target_identity_v2(
        url,
        Digest32V2::new(digest(transport, "server_spki_sha256")?),
    )
    .map_err(|_| fail())?;
    let credential = Digest32V2::new(digest(transport, "credential_handle_identity_digest")?);
    let profile = final_release_business_profile_v2(target, credential).map_err(|_| fail())?;
    let executor = ExecutorIdentityV2::new(digest(policy, "executor_identity")?);
    if executor != legacy.unsigned().executor_identity() {
        return Err(fail());
    }
    let role = u32::try_from(number(policy, "role_id")?).map_err(|_| fail())?;
    let retry = ExecutorIdempotencyContractV2::ConnectorNonIdempotentSingleAttempt;
    let release = UnsignedToolDescriptorV2::from_verified_manifest(
        2,
        version,
        target,
        IdentifierV2::new("development.final_release").map_err(|_| fail())?,
        ActionTemplateIdV2::new(103),
        ToolClassIdV2::new(203),
        profile.digest(),
        Digest32V2::new(Sha256::digest(b"SAVANA_FIXED_POST_CORRELATED_STATUS_V1\0").into()),
        vec![RoleIdV2::new(role)],
        EffectSetV2::FINAL_RELEASE,
        AttemptKindV2::ToolWrite,
        BoundedConnectorRetryPolicyV2::new(retry, 1, 0).map_err(|_| fail())?,
        vec![],
        executor,
        legacy.unsigned().destination_projection(),
        projection(
            b"SAVANA_KERNEL_DESTINATION_PROJECTION_V2\0",
            legacy.unsigned().destination_projection().get(),
        ),
        legacy.unsigned().display_projection(),
        projection(
            b"SAVANA_KERNEL_DISPLAY_PROJECTION_V2\0",
            legacy.unsigned().display_projection().get(),
        ),
        retry,
        UnixMillisV2::new(start),
        UnixMillisV2::new(end),
    )
    .and_then(|d| d.with_business_profile(profile))
    .map_err(|_| fail())?;
    let release_digest = descriptor_digest_v2(&release).map_err(|_| fail())?;
    let legacy_signed = sign(legacy.unsigned(), publisher_key)?;
    let release_signed = sign(&release, publisher_key)?;
    let mut updated = kernel.clone();
    let updated_policy = &mut updated["policy_runtime"];
    updated_policy["registry_publisher_key_id"] = json!(hex(derive_ed25519_key_id_v2(
        publisher_key.verifying_key().to_bytes()
    )
    .as_bytes()));
    updated_policy["registry_publisher_public_key"] =
        json!(hex(&publisher_key.verifying_key().to_bytes()));
    updated_policy["signed_tool_descriptor_paths"] = json!([legacy_path, release_path]);
    let activations = updated_policy["policy_activations"]
        .as_array_mut()
        .ok_or_else(fail)?;
    activations.push(json!({
        "descriptor_digest": hex(release_digest.as_bytes()), "registry_ordinal": 1,
        "policy_activation_digest": hex(&Sha256::digest([b"SAVANA_REVIEWED_RELEASE_ACTIVATION_V1\0".as_slice(), release_digest.as_bytes()].concat())),
    }));
    activations.sort_by(|a, b| {
        a["descriptor_digest"]
            .as_str()
            .cmp(&b["descriptor_digest"].as_str())
    });
    let constraints = updated_policy["manifest_constraints"]
        .as_array_mut()
        .ok_or_else(fail)?;
    constraints.push(json!({
        "descriptor_digest": hex(release_digest.as_bytes()), "maximum_attempts": 1,
        "maximum_elapsed_ns": 0, "internal_validators": [],
    }));
    constraints.sort_by(|a, b| {
        a["descriptor_digest"]
            .as_str()
            .cmp(&b["descriptor_digest"].as_str())
    });
    Ok((updated, legacy_signed, release_signed))
}

fn sign(unsigned: &UnsignedToolDescriptorV2, key: &SigningKey) -> Result<Vec<u8>, String> {
    let digest = descriptor_digest_v2(unsigned).map_err(|_| "profile digest failed")?;
    let payload = minicbor::to_vec(unsigned).map_err(|_| "profile encoding failed")?;
    let mut input = b"SAVANA_TOOL_DESCRIPTOR_SIGNATURE_V2\0".to_vec();
    input.extend_from_slice(digest.as_bytes());
    let mut e = minicbor::Encoder::new(Vec::new());
    e.array(3)
        .and_then(|e| e.bytes(&payload))
        .and_then(|e| e.bytes(derive_ed25519_key_id_v2(key.verifying_key().to_bytes()).as_bytes()))
        .and_then(|e| e.bytes(&key.sign(&input).to_bytes()))
        .map_err(|_| "profile signature encoding failed")?;
    Ok(e.into_writer())
}

fn projection(domain: &[u8], id: u32) -> Digest32V2 {
    let mut h = Sha256::new();
    h.update(domain);
    h.update(4u64.to_be_bytes());
    h.update(id.to_be_bytes());
    Digest32V2::new(h.finalize().into())
}
fn number(value: &Value, key: &str) -> Result<u64, String> {
    value[key]
        .as_u64()
        .ok_or_else(|| "profile number missing".into())
}
fn digest(value: &Value, key: &str) -> Result<[u8; 32], String> {
    let text = value[key].as_str().ok_or("profile digest missing")?;
    if text.len() != 64
        || !text
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err("profile digest is not canonical".into());
    }
    let mut out = [0; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&text[2 * i..2 * i + 2], 16)
            .map_err(|_| "invalid profile digest")?;
    }
    Ok(out)
}
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut text = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(&mut text, "{b:02x}").expect("string write");
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use savana_kernel_protocol::v2::{DisplayProjectionIdV2, ProjectionIdV2};
    use savana_policy_core::v2::{
        ActiveToolRegistryV2, VerifiedManifestToolConstraintSetV2,
        VerifiedManifestToolConstraintV2, VerifiedPolicyToolActivationV2, VerifiedPolicyToolSetV2,
        VerifiedToolRegistryV2,
    };

    fn inputs() -> (Value, Value, Vec<u8>) {
        let key = SigningKey::from_bytes(&[1; 32]);
        let retry = ExecutorIdempotencyContractV2::ConnectorIdempotentByExecutionNonce;
        let unsigned = UnsignedToolDescriptorV2::from_verified_manifest(
            2,
            VersionV2::new(2, 0, 0),
            Digest32V2::new([2; 32]),
            IdentifierV2::new("development.draft_due_diligence_report").unwrap(),
            ActionTemplateIdV2::new(102),
            ToolClassIdV2::new(202),
            Digest32V2::new([3; 32]),
            Digest32V2::new([4; 32]),
            vec![RoleIdV2::new(1)],
            EffectSetV2::READ,
            AttemptKindV2::ToolRead,
            BoundedConnectorRetryPolicyV2::new(retry, 3, 5_000_000_000).unwrap(),
            vec![],
            ExecutorIdentityV2::new([5; 32]),
            ProjectionIdV2::new(1),
            Digest32V2::new([6; 32]),
            DisplayProjectionIdV2::new(1),
            Digest32V2::new([7; 32]),
            retry,
            UnixMillisV2::new(1),
            UnixMillisV2::new(10_000),
        )
        .unwrap();
        let d = descriptor_digest_v2(&unsigned).unwrap();
        let kernel = json!({"policy_runtime": {
            "registry_version": [2,0,0],
            "registry_publisher_key_id": hex(derive_ed25519_key_id_v2(key.verifying_key().to_bytes()).as_bytes()),
            "registry_publisher_public_key": hex(&key.verifying_key().to_bytes()),
            "registry_not_before": 1, "registry_expires_at": 10000,
            "signed_tool_descriptor_paths": ["/fixture/legacy.cbor"],
            "executor_identity": hex(&[5;32]), "role_id": 1,
            "policy_activations": [{"descriptor_digest":hex(d.as_bytes()), "registry_ordinal":0, "policy_activation_digest":hex(&[8;32])}],
            "manifest_constraints": [{"descriptor_digest":hex(d.as_bytes()), "maximum_attempts":3, "maximum_elapsed_ns":5_000_000_000u64,"internal_validators":[]}],
        }});
        let exec = json!({"provider_routing_mode":"split-final-release", "final_release_provider":{
            "address":"127.0.0.1:43191", "server_name":"release.savana-development.invalid",
            "canonical_url":"https://release.savana-development.invalid:43191/savana/final-release",
            "alpn_protocol_hex":hex(b"savana-provider-v2"),
            "server_spki_sha256":hex(&[9;32]), "credential_handle_identity_digest":hex(&[10;32]),
        }});
        (kernel, exec, sign(&unsigned, &key).unwrap())
    }

    fn build(
        kernel: &Value,
        exec: &Value,
        bytes: &[u8],
    ) -> Result<(Value, Vec<u8>, Vec<u8>), String> {
        materialize(
            kernel,
            exec,
            bytes,
            Path::new("/fixture/legacy.cbor"),
            Path::new("/fixture/release.cbor"),
            &SigningKey::from_bytes(&[11; 32]),
        )
    }

    #[test]
    fn materialization_authenticates_old_descriptor_and_pins_exact_release_transport() {
        let (kernel, exec, bytes) = inputs();
        let (updated, legacy_bytes, release_bytes) = build(&kernel, &exec, &bytes).unwrap();
        let p = &updated["policy_runtime"];
        let publisher = VerifiedRegistryPublisherV2::from_verified_manifest(
            Ed25519KeyIdV2::new(digest(p, "registry_publisher_key_id").unwrap()),
            digest(p, "registry_publisher_public_key").unwrap(),
            UnixMillisV2::new(1),
            UnixMillisV2::new(10000),
        )
        .unwrap();
        let descriptors = [&legacy_bytes, &release_bytes]
            .into_iter()
            .map(|b| {
                SignedToolDescriptorV2::from_canonical_bytes(b)
                    .unwrap()
                    .verify(&publisher, VersionV2::new(2, 0, 0), UnixMillisV2::new(2))
                    .unwrap()
            })
            .collect::<Vec<_>>();
        assert!(descriptors[0]
            .unsigned()
            .require_business_profile()
            .is_err());
        let release = descriptors[1]
            .unsigned()
            .require_business_profile()
            .unwrap();
        assert_eq!(
            *release,
            final_release_business_profile_v2(
                business_target_identity_v2(
                    exec["final_release_provider"]["canonical_url"]
                        .as_str()
                        .unwrap(),
                    Digest32V2::new([9; 32])
                )
                .unwrap(),
                Digest32V2::new([10; 32]),
            )
            .unwrap()
        );
        assert_eq!(
            descriptors[1].unsigned().destination_projection_digest(),
            projection(b"SAVANA_KERNEL_DESTINATION_PROJECTION_V2\0", 1)
        );
        let registry =
            VerifiedToolRegistryV2::from_verified_descriptors(VersionV2::new(2, 0, 0), descriptors)
                .unwrap();
        let policy = VerifiedPolicyToolSetV2::from_verified_policy(
            p["policy_activations"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| {
                    VerifiedPolicyToolActivationV2::from_verified_policy(
                        Digest32V2::new(digest(v, "descriptor_digest").unwrap()),
                        v["registry_ordinal"].as_u64().unwrap() as u32,
                        Digest32V2::new(digest(v, "policy_activation_digest").unwrap()),
                    )
                })
                .collect(),
        )
        .unwrap();
        let constraints = VerifiedManifestToolConstraintSetV2::from_manifest(
            p["manifest_constraints"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| {
                    VerifiedManifestToolConstraintV2::from_manifest(
                        Digest32V2::new(digest(v, "descriptor_digest").unwrap()),
                        v["maximum_attempts"].as_u64().unwrap() as u16,
                        v["maximum_elapsed_ns"].as_u64().unwrap(),
                        vec![],
                    )
                    .unwrap()
                })
                .collect(),
        )
        .unwrap();
        let active = ActiveToolRegistryV2::intersect(&registry, &policy, &constraints).unwrap();
        assert_eq!(active.len(), 2);
        assert_eq!(
            active
                .resolve_class(
                    ToolClassIdV2::new(203),
                    RoleIdV2::new(1),
                    UnixMillisV2::new(2)
                )
                .unwrap()
                .descriptor()
                .unsigned()
                .effects(),
            EffectSetV2::FINAL_RELEASE
        );
        let mut changed_exec = exec.clone();
        changed_exec["final_release_provider"]["server_spki_sha256"] = json!(hex(&[12; 32]));
        assert_ne!(
            release_bytes,
            build(&kernel, &changed_exec, &bytes).unwrap().2
        );
        changed_exec = exec.clone();
        changed_exec["final_release_provider"]["credential_handle_identity_digest"] =
            json!(hex(&[13; 32]));
        assert_ne!(
            release_bytes,
            build(&kernel, &changed_exec, &bytes).unwrap().2
        );
    }

    #[test]
    fn materialization_refuses_unreviewed_inputs_without_mutating_them() {
        let (kernel, exec, mut bytes) = inputs();
        for (pointer, replacement) in [
            ("/provider_routing_mode", json!("legacy-shared")),
            (
                "/final_release_provider/canonical_url",
                json!("https://other.invalid/"),
            ),
            (
                "/final_release_provider/server_spki_sha256",
                json!(hex(&[0; 32])),
            ),
            (
                "/final_release_provider/credential_handle_identity_digest",
                json!(hex(&[0; 32])),
            ),
        ] {
            let mut changed = exec.clone();
            *changed.pointer_mut(pointer).unwrap() = replacement;
            assert!(build(&kernel, &changed, &bytes).is_err());
        }
        let mut changed = kernel.clone();
        changed["policy_runtime"]["policy_activations"][0]["descriptor_digest"] =
            json!(hex(&[14; 32]));
        assert!(build(&changed, &exec, &bytes).is_err());
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        assert!(build(&kernel, &exec, &bytes).is_err());
        assert_eq!(
            kernel["policy_runtime"]["signed_tool_descriptor_paths"],
            json!(["/fixture/legacy.cbor"])
        );
    }
}
