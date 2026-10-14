//! Model endpoints come exclusively from manifest-verified bootstrap config.
//! This is not an admin/model registration RPC and grants no disclosure rights.
use savana_agentd::{fused_model_recipient_v04, UnixMtlsFusedModelTransportV04};
use savana_kernel_protocol::{v2::Digest32V2, StableCode};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WorkerConfigV04 {
    host: String,
    socket: std::path::PathBuf,
    server_spki_sha256: [u8; 32],
    root_certificate_der: Vec<u8>,
    client_certificate_der: Vec<u8>,
    // Name in the service's protected credential directory, never a free path.
    private_key_credential: String,
}

pub(crate) struct LoadedWorkersV04 {
    pub(crate) fingerprint: [u8; 32],
    pub(crate) workers: Vec<UnixMtlsFusedModelTransportV04>,
}

pub(crate) fn load_workers(
    config: &[WorkerConfigV04],
    mut read_key: impl FnMut(&str) -> Result<Zeroizing<Vec<u8>>, StableCode>,
) -> Result<LoadedWorkersV04, StableCode> {
    let fail = StableCode::KernelUnavailable;
    if config.len() > 8 {
        return Err(fail);
    }
    let mut recipients = std::collections::BTreeSet::new();
    // Validate the whole list before reading any secret or constructing clients.
    for c in config {
        let identity = fused_model_recipient_v04(&c.host, Digest32V2::new(c.server_spki_sha256))
            .map_err(|_| fail)?;
        if !recipients.insert(identity)
            || c.root_certificate_der.is_empty()
            || c.root_certificate_der.len() > 16384
            || c.client_certificate_der.is_empty()
            || c.client_certificate_der.len() > 16384
            || !c.socket.is_absolute()
            || c.socket.as_os_str().len() > 100
            || c.socket.components().any(|v| {
                !matches!(
                    v,
                    std::path::Component::RootDir | std::path::Component::Normal(_)
                )
            })
            || !c.private_key_credential.starts_with("fused-model-")
            || c.private_key_credential.len() > 128
            || !c
                .private_key_credential
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        {
            return Err(fail);
        }
    }
    let mut hash = Sha256::new();
    hash.update(b"SAVANA_FUSED_WORKER_CONFIG_V04\0");
    hash.update(serde_json::to_vec(config).map_err(|_| fail)?);
    let fingerprint = hash.finalize().into();
    let workers = config
        .iter()
        .map(|c| {
            UnixMtlsFusedModelTransportV04::from_verified_deployment(
                c.host.clone(),
                c.socket.clone(),
                Digest32V2::new(c.server_spki_sha256),
                c.root_certificate_der.clone(),
                c.client_certificate_der.clone(),
                read_key(&c.private_key_credential)?,
            )
            .map_err(|_| fail)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(LoadedWorkersV04 {
        fingerprint,
        workers,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config() -> serde_json::Value {
        serde_json::json!({"host":"provider.example","socket":"/run/savana/model.sock",
        "server_spki_sha256":vec![1u8;32],"root_certificate_der":[1],"client_certificate_der":[1],
        "private_key_credential":"fused-model-client-key"})
    }
    #[test]
    fn fused_worker_config_empty_is_disabled_without_credentials() {
        let loaded = load_workers(&[], |_| panic!("must not read a credential")).unwrap();
        assert!(loaded.workers.is_empty());
        assert_ne!(loaded.fingerprint, [0; 32]);
    }
    fn fixture(name: &str) -> Vec<u8> {
        let prefix = format!("{name}=");
        let line = include_str!("../../savana-execd/tests/fixtures/provider-tls-v2.hex")
            .lines()
            .find_map(|line| line.strip_prefix(&prefix))
            .unwrap();
        (0..line.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&line[i..i + 2], 16).unwrap())
            .collect()
    }
    #[test]
    fn fused_worker_config_loads_pinned_client_without_opening_socket() {
        use savana_policy_core::v2::FusedModelTransportV04;
        let mut c = config();
        c["root_certificate_der"] = serde_json::json!(fixture("ca_cert"));
        c["client_certificate_der"] = serde_json::json!(fixture("client_cert"));
        let config: WorkerConfigV04 = serde_json::from_value(c.clone()).unwrap();
        let mut calls = 0;
        let loaded = load_workers(&[config], |name| {
            assert_eq!(name, "fused-model-client-key");
            calls += 1;
            Ok(Zeroizing::new(fixture("client_key")))
        })
        .unwrap();
        assert_eq!(calls, 1);
        assert_eq!(loaded.workers.len(), 1);
        assert_eq!(
            loaded.workers[0].recipient_identity(),
            fused_model_recipient_v04("provider.example", Digest32V2::new([1; 32])).unwrap()
        );
        let again = load_workers(&[serde_json::from_value(c.clone()).unwrap()], |_| {
            Ok(Zeroizing::new(fixture("client_key")))
        })
        .unwrap();
        assert_eq!(loaded.fingerprint, again.fingerprint);
        c["host"] = serde_json::json!("changed.example");
        let changed = load_workers(&[serde_json::from_value(c).unwrap()], |_| {
            Ok(Zeroizing::new(fixture("client_key")))
        })
        .unwrap();
        assert_ne!(loaded.fingerprint, changed.fingerprint);
    }
    #[test]
    fn fused_worker_config_missing_or_invalid_credentials_fail_closed() {
        let c: WorkerConfigV04 = serde_json::from_value(config()).unwrap();
        assert!(load_workers(&[c], |_| Err(StableCode::KernelUnavailable)).is_err());
        let c: WorkerConfigV04 = serde_json::from_value(config()).unwrap();
        assert!(load_workers(&[c], |_| Ok(Zeroizing::new(vec![1; 32]))).is_err());
    }
    #[test]
    fn fused_worker_config_rejects_ambiguity_and_paths_before_credentials() {
        for (field, value) in [
            ("host", serde_json::json!("Provider.example")),
            ("socket", serde_json::json!("../m.sock")),
            ("socket", serde_json::json!("/run/../tmp/m.sock")),
            ("private_key_credential", serde_json::json!("../key")),
            ("private_key_credential", serde_json::json!("kernel-root")),
        ] {
            let mut c = config();
            c[field] = value;
            let c: WorkerConfigV04 = serde_json::from_value(c).unwrap();
            assert!(load_workers(&[c], |_| panic!("invalid config must not read keys")).is_err());
        }
        let pair = vec![
            serde_json::from_value(config()).unwrap(),
            serde_json::from_value(config()).unwrap(),
        ];
        assert!(load_workers(&pair, |_| panic!("duplicate must not read keys")).is_err());
    }
}
