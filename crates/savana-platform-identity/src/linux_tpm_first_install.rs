//! Root-only fixed-path first install. Secrets arrive through encrypted systemd
//! credentials, not argv/environment/stdin. No reset/clear/migration/retry path.
use crate::linux_tpm::Device;
use crate::linux_tpm_journal::{check_file, root_dir, DiskJournal};
use crate::tpm_enrollment_tool::fixed;
use crate::tpm_first_install::{self, TpmFirstInstallSpecV3, GUARD_INDEX};
use crate::{TpmClientIdentityV3, TpmEnrollmentV3, TpmPcrPolicyV3, TpmSignatureErrorV3 as Error};
use rustix::fs::{openat, Mode, OFlags};
use serde::Deserialize;
use std::fs::File;
use std::io::{Read, Write};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Identity {
    uid: u32,
    gid: u32,
    executable_sha256: String,
}
impl Identity {
    fn build(self) -> Result<TpmClientIdentityV3, Error> {
        TpmClientIdentityV3::new(self.uid, self.gid, fixed(&self.executable_sha256)?)
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: u8,
    installation_id: String,
    store_ids: [String; 5],
    pcr_mask: u8,
    pcr_digest: String,
    deployer: Identity,
    kernel: Identity,
    broker: Identity,
    not_before: u64,
    expires: u64,
}
impl Plan {
    fn build(self, now: u64) -> Result<TpmFirstInstallSpecV3, Error> {
        if self.schema != 3 || now < self.not_before || now >= self.expires {
            return Err(Error::BindingMismatch);
        }
        let mut ids = [[0; 32]; 5];
        for (to, from) in ids.iter_mut().zip(&self.store_ids) {
            *to = fixed(from)?;
        }
        Ok(TpmFirstInstallSpecV3 {
            installation: fixed(&self.installation_id)?,
            store_ids: ids,
            pcr_policy: TpmPcrPolicyV3::new(self.pcr_mask, fixed(&self.pcr_digest)?)?,
            deployer: self.deployer.build()?,
            kernel: self.kernel.build()?,
            broker: self.broker.build()?,
            not_before: self.not_before,
            expires: self.expires,
        })
    }
}
fn read(directory: &str, name: &str, limit: u64) -> Result<Zeroizing<Vec<u8>>, Error> {
    let dir = root_dir(directory)?;
    let file = File::from(
        openat(
            &dir,
            name,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|_| Error::Unavailable)?,
    );
    check_file(&file, limit)?;
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::Unavailable)?;
    if bytes.len() as u64 > limit {
        return Err(Error::Malformed);
    }
    Ok(bytes)
}
fn credentials(operation: &str) -> Result<Zeroizing<[[u8; 32]; 7]>, Error> {
    let directory = match operation {
        "prepare" => "/run/credentials/savana-tpm-first-install-v3.service",
        "activate" => "/run/credentials/savana-tpm-first-activate-v3.service",
        _ => return Err(Error::Malformed),
    };
    let mut values = Zeroizing::new([[0; 32]; 7]);
    for (i, name) in [
        "signing-auth",
        "enrollment-auth",
        "deployment-auth",
        "vault-auth",
        "agent-auth",
        "g4-auth",
        "connector-auth",
    ]
    .iter()
    .enumerate()
    {
        values[i] = read(directory, name, 32)?
            .as_slice()
            .try_into()
            .map_err(|_| Error::Malformed)?;
    }
    Ok(values)
}
fn now() -> Result<u64, Error> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|v| v.as_secs())
        .map_err(|_| Error::Unavailable)
}

/// Occupied output/hardware is a hard stop, including after an interrupted
/// attempt. The caller must not delete it or clear hardware to retry.
pub fn run_linux_tpm_first_install_v3(operation: &str) -> Result<(), Error> {
    if !nix::unistd::geteuid().is_root()
        || nix::unistd::getegid().as_raw() != 0
        || !matches!(operation, "prepare" | "activate")
    {
        return Err(Error::Unavailable);
    }
    let _lock = DiskJournal::open(GUARD_INDEX)?;
    let credentials = credentials(operation)?;
    match operation {
        "prepare" => {
            let plan = read("/etc/savana", "tpm-first-install-v3.json", 16 * 1024)?;
            let spec: Plan = serde_json::from_slice(&plan).map_err(|_| Error::Malformed)?;
            let spec = spec.build(now()?)?;
            for path in [
                "/etc/savana/tpm-enrollment-v3.bin",
                "/var/lib/savana/deployment",
                "/var/lib/savana/deployment-v3",
                "/var/lib/savana/kerneld",
                "/var/lib/savana/approvald",
                "/var/lib/savana/agentd",
                "/var/lib/savana/execd",
            ] {
                match std::fs::symlink_metadata(path) {
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
                    _ => return Err(Error::BindingMismatch),
                }
            }
            let dir = root_dir("/etc/savana")?;
            let mut file = File::from(
                openat(
                    &dir,
                    "tpm-first-install-proposal-v3.bin",
                    OFlags::WRONLY
                        | OFlags::CREATE
                        | OFlags::EXCL
                        | OFlags::CLOEXEC
                        | OFlags::NOFOLLOW,
                    Mode::RUSR | Mode::WUSR,
                )
                .map_err(|_| Error::Unavailable)?,
            );
            check_file(&file, 0)?;
            file.sync_all().map_err(|_| Error::OperationFailed)?;
            dir.sync_all().map_err(|_| Error::OperationFailed)?;
            let mut seeds = [[0; 32]; 5];
            for seed in &mut seeds {
                getrandom::getrandom(seed).map_err(|_| Error::Unavailable)?;
            }
            let proposal =
                tpm_first_install::prepare(&mut Device::open()?, spec, &credentials, &seeds)?;
            file.write_all(&proposal.canonical_bytes())
                .map_err(|_| Error::OperationFailed)?;
            file.sync_all().map_err(|_| Error::OperationFailed)?;
            dir.sync_all().map_err(|_| Error::OperationFailed)
        }
        "activate" => {
            let root = read("/etc/savana", "tpm-v3-installer.pub", 32)?;
            let bytes = read("/etc/savana", "tpm-enrollment-v3.bin", 2048)?;
            let enrollment = TpmEnrollmentV3::verify(
                &bytes,
                root.as_slice().try_into().map_err(|_| Error::Malformed)?,
                now()?,
            )?;
            let original = read("/etc/savana", "tpm-first-install-proposal-v3.bin", 1984)?;
            if enrollment.proposal.canonical_bytes() != *original {
                return Err(Error::BindingMismatch);
            }
            tpm_first_install::activate(Device::open()?, &enrollment, &credentials, now()?)
        }
        _ => Err(Error::Malformed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn plan() -> serde_json::Value {
        let identity = |uid, byte: u8| {
            serde_json::json!({"uid":uid,"gid":uid,
            "executable_sha256":format!("{byte:02x}").repeat(32)})
        };
        serde_json::json!({"schema":3,"installation_id":"01".repeat(32),
            "store_ids":["02".repeat(32),"03".repeat(32),"04".repeat(32),"05".repeat(32),"06".repeat(32)],
            "pcr_mask":129,"pcr_digest":"07".repeat(32),
            "deployer":identity(0,8),"kernel":identity(1001,9),"broker":identity(0,10),
            "not_before":100,"expires":200})
    }
    #[test]
    fn plan_is_strict_bounded_and_has_no_mutation_controls() {
        for now in [100, 199] {
            assert!(serde_json::from_value::<Plan>(plan())
                .unwrap()
                .build(now)
                .is_ok());
        }
        for now in [0, 99, 200, u64::MAX] {
            assert!(serde_json::from_value::<Plan>(plan())
                .unwrap()
                .build(now)
                .is_err());
        }
        for field in ["reset", "device", "epoch", "previous_root", "signing_key"] {
            let mut p = plan();
            p[field] = serde_json::json!(true);
            assert!(serde_json::from_value::<Plan>(p).is_err());
        }
        for field in ["installation_id", "pcr_digest"] {
            let mut p = plan();
            p[field] = serde_json::json!("AB".repeat(32));
            assert!(serde_json::from_value::<Plan>(p)
                .unwrap()
                .build(150)
                .is_err());
        }
        let mut p = plan();
        p["schema"] = serde_json::json!(2);
        assert!(serde_json::from_value::<Plan>(p)
            .unwrap()
            .build(150)
            .is_err());
        assert!(serde_json::from_str::<Plan>(r#"{"schema":3,"schema":3}"#).is_err());
    }
    #[test]
    fn privileged_units_are_manual_closed_and_use_the_runtime_credentials() {
        let prepare = include_str!("../../../deploy/systemd/savana-tpm-first-install-v3.service");
        let activate = include_str!("../../../deploy/systemd/savana-tpm-first-activate-v3.service");
        let runtime = include_str!("../../../deploy/systemd/savana-tpm-authority-v3.service");
        for (unit, verb) in [(prepare, "prepare"), (activate, "activate")] {
            for required in [
                "Type=oneshot",
                "User=root",
                "Group=root",
                "Restart=no",
                "ProtectSystem=strict",
                "DeviceAllow=/dev/tpmrm0 rw",
                "IPAddressDeny=any",
                "CapabilityBoundingSet=\n",
            ] {
                assert!(unit.contains(required));
            }
            assert!(unit.contains(&format!(
                "ExecStart=/usr/libexec/savana/savana-tpm-first-install {verb}"
            )));
            assert!(!unit.contains("[Install]"));
            assert!(!unit.contains("ExecStartPre="));
            assert!(!unit.contains("Environment="));
            let credentials: Vec<_> = unit
                .lines()
                .filter(|l| l.starts_with("LoadCredentialEncrypted="))
                .collect();
            assert_eq!(credentials.len(), 7);
            for credential in credentials {
                assert!(runtime.lines().any(|l| l == credential));
            }
        }
        assert!(!prepare.contains("ReadOnlyPaths=/etc/savana"));
        assert!(activate.contains("ReadOnlyPaths=/etc/savana"));
    }
}
