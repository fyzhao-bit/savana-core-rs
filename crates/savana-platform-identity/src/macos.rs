pub(crate) mod ffi;

use std::fs::File;
use std::io::{Read as _, Seek as _, SeekFrom};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;

use sha2::{Digest as _, Sha256};

use crate::{BoundedIdentityStringV2, NativeIdentityErrorV2, NativePeerMeasurementV2};

const CODE_DIRECTORY_DOMAIN_V2: &[u8] = b"SAVANA_MACOS_CODE_DIRECTORY_MEASUREMENT_V2\0";
const DESIGNATED_REQUIREMENT_DOMAIN_V2: &[u8] =
    b"SAVANA_MACOS_DESIGNATED_REQUIREMENT_MEASUREMENT_V2\0";
const ENTITLEMENT_DOMAIN_V2: &[u8] = b"SAVANA_MACOS_ENTITLEMENT_MEASUREMENT_V2\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MacOsAuditIdentityV2 {
    pid: u32,
    euid: u32,
    egid: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacOsCodeIdentityMeasurementV2 {
    bundle_id: BoundedIdentityStringV2,
    team_id: BoundedIdentityStringV2,
    code_directory_measurement: [u8; 32],
    designated_requirement_measurement: [u8; 32],
    entitlement_measurement: [u8; 32],
}

impl MacOsCodeIdentityMeasurementV2 {
    pub fn bundle_id(&self) -> &BoundedIdentityStringV2 {
        &self.bundle_id
    }

    pub fn team_id(&self) -> &BoundedIdentityStringV2 {
        &self.team_id
    }

    pub const fn code_directory_measurement(&self) -> [u8; 32] {
        self.code_directory_measurement
    }

    pub const fn designated_requirement_measurement(&self) -> [u8; 32] {
        self.designated_requirement_measurement
    }

    pub const fn entitlement_measurement(&self) -> [u8; 32] {
        self.entitlement_measurement
    }
}

pub struct PinnedMacOsServiceV2 {
    measurement: NativePeerMeasurementV2,
    _executable: File,
}

impl PinnedMacOsServiceV2 {
    pub const fn measurement(&self) -> &NativePeerMeasurementV2 {
        &self.measurement
    }
}

impl std::fmt::Debug for PinnedMacOsServiceV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PinnedMacOsServiceV2(<redacted>)")
    }
}

impl MacOsAuditIdentityV2 {
    pub const fn pid(self) -> u32 {
        self.pid
    }

    pub const fn euid(self) -> u32 {
        self.euid
    }

    pub const fn egid(self) -> u32 {
        self.egid
    }
}

pub fn parse_macos_audit_token_v2(
    audit_token: [u8; 32],
) -> Result<MacOsAuditIdentityV2, NativeIdentityErrorV2> {
    if audit_token.iter().all(|byte| *byte == 0) {
        return Err(NativeIdentityErrorV2::InvalidMeasurement);
    }
    let word = |index: usize| {
        u32::from_ne_bytes(
            audit_token[index * 4..index * 4 + 4]
                .try_into()
                .expect("audit-token word bounds are constant"),
        )
    };
    let identity = MacOsAuditIdentityV2 {
        euid: word(1),
        egid: word(2),
        pid: word(5),
    };
    if identity.pid == 0 {
        return Err(NativeIdentityErrorV2::InvalidMeasurement);
    }
    Ok(identity)
}

pub fn current_process_audit_token_v2() -> Result<[u8; 32], NativeIdentityErrorV2> {
    ffi::current_process_audit_token_v2()
}

pub fn measure_macos_peer_v2(
    audit_token: [u8; 32],
) -> Result<NativePeerMeasurementV2, NativeIdentityErrorV2> {
    let audit_identity = parse_macos_audit_token_v2(audit_token)?;
    let code_identity = measurement_from_owned(ffi::copy_code_identity_v2(audit_token)?)?;
    NativePeerMeasurementV2::macos(
        audit_token,
        audit_identity.euid,
        audit_identity.egid,
        code_identity.bundle_id,
        code_identity.team_id,
        code_identity.code_directory_measurement,
        code_identity.designated_requirement_measurement,
        code_identity.entitlement_measurement,
    )
}

pub fn measure_macos_static_code_v2(
    path: &Path,
) -> Result<MacOsCodeIdentityMeasurementV2, NativeIdentityErrorV2> {
    measurement_from_owned(ffi::copy_static_code_identity_v2(
        path.as_os_str().as_bytes(),
    )?)
}

pub fn pin_current_macos_service_v2(
    expected_euid: u32,
    expected_egid: u32,
    expected_executable_measurement: [u8; 32],
    expected_code_directory_measurement: [u8; 32],
) -> Result<PinnedMacOsServiceV2, NativeIdentityErrorV2> {
    if expected_euid == 0
        || expected_egid == 0
        || expected_executable_measurement
            .iter()
            .all(|byte| *byte == 0)
        || expected_code_directory_measurement
            .iter()
            .all(|byte| *byte == 0)
    {
        return Err(NativeIdentityErrorV2::InvalidMeasurement);
    }

    let executable_path =
        std::env::current_exe().map_err(|_| NativeIdentityErrorV2::CodeIdentityUnavailable)?;
    let mut executable =
        File::open(executable_path).map_err(|_| NativeIdentityErrorV2::CodeIdentityUnavailable)?;
    let metadata = executable
        .metadata()
        .map_err(|_| NativeIdentityErrorV2::CodeIdentityUnavailable)?;
    let actual_euid = nix::unistd::geteuid().as_raw();
    let actual_egid = nix::unistd::getegid().as_raw();
    let trusted_owner = (metadata.uid() == 0 && metadata.gid() == 0)
        || (cfg!(debug_assertions)
            && metadata.uid() == actual_euid
            && metadata.gid() == actual_egid);
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || !trusted_owner
        || metadata.mode() & 0o022 != 0
        || metadata.mode() & 0o6000 != 0
        || metadata.mode() & 0o111 == 0
    {
        return Err(NativeIdentityErrorV2::InvalidMeasurement);
    }

    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = executable
            .read(&mut buffer)
            .map_err(|_| NativeIdentityErrorV2::Io)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    executable
        .seek(SeekFrom::Start(0))
        .map_err(|_| NativeIdentityErrorV2::Io)?;
    let executable_measurement: [u8; 32] = hasher.finalize().into();

    let measurement = measure_macos_peer_v2(current_process_audit_token_v2()?)?;
    match &measurement {
        NativePeerMeasurementV2::MacOs {
            euid,
            egid,
            code_directory_measurement,
            ..
        } if *euid == expected_euid
            && *egid == expected_egid
            && actual_euid == expected_euid
            && actual_egid == expected_egid
            && executable_measurement == expected_executable_measurement
            && *code_directory_measurement == expected_code_directory_measurement =>
        {
            Ok(PinnedMacOsServiceV2 {
                measurement,
                _executable: executable,
            })
        }
        _ => Err(NativeIdentityErrorV2::IdentityMismatch),
    }
}

fn measurement_from_owned(
    code_identity: ffi::OwnedMacOsCodeIdentityV2,
) -> Result<MacOsCodeIdentityMeasurementV2, NativeIdentityErrorV2> {
    Ok(MacOsCodeIdentityMeasurementV2 {
        bundle_id: BoundedIdentityStringV2::new(code_identity.bundle_id)?,
        team_id: BoundedIdentityStringV2::new(code_identity.team_id)?,
        code_directory_measurement: domain_hash(
            CODE_DIRECTORY_DOMAIN_V2,
            &code_identity.code_directory,
        ),
        designated_requirement_measurement: domain_hash(
            DESIGNATED_REQUIREMENT_DOMAIN_V2,
            &code_identity.designated_requirement,
        ),
        entitlement_measurement: domain_hash(ENTITLEMENT_DOMAIN_V2, &code_identity.entitlements),
    })
}

fn domain_hash(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(bytes);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::{
        domain_hash, parse_macos_audit_token_v2, CODE_DIRECTORY_DOMAIN_V2,
        DESIGNATED_REQUIREMENT_DOMAIN_V2, ENTITLEMENT_DOMAIN_V2,
    };

    #[test]
    fn audit_token_parser_uses_kernel_defined_words() {
        let mut token = [0_u8; 32];
        token[4..8].copy_from_slice(&501_u32.to_ne_bytes());
        token[8..12].copy_from_slice(&20_u32.to_ne_bytes());
        token[20..24].copy_from_slice(&42_u32.to_ne_bytes());
        let identity = parse_macos_audit_token_v2(token).unwrap();
        assert_eq!(identity.pid(), 42);
        assert_eq!(identity.euid(), 501);
        assert_eq!(identity.egid(), 20);
    }

    #[test]
    fn macos_measurements_are_domain_separated() {
        let bytes = b"same signed bytes";
        assert_ne!(
            domain_hash(CODE_DIRECTORY_DOMAIN_V2, bytes),
            domain_hash(DESIGNATED_REQUIREMENT_DOMAIN_V2, bytes)
        );
        assert_ne!(
            domain_hash(CODE_DIRECTORY_DOMAIN_V2, bytes),
            domain_hash(ENTITLEMENT_DOMAIN_V2, bytes)
        );
    }
}
