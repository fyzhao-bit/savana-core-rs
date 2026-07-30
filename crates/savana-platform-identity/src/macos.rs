pub(crate) mod ffi;

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
    let code_identity = ffi::copy_code_identity_v2(audit_token)?;
    NativePeerMeasurementV2::macos(
        audit_token,
        audit_identity.euid,
        audit_identity.egid,
        BoundedIdentityStringV2::new(code_identity.bundle_id)?,
        BoundedIdentityStringV2::new(code_identity.team_id)?,
        domain_hash(CODE_DIRECTORY_DOMAIN_V2, &code_identity.code_directory),
        domain_hash(
            DESIGNATED_REQUIREMENT_DOMAIN_V2,
            &code_identity.designated_requirement,
        ),
        domain_hash(ENTITLEMENT_DOMAIN_V2, &code_identity.entitlements),
    )
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
