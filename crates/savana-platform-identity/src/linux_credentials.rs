//! Accept systemd's exact per-UID read-only ACL, or its ownership fallback only
//! on a read-only mount. Never relax credentials to arbitrary group/world read.
use crate::TpmSignatureErrorV3 as Error;
use rustix::fs::{fgetxattr, fstatvfs, openat, Mode, OFlags, StatVfsMountFlags};
use std::fs::File;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use zeroize::Zeroizing;

/// Closed unit names: callers cannot redirect credential lookup with an
/// environment variable, arbitrary pathname or attacker-selected unit string.
#[derive(Debug, Clone, Copy)]
pub enum LinuxCredentialServiceV2 {
    Kernel,
    Agent,
    Ingress,
    Approval,
    Executor,
    OwnerControl,
}
impl LinuxCredentialServiceV2 {
    const fn unit(self) -> &'static str {
        match self {
            Self::Kernel => "savana-kerneld.service",
            Self::Agent => "savana-agentd.service",
            Self::Ingress => "savana-ingressd.service",
            Self::Approval => "savana-approvald.service",
            Self::Executor => "savana-execd.service",
            Self::OwnerControl => "savana-ownerctl.service",
        }
    }
}
fn acl_matches(bytes: &[u8], uid: u32, permission: u16) -> bool {
    if bytes.len() != 44 || bytes[..4] != 2_u32.to_le_bytes() {
        return false;
    }
    let expected = [
        (1u16, permission, u32::MAX),
        (2, permission, uid),
        (4, 0, u32::MAX),
        (16, permission, u32::MAX),
        (32, 0, u32::MAX),
    ];
    bytes[4..]
        .chunks_exact(8)
        .zip(expected)
        .all(|(entry, (tag, perm, id))| {
            entry[..2] == tag.to_le_bytes()
                && entry[2..4] == perm.to_le_bytes()
                && entry[4..] == id.to_le_bytes()
        })
}
fn check(file: &File, directory: bool, maximum: u64) -> Result<(), Error> {
    let m = file.metadata().map_err(|_| Error::Unavailable)?;
    let uid = nix::unistd::geteuid().as_raw();
    let gid = nix::unistd::getegid().as_raw();
    if uid == 0
        || (directory && !m.is_dir())
        || (!directory && (!m.is_file() || m.nlink() != 1 || m.len() > maximum))
    {
        return Err(Error::Unavailable);
    }
    let perm: u16 = if directory { 5 } else { 4 };
    let mut acl = [0; 256];
    let attribute = match fgetxattr(file, "system.posix_acl_access", &mut acl[..]) {
        Ok(n) => Some(&acl[..n]),
        Err(rustix::io::Errno::NODATA | rustix::io::Errno::NOTSUP) => None,
        Err(_) => return Err(Error::Unavailable),
    };
    let mode = m.mode() & 0o7777;
    let acl_mode = (u32::from(perm) << 6) | (u32::from(perm) << 3);
    if m.uid() == 0
        && m.gid() == 0
        && mode == acl_mode
        && attribute.is_some_and(|a| acl_matches(a, uid, perm))
    {
        return Ok(());
    }
    if m.uid() == uid
        // systemd's ownership fallback may retain root's group even when the
        // service has a distinct primary group. With owner-only permissions,
        // no ACL and a read-only mount, that group grants no access.
        && (m.gid() == 0 || m.gid() == gid)
        && mode == u32::from(perm) << 6
        && attribute.is_none()
        && fstatvfs(file)
            .map_err(|_| Error::Unavailable)?
            .f_flag
            .contains(StatVfsMountFlags::RDONLY)
    {
        return Ok(());
    }
    Err(Error::Unavailable)
}
fn directory(service: LinuxCredentialServiceV2) -> Result<File, Error> {
    let parent = crate::linux_tpm_journal::root_dir("/run/credentials")?;
    let dir = File::from(
        openat(
            &parent,
            service.unit(),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|_| Error::Unavailable)?,
    );
    check(&dir, true, 0)?;
    Ok(dir)
}
pub fn validate_linux_kerneld_credential_directory_v3() -> Result<(), Error> {
    directory(LinuxCredentialServiceV2::Kernel).map(drop)
}
pub fn read_linux_kerneld_credential_v3(
    name: &str,
    maximum: usize,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    // Retain the V3 TPM credential interface's original narrower bound.
    if maximum > 2048 {
        return Err(Error::Malformed);
    }
    read_linux_service_credential_v2(LinuxCredentialServiceV2::Kernel, name, maximum)
}

/// Read a service-local systemd credential, preserving exact per-UID ACL or
/// read-only ownership-fallback checks. TLS blobs have a separate 128-KiB cap.
pub fn read_linux_service_credential_v2(
    service: LinuxCredentialServiceV2,
    name: &str,
    maximum: usize,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    if name.is_empty()
        || name.len() > 128
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
        || name == "."
        || name == ".."
        || maximum == 0
        || maximum > 128 * 1024
    {
        return Err(Error::Malformed);
    }
    let dir = directory(service)?;
    let file = File::from(
        openat(
            &dir,
            name,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(|_| Error::Unavailable)?,
    );
    check(&file, false, maximum as u64)?;
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::Unavailable)?;
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(Error::Malformed);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unit_names_are_closed_and_distinct() {
        let names: std::collections::BTreeSet<_> = [
            LinuxCredentialServiceV2::Kernel,
            LinuxCredentialServiceV2::Agent,
            LinuxCredentialServiceV2::Ingress,
            LinuxCredentialServiceV2::Approval,
            LinuxCredentialServiceV2::Executor,
            LinuxCredentialServiceV2::OwnerControl,
        ]
        .into_iter()
        .map(LinuxCredentialServiceV2::unit)
        .collect();
        assert_eq!(names.len(), 6);
        assert!(names.contains("savana-ownerctl.service"));
        assert!(names.iter().all(|name| name.starts_with("savana-")
            && name.ends_with(".service")
            && !name.contains('/')));
    }
    #[test]
    fn malformed_name_and_size_fail_before_filesystem_access() {
        for name in ["", ".", "..", "../key", "/key", "key/x", "key\0"] {
            assert_eq!(
                read_linux_service_credential_v2(LinuxCredentialServiceV2::Agent, name, 32)
                    .unwrap_err(),
                Error::Malformed
            );
        }
        for size in [0, 128 * 1024 + 1, usize::MAX] {
            assert_eq!(
                read_linux_service_credential_v2(LinuxCredentialServiceV2::Agent, "key", size)
                    .unwrap_err(),
                Error::Malformed
            );
        }
        assert_eq!(
            read_linux_kerneld_credential_v3("key", 2049).unwrap_err(),
            Error::Malformed
        );
    }
    #[test]
    fn only_systemd_exact_service_acl_is_accepted() {
        for permission in [4u16, 5] {
            let mut bytes = 2_u32.to_le_bytes().to_vec();
            for (tag, perm, id) in [
                (1u16, permission, u32::MAX),
                (2, permission, 1001),
                (4, 0, u32::MAX),
                (16, permission, u32::MAX),
                (32, 0, u32::MAX),
            ] {
                bytes.extend_from_slice(&tag.to_le_bytes());
                bytes.extend_from_slice(&perm.to_le_bytes());
                bytes.extend_from_slice(&id.to_le_bytes());
            }
            assert!(acl_matches(&bytes, 1001, permission));
            assert!(!acl_matches(&bytes, 1002, permission));
            for i in 0..bytes.len() {
                let mut bad = bytes.clone();
                bad[i] ^= 1;
                assert!(!acl_matches(&bad, 1001, permission));
            }
            let mut extra = bytes;
            extra.extend_from_slice(&[0; 8]);
            assert!(!acl_matches(&extra, 1001, permission));
        }
    }
}
