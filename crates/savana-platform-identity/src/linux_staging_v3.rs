//! Closed, descriptor-relative Linux staging measurement. This does not authorize
//! installation. It retains descriptors, not caller paths, and rejects all ACLs
//! and xattrs (including capabilities) in this initial staging profile.
use super::*;
use rustix::fs::{flistxattr, Dir};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::Metadata;
use std::io::{Seek, SeekFrom};

const PLANS: [&str; 6] = [
    "MigrationPlanV2.cbor",
    "ArtifactInstallPlanV2.cbor",
    "ServiceTransitionPlanV2.cbor",
    "IsolatedE2EPlanV2.cbor",
    "EvidenceContractV2.cbor",
    "ProtectedAcceptancePlanV2.cbor",
];
const PAYLOAD: &str = "ArtifactPayloadRoot";
const PLAN_LIMIT: u64 = 4_194_304;
const ARTIFACT_LIMIT: u64 = 8_589_934_592;
const TOTAL_LIMIT: u64 = 68_719_476_736;
const EMPTY_ACL: &[u8] = b"savana.linux-staging.v3.empty-acl\0";
const EMPTY_XATTR: &[u8] = b"savana.linux-staging.v3.empty-xattr\0";
type Error = NativeIdentityErrorV2;
fn bad() -> Error {
    Error::UnsafeDeploymentSpool
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MeasuredStagingEntryV3 {
    tag: u16,
    size: u64,
    sha256: [u8; 32],
}
impl MeasuredStagingEntryV3 {
    pub const fn tag(&self) -> u16 {
        self.tag
    }
    pub const fn size(&self) -> u64 {
        self.size
    }
    pub const fn sha256(&self) -> [u8; 32] {
        self.sha256
    }
    pub const fn mode(&self) -> u32 {
        if self.tag == 7 {
            0o700
        } else {
            0o600
        }
    }
    pub fn acl_digest(&self) -> [u8; 32] {
        Sha256::digest(EMPTY_ACL).into()
    }
    pub fn xattr_digest(&self) -> [u8; 32] {
        Sha256::digest(EMPTY_XATTR).into()
    }
}

#[derive(Debug)]
struct Node {
    file: File,
    before: Metadata,
    leaf: String,
    in_payload: bool,
    entry: MeasuredStagingEntryV3,
}

/// Read-only measurement lease. Any subsequent installation must revalidate and
/// use these retained objects, not reopen a caller-supplied path after checking.
/// Root ownership is guaranteed only by the production fixed-spool constructor;
/// `open_for_test` is an explicitly test-feature-only non-root harness.
#[derive(Debug)]
pub struct LinuxMeasuredStagingTreeV3<'a> {
    spool: &'a FixedDeploymentSpoolV2,
    selector: DeploymentApplySelectorV2,
    root: File,
    root_before: Metadata,
    payload: File,
    payload_before: Metadata,
    descriptor: Vec<u8>,
    entries: Vec<MeasuredStagingEntryV3>,
    nodes: Vec<Node>,
    plans: Vec<Vec<u8>>,
    poisoned: bool,
}

impl FixedDeploymentSpoolV2 {
    pub fn measure_staging_v3(
        &self,
        selector: DeploymentApplySelectorV2,
    ) -> Result<LinuxMeasuredStagingTreeV3<'_>, Error> {
        self.recheck_ready()?;
        let root = open_node(&self.ready, &selector.leaf(), true, self, self.ready_dev)?;
        let root_before = root.metadata().map_err(|_| bad())?;
        let descriptor =
            read_fixed_descriptor(&root, self.owner_uid, self.owner_gid, self.ready_dev)?;
        // Descriptor bytes are excluded from the Merkle tree to avoid a cycle,
        // but its filesystem attributes are not exempt from the staging profile.
        let descriptor_file = File::from(
            openat(
                &root,
                TRANSACTION_DESCRIPTOR_LEAF_V2,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
                Mode::empty(),
            )
            .map_err(|_| bad())?,
        );
        no_attributes(&descriptor_file)?;
        let payload = open_node(&root, PAYLOAD, true, self, self.ready_dev)?;
        let payload_before = payload.metadata().map_err(|_| bad())?;
        let mut nodes = Vec::new();
        let mut entries = Vec::new();
        let mut plans = Vec::new();
        let mut total = 0u64;
        for (index, leaf) in PLANS.iter().enumerate() {
            let mut node = node(&root, leaf, index as u16 + 1, false, self)?;
            let (hash, bytes) = hash_file(&mut node.file, node.before.len(), true)?;
            node.entry.sha256 = hash;
            total = total.checked_add(node.entry.size).ok_or_else(bad)?;
            plans.push(bytes);
            entries.push(node.entry.clone());
            nodes.push(node);
        }
        entries.push(MeasuredStagingEntryV3 {
            tag: 7,
            size: 0,
            sha256: [0; 32],
        });
        let names = list(&payload)?;
        if names.is_empty() || names.len() > 35 {
            return Err(bad());
        }
        for leaf in names {
            let tag: u16 = leaf.parse().map_err(|_| bad())?;
            if !(10..=44).contains(&tag) || leaf != tag.to_string() {
                return Err(bad());
            }
            let mut node = node(&payload, &leaf, tag, true, self)?;
            total = total
                .checked_add(node.entry.size)
                .filter(|n| *n <= TOTAL_LIMIT)
                .ok_or_else(bad)?;
            node.entry.sha256 = hash_file(&mut node.file, node.before.len(), false)?.0;
            entries.push(node.entry.clone());
            nodes.push(node);
        }
        let mut lease = LinuxMeasuredStagingTreeV3 {
            spool: self,
            selector,
            root,
            root_before,
            payload,
            payload_before,
            descriptor,
            entries,
            nodes,
            plans,
            poisoned: false,
        };
        lease.revalidate()?;
        Ok(lease)
    }
}

impl LinuxMeasuredStagingTreeV3<'_> {
    pub fn entries(&self) -> &[MeasuredStagingEntryV3] {
        &self.entries
    }
    pub fn descriptor_bytes(&self) -> &[u8] {
        &self.descriptor
    }
    pub const fn selector(&self) -> DeploymentApplySelectorV2 {
        self.selector
    }
    pub fn plan_bytes(&self, tag: u16) -> Result<&[u8], Error> {
        self.plans
            .get(usize::from(tag.checked_sub(1).ok_or_else(bad)?))
            .map(Vec::as_slice)
            .ok_or_else(bad)
    }
    pub fn revalidate(&mut self) -> Result<(), Error> {
        if self.poisoned {
            return Err(bad());
        }
        self.poisoned = true;
        self.check_unchanged()?;
        self.poisoned = false;
        Ok(())
    }
    fn check_unchanged(&mut self) -> Result<(), Error> {
        self.spool.recheck_ready()?;
        same_link(
            &self.spool.ready,
            &self.selector.leaf(),
            &self.root,
            &self.root_before,
        )?;
        same_link(&self.root, PAYLOAD, &self.payload, &self.payload_before)?;
        let expected_root: BTreeSet<String> = PLANS
            .iter()
            .map(|s| (*s).to_owned())
            .chain([
                PAYLOAD.to_owned(),
                TRANSACTION_DESCRIPTOR_LEAF_V2.to_owned(),
            ])
            .collect();
        if list(&self.root)? != expected_root {
            return Err(bad());
        }
        let expected_payload = self
            .nodes
            .iter()
            .filter(|n| n.in_payload)
            .map(|n| n.leaf.clone())
            .collect();
        if list(&self.payload)? != expected_payload {
            return Err(bad());
        }
        if read_fixed_descriptor(
            &self.root,
            self.spool.owner_uid,
            self.spool.owner_gid,
            self.spool.ready_dev,
        )? != self.descriptor
        {
            return Err(bad());
        }
        let descriptor = File::from(
            openat(
                &self.root,
                TRANSACTION_DESCRIPTOR_LEAF_V2,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
                Mode::empty(),
            )
            .map_err(|_| bad())?,
        );
        no_attributes(&descriptor)?;
        for n in &mut self.nodes {
            let parent = if n.in_payload {
                &self.payload
            } else {
                &self.root
            };
            same_link(parent, &n.leaf, &n.file, &n.before)?;
            if hash_file(&mut n.file, n.entry.size, false)?.0 != n.entry.sha256 {
                return Err(bad());
            }
            same_link(parent, &n.leaf, &n.file, &n.before)?;
        }
        same_link(&self.root, PAYLOAD, &self.payload, &self.payload_before)?;
        same_link(
            &self.spool.ready,
            &self.selector.leaf(),
            &self.root,
            &self.root_before,
        )?;
        self.spool.recheck_ready()
    }
}

fn list(directory: &File) -> Result<BTreeSet<String>, Error> {
    let mut names = BTreeSet::new();
    for entry in Dir::read_from(directory).map_err(|_| bad())? {
        let entry = entry.map_err(|_| bad())?;
        let bytes = entry.file_name().to_bytes();
        if bytes == b"." || bytes == b".." {
            continue;
        }
        let name = std::str::from_utf8(bytes).map_err(|_| bad())?;
        if names.len() >= 44 || !names.insert(name.to_owned()) {
            return Err(bad());
        }
    }
    Ok(names)
}
fn no_attributes(file: &File) -> Result<(), Error> {
    // Size query: never allocate attacker-controlled xattr lengths. ACL and
    // security.capability are xattrs too. ENOTSUP is not proof of an empty set.
    if flistxattr(file, &mut [0u8; 0][..]).map_err(|_| bad())? != 0 {
        return Err(bad());
    }
    Ok(())
}
fn same_metadata(a: &Metadata, b: &Metadata) -> bool {
    a.dev() == b.dev()
        && a.ino() == b.ino()
        && a.mode() == b.mode()
        && a.uid() == b.uid()
        && a.gid() == b.gid()
        && a.nlink() == b.nlink()
        && a.len() == b.len()
        && a.mtime() == b.mtime()
        && a.mtime_nsec() == b.mtime_nsec()
        && a.ctime() == b.ctime()
        && a.ctime_nsec() == b.ctime_nsec()
}
fn same_link(parent: &File, leaf: &str, file: &File, before: &Metadata) -> Result<(), Error> {
    let now = file.metadata().map_err(|_| bad())?;
    let linked = statat(parent, leaf, AtFlags::SYMLINK_NOFOLLOW).map_err(|_| bad())?;
    if !same_metadata(before, &now)
        || linked.st_dev != now.dev()
        || linked.st_ino != now.ino()
        || linked.st_mode != now.mode()
        || linked.st_uid != now.uid()
        || linked.st_gid != now.gid()
    {
        return Err(bad());
    }
    no_attributes(file)
}
fn open_node(
    parent: &File,
    leaf: &str,
    directory: bool,
    spool: &FixedDeploymentSpoolV2,
    dev: u64,
) -> Result<File, Error> {
    let before = statat(parent, leaf, AtFlags::SYMLINK_NOFOLLOW).map_err(|_| bad())?;
    if FileType::from_raw_mode(before.st_mode)
        != if directory {
            FileType::Directory
        } else {
            FileType::RegularFile
        }
        || before.st_dev != dev
        || before.st_uid != spool.owner_uid
        || before.st_gid != spool.owner_gid
        || before.st_mode & 0o7777 != if directory { 0o700 } else { 0o600 }
        || (!directory && before.st_nlink != 1)
    {
        return Err(bad());
    }
    let mut flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
    if directory {
        flags |= OFlags::DIRECTORY;
    }
    let file = File::from(openat(parent, leaf, flags, Mode::empty()).map_err(|_| bad())?);
    let m = file.metadata().map_err(|_| bad())?;
    if m.dev() != dev
        || m.ino() != before.st_ino
        || m.uid() != spool.owner_uid
        || m.gid() != spool.owner_gid
        || m.mode() & 0o7777 != if directory { 0o700 } else { 0o600 }
        || if directory {
            !m.is_dir()
        } else {
            !m.is_file() || m.nlink() != 1
        }
    {
        return Err(bad());
    }
    same_link(parent, leaf, &file, &m)?;
    Ok(file)
}
fn node(
    parent: &File,
    leaf: &str,
    tag: u16,
    in_payload: bool,
    spool: &FixedDeploymentSpoolV2,
) -> Result<Node, Error> {
    let file = open_node(parent, leaf, false, spool, spool.ready_dev)?;
    let before = file.metadata().map_err(|_| bad())?;
    let size = before.len();
    let limit = if in_payload {
        ARTIFACT_LIMIT
    } else {
        PLAN_LIMIT
    };
    if size == 0 || size > limit {
        return Err(bad());
    }
    Ok(Node {
        file,
        before,
        leaf: leaf.into(),
        in_payload,
        entry: MeasuredStagingEntryV3 {
            tag,
            size,
            sha256: [0; 32],
        },
    })
}
fn hash_file(file: &mut File, length: u64, keep: bool) -> Result<([u8; 32], Vec<u8>), Error> {
    file.seek(SeekFrom::Start(0)).map_err(|_| bad())?;
    let mut h = Sha256::new();
    let mut bytes = Vec::new();
    if keep {
        bytes
            .try_reserve_exact(usize::try_from(length).map_err(|_| bad())?)
            .map_err(|_| bad())?;
    }
    let mut count = 0u64;
    let mut buffer = [0u8; 65_536];
    loop {
        let n = file.read(&mut buffer).map_err(|_| bad())?;
        if n == 0 {
            break;
        }
        count = count
            .checked_add(n as u64)
            .filter(|n| *n <= length)
            .ok_or_else(bad)?;
        h.update(&buffer[..n]);
        if keep {
            bytes.extend_from_slice(&buffer[..n]);
        }
    }
    if count != length {
        return Err(bad());
    }
    Ok((h.finalize().into(), bytes))
}

#[cfg(test)]
#[path = "linux_staging_v3_tests.rs"]
mod tests;
