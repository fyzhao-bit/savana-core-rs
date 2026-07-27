use std::ffi::{OsStr, OsString};
use std::fs::{File, OpenOptions};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::net::UnixListener;
use std::path::{Component, Path, PathBuf};
use std::sync::Mutex;

use nix::errno::Errno;
use nix::fcntl::{fcntl, AtFlags, FcntlArg, FdFlag, OFlag};
use nix::sys::socket::{
    bind, connect, listen, socket, AddressFamily, Backlog, SockFlag, SockType, UnixAddr,
};
use nix::sys::stat::{fstatat, umask, FileStat, Mode, SFlag};
use nix::unistd::{fchdir, fchownat, getegid, geteuid, unlinkat, Gid, UnlinkatFlags};
use savana_kernel_protocol::StableCode;
use savana_policy_core::VerifiedReleaseIdentity;

const LISTENER_BACKLOG: i32 = 64;
const SOCKET_PARENT_MODE: u32 = 0o750;
const SOCKET_MODE: u32 = 0o660;

static STARTUP_MUTATION: Mutex<()> = Mutex::new(());
#[cfg(test)]
pub(crate) static PROCESS_TEST_LOCK: Mutex<()> = Mutex::new(());

#[derive(Clone)]
pub(crate) struct SocketConfig {
    path: PathBuf,
    daemon_uid: u32,
    daemon_gid: u32,
    socket_client_gid: u32,
    logical_daemon_gid: u32,
    logical_socket_client_gid: u32,
    mapped_identity: bool,
    parent_mode: u32,
    socket_mode: u32,
    #[cfg(test)]
    post_bind_fault: Option<PostBindTestFault>,
    #[cfg(test)]
    leaf_probe_fault: Option<LeafProbeTestFault>,
    #[cfg(test)]
    cwd_restore_failure: bool,
    #[cfg(test)]
    bind_failure: Option<Errno>,
}

#[cfg(test)]
#[derive(Clone, Copy)]
enum PostBindTestFault {
    ReplaceLeaf,
}

#[cfg(test)]
#[derive(Clone, Copy)]
enum LeafProbeTestFault {
    Indeterminate,
    ReplaceBeforeStaleUnlink,
    ParentPathAba,
}

impl SocketConfig {
    pub(crate) fn from_release(release: &VerifiedReleaseIdentity) -> Result<Self, StableCode> {
        let socket_client_gid = release
            .daemon_clients()
            .first()
            .map(savana_policy_core::InstallationClientV1::peer_gid)
            .ok_or(StableCode::IdentitySocketPermissions)?;
        Ok(Self {
            path: PathBuf::from(release.socket_path()),
            daemon_uid: release.daemon_uid(),
            daemon_gid: release.daemon_gid(),
            socket_client_gid,
            logical_daemon_gid: release.daemon_gid(),
            logical_socket_client_gid: socket_client_gid,
            mapped_identity: false,
            parent_mode: u32::from(release.socket_parent_mode()),
            socket_mode: u32::from(release.socket_mode()),
            #[cfg(test)]
            post_bind_fault: None,
            #[cfg(test)]
            leaf_probe_fault: None,
            #[cfg(test)]
            cwd_restore_failure: false,
            #[cfg(test)]
            bind_failure: None,
        })
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        path: PathBuf,
        daemon_uid: u32,
        daemon_gid: u32,
        socket_client_gid: u32,
    ) -> Self {
        Self {
            path,
            daemon_uid,
            daemon_gid,
            socket_client_gid,
            logical_daemon_gid: daemon_gid,
            logical_socket_client_gid: socket_client_gid,
            mapped_identity: false,
            parent_mode: SOCKET_PARENT_MODE,
            socket_mode: SOCKET_MODE,
            post_bind_fault: None,
            leaf_probe_fault: None,
            cwd_restore_failure: false,
            bind_failure: None,
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn from_mapped_release(
        release: &VerifiedReleaseIdentity,
        path: PathBuf,
        physical_uid: u32,
        physical_gid: u32,
    ) -> Result<Self, StableCode> {
        let logical_socket_client_gid = release
            .daemon_clients()
            .first()
            .map(savana_policy_core::InstallationClientV1::peer_gid)
            .ok_or(StableCode::IdentitySocketPermissions)?;
        Ok(Self {
            path,
            daemon_uid: physical_uid,
            daemon_gid: physical_gid,
            socket_client_gid: physical_gid,
            logical_daemon_gid: release.daemon_gid(),
            logical_socket_client_gid,
            mapped_identity: true,
            parent_mode: u32::from(release.socket_parent_mode()),
            socket_mode: u32::from(release.socket_mode()),
            #[cfg(test)]
            post_bind_fault: None,
            #[cfg(test)]
            leaf_probe_fault: None,
            #[cfg(test)]
            cwd_restore_failure: false,
            #[cfg(test)]
            bind_failure: None,
        })
    }

    #[cfg(test)]
    fn for_mapped_test(
        path: PathBuf,
        physical_uid: u32,
        physical_gid: u32,
        logical_daemon_gid: u32,
        logical_socket_client_gid: u32,
    ) -> Self {
        Self {
            path,
            daemon_uid: physical_uid,
            daemon_gid: physical_gid,
            socket_client_gid: physical_gid,
            logical_daemon_gid,
            logical_socket_client_gid,
            mapped_identity: true,
            parent_mode: SOCKET_PARENT_MODE,
            socket_mode: SOCKET_MODE,
            post_bind_fault: None,
            leaf_probe_fault: None,
            cwd_restore_failure: false,
            bind_failure: None,
        }
    }

    #[cfg(test)]
    fn with_post_bind_replacement(mut self) -> Self {
        self.post_bind_fault = Some(PostBindTestFault::ReplaceLeaf);
        self
    }

    #[cfg(test)]
    fn with_indeterminate_probe(mut self) -> Self {
        self.leaf_probe_fault = Some(LeafProbeTestFault::Indeterminate);
        self
    }

    #[cfg(test)]
    fn with_stale_inode_replacement(mut self) -> Self {
        self.leaf_probe_fault = Some(LeafProbeTestFault::ReplaceBeforeStaleUnlink);
        self
    }

    #[cfg(test)]
    fn with_parent_path_aba(mut self) -> Self {
        self.leaf_probe_fault = Some(LeafProbeTestFault::ParentPathAba);
        self
    }

    #[cfg(test)]
    fn with_cwd_restore_failure(mut self) -> Self {
        self.cwd_restore_failure = true;
        self
    }

    #[cfg(test)]
    fn with_bind_failure(mut self, error: Errno) -> Self {
        self.bind_failure = Some(error);
        self
    }
}

impl std::fmt::Debug for SocketConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SocketConfig(<verified>)")
    }
}

#[derive(Clone, Copy)]
enum PreflightLeaf {
    Missing,
    Stale(LeafIdentity),
}

pub(crate) struct SocketPreflight {
    config: SocketConfig,
    parent: File,
    parent_path: PathBuf,
    parent_identity: ParentIdentity,
    leaf: OsString,
    existing: PreflightLeaf,
}

impl std::fmt::Debug for SocketPreflight {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SocketPreflight(<verified>)")
    }
}

impl SocketPreflight {
    pub(crate) fn recheck(&self) -> Result<(), StableCode> {
        verify_process_identity(&self.config)?;
        recheck_parent_path(&self.parent_path, self.parent_identity)?;
        match self.existing {
            PreflightLeaf::Missing => match stat_leaf(&self.parent, &self.leaf) {
                Err(Errno::ENOENT) => Ok(()),
                _ => Err(StableCode::KernelUnavailable),
            },
            PreflightLeaf::Stale(expected) => {
                let current = stat_leaf(&self.parent, &self.leaf)
                    .map_err(|_| StableCode::KernelUnavailable)?;
                if LeafIdentity::from_stat(&current) != expected {
                    return Err(StableCode::KernelUnavailable);
                }
                Ok(())
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ParentIdentity {
    dev: u64,
    ino: u64,
    uid: u32,
    gid: u32,
    mode: u32,
}

impl ParentIdentity {
    fn from_file(file: &File) -> Result<Self, StableCode> {
        let metadata = file.metadata().map_err(|_| StableCode::KernelUnavailable)?;
        if !metadata.is_dir() {
            return Err(StableCode::IdentitySocketPermissions);
        }
        Ok(Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            mode: metadata.mode() & 0o7777,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct LeafIdentity {
    dev: i128,
    ino: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    nlink: u64,
    file_type: SFlag,
}

impl LeafIdentity {
    fn from_stat(stat: &FileStat) -> Self {
        Self {
            dev: i128::from(stat.st_dev),
            ino: stat.st_ino,
            uid: stat.st_uid,
            gid: stat.st_gid,
            mode: u32::from(stat.st_mode) & 0o7777,
            nlink: u64::from(stat.st_nlink),
            file_type: SFlag::from_bits_truncate(stat.st_mode),
        }
    }

    const fn same_inode(self, other: Self) -> bool {
        self.dev == other.dev && self.ino == other.ino
    }

    fn exact_socket(self, uid: u32, gid: u32, mode: u32) -> bool {
        self.file_type == SFlag::S_IFSOCK
            && self.nlink == 1
            && self.uid == uid
            && self.gid == gid
            && self.mode == mode
    }

    fn provisional_socket(self, config: &SocketConfig) -> bool {
        self.file_type == SFlag::S_IFSOCK
            && self.nlink == 1
            && self.uid == config.daemon_uid
            && (self.gid == config.daemon_gid || self.gid == config.socket_client_gid)
            && self.mode == SOCKET_MODE
    }
}

pub(crate) struct BoundListener {
    listener: Option<UnixListener>,
    parent: File,
    leaf: OsString,
    identity: LeafIdentity,
    cleanup_active: bool,
}

impl std::fmt::Debug for BoundListener {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("BoundListener(<inode-guarded>)")
    }
}

impl BoundListener {
    pub(crate) fn listener(&self) -> Result<&UnixListener, StableCode> {
        self.listener.as_ref().ok_or(StableCode::KernelUnavailable)
    }

    pub(crate) fn close(mut self) -> Result<(), StableCode> {
        drop(self.listener.take());
        let result = cleanup_exact(&self.parent, &self.leaf, self.identity);
        self.cleanup_active = false;
        result
    }

    pub(crate) fn stop_accepting(&mut self) -> Result<(), StableCode> {
        self.listener
            .take()
            .map(drop)
            .ok_or(StableCode::KernelUnavailable)
    }
}

impl Drop for BoundListener {
    fn drop(&mut self) {
        drop(self.listener.take());
        if self.cleanup_active {
            let _ = cleanup_exact(&self.parent, &self.leaf, self.identity);
            self.cleanup_active = false;
        }
    }
}

struct ProvisionalGuard<'parent> {
    parent: &'parent File,
    leaf: &'parent OsStr,
    expected: LeafIdentity,
    active: bool,
}

impl<'parent> ProvisionalGuard<'parent> {
    const fn new(parent: &'parent File, leaf: &'parent OsStr, expected: LeafIdentity) -> Self {
        Self {
            parent,
            leaf,
            expected,
            active: true,
        }
    }

    fn transition_group(&mut self, gid: u32) {
        self.expected.gid = gid;
    }

    fn replace_expected(&mut self, identity: LeafIdentity) {
        self.expected = identity;
    }

    fn disarm(&mut self) {
        self.active = false;
    }

    fn cleanup(&mut self) -> Result<(), StableCode> {
        if !self.active {
            return Ok(());
        }
        cleanup_exact(self.parent, self.leaf, self.expected)?;
        self.active = false;
        Ok(())
    }
}

impl Drop for ProvisionalGuard<'_> {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

struct CwdGuard {
    saved: File,
    changed: bool,
    #[cfg(test)]
    report_restore_failure: bool,
}

impl CwdGuard {
    fn capture() -> Result<Self, StableCode> {
        let saved = OpenOptions::new()
            .read(true)
            .custom_flags((OFlag::O_DIRECTORY | OFlag::O_CLOEXEC).bits())
            .open(".")
            .map_err(|_| StableCode::KernelUnavailable)?;
        Ok(Self {
            saved,
            changed: false,
            #[cfg(test)]
            report_restore_failure: false,
        })
    }

    fn enter(&mut self, parent: &File) -> Result<(), StableCode> {
        fchdir(parent.as_raw_fd()).map_err(|_| StableCode::KernelUnavailable)?;
        self.changed = true;
        Ok(())
    }

    fn restore(&mut self) -> Result<(), StableCode> {
        if self.changed {
            fchdir(self.saved.as_raw_fd()).map_err(|_| StableCode::KernelUnavailable)?;
            self.changed = false;
            #[cfg(test)]
            if self.report_restore_failure {
                return Err(StableCode::KernelUnavailable);
            }
        }
        Ok(())
    }

    #[cfg(test)]
    fn fail_restore_for_test(&mut self) {
        self.report_restore_failure = true;
    }
}

impl Drop for CwdGuard {
    fn drop(&mut self) {
        if self.changed {
            let _ = fchdir(self.saved.as_raw_fd());
            self.changed = false;
        }
    }
}

struct UmaskGuard {
    previous: Mode,
    installed: bool,
}

impl UmaskGuard {
    fn install() -> Self {
        Self {
            previous: umask(Mode::from_bits_truncate(0o117)),
            installed: true,
        }
    }

    fn restore(&mut self) -> Result<(), StableCode> {
        if self.installed {
            umask(self.previous);
            self.installed = false;
        }
        Ok(())
    }
}

impl Drop for UmaskGuard {
    fn drop(&mut self) {
        if self.installed {
            umask(self.previous);
            self.installed = false;
        }
    }
}

pub(crate) fn bind_socket(config: &SocketConfig) -> Result<BoundListener, StableCode> {
    bind_preflight(preflight_socket(config)?)
}

pub(crate) fn preflight_socket(config: &SocketConfig) -> Result<SocketPreflight, StableCode> {
    if config.parent_mode != SOCKET_PARENT_MODE
        || config.socket_mode != SOCKET_MODE
        || config.logical_socket_client_gid == config.logical_daemon_gid
    {
        return Err(StableCode::IdentitySocketPermissions);
    }
    verify_process_identity(config)?;
    let (parent_path, leaf) = split_socket_path(&config.path)?;
    let parent = open_verified_parent(parent_path, config)?;
    let parent_identity = ParentIdentity::from_file(&parent)?;
    let existing = classify_leaf(&parent, parent_path, parent_identity, &leaf, config)?;
    recheck_parent_path(parent_path, parent_identity)?;
    Ok(SocketPreflight {
        config: config.clone(),
        parent,
        parent_path: parent_path.to_owned(),
        parent_identity,
        leaf,
        existing,
    })
}

pub(crate) fn bind_preflight(preflight: SocketPreflight) -> Result<BoundListener, StableCode> {
    let SocketPreflight {
        config,
        parent,
        parent_path,
        parent_identity,
        leaf,
        existing,
    } = preflight;

    let socket_fd = create_stream_socket(false).map_err(|_| StableCode::KernelUnavailable)?;

    let mutation_lock = STARTUP_MUTATION
        .lock()
        .map_err(|_| StableCode::KernelUnavailable)?;
    let mut cwd_guard = CwdGuard::capture()?;
    #[cfg(test)]
    if config.cwd_restore_failure {
        cwd_guard.fail_restore_for_test();
    }
    let mut umask_guard: Option<UmaskGuard> = None;
    let bind_result = (|| {
        recheck_parent_path(&parent_path, parent_identity)?;
        consume_preflight_leaf(&parent, &leaf, &config, existing)?;
        cwd_guard.enter(&parent)?;
        umask_guard = Some(UmaskGuard::install());
        let address =
            UnixAddr::new(leaf.as_os_str()).map_err(|_| StableCode::IdentitySocketPermissions)?;
        #[cfg(test)]
        let bind_attempt = match config.bind_failure {
            Some(error) => Err(error),
            None => bind(socket_fd.as_raw_fd(), &address),
        };
        #[cfg(not(test))]
        let bind_attempt = bind(socket_fd.as_raw_fd(), &address);
        bind_attempt.map_err(map_setup_errno)?;
        let stat = stat_leaf(&parent, &leaf).map_err(|_| StableCode::KernelUnavailable)?;
        let identity = LeafIdentity::from_stat(&stat);
        if !identity.provisional_socket(&config) {
            return Err(StableCode::KernelUnavailable);
        }
        Ok(identity)
    })();

    let mut provisional = bind_result
        .as_ref()
        .ok()
        .copied()
        .map(|identity| ProvisionalGuard::new(&parent, &leaf, identity));
    let umask_restore = match umask_guard.as_mut() {
        Some(guard) => guard.restore(),
        None => Ok(()),
    };
    let cwd_restore = cwd_guard.restore();
    drop(umask_guard);
    drop(cwd_guard);
    drop(mutation_lock);
    if umask_restore.is_err() || cwd_restore.is_err() {
        if let Some(guard) = provisional.as_mut() {
            let _ = guard.cleanup();
        }
        return Err(StableCode::KernelUnavailable);
    }
    let provisional_identity = bind_result?;
    let guard = provisional.as_mut().ok_or(StableCode::KernelUnavailable)?;

    let completion = (|| {
        recheck_parent_path(&parent_path, parent_identity)?;
        fchownat(
            Some(parent.as_raw_fd()),
            leaf.as_os_str(),
            None,
            Some(Gid::from_raw(config.socket_client_gid)),
            AtFlags::AT_SYMLINK_NOFOLLOW,
        )
        .map_err(map_setup_errno)?;
        guard.transition_group(config.socket_client_gid);

        let final_stat = stat_leaf(&parent, &leaf).map_err(|_| StableCode::KernelUnavailable)?;
        let final_identity = LeafIdentity::from_stat(&final_stat);
        if !final_identity.same_inode(provisional_identity) {
            return Err(StableCode::KernelUnavailable);
        }
        if !final_identity.exact_socket(config.daemon_uid, config.socket_client_gid, SOCKET_MODE) {
            return Err(StableCode::IdentitySocketPermissions);
        }
        guard.replace_expected(final_identity);

        #[cfg(test)]
        inject_post_bind_fault(&config)?;

        let backlog = Backlog::new(LISTENER_BACKLOG).map_err(|_| StableCode::KernelUnavailable)?;
        listen(&socket_fd, backlog).map_err(|_| StableCode::KernelUnavailable)?;
        let listener = UnixListener::from(socket_fd);
        ensure_cloexec(&listener)?;
        listener
            .set_nonblocking(true)
            .map_err(|_| StableCode::KernelUnavailable)?;
        Ok((listener, final_identity))
    })();

    let (listener, final_identity) = match completion {
        Ok(completed) => completed,
        Err(original) => {
            let cleanup = guard.cleanup();
            return Err(if cleanup.is_err() {
                StableCode::KernelUnavailable
            } else {
                original
            });
        }
    };

    guard.disarm();
    drop(provisional);
    Ok(BoundListener {
        listener: Some(listener),
        parent,
        leaf,
        identity: final_identity,
        cleanup_active: true,
    })
}

#[cfg(test)]
fn inject_post_bind_fault(config: &SocketConfig) -> Result<(), StableCode> {
    match config.post_bind_fault {
        None => Ok(()),
        Some(PostBindTestFault::ReplaceLeaf) => {
            let displaced = config.path.with_extension("displaced");
            std::fs::rename(&config.path, displaced).map_err(|_| StableCode::KernelUnavailable)?;
            std::fs::write(&config.path, b"replacement")
                .map_err(|_| StableCode::KernelUnavailable)?;
            Err(StableCode::IdentitySocketPermissions)
        }
    }
}

fn verify_process_identity(config: &SocketConfig) -> Result<(), StableCode> {
    if geteuid().as_raw() != config.daemon_uid || getegid().as_raw() != config.daemon_gid {
        return Err(StableCode::IdentitySocketPermissions);
    }
    let groups = rustix::process::getgroups().map_err(|_| StableCode::KernelUnavailable)?;
    let supplementary_member = groups
        .iter()
        .any(|gid| gid.as_raw() == config.socket_client_gid);
    if !(supplementary_member
        || config.mapped_identity && getegid().as_raw() == config.socket_client_gid)
    {
        return Err(StableCode::IdentitySocketPermissions);
    }
    Ok(())
}

fn split_socket_path(path: &Path) -> Result<(&Path, OsString), StableCode> {
    if !path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::CurDir | Component::ParentDir | Component::Prefix(_)
            )
        })
    {
        return Err(StableCode::IdentitySocketPermissions);
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or(StableCode::IdentitySocketPermissions)?;
    let leaf = path
        .file_name()
        .filter(|leaf| !leaf.is_empty())
        .ok_or(StableCode::IdentitySocketPermissions)?
        .to_os_string();
    if Path::new(&leaf).components().count() != 1 {
        return Err(StableCode::IdentitySocketPermissions);
    }
    Ok((parent, leaf))
}

fn open_parent(path: &Path) -> Result<File, std::io::Error> {
    OpenOptions::new()
        .read(true)
        .custom_flags((OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC).bits())
        .open(path)
}

fn open_verified_parent(path: &Path, config: &SocketConfig) -> Result<File, StableCode> {
    let parent = open_parent(path).map_err(map_parent_open_error)?;
    let identity = ParentIdentity::from_file(&parent)?;
    if identity.uid != config.daemon_uid
        || identity.gid != config.socket_client_gid
        || identity.mode != SOCKET_PARENT_MODE
    {
        return Err(StableCode::IdentitySocketPermissions);
    }
    Ok(parent)
}

fn map_parent_open_error(error: std::io::Error) -> StableCode {
    match error.raw_os_error().map(Errno::from_raw) {
        Some(
            Errno::ENOENT
            | Errno::EACCES
            | Errno::EPERM
            | Errno::ENOTDIR
            | Errno::ELOOP
            | Errno::EINVAL
            | Errno::ENAMETOOLONG,
        ) => StableCode::IdentitySocketPermissions,
        _ => StableCode::KernelUnavailable,
    }
}

fn recheck_parent_path(path: &Path, expected: ParentIdentity) -> Result<(), StableCode> {
    let current = open_parent(path).map_err(|_| StableCode::KernelUnavailable)?;
    let identity =
        ParentIdentity::from_file(&current).map_err(|_| StableCode::KernelUnavailable)?;
    if identity != expected {
        return Err(StableCode::KernelUnavailable);
    }
    Ok(())
}

fn stat_leaf(parent: &File, leaf: &OsStr) -> Result<FileStat, Errno> {
    fstatat(Some(parent.as_raw_fd()), leaf, AtFlags::AT_SYMLINK_NOFOLLOW)
}

fn classify_leaf(
    parent: &File,
    parent_path: &Path,
    parent_identity: ParentIdentity,
    leaf: &OsStr,
    config: &SocketConfig,
) -> Result<PreflightLeaf, StableCode> {
    let mut enoent_rechecked = false;
    loop {
        let initial = match stat_leaf(parent, leaf) {
            Ok(stat) => LeafIdentity::from_stat(&stat),
            Err(Errno::ENOENT) => return Ok(PreflightLeaf::Missing),
            Err(error) => return Err(map_leaf_errno(error)),
        };
        if !initial.exact_socket(config.daemon_uid, config.socket_client_gid, SOCKET_MODE) {
            return Err(StableCode::IdentitySocketPermissions);
        }
        #[cfg(test)]
        let probe = match config.leaf_probe_fault {
            Some(LeafProbeTestFault::Indeterminate) => Err(Errno::EAGAIN),
            _ => {
                probe_existing_socket_anchored(parent, parent_path, parent_identity, leaf, config)?
            }
        };
        #[cfg(not(test))]
        let probe = probe_existing_socket_anchored(parent, parent_path, parent_identity, leaf)?;
        match probe {
            Ok(()) => return Err(StableCode::KernelUnavailable),
            Err(Errno::ECONNREFUSED) => {
                let current = stat_leaf(parent, leaf).map_err(|_| StableCode::KernelUnavailable)?;
                let current = LeafIdentity::from_stat(&current);
                if current != initial {
                    return Err(StableCode::KernelUnavailable);
                }
                return Ok(PreflightLeaf::Stale(initial));
            }
            Err(Errno::ENOENT) if !enoent_rechecked => {
                enoent_rechecked = true;
            }
            Err(_) => return Err(StableCode::KernelUnavailable),
        }
    }
}

fn consume_preflight_leaf(
    parent: &File,
    leaf: &OsStr,
    _config: &SocketConfig,
    existing: PreflightLeaf,
) -> Result<(), StableCode> {
    match existing {
        PreflightLeaf::Missing => match stat_leaf(parent, leaf) {
            Err(Errno::ENOENT) => Ok(()),
            _ => Err(StableCode::KernelUnavailable),
        },
        PreflightLeaf::Stale(expected) => {
            #[cfg(test)]
            if matches!(
                _config.leaf_probe_fault,
                Some(LeafProbeTestFault::ReplaceBeforeStaleUnlink)
            ) {
                let displaced = _config.path.with_extension("stale-displaced");
                std::fs::rename(&_config.path, displaced)
                    .map_err(|_| StableCode::KernelUnavailable)?;
                std::fs::write(&_config.path, b"replacement")
                    .map_err(|_| StableCode::KernelUnavailable)?;
            }
            let current = stat_leaf(parent, leaf).map_err(|_| StableCode::KernelUnavailable)?;
            if LeafIdentity::from_stat(&current) != expected {
                return Err(StableCode::KernelUnavailable);
            }
            unlinkat(Some(parent.as_raw_fd()), leaf, UnlinkatFlags::NoRemoveDir)
                .map_err(|_| StableCode::KernelUnavailable)
        }
    }
}

fn probe_existing_socket_anchored(
    parent: &File,
    parent_path: &Path,
    parent_identity: ParentIdentity,
    leaf: &OsStr,
    #[cfg(test)] config: &SocketConfig,
) -> Result<Result<(), Errno>, StableCode> {
    let mutation_lock = STARTUP_MUTATION
        .lock()
        .map_err(|_| StableCode::KernelUnavailable)?;
    let mut cwd_guard = CwdGuard::capture()?;
    let probe = (|| {
        recheck_parent_path(parent_path, parent_identity)?;
        cwd_guard.enter(parent)?;
        #[cfg(test)]
        if matches!(
            config.leaf_probe_fault,
            Some(LeafProbeTestFault::ParentPathAba)
        ) {
            return probe_during_parent_aba(parent_path, leaf);
        }
        Ok(probe_existing_socket(Path::new(leaf)))
    })();
    let cwd_restore = cwd_guard.restore();
    drop(cwd_guard);
    drop(mutation_lock);
    if cwd_restore.is_err() {
        return Err(StableCode::KernelUnavailable);
    }
    let probe = probe?;
    recheck_parent_path(parent_path, parent_identity)?;
    Ok(probe)
}

#[cfg(test)]
fn probe_during_parent_aba(
    parent_path: &Path,
    leaf: &OsStr,
) -> Result<Result<(), Errno>, StableCode> {
    let held_name = parent_path.with_extension("probe-held");
    let alternate = parent_path.with_extension("probe-alternate");
    std::fs::rename(parent_path, &held_name).map_err(|_| StableCode::KernelUnavailable)?;
    if std::fs::rename(&alternate, parent_path).is_err() {
        let _ = std::fs::rename(&held_name, parent_path);
        return Err(StableCode::KernelUnavailable);
    }

    let probe = probe_existing_socket(Path::new(leaf));
    let restore_alternate = std::fs::rename(parent_path, &alternate);
    let restore_held = std::fs::rename(&held_name, parent_path);
    if restore_alternate.is_err() || restore_held.is_err() {
        return Err(StableCode::KernelUnavailable);
    }
    Ok(probe)
}

fn probe_existing_socket(path: &Path) -> Result<(), Errno> {
    let descriptor = create_stream_socket(true)?;
    let address = UnixAddr::new(path)?;
    connect(descriptor.as_raw_fd(), &address)
}

fn ensure_cloexec(listener: &UnixListener) -> Result<(), StableCode> {
    ensure_cloexec_raw(listener.as_raw_fd()).map_err(|_| StableCode::KernelUnavailable)
}

fn ensure_cloexec_raw(raw: std::os::fd::RawFd) -> Result<(), Errno> {
    let mut flags = FdFlag::from_bits_truncate(fcntl(raw, FcntlArg::F_GETFD)?);
    if !flags.contains(FdFlag::FD_CLOEXEC) {
        flags.insert(FdFlag::FD_CLOEXEC);
        fcntl(raw, FcntlArg::F_SETFD(flags))?;
    }
    let verified = FdFlag::from_bits_truncate(fcntl(raw, FcntlArg::F_GETFD)?);
    if !verified.contains(FdFlag::FD_CLOEXEC) {
        return Err(Errno::EIO);
    }
    Ok(())
}

fn create_stream_socket(nonblocking: bool) -> Result<OwnedFd, Errno> {
    #[cfg(target_os = "linux")]
    let flags = {
        let mut flags = SockFlag::SOCK_CLOEXEC;
        if nonblocking {
            flags.insert(SockFlag::SOCK_NONBLOCK);
        }
        flags
    };
    #[cfg(target_os = "macos")]
    let flags = SockFlag::empty();

    let descriptor = socket(AddressFamily::Unix, SockType::Stream, flags, None)?;
    ensure_cloexec_raw(descriptor.as_raw_fd())?;
    if nonblocking {
        let raw = descriptor.as_raw_fd();
        let mut status = OFlag::from_bits_truncate(fcntl(raw, FcntlArg::F_GETFL)?);
        status.insert(OFlag::O_NONBLOCK);
        fcntl(raw, FcntlArg::F_SETFL(status))?;
    }
    Ok(descriptor)
}

fn cleanup_exact(parent: &File, leaf: &OsStr, expected: LeafIdentity) -> Result<(), StableCode> {
    let current = stat_leaf(parent, leaf).map_err(|_| StableCode::KernelUnavailable)?;
    let current = LeafIdentity::from_stat(&current);
    if current != expected {
        return Err(StableCode::KernelUnavailable);
    }
    unlinkat(Some(parent.as_raw_fd()), leaf, UnlinkatFlags::NoRemoveDir)
        .map_err(|_| StableCode::KernelUnavailable)
}

fn map_setup_errno(error: Errno) -> StableCode {
    match error {
        Errno::EACCES
        | Errno::EPERM
        | Errno::EINVAL
        | Errno::ENOTDIR
        | Errno::ELOOP
        | Errno::ENAMETOOLONG => StableCode::IdentitySocketPermissions,
        _ => StableCode::KernelUnavailable,
    }
}

fn map_leaf_errno(error: Errno) -> StableCode {
    match error {
        Errno::EACCES
        | Errno::EPERM
        | Errno::EINVAL
        | Errno::ENOTDIR
        | Errno::ELOOP
        | Errno::ENAMETOOLONG => StableCode::IdentitySocketPermissions,
        _ => StableCode::KernelUnavailable,
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{chown, symlink, FileTypeExt, MetadataExt, PermissionsExt};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::PathBuf;

    use nix::fcntl::{fcntl, FcntlArg, FdFlag};
    use nix::sys::stat::{umask, Mode};
    use nix::unistd::{getegid, geteuid, mkfifo};
    use rustix::process::getgroups;
    use savana_kernel_protocol::StableCode;
    use tempfile::TempDir;

    use super::*;

    struct SocketFixture {
        _root: TempDir,
        parent: PathBuf,
        path: PathBuf,
        config: SocketConfig,
    }

    impl SocketFixture {
        fn new() -> Self {
            let root = tempfile::tempdir().unwrap();
            let parent = root.path().join("socket-parent");
            fs::create_dir(&parent).unwrap();
            let daemon_gid = getegid().as_raw();
            let socket_client_gid = getgroups()
                .unwrap()
                .into_iter()
                .map(|gid| gid.as_raw())
                .find(|gid| *gid != daemon_gid)
                .expect("Task 6 tests require a supplementary client group");
            chown(&parent, None, Some(socket_client_gid)).unwrap();
            fs::set_permissions(&parent, fs::Permissions::from_mode(0o750)).unwrap();
            let path = parent.join("kerneld.sock");
            let config = SocketConfig::for_test(
                path.clone(),
                geteuid().as_raw(),
                daemon_gid,
                socket_client_gid,
            );
            Self {
                _root: root,
                parent,
                path,
                config,
            }
        }
    }

    #[test]
    fn socket_preflight_of_a_missing_leaf_is_read_only() {
        let _test_guard = PROCESS_TEST_LOCK.lock().unwrap();
        let fixture = SocketFixture::new();

        let preflight = preflight_socket(&fixture.config).unwrap();
        assert!(!fixture.path.exists());
        drop(preflight);
        assert!(!fixture.path.exists());
    }

    #[test]
    fn mapped_process_identity_accepts_effective_gid_only_after_logical_group_separation() {
        let config = SocketConfig::for_mapped_test(
            PathBuf::from("/mapped/run/savana/kernel/kerneld.sock"),
            geteuid().as_raw(),
            getegid().as_raw(),
            1_002,
            1_003,
        );
        verify_process_identity(&config).unwrap();
    }

    #[test]
    fn socket_preflight_classifies_but_does_not_remove_an_exact_stale_leaf() {
        let _test_guard = PROCESS_TEST_LOCK.lock().unwrap();
        let fixture = SocketFixture::new();
        let stale = UnixListener::bind(&fixture.path).unwrap();
        drop(stale);
        chown(&fixture.path, None, Some(fixture.config.socket_client_gid)).unwrap();
        fs::set_permissions(&fixture.path, fs::Permissions::from_mode(0o660)).unwrap();

        let preflight = preflight_socket(&fixture.config).unwrap();
        assert!(fixture.path.exists());
        let bound = bind_preflight(preflight).unwrap();
        assert!(fixture.path.exists());
        bound.close().unwrap();
        assert!(!fixture.path.exists());
    }

    #[test]
    fn bind_configures_exact_identity_before_listen_and_restores_process_state() {
        let _test_guard = PROCESS_TEST_LOCK.lock().unwrap();
        let fixture = SocketFixture::new();
        let original_cwd = std::env::current_dir().unwrap();
        let prior_umask = umask(Mode::from_bits_truncate(0o027));
        let bound = bind_socket(&fixture.config).unwrap();

        let observed_umask = umask(prior_umask);
        assert_eq!(observed_umask, Mode::from_bits_truncate(0o027));
        assert_eq!(std::env::current_dir().unwrap(), original_cwd);
        let metadata = fs::symlink_metadata(&fixture.path).unwrap();
        assert!(metadata.file_type().is_socket());
        assert_eq!(metadata.uid(), geteuid().as_raw());
        assert_eq!(metadata.gid(), fixture.config.socket_client_gid);
        assert_eq!(metadata.mode() & 0o7777, 0o660);
        assert_eq!(metadata.nlink(), 1);
        let fd_flags = FdFlag::from_bits_truncate(
            fcntl(bound.listener().unwrap().as_raw_fd(), FcntlArg::F_GETFD).unwrap(),
        );
        assert!(fd_flags.contains(FdFlag::FD_CLOEXEC));

        let client = UnixStream::connect(&fixture.path).unwrap();
        let (_accepted, _) = loop {
            match bound.listener().unwrap().accept() {
                Ok(value) => break value,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::yield_now();
                }
                Err(error) => panic!("accept failed: {error}"),
            }
        };
        drop(client);
        bound.close().unwrap();
        assert!(!fixture.path.exists());
    }

    #[test]
    fn invalid_parent_modes_and_symlink_parent_are_preserved() {
        let _test_guard = PROCESS_TEST_LOCK.lock().unwrap();
        for mode in [0o700, 0o755, 0o770, 0o4750] {
            let fixture = SocketFixture::new();
            fs::set_permissions(&fixture.parent, fs::Permissions::from_mode(mode)).unwrap();
            assert_eq!(
                bind_socket(&fixture.config).unwrap_err(),
                StableCode::IdentitySocketPermissions
            );
            assert!(fixture.parent.exists());
        }

        let fixture = SocketFixture::new();
        let linked_parent = fixture._root.path().join("linked-parent");
        symlink(&fixture.parent, &linked_parent).unwrap();
        let linked = SocketConfig::for_test(
            linked_parent.join("kerneld.sock"),
            fixture.config.daemon_uid,
            fixture.config.daemon_gid,
            fixture.config.socket_client_gid,
        );
        assert_eq!(
            bind_socket(&linked).unwrap_err(),
            StableCode::IdentitySocketPermissions
        );
        assert!(linked_parent
            .symlink_metadata()
            .unwrap()
            .file_type()
            .is_symlink());
    }

    #[test]
    fn missing_wrong_identity_and_nondirectory_parents_are_rejected() {
        let _test_guard = PROCESS_TEST_LOCK.lock().unwrap();

        let missing = SocketFixture::new();
        fs::remove_dir(&missing.parent).unwrap();
        assert_eq!(
            bind_socket(&missing.config).unwrap_err(),
            StableCode::IdentitySocketPermissions
        );

        let wrong_group = SocketFixture::new();
        chown(
            &wrong_group.parent,
            None,
            Some(wrong_group.config.daemon_gid),
        )
        .unwrap();
        assert_eq!(
            bind_socket(&wrong_group.config).unwrap_err(),
            StableCode::IdentitySocketPermissions
        );
        assert!(wrong_group.parent.is_dir());

        let nondirectory = SocketFixture::new();
        let parent_file = nondirectory._root.path().join("parent-file");
        fs::write(&parent_file, b"not a directory").unwrap();
        let config = SocketConfig::for_test(
            parent_file.join("kerneld.sock"),
            nondirectory.config.daemon_uid,
            nondirectory.config.daemon_gid,
            nondirectory.config.socket_client_gid,
        );
        assert_eq!(
            bind_socket(&config).unwrap_err(),
            StableCode::IdentitySocketPermissions
        );
        assert_eq!(fs::read(parent_file).unwrap(), b"not a directory");
    }

    #[test]
    fn process_identity_requires_exact_effective_ids_and_supplementary_group() {
        let _test_guard = PROCESS_TEST_LOCK.lock().unwrap();
        let fixture = SocketFixture::new();

        let mut wrong_uid = fixture.config.clone();
        wrong_uid.daemon_uid = wrong_uid.daemon_uid.wrapping_add(1);
        assert_eq!(
            bind_socket(&wrong_uid).unwrap_err(),
            StableCode::IdentitySocketPermissions
        );

        let mut wrong_gid = fixture.config.clone();
        wrong_gid.daemon_gid = wrong_gid.daemon_gid.wrapping_add(1);
        if wrong_gid.daemon_gid == wrong_gid.socket_client_gid {
            wrong_gid.daemon_gid = wrong_gid.daemon_gid.wrapping_add(1);
        }
        assert_eq!(
            bind_socket(&wrong_gid).unwrap_err(),
            StableCode::IdentitySocketPermissions
        );

        let groups = getgroups()
            .unwrap()
            .into_iter()
            .map(|gid| gid.as_raw())
            .collect::<Vec<_>>();
        let mut absent_gid = 1_u32;
        while absent_gid == fixture.config.daemon_gid || groups.contains(&absent_gid) {
            absent_gid = absent_gid.checked_add(1).unwrap();
        }
        let mut missing_group = fixture.config.clone();
        missing_group.socket_client_gid = absent_gid;
        assert_eq!(
            bind_socket(&missing_group).unwrap_err(),
            StableCode::IdentitySocketPermissions
        );
    }

    #[test]
    fn all_nonexact_leaf_classes_are_preserved() {
        let _test_guard = PROCESS_TEST_LOCK.lock().unwrap();

        let symlink_leaf = SocketFixture::new();
        let target = symlink_leaf.parent.join("target");
        fs::write(&target, b"target").unwrap();
        symlink(&target, &symlink_leaf.path).unwrap();
        assert_eq!(
            bind_socket(&symlink_leaf.config).unwrap_err(),
            StableCode::IdentitySocketPermissions
        );
        assert!(symlink_leaf
            .path
            .symlink_metadata()
            .unwrap()
            .file_type()
            .is_symlink());

        let regular_leaf = SocketFixture::new();
        fs::write(&regular_leaf.path, b"regular").unwrap();
        assert_eq!(
            bind_socket(&regular_leaf.config).unwrap_err(),
            StableCode::IdentitySocketPermissions
        );
        assert_eq!(fs::read(&regular_leaf.path).unwrap(), b"regular");

        let directory_leaf = SocketFixture::new();
        fs::create_dir(&directory_leaf.path).unwrap();
        assert_eq!(
            bind_socket(&directory_leaf.config).unwrap_err(),
            StableCode::IdentitySocketPermissions
        );
        assert!(directory_leaf.path.is_dir());

        let fifo_leaf = SocketFixture::new();
        mkfifo(&fifo_leaf.path, Mode::from_bits_truncate(0o660)).unwrap();
        assert_eq!(
            bind_socket(&fifo_leaf.config).unwrap_err(),
            StableCode::IdentitySocketPermissions
        );
        assert!(fifo_leaf
            .path
            .symlink_metadata()
            .unwrap()
            .file_type()
            .is_fifo());

        let wrong_group = SocketFixture::new();
        install_exact_stale_socket(&wrong_group);
        chown(&wrong_group.path, None, Some(wrong_group.config.daemon_gid)).unwrap();
        assert_eq!(
            bind_socket(&wrong_group.config).unwrap_err(),
            StableCode::IdentitySocketPermissions
        );
        assert!(wrong_group
            .path
            .symlink_metadata()
            .unwrap()
            .file_type()
            .is_socket());

        let wrong_mode = SocketFixture::new();
        install_exact_stale_socket(&wrong_mode);
        fs::set_permissions(&wrong_mode.path, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            bind_socket(&wrong_mode.config).unwrap_err(),
            StableCode::IdentitySocketPermissions
        );
        assert_eq!(
            wrong_mode.path.symlink_metadata().unwrap().mode() & 0o7777,
            0o600
        );
    }

    #[test]
    fn active_socket_is_preserved_and_exact_stale_socket_is_replaced() {
        let _test_guard = PROCESS_TEST_LOCK.lock().unwrap();
        let active = SocketFixture::new();
        let first = bind_socket(&active.config).unwrap();
        assert_eq!(
            bind_socket(&active.config).unwrap_err(),
            StableCode::KernelUnavailable
        );
        assert!(active.path.exists());
        first.close().unwrap();

        let stale = SocketFixture::new();
        install_exact_stale_socket(&stale);
        let replacement = bind_socket(&stale.config).unwrap();
        replacement.close().unwrap();
        assert!(!stale.path.exists());
    }

    #[test]
    fn indeterminate_probe_and_stale_inode_swap_preserve_the_leaf() {
        let _test_guard = PROCESS_TEST_LOCK.lock().unwrap();

        let indeterminate = SocketFixture::new();
        install_exact_stale_socket(&indeterminate);
        let original = indeterminate.path.symlink_metadata().unwrap();
        let config = indeterminate.config.clone().with_indeterminate_probe();
        assert_eq!(
            bind_socket(&config).unwrap_err(),
            StableCode::KernelUnavailable
        );
        let preserved = indeterminate.path.symlink_metadata().unwrap();
        assert_eq!(
            (preserved.dev(), preserved.ino()),
            (original.dev(), original.ino())
        );

        let swapped = SocketFixture::new();
        install_exact_stale_socket(&swapped);
        let config = swapped.config.clone().with_stale_inode_replacement();
        assert_eq!(
            bind_socket(&config).unwrap_err(),
            StableCode::KernelUnavailable
        );
        assert_eq!(fs::read(&swapped.path).unwrap(), b"replacement");
        assert!(swapped.path.with_extension("stale-displaced").exists());
    }

    #[test]
    fn parent_path_aba_cannot_redirect_probe_away_from_held_active_socket() {
        let _test_guard = PROCESS_TEST_LOCK.lock().unwrap();
        let active = SocketFixture::new();
        let first = bind_socket(&active.config).unwrap();

        let alternate_parent = active.parent.with_extension("probe-alternate");
        fs::create_dir(&alternate_parent).unwrap();
        chown(
            &alternate_parent,
            None,
            Some(active.config.socket_client_gid),
        )
        .unwrap();
        fs::set_permissions(
            &alternate_parent,
            fs::Permissions::from_mode(SOCKET_PARENT_MODE),
        )
        .unwrap();
        let alternate_path = alternate_parent.join("kerneld.sock");
        let stale = UnixListener::bind(&alternate_path).unwrap();
        drop(stale);
        fs::set_permissions(&alternate_path, fs::Permissions::from_mode(SOCKET_MODE)).unwrap();
        chown(&alternate_path, None, Some(active.config.socket_client_gid)).unwrap();

        let aba = active.config.clone().with_parent_path_aba();
        assert_eq!(
            bind_socket(&aba).unwrap_err(),
            StableCode::KernelUnavailable
        );
        let client = UnixStream::connect(&active.path).unwrap();
        drop(client);
        first.close().unwrap();
    }

    #[test]
    fn relative_bind_allows_ancestor_symlink() {
        let _test_guard = PROCESS_TEST_LOCK.lock().unwrap();

        let fixture = SocketFixture::new();
        let alias = fixture._root.path().join("ancestor-alias");
        symlink(fixture._root.path(), &alias).unwrap();
        let aliased_config = SocketConfig::for_test(
            alias.join("socket-parent").join("kerneld.sock"),
            fixture.config.daemon_uid,
            fixture.config.daemon_gid,
            fixture.config.socket_client_gid,
        );
        let bound = bind_socket(&aliased_config).unwrap();
        bound.close().unwrap();
    }

    #[test]
    fn overlong_leaf_is_an_identity_error_before_startup_mutation() {
        let _test_guard = PROCESS_TEST_LOCK.lock().unwrap();
        let failure = SocketFixture::new();
        let original_cwd = std::env::current_dir().unwrap();
        let prior_umask = umask(Mode::from_bits_truncate(0o027));
        let too_long = "x".repeat(256);
        let invalid = SocketConfig::for_test(
            failure.parent.join(too_long),
            failure.config.daemon_uid,
            failure.config.daemon_gid,
            failure.config.socket_client_gid,
        );
        assert_eq!(
            bind_socket(&invalid).unwrap_err(),
            StableCode::IdentitySocketPermissions
        );
        let observed_umask = umask(prior_umask);
        assert_eq!(observed_umask, Mode::from_bits_truncate(0o027));
        assert_eq!(std::env::current_dir().unwrap(), original_cwd);
    }

    #[test]
    fn bind_setup_failure_restores_both_guards_before_return_without_a_leaf() {
        let _test_guard = PROCESS_TEST_LOCK.lock().unwrap();
        let fixture = SocketFixture::new();
        let config = fixture.config.clone().with_bind_failure(Errno::EACCES);
        let original_cwd = std::env::current_dir().unwrap();
        let prior_umask = umask(Mode::from_bits_truncate(0o027));

        assert_eq!(
            bind_socket(&config).unwrap_err(),
            StableCode::IdentitySocketPermissions
        );
        let observed_umask = umask(prior_umask);
        assert_eq!(observed_umask, Mode::from_bits_truncate(0o027));
        assert_eq!(std::env::current_dir().unwrap(), original_cwd);
        assert!(!fixture.path.exists());
        assert!(UnixStream::connect(&fixture.path).is_err());
    }

    #[test]
    fn explicit_cwd_restore_failure_is_kernel_unavailable_before_listen_and_cleans() {
        let _test_guard = PROCESS_TEST_LOCK.lock().unwrap();
        let fixture = SocketFixture::new();
        let config = fixture.config.clone().with_cwd_restore_failure();
        let original_cwd = std::env::current_dir().unwrap();
        let prior_umask = umask(Mode::from_bits_truncate(0o027));

        assert_eq!(
            bind_socket(&config).unwrap_err(),
            StableCode::KernelUnavailable
        );
        let observed_umask = umask(prior_umask);
        assert_eq!(observed_umask, Mode::from_bits_truncate(0o027));
        assert_eq!(std::env::current_dir().unwrap(), original_cwd);
        assert!(!fixture.path.exists());
        assert!(UnixStream::connect(&fixture.path).is_err());
    }

    #[test]
    fn provisional_socket_group_is_closed_to_daemon_or_client_group() {
        let fixture = SocketFixture::new();
        let base = LeafIdentity {
            dev: 1,
            ino: 2,
            uid: fixture.config.daemon_uid,
            gid: fixture.config.daemon_gid,
            mode: 0o660,
            nlink: 1,
            file_type: SFlag::S_IFSOCK,
        };
        assert!(base.provisional_socket(&fixture.config));
        assert!(LeafIdentity {
            gid: fixture.config.socket_client_gid,
            ..base
        }
        .provisional_socket(&fixture.config));
        assert!(!LeafIdentity {
            gid: fixture.config.socket_client_gid.wrapping_add(1),
            ..base
        }
        .provisional_socket(&fixture.config));
    }

    #[test]
    fn cleanup_preserves_a_replacement_leaf_and_reports_the_race() {
        let _test_guard = PROCESS_TEST_LOCK.lock().unwrap();
        let fixture = SocketFixture::new();
        let bound = bind_socket(&fixture.config).unwrap();
        let original = fixture.parent.join("original.sock");
        fs::rename(&fixture.path, &original).unwrap();
        fs::write(&fixture.path, b"replacement").unwrap();

        assert_eq!(bound.close().unwrap_err(), StableCode::KernelUnavailable);
        assert_eq!(fs::read(&fixture.path).unwrap(), b"replacement");
    }

    #[test]
    fn post_bind_error_promotes_cleanup_identity_change_to_kernel_unavailable() {
        let _test_guard = PROCESS_TEST_LOCK.lock().unwrap();
        let fixture = SocketFixture::new();
        let config = fixture.config.clone().with_post_bind_replacement();

        assert_eq!(
            bind_socket(&config).unwrap_err(),
            StableCode::KernelUnavailable
        );
        assert_eq!(fs::read(&fixture.path).unwrap(), b"replacement");
        assert!(fixture.path.with_extension("displaced").exists());
    }

    #[test]
    fn path_error_mapping_distinguishes_identity_from_kernel_failures() {
        assert_eq!(
            map_parent_open_error(std::io::Error::from_raw_os_error(Errno::ENOENT as i32)),
            StableCode::IdentitySocketPermissions
        );
        assert_eq!(
            map_parent_open_error(std::io::Error::from_raw_os_error(Errno::ELOOP as i32)),
            StableCode::IdentitySocketPermissions
        );
        assert_eq!(
            map_parent_open_error(std::io::Error::from_raw_os_error(
                Errno::ENAMETOOLONG as i32
            )),
            StableCode::IdentitySocketPermissions
        );
        assert_eq!(
            map_setup_errno(Errno::ENAMETOOLONG),
            StableCode::IdentitySocketPermissions
        );
        assert_eq!(
            map_leaf_errno(Errno::ENAMETOOLONG),
            StableCode::IdentitySocketPermissions
        );
        assert_eq!(
            map_leaf_errno(Errno::EINVAL),
            StableCode::IdentitySocketPermissions
        );
        assert_eq!(
            map_parent_open_error(std::io::Error::from_raw_os_error(Errno::EMFILE as i32)),
            StableCode::KernelUnavailable
        );
        assert_eq!(
            map_parent_open_error(std::io::Error::from_raw_os_error(Errno::EIO as i32)),
            StableCode::KernelUnavailable
        );
        assert_eq!(map_setup_errno(Errno::EIO), StableCode::KernelUnavailable);
        assert_eq!(map_leaf_errno(Errno::EIO), StableCode::KernelUnavailable);
    }

    fn install_exact_stale_socket(fixture: &SocketFixture) {
        let listener = UnixListener::bind(&fixture.path).unwrap();
        drop(listener);
        fs::set_permissions(&fixture.path, fs::Permissions::from_mode(0o660)).unwrap();
        chown(&fixture.path, None, Some(fixture.config.socket_client_gid)).unwrap();
    }
}
