#![allow(unsafe_code)]

use std::ffi::CString;
use std::fs::OpenOptions;
use std::io;
use std::os::fd::AsRawFd as _;
use std::os::unix::ffi::OsStrExt as _;
use std::path::{Path, PathBuf};

use nix::libc;

use super::{ValidatedIsolationProfileV2, WorkerSandboxErrorV2};

const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1;
const LANDLOCK_RULE_PATH_BENEATH: u32 = 1;
const LANDLOCK_ACCESS_FS_EXECUTE: u64 = 1 << 0;
const LANDLOCK_ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
const LANDLOCK_ACCESS_FS_READ_FILE: u64 = 1 << 2;
const LANDLOCK_ACCESS_FS_READ_DIR: u64 = 1 << 3;
const LANDLOCK_ACCESS_FS_REMOVE_DIR: u64 = 1 << 4;
const LANDLOCK_ACCESS_FS_REMOVE_FILE: u64 = 1 << 5;
const LANDLOCK_ACCESS_FS_MAKE_CHAR: u64 = 1 << 6;
const LANDLOCK_ACCESS_FS_MAKE_DIR: u64 = 1 << 7;
const LANDLOCK_ACCESS_FS_MAKE_REG: u64 = 1 << 8;
const LANDLOCK_ACCESS_FS_MAKE_SOCK: u64 = 1 << 9;
const LANDLOCK_ACCESS_FS_MAKE_FIFO: u64 = 1 << 10;
const LANDLOCK_ACCESS_FS_MAKE_BLOCK: u64 = 1 << 11;
const LANDLOCK_ACCESS_FS_MAKE_SYM: u64 = 1 << 12;
const LANDLOCK_ACCESS_FS_REFER: u64 = 1 << 13;
const LANDLOCK_ACCESS_FS_TRUNCATE: u64 = 1 << 14;
const LANDLOCK_ACCESS_FS_IOCTL_DEV: u64 = 1 << 15;

const SECCOMP_SET_MODE_FILTER: libc::c_uint = 1;
const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const BPF_LD: u16 = 0x00;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JMP: u16 = 0x05;
const BPF_JEQ: u16 = 0x10;
const BPF_K: u16 = 0x00;
const BPF_RET: u16 = 0x06;

#[repr(C)]
struct LandlockRulesetAttr {
    handled_access_fs: u64,
}

#[repr(C)]
struct LandlockPathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
    reserved: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SockFilter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

#[repr(C)]
struct SockFprog {
    len: u16,
    filter: *const SockFilter,
}

pub(super) fn enter_and_exec(
    worker: &Path,
    worker_arguments: &[String],
    profile: ValidatedIsolationProfileV2,
) -> Result<(), WorkerSandboxErrorV2> {
    set_no_new_privileges()?;
    close_untrusted_descriptors()?;
    apply_resource_limits(&profile)?;
    install_landlock(worker, &profile.read_only_paths)?;
    install_seccomp()?;
    exec_worker(worker, worker_arguments)
}

fn set_no_new_privileges() -> Result<(), WorkerSandboxErrorV2> {
    // SAFETY: prctl receives scalar values only. Failure is checked and the
    // sandbox never continues without the irreversible no-new-privileges bit.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(WorkerSandboxErrorV2::SandboxUnavailable);
    }
    Ok(())
}

fn close_untrusted_descriptors() -> Result<(), WorkerSandboxErrorV2> {
    // SAFETY: close_range closes only descriptors >= 3. stdin/stdout/stderr
    // are the anonymous worker protocol and diagnostic endpoints.
    let result = unsafe { libc::syscall(libc::SYS_close_range, 3_u32, u32::MAX, 0_u32) };
    if result != 0 {
        return Err(WorkerSandboxErrorV2::SandboxUnavailable);
    }
    Ok(())
}

fn apply_resource_limits(
    profile: &ValidatedIsolationProfileV2,
) -> Result<(), WorkerSandboxErrorV2> {
    for (resource, value) in [
        (libc::RLIMIT_AS, profile.memory_limit_bytes),
        (libc::RLIMIT_CPU, profile.cpu_time_seconds),
        (libc::RLIMIT_FSIZE, profile.output_file_limit_bytes),
        (libc::RLIMIT_NOFILE, profile.open_file_limit),
        (libc::RLIMIT_NPROC, profile.process_limit),
        (libc::RLIMIT_CORE, 0),
    ] {
        let limit = libc::rlimit {
            rlim_cur: value,
            rlim_max: value,
        };
        // SAFETY: limit points to an initialized rlimit for the named
        // resource. Every failure aborts before executing the worker.
        if unsafe { libc::setrlimit(resource, &limit) } != 0 {
            return Err(WorkerSandboxErrorV2::SandboxUnavailable);
        }
    }
    Ok(())
}

fn install_landlock(
    worker: &Path,
    configured_read_paths: &[PathBuf],
) -> Result<(), WorkerSandboxErrorV2> {
    let abi = landlock_abi()?;
    let handled_access_fs = handled_access_for_abi(abi);
    let attributes = LandlockRulesetAttr { handled_access_fs };
    // SAFETY: attributes is a valid ruleset structure and its exact size is
    // passed. A negative return value is handled as fail-closed.
    let ruleset_fd = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            &attributes,
            std::mem::size_of::<LandlockRulesetAttr>(),
            0_u32,
        )
    };
    if ruleset_fd < 0 {
        return Err(WorkerSandboxErrorV2::SandboxUnavailable);
    }
    let ruleset = OwnedRawFd::new(
        i32::try_from(ruleset_fd).map_err(|_| WorkerSandboxErrorV2::SandboxUnavailable)?,
    );

    add_landlock_path_rule(
        ruleset.0,
        worker,
        LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE,
    )?;
    for path in default_runtime_read_paths()
        .into_iter()
        .chain(configured_read_paths.iter().cloned())
    {
        if path.exists() {
            let metadata =
                std::fs::metadata(&path).map_err(|_| WorkerSandboxErrorV2::SandboxUnavailable)?;
            let allowed = if metadata.is_dir() {
                LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR
            } else if metadata.is_file() {
                LANDLOCK_ACCESS_FS_READ_FILE
            } else {
                return Err(WorkerSandboxErrorV2::SandboxUnavailable);
            };
            add_landlock_path_rule(ruleset.0, &path, allowed)?;
        }
    }

    // SAFETY: ruleset.0 is the live Landlock ruleset descriptor constructed
    // above. Restriction is irreversible for this process and descendants.
    if unsafe { libc::syscall(libc::SYS_landlock_restrict_self, ruleset.0, 0_u32) } != 0 {
        return Err(WorkerSandboxErrorV2::SandboxUnavailable);
    }
    Ok(())
}

fn landlock_abi() -> Result<i32, WorkerSandboxErrorV2> {
    // SAFETY: the VERSION query requires a null attribute and zero size.
    let abi = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<LandlockRulesetAttr>(),
            0_usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    if abi < 1 {
        return Err(WorkerSandboxErrorV2::SandboxUnavailable);
    }
    i32::try_from(abi).map_err(|_| WorkerSandboxErrorV2::SandboxUnavailable)
}

fn handled_access_for_abi(abi: i32) -> u64 {
    let mut rights = LANDLOCK_ACCESS_FS_EXECUTE
        | LANDLOCK_ACCESS_FS_WRITE_FILE
        | LANDLOCK_ACCESS_FS_READ_FILE
        | LANDLOCK_ACCESS_FS_READ_DIR
        | LANDLOCK_ACCESS_FS_REMOVE_DIR
        | LANDLOCK_ACCESS_FS_REMOVE_FILE
        | LANDLOCK_ACCESS_FS_MAKE_CHAR
        | LANDLOCK_ACCESS_FS_MAKE_DIR
        | LANDLOCK_ACCESS_FS_MAKE_REG
        | LANDLOCK_ACCESS_FS_MAKE_SOCK
        | LANDLOCK_ACCESS_FS_MAKE_FIFO
        | LANDLOCK_ACCESS_FS_MAKE_BLOCK
        | LANDLOCK_ACCESS_FS_MAKE_SYM;
    if abi >= 2 {
        rights |= LANDLOCK_ACCESS_FS_REFER;
    }
    if abi >= 3 {
        rights |= LANDLOCK_ACCESS_FS_TRUNCATE;
    }
    if abi >= 5 {
        rights |= LANDLOCK_ACCESS_FS_IOCTL_DEV;
    }
    rights
}

fn add_landlock_path_rule(
    ruleset_fd: i32,
    path: &Path,
    allowed_access: u64,
) -> Result<(), WorkerSandboxErrorV2> {
    let file = OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|_| WorkerSandboxErrorV2::SandboxUnavailable)?;
    let attributes = LandlockPathBeneathAttr {
        allowed_access,
        parent_fd: file.as_raw_fd(),
        reserved: 0,
    };
    // SAFETY: both file descriptors remain live across the syscall and the
    // attributes structure has the kernel-defined path-beneath layout.
    if unsafe {
        libc::syscall(
            libc::SYS_landlock_add_rule,
            ruleset_fd,
            LANDLOCK_RULE_PATH_BENEATH,
            &attributes,
            0_u32,
        )
    } != 0
    {
        return Err(WorkerSandboxErrorV2::SandboxUnavailable);
    }
    Ok(())
}

fn default_runtime_read_paths() -> Vec<PathBuf> {
    ["/usr", "/lib", "/lib64", "/etc/ld.so.cache"]
        .into_iter()
        .map(PathBuf::from)
        .collect()
}

fn install_seccomp() -> Result<(), WorkerSandboxErrorV2> {
    let mut program = Vec::with_capacity(64);
    program.push(statement(BPF_LD | BPF_W | BPF_ABS, 4));
    program.push(jump(BPF_JMP | BPF_JEQ | BPF_K, audit_arch(), 1, 0));
    program.push(statement(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));
    program.push(statement(BPF_LD | BPF_W | BPF_ABS, 0));
    for &syscall in denied_syscalls() {
        program.push(jump(
            BPF_JMP | BPF_JEQ | BPF_K,
            u32::try_from(syscall).map_err(|_| WorkerSandboxErrorV2::SandboxUnavailable)?,
            0,
            1,
        ));
        program.push(statement(
            BPF_RET | BPF_K,
            SECCOMP_RET_ERRNO | u32::try_from(libc::EPERM).unwrap_or(1),
        ));
    }
    program.push(statement(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
    let filter = SockFprog {
        len: u16::try_from(program.len()).map_err(|_| WorkerSandboxErrorV2::SandboxUnavailable)?,
        filter: program.as_ptr(),
    };
    // SAFETY: filter references the live, initialized BPF program for the
    // duration of the syscall. no_new_privileges was installed first.
    if unsafe { libc::syscall(libc::SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0_u32, &filter) } != 0 {
        return Err(WorkerSandboxErrorV2::SandboxUnavailable);
    }
    Ok(())
}

const fn statement(code: u16, k: u32) -> SockFilter {
    SockFilter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

const fn jump(code: u16, k: u32, jt: u8, jf: u8) -> SockFilter {
    SockFilter { code, jt, jf, k }
}

#[cfg(target_arch = "x86_64")]
const fn audit_arch() -> u32 {
    0xc000_003e
}

#[cfg(target_arch = "aarch64")]
const fn audit_arch() -> u32 {
    0xc000_00b7
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("the production Linux worker sandbox supports only x86_64 and aarch64");

fn denied_syscalls() -> &'static [libc::c_long] {
    &[
        libc::SYS_socket,
        libc::SYS_socketpair,
        libc::SYS_connect,
        libc::SYS_bind,
        libc::SYS_listen,
        libc::SYS_accept,
        libc::SYS_accept4,
        libc::SYS_sendto,
        libc::SYS_sendmsg,
        libc::SYS_recvmsg,
        libc::SYS_ptrace,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
        libc::SYS_open_by_handle_at,
        libc::SYS_name_to_handle_at,
        libc::SYS_bpf,
        libc::SYS_perf_event_open,
        libc::SYS_keyctl,
        libc::SYS_add_key,
        libc::SYS_request_key,
        libc::SYS_unshare,
        libc::SYS_setns,
        libc::SYS_clone3,
        libc::SYS_kexec_load,
        libc::SYS_reboot,
    ]
}

fn exec_worker(worker: &Path, arguments: &[String]) -> Result<(), WorkerSandboxErrorV2> {
    let worker = CString::new(worker.as_os_str().as_bytes())
        .map_err(|_| WorkerSandboxErrorV2::ExecutionFailed)?;
    let mut owned_arguments = Vec::with_capacity(arguments.len() + 1);
    owned_arguments.push(worker.clone());
    for argument in arguments {
        owned_arguments.push(
            CString::new(argument.as_bytes()).map_err(|_| WorkerSandboxErrorV2::ExecutionFailed)?,
        );
    }
    let mut pointers = owned_arguments
        .iter()
        .map(|argument| argument.as_ptr())
        .collect::<Vec<_>>();
    pointers.push(std::ptr::null());
    let environment = [std::ptr::null::<libc::c_char>()];
    // SAFETY: worker, argv, and envp are NUL-terminated and live for the
    // syscall. On success execve never returns; on failure errno is checked.
    unsafe {
        libc::execve(worker.as_ptr(), pointers.as_ptr(), environment.as_ptr());
    }
    let _ = io::Error::last_os_error();
    Err(WorkerSandboxErrorV2::ExecutionFailed)
}

struct OwnedRawFd(i32);

impl OwnedRawFd {
    const fn new(descriptor: i32) -> Self {
        Self(descriptor)
    }
}

impl Drop for OwnedRawFd {
    fn drop(&mut self) {
        // SAFETY: this type is the sole owner of the descriptor.
        unsafe {
            libc::close(self.0);
        }
    }
}
