#![allow(unsafe_code)]

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt as _;
use std::path::Path;

use nix::libc;

use super::{ValidatedIsolationProfileV2, WorkerSandboxErrorV2};

pub(super) fn enter_and_exec(
    worker: &Path,
    worker_arguments: &[String],
    profile: ValidatedIsolationProfileV2,
) -> Result<(), WorkerSandboxErrorV2> {
    close_untrusted_descriptors()?;
    // SAFETY: the production wrapper invokes this function from its
    // single-threaded main before any worker-controlled code runs. The child
    // installs irreversible limits and Seatbelt before exec; the parent
    // executes only the fixed physical-footprint monitor.
    let child = unsafe { libc::fork() };
    if child < 0 {
        return Err(WorkerSandboxErrorV2::SandboxUnavailable);
    }
    if child > 0 {
        return monitor_worker_footprint(child, profile.memory_limit_bytes);
    }
    apply_resource_limits(&profile)?;
    install_seatbelt(worker, &profile)?;
    exec_worker(worker, worker_arguments)
}

fn close_untrusted_descriptors() -> Result<(), WorkerSandboxErrorV2> {
    let maximum = nix::unistd::sysconf(nix::unistd::SysconfVar::OPEN_MAX)
        .map_err(|_| WorkerSandboxErrorV2::SandboxUnavailable)?
        .ok_or(WorkerSandboxErrorV2::SandboxUnavailable)?;
    let maximum = i32::try_from(maximum).map_err(|_| WorkerSandboxErrorV2::SandboxUnavailable)?;
    for descriptor in 3..maximum {
        let _ = nix::unistd::close(descriptor);
    }
    Ok(())
}

fn apply_resource_limits(
    profile: &ValidatedIsolationProfileV2,
) -> Result<(), WorkerSandboxErrorV2> {
    for (resource, value) in [
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
        // SAFETY: `limit` is fully initialized for the named resource. Any
        // failure aborts before sandbox entry or worker execution.
        if unsafe { libc::setrlimit(resource, &limit) } != 0 {
            return Err(WorkerSandboxErrorV2::SandboxUnavailable);
        }
    }
    Ok(())
}

fn monitor_worker_footprint(
    child: libc::pid_t,
    limit_bytes: u64,
) -> Result<(), WorkerSandboxErrorV2> {
    loop {
        let mut status = 0;
        // SAFETY: `status` is live writable storage and `child` is the exact
        // direct child returned by fork.
        let waited = unsafe { libc::waitpid(child, &mut status, libc::WNOHANG) };
        if waited == child {
            // SAFETY: these macros only inspect the initialized wait status.
            if libc::WIFEXITED(status) {
                let code = libc::WEXITSTATUS(status);
                // SAFETY: the supervisor owns no buffered protocol output and
                // must preserve the exact worker exit status.
                unsafe { libc::_exit(code) };
            }
            return Err(WorkerSandboxErrorV2::ExecutionFailed);
        }
        if waited < 0 {
            return Err(WorkerSandboxErrorV2::SandboxUnavailable);
        }

        // SAFETY: this plain-old-data kernel ABI structure permits an all-zero
        // initialization before proc_pid_rusage fills every V4 field.
        let mut usage: libc::rusage_info_v4 = unsafe { std::mem::zeroed() };
        // SAFETY: the cast follows libproc's documented `rusage_info_t *`
        // convention and points to writable V4-sized storage.
        let usage_result = unsafe {
            libc::proc_pid_rusage(
                child,
                libc::RUSAGE_INFO_V4,
                (&mut usage as *mut libc::rusage_info_v4).cast(),
            )
        };
        if usage_result != 0 {
            terminate_worker(child);
            return Err(WorkerSandboxErrorV2::SandboxUnavailable);
        }
        if usage.ri_phys_footprint > limit_bytes {
            terminate_worker(child);
            return Err(WorkerSandboxErrorV2::SandboxUnavailable);
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
}

fn terminate_worker(child: libc::pid_t) {
    // SAFETY: `child` is the exact child PID and SIGKILL is used only after an
    // enforcement or monitor failure. A blocking reap prevents a zombie.
    unsafe {
        libc::kill(child, libc::SIGKILL);
        libc::waitpid(child, std::ptr::null_mut(), 0);
    }
}

fn install_seatbelt(
    worker: &Path,
    profile: &ValidatedIsolationProfileV2,
) -> Result<(), WorkerSandboxErrorV2> {
    let worker = sandbox_literal(worker)?;
    let mut policy = String::from(
        "(version 1)\n\
         (deny default)\n\
         (allow process-exec (literal \"",
    );
    policy.push_str(&worker);
    policy.push_str(
        "\"))\n\
         (allow file-read* (literal \"",
    );
    policy.push_str(&worker);
    policy.push_str(
        "\"))\n\
         (allow file-read-data (literal \"/\"))\n\
         (allow file-read* (subpath \"/System\"))\n\
         (allow file-read* (subpath \"/usr/lib\"))\n\
         (allow file-read* (subpath \"/Library/Apple/System\"))\n\
         (allow sysctl-read)\n\
         (allow signal (target self))\n",
    );
    for path in &profile.read_only_paths {
        let literal = sandbox_literal(path)?;
        let metadata =
            std::fs::metadata(path).map_err(|_| WorkerSandboxErrorV2::SandboxUnavailable)?;
        if metadata.is_dir() {
            policy.push_str("(allow file-read* (subpath \"");
        } else if metadata.is_file() {
            policy.push_str("(allow file-read* (literal \"");
        } else {
            return Err(WorkerSandboxErrorV2::SandboxUnavailable);
        }
        policy.push_str(&literal);
        policy.push_str("\"))\n");
    }
    let policy = CString::new(policy).map_err(|_| WorkerSandboxErrorV2::SandboxUnavailable)?;
    let mut error = std::ptr::null_mut();
    // SAFETY: `policy` is a live NUL-terminated custom Seatbelt profile and
    // `error` points to writable storage for the optional library-owned error.
    // A nonzero result aborts without executing the worker.
    let result = unsafe { sandbox_init(policy.as_ptr(), 0, &mut error) };
    if !error.is_null() {
        // SAFETY: a non-null error is allocated by sandbox_init and must be
        // released exactly once with sandbox_free_error.
        unsafe { sandbox_free_error(error) };
    }
    if result != 0 {
        return Err(WorkerSandboxErrorV2::SandboxUnavailable);
    }
    Ok(())
}

fn sandbox_literal(path: &Path) -> Result<String, WorkerSandboxErrorV2> {
    let value = path.to_str().ok_or(WorkerSandboxErrorV2::InvalidProfile)?;
    if !path.is_absolute()
        || value
            .bytes()
            .any(|byte| byte < 0x20 || matches!(byte, b'"' | b'\\' | b'(' | b')'))
    {
        return Err(WorkerSandboxErrorV2::InvalidProfile);
    }
    Ok(value.to_owned())
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
    // SAFETY: all strings and both pointer arrays remain live and
    // NUL-terminated for the syscall. Success replaces the process.
    unsafe {
        libc::execve(worker.as_ptr(), pointers.as_ptr(), environment.as_ptr());
    }
    Err(WorkerSandboxErrorV2::ExecutionFailed)
}

#[link(name = "System")]
unsafe extern "C" {
    fn sandbox_init(
        profile: *const libc::c_char,
        flags: u64,
        error_buffer: *mut *mut libc::c_char,
    ) -> libc::c_int;
    fn sandbox_free_error(error_buffer: *mut libc::c_char);
}
