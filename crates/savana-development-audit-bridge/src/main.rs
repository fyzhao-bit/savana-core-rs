#![forbid(unsafe_code)]

use std::path::Path;
use std::process::ExitCode;
use std::sync::atomic::AtomicBool;

use nix::unistd::User;
use savana_development_audit_bridge::{run_with_paths, FIFO_PATH, LOG_PATH};

fn main() -> ExitCode {
    if std::env::args_os().len() != 1 {
        return ExitCode::from(64);
    }
    let kernel_uid = match User::from_name("_savana_kernel_dev") {
        Ok(Some(user)) => user.uid.as_raw(),
        Ok(None) | Err(_) => return unavailable(),
    };
    let stop = AtomicBool::new(false);
    match run_with_paths(Path::new(FIFO_PATH), Path::new(LOG_PATH), kernel_uid, &stop) {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => unavailable(),
    }
}

fn unavailable() -> ExitCode {
    eprintln!("Savana development audit bridge unavailable");
    ExitCode::from(70)
}
