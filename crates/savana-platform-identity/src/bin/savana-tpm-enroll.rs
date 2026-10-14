//! Offline stdin/stdout enrollment authoring. This process never accesses TPM
//! devices, private signing keys, system services or installed kernel state.
use std::io::{Read, Write};

fn run() -> Result<(), ()> {
    if std::env::args_os().len() != 1 {
        return Err(());
    }
    let mut input = Vec::new();
    std::io::stdin()
        .take(16 * 1024 + 1)
        .read_to_end(&mut input)
        .map_err(|_| ())?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| ())?
        .as_secs();
    let output =
        savana_platform_identity::process_tpm_enrollment_request_v3(&input, now).map_err(|_| ())?;
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(&output).map_err(|_| ())?;
    stdout.write_all(b"\n").map_err(|_| ())?;
    Ok(())
}
fn main() {
    if run().is_err() {
        // Do not reflect paths, credentials or submitted material in diagnostics.
        eprintln!("TPM enrollment request rejected; no state changed");
        std::process::exit(2);
    }
}
