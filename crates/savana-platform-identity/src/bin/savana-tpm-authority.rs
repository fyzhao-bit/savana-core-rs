#[cfg(target_os = "linux")]
fn main() {
    if std::env::args_os().len() != 1 {
        std::process::exit(64);
    }
    if savana_platform_identity::run_linux_tpm_authority_v3().is_err() {
        eprintln!("native TPM authority unavailable");
        std::process::exit(1);
    }
}
#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("native TPM authority requires Linux");
    std::process::exit(64);
}
