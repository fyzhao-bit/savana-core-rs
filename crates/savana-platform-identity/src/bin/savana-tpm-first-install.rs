fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    #[cfg(target_os = "linux")]
    let ok = args.len() == 1
        && savana_platform_identity::run_linux_tpm_first_install_v3(&args[0]).is_ok();
    #[cfg(not(target_os = "linux"))]
    let ok = {
        let _ = args;
        false
    };
    if !ok {
        eprintln!("TPM first installation stopped; do not clear hardware or retry occupied slots");
        std::process::exit(2);
    }
}
