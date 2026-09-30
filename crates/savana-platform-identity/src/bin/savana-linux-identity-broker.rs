#[cfg(target_os = "linux")]
fn main() {
    if std::env::args_os().len() != 1 {
        std::process::exit(64);
    }
    if savana_platform_identity::run_linux_identity_broker_v2().is_err() {
        // Do not publish measured paths, process metadata or request contents.
        eprintln!("native identity broker startup failed");
        std::process::exit(1);
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("native identity broker requires Linux");
    std::process::exit(64);
}
