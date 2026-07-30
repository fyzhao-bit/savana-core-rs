fn main() {
    let result = savana_platform_identity::run_worker_sandbox_v2(std::env::args().skip(1));
    if let Err(error) = result {
        eprintln!("savana-worker-sandbox: {error}");
        std::process::exit(64);
    }
}
