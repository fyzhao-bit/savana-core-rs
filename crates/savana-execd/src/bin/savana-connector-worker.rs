#![forbid(unsafe_code)]

fn main() {
    if savana_execd::run_connector_worker_stdio_v2().is_err() {
        std::process::exit(1);
    }
}
