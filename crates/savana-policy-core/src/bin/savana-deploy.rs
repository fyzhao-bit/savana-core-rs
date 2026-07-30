mod support;

fn main() {
    if let Err(error) = support::run_apply(std::env::args_os()) {
        std::process::exit(error.exit_code());
    }
}
