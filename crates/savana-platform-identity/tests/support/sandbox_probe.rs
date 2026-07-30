use std::io::ErrorKind;
use std::net::TcpStream;
use std::process::ExitCode;
use std::time::Duration;

fn main() -> ExitCode {
    match std::env::args().nth(1).as_deref() {
        Some("ok") => ExitCode::SUCCESS,
        Some("forbidden-file") => {
            let data_denied = std::fs::File::open("/etc/passwd")
                .is_err_and(|error| error.kind() == ErrorKind::PermissionDenied);
            let metadata_denied = std::fs::metadata("/etc/passwd")
                .is_err_and(|error| error.kind() == ErrorKind::PermissionDenied);
            if data_denied && metadata_denied {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(70)
            }
        }
        Some("forbidden-network") => match TcpStream::connect("127.0.0.1:9") {
            Err(error) if error.kind() == ErrorKind::PermissionDenied => ExitCode::SUCCESS,
            _ => ExitCode::from(71),
        },
        Some("exceed-memory") => {
            let allocation = vec![0xa5_u8; 32 * 1024 * 1024];
            std::hint::black_box(&allocation);
            std::thread::sleep(Duration::from_secs(2));
            ExitCode::from(72)
        }
        _ => ExitCode::from(64),
    }
}
