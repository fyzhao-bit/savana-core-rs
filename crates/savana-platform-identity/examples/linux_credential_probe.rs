//! Synthetic, non-secret credential loader check. Not installed in a deployment.
#![forbid(unsafe_code)]

#[cfg(not(target_os = "linux"))]
fn main() {
    std::process::exit(69);
}

#[cfg(target_os = "linux")]
fn main() {
    use savana_platform_identity::{read_linux_service_credential_v2, LinuxCredentialServiceV2};
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() != 3 {
        std::process::exit(64);
    }
    let service = match args[0].as_str() {
        "kernel" => LinuxCredentialServiceV2::Kernel,
        "agent" => LinuxCredentialServiceV2::Agent,
        "ingress" => LinuxCredentialServiceV2::Ingress,
        "approval" => LinuxCredentialServiceV2::Approval,
        "exec" => LinuxCredentialServiceV2::Executor,
        _ => std::process::exit(64),
    };
    let maximum = match args[1].parse::<usize>() {
        Ok(v) => v,
        Err(_) => std::process::exit(64),
    };
    let result = read_linux_service_credential_v2(service, "synthetic.key", maximum);
    let success = match args[2].as_str() {
        "accept" => result.is_ok_and(|bytes| !bytes.is_empty() && bytes.iter().all(|b| *b == 0x37)),
        "reject" => result.is_err(),
        _ => false,
    };
    // Never output credential content, even for an unexpected real file.
    std::process::exit(if success { 0 } else { 1 });
}
