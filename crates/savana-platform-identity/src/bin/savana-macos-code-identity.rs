#![forbid(unsafe_code)]

#[cfg(all(feature = "macos-development-authority", not(debug_assertions)))]
compile_error!("macos-development-authority is forbidden in release builds");

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("savana-macos-code-identity is available only on macOS");
    std::process::exit(69);
}

#[cfg(target_os = "macos")]
fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(70);
    }
}

#[cfg(target_os = "macos")]
fn run() -> Result<(), &'static str> {
    let mut arguments = std::env::args_os().skip(1);
    let path = arguments.next().ok_or("expected executable path")?;
    let expected_bundle = arguments
        .next()
        .and_then(|value| value.into_string().ok())
        .ok_or("expected bundle identifier")?;
    let expected_team = arguments
        .next()
        .and_then(|value| value.into_string().ok())
        .ok_or("expected team identifier")?;
    if arguments.next().is_some()
        || !std::path::Path::new(&path).is_absolute()
        || expected_team != "SAVANADEV1"
    {
        return Err("invalid closed code-identity invocation");
    }
    let measurement =
        savana_platform_identity::measure_macos_static_code_v2(std::path::Path::new(&path))
            .map_err(|_| "Security.framework rejected the executable")?;
    if measurement.bundle_id().as_str() != expected_bundle
        || measurement.team_id().as_str() != expected_team
    {
        return Err("measured bundle or team identity does not match");
    }
    let value = serde_json::json!({
        "bundle_id": measurement.bundle_id().as_str(),
        "team_id": measurement.team_id().as_str(),
        "code_directory_measurement": hex(measurement.code_directory_measurement()),
        "designated_requirement_measurement": hex(
            measurement.designated_requirement_measurement()
        ),
        "entitlement_measurement": hex(measurement.entitlement_measurement()),
    });
    println!(
        "{}",
        serde_json::to_string(&value).map_err(|_| "identity serialization failed")?
    );
    Ok(())
}

#[cfg(target_os = "macos")]
fn hex(bytes: [u8; 32]) -> String {
    use std::fmt::Write as _;

    let mut encoded = String::with_capacity(64);
    for byte in bytes {
        write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}
