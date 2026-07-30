use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

const PRODUCTION_CONFIG_PATH_V2: &str = "/etc/savana/agentd-bootstrap-v2.json";
#[cfg(all(target_os = "macos", feature = "macos-development-authority"))]
const DEVELOPMENT_CONFIG_PATH_V2: &str =
    "/Library/Application Support/Savana/Development/config/agentd-bootstrap-v2.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CliError;

fn parse_args(mut arguments: impl Iterator<Item = OsString>) -> Result<PathBuf, CliError> {
    let _program = arguments.next().ok_or(CliError)?;
    let token = arguments.next().ok_or(CliError)?;
    let path = PathBuf::from(arguments.next().ok_or(CliError)?);
    if token != OsStr::new("--config")
        || (path != Path::new(PRODUCTION_CONFIG_PATH_V2) && !development_config_path(&path))
        || arguments.next().is_some()
    {
        return Err(CliError);
    }
    Ok(path)
}

fn development_config_path(path: &Path) -> bool {
    #[cfg(all(target_os = "macos", feature = "macos-development-authority"))]
    {
        path == Path::new(DEVELOPMENT_CONFIG_PATH_V2)
    }
    #[cfg(not(all(target_os = "macos", feature = "macos-development-authority")))]
    {
        let _ = path;
        false
    }
}

fn main() {
    let exit_code = match parse_args(std::env::args_os()) {
        Ok(path) => savana_agentd::run(&path).map_or(1, |()| 0),
        Err(_) => 64,
    };
    std::process::exit(exit_code);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_accepts_only_the_fixed_production_bootstrap() {
        assert!(parse_args(
            [
                OsString::from("savana-agentd"),
                OsString::from("--config"),
                OsString::from(PRODUCTION_CONFIG_PATH_V2),
            ]
            .into_iter(),
        )
        .is_ok());
        #[cfg(all(target_os = "macos", feature = "macos-development-authority"))]
        assert!(parse_args(
            [
                OsString::from("savana-agentd"),
                OsString::from("--config"),
                OsString::from(DEVELOPMENT_CONFIG_PATH_V2),
            ]
            .into_iter(),
        )
        .is_ok());
        assert_eq!(
            parse_args(
                [
                    OsString::from("savana-agentd"),
                    OsString::from("--config"),
                    OsString::from("/tmp/agentd.json"),
                ]
                .into_iter(),
            ),
            Err(CliError)
        );
    }
}
