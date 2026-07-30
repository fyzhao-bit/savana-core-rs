use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

const PRODUCTION_CONFIG_PATH_V2: &str = "/etc/savana/ingressd-bootstrap-v2.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CliError;

fn parse_args(mut arguments: impl Iterator<Item = OsString>) -> Result<PathBuf, CliError> {
    let _program = arguments.next().ok_or(CliError)?;
    let token = arguments.next().ok_or(CliError)?;
    let path = PathBuf::from(arguments.next().ok_or(CliError)?);
    if token != OsStr::new("--config")
        || path != Path::new(PRODUCTION_CONFIG_PATH_V2)
        || arguments.next().is_some()
    {
        return Err(CliError);
    }
    Ok(path)
}

fn main() {
    let exit_code = match parse_args(std::env::args_os()) {
        Ok(path) => savana_ingressd::run(&path).map_or(1, |()| 0),
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
                OsString::from("savana-ingressd"),
                OsString::from("--config"),
                OsString::from(PRODUCTION_CONFIG_PATH_V2),
            ]
            .into_iter()
        )
        .is_ok());
        assert!(parse_args(
            [
                OsString::from("savana-ingressd"),
                OsString::from("--config"),
                OsString::from("/tmp/ingressd.json"),
            ]
            .into_iter()
        )
        .is_err());
    }
}
