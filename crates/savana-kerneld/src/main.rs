use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

const PRODUCTION_CONFIG_PATH_V2: &str = "/etc/savana/kerneld-bootstrap-v2.json";
#[cfg(all(target_os = "macos", feature = "macos-development-authority"))]
const DEVELOPMENT_CONFIG_PATH_V2: &str =
    "/Library/Application Support/Savana/Development/config/kerneld-bootstrap-v2.json";
#[cfg(all(feature = "test-support", debug_assertions))]
const TEST_V1_RUNTIME_ENV: &str = "SAVANA_TEST_V1_RUNTIME";
#[cfg(all(feature = "test-support", debug_assertions))]
const TEST_V1_RUNTIME_VALUE: &str = "frozen-regression-v1";
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CliError;

fn parse_args(
    mut arguments: impl Iterator<Item = OsString>,
    allow_test_support_path: bool,
) -> Result<PathBuf, CliError> {
    let _program = arguments.next().ok_or(CliError)?;
    let token = arguments.next().ok_or(CliError)?;
    let path = PathBuf::from(arguments.next().ok_or(CliError)?);
    if token != OsStr::new("--config")
        || (path != Path::new(PRODUCTION_CONFIG_PATH_V2)
            && !development_config_path(&path)
            && !(allow_test_support_path && path.is_absolute()))
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
    #[cfg(all(feature = "test-support", debug_assertions))]
    let allow_test_support_path = std::env::var_os(TEST_V1_RUNTIME_ENV)
        .as_deref()
        .is_some_and(|value| value == OsStr::new(TEST_V1_RUNTIME_VALUE));
    #[cfg(not(all(feature = "test-support", debug_assertions)))]
    let allow_test_support_path = false;
    let exit_code = match parse_args(std::env::args_os(), allow_test_support_path) {
        Ok(path) => match savana_kerneld::run(&path) {
            Ok(()) => 0,
            Err(_) => 1,
        },
        Err(_) => 64,
    };
    std::process::exit(exit_code);
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::path::Path;

    use super::*;

    #[test]
    fn cli_accepts_only_the_exact_token_and_one_absolute_path() {
        assert_eq!(
            parse_args(
                [
                    OsString::from("savana-kerneld"),
                    OsString::from("--config"),
                    OsString::from(PRODUCTION_CONFIG_PATH_V2),
                ]
                .into_iter(),
                false,
            )
            .unwrap(),
            Path::new(PRODUCTION_CONFIG_PATH_V2)
        );
        #[cfg(all(target_os = "macos", feature = "macos-development-authority"))]
        assert_eq!(
            parse_args(
                [
                    OsString::from("savana-kerneld"),
                    OsString::from("--config"),
                    OsString::from(DEVELOPMENT_CONFIG_PATH_V2),
                ]
                .into_iter(),
                false,
            )
            .unwrap(),
            Path::new(DEVELOPMENT_CONFIG_PATH_V2)
        );

        for arguments in [
            vec![OsString::from("savana-kerneld")],
            vec![OsString::from("savana-kerneld"), OsString::from("--config")],
            vec![
                OsString::from("savana-kerneld"),
                OsString::from("-c"),
                OsString::from(PRODUCTION_CONFIG_PATH_V2),
            ],
            vec![
                OsString::from("savana-kerneld"),
                OsString::from("--config"),
                OsString::from("relative.json"),
            ],
            vec![
                OsString::from("savana-kerneld"),
                OsString::from("--config"),
                OsString::from(PRODUCTION_CONFIG_PATH_V2),
                OsString::from("extra"),
            ],
        ] {
            assert_eq!(parse_args(arguments.into_iter(), false), Err(CliError));
        }
        assert!(parse_args(
            [
                OsString::from("savana-kerneld"),
                OsString::from("--config"),
                OsString::from("/tmp/v1-test-support.json"),
            ]
            .into_iter(),
            true,
        )
        .is_ok());
    }
}
