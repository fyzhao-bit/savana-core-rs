use std::ffi::{OsStr, OsString};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CliError;

fn parse_args(mut arguments: impl Iterator<Item = OsString>) -> Result<PathBuf, CliError> {
    let _program = arguments.next().ok_or(CliError)?;
    let token = arguments.next().ok_or(CliError)?;
    let path = PathBuf::from(arguments.next().ok_or(CliError)?);
    if token != OsStr::new("--config") || !path.is_absolute() || arguments.next().is_some() {
        return Err(CliError);
    }
    Ok(path)
}

fn main() {
    let exit_code = match parse_args(std::env::args_os()) {
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
                    OsString::from("/etc/savana/kerneld-bootstrap-v1.json"),
                ]
                .into_iter()
            )
            .unwrap(),
            Path::new("/etc/savana/kerneld-bootstrap-v1.json")
        );

        for arguments in [
            vec![OsString::from("savana-kerneld")],
            vec![OsString::from("savana-kerneld"), OsString::from("--config")],
            vec![
                OsString::from("savana-kerneld"),
                OsString::from("-c"),
                OsString::from("/etc/savana/kerneld-bootstrap-v1.json"),
            ],
            vec![
                OsString::from("savana-kerneld"),
                OsString::from("--config"),
                OsString::from("relative.json"),
            ],
            vec![
                OsString::from("savana-kerneld"),
                OsString::from("--config"),
                OsString::from("/etc/savana/kerneld-bootstrap-v1.json"),
                OsString::from("extra"),
            ],
        ] {
            assert_eq!(parse_args(arguments.into_iter()), Err(CliError));
        }
    }
}
