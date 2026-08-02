use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::fs::{self, File};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use rustix::fs::{
    fchmod, open as rustix_open, openat, renameat, statat, unlinkat, AtFlags, FileType, Mode,
    OFlags,
};
use rustix::io::Errno;
use savana_policy_core::v2::{
    measured_model_destination_ips_v2, parse_measured_model_connect_addresses_v2,
};
use serde::Deserialize;

const MAX_BOOTSTRAP_BYTES_V2: u64 = 1024 * 1024;
const MAX_DROP_IN_BYTES_V2: u64 = 16 * 1024;
const DROP_IN_DIRECTORY_V2: &str = "/etc/systemd/system/savana-agentd.service.d";
const DROP_IN_LEAF_V2: &str = "20-measured-network.conf";
const TEMPORARY_ATTEMPTS_V2: usize = 16;

#[derive(Deserialize)]
struct AgentdNetworkBootstrapV2 {
    planner_host: String,
    planner_port: u16,
    planner_connect_addresses: Vec<String>,
    private_mapper_host: String,
    private_mapper_port: u16,
    private_mapper_connect_addresses: Vec<String>,
    intent_trust_deployment_ceiling: u16,
    #[serde(default)]
    third_party_mapper_host: Option<String>,
    #[serde(default)]
    third_party_mapper_port: Option<u16>,
    #[serde(default)]
    third_party_mapper_server_spki_sha256: Option<String>,
    #[serde(default)]
    third_party_mapper_connect_addresses: Option<Vec<String>>,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(66);
    }
}

fn run() -> Result<(), String> {
    let arguments = std::env::args_os().collect::<Vec<_>>();
    if arguments.len() != 3 {
        return Err(
            "usage: savana-systemd-agentd-network-policy-v2 <render|install|validate> <absolute-agentd-bootstrap>"
                .to_owned(),
        );
    }
    let operation = arguments[1]
        .to_str()
        .ok_or_else(|| "network policy operation is not UTF-8".to_owned())?;
    let bootstrap = PathBuf::from(&arguments[2]);
    require_absolute_regular_input(&bootstrap, MAX_BOOTSTRAP_BYTES_V2)?;
    let expected = render_policy(&bootstrap)?;
    match operation {
        "render" => std::io::stdout()
            .write_all(expected.as_bytes())
            .map_err(|_| "network policy cannot be rendered".to_owned()),
        "install" => {
            require_root()?;
            SecureDropInDirectoryV2::open()?.replace(expected.as_bytes())
        }
        "validate" => SecureDropInDirectoryV2::open()?.validate(expected.as_bytes()),
        _ => Err("unknown network policy operation".to_owned()),
    }
}

fn render_policy(bootstrap_path: &Path) -> Result<String, String> {
    let bootstrap: AgentdNetworkBootstrapV2 =
        serde_json::from_slice(&read_bounded_path(bootstrap_path, MAX_BOOTSTRAP_BYTES_V2)?)
            .map_err(|_| "agentd bootstrap network measurements are invalid".to_owned())?;
    if !valid_dns_identity(&bootstrap.planner_host)
        || !valid_dns_identity(&bootstrap.private_mapper_host)
    {
        return Err("model TLS identity is invalid".to_owned());
    }
    let planner = parse_measured_model_connect_addresses_v2(
        &bootstrap.planner_connect_addresses,
        bootstrap.planner_port,
    )
    .map_err(|_| "planner connect addresses are invalid".to_owned())?;
    let mapper = parse_measured_model_connect_addresses_v2(
        &bootstrap.private_mapper_connect_addresses,
        bootstrap.private_mapper_port,
    )
    .map_err(|_| "private mapper connect addresses are invalid".to_owned())?;

    let third_party = match (
        bootstrap.third_party_mapper_host.as_deref(),
        bootstrap.third_party_mapper_port,
        bootstrap.third_party_mapper_server_spki_sha256.as_deref(),
        bootstrap.third_party_mapper_connect_addresses.as_deref(),
    ) {
        (None, None, None, None) => None,
        (Some(host), Some(port), Some(pin), Some(connect_addresses))
            if valid_dns_identity(host) && valid_nonzero_hex_32(pin) =>
        {
            Some(
                parse_measured_model_connect_addresses_v2(connect_addresses, port)
                    .map_err(|_| "third-party mapper connect addresses are invalid".to_owned())?,
            )
        }
        _ => return Err("third-party mapper deployment is incomplete".to_owned()),
    };
    match bootstrap.intent_trust_deployment_ceiling {
        1 if third_party.is_some() => {
            return Err("PrivateOnly deployment contains third-party network access".to_owned())
        }
        1 | 2 => {}
        _ => return Err("intent trust deployment ceiling is invalid".to_owned()),
    }

    let mut ips = BTreeSet::new();
    ips.extend(measured_model_destination_ips_v2(&planner));
    ips.extend(measured_model_destination_ips_v2(&mapper));
    if let Some(third_party) = third_party {
        ips.extend(measured_model_destination_ips_v2(&third_party));
    }
    if ips.is_empty() {
        return Err("model destination allowlist is empty".to_owned());
    }
    let mut output = String::from("[Service]\nIPAddressDeny=any\n");
    for ip in ips {
        output.push_str("IPAddressAllow=");
        output.push_str(&ip.to_string());
        output.push('\n');
    }
    Ok(output)
}

struct SecureDropInDirectoryV2 {
    parent: File,
    parent_path: PathBuf,
    device: u64,
    inode: u64,
}

impl SecureDropInDirectoryV2 {
    fn open() -> Result<Self, String> {
        let parent_path = PathBuf::from(DROP_IN_DIRECTORY_V2);
        let before = fs::symlink_metadata(&parent_path)
            .map_err(|_| "measured network drop-in directory is unavailable".to_owned())?;
        if before.file_type().is_symlink() || !valid_parent_metadata(&before) {
            return Err("measured network drop-in directory is unsafe".to_owned());
        }
        let descriptor = rustix_open(
            &parent_path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| "measured network drop-in directory cannot be pinned".to_owned())?;
        let parent = File::from(descriptor);
        let opened = parent
            .metadata()
            .map_err(|_| "measured network drop-in directory cannot be measured".to_owned())?;
        if !same_metadata(&before, &opened) || !valid_parent_metadata(&opened) {
            return Err("measured network drop-in directory changed during open".to_owned());
        }
        let value = Self {
            parent,
            parent_path,
            device: opened.dev(),
            inode: opened.ino(),
        };
        value.recheck_parent()?;
        Ok(value)
    }

    fn replace(&self, bytes: &[u8]) -> Result<(), String> {
        validate_rendered_bytes(bytes)?;
        self.recheck_parent()?;
        let (temporary_leaf, mut temporary) = self.create_temporary()?;
        let before_rename = (|| {
            temporary
                .write_all(bytes)
                .and_then(|()| temporary.sync_all())
                .map_err(|_| "temporary measured network policy cannot be committed".to_owned())?;
            validate_open_file(&self.parent, &temporary_leaf, &temporary, bytes.len())?;
            self.recheck_parent()
        })();
        if before_rename.is_err() {
            let _ = unlinkat(&self.parent, &temporary_leaf, AtFlags::empty());
            return before_rename;
        }
        if renameat(&self.parent, &temporary_leaf, &self.parent, DROP_IN_LEAF_V2).is_err() {
            let _ = unlinkat(&self.parent, &temporary_leaf, AtFlags::empty());
            return Err("measured network policy cannot be installed atomically".to_owned());
        }
        validate_open_file(
            &self.parent,
            OsStr::new(DROP_IN_LEAF_V2),
            &temporary,
            bytes.len(),
        )?;
        self.parent
            .sync_all()
            .map_err(|_| "measured network policy directory cannot be committed".to_owned())?;
        self.recheck_parent()?;
        self.validate(bytes)
    }

    fn validate(&self, expected: &[u8]) -> Result<(), String> {
        validate_rendered_bytes(expected)?;
        self.recheck_parent()?;
        let before = statat(&self.parent, DROP_IN_LEAF_V2, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| "measured network drop-in is unavailable".to_owned())?;
        if !valid_file_stat(&before, expected.len()) {
            return Err("measured network drop-in metadata is invalid".to_owned());
        }
        let descriptor = openat(
            &self.parent,
            DROP_IN_LEAF_V2,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| "measured network drop-in cannot be opened".to_owned())?;
        let mut file = File::from(descriptor);
        validate_open_file(
            &self.parent,
            OsStr::new(DROP_IN_LEAF_V2),
            &file,
            expected.len(),
        )?;
        let mut observed = Vec::new();
        observed
            .try_reserve_exact(expected.len())
            .map_err(|_| "measured network drop-in cannot be allocated".to_owned())?;
        file.read_to_end(&mut observed)
            .map_err(|_| "measured network drop-in cannot be read".to_owned())?;
        if observed != expected {
            return Err("measured network drop-in does not match bootstrap".to_owned());
        }
        validate_open_file(
            &self.parent,
            OsStr::new(DROP_IN_LEAF_V2),
            &file,
            expected.len(),
        )?;
        self.recheck_parent()
    }

    fn create_temporary(&self) -> Result<(OsString, File), String> {
        for _ in 0..TEMPORARY_ATTEMPTS_V2 {
            let mut random = [0_u8; 16];
            getrandom::getrandom(&mut random)
                .map_err(|_| "temporary network policy name entropy failed".to_owned())?;
            let leaf = OsString::from(format!(
                ".{DROP_IN_LEAF_V2}.tmp-{:032x}",
                u128::from_be_bytes(random)
            ));
            match openat(
                &self.parent,
                &leaf,
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from_bits_truncate(0o444),
            ) {
                Ok(descriptor) => {
                    let file = File::from(descriptor);
                    fchmod(&file, Mode::from_bits_truncate(0o444)).map_err(|_| {
                        "temporary network policy permissions cannot be fixed".to_owned()
                    })?;
                    validate_open_file(&self.parent, &leaf, &file, 0)?;
                    return Ok((leaf, file));
                }
                Err(Errno::EXIST) => {}
                Err(_) => {
                    return Err("temporary network policy cannot be created".to_owned());
                }
            }
        }
        Err("temporary network policy name attempts exhausted".to_owned())
    }

    fn recheck_parent(&self) -> Result<(), String> {
        let opened = self
            .parent
            .metadata()
            .map_err(|_| "measured network drop-in directory cannot be remeasured".to_owned())?;
        let linked = fs::symlink_metadata(&self.parent_path)
            .map_err(|_| "measured network drop-in directory disappeared".to_owned())?;
        if linked.file_type().is_symlink()
            || !valid_parent_metadata(&opened)
            || !valid_parent_metadata(&linked)
            || opened.dev() != self.device
            || opened.ino() != self.inode
            || linked.dev() != self.device
            || linked.ino() != self.inode
        {
            return Err("measured network drop-in directory identity changed".to_owned());
        }
        Ok(())
    }
}

fn validate_open_file(
    parent: &File,
    leaf: &OsStr,
    file: &File,
    expected_length: usize,
) -> Result<(), String> {
    let opened = file
        .metadata()
        .map_err(|_| "measured network drop-in cannot be measured".to_owned())?;
    let linked = statat(parent, leaf, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| "measured network drop-in link cannot be measured".to_owned())?;
    if !valid_open_file_metadata(&opened, expected_length)
        || !valid_file_stat(&linked, expected_length)
        || i128::from(linked.st_dev) != i128::from(opened.dev())
        || linked.st_ino != opened.ino()
    {
        return Err("measured network drop-in identity is invalid".to_owned());
    }
    Ok(())
}

fn valid_parent_metadata(metadata: &fs::Metadata) -> bool {
    metadata.is_dir()
        && metadata.uid() == 0
        && metadata.gid() == 0
        && metadata.mode() & 0o7777 == 0o755
        && metadata.nlink() >= 2
}

fn valid_open_file_metadata(metadata: &fs::Metadata, expected_length: usize) -> bool {
    metadata.is_file()
        && metadata.uid() == 0
        && metadata.gid() == 0
        && metadata.mode() & 0o7777 == 0o444
        && metadata.nlink() == 1
        && metadata.len() == u64::try_from(expected_length).unwrap_or(u64::MAX)
}

fn valid_file_stat(stat: &rustix::fs::Stat, expected_length: usize) -> bool {
    FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile
        && stat.st_uid == 0
        && stat.st_gid == 0
        && stat.st_mode & 0o7777 == 0o444
        && stat.st_nlink == 1
        && stat.st_size == i64::try_from(expected_length).unwrap_or(-1)
}

fn same_metadata(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.uid() == right.uid()
        && left.gid() == right.gid()
        && left.mode() == right.mode()
}

fn require_root() -> Result<(), String> {
    if rustix::process::geteuid().as_raw() != 0 || rustix::process::getegid().as_raw() != 0 {
        return Err("network policy installation requires root:root".to_owned());
    }
    Ok(())
}

fn validate_rendered_bytes(bytes: &[u8]) -> Result<(), String> {
    if bytes.is_empty() || u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_DROP_IN_BYTES_V2 {
        return Err("rendered network policy is outside bounds".to_owned());
    }
    Ok(())
}

fn require_absolute_regular_input(path: &Path, maximum: u64) -> Result<(), String> {
    if !path.is_absolute() {
        return Err("network policy path must be absolute".to_owned());
    }
    let metadata =
        fs::symlink_metadata(path).map_err(|_| "network policy input is unavailable".to_owned())?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() == 0
        || metadata.len() > maximum
    {
        return Err("network policy input is unsafe".to_owned());
    }
    Ok(())
}

fn read_bounded_path(path: &Path, maximum: u64) -> Result<Vec<u8>, String> {
    let file = File::open(path).map_err(|_| "network policy input cannot be opened".to_owned())?;
    let mut bytes = Vec::new();
    file.take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| "network policy input cannot be read".to_owned())?;
    if bytes.is_empty() || u64::try_from(bytes.len()).unwrap_or(u64::MAX) > maximum {
        return Err("network policy input is outside bounds".to_owned());
    }
    Ok(bytes)
}

fn valid_nonzero_hex_32(value: &str) -> bool {
    value.len() == 64
        && value.bytes().all(|byte| byte.is_ascii_hexdigit())
        && value.bytes().any(|byte| byte != b'0')
}

fn valid_dns_identity(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

#[cfg(test)]
mod tests {
    use super::{valid_file_stat, valid_open_file_metadata, valid_parent_metadata};

    #[test]
    fn metadata_contract_requires_root_owned_exact_modes_and_single_link() {
        let fixture = tempfile::tempdir().unwrap();
        let parent = fixture.path().metadata().unwrap();
        assert!(!valid_parent_metadata(&parent));
        let file_path = fixture.path().join("drop-in");
        std::fs::write(&file_path, b"x").unwrap();
        let file = file_path.metadata().unwrap();
        assert!(!valid_open_file_metadata(&file, 1));
        let stat = rustix::fs::stat(&file_path).unwrap();
        assert!(!valid_file_stat(&stat, 1));
    }
}
