use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write as _};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::AuthError;

const IDENTITY_VERSION: u8 = 2;
const MAX_IDENTITY_BYTES: u64 = 32 * 1024;
const TEMPORARY_ATTEMPTS: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum PublicCredentialState {
    Active,
    Revoked,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityDocument {
    version: u8,
    credential_digest: String,
    credential_id: String,
    public_credential_state: PublicCredentialState,
}

pub struct Identity {
    credential_digest: [u8; 32],
    credential_id: Zeroizing<Vec<u8>>,
    public_credential_state: PublicCredentialState,
}

impl Identity {
    pub fn load(path: &Path) -> Result<Self, AuthError> {
        let mut file = open_private_identity(path)?;
        let metadata = file
            .metadata()
            .map_err(|_| AuthError::AuthenticationFailed)?;
        let observed_length = metadata.len();
        let bytes = read_bounded_identity(&mut file, observed_length)?;
        validate_open_identity(path, &file, Some(observed_length))?;
        let document: IdentityDocument =
            serde_json::from_slice(&bytes).map_err(|_| AuthError::AuthenticationFailed)?;
        if document.version != IDENTITY_VERSION
            || serde_json::to_vec(&document).map_err(|_| AuthError::AuthenticationFailed)? != bytes
        {
            return Err(AuthError::AuthenticationFailed);
        }
        Self::from_document(document, AuthError::AuthenticationFailed)
    }

    pub(crate) fn persist(
        path: &Path,
        credential_digest: [u8; 32],
        credential_id: Vec<u8>,
        public_credential_state: PublicCredentialState,
    ) -> Result<Self, AuthError> {
        let identity = Self {
            credential_digest,
            credential_id: Zeroizing::new(credential_id),
            public_credential_state,
        };
        if identity.credential_digest == [0; 32] || identity.credential_id.is_empty() {
            return Err(AuthError::EnrollmentFailed);
        }
        let bytes =
            serde_json::to_vec(&identity.document()).map_err(|_| AuthError::EnrollmentFailed)?;
        atomic_replace(path, &bytes)?;
        Ok(identity)
    }

    pub(crate) fn credential_id(&self) -> &[u8] {
        &self.credential_id
    }

    pub(crate) const fn is_active(&self) -> bool {
        matches!(self.public_credential_state, PublicCredentialState::Active)
    }

    fn document(&self) -> IdentityDocument {
        IdentityDocument {
            version: IDENTITY_VERSION,
            credential_digest: URL_SAFE_NO_PAD.encode(self.credential_digest),
            credential_id: URL_SAFE_NO_PAD.encode(self.credential_id.as_slice()),
            public_credential_state: self.public_credential_state,
        }
    }

    fn from_document(document: IdentityDocument, error: AuthError) -> Result<Self, AuthError> {
        let credential_digest = decode_canonical_base64(&document.credential_digest)
            .and_then(|bytes| bytes.try_into().ok())
            .filter(|bytes: &[u8; 32]| bytes != &[0; 32])
            .ok_or(error)?;
        let credential_id = decode_canonical_base64(&document.credential_id)
            .filter(|bytes| !bytes.is_empty() && bytes.len() <= 4096)
            .ok_or(AuthError::AuthenticationFailed)?;
        Ok(Self {
            credential_digest,
            credential_id: Zeroizing::new(credential_id),
            public_credential_state: document.public_credential_state,
        })
    }
}

impl PartialEq for Identity {
    fn eq(&self, other: &Self) -> bool {
        self.credential_digest == other.credential_digest
            && self.credential_id == other.credential_id
            && self.public_credential_state == other.public_credential_state
    }
}

impl Eq for Identity {}

impl core::fmt::Debug for Identity {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("Identity(<public-credential>)")
    }
}

fn decode_canonical_base64(value: &str) -> Option<Vec<u8>> {
    let decoded = URL_SAFE_NO_PAD.decode(value).ok()?;
    (URL_SAFE_NO_PAD.encode(&decoded) == value).then_some(decoded)
}

fn normalized_parent(path: &Path) -> Result<&Path, AuthError> {
    let parent = path.parent().ok_or(AuthError::EnrollmentFailed)?;
    if parent.as_os_str().is_empty() {
        Ok(Path::new("."))
    } else {
        Ok(parent)
    }
}

fn atomic_replace(path: &Path, bytes: &[u8]) -> Result<(), AuthError> {
    let parent = normalized_parent(path)?;
    let file_name = path.file_name().ok_or(AuthError::EnrollmentFailed)?;
    let (temporary_path, mut temporary) = create_temporary(parent, file_name)?;
    let before_rename = (|| {
        temporary
            .write_all(bytes)
            .map_err(|_| AuthError::EnrollmentFailed)?;
        temporary
            .sync_all()
            .map_err(|_| AuthError::EnrollmentFailed)?;
        validate_temporary(&temporary_path, &temporary, bytes.len())
    })();
    if let Err(error) = before_rename {
        let _ = fs::remove_file(&temporary_path);
        return Err(error);
    }
    if fs::rename(&temporary_path, path).is_err() {
        let _ = fs::remove_file(&temporary_path);
        return Err(AuthError::EnrollmentFailed);
    }
    validate_temporary(path, &temporary, bytes.len())?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| AuthError::EnrollmentFailed)
}

fn create_temporary(
    parent: &Path,
    file_name: &std::ffi::OsStr,
) -> Result<(PathBuf, File), AuthError> {
    for _ in 0..TEMPORARY_ATTEMPTS {
        let mut random = [0_u8; 16];
        getrandom::getrandom(&mut random).map_err(|_| AuthError::EnrollmentFailed)?;
        let mut temporary_name = OsString::from(".");
        temporary_name.push(file_name);
        temporary_name.push(".tmp-");
        temporary_name.push(hex(&random));
        let temporary_path = parent.join(temporary_name);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        match options.open(&temporary_path) {
            Ok(file) => {
                #[cfg(unix)]
                file.set_permissions(fs::Permissions::from_mode(0o600))
                    .map_err(|_| AuthError::EnrollmentFailed)?;
                return Ok((temporary_path, file));
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(AuthError::EnrollmentFailed),
        }
    }
    Err(AuthError::EnrollmentFailed)
}

fn open_private_identity(path: &Path) -> Result<File, AuthError> {
    #[cfg(unix)]
    {
        use rustix::fs::{open, Mode, OFlags};
        let descriptor = open(
            path,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| AuthError::AuthenticationFailed)?;
        let file = File::from(descriptor);
        validate_open_identity(path, &file, None)?;
        Ok(file)
    }
    #[cfg(not(unix))]
    {
        File::open(path).map_err(|_| AuthError::AuthenticationFailed)
    }
}

fn validate_open_identity(
    path: &Path,
    file: &File,
    expected_length: Option<u64>,
) -> Result<(), AuthError> {
    let opened = file
        .metadata()
        .map_err(|_| AuthError::AuthenticationFailed)?;
    let linked = fs::symlink_metadata(path).map_err(|_| AuthError::AuthenticationFailed)?;
    #[cfg(unix)]
    if !opened.is_file()
        || opened.mode() & 0o7777 != 0o600
        || opened.nlink() != 1
        || linked.file_type().is_symlink()
        || !linked.is_file()
        || linked.dev() != opened.dev()
        || linked.ino() != opened.ino()
        || linked.mode() & 0o7777 != 0o600
        || linked.nlink() != 1
        || expected_length.is_some_and(|length| opened.len() != length || linked.len() != length)
    {
        return Err(AuthError::AuthenticationFailed);
    }
    #[cfg(not(unix))]
    if !opened.is_file()
        || !linked.is_file()
        || expected_length.is_some_and(|length| opened.len() != length || linked.len() != length)
    {
        return Err(AuthError::AuthenticationFailed);
    }
    Ok(())
}

fn read_bounded_identity(
    reader: &mut impl Read,
    observed_length: u64,
) -> Result<Vec<u8>, AuthError> {
    if observed_length == 0 || observed_length > MAX_IDENTITY_BYTES {
        return Err(AuthError::AuthenticationFailed);
    }
    let capacity = usize::try_from(observed_length).map_err(|_| AuthError::AuthenticationFailed)?;
    let mut bytes = Vec::with_capacity(capacity);
    reader
        .take(MAX_IDENTITY_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| AuthError::AuthenticationFailed)?;
    if u64::try_from(bytes.len()).map_err(|_| AuthError::AuthenticationFailed)? != observed_length {
        return Err(AuthError::AuthenticationFailed);
    }
    Ok(bytes)
}

fn validate_temporary(path: &Path, file: &File, expected_length: usize) -> Result<(), AuthError> {
    let opened = file.metadata().map_err(|_| AuthError::EnrollmentFailed)?;
    let linked = fs::symlink_metadata(path).map_err(|_| AuthError::EnrollmentFailed)?;
    if !opened.is_file() || opened.len() != expected_length as u64 || !linked.is_file() {
        return Err(AuthError::EnrollmentFailed);
    }
    #[cfg(unix)]
    if opened.mode() & 0o7777 != 0o600
        || opened.nlink() != 1
        || linked.file_type().is_symlink()
        || linked.dev() != opened.dev()
        || linked.ino() != opened.ino()
        || linked.mode() & 0o7777 != 0o600
        || linked.nlink() != 1
    {
        return Err(AuthError::EnrollmentFailed);
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    encoded
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::{read_bounded_identity, MAX_IDENTITY_BYTES};

    #[test]
    fn bounded_identity_reader_rejects_growth_past_observed_length_and_limit() {
        let oversized_length = usize::try_from(MAX_IDENTITY_BYTES + 1).unwrap();
        let mut oversized = Cursor::new(vec![0x61; oversized_length]);
        assert!(read_bounded_identity(&mut oversized, MAX_IDENTITY_BYTES + 1).is_err());

        let mut grew_after_metadata = Cursor::new(vec![0x61; 2]);
        assert!(read_bounded_identity(&mut grew_after_metadata, 1).is_err());

        let mut stable = Cursor::new(vec![0x61]);
        assert_eq!(read_bounded_identity(&mut stable, 1).unwrap(), vec![0x61]);
    }
}
