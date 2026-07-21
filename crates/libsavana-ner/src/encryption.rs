//! End-to-end encryption core — Rust port of the PURE crypto primitives of
//! `server/security/encryption.py`. **Byte-exact vs. Python is mandatory** (a
//! ciphertext/tag/signature mismatch = data loss), so every primitive mirrors
//! the exact Python construction:
//!
//!   - [`derive_key`]  — `_derive_key` (encryption.py:27-33): PBKDF2-HMAC-SHA256,
//!     `100_000` iterations, `dklen=32`; the empty-salt default resolves to the
//!     fixed salt `b"jarvis_secure_layer_v1"`.
//!   - [`encrypt_with_nonce`] / [`decrypt`] — the AES-256-GCM core inside
//!     `encrypt`/`decrypt` (encryption.py:84-109): a 12-byte (96-bit) nonce, and
//!     the wire layout `base64(nonce || ciphertext || tag)` — RustCrypto's
//!     `Aead::encrypt` appends the 16-byte GCM tag to the ciphertext exactly as
//!     Python's `AESGCM.encrypt` does, so the two layouts are identical.
//!   - [`sign`] / [`verify`] — `sign`/`verify` (encryption.py:114-125): HMAC-
//!     SHA256 over the data keyed by `derive_key(password)`, hex-encoded and
//!     **truncated to the first 16 hex chars** (Python `.hexdigest()[:16]`).
//!
//! Deliberately NOT ported (I/O and process env — the impure shell around the
//! core, mirroring the seam-lifting done in the sibling ports):
//!   - `KEY_FILE`, `init_key`, `_load_key` (encryption.py:36-68): the on-disk
//!     key-verification blob (`Path.home()/.jarvis/encryption.key`, `os.chmod`).
//!   - the `JARVIS_MASTER_KEY` env lookup + `KEY_FILE.exists()` guards + the
//!     Chinese `RuntimeError` messages at the top of `encrypt`/`decrypt`/`sign`.
//!   - **the random nonce**: Python's `encrypt` draws `os.urandom(12)` inline.
//!     That is the one non-deterministic step, so it is lifted into a parameter
//!     ([`encrypt_with_nonce`], the byte-exact seam). [`encrypt`] restores the
//!     full Python behaviour (fresh OS-random nonce per call) on top of it.
//!   - `decrypt`'s broad `except → "[解密失败: {e}]"` fallback string: this port
//!     returns a typed [`EncryptionError`] instead of an interpolated Python
//!     exception message (error *handling*, not the crypto — the AES-GCM decrypt
//!     it wraps is byte-identical).

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use hmac::{Hmac, Mac};
use sha2::Sha256;

/// 96-bit GCM nonce length — `NONCE_LEN` (encryption.py:22).
pub const NONCE_LEN: usize = 12;
/// Fixed salt used when the caller passes an empty salt — `_derive_key`
/// (encryption.py:29-30).
const DEFAULT_SALT: &[u8] = b"jarvis_secure_layer_v1";
/// PBKDF2 iteration count — `_derive_key` (encryption.py:32).
const PBKDF2_ITERATIONS: u32 = 100_000;

type HmacSha256 = Hmac<Sha256>;

/// Failure modes of [`decrypt`]. Carries only stable variants, never the input
/// or a derived plaintext (fail-closed like the rest of the kernel). Mirrors the
/// three failure points inside Python `decrypt`'s try-block (bad base64, GCM
/// auth/decrypt failure, non-UTF-8 plaintext).
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum EncryptionError {
    /// `base64.b64decode` failed, or the blob is shorter than one nonce.
    #[error("bad_ciphertext")]
    BadCiphertext,
    /// AES-256-GCM authentication/decryption failed (wrong key or tampering).
    #[error("decrypt_failed")]
    DecryptFailed,
    /// Decrypted bytes were not valid UTF-8 (`plaintext.decode("utf-8")`).
    #[error("not_utf8")]
    NotUtf8,
}

/// `_derive_key(master_password, salt=b"")` (encryption.py:27-33). PBKDF2-HMAC-
/// SHA256, `100_000` iterations, 32-byte output. An empty `salt` resolves to the
/// fixed [`DEFAULT_SALT`] (Python's `if not salt:` branch), so
/// `derive_key(pw, b"")` == `derive_key(pw, b"jarvis_secure_layer_v1")`.
pub fn derive_key(master_password: &str, salt: &[u8]) -> [u8; 32] {
    let salt = if salt.is_empty() { DEFAULT_SALT } else { salt };
    let mut key = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(
        master_password.as_bytes(),
        salt,
        PBKDF2_ITERATIONS,
        &mut key,
    );
    key
}

/// The deterministic AES-256-GCM core of Python `encrypt` (encryption.py:84-88)
/// with the nonce lifted to a parameter (Python draws it from `os.urandom`).
/// Returns `base64(nonce || ciphertext || tag)` — the exact wire format Python
/// emits. The 16-byte GCM tag is appended to the ciphertext by RustCrypto's
/// `Aead::encrypt`, matching `AESGCM.encrypt`.
pub fn encrypt_with_nonce(key: &[u8; 32], nonce: &[u8; NONCE_LEN], plaintext: &str) -> String {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    // Infallible for our inputs (plaintext far below the 2^36-byte GCM cap);
    // `Aead::encrypt` only errors on that overflow.
    let ct = cipher
        .encrypt(Nonce::from_slice(nonce), plaintext.as_bytes())
        .expect("AES-256-GCM encryption cannot fail for bounded plaintext");
    let mut blob = Vec::with_capacity(NONCE_LEN + ct.len());
    blob.extend_from_slice(nonce);
    blob.extend_from_slice(&ct);
    STANDARD.encode(blob)
}

/// Draw a fresh 12-byte nonce from the OS CSPRNG — the `os.urandom(NONCE_LEN)`
/// step of Python `encrypt` (encryption.py:85), lifted out so
/// [`encrypt_with_nonce`] stays deterministic/testable.
pub fn random_nonce() -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut nonce).expect("OS CSPRNG unavailable");
    nonce
}

/// Full port of Python `encrypt` minus the env/key-file shell (encryption.py:73-88):
/// draw a fresh OS-random nonce, then seal. Non-deterministic by construction —
/// the byte-exact differential runs against [`encrypt_with_nonce`]; this one is
/// covered by an encrypt→decrypt round-trip.
pub fn encrypt(key: &[u8; 32], plaintext: &str) -> String {
    encrypt_with_nonce(key, &random_nonce(), plaintext)
}

/// The AES-256-GCM core of Python `decrypt` (encryption.py:100-106): base64-
/// decode, split off the leading [`NONCE_LEN`] nonce, GCM-decrypt the rest
/// (ciphertext||tag), and UTF-8 decode. Returns a typed error instead of
/// Python's `"[解密失败: {e}]"` fallback string (see module docs).
pub fn decrypt(key: &[u8; 32], ciphertext_b64: &str) -> Result<String, EncryptionError> {
    let raw = STANDARD
        .decode(ciphertext_b64.as_bytes())
        .map_err(|_| EncryptionError::BadCiphertext)?;
    if raw.len() < NONCE_LEN {
        return Err(EncryptionError::BadCiphertext);
    }
    let (nonce, ciphertext) = raw.split_at(NONCE_LEN);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let plaintext = cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| EncryptionError::DecryptFailed)?;
    String::from_utf8(plaintext).map_err(|_| EncryptionError::NotUtf8)
}

/// `sign(data, master_password)` (encryption.py:114-120): HMAC-SHA256 over
/// `data`, keyed by `derive_key(master_password)` (default salt), hex-encoded
/// and truncated to the **first 16 hex characters** (`.hexdigest()[:16]`, i.e.
/// the first 8 MAC bytes).
pub fn sign(master_password: &str, data: &str) -> String {
    let key = derive_key(master_password, b"");
    let mut mac = <HmacSha256 as Mac>::new_from_slice(&key).expect("HMAC accepts any key length");
    mac.update(data.as_bytes());
    let digest = mac.finalize().into_bytes();
    let mut hex = String::with_capacity(16);
    for byte in digest.iter().take(8) {
        use std::fmt::Write as _;
        write!(hex, "{byte:02x}").expect("writing to String is infallible");
    }
    hex
}

/// `verify(data, signature, master_password)` (encryption.py:123-125): recompute
/// [`sign`] and compare. Mirrors Python's plain `==` (not constant-time — the
/// signature is a public integrity tag, and this preserves exact behaviour).
pub fn verify(master_password: &str, data: &str, signature: &str) -> bool {
    sign(master_password, data) == signature
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // ── Golden vectors emitted by LIVE Python (see report / gen_enc_vectors.py):
    //    PYTHONPATH=. /tmp/civenv/bin/python gen_enc_vectors.py
    // Each tuple is byte-for-byte what server/security/encryption.py produced.

    /// (password, salt_hex, key_hex) from `_derive_key`.
    const KDF: &[(&str, &str, &str)] = &[
        (
            "hunter2",
            "",
            "cacd7173585c0522303bf09a4a9a1568c959512143f71d9d5a748fbcf644bf80",
        ),
        (
            "",
            "",
            "4da59a3dd1bd3335313363f327ac36cca14056fb76a76755de8c1e2771d02da7",
        ),
        (
            "correct horse battery staple",
            "",
            "c679e991f2b41e39efbada05b327e595ddba185f90cb602ad61f8431f111e12f",
        ),
        (
            "pw",
            "637573746f6d5f73616c745f313233",
            "86ea59eece96de915112f43c371b7bbb0765092b406a5ce21421721538ae83b8",
        ),
        (
            "Ünïcödé-pass-🔑",
            "",
            "15886708c9fd25bf32351019dac0fc19a022fc5bf3c56f705c8a843b174ccd82",
        ),
    ];

    /// (password, nonce_hex, plaintext, base64(nonce||ct||tag)) from `encrypt`'s core.
    const SEAL: &[(&str, &str, &str, &str)] = &[
        (
            "hunter2",
            "000102030405060708090a0b",
            "hello world",
            "AAECAwQFBgcICQoLQ1mfNqWBf6JXM7YPb2h2rgSxArlXmuNx+hSh",
        ),
        (
            "hunter2",
            "000102030405060708090a0b",
            "",
            "AAECAwQFBgcICQoL+Uh7l6kTLrZxiujaNOH1Ug==",
        ),
        (
            "hunter2",
            "ffffffffffffffffffffffff",
            "The quick brown fox.",
            "////////////////d6tUFugmcFlucpu6+kahJif+ICLh82jluAii00gHMOfgcZFX",
        ),
        (
            "master-key",
            "000102030405060708090a0b",
            "email: alice@example.com ssn 123-45-6789",
            "AAECAwQFBgcICQoLN3p3wlUxdu53/8ZPvq52sVF52DIDc7MeEo8zjnFvC4AUBYeKLGGiqX1km3uj9a8mB/JOLVNlGh4=",
        ),
        (
            "master-key",
            "000102030405060708090a0b",
            "多字节 UTF-8 内容 🔒 mixed",
            "AAECAwQFBgcICQoLt7OMTpScvgWZtvB+uOY28NmPMbKDqfyDrWjSwDw3QdZdjYoy/zBhrBdnbmyaGH1RDA==",
        ),
    ];

    /// (password, data, first-16-hex-char signature) from `sign`.
    const SIGN: &[(&str, &str, &str)] = &[
        ("hunter2", "integrity-me", "39451734fadff50b"),
        ("hunter2", "", "ddec08467fd57d47"),
        ("master-key", "email: alice@example.com", "e8e22e7f5362c341"),
        ("master-key", "多字节 data 🔒", "7d2f341393be4047"),
    ];

    #[test]
    fn derive_key_byte_exact_vs_python() {
        for (pw, salt_hex, key_hex) in KDF {
            let salt = unhex(salt_hex);
            let got = derive_key(pw, &salt);
            assert_eq!(
                got.to_vec(),
                unhex(key_hex),
                "PBKDF2 mismatch for password {pw:?}"
            );
        }
    }

    #[test]
    fn empty_salt_equals_default_salt() {
        // Python `if not salt: salt = b"jarvis_secure_layer_v1"`.
        assert_eq!(
            derive_key("hunter2", b""),
            derive_key("hunter2", b"jarvis_secure_layer_v1"),
        );
    }

    #[test]
    fn encrypt_with_nonce_byte_exact_vs_python() {
        for (pw, nonce_hex, plaintext, expected_b64) in SEAL {
            let key = derive_key(pw, b"");
            let mut nonce = [0u8; NONCE_LEN];
            nonce.copy_from_slice(&unhex(nonce_hex));
            let got = encrypt_with_nonce(&key, &nonce, plaintext);
            assert_eq!(
                &got, expected_b64,
                "AES-256-GCM ciphertext mismatch for plaintext {plaintext:?}"
            );
        }
    }

    #[test]
    fn decrypt_recovers_python_ciphertext() {
        // Rust decrypts what Python sealed → recovers the exact plaintext.
        for (pw, _nonce_hex, plaintext, python_b64) in SEAL {
            let key = derive_key(pw, b"");
            let got = decrypt(&key, python_b64).expect("decrypt python vector");
            assert_eq!(&got, plaintext);
        }
    }

    #[test]
    fn encrypt_decrypt_round_trip_random_nonce() {
        // The full random-nonce `encrypt` path round-trips through `decrypt`.
        let key = derive_key("hunter2", b"");
        for pt in ["", "roundtrip", "多字节 🔒 mixed", "line1\nline2\ttab"] {
            let sealed = encrypt(&key, pt);
            assert_eq!(decrypt(&key, &sealed).unwrap(), pt);
        }
    }

    #[test]
    fn sign_byte_exact_vs_python() {
        for (pw, data, expected_sig) in SIGN {
            let got = sign(pw, data);
            assert_eq!(&got, expected_sig, "HMAC signature mismatch for {data:?}");
            assert_eq!(got.len(), 16, "signature must be 16 hex chars");
        }
    }

    #[test]
    fn verify_accepts_valid_and_rejects_tampered() {
        for (pw, data, sig) in SIGN {
            assert!(verify(pw, data, sig));
            assert!(!verify(pw, data, "0000000000000000"));
            assert!(!verify("wrong-password", data, sig));
        }
    }

    #[test]
    fn decrypt_rejects_tampered_and_garbage() {
        let key = derive_key("hunter2", b"");
        // Not valid base64 padding / length.
        assert_eq!(decrypt(&key, "!!!!"), Err(EncryptionError::BadCiphertext));
        // Too short to hold a nonce.
        assert_eq!(decrypt(&key, "AAAA"), Err(EncryptionError::BadCiphertext));
        // Valid Python ciphertext but wrong key → GCM auth failure.
        let wrong = derive_key("nope", b"");
        assert_eq!(
            decrypt(
                &wrong,
                "AAECAwQFBgcICQoLQ1mfNqWBf6JXM7YPb2h2rgSxArlXmuNx+hSh"
            ),
            Err(EncryptionError::DecryptFailed),
        );
    }
}
