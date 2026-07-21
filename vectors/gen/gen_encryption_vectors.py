"""Emit byte-exact reference vectors for the encryption core from LIVE Python.

Mirrors server/security/encryption.py's pure crypto primitives:
  _derive_key (PBKDF2-HMAC-SHA256, salt b"jarvis_secure_layer_v1", 100k, dklen=32),
  the AESGCM(key).encrypt(nonce, pt, None) core inside encrypt(),
  the base64(nonce+ciphertext) output layout,
  sign() = HMAC-SHA256(key, data).hexdigest()[:16].
"""
import hashlib
import hmac
import base64
import json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def derive_key(master_password: str, salt: bytes = b"") -> bytes:
    if not salt:
        salt = b"jarvis_secure_layer_v1"
    return hashlib.pbkdf2_hmac("sha256", master_password.encode(), salt, 100000, dklen=32)


def seal_b64(key: bytes, nonce: bytes, plaintext: str) -> str:
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    return base64.b64encode(nonce + ct).decode()


def sign(master_password: str, data: str) -> str:
    key = derive_key(master_password)
    return hmac.new(key, data.encode(), hashlib.sha256).hexdigest()[:16]


vectors = {}

# --- KDF vectors (password, salt-hex) -> key-hex ---
kdf = []
for pw, salt in [
    ("hunter2", b""),                      # default salt path
    ("", b""),                             # empty password, default salt
    ("correct horse battery staple", b""),
    ("pw", b"custom_salt_123"),            # explicit salt path
    ("Ünïcödé-pass-🔑", b""),               # non-ascii utf-8 password
]:
    kdf.append({
        "password": pw,
        "salt_hex": salt.hex(),
        "key_hex": derive_key(pw, salt).hex(),
    })
vectors["kdf"] = kdf

# --- AES-256-GCM seal vectors (fixed nonce) -> base64(nonce+ct+tag) ---
seals = []
fixed_nonce = bytes(range(12))  # 00 01 02 ... 0b
for pw, nonce, pt in [
    ("hunter2", fixed_nonce, "hello world"),
    ("hunter2", fixed_nonce, ""),                                  # empty plaintext
    ("hunter2", bytes([0xff] * 12), "The quick brown fox."),
    ("master-key", fixed_nonce, "email: alice@example.com ssn 123-45-6789"),
    ("master-key", fixed_nonce, "多字节 UTF-8 内容 🔒 mixed"),          # non-ascii plaintext
]:
    key = derive_key(pw)
    seals.append({
        "password": pw,
        "nonce_hex": nonce.hex(),
        "plaintext": pt,
        "b64": seal_b64(key, nonce, pt),
    })
vectors["seal"] = seals

# --- HMAC sign vectors -> 16-hex-char signature ---
signs = []
for pw, data in [
    ("hunter2", "integrity-me"),
    ("hunter2", ""),
    ("master-key", "email: alice@example.com"),
    ("master-key", "多字节 data 🔒"),
]:
    signs.append({"password": pw, "data": data, "sig": sign(pw, data)})
vectors["sign"] = signs

print(json.dumps(vectors, ensure_ascii=False, indent=2))
