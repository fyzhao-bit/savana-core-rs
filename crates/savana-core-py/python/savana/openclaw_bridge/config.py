"""Private, closed bridge deployment configuration."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
from typing import Any


MAX_CONFIG_BYTES = 64 * 1024
CONFIG_VERSION = 1
_CONFIG_KEYS = frozenset(
    {
        "version",
        "identity_path",
        "bootstrap_path",
        "webauthn_fd",
        "release_journal_path",
        "release_canonical_host",
        "client_root_certificate_path",
        "server_certificate_path",
        "server_private_key_path",
        "expected_client_spki_pin_path",
        "max_steps",
        "max_replans",
        "turn_timeout_seconds",
    }
)
_HOST = re.compile(r"(?=.{1,253}\Z)[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?\Z")


class ConfigError(Exception):
    """A redacted bridge configuration error."""


@dataclass(frozen=True, slots=True)
class BridgeConfig:
    version: int
    identity_path: Path
    bootstrap_path: Path
    webauthn_fd: int
    release_journal_path: Path
    release_canonical_host: str
    client_root_certificate_path: Path
    server_certificate_path: Path
    server_private_key_path: Path
    expected_client_spki_pin_path: Path
    max_steps: int
    max_replans: int
    turn_timeout_seconds: float

    @classmethod
    def load(cls, path: str | os.PathLike[str]) -> "BridgeConfig":
        path = Path(path)
        _require_absolute(path)
        _require_private_regular_file(path)
        try:
            with path.open("rb") as stream:
                encoded = stream.read(MAX_CONFIG_BYTES + 1)
            if not encoded or len(encoded) > MAX_CONFIG_BYTES:
                raise ConfigError("bridge configuration is invalid")
            value = json.loads(
                encoded.decode("utf-8", errors="strict"),
                object_pairs_hook=_unique_object,
            )
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, ConfigError) as error:
            raise ConfigError("bridge configuration is invalid") from error
        if not isinstance(value, dict) or frozenset(value) != _CONFIG_KEYS:
            raise ConfigError("bridge configuration is invalid")
        if type(value["version"]) is not int or value["version"] != CONFIG_VERSION:
            raise ConfigError("bridge configuration is incompatible")

        paths = {
            name: Path(value[name]) if isinstance(value[name], str) else None
            for name in (
                "identity_path",
                "bootstrap_path",
                "release_journal_path",
                "client_root_certificate_path",
                "server_certificate_path",
                "server_private_key_path",
                "expected_client_spki_pin_path",
            )
        }
        if any(item is None for item in paths.values()):
            raise ConfigError("bridge configuration is invalid")
        for item in paths.values():
            _require_absolute(item)
        for name in (
            "identity_path",
            "bootstrap_path",
            "server_private_key_path",
            "expected_client_spki_pin_path",
        ):
            _require_private_regular_file(paths[name])
        for name in ("client_root_certificate_path", "server_certificate_path"):
            _require_regular_file(paths[name])
        journal_parent = paths["release_journal_path"].parent
        if not journal_parent.is_dir():
            raise ConfigError("bridge configuration is invalid")

        webauthn_fd = value["webauthn_fd"]
        max_steps = value["max_steps"]
        max_replans = value["max_replans"]
        timeout = value["turn_timeout_seconds"]
        host = value["release_canonical_host"]
        if type(webauthn_fd) is not int or not 3 <= webauthn_fd <= 1024:
            raise ConfigError("bridge configuration is invalid")
        if type(max_steps) is not int or not 1 <= max_steps <= 64:
            raise ConfigError("bridge configuration is invalid")
        if type(max_replans) is not int or not 0 <= max_replans <= 16:
            raise ConfigError("bridge configuration is invalid")
        if type(timeout) not in (int, float) or isinstance(timeout, bool):
            raise ConfigError("bridge configuration is invalid")
        timeout = float(timeout)
        if not 1.0 <= timeout <= 300.0:
            raise ConfigError("bridge configuration is invalid")
        if not isinstance(host, str) or not _HOST.fullmatch(host) or ".." in host:
            raise ConfigError("bridge configuration is invalid")

        return cls(
            version=CONFIG_VERSION,
            identity_path=paths["identity_path"],
            bootstrap_path=paths["bootstrap_path"],
            webauthn_fd=webauthn_fd,
            release_journal_path=paths["release_journal_path"],
            release_canonical_host=host.lower(),
            client_root_certificate_path=paths["client_root_certificate_path"],
            server_certificate_path=paths["server_certificate_path"],
            server_private_key_path=paths["server_private_key_path"],
            expected_client_spki_pin_path=paths["expected_client_spki_pin_path"],
            max_steps=max_steps,
            max_replans=max_replans,
            turn_timeout_seconds=timeout,
        )


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ConfigError("duplicate bridge configuration key")
        result[key] = value
    return result


def _require_absolute(path: Path) -> None:
    if not path.is_absolute() or "\x00" in str(path):
        raise ConfigError("bridge configuration paths must be absolute")


def _require_regular_file(path: Path) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ConfigError("bridge configuration is invalid") from error
    if path.is_symlink() or not path.is_file() or metadata.st_size <= 0:
        raise ConfigError("bridge configuration is invalid")


def _require_private_regular_file(path: Path) -> None:
    _require_regular_file(path)
    if os.name == "posix" and path.stat().st_mode & 0o077:
        raise ConfigError("bridge configuration file permissions are too broad")
