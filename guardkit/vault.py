"""Encrypted file vault used when no native secret store is available.

AES-256-GCM with a random key kept in a separate 0600 file next to the vault.
It protects against accidental leaks (git, backups, logs), not against code
running as the same user, which is the same trust level as ~/.ssh keys.
"""
from __future__ import annotations

import base64
import fcntl
import json
import os
from pathlib import Path

from .secrets import SecretError


def _home() -> Path:
    override = os.environ.get("GUARDKIT_HOME")
    if override:
        return Path(override)
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "guardkit"


class FileVault:
    def __init__(self, directory: Path | None = None):
        self.directory = Path(directory) if directory else _home()
        self.path = self.directory / "vault.json"
        self.key_path = self.directory / "vault.key"

    def _aead(self, create: bool):
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        except ImportError:
            raise SecretError("File vault needs the cryptography package") from None
        try:
            key = self.key_path.read_bytes()
        except FileNotFoundError:
            if not create:
                return None
            self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            key = os.urandom(32)
            try:
                fd = os.open(self.key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            except FileExistsError:
                key = self.key_path.read_bytes()
            else:
                with os.fdopen(fd, "wb") as handle:
                    handle.write(key)
        if len(key) != 32:
            raise SecretError("Vault key is damaged")
        return AESGCM(key)

    def _load(self) -> dict:
        try:
            data = json.loads(self.path.read_text("utf-8"))
        except FileNotFoundError:
            return {}
        except (OSError, ValueError):
            raise SecretError("Vault file is damaged") from None
        return data if isinstance(data, dict) else {}

    def _save(self, data: dict) -> None:
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        temporary = self.path.with_name(self.path.name + f".{os.getpid()}.tmp")
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle)
        os.replace(temporary, self.path)

    def _locked(self):
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        handle = open(self.directory / "vault.lock", "a")
        fcntl.flock(handle, fcntl.LOCK_EX)
        return handle

    def put(self, name: str, value: str) -> None:
        try:
            aead = self._aead(create=True)
            nonce = os.urandom(12)
            sealed = aead.encrypt(nonce, value.encode("utf-8"), name.encode())
            with self._locked():
                data = self._load()
                data[name] = base64.b64encode(nonce + sealed).decode()
                self._save(data)
        except SecretError:
            raise
        except Exception:
            raise SecretError("Vault operation failed") from None

    def get(self, name: str) -> str:
        try:
            blob = self._load().get(name)
            aead = self._aead(create=False)
            if blob is None or aead is None:
                raise SecretError("Secret not found or access denied")
            raw = base64.b64decode(blob)
            return aead.decrypt(raw[:12], raw[12:], name.encode()).decode("utf-8")
        except SecretError:
            raise
        except Exception:
            raise SecretError("Vault operation failed") from None

    def delete(self, name: str) -> bool:
        if not self.path.exists():
            return False
        try:
            with self._locked():
                data = self._load()
                if name not in data:
                    return False
                del data[name]
                self._save(data)
                return True
        except SecretError:
            raise
        except Exception:
            raise SecretError("Vault operation failed") from None

    def names(self) -> list[str]:
        return sorted(self._load())
