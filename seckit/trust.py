"""Which `.seckit/` files the user has accepted on this machine.

`.seckit/ignore.json` and `.seckit/triage.json` live in the project, so whoever
wrote the project, including the author of an untrusted repository, controls
them. Their suppressions and verdicts take effect only for the exact bytes the
user accepted with `seckit trust` in a terminal, or that Seckit itself wrote.
The record lives in the private user cache, outside every project.
"""
from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
from pathlib import Path

from . import provision

_RECORD = "trust.json"


def _record_path() -> Path:
    return provision.cache_dir() / _RECORD


def _load() -> dict[str, dict[str, str]]:
    path = _record_path()
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_size > 5_000_000:
            return {}
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError):
        return {}
    return data if isinstance(data, dict) else {}


def digest(path: Path) -> str | None:
    try:
        if path.is_symlink() or not path.is_file():
            return None
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def is_trusted(root: Path, relative: str) -> bool:
    root = Path(root).resolve()
    current = digest(root / relative)
    if current is None:
        return False
    entry = _load().get(str(root))
    return isinstance(entry, dict) and entry.get(relative) == current


def remember(root: Path, relatives: list[str]) -> list[str]:
    """Record the current bytes of these project files as accepted; returns those recorded."""
    root = Path(root).resolve()
    record = _record_path()
    provision.ensure_private_dir(record.parent)
    data = _load()
    entry = data.get(str(root)) if isinstance(data.get(str(root)), dict) else {}
    recorded = []
    for relative in relatives:
        current = digest(root / relative)
        if current is None:
            continue
        entry[relative] = current
        recorded.append(relative)
    data[str(root)] = entry
    descriptor, temporary = tempfile.mkstemp(dir=record.parent, prefix=".trust-", suffix=".tmp")
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(data, stream, indent=2, sort_keys=True)
        os.chmod(temporary, 0o600)
        os.replace(temporary, record)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise
    return recorded


def untrusted_notice(relative: str, effect: str) -> str:
    return (f"{relative} is not accepted on this machine (new, or changed since it was accepted); {effect}. "
            "If you wrote or reviewed it, run `seckit trust` in a terminal.")
