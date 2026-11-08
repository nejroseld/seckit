"""Short-lived, root-bound CLI reviews kept outside the inspected repository."""
from __future__ import annotations

import json
import os
import re
import secrets
import stat
import time
from pathlib import Path

from . import provision


class ReviewError(ValueError):
    """A safe, actionable message about a missing or invalid review."""


def _directory() -> Path:
    directory = provision.cache_dir() / "reviews"
    provision.ensure_private_dir(provision.cache_dir())
    directory.mkdir(mode=0o700, exist_ok=True)
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or (hasattr(os, "getuid") and info.st_uid != os.getuid()):
        raise ValueError("unsafe review cache")
    directory.chmod(0o700)
    return directory


def create(root: Path, plans: list[dict]) -> str | None:
    if not plans:
        return None
    review_id = secrets.token_hex(32)
    payload = {"root": str(root.resolve()), "expires": time.time() + 3600, "plans": plans}
    directory = _directory()
    # Expired snapshots may include source comments; don't retain them indefinitely.
    for old in directory.glob("*.json"):
        try:
            info = old.lstat()
            if stat.S_ISREG(info.st_mode) and info.st_mtime < time.time() - 3600:
                old.unlink()
        except OSError:
            continue
    path = directory / (review_id + ".json")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(payload, stream)
    return review_id


def consume(root: Path, review_id: str) -> list[dict]:
    if not re.fullmatch(r"[0-9a-f]{64}", review_id):
        raise ReviewError("Invalid review ID; request a new proposal.")
    path = _directory() / (review_id + ".json")
    # Claim atomically so concurrent/replayed invocations cannot both apply it.
    claimed = path.with_suffix(".claimed-" + secrets.token_hex(8))
    try:
        path.rename(claimed)
    except FileNotFoundError as exc:
        raise ReviewError("Review is missing or already consumed; request a new proposal.") from exc
    try:
        descriptor = os.open(claimed, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "r", encoding="utf-8") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 16_000_000:
                raise ValueError("invalid review file")
            payload = json.load(stream)
        if (not isinstance(payload, dict) or not isinstance(payload.get("root"), str)
                or not isinstance(payload.get("expires"), (int, float))
                or not isinstance(payload.get("plans"), list)):
            raise ReviewError("Invalid review snapshot; request a new proposal.")
        if payload["root"] != str(root.resolve()) or payload["expires"] <= time.time():
            raise ReviewError("Review expired or belongs to another project; request a new proposal.")
        return payload["plans"]
    finally:
        claimed.unlink(missing_ok=True)
