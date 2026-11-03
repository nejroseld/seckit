"""Small, reviewable repository fixes with optimistic concurrency checks.

Only narrowly scoped .gitignore and Docker Compose edits are generated here. No
project commands are run and no finding text is interpreted as shell or source.
"""
from __future__ import annotations

import os
import re
import stat
from pathlib import Path, PurePosixPath
from typing import Any


_MARKER = "# BlueKit: keep local secrets out of version control"
_COMPOSE_PRIVILEGED = re.compile(r"^(\s*privileged\s*:\s*)true(\s*(?:#.*)?\r?\n?)$", re.IGNORECASE)
_DOCKER_USER_ROOT = re.compile(r"^(\s*USER\s+)(?:root|0)(?::(?:root|0))?(\s*(?:#.*)?\r?\n?)$", re.IGNORECASE)
_DOCKER_USER_SAFE = re.compile(r"^\s*USER\s+65532:65532\s*(?:#.*)?\r?\n?$", re.IGNORECASE)
_PATTERNS = {
    ".env": (".env", ".env.*", "!.env.example"),
    ".pem": ("*.pem",),
    ".key": ("*.key",),
    "credentials.json": ("credentials.json",),
}
_PUBLIC_IGNORE_LINES = {_MARKER, *(line for patterns in _PATTERNS.values() for line in patterns)}


def _sensitive_pattern(file: Any) -> tuple[str, ...] | None:
    if not isinstance(file, str):
        return None
    name = PurePosixPath(file.replace("\\", "/")).name.lower()
    if name == ".env" or name.startswith(".env."):
        return _PATTERNS[".env"]
    if name.endswith(".pem"):
        return _PATTERNS[".pem"]
    if name.endswith(".key"):
        return _PATTERNS[".key"]
    if name in {"credentials.json", "credential.json"}:
        return _PATTERNS["credentials.json"]
    return None


def _read_text_exact(path: Path) -> str:
    with path.open("r", encoding="utf-8", newline="") as stream:
        return stream.read()


def _read_gitignore(root: Path) -> str | None:
    path = root / ".gitignore"
    try:
        if path.is_symlink() or not path.is_file():
            return None
        if path.stat().st_size > 1_000_000:
            return None
        return _read_text_exact(path)
    except (OSError, UnicodeError):
        return None


def _safe_relative(relative: Any) -> bool:
    if not isinstance(relative, str) or not relative:
        return False
    path = PurePosixPath(relative.replace("\\", "/"))
    return not path.is_absolute() and all(part not in {"", ".", ".."} for part in path.parts)


def _has_symlink_component(root: Path, relative: str) -> bool:
    current = root
    for part in PurePosixPath(relative.replace("\\", "/")).parts:
        current = current / part
        if current.is_symlink():
            return True
    return False


def propose(root: Path, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Propose safe secret ignores or a precise Compose privileged-mode edit."""
    root = Path(root).resolve()
    if not root.is_dir():
        return []
    applicable: dict[tuple[str, ...], list[str]] = {}
    compose: dict[str, list[dict[str, Any]]] = {}
    dockerfiles: dict[str, list[dict[str, Any]]] = {}
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        signal = " ".join(str(finding.get(key, "")) for key in ("rule_id", "title")).lower()
        file = finding.get("file")
        if "privileged" in signal and isinstance(file, str) and Path(file).name.lower() in {
            "docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml",
        }:
            compose.setdefault(file, []).append(finding)
        if isinstance(file, str) and Path(file).name.lower() == "dockerfile" and (
            "ds002" in signal or "last user command" in signal or "user" in signal and "root" in signal
        ):
            dockerfiles.setdefault(file, []).append(finding)
        if "secret" in signal or finding.get("category") == "credential":
            patterns = _sensitive_pattern(file)
            if patterns:
                applicable.setdefault(patterns, []).append(str(finding.get("id") or "unknown"))

    plans: list[dict[str, Any]] = []
    if applicable:
        before = _read_gitignore(root)
        if before is not None or not (root / ".gitignore").exists():
            existing = set((before or "").splitlines())
            additions: list[str] = []
            for patterns in applicable:
                additions.extend(pattern for pattern in patterns if pattern not in existing and pattern not in additions)
            if additions:
                suffix = "" if not before or before.endswith("\n") else "\n"
                after = (before or "") + suffix + _MARKER + "\n" + "\n".join(additions) + "\n"
                plans.append({
                    "kind": "ignore_secret_files", "path": ".gitignore", "before": before, "after": after,
                    "finding_ids": sorted({item for ids in applicable.values() for item in ids}),
                    "reason": "Ignore recognized local secret-file names. This does not revoke or delete exposed credentials.",
                })

    for relative, related in compose.items():
        if not _safe_relative(relative) or _has_symlink_component(root, relative):
            continue
        path = root / relative
        try:
            if not path.is_file() or path.stat().st_size > 1_000_000:
                continue
            before = _read_text_exact(path)
        except (OSError, UnicodeError):
            continue
        lines = before.splitlines(keepends=True)
        target_lines = {int(item.get("line") or 0) for item in related if str(item.get("line") or "0").isdigit()}
        matches = [index for index, line in enumerate(lines, start=1) if _COMPOSE_PRIVILEGED.fullmatch(line)]
        if target_lines:
            matches = [index for index in matches if index in target_lines]
        if len(matches) != 1:
            continue
        index = matches[0] - 1
        lines[index] = _COMPOSE_PRIVILEGED.sub(r"\g<1>false\g<2>", lines[index], count=1)
        plans.append({
            "kind": "compose_privileged_false", "path": relative, "before": before, "after": "".join(lines),
            "finding_ids": sorted({str(item.get("id") or "unknown") for item in related}),
            "reason": "Disable privileged mode on the exact Docker Compose line reported by the scanner.",
        })
    for relative, related in dockerfiles.items():
        if not _safe_relative(relative) or _has_symlink_component(root, relative):
            continue
        path = root / relative
        try:
            if not path.is_file() or path.stat().st_size > 1_000_000:
                continue
            before = _read_text_exact(path)
        except (OSError, UnicodeError):
            continue
        lines = before.splitlines(keepends=True)
        target_lines = {int(item.get("line") or 0) for item in related if str(item.get("line") or "0").isdigit()}
        matches = [index for index, line in enumerate(lines, start=1) if _DOCKER_USER_ROOT.fullmatch(line)]
        if target_lines:
            matches = [index for index in matches if index in target_lines]
        elif len(matches) == 1:
            last_user = max((index for index, line in enumerate(lines, start=1)
                             if re.match(r"^\s*USER\b", line, re.IGNORECASE)), default=0)
            matches = [index for index in matches if index == last_user]
        if len(matches) != 1:
            continue
        index = matches[0] - 1
        lines[index] = _DOCKER_USER_ROOT.sub(r"\g<1>65532:65532\g<2>", lines[index], count=1)
        plans.append({
            "kind": "dockerfile_user_nonroot", "path": relative, "before": before, "after": "".join(lines),
            "finding_ids": sorted({str(item.get("id") or "unknown") for item in related}),
            "reason": "Switch the reported Dockerfile runtime user to UID/GID 65532. Check file ownership, writable paths, and required capabilities before applying.",
        })
    return plans


def _safe_label(value: Any, limit: int = 256) -> str:
    """Remove controls before metadata is returned to an agent or terminal."""
    if not isinstance(value, str):
        return ""
    return "".join(char for char in value if char.isprintable())[:limit]


def public_plans(plans: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return review diffs without including unchanged or sensitive file text.

    The internal plans retain exact snapshots for optimistic concurrency. This
    presentation form includes only fixed ignore additions or normalized
    Compose directives, never arbitrary source lines or comments.
    """
    safe: list[dict[str, Any]] = []
    for plan in plans:
        if not isinstance(plan, dict):
            continue
        kind = plan.get("kind")
        path = _safe_label(plan.get("path"))
        if kind == "ignore_secret_files" and plan.get("path") == ".gitignore":
            before_lines = set((plan.get("before") or "").splitlines())
            additions = [line for line in (plan.get("after") or "").splitlines()
                         if line in _PUBLIC_IGNORE_LINES and line not in before_lines]
            if not additions:
                continue
            start = len((plan.get("before") or "").splitlines())
            diff_lines = [f"--- a/{path}", f"+++ b/{path}", f"@@ -{start},0 +{start + 1},{len(additions)} @@"]
            diff_lines.extend("+" + line for line in additions)
            reason = "Ignore recognized local secret-file names. This does not revoke or delete exposed credentials."
        elif kind == "compose_privileged_false":
            before = (plan.get("before") or "").splitlines()
            after = (plan.get("after") or "").splitlines()
            changes = [(index, old, new) for index, (old, new) in enumerate(zip(before, after), 1) if old != new]
            if len(before) != len(after) or len(changes) != 1:
                continue
            index, old, new = changes[0]
            old_match, new_match = _COMPOSE_PRIVILEGED.fullmatch(old), _COMPOSE_PRIVILEGED.fullmatch(new)
            # The full-line validation doesn't accept false as a new value, so
            # validate the exact directive with a separate conservative match.
            if not old_match:
                continue
            new_directive = re.fullmatch(r"\s*privileged\s*:\s*false\s*(?:#.*)?", new, re.IGNORECASE)
            if not new_directive or new_match:
                continue
            diff_lines = [f"--- a/{path}", f"+++ b/{path}", f"@@ -{index},1 +{index},1 @@",
                          "-privileged: true", "+privileged: false"]
            reason = "Disable privileged mode on the exact Docker Compose line reported by the scanner."
        elif kind == "dockerfile_user_nonroot":
            before = (plan.get("before") or "").splitlines()
            after = (plan.get("after") or "").splitlines()
            changes = [(index, old, new) for index, (old, new) in enumerate(zip(before, after), 1) if old != new]
            if len(before) != len(after) or len(changes) != 1:
                continue
            index, old, new = changes[0]
            if not _DOCKER_USER_ROOT.fullmatch(old) or not _DOCKER_USER_SAFE.fullmatch(new):
                continue
            diff_lines = [f"--- a/{path}", f"+++ b/{path}", f"@@ -{index},1 +{index},1 @@",
                          "-USER root", "+USER 65532:65532"]
            reason = "Switch the reported Dockerfile runtime user to UID/GID 65532. Check file ownership, writable paths, and required capabilities before applying."
        else:
            continue
        ids = sorted({_safe_label(item, 128) for item in plan.get("finding_ids", []) if _safe_label(item, 128)})
        safe.append({"path": path, "finding_ids": ids, "reason": reason, "diff": "\n".join(diff_lines) + "\n"})
    return safe


def _validate_plan(root: Path, plan: dict[str, Any]) -> tuple[Path, bytes | None, bytes]:
    if not isinstance(plan, dict):
        raise ValueError("unsupported fix plan")
    kind, relative = plan.get("kind"), plan.get("path")
    compose_names = {"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}
    if kind == "ignore_secret_files" and relative == ".gitignore" and _safe_relative(relative):
        pass
    elif kind == "compose_privileged_false" and _safe_relative(relative) and Path(relative).name.lower() in compose_names:
        pass
    elif kind == "dockerfile_user_nonroot" and _safe_relative(relative) and Path(relative).name.lower() == "dockerfile":
        pass
    else:
        raise ValueError("unsupported fix plan")
    before, after = plan.get("before"), plan.get("after")
    if before is not None and not isinstance(before, str):
        raise ValueError("invalid expected file content")
    if not isinstance(after, str):
        raise ValueError("invalid proposed file content")
    if kind == "ignore_secret_files":
        if _MARKER not in after or (before is not None and not after.startswith(before)):
            raise ValueError("invalid proposed file content")
    elif kind == "compose_privileged_false":
        if before is None:
            raise ValueError("compose fix requires an existing file")
        old_lines, new_lines = before.splitlines(keepends=True), after.splitlines(keepends=True)
        changes = [(old, new) for old, new in zip(old_lines, new_lines) if old != new]
        if len(old_lines) != len(new_lines) or len(changes) != 1:
            raise ValueError("compose fix must change exactly one line")
        old, new = changes[0]
        if not _COMPOSE_PRIVILEGED.fullmatch(old) or new != _COMPOSE_PRIVILEGED.sub(r"\g<1>false\g<2>", old, count=1):
            raise ValueError("invalid Docker Compose fix")
    else:
        if before is None:
            raise ValueError("Dockerfile fix requires an existing file")
        old_lines, new_lines = before.splitlines(keepends=True), after.splitlines(keepends=True)
        changes = [(old, new) for old, new in zip(old_lines, new_lines) if old != new]
        if len(old_lines) != len(new_lines) or len(changes) != 1:
            raise ValueError("Dockerfile fix must change exactly one line")
        old, new = changes[0]
        if not _DOCKER_USER_ROOT.fullmatch(old) or not _DOCKER_USER_SAFE.fullmatch(new):
            raise ValueError("invalid Dockerfile non-root fix")
    if _has_symlink_component(root, relative):
        raise ValueError("refusing to write through a symlink")
    target = root / relative
    try:
        target.resolve(strict=False).relative_to(root)
    except ValueError as exc:
        raise ValueError("fix path escapes repository") from exc
    return target, before.encode("utf-8") if before is not None else None, after.encode("utf-8")


def _write_checked(root: Path, plan: dict[str, Any]) -> dict[str, Any]:
    target, expected, proposed = _validate_plan(root, plan)
    target.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_RDWR | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if expected is None:
        flags |= os.O_CREAT | os.O_EXCL
        try:
            fd = os.open(target, flags, 0o644)
        except FileExistsError as exc:
            raise ValueError("fix target content changed; review the proposal again") from exc
        old_mode = None
    else:
        fd = os.open(target, flags)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            os.close(fd)
            raise ValueError("fix target must be a regular file without hard links")
        old_mode = stat.S_IMODE(info.st_mode)
    try:
        actual_stat = os.fstat(fd)
        try:
            path_stat = target.lstat()
        except FileNotFoundError:
            raise ValueError("fix target changed while applying")
        if (actual_stat.st_dev, actual_stat.st_ino) != (path_stat.st_dev, path_stat.st_ino):
            raise ValueError("fix target changed while applying")
        os.lseek(fd, 0, os.SEEK_SET)
        actual = b""
        while True:
            chunk = os.read(fd, 65536) if expected is not None else b""
            if not chunk:
                break
            actual += chunk
        if actual != (expected if expected is not None else b""):
            raise ValueError("fix target content changed; review the proposal again")
        # Verify again immediately before writing. The open descriptor and
        # no-follow flag prevent path substitution from redirecting the write.
        if target.is_symlink():
            raise ValueError("refusing to write through a symlink")
        os.ftruncate(fd, 0)
        os.lseek(fd, 0, os.SEEK_SET)
        view = memoryview(proposed)
        while view:
            count = os.write(fd, view)
            view = view[count:]
        os.fsync(fd)
    except Exception:
        # Restore the exact bytes only if this call actually changed the file;
        # callers' intervening edits are never overwritten.
        try:
            os.lseek(fd, 0, os.SEEK_SET)
            current = os.read(fd, max(len(proposed), 1_000_000))
            if current == proposed:
                os.ftruncate(fd, 0)
                os.lseek(fd, 0, os.SEEK_SET)
                if expected is not None:
                    os.write(fd, expected)
                os.fsync(fd)
        except OSError:
            pass
        raise
    finally:
        os.close(fd)
    return {"path": plan["path"], "before": expected.decode("utf-8") if expected is not None else None,
            "after": proposed.decode("utf-8"), "finding_ids": plan.get("finding_ids", [])}


def apply(root: Path, plans: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Apply approved plans if target bytes still match the reviewed snapshot.

    If a later plan fails, prior files are rolled back only when their contents
    still exactly match the bytes written by this call.
    """
    root = Path(root).resolve()
    if not root.is_dir():
        raise NotADirectoryError(root)
    # Plans touching the same file cannot both describe the same reviewed
    # snapshot; reject them before making the first write.
    seen: set[str] = set()
    for plan in plans:
        target, expected, _ = _validate_plan(root, plan)
        relative = target.relative_to(root).as_posix()
        if relative in seen:
            raise ValueError("multiple fix plans target the same file")
        seen.add(relative)
        try:
            current = target.read_bytes()
        except FileNotFoundError:
            current = None
        if current != expected:
            raise ValueError("fix target content changed; review the proposal again")
    applied: list[dict[str, Any]] = []
    try:
        for plan in plans:
            applied.append(_write_checked(root, plan))
    except Exception:
        for record in reversed(applied):
            target = root / record["path"]
            try:
                if target.is_symlink() or _read_text_exact(target) != record["after"]:
                    continue
                before = record["before"]
                if before is None:
                    target.unlink()
                else:
                    expected_after = record["after"].encode("utf-8")
                    fd = os.open(target, os.O_RDWR | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0))
                    try:
                        current = b""
                        while True:
                            chunk = os.read(fd, 65536)
                            if not chunk:
                                break
                            current += chunk
                        if current != expected_after:
                            continue
                        os.ftruncate(fd, 0)
                        os.lseek(fd, 0, os.SEEK_SET)
                        os.write(fd, before.encode("utf-8"))
                        os.fsync(fd)
                    finally:
                        os.close(fd)
            except (OSError, UnicodeError):
                continue
        raise
    return applied
