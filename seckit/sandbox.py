"""Process environment for scanners and git: what they may see, run and reach.

Scanners inherit only an allowlist of environment variables, never search a PATH
entry inside the scanned project, and, while they read the project, can reach no
network: every proxy variable points at a local port that refuses connections,
and git transports are disabled. Repository files can name hosts (Maven
repositories in pom.xml, remote Terraform modules); without this a scan would
contact them.
"""
from __future__ import annotations

import contextlib
import os
import socket
import subprocess
from pathlib import Path
from typing import Iterator

_KEEP = {"HOME", "USER", "LOGNAME", "USERNAME", "LANG", "LANGUAGE", "TZ", "TERM", "TMPDIR", "TMP", "TEMP",
         "SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "COMSPEC", "PATHEXT", "LOCALAPPDATA", "APPDATA", "USERPROFILE",
         "PROGRAMDATA", "SSL_CERT_FILE", "SSL_CERT_DIR", "SEMGREP_SETTINGS_FILE", "SEMGREP_LOG_FILE"}
_PROXIES = ("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "NO_PROXY")


def safe_path(root: Path | None) -> str:
    """PATH without relative entries or directories inside the scanned project."""
    root = Path(root).resolve() if root is not None else None
    entries = []
    for entry in os.environ.get("PATH", "").split(os.pathsep):
        if not entry or not os.path.isabs(entry):
            continue
        try:
            resolved = Path(entry).resolve()
        except (OSError, RuntimeError):
            continue
        if root is not None and (resolved == root or root in resolved.parents):
            continue
        entries.append(entry)
    return os.pathsep.join(entries)


def which(name: str, root: Path | None) -> str | None:
    """Find a program on the safe PATH only; the current directory is never searched."""
    suffixes = [""]
    if os.name == "nt":
        suffixes = [ext.lower() for ext in os.environ.get("PATHEXT", ".EXE;.CMD;.BAT").split(";") if ext] or [".exe"]
    for directory in safe_path(root).split(os.pathsep):
        if not directory:
            continue
        for suffix in suffixes:
            candidate = Path(directory) / (name + suffix)
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return str(candidate)
    return None


def environment(root: Path | None, offline_proxy: str | None, path: str | None = None) -> dict[str, str]:
    """Allowlisted environment; with `offline_proxy` all network access goes to a dead end."""
    env = {key: value for key, value in os.environ.items()
           if key.upper() in _KEEP or key.upper().startswith(("LC_", "XDG_"))}
    env["PATH"] = safe_path(root) if path is None else path
    if offline_proxy is None:
        env.update({key: value for key, value in os.environ.items() if key.upper() in _PROXIES})
    else:
        for key in _PROXIES:
            value = "" if key == "NO_PROXY" else offline_proxy
            env[key] = value
            if os.name != "nt":  # POSIX tools read either spelling; Windows names are case-insensitive
                env[key.lower()] = value
        # Git (used by scanners to fetch remote modules) gets no usable transport.
        env.update(GIT_ALLOW_PROTOCOL="seckit-none", GIT_SSH_COMMAND="exit 1", GIT_TERMINAL_PROMPT="0")
    env.update(NO_COLOR="1", GIT_CONFIG_NOSYSTEM="1", TRIVY_DISABLE_TELEMETRY="true",
               SEMGREP_SEND_METRICS="off", SEMGREP_ENABLE_VERSION_CHECK="0")
    return env


_ISOLATION: list[str] | None = None


def isolation() -> tuple[str, list[str]]:
    """How scanners are cut off from the network while they read the project.

    `namespace` (Linux with unprivileged user namespaces): a fresh network
    namespace with no interfaces up, so not even loopback services are
    reachable. Otherwise `proxy`: the refusing proxy plus disabled git
    transports, which stop remote hosts but not a direct request to loopback.
    """
    global _ISOLATION
    if _ISOLATION is None:
        _ISOLATION = []
        unshare = which("unshare", None) if os.name == "posix" else None
        true = which("true", None)
        if unshare and true:
            try:
                probe = subprocess.run([unshare, "--user", "--map-root-user", "--net", "--", true],
                                       capture_output=True, timeout=10, env={"PATH": ""})
                if probe.returncode == 0:
                    _ISOLATION = [unshare, "--user", "--map-root-user", "--net", "--"]
            except (OSError, subprocess.SubprocessError):
                pass
    return ("namespace" if _ISOLATION else "proxy"), list(_ISOLATION)


@contextlib.contextmanager
def no_network() -> Iterator[str]:
    """A proxy URL on a local port that is bound but never listens, so connections are refused."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", 0))
        yield f"http://127.0.0.1:{sock.getsockname()[1]}"
    finally:
        sock.close()
