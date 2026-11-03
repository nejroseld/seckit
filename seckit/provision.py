"""Non-destructive user-local installation, with verification before execution."""
from __future__ import annotations
import hashlib
from concurrent.futures import ThreadPoolExecutor
import json
import os
import platform
import re
import shutil
import subprocess
import tarfile
import tempfile
import time
import urllib.parse
import urllib.request
import sys
import venv
import zipfile
from pathlib import Path

TRIVY = "0.76.1"
SEMGREP = "1.182.0"
PIP = "26.2.2"
# Pinned digest of the publisher's checksum manifest, from immutable GitHub release.
CHECKSUM_SHA256 = "885debc41b570179e81af560e5f393a66be29b9ff8c52915674f3eb2304c535d"

def _note(message: str) -> None:
    """Progress goes to stderr so JSON on stdout stays clean."""
    print(f"seckit: {message}", file=sys.stderr, flush=True)


class ProvisionError(RuntimeError):
    pass

def cache_dir() -> Path:
    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData/Local"))
    else:
        base = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache"))
    return base / "seckit"

def fetch(url: str) -> bytes:
    if urllib.parse.urlsplit(url).scheme != "https":
        raise ProvisionError("Only HTTPS downloads are allowed")
    try:
        with urllib.request.urlopen(url, timeout=60) as response:
            if urllib.parse.urlsplit(response.url).scheme != "https":
                raise ProvisionError("Insecure download redirect")
            return response.read(512 * 1024 * 1024)
    except OSError as exc:
        raise ProvisionError("Download unavailable. Check network access and run seckit doctor.") from exc

def verify(data: bytes, digest: str) -> None:
    if hashlib.sha256(data).hexdigest() != digest:
        raise ProvisionError("Download checksum mismatch; nothing executed")

def compatible(path: str, version: str) -> bool:
    try:
        p = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=15,
                           env={**os.environ, "SEMGREP_ENABLE_VERSION_CHECK": "0", "SEMGREP_SEND_METRICS": "off"})
        return p.returncode == 0 and re.search(r"(?<![\d.])" + re.escape(version) + r"(?![\d.])", p.stdout) is not None
    except (OSError, subprocess.TimeoutExpired):
        return False

def _trivy(base: Path) -> str:
    system = {"Linux": "Linux", "Darwin": "macOS", "Windows": "windows"}.get(platform.system())
    arch = {"x86_64": "64bit", "AMD64": "64bit", "aarch64": "ARM64", "arm64": "ARM64"}.get(platform.machine())
    if not system or not arch:
        raise ProvisionError("Unsupported Trivy platform; use Linux, macOS, or Windows x64/ARM64")
    name = "trivy.exe" if os.name == "nt" else "trivy"
    dest = base / f"trivy-{TRIVY}" / name
    if dest.is_file() and compatible(str(dest), TRIVY): return str(dest)
    _note(f"downloading Trivy {TRIVY} (first run only, ~1 min including all scanners)")
    url = f"https://github.com/aquasecurity/trivy/releases/download/v{TRIVY}/"
    checksums = fetch(url + f"trivy_{TRIVY}_checksums.txt")
    verify(checksums, CHECKSUM_SHA256)
    filename = f"trivy_{TRIVY}_{system}-{arch}." + ("zip" if os.name == "nt" else "tar.gz")
    sums = dict((line.split()[-1].lstrip("*"), line.split()[0]) for line in checksums.decode().splitlines() if len(line.split()) == 2)
    if filename not in sums: raise ProvisionError("No verified binary for this platform")
    data = fetch(url + filename)
    verify(data, sums[filename])
    import io
    if filename.endswith("zip"):
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            binary = archive.read(name)
    else:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
            member = archive.getmember(name)
            if not member.isfile(): raise ProvisionError("Unexpected archive member")
            binary = archive.extractfile(member).read()
    dest.parent.mkdir(parents=True, exist_ok=True)
    temporary = dest.with_suffix(".tmp")
    temporary.write_bytes(binary)
    temporary.chmod(0o700)
    temporary.replace(dest)
    if not compatible(str(dest), TRIVY): raise ProvisionError("Installed Trivy did not pass version check")
    return str(dest)

def _checked(command: list[str]) -> None:
    try:
        proc = subprocess.run(command, capture_output=True, timeout=600)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ProvisionError("Scanner installation could not complete") from exc
    if proc.returncode:
        raise ProvisionError("Semgrep installation failed. Python 3.10–3.14 with binary wheels and network access is recommended; run seckit doctor.")

def _pip_version(python: str) -> str | None:
    """Read the venv pip version without allowing the project cwd to shadow it."""
    try:
        proc = subprocess.run([python, "-I", "-m", "pip", "--version"], capture_output=True,
                              text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode:
        return None
    match = re.search(r"\bpip\s+([0-9]+(?:\.[0-9A-Za-z]+)+)", proc.stdout)
    return match.group(1) if match else None

def _ensure_pip(python: str, base: Path) -> None:
    """Replace venv bootstrap pip with a PyPI-metadata-verified pinned wheel."""
    if _pip_version(python) == PIP:
        return
    try:
        metadata = json.loads(fetch(f"https://pypi.org/pypi/pip/{PIP}/json"))
    except (json.JSONDecodeError, TypeError) as exc:
        raise ProvisionError("Pinned pip release metadata was invalid") from exc
    info = metadata.get("info") or {}
    if info.get("name", "").lower() != "pip" or info.get("version") != PIP:
        raise ProvisionError("Pinned pip release metadata did not match the requested version")
    filename = f"pip-{PIP}-py3-none-any.whl"
    matches = [item for item in metadata.get("urls", [])
               if item.get("filename") == filename and item.get("packagetype") == "bdist_wheel"]
    if len(matches) != 1:
        raise ProvisionError("Pinned pip universal wheel was missing from publisher metadata")
    artifact = matches[0]
    url = urllib.parse.urlsplit(artifact.get("url", ""))
    digest = (artifact.get("digests") or {}).get("sha256", "")
    if url.scheme != "https" or url.hostname != "files.pythonhosted.org" or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ProvisionError("Pinned pip wheel metadata was invalid")
    wheel_data = fetch(artifact["url"])
    verify(wheel_data, digest)
    with tempfile.TemporaryDirectory(dir=base) as tmp:
        wheel = Path(tmp) / filename
        wheel.write_bytes(wheel_data)
        requirements = Path(tmp) / "verified-pip.txt"
        requirements.write_text(f"pip=={PIP} --hash=sha256:{digest}\n")
        _checked([python, "-I", "-m", "pip", "--isolated", "--disable-pip-version-check",
                  "install", "--no-index", "--no-deps", "--find-links", tmp,
                  "--require-hashes", "--upgrade", "-r", str(requirements)])
    if _pip_version(python) != PIP:
        raise ProvisionError("Installed pip did not pass the pinned version check")

def _semgrep(base: Path) -> str:
    folder = base / f"semgrep-{SEMGREP}"
    bindir = folder / ("Scripts" if os.name == "nt" else "bin")
    executable = bindir / ("semgrep.exe" if os.name == "nt" else "semgrep")
    python = str(bindir / ("python.exe" if os.name == "nt" else "python"))
    if executable.exists() and compatible(str(executable), SEMGREP):
        _ensure_pip(python, base)
        return str(executable)
    _note(f"installing Semgrep {SEMGREP} into the scanner cache (first run only)")
    try:
        venv.EnvBuilder(with_pip=True).create(folder)
    except (OSError, subprocess.SubprocessError) as exc:
        raise ProvisionError("Python venv/pip support is unavailable; use a full user-space Python installation.") from exc
    _ensure_pip(python, base)
    # Download wheels without executing source builds. Verify every transitive wheel
    # against PyPI's HTTPS metadata before allowing pip to install any of them.
    with tempfile.TemporaryDirectory(dir=base) as tmp:
        _checked([python, "-I", "-m", "pip", "--isolated", "--disable-pip-version-check", "download", "--index-url", "https://pypi.org/simple", "--only-binary=:all:", "--dest", tmp, f"semgrep=={SEMGREP}"])
        def verified_requirement(wheel: Path) -> str:
            package, version = wheel.name.split("-")[:2]
            metadata = json.loads(fetch(f"https://pypi.org/pypi/{package}/{version}/json"))
            matches = [item for item in metadata["urls"] if item["filename"] == wheel.name]
            if len(matches) != 1: raise ProvisionError("Wheel missing from publisher metadata")
            digest = matches[0]["digests"]["sha256"]
            verify(wheel.read_bytes(), digest)
            return f"{package}=={version} --hash=sha256:{digest}"
        with ThreadPoolExecutor(max_workers=8) as workers:
            lock = list(workers.map(verified_requirement, Path(tmp).glob("*.whl")))
        if not lock: raise ProvisionError("No Semgrep wheels downloaded")
        requirements = Path(tmp) / "verified.txt"
        requirements.write_text("\n".join(sorted(lock)) + "\n")
        _checked([python, "-I", "-m", "pip", "--isolated", "--disable-pip-version-check", "install", "--no-index", "--find-links", tmp, "--require-hashes", "-r", str(requirements)])
        (folder / "verified-requirements.txt").write_text(requirements.read_text())
    if not compatible(str(executable), SEMGREP): raise ProvisionError("Installed Semgrep did not pass version check")
    return str(executable)

def _locked_install(base: Path, name: str, installer) -> str:
    """Serialize installers for the same cache, including across CLI processes."""
    with (base / f".{name}.install.lock").open("a+b") as lock:
        if os.name == "nt":
            import msvcrt
            if lock.tell() == 0:
                lock.write(b"0"); lock.flush()
            lock.seek(0)
            while True:
                try:
                    msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
                    break
                except OSError:
                    time.sleep(0.5)
        else:
            import fcntl
            fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            return installer(base)
        finally:
            if os.name == "nt":
                lock.seek(0)
                msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(lock, fcntl.LOCK_UN)


def tools(install: bool = True) -> dict[str, str]:
    base = cache_dir()
    def resolve(spec):
        name, version, installer = spec
        existing = shutil.which(name)
        if existing and compatible(existing, version):
            return name, existing
        if install:
            try:
                base.mkdir(parents=True, exist_ok=True, mode=0o700)
            except OSError as exc:
                raise ProvisionError("Scanner cache is not writable. Set XDG_CACHE_HOME (LOCALAPPDATA on Windows) to a writable directory.") from exc
            return name, _locked_install(base, name, installer)
        path = base / f"{name}-{version}"
        path = path / ("trivy.exe" if os.name == "nt" else "trivy") if name == "trivy" else path / ("Scripts/semgrep.exe" if os.name == "nt" else "bin/semgrep")
        return name, str(path) if path.exists() and compatible(str(path), version) else None
    specs = (("trivy", TRIVY, _trivy), ("semgrep", SEMGREP, _semgrep))
    with ThreadPoolExecutor(max_workers=2) as workers:
        return {name: path for name, path in workers.map(resolve, specs) if path is not None}
