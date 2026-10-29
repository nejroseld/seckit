# Setup and operations

Run `python3 -m guardkit init` from this checkout. For a console command in another project, install this source with `python3 -m pip install /absolute/path/to/checkout` (prefer a virtual environment), then run `guardkit init` in that project. The distribution name is `guardkit-local`; it is not published to PyPI/npm. No account, Docker, sudo, API key, or global agent settings are used.

`init` provisions scanners and adds missing project-local agent instructions; `--no-agents` skips instructions. `scan` provisions missing scanners automatically. Project commands accept `--root PATH`; scan, fix, init, doctor accept `--json`. `fix --check` reviews proposed changes, `fix` requires terminal approval then reruns scanners. When a test script or tests directory is detected, the fix approval also names the project test command. It runs only after that explicit approval, with a timeout and output discarded to prevent accidental credential logging. Use `fix --skip-tests` for scanner-only verification. Review project code before approving execution. Scanner errors yield exit 2; findings yield exit 1; complete clean scans yield exit 0. All findings remain in JSON, terminal shows the first 20. A clean static scan is not proof of security or authorization correctness.

Trivy 0.76.1 is fetched from official GitHub releases; a shipped SHA256 pin authenticates the checksums manifest before extraction of the single binary. Archive links/paths are never extracted. Semgrep 1.182.0 installs in a private virtual environment; only wheels are permitted and each transitive wheel is checked against PyPI HTTPS metadata before hash-enforced offline installation. Transitive versions are resolved at install time and recorded in `verified-requirements.txt`: engine versions/rules are pinned, but fresh dependency resolution and changing CVE databases mean results are not bit-for-bit reproducible. Publisher TLS and pinned Trivy manifest are the supply-chain trust roots; this is not independent signature verification. Existing exact-version executables on PATH are reused as user-trusted installations. Local cache tampering by the same user is outside this boundary.

Installations run in parallel with per-scanner process locks; wheel metadata/hash verification uses a bounded worker pool. No wheel is installed until all checks pass.

Before resolving Semgrep dependencies, Guardkit upgrades the private environment's
pip to pinned version 26.2.2. Its universal wheel is fetched directly from PyPI's
release metadata, verified against the published SHA-256, and installed offline
with `python -I`, `--no-deps`, and `--require-hashes`. Cached Semgrep environments
receive the same pip check and update without rebuilding the scanner environment.
The build backend requires setuptools 84.1.0 or later.

Cache: `$XDG_CACHE_HOME/guardkit`, `~/.cache/guardkit`, or `%LOCALAPPDATA%/guardkit`. No permanent service runs. `doctor` diagnoses Python, tools, cache, stack, and native store availability. Initial install and CVE database fetch require internet. Failed downloads fail closed, not as clean scans. Python 3.10–3.14 scanner wheels are published; Linux Python 3.14 was tested locally. Unsupported wheels produce an actionable installation error. Linux x64/ARM64 and macOS x64/ARM64 are implementation targets; native Windows is conditional on publisher artifacts. WSL follows Linux. These are support targets, not a tested platform matrix.

Uninstall the Python package using the installer that installed it, then remove the displayed Guardkit cache directory if desired. Remove only Guardkit-owned project instruction files, retaining local edits. `guardkit uninstall` prints these locations without deleting anything. Remove named credentials with `guardkit secrets delete NAME`; uninstall never removes credentials automatically.

Source provenance for pins: [Trivy 0.76.1 release](https://github.com/aquasecurity/trivy/releases/tag/v0.76.1), [published checksum manifest digest](https://github.com/aquasecurity/trivy/releases?after=v0.10.2), [Semgrep 1.182.0](https://pypi.org/project/semgrep/1.182.0/). Guardkit ships no scanner binaries; their upstream licenses remain applicable.

Trivy is invoked with repository config, ignore, and secret-rule files disabled; only the shipped orchestration policy and built-in checks are used. Semgrep uses bundled rules, ignores repository `.semgrepignore`/`.gitignore` files and inline `nosemgrep`, and applies Guardkit's explicit generated/dependency directory exclusions. Filesystem scans inspect dependency manifests, source, and deployment files; they do not pull/build container images or scan Git history.
