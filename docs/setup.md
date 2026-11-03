# Setup and operations

Guardkit is designed to be installed and used by a coding agent as the project's local security toolkit. The agent supplies the intelligence: it investigates scanner evidence, interprets project context, and makes changes within the user's task. Guardkit provides local deterministic tools and does not bundle an LLM or require an AI API key. Install it in an isolated virtual environment outside the project being scanned. The distribution name is `guardkit-local`; it is not published to PyPI/npm.

`init` provisions scanners and always installs project-local agent instructions. It adds managed blocks to `AGENTS.md` and `CLAUDE.md`, Codex and Claude Code skills, and a Cursor rule marked `alwaysApply: true`. Existing custom text is preserved; only exact recognized old Guardkit templates are migrated. Its JSON result includes the command and arguments for optional MCP client registration; init does not change global client configuration. Commands accept `--root PATH`; `scan`, `fix`, `init`, and `doctor` emit JSON by default, accept explicit `--json`, and accept `--human` for terminal display. Scan exit codes: 0 means complete with no findings, 1 means findings, and 2 means incomplete. A clean static scan is not proof of security or authorization correctness.

`fix` defaults to producing proposals only; it does not apply changes or require a TTY. `fix --check --json` returns sanitized diffs and a `review_id`. Proposal generation exits 0 on success even when findings exist; exit 2 means incomplete. To apply, pass the ID to `fix --apply REVIEW_ID --json`; Guardkit applies only the exact reviewed bytes in the selected project and rescans. `--run-tests` must be supplied alongside `--apply REVIEW_ID` to opt into tests after application. `--skip-tests` is retained as a legacy no-op. CLI review snapshots are stored outside the project in the private user scanner cache at `/reviews`, with directory mode 0700 and file mode 0600. Each snapshot is root-bound, one-use, and expires after one hour. Snapshots contain exact before/after bytes internally, potentially including sensitive comments; CLI output shows sanitized diffs only. MCP review IDs live only in the server session. The coding agent handles other remediation as normal project changes within the user's task authority and reports those changes. Machine-readable errors are available to agent workflows.

Trivy 0.76.1 is fetched from official GitHub releases; a shipped SHA256 pin authenticates the checksums manifest before extraction of the single binary. Archive links/paths are never extracted. Semgrep 1.182.0 installs in a private virtual environment; only wheels are permitted and each transitive wheel is checked against PyPI HTTPS metadata before hash-enforced offline installation. Transitive versions are resolved at install time and recorded in `verified-requirements.txt`: engine versions/rules are pinned, but fresh dependency resolution and changing CVE databases mean results are not bit-for-bit reproducible. Publisher TLS and pinned Trivy manifest are the supply-chain trust roots; this is not independent signature verification. Existing exact-version executables on PATH are reused as user-trusted installations. Local cache tampering by the same user is outside this boundary.

Installations run in parallel with per-scanner process locks; wheel metadata/hash verification uses a bounded worker pool. No wheel is installed until all checks pass.

Before resolving Semgrep dependencies, Guardkit upgrades the private environment's
pip to pinned version 26.2.2. Its universal wheel is fetched directly from PyPI's
release metadata, verified against the published SHA-256, and installed offline
with `python -I`, `--no-deps`, and `--require-hashes`. Cached Semgrep environments
receive the same pip check and update without rebuilding the scanner environment.
The build backend requires setuptools 84.1.0 or later.

Cache: `$XDG_CACHE_HOME/guardkit`, `~/.cache/guardkit`, or `%LOCALAPPDATA%/guardkit`. No permanent service runs. `doctor` diagnoses Python, tools, cache and stack. Initial install and CVE database fetch require internet. Failed downloads fail closed, not as clean scans. Python 3.10–3.14 scanner wheels are published; Linux Python 3.14 was tested locally. Unsupported wheels produce an actionable installation error. Linux x64/ARM64 and macOS x64/ARM64 are implementation targets; native Windows is conditional on publisher artifacts. WSL follows Linux. These are support targets, not a tested platform matrix.

Uninstall the Python package using the installer that installed it, then remove the displayed Guardkit cache directory if desired. Remove only Guardkit-owned project instruction files, retaining local edits. `guardkit uninstall` prints these locations without deleting anything.

Source provenance for pins: [Trivy 0.76.1 release](https://github.com/aquasecurity/trivy/releases/tag/v0.76.1), [published checksum manifest digest](https://github.com/aquasecurity/trivy/releases?after=v0.10.2), [Semgrep 1.182.0](https://pypi.org/project/semgrep/1.182.0/). Guardkit ships no scanner binaries; their upstream licenses remain applicable.

Trivy is invoked with repository config, ignore, and secret-rule files disabled; only the shipped orchestration policy and built-in checks are used. Semgrep uses bundled rules, ignores repository `.semgrepignore`/`.gitignore` files and inline `nosemgrep`, and applies Guardkit's explicit generated/dependency directory exclusions. Filesystem scans inspect dependency manifests, source, and deployment files; they do not pull/build container images or scan Git history.

## Migrating an existing installation

Reinstall the updated package in its trusted virtual environment and rerun `init --root PROJECT`. Exact legacy Guardkit templates are migrated; custom instructions are retained alongside managed blocks. The former `init --no-agents` option is removed. JSON is now the default; use `--human` when reading terminal output. Replace interactive `fix` automation with the proposal `review_id` followed by `fix --apply REVIEW_ID`. CLI review IDs last one hour and are single-use; MCP review IDs last only for the server session.

Scanners are downloaded on first use; progress lines are written to stderr
(`guardkit: downloading Trivy …`), stdout stays valid JSON. A cold first scan
takes about a minute. Running the repository's own tests needs the package on
the path (`pip install -e .` or `PYTHONPATH=.`); `python -I` hides the working
directory.
