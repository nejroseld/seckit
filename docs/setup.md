# Setup and operations

Seckit is installed by the user and used by a coding agent as the project's local security toolkit. The agent supplies the intelligence: it investigates scanner evidence, interprets project context, and makes changes within the user's task. Seckit provides local deterministic tools and does not bundle an LLM or require an AI API key. Install it from [PyPI](https://pypi.org/project/seckit/) as the `seckit` package into its own environment outside the project being scanned, with `pipx install seckit` or `uv tool install seckit`; both put the `seckit` command on PATH. Releases are built by `.github/workflows/publish.yml` from a version tag and carry a Sigstore provenance attestation.

## Install (Linux and macOS)

### Requirements

- Python 3.10 to 3.14 with `venv` and `pip` (Seckit builds a private environment for Semgrep).
- `pipx` or `uv`, to install Seckit into its own environment and put `seckit` on PATH.
- `git` (recommended): the project root is the git top level, and change review reads diffs.
- Internet on the first `init` and on scans that refresh the CVE database: GitHub releases (Trivy), pypi.org and files.pythonhosted.org (Semgrep, pip).
- About 1 GB free in the cache directory `~/.cache/seckit` (the scanners alone take roughly 0.5 GB).
- A glibc 2.34 or newer Linux (Debian 12, Ubuntu 22.04, Fedora 35 or newer), or musl (Alpine), or macOS 11 or newer on Intel or Apple silicon. Older distributions such as Ubuntu 20.04 and RHEL 8 have no Semgrep wheel; use a newer Python image or WSL with a recent distribution.

### 1. Python, git and pipx

macOS ([Homebrew](https://brew.sh)). The Python that ships with Xcode tools is 3.9, too old:

```bash
brew install python pipx git
pipx ensurepath
```

Debian, Ubuntu (Ubuntu 23.04 and Debian 12 or newer have the `pipx` package):

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip pipx git
pipx ensurepath
```

On an older release without the `pipx` package, replace it with `python3 -m pip install --user pipx`, then run `python3 -m pipx ensurepath`.

Fedora, RHEL-compatible:

```bash
sudo dnf install -y python3 python3-pip pipx git
pipx ensurepath
```

Arch:

```bash
sudo pacman -S --needed python python-pipx git
pipx ensurepath
```

Alpine:

```bash
sudo apk add python3 py3-pip pipx git
pipx ensurepath
```

Open a new terminal afterwards so PATH picks up `~/.local/bin`. Check `python3 --version` prints 3.10 or newer; if not, install a newer Python (`brew install python@3.13`, the `deadsnakes` PPA on Ubuntu, `dnf install python3.13`) and pass it to pipx with `--python python3.13`.

Instead of pipx you can use [uv](https://docs.astral.sh/uv/getting-started/installation/) (`brew install uv`, or the official installer); it downloads a suitable Python by itself.

### 2. Seckit

```bash
pipx install seckit        # or uv tool install seckit
seckit --version
```

### 3. A project

```bash
cd /path/to/project
seckit init
```

`init` downloads Trivy and Semgrep into the cache (about a minute the first time) and writes the agent instructions into the project. Preview first with `seckit init --plan`. Then run `seckit doctor`: it reports the Python, the platform, whether `seckit` on PATH belongs to this installation, the scanner versions and the cache path.

### Update and remove

```bash
pipx upgrade seckit            # uv tool upgrade seckit
seckit init                    # in each project, to refresh its instructions
```

```bash
seckit uninstall               # in a project: removes only Seckit-managed blocks and files
pipx uninstall seckit          # uv tool uninstall seckit
rm -rf ~/.cache/seckit         # scanners and review cache
```

### If something fails

| Symptom | Fix |
|---|---|
| `seckit: command not found` | Run `pipx ensurepath` and open a new terminal. |
| `Python venv/pip support is unavailable` | Debian and Ubuntu: `sudo apt install python3-venv`. |
| `Semgrep installation failed` | Python older than 3.10, a Linux older than glibc 2.34, or no access to pypi.org. Run `seckit doctor`. |
| `Download unavailable` | Allow HTTPS to github.com, pypi.org and files.pythonhosted.org, or set `HTTPS_PROXY`. |
| `Scanner cache is not writable` | Point `XDG_CACHE_HOME` at a writable directory. |
| `doctor` says `seckit` on PATH is not this installation | Another copy shadows it; remove the old one or put the pipx `bin` directory first on PATH. |

### Allow seckit in your agent

`seckit scan` updates the CVE database over the network and writes to `~/.cache/seckit`, so a sandboxed agent needs `seckit` allowed to run outside the sandbox. Allow the command once:

- **Claude Code**: `/permissions`, add the allow rule `Bash(seckit *)`, or put it in `.claude/settings.local.json`:
  `{"permissions": {"allow": ["Bash(seckit *)"]}}`. Narrow rules [stay in effect in auto mode](https://code.claude.com/docs/en/permission-modes) and skip the classifier. Answering "Yes, and don't ask again" on the first prompt does the same.
- **Codex**: add a [rule](https://learn.chatgpt.com/docs/agent-configuration/rules); `allow` runs the command outside the sandbox without prompting:
  ```bash
  mkdir -p ~/.codex/rules
  echo 'prefix_rule(pattern = ["seckit"], decision = "allow")' >> ~/.codex/rules/default.rules
  ```
- **Cursor**: Settings > Agents > Approvals & Execution, add `seckit` to the command allowlist. In Auto-review mode allowlisted commands run outside the sandbox.
- **OpenCode**: nothing to do with default settings. If your `opencode.json` sets `bash` to `ask`, add `"seckit *": "allow"` after it (the last matching rule wins).

OpenCode reads `AGENTS.md` and the skills in `.claude/skills` and `.agents/skills`, so `init` covers it without extra files. Cursor loads skills from `.agents/skills` and `.claude/skills` as well as its rule.

## Operations


`init` provisions scanners and always installs project-local agent instructions. It adds managed blocks to `AGENTS.md` and `CLAUDE.md`, Codex and Claude Code skills, and a Cursor rule marked `alwaysApply: true`. Existing custom text is preserved; only exact recognized old Seckit templates are migrated. Its JSON result includes the command and arguments for optional MCP client registration; init does not change global client configuration. Commands accept `--root PATH`, which defaults to the git top level of the working directory (or the directory itself outside git); `init --plan` shows the files and diffs init would write without changing anything; `scan`, `fix`, `init`, and `doctor` emit JSON by default, accept explicit `--json`, and accept `--human` for terminal display. Scan exit codes: 0 means complete with no findings, 1 means findings, and 2 means incomplete. A clean static scan is not proof of security or authorization correctness.

`fix` defaults to producing proposals only; it does not apply changes or require a TTY. `fix --check --json` returns sanitized diffs and a `review_id`. Proposal generation exits 0 on success even when findings exist; exit 2 means incomplete. To apply, pass the ID to `fix --apply REVIEW_ID --json`; Seckit applies only the exact reviewed bytes in the selected project and rescans. `--run-tests` must be supplied alongside `--apply REVIEW_ID` to opt into tests after application. `--skip-tests` is retained as a legacy no-op. CLI review snapshots are stored outside the project in the private user scanner cache at `/reviews`, with directory mode 0700 and file mode 0600. Each snapshot is root-bound, one-use, and expires after one hour. Snapshots contain exact before/after bytes internally, potentially including sensitive comments; CLI output shows sanitized diffs only. MCP review IDs live only in the server session. The coding agent handles other remediation as normal project changes within the user's task authority and reports those changes. Machine-readable errors are available to agent workflows.

Trivy 0.76.1 is fetched from official GitHub releases; a shipped SHA256 pin authenticates the checksums manifest before extraction of the single binary. Archive links/paths are never extracted. Semgrep 1.182.0 installs in a private virtual environment; only wheels are permitted and each transitive wheel is checked against PyPI HTTPS metadata before hash-enforced offline installation. Transitive versions are resolved at install time and recorded in `verified-requirements.txt`: engine versions/rules are pinned, but fresh dependency resolution and changing CVE databases mean results are not bit-for-bit reproducible. Publisher TLS and pinned Trivy manifest are the supply-chain trust roots; this is not independent signature verification. Existing exact-version executables on PATH are reused as user-trusted installations. Local cache tampering by the same user is outside this boundary.

Installations run in parallel with per-scanner process locks; wheel metadata/hash verification uses a bounded worker pool. No wheel is installed until all checks pass.

Before resolving Semgrep dependencies, Seckit upgrades the private environment's
pip to pinned version 26.2.2. Its universal wheel is fetched directly from PyPI's
release metadata, verified against the published SHA-256, and installed offline
with `python -I`, `--no-deps`, and `--require-hashes`. Cached Semgrep environments
receive the same pip check and update without rebuilding the scanner environment.
The build backend requires setuptools 84.1.0 or later.

Cache: `$XDG_CACHE_HOME/seckit`, `~/.cache/seckit`, or `%LOCALAPPDATA%/seckit`. No permanent service runs. `doctor` diagnoses Python, tools, cache and stack. Initial install and CVE database fetch require internet. Failed downloads fail closed, not as clean scans. Python 3.10–3.14 scanner wheels are published; Linux Python 3.14 was tested locally. Unsupported wheels produce an actionable installation error. Linux x64/ARM64 and macOS x64/ARM64 are implementation targets; native Windows is conditional on publisher artifacts. WSL follows Linux. These are support targets, not a tested platform matrix.

Uninstall the Python package using the installer that installed it, then remove the displayed Seckit cache directory if desired. Remove only Seckit-owned project instruction files, retaining local edits. `seckit uninstall` prints these locations without deleting anything.

Source provenance for pins: [Trivy 0.76.1 release](https://github.com/aquasecurity/trivy/releases/tag/v0.76.1), [published checksum manifest digest](https://github.com/aquasecurity/trivy/releases?after=v0.10.2), [Semgrep 1.182.0](https://pypi.org/project/semgrep/1.182.0/). Seckit ships no scanner binaries; their upstream licenses remain applicable.

Trivy is invoked with repository config, ignore, and secret-rule files disabled; only the shipped orchestration policy and built-in checks are used. Semgrep uses bundled rules, ignores repository `.semgrepignore`/`.gitignore` files and inline `nosemgrep`, and applies Seckit's explicit generated/dependency directory exclusions. Filesystem scans inspect dependency manifests, source, and deployment files; they do not pull/build container images or scan Git history.

## Migrating from Guardkit

Seckit was previously called Guardkit (package `guardkit-local`, command `guardkit`). Install the `seckit` package and run `seckit init --root PROJECT` once per project. It replaces `guardkit:managed` blocks in `AGENTS.md` and `CLAUDE.md` in place, removes the old `guardkit` skills and Cursor rule while keeping any text you added to them, renames `.guardkit/` to `.seckit/` unless `.seckit/` already exists, and renames a `guardkit` server in the project-local `.mcp.json`. Until then, suppressions and verdicts are still read from `.guardkit/`. `seckit uninstall` removes old-name blocks too. The scanner cache moves to `~/.cache/seckit`, so scanners download once more; `doctor` points at the unused `~/.cache/guardkit`, which you can delete. The GitHub repository is now `nejroseld/seckit`; the old URL redirects.

## Migrating an existing installation

Reinstall the updated package in its trusted virtual environment and rerun `init --root PROJECT`. Exact legacy Seckit templates are migrated; custom instructions are retained alongside managed blocks. The former `init --no-agents` option is removed. JSON is now the default; use `--human` when reading terminal output. Replace interactive `fix` automation with the proposal `review_id` followed by `fix --apply REVIEW_ID`. CLI review IDs last one hour and are single-use; MCP review IDs last only for the server session.

Scanners are downloaded on first use; progress lines are written to stderr
(`seckit: downloading Trivy …`), stdout stays valid JSON. A cold first scan
takes about a minute. Running the repository's own tests needs the package on
the path (`pip install -e .` or `PYTHONPATH=.`); `python -I` hides the working
directory.
