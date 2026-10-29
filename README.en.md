<p align="center">
  <img src="assets/hero.svg" alt="Guardkit" width="100%">
</p>

<p align="center">
  <b>Security-check your project with one command — locally, no cloud.</b><br>
  <a href="README.md">Русский</a> · English
</p>

<p align="center">
  <img alt="Python 3.10+" src="https://img.shields.io/badge/python-3.10%2B-3776ab?logo=python&logoColor=white">
  <img alt="Linux · macOS · WSL" src="https://img.shields.io/badge/Linux%20·%20macOS%20·%20WSL-0f172a">
  <img alt="Trivy + Semgrep" src="https://img.shields.io/badge/Trivy%20%2B%20Semgrep-10b981">
  <a href="LICENSE"><img alt="MIT" src="https://img.shields.io/badge/license-MIT-64748b"></a>
</p>

<p align="center"><img src="assets/demo.svg" alt="guardkit scan" width="760"></p>

## Install

**With an agent.** Send the [installation prompt](README.md#установка) to Claude Code, Codex, or Cursor — it installs Guardkit and scans your project.

**Manually** (Linux, macOS, WSL):

```bash
git clone https://github.com/nejroseld/guardkit.git && cd guardkit
python3 -m venv .venv && .venv/bin/python -I -m pip install .
.venv/bin/guardkit init --root /path/to/project
.venv/bin/guardkit scan --root /path/to/project
```

> The repository is private for now — GitHub access required. The first run downloads scanners and databases.

## How it works

<p align="center"><img src="assets/flow.en.svg" alt="init → scan → fix" width="760"></p>

| | |
|---|---|
| 🧩 **Code** | dangerous patterns in Python, JS, TS (Semgrep) |
| 📦 **Dependencies** | known CVEs in packages (Trivy) |
| ⚙️ **Config** | Dockerfile, Kubernetes, Terraform (Trivy) |
| 🔑 **Secrets** | leaked keys and tokens, values never printed |

`guardkit fix --check` shows the diff; `guardkit fix` applies it after you confirm.

## More

[Setup](docs/setup.md) · [Agents & MCP](docs/agents.md) · [Scanners](docs/scanners.md) · [Secrets](docs/secrets.md) · [Validation](docs/validation.md) · [Audit](docs/security-audit.md)

<sub>MIT · Scanning does not guarantee the absence of all vulnerabilities.</sub>
