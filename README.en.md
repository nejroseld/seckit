<p align="center">
  <img src="assets/hero.svg" alt="Guardkit" width="100%">
</p>

<p align="center">
  <b>Local security checks for your project, built for Claude Code, Codex and Cursor.</b><br>
  <a href="README.md">Русский</a> · English
</p>

<p align="center">
  <img alt="Python 3.10+" src="https://img.shields.io/badge/python-3.10%2B-3776ab?logo=python&logoColor=white">
  <img alt="Linux · macOS · WSL" src="https://img.shields.io/badge/Linux%20·%20macOS%20·%20WSL-0f172a">
  <img alt="Trivy + Semgrep" src="https://img.shields.io/badge/Trivy%20%2B%20Semgrep-10b981">
  <a href="LICENSE"><img alt="MIT" src="https://img.shields.io/badge/license-MIT-64748b"></a>
</p>

Guardkit finds vulnerabilities. Your agent reviews the findings and fixes the code. No API key needed.

## Install

The easiest way is to give your agent the [installation prompt](README.md#установка) from the Russian README.

Or install manually (Linux, macOS, WSL):

```bash
git clone https://github.com/nejroseld/guardkit.git && cd guardkit
python3 -m venv .venv && .venv/bin/python -I -m pip install .
.venv/bin/guardkit init --root /path/to/project
.venv/bin/guardkit scan --root /path/to/project
```

The repository is private for now, so you need GitHub access. The first run downloads scanners and databases.

## What it checks

| | |
|---|---|
| **Code** | dangerous patterns in Python, JS, TS (Semgrep) |
| **Dependencies** | known CVEs in packages (Trivy) |
| **Config** | Dockerfile, Kubernetes, Terraform (Trivy) |
| **Secrets** | leaked keys and tokens, values never printed |

## How it works

<p align="center"><img src="assets/flow.en.svg" alt="agent, scan, triage, review_id, rescan" width="100%"></p>

1. `guardkit scan --json` finds problems.
2. `guardkit fix --check --json` suggests fixes and returns a `review_id`.
3. `guardkit fix --apply REVIEW_ID --json` applies only that plan, the one already shown, then scans again.

Anything the plans don't cover, the agent edits itself and shows you the changes.

`scan` exit codes: 0 no findings, 1 findings, 2 scan incomplete (not "clean"). `fix`: 0 proposals ready, 2 operation incomplete.

`guardkit init` connects your agent: it adds blocks to `AGENTS.md`/`CLAUDE.md`, installs skills for Codex and Claude Code, and adds a Cursor rule. The same commands are available as an MCP server: `scan`, `findings`, `propose_safe_fixes`, `apply_safe_fixes`, `open_safe_input`.

## Secrets stay out of the chat

<p align="center"><img src="assets/trust.en.svg" alt="the agent gets only status and a reference; the value goes to the OS keystore" width="100%"></p>

When the agent needs a token or login, it calls `open_safe_input`. You type the value into a masked field (form or TUI) and it goes to the OS keystore. The agent sees only status and a reference.

In MCP Apps clients the form opens right in the chat, and the value is encrypted before it is sent (AES-256-GCM, key wrapped with RSA-OAEP). To build a plugin for such a client: `guardkit plugin --root PROJECT --output OUTPUT`. See [Safe Input App](docs/safe-input-app.md) and [Secrets](docs/secrets.md#safe-input-for-agent-requests).

## Docs

[Setup](docs/setup.md) · [Agents & MCP](docs/agents.md) · [Scanners](docs/scanners.md) · [Secrets](docs/secrets.md) · [Safe Input App](docs/safe-input-app.md) · [Validation](docs/validation.md) · [Audit](docs/security-audit.md)

<sub>MIT · Scanning does not guarantee that there are no vulnerabilities.</sub>
