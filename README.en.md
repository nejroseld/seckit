<p align="center">
  <img src="https://raw.githubusercontent.com/nejroseld/seckit/main/assets/hero.svg" alt="Seckit" width="100%">
</p>

<p align="center">
  <b>Local security checks for your project, built for Claude Code, Codex, Cursor and OpenCode.</b><br>
  <a href="https://github.com/nejroseld/seckit/blob/main/README.md">Русский</a> · English
</p>

<p align="center">
  <a href="https://pypi.org/project/seckit/"><img alt="PyPI" src="https://img.shields.io/pypi/v/seckit?color=3776ab"></a>
  <img alt="Python 3.10+" src="https://img.shields.io/badge/python-3.10%2B-3776ab?logo=python&logoColor=white">
  <img alt="Linux · macOS · WSL" src="https://img.shields.io/badge/Linux%20·%20macOS%20·%20WSL-0f172a">
  <img alt="Trivy + Semgrep" src="https://img.shields.io/badge/Trivy%20%2B%20Semgrep-10b981">
  <a href="https://github.com/nejroseld/seckit/blob/main/LICENSE"><img alt="FSL-1.1-ALv2" src="https://img.shields.io/badge/license-FSL--1.1--ALv2-64748b"></a>
</p>

Seckit finds vulnerabilities and leaked secrets. Your agent reviews the findings and fixes the code. No API key needed, everything runs locally.

## What it does

| What | How |
|---|---|
| 🧩 **Code** | finds dangerous patterns in Python, JS, TS (Semgrep) |
| 📦 **Dependencies** | finds known CVEs in packages (Trivy) |
| ⚙️ **Config** | checks Dockerfile, Kubernetes, Terraform (Trivy) |
| 🔑 **Leaked secrets** | finds keys and tokens in project files without printing values |
| 🧾 **One report** | merges findings from all scanners into one list with priority and code location |
| 🗺️ **Attack surface** | maps entry points, dangerous calls, access checks and insecure defaults, and ranks files to read first |
| 🔀 **Change review** | shows new risky lines and removed checks in a diff or PR |
| ⛓️ **Supply chain** | catches install scripts, git and URL dependencies, dependency confusion, GitHub Actions injection and `curl \| sh` |
| 🔁 **Variants** | hunts siblings of a confirmed bug with a custom Semgrep rule or regex |
| ✅ **Triage** | records true/false positive verdicts with reasons and exports Markdown and SARIF reports |
| 🤖 **Agent** | plugs into Claude Code, Codex, Cursor and OpenCode via instructions and MCP; the agent reviews findings and applies reviewed fixes |

## Install

In a terminal (Linux, macOS, WSL):

```bash
pipx install seckit        # or uv tool install seckit
cd /path/to/project
seckit init
```

`init` downloads the Trivy and Semgrep scanners and adds Seckit instructions to AGENTS.md, CLAUDE.md, .claude/skills, .agents/skills and .cursor/rules, keeping your text. From then on the agent knows how to use Seckit: ask it to check the project.

So the agent doesn't ask for approval on every call, allow the `seckit` command: [Claude Code, Codex, Cursor, OpenCode](docs/setup.md#allow-seckit-in-your-agent).

## Docs

[Setup](https://github.com/nejroseld/seckit/blob/main/docs/setup.md) · [Agents & MCP](https://github.com/nejroseld/seckit/blob/main/docs/agents.md) · [Scanners](https://github.com/nejroseld/seckit/blob/main/docs/scanners.md) · [Audit tools](https://github.com/nejroseld/seckit/blob/main/docs/audit-tools.md)

<sub>FSL-1.1-ALv2 · Scanning does not guarantee that there are no vulnerabilities.</sub>
