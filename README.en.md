# Guardkit

[Русский](README.md) · English

Local Trivy and Semgrep security checks, reviewed fixes, and native credential-store access for developer projects.

## Agent Ctrl+C

Copy the [ready-to-send installation prompt](README.md#agent-ctrlc) into your coding agent. It installs Guardkit in a separate environment, initializes it for your project, and runs a scan. The repository is currently private, so the agent needs your existing GitHub access.

## Install

From this checkout:

```bash
python3 -m guardkit init
```

To install the CLI for another project, see [setup](docs/setup.md).

## Features

- Automatic stack detection and verified scanner installation.
- Prioritized findings in terminal or JSON.
- Approved project fixes and local Codex, Claude Code, and Cursor instructions.
- Native secret storage and scoped HTTP requests; [isolation limitations](docs/secrets.md).

## Usage

```bash
python3 -m guardkit scan
```

## Requirements

Python 3.10+ and internet for initial scanner/database downloads. Linux and macOS; Windows scanner support depends on publisher wheels, with WSL preferred. See [setup](docs/setup.md), [validation status](docs/validation.md), and the [security audit](docs/security-audit.md).

## License

[MIT](LICENSE).
