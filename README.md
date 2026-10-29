# Guardkit

Local Trivy and Semgrep security checks, reviewed fixes, and native credential-store access for developer projects.

## Install

From this checkout:

```bash
python3 -m guardkit init
```

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

Python 3.10+ and internet for initial scanner/database downloads. Linux and macOS; Windows support depends on scanner wheels, with WSL preferred. See [setup](docs/setup.md) and [validation status](docs/validation.md).
