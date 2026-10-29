"""Build a self-contained local Guardkit MCP App plugin package."""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
from pathlib import Path


def build(root: Path, output: Path) -> dict:
    """Build a portable local plugin, without installing or uploading it."""
    root = Path(root).resolve(strict=True)
    output = Path(output).expanduser().resolve(strict=False)
    if not root.is_dir():
        raise ValueError("Project root must be a directory")
    if output.exists() or output.is_symlink():
        raise FileExistsError("Plugin output already exists")
    source_package = Path(__file__).resolve().parent
    if output == source_package or source_package in output.parents:
        raise ValueError("Plugin output must be outside the Guardkit runtime package")
    parent = output.parent
    parent.mkdir(parents=True, exist_ok=True)

    manifest = {
        "$schema": "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json",
        "name": "guardkit-safe-input",
        "version": "0.1.0",
        "description": "Private local credential entry for Guardkit safe input.",
        "extensions": {"com.openai": {"interface": {
            "displayName": "Guardkit Safe Input",
            "shortDescription": "Private credential input",
            "capabilities": ["Interactive"],
        }}},
    }
    mcp = {
        "$schema": "https://agent-plugins.org/schemas/1.0.0/mcp.schema.json",
        "mcpServers": {"guardkit": {
            # Keep the venv entrypoint itself: resolving its symlink can select
            # the base interpreter, which may not have optional app dependencies.
            "type": "stdio", "command": os.path.abspath(sys.executable),
            "args": ["-I", "${PLUGIN_ROOT}/server.py", "--root", str(root)],
        }},
    }
    temp = Path(tempfile.mkdtemp(prefix=f".{output.name}.", dir=parent))
    try:
        runtime = temp / "runtime" / "guardkit"
        runtime.mkdir(parents=True)
        package = source_package
        for source in sorted(package.glob("*.py")):
            if source.is_file() and not source.is_symlink():
                shutil.copy2(source, runtime / source.name)
        for directory, pattern in (("rules", "*.yml"), ("ui", "*.html")):
            source_dir = package / directory
            target_dir = runtime / directory
            target_dir.mkdir()
            if source_dir.is_dir() and not source_dir.is_symlink():
                for source in sorted(source_dir.glob(pattern)):
                    if source.is_file() and not source.is_symlink():
                        shutil.copy2(source, target_dir / source.name)
        (temp / "plugin.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        (temp / "mcp.json").write_text(json.dumps(mcp, indent=2) + "\n", encoding="utf-8")
        (temp / "server.py").write_text(
            "from pathlib import Path\nimport sys\n"
            "sys.path.insert(0, str(Path(__file__).resolve().parent / 'runtime'))\n"
            "from guardkit.cli import main\n"
            "if __name__ == '__main__':\n"
            "    raise SystemExit(main(['mcp', *sys.argv[1:]]))\n",
            encoding="utf-8",
        )
        skill_dir = temp / "skills" / "guardkit-safe-input"
        skill_dir.mkdir(parents=True)
        (skill_dir / "SKILL.md").write_text(
            "---\nname: guardkit-safe-input\n"
            "description: Use when an agent needs a user to enter a credential privately for an approved local request.\n---\n\n"
            "Use Guardkit's `open_safe_input` interaction to request credentials. Keep values in the private UI and send only the encrypted envelope to the local server. Never put credential values in chat, tool arguments, logs, or files.\n\n"
            "A compatible desktop MCP Apps host is required to render the private UI. Clients without Apps support must use the terminal fallback; do not replace it with a plain HTML page.\n",
            encoding="utf-8",
        )
        os.rename(temp, output)
    except BaseException:
        shutil.rmtree(temp, ignore_errors=True)
        raise
    return {"plugin_directory": str(output.resolve()), "manifest": manifest, "mcp": mcp}
