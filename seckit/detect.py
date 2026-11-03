"""Repository technology detection without executing project code."""
import json
import os
from pathlib import Path


_MARKERS = {
    "Next.js": ("next.config.js", "next.config.mjs", "next.config.ts"),
    "Vite": ("vite.config.js", "vite.config.ts", "vite.config.mjs", "vite.config.mts"),
    "Node.js": ("package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"),
    "TypeScript": ("tsconfig.json",),
    "JavaScript": ("package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"),
    "Python": ("pyproject.toml", "requirements.txt", "Pipfile", "poetry.lock", "uv.lock", "setup.py", "setup.cfg"),
    "FastAPI": (),
    "Docker": ("Dockerfile", "docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"),
    "GitHub Actions": (),
    "Codex": ("AGENTS.md",),
    "Claude": (),
    "Cursor": (),
}


def detect(root: Path) -> list[str]:
    """Return sorted, conservative technology labels based on manifests/config."""
    root = Path(root)
    if not root.is_dir():
        return []
    found: set[str] = set()
    files: set[str] = set()
    try:
        for current, dirs, names in os.walk(root, topdown=True):
            dirs[:] = sorted(d for d in dirs if d not in {".git", "node_modules", ".venv", "venv", "dist", "build", ".next", "vendor"})
            base = Path(current)
            for name in names:
                p = base / name
                if p.is_symlink(): continue
                if p.suffix in {".js", ".jsx", ".mjs", ".cjs"}: found.add("JavaScript")
                if p.suffix in {".ts", ".tsx"}: found.add("TypeScript")
                if p.suffix == ".py": found.add("Python")
                rel = p.relative_to(root).as_posix()
                files.add(rel)
                files.add(name)
    except OSError:
        pass
    for label, markers in _MARKERS.items():
        if any(marker in files for marker in markers):
            found.add(label)
    # Parse only small manifests; avoid reading source files or executing code.
    for rel in sorted(f for f in files if f.endswith("package.json")):
        p = root / rel
        try:
            if p.stat().st_size > 1_000_000:
                continue
            data = json.loads(p.read_text(encoding="utf-8"))
            deps = {k for section in ("dependencies", "devDependencies", "peerDependencies") for k in data.get(section, {})}
            if "react" in deps: found.add("React")
            if "next" in deps: found.add("Next.js")
            if "vite" in deps: found.add("Vite")
            if "express" in deps: found.add("Express")
            if "typescript" in deps: found.add("TypeScript")
            if data.get("engines", {}).get("node") or deps: found.add("Node.js")
            if deps: found.add("JavaScript")
        except (OSError, ValueError, AttributeError, TypeError):
            continue
    for p in (root / "pyproject.toml", root / "requirements.txt", root / "Pipfile"):
        if not p.is_file(): continue
        try:
            content = p.read_text(encoding="utf-8")[:1_000_000].lower()
            if "fastapi" in content: found.add("FastAPI")
        except OSError: pass
    if any(f.startswith(".github/workflows/") for f in files): found.add("GitHub Actions")
    if ".claude" in files or any(f.startswith(".claude/") for f in files): found.add("Claude")
    if ".cursor" in files or any(f.startswith(".cursor/") for f in files): found.add("Cursor")
    return sorted(found)
