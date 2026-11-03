"""Suggested next actions an agent can offer the user after init, scan or doctor.

Each step says what it does, why it fits this project, the exact command and
which project files it would write, so the agent can tell at a glance whether
the step needs the user's go-ahead. Steps are ordered; agents show the first few.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

_WEB = {"FastAPI", "Next.js", "Node.js", "Vite"}
LIMIT = 4


def _step(step_id: str, title: str, why: str, command: str, writes: list[str] | None = None) -> dict[str, Any]:
    return {"id": step_id, "title": title, "why": why, "command": command, "writes": writes or []}


def _audit(stack: list[str]) -> dict[str, Any]:
    web = sorted(_WEB.intersection(stack))
    why = (f"{', '.join(web)} detected: a static scan does not check authorization, input handling or business logic."
           if web else "A static scan only matches known patterns; an audit reads the code that handles untrusted input.")
    return _step("audit", "Full security audit (read-only)", why,
                 "Use the bluekit-audit skill (starts with `bluekit surface --json`).")


def _supply_chain(root: Path) -> dict[str, Any] | None:
    if not (root / ".github" / "workflows").is_dir():
        return None
    return _step("supply-chain", "Check CI and dependencies for supply-chain risks",
                 "GitHub Actions workflows found: unpinned actions, broad permissions and script injection are common.",
                 "bluekit supply-chain --json")


def _ordered(steps: list[dict[str, Any] | None]) -> list[dict[str, Any]]:
    return [step for step in steps if step][:LIMIT]


def after_scan(root: Path, report: dict[str, Any]) -> list[dict[str, Any]]:
    findings = report.get("findings", [])
    stack = report.get("stack", [])
    steps: list[dict[str, Any] | None] = []
    if report.get("errors"):
        steps.append(_step("doctor", "Find out why some checks did not run",
                           "The scan is incomplete, so a missing finding does not mean the code is clean.",
                           "bluekit doctor --json"))
    fixable = [f for f in findings if f.get("fix_available")]
    if fixable:
        steps.append(_step("fix", f"Review proposed fixes for {len(fixable)} finding(s)",
                           "Bluekit has exact diffs for these; reviewing them changes nothing.",
                           "bluekit fix --check --json",
                           []))
    manual = len(findings) - len(fixable)
    if manual:
        steps.append(_step("review", f"Review {manual} finding(s) without an automatic fix",
                           "Each needs a verdict in context: real issue to fix, or a false positive to record.",
                           "bluekit triage FINDING_ID --verdict ... --reason '...'", [".bluekit/triage.json"]))
    steps.append(_audit(stack))
    steps.append(_supply_chain(root))
    return _ordered(steps)


def after_init(root: Path, stack: list[str], created: list[str], mcp_registered: bool, on_path: bool) -> list[dict[str, Any]]:
    steps: list[dict[str, Any] | None] = [
        _step("scan", "Run the first scan", "Code, dependencies, configuration and leaked secrets in one pass.",
              "bluekit scan --json"),
        _audit(stack),
    ]
    agent_files = [path for path in created if not path.startswith(".bluekit") and path != ".mcp.json"]
    if agent_files and (root / ".git").exists():
        steps.append(_step("commit-agent-files", "Decide whether to commit the agent files",
                           "They contain no machine-specific paths, so committing them gives teammates' agents the same setup."
                           if on_path else
                           "They contain this machine's install path; install Bluekit with pipx or uv first if you want to commit them.",
                           "git add " + " ".join(sorted({path.split("/", 1)[0] for path in agent_files}))))
    if not mcp_registered:
        steps.append(_step("mcp", "Optional: register the MCP server",
                           "Only needed if you want Bluekit as MCP tools; the CLI is enough for agents with a shell.",
                           "bluekit init --mcp", [".mcp.json"]))
    return _ordered(steps)


def after_doctor(report: dict[str, Any]) -> list[dict[str, Any]]:
    steps: list[dict[str, Any] | None] = []
    command = report.get("command", {})
    if command.get("path") and not command.get("ours"):
        steps.append(_step("fix-path", "`bluekit` on PATH is a different installation",
                           f"{command['path']} does not run this Bluekit; agent instructions would call the wrong program.",
                           "pipx install --force bluekit"))
    if set(report.get("expected_versions", {})) - set(report.get("tools", {})):
        steps.append(_step("init", "Install the scanners", "Trivy or Semgrep is missing, so scans would be incomplete.",
                           "bluekit init --json"))
    else:
        steps.append(_step("scan", "Scan the project", "Scanners are ready.", "bluekit scan --json"))
    return _ordered(steps)
