"""Concise command-line interface. No project code is executed during scans."""
from __future__ import annotations
import argparse
import json
import platform
import shutil
import shlex
import subprocess
import sys
import time
from pathlib import Path
from . import __version__
from . import agents, fixes, provision
from .detect import detect
from .scanning import scan


def _scan(root: Path) -> dict:
    start = time.monotonic()
    executables = provision.tools()
    report = scan(root, **executables)
    automatic_ids = {fid for plan in fixes.propose(root, report["findings"]) for fid in plan["finding_ids"]}
    for finding in report["findings"]:
        finding["fix_available"] = finding["id"] in automatic_ids
    report.update(schema_version=1, stack=detect(root), duration_seconds=round(time.monotonic() - start, 3))
    return report


def _terminal_text(value: object) -> str:
    """Render untrusted names without interpreting terminal controls."""
    return "".join(char if char.isprintable() else repr(char)[1:-1] for char in str(value))


def _show(report: dict, as_json: bool = False) -> int:
    if as_json:
        print(json.dumps(report, indent=2))
    else:
        print("Guardkit\n")
        if report.get("stack"):
            print("Detected: " + ", ".join(report["stack"]) + "\n")
        findings = report.get("findings", [])
        print(f"{len(findings)} issue(s) to review" if findings else "Checks incomplete; no clean result available." if report.get("errors") else "No findings in the completed checks.")
        for finding in findings[:20]:
            print(f"  {finding['severity']:8} {_terminal_text(finding['title'])}\n           {_terminal_text(finding['file'])}:{finding['line']}")
        if len(findings) > 20: print(f"  {len(findings) - 20} more; use --json for all findings.")
        if findings: print("\nRun `guardkit fix` to review available changes.")
        for error in report.get("errors", []): print(f"Incomplete check: {error}", file=sys.stderr)
    return 2 if report.get("errors") else 1 if report.get("findings") else 0


def _project_tests(root: Path) -> list[str] | None:
    try:
        manifest = root / "package.json"
        if manifest.is_file() and manifest.stat().st_size < 1_000_000:
            data = json.loads(manifest.read_text())
            if data.get("scripts", {}).get("test"):
                manager = "pnpm" if (root / "pnpm-lock.yaml").exists() else "yarn" if (root / "yarn.lock").exists() else "npm"
                return [manager, "test"]
    except (OSError, ValueError, TypeError, AttributeError):
        pass
    if (root / "tests").is_dir() and not (root / "tests").is_symlink():
        return [sys.executable, "-m", "unittest", "discover", "-s", "tests"]
    return None


def _fix(root: Path, as_json: bool, check: bool, skip_tests: bool = False) -> int:
    report = _scan(root)
    plans = fixes.propose(root, report["findings"])
    if as_json:
        print(json.dumps({"plans": fixes.public_plans(plans), "errors": report["errors"]}, indent=2))
        return 2 if report["errors"] else 0
    if not plans:
        print("No automatic corrections available. Review scan findings for manual remediation.")
        return 2 if report["errors"] else 0
    for plan in fixes.public_plans(plans):
        print(plan["reason"])
        print(plan["diff"], end="")
    if check:
        print("Review only; no files changed.")
        return 0
    if not sys.stdin.isatty():
        print("Approval requires an interactive terminal. Use --check to review.", file=sys.stderr)
        return 2
    tests = None if skip_tests else _project_tests(root)
    if tests:
        print("After applying, run project code: " + shlex.join(tests))
    if input("Apply these changes and run the displayed checks? [y/N] ").strip().lower() != "y":
        print("No changes applied.")
        return 0
    applied = fixes.apply(root, plans)
    test_status = "not_run"
    if tests:
        try:
            import os
            process = subprocess.run(tests, cwd=root, env={**os.environ, "CI": "1"},
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=180)
            test_status = "passed" if process.returncode == 0 else "failed"
        except (OSError, subprocess.TimeoutExpired):
            test_status = "failed"
    verified = _scan(root)
    verified["project_tests"] = {"command": tests, "status": test_status}
    remaining_ids = {f["id"] for f in verified["findings"]}
    expected = {fid for p in applied for fid in p["finding_ids"]}
    resolved = expected - remaining_ids if not verified["errors"] else set()
    verified["fix_verification"] = {"resolved_ids": sorted(resolved), "status": "incomplete" if verified["errors"] else "rescanned"}
    print(f"Applied {len(applied)} change(s); {len(resolved)} finding(s) no longer reported.")
    if any(p["path"] == ".gitignore" for p in applied):
        print("Ignore rules protect future additions. Existing secrets still require revocation and removal from history.")
    print("Project tests: " + test_status + ".")
    status = _show(verified)
    return 2 if test_status == "failed" else status


def doctor(root: Path) -> dict:
    available = provision.tools(install=False)
    return {"version": __version__, "python": platform.python_version(), "platform": platform.platform(),
            "cache": str(provision.cache_dir()), "tools": available,
            "expected_versions": {"trivy": provision.TRIVY, "semgrep": provision.SEMGREP},
            "stack": detect(root), "native_secret_store": bool(shutil.which("security" if sys.platform == "darwin" else "secret-tool")),
            "limitations": ["Scanners require initial downloads; CVE databases require periodic network access.",
                            "Secret isolation from unrestricted same-user processes is not provided."]}


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "secrets":
        from .secrets import secrets_main
        return secrets_main(argv[1:])
    parser = argparse.ArgumentParser(prog="guardkit", description="Local security scans and reviewed project fixes")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("secrets", help="Native credential storage and approved HTTP requests")
    for command in ("init", "scan", "fix", "doctor", "mcp", "uninstall"):
        cmd = sub.add_parser(command)
        cmd.add_argument("--root", type=Path, default=Path.cwd())
        if command != "mcp": cmd.add_argument("--json", action="store_true")
        if command == "fix":
            cmd.add_argument("--check", action="store_true", help="Show proposed diffs without applying")
            cmd.add_argument("--skip-tests", action="store_true", help="Only rerun scanners after approved edits")
        if command == "init": cmd.add_argument("--no-agents", action="store_true", help="Skip project-local agent instructions")
    ns = parser.parse_args(argv)
    root = ns.root.resolve()
    if not root.is_dir():
        print("Project directory does not exist.", file=sys.stderr)
        return 2
    try:
        if ns.command == "doctor":
            report = doctor(root)
            if ns.json: print(json.dumps(report, indent=2))
            else:
                print(f"Guardkit {__version__}\nPython {report['python']}\nCache: {report['cache']}")
                for tool, version in report['expected_versions'].items(): print(f"  {tool} {version}: {'ready' if tool in report['tools'] else 'missing; run guardkit init'}")
                print("Native secret store: " + ("adapter available; live store not checked" if report['native_secret_store'] else "unavailable; see docs/secrets.md"))
            return 0 if len(report["tools"]) == 2 else 2
        if ns.command == "init":
            start = time.monotonic()
            installed = provision.tools()
            created = [] if ns.no_agents else agents.install(root)
            report = {"stack": detect(root), "tools": installed, "agent_files_created": created,
                      "duration_seconds": round(time.monotonic() - start, 3)}
            if ns.json: print(json.dumps(report, indent=2))
            else:
                print("Guardkit ready\nDetected: " + (", ".join(report["stack"]) or "generic project"))
                print("Application, dependency, configuration, and secret checks ready.\nRun `guardkit scan`.")
            return 0
        if ns.command == "scan": return _show(_scan(root), ns.json)
        if ns.command == "fix": return _fix(root, ns.json, ns.check, ns.skip_tests)
        if ns.command == "mcp":
            agents.serve(root, lambda target: _scan(target))
            return 0
        if ns.command == "uninstall":
            # Never remove caches automatically: show exact location and manual instructions.
            print("Remove the Guardkit package with your installer. Scanner cache: " + str(provision.cache_dir()))
            print("Remove project-local Guardkit instruction files only if you no longer need them. Native credentials remain in your OS store.")
            return 0
    except provision.ProvisionError as exc:
        if getattr(ns, "json", False): print(json.dumps({"findings": [], "errors": [str(exc)]}))
        else: print(str(exc), file=sys.stderr)
        return 2
    except (OSError, ValueError) as exc:
        # Avoid echoing arbitrary exception values which can contain secret-bearing paths.
        message = f"Operation could not complete ({type(exc).__name__}); run guardkit doctor."
        if getattr(ns, "json", False): print(json.dumps({"findings": [], "errors": [message]}))
        else: print(message, file=sys.stderr)
        return 2
    except (EOFError, KeyboardInterrupt):
        print("Cancelled; no further changes applied.", file=sys.stderr)
        return 130
    return 0
