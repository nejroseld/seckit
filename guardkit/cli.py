"""Agent-first JSON tools. Project code runs only with explicit --run-tests."""
from __future__ import annotations
import argparse
import json
import platform
import shlex
import subprocess
import sys
import time
from pathlib import Path
from . import __version__
from . import agents, fixes, provision, reviews
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


def _fix(root: Path, as_json: bool, review_id: str | None = None,
         run_tests: bool = False) -> int:
    if review_id is None:
        report = _scan(root)
        plans = fixes.propose(root, report["findings"])
        review_id = reviews.create(root, plans)
        result = {"schema_version": 1, "plans": fixes.public_plans(plans),
                  "review_id": review_id, "findings": report["findings"], "errors": report["errors"],
                  "complete": not bool(report["errors"]),
                  "next_action": "Review diffs, then apply the review_id within the user's authorized scope."
                                 if plans else "Agent should review findings for manual remediation."}
        if as_json:
            print(json.dumps(result, indent=2))
        else:
            for plan in result["plans"]:
                print(plan["reason"])
                print(plan["diff"], end="")
            print("Review only; no project files changed.")
            if review_id:
                print("Apply reviewed changes: guardkit fix --root " + shlex.quote(str(root)) + " --apply " + review_id)
            for error in result["errors"]:
                print("Incomplete check: " + _terminal_text(error), file=sys.stderr)
        return 2 if report["errors"] else 0

    plans = reviews.consume(root, review_id)
    try:
        applied = fixes.apply(root, plans)
    except (OSError, ValueError) as exc:
        raise reviews.ReviewError("Reviewed changes could not be applied; files may have changed. Request and review a new proposal.") from exc
    tests = _project_tests(root) if run_tests else None
    test_status = "not_run"
    if tests:
        try:
            import os
            process = subprocess.run(tests, cwd=root, env={**os.environ, "CI": "1"},
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=180)
            test_status = "passed" if process.returncode == 0 else "failed"
        except (OSError, subprocess.TimeoutExpired):
            test_status = "failed"
    try:
        verified = _scan(root)
    except (provision.ProvisionError, OSError, ValueError):
        verified = {"findings": [], "errors": ["Post-apply scan failed; changes were applied but verification is incomplete."]}
    verified["project_tests"] = {"command": tests, "status": test_status}
    remaining_ids = {f["id"] for f in verified["findings"]}
    expected = {fid for p in applied for fid in p["finding_ids"]}
    resolved = expected - remaining_ids if not verified["errors"] else set()
    verified["applied_count"] = len(applied)
    verified["fix_verification"] = {"resolved_ids": sorted(resolved), "status": "incomplete" if verified["errors"] else "rescanned"}
    status = _show(verified, as_json)
    return 2 if test_status == "failed" else status


def doctor(root: Path) -> dict:
    available = provision.tools(install=False)
    return {"version": __version__, "python": platform.python_version(), "platform": platform.platform(),
            "cache": str(provision.cache_dir()), "tools": available,
            "expected_versions": {"trivy": provision.TRIVY, "semgrep": provision.SEMGREP},
            "stack": detect(root),
            "limitations": ["Scanners require initial downloads; CVE databases require periodic network access."]}


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = argparse.ArgumentParser(prog="guardkit", description="Security tools for coding agents: scan, review, apply, verify")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)
    for command in ("init", "scan", "fix", "doctor", "mcp", "uninstall"):
        cmd = sub.add_parser(command)
        cmd.add_argument("--root", type=Path, default=Path.cwd())
        if command != "mcp":
            output = cmd.add_mutually_exclusive_group()
            output.add_argument("--json", dest="json", action="store_true", default=True, help="Structured output (default)")
            output.add_argument("--human", dest="json", action="store_false", help="Readable terminal output")
        if command == "fix":
            mode = cmd.add_mutually_exclusive_group()
            mode.add_argument("--check", action="store_true", help="Propose reviewable diffs (default)")
            mode.add_argument("--apply", metavar="REVIEW_ID", help="Apply exact previously reviewed plans; requires task authorization")
            tests = cmd.add_mutually_exclusive_group()
            tests.add_argument("--run-tests", action="store_true", help="Explicitly authorize project test execution after applying")
            tests.add_argument("--skip-tests", action="store_true", help=argparse.SUPPRESS)
    ns = parser.parse_args(argv)
    root = ns.root.resolve()
    if not root.is_dir():
        if getattr(ns, "json", False):
            print(json.dumps({"findings": [], "errors": ["Project directory does not exist."]}))
        else:
            print("Project directory does not exist.", file=sys.stderr)
        return 2
    try:
        if ns.command == "doctor":
            report = doctor(root)
            if ns.json: print(json.dumps(report, indent=2))
            else:
                print(f"Guardkit {__version__}\nPython {report['python']}\nCache: {report['cache']}")
                for tool, version in report['expected_versions'].items(): print(f"  {tool} {version}: {'ready' if tool in report['tools'] else 'missing; run guardkit init'}")
            return 0 if len(report["tools"]) == 2 else 2
        if ns.command == "init":
            start = time.monotonic()
            installed = provision.tools()
            created = agents.install(root)
            report = {"stack": detect(root), "tools": installed, "agent_files_created": created,
                      "duration_seconds": round(time.monotonic() - start, 3),
                      "mcp": {"command": sys.executable, "args": ["-I", "-m", "guardkit", "mcp", "--root", str(root)]},
                      "next_action": "Use agent instructions to scan, triage, remediate, and verify within task authorization."}
            if ns.json: print(json.dumps(report, indent=2))
            else:
                print("Guardkit ready\nDetected: " + (", ".join(report["stack"]) or "generic project"))
                print("Application, dependency, configuration, and secret checks ready.\nRun `guardkit scan`.")
            return 0
        if ns.command == "scan": return _show(_scan(root), ns.json)
        if ns.command == "fix":
            if ns.run_tests and not ns.apply:
                raise ValueError("--run-tests requires --apply REVIEW_ID")
            return _fix(root, ns.json, ns.apply, ns.run_tests)
        if ns.command == "mcp":
            agents.serve(root, lambda target: _scan(target))
            return 0
        if ns.command == "uninstall":
            # Never remove caches automatically: show exact location and manual instructions.
            report = {"cache": str(provision.cache_dir()),
                      "instructions": "Remove the package with your installer and Guardkit-owned instruction blocks/files if no longer needed."}
            if ns.json: print(json.dumps(report, indent=2))
            else: print(report["instructions"] + " Scanner cache: " + report["cache"])
            return 0
    except reviews.ReviewError as exc:
        report = {"findings": [], "errors": [str(exc)], "error_code": "invalid_review", "next_action": "Run fix --check and review a fresh proposal."}
        if getattr(ns, "json", False): print(json.dumps(report))
        else: print(str(exc), file=sys.stderr)
        return 2
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
