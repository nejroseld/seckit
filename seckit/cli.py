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
from . import agents, audit, fixes, ignores, nextsteps, provision, reviews, supply_chain, triage
from . import report as reporting
from .detect import detect
from .scanning import _SECRET, scan


def scanning_redact_lines(text: str) -> str:
    """Keep line structure but mask secret-looking assignments and host paths."""
    text = "".join(c if c.isprintable() or c == "\n" else " " for c in text)
    return _SECRET.sub(r"\1\2[REDACTED]", text)


def _scan(root: Path) -> dict:
    start = time.monotonic()
    executables = provision.tools()
    report = triage.annotate(root, ignores.apply(root, scan(root, **executables)))
    automatic_ids = {fid for plan in fixes.propose(root, report["findings"]) for fid in plan["finding_ids"]}
    for finding in report["findings"]:
        finding["fix_available"] = finding["id"] in automatic_ids
    report.update(schema_version=1, stack=detect(root), duration_seconds=round(time.monotonic() - start, 3))
    return report


def _terminal_text(value: object) -> str:
    """Render untrusted names without interpreting terminal controls."""
    return "".join(char if char.isprintable() else repr(char)[1:-1] for char in str(value))


def _status(report: dict) -> tuple[str, int]:
    if report.get("errors"): return "incomplete", 2
    if report.get("findings"): return "findings", 1
    return "clean", 0


def _default_root() -> Path:
    """The git top level above the working directory, else the directory itself."""
    cwd = Path.cwd()
    for candidate in (cwd, *cwd.parents):
        if (candidate / ".git").exists():
            return candidate
    return cwd


def _print_steps(steps: list[dict]) -> None:
    if steps:
        print("\nNext steps:")
        for number, step in enumerate(steps, 1):
            print(f"  {number}. {step['title']}: {step['command']}")


def _show(report: dict, as_json: bool = False, root: Path | None = None) -> int:
    status, code = _status(report)
    if root is not None:
        report["next_steps"] = nextsteps.after_scan(root, report)
    if as_json:
        report.setdefault("schema_version", 1)
        report.update(status=status, exit_code=code)
        print(json.dumps(report, indent=2))
    else:
        print("Seckit\n")
        if report.get("stack"):
            print("Detected: " + ", ".join(report["stack"]) + "\n")
        findings = report.get("findings", [])
        print(f"{len(findings)} issue(s) to review" if findings else "Checks incomplete; no clean result available." if report.get("errors") else "No findings in the completed checks.")
        for finding in findings[:20]:
            print(f"  {finding['severity']:8} {_terminal_text(finding['title'])}\n           {_terminal_text(finding['file'])}:{finding['line']}")
        if len(findings) > 20: print(f"  {len(findings) - 20} more; use --json for all findings.")
        if findings: print("\nRun `seckit fix` to review available changes.")
        if report.get("suppressed"): print(f"{len(report['suppressed'])} finding(s) suppressed by .seckit/ignore.json (listed under `suppressed` in --json).")
        for warning in report.get("warnings", []): print(f"Warning: {_terminal_text(warning)}", file=sys.stderr)
        for error in report.get("errors", []): print(f"Incomplete check: {error}", file=sys.stderr)
        _print_steps(report.get("next_steps", []))
    return code


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
        if any((root / name).is_file() for name in ("pytest.ini", "conftest.py", "tests/conftest.py")) or _pyproject_has_pytest(root):
            return [sys.executable, "-m", "pytest", "-q", "-x"]
        return [sys.executable, "-m", "unittest", "discover", "-s", "tests"]
    return None


def _pyproject_has_pytest(root: Path) -> bool:
    try:
        manifest = root / "pyproject.toml"
        return manifest.is_file() and manifest.stat().st_size < 1_000_000 and "[tool.pytest" in manifest.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return False


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
                print("Apply reviewed changes: seckit fix --root " + shlex.quote(str(root)) + " --apply " + review_id)
            for error in result["errors"]:
                print("Incomplete check: " + _terminal_text(error), file=sys.stderr)
        return 2 if report["errors"] else 0

    plans = reviews.consume(root, review_id)
    try:
        applied = fixes.apply(root, plans)
    except (OSError, ValueError) as exc:
        raise reviews.ReviewError("Reviewed changes could not be applied; files may have changed. Request and review a new proposal.") from exc
    tests = _project_tests(root) if run_tests else None
    test_status, test_output = "not_run", ""
    if tests:
        try:
            import os
            process = subprocess.run(tests, cwd=root, env={**os.environ, "CI": "1"}, text=True, errors="replace",
                                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=180)
            test_status = "passed" if process.returncode == 0 else "failed"
            if process.returncode:
                test_output = "\n".join(scanning_redact_lines((process.stdout or "")[-4000:]).splitlines()[-30:])
        except subprocess.TimeoutExpired:
            test_status, test_output = "failed", "Tests timed out after 180 seconds."
        except OSError:
            test_status, test_output = "failed", "Test command could not start."
    try:
        verified = _scan(root)
    except (provision.ProvisionError, OSError, ValueError):
        verified = {"findings": [], "errors": ["Post-apply scan failed; changes were applied but verification is incomplete."]}
    verified["project_tests"] = {"command": tests, "status": test_status}
    if test_output: verified["project_tests"]["output_tail"] = test_output
    remaining_ids = {f["id"] for f in verified["findings"]}
    expected = {fid for p in applied for fid in p["finding_ids"]}
    resolved = expected - remaining_ids if not verified["errors"] else set()
    verified["applied_count"] = len(applied)
    verified["fix_verification"] = {"resolved_ids": sorted(resolved), "status": "incomplete" if verified["errors"] else "rescanned"}
    status = _show(verified, as_json, root)
    return 2 if test_status == "failed" else status


def _fail(message: str, as_json: bool, **extra: object) -> int:
    if as_json:
        print(json.dumps({"schema_version": 1, "status": "incomplete", "exit_code": 2, "findings": [], "errors": [message], **extra}))
    else:
        print(message, file=sys.stderr)
    return 2


def doctor(root: Path) -> dict:
    available = provision.tools(install=False)
    limitations = ["Scanners require initial downloads; CVE databases require periodic network access."]
    old_cache = provision.cache_dir().with_name("guardkit")
    if old_cache.is_dir():
        limitations.append(f"Scanner cache from Guardkit (the former name) is unused and can be deleted: {old_cache}")
    report = {"version": __version__, "python": platform.python_version(), "platform": platform.platform(),
            "command": agents.command_status(), "cache": str(provision.cache_dir()), "tools": available,
            "expected_versions": {"trivy": provision.TRIVY, "semgrep": provision.SEMGREP},
            "stack": detect(root),
            "limitations": limitations}
    report["next_steps"] = nextsteps.after_doctor(report)
    return report


def _print(value: dict) -> None:
    print(json.dumps(value, indent=2, ensure_ascii=False))


def _audit_command(ns: argparse.Namespace, root: Path) -> int:
    try:
        if ns.command == "surface":
            _print(audit.attack_surface(root, ns.path, ns.kind, max(1, ns.limit)))
            return 0
        if ns.command == "supply-chain":
            report = triage.annotate(root, supply_chain.scan(root))
            report["schema_version"] = 1
            return _show(report, ns.json)
        if ns.command == "diff":
            report = None if ns.no_scan else _scan(root)
            result = audit.diff_review(root, ns.base, report)
            _print(result)
            if report is not None and report.get("errors"):
                return 2
            return 1 if result["new_risky_lines"] or result["removed_controls"] or result.get("findings_in_changed_files") else 0
        if ns.command == "rule":
            if ns.config is not None:
                if not ns.config.is_file() or ns.config.stat().st_size > 100_000:
                    return _fail("--config must be a rule file under 100 KB.", True, error_code="usage")
                rule = ns.config.read_text(encoding="utf-8")
            else:
                rule = audit.build_rule(ns.pattern, ns.lang, ns.message)
            result = audit.rule_scan(root, provision.tools()["semgrep"], rule, ns.path)
            _print({"schema_version": 1, **result})
            return 2 if result["errors"] else 1 if result["findings"] else 0
        if ns.command == "triage":
            _print({"recorded": triage.record(root, ns.finding_id, ns.verdict, ns.reason, ns.evidence)})
            return 0
        if ns.command == "report":
            report = agents.combined_report(root, _scan(root))
            if ns.format == "sarif":
                text = json.dumps(reporting.sarif(report), indent=2, ensure_ascii=False)
            elif ns.format == "json":
                text = json.dumps({"schema_version": 1, **report}, indent=2, ensure_ascii=False)
            else:
                text = reporting.markdown(report, audit.attack_surface(root, limit=1))
            if ns.output:
                ns.output.write_text(text + "\n", encoding="utf-8")
                print(json.dumps({"written": str(ns.output), "findings": len(report["findings"]), "errors": report["errors"]}))
            else:
                print(text)
            return _status(report)[1]
    except audit.AuditError as exc:
        return _fail(str(exc), True, error_code="usage")
    except ValueError as exc:
        if ns.command == "triage":
            return _fail(str(exc), True, error_code="usage")
        raise
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = argparse.ArgumentParser(prog="seckit", description="Security tools for coding agents: scan, review, apply, verify")
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)
    helps = {"surface": "Map entry points, sinks, controls and insecure defaults",
             "supply-chain": "Offline dependency, CI and Dockerfile supply-chain checks",
             "diff": "Security review data for changes against a git base ref",
             "rule": "Run a custom Semgrep rule or pattern (variant analysis)",
             "triage": "Record a verdict for a finding in .seckit/triage.json",
             "report": "Full audit report (scan + supply chain + triage) as markdown or SARIF"}
    for command in ("init", "scan", "fix", "doctor", "mcp", "uninstall", *helps):
        cmd = sub.add_parser(command, help=helps.get(command))
        cmd.add_argument("--root", type=Path, default=None, help="Project root (default: git top level of the working directory)")
        if command == "init":
            cmd.add_argument("--mcp", action="store_true", help="Also register the MCP server in the project-local .mcp.json")
            cmd.add_argument("--plan", action="store_true", help="Show the files and diffs init would write; change nothing")
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
        if command == "surface":
            cmd.add_argument("--path", default="")
            cmd.add_argument("--kind", choices=["entry_points", "sinks", "controls", "insecure_defaults"])
            cmd.add_argument("--limit", type=int, default=200)
        if command == "diff":
            cmd.add_argument("--base", default="HEAD", help="Git ref to compare against (default: uncommitted changes)")
            cmd.add_argument("--no-scan", action="store_true", help="Skip scanners; report diff signals only")
        if command == "rule":
            source = cmd.add_mutually_exclusive_group(required=True)
            source.add_argument("--config", type=Path, help="Semgrep rule YAML file")
            source.add_argument("--pattern", help="Semgrep pattern")
            cmd.add_argument("--lang", default="python")
            cmd.add_argument("--message", default="")
            cmd.add_argument("--path", default="")
        if command == "triage":
            cmd.add_argument("finding_id")
            cmd.add_argument("--verdict", required=True, choices=list(triage.VERDICTS))
            cmd.add_argument("--reason", required=True)
            cmd.add_argument("--evidence", default="")
        if command == "report":
            cmd.add_argument("--format", choices=["markdown", "sarif", "json"], default="markdown")
            cmd.add_argument("--output", type=Path, help="Write the report to this file instead of stdout")
    ns = parser.parse_args(argv)
    root = (ns.root if ns.root is not None else _default_root()).resolve()
    if not root.is_dir():
        message = "--root must be a directory, not a file." if root.exists() else "Project directory does not exist."
        return _fail(message, getattr(ns, "json", False))
    try:
        if ns.command == "doctor":
            report = doctor(root)
            if ns.json: print(json.dumps(report, indent=2))
            else:
                print(f"Seckit {__version__}\nPython {report['python']}\nCache: {report['cache']}")
                for tool, version in report['expected_versions'].items(): print(f"  {tool} {version}: {'ready' if tool in report['tools'] else 'missing; run seckit init'}")
                command = report["command"]
                print("Command: " + (command["path"] + ("" if command["ours"] else " (a different installation)") if command["path"] else "seckit is not on PATH"))
                _print_steps(report["next_steps"])
            return 0 if len(report["tools"]) == 2 else 2
        if ns.command == "init" and ns.plan:
            plan: list[dict] = []
            agents.install(root, plan)
            if ns.mcp:
                plan.append({"file": ".mcp.json", "action": "update", "diff": "", "note": "register the seckit MCP server"})
            report = {"schema_version": 1, "plan": plan, "writes": [entry["file"] for entry in plan],
                      "downloads": [f"Trivy {provision.TRIVY}", f"Semgrep {provision.SEMGREP}"],
                      "command": agents.command_status(),
                      "next_action": "Show the user this plan; run the same command without --plan to apply it."}
            if ns.json: print(json.dumps(report, indent=2))
            else:
                for entry in plan:
                    print(f"{entry['action']}: {entry['file']}")
                    if entry.get("diff"): print(entry["diff"], end="")
                print("Nothing changed. Run `seckit init` to apply." if plan else "Agent files are up to date.")
            return 0
        if ns.command == "init":
            start = time.monotonic()
            installed = provision.tools()
            created = agents.install(root)
            if ns.mcp and agents.register_mcp(root, sys.executable, ["-I", "-m", "seckit", "mcp", "--root", str(root)]):
                created.append(".mcp.json")
            report = {"stack": detect(root), "tools": installed, "agent_files_created": created,
                      "duration_seconds": round(time.monotonic() - start, 3),
                      "mcp": {"command": sys.executable, "args": ["-I", "-m", "seckit", "mcp", "--root", str(root)]},
                      "mcp_registered": ns.mcp, "command": agents.command_status()}
            report["next_steps"] = nextsteps.after_init(root, report["stack"], created, ns.mcp, report["command"]["ours"])
            report["next_action"] = "Report what was created, then offer next_steps to the user and ask which to start."
            if ns.json: print(json.dumps(report, indent=2))
            else:
                print("Seckit ready\nDetected: " + (", ".join(report["stack"]) or "generic project"))
                print("Application, dependency, configuration, and secret checks ready.")
                print("Created or updated: " + (", ".join(created) or "nothing"))
                _print_steps(report["next_steps"])
            return 0
        if ns.command == "scan": return _show(_scan(root), ns.json, root)
        if ns.command in ("surface", "supply-chain", "diff", "rule", "triage", "report"):
            return _audit_command(ns, root)
        if ns.command == "fix":
            if ns.run_tests and not ns.apply:
                return _fail("--run-tests requires --apply REVIEW_ID.", ns.json, error_code="usage")
            return _fix(root, ns.json, ns.apply, ns.run_tests)
        if ns.command == "mcp":
            agents.serve(root, lambda target: _scan(target), lambda: provision.tools()["semgrep"])
            return 0
        if ns.command == "uninstall":
            # Project files are cleaned; the shared scanner cache is never removed automatically.
            report = {"removed": agents.uninstall(root), "cache": str(provision.cache_dir()),
                      "instructions": "Removed Seckit-managed blocks and files from this project; your own content was kept. Uninstall the package with your installer and delete the scanner cache directory manually if no longer needed."}
            if ns.json: print(json.dumps(report, indent=2))
            else: print(report["instructions"] + " Removed: " + (", ".join(report["removed"]) or "nothing") + ". Scanner cache: " + report["cache"])
            return 0
    except reviews.ReviewError as exc:
        return _fail(str(exc), getattr(ns, "json", False), error_code="invalid_review",
                     next_action="Run fix --check and review a fresh proposal.")
    except provision.ProvisionError as exc:
        return _fail(str(exc), getattr(ns, "json", False), error_code="provision")
    except (OSError, ValueError) as exc:
        # Avoid echoing arbitrary exception values which can contain secret-bearing paths.
        message = f"Operation could not complete ({type(exc).__name__}); run seckit doctor."
        return _fail(message, getattr(ns, "json", False))
    except (EOFError, KeyboardInterrupt):
        print("Cancelled; no further changes applied.", file=sys.stderr)
        return 130
    return 0
