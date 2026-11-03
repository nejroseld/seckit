"""Run local Trivy and Semgrep scans and normalize their JSON output."""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any

_SEVERITY = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "UNKNOWN": 1}
_PRIORITY = {"P0": 5, "P1": 4, "P2": 3, "P3": 2, "P4": 1}
_SECRET = re.compile(r"(?i)(api[_-]?key|secret|token|password|passwd|credential)(\s*[:=]\s*)([^\s,;]+)")
_ABS = re.compile(r"(?:[A-Za-z]:)?[/\\][^\s:'\"]+")


def _redact(value: Any) -> str:
    text = "".join(char if char.isprintable() else " " for char in str(value or ""))
    text = _SECRET.sub(r"\1\2[REDACTED]", text)
    # Explanations may contain snippets or host-local paths; do not expose either.
    text = _ABS.sub("[path]", text)
    return text[:1200]


def _relative(path: Any, root: Path) -> str:
    raw = str(path or "")
    p = Path(raw)
    try:
        absolute = p if p.is_absolute() else root / p
        return absolute.resolve().relative_to(root.resolve()).as_posix()
    except (OSError, ValueError):
        return p.name if not p.is_absolute() else "[external]"


def _finding(scanner: str, rule_id: str, title: str, severity: Any, confidence: Any,
             file: Any, line: Any, explanation: Any, impact: Any, remediation: Any,
             fix_available: Any, verification: Any, root: Path, credential: bool = False,
             finding_category: str = "code", identity: str = "") -> dict[str, Any]:
    sev = str(severity or "UNKNOWN").upper()
    sev = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}.get(sev, sev)
    if sev not in _SEVERITY: sev = "UNKNOWN"
    conf = str(confidence or "MEDIUM").upper()
    if conf not in {"HIGH", "MEDIUM", "LOW"}: conf = "MEDIUM"
    rel = _relative(file, root)
    try: lineno = max(0, int(line or 0))
    except (ValueError, TypeError): lineno = 0
    rid = _redact(rule_id) or "unknown"
    stable = hashlib.sha256(f"{scanner}\0{rid}\0{rel}\0{lineno}\0{identity}".encode()).hexdigest()[:16]
    # Credential exposure is supplied by the scanner result type, never inferred
    # from words such as "credentials" in an unrelated CORS rule name.
    credential = credential or finding_category == "credential"
    priority = "P0" if credential or sev == "CRITICAL" else {"HIGH": "P1", "ERROR": "P1", "MEDIUM": "P2", "WARNING": "P2", "LOW": "P3", "INFO": "P4", "UNKNOWN": "P3"}[sev]
    classification = "confirmed" if scanner == "Trivy" and rid.upper().startswith("CVE-") else "heuristic"
    return {
        "id": f"{scanner.lower()}-{stable}", "rule_id": rid, "title": _redact(title) or rid,
        "severity": sev, "confidence": conf, "file": rel, "line": lineno,
        "explanation": _redact(explanation), "impact": _redact(impact),
        "remediation": _redact(remediation), "fix_available": bool(fix_available),
        "verification": _redact(verification), "verification_status": "unverified",
        "priority": priority, "classification": classification, "category": finding_category,
        "scanner": scanner,
    }


def _dependency_title(pkg: str, title: str) -> str:
    """Prefix the package once; Trivy titles often already start with it."""
    title = str(title)
    while title.lower().startswith(pkg.lower() + ":"):
        title = title[len(pkg) + 1:].lstrip()
    # Titles like "nodejs-lodash: ..." name the package differently; drop that prefix too.
    head, sep, rest = title.partition(": ")
    if sep and pkg.lower() in head.lower() and " " not in head:
        title = rest
    return f"{pkg}: {title}"


def normalize_trivy(data: dict[str, Any], root: Path) -> list[dict[str, Any]]:
    findings = []
    for result in data.get("Results") or []:
        target = result.get("Target", "")
        for vuln in result.get("Vulnerabilities") or []:
            pkg = vuln.get("PkgName", "dependency")
            vid = vuln.get("VulnerabilityID", "TRIVY-UNKNOWN")
            fixed = vuln.get("FixedVersion")
            findings.append(_finding("Trivy", vid, _dependency_title(pkg, vuln.get("Title") or vid), vuln.get("Severity"), "HIGH",
                target, 0, vuln.get("Description") or vuln.get("Title"),
                f"Affected dependency {pkg} may expose the application to a known vulnerability.",
                f"Upgrade {pkg} to {fixed}." if fixed else f"Review {pkg} and select a patched version.", False,
                "Confirm the resolved package version in the lockfile and rerun the scan.", root,
                finding_category="dependency",
                identity=f"{pkg}@{vuln.get('InstalledVersion', '')}"))
            findings[-1].update(package=_redact(pkg), installed_version=_redact(vuln.get("InstalledVersion")),
                                fixed_version=_redact(fixed) if fixed else None)
        for mis in result.get("Misconfigurations") or []:
            findings.append(_finding("Trivy", mis.get("ID", "TRIVY-MISCONFIG"), mis.get("Title", "Misconfiguration"),
                mis.get("Severity"), "MEDIUM", target,
                mis.get("CauseMetadata", {}).get("StartLine", 0), mis.get("Message") or mis.get("Description"),
                mis.get("Description"), mis.get("Resolution"), False,
                "Apply the configuration change and rerun Trivy.", root, finding_category="misconfiguration"))
        for secret in result.get("Secrets") or []:
            findings.append(_finding("Trivy", secret.get("RuleID", "TRIVY-SECRET"), secret.get("Title", "Potential secret"),
                secret.get("Severity", "HIGH"), "MEDIUM", target, secret.get("StartLine", 0),
                # Never return matched text: Trivy may include the credential itself.
                secret.get("Title"), "Exposed credentials can enable unauthorized access.",
                "Revoke or rotate the credential, then move it to an approved secret store.", False,
                "Verify the old credential is revoked and the replacement is not committed.", root,
                credential=True, finding_category="credential"))
    return findings


def normalize_semgrep(data: dict[str, Any], root: Path) -> list[dict[str, Any]]:
    findings = []
    for item in data.get("results") or []:
        extra = item.get("extra") or {}
        metadata = extra.get("metadata") or {}
        start = item.get("start") or {}
        findings.append(_finding("Semgrep", item.get("check_id", "SEMGREP-UNKNOWN"),
            extra.get("message") or item.get("check_id", "Semgrep finding"),
            metadata.get("severity") or extra.get("severity"), metadata.get("confidence"),
            item.get("path"), start.get("line", 0), extra.get("message"),
            metadata.get("impact") or "This insecure pattern may weaken application security.",
            metadata.get("remediation") or metadata.get("fix") or "Replace the unsafe pattern with a validated secure alternative.",
            False, "Apply the change and rerun this local rule set.", root))
    return findings


def _run(command: list[str], cwd: Path, timeout: int = 600) -> tuple[dict[str, Any] | None, str | None]:
    try:
        proc = subprocess.run(command, cwd=cwd, capture_output=True, text=True, timeout=timeout, check=False,
                              env={**os.environ, "NO_COLOR": "1"})
    except FileNotFoundError:
        return None, f"Scanner executable not found: {Path(command[0]).name}"
    except subprocess.TimeoutExpired:
        return None, f"Scanner timed out after {timeout} seconds"
    except OSError:
        return None, "Scanner could not start due to an operating-system error"
    try:
        payload = json.loads(proc.stdout)
    except (json.JSONDecodeError, TypeError):
        return None, "Scanner returned invalid JSON output"
    if not isinstance(payload, dict):
        return None, "Scanner returned JSON with an unexpected top-level type"
    if proc.returncode != 0:
        return payload, f"Scanner exited with status {proc.returncode}"
    return payload, None


def _reported_errors(data: dict[str, Any], scanner: str) -> list[str]:
    """Surface scanner diagnostic counts without echoing potentially sensitive text."""
    errors = data.get("Errors") if scanner == "Trivy" else data.get("errors")
    if not isinstance(errors, list):
        errors = []
    # Trivy can also report per-result diagnostics.
    if scanner == "Trivy":
        errors.extend(error for result in data.get("Results") or [] for error in (result.get("Errors") or []))
    return [f"{scanner} reported {len(errors)} scan error(s)"] if errors else []


def scan(root: Path, trivy: str, semgrep: str) -> dict[str, Any]:
    """Run both scanners locally. Paths to executables/rules are explicit inputs."""
    root = Path(root).resolve()
    findings: list[dict[str, Any]] = []
    errors: list[str] = []
    skip = [".git", ".guardkit", "node_modules", ".venv", "venv", "dist", "build", ".next", "vendor"]
    trivy_command = [trivy, "fs", "--config", "", "--ignorefile", "", "--secret-config", "",
                     "--format", "json", "--quiet", "--exit-code", "0",
                     "--scanners", "vuln,misconfig,secret"]
    for directory in skip:
        trivy_command.extend(["--skip-dirs", directory])
    trivy_data, error = _run([*trivy_command, str(root)], root)
    if error: errors.append(f"Trivy: {error}")
    if trivy_data is not None:
        findings.extend(normalize_trivy(trivy_data, root))
        errors.extend(_reported_errors(trivy_data, "Trivy"))
    rules = Path(__file__).with_name("rules")
    # Repository-controlled ignore files and inline suppressions must not hide
    # findings during an audit. Keep exclusions explicit and owned by Guardkit.
    semgrep_command = [semgrep, "scan", "--config", str(rules), "--json", "--metrics=off",
                       "--disable-version-check", "--no-rewrite-rule-ids", "--disable-nosem",
                       "--no-git-ignore", "--x-ignore-semgrepignore-files", "--quiet"]
    for directory in skip:
        semgrep_command.extend(["--exclude", directory])
    semgrep_data, error = _run([*semgrep_command, str(root)], root)
    if error: errors.append(f"Semgrep: {error}")
    if semgrep_data is not None:
        findings.extend(normalize_semgrep(semgrep_data, root))
        errors.extend(_reported_errors(semgrep_data, "Semgrep"))
    # A secret-in-Docker-ENV check and a token detector can describe the same
    # exposure. Keep the token finding and retain the supporting rule as evidence.
    credential_locations = {(f["file"], f["line"]): f for f in findings if f["category"] == "credential" and f["line"] > 0}
    consolidated = []
    for item in findings:
        primary = credential_locations.get((item["file"], item["line"]))
        if item["scanner"] == "Trivy" and item["rule_id"] in {"DS-0031", "AVD-DS-0031"} and primary is not None:
            primary.setdefault("related_rules", []).append({"scanner": item["scanner"], "rule_id": item["rule_id"]})
            if _SEVERITY[item["severity"]] > _SEVERITY[primary["severity"]]:
                primary["severity"], primary["priority"] = item["severity"], item["priority"]
            continue
        consolidated.append(item)
    findings = consolidated
    # Collapse duplicate engine reports, preserving the highest priority representation.
    unique: dict[str, dict[str, Any]] = {}
    for item in findings:
        key = item["id"]
        prev = unique.get(key)
        if prev is None or _SEVERITY[item["severity"]] > _SEVERITY[prev["severity"]]: unique[key] = item
    findings = sorted(unique.values(), key=lambda f: (-_PRIORITY[f["priority"]], f["category"] != "credential", -_SEVERITY[f["severity"]],
                                                       {"dependency": 0, "code": 1, "misconfiguration": 2}.get(f["category"], 3),
                                                       f["file"], f["line"], f["id"]))
    return {"findings": findings, "errors": errors}
