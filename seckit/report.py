"""Audit report renderers: SARIF 2.1.0 for code-scanning tools, Markdown for people."""
from __future__ import annotations

from typing import Any

from . import __version__

_LEVEL = {"P0": "error", "P1": "error", "P2": "warning", "P3": "note", "P4": "note"}
_SCORE = {"CRITICAL": "9.5", "HIGH": "8.0", "MEDIUM": "5.5", "LOW": "3.0", "UNKNOWN": "0.0"}


def sarif(report: dict[str, Any]) -> dict[str, Any]:
    rules: dict[str, dict[str, Any]] = {}
    results = []
    for f in report.get("findings", []) + report.get("suppressed", []):
        rid = str(f.get("rule_id") or "unknown")
        rules.setdefault(rid, {"id": rid, "name": rid.rsplit(".", 1)[-1],
                               "shortDescription": {"text": str(f.get("title") or rid)[:300]},
                               "help": {"text": str(f.get("remediation") or "")},
                               "properties": {"security-severity": _SCORE.get(str(f.get("severity")), "0.0"),
                                              "tags": ["security", str(f.get("category") or "code")]}})
        result: dict[str, Any] = {
            "ruleId": rid, "level": _LEVEL.get(str(f.get("priority")), "warning"),
            "message": {"text": str(f.get("title") or rid) + (". " + str(f["explanation"]) if f.get("explanation") and f.get("explanation") != f.get("title") else "")},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": str(f.get("file") or ""), "uriBaseId": "SRCROOT"},
                                                "region": {"startLine": max(1, int(f.get("line") or 1))}}}],
            "partialFingerprints": {"seckitId/v1": str(f.get("id"))},
            "properties": {k: f[k] for k in ("priority", "severity", "confidence", "category", "scanner", "classification") if k in f},
        }
        suppressions = []
        if f.get("suppressed_reason"):
            suppressions.append({"kind": "external", "justification": str(f["suppressed_reason"])})
        triage = f.get("triage") or {}
        if triage:
            result["properties"]["triage"] = triage
            if triage.get("verdict") == "false_positive":
                suppressions.append({"kind": "external", "status": "accepted", "justification": str(triage.get("reason", ""))})
        if suppressions:
            result["suppressions"] = suppressions
        results.append(result)
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "Seckit", "version": __version__, "informationUri": "https://github.com/nejroseld/seckit",
                                          "rules": sorted(rules.values(), key=lambda r: r["id"])}},
                      "originalUriBaseIds": {"SRCROOT": {"description": {"text": "Project root"}}},
                      "results": results,
                      "invocations": [{"executionSuccessful": not report.get("errors"),
                                       "toolExecutionNotifications": [{"level": "error", "message": {"text": str(e)}} for e in report.get("errors", [])]}]}]}


def _cell(value: Any) -> str:
    return str(value if value is not None else "").replace("|", "\\|").replace("\n", " ")[:300]


def markdown(report: dict[str, Any], surface: dict[str, Any] | None = None, title: str = "Security audit") -> str:
    findings = report.get("findings", [])
    groups: dict[str, list[dict[str, Any]]] = {"true_positive": [], "untriaged": [], "needs_info": [], "fixed": [], "false_positive": []}
    for f in findings:
        groups.get((f.get("triage") or {}).get("verdict", "untriaged"), groups["untriaged"]).append(f)
    lines = [f"# {title}", ""]
    status = "incomplete" if report.get("errors") else "findings" if findings else "clean"
    lines += [f"Status: **{status}**. Findings: {len(findings)} "
              f"(confirmed {len(groups['true_positive'])}, untriaged {len(groups['untriaged'])}, needs info {len(groups['needs_info'])}, "
              f"fixed {len(groups['fixed'])}, false positive {len(groups['false_positive'])}). "
              f"Suppressed by owner: {len(report.get('suppressed', []))}.", ""]
    by_priority: dict[str, int] = {}
    for f in findings:
        by_priority[str(f.get("priority"))] = by_priority.get(str(f.get("priority")), 0) + 1
    if by_priority:
        lines += ["| Priority | Count |", "|---|---|"] + [f"| {p} | {by_priority[p]} |" for p in sorted(by_priority)] + [""]
    if report.get("errors"):
        lines += ["## Incomplete checks", ""] + [f"- {_cell(e)}" for e in report["errors"]] + [""]
    headings = {"true_positive": "Confirmed vulnerabilities", "untriaged": "Untriaged findings", "needs_info": "Needs more information",
                "fixed": "Fixed", "false_positive": "False positives"}
    for key, heading in headings.items():
        items = groups[key]
        if not items:
            continue
        lines += [f"## {heading}", "", "| Priority | Title | Location | Category | Note |", "|---|---|---|---|---|"]
        for f in items:
            note = (f.get("triage") or {}).get("reason") or f.get("remediation")
            lines.append(f"| {_cell(f.get('priority'))} | {_cell(f.get('title'))} | `{_cell(f.get('file'))}:{_cell(f.get('line'))}` "
                         f"| {_cell(f.get('category'))} | {_cell(note)} |")
        lines.append("")
    if surface:
        totals = surface.get("totals", {})
        lines += ["## Attack surface", "",
                  f"Files scanned: {surface.get('files_scanned', 0)}. Entry points: {totals.get('entry_points', 0)}, "
                  f"sinks: {totals.get('sinks', 0)}, controls: {totals.get('controls', 0)}, insecure defaults: {totals.get('insecure_defaults', 0)}.", ""]
        top = surface.get("review_order", [])[:15]
        if top:
            lines += ["| File | Entry points | Sinks | Controls | Defaults |", "|---|---|---|---|---|"]
            lines += [f"| `{_cell(r['file'])}`{' ⚠ no auth markers' if r.get('unguarded_entry') else ''} | {r['entry_points']} | {r['sinks']} "
                      f"| {r['controls']} | {r['insecure_defaults']} |" for r in top]
            lines.append("")
    lines += ["## Method and limits", "",
              "Automated checks: Trivy (dependencies, configuration, secrets), Semgrep with Seckit rules, offline supply-chain and CI checks. "
              "Rule matches are heuristic until triaged. A clean result does not prove the absence of vulnerabilities; "
              "business logic, authorization design and multi-file data flow need manual review.", ""]
    return "\n".join(lines)
