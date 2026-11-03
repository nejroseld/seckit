"""Reviewer verdicts kept in `.guardkit/triage.json`.

Triage annotates findings; it never hides them. Suppression stays the job of
`.guardkit/ignore.json`, which only the project owner should edit.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any

FILE = Path(".guardkit") / "triage.json"
VERDICTS = ("true_positive", "false_positive", "needs_info", "fixed")


def load(root: Path) -> dict[str, dict[str, Any]]:
    target = Path(root) / FILE
    if target.is_symlink() or not target.is_file():
        return {}
    try:
        if target.stat().st_size > 2_000_000:
            return {}
        data = json.loads(target.read_text(encoding="utf-8")).get("triage", {})
    except (OSError, ValueError, AttributeError):
        return {}
    return {k: v for k, v in data.items() if isinstance(k, str) and isinstance(v, dict) and v.get("verdict") in VERDICTS}


def record(root: Path, finding_id: str, verdict: str, reason: str, evidence: str = "") -> dict[str, Any]:
    root = Path(root).resolve()
    if not isinstance(finding_id, str) or not finding_id.strip() or len(finding_id) > 200:
        raise ValueError("finding id is required")
    if verdict not in VERDICTS:
        raise ValueError("verdict must be one of " + ", ".join(VERDICTS))
    if not isinstance(reason, str) or not reason.strip() or len(reason) > 4000:
        raise ValueError("a non-empty reason (max 4000 characters) is required")
    folder = root / FILE.parent
    if folder.is_symlink() or (root / FILE).is_symlink():
        raise ValueError(".guardkit/triage.json must not be a symlink")
    folder.mkdir(exist_ok=True)
    entries = load(root)
    entry = {"verdict": verdict, "reason": reason.strip(), "updated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    if evidence:
        entry["evidence"] = str(evidence)[:4000]
    entries[finding_id.strip()] = entry
    temp = folder / f".triage.{os.getpid()}.tmp"
    temp.write_text(json.dumps({"triage": dict(sorted(entries.items()))}, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    os.replace(temp, root / FILE)
    return {"id": finding_id.strip(), **entry}


def annotate(root: Path, report: dict[str, Any]) -> dict[str, Any]:
    entries = load(root)
    if entries:
        for key in ("findings", "suppressed"):
            for finding in report.get(key, []):
                if isinstance(finding, dict) and finding.get("id") in entries:
                    finding["triage"] = entries[finding["id"]]
    return report
