"""Explicit, auditable suppressions kept in `.seckit/ignore.json`.

Unlike scanner ignore files, suppressed findings are never hidden: they move to
the report's `suppressed` list together with the stated reason. Every rule
needs a non-empty `reason`, and a rule matches by `path` glob, finding `id`,
or `rule_id` (optionally combined with `path`).
"""
from __future__ import annotations

import fnmatch
import json
from pathlib import Path
from typing import Any

FILE = Path(".seckit") / "ignore.json"


def _glob(path: str, pattern: str) -> bool:
    if pattern.endswith("/**"):
        return path.startswith(pattern[:-2])
    return fnmatch.fnmatchcase(path, pattern)


def _existing(root: Path) -> Path:
    """Prefer `.seckit/`, fall back to a not yet migrated `.guardkit/` (the former name)."""
    target = Path(root) / FILE
    old = Path(root) / ".guardkit" / FILE.name
    return old if not target.exists() and not (Path(root) / FILE.parent).exists() and old.is_file() else target


def load(root: Path) -> tuple[list[dict[str, str]], list[str]]:
    """Return (valid rules, human-readable problems)."""
    target = _existing(root)
    if target.is_symlink() or not target.is_file():
        return [], []
    try:
        if target.stat().st_size > 1_000_000:
            return [], [f"{FILE.as_posix()} is too large and was ignored"]
        data = json.loads(target.read_text(encoding="utf-8"))
        items = data["ignore"]
        if not isinstance(items, list):
            raise TypeError
    except (OSError, ValueError, KeyError, TypeError):
        return [], [f"{FILE.as_posix()} is invalid; expected {{\"ignore\": [...]}}. No suppressions applied"]
    rules, problems = [], []
    for index, item in enumerate(items):
        ok = (isinstance(item, dict) and isinstance(item.get("reason"), str) and item["reason"].strip()
              and any(isinstance(item.get(k), str) and item[k] for k in ("path", "id", "rule_id")))
        if ok:
            rules.append({k: item[k] for k in ("path", "id", "rule_id", "reason") if isinstance(item.get(k), str)})
        else:
            problems.append(f"{FILE.as_posix()} entry {index} needs a non-empty reason and one of path, id, rule_id; skipped")
    return rules, problems


def _matches(rule: dict[str, str], finding: dict[str, Any]) -> bool:
    if "id" in rule and rule["id"] != finding.get("id"):
        return False
    if "rule_id" in rule and rule["rule_id"] != finding.get("rule_id"):
        return False
    if "path" in rule and not _glob(str(finding.get("file", "")), rule["path"]):
        return False
    return True


def apply(root: Path, report: dict[str, Any]) -> dict[str, Any]:
    """Move suppressed findings out of `findings`; invalid rules become warnings."""
    rules, problems = load(root)
    kept, suppressed = [], []
    for finding in report.get("findings", []):
        rule = next((r for r in rules if _matches(r, finding)), None)
        if rule is None:
            kept.append(finding)
        else:
            suppressed.append({**finding, "suppressed_reason": rule["reason"]})
    report["findings"] = kept
    report["suppressed"] = suppressed
    report["warnings"] = problems
    return report
