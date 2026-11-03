"""Real-engine acceptance checks on disposable fixtures. Never executes fixture code."""
from pathlib import Path
import json
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from bluekit import fixes, provision
from bluekit.scanning import scan


def main():
    started = time.monotonic()
    try:
        engines = provision.tools()
    except (provision.ProvisionError, OSError):
        print(json.dumps({"status": "blocked", "reason": "Scanner provisioning unavailable", "setup_success": False}))
        return 2
    setup_seconds = time.monotonic() - started
    rules = ROOT / 'bluekit' / 'rules'
    validate = subprocess.run([engines['semgrep'], 'scan', '--validate', '--config', str(rules), '--metrics=off', '--disable-version-check'], capture_output=True)
    if validate.returncode:
        print(json.dumps({"status": "failed", "reason": "Semgrep rule validation failed", "setup_success": True}))
        return 1
    with tempfile.TemporaryDirectory(prefix='bluekit-acceptance-') as tmp:
        project = Path(tmp) / 'project'
        shutil.copytree(ROOT / 'benchmarks/fixtures/positive', project)
        # Represent unrelated pre-existing local edits; fixes must preserve exact bytes.
        unrelated = project / 'unrelated.txt'
        unrelated.write_text('Uncommitted local edit\n')
        first = time.monotonic()
        before = scan(project, **engines)
        first_seconds = time.monotonic() - first
        if before['errors']:
            print(json.dumps({"status": "incomplete", "errors": before['errors'], "setup_success": True}))
            return 2
        plans = fixes.propose(project, before['findings'])
        if not plans:
            print(json.dumps({"status": "failed", "reason": "No scanner-detected fix available"}))
            return 1
        fix_start = time.monotonic()
        # Explicit test approval applies only to these synthetic disposable files.
        applied = fixes.apply(project, plans)
        after = scan(project, **engines)
        expected = {fid for plan in applied for fid in plan['finding_ids']}
        remaining = {item['id'] for item in after['findings']}
        resolved = expected - remaining if not after['errors'] else set()
        unchanged = unrelated.read_text() == 'Uncommitted local edit\n'
        positive_categories = {f['category'] for f in before['findings']}
        success = bool(resolved) and unchanged and not after['errors'] and {'credential','dependency','misconfiguration','code'} <= positive_categories
        print(json.dumps({"status": "passed" if success else "failed", "setup_success": True,
                          "setup_seconds": round(setup_seconds, 3), "time_to_first_scan_seconds": round(first_seconds, 3),
                          "time_to_verified_fix_seconds": round(time.monotonic() - fix_start, 3),
                          "resolved_count": len(resolved), "categories": sorted(positive_categories),
                          "preserved_unrelated_edits": unchanged, "errors": after['errors']}, indent=2))
        return 0 if success else 1

if __name__ == '__main__':
    raise SystemExit(main())
