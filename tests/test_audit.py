import _isolate  # noqa: F401
import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from bluekit import agents, audit, report, supply_chain, triage


def write(root: Path, rel: str, text: str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


class SurfaceTests(unittest.TestCase):
    def test_maps_entries_sinks_controls_and_defaults(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root, "app.py", "@app.route('/x')\ndef x():\n    os.system(request.args['c'])\napp.run(debug=True)\n")
            write(root, "safe.py", "@app.get('/y')\n@login_required\ndef y():\n    return 1\n")
            write(root, "node_modules/lib.js", "eval(x)\n")
            result = audit.attack_surface(root)
            self.assertEqual({(i["file"], i["label"]) for i in result["sinks"]}, {("app.py", "command-exec")})
            self.assertIn("debug-enabled", {i["label"] for i in result["insecure_defaults"]})
            self.assertEqual(result["review_order"][0]["file"], "app.py")
            self.assertTrue(result["review_order"][0]["unguarded_entry"])
            self.assertFalse(next(r for r in result["review_order"] if r["file"] == "safe.py")["unguarded_entry"])

    def test_snippets_mask_secret_assignments(self):
        with tempfile.TemporaryDirectory() as tmp:
            write(Path(tmp), "a.py", "requests.get(url, token='abc123secret')\n")
            hit = audit.attack_surface(Path(tmp))["sinks"][0]
            self.assertNotIn("abc123secret", hit["snippet"])


class ReadSearchTests(unittest.TestCase):
    def test_read_code_stays_inside_root_and_skips_symlinks(self):
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as outside:
            root = Path(tmp)
            write(root, "a.py", "one\npassword = 'hunter22'\nthree\n")
            write(Path(outside), "secret.txt", "x")
            os.symlink(Path(outside) / "secret.txt", root / "link.txt")
            out = audit.read_code(root, "a.py", 1, 3)
            self.assertIn("     1  one", out["content"])
            self.assertNotIn("hunter22", out["content"])
            for bad in ("../x", "/etc/passwd", "link.txt"):
                with self.assertRaises(audit.AuditError):
                    audit.read_code(root, bad)

    def test_search_code_regex_glob_and_limit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root, "a.py", "pickle.loads(x)\npickle.loads(y)\n")
            write(root, "b.js", "pickle.loads(z)\n")
            out = audit.search_code(root, r"pickle\.loads", glob="*.py", limit=1)
            self.assertEqual((out["total"], len(out["matches"]), out["truncated"]), (2, 1, True))
            with self.assertRaises(audit.AuditError):
                audit.search_code(root, "(")


@unittest.skipUnless(shutil.which("git"), "git is required")
class DiffTests(unittest.TestCase):
    def git(self, root, *args):
        subprocess.run(["git", *args], cwd=root, check=True, capture_output=True)

    def test_reports_new_sinks_removed_controls_and_does_not_run_filters(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.git(root, "init", "-q")
            self.git(root, "config", "user.email", "t@t")
            self.git(root, "config", "user.name", "t")
            write(root, "views.py", "@app.route('/a')\n@login_required\ndef a():\n    return 1\n")
            self.git(root, "add", "-A")
            self.git(root, "commit", "-qm", "init")
            marker = root / "filter-ran"
            # A repository-defined clean filter must never be executed by the review.
            self.git(root, "config", "filter.evil.clean", f"touch {marker}; cat")
            self.git(root, "config", "core.fsmonitor", f"touch {marker}; true")
            write(root, ".gitattributes", "*.py filter=evil\n")
            write(root, "views.py", "@app.route('/a')\ndef a():\n    subprocess.run(cmd, shell=True)\n")
            write(root, "new.py", "eval(x)\n")
            out = audit.diff_review(root, "HEAD", {"findings": [{"id": "f", "file": "views.py", "line": 3}], "errors": []})
            self.assertFalse(marker.exists())
            self.assertEqual({f["file"] for f in out["files"]}, {"views.py", "new.py", ".gitattributes"})
            self.assertEqual([c["label"] for c in out["removed_controls"]], ["authn-authz"])
            self.assertEqual({(r["file"], r["label"]) for r in out["new_risky_lines"]}, {("views.py", "command-exec"), ("new.py", "code-eval")})
            self.assertTrue(out["findings_in_changed_files"][0]["in_changed_lines"])

    def test_rejects_option_like_refs(self):
        with self.assertRaises(audit.AuditError):
            audit.changed_files(Path("."), "--output=/tmp/x")


class SupplyChainTests(unittest.TestCase):
    def test_detects_ci_dependency_and_docker_risks(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root, "package.json", json.dumps({"scripts": {"postinstall": "node x"}, "dependencies": {"a": "github:u/a", "b": "*"}}))
            write(root, "requirements.txt", "--extra-index-url https://x.example/simple\nflask\nrequests==2.0\n")
            write(root, "Dockerfile", "FROM node\nRUN curl -s https://x.example | sh\n")
            write(root, ".github/workflows/ci.yml",
                  "on: pull_request_target\npermissions:\n  contents: read\njobs:\n  a:\n    steps:\n"
                  "      - uses: actions/checkout@" + "a" * 40 + "\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n"
                  "      - run: echo ${{ github.event.pull_request.title }}\n      - uses: evil/thing@main\n")
            rules = {f["rule_id"] for f in supply_chain.scan(root)["findings"]}
            for expected in ("npm-install-script", "npm-url-dependency", "npm-floating-version", "missing-lockfile",
                             "extra-index-url", "unpinned-requirement", "floating-base-image", "curl-pipe-shell",
                             "pwn-request", "script-injection", "unpinned-action"):
                self.assertTrue(any(r.endswith(expected) for r in rules), expected)
            self.assertNotIn("bluekit.ci.missing-permissions", rules)

    def test_clean_manifests_have_no_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root, "package.json", json.dumps({"dependencies": {"a": "^1.0.0"}}))
            write(root, "package-lock.json", json.dumps({"packages": {"": {}, "node_modules/a": {"resolved": "https://r/a.tgz", "integrity": "sha512-x"}}}))
            write(root, "requirements.txt", "flask==3.0.0\n")
            write(root, "Dockerfile", "FROM python:3.12-slim\n")
            self.assertEqual(supply_chain.scan(root)["findings"], [])


class TriageReportTests(unittest.TestCase):
    def test_triage_annotates_without_hiding_and_renders_reports(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            triage.record(root, "a", "false_positive", "Input is a constant", "x.py:3")
            with self.assertRaises(ValueError):
                triage.record(root, "a", "maybe", "x")
            with self.assertRaises(ValueError):
                triage.record(root, "a", "fixed", " ")
            data = triage.annotate(root, {"findings": [{"id": "a", "rule_id": "r", "title": "T", "priority": "P1", "file": "x.py", "line": 3},
                                                       {"id": "b", "rule_id": "r", "title": "T", "priority": "P2", "file": "y.py", "line": 0}], "errors": []})
            self.assertEqual(len(data["findings"]), 2)
            sarif = report.sarif(data)
            results = sarif["runs"][0]["results"]
            self.assertEqual(sarif["version"], "2.1.0")
            self.assertEqual(results[0]["suppressions"][0]["justification"], "Input is a constant")
            self.assertEqual(results[1]["locations"][0]["physicalLocation"]["region"]["startLine"], 1)
            md = report.markdown(data)
            self.assertIn("## False positives", md)
            self.assertIn("## Untriaged findings", md)


class McpAuditTests(unittest.TestCase):
    def call(self, root, requests):
        out = io.StringIO()
        with patch.object(sys, "stdin", io.StringIO("\n".join(map(json.dumps, requests)) + "\n")), contextlib.redirect_stdout(out):
            agents.serve(root, lambda r: {"findings": [], "errors": []}, lambda: "semgrep")
        return [json.loads(line) for line in out.getvalue().splitlines()]

    def test_prompts_triage_and_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            replies = self.call(root, [
                {"jsonrpc": "2.0", "id": 1, "method": "prompts/get", "params": {"name": "security_audit"}},
                {"jsonrpc": "2.0", "id": 2, "method": "prompts/get", "params": {"name": "nope"}},
                {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "triage", "arguments": {"id": "a", "verdict": "needs_info", "reason": "depends on proxy"}}},
                {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "rule_scan", "arguments": {"pattern": "x"}}},
                {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "audit_report", "arguments": {"format": "sarif"}}},
                {"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": {"name": "search_code", "arguments": {"pattern": "x", "ignore_case": "yes"}}},
            ])
            self.assertIn("Variant analysis", replies[0]["result"]["messages"][0]["content"]["text"])
            self.assertEqual(replies[1]["error"]["code"], -32602)
            self.assertEqual(triage.load(root)["a"]["verdict"], "needs_info")
            self.assertTrue(replies[3]["result"]["isError"])
            self.assertEqual(replies[4]["result"]["structuredContent"]["sarif"]["version"], "2.1.0")
            self.assertEqual(replies[5]["error"]["code"], -32602)

    def test_uninstall_removes_audit_skill(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            agents.install(root)
            self.assertTrue((root / ".claude/skills/bluekit-audit/SKILL.md").is_file())
            agents.uninstall(root)
            self.assertFalse((root / ".claude").exists())
            self.assertFalse((root / ".agents").exists())


if __name__ == "__main__":
    unittest.main()
