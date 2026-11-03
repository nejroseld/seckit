import _isolate  # noqa: F401
import contextlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from bluekit import agents, cli, fixes, ignores, scanning


def finding(**kw):
    base = {"id": "a1", "rule_id": "r", "file": "src/x.py", "line": 1, "priority": "P2", "category": "code", "severity": "MEDIUM"}
    return {**base, **kw}


class IgnoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / ".bluekit").mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, data):
        (self.root / ".bluekit/ignore.json").write_text(json.dumps(data))

    def test_suppressed_findings_stay_visible_with_reason(self):
        self.write({"ignore": [{"path": "tests/fixtures/**", "reason": "fixtures"}, {"rule_id": "r2", "reason": "accepted"}]})
        report = {"findings": [finding(file="tests/fixtures/a.py"), finding(id="b", rule_id="r2"), finding(id="c")], "errors": []}
        out = ignores.apply(self.root, report)
        self.assertEqual([f["id"] for f in out["findings"]], ["c"])
        self.assertEqual({f["suppressed_reason"] for f in out["suppressed"]}, {"fixtures", "accepted"})

    def test_rule_without_reason_is_rejected_and_reported(self):
        self.write({"ignore": [{"path": "**"}]})
        out = ignores.apply(self.root, {"findings": [finding()], "errors": []})
        self.assertEqual(len(out["findings"]), 1)
        self.assertTrue(out["warnings"])

    def test_invalid_file_suppresses_nothing(self):
        (self.root / ".bluekit/ignore.json").write_text("{bad")
        out = ignores.apply(self.root, {"findings": [finding()], "errors": []})
        self.assertEqual(len(out["findings"]), 1)
        self.assertTrue(out["warnings"])


class ScanningTests(unittest.TestCase):
    def test_dependency_title_has_single_prefix_and_fix_version(self):
        data = {"Results": [{"Target": "package-lock.json", "Vulnerabilities": [
            {"PkgName": "lodash", "VulnerabilityID": "CVE-1", "Title": "lodash: nodejs-lodash: bad", "Severity": "HIGH",
             "InstalledVersion": "4.0.0", "FixedVersion": "4.17.21"}]}]}
        item = scanning.normalize_trivy(data, Path("."))[0]
        self.assertEqual(item["title"], "lodash: bad")
        self.assertEqual((item["package"], item["fixed_version"]), ("lodash", "4.17.21"))

    def test_credential_without_secret_in_name_gets_gitignore_fix(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / ".env").write_text("X=1\n")
            plans = fixes.propose(Path(tmp), [finding(id="k", rule_id="aws-access-key-id", title="AWS Access Key ID",
                                                     file=".env", category="credential")])
            self.assertEqual(plans[0]["path"], ".gitignore")


class McpTests(unittest.TestCase):
    def call(self, args):
        report = {"findings": [finding(id="1", priority="P0", category="credential", file="a/x"),
                               finding(id="2", priority="P3", file="b/y"), finding(id="3", priority="P2", file="a/z")], "errors": []}
        requests = [{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "findings", "arguments": args}},
                    {"jsonrpc": "2.0", "id": 2, "method": "resources/list"}, {"jsonrpc": "2.0", "id": 3, "method": "prompts/list"}]
        out = io.StringIO()
        with patch.object(sys, "stdin", io.StringIO("\n".join(map(json.dumps, requests)) + "\n")), contextlib.redirect_stdout(out):
            agents.serve(Path("."), lambda root: report)
        return [json.loads(line) for line in out.getvalue().splitlines()]

    def test_filters_and_pagination(self):
        first = self.call({"min_priority": "P2"})[0]["result"]["structuredContent"]
        self.assertEqual([f["id"] for f in first["findings"]], ["1", "3"])
        page = self.call({"limit": 1, "offset": 1})[0]["result"]["structuredContent"]
        self.assertEqual((page["total"], page["next_offset"], page["findings"][0]["id"]), (3, 2, "2"))
        self.assertEqual(self.call({"file": "a/"})[0]["result"]["structuredContent"]["total"], 2)
        self.assertEqual(self.call({"id": "2"})[0]["result"]["structuredContent"]["total"], 1)

    def test_bad_types_rejected_and_empty_lists_supported(self):
        replies = self.call({"limit": "5"})
        self.assertEqual(replies[0]["error"]["code"], -32602)
        self.assertEqual(replies[1]["result"], {"resources": []})
        self.assertEqual([p["name"] for p in replies[2]["result"]["prompts"]],
                         ["security_audit", "differential_review", "variant_analysis", "triage_findings"])


class InstallTests(unittest.TestCase):
    def test_mcp_registration_and_uninstall_keep_user_content(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "AGENTS.md").write_text("# mine\n")
            (root / ".mcp.json").write_text(json.dumps({"mcpServers": {"other": {"command": "x"}}}))
            agents.install(root)
            self.assertEqual(agents.register_mcp(root, "py", ["-m", "bluekit"]), ".mcp.json")
            self.assertIsNone(agents.register_mcp(root, "py", ["-m", "bluekit"]))
            removed = agents.uninstall(root)
            self.assertIn("AGENTS.md", removed)
            self.assertEqual((root / "AGENTS.md").read_text(), "# mine\n")
            self.assertFalse((root / "CLAUDE.md").exists())
            self.assertFalse((root / ".claude").exists())
            self.assertEqual(list(json.loads((root / ".mcp.json").read_text())["mcpServers"]), ["other"])


class CliTests(unittest.TestCase):
    def run_cli(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_usage_and_file_root_errors_are_specific_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, out, _ = self.run_cli(["fix", "--root", tmp, "--run-tests"])
            self.assertEqual(code, 2)
            self.assertIn("--apply", json.loads(out)["errors"][0])
            f = Path(tmp) / "a.py"; f.write_text("")
            code, out, _ = self.run_cli(["scan", "--root", str(f)])
            self.assertIn("not a file", json.loads(out)["errors"][0])
            self.assertEqual(json.loads(out)["schema_version"], 1)

    def test_json_report_has_status_and_exit_code(self):
        with patch.object(cli, "_scan", return_value={"findings": [finding()], "errors": []}):
            code, out, _ = self.run_cli(["scan"])
        data = json.loads(out)
        self.assertEqual((code, data["status"], data["exit_code"]), (1, "findings", 1))

    def test_pytest_projects_use_pytest(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "tests").mkdir(); (Path(tmp) / "tests/conftest.py").write_text("")
            self.assertEqual(cli._project_tests(Path(tmp))[1:3], ["-m", "pytest"])

    def test_failed_tests_return_output_tail(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            proc = subprocess.CompletedProcess([], 1, stdout="line\nAssertionError: boom\n")
            with patch.object(cli.reviews, "consume", return_value=[]), patch.object(cli.fixes, "apply", return_value=[]), \
                 patch.object(cli, "_project_tests", return_value=["t"]), patch.object(subprocess, "run", return_value=proc), \
                 patch.object(cli, "_scan", return_value={"findings": [], "errors": []}):
                code, out, _ = self.run_cli(["fix", "--root", tmp, "--apply", "x", "--run-tests"])
        self.assertEqual(code, 2)
        self.assertIn("boom", json.loads(out)["project_tests"]["output_tail"])


if __name__ == "__main__":
    unittest.main()
