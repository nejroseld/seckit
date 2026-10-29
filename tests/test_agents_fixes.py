import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
import json
from pathlib import Path
from unittest.mock import patch

from guardkit import agents, fixes


class AgentInstallTests(unittest.TestCase):
    def test_installs_project_local_files_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            created = agents.install(root)
            self.assertEqual(len(created), 3)
            self.assertTrue((root / ".agents/skills/guardkit/SKILL.md").is_file())
            self.assertTrue((root / ".claude/skills/guardkit/SKILL.md").is_file())
            cursor = (root / ".cursor/rules/guardkit.mdc").read_text()
            self.assertIn("alwaysApply: false", cursor)
            self.assertEqual(agents.install(root), [])

    def test_preserves_existing_content_and_skips_symlinked_path(self):
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as outside:
            root, external = Path(tmp), Path(outside)
            keep = root / ".agents/skills/guardkit/SKILL.md"
            keep.parent.mkdir(parents=True)
            keep.write_text("team instructions\n")
            (root / ".claude").symlink_to(external, target_is_directory=True)
            created = agents.install(root)
            self.assertEqual(created, [".cursor/rules/guardkit.mdc"])
            self.assertEqual(keep.read_text(), "team instructions\n")
            self.assertFalse((external / "skills/guardkit/SKILL.md").exists())


class SafeFixTests(unittest.TestCase):
    def test_proposes_and_applies_reviewable_secret_ignore(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".gitignore").write_text("dist/\n")
            finding = {"id": "trivy-123", "rule_id": "SECRET-API", "title": "Secret found", "file": ".env.local"}
            plans = fixes.propose(root, [finding])
            self.assertEqual(len(plans), 1)
            self.assertEqual(plans[0]["before"], "dist/\n")
            self.assertIn(".env.*", plans[0]["after"])
            applied = fixes.apply(root, plans)
            self.assertEqual(len(applied), 1)
            self.assertIn("!.env.example", (root / ".gitignore").read_text())

    def test_creates_missing_gitignore(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plan = fixes.propose(root, [{"id": "secret", "rule_id": "secret-match", "file": ".env"}])[0]
            fixes.apply(root, [plan])
            self.assertTrue((root / ".gitignore").read_text().startswith("# GuardKit:"))

    def test_proposes_exact_compose_line_fix_and_preserves_surrounding_content(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = "services:\n  app:\n    privileged: true # scanner finding\n    image: local/app\n"
            (root / "compose.yaml").write_text(source)
            finding = {"id": "trivy-compose-1", "rule_id": "AVD-DS-0002", "title": "privileged container", "file": "compose.yaml", "line": 3}
            plan = fixes.propose(root, [finding])[0]
            self.assertEqual(plan["kind"], "compose_privileged_false")
            self.assertEqual(plan["after"], source.replace("privileged: true", "privileged: false"))
            fixes.apply(root, [plan])
            self.assertEqual((root / "compose.yaml").read_text(), plan["after"])

    def test_proposes_scanner_reported_dockerfile_nonroot_change(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = "FROM alpine:3.20\nUSER root # migration note\nCMD [\"app\"]\n"
            (root / "Dockerfile").write_text(source)
            finding = {"id": "trivy-ds002", "rule_id": "AVD-DS-0002", "title": "Last USER command in Dockerfile should not be root", "file": "Dockerfile", "line": 2}
            plan = fixes.propose(root, [finding])[0]
            self.assertEqual(plan["kind"], "dockerfile_user_nonroot")
            self.assertIn("USER 65532:65532 # migration note", plan["after"])
            public = fixes.public_plans([plan])[0]
            self.assertIn("+USER 65532:65532", public["diff"])
            self.assertNotIn("migration note", public["diff"])
            self.assertIn("ownership", public["reason"])
            fixes.apply(root, [plan])
            self.assertIn("USER 65532:65532", (root / "Dockerfile").read_text())

    def test_public_plans_include_only_sanitized_changed_lines(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            token = "SENTINEL-SECRET-DO-NOT-LEAK"
            (root / ".gitignore").write_text(f"# existing {token}\n")
            (root / "compose.yml").write_text(f"services:\n  app:\n    privileged: true # {token}\n    environment:\n      API_KEY: {token}\n")
            plans = fixes.propose(root, [
                {"id": "secret-1", "rule_id": "secret-match", "file": ".env"},
                {"id": "compose-1", "rule_id": "AVD-DS-0002", "title": "privileged", "file": "compose.yml", "line": 3},
            ])
            public = fixes.public_plans(plans)
            encoded = json.dumps(public)
            self.assertNotIn(token, encoded)
            self.assertEqual(len(public), 2)
            self.assertTrue(all("before" not in plan and "after" not in plan for plan in public))
            self.assertIn("+privileged: false", public[1]["diff"])
            self.assertNotIn("API_KEY", public[1]["diff"])

    def test_does_not_propose_for_non_secret_or_unrecognized_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            findings = [
                {"rule_id": "unsafe-call", "title": "unsafe", "file": ".env"},
                {"rule_id": "secret-match", "title": "secret", "file": "src/app.py"},
            ]
            self.assertEqual(fixes.propose(root, findings), [])

    def test_rejects_stale_content_and_symlink(self):
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as outside:
            root = Path(tmp)
            plan = fixes.propose(root, [{"rule_id": "secret-key", "file": "private.pem"}])[0]
            (root / ".gitignore").write_text("user edit\n")
            with self.assertRaisesRegex(ValueError, "content changed"):
                fixes.apply(root, [plan])
            self.assertEqual((root / ".gitignore").read_text(), "user edit\n")
            target = Path(outside) / "ignore"
            target.write_text("external\n")
            (root / ".gitignore").unlink()
            (root / ".gitignore").symlink_to(target)
            with self.assertRaises(ValueError):
                fixes.apply(root, [plan])
            self.assertEqual(target.read_text(), "external\n")

    def test_rolls_back_only_its_own_prior_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = fixes.propose(root, [{"id": "a", "rule_id": "secret-key", "file": "private.pem"}])[0]
            stale = dict(first, after=first["after"] + "# stale\n")
            with self.assertRaises(ValueError):
                fixes.apply(root, [first, stale])
            self.assertFalse((root / ".gitignore").exists())

    def test_mcp_exposes_only_fixed_repo_tools_and_does_not_apply_fixes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            mcp_token = "MCP-SECRET-SENTINEL"
            (root / ".gitignore").write_text(f"# {mcp_token}\n")
            callback_calls = []
            def scanner(scan_root):
                callback_calls.append(scan_root)
                return {"findings": [{"id": "a", "rule_id": "secret-key", "file": ".env"}], "errors": []}
            requests = [
                {"jsonrpc": "2.0", "id": 1, "method": "initialize"},
                {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
                {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "scan", "arguments": {}}},
                {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "findings", "arguments": {}}},
                {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "propose_safe_fixes", "arguments": {}}},
                {"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": {"name": "scan", "arguments": {"command": "cat credentials"}}},
            ]
            output = StringIO()
            with patch("sys.stdin", StringIO("\n".join(map(json.dumps, requests)) + "\n")), redirect_stdout(output):
                agents.serve(root, scanner)
            messages = [json.loads(line) for line in output.getvalue().splitlines()]
            self.assertNotIn(mcp_token, output.getvalue())
            self.assertEqual(len(callback_calls), 1)
            self.assertEqual(messages[0]["result"]["serverInfo"]["name"], "guardkit")
            self.assertEqual([tool["name"] for tool in messages[1]["result"]["tools"]], ["scan", "findings", "propose_safe_fixes"])
            self.assertEqual((root / ".gitignore").read_text(), f"# {mcp_token}\n")
            self.assertEqual(messages[2]["result"]["structuredContent"]["findings"][0]["id"], "a")
            self.assertEqual(messages[3]["result"]["structuredContent"]["findings"][0]["id"], "a")
            plans = messages[4]["result"]["structuredContent"]["plans"]
            self.assertIn(".env", plans[0]["diff"])
            self.assertNotIn("before", plans[0])
            self.assertEqual(messages[5]["error"]["code"], -32602)


if __name__ == "__main__":
    unittest.main()
