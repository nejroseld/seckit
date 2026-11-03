import _isolate  # noqa: F401
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
import json
import shlex
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

from seckit import agents, fixes


class AgentInstallTests(unittest.TestCase):
    def setUp(self):
        # CI installs the package, so `seckit` is on PATH there; these tests cover the fallback.
        patcher = patch("seckit.agents.command_status", return_value={"path": None, "ours": False})
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_installs_project_local_files_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            created = agents.install(root)
            self.assertEqual(len(created), 7)
            for audit_skill in (root / ".agents/skills/seckit-audit/SKILL.md", root / ".claude/skills/seckit-audit/SKILL.md"):
                text = audit_skill.read_text()
                self.assertTrue(text.startswith("---\nname: seckit-audit\ndescription:"))
                self.assertIn("seckit surface`", text)
                self.assertNotIn(str(root.resolve()), text)
                self.assertIn("Variant analysis", text)
            self.assertTrue((root / "AGENTS.md").is_file())
            self.assertTrue((root / "CLAUDE.md").is_file())
            self.assertTrue((root / ".agents/skills/seckit/SKILL.md").is_file())
            self.assertTrue((root / ".claude/skills/seckit/SKILL.md").is_file())
            for skill_path in (root / ".agents/skills/seckit/SKILL.md", root / ".claude/skills/seckit/SKILL.md"):
                skill = skill_path.read_text()
                self.assertTrue(skill.startswith("---\nname: seckit\ndescription:"))
                self.assertEqual(skill.count("name: seckit"), 1)
            cursor = (root / ".cursor/rules/seckit.mdc").read_text()
            self.assertIn("alwaysApply: true", cursor)
            self.assertIn("-I -m seckit scan --json", cursor)
            self.assertNotIn(str(root.resolve()), cursor)
            self.assertEqual(agents.install(root), [])

    def test_preserves_existing_content_and_skips_symlinked_path(self):
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as outside:
            root, external = Path(tmp), Path(outside)
            keep = root / ".agents/skills/seckit/SKILL.md"
            keep.parent.mkdir(parents=True)
            keep.write_text("team instructions\n")
            (root / ".claude").symlink_to(external, target_is_directory=True)
            created = agents.install(root)
            self.assertEqual(created, ["AGENTS.md", "CLAUDE.md", ".cursor/rules/seckit.mdc", ".agents/skills/seckit/SKILL.md",
                                       ".agents/skills/seckit-audit/SKILL.md"])
            self.assertIn("team instructions\n", keep.read_text())
            self.assertIn("<!-- seckit:managed:start -->", keep.read_text())
            self.assertFalse((external / "skills/seckit/SKILL.md").exists())


    def test_generated_invocation_runs_with_cli_option_order(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            command = shlex.split(agents._invocation(root))
            self.assertEqual(command[0], sys.executable)
            self.assertEqual(command[1:4], ["-I", "-m", "seckit"])
            # Isolated mode intentionally ignores this source checkout; remove it only
            # in the harness while exercising the generated module/CLI argument order.
            command.remove("-I")
            process = subprocess.run(command + ["scan", "--root", str(root), "--help"],
                                     cwd=Path(__file__).resolve().parents[1], capture_output=True, text=True)
            self.assertEqual(process.returncode, 0, process.stderr)

    def test_migrates_exact_legacy_templates_and_preserves_custom_cursor_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            old_skill, old_cursor = agents._legacy_contents()
            skill = root / ".agents/skills/seckit/SKILL.md"
            skill.parent.mkdir(parents=True)
            skill.write_text(old_skill)
            cursor = root / ".cursor/rules/seckit.mdc"
            cursor.parent.mkdir(parents=True)
            cursor.write_text("---\ndescription: Team rule\nglobs:\n- '*.py'\nalwaysApply: false\n---\n\nTeam body\n")
            (root / ".claude/skills/seckit/SKILL.md").parent.mkdir(parents=True)
            (root / ".claude/skills/seckit/SKILL.md").write_text(old_skill)
            agents.install(root)
            self.assertIn("alwaysApply: true", cursor.read_text())
            self.assertIn("description: Team rule", cursor.read_text())
            self.assertIn("Team body", cursor.read_text())
            self.assertIn("seckit:managed:start", cursor.read_text())
            for path in (skill, root / ".claude/skills/seckit/SKILL.md"):
                self.assertTrue(path.read_text().startswith("---\nname: seckit\ndescription:"))
                self.assertIn("always-on security assistant", path.read_text())
            self.assertEqual(agents.install(root), [])

    def test_preserves_crlf_cursor_and_skill_frontmatter(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cursor = root / ".cursor/rules/seckit.mdc"
            cursor.parent.mkdir(parents=True)
            cursor_original = b"---\r\ndescription: team cursor\r\nglobs:\r\n- '*.py'\r\nalwaysApply: false\r\n---\r\n\r\nTeam cursor body\r\n"
            cursor.write_bytes(cursor_original)
            skill = root / ".agents/skills/seckit/SKILL.md"
            skill.parent.mkdir(parents=True)
            skill_original = b"---\r\nname: team-skill\r\ndescription: Keep this skill metadata\r\n---\r\n\r\nTeam skill body\r\n"
            skill.write_bytes(skill_original)
            agents.install(root)
            cursor_data = cursor.read_bytes()
            skill_data = skill.read_bytes()
            self.assertIn(b"description: team cursor\r\n", cursor_data)
            self.assertIn(b"globs:\r\n- '*.py'\r\n", cursor_data)
            self.assertEqual(cursor_data.count(b"---\r\n"), 2)
            self.assertIn(b"alwaysApply: true\r\n", cursor_data)
            self.assertIn(b"Team cursor body\r\n", cursor_data)
            self.assertIn(b"name: team-skill\r\n", skill_data)
            self.assertIn(b"description: Keep this skill metadata\r\n", skill_data)
            self.assertEqual(skill_data.count(b"---\r\n"), 2)
            self.assertIn(b"Team skill body\r\n", skill_data)
            agents.install(root)
            self.assertEqual(cursor.read_bytes(), cursor_data)
            self.assertEqual(skill.read_bytes(), skill_data)

    def test_invalid_utf8_file_does_not_block_other_integrations(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            invalid = root / "AGENTS.md"
            invalid.write_bytes(b"team text\xff\n")
            created = agents.install(root)
            self.assertEqual(invalid.read_bytes(), b"team text\xff\n")
            self.assertIn("CLAUDE.md", created)
            self.assertTrue((root / ".cursor/rules/seckit.mdc").is_file())
            self.assertTrue((root / ".agents/skills/seckit/SKILL.md").is_file())

    def test_preserves_existing_instruction_newlines(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            agent = root / "AGENTS.md"
            agent.write_bytes(b"team text\r\nsecond line\r\n")
            agents.install(root)
            data = agent.read_bytes()
            self.assertTrue(data.startswith(b"team text\r\nsecond line\r\n"))
            self.assertIn(b"<!-- seckit:managed:start -->", data)
            after_first = data
            agents.install(root)
            self.assertEqual(agent.read_bytes(), after_first)

    def test_skips_hardlinked_agent_file(self):
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as outside:
            root, external = Path(tmp), Path(outside) / "shared.md"
            root_file = root / "AGENTS.md"
            external.write_text("shared user content\n")
            root_file.hardlink_to(external)
            agents.install(root)
            self.assertEqual(root_file.read_text(), "shared user content\n")
            self.assertEqual(external.read_text(), "shared user content\n")


class SafeFixTests(unittest.TestCase):
    def test_proposes_and_applies_reviewable_secret_ignore(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".gitignore").write_bytes(b"dist/\n")
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
            self.assertTrue((root / ".gitignore").read_text().startswith("# SecKit:"))

    def test_proposes_exact_compose_line_fix_and_preserves_surrounding_content(self):
        for newline in ("\n", "\r\n"):
            with self.subTest(newline=repr(newline)), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                source = "services:\n  app:\n    privileged: true # scanner finding\n    image: local/app\n".replace("\n", newline)
                # Exact byte fixtures avoid platform text-mode translation and
                # verify that applying a fix preserves both LF and CRLF files.
                (root / "compose.yaml").write_bytes(source.encode())
                finding = {"id": "trivy-compose-1", "rule_id": "AVD-DS-0002", "title": "privileged container", "file": "compose.yaml", "line": 3}
                plan = fixes.propose(root, [finding])[0]
                self.assertEqual(plan["kind"], "compose_privileged_false")
                self.assertEqual(plan["after"], source.replace("privileged: true", "privileged: false"))
                fixes.apply(root, [plan])
                self.assertEqual((root / "compose.yaml").read_bytes(), plan["after"].encode())

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
            self.assertEqual(messages[0]["result"]["serverInfo"]["name"], "seckit")
            self.assertEqual([tool["name"] for tool in messages[1]["result"]["tools"]], ["scan", "findings", "propose_safe_fixes", "apply_safe_fixes",
                              "attack_surface", "supply_chain", "diff_review", "rule_scan", "search_code", "read_code", "triage", "audit_report"])
            self.assertEqual((root / ".gitignore").read_text(), f"# {mcp_token}\n")
            self.assertEqual(messages[2]["result"]["structuredContent"]["findings"][0]["id"], "a")
            self.assertEqual(messages[3]["result"]["structuredContent"]["findings"][0]["id"], "a")
            plans = messages[4]["result"]["structuredContent"]
            self.assertIn(".env", plans["plans"][0]["diff"])
            self.assertNotIn("before", plans["plans"][0])
            self.assertTrue(plans["review_id"])
            self.assertEqual(messages[5]["error"]["code"], -32602)

    def test_mcp_review_apply_is_single_use_and_rescans(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".gitignore").write_text("dist/\n")
            calls = []
            def scanner(_root):
                calls.append(1)
                findings = [{"id": "secret-a", "rule_id": "secret-key", "file": ".env"}] if len(calls) == 1 else []
                return {"findings": findings, "errors": []}
            def call(i, name, args=None):
                return {"jsonrpc": "2.0", "id": i, "method": "tools/call", "params": {"name": name, "arguments": args or {}}}
            requests = [call(1, "propose_safe_fixes"), call(2, "apply_safe_fixes", {"review_id": "review-1"}), call(3, "apply_safe_fixes", {"review_id": "review-1"})]
            output = StringIO()
            fake_uuid = type("UUID", (), {"hex": "review-1"})()
            with patch("seckit.agents.uuid.uuid4", return_value=fake_uuid), patch("sys.stdin", StringIO("\n".join(map(json.dumps, requests)) + "\n")), redirect_stdout(output):
                agents.serve(root, scanner)
            messages = [json.loads(line) for line in output.getvalue().splitlines()]
            applied = messages[1]["result"]["structuredContent"]
            self.assertEqual(applied["applied_count"], 1)
            self.assertEqual(applied["resolved_ids"], ["secret-a"])
            self.assertEqual(applied["findings"], [])
            self.assertEqual(applied["status"], "rescanned")
            self.assertTrue(messages[2]["result"]["isError"])
            self.assertEqual(len(calls), 2)
            self.assertIn(".env.*", (root / ".gitignore").read_text())

    def test_mcp_stale_review_does_not_overwrite_user_edit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ignore = root / ".gitignore"
            ignore.write_text("dist/\n")
            requests = [
                {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "propose_safe_fixes", "arguments": {}}},
                {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "apply_safe_fixes", "arguments": {"review_id": "stale"}}},
            ]
            class Input:
                def __iter__(self):
                    yield json.dumps(requests[0])
                    ignore.write_text("user changed this\n")
                    yield json.dumps(requests[1])
            scanner = lambda _root: {"findings": [{"id": "a", "rule_id": "secret-key", "file": ".env"}], "errors": []}
            output = StringIO()
            fake_uuid = type("UUID", (), {"hex": "stale"})()
            with patch("seckit.agents.uuid.uuid4", return_value=fake_uuid), patch("sys.stdin", Input()), redirect_stdout(output):
                agents.serve(root, scanner)
            messages = [json.loads(line) for line in output.getvalue().splitlines()]
            self.assertTrue(messages[1]["result"]["isError"])
            self.assertEqual(ignore.read_text(), "user changed this\n")

    def test_mcp_apply_reports_incomplete_post_apply_scan(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".gitignore").write_text("dist/\n")
            calls = []
            def scanner(_root):
                calls.append(1)
                return {"findings": [{"id": "a", "rule_id": "secret-key", "file": ".env"}], "errors": []} if len(calls) == 1 else {"findings": [], "errors": ["scanner unavailable"]}
            requests = [
                {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "propose_safe_fixes", "arguments": {}}},
                {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "apply_safe_fixes", "arguments": {"review_id": "incomplete"}}},
            ]
            fake_uuid = type("UUID", (), {"hex": "incomplete"})()
            output = StringIO()
            with patch("seckit.agents.uuid.uuid4", return_value=fake_uuid), patch("sys.stdin", StringIO("\n".join(map(json.dumps, requests)) + "\n")), redirect_stdout(output):
                agents.serve(root, scanner)
            result = json.loads(output.getvalue().splitlines()[1])["result"]
            self.assertTrue(result["isError"])
            self.assertFalse(result["structuredContent"]["complete"])
            self.assertEqual(result["structuredContent"]["resolved_ids"], [])
            self.assertEqual(result["structuredContent"]["errors"], ["scanner unavailable"])

    def test_mcp_apply_scan_exception_keeps_applied_count_and_clears_cached_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".gitignore").write_text("dist/\n")
            calls = []
            def scanner(_root):
                calls.append(1)
                if len(calls) == 2:
                    raise RuntimeError("untrusted scanner detail")
                return {"findings": [{"id": "a", "rule_id": "secret-key", "file": ".env"}], "errors": []}
            def request(i, name, args=None):
                return {"jsonrpc": "2.0", "id": i, "method": "tools/call", "params": {"name": name, "arguments": args or {}}}
            requests = [request(1, "propose_safe_fixes"), request(2, "apply_safe_fixes", {"review_id": "post-error"}), request(3, "findings")]
            fake_uuid = type("UUID", (), {"hex": "post-error"})()
            output = StringIO()
            with patch("seckit.agents.uuid.uuid4", return_value=fake_uuid), patch("sys.stdin", StringIO("\n".join(map(json.dumps, requests)) + "\n")), redirect_stdout(output):
                agents.serve(root, scanner)
            messages = [json.loads(line) for line in output.getvalue().splitlines()]
            failed = messages[1]["result"]["structuredContent"]
            self.assertEqual(failed["applied_count"], 1)
            self.assertFalse(failed["complete"])
            self.assertEqual(failed["resolved_ids"], [])
            self.assertEqual(failed["errors"], ["post-apply scan failed"])
            self.assertEqual(messages[2]["result"]["structuredContent"]["findings"][0]["id"], "a")
            self.assertEqual(len(calls), 3)

    def test_mcp_failed_scan_is_explicitly_incomplete(self):
        with tempfile.TemporaryDirectory() as tmp:
            request = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "findings", "arguments": {}}}
            output = StringIO()
            scanner = lambda _root: {"findings": [], "errors": ["scanner unavailable"]}
            with patch("sys.stdin", StringIO(json.dumps(request) + "\n")), redirect_stdout(output):
                agents.serve(Path(tmp), scanner)
            result = json.loads(output.getvalue())["result"]
            self.assertTrue(result["isError"])
            self.assertFalse(result["structuredContent"]["complete"])


if __name__ == "__main__":
    unittest.main()
