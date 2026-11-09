import _isolate  # noqa: F401
import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from seckit import agents, cli, nextsteps


def run_cli(*args, cwd=None):
    out = io.StringIO()
    previous = os.getcwd()
    try:
        if cwd:
            os.chdir(cwd)
        with contextlib.redirect_stdout(out):
            code = cli.main(list(args))
    finally:
        os.chdir(previous)
    return code, out.getvalue()


class PlanTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()

    def tearDown(self):
        self.tmp.cleanup()

    def test_plan_writes_nothing_and_lists_diffs(self):
        (self.root / "AGENTS.md").write_text("# Mine\n")
        with patch("seckit.provision.tools", side_effect=AssertionError("plan must not download")):
            code, out = run_cli("init", "--plan", "--root", str(self.root))
        self.assertEqual(code, 0)
        report = json.loads(out)
        self.assertIn("AGENTS.md", report["writes"])
        agents_entry = next(entry for entry in report["plan"] if entry["file"] == "AGENTS.md")
        self.assertEqual(agents_entry["action"], "update")
        self.assertIn("+<!-- seckit:managed:start -->", agents_entry["diff"])
        self.assertEqual(sorted(p.name for p in self.root.iterdir()), ["AGENTS.md"])
        self.assertEqual((self.root / "AGENTS.md").read_text(), "# Mine\n")

    def test_crlf_legacy_template_is_recognised(self):
        old_skill, _ = agents._legacy_contents()
        skill = self.root / ".claude/skills/seckit/SKILL.md"
        skill.parent.mkdir(parents=True)
        skill.write_bytes(old_skill.replace("\n", "\r\n").encode())
        agents.install(self.root)
        self.assertTrue(skill.read_text().startswith("---\nname: seckit\n"))
        self.assertNotIn("name: guardkit", skill.read_text())

    def test_plan_is_empty_after_init(self):
        agents.install(self.root)
        plan = []
        self.assertEqual(agents.install(self.root, plan), [])
        self.assertEqual(plan, [])

    def test_plan_reports_old_name_migration_once(self):
        old = agents._old_name(agents._instructions(self.root))
        (self.root / "AGENTS.md").write_text(old + "\n")
        (self.root / ".guardkit").mkdir()
        plan = []
        agents.install(self.root, plan)
        files = [entry["file"] for entry in plan]
        self.assertEqual(files.count("AGENTS.md"), 1)
        self.assertIn(".guardkit -> .seckit", files)
        self.assertTrue((self.root / ".guardkit").is_dir())


class RootAndCommandTests(unittest.TestCase):
    def test_default_root_is_git_top_level(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            (root / ".git").mkdir()
            (root / "src/deep").mkdir(parents=True)
            previous = os.getcwd()
            try:
                os.chdir(root / "src/deep")
                self.assertEqual(cli._default_root().resolve(), root)
            finally:
                os.chdir(previous)

    @unittest.skipIf(os.name == "nt", "shebang launchers are POSIX only")
    def test_command_on_path_must_use_this_interpreter(self):
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / "seckit"
            with patch("shutil.which", return_value=str(script)):
                script.write_text(f"#!{sys.executable}\nimport seckit\n")
                self.assertTrue(agents.command_status()["ours"])
                self.assertEqual(agents._invocation(Path(tmp)), "seckit")
                script.write_text("#!/opt/other/venv/bin/python\n")
                self.assertFalse(agents.command_status()["ours"])
                self.assertIn(sys.executable, agents._invocation(Path(tmp)))
                self.assertNotEqual(agents._invocation(Path(tmp)), "seckit")
            with patch("shutil.which", return_value=None):
                self.assertEqual(agents.command_status(), {"path": None, "ours": False})

    @unittest.skipUnless(os.name == "nt", "console scripts are .exe launchers on Windows")
    def test_windows_launcher_must_sit_next_to_this_interpreter(self):
        beside = Path(sys.executable).with_name("seckit.exe")
        with patch("shutil.which", return_value=str(beside)):
            self.assertTrue(agents.command_status()["ours"])
            self.assertEqual(agents._invocation(Path(".")), "seckit")
        with patch("shutil.which", return_value=str(Path(sys.executable).parent.parent / "other" / "seckit.exe")):
            self.assertFalse(agents.command_status()["ours"])

    def test_instructions_have_no_machine_paths_when_on_path(self):
        with tempfile.TemporaryDirectory() as tmp, \
                patch("seckit.agents.command_status", return_value={"path": "/x/seckit", "ours": True}):
            root = Path(tmp).resolve()
            agents.install(root)
            for relative in ("AGENTS.md", ".claude/skills/seckit-audit/SKILL.md", ".cursor/rules/seckit.mdc"):
                text = (root / relative).read_text()
                self.assertNotIn(str(root), text)
                self.assertNotIn(sys.executable, text)
            self.assertIn("`seckit scan --json`", (root / "AGENTS.md").read_text())
            self.assertIn("next_steps", (root / "AGENTS.md").read_text())


class NextStepTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def ids(self, steps):
        return [step["id"] for step in steps]

    def test_clean_scan_offers_audit_and_supply_chain_with_ci(self):
        (self.root / ".github/workflows").mkdir(parents=True)
        steps = nextsteps.after_scan(self.root, {"findings": [], "errors": [], "stack": ["FastAPI", "Python"]})
        self.assertEqual(self.ids(steps), ["audit", "supply-chain"])
        self.assertIn("FastAPI", steps[0]["why"])

    def test_findings_come_first(self):
        report = {"findings": [{"id": "a", "fix_available": True}, {"id": "b", "fix_available": False}], "errors": [], "stack": []}
        steps = nextsteps.after_scan(self.root, report)
        self.assertEqual(self.ids(steps)[:2], ["fix", "review"])
        self.assertEqual(steps[0]["writes"], [])
        self.assertEqual(steps[1]["writes"], [".seckit/triage.json"])

    def test_incomplete_scan_starts_with_doctor(self):
        steps = nextsteps.after_scan(self.root, {"findings": [], "errors": ["trivy failed"], "stack": []})
        self.assertEqual(steps[0]["id"], "doctor")

    def test_steps_are_capped_and_well_formed(self):
        (self.root / ".github/workflows").mkdir(parents=True)
        report = {"findings": [{"id": "a", "fix_available": True}, {"id": "b"}], "errors": ["x"], "stack": []}
        steps = nextsteps.after_scan(self.root, report)
        self.assertLessEqual(len(steps), nextsteps.LIMIT)
        for step in steps:
            self.assertEqual(set(step), {"id", "title", "why", "command", "writes"})

    def test_after_init(self):
        (self.root / ".git").mkdir()
        steps = nextsteps.after_init(self.root, [], ["AGENTS.md", ".claude/skills/seckit/SKILL.md"], False, True)
        self.assertEqual(self.ids(steps), ["scan", "audit", "commit-agent-files", "mcp"])
        self.assertIn("no machine-specific paths", steps[2]["why"])
        self.assertEqual(steps[2]["command"], "git add .claude AGENTS.md")

    def test_doctor_flags_foreign_command_and_missing_tools(self):
        report = {"command": {"path": "/usr/bin/seckit", "ours": False},
                  "expected_versions": {"trivy": "1", "semgrep": "1"}, "tools": {}}
        self.assertEqual(self.ids(nextsteps.after_doctor(report)), ["fix-path", "init"])

    def test_scan_json_includes_next_steps(self):
        report = {"findings": [], "errors": [], "stack": []}
        with patch("seckit.cli._scan", return_value=report):
            code, out = run_cli("scan", "--root", str(self.root))
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["next_steps"][0]["id"], "audit")


if __name__ == "__main__":
    unittest.main()
