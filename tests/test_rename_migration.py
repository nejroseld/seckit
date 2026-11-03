import _isolate  # noqa: F401
import json
import tempfile
import unittest
from pathlib import Path

from bluekit import agents, ignores


class GuardkitMigrationTests(unittest.TestCase):
    """Projects initialised under the former name Guardkit upgrade cleanly."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, relative, text):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def old_project(self):
        old = agents._old_name
        self.write("AGENTS.md", "# My rules\n\nKeep this.\n\n" + old(agents._instructions(self.root)) + "\n")
        self.write("CLAUDE.md", old(agents._instructions(self.root)) + "\n")
        self.write(".claude/skills/guardkit/SKILL.md", old(agents._skill(self.root)))
        self.write(".agents/skills/guardkit-audit/SKILL.md", old(agents._audit_skill(self.root)))
        self.write(".cursor/rules/guardkit.mdc", old(agents._cursor_content(self.root)))
        self.write(".guardkit/ignore.json", json.dumps({"ignore": [{"path": "tests/**", "reason": "fixtures"}]}))
        self.write(".mcp.json", json.dumps({"mcpServers": {
            "guardkit": {"command": "/venv/bin/python", "args": ["-I", "-m", "guardkit", "mcp", "--root", str(self.root)]},
            "other": {"command": "x"}}}))

    def test_init_replaces_old_blocks_and_files(self):
        self.old_project()
        agents.install(self.root)
        text = (self.root / "AGENTS.md").read_text()
        self.assertIn("Keep this.", text)
        self.assertEqual(text.count(agents._BLOCK_START), 1)
        self.assertNotIn("guardkit:managed", text)
        self.assertNotIn("guardkit:managed", (self.root / "CLAUDE.md").read_text())
        for gone in (".claude/skills/guardkit", ".agents/skills/guardkit-audit", ".cursor/rules/guardkit.mdc", ".guardkit"):
            self.assertFalse((self.root / gone).exists(), gone)
        self.assertTrue((self.root / ".claude/skills/bluekit/SKILL.md").is_file())
        self.assertTrue((self.root / ".bluekit/ignore.json").is_file())
        servers = json.loads((self.root / ".mcp.json").read_text())["mcpServers"]
        self.assertEqual(sorted(servers), ["bluekit", "other"])
        self.assertEqual(servers["bluekit"]["args"][2], "bluekit")

    def test_custom_text_in_old_skill_is_kept(self):
        old = agents._old_name
        path = self.write(".claude/skills/guardkit/SKILL.md", old(agents._skill(self.root)) + "\nMy own note.\n")
        agents.install(self.root)
        self.assertEqual(path.read_text().strip().splitlines()[-1], "My own note.")
        self.assertNotIn("guardkit:managed", path.read_text())

    def test_init_is_idempotent_after_migration(self):
        self.old_project()
        agents.install(self.root)
        self.assertEqual(agents.install(self.root), [])

    def test_existing_bluekit_dir_is_not_overwritten(self):
        self.write(".guardkit/ignore.json", "{}")
        self.write(".bluekit/ignore.json", json.dumps({"ignore": []}))
        agents.install(self.root)
        self.assertTrue((self.root / ".guardkit/ignore.json").exists())
        self.assertEqual(json.loads((self.root / ".bluekit/ignore.json").read_text()), {"ignore": []})

    def test_uninstall_removes_old_name_too(self):
        self.old_project()
        removed = agents.uninstall(self.root)
        self.assertIn(".claude/skills/guardkit/SKILL.md", removed)
        self.assertFalse((self.root / "CLAUDE.md").exists())
        self.assertEqual((self.root / "AGENTS.md").read_text(), "# My rules\n\nKeep this.\n")
        self.assertNotIn("guardkit", json.loads((self.root / ".mcp.json").read_text())["mcpServers"])

    def test_ignore_rules_are_read_from_old_dir_before_migration(self):
        self.write(".guardkit/ignore.json", json.dumps({"ignore": [{"path": "tests/**", "reason": "fixtures"}]}))
        rules, problems = ignores.load(self.root)
        self.assertEqual([rule["reason"] for rule in rules], ["fixtures"])
        self.assertEqual(problems, [])


if __name__ == "__main__":
    unittest.main()
