import _isolate  # noqa: F401
import sys
import tempfile
import unittest
from pathlib import Path

from guardkit import agents


class ClaudeModInstallTests(unittest.TestCase):
    def test_init_installs_bound_panel_mod_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            changed = agents.install(root)
            mod = root / ".claude/skills/guardkit-input"
            for relative in (".claude-plugin/plugin.json", "hooks/hooks.json", "hooks/register.tsx", "types/index.d.ts"):
                self.assertTrue((mod / relative).is_file(), relative)
                self.assertIn(".claude/skills/guardkit-input/" + relative, changed)
            code = (mod / "hooks/register.tsx").read_text()
            self.assertNotIn("__GUARDKIT_", code)
            self.assertIn(sys.executable, code)
            self.assertEqual(agents.install(root), [])

    def test_stale_mod_file_is_refreshed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            agents.install(root)
            target = root / ".claude/skills/guardkit-input/hooks/register.tsx"
            target.write_text("stale")
            self.assertIn(".claude/skills/guardkit-input/hooks/register.tsx", agents.install(root))
            self.assertNotEqual(target.read_text(), "stale")


if __name__ == "__main__":
    unittest.main()
