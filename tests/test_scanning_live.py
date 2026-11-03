"""Opt-in real Semgrep regressions; Trivy is stubbed, no downloads are needed."""
import _isolate  # noqa: F401
import contextlib
import io
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from seckit import provision
from seckit.cli import _show
from seckit.scanning import _run, scan


@unittest.skipUnless(os.environ.get("SECKIT_LIVE_SCANNERS") == "1",
                     "set SECKIT_LIVE_SCANNERS=1 with Semgrep installed")
class LiveSemgrepAuditTests(unittest.TestCase):
    def test_repository_suppressions_cannot_hide_findings(self):
        with tempfile.TemporaryDirectory(prefix="seckit-audit-live-") as tmp:
            base = Path(tmp)
            root = base / "repo"
            root.mkdir()
            if shutil.which("git"):
                subprocess.run(["git", "init", "-q", str(root)], check=True,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            (root / ".semgrepignore").write_text("*\n")
            (root / ".gitignore").write_text("*\n")
            (root / "unsafe.js").write_text("eval(userInput); // nosemgrep\n")
            nested = root / "src"
            nested.mkdir()
            (nested / ".semgrepignore").write_text("*\n")
            (nested / "nested.js").write_text("eval(userInput); // nosemgrep\n")
            (root / "vendor").mkdir()
            (root / "vendor" / "ignored.js").write_text("eval(userInput);\n")
            terminal_name = "unsafe\x1b[2K\rFORGED.js"
            if os.name == "posix":
                (root / terminal_name).write_text("eval(userInput);\n")

            def run(command, cwd):
                if command[0] == "unused-trivy":
                    return {"Results": []}, None
                return _run(command, cwd)

            env = {"SEMGREP_SETTINGS_FILE": str(base / "settings.yml"),
                   "SEMGREP_LOG_FILE": str(base / "semgrep.log"),
                   "XDG_CACHE_HOME": str(base / "cache")}
            with patch.dict(os.environ, {key: value for key, value in env.items()
                                         if key != "XDG_CACHE_HOME"}):
                semgrep = provision.tools(install=False).get("semgrep")
            if not semgrep:
                self.skipTest("Pinned Semgrep is not installed")
            with patch.dict(os.environ, env), patch("seckit.scanning._run", side_effect=run):
                report = scan(root, "unused-trivy", semgrep)
            self.assertEqual(report["errors"], [])
            paths = {finding["file"] for finding in report["findings"]}
            expected = {"unsafe.js", "src/nested.js"}
            if os.name == "posix":
                expected.add(terminal_name)
            self.assertEqual(paths, expected)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                _show(report)
            self.assertNotIn("\x1b", output.getvalue())
            self.assertNotIn("\r", output.getvalue())
