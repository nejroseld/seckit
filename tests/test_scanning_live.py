"""Opt-in real-engine regressions. No downloads: Trivy uses its existing database or is stubbed."""
import _isolate  # noqa: F401
import contextlib
import io
import os
from pathlib import Path
import shutil
import socket
import subprocess
import threading
import tempfile
import unittest
from unittest.mock import patch

from seckit import provision, sandbox, scanning
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

            def run(command, cwd, timeout=600, env=None):
                if command[0] == "unused-trivy":
                    return {"Results": []}, None
                return _run(command, cwd, timeout, env)

            env = {"SEMGREP_SETTINGS_FILE": str(base / "settings.yml"),
                   "SEMGREP_LOG_FILE": str(base / "semgrep.log"),
                   "XDG_CACHE_HOME": str(base / "cache")}
            with patch.dict(os.environ, {key: value for key, value in env.items()
                                         if key != "XDG_CACHE_HOME"}):
                semgrep = provision.tools(install=False).get("semgrep")
            if not semgrep:
                self.skipTest("Pinned Semgrep is not installed")
            with patch.dict(os.environ, env), patch("seckit.scanning._run", side_effect=run), \
                 patch("seckit.scanning._update_trivy", return_value=None):
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


@unittest.skipUnless(os.environ.get("SECKIT_LIVE_SCANNERS") == "1",
                     "set SECKIT_LIVE_SCANNERS=1 with Trivy and Semgrep installed")
class LiveNetworkIsolationTests(unittest.TestCase):
    """A hostile project names a local listener as Maven repository and Terraform module host."""

    def test_scanners_reading_the_project_reach_no_network(self):
        tools = provision.tools(install=False)
        if len(tools) != 2:
            self.skipTest("Pinned Trivy and Semgrep are not installed")
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(16)
        listener.settimeout(0.2)
        port, hits, stop = listener.getsockname()[1], [], threading.Event()

        def accept():
            while not stop.is_set():
                try:
                    connection, _ = listener.accept()
                except OSError:
                    continue
                hits.append(1)
                connection.close()

        thread = threading.Thread(target=accept, daemon=True)
        thread.start()
        previous = sandbox._ISOLATION
        sandbox._ISOLATION = None  # probe the real platform
        self.addCleanup(setattr, sandbox, "_ISOLATION", previous)
        kind, _ = sandbox.isolation()
        with tempfile.TemporaryDirectory(prefix="seckit-egress-live-") as tmp:
            root = Path(tmp)
            modules = [f'module "g" {{\n  source = "git::http://127.0.0.1:{port}/m.git"\n}}\n',
                       f'module "s" {{\n  source = "git::ssh://git@127.0.0.1:{port}/m.git"\n}}\n']
            if kind == "namespace":  # Trivy itself fetches registry modules; only a namespace stops loopback
                modules.append(f'module "r" {{\n  source  = "127.0.0.1:{port}/ns/name/aws"\n  version = "1.0.0"\n}}\n')
            (root / "main.tf").write_text("".join(modules))
            (root / "pom.xml").write_text(
                "<project><modelVersion>4.0.0</modelVersion><groupId>g</groupId><artifactId>a</artifactId><version>1</version>"
                f"<repositories><repository><id>c</id><url>http://127.0.0.1:{port}/m2</url></repository></repositories>"
                "<dependencies><dependency><groupId>x</groupId><artifactId>y</artifactId><version>1</version></dependency>"
                "</dependencies></project>\n")
            with patch.object(scanning, "_update_trivy", return_value=None):
                report = scan(root, tools["trivy"], tools["semgrep"])
        stop.set()
        thread.join(2)
        listener.close()
        self.assertEqual(report["coverage"]["network_isolation"], kind)
        self.assertEqual(hits, [], f"scanners connected out while reading the project ({kind})")

