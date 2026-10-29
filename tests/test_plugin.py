import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from guardkit.plugin import build


class PluginBuildTests(unittest.TestCase):
    def test_builds_isolated_local_package_and_server_discovers_tools(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            project = base / "project"
            project.mkdir()
            (project / "guardkit.py").write_text("raise RuntimeError('shadowed')")
            output = base / "plugin"
            result = build(project, output)
            manifest = json.loads((output / "plugin.json").read_text())
            mcp = json.loads((output / "mcp.json").read_text())
            self.assertEqual(result["plugin_directory"], str(output.resolve()))
            self.assertEqual(manifest["name"], "guardkit-safe-input")
            interface = manifest["extensions"]["com.openai"]["interface"]
            self.assertEqual(interface["capabilities"], ["Interactive"])
            self.assertLessEqual(len(interface["shortDescription"]), 30)
            server = mcp["mcpServers"]["guardkit"]
            self.assertEqual(server["args"], ["-I", "${PLUGIN_ROOT}/server.py", "--root", str(project.resolve())])
            runtime = output / "runtime"
            self.assertTrue((runtime / "guardkit" / "cli.py").is_file())
            self.assertTrue((runtime / "guardkit" / "ui" / "safe_input.html").is_file())
            self.assertTrue((runtime / "guardkit" / "rules" / "backend.yml").is_file())
            self.assertFalse(any(path.suffix in (".pyc", ".json") for path in runtime.rglob("*")))
            request = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
            process = subprocess.run(
                [sys.executable, "-I", str(output / "server.py"), "--root", str(project)],
                input=json.dumps(request) + "\n", text=True, capture_output=True, timeout=10,
                cwd=project,
            )
            self.assertEqual(process.returncode, 0, process.stderr)
            tools = json.loads(process.stdout.splitlines()[0])["result"]["tools"]
            self.assertIn("open_safe_input", {tool["name"] for tool in tools})

    def test_refuses_existing_output_without_modifying_it(self):
        with tempfile.TemporaryDirectory() as temp:
            project = Path(temp) / "project"
            project.mkdir()
            output = Path(temp) / "plugin"
            output.mkdir()
            marker = output / "keep"
            marker.write_text("untouched")
            with self.assertRaises(FileExistsError):
                build(project, output)
            self.assertEqual(marker.read_text(), "untouched")

    def test_manifest_preserves_venv_interpreter_symlink(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            project = base / "project"
            project.mkdir()
            venv_python = base / "venv" / "bin" / "python"
            venv_python.parent.mkdir(parents=True)
            venv_python.symlink_to(Path(sys.executable))
            output = base / "plugin"
            with patch("guardkit.plugin.sys.executable", str(venv_python)):
                result = build(project, output)
            self.assertEqual(result["mcp"]["mcpServers"]["guardkit"]["command"], str(venv_python))

    def test_cleans_temporary_package_after_failure(self):
        with tempfile.TemporaryDirectory() as temp:
            project = Path(temp) / "project"
            project.mkdir()
            # An unusable parent fails before publication and leaves no output.
            obstruction = Path(temp) / "file"
            obstruction.write_text("x")
            output = obstruction / "child"
            with self.assertRaises((OSError, ValueError)):
                build(project, output)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
