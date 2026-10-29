"""Agent/CLI boundaries expose enrollment metadata, never credential fields."""
import _isolate  # noqa: F401
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from guardkit import agents
from guardkit.secrets import secrets_main


class SafeInputIntegrationTests(unittest.TestCase):
    def test_mcp_opens_tui_without_scanning_or_accepting_values(self):
        result = {"status": "stored", "credential_ref": "github", "kind": "login"}
        calls = [
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
                "name": "open_safe_input", "arguments": {"name": "github", "kind": "login", "service": "github.com"}}},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {
                "name": "open_safe_input", "arguments": {"name": "github", "value": "SENTINEL-DO-NOT-ECHO"}}},
        ]
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as root, patch("guardkit.safe_input.request", return_value=result) as request, \
                patch("sys.stdin", io.StringIO("\n".join(map(json.dumps, calls)))), redirect_stdout(output):
            agents.serve(Path(root), lambda _: self.fail("must not scan for credential input"))
        responses = [json.loads(line) for line in output.getvalue().splitlines()]
        tool = next(item for item in responses[0]["result"]["tools"] if item["name"] == "open_safe_input")
        self.assertFalse(tool["inputSchema"]["additionalProperties"])
        self.assertEqual(set(tool["inputSchema"]["properties"]), {"name", "kind", "service"})
        self.assertEqual(responses[1]["result"]["structuredContent"], result)
        self.assertEqual(responses[2]["error"]["code"], -32602)
        self.assertNotIn("SENTINEL", output.getvalue())
        request.assert_called_once_with("github", "login", "github.com")

    def test_mcp_handles_headless_and_missing_metadata(self):
        calls = [{"jsonrpc": "2.0", "id": i, "method": "tools/call", "params": {
            "name": "open_safe_input", "arguments": arguments}} for i, arguments in enumerate(
                ({"name": "github"}, {}, {"name": "github", "kind": []}), 1)]
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as root, patch("guardkit.safe_input.open", side_effect=OSError), \
                patch("sys.stdin", io.StringIO("\n".join(map(json.dumps, calls)))), redirect_stdout(output):
            agents.serve(Path(root), lambda _: self.fail("must not scan"))
        responses = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertTrue(responses[0]["result"]["isError"])
        self.assertEqual(responses[0]["result"]["structuredContent"]["status"], "unavailable")
        self.assertTrue(all(item["error"]["code"] == -32602 for item in responses[1:]))

    def test_cli_returns_only_status_and_ref_without_initializing_parent_store(self):
        for status, code in (("stored", 0), ("cancelled", 130), ("unavailable", 2), ("expired", 2)):
            with self.subTest(status=status):
                result = {"status": status, "credential_ref": "github", "kind": "login"}
                output = io.StringIO()
                with patch("guardkit.safe_input.request", return_value=result) as request, \
                        patch("guardkit.secrets.SecretStore", side_effect=AssertionError("parent must not read store")), \
                        redirect_stdout(output):
                    actual = secrets_main(["input", "github", "--kind", "login", "--service", "github.com"])
                self.assertEqual(actual, code)
                self.assertEqual(json.loads(output.getvalue()), result)
                request.assert_called_once_with("github", "login", "github.com")

    def test_installed_agent_guidance_directs_values_to_tui_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            agents.install(Path(tmp))
            text = (Path(tmp) / "AGENTS.md").read_text()
        self.assertIn("open_safe_input", text)
        self.assertIn("secrets input NAME", text)
        self.assertIn("never fall back to tool stdin", text)
