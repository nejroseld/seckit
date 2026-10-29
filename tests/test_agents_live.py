"""Opt-in end-to-end test that launches an authenticated Codex MCP session.

Run with GUARDKIT_LIVE_CODEX=1 after GuardKit scanners and their databases are
available. It uses a throwaway fixture project and does not read the real repo.
"""
from __future__ import annotations
import _isolate  # noqa: F401

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from guardkit.provision import SEMGREP, TRIVY, cache_dir


def _live_ready() -> bool:
    base = cache_dir()
    trivy = base / f"trivy-{TRIVY}" / "trivy"
    semgrep = base / f"semgrep-{SEMGREP}" / "bin" / "semgrep"
    return (os.environ.get("GUARDKIT_LIVE_CODEX") == "1" and shutil.which("codex") is not None
            and trivy.is_file() and semgrep.is_file())


@unittest.skipUnless(_live_ready(), "set GUARDKIT_LIVE_CODEX=1 and install both GuardKit scanners to run the live Codex test")
class LiveCodexMCPTests(unittest.TestCase):
    def test_codex_calls_guardkit_scan_findings_and_safe_fix_tools(self):
        with tempfile.TemporaryDirectory(prefix="guardkit-codex-live-") as temporary:
            root = Path(temporary).resolve()
            source_root = Path(__file__).resolve().parents[1]
            (root / "compose.yaml").write_text(
                "services:\n  app:\n    image: alpine:3.20\n    privileged: true\n",
                encoding="utf-8",
            )
            (root / "Dockerfile").write_text("FROM alpine:3.20\nUSER root\nCMD [\"true\"]\n", encoding="utf-8")

            prompt = (
                "Use only the configured GuardKit MCP server. Call its scan, findings, and "
                "propose_safe_fixes tools in that order. Do not use shell, inspect files, or edit anything. "
                "Return exactly one short line starting with E2E_OK and report success or failure for each "
                "tool, the number of findings, the number of proposed fixes, and that no edits were made. "
                "Do not include finding details or file contents."
            )
            bootstrap = (
                f"import sys; sys.path.insert(0,{json.dumps(str(source_root))}); "
                f"from guardkit.cli import main; raise SystemExit(main(['mcp','--root',{json.dumps(str(root))}]))"
            )
            command = [
                shutil.which("codex") or "codex", "exec",
                "--ignore-user-config", "--ephemeral", "--skip-git-repo-check",
                "--sandbox", "read-only", "--json", "--cd", str(root),
                "-c", f"mcp_servers.guardkit.command={json.dumps(sys.executable)}",
                "-c", f"mcp_servers.guardkit.args={json.dumps(['-I', '-c', bootstrap])}",
                prompt,
            ]
            completed = subprocess.run(command, cwd=root, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=240, check=False)
            events = [json.loads(line) for line in completed.stdout.splitlines() if line.strip()]
            failure_types = [event.get("type", "unknown") for event in events
                             if "error" in event or event.get("type") in {"error", "turn.failed"}]
            self.assertEqual(completed.returncode, 0,
                             f"Codex exited {completed.returncode}; error event types: {failure_types}")
            event_text = "\n".join(json.dumps(event, ensure_ascii=True) for event in events)
            mcp_events = [json.dumps(event, ensure_ascii=True, separators=(",", ":")) for event in events
                          if "mcp_tool_call" in json.dumps(event)]
            self.assertTrue(mcp_events, event_text[-3000:])
            for tool_name in ("scan", "findings", "propose_safe_fixes"):
                self.assertTrue(any('"server":"guardkit"' in event and f'"tool":"{tool_name}"' in event
                                    for event in mcp_events), event_text[-3000:])
            self.assertTrue(any(event.get("type") == "turn.completed" for event in events), event_text[-3000:])
            self.assertIn("E2E_OK", event_text)
            self.assertTrue((root / "compose.yaml").read_text(encoding="utf-8").endswith("privileged: true\n"))
            self.assertEqual((root / "Dockerfile").read_text(encoding="utf-8"), "FROM alpine:3.20\nUSER root\nCMD [\"true\"]\n")


if __name__ == "__main__":
    unittest.main()
