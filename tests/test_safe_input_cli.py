"""Full CLI/worker/TTY boundary using a disposable synthetic native-store stub."""
import _isolate  # noqa: F401
import importlib.util
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import tempfile
import time
import unittest

try:
    import fcntl
    import pty
    import struct
    import termios
except ImportError:
    pty = None


@unittest.skipUnless(sys.platform.startswith("linux") and pty is not None
                     and importlib.util.find_spec("curses") is not None,
                     "requires Linux and curses; no native keystore is accessed")
class SafeInputCLITests(unittest.TestCase):
    def test_real_cli_child_returns_metadata_and_discards_store_output(self):
        sentinel = b"synthetic-cli-token-91"
        source = str(Path(__file__).resolve().parents[1])
        with tempfile.TemporaryDirectory(prefix="guardkit-tui-cli-") as tmp:
            fixture = Path(tmp)
            marker = fixture / "stored.marker"
            tool = fixture / "secret-tool"
            tool.write_text("#!" + sys.executable + "\nimport os,sys\nfrom pathlib import Path\n"
                            "value=sys.stdin.buffer.read()\n"
                            "assert value == b'synthetic-cli-token-91'\n"
                            "os.write(1,value); os.write(2,value)\n"
                            "Path(" + repr(str(marker)) + ").write_text('stored')\n")
            tool.chmod(0o700)
            (fixture / "guardkit.py").write_text("raise RuntimeError('repository module executed')\n")
            bootstrap = ("import sys; sys.path.insert(0, " + repr(source)
                         + "); from guardkit.cli import main; raise SystemExit(main(sys.argv[1:]))")
            pid, master = pty.fork()
            if pid == 0:
                try:
                    os.environ["TERM"] = "xterm-256color"
                    os.environ["PATH"] = str(fixture) + os.pathsep + os.environ.get("PATH", "")
                    fcntl.ioctl(0, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
                    process = subprocess.run([sys.executable, "-I", "-c", bootstrap,
                                              "secrets", "input", "cli-test", "--service", "Test service"],
                                             cwd=fixture, capture_output=True, timeout=15)
                    assert process.returncode == 0
                    assert json.loads(process.stdout) == {"credential_ref": "cli-test", "kind": "token", "status": "stored"}
                    assert sentinel not in process.stdout + process.stderr
                    os._exit(0)
                except BaseException:
                    os._exit(99)
            transcript = bytearray()
            sent = False
            child_status = None
            try:
                deadline = time.monotonic() + 20
                while time.monotonic() < deadline:
                    if select.select([master], [], [], 0.1)[0]:
                        try:
                            chunk = os.read(master, 16384)
                        except OSError:
                            chunk = b""
                        transcript.extend(chunk)
                        if not sent and b"Token / API key" in transcript:
                            os.write(master, sentinel + b"\x13")
                            sent = True
                    finished, status = os.waitpid(pid, os.WNOHANG)
                    if finished:
                        child_status = status
                        break
                self.assertTrue(sent, "the TUI did not render")
                self.assertIsNotNone(child_status, "the CLI did not complete")
                self.assertEqual(os.waitstatus_to_exitcode(child_status), 0, "CLI/worker boundary failed")
                self.assertNotIn(sentinel, transcript, "credential appeared in the terminal transcript")
                self.assertEqual(marker.read_text(), "stored")
            finally:
                if child_status is None:
                    try:
                        os.kill(pid, 9)
                    except ProcessLookupError:
                        pass
                    os.waitpid(pid, 0)
                os.close(master)
