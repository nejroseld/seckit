"""Bridged form: CLI without a terminal, user joins from a separate pty."""
import _isolate  # noqa: F401
import json
import os
from pathlib import Path
import pty
import select
import subprocess
import sys
import tempfile
import time
import unittest


@unittest.skipUnless(sys.platform.startswith("linux"), "requires Linux; no native keystore is accessed")
class SafeInputBridgeTests(unittest.TestCase):
    def test_attach_completes_headless_request(self):
        source = str(Path(__file__).resolve().parents[1])
        with tempfile.TemporaryDirectory(prefix="guardkit-bridge-") as tmp:
            fixture = Path(tmp)
            marker = fixture / "stored.marker"
            tool = fixture / "secret-tool"
            tool.write_text("#!" + sys.executable + "\nimport sys\nfrom pathlib import Path\n"
                            "assert sys.stdin.buffer.read() == b'synthetic-bridge-token-17'\n"
                            "Path(" + repr(str(marker)) + ").write_text('stored')\n")
            tool.chmod(0o700)
            env = {**os.environ, "PATH": str(fixture) + os.pathsep + os.environ["PATH"]}
            bootstrap = ("import sys; sys.path.insert(0, " + repr(source)
                         + "); from guardkit.cli import main; raise SystemExit(main(sys.argv[1:]))")
            cli = subprocess.Popen([sys.executable, "-I", "-c", bootstrap, "secrets", "input", "bridge-test"],
                                   stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   env=env, start_new_session=True)
            try:
                hint = b""
                while hint.count(b"\n") < 2 and cli.poll() is None:
                    hint += os.read(cli.stderr.fileno(), 4096)
                command = hint.decode().splitlines()[-1].strip()
                self.assertIn("secrets attach", command)
                pid, master = pty.fork()
                if pid == 0:
                    os.execvpe("/bin/sh", ["sh", "-c", command], env)
                transcript = bytearray()
                sent = False
                deadline = time.monotonic() + 20
                while time.monotonic() < deadline:
                    if select.select([master], [], [], 0.1)[0]:
                        try:
                            chunk = os.read(master, 16384)
                        except OSError:
                            break
                        if not chunk:
                            break
                        transcript.extend(chunk)
                        if not sent and b"Token / API key" in transcript:
                            os.write(master, b"synthetic-bridge-token-17\x13")
                            sent = True
                os.waitpid(pid, 0)
                os.close(master)
                self.assertTrue(sent, "the form did not render")
                self.assertNotIn(b"synthetic-bridge-token-17", transcript)
                out, _ = cli.communicate(timeout=10)
                self.assertEqual(json.loads(out), {"credential_ref": "bridge-test", "kind": "token", "status": "stored"})
                self.assertEqual(marker.read_text(), "stored")
            finally:
                if cli.poll() is None:
                    cli.kill()
                    cli.wait()


if __name__ == "__main__":
    unittest.main()


class StoreMainTests(unittest.TestCase):
    def test_rejects_bad_login_and_name_without_echo(self):
        source = str(Path(__file__).resolve().parents[1])
        code = ("import sys; sys.path.insert(0, " + repr(source) + "); from guardkit.safe_input import store_main; "
                "raise SystemExit(store_main(sys.argv[1:]))")
        for args, data in ((["ok-name", "login"], '{"username": "u"}'), (["bad name!", "token"], "x"), (["ok-name", "token"], "")):
            done = subprocess.run([sys.executable, "-I", "-c", code, *args], input=data, capture_output=True, text=True)
            self.assertEqual(done.returncode, 5)
            self.assertEqual(done.stdout + done.stderr, "")
