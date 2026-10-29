"""Security and interaction tests for the agent-triggered local input TUI."""
import errno
import json
import os
import select
import time
import unittest
from unittest.mock import patch

try:
    import fcntl
    import pty
    import struct
    import termios
except ImportError:  # Windows: keep the form tests importable.
    fcntl = pty = struct = termios = None

from guardkit import safe_input
from guardkit.secrets import SecretError


class FormTests(unittest.TestCase):
    def test_login_payload_is_local_and_repr_never_discloses_values(self):
        form = safe_input._Form("login")
        form.values[:] = ["name-sentinel-73", "password-sentinel-91"]
        representation = repr(form)
        self.assertNotIn("name-sentinel-73", representation)
        self.assertNotIn("password-sentinel-91", representation)
        self.assertEqual(json.loads(form.payload()), {
            "username": "name-sentinel-73", "password": "password-sentinel-91"})
        self.assertNotIn("name-sentinel-73", repr(form))
        self.assertNotIn("password-sentinel-91", repr(form))

    def test_token_payload_and_limits(self):
        form = safe_input._Form("token")
        form.values[0] = "token-sentinel-42"
        self.assertEqual(form.payload(), "token-sentinel-42")
        form.values[0] = "x" * (safe_input.MAX_BYTES + 1)
        with self.assertRaises(SecretError):
            form.payload()


@unittest.skipUnless(os.name == "posix" and termios is not None,
                     "POSIX terminal APIs are required")
class RequestIsolationTests(unittest.TestCase):
    def test_bad_arguments_are_rejected_before_opening_terminal(self):
        with patch("builtins.open", side_effect=AssertionError("terminal touched")):
            for args in (("../bad", "token", None), ("good", "password", None),
                         ("good", "login", "")):
                with self.subTest(args=args), self.assertRaises(SecretError):
                    safe_input.request(*args)

    def test_no_controlling_terminal_has_metadata_only_result(self):
        with patch("guardkit.safe_input.os.name", "posix"), \
                patch("builtins.open", side_effect=OSError(errno.ENXIO, "no tty")):
            result = safe_input.request("service", "token")
        self.assertEqual(result, {"credential_ref": "service", "kind": "token",
                                  "status": "unavailable", "error_code": "terminal_unavailable"})
        self.assertNotIn("stdin", repr(result))

    def _fake_terminal(self):
        class Terminal:
            def __init__(self):
                self.bytes = bytearray()
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def fileno(self): return 101
            def write(self, data): self.bytes.extend(data)
        return Terminal()

    def test_child_streams_are_the_same_tty_and_only_exit_status_returns(self):
        tty = self._fake_terminal()
        old = [0, 0, 0, 0, 0, 0, []]
        with patch("guardkit.safe_input.os.name", "posix"), \
                patch("builtins.open", return_value=tty), \
                patch("termios.tcgetattr", return_value=old), \
                patch("termios.tcflush"), \
                patch("termios.tcsetattr") as restore, \
                patch("subprocess.run", return_value=type("R", (), {"returncode": 0})()) as run:
            result = safe_input.request("mail", "login", "Mail")
        kwargs = run.call_args.kwargs
        self.assertIs(kwargs["stdin"], tty)
        self.assertIs(kwargs["stdout"], tty)
        self.assertIs(kwargs["stderr"], tty)
        self.assertEqual(kwargs["timeout"], safe_input._TIMEOUT + 5)
        self.assertEqual(result, {"credential_ref": "mail", "kind": "login", "status": "stored"})
        self.assertEqual(restore.call_args_list[-1].args, (101, termios.TCSANOW, old))
        self.assertTrue(tty.bytes)
        # Credentials are not arguments, environment entries, or a captured pipe.
        self.assertNotIn("stdin", repr(run.call_args.args[0]))
        self.assertNotIn("secret", repr(result).lower())

    def test_timeout_restores_terminal_and_returns_fixed_status(self):
        tty = self._fake_terminal()
        old = [0, 0, 0, 0, 0, 0, []]
        with patch("guardkit.safe_input.os.name", "posix"), \
                patch("builtins.open", return_value=tty), \
                patch("termios.tcgetattr", return_value=old), \
                patch("termios.tcflush"), \
                patch("termios.tcsetattr") as restore, \
                patch("subprocess.run", side_effect=__import__("subprocess").TimeoutExpired("worker", 305)):
            result = safe_input.request("mail", "token")
        self.assertEqual(result["status"], "expired")
        self.assertEqual(restore.call_args_list[-1].args, (101, termios.TCSANOW, old))
        self.assertIn(b"\x1b[?1049l", tty.bytes)

    def test_worker_does_not_print_secret_bearing_exception(self):
        sentinel = "exception-secret-28"
        with patch("guardkit.safe_input._validate", side_effect=RuntimeError(sentinel)):
            self.assertEqual(safe_input.worker_main(["x", "token", "x"]), 5)


def _pty_worker(kind, expected):
    """Drive the real curses worker in a forked controlling-terminal session."""
    if os.name != "posix" or pty is None:
        raise unittest.SkipTest("POSIX pty is required")
    try:
        import curses  # noqa: F401
    except ImportError:
        raise unittest.SkipTest("curses is unavailable")

    pid, fd = pty.fork()
    if pid == 0:
        os.environ["TERM"] = "xterm-256color"
        fcntl.ioctl(0, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
        # This child-only fake keeps the submitted value in memory; it never
        # contacts a real OS keychain or secret service.
        class MemoryStore:
            def __init__(self): pass
            @staticmethod
            def _service(name): return name

        def fake_put(store, name, value):
            assert name == "pty-test"
            assert value == expected

        safe_input.SecretStore = MemoryStore
        safe_input.put_from_tui = fake_put
        try:
            code = safe_input.worker_main(["pty-test", kind, "Test service"])
        except BaseException as exc:
            os.write(2, b"child failure\\n")
            code = 99
        os._exit(code)

    # Set a deterministic, sufficiently large terminal before curses starts.
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
    transcript = bytearray()
    sent = False
    deadline = time.monotonic() + 12
    expected_screen = b"Username / email" if kind == "login" else b"Token / API key"
    sequence = (b"user-sentinel-33\tpass-sentinel-66\x13" if kind == "login"
                else b"token-sentinel-57\x13")
    while time.monotonic() < deadline:
        ready, _, _ = select.select([fd], [], [], .2)
        if ready:
            try:
                data = os.read(fd, 8192)
            except OSError:
                data = b""
            if not data:
                finished, status = os.waitpid(pid, 0)
                os.close(fd)
                return os.waitstatus_to_exitcode(status), bytes(transcript), sent
            transcript.extend(data)
            if not sent and expected_screen in transcript:
                os.write(fd, sequence)
                sent = True
        finished, status = os.waitpid(pid, os.WNOHANG)
        if finished:
            os.close(fd)
            return os.waitstatus_to_exitcode(status), bytes(transcript), sent
    try:
        os.kill(pid, 9)
    except ProcessLookupError:
        pass
    os.waitpid(pid, 0)
    os.close(fd)
    raise AssertionError("TUI worker did not finish")


class CursesPtyTests(unittest.TestCase):
    def test_token_value_is_masked_and_saved_only_inside_worker(self):
        code, transcript, sent = _pty_worker("token", "token-sentinel-57")
        self.assertEqual(code, 0)
        self.assertTrue(sent, "worker never rendered the token prompt")
        self.assertNotIn(b"token-sentinel-57", transcript)

    def test_login_fields_are_masked_and_saved_only_inside_worker(self):
        expected = json.dumps({"username": "user-sentinel-33", "password": "pass-sentinel-66"},
                              ensure_ascii=False)
        code, transcript, sent = _pty_worker("login", expected)
        self.assertEqual(code, 0)
        self.assertTrue(sent, "worker never rendered the login prompt")
        self.assertEqual(code, 0)
        self.assertNotIn(b"user-sentinel-33", transcript)
        self.assertNotIn(b"pass-sentinel-66", transcript)

    def test_token_is_masked_and_cancel_exits_cleanly(self):
        # A separate interaction drives cancellation before any store call.
        if os.name != "posix" or pty is None:
            self.skipTest("POSIX pty is required")
        try:
            import curses  # noqa: F401
        except ImportError:
            self.skipTest("curses is unavailable")
        pid, fd = pty.fork()
        if pid == 0:
            os.environ["TERM"] = "xterm-256color"
            fcntl.ioctl(0, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
            class MemoryStore:
                @staticmethod
                def _service(name): return name
                def __init__(self): pass
            safe_input.SecretStore = MemoryStore
            try:
                code = safe_input.worker_main(["pty-test", "token", "Test service"])
            except BaseException as exc:
                os.write(2, b"child failure\\n")
                code = 99
            os._exit(code)
        def close_master():
            try:
                os.close(fd)
            except OSError:
                pass
        self.addCleanup(close_master)
        fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
        transcript = bytearray()
        sent = False
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            ready, _, _ = select.select([fd], [], [], .2)
            if ready:
                try: data = os.read(fd, 8192)
                except OSError: data = b""
                if not data:
                    _, status = os.waitpid(pid, 0)
                    self.assertTrue(sent)
                    self.assertEqual(os.waitstatus_to_exitcode(status), 3)
                    self.assertNotIn(b"cancel-sentinel-14", transcript)
                    os.close(fd)
                    return
                transcript.extend(data)
                if not sent and b"Token / API key" in transcript:
                    os.write(fd, b"cancel-sentinel-14\x1b")
                    sent = True
            finished, status = os.waitpid(pid, os.WNOHANG)
            if finished:
                self.assertTrue(sent)
                self.assertEqual(os.waitstatus_to_exitcode(status), 3)
                self.assertNotIn(b"cancel-sentinel-14", transcript)
                os.close(fd)
                return
        try: os.kill(pid, 9)
        except ProcessLookupError: pass
        os.waitpid(pid, 0)
        os.close(fd)
        self.fail("cancel TUI worker did not finish")


if __name__ == "__main__":
    unittest.main()
