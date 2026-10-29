"""Agent-triggered TUI enrollment; credentials never travel over tool stdio."""
from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
import time
from pathlib import Path

from .secrets import SecretError, SecretStore
from .native_store import put_from_tui

MAX_BYTES = 65536
_TIMEOUT = 300
_EXIT = {0: "stored", 3: "cancelled", 4: "unavailable", 5: "failed", 6: "expired"}


def _validate(name: str, kind: str, service: str) -> None:
    if not isinstance(name, str):
        raise SecretError("Invalid secret name")
    SecretStore._service(name)
    if not isinstance(kind, str) or kind not in {"token", "login"}:
        raise SecretError("Input kind must be token or login")
    if not isinstance(service, str) or not 1 <= len(service) <= 128 or not all(c.isprintable() for c in service):
        raise SecretError("Service must be a short printable label")


def request(name: str, kind: str = "token", service: str | None = None) -> dict:
    """Open a masked TUI on the controlling terminal and return metadata only.

    Tool stdin is never read. The worker's three streams go directly to the TTY;
    its only result channel is a fixed exit code. Restore terminal state even if
    the worker is interrupted or killed after the bounded input deadline.
    """
    service = name if service is None else service
    _validate(name, kind, service)
    result = {"credential_ref": name, "kind": kind}
    if os.name != "posix":
        return {**result, "status": "unavailable", "error_code": "terminal_unavailable"}
    import termios
    try:
        terminal = open("/dev/tty", "r+b", buffering=0)
    except OSError:
        return {**result, "status": "unavailable", "error_code": "terminal_unavailable"}
    with terminal:
        try:
            state = termios.tcgetattr(terminal.fileno())
        except termios.error:
            return {**result, "status": "unavailable", "error_code": "terminal_unavailable"}
        # Pin trusted installed/source code, ignoring modules in the inspected repo.
        bootstrap = ("import sys; sys.path.insert(0, " + repr(str(Path(__file__).resolve().parent.parent))
                     + "); from guardkit.safe_input import worker_main; raise SystemExit(worker_main(sys.argv[1:]))")
        command = [sys.executable, "-I", "-c", bootstrap, name, kind, service]
        try:
            masked_state = state.copy()
            masked_state[3] &= ~(termios.ECHO | termios.ECHONL)
            termios.tcsetattr(terminal.fileno(), termios.TCSANOW, masked_state)
            process = subprocess.run(command, stdin=terminal, stdout=terminal, stderr=terminal,
                                     timeout=_TIMEOUT + 5, check=False)
            status = _EXIT.get(process.returncode, "failed")
        except subprocess.TimeoutExpired:
            status = "expired"
        except (KeyboardInterrupt, EOFError):
            status = "cancelled"
        except OSError:
            status = "unavailable"
        finally:
            try:
                termios.tcflush(terminal.fileno(), termios.TCIFLUSH)
                termios.tcsetattr(terminal.fileno(), termios.TCSANOW, state)
                # Recover from a worker killed while in curses' alternate screen.
                terminal.write(b"\x1b[?2004l\x1b[?25h\x1b[?1049l")
            except (termios.error, OSError):
                status = "failed"
        return {**result, "status": status}


def _worker_command(name: str, kind: str, service: str) -> list[str]:
    bootstrap = ("import sys; sys.path.insert(0, " + repr(str(Path(__file__).resolve().parent.parent))
                 + "); from guardkit.safe_input import worker_main; raise SystemExit(worker_main(sys.argv[1:]))")
    return [sys.executable, "-I", "-c", bootstrap, name, kind, service]


def attach_command(socket_path: str) -> str:
    root = str(Path(__file__).resolve().parent.parent)
    return f"PYTHONPATH={shlex.quote(root)} {shlex.quote(sys.executable)} -m guardkit secrets attach {shlex.quote(socket_path)}"


def request_bridged(name: str, kind: str = "token", service: str | None = None, announce=None) -> dict:
    """Run the masked TUI on a private pty that the user joins from another terminal.

    For sessions with no controlling terminal (agent shells, headless runs). The
    pty is relayed over a 0700 unix socket reachable only by the same user, so
    keystrokes never pass through tool stdio or the chat.
    """
    service = name if service is None else service
    _validate(name, kind, service)
    result = {"credential_ref": name, "kind": kind}
    if os.name != "posix":
        return {**result, "status": "unavailable", "error_code": "terminal_unavailable"}
    import pty
    import fcntl
    import select
    import shutil
    import socket
    import struct
    import tempfile
    import termios
    directory = tempfile.mkdtemp(prefix="guardkit-input-")
    path = os.path.join(directory, "s")
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    conn = process = None
    master = slave = -1
    try:
        server.bind(path)
        server.listen(1)
        if announce:
            announce(attach_command(path))
        deadline = time.monotonic() + _TIMEOUT
        server.settimeout(_TIMEOUT)
        try:
            conn, _ = server.accept()
        except socket.timeout:
            return {**result, "status": "expired"}
        uid = struct.unpack("3i", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))[1]
        if uid != os.getuid():
            return {**result, "status": "failed"}
        header = b""
        while not header.endswith(b"\n") and len(header) < 32:
            chunk = conn.recv(1)
            if not chunk:
                return {**result, "status": "cancelled"}
            header += chunk
        try:
            rows, cols = (int(v) for v in header.split())
        except ValueError:
            rows, cols = 24, 80
        master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
        env = {k: v for k, v in os.environ.items()
               if k in {"PATH", "HOME", "LANG", "LC_ALL", "DBUS_SESSION_BUS_ADDRESS", "XDG_RUNTIME_DIR",
                                "XDG_CONFIG_HOME", "GUARDKIT_HOME"}}
        env["TERM"] = "xterm-256color"
        process = subprocess.Popen(_worker_command(name, kind, service), stdin=slave, stdout=slave, stderr=slave,
                                   env=env, start_new_session=True)
        os.close(slave)
        slave = -1
        while process.poll() is None and time.monotonic() < deadline + 5:
            ready = select.select([master, conn], [], [], 0.2)[0]
            if master in ready:
                try:
                    data = os.read(master, 16384)
                except OSError:
                    data = b""
                if data:
                    conn.sendall(data)
            if conn in ready:
                data = conn.recv(16384)
                if not data:
                    process.kill()
                    break
                os.write(master, data)
        if process.poll() is None:
            process.kill()
            process.wait()
            status = "expired" if time.monotonic() >= deadline else "cancelled"
        else:
            status = _EXIT.get(process.returncode, "failed")
        try:
            conn.sendall(b"\x1b[?2004l\x1b[?25h\x1b[?1049l")
        except OSError:
            pass
        return {**result, "status": status}
    except OSError:
        return {**result, "status": "unavailable", "error_code": "terminal_unavailable"}
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait()
        for fd in (master, slave):
            if fd >= 0:
                os.close(fd)
        for sock in (conn, server):
            if sock is not None:
                sock.close()
        shutil.rmtree(directory, ignore_errors=True)


def attach(socket_path: str) -> int:
    """Join a bridged form from the user's own terminal."""
    import select
    import socket
    import termios
    import tty
    if not sys.stdin.isatty():
        print("attach needs an interactive terminal", file=sys.stderr)
        return 2
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.connect(socket_path)
    except OSError:
        print("no pending input request at this path", file=sys.stderr)
        return 2
    size = os.get_terminal_size(sys.stdin.fileno())
    sock.sendall(f"{size.lines} {size.columns}\n".encode())
    fd = sys.stdin.fileno()
    saved = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        while True:
            ready = select.select([fd, sock], [], [])[0]
            if sock in ready:
                data = sock.recv(16384)
                if not data:
                    break
                os.write(sys.stdout.fileno(), data)
            if fd in ready:
                data = os.read(fd, 1024)
                if not data:
                    break
                sock.sendall(data)
    except OSError:
        pass
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, saved)
        sock.close()
    print("\nDone. The agent has the result.")
    return 0


class _Form:
    """Local-only editing state. No representation includes entered data."""
    def __init__(self, kind: str):
        self.kind = kind
        self.labels = ["Token / API key"] if kind == "token" else ["Username / email", "Password"]
        self.values = [""] * len(self.labels)
        self.focus = 0
        self.error = ""

    def clear(self) -> None:
        self.values[:] = [""] * len(self.labels)

    def payload(self) -> str:
        if not all(self.values):
            raise SecretError("Fill in every field before saving.")
        value = self.values[0] if self.kind == "token" else json.dumps(
            {"username": self.values[0], "password": self.values[1]}, ensure_ascii=False)
        if len(value.encode("utf-8")) > MAX_BYTES:
            raise SecretError("The credential is too large (maximum 64 KiB).")
        return value


def _draw(screen, form: _Form, name: str, service: str, curses) -> None:
    screen.erase()
    height, width = screen.getmaxyx()
    def line(row, value, style=0):
        if 0 <= row < height - 1 and width > 2:
            try:
                screen.addnstr(row, 2, value, width - 3, style)
            except curses.error:
                pass
    if height < 17 or width < 48:
        line(0, "Enlarge terminal to 48 x 17. Esc cancels.")
        screen.refresh()
        return
    line(1, "Guardkit | Safe input", curses.A_BOLD)
    line(3, "Agent requested credentials for: " + service)
    line(4, "Store reference: " + name)
    line(6, "All fields stay masked, including the username.")
    for index, label in enumerate(form.labels):
        row = 8 + index * 2
        line(row, ("> " if index == form.focus else "  ") + label,
             curses.A_BOLD if index == form.focus else 0)
        masked = "*" * min(len(form.values[index]), max(1, width - 10))
        line(row + 1, "  [" + masked + "_" + "]")
    line(13, form.error or "Save / replace in the OS secret store. No login is sent.")
    line(14, "Ctrl+S Save   Esc Cancel   Tab Next   Ctrl+U Clear")
    line(15, "Only status and reference return to the agent.")
    screen.refresh()


def _interact(screen, name: str, kind: str, service: str, curses) -> int:
    form = _Form(kind)
    deadline = time.monotonic() + _TIMEOUT
    screen.keypad(True)
    screen.timeout(250)
    curses.noecho()
    curses.raw()  # Ctrl+S is a save action, not terminal flow control.
    curses.curs_set(0)
    try:
        store = SecretStore()
        while time.monotonic() < deadline:
            _draw(screen, form, name, service, curses)
            try:
                key = screen.get_wch()
            except curses.error:
                continue
            if key in ("\x1b", "\x03"):
                return 3
            if key == "\x13":
                if screen.getmaxyx()[0] < 17 or screen.getmaxyx()[1] < 48:
                    continue
                try:
                    value = form.payload()
                    put_from_tui(store, name, value)
                    value = ""
                    return 0
                except SecretError:
                    # Native errors and validation must never echo entered data.
                    form.error = "Could not save. Fill all fields and check the OS secret store."
                finally:
                    value = ""
            elif key in ("\t", "\n", "\r", curses.KEY_DOWN):
                form.focus = (form.focus + 1) % len(form.values)
            elif key in (curses.KEY_UP, curses.KEY_BTAB):
                form.focus = (form.focus - 1) % len(form.values)
            elif key == "\x15":
                form.values[form.focus] = ""
            elif key in (curses.KEY_BACKSPACE, "\x7f", "\b"):
                form.values[form.focus] = form.values[form.focus][:-1]
            elif isinstance(key, str) and key.isprintable():
                if len(form.values[form.focus].encode("utf-8")) + len(key.encode("utf-8")) <= MAX_BYTES:
                    form.values[form.focus] += key
        return 6
    finally:
        form.clear()
        curses.flushinp()
        screen.erase()
        screen.refresh()


def store_main(args: list[str]) -> int:
    """Store one credential read from stdin for a trusted pane; fixed exit codes only."""
    try:
        name, kind = args
        _validate(name, kind, name)
        value = sys.stdin.read()
        if kind == "login":
            fields = json.loads(value)
            if not isinstance(fields, dict) or not fields.get("username") or not fields.get("password"):
                return 5
        elif not value:
            return 5
        put_from_tui(SecretStore(), name, value)
        return 0
    except (OSError, ValueError, SecretError):
        return 5
    finally:
        value = ""


def worker_main(args: list[str]) -> int:
    """Trusted local UI worker: fixed codes, no credential-bearing exceptions."""
    try:
        name, kind, service = args
        _validate(name, kind, service)
        import curses
        return curses.wrapper(lambda screen: _interact(screen, name, kind, service, curses))
    except (KeyboardInterrupt, EOFError):
        return 3
    except (ImportError, OSError):
        return 4
    except Exception:
        return 5
