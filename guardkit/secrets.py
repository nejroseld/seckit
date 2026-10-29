"""Small, stdlib-only bridge to the operating system's existing secret store.

This module intentionally has no API that returns a credential to an agent-facing
caller. The broker can use a stored credential for one pre-approved HTTPS request
and returns response metadata only.
"""
from __future__ import annotations

import getpass
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Callable, Mapping



SERVICE_PREFIX = "guardkit.secret."
MAX_TTL_SECONDS = 3600
_NAME = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$")


class SecretError(Exception):
    """Safe-to-display failure; messages must never contain secret data."""


class SecretStore:
    """Adapter for macOS Keychain or Linux Secret Service via native CLI tools."""

    def __init__(self, system: str | None = None, runner: Callable = subprocess.run, vault=None):
        self.system = system or platform.system()
        self.runner = runner
        self.tool = "security" if self.system == "Darwin" else "secret-tool" if self.system == "Linux" else None
        if vault is None and os.name == "posix":
            from .vault import FileVault
            vault = FileVault()
        self.vault = vault
        self.is_native = self.tool is not None and bool(shutil.which(self.tool))
        if not self.is_native and self.vault is None:
            raise SecretError("No supported native secret store on this platform" if self.tool is None
                              else f"Required native store tool unavailable: {self.tool}")

    @staticmethod
    def _service(name: str) -> str:
        if not _NAME.fullmatch(name):
            raise SecretError("Invalid secret name")
        return SERVICE_PREFIX + name

    def put(self, name: str, value: str) -> None:
        """Store in the native store; fall back to the encrypted file vault when it is unavailable."""
        self._service(name)
        if not value or "\0" in value:
            raise SecretError("Secret must be nonempty text")
        if self.is_native:
            try:
                self._native_put(name, value)
            except SecretError:
                if self.system == "Darwin" or self.vault is None:
                    raise
            else:
                if self.vault is not None:
                    try:
                        self.vault.delete(name)
                    except SecretError:
                        pass
                return
        self.vault.put(name, value)

    def _native_put(self, name: str, value: str) -> None:
        service = self._service(name)
        if self.system == "Darwin":
            raise SecretError("Use put_interactive on macOS; security CLI has no safe stdin input")
        cmd = ["secret-tool", "store", "--label=Guardkit managed secret", "service", service, "account", "guardkit"]
        try:
            # Values only travel through a pipe. Never interpolate them into argv or errors.
            result = self.runner(cmd, input=value.encode(), stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, check=False, timeout=15)
            if result.returncode:
                raise SecretError("Native secret store rejected the value")
        except SecretError:
            raise
        except Exception:
            raise SecretError("Native secret store operation failed") from None

    def put_interactive(self, name: str) -> None:
        """Store without putting a value in Python, argv, or an environment variable."""
        service = self._service(name)
        if self.system == "Darwin" and self.is_native:
            # Apple's CLI prompts when -w is the final option; do not capture its output
            # or pass a password argument. The user enters the value at the native prompt.
            cmd = ["security", "add-generic-password", "-U", "-s", service,
                   "-a", "guardkit", "-w"]
            try:
                result = self.runner(cmd, stdin=None, stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL, check=False, timeout=120)
                if result.returncode:
                    raise SecretError("Native secret store rejected the value")
            except SecretError:
                raise
            except Exception:
                raise SecretError("Native secret store operation failed") from None
            return
        first = getpass.getpass("Secret value (hidden): ")
        second = getpass.getpass("Repeat secret value: ")
        try:
            if first != second:
                raise SecretError("Values did not match")
            self.put(name, first)
        finally:
            first = second = ""

    def _read(self, name: str) -> str:
        self._service(name)
        if self.is_native:
            try:
                return self._native_read(name)
            except SecretError:
                if self.vault is None:
                    raise
        return self.vault.get(name)

    def _native_read(self, name: str) -> str:
        service = self._service(name)
        if self.system == "Darwin":
            cmd = ["security", "find-generic-password", "-s", service, "-a", "guardkit", "-w"]
        else:
            cmd = ["secret-tool", "lookup", "service", service, "account", "guardkit"]
        try:
            result = self.runner(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                 check=False, timeout=15)
            if result.returncode:
                raise SecretError("Secret not found or access denied")
            return result.stdout.decode("utf-8").rstrip("\n")
        except SecretError:
            raise
        except Exception:
            raise SecretError("Native secret store operation failed") from None

    def delete(self, name: str) -> None:
        self._service(name)
        removed = False
        if self.vault is not None:
            removed = self.vault.delete(name)
        if self.is_native:
            try:
                self._native_delete(name)
                return
            except SecretError:
                if not removed:
                    raise
        elif not removed:
            raise SecretError("Secret not found or removal failed")

    def _native_delete(self, name: str) -> None:
        service = self._service(name)
        cmd = (["security", "delete-generic-password", "-s", service, "-a", "guardkit"]
               if self.system == "Darwin" else
               ["secret-tool", "clear", "service", service, "account", "guardkit"])
        try:
            result = self.runner(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                 check=False, timeout=15)
            if result.returncode:
                raise SecretError("Secret not found or removal failed")
        except SecretError:
            raise
        except Exception:
            raise SecretError("Native secret store operation failed") from None


@dataclass(frozen=True)
class Endpoint:
    """A single exact HTTPS destination; no wildcard hosts, paths, or methods."""
    name: str
    url: str
    method: str
    credential_name: str
    credential_header: str = "Authorization"
    prefix: str = "Bearer "

    def validate(self) -> None:
        try:
            p = urllib.parse.urlsplit(self.url)
            _ = p.port
        except ValueError:
            raise SecretError("Invalid fixed HTTPS endpoint policy") from None
        if (not _NAME.fullmatch(self.name) or not _NAME.fullmatch(self.credential_name)
                or any(ord(c) < 32 or ord(c) == 127 for c in self.url)
                or p.scheme != "https" or not p.hostname or p.username or p.password
                or p.fragment or p.query or not p.path.startswith("/")
                or self.method not in {"GET", "POST", "PUT", "PATCH", "DELETE"}
                or not re.fullmatch(r"[A-Za-z0-9-]+", self.credential_header)
                or any(c in self.prefix for c in "\r\n")):
            raise SecretError("Invalid fixed HTTPS endpoint policy")


@dataclass(frozen=True)
class Approval:
    endpoint: str
    expires_at: float


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class RequestBroker:
    """In-memory, expiring approvals. Secret-bearing responses are never returned."""

    def __init__(self, store: SecretStore, endpoints: Mapping[str, Endpoint],
                 opener=None, clock: Callable[[], float] = time.monotonic):
        self.store, self.endpoints, self.clock = store, dict(endpoints), clock
        for endpoint in self.endpoints.values():
            endpoint.validate()
        # Ignore HTTP(S)_PROXY and related environment settings: a proxy can
        # observe or replace credential-bearing requests.
        self.opener = opener or urllib.request.build_opener(
            urllib.request.ProxyHandler({}), _NoRedirect())
        self._approvals: dict[str, Approval] = {}

    def _grant_after_confirmation(self, endpoint_name: str, ttl: int) -> None:
        if endpoint_name not in self.endpoints:
            raise SecretError("Unknown endpoint")
        if type(ttl) is not int or not 1 <= ttl <= MAX_TTL_SECONDS:
            raise SecretError("Approval TTL must be between 1 and 3600 seconds")
        self._approvals[endpoint_name] = Approval(endpoint_name, self.clock() + ttl)

    def approve_interactive(self, endpoint_name: str, ttl: int) -> None:
        """Approve from a foreground trusted terminal; do not expose to MCP/tools."""
        endpoint = self.endpoints.get(endpoint_name)
        if endpoint is None:
            raise SecretError("Unknown endpoint")
        if type(ttl) is not int or not 1 <= ttl <= MAX_TTL_SECONDS:
            raise SecretError("Approval TTL must be between 1 and 3600 seconds")
        if not _tty_confirm(endpoint, ttl):
            raise SecretError("Approval requires trusted-terminal confirmation")
        self._grant_after_confirmation(endpoint_name, ttl)

    def revoke(self, endpoint_name: str) -> None:
        self._approvals.pop(endpoint_name, None)

    def send(self, endpoint_name: str, method: str, url: str, body: bytes | None = None) -> dict:
        endpoint = self.endpoints.get(endpoint_name)
        approval = self._approvals.get(endpoint_name)
        if endpoint is None or approval is None or self.clock() >= approval.expires_at:
            self._approvals.pop(endpoint_name, None)
            raise SecretError("No active approval for endpoint")
        if method != endpoint.method or url != endpoint.url:
            raise SecretError("Request does not match approved method and URL")
        if body is not None and (not isinstance(body, bytes) or len(body) > 1024 * 1024):
            raise SecretError("Request body must be bytes of at most 1 MiB")
        secret = self.store._read(endpoint.credential_name)
        if not secret or "\r" in secret or "\n" in secret:
            raise SecretError("Credential unavailable")
        headers = {endpoint.credential_header: endpoint.prefix + secret,
                   "Accept": "application/json", "User-Agent": "Guardkit-secret-broker/1"}
        request = urllib.request.Request(endpoint.url, data=body, headers=headers, method=method)
        response = None
        try:
            try:
                response = self.opener.open(request, timeout=15)
            except urllib.error.HTTPError as error:
                response = error
            # Drain then discard: servers sometimes echo Authorization or request data.
            response.read(1024 * 1024 + 1)
            code = int(response.code)
            if not 100 <= code <= 599:
                raise SecretError("Invalid upstream status")
            return {"status": code}
        except Exception:
            raise SecretError("Approved HTTPS request failed") from None
        finally:
            try:
                if response is not None:
                    response.close()
            except Exception:
                pass
            secret = ""  # Drop the local reference promptly; Python cannot guarantee zeroization.


def _tty_confirm(endpoint: Endpoint, ttl: int) -> bool:
    if platform.system() not in {"Darwin", "Linux"}:
        return False
    host = urllib.parse.urlsplit(endpoint.url).hostname
    try:
        # Read approval independently of stdin so `serve` can take JSON lines
        # from an MCP client without letting that client approve itself.
        with open("/dev/tty", "r+", encoding="utf-8") as tty:
            tty.write(f"Allow {endpoint.method} to {host}{urllib.parse.urlsplit(endpoint.url).path} for {ttl}s? Type '{endpoint.name}': ")
            tty.flush()
            answer = tty.readline().rstrip("\r\n")
        return answer == endpoint.name
    except (OSError, EOFError, KeyboardInterrupt):
        return False


def _request_broker(store: SecretStore, name: str, url: str, method: str) -> RequestBroker:
    endpoint = Endpoint("request", url, method, name)
    endpoint.validate()
    return RequestBroker(store, {"request": endpoint})


def _serve(broker: RequestBroker, endpoint: Endpoint, ttl: int) -> int:
    """Serve a tiny JSONL protocol; request input cannot choose URL/method/body."""
    try:
        broker.approve_interactive(endpoint.name, ttl)
        for line in sys.stdin:
            try:
                if len(line) > 4096:
                    raise SecretError("Request line too large")
                message = json.loads(line)
                if not isinstance(message, dict) or set(message) != {"op"}:
                    raise SecretError("Expected an operation-only JSON object")
                if message["op"] == "request":
                    print(json.dumps(broker.send(endpoint.name, endpoint.method, endpoint.url)), flush=True)
                elif message["op"] == "revoke":
                    broker.revoke(endpoint.name)
                    print(json.dumps({"revoked": True}), flush=True)
                else:
                    raise SecretError("Unknown operation")
            except (json.JSONDecodeError, SecretError):
                print(json.dumps({"error": "request rejected"}), flush=True)
        return 0
    except SecretError as error:
        print(json.dumps({"error": str(error)}), file=sys.stderr)
        return 2


def secrets_main(args: list[str]) -> int:
    """CLI storage and restricted broker operations; no raw-value retrieval command."""
    import argparse
    parser = argparse.ArgumentParser(prog="guardkit-secrets")
    sub = parser.add_subparsers(dest="command", required=True)
    put = sub.add_parser("put"); put.add_argument("name")
    entry = sub.add_parser("input", help="Open masked credential entry on the user terminal; return metadata only")
    entry.add_argument("name")
    entry.add_argument("--kind", choices=("token", "login"), default="token")
    entry.add_argument("--service", help="Service label displayed to the user (no credential data)")
    sub.add_parser("status", help="Show which secret backends are available and the names held in the file vault")
    attach = sub.add_parser("attach", help="Join a pending masked input form from your own terminal")
    attach.add_argument("socket")
    delete = sub.add_parser("delete"); delete.add_argument("name")
    request = sub.add_parser("request"); request.add_argument("name"); request.add_argument("url")
    request.add_argument("--method", default="GET"); request.add_argument("--ttl", type=int, default=60)
    serve = sub.add_parser("serve"); serve.add_argument("name"); serve.add_argument("url")
    serve.add_argument("--method", default="GET"); serve.add_argument("--ttl", type=int, default=60)
    ns = parser.parse_args(args)
    if ns.command == "status":
        try:
            store = SecretStore()
            print(json.dumps({"native_tool": store.is_native,
                              "vault_path": str(store.vault.path) if store.vault else None,
                              "vault_names": store.vault.names() if store.vault else []}))
            return 0
        except SecretError as error:
            print(json.dumps({"error": str(error)}), file=sys.stderr)
            return 2
    if ns.command == "attach":
        from .safe_input import attach
        return attach(ns.socket)
    if ns.command == "input":
        from .safe_input import request as open_input, request_bridged
        try:
            result = open_input(ns.name, ns.kind, ns.service)
            if result.get("error_code") == "terminal_unavailable":
                def announce(command):
                    print("No terminal here. Run this in your own terminal to open the form:\n  "
                          + command, file=sys.stderr, flush=True)
                result = request_bridged(ns.name, ns.kind, ns.service, announce)
            print(json.dumps(result))
            return 0 if result["status"] == "stored" else 130 if result["status"] == "cancelled" else 2
        except SecretError as error:
            print(json.dumps({"status": "failed", "error": str(error)}))
            return 2
    try:
        store = SecretStore()
        if ns.command == "put":
            if not sys.stdin.isatty():
                raise SecretError("Secret entry requires a trusted interactive terminal")
            store.put_interactive(ns.name)
        elif ns.command == "delete":
            store.delete(ns.name)
        else:
            if type(ns.ttl) is not int or not 1 <= ns.ttl <= MAX_TTL_SECONDS:
                raise SecretError("Approval TTL must be between 1 and 3600 seconds")
            broker = _request_broker(store, ns.name, ns.url, ns.method)
            endpoint = broker.endpoints["request"]
            if ns.command == "request":
                broker.approve_interactive(endpoint.name, ns.ttl)
                status = broker.send(endpoint.name, endpoint.method, endpoint.url)["status"]
                print(status)
                return 0
            return _serve(broker, endpoint, ns.ttl)
        print(json.dumps({"ok": True, "operation": ns.command, "name": ns.name}))
        return 0
    except SecretError as error:
        print(json.dumps({"ok": False, "error": str(error)}), file=sys.stderr)
        return 2


__all__ = ["Approval", "Endpoint", "RequestBroker", "SecretError", "SecretStore", "secrets_main"]
