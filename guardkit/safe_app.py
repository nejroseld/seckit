"""Encrypted local-app credential input sessions for MCP Apps."""
from __future__ import annotations

import base64
import hmac
import json
import secrets
import time
from dataclasses import dataclass
from typing import Callable

from .safe_input import MAX_BYTES, _validate
from .secrets import SecretStore

_TTL = 300
_MAX_PENDING = 16
_MAX_RECORDS = 64
_B64_LIMIT = 100_000


def _crypto():
    """Load encryption lazily so diagnostics survive an incomplete installation."""
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding, rsa
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        return hashes, serialization, padding, rsa, AESGCM
    except ImportError:
        return None


def available() -> bool:
    return _crypto() is not None


@dataclass(repr=False)
class _Session:
    request_id: str
    capability: str
    private_key: object
    name: str
    kind: str
    service: str
    expires: float
    state: str = "awaiting_user"


class SafeInputApp:
    def __init__(self, store_callback: Callable[[str, str], None] | None = None,
                 clock: Callable[[], float] = time.monotonic):
        self.store_callback = store_callback or self._native_store
        self.clock = clock
        self._sessions: dict[str, _Session] = {}
        self._records: dict[str, dict] = {}

    @staticmethod
    def _native_store(name: str, value: str) -> None:
        from .native_store import put_from_tui
        put_from_tui(SecretStore(), name, value)

    @staticmethod
    def _ok(data: dict, text: str | None = None) -> dict:
        return {"content": [{"type": "text", "text": text or json.dumps(data, ensure_ascii=False)}],
                "structuredContent": data}

    @staticmethod
    def _error(message: str) -> dict:
        return {"content": [{"type": "text", "text": message}], "isError": True}

    def _prune(self) -> None:
        now = self.clock()
        for session in list(self._sessions.values()):
            if session.state == "awaiting_user" and now >= session.expires:
                self._finish(session, "expired")
        while len(self._records) > _MAX_RECORDS:
            self._records.pop(next(iter(self._records)))

    def _finish(self, session: _Session, state: str) -> None:
        session.state = state
        session.private_key = None
        self._records[session.request_id] = {"request_id": session.request_id,
            "credential_ref": session.name, "kind": session.kind,
            "service": session.service, "status": state}
        self._sessions.pop(session.request_id, None)

    def _state_result(self, request_id: str, state: str) -> dict:
        record = self._records[request_id]
        public = {key: record[key] for key in
                  ("status", "request_id", "credential_ref", "kind", "service")}
        result = self._ok(public)
        if state == "failed":
            result["isError"] = True
            result["content"] = [{"type": "text", "text": "Credential submission failed."}]
        return result

    def open(self, name: str, kind: str = "token", service: str | None = None) -> dict:
        service = name if service is None else service
        try:
            _validate(name, kind, service)
        except Exception:
            return self._error("Invalid credential request.")
        crypto = _crypto()
        if crypto is None:
            return self._ok({"status": "unavailable", "credential_ref": name,
                             "kind": kind, "service": service})
        self._prune()
        for previous in list(self._sessions.values()):
            if previous.name == name and previous.state == "awaiting_user":
                self._finish(previous, "cancelled")
        if len(self._sessions) >= _MAX_PENDING:
            return self._error("Too many credential requests are active.")
        hashes, serialization, padding, rsa, _ = crypto
        try:
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
            public_der = private_key.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        except Exception:
            return self._ok({"status": "unavailable", "credential_ref": name,
                             "kind": kind, "service": service})
        request_id = secrets.token_hex(16)
        capability = secrets.token_urlsafe(32)
        session = _Session(request_id, capability, private_key, name, kind,
                           service, self.clock() + _TTL)
        self._sessions[request_id] = session
        public = {"status": "awaiting_user", "request_id": request_id,
                  "credential_ref": name, "kind": kind, "service": service}
        result = self._ok(public)
        result["_meta"] = {"guardkit/safeInput": {"request_id": request_id,
            "capability": capability,
            "public_key_spki": base64.b64encode(public_der).decode("ascii"),
            "expires_in": _TTL}}
        return result

    def _auth(self, args: object, fields: set[str]):
        if not isinstance(args, dict) or set(args) != fields:
            return None, self._error("Invalid credential submission.")
        request_id, capability = args.get("request_id"), args.get("capability")
        if (not isinstance(request_id, str) or not isinstance(capability, str)
                or len(capability) != 43 or not capability.isascii()):
            return None, self._error("Invalid credential submission.")
        self._prune()
        session = self._sessions.get(request_id)
        if session is None:
            return None, self._error("Credential request is unavailable.")
        try:
            matches = hmac.compare_digest(session.capability, capability)
        except (TypeError, ValueError):
            matches = False
        if not matches:
            return None, self._error("Credential request is unavailable.")
        return session, None

    def submit(self, args: object) -> dict:
        fields = {"request_id", "capability", "wrapped_key", "nonce", "ciphertext"}
        session, error = self._auth(args, fields)
        if error:
            return error
        # An authenticated attempt is single-use, including malformed or failed submissions.
        private_key = session.private_key
        self._finish(session, "failed")
        try:
            encoded = []
            for field in ("wrapped_key", "nonce", "ciphertext"):
                value = args[field]
                if not isinstance(value, str) or len(value) > _B64_LIMIT:
                    raise ValueError
                raw = base64.b64decode(value, validate=True)
                if base64.b64encode(raw).decode("ascii") != value:
                    raise ValueError
                encoded.append(raw)
            wrapped, nonce, ciphertext = encoded
            if len(nonce) != 12 or len(wrapped) > 2048 or not 16 <= len(ciphertext) <= MAX_BYTES + 16:
                raise ValueError
            crypto = _crypto()
            if crypto is None:
                return self._state_result(session.request_id, "failed")
            hashes, _, padding, _, AESGCM = crypto
            key = private_key.decrypt(wrapped, padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
            if len(key) != 32:
                raise ValueError
            plaintext = AESGCM(key).decrypt(nonce, ciphertext, session.request_id.encode("utf-8"))
            if len(plaintext) > MAX_BYTES:
                raise ValueError
            payload = json.loads(plaintext.decode("utf-8"))
            if session.kind == "token":
                if not isinstance(payload, dict) or set(payload) != {"value"}:
                    raise ValueError
                value = payload["value"]
                if not isinstance(value, str) or not value or "\0" in value:
                    raise ValueError
                value.encode("utf-8")
            else:
                if not isinstance(payload, dict) or set(payload) != {"username", "password"}:
                    raise ValueError
                username, password = payload["username"], payload["password"]
                if any(not isinstance(v, str) or not v or "\0" in v for v in (username, password)):
                    raise ValueError
                value = json.dumps({"username": username, "password": password}, ensure_ascii=False)
                value.encode("utf-8")
            if len(value.encode("utf-8")) > MAX_BYTES:
                raise ValueError
            self.store_callback(session.name, value)
            self._records[session.request_id]["status"] = "stored"
            return self._state_result(session.request_id, "stored")
        except Exception:
            return self._state_result(session.request_id, "failed")
        finally:
            key = plaintext = value = payload = None

    def cancel(self, args: object) -> dict:
        session, error = self._auth(args, {"request_id", "capability"})
        if error:
            return error
        self._finish(session, "cancelled")
        return self._state_result(session.request_id, "cancelled")

    def status(self, request_id: str) -> dict:
        self._prune()
        if not isinstance(request_id, str):
            return self._error("Invalid request identifier.")
        session = self._sessions.get(request_id)
        if session:
            return self._ok({"request_id": request_id, "credential_ref": session.name,
                "kind": session.kind, "service": session.service, "status": "awaiting_user"})
        record = self._records.get(request_id)
        if record:
            return self._ok(dict(record))
        return self._ok({"request_id": request_id, "status": "unknown"})
