"""Trusted UI enrollment helpers for native secret stores.

This module is intentionally separate from agent-facing secret APIs: callers
must collect ``value`` in a trusted UI and must never forward it to an LLM.
"""
from __future__ import annotations

import ctypes
import ctypes.util
import sys

from .secrets import SecretError, SecretStore


_MAX_SECRET_BYTES = 64 * 1024
_ERR_SEC_DUPLICATE_ITEM = -25299


def _load_frameworks():
    if sys.platform != "darwin":
        raise SecretError("Native secret store operation failed")
    security_path = ctypes.util.find_library("Security")
    core_path = ctypes.util.find_library("CoreFoundation")
    if not security_path or not core_path:
        raise SecretError("Native secret store operation failed")
    return ctypes.CDLL(security_path), ctypes.CDLL(core_path)


def _bind(function, restype, argtypes):
    # Python fakes used by tests need not expose ctypes function attributes.
    try:
        function.restype = restype
        function.argtypes = argtypes
    except (AttributeError, TypeError):
        pass
    return function


def _put_darwin(service: str, value: bytes) -> None:
    try:
        security, core = _load_frameworks()
        add = _bind(security.SecKeychainAddGenericPassword, ctypes.c_int32,
                    [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_char_p,
                     ctypes.c_uint32, ctypes.c_char_p, ctypes.c_uint32,
                     ctypes.c_void_p, ctypes.c_void_p])
        find = _bind(security.SecKeychainFindGenericPassword, ctypes.c_int32,
                     [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_char_p,
                      ctypes.c_uint32, ctypes.c_char_p, ctypes.c_void_p,
                      ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)])
        modify = _bind(security.SecKeychainItemModifyAttributesAndData,
                       ctypes.c_int32,
                       [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32,
                        ctypes.c_void_p])
        release = _bind(core.CFRelease, None, [ctypes.c_void_p])

        service_bytes = service.encode("utf-8")
        account_bytes = b"guardkit"
        # Keep secret bytes in a mutable native buffer for the duration of the
        # Security.framework call. It never enters argv, environment, or files.
        secret_buffer = ctypes.create_string_buffer(value, len(value))
        try:
            status = add(None, len(service_bytes), service_bytes,
                         len(account_bytes), account_bytes, len(value),
                         ctypes.cast(secret_buffer, ctypes.c_void_p), None)
            if status == 0:
                return
            if status != _ERR_SEC_DUPLICATE_ITEM:
                raise SecretError("Native secret store operation failed")
            item = ctypes.c_void_p()
            # NULL password length and data mean lookup does not retrieve/decrypt
            # the existing password. Only the item reference is requested.
            status = find(None, len(service_bytes), service_bytes,
                          len(account_bytes), account_bytes, None, None,
                          ctypes.byref(item))
            try:
                if status != 0 or not item.value:
                    raise SecretError("Native secret store operation failed")
                status = modify(item, None, len(value),
                                ctypes.cast(secret_buffer, ctypes.c_void_p))
                if status != 0:
                    raise SecretError("Native secret store operation failed")
            finally:
                if item.value:
                    release(item)
        finally:
            ctypes.memset(secret_buffer, 0, len(value))
    except SecretError:
        raise
    except Exception:
        raise SecretError("Native secret store operation failed") from None


def put_from_tui(store: SecretStore, name: str, value: str) -> None:
    """Store a secret collected by a trusted UI without command-line exposure."""
    service = store._service(name)
    if not isinstance(value, str) or not value or "\0" in value:
        raise SecretError("Secret must be nonempty text")
    try:
        encoded = value.encode("utf-8")
    except UnicodeError:
        raise SecretError("Secret must be valid UTF-8 text") from None
    if not encoded or len(encoded) > _MAX_SECRET_BYTES:
        raise SecretError("Secret exceeds 64 KiB")
    if store.system == "Darwin" and store.is_native:
        _put_darwin(service, encoded)
        return
    store.put(name, value)
