import _isolate  # noqa: F401
import ctypes
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from guardkit.secrets import SecretError, SecretStore
from guardkit.native_store import put_from_tui


class NativeStoreTests(unittest.TestCase):
    def store(self, system="Darwin"):
        # Avoid requiring platform tools in unit tests.
        return SimpleNamespace(system=system, is_native=True, _service=SecretStore._service,
                               put=lambda name, value: None)

    def test_linux_delegates_to_existing_pipe_based_put(self):
        calls = []
        store = self.store("Linux")
        store.put = lambda name, value: calls.append((name, value))
        put_from_tui(store, "api-token", "opaque-value")
        self.assertEqual(calls, [("api-token", "opaque-value")])

    def test_rejects_empty_nul_and_oversized_values(self):
        for value in ("", "bad\0value", "x" * (64 * 1024 + 1)):
            with self.subTest(length=len(value)):
                with self.assertRaises(SecretError):
                    put_from_tui(self.store(), "api-token", value)

    def test_darwin_adds_secret_in_native_buffer(self):
        observed = {}

        def add(_keychain, slen, service, alen, account, length, data, item):
            observed.update(service=ctypes.string_at(service, slen),
                            account=ctypes.string_at(account, alen),
                            value=ctypes.string_at(data, length), item=item,
                            secret_buffer=data.value)
            return 0

        with patch("guardkit.native_store._load_frameworks", return_value=(
                SimpleNamespace(SecKeychainAddGenericPassword=add,
                                SecKeychainFindGenericPassword=lambda *_args: -1,
                                SecKeychainItemModifyAttributesAndData=lambda *_args: -1),
                SimpleNamespace(CFRelease=lambda _item: None))):
            put_from_tui(self.store(), "api-token", "opaque-value")
        self.assertEqual(observed, {
            "service": b"guardkit.secret.api-token", "account": b"guardkit",
            "value": b"opaque-value", "item": None,
            "secret_buffer": observed["secret_buffer"],
        })
        self.assertEqual(ctypes.string_at(observed["secret_buffer"], len(b"opaque-value")),
                         b"\0" * len(b"opaque-value"))

    def test_darwin_updates_existing_item_and_releases_reference(self):
        observed = {}
        item_value = 0x1234

        def add(*_args):
            return -25299

        def find(_keychain, _slen, _service, _alen, _account,
                 password_length, password_data, item_out):
            observed["no_password_fetch"] = password_length is None and password_data is None
            ctypes.cast(item_out, ctypes.POINTER(ctypes.c_void_p))[0] = item_value
            return 0

        def modify(item, attrs, length, data):
            observed.update(modified_item=item.value, attrs=attrs,
                            value=ctypes.string_at(data, length),
                            secret_buffer=data.value)
            return 0

        def release(item):
            observed["released"] = item.value

        fake = SimpleNamespace(SecKeychainAddGenericPassword=add,
                               SecKeychainFindGenericPassword=find,
                               SecKeychainItemModifyAttributesAndData=modify)
        core = SimpleNamespace(CFRelease=release)
        with patch("guardkit.native_store._load_frameworks", return_value=(fake, core)):
            put_from_tui(self.store(), "api-token", "new-value")
        self.assertEqual(observed, {"no_password_fetch": True,
                                    "modified_item": item_value, "attrs": None,
                                    "value": b"new-value", "released": item_value,
                                    "secret_buffer": observed["secret_buffer"]})
        self.assertEqual(ctypes.string_at(observed["secret_buffer"], len(b"new-value")),
                         b"\0" * len(b"new-value"))

    def test_native_errors_are_constant_and_release_after_modify_failure(self):
        secret = "never-print-this"
        item_value = 0x1234
        released = []

        def find(*args):
            ctypes.cast(args[-1], ctypes.POINTER(ctypes.c_void_p))[0] = item_value
            return 0

        fake = SimpleNamespace(
            SecKeychainAddGenericPassword=lambda *_args: -25299,
            SecKeychainFindGenericPassword=find,
            SecKeychainItemModifyAttributesAndData=lambda *_args: -50)
        core = SimpleNamespace(CFRelease=lambda item: released.append(item.value))
        with patch("guardkit.native_store._load_frameworks", return_value=(fake, core)):
            with self.assertRaises(SecretError) as raised:
                put_from_tui(self.store(), "api-token", secret)
        self.assertEqual(str(raised.exception), "Native secret store operation failed")
        self.assertNotIn(secret, str(raised.exception))
        self.assertEqual(released, [item_value])

    def test_failed_lookup_releases_any_returned_item_and_wipes_buffer(self):
        item_value = 0x4321
        state = {}

        def add(_keychain, _slen, _service, _alen, _account, length, data, _item):
            state["buffer"] = data.value
            state["value"] = ctypes.string_at(data, length)
            return -25299

        def find(*args):
            ctypes.cast(args[-1], ctypes.POINTER(ctypes.c_void_p))[0] = item_value
            return -50

        fake = SimpleNamespace(
            SecKeychainAddGenericPassword=add,
            SecKeychainFindGenericPassword=find,
            SecKeychainItemModifyAttributesAndData=lambda *_args: self.fail("must not modify"))
        core = SimpleNamespace(CFRelease=lambda item: state.setdefault("released", item.value))
        with patch("guardkit.native_store._load_frameworks", return_value=(fake, core)):
            with self.assertRaises(SecretError):
                put_from_tui(self.store(), "api-token", "private-value")
        self.assertEqual(state["released"], item_value)
        self.assertEqual(state["value"], b"private-value")
        self.assertEqual(ctypes.string_at(state["buffer"], len(b"private-value")),
                         b"\0" * len(b"private-value"))

    def test_bad_name_is_rejected_and_unavailable_native_store_delegates(self):
        with self.assertRaises(SecretError):
            put_from_tui(self.store(), "../bad", "value")
        calls = []
        store = self.store()
        store.is_native = False
        store.put = lambda name, value: calls.append(name)
        put_from_tui(store, "valid", "value")
        self.assertEqual(calls, ["valid"])


if __name__ == "__main__":
    unittest.main()
