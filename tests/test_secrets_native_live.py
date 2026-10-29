"""Opt-in macOS adapter check against a disposable native Keychain only."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from guardkit.secrets import SecretError, SecretStore


@unittest.skipUnless(os.environ.get("GUARDKIT_LIVE_NATIVE_STORE") == "1"
                     and os.sys.platform == "darwin",
                     "requires macOS and GUARDKIT_LIVE_NATIVE_STORE=1")
class LiveMacOSKeychainTests(unittest.TestCase):
    def test_read_delete_use_disposable_native_keychain(self):
        # Public fixture strings, never real credentials. Automated enrollment
        # seeds the fixture; interactive production enrollment is not simulated.
        fixture_password = "guardkit-disposable-keychain-password"
        fixture_value = "guardkit-synthetic-native-test-value"
        service = SecretStore._service("native-audit-fixture")
        with tempfile.TemporaryDirectory(prefix="guardkit-keychain-") as tmp:
            keychain = str(Path(tmp) / "fixture.keychain-db")

            def security(*args):
                subprocess.run(["/usr/bin/security", *args], check=True,
                               stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                               timeout=30)

            security("create-keychain", "-p", fixture_password, keychain)
            try:
                security("unlock-keychain", "-p", fixture_password, keychain)
                security("add-generic-password", "-s", service, "-a", "guardkit",
                         "-w", fixture_value, "-T", "/usr/bin/security", keychain)

                def runner(command, **kwargs):
                    self.assertIn(command[1], {"find-generic-password", "delete-generic-password"})
                    return subprocess.run(["/usr/bin/security", *command[1:], keychain], **kwargs)

                store = SecretStore(system="Darwin", runner=runner)
                self.assertEqual(store._read("native-audit-fixture"), fixture_value)
                store.delete("native-audit-fixture")
                with self.assertRaises(SecretError):
                    store._read("native-audit-fixture")
            finally:
                security("delete-keychain", keychain)
