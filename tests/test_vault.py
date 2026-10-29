import _isolate  # noqa: F401
import json
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

from guardkit.secrets import SecretError, SecretStore
from guardkit.vault import FileVault


def failing_runner(*args, **kwargs):
    return subprocess.CompletedProcess(args[0], 1, b"", b"")


class VaultTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.vault = FileVault(Path(self.tmp.name) / "g")

    def test_round_trip_encrypted_with_private_files(self):
        self.vault.put("api-token", "synthetic-vault-value")
        self.assertEqual(self.vault.get("api-token"), "synthetic-vault-value")
        self.assertNotIn(b"synthetic-vault-value", self.vault.path.read_bytes())
        for path in (self.vault.path, self.vault.key_path):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(self.vault.names(), ["api-token"])

    def test_replace_delete_and_missing(self):
        self.vault.put("a", "one")
        self.vault.put("a", "two")
        self.assertEqual(self.vault.get("a"), "two")
        self.assertTrue(self.vault.delete("a"))
        self.assertFalse(self.vault.delete("a"))
        with self.assertRaises(SecretError):
            self.vault.get("a")

    def test_entry_is_bound_to_its_name(self):
        self.vault.put("a", "one")
        data = json.loads(self.vault.path.read_text())
        data["b"] = data["a"]
        self.vault.path.write_text(json.dumps(data))
        with self.assertRaises(SecretError):
            self.vault.get("b")

    def test_damaged_key_is_rejected_without_leaking(self):
        self.vault.put("a", "one")
        self.vault.key_path.write_bytes(b"short")
        with self.assertRaises(SecretError):
            self.vault.get("a")


class FallbackTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.vault = FileVault(Path(self.tmp.name) / "g")

    def test_falls_back_when_native_store_rejects(self):
        store = SecretStore(system="Linux", runner=failing_runner, vault=self.vault)
        store.is_native = True
        store.put("tok", "fallback-value")
        self.assertEqual(store._read("tok"), "fallback-value")
        store.delete("tok")
        with self.assertRaises(SecretError):
            store._read("tok")

    def test_uses_vault_when_tool_is_missing(self):
        store = SecretStore(system="Linux", runner=failing_runner, vault=self.vault)
        store.is_native = False
        store.put("tok", "v")
        self.assertEqual(store._read("tok"), "v")

    def test_native_success_replaces_stale_vault_entry(self):
        self.vault.put("tok", "old")
        ok = lambda *a, **k: subprocess.CompletedProcess(a[0], 0, b"", b"")
        store = SecretStore(system="Linux", runner=ok, vault=self.vault)
        store.is_native = True
        store.put("tok", "new")
        self.assertEqual(self.vault.names(), [])


if __name__ == "__main__":
    unittest.main()
