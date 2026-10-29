import base64
import json
import unittest
from unittest import mock

from guardkit.safe_app import SafeInputApp, _Session, available


def setup_request(app, name="alpha", kind="token"):
    result = app.open(name, kind)
    public = result["structuredContent"]
    meta = result["_meta"]["guardkit/safeInput"]
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    pubkey = serialization.load_der_public_key(base64.b64decode(meta["public_key_spki"]))
    return public, meta, pubkey, hashes, padding, AESGCM


def seal(public, meta, pubkey, hashes, padding, AESGCM, data):
    key, nonce = b"k" * 32, b"n" * 12
    wrapped = pubkey.encrypt(key, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                          algorithm=hashes.SHA256(), label=None))
    ciphertext = AESGCM(key).encrypt(nonce, json.dumps(data).encode(),
                                     public["request_id"].encode())
    b64 = lambda x: base64.b64encode(x).decode()
    return {"request_id": public["request_id"], "capability": meta["capability"],
            "wrapped_key": b64(wrapped), "nonce": b64(nonce), "ciphertext": b64(ciphertext)}


@unittest.skipUnless(available(), "cryptography is optional")
class SafeInputAppTests(unittest.TestCase):
    def test_encrypted_submit_stores_value_without_echo(self):
        stored = []
        app = SafeInputApp(lambda name, value: stored.append((name, value)))
        public, meta, pubkey, hashes, padding, AESGCM = setup_request(app)
        result = app.submit(seal(public, meta, pubkey, hashes, padding, AESGCM,
                                 {"value": "super-secret"}))
        self.assertEqual(result["structuredContent"]["status"], "stored")
        self.assertEqual(stored, [("alpha", "super-secret")])
        self.assertNotIn("super-secret", json.dumps(result))
        self.assertNotIn("super-secret", json.dumps(app.status(public["request_id"])))

    def test_wrong_capability_unicode_tamper_and_replay(self):
        app = SafeInputApp(lambda *_: None)
        public, meta, pubkey, hashes, padding, AESGCM = setup_request(app)
        args = seal(public, meta, pubkey, hashes, padding, AESGCM, {"value": "secret"})
        for capability in ("wrong", "é" * 43):
            self.assertTrue(app.submit(dict(args, capability=capability))["isError"])
        self.assertEqual(app.status(public["request_id"])["structuredContent"]["status"],
                         "awaiting_user")
        args["ciphertext"] = base64.b64encode(b"x" * 20).decode()
        self.assertTrue(app.submit(args)["isError"])
        self.assertTrue(app.submit(args)["isError"])

    def test_ciphertext_is_bound_to_its_request(self):
        app = SafeInputApp(lambda *_: None)
        first, m1, p1, h, pad, aes = setup_request(app, "one")
        second, m2, *_ = setup_request(app, "two")
        args = seal(first, m1, p1, h, pad, aes, {"value": "secret"})
        args["request_id"], args["capability"] = second["request_id"], m2["capability"]
        self.assertTrue(app.submit(args)["isError"])
        self.assertEqual(app.status(first["request_id"])["structuredContent"]["status"],
                         "awaiting_user")

    def test_expiry_oversize_and_store_failure_are_safe(self):
        now = [0.0]
        app = SafeInputApp(lambda *_: (_ for _ in ()).throw(RuntimeError("leaked-value")),
                           clock=lambda: now[0])
        public, meta, pubkey, hashes, padding, AESGCM = setup_request(app)
        args = seal(public, meta, pubkey, hashes, padding, AESGCM, {"value": "secret"})
        args["ciphertext"] = base64.b64encode(b"x" * 65553).decode()
        self.assertTrue(app.submit(args)["isError"])
        self.assertNotIn("leaked-value", json.dumps(app.status(public["request_id"])))

        public, meta, pubkey, hashes, padding, AESGCM = setup_request(app, "beta")
        now[0] = 301
        self.assertEqual(app.status(public["request_id"])["structuredContent"]["status"],
                         "expired")

        now[0] = 400
        public, meta, pubkey, hashes, padding, AESGCM = setup_request(app, "gamma")
        args = seal(public, meta, pubkey, hashes, padding, AESGCM, {"value": "secret"})
        result = app.submit(args)
        self.assertTrue(result["isError"])
        self.assertEqual(result["structuredContent"]["credential_ref"], "gamma")
        self.assertNotIn("leaked-value", json.dumps(result))

    def test_login_serialization_and_alias_reopen_cancel(self):
        stored = []
        app = SafeInputApp(lambda n, v: stored.append((n, v)))
        first, *_ = setup_request(app, "gamma")
        second, meta, pubkey, hashes, padding, AESGCM = setup_request(app, "gamma", "login")
        self.assertEqual(app.status(first["request_id"])["structuredContent"]["status"],
                         "cancelled")
        args = seal(second, meta, pubkey, hashes, padding, AESGCM,
                    {"username": "user", "password": "pw"})
        self.assertEqual(app.submit(args)["structuredContent"]["status"], "stored")
        self.assertEqual(json.loads(stored[0][1]), {"username": "user", "password": "pw"})

    def test_cancel_wrong_capability_and_outstanding_bound(self):
        app = SafeInputApp(lambda *_: None)
        first, meta, *_ = setup_request(app)
        self.assertTrue(app.cancel({"request_id": first["request_id"],
                                    "capability": "é" * 43})["isError"])
        self.assertEqual(app.status(first["request_id"])["structuredContent"]["status"],
                         "awaiting_user")
        result = app.cancel({"request_id": first["request_id"], "capability": meta["capability"]})
        self.assertEqual(result["structuredContent"]["status"], "cancelled")
        for index in range(16):
            setup_request(app, "name%02d" % index)
        self.assertTrue(app.open("overflow")["isError"])

    def test_optional_crypto_fallback(self):
        with mock.patch("guardkit.safe_app._crypto", return_value=None):
            self.assertFalse(available())
            result = SafeInputApp().open("alpha")
            self.assertEqual(result["structuredContent"]["status"], "unavailable")
            self.assertNotIn("_meta", result)

    def test_completed_metadata_is_bounded(self):
        app = SafeInputApp(clock=lambda: 0)
        for index in range(70):
            request_id = "r%02d" % index
            app._finish(_Session(request_id, "c" * 43, object(), "name", "token",
                                 "service", 300), "cancelled")
        app._prune()
        self.assertEqual(len(app._records), 64)
        self.assertEqual(app.status("r00")["structuredContent"]["status"], "unknown")
