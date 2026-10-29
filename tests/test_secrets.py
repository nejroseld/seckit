import _isolate  # noqa: F401
import unittest
import io
import json
from unittest.mock import patch

from guardkit.secrets import Endpoint, RequestBroker, SecretError, SecretStore, _serve, secrets_main


class FakeStore:
    def __init__(self, value="top-secret-token"):
        self.value = value
        self.reads = 0

    def _read(self, name):
        self.reads += 1
        return self.value


class FakeResponse:
    code = 200
    headers = {"Content-Type": "top-secret-token"}

    def read(self, _limit):
        return b'{"echo":"top-secret-token"}'


class FakeOpener:
    def __init__(self):
        self.request = None

    def open(self, request, timeout):
        self.request = request
        return FakeResponse()


class SecretStoreTests(unittest.TestCase):
    def test_macos_native_prompt_has_no_secret_argument_or_pipe(self):
        seen = {}

        class Result:
            returncode = 0

        def runner(args, **kwargs):
            seen["args"] = args
            seen["input"] = kwargs.get("input")
            seen["stdout"] = kwargs.get("stdout")
            return Result()

        with patch("guardkit.secrets.shutil.which", return_value="/usr/bin/security"):
            store = SecretStore(system="Darwin", runner=runner)
            store.put_interactive("api")
        self.assertNotIn("credential-value", seen["args"])
        self.assertIsNone(seen["input"])
        self.assertEqual(seen["args"][-1], "-w")
        self.assertNotEqual(seen["stdout"], -1)  # Store output is discarded, not captured.

    def test_macos_refuses_password_passed_through_python(self):
        with patch("guardkit.secrets.shutil.which", return_value="/usr/bin/security"):
            store = SecretStore(system="Darwin", runner=lambda *a, **k: self.fail("must not launch"))
            with self.assertRaises(SecretError):
                store.put("api", "credential-value")

    def test_name_validation(self):
        with self.assertRaises(SecretError):
            SecretStore._service("../credential")


class BrokerTests(unittest.TestCase):
    def setUp(self):
        self.store = FakeStore()
        self.endpoint = Endpoint("issue", "https://api.example.test/v1/issue", "POST", "api")
        self.opener = FakeOpener()
        self.now = [10.0]
        self.broker = RequestBroker(self.store, {"issue": self.endpoint}, self.opener,
                                    clock=lambda: self.now[0])

    def test_fixed_request_returns_metadata_only_when_response_reflects_secret(self):
        self.broker._grant_after_confirmation("issue", 20)
        result = self.broker.send("issue", "POST", self.endpoint.url, b"{}")
        self.assertEqual(result, {"status": 200})
        self.assertNotIn("top-secret-token", repr(result))
        self.assertEqual(self.opener.request.get_header("Authorization"), "Bearer top-secret-token")

    def test_unapproved_and_nonmatching_request_do_not_read_secret(self):
        for method, url in (("GET", self.endpoint.url), ("POST", "https://evil.test/")):
            with self.assertRaises(SecretError):
                self.broker.send("issue", method, url)
        self.assertEqual(self.store.reads, 0)

    def test_expiry_and_revocation(self):
        self.broker._grant_after_confirmation("issue", 2)
        self.broker.revoke("issue")
        with self.assertRaises(SecretError):
            self.broker.send("issue", "POST", self.endpoint.url)
        self.broker._grant_after_confirmation("issue", 2)
        self.now[0] = 13
        with self.assertRaises(SecretError):
            self.broker.send("issue", "POST", self.endpoint.url)

    def test_invalid_endpoint_and_ttl_rejected(self):
        with self.assertRaises(SecretError):
            Endpoint("x", "http://api.example.test/v1", "POST", "api").validate()
        for ttl in (0, 3601, True):
            with self.assertRaises(SecretError):
                self.broker._grant_after_confirmation("issue", ttl)
        with patch("guardkit.secrets._tty_confirm", return_value=False):
            with self.assertRaises(SecretError):
                self.broker.approve_interactive("issue", 10)

    def test_jsonl_protocol_has_no_url_method_body_or_secret_output(self):
        self.broker._grant_after_confirmation("issue", 20)
        lines = [
            '{"op":"request"}',
            '{"op":"reveal","name":"api"}',
            '{"op":"request","url":"https://evil.test","method":"GET","body":"x"}',
            '{"op":"revoke"}',
            '{"op":"request"}',
        ]
        output = io.StringIO()
        with patch("guardkit.secrets.sys.stdin", io.StringIO("\n".join(lines) + "\n")), \
                patch("guardkit.secrets.sys.stdout", output), \
                patch.object(self.broker, "approve_interactive", return_value=None):
            self.assertEqual(_serve(self.broker, self.endpoint, 20), 0)
        replies = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual(replies[0], {"status": 200})
        self.assertEqual(replies[1], {"error": "request rejected"})
        self.assertEqual(replies[2], {"error": "request rejected"})
        self.assertEqual(replies[3], {"revoked": True})
        self.assertEqual(replies[4], {"error": "request rejected"})
        self.assertNotIn("top-secret-token", output.getvalue())

    def test_request_cli_prints_only_numeric_status(self):
        output = io.StringIO()
        cli_endpoint = Endpoint("request", self.endpoint.url, "GET", "api")
        cli_broker = RequestBroker(self.store, {"request": cli_endpoint}, self.opener)
        with patch("guardkit.secrets.SecretStore", return_value=self.store), \
                patch("guardkit.secrets._request_broker", return_value=cli_broker), \
                patch("guardkit.secrets._tty_confirm", return_value=True), \
                patch("guardkit.secrets.sys.stdout", output):
            # Exercise CLI's approval path without an actual terminal.
            with patch.object(cli_broker, "approve_interactive", side_effect=lambda name, ttl: cli_broker._grant_after_confirmation(name, ttl)):
                self.assertEqual(secrets_main(["request", "api", self.endpoint.url]), 0)
        self.assertEqual(output.getvalue(), "200\n")
        self.assertNotIn("top-secret-token", output.getvalue())


if __name__ == "__main__":
    unittest.main()
