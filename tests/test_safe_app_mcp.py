"""MCP capability negotiation and private encrypted enrollment routing."""
import base64
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from guardkit import agents
from guardkit.safe_app import SafeInputApp, available

UI = {"protocolVersion": "2025-11-25", "capabilities": {"extensions": {
    "io.modelcontextprotocol/ui": {"mimeTypes": ["text/html;profile=mcp-app"]}}}}


def message(i, method, params=None):
    return {"jsonrpc": "2.0", "id": i, "method": method, "params": params or {}}


def call(i, name, args=None):
    return message(i, "tools/call", {"name": name, "arguments": args or {}})


class AppMCPTests(unittest.TestCase):
    def run_protocol(self, requests, app=None):
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as root, patch("sys.stdin", requests), redirect_stdout(output), \
                patch("guardkit.safe_app.SafeInputApp", return_value=app or SafeInputApp()):
            agents.serve(Path(root), lambda _: self.fail("must not scan for app input"))
        return [json.loads(line) for line in output.getvalue().splitlines()]

    def test_negotiates_ui_resources_and_app_only_tools(self):
        requests = [message(1, "initialize", UI), message(2, "tools/list"),
                    message(3, "resources/list"), message(4, "resources/read", {"uri": agents._APP_URI})]
        responses = self.run_protocol(map(json.dumps, requests))
        self.assertEqual(responses[0]["result"]["protocolVersion"], "2025-11-25")
        tools = {tool["name"]: tool for tool in responses[1]["result"]["tools"]}
        self.assertEqual(tools["open_safe_input"]["_meta"]["ui"]["resourceUri"], agents._APP_URI)
        for name in ("submit_safe_input", "cancel_safe_input"):
            self.assertEqual(tools[name]["_meta"]["ui"]["visibility"], ["app"])
        self.assertFalse(set(tools["submit_safe_input"]["inputSchema"]["properties"]) & {"password", "username", "value"})
        resource = responses[3]["result"]["contents"][0]
        self.assertEqual(resource["mimeType"], agents._APP_MIME)
        self.assertEqual(resource["_meta"]["ui"]["csp"]["connectDomains"], [])
        self.assertIn('<form', resource["text"])
        self.assertNotIn('private_key', resource["text"])

    def test_non_app_clients_cannot_call_private_methods(self):
        requests = [message(1, "initialize"), message(2, "tools/list"),
                    call(3, "submit_safe_input", {"password": "SENTINEL-DO-NOT-ECHO"})]
        responses = self.run_protocol(map(json.dumps, requests))
        names = {tool["name"] for tool in responses[1]["result"]["tools"]}
        self.assertNotIn("submit_safe_input", names)
        self.assertEqual(responses[2]["error"]["code"], -32602)
        self.assertNotIn("SENTINEL", json.dumps(responses))

    def test_malformed_client_capabilities_fail_closed(self):
        for params in ([], {"capabilities": []}, {"capabilities": {"extensions": {
                "io.modelcontextprotocol/ui": {"mimeTypes": agents._APP_MIME}}}}):
            with self.subTest(params=params):
                self.assertFalse(agents._supports_app_ui(params))

    @unittest.skipUnless(available(), "requires optional cryptography")
    def test_full_session_accepts_only_encrypted_envelope_and_reports_status(self):
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        stored, output = [], io.StringIO()
        app = SafeInputApp(lambda name, value: stored.append((name, value)))
        def requests():
            yield json.dumps(message(1, "initialize", UI))
            yield json.dumps(call(2, "open_safe_input", {"name": "demo", "kind": "login", "service": "demo.example"}))
            opened = json.loads(output.getvalue().splitlines()[-1])["result"]
            private = opened["_meta"]["guardkit/safeInput"]
            public = opened["structuredContent"]
            self.assertNotIn(private["capability"], json.dumps({"content": opened["content"], "structuredContent": public}))
            public_key = serialization.load_der_public_key(base64.b64decode(private["public_key_spki"]))
            key, nonce = os.urandom(32), os.urandom(12)
            wrapped = public_key.encrypt(key, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
            value = json.dumps({"username": "SYNTHETIC-USER", "password": "SYNTHETIC-PASSWORD"}).encode()
            ciphertext = AESGCM(key).encrypt(nonce, value, public["request_id"].encode())
            args = {"request_id": public["request_id"], "capability": private["capability"],
                    **{name: base64.b64encode(value).decode() for name, value in
                       (("wrapped_key", wrapped), ("nonce", nonce), ("ciphertext", ciphertext))}}
            yield json.dumps(call(3, "submit_safe_input", args))
            yield json.dumps(call(4, "safe_input_status", {"request_id": public["request_id"]}))
            yield json.dumps(call(5, "submit_safe_input", args))
        with tempfile.TemporaryDirectory() as root, patch("sys.stdin", requests()), redirect_stdout(output), \
                patch("guardkit.safe_app.SafeInputApp", return_value=app):
            agents.serve(Path(root), lambda _: self.fail("must not scan"))
        responses = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual(responses[2]["result"]["structuredContent"]["status"], "stored")
        self.assertEqual(responses[3]["result"]["structuredContent"]["credential_ref"], "demo")
        self.assertEqual(json.loads(stored[0][1]), {"username": "SYNTHETIC-USER", "password": "SYNTHETIC-PASSWORD"})
        self.assertNotIn("SYNTHETIC-", output.getvalue())
        self.assertTrue(responses[4]["result"]["isError"])
