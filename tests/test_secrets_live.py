"""Live loopback HTTPS tests; all credentials and certificates are disposable."""
import shutil
import ssl
import subprocess
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.request import HTTPSHandler, ProxyHandler, build_opener

from guardkit.secrets import Endpoint, RequestBroker, SecretError, _NoRedirect


TEST_TOKEN = "guardkit-live-test-token-not-a-real-credential"


class FakeStore:
    def __init__(self):
        self.reads = 0

    def _read(self, name):
        self.reads += 1
        if name != "synthetic":
            raise SecretError("test fixture missing")
        return TEST_TOKEN


class LiveSecretsHTTPS(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not shutil.which("openssl"):
            raise unittest.SkipTest("openssl is required for the disposable TLS fixture")
        cls.temp = tempfile.TemporaryDirectory(prefix="guardkit-secrets-tls-")
        root = Path(cls.temp.name)
        cls.cert = root / "cert.pem"
        cls.key = root / "key.pem"
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-keyout", str(cls.key), "-out", str(cls.cert), "-days", "1",
             "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1"],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        try:
            cls.destination = cls._server()
            cls.destination.redirect_target = None
            cls.destination_thread = cls._start(cls.destination)
            cls.upstream = cls._server()
            cls.upstream.redirect_target = f"https://127.0.0.1:{cls.destination.server_port}/destination"
            cls.upstream_thread = cls._start(cls.upstream)
        except PermissionError as error:
            for name in ("upstream", "destination"):
                server = getattr(cls, name, None)
                if server is not None:
                    server.server_close()
            cls.temp.cleanup()
            raise unittest.SkipTest(f"loopback listener is unavailable in this sandbox: {error}") from None

        # Test-only trust: this client trusts only the temporary self-signed
        # certificate created above. Production broker defaults retain system TLS.
        context = ssl.create_default_context(cafile=str(cls.cert))
        cls.opener = build_opener(ProxyHandler({}), _NoRedirect(), HTTPSHandler(context=context))

    @classmethod
    def _server(cls):
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_GET(self):
                self.server.hits += 1
                auth = self.headers.get("Authorization", "")
                self.server.received_auth.append(auth)
                if self.path == "/redirect":
                    self.send_response(302)
                    self.send_header("Location", self.server.redirect_target)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                if self.path == "/reflect":
                    body = ("upstream reflected " + auth).encode()
                    self.send_response(200)
                    self.send_header("X-Echo-Credential", auth)
                    self.send_header("Content-Type", TEST_TOKEN)
                else:
                    body = b"ok"
                    self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.daemon_threads = True
        server.hits = 0
        server.received_auth = []
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(str(cls.cert), str(cls.key))
        server.socket = tls.wrap_socket(server.socket, server_side=True)
        return server

    @staticmethod
    def _start(server):
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return thread

    @classmethod
    def tearDownClass(cls):
        for name in ("upstream", "destination"):
            server = getattr(cls, name, None)
            if server is not None:
                server.shutdown()
                server.server_close()
        if hasattr(cls, "temp"):
            cls.temp.cleanup()

    def _broker(self, path, clock=lambda: 100.0):
        url = f"https://127.0.0.1:{self.upstream.server_port}{path}"
        endpoint = Endpoint("test", url, "GET", "synthetic")
        broker = RequestBroker(FakeStore(), {"test": endpoint}, opener=self.opener, clock=clock)
        return broker, endpoint

    def test_tls_reflection_in_body_and_headers_never_reaches_result(self):
        broker, endpoint = self._broker("/reflect")
        broker._grant_after_confirmation("test", 30)
        result = broker.send("test", "GET", endpoint.url)
        self.assertEqual(result, {"status": 200})
        self.assertNotIn(TEST_TOKEN, repr(result))
        self.assertEqual(self.upstream.received_auth[-1], "Bearer " + TEST_TOKEN)

    def test_redirect_is_returned_as_status_and_not_followed(self):
        broker, endpoint = self._broker("/redirect")
        before_upstream = self.upstream.hits
        before_destination = self.destination.hits
        broker._grant_after_confirmation("test", 30)
        result = broker.send("test", "GET", endpoint.url)
        self.assertEqual(result, {"status": 302})
        self.assertEqual(self.upstream.hits, before_upstream + 1)
        self.assertEqual(self.destination.hits, before_destination)

    def test_revoke_and_expiry_prevent_further_live_requests(self):
        now = [100.0]
        broker, endpoint = self._broker("/ok", clock=lambda: now[0])
        broker._grant_after_confirmation("test", 2)
        broker.send("test", "GET", endpoint.url)
        hits_after_first_request = self.upstream.hits
        broker.revoke("test")
        with self.assertRaises(SecretError):
            broker.send("test", "GET", endpoint.url)
        self.assertEqual(self.upstream.hits, hits_after_first_request)

        broker._grant_after_confirmation("test", 2)
        now[0] = 103.0
        with self.assertRaises(SecretError):
            broker.send("test", "GET", endpoint.url)
        self.assertEqual(self.upstream.hits, hits_after_first_request)


if __name__ == "__main__":
    unittest.main()
