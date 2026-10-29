"""Opt-in real-browser checks for the credential-only MCP App surface.

Run with GUARDKIT_LIVE_APP_UI=1 python -m unittest tests.test_safe_app_ui.
Requires Playwright Python and its Chromium browser; no external network is used.
"""
from __future__ import annotations

import http.server
import os
import threading
import unittest
from pathlib import Path
from urllib.parse import urlparse

from guardkit.safe_app import SafeInputApp


ROOT = Path(__file__).resolve().parents[1]
HTML = (ROOT / "guardkit" / "ui" / "safe_input.html").read_text(encoding="utf-8")
SENTINELS = ("PRIVATE-TOKEN-SENTINEL", "PRIVATE-USER-SENTINEL", "PRIVATE-PASSWORD-SENTINEL")


class _Server(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if urlparse(self.path).path == "/app":
            body = HTML.encode()
        else:
            body = b"""<!doctype html><meta charset=utf-8><title>Local MCP host</title>
<iframe id=app src=/app style="width:440px;height:560px;border:0"></iframe><script>
window.messages=[];
window.addEventListener('message', async event => {
  const message=event.data;
  if (!message || message.jsonrpc !== '2.0') return;
  window.messages.push(message);
  const frame=document.getElementById('app');
  if (message.method === 'ui/initialize') {
    frame.contentWindow.postMessage({jsonrpc:'2.0',id:message.id,result:{
      protocolVersion:'2026-01-26',hostCapabilities:new URLSearchParams(location.search).get('tools') === '0' ? {} : {serverTools:{}},hostInfo:{name:'test',version:'1'}}},'*');
    const result=await window.openRequest(new URLSearchParams(location.search).get('kind'));
    frame.contentWindow.postMessage({jsonrpc:'2.0',method:'ui/notifications/tool-result',params:result},'*');
  } else if (message.method === 'tools/call') {
    const result=await window.routeTool(message.params.name,message.params.arguments);
    frame.contentWindow.postMessage({jsonrpc:'2.0',id:message.id,result},'*');
  } else if (message.method === 'ui/resource-teardown') {
    frame.contentWindow.postMessage({jsonrpc:'2.0',id:message.id,result:{}},'*');
  }
});
</script>"""
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


@unittest.skipUnless(os.environ.get("GUARDKIT_LIVE_APP_UI") == "1", "set GUARDKIT_LIVE_APP_UI=1 to run Chromium checks")
class SafeInputAppBrowserTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            from playwright.sync_api import sync_playwright
        except ImportError as exc:
            raise unittest.SkipTest("Playwright is not installed") from exc
        cls.playwright = sync_playwright().start()
        try:
            cls.browser = cls.playwright.chromium.launch(headless=True)
        except Exception as exc:
            cls.playwright.stop()
            raise unittest.SkipTest(f"Playwright Chromium is unavailable: {exc}") from exc
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Server)
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.server_thread.join(timeout=2)
        cls.browser.close()
        cls.playwright.stop()

    def _open_page(self, kind, mock_clock=False):
        stored = []
        app = SafeInputApp(lambda name, value: stored.append((name, value)))
        context = self.browser.new_context()
        page = context.new_page()

        def open_request(_source, requested_kind):
            return app.open("test-ref", requested_kind, "Local test service")

        def route_tool(_source, name, arguments):
            if name == "submit_safe_input":
                return app.submit(arguments)
            if name == "cancel_safe_input":
                return app.cancel(arguments)
            return {"isError": True, "content": [{"type": "text", "text": "unknown"}]}

        page.expose_binding("openRequest", open_request)
        page.expose_binding("routeTool", route_tool)
        if mock_clock:
            page.clock.install()
        page.goto(f"http://127.0.0.1:{self.server.server_port}/host?kind={kind}")
        frame = page.frame_locator("#app")
        page.wait_for_function("document.querySelector('#app').contentWindow")
        frame.get_by_role("status").wait_for()
        page.wait_for_function("document.querySelector('#app').contentDocument?.querySelector('#save')?.disabled === false")
        return context, page, frame, stored

    def _assert_no_plaintext_on_bridge(self, page):
        serialized = page.evaluate("JSON.stringify(window.messages)")
        for sentinel in SENTINELS:
            self.assertNotIn(sentinel, serialized)

    def test_token_submit_encrypts_before_tool_call_and_hides_login_required_fields(self):
        context, page, frame, stored = self._open_page("token")
        try:
            token = SENTINELS[0]
            frame.locator("#token").fill(token)
            self.assertTrue(frame.locator("#credential-form").evaluate("form => form.checkValidity()"))
            frame.get_by_role("button", name="Save or replace locally").click()
            frame.get_by_role("status").filter(has_text="Credential saved.").wait_for()
            self.assertEqual(stored, [("test-ref", token)])
            self._assert_no_plaintext_on_bridge(page)
            self.assertEqual(frame.locator("#token").input_value(), "")
        finally:
            context.close()

    def test_login_masks_username_and_password_and_stores_only_after_decryption(self):
        context, page, frame, stored = self._open_page("login")
        try:
            username, password = SENTINELS[1:]
            self.assertEqual(frame.locator("#username").get_attribute("type"), "password")
            frame.locator("#username").fill(username)
            frame.locator("#password").fill(password)
            self.assertTrue(frame.get_by_text("Credential reference: test-ref", exact=True).is_visible())
            self.assertTrue(frame.get_by_text("Requested service: Local test service", exact=True).is_visible())
            frame.locator("body").screenshot(path="/tmp/guardkit-safe-input-preview.png")
            self.assertTrue(frame.locator("#credential-form").evaluate("form => form.checkValidity()"))
            frame.get_by_role("button", name="Save or replace locally").click()
            frame.get_by_role("status").filter(has_text="Credential saved.").wait_for()
            self.assertEqual(stored, [("test-ref", '{"username": "PRIVATE-USER-SENTINEL", "password": "PRIVATE-PASSWORD-SENTINEL"}')])
            self._assert_no_plaintext_on_bridge(page)
        finally:
            context.close()

    def test_cancel_sends_only_request_capability_and_teardown_clears_form(self):
        context, page, frame, stored = self._open_page("token")
        try:
            frame.locator("#token").fill(SENTINELS[0])
            frame.get_by_role("button", name="Cancel").click()
            frame.get_by_role("status").filter(has_text="Request cancelled.").wait_for()
            self.assertEqual(stored, [])
            self._assert_no_plaintext_on_bridge(page)
        finally:
            context.close()

        context, page, frame, _ = self._open_page("login")
        try:
            frame.locator("#username").fill(SENTINELS[1])
            frame.locator("#password").fill(SENTINELS[2])
            page.evaluate("document.querySelector('#app').contentWindow.postMessage({jsonrpc:'2.0',id:777,method:'ui/resource-teardown',params:{reason:'test'}},'*')")
            page.wait_for_function("document.querySelector('#app').contentDocument?.querySelector('#username')?.value === ''")
            self.assertTrue(frame.locator("#username").is_disabled())
            self.assertTrue(frame.locator("#password").is_disabled())
            self._assert_no_plaintext_on_bridge(page)
        finally:
            context.close()

    def test_missing_server_tools_fails_closed(self):
        # A tiny host response without the serverTools capability must never enable submission.
        page = self.browser.new_page()
        try:
            page.goto(f"http://127.0.0.1:{self.server.server_port}/host?kind=token&tools=0")
            page.wait_for_function("document.querySelector('#app').contentDocument?.querySelector('#status')?.textContent.includes('connection is unavailable')")
            frame = page.frame_locator("#app")
            self.assertTrue(frame.get_by_role("button", name="Save or replace locally").is_disabled())
        finally:
            page.close()

    def test_five_minute_expiry_clears_fields_and_disables_form(self):
        context, page, frame, _ = self._open_page("login", mock_clock=True)
        try:
            frame.locator("#username").fill(SENTINELS[1])
            frame.locator("#password").fill(SENTINELS[2])
            page.clock.fast_forward(300_001)
            frame.get_by_role("status").filter(has_text="This request expired.").wait_for()
            self.assertEqual(frame.locator("#username").input_value(), "")
            self.assertEqual(frame.locator("#password").input_value(), "")
            self.assertTrue(frame.get_by_role("button", name="Save or replace locally").is_disabled())
            self._assert_no_plaintext_on_bridge(page)
        finally:
            context.close()


if __name__ == "__main__":
    unittest.main()
