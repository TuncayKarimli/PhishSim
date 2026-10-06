"""Playwright E2E integration tests for login and campaign creation flows.

Run with:
    pytest tests/test_e2e_playwright.py
"""
import threading
import time
import unittest

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    sync_playwright = None  # type: ignore

from werkzeug.serving import make_server
from tests.conftest import make_test_app


class LiveServerThread(threading.Thread):
    def __init__(self, app, port: int = 5059):
        super().__init__(daemon=True)
        self.srv = make_server("127.0.0.1", port, app)
        self.port = port

    def run(self):
        self.srv.serve_forever()

    def shutdown(self):
        self.srv.shutdown()


@unittest.skipIf(sync_playwright is None, "playwright is not installed in this environment")
class PlaywrightE2ETests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = make_test_app()
        cls.server = LiveServerThread(cls.app, port=5059)
        cls.server.start()
        time.sleep(0.3)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def test_admin_login_and_campaign_creation_flow(self):
        with sync_playwright() as p:
            try:
                browser = p.chromium.launch(headless=True)
            except Exception as exc:
                self.skipTest(f"Playwright browser binary not installed: {exc}")

            page = browser.new_page()
            page.goto("http://127.0.0.1:5059/login")
            page.fill("input[name='email']", "admin@example.com")
            page.fill("input[name='password']", "AdminTestPassword123!")
            page.click("button[type='submit']")
            page.wait_for_url("http://127.0.0.1:5059/")

            page.click("text=+ New campaign")
            page.wait_for_url("**/campaigns/new")
            page.fill("input[name='name']", "Playwright E2E Campaign")
            page.fill("input[name='subject']", "Playwright Security Check")
            page.fill("textarea[name='targets_text']", "e2e@example.com,Jamie,Doe,IT,Austin,Core")
            page.click("button[type='submit']")

            self.assertIn("/campaigns/", page.url)
            self.assertIn("Playwright E2E Campaign", page.content())
            browser.close()
