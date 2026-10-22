# tests/test_recon_helpers.py
"""Unit tests for level_handlers/helpers.py."""

import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from level_handlers.helpers import (
    PurePythonPDF,
    advanced_fingerprint,
    deep_crawl,
    download_database,
    export_html_report,
    export_pdf_report,
    extract_credentials_from_response,
    fingerprint_target,
    load_recon_config,
    mass_subdomains,
    proxy_headers,
    save_recon_config,
    scan_ports,
    stealth_headers,
)


class TestReconHelpers(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_stealth_headers(self):
        h = stealth_headers()
        self.assertIn("User-Agent", h)
        self.assertIn("Referer", h)
        self.assertIn("X-Forwarded-For", h)
        self.assertIn("DNT", h)

    def test_proxy_headers(self):
        res = proxy_headers(stealth=True, auto_tor=False, check_privacy=False)
        self.assertIn("proxies", res)
        self.assertIn("headers", res)
        self.assertIn("tor_active", res)
        self.assertIsInstance(res["headers"], dict)

    def test_advanced_fingerprint_detection(self):
        mock_html = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Test Portal</title>
            <meta name="generator" content="WordPress 6.5" />
            <link rel="stylesheet" href="/wp-content/themes/theme.css">
            <script src="/_next/static/chunks/main.js"></script>
        </head>
        <body data-reactroot="">
            <div id="__next">Hello Cyber</div>
        </body>
        </html>
        """
        mock_resp = MagicMock()
        mock_resp.text = mock_html
        mock_resp.headers = {
            "Server": "nginx/1.24.0",
            "X-Powered-By": "Next.js",
            "Set-Cookie": "wordpress_logged_in_123=abc; PHPSESSID=xyz123",
        }
        mock_resp.cookies = {"wordpress_logged_in_123": "abc", "PHPSESSID": "xyz123"}

        with patch("requests.get", return_value=mock_resp):
            res = advanced_fingerprint("https://example.com")
            self.assertEqual(res["title"], "Test Portal")
            self.assertEqual(res["server"], "nginx/1.24.0")
            tech_names = [t["name"] for t in res["technologies"]]
            self.assertIn("WordPress", tech_names)
            self.assertIn("React", tech_names)
            self.assertIn("Next.js", tech_names)
            self.assertIn("PHP", tech_names)
            self.assertIn("Nginx", tech_names)

    def test_deep_crawl(self):
        page1 = """
        <html><body>
            <a href="/api/v1/users">Users API</a>
            <a href="https://example.com/about">About</a>
            <a href="https://external-domain.com/leak">External</a>
            <form action="/login" method="POST">
                <input name="username" type="text" />
                <input name="password" type="password" />
            </form>
            <script src="/static/app.js"></script>
            <div>AKIAIOSFODNN7EXAMPLE</div>
        </body></html>
        """
        page2 = "<html><body><h1>About Us</h1><p>Contact us</p></body></html>"

        def mock_get(url, **kwargs):
            r = MagicMock()
            if "/about" in url:
                r.text = page2
            else:
                r.text = page1
            r.status_code = 200
            r.headers = {}
            r.cookies = {}
            return r

        with patch("requests.get", side_effect=mock_get):
            res = deep_crawl("https://example.com", max_depth=1, max_pages=5)
            self.assertEqual(res["target"], "https://example.com")
            self.assertGreaterEqual(res["pages_crawled"], 1)
            # Should not crawl external-domain.com
            for ep in res["endpoints"]:
                self.assertNotIn("external-domain.com", ep)
            # Should have found form
            self.assertEqual(len(res["forms"]), 1)
            self.assertEqual(res["forms"][0]["method"], "POST")
            self.assertIn("username", res["forms"][0]["inputs"])
            # Should have extracted AWS key leak
            self.assertTrue(any("AKIA" in c for c in res["creds"]))

    def test_mass_subdomains_async(self):
        async def _test():
            with patch("level_handlers.helpers.asyncio.get_running_loop") as mock_loop_fn:
                loop = asyncio.new_event_loop()
                mock_loop_fn.return_value = loop
                
                # Directly test with mocked helper functions
                res = await mass_subdomains("example.com")
                self.assertEqual(res["domain"], "example.com")
                self.assertIsInstance(res["subdomains"], list)

        asyncio.run(_test())

    def test_pure_python_pdf_generation(self):
        pdf = PurePythonPDF()
        pdf.write_heading("TEST AUDIT HEADING", "Test Subtitle")
        pdf.write_section("1. Section Test")
        pdf.write_key_value("Target Host", "audit.local")
        pdf.write_table_row(["PORT", "STATE", "SERVICE"], [80, 100, 300], is_header=True)
        pdf.write_table_row(["80", "OPEN", "HTTP"], [80, 100, 300])

        pdf_bytes = pdf.build_bytes()
        self.assertTrue(pdf_bytes.startswith(b"%PDF-1.4"))
        self.assertIn(b"xref", pdf_bytes)
        self.assertIn(b"%%EOF", pdf_bytes)

    def test_export_pdf_and_html_reports(self):
        sample_data = {
            "target": "security.local",
            "mode": "Recon",
            "timestamp": "2026-10-21 21:00:00",
            "ports": {80: "open", 443: "open", 8080: "closed"},
            "subdomains": [{"host": "api.security.local", "ip": "10.0.0.1"}],
            "endpoints": ["/admin", "/api/v1"],
            "creds": ["JWT: eyJhbGciOi..."],
            "technologies": [{"name": "React", "category": "Framework", "confidence": 100}],
        }
        pdf_file = self.temp_path / "report.pdf"
        html_file = self.temp_path / "report.html"

        out_pdf = export_pdf_report(sample_data, pdf_file)
        out_html = export_html_report(sample_data, html_file)

        self.assertTrue(out_pdf.exists())
        self.assertGreater(out_pdf.stat().st_size, 1000)
        self.assertTrue(out_pdf.read_bytes().startswith(b"%PDF-1.4"))

        self.assertTrue(out_html.exists())
        self.assertGreater(out_html.stat().st_size, 500)
        html_content = out_html.read_text(encoding="utf-8")
        self.assertIn("security.local", html_content)

    def test_extract_credentials_from_response(self):
        text = "Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-ID and AWS: AKIAIOSFODNN7EXAMPLE Bearer test_bearer_token"
        creds = extract_credentials_from_response(text)
        self.assertTrue(any("JWT:" in c for c in creds))
        self.assertTrue(any("AWS-KEY:" in c for c in creds))
        self.assertTrue(any("BEARER:" in c for c in creds))


if __name__ == "__main__":
    unittest.main()
