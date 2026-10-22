# tests/test_recon_handler.py
"""Unit and integration tests for level_handlers/recon.py."""

import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from level_handlers import recon
import storage_vault


class DummyLogger:
    def __init__(self):
        self.logs = []
        self.app = MagicMock()
        self.app.call_from_thread = lambda fn, *args, **kwargs: fn(*args, **kwargs)
        self.app.recon_flags = {
            "scan_ports": False,
            "subdomains": False,
            "deep_crawl": False,
            "fingerprint": False,
            "dump_db": False,
            "vault_store": True,
            "export_report": False,
            "stealth": False,
            "proxy_tor": False,
        }
        self.app.progress_bar = MagicMock()
        self.progress_bar = self.app.progress_bar

    def write(self, msg: str):
        self.logs.append(msg)


class TestReconHandler(unittest.TestCase):
    def setUp(self):
        self.logger = DummyLogger()

    @patch("level_handlers.recon.enumerate_endpoints")
    def test_recon_run_baseline(self, mock_enum):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "Admin Panel Token: eyJhbGciOiJIUzI1NiJ9.e30.secret"
        mock_enum.return_value = {"https://test.local/admin": mock_resp}

        result = recon.run("test.local", mode="WebSec", logger=self.logger)

        self.assertEqual(result["mode"], "recon")
        self.assertEqual(result["target"], "https://test.local")
        self.assertIn("https://test.local/admin", result["endpoints"])
        self.assertTrue(any("JWT:" in c for c in result["creds"]))
        self.assertIn("flags", result)

    @patch("level_handlers.recon.enumerate_endpoints")
    @patch("level_handlers.recon.scan_ports")
    @patch("level_handlers.recon.mass_subdomains")
    @patch("level_handlers.recon.advanced_fingerprint")
    @patch("level_handlers.recon.deep_crawl")
    @patch("level_handlers.recon.export_html_report")
    @patch("level_handlers.recon.export_pdf_report")
    def test_recon_run_all_flags(
        self,
        mock_pdf,
        mock_html,
        mock_crawl,
        mock_fp,
        mock_sub,
        mock_ports,
        mock_enum,
    ):
        mock_enum.return_value = {}
        mock_ports.return_value = {80: "open", 443: "open"}
        mock_sub.return_value = {
            "domain": "test.local",
            "total_live": 1,
            "subdomains": [{"host": "api.test.local", "ip": "127.0.0.1"}],
            "sources": ["DNS"],
        }
        mock_fp.return_value = {
            "server": "nginx",
            "powered_by": "FastAPI",
            "title": "API Docs",
            "technologies": [{"name": "FastAPI", "category": "Backend", "confidence": 100}],
        }
        mock_crawl.return_value = {
            "endpoints": ["https://test.local/v1"],
            "forms": [],
            "creds": ["AKIAIOSFODNN7EXAMPLE"],
        }
        mock_html.return_value = Path("outputs/mock.html")
        mock_pdf.return_value = Path("outputs/mock.pdf")

        flags = {
            "p": True,
            "m": True,
            "d": True,
            "F": True,
            "D": False,
            "v": True,
            "r": True,
            "s": False,
            "P": False,
        }

        result = recon.run("test.local", mode="WebSec", logger=self.logger, flags=flags)

        self.assertIn(80, result["ports"])
        self.assertEqual(result["ports"][80], "open")
        self.assertEqual(len(result["subdomains"]), 1)
        self.assertEqual(len(result["technologies"]), 1)
        self.assertIn("https://test.local/v1", result["endpoints"])
        self.assertIn("AKIAIOSFODNN7EXAMPLE", result["creds"])
        self.assertIn("reports", result)

        # Verify progress updates were sent
        self.logger.app.progress_bar.set_progress.assert_called()


if __name__ == "__main__":
    unittest.main()
