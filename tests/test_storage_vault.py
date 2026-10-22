# tests/test_storage_vault.py
"""Unit tests for storage_vault.py."""

import tempfile
import unittest
from pathlib import Path

import storage_vault


class TestStorageVault(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.orig_db = storage_vault.DB_PATH
        storage_vault.DB_PATH = Path(self.temp_dir.name) / "test_vault.db"
        storage_vault.init_database()

    def tearDown(self):
        storage_vault.DB_PATH = self.orig_db
        self.temp_dir.cleanup()

    def test_encryption_decryption(self):
        secret = "SUPER_SECRET_AWS_KEY_12345"
        enc = storage_vault.encrypt_data(secret)
        self.assertNotEqual(secret, enc)
        dec = storage_vault.decrypt_data(enc)
        self.assertEqual(secret, dec)

    def test_save_and_retrieve_findings(self):
        storage_vault.save_finding(
            target="target.local",
            tool="test_tool",
            finding_type="token",
            content="SECRET_TOKEN_XYZ",
            encrypt=True,
        )
        findings = storage_vault.get_recent_findings(10)
        self.assertGreaterEqual(len(findings), 1)
        self.assertEqual(findings[0]["content"], "SECRET_TOKEN_XYZ")
        self.assertEqual(findings[0]["finding_type"], "token")

    def test_save_recon_results(self):
        recon_data = {
            "mode": "Recon",
            "ports": {80: "open", 22: "closed"},
            "subdomains": [{"host": "api.target.local", "ip": "127.0.0.1"}],
            "endpoints": ["/admin", "/login"],
            "creds": ["JWT: secret.jwt.here"],
            "technologies": [{"name": "WordPress", "confidence": 100}],
        }
        storage_vault.save_recon_results("target.local", recon_data, encrypt=True)

        findings = storage_vault.get_recent_findings(20)
        types = [f["finding_type"] for f in findings]
        self.assertIn("credential_leak", types)
        self.assertIn("open_ports", types)
        self.assertIn("subdomains", types)
        self.assertIn("technologies", types)

    def test_export_markdown_report(self):
        out_dir = Path(self.temp_dir.name) / "reports"
        storage_vault.save_scan_record("target.local", mode="WebSec", level="recon", summary="Test scan")
        report_path = storage_vault.export_markdown_report(output_dir=out_dir)

        self.assertTrue(report_path.exists())
        content = report_path.read_text(encoding="utf-8")
        self.assertIn("Web-Sec Executive Security & Reconnaissance Report", content)
        self.assertIn("target.local", content)


if __name__ == "__main__":
    unittest.main()
