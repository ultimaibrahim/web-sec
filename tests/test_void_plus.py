# tests/test_void_plus.py
"""Unit tests for level_handlers/void_plus.py."""

import unittest
from unittest.mock import MagicMock, patch

from level_handlers import void_plus


class DummyLogger:
    def __init__(self):
        self.logs = []

    def write(self, msg: str):
        self.logs.append(msg)


class TestVoidPlus(unittest.TestCase):
    def setUp(self):
        self.logger = DummyLogger()

    def test_void_plus_scope_protection(self):
        # Target not in whitelist should be blocked immediately
        res = void_plus.run("unauthorized-bank.com", mode="WebSec", logger=self.logger)
        self.assertEqual(res.get("status"), "ABORTED_NOT_WHITELISTED")
        self.assertTrue(any("NOT in allowed_targets.txt" in log for log in self.logger.logs))

    @patch("level_handlers.void_plus._is_whitelisted", return_value=True)
    @patch("level_handlers.void_plus.async_bulk_requests")
    @patch("level_handlers.void_plus.upload_bomb")
    @patch("level_handlers.void_plus.ws_flood")
    @patch("level_handlers.void_plus.ddos_light")
    @patch("level_handlers.void_plus.rollback_action")
    def test_void_plus_execution_and_rollback(
        self,
        mock_rb,
        mock_ddos,
        mock_ws,
        mock_ub,
        mock_bulk,
        mock_wl,
    ):
        mock_resp = MagicMock()
        mock_resp.status_code = 201
        mock_resp.text = "Created dummy object. Leaked token: eyJhbGciOiJIUzI1NiJ9.e30.voidplus"
        mock_bulk.return_value = [mock_resp, mock_resp, mock_resp, mock_resp]

        mock_ub.return_value = [(0, 200), (1, 200)]
        mock_ws.return_value = [(0, 101, "payload")]
        mock_ddos.return_value = [(0, 0.05, 200)]

        rb_resp = MagicMock()
        rb_resp.status_code = 200
        mock_rb.return_value = rb_resp

        res = void_plus.run("target.local", mode="WebSec", logger=self.logger, double_confirmed=True)

        self.assertEqual(res["level"], "void_plus")
        self.assertIn("vectors", res)
        self.assertIn("rollbacks", res)
        self.assertTrue(any("voidplus" in c for c in res["creds_found"]))
        mock_rb.assert_called()


if __name__ == "__main__":
    unittest.main()
