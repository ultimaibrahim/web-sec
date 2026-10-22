# tests/test_ui_widgets.py
"""Unit tests for UI widgets and action bindings."""

import unittest
from unittest.mock import MagicMock

from main import FlipProgressBarWidget, MicroControlWidget, WebSecApp


class TestUIWidgets(unittest.TestCase):
    def test_micro_control_widget_refresh_display(self):
        widget = MicroControlWidget()

        # Test baseline passive level
        widget.refresh_display(mode="WebSec", level="0", browser=False)
        self.assertIn("WebSec", widget.content)
        self.assertIn("0·Passive", widget.content)

        # Test recon level with flags
        flags = {
            "scan_ports": True,
            "subdomains": True,
            "deep_crawl": False,
            "fingerprint": True,
            "dump_db": False,
            "vault_store": True,
            "export_report": True,
            "stealth": True,
            "proxy_tor": False,
        }
        widget.refresh_display(mode="WebSec", level="recon", browser=True, recon_flags=flags)
        self.assertIn("Recon·Intel", widget.content)
        self.assertIn("RECON", widget.content)
        self.assertIn("FLAGS:", widget.content)

    def test_flip_progress_bar_widget(self):
        bar = FlipProgressBarWidget()
        # Initial state
        self.assertEqual(bar.progress, 0.0)
        self.assertEqual(bar.stage_text, "STANDBY // READY")

        # Set progress
        bar.set_progress(55.5, "SCANNING PORTS")
        self.assertEqual(bar.progress, 55.5)
        self.assertEqual(bar.stage_text, "SCANNING PORTS")

        # Bounds clipping
        bar.set_progress(150.0, "EXCEED")
        self.assertEqual(bar.progress, 100.0)

        bar.set_progress(-20.0, "NEGATIVE")
        self.assertEqual(bar.progress, 0.0)

        # Reset
        bar.reset()
        self.assertEqual(bar.progress, 0.0)
        self.assertEqual(bar.stage_text, "STANDBY // READY")

    def test_app_flag_actions(self):
        app = WebSecApp()
        self.assertFalse(app.recon_flags["scan_ports"])
        self.assertFalse(app.recon_flags["deep_crawl"])
        self.assertFalse(app.recon_flags["subdomains"])

        # Test toggling flags
        app.action_scan_ports()
        self.assertTrue(app.recon_flags["scan_ports"])

        app.action_deep_crawl()
        self.assertTrue(app.recon_flags["deep_crawl"])

        app.action_subdomains()
        self.assertTrue(app.recon_flags["subdomains"])

        app.action_fingerprint()
        self.assertTrue(app.recon_flags["fingerprint"])

        app.action_toggle_stealth()
        self.assertTrue(app.recon_flags["stealth"])

        app.action_toggle_proxy()
        self.assertTrue(app.recon_flags["proxy_tor"])

    def test_app_level_cycling(self):
        app = WebSecApp()
        initial_lvl = app.level
        self.assertEqual(initial_lvl, "0")

        # Cycle through levels
        app.action_cycle_level()
        self.assertEqual(app.level, "1")
        app.action_cycle_level()
        self.assertEqual(app.level, "2")
        app.action_cycle_level()
        self.assertEqual(app.level, "3")
        app.action_cycle_level()
        self.assertEqual(app.level, "recon")
        app.action_cycle_level()
        self.assertEqual(app.level, "void")
        app.action_cycle_level()
        self.assertEqual(app.level, "void_plus")


if __name__ == "__main__":
    unittest.main()
