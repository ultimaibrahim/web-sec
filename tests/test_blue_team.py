"""Unit tests for blue_team_shield (Active Defense & Countermeasures)."""

import unittest
import gzip
import json
from blue_team_shield import (
    THREAT_REGISTRY,
    is_decoy_path,
    generate_decoy_response,
    generate_poisoned_gzip,
    HONEY_CREDENTIALS,
)

class TestBlueTeamShield(unittest.TestCase):
    def test_decoy_path_detection(self):
        self.assertTrue(is_decoy_path("/api/v1/internal_auth"))
        self.assertTrue(is_decoy_path("/backup/admin.sql.gz"))
        self.assertTrue(is_decoy_path("/.aws/credentials"))
        self.assertFalse(is_decoy_path("/index.html"))
        self.assertFalse(is_decoy_path("/api/products"))

    def test_decoy_response_generation(self):
        resp = generate_decoy_response("/.aws/credentials")
        self.assertEqual(resp["status"], 200)
        self.assertIn(HONEY_CREDENTIALS["AWS_KEY"].encode(), resp["body"])

        resp_jwt = generate_decoy_response("/api/v1/internal_auth")
        self.assertIn(HONEY_CREDENTIALS["BEARER_CANARY"].encode(), resp_jwt["body"])

    def test_poisoned_gzip_bomb(self):
        compressed = generate_poisoned_gzip(expansion_mb=5)
        self.assertLess(len(compressed), 15 * 1024)  # Menos de 15 KB comprimido
        # Al descomprimir debe tener 5 MB
        decompressed = gzip.decompress(compressed)
        self.assertEqual(len(decompressed), 5 * 1024 * 1024)

    def test_threat_registry_shadow_ban(self):
        attacker_ip = "192.168.1.199"
        self.assertFalse(THREAT_REGISTRY.is_hostile(attacker_ip))
        THREAT_REGISTRY.record_hit(attacker_ip, "/wp-login.php", "FuzzScanner/1.0", "decoy_access")
        self.assertTrue(THREAT_REGISTRY.is_hostile(attacker_ip))
        summary = THREAT_REGISTRY.get_summary()
        self.assertGreaterEqual(summary["total_hostiles"], 1)

if __name__ == "__main__":
    unittest.main()
