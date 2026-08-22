from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "open-cleaner" / "scripts"
sys.path.insert(0, str(SCRIPTS))

from rules import RuleCatalog


class RuleCatalogTests(unittest.TestCase):
    def test_every_executable_rule_declares_risk_and_non_targets(self) -> None:
        with tempfile.TemporaryDirectory(prefix="storage-rules-") as temporary:
            home = Path(temporary) / "home"
            home.mkdir()
            catalog = RuleCatalog("darwin", {"HOME": str(home)})
            self.assertTrue(catalog.rules)
            for rule in catalog.rules:
                with self.subTest(rule=rule.id):
                    self.assertEqual(rule.classification, "green")
                    self.assertTrue(rule.recovery)
                    self.assertTrue(rule.risk)
                    self.assertTrue(rule.non_targets)

    def test_blocked_component_cannot_match_broad_cache_rule(self) -> None:
        with tempfile.TemporaryDirectory(prefix="storage-rules-") as temporary:
            home = Path(temporary) / "home"
            target = home / ".cache" / "credentials"
            target.mkdir(parents=True)
            catalog = RuleCatalog("darwin", {"HOME": str(home)})
            self.assertIsNone(catalog.match(str(target), "trash"))


if __name__ == "__main__":
    unittest.main()
