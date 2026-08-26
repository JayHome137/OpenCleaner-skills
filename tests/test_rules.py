from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "open-cleaner" / "scripts"
sys.path.insert(0, str(SCRIPTS))

from rules import RuleCatalog, RuleError, normalized_platform


class RuleCatalogTests(unittest.TestCase):
    def test_every_executable_rule_declares_risk_and_non_targets(self) -> None:
        with tempfile.TemporaryDirectory(prefix="storage-rules-") as temporary:
            home = Path(temporary) / "home"
            home.mkdir()
            catalog = RuleCatalog("darwin", {"HOME": str(home)})
            self.assertEqual(catalog.rules, ())
            for rule in catalog.rules:
                with self.subTest(rule=rule.id):
                    self.assertEqual(rule.classification, "green")
                    self.assertTrue(rule.recovery)
                    self.assertTrue(rule.risk)
                    self.assertTrue(rule.non_targets)

    def test_broad_cache_roots_are_not_executable_rules(self) -> None:
        with tempfile.TemporaryDirectory(prefix="storage-rules-") as temporary:
            home = Path(temporary) / "home"
            targets = [
                home / ".cache" / "entry",
                home / "Library" / "Caches" / "com.example",
                home / ".npm" / "_cacache",
                home / "Library" / "pnpm" / "store" / "v3",
                home / ".gradle" / "caches" / "modules",
                home / "go" / "pkg" / "mod",
                home / ".codex" / "cache",
                home / ".codex" / "plugins" / "cache",
                home / ".claude" / "cache",
            ]
            for target in targets:
                target.mkdir(parents=True)
            catalog = RuleCatalog("darwin", {"HOME": str(home)})
            for target in targets:
                with self.subTest(path=target):
                    self.assertIsNone(catalog.match(str(target), "trash"))

    def test_owner_managed_generated_targets_are_not_executable(self) -> None:
        with tempfile.TemporaryDirectory(prefix="storage-rules-") as temporary:
            home = Path(temporary) / "home"
            targets = {
                home / ".codex" / ".tmp" / "bundled-marketplaces",
                home / ".codex" / ".tmp" / "plugins",
                home / "Library" / "Developer" / "Xcode" / "DerivedData" / "Example",
            }
            for path in targets:
                path.mkdir(parents=True, exist_ok=True)
            catalog = RuleCatalog("darwin", {"HOME": str(home)})
            for path in targets:
                with self.subTest(path=path):
                    self.assertIsNone(catalog.match(str(path), "trash"))
            backup = home / ".codex" / ".tmp" / "plugins-backup-example"
            backup.mkdir()
            self.assertIsNone(catalog.match(str(backup), "trash"))

            # The explicit temporary root may contain generated children, but
            # a similarly named sibling must never inherit its rule.
            sibling = home / ".codex" / ".tmp" / "plugins-staging"
            sibling.mkdir()
            self.assertIsNone(catalog.match(str(sibling), "trash"))

    def test_windows_rule_entry_is_disabled(self) -> None:
        with self.assertRaisesRegex(RuleError, "仅支持 macOS"):
            normalized_platform("win32")
        with self.assertRaises(RuleError):
            RuleCatalog("win32", {"HOME": "/tmp/example"})


if __name__ == "__main__":
    unittest.main()
