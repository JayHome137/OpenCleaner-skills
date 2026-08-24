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

    def test_agent_and_go_workflow_rules_are_exactly_scoped(self) -> None:
        with tempfile.TemporaryDirectory(prefix="storage-rules-") as temporary:
            home = Path(temporary) / "home"
            expected = {
                home / "go" / "pkg" / "mod": "common.go-module-cache",
                home / ".codex" / "cache": "common.codex-cache",
                home / ".codex" / ".tmp" / "bundled-marketplaces": "common.codex-bundled-marketplaces-temp",
                home / ".codex" / ".tmp" / "plugins": "common.codex-plugins-temp",
                home / ".codex" / "plugins" / "cache": "common.codex-plugin-cache",
                home / ".claude" / "cache": "common.claude-cache",
            }
            for path in expected:
                path.mkdir(parents=True, exist_ok=True)
            catalog = RuleCatalog("darwin", {"HOME": str(home)})
            for path, rule_id in expected.items():
                with self.subTest(rule_id=rule_id):
                    self.assertEqual(catalog.match(str(path), "trash").id, rule_id)
            backup = home / ".codex" / ".tmp" / "plugins-backup-example"
            backup.mkdir()
            self.assertIsNone(catalog.match(str(backup), "trash"))

    def test_windows_rule_entry_is_disabled(self) -> None:
        with self.assertRaisesRegex(RuleError, "仅支持 macOS"):
            normalized_platform("win32")
        with self.assertRaises(RuleError):
            RuleCatalog("win32", {"HOME": "/tmp/example"})


if __name__ == "__main__":
    unittest.main()
