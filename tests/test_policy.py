from __future__ import annotations

import os
import sys
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "storage-analyzer" / "scripts"
sys.path.insert(0, str(SCRIPTS))

from policy import PolicyError, SafetyPolicy, build_action_plan, ensure_plan_fresh, parse_time


def analysis_for(home: Path, green=None, yellow=None, red=None):
    normalized_green = []
    for raw in green or []:
        item = dict(raw)
        item.setdefault("name", "cache")
        item.setdefault("path", str(home / "Library" / "Caches" / "cache"))
        item.setdefault("size_estimate", "约 0.0 GB")
        item.setdefault("kill_processes", [])
        item.setdefault("trash_paths", [item["path"]])
        item.setdefault("commands", [])
        item.setdefault("rule_id", "macos.library-cache-entry")
        item.setdefault("rule_reason", "test recovery")
        item.setdefault("rule_risk", "test risk")
        item.setdefault("rule_non_targets", ["test exclusion"])
        normalized_green.append(item)
    return {
        "schema_version": "1.0",
        "source_scan_sha256": "0" * 64,
        "generated_at": "2026-08-22 00:00:00",
        "scan_seconds": 0,
        "system": {"os": "macOS", "home": str(home)},
        "top5": [],
        "green": normalized_green,
        "yellow": yellow or [],
        "red": red or [],
        "summary": {
            "overview": "test",
            "tier_stats": {"green": "约 0 GB", "yellow": "约 0 GB", "red": "约 0 GB"},
            "priority": [],
            "long_term": [],
        },
    }


class PolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="storage-policy-")
        self.home = Path(self.temp.name) / "home"
        self.home.mkdir()
        self.environment = {"HOME": str(self.home)}
        self.policy = SafetyPolicy(
            home=str(self.home), platform="darwin", environment=self.environment
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def make_cache(self, name: str = "com.example") -> Path:
        path = self.home / "Library" / "Caches" / name
        path.mkdir(parents=True)
        (path / "cache.bin").write_bytes(b"cache")
        return path

    def test_deterministic_cache_rule_authorizes_trash(self) -> None:
        target = self.make_cache()
        action = self.policy.authorize(str(target), "trash", "green")
        self.assertEqual(action["rule_id"], "macos.library-cache-entry")
        self.assertEqual(action["mode"], "trash")

    def test_home_root_is_never_authorized(self) -> None:
        with self.assertRaises(PolicyError) as raised:
            self.policy.authorize(str(self.home), "trash", "green")
        self.assertEqual(raised.exception.code, "protected_root")

    @unittest.skipUnless(sys.platform == "darwin", "macOS root semantics require a macOS host")
    def test_macos_system_roots_are_never_authorized(self) -> None:
        for path in ("/", "/Applications", "/Library", "/System"):
            with self.subTest(path=path):
                with self.assertRaises(PolicyError) as raised:
                    self.policy.authorize(path, "open", "red")
                self.assertEqual(raised.exception.code, "protected_root")

    def test_parent_traversal_cannot_escape_cache_rule(self) -> None:
        actual = self.home / "Library" / "Application Support" / "important"
        actual.mkdir(parents=True)
        traversed = self.home / "Library" / "Caches" / ".." / "Application Support" / "important"
        with self.assertRaises(PolicyError) as raised:
            self.policy.authorize(str(traversed), "trash", "green")
        self.assertEqual(raised.exception.code, "sensitive_data")

    def test_protected_root_and_sensitive_path_corpus_fails_closed(self) -> None:
        protected = [
            self.home / ".config",
            self.home / ".Trash",
            self.home / "Library",
            self.home / "Library" / "Keychains" / "login.keychain-db",
            self.home / "Library" / "Application Support" / "Example",
            self.home / ".ssh" / "id_ed25519",
        ]
        for path in protected:
            if path.suffix:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"protected")
            else:
                path.mkdir(parents=True, exist_ok=True)
        for path in protected:
            with self.subTest(path=path):
                with self.assertRaises(PolicyError):
                    self.policy.authorize(str(path), "trash", "green")

    def test_unknown_download_is_not_authorized_for_trash(self) -> None:
        target = self.home / "Downloads" / "archive.zip"
        target.parent.mkdir()
        target.write_bytes(b"data")
        with self.assertRaises(PolicyError) as raised:
            self.policy.authorize(str(target), "trash", "green")
        self.assertEqual(raised.exception.code, "no_matching_rule")

    def test_sensitive_data_can_open_but_cannot_trash(self) -> None:
        target = self.home / "Library" / "Application Support" / "Example"
        target.mkdir(parents=True)
        opened = self.policy.authorize(str(target), "open", "yellow")
        self.assertEqual(opened["mode"], "open")
        with self.assertRaises(PolicyError) as raised:
            self.policy.authorize(str(target), "trash", "yellow")
        self.assertEqual(raised.exception.code, "sensitive_data")

    def test_symlink_target_is_rejected(self) -> None:
        target = self.make_cache("real")
        link = target.parent / "link"
        link.symlink_to(target, target_is_directory=True)
        with self.assertRaises(PolicyError) as raised:
            self.policy.authorize(str(link), "trash", "green")
        self.assertEqual(raised.exception.code, "symlink_denied")

    def test_replaced_target_invalidates_plan(self) -> None:
        target = self.make_cache()
        action = self.policy.authorize(str(target), "trash", "green")
        original = target.with_name("old")
        target.rename(original)
        target.mkdir()
        with self.assertRaises(PolicyError) as raised:
            self.policy.revalidate(action)
        self.assertEqual(raised.exception.code, "identity_changed")

    def test_modified_target_invalidates_plan(self) -> None:
        target = self.make_cache("modified") / "cache.bin"
        action = self.policy.authorize(str(target), "trash", "green")
        target.write_bytes(b"changed cache content")
        with self.assertRaises(PolicyError) as raised:
            self.policy.revalidate(action)
        self.assertEqual(raised.exception.code, "identity_changed")

    def test_replaced_parent_invalidates_plan_even_if_target_inode_is_reused(self) -> None:
        target = self.make_cache("parent-swap") / "cache.bin"
        action = self.policy.authorize(str(target), "trash", "green")
        original_parent = target.parent.with_name("parent-swap-old")
        target.parent.rename(original_parent)
        target.parent.mkdir()
        os.link(original_parent / target.name, target)

        with self.assertRaises(PolicyError) as raised:
            self.policy.revalidate(action)
        self.assertEqual(raised.exception.code, "parent_changed")

    def test_agent_path_without_rule_is_rejected_from_plan(self) -> None:
        target = self.home / "Documents" / "important.txt"
        target.parent.mkdir()
        target.write_text("important", encoding="utf-8")
        data = analysis_for(
            self.home,
            green=[{"name": "wrong", "path": str(target), "trash_paths": [str(target)]}],
        )
        plan = build_action_plan(
            data, home=str(self.home), platform="darwin", environment=self.environment
        )
        self.assertEqual(plan["actions"], [])
        self.assertEqual(plan["rejected"][0]["code"], "no_matching_rule")

    def test_agent_cannot_replace_the_matching_rule_id(self) -> None:
        target = self.make_cache("rule-tamper")
        data = analysis_for(
            self.home,
            green=[
                {
                    "name": "cache",
                    "path": str(target),
                    "trash_paths": [str(target)],
                    "rule_id": "common.user-cache-entry",
                }
            ],
        )
        plan = build_action_plan(
            data, home=str(self.home), platform="darwin", environment=self.environment
        )
        self.assertEqual(plan["actions"], [])
        self.assertEqual(plan["rejected"][0]["code"], "no_matching_rule")

    def test_expired_plan_is_rejected(self) -> None:
        target = self.make_cache()
        data = analysis_for(
            self.home,
            green=[{"name": "cache", "path": str(target), "trash_paths": [str(target)]}],
        )
        plan = build_action_plan(
            data, home=str(self.home), platform="darwin", environment=self.environment
        )
        after_expiry = parse_time(plan["expires_at"]) + timedelta(seconds=1)
        with self.assertRaises(PolicyError) as raised:
            ensure_plan_fresh(plan, now=after_expiry)
        self.assertEqual(raised.exception.code, "plan_expired")

    def test_default_action_plan_is_explicit_dry_run(self) -> None:
        target = self.make_cache("dry-run")
        data = analysis_for(
            self.home,
            green=[{"name": "cache", "path": str(target), "trash_paths": [str(target)]}],
        )
        plan = build_action_plan(
            data, home=str(self.home), platform="darwin", environment=self.environment
        )
        self.assertEqual(plan["purpose"], "dry-run")
        self.assertTrue(plan["dry_run"])
        self.assertEqual(plan["actions"][0]["risk"], "应用首次启动可能变慢，离线内容可能需要重新下载。")
        self.assertTrue(plan["actions"][0]["non_targets"])

    def test_analysis_home_must_match_policy_home(self) -> None:
        data = analysis_for(self.home)
        other_home = self.home.parent / "other-home"
        other_home.mkdir()
        with self.assertRaises(PolicyError) as raised:
            build_action_plan(
                data,
                home=str(other_home),
                platform="darwin",
                environment={"HOME": str(other_home)},
            )
        self.assertEqual(raised.exception.code, "home_mismatch")


if __name__ == "__main__":
    unittest.main()
