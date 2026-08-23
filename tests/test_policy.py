from __future__ import annotations

import os
import sys
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "open-cleaner" / "scripts"
sys.path.insert(0, str(SCRIPTS))

from policy import PolicyError, SafetyPolicy, build_action_plan, ensure_plan_fresh, parse_time
from runtime import RuntimeInspector


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

    def test_recent_project_tool_outputs_are_not_authorized_as_green(self) -> None:
        cases = (
            (
                self.home / "Library" / "Developer" / "Xcode" / "DerivedData" / "Current",
                "macos.xcode-derived-data-entry",
            ),
            (
                self.home / "Library" / "Caches" / "ms-playwright",
                "macos.library-cache-entry",
            ),
        )
        guarded = SafetyPolicy(
            home=str(self.home),
            platform="darwin",
            environment=self.environment,
            runtime_inspector=RuntimeInspector(
                "darwin",
                checker=lambda _pattern: False,
                tool_checker=lambda _tool: True,
            ),
        )
        for target, rule_id in cases:
            with self.subTest(rule_id=rule_id):
                target.mkdir(parents=True)
                (target / "active.bin").write_bytes(b"active")
                with self.assertRaises(PolicyError) as raised:
                    guarded.authorize(str(target), "trash", "green", rule_id)
                self.assertEqual(raised.exception.code, "project_not_idle")

    def test_home_root_is_never_authorized(self) -> None:
        with self.assertRaises(PolicyError) as raised:
            self.policy.authorize(str(self.home), "trash", "green")
        self.assertEqual(raised.exception.code, "protected_root")

    def test_windows_policy_entry_is_disabled(self) -> None:
        with self.assertRaisesRegex(ValueError, "仅支持 macOS"):
            SafetyPolicy(
                home=str(self.home), platform="win32", environment=self.environment
            )

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

    def test_reviewed_trash_validates_direct_user_items_before_project_artifacts(self) -> None:
        downloads = self.home / "Downloads"
        downloads.mkdir()
        direct = downloads / "archive.zip"
        direct.write_bytes(b"data")
        nested = downloads / "folder" / "nested.zip"
        nested.parent.mkdir()
        nested.write_bytes(b"nested")

        action = self.policy.authorize(str(direct), "reviewed_trash", "yellow")
        self.assertEqual(action["mode"], "reviewed_trash")
        self.assertEqual(action["rule_id"], "reviewed.user-item")

        cases = [
            (str(direct), "trash", "yellow", "tier_denied"),
            (str(direct), "reviewed_trash", "green", "tier_denied"),
            (str(nested), "reviewed_trash", "yellow", "review_scope_denied"),
            (str(downloads), "reviewed_trash", "yellow", "review_scope_denied"),
        ]
        for path, mode, tier, expected in cases:
            with self.subTest(path=path, mode=mode, tier=tier):
                with self.assertRaises(PolicyError) as raised:
                    self.policy.authorize(path, mode, tier)
                self.assertEqual(raised.exception.code, expected)

    def test_reviewed_trash_rejects_hidden_sensitive_symlink_and_wrong_owner(self) -> None:
        downloads = self.home / "Downloads"
        downloads.mkdir()
        hidden = downloads / ".ssh"
        hidden.mkdir()
        sensitive = downloads / "Application Support"
        sensitive.mkdir()
        real = downloads / "real.zip"
        real.write_bytes(b"data")
        link = downloads / "link.zip"
        link.symlink_to(real)

        for path, expected in (
            (hidden, "review_sensitive_name"),
            (sensitive, "review_sensitive_name"),
            (link, "symlink_denied"),
        ):
            with self.subTest(path=path):
                with self.assertRaises(PolicyError) as raised:
                    self.policy.authorize(str(path), "reviewed_trash", "yellow")
                self.assertEqual(raised.exception.code, expected)

        with patch("policy.owner_matches_current_user", return_value=False):
            with self.assertRaises(PolicyError) as raised:
                self.policy.authorize(str(real), "reviewed_trash", "yellow")
        self.assertEqual(raised.exception.code, "wrong_owner")

    def test_reviewed_trash_still_fails_closed_for_active_known_owner(self) -> None:
        target = self.home / "Downloads" / "ClaudeExport"
        target.parent.mkdir()
        target.mkdir()
        guarded = SafetyPolicy(
            home=str(self.home),
            platform="darwin",
            environment=self.environment,
            runtime_inspector=RuntimeInspector("darwin", checker=lambda _pattern: True),
        )
        with self.assertRaises(PolicyError) as raised:
            guarded.authorize(str(target), "reviewed_trash", "yellow")
        self.assertEqual(raised.exception.code, "owner_active")

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

    def test_active_and_unknown_owner_processes_are_rejected_from_plan(self) -> None:
        target = self.home / ".npm" / "_cacache"
        target.mkdir(parents=True)
        data = analysis_for(
            self.home,
            green=[
                {
                    "name": "npm cache",
                    "path": str(target),
                    "trash_paths": [str(target)],
                    "rule_id": "common.npm-content-cache",
                }
            ],
        )
        for process_state, expected in ((True, "owner_active"), (None, "runtime_unknown")):
            with self.subTest(process_state=process_state):
                inspector = RuntimeInspector(
                    "darwin",
                    checker=lambda _pattern, value=process_state: value,
                    tool_checker=lambda _tool: True,
                )
                plan = build_action_plan(
                    data,
                    home=str(self.home),
                    platform="darwin",
                    environment=self.environment,
                    runtime_inspector=inspector,
                )
                self.assertEqual(plan["actions"], [])
                self.assertEqual(plan["rejected"][0]["code"], expected)

    def test_process_started_after_plan_invalidates_action(self) -> None:
        target = self.home / ".npm" / "_cacache"
        target.mkdir(parents=True)
        state = {"active": False}
        inspector = RuntimeInspector(
            "darwin",
            checker=lambda _pattern: state["active"],
            tool_checker=lambda _tool: True,
        )
        guarded = SafetyPolicy(
            home=str(self.home),
            platform="darwin",
            environment=self.environment,
            runtime_inspector=inspector,
        )
        action = guarded.authorize(
            str(target), "trash", "green", "common.npm-content-cache"
        )
        self.assertEqual(action["runtime"]["state"], "inactive")
        state["active"] = True
        with self.assertRaises(PolicyError) as raised:
            guarded.revalidate(action)
        self.assertEqual(raised.exception.code, "owner_active")


if __name__ == "__main__":
    unittest.main()
