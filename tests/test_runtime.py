from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "open-cleaner" / "scripts"
sys.path.insert(0, str(SCRIPTS))

from runtime import RuntimeInspector, owner_profile


class RuntimeTests(unittest.TestCase):
    def test_known_profiles_are_deterministic(self) -> None:
        cases = [
            ("/Users/test/.npm/_cacache/content-v2", "common.npm-content-cache", "npm"),
            ("/Users/test/.gradle/caches/modules", "common.gradle-cache-entry", "gradle"),
            ("/Users/test/Library/pnpm/store/v3", "macos.pnpm-cache-entry", "pnpm"),
            ("/Users/test/go/pkg/mod", "common.go-module-cache", "go-module"),
            ("/Users/test/.codex/.tmp/plugins", "common.codex-plugins-temp", "codex"),
            ("/Users/test/.claude/cache", "common.claude-cache", "claude"),
            ("/Users/test/.docker/buildx", "", "docker"),
            ("/Users/test/.tart/cache", "", "tart"),
        ]
        for path, rule_id, expected in cases:
            with self.subTest(path=path):
                self.assertEqual(owner_profile(path, rule_id)["id"], expected)

    def test_runtime_states_fail_closed(self) -> None:
        path = "/Users/test/.npm/_cacache/content-v2"
        for returned, expected in ((True, "active"), (False, "inactive"), (None, "unknown")):
            with self.subTest(returned=returned):
                inspector = RuntimeInspector(
                    "darwin",
                    checker=lambda _pattern, value=returned: value,
                    tool_checker=lambda _tool: True,
                )
                self.assertEqual(inspector.inspect(path, "common.npm-content-cache")["state"], expected)

    def test_missing_recovery_tool_is_unknown(self) -> None:
        inspector = RuntimeInspector(
            "darwin",
            checker=lambda _pattern: False,
            tool_checker=lambda _tool: False,
        )
        result = inspector.inspect(
            "/Users/test/.npm/_cacache/content-v2",
            "common.npm-content-cache",
        )
        self.assertEqual(result["state"], "unknown")
        self.assertEqual(result["reason"], "owner_tool_missing")

    def test_unknown_owner_requires_no_process_guess(self) -> None:
        called = []
        inspector = RuntimeInspector("darwin", checker=lambda pattern: called.append(pattern))
        self.assertEqual(inspector.inspect("/Users/test/Downloads/archive.zip"), {})
        self.assertEqual(called, [])

    def test_owner_hints_use_exact_roots_and_support_xcode_root(self) -> None:
        self.assertEqual(
            owner_profile("/Users/test/Library/Developer/Xcode/DerivedData")["id"],
            "xcode",
        )
        for path in (
            "/Users/test/.npm/_cacache-old/content",
            "/Users/test/.gradle/caches-other/modules",
            "/Users/test/.codex/cache-old",
            "/Users/test/.claude-config/cache",
            "/Users/test/project/go-build-tool",
        ):
            with self.subTest(path=path):
                self.assertEqual(owner_profile(path, None), {})


if __name__ == "__main__":
    unittest.main()
