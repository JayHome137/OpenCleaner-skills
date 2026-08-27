from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "open-cleaner" / "scripts"
sys.path.insert(0, str(SCRIPTS))

from classify import build_analysis, build_owner_groups, platform_from_scan
from contracts import ContractError


class ClassificationTests(unittest.TestCase):
    def test_owner_groups_do_not_merge_unrelated_path_hints(self) -> None:
        analysis = {
            "green": [],
            "yellow": [
                {
                    "name": "CloudStorage",
                    "path": "/Users/example/Library/CloudStorage",
                    "size_bytes": 100,
                    "evidence": {"owner": "cloudstorage", "content_profile": "通用模板"},
                },
                {
                    "name": ".cargo",
                    "path": "/Users/example/.cargo",
                    "size_bytes": 200,
                    "evidence": {"owner": ".cargo", "content_profile": "通用模板"},
                },
                {
                    "name": "Google",
                    "path": "/Users/example/Library/Caches/Google",
                    "size_bytes": 300,
                    "ownership": {"bundle_id": "google", "app_paths": []},
                    "runtime": {"id": "chrome", "owner_tool": {"name": "Chrome"}},
                    "evidence": {"owner": "Chrome", "content_profile": "缓存"},
                },
            ],
            "red": [],
        }
        groups = build_owner_groups(analysis)
        by_id = {group["id"]: group for group in groups}
        self.assertEqual(by_id["path-hint:cloudstorage"]["size_bytes"], 100)
        self.assertEqual(by_id["path-hint:.cargo"]["size_bytes"], 200)
        self.assertEqual(by_id["tool:chrome"]["size_bytes"], 300)
        self.assertNotIn("bundle:google", by_id)

    def test_unknown_platform_is_rejected_instead_of_assumed_macos(self) -> None:
        with self.assertRaises(ContractError):
            platform_from_scan({"system": {"os": "Linux"}})

    def test_windows_analysis_entry_is_disabled(self) -> None:
        with self.assertRaisesRegex(ContractError, "仅支持 macOS"):
            platform_from_scan({"system": {"os": "Windows 11"}})

    def test_rules_produce_green_and_unknown_data_stays_yellow(self) -> None:
        with tempfile.TemporaryDirectory(prefix="storage-classify-") as temp:
            home = Path(temp) / "home"
            cache = home / "Library" / "Developer" / "Xcode" / "DerivedData" / "com.example"
            download = home / "Downloads" / "archive.zip"
            cache.mkdir(parents=True)
            download.parent.mkdir()
            download.write_bytes(b"data")
            scan = {
                "schema_version": "1.0",
                "generated_at": "2026-08-22 00:00:00",
                "scan_seconds": 1.0,
                "system": {
                    "os": "macOS 15",
                    "home": str(home),
                    "disk_total": "100 GB",
                    "disk_used": "50 GB",
                    "disk_free": "50 GB",
                    "disks": [],
                },
                "groups": {
                    "caches": [{"name": "com.example", "path": str(cache), "size_kb": 1024, "size_h": "1 MB"}],
                    "downloads": [{"name": "archive.zip", "path": str(download), "size_kb": 2048, "size_h": "2 MB"}],
                },
                "coverage": {"requested_roots": 2, "completed_roots": 2, "skipped_roots": 0},
                "errors": [],
            }
            analysis = build_analysis(scan, environment={"HOME": str(home)})
            self.assertEqual(analysis["green"], [])
            by_name = {item["name"]: item for item in analysis["yellow"]}
            self.assertEqual(by_name["com.example"]["runtime"]["id"], "xcode")
            self.assertNotIn("reviewed_trash_paths", by_name["com.example"])
            self.assertEqual(by_name["archive.zip"]["name"], "archive.zip")
            self.assertEqual(analysis["source_scan_sha256"], analysis["source_scan_sha256"].lower())

    def test_owner_tool_caches_are_explained_without_delete_paths(self) -> None:
        with tempfile.TemporaryDirectory(prefix="storage-classify-") as temp:
            home = Path(temp) / "home"
            paths = {
                "library": home / "Library" / "Caches" / "com.example",
                "npm": home / ".npm" / "_cacache",
                "pnpm": home / "Library" / "pnpm" / "store" / "v3",
                "gradle": home / ".gradle" / "caches" / "modules",
                "go": home / "go" / "pkg" / "mod",
                "codex": home / ".codex" / "cache",
                "claude": home / ".claude" / "cache",
                "codex_temp": home / ".codex" / ".tmp" / "plugins",
            }
            for path in paths.values():
                path.mkdir(parents=True)
            items = [
                {"name": name, "path": str(path), "size_kb": 1, "size_h": "1 KB"}
                for name, path in paths.items()
            ]
            scan = {
                "schema_version": "1.0",
                "generated_at": "2026-08-22 00:00:00",
                "scan_seconds": 0.1,
                "system": {
                    "os": "macOS 15",
                    "home": str(home),
                    "disk_total": "100 GB",
                    "disk_used": "50 GB",
                    "disk_free": "50 GB",
                    "disks": [],
                },
                "groups": {"dev_caches": items},
                "coverage": {"requested_roots": 1, "completed_roots": 1, "skipped_roots": 0},
                "errors": [],
            }
            analysis = build_analysis(scan, environment={"HOME": str(home)})
            by_name = {item["name"]: item for item in analysis["green"] + analysis["yellow"]}
            self.assertNotIn("trash_paths", by_name["codex_temp"])
            self.assertNotIn("reviewed_trash_paths", by_name["codex_temp"])
            self.assertNotIn("trash_paths", by_name["library"])
            self.assertNotIn("reviewed_trash_paths", by_name["library"])
            self.assertNotIn("runtime", by_name["library"])
            for name in ("npm", "pnpm", "gradle", "go", "codex", "claude", "codex_temp"):
                with self.subTest(owner=name):
                    item = by_name[name]
                    self.assertNotIn("trash_paths", item)
                    self.assertNotIn("reviewed_trash_paths", item)
                    self.assertEqual(item["runtime"]["owner_tool"]["execution"], "review-only" if name in ("npm", "pnpm", "gradle", "go") else "app-managed")
                    self.assertIn("不提供直接删除入口", item["disposal"])

    def test_duplicate_path_is_classified_and_counted_once(self) -> None:
        with tempfile.TemporaryDirectory(prefix="storage-classify-") as temp:
            home = Path(temp) / "home"
            cache = home / "Library" / "Developer" / "Xcode" / "DerivedData" / "com.example"
            cache.mkdir(parents=True)
            item = {"name": "com.example", "path": str(cache), "size_kb": 2048, "size_h": "2 MB"}
            scan = {
                "schema_version": "1.0",
                "generated_at": "2026-08-22 00:00:00",
                "scan_seconds": 0.1,
                "system": {
                    "os": "macOS 15",
                    "home": str(home),
                    "disk_total": "100 GB",
                    "disk_used": "50 GB",
                    "disk_free": "50 GB",
                    "disks": [],
                },
                "groups": {"caches": [item], "dev_caches": [dict(item)]},
                "coverage": {"requested_roots": 2, "completed_roots": 2, "skipped_roots": 0},
                "errors": [],
            }
            analysis = build_analysis(scan, environment={"HOME": str(home)})
            self.assertEqual(len(analysis["green"]), 0)
            self.assertEqual(len(analysis["yellow"]), 1)
            self.assertEqual(len(analysis["top5"]), 1)
            self.assertEqual(analysis["summary"]["tier_stats"]["green"], "约 0.0 GB")


if __name__ == "__main__":
    unittest.main()
