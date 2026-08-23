from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "open-cleaner" / "scripts"
sys.path.insert(0, str(SCRIPTS))

from classify import build_analysis, platform_from_scan
from contracts import ContractError


class ClassificationTests(unittest.TestCase):
    def test_unknown_platform_is_rejected_instead_of_assumed_macos(self) -> None:
        with self.assertRaises(ContractError):
            platform_from_scan({"system": {"os": "Linux"}})

    def test_windows_analysis_entry_is_disabled(self) -> None:
        with self.assertRaisesRegex(ContractError, "仅支持 macOS"):
            platform_from_scan({"system": {"os": "Windows 11"}})

    def test_rules_produce_green_and_unknown_data_stays_yellow(self) -> None:
        with tempfile.TemporaryDirectory(prefix="storage-classify-") as temp:
            home = Path(temp) / "home"
            cache = home / "Library" / "Caches" / "com.example"
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
            self.assertEqual(analysis["green"][0]["rule_id"], "macos.library-cache-entry")
            self.assertEqual(analysis["yellow"][0]["name"], "archive.zip")
            self.assertEqual(analysis["source_scan_sha256"], analysis["source_scan_sha256"].lower())

    def test_duplicate_path_is_classified_and_counted_once(self) -> None:
        with tempfile.TemporaryDirectory(prefix="storage-classify-") as temp:
            home = Path(temp) / "home"
            cache = home / "Library" / "Caches" / "com.example"
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
            self.assertEqual(len(analysis["green"]), 1)
            self.assertEqual(len(analysis["top5"]), 1)
            self.assertEqual(analysis["summary"]["tier_stats"]["green"], "约 0.0 GB")


if __name__ == "__main__":
    unittest.main()
