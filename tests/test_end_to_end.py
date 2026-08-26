from __future__ import annotations

import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "open-cleaner" / "scripts"
sys.path.insert(0, str(SCRIPTS))

from build_report import render_report
from classify import build_analysis
from policy import build_action_plan
from runtime import RuntimeInspector
from scan import ScanEngine, ScanTarget


class EndToEndTests(unittest.TestCase):
    def test_temporary_home_reaches_report_without_file_operations(self) -> None:
        with tempfile.TemporaryDirectory(prefix="storage-e2e-") as temporary:
            home = Path(temporary) / "home"
            cache = home / "Library" / "Developer" / "Xcode" / "DerivedData" / "com.example"
            download = home / "Downloads" / "archive.zip"
            cache.mkdir(parents=True)
            download.parent.mkdir(parents=True)
            (cache / "cache.bin").write_bytes(b"c" * 4096)
            old = time.time() - 3600
            os.utime(cache, (old, old))
            os.utime(cache / "cache.bin", (old, old))
            download.write_bytes(b"d" * 2048)

            engine = ScanEngine("darwin", max_workers=2, timeout_seconds=5)
            groups, coverage = engine.scan_targets(
                [
                    ScanTarget("caches", str(cache.parent), min_kb=0),
                    ScanTarget("downloads", str(download.parent), min_kb=0),
                ]
            )
            scan = {
                "schema_version": "1.0",
                "generated_at": "2026-08-22 00:00:00",
                "scan_seconds": 0.1,
                "system": {
                    "os": "macOS 15",
                    "home": str(home),
                    "disk_name": "Temporary",
                    "disk_total": "100 GB",
                    "disk_used": "40 GB",
                    "disk_free": "60 GB",
                    "disks": [],
                },
                "groups": groups,
                "coverage": coverage,
                "errors": engine.errors,
            }
            environment = {"HOME": str(home)}
            runtime_inspector = RuntimeInspector(
                "darwin",
                checker=lambda _pattern: False,
                tool_checker=lambda _tool: True,
                open_file_checker=lambda _path: False,
            )
            analysis = build_analysis(scan, environment=environment)
            plan = build_action_plan(
                analysis,
                home=str(home),
                platform="darwin",
                environment=environment,
                runtime_inspector=runtime_inspector,
            )
            template = (ROOT / "open-cleaner" / "assets" / "report_template.html").read_text(
                encoding="utf-8"
            )
            report = render_report(analysis, template)
            output = Path(temporary) / "storage-report.html"
            output.write_text(report, encoding="utf-8")

            self.assertEqual(len(analysis["green"]), 0)
            self.assertEqual(len(analysis["yellow"]), 2)
            self.assertEqual(
                {action["mode"] for action in plan["actions"]},
                {"open", "reviewed_trash"},
            )
            self.assertTrue(plan["dry_run"])
            self.assertIn("存储分析报告", output.read_text(encoding="utf-8"))
            self.assertTrue(cache.exists())
            self.assertTrue(download.exists())


if __name__ == "__main__":
    unittest.main()
