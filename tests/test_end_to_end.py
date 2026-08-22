from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "storage-analyzer" / "scripts"
sys.path.insert(0, str(SCRIPTS))

from build_report import render_report
from classify import build_analysis
from policy import build_action_plan
from scan import ScanEngine, ScanTarget


class EndToEndTests(unittest.TestCase):
    def test_temporary_home_reaches_report_without_file_operations(self) -> None:
        with tempfile.TemporaryDirectory(prefix="storage-e2e-") as temporary:
            home = Path(temporary) / "home"
            cache = home / "Library" / "Caches" / "com.example"
            download = home / "Downloads" / "archive.zip"
            cache.mkdir(parents=True)
            download.parent.mkdir(parents=True)
            (cache / "cache.bin").write_bytes(b"c" * 4096)
            download.write_bytes(b"d" * 2048)

            engine = ScanEngine("win32", max_workers=2, timeout_seconds=5)
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
            analysis = build_analysis(scan, environment=environment)
            plan = build_action_plan(
                analysis,
                home=str(home),
                platform="darwin",
                environment=environment,
            )
            template = (ROOT / "storage-analyzer" / "assets" / "report_template.html").read_text(
                encoding="utf-8"
            )
            report = render_report(analysis, template)
            output = Path(temporary) / "storage-report.html"
            output.write_text(report, encoding="utf-8")

            self.assertEqual(len(analysis["green"]), 1)
            self.assertEqual(len(analysis["yellow"]), 1)
            self.assertEqual({action["mode"] for action in plan["actions"]}, {"open", "trash"})
            self.assertTrue(plan["dry_run"])
            self.assertIn("存储分析报告", output.read_text(encoding="utf-8"))
            self.assertTrue(cache.exists())
            self.assertTrue(download.exists())


if __name__ == "__main__":
    unittest.main()
