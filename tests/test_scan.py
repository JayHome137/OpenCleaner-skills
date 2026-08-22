from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "storage-analyzer" / "scripts"
sys.path.insert(0, str(SCRIPTS))

from scan import ScanEngine, ScanTarget


class ScanEngineTests(unittest.TestCase):
    def test_scan_deduplicates_scheduled_paths_and_reports_coverage(self) -> None:
        with tempfile.TemporaryDirectory(prefix="storage-scan-") as temp:
            root = Path(temp)
            child = root / "cache"
            child.mkdir()
            (child / "data.bin").write_bytes(b"x" * 4096)
            engine = ScanEngine("win32", max_workers=2, timeout_seconds=5)
            groups, coverage = engine.scan_targets(
                [
                    ScanTarget("first", str(root), min_kb=0),
                    ScanTarget("second", str(child), min_kb=0, mode="exact"),
                ]
            )
            self.assertEqual(coverage["requested_roots"], 2)
            self.assertEqual(coverage["completed_roots"], 2)
            self.assertEqual(coverage["scheduled_paths"], 1)
            self.assertEqual(len(groups["first"]), 1)
            self.assertEqual(groups["second"], [])

    def test_missing_root_is_structured_error(self) -> None:
        with tempfile.TemporaryDirectory(prefix="storage-scan-") as temp:
            missing = str(Path(temp) / "missing")
            engine = ScanEngine("win32", max_workers=1, timeout_seconds=2)
            _groups, coverage = engine.scan_targets([ScanTarget("missing", missing)])
            self.assertEqual(coverage["skipped_roots"], 1)
            self.assertEqual(engine.errors[0]["code"], "missing_root")
            self.assertEqual(engine.errors[0]["path"], missing)

    def test_cancel_before_enumeration_is_structured_and_schedules_nothing(self) -> None:
        with tempfile.TemporaryDirectory(prefix="storage-scan-") as temp:
            engine = ScanEngine("win32", max_workers=1, timeout_seconds=2)
            engine.cancel()
            groups, coverage = engine.scan_targets([ScanTarget("cancelled", temp, min_kb=0)])
            self.assertEqual(groups["cancelled"], [])
            self.assertEqual(coverage["scheduled_paths"], 0)
            self.assertEqual(coverage["skipped_roots"], 1)
            self.assertEqual(engine.errors[0]["code"], "cancelled")

    def test_equal_size_results_have_stable_name_order(self) -> None:
        with tempfile.TemporaryDirectory(prefix="storage-scan-") as temp:
            root = Path(temp)
            for name in ("zeta", "Alpha", "beta"):
                directory = root / name
                directory.mkdir()
                (directory / "same.bin").write_bytes(b"x" * 4096)
            orders = []
            for _ in range(4):
                engine = ScanEngine("win32", max_workers=3, timeout_seconds=5)
                groups, _coverage = engine.scan_targets(
                    [ScanTarget("same", str(root), min_kb=0)]
                )
                orders.append([item["name"] for item in groups["same"]])
            self.assertTrue(all(order == ["Alpha", "beta", "zeta"] for order in orders))


if __name__ == "__main__":
    unittest.main()
