from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "open-cleaner" / "scripts"))

from compare_reports import compare  # noqa: E402
from contracts import load_json_object  # noqa: E402


class CompareReportsTests(unittest.TestCase):
    def test_reports_expose_tier_and_total_deltas(self) -> None:
        fixture = load_json_object(ROOT / "tests" / "fixtures" / "sample_analysis.json")
        current = __import__("copy").deepcopy(fixture)
        current["generated_at"] = "2026-08-26 00:00:00"
        current["yellow"][0]["size_bytes"] = 1024
        result = compare(fixture, current)
        self.assertEqual(result["tiers"]["yellow"]["delta_bytes"], 1024)
        self.assertEqual(result["total"]["delta_bytes"], 1024)


if __name__ == "__main__":
    unittest.main()
