from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "open-cleaner" / "scripts"
sys.path.insert(0, str(SCRIPTS))

from contracts import (
    ContractError,
    json_for_script,
    validate_action_plan,
    validate_analysis,
    validate_scan_result,
)


class ContractTests(unittest.TestCase):
    def test_action_plan_requires_explicit_consistent_dry_run_state(self) -> None:
        plan = {
            "schema_version": "1.0",
            "purpose": "dry-run",
            "dry_run": True,
            "plan_id": "a" * 24,
            "generated_at": "2026-08-22T00:00:00Z",
            "expires_at": "2026-08-22T00:30:00Z",
            "platform": "darwin",
            "home": "/Users/example",
            "source_analysis_sha256": "0" * 64,
            "actions": [],
            "rejected": [],
        }
        self.assertIs(validate_action_plan(plan), plan)
        plan["dry_run"] = False
        with self.assertRaises(ContractError):
            validate_action_plan(plan)

    def test_json_for_script_cannot_close_script_element(self) -> None:
        payload = json_for_script({"name": "</script><script>alert(1)</script>"})
        self.assertNotIn("</script>", payload)
        self.assertIn("\\u003c/script\\u003e", payload)

    def test_analysis_requires_version_and_source_hash(self) -> None:
        with self.assertRaises(ContractError):
            validate_analysis({"schema_version": "1.0"})

    def test_green_analysis_item_requires_rule_evidence(self) -> None:
        analysis = {
            "schema_version": "1.0",
            "source_scan_sha256": "0" * 64,
            "generated_at": "2026-08-22 00:00:00",
            "system": {"os": "macOS", "home": "/tmp/home"},
            "top5": [],
            "green": [
                {
                    "name": "unsafe",
                    "path": "/tmp/home/.cache/unsafe",
                    "trash_paths": ["/tmp/home/.cache/unsafe"],
                }
            ],
            "yellow": [],
            "red": [],
            "summary": {
                "overview": "test",
                "tier_stats": {"green": "0 GB", "yellow": "0 GB", "red": "0 GB"},
                "priority": [],
                "long_term": [],
            },
        }
        with self.assertRaises(ContractError):
            validate_analysis(analysis)

    def test_scan_rejects_unknown_schema_version(self) -> None:
        scan = {
            "schema_version": "2.0",
            "generated_at": "now",
            "scan_seconds": 0,
            "system": {},
            "groups": {},
            "coverage": {},
            "errors": [],
        }
        with self.assertRaises(ContractError):
            validate_scan_result(scan)


if __name__ == "__main__":
    unittest.main()
