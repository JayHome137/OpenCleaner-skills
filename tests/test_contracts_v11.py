from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "open-cleaner" / "scripts"
sys.path.insert(0, str(SCRIPTS))

from contracts import (  # noqa: E402
    ContractError,
    blocked_bucket,
    validate_action_plan,
    validate_analysis,
    validate_scan_result,
)


def legacy_scan() -> dict:
    return {
        "schema_version": "1.0",
        "generated_at": "2026-08-26 00:00:00",
        "scan_seconds": 0.1,
        "system": {
            "os": "macOS 15",
            "home": "/Users/example",
            "disk_total": "1 GB",
            "disk_used": "0 GB",
            "disk_free": "1 GB",
            "disks": [],
        },
        "groups": {},
        "coverage": {"requested_roots": 1, "completed_roots": 1, "skipped_roots": 0},
        "errors": [],
    }


def legacy_analysis() -> dict:
    return {
        "schema_version": "1.0",
        "source_scan_sha256": "0" * 64,
        "generated_at": "2026-08-26 00:00:00",
        "system": {"os": "macOS 15", "home": "/Users/example"},
        "top5": [],
        "green": [],
        "yellow": [
            {
                "name": "unknown",
                "path": "/Users/example/unknown",
                "size": "约 1 GB",
                "content_profile": "未知",
                "why_manual": "需查看",
                "disposal": "保留",
                "risk": "可能含用户数据",
            }
        ],
        "red": [],
        "summary": {
            "overview": "旧结果",
            "tier_stats": {"green": "0 GB", "yellow": "1 GB", "red": "0 GB"},
            "priority": [],
            "long_term": [],
        },
    }


def action_plan() -> dict:
    return {
        "schema_version": "1.1",
        "purpose": "dry-run",
        "dry_run": True,
        "plan_id": "p" * 24,
        "generated_at": "2026-08-26T00:00:00Z",
        "expires_at": "2026-08-26T00:30:00Z",
        "platform": "darwin",
        "home": "/Users/example",
        "source_analysis_sha256": "0" * 64,
        "actions": [],
        "rejected": [],
        "decision": {
            "discovery": {
                "green": {"count": 0, "size_bytes": 0},
                "yellow": {"count": 0, "size_bytes": 0},
                "red": {"count": 0, "size_bytes": 0},
            },
            "actionable": {
                "trash": {"count": 0, "size_bytes": 0},
                "reviewed_trash": {"count": 0, "size_bytes": 0},
                "open": {"count": 0, "size_bytes": 0},
            },
            "blocked": {"count": 0, "size_bytes": 0, "reasons": []},
        },
    }


class ContractV11Tests(unittest.TestCase):
    def test_blocked_bucket_is_target_level_not_rejected_action_level(self) -> None:
        actions = [{"path": "/tmp/review", "canonical_path": "/tmp/review"}]
        rejected = [
            {
                "path": "/tmp/review",
                "code": "open_out_of_scope",
                "message": "打开路径超出允许范围：/tmp/review",
                "size_estimate_bytes": 10,
            },
            {
                "path": "/Library/system-only",
                "code": "open_out_of_scope",
                "message": "打开路径超出允许范围：/Library/system-only",
                "size_estimate_bytes": 20,
            },
        ]
        bucket = blocked_bucket(actions, rejected)
        self.assertEqual(bucket["count"], 1)
        self.assertEqual(bucket["size_bytes"], 20)
        self.assertEqual(bucket["reasons"][0]["message"], "路径超出受控打开范围")

    def test_legacy_scan_is_migrated_with_non_published_cache(self) -> None:
        value = legacy_scan()
        self.assertIs(validate_scan_result(value), value)
        self.assertEqual(value["schema_version"], "1.1")
        self.assertEqual(value["system"]["apfs_diagnostics"]["purgeable"]["status"], "unavailable")
        self.assertFalse(value["coverage"]["cache"]["published"])

    def test_legacy_analysis_gets_conservative_evidence_and_coverage(self) -> None:
        value = legacy_analysis()
        validate_analysis(value)
        self.assertEqual(value["schema_version"], "1.1")
        self.assertEqual(value["yellow"][0]["size_bytes"], 0)
        self.assertEqual(value["yellow"][0]["evidence"]["confidence"], "low")
        self.assertEqual(value["coverage_assessment"]["level"], "critical_gaps")

    def test_malformed_legacy_container_raises_contract_error(self) -> None:
        value = legacy_scan()
        value["system"] = []
        with self.assertRaises(ContractError):
            validate_scan_result(value)

    def test_v11_action_plan_rejects_missing_or_inconsistent_decision_fields(self) -> None:
        value = action_plan()
        validate_action_plan(value)
        missing = copy.deepcopy(value)
        missing["decision"]["blocked"] = {"count": 1, "size_bytes": 0, "reasons": []}
        with self.assertRaisesRegex(ContractError, "decision.blocked 与 rejected 不一致"):
            validate_action_plan(missing)
        malformed = copy.deepcopy(value)
        malformed["rejected"] = [{"path": "/tmp/x", "mode": "trash", "code": "x", "message": "x"}]
        with self.assertRaises(ContractError):
            validate_action_plan(malformed)


if __name__ == "__main__":
    unittest.main()
