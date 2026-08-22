#!/usr/bin/env python3
"""macOS end-to-end smoke test using only disposable temporary data."""
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "storage-analyzer" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import build_report
import classify
import contracts
import file_ops
import policy
import scan


def main() -> None:
    if sys.platform != "darwin":
        raise SystemExit("macos_smoke.py 只能在 macOS 上运行")

    with tempfile.TemporaryDirectory(prefix="storage-analyzer-mac-") as temporary:
        base = Path(temporary)
        home = base / "Users" / "alice"
        cache_root = home / "Library" / "Caches"
        cache = cache_root / "com.example.cache"
        download = home / "Downloads" / "archive.zip"
        cache.mkdir(parents=True)
        download.parent.mkdir(parents=True)
        (cache / "cache.bin").write_bytes(b"c" * 4096)
        download.write_bytes(b"d" * 2048)

        engine = scan.ScanEngine("darwin", max_workers=2, timeout_seconds=10)
        groups, coverage = engine.scan_targets(
            [
                scan.ScanTarget("caches", str(cache_root), min_kb=0),
                scan.ScanTarget("downloads", str(download.parent), min_kb=0),
            ]
        )
        scan_result = {
            "schema_version": "1.0",
            "generated_at": "2026-08-22 00:00:00",
            "scan_seconds": 0.1,
            "system": {
                "os": "macOS CI",
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
        contracts.validate_scan_result(scan_result)
        environment = {"HOME": str(home)}
        analysis = classify.build_analysis(scan_result, environment=environment)
        dry_run = policy.build_action_plan(
            analysis,
            home=str(home),
            platform="darwin",
            environment=environment,
        )
        session = policy.build_action_plan(
            analysis,
            home=str(home),
            platform="darwin",
            environment=environment,
            purpose="session",
        )
        assert dry_run["dry_run"] is True
        assert session["dry_run"] is False

        analysis_path = base / "analysis.json"
        report_path = base / "report.html"
        analysis_path.write_text(json.dumps(analysis, ensure_ascii=False), encoding="utf-8")
        build_report.build_report(str(analysis_path), str(report_path))
        assert "存储分析报告" in report_path.read_text(encoding="utf-8")

        action = next(item for item in session["actions"] if item["mode"] == "trash")
        operator = file_ops.FileOperator(
            policy.SafetyPolicy(
                home=str(home), platform="darwin", environment=environment
            ),
            file_ops.OperationLog(base / "state"),
        )
        result = operator.execute(action, session["plan_id"], session["purpose"])
        assert result["status"] == "completed", result
        assert result["target_exists_after"] is False
        assert "disk_free_delta_bytes" in result
        assert not cache.exists()

    print("MACOS_SMOKE_OK")


if __name__ == "__main__":
    main()
