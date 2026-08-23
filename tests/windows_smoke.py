#!/usr/bin/env python3
"""Windows end-to-end smoke test using only disposable temporary data."""
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "open-cleaner" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import build_report
import classify
import contracts
import file_ops
import policy
import scan


def make_sparse_file(path: Path, size_mb: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as handle:
        handle.truncate(size_mb * 1024 * 1024)


def main() -> None:
    if not sys.platform.startswith("win"):
        raise SystemExit("windows_smoke.py 只能在 Windows 上运行")

    with tempfile.TemporaryDirectory(prefix="open-cleaner-win-") as temporary:
        base = Path(temporary)
        profile = base / "Users" / "alice"
        local = profile / "AppData" / "Local"
        roaming = profile / "AppData" / "Roaming"
        temp = local / "Temp"
        downloads = profile / "Downloads"
        program_files = base / "Program Files"
        program_files_x86 = base / "Program Files (x86)"
        for path in (profile, local, roaming, temp, downloads, program_files, program_files_x86):
            path.mkdir(parents=True, exist_ok=True)

        make_sparse_file(downloads / "installer.iso", 70)
        make_sparse_file(temp / "temp-cache.bin", 60)
        make_sparse_file(profile / ".npm" / "_cacache" / "cache.bin", 60)
        make_sparse_file(local / "pip" / "Cache" / "pip-cache.bin", 60)
        make_sparse_file(roaming / "profile-data.bin", 60)

        original_environment = os.environ.copy()
        os.environ.update(
            {
                "USERPROFILE": str(profile),
                "HOME": str(profile),
                "LOCALAPPDATA": str(local),
                "APPDATA": str(roaming),
                "TEMP": str(temp),
                "USERNAME": "alice",
                "ProgramFiles": str(program_files),
                "ProgramFiles(x86)": str(program_files_x86),
                "OPEN_CLEANER_STATE_DIR": str(base / "state"),
            }
        )
        try:
            scan_result = scan.scan_current(platform="win32", max_workers=2, timeout_seconds=20)
            contracts.validate_scan_result(scan_result)
            analysis = classify.build_analysis(scan_result)
            action_plan = policy.build_action_plan(analysis, platform="win32")
            session_plan = policy.build_action_plan(
                analysis, platform="win32", purpose="session"
            )
            session_policy = policy.SafetyPolicy(platform="win32")
            case_action = session_policy.authorize(
                str(temp / "temp-cache.bin").swapcase(),
                "trash",
                "green",
                "windows.temp-entry",
            )
            assert case_action["rule_id"] == "windows.temp-entry"
        finally:
            os.environ.clear()
            os.environ.update(original_environment)

        required_groups = {
            "user_profile",
            "appdata_local",
            "appdata_roaming",
            "temp",
            "downloads",
            "program_files",
            "program_files_x86",
            "dev_caches",
        }
        assert required_groups <= scan_result["groups"].keys()
        assert scan_result["coverage"]["completed_roots"] > 0
        assert any(item["name"] == "installer.iso" for item in scan_result["groups"]["downloads"])
        assert any(item["name"] == "temp-cache.bin" for item in scan_result["groups"]["temp"])
        assert any(item["rule_id"] == "windows.temp-entry" for item in analysis["green"])
        assert action_plan["actions"], "deterministic rules should authorize disposable cache actions"
        assert action_plan["purpose"] == "dry-run" and action_plan["dry_run"] is True
        assert all(
            action["mode"] in ("open", "trash", "reviewed_trash")
            for action in action_plan["actions"]
        )
        assert any(
            action["mode"] == "reviewed_trash"
            and action["canonical_path"].endswith("installer.iso")
            for action in action_plan["actions"]
        )

        analysis_path = base / "analysis.json"
        report_path = base / "report.html"
        analysis_path.write_text(json.dumps(analysis, ensure_ascii=False), encoding="utf-8")
        build_report.build_report(str(analysis_path), str(report_path))
        html = report_path.read_text(encoding="utf-8")
        assert "存储分析报告" in html
        assert "__REPORT_DATA__" not in html
        assert "const SESSION = null;" in html
        assert "本报告不生成永久删除命令" in html
        assert 'data-mode="rm"' not in html
        assert "data-paths" not in html
        assert "authorizedPaths" not in html

        trash_action = next(
            action
            for action in session_plan["actions"]
            if action["mode"] == "trash" and action["canonical_path"].endswith("temp-cache.bin")
        )
        operator = file_ops.FileOperator(
            session_policy,
            file_ops.OperationLog(base / "state"),
        )
        operation = operator.execute(
            trash_action,
            session_plan["plan_id"],
            session_plan["purpose"],
        )
        assert operation["status"] == "completed", operation
        assert operation["target_exists_after"] is False
        assert "disk_free_delta_bytes" in operation
        assert not (temp / "temp-cache.bin").exists()

    print("WINDOWS_SMOKE_OK")


if __name__ == "__main__":
    main()
