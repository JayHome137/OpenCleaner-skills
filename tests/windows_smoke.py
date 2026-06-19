#!/usr/bin/env python3
"""Windows smoke test for storage-analyzer.

This test is intentionally small and safe. It runs on a temporary profile tree,
checks the Windows scanner shape, builds a static report, and verifies the
Windows recycle-bin helper against a disposable temp file.
"""
from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"无法加载模块: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def make_file(path: Path, size_mb: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as f:
        f.truncate(size_mb * 1024 * 1024)


def main() -> None:
    if not sys.platform.startswith("win"):
        raise SystemExit("windows_smoke.py 只能在 Windows 上运行")

    scan = load_module("storage_scan", ROOT / "storage-analyzer" / "scripts" / "scan.py")
    build_report = load_module("build_report", ROOT / "storage-analyzer" / "scripts" / "build_report.py")
    server = load_module("storage_server", ROOT / "storage-analyzer" / "scripts" / "server.py")

    with tempfile.TemporaryDirectory(prefix="storage-analyzer-win-") as tmp:
        base = Path(tmp)
        profile = base / "Users" / "alice"
        local = profile / "AppData" / "Local"
        roaming = profile / "AppData" / "Roaming"
        temp = local / "Temp"
        downloads = profile / "Downloads"
        program_files = base / "Program Files"
        program_files_x86 = base / "Program Files (x86)"

        for path in (profile, local, roaming, temp, downloads, program_files, program_files_x86):
            path.mkdir(parents=True, exist_ok=True)

        make_file(downloads / "installer.iso", 120)
        make_file(temp / "temp-cache.bin", 70)
        make_file(profile / ".npm" / "npm-cache.bin", 80)
        make_file(local / "pip" / "Cache" / "pip-cache.bin", 90)
        make_file(roaming / "profile-data.bin", 65)
        make_file(local / "app-cache.bin", 75)

        old_env = os.environ.copy()
        os.environ.update(
            {
                "USERPROFILE": str(profile),
                "LOCALAPPDATA": str(local),
                "APPDATA": str(roaming),
                "TEMP": str(temp),
                "USERNAME": "alice",
                "ProgramFiles": str(program_files),
                "ProgramFiles(x86)": str(program_files_x86),
            }
        )
        try:
            system, groups = scan.scan_windows()
        finally:
            os.environ.clear()
            os.environ.update(old_env)

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
        missing = required_groups - groups.keys()
        assert not missing, f"缺少 Windows 分组: {sorted(missing)}"
        assert system["disks"], "Windows runner 应至少枚举到一个盘符"
        assert any(item["name"] == "Downloads" for item in groups["user_profile"])
        assert any(item["name"] == "installer.iso" for item in groups["downloads"])
        assert any(item["path"].endswith(".npm") or item["path"].endswith("pip\\Cache") for item in groups["dev_caches"])

        analysis = {
            "generated_at": "2026-06-19 00:00:00",
            "system": system,
            "top5": [],
            "green": [
                {
                    "name": "临时测试缓存",
                    "path": str(temp),
                    "size_estimate": "约 70 MB",
                    "kill_processes": [],
                    "trash_paths": [str(temp / "temp-cache.bin")],
                    "commands": [],
                }
            ],
            "yellow": [],
            "red": [],
            "summary": {
                "overview": "Windows smoke test report.",
                "tier_stats": {"green": "约 0.1 GB", "yellow": "约 0 GB", "red": "约 0 GB"},
                "priority": [],
                "long_term": [],
            },
        }
        analysis_path = base / "analysis.json"
        report_path = base / "report.html"
        analysis_path.write_text(json.dumps(analysis, ensure_ascii=False), encoding="utf-8")
        old_argv = sys.argv[:]
        try:
            sys.argv = ["build_report.py", str(analysis_path), str(report_path)]
            build_report.main()
        finally:
            sys.argv = old_argv
        html = report_path.read_text(encoding="utf-8")
        assert "Windows smoke test report." in html
        assert "__REPORT_DATA__" not in html

        recycle_probe = base / "recycle-probe.txt"
        recycle_probe.write_text("disposable", encoding="utf-8")
        server._trash_windows(str(recycle_probe))
        assert not recycle_probe.exists(), "SHFileOperationW 后文件仍在原路径"

    print("WINDOWS_SMOKE_OK")


if __name__ == "__main__":
    main()
