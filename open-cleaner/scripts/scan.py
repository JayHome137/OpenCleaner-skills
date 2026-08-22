#!/usr/bin/env python3
"""Bounded, read-only storage scanner for macOS and Windows."""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import platform as platform_module
import re
import shutil
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Optional, Sequence

SCHEMA_VERSION = "1.0"
DEFAULT_MIN_KB = 50 * 1024
DEFAULT_WORKERS = 4
DEFAULT_TIMEOUT_SECONDS = 120
GROUP_ITEM_LIMIT = 40


def configure_text_output() -> None:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")


def human_kb(kilobytes: int) -> str:
    value = float(kilobytes) * 1024
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.1f} {unit}" if unit not in ("B", "KB") else f"{int(value)} {unit}"
        value /= 1024
    return "0 B"


@dataclass(frozen=True)
class ScanTarget:
    group: str
    path: str
    min_kb: int = DEFAULT_MIN_KB
    mode: str = "children"
    exclude_names: tuple[str, ...] = ()


@dataclass(frozen=True)
class SizeTask:
    group: str
    path: str
    name: str
    min_kb: int


class ScanEngine:
    def __init__(
        self,
        platform: str,
        max_workers: int = DEFAULT_WORKERS,
        timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self.platform = platform
        self.max_workers = max(1, min(int(max_workers), 8))
        self.timeout_seconds = max(1, int(timeout_seconds))
        self.errors: list[dict[str, Any]] = []
        self._error_lock = threading.Lock()
        self.cancelled = threading.Event()

    def add_error(self, code: str, path: str, message: str, phase: str = "scan") -> None:
        with self._error_lock:
            self.errors.append(
                {"code": code, "path": path, "message": message, "phase": phase}
            )

    def cancel(self) -> None:
        self.cancelled.set()

    def _list_target(self, target: ScanTarget) -> tuple[list[SizeTask], bool]:
        path = os.path.abspath(os.path.expanduser(target.path))
        if self.cancelled.is_set():
            self.add_error("cancelled", path, "扫描已取消", "enumerate")
            return [], False
        if not os.path.exists(path):
            self.add_error("missing_root", path, "扫描根不存在", "enumerate")
            return [], False
        if os.path.islink(path):
            self.add_error("symlink_root", path, "跳过符号链接扫描根", "enumerate")
            return [], False
        if target.mode == "exact":
            return [SizeTask(target.group, path, os.path.basename(path.rstrip(os.sep)) or path, target.min_kb)], True
        try:
            entries = sorted(os.scandir(path), key=lambda entry: entry.name.casefold())
        except PermissionError:
            self.add_error("permission_denied", path, "没有权限列出扫描根", "enumerate")
            return [], False
        except OSError as exc:
            self.add_error("enumeration_failed", path, str(exc), "enumerate")
            return [], False
        tasks = []
        excludes = {name.casefold() for name in target.exclude_names}
        for entry in entries:
            if entry.name.casefold() in excludes:
                continue
            try:
                if entry.is_symlink():
                    continue
            except OSError as exc:
                self.add_error("metadata_failed", entry.path, str(exc), "enumerate")
                continue
            tasks.append(SizeTask(target.group, entry.path, entry.name, target.min_kb))
        return tasks, True

    def _size_macos(self, task: SizeTask) -> Optional[int]:
        try:
            result = subprocess.run(
                ["/usr/bin/du", "-sk", task.path],
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired:
            self.add_error("timeout", task.path, f"大小统计超过 {self.timeout_seconds}s")
            return None
        except OSError as exc:
            self.add_error("command_failed", task.path, str(exc))
            return None
        if result.returncode != 0:
            detail = (result.stderr or result.stdout or f"du exit {result.returncode}").strip()
            code = "permission_denied" if "permission denied" in detail.lower() or "operation not permitted" in detail.lower() else "command_failed"
            self.add_error(code, task.path, detail[:500])
            return None
        match = re.match(r"\s*(\d+)", result.stdout)
        if not match:
            self.add_error("invalid_size", task.path, "du 未返回可解析的大小")
            return None
        return int(match.group(1))

    def _size_windows(self, task: SizeTask) -> Optional[int]:
        deadline = time.monotonic() + self.timeout_seconds
        total = 0
        stack = [task.path]
        while stack:
            if self.cancelled.is_set():
                self.add_error("cancelled", task.path, "扫描已取消")
                return None
            if time.monotonic() >= deadline:
                self.add_error("timeout", task.path, f"大小统计超过 {self.timeout_seconds}s")
                return None
            current = stack.pop()
            try:
                if os.path.isfile(current):
                    total += os.path.getsize(current)
                    continue
                with os.scandir(current) as entries:
                    for entry in entries:
                        try:
                            if entry.is_symlink():
                                continue
                            if entry.is_file(follow_symlinks=False):
                                total += entry.stat(follow_symlinks=False).st_size
                            elif entry.is_dir(follow_symlinks=False):
                                stack.append(entry.path)
                        except PermissionError:
                            self.add_error("permission_denied", entry.path, "没有权限读取目录项")
                        except OSError as exc:
                            self.add_error("metadata_failed", entry.path, str(exc))
            except PermissionError:
                self.add_error("permission_denied", current, "没有权限读取目录")
            except OSError as exc:
                self.add_error("scan_failed", current, str(exc))
        return total // 1024

    def _measure(self, task: SizeTask) -> Optional[dict[str, Any]]:
        if self.cancelled.is_set():
            return None
        size_kb = self._size_macos(task) if self.platform == "darwin" else self._size_windows(task)
        if size_kb is None or size_kb < task.min_kb:
            return None
        return {
            "name": task.name,
            "path": task.path,
            "size_kb": size_kb,
            "size_h": human_kb(size_kb),
        }

    def scan_targets(self, targets: Sequence[ScanTarget]) -> tuple[dict[str, list[dict[str, Any]]], dict[str, int]]:
        groups: dict[str, list[dict[str, Any]]] = {target.group: [] for target in targets}
        all_tasks: list[SizeTask] = []
        seen_paths: set[str] = set()
        completed_roots = 0
        skipped_roots = 0
        for target in targets:
            tasks, completed = self._list_target(target)
            if completed:
                completed_roots += 1
            else:
                skipped_roots += 1
            for task in tasks:
                key = os.path.normcase(os.path.abspath(task.path))
                if key in seen_paths:
                    continue
                seen_paths.add(key)
                all_tasks.append(task)

        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                future_to_task = {executor.submit(self._measure, task): task for task in all_tasks}
                for future in concurrent.futures.as_completed(future_to_task):
                    task = future_to_task[future]
                    try:
                        item = future.result()
                    except Exception as exc:
                        self.add_error("worker_failed", task.path, str(exc))
                        continue
                    if item is not None:
                        groups[task.group].append(item)
        except KeyboardInterrupt:
            self.cancel()
            raise

        for items in groups.values():
            items.sort(
                key=lambda item: (
                    -int(item["size_kb"]),
                    str(item["name"]).casefold(),
                    os.path.normcase(os.path.abspath(str(item["path"]))),
                )
            )
            del items[GROUP_ITEM_LIMIT:]
        coverage = {
            "requested_roots": len(targets),
            "completed_roots": completed_roots,
            "skipped_roots": skipped_roots,
            "scheduled_paths": len(all_tasks),
            "reported_items": sum(len(items) for items in groups.values()),
        }
        return groups, coverage


def _command(
    command: Sequence[str],
    engine: ScanEngine,
    path: str,
    timeout: int = 15,
    record_error: bool = True,
) -> str:
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        if record_error:
            engine.add_error("probe_failed", path, str(exc), "system_info")
        return ""
    if result.returncode != 0:
        if record_error:
            engine.add_error("probe_failed", path, (result.stderr or f"exit {result.returncode}").strip(), "system_info")
        return ""
    return result.stdout.strip()


def _disk_values(root: str) -> tuple[str, str, str]:
    try:
        total, used, free = shutil.disk_usage(root)
        return human_kb(total // 1024), human_kb(used // 1024), human_kb(free // 1024)
    except OSError:
        return "?", "?", "?"


def system_info_macos(engine: ScanEngine, home: str) -> dict[str, Any]:
    total, used, free = _disk_values("/")
    version = _command(["/usr/bin/sw_vers", "-productVersion"], engine, "/")
    build = _command(["/usr/bin/sw_vers", "-buildVersion"], engine, "/")
    arch = _command(["/usr/bin/uname", "-m"], engine, "/") or platform_module.machine()
    brand = _command(["/usr/sbin/sysctl", "-n", "machdep.cpu.brand_string"], engine, "/", record_error=False)
    disk_info = _command(["/usr/sbin/diskutil", "info", "/"], engine, "/", record_error=False)
    filesystem_match = re.search(r"File System Personality:\s*(.+)", disk_info)
    purgeable_match = re.search(r"Purgeable Space:\s*([\d.,]+ \w+)", disk_info)
    architecture = f"Apple Silicon ({arch})" if arch == "arm64" else arch
    if brand:
        architecture += f" / {brand}"
    return {
        "os": f"macOS {version}".strip(),
        "build": build,
        "arch": architecture,
        "user": os.environ.get("USER", ""),
        "home": home,
        "filesystem": filesystem_match.group(1).strip() if filesystem_match else "APFS",
        "purgeable": purgeable_match.group(1).strip() if purgeable_match else "",
        "disk_name": "Macintosh HD",
        "disk_total": total,
        "disk_used": used,
        "disk_free": free,
        "disks": [{"name": "Macintosh HD", "total": total, "used": used, "free": free}],
    }


def list_windows_disks() -> list[dict[str, str]]:
    disks = []
    for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        root = f"{letter}:\\"
        if os.path.exists(root):
            total, used, free = _disk_values(root)
            disks.append({"name": root, "total": total, "used": used, "free": free})
    return disks


def system_info_windows(home: str) -> dict[str, Any]:
    system_root = os.environ.get("SystemDrive", "C:") + "\\"
    total, used, free = _disk_values(system_root)
    disks = list_windows_disks()
    return {
        "os": f"Windows {platform_module.release()}",
        "build": platform_module.version(),
        "arch": os.environ.get("PROCESSOR_ARCHITECTURE", platform_module.machine()),
        "user": os.environ.get("USERNAME", ""),
        "home": home,
        "filesystem": "NTFS",
        "purgeable": "",
        "disk_name": system_root,
        "disk_total": total,
        "disk_used": used,
        "disk_free": free,
        "disks": disks,
    }


def macos_targets(home: str) -> list[ScanTarget]:
    library = os.path.join(home, "Library")
    return [
        ScanTarget("home", home, 100 * 1024, exclude_names=("Library", "Downloads", ".cache", ".npm", ".gradle")),
        ScanTarget("library", library, exclude_names=("Caches", "Containers", "Group Containers", "Application Support", "Developer")),
        ScanTarget("caches", os.path.join(library, "Caches")),
        ScanTarget("containers", os.path.join(library, "Containers")),
        ScanTarget("group_containers", os.path.join(library, "Group Containers")),
        ScanTarget("app_support", os.path.join(library, "Application Support")),
        ScanTarget("downloads", os.path.join(home, "Downloads")),
        ScanTarget("applications", "/Applications", 100 * 1024),
        ScanTarget("system_library", "/Library", exclude_names=("Developer",)),
        ScanTarget("system_developer", "/Library/Developer", exclude_names=("CoreSimulator",)),
        ScanTarget("core_simulator", "/Library/Developer/CoreSimulator"),
        ScanTarget("private_var", "/private/var"),
        ScanTarget("dev_caches", os.path.join(home, ".cache")),
        ScanTarget("dev_caches", os.path.join(home, ".npm", "_cacache"), mode="exact"),
        ScanTarget("dev_caches", os.path.join(home, ".gradle", "caches")),
        ScanTarget("dev_caches", os.path.join(library, "Developer", "Xcode", "DerivedData")),
        ScanTarget("dev_caches", os.path.join(library, "pnpm", "store")),
    ]


def windows_targets(home: str) -> list[ScanTarget]:
    local = os.environ.get("LOCALAPPDATA", os.path.join(home, "AppData", "Local"))
    roaming = os.environ.get("APPDATA", os.path.join(home, "AppData", "Roaming"))
    temp = os.environ.get("TEMP", os.path.join(local, "Temp"))
    return [
        ScanTarget("user_profile", home, 100 * 1024, exclude_names=("AppData", "Downloads", ".cache", ".npm", ".gradle")),
        ScanTarget("appdata_local", local, exclude_names=("Temp", "pip", "Yarn", "uv", "ms-playwright", "go-build")),
        ScanTarget("appdata_roaming", roaming),
        ScanTarget("temp", temp),
        ScanTarget("downloads", os.path.join(home, "Downloads")),
        ScanTarget("program_files", os.environ.get("ProgramFiles", r"C:\Program Files"), 100 * 1024),
        ScanTarget("program_files_x86", os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"), 100 * 1024),
        ScanTarget("dev_caches", os.path.join(home, ".cache")),
        ScanTarget("dev_caches", os.path.join(home, ".npm", "_cacache"), mode="exact"),
        ScanTarget("dev_caches", os.path.join(home, ".gradle", "caches")),
        ScanTarget("dev_caches", os.path.join(local, "pip", "Cache"), mode="exact"),
        ScanTarget("dev_caches", os.path.join(local, "go-build"), mode="exact"),
        ScanTarget("dev_caches", os.path.join(local, "ms-playwright"), mode="exact"),
    ]


def scan_current(
    platform: Optional[str] = None,
    max_workers: int = DEFAULT_WORKERS,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    selected = platform or sys.platform
    if selected.startswith("win"):
        normalized = "win32"
        home = os.path.abspath(os.environ.get("USERPROFILE", os.path.expanduser("~")))
        targets = windows_targets(home)
    elif selected == "darwin":
        normalized = "darwin"
        home = os.path.abspath(os.path.expanduser("~"))
        targets = macos_targets(home)
    else:
        raise ValueError(f"unsupported platform: {selected}")
    engine = ScanEngine(normalized, max_workers=max_workers, timeout_seconds=timeout_seconds)
    started = time.monotonic()
    groups, coverage = engine.scan_targets(targets)
    system = system_info_macos(engine, home) if normalized == "darwin" else system_info_windows(home)
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "scan_seconds": round(time.monotonic() - started, 1),
        "system": system,
        "groups": groups,
        "coverage": coverage,
        "errors": sorted(engine.errors, key=lambda error: (error["path"], error["code"])),
    }


def parse_args(argv: Optional[Iterable[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--max-workers", type=int, default=DEFAULT_WORKERS)
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT_SECONDS)
    return parser.parse_args(argv)


def main() -> None:
    configure_text_output()
    args = parse_args()
    try:
        result = scan_current(max_workers=args.max_workers, timeout_seconds=args.timeout)
    except ValueError as exc:
        print(json.dumps({"error": "unsupported_platform", "message": str(exc)}, ensure_ascii=False))
        raise SystemExit(2) from exc
    except KeyboardInterrupt as exc:
        print(json.dumps({"error": "cancelled", "message": "扫描已取消"}, ensure_ascii=False))
        raise SystemExit(130) from exc
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
