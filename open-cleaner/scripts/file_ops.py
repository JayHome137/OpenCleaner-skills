#!/usr/bin/env python3
"""Centralized, recoverable file operations with JSONL history."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable, Mapping, Optional, Union

from policy import PolicyError, SafetyPolicy, isoformat, utc_now


class FileOperationError(OSError):
    """Raised when a guarded operation cannot complete."""


def disk_free_bytes(path: str) -> int:
    try:
        return int(shutil.disk_usage(path).free)
    except OSError as exc:
        raise FileOperationError(f"无法读取磁盘可用空间：{exc}") from exc


def path_is_within(path: str, root: str) -> bool:
    try:
        return os.path.commonpath(
            (os.path.normcase(os.path.realpath(path)), os.path.normcase(os.path.realpath(root)))
        ) == os.path.normcase(os.path.realpath(root))
    except ValueError:
        return False


def default_state_dir() -> Path:
    override = os.environ.get("OPEN_CLEANER_STATE_DIR")
    if override:
        return Path(override).expanduser()
    return Path(os.path.expanduser("~")) / ".local" / "state" / "open-cleaner"


class OperationLog:
    def __init__(self, state_dir: Optional[Union[str, Path]] = None) -> None:
        self.state_dir = Path(state_dir) if state_dir is not None else default_state_dir()
        self.path = self.state_dir / "operations.jsonl"

    def append(self, entry: Mapping[str, Any]) -> None:
        self.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        if os.name != "nt":
            os.chmod(self.state_dir, 0o700)
        line = json.dumps(dict(entry), ensure_ascii=False, sort_keys=True)
        if self.path.is_symlink():
            raise OSError("操作日志不能是符号链接")
        flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(self.path, flags, 0o600)
        if os.name != "nt":
            os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "a", encoding="utf-8", newline="\n") as handle:
            handle.write(line + "\n")


def _trash_macos(path: str) -> None:
    trash_binary = "/usr/bin/trash"
    if os.path.isfile(trash_binary) and os.access(trash_binary, os.X_OK):
        result = subprocess.run(
            [trash_binary, path],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    else:
        script = 'tell application "Finder" to delete (POSIX file %s as alias)' % json.dumps(path)
        result = subprocess.run(
            ["/usr/bin/osascript", "-e", script],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "Trash unavailable").strip()
        raise FileOperationError(detail)


def _trash_windows(path: str) -> None:
    import ctypes
    from ctypes import wintypes

    class SHFILEOPSTRUCTW(ctypes.Structure):
        _fields_ = [
            ("hwnd", wintypes.HWND),
            ("wFunc", wintypes.UINT),
            ("pFrom", wintypes.LPCWSTR),
            ("pTo", wintypes.LPCWSTR),
            ("fFlags", ctypes.c_uint16),
            ("fAnyOperationsAborted", wintypes.BOOL),
            ("hNameMappings", ctypes.c_void_p),
            ("lpszProgressTitle", wintypes.LPCWSTR),
        ]

    operation = SHFILEOPSTRUCTW()
    operation.wFunc = 3
    operation.pFrom = os.path.abspath(path) + "\x00\x00"
    operation.fFlags = 0x0040 | 0x0010 | 0x0004
    result = ctypes.windll.shell32.SHFileOperationW(ctypes.byref(operation))
    if result != 0 or operation.fAnyOperationsAborted:
        raise FileOperationError(f"Windows 回收站操作失败（code={result}）")


def move_to_trash(path: str) -> None:
    if sys.platform == "darwin":
        _trash_macos(path)
    else:
        raise FileOperationError("当前版本的废纸篓操作仅支持 macOS")


def open_in_file_manager(path: str) -> None:
    if sys.platform == "darwin":
        command = ["/usr/bin/open", "-R", path]
    else:
        raise FileOperationError("当前版本的文件管理器操作仅支持 macOS")
    result = subprocess.run(command, capture_output=True, text=True, timeout=15, check=False)
    if result.returncode != 0:
        manager = "访达"
        detail = (result.stderr or result.stdout or f"无法在{manager}打开目标").strip()
        raise FileOperationError(detail)


class FileOperator:
    def __init__(
        self,
        policy: SafetyPolicy,
        operation_log: Optional[OperationLog] = None,
        trash_handler: Optional[Callable[[str], None]] = None,
        open_handler: Optional[Callable[[str], None]] = None,
    ) -> None:
        self.policy = policy
        self.operation_log = operation_log or OperationLog()
        self.trash_handler = trash_handler or move_to_trash
        self.open_handler = open_handler or open_in_file_manager

    def execute(
        self,
        action: Mapping[str, Any],
        plan_id: str,
        plan_purpose: str,
    ) -> dict[str, Any]:
        started = time.monotonic()
        result: dict[str, Any] = {
            "timestamp": isoformat(utc_now()),
            "plan_id": plan_id,
            "plan_purpose": plan_purpose,
            "action_id": action["action_id"],
            "mode": action["mode"],
            "path": action["canonical_path"],
            "rule_id": action.get("rule_id", ""),
            "status": "started",
        }
        log_path = getattr(self.operation_log, "path", None)
        if (
            action.get("mode") in ("trash", "reviewed_trash")
            and log_path is not None
            and path_is_within(str(log_path), str(action["canonical_path"]))
        ):
            result["status"] = "failed"
            result["error"] = "操作日志位于待处理目标内部，已取消操作"
            result["error_code"] = "audit_path_inside_target"
            result["duration_ms"] = round((time.monotonic() - started) * 1000)
            return result
        try:
            self.operation_log.append(result)
        except OSError as exc:
            result["status"] = "failed"
            result["error"] = f"无法写入操作日志，已取消操作：{exc}"
            result["error_code"] = "audit_unavailable"
            result["duration_ms"] = round((time.monotonic() - started) * 1000)
            return result
        try:
            if plan_purpose != "session":
                raise PolicyError("dry_run_only", "Dry Run 计划不能执行文件操作")
            self.policy.revalidate(action)
            if action["mode"] in ("trash", "reviewed_trash"):
                target = str(action["canonical_path"])
                parent = os.path.dirname(target)
                result["disk_free_before_bytes"] = disk_free_bytes(parent)
                self.trash_handler(target)
                result["target_exists_after"] = os.path.lexists(target)
                result["disk_free_after_bytes"] = disk_free_bytes(parent)
                result["disk_free_delta_bytes"] = (
                    result["disk_free_after_bytes"] - result["disk_free_before_bytes"]
                )
                if result["target_exists_after"]:
                    raise FileOperationError("废纸篓操作返回成功，但原路径仍然存在")
            elif action["mode"] == "open":
                self.open_handler(str(action["canonical_path"]))
                result["target_exists_after"] = os.path.lexists(str(action["canonical_path"]))
            else:
                raise FileOperationError("不支持的文件操作")
            result["status"] = "completed"
        except (OSError, PolicyError) as exc:
            result.setdefault(
                "target_exists_after", os.path.lexists(str(action["canonical_path"]))
            )
            result["error"] = str(exc)
            result["error_code"] = getattr(exc, "code", "operation_failed")
            result["status"] = "failed"
        result["duration_ms"] = round((time.monotonic() - started) * 1000)
        try:
            self.operation_log.append(result)
        except OSError as exc:
            result["audit_error"] = str(exc)
        return result
