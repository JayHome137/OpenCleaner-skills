#!/usr/bin/env python3
"""Private, local settings for protected targets and read-only scan roots."""
from __future__ import annotations

import json
import os
import stat
import tempfile
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional

from rules import RuleError, canonical_path, is_within

SETTINGS_VERSION = "1.0"
SETTINGS_FILE = "settings.json"
MAX_SETTINGS_ITEMS = 100


class SettingsError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def default_state_dir(home: str, environment: Mapping[str, str]) -> Path:
    configured = environment.get("OPEN_CLEANER_STATE_DIR", "").strip()
    if configured:
        return Path(os.path.abspath(os.path.expanduser(configured)))
    return Path(home) / ".local" / "state" / "open-cleaner"


def _unique(values: Iterable[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        key = os.path.normcase(value)
        if key not in seen:
            seen.add(key)
            result.append(value)
    return result


class SettingsStore:
    def __init__(
        self,
        home: str,
        environment: Optional[Mapping[str, str]] = None,
        state_dir: Optional[str | Path] = None,
        volume_root: str | Path = "/Volumes",
    ) -> None:
        self.home = canonical_path(os.path.abspath(os.path.expanduser(home)))
        self.environment = dict(os.environ if environment is None else environment)
        self.environment["HOME"] = self.home
        self.state_dir = Path(state_dir) if state_dir is not None else default_state_dir(self.home, self.environment)
        self.path = self.state_dir / SETTINGS_FILE
        self.volume_root = canonical_path(str(volume_root)) if Path(volume_root).exists() else os.path.abspath(str(volume_root))

    def _defaults(self) -> dict[str, Any]:
        return {
            "schema_version": SETTINGS_VERSION,
            "protected_paths": [],
            "protected_apps": [],
            "scan_roots": [self.home],
        }

    def _validate_path(self, raw: str, *, scan_root: bool, allow_app: bool = False) -> str:
        if not isinstance(raw, str) or not raw.strip():
            raise SettingsError("invalid_setting", "设置路径必须是非空字符串")
        original = os.path.abspath(os.path.expanduser(raw))
        if os.path.islink(original):
            raise SettingsError("symlink_denied", f"设置路径不能是符号链接：{original}")
        try:
            target = canonical_path(original)
        except RuleError as exc:
            raise SettingsError("invalid_path", str(exc)) from exc
        if not os.path.exists(target):
            raise SettingsError("missing_path", f"设置路径不存在：{target}")
        if scan_root and not os.path.isdir(target):
            raise SettingsError("scan_root_not_directory", f"扫描根必须是目录：{target}")
        inside_home = is_within(target, self.home, include_root=True)
        inside_volume = is_within(target, self.volume_root, include_root=False)
        inside_applications = allow_app and (
            is_within(target, "/Applications", include_root=False)
            or is_within(target, "/System/Applications", include_root=False)
        )
        if not inside_home and not inside_volume and not inside_applications:
            raise SettingsError("setting_out_of_scope", "只允许登记主目录或 /Volumes 下当前挂载卷中的路径")
        if inside_volume:
            relative = os.path.relpath(target, self.volume_root).split(os.sep)[0]
            mount = os.path.join(self.volume_root, relative)
            if not os.path.ismount(mount):
                raise SettingsError("volume_not_mounted", "外置卷必须是 /Volumes 下当前真实挂载点")
        return target

    def _validate(self, data: Mapping[str, Any]) -> dict[str, Any]:
        if set(data) != {"schema_version", "protected_paths", "protected_apps", "scan_roots"}:
            raise SettingsError("invalid_settings_fields", "设置字段不完整或包含未知字段")
        if data.get("schema_version") != SETTINGS_VERSION:
            raise SettingsError("invalid_settings_version", "不支持的设置版本")
        for key in ("protected_paths", "protected_apps", "scan_roots"):
            if not isinstance(data.get(key), list) or len(data[key]) > MAX_SETTINGS_ITEMS:
                raise SettingsError("invalid_setting", f"{key} 必须是最多 {MAX_SETTINGS_ITEMS} 项的数组")
        protected_paths = _unique(self._validate_path(value, scan_root=False) for value in data["protected_paths"])
        scan_roots = _unique(self._validate_path(value, scan_root=True) for value in data["scan_roots"])
        if not scan_roots:
            raise SettingsError("scan_roots_empty", "至少保留一个只读扫描根")
        protected_apps: list[str] = []
        for value in data["protected_apps"]:
            if not isinstance(value, str) or not value.strip() or len(value.strip()) > 255:
                raise SettingsError("invalid_protected_app", "保护 App 必须是显示名称、Bundle ID 或 .app 路径")
            normalized = value.strip()
            if "/" in normalized or normalized.endswith(".app"):
                normalized = self._validate_path(normalized, scan_root=False, allow_app=True)
            protected_apps.append(normalized)
        return {
            "schema_version": SETTINGS_VERSION,
            "protected_paths": protected_paths,
            "protected_apps": _unique(protected_apps),
            "scan_roots": scan_roots,
        }

    def load(self) -> dict[str, Any]:
        if not self.path.exists():
            return self._defaults()
        try:
            info = os.lstat(self.path)
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                raise SettingsError("unsafe_settings_file", "设置文件必须是普通文件且不能是符号链接")
            if stat.S_IMODE(info.st_mode) & 0o077:
                raise SettingsError("unsafe_settings_permissions", "设置文件权限必须为 0600")
            with self.path.open(encoding="utf-8") as handle:
                value = json.load(handle)
        except SettingsError:
            raise
        except (OSError, json.JSONDecodeError) as exc:
            raise SettingsError("settings_unreadable", f"无法读取设置：{exc}") from exc
        if not isinstance(value, dict):
            raise SettingsError("invalid_settings", "设置顶层必须是对象")
        return self._validate(value)

    def save(self, data: Mapping[str, Any]) -> dict[str, Any]:
        normalized = self._validate(data)
        if self.state_dir.exists() and self.state_dir.is_symlink():
            raise SettingsError("unsafe_state_dir", "状态目录不能是符号链接")
        self.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.state_dir, 0o700)
        fd, temporary = tempfile.mkstemp(prefix=".settings-", suffix=".json", dir=self.state_dir)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(normalized, handle, ensure_ascii=False, indent=2)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, self.path)
            os.chmod(self.path, 0o600)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
        return normalized

    def is_path_protected(self, path: str) -> bool:
        target = canonical_path(path)
        return any(is_within(target, root, include_root=True) for root in self.load()["protected_paths"])

    def is_app_protected(self, ownership: Mapping[str, Any]) -> bool:
        values = {
            str(ownership.get("bundle_id", "")).casefold(),
            str(ownership.get("display_name", "")).casefold(),
            *(os.path.normcase(str(path)).casefold() for path in ownership.get("app_paths", [])),
        }
        return any(os.path.normcase(value).casefold() in values for value in self.load()["protected_apps"])
