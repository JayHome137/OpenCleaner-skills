#!/usr/bin/env python3
"""Fail-closed policy and short-lived action plans for report operations."""
from __future__ import annotations

import os
import secrets
import stat
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional

from contracts import ACTION_PLAN_SCHEMA_VERSION, canonical_sha256, validate_action_plan, validate_analysis
from project_artifacts import (
    ProjectArtifactError,
    inspect_artifact_activity,
    inspect_project_artifact,
)
from rules import RuleCatalog, RuleError, canonical_path, is_within, normalized_platform
from runtime import RuntimeInspector
from ownership import installed_apps, resolve_ownership
from settings import SettingsStore

PLAN_TTL_MINUTES = 30
MAX_PLAN_ACTIONS = 200
MUTATING_MODES = ("trash", "reviewed_trash")


class PolicyError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def isoformat(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_time(value: str) -> datetime:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise PolicyError("invalid_time", "操作计划时间格式无效") from exc


def capture_identity(path: str) -> dict[str, Any]:
    try:
        info = os.lstat(path)
    except OSError as exc:
        raise PolicyError("missing_path", f"目标不存在或不可读取：{path}") from exc
    if stat.S_ISLNK(info.st_mode):
        raise PolicyError("symlink_denied", f"拒绝符号链接目标：{path}")
    if stat.S_ISDIR(info.st_mode):
        kind = "directory"
    elif stat.S_ISREG(info.st_mode):
        kind = "file"
    else:
        raise PolicyError("unsupported_file_type", f"拒绝非常规文件目标：{path}")
    return {
        "device": int(info.st_dev),
        "inode": int(info.st_ino),
        "mode": int(stat.S_IFMT(info.st_mode)),
        "kind": kind,
        "size": int(info.st_size),
        "mtime_ns": int(getattr(info, "st_mtime_ns", int(info.st_mtime * 1_000_000_000))),
    }


def identities_match(
    expected: Mapping[str, Any],
    actual: Mapping[str, Any],
    include_metadata: bool = True,
) -> bool:
    keys = ("device", "inode", "mode", "kind")
    if include_metadata:
        keys += ("size", "mtime_ns")
    return all(expected.get(key) == actual.get(key) for key in keys)


def _windows_owner_matches_current_user(path: str) -> bool:
    import ctypes
    from ctypes import wintypes

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32.GetNamedSecurityInfoW.argtypes = [
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
    ]
    advapi32.GetNamedSecurityInfoW.restype = wintypes.DWORD
    advapi32.OpenProcessToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    advapi32.OpenProcessToken.restype = wintypes.BOOL
    advapi32.GetTokenInformation.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.GetTokenInformation.restype = wintypes.BOOL
    advapi32.EqualSid.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    advapi32.EqualSid.restype = wintypes.BOOL
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]

    owner_sid = ctypes.c_void_p()
    security_descriptor = ctypes.c_void_p()
    token = wintypes.HANDLE()
    token_buffer = None
    try:
        result = advapi32.GetNamedSecurityInfoW(
            path,
            1,
            1,
            ctypes.byref(owner_sid),
            None,
            None,
            None,
            ctypes.byref(security_descriptor),
        )
        if result != 0 or not owner_sid:
            return False
        if not advapi32.OpenProcessToken(
            kernel32.GetCurrentProcess(), 0x0008, ctypes.byref(token)
        ):
            return False
        required = wintypes.DWORD()
        advapi32.GetTokenInformation(token, 1, None, 0, ctypes.byref(required))
        if not required.value:
            return False
        token_buffer = ctypes.create_string_buffer(required.value)
        if not advapi32.GetTokenInformation(
            token,
            1,
            token_buffer,
            required.value,
            ctypes.byref(required),
        ):
            return False
        token_user_sid = ctypes.cast(token_buffer, ctypes.POINTER(ctypes.c_void_p))[0]
        return bool(advapi32.EqualSid(owner_sid, token_user_sid))
    except (AttributeError, OSError):
        return False
    finally:
        if token:
            kernel32.CloseHandle(token)
        if security_descriptor:
            kernel32.LocalFree(security_descriptor)


def owner_matches_current_user(path: str, platform: str) -> bool:
    if platform == "win32":
        return _windows_owner_matches_current_user(path)
    try:
        return int(os.lstat(path).st_uid) == int(os.getuid())
    except (AttributeError, OSError):
        return False


def sqlite_live_set(path: str) -> Optional[bool]:
    """Return true when a target contains a SQLite database with live sidecars."""
    if os.path.isfile(path):
        lowered = path.casefold()
        if lowered.endswith("-wal") or lowered.endswith("-shm"):
            return True
        return any(os.path.exists(path + suffix) for suffix in ("-wal", "-shm"))
    if not os.path.isdir(path):
        return False
    try:
        result = subprocess.run(
            [
                "/usr/bin/find", path, "-type", "f", "(",
                "-name", "*-wal", "-o", "-name", "*-shm", ")", "-print", "-quit",
            ],
            capture_output=True,
            text=True,
            timeout=8,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    return bool(result.stdout.strip())


class SafetyPolicy:
    def __init__(
        self,
        home: Optional[str] = None,
        platform: Optional[str] = None,
        environment: Optional[Mapping[str, str]] = None,
        catalog: Optional[RuleCatalog] = None,
        runtime_inspector: Optional[RuntimeInspector] = None,
        settings_store: Optional[SettingsStore] = None,
    ) -> None:
        self.platform = normalized_platform(platform)
        self.home_input = os.path.abspath(os.path.expanduser(home or "~"))
        self.home = canonical_path(self.home_input)
        self.environment = dict(os.environ if environment is None else environment)
        self.environment["HOME"] = self.home
        self.catalog = catalog or RuleCatalog(self.platform, self.environment)
        self.runtime_inspector = runtime_inspector or RuntimeInspector(self.platform)
        self.settings_store = settings_store or SettingsStore(
            self.home,
            self.environment,
        )
        self._ownership_apps: Optional[list[dict[str, str]]] = None

    def _reject_user_symlink_components(self, original: str) -> None:
        if not is_within(original, self.home_input):
            if os.path.islink(original):
                raise PolicyError("symlink_denied", f"拒绝符号链接目标：{original}")
            return
        current = original
        while os.path.normcase(current) != os.path.normcase(self.home_input):
            if os.path.islink(current):
                raise PolicyError("symlink_denied", f"拒绝主目录内的符号链接路径：{original}")
            parent = os.path.dirname(current)
            if parent == current:
                break
            current = parent

    def _exact_protected_roots(self) -> tuple[str, ...]:
        roots = [
            self.home,
            os.path.join(self.home, ".config"),
            os.path.join(self.home, ".Trash"),
        ]
        if self.platform == "darwin":
            roots.extend(
                (
                    os.path.join(self.home, "Library"),
                    "/",
                    "/Applications",
                    "/Library",
                    "/System",
                    "/Users",
                    "/Volumes",
                    "/private",
                )
            )
        else:
            for key in ("SystemDrive", "ProgramFiles", "ProgramFiles(x86)"):
                value = self.environment.get(key)
                if value:
                    roots.append(value)
        return tuple(canonical_path(root) for root in roots if os.path.isabs(os.path.expanduser(root)))

    def _sensitive_subtrees(self) -> tuple[str, ...]:
        relative = [
            ".ssh",
            ".gnupg",
            ".aws",
            ".azure",
            ".kube",
            "Library/Keychains",
            "Library/Mail",
            "Library/Messages",
            "Library/Safari",
            "Library/Application Support",
            "Library/Containers",
            "Library/Group Containers",
        ]
        if self.platform == "win32":
            relative.extend(("AppData/Roaming", "Documents", "Desktop"))
        return tuple(canonical_path(os.path.join(self.home, part)) for part in relative)

    def _reject_protected(self, path: str, mode: str) -> None:
        if any(os.path.normcase(path) == os.path.normcase(root) for root in self._exact_protected_roots()):
            raise PolicyError("protected_root", f"拒绝整体操作受保护根目录：{path}")
        if mode in MUTATING_MODES:
            for root in self._sensitive_subtrees():
                if is_within(path, root):
                    raise PolicyError("sensitive_data", f"拒绝操作敏感数据目录：{path}")
        trash_root = canonical_path(os.path.join(self.home, ".Trash"))
        if is_within(path, trash_root):
            raise PolicyError("trash_root", f"拒绝再次操作废纸篓内容：{path}")
        if mode in MUTATING_MODES and self.settings_store.is_path_protected(path):
            raise PolicyError("user_protected", "目标已加入永久保护列表，不会建议或执行处置")

    def _authorize_open(self, path: str) -> None:
        allowed = is_within(path, self.home, include_root=False)
        if self.platform == "darwin":
            allowed = allowed or is_within(path, "/Applications", include_root=False)
        else:
            for key in ("ProgramFiles", "ProgramFiles(x86)"):
                root = self.environment.get(key)
                if root:
                    allowed = allowed or is_within(path, canonical_path(root), include_root=False)
        if not allowed:
            raise PolicyError("open_out_of_scope", f"打开路径超出允许范围：{path}")

    def _review_roots(self) -> tuple[str, ...]:
        roots = [os.path.join(self.home, "Downloads")]
        if self.platform == "darwin":
            roots.append("/private/tmp")
            temp_root = self.environment.get("TMPDIR")
            if temp_root:
                roots.append(temp_root)
        else:
            temp_root = self.environment.get("TEMP")
            if temp_root:
                roots.append(temp_root)
        resolved = []
        for root in roots:
            try:
                resolved.append(canonical_path(root))
            except RuleError:
                continue
        return tuple(dict.fromkeys(resolved))

    def _authorize_reviewed_trash(self, target: str) -> dict[str, Any]:
        direct_review = any(
            os.path.normcase(os.path.dirname(target)) == os.path.normcase(root)
            for root in self._review_roots()
        )
        if direct_review:
            name = os.path.basename(target).casefold()
            if name.startswith(".") or name in {
                "application support",
                "containers",
                "group containers",
                "documents",
                "keychains",
            }:
                raise PolicyError("review_sensitive_name", "人工复核目标疑似敏感目录，已阻止处置")
            authorization = {
                "rule_id": "reviewed.user-item",
                "recovery": "目标只会移入废纸篓，可在清空前恢复。",
                "risk": "这是人工复核的数据项，可能包含唯一副本或仍需使用的内容。",
                "non_targets": [
                    "下载或临时目录根本身",
                    "下载或临时目录的深层后代",
                    "敏感目录、应用数据、容器数据、系统路径和符号链接",
                ],
            }
        else:
            if any(is_within(target, root, include_root=True) for root in self._review_roots()):
                raise PolicyError(
                    "review_scope_denied",
                    "人工复核目标必须是下载或临时目录的当前用户直接子项",
                )
            try:
                project = inspect_project_artifact(target, self.home, self.environment)
            except ProjectArtifactError as exc:
                raise PolicyError(exc.code, str(exc)) from exc
            authorization = {
                "rule_id": "reviewed.project-artifact",
                "recovery": "项目源码和构建清单保持不变；目标可由项目工具重新生成。",
                "risk": "下一次构建或测试会变慢，必要时需要重新下载依赖。",
                "non_targets": [
                    "项目源码、锁文件和配置",
                    "Archives、发布包、签名产物和项目根目录",
                    "node_modules、虚拟环境和共享依赖仓库",
                ],
                "project": project,
            }
        if not owner_matches_current_user(target, self.platform):
            raise PolicyError("wrong_owner", "目标不属于当前用户，已阻止处置")
        return authorization

    def authorize(
        self,
        path: str,
        mode: str,
        tier: str,
        requested_rule_id: Optional[str] = None,
    ) -> dict[str, Any]:
        if mode not in ("open", "trash", "reviewed_trash"):
            raise PolicyError("unsupported_mode", f"不支持的操作：{mode}")
        try:
            original = os.path.abspath(os.path.expanduser(path))
            target = canonical_path(original)
        except RuleError as exc:
            raise PolicyError("invalid_path", str(exc)) from exc
        self._reject_user_symlink_components(original)
        self._reject_protected(target, mode)
        identity = capture_identity(target)
        parent_identity = capture_identity(os.path.dirname(target))
        rule_id = "open.review"
        recovery = ""
        risk = ""
        non_targets: list[str] = []
        if mode == "open":
            self._authorize_open(target)
        elif mode == "trash":
            if tier != "green":
                raise PolicyError("tier_denied", "普通处置只允许确定性规则授权的绿灯目标")
            if not is_within(target, self.home, include_root=False):
                raise PolicyError("trash_out_of_scope", "只允许处置用户主目录内的目标")
            rule = self.catalog.match(target, "trash", requested_rule_id)
            if rule is None:
                raise PolicyError("no_matching_rule", f"没有确定性规则授权该路径：{target}")
            rule_id = rule.id
            recovery = rule.recovery
            risk = rule.risk
            non_targets = list(rule.non_targets)
        else:
            if tier != "yellow":
                raise PolicyError("tier_denied", "人工复核处置只允许黄灯目标")
            reviewed = self._authorize_reviewed_trash(target)
            rule_id = reviewed["rule_id"]
            recovery = reviewed["recovery"]
            risk = reviewed["risk"]
            non_targets = reviewed["non_targets"]
        result = {
            "mode": mode,
            "path": original,
            "canonical_path": target,
            "tier": tier,
            "rule_id": rule_id,
            "recovery": recovery,
            "risk": risk,
            "non_targets": non_targets,
            "identity": identity,
            "parent_identity": parent_identity,
        }
        if mode in MUTATING_MODES:
            if self._ownership_apps is None:
                self._ownership_apps = installed_apps(self.home)
            ownership = resolve_ownership(
                target,
                self.home,
                apps=self._ownership_apps,
                launch_agents=[],
            )
            if self.settings_store.is_app_protected(ownership):
                raise PolicyError("app_protected", "所属 App 已加入永久保护列表")
            if ownership.get("shared_bundle_id") or ownership.get("multiple_versions"):
                raise PolicyError("shared_app_identity", "检测到共享 Bundle ID 或多个 App 版本，已阻止处置")
            if ownership.get("bundle_id") or ownership.get("app_paths"):
                result["ownership"] = ownership
            sqlite_state = sqlite_live_set(target)
            if sqlite_state is True:
                raise PolicyError("sqlite_live_set", "检测到 SQLite WAL/SHM 活动文件集，已阻止处置")
            if sqlite_state is None:
                raise PolicyError("sqlite_state_unknown", "无法确认 SQLite 运行态，已阻止处置")
            opened = self.runtime_inspector.inspect_open_files(target)
            if opened is True:
                raise PolicyError("open_files", "目标或其后代仍有打开文件，已阻止处置")
            if opened is None:
                raise PolicyError("open_files_unknown", "无法确认目标是否有打开文件，已阻止处置")
            runtime = self.runtime_inspector.inspect(target, rule_id)
            if runtime:
                if runtime["state"] == "active":
                    raise PolicyError("owner_active", f"{runtime['owner_tool']['name']} 正在运行，已阻止处置")
                if runtime["state"] == "unknown":
                    raise PolicyError("runtime_unknown", "无法确认所有者工具是否正在运行，已阻止处置")
                result["runtime"] = runtime
            workflow_owner = str(runtime.get("id", "")) if runtime else ""
            if (
                rule_id == "macos.xcode-derived-data-entry"
                or os.path.basename(target) == "ms-playwright"
                or workflow_owner in {"pnpm", "npm", "gradle", "go-build", "go-module", "codex", "claude"}
            ):
                try:
                    result["activity"] = inspect_artifact_activity(target, self.environment)
                except ProjectArtifactError as exc:
                    raise PolicyError(exc.code, str(exc)) from exc
        if mode == "reviewed_trash" and rule_id == "reviewed.project-artifact":
            result["project"] = reviewed["project"]
        return result

    def revalidate(self, action: Mapping[str, Any]) -> None:
        target = canonical_path(str(action["path"]))
        if os.path.normcase(target) != os.path.normcase(str(action["canonical_path"])):
            raise PolicyError("path_changed", "目标真实路径已经变化")
        refreshed = self.authorize(
            target,
            str(action["mode"]),
            str(action["tier"]),
            str(action.get("rule_id")) if action.get("mode") == "trash" else None,
        )
        if not identities_match(action["identity"], refreshed["identity"]):
            raise PolicyError("identity_changed", "目标文件身份已经变化，操作计划失效")
        if not identities_match(
            action["parent_identity"],
            refreshed["parent_identity"],
            include_metadata=False,
        ):
            raise PolicyError("parent_changed", "目标父目录身份已经变化，操作计划失效")


def _iter_requested_actions(analysis: Mapping[str, Any]) -> Iterable[tuple[str, str, str, Optional[str], str]]:
    for tier in ("green", "yellow"):
        for item in analysis.get(tier, []):
            name = str(item.get("name", "未命名项目"))
            rule_id = item.get("rule_id")
            for path in item.get("trash_paths") or []:
                yield "trash", str(path), tier, str(rule_id) if rule_id else None, name
            for path in item.get("reviewed_trash_paths") or []:
                yield "reviewed_trash", str(path), tier, None, name
            if tier == "yellow" and item.get("path"):
                yield "open", str(item["path"]), tier, None, name
    for item in analysis.get("red", []):
        name = str(item.get("name", "未命名应用"))
        for path in item.get("app_paths") or []:
            yield "open", str(path), "red", None, name


def build_action_plan(
    analysis: dict[str, Any],
    home: Optional[str] = None,
    platform: Optional[str] = None,
    environment: Optional[Mapping[str, str]] = None,
    now: Optional[datetime] = None,
    purpose: str = "dry-run",
    runtime_inspector: Optional[RuntimeInspector] = None,
    settings_store: Optional[SettingsStore] = None,
) -> dict[str, Any]:
    validate_analysis(analysis)
    if purpose not in ("dry-run", "session"):
        raise PolicyError("invalid_plan_purpose", "操作计划用途必须是 dry-run 或 session")
    policy = SafetyPolicy(
        home=home,
        platform=platform,
        environment=environment,
        runtime_inspector=runtime_inspector,
        settings_store=settings_store,
    )
    try:
        analysis_home = canonical_path(str(analysis["system"]["home"]))
    except RuleError as exc:
        raise PolicyError("invalid_analysis_home", str(exc)) from exc
    if os.path.normcase(analysis_home) != os.path.normcase(policy.home):
        raise PolicyError("home_mismatch", "analysis 主目录与当前策略主目录不一致")
    generated = now or utc_now()
    actions: list[dict[str, Any]] = []
    rejected: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    policy.runtime_inspector.refresh_open_file_snapshot()
    for mode, path, tier, rule_id, name in _iter_requested_actions(analysis):
        if len(actions) >= MAX_PLAN_ACTIONS:
            rejected.append({"path": path, "mode": mode, "code": "plan_limit", "message": "操作计划数量超过上限"})
            continue
        try:
            action = policy.authorize(path, mode, tier, rule_id)
        except PolicyError as exc:
            rejected.append({"path": path, "mode": mode, "code": exc.code, "message": str(exc)})
            continue
        key = (mode, os.path.normcase(action["canonical_path"]))
        if key in seen:
            continue
        seen.add(key)
        action["action_id"] = secrets.token_urlsafe(18)
        action["name"] = name
        actions.append(action)
    policy.runtime_inspector.clear_open_file_snapshot()
    plan = {
        "schema_version": ACTION_PLAN_SCHEMA_VERSION,
        "purpose": purpose,
        "dry_run": purpose == "dry-run",
        "plan_id": secrets.token_urlsafe(24),
        "generated_at": isoformat(generated),
        "expires_at": isoformat(generated + timedelta(minutes=PLAN_TTL_MINUTES)),
        "platform": policy.platform,
        "home": policy.home,
        "source_analysis_sha256": canonical_sha256(analysis),
        "actions": actions,
        "rejected": rejected,
    }
    return validate_action_plan(plan)


def ensure_plan_fresh(plan: Mapping[str, Any], now: Optional[datetime] = None) -> None:
    if parse_time(str(plan["expires_at"])) <= (now or utc_now()):
        raise PolicyError("plan_expired", "操作计划已过期，请重新生成报告")
