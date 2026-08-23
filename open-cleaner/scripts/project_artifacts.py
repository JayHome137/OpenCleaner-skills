#!/usr/bin/env python3
"""Discover and validate project-stage artifacts without granting arbitrary paths."""
from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Optional

from rules import canonical_path, is_within

DEFAULT_IDLE_SECONDS = 30 * 60
PROJECT_MARKERS = (
    "Package.swift",
    "package.json",
    "pyproject.toml",
    "go.mod",
    "Cargo.toml",
    "project.yml",
)
ARTIFACT_NAMES = {
    ".build",
    ".mypy_cache",
    ".nyc_output",
    ".pytest_cache",
    ".ruff_cache",
    "__pycache__",
    "build",
    "coverage",
    "DerivedData",
    "playwright-report",
    "test-results",
}
WALK_PRUNE_NAMES = {
    ".git",
    ".Trash",
    ".venv",
    "Pods",
    "node_modules",
    "target",
    "venv",
}
PROTECTED_BUILD_NAMES = {"Archives"}
PROTECTED_BUILD_SUFFIXES = {".aab", ".dmg", ".ipa", ".pkg", ".xcarchive", ".zip"}


class ProjectArtifactError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def configured_idle_seconds(environment: Mapping[str, str]) -> int:
    raw = environment.get("OPEN_CLEANER_PROJECT_IDLE_SECONDS", str(DEFAULT_IDLE_SECONDS))
    try:
        value = int(raw)
    except ValueError as exc:
        raise ProjectArtifactError("invalid_idle_window", "项目静置时间配置无效") from exc
    if value < DEFAULT_IDLE_SECONDS or value > 7 * 24 * 60 * 60:
        raise ProjectArtifactError("invalid_idle_window", "项目静置时间必须在 30 分钟到 7 天之间")
    return value


def project_search_roots(home: str, environment: Mapping[str, str]) -> tuple[str, ...]:
    home = canonical_path(home)
    configured = environment.get("OPEN_CLEANER_PROJECT_ROOTS", "")
    if configured:
        candidates = configured.split(os.pathsep)
    else:
        candidates = [
            os.path.join(home, "Desktop"),
            os.path.join(home, "Documents", "Claude", "New PR"),
            os.path.join(home, "Documents", "Codex"),
            os.path.join(home, "Developer"),
            os.path.join(home, "Projects"),
            os.path.join(home, "Code"),
            os.path.join(home, ".codex", "worktrees"),
        ]
    roots = []
    for raw in candidates:
        expanded = os.path.abspath(os.path.expanduser(raw))
        if not os.path.isdir(expanded) or os.path.islink(expanded):
            continue
        resolved = canonical_path(expanded)
        if is_within(resolved, home, include_root=False):
            roots.append(resolved)
    return tuple(dict.fromkeys(roots))


def _has_project_marker(path: str) -> bool:
    if any(os.path.isfile(os.path.join(path, marker)) for marker in PROJECT_MARKERS):
        return True
    try:
        return any(entry.is_dir() and entry.name.endswith(".xcodeproj") for entry in os.scandir(path))
    except OSError:
        return False


def find_project_root(
    target: str,
    home: str,
    environment: Mapping[str, str],
) -> str:
    home = canonical_path(home)
    roots = project_search_roots(home, environment)
    current = os.path.dirname(target)
    while is_within(current, home, include_root=False):
        if any(is_within(current, root) for root in roots) and _has_project_marker(current):
            return canonical_path(current)
        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent
    raise ProjectArtifactError("project_marker_missing", "目标不属于具有构建清单的已识别项目")


def _git_output(command: list[str]) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ProjectArtifactError("git_check_failed", f"无法验证 Git 状态：{exc}") from exc


def _validate_git_target(project_root: str, target: str) -> None:
    root_result = _git_output(["git", "-C", project_root, "rev-parse", "--show-toplevel"])
    if root_result.returncode != 0:
        return
    git_root = canonical_path(root_result.stdout.strip())
    if not is_within(target, git_root, include_root=False):
        raise ProjectArtifactError("git_scope_mismatch", "目标不在识别出的 Git 工作区内")
    relative = os.path.relpath(target, git_root)
    tracked = _git_output(["git", "-C", git_root, "ls-files", "--", relative])
    if tracked.returncode != 0:
        raise ProjectArtifactError("git_check_failed", "无法检查项目生成目录的跟踪状态")
    if tracked.stdout.strip():
        raise ProjectArtifactError("tracked_content", "目标包含 Git 已跟踪内容")
    ignored = _git_output(["git", "-C", git_root, "check-ignore", "-q", "--", relative])
    if ignored.returncode == 1:
        raise ProjectArtifactError("not_git_ignored", "Git 项目只允许处置明确 ignored 的生成目录")
    if ignored.returncode != 0:
        raise ProjectArtifactError("git_check_failed", "无法检查项目生成目录的 ignored 状态")


def _latest_tree_mtime_ns(target: str) -> int:
    try:
        latest = int(os.lstat(target).st_mtime_ns)
        for root, directories, files in os.walk(target, followlinks=False):
            for name in directories + files:
                path = os.path.join(root, name)
                info = os.lstat(path)
                latest = max(latest, int(info.st_mtime_ns))
        return latest
    except OSError as exc:
        raise ProjectArtifactError("artifact_unreadable", f"无法完整读取项目生成目录：{exc}") from exc


def _default_open_file_check(target: str) -> Optional[bool]:
    if sys_platform() != "darwin":
        return None
    try:
        result = subprocess.run(
            ["/usr/sbin/lsof", "-n", "-F", "n"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode not in (0, 1):
        return None
    prefix = target.rstrip(os.sep) + os.sep
    return any(line.startswith("n") and (line[1:] == target or line[1:].startswith(prefix)) for line in result.stdout.splitlines())


def sys_platform() -> str:
    import sys

    return sys.platform


def _validate_build_contents(target: str) -> None:
    if os.path.basename(target) != "build":
        return
    for root, directories, files in os.walk(target, followlinks=False):
        if any(name in PROTECTED_BUILD_NAMES for name in directories):
            raise ProjectArtifactError("protected_build_output", "build 内含 Archives，必须保留并拆分复核")
        for name in files:
            if Path(name).suffix.casefold() in PROTECTED_BUILD_SUFFIXES:
                raise ProjectArtifactError("protected_build_output", "build 内含发布或归档产物，不能整体处置")


def inspect_artifact_activity(
    target: str,
    environment: Mapping[str, str],
    *,
    now_ns: Optional[int] = None,
    open_file_checker: Optional[Callable[[str], Optional[bool]]] = None,
) -> dict[str, int]:
    idle_seconds = configured_idle_seconds(environment)
    latest_mtime_ns = _latest_tree_mtime_ns(target)
    current_ns = int(time.time_ns() if now_ns is None else now_ns)
    if current_ns - latest_mtime_ns < idle_seconds * 1_000_000_000:
        raise ProjectArtifactError("project_not_idle", f"生成目录尚未静置 {idle_seconds // 60} 分钟")
    opened = (open_file_checker or _default_open_file_check)(target)
    if opened is True:
        raise ProjectArtifactError("project_artifact_active", "生成目录仍有打开文件")
    if opened is None:
        raise ProjectArtifactError("project_activity_unknown", "无法确认生成目录是否仍在使用")
    return {"idle_seconds": idle_seconds, "latest_mtime_ns": latest_mtime_ns}


def inspect_project_artifact(
    target: str,
    home: str,
    environment: Mapping[str, str],
    *,
    now_ns: Optional[int] = None,
    open_file_checker: Optional[Callable[[str], Optional[bool]]] = None,
) -> dict[str, Any]:
    home = canonical_path(home)
    canonical = canonical_path(target)
    if not is_within(canonical, home, include_root=False):
        raise ProjectArtifactError("project_out_of_scope", "项目生成目录必须位于用户主目录内")
    if os.path.basename(canonical) not in ARTIFACT_NAMES:
        raise ProjectArtifactError("artifact_name_denied", "目标名称不在项目生成目录 allowlist 中")
    project_root = find_project_root(canonical, home, environment)
    _validate_git_target(project_root, canonical)
    _validate_build_contents(canonical)
    activity = inspect_artifact_activity(
        canonical,
        environment,
        now_ns=now_ns,
        open_file_checker=open_file_checker,
    )
    return {
        "project_root": project_root,
        "artifact_kind": os.path.basename(canonical),
        **activity,
    }


def discover_artifact_paths(
    home: str,
    environment: Mapping[str, str],
) -> Iterable[str]:
    home = canonical_path(home)
    seen: set[str] = set()
    for search_root in project_search_roots(home, environment):
        for root, directories, _files in os.walk(search_root, followlinks=False):
            directories[:] = [
                name
                for name in directories
                if name not in WALK_PRUNE_NAMES and not os.path.islink(os.path.join(root, name))
            ]
            for name in list(directories):
                if name not in ARTIFACT_NAMES:
                    continue
                path = canonical_path(os.path.join(root, name))
                if path not in seen:
                    seen.add(path)
                    yield path
                directories.remove(name)
