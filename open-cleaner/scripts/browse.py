#!/usr/bin/env python3
"""Bounded read-only directory browsing for registered scan roots."""
from __future__ import annotations

import os
import subprocess
from datetime import datetime, timezone
from typing import Any, Mapping

from rules import canonical_path, is_within
from settings import SettingsError, SettingsStore

MAX_BROWSE_ITEMS = 250
VALID_SORTS = {"name", "size", "modified"}


def _sizes(entries: list[os.DirEntry[str]]) -> dict[str, int | None]:
    sizes: dict[str, int | None] = {}
    directories: list[str] = []
    for entry in entries:
        try:
            if entry.is_file(follow_symlinks=False):
                sizes[entry.path] = int(entry.stat(follow_symlinks=False).st_size)
            elif entry.is_dir(follow_symlinks=False):
                directories.append(entry.path)
        except OSError:
            sizes[entry.path] = None
    if directories:
        try:
            result = subprocess.run(
                ["/usr/bin/du", "-sk", *directories],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            result = None
        if result is not None:
            for line in result.stdout.splitlines():
                fields = line.split("\t", 1)
                if len(fields) == 2 and fields[0].strip().isdigit():
                    sizes[fields[1]] = int(fields[0]) * 1024
    for path in directories:
        sizes.setdefault(path, None)
    return sizes


def browse_directory(
    store: SettingsStore,
    path: str,
    *,
    search: str = "",
    sort: str = "name",
    descending: bool = False,
    min_size_bytes: int = 0,
) -> dict[str, Any]:
    if sort not in VALID_SORTS:
        raise SettingsError("invalid_sort", "排序字段必须是 name、size 或 modified")
    if min_size_bytes < 0:
        raise SettingsError("invalid_size_filter", "大小筛选不能为负数")
    target = canonical_path(path)
    roots = store.load()["scan_roots"]
    if not any(is_within(target, root, include_root=True) for root in roots):
        raise SettingsError("browse_out_of_scope", "目录不在已登记的只读扫描根内")
    if os.path.islink(path) or not os.path.isdir(target):
        raise SettingsError("browse_not_directory", "浏览目标必须是非符号链接目录")
    try:
        entries = [entry for entry in os.scandir(target) if not entry.is_symlink()]
    except OSError as exc:
        raise SettingsError("browse_unreadable", f"无法读取目录：{exc}") from exc
    needle = search.strip().casefold()
    if needle:
        entries = [entry for entry in entries if needle in entry.name.casefold()]
    truncated = len(entries) > MAX_BROWSE_ITEMS
    entries = entries[:MAX_BROWSE_ITEMS]
    sizes = _sizes(entries)
    items = []
    for entry in entries:
        try:
            info = entry.stat(follow_symlinks=False)
            kind = "directory" if entry.is_dir(follow_symlinks=False) else "file"
        except OSError:
            continue
        size = sizes.get(entry.path)
        if size is not None and size < min_size_bytes:
            continue
        if size is None and min_size_bytes > 0:
            continue
        items.append(
            {
                "name": entry.name,
                "path": entry.path,
                "kind": kind,
                "size_bytes": size,
                "modified_at": datetime.fromtimestamp(info.st_mtime, timezone.utc).isoformat().replace("+00:00", "Z"),
                "protected": store.is_path_protected(entry.path),
            }
        )
    keys = {
        "name": lambda item: (str(item["name"]).casefold(), str(item["path"])),
        "size": lambda item: (item["size_bytes"] is None, int(item["size_bytes"] or 0), str(item["name"]).casefold()),
        "modified": lambda item: (str(item["modified_at"]), str(item["name"]).casefold()),
    }
    items.sort(key=keys[sort], reverse=bool(descending))
    root = next(root for root in roots if is_within(target, root, include_root=True))
    parent = os.path.dirname(target) if os.path.normcase(target) != os.path.normcase(root) else ""
    return {"path": target, "root": root, "parent": parent, "items": items, "truncated": truncated}
