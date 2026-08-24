#!/usr/bin/env python3
"""Read-only installer package metadata for the analysis report."""
from __future__ import annotations

import os
import plistlib
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional
from urllib.parse import urlsplit

INSTALLER_SUFFIXES = {".dmg", ".pkg", ".iso", ".xip", ".zip"}


def sanitize_source(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme in ("http", "https") and parsed.hostname:
        port = f":{parsed.port}" if parsed.port else ""
        return f"{parsed.scheme}://{parsed.hostname}{port}"
    if parsed.scheme == "file":
        return "本地文件"
    return ""


def _where_from(path: str) -> str:
    try:
        result = subprocess.run(
            ["/usr/bin/xattr", "-px", "com.apple.metadata:kMDItemWhereFroms", path],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
        if result.returncode != 0:
            return ""
        payload = bytes.fromhex("".join(result.stdout.split()))
        values = plistlib.loads(payload)
        if isinstance(values, list) and values:
            return sanitize_source(str(values[0]))
    except (OSError, subprocess.SubprocessError, ValueError, plistlib.InvalidFileException):
        pass
    return ""


def _matching_apps(path: str, app_roots: Iterable[str]) -> list[str]:
    stem = Path(path).stem.casefold()
    matches = []
    for root in app_roots:
        try:
            entries = list(os.scandir(root))
        except OSError:
            continue
        for entry in entries:
            if entry.name.casefold().endswith(".app") and entry.name[:-4].casefold() == stem:
                matches.append(entry.path)
    return sorted(set(matches))


def inspect_installer(
    path: str,
    *,
    app_roots: Iterable[str] = ("/Applications",),
    duplicate_paths: Optional[Iterable[str]] = None,
) -> dict[str, Any]:
    suffix = Path(path).suffix.casefold()
    if suffix not in INSTALLER_SUFFIXES:
        raise ValueError("unsupported installer suffix")
    info = os.stat(path, follow_symlinks=False)
    installed_apps = _matching_apps(path, app_roots)
    duplicates = sorted({os.path.abspath(value) for value in (duplicate_paths or []) if os.path.abspath(value) != os.path.abspath(path)})
    source = _where_from(path)
    return {
        "name": Path(path).name,
        "path": os.path.abspath(path),
        "format": suffix[1:].upper(),
        "size_bytes": int(info.st_size),
        "installed_state": "可能已安装" if installed_apps else "未检测到同名应用",
        "installed_apps": installed_apps,
        "source": source,
        "last_used_at": datetime.fromtimestamp(info.st_atime, timezone.utc).isoformat().replace("+00:00", "Z"),
        "unique_copy_risk": "较低：检测到同名副本" if duplicates else "需确认：未检测到同名副本",
        "duplicates": duplicates,
    }


def collect_installers(items: Iterable[dict[str, Any]], home: str) -> list[dict[str, Any]]:
    candidates = [
        str(item.get("path", ""))
        for item in items
        if Path(str(item.get("path", ""))).suffix.casefold() in INSTALLER_SUFFIXES
        and os.path.isfile(str(item.get("path", "")))
    ]
    by_name: dict[str, list[str]] = {}
    for path in candidates:
        by_name.setdefault(Path(path).name.casefold(), []).append(path)
    app_roots = ("/Applications", str(Path(home) / "Applications"))
    return [
        inspect_installer(path, app_roots=app_roots, duplicate_paths=by_name[Path(path).name.casefold()])
        for path in candidates
    ]
