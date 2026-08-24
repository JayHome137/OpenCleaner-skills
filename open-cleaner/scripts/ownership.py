#!/usr/bin/env python3
"""Resolve macOS paths to installed apps and related runtime surfaces."""
from __future__ import annotations

import os
import plistlib
import subprocess
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional


def _read_app(app_path: str) -> dict[str, str]:
    info_path = Path(app_path) / "Contents" / "Info.plist"
    try:
        with info_path.open("rb") as handle:
            info = plistlib.load(handle)
    except (OSError, plistlib.InvalidFileException, ValueError):
        return {}
    bundle_id = str(info.get("CFBundleIdentifier", "")).strip()
    display_name = str(
        info.get("CFBundleDisplayName") or info.get("CFBundleName") or Path(app_path).stem
    ).strip()
    return {"bundle_id": bundle_id, "display_name": display_name, "path": app_path}


def installed_apps(home: str, app_roots: Optional[Iterable[str]] = None) -> list[dict[str, str]]:
    roots = list(app_roots or ("/Applications", str(Path(home) / "Applications")))
    apps: list[dict[str, str]] = []
    for root in roots:
        try:
            entries = list(os.scandir(root))
        except OSError:
            continue
        for entry in entries:
            if entry.is_symlink() or not entry.name.casefold().endswith(".app"):
                continue
            value = _read_app(entry.path)
            if value:
                apps.append(value)
    return apps


def launch_items(home: str) -> list[dict[str, str]]:
    agents: list[dict[str, str]] = []
    for root in (Path(home) / "Library" / "LaunchAgents", Path("/Library/LaunchAgents")):
        try:
            entries = list(root.glob("*.plist"))
        except OSError:
            continue
        for path in entries:
            try:
                with path.open("rb") as handle:
                    value = plistlib.load(handle)
            except (OSError, plistlib.InvalidFileException, ValueError):
                continue
            agents.append(
                {
                    "label": str(value.get("Label", path.stem)),
                    "program": str(value.get("Program", "")),
                    "kind": "background",
                }
            )
    try:
        result = subprocess.run(
            ["/usr/bin/sfltool", "dumpbtm"],
            capture_output=True,
            text=True,
            timeout=8,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        result = None
    if result is not None and result.returncode == 0:
        for block in result.stdout.split("\n\n"):
            fields: dict[str, str] = {}
            for line in block.splitlines():
                if ":" not in line:
                    continue
                key, value = line.split(":", 1)
                fields[key.strip().casefold()] = value.strip()
            label = fields.get("name") or fields.get("identifier")
            if label:
                agents.append(
                    {
                        "label": label,
                        "program": fields.get("url", ""),
                        "kind": "login",
                    }
                )
    return agents


def resolve_ownership(
    path: str,
    home: str,
    *,
    apps: Optional[list[dict[str, str]]] = None,
    launch_agents: Optional[list[dict[str, str]]] = None,
) -> dict[str, Any]:
    normalized = os.path.normcase(os.path.abspath(path)).replace("\\", "/")
    known_apps = installed_apps(home) if apps is None else apps
    bundle_candidates: set[str] = set()
    name_candidates: set[str] = set()
    relationships: list[str] = []
    if ".app/" in normalized.casefold() or normalized.casefold().endswith(".app"):
        marker = normalized.casefold().find(".app") + 4
        app_value = _read_app(normalized[:marker])
        if app_value:
            bundle_candidates.add(app_value["bundle_id"].casefold())
            name_candidates.add(app_value["display_name"].casefold())
            relationships.append("应用本体")
    markers = (
        ("/library/containers/", "沙盒容器"),
        ("/library/group containers/", "共享容器"),
        ("/library/caches/", "缓存"),
        ("/library/application support/", "Application Support"),
    )
    lowered = normalized.casefold()
    leaf = Path(normalized).name.casefold()
    for marker, relationship in markers:
        if marker in lowered:
            suffix = normalized[lowered.index(marker) + len(marker) :].split("/", 1)[0]
            if suffix:
                bundle_candidates.add(suffix.casefold())
                name_candidates.add(suffix.removeprefix("group.").split(".")[-1].casefold())
            relationships.append(relationship)
    name_candidates.add(leaf.removesuffix(".app"))
    matches = []
    for app in known_apps:
        bundle_id = app.get("bundle_id", "").casefold()
        display_name = app.get("display_name", "").casefold()
        stem = Path(app.get("path", "")).stem.casefold()
        bundle_match = bundle_id and any(
            candidate == bundle_id or candidate.endswith(bundle_id) or bundle_id.endswith(candidate)
            for candidate in bundle_candidates
            if candidate
        )
        name_match = any(candidate and candidate in {display_name, stem} for candidate in name_candidates)
        if bundle_match or name_match:
            matches.append(app)
    bundle_id = matches[0].get("bundle_id", "") if matches else next(iter(bundle_candidates), "")
    display_name = matches[0].get("display_name", "") if matches else leaf.removesuffix(".app")
    app_paths = sorted({app.get("path", "") for app in matches if app.get("path")})
    agents = launch_items(home) if launch_agents is None else launch_agents
    login_items = []
    background = []
    for agent in agents:
        text = f"{agent.get('label', '')} {agent.get('program', '')}".casefold()
        if (bundle_id and bundle_id.casefold() in text) or (display_name and display_name.casefold() in text):
            if agent.get("kind", "login") == "background":
                background.append(agent.get("label", ""))
            else:
                login_items.append(agent.get("label", ""))
    return {
        "bundle_id": bundle_id,
        "display_name": display_name,
        "app_paths": app_paths,
        "relationships": sorted(set(relationships)),
        "login_items": sorted({value for value in login_items if value}),
        "background_processes": sorted({value for value in background if value}),
        "shared_bundle_id": bool(bundle_id and len(app_paths) > 1),
        "multiple_versions": len(app_paths) > 1,
    }


def ownership_summary(value: Mapping[str, Any]) -> str:
    app = str(value.get("display_name") or value.get("bundle_id") or "未识别应用")
    relations = "、".join(str(item) for item in value.get("relationships", [])) or "关联数据"
    return f"{app} · {relations}"
