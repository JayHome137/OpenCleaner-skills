#!/usr/bin/env python3
"""Build an OpenCleaner analysis augmented with project-stage artifacts."""
from __future__ import annotations

import argparse
import copy
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from classify import build_analysis, build_owner_groups, format_gb  # noqa: E402
from contracts import ContractError, validate_analysis  # noqa: E402
from project_artifacts import (  # noqa: E402
    ProjectArtifactError,
    configured_idle_seconds,
    discover_artifact_paths,
    inspect_project_artifact,
)
from scan import configure_text_output, scan_current  # noqa: E402

DEFAULT_MIN_KB = 50 * 1024
MAX_DISCOVERED_ARTIFACTS = 200


def _size_kb(path: str) -> int:
    try:
        result = subprocess.run(
            ["/usr/bin/du", "-sk", path],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return 0
    if result.returncode != 0:
        return 0
    try:
        return int(result.stdout.split()[0])
    except (IndexError, ValueError):
        return 0


def augment_with_project_artifacts(
    analysis: dict[str, Any],
    environment: Optional[Mapping[str, str]] = None,
    min_kb: int = DEFAULT_MIN_KB,
) -> dict[str, Any]:
    validate_analysis(analysis)
    analysis = copy.deepcopy(analysis)
    normalized_min_kb = max(0, int(min_kb))
    env = dict(os.environ if environment is None else environment)
    home = str(analysis["system"]["home"])
    env["HOME"] = home
    idle_seconds = configured_idle_seconds(env)
    known = {
        os.path.normcase(os.path.abspath(str(item.get("path", ""))))
        for tier in ("green", "yellow", "red")
        for item in analysis.get(tier, [])
    }
    discovered = 0
    actionable = 0
    actionable_kb = 0
    for path in discover_artifact_paths(home, env):
        if discovered >= MAX_DISCOVERED_ARTIFACTS:
            break
        key = os.path.normcase(os.path.abspath(path))
        if key in known:
            continue
        size_kb = _size_kb(path)
        if size_kb < normalized_min_kb:
            continue
        discovered += 1
        card = {
            "name": f"项目生成目录：{os.path.basename(path)}",
            "path": path,
            "size": format_gb(size_kb),
            "size_bytes": size_kb * 1024,
            "content_profile": "项目构建或测试阶段产生的可重建目录。",
            "why_manual": "只有生成目录边界、项目清单、Git 状态、静置期和打开文件检查全部通过后才能移入废纸篓。",
            "disposal": "保留源码、锁文件、归档和发布产物；本目标只通过 reviewed_trash 批次确认处理。",
            "risk": "后续首次构建会变慢；若恢复契约或项目状态变化，本次计划会被拒绝。",
            "evidence": {
                "owner": "当前项目",
                "confidence": "high",
                "sources": ["项目清单与构建系统", "Git tracked/ignored 状态", "静置期与打开文件检查"],
                "largest_children": [],
                "content_profile": "项目构建或测试阶段产生的可重建目录。",
                "recommended_owner_action": "仅在全部阶段门通过后，通过 reviewed_trash 二次确认处理。",
                "unknown_reason": "",
            },
        }
        try:
            metadata = inspect_project_artifact(path, home, env)
        except ProjectArtifactError as exc:
            card["why_manual"] = f"当前不可处置：{exc}"
            card["stage_status"] = {"state": "deferred", "code": exc.code}
        else:
            card["reviewed_trash_paths"] = [path]
            card["project_artifact"] = metadata
            card["stage_status"] = {"state": "ready", "code": "stage_ready"}
            actionable += 1
            actionable_kb += size_kb
        analysis["yellow"].append(card)
        known.add(key)

    analysis["analysis_origin"] = "project-stage"
    analysis["project_stage"] = {
        "discovered": discovered,
        "actionable": actionable,
        "actionable_size": format_gb(actionable_kb),
        "idle_minutes": idle_seconds // 60,
        "min_kb": normalized_min_kb,
    }
    analysis["summary"]["overview"] += (
        f" 项目阶段扫描发现 {discovered} 个大于阈值的生成目录，"
        f"其中 {actionable} 个已完成静置和恢复边界复核，预计涉及 {format_gb(actionable_kb)}。"
    )
    analysis["summary"]["priority"].insert(
        0,
        "项目生成目录必须通过 allowlist、项目清单、Git 状态、静置期和打开文件检查，再经过 reviewed_trash 二次确认。",
    )
    analysis["owner_groups"] = build_owner_groups(analysis)
    return validate_analysis(analysis)


def build_project_stage_analysis(
    environment: Optional[Mapping[str, str]] = None,
    min_kb: int = DEFAULT_MIN_KB,
    max_workers: int = 4,
    timeout_seconds: int = 120,
    custom_roots: Optional[list[str]] = None,
) -> dict[str, Any]:
    scan = scan_current(
        max_workers=max_workers,
        timeout_seconds=timeout_seconds,
        custom_roots=custom_roots,
    )
    analysis = build_analysis(scan, environment=environment)
    return augment_with_project_artifacts(analysis, environment=environment, min_kb=min_kb)


def parse_args(argv: Optional[Iterable[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--min-kb", type=int, default=DEFAULT_MIN_KB)
    parser.add_argument("--max-workers", type=int, default=4)
    parser.add_argument("--timeout", type=int, default=120)
    return parser.parse_args(argv)


def main() -> None:
    configure_text_output()
    args = parse_args()
    try:
        analysis = build_project_stage_analysis(
            min_kb=args.min_kb,
            max_workers=args.max_workers,
            timeout_seconds=args.timeout,
        )
    except (ContractError, ProjectArtifactError, OSError, ValueError) as exc:
        print(f"项目阶段分析失败：{exc}", file=sys.stderr)
        raise SystemExit(1) from exc
    print(json.dumps(analysis, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
