#!/usr/bin/env python3
"""Create a deterministic analysis draft from a versioned scan result."""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Mapping, Optional

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from contracts import (  # noqa: E402
    ContractError,
    canonical_sha256,
    load_json_object,
    validate_analysis,
    validate_scan_result,
)
from rules import RuleCatalog, RuleError, canonical_path  # noqa: E402
from runtime import owner_profile  # noqa: E402


def platform_from_scan(scan: Mapping[str, Any]) -> str:
    os_name = str(scan["system"].get("os", "")).lower()
    if "macos" in os_name or "mac os" in os_name:
        return "darwin"
    raise ContractError(f"analysis 当前仅支持 macOS：{scan['system'].get('os', '')}")


def format_gb(size_kb: int) -> str:
    return f"约 {size_kb / 1024 / 1024:.1f} GB"


def item_type(group: str) -> str:
    if group in ("applications", "program_files", "program_files_x86"):
        return "应用本体"
    if group in ("downloads",):
        return "下载内容"
    if group in ("dev_caches", "caches", "temp"):
        return "开发或应用缓存"
    if group in ("containers", "group_containers", "app_support"):
        return "应用数据"
    if group.startswith("system_") or group in ("private_var", "core_simulator"):
        return "系统资产"
    return "用户文件或其他数据"


def flatten_unique(scan: Mapping[str, Any]) -> list[dict[str, Any]]:
    unique: dict[str, dict[str, Any]] = {}
    for group, items in scan["groups"].items():
        for item in items:
            path = str(item.get("path", ""))
            if not path:
                continue
            try:
                key = os.path.normcase(canonical_path(path))
            except RuleError:
                continue
            candidate = dict(item)
            candidate["group"] = group
            previous = unique.get(key)
            if previous is None or int(candidate.get("size_kb", 0)) > int(previous.get("size_kb", 0)):
                unique[key] = candidate
    return sorted(
        unique.values(),
        key=lambda item: (
            -int(item.get("size_kb", 0)),
            str(item.get("name", "")).casefold(),
            os.path.normcase(str(item.get("path", ""))),
        ),
    )


def make_green(item: Mapping[str, Any], rule: Any) -> dict[str, Any]:
    result = {
        "name": str(item["name"]),
        "path": str(item["path"]),
        "size_estimate": format_gb(int(item["size_kb"])),
        "kill_processes": [],
        "trash_paths": [str(item["path"])],
        "commands": [],
        "rule_id": rule.id,
        "rule_reason": rule.recovery,
        "rule_risk": rule.risk,
        "rule_non_targets": list(rule.non_targets),
    }
    profile = owner_profile(str(item["path"]), rule.id)
    if profile:
        result["runtime"] = profile
        result["kill_processes"] = list(profile["processes"])
    return result


def make_yellow(item: Mapping[str, Any]) -> dict[str, Any]:
    content_type = item_type(str(item["group"]))
    result = {
        "name": str(item["name"]),
        "path": str(item["path"]),
        "size": format_gb(int(item["size_kb"])),
        "content_profile": f"扫描确认这里主要属于{content_type}，需要结合实际内容继续判断。",
        "why_manual": "没有确定性清理规则证明整个目标可再生，因此不会自动授予处置权限。",
        "disposal": "先在文件管理器中查看；应用托管的数据优先使用应用内清理；确认有独立备份后再处理用户文件。",
        "risk": "删除前需要确认目标不是唯一副本、活动项目或应用核心数据。",
    }
    profile = owner_profile(str(item["path"]))
    if profile:
        result["runtime"] = profile
    if str(item.get("group", "")) in ("downloads", "temp"):
        result["reviewed_trash_paths"] = [str(item["path"])]
    return result


def make_red(item: Mapping[str, Any]) -> dict[str, Any]:
    path = str(item["path"])
    result = {
        "name": str(item["name"]),
        "path": path,
        "size": format_gb(int(item["size_kb"])),
        "why_keep": "这是应用本体或受系统管理的内容，不应由存储报告直接删除。",
        "indirect_release": "通过应用自带卸载器、系统应用管理入口或文件管理器进行正规卸载。",
        "auto_reclaim": "本 Skill 不自动删除应用本体。",
    }
    if path.lower().endswith((".app", ".exe")) or str(item["group"]) == "applications":
        result["app_paths"] = [path]
    return result


def build_analysis(
    scan: dict[str, Any],
    environment: Optional[Mapping[str, str]] = None,
) -> dict[str, Any]:
    validate_scan_result(scan)
    platform = platform_from_scan(scan)
    env = dict(os.environ if environment is None else environment)
    env["HOME"] = str(scan["system"]["home"])
    catalog = RuleCatalog(platform=platform, environment=env)
    items = flatten_unique(scan)
    green: list[dict[str, Any]] = []
    yellow: list[dict[str, Any]] = []
    red: list[dict[str, Any]] = []
    classified: list[tuple[str, dict[str, Any]]] = []

    for item in items:
        path = str(item["path"])
        rule = catalog.match(path, "trash")
        group = str(item["group"])
        if rule is not None:
            card = make_green(item, rule)
            green.append(card)
            tier = "green"
        elif group in ("applications", "program_files", "program_files_x86"):
            card = make_red(item)
            red.append(card)
            tier = "red"
        else:
            card = make_yellow(item)
            yellow.append(card)
            tier = "yellow"
        classified.append((tier, card))

    item_by_path = {
        os.path.normcase(canonical_path(str(item["path"]))): item for item in items
    }
    size_by_path = {key: int(item["size_kb"]) for key, item in item_by_path.items()}
    top5 = []
    for rank, (tier, card) in enumerate(classified[:5], start=1):
        path = str(card["path"])
        key = os.path.normcase(canonical_path(path))
        source_item = item_by_path[key]
        top5.append(
            {
                "rank": rank,
                "tier": tier,
                "size": format_gb(size_by_path.get(key, 0)),
                "type": item_type(str(source_item["group"])),
                "name": card["name"],
                "path": path,
                "note": "确定性规则已授权" if tier == "green" else "需要人工或正规系统入口处理",
            }
        )

    def tier_total(cards: list[dict[str, Any]]) -> int:
        return sum(size_by_path.get(os.path.normcase(canonical_path(str(card["path"]))), 0) for card in cards)

    errors = scan.get("errors", [])
    denied = sorted({str(error.get("path", "")) for error in errors if error.get("code") == "permission_denied" and error.get("path")})
    green_total = tier_total(green)
    analysis = {
        "schema_version": "1.0",
        "source_scan_sha256": canonical_sha256(scan),
        "analysis_origin": "deterministic-draft",
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "scan_seconds": scan["scan_seconds"],
        "system": scan["system"],
        "coverage": scan["coverage"],
        "top5": top5,
        "green": green,
        "yellow": yellow,
        "red": red,
        "denied": denied,
        "summary": {
            "overview": f"确定性规则识别出 {len(green)} 项可恢复处理目标，预计涉及 {format_gb(green_total)}。",
            "tier_stats": {
                "green": format_gb(green_total),
                "yellow": format_gb(tier_total(yellow)),
                "red": format_gb(tier_total(red)),
            },
            "priority": [
                "先复核绿灯目标的规则来源，再使用移到废纸篓操作。",
                "黄灯内容先在文件管理器或对应应用中查看，不直接删除。",
                "应用本体和系统内容只通过正规入口处理。",
            ],
            "long_term": [
                "定期重新扫描并比较实际变化，不把一次分析长期复用。",
                "重要项目、文档和媒体内容先建立独立备份。",
            ],
        },
    }
    return validate_analysis(analysis)


def main() -> None:
    if len(sys.argv) not in (2, 3):
        print("Usage: classify.py <scan.json> [analysis.json]", file=sys.stderr)
        raise SystemExit(2)
    scan = load_json_object(sys.argv[1])
    analysis = build_analysis(scan)
    payload = json.dumps(analysis, ensure_ascii=False, indent=2)
    if len(sys.argv) == 3:
        Path(sys.argv[2]).write_text(payload + "\n", encoding="utf-8")
        print(f"分析草稿已生成：{sys.argv[2]}")
    else:
        print(payload)


if __name__ == "__main__":
    main()
