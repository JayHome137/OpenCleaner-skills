#!/usr/bin/env python3
"""Create a deterministic analysis draft from a versioned scan result."""
from __future__ import annotations

import json
import os
import sys
import subprocess
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
from runtime import DIRECT_TRASH_OWNER_RULE_IDS, owner_profile  # noqa: E402
from installers import collect_installers  # noqa: E402
from ownership import installed_apps, launch_items, resolve_ownership  # noqa: E402
from settings import SettingsStore  # noqa: E402


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
    if group == "custom_roots":
        return "自定义扫描根内容"
    if group in ("dev_caches", "caches", "temp"):
        return "开发或应用缓存"
    if group in ("containers", "group_containers", "app_support"):
        return "应用数据"
    if group.startswith("system_") or group in ("private_var", "core_simulator"):
        return "系统资产"
    return "用户文件或其他数据"


def direct_children_evidence(path: str, limit: int = 5) -> list[dict[str, Any]]:
    """Return a bounded, read-only size profile for direct children."""
    try:
        entries = []
        with os.scandir(path) as iterator:
            for entry in iterator:
                if len(entries) >= 40:
                    break
                if not entry.is_symlink() and "\n" not in entry.name:
                    entries.append(entry)
    except OSError:
        return []
    if not entries:
        return []
    try:
        result = subprocess.run(
            ["/usr/bin/du", "-sk", *(entry.path for entry in entries)],
            capture_output=True,
            text=True,
            timeout=8,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    sizes: dict[str, int] = {}
    for line in result.stdout.splitlines():
        try:
            size, measured_path = line.split("\t", 1)
            sizes[os.path.normcase(os.path.abspath(measured_path))] = max(0, int(size)) * 1024
        except (ValueError, TypeError):
            continue
    measured = [
        {"name": entry.name, "size_bytes": sizes.get(os.path.normcase(os.path.abspath(entry.path)), 0)}
        for entry in entries
    ]
    measured.sort(key=lambda value: (-int(value["size_bytes"]), str(value["name"]).casefold()))
    return measured[:limit]


def content_profile_for(group: str, children: list[dict[str, Any]], inspected: bool) -> str:
    """Describe observed direct-child shape without inferring ownership."""
    names = [str(item["name"]) for item in children]
    suffixes = sorted({os.path.splitext(name)[1].lower() for name in names if os.path.splitext(name)[1]})
    if names:
        suffix_text = "、".join(suffixes[:4]) if suffixes else "无扩展名条目"
        return f"扫描确认这里主要属于{item_type(group)}；最大直接子项为 { '、'.join(names[:3]) }，可见类型：{suffix_text}。"
    if inspected:
        return f"扫描确认这里主要属于{item_type(group)}，目录当前没有可读取的直接子项。"
    return f"扫描确认这里主要属于{item_type(group)}；本轮未进入最大直接子项的优先证据采样。"


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
    size_bytes = int(item["size_kb"]) * 1024
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
        "size_bytes": size_bytes,
    }
    profile = owner_profile(str(item["path"]), rule.id)
    if profile:
        result["runtime"] = profile
        result["kill_processes"] = list(profile["processes"])
    return result


def _owner_name(profile: Mapping[str, Any], ownership: Mapping[str, Any]) -> str:
    tool = profile.get("owner_tool") or {}
    return str(tool.get("name") or ownership.get("display_name") or "未识别")


def _evidence(
    item: Mapping[str, Any],
    profile: Mapping[str, Any],
    ownership: Mapping[str, Any],
    content_profile: str,
    recommendation: str,
    largest_children: Optional[list[dict[str, Any]]] = None,
) -> dict[str, Any]:
    owner = _owner_name(profile, ownership)
    sources = [
        f"只读扫描路径类别：{item_type(str(item['group']))}",
        f"只读容量测量：{item.get('size_h') or format_gb(int(item['size_kb']))}",
    ]
    if ownership.get("bundle_id"):
        sources.append(f"Bundle ID：{ownership['bundle_id']}")
    if profile:
        sources.append(f"所有者工具映射：{profile.get('id', '')}")
    confidence = "high" if ownership.get("bundle_id") else ("medium" if profile else "low")
    return {
        "owner": owner,
        "confidence": confidence,
        "sources": sources,
        "largest_children": list(largest_children or []),
        "content_profile": content_profile,
        "recommended_owner_action": recommendation,
        "unknown_reason": "" if owner != "未识别" else "路径和只读元数据不足以确认具体 App 或工具。",
    }


def make_yellow(
    item: Mapping[str, Any],
    ownership: Optional[Mapping[str, Any]] = None,
    enrich_evidence: bool = False,
) -> dict[str, Any]:
    content_type = item_type(str(item["group"]))
    profile = owner_profile(str(item["path"]))
    resolved_ownership = dict(ownership or {})
    tool = profile.get("owner_tool") or {}
    owner = _owner_name(profile, resolved_ownership)
    if profile:
        recommendation = (
            f"由用户在 {tool.get('name') or owner} 中检查；下方命令只供参考，"
            "OpenCleaner 不会执行，也不提供直接删除入口。"
        )
        disposal = recommendation
        why_manual = "该目标由应用或开发工具管理，直接移动目录可能破坏索引、离线依赖或并发锁。"
    else:
        recommendation = "先在访达或对应应用中查看；无法证明可恢复时保留。"
        disposal = "先在访达中查看；应用托管的数据优先使用应用内清理；确认有独立备份后再处理用户文件。"
        why_manual = "没有确定性清理规则证明整个目标可再生，因此不会授予直接处置权限。"
    largest_children = direct_children_evidence(str(item["path"])) if enrich_evidence else []
    content_profile = content_profile_for(str(item["group"]), largest_children, enrich_evidence)
    result = {
        "name": str(item["name"]),
        "path": str(item["path"]),
        "size": format_gb(int(item["size_kb"])),
        "size_bytes": int(item["size_kb"]) * 1024,
        "content_profile": content_profile,
        "why_manual": why_manual,
        "disposal": disposal,
        "risk": "删除前需要确认目标不是唯一副本、活动项目或应用核心数据。",
        "evidence": _evidence(
            item, profile, resolved_ownership, content_profile, recommendation, largest_children
        ),
    }
    if profile:
        result["runtime"] = profile
    if not profile and str(item.get("group", "")) in ("downloads", "temp"):
        result["reviewed_trash_paths"] = [str(item["path"])]
    return result


def make_red(
    item: Mapping[str, Any],
    ownership: Optional[Mapping[str, Any]] = None,
) -> dict[str, Any]:
    path = str(item["path"])
    resolved_ownership = dict(ownership or {})
    content_profile = "应用本体或受系统管理的内容。"
    recommendation = "通过应用自带卸载器、系统应用管理入口或访达进行正规卸载。"
    result = {
        "name": str(item["name"]),
        "path": path,
        "size": format_gb(int(item["size_kb"])),
        "size_bytes": int(item["size_kb"]) * 1024,
        "why_keep": "这是应用本体或受系统管理的内容，不应由存储报告直接删除。",
        "indirect_release": recommendation,
        "auto_reclaim": "本 Skill 不自动删除应用本体。",
        "evidence": _evidence(item, {}, resolved_ownership, content_profile, recommendation),
    }
    if path.lower().endswith((".app", ".exe")) or str(item["group"]) == "applications":
        result["app_paths"] = [path]
    return result


def coverage_assessment(scan: Mapping[str, Any]) -> dict[str, Any]:
    coverage = scan.get("coverage") or {}
    requested = int(coverage.get("requested_roots", 0) or 0)
    completed = int(coverage.get("completed_roots", 0) or 0)
    skipped = int(coverage.get("skipped_roots", 0) or 0)
    ratio = completed / requested if requested else 0.0
    denied = sum(1 for error in scan.get("errors", []) if error.get("code") == "permission_denied")
    if requested and skipped == 0 and denied == 0:
        level, label = "complete", "完整"
        limitations: list[str] = []
        advice = "当前扫描根均已完成；仍应把容量视为扫描时点的估算。"
    elif ratio < 0.75:
        level, label = "critical_gaps", "关键区域缺失"
        limitations = ["完成的扫描根不足 75%，结果不能代表完整磁盘视图。"]
        advice = "查看权限错误；如需完整视图，在系统设置授予 Full Disk Access 后重新扫描。"
    else:
        level, label = "usable_with_gaps", "可用于初筛"
        limitations = ["部分扫描根或其后代不可读，未计入的内容可能改变排序和容量结论。"]
        advice = "先按当前结果处理明确目标；需要完整归因时授予 Full Disk Access 后重扫。"
    if denied:
        limitations.append(f"记录到 {denied} 个权限拒绝。")
    return {
        "level": level,
        "label": label,
        "completed_ratio": round(ratio, 4),
        "permission_denied": denied,
        "skipped_roots": skipped,
        "limitations": limitations,
        "rescan_advice": advice,
    }


def build_owner_groups(analysis: Mapping[str, Any]) -> list[dict[str, Any]]:
    tiers = {"green": 0, "yellow": 1, "red": 2}
    groups: dict[str, dict[str, Any]] = {}
    for tier in ("green", "yellow", "red"):
        for item in analysis.get(tier, []):
            ownership = item.get("ownership") or {}
            runtime = item.get("runtime") or {}
            evidence = item.get("evidence") or {}
            if ownership.get("bundle_id"):
                key = f"bundle:{ownership['bundle_id']}"
                owner = ownership.get("display_name") or ownership["bundle_id"]
                source = "Bundle ID"
            elif runtime.get("id"):
                key = f"tool:{runtime['id']}"
                owner = (runtime.get("owner_tool") or {}).get("name") or runtime["id"]
                source = "所有者工具"
            else:
                category = evidence.get("content_profile") or (
                    "确定性可恢复目标" if tier == "green" else "未识别内容"
                )
                key = f"category:{category}"
                owner = evidence.get("owner") or category
                source = "内容类别"
            group = groups.setdefault(
                str(key),
                {
                    "id": str(key), "owner": str(owner), "source": source,
                    "item_count": 0, "size_bytes": 0, "highest_tier": tier, "paths": [],
                    "has_owner_tool": False, "has_reviewed": False,
                },
            )
            group["item_count"] += 1
            group["size_bytes"] += int(item.get("size_bytes", 0) or 0)
            group["paths"].append(str(item.get("path", "")))
            if tiers[tier] > tiers[group["highest_tier"]]:
                group["highest_tier"] = tier
            group["has_owner_tool"] = group["has_owner_tool"] or bool(runtime)
            group["has_reviewed"] = group["has_reviewed"] or bool(item.get("reviewed_trash_paths"))
    result = []
    for group in groups.values():
        highest = group["highest_tier"]
        if highest == "red":
            policy, summary = "keep", "只展示归属和正规释放方式，不提供删除入口。"
        elif highest == "green":
            policy, summary = "safe_trash", "仅确定性规则目标可进入受控 Trash 计划。"
        elif group["has_owner_tool"]:
            policy, summary = "owner_tool", "由所有者应用或工具管理；命令仅展示，不提供删除入口。"
        else:
            policy, summary = "review", "需要查看内容；仅受限下载或临时子项可人工复核。"
        group.pop("has_owner_tool", None)
        group.pop("has_reviewed", None)
        group["policy"] = policy
        group["summary"] = summary
        group["size"] = format_gb(int(group["size_bytes"]) // 1024)
        result.append(group)
    return sorted(result, key=lambda group: (-group["size_bytes"], group["owner"].casefold()))


def build_analysis(
    scan: dict[str, Any],
    environment: Optional[Mapping[str, str]] = None,
    settings_store: Optional[SettingsStore] = None,
) -> dict[str, Any]:
    validate_scan_result(scan)
    platform = platform_from_scan(scan)
    env = dict(os.environ if environment is None else environment)
    env["HOME"] = str(scan["system"]["home"])
    catalog = RuleCatalog(platform=platform, environment=env)
    settings = settings_store or SettingsStore(str(scan["system"]["home"]), env)
    items = flatten_unique(scan)
    ownership_apps = installed_apps(str(scan["system"]["home"]))
    ownership_launch_items = launch_items(str(scan["system"]["home"]))
    green: list[dict[str, Any]] = []
    yellow: list[dict[str, Any]] = []
    red: list[dict[str, Any]] = []
    classified: list[tuple[str, dict[str, Any]]] = []

    enriched_unknowns = 0
    for item in items:
        path = str(item["path"])
        rule = catalog.match(path, "trash")
        # Owner hints are explanatory metadata. Known owner-managed paths stay
        # review-only even if a future rule file accidentally grants Trash.
        if rule is not None and owner_profile(path, rule.id):
            if rule.id not in DIRECT_TRASH_OWNER_RULE_IDS:
                rule = None
        group = str(item["group"])
        ownership = resolve_ownership(
            path,
            str(scan["system"]["home"]),
            apps=ownership_apps,
            launch_agents=ownership_launch_items,
        )
        user_protected = settings.is_path_protected(path) or settings.is_app_protected(ownership)
        if rule is not None and not user_protected:
            card = make_green(item, rule)
            green.append(card)
            tier = "green"
        elif group in ("applications", "program_files", "program_files_x86"):
            card = make_red(item, ownership)
            red.append(card)
            tier = "red"
        else:
            enrich = not owner_profile(path) and not ownership.get("bundle_id") and enriched_unknowns < 8
            card = make_yellow(item, ownership, enrich_evidence=enrich)
            if enrich:
                enriched_unknowns += 1
            yellow.append(card)
            tier = "yellow"
        if ownership.get("bundle_id") or ownership.get("app_paths") or ownership.get("relationships"):
            card["ownership"] = ownership
        if user_protected:
            card.pop("reviewed_trash_paths", None)
            card["protected"] = True
            card["why_manual"] = "目标或所属 App 已加入永久保护列表，只展示占用，不建议处置。"
            card["disposal"] = "保留；如需重新评估，先从本地保护列表中明确移除。"
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
                "note": (
                    "确定性规则候选；仍需实时策略重验"
                    if tier == "green"
                    else (
                        "由所有者应用或工具管理，不提供直接删除"
                        if card.get("runtime")
                        else "需要人工或正规系统入口处理"
                    )
                ),
            }
        )

    def tier_total(cards: list[dict[str, Any]]) -> int:
        return sum(size_by_path.get(os.path.normcase(canonical_path(str(card["path"]))), 0) for card in cards)

    errors = scan.get("errors", [])
    denied = sorted({str(error.get("path", "")) for error in errors if error.get("code") == "permission_denied" and error.get("path")})
    green_total = tier_total(green)
    analysis = {
        "schema_version": "1.1",
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
        "installer_packages": collect_installers(items, str(scan["system"]["home"])),
        "denied": denied,
        "coverage_assessment": coverage_assessment(scan),
        "owner_groups": [],
        "summary": {
            "overview": (
                f"扫描发现 {len(green)} 项确定性规则候选，预计涉及 {format_gb(green_total)}；"
                "实际可操作量以实时 Dry Run 决策为准。"
            ),
            "tier_stats": {
                "green": format_gb(green_total),
                "yellow": format_gb(tier_total(yellow)),
                "red": format_gb(tier_total(red)),
            },
            "priority": [
                "先查看实时 Dry Run 的可操作量与阻止原因，再决定是否移到废纸篓。",
                "所有者工具管理的目标只展示说明和命令，不提供直接删除入口。",
                "应用本体和系统内容只通过正规入口处理。",
            ],
            "long_term": [
                "定期重新扫描并比较实际变化，不把一次分析长期复用。",
                "重要项目、文档和媒体内容先建立独立备份。",
            ],
        },
    }
    analysis["owner_groups"] = build_owner_groups(analysis)
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
