#!/usr/bin/env python3
"""Runtime validation for OpenCleaner's versioned JSON contracts."""
from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path
from typing import Any, Iterable, Union

SCAN_SCHEMA_VERSION = "1.1"
ANALYSIS_SCHEMA_VERSION = "1.1"
ACTION_PLAN_SCHEMA_VERSION = "1.1"
LEGACY_SCHEMA_VERSION = "1.0"
MIN_PROJECT_IDLE_SECONDS = 30 * 60


class ContractError(ValueError):
    """Raised when an input does not satisfy a runtime contract."""


def load_json_object(path: Union[str, Path]) -> dict[str, Any]:
    try:
        with Path(path).open(encoding="utf-8") as handle:
            value = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise ContractError(f"无法读取 JSON：{exc}") from exc
    if not isinstance(value, dict):
        raise ContractError("JSON 顶层必须是对象")
    return value


def canonical_sha256(value: Any) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def json_for_script(value: Any) -> str:
    """Serialize JSON without allowing data to terminate an inline script."""
    return (
        json.dumps(value, ensure_ascii=False, separators=(",", ":"))
        .replace("&", "\\u0026")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )


def _require_keys(value: dict[str, Any], keys: Iterable[str], label: str) -> None:
    missing = [key for key in keys if key not in value]
    if missing:
        raise ContractError(f"{label} 缺少字段：{', '.join(missing)}")


def _require_type(value: Any, expected: type, label: str) -> None:
    if not isinstance(value, expected):
        raise ContractError(f"{label} 类型必须是 {expected.__name__}")


def _require_number(value: Any, label: str) -> None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ContractError(f"{label} 类型必须是 number")
    if not math.isfinite(float(value)):
        raise ContractError(f"{label} 必须是有限 number")


def _require_string_list(value: Any, label: str) -> None:
    _require_type(value, list, label)
    if any(not isinstance(item, str) for item in value):
        raise ContractError(f"{label} 必须只包含字符串")


def _require_sha256(value: Any, label: str) -> None:
    if not isinstance(value, str) or len(value) != 64 or value != value.lower():
        raise ContractError(f"{label} 必须是 64 位 SHA-256")
    try:
        int(value, 16)
    except ValueError as exc:
        raise ContractError(f"{label} 必须是十六进制 SHA-256") from exc


def _validate_runtime(value: Any, label: str, live_state: bool) -> None:
    _require_type(value, dict, label)
    _require_keys(value, ("id", "processes", "owner_tool"), label)
    _require_type(value["id"], str, f"{label}.id")
    _require_string_list(value["processes"], f"{label}.processes")
    if not value["id"] or not value["processes"]:
        raise ContractError(f"{label} 必须包含所有者和进程模式")
    tool = value["owner_tool"]
    _require_type(tool, dict, f"{label}.owner_tool")
    _require_keys(tool, ("name", "inspect_command", "cleanup_command", "execution"), f"{label}.owner_tool")
    for key in ("name", "inspect_command", "cleanup_command", "execution"):
        _require_type(tool[key], str, f"{label}.owner_tool.{key}")
    if tool["execution"] not in ("review-only", "app-managed"):
        raise ContractError(f"{label}.owner_tool.execution 无效")
    if live_state:
        _require_keys(value, ("state",), label)
        if value["state"] not in ("active", "inactive", "unknown"):
            raise ContractError(f"{label}.state 无效")


def _validate_ownership(value: Any, label: str) -> None:
    _require_type(value, dict, label)
    _require_keys(
        value,
        (
            "bundle_id", "display_name", "app_paths", "relationships",
            "login_items", "background_processes", "shared_bundle_id", "multiple_versions",
        ),
        label,
    )
    for key in ("bundle_id", "display_name"):
        _require_type(value[key], str, f"{label}.{key}")
    for key in ("app_paths", "relationships", "login_items", "background_processes"):
        _require_string_list(value[key], f"{label}.{key}")
    for key in ("shared_bundle_id", "multiple_versions"):
        _require_type(value[key], bool, f"{label}.{key}")


def _empty_apfs_diagnostics() -> dict[str, Any]:
    return {
        "purgeable": {"status": "unavailable", "value": ""},
        "trash": {"status": "unavailable", "estimated_bytes": 0},
        "local_snapshots": {"status": "unavailable", "count": 0},
        "open_unlinked_files": {"status": "unavailable", "count": 0, "estimated_bytes": 0},
        "release_notes": [],
    }


def _legacy_cache_metadata() -> dict[str, Any]:
    """Return an explicit non-published cache state for migrated 1.0 data."""
    return {
        "enabled": False,
        "schema_version": "1.1",
        "ttl_seconds": 0,
        "hits": 0,
        "misses": 0,
        "invalidated": 0,
        "published": False,
        "status": "legacy",
    }


def _non_negative_int(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return 0
    return int(value)


def _actionable_buckets(actions: Any) -> dict[str, dict[str, int]]:
    buckets = {
        mode: {"count": 0, "size_bytes": 0}
        for mode in ("trash", "reviewed_trash", "open")
    }
    if not isinstance(actions, list):
        return buckets
    for action in actions:
        if not isinstance(action, dict):
            continue
        mode = action.get("mode")
        if mode in buckets:
            buckets[mode]["count"] += 1
            buckets[mode]["size_bytes"] += _non_negative_int(action.get("size_estimate_bytes", 0))
    return buckets


def _blocked_bucket(rejected: Any) -> dict[str, Any]:
    reasons: dict[str, dict[str, Any]] = {}
    count = 0
    size_bytes = 0
    if isinstance(rejected, list):
        for item in rejected:
            if not isinstance(item, dict):
                continue
            count += 1
            size = _non_negative_int(item.get("size_estimate_bytes", 0))
            size_bytes += size
            code = str(item.get("code") or "unknown")
            reason = reasons.setdefault(
                code,
                {"code": code, "message": str(item.get("message") or "已阻止"), "count": 0, "size_bytes": 0},
            )
            reason["count"] += 1
            reason["size_bytes"] += size
    return {
        "count": count,
        "size_bytes": size_bytes,
        "reasons": sorted(reasons.values(), key=lambda item: (-item["size_bytes"], -item["count"], item["code"])),
    }


def _legacy_evidence(item: dict[str, Any], tier: str) -> dict[str, Any]:
    runtime = item.get("runtime") if isinstance(item.get("runtime"), dict) else {}
    tool = runtime.get("owner_tool") if isinstance(runtime.get("owner_tool"), dict) else {}
    ownership = item.get("ownership") if isinstance(item.get("ownership"), dict) else {}
    owner = ownership.get("display_name") or tool.get("name") or (
        "系统或应用" if tier == "red" else "未识别"
    )
    return {
        "owner": str(owner),
        "confidence": "medium" if owner != "未识别" else "low",
        "sources": ["从 1.0 结果迁移；需要重新扫描以补齐证据"],
        "largest_children": [],
        "content_profile": str(item.get("content_profile") or item.get("why_keep") or ""),
        "recommended_owner_action": str(item.get("disposal") or item.get("indirect_release") or "只读查看"),
        "unknown_reason": "旧结果缺少结构化归属证据" if owner == "未识别" else "",
    }


def _migrate_scan_result(data: dict[str, Any]) -> None:
    version = data.get("schema_version")
    if version == LEGACY_SCHEMA_VERSION:
        data["schema_version"] = SCAN_SCHEMA_VERSION
        system = data.setdefault("system", {})
        if not isinstance(system, dict):
            raise ContractError("scan-result.system 必须是 object")
        system.setdefault("apfs_diagnostics", _empty_apfs_diagnostics())
        coverage = data.setdefault("coverage", {})
        if not isinstance(coverage, dict):
            raise ContractError("scan-result.coverage 必须是 object")
        coverage.setdefault("cache", _legacy_cache_metadata())
    elif version != SCAN_SCHEMA_VERSION:
        raise ContractError("不支持的 scan-result schema_version")


def _migrate_analysis(data: dict[str, Any]) -> None:
    version = data.get("schema_version")
    if version == LEGACY_SCHEMA_VERSION:
        data["schema_version"] = ANALYSIS_SCHEMA_VERSION
        system = data.setdefault("system", {})
        if not isinstance(system, dict):
            raise ContractError("analysis.system 必须是 object")
        system.setdefault("apfs_diagnostics", _empty_apfs_diagnostics())
        for tier in ("green", "yellow", "red"):
            items = data.get(tier, [])
            if not isinstance(items, list):
                raise ContractError(f"analysis.{tier} 必须是 array")
            for item in items:
                if not isinstance(item, dict):
                    # Let the normal validator report the precise item path.
                    continue
                item.setdefault("size_bytes", 0)
                if tier in ("yellow", "red"):
                    item.setdefault("evidence", _legacy_evidence(item, tier))
        coverage = data.get("coverage", {})
        if coverage is None:
            coverage = {}
        if not isinstance(coverage, dict):
            raise ContractError("analysis.coverage 必须是 object")
        requested = coverage.get("requested_roots", 0)
        completed = coverage.get("completed_roots", 0)
        skipped = coverage.get("skipped_roots", 0)
        requested_i = _non_negative_int(requested)
        completed_i = _non_negative_int(completed)
        skipped_i = _non_negative_int(skipped)
        ratio = completed_i / requested_i if requested_i else 0.0
        # A legacy result has no structured coverage proof. Even a complete
        # root count is therefore only suitable for an initial review.
        level = "usable_with_gaps" if requested_i and completed_i == requested_i and skipped_i == 0 else "critical_gaps"
        data.setdefault(
            "coverage_assessment",
            {
                "level": level,
                "label": "旧结果，建议重扫",
                "completed_ratio": ratio,
                "permission_denied": len(data.get("denied")) if isinstance(data.get("denied"), list) else 0,
                "skipped_roots": skipped_i,
                "limitations": ["1.0 结果不含结构化覆盖结论"],
                "rescan_advice": "使用 1.1 扫描器重新扫描以补齐覆盖与 APFS 诊断。",
            },
        )
        data.setdefault("owner_groups", [])
    elif version != ANALYSIS_SCHEMA_VERSION:
        raise ContractError("不支持的 analysis schema_version")


def _migrate_action_plan(data: dict[str, Any]) -> None:
    version = data.get("schema_version")
    if version == LEGACY_SCHEMA_VERSION:
        data["schema_version"] = ACTION_PLAN_SCHEMA_VERSION
        actions = data.get("actions", [])
        if not isinstance(actions, list):
            raise ContractError("action-plan.actions 必须是 array")
        for action in actions:
            if isinstance(action, dict):
                action.setdefault("size_estimate_bytes", 0)
        rejected = data.get("rejected", [])
        if not isinstance(rejected, list):
            raise ContractError("action-plan.rejected 必须是 array")
        for item in rejected:
            if isinstance(item, dict):
                item.setdefault("size_estimate_bytes", 0)
        data.setdefault(
            "decision",
            {
                "discovery": {tier: {"count": 0, "size_bytes": 0} for tier in ("green", "yellow", "red")},
                "actionable": _actionable_buckets(actions),
                "blocked": _blocked_bucket(rejected),
            },
        )
    elif version != ACTION_PLAN_SCHEMA_VERSION:
        raise ContractError("不支持的 action-plan schema_version")


def _validate_evidence(value: Any, label: str) -> None:
    _require_type(value, dict, label)
    _require_keys(
        value,
        (
            "owner", "confidence", "sources", "largest_children", "content_profile",
            "recommended_owner_action", "unknown_reason",
        ),
        label,
    )
    for key in ("owner", "content_profile", "recommended_owner_action", "unknown_reason"):
        _require_type(value[key], str, f"{label}.{key}")
    if value["confidence"] not in ("high", "medium", "low"):
        raise ContractError(f"{label}.confidence 无效")
    _require_string_list(value["sources"], f"{label}.sources")
    _require_type(value["largest_children"], list, f"{label}.largest_children")
    for index, item in enumerate(value["largest_children"]):
        child_label = f"{label}.largest_children[{index}]"
        _require_type(item, dict, child_label)
        _require_keys(item, ("name", "size_bytes"), child_label)
        _require_type(item["name"], str, f"{child_label}.name")
        if isinstance(item["size_bytes"], bool) or not isinstance(item["size_bytes"], int) or item["size_bytes"] < 0:
            raise ContractError(f"{child_label}.size_bytes 必须是非负整数")


def _validate_apfs(value: Any, label: str) -> None:
    _require_type(value, dict, label)
    _require_keys(value, ("purgeable", "trash", "local_snapshots", "open_unlinked_files", "release_notes"), label)
    nested_required = {
        "purgeable": ("status", "value"),
        "trash": ("status", "estimated_bytes"),
        "local_snapshots": ("status", "count"),
        "open_unlinked_files": ("status", "count", "estimated_bytes"),
    }
    for key, required in nested_required.items():
        nested = value[key]
        _require_type(nested, dict, f"{label}.{key}")
        _require_keys(nested, required, f"{label}.{key}")
        if nested["status"] not in ("available", "empty", "unavailable"):
            raise ContractError(f"{label}.{key}.status 无效")
    _require_type(value["purgeable"]["value"], str, f"{label}.purgeable.value")
    for key, field in (("trash", "estimated_bytes"), ("local_snapshots", "count"), ("open_unlinked_files", "count"), ("open_unlinked_files", "estimated_bytes")):
        number = value[key][field]
        if isinstance(number, bool) or not isinstance(number, int) or number < 0:
            raise ContractError(f"{label}.{key}.{field} 必须是非负整数")
    for key in ("trash", "local_snapshots", "open_unlinked_files"):
        if value[key]["status"] == "empty":
            numeric = value[key].get("estimated_bytes", value[key].get("count", 0))
            if numeric != 0:
                raise ContractError(f"{label}.{key} 标记为 empty 时数值必须为 0")
    _require_string_list(value["release_notes"], f"{label}.release_notes")


def _validate_cache_metadata(value: Any, label: str) -> None:
    _require_type(value, dict, label)
    _require_keys(
        value,
        ("enabled", "schema_version", "ttl_seconds", "hits", "misses", "invalidated", "published", "status"),
        label,
    )
    _require_type(value["enabled"], bool, f"{label}.enabled")
    _require_type(value["schema_version"], str, f"{label}.schema_version")
    if value["schema_version"] != "1.1":
        raise ContractError(f"{label}.schema_version 无效")
    for key in ("ttl_seconds", "hits", "misses", "invalidated"):
        number = value[key]
        if isinstance(number, bool) or not isinstance(number, int) or number < 0:
            raise ContractError(f"{label}.{key} 必须是非负整数")
    _require_type(value["published"], bool, f"{label}.published")
    _require_type(value["status"], str, f"{label}.status")
    if value["enabled"] and value["ttl_seconds"] <= 0:
        raise ContractError(f"{label}.ttl_seconds 必须大于 0")
    if value["published"] and not value["enabled"]:
        raise ContractError(f"{label}.disabled 缓存不能标记为 published")


def validate_scan_result(data: dict[str, Any]) -> dict[str, Any]:
    _require_type(data, dict, "scan-result")
    _migrate_scan_result(data)
    _require_keys(
        data,
        (
            "schema_version",
            "generated_at",
            "scan_seconds",
            "system",
            "groups",
            "coverage",
            "errors",
        ),
        "scan-result",
    )
    _require_type(data["generated_at"], str, "generated_at")
    _require_number(data["scan_seconds"], "scan_seconds")
    _require_type(data["system"], dict, "system")
    _require_type(data["groups"], dict, "groups")
    _require_type(data["coverage"], dict, "coverage")
    _require_type(data["errors"], list, "errors")
    _require_keys(
        data["system"],
        ("os", "home", "disk_total", "disk_used", "disk_free", "disks"),
        "system",
    )
    for key in ("os", "home", "disk_total", "disk_used", "disk_free"):
        _require_type(data["system"][key], str, f"system.{key}")
    _require_type(data["system"]["disks"], list, "system.disks")
    _require_keys(data["system"], ("apfs_diagnostics",), "system")
    _validate_apfs(data["system"]["apfs_diagnostics"], "system.apfs_diagnostics")
    _require_keys(
        data["coverage"],
        ("requested_roots", "completed_roots", "skipped_roots", "cache"),
        "coverage",
    )
    for key in ("requested_roots", "completed_roots", "skipped_roots"):
        value = data["coverage"][key]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ContractError(f"coverage.{key} 必须是非负整数")
    if data["coverage"]["completed_roots"] + data["coverage"]["skipped_roots"] != data["coverage"]["requested_roots"]:
        raise ContractError("coverage 完成数与跳过数之和必须等于请求数")
    _validate_cache_metadata(data["coverage"]["cache"], "coverage.cache")
    for group_name, items in data["groups"].items():
        _require_type(group_name, str, "group name")
        _require_type(items, list, f"groups.{group_name}")
        for index, item in enumerate(items):
            _require_type(item, dict, f"groups.{group_name}[{index}]")
            _require_keys(
                item,
                ("name", "path", "size_kb", "size_h"),
                f"groups.{group_name}[{index}]",
            )
            for key in ("name", "path", "size_h"):
                _require_type(item[key], str, f"groups.{group_name}[{index}].{key}")
            if isinstance(item["size_kb"], bool) or not isinstance(item["size_kb"], int) or item["size_kb"] < 0:
                raise ContractError(f"groups.{group_name}[{index}].size_kb 必须是非负整数")
    for index, error in enumerate(data["errors"]):
        _require_type(error, dict, f"errors[{index}]")
        _require_keys(error, ("code", "path", "message"), f"errors[{index}]")
        for key in ("code", "path", "message"):
            _require_type(error[key], str, f"errors[{index}].{key}")
    return data


def validate_analysis(data: dict[str, Any]) -> dict[str, Any]:
    _require_type(data, dict, "analysis")
    _migrate_analysis(data)
    _require_keys(
        data,
        (
            "schema_version",
            "source_scan_sha256",
            "generated_at",
            "system",
            "top5",
            "green",
            "yellow",
            "red",
            "summary",
            "coverage_assessment",
            "owner_groups",
        ),
        "analysis",
    )
    _require_sha256(data["source_scan_sha256"], "source_scan_sha256")
    _require_type(data["generated_at"], str, "generated_at")
    _require_type(data["system"], dict, "system")
    _require_keys(data["system"], ("os", "home"), "system")
    for key in ("os", "home"):
        _require_type(data["system"][key], str, f"system.{key}")
    _require_keys(data["system"], ("apfs_diagnostics",), "system")
    _validate_apfs(data["system"]["apfs_diagnostics"], "system.apfs_diagnostics")
    os_name = data["system"]["os"].lower()
    if "macos" not in os_name and "mac os" not in os_name:
        raise ContractError("analysis 当前仅支持 macOS")
    item_specs = {
        "top5": ("rank", "tier", "size", "type", "name", "path", "note"),
        "green": (
            "name", "path", "size_estimate", "kill_processes", "trash_paths", "commands",
            "rule_id", "rule_reason", "rule_risk", "rule_non_targets", "size_bytes",
        ),
        "yellow": ("name", "path", "size", "size_bytes", "content_profile", "why_manual", "disposal", "risk"),
        "red": ("name", "path", "size", "size_bytes", "why_keep", "indirect_release", "auto_reclaim"),
    }
    for key, required in item_specs.items():
        _require_type(data[key], list, key)
        for index, item in enumerate(data[key]):
            label = f"{key}[{index}]"
            _require_type(item, dict, label)
            _require_keys(item, required, label)
            if key == "top5":
                if isinstance(item["rank"], bool) or not isinstance(item["rank"], int) or item["rank"] < 1:
                    raise ContractError(f"{label}.rank 必须是正整数")
                if item["tier"] not in ("green", "yellow", "red"):
                    raise ContractError(f"{label}.tier 无效")
                for field in ("size", "type", "name", "path", "note"):
                    _require_type(item[field], str, f"{label}.{field}")
            elif key == "green":
                for field in ("name", "path", "size_estimate", "rule_id", "rule_reason", "rule_risk"):
                    _require_type(item[field], str, f"{label}.{field}")
                for field in ("kill_processes", "trash_paths", "rule_non_targets"):
                    _require_string_list(item[field], f"{label}.{field}")
                _require_type(item["commands"], list, f"{label}.commands")
            else:
                for field in required:
                    if field == "size_bytes":
                        continue
                    _require_type(item[field], str, f"{label}.{field}")
            if "trash_paths" in item:
                _require_string_list(item["trash_paths"], f"{label}.trash_paths")
            if "reviewed_trash_paths" in item:
                _require_string_list(item["reviewed_trash_paths"], f"{label}.reviewed_trash_paths")
            if "app_paths" in item:
                _require_string_list(item["app_paths"], f"{label}.app_paths")
            if "runtime" in item:
                _validate_runtime(item["runtime"], f"{label}.runtime", live_state=False)
            if "ownership" in item:
                _validate_ownership(item["ownership"], f"{label}.ownership")
            if "size_bytes" in item:
                value = item["size_bytes"]
                if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                    raise ContractError(f"{label}.size_bytes 必须是非负整数")
            if key in ("yellow", "red"):
                _require_keys(item, ("evidence",), label)
                _validate_evidence(item["evidence"], f"{label}.evidence")
            if "protected" in item:
                _require_type(item["protected"], bool, f"{label}.protected")
            if "stage_status" in item:
                stage = item["stage_status"]
                _require_type(stage, dict, f"{label}.stage_status")
                _require_keys(stage, ("state", "code"), f"{label}.stage_status")
                if stage["state"] not in ("ready", "deferred"):
                    raise ContractError(f"{label}.stage_status.state 无效")
                _require_type(stage["code"], str, f"{label}.stage_status.code")
                if stage["state"] == "ready" and not item.get("reviewed_trash_paths"):
                    raise ContractError(f"{label} ready 项必须包含 reviewed_trash_paths")
            if "project_artifact" in item:
                project = item["project_artifact"]
                _require_type(project, dict, f"{label}.project_artifact")
                _require_keys(
                    project,
                    ("project_root", "artifact_kind", "build_system", "idle_seconds", "latest_mtime_ns"),
                    f"{label}.project_artifact",
                )
                for field in ("project_root", "artifact_kind", "build_system"):
                    _require_type(project[field], str, f"{label}.project_artifact.{field}")
                for field in ("idle_seconds", "latest_mtime_ns"):
                    value = project[field]
                    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                        raise ContractError(f"{label}.project_artifact.{field} 必须是非负整数")
                if project["idle_seconds"] < MIN_PROJECT_IDLE_SECONDS:
                    raise ContractError(f"{label}.project_artifact.idle_seconds 不能少于 1800 秒")
    _require_type(data["summary"], dict, "summary")
    _require_keys(
        data["summary"],
        ("overview", "tier_stats", "priority", "long_term"),
        "summary",
    )
    _require_type(data["summary"]["overview"], str, "summary.overview")
    _require_type(data["summary"]["tier_stats"], dict, "summary.tier_stats")
    _require_string_list(data["summary"]["priority"], "summary.priority")
    _require_string_list(data["summary"]["long_term"], "summary.long_term")
    _require_keys(data["summary"]["tier_stats"], ("green", "yellow", "red"), "summary.tier_stats")
    for key in ("green", "yellow", "red"):
        _require_type(data["summary"]["tier_stats"][key], str, f"summary.tier_stats.{key}")
    coverage = data["coverage_assessment"]
    _require_type(coverage, dict, "coverage_assessment")
    _require_keys(
        coverage,
        ("level", "label", "completed_ratio", "permission_denied", "skipped_roots", "limitations", "rescan_advice"),
        "coverage_assessment",
    )
    if coverage["level"] not in ("complete", "usable_with_gaps", "critical_gaps"):
        raise ContractError("coverage_assessment.level 无效")
    for key in ("label", "rescan_advice"):
        _require_type(coverage[key], str, f"coverage_assessment.{key}")
    _require_number(coverage["completed_ratio"], "coverage_assessment.completed_ratio")
    if not 0 <= float(coverage["completed_ratio"]) <= 1:
        raise ContractError("coverage_assessment.completed_ratio 必须在 0 到 1 之间")
    for key in ("permission_denied", "skipped_roots"):
        if isinstance(coverage[key], bool) or not isinstance(coverage[key], int) or coverage[key] < 0:
            raise ContractError(f"coverage_assessment.{key} 必须是非负整数")
    _require_string_list(coverage["limitations"], "coverage_assessment.limitations")
    _require_type(data["owner_groups"], list, "owner_groups")
    for index, group in enumerate(data["owner_groups"]):
        label = f"owner_groups[{index}]"
        _require_type(group, dict, label)
        _require_keys(group, ("id", "owner", "source", "item_count", "size_bytes", "size", "highest_tier", "policy", "summary", "paths"), label)
        for key in ("id", "owner", "source", "size", "highest_tier", "policy", "summary"):
            _require_type(group[key], str, f"{label}.{key}")
        for key in ("item_count", "size_bytes"):
            value = group[key]
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ContractError(f"{label}.{key} 必须是非负整数")
        _require_string_list(group["paths"], f"{label}.paths")
    if "denied" in data:
        _require_string_list(data["denied"], "denied")
    if "installer_packages" in data:
        _require_type(data["installer_packages"], list, "installer_packages")
        required = (
            "name", "path", "format", "size_bytes", "installed_state", "installed_apps",
            "source", "last_used_at", "unique_copy_risk", "duplicates",
        )
        for index, item in enumerate(data["installer_packages"]):
            label = f"installer_packages[{index}]"
            _require_type(item, dict, label)
            _require_keys(item, required, label)
            for key in ("name", "path", "format", "installed_state", "source", "last_used_at", "unique_copy_risk"):
                _require_type(item[key], str, f"{label}.{key}")
            for key in ("installed_apps", "duplicates"):
                _require_string_list(item[key], f"{label}.{key}")
            if isinstance(item["size_bytes"], bool) or not isinstance(item["size_bytes"], int) or item["size_bytes"] < 0:
                raise ContractError(f"{label}.size_bytes 必须是非负整数")
            for key in ("signature_state", "mount_state", "duplicate_evidence"):
                if key in item:
                    _require_type(item[key], str, f"{label}.{key}")
    origin = data.get("analysis_origin")
    if origin is not None and origin not in ("deterministic-draft", "project-stage"):
        raise ContractError("analysis_origin 无效")
    if origin == "project-stage" or "project_stage" in data:
        if origin != "project-stage" or "project_stage" not in data:
            raise ContractError("analysis_origin 与 project_stage 不一致")
        stage = data.get("project_stage")
        _require_type(stage, dict, "project_stage")
        _require_keys(stage, ("discovered", "actionable", "actionable_size", "idle_minutes", "min_kb"), "project_stage")
        for key in ("discovered", "actionable", "idle_minutes", "min_kb"):
            value = stage[key]
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ContractError(f"project_stage.{key} 必须是非负整数")
        if stage["actionable"] > stage["discovered"]:
            raise ContractError("project_stage.actionable 不能超过 discovered")
        _require_type(stage["actionable_size"], str, "project_stage.actionable_size")
    return data


def validate_action_plan(data: dict[str, Any]) -> dict[str, Any]:
    _require_type(data, dict, "action-plan")
    _migrate_action_plan(data)
    _require_keys(
        data,
        (
            "schema_version",
            "purpose",
            "dry_run",
            "plan_id",
            "generated_at",
            "expires_at",
            "platform",
            "home",
            "source_analysis_sha256",
            "actions",
            "rejected",
            "decision",
        ),
        "action-plan",
    )
    if data["purpose"] not in ("dry-run", "session"):
        raise ContractError("action-plan purpose 必须是 dry-run 或 session")
    for key in ("purpose", "plan_id", "generated_at", "expires_at", "platform", "home"):
        _require_type(data[key], str, f"action-plan {key}")
    _require_type(data["dry_run"], bool, "action-plan dry_run")
    if data["dry_run"] is not (data["purpose"] == "dry-run"):
        raise ContractError("action-plan dry_run 与 purpose 不一致")
    if data["platform"] != "darwin":
        raise ContractError("action-plan platform 当前必须是 darwin")
    _require_sha256(data["source_analysis_sha256"], "source_analysis_sha256")
    _require_type(data["actions"], list, "actions")
    _require_type(data["rejected"], list, "rejected")
    action_ids: set[str] = set()
    for index, action in enumerate(data["actions"]):
        _require_type(action, dict, f"actions[{index}]")
        _require_keys(
            action,
            (
                "action_id",
                "mode",
                "path",
                "canonical_path",
                "tier",
                "rule_id",
                "recovery",
                "risk",
                "non_targets",
                "identity",
                "parent_identity",
                "size_estimate_bytes",
            ),
            f"actions[{index}]",
        )
        if action["mode"] not in ("open", "trash", "reviewed_trash"):
            raise ContractError(f"actions[{index}] 含不支持的 mode")
        for key in ("action_id", "path", "canonical_path", "tier", "rule_id", "recovery", "risk"):
            _require_type(action[key], str, f"actions[{index}].{key}")
        if len(action["action_id"]) < 16 or action["action_id"] in action_ids:
            raise ContractError(f"actions[{index}].action_id 过短或重复")
        action_ids.add(action["action_id"])
        if action["tier"] not in ("green", "yellow", "red"):
            raise ContractError(f"actions[{index}].tier 无效")
        size_estimate = action["size_estimate_bytes"]
        if isinstance(size_estimate, bool) or not isinstance(size_estimate, int) or size_estimate < 0:
            raise ContractError(f"actions[{index}].size_estimate_bytes 必须是非负整数")
        if "runtime" in action:
            _validate_runtime(action["runtime"], f"actions[{index}].runtime", live_state=True)
        if "project" in action:
            project = action["project"]
            _require_type(project, dict, f"actions[{index}].project")
            _require_keys(
                project,
                ("project_root", "artifact_kind", "idle_seconds", "latest_mtime_ns"),
                f"actions[{index}].project",
            )
            if action["rule_id"] != "reviewed.project-artifact":
                raise ContractError(f"actions[{index}].project 只能用于项目生成目录")
            for key in ("project_root", "artifact_kind"):
                _require_type(project[key], str, f"actions[{index}].project.{key}")
            for key in ("idle_seconds", "latest_mtime_ns"):
                value = project[key]
                if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                    raise ContractError(f"actions[{index}].project.{key} 必须是非负整数")
            if project["idle_seconds"] < MIN_PROJECT_IDLE_SECONDS:
                raise ContractError(f"actions[{index}].project.idle_seconds 不能少于 1800 秒")
        _require_string_list(action["non_targets"], f"actions[{index}].non_targets")
        for identity_key in ("identity", "parent_identity"):
            label = f"actions[{index}].{identity_key}"
            identity = action[identity_key]
            _require_type(identity, dict, label)
            _require_keys(
                identity,
                ("device", "inode", "mode", "kind", "size", "mtime_ns"),
                label,
            )
            for key in ("device", "inode", "mode", "size", "mtime_ns"):
                value = identity[key]
                if isinstance(value, bool) or not isinstance(value, int):
                    raise ContractError(f"{label}.{key} 必须是整数")
            if identity["device"] < 0 or identity["inode"] < 0 or identity["mode"] < 0 or identity["size"] < 0:
                raise ContractError(f"{label} 包含无效的负数身份字段")
            if identity["kind"] not in ("file", "directory"):
                raise ContractError(f"{label}.kind 无效")
            if identity_key == "parent_identity" and identity["kind"] != "directory":
                raise ContractError(f"{label}.kind 必须是 directory")
    for index, rejected in enumerate(data["rejected"]):
        label = f"rejected[{index}]"
        _require_type(rejected, dict, label)
        _require_keys(rejected, ("path", "mode", "code", "message", "size_estimate_bytes"), label)
        for key in ("path", "code", "message"):
            _require_type(rejected[key], str, f"{label}.{key}")
        if rejected["mode"] not in ("open", "trash", "reviewed_trash"):
            raise ContractError(f"{label}.mode 无效")
        size = rejected["size_estimate_bytes"]
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            raise ContractError(f"{label}.size_estimate_bytes 必须是非负整数")
        if "name" in rejected:
            _require_type(rejected["name"], str, f"{label}.name")
    decision = data["decision"]
    _require_type(decision, dict, "decision")
    _require_keys(decision, ("discovery", "actionable", "blocked"), "decision")
    for section, keys in (("discovery", ("green", "yellow", "red")), ("actionable", ("trash", "reviewed_trash", "open"))):
        _require_type(decision[section], dict, f"decision.{section}")
        _require_keys(decision[section], keys, f"decision.{section}")
        for key in keys:
            bucket = decision[section][key]
            _require_type(bucket, dict, f"decision.{section}.{key}")
            _require_keys(bucket, ("count", "size_bytes"), f"decision.{section}.{key}")
            for field in ("count", "size_bytes"):
                value = bucket[field]
                if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                    raise ContractError(f"decision.{section}.{key}.{field} 必须是非负整数")
    blocked = decision["blocked"]
    _require_type(blocked, dict, "decision.blocked")
    _require_keys(blocked, ("count", "size_bytes", "reasons"), "decision.blocked")
    _require_type(blocked["reasons"], list, "decision.blocked.reasons")
    for index, reason in enumerate(blocked["reasons"]):
        label = f"decision.blocked.reasons[{index}]"
        _require_type(reason, dict, label)
        _require_keys(reason, ("code", "message", "count", "size_bytes"), label)
        for key in ("code", "message"):
            _require_type(reason[key], str, f"{label}.{key}")
        for key in ("count", "size_bytes"):
            value = reason[key]
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ContractError(f"{label}.{key} 必须是非负整数")

    # The decision block is derived data. Requiring it to agree with the
    # action lists prevents a stale or hand-edited summary from overstating
    # what the current plan can actually do.
    expected_actionable = _actionable_buckets(data["actions"])
    if decision["actionable"] != expected_actionable:
        raise ContractError("decision.actionable 与 actions 不一致")
    expected_blocked = _blocked_bucket(data["rejected"])
    if decision["blocked"] != expected_blocked:
        raise ContractError("decision.blocked 与 rejected 不一致")
    return data
