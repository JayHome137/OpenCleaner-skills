#!/usr/bin/env python3
"""Deterministic owner hints and fail-closed runtime process checks."""
from __future__ import annotations

import csv
import io
import os
import shlex
import shutil
import subprocess
from typing import Any, Callable, Optional

ProcessChecker = Callable[[str], Optional[bool]]
ToolChecker = Callable[[str], bool]


def owner_profile(path: str, rule_id: str = "") -> dict[str, Any]:
    normalized = os.path.normcase(path).replace("\\", "/").casefold()
    basename = os.path.basename(normalized.rstrip("/"))
    profile: dict[str, Any] = {}

    if rule_id == "macos.xcode-derived-data-entry":
        profile = {
            "id": "xcode",
            "processes": ["Xcode", "xcodebuild", "swiftc"],
            "owner_tool": {
                "name": "Xcode",
                "inspect_command": "",
                "cleanup_command": "",
                "execution": "app-managed",
            },
        }
    elif rule_id == "macos.pnpm-cache-entry" or "/library/pnpm/store/" in normalized:
        profile = {
            "id": "pnpm",
            "processes": ["pnpm"],
            "owner_tool": {
                "name": "pnpm",
                "inspect_command": "pnpm store path",
                "cleanup_command": "pnpm store prune",
                "execution": "review-only",
            },
        }
    elif rule_id == "common.npm-content-cache" or "/.npm/_cacache" in normalized:
        profile = {
            "id": "npm",
            "processes": ["npm"],
            "owner_tool": {
                "name": "npm",
                "inspect_command": "npm cache verify",
                "cleanup_command": "",
                "execution": "review-only",
            },
        }
    elif rule_id == "common.gradle-cache-entry" or "/.gradle/caches/" in normalized:
        profile = {
            "id": "gradle",
            "processes": ["GradleDaemon"],
            "owner_tool": {
                "name": "Gradle",
                "inspect_command": "gradle --status",
                "cleanup_command": "",
                "execution": "review-only",
            },
        }
    elif rule_id == "common.go-module-cache" or basename == "go-build" or "/go-build/" in normalized:
        profile = {
            "id": "go-module" if rule_id == "common.go-module-cache" else "go-build",
            "processes": ["go build", "go test"],
            "owner_tool": {
                "name": "Go",
                "inspect_command": "go env GOMODCACHE" if rule_id == "common.go-module-cache" else "go env GOCACHE",
                "cleanup_command": "go clean -modcache" if rule_id == "common.go-module-cache" else "go clean -cache",
                "execution": "review-only",
            },
        }
    elif "/library/caches/google" in normalized or "chrome" in basename:
        profile = {
            "id": "chrome",
            "processes": ["Google Chrome"],
            "owner_tool": {"name": "Chrome", "inspect_command": "", "cleanup_command": "", "execution": "app-managed"},
        }
    elif (
        rule_id.startswith("common.codex-")
        or "/library/caches/codex" in normalized
        or "/library/caches/com.openai.codex" in normalized
        or "/.cache/codex-runtimes" in normalized
        or "/.codex/cache" in normalized
        or "/.codex/.tmp/" in normalized
        or "/.codex/plugins/cache" in normalized
    ):
        profile = {
            "id": "codex",
            "processes": ["Codex"],
            "owner_tool": {"name": "Codex", "inspect_command": "", "cleanup_command": "", "execution": "app-managed"},
        }
    elif rule_id == "common.claude-cache" or "claude" in basename or "/claude" in normalized or "/.claude/" in normalized:
        profile = {
            "id": "claude",
            "processes": ["Claude"],
            "owner_tool": {"name": "Claude", "inspect_command": "", "cleanup_command": "", "execution": "app-managed"},
        }
    elif "com.utmapp.utm" in normalized or basename == "utm":
        profile = {
            "id": "utm",
            "processes": ["UTM"],
            "owner_tool": {"name": "UTM", "inspect_command": "", "cleanup_command": "", "execution": "app-managed"},
        }
    elif "/.tart/" in normalized or basename == "tart":
        profile = {
            "id": "tart",
            "processes": ["tart"],
            "owner_tool": {
                "name": "Tart",
                "inspect_command": "tart list",
                "cleanup_command": "tart prune --entries caches --older-than 30",
                "execution": "review-only",
            },
        }
    elif "/.docker/" in normalized or "orbstack" in normalized:
        profile = {
            "id": "docker",
            "processes": ["Docker", "OrbStack"],
            "owner_tool": {
                "name": "Docker / OrbStack",
                "inspect_command": "docker system df",
                "cleanup_command": "",
                "execution": "review-only",
            },
        }
    elif "wechat" in normalized or "xinwechat" in normalized:
        profile = {
            "id": "wechat",
            "processes": ["WeChat"],
            "owner_tool": {"name": "微信", "inspect_command": "", "cleanup_command": "", "execution": "app-managed"},
        }
    return profile


class RuntimeInspector:
    def __init__(
        self,
        platform: str,
        checker: Optional[ProcessChecker] = None,
        tool_checker: Optional[ToolChecker] = None,
    ) -> None:
        self.platform = platform
        self.checker = checker or self._default_check
        self.tool_checker = tool_checker or (lambda executable: shutil.which(executable) is not None)

    def _default_check(self, pattern: str) -> Optional[bool]:
        try:
            if self.platform == "darwin":
                result = subprocess.run(
                    ["/usr/bin/pgrep", "-ifl", pattern],
                    capture_output=True,
                    text=True,
                    timeout=3,
                    check=False,
                )
                if result.returncode == 0:
                    return True
                if result.returncode == 1:
                    return False
                return None
            result = subprocess.run(
                ["tasklist", "/FO", "CSV", "/NH"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if result.returncode != 0:
                return None
            names = [row[0].casefold() for row in csv.reader(io.StringIO(result.stdout)) if row]
            needle = pattern.casefold()
            return any(needle in name for name in names)
        except (OSError, subprocess.SubprocessError):
            return None

    def inspect(self, path: str, rule_id: str = "") -> dict[str, Any]:
        profile = owner_profile(path, rule_id)
        if not profile:
            return {}
        inspect_command = str(profile["owner_tool"].get("inspect_command", "")).strip()
        if inspect_command:
            try:
                executable = shlex.split(inspect_command)[0]
            except (IndexError, ValueError):
                return {**profile, "state": "unknown", "reason": "owner_tool_invalid"}
            if not self.tool_checker(executable):
                return {**profile, "state": "unknown", "reason": "owner_tool_missing"}
        states = [self.checker(process) for process in profile["processes"]]
        if any(state is True for state in states):
            state = "active"
        elif any(value is None for value in states):
            state = "unknown"
        else:
            state = "inactive"
        return {**profile, "state": state}
