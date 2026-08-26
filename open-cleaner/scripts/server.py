#!/usr/bin/env python3
"""Serve the report with short-lived, policy-validated local actions.

Usage:
    server.py <analysis.json>

The browser never submits paths or operation modes. It submits action IDs from
an in-memory plan; the server revalidates every target before execution. The
mutating modes only move an authorized path to the macOS Trash.
"""
from __future__ import annotations

import json
import os
import secrets
import sys
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Mapping, Optional, Sequence
from urllib.parse import parse_qs, urlsplit

HERE = Path(__file__).resolve().parent
TEMPLATE = HERE.parent / "assets" / "report_template.html"
MAX_REQUEST_BYTES = 64 * 1024
MAX_ACTIONS_PER_REQUEST = 50
REVIEW_TOKEN_TTL_SECONDS = 120

if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from contracts import (  # noqa: E402
    ContractError,
    canonical_sha256,
    json_for_script,
    load_json_object,
    validate_action_plan,
    validate_analysis,
)
from file_ops import FileOperator, OperationLog  # noqa: E402
from policy import PolicyError, SafetyPolicy, build_action_plan, ensure_plan_fresh  # noqa: E402
from compare_reports import compare as compare_reports  # noqa: E402
from browse import browse_directory  # noqa: E402
from settings import SettingsError, SettingsStore  # noqa: E402


def configure_text_output() -> None:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")


class ServerContext:
    def __init__(
        self,
        analysis: dict[str, Any],
        template: str,
        policy: SafetyPolicy,
        plan: dict[str, Any],
        operator: Optional[FileOperator] = None,
        token: Optional[str] = None,
        rescan_handler: Optional[Callable[[], dict[str, Any]]] = None,
        settings_store: Optional[SettingsStore] = None,
    ) -> None:
        self.analysis = validate_analysis(analysis)
        validate_action_plan(plan)
        if plan.get("purpose") != "session" or plan.get("dry_run") is not False:
            raise PolicyError("dry_run_only", "Dry Run 计划不能用于文件操作会话")
        if plan["source_analysis_sha256"] != canonical_sha256(self.analysis):
            raise PolicyError("analysis_changed", "操作计划不属于当前 analysis")
        self.template = template
        self.policy = policy
        self.plan = plan
        self.operator = operator or FileOperator(policy, OperationLog())
        self.token = token or secrets.token_urlsafe(32)
        self.rescan_handler = rescan_handler
        self.settings_store = settings_store or policy.settings_store
        self.actions = {action["action_id"]: action for action in plan["actions"]}
        self.completed: set[str] = set()
        self.review_tokens: dict[str, dict[str, Any]] = {}
        self.last_comparison: Optional[dict[str, Any]] = None
        self.lock = threading.Lock()

    def public_config(self) -> dict[str, Any]:
        return {
            "token": self.token,
            "endpoint": "/action",
            "review_endpoint": "/review" if any(
                action["mode"] == "reviewed_trash" for action in self.plan["actions"]
            ) else "",
            "rescan_endpoint": "/rescan" if self.rescan_handler else "",
            "browse_endpoint": "/browse",
            "settings_endpoint": "/settings",
            "plan_id": self.plan["plan_id"],
            "expires_at": self.plan["expires_at"],
            "rejected": [
                {
                    "path": item["path"],
                    "mode": item["mode"],
                    "code": item["code"],
                    "message": item["message"],
                    "name": item.get("name", ""),
                    "size_estimate_bytes": item.get("size_estimate_bytes", 0),
                }
                for item in self.plan["rejected"]
            ],
            "actions": [
                {
                    "action_id": action["action_id"],
                    "mode": action["mode"],
                    "path": action["path"],
                    "size_estimate_bytes": action.get("size_estimate_bytes", 0),
                    **({"runtime": action["runtime"]} if action.get("runtime") else {}),
                }
                for action in self.plan["actions"]
            ],
        }

    def decision_data(self) -> dict[str, Any]:
        operation_log = getattr(self.operator, "operation_log", None)
        recent = getattr(operation_log, "recent", None)
        history = recent() if callable(recent) else {
            "status": "unavailable", "entries": [], "completed": 0, "failed": 0, "disk_delta_bytes": 0
        }
        return {
            **self.plan["decision"],
            "authorized": [
                {"mode": item["mode"], "path": item["path"], "size_estimate_bytes": item.get("size_estimate_bytes", 0)}
                for item in self.plan["actions"]
            ],
            "rejected_items": [
                {
                    "mode": item["mode"], "path": item["path"], "code": item["code"],
                    "message": item["message"], "size_estimate_bytes": item.get("size_estimate_bytes", 0),
                }
                for item in self.plan["rejected"]
            ],
            "history": history,
            "comparison": self.last_comparison,
        }

    def settings(self) -> dict[str, Any]:
        return self.settings_store.load()

    def browse(self, parameters: Mapping[str, list[str]]) -> dict[str, Any]:
        allowed = {"path", "search", "sort", "descending", "min_size_bytes"}
        if set(parameters) - allowed:
            raise SettingsError("unknown_browse_field", "目录浏览请求包含未知字段")
        path = (parameters.get("path") or [""])[0]
        if not path:
            raise SettingsError("browse_path_required", "目录浏览缺少 path")
        try:
            minimum = int((parameters.get("min_size_bytes") or ["0"])[0])
        except ValueError as exc:
            raise SettingsError("invalid_size_filter", "大小筛选必须是整数") from exc
        return browse_directory(
            self.settings_store,
            path,
            search=(parameters.get("search") or [""])[0],
            sort=(parameters.get("sort") or ["name"])[0],
            descending=(parameters.get("descending") or ["false"])[0].casefold() == "true",
            min_size_bytes=minimum,
        )

    def update_settings(self, value: Mapping[str, Any]) -> dict[str, Any]:
        saved = self.settings_store.save(value)
        refreshed = validate_analysis(
            self.rescan_handler() if self.rescan_handler is not None else self.analysis
        )
        refreshed_plan = build_action_plan(
            refreshed,
            home=self.policy.home,
            platform=self.policy.platform,
            environment=self.policy.environment,
            purpose="session",
            runtime_inspector=self.policy.runtime_inspector,
            settings_store=self.settings_store,
        )
        self.analysis = refreshed
        self.plan = refreshed_plan
        self.actions = {action["action_id"]: action for action in refreshed_plan["actions"]}
        self.completed.clear()
        self.review_tokens.clear()
        return {"ok": True, "settings": saved, "plan_id": refreshed_plan["plan_id"]}

    def rescan(self) -> dict[str, Any]:
        if self.rescan_handler is None:
            raise PolicyError("rescan_unavailable", "当前报告不支持重新扫描")
        refreshed = validate_analysis(self.rescan_handler())
        comparison = compare_reports(self.analysis, refreshed)
        refreshed_plan = build_action_plan(
            refreshed,
            home=self.policy.home,
            platform=self.policy.platform,
            environment=self.policy.environment,
            purpose="session",
            runtime_inspector=self.policy.runtime_inspector,
            settings_store=self.settings_store,
        )
        self.analysis = refreshed
        self.last_comparison = comparison
        self.plan = refreshed_plan
        self.actions = {action["action_id"]: action for action in refreshed_plan["actions"]}
        self.completed.clear()
        self.review_tokens.clear()
        return {
            "ok": True,
            "plan_id": refreshed_plan["plan_id"],
            "expires_at": refreshed_plan["expires_at"],
        }

    def render(self) -> str:
        report_blob = json_for_script(self.analysis)
        config_blob = json_for_script(self.public_config())
        decision_blob = json_for_script(self.decision_data())
        return (
            self.template.replace("__REPORT_DATA__", report_blob)
            .replace("__DECISION_DATA__", decision_blob)
            .replace("__DELETE_CONFIG__", config_blob)
        )

    def _resolve_actions(self, action_ids: Sequence[str]) -> list[dict[str, Any]]:
        if not action_ids or len(action_ids) > MAX_ACTIONS_PER_REQUEST:
            raise PolicyError("invalid_batch", "操作数量必须在 1 到 50 之间")
        if len(set(action_ids)) != len(action_ids):
            raise PolicyError("duplicate_action", "一次请求不能包含重复操作")
        try:
            actions = [self.actions[action_id] for action_id in action_ids]
        except KeyError as exc:
            raise PolicyError("unknown_action", "操作 ID 不属于当前计划") from exc
        for action in actions:
            if action["mode"] in ("trash", "reviewed_trash") and action[
                "action_id"
            ] in self.completed:
                raise PolicyError("action_completed", "该目标已经处理，请重新扫描")
        return actions

    def review(self, action_ids: Sequence[str]) -> dict[str, Any]:
        ensure_plan_fresh(self.plan)
        actions = self._resolve_actions(action_ids)
        if any(action["mode"] != "reviewed_trash" for action in actions):
            raise PolicyError("review_mode_required", "复核令牌只能签发给黄灯人工复核动作")
        self.policy.runtime_inspector.refresh_open_file_snapshot()
        for action in actions:
            self.policy.revalidate(action)
        review_token = secrets.token_urlsafe(32)
        self.review_tokens[review_token] = {
            "plan_id": self.plan["plan_id"],
            "action_ids": tuple(sorted(action_ids)),
            "expires_at": time.monotonic() + REVIEW_TOKEN_TTL_SECONDS,
            "used": False,
        }
        return {
            "ok": True,
            "review_token": review_token,
            "expires_in_seconds": REVIEW_TOKEN_TTL_SECONDS,
        }

    def execute(
        self,
        action_ids: Sequence[str],
        review_token: Optional[str] = None,
    ) -> dict[str, Any]:
        ensure_plan_fresh(self.plan)
        actions = self._resolve_actions(action_ids)
        reviewed = [action for action in actions if action["mode"] == "reviewed_trash"]
        if reviewed and len(reviewed) != len(actions):
            raise PolicyError("mixed_review_batch", "普通动作与黄灯人工复核动作不能混合提交")
        token_record = None
        if reviewed:
            token_record = self.review_tokens.get(review_token or "")
            if token_record is None:
                raise PolicyError("review_token_required", "缺少有效的黄灯复核令牌")
            if token_record["used"]:
                raise PolicyError("review_token_used", "黄灯复核令牌已经使用")
            if token_record["expires_at"] <= time.monotonic():
                raise PolicyError("review_token_expired", "黄灯复核令牌已经过期")
            if token_record["plan_id"] != self.plan["plan_id"] or token_record[
                "action_ids"
            ] != tuple(sorted(action_ids)):
                raise PolicyError("review_token_mismatch", "黄灯复核令牌与当前操作不匹配")
        elif review_token:
            raise PolicyError("unexpected_review_token", "普通动作不能携带黄灯复核令牌")

        # Validate the full batch before the first side effect.
        self.policy.runtime_inspector.refresh_open_file_snapshot()
        for action in actions:
            self.policy.revalidate(action)
        if token_record is not None:
            token_record["used"] = True

        results = []
        completed_this_request = 0
        for action in actions:
            result = self.operator.execute(
                action,
                self.plan["plan_id"],
                self.plan["purpose"],
            )
            results.append(result)
            if result["status"] == "completed" and action["mode"] in (
                "trash",
                "reviewed_trash",
            ):
                self.completed.add(action["action_id"])
                completed_this_request += 1
            if result["status"] != "completed":
                return {
                    "ok": False,
                    "partial": completed_this_request > 0,
                    "results": results,
                    "error": result.get("error", "操作失败"),
                }
        return {"ok": True, "results": results}


def create_context(
    analysis_path: str,
    home: Optional[str] = None,
    platform: Optional[str] = None,
    environment: Optional[Mapping[str, str]] = None,
    state_dir: Optional[str] = None,
) -> ServerContext:
    analysis = load_json_object(analysis_path)
    validate_analysis(analysis)
    template = TEMPLATE.read_text(encoding="utf-8")
    normalized_home = os.path.abspath(os.path.expanduser(home or "~"))
    settings_store = SettingsStore(
        normalized_home,
        environment,
        state_dir=state_dir,
    )
    policy = SafetyPolicy(
        home=home,
        platform=platform,
        environment=environment,
        settings_store=settings_store,
    )
    plan = build_action_plan(
        analysis,
        home=policy.home,
        platform=policy.platform,
        environment=policy.environment,
        purpose="session",
        runtime_inspector=policy.runtime_inspector,
        settings_store=settings_store,
    )
    operator = FileOperator(policy, OperationLog(state_dir))

    def rescan_current() -> dict[str, Any]:
        roots = [
            root
            for root in settings_store.load()["scan_roots"]
            if os.path.normcase(root) != os.path.normcase(policy.home)
        ]
        if analysis.get("analysis_origin") == "project-stage":
            from project_stage import build_project_stage_analysis

            project_options: dict[str, Any] = {}
            if roots:
                project_options["custom_roots"] = roots
            return build_project_stage_analysis(
                environment=policy.environment,
                min_kb=int(analysis["project_stage"].get("min_kb", 50 * 1024)),
                **project_options,
            )
        from classify import build_analysis
        from scan import scan_current

        scan_result = scan_current(platform=policy.platform, custom_roots=roots)
        return build_analysis(
            scan_result,
            environment=policy.environment,
            settings_store=settings_store,
        )

    return ServerContext(
        analysis,
        template,
        policy,
        plan,
        operator=operator,
        rescan_handler=rescan_current,
        settings_store=settings_store,
    )


def make_handler(context: ServerContext) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args: object) -> None:
            return

        def _send(self, code: int, body: Any, content_type: str = "application/json; charset=utf-8") -> None:
            if not isinstance(body, (str, bytes)):
                body = json.dumps(body, ensure_ascii=False)
            payload = body.encode("utf-8") if isinstance(body, str) else body
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
                "connect-src 'self'; img-src 'self' data:; base-uri 'none'; "
                "form-action 'none'; frame-ancestors 'none'",
            )
            self.end_headers()
            self.wfile.write(payload)

        def _host_allowed(self) -> bool:
            host = (self.headers.get("Host") or "").split(":", 1)[0].lower()
            return host in ("127.0.0.1", "localhost")

        def do_GET(self) -> None:
            parsed = urlsplit(self.path)
            if parsed.path not in ("/", "/index.html", "/browse", "/settings"):
                self._send(404, "not found", "text/plain; charset=utf-8")
                return
            if not self._host_allowed():
                self._send(403, {"ok": False, "error": "Host 不被允许"})
                return
            if parsed.path in ("/", "/index.html"):
                self._send(200, context.render(), "text/html; charset=utf-8")
                return
            if not secrets.compare_digest(
                self.headers.get("X-OpenCleaner-Token", ""), context.token
            ):
                self._send(403, {"ok": False, "error": "访问令牌无效"})
                return
            try:
                if parsed.path == "/settings":
                    response = {"ok": True, "settings": context.settings()}
                else:
                    response = {"ok": True, **context.browse(parse_qs(parsed.query, keep_blank_values=True))}
            except (PolicyError, SettingsError, OSError, ValueError) as exc:
                self._send(400, {"ok": False, "error": str(exc), "code": getattr(exc, "code", "request_failed")})
                return
            self._send(200, response)

        def do_POST(self) -> None:
            if self.path not in ("/action", "/review", "/rescan", "/settings"):
                self._send(404, {"ok": False, "error": "not found"})
                return
            if not self._host_allowed():
                self._send(403, {"ok": False, "error": "Host 不被允许"})
                return
            if not (self.headers.get("Content-Type") or "").lower().startswith("application/json"):
                self._send(415, {"ok": False, "error": "Content-Type 必须是 application/json"})
                return
            try:
                content_length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                content_length = -1
            if content_length <= 0 or content_length > MAX_REQUEST_BYTES:
                self._send(413, {"ok": False, "error": "请求体大小无效"})
                return
            try:
                request = json.loads(self.rfile.read(content_length))
            except (json.JSONDecodeError, UnicodeDecodeError):
                self._send(400, {"ok": False, "error": "请求 JSON 无效"})
                return
            if self.path == "/action":
                expected_fields = (
                    {"token", "plan_id", "action_ids"},
                    {"token", "plan_id", "action_ids", "review_token"},
                )
            elif self.path == "/review":
                expected_fields = ({"token", "plan_id", "action_ids"},)
            elif self.path == "/settings":
                expected_fields = ({"token", "plan_id", "settings"},)
            else:
                expected_fields = ({"token", "plan_id"},)
            if not isinstance(request, dict) or set(request) not in expected_fields:
                self._send(400, {"ok": False, "error": "请求字段无效"})
                return
            if not secrets.compare_digest(str(request.get("token", "")), context.token):
                self._send(403, {"ok": False, "error": "token 校验失败"})
                return
            if request.get("plan_id") != context.plan["plan_id"]:
                self._send(409, {"ok": False, "error": "操作计划已经变化"})
                return
            try:
                with context.lock:
                    if self.path == "/rescan":
                        response = context.rescan()
                    elif self.path == "/settings":
                        value = request.get("settings")
                        if not isinstance(value, dict):
                            self._send(400, {"ok": False, "error": "settings 格式无效"})
                            return
                        response = context.update_settings(value)
                    else:
                        action_ids = request.get("action_ids")
                        if not isinstance(action_ids, list) or any(
                            not isinstance(item, str) for item in action_ids
                        ):
                            self._send(400, {"ok": False, "error": "action_ids 格式无效"})
                            return
                        if self.path == "/review":
                            response = context.review(action_ids)
                        else:
                            review_token = request.get("review_token")
                            if review_token is not None and not isinstance(review_token, str):
                                self._send(400, {"ok": False, "error": "review_token 格式无效"})
                                return
                            response = context.execute(action_ids, review_token=review_token)
            except (ContractError, PolicyError, SettingsError, OSError, ValueError) as exc:
                if not isinstance(exc, (PolicyError, SettingsError)):
                    label = "重新扫描失败" if self.path == "/rescan" else "请求处理失败"
                    self._send(500, {"ok": False, "error": f"{label}：{exc}"})
                    return
                self._send(409, {"ok": False, "error": str(exc), "code": exc.code})
                return
            self._send(200 if response.get("ok") else 500, response)

    return Handler


def main() -> None:
    configure_text_output()
    if len(sys.argv) != 2:
        print(__doc__)
        raise SystemExit(2)
    try:
        context = create_context(sys.argv[1])
    except (ContractError, PolicyError, OSError) as exc:
        print(f"报告服务启动失败：{exc}", file=sys.stderr)
        raise SystemExit(1) from exc
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(context))
    port = server.server_address[1]
    url = f"http://127.0.0.1:{port}/"
    trash_count = sum(1 for action in context.plan["actions"] if action["mode"] == "trash")
    reviewed_count = sum(
        1 for action in context.plan["actions"] if action["mode"] == "reviewed_trash"
    )
    open_count = sum(1 for action in context.plan["actions"] if action["mode"] == "open")
    print(f"报告服务已启动：{url}")
    print(
        f"绿灯可移到废纸篓 {trash_count} 项 | 黄灯可人工复核 {reviewed_count} 项 | "
        f"可打开查看 {open_count} 项 | "
        f"拒绝 {len(context.plan['rejected'])} 项"
    )
    print("所有操作计划 30 分钟后失效；用完按 Ctrl+C 停止服务。")
    webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n已停止服务。")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
