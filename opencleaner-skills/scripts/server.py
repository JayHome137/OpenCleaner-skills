#!/usr/bin/env python3
"""Serve the report with short-lived, policy-validated local actions.

Usage:
    server.py <analysis.json>

The browser never submits paths or operation modes. It submits action IDs from
an in-memory plan; the server revalidates every target before execution. The
only mutating action is moving an authorized path to Trash/Recycle Bin.
"""
from __future__ import annotations

import json
import secrets
import sys
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Mapping, Optional, Sequence

HERE = Path(__file__).resolve().parent
TEMPLATE = HERE.parent / "assets" / "report_template.html"
MAX_REQUEST_BYTES = 64 * 1024
MAX_ACTIONS_PER_REQUEST = 50

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
        self.actions = {action["action_id"]: action for action in plan["actions"]}
        self.completed: set[str] = set()
        self.lock = threading.Lock()

    def public_config(self) -> dict[str, Any]:
        return {
            "token": self.token,
            "endpoint": "/action",
            "plan_id": self.plan["plan_id"],
            "expires_at": self.plan["expires_at"],
            "actions": [
                {
                    "action_id": action["action_id"],
                    "mode": action["mode"],
                    "path": action["path"],
                }
                for action in self.plan["actions"]
            ],
        }

    def render(self) -> str:
        report_blob = json_for_script(self.analysis)
        config_blob = json_for_script(self.public_config())
        return self.template.replace("__REPORT_DATA__", report_blob).replace(
            "__DELETE_CONFIG__", config_blob
        )

    def execute(self, action_ids: Sequence[str]) -> dict[str, Any]:
        if not action_ids or len(action_ids) > MAX_ACTIONS_PER_REQUEST:
            raise PolicyError("invalid_batch", "操作数量必须在 1 到 50 之间")
        if len(set(action_ids)) != len(action_ids):
            raise PolicyError("duplicate_action", "一次请求不能包含重复操作")
        ensure_plan_fresh(self.plan)
        try:
            actions = [self.actions[action_id] for action_id in action_ids]
        except KeyError as exc:
            raise PolicyError("unknown_action", "操作 ID 不属于当前计划") from exc
        for action in actions:
            if action["mode"] == "trash" and action["action_id"] in self.completed:
                raise PolicyError("action_completed", "该目标已经处理，请重新扫描")

        # Validate the full batch before the first side effect.
        for action in actions:
            self.policy.revalidate(action)

        results = []
        completed_this_request = 0
        for action in actions:
            result = self.operator.execute(
                action,
                self.plan["plan_id"],
                self.plan["purpose"],
            )
            results.append(result)
            if result["status"] == "completed" and action["mode"] == "trash":
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
    policy = SafetyPolicy(home=home, platform=platform, environment=environment)
    plan = build_action_plan(
        analysis,
        home=policy.home,
        platform=policy.platform,
        environment=policy.environment,
        purpose="session",
    )
    operator = FileOperator(policy, OperationLog(state_dir))
    return ServerContext(analysis, template, policy, plan, operator=operator)


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
            if self.path not in ("/", "/index.html"):
                self._send(404, "not found", "text/plain; charset=utf-8")
                return
            if not self._host_allowed():
                self._send(403, {"ok": False, "error": "Host 不被允许"})
                return
            self._send(200, context.render(), "text/html; charset=utf-8")

        def do_POST(self) -> None:
            if self.path != "/action":
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
            if not isinstance(request, dict) or set(request) != {"token", "plan_id", "action_ids"}:
                self._send(400, {"ok": False, "error": "请求字段无效"})
                return
            if not secrets.compare_digest(str(request.get("token", "")), context.token):
                self._send(403, {"ok": False, "error": "token 校验失败"})
                return
            if request.get("plan_id") != context.plan["plan_id"]:
                self._send(409, {"ok": False, "error": "操作计划已经变化"})
                return
            action_ids = request.get("action_ids")
            if not isinstance(action_ids, list) or any(not isinstance(item, str) for item in action_ids):
                self._send(400, {"ok": False, "error": "action_ids 格式无效"})
                return
            try:
                with context.lock:
                    response = context.execute(action_ids)
            except PolicyError as exc:
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
    open_count = sum(1 for action in context.plan["actions"] if action["mode"] == "open")
    print(f"报告服务已启动：{url}")
    print(
        f"已授权移到废纸篓 {trash_count} 项 | 可打开查看 {open_count} 项 | "
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
