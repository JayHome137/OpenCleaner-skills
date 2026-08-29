from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from contextlib import contextmanager
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "open-cleaner" / "scripts"
sys.path.insert(0, str(SCRIPTS))

from file_ops import FileOperator, OperationLog
from policy import PolicyError, SafetyPolicy, build_action_plan
from runtime import RuntimeInspector
from server import ServerContext, create_context, make_handler
from test_policy import analysis_for, test_catalog


@contextmanager
def running(context):
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(context))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


class ServerContextTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="storage-server-")
        self.root = Path(self.temp.name)
        self.home = self.root / "home"
        self.home.mkdir()
        self.environment = {"HOME": str(self.home)}
        self.catalog = test_catalog(self.home)
        self.runtime_inspector = RuntimeInspector(
            "darwin",
            checker=lambda _pattern: False,
            tool_checker=lambda _tool: True,
            open_file_checker=lambda _path: False,
        )
        self.policy = SafetyPolicy(
            home=str(self.home),
            platform="darwin",
            environment=self.environment,
            catalog=self.catalog,
            runtime_inspector=self.runtime_inspector,
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def make_cache(self, name: str) -> Path:
        path = self.home / "TestTrash" / name
        path.mkdir(parents=True)
        old = time.time() - 3600
        os.utime(path, (old, old))
        return path

    def make_context(self, paths, called, rescan_handler=None):
        green = [
            {"name": path.name, "path": str(path), "trash_paths": [str(path)]}
            for path in paths
        ]
        analysis = analysis_for(self.home, green=green)
        plan = build_action_plan(
            analysis,
            home=str(self.home),
            platform="darwin",
            environment=self.environment,
            purpose="session",
            runtime_inspector=self.runtime_inspector,
            catalog=self.catalog,
        )
        fake_trash = self.root / "fake-trash"

        def move(path: str) -> None:
            called.append(path)
            fake_trash.mkdir(exist_ok=True)
            Path(path).rename(fake_trash / Path(path).name)

        operator = FileOperator(
            self.policy,
            OperationLog(self.root / "state"),
            trash_handler=move,
        )
        return ServerContext(
            analysis,
            "<script>const DATA=__REPORT_DATA__;const CONFIG=__DELETE_CONFIG__;</script>",
            self.policy,
            plan,
            operator=operator,
            token="test-token",
            rescan_handler=rescan_handler,
        )

    def make_review_context(self, paths, called):
        yellow = [
            {
                "name": path.name,
                "path": str(path),
                "size": "约 0.0 GB",
                "content_profile": "test",
                "why_manual": "test",
                "disposal": "test",
                "risk": "test",
                "reviewed_trash_paths": [str(path)],
            }
            for path in paths
        ]
        analysis = analysis_for(self.home, yellow=yellow)
        plan = build_action_plan(
            analysis,
            home=str(self.home),
            platform="darwin",
            environment=self.environment,
            purpose="session",
        )
        fake_trash = self.root / "fake-trash"

        def move(path: str) -> None:
            called.append(path)
            fake_trash.mkdir(exist_ok=True)
            Path(path).rename(fake_trash / Path(path).name)

        operator = FileOperator(
            self.policy,
            OperationLog(self.root / "state"),
            trash_handler=move,
            open_handler=lambda _path: None,
        )
        return ServerContext(
            analysis,
            "__REPORT_DATA____DELETE_CONFIG__",
            self.policy,
            plan,
            operator=operator,
            token="test-token",
        )

    def test_expired_review_tokens_are_purged(self) -> None:
        context = self.make_review_context([], [])
        context.review_tokens["expired"] = {
            "expires_at": time.monotonic() - 1,
            "used": False,
        }
        context.review_tokens["live"] = {
            "expires_at": time.monotonic() + 60,
            "used": False,
        }
        context.purge_review_tokens()
        self.assertNotIn("expired", context.review_tokens)
        self.assertIn("live", context.review_tokens)

    def test_loopback_request_rate_limit_is_bounded(self) -> None:
        context = self.make_review_context([], [])
        for _ in range(60):
            self.assertTrue(context.allow_request("127.0.0.1"))
        self.assertFalse(context.allow_request("127.0.0.1"))

    def test_render_exposes_action_ids_but_no_path_submission_contract(self) -> None:
        target = self.make_cache("one")
        context = self.make_context([target], [])
        rendered = context.render()
        self.assertIn(context.plan["actions"][0]["action_id"], rendered)
        self.assertNotIn("__REPORT_DATA__", rendered)
        self.assertEqual(
            context.public_config()["actions"][0]["path"],
            str(target.absolute()),
        )

    def test_public_config_explains_runtime_rejection_without_action(self) -> None:
        target = self.home / "Library" / "Developer" / "Xcode" / "DerivedData" / "Current"
        target.mkdir(parents=True)
        analysis = analysis_for(
            self.home,
            green=[
                {
                    "name": target.name,
                    "path": str(target),
                    "trash_paths": [str(target)],
                    "rule_id": "macos.xcode-derived-data-entry",
                }
            ],
        )
        inspector = RuntimeInspector(
            "darwin",
            checker=lambda _pattern: True,
            open_file_checker=lambda _path: False,
        )
        policy = SafetyPolicy(
            home=str(self.home),
            platform="darwin",
            environment=self.environment,
            runtime_inspector=inspector,
        )
        plan = build_action_plan(
            analysis,
            home=str(self.home),
            platform="darwin",
            environment=self.environment,
            purpose="session",
            runtime_inspector=inspector,
        )
        context = ServerContext(
            analysis,
            "__REPORT_DATA____DELETE_CONFIG__",
            policy,
            plan,
            token="test-token",
        )
        config = context.public_config()
        self.assertEqual(config["actions"], [])
        self.assertEqual(config["rejected"][0]["code"], "owner_tool_only")

    def test_dry_run_plan_cannot_start_operation_session(self) -> None:
        target = self.make_cache("one")
        analysis = analysis_for(
            self.home,
            green=[{"name": target.name, "path": str(target), "trash_paths": [str(target)]}],
        )
        plan = build_action_plan(
            analysis,
            home=str(self.home),
            platform="darwin",
            environment=self.environment,
            purpose="dry-run",
        )
        with self.assertRaises(PolicyError) as raised:
            ServerContext(
                analysis,
                "__REPORT_DATA____DELETE_CONFIG__",
                self.policy,
                plan,
                token="test-token",
            )
        self.assertEqual(raised.exception.code, "dry_run_only")

    def test_session_plan_must_belong_to_current_analysis(self) -> None:
        target = self.make_cache("one")
        context = self.make_context([target], [])
        changed = dict(context.analysis)
        changed["generated_at"] = "changed"
        with self.assertRaises(PolicyError) as raised:
            ServerContext(
                changed,
                "__REPORT_DATA____DELETE_CONFIG__",
                self.policy,
                context.plan,
                token="test-token",
            )
        self.assertEqual(raised.exception.code, "analysis_changed")

    def test_batch_is_fully_revalidated_before_first_operation(self) -> None:
        first = self.make_cache("one")
        second = self.make_cache("two")
        called = []
        context = self.make_context([first, second], called)
        stale = second.with_name("stale")
        second.rename(stale)
        second.mkdir()
        ids = [action["action_id"] for action in context.plan["actions"]]
        with self.assertRaises(PolicyError) as raised:
            context.execute(ids)
        self.assertEqual(raised.exception.code, "identity_changed")
        self.assertEqual(called, [])

    def test_completed_trash_action_cannot_be_replayed(self) -> None:
        target = self.make_cache("one")
        context = self.make_context([target], [])
        action_id = context.plan["actions"][0]["action_id"]
        response = context.execute([action_id])
        self.assertTrue(response["ok"])
        with self.assertRaises(PolicyError) as raised:
            context.execute([action_id])
        self.assertEqual(raised.exception.code, "action_completed")

    def post(self, port: int, body: dict):
        request = urllib.request.Request(
            f"http://127.0.0.1:{port}/action",
            data=json.dumps(body).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        return urllib.request.urlopen(request, timeout=3)

    def post_endpoint(self, port: int, endpoint: str, body: dict):
        request = urllib.request.Request(
            f"http://127.0.0.1:{port}{endpoint}",
            data=json.dumps(body).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        return urllib.request.urlopen(request, timeout=3)

    def valid_request(self, context, action_ids=None, **overrides):
        body = {
            "token": "test-token",
            "plan_id": context.plan["plan_id"],
            "action_ids": action_ids
            if action_ids is not None
            else [context.plan["actions"][0]["action_id"]],
        }
        body.update(overrides)
        return body

    def test_http_rejects_client_supplied_paths_and_mode(self) -> None:
        target = self.make_cache("one")
        context = self.make_context([target], [])
        server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(context))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with self.assertRaises(urllib.error.HTTPError) as raised:
                self.post(
                    server.server_address[1],
                    {
                        "token": "test-token",
                        "plan_id": context.plan["plan_id"],
                        "paths": [str(target)],
                        "mode": "trash",
                    },
                )
            self.assertEqual(raised.exception.code, 400)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)

    def test_http_accepts_only_current_action_id(self) -> None:
        target = self.make_cache("one")
        called = []
        context = self.make_context([target], called)
        server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(context))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            action_id = context.plan["actions"][0]["action_id"]
            with self.post(
                server.server_address[1],
                {
                    "token": "test-token",
                    "plan_id": context.plan["plan_id"],
                    "action_ids": [action_id],
                },
            ) as response:
                payload = json.loads(response.read())
            self.assertTrue(payload["ok"])
            self.assertFalse(payload["results"][0]["target_exists_after"])
            self.assertIn("disk_free_delta_bytes", payload["results"][0])
            self.assertEqual(len(called), 1)
            self.assertIn(".open-cleaner-stage-", called[0])
            self.assertTrue(called[0].endswith("/one"))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)

    def test_report_response_has_local_security_headers(self) -> None:
        target = self.make_cache("one")
        context = self.make_context([target], [])
        with running(context) as port:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=3) as response:
                self.assertEqual(response.headers["X-Frame-Options"], "DENY")
                self.assertIn("frame-ancestors 'none'", response.headers["Content-Security-Policy"])
                self.assertEqual(response.headers["Cache-Control"], "no-store")

    def test_http_rejects_wrong_token_plan_action_and_host(self) -> None:
        target = self.make_cache("one")
        context = self.make_context([target], [])
        cases = [
            (self.valid_request(context, token="wrong"), {}, 403),
            (self.valid_request(context, plan_id="stale-plan"), {}, 409),
            (self.valid_request(context, action_ids=["unknown-action"]), {}, 409),
            (self.valid_request(context), {"Host": "example.invalid"}, 403),
        ]
        with running(context) as port:
            for body, headers, expected in cases:
                with self.subTest(expected=expected, body=body, headers=headers):
                    request = urllib.request.Request(
                        f"http://127.0.0.1:{port}/action",
                        data=json.dumps(body).encode("utf-8"),
                        headers={"Content-Type": "application/json", **headers},
                        method="POST",
                    )
                    with self.assertRaises(urllib.error.HTTPError) as raised:
                        urllib.request.urlopen(request, timeout=3)
                    self.assertEqual(raised.exception.code, expected)

    def test_http_rejects_oversized_body(self) -> None:
        target = self.make_cache("one")
        context = self.make_context([target], [])
        body = json.dumps({"padding": "x" * (64 * 1024)}).encode("utf-8")
        with running(context) as port:
            request = urllib.request.Request(
                f"http://127.0.0.1:{port}/action",
                data=body,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with self.assertRaises(urllib.error.HTTPError) as raised:
                urllib.request.urlopen(request, timeout=3)
            self.assertEqual(raised.exception.code, 413)

    def test_rescan_replaces_plan_and_actions_atomically(self) -> None:
        original = self.make_cache("original")
        refreshed = self.make_cache("refreshed")
        refreshed_analysis = analysis_for(
            self.home,
            green=[
                {
                    "name": refreshed.name,
                    "path": str(refreshed),
                    "trash_paths": [str(refreshed)],
                }
            ],
        )
        context = self.make_context([original], [], rescan_handler=lambda: refreshed_analysis)
        old_plan_id = context.plan["plan_id"]
        old_action_id = context.plan["actions"][0]["action_id"]

        with running(context) as port:
            with self.post_endpoint(
                port,
                "/rescan",
                {"token": "test-token", "plan_id": old_plan_id},
            ) as response:
                payload = json.loads(response.read())

        self.assertTrue(payload["ok"])
        self.assertNotEqual(payload["plan_id"], old_plan_id)
        self.assertNotIn(old_action_id, context.actions)
        self.assertEqual(context.analysis, refreshed_analysis)
        self.assertEqual(context.public_config()["rescan_endpoint"], "/rescan")

    def test_failed_rescan_preserves_current_plan(self) -> None:
        target = self.make_cache("original")

        def fail_rescan():
            raise OSError("fixture scan failed")

        context = self.make_context([target], [], rescan_handler=fail_rescan)
        old_analysis = context.analysis
        old_plan = context.plan
        old_actions = context.actions

        with running(context) as port:
            with self.assertRaises(urllib.error.HTTPError) as raised:
                self.post_endpoint(
                    port,
                    "/rescan",
                    {"token": "test-token", "plan_id": old_plan["plan_id"]},
                )
            self.assertEqual(raised.exception.code, 500)

        self.assertIs(context.analysis, old_analysis)
        self.assertIs(context.plan, old_plan)
        self.assertIs(context.actions, old_actions)

    def test_project_stage_rescan_preserves_analysis_mode(self) -> None:
        import project_stage

        analysis = analysis_for(self.home)
        analysis["analysis_origin"] = "project-stage"
        analysis["project_stage"] = {
            "discovered": 0,
            "actionable": 0,
            "actionable_size": "约 0.0 GB",
            "idle_minutes": 30,
            "min_kb": 1234,
        }
        source = self.root / "project-stage.json"
        source.write_text(json.dumps(analysis), encoding="utf-8")
        context = create_context(
            str(source),
            home=str(self.home),
            platform="darwin",
            environment=self.environment,
            state_dir=str(self.root / "project-state"),
        )
        with patch.object(
            project_stage, "build_project_stage_analysis", return_value=analysis
        ) as rebuild:
            response = context.rescan()
        self.assertTrue(response["ok"])
        rebuild.assert_called_once_with(
            environment=context.policy.environment,
            min_kb=1234,
        )

    def test_rescan_rejects_extra_fields_and_is_hidden_when_unavailable(self) -> None:
        target = self.make_cache("one")
        context = self.make_context([target], [])
        self.assertEqual(context.public_config()["rescan_endpoint"], "")
        with running(context) as port:
            with self.assertRaises(urllib.error.HTTPError) as raised:
                self.post_endpoint(
                    port,
                    "/rescan",
                    {
                        "token": "test-token",
                        "plan_id": context.plan["plan_id"],
                        "path": str(target),
                    },
                )
            self.assertEqual(raised.exception.code, 400)

    def test_reviewed_trash_requires_matching_short_lived_one_time_token(self) -> None:
        downloads = self.home / "Downloads"
        downloads.mkdir()
        first = downloads / "first.zip"
        second = downloads / "second.zip"
        first.write_bytes(b"first")
        second.write_bytes(b"second")
        called = []
        context = self.make_review_context([first, second], called)
        review_ids = [
            action["action_id"]
            for action in context.plan["actions"]
            if action["mode"] == "reviewed_trash"
        ]

        with self.assertRaises(PolicyError) as raised:
            context.execute([review_ids[0]])
        self.assertEqual(raised.exception.code, "review_token_required")

        review = context.review([review_ids[0]])
        token = review["review_token"]
        with self.assertRaises(PolicyError) as raised:
            context.execute([review_ids[1]], review_token=token)
        self.assertEqual(raised.exception.code, "review_token_mismatch")

        context.review_tokens[token]["expires_at"] = 0
        with self.assertRaises(PolicyError) as raised:
            context.execute([review_ids[0]], review_token=token)
        self.assertEqual(raised.exception.code, "review_token_expired")
        self.assertEqual(called, [])

        valid = context.review([review_ids[0]])
        response = context.execute([review_ids[0]], review_token=valid["review_token"])
        self.assertTrue(response["ok"])
        self.assertTrue(context.review_tokens[valid["review_token"]]["used"])
        self.assertEqual(len(called), 1)
        self.assertIn(".open-cleaner-stage-", called[0])
        self.assertTrue(called[0].endswith("/first.zip"))
        context.completed.clear()
        with self.assertRaises(PolicyError) as raised:
            context.execute([review_ids[0]], review_token=valid["review_token"])
        self.assertEqual(raised.exception.code, "review_token_used")

    def test_reviewed_trash_cannot_mix_with_open_action(self) -> None:
        downloads = self.home / "Downloads"
        downloads.mkdir()
        target = downloads / "archive.zip"
        target.write_bytes(b"data")
        context = self.make_review_context([target], [])
        reviewed_id = next(
            action["action_id"]
            for action in context.plan["actions"]
            if action["mode"] == "reviewed_trash"
        )
        open_id = next(
            action["action_id"]
            for action in context.plan["actions"]
            if action["mode"] == "open"
        )
        token = context.review([reviewed_id])["review_token"]
        with self.assertRaises(PolicyError) as raised:
            context.execute([reviewed_id, open_id], review_token=token)
        self.assertEqual(raised.exception.code, "mixed_review_batch")

    def test_review_endpoint_rejects_paths_and_green_actions(self) -> None:
        target = self.make_cache("one")
        context = self.make_context([target], [])
        action_id = context.plan["actions"][0]["action_id"]
        with self.assertRaises(PolicyError) as raised:
            context.review([action_id])
        self.assertEqual(raised.exception.code, "review_mode_required")

        with running(context) as port:
            with self.assertRaises(urllib.error.HTTPError) as raised:
                self.post_endpoint(
                    port,
                    "/review",
                    {
                        "token": "test-token",
                        "plan_id": context.plan["plan_id"],
                        "paths": [str(target)],
                    },
                )
            self.assertEqual(raised.exception.code, 400)

    def test_http_review_then_action_moves_only_bound_target(self) -> None:
        downloads = self.home / "Downloads"
        downloads.mkdir()
        target = downloads / "archive.zip"
        target.write_bytes(b"data")
        called = []
        context = self.make_review_context([target], called)
        action_id = next(
            action["action_id"]
            for action in context.plan["actions"]
            if action["mode"] == "reviewed_trash"
        )
        base = {
            "token": "test-token",
            "plan_id": context.plan["plan_id"],
            "action_ids": [action_id],
        }
        with running(context) as port:
            with self.post_endpoint(port, "/review", base) as response:
                reviewed = json.loads(response.read())
            with self.post_endpoint(
                port,
                "/action",
                {**base, "review_token": reviewed["review_token"]},
            ) as response:
                completed = json.loads(response.read())
        self.assertTrue(completed["ok"])
        self.assertEqual(completed["results"][0]["mode"], "reviewed_trash")
        self.assertEqual(len(called), 1)
        self.assertIn(".open-cleaner-stage-", called[0])
        self.assertTrue(called[0].endswith("/archive.zip"))

    def test_http_validates_full_batch_before_first_side_effect(self) -> None:
        first = self.make_cache("one")
        second = self.make_cache("two")
        called = []
        context = self.make_context([first, second], called)
        second.rename(second.with_name("stale"))
        second.mkdir()
        ids = [action["action_id"] for action in context.plan["actions"]]
        with running(context) as port:
            with self.assertRaises(urllib.error.HTTPError) as raised:
                self.post(port, self.valid_request(context, action_ids=ids))
            self.assertEqual(raised.exception.code, 409)
        self.assertEqual(called, [])

    def test_concurrent_replay_executes_trash_once(self) -> None:
        target = self.make_cache("one")
        called = []
        context = self.make_context([target], called)
        request_body = self.valid_request(context)
        barrier = threading.Barrier(3)
        statuses = []

        def submit(port: int) -> None:
            barrier.wait()
            try:
                with self.post(port, request_body) as response:
                    statuses.append(response.status)
            except urllib.error.HTTPError as exc:
                statuses.append(exc.code)

        with running(context) as port:
            threads = [threading.Thread(target=submit, args=(port,)) for _ in range(2)]
            for thread in threads:
                thread.start()
            barrier.wait()
            for thread in threads:
                thread.join(timeout=3)
        self.assertEqual(sorted(statuses), [200, 409])
        self.assertEqual(len(called), 1)
        self.assertIn(".open-cleaner-stage-", called[0])
        self.assertTrue(called[0].endswith("/one"))


if __name__ == "__main__":
    unittest.main()
