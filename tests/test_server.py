from __future__ import annotations

import json
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from contextlib import contextmanager
from http.server import ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "opencleaner-skills" / "scripts"
sys.path.insert(0, str(SCRIPTS))

from file_ops import FileOperator, OperationLog
from policy import PolicyError, SafetyPolicy, build_action_plan
from server import ServerContext, make_handler
from test_policy import analysis_for


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
        self.policy = SafetyPolicy(
            home=str(self.home), platform="darwin", environment=self.environment
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def make_cache(self, name: str) -> Path:
        path = self.home / "Library" / "Caches" / name
        path.mkdir(parents=True)
        return path

    def make_context(self, paths, called):
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
        )

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
            self.assertEqual(called, [str(target.resolve())])
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
        self.assertEqual(called, [str(target.resolve())])


if __name__ == "__main__":
    unittest.main()
