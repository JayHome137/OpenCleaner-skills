from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "open-cleaner" / "scripts"
sys.path.insert(0, str(SCRIPTS))

from file_ops import (
    FileOperationError,
    FileOperator,
    OperationLog,
    move_to_trash,
    open_in_file_manager,
)
from policy import SafetyPolicy
from runtime import RuntimeInspector


class FileOperationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="storage-file-ops-")
        self.root = Path(self.temp.name)
        self.home = self.root / "home"
        self.target = self.home / "Downloads" / "archive.zip"
        self.target.parent.mkdir(parents=True)
        self.target.write_bytes(b"review")
        old = time.time() - 3600
        os.utime(self.target, (old, old))
        self.environment = {"HOME": str(self.home)}
        inspector = RuntimeInspector(
            "darwin",
            checker=lambda _pattern: False,
            tool_checker=lambda _tool: True,
            open_file_checker=lambda _path: False,
        )
        self.policy = SafetyPolicy(
            home=str(self.home),
            platform="darwin",
            environment=self.environment,
            runtime_inspector=inspector,
        )
        self.action = self.policy.authorize(str(self.target), "reviewed_trash", "yellow")
        self.action["action_id"] = "action-1"

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_successful_operation_is_logged(self) -> None:
        called = []
        fake_trash = self.root / "fake-trash"

        def move(path: str) -> None:
            called.append(path)
            fake_trash.mkdir(exist_ok=True)
            Path(path).rename(fake_trash / Path(path).name)

        log = OperationLog(self.root / "state")
        operator = FileOperator(self.policy, log, trash_handler=move)
        result = operator.execute(self.action, "plan-1", "session")
        self.assertEqual(result["status"], "completed")
        self.assertEqual(len(called), 1)
        self.assertIn(".open-cleaner-stage-", called[0])
        self.assertTrue(called[0].endswith("/archive.zip"))
        entries = [json.loads(line) for line in log.path.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(entries[0]["status"], "started")
        entry = entries[-1]
        self.assertTrue(
            {
                "timestamp",
                "plan_id",
                "action_id",
                "mode",
                "path",
                "rule_id",
                "status",
                "duration_ms",
                "disk_free_before_bytes",
                "disk_free_after_bytes",
                "disk_free_delta_bytes",
                "target_exists_after",
            }.issubset(entry)
        )
        self.assertEqual(entry["rule_id"], "reviewed.user-item")
        self.assertEqual(entry["status"], "completed")
        self.assertFalse(entry["target_exists_after"])
        self.assertFalse(self.target.exists())

    def test_failed_operation_does_not_fall_back_to_permanent_delete(self) -> None:
        def fail(_path: str) -> None:
            raise FileOperationError("trash unavailable")

        log = OperationLog(self.root / "state")
        operator = FileOperator(self.policy, log, trash_handler=fail)
        result = operator.execute(self.action, "plan-1", "session")
        self.assertEqual(result["status"], "failed")
        self.assertTrue(self.target.exists())
        self.assertIn("trash unavailable", result["error"])
        entries = [json.loads(line) for line in log.path.read_text(encoding="utf-8").splitlines()]
        entry = entries[-1]
        self.assertEqual(entry["status"], "failed")
        self.assertEqual(entry["error_code"], "operation_failed")

    def test_windows_file_operation_entries_are_disabled(self) -> None:
        with patch("file_ops.sys.platform", "win32"):
            with self.assertRaisesRegex(FileOperationError, "仅支持 macOS"):
                move_to_trash(str(self.target))
            with self.assertRaisesRegex(FileOperationError, "仅支持 macOS"):
                open_in_file_manager(str(self.target))

    def test_trash_success_without_source_disappearing_is_failed(self) -> None:
        log = OperationLog(self.root / "state")
        operator = FileOperator(self.policy, log, trash_handler=lambda _path: None)
        result = operator.execute(self.action, "plan-1", "session")
        self.assertEqual(result["status"], "failed")
        self.assertTrue(result["target_exists_after"])
        self.assertIn("原路径仍然存在", result["error"])

    def test_unavailable_audit_log_prevents_side_effect(self) -> None:
        called = []

        class BrokenLog:
            def append(self, _entry) -> None:
                raise OSError("read only")

        operator = FileOperator(self.policy, BrokenLog(), trash_handler=called.append)
        result = operator.execute(self.action, "plan-1", "session")
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["error_code"], "audit_unavailable")
        self.assertEqual(called, [])
        self.assertTrue(self.target.exists())

    def test_dry_run_action_cannot_reach_handler(self) -> None:
        called = []
        log = OperationLog(self.root / "state")
        operator = FileOperator(self.policy, log, trash_handler=called.append)
        result = operator.execute(self.action, "plan-1", "dry-run")
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["error_code"], "dry_run_only")
        self.assertEqual(called, [])
        self.assertTrue(self.target.exists())

    def test_operation_log_inside_target_is_rejected_before_any_write(self) -> None:
        called = []
        log = OperationLog(self.target / "state")
        operator = FileOperator(self.policy, log, trash_handler=called.append)
        result = operator.execute(self.action, "plan-1", "session")
        self.assertEqual(result["error_code"], "audit_path_inside_target")
        self.assertEqual(called, [])
        self.assertFalse(log.path.exists())
        self.assertTrue(self.target.exists())

    @unittest.skipIf(os.name == "nt", "POSIX permission bits are not authoritative on Windows")
    def test_operation_log_is_private_and_rejects_symlink(self) -> None:
        log = OperationLog(self.root / "state")
        log.append({"status": "started"})
        self.assertEqual(stat.S_IMODE(log.state_dir.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(log.path.stat().st_mode), 0o600)

        log.path.unlink()
        destination = self.root / "must-not-change.txt"
        destination.write_text("original", encoding="utf-8")
        log.path.symlink_to(destination)
        with self.assertRaises(OSError):
            log.append({"status": "completed"})
        self.assertEqual(destination.read_text(encoding="utf-8"), "original")


if __name__ == "__main__":
    unittest.main()
