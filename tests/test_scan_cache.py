from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "open-cleaner" / "scripts"
sys.path.insert(0, str(SCRIPTS))

from scan import ScanEngine, ScanTarget, apfs_diagnostics  # noqa: E402
from scan_cache import ScanCache, path_signature  # noqa: E402


class ScanCacheTests(unittest.TestCase):
    def test_direct_child_fingerprint_invalidates_even_when_root_mtime_is_restored(self) -> None:
        with tempfile.TemporaryDirectory(prefix="open-cleaner-cache-") as temporary:
            root = Path(temporary) / "target"
            root.mkdir()
            child = root / "data"
            child.write_bytes(b"one")
            before = path_signature(root)
            root_stat = root.stat()
            child.write_bytes(b"two-two")
            os.utime(root, ns=(root_stat.st_atime_ns, root_stat.st_mtime_ns))
            self.assertNotEqual(before, path_signature(root))

    def test_round_trip_ttl_and_atomic_file_permissions(self) -> None:
        with tempfile.TemporaryDirectory(prefix="open-cleaner-cache-") as temporary:
            state = Path(temporary) / "state"
            target = Path(temporary) / "target"
            target.mkdir()
            (target / "data").write_bytes(b"x")
            cache = ScanCache(state, ttl_seconds=10, now=100)
            cache.stage(target, 1)
            cache.commit()
            self.assertTrue(cache.path.is_file())
            self.assertEqual(stat.S_IMODE(cache.path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(state.stat().st_mode), 0o700)
            loaded = ScanCache(state, ttl_seconds=10, now=109)
            self.assertEqual(loaded.lookup(target)[0], 1)
            expired = ScanCache(state, ttl_seconds=10, now=110)
            self.assertIsNone(expired.lookup(target)[0])
            self.assertEqual(expired.metadata()["invalidated"], 1)

    def test_symlink_state_directory_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="open-cleaner-cache-") as temporary:
            base = Path(temporary)
            real = base / "real"
            real.mkdir()
            link = base / "link"
            link.symlink_to(real, target_is_directory=True)
            cache = ScanCache(link, now=1)
            cache.stage(base, 1)
            cache.commit()
            self.assertFalse((real / "scan-cache-v1.json").exists())
            self.assertFalse(cache.metadata()["published"])
            self.assertIn("write_failed", cache.metadata()["status"])

    def test_discard_pending_keeps_previous_published_cache(self) -> None:
        with tempfile.TemporaryDirectory(prefix="open-cleaner-cache-") as temporary:
            state = Path(temporary) / "state"
            target = Path(temporary) / "target"
            target.mkdir()
            cache = ScanCache(state, now=1)
            cache.stage(target, 1)
            cache.commit()
            original = cache.path.read_text(encoding="utf-8")
            cache.stage(target, 2)
            cache.discard_pending()
            self.assertEqual(cache.path.read_text(encoding="utf-8"), original)
            self.assertEqual(cache.metadata()["pending"], 0)

    def test_scan_errors_and_cancellation_do_not_publish_pending_values(self) -> None:
        with tempfile.TemporaryDirectory(prefix="open-cleaner-cache-") as temporary:
            state = Path(temporary) / "state"
            target = Path(temporary) / "target"
            target.mkdir()
            (target / "data").write_bytes(b"x")
            cache = ScanCache(state, now=1)
            engine = ScanEngine("darwin", max_workers=1, timeout_seconds=2, cache=cache)
            engine.add_error("test_error", str(target), "forced")
            engine.scan_targets([ScanTarget("x", str(target), min_kb=0)])
            self.assertFalse(cache.path.exists())
            self.assertEqual(cache.metadata()["status"], "scan_errors")

            cancelled_state = Path(temporary) / "cancelled-state"
            cancelled_cache = ScanCache(cancelled_state, now=1)
            cancelled = ScanEngine("darwin", max_workers=1, timeout_seconds=2, cache=cancelled_cache)
            cancelled.cancel()
            _groups, coverage = cancelled.scan_targets([ScanTarget("x", str(target), min_kb=0)])
            self.assertFalse(cancelled_cache.path.exists())
            self.assertEqual(coverage["cache"]["status"], "cancelled")
            self.assertFalse(coverage["cache"]["published"])

    def test_progress_events_are_emitted_without_polluting_scan_result(self) -> None:
        with tempfile.TemporaryDirectory(prefix="open-cleaner-cache-") as temporary:
            target = Path(temporary) / "target"
            target.mkdir()
            (target / "data").write_bytes(b"x")
            events: list[dict[str, object]] = []
            engine = ScanEngine("darwin", max_workers=1, timeout_seconds=2, progress_callback=events.append)
            _groups, coverage = engine.scan_targets([ScanTarget("x", str(target), min_kb=0)])
            self.assertEqual(coverage["requested_roots"], 1)
            self.assertEqual(events[-1]["phase"], "complete")
            self.assertTrue(any(event["phase"] == "measure" for event in events))


class ApfsDiagnosticTests(unittest.TestCase):
    def test_read_only_diagnostics_parse_snapshot_and_unlinked_file_output(self) -> None:
        outputs = {
            ("/usr/bin/tmutil", "listlocalsnapshots", "/"): (0, "Snapshots for disk /:\ncom.apple.TimeMachine.2026-01-01-010101\n"),
            ("/usr/sbin/lsof", "-nP", "+L1", "-F", "ns"): (0, "s2048\nn/tmp/deleted\ns4096\nn/tmp/deleted\n"),
        }

        def fake_run(command, **_kwargs):
            key = tuple(command)
            return type("Result", (), {
                "returncode": outputs.get(key, (1, ""))[0],
                "stdout": outputs.get(key, (1, ""))[1],
                "stderr": "",
            })()

        with tempfile.TemporaryDirectory(prefix="open-cleaner-apfs-") as temporary:
            with patch("scan.subprocess.run", side_effect=fake_run):
                result = apfs_diagnostics(temporary, "0 B")
            self.assertEqual(result["purgeable"]["status"], "empty")
            self.assertEqual(result["local_snapshots"]["count"], 1)
            self.assertEqual(result["open_unlinked_files"]["count"], 1)
            self.assertEqual(result["open_unlinked_files"]["estimated_bytes"], 4096)


if __name__ == "__main__":
    unittest.main()
