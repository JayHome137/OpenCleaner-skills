#!/usr/bin/env python3
"""Serve an interactive report backed only by a disposable temporary HOME."""
from __future__ import annotations

import sys
import tempfile
from http.server import ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "opencleaner-skills" / "scripts"
sys.path.insert(0, str(SCRIPTS))

from classify import build_analysis
from file_ops import FileOperator, OperationLog
from policy import SafetyPolicy, build_action_plan
from server import ServerContext, make_handler


def main() -> None:
    temporary = tempfile.TemporaryDirectory(prefix="storage-interactive-preview-")
    base = Path(temporary.name)
    home = base / "home"
    cache = home / "Library" / "Caches" / "com.example.preview"
    download = home / "Downloads" / "archive.zip"
    cache.mkdir(parents=True)
    download.parent.mkdir(parents=True)
    (cache / "cache.bin").write_bytes(b"cache")
    download.write_bytes(b"download")
    environment = {"HOME": str(home)}
    scan = {
        "schema_version": "1.0",
        "generated_at": "2026-08-22 00:00:00",
        "scan_seconds": 0.1,
        "system": {
            "os": "macOS preview",
            "home": str(home),
            "disk_name": "Temporary",
            "disk_total": "100 GB",
            "disk_used": "40 GB",
            "disk_free": "60 GB",
            "disks": [],
        },
        "groups": {
            "caches": [
                {"name": cache.name, "path": str(cache), "size_kb": 1024, "size_h": "1 MB"}
            ],
            "downloads": [
                {"name": download.name, "path": str(download), "size_kb": 512, "size_h": "512 KB"}
            ],
        },
        "coverage": {"requested_roots": 2, "completed_roots": 2, "skipped_roots": 0},
        "errors": [],
    }
    analysis = build_analysis(scan, environment=environment)
    policy = SafetyPolicy(home=str(home), platform="darwin", environment=environment)
    plan = build_action_plan(
        analysis,
        home=str(home),
        platform="darwin",
        environment=environment,
        purpose="session",
    )
    fake_trash = base / "fake-trash"

    def move(path: str) -> None:
        fake_trash.mkdir(exist_ok=True)
        Path(path).rename(fake_trash / Path(path).name)

    operator = FileOperator(
        policy,
        OperationLog(base / "state"),
        trash_handler=move,
        open_handler=lambda _path: None,
    )
    template = (ROOT / "opencleaner-skills" / "assets" / "report_template.html").read_text(
        encoding="utf-8"
    )
    context = ServerContext(analysis, template, policy, plan, operator=operator)
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(context))
    print(f"http://127.0.0.1:{server.server_address[1]}/", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        temporary.cleanup()


if __name__ == "__main__":
    main()
